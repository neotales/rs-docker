//! A supervised, synchronous socket worker for managed SSH establishment.
//!
//! This is an isolated boundary, not a safe SSH establishment implementation:
//! callers must order every trust, auth and exec effect through the control,
//! and must not put unbounded work inside its ordering lock. The legacy worker
//! does neither. Resolver background work is independent and cannot be stopped
//! once issued; it must never own this worker or perform trust effects.
//!
//! An effect commits when its cancellation check observes false under the
//! ordering lock, provided the subsequent deadline check also succeeds.
//! Cancellation can therefore win after that check but before the syscall;
//! that syscall is already committed. Shutdown interrupts socket I/O where
//! the OS supports it. The per-call timeout is additionally capped by the
//! original absolute deadline, so repeated partial reads do not extend it.
//!
//! Rust cannot forcibly stop a thread blocked outside socket I/O. A process-
//! lifetime registry owns every worker's OS join handle until explicit reaping;
//! it refuses new workers at its fixed capacity. Cancellation may return while
//! a worker remains alive, but does not silently discard its handle. This does
//! not make filesystem work bounded or replace process isolation.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::ssh_cancellation::{EstablishmentControl, Refused};
use super::ssh_connect::{CancelOnDrop, Dialed};

const MAX_WORKERS: usize = 16;

pub(crate) struct WorkerRegistry {
    state: Mutex<RegistryState>,
    capacity: usize,
}

struct RegistryState {
    workers: Vec<JoinHandle<()>>,
    completed: usize,
    panicked: usize,
}

#[derive(Debug)]
struct WorkerStatus {
    outstanding: usize,
    completed: usize,
    panicked: usize,
}

impl WorkerRegistry {
    const fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(RegistryState {
                workers: Vec::new(),
                completed: 0,
                panicked: 0,
            }),
            capacity,
        }
    }

    fn reap(state: &mut RegistryState) {
        let mut index = 0;
        while index < state.workers.len() {
            if state.workers[index].is_finished() {
                let handle = state.workers.swap_remove(index);
                state.completed += 1;
                if handle.join().is_err() {
                    state.panicked += 1;
                }
            } else {
                index += 1;
            }
        }
    }

    /// Reap only finished threads; a still-running worker remains owned.
    fn reap_finished(&self) -> io::Result<WorkerStatus> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("worker registry poisoned"))?;
        Self::reap(&mut state);
        Ok(WorkerStatus {
            outstanding: state.workers.len(),
            completed: state.completed,
            panicked: state.panicked,
        })
    }

    fn spawn<T, F>(&self, worker: F) -> io::Result<tokio::sync::oneshot::Receiver<io::Result<T>>>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("worker registry poisoned"))?;
        Self::reap(&mut state);
        if state.workers.len() >= self.capacity {
            return Err(io::Error::other("SSH worker registry is full"));
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let handle = thread::Builder::new()
            .name("managed-ssh-worker".into())
            .spawn(move || {
                let _ = tx.send(worker());
            })?;
        state.workers.push(handle);
        Ok(rx)
    }
}

pub(crate) static WORKERS: WorkerRegistry = WorkerRegistry::new(MAX_WORKERS);

pub(crate) fn refused(error: Refused) -> io::Error {
    let kind = match error {
        Refused::Deadline => {
            return io::Error::new(
                io::ErrorKind::TimedOut,
                crate::TransportTimeout {
                    kind: crate::TransportTimeoutKind::ManagedSshEstablishment,
                    message: "managed SSH establishment deadline was observed; peer text withheld"
                        .to_owned(),
                },
            );
        }
        // `read_exact` retries Interrupted indefinitely, including after
        // cancellation. Use a terminal error for an establishment refusal.
        Refused::Cancelled => io::ErrorKind::ConnectionAborted,
        Refused::Poisoned | Refused::SocketRegistered => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("SSH establishment refused: {error:?}"))
}

pub(crate) struct DeadlineSocket {
    socket: TcpStream,
    control: EstablishmentControl,
    operation_limit: Duration,
    in_session: Arc<AtomicBool>,
    /// An OS socket timeout can fire just before the absolute clock deadline.
    /// Retain that local observation even if the SSH library flattens its error.
    timed_out: Arc<AtomicBool>,
}

impl DeadlineSocket {
    fn observe_timeout<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result
            && matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            )
        {
            self.timed_out.store(true, Ordering::SeqCst);
            return Err(refused(Refused::Deadline));
        }
        result
    }

    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self
            .control
            .deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(refused(Refused::Deadline));
        }
        Ok(remaining.min(self.operation_limit))
    }
}

impl Read for DeadlineSocket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.in_session.load(Ordering::SeqCst) {
            return self
                .control
                .clone()
                .try_session_effect(|| self.socket.read(buffer))
                .map_err(refused)?;
        }
        self.control
            .clone()
            .try_effect(|| {
                self.socket.set_read_timeout(Some(self.remaining()?))?;
                let result = self.socket.read(buffer);
                self.observe_timeout(result)
            })
            .map_err(refused)?
    }
}

impl Write for DeadlineSocket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.in_session.load(Ordering::SeqCst) {
            return self
                .control
                .clone()
                .try_session_effect(|| self.socket.write(buffer))
                .map_err(refused)?;
        }
        self.control
            .clone()
            .try_effect(|| {
                self.socket.set_write_timeout(Some(self.remaining()?))?;
                let result = self.socket.write(buffer);
                self.observe_timeout(result)
            })
            .map_err(refused)?
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.in_session.load(Ordering::SeqCst) {
            return self
                .control
                .try_session_effect(|| self.socket.flush())
                .map_err(refused)?;
        }
        self.control
            .try_effect(|| self.socket.flush())
            .map_err(refused)?
    }
}

/// Holds the only cancellation owner together with a successful worker result.
pub(crate) struct Established<T> {
    value: T,
    guard: CancelOnDrop,
}

impl<T> Established<T> {
    /// A clone of the cancellation control the session guard owns.
    ///
    /// The clone has no drop behaviour of its own. It exists so an owner that
    /// can outlive the guard can request cancellation without duplicating the
    /// guard, and without waiting for this `Established` to be dropped.
    pub(crate) fn control(&self) -> EstablishmentControl {
        self.guard.control.clone()
    }
}

impl<T: Read + Write> Established<crate::ssh_neotales::SessionParts<T>> {
    /// These operations never expose a reference to the guarded transport.
    pub(crate) fn dispatch(&mut self) -> Result<crate::ssh_neotales::Progress, crate::Error> {
        self.value.dispatch()
    }

    pub(crate) fn write(
        &mut self,
        bytes: &[u8],
    ) -> Result<crate::ssh_neotales::Progress, crate::Error> {
        self.value.write(bytes)
    }

    pub(crate) fn credit(&mut self, bytes: u32) {
        self.value.credit(bytes);
    }

    pub(crate) fn can_read_behind_active(&self) -> bool {
        self.value.can_read_behind_active()
    }

    /// Whether a peer-initiated rekey is retained or in progress.
    pub(crate) fn rekey_active(&self) -> bool {
        self.value.rekey_active()
    }

    pub(crate) fn read_one_behind_active(
        &mut self,
    ) -> Result<crate::ssh_neotales::Progress, crate::Error> {
        self.value.read_one_behind_active()
    }

    /// Whether the owned driver can admit another channel-data packet now.
    ///
    /// This only reads retained state. It never touches the guarded transport,
    /// so a caller may use it from `poll_write` without driving the protocol.
    pub(crate) fn accepts_data(&self) -> bool {
        self.value.accepts_data()
    }

    /// The remote receive window still available to admitted packets.
    ///
    /// This is a state observation, not a protocol step.
    pub(crate) fn available_window(&self) -> u32 {
        self.value.available_window()
    }

    pub(crate) fn flush_credit(
        &mut self,
    ) -> Result<Option<crate::ssh_neotales::BlockedOn>, crate::Error> {
        self.value.flush_credit()
    }

    pub(crate) fn complete_outbound(
        &mut self,
    ) -> Result<Option<crate::ssh_neotales::BlockedOn>, crate::Error> {
        self.value.complete_outbound()
    }

    pub(crate) fn shutdown(&mut self) -> Result<crate::ssh_neotales::Progress, crate::Error> {
        self.value.shutdown()
    }

    pub(crate) fn take_early(&mut self) -> Vec<u8> {
        self.value.take_early()
    }

    #[cfg(test)]
    pub(crate) fn close_pending(&self) -> bool {
        self.value.close_pending()
    }

    #[cfg(test)]
    pub(crate) fn owed_close_reply(&self) -> bool {
        self.value.owed_close_reply()
    }

    #[cfg(test)]
    pub(crate) fn reply_queued(&self) -> bool {
        self.value.reply_queued()
    }

    /// Whether a protocol reply is queued or being written.
    ///
    /// While true the channel driver refuses further reads, so a blocked write
    /// cannot be escaped by reading. The pump bounds that wait.
    pub(crate) fn reply_outstanding(&self) -> bool {
        self.value.reply_outstanding()
    }

    #[cfg(test)]
    pub(crate) fn adjustment_active(&self) -> bool {
        self.value.adjustment_active()
    }

    #[cfg(test)]
    pub(crate) fn data_active(&self) -> bool {
        self.value.data_active()
    }

    #[cfg(test)]
    pub(crate) fn eof_active(&self) -> bool {
        self.value.eof_active()
    }

    #[cfg(test)]
    pub(crate) fn global_reply_writing(&self) -> bool {
        self.value.global_reply_writing()
    }

    #[cfg(test)]
    pub(crate) fn channel_reply_writing(&self) -> bool {
        self.value.channel_reply_writing()
    }

    #[cfg(test)]
    pub(crate) fn open_rejection_writing(&self) -> bool {
        self.value.open_rejection_writing()
    }

    #[cfg(test)]
    pub(crate) fn pending_peer_opens(&self) -> usize {
        self.value.pending_peer_opens()
    }

    #[cfg(test)]
    pub(crate) fn close_reply_writing(&self) -> bool {
        self.value.close_reply_writing()
    }

    #[cfg(test)]
    pub(crate) fn pong_writing(&self) -> bool {
        self.value.pong_writing()
    }

    #[cfg(test)]
    pub(crate) fn next_is_pong(&self) -> bool {
        self.value.next_is_pong()
    }

    #[cfg(test)]
    pub(crate) fn session_close_pending_in_driver(&self) -> bool {
        self.value.session_close_pending_in_driver()
    }

    #[cfg(test)]
    pub(crate) fn session_retired(&self) -> bool {
        self.value.session_retired()
    }

    #[cfg(test)]
    pub(crate) fn committed_outbound_sequence(&self) -> u32 {
        self.value.committed_outbound_sequence()
    }

    /// Test-only wrapper for a driver assembled outside the supervised worker.
    #[cfg(test)]
    pub(crate) fn test_wrap(
        value: crate::ssh_neotales::SessionParts<T>,
        guard: CancelOnDrop,
    ) -> Self {
        Self { value, guard }
    }
}

// Also prevents moving fields out when code inside this module handles a
// session. Field destruction still drops the transport before its guard.
impl<T> Drop for Established<T> {
    fn drop(&mut self) {}
}

// Expose operations, not the owned transport: moving it away would drop its
// cancellation owner. Session sockets are nonblocking and may return WouldBlock.
impl Read for Established<DeadlineSocket> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.value.read(buffer)
    }
}

impl Write for Established<DeadlineSocket> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.value.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.value.flush()
    }
}

/// Mode change and owner transfer share one effect-ordering boundary.
fn commit_session<T>(
    value: T,
    guard: CancelOnDrop,
    in_session: &AtomicBool,
    prepare: impl FnOnce(&CancelOnDrop) -> io::Result<()>,
) -> io::Result<Established<T>> {
    let control = guard.control.clone();
    control
        .try_effect(|| {
            prepare(&guard)?;
            if control.is_cancelled() {
                return Err(refused(Refused::Cancelled));
            }
            if Instant::now() >= control.deadline() {
                return Err(refused(Refused::Deadline));
            }
            in_session.store(true, Ordering::SeqCst);
            Ok(Established { value, guard })
        })
        .map_err(refused)?
}

/// Run one bounded socket worker. Non-I/O effects still need explicit gating.
/// The unique owner moves into the returned result, or cancels on every failure.
pub(crate) async fn supervise<T, F>(
    dialed: Dialed,
    operation_limit: Duration,
    registry: &'static WorkerRegistry,
    worker: F,
) -> io::Result<Established<T>>
where
    T: Send + 'static,
    F: FnOnce(DeadlineSocket, EstablishmentControl) -> io::Result<T> + Send + 'static,
{
    if operation_limit.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "zero I/O timeout",
        ));
    }
    let Dialed { socket, guard } = dialed;
    let control = guard.control.clone();
    control
        .try_effect(|| socket.set_nonblocking(false))
        .map_err(refused)??;
    let worker_control = control.clone();
    let in_session = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let socket = DeadlineSocket {
        socket,
        control: control.clone(),
        operation_limit,
        in_session: Arc::clone(&in_session),
        timed_out: Arc::clone(&timed_out),
    };
    let task = registry.spawn(move || worker(socket, worker_control))?;
    let result = tokio::select! {
        biased;
        () = control.cancelled() => Err(refused(Refused::Cancelled)),
        () = tokio::time::sleep_until(tokio::time::Instant::from_std(control.deadline())) => {
            Err(refused(Refused::Deadline))
        }
        result = task => {
            let result = result.map_err(|_| io::Error::other("SSH worker terminated without a result"))?;
            if timed_out.load(Ordering::SeqCst) {
                return Err(refused(Refused::Deadline));
            }
            control.try_effect(|| ()).map_err(refused)?;
            result
        }
    };
    let value = result?;
    commit_session(value, guard, &in_session, CancelOnDrop::prepare_session)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };
    use tokio::io::AsyncWriteExt;

    use crate::ssh_cancellation::{EstablishmentControl, Refused};
    use crate::ssh_connect::Dialed;

    async fn supervise<T, F>(
        socket: TcpStream,
        control: EstablishmentControl,
        operation_limit: Duration,
        registry: &'static super::WorkerRegistry,
        worker: F,
    ) -> io::Result<T>
    where
        T: Clone + Send + 'static,
        F: FnOnce(super::DeadlineSocket, EstablishmentControl) -> io::Result<T> + Send + 'static,
    {
        let dialed = Dialed::test_connected(socket, control)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let established = super::supervise(dialed, operation_limit, registry, worker).await?;
        Ok(established.value.clone())
    }

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        (client, peer)
    }

    fn control(duration: Duration) -> EstablishmentControl {
        EstablishmentControl::new(Instant::now() + duration)
    }

    #[tokio::test]
    async fn simultaneous_session_cancel_and_drop_are_isolated() {
        let (first_socket, mut first_peer) = pair();
        let (second_socket, mut second_peer) = pair();
        for peer in [&first_peer, &second_peer] {
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        let first_control = control(Duration::from_secs(5));
        let second_control = control(Duration::from_secs(5));
        let first_dial = Dialed::test_connected(first_socket, first_control.clone()).unwrap();
        let second_dial = Dialed::test_connected(second_socket, second_control.clone()).unwrap();
        let first = super::supervise(
            first_dial,
            Duration::from_secs(1),
            &super::WORKERS,
            |socket, _| Ok(socket),
        )
        .await
        .unwrap();
        let mut second = super::supervise(
            second_dial,
            Duration::from_secs(1),
            &super::WORKERS,
            |socket, _| Ok(socket),
        )
        .await
        .unwrap();
        first_control.request_cancel();
        assert_eq!(first_peer.read(&mut [0]).unwrap(), 0);
        assert!(!second_control.is_cancelled());
        second.write_all(b"intact").unwrap();
        let mut received = [0; 6];
        second_peer.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"intact");
        drop(second);
        assert_eq!(second_peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(second_control.shutdown_count(), 1);
        drop(first);
        assert_eq!(first_control.shutdown_count(), 1);
    }

    #[tokio::test]
    async fn committed_session_can_write_after_establishment_deadline() {
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_millis(100));
        let dialed = Dialed::test_connected(socket, control).unwrap();
        let mut session = super::supervise(
            dialed,
            Duration::from_secs(1),
            &super::WORKERS,
            |socket, _| Ok(socket),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        session.write_all(b"x").unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        assert_eq!(
            session.read(&mut byte).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        peer.write_all(b"y").unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match session.read(&mut byte) {
                    Ok(1) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    other => panic!("unexpected session read: {other:?}"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(&byte, b"y");
    }

    #[tokio::test]
    async fn cancellation_before_worker_completion_prevents_session_commit() {
        static REGISTRY: super::WorkerRegistry = super::WorkerRegistry::new(1);
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control.clone()).unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let task = tokio::spawn(super::supervise(
            dialed,
            Duration::from_secs(1),
            &REGISTRY,
            move |socket, _| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
                Ok(socket)
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .unwrap()
            .unwrap();
        control.request_cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionAborted)
        );
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if REGISTRY.reap_finished().unwrap().outstanding == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(control.shutdown_count(), 1);
    }

    #[test]
    fn cancellation_during_session_mode_change_refuses_commit() {
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let Dialed { socket, guard } = Dialed::test_connected(socket, control.clone()).unwrap();
        let phase = Arc::new(AtomicBool::new(false));
        let worker_phase = phase.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = super::commit_session(socket, guard, &worker_phase, |owner| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                owner.prepare_session()
            });
            done_tx.send(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionAborted)).unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        control.request_cancel();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        release_tx.send(()).unwrap();
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        worker.join().unwrap();
        assert!(!phase.load(Ordering::SeqCst));
        assert_eq!(control.shutdown_count(), 1);
    }

    #[test]
    fn failed_session_mode_change_drops_owner_without_committing() {
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let Dialed { socket, guard } = Dialed::test_connected(socket, control.clone()).unwrap();
        let phase = AtomicBool::new(false);
        let result = super::commit_session(socket, guard, &phase, |_| {
            Err(io::Error::other("mode failure"))
        });
        assert!(matches!(result, Err(ref error) if error.to_string().contains("mode failure")));
        assert!(!phase.load(Ordering::SeqCst));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(control.shutdown_count(), 1);
    }

    #[tokio::test]
    async fn dialed_socket_transfers_to_worker_and_session() {
        use crate::ssh_connect::dial;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = dial("127.0.0.1", address.port(), control.clone())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            super::supervise(
                dialed,
                Duration::from_secs(1),
                &super::WORKERS,
                move |socket, _| Ok(socket),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!control.is_cancelled());
        let mut result = result;
        result.write_all(b"ok").unwrap();
        let mut bytes = [0; 2];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ok");
        control.request_cancel();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        drop(result);
        control.cancel();
        assert!(control.is_cancelled());
        assert_eq!(control.shutdown_count(), 1);
    }

    #[tokio::test]
    async fn cancellation_at_handoff_refuses_worker_and_shuts_down_once() {
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control.clone()).unwrap();
        control.request_cancel();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let result = super::supervise(
            dialed,
            Duration::from_secs(1),
            &super::WORKERS,
            move |_, _| {
                worker_started.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(
            matches!(result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionAborted)
        );
        assert!(!started.load(Ordering::SeqCst));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        control.cancel();
        assert_eq!(control.shutdown_count(), 1);
    }

    #[tokio::test]
    async fn dropping_committed_session_closes_socket_once() {
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control.clone()).unwrap();
        let session = super::supervise(
            dialed,
            Duration::from_secs(1),
            &super::WORKERS,
            |socket, _| Ok(socket),
        )
        .await
        .unwrap();
        assert!(!control.is_cancelled());
        drop(session);
        assert!(control.is_cancelled());
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        control.cancel();
        assert_eq!(control.shutdown_count(), 1);
    }

    #[tokio::test]
    async fn spawn_refusal_and_unpolled_drop_close_owned_socket() {
        static FULL: super::WorkerRegistry = super::WorkerRegistry::new(0);
        for do_spawn in [false, true] {
            let (socket, mut peer) = pair();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let control = control(Duration::from_secs(5));
            let dialed = Dialed::test_connected(socket, control.clone()).unwrap();
            let future = super::supervise(dialed, Duration::from_secs(1), &FULL, |_, _| Ok(()));
            if do_spawn {
                assert!(
                    matches!(future.await, Err(ref error) if error.to_string().contains("registry is full"))
                );
            } else {
                drop(future);
            }
            assert_eq!(peer.read(&mut [0]).unwrap(), 0);
            assert!(control.is_cancelled());
            control.cancel();
            assert_eq!(control.shutdown_count(), 1);
        }
    }

    #[tokio::test]
    async fn late_worker_result_is_dropped_after_supervisor_drop() {
        struct Marker(Arc<AtomicBool>);
        impl Drop for Marker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        static REGISTRY: super::WorkerRegistry = super::WorkerRegistry::new(1);
        let (socket, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control.clone()).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let worker_marker = dropped.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let task = tokio::spawn(super::supervise(
            dialed,
            Duration::from_secs(1),
            &REGISTRY,
            move |socket, _| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
                Ok((socket, Marker(worker_marker)))
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(
            matches!(tokio::time::timeout(Duration::from_secs(1), task).await.unwrap(), Err(error) if error.is_cancelled())
        );
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        control.cancel();
        assert_eq!(control.shutdown_count(), 1);
    }

    #[test]
    fn drop_does_not_deadlock_when_cancellation_is_inspected() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (socket, _peer) = pair();
            let control = control(Duration::from_secs(5));
            let inspected = control.clone();
            let mut pending_notification = Box::pin(inspected.cancelled());
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(
                pending_notification.as_mut().poll(&mut context),
                Poll::Pending
            ));
            assert!(!inspected.is_cancelled());
            let dialed = Dialed::test_connected(socket, control).unwrap();
            drop(dialed);
            assert!(inspected.is_cancelled());
            assert!(matches!(
                pending_notification.as_mut().poll(&mut context),
                Poll::Ready(())
            ));
            drop(pending_notification);
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(1))
            .expect("drop deadlocked while receiver was inspected");
    }

    #[tokio::test]
    async fn cancelled_stalled_worker_remains_owned_until_reaped() {
        static REGISTRY: super::WorkerRegistry = super::WorkerRegistry::new(1);
        let (client, _peer) = pair();
        let control = control(Duration::from_secs(10));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(supervise(
            client,
            control.clone(),
            Duration::from_secs(1),
            &REGISTRY,
            move |_, control| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
                let _ = finished_tx.send(control.try_effect(|| ()));
                Ok(())
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        control.request_cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        let status = REGISTRY.reap_finished().unwrap();
        assert_eq!(status.outstanding, 1);
        assert_eq!(status.completed, 0);
        assert!(
            REGISTRY.spawn(|| Ok(())).is_err(),
            "capacity must fail closed"
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), finished_rx)
                .await
                .unwrap()
                .unwrap(),
            Err(Refused::Cancelled)
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = REGISTRY.reap_finished().unwrap();
                if status.outstanding == 0 {
                    assert_eq!(status.completed, 1);
                    assert_eq!(status.panicked, 0);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn fake_handshake_reads_and_writes_before_deadline() {
        let (client, mut peer) = pair();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.write_all(b"SSH-2.0-fake\r\n").unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise(
                client,
                control(Duration::from_secs(5)),
                Duration::from_secs(1),
                &super::WORKERS,
                |mut socket, _| {
                    let mut greeting = [0; 14];
                    socket.read_exact(&mut greeting)?;
                    socket.write_all(b"auth")?;
                    Ok(greeting)
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&result, b"SSH-2.0-fake\r\n");
        let mut response = [0; 4];
        peer.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"auth");
    }

    #[tokio::test]
    async fn individual_stalled_read_retains_its_marker_even_if_the_callback_flattens_it() {
        let (client, _peer) = pair();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise(
                client,
                control(Duration::from_secs(5)),
                Duration::from_millis(35),
                &super::WORKERS,
                |mut socket, _| {
                    let error = socket.read(&mut [0]).unwrap_err();
                    // Model an SSH API that reports only a rendered source.
                    Err::<usize, _>(io::Error::other(format!("flattened callback: {error}")))
                },
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(matches!(
            result.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert_eq!(
            crate::transport_timeout_in(&result),
            Some(crate::TransportTimeoutKind::ManagedSshEstablishment)
        );

        // An unobserved OS timeout or forged wording is not enough to create
        // the local marker. Only DeadlineSocket's bounded I/O may record it.
        let (client, _peer) = pair();
        let unobserved = supervise(
            client,
            control(Duration::from_secs(5)),
            Duration::from_secs(1),
            &super::WORKERS,
            |_, _| {
                Err::<usize, _>(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed SSH establishment deadline was observed",
                ))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(crate::transport_timeout_in(&unobserved), None);
    }

    #[tokio::test]
    async fn cancellation_interrupts_stalled_read_and_refuses_next_effect() {
        let (client, _peer) = pair();
        let control = control(Duration::from_secs(10));
        let effect = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let worker_effect = effect.clone();
        let task = tokio::spawn(supervise(
            client,
            control.clone(),
            Duration::from_secs(5),
            &super::WORKERS,
            move |mut socket, control| {
                let _ = started_tx.send(());
                let _ = socket.read(&mut [0]);
                let result = control.try_effect(|| worker_effect.store(true, Ordering::SeqCst));
                let _ = finished_tx.send(result);
                Ok(())
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        control.request_cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        let effect_result = tokio::time::timeout(Duration::from_secs(2), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(effect_result, Err(Refused::Cancelled));
        assert!(!effect.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn trickle_does_not_extend_absolute_deadline() {
        let (client, peer) = pair();
        peer.set_nonblocking(true).unwrap();
        let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
        let peer_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if peer.write_all(b"x").await.is_err() {
                    break;
                }
            }
        });
        let control = control(Duration::from_millis(150));
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            supervise(
                client,
                control,
                Duration::from_millis(80),
                &super::WORKERS,
                |mut socket, _| {
                    let mut handshake = [0; 100];
                    socket.read_exact(&mut handshake)
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_millis(75));
        assert!(started.elapsed() < Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(2), peer_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dropping_supervisor_does_not_wait_for_stuck_worker() {
        let (client, _peer) = pair();
        let control = control(Duration::from_secs(10));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(supervise(
            client,
            control.clone(),
            Duration::from_secs(1),
            &super::WORKERS,
            move |_, control| {
                let _ = control.try_effect(|| {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(2));
                });
                let _ = finished_tx.send(control.try_effect(|| ()));
                Ok(())
            },
        ));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap_err()
                .is_cancelled()
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), finished_rx)
                .await
                .unwrap()
                .unwrap(),
            Err(Refused::Cancelled)
        );
    }
}
