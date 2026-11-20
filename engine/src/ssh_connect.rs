//! Deadline-bound first phase of managed SSH establishment.
//!
//! Async DNS and TCP dialing transfer socket ownership and the shared
//! cancellation/deadline control to the supervised SSH worker.

use std::{
    future::{Future, poll_fn},
    io,
    net::{SocketAddr, TcpStream},
    task::Poll,
};

use tokio::{net::TcpSocket, time::timeout_at};

use super::ssh_cancellation::{EstablishmentControl, Refused};

#[derive(Debug)]
pub(crate) enum DialError {
    Refused(Refused),
    Io(io::Error),
}

/// The unique cancellation owner, moved from dial to worker to session.
/// Drop does not wait for the worker's effect lock, but notification and the
/// OS shutdown syscall do not have a hard wall-clock bound.
pub(crate) struct CancelOnDrop {
    pub(crate) control: EstablishmentControl,
    shutdown: Option<TcpStream>,
}

impl CancelOnDrop {
    /// Switch all socket duplicates to nonblocking mode before session commit.
    pub(crate) fn prepare_session(&self) -> io::Result<()> {
        self.shutdown
            .as_ref()
            .ok_or_else(|| io::Error::other("SSH socket owner has no socket"))?
            .set_nonblocking(true)
    }
}

#[cfg(test)]
impl CancelOnDrop {
    /// A guard that owns only the control, with no socket registered.
    ///
    /// `Dialed::test_connected` always registers a socket, and cancellation
    /// then shuts it down. A test that needs the socket to stay live across
    /// cancellation uses this instead, so it observes the effect ordering
    /// check rather than the opportunistic shutdown.
    pub(crate) fn test_unregistered(control: EstablishmentControl) -> Self {
        Self {
            control,
            shutdown: None,
        }
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.control.request_cancel();
        if let Some(socket) = &self.shutdown {
            self.control.shutdown_socket(socket);
        }
    }
}

pub(crate) struct Dialed {
    pub(crate) socket: TcpStream,
    pub(crate) guard: CancelOnDrop,
}

impl Dialed {
    /// Clone solely for reactor readiness; the owner remains in `Dialed`.
    pub(crate) fn readiness_clone(&self) -> Result<TcpStream, DialError> {
        self.guard
            .control
            .try_effect(|| self.socket.try_clone())
            .map_err(DialError::Refused)?
            .map_err(DialError::Io)
    }

    /// Attach the dial's sole owner and register the socket exactly once.
    fn attach(socket: TcpStream, mut guard: CancelOnDrop) -> Result<Self, DialError> {
        let shutdown = guard
            .control
            .try_effect(|| socket.try_clone())
            .map_err(DialError::Refused)?
            .map_err(DialError::Io)?;
        guard.shutdown = Some(shutdown);
        let duplicate = guard
            .control
            .try_effect(|| socket.try_clone())
            .map_err(DialError::Refused)?
            .map_err(DialError::Io)?;
        guard
            .control
            .register_socket(duplicate)
            .map_err(DialError::Refused)?;
        // If cancellation raced registration while the socket mutex was held,
        // the owner closes the socket instead of returning a cancelled dial.
        guard
            .control
            .try_effect(|| ())
            .map_err(DialError::Refused)?;
        Ok(Self { socket, guard })
    }

    #[cfg(test)]
    pub(crate) fn test_connected(
        socket: TcpStream,
        control: EstablishmentControl,
    ) -> Result<Self, DialError> {
        Self::attach(
            socket,
            CancelOnDrop {
                control,
                shutdown: None,
            },
        )
    }
}

fn deadline_error() -> DialError {
    DialError::Refused(Refused::Deadline)
}

#[cfg(test)]
tokio::task_local! {
    // Deterministic pending DNS (true) or TCP connect (false), scoped to one
    // caller. The production resolver and connector cannot be replaced.
    pub(crate) static TEST_DIAL_STALL: bool;
}

/// Resolver background work never owns a control or a socket and therefore
/// cannot initiate TCP or trust effects after this future is dropped. An
/// already-started DNS query cannot be retracted.
pub(crate) async fn dial(
    host: &str,
    port: u16,
    control: EstablishmentControl,
) -> Result<Dialed, DialError> {
    #[cfg(test)]
    if let Ok(resolve) = TEST_DIAL_STALL.try_with(|resolve| *resolve) {
        return if resolve {
            dial_resolved(
                std::future::pending::<io::Result<Vec<SocketAddr>>>(),
                control,
            )
            .await
        } else {
            dial_with(
                std::future::ready(Ok([SocketAddr::from(([127, 0, 0, 1], port))])),
                control,
                |_| Ok(std::future::pending::<io::Result<tokio::net::TcpStream>>()),
            )
            .await
        };
    }
    dial_resolved(tokio::net::lookup_host((host, port)), control).await
}

async fn dial_resolved<F, I>(
    resolver: F,
    control: EstablishmentControl,
) -> Result<Dialed, DialError>
where
    F: Future<Output = io::Result<I>>,
    I: IntoIterator<Item = SocketAddr>,
{
    dial_with(resolver, control, |address| {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        Ok(socket.connect(address))
    })
    .await
}

/// Every poll is ordered against cancellation, including the resolver's first
/// poll (which may launch a DNS query). The registered notification cannot miss a
/// cancellation occurring between the check and parking the task. Futures
/// polled here must not block: cancellation waits for an in-flight poll.
async fn wait_phase<F: Future>(
    future: F,
    control: &EstablishmentControl,
) -> Result<F::Output, DialError> {
    let mut future = Box::pin(future);
    let ordered = poll_fn(|cx| match control.try_effect(|| future.as_mut().poll(cx)) {
        Ok(result) => result.map(Ok),
        Err(error) => Poll::Ready(Err(DialError::Refused(error))),
    });
    tokio::select! {
        biased;
        () = control.cancelled() => Err(DialError::Refused(Refused::Cancelled)),
        result = timeout_at(tokio::time::Instant::from_std(control.deadline()), ordered) => {
            result.map_err(|_| deadline_error())?
        }
    }
}

async fn dial_with<F, I, C, A>(
    resolver: F,
    control: EstablishmentControl,
    mut connector: C,
) -> Result<Dialed, DialError>
where
    F: Future<Output = io::Result<I>>,
    I: IntoIterator<Item = SocketAddr>,
    C: FnMut(SocketAddr) -> io::Result<A>,
    A: Future<Output = io::Result<tokio::net::TcpStream>>,
{
    let guard = CancelOnDrop {
        control: control.clone(),
        shutdown: None,
    };
    let addresses = wait_phase(resolver, &control)
        .await?
        .map_err(DialError::Io)?;
    control.try_effect(|| ()).map_err(DialError::Refused)?;
    let mut last_error = None;
    for address in addresses {
        // The connect future is polled only while holding the cancellation lock:
        // dropping it cancels readiness, not an already-issued connect syscall.
        let connect = match control
            .try_effect(|| connector(address))
            .map_err(DialError::Refused)?
        {
            Ok(connect) => connect,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match wait_phase(connect, &control).await? {
            Err(error) => last_error = Some(error),
            Ok(socket) => {
                let socket = socket.into_std().map_err(DialError::Io)?;
                return Dialed::attach(socket, guard);
            }
        }
    }
    Err(DialError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "DNS returned no addresses")
    })))
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        io::{self, Read},
        net::{SocketAddr, TcpListener},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use super::{DialError, dial, dial_resolved, dial_with};
    use crate::ssh_cancellation::{EstablishmentControl, Refused};

    fn control(duration: Duration) -> EstablishmentControl {
        EstablishmentControl::new(Instant::now() + duration)
    }

    #[tokio::test]
    async fn precancelled_control_does_not_poll_resolver() {
        let control = control(Duration::from_secs(30));
        control.cancel();
        let resolver = future::poll_fn(|_| -> std::task::Poll<io::Result<Vec<SocketAddr>>> {
            panic!("cancelled resolver was polled")
        });
        assert!(matches!(
            dial_resolved(resolver, control).await,
            Err(DialError::Refused(Refused::Cancelled))
        ));
    }

    #[tokio::test]
    async fn explicit_cancel_wakes_pending_resolver() {
        let control = control(Duration::from_secs(30));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(dial_resolved(
            async move {
                let _ = entered_tx.send(());
                future::pending::<io::Result<Vec<SocketAddr>>>().await
            },
            control.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        control.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(matches!(
            result,
            Ok(Ok(Err(DialError::Refused(Refused::Cancelled))))
        ));
    }

    #[tokio::test]
    async fn explicit_cancel_drops_pending_connect_and_does_not_try_next_address() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let control = control(Duration::from_secs(30));
        let addresses = vec![
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let calls = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(dial_with(future::ready(Ok(addresses)), control.clone(), {
            let calls = calls.clone();
            let dropped = dropped.clone();
            let mut entered_tx = Some(entered_tx);
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                let marker = Dropped(dropped.clone());
                let signal = entered_tx.take();
                Ok(async move {
                    let _marker = marker;
                    if let Some(signal) = signal {
                        let _ = signal.send(());
                    }
                    future::pending::<io::Result<tokio::net::TcpStream>>().await
                })
            }
        }));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        control.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(matches!(
            result,
            Ok(Ok(Err(DialError::Refused(Refused::Cancelled))))
        ));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn absolute_deadline_interrupts_pending_connect() {
        let control = control(Duration::from_millis(25));
        let result = dial_with(
            future::ready(Ok(vec!["127.0.0.1:1".parse().unwrap()])),
            control,
            |_| Ok(future::pending::<io::Result<tokio::net::TcpStream>>()),
        )
        .await;
        assert!(matches!(result, Err(DialError::Refused(Refused::Deadline))));
    }

    #[tokio::test]
    async fn numeric_host_uses_real_resolver_and_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dialed = dial("127.0.0.1", address.port(), control(Duration::from_secs(5)))
            .await
            .unwrap();
        let (_peer, _) = listener.accept().unwrap();
        drop(dialed);
    }

    #[tokio::test]
    async fn cancellation_before_addresses_prevents_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let control = control(Duration::from_secs(5));
        control.cancel();
        let result = dial_resolved(
            future::ready(Ok(vec![listener.local_addr().unwrap()])),
            control,
        )
        .await;
        assert!(matches!(
            result,
            Err(DialError::Refused(Refused::Cancelled))
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn falls_back_and_drop_shuts_down_the_registered_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = TcpListener::bind("127.0.0.1:0").unwrap();
        let refused_address = refused.local_addr().unwrap();
        drop(refused);
        let address = listener.local_addr().unwrap();
        let control = control(Duration::from_secs(5));
        let dialed = dial_resolved(
            future::ready(Ok(vec![refused_address, address])),
            control.clone(),
        )
        .await
        .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        drop(dialed);
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(control.try_effect(|| ()), Err(Refused::Cancelled));
    }

    #[tokio::test]
    async fn deadline_covers_resolution_without_connecting() {
        let control = control(Duration::from_millis(25));
        let result = dial_resolved(
            future::pending::<io::Result<Vec<SocketAddr>>>(),
            control.clone(),
        )
        .await;
        assert!(matches!(result, Err(DialError::Refused(Refused::Deadline))));
        assert_eq!(control.try_effect(|| ()), Err(Refused::Cancelled));
    }

    #[tokio::test]
    async fn dropping_during_resolution_cancels_before_any_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let control = control(Duration::from_secs(5));
        let (tx, rx) = tokio::sync::oneshot::channel::<io::Result<Vec<SocketAddr>>>();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(dial_resolved(
            async move {
                let _ = entered_tx.send(());
                rx.await
                    .unwrap_or_else(|_| Err(io::ErrorKind::Interrupted.into()))
            },
            control.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert!(tx.send(Ok(vec![listener.local_addr().unwrap()])).is_err());
        assert_eq!(control.try_effect(|| ()), Err(Refused::Cancelled));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
