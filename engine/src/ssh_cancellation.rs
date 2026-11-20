//! Cancellation/side-effect ordering for managed SSH establishment.
//!
//! This is only a synchronization primitive, not a cancellation-safe dialer.
//! The dialer and supervised worker share this control. It cannot interrupt an
//! already-started resolver or bound all I/O or lock waits.

use std::{
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

/// A single absolute deadline and a cancellation state shared with the worker.
#[derive(Clone)]
pub(crate) struct EstablishmentControl {
    shared: Arc<Shared>,
}

struct Shared {
    deadline: Instant,
    cancelled: Mutex<bool>,
    cancellation_requested: AtomicBool,
    socket_shutdown: AtomicBool,
    #[cfg(test)]
    socket_shutdown_count: std::sync::atomic::AtomicUsize,
    notification: tokio::sync::Notify,
    socket: Mutex<SocketState>,
}

#[derive(Default)]
struct SocketState {
    cancelled: bool,
    socket: Option<TcpStream>,
}

/// The reason a new effect cannot be started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refused {
    Cancelled,
    Deadline,
    Poisoned,
    SocketRegistered,
}

impl EstablishmentControl {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            shared: Arc::new(Shared {
                deadline,
                cancelled: Mutex::new(false),
                cancellation_requested: AtomicBool::new(false),
                socket_shutdown: AtomicBool::new(false),
                #[cfg(test)]
                socket_shutdown_count: std::sync::atomic::AtomicUsize::new(0),
                notification: tokio::sync::Notify::new(),
                socket: Mutex::new(SocketState::default()),
            }),
        }
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.shared.deadline
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.shared.cancellation_requested.load(Ordering::SeqCst)
    }

    pub(crate) async fn cancelled(&self) {
        let notification = self.shared.notification.notified();
        tokio::pin!(notification);
        notification.as_mut().enable();
        if !self.is_cancelled() {
            notification.await;
        }
    }

    /// Commit cancellation without waiting for a worker's ordering lock.
    /// Effects that already passed their check are committed; later checks fail.
    /// Notification does not expose a borrow guard, but waking tasks and the
    /// notification's internal synchronization are not a wait-free guarantee.
    /// Callers must not attach blocking or untrusted wakers.
    pub(crate) fn request_cancel(&self) {
        self.shared
            .cancellation_requested
            .store(true, Ordering::SeqCst);
        self.shared.notification.notify_waiters();
        // Never wait for registration or the worker's ordering lock. A
        // successful take also lets explicit cancellation interrupt an already
        // committed session, without waiting for its owner to be dropped.
        if let Ok(mut state) = self.shared.socket.try_lock() {
            state.cancelled = true;
            let registered = state.socket.take();
            drop(state);
            if let Some(socket) = registered {
                self.shutdown_socket(&socket);
            }
        }
    }

    /// Issue socket shutdown once, regardless of which cancellation path wins.
    pub(crate) fn shutdown_socket(&self, socket: &TcpStream) {
        if !self.shared.socket_shutdown.swap(true, Ordering::SeqCst) {
            #[cfg(test)]
            self.shared
                .socket_shutdown_count
                .fetch_add(1, Ordering::SeqCst);
            let _ = socket.shutdown(Shutdown::Both);
        }
        // Opportunistically release the registered duplicate without waiting
        // for a concurrent cancellation/registration holder.
        if let Ok(mut state) = self.shared.socket.try_lock() {
            state.cancelled = true;
            let registered = state.socket.take();
            drop(state);
            drop(registered);
        }
    }

    #[cfg(test)]
    pub(crate) fn shutdown_count(&self) -> usize {
        self.shared.socket_shutdown_count.load(Ordering::SeqCst)
    }

    /// Cancel and wait for any effect that already won the ordering lock.
    ///
    /// On return, no subsequent `try_effect` may start. Cancellation cannot
    /// retract an effect already issued. A poisoned lock also fails closed.
    pub(crate) fn cancel(&self) {
        self.request_cancel();
        // Shutdown must precede waiting for the effect lock: an in-flight
        // effect may itself be blocked in socket I/O while holding that lock.
        let mut socket = self
            .shared
            .socket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        socket.cancelled = true;
        let registered = socket.socket.take();
        drop(socket);
        if let Some(socket) = registered {
            self.shutdown_socket(&socket);
        }
        let mut cancelled = self
            .shared
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cancelled = true;
    }

    /// Register an owned duplicate of the worker's socket for shutdown.
    ///
    /// Registration and cancellation are ordered even if cancellation starts
    /// while an effect owns the ordering lock. Only one socket may be registered;
    /// callers must not replace a live socket behind the control's back. On
    /// refusal the caller must discard its worker socket as well.
    pub(crate) fn register_socket(&self, socket: TcpStream) -> Result<(), Refused> {
        self.try_effect(|| {
            let mut state = self.shared.socket.lock().map_err(|_| Refused::Poisoned)?;
            if state.cancelled {
                drop(state);
                self.shutdown_socket(&socket);
                return Err(Refused::Cancelled);
            }
            if state.socket.is_some() {
                return Err(Refused::SocketRegistered);
            }
            state.socket = Some(socket);
            Ok(())
        })?
    }

    /// Atomically check cancellation and the original deadline, then issue one
    /// effect while holding the same lock used by `cancel`.
    ///
    /// The closure must issue at most one effect and must not recursively use
    /// this control. It must not wait on unbounded I/O: cancellation waits for
    /// the closure. Callers still need bounded file/lock operations and a
    /// reviewed policy for any non-socket side effects.
    pub(crate) fn try_effect<T>(&self, effect: impl FnOnce() -> T) -> Result<T, Refused> {
        self.try_ordered_effect(true, effect)
    }

    /// Order a nonblocking session effect against cancellation, without the
    /// establishment deadline, which no longer applies after session commit.
    pub(crate) fn try_session_effect<T>(&self, effect: impl FnOnce() -> T) -> Result<T, Refused> {
        self.try_ordered_effect(false, effect)
    }

    fn try_ordered_effect<T>(
        &self,
        establishment: bool,
        effect: impl FnOnce() -> T,
    ) -> Result<T, Refused> {
        let cancelled = self
            .shared
            .cancelled
            .lock()
            .map_err(|_| Refused::Poisoned)?;
        if *cancelled || self.shared.cancellation_requested.load(Ordering::SeqCst) {
            return Err(Refused::Cancelled);
        }
        if establishment && Instant::now() >= self.shared.deadline {
            return Err(Refused::Deadline);
        }
        Ok(effect())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
        sync::{Arc, Barrier, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use super::{EstablishmentControl, Refused};

    fn control() -> EstablishmentControl {
        EstablishmentControl::new(Instant::now() + Duration::from_secs(60))
    }

    #[test]
    fn shutdown_unblocks_in_flight_socket_effect_before_cancel_waits() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let control = control();
        control
            .register_socket(client.try_clone().unwrap())
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = {
            let control = control.clone();
            thread::spawn(move || {
                let result = control.try_effect(|| {
                    entered_tx.send(()).unwrap();
                    client.read(&mut [0])
                });
                done_tx.send(result).unwrap();
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let canceller = {
            let control = control.clone();
            thread::spawn(move || control.cancel())
        };
        let read = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancellation did not shut down the socket before waiting on the effect lock");
        assert!(
            !matches!(read, Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut)
        );
        worker.join().unwrap();
        canceller.join().unwrap();
        assert_eq!(control.try_effect(|| ()), Err(Refused::Cancelled));
    }

    #[test]
    fn socket_registration_refuses_replacement_and_after_cancellation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let control = control();
        control
            .register_socket(client.try_clone().unwrap())
            .unwrap();
        assert_eq!(
            control.register_socket(client.try_clone().unwrap()),
            Err(Refused::SocketRegistered)
        );
        control.cancel();
        assert_eq!(control.register_socket(client), Err(Refused::Cancelled));
    }

    #[test]
    fn cancellation_that_wins_prevents_the_effect() {
        let control = control();
        let ready = Arc::new(Barrier::new(2));
        let cancelled = Arc::new(Barrier::new(2));
        let worker = {
            let control = control.clone();
            let ready = Arc::clone(&ready);
            let cancelled = Arc::clone(&cancelled);
            thread::spawn(move || {
                ready.wait();
                cancelled.wait();
                control.try_effect(|| panic!("cancelled effect started"))
            })
        };
        ready.wait();
        control.cancel();
        cancelled.wait();
        assert_eq!(worker.join().unwrap(), Err(Refused::Cancelled));
    }

    /// Cancellation cannot finish while an effect that won the ordering lock is
    /// still running.
    ///
    /// The canceller reports immediately before entering `cancel`, then reports
    /// again only after it returns. The effect stays parked in the closure, so
    /// the second report must not arrive. Releasing the effect is the only thing
    /// that may let `cancel` return; a `cancel` that sets the flag and returns
    /// without waiting fails here rather than passing on the eventual refusal.
    #[test]
    fn cancellation_cannot_complete_before_an_in_flight_effect_is_released() {
        let control = control();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = {
            let control = control.clone();
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            thread::spawn(move || {
                control.try_effect(|| {
                    entered.wait();
                    release.wait();
                    42
                })
            })
        };
        entered.wait();

        let (cancel_started, cancel_entered) = mpsc::channel();
        let (cancel_returned, cancel_completed) = mpsc::channel();
        let canceller = {
            let control = control.clone();
            thread::spawn(move || {
                cancel_started.send(()).unwrap();
                control.cancel();
                cancel_returned.send(()).unwrap();
            })
        };

        cancel_entered.recv().unwrap();
        assert_eq!(
            cancel_completed.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "cancel returned while the effect that won the ordering lock was still running"
        );
        assert!(
            !worker.is_finished(),
            "the effect left the closure before cancellation completion was observed"
        );

        release.wait();
        assert_eq!(worker.join().unwrap(), Ok(42));
        cancel_completed
            .recv_timeout(Duration::from_secs(5))
            .expect("cancel did not return after the in-flight effect released");
        canceller.join().unwrap();
        assert_eq!(control.try_effect(|| 99), Err(Refused::Cancelled));
    }

    #[test]
    fn expired_deadline_refuses_effect_without_running_it() {
        let control = EstablishmentControl::new(Instant::now());
        assert_eq!(
            control.try_effect(|| panic!("expired effect started")),
            Err(Refused::Deadline)
        );
    }

    #[test]
    fn poison_refuses_subsequent_effects() {
        let control = control();
        let worker = control.clone();
        assert!(
            thread::spawn(move || {
                let _ = worker.try_effect(|| panic!("poison test"));
            })
            .join()
            .is_err()
        );
        assert_eq!(control.try_effect(|| ()), Err(Refused::Poisoned));
        control.cancel();
        assert_eq!(control.try_effect(|| ()), Err(Refused::Poisoned));
    }
}
