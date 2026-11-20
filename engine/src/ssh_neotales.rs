//! `docker system dial-stdio` over a session opened by `neotales-ssh`.
//!
//! The establishment gate is open by default. Requests can resolve, dial, read
//! `known_hosts` and identity material, handshake, authenticate, run
//! `docker system dial-stdio` remotely and carry Engine requests. An explicit
//! per-client `require_closed` policy refuses before DNS, file or network work.
//!
//! The post-gate path uses the supervised worker. Filesystem reads can block
//! indefinitely: the capacity-limited registry retains a stalled reader while
//! cancellation/deadline returns to the caller. A committed read cannot be
//! retracted and a permanently stalled reader can exhaust that registry;
//! neither thread termination nor bounded syscall duration is promised. The
//! default gate does not promise bounded filesystem syscall duration.
//!
//! This is the same mechanism as [`super::ssh_dial_stdio`] — run
//! `docker system dial-stdio` on the far end and speak Engine HTTP over its
//! standard streams — with the local end implemented by this repository's own
//! SSH crate rather than by the `ssh` binary.
//!
//! # Why this is the same transport and not a second one
//!
//! The output of this module is a [`StreamFactory`], exactly like the native
//! `ssh` binary's. Everything above it — the versioned URI, the request head,
//! `engine_result`, `FrameStream`, `escape_path_segment` — is the one
//! implementation in [`crate::raw::transport`]. There is no SSH-shaped status
//! mapping and no SSH-shaped stream decoder here, because a byte stream that
//! carries HTTP is not a different protocol once it is carrying HTTP.
//!
//! # The blocking part, and why it is only the blocking part
//!
//! `neotales-ssh` is synchronous. DNS and TCP dialing run asynchronously;
//! the SSH handshake, user authentication, channel open and `exec` run on an
//! owned, capacity-limited worker thread.
//!
//! Once the `exec` is accepted the shared socket is switched to non-blocking
//! mode and the transport is driven from the async task. That is not a
//! convenience: `neotales-ssh`'s packet layer documents that a stream "may
//! return `WouldBlock` after any prefix. In that case the current buffer,
//! suite, and sequence remain in place and the caller can retry the same
//! operation" (`neotales_ssh::transport`, on
//! `read_protected_packet_buffered`). That is what makes a non-blocking socket
//! usable at all.
//!
//! After setup an owned pump drives an
//! [`neotales_ssh::channel::OwnedChannelDriver`], which keeps the admitted
//! packet, its reserved window, and any required protocol reply owned across
//! `WouldBlock`. The application's poll methods only copy bytes into one
//! bounded admission slot, observe completion, register a waker, and notify
//! the pump; they never drive the channel. That is the ownership the earlier
//! duplex lacked, and it is why this phase can answer setup requests without
//! dropping them. A peer-initiated rekey is retained and
//! advanced in bounded steps, but unsupported or malformed rekey proposals
//! still fail the driver closed; once the shared eight-entry reply FIFO fills,
//! reads stop until a reply completes, so a peer that withholds reads can
//! still stop read progress — the pump retains every admitted reply and
//! fails that session closed once the socket accepts no write bytes for
//! the configured write-inactivity bound while a reply or retained peer rekey is outstanding;
//! a peer interleaving control traffic with a blocked write therefore causes a
//! bounded failure, not a hang. Password authentication remains unverified
//! against a real server: the internal fixture mounts the Docker socket and
//! is excluded from the default gate. Native `ssh` is a separate, explicit
//! choice, never a silent downgrade after managed failure.
//!
//! Three consequences follow, and all three are load-bearing:
//!
//! * The setup path reads through `ChannelConnection`, whose errors collapse a
//!   retryable `WouldBlock` into `ChannelError::Transport`, indistinguishable
//!   from a dead connection. [`WouldBlock`] records the blocked direction so
//!   setup can tell a stall from a failure; the post-setup driver preserves
//!   `TransportError::Io`, so the pump classifies on the error kind and uses
//!   the record only as a fallback. Guessing would turn every retryable stall
//!   into a dead connection.
//! * A write refused for a *window* is not a transport failure either. The
//!   remote window is SSH flow control and the answer arrives later as a
//!   `WindowAdjusted` event on the same session, so the pump reads inbound
//!   events until the write can proceed. A blocked window-credit write is
//!   handled the same way while the reply FIFO has room: the pump
//!   reads one inbound packet behind the active adjustment. At capacity,
//!   it waits for writability instead. Ordinary reads also stop for an
//!   undelivered event or retained peer rekey. A blocked write with a reply or
//!   rekey outstanding remains bounded: if
//!   the socket accepts no write bytes for the configured bound, the session
//!   fails closed. Buffered inbound bytes may be waiting, but they are not
//!   readable in that state.
//! * SSH windows are finite. The duplex grants the remote more room as bytes are
//!   handed to the caller, because granting on arrival instead would stall any
//!   response larger than one window at exactly the window boundary — which for
//!   a `docker build` or a long `pull` is every response of interest.
//!
//! # The credential is the caller's, and is not asked for
//!
//! This client speaks a transport, not a console, so an SSH password and the
//! passphrase on an encrypted identity file are both **values the caller
//! supplies**, wrapped in [`SshSecret`]. A library that blocked on a terminal
//! prompt inside a request would hang in exactly the situation a caller cannot
//! interrupt — a daemon, a CI job, a server — and the secret belongs to whoever
//! is driving the program, not to a request already in flight on someone else's
//! task.
//!
//! # What is not here, and why
//!
//! **Connection reuse.** Each request gets a whole connection, handshake,
//! authentication, session, and `exec`, which is heavier per request than the
//! native `ssh` binary reusing OpenSSH multiplexing. Reusing the *connection*
//! and opening a fresh channel per request is the shape that fits a
//! `StreamFactory` — which is called once per request and hands back a duplex no
//! other request holds — and it is not implemented here.
//!
//! `ChannelConnection` now retires a channel once both sides have sent
//! `SSH_MSG_CHANNEL_CLOSE`, so the channel-table ceiling and the
//! duplicate-remote-identifier failure recorded against an earlier revision are
//! no longer the reason. What remains is that this module's post-setup owner is
//! a single-channel `OwnedChannelDriver`: a pooled target would need a
//! per-request driver handoff, a policy for connection-level requests that
//! outlive one request, and its own tests. Reported rather than worked around
//! here, because `neotales-ssh` is not this change's to modify.
//!
//! **Agent and ECDSA identity keys.** `PublicKeySigner` and `OpenSshPrivateKey`
//! are closed enums carrying `Ed25519` and `Rsa` and nothing else, so an
//! agent-held identity and an `ecdsa-sha2-nistp256` key file are both
//! inexpressible from here — there is no constructor to call, and a
//! `cargo build` says so. `neotales_ssh::agent::AgentClient` can already list
//! identities and sign, and `neotales_ssh::ecdsa_hostkey::EcdsaSigner` can
//! already sign, so neither needs new cryptography: a variant on each enum and
//! the plumbing to fill it is the whole of it. Also reported rather than worked
//! around.
//!
//! **A second stream decoder.** Nothing here decodes the Engine's frames. The
//! `FrameStream` in [`crate::raw`] is the only one, and a multiplexed scheme
//! carrying several requests over one channel would have needed a second.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream as StdTcpStream;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use neotales_ssh::auth::{ClientAuthMethod, ClientAuthenticator, PublicKeySigner, RsaAuthSigner};
use neotales_ssh::channel::{
    ChannelConnection, ChannelError, ChannelEvent, ChannelId, ChannelTransport,
    INITIAL_CHANNEL_WINDOW, MAX_CHANNEL_PACKET_SIZE, OwnedChannelDriver, OwnedChannelEofId,
    OwnedChannelError, OwnedChannelInbound, OwnedChannelWriteId, OwnedWindowAdjustmentId,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use neotales_ssh::client::ClientConfig;
use neotales_ssh::ecdsa_hostkey::EcdsaSigner;
use neotales_ssh::hostkey::{Ed25519PublicKey, Ed25519Signer};
use neotales_ssh::known_hosts::{KnownHosts, KnownHostsStatus};
use neotales_ssh::openssh_key::{OpenSshKeyError, OpenSshPrivateKey};
use neotales_ssh::session::ClientSessions;
use neotales_ssh::transport::{ClientTransport, TransportError};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use zeroize::Zeroizing;

use super::ssh_auth::{ManagedSshEstablishmentFailure, SshIdentity, SshSecret};
use super::ssh_cancellation::{EstablishmentControl, Refused};
use super::ssh_connect::{DialError, dial};
use super::ssh_dial_stdio::{DIAL_STDIO, DIAL_STDIO_AUTHORITY, SshDestination};
use super::ssh_worker::{self, DeadlineSocket};
use crate::Error;
use crate::raw::{Duplex, RawTarget, StreamFactory};

/// The most protocol steps one pump step may take before it yields to the
/// executor. A peer that keeps sending control traffic must not be able to
/// monopolise a task.
const MAX_PROTOCOL_STEPS_PER_POLL: usize = 8;
const REPLY_CAPACITY: usize = 8;
// settle() can drain the entire bounded FIFO, including its active front.
const _: () = assert!(MAX_PROTOCOL_STEPS_PER_POLL >= REPLY_CAPACITY);

/// The most application bytes the single outbound admission slot may hold.
///
/// One channel-data packet is bounded by the protocol's packet size, so this
/// slot holds at most one such packet. `poll_write` copies into it and never
/// keeps a reference to the caller's buffer.
const MAX_ADMISSION_BYTES: usize = MAX_CHANNEL_PACKET_SIZE as usize;

/// Default write-inactivity bound; callers can choose another duration.
///
/// While a protocol reply is owed the channel driver refuses further reads.
/// While a peer-initiated rekey is retained behind the active outbound packet,
/// the pump cannot read either until that packet completes. In both states the
/// only local way forward is a socket write, and the peer is the only party
/// that can drain it. Buffered inbound bytes may be waiting, but they are not
/// readable in this state, so reading cannot be the escape.
///
/// The clock restarts on any positive socket byte write, not on a wakeup,
/// writability, or an application notification. A peer that is still accepting
/// bytes is making progress and is not failed; a peer that accepts a prefix and
/// then stops still reaches the bound. On expiry the session fails closed with
/// [`WRITE_STALL_MESSAGE`] instead of leaving a request that never returns.
///
/// This is an inactivity bound, not a request timeout.
pub(crate) const WRITE_STALL_BOUND: Duration = Duration::from_secs(120);

/// The stable diagnostic for a session failed by write inactivity.
///
/// It states only what the pump observed: no write bytes were accepted while a
/// reply or rekey was outstanding. It does not claim the peer stopped reading,
/// which the pump cannot know, and it never carries a credential, a hostname, a
/// path, or peer-controlled bytes.
const WRITE_STALL_MESSAGE: &str = concat!(
    "the SSH session cannot make progress: the socket accepted no write bytes ",
    "while a reply or rekey was outstanding",
);

#[cfg(test)]
tokio::task_local! {
    pub(crate) static OPEN_TIMEOUT_OBSERVER: tokio::sync::mpsc::UnboundedSender<Duration>;
    // First effectful establishment boundary, before DNS, files or sockets.
    static TEST_ESTABLISHMENT_START: Arc<std::sync::atomic::AtomicUsize>;
    pub(crate) static TEST_NATIVE_CALLS: Arc<std::sync::atomic::AtomicUsize>;
}

/// How the managed SSH client opens its session.
///
/// A struct, not a parameter list: this is the shape a caller has to describe
/// an `ssh://` endpoint, and it is the shape that grows when an agent or a
/// password provider is wired to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedSshOptions {
    /// The host to connect to.
    pub(crate) host: String,
    /// The TCP port to connect to.
    pub(crate) port: u16,
    /// The login name to authenticate as.
    pub(crate) user: String,
    /// The OpenSSH known-hosts token for `host` and `port`.
    pub(crate) host_token: String,
    /// The credential to authenticate with.
    pub(crate) identity: SshIdentity,
    /// The pre-provisioned known-hosts file checked without modification.
    pub(crate) known_hosts_path: std::path::PathBuf,
    /// Per-open establishment budget, distinct from request time remaining.
    pub(crate) establishment_timeout: Duration,
    /// Maximum write inactivity while a reply or rekey is blocked.
    pub(crate) write_inactivity_timeout: Duration,
    /// Optional connect-through-response-head deadline, excluding the body.
    pub(crate) request_deadline: Option<Duration>,
    /// Explicitly refuse establishment before any DNS, file or network work.
    pub(crate) require_closed: bool,
}

impl ManagedSshOptions {
    /// Reads the managed options out of an `ssh://` address, a credential, and
    /// a known-hosts path.
    ///
    /// # Errors
    ///
    /// Returns an error naming the missing part when the address is not an
    /// `ssh://` endpoint or names no host, when it names no login name, and when
    /// no known-hosts file is given. Each of the two is refused with its own
    /// reason rather than as one "incomplete", because a caller who supplied one
    /// of them needs to know which is absent.
    ///
    /// A credential is not defaulted here, but it is also not *required*: a
    /// caller who named none is refused by the builder before this is reached,
    /// with a message naming the three ways to set one. Refusing it here as
    /// "incomplete" would report a missing password as a malformed endpoint.
    pub(crate) fn from_endpoint(
        address: &str,
        identity: SshIdentity,
        known_hosts_path: Option<&Path>,
        establishment_timeout: Duration,
    ) -> Result<Self, Error> {
        let destination = SshDestination::parse(address)?;
        let user = destination.user.ok_or_else(|| {
            Error::invalid_input(format!(
                "the managed Engine SSH client authenticates as a named user and \
                 '{address}' names none"
            ))
        })?;
        let known_hosts_path = known_hosts_path.ok_or_else(|| {
            Error::invalid_input(format!(
                "the managed Engine SSH client checks the host key against a known-hosts \
                 file and '{address}' names none"
            ))
        })?;
        let options = Self {
            host: destination.host,
            port: destination.port,
            user,
            host_token: destination.host_token,
            identity,
            known_hosts_path: known_hosts_path.to_path_buf(),
            establishment_timeout,
            write_inactivity_timeout: WRITE_STALL_BOUND,
            request_deadline: None,
            require_closed: false,
        };
        options.validate()?;
        Ok(options)
    }

    /// Reject durations that cannot be used as deadlines, naming the setting.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        for (name, value) in [
            ("establishment_timeout", Some(self.establishment_timeout)),
            (
                "write_inactivity_timeout",
                Some(self.write_inactivity_timeout),
            ),
            ("request_deadline", self.request_deadline),
        ] {
            if let Some(value) = value
                && (value.is_zero() || Instant::now().checked_add(value).is_none())
            {
                return Err(Error::invalid_input(format!(
                    "{name} must be nonzero and in range"
                )));
            }
        }
        Ok(())
    }
}

/// Builds the owned `RawTarget` for the managed SSH client.
///
/// The factory opens a whole new TCP connection, handshake, authentication,
/// session, and `exec` for every request. That is heavier per request than the
/// native `ssh` binary, which at least reuses the user's connection
/// multiplexing, and it is also the property that makes the target stateless —
/// and statelessness is what lets two requests share one
/// [`RawEngine`](crate::raw::RawEngine) with no coordination between them.
///
/// A connect, handshake, authentication, or `exec` failure is reported by the
/// first request that needed it, which is where a user sees it against the
/// request they made.
pub(crate) fn managed_ssh_target(options: ManagedSshOptions) -> RawTarget {
    let authority = DIAL_STDIO_AUTHORITY.to_owned();
    let factory = StreamFactory::from_fn(move || {
        let options = options.clone();
        async move { open(&options).await }
    })
    .with_managed_ssh_policy();
    RawTarget::Stream {
        authority,
        open: factory,
    }
}

/// Opens one SSH session running `docker system dial-stdio`.
pub(crate) async fn open(options: &ManagedSshOptions) -> Result<Box<dyn Duplex>, Error> {
    #[cfg(test)]
    let _ = OPEN_TIMEOUT_OBSERVER.try_with(|observer| observer.send(options.establishment_timeout));
    // Explicit closure must precede even the first effectful establishment poll.
    managed_establishment_gate(options.require_closed)?;
    // Final public establishment boundary: preserve only locally typed
    // classifications, never a worker/factory source chain or peer text.
    open_supervised(options).await.map_err(|error| {
        error.withhold_transport(ESTABLISHMENT_FAILURE_MESSAGE, ESTABLISHMENT_TIMEOUT_MESSAGE)
    })
}

async fn open_supervised(options: &ManagedSshOptions) -> Result<Box<dyn Duplex>, Error> {
    open_supervised_with_register(options, TcpStream::from_std).await
}

async fn open_supervised_with_register(
    options: &ManagedSshOptions,
    register: impl FnOnce(StdTcpStream) -> std::io::Result<TcpStream>,
) -> Result<Box<dyn Duplex>, Error> {
    #[cfg(test)]
    let _ = TEST_ESTABLISHMENT_START.try_with(|starts| starts.fetch_add(1, Ordering::SeqCst));
    let write_inactivity_timeout = options.write_inactivity_timeout;
    let deadline = Instant::now()
        .checked_add(options.establishment_timeout)
        .ok_or_else(|| Error::invalid_input("managed SSH deadline is out of range"))?;
    let control = EstablishmentControl::new(deadline);
    let dialed = dial(&options.host, options.port, control)
        .await
        .map_err(|error| dial_error("dial managed SSH", &error))?;
    let readiness = dialed
        .readiness_clone()
        .map_err(|error| dial_error("clone managed SSH readiness socket", &error))?;
    let readiness_slot = Arc::new(OnceLock::new());
    let worker_readiness = Arc::clone(&readiness_slot);
    let write_progress = Arc::new(AtomicU64::new(0));
    let worker_progress = Arc::clone(&write_progress);
    let options = options.clone();
    let established = ssh_worker::supervise(
        dialed,
        options.establishment_timeout,
        &ssh_worker::WORKERS,
        move |socket, control| {
            let check = || control.try_effect(|| ()).map_err(ssh_worker::refused);
            // These read-only operations may block even after cancellation.
            // The registry retains the worker; checks gate subsequent effects.
            check()?;
            let known =
                load_known_hosts(&options.known_hosts_path).map_err(|error| io_error(&error))?;
            check()?;
            let methods = auth_methods(&options.identity).map_err(|error| io_error(&error))?;
            check()?;
            let would_block = WouldBlock::default();
            let transport = checked_handshake(
                Socket {
                    inner: socket,
                    would_block: Arc::clone(&would_block.0),
                    // Production gives both directions the same registered
                    // socket. The split exists so a test can put write
                    // readiness on a separate loopback socket without
                    // changing what production waits on.
                    read_readiness: Arc::clone(&worker_readiness),
                    write_readiness: Arc::clone(&worker_readiness),
                    write_progress: worker_progress,
                },
                &known,
                &options.known_hosts_path,
                &options.host_token,
                &options.host,
                options.port,
            )
            .map_err(|error| io_error(&error))?;
            check()?;
            let parts = authenticate_and_exec(transport, &methods, &options, would_block)
                .map_err(|error| io_error(&error))?;
            check()?;
            Ok(parts)
        },
    )
    .await
    .map_err(|error| {
        if let Some(kind) = crate::transport_timeout_in(&error) {
            return Error::transport_timeout(kind, ESTABLISHMENT_TIMEOUT_MESSAGE);
        }
        if let Some(reason) = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ManagedSshEstablishmentFailure>())
        {
            return Error::ssh_establishment_failed(*reason);
        }
        // Preserve only our safe local classification, not an arbitrary
        // callback error or text supplied by the peer.
        match error
            .get_ref()
            .and_then(|source| source.downcast_ref())
            .copied()
        {
            Some(reason) => Error::ssh_host_key_rejected(reason),
            None => Error::transport(ESTABLISHMENT_FAILURE_MESSAGE),
        }
    })?;
    finish_session(
        established,
        readiness,
        &readiness_slot,
        write_progress,
        write_inactivity_timeout,
        register,
    )
}

const ESTABLISHMENT_TIMEOUT_MESSAGE: &str =
    "managed SSH establishment deadline was observed; peer text withheld";
const ESTABLISHMENT_FAILURE_MESSAGE: &str = "managed SSH establishment failed; peer text withheld";

fn dial_error(what: &str, error: &DialError) -> Error {
    if matches!(error, DialError::Refused(Refused::Deadline)) {
        Error::transport_timeout(
            crate::TransportTimeoutKind::ManagedSshEstablishment,
            ESTABLISHMENT_TIMEOUT_MESSAGE,
        )
    } else {
        Error::transport(format!("{what}: {error:?}"))
    }
}

fn finish_session(
    mut established: ssh_worker::Established<SessionParts<Socket<DeadlineSocket>>>,
    readiness: StdTcpStream,
    readiness_slot: &OnceLock<Arc<TcpStream>>,
    write_progress: Arc<AtomicU64>,
    write_inactivity_timeout: Duration,
    register: impl FnOnce(StdTcpStream) -> std::io::Result<TcpStream>,
) -> Result<Box<dyn Duplex>, Error> {
    let readiness = Arc::new(
        register(readiness)
            .map_err(|error| transport_error("register the Engine SSH socket", error))?,
    );
    readiness_slot
        .set(Arc::clone(&readiness))
        .map_err(|_| Error::transport("SSH readiness already registered"))?;
    let early = established.take_early();
    let mut inbound = InboundBuffer::default();
    inbound.push(&early)?;
    // The duplex keeps its own handle on the session's cancellation state. The
    // guard that owns the socket moves into the shared driver, where the pump
    // can hold it alive after the duplex is gone.
    let control = established.control();
    let shared = Arc::new(Mutex::new(SharedDriver::new(established, inbound)));
    let notify = Arc::new(Notify::new());
    let pump = tokio::spawn(pump(
        Arc::downgrade(&shared),
        // Production waits on the same registered SSH socket in both
        // directions. Passing it twice is the pre-split behaviour.
        Arc::downgrade(&readiness),
        Arc::downgrade(&readiness),
        Arc::clone(&notify),
        write_progress,
        write_inactivity_timeout,
    ));
    Ok(Box::new(SessionDuplex {
        shared,
        control,
        _read_readiness: Arc::clone(&readiness),
        _write_readiness: readiness,
        notify,
        pump,
    }))
}

/// The stable safe diagnostic returned while the managed SSH establishment gate
/// is closed.
///
/// This is the single source of the text. The facade returns the same error
/// through [`managed_establishment_gate`], so the migration note and the
/// compatibility table cannot drift from the transport's own diagnostic.
pub(crate) const MANAGED_SSH_GATE_MESSAGE: &str =
    "managed SSH establishment is explicitly closed by client policy";

/// The single authoritative managed-SSH establishment gate.
///
/// Both facade and transport use the same per-client closure decision.
pub(crate) fn managed_establishment_gate(require_closed: bool) -> Result<(), Error> {
    if require_closed {
        Err(Error::transport(MANAGED_SSH_GATE_MESSAGE.to_owned()))
    } else {
        managed_establishment_is_safe()
    }
}

/// Returns whether managed SSH establishment is currently safe.
///
/// The default gate is open. Explicit per-client closure is applied by
/// [`managed_establishment_gate`] in both the facade and transport.
#[allow(
    clippy::unnecessary_wraps,
    reason = "keep the reviewed security gate fallible"
)]
pub(crate) fn managed_establishment_is_safe() -> Result<(), Error> {
    Ok(())
}

/// The unique packet or control reply being written, if any.
///
/// `WouldBlock` leaves the packet and its reserved credit owned by the driver.
/// The identifier is retained here so the next poll resumes that exact packet
/// rather than sealing a second one or dropping the bytes.
#[derive(Clone, Debug)]
enum Active {
    None,
    Data { id: OwnedChannelWriteId },
    Adjustment { id: OwnedWindowAdjustmentId },
    Eof { id: OwnedChannelEofId },
    ReplyQueued(OwedReply),
    ReplyWriting(OwedReply),
}

/// The one protocol reply this session owes and has not finished writing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwedReply {
    Pong,
    GlobalFailure,
    ChannelFailure(ChannelId),
    OpenRejection(ChannelId),
    CloseReply(ChannelId),
}

/// What one step of the owned channel driver achieved.
#[derive(Debug)]
pub(super) enum Progress {
    /// One complete inbound channel-data packet.
    Data(Vec<u8>),
    /// Progress with no bytes for the caller.
    Moved,
    /// One admitted outbound packet was written; the count is its payload size.
    Wrote(usize),
    /// The remote window is zero, so the caller must pump inbound events.
    NoWindow,
    /// The socket could not make progress in this direction.
    Blocked(BlockedOn),
    /// The remote half-closed its side. Local writes may continue until this
    /// side sends EOF, and the peer's later CLOSE still has to be answered.
    Eof,
    /// The peer closed the session channel and its close was answered.
    Closed,
    /// The bounded protocol-step budget was reached. The caller must wake the
    /// task and retry rather than monopolising the executor.
    Yield,
    /// Logical capacity backpressure; no socket operation was attempted.
    Backpressured,
}

/// One session channel owned by [`OwnedChannelDriver`] after setup.
///
/// The driver is the only writer of protected packets once establishment
/// succeeds. This type adds the small amount of state the async duplex needs on
/// top of it: early bytes consumed during setup, the reply currently being
/// written, and the bounded mirror of the driver's reply FIFO.
pub(super) struct SessionParts<T> {
    driver: OwnedChannelDriver<T>,
    session: ChannelId,
    would_block: WouldBlock,
    /// Channel data the peer sent before it accepted `exec`.
    early: Vec<u8>,
    /// The unique active writer; an active reply also remains at the FIFO front.
    active: Active,
    replies: VecDeque<OwedReply>,
    /// Inbound bytes consumed but not yet credited back to the remote.
    pending_grant: u32,
    /// This side sent its half-close EOF. Writes are no longer legal, reads are.
    local_eof_sent: bool,
    /// The peer closed the channel and its close reply has been sent.
    close_pending: bool,
}

enum ReadMode {
    Idle,
    Data(OwnedChannelWriteId),
    Adjustment(OwnedWindowAdjustmentId),
    Eof(OwnedChannelEofId),
}

impl<T: Read + Write> SessionParts<T> {
    /// Takes the channel data the peer sent before accepting `exec`.
    pub(super) fn take_early(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.early)
    }

    /// The remote's remaining receive window and maximum packet size.
    pub(super) fn limits(&self) -> (u32, u32) {
        self.driver.channel(self.session).map_or((0, 0), |state| {
            (state.remote_window(), state.remote_maximum_packet_size())
        })
    }

    /// The remote's remaining receive window.
    ///
    /// This is a state observation, not a protocol step. `poll_write` uses it
    /// together with the bytes already in the admission slot so the
    /// application cannot enqueue past the remote window.
    pub(super) fn available_window(&self) -> u32 {
        self.limits().0
    }

    /// Whether a new channel-data packet may be admitted now.
    ///
    /// This is a state observation, not a protocol step: the caller uses it to
    /// decide whether `poll_write` may fill the admission slot. Only the pump
    /// calls [`Self::write`], so this never races an admission.
    pub(super) fn accepts_data(&self) -> bool {
        matches!(self.active, Active::None)
            && self.replies.is_empty()
            && !self.close_pending
            && !self.local_eof_sent
            && !self.driver.rekey_active()
    }

    /// Whether the peer's close has been received.
    #[cfg(test)]
    pub(super) fn close_pending(&self) -> bool {
        self.close_pending
    }

    /// Whether the peer's close reply is still owed.
    #[cfg(test)]
    pub(super) fn owed_close_reply(&self) -> bool {
        matches!(
            self.active,
            Active::ReplyQueued(OwedReply::CloseReply(_))
                | Active::ReplyWriting(OwedReply::CloseReply(_))
        ) || self
            .replies
            .iter()
            .any(|reply| matches!(reply, OwedReply::CloseReply(_)))
    }

    /// Whether a reply is queued behind the active writer.
    ///
    /// Test-only observation of the actual pump state. A test uses it to
    /// synchronize on the pump having read a reply-requiring event behind a
    /// blocked adjustment, rather than inferring that from data arrival or
    /// transcript order.
    #[cfg(test)]
    pub(super) fn reply_queued(&self) -> bool {
        self.replies.len()
            > usize::from(matches!(
                self.active,
                Active::ReplyQueued(_) | Active::ReplyWriting(_)
            ))
    }

    /// Whether a protocol reply is queued behind the active writer or is
    /// currently being written.
    ///
    /// At full capacity or during retained rekey the pump cannot escape a
    /// blocked write by reading. The inactivity bound observes this state.
    pub(super) fn reply_outstanding(&self) -> bool {
        !self.replies.is_empty()
            || matches!(
                self.active,
                Active::ReplyQueued(_) | Active::ReplyWriting(_)
            )
    }

    /// Whether the active writer is the blocked window adjustment.
    ///
    /// Test-only companion to [`Self::reply_queued`].
    #[cfg(test)]
    pub(super) fn adjustment_active(&self) -> bool {
        matches!(self.active, Active::Adjustment { .. })
    }

    #[cfg(test)]
    pub(super) fn data_active(&self) -> bool {
        matches!(self.active, Active::Data { .. })
    }

    #[cfg(test)]
    pub(super) fn eof_active(&self) -> bool {
        matches!(self.active, Active::Eof { .. })
    }

    #[cfg(test)]
    pub(super) fn global_reply_writing(&self) -> bool {
        matches!(self.active, Active::ReplyWriting(OwedReply::GlobalFailure))
    }

    #[cfg(test)]
    pub(super) fn channel_reply_writing(&self) -> bool {
        matches!(
            self.active,
            Active::ReplyWriting(OwedReply::ChannelFailure(_))
        )
    }

    #[cfg(test)]
    pub(super) fn open_rejection_writing(&self) -> bool {
        matches!(
            self.active,
            Active::ReplyWriting(OwedReply::OpenRejection(9))
        )
    }

    #[cfg(test)]
    pub(super) fn close_reply_writing(&self) -> bool {
        matches!(self.active, Active::ReplyWriting(OwedReply::CloseReply(_)))
    }

    #[cfg(test)]
    pub(super) fn pong_writing(&self) -> bool {
        matches!(self.active, Active::ReplyWriting(OwedReply::Pong))
    }

    #[cfg(test)]
    pub(super) fn next_is_pong(&self) -> bool {
        let index = usize::from(matches!(
            self.active,
            Active::ReplyQueued(_) | Active::ReplyWriting(_)
        ));
        matches!(self.replies.get(index), Some(OwedReply::Pong))
    }

    #[cfg(test)]
    pub(super) fn session_close_pending_in_driver(&self) -> bool {
        self.driver
            .channel(self.session)
            .is_some_and(|channel| channel.remote_close_received() && !channel.local_close_sent())
            && !self.driver.is_retired_channel(self.session)
    }

    #[cfg(test)]
    pub(super) fn session_retired(&self) -> bool {
        self.driver.channel(self.session).is_none() && self.driver.is_retired_channel(self.session)
    }

    #[cfg(test)]
    pub(super) fn pending_peer_opens(&self) -> usize {
        self.driver.pending_open_count()
    }

    #[cfg(test)]
    pub(super) fn committed_outbound_sequence(&self) -> u32 {
        self.driver.outbound_sequence()
    }

    /// Credits the remote with room for bytes already handed to the caller.
    pub(super) fn credit(&mut self, bytes: u32) {
        self.pending_grant = self.pending_grant.saturating_add(bytes);
    }

    /// Whether one inbound packet can be read behind the active packet.
    pub(super) fn can_read_behind_active(&self) -> bool {
        !self.driver.rekey_active()
            && matches!(
                self.active,
                Active::Data { .. }
                    | Active::Adjustment { .. }
                    | Active::Eof { .. }
                    | Active::ReplyWriting(
                        OwedReply::GlobalFailure
                            | OwedReply::ChannelFailure(_)
                            | OwedReply::OpenRejection(_)
                            | OwedReply::CloseReply(_)
                            | OwedReply::Pong
                    )
            )
            && self.replies.len() < REPLY_CAPACITY
    }

    /// Whether a peer-initiated rekey is retained or in progress.
    pub(super) fn rekey_active(&self) -> bool {
        self.driver.rekey_active()
    }

    /// Read one packet without retrying the blocked writer first.
    pub(super) fn read_one_behind_active(&mut self) -> Result<Progress, Error> {
        if self.replies.len() >= REPLY_CAPACITY {
            return Ok(Progress::Backpressured);
        }
        self.would_block.arm();
        let inbound = match &self.active {
            Active::Data { id } => self.driver.read_inbound(id),
            Active::Adjustment { id } => self.driver.read_while_window_adjustment(id),
            Active::Eof { id } => self.driver.read_while_eof(id),
            Active::ReplyWriting(OwedReply::GlobalFailure) => {
                self.driver.read_while_global_failure()
            }
            Active::ReplyWriting(OwedReply::ChannelFailure(channel)) => {
                let id = self
                    .driver
                    .channel_failure_read_id(*channel)
                    .map_err(|error| Self::fatal(&error))?;
                self.driver.read_while_channel_failure(&id)
            }
            Active::ReplyWriting(OwedReply::OpenRejection(remote)) => {
                let id = self
                    .driver
                    .open_rejection_read_id(*remote)
                    .map_err(|error| Self::fatal(&error))?;
                self.driver.read_while_open_rejection(&id)
            }
            Active::ReplyWriting(OwedReply::CloseReply(channel)) => {
                let id = self
                    .driver
                    .close_reply_read_id(*channel)
                    .map_err(|error| Self::fatal(&error))?;
                self.driver.read_while_close_reply(&id)
            }
            Active::ReplyWriting(OwedReply::Pong) => {
                let id = self
                    .driver
                    .pong_read_id()
                    .map_err(|error| Self::fatal(&error))?;
                self.driver.read_while_pong(&id)
            }
            _ => {
                return Err(Error::transport(
                    "SSH writer does not support read-behind".to_owned(),
                ));
            }
        };
        match inbound {
            Ok(OwnedChannelInbound::Event(event)) => {
                Ok(self.handle_event(event)?.unwrap_or(Progress::Moved))
            }
            Ok(OwnedChannelInbound::Consumed | OwnedChannelInbound::PeerRekey) => {
                Ok(Progress::Moved)
            }
            Ok(OwnedChannelInbound::PongDeferred) => {
                self.queue_reply(OwedReply::Pong)?;
                Ok(Progress::Moved)
            }
            Err(error) => self.classify(&error, BlockedOn::Read),
        }
    }

    /// Reads one inbound step, answering any reply the peer requires first.
    ///
    /// The loop is bounded so sustained control traffic cannot monopolise the
    /// executor. On the budget it returns [`Progress::Yield`] with all state
    /// retained; the caller self-wakes and retries.
    pub(super) fn dispatch(&mut self) -> Result<Progress, Error> {
        for _ in 0..MAX_PROTOCOL_STEPS_PER_POLL {
            if let Some(blocked) = self.settle()? {
                return Ok(Progress::Blocked(blocked));
            }
            if self.close_pending {
                return Ok(Progress::Closed);
            }
            let mode = self.read_mode()?;
            self.would_block.arm();
            let inbound = match mode {
                ReadMode::Idle => self.driver.read_idle(),
                ReadMode::Data(id) => self.driver.read_inbound(&id),
                ReadMode::Adjustment(id) => self.driver.read_while_window_adjustment(&id),
                ReadMode::Eof(id) => self.driver.read_while_eof(&id),
            };
            match inbound {
                Ok(OwnedChannelInbound::Event(event)) => {
                    if let Some(progress) = self.handle_event(event)? {
                        return Ok(progress);
                    }
                }
                Ok(OwnedChannelInbound::Consumed) => {}
                Ok(OwnedChannelInbound::PeerRekey) => {
                    if !self.driver.rekey_active() {
                        // The final rekey step returned to the scheduler. Do
                        // not read again here: accepted application bytes may
                        // be waiting for the outer pump to write them.
                        return Ok(Progress::Moved);
                    }
                }
                Ok(OwnedChannelInbound::PongDeferred) => {
                    self.queue_reply(OwedReply::Pong)?;
                }
                Err(error) => return self.classify(&error, BlockedOn::Read),
            }
        }
        Ok(Progress::Yield)
    }

    /// Admits at most one channel-data packet from `bytes`.
    ///
    /// The payload is copied into the driver's owned protected packet before
    /// this returns, so `Wrote(n)` means the caller may reuse its buffer
    /// immediately. The packet is driven later by [`Self::complete_outbound`],
    /// a later write, flush, read, or shutdown. A `WouldBlock` while finishing
    /// a packet admitted by an earlier call returns `Blocked` without admitting
    /// any of the current buffer, so a cancelled poll can never attribute one
    /// packet's length to a later, different buffer.
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<Progress, Error> {
        if bytes.is_empty() {
            return Ok(Progress::Wrote(0));
        }
        if let Some(blocked) = self.settle()? {
            return Ok(Progress::Blocked(blocked));
        }
        if self.close_pending || self.local_eof_sent {
            return Ok(Progress::Closed);
        }
        if let Some(blocked) = self.complete_outbound()? {
            return Ok(Progress::Blocked(blocked));
        }
        if self.close_pending || self.local_eof_sent {
            return Ok(Progress::Closed);
        }
        let (window, maximum) = self.limits();
        let maximum = usize::try_from(maximum).unwrap_or(0);
        if maximum == 0 {
            return Ok(Progress::Closed);
        }
        let wanted = bytes
            .len()
            .min(maximum)
            .min(usize::try_from(window).unwrap_or(0));
        if wanted == 0 {
            return Ok(Progress::NoWindow);
        }
        self.would_block.arm();
        match self.driver.admit_data(self.session, &bytes[..wanted]) {
            Ok(id) => {
                self.admit_active(Active::Data { id })?;
                // Try to write it now. A block leaves the packet owned and the
                // caller still gets `Wrote`, because its bytes were copied into
                // that packet at admission; a later poll, flush, read, or
                // shutdown finishes it.
                self.complete_outbound()?;
                Ok(Progress::Wrote(wanted))
            }
            Err(error) => self.classify(&error, BlockedOn::Write),
        }
    }

    /// Sends as much of the pending inbound credit as the socket will take.
    ///
    /// The credit is admitted before it is driven, and `pending_grant` is
    /// cleared at admission. A `WouldBlock` leaves the exact adjustment packet
    /// owned by the driver, so the next call resumes it instead of granting the
    /// same bytes twice.
    pub(super) fn flush_credit(&mut self) -> Result<Option<BlockedOn>, Error> {
        if let Some(blocked) = self.settle()? {
            return Ok(Some(blocked));
        }
        if let Some(blocked) = self.complete_outbound()? {
            return Ok(Some(blocked));
        }
        if self.pending_grant == 0 || self.close_pending {
            return Ok(None);
        }
        let increment = self.pending_grant;
        self.would_block.arm();
        match self.driver.admit_window_adjustment(self.session, increment) {
            Ok(id) => {
                self.pending_grant = 0;
                self.admit_active(Active::Adjustment { id })?;
                self.complete_outbound()
            }
            // The channel is gone or closed locally. The peer cannot receive
            // more data on it, so the credit has no destination and is dropped.
            Err(OwnedChannelError::Channel(
                ChannelError::UnknownChannel
                | ChannelError::ClosedChannel(_)
                | ChannelError::InvalidMessage,
            )) => {
                self.pending_grant = 0;
                Ok(None)
            }
            Err(error) => match self.blocked(&error, BlockedOn::Write) {
                Some(blocked) => Ok(Some(blocked)),
                None => Err(Self::fatal(&error)),
            },
        }
    }

    /// Completes any admitted outbound packet without settling a reply.
    ///
    /// Used by `flush` so a partially written data packet is finished before
    /// the caller believes its buffer was flushed.
    pub(super) fn complete_outbound(&mut self) -> Result<Option<BlockedOn>, Error> {
        match self.active.clone() {
            Active::None | Active::ReplyQueued(_) | Active::ReplyWriting(_) => Ok(None),
            Active::Data { id } => {
                self.would_block.arm();
                match self.driver.drive(&id) {
                    Ok(()) => {
                        self.promote();
                        Ok(None)
                    }
                    Err(error) => match self.blocked(&error, BlockedOn::Write) {
                        Some(blocked) => Ok(Some(blocked)),
                        None => Err(Self::fatal(&error)),
                    },
                }
            }
            Active::Adjustment { id } => {
                self.would_block.arm();
                match self.driver.drive_window_adjustment(&id) {
                    Ok(_) => {
                        self.promote();
                        Ok(None)
                    }
                    Err(error) => match self.blocked(&error, BlockedOn::Write) {
                        Some(blocked) => Ok(Some(blocked)),
                        None => Err(Self::fatal(&error)),
                    },
                }
            }
            Active::Eof { id } => {
                self.would_block.arm();
                match self.driver.drive_eof(&id) {
                    Ok(()) => {
                        self.promote();
                        self.local_eof_sent = true;
                        Ok(None)
                    }
                    Err(error) => match self.blocked(&error, BlockedOn::Write) {
                        Some(blocked) => Ok(Some(blocked)),
                        None => Err(Self::fatal(&error)),
                    },
                }
            }
        }
    }

    /// Flushes admitted data, then sends this side's half-close EOF exactly once.
    ///
    /// The read half remains usable: the peer may still send data and its own
    /// CLOSE after our EOF.
    pub(super) fn shutdown(&mut self) -> Result<Progress, Error> {
        if let Some(blocked) = self.complete_outbound()? {
            return Ok(Progress::Blocked(blocked));
        }
        if let Some(blocked) = self.settle()? {
            return Ok(Progress::Blocked(blocked));
        }
        if self.close_pending {
            return Ok(Progress::Closed);
        }
        if self.local_eof_sent {
            return Ok(Progress::Moved);
        }
        self.would_block.arm();
        match self.driver.admit_eof(self.session) {
            Ok(id) => {
                self.admit_active(Active::Eof { id })?;
                match self.complete_outbound()? {
                    Some(blocked) => Ok(Progress::Blocked(blocked)),
                    None => Ok(Progress::Moved),
                }
            }
            Err(OwnedChannelError::Channel(
                ChannelError::UnknownChannel
                | ChannelError::ClosedChannel(_)
                | ChannelError::InvalidMessage,
            )) => {
                self.local_eof_sent = true;
                Ok(Progress::Moved)
            }
            Err(error) => match self.blocked(&error, BlockedOn::Write) {
                Some(blocked) => Ok(Progress::Blocked(blocked)),
                None => Err(Self::fatal(&error)),
            },
        }
    }

    fn read_mode(&self) -> Result<ReadMode, Error> {
        Ok(match &self.active {
            Active::None => ReadMode::Idle,
            Active::Data { id } => ReadMode::Data(id.clone()),
            Active::Adjustment { id } => ReadMode::Adjustment(id.clone()),
            Active::Eof { id } => ReadMode::Eof(id.clone()),
            Active::ReplyQueued(_) | Active::ReplyWriting(_) => {
                return Err(Error::transport("SSH reply is still active".to_owned()));
            }
        })
    }

    fn admit_active(&mut self, active: Active) -> Result<(), Error> {
        if !matches!(self.active, Active::None) || !self.replies.is_empty() {
            return Err(Error::transport("SSH active writer is busy".to_owned()));
        }
        self.active = active;
        Ok(())
    }

    fn queue_reply(&mut self, reply: OwedReply) -> Result<(), Error> {
        if self.replies.len() >= REPLY_CAPACITY {
            // Readers check capacity before I/O. Reaching this after
            // consumption means the scheduling mirror has diverged.
            return Err(Error::transport(
                "SSH reply capacity invariant failed".to_owned(),
            ));
        }
        self.replies.push_back(reply);
        if matches!(self.active, Active::None) {
            self.active = Active::ReplyQueued(reply);
        }
        Ok(())
    }

    fn promote(&mut self) {
        if matches!(
            self.active,
            Active::ReplyQueued(_) | Active::ReplyWriting(_)
        ) {
            self.replies.pop_front();
        }
        self.active = self
            .replies
            .front()
            .copied()
            .map_or(Active::None, Active::ReplyQueued);
    }

    /// Drains FIFO fronts within the protocol-step budget.
    ///
    /// The driver refuses a reply while a data packet or adjustment is still
    /// active, so the admitted packet is finished first. A `WouldBlock` keeps
    /// the active reply intact for a later drive or supported read-behind.
    fn settle(&mut self) -> Result<Option<BlockedOn>, Error> {
        for _ in 0..MAX_PROTOCOL_STEPS_PER_POLL {
            if self.replies.is_empty()
                && !matches!(
                    self.active,
                    Active::ReplyQueued(_) | Active::ReplyWriting(_)
                )
            {
                return Ok(None);
            }
            if let Some(blocked) = self.complete_outbound()? {
                return Ok(Some(blocked));
            }
            let (Active::ReplyQueued(owed) | Active::ReplyWriting(owed)) = self.active else {
                return Err(Error::transport(
                    "SSH reply state is inconsistent".to_owned(),
                ));
            };
            self.active = Active::ReplyWriting(owed);
            self.would_block.arm();
            let result = match owed {
                OwedReply::Pong => self.driver.drive_deferred_pong(),
                OwedReply::GlobalFailure => self.driver.drive_global_failure(),
                OwedReply::ChannelFailure(channel) => self.driver.drive_channel_failure(channel),
                OwedReply::OpenRejection(remote) => self
                    .driver
                    .drive_open_rejection(remote, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED),
                OwedReply::CloseReply(channel) => self.driver.drive_close_reply(channel),
            };
            match result {
                Ok(()) => {
                    self.promote();
                }
                Err(error) => match self.blocked(&error, BlockedOn::Write) {
                    Some(blocked) => return Ok(Some(blocked)),
                    None => return Err(Self::fatal(&error)),
                },
            }
        }
        Ok(None)
    }

    fn handle_event(&mut self, event: ChannelEvent) -> Result<Option<Progress>, Error> {
        match event {
            ChannelEvent::Data { channel, data } if channel == self.session => {
                Ok(Some(Progress::Data(data)))
            }
            // Extended data is not part of the Engine byte stream. It still
            // consumed local window, so it is credited rather than silently
            // leaking the peer's send credit.
            ChannelEvent::ExtendedData { channel, data, .. } if channel == self.session => {
                self.pending_grant = self
                    .pending_grant
                    .saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
                Ok(Some(Progress::Moved))
            }
            ChannelEvent::Eof { channel } if channel == self.session => Ok(Some(Progress::Eof)),
            ChannelEvent::Close { channel } if channel == self.session => {
                self.queue_reply(OwedReply::CloseReply(channel))?;
                self.close_pending = true;
                Ok(None)
            }
            ChannelEvent::Request {
                channel,
                want_reply: true,
                ..
            } if channel == self.session => {
                self.queue_reply(OwedReply::ChannelFailure(channel))?;
                Ok(None)
            }
            ChannelEvent::GlobalRequest {
                want_reply: true, ..
            } => {
                self.queue_reply(OwedReply::GlobalFailure)?;
                Ok(None)
            }
            ChannelEvent::OpenRequest(request) => {
                self.queue_reply(OwedReply::OpenRejection(request.sender_channel()))?;
                Ok(None)
            }
            // A session request without `want_reply` carries nothing this
            // transport acts on: `exit-status` is the usual one and the
            // `exec` reply already told us the command started.
            ChannelEvent::Request {
                channel,
                want_reply: false,
                ..
            } if channel == self.session => Ok(Some(Progress::Moved)),
            // Ignorable connection-level traffic, window credit, and replies
            // to requests this session never sent.
            ChannelEvent::GlobalRequest {
                want_reply: false, ..
            }
            | ChannelEvent::GlobalRequestSucceeded { .. }
            | ChannelEvent::GlobalRequestFailed { .. }
            | ChannelEvent::WindowAdjusted { .. }
            | ChannelEvent::Opened(_)
            | ChannelEvent::OpenFailed { .. }
            | ChannelEvent::RequestSucceeded { .. }
            | ChannelEvent::RequestFailed { .. } => Ok(Some(Progress::Moved)),
            // The Engine transport owns one session, not a channel
            // multiplexer. Foreign channel traffic fails closed, including
            // data and CLOSE received behind an active close reply.
            ChannelEvent::Data { channel, .. }
            | ChannelEvent::ExtendedData { channel, .. }
            | ChannelEvent::Eof { channel }
            | ChannelEvent::Close { channel }
            | ChannelEvent::Request { channel, .. } => Err(Error::transport(format!(
                "the remote host addressed an SSH channel this session did not open: {channel}"
            ))),
        }
    }

    fn blocked(&self, error: &OwnedChannelError, default: BlockedOn) -> Option<BlockedOn> {
        match error {
            OwnedChannelError::Transport(TransportError::Io(error))
                if error.kind() == std::io::ErrorKind::WouldBlock =>
            {
                Some(self.would_block.take().unwrap_or(default))
            }
            _ => None,
        }
    }

    fn classify(&self, error: &OwnedChannelError, default: BlockedOn) -> Result<Progress, Error> {
        match self.blocked(error, default) {
            Some(blocked) => Ok(Progress::Blocked(blocked)),
            None => Err(Self::fatal(error)),
        }
    }

    fn fatal(error: &OwnedChannelError) -> Error {
        Error::transport(format!("the SSH session channel failed: {error}"))
    }
}

/// One write that must finish before establishment reads again.
///
/// Each variant is idempotent: the channel layer builds the same payload for
/// the same request, so retrying after `WouldBlock` resumes the protected
/// packet instead of replacing it.
#[derive(Clone, Debug)]
enum SetupWrite {
    GlobalFailure,
    ChannelFailure(ChannelId),
    OpenRejection(ChannelId),
    CloseReply(ChannelId),
    Exec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupPhase {
    Confirming,
    ExecRequested,
}

#[derive(Debug)]
enum SetupStep {
    Progress,
    Done,
    Blocked(BlockedOn),
}

/// Post-authentication establishment for one `docker system dial-stdio` session.
///
/// Every connection-level and channel-level message is answered explicitly
/// before the next read: a global request that asked for a reply is refused, a
/// session request that asked for one is refused, an inbound channel open is
/// rejected, and a peer close is answered with the matching close. Channel data
/// that arrives before the peer accepts `exec` is retained and handed to the
/// duplex. Anything this state machine cannot preserve is an establishment
/// error rather than a silently discarded event.
///
/// It is a state machine because a reply that was consumed must not be lost if
/// its write reports `WouldBlock`: `pending` retains the exact request, and
/// [`authenticate_and_exec`] abandons the connection rather than reading past
/// an unanswered one. The establishment socket is blocking in production, so
/// that path is a defence rather than an expected flow.
struct Setup {
    session: ChannelId,
    phase: SetupPhase,
    pending: Option<SetupWrite>,
    early: Vec<u8>,
    terminal: Option<Error>,
}

impl Setup {
    fn new(session: ChannelId) -> Self {
        Self {
            session,
            phase: SetupPhase::Confirming,
            pending: None,
            early: Vec::new(),
            terminal: None,
        }
    }

    fn into_early(self) -> Vec<u8> {
        self.early
    }

    fn step<T: ChannelTransport>(
        &mut self,
        sessions: &mut ClientSessions<T>,
        would_block: &WouldBlock,
    ) -> Result<SetupStep, Error> {
        if let Some(pending) = self.pending.take() {
            would_block.arm();
            match self.write_pending(sessions, &pending) {
                Ok(()) => {
                    if matches!(pending, SetupWrite::Exec) {
                        self.phase = SetupPhase::ExecRequested;
                    }
                    if let Some(error) = self.terminal.take() {
                        return Err(error);
                    }
                }
                Err(error) => {
                    if let Some(blocked) = would_block.take() {
                        self.pending = Some(pending);
                        return Ok(SetupStep::Blocked(blocked));
                    }
                    return Err(error);
                }
            }
        }
        would_block.arm();
        match sessions.connection_mut().dispatch_one() {
            Ok(event) => self.handle(event),
            Err(error) => {
                if let Some(blocked) = would_block.take() {
                    return Ok(SetupStep::Blocked(blocked));
                }
                Err(transport_error(
                    "read from the SSH connection during session establishment",
                    error,
                ))
            }
        }
    }

    fn write_pending<T: ChannelTransport>(
        &self,
        sessions: &mut ClientSessions<T>,
        pending: &SetupWrite,
    ) -> Result<(), Error> {
        if matches!(pending, SetupWrite::Exec) {
            return sessions
                .request_exec(self.session, &exec_request(), true)
                .map_err(|error| {
                    transport_error("request 'docker system dial-stdio' over SSH", error)
                });
        }
        let connection = sessions.connection_mut();
        match pending {
            SetupWrite::GlobalFailure => connection
                .send_global_request_failure()
                .map_err(|error| transport_error("answer an SSH global request", error)),
            SetupWrite::ChannelFailure(channel) => connection
                .send_request_failure(*channel)
                .map_err(|error| transport_error("refuse an SSH session request", error)),
            SetupWrite::OpenRejection(remote) => connection
                .reject_open(*remote, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, b"", b"")
                .map_err(|error| transport_error("reject an inbound SSH channel open", error)),
            SetupWrite::CloseReply(channel) => connection
                .send_close(*channel)
                .map_err(|error| transport_error("answer an SSH channel close", error)),
            SetupWrite::Exec => unreachable!("handled above"),
        }
    }

    #[allow(clippy::too_many_lines)] // One explicit arm per event keeps each obligation visible.
    fn handle(&mut self, event: ChannelEvent) -> Result<SetupStep, Error> {
        match event {
            ChannelEvent::Opened(channel) if channel == self.session => {
                if self.phase != SetupPhase::Confirming {
                    return Err(Error::transport(
                        "the remote host confirmed the SSH session channel twice",
                    ));
                }
                self.pending = Some(SetupWrite::Exec);
                Ok(SetupStep::Progress)
            }
            ChannelEvent::OpenFailed { channel, .. } if channel == self.session => Err(
                Error::ssh_establishment_failed(ManagedSshEstablishmentFailure::ChannelOpenRefused),
            ),
            ChannelEvent::OpenRequest(request) => {
                self.pending = Some(SetupWrite::OpenRejection(request.sender_channel()));
                Ok(SetupStep::Progress)
            }
            ChannelEvent::GlobalRequest {
                want_reply: true, ..
            } => {
                self.pending = Some(SetupWrite::GlobalFailure);
                Ok(SetupStep::Progress)
            }
            ChannelEvent::GlobalRequest {
                want_reply: false, ..
            }
            | ChannelEvent::GlobalRequestSucceeded { .. }
            | ChannelEvent::GlobalRequestFailed { .. }
            | ChannelEvent::WindowAdjusted { .. } => Ok(SetupStep::Progress),
            ChannelEvent::Request {
                channel,
                want_reply: true,
                ..
            } if channel == self.session => {
                self.pending = Some(SetupWrite::ChannelFailure(channel));
                Ok(SetupStep::Progress)
            }
            ChannelEvent::Request {
                channel,
                want_reply: false,
                ..
            } if channel == self.session => Ok(SetupStep::Progress),
            ChannelEvent::Data { channel, data } if channel == self.session => {
                let total = self
                    .early
                    .len()
                    .checked_add(data.len())
                    .ok_or_else(|| Error::transport("SSH early data length overflow"))?;
                if total > INITIAL_CHANNEL_WINDOW as usize {
                    return Err(Error::transport(
                        "the remote host sent more SSH session data before accepting exec than \
                         the advertised receive window",
                    ));
                }
                self.early.extend_from_slice(&data);
                Ok(SetupStep::Progress)
            }
            ChannelEvent::ExtendedData { channel, .. } if channel == self.session => {
                Err(Error::transport(
                    "the remote host sent extended SSH session data before accepting exec, which \
                 this transport cannot deliver to the Engine",
                ))
            }
            ChannelEvent::Eof { channel } if channel == self.session => Err(Error::transport(
                "the remote host closed the SSH session input before accepting \
                 'docker system dial-stdio'",
            )),
            ChannelEvent::Close { channel } if channel == self.session => {
                self.pending = Some(SetupWrite::CloseReply(channel));
                self.terminal = Some(Error::transport(
                    "the remote host closed the SSH session channel before accepting \
                     'docker system dial-stdio'",
                ));
                Ok(SetupStep::Progress)
            }
            ChannelEvent::RequestSucceeded { channel } if channel == self.session => {
                if self.phase == SetupPhase::ExecRequested {
                    Ok(SetupStep::Done)
                } else {
                    Err(Error::transport(
                        "the remote host accepted an SSH session request before one was sent",
                    ))
                }
            }
            ChannelEvent::RequestFailed { channel } if channel == self.session => {
                if self.phase != SetupPhase::ExecRequested {
                    return Err(Error::transport(
                        "the remote host refused an SSH session request before one was sent",
                    ));
                }
                Err(Error::transport(
                    "the remote host refused 'docker system dial-stdio'; check that the login \
                     user can reach the Docker socket and that the docker CLI is on that \
                     account's PATH",
                ))
            }
            // A session event that names no channel this client opened, a
            // second confirmation, or a channel request outside the one
            // session: all are protocol faults for this single-channel client.
            ChannelEvent::Data { channel, .. }
            | ChannelEvent::ExtendedData { channel, .. }
            | ChannelEvent::Eof { channel }
            | ChannelEvent::Close { channel }
            | ChannelEvent::Request { channel, .. }
            | ChannelEvent::Opened(channel)
            | ChannelEvent::OpenFailed { channel, .. }
            | ChannelEvent::RequestSucceeded { channel }
            | ChannelEvent::RequestFailed { channel } => Err(Error::transport(format!(
                "the remote host addressed an SSH channel this session did not open: {channel}"
            ))),
        }
    }
}

/// The real post-handshake protocol path. Socket operations are gated when the
/// supplied transport uses the supervised worker's deadline socket.
fn authenticate_and_exec<T: Read + Write>(
    transport: ClientTransport<T>,
    methods: &[ClientAuthMethod],
    options: &ManagedSshOptions,
    would_block: WouldBlock,
) -> Result<SessionParts<T>, Error> {
    let transport = authenticate(transport, methods, options)?;
    let mut sessions = ClientSessions::from_connection(ChannelConnection::new(transport));
    would_block.arm();
    let session = sessions.open_session().map_err(|error| {
        if let Some(blocked) = would_block.take() {
            establishment_blocked("opening the SSH session channel", blocked)
        } else {
            transport_error("open an SSH session channel", error)
        }
    })?;

    let mut setup = Setup::new(session);
    loop {
        match setup.step(&mut sessions, &would_block)? {
            SetupStep::Progress => {}
            SetupStep::Done => break,
            SetupStep::Blocked(blocked) => {
                return Err(establishment_blocked(
                    "answering SSH session establishment",
                    blocked,
                ));
            }
        }
    }
    let early = setup.into_early();
    let driver = into_driver(sessions.into_connection())?;
    Ok(SessionParts {
        driver,
        session,
        would_block,
        early,
        active: Active::None,
        replies: VecDeque::new(),
        pending_grant: 0,
        local_eof_sent: false,
        close_pending: false,
    })
}

/// Authenticates one protected transport, leaving it ready for channel setup.
///
/// The connection-level demultiplexer is not installed separately: a current
/// OpenSSH server sends `hostkeys-00@openssh.com` and `SSH_MSG_DEBUG` as the
/// first payloads after `SSH_MSG_USERAUTH_SUCCESS`, and
/// [`ChannelConnection::dispatch_one`] surfaces or ignores them rather than
/// treating them as channel messages.
fn authenticate<T: Read + Write>(
    mut transport: ClientTransport<T>,
    methods: &[ClientAuthMethod],
    options: &ManagedSshOptions,
) -> Result<ClientTransport<T>, Error> {
    let mut authenticator = ClientAuthenticator::new(&mut transport, &options.user, 4)
        .map_err(|error| transport_error("prepare SSH authentication", error))?;
    let result = authenticator.authenticate(methods);
    let rejected = authenticator.server_rejected_authentication();
    result.map_err(|error| {
        if error == neotales_ssh::auth::AuthError::AuthenticationFailed {
            return Error::ssh_establishment_failed(if rejected {
                ManagedSshEstablishmentFailure::AuthenticationRejected
            } else {
                ManagedSshEstablishmentFailure::NoUsableAuthenticationMethod
            });
        }
        transport_error(
            format!(
                "authenticate managed SSH with {}",
                options.identity.mechanism()
            ),
            error,
        )
    })?;
    drop(authenticator);
    Ok(transport)
}

/// The real managed handshake, generic over its I/O so a supervised socket can
/// enforce the original absolute deadline and cancellation on every operation.
/// This does not make the surrounding legacy establishment safe to enable.
fn checked_handshake<T: Read + Write>(
    socket: T,
    known_hosts: &KnownHosts,
    known_hosts_path: &Path,
    host_token: &str,
    host: &str,
    port: u16,
) -> Result<ClientTransport<T>, Error> {
    let mut refusal = None;
    ClientConfig::new()
        .with_extension_info()
        .connect(socket, |host_key| {
            check_host_key(known_hosts, known_hosts_path, host_token, host_key).map_err(|error| {
                // ClientConfig deliberately discards generic callback errors.
                // Retain our bounded local reason, never arbitrary peer text.
                refusal = Some(error);
            })
        })
        .map_err(|error| {
            refusal.unwrap_or_else(|| {
                transport_error(format!("the SSH handshake with {host}:{port}"), error)
            })
        })
}

/// The exact bytes of the `exec` request: one command string, no shell.
///
/// `sshd` hands the command to the login shell, so the words are spelled the way
/// a user would type them. The .NET reference sends the identical command string
/// (`session.StartAsync("docker system dial-stdio", …)`), and so does `docker`.
fn exec_request() -> Vec<u8> {
    DIAL_STDIO.join(" ").into_bytes()
}

/// Hands a fully settled connection to the single-packet owned writer.
///
/// `OwnedChannelDriver::try_new` refuses a connection that still holds a peer
/// open or an unanswered close, or whose transport is busy. Setup answers every
/// such obligation, so a refusal here is an establishment failure, not
/// something to work around: taking the connection anyway would leave the
/// caller unable to answer it.
fn into_driver<T: Read + Write>(
    connection: ChannelConnection<ClientTransport<T>>,
) -> Result<OwnedChannelDriver<T>, Error> {
    OwnedChannelDriver::try_new(connection).map_err(|_connection| {
        Error::transport(
            "the SSH session could not be handed to the owned channel driver: an inbound open \
             or unanswered close remained after setup"
                .to_owned(),
        )
    })
}

/// Reports an establishment step that could not proceed on the blocking socket.
///
/// The consumed request is still retained by [`Setup`]; abandoning the
/// connection is what makes dropping it impossible to confuse with answering
/// it.
fn establishment_blocked(what: &str, blocked: BlockedOn) -> Error {
    Error::transport(format!(
        "failed to continue {what}: the blocking establishment socket reported {blocked:?} and \
         the connection was abandoned rather than reading past an unanswered request"
    ))
}

/// Decides whether an offered host key is accepted.
///
/// Only a matching, plain entry in the pre-provisioned snapshot is accepted.
/// Unknown, changed, revoked, and CA-only keys are refused without writing.
fn check_host_key(
    known_hosts: &KnownHosts,
    _known_hosts_path: &Path,
    host_token: &str,
    host_key: &Ed25519PublicKey,
) -> Result<(), Error> {
    let blob = host_key.to_blob().map_err(|error| {
        Error::transport(format!("encode the SSH host key for {host_token}: {error}"))
    })?;
    match known_hosts.check_host_token(host_token, &blob) {
        KnownHostsStatus::Trusted => Ok(()),
        KnownHostsStatus::NotFound => Err(Error::ssh_host_key_rejected(
            crate::ManagedSshHostKeyRejection::Unknown,
        )),
        KnownHostsStatus::Changed => Err(Error::ssh_host_key_rejected(
            crate::ManagedSshHostKeyRejection::Changed,
        )),
        KnownHostsStatus::Revoked => Err(Error::ssh_host_key_rejected(
            crate::ManagedSshHostKeyRejection::Revoked,
        )),
        KnownHostsStatus::CertificateAuthority => Err(Error::ssh_host_key_rejected(
            crate::ManagedSshHostKeyRejection::CertificateAuthorityOnly,
        )),
    }
}

const MAX_KNOWN_HOSTS_BYTES: usize = 4 * 1024 * 1024;
const MAX_IDENTITY_BYTES: usize = 1024 * 1024;
const MAX_BCRYPT_ROUNDS: u32 = 128;

/// A size cap is enforced on bytes actually read, not a racy metadata length.
/// The syscall itself may still block; the supervised registry owns that worker.
fn read_bounded(path: &Path, limit: usize, kind: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let file = std::fs::File::open(path)
        .map_err(|error| Error::transport(format!("read {kind} {}: {error}", path.display())))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| Error::transport(format!("read {kind} {}: {error}", path.display())))?;
    if bytes.len() > limit {
        return Err(Error::invalid_input(format!(
            "{kind} {} exceeds the {limit}-byte limit",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Loads one pre-provisioned snapshot. Missing, unreadable and malformed files
/// fail closed. Replacing the path later does not change this in-memory snapshot.
fn load_known_hosts(path: &Path) -> Result<KnownHosts, Error> {
    let bytes = read_bounded(path, MAX_KNOWN_HOSTS_BYTES, "known-hosts file")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        Error::invalid_input(format!(
            "the known-hosts file {} is not UTF-8",
            path.display()
        ))
    })?;
    KnownHosts::parse(text).map_err(|error| {
        Error::invalid_input(format!(
            "the known-hosts file {} could not be parsed: {error}",
            path.display()
        ))
    })
}

/// The authentication methods to try, in order, for one connection.
///
/// One method per connection, because the caller named exactly one credential
/// and offering the server a choice would let it steer which one is used. The
/// vector rather than a single value because `ClientAuthenticator::authenticate`
/// takes a slice, and a one-element slice is not a special case worth a branch.
fn auth_methods(identity: &SshIdentity) -> Result<Vec<ClientAuthMethod>, Error> {
    let method = match identity {
        SshIdentity::KeyFile(path) => {
            ClientAuthMethod::PublicKey(Box::new(public_key_signer(path, None).map_err(|_| {
                Error::ssh_establishment_failed(ManagedSshEstablishmentFailure::IdentityFile)
            })?))
        }
        SshIdentity::EncryptedKeyFile { path, passphrase } => ClientAuthMethod::PublicKey(
            Box::new(public_key_signer(path, Some(passphrase)).map_err(|_| {
                Error::ssh_establishment_failed(ManagedSshEstablishmentFailure::IdentityFile)
            })?),
        ),
        // The constructor rather than the variant, because the variant holds a
        // `Zeroizing` string: the copy made here is wiped with the method, and
        // naming the constructor is what makes that the case.
        SshIdentity::Password(password) => ClientAuthMethod::password(password.expose()),
    };
    Ok(vec![method])
}

/// Reject excessive bcrypt work before the library performs key derivation.
/// This parses only the public container header and never formats key bytes.
fn preflight_identity_kdf(bytes: &[u8], path: &Path) -> Result<(), Error> {
    let invalid = || {
        Error::invalid_input(format!(
            "the SSH identity {} has a malformed or unsupported OpenSSH protection header",
            path.display()
        ))
    };
    let body = bytes
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or_else(invalid)?;
    let mut reader = neotales_ssh::Reader::new(body);
    let cipher = reader.read_string().map_err(|_| invalid())?;
    let kdf = reader.read_string().map_err(|_| invalid())?;
    let options = reader.read_string().map_err(|_| invalid())?;
    match (cipher, kdf) {
        (b"none", b"none") if options.is_empty() => Ok(()),
        (b"aes256-ctr", b"bcrypt") => {
            let mut options = neotales_ssh::Reader::new(options);
            let salt = options.read_string().map_err(|_| invalid())?;
            let rounds = options.read_u32().map_err(|_| invalid())?;
            if salt.is_empty() || !options.is_empty() || rounds == 0 {
                return Err(invalid());
            }
            if rounds > MAX_BCRYPT_ROUNDS {
                return Err(Error::invalid_input(format!(
                    "the SSH identity {} exceeds the bcrypt limit of {MAX_BCRYPT_ROUNDS} rounds",
                    path.display()
                )));
            }
            Ok(())
        }
        _ => Err(invalid()),
    }
}

/// Loads an OpenSSH private key as a public-key signer.
///
/// An encrypted key needs the caller's passphrase. A library that blocked on a
/// terminal prompt inside a request would hang, so the passphrase is a
/// caller-supplied [`SshSecret`], and a key that needs one and was given none is
/// refused with a message naming the call that would work rather than with
/// whatever the container parser happens to report for an empty passphrase.
fn public_key_signer(
    path: &Path,
    passphrase: Option<&SshSecret>,
) -> Result<PublicKeySigner, Error> {
    let bytes = read_bounded(path, MAX_IDENTITY_BYTES, "SSH identity")?;
    // `ssh-keygen` writes the new format inside a PEM armor, and the file every
    // user has on disk is armored. `OpenSshPrivateKey::parse` takes the decoded
    // container — its own documentation says so — so the armor is removed here
    // rather than in `neotales-ssh`, which is a protocol crate and not a file
    // format reader for OpenSSH's armor.
    let bytes = match decode_openssh_armor(&bytes) {
        Some(decoded) => Zeroizing::new(decoded),
        // Not armored: the caller handed the raw container, which the parser
        // accepts, and its own error message is the better one.
        None => bytes,
    };
    preflight_identity_kdf(&bytes, path)?;
    // The passphrase is a throwaway buffer rather than the secret's own storage,
    // because `OpenSshPrivateKey::parse` zeroizes what it is given and that
    // promise is only worth something about a copy.
    let passphrase_was_given = passphrase.is_some();
    let mut passphrase =
        passphrase.map_or_else(|| Zeroizing::new(Vec::new()), SshSecret::expose_throwaway);
    match OpenSshPrivateKey::parse(&bytes, &mut passphrase) {
        Ok(OpenSshPrivateKey::Ed25519 { seed, .. }) => {
            let mut bytes = [0_u8; 32];
            let seed = seed.as_slice();
            if seed.len() != bytes.len() {
                return Err(Error::invalid_input(format!(
                    "the Ed25519 SSH identity {} carries a {}-byte seed",
                    path.display(),
                    seed.len()
                )));
            }
            bytes.copy_from_slice(seed);
            Ok(PublicKeySigner::ed25519(Ed25519Signer::from_seed(
                &mut bytes,
            )))
        }
        Ok(OpenSshPrivateKey::Ecdsa { secret, .. }) => {
            let signer = EcdsaSigner::from_secret_scalar_bytes(&secret).map_err(|error| {
                Error::invalid_input(format!(
                    "the ECDSA SSH identity {} could not be used: {error}",
                    path.display()
                ))
            })?;
            Ok(PublicKeySigner::ecdsa(signer))
        }
        Ok(OpenSshPrivateKey::Rsa { p, q, e, .. }) => {
            let signer = RsaAuthSigner::from_p_q(
                rsa::BigUint::from_bytes_be(&p),
                rsa::BigUint::from_bytes_be(&q),
                rsa::BigUint::from_bytes_be(&e),
            )
            .map_err(|error| {
                Error::invalid_input(format!(
                    "the RSA SSH identity {} could not be used: {error}",
                    path.display()
                ))
            })?;
            Ok(PublicKeySigner::rsa(signer))
        }
        // An encrypted key with no passphrase is a caller's mistake, and the
        // container parser's own words for it are about an unsupported algorithm
        // — true, and useless. `WrongPassphrase` reaches the same place, because
        // with an empty passphrase the derived key is wrong rather than absent,
        // so the parser cannot tell the two apart either.
        // One arm for the three errors that all mean "this key wanted a
        // passphrase and did not get one". Nested rather than three `Err(..)`
        // alternatives, which is the same pattern written three times.
        Err(
            OpenSshKeyError::WrongPassphrase
            | OpenSshKeyError::UnsupportedCipher
            | OpenSshKeyError::UnsupportedKdf,
        ) if !passphrase_was_given => Err(Error::invalid_input(format!(
            "the SSH identity {} is encrypted and no passphrase was given; an encrypted \
                 identity is authenticated with SshIdentity::EncryptedKeyFile",
            path.display()
        ))),
        Err(OpenSshKeyError::WrongPassphrase) => Err(Error::invalid_input(format!(
            "the passphrase for the SSH identity {} is incorrect",
            path.display()
        ))),
        Err(error @ (OpenSshKeyError::UnsupportedCipher | OpenSshKeyError::UnsupportedKdf)) => {
            // A passphrase *was* given, so the key is asking for a cipher or a
            // key derivation this parser does not implement. Which one is the
            // useful half, so it is named rather than flattened.
            Err(Error::invalid_input(format!(
                "the SSH identity {} is encrypted with a cipher or key derivation this client \
                 does not implement: {error}",
                path.display()
            )))
        }
        Err(error) => Err(Error::invalid_input(format!(
            "the SSH identity {} could not be read: {error}",
            path.display()
        ))),
    }
}

/// The `-----BEGIN OPENSSH PRIVATE KEY-----` armor lines.
const OPENSSH_ARMOR_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// The `-----END OPENSSH PRIVATE KEY-----` armor line.
const OPENSSH_ARMOR_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// Decodes the base64 body of an armored OpenSSH private key.
///
/// Returns `None` when the bytes are not that armor, so the caller can hand
/// them to the container parser unchanged and let it report the shape it
/// actually saw. The armor is a line-oriented format and this reads it that
/// way: everything between the two markers, with the whitespace a text editor
/// or a line wrap introduced removed before decoding.
fn decode_openssh_armor(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;

    let text = std::str::from_utf8(bytes).ok()?;
    let (_, after_begin) = text.split_once(OPENSSH_ARMOR_BEGIN)?;
    let (body, _) = after_begin.split_once(OPENSSH_ARMOR_END)?;
    let encoded = Zeroizing::new(
        body.chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>(),
    );
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .ok()
}

/// The first socket direction which could not make progress in an operation.
///
/// The channel layer maps every transport failure onto one
/// `ChannelError::Transport`, so a retryable `WouldBlock` and a dead connection
/// arrive as the same value. The socket is the only place that still knows which
/// happened, so the flag it sets is what the duplex classifies on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlockedOn {
    Read,
    Write,
}

#[derive(Clone, Debug, Default)]
struct WouldBlock(Arc<AtomicU8>);

impl WouldBlock {
    /// Clears the record so the next classification is about one operation.
    fn arm(&self) {
        self.0.store(0, Ordering::Release);
    }

    /// Returns and clears the record.
    fn take(&self) -> Option<BlockedOn> {
        match self.0.swap(0, Ordering::AcqRel) {
            1 => Some(BlockedOn::Read),
            2 => Some(BlockedOn::Write),
            _ => None,
        }
    }
}

/// A socket that records when it could not make progress.
///
/// Read and write readiness are separate handles. Production passes the same
/// registered SSH socket for both, so the split does not change what the pump
/// waits on. A test can give write readiness its own loopback socket to prove
/// the pump's write wait without claiming pressure on the SSH socket.
struct Socket<S> {
    inner: S,
    would_block: Arc<AtomicU8>,
    read_readiness: Arc<OnceLock<Arc<TcpStream>>>,
    write_readiness: Arc<OnceLock<Arc<TcpStream>>>,
    /// Positive bytes accepted by successful socket writes.
    ///
    /// The pump resets the write-stall bound from this, not from a completed
    /// packet: a peer that accepts a packet a little at a time is still making
    /// progress. It is O(1) state and never carries payload.
    write_progress: Arc<AtomicU64>,
}

impl<S: Read> Read for Socket<S> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let result = if let Some(readiness) = self.read_readiness.get() {
            readiness.try_io(Interest::READABLE, || self.inner.read(buffer))
        } else {
            self.inner.read(buffer)
        };
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let _ =
                    self.would_block
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
                Err(error)
            }
            other => other,
        }
    }
}

impl<S: Write> Write for Socket<S> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = if let Some(readiness) = self.write_readiness.get() {
            readiness.try_io(Interest::WRITABLE, || self.inner.write(bytes))
        } else {
            self.inner.write(bytes)
        };
        match result {
            Ok(count) => {
                if count > 0 {
                    self.write_progress
                        .fetch_add(count as u64, Ordering::Relaxed);
                }
                Ok(count)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let _ =
                    self.would_block
                        .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
                Err(error)
            }
            other => other,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Holds only unread channel bytes. The maximum is the receive window granted
/// when opening this one session; credit is returned only after consumption.
#[derive(Default)]
struct InboundBuffer {
    bytes: VecDeque<u8>,
}

impl InboundBuffer {
    fn can_push(&self, count: usize) -> bool {
        count <= (INITIAL_CHANNEL_WINDOW as usize).saturating_sub(self.bytes.len())
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let maximum = INITIAL_CHANNEL_WINDOW as usize;
        if bytes.len() > maximum.saturating_sub(self.bytes.len()) {
            return Err(Error::transport(
                "SSH inbound data exceeds the session receive window",
            ));
        }
        self.bytes.extend(bytes);
        Ok(())
    }

    fn copy_into(&mut self, destination: &mut ReadBuf<'_>) -> usize {
        let count = destination.remaining().min(self.bytes.len());
        let (first, second) = self.bytes.as_slices();
        let first_count = count.min(first.len());
        destination.put_slice(&first[..first_count]);
        destination.put_slice(&second[..count - first_count]);
        self.bytes.drain(..count);
        count
    }
}

#[cfg(test)]
type ReadinessFuture = Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;

/// Each operation owns its own cancel-safe readiness future. Tokio's
/// `readable()`/`writable()` support multiple independent waiters.
///
/// Test-only: production waits for readiness in the pump, not in a poll method.
#[cfg(test)]
#[derive(Default)]
struct ReadinessSlot {
    direction: Option<BlockedOn>,
    future: Option<ReadinessFuture>,
}

#[cfg(test)]
impl ReadinessSlot {
    fn reset(&mut self) {
        self.direction = None;
        self.future = None;
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
        readiness: &Arc<TcpStream>,
        direction: BlockedOn,
    ) -> Poll<std::io::Result<()>> {
        if self.direction != Some(direction) {
            let readiness = Arc::clone(readiness);
            self.direction = Some(direction);
            self.future = Some(Box::pin(async move {
                match direction {
                    BlockedOn::Read => readiness.readable().await,
                    BlockedOn::Write => readiness.writable().await,
                }
            }));
        }
        let result = self
            .future
            .as_mut()
            .expect("readiness future is initialized")
            .as_mut()
            .poll(context);
        if result.is_ready() {
            self.reset();
        }
        result
    }
}

/// State shared between the application's poll methods and the owned pump.
///
/// The application only enqueues bytes, observes completion, registers a waker,
/// and notifies the pump. Every call that can drive the channel is made by
/// [`Self::pump_step`] under this same lock, so a cancelled poll cannot leave a
/// protocol step half-owned by the application.
struct SharedDriver<T> {
    established: ssh_worker::Established<SessionParts<T>>,
    /// Decoded `SSH_MSG_CHANNEL_DATA` not yet handed to the caller.
    inbound: InboundBuffer,
    /// One decoded data event awaiting application-buffer room. No later
    /// ordinary packet may be read until this event has been delivered.
    retained_event: Option<Vec<u8>>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// The single bounded admission slot filled by `poll_write`.
    ///
    /// The pump empties it into the owned channel driver. `poll_write` copies
    /// into it, so no caller buffer is referenced after the poll returns.
    outbound: Vec<u8>,
    /// Flush requested by the application and its completion.
    flush: Completion,
    /// Local half-close EOF requested by the application and its completion.
    shutdown: Completion,
    /// Whether the remote has signalled end of input.
    remote_eof: bool,
    /// Whether the session channel is fully closed or failed.
    closed: bool,
    /// A terminal failure, reported to the application's next poll.
    failure: Option<String>,
    /// Typed local timeout retained separately from the rendered diagnostic.
    failure_timeout: Option<crate::TransportTimeoutKind>,
    /// The arm state of the write-stall bound.
    reply_stall: ReplyStall,
    /// When `fail` recorded the terminal failure, for tests only.
    #[cfg(test)]
    failed_at: Option<tokio::time::Instant>,
    #[cfg(test)]
    pump_calls: usize,
    /// Test-only notification fired after every pump state observation.
    ///
    /// A test installs one before waiting for a bounded condition, so it can
    /// await the pump's next observation instead of spinning `yield_now` and
    /// starving the runtime's I/O driver. It fires after the state lock is
    /// released and before the readiness wait, so an arm or a close is visible
    /// without waiting for the pump to be woken again. Production compiles
    /// this out.
    #[cfg(test)]
    pump_events: Option<Arc<tokio::sync::Notify>>,
}

/// What the pump should wait for before its next step.
#[derive(Clone, Copy, Debug)]
enum PumpAction {
    WaitRead,
    WaitWrite,
    WaitReadWrite,
    WaitNotify,
    Yield,
    Closed,
}

impl PumpAction {
    const fn from_blocked(direction: BlockedOn) -> Self {
        match direction {
            BlockedOn::Read => Self::WaitRead,
            BlockedOn::Write => Self::WaitWrite,
        }
    }
}

/// The decision for one pump step's write-stall bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StallWait {
    /// Not in a non-escapable write state.
    Idle,
    /// In the state; the bound expires at this instant.
    Open(tokio::time::Instant),
    /// In the state and the bound has elapsed.
    Expired,
}

/// Timer bookkeeping for the one wait the pump cannot resolve locally.
///
/// `observe` is called after every pump step. Any positive socket byte write
/// clears the arm; a wakeup, writability, or a partial step that wrote nothing
/// does not.
#[derive(Debug, Default)]
struct ReplyStall {
    armed_at: Option<tokio::time::Instant>,
    /// Count new logical arms separately from permitted positive-byte restarts.
    /// A one-time clear/re-arm must remain observable even at the same instant.
    #[cfg(test)]
    arm_count: usize,
    #[cfg(test)]
    positive_restarts: usize,
    /// The last instant `observe` evaluated, for tests only.
    #[cfg(test)]
    last_observed_at: Option<tokio::time::Instant>,
}

impl ReplyStall {
    /// The arm instant while the bound is open, for tests and diagnostics.
    #[cfg(test)]
    fn armed_at(&self) -> Option<tokio::time::Instant> {
        self.armed_at
    }

    /// The last instant `observe` evaluated, for tests only.
    #[cfg(test)]
    fn last_observed_at(&self) -> Option<tokio::time::Instant> {
        self.last_observed_at
    }

    /// Applies one pump step and returns what the pump should do.
    fn observe(
        &mut self,
        now: tokio::time::Instant,
        non_escapable: bool,
        wrote_bytes: bool,
        bound: Duration,
    ) -> StallWait {
        #[cfg(test)]
        {
            self.last_observed_at = Some(now);
            if non_escapable {
                if self.armed_at.is_none() {
                    self.arm_count += 1;
                } else if wrote_bytes {
                    self.positive_restarts += 1;
                }
            }
        }
        if !non_escapable {
            self.armed_at = None;
            return StallWait::Idle;
        }
        // A positive byte write restarts the inactivity clock at that instant.
        // It must still arm: the pump then waits with a timeout instead of
        // parking, because the socket can refuse the next byte forever.
        let armed = if wrote_bytes {
            self.armed_at = Some(now);
            now
        } else {
            *self.armed_at.get_or_insert(now)
        };
        let deadline = armed + bound;
        if now >= deadline {
            StallWait::Expired
        } else {
            StallWait::Open(deadline)
        }
    }
}

/// Completion state for one operation the application asked the pump to finish.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Completion {
    /// The application has not asked for this operation since the last one.
    #[default]
    Idle,
    /// The application asked; the pump has not observed completion yet.
    Requested,
    /// The pump observed completion.
    Done,
}

impl<T: Read + Write> SharedDriver<T> {
    fn new(established: ssh_worker::Established<SessionParts<T>>, inbound: InboundBuffer) -> Self {
        Self {
            established,
            inbound,
            retained_event: None,
            read_waker: None,
            write_waker: None,
            outbound: Vec::new(),
            flush: Completion::Idle,
            shutdown: Completion::Idle,
            remote_eof: false,
            closed: false,
            failure: None,
            failure_timeout: None,
            reply_stall: ReplyStall::default(),
            #[cfg(test)]
            failed_at: None,
            #[cfg(test)]
            pump_calls: 0,
            #[cfg(test)]
            pump_events: None,
        }
    }

    fn wake_reader(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    fn fail(&mut self, error: &Error) {
        self.failure = Some(error.to_string());
        self.failure_timeout = error.transport_timeout_kind();
        self.closed = true;
        self.retained_event = None;
        #[cfg(test)]
        {
            self.failed_at = Some(tokio::time::Instant::now());
        }
        self.wake_reader();
        self.wake_writer();
    }

    fn failure_io(&self) -> Option<std::io::Error> {
        self.failure
            .as_ref()
            .map(|message| match self.failure_timeout {
                Some(kind) => std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    crate::TransportTimeout {
                        kind,
                        message: message.clone(),
                    },
                ),
                None => std::io::Error::other(message.clone()),
            })
    }

    fn deliver_retained_event(&mut self) -> Result<bool, Error> {
        if !self
            .retained_event
            .as_ref()
            .is_some_and(|data| self.inbound.can_push(data.len()))
        {
            return Ok(false);
        }
        let data = self.retained_event.take().expect("checked retained event");
        self.inbound.push(&data)?;
        self.wake_reader();
        self.wake_writer();
        Ok(true)
    }

    /// One bounded step of driver progress, independent of the application.
    ///
    /// This is the only caller of [`SessionParts::write`],
    /// [`SessionParts::flush_credit`], [`SessionParts::shutdown`], and
    /// [`SessionParts::dispatch`] after setup. A step that cannot proceed
    /// returns a direction to wait on; all partially owned protocol state stays
    /// in the driver.
    ///
    /// Active packets and admitted replies support read-behind. Once
    /// the eight-entry FIFO fills, reading stops until an entry can be
    /// answered, so a peer can still prevent progress by withholding reads.
    #[allow(clippy::too_many_lines)] // One explicit arm per protocol obligation.
    fn pump_step(&mut self) -> PumpAction {
        #[cfg(test)]
        {
            self.pump_calls += 1;
        }
        for _ in 0..MAX_PROTOCOL_STEPS_PER_POLL {
            if self.closed {
                return PumpAction::Closed;
            }
            if let Err(error) = self.deliver_retained_event() {
                self.fail(&error);
                return PumpAction::Closed;
            }

            // A peer KEXINIT is retained behind the active packet. Finish that
            // packet, then drive the bounded rekey before admitting or sending
            // any application payload.
            if self.established.rekey_active() {
                match self.established.complete_outbound() {
                    Ok(None) => {}
                    Ok(Some(direction)) => return PumpAction::from_blocked(direction),
                    Err(error) => {
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                }
                let result = self.established.dispatch();
                if let Some(action) = self.handle_inbound(result) {
                    return action;
                }
                continue;
            }

            // Application bytes were already accepted by `poll_write`, so they
            // are admitted before any inbound step that could block.
            if !self.outbound.is_empty() {
                let result = {
                    let Self {
                        established,
                        outbound,
                        ..
                    } = self;
                    established.write(outbound)
                };
                match result {
                    Ok(Progress::Wrote(count)) => {
                        self.outbound.drain(..count);
                        // The slot may have room again, and a blocked active
                        // packet may also have completed.
                        self.wake_writer();
                        continue;
                    }
                    Ok(Progress::NoWindow) => {
                        if self.retained_event.is_some() {
                            return PumpAction::WaitNotify;
                        }
                        let result = self.established.dispatch();
                        if let Some(action) = self.handle_inbound(result) {
                            return action;
                        }
                        continue;
                    }
                    Ok(Progress::Blocked(direction)) => {
                        if let Some(action) = self.blocked_writer(direction) {
                            return action;
                        }
                        continue;
                    }
                    Ok(Progress::Closed) => {
                        // `poll_write` already accepted the bytes still in the
                        // admission slot. The close reply was driven by
                        // `write`, but those bytes can no longer be sent.
                        self.fail(&Error::transport(
                            "the SSH peer closed before all accepted data was transmitted"
                                .to_owned(),
                        ));
                        return PumpAction::Closed;
                    }
                    Ok(other) => {
                        let error = Error::transport(format!(
                            "the SSH session driver returned an unexpected write result: {other:?}"
                        ));
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                    Err(error) => {
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                }
            }

            // Drives any packet admitted by an earlier step, and sends credit
            // the application returned by reading.
            match self.established.flush_credit() {
                Ok(None) => {
                    // Completing an active packet can make the admission slot
                    // usable again. Wake a writer that was pending on it; a
                    // window adjustment wakes the writer through `Moved`.
                    if self.outbound.is_empty()
                        && self.established.accepts_data()
                        && self.established.available_window() > 0
                    {
                        self.wake_writer();
                    }
                }
                Ok(Some(direction)) => {
                    if let Some(action) = self.blocked_writer(direction) {
                        return action;
                    }
                    continue;
                }
                Err(error) => {
                    self.fail(&error);
                    return PumpAction::Closed;
                }
            }

            // Flush completion is observed here, never driven by `poll_flush`.
            if self.flush == Completion::Requested {
                match self.established.complete_outbound() {
                    Ok(None) => {
                        self.flush = Completion::Done;
                        self.wake_writer();
                    }
                    Ok(Some(direction)) => return PumpAction::from_blocked(direction),
                    Err(error) => {
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                }
            }

            // Shutdown completion sends the local EOF once, after admitted data.
            if self.shutdown == Completion::Requested {
                match self.established.shutdown() {
                    Ok(Progress::Moved) => {
                        self.shutdown = Completion::Done;
                        self.wake_writer();
                    }
                    Ok(Progress::Closed) => {
                        self.shutdown = Completion::Done;
                        self.closed = true;
                        self.wake_reader();
                        self.wake_writer();
                        return PumpAction::Closed;
                    }
                    Ok(Progress::Blocked(direction)) => {
                        if let Some(action) = self.blocked_writer(direction) {
                            return action;
                        }
                        continue;
                    }
                    Ok(other) => {
                        let error = Error::transport(format!(
                            "the SSH session driver returned an unexpected shutdown result: \
                             {other:?}"
                        ));
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                    Err(error) => {
                        self.fail(&error);
                        return PumpAction::Closed;
                    }
                }
            }

            if self.retained_event.is_some() {
                return PumpAction::WaitNotify;
            }
            let result = self.established.dispatch();
            if let Some(action) = self.handle_inbound(result) {
                return action;
            }
        }
        PumpAction::Yield
    }

    /// Retry a read only when the reply FIFO and retained-event slot allow it.
    fn blocked_writer(&mut self, direction: BlockedOn) -> Option<PumpAction> {
        if direction != BlockedOn::Write
            || self.retained_event.is_some()
            || !self.established.can_read_behind_active()
        {
            return Some(PumpAction::from_blocked(direction));
        }
        match self.established.read_one_behind_active() {
            Ok(Progress::Blocked(BlockedOn::Read)) => Some(PumpAction::WaitReadWrite),
            Ok(Progress::Blocked(direction)) => Some(PumpAction::from_blocked(direction)),
            result => self.handle_inbound(result),
        }
    }

    /// Apply one decoded inbound event to the duplex.
    fn handle_inbound(&mut self, result: Result<Progress, Error>) -> Option<PumpAction> {
        match result {
            Ok(Progress::Data(data)) => {
                if !self.inbound.can_push(data.len()) {
                    if self.retained_event.is_some() || data.len() > INITIAL_CHANNEL_WINDOW as usize
                    {
                        self.fail(&Error::transport(
                            "SSH retained event capacity invariant failed",
                        ));
                        return Some(PumpAction::Closed);
                    }
                    self.retained_event = Some(data);
                    self.wake_reader();
                    return None;
                }
                if let Err(error) = self.inbound.push(&data) {
                    self.fail(&error);
                    return Some(PumpAction::Closed);
                }
                self.wake_reader();
            }
            Ok(Progress::Moved) => self.wake_writer(),
            Ok(Progress::Eof) => {
                self.remote_eof = true;
                self.wake_reader();
            }
            Ok(Progress::Closed) => {
                self.closed = true;
                self.wake_reader();
                self.wake_writer();
                return Some(PumpAction::Closed);
            }
            Ok(Progress::Yield) => return Some(PumpAction::Yield),
            Ok(Progress::Backpressured) => return Some(PumpAction::WaitWrite),
            Ok(Progress::Blocked(direction)) => return self.blocked_writer(direction),
            Ok(Progress::Wrote(_) | Progress::NoWindow) => {}
            Err(error) => {
                self.fail(&error);
                return Some(PumpAction::Closed);
            }
        }
        None
    }
}

/// Notifies a test that the pump observed one state, for tests only.
///
/// It is called after the state lock is released and before the readiness wait,
/// so the arm or restart is visible while the pump is still parked, and it is
/// called again by [`fail_readiness`] and [`fail_write_stall`] after the
/// terminal state is recorded. Production compiles this out.
#[cfg(test)]
fn notify_pump_event<T: Read + Write>(shared: &Weak<Mutex<SharedDriver<T>>>) {
    if let Some(shared) = shared.upgrade()
        && let Some(notify) = shared.lock().unwrap().pump_events.clone()
    {
        notify.notify_one();
    }
}

/// Drives the channel after the application stops polling, without owning the
/// transport.
///
/// The task holds only `Weak` references to the duplex's driver and readiness
/// handles, so it cannot keep the transport or cancellation guard alive. The
/// duplex owns all of them and aborts this task on drop. Production passes the
/// same registered SSH socket as both handles; the split lets a test wait for
/// reads on the SSH socket and writes on a separate probe. Each step is bounded
/// and the lock is never held across an await.
///
/// `stall_bound` bounds the one wait the pump cannot resolve locally: a write
/// refused while either a protocol reply is owed or a peer rekey is retained,
/// because the channel driver refuses the reads that could advance either. The
/// clock restarts on any positive socket byte write. A peer that is still
/// accepting bytes is making progress; a peer that stops accepting bytes
/// reaches the bound even if an earlier packet was only partly written.
async fn pump<T: Read + Write + Send + 'static>(
    shared: Weak<Mutex<SharedDriver<T>>>,
    read_readiness: Weak<TcpStream>,
    write_readiness: Weak<TcpStream>,
    notify: Arc<Notify>,
    write_progress: Arc<AtomicU64>,
    stall_bound: Duration,
) {
    loop {
        let (action, stall_wait) = {
            let Some(shared) = shared.upgrade() else {
                break;
            };
            let mut state = shared.lock().unwrap();
            let before = write_progress.load(Ordering::Relaxed);
            let action = state.pump_step();
            let wrote_bytes = write_progress.load(Ordering::Relaxed) != before;
            let non_escapable = matches!(action, PumpAction::WaitWrite)
                && (state.established.reply_outstanding() || state.established.rekey_active());
            let stall_wait = state.reply_stall.observe(
                tokio::time::Instant::now(),
                non_escapable,
                wrote_bytes,
                stall_bound,
            );
            (action, stall_wait)
        };
        // The state lock is released here. Notify before the readiness wait so
        // a test sees the observation while this task is still parked.
        #[cfg(test)]
        notify_pump_event(&shared);
        match action {
            PumpAction::WaitRead
            | PumpAction::WaitWrite
            | PumpAction::WaitReadWrite
            | PumpAction::WaitNotify => {
                let Some(read_readiness) = read_readiness.upgrade() else {
                    break;
                };
                let Some(write_readiness) = write_readiness.upgrade() else {
                    break;
                };
                let wait = wait_for_pump(&read_readiness, &write_readiness, &notify, action);
                match stall_wait {
                    StallWait::Idle => {
                        if let Err(error) = wait.await {
                            fail_readiness(&shared, &error);
                            break;
                        }
                    }
                    StallWait::Open(deadline) => {
                        match tokio::time::timeout_at(deadline, wait).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                fail_readiness(&shared, &error);
                                break;
                            }
                            Err(_) => {
                                fail_write_stall(&shared);
                                break;
                            }
                        }
                    }
                    StallWait::Expired => {
                        fail_write_stall(&shared);
                        break;
                    }
                }
            }
            PumpAction::Yield => tokio::task::yield_now().await,
            PumpAction::Closed => break,
        }
    }
}

/// Reports a failed readiness wait on the shared driver.
fn fail_readiness<T: Read + Write>(shared: &Weak<Mutex<SharedDriver<T>>>, error: &std::io::Error) {
    if let Some(shared) = shared.upgrade() {
        shared.lock().unwrap().fail(&Error::transport(format!(
            "SSH socket readiness failed: {error}"
        )));
    }
    #[cfg(test)]
    notify_pump_event(shared);
}

/// Fails the session closed after the configured bound with no write bytes.
fn fail_write_stall<T: Read + Write>(shared: &Weak<Mutex<SharedDriver<T>>>) {
    if let Some(shared) = shared.upgrade() {
        shared.lock().unwrap().fail(&Error::transport_timeout(
            crate::TransportTimeoutKind::ManagedSshWriteInactivity,
            WRITE_STALL_MESSAGE,
        ));
    }
    #[cfg(test)]
    notify_pump_event(shared);
}

/// Waits for the direction(s) a [`PumpAction`] names, or for the application to
/// notify the pump.
///
/// Read and write readiness are separate handles so a test can observe a real
/// write block on a probe socket while reads still come from the SSH socket.
/// Production passes the same socket for both, so this is the pre-split wait.
async fn wait_for_pump(
    read_readiness: &TcpStream,
    write_readiness: &TcpStream,
    notify: &Notify,
    action: PumpAction,
) -> std::io::Result<()> {
    match action {
        PumpAction::WaitRead => tokio::select! {
            result = read_readiness.readable() => result,
            () = notify.notified() => Ok(()),
        },
        PumpAction::WaitWrite => tokio::select! {
            result = write_readiness.writable() => result,
            () = notify.notified() => Ok(()),
        },
        PumpAction::WaitReadWrite => tokio::select! {
            result = read_readiness.readable() => result,
            result = write_readiness.writable() => result,
            () = notify.notified() => Ok(()),
        },
        PumpAction::WaitNotify => {
            notify.notified().await;
            Ok(())
        }
        PumpAction::Yield | PumpAction::Closed => Err(std::io::Error::other("invalid pump wait")),
    }
}

/// One `docker system dial-stdio` exec request, as a byte duplex.
struct SessionDuplex<T> {
    shared: Arc<Mutex<SharedDriver<T>>>,
    /// A clone of the cancellation state the shared driver's guard owns.
    ///
    /// The guard itself lives inside `shared`, which the pump can keep alive
    /// after this duplex is dropped, so `Drop` needs its own handle to signal
    /// cancellation.
    control: EstablishmentControl,
    /// Keeps the read readiness handle alive for the pump's `Weak`.
    _read_readiness: Arc<TcpStream>,
    /// Keeps the write readiness handle alive for the pump's `Weak`.
    ///
    /// Production uses the same allocation as the read handle; the field is
    /// separate so a test can use a different socket for write readiness.
    _write_readiness: Arc<TcpStream>,
    /// Wakes the pump when the application adds credit, admits a packet, or
    /// asks for flush/shutdown.
    notify: Arc<Notify>,
    pump: tokio::task::JoinHandle<()>,
}

impl<T> Drop for SessionDuplex<T> {
    /// Commits cancellation before aborting the pump.
    ///
    /// The pump may be inside a synchronous step and still own an upgraded
    /// `shared` `Arc`, which owns the session guard. `abort` only takes effect
    /// when that step next yields, so aborting alone would leave the guard
    /// alive and every later effect admissible for the rest of the step.
    /// `request_cancel` commits cancellation without waiting for the effect
    /// ordering lock: an effect that already passed its check remains
    /// committed and runs to completion, and every check after this returns
    /// refuses. Its socket shutdown is opportunistic — `request_cancel` takes
    /// the registration lock with `try_lock` — so under contention that
    /// shutdown can be deferred to the guard's own drop. Refusing later effects
    /// does not depend on it.
    fn drop(&mut self) {
        self.control.request_cancel();
        self.pump.abort();
    }
}

impl<T: Read + Write + Send + 'static> AsyncRead for SessionDuplex<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = this.shared.lock().unwrap();
        if !state.inbound.bytes.is_empty() {
            let count = state.inbound.copy_into(buffer);
            // Credited as the bytes leave the buffer rather than as they
            // arrive: the remote may not send its next packet until the window
            // allows it, so crediting on arrival would stall any response
            // larger than one window at exactly that boundary.
            state
                .established
                .credit(u32::try_from(count).unwrap_or(u32::MAX));
            state.wake_writer();
            drop(state);
            // The pump owns credit flushing when the application is not
            // reading, so wake it after adding credit.
            this.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if let Some(failure) = state.failure_io() {
            return Poll::Ready(Err(failure));
        }
        if state.remote_eof || state.closed {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(context.waker().clone());
        Poll::Pending
    }
}

impl<T: Read + Write + Send + 'static> AsyncWrite for SessionDuplex<T> {
    /// Copies at most one bounded admission slot and returns its length once.
    ///
    /// This never drives the channel. The pump admits the copied bytes later,
    /// so the caller's buffer is not referenced after this returns. `Pending`
    /// means nothing from this call was enqueued.
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = this.shared.lock().unwrap();
        if let Some(failure) = state.failure_io() {
            return Poll::Ready(Err(failure));
        }
        if state.closed {
            return Poll::Ready(Err(closed("the session is closed")));
        }
        if state.shutdown != Completion::Idle {
            return Poll::Ready(Err(closed("the session is shutting down")));
        }
        // One admission at a time: the pump must empty the slot and finish the
        // packet it admitted before another write can be accepted. This keeps
        // the accepted length attributable to exactly one buffer, and never
        // enqueues past the remote window.
        let available = usize::try_from(state.established.available_window()).unwrap_or(0);
        if !state.outbound.is_empty() || available == 0 || !state.established.accepts_data() {
            state.write_waker = Some(context.waker().clone());
            drop(state);
            this.notify.notify_one();
            return Poll::Pending;
        }
        let count = bytes.len().min(MAX_ADMISSION_BYTES).min(available);
        state.outbound.extend_from_slice(&bytes[..count]);
        // New bytes invalidate a flush that finished before they arrived.
        if state.flush == Completion::Done {
            state.flush = Completion::Idle;
        }
        drop(state);
        this.notify.notify_one();
        Poll::Ready(Ok(count))
    }

    /// Asks the pump to finish admitted output and waits for its observation.
    ///
    /// This method never calls the channel driver. A completed flush stays
    /// completed until `poll_write` enqueues new bytes. A recorded session
    /// failure is reported in preference to that completed state, because the
    /// pump can fail after marking the flush done and a caller must not read
    /// the failure as a clean finish.
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.shared.lock().unwrap();
        if let Some(failure) = state.failure_io() {
            return Poll::Ready(Err(failure));
        }
        if state.closed || state.shutdown == Completion::Done || state.flush == Completion::Done {
            return Poll::Ready(Ok(()));
        }
        state.flush = Completion::Requested;
        state.write_waker = Some(context.waker().clone());
        drop(state);
        this.notify.notify_one();
        Poll::Pending
    }

    /// Asks the pump to send the local half-close EOF exactly once.
    ///
    /// This method never calls the channel driver. A second shutdown observes
    /// the same completion instead of admitting a second EOF.
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.shared.lock().unwrap();
        if let Some(failure) = state.failure_io() {
            return Poll::Ready(Err(failure));
        }
        if state.closed || state.shutdown == Completion::Done {
            return Poll::Ready(Ok(()));
        }
        state.shutdown = Completion::Requested;
        state.write_waker = Some(context.waker().clone());
        drop(state);
        this.notify.notify_one();
        Poll::Pending
    }
}

/// The I/O error for a session the remote has closed.
fn closed(when: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        format!("the Engine closed the SSH session {when}"),
    )
}

/// Converts a crate error into the I/O error the async traits speak.
fn io_error(error: &Error) -> std::io::Error {
    if let Some(kind) = error.transport_timeout_kind() {
        return std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            crate::TransportTimeout {
                kind,
                message: ESTABLISHMENT_TIMEOUT_MESSAGE.to_owned(),
            },
        );
    }
    if let Some(reason) = error.managed_ssh_establishment_failure() {
        return std::io::Error::other(reason);
    }
    error.managed_ssh_host_key_rejection().map_or_else(
        || std::io::Error::other(ESTABLISHMENT_FAILURE_MESSAGE),
        std::io::Error::other,
    )
}

/// Wraps a connect, handshake, or session failure with the target it happened
/// against.
fn transport_error(what: impl std::fmt::Display, error: impl std::fmt::Display) -> Error {
    Error::transport(format!("failed to {what}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::{
        MANAGED_SSH_GATE_MESSAGE, ManagedSshOptions, WouldBlock, managed_establishment_gate,
        managed_establishment_is_safe, managed_ssh_target,
    };
    use crate::SshIdentity;
    use crate::raw::RawTarget;
    use base64::Engine as _;
    use neotales_ssh::channel::MAX_CHANNEL_PACKET_SIZE;
    use neotales_ssh::server::ServerTransportError;
    use neotales_ssh::session::SESSION_CHANNEL_TYPE;
    use neotales_ssh::transport::TransportError;

    /// Exact private gate decision; public routing tests exercise both policies.
    #[test]
    fn the_managed_gate_is_open_unless_explicitly_closed() {
        managed_establishment_is_safe().expect("the default gate must be open");
        let closed = managed_establishment_gate(true).expect_err("explicit closure");
        assert_eq!(
            closed.to_string(),
            format!("Docker transport error: {MANAGED_SSH_GATE_MESSAGE}")
        );
        assert!(
            managed_establishment_gate(false).is_ok(),
            "the open branch must allow the normal route"
        );
        assert!(
            managed_establishment_gate(true).is_err(),
            "the closed branch must return the shared diagnostic"
        );
    }

    /// Private effect-boundary observation: closure must not even enter the
    /// supervised path, whose first work can resolve DNS and then dial/read
    /// trust and identity files. Missing paths alone cannot detect file reads.
    #[tokio::test]
    async fn explicit_closure_refuses_before_the_first_establishment_effect() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = ManagedSshOptions::from_endpoint(
            "ssh://test@no-peer.invalid",
            SshIdentity::KeyFile(directory.path().join("identity")),
            Some(&directory.path().join("known_hosts")),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(!options.require_closed, "default options must be open");
        options.require_closed = true;
        let starts = Arc::new(AtomicUsize::new(0));
        let error = super::TEST_ESTABLISHMENT_START
            .scope(Arc::clone(&starts), super::open(&options))
            .await
            .err()
            .expect("explicit closure must refuse");
        assert_eq!(starts.load(Ordering::SeqCst), 0, "establishment was polled");
        assert_eq!(
            error.to_string(),
            format!("Docker transport error: {MANAGED_SSH_GATE_MESSAGE}")
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    /// A channel transport whose input is scripted and whose next write can be
    /// made to fail once with `WouldBlock`.
    #[derive(Default)]
    struct FakeSetupTransport {
        input: std::collections::VecDeque<Vec<u8>>,
        writes: Vec<Vec<u8>>,
        block_next_write: Arc<std::sync::atomic::AtomicBool>,
        would_block: Arc<std::sync::atomic::AtomicU8>,
    }

    impl neotales_ssh::channel::ChannelTransport for FakeSetupTransport {
        fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
            if self.block_next_write.swap(false, Ordering::SeqCst) {
                self.would_block.store(2, Ordering::SeqCst);
                return Err(());
            }
            self.writes.push(payload.to_vec());
            Ok(())
        }

        fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
            self.input.pop_front().ok_or(())
        }
    }

    fn opened(local: u32, remote: u32) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(91);
        writer.write_uint32(local);
        writer.write_uint32(remote);
        writer.write_uint32(super::INITIAL_CHANNEL_WINDOW);
        writer.write_uint32(MAX_CHANNEL_PACKET_SIZE);
        writer.into_bytes()
    }

    fn global_request(want_reply: bool) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(80);
        writer.write_string(b"unsupported@example.com").unwrap();
        writer.write_boolean(want_reply);
        writer.into_bytes()
    }

    fn request_succeeded(local: u32) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(99);
        writer.write_uint32(local);
        writer.into_bytes()
    }

    fn extended_data(local: u32, data: &[u8]) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(95);
        writer.write_uint32(local);
        writer.write_uint32(1);
        writer.write_string(data).unwrap();
        writer.into_bytes()
    }

    /// `SSH_MSG_CHANNEL_EOF` (RFC 4254 §5.3), message number 96.
    fn eof_packet(local: u32) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(96);
        writer.write_uint32(local);
        writer.into_bytes()
    }

    /// `SSH_MSG_CHANNEL_DATA` (RFC 4254 §5.2), message number 94.
    fn data_packet(local: u32, data: &[u8]) -> Vec<u8> {
        let mut writer = neotales_ssh::Writer::new();
        writer.write_byte(94);
        writer.write_uint32(local);
        writer.write_string(data).unwrap();
        writer.into_bytes()
    }

    #[test]
    fn early_extended_data_fails_establishment_instead_of_being_dropped() {
        let would_block = WouldBlock::default();
        let transport = FakeSetupTransport {
            input: [
                opened(0, 7),
                extended_data(0, b"stderr-before-exec"),
                request_succeeded(0),
            ]
            .into(),
            would_block: Arc::clone(&would_block.0),
            ..FakeSetupTransport::default()
        };
        let mut connection = super::ChannelConnection::new(transport);
        let session = connection.allocate_channel_id().unwrap();
        connection
            .open_channel(session, SESSION_CHANNEL_TYPE.as_bytes(), &[])
            .unwrap();
        let mut sessions = super::ClientSessions::from_connection(connection);
        let mut setup = super::Setup::new(session);

        assert!(matches!(
            setup.step(&mut sessions, &would_block).unwrap(),
            super::SetupStep::Progress
        ));
        let error = setup
            .step(&mut sessions, &would_block)
            .expect_err("early extended data was silently accepted");
        assert!(
            error
                .to_string()
                .contains("extended SSH session data before accepting exec"),
            "unexpected failure: {error}"
        );
    }

    #[test]
    fn blocked_global_reply_is_retained_and_written_before_the_next_read() {
        let would_block = WouldBlock::default();
        let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = FakeSetupTransport {
            input: [opened(0, 7), global_request(true), request_succeeded(0)].into(),
            block_next_write: Arc::clone(&gate),
            would_block: Arc::clone(&would_block.0),
            ..FakeSetupTransport::default()
        };
        let mut connection = super::ChannelConnection::new(transport);
        let session = connection.allocate_channel_id().unwrap();
        connection
            .open_channel(session, SESSION_CHANNEL_TYPE.as_bytes(), &[])
            .unwrap();
        let mut sessions = super::ClientSessions::from_connection(connection);
        let mut setup = super::Setup::new(session);

        // The peer confirms the channel. The setup sends `exec` next and then
        // consumes the global request, which asks for a reply.
        assert!(matches!(
            setup.step(&mut sessions, &would_block).unwrap(),
            super::SetupStep::Progress
        ));
        assert!(matches!(
            setup.step(&mut sessions, &would_block).unwrap(),
            super::SetupStep::Progress
        ));
        assert_eq!(sessions.connection().transport().writes.len(), 2);

        // The reply write reports WouldBlock. It must stay owed: no further
        // payload is read and no second reply is produced.
        gate.store(true, Ordering::SeqCst);
        assert!(matches!(
            setup.step(&mut sessions, &would_block).unwrap(),
            super::SetupStep::Blocked(super::BlockedOn::Write)
        ));
        assert_eq!(sessions.connection().transport().writes.len(), 2);

        // The retry writes the same failure and only then reads the accepted
        // exec reply.
        assert!(matches!(
            setup.step(&mut sessions, &would_block).unwrap(),
            super::SetupStep::Done
        ));
        let writes = sessions.connection().transport().writes.clone();
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[2], vec![82]);
    }

    #[tokio::test]
    async fn writable_wait_does_not_depend_on_peer_sending_readable_data() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Arc::new(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap(),
        );
        let (_peer, _) = listener.accept().await.unwrap();
        let mut slot = super::ReadinessSlot::default();
        tokio::time::timeout(
            Duration::from_millis(250),
            std::future::poll_fn(|cx| slot.poll(cx, &client, super::BlockedOn::Write)),
        )
        .await
        .expect("writable wait incorrectly depended on readable data")
        .unwrap();
    }

    #[tokio::test]
    async fn two_independent_read_waiters_are_both_woken() {
        use std::io::Write as _;
        let (_socket, readiness, mut peer) = readiness_socket_pair();
        let (polled_tx, mut polled_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let readiness = Arc::clone(&readiness);
            let polled = polled_tx.clone();
            tasks.push(tokio::spawn(async move {
                let mut reported = false;
                let mut slot = super::ReadinessSlot::default();
                std::future::poll_fn(|context| {
                    if !reported {
                        reported = true;
                        polled.send(()).unwrap();
                    }
                    slot.poll(context, &readiness, super::BlockedOn::Read)
                })
                .await
                .unwrap();
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), polled_rx.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), polled_rx.recv())
            .await
            .unwrap()
            .unwrap();
        peer.write_all(b"x").unwrap();
        for task in tasks {
            tokio::time::timeout(Duration::from_millis(300), task)
                .await
                .expect("a registered reader was not woken")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn two_independent_write_waiters_are_both_woken() {
        use std::io::Write as _;
        use tokio::io::AsyncReadExt;
        let (mut socket, readiness, peer) = readiness_socket_pair();
        tokio::time::timeout(Duration::from_secs(1), readiness.writable())
            .await
            .unwrap()
            .unwrap();
        let data = vec![9_u8; 65_536];
        let mut blocked = false;
        for _ in 0..512 {
            match socket.write(&data) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("unexpected write error: {error}"),
            }
        }
        assert!(blocked, "did not reach local backpressure");
        let (pending_tx, mut pending_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let readiness = Arc::clone(&readiness);
            let pending = pending_tx.clone();
            tasks.push(tokio::spawn(async move {
                let mut slot = super::ReadinessSlot::default();
                let mut reported = false;
                let mut polls = 0_usize;
                std::future::poll_fn(|context| {
                    polls += 1;
                    let result = slot.poll(context, &readiness, super::BlockedOn::Write);
                    if result.is_pending() && !reported {
                        reported = true;
                        pending.send(()).unwrap();
                    }
                    result
                })
                .await
                .unwrap();
                polls
            }));
        }
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), pending_rx.recv())
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tasks.iter().all(|task| !task.is_finished()));
        let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
        let drain = tokio::spawn(async move {
            let mut buffer = [0; 8192];
            while matches!(peer.read(&mut buffer).await, Ok(count) if count > 0) {}
        });
        for task in tasks {
            let polls = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("a registered writer was not woken")
                .unwrap();
            assert!(polls <= 5, "writable readiness spun {polls} times");
        }
        drop(socket);
        drop(readiness);
        tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .unwrap()
            .unwrap();
    }

    fn readiness_socket_pair() -> (
        super::Socket<std::net::TcpStream>,
        Arc<tokio::net::TcpStream>,
        std::net::TcpStream,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let readiness =
            Arc::new(tokio::net::TcpStream::from_std(socket.try_clone().unwrap()).unwrap());
        let slot = Arc::new(std::sync::OnceLock::new());
        assert!(slot.set(Arc::clone(&readiness)).is_ok());
        (
            super::Socket {
                inner: socket,
                would_block: Arc::new(std::sync::atomic::AtomicU8::new(0)),
                read_readiness: Arc::clone(&slot),
                write_readiness: slot,
                write_progress: new_write_progress(),
            },
            readiness,
            peer,
        )
    }

    #[tokio::test]
    async fn real_read_would_block_clears_readiness_and_wakes_on_new_data() {
        use std::io::{Read as _, Write as _};
        let (mut socket, readiness, mut peer) = readiness_socket_pair();
        peer.write_all(b"a").unwrap();
        tokio::time::timeout(Duration::from_secs(1), readiness.readable())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).unwrap(), 1);
        assert_eq!(&byte, b"a");
        assert_eq!(
            socket.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(socket.would_block.load(Ordering::SeqCst), 1);

        let mut polls = 0_usize;
        let mut slot = super::ReadinessSlot::default();
        let waiting = std::future::poll_fn(|cx| {
            polls += 1;
            slot.poll(cx, &readiness, super::BlockedOn::Read)
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(75), waiting)
                .await
                .is_err()
        );
        assert!(polls <= 4, "read readiness spun {polls} times");
        let waiting = std::future::poll_fn(|cx| slot.poll(cx, &readiness, super::BlockedOn::Read));
        let (ready, ()) = tokio::join!(
            async {
                tokio::time::timeout(Duration::from_secs(1), waiting)
                    .await
                    .unwrap()
                    .unwrap();
            },
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                peer.write_all(b"z").unwrap();
            },
        );
        let () = ready;
        assert_eq!(socket.read(&mut byte).unwrap(), 1);
        assert_eq!(&byte, b"z");
    }

    #[tokio::test]
    async fn real_write_would_block_clears_readiness_and_wakes_after_drain() {
        use std::io::Write as _;
        use tokio::io::AsyncReadExt;
        let (mut socket, readiness, peer) = readiness_socket_pair();
        tokio::time::timeout(Duration::from_secs(1), readiness.writable())
            .await
            .unwrap()
            .unwrap();
        let data = vec![7_u8; 65_536];
        let mut sent = 0_usize;
        let mut blocked = false;
        for _ in 0..512 {
            match socket.write(&data) {
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("unexpected write error: {error}"),
            }
        }
        assert!(
            sent > 0 && blocked,
            "did not reach deterministic local backpressure"
        );
        assert_eq!(socket.would_block.load(Ordering::SeqCst), 2);
        let mut polls = 0_usize;
        let mut slot = super::ReadinessSlot::default();
        let waiting = std::future::poll_fn(|cx| {
            polls += 1;
            slot.poll(cx, &readiness, super::BlockedOn::Write)
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(75), waiting)
                .await
                .is_err()
        );
        assert!(polls <= 4, "write readiness spun {polls} times");

        let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
        let drain = tokio::spawn(async move {
            let mut buffer = [0_u8; 8192];
            loop {
                match peer.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| slot.poll(cx, &readiness, super::BlockedOn::Write)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(socket.write(b"z").is_ok());
        drop(socket);
        drop(readiness);
        tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn pump_wait_readwrite_wakes_on_either_real_direction_or_notification() {
        use std::io::{Read as _, Write as _};
        use tokio::io::AsyncReadExt as _;

        for wake_read in [true, false] {
            let (mut socket, readiness, mut peer) = readiness_socket_pair();
            readiness.writable().await.unwrap();
            let data = vec![7_u8; 65_536];
            let mut blocked = false;
            for _ in 0..512 {
                match socket.write(&data) {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        blocked = true;
                        break;
                    }
                    Err(error) => panic!("write failed: {error}"),
                }
            }
            assert!(blocked);
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let notify = tokio::sync::Notify::new();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    super::wait_for_pump(
                        &readiness,
                        &readiness,
                        &notify,
                        super::PumpAction::WaitReadWrite
                    )
                )
                .await
                .is_err(),
                "wait returned before either direction was ready"
            );
            if wake_read {
                peer.write_all(b"x").unwrap();
                tokio::time::timeout(
                    Duration::from_secs(2),
                    super::wait_for_pump(
                        &readiness,
                        &readiness,
                        &notify,
                        super::PumpAction::WaitReadWrite,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(socket.read(&mut byte).unwrap(), 1);
                assert_eq!(byte, *b"x");
            } else {
                let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
                let drain = tokio::spawn(async move {
                    let mut buffer = [0_u8; 8192];
                    while matches!(peer.read(&mut buffer).await, Ok(count) if count > 0) {}
                });
                tokio::time::timeout(
                    Duration::from_secs(2),
                    super::wait_for_pump(
                        &readiness,
                        &readiness,
                        &notify,
                        super::PumpAction::WaitReadWrite,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(socket.write(b"x").is_ok());
                drop(socket);
                drop(readiness);
                tokio::time::timeout(Duration::from_secs(2), drain)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        let (_socket, readiness, _peer) = readiness_socket_pair();
        let notify = tokio::sync::Notify::new();
        notify.notify_one();
        tokio::time::timeout(
            Duration::from_secs(1),
            super::wait_for_pump(&readiness, &readiness, &notify, super::PumpAction::WaitRead),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // One fake peer covers adjustment and cancellation.
    async fn exhausted_remote_window_waits_for_adjustment_and_allows_cancellation() {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent},
        };
        use std::{io::Read as _, net::TcpListener, thread};
        use tokio::io::AsyncWriteExt;

        for cancel in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [104; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let content = format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port());
            std::fs::write(&path, &content).unwrap();
            let options = ManagedSshOptions::from_endpoint(
                &format!("ssh://fixture@{address}"),
                SshIdentity::Password("test-only".into()),
                Some(&path),
                Duration::from_secs(5),
            )
            .unwrap();
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |_| SessionDecision::accept(0));
                let session = match sessions.dispatch_one().unwrap() {
                    SessionEvent::Opened { session } => session,
                    other => panic!("expected channel open: {other:?}"),
                };
                assert!(matches!(
                    sessions.dispatch_one().unwrap(),
                    SessionEvent::Request { accepted: true, .. }
                ));
                let mut received = Vec::new();
                while received.len() < super::INITIAL_CHANNEL_WINDOW as usize {
                    if let SessionEvent::Data { data, .. } = sessions.dispatch_one().unwrap() {
                        received.extend_from_slice(&data);
                    }
                }
                assert_eq!(received.len(), super::INITIAL_CHANNEL_WINDOW as usize);
                assert!(received.iter().all(|byte| *byte == 0x5a));
                let _ = reached_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                if cancel {
                    let mut socket = sessions.into_inner().into_inner();
                    let closed = match socket.read(&mut [0]) {
                        Ok(0) => true,
                        Err(error) => matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ),
                        Ok(_) => false,
                    };
                    let _ = done_tx.send(closed);
                } else {
                    sessions.increase_local_window(session, 1).unwrap();
                    let event = sessions.dispatch_one().unwrap();
                    let _ = done_tx
                        .send(matches!(event, SessionEvent::Data { data, .. } if data == [0x5a]));
                }
            });
            let mut task = tokio::spawn(async move {
                let mut duplex = super::open_supervised(&options).await.unwrap();
                duplex
                    .write_all(&vec![0x5a; super::INITIAL_CHANNEL_WINDOW as usize + 1])
                    .await?;
                // The last byte is accepted into the admission slot before the
                // pump sends it, so a flush is required before the duplex is
                // dropped.
                duplex.flush().await
            });
            tokio::time::timeout(Duration::from_secs(3), reached_rx)
                .await
                .unwrap()
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(75), &mut task)
                    .await
                    .is_err(),
                "write advanced without a remote window adjustment"
            );
            if cancel {
                task.abort();
                assert!(
                    matches!(tokio::time::timeout(Duration::from_secs(1), task).await.unwrap(), Err(error) if error.is_cancelled())
                );
                release_tx.send(()).unwrap();
            } else {
                release_tx.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(3), done_rx)
                    .await
                    .unwrap()
                    .unwrap()
            );
            server.join().unwrap();
            assert_eq!(std::fs::read(path).unwrap(), content.as_bytes());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // Exercises two split tasks against one paused SSH peer.
    async fn split_read_and_write_both_wake_after_withheld_window_adjustment() {
        use futures_util::task::AtomicWaker;
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent},
        };
        use std::{
            future::Future as _,
            net::TcpListener,
            sync::{
                Arc,
                atomic::{AtomicBool, AtomicUsize, Ordering},
                mpsc,
            },
            task::Poll,
            thread,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for cancel_reader in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [105; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            std::fs::write(
                &path,
                format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port()),
            )
            .unwrap();
            let options = ManagedSshOptions::from_endpoint(
                &format!("ssh://fixture@{address}"),
                SshIdentity::Password("test-only".into()),
                Some(&path),
                Duration::from_secs(5),
            )
            .unwrap();
            let (window_tx, window_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            // The peer must outlive the writer's flush. Closing the socket as
            // soon as the final byte arrives races the pump's next read, and a
            // transport failure is reported in preference to the completed
            // flush, so the writer would see a truncated transport instead of
            // its own success. Teardown is explicit and bounded.
            let (teardown_tx, teardown_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |_| SessionDecision::accept(0));
                let session = match sessions.dispatch_one().unwrap() {
                    SessionEvent::Opened { session } => session,
                    other => panic!("expected channel open: {other:?}"),
                };
                assert!(matches!(
                    sessions.dispatch_one().unwrap(),
                    SessionEvent::Request { accepted: true, .. }
                ));
                let mut count = 0;
                while count < super::INITIAL_CHANNEL_WINDOW as usize {
                    if let SessionEvent::Data { data, .. } = sessions.dispatch_one().unwrap() {
                        assert!(data.iter().all(|byte| *byte == 0x5a));
                        count += data.len();
                    }
                }
                assert_eq!(count, super::INITIAL_CHANNEL_WINDOW as usize);
                let _ = window_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                sessions.increase_local_window(session, 1).unwrap();
                sessions.send_data(session, b"R").unwrap();
                let mut final_byte = false;
                for _ in 0..8 {
                    if let SessionEvent::Data { data, .. } = sessions.dispatch_one().unwrap() {
                        final_byte = data == [0x5a];
                        break;
                    }
                }
                let _ = done_tx.send(final_byte);
                teardown_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            });
            let duplex = super::open_supervised(&options).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(duplex);
            let armed = Arc::new(AtomicBool::new(false));
            let read_polls = Arc::new(AtomicUsize::new(0));
            let write_polls = Arc::new(AtomicUsize::new(0));
            let read_waker = Arc::new(AtomicWaker::new());
            let write_waker = Arc::new(AtomicWaker::new());
            let (first_read_tx, first_read_rx) = tokio::sync::oneshot::channel();
            let (pending_tx, mut pending_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut reader_task = Some({
                let armed = Arc::clone(&armed);
                let polls = Arc::clone(&read_polls);
                let force = Arc::clone(&read_waker);
                let pending = pending_tx.clone();
                tokio::spawn(async move {
                    let mut byte = [0];
                    let mut first = Some(first_read_tx);
                    let mut reported = false;
                    let mut operation = Box::pin(reader.read_exact(&mut byte));
                    std::future::poll_fn(|cx| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        force.register(cx.waker());
                        match operation.as_mut().poll(cx) {
                            Poll::Pending => {
                                if let Some(first) = first.take() {
                                    let _ = first.send(());
                                }
                                if armed.load(Ordering::SeqCst) && !reported {
                                    reported = true;
                                    pending.send("read").unwrap();
                                }
                                Poll::Pending
                            }
                            Poll::Ready(result) => Poll::Ready(result),
                        }
                    })
                    .await
                    .unwrap();
                    drop(operation);
                    byte
                })
            });
            tokio::time::timeout(Duration::from_secs(2), first_read_rx)
                .await
                .unwrap()
                .unwrap();
            let writer_task = {
                let armed = Arc::clone(&armed);
                let polls = Arc::clone(&write_polls);
                let force = Arc::clone(&write_waker);
                tokio::spawn(async move {
                    let data = vec![0x5a; super::INITIAL_CHANNEL_WINDOW as usize + 1];
                    let mut operation = Box::pin(async {
                        writer.write_all(&data).await?;
                        // The admission slot returns before the pump sends the
                        // final packet, so flush before dropping the half.
                        writer.flush().await
                    });
                    let mut reported = false;
                    std::future::poll_fn(|cx| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        force.register(cx.waker());
                        match operation.as_mut().poll(cx) {
                            Poll::Pending => {
                                if armed.load(Ordering::SeqCst) && !reported {
                                    reported = true;
                                    pending_tx.send("write").unwrap();
                                }
                                Poll::Pending
                            }
                            Poll::Ready(result) => Poll::Ready(result),
                        }
                    })
                    .await
                    .unwrap();
                })
            };
            tokio::time::timeout(Duration::from_secs(3), window_rx)
                .await
                .unwrap()
                .unwrap();
            armed.store(true, Ordering::SeqCst);
            read_waker.wake();
            write_waker.wake();
            let first = tokio::time::timeout(Duration::from_secs(1), pending_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let second = tokio::time::timeout(Duration::from_secs(1), pending_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_ne!(first, second, "both split operations must be pending");
            let before_read = read_polls.load(Ordering::SeqCst);
            let before_write = write_polls.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(75)).await;
            assert!(
                read_polls.load(Ordering::SeqCst) <= before_read + 4,
                "read task spun"
            );
            assert!(
                write_polls.load(Ordering::SeqCst) <= before_write + 4,
                "write task spun"
            );
            if cancel_reader {
                let task = reader_task.take().unwrap();
                task.abort();
                assert!(
                    matches!(tokio::time::timeout(Duration::from_secs(1), task).await.unwrap(), Err(error) if error.is_cancelled())
                );
            }
            release_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), writer_task)
                .await
                .expect("writer lost its readiness wake")
                .unwrap();
            if !cancel_reader {
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), reader_task.take().unwrap())
                        .await
                        .expect("reader lost its readiness wake")
                        .unwrap(),
                    [b'R']
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(2), done_rx)
                    .await
                    .unwrap()
                    .unwrap()
            );
            teardown_tx.send(()).unwrap();
            server.join().unwrap();
        }
    }

    #[test]
    fn inbound_buffer_reuses_space_across_many_windows_without_losing_bytes() {
        use tokio::io::ReadBuf;
        let mut inbound = super::InboundBuffer::default();
        let mut produced = 0_usize;
        let mut consumed = 0_usize;
        let mut append = |inbound: &mut super::InboundBuffer, count: usize| {
            let data: Vec<u8> = (produced..produced + count)
                .map(|offset| u8::try_from(offset % 251).unwrap())
                .collect();
            inbound.push(&data).unwrap();
            produced += count;
        };
        append(&mut inbound, 32_768);
        for _ in 0..128 {
            // Keep unread data resident while repeatedly consuming and
            // replenishing it: this is where a monotonically increasing
            // drained offset used to retain megabytes of old data.
            let mut output = [0_u8; 16_384];
            let mut buffer = ReadBuf::new(&mut output);
            assert_eq!(inbound.copy_into(&mut buffer), 16_384);
            for (index, byte) in buffer.filled().iter().enumerate() {
                assert_eq!(*byte, u8::try_from((consumed + index) % 251).unwrap());
            }
            consumed += buffer.filled().len();
            append(&mut inbound, 16_384);
            assert_eq!(inbound.bytes.len(), 32_768);
            assert!(inbound.bytes.capacity() <= 2 * super::INITIAL_CHANNEL_WINDOW as usize);
        }
        let mut output = vec![0_u8; 32_768];
        let mut buffer = ReadBuf::new(&mut output);
        assert_eq!(inbound.copy_into(&mut buffer), 32_768);
        for (index, byte) in buffer.filled().iter().enumerate() {
            assert_eq!(*byte, u8::try_from((consumed + index) % 251).unwrap());
        }
        assert!(inbound.bytes.is_empty());
    }

    #[test]
    fn inbound_buffer_rejects_receive_window_overflow_without_modification() {
        let mut inbound = super::InboundBuffer::default();
        let window = super::INITIAL_CHANNEL_WINDOW as usize;
        inbound.push(&vec![7; window]).unwrap();
        assert!(inbound.push(&[8]).is_err());
        assert_eq!(inbound.bytes.len(), window);
        assert!(inbound.bytes.iter().all(|byte| *byte == 7));
    }

    // Private backpressure branching: inject a decoded event at the application
    // boundary to exercise the retained slot independently of the receive-window
    // cap. The controlled peer verifies the actual credit packets.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One bounded transcript checks retention, no read, wakeups, and credit.
    async fn retained_event_stops_reads_and_returns_only_consumed_prefix_credit() {
        struct CountIo {
            socket: std::net::TcpStream,
            reads: Arc<AtomicUsize>,
            writes: Arc<AtomicUsize>,
        }
        impl std::io::Read for CountIo {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                std::io::Read::read(&mut self.socket, bytes)
            }
        }
        impl std::io::Write for CountIo {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                std::io::Write::write(&mut self.socket, bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                std::io::Write::flush(&mut self.socket)
            }
        }
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [134; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let peer = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let before = connection.channel(session).unwrap().remote_window();
            for increment in [1, 3] {
                assert!(matches!(connection.dispatch_one().unwrap(),
                    neotales_ssh::channel::ChannelEvent::WindowAdjusted { available, .. }
                    if available == before + increment));
            }
            done_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let readiness_socket = socket.try_clone().unwrap();
        let control = crate::ssh_cancellation::EstablishmentControl::new(
            std::time::Instant::now() + Duration::from_secs(5),
        );
        let crate::ssh_connect::Dialed { guard, .. } = crate::ssh_connect::Dialed::test_connected(
            socket.try_clone().unwrap(),
            control.clone(),
        )
        .unwrap();
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let transport = neotales_ssh::ClientConfig::new()
            .connect(
                CountIo {
                    socket,
                    reads: Arc::clone(&reads),
                    writes: Arc::clone(&writes),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        readiness_socket.set_nonblocking(true).unwrap();
        let readiness = Arc::new(tokio::net::TcpStream::from_std(readiness_socket).unwrap());
        let mut inbound = super::InboundBuffer::default();
        inbound
            .push(&vec![b'A'; super::INITIAL_CHANNEL_WINDOW as usize])
            .unwrap();
        let shared = Arc::new(std::sync::Mutex::new(super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            inbound,
        )));
        let mut duplex = super::SessionDuplex {
            shared: Arc::clone(&shared),
            control,
            _read_readiness: Arc::clone(&readiness),
            _write_readiness: readiness,
            notify: Arc::new(tokio::sync::Notify::new()),
            pump: tokio::spawn(std::future::pending()),
        };
        let before_reads = reads.load(Ordering::SeqCst);
        let before_writes = writes.load(Ordering::SeqCst);
        {
            let mut state = shared.lock().unwrap();
            assert!(
                state
                    .handle_inbound(Ok(super::Progress::Data(b"BBB".to_vec())))
                    .is_none()
            );
            for _ in 0..8 {
                assert!(matches!(state.pump_step(), super::PumpAction::WaitNotify));
            }
            assert_eq!(state.retained_event.as_deref(), Some(b"BBB".as_slice()));
        }
        assert_eq!(reads.load(Ordering::SeqCst), before_reads);
        assert_eq!(writes.load(Ordering::SeqCst), before_writes);
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        for count in [1, 2] {
            let mut bytes = vec![0; count];
            let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
            assert!(
                tokio::io::AsyncRead::poll_read(
                    std::pin::Pin::new(&mut duplex),
                    &mut context,
                    &mut buffer
                )
                .is_ready()
            );
            assert_eq!(buffer.filled(), vec![b'A'; count]);
            let mut state = shared.lock().unwrap();
            assert!(state.established.flush_credit().unwrap().is_none());
        }
        let wake = Arc::new(CountWake(AtomicUsize::new(0)));
        {
            let mut state = shared.lock().unwrap();
            let before_delivery = writes.load(Ordering::SeqCst);
            state.read_waker = Some(std::task::Waker::from(Arc::clone(&wake)));
            assert!(state.deliver_retained_event().unwrap());
            assert!(!state.deliver_retained_event().unwrap());
            assert!(state.established.flush_credit().unwrap().is_none());
            assert_eq!(writes.load(Ordering::SeqCst), before_delivery);
            assert_eq!(
                state
                    .inbound
                    .bytes
                    .iter()
                    .rev()
                    .take(3)
                    .copied()
                    .collect::<Vec<_>>(),
                b"BBB"
            );
            assert_eq!(
                state.inbound.bytes.len(),
                super::INITIAL_CHANNEL_WINDOW as usize
            );
        }
        assert!(wake.0.load(Ordering::SeqCst) > 0);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        release_tx.send(()).unwrap();
        drop(duplex);
        peer.join().unwrap();
    }

    #[test]
    fn oversized_trust_file_is_rejected_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let mut contents = vec![b' '; 4 * 1024 * 1024 + 1];
        contents[0] = b'#';
        std::fs::write(&path, &contents).unwrap();
        let error = super::load_known_hosts(&path).unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            contents.len() as u64
        );
    }

    #[test]
    fn oversized_identity_is_rejected_without_printing_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        let mut contents = vec![b'x'; 1024 * 1024 + 1];
        contents[..12].copy_from_slice(b"TEST-CANARY!");
        std::fs::write(&path, contents).unwrap();
        let error = super::public_key_signer(&path, None).unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(text.contains("exceeds"), "{text}");
        assert!(!text.contains("TEST-CANARY!"));
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_one_more_byte() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(
            &*super::read_bounded(&path, 4, "test input").unwrap(),
            b"1234"
        );
        std::fs::write(&path, b"12345").unwrap();
        let error = super::read_bounded(&path, 4, "test input").unwrap_err();
        assert!(error.to_string().contains("4-byte limit"));
    }

    #[test]
    fn encrypted_identity_kdf_limit_is_checked_before_key_parsing() {
        fn synthetic_header(rounds: u32) -> Vec<u8> {
            let mut options = neotales_ssh::Writer::new();
            options.write_string(b"TEST-SALT-CANARY").unwrap();
            options.write_u32(rounds);
            let mut header = neotales_ssh::Writer::new();
            header.write_string(b"aes256-ctr").unwrap();
            header.write_string(b"bcrypt").unwrap();
            header.write_string(&options.into_bytes()).unwrap();
            let mut bytes = b"openssh-key-v1\0".to_vec();
            bytes.extend_from_slice(&header.into_bytes());
            bytes
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        let at_limit = synthetic_header(super::MAX_BCRYPT_ROUNDS);
        assert!(super::preflight_identity_kdf(&at_limit, &path).is_ok());
        let above = synthetic_header(super::MAX_BCRYPT_ROUNDS + 1);
        for bytes in [
            above.clone(),
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(&above)
            )
            .into_bytes(),
        ] {
            std::fs::write(&path, &bytes).unwrap();
            let error = super::public_key_signer(&path, None).unwrap_err();
            let text = format!("{error} {error:?}");
            assert!(text.contains("bcrypt limit"), "{text}");
            assert!(!text.contains("TEST-SALT-CANARY"));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        assert!(super::preflight_identity_kdf(&synthetic_header(0), &path).is_err());
        assert!(super::preflight_identity_kdf(b"openssh-key-v1\0\xff", &path).is_err());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One synthetic fixture exercises both encodings and cancellation.
    async fn oversized_synthetic_rsa_identity_is_rejected_before_handshake() {
        use std::{io::Write as _, net::TcpListener};
        use tokio::io::AsyncReadExt;

        // Synthetic structural fixture: it contains no real user key.
        let mut public = neotales_ssh::Writer::new();
        public.write_string("ssh-rsa").unwrap();
        public.write_mpint(&[3_u8][..]).unwrap();
        public.write_mpint(&[15_u8][..]).unwrap();
        let mut private = neotales_ssh::Writer::new();
        private.write_u32(17);
        private.write_u32(17);
        private.write_string("ssh-rsa").unwrap();
        for (index, value) in [15_u8, 3, 7, 2, 3, 5].into_iter().enumerate() {
            let mut component = if index == 2 {
                vec![b'A'; 32 * 1024]
            } else {
                vec![value]
            };
            if index == 2 {
                component[..10].copy_from_slice(b"CANARY-RSA");
            }
            private.write_mpint(&component[..]).unwrap();
        }
        private.write_string(b"synthetic-only").unwrap();
        let mut section = private.into_bytes();
        let padding = (8 - section.len() % 8) % 8;
        for byte in 1..=padding {
            section.push(u8::try_from(byte).unwrap());
        }
        let mut outer = neotales_ssh::Writer::new();
        outer.write_string("none").unwrap();
        outer.write_string("none").unwrap();
        outer.write_string(b"").unwrap();
        outer.write_u32(1);
        outer.write_string(&public.into_bytes()).unwrap();
        outer.write_string(&section).unwrap();
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend_from_slice(&outer.into_bytes());
        let armored = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&raw)
        )
        .into_bytes();
        for bytes in [&raw, &armored] {
            let directory = tempfile::tempdir().unwrap();
            let identity = directory.path().join("synthetic-identity");
            let known = directory.path().join("known_hosts");
            std::fs::write(&identity, bytes).unwrap();
            std::fs::write(&known, b"# no keys\n").unwrap();
            // The parser still rejects this exact structural defect. Its local
            // diagnostic is not the supervised transport's public diagnostic.
            let parse_error = super::public_key_signer(&identity, None).unwrap_err();
            assert!(
                parse_error
                    .to_string()
                    .contains("OpenSSH private-key fields are invalid")
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let options = ManagedSshOptions::from_endpoint(
                &format!("ssh://fixture@{address}"),
                SshIdentity::KeyFile(identity.clone()),
                Some(&known),
                Duration::from_secs(5),
            )
            .unwrap();
            let task = tokio::spawn(async move { super::open_supervised(&options).await });
            let (mut peer, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert!(
                received.is_empty(),
                "client sent handshake bytes after invalid key"
            );
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            let Err(error) = result else {
                panic!("oversized RSA identity was accepted")
            };
            let diagnostic = format!("{error} {error:?}");
            assert_eq!(
                error.managed_ssh_establishment_failure(),
                Some(crate::ManagedSshEstablishmentFailure::IdentityFile)
            );
            assert!(diagnostic.contains("file details withheld"));
            assert!(!error.is_managed_ssh_authentication_rejected());
            assert_eq!(error.transport_timeout_kind(), None);
            assert_eq!(error.managed_ssh_host_key_rejection(), None);
            assert!(!diagnostic.contains("CANARY-RSA"));
            assert_eq!(std::fs::read(&identity).unwrap(), *bytes);
            assert_eq!(std::fs::read(&known).unwrap(), b"# no keys\n");

            // The read is committed before cancellation. A late worker may
            // finish parsing the bounded synthetic input, but cannot start
            // the following socket effect.
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let control = crate::ssh_cancellation::EstablishmentControl::new(
                std::time::Instant::now() + Duration::from_secs(5),
            );
            let dialed = crate::ssh_connect::dial("127.0.0.1", address.port(), control.clone())
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
            let worker_identity = identity.clone();
            let task = tokio::spawn(crate::ssh_worker::supervise(
                dialed,
                Duration::from_secs(1),
                &crate::ssh_worker::WORKERS,
                move |mut socket, control| {
                    control.try_effect(|| ()).unwrap();
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(2));
                    let rejected = super::public_key_signer(&worker_identity, None).is_err();
                    let next = control.try_effect(|| ());
                    let _ = finished_tx.send((rejected, next));
                    if next.is_ok() {
                        socket.write_all(b"handshake")?;
                    }
                    Ok(())
                },
            ));
            tokio::time::timeout(Duration::from_secs(1), entered_rx)
                .await
                .unwrap()
                .unwrap();
            control.request_cancel();
            let cancelled = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(cancelled, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionAborted)
            );
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut received))
                .await
                .unwrap()
                .unwrap();
            assert!(received.is_empty(), "expected received to be empty");
            release_tx.send(()).unwrap();
            let (rejected, next) = tokio::time::timeout(Duration::from_secs(2), finished_rx)
                .await
                .unwrap()
                .unwrap();
            assert!(rejected);
            assert_eq!(next, Err(crate::ssh_cancellation::Refused::Cancelled));
        }
    }

    #[tokio::test]
    async fn configured_open_deadline_covers_handshake_auth_channel_and_exec() {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, ServerAuthStep, ServerAuthenticator, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent},
        };
        use std::{io::Read as _, net::TcpListener, sync::mpsc, thread, time::Instant};
        for phase in ["handshake", "auth", "channel", "exec"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [83; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let contents = format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port());
            std::fs::write(&path, &contents).unwrap();
            let options = ManagedSshOptions::from_endpoint(
                &format!("ssh://fixture@{address}"),
                SshIdentity::Password("test-only".into()),
                Some(&path),
                Duration::from_millis(750),
            )
            .unwrap();
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                if phase == "handshake" {
                    peer.read_exact(&mut [0]).unwrap();
                    let _ = reached_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(3));
                    return;
                }
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                if phase == "auth" {
                    let mut auth = ServerAuthenticator::new(&mut transport, &policy);
                    assert_eq!(auth.step().unwrap(), ServerAuthStep::ServiceAccepted);
                    let _ = reached_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(3));
                    return;
                }
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |_| SessionDecision::accept(0));
                if phase == "exec" {
                    assert!(matches!(
                        sessions.dispatch_one().unwrap(),
                        SessionEvent::Opened { .. }
                    ));
                }
                let _ = reached_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
            });
            let start = Instant::now();
            let task = tokio::spawn(async move { super::open_supervised(&options).await });
            tokio::time::timeout(Duration::from_secs(2), reached_rx)
                .await
                .unwrap()
                .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_err(), "{phase} unexpectedly completed");
            assert!(
                start.elapsed() >= Duration::from_millis(400),
                "{phase} failed before the peer was stalled"
            );
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "{phase} exceeded the configured establishment budget"
            );
            release_tx.send(()).unwrap();
            server.join().unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
        }
    }

    #[test]
    fn unrepresentable_deadline_fails_before_reading_or_dialing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("does-not-exist");
        let result = ManagedSshOptions::from_endpoint(
            "ssh://fixture@127.0.0.1:1",
            SshIdentity::KeyFile(directory.path().join("unread-identity")),
            Some(&path),
            Duration::MAX,
        );
        assert!(
            matches!(result, Err(ref error) if error.to_string().contains("establishment_timeout"))
        );
        assert!(!path.exists());
        assert!(!directory.path().join("unread-identity").exists());
    }

    // Test the intended ordering with the real loader and protocol functions:
    // the read commits at the first check; cancellation cannot retract it, but
    // the second check prevents starting the next phase after it returns.
    fn supervised_test_protocol(
        socket: crate::ssh_worker::DeadlineSocket,
        control: &crate::ssh_cancellation::EstablishmentControl,
        options: &ManagedSshOptions,
    ) -> std::io::Result<super::SessionParts<crate::ssh_worker::DeadlineSocket>> {
        let check = || {
            control
                .try_effect(|| ())
                .map_err(|error| std::io::Error::other(format!("{error:?}")))
        };
        check()?;
        let known = super::load_known_hosts(&options.known_hosts_path)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        check()?;
        let methods = super::auth_methods(&options.identity)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        check()?;
        let transport = super::checked_handshake(
            socket,
            &known,
            &options.known_hosts_path,
            &options.host_token,
            &options.host,
            options.port,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        super::authenticate_and_exec(transport, &methods, options, super::WouldBlock::default())
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    /// A controlled peer that authenticates, then hands the channel connection
    /// to `script`. The client side is the real managed establishment path.
    fn raw_peer<F>(
        signer: neotales_ssh::hostkey::Ed25519Signer,
        listener: std::net::TcpListener,
        script: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: FnOnce(
                &mut neotales_ssh::channel::ChannelConnection<
                    neotales_ssh::server::ServerTransport<std::net::TcpStream>,
                >,
            ) + Send
            + 'static,
    {
        raw_peer_inner(signer, listener, false, script)
    }

    /// The same controlled peer without the strict-KEX server marker, so a
    /// test can exercise the permitted non-strict rekey IGNORE path.
    fn raw_peer_non_strict<F>(
        signer: neotales_ssh::hostkey::Ed25519Signer,
        listener: std::net::TcpListener,
        script: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: FnOnce(
                &mut neotales_ssh::channel::ChannelConnection<
                    neotales_ssh::server::ServerTransport<std::net::TcpStream>,
                >,
            ) + Send
            + 'static,
    {
        raw_peer_inner(signer, listener, true, script)
    }

    fn raw_peer_inner<F>(
        signer: neotales_ssh::hostkey::Ed25519Signer,
        listener: std::net::TcpListener,
        non_strict: bool,
        script: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: FnOnce(
                &mut neotales_ssh::channel::ChannelConnection<
                    neotales_ssh::server::ServerTransport<std::net::TcpStream>,
                >,
            ) + Send
            + 'static,
    {
        std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut config = neotales_ssh::server::ServerConfig::new(signer);
            if non_strict {
                let mut proposal = config.kexinit().clone();
                proposal
                    .kex_algorithms
                    .retain(|name| name != "kex-strict-s-v00@openssh.com");
                config = config.with_kexinit(proposal);
            }
            let mut transport = config.connect(peer).unwrap();
            let policy = neotales_ssh::auth::ServerAuthPolicy::new(2)
                .unwrap()
                .with_password_callback(|_| true);
            neotales_ssh::auth::authenticate_server(&mut transport, &policy).unwrap();
            let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
            script(&mut connection);
        })
    }

    /// Writes the known-hosts entry for one loopback peer and builds the
    /// managed options the real client uses against it.
    fn options_for_peer(
        address: std::net::SocketAddr,
        signer: &neotales_ssh::hostkey::Ed25519Signer,
    ) -> (tempfile::TempDir, ManagedSshOptions) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(signer.public_key().to_blob().unwrap());
        std::fs::write(
            &path,
            format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port()),
        )
        .unwrap();
        let options = ManagedSshOptions::from_endpoint(
            &format!("ssh://fixture@{address}"),
            SshIdentity::Password("test-only".into()),
            Some(&path),
            Duration::from_secs(5),
        )
        .unwrap();
        (directory, options)
    }

    fn confirm_peer_session<T>(connection: &mut neotales_ssh::channel::ChannelConnection<T>) -> u32
    where
        T: neotales_ssh::channel::ChannelTransport,
    {
        match connection.dispatch_one().unwrap() {
            neotales_ssh::channel::ChannelEvent::OpenRequest(request) => {
                connection
                    .confirm_open(request.sender_channel(), 0)
                    .unwrap();
                0
            }
            other => panic!("expected a session channel open: {other:?}"),
        }
    }

    fn accept_exec<T>(connection: &mut neotales_ssh::channel::ChannelConnection<T>, session: u32)
    where
        T: neotales_ssh::channel::ChannelTransport,
    {
        loop {
            match connection.dispatch_one().unwrap() {
                neotales_ssh::channel::ChannelEvent::Request {
                    request_type,
                    want_reply: true,
                    ..
                } if request_type == b"exec" => {
                    connection.send_request_success(session).unwrap();
                    return;
                }
                _ => {}
            }
        }
    }

    /// A client socket whose writes can be stopped after a chosen number of
    /// bytes, forcing the owned driver to retain a partially written packet.
    struct Gate {
        block_after: Option<usize>,
    }

    struct GatedSocket {
        socket: std::net::TcpStream,
        gate: Arc<std::sync::Mutex<Gate>>,
    }

    impl std::io::Read for GatedSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.socket.read(bytes)
        }
    }

    impl std::io::Write for GatedSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut gate = self.gate.lock().unwrap();
            if let Some(remaining) = gate.block_after {
                if remaining == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                let length = remaining.min(bytes.len());
                let count = self.socket.write(&bytes[..length])?;
                gate.block_after = Some(remaining - count);
                return Ok(count);
            }
            self.socket.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.socket.flush()
        }
    }

    fn gated_duplex<T: std::io::Read + std::io::Write + Send + 'static>(
        parts: super::SessionParts<T>,
        guard: crate::ssh_connect::CancelOnDrop,
        read_readiness: Arc<tokio::net::TcpStream>,
        write_readiness: Arc<tokio::net::TcpStream>,
        write_progress: Arc<std::sync::atomic::AtomicU64>,
        stall_bound: Duration,
    ) -> super::SessionDuplex<T> {
        let control = guard.control.clone();
        let shared = Arc::new(std::sync::Mutex::new(super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            super::InboundBuffer::default(),
        )));
        let notify = Arc::new(tokio::sync::Notify::new());
        let pump = tokio::spawn(super::pump(
            Arc::downgrade(&shared),
            Arc::downgrade(&read_readiness),
            Arc::downgrade(&write_readiness),
            Arc::clone(&notify),
            write_progress,
            stall_bound,
        ));
        super::SessionDuplex {
            shared,
            control,
            _read_readiness: read_readiness,
            _write_readiness: write_readiness,
            notify,
            pump,
        }
    }

    /// A fresh socket write-progress counter for a fixture.
    fn new_write_progress() -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(0))
    }

    /// Wall-clock bound for one pump observation.
    ///
    /// Paused Tokio time cannot bound a wait that is blocked on real I/O, so
    /// this bound is a real-time notification from a helper thread. It is not
    /// the synchronization: the test waits for the pump's own event, and the
    /// bound only distinguishes scheduler starvation from a missing arm.
    const PUMP_EVENT_BOUND: Duration = Duration::from_secs(10);

    /// Waits for the pump's next iteration, bounded by real time.
    ///
    /// Returns `false` when the wall bound expired before the pump reported a
    /// step. The pump notifies `events` at the end of every iteration; the
    /// paused Tokio clock is not involved and cannot fire this early.
    async fn await_pump_event(
        events: &tokio::sync::Notify,
        deadline: &tokio::sync::Notify,
    ) -> bool {
        tokio::select! {
            () = events.notified() => true,
            () = deadline.notified() => false,
        }
    }

    /// Owns one bounded blocking worker that prevents paused-time auto-advance.
    ///
    /// Each armed deadline has an explicit cancellation command, so an early
    /// successful observation cannot consume the next phase's timeout. The
    /// worker is released and joined on normal completion, and disconnects on
    /// unwind.
    enum PumpDeadlineCommand {
        Arm(Duration, Arc<tokio::sync::Notify>),
        Cancel,
    }

    struct PumpDeadlineSupervisor {
        requests: Option<std::sync::mpsc::Sender<PumpDeadlineCommand>>,
        worker: Option<tokio::task::JoinHandle<()>>,
    }

    impl PumpDeadlineSupervisor {
        /// Starts the inhibitor and waits until the blocking worker is running.
        async fn start() -> Self {
            let (requests, receiver) = std::sync::mpsc::channel::<PumpDeadlineCommand>();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let worker = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                while let Ok(command) = receiver.recv() {
                    let PumpDeadlineCommand::Arm(bound, notify) = command else {
                        continue;
                    };
                    match receiver.recv_timeout(bound) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => notify.notify_one(),
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        Ok(PumpDeadlineCommand::Cancel) => {}
                        Ok(PumpDeadlineCommand::Arm(_, _)) => {
                            // This test arms only after cancelling its prior
                            // phase. Preserve a strict single-deadline contract.
                            notify.notify_one();
                        }
                    }
                }
            });
            started_rx
                .await
                .expect("deadline inhibitor failed to start");
            Self {
                requests: Some(requests),
                worker: Some(worker),
            }
        }

        /// Returns a notification fired after the requested wall-clock bound.
        fn deadline(&self, bound: Duration) -> Arc<tokio::sync::Notify> {
            let notify = Arc::new(tokio::sync::Notify::new());
            self.requests
                .as_ref()
                .expect("deadline inhibitor already released")
                .send(PumpDeadlineCommand::Arm(bound, Arc::clone(&notify)))
                .expect("deadline inhibitor stopped unexpectedly");
            notify
        }

        /// Cancels the current deadline after its phase succeeds.
        fn cancel_deadline(&self) {
            self.requests
                .as_ref()
                .expect("deadline inhibitor already released")
                .send(PumpDeadlineCommand::Cancel)
                .expect("deadline inhibitor stopped unexpectedly");
        }

        /// Releases the inhibitor and awaits the blocking task.
        async fn finish(mut self) {
            drop(self.requests.take());
            if let Some(worker) = self.worker.take() {
                worker.await.expect("deadline inhibitor panicked");
            }
        }
    }

    impl Drop for PumpDeadlineSupervisor {
        fn drop(&mut self) {
            // Dropping the sender releases recv/recv_timeout even during panic.
            // The blocking task is deliberately not aborted; it exits itself.
            let _ = self.requests.take();
        }
    }

    /// Runs the real managed client handshake, authentication, and exec on an
    /// already-connected socket and returns the duplex.
    ///
    /// The caller connects and accepts the peer first, so this never dials and
    /// never leaves a peer thread blocked in `accept`.
    fn manual_duplex(
        socket: std::net::TcpStream,
        options: &ManagedSshOptions,
        bound: Duration,
    ) -> super::SessionDuplex<super::Socket<std::net::TcpStream>> {
        let guard_socket = socket.try_clone().unwrap();
        let ssh_control = socket.try_clone().unwrap();
        let control =
            crate::ssh_cancellation::EstablishmentControl::new(std::time::Instant::now() + bound);
        let crate::ssh_connect::Dialed { guard, .. } =
            crate::ssh_connect::Dialed::test_connected(guard_socket, control).unwrap();

        let would_block = WouldBlock::default();
        let read_slot = Arc::new(std::sync::OnceLock::new());
        let write_slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = Arc::new(AtomicU64::new(0));
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: socket,
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&read_slot),
                    write_readiness: Arc::clone(&write_slot),
                    write_progress: Arc::clone(&write_progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, options, would_block).unwrap();

        ssh_control.set_nonblocking(true).unwrap();
        let readiness = Arc::new(tokio::net::TcpStream::from_std(ssh_control).unwrap());
        read_slot.set(Arc::clone(&readiness)).unwrap();
        write_slot.set(Arc::clone(&readiness)).unwrap();
        gated_duplex(
            parts,
            guard,
            Arc::clone(&readiness),
            Arc::clone(&readiness),
            write_progress,
            super::WRITE_STALL_BOUND,
        )
    }

    /// A client transport whose writes are gated by a real nonblocking kernel
    /// write on a separate loopback probe socket.
    ///
    /// The probe is the only socket under pressure in this fixture. When the
    /// probe cannot take a full chunk (either `WouldBlock` or a partial write),
    /// the transport reports `WouldBlock` to the driver and does not touch the
    /// SSH socket. When the probe has room, the protected write is forwarded to
    /// the SSH socket unchanged. A real `WouldBlock` from the SSH socket would
    /// mean the fixture measured the wrong socket, so it is recorded and
    /// surfaced as a distinct error.
    struct ProbeWriteSocket {
        ssh: std::net::TcpStream,
        probe: std::net::TcpStream,
        probe_chunk: Vec<u8>,
        armed: Arc<std::sync::atomic::AtomicBool>,
        probe_blocked: Arc<std::sync::atomic::AtomicUsize>,
        ssh_would_block: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl std::io::Read for ProbeWriteSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.ssh.read(bytes)
        }
    }

    impl ProbeWriteSocket {
        /// Writes the protected bytes to the SSH socket, turning real SSH
        /// pressure into a distinct terminal error so the fixture cannot pass
        /// while measuring the wrong socket.
        fn write_ssh(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match std::io::Write::write(&mut self.ssh, bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.ssh_would_block.fetch_add(1, Ordering::SeqCst);
                    // Do not let the pump treat SSH pressure as a retryable
                    // write block. The fixture is invalid; fail the session.
                    Err(std::io::Error::other(
                        "test transport: unexpected SSH write WouldBlock",
                    ))
                }
                other => other,
            }
        }
    }

    impl std::io::Write for ProbeWriteSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            // Establishment writes go straight to the SSH socket: the probe
            // is armed only after setup, so the fixed, small probe buffers
            // hold the post-setup pressure the test measures and not the
            // handshake traffic.
            if !self.armed.load(Ordering::SeqCst) {
                return self.write_ssh(bytes);
            }
            // Probe the separate readiness socket with a real nonblocking
            // kernel write. This is the only write pressure this fixture
            // claims; the SSH socket is expected to stay writable. A partial
            // write means the probe cannot take a full chunk, which is the
            // same pressure as `WouldBlock`.
            let chunk_len = self.probe_chunk.len();
            let probe_result = self.probe.write(&self.probe_chunk);
            match probe_result {
                Ok(count) if count == chunk_len => {}
                Ok(_) => {
                    self.probe_blocked.fetch_add(1, Ordering::SeqCst);
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.probe_blocked.fetch_add(1, Ordering::SeqCst);
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
            self.write_ssh(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.ssh.flush()
        }
    }

    /// A client transport that forces the next admitted packet to be written
    /// only partly, then blocks on a separate kernel probe socket.
    ///
    /// The SSH socket is not the socket under pressure. The probe is its own
    /// loopback pair; when the probe is full the transport reports
    /// `WouldBlock` and the pump waits on the probe's writability through the
    /// production `Socket::try_io` adapter. A real `WouldBlock` from the SSH
    /// socket would mean the fixture measured the wrong socket, so it is
    /// recorded and surfaced as a distinct terminal error.
    ///
    /// The partial write is armed by the test after establishment. The first
    /// write after arming writes a strict prefix of the protected packet to
    /// the SSH socket, fills the probe to a real kernel `WouldBlock`, and
    /// signals the test. The rest of the packet stays owned by the driver
    /// until the test drains the probe.
    struct PartialProbeSocket {
        ssh: std::net::TcpStream,
        probe: std::net::TcpStream,
        probe_chunk: Vec<u8>,
        state: Arc<PartialWriteState>,
    }

    #[derive(Default)]
    struct PartialWriteState {
        armed: AtomicBool,
        partial_after: std::sync::Mutex<Option<usize>>,
        partial_written: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        partial_bytes: AtomicUsize,
        probe_blocked: AtomicUsize,
        probe_filled: AtomicUsize,
        ssh_would_block: AtomicUsize,
    }

    impl PartialProbeSocket {
        fn write_ssh(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match std::io::Write::write(&mut self.ssh, bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.state.ssh_would_block.fetch_add(1, Ordering::SeqCst);
                    // Do not let the pump treat SSH pressure as a retryable
                    // write block. The fixture is invalid; fail the session.
                    Err(std::io::Error::other(
                        "test transport: unexpected SSH write WouldBlock",
                    ))
                }
                other => other,
            }
        }
    }

    impl std::io::Read for PartialProbeSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.ssh.read(bytes)
        }
    }

    impl std::io::Write for PartialProbeSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.state.armed.load(Ordering::SeqCst) {
                return self.write_ssh(bytes);
            }
            // The probe is the only socket under pressure. A partial probe
            // write is the same pressure as `WouldBlock`: it cannot take a
            // whole chunk.
            let chunk_len = self.probe_chunk.len();
            match self.probe.write(&self.probe_chunk) {
                Ok(count) if count == chunk_len => {}
                Ok(_) => {
                    self.state.probe_blocked.fetch_add(1, Ordering::SeqCst);
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.state.probe_blocked.fetch_add(1, Ordering::SeqCst);
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
            let limit = self.state.partial_after.lock().unwrap().take();
            if let Some(limit) = limit {
                let count = limit.min(bytes.len());
                if count == 0 || count == bytes.len() {
                    return Err(std::io::Error::other(
                        "test transport: the partial write did not split the packet",
                    ));
                }
                let written = self.write_ssh(&bytes[..count])?;
                let filled = fill_kernel_probe(&mut self.probe, &self.probe_chunk)?;
                self.state.probe_filled.store(filled, Ordering::SeqCst);
                self.state.partial_bytes.store(written, Ordering::SeqCst);
                if let Some(sender) = self.state.partial_written.lock().unwrap().take() {
                    let _ = sender.send(());
                }
                return Ok(written);
            }
            // The probe has room again, so the pump observed real readiness.
            // From here the packet finishes without another artificial limit.
            self.state.armed.store(false, Ordering::SeqCst);
            self.write_ssh(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.ssh.flush()
        }
    }

    /// Fills `probe` until a full chunk write returns a real kernel
    /// `WouldBlock`, and returns the number of bytes written.
    fn fill_kernel_probe(probe: &mut std::net::TcpStream, chunk: &[u8]) -> std::io::Result<usize> {
        const LIMIT: usize = 16 * 1024 * 1024;
        let mut filled = 0_usize;
        while filled < LIMIT {
            match std::io::Write::write(probe, chunk) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(filled);
                }
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::other(
            "test transport: the probe did not reach a kernel WouldBlock",
        ))
    }

    /// Releases the fixture peer without joining it.
    ///
    /// Detaching is nonblocking: it closes the client clone and drops the
    /// handle. That does **not** prove the peer thread has terminated. The
    /// peer is expected to exit after the client close or its own bounded
    /// read/write timeouts, but this cleanup does not wait for, observe, or
    /// assert that termination. The alternative, `join`, can block forever if
    /// the peer is stuck in an I/O call, so the test accepts a detached thread
    /// bounded by the socket close and the peer's timeouts instead.
    struct PeerCleanup {
        server: Option<std::thread::JoinHandle<()>>,
        /// A duplicate of the client socket, used only to unblock the peer's
        /// read on an unwind. Dropping it is not enough: the transport still
        /// owns the file description, so the shutdown has to be explicit.
        client: Option<std::net::TcpStream>,
    }

    impl PeerCleanup {
        /// Closes the client clone so the peer observes a clean transport
        /// closure now, rather than waiting for its own read timeout. The
        /// transport's cancellation shutdown is opportunistic and can be
        /// skipped under lock contention, so the test does not rely on it.
        fn close_client(&mut self) {
            if let Some(client) = self.client.take() {
                let _ = client.shutdown(std::net::Shutdown::Both);
            }
        }

        /// Closes the client and drops the thread handle. The peer's socket
        /// close and bounded timeouts end the thread; the test never waits on
        /// `join`.
        fn detach(&mut self) {
            self.close_client();
            let _ = self.server.take();
        }
    }

    impl Drop for PeerCleanup {
        fn drop(&mut self) {
            self.detach();
        }
    }

    /// One raw result from the peer socket's `read`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ReadOutcome {
        /// The socket returned application bytes.
        Bytes(usize),
        /// The socket returned `Ok(0)`: the transport observed a real EOF.
        Eof,
        /// The socket returned a retryable timeout.
        Timeout,
        /// The socket returned any other I/O error.
        Error(String),
    }

    /// The transport failure the channel layer flattens into
    /// [`ChannelError::Transport`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TransportFailure {
        Timeout,
        Truncated,
        Wire,
        PacketProtection,
        Other(String),
    }

    fn transport_failure(error: &ServerTransportError) -> TransportFailure {
        match error {
            ServerTransportError::Transport(TransportError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                TransportFailure::Timeout
            }
            ServerTransportError::Transport(TransportError::Truncated) => {
                TransportFailure::Truncated
            }
            ServerTransportError::Transport(TransportError::Wire(_)) => TransportFailure::Wire,
            ServerTransportError::Transport(TransportError::PacketProtection(_)) => {
                TransportFailure::PacketProtection
            }
            other => TransportFailure::Other(format!("{other:?}")),
        }
    }

    /// What the instrumented peer socket observed, independent of the channel
    /// layer's error mapping.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    struct TransportObservation {
        outcomes: Vec<ReadOutcome>,
        /// Bytes read since the last protected-packet boundary.
        partial_bytes: usize,
        /// The transport error the channel layer erased into `Transport`.
        failure: Option<TransportFailure>,
        /// Protected packets the failing `read_payload` consumed before it
        /// returned, counted monotonically across strict-rekey resets.
        /// `Some(0)` is a provable boundary; `Some(n)` means internal traffic
        /// (`PING`, `EXT_INFO`, rekey) shared the call; `None` means the
        /// counter overflowed and the boundary is not provable.
        terminal_packets_consumed: Option<u64>,
        /// Protected packets consumed internally before a returned channel
        /// packet. `None` means the counter overflowed. Diagnostic and
        /// fail-closed evidence.
        internal_packets: Option<u64>,
        /// Number of strict-rekey inbound sequence resets seen in the channel
        /// phase. Diagnostic and fail-closed evidence.
        sequence_resets: u64,
        /// The failing call saw the inbound sequence move backwards, which is
        /// a strict-rekey reset.
        terminal_sequence_reset: bool,
    }

    impl TransportObservation {
        fn observed_eof(&self) -> bool {
            matches!(self.outcomes.last(), Some(ReadOutcome::Eof))
        }

        fn observed_timeout(&self) -> bool {
            matches!(self.outcomes.last(), Some(ReadOutcome::Timeout))
        }

        /// A clean transport end: a real `Ok(0)` at a protected-packet
        /// boundary with exactly zero packets consumed in the failing call and
        /// no rekey reset.
        fn clean_eof(&self) -> bool {
            self.observed_eof()
                && self.partial_bytes == 0
                && self.terminal_packets_consumed == Some(0)
                && !self.terminal_sequence_reset
        }

        /// The failing call consumed internal traffic, overflowed its counter,
        /// or reset its sequence before the EOF, so a boundary cannot be
        /// proven.
        fn ambiguous_boundary(&self) -> bool {
            self.observed_eof()
                && (self.terminal_packets_consumed != Some(0) || self.terminal_sequence_reset)
        }

        /// The peer closed in the middle of a packet, with exactly zero
        /// packets consumed in the failing call and no rekey reset.
        fn truncated(&self) -> bool {
            self.observed_eof()
                && self.partial_bytes > 0
                && self.terminal_packets_consumed == Some(0)
                && !self.terminal_sequence_reset
        }
    }

    /// Records every raw read outcome, the transport error the channel layer
    /// would otherwise erase, and the monotonic protected-packet count from
    /// `protected_packets_read`.
    struct ReadObserver {
        outcomes: std::sync::Mutex<Vec<ReadOutcome>>,
        partial_bytes: AtomicUsize,
        failure: std::sync::Mutex<Option<TransportFailure>>,
        /// `Some(count)` while the packet counter is accurate; `None` after it
        /// overflows. `None` must fail the fixture closed.
        terminal_packets_consumed: std::sync::Mutex<Option<u64>>,
        internal_packets: std::sync::Mutex<Option<u64>>,
        sequence_resets: AtomicU64,
        terminal_sequence_reset: AtomicBool,
    }

    impl Default for ReadObserver {
        fn default() -> Self {
            Self {
                outcomes: std::sync::Mutex::default(),
                partial_bytes: AtomicUsize::new(0),
                failure: std::sync::Mutex::default(),
                terminal_packets_consumed: std::sync::Mutex::new(None),
                internal_packets: std::sync::Mutex::new(Some(0)),
                sequence_resets: AtomicU64::new(0),
                terminal_sequence_reset: AtomicBool::new(false),
            }
        }
    }

    impl ReadObserver {
        fn record(&self, outcome: ReadOutcome) {
            if let ReadOutcome::Bytes(count) = &outcome {
                self.partial_bytes.fetch_add(*count, Ordering::SeqCst);
            }
            self.outcomes.lock().unwrap().push(outcome);
        }

        fn note_packet(&self, consumed: Option<u64>, sequence_reset: bool) {
            self.partial_bytes.store(0, Ordering::SeqCst);
            let mut internal = self.internal_packets.lock().unwrap();
            *internal = match (*internal, consumed) {
                (Some(total), Some(count)) => total.checked_add(count.saturating_sub(1)),
                _ => None,
            };
            drop(internal);
            if sequence_reset {
                self.sequence_resets.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn note_failure(
            &self,
            failure: TransportFailure,
            consumed: Option<u64>,
            sequence_reset: bool,
        ) {
            *self.failure.lock().unwrap() = Some(failure);
            *self.terminal_packets_consumed.lock().unwrap() = consumed;
            self.terminal_sequence_reset
                .store(sequence_reset, Ordering::SeqCst);
            if sequence_reset {
                self.sequence_resets.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn snapshot(&self) -> TransportObservation {
            TransportObservation {
                outcomes: self.outcomes.lock().unwrap().clone(),
                partial_bytes: self.partial_bytes.load(Ordering::SeqCst),
                failure: self.failure.lock().unwrap().clone(),
                terminal_packets_consumed: *self.terminal_packets_consumed.lock().unwrap(),
                internal_packets: *self.internal_packets.lock().unwrap(),
                sequence_resets: self.sequence_resets.load(Ordering::SeqCst),
                terminal_sequence_reset: self.terminal_sequence_reset.load(Ordering::SeqCst),
            }
        }
    }

    /// The peer socket, instrumented so the test can see a real `Ok(0)` and
    /// distinguish it from a timeout or an I/O error.
    struct ObservedSocket {
        socket: std::net::TcpStream,
        observer: Arc<ReadObserver>,
    }

    impl std::io::Read for ObservedSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let result = std::io::Read::read(&mut self.socket, bytes);
            let outcome = match &result {
                Ok(0) => ReadOutcome::Eof,
                Ok(count) => ReadOutcome::Bytes(*count),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    ReadOutcome::Timeout
                }
                Err(error) => ReadOutcome::Error(format!("{:?}", error.kind())),
            };
            self.observer.record(outcome);
            result
        }
    }

    impl std::io::Write for ObservedSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut self.socket, bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut self.socket)
        }
    }

    /// Keeps the transport error that [`ChannelError::Transport`] discards and
    /// counts protected packets monotonically. The inbound sequence resets at
    /// a strict-rekey NEWKEYS, so it is used only to detect that reset, never
    /// as the packet delta.
    struct ObservedChannelTransport {
        inner: neotales_ssh::server::ServerTransport<ObservedSocket>,
        observer: Arc<ReadObserver>,
    }

    impl neotales_ssh::channel::ChannelTransport for ObservedChannelTransport {
        fn write_channel_payload(&mut self, payload: &[u8]) -> Result<(), ()> {
            self.inner.write_payload(payload).map_err(|_error| ())
        }

        fn read_channel_payload(&mut self) -> Result<Vec<u8>, ()> {
            let packets_before = self.inner.protected_packets_read();
            let sequence_before = self.inner.inbound_sequence();
            let result = self.inner.read_payload();
            let packets_after = self.inner.protected_packets_read();
            let sequence_after = self.inner.inbound_sequence();
            // `None` means the counter overflowed, or it moved backwards
            // unexpectedly. Either way the delta is not provable and must fail
            // the fixture closed rather than be guessed.
            let consumed = match (packets_before, packets_after) {
                (Some(before), Some(after)) if after >= before => Some(after - before),
                _ => None,
            };
            // A strict-rekey NEWKEYS resets the wire sequence. The monotonic
            // packet count still sees the rekey packets; the reset is retained
            // as fail-closed evidence.
            let sequence_reset = sequence_after < sequence_before;
            match result {
                Ok(payload) => {
                    self.observer.note_packet(consumed, sequence_reset);
                    Ok(payload)
                }
                Err(error) => {
                    self.observer
                        .note_failure(transport_failure(&error), consumed, sequence_reset);
                    Err(())
                }
            }
        }
    }

    /// A peer whose socket and transport errors are observable by the test.
    ///
    /// The caller connects first and accepts the peer synchronously, then
    /// passes the accepted socket here. `accept` never runs on the peer
    /// thread, so a failed client setup cannot leave a thread blocked forever
    /// in `accept`. The socket carries a generous handshake timeout; a test
    /// that needs an intentional post-EOF timeout sets it on its own clone
    /// after the EOF.
    fn observed_peer<F>(
        signer: neotales_ssh::hostkey::Ed25519Signer,
        peer: std::net::TcpStream,
        handshake_timeout: Duration,
        observer: Arc<ReadObserver>,
        script: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: FnOnce(&mut neotales_ssh::channel::ChannelConnection<ObservedChannelTransport>)
            + Send
            + 'static,
    {
        peer.set_read_timeout(Some(handshake_timeout)).unwrap();
        peer.set_write_timeout(Some(handshake_timeout)).unwrap();
        std::thread::spawn(move || {
            let socket = ObservedSocket {
                socket: peer,
                observer: Arc::clone(&observer),
            };
            let mut transport = neotales_ssh::server::ServerConfig::new(signer)
                .connect(socket)
                .unwrap();
            let policy = neotales_ssh::auth::ServerAuthPolicy::new(2)
                .unwrap()
                .with_password_callback(|_| true);
            neotales_ssh::auth::authenticate_server(&mut transport, &policy).unwrap();
            let mut connection =
                neotales_ssh::channel::ChannelConnection::new(ObservedChannelTransport {
                    inner: transport,
                    observer,
                });
            script(&mut connection);
        })
    }

    /// One application-visible event the peer observed while the client shut
    /// down.
    ///
    /// `WindowAdjusted` is flow-control noise and `Close` is a clean end
    /// marker, so neither is a transcript entry. The transcript is only what
    /// the test asserts must happen exactly once.
    #[derive(Debug, PartialEq, Eq)]
    enum ShutdownEvent {
        Data(Vec<u8>),
        Eof,
    }

    /// A clean way the peer's read loop may end.
    #[derive(Debug, PartialEq, Eq)]
    enum CleanEnd {
        /// The client sent an authenticated `SSH_MSG_CHANNEL_CLOSE`.
        ChannelClosed,
        /// The peer's instrumented socket observed a real `Ok(0)` at a packet
        /// boundary.
        TransportEof,
    }

    /// The outcome of classifying one inbound event after the client's EOF.
    #[derive(Debug, PartialEq, Eq)]
    enum AfterEof {
        Event(ShutdownEvent),
        Ignored,
        Clean(CleanEnd),
        ProtocolViolation(String),
    }

    /// Classifies one inbound event the peer reads after the client's EOF.
    ///
    /// A duplicate EOF is surfaced by the channel layer as
    /// [`ChannelError::InvalidMessage`] and data after EOF as
    /// [`ChannelError::DataAfterEof`]; both fail. A
    /// [`ChannelError::Transport`] is not clean by itself: the instrumented
    /// socket must have observed a real `Ok(0)` at a packet boundary. A
    /// timeout, a truncated packet, or any other transport failure is a
    /// violation even though the channel layer reports all of them as
    /// `Transport`.
    fn classify_after_eof(
        session: u32,
        event: Result<super::ChannelEvent, super::ChannelError>,
        observation: &TransportObservation,
    ) -> AfterEof {
        match event {
            Ok(super::ChannelEvent::Data { channel, data }) if channel == session => {
                AfterEof::Event(ShutdownEvent::Data(data))
            }
            Ok(super::ChannelEvent::Eof { channel }) if channel == session => {
                AfterEof::Event(ShutdownEvent::Eof)
            }
            Ok(super::ChannelEvent::Close { channel }) if channel == session => {
                AfterEof::Clean(CleanEnd::ChannelClosed)
            }
            Ok(super::ChannelEvent::WindowAdjusted { .. }) => AfterEof::Ignored,
            Ok(other) => AfterEof::ProtocolViolation(format!(
                "the client sent an unexpected event after its EOF: {other:?}"
            )),
            Err(super::ChannelError::Transport) => {
                if observation.observed_timeout() {
                    AfterEof::ProtocolViolation(format!(
                        "the peer's read timed out instead of observing a clean EOF: \
                         {observation:?}"
                    ))
                } else if observation.clean_eof() {
                    AfterEof::Clean(CleanEnd::TransportEof)
                } else if observation.ambiguous_boundary() {
                    AfterEof::ProtocolViolation(format!(
                        "inconclusive: the peer consumed {:?} internal transport packet(s) \
                         (strict-rekey reset: {}) before the EOF, so the packet boundary is \
                         not provable: {observation:?}",
                        observation.terminal_packets_consumed, observation.terminal_sequence_reset
                    ))
                } else if observation.truncated() {
                    AfterEof::ProtocolViolation(format!(
                        "the peer closed in the middle of an SSH packet: {observation:?}"
                    ))
                } else {
                    AfterEof::ProtocolViolation(format!(
                        "the transport ended without an observed clean EOF: {observation:?}"
                    ))
                }
            }
            Err(error) => AfterEof::ProtocolViolation(format!(
                "the client violated the SSH channel protocol after its EOF: {error:?}"
            )),
        }
    }

    /// Drives one observed peer through the shutdown transcript.
    ///
    /// The peer reads until the client's EOF, optionally answers with `reply`,
    /// then drains until a clean end. `post_eof_timeout` replaces the
    /// handshake read budget with an intentional timeout only after the EOF,
    /// so a slow handshake under parallel load cannot trip it. Any protocol
    /// violation, timeout, or truncated packet is returned as an error.
    fn record_shutdown(
        connection: &mut neotales_ssh::channel::ChannelConnection<ObservedChannelTransport>,
        observer: &ReadObserver,
        reply: Option<&[u8]>,
        post_eof_timeout: Option<(&std::net::TcpStream, Duration)>,
    ) -> Result<(Vec<ShutdownEvent>, CleanEnd), String> {
        let session = confirm_peer_session(connection);
        accept_exec(connection, session);
        let mut transcript = Vec::new();
        loop {
            match connection
                .dispatch_one()
                .map_err(|error| format!("before the client's EOF: {error:?}"))?
            {
                super::ChannelEvent::Data { data, .. } => {
                    transcript.push(ShutdownEvent::Data(data));
                }
                super::ChannelEvent::Eof { channel } if channel == session => {
                    transcript.push(ShutdownEvent::Eof);
                    break;
                }
                super::ChannelEvent::WindowAdjusted { .. } => {}
                other => {
                    return Err(format!("unexpected before the client's EOF: {other:?}"));
                }
            }
        }
        if let Some(reply) = reply {
            connection
                .write_data(session, reply)
                .map_err(|error| format!("writing the reply: {error:?}"))?;
        }
        if let Some((control, timeout)) = post_eof_timeout {
            control
                .set_read_timeout(Some(timeout))
                .map_err(|error| format!("setting the post-EOF read timeout: {error}"))?;
        }
        // Fail closed if the client sends PING, EXT_INFO, or rekey traffic
        // during the drain: that would make the packet-boundary counter
        // ambiguous. The production client has no keepalive timer and the test
        // never triggers a rekey, so any delta here is a fixture violation.
        let before_drain = observer.snapshot();
        let end = loop {
            let event = connection.dispatch_one();
            let observation = observer.snapshot();
            match classify_after_eof(session, event, &observation) {
                AfterEof::Event(event) => transcript.push(event),
                AfterEof::Ignored => {}
                AfterEof::Clean(end) => break end,
                AfterEof::ProtocolViolation(message) => return Err(message),
            }
        };
        let final_observation = observer.snapshot();
        if final_observation.internal_packets.is_none()
            || final_observation.internal_packets != before_drain.internal_packets
            || final_observation.sequence_resets != before_drain.sequence_resets
        {
            return Err(format!(
                "inconclusive: the peer's internal packet count is {:?} (was {:?}; None means \
                 overflow) and it saw {} strict-rekey reset(s) during the post-EOF drain, so the \
                 packet boundary is not provable: {final_observation:?}",
                final_observation.internal_packets,
                before_drain.internal_packets,
                final_observation.sequence_resets - before_drain.sequence_resets
            ));
        }
        Ok((transcript, end))
    }

    /// Always opens the atomic gate and joins the bounded fixture threads,
    /// including when setup or an assertion unwinds.
    struct PumpReproCleanup {
        allowance: Arc<std::sync::atomic::AtomicUsize>,
        send: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Sender<()>,
        notify: Option<Arc<tokio::sync::Notify>>,
        peer: Option<std::thread::JoinHandle<Result<(), String>>>,
        watchdog_cancel: Option<std::sync::mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl PumpReproCleanup {
        fn release(&mut self) {
            self.allowance.store(usize::MAX, Ordering::SeqCst);
            if let Some(notify) = &self.notify {
                notify.notify_one();
            }
            let _ = self.send.send(());
            let _ = self.release.send(());
            if let Some(cancel) = self.watchdog_cancel.take() {
                let _ = cancel.send(());
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    impl Drop for PumpReproCleanup {
        fn drop(&mut self) {
            self.release();
            if let Some(peer) = self.peer.take() {
                let _ = peer.join();
            }
        }
    }

    #[test]
    fn pump_repro_cleanup_releases_and_joins_peer_during_unwind() {
        use std::sync::{atomic::AtomicUsize, mpsc};
        let allowance = Arc::new(AtomicUsize::new(0));
        let (send, send_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (joined, joined_rx) = mpsc::channel();
        let peer_allowance = Arc::clone(&allowance);
        let peer = std::thread::spawn(move || -> Result<(), String> {
            send_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|e| e.to_string())?;
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|e| e.to_string())?;
            if peer_allowance.load(Ordering::SeqCst) != usize::MAX {
                return Err("cleanup did not open the gate".into());
            }
            joined.send(()).map_err(|e| e.to_string())
        });
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _cleanup = PumpReproCleanup {
                allowance,
                send,
                release,
                notify: None,
                peer: Some(peer),
                watchdog_cancel: None,
                watchdog: None,
            };
            panic!("synthetic early assertion");
        }));
        assert!(outcome.is_err());
        joined_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    /// Releases the probe and peer on every exit path without joining on the
    /// async runtime.
    ///
    /// The normal path awaits the peer's transcript (its completion signal)
    /// before joining it on the blocking pool. A test that unwinds detaches
    /// the bounded peer after releasing it, so no blocking join runs on the
    /// runtime thread.
    struct ProbeReproCleanup {
        send: Option<std::sync::mpsc::Sender<()>>,
        start: Option<std::sync::mpsc::Sender<()>>,
        release: Option<std::sync::mpsc::Sender<()>>,
        finish: Option<std::sync::mpsc::Sender<()>>,
        barrier: Option<std::sync::mpsc::Sender<()>>,
        probe_peer: Option<tokio::net::TcpStream>,
        peer: Option<std::thread::JoinHandle<Result<(), String>>>,
    }

    struct CountWake(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ProbeReproCleanup {
        fn release(&mut self) {
            if let Some(start) = self.start.take() {
                let _ = start.send(());
            }
            if let Some(send) = self.send.take() {
                let _ = send.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            // Closing the probe peer releases a blocked probe write. The
            // duplex is declared after this guard, so it is aborted first on
            // unwind.
            drop(self.probe_peer.take());
        }

        fn finish(&mut self) {
            if let Some(barrier) = self.barrier.take() {
                let _ = barrier.send(());
            }
            if let Some(finish) = self.finish.take() {
                let _ = finish.send(());
            }
        }
    }

    impl Drop for ProbeReproCleanup {
        fn drop(&mut self) {
            self.release();
            self.finish();
            // Drop runs on the async runtime thread. Never join there: the
            // peer has been released and is bounded by its socket timeouts.
            drop(self.peer.take());
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum ProbeOutcome {
        Complete,
        Drop,
        Fatal,
        GlobalComplete,
        GlobalDrop,
        GlobalFatal,
        ChannelComplete,
        ChannelDrop,
        ChannelFatal,
        OpenComplete,
        OpenDrop,
        OpenFatal,
        CloseComplete,
        CloseDrop,
        CloseFatal,
        CloseForeignData,
        CloseForeignClose,
        CloseDuplicate,
        PongPing,
        PongGlobal,
        PongClose,
        PongDrop,
        PongFatal,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_data() {
        probe_read_behind(true, ProbeOutcome::Complete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_pump_with_blocked_data_and_queued_reply() {
        probe_read_behind(true, ProbeOutcome::Drop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_peer_data_while_window_credit_write_is_blocked() {
        probe_read_behind(false, ProbeOutcome::Complete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_close_reports_accepted_untransmitted_data() {
        probe_read_behind(true, ProbeOutcome::Complete, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_eof_and_replies() {
        probe_read_behind(false, ProbeOutcome::Complete, false, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_eof_and_answers_close() {
        probe_read_behind(false, ProbeOutcome::Complete, true, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_pump_with_blocked_eof_and_queued_reply() {
        probe_read_behind(false, ProbeOutcome::Drop, false, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_eof_write_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::Fatal, false, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_global_reply() {
        probe_read_behind(false, ProbeOutcome::GlobalComplete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_close_behind_blocked_global_reply() {
        probe_read_behind(false, ProbeOutcome::GlobalComplete, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_blocked_global_reply() {
        probe_read_behind(false, ProbeOutcome::GlobalDrop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_global_reply_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::GlobalFatal, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_channel_reply() {
        probe_read_behind(false, ProbeOutcome::ChannelComplete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_close_behind_blocked_channel_reply() {
        probe_read_behind(false, ProbeOutcome::ChannelComplete, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_blocked_channel_reply() {
        probe_read_behind(false, ProbeOutcome::ChannelDrop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_channel_reply_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::ChannelFatal, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_open_rejection() {
        probe_read_behind(false, ProbeOutcome::OpenComplete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_close_behind_blocked_open_rejection() {
        probe_read_behind(false, ProbeOutcome::OpenComplete, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_blocked_open_rejection() {
        probe_read_behind(false, ProbeOutcome::OpenDrop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_open_rejection_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::OpenFatal, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_behind_blocked_close_reply() {
        probe_read_behind(false, ProbeOutcome::CloseComplete, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_blocked_close_reply() {
        probe_read_behind(false, ProbeOutcome::CloseDrop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_close_reply_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::CloseFatal, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_data_behind_blocked_close_fails_closed() {
        probe_read_behind(false, ProbeOutcome::CloseForeignData, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_close_behind_blocked_close_fails_closed() {
        probe_read_behind(false, ProbeOutcome::CloseForeignClose, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_close_behind_blocked_close_fails_closed() {
        probe_read_behind(false, ProbeOutcome::CloseDuplicate, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_ping_behind_blocked_pong() {
        probe_read_behind(false, ProbeOutcome::PongPing, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_global_behind_blocked_pong() {
        probe_read_behind(false, ProbeOutcome::PongGlobal, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pump_reads_close_behind_blocked_pong() {
        probe_read_behind(false, ProbeOutcome::PongClose, true, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_cancels_blocked_pong() {
        probe_read_behind(false, ProbeOutcome::PongDrop, false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_pong_failure_is_terminal() {
        probe_read_behind(false, ProbeOutcome::PongFatal, false, false).await;
    }

    /// Drives the real pump with protected SSH and pressure on a separate
    /// kernel probe, not on the SSH socket. It observes the actual active
    /// packet and reply slot before releasing the probe, and bounds the
    /// transcript with EOF or a close handshake.
    #[allow(clippy::too_many_lines)] // One controlled peer covers pressure, state, reads, and transcript order.
    async fn probe_read_behind(
        data_packet: bool,
        outcome: ProbeOutcome,
        peer_close: bool,
        eof_packet: bool,
    ) {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::atomic::{AtomicU32, AtomicUsize};
        use std::sync::mpsc;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const BOUND: Duration = Duration::from_secs(5);
        const FILL_CHUNK: usize = 64 * 1024;
        const FILL_LIMIT: usize = 16 * 1024 * 1024;
        /// The fixed probe send/receive buffer, in bytes.
        ///
        /// Small and locked so TCP cannot autotune the probe out of the
        /// pressure state the fill establishes. It is large enough to absorb
        /// the several 64 KiB probe chunks the pump writes after the test
        /// drains the probe, so those writes are not re-blocked by the
        /// fixture itself.
        const PROBE_BUFFER: u32 = 1024 * 1024;

        let global_packet = matches!(
            outcome,
            ProbeOutcome::GlobalComplete | ProbeOutcome::GlobalDrop | ProbeOutcome::GlobalFatal
        );
        let channel_packet = matches!(
            outcome,
            ProbeOutcome::ChannelComplete | ProbeOutcome::ChannelDrop | ProbeOutcome::ChannelFatal
        );
        let open_packet = matches!(
            outcome,
            ProbeOutcome::OpenComplete | ProbeOutcome::OpenDrop | ProbeOutcome::OpenFatal
        );
        let close_packet = matches!(
            outcome,
            ProbeOutcome::CloseComplete
                | ProbeOutcome::CloseDrop
                | ProbeOutcome::CloseFatal
                | ProbeOutcome::CloseForeignData
                | ProbeOutcome::CloseForeignClose
                | ProbeOutcome::CloseDuplicate
        );
        let pong_packet = matches!(
            outcome,
            ProbeOutcome::PongPing
                | ProbeOutcome::PongGlobal
                | ProbeOutcome::PongClose
                | ProbeOutcome::PongDrop
                | ProbeOutcome::PongFatal
        );
        let nested_ping = outcome == ProbeOutcome::PongPing;
        let foreign_packet = matches!(
            outcome,
            ProbeOutcome::CloseForeignData
                | ProbeOutcome::CloseForeignClose
                | ProbeOutcome::CloseDuplicate
        );
        let reply_packet =
            global_packet || channel_packet || open_packet || close_packet || pong_packet;
        let filler_count = super::REPLY_CAPACITY - usize::from(reply_packet) - 1;
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [131; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);

        // The probe is a separate loopback pair. Its send buffer, not the SSH
        // socket's, is the write pressure this test measures.
        //
        // Lock both probe buffers small. TCP otherwise autotunes the send
        // buffer upward after the fill, and a grown receive buffer opens the
        // window, either of which frees room for the transport's chunk after
        // the fixture has proved the probe blocked. Setting `SO_SNDBUF` and
        // `SO_RCVBUF` also disables that autotuning, so a probe that refuses a
        // byte stays refusing it.
        let probe_listener = tokio::net::TcpSocket::new_v4().unwrap();
        probe_listener.set_recv_buffer_size(PROBE_BUFFER).unwrap();
        probe_listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let probe_listener = probe_listener.listen(1).unwrap();
        let probe_address = probe_listener.local_addr().unwrap();
        let probe_socket = tokio::net::TcpSocket::new_v4().unwrap();
        probe_socket.set_send_buffer_size(PROBE_BUFFER).unwrap();
        let probe_client = probe_socket.connect(probe_address).await.unwrap();
        let (probe_peer, _) = probe_listener.accept().await.unwrap();
        let probe_client = probe_client.into_std().unwrap();
        let mut probe_fill = probe_client.try_clone().unwrap();
        let probe_readiness =
            Arc::new(tokio::net::TcpStream::from_std(probe_client.try_clone().unwrap()).unwrap());

        // Connect before spawning so cleanup never detaches a thread waiting on
        // an accept for a connection that setup failed to create.
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(BOUND)).unwrap();
        socket.set_write_timeout(Some(BOUND)).unwrap();

        let (send_tx, send_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let (barrier_tx, barrier_rx) = mpsc::channel();
        let (transcript_tx, transcript_rx) = tokio::sync::oneshot::channel();
        let probe_blocked = Arc::new(AtomicUsize::new(0));
        let probe_armed = Arc::new(AtomicBool::new(false));
        let ssh_would_block = Arc::new(AtomicUsize::new(0));
        let session_id = Arc::new(AtomicU32::new(0));
        let initial_remote = Arc::new(AtomicU32::new(0));
        let mut cleanup = ProbeReproCleanup {
            send: Some(send_tx.clone()),
            start: Some(start_tx.clone()),
            release: Some(release_tx.clone()),
            finish: Some(finish_tx.clone()),
            barrier: Some(barrier_tx.clone()),
            probe_peer: Some(probe_peer),
            peer: None,
        };
        let peer_session = Arc::clone(&session_id);
        let peer_initial = Arc::clone(&initial_remote);
        cleanup.peer = Some(std::thread::spawn(move || -> Result<(), String> {
            let (socket, _) = listener.accept().map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(BOUND))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(BOUND))
                .map_err(|e| e.to_string())?;
            let mut transport = neotales_ssh::server::ServerConfig::new(signer)
                .connect(socket)
                .map_err(|e| e.to_string())?;
            let policy = neotales_ssh::auth::ServerAuthPolicy::new(2)
                .unwrap()
                .with_password_callback(|_| true);
            neotales_ssh::auth::authenticate_server(&mut transport, &policy)
                .map_err(|e| e.to_string())?;
            let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
            let session = if data_packet {
                match connection.dispatch_one().map_err(|e| e.to_string())? {
                    ChannelEvent::OpenRequest(request) => {
                        connection
                            .confirm_open_with_limits(
                                request.sender_channel(),
                                0,
                                super::INITIAL_CHANNEL_WINDOW,
                                64,
                            )
                            .map_err(|e| e.to_string())?;
                        0
                    }
                    other => return Err(format!("expected session open, got {other:?}")),
                }
            } else {
                confirm_peer_session(&mut connection)
            };
            accept_exec(&mut connection, session);
            let window = connection
                .channel(session)
                .ok_or_else(|| "peer session channel disappeared".to_owned())?
                .remote_window();
            peer_session.store(session, Ordering::SeqCst);
            peer_initial.store(window, Ordering::SeqCst);
            connection
                .write_data(session, b"A")
                .map_err(|e| e.to_string())?;
            if reply_packet {
                start_rx.recv_timeout(BOUND).map_err(|e| e.to_string())?;
                if pong_packet {
                    let ping = neotales_ssh::keepalive::TransportPing::Ping(b"first".to_vec())
                        .encode()
                        .map_err(|e| e.to_string())?;
                    connection
                        .transport_mut()
                        .write_payload(&ping)
                        .map_err(|e| e.to_string())?;
                } else if close_packet {
                    connection
                        .write_data(session, b"B")
                        .map_err(|e| e.to_string())?;
                    connection.send_eof(session).map_err(|e| e.to_string())?;
                    connection.send_close(session).map_err(|e| e.to_string())?;
                } else if open_packet {
                    connection
                        .open_channel(9, b"session", b"")
                        .map_err(|e| e.to_string())?;
                } else if channel_packet {
                    connection
                        .send_request(session, b"unsupported", true, b"")
                        .map_err(|e| e.to_string())?;
                } else {
                    connection
                        .transport_mut()
                        .write_payload(&global_request(true))
                        .map_err(|e| e.to_string())?;
                }
            }
            send_rx.recv_timeout(BOUND).map_err(|e| e.to_string())?;
            if !close_packet {
                connection
                    .write_data(session, b"B")
                    .map_err(|e| e.to_string())?;
                if eof_packet || channel_packet || open_packet || pong_packet {
                    connection.send_eof(session).map_err(|e| e.to_string())?;
                }
            }
            if foreign_packet {
                let mut packet = neotales_ssh::Writer::new();
                packet.write_byte(if outcome == ProbeOutcome::CloseForeignData {
                    94
                } else {
                    97
                });
                packet.write_uint32(if outcome == ProbeOutcome::CloseDuplicate {
                    0
                } else {
                    42
                });
                if outcome == ProbeOutcome::CloseForeignData {
                    packet.write_string(b"foreign").map_err(|e| e.to_string())?;
                }
                connection
                    .transport_mut()
                    .write_payload(&packet.into_bytes())
                    .map_err(|e| e.to_string())?;
            } else if peer_close {
                connection.send_close(session).map_err(|e| e.to_string())?;
            } else if nested_ping {
                let ping = neotales_ssh::keepalive::TransportPing::Ping(b"second".to_vec())
                    .encode()
                    .map_err(|e| e.to_string())?;
                connection
                    .transport_mut()
                    .write_payload(&ping)
                    .map_err(|e| e.to_string())?;
            } else {
                connection
                    .transport_mut()
                    .write_payload(&global_request(true))
                    .map_err(|e| e.to_string())?;
            }
            if !foreign_packet {
                for _ in 0..filler_count {
                    connection
                        .transport_mut()
                        .write_payload(&global_request(true))
                        .map_err(|e| e.to_string())?;
                }
            }
            if (eof_packet || reply_packet) && !foreign_packet {
                connection
                    .transport_mut()
                    .write_payload(&global_request(false))
                    .map_err(|e| e.to_string())?;
            }
            if data_packet && !peer_close {
                connection
                    .write_data(session, b"C")
                    .map_err(|e| e.to_string())?;
            }
            let _ = sent_tx.send(());
            release_rx.recv_timeout(BOUND).map_err(|e| e.to_string())?;
            // The client's EOF is the bounded protocol delimiter. Everything
            // before it must be the exact expected transcript; anything extra
            // would mean the test drained before the reply was queued or a
            // duplicate was sent.
            let mut transcript = Vec::new();
            if pong_packet {
                let expected: &[&[u8]] = if nested_ping {
                    &[b"first", b"second"]
                } else {
                    &[b"first"]
                };
                for data in expected {
                    let payload = connection
                        .transport_mut()
                        .read_payload()
                        .map_err(|e| e.to_string())?;
                    let pong = neotales_ssh::keepalive::TransportPing::decode(&payload)
                        .map_err(|e| e.to_string())?;
                    if pong != neotales_ssh::keepalive::TransportPing::Pong(data.to_vec()) {
                        return Err(format!("unexpected PONG: {pong:?}"));
                    }
                }
            }
            let original_globals = usize::from(global_packet)
                + usize::from(!peer_close && !nested_ping && !foreign_packet);
            let mut globals_seen = 0;
            let mut fillers_seen = 0;
            loop {
                let event = connection.dispatch_one();
                if matches!(event, Ok(ChannelEvent::GlobalRequestFailed { .. })) {
                    globals_seen += 1;
                    if globals_seen > original_globals {
                        fillers_seen += 1;
                        continue;
                    }
                }
                match event {
                    Ok(event @ ChannelEvent::Close { channel })
                        if close_packet && channel == session =>
                    {
                        transcript.push(event);
                    }
                    Ok(event @ ChannelEvent::GlobalRequestFailed { .. }) if close_packet => {
                        transcript.push(event);
                        break;
                    }
                    Ok(event @ ChannelEvent::Eof { channel })
                        if eof_packet && channel == session =>
                    {
                        transcript.push(event);
                    }
                    Ok(event @ ChannelEvent::GlobalRequestFailed { .. })
                        if eof_packet && !peer_close =>
                    {
                        transcript.push(event);
                        barrier_rx.recv_timeout(BOUND).map_err(|e| e.to_string())?;
                        connection.send_close(session).map_err(|e| e.to_string())?;
                    }
                    Ok(event @ ChannelEvent::Close { channel })
                        if (peer_close || eof_packet) && channel == session =>
                    {
                        transcript.push(event);
                        break;
                    }
                    Ok(ChannelEvent::Eof { channel }) if channel == session => break,
                    Ok(event) => transcript.push(event),
                    Err(error) => return Err(format!("peer dispatch failed: {error}")),
                }
            }
            for _ in fillers_seen..filler_count {
                let payload = connection
                    .transport_mut()
                    .read_payload()
                    .map_err(|e| e.to_string())?;
                if payload != [82] {
                    return Err(format!("expected FIFO filler failure, got {payload:?}"));
                }
            }
            transcript_tx
                .send(transcript)
                .map_err(|_| "peer transcript receiver dropped".to_owned())?;
            // Keep the connection alive until the test has observed the
            // client's shutdown completion and the transcript. Returning here
            // would reset the connection while the pump is still observing
            // the shutdown.
            finish_rx.recv_timeout(BOUND).map_err(|e| e.to_string())
        }));

        let guard_socket = socket.try_clone().unwrap();
        let ssh_control = socket.try_clone().unwrap();
        let fail_socket = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + BOUND);
        let Dialed { guard, .. } = Dialed::test_connected(guard_socket, control).unwrap();
        let would_block = WouldBlock::default();
        let read_slot = Arc::new(std::sync::OnceLock::new());
        let write_slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = new_write_progress();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: ProbeWriteSocket {
                        ssh: socket,
                        probe: probe_client,
                        probe_chunk: vec![0_u8; FILL_CHUNK],
                        armed: Arc::clone(&probe_armed),
                        probe_blocked: Arc::clone(&probe_blocked),
                        ssh_would_block: Arc::clone(&ssh_would_block),
                    },
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&read_slot),
                    write_readiness: Arc::clone(&write_slot),
                    write_progress: Arc::clone(&write_progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();
        probe_armed.store(true, Ordering::SeqCst);

        ssh_control.set_nonblocking(true).unwrap();
        let read_readiness = Arc::new(tokio::net::TcpStream::from_std(ssh_control).unwrap());
        read_slot.set(Arc::clone(&read_readiness)).unwrap();
        // Mark the probe writable before filling it. Tokio readiness is
        // edge-triggered, so the pump's first `try_io` reaches the transport's
        // real probe write and observes the `WouldBlock` it records.
        tokio::time::timeout(BOUND, probe_readiness.writable())
            .await
            .expect("inconclusive: probe never reported writable")
            .unwrap();
        write_slot.set(Arc::clone(&probe_readiness)).unwrap();

        // Fill the probe to a real kernel `WouldBlock`. The bound keeps a
        // wrong socket size from turning this into an unbounded loop.
        //
        // A single `WouldBlock` is not a stable pressure point. The sender's
        // queue can still drain into the peer's receive buffer, and TCP can
        // grow that receive buffer after the fill, opening the window again.
        // Both free room *after* the check, and the transport's next chunk
        // then succeeds instead of blocking. Each settle round therefore
        // waits, then probes with a single byte: any room at all means the
        // probe is not blocked, so the fill is topped up and the count
        // restarts. Ten consecutive one-byte failures across 20 ms waits give
        // the queue time to drain and the receive window time to settle, so a
        // probe that still refuses one byte refuses the transport's chunk.
        let mut filled = 0_usize;
        let fill_blocked;
        let chunk = vec![0_u8; FILL_CHUNK];
        {
            use std::io::Write as _;
            let one = [0_u8; 1];
            let mut blocked_checks = 0_u8;
            let mut rounds = 0_u16;
            while blocked_checks < 10 && rounds < 200 {
                rounds += 1;
                while filled < FILL_LIMIT {
                    match probe_fill.write(&chunk) {
                        Ok(0) => panic!("inconclusive: probe fill wrote zero bytes"),
                        Ok(count) => filled += count,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => panic!("inconclusive: probe fill failed: {error}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
                match probe_fill.write(&one) {
                    Ok(1) => {
                        filled += 1;
                        blocked_checks = 0;
                    }
                    Ok(count) => panic!("inconclusive: probe settle write returned {count}"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        blocked_checks += 1;
                    }
                    Err(error) => panic!("inconclusive: probe settle write failed: {error}"),
                }
            }
            fill_blocked = blocked_checks == 10;
        }
        assert!(
            fill_blocked && filled > 0,
            "inconclusive: probe did not reach a stable one-byte WouldBlock within {FILL_LIMIT} bytes"
        );
        drop(probe_fill);

        let mut probe_peer = cleanup.probe_peer.take().unwrap();
        let mut duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&read_readiness),
            Arc::clone(&probe_readiness),
            write_progress,
            super::WRITE_STALL_BOUND,
        );

        // In data mode, admit an application packet before consuming A, so
        // no window adjustment can precede the packet being tested.
        let mut first = [0_u8; 1];
        if reply_packet {
            start_tx.send(()).unwrap();
        } else if eof_packet {
            use std::future::Future as _;
            let mut shutdown = Box::pin(duplex.shutdown());
            let waker = futures_util::task::noop_waker();
            assert!(
                shutdown
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&waker))
                    .is_pending()
            );
        } else if data_packet {
            tokio::time::timeout(BOUND, duplex.write_all(&[b'R'; 128]))
                .await
                .expect("inconclusive: data admission timed out")
                .unwrap();
        } else {
            tokio::time::timeout(BOUND, duplex.read_exact(&mut first))
                .await
                .expect("inconclusive: first peer byte was not observed")
                .unwrap();
            assert_eq!(first, *b"A");
        }

        if close_packet || pong_packet {
            // The kernel may clear cached writability before `try_io` enters
            // the probe closure. The admitted reply and a still-full probe
            // prove the block without requiring that closure to have run.
            tokio::time::timeout(BOUND, async {
                while {
                    let state = duplex.shared.lock().unwrap();
                    if pong_packet {
                        !state.established.pong_writing()
                    } else {
                        !state.established.close_reply_writing()
                    }
                } {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("inconclusive: pump never admitted the reply");
            assert!(
                tokio::time::timeout(Duration::from_millis(50), probe_readiness.writable())
                    .await
                    .is_err(),
                "inconclusive: probe became writable before release"
            );
        } else {
            tokio::time::timeout(BOUND, async {
                while probe_blocked.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("inconclusive: pump never attempted the blocked write");
        }

        if close_packet {
            let state = duplex.shared.lock().unwrap();
            assert!(state.established.close_reply_writing());
            assert!(state.established.session_close_pending_in_driver());
            assert!(state.remote_eof);
            assert_eq!(
                state.inbound.bytes.iter().copied().collect::<Vec<_>>(),
                b"AB"
            );
        }

        // Let the peer send B and a reply-requiring global request while the
        // probe stays full.
        send_tx.send(()).unwrap();
        tokio::time::timeout(BOUND, sent_rx)
            .await
            .expect("inconclusive: peer did not confirm sending B")
            .unwrap();

        if foreign_packet {
            tokio::time::timeout(BOUND, async {
                while !duplex.shared.lock().unwrap().closed {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("foreign channel traffic did not fail the pump");
            {
                let state = duplex.shared.lock().unwrap();
                assert!(state.failure.is_some());
                assert!(state.established.close_reply_writing());
                assert!(state.established.session_close_pending_in_driver());
            }
            assert!(duplex.flush().await.is_err());
            assert!(duplex.shutdown().await.is_err());
            drop(duplex);
            cleanup.release();
            cleanup.finish();
            let peer = cleanup.peer.take().unwrap();
            let joined =
                tokio::time::timeout(BOUND, tokio::task::spawn_blocking(move || peer.join()))
                    .await
                    .expect("foreign-channel peer did not finish")
                    .expect("peer join task failed")
                    .expect("peer panicked");
            assert!(
                joined.is_err(),
                "foreign-channel peer unexpectedly completed"
            );
            return;
        }

        // Synchronize on the actual pump state: the pump must have read B and
        // the following global request, queued that reply, and still have the
        // writer blocked on the full probe. This is not inferred from B
        // arriving or from transcript order.
        tokio::time::timeout(BOUND, async {
            loop {
                {
                    let state = duplex.shared.lock().unwrap();
                    if state.established.reply_queued()
                        && !state.established.can_read_behind_active()
                        && if pong_packet {
                            state.established.pong_writing() && state.remote_eof
                        } else if close_packet {
                            state.established.close_reply_writing()
                                && state.established.session_close_pending_in_driver()
                        } else if open_packet {
                            state.established.open_rejection_writing() && state.remote_eof
                        } else if channel_packet {
                            state.established.channel_reply_writing() && state.remote_eof
                        } else if global_packet {
                            state.established.global_reply_writing()
                        } else if eof_packet {
                            state.established.eof_active() && state.remote_eof
                        } else if data_packet {
                            state.established.data_active()
                        } else {
                            state.established.adjustment_active()
                        }
                    {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("inconclusive: pump did not queue the reply behind the blocked writer");

        if eof_packet || reply_packet {
            let state = duplex.shared.lock().unwrap();
            assert_eq!(
                state.inbound.bytes.iter().copied().collect::<Vec<_>>(),
                b"AB"
            );
            if eof_packet || channel_packet || open_packet || close_packet || pong_packet {
                assert!(state.remote_eof);
            }
        }
        let sequence_before = if channel_packet || open_packet || close_packet || pong_packet {
            Some(
                duplex
                    .shared
                    .lock()
                    .unwrap()
                    .established
                    .committed_outbound_sequence(),
            )
        } else {
            None
        };
        if eof_packet || reply_packet {
            let mut encrypted = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(BOUND, read_readiness.peek(&mut encrypted))
                    .await
                    .expect("packet after EOF obligation was not readable")
                    .unwrap(),
                1
            );
            let state = duplex.shared.lock().unwrap();
            if pong_packet {
                assert!(state.established.pong_writing());
                if nested_ping {
                    assert!(state.established.next_is_pong());
                }
            } else if close_packet {
                assert!(state.established.close_reply_writing());
                assert!(state.established.session_close_pending_in_driver());
            } else if open_packet {
                assert!(state.established.open_rejection_writing());
                assert_eq!(state.established.pending_peer_opens(), 1);
            } else if channel_packet {
                assert!(state.established.channel_reply_writing());
            } else if global_packet {
                assert!(state.established.global_reply_writing());
            } else {
                assert!(state.established.eof_active());
            }
            assert!(state.established.reply_queued());
            if peer_close {
                assert!(state.established.owed_close_reply());
            }
        }
        if eof_packet {
            use std::future::Future as _;
            let waker = futures_util::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            let mut shutdown = Box::pin(duplex.shutdown());
            assert!(shutdown.as_mut().poll(&mut context).is_pending());
            drop(shutdown);
            let mut flush = Box::pin(duplex.flush());
            assert!(flush.as_mut().poll(&mut context).is_pending());
        }
        if data_packet && !peer_close {
            // The complete C packet follows the request on the protected
            // stream. The full obligation slot must leave it on the socket.
            let mut encrypted = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(BOUND, read_readiness.peek(&mut encrypted))
                    .await
                    .expect("peer's following packet was not readable")
                    .unwrap(),
                1
            );
            let state = duplex.shared.lock().unwrap();
            assert!(state.established.data_active());
            assert!(state.established.reply_queued());
            assert_eq!(state.outbound, vec![b'R'; 64]);
            assert!(!state.inbound.bytes.contains(&b'C'));
        }
        if peer_close && data_packet {
            let state = duplex.shared.lock().unwrap();
            assert!(state.established.data_active());
            assert!(state.established.owed_close_reply());
            assert_eq!(state.outbound, vec![b'R'; 64]);
        }
        if data_packet || eof_packet || reply_packet {
            let before = duplex.shared.lock().unwrap().pump_calls;
            for _ in 0..128 {
                tokio::task::yield_now().await;
            }
            let after = duplex.shared.lock().unwrap().pump_calls;
            assert!(
                after.saturating_sub(before) <= 2,
                "pump repeatedly ran while the next slot and probe were blocked"
            );
        }
        if matches!(
            outcome,
            ProbeOutcome::Drop
                | ProbeOutcome::GlobalDrop
                | ProbeOutcome::ChannelDrop
                | ProbeOutcome::OpenDrop
                | ProbeOutcome::CloseDrop
                | ProbeOutcome::PongDrop
        ) {
            let control = duplex.control.clone();
            drop(duplex);
            assert!(control.is_cancelled());
            cleanup.release();
            cleanup.finish();
            let peer = cleanup.peer.take().unwrap();
            let joined =
                tokio::time::timeout(BOUND, tokio::task::spawn_blocking(move || peer.join()))
                    .await
                    .expect("cancelled peer did not finish")
                    .expect("cancelled peer join task failed")
                    .expect("cancelled peer panicked");
            assert!(
                joined.is_err(),
                "peer saw an unexpected completed transcript"
            );
            return;
        }
        if matches!(
            outcome,
            ProbeOutcome::Fatal
                | ProbeOutcome::GlobalFatal
                | ProbeOutcome::ChannelFatal
                | ProbeOutcome::OpenFatal
                | ProbeOutcome::CloseFatal
                | ProbeOutcome::PongFatal
        ) {
            fail_socket.shutdown(std::net::Shutdown::Both).unwrap();
            tokio::time::timeout(BOUND, async {
                let mut buffer = vec![0_u8; FILL_CHUNK];
                let mut drained = 0;
                while drained < filled {
                    let count = probe_peer.read(&mut buffer).await.unwrap();
                    assert_ne!(count, 0);
                    drained += count;
                }
            })
            .await
            .expect("fatal test probe did not drain");
            cleanup.release();
            assert!(
                tokio::time::timeout(BOUND, duplex.shutdown())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(duplex.flush().await.is_err());
            cleanup.finish();
            let peer = cleanup.peer.take().unwrap();
            let joined =
                tokio::time::timeout(BOUND, tokio::task::spawn_blocking(move || peer.join()))
                    .await
                    .expect("failed peer did not finish")
                    .expect("failed peer join task failed")
                    .expect("failed peer panicked");
            assert!(
                joined.is_err(),
                "peer saw an unexpected completed transcript"
            );
            return;
        }

        // The application must still receive A and B before the probe drains.
        if data_packet || reply_packet {
            tokio::time::timeout(BOUND, duplex.read_exact(&mut first))
                .await
                .expect("inconclusive: first peer byte was not observed")
                .unwrap();
            assert_eq!(first, *b"A");
        }
        if !eof_packet {
            let mut second = [0_u8; 1];
            match tokio::time::timeout(Duration::from_secs(1), duplex.read_exact(&mut second)).await
            {
                Ok(Ok(_)) => assert_eq!(second, *b"B"),
                Ok(Err(error))
                    if error
                        .to_string()
                        .contains("unexpected SSH write WouldBlock") =>
                {
                    panic!(
                        "inconclusive: the SSH socket write blocked; the probe is the only intended pressure"
                    );
                }
                Ok(Err(error)) => panic!("inconclusive: reading B failed: {error}"),
                Err(error) => {
                    panic!("inconclusive: B was not read while the probe was full: {error}")
                }
            }
        }
        if channel_packet || open_packet || close_packet || pong_packet {
            assert_eq!(duplex.read(&mut [0_u8; 1]).await.unwrap(), 0);
        }
        let wakes = if peer_close && data_packet {
            use std::future::Future as _;
            use tokio::io::AsyncRead as _;
            let writer = Arc::new(CountWake(std::sync::atomic::AtomicUsize::new(0)));
            let reader = Arc::new(CountWake(std::sync::atomic::AtomicUsize::new(0)));
            let writer_waker = std::task::Waker::from(Arc::clone(&writer));
            let reader_waker = std::task::Waker::from(Arc::clone(&reader));
            let mut flush = Box::pin(duplex.flush());
            assert!(
                flush
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(&writer_waker))
                    .is_pending()
            );
            drop(flush);
            let mut byte = [0];
            let mut buffer = tokio::io::ReadBuf::new(&mut byte);
            assert!(
                std::pin::Pin::new(&mut duplex)
                    .poll_read(
                        &mut std::task::Context::from_waker(&reader_waker),
                        &mut buffer
                    )
                    .is_pending()
            );
            Some((reader, writer))
        } else {
            None
        };

        // Drain the probe. Its writability is what lets the pump finish the
        // active packet and the queued reply.
        let drain = async {
            let mut buffer = vec![0_u8; FILL_CHUNK];
            let mut drained = 0_usize;
            while drained < filled {
                match probe_peer.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => drained += count,
                    Err(error) => panic!("inconclusive: probe drain failed: {error}"),
                }
            }
        };
        tokio::time::timeout(BOUND, drain)
            .await
            .expect("inconclusive: probe did not drain");

        if data_packet && !peer_close {
            tokio::time::timeout(BOUND, async {
                loop {
                    if duplex.shared.lock().unwrap().inbound.bytes.contains(&b'C') {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the packet behind the full slot was not read after the reply");
        }

        // Release the peer so it reads the client's events, then send the
        // client's EOF. The EOF is the bounded protocol delimiter that proves
        // nothing extra was sent before the half-close. Keep the probe peer
        // alive through the EOF write so the transport's probe still has a
        // destination.
        cleanup.release();
        if peer_close && data_packet {
            tokio::time::timeout(BOUND, async {
                while !duplex.shared.lock().unwrap().closed {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("pump did not finish the close reply");
            let (reader, writer) = wakes.unwrap();
            assert!(reader.0.load(Ordering::SeqCst) > 0, "reader was not woken");
            assert!(writer.0.load(Ordering::SeqCst) > 0, "writer was not woken");
            let flush_error = tokio::time::timeout(BOUND, duplex.flush())
                .await
                .unwrap()
                .expect_err("flush reported unsent accepted bytes as successful");
            let shutdown_error = tokio::time::timeout(BOUND, duplex.shutdown())
                .await
                .unwrap()
                .expect_err("shutdown reported unsent accepted bytes as successful");
            assert!(flush_error.to_string().contains("all accepted data"));
            assert_eq!(shutdown_error.to_string(), flush_error.to_string());
        } else {
            tokio::time::timeout(BOUND, duplex.shutdown())
                .await
                .expect("inconclusive: shutdown did not complete")
                .expect("inconclusive: shutdown failed");
            if eof_packet {
                assert!(
                    !duplex
                        .shared
                        .lock()
                        .unwrap()
                        .established
                        .reply_outstanding()
                );
                if !peer_close {
                    barrier_tx.send(()).unwrap();
                }
            }
        }

        // The transcript signal is the peer's protocol-complete signal. Await
        // it with a timeout, then let the peer return before joining it off
        // the async runtime thread.
        let transcript = tokio::time::timeout(BOUND, transcript_rx)
            .await
            .expect("inconclusive: peer did not send its transcript")
            .expect("inconclusive: peer dropped its transcript sender");
        if let Some(before) = sequence_before {
            let state = duplex.shared.lock().unwrap();
            let after = state.established.committed_outbound_sequence();
            assert_eq!(
                after,
                before
                    + if peer_close || close_packet { 2 } else { 4 }
                    + u32::try_from(filler_count).unwrap()
            );
            if open_packet {
                assert_eq!(state.established.pending_peer_opens(), 0);
            }
            if close_packet {
                assert!(state.established.session_retired());
                assert!(state.closed);
                assert!(!state.established.reply_outstanding());
            }
        }
        if eof_packet {
            let mut bytes = [0_u8; 2];
            tokio::time::timeout(BOUND, duplex.read_exact(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes, b"AB");
            assert_eq!(duplex.read(&mut [0_u8; 1]).await.unwrap(), 0);
            duplex.shutdown().await.unwrap();
            duplex.flush().await.unwrap();
        }
        cleanup.finish();
        let peer = cleanup.peer.take().unwrap();
        let joined = tokio::time::timeout(BOUND, tokio::task::spawn_blocking(move || peer.join()))
            .await
            .expect("inconclusive: peer join did not finish")
            .expect("inconclusive: peer join task failed");
        joined
            .expect("inconclusive: peer panicked")
            .expect("inconclusive: peer failed");

        assert_eq!(
            ssh_would_block.load(Ordering::SeqCst),
            0,
            "the SSH socket, not the probe, reported write pressure"
        );
        let session = session_id.load(Ordering::SeqCst);
        let window = initial_remote.load(Ordering::SeqCst);
        let expected = if pong_packet && peer_close {
            vec![ChannelEvent::Close { channel: session }]
        } else if pong_packet && nested_ping {
            vec![ChannelEvent::WindowAdjusted {
                channel: session,
                available: window,
            }]
        } else if pong_packet {
            vec![
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
                ChannelEvent::WindowAdjusted {
                    channel: session,
                    available: window,
                },
            ]
        } else if close_packet {
            vec![
                ChannelEvent::Close { channel: session },
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
            ]
        } else if eof_packet && !peer_close {
            vec![
                ChannelEvent::Eof { channel: session },
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
                ChannelEvent::Close { channel: session },
            ]
        } else if eof_packet {
            vec![
                ChannelEvent::Eof { channel: session },
                ChannelEvent::Close { channel: session },
            ]
        } else if peer_close && reply_packet {
            vec![
                if open_packet {
                    ChannelEvent::OpenFailed {
                        channel: 9,
                        reason: 1,
                        description: Vec::new(),
                        language: Vec::new(),
                    }
                } else if channel_packet {
                    ChannelEvent::RequestFailed { channel: session }
                } else {
                    ChannelEvent::GlobalRequestFailed { data: Vec::new() }
                },
                ChannelEvent::Close { channel: session },
            ]
        } else if peer_close {
            vec![
                ChannelEvent::Data {
                    channel: session,
                    data: vec![b'R'; 64],
                },
                ChannelEvent::Close { channel: session },
            ]
        } else if reply_packet {
            vec![
                if open_packet {
                    ChannelEvent::OpenFailed {
                        channel: 9,
                        reason: 1,
                        description: Vec::new(),
                        language: Vec::new(),
                    }
                } else if channel_packet {
                    ChannelEvent::RequestFailed { channel: session }
                } else {
                    ChannelEvent::GlobalRequestFailed { data: Vec::new() }
                },
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
                ChannelEvent::WindowAdjusted {
                    channel: session,
                    available: window,
                },
            ]
        } else if data_packet {
            vec![
                ChannelEvent::Data {
                    channel: session,
                    data: vec![b'R'; 64],
                },
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
                ChannelEvent::Data {
                    channel: session,
                    data: vec![b'R'; 64],
                },
                ChannelEvent::WindowAdjusted {
                    channel: session,
                    available: window - 1,
                },
            ]
        } else {
            vec![
                ChannelEvent::WindowAdjusted {
                    channel: session,
                    available: window - 1,
                },
                ChannelEvent::GlobalRequestFailed { data: Vec::new() },
                ChannelEvent::WindowAdjusted {
                    channel: session,
                    available: window,
                },
            ]
        };
        assert_eq!(
            transcript, expected,
            "the adjustment, reply, and credit were not sent once, in order, before EOF"
        );
        drop(duplex);
    }

    use neotales_ssh::channel::ChannelEvent;

    const BOUND: Duration = Duration::from_secs(10);
    /// Setup is expected in milliseconds. A short bound keeps a failed fixture
    /// from holding the peer in a setup read for the full test budget.
    const SETUP_BOUND: Duration = Duration::from_secs(2);
    /// Bound on receiving the peer's pre-termination signal.
    const CLEANUP_BOUND: Duration = Duration::from_secs(2);
    const EVENTS: usize = super::REPLY_CAPACITY;
    /// Requested sizes, not guaranteed sizes: the kernel may clamp them. The
    /// test does not assume the clamp; it observes the real `WouldBlock` and
    /// fails as inconclusive if the packet completes.
    const SMALL_BUFFER: u32 = 4 * 1024;

    /// A client socket that records real kernel write pressure on the managed
    /// SSH socket itself.
    ///
    /// Unlike [`ProbeWriteSocket`] and [`PartialProbeSocket`], this fixture has
    /// no second socket. Every `WouldBlock` counted here came from the one
    /// loopback connection the peer is (or, while it withholds reads, is not)
    /// reading.
    struct CountingSocket {
        inner: std::net::TcpStream,
        write_would_block: Arc<AtomicUsize>,
        bytes_written: Arc<AtomicUsize>,
    }

    impl std::io::Read for CountingSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.inner, bytes)
        }
    }

    impl std::io::Write for CountingSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            match std::io::Write::write(&mut self.inner, bytes) {
                Ok(count) => {
                    self.bytes_written.fetch_add(count, Ordering::SeqCst);
                    Ok(count)
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.write_would_block.fetch_add(1, Ordering::SeqCst);
                    Err(error)
                }
                Err(error) => Err(error),
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut self.inner)
        }
    }

    /// A waker that counts how many times it was woken.
    struct StallWake(AtomicUsize);

    impl std::task::Wake for StallWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The most recently observed socket read result.
    ///
    /// The channel layer collapses every transport failure into
    /// `ChannelError::Transport`, so this records the original I/O result at
    /// the socket boundary. It is not a later `peek`: it is the read the
    /// transport made, but it is not necessarily the cause of a later failure.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ReadObservation {
        None,
        Bytes(usize),
        Eof,
        Error {
            kind: std::io::ErrorKind,
            message: String,
        },
    }

    /// A peer-side socket that records every read result before the transport
    /// maps it to an opaque error.
    struct RecordingSocket {
        inner: std::net::TcpStream,
        last_read: Arc<std::sync::Mutex<ReadObservation>>,
    }

    impl std::io::Read for RecordingSocket {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let result = std::io::Read::read(&mut self.inner, buffer);
            let observation = match &result {
                Ok(0) => ReadObservation::Eof,
                Ok(count) => ReadObservation::Bytes(*count),
                Err(error) => ReadObservation::Error {
                    kind: error.kind(),
                    message: error.to_string(),
                },
            };
            *self.last_read.lock().unwrap() = observation;
            result
        }
    }

    impl std::io::Write for RecordingSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut self.inner, bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut self.inner)
        }
    }

    /// One recorded event on the controlled peer's read side.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum PeerRecord {
        Data(Vec<u8>),
        Reply,
        Eof,
        Close,
    }

    /// What the controlled peer actually observed.
    ///
    #[derive(Debug)]
    enum PeerOutcome {
        Completed(Vec<PeerRecord>),
        Failed {
            stage: &'static str,
            detail: String,
            error: Option<neotales_ssh::channel::ChannelError>,
            observation: ReadObservation,
        },
        Aborted,
    }

    fn failed(stage: &'static str, detail: impl Into<String>) -> PeerOutcome {
        PeerOutcome::Failed {
            stage,
            detail: detail.into(),
            error: None,
            observation: ReadObservation::None,
        }
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum RealPressureEnd {
        Release,
        Cancel,
        /// The peer never reads and the pump's write-stall bound expires.
        FailClosed,
        /// A peer KEXINIT is retained behind the blocked packet with no reply
        /// owed; the pump's write-stall bound must expire.
        RekeyFailClosed,
    }

    /// Accepts at most one connection, but wakes every few milliseconds to
    /// observe `stop`, so a client that fails before dialing cannot leave the
    /// peer blocked in `accept` forever.
    fn accept_with_stop(
        listener: &std::net::TcpListener,
        stop: &AtomicBool,
        bound: Duration,
    ) -> Result<Option<std::net::TcpStream>, String> {
        let deadline = std::time::Instant::now() + bound;
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(None);
            }
            match listener.accept() {
                Ok((socket, _)) => return Ok(Some(socket)),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    /// Registers the socket clone the cleanup uses to interrupt a blocked peer.
    ///
    /// Registration is mandatory: a clone failure is returned to the peer and
    /// becomes a structured `Failed` outcome rather than being ignored.
    fn register_interrupt<F>(
        socket: &std::net::TcpStream,
        slot: &std::sync::Mutex<Option<std::net::TcpStream>>,
        clone: F,
    ) -> Result<(), String>
    where
        F: FnOnce(&std::net::TcpStream) -> std::io::Result<std::net::TcpStream>,
    {
        let clone = clone(socket).map_err(|error| error.to_string())?;
        *slot.lock().unwrap() = Some(clone);
        Ok(())
    }

    /// Everything the peer script needs.
    struct PeerControl {
        listener: std::net::TcpListener,
        stop: Arc<AtomicBool>,
        socket_slot: Arc<std::sync::Mutex<Option<std::net::TcpStream>>>,
        send_events: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Receiver<()>,
        ready: tokio::sync::oneshot::Sender<()>,
        events_sent: tokio::sync::oneshot::Sender<()>,
        replies: tokio::sync::oneshot::Sender<()>,
        /// Every `GlobalRequestFailed` the peer actually dispatched.
        observed_replies: Arc<AtomicUsize>,
        /// Send a peer KEXINIT instead of reply-requiring global requests.
        rekey_only: bool,
        signer: neotales_ssh::hostkey::Ed25519Signer,
        payload: Vec<u8>,
        later: Vec<u8>,
    }

    /// The receivers the test drives.
    struct PeerSignals {
        ready: tokio::sync::oneshot::Receiver<()>,
        events_sent: tokio::sync::oneshot::Receiver<()>,
        replies: tokio::sync::oneshot::Receiver<()>,
        observed_replies: Arc<AtomicUsize>,
        outcome: tokio::sync::oneshot::Receiver<PeerOutcome>,
    }

    /// Runs the peer script and returns exactly what it observed.
    #[allow(clippy::too_many_lines)] // The peer script is the fixture; splitting it would hide the ordering.
    fn run_real_pressure_peer(control: PeerControl) -> PeerOutcome {
        let PeerControl {
            listener,
            stop,
            socket_slot,
            send_events,
            release,
            ready,
            events_sent,
            replies,
            observed_replies,
            rekey_only,
            signer,
            payload,
            later,
        } = control;
        let socket = match accept_with_stop(&listener, &stop, BOUND) {
            Ok(Some(socket)) => socket,
            Ok(None) => return PeerOutcome::Aborted,
            Err(error) => return failed("accept", error),
        };
        if let Err(error) =
            register_interrupt(&socket, &socket_slot, std::net::TcpStream::try_clone)
        {
            return failed("register-interrupt", error);
        }
        if stop.load(Ordering::SeqCst) {
            return PeerOutcome::Aborted;
        }
        let recording = Arc::new(std::sync::Mutex::new(ReadObservation::None));
        let recording_for_socket = Arc::clone(&recording);
        if let Err(error) = socket.set_read_timeout(Some(SETUP_BOUND)) {
            return failed("read-timeout", error.to_string());
        }
        if let Err(error) = socket.set_write_timeout(Some(SETUP_BOUND)) {
            return failed("write-timeout", error.to_string());
        }
        let mut transport =
            match neotales_ssh::server::ServerConfig::new(signer).connect(RecordingSocket {
                inner: socket,
                last_read: recording_for_socket,
            }) {
                Ok(transport) => transport,
                Err(error) => return failed("handshake", error.to_string()),
            };
        let policy = match neotales_ssh::auth::ServerAuthPolicy::new(2) {
            Ok(policy) => policy.with_password_callback(|_| true),
            Err(error) => return failed("auth-policy", error.to_string()),
        };
        if let Err(error) = neotales_ssh::auth::authenticate_server(&mut transport, &policy) {
            return failed("authentication", error.to_string());
        }
        let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
        let session = match connection.dispatch_one() {
            Ok(ChannelEvent::OpenRequest(request)) => {
                if let Err(error) = connection.confirm_open_with_limits(
                    request.sender_channel(),
                    0,
                    super::INITIAL_CHANNEL_WINDOW,
                    MAX_CHANNEL_PACKET_SIZE,
                ) {
                    return failed("open-confirmation", format!("{error:?}"));
                }
                0
            }
            Ok(other) => return failed("open", format!("expected a session open, got {other:?}")),
            Err(error) => return failed("open-dispatch", format!("{error:?}")),
        };
        loop {
            match connection.dispatch_one() {
                Ok(ChannelEvent::Request {
                    request_type,
                    want_reply: true,
                    ..
                }) if request_type == b"exec" => {
                    if let Err(error) = connection.send_request_success(session) {
                        return failed("exec-reply", format!("{error:?}"));
                    }
                    break;
                }
                Ok(_) => {}
                Err(error) => return failed("exec-dispatch", format!("{error:?}")),
            }
        }
        // The post-release read may wait for the test's release, so it gets the
        // full budget; setup keeps the short bound above.
        if let Some(interrupt) = socket_slot.lock().unwrap().as_ref() {
            let _ = interrupt.set_read_timeout(Some(BOUND));
            let _ = interrupt.set_write_timeout(Some(BOUND));
        }
        if ready.send(()).is_err() {
            return failed("ready", "receiver dropped");
        }
        if send_events.recv_timeout(BOUND).is_err() {
            return failed("send-events", "wait timed out");
        }
        // Withhold every read. A reply-requiring request must be answered or
        // retained; a KEXINIT is retained by the client behind its blocked
        // packet and must not be read past.
        if rekey_only {
            if let Err(error) = connection.transport_mut().begin_rekey() {
                return failed("rekey", format!("{error:?}"));
            }
        } else {
            for _ in 0..EVENTS {
                if let Err(error) = connection
                    .transport_mut()
                    .write_payload(&global_request(true))
                {
                    return failed("event-write", format!("{error:?}"));
                }
            }
        }
        if events_sent.send(()).is_err() {
            return failed("events-sent", "receiver dropped");
        }
        if release.recv_timeout(BOUND).is_err() {
            return failed("release", "wait timed out");
        }
        let mut transcript = Vec::new();
        let mut replies = Some(replies);
        let mut reply_count = 0_usize;
        loop {
            match connection.dispatch_one() {
                Ok(ChannelEvent::Data { channel, data }) if channel == session => {
                    if data == payload || data == later {
                        transcript.push(PeerRecord::Data(data));
                    } else {
                        return failed(
                            "data",
                            format!("unexpected session data: {} bytes", data.len()),
                        );
                    }
                }
                Ok(ChannelEvent::GlobalRequestFailed { .. }) => {
                    reply_count += 1;
                    observed_replies.fetch_add(1, Ordering::SeqCst);
                    transcript.push(PeerRecord::Reply);
                    if reply_count == EVENTS
                        && let Some(tx) = replies.take()
                        && tx.send(()).is_err()
                    {
                        return failed("replies", "receiver dropped");
                    }
                }
                Ok(ChannelEvent::WindowAdjusted { .. }) => {}
                Ok(ChannelEvent::Eof { channel }) if channel == session => {
                    transcript.push(PeerRecord::Eof);
                    return PeerOutcome::Completed(transcript);
                }
                Ok(ChannelEvent::Close { channel }) if channel == session => {
                    transcript.push(PeerRecord::Close);
                    return PeerOutcome::Completed(transcript);
                }
                Ok(other) => return failed("event", format!("unexpected peer event: {other:?}")),
                Err(error) => {
                    let observation = recording.lock().unwrap().clone();
                    return PeerOutcome::Failed {
                        stage: "dispatch",
                        detail: format!("dispatch failed with {error:?} after {observation:?}"),
                        error: Some(error),
                        observation,
                    };
                }
            }
        }
    }

    /// Requests peer shutdown and joins after its pre-termination signal.
    ///
    /// The accept loop is interruptible and the accepted socket is registered
    /// here, so `shutdown` can stop a peer that is blocked in accept, a setup
    /// read, or the release wait. If the peer does not report `done` within the
    /// bound, the handle is detached and `shutdown` returns an error. The
    /// signal precedes thread termination, so the subsequent join is not
    /// itself bounded. The enclosing supervised process is the outer bound.
    struct RealPressureCleanup {
        send_events: Option<std::sync::mpsc::Sender<()>>,
        release: Option<std::sync::mpsc::Sender<()>>,
        stop: Arc<AtomicBool>,
        socket: Arc<std::sync::Mutex<Option<std::net::TcpStream>>>,
        done: Option<std::sync::mpsc::Receiver<()>>,
        peer: Option<std::thread::JoinHandle<()>>,
    }

    impl RealPressureCleanup {
        fn release(&mut self) {
            if let Some(send) = self.send_events.take() {
                let _ = send.send(());
            }
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
        }

        fn shutdown_with_bound(&mut self, bound: Duration) -> Result<(), String> {
            self.stop.store(true, Ordering::SeqCst);
            self.release();
            // The peer stores its accepted socket before its stop check. Give
            // that store a short window so a setup read can be interrupted
            // instead of waiting for its socket timeout.
            for _ in 0..20 {
                let socket = self.socket.lock().unwrap().take();
                if let Some(socket) = socket {
                    let _ = socket.shutdown(std::net::Shutdown::Both);
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let Some(peer) = self.peer.take() else {
                return Ok(());
            };
            let Some(done) = self.done.take() else {
                drop(peer);
                return Err("peer has no termination channel".to_owned());
            };
            if let Ok(()) = done.recv_timeout(bound) {
                peer.join().map_err(|_| "peer panicked".to_owned())
            } else {
                // Do not join an unresponsive thread without a bound and do
                // not report it as joined.
                drop(peer);
                Err("peer did not report termination within the cleanup bound".to_owned())
            }
        }

        fn shutdown(&mut self) -> Result<(), String> {
            self.shutdown_with_bound(CLEANUP_BOUND)
        }
    }

    impl Drop for RealPressureCleanup {
        fn drop(&mut self) {
            // Drop cannot report. The supervisor bounds the enclosing process
            // if the pre-termination signal is followed by a stuck join.
            let _ = self.shutdown();
        }
    }

    /// Spawns the peer and returns the cleanup plus the signals the test drives.
    fn spawn_real_pressure_peer(
        listener: std::net::TcpListener,
        signer: neotales_ssh::hostkey::Ed25519Signer,
        payload: Vec<u8>,
        later: Vec<u8>,
        rekey_only: bool,
    ) -> (RealPressureCleanup, PeerSignals) {
        let (send_events_tx, send_events_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (events_sent_tx, events_sent_rx) = tokio::sync::oneshot::channel();
        let (replies_tx, replies_rx) = tokio::sync::oneshot::channel();
        let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let socket_slot = Arc::new(std::sync::Mutex::new(None));
        let observed_replies = Arc::new(AtomicUsize::new(0));
        let control = PeerControl {
            listener,
            stop: Arc::clone(&stop),
            socket_slot: Arc::clone(&socket_slot),
            send_events: send_events_rx,
            release: release_rx,
            ready: ready_tx,
            events_sent: events_sent_tx,
            replies: replies_tx,
            observed_replies: Arc::clone(&observed_replies),
            rekey_only,
            signer,
            payload,
            later,
        };
        let peer = std::thread::spawn(move || {
            let outcome = run_real_pressure_peer(control);
            let _ = outcome_tx.send(outcome);
            let _ = done_tx.send(());
        });
        let cleanup = RealPressureCleanup {
            send_events: Some(send_events_tx),
            release: Some(release_tx),
            stop,
            socket: socket_slot,
            done: Some(done_rx),
            peer: Some(peer),
        };
        let signals = PeerSignals {
            ready: ready_rx,
            events_sent: events_sent_rx,
            replies: replies_rx,
            observed_replies,
            outcome: outcome_rx,
        };
        (cleanup, signals)
    }

    // The child runs just one named libtest and never starts subprocesses.
    // Its peer and Tokio workers therefore die with it. On ordinary timeout
    // the parent kills and waits for the child; parent death and uninterruptible
    // kernel waits are outside this guarantee.
    const PRESSURE_CHILD: &str = "NEOTALES_PRESSURE_TEST_CHILD";
    const PRESSURE_READY: &str = "NEOTALES_PRESSURE_TEST_READY";
    const PRESSURE_PREFIX: &str = "ssh_neotales::tests::";
    const PRESSURE_PROCESS_BOUND: Duration = Duration::from_secs(45);

    struct SupervisedChild(std::process::Child);

    impl Drop for SupervisedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn accept_pressure_readiness(ready: &std::net::TcpListener) -> Result<bool, String> {
        match ready.accept() {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(format!("child readiness: {error}")),
        }
    }

    fn confirm_pressure_child_started(
        started: bool,
        recheck: impl FnOnce() -> Result<bool, String>,
    ) -> Result<(), String> {
        if started || recheck()? {
            Ok(())
        } else {
            Err("child did not run fixture".to_owned())
        }
    }

    fn supervise_pressure_test(name: &str, mode: &str, bound: Duration) -> Result<(), String> {
        let full_name = format!("{PRESSURE_PREFIX}{name}");
        let ready = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        ready.set_nonblocking(true).map_err(|e| e.to_string())?;
        let child = std::process::Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .args(["--exact", &full_name, "--nocapture", "--test-threads=1"])
            .env(PRESSURE_CHILD, mode)
            .env(
                PRESSURE_READY,
                ready.local_addr().map_err(|e| e.to_string())?.to_string(),
            )
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut child = SupervisedChild(child);
        let deadline = std::time::Instant::now() + bound;
        let mut started = false;
        loop {
            if !started {
                started = accept_pressure_readiness(&ready)?;
            }
            match child.0.try_wait().map_err(|e| e.to_string())? {
                Some(status) if status.success() => {
                    return confirm_pressure_child_started(started, || {
                        accept_pressure_readiness(&ready)
                    });
                }
                Some(status) => return Err(format!("child failed: {status}")),
                None if std::time::Instant::now() >= deadline => {
                    child.0.kill().map_err(|e| format!("kill child: {e}"))?;
                    child.0.wait().map_err(|e| format!("reap child: {e}"))?;
                    return Err(format!(
                        "child timed out and was reaped (started: {started})"
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    #[test]
    fn pressure_supervisor_rechecks_readiness_after_child_exit() {
        let ready = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ready.set_nonblocking(true).unwrap();
        let started = accept_pressure_readiness(&ready).unwrap();
        assert!(!started, "first readiness check must precede the child");
        let child = std::net::TcpStream::connect(ready.local_addr().unwrap()).unwrap();
        drop(child);
        // The successful child exit is observed between the initial failed
        // accept and this recheck; the connection remains queued.
        confirm_pressure_child_started(started, || accept_pressure_readiness(&ready)).unwrap();
        assert!(
            confirm_pressure_child_started(false, || accept_pressure_readiness(&ready))
                .unwrap_err()
                .contains("child did not run fixture")
        );
    }

    fn pressure_child_ready() {
        let address = std::env::var(PRESSURE_READY).expect("missing supervisor readiness address");
        std::net::TcpStream::connect(address).expect("cannot notify supervisor");
    }

    fn pressure_child_or_supervise(name: &str) -> bool {
        if std::env::var(PRESSURE_CHILD).as_deref() == Ok(name) {
            pressure_child_ready();
            true
        } else {
            supervise_pressure_test(name, name, PRESSURE_PROCESS_BOUND)
                .expect("supervised pressure fixture failed");
            false
        }
    }

    #[test]
    fn pressure_supervisor_fixture() {
        if std::env::var_os(PRESSURE_CHILD).is_some() {
            pressure_child_ready();
        }
        match std::env::var(PRESSURE_CHILD).as_deref() {
            Ok("timeout") => std::thread::sleep(Duration::from_secs(30)),
            Ok("failure") => panic!("injected supervised child failure"),
            Ok("success") | Err(_) => {}
            Ok(other) => panic!("unexpected child mode: {other}"),
        }
    }

    #[test]
    fn pressure_supervisor_reports_failure_and_reaps_timeout() {
        let name = "pressure_supervisor_fixture";
        assert!(supervise_pressure_test(name, "success", BOUND).is_ok());
        assert!(
            supervise_pressure_test(name, "failure", BOUND)
                .unwrap_err()
                .contains("child failed")
        );
        assert!(
            supervise_pressure_test(name, "timeout", Duration::from_millis(500))
                .unwrap_err()
                .contains("timed out and was reaped (started: true)")
        );
        assert!(
            supervise_pressure_test("nonexistent_pressure_fixture", "success", BOUND)
                .unwrap_err()
                .contains("child did not run fixture")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_socket_send_pressure_progresses_and_preserves_order() {
        if !pressure_child_or_supervise("real_socket_send_pressure_progresses_and_preserves_order")
        {
            return;
        }
        real_socket_pressure(RealPressureEnd::Release, super::WRITE_STALL_BOUND).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_socket_send_pressure_cancels_without_false_success() {
        if !pressure_child_or_supervise("real_socket_send_pressure_cancels_without_false_success") {
            return;
        }
        real_socket_pressure(RealPressureEnd::Cancel, super::WRITE_STALL_BOUND).await;
    }

    /// A peer that fills the send buffer, requires replies, and never reads
    /// must end the session at the write-stall bound instead of hanging.
    ///
    /// This drives the real managed SSH socket and the real pump. It is the
    /// fail-closed side of full-FIFO backpressure: the channel driver
    /// refuses a second read while a reply is owed, so the only remaining
    /// progress is the peer reading; when it does not, the pump fails closed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_socket_send_pressure_fails_closed_when_the_peer_never_reads() {
        if !pressure_child_or_supervise(
            "real_socket_send_pressure_fails_closed_when_the_peer_never_reads",
        ) {
            return;
        }
        real_socket_pressure(RealPressureEnd::FailClosed, Duration::from_secs(1)).await;
    }

    /// A retained peer KEXINIT behind the blocked packet, with no reply owed,
    /// must arm and expire on the same bound through the real async pump.
    ///
    /// The peer sends KEXINIT instead of reply-requiring requests and withholds
    /// reads. The test observes the arm, the retained rekey with
    /// `reply_outstanding() == false`, both wakers firing at failure, and the
    /// terminal diagnostic after the bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_pump_retained_rekey_without_a_reply_expires_at_the_bound() {
        if !pressure_child_or_supervise(
            "async_pump_retained_rekey_without_a_reply_expires_at_the_bound",
        ) {
            return;
        }
        real_socket_pressure(RealPressureEnd::RekeyFailClosed, Duration::from_secs(1)).await;
    }

    /// The accept loop must observe `stop` even when no client ever connects,
    /// so a failed fixture cannot leave the peer blocked in `accept`.
    #[test]
    fn real_pressure_accept_stops_without_a_client() {
        if !pressure_child_or_supervise("real_pressure_accept_stops_without_a_client") {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let peer_stop = Arc::clone(&stop);
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let result = accept_with_stop(&listener, &peer_stop, Duration::from_secs(10));
            result_tx.send(result).unwrap();
        });
        stop.store(true, Ordering::SeqCst);
        let result = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("accept did not observe the stop flag");
        match result {
            Ok(None) => {}
            other => panic!("accept returned {other:?}"),
        }
        peer.join().unwrap();
    }

    /// A registration failure is a structured failure, not a silent skip.
    #[test]
    fn real_pressure_registration_failure_is_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(address).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let slot = std::sync::Mutex::new(None);
        let result = register_interrupt(&socket, &slot, |_| {
            Err(std::io::Error::other("injected registration failure"))
        });
        assert!(result.is_err(), "registration failure was silently ignored");
        assert!(slot.lock().unwrap().is_none());
        drop(client);
    }

    /// A peer that ignores every stop signal is reported, not joined without a
    /// bound. The thread finishes shortly after the bound so the test does not
    /// leave it running.
    #[test]
    fn real_pressure_cleanup_reports_a_peer_that_does_not_terminate() {
        if !pressure_child_or_supervise(
            "real_pressure_cleanup_reports_a_peer_that_does_not_terminate",
        ) {
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(std::sync::Mutex::new(None));
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, _release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let _ = done_tx.send(());
            let _ = finished_tx.send(());
        });
        let mut cleanup = RealPressureCleanup {
            send_events: None,
            release: Some(release_tx),
            stop,
            socket,
            done: Some(done_rx),
            peer: Some(peer),
        };
        let result = cleanup.shutdown_with_bound(Duration::from_millis(100));
        assert!(
            result.is_err(),
            "a non-terminating peer was reported as joined"
        );
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("peer thread did not finish");
    }

    /// A client that fails during setup must still let the test observe the
    /// peer's structured failure and termination under process supervision.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_pressure_setup_failure_terminates_the_peer() {
        if !pressure_child_or_supervise("real_pressure_setup_failure_terminates_the_peer") {
            return;
        }
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [152; 32]);
        let peer_socket = tokio::net::TcpSocket::new_v4().unwrap();
        peer_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = peer_socket.listen(1).unwrap();
        let address = listener.local_addr().unwrap();
        let listener = listener.into_std().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (mut cleanup, signals) =
            spawn_real_pressure_peer(listener, signer, vec![b'R'; 16], b"later".to_vec(), false);
        let PeerSignals { outcome, .. } = signals;
        let client = std::net::TcpStream::connect(address).unwrap();
        drop(client);
        let outcome = tokio::time::timeout(BOUND, outcome)
            .await
            .expect("the peer did not report a setup failure")
            .expect("the peer ended without an outcome");
        cleanup
            .shutdown()
            .expect("the peer did not terminate after a client setup failure");
        match outcome {
            PeerOutcome::Failed { stage, detail, .. } => assert!(
                matches!(
                    stage,
                    "handshake" | "authentication" | "open-dispatch" | "exec-dispatch"
                ),
                "unexpected setup failure stage {stage}: {detail}"
            ),
            other => panic!("expected a structured setup failure, got {other:?}"),
        }
    }

    /// Drives the real managed SSH socket to kernel send-buffer saturation.
    ///
    /// The controlled peer completes establishment, withholds every read, and
    /// sends eight reply-requiring global requests. The client requests small
    /// send and receive buffers; the kernel may clamp or adjust them, so the
    /// test requires a real `WouldBlock` on the SSH socket and fails as
    /// inconclusive if the admitted packet completes instead.
    ///
    /// The peer's writes returning does not prove every byte reached the
    /// client's kernel. What the test proves is narrower: the pump reads one
    /// events behind the blocked packet and retains the full bounded FIFO; an additional queued
    /// reply would fail the driver, so a clean state means the pump did not
    /// consume another reply-requiring event. Where the unread bytes are
    /// buffered is not observed.
    ///
    /// Releasing the peer must let the packet, then the retained replies, then
    /// later application data leave in order. Cancellation checks only the
    /// pending client flush and its cancellation state, not the cause of an
    /// opaque peer error.
    ///
    /// When the peer never releases its reads, the same state is the one the
    /// write-stall bound covers: the driver refuses another read at full
    /// FIFO capacity while the socket refuses the write. The `FailClosed` end
    /// asserts that the session ends with the stable diagnostic inside a
    /// short bound, that no application operation reports success afterwards,
    /// the peer dispatched no reply event (this is an observed dispatch fact,
    /// not a claim about bytes on the wire).
    #[allow(clippy::too_many_lines)] // One peer covers pressure, bounded state, order, and the terminal path.
    async fn real_socket_pressure(end: RealPressureEnd, stall_bound: Duration) {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use std::future::Future as _;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let payload = vec![b'R'; super::MAX_ADMISSION_BYTES];
        let later = b"after-the-replies".to_vec();

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [151; 32]);
        let peer_socket = tokio::net::TcpSocket::new_v4().unwrap();
        peer_socket.set_recv_buffer_size(SMALL_BUFFER).unwrap();
        peer_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = peer_socket.listen(1).unwrap();
        let address = listener.local_addr().unwrap();
        let listener = listener.into_std().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (_directory, mut options) = options_for_peer(address, &signer);
        options.write_inactivity_timeout = stall_bound;
        options.validate().unwrap();
        let (mut cleanup, signals) = spawn_real_pressure_peer(
            listener,
            signer,
            payload.clone(),
            later.clone(),
            end == RealPressureEnd::RekeyFailClosed,
        );
        let PeerSignals {
            ready,
            events_sent,
            replies,
            observed_replies,
            outcome,
        } = signals;

        // Connect with a requested small send buffer. The peer requested a
        // small receive buffer on its listener. Neither size is guaranteed.
        let client_socket = tokio::net::TcpSocket::new_v4().unwrap();
        client_socket.set_send_buffer_size(SMALL_BUFFER).unwrap();
        let client = client_socket.connect(address).await.unwrap();
        let client = client.into_std().unwrap();
        // `into_std` leaves the descriptor nonblocking. Establishment is the
        // synchronous blocking phase, so restore blocking until the session is
        // committed; the pump switches it back below.
        client.set_nonblocking(false).unwrap();
        client.set_read_timeout(Some(BOUND)).unwrap();
        client.set_write_timeout(Some(BOUND)).unwrap();

        let guard_socket = client.try_clone().unwrap();
        let ssh_control = client.try_clone().unwrap();
        let write_would_block = Arc::new(AtomicUsize::new(0));
        let bytes_written = Arc::new(AtomicUsize::new(0));
        let read_slot = Arc::new(std::sync::OnceLock::new());
        let write_slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = new_write_progress();
        let control = EstablishmentControl::new(Instant::now() + BOUND);
        let Dialed { guard, .. } = Dialed::test_connected(guard_socket, control).unwrap();
        let would_block = WouldBlock::default();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: CountingSocket {
                        inner: client,
                        write_would_block: Arc::clone(&write_would_block),
                        bytes_written: Arc::clone(&bytes_written),
                    },
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&read_slot),
                    write_readiness: Arc::clone(&write_slot),
                    write_progress: Arc::clone(&write_progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();

        tokio::time::timeout(BOUND, ready)
            .await
            .expect("inconclusive: the peer did not finish exec")
            .unwrap();

        ssh_control.set_nonblocking(true).unwrap();
        let readiness = Arc::new(tokio::net::TcpStream::from_std(ssh_control).unwrap());
        read_slot.set(Arc::clone(&readiness)).unwrap();
        // Mark the real socket writable before the first `try_io`, so the
        // pump's first write reaches the kernel and observes the pressure
        // instead of being short-circuited by stale readiness state.
        tokio::time::timeout(BOUND, readiness.writable())
            .await
            .expect("inconclusive: the SSH socket never reported writable")
            .unwrap();
        write_slot.set(Arc::clone(&readiness)).unwrap();
        let mut duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&readiness),
            Arc::clone(&readiness),
            Arc::clone(&write_progress),
            options.write_inactivity_timeout,
        );

        let baseline_blocked = write_would_block.load(Ordering::SeqCst);
        let baseline_written = bytes_written.load(Ordering::SeqCst);
        tokio::time::timeout(BOUND, duplex.write_all(&payload))
            .await
            .expect("inconclusive: application admission timed out")
            .unwrap();

        tokio::time::timeout(BOUND, async {
            while write_would_block.load(Ordering::SeqCst) == baseline_blocked {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("inconclusive: the managed SSH socket never reported a real write WouldBlock");

        cleanup.send_events.take().unwrap().send(()).unwrap();
        tokio::time::timeout(BOUND, events_sent)
            .await
            .expect("inconclusive: the peer did not send the reply-requiring events")
            .unwrap();

        if end == RealPressureEnd::RekeyFailClosed {
            // The peer sent a KEXINIT and withholds reads. Wait for the pump
            // to retain it and arm the bound with no reply owed.
            tokio::time::timeout(BOUND, async {
                loop {
                    if duplex
                        .shared
                        .lock()
                        .unwrap()
                        .reply_stall
                        .armed_at()
                        .is_some()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the pump did not arm the retained-rekey bound");
            let armed_at = {
                let state = duplex.shared.lock().unwrap();
                assert!(
                    state.established.rekey_active(),
                    "the peer rekey was not retained"
                );
                assert!(
                    !state.established.reply_outstanding(),
                    "a reply was owed; this fixture is rekey-only"
                );
                assert!(!state.closed, "the session failed before the bound");
                assert!(
                    state.failure.is_none(),
                    "the session failed at the arm point: {:?}",
                    state.failure
                );
                state
                    .reply_stall
                    .armed_at()
                    .expect("armed bound disappeared")
            };

            // Register both directions before failure so the test observes the
            // terminal wakeups rather than inferring them.
            let reader = Arc::new(StallWake(AtomicUsize::new(0)));
            let writer = Arc::new(StallWake(AtomicUsize::new(0)));
            let mut byte = [0_u8; 1];
            let mut buffer = tokio::io::ReadBuf::new(&mut byte);
            let read = tokio::io::AsyncRead::poll_read(
                std::pin::Pin::new(&mut duplex),
                &mut std::task::Context::from_waker(&std::task::Waker::from(Arc::clone(&reader))),
                &mut buffer,
            );
            assert!(read.is_pending(), "read completed before the failure");
            let mut flush = Box::pin(duplex.flush());
            assert!(
                flush
                    .as_mut()
                    .poll(&mut std::task::Context::from_waker(
                        &std::task::Waker::from(Arc::clone(&writer))
                    ))
                    .is_pending(),
                "flush completed while the socket was blocked"
            );
            drop(flush);

            tokio::time::timeout(BOUND, async {
                loop {
                    if duplex.shared.lock().unwrap().closed {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the retained-rekey bound did not expire");
            let (failure, failed_at, rekey) = {
                let state = duplex.shared.lock().unwrap();
                (
                    state.failure.clone(),
                    state.failed_at,
                    state.established.rekey_active(),
                )
            };
            assert!(rekey, "the retained rekey state was not preserved");
            assert!(
                failure
                    .as_deref()
                    .is_some_and(|failure| failure.contains(super::WRITE_STALL_MESSAGE)),
                "the retained rekey did not fail with the write-stall diagnostic: {failure:?}"
            );
            let elapsed = failed_at
                .expect("the pump never recorded its failure time")
                .duration_since(armed_at);
            assert!(
                elapsed >= stall_bound,
                "the retained rekey failed before the bound: {elapsed:?}"
            );
            assert!(
                reader.0.load(Ordering::SeqCst) > 0,
                "the reader was not woken at failure"
            );
            assert!(
                writer.0.load(Ordering::SeqCst) > 0,
                "the writer was not woken at failure"
            );

            drop(duplex);
            cleanup.release();
            cleanup
                .shutdown()
                .expect("the peer did not terminate after the retained-rekey failure");
            return;
        }

        tokio::time::timeout(BOUND, async {
            loop {
                {
                    let state = duplex.shared.lock().unwrap();
                    if state.established.data_active() && state.established.reply_queued() {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect(
            "inconclusive: the pump did not read one event and retain one reply behind the \
             blocked packet",
        );

        {
            let state = duplex.shared.lock().unwrap();
            assert!(
                state.established.data_active(),
                "the data packet completed: the real socket did not stay saturated"
            );
            assert!(
                state.established.reply_queued(),
                "the pump did not retain a FIFO reply"
            );
            assert!(
                state.inbound.bytes.is_empty(),
                "the peer sent application data this fixture did not expect"
            );
            assert!(
                state.outbound.is_empty(),
                "the application admission slot still holds bytes"
            );
            assert_eq!(state.established.pending_peer_opens(), 0);
            assert!(!state.established.rekey_active());
            // The peer wrote eight reply-requiring events. Full capacity must
            // stop reads nonfatally. Only the pump's consumption is observed,
            // not where the remaining encrypted bytes are buffered.
            //
            // The fail-closed variant deliberately lets the bound expire, so
            // its failure is expected here; the other variants must not fail.
            assert!(
                end == RealPressureEnd::FailClosed || state.failure.is_none(),
                "the pump failed while the reply FIFO was full: {:?}",
                state.failure
            );
        }
        let written = bytes_written.load(Ordering::SeqCst) - baseline_written;
        assert!(
            written > 0,
            "the protected packet wrote nothing to the real socket"
        );

        // A sample, not a proof: 128 yields show the pump did not spin during
        // this window. It says nothing about arbitrary durations, CPU, or
        // memory bounds.
        let before = duplex.shared.lock().unwrap().pump_calls;
        for _ in 0..128 {
            tokio::task::yield_now().await;
        }
        let after = duplex.shared.lock().unwrap().pump_calls;
        assert!(
            after.saturating_sub(before) <= 2,
            "the pump kept running while the reply FIFO and the real socket were blocked"
        );

        if end == RealPressureEnd::Cancel {
            // Cancel while the pump is inside the armed write-stall wait, not
            // before it armed. Otherwise the test would not cover the timed
            // path.
            tokio::time::timeout(BOUND, async {
                loop {
                    if duplex
                        .shared
                        .lock()
                        .unwrap()
                        .reply_stall
                        .armed_at()
                        .is_some()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the pump did not arm the write-stall bound before cancellation");
            let waker = futures_util::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            let mut flush = Box::pin(duplex.flush());
            assert!(
                flush.as_mut().poll(&mut context).is_pending(),
                "flush reported success while the real SSH socket was blocked"
            );
            drop(flush);
            let control = duplex.control.clone();
            // Normal drop/cancel path. Moving the real pump handle out means
            // `Drop`'s abort targets the replacement, not the task under
            // observation. Observed here: the cancellation flag is set on
            // drop, the test does not explicitly abort the real handle, and
            // the real pump subsequently terminates. That is an observation,
            // not proof of what caused the exit (the drop also changes
            // ownership and the socket), and it does not exercise production
            // `Drop`'s abort of the real handle.
            let pump = std::mem::replace(&mut duplex.pump, tokio::spawn(async {}));
            drop(duplex);
            assert!(
                control.is_cancelled(),
                "dropping the duplex did not cancel the session"
            );
            let pump = tokio::time::timeout(Duration::from_secs(2), pump)
                .await
                .expect("the pump task did not terminate after the drop");
            assert!(
                pump.is_ok(),
                "the pump task panicked after the drop: {pump:?}"
            );
            cleanup.release();
            cleanup
                .shutdown()
                .expect("the peer did not terminate after cancellation");
            return;
        }

        if end == RealPressureEnd::FailClosed {
            // Wait for the pump's explicit arm point. The arm is set in the
            // same locked step that observes the non-escapable write, so a
            // failure before this point would be a different bug and must not
            // satisfy the test.
            tokio::time::timeout(BOUND, async {
                loop {
                    if duplex
                        .shared
                        .lock()
                        .unwrap()
                        .reply_stall
                        .armed_at()
                        .is_some()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the pump never armed the write-stall bound");
            {
                let state = duplex.shared.lock().unwrap();
                assert!(
                    !state.closed,
                    "the session failed before the bound was armed"
                );
                assert!(
                    state.failure.is_none(),
                    "the session failed at the arm point: {:?}",
                    state.failure
                );
                assert!(state.established.data_active());
                assert!(state.established.reply_outstanding());
            }
            let progress_at_arm = write_progress.load(Ordering::Relaxed);
            assert!(
                progress_at_arm > 0,
                "the real socket accepted no positive bytes before the stall"
            );

            // Wake the pump exactly as a polling application would, after the
            // arm and while the bound is open. A wakeup is not write progress.
            let notify = Arc::clone(&duplex.notify);
            let stop = Arc::new(AtomicBool::new(false));
            let stop_task = Arc::clone(&stop);
            let notifications = Arc::new(AtomicUsize::new(0));
            let notifications_task = Arc::clone(&notifications);
            let spam = tokio::spawn(async move {
                while !stop_task.load(Ordering::SeqCst) {
                    notify.notify_one();
                    notifications_task.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });

            // The peer has not read, so the write cannot drain. The pump must
            // end the session at the bound rather than park forever.
            tokio::time::timeout(BOUND, async {
                while !duplex.shared.lock().unwrap().closed {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the pump did not fail closed at the write-stall bound");
            stop.store(true, Ordering::SeqCst);
            spam.await.unwrap();
            assert!(
                notifications.load(Ordering::Relaxed) > 0,
                "the notification loop never ran while the bound was open"
            );

            let (armed_at, failed_at) = {
                let state = duplex.shared.lock().unwrap();
                let failure = state
                    .failure
                    .as_deref()
                    .expect("the pump closed without a diagnostic");
                assert!(
                    failure.contains(super::WRITE_STALL_MESSAGE),
                    "the failure was not the stable write-stall diagnostic: {failure}"
                );
                // The state that caused the bound is retained, not discarded:
                // the packet was never finished and the reply was never sent.
                assert!(state.established.data_active());
                assert!(state.established.reply_outstanding());
                assert!(
                    write_progress.load(Ordering::Relaxed) >= progress_at_arm,
                    "the socket write counter went backwards"
                );
                (
                    state
                        .reply_stall
                        .armed_at()
                        .expect("the session failed without an armed bound"),
                    state
                        .failed_at
                        .expect("the session failed without a recorded failure time"),
                )
            };
            // The timestamp is the one captured in `fail`, not a later
            // inspection: a delayed read would overstate the interval.
            let elapsed = failed_at.duration_since(armed_at);
            assert!(
                elapsed >= stall_bound,
                "the session failed before the bound: {elapsed:?} < {stall_bound:?}"
            );
            assert!(
                elapsed < stall_bound + Duration::from_secs(2),
                "the session did not fail within the bound and jitter: {elapsed:?}"
            );

            // Every application operation observes the same terminal failure
            // instead of reporting a clean end or hanging.
            let flush = tokio::time::timeout(BOUND, duplex.flush())
                .await
                .expect("flush hung after the bound")
                .expect_err("flush reported success after the session failed");
            let shutdown = tokio::time::timeout(BOUND, duplex.shutdown())
                .await
                .expect("shutdown hung after the bound")
                .expect_err("shutdown reported success after the session failed");
            assert!(
                flush.to_string().contains(super::WRITE_STALL_MESSAGE),
                "flush hid the write-stall diagnostic: {flush}"
            );
            assert_eq!(shutdown.to_string(), flush.to_string());
            let mut byte = [0_u8; 1];
            let read = tokio::time::timeout(BOUND, duplex.read(&mut byte))
                .await
                .expect("read hung after the bound")
                .expect_err("read reported a clean end after the session failed");
            assert!(
                read.to_string().contains(super::WRITE_STALL_MESSAGE),
                "read hid the write-stall diagnostic: {read}"
            );

            // Carry the real pump's terminal I/O error through a public Engine
            // route and its operation-specific withholding wrapper. The open
            // factory does not manufacture a marker; it hands over this session.
            let slot = Arc::new(std::sync::Mutex::new(Some(duplex)));
            let open = crate::raw::StreamFactory::from_fn(move || {
                let duplex = slot.lock().unwrap().take().expect("one request");
                async move { Ok(Box::new(duplex) as Box<dyn crate::raw::Duplex>) }
            })
            .with_managed_ssh_policy();
            let engine = crate::raw::RawEngine::new(
                crate::raw::RawTarget::Stream {
                    authority: "fixture".to_owned(),
                    open,
                },
                crate::API_VERSION,
            );
            let error =
                crate::raw::plugin_set(&engine, "fixture", &[format!("TOKEN={RESPONSE_CANARY}")])
                    .await
                    .expect_err("failed session accepted a public request");
            assert_timeout_kind(
                &error,
                crate::TransportTimeoutKind::ManagedSshWriteInactivity,
            );
            assert!(!format!("{error:?}").contains(RESPONSE_CANARY));
            cleanup.release();
            let outcome = tokio::time::timeout(BOUND, outcome)
                .await
                .expect("the peer did not finish after the failed session")
                .expect("the peer ended without an outcome");
            cleanup
                .shutdown()
                .expect("the peer did not terminate after the failed session");
            // Count what the peer actually dispatched, not a four-reply
            // aggregate: a single dispatched reply event would already
            // contradict the blocked write. This is a dispatch observation,
            // not proof about bytes on the wire.
            assert_eq!(
                observed_replies.load(Ordering::SeqCst),
                0,
                "the peer dispatched a reply event after the session failed closed"
            );
            match outcome {
                PeerOutcome::Completed(transcript) => assert!(
                    !transcript
                        .iter()
                        .any(|record| matches!(record, PeerRecord::Reply)),
                    "the peer dispatched a reply event that never read: {transcript:?}"
                ),
                // A peer that withholds reads until the client closes observes
                // a truncated or reset transport rather than a transcript.
                PeerOutcome::Failed { .. } | PeerOutcome::Aborted => {}
            }
            return;
        }

        // Release the peer. Its reads free the send buffer, so the active
        // packet completes, the retained reply is written, and the remaining
        // reply-requiring events are read one at a time and answered.
        cleanup.release();
        tokio::time::timeout(BOUND, replies)
            .await
            .expect("inconclusive: the peer did not receive the retained replies")
            .unwrap();

        tokio::time::timeout(BOUND, duplex.write_all(&later))
            .await
            .expect("inconclusive: the later application write timed out")
            .unwrap();

        tokio::time::timeout(BOUND, duplex.shutdown())
            .await
            .expect("inconclusive: shutdown did not complete")
            .unwrap();

        let outcome = tokio::time::timeout(BOUND, outcome)
            .await
            .expect("inconclusive: the peer did not report a completed transcript")
            .expect("inconclusive: the peer ended without an outcome");
        cleanup
            .shutdown()
            .expect("the peer did not terminate after the completed transcript");
        let mut expected = vec![PeerRecord::Data(payload.clone())];
        expected.extend(std::iter::repeat_n(PeerRecord::Reply, EVENTS));
        expected.push(PeerRecord::Data(later.clone()));
        expected.push(PeerRecord::Eof);
        match outcome {
            PeerOutcome::Completed(transcript) => assert_eq!(
                transcript, expected,
                "the data packet, retained replies, later data, and EOF were not observed once, in order"
            ),
            PeerOutcome::Failed {
                stage,
                detail,
                error,
                observation,
            } => panic!(
                "the peer failed ({stage}) instead of completing: {detail}; \
                 error={error:?} observation={observation:?}"
            ),
            PeerOutcome::Aborted => panic!("the peer aborted before completion"),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One peer checks ordering through data, credit, reply, and EOF.
    fn partial_write_then_different_shorter_write_preserves_the_transcript() {
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::Mutex;
        use std::sync::mpsc;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [119; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (transcript_tx, transcript_rx) = mpsc::channel();
        let (request_tx, request_rx) = mpsc::channel();
        let (behind_tx, behind_rx) = mpsc::channel();
        let big = vec![b'A'; 1_024];
        let short = b"shorter".to_vec();
        let expected = big.len() + short.len();
        let server = std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut transport = neotales_ssh::server::ServerConfig::new(signer)
                .connect(peer)
                .unwrap();
            let policy = neotales_ssh::auth::ServerAuthPolicy::new(2)
                .unwrap()
                .with_password_callback(|_| true);
            neotales_ssh::auth::authenticate_server(&mut transport, &policy).unwrap();
            let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
            let session = confirm_peer_session(&mut connection);
            accept_exec(&mut connection, session);
            request_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            connection
                .transport_mut()
                .write_payload(&global_request(true))
                .unwrap();
            connection.write_data(session, b"x").unwrap();
            behind_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            connection.write_data(session, b"y").unwrap();
            connection
                .transport_mut()
                .write_payload(&global_request(true))
                .unwrap();
            connection.write_data(session, b"z").unwrap();
            let mut received = Vec::new();
            let mut failures = 0;
            let mut adjustments = 0;
            while received.len() < expected {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Data { data, .. } => received.extend_from_slice(&data),
                    ChannelEvent::GlobalRequestFailed { .. } => failures += 1,
                    ChannelEvent::WindowAdjusted { .. } => adjustments += 1,
                    ChannelEvent::Eof { .. } | ChannelEvent::Close { .. } => break,
                    _ => {}
                }
            }
            assert_eq!(failures, 2);
            assert_eq!(adjustments, 1);
            transcript_tx.send(received).unwrap();
            assert!(matches!(
                connection.dispatch_one(),
                Ok(ChannelEvent::Eof { .. })
            ));
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let gate = Arc::new(Mutex::new(Gate { block_after: None }));
        let gated = GatedSocket {
            socket,
            gate: Arc::clone(&gate),
        };
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(gated, |_| Ok::<(), ()>(()))
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let mut parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();

        // Force a partial write of the next admitted packet.
        gate.lock().unwrap().block_after = Some(1);

        // Admission accepts the whole buffer and returns its length even when
        // the socket stops after one byte of the owned packet.
        assert!(matches!(
            parts.write(&big),
            Ok(super::Progress::Wrote(count)) if count == big.len()
        ));
        assert!(matches!(
            parts.complete_outbound(),
            Ok(Some(super::BlockedOn::Write))
        ));
        assert!(matches!(parts.active, super::Active::Data { .. }));
        request_tx.send(()).unwrap();
        assert!(matches!(
            parts.dispatch(),
            Ok(super::Progress::Blocked(super::BlockedOn::Write))
        ));
        assert!(matches!(parts.active, super::Active::Data { .. }));
        assert_eq!(
            parts.replies.front(),
            Some(&super::OwedReply::GlobalFailure)
        );
        assert_eq!(parts.replies.len(), 1);

        // Cancellation: the admitted packet stays owned. A different, shorter
        // buffer must finish it first and be reported as its own length.
        gate.lock().unwrap().block_after = None;
        assert!(parts.complete_outbound().unwrap().is_none());
        assert!(matches!(
            parts.active,
            super::Active::ReplyQueued(super::OwedReply::GlobalFailure)
        ));
        gate.lock().unwrap().block_after = Some(1);
        assert!(matches!(parts.settle(), Ok(Some(super::BlockedOn::Write))));
        assert!(matches!(
            parts.active,
            super::Active::ReplyWriting(super::OwedReply::GlobalFailure)
        ));
        gate.lock().unwrap().block_after = None;
        assert!(parts.settle().unwrap().is_none());
        assert!(matches!(parts.active, super::Active::None));
        assert!(parts.replies.is_empty());
        assert!(matches!(parts.dispatch(), Ok(super::Progress::Data(ref bytes)) if bytes == b"x"));
        parts.credit(1);
        gate.lock().unwrap().block_after = Some(1);
        assert!(matches!(
            parts.flush_credit(),
            Ok(Some(super::BlockedOn::Write))
        ));
        assert!(matches!(parts.active, super::Active::Adjustment { .. }));
        assert_eq!(parts.pending_grant, 0);
        behind_tx.send(()).unwrap();
        assert!(parts.can_read_behind_active());
        assert!(matches!(
            parts.read_one_behind_active(),
            Ok(super::Progress::Data(ref bytes)) if bytes == b"y"
        ));
        assert!(matches!(
            parts.read_one_behind_active(),
            Ok(super::Progress::Moved)
        ));
        assert_eq!(
            parts.replies.front(),
            Some(&super::OwedReply::GlobalFailure)
        );
        assert!(parts.can_read_behind_active());
        gate.lock().unwrap().block_after = None;
        assert!(parts.flush_credit().unwrap().is_none());
        assert!(matches!(parts.active, super::Active::None));
        assert!(matches!(parts.dispatch(), Ok(super::Progress::Data(ref bytes)) if bytes == b"z"));
        assert!(matches!(
            parts.write(&short),
            Ok(super::Progress::Wrote(count)) if count == short.len()
        ));
        assert!(parts.complete_outbound().unwrap().is_none());
        gate.lock().unwrap().block_after = Some(1);
        assert!(matches!(
            parts.shutdown(),
            Ok(super::Progress::Blocked(super::BlockedOn::Write))
        ));
        assert!(matches!(parts.active, super::Active::Eof { .. }));
        gate.lock().unwrap().block_after = None;
        assert!(matches!(parts.shutdown(), Ok(super::Progress::Moved)));
        assert!(matches!(parts.active, super::Active::None));
        drop(parts);

        let received = transcript_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received.len(), expected);
        assert_eq!(&received[..big.len()], big.as_slice());
        assert_eq!(&received[big.len()..], short.as_slice());
        server.join().unwrap();
    }

    /// Whole-packet grants stop at the actual protected-write boundary, even
    /// if the underlying TCP write is short. No packet length is guessed.
    #[derive(Default)]
    struct FrontGate {
        enabled: bool,
        bytes: usize,
        packets: usize,
        fatal: bool,
    }
    struct FrontSocket {
        ssh: std::net::TcpStream,
        gate: Arc<std::sync::Mutex<FrontGate>>,
        reads: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        dropped: Arc<tokio::sync::Notify>,
        control: crate::ssh_cancellation::EstablishmentControl,
    }
    impl Drop for FrontSocket {
        fn drop(&mut self) {
            self.dropped.notify_one();
        }
    }
    impl std::io::Read for FrontSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let control = self.control.clone();
            control
                .try_session_effect(|| {
                    self.reads.fetch_add(1, Ordering::SeqCst);
                    std::io::Read::read(&mut self.ssh, bytes)
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }
    }
    impl std::io::Write for FrontSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let control = self.control.clone();
            control
                .try_session_effect(|| {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                    let mut gate = self.gate.lock().unwrap();
                    if !gate.enabled {
                        return std::io::Write::write(&mut self.ssh, bytes);
                    }
                    if gate.fatal {
                        return Err(std::io::ErrorKind::BrokenPipe.into());
                    }
                    let length = if gate.packets > 0 {
                        bytes.len()
                    } else {
                        bytes.len().min(gate.bytes)
                    };
                    if length == 0 {
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    let count = std::io::Write::write(&mut self.ssh, &bytes[..length])?;
                    if gate.packets > 0 {
                        if count == bytes.len() {
                            gate.packets -= 1;
                        }
                    } else {
                        gate.bytes -= count;
                    }
                    Ok(count)
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.control
                .clone()
                .try_session_effect(|| std::io::Write::flush(&mut self.ssh))
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }
    }
    type FrontDuplex = super::SessionDuplex<super::Socket<FrontSocket>>;
    struct FrontFixture {
        duplex: Option<FrontDuplex>,
        gate: Arc<std::sync::Mutex<FrontGate>>,
        progress: Arc<AtomicU64>,
        reads: Arc<AtomicUsize>,
        writes: Arc<AtomicUsize>,
        send: std::sync::mpsc::Sender<()>,
        action: std::sync::mpsc::Sender<u8>,
        sent: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::Sender<()>,
        peer: Option<std::thread::JoinHandle<()>>,
        shutdown: std::net::TcpStream,
        probe_peer: std::net::TcpStream,
        dropped: Arc<tokio::sync::Notify>,
        readiness: Arc<tokio::net::TcpStream>,
    }
    impl Drop for FrontFixture {
        fn drop(&mut self) {
            let _ = self.send.send(());
            let _ = self.action.send(0);
            let _ = self.release.send(());
            drop(self.duplex.take());
            let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
            if let Some(peer) = self.peer.take() {
                let _ = peer.join();
            }
        }
    }
    #[allow(clippy::too_many_lines)] // Shared bounded peer/real-pump fixture for the three transition regressions.
    fn front_fixture(bound: Duration, with_eof: bool) -> FrontFixture {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [135; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (start, receive) = std::sync::mpsc::channel();
        let (action, action_rx) = std::sync::mpsc::channel();
        let (sent_tx, sent) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let peer = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            receive.recv_timeout(Duration::from_secs(5)).unwrap();
            if with_eof {
                connection.send_eof(session).unwrap();
            }
            // The ninth request is already readable when capacity fills.
            for _ in 0..=super::REPLY_CAPACITY {
                connection
                    .transport_mut()
                    .write_payload(&global_request(true))
                    .unwrap();
            }
            sent_tx.send(()).unwrap();
            match action_rx.recv_timeout(Duration::from_secs(5)).unwrap_or(0) {
                1 => {
                    connection.transport_mut().begin_rekey().unwrap();
                    sent_tx.send(()).unwrap();
                }
                2 => {
                    for _ in 0..=super::REPLY_CAPACITY {
                        assert!(matches!(
                            connection.dispatch_one().unwrap(),
                            neotales_ssh::channel::ChannelEvent::GlobalRequestFailed { .. }
                        ));
                    }
                    assert!(matches!(
                        connection.dispatch_one().unwrap(),
                        neotales_ssh::channel::ChannelEvent::Eof { .. }
                    ));
                    sent_tx.send(()).unwrap();
                }
                _ => {}
            }
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let shutdown = socket.try_clone().unwrap();
        let control = crate::ssh_cancellation::EstablishmentControl::new(
            std::time::Instant::now() + Duration::from_secs(5),
        );
        let crate::ssh_connect::Dialed { guard, .. } = crate::ssh_connect::Dialed::test_connected(
            socket.try_clone().unwrap(),
            control.clone(),
        )
        .unwrap();
        let gate = Arc::new(std::sync::Mutex::new(FrontGate::default()));
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let progress = new_write_progress();
        let dropped = Arc::new(tokio::sync::Notify::new());
        let read_slot = Arc::new(std::sync::OnceLock::new());
        let write_slot = Arc::new(std::sync::OnceLock::new());
        let would_block = WouldBlock::default();
        let transport = neotales_ssh::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: FrontSocket {
                        ssh: socket.try_clone().unwrap(),
                        gate: Arc::clone(&gate),
                        reads: Arc::clone(&reads),
                        writes: Arc::clone(&writes),
                        dropped: Arc::clone(&dropped),
                        control: control.clone(),
                    },
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&read_slot),
                    write_readiness: Arc::clone(&write_slot),
                    write_progress: Arc::clone(&progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();
        socket.set_nonblocking(true).unwrap();
        let read_readiness = Arc::new(tokio::net::TcpStream::from_std(socket).unwrap());
        read_slot.set(Arc::clone(&read_readiness)).unwrap();
        let (probe, probe_peer) = filled_write_probe();
        let write_readiness = Arc::new(tokio::net::TcpStream::from_std(probe).unwrap());
        // The pump waits on a real probe, while packet grants control writes.
        // Leaving the adapter's write slot empty lets explicit notifications
        // apply a grant without claiming the full probe became writable.
        *gate.lock().unwrap() = FrontGate {
            enabled: true,
            bytes: 1,
            ..FrontGate::default()
        };
        let duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&read_readiness),
            write_readiness,
            Arc::clone(&progress),
            bound,
        );
        FrontFixture {
            duplex: Some(duplex),
            gate,
            progress,
            reads,
            writes,
            send: start,
            action,
            sent,
            release,
            peer: Some(peer),
            shutdown,
            probe_peer,
            dropped,
            readiness: read_readiness,
        }
    }
    async fn front_observation(
        duplex: &FrontDuplex,
        events: &tokio::sync::Notify,
        supervisor: &PumpDeadlineSupervisor,
        predicate: impl Fn(&super::SharedDriver<super::Socket<FrontSocket>>) -> bool,
    ) {
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        loop {
            if predicate(&duplex.shared.lock().unwrap()) {
                break;
            }
            if !await_pump_event(events, &deadline).await {
                let state = duplex.shared.lock().unwrap();
                panic!(
                    "pump transition timed out: seq={} reply={} rekey={} can_read={} arm={:?} observed={:?} calls={} closed={} failure={:?}",
                    state.established.committed_outbound_sequence(),
                    state.established.reply_outstanding(),
                    state.established.rekey_active(),
                    state.established.can_read_behind_active(),
                    state.reply_stall.armed_at(),
                    state.reply_stall.last_observed_at(),
                    state.pump_calls,
                    state.closed,
                    state.failure
                );
            }
        }
        supervisor.cancel_deadline();
    }

    fn stall_identity(duplex: &FrontDuplex) -> (usize, usize, Option<tokio::time::Instant>) {
        let state = duplex.shared.lock().unwrap();
        (
            state.reply_stall.arm_count,
            state.reply_stall.positive_restarts,
            state.reply_stall.armed_at(),
        )
    }

    /// Completing a front necessarily writes bytes and restarts the arm.
    /// Later zero-byte waits must preserve that latest arm, including while
    /// retained rekey starts. Exercise the actual pump and timer expiry.
    /// New-arm counts distinguish one-time clears from valid byte restarts.
    /// At capacity KEXINIT cannot be consumed without a completed front; a
    /// front cannot complete without its remaining ciphertext being written.
    /// The assertions prove those positive-write constraints rather than
    /// inventing a zero-byte completion/retention transition.
    #[tokio::test(start_paused = true)]
    async fn eof_and_a_following_rekey_do_not_clear_the_reply_stall_state() {
        if !pressure_child_or_supervise(
            "eof_and_a_following_rekey_do_not_clear_the_reply_stall_state",
        ) {
            return;
        }
        eof_and_a_following_rekey_do_not_clear_the_reply_stall_state_body().await;
    }

    #[allow(clippy::too_many_lines)] // Observe each real write/front/rekey/timer boundary independently.
    async fn eof_and_a_following_rekey_do_not_clear_the_reply_stall_state_body() {
        let bound = Duration::from_millis(300);
        let fixture = front_fixture(bound, true);
        let duplex = fixture.duplex.as_ref().unwrap();
        let supervisor = PumpDeadlineSupervisor::start().await;
        let events = Arc::new(tokio::sync::Notify::new());
        duplex.shared.lock().unwrap().pump_events = Some(Arc::clone(&events));
        let baseline = duplex
            .shared
            .lock()
            .unwrap()
            .established
            .committed_outbound_sequence();
        let progress = fixture.progress.load(Ordering::SeqCst);
        fixture.send.send(()).unwrap();
        fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.reply_stall.armed_at().is_some()
        })
        .await;
        let first = duplex
            .shared
            .lock()
            .unwrap()
            .reply_stall
            .armed_at()
            .unwrap();
        assert_eq!(
            fixture.progress.load(Ordering::SeqCst),
            progress + 1,
            "front is not partial"
        );
        assert!(duplex.shared.lock().unwrap().remote_eof);
        let (first_arms, first_restarts, _) = stall_identity(duplex);
        assert_eq!(first_arms, 1);

        // Finish exactly one front. The buffered ninth request refills the
        // FIFO, so the writer remains non-escapable without any new read edge.
        tokio::time::advance(Duration::from_millis(20)).await;
        let front_at = tokio::time::Instant::now();
        assert!(front_at > first);
        fixture.gate.lock().unwrap().packets = 1;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.established.committed_outbound_sequence() == baseline + 1
                && state
                    .reply_stall
                    .last_observed_at()
                    .is_some_and(|at| at >= front_at)
        })
        .await;
        assert!(
            fixture.progress.load(Ordering::SeqCst) > progress + 1,
            "front completion must write its remaining bytes"
        );
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "front transition created a new arm"
        );
        assert_eq!(
            stall_identity(duplex).1,
            first_restarts + 1,
            "front bytes must restart the existing arm"
        );
        assert_eq!(
            stall_identity(duplex).2,
            Some(front_at),
            "front restart must be caused by these bytes"
        );
        let front_arm = front_at;
        let written = fixture.progress.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(20)).await;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state
                .reply_stall
                .last_observed_at()
                .is_some_and(|at| at > front_arm)
        })
        .await;
        assert_eq!(fixture.progress.load(Ordering::SeqCst), written);
        assert_eq!(
            duplex.shared.lock().unwrap().reply_stall.armed_at(),
            Some(front_arm)
        );
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "zero-byte front wait re-armed"
        );
        assert_eq!(stall_identity(duplex).1, first_restarts + 1);

        // Seven more replies finish; the last front is blocked while the peer
        // KEXINIT becomes retained. Only actual bytes may renew the arm.
        fixture.action.send(1).unwrap();
        fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
        // No slot has freed yet. A zero-byte wake may not consume KEXINIT.
        let read_calls = fixture.reads.load(Ordering::SeqCst);
        let calls = duplex.shared.lock().unwrap().pump_calls;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.pump_calls > calls
        })
        .await;
        assert_eq!(fixture.reads.load(Ordering::SeqCst), read_calls);
        assert!(!duplex.shared.lock().unwrap().established.rekey_active());
        assert_eq!(
            stall_identity(duplex),
            (first_arms, first_restarts + 1, Some(front_arm))
        );
        let retained_at = tokio::time::Instant::now();
        let before_retained = fixture.progress.load(Ordering::SeqCst);
        fixture.gate.lock().unwrap().packets = 7;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.established.rekey_active()
                && state.established.committed_outbound_sequence() == baseline + 8
                && state
                    .reply_stall
                    .last_observed_at()
                    .is_some_and(|at| at >= retained_at)
        })
        .await;
        assert!(
            fixture.progress.load(Ordering::SeqCst) > before_retained,
            "making room for KEXINIT must write older replies"
        );
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "retained KEXINIT created a new arm"
        );
        assert_eq!(stall_identity(duplex).1, first_restarts + 2);
        assert_eq!(stall_identity(duplex).2, Some(retained_at));
        let retained_arm = retained_at;
        let written = fixture.progress.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(20)).await;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state
                .reply_stall
                .last_observed_at()
                .is_some_and(|at| at > retained_arm)
        })
        .await;
        assert_eq!(fixture.progress.load(Ordering::SeqCst), written);
        assert_eq!(
            duplex.shared.lock().unwrap().reply_stall.armed_at(),
            Some(retained_arm)
        );
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "zero-byte retained wait re-armed"
        );
        assert_eq!(stall_identity(duplex).1, first_restarts + 2);

        // Finish the final reply, then block local KEXINIT before any byte.
        tokio::time::advance(Duration::from_millis(20)).await;
        let rekey_at = tokio::time::Instant::now();
        fixture.gate.lock().unwrap().packets = 1;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            !state.established.reply_outstanding()
                && state.established.rekey_active()
                && state
                    .reply_stall
                    .last_observed_at()
                    .is_some_and(|at| at >= rekey_at)
        })
        .await;
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "local KEXINIT transition created a new arm"
        );
        assert_eq!(stall_identity(duplex).1, first_restarts + 3);
        assert_eq!(stall_identity(duplex).2, Some(rekey_at));
        let rekey_arm = rekey_at;
        let written = fixture.progress.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(20)).await;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state
                .reply_stall
                .last_observed_at()
                .is_some_and(|at| at > rekey_arm)
        })
        .await;
        assert_eq!(fixture.progress.load(Ordering::SeqCst), written);
        assert_eq!(
            duplex.shared.lock().unwrap().reply_stall.armed_at(),
            Some(rekey_arm)
        );
        assert_eq!(
            stall_identity(duplex).0,
            first_arms,
            "zero-byte KEXINIT retry re-armed"
        );
        assert_eq!(stall_identity(duplex).1, first_restarts + 3);
        // Expire against the pre-retry positive-write deadline, not against a
        // timestamp recaptured after an illicit transition-only re-arm.
        let original_deadline = rekey_at + bound;
        tokio::time::advance(
            original_deadline - tokio::time::Instant::now() + Duration::from_millis(1),
        )
        .await;
        front_observation(duplex, &events, &supervisor, |state| state.closed).await;
        {
            let state = duplex.shared.lock().unwrap();
            assert!(
                state
                    .failure
                    .as_deref()
                    .unwrap()
                    .contains(super::WRITE_STALL_MESSAGE)
            );
            assert!(state.failed_at.unwrap() >= original_deadline);
            assert!(state.failed_at.unwrap() <= original_deadline + Duration::from_millis(1));
        }
        drop(fixture);
        supervisor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn full_fifo_wakes_on_write_and_reads_buffered_ninth_without_new_read_edge() {
        use std::io::Read as _;
        use tokio::io::AsyncWriteExt as _;
        let mut fixture = front_fixture(Duration::from_secs(1), true);
        let duplex = fixture.duplex.as_ref().unwrap();
        let supervisor = PumpDeadlineSupervisor::start().await;
        let events = Arc::new(tokio::sync::Notify::new());
        duplex.shared.lock().unwrap().pump_events = Some(Arc::clone(&events));
        let sequence = duplex
            .shared
            .lock()
            .unwrap()
            .established
            .committed_outbound_sequence();
        fixture.send.send(()).unwrap();
        fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.reply_stall.armed_at().is_some()
        })
        .await;
        assert_eq!(
            duplex
                .shared
                .lock()
                .unwrap()
                .established
                .committed_outbound_sequence(),
            sequence
        );
        let reads = fixture.reads.load(Ordering::SeqCst);
        let calls = duplex.shared.lock().unwrap().pump_calls;
        duplex.notify.notify_one();
        front_observation(duplex, &events, &supervisor, |state| {
            state.pump_calls > calls
        })
        .await;
        assert_eq!(
            fixture.reads.load(Ordering::SeqCst),
            reads,
            "capacity refusal performed I/O"
        );
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        tokio::select! {
            result = fixture.readiness.readable() => result.unwrap(),
            () = deadline.notified() => panic!("buffered ninth request was not readable"),
        }
        supervisor.cancel_deadline();
        assert_eq!(fixture.shutdown.peek(&mut [0]).unwrap(), 1);
        fixture.gate.lock().unwrap().packets = super::REPLY_CAPACITY + 1;
        fixture.probe_peer.set_nonblocking(true).unwrap();
        let mut bytes = vec![0; 64 * 1024];
        let mut drained = 0;
        for _ in 0..1024 {
            match fixture.probe_peer.read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => drained += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("probe drain failed: {error}"),
            }
        }
        assert!(drained > 0);
        // No application notification and no peer write: only the probe's
        // write-ready edge can resume the pump. Request nine was buffered above.
        front_observation(duplex, &events, &supervisor, |state| {
            state.established.committed_outbound_sequence() == sequence + 9
                && !state.established.reply_outstanding()
        })
        .await;
        assert!(fixture.reads.load(Ordering::SeqCst) > reads);
        fixture.gate.lock().unwrap().packets = 1;
        fixture.action.send(2).unwrap();
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        tokio::select! {
            result = fixture.duplex.as_mut().unwrap().shutdown() => result.unwrap(),
            () = deadline.notified() => panic!("shutdown did not complete after FIFO drain"),
        }
        supervisor.cancel_deadline();
        fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
        fixture.release.send(()).unwrap();
        fixture.peer.take().unwrap().join().unwrap();
        drop(fixture);
        supervisor.finish().await;
    }

    #[tokio::test(start_paused = true)]
    async fn partial_reply_and_full_fifo_are_terminal_on_failure_or_cancellation() {
        use std::task::{Context, Poll, Waker};
        use tokio::io::{AsyncRead as _, AsyncWrite as _, AsyncWriteExt as _};
        for fatal in [false, true] {
            let mut fixture = front_fixture(Duration::from_secs(1), false);
            let duplex = fixture.duplex.as_mut().unwrap();
            let supervisor = PumpDeadlineSupervisor::start().await;
            let events = Arc::new(tokio::sync::Notify::new());
            duplex.shared.lock().unwrap().pump_events = Some(Arc::clone(&events));
            let before = fixture.progress.load(Ordering::SeqCst);
            fixture.send.send(()).unwrap();
            fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
            duplex.notify.notify_one();
            front_observation(duplex, &events, &supervisor, |state| {
                state.reply_stall.armed_at().is_some()
            })
            .await;
            {
                let state = duplex.shared.lock().unwrap();
                assert!(state.established.global_reply_writing());
                assert!(!state.established.can_read_behind_active());
                assert!(state.established.reply_queued());
            }
            assert_eq!(
                fixture.progress.load(Ordering::SeqCst),
                before + 1,
                "front must be partial"
            );
            let reader = Arc::new(CountWake(AtomicUsize::new(0)));
            let writer = Arc::new(CountWake(AtomicUsize::new(0)));
            let read_waker = Waker::from(Arc::clone(&reader));
            let write_waker = Waker::from(Arc::clone(&writer));
            let mut bytes = [0];
            let mut buffer = tokio::io::ReadBuf::new(&mut bytes);
            assert!(matches!(
                std::pin::Pin::new(&mut *duplex)
                    .poll_read(&mut Context::from_waker(&read_waker), &mut buffer),
                Poll::Pending
            ));
            assert!(
                std::pin::Pin::new(&mut *duplex)
                    .poll_flush(&mut Context::from_waker(&write_waker))
                    .is_pending()
            );
            assert!(
                std::pin::Pin::new(&mut *duplex)
                    .poll_shutdown(&mut Context::from_waker(&write_waker))
                    .is_pending()
            );
            if fatal {
                fixture.gate.lock().unwrap().fatal = true;
                duplex.notify.notify_one();
                front_observation(duplex, &events, &supervisor, |state| state.closed).await;
                assert!(reader.0.load(Ordering::SeqCst) > 0);
                assert!(writer.0.load(Ordering::SeqCst) > 0);
                let reads = fixture.reads.load(Ordering::SeqCst);
                let write_calls = fixture.writes.load(Ordering::SeqCst);
                assert!(duplex.flush().await.is_err());
                assert!(duplex.shutdown().await.is_err());
                assert!(matches!(
                    duplex.shared.lock().unwrap().pump_step(),
                    super::PumpAction::Closed
                ));
                assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
                assert_eq!(fixture.writes.load(Ordering::SeqCst), write_calls);
            } else {
                let reads = fixture.reads.load(Ordering::SeqCst);
                let write_calls = fixture.writes.load(Ordering::SeqCst);
                let control = duplex.control.clone();
                drop(fixture.duplex.take()); // Normal Drop aborts the actual pump.
                assert!(control.is_cancelled());
                let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
                tokio::select! {
                    () = fixture.dropped.notified() => {},
                    () = deadline.notified() => panic!("cancelled pump retained the transport"),
                }
                supervisor.cancel_deadline();
                assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
                assert_eq!(fixture.writes.load(Ordering::SeqCst), write_calls);
            }
            drop(fixture);
            supervisor.finish().await;
        }
    }

    /// Retained application events are injected at the private application
    /// backpressure boundary, as in the retained-event credit test. Peer
    /// KEXINIT is authenticated through the actual owned read path.
    #[tokio::test(start_paused = true)]
    #[allow(clippy::too_many_lines)] // One matrix checks both retained owners and both terminal causes.
    async fn retained_event_and_peer_kexinit_are_dropped_on_cancel_or_fatal_io() {
        use std::task::{Context, Waker};
        use tokio::io::{AsyncWrite as _, AsyncWriteExt as _};
        for rekey in [false, true] {
            for cancel in [false, true] {
                let mut fixture = front_fixture(Duration::from_secs(1), false);
                let duplex = fixture.duplex.as_mut().unwrap();
                let supervisor = PumpDeadlineSupervisor::start().await;
                let events = Arc::new(tokio::sync::Notify::new());
                duplex.shared.lock().unwrap().pump_events = Some(Arc::clone(&events));
                let initial_sequence = duplex
                    .shared
                    .lock()
                    .unwrap()
                    .established
                    .committed_outbound_sequence();
                fixture.send.send(()).unwrap();
                fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
                duplex.notify.notify_one();
                front_observation(duplex, &events, &supervisor, |state| {
                    state.reply_stall.armed_at().is_some()
                })
                .await;
                assert!(
                    duplex
                        .shared
                        .lock()
                        .unwrap()
                        .established
                        .global_reply_writing()
                );
                assert!(
                    !duplex
                        .shared
                        .lock()
                        .unwrap()
                        .established
                        .can_read_behind_active()
                );
                if rekey {
                    fixture.action.send(1).unwrap();
                    fixture.sent.recv_timeout(Duration::from_secs(5)).unwrap();
                    {
                        let mut gate = fixture.gate.lock().unwrap();
                        gate.packets = 2;
                        gate.bytes = 1;
                    }
                    duplex.notify.notify_one();
                    front_observation(duplex, &events, &supervisor, |state| {
                        state.established.rekey_active()
                            && state.established.committed_outbound_sequence()
                                == initial_sequence + 2
                    })
                    .await;
                    assert_eq!(
                        fixture.gate.lock().unwrap().bytes,
                        0,
                        "new front must have a ciphertext prefix"
                    );
                    assert!(
                        duplex
                            .shared
                            .lock()
                            .unwrap()
                            .established
                            .global_reply_writing()
                    );
                    // KEXINIT cannot be admitted at capacity eight. Nine
                    // requests minus two completed replies leaves seven, the
                    // largest reachable FIFO alongside retained KEXINIT.
                    assert!(duplex.shared.lock().unwrap().established.reply_queued());
                } else {
                    let mut state = duplex.shared.lock().unwrap();
                    state
                        .inbound
                        .push(&vec![b'A'; super::INITIAL_CHANNEL_WINDOW as usize])
                        .unwrap();
                    assert!(
                        state
                            .handle_inbound(Ok(super::Progress::Data(b"undelivered".to_vec())))
                            .is_none()
                    );
                    assert_eq!(
                        state.retained_event.as_deref(),
                        Some(b"undelivered".as_slice())
                    );
                    assert_eq!(
                        state.established.committed_outbound_sequence(),
                        initial_sequence
                    );
                }
                let reader = Arc::new(CountWake(AtomicUsize::new(0)));
                let writer = Arc::new(CountWake(AtomicUsize::new(0)));
                let read_waker = Waker::from(Arc::clone(&reader));
                let write_waker = Waker::from(Arc::clone(&writer));
                // Register the undeliverable event's consumer explicitly: the
                // artificial full application buffer would otherwise return
                // already-buffered data, rather than register a pending read.
                duplex.shared.lock().unwrap().read_waker = Some(read_waker);
                assert!(
                    std::pin::Pin::new(&mut *duplex)
                        .poll_flush(&mut Context::from_waker(&write_waker))
                        .is_pending()
                );
                assert!(
                    std::pin::Pin::new(&mut *duplex)
                        .poll_shutdown(&mut Context::from_waker(&write_waker))
                        .is_pending()
                );
                let sequence = duplex
                    .shared
                    .lock()
                    .unwrap()
                    .established
                    .committed_outbound_sequence();
                let written = fixture.progress.load(Ordering::SeqCst);
                if cancel {
                    // Cancel a retained session, not an already-disposed
                    // future: the pump must report failure to both waiters.
                    duplex.control.request_cancel();
                } else {
                    fixture.gate.lock().unwrap().fatal = true;
                }
                duplex.notify.notify_one();
                front_observation(duplex, &events, &supervisor, |state| state.closed).await;
                assert!(reader.0.load(Ordering::SeqCst) > 0, "reader was not woken");
                assert!(writer.0.load(Ordering::SeqCst) > 0, "writer was not woken");
                assert_eq!(fixture.progress.load(Ordering::SeqCst), written);
                let read_calls = fixture.reads.load(Ordering::SeqCst);
                let write_calls = fixture.writes.load(Ordering::SeqCst);
                {
                    let mut state = duplex.shared.lock().unwrap();
                    assert!(
                        state.retained_event.is_none(),
                        "terminal event was retained"
                    );
                    assert!(
                        !state.established.rekey_active(),
                        "terminal KEXINIT was retained"
                    );
                    assert!(
                        !state.deliver_retained_event().unwrap(),
                        "terminal event resumed"
                    );
                    assert!(state.inbound.bytes.iter().all(|byte| *byte == b'A'));
                    assert_eq!(state.established.committed_outbound_sequence(), sequence);
                    assert!(matches!(state.pump_step(), super::PumpAction::Closed));
                }
                assert!(
                    duplex.flush().await.is_err(),
                    "terminal flush falsely succeeded"
                );
                assert!(
                    duplex.shutdown().await.is_err(),
                    "terminal shutdown falsely succeeded"
                );
                assert_eq!(fixture.reads.load(Ordering::SeqCst), read_calls);
                assert_eq!(fixture.writes.load(Ordering::SeqCst), write_calls);
                drop(fixture.duplex.take());
                let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
                tokio::select! {
                    () = fixture.dropped.notified() => {},
                    () = deadline.notified() => panic!("terminal retained transport was not dropped"),
                }
                supervisor.cancel_deadline();
                drop(fixture);
                supervisor.finish().await;
            }
        }
    }

    #[test]
    fn active_packet_transport_failure_is_terminal() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [120; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            assert!(connection.dispatch_one().is_err());
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        let shutdown = socket.try_clone().unwrap();
        let gate = Arc::new(std::sync::Mutex::new(Gate { block_after: None }));
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                GatedSocket {
                    socket,
                    gate: Arc::clone(&gate),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let mut parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        gate.lock().unwrap().block_after = Some(1);
        assert!(matches!(
            parts.write(b"payload"),
            Ok(super::Progress::Wrote(7))
        ));
        assert!(matches!(parts.active, super::Active::Data { .. }));
        shutdown.shutdown(std::net::Shutdown::Both).unwrap();
        gate.lock().unwrap().block_after = None;
        assert!(parts.complete_outbound().is_err());
        assert!(matches!(parts.active, super::Active::Data { .. }));
        assert!(parts.complete_outbound().is_err());
        drop(parts);
        server.join().unwrap();
    }

    // Cancellation coverage split: this test cancels a write that is still
    // queued in the admission slot. The partial-packet case -- a packet already
    // admitted to the driver and only partly written -- is covered by the
    // synchronous `partial_write_then_different_shorter_write_preserves_the_transcript`.
    #[tokio::test]
    async fn pending_write_cancellation_then_a_shorter_write_preserves_the_transcript() {
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::mpsc;
        use std::task::{Context, Poll};
        use tokio::io::AsyncWriteExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [126; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (transcript_tx, transcript_rx) = mpsc::channel();
        let big = vec![b'A'; 1_024];
        let second = vec![b'B'; 512];
        let short = b"short".to_vec();
        let expected = big.len() + short.len();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let mut received = Vec::new();
            while received.len() < expected {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Data { data, .. } => received.extend_from_slice(&data),
                    ChannelEvent::Eof { .. } | ChannelEvent::Close { .. } => break,
                    _ => {}
                }
            }
            transcript_tx.send(received).unwrap();
            let _ = connection.dispatch_one();
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();

        // Fill the single admission slot. This runtime is single-threaded and
        // the test does not await between these polls, so the pump cannot drain
        // the slot first.
        let mut first = Box::pin(duplex.write(&big));
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        match first.as_mut().poll(&mut context) {
            Poll::Ready(Ok(count)) => assert_eq!(count, big.len()),
            other => panic!("the first write did not enqueue: {other:?}"),
        }
        drop(first);

        // The slot is still occupied, so this write is genuinely Pending and
        // nothing from `second` is enqueued. Cancelling it must not later
        // attribute those bytes to a different buffer.
        let mut cancelled = Box::pin(duplex.write(&second));
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(cancelled);

        tokio::time::timeout(Duration::from_secs(5), duplex.write_all(&short))
            .await
            .expect("the short write did not complete")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), duplex.flush())
            .await
            .expect("the flush did not complete")
            .unwrap();
        let received = transcript_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received, [big, short].concat());
        drop(duplex);
        server.join().unwrap();
    }

    /// The admission slot copies the caller's bytes before the pump sends them,
    /// and one poll returns the accepted length exactly once.
    #[tokio::test]
    async fn admission_slot_copies_bytes_before_the_pump_sends() {
        use neotales_ssh::channel::ChannelEvent;
        use std::task::{Context, Poll};
        use tokio::io::AsyncWriteExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [129; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (transcript_tx, transcript_rx) = std::sync::mpsc::channel();
        let expected = b"original".to_vec();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let mut received = Vec::new();
            while received.len() < expected.len() {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Data { data, .. } => received.extend_from_slice(&data),
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("unexpected before data: {other:?}"),
                }
            }
            transcript_tx.send(received).unwrap();
            let _ = connection.dispatch_one();
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();
        let mut caller = b"original".to_vec();
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut write = Box::pin(duplex.write(&caller));
        match write.as_mut().poll(&mut context) {
            Poll::Ready(Ok(count)) => assert_eq!(count, caller.len()),
            other => panic!("the write did not enqueue: {other:?}"),
        }
        drop(write);

        // The slot owns a copy. Changing the caller's buffer now cannot change
        // what the pump later admits.
        caller.fill(b'X');
        duplex.flush().await.unwrap();
        let received = transcript_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(received, b"original");
        drop(duplex);
        server.join().unwrap();
    }

    /// A pending application write is woken and fails when the session closes,
    /// whether the peer sends a channel CLOSE or the transport disappears.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One controlled peer covers both close kinds.
    async fn pending_write_is_woken_and_fails_when_the_session_closes() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::atomic::AtomicUsize;
        use std::task::{Context, Poll, Wake, Waker};
        use std::time::Instant;
        use tokio::io::AsyncWriteExt as _;

        struct CountingWake {
            wakes: AtomicUsize,
            signal: tokio::sync::Notify,
        }

        impl Wake for CountingWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.wakes.fetch_add(1, Ordering::SeqCst);
                self.signal.notify_one();
            }
        }

        for abrupt in [false, true] {
            let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [128; 32]);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (_directory, options) = options_for_peer(address, &signer);
            let (window_full_tx, window_full_rx) = tokio::sync::oneshot::channel();
            let (close_tx, close_rx) = std::sync::mpsc::channel();
            let server = raw_peer(signer, listener, move |connection| {
                let session = confirm_peer_session(connection);
                accept_exec(connection, session);
                let mut received = 0;
                while received < super::INITIAL_CHANNEL_WINDOW as usize {
                    match connection.dispatch_one().unwrap() {
                        ChannelEvent::Data { data, .. } => received += data.len(),
                        ChannelEvent::WindowAdjusted { .. } => {}
                        other => panic!("unexpected while filling the window: {other:?}"),
                    }
                }
                assert_eq!(received, super::INITIAL_CHANNEL_WINDOW as usize);
                let _ = window_full_tx.send(());
                let _ = close_rx.recv_timeout(Duration::from_secs(5));
                if abrupt {
                    return;
                }
                connection.send_close(session).unwrap();
                for _ in 0..8 {
                    match connection.dispatch_one().unwrap() {
                        ChannelEvent::Close { channel } if channel == session => break,
                        ChannelEvent::WindowAdjusted { .. } => {}
                        other => panic!("unexpected after close: {other:?}"),
                    }
                }
            });

            let socket = std::net::TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let guard_socket = socket.try_clone().unwrap();
            let readiness_socket = socket.try_clone().unwrap();
            let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
            let Dialed { guard, .. } = Dialed::test_connected(guard_socket, control).unwrap();
            // Use the production readiness adapter. `Socket::try_io` clears
            // Tokio readiness when a read or write returns WouldBlock, so a
            // partial close read parks instead of spinning the pump.
            let would_block = WouldBlock::default();
            let readiness_slot = Arc::new(std::sync::OnceLock::new());
            let write_progress = new_write_progress();
            let transport = neotales_ssh::client::ClientConfig::new()
                .connect(
                    super::Socket {
                        inner: socket,
                        would_block: Arc::clone(&would_block.0),
                        read_readiness: Arc::clone(&readiness_slot),
                        write_readiness: Arc::clone(&readiness_slot),
                        write_progress: Arc::clone(&write_progress),
                    },
                    |_| Ok::<(), ()>(()),
                )
                .unwrap();
            let methods = super::auth_methods(&options.identity).unwrap();
            let parts =
                super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();
            readiness_socket.set_nonblocking(true).unwrap();
            let readiness = Arc::new(tokio::net::TcpStream::from_std(readiness_socket).unwrap());
            readiness_slot.set(Arc::clone(&readiness)).unwrap();
            let mut duplex = gated_duplex(
                parts,
                guard,
                Arc::clone(&readiness),
                readiness,
                write_progress,
                super::WRITE_STALL_BOUND,
            );

            // Fill the remote window. The peer reads it and grants nothing
            // back, so the next write is Pending on the window, not on the
            // admission slot.
            tokio::time::timeout(
                Duration::from_secs(5),
                duplex.write_all(&vec![0x5a; super::INITIAL_CHANNEL_WINDOW as usize]),
            )
            .await
            .expect("filling the remote window did not complete")
            .unwrap();
            tokio::time::timeout(Duration::from_secs(5), duplex.flush())
                .await
                .expect("the window-filling flush did not complete")
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), window_full_rx)
                .await
                .unwrap()
                .unwrap();
            {
                let state = duplex.shared.lock().unwrap();
                assert!(
                    state.outbound.is_empty(),
                    "the admission slot was not drained before the wait"
                );
                assert_eq!(
                    state.established.available_window(),
                    0,
                    "the remote window was not exhausted"
                );
            }

            let wake = Arc::new(CountingWake {
                wakes: AtomicUsize::new(0),
                signal: tokio::sync::Notify::new(),
            });
            let waker = Waker::from(Arc::clone(&wake));
            let mut context = Context::from_waker(&waker);

            // The pump is waiting for inbound input, so the only event that can
            // wake this writer is the peer close (or the transport loss).
            let mut pending = Box::pin(duplex.write(b"after-window"));
            assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(wake.wakes.load(Ordering::SeqCst), 0);
            drop(pending);

            close_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), wake.signal.notified())
                .await
                .expect("the pending writer was not woken by the peer close");
            assert!(wake.wakes.load(Ordering::SeqCst) > 0);

            let mut after = Box::pin(duplex.write(b"after-close"));
            match after.as_mut().poll(&mut context) {
                Poll::Ready(Err(error)) if abrupt => {
                    assert_eq!(error.kind(), std::io::ErrorKind::Other);
                }
                Poll::Ready(Err(error)) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                }
                other => panic!("the closed session did not fail the write: {other:?}"),
            }
            drop(after);
            drop(duplex);
            server.join().unwrap();
        }
    }

    /// A session transport that orders every effect through the same control
    /// the session guard owns, like the production `DeadlineSocket`.
    ///
    /// It wraps the production readiness adapter (`Socket`) so a drained socket
    /// clears Tokio's readiness state instead of waking the pump in a spin. The
    /// ordering check and the park sit outside that adapter, so a parked effect
    /// never holds the adapter's readiness lock.
    ///
    /// All three entry points are instrumented. `attempted` counts calls that
    /// reach the ordering check, `entered` counts calls the check admitted, and
    /// `completed` counts admitted calls that returned. The first armed write is
    /// parked inside its effect closure, between the check and the socket call:
    /// that is the window in which a synchronous pump step is committed but not
    /// finished.
    struct GateTransport {
        inner: super::Socket<std::net::TcpStream>,
        control: crate::ssh_cancellation::EstablishmentControl,
        attempted: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
        completed: Arc<std::sync::atomic::AtomicUsize>,
        armed: Arc<std::sync::atomic::AtomicBool>,
        write_entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: Arc<EffectGate>,
        dropped: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl GateTransport {
        fn armed(&self) -> bool {
            self.armed.load(Ordering::SeqCst)
        }
    }

    impl std::io::Read for GateTransport {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.armed() {
                self.attempted.fetch_add(1, Ordering::SeqCst);
            }
            self.control
                .clone()
                .try_session_effect(|| {
                    if !self.armed() {
                        return self.inner.read(bytes);
                    }
                    self.entered.fetch_add(1, Ordering::SeqCst);
                    let result = self.inner.read(bytes);
                    self.completed.fetch_add(1, Ordering::SeqCst);
                    result
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }
    }

    impl std::io::Write for GateTransport {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.armed() {
                self.attempted.fetch_add(1, Ordering::SeqCst);
            }
            self.control
                .clone()
                .try_session_effect(|| {
                    if !self.armed() {
                        return self.inner.write(bytes);
                    }
                    self.entered.fetch_add(1, Ordering::SeqCst);
                    if let Some(entered) = self.write_entered.take() {
                        let _ = entered.send(());
                    }
                    self.release.wait();
                    let result = self.inner.write(bytes);
                    self.completed.fetch_add(1, Ordering::SeqCst);
                    result
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.armed() {
                self.attempted.fetch_add(1, Ordering::SeqCst);
            }
            self.control
                .clone()
                .try_session_effect(|| {
                    if !self.armed() {
                        return self.inner.flush();
                    }
                    self.entered.fetch_add(1, Ordering::SeqCst);
                    let result = self.inner.flush();
                    self.completed.fetch_add(1, Ordering::SeqCst);
                    result
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionAborted))?
        }
    }

    impl Drop for GateTransport {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(());
            }
        }
    }

    /// A one-way release gate the pump parks on inside an admitted effect.
    ///
    /// Releasing only sets a flag and notifies, so it never blocks: both the
    /// explicit release and the cleanup guard can run from an unwind path.
    struct EffectGate {
        released: std::sync::Mutex<bool>,
        signal: std::sync::Condvar,
    }

    impl EffectGate {
        fn new() -> Self {
            Self {
                released: std::sync::Mutex::new(false),
                signal: std::sync::Condvar::new(),
            }
        }

        fn wait(&self) {
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.signal.wait(released).unwrap();
            }
        }

        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.signal.notify_all();
        }
    }

    /// Releases the effect gate unconditionally on drop, so a failing assertion
    /// lets the pump leave instead of parking a runtime worker through teardown.
    struct ReleaseOnDrop(Arc<EffectGate>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    /// A drop must commit cancellation while the pump still owns the shared
    /// `Arc`, and a check after it must refuse a later effect.
    ///
    /// One inbound byte makes the pump write a window adjustment, and the first
    /// armed write is parked inside `pump_step`, so the pump provably holds the
    /// only other strong reference to the shared driver, and therefore to the
    /// session guard, when the duplex is dropped. The guard is unregistered on
    /// purpose: `request_cancel` takes the socket registration lock with
    /// `try_lock`, so its shutdown is opportunistic. Keeping the socket live
    /// proves the ordering check, not the shutdown, is what refuses the later
    /// effect. After the release the parked write finishes and the pump loops to
    /// another effect within the same synchronous step; that attempt reaches the
    /// check and is refused, so no effect is entered after cancellation.
    ///
    /// This is a unit test of a private duplex because the property is the
    /// ordering inside one private type; a public path cannot park an effect at
    /// this exact boundary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // One fixture covers the park, cancellation, and the later check.
    async fn dropping_the_duplex_refuses_a_later_effect_after_the_pump_step_is_released() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::CancelOnDrop;
        use neotales_ssh::channel::ChannelError;
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::time::Instant;
        use tokio::io::AsyncReadExt as _;

        const BOUND: Duration = Duration::from_secs(5);

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [123; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.write_data(session, b"x").unwrap();
            let result = loop {
                match connection.dispatch_one() {
                    Ok(_) => {}
                    Err(error) => break error,
                }
            };
            let _ = closed_tx.send(result);
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(BOUND)).unwrap();
        socket.set_write_timeout(Some(BOUND)).unwrap();
        let readiness_socket = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + BOUND);
        let guard = CancelOnDrop::test_unregistered(control.clone());
        let attempted = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let armed = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(EffectGate::new());
        let (write_entered_tx, write_entered_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let would_block = WouldBlock::default();
        let readiness_slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = new_write_progress();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                GateTransport {
                    inner: super::Socket {
                        inner: socket,
                        would_block: Arc::clone(&would_block.0),
                        read_readiness: Arc::clone(&readiness_slot),
                        write_readiness: Arc::clone(&readiness_slot),
                        write_progress: Arc::clone(&write_progress),
                    },
                    control: control.clone(),
                    attempted: Arc::clone(&attempted),
                    entered: Arc::clone(&entered),
                    completed: Arc::clone(&completed),
                    armed: Arc::clone(&armed),
                    write_entered: Some(write_entered_tx),
                    release: Arc::clone(&gate),
                    dropped: Some(dropped_tx),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();
        readiness_socket.set_nonblocking(true).unwrap();
        let readiness = Arc::new(tokio::net::TcpStream::from_std(readiness_socket).unwrap());
        readiness_slot.set(Arc::clone(&readiness)).unwrap();
        drop(readiness_slot);
        armed.store(true, Ordering::SeqCst);
        let mut duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&readiness),
            Arc::clone(&readiness),
            write_progress,
            super::WRITE_STALL_BOUND,
        );
        // Constructed before any wait or assertion, and releasing never blocks,
        // so every exit path lets the pump leave the gate.
        let _release = ReleaseOnDrop(Arc::clone(&gate));

        // Consume the peer's byte. That credits the remote, and the pump's next
        // step writes the window adjustment.
        let mut byte = [0; 1];
        tokio::time::timeout(BOUND, duplex.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&byte, b"x");

        // The pump is parked inside `pump_step`, holding the only other strong
        // reference to the shared driver and therefore to the session guard.
        tokio::time::timeout(BOUND, write_entered_rx)
            .await
            .unwrap()
            .unwrap();
        let attempted_before = attempted.load(Ordering::SeqCst);
        let entered_before = entered.load(Ordering::SeqCst);
        assert_eq!(Arc::strong_count(&duplex.shared), 2);

        drop(duplex);
        assert!(control.is_cancelled());

        gate.release();
        tokio::time::timeout(BOUND, dropped_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            attempted.load(Ordering::SeqCst) > attempted_before,
            "the pump never attempted a later effect after cancellation"
        );
        assert_eq!(
            entered.load(Ordering::SeqCst),
            entered_before,
            "a session effect started after cancellation"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            entered_before,
            "the effect that won its check before cancellation did not finish"
        );
        // The transport is gone; this is the last handle keeping the socket
        // open, so closing it lets the peer observe the close.
        drop(readiness);
        let peer = tokio::time::timeout(BOUND, closed_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(peer, ChannelError::Transport),
            "the peer did not observe the closed socket: {peer:?}"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn remote_eof_allows_local_writes_and_answers_the_later_peer_close() {
        use neotales_ssh::channel::ChannelEvent;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [120; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (close_sent_tx, close_sent_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.write_data(session, b"before-eof").unwrap();
            connection.send_eof(session).unwrap();
            let mut received = Vec::new();
            while received.len() < b"after-eof".len() {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Data { data, .. } => received.extend_from_slice(&data),
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("expected continued data after EOF: {other:?}"),
                }
            }
            assert_eq!(received, b"after-eof");
            connection.send_close(session).unwrap();
            let _ = close_sent_tx.send(());
            let mut answered = false;
            for _ in 0..8 {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Close { channel } if channel == session => {
                        answered = true;
                        break;
                    }
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("expected the client's close reply: {other:?}"),
                }
            }
            let _ = done_tx.send(answered);
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();
        let mut before = [0_u8; 10];
        duplex.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before-eof");
        let mut eof = [0_u8; 1];
        assert_eq!(duplex.read(&mut eof).await.unwrap(), 0);

        // A remote EOF is a read half-close, not a bidirectional close.
        duplex.write_all(b"after-eof").await.unwrap();
        duplex.flush().await.unwrap();

        // The peer has written its CLOSE. Reading again must drive and answer it.
        tokio::time::timeout(Duration::from_secs(5), close_sent_rx)
            .await
            .unwrap()
            .unwrap();
        let mut after = [0_u8; 1];
        assert_eq!(duplex.read(&mut after).await.unwrap(), 0);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done_rx)
                .await
                .unwrap()
                .unwrap(),
            "the client did not answer the peer close"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn peer_transport_failure_after_eof_is_not_success() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [126; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (release, wait) = std::sync::mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.send_eof(session).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        let guard = Dialed::test_connected(
            socket.try_clone().unwrap(),
            EstablishmentControl::new(Instant::now() + Duration::from_secs(5)),
        )
        .unwrap()
        .guard;
        let readiness = socket.try_clone().unwrap();
        let would_block = WouldBlock::default();
        let slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = new_write_progress();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: GatedSocket {
                        socket,
                        gate: Arc::new(std::sync::Mutex::new(Gate { block_after: None })),
                    },
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&slot),
                    write_readiness: Arc::clone(&slot),
                    write_progress: Arc::clone(&write_progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();
        readiness.set_nonblocking(true).unwrap();
        let readiness = Arc::new(tokio::net::TcpStream::from_std(readiness).unwrap());
        slot.set(Arc::clone(&readiness)).unwrap();
        let mut duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&readiness),
            readiness,
            write_progress,
            super::WRITE_STALL_BOUND,
        );
        let mut byte = [0];
        assert_eq!(duplex.read(&mut byte).await.unwrap(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !duplex.pump.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            duplex.flush().await.is_err(),
            "abrupt peer transport loss after EOF must fail flush"
        );
        assert!(
            duplex.shutdown().await.is_err(),
            "abrupt peer transport loss after EOF must fail shutdown"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One controlled peer covers EOF, blocked reply, and release.
    async fn pump_answers_a_later_close_after_eof_without_an_application_read() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::Mutex;
        use std::sync::mpsc;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [124; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        let (send_close_tx, send_close_rx) = mpsc::channel();
        let (replies_tx, replies_rx) = mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.write_data(session, b"before-eof").unwrap();
            connection.send_eof(session).unwrap();
            let _ = eof_tx.send(());
            let _ = send_close_rx.recv_timeout(Duration::from_secs(5));
            connection.send_close(session).unwrap();
            let mut reply_count = 0;
            for _ in 0..8 {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Close { channel } if channel == session => {
                        reply_count += 1;
                        break;
                    }
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("unexpected after close: {other:?}"),
                }
            }
            let _ = replies_tx.send(reply_count);
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guard_socket = socket.try_clone().unwrap();
        let client_socket = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let dialed = Dialed::test_connected(guard_socket, control).unwrap();
        let Dialed { guard, .. } = dialed;
        let gate = Arc::new(Mutex::new(Gate { block_after: None }));
        let gated = GatedSocket {
            socket,
            gate: Arc::clone(&gate),
        };
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(gated, |_| Ok::<(), ()>(()))
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        // The production path switches the socket to non-blocking at session
        // commit; this test assembles the driver directly, so do it here.
        client_socket.set_nonblocking(true).unwrap();
        let mut shared = super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            super::InboundBuffer::default(),
        );

        // Drive the peer's data and EOF with pump steps only; the application
        // never issues a read.
        tokio::time::timeout(Duration::from_secs(5), eof_rx)
            .await
            .unwrap()
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !shared.remote_eof && tokio::time::Instant::now() < deadline {
            match shared.pump_step() {
                super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify
                | super::PumpAction::Yield => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                super::PumpAction::Closed => break,
            }
        }
        assert!(shared.remote_eof, "the pump did not observe the peer EOF");
        assert!(!shared.closed);

        // Block the close reply, then let the peer send CLOSE. The pump must
        // retain the exact reply across the block.
        gate.lock().unwrap().block_after = Some(0);
        send_close_tx.send(()).unwrap();
        let mut blocked = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !blocked && tokio::time::Instant::now() < deadline {
            match shared.pump_step() {
                super::PumpAction::WaitWrite | super::PumpAction::WaitReadWrite
                    if shared.established.close_reply_writing() =>
                {
                    blocked = true;
                }
                super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify
                | super::PumpAction::Yield => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                super::PumpAction::Closed => break,
            }
        }
        assert!(blocked, "the close reply did not block");
        assert!(shared.established.close_pending());
        assert!(shared.established.owed_close_reply());

        // Release the socket. The pump finishes exactly one close reply.
        gate.lock().unwrap().block_after = None;
        let mut closed = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !closed && tokio::time::Instant::now() < deadline {
            match shared.pump_step() {
                super::PumpAction::Closed => closed = true,
                super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify
                | super::PumpAction::Yield => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        assert!(closed, "the pump did not finish the close reply");
        let reply_count = replies_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(reply_count, 1, "the peer saw more than one close reply");
        drop(shared);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn shutdown_drives_a_blocked_close_reply_before_returning_success() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use neotales_ssh::channel::ChannelEvent;
        use std::sync::Mutex;
        use std::sync::mpsc;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [125; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (send_close_tx, send_close_rx) = mpsc::channel();
        let (replies_tx, replies_rx) = mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let _ = send_close_rx.recv_timeout(Duration::from_secs(5));
            connection.send_close(session).unwrap();
            let mut reply_count = 0;
            for _ in 0..8 {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Close { channel } if channel == session => {
                        reply_count += 1;
                        break;
                    }
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("unexpected after close: {other:?}"),
                }
            }
            let _ = replies_tx.send(reply_count);
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guard_socket = socket.try_clone().unwrap();
        let client_socket = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let dialed = Dialed::test_connected(guard_socket, control).unwrap();
        let Dialed { guard, .. } = dialed;
        let gate = Arc::new(Mutex::new(Gate { block_after: None }));
        let gated = GatedSocket {
            socket,
            gate: Arc::clone(&gate),
        };
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(gated, |_| Ok::<(), ()>(()))
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        client_socket.set_nonblocking(true).unwrap();
        gate.lock().unwrap().block_after = Some(0);
        let mut shared = super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            super::InboundBuffer::default(),
        );

        // Let the peer send CLOSE. The pump reads it and blocks writing the
        // close reply.
        send_close_tx.send(()).unwrap();
        let mut blocked = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !blocked && tokio::time::Instant::now() < deadline {
            match shared.pump_step() {
                super::PumpAction::WaitWrite | super::PumpAction::WaitReadWrite
                    if shared.established.close_reply_writing() =>
                {
                    blocked = true;
                }
                super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify
                | super::PumpAction::Yield => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                super::PumpAction::Closed => break,
            }
        }
        assert!(blocked, "the close reply did not block");
        assert!(shared.established.close_pending());
        assert!(shared.established.owed_close_reply());

        // Shutdown must drive the outstanding reply, not return success on
        // `close_pending` alone.
        assert!(matches!(
            shared.established.shutdown(),
            Ok(super::Progress::Blocked(super::BlockedOn::Write))
        ));

        gate.lock().unwrap().block_after = None;
        assert!(matches!(
            shared.established.shutdown(),
            Ok(super::Progress::Closed)
        ));
        let reply_count = replies_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(reply_count, 1, "the peer saw more than one close reply");
        drop(shared);
        server.join().unwrap();
    }

    // This test covers cancellation of a shutdown requested before the pump
    // starts it: the data is still queued in the admission slot, so the first
    // poll is Pending and nothing has been admitted yet. The case where a
    // channel-data packet is already admitted and only partly written is
    // covered by
    // `cancelled_shutdown_while_admitted_data_is_partially_written_retries_once`.
    // `shutdown_drives_a_blocked_close_reply_before_returning_success` covers a
    // blocked close reply, and
    // `shutdown_flushes_data_sends_one_eof_and_keeps_reading` covers an
    // uncancelled shutdown flushing admitted data.
    #[tokio::test]
    async fn cancelled_shutdown_retries_without_a_second_eof() {
        use neotales_ssh::channel::ChannelEvent;
        use std::task::Poll;
        use tokio::io::AsyncWriteExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [127; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let data = b"partial-data-before-eof".to_vec();
        let expected = data.clone();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let mut received = Vec::new();
            let mut eofs = 0;
            loop {
                match connection.dispatch_one() {
                    Ok(ChannelEvent::Data { data, .. }) => received.extend_from_slice(&data),
                    Ok(ChannelEvent::Eof { .. }) => eofs += 1,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            let _ = done_tx.send((received, eofs));
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();

        // The data is in the admission slot; the pump has not run yet.
        tokio::time::timeout(Duration::from_secs(5), duplex.write_all(&data))
            .await
            .expect("the data write did not complete")
            .unwrap();

        // Shutdown must flush that data first, so the first poll is genuinely
        // Pending. Cancel it, then retry.
        let mut pending = Box::pin(duplex.shutdown());
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
        drop(pending);

        tokio::time::timeout(Duration::from_secs(5), duplex.shutdown())
            .await
            .expect("the shutdown retry did not complete")
            .unwrap();
        // A second shutdown is a no-op, not a second EOF.
        tokio::time::timeout(Duration::from_secs(5), duplex.shutdown())
            .await
            .expect("the second shutdown did not complete")
            .unwrap();
        drop(duplex);
        let (received, eofs) = tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        assert_eq!(eofs, 1, "the peer saw more than one EOF");
        server.join().unwrap();
    }

    /// Cancels an async shutdown while an admitted channel-data packet has
    /// been only partly written, then retries it.
    ///
    /// The pump is the real one and the peer is a real SSH server. Write
    /// pressure comes from a separate loopback probe used through the
    /// production `Socket::try_io` adapter; the SSH socket itself is not
    /// saturated. The packet must finish exactly once, the EOF must be sent
    /// exactly once, and the read half must still deliver a later response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // One peer, probe, and pump cover the partial-shutdown lifecycle.
    async fn cancelled_shutdown_while_admitted_data_is_partially_written_retries_once() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use std::future::Future as _;
        use std::task::Poll;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const BOUND: Duration = Duration::from_secs(5);
        const PROBE_CHUNK: usize = 16 * 1024;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [133; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let data = vec![b'P'; 256];

        // Connect and accept before spawning: `accept` then returns
        // immediately, so a failed client setup cannot leave a peer thread
        // blocked in `accept` forever.
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(BOUND)).unwrap();
        socket.set_write_timeout(Some(BOUND)).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let cleanup_socket = socket.try_clone().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let observer = Arc::new(ReadObserver::default());
        let script_observer = Arc::clone(&observer);
        let server = observed_peer(
            signer,
            peer,
            BOUND,
            Arc::clone(&observer),
            move |connection| {
                // The client's read half must still work after its own EOF, so
                // the peer answers before draining.
                let outcome = record_shutdown(connection, &script_observer, Some(b"reply"), None);
                let _ = done_tx.send(outcome);
            },
        );
        let mut cleanup = PeerCleanup {
            server: Some(server),
            client: Some(cleanup_socket),
        };

        // The probe is a separate loopback pair. Its send buffer, not the SSH
        // socket's, is the write pressure this test measures.
        let probe_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe_address = probe_listener.local_addr().unwrap();
        let probe_client = std::net::TcpStream::connect(probe_address).unwrap();
        let (probe_peer, _) = probe_listener.accept().unwrap();
        probe_client.set_nonblocking(true).unwrap();
        probe_peer.set_nonblocking(true).unwrap();
        let probe_readiness =
            Arc::new(tokio::net::TcpStream::from_std(probe_client.try_clone().unwrap()).unwrap());
        let mut probe_peer = tokio::net::TcpStream::from_std(probe_peer).unwrap();

        let guard_socket = socket.try_clone().unwrap();
        let ssh_control = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + BOUND);
        let Dialed { guard, .. } = Dialed::test_connected(guard_socket, control).unwrap();

        let would_block = WouldBlock::default();
        let read_slot = Arc::new(std::sync::OnceLock::new());
        let write_slot = Arc::new(std::sync::OnceLock::new());
        let write_progress = new_write_progress();
        let partial = Arc::new(PartialWriteState::default());
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                super::Socket {
                    inner: PartialProbeSocket {
                        ssh: socket,
                        probe: probe_client,
                        probe_chunk: vec![0_u8; PROBE_CHUNK],
                        state: Arc::clone(&partial),
                    },
                    would_block: Arc::clone(&would_block.0),
                    read_readiness: Arc::clone(&read_slot),
                    write_readiness: Arc::clone(&write_slot),
                    write_progress: Arc::clone(&write_progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, would_block).unwrap();

        ssh_control.set_nonblocking(true).unwrap();
        let read_readiness = Arc::new(tokio::net::TcpStream::from_std(ssh_control).unwrap());
        read_slot.set(Arc::clone(&read_readiness)).unwrap();
        // Mark the probe writable before the production adapter starts using
        // it. Tokio readiness is edge-triggered, so the pump's first `try_io`
        // reaches the transport's real probe write.
        tokio::time::timeout(BOUND, probe_readiness.writable())
            .await
            .expect("inconclusive: probe never reported writable")
            .unwrap();
        write_slot.set(Arc::clone(&probe_readiness)).unwrap();

        let mut duplex = gated_duplex(
            parts,
            guard,
            Arc::clone(&read_readiness),
            Arc::clone(&probe_readiness),
            write_progress,
            super::WRITE_STALL_BOUND,
        );
        let sequence_before = duplex
            .shared
            .lock()
            .unwrap()
            .established
            .committed_outbound_sequence();

        // Arm a one-byte prefix of the next admitted packet, then admit it.
        let (partial_tx, partial_rx) = tokio::sync::oneshot::channel();
        *partial.partial_written.lock().unwrap() = Some(partial_tx);
        partial.partial_after.lock().unwrap().replace(1);
        partial.armed.store(true, Ordering::SeqCst);

        tokio::time::timeout(BOUND, duplex.write_all(&data))
            .await
            .expect("the data write did not complete")
            .unwrap();
        tokio::time::timeout(BOUND, partial_rx)
            .await
            .expect("inconclusive: the pump never wrote a partial DATA prefix")
            .expect("inconclusive: the partial signal sender was dropped");

        // Synchronize on the actual pump state: the packet is admitted and
        // retained, the one-byte prefix reached the SSH socket, and the
        // sequence did not commit. This is not inferred from the write result.
        {
            let state = duplex.shared.lock().unwrap();
            assert!(
                state.established.data_active(),
                "the admitted DATA packet was not retained"
            );
            assert!(
                state.outbound.is_empty(),
                "expected state.outbound to be empty"
            );
            assert_eq!(
                state.established.committed_outbound_sequence(),
                sequence_before,
                "the partially written packet committed its sequence"
            );
        }
        assert_eq!(partial.partial_bytes.load(Ordering::SeqCst), 1);
        assert!(partial.probe_blocked.load(Ordering::SeqCst) > 0);
        assert_eq!(partial.ssh_would_block.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), probe_readiness.writable())
                .await
                .is_err(),
            "inconclusive: the probe became writable before release"
        );

        // Cancel an async shutdown while the packet is partly written.
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        let mut cancelled = Box::pin(duplex.shutdown());
        assert!(matches!(
            cancelled.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(cancelled);
        {
            let state = duplex.shared.lock().unwrap();
            assert!(state.established.data_active());
            assert!(!state.established.eof_active());
            assert_eq!(
                state.established.committed_outbound_sequence(),
                sequence_before
            );
        }

        // Retry. It stays pending until the probe is released.
        let mut retry = Box::pin(duplex.shutdown());
        assert!(matches!(retry.as_mut().poll(&mut context), Poll::Pending));

        // Drain the probe. Its writability is what lets the pump finish the
        // active packet and then send the single EOF.
        let filled = partial.probe_filled.load(Ordering::SeqCst);
        assert!(filled > 0, "inconclusive: the probe was never filled");
        let drain = async {
            let mut buffer = vec![0_u8; PROBE_CHUNK];
            let mut drained = 0_usize;
            while drained < filled {
                match probe_peer.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(count) => drained += count,
                    Err(error) => panic!("inconclusive: probe drain failed: {error}"),
                }
            }
        };
        tokio::time::timeout(BOUND, drain)
            .await
            .expect("inconclusive: the probe did not drain");

        tokio::time::timeout(BOUND, retry)
            .await
            .expect("the shutdown retry did not complete")
            .unwrap();
        // A second shutdown is a no-op, not a second EOF.
        tokio::time::timeout(BOUND, duplex.shutdown())
            .await
            .expect("the second shutdown did not complete")
            .unwrap();

        // The read half stays usable after this side's EOF.
        let mut reply = [0_u8; 5];
        tokio::time::timeout(BOUND, duplex.read_exact(&mut reply))
            .await
            .expect("the peer's response was not readable after the local EOF")
            .unwrap();
        assert_eq!(&reply, b"reply");

        drop(duplex);
        // Close the last client-side handle so the peer observes a clean
        // transport closure now. Without this it waits for its own read
        // timeout, which races the bound below.
        cleanup.close_client();
        let (transcript, end) = tokio::time::timeout(BOUND, done_rx)
            .await
            .expect("inconclusive: the peer did not finish")
            .expect("inconclusive: the peer dropped its result")
            .unwrap_or_else(|message| panic!("{message}"));
        assert_eq!(
            transcript,
            vec![ShutdownEvent::Data(data), ShutdownEvent::Eof],
            "the peer did not observe exactly one DATA followed by exactly one EOF"
        );
        assert_eq!(
            end,
            CleanEnd::TransportEof,
            "the peer did not observe a clean transport EOF"
        );
        assert_eq!(
            partial.ssh_would_block.load(Ordering::SeqCst),
            0,
            "the SSH socket, not the probe, reported write pressure"
        );
        cleanup.detach();
    }

    /// The shutdown classifier must reject the two protocol errors a sloppy
    /// client can produce after its EOF.
    ///
    /// This drives a duplicate EOF and data after EOF through the real channel
    /// layer, then feeds the resulting errors to [`classify_after_eof`].
    /// Treating every `Err` as a clean end would let either violation pass the
    /// partial-shutdown test, so this is the mutation the classifier guards
    /// against.
    #[test]
    fn after_eof_classifier_rejects_a_duplicate_eof_and_data_after_eof() {
        fn after_eof_connection(
            input: impl IntoIterator<Item = Vec<u8>>,
        ) -> super::ChannelConnection<FakeSetupTransport> {
            let transport = FakeSetupTransport {
                input: input.into_iter().collect(),
                ..FakeSetupTransport::default()
            };
            let mut connection = super::ChannelConnection::new(transport);
            let session = connection.allocate_channel_id().unwrap();
            connection
                .open_channel(session, SESSION_CHANNEL_TYPE.as_bytes(), &[])
                .unwrap();
            assert!(matches!(
                connection.dispatch_one().unwrap(),
                super::ChannelEvent::Opened(0)
            ));
            assert!(matches!(
                connection.dispatch_one().unwrap(),
                super::ChannelEvent::Eof { channel: 0 }
            ));
            connection
        }

        let no_transport_observation = TransportObservation::default();
        let mut duplicate_eof = after_eof_connection([opened(0, 7), eof_packet(0), eof_packet(0)]);
        assert!(
            matches!(
                classify_after_eof(0, duplicate_eof.dispatch_one(), &no_transport_observation),
                AfterEof::ProtocolViolation(_)
            ),
            "a duplicate EOF was accepted as a clean end"
        );

        let mut data_after_eof =
            after_eof_connection([opened(0, 7), eof_packet(0), data_packet(0, b"late")]);
        assert!(
            matches!(
                classify_after_eof(0, data_after_eof.dispatch_one(), &no_transport_observation),
                AfterEof::ProtocolViolation(_)
            ),
            "data after EOF was accepted as a clean end"
        );
    }

    /// A `ChannelError::Transport` is clean only when the instrumented socket
    /// observed a real `Ok(0)` at a packet boundary.
    ///
    /// The channel layer flattens EOF, timeout, a truncated packet, and a
    /// corrupted packet into the same `Transport` error, so the observation —
    /// not the error value — decides. This is the negative-timeout and
    /// corrupted-packet proof at the classifier boundary.
    #[test]
    fn after_eof_classifier_requires_an_observed_clean_eof() {
        let clean = TransportObservation {
            outcomes: vec![ReadOutcome::Eof],
            failure: Some(TransportFailure::Truncated),
            terminal_packets_consumed: Some(0),
            ..TransportObservation::default()
        };
        assert!(matches!(
            classify_after_eof(0, Err(super::ChannelError::Transport), &clean),
            AfterEof::Clean(CleanEnd::TransportEof)
        ));

        let timeout = TransportObservation {
            outcomes: vec![ReadOutcome::Timeout],
            failure: Some(TransportFailure::Timeout),
            terminal_packets_consumed: Some(0),
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &timeout),
                AfterEof::ProtocolViolation(_)
            ),
            "a read timeout was accepted as a clean end"
        );

        let truncated = TransportObservation {
            outcomes: vec![ReadOutcome::Bytes(4), ReadOutcome::Eof],
            partial_bytes: 4,
            failure: Some(TransportFailure::Truncated),
            terminal_packets_consumed: Some(0),
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &truncated),
                AfterEof::ProtocolViolation(_)
            ),
            "a truncated packet was accepted as a clean end"
        );

        let corrupted = TransportObservation {
            outcomes: vec![ReadOutcome::Bytes(16)],
            partial_bytes: 16,
            failure: Some(TransportFailure::PacketProtection),
            terminal_packets_consumed: Some(0),
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &corrupted),
                AfterEof::ProtocolViolation(_)
            ),
            "a corrupted packet was accepted as a clean end"
        );

        // The authenticated channel CLOSE is the other clean end.
        assert!(matches!(
            classify_after_eof(
                0,
                Ok(super::ChannelEvent::Close { channel: 0 }),
                &TransportObservation::default()
            ),
            AfterEof::Clean(CleanEnd::ChannelClosed)
        ));
    }

    /// Internal traffic, an overflowed packet counter, or a strict-rekey reset
    /// cannot prove a clean EOF boundary, even when the socket saw `Ok(0)`.
    ///
    /// These are the fail-closed cases the packet counter must not guess.
    #[test]
    fn after_eof_classifier_fails_closed_on_ambiguous_boundaries() {
        // Internal traffic (PING, EXT_INFO, rekey) sharing the failing call.
        let ambiguous = TransportObservation {
            outcomes: vec![ReadOutcome::Bytes(20), ReadOutcome::Eof],
            partial_bytes: 20,
            failure: Some(TransportFailure::Truncated),
            terminal_packets_consumed: Some(1),
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &ambiguous),
                AfterEof::ProtocolViolation(message) if message.contains("inconclusive")
            ),
            "an ambiguous packet boundary was accepted as a clean end"
        );

        // An overflowed counter (`None`) cannot prove a boundary even when the
        // socket saw a clean EOF at zero partial bytes.
        let overflowed = TransportObservation {
            outcomes: vec![ReadOutcome::Eof],
            failure: Some(TransportFailure::Truncated),
            terminal_packets_consumed: None,
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &overflowed),
                AfterEof::ProtocolViolation(message) if message.contains("inconclusive")
            ),
            "an overflowed packet counter was accepted as a clean end"
        );

        // A strict-rekey NEWKEYS resets the wire sequence. The monotonic
        // counter sees the rekey packets, but a reset in the failing call must
        // also fail closed.
        let rekey_reset = TransportObservation {
            outcomes: vec![ReadOutcome::Eof],
            failure: Some(TransportFailure::Truncated),
            terminal_packets_consumed: Some(0),
            terminal_sequence_reset: true,
            ..TransportObservation::default()
        };
        assert!(
            matches!(
                classify_after_eof(0, Err(super::ChannelError::Transport), &rekey_reset),
                AfterEof::ProtocolViolation(message)
                    if message.contains("strict-rekey reset: true")
            ),
            "a strict-rekey sequence reset was accepted as a clean end"
        );
    }

    /// A peer read that times out is not a clean end, even though the channel
    /// layer reports it as `ChannelError::Transport`.
    ///
    /// The client sends its EOF and then stays alive, so the peer's read
    /// cannot observe `Ok(0)`; it can only time out. The instrumented socket
    /// records that, and the classifier must reject it. The peer keeps the
    /// generous handshake bound; only the post-EOF drain gets the short
    /// timeout, so a slow handshake under parallel load cannot trip it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_treats_a_peer_read_timeout_as_a_protocol_violation() {
        use tokio::io::AsyncWriteExt as _;

        const HANDSHAKE_BOUND: Duration = Duration::from_secs(5);
        const PEER_TIMEOUT: Duration = Duration::from_millis(500);
        const BOUND: Duration = Duration::from_secs(5);

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [144; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);

        // Connect and accept before spawning; `accept` cannot block.
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(HANDSHAKE_BOUND)).unwrap();
        socket.set_write_timeout(Some(HANDSHAKE_BOUND)).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let timeout_control = peer.try_clone().unwrap();
        let cleanup_socket = socket.try_clone().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let observer = Arc::new(ReadObserver::default());
        let script_observer = Arc::clone(&observer);
        let server = observed_peer(
            signer,
            peer,
            HANDSHAKE_BOUND,
            Arc::clone(&observer),
            move |connection| {
                // No reply and no close: the client stays alive, so the
                // post-EOF read must time out.
                let outcome = record_shutdown(
                    connection,
                    &script_observer,
                    None,
                    Some((&timeout_control, PEER_TIMEOUT)),
                );
                let _ = done_tx.send(outcome);
            },
        );
        let mut cleanup = PeerCleanup {
            server: Some(server),
            client: Some(cleanup_socket),
        };

        let mut duplex = manual_duplex(socket, &options, HANDSHAKE_BOUND);
        tokio::time::timeout(BOUND, duplex.write_all(b"request"))
            .await
            .expect("the request write did not complete")
            .unwrap();
        tokio::time::timeout(BOUND, duplex.shutdown())
            .await
            .expect("the shutdown did not complete")
            .unwrap();

        let outcome = tokio::time::timeout(BOUND, done_rx)
            .await
            .expect("inconclusive: the peer did not finish")
            .expect("inconclusive: the peer dropped its result");
        let message = outcome.expect_err("a peer read timeout was accepted as a clean end");
        assert!(
            message.contains("timed out"),
            "the timeout was not reported as a timeout: {message}"
        );

        drop(duplex);
        cleanup.detach();
    }

    /// A corrupted packet after the client's EOF is not a clean end, even
    /// though the channel layer reports it as `ChannelError::Transport`.
    ///
    /// The client sends a valid EOF and reads the peer's reply, then appends
    /// four zero bytes directly to the TCP stream and closes. The peer's
    /// transport rejects the malformed length prefix, and the instrumented
    /// socket shows no clean `Ok(0)` at a packet boundary.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_treats_a_corrupted_packet_as_a_protocol_violation() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const BOUND: Duration = Duration::from_secs(5);

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [155; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);

        // Connect and accept before spawning; `accept` cannot block.
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(BOUND)).unwrap();
        socket.set_write_timeout(Some(BOUND)).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let mut cleanup_socket = socket.try_clone().unwrap();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let observer = Arc::new(ReadObserver::default());
        let script_observer = Arc::clone(&observer);
        let server = observed_peer(
            signer,
            peer,
            BOUND,
            Arc::clone(&observer),
            move |connection| {
                let outcome = record_shutdown(connection, &script_observer, Some(b"reply"), None);
                let _ = done_tx.send(outcome);
            },
        );
        let mut cleanup = PeerCleanup {
            server: Some(server),
            client: Some(cleanup_socket.try_clone().unwrap()),
        };

        let mut duplex = manual_duplex(socket, &options, BOUND);
        tokio::time::timeout(BOUND, duplex.write_all(b"request"))
            .await
            .expect("the request write did not complete")
            .unwrap();
        tokio::time::timeout(BOUND, duplex.shutdown())
            .await
            .expect("the shutdown did not complete")
            .unwrap();

        let mut reply = [0_u8; 5];
        tokio::time::timeout(BOUND, duplex.read_exact(&mut reply))
            .await
            .expect("the peer's reply was not readable")
            .unwrap();
        assert_eq!(&reply, b"reply");

        // Append a malformed SSH packet directly to the TCP stream, then close
        // the last client handle so the peer cannot wait for its read timeout.
        std::io::Write::write_all(&mut cleanup_socket, &[0_u8; 4]).unwrap();
        drop(duplex);
        cleanup.close_client();

        let outcome = tokio::time::timeout(BOUND, done_rx)
            .await
            .expect("inconclusive: the peer did not finish")
            .expect("inconclusive: the peer dropped its result");
        let message = outcome.expect_err("a corrupted packet was accepted as a clean end");
        assert!(
            message.contains("without an observed clean EOF")
                || message.contains("middle of an SSH packet"),
            "the corruption was not reported as a protocol failure: {message}"
        );

        cleanup.detach();
    }

    #[tokio::test]
    async fn shutdown_flushes_data_sends_one_eof_and_keeps_reading() {
        use neotales_ssh::channel::ChannelEvent;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [121; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (eof_seen_tx, eof_seen_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            let mut received = Vec::new();
            let mut saw_eof = false;
            while !saw_eof {
                match connection.dispatch_one().unwrap() {
                    ChannelEvent::Data { data, .. } => received.extend_from_slice(&data),
                    ChannelEvent::Eof { channel } if channel == session => saw_eof = true,
                    ChannelEvent::WindowAdjusted { .. } => {}
                    other => panic!("unexpected before EOF: {other:?}"),
                }
            }
            assert_eq!(received, b"request");
            let _ = eof_seen_tx.send(());
            connection.write_data(session, b"response").unwrap();
            let _ = connection.dispatch_one();
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();
        duplex.write_all(b"request").await.unwrap();
        // No explicit flush: shutdown must flush the admitted data first.
        duplex.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), eof_seen_rx)
            .await
            .unwrap()
            .unwrap();

        // The read half stays usable after this side's EOF.
        let mut response = [0_u8; 8];
        duplex.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        // A second shutdown is a no-op, not a second EOF.
        duplex.shutdown().await.unwrap();
        drop(duplex);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn pump_step_is_bounded_and_retains_state_under_control_traffic() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use crate::ssh_worker::supervise;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [123; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            for _ in 0..(super::MAX_PROTOCOL_STEPS_PER_POLL * 3) {
                connection
                    .transport_mut()
                    .write_payload(&global_request(false))
                    .unwrap();
            }
            let _ = done_tx.send(());
            let _ = connection.dispatch_one();
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control).unwrap();
        let worker_options = options.clone();
        let established = supervise(
            dialed,
            Duration::from_secs(5),
            &crate::ssh_worker::WORKERS,
            move |socket, _control| {
                let known = super::load_known_hosts(&worker_options.known_hosts_path)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let methods = super::auth_methods(&worker_options.identity)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let transport = super::checked_handshake(
                    socket,
                    &known,
                    &worker_options.known_hosts_path,
                    &worker_options.host_token,
                    &worker_options.host,
                    worker_options.port,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                super::authenticate_and_exec(
                    transport,
                    &methods,
                    &worker_options,
                    WouldBlock::default(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))
            },
        )
        .await
        .unwrap();

        // The peer signals after it has queued all the control events.
        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        let mut shared = super::SharedDriver::new(established, super::InboundBuffer::default());
        // The peer queued more control events than one budget. Keep taking
        // bounded steps until the queue is visible; a step must stop at the
        // budget and report Yield rather than consuming the whole queue.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut yielded = false;
        while tokio::time::Instant::now() < deadline {
            match shared.pump_step() {
                super::PumpAction::Yield => {
                    yielded = true;
                    break;
                }
                super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                super::PumpAction::Closed => break,
            }
        }
        assert!(
            yielded,
            "a bounded pump step never reported Yield under sustained control traffic"
        );
        drop(shared);
        server.join().unwrap();
    }

    /// A partial socket write restarts the bound; stopped progress expires it.
    ///
    /// The reset signal is positive socket bytes, not a completed packet. A
    /// slow-but-live peer that keeps accepting a prefix is therefore not
    /// disconnected; once the bytes stop, the latest arm expires.
    #[test]
    fn write_stall_restarts_on_positive_bytes_and_expires_after_they_stop() {
        let base = tokio::time::Instant::now();
        let bound = Duration::from_secs(10);
        let mut stall = super::ReplyStall::default();

        // The first non-escapable observation arms the bound.
        assert_eq!(
            stall.observe(base, true, false, bound),
            super::StallWait::Open(base + bound)
        );
        assert_eq!(stall.armed_at(), Some(base));

        // A positive byte write near the deadline restarts the clock there.
        let progress_at = base + Duration::from_millis(9_999);
        assert_eq!(
            stall.observe(progress_at, true, true, bound),
            super::StallWait::Open(progress_at + bound)
        );
        assert_eq!(stall.armed_at(), Some(progress_at));

        // No further bytes: the renewed arm holds until its deadline.
        assert_eq!(
            stall.observe(progress_at + Duration::from_secs(5), true, false, bound),
            super::StallWait::Open(progress_at + bound)
        );
        assert_eq!(
            stall.observe(progress_at + bound, true, false, bound),
            super::StallWait::Expired
        );
    }

    /// A wakeup, writability, or a step that wrote nothing does not reset it.
    #[test]
    fn write_stall_does_not_reset_without_positive_bytes() {
        let base = tokio::time::Instant::now();
        let bound = Duration::from_secs(10);
        let mut stall = super::ReplyStall::default();
        assert_eq!(
            stall.observe(base, true, false, bound),
            super::StallWait::Open(base + bound)
        );
        // Repeated no-byte observations keep the original deadline.
        assert_eq!(
            stall.observe(base + Duration::from_secs(9), true, false, bound),
            super::StallWait::Open(base + bound)
        );
        assert_eq!(
            stall.observe(base + bound, true, false, bound),
            super::StallWait::Expired
        );
        // Leaving the non-escapable state clears the arm.
        assert_eq!(
            stall.observe(base, false, false, bound),
            super::StallWait::Idle
        );
        assert_eq!(stall.armed_at(), None);
    }

    /// The socket adapter counts only positive writes, not `WouldBlock`.
    #[test]
    fn socket_write_progress_counts_only_positive_bytes() {
        use std::io::Write as _;

        struct Scripted {
            result: Result<usize, std::io::ErrorKind>,
        }

        impl std::io::Write for Scripted {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                self.result.map_err(std::io::Error::from)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let progress = new_write_progress();
        let mut socket = super::Socket {
            inner: Scripted { result: Ok(3) },
            would_block: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            read_readiness: Arc::new(std::sync::OnceLock::new()),
            write_readiness: Arc::new(std::sync::OnceLock::new()),
            write_progress: Arc::clone(&progress),
        };
        assert_eq!(socket.write(b"abc").unwrap(), 3);
        assert_eq!(progress.load(Ordering::Relaxed), 3);
        socket.inner.result = Err(std::io::ErrorKind::WouldBlock);
        assert!(socket.write(b"abc").is_err());
        assert_eq!(progress.load(Ordering::Relaxed), 3);
    }

    /// A retained peer rekey behind a blocked write releases successfully.
    ///
    /// The client admitted a data packet, the peer sent KEXINIT, and the socket
    /// refused the write. That is the non-escapable state the write-stall bound
    /// covers and the channel driver refuses the reads that could advance it.
    /// Once the socket accepts writes again the client must finish the admitted
    /// packet and complete the exchange: the peer receives the admitted payload
    /// while its own rekey is still active, and a later payload only after both
    /// sides completed it, in that order.
    ///
    /// The bounded-stall expiry and cancellation paths are asserted separately
    /// by `async_pump_retained_rekey_without_a_reply_expires_at_the_bound` and
    /// `retained_peer_rekey_with_a_blocked_write_cancels`. This test accepts no
    /// failure on the release path.
    #[test]
    fn retained_peer_rekey_with_a_blocked_write_releases_and_preserves_order() {
        if !pressure_child_or_supervise(
            "retained_peer_rekey_with_a_blocked_write_releases_and_preserves_order",
        ) {
            return;
        }
        retained_peer_rekey_with_a_blocked_write_releases_and_preserves_order_body();
    }

    /// What the controlled peer observed across the release.
    struct PeerRelease {
        /// Application payloads in arrival order.
        data: Vec<Vec<u8>>,
        /// Whether the peer still held the rekey when the admitted payload
        /// arrived, which is the in-flight window RFC 4253 §7.1 requires it to
        /// process.
        rekey_active_during_first_data: bool,
        /// Whether the rekey was still active after the post-rekey payload.
        rekey_active_after: bool,
        /// The first dispatch error, if any. `None` is success.
        failure: Option<String>,
    }

    #[allow(clippy::too_many_lines)] // One peer covers the stall, release, rekey, and ordering.
    fn retained_peer_rekey_with_a_blocked_write_releases_and_preserves_order_body() {
        use std::sync::Mutex;
        use std::sync::mpsc;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [131; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (rekey_tx, rekey_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let (peer_tx, peer_rx) = mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.transport_mut().begin_rekey().unwrap();
            rekey_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the client never reached the retained rekey state");
            // Dispatching drives the peer side of the rekey itself. The
            // transport returns the application packet the client admitted
            // before its KEXINIT instead of rejecting it, so the channel layer
            // sees it in arrival order.
            let mut payloads = Vec::new();
            let mut rekey_active_during_first_data = false;
            let mut failure = None;
            while payloads.len() < 2 {
                match connection.dispatch_one() {
                    Ok(neotales_ssh::channel::ChannelEvent::Data { channel, data })
                        if channel == session =>
                    {
                        if payloads.is_empty() {
                            rekey_active_during_first_data =
                                connection.transport_mut().rekey_active();
                        }
                        payloads.push(data);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        failure = Some(format!("{error:?}"));
                        break;
                    }
                }
            }
            let rekey_active_after = connection.transport_mut().rekey_active();
            let _ = peer_tx.send(PeerRelease {
                data: payloads,
                rekey_active_during_first_data,
                rekey_active_after,
                failure,
            });
            // Keep the socket open until the client has observed its own
            // progress, so a peer close cannot be mistaken for a release
            // failure.
            let _ = finish_rx.recv_timeout(Duration::from_secs(5));
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guard_socket = socket.try_clone().unwrap();
        let control = crate::ssh_cancellation::EstablishmentControl::new(
            Instant::now() + Duration::from_secs(5),
        );
        let crate::ssh_connect::Dialed { guard, .. } =
            crate::ssh_connect::Dialed::test_connected(guard_socket, control).unwrap();
        let gate = Arc::new(Mutex::new(Gate { block_after: None }));
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                GatedSocket {
                    socket,
                    gate: Arc::clone(&gate),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        let mut shared = super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            super::InboundBuffer::default(),
        );

        gate.lock().unwrap().block_after = Some(0);
        assert!(matches!(
            shared.established.write(&vec![b'R'; 1_024]),
            Ok(super::Progress::Wrote(1_024))
        ));
        rekey_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the peer never sent its rekey");

        let mut action = shared.pump_step();
        for _ in 0..100 {
            if shared.established.rekey_active() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            action = shared.pump_step();
        }
        assert!(
            shared.established.rekey_active(),
            "the client did not retain the peer rekey"
        );
        assert!(
            !shared.established.reply_outstanding(),
            "the test expected a rekey-only obligation"
        );
        assert!(
            matches!(action, super::PumpAction::WaitWrite),
            "the pump did not report the blocked write: {action:?}"
        );
        assert!(
            !shared.established.can_read_behind_active(),
            "read-behind was allowed while a retained rekey blocked the write"
        );
        assert!(shared.failure.is_none());

        // Release only now: the admitted packet and the client's rekey must
        // both make progress, and this test requires that they do.
        gate.lock().unwrap().block_after = None;
        release_tx.send(()).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let _ = shared.pump_step();
            assert!(
                shared.failure.is_none(),
                "the release path failed instead of completing: {:?}",
                shared.failure
            );
            assert!(!shared.closed, "the client closed a successful release");
            if !shared.established.rekey_active() && !shared.established.data_active() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the client did not finish the admitted packet and its rekey"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        // Post-rekey application progress: a new packet admitted after both
        // sides completed the exchange.
        assert!(matches!(
            shared.established.write(b"later"),
            Ok(super::Progress::Wrote(5))
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while shared.established.data_active() {
            let _ = shared.pump_step();
            assert!(
                shared.failure.is_none(),
                "the post-rekey write failed: {:?}",
                shared.failure
            );
            assert!(
                Instant::now() < deadline,
                "the post-rekey packet did not leave the client"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        finish_tx.send(()).unwrap();

        let peer = peer_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the peer did not report its release result");
        assert!(
            peer.failure.is_none(),
            "the peer failed during the release: {:?}",
            peer.failure
        );
        assert!(
            peer.rekey_active_during_first_data,
            "the peer had left the rekey before the admitted payload arrived"
        );
        assert!(
            !peer.rekey_active_after,
            "the peer did not complete the rekey"
        );
        assert_eq!(peer.data.len(), 2, "the peer saw the wrong payload count");
        assert_eq!(
            peer.data[0],
            vec![b'R'; 1_024],
            "the admitted payload was not delivered intact"
        );
        assert_eq!(
            peer.data[1],
            b"later".to_vec(),
            "the post-rekey payload was missing or out of order"
        );
        assert!(shared.failure.is_none());

        drop(shared);
        server.join().expect("the peer panicked");
    }

    /// A post-setup client socket that accepts at most the shared allowance.
    ///
    /// Establishment writes pass through untouched; after the test arms it,
    /// each protected write accepts a positive prefix and then reports
    /// `WouldBlock`. The progress counter is the same one the pump reads.
    struct StepSocket {
        ssh: std::net::TcpStream,
        armed: Arc<AtomicBool>,
        allowance: Arc<std::sync::Mutex<usize>>,
        progress: Arc<AtomicU64>,
    }

    impl std::io::Read for StepSocket {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.ssh, bytes)
        }
    }

    impl std::io::Write for StepSocket {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.armed.load(Ordering::SeqCst) {
                return std::io::Write::write(&mut self.ssh, bytes);
            }
            let mut allowance = self.allowance.lock().unwrap();
            if *allowance == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let length = (*allowance).min(bytes.len());
            let written = std::io::Write::write(&mut self.ssh, &bytes[..length])?;
            *allowance -= written;
            if written > 0 {
                self.progress.fetch_add(written as u64, Ordering::Relaxed);
            }
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            std::io::Write::flush(&mut self.ssh)
        }
    }

    /// A filled loopback probe used as a never-writable readiness handle.
    ///
    /// The test wakes the pump with `notify` instead of socket writability, so
    /// partial writes are delivered on command and the pump never spins.
    fn filled_write_probe() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(address).unwrap();
        let (peer, _) = listener.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        let mut fill = client.try_clone().unwrap();
        let chunk = vec![0_u8; 64 * 1024];
        let filled = fill_kernel_probe(&mut fill, &chunk).unwrap();
        assert!(filled > 0, "the write probe was never filled");
        (client, peer)
    }

    /// Actual positive partial writes through the async pump restart the bound.
    ///
    /// The socket accepts bytes only when the test grants an allowance and
    /// notifies the pump. Time is paused: no wall-clock sleep is involved.
    /// After a grant near the original deadline the session must stay open past
    /// that deadline, then fail only after the inactivity bound from the last
    /// positive write.
    #[tokio::test(start_paused = true)]
    async fn partial_socket_writes_through_the_async_pump_restart_the_bound() {
        if !pressure_child_or_supervise(
            "partial_socket_writes_through_the_async_pump_restart_the_bound",
        ) {
            return;
        }
        partial_socket_writes_through_the_async_pump_restart_the_bound_body().await;
    }

    #[allow(clippy::too_many_lines)] // One socket and pump cover grants, deadline, and expiry.
    async fn partial_socket_writes_through_the_async_pump_restart_the_bound_body() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use std::task::Poll;
        use std::time::Instant;
        use tokio::io::AsyncWriteExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [133; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, mut options) = options_for_peer(address, &signer);
        options.write_inactivity_timeout = Duration::from_millis(300);
        options.validate().unwrap();
        let (send_tx, send_rx) = std::sync::mpsc::channel();
        let (sent_tx, sent_rx) = std::sync::mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            send_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the client never admitted the blocked packet");
            for _ in 0..super::REPLY_CAPACITY {
                connection
                    .transport_mut()
                    .write_payload(&global_request(true))
                    .unwrap();
            }
            let _ = sent_tx.send(());
            // Drain the client's partial writes until the session ends.
            for _ in 0..64 {
                if connection.dispatch_one().is_err() {
                    break;
                }
            }
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guard_socket = socket.try_clone().unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let Dialed { guard, .. } = Dialed::test_connected(guard_socket, control).unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let allowance = Arc::new(std::sync::Mutex::new(0_usize));
        let progress = new_write_progress();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                StepSocket {
                    ssh: socket.try_clone().unwrap(),
                    armed: Arc::clone(&armed),
                    allowance: Arc::clone(&allowance),
                    progress: Arc::clone(&progress),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        // The socket's file description is shared with the clone the pump uses
        // for reads. Establishment is done, so nonblocking is safe now, and
        // the allowance applies only from here.
        socket.set_nonblocking(true).unwrap();
        armed.store(true, Ordering::SeqCst);
        let read_readiness =
            Arc::new(tokio::net::TcpStream::from_std(socket.try_clone().unwrap()).unwrap());
        let (probe, _probe_peer) = filled_write_probe();
        let write_readiness = Arc::new(tokio::net::TcpStream::from_std(probe).unwrap());
        let bound = options.write_inactivity_timeout;
        let mut duplex = gated_duplex(
            parts,
            guard,
            read_readiness,
            write_readiness,
            Arc::clone(&progress),
            bound,
        );

        // Install the pump-step notification before any wait. The test waits
        // for the arm event the pump emits, not for a scheduler slice.
        let supervisor = PumpDeadlineSupervisor::start().await;
        let pump_events = Arc::new(tokio::sync::Notify::new());
        duplex.shared.lock().unwrap().pump_events = Some(Arc::clone(&pump_events));

        // Admit one full packet. The slot returns its length once; the pump
        // then blocks on the zero allowance.
        let payload = vec![b'R'; super::MAX_ADMISSION_BYTES];
        let mut admit = Box::pin(duplex.write(&payload));
        let waker = futures_util::task::noop_waker();
        let mut context = std::task::Context::from_waker(&waker);
        assert!(matches!(
            admit.as_mut().poll(&mut context),
            Poll::Ready(Ok(count)) if count == payload.len()
        ));
        drop(admit);
        send_tx.send(()).unwrap();
        sent_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the peer never sent the reply-requiring event");

        // Wake the pump once through the application notification it already
        // supports. The peer's bytes are buffered now, so this cannot stand in
        // for reading them: the pump still has to read and arm.
        duplex.notify.notify_one();

        // Wait for the pump's arm observation, not for a scheduler slice. The
        // wall bound separates a slow scheduler from a missing arm; the counts
        // are reported as facts, not as a deduced root cause.
        let arm_baseline = duplex.shared.lock().unwrap().pump_calls;
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        let first_arm = loop {
            if let Some(at) = duplex.shared.lock().unwrap().reply_stall.armed_at() {
                break at;
            }
            if await_pump_event(&pump_events, &deadline).await {
                continue;
            }
            if let Some(at) = duplex.shared.lock().unwrap().reply_stall.armed_at() {
                break at;
            }
            let state = duplex.shared.lock().unwrap();
            let steps = state.pump_calls.saturating_sub(arm_baseline);
            let total = state.pump_calls;
            panic!(
                "the pump did not arm the write-stall bound within {PUMP_EVENT_BOUND:?} of wall time: steps_this_phase={steps} steps_total={total} closed={} failure={:?} reply={} data={} rekey={} progress={} outbound={} pump_finished={}",
                state.closed,
                state.failure,
                state.established.reply_outstanding(),
                state.established.data_active(),
                state.established.rekey_active(),
                progress.load(Ordering::Relaxed),
                state.outbound.len(),
                duplex.pump.is_finished()
            );
        };
        supervisor.cancel_deadline();
        {
            let state = duplex.shared.lock().unwrap();
            assert!(!state.closed);
            assert!(state.failure.is_none());
            assert_eq!(state.reply_stall.armed_at(), Some(first_arm));
        }
        assert_eq!(
            progress.load(Ordering::Relaxed),
            0,
            "the initially armed pump had already written bytes"
        );

        // Advance to just before the original deadline and grant a positive
        // partial write. The pump must restart the clock at the write.
        tokio::time::advance(bound.saturating_sub(Duration::from_millis(10))).await;
        let restart_baseline = duplex.shared.lock().unwrap().pump_calls;
        let progress_before = progress.load(Ordering::Relaxed);
        *allowance.lock().unwrap() = 8 * 1024;
        duplex.notify.notify_one();
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        let second_arm = loop {
            if progress.load(Ordering::Relaxed) > progress_before
                && let Some(at) = duplex.shared.lock().unwrap().reply_stall.armed_at()
                && at > first_arm
            {
                break at;
            }
            if await_pump_event(&pump_events, &deadline).await {
                continue;
            }
            if progress.load(Ordering::Relaxed) > progress_before
                && let Some(at) = duplex.shared.lock().unwrap().reply_stall.armed_at()
                && at > first_arm
            {
                break at;
            }
            let state = duplex.shared.lock().unwrap();
            let steps = state.pump_calls.saturating_sub(restart_baseline);
            let total = state.pump_calls;
            panic!(
                "the granted partial write did not restart the write-stall bound within {PUMP_EVENT_BOUND:?} of wall time: steps_this_phase={steps} steps_total={total} progress={} armed_at={:?} closed={} failure={:?}",
                progress.load(Ordering::Relaxed),
                state.reply_stall.armed_at(),
                state.closed,
                state.failure
            );
        };
        supervisor.cancel_deadline();
        *allowance.lock().unwrap() = 0;

        // Advance just past the original deadline. Wake the pump before
        // awaiting it: the paused runtime only auto-advances when no task is
        // ready, so making the pump ready is the explicit barrier that keeps
        // the clock from jumping to the renewed deadline. Require a real pump
        // observation at or after the original deadline and before the renewed
        // one before asserting the session is still open.
        let original_deadline = first_arm + bound;
        let renewed_deadline = second_arm + bound;
        let observation_baseline = duplex.shared.lock().unwrap().pump_calls;
        tokio::time::advance(Duration::from_millis(20)).await;
        duplex.notify.notify_one();
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        loop {
            {
                let state = duplex.shared.lock().unwrap();
                if state.pump_calls > observation_baseline
                    && let Some(at) = state.reply_stall.last_observed_at()
                    && at >= original_deadline
                {
                    assert!(
                        at < renewed_deadline,
                        "the paused clock advanced past the renewed deadline before the pump observed it: observed={at:?} renewed={renewed_deadline:?}"
                    );
                    break;
                }
            }
            if await_pump_event(&pump_events, &deadline).await {
                continue;
            }
            {
                let state = duplex.shared.lock().unwrap();
                if state.pump_calls > observation_baseline
                    && let Some(at) = state.reply_stall.last_observed_at()
                    && at >= original_deadline
                {
                    assert!(
                        at < renewed_deadline,
                        "the paused clock advanced past the renewed deadline before the pump observed it: observed={at:?} renewed={renewed_deadline:?}"
                    );
                    break;
                }
                let steps = state.pump_calls.saturating_sub(observation_baseline);
                let total = state.pump_calls;
                panic!(
                    "the pump did not observe the session at or after the original deadline within {PUMP_EVENT_BOUND:?} of wall time: steps_this_phase={steps} steps_total={total} last_observed={:?} original_deadline={original_deadline:?} renewed_deadline={renewed_deadline:?} closed={} failure={:?}",
                    state.reply_stall.last_observed_at(),
                    state.closed,
                    state.failure
                );
            }
        }
        supervisor.cancel_deadline();
        {
            let state = duplex.shared.lock().unwrap();
            assert!(
                !state.closed,
                "the session failed at the original deadline despite partial progress"
            );
            assert!(state.failure.is_none());
            assert_eq!(
                state.reply_stall.armed_at(),
                Some(second_arm),
                "the original deadline observation changed the renewed arm"
            );
        }

        // Stop all writes and advance past the renewed inactivity bound
        // without notifying the pump. The deadline itself must wake the
        // readiness wait and fail the session; traffic is not the timer.
        let expiry_baseline = duplex.shared.lock().unwrap().pump_calls;
        tokio::time::advance(bound + Duration::from_millis(10)).await;
        let deadline = supervisor.deadline(PUMP_EVENT_BOUND);
        loop {
            if duplex.shared.lock().unwrap().closed {
                break;
            }
            if await_pump_event(&pump_events, &deadline).await {
                continue;
            }
            if duplex.shared.lock().unwrap().closed {
                break;
            }
            let state = duplex.shared.lock().unwrap();
            let steps = state.pump_calls.saturating_sub(expiry_baseline);
            let total = state.pump_calls;
            panic!(
                "the session did not fail closed within {PUMP_EVENT_BOUND:?} of wall time after the inactivity bound: steps_this_phase={steps} steps_total={total} closed={} failure={:?} armed_at={:?}",
                state.closed,
                state.failure,
                state.reply_stall.armed_at()
            );
        }
        supervisor.cancel_deadline();
        let (failed_at, failure) = {
            let state = duplex.shared.lock().unwrap();
            (
                state
                    .failed_at
                    .expect("the pump never recorded its failure time"),
                state.failure.clone(),
            )
        };
        assert!(
            failure
                .as_deref()
                .is_some_and(|failure| failure.contains(super::WRITE_STALL_MESSAGE)),
            "the session did not fail with the write-stall diagnostic: {failure:?}"
        );
        let elapsed = failed_at.duration_since(second_arm);
        assert!(
            elapsed >= bound,
            "the session failed before the inactivity bound: {elapsed:?}"
        );
        assert!(
            failed_at >= renewed_deadline,
            "the session failed before the renewed deadline: failed_at={failed_at:?} renewed_deadline={renewed_deadline:?}"
        );

        drop(duplex);
        server.join().expect("the peer panicked");
        supervisor.finish().await;
    }

    /// Cancelling while a retained peer rekey blocks the write still cancels
    /// the session. This exercises the synchronous `SharedDriver::pump_step`
    /// path, not the async pump task. The peer is supervised so it cannot
    /// outlive the parent if it does not stop.
    #[test]
    fn retained_peer_rekey_with_a_blocked_write_cancels() {
        if !pressure_child_or_supervise("retained_peer_rekey_with_a_blocked_write_cancels") {
            return;
        }
        retained_peer_rekey_with_a_blocked_write_cancels_body();
    }

    fn retained_peer_rekey_with_a_blocked_write_cancels_body() {
        use std::sync::Mutex;
        use std::sync::mpsc;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [132; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (rekey_tx, rekey_rx) = mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.transport_mut().begin_rekey().unwrap();
            let _ = rekey_tx.send(());
            let _ = connection.dispatch_one();
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guard_socket = socket.try_clone().unwrap();
        let control = crate::ssh_cancellation::EstablishmentControl::new(
            Instant::now() + Duration::from_secs(5),
        );
        let crate::ssh_connect::Dialed { guard, .. } =
            crate::ssh_connect::Dialed::test_connected(guard_socket, control).unwrap();
        let gate = Arc::new(Mutex::new(Gate { block_after: None }));
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(
                GatedSocket {
                    socket,
                    gate: Arc::clone(&gate),
                },
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let parts =
            super::authenticate_and_exec(transport, &methods, &options, WouldBlock::default())
                .unwrap();
        let mut shared = super::SharedDriver::new(
            crate::ssh_worker::Established::test_wrap(parts, guard),
            super::InboundBuffer::default(),
        );

        gate.lock().unwrap().block_after = Some(0);
        assert!(matches!(
            shared.established.write(&vec![b'R'; 1_024]),
            Ok(super::Progress::Wrote(1_024))
        ));
        rekey_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the peer never sent its rekey");
        for _ in 0..100 {
            if shared.established.rekey_active() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
            let _ = shared.pump_step();
        }
        assert!(shared.established.rekey_active());

        let control = shared.established.control();
        drop(shared);
        assert!(
            control.is_cancelled(),
            "dropping a session blocked on a retained rekey did not cancel it"
        );
        server.join().expect("the peer panicked");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One controlled peer checks bounded rekey progress.
    async fn pump_yields_under_sustained_ignored_packets() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use crate::ssh_worker::supervise;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [124; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (rekey_started_tx, rekey_started_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer_non_strict(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.transport_mut().begin_rekey().unwrap();
            // These are valid protected IGNORE packets written after KEXINIT,
            // while the non-strict rekey is active.
            for _ in 0..(super::MAX_PROTOCOL_STEPS_PER_POLL * 3) {
                connection
                    .transport_mut()
                    .write_rekey_ignorable(b"ignored")
                    .unwrap();
            }
            let _ = rekey_started_tx.send(());
            while connection.transport_mut().rekey_active() {
                connection.transport_mut().advance_rekey().unwrap();
            }
            let _ = done_tx.send(());
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let dialed = Dialed::test_connected(socket, control).unwrap();
        let worker_options = options.clone();
        let established = supervise(
            dialed,
            Duration::from_secs(5),
            &crate::ssh_worker::WORKERS,
            move |socket, _control| {
                let known = super::load_known_hosts(&worker_options.known_hosts_path)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let methods = super::auth_methods(&worker_options.identity)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let transport = super::checked_handshake(
                    socket,
                    &known,
                    &worker_options.known_hosts_path,
                    &worker_options.host_token,
                    &worker_options.host,
                    worker_options.port,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                super::authenticate_and_exec(
                    transport,
                    &methods,
                    &worker_options,
                    WouldBlock::default(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(5), rekey_started_rx)
            .await
            .unwrap()
            .unwrap();
        let mut shared = super::SharedDriver::new(established, super::InboundBuffer::default());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut started = false;
        let mut yielded_active = false;
        let mut completed = false;
        while tokio::time::Instant::now() < deadline {
            let action = shared.pump_step();
            if shared.established.rekey_active() {
                started = true;
            }
            if started
                && matches!(action, super::PumpAction::Yield)
                && shared.established.rekey_active()
            {
                yielded_active = true;
            }
            if started && !shared.established.rekey_active() {
                completed = true;
                break;
            }
            match action {
                super::PumpAction::Closed => break,
                super::PumpAction::Yield
                | super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        assert!(started, "the client never started the rekey");
        assert!(
            yielded_active,
            "a bounded pump step never reported Yield while the rekey was active"
        );
        assert!(
            completed,
            "the rekey did not complete after the bounded steps"
        );
        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        drop(shared);
        server.join().unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One controlled peer checks completion, queued write, and bytes.
    async fn pump_writes_queued_data_when_rekey_completes_without_a_read_wake() {
        use crate::ssh_cancellation::EstablishmentControl;
        use crate::ssh_connect::Dialed;
        use crate::ssh_worker::supervise;
        use std::time::Instant;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [125; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let queued = b"queued-during-rekey".to_vec();
        let queued_len = queued.len();
        let expected = queued.clone();
        let (received_tx, received_rx) = std::sync::mpsc::channel();
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let result = (|| -> Result<(), String> {
                let session = confirm_peer_session(connection);
                accept_exec(connection, session);
                connection
                    .transport_mut()
                    .begin_rekey()
                    .map_err(|error| error.to_string())?;
                // Hold the peer at its KEXINIT until the test has queued
                // application bytes while the client rekey is active.
                continue_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|error| error.to_string())?;
                while connection.transport_mut().rekey_active() {
                    connection
                        .transport_mut()
                        .advance_rekey()
                        .map_err(|error| error.to_string())?;
                }
                connection
                    .write_data(session, b"peer-after-rekey")
                    .map_err(|error| error.to_string())?;
                connection
                    .transport_mut()
                    .write_payload(&global_request(true))
                    .map_err(|error| error.to_string())?;
                connection
                    .write_data(session, b"peer-after-rekey-2")
                    .map_err(|error| error.to_string())?;
                let mut client_data = Vec::new();
                let mut failures = 0;
                while client_data.len() < queued_len || failures == 0 {
                    match connection
                        .dispatch_one()
                        .map_err(|error| error.to_string())?
                    {
                        neotales_ssh::channel::ChannelEvent::Data { data, .. } => {
                            client_data.extend(data);
                        }
                        neotales_ssh::channel::ChannelEvent::GlobalRequestFailed { .. } => {
                            failures += 1;
                        }
                        other => return Err(format!("unexpected client event: {other:?}")),
                    }
                }
                if failures != 1 {
                    return Err(format!("control reply count was {failures}"));
                }
                received_tx
                    .send(client_data)
                    .map_err(|error| error.to_string())?;
                Ok(())
            })();
            let _ = done_tx.send(result);
        });

        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(10));
        let dialed = Dialed::test_connected(socket, control).unwrap();
        let worker_options = options.clone();
        let established = supervise(
            dialed,
            Duration::from_secs(10),
            &crate::ssh_worker::WORKERS,
            move |socket, _control| {
                let known = super::load_known_hosts(&worker_options.known_hosts_path)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let methods = super::auth_methods(&worker_options.identity)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                let transport = super::checked_handshake(
                    socket,
                    &known,
                    &worker_options.known_hosts_path,
                    &worker_options.host_token,
                    &worker_options.host,
                    worker_options.port,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                super::authenticate_and_exec(
                    transport,
                    &methods,
                    &worker_options,
                    WouldBlock::default(),
                )
                .map_err(|error| std::io::Error::other(error.to_string()))
            },
        )
        .await
        .unwrap();

        let mut shared = super::SharedDriver::new(established, super::InboundBuffer::default());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline && !shared.established.rekey_active() {
            match shared.pump_step() {
                super::PumpAction::Closed => break,
                super::PumpAction::Yield
                | super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        assert!(
            shared.established.rekey_active(),
            "the client did not start the peer rekey"
        );
        // The application accepted these bytes while the rekey was active.
        shared.outbound = queued;
        continue_tx.send(()).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut completed = false;
        while tokio::time::Instant::now() < deadline {
            let before = shared.established.rekey_active();
            let action = shared.pump_step();
            let after = shared.established.rekey_active();
            if before && !after {
                completed = true;
                assert!(
                    !matches!(action, super::PumpAction::WaitRead) || shared.outbound.is_empty(),
                    "rekey completion waited for a read with application bytes queued"
                );
            }
            if completed && shared.outbound.is_empty() {
                break;
            }
            match action {
                super::PumpAction::Closed => break,
                super::PumpAction::Yield
                | super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        assert!(completed, "the rekey did not complete");
        assert!(shared.outbound.is_empty(), "queued data was not written");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut done = false;
        while tokio::time::Instant::now() < deadline {
            match done_rx.try_recv() {
                Ok(Ok(())) => {
                    done = true;
                    break;
                }
                Ok(Err(error)) => panic!("controlled peer failed: {error}"),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    panic!("controlled peer ended without a result")
                }
            }
            let action = shared.pump_step();
            match done_rx.try_recv() {
                Ok(Ok(())) => {
                    done = true;
                    break;
                }
                Ok(Err(error)) => panic!("controlled peer failed: {error}"),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    panic!("controlled peer ended without a result")
                }
            }
            match action {
                super::PumpAction::Closed => break,
                super::PumpAction::Yield
                | super::PumpAction::WaitRead
                | super::PumpAction::WaitWrite
                | super::PumpAction::WaitReadWrite
                | super::PumpAction::WaitNotify => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
        assert!(
            done,
            "the peer did not receive the queued data and control reply; closed={} failure={:?}",
            shared.closed, shared.failure
        );
        let inbound: Vec<u8> = shared.inbound.bytes.iter().copied().collect();
        assert_eq!(inbound, b"peer-after-rekeypeer-after-rekey-2");
        let received = received_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("peer did not receive the queued data");
        assert_eq!(received, expected);
        drop(shared);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn sustained_control_traffic_still_delivers_data() {
        use tokio::io::AsyncReadExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [122; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            for _ in 0..(super::MAX_PROTOCOL_STEPS_PER_POLL * 3) {
                connection
                    .transport_mut()
                    .write_payload(&global_request(false))
                    .unwrap();
            }
            connection.write_data(session, b"after-control").unwrap();
            let _ = done_tx.send(());
        });

        let mut duplex = super::open_supervised(&options).await.unwrap();
        let mut received = [0_u8; 13];
        tokio::time::timeout(Duration::from_secs(5), duplex.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"after-control");
        drop(duplex);
        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_answers_peer_global_requests_before_accepting_exec() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [111; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            // A current OpenSSH sends its post-authentication global requests
            // before the client's channel is confirmed, which is the order this
            // test exercises.
            connection
                .transport_mut()
                .write_payload(&global_request(false))
                .unwrap();
            connection
                .transport_mut()
                .write_payload(&global_request(true))
                .unwrap();
            let session = confirm_peer_session(connection);
            let mut failures = 0;
            let mut executed = false;
            while !executed || failures == 0 {
                match connection.dispatch_one().unwrap() {
                    neotales_ssh::channel::ChannelEvent::Request {
                        request_type,
                        want_reply: true,
                        ..
                    } if request_type == b"exec" => {
                        connection.send_request_success(session).unwrap();
                        executed = true;
                    }
                    neotales_ssh::channel::ChannelEvent::GlobalRequestFailed { .. } => {
                        failures += 1;
                    }
                    _ => {}
                }
            }
            let _ = done_tx.send(failures);
        });
        let duplex = super::open_supervised(&options).await;
        assert!(duplex.is_ok(), "setup failed: {:?}", duplex.err());
        drop(duplex);
        let failures = tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            failures, 1,
            "the client answered a global request that did not ask for a reply, or lost the one that did"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_refuses_a_reply_required_channel_request() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [112; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            connection
                .send_request(session, b"x-test@example.com", true, &[])
                .unwrap();
            let mut refused = false;
            let mut executed = false;
            while !executed || !refused {
                match connection.dispatch_one().unwrap() {
                    neotales_ssh::channel::ChannelEvent::Request {
                        request_type,
                        want_reply: true,
                        ..
                    } if request_type == b"exec" => {
                        connection.send_request_success(session).unwrap();
                        executed = true;
                    }
                    neotales_ssh::channel::ChannelEvent::RequestFailed { channel }
                        if channel == session =>
                    {
                        refused = true;
                    }
                    _ => {}
                }
            }
            let _ = done_tx.send(refused);
        });
        let duplex = super::open_supervised(&options).await;
        assert!(duplex.is_ok(), "setup failed: {:?}", duplex.err());
        drop(duplex);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done_rx)
                .await
                .unwrap()
                .unwrap()
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_rejects_an_incoming_peer_open() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [113; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            connection.open_channel(1, b"forwarded-tcpip", &[]).unwrap();
            let mut rejected = false;
            let mut executed = false;
            while !executed || !rejected {
                match connection.dispatch_one().unwrap() {
                    neotales_ssh::channel::ChannelEvent::Request {
                        request_type,
                        want_reply: true,
                        ..
                    } if request_type == b"exec" => {
                        connection.send_request_success(session).unwrap();
                        executed = true;
                    }
                    neotales_ssh::channel::ChannelEvent::OpenFailed {
                        channel: 1, reason, ..
                    } => {
                        assert_eq!(
                            reason,
                            neotales_ssh::channel::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
                        );
                        rejected = true;
                    }
                    _ => {}
                }
            }
            let _ = done_tx.send(rejected);
        });
        let duplex = super::open_supervised(&options).await;
        assert!(duplex.is_ok(), "setup failed: {:?}", duplex.err());
        drop(duplex);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), done_rx)
                .await
                .unwrap()
                .unwrap()
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_preserves_data_the_peer_sends_before_exec_is_accepted() {
        use tokio::io::AsyncReadExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [114; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            connection.write_data(session, b"early-bytes").unwrap();
            accept_exec(connection, session);
            let _ = done_tx.send(());
        });
        let mut duplex = super::open_supervised(&options).await.unwrap();
        let mut received = [0_u8; 11];
        tokio::time::timeout(Duration::from_secs(2), duplex.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"early-bytes");
        drop(duplex);
        tokio::time::timeout(Duration::from_secs(5), done_rx)
            .await
            .unwrap()
            .unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_fails_explicitly_when_the_peer_closes_before_exec() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [115; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            loop {
                match connection.dispatch_one().unwrap() {
                    neotales_ssh::channel::ChannelEvent::Request { request_type, .. }
                        if request_type == b"exec" =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
            connection.send_close(session).unwrap();
            let _ = connection.dispatch_one();
        });
        let Err(error) = super::open_supervised(&options).await else {
            panic!("setup succeeded after the peer closed the channel");
        };
        assert!(
            error
                .to_string()
                .contains(super::ESTABLISHMENT_FAILURE_MESSAGE)
        );
        assert!(!error.is_managed_ssh_authentication_rejected());
        assert_eq!(error.transport_timeout_kind(), None);
        assert_eq!(error.managed_ssh_host_key_rejection(), None);
        assert_establishment_diagnostics_are_content_free(&error, &options);
        server.join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_setup_closes_the_socket() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [116; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = raw_peer(signer, listener, move |connection| {
            match connection.dispatch_one() {
                Ok(neotales_ssh::channel::ChannelEvent::OpenRequest(_)) => {}
                other => panic!("expected a session channel open: {other:?}"),
            }
            let _ = reached_tx.send(());
            let closed = connection.dispatch_one().is_err();
            let _ = closed_tx.send(closed);
        });
        let task = tokio::spawn(async move { super::open_supervised(&options).await });
        tokio::time::timeout(Duration::from_secs(3), reached_rx)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap(),
                Err(error) if error.is_cancelled()
            ),
            "the setup task did not cancel"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(3), closed_rx)
                .await
                .unwrap()
                .unwrap(),
            "the peer did not observe the cancelled socket close"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_completes_normal_auth_channel_and_exec() {
        use tokio::io::AsyncReadExt as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [117; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            connection.write_data(session, b"OK").unwrap();
            let _ = connection.dispatch_one();
        });
        let mut duplex = super::open_supervised(&options).await.unwrap();
        let mut received = [0_u8; 2];
        tokio::time::timeout(Duration::from_secs(2), duplex.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"OK");
        drop(duplex);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn setup_refuses_to_hand_a_pending_peer_open_to_the_owned_driver() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [118; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let server = raw_peer(signer, listener, move |connection| {
            connection.open_channel(0, b"forwarded-tcpip", &[]).unwrap();
            let _ = connection.dispatch_one();
        });
        let socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let transport = neotales_ssh::client::ClientConfig::new()
            .connect(socket, |_| Ok::<(), ()>(()))
            .unwrap();
        let methods = super::auth_methods(&options.identity).unwrap();
        let transport = super::authenticate(transport, &methods, &options).unwrap();
        let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
        match connection.dispatch_one().unwrap() {
            neotales_ssh::channel::ChannelEvent::OpenRequest(_) => {}
            other => panic!("expected a peer channel open: {other:?}"),
        }
        let Err(error) = super::into_driver(connection) else {
            panic!("the driver accepted a connection with a pending peer open");
        };
        assert!(
            error
                .to_string()
                .contains("inbound open or unanswered close remained after setup"),
            "unexpected refusal: {error}"
        );
        server.join().unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Each route uses the same controlled SSH/HTTP fixture.
    async fn public_raw_and_facade_use_supervised_ssh_and_enforce_trust() {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent, SessionRequest},
        };
        use std::{
            net::TcpListener,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            thread,
        };

        for raw in [true, false] {
            for scenario in ["known", "unknown", "changed"] {
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("known_hosts");
                let signer = Ed25519Signer::from_seed(&mut [91; 32]);
                let other = Ed25519Signer::from_seed(&mut [92; 32]);
                let public = if scenario == "changed" {
                    other.public_key()
                } else {
                    signer.public_key()
                };
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(public.to_blob().unwrap());
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let contents = if scenario == "unknown" {
                    "# empty trust\n".to_owned()
                } else {
                    format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port())
                };
                std::fs::write(&path, &contents).unwrap();
                let client = crate::DockerClient::connect_ssh_managed(
                    &format!("ssh://fixture@{address}"),
                    &path,
                )
                .timeout(Duration::from_secs(3))
                .password("synthetic-test".into())
                .connect()
                .unwrap();
                let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                let server = thread::spawn(move || {
                    let (peer, _) = listener.accept().unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    peer.set_write_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let result = ServerConfig::new(signer).connect(peer);
                    let Ok(mut transport) = result else {
                        let _ = done_tx.send(false);
                        return;
                    };
                    let policy = ServerAuthPolicy::new(2)
                        .unwrap()
                        .with_password_callback(|_| true);
                    authenticate_server(&mut transport, &policy).unwrap();
                    let mut sessions =
                        ServerSessions::with_policy(transport, |request| match request {
                            SessionRequest::Exec { command }
                                if command == b"docker system dial-stdio" =>
                            {
                                SessionDecision::accept(0)
                            }
                            _ => SessionDecision::reject(),
                        });
                    let session = match sessions.dispatch_one().unwrap() {
                        SessionEvent::Opened { session } => session,
                        other => panic!("expected channel open: {other:?}"),
                    };
                    assert!(matches!(
                        sessions.dispatch_one().unwrap(),
                        SessionEvent::Request { accepted: true, .. }
                    ));
                    let mut request = Vec::new();
                    loop {
                        match sessions.dispatch_one().unwrap() {
                            SessionEvent::Data { data, .. } => {
                                request.extend_from_slice(&data);
                                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            other => panic!("expected HTTP request bytes: {other:?}"),
                        }
                    }
                    assert!(request.starts_with(b"GET /"));
                    assert!(
                        request
                            .windows(b"/_ping HTTP/1.1\r\n".len())
                            .any(|window| window == b"/_ping HTTP/1.1\r\n")
                    );
                    sessions
                        .send_data(
                            session,
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .unwrap();
                    let _ = done_tx.send(true);
                });
                let native_calls = Arc::new(AtomicUsize::new(0));
                let outcome = super::TEST_NATIVE_CALLS
                    .scope(Arc::clone(&native_calls), async {
                        tokio::time::timeout(Duration::from_secs(4), async {
                            if raw {
                                crate::raw::ping(&client.raw_engine().unwrap())
                                    .await
                                    .map(|_| ())
                            } else {
                                client.ping().await.map(|_| ())
                            }
                        })
                        .await
                        .expect("public request did not finish")
                    })
                    .await;
                if scenario == "known" {
                    assert!(outcome.is_ok(), "known key failed: {outcome:?}");
                } else {
                    let error = outcome.expect_err("untrusted key was accepted");
                    assert_eq!(
                        error.managed_ssh_host_key_rejection(),
                        Some(if scenario == "unknown" {
                            crate::ManagedSshHostKeyRejection::Unknown
                        } else {
                            crate::ManagedSshHostKeyRejection::Changed
                        }),
                        "unrelated failure: {error}"
                    );
                }
                assert_eq!(native_calls.load(Ordering::SeqCst), 0);
                let http_answered = tokio::time::timeout(Duration::from_secs(4), done_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(http_answered, scenario == "known");
                server.join().unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
            }
        }
    }

    const RESPONSE_CANARY: &str = "synthetic-managed-response-secret-do-not-log";

    fn assert_response_diagnostic(
        error: &crate::Error,
        managed: bool,
        operation: &str,
        status: u16,
    ) {
        use std::error::Error as _;
        let api = error.api_error().expect("HTTP status was lost");
        assert_eq!(api.status_code, status);
        let expected = format!(
            "managed SSH Engine {operation} operation failed (HTTP {status}); response text withheld"
        );
        let mut rendered = vec![
            format!("{error}"),
            format!("{error:?}"),
            api.message.clone(),
        ];
        let mut source = error.source();
        while let Some(error) = source {
            rendered.extend([format!("{error}"), format!("{error:?}")]);
            source = error.source();
        }
        for text in rendered {
            if managed {
                assert!(!text.contains(RESPONSE_CANARY), "peer text leaked: {text}");
                assert!(text.contains(&expected), "fixed diagnostic lost: {text}");
            } else {
                assert!(
                    text.contains(RESPONSE_CANARY),
                    "control lost peer text: {text}"
                );
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Shared controlled peer pins the raw, facade and default routes.
    async fn response_rejection_case(operation: &'static str, managed: bool) {
        use crate::raw::{RawBody, RawEngine, RawRequest, RawTarget};
        use neotales_ssh::channel::ChannelEvent;
        use std::io::{Read as _, Write as _};

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [93; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_directory, options) = options_for_peer(address, &signer);
        let response = move |request: &[u8]| {
            if operation == "POST" {
                assert!(
                    request
                        .windows(RESPONSE_CANARY.len())
                        .any(|part| part == RESPONSE_CANARY.as_bytes())
                );
            }
            // Echo the request as well as the canary, as an untrusted daemon can.
            let (status, body) = if matches!(operation, "PUSH" | "LOAD") {
                (
                    "200 OK",
                    serde_json::json!({"errorDetail": {"message": RESPONSE_CANARY}}).to_string(),
                )
            } else {
                ("500 Internal Server Error", serde_json::json!({
                    "message": format!("{RESPONSE_CANARY}: {}", String::from_utf8_lossy(request))
                }).to_string())
            };
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let server = if managed {
            raw_peer(signer, listener, move |connection| {
                let session = confirm_peer_session(connection);
                accept_exec(connection, session);
                let mut request = Vec::new();
                loop {
                    if let ChannelEvent::Data { data, .. } = connection.dispatch_one().unwrap() {
                        request.extend_from_slice(&data);
                        if request.windows(4).any(|part| part == b"\r\n\r\n")
                            && (operation != "POST"
                                || request.ends_with(RESPONSE_CANARY.as_bytes()))
                        {
                            break;
                        }
                    }
                }
                connection
                    .write_data(session, response(&request).as_bytes())
                    .unwrap();
            })
        } else {
            std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut bytes = [0; 4096];
                    let count = socket.read(&mut bytes).unwrap();
                    assert_ne!(count, 0);
                    request.extend_from_slice(&bytes[..count]);
                    if request.windows(4).any(|part| part == b"\r\n\r\n")
                        && (operation != "POST" || request.ends_with(RESPONSE_CANARY.as_bytes()))
                    {
                        break;
                    }
                }
                socket.write_all(response(&request).as_bytes()).unwrap();
            })
        };
        let target = if managed {
            super::managed_ssh_target(options)
        } else {
            RawTarget::Tcp {
                host: address.ip().to_string(),
                port: address.port(),
            }
        };
        let engine = RawEngine::new(target.clone(), crate::API_VERSION);
        // Raw operations deliberately include an arbitrary extension route. The
        // managed policy must not depend on a facade operation allowlist.
        let result = async {
            match operation {
                "GET" => crate::raw::version(&engine).await.map(|_| ()),
                "POST" => {
                    let request = RawRequest::new(http::Method::POST, "/extension").with_body(
                        RawBody::Bytes(bytes::Bytes::from_static(RESPONSE_CANARY.as_bytes())),
                    );
                    crate::raw::engine_result(engine.send(request).await?)
                        .await
                        .map(|_| ())
                }
                "STREAM" => crate::raw::events(&engine, &crate::EventOptions::default())
                    .await
                    .map(|_| ()),
                "PUSH" => crate::raw::image_push_document(
                    &engine,
                    "example",
                    &crate::ImagePushOptions::default(),
                    crate::raw::RegistryAuth::none(),
                )
                .await
                .map(|_| ()),
                "LOAD" => {
                    let client = crate::DockerClient::from_target(
                        crate::OwnedTarget::Reachable(target),
                        crate::ProxyPolicy::Direct,
                        crate::API_VERSION,
                    );
                    let input = futures_util::stream::empty::<Result<Vec<u8>, std::io::Error>>();
                    let mut stream = client
                        .load_image(input, None, crate::ImageTransferLimits::default())
                        .unwrap();
                    stream
                        .next()
                        .await
                        .expect("missing failure record")
                        .map(|_| ())
                }
                _ => unreachable!(),
            }
        }
        .await;
        let error = result.expect_err("peer rejection was accepted");
        // Default load records carry StreamError rather than DockerApiError.
        if !managed && operation == "LOAD" {
            use std::error::Error as _;
            assert!(
                error
                    .source()
                    .unwrap()
                    .to_string()
                    .contains(RESPONSE_CANARY)
            );
        } else {
            assert_response_diagnostic(
                &error,
                managed,
                if matches!(operation, "POST" | "PUSH" | "LOAD") {
                    "POST"
                } else {
                    "GET"
                },
                if matches!(operation, "PUSH" | "LOAD") {
                    200
                } else {
                    500
                },
            );
        }
        server.join().unwrap();
    }

    #[tokio::test]
    async fn managed_read_withholds_peer_rejection_and_default_read_preserves_it() {
        for managed in [true, false] {
            response_rejection_case("GET", managed).await;
        }
    }

    #[tokio::test]
    async fn managed_mutation_withholds_echoed_request_and_default_mutation_preserves_it() {
        for managed in [true, false] {
            response_rejection_case("POST", managed).await;
        }
    }

    #[tokio::test]
    async fn managed_stream_withholds_peer_rejection_and_default_stream_preserves_it() {
        for managed in [true, false] {
            response_rejection_case("STREAM", managed).await;
        }
    }

    #[tokio::test]
    async fn managed_in_band_failures_use_route_policy_in_raw_and_facade_decoders() {
        for operation in ["PUSH", "LOAD"] {
            for managed in [true, false] {
                response_rejection_case(operation, managed).await;
            }
        }
    }

    #[tokio::test]
    async fn managed_response_policy_preserves_the_typed_request_deadline() {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [96; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (_directory, mut options) = options_for_peer(listener.local_addr().unwrap(), &signer);
        options.request_deadline = Some(Duration::from_millis(500));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = raw_peer(signer, listener, move |connection| {
            let session = confirm_peer_session(connection);
            accept_exec(connection, session);
            // Read the request but withhold the response until the test
            // releases the peer after observing the typed deadline.
            loop {
                match connection.dispatch_one() {
                    Ok(neotales_ssh::channel::ChannelEvent::Data { .. }) => break,
                    Err(error) => panic!("request did not reach peer: {error}"),
                    _ => {}
                }
            }
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let client = crate::DockerClient::connect_ssh_managed_inner(options).unwrap();
        let error = client.ping().await.unwrap_err();
        assert!(
            error.is_transport_deadline(),
            "typed deadline lost: {error:?}"
        );
        assert_timeout_kind(&error, crate::TransportTimeoutKind::RequestDeadline);
        assert!(error.to_string().contains("timed out after"));
        assert!(error.api_error().is_none());
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn managed_host_key_refusal_classifications_survive_public_route() {
        host_key_classifications_for_operation("ping").await;
    }

    const ESTABLISHMENT_CANARY: &str = "peer-establishment-canary-authentication-rejected-86cf";

    /// Generated identity container; no external key or key-generation tool.
    fn write_marker_identity(path: &Path) {
        let seed = [92; 32];
        let mut signing_seed = seed;
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut signing_seed);
        let point = signer.public_key().as_bytes();
        let mut private = neotales_ssh::Writer::new();
        private.write_uint32(9);
        private.write_uint32(9);
        private.write_string("ssh-ed25519").unwrap();
        private.write_string(point).unwrap();
        let mut secret = seed.to_vec();
        secret.extend_from_slice(point);
        private.write_string(&secret).unwrap();
        private.write_string(ESTABLISHMENT_CANARY).unwrap();
        let mut section = private.into_bytes();
        for byte in 1..=(8 - section.len() % 8) % 8 {
            section.push(u8::try_from(byte).unwrap());
        }
        let mut outer = neotales_ssh::Writer::new();
        outer.write_string("none").unwrap();
        outer.write_string("none").unwrap();
        outer.write_string(b"").unwrap();
        outer.write_uint32(1);
        outer
            .write_string(&signer.public_key().to_blob().unwrap())
            .unwrap();
        outer.write_string(&section).unwrap();
        let mut bytes = b"openssh-key-v1\0".to_vec();
        bytes.extend_from_slice(outer.as_bytes());
        std::fs::write(path, bytes).unwrap();
    }

    async fn refused_establishment_case(operation: &str, failure: &'static str) -> crate::Error {
        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [91; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (directory, mut options) = options_for_peer(address, &signer);
        if matches!(
            failure,
            "incompatible-algorithms" | "missing-identity" | "malformed-identity"
        ) {
            let path = directory.path().join("identity");
            if failure == "incompatible-algorithms" {
                write_marker_identity(&path);
                super::public_key_signer(&path, None).expect("valid generated identity");
            } else if failure == "malformed-identity" {
                std::fs::write(&path, ESTABLISHMENT_CANARY).unwrap();
            }
            options.identity = SshIdentity::KeyFile(path);
        }
        let client = crate::DockerClient::connect_ssh_managed(
            &format!("ssh://fixture@{address}"),
            &options.known_hosts_path,
        )
        .timeout(options.establishment_timeout)
        .identity(options.identity.clone())
        .connect()
        .unwrap();
        let server = spawn_establishment_failure_peer(listener, signer, failure);
        let error =
            tokio::time::timeout(Duration::from_secs(6), marker_request(&client, operation))
                .await
                .expect("establishment failed to settle")
                .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::Transport);
        assert!(
            error.api_error().is_none(),
            "no Engine HTTP status was received"
        );
        assert_eq!(error.transport_timeout_kind(), None);
        assert_eq!(error.managed_ssh_host_key_rejection(), None);
        assert_establishment_diagnostics_are_content_free(&error, &options);
        error
    }

    fn spawn_establishment_failure_peer(
        listener: std::net::TcpListener,
        signer: neotales_ssh::hostkey::Ed25519Signer,
        failure: &'static str,
    ) -> std::thread::JoinHandle<()> {
        use neotales_ssh::auth::{
            ServerAuthPolicy, ServerAuthStep, ServerAuthenticator, authenticate_server,
        };
        use std::io::Read as _;
        std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            if matches!(failure, "missing-identity" | "malformed-identity") {
                let mut received = Vec::new();
                peer.read_to_end(&mut received).unwrap();
                assert!(
                    received.is_empty(),
                    "invalid identity was used for a handshake"
                );
                return;
            }
            let mut transport = neotales_ssh::server::ServerConfig::new(signer)
                .connect(peer)
                .unwrap();
            if failure == "malformed-auth" {
                assert_eq!(transport.read_payload().unwrap()[0], 5);
                // An invalid service name tests a protocol failure, not refusal.
                let mut packet = neotales_ssh::Writer::new();
                packet.write_byte(6);
                packet
                    .write_string(ESTABLISHMENT_CANARY.as_bytes())
                    .unwrap();
                transport.write_payload(packet.as_bytes()).unwrap();
            } else {
                let mut policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(move |_| failure != "auth-rejected")
                    .with_banner(ESTABLISHMENT_CANARY, "en");
                if failure == "incompatible-algorithms" {
                    policy = policy.with_signature_algorithms(&["rsa-sha2-256"]).unwrap();
                }
                if matches!(failure, "auth-rejected" | "incompatible-algorithms") {
                    let mut auth = ServerAuthenticator::new(&mut transport, &policy);
                    assert_eq!(auth.step().unwrap(), ServerAuthStep::ServiceAccepted);
                    if failure == "auth-rejected" {
                        assert_eq!(auth.step().unwrap(), ServerAuthStep::Failure);
                    } else {
                        drop(auth);
                        assert!(
                            transport.read_payload().is_err(),
                            "the client offered a method despite incompatible signature algorithms"
                        );
                    }
                } else {
                    authenticate_server(&mut transport, &policy).unwrap();
                    let mut connection = neotales_ssh::channel::ChannelConnection::new(transport);
                    let neotales_ssh::channel::ChannelEvent::OpenRequest(request) =
                        connection.dispatch_one().unwrap()
                    else {
                        panic!("expected channel open")
                    };
                    connection
                        .reject_open(
                            request.sender_channel(),
                            neotales_ssh::channel::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                            ESTABLISHMENT_CANARY.as_bytes(),
                            ESTABLISHMENT_CANARY.as_bytes(),
                        )
                        .unwrap();
                }
            }
        })
    }

    fn assert_establishment_diagnostics_are_content_free(
        error: &crate::Error,
        options: &ManagedSshOptions,
    ) {
        use std::error::Error as _;
        let mut diagnostics = vec![format!("{error}"), format!("{error:?}")];
        let mut source = error.source();
        while let Some(cause) = source {
            diagnostics.extend([format!("{cause}"), format!("{cause:?}")]);
            source = cause.source();
        }
        for text in diagnostics {
            for forbidden in [
                ESTABLISHMENT_CANARY,
                RESPONSE_CANARY,
                &options.host_token,
                &options.known_hosts_path.display().to_string(),
            ] {
                assert!(
                    !text.contains(forbidden),
                    "establishment diagnostic leaked: {text}"
                );
            }
            if let SshIdentity::KeyFile(path) | SshIdentity::EncryptedKeyFile { path, .. } =
                &options.identity
            {
                assert!(
                    !text.contains(&path.display().to_string()),
                    "identity path leaked: {text}"
                );
            }
        }
    }

    #[tokio::test]
    async fn managed_channel_open_description_is_withheld_in_public_facade_and_raw_routes() {
        for operation in ["ping", "raw-ping", "registry-auth"] {
            let error = refused_establishment_case(operation, "open-failed").await;
            assert!(!error.is_managed_ssh_authentication_rejected());
            assert_eq!(
                error.managed_ssh_establishment_failure(),
                Some(crate::ManagedSshEstablishmentFailure::ChannelOpenRefused)
            );
        }
    }

    #[tokio::test]
    async fn managed_incompatible_algorithms_do_not_claim_authentication_rejection() {
        for operation in ["ping", "raw-ping", "registry-auth", "plugin-set"] {
            let error = refused_establishment_case(operation, "incompatible-algorithms").await;
            assert!(
                !error.is_managed_ssh_authentication_rejected(),
                "{operation}: {error:?}"
            );
            assert_eq!(
                error.managed_ssh_establishment_failure(),
                Some(crate::ManagedSshEstablishmentFailure::NoUsableAuthenticationMethod)
            );
        }
    }

    #[tokio::test]
    async fn managed_channel_refusal_is_distinct_from_protocol_and_identity_failures() {
        use crate::ManagedSshEstablishmentFailure::{ChannelOpenRefused, IdentityFile};
        for operation in ["ping", "raw-ping", "registry-auth"] {
            for (failure, expected) in [
                ("open-failed", Some(ChannelOpenRefused)),
                ("malformed-auth", None),
                ("missing-identity", Some(IdentityFile)),
                ("malformed-identity", Some(IdentityFile)),
            ] {
                let error = refused_establishment_case(operation, failure).await;
                assert_eq!(
                    error.managed_ssh_establishment_failure(),
                    expected,
                    "{operation}/{failure}"
                );
                assert!(!error.is_managed_ssh_authentication_rejected());
            }
        }
    }

    #[tokio::test]
    async fn managed_authentication_rejection_is_distinct_across_public_routes() {
        for operation in [
            "ping",
            "raw-ping",
            "registry-auth",
            "distribution",
            "plugin-set",
            "plugin-create",
            "plugin-install",
            "plugin-upgrade",
            "plugin-push",
            "swarm-unlock",
            "secret-remove",
            "container-attach",
        ] {
            for failure in ["auth-rejected", "open-failed", "malformed-auth"] {
                let error = refused_establishment_case(operation, failure).await;
                assert_eq!(
                    error.is_managed_ssh_authentication_rejected(),
                    failure == "auth-rejected",
                    "{operation}/{failure}: {error:?}"
                );
                let expected = match failure {
                    "auth-rejected" => {
                        Some(crate::ManagedSshEstablishmentFailure::AuthenticationRejected)
                    }
                    "open-failed" => {
                        Some(crate::ManagedSshEstablishmentFailure::ChannelOpenRefused)
                    }
                    _ => None,
                };
                assert_eq!(error.managed_ssh_establishment_failure(), expected);
            }
        }
    }

    #[tokio::test]
    async fn managed_plugin_operations_preserve_all_host_key_classifications() {
        for operation in [
            "plugin-set",
            "plugin-create",
            "plugin-list",
            "plugin-inspect",
            "plugin-remove",
            "plugin-enable",
            "plugin-disable",
            "plugin-privileges",
            "plugin-install",
            "plugin-upgrade",
            "plugin-push",
        ] {
            host_key_classifications_for_operation(operation).await;
        }
    }

    #[tokio::test]
    async fn other_withholding_wrappers_preserve_all_host_key_classifications() {
        for operation in [
            "secret-remove",
            "container-attach",
            "registry-auth",
            "distribution",
        ] {
            host_key_classifications_for_operation(operation).await;
        }
    }

    fn assert_timeout_kind(error: &crate::Error, expected: crate::TransportTimeoutKind) {
        assert_eq!(error.transport_timeout_kind(), Some(expected), "{error:?}");
        assert_eq!(
            error.is_transport_deadline(),
            expected != crate::TransportTimeoutKind::ManagedSshWriteInactivity
        );
        assert_eq!(error.managed_ssh_host_key_rejection(), None);
        assert!(!error.is_managed_ssh_authentication_rejected());
        assert!(error.api_error().is_none());
    }

    #[tokio::test]
    async fn managed_dns_and_dial_timeouts_survive_public_withholding_routes() {
        for resolve in [true, false] {
            for operation in [
                "ping",
                "plugin-set",
                // The facade install spawns a separate task, outside the
                // task-local DNS seam; its real-worker case is tested below.
                "raw-plugin-install",
                "swarm-unlock",
                "secret-remove",
                "container-attach",
            ] {
                let directory = tempfile::tempdir().unwrap();
                let client = crate::DockerClient::connect_ssh_managed(
                    "ssh://fixture@no-peer.invalid",
                    &directory.path().join("known_hosts"),
                )
                .timeout(Duration::from_millis(40))
                .password("synthetic-test".into())
                .connect()
                .unwrap();
                let error = crate::ssh_connect::TEST_DIAL_STALL
                    .scope(resolve, marker_request(&client, operation))
                    .await
                    .unwrap_err();
                assert_timeout_kind(&error, crate::TransportTimeoutKind::ManagedSshEstablishment);
                assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
                for rendered in [format!("{error}"), format!("{error:?}")] {
                    for forbidden in [RESPONSE_CANARY, "no-peer.invalid", "synthetic-test"] {
                        assert!(!rendered.contains(forbidden), "{operation}: {rendered}");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn managed_worker_timeouts_survive_public_withholding_routes() {
        for operation in [
            "plugin-set",
            "plugin-create",
            "plugin-install",
            "plugin-upgrade",
            "plugin-push",
            "swarm-unlock",
            "secret-remove",
            "container-attach",
        ] {
            let fixture = stalled_public_peer("handshake", Duration::from_secs(2));
            let error = marker_request(&fixture.client, operation)
                .await
                .unwrap_err();
            fixture.reached.await.unwrap();
            assert_timeout_kind(&error, crate::TransportTimeoutKind::ManagedSshEstablishment);
            assert!(!format!("{error:?}").contains(RESPONSE_CANARY));
            assert!(
                fixture.closed.await.unwrap(),
                "{operation}: socket retained"
            );
            fixture.server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn overall_request_deadlines_survive_public_withholding_routes() {
        for operation in [
            "plugin-set",
            "plugin-create",
            "plugin-install",
            "plugin-upgrade",
            "plugin-push",
            "swarm-unlock",
            "secret-remove",
            "container-attach",
            "registry-auth",
            "distribution",
        ] {
            let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [96; 32]);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (_directory, mut options) =
                options_for_peer(listener.local_addr().unwrap(), &signer);
            options.request_deadline = Some(Duration::from_millis(500));
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let server = raw_peer(signer, listener, move |connection| {
                let session = confirm_peer_session(connection);
                accept_exec(connection, session);
                loop {
                    if matches!(
                        connection.dispatch_one().unwrap(),
                        neotales_ssh::channel::ChannelEvent::Data { .. }
                    ) {
                        break;
                    }
                }
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            });
            let client = crate::DockerClient::connect_ssh_managed_inner(options).unwrap();
            let error = marker_request(&client, operation).await.unwrap_err();
            release_tx.send(()).unwrap();
            server.join().unwrap();
            assert_timeout_kind(&error, crate::TransportTimeoutKind::RequestDeadline);
            assert!(!format!("{error:?}").contains(RESPONSE_CANARY));
        }
    }

    async fn marker_request(
        client: &crate::DockerClient,
        operation: &str,
    ) -> Result<(), crate::Error> {
        match operation {
            "ping" => client.ping().await.map(|_| ()),
            "raw-ping" => crate::raw::ping(&client.raw_engine()?).await.map(|_| ()),
            "plugin-set" => {
                client
                    .set_plugin_config("fixture", vec![format!("TOKEN={RESPONSE_CANARY}")])
                    .await
            }
            "plugin-create" => {
                client
                    .create_plugin("fixture", RESPONSE_CANARY.as_bytes().to_vec())
                    .await
            }
            "plugin-list" => client.list_plugins(None).await.map(|_| ()),
            "plugin-inspect" => client.inspect_plugin("fixture").await.map(|_| ()),
            "plugin-remove" => client.remove_plugin("fixture", None).await.map(|_| ()),
            "plugin-enable" => client.enable_plugin("fixture", None).await,
            "plugin-disable" => client.disable_plugin("fixture", None).await,
            "plugin-privileges" => client
                .plugin_privileges("example/fixture")
                .await
                .map(|_| ()),
            "plugin-install" => client
                .install_plugin_with_credentials(
                    crate::PluginInstallOptions::new("example/fixture"),
                    crate::RegistryCredentials::new("fixture", RESPONSE_CANARY),
                )?
                .next()
                .await
                .expect("missing plugin failure")
                .map(|_| ()),
            "raw-plugin-install" => crate::raw::plugin_pull_with_registry_auth(
                &client.raw_engine()?,
                &crate::PluginInstallOptions::new("example/fixture"),
                crate::raw::RegistryAuth::identity_token("registry.example", RESPONSE_CANARY)?,
            )
            .await
            .map(|_| ()),
            "plugin-upgrade" => {
                client
                    .upgrade_plugin_with_credentials(
                        "fixture",
                        crate::PluginUpgradeOptions::new("example/fixture"),
                        crate::RegistryCredentials::new("fixture", RESPONSE_CANARY),
                    )
                    .await
            }
            "plugin-push" => {
                client
                    .push_plugin_with_credentials(
                        "example/fixture",
                        crate::RegistryCredentials::new("fixture", RESPONSE_CANARY),
                    )
                    .await
            }
            "swarm-unlock" => {
                client
                    .unlock_swarm(crate::SwarmUnlockOptions {
                        key: RESPONSE_CANARY.to_owned(),
                    })
                    .await
            }
            "secret-remove" => client.remove_secret("fixture").await,
            "container-attach" => client
                .attach_container("fixture", false, false, None)
                .await
                .map(|_| ()),
            "registry-auth" => client
                .registry_authenticate(&crate::raw::RegistryAuthentication {
                    username: "fixture",
                    password: RESPONSE_CANARY,
                    serveraddress: "registry.example",
                    identitytoken: None,
                    registrytoken: None,
                })
                .await
                .map(|_| ()),
            "distribution" => client
                .distribution_inspect("example/fixture")
                .await
                .map(|_| ()),
            _ => unreachable!(),
        }
    }

    async fn host_key_classifications_for_operation(operation: &str) {
        use std::error::Error as _;

        for (marker, changed, classification) in [
            ("", false, "unknown"),
            ("", true, "changed"),
            ("@revoked ", false, "revoked"),
            ("@cert-authority ", false, "CA-only"),
        ] {
            let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [94; 32]);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (_directory, options) = options_for_peer(address, &signer);
            let key = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [95; 32]);
            let encoded = base64::engine::general_purpose::STANDARD.encode(
                if changed {
                    key.public_key()
                } else {
                    signer.public_key()
                }
                .to_blob()
                .unwrap(),
            );
            let contents = if classification == "unknown" {
                "# provisioned but unknown\n".to_owned()
            } else {
                format!("{marker}{} ssh-ed25519 {encoded}\n", options.host_token)
            };
            std::fs::write(&options.known_hosts_path, &contents).unwrap();
            let client = crate::DockerClient::connect_ssh_managed_inner(options.clone()).unwrap();
            let server = std::thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                assert!(
                    neotales_ssh::server::ServerConfig::new(signer)
                        .connect(peer)
                        .is_err()
                );
            });
            let error = marker_request(&client, operation).await.unwrap_err();
            assert!(
                error.to_string().contains(classification),
                "{operation}: classification lost: {error}"
            );
            let expected = match classification {
                "unknown" => crate::ManagedSshHostKeyRejection::Unknown,
                "changed" => crate::ManagedSshHostKeyRejection::Changed,
                "revoked" => crate::ManagedSshHostKeyRejection::Revoked,
                "CA-only" => crate::ManagedSshHostKeyRejection::CertificateAuthorityOnly,
                _ => unreachable!(),
            };
            assert_eq!(error.managed_ssh_host_key_rejection(), Some(expected));
            assert!(!error.is_managed_ssh_authentication_rejected());
            assert_eq!(error.transport_timeout_kind(), None);
            let mut diagnostics = vec![format!("{error}"), format!("{error:?}")];
            let mut source = error.source();
            while let Some(error) = source {
                diagnostics.extend([format!("{error}"), format!("{error:?}")]);
                source = error.source();
            }
            for text in diagnostics {
                for forbidden in [
                    RESPONSE_CANARY,
                    &encoded,
                    &options.host_token,
                    &options.known_hosts_path.display().to_string(),
                ] {
                    assert!(!text.contains(forbidden), "unsafe host refusal: {text}");
                }
            }
            assert_eq!(
                std::fs::read(&options.known_hosts_path).unwrap(),
                contents.as_bytes()
            );
            server.join().unwrap();
        }
    }

    async fn managed_sensitive_request(
        engine: &crate::raw::RawEngine,
        operation: &str,
    ) -> Result<(), crate::Error> {
        let spec = crate::ServiceSpec {
            name: Some("fixture".to_owned()),
            ..crate::ServiceSpec::default()
        };
        match operation {
            "unlock" => {
                crate::raw::swarm_unlock(
                    engine,
                    &crate::SwarmUnlockOptions {
                        key: RESPONSE_CANARY.to_owned(),
                    },
                )
                .await
            }
            "create" => crate::raw::service_create_with_registry_auth(
                engine,
                &spec,
                crate::raw::RegistryAuth::identity_token("registry.example", RESPONSE_CANARY)?,
            )
            .await
            .map(|_| ()),
            "update" => crate::raw::service_update(
                engine,
                "fixture",
                &crate::ServiceUpdateOptions {
                    spec,
                    version: 1,
                    rollback: false,
                },
            )
            .await
            .map(|_| ()),
            _ => unreachable!(),
        }
    }

    #[allow(clippy::too_many_lines)] // Same real managed route checks each pre-response marker.
    async fn managed_sensitive_marker_case(operation: &str, revoked: bool) {
        use std::error::Error as _;

        let signer = neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [97; 32]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (_directory, mut options) = options_for_peer(listener.local_addr().unwrap(), &signer);
        if revoked {
            let entry = std::fs::read_to_string(&options.known_hosts_path).unwrap();
            std::fs::write(&options.known_hosts_path, format!("@revoked {entry}")).unwrap();
        } else {
            options.request_deadline = Some(Duration::from_millis(500));
        }
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = if revoked {
            std::thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                assert!(
                    neotales_ssh::server::ServerConfig::new(signer)
                        .connect(peer)
                        .is_err()
                );
            })
        } else {
            raw_peer(signer, listener, move |connection| {
                let session = confirm_peer_session(connection);
                accept_exec(connection, session);
                loop {
                    match connection.dispatch_one() {
                        Ok(neotales_ssh::channel::ChannelEvent::Data { .. }) => break,
                        Err(error) => panic!("request did not reach peer: {error}"),
                        _ => {}
                    }
                }
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            })
        };
        let client = crate::DockerClient::connect_ssh_managed_inner(options.clone()).unwrap();
        let engine = client.raw_engine().unwrap();
        let error = async {
            tokio::time::timeout(
                Duration::from_secs(3),
                managed_sensitive_request(&engine, operation),
            )
            .await
            .expect("managed request did not finish")
            .unwrap_err()
        }
        .await;
        if !revoked {
            release_tx.send(()).unwrap();
        }
        server.join().unwrap();
        assert_eq!(error.kind(), crate::ErrorKind::Transport);
        assert!(error.api_error().is_none(), "no response was observed");
        if revoked {
            assert_eq!(
                error.managed_ssh_host_key_rejection(),
                Some(crate::ManagedSshHostKeyRejection::Revoked),
                "{operation}: safe host-key classification lost: {error:?}",
            );
        } else {
            assert!(
                error.is_transport_deadline(),
                "{operation}: deadline marker lost: {error:?}"
            );
            assert_timeout_kind(&error, crate::TransportTimeoutKind::RequestDeadline);
        }
        let mut diagnostics = vec![format!("{error}"), format!("{error:?}")];
        let mut source = error.source();
        while let Some(error) = source {
            diagnostics.extend([format!("{error}"), format!("{error:?}")]);
            source = error.source();
        }
        for text in diagnostics {
            assert!(!text.contains(RESPONSE_CANARY), "peer text leaked: {text}");
            assert!(
                !text.contains(&options.host_token),
                "host text leaked: {text}"
            );
            assert!(
                !text.contains(&options.known_hosts_path.display().to_string()),
                "path leaked: {text}"
            );
        }
    }

    #[tokio::test]
    async fn managed_swarm_unlock_preserves_request_deadline() {
        managed_sensitive_marker_case("unlock", false).await;
    }

    #[tokio::test]
    async fn managed_swarm_unlock_preserves_revoked_host_key() {
        managed_sensitive_marker_case("unlock", true).await;
    }

    #[tokio::test]
    async fn managed_credentialed_service_create_preserves_request_deadline() {
        managed_sensitive_marker_case("create", false).await;
    }

    #[tokio::test]
    async fn managed_credentialed_service_create_preserves_revoked_host_key() {
        managed_sensitive_marker_case("create", true).await;
    }

    #[tokio::test]
    async fn managed_service_update_preserves_request_deadline() {
        managed_sensitive_marker_case("update", false).await;
    }

    #[tokio::test]
    async fn managed_service_update_preserves_revoked_host_key() {
        managed_sensitive_marker_case("update", true).await;
    }

    struct StalledPublicPeer {
        client: crate::DockerClient,
        _directory: tempfile::TempDir,
        reached: tokio::sync::oneshot::Receiver<()>,
        closed: tokio::sync::oneshot::Receiver<bool>,
        server: std::thread::JoinHandle<()>,
    }

    fn stalled_public_peer(phase: &'static str, monitor: Duration) -> StalledPublicPeer {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, ServerAuthStep, ServerAuthenticator, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent},
        };
        use std::{io::Read as _, net::TcpListener, thread};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let signer = Ed25519Signer::from_seed(&mut [93; 32]);
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(signer.public_key().to_blob().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::fs::write(
            &path,
            format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port()),
        )
        .unwrap();
        let client =
            crate::DockerClient::connect_ssh_managed(&format!("ssh://fixture@{address}"), &path)
                .timeout(Duration::from_secs(1))
                .password("synthetic-test".into())
                .connect()
                .unwrap();
        let (reached_tx, reached) = tokio::sync::oneshot::channel();
        let (closed_tx, closed) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut socket = if phase == "handshake" {
                peer.read_exact(&mut [0]).unwrap();
                peer
            } else {
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                if phase == "auth" {
                    let mut auth = ServerAuthenticator::new(&mut transport, &policy);
                    assert_eq!(auth.step().unwrap(), ServerAuthStep::ServiceAccepted);
                    drop(auth);
                    transport.into_inner()
                } else {
                    authenticate_server(&mut transport, &policy).unwrap();
                    let mut sessions =
                        ServerSessions::with_policy(transport, |_| SessionDecision::accept(0));
                    if phase == "exec" {
                        assert!(matches!(
                            sessions.dispatch_one().unwrap(),
                            SessionEvent::Opened { .. }
                        ));
                    }
                    sessions.into_inner().into_inner()
                }
            };
            socket.set_read_timeout(Some(monitor)).unwrap();
            let _ = reached_tx.send(());
            let mut did_close = false;
            for _ in 0..128 {
                match socket.read(&mut [0; 4096]) {
                    Ok(0) => {
                        did_close = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                        ) =>
                    {
                        did_close = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            let _ = closed_tx.send(did_close);
        });
        StalledPublicPeer {
            client,
            _directory: directory,
            reached,
            closed,
            server,
        }
    }

    async fn public_test_request(
        client: crate::DockerClient,
        raw: bool,
    ) -> Result<(), crate::Error> {
        if raw {
            crate::raw::ping(&client.raw_engine().unwrap())
                .await
                .map(|_| ())
        } else {
            client.ping().await.map(|_| ())
        }
    }

    #[tokio::test]
    async fn public_raw_and_facade_deadlines_reach_each_protocol_phase() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for raw in [true, false] {
            for phase in ["handshake", "auth", "channel", "exec"] {
                let fixture = stalled_public_peer(phase, Duration::from_secs(2));
                let native = Arc::new(AtomicUsize::new(0));
                let task = tokio::spawn(super::TEST_NATIVE_CALLS.scope(
                    Arc::clone(&native),
                    public_test_request(fixture.client, raw),
                ));
                tokio::time::timeout(Duration::from_secs(2), fixture.reached)
                    .await
                    .unwrap()
                    .unwrap();
                let result = tokio::time::timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap()
                    .unwrap();
                let error = result.expect_err("stalled public request unexpectedly succeeded");
                assert!(
                    error.is_transport_deadline(),
                    "unmarked {phase} timeout (raw={raw}): {error}"
                );
                assert_timeout_kind(&error, crate::TransportTimeoutKind::ManagedSshEstablishment);
                assert_eq!(native.load(Ordering::SeqCst), 0);
                let closed = tokio::time::timeout(Duration::from_secs(3), fixture.closed)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    closed,
                    "{phase}: timed-out public route retained its socket (raw={raw})"
                );
                fixture.server.join().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn public_raw_and_facade_dropped_requests_are_observed() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for raw in [true, false] {
            for phase in ["handshake", "auth", "channel", "exec"] {
                let fixture = stalled_public_peer(phase, Duration::from_millis(400));
                let native = Arc::new(AtomicUsize::new(0));
                let task = tokio::spawn(super::TEST_NATIVE_CALLS.scope(
                    Arc::clone(&native),
                    public_test_request(fixture.client, raw),
                ));
                tokio::time::timeout(Duration::from_secs(2), fixture.reached)
                    .await
                    .unwrap()
                    .unwrap();
                task.abort();
                assert!(
                    matches!(tokio::time::timeout(Duration::from_secs(1), task).await.unwrap(), Err(error) if error.is_cancelled())
                );
                let closed = tokio::time::timeout(Duration::from_secs(2), fixture.closed)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    closed,
                    "the {phase} socket remained open after caller drop (raw={raw})"
                );
                assert_eq!(native.load(Ordering::SeqCst), 0);
                fixture.server.join().unwrap();
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One peer fixture covers the three ownership outcomes.
    async fn supervised_duplex_transfers_io_and_closes_on_failure_or_cancellation() {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent, SessionRequest},
        };
        use std::{io::Read as _, net::TcpListener, sync::mpsc, thread, time::Duration};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 0: live duplex and readiness, 1: reactor registration failure,
        // 2: caller cancels before exec confirmation/session commit.
        for mode in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [61; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let contents = format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port());
            std::fs::write(&path, &contents).unwrap();
            let options = super::ManagedSshOptions::from_endpoint(
                &format!("ssh://fixture@{address}"),
                SshIdentity::Password("test-only".into()),
                Some(&path),
                Duration::from_secs(5),
            )
            .unwrap();
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |request| match request {
                        SessionRequest::Exec { command }
                            if command == b"docker system dial-stdio" =>
                        {
                            SessionDecision::accept(0)
                        }
                        _ => SessionDecision::reject(),
                    });
                let session = match sessions.dispatch_one().unwrap() {
                    SessionEvent::Opened { session } => session,
                    other => panic!("expected channel open, got {other:?}"),
                };
                if mode == 2 {
                    let _ = reached_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(2));
                } else {
                    assert!(matches!(
                        sessions.dispatch_one().unwrap(),
                        SessionEvent::Request { accepted: true, .. }
                    ));
                    if mode == 0 {
                        assert!(
                            matches!(sessions.dispatch_one().unwrap(), SessionEvent::Data { data, .. } if data == b"ping")
                        );
                        let _ = reached_tx.send(());
                        release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                        sessions.send_data(session, b"pong").unwrap();
                    }
                }
                // Inspect the underlying socket directly: a channel error
                // could merely be a read timeout, not actual peer closure.
                let mut socket = sessions.into_inner().into_inner();
                let mut closed = false;
                for _ in 0..64 {
                    match socket.read(&mut [0; 4096]) {
                        Ok(0) => {
                            closed = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::BrokenPipe
                            ) =>
                        {
                            closed = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = done_tx.send(closed);
            });
            if mode == 2 {
                let task = tokio::spawn(async move { super::open_supervised(&options).await });
                tokio::time::timeout(Duration::from_secs(3), reached_rx)
                    .await
                    .unwrap()
                    .unwrap();
                task.abort();
                assert!(
                    matches!(tokio::time::timeout(Duration::from_secs(1), task).await.unwrap(), Err(error) if error.is_cancelled())
                );
                release_tx.send(()).unwrap();
            } else if mode == 1 {
                let result = super::open_supervised_with_register(&options, |_| {
                    Err(std::io::Error::other("injected registration failure"))
                })
                .await;
                assert!(
                    matches!(result, Err(ref error) if error.to_string().contains("injected registration failure"))
                );
            } else {
                let mut duplex = super::open_supervised(&options).await.unwrap();
                duplex.write_all(b"ping").await.unwrap();
                // `write` accepts the bytes into the driver's owned packet; the
                // caller flushes when it needs the peer to observe them before
                // the next read.
                duplex.flush().await.unwrap();
                tokio::time::timeout(Duration::from_secs(3), reached_rx)
                    .await
                    .unwrap()
                    .unwrap();
                let mut answer = [0; 4];
                assert!(
                    tokio::time::timeout(Duration::from_millis(75), duplex.read_exact(&mut answer))
                        .await
                        .is_err(),
                    "read should await socket readiness"
                );
                release_tx.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(2), duplex.read_exact(&mut answer))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&answer, b"pong");
                drop(duplex);
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(4), done_rx)
                    .await
                    .unwrap()
                    .unwrap(),
                "peer did not observe socket closure"
            );
            server.join().unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Both peer lifetimes are exercised together.
    async fn two_managed_duplexes_remain_isolated_when_one_is_dropped() {
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent, SessionRequest},
        };
        use std::{io::Read as _, net::TcpListener, thread, time::Duration};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut directories = Vec::new();
        let mut options = Vec::new();
        let mut servers = Vec::new();
        let mut completions = Vec::new();
        for seed in [71, 72] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [seed; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            std::fs::write(
                &path,
                format!("[127.0.0.1]:{} ssh-ed25519 {encoded}\n", address.port()),
            )
            .unwrap();
            options.push(
                super::ManagedSshOptions::from_endpoint(
                    &format!("ssh://fixture@{address}"),
                    SshIdentity::Password("test-only".into()),
                    Some(&path),
                    Duration::from_secs(5),
                )
                .unwrap(),
            );
            directories.push(directory);
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            completions.push(done_rx);
            servers.push(thread::spawn(move || {
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |request| match request {
                        SessionRequest::Exec { command }
                            if command == b"docker system dial-stdio" =>
                        {
                            SessionDecision::accept(0)
                        }
                        _ => SessionDecision::reject(),
                    });
                let session = match sessions.dispatch_one().unwrap() {
                    SessionEvent::Opened { session } => session,
                    other => panic!("expected channel open, got {other:?}"),
                };
                assert!(matches!(
                    sessions.dispatch_one().unwrap(),
                    SessionEvent::Request { accepted: true, .. }
                ));
                while let Ok(event) = sessions.dispatch_one() {
                    if let SessionEvent::Data { data, .. } = event {
                        sessions.send_data(session, &data).unwrap();
                    }
                }
                let mut socket = sessions.into_inner().into_inner();
                let closed = match socket.read(&mut [0]) {
                    Ok(0) => true,
                    Err(error) => matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::BrokenPipe
                    ),
                    Ok(_) => false,
                };
                let _ = done_tx.send(closed);
            }));
        }
        let first = super::open_supervised(&options[0]).await.unwrap();
        let mut second = super::open_supervised(&options[1]).await.unwrap();
        drop(first);
        let first_done = completions.remove(0);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), first_done)
                .await
                .unwrap()
                .unwrap()
        );
        second.write_all(b"second remains live").await.unwrap();
        let mut reply = [0; 19];
        tokio::time::timeout(Duration::from_secs(2), second.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"second remains live");
        drop(second);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), completions.remove(0))
                .await
                .unwrap()
                .unwrap()
        );
        for server in servers {
            server.join().unwrap();
        }
        drop(directories);
    }

    #[test]
    fn missing_known_hosts_is_rejected_without_creation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing");
        assert!(super::load_known_hosts(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn fake_ssh_peer_reaches_and_is_rejected_by_read_only_trust() {
        use neotales_ssh::{
            client::{ClientConfig, HandshakeError},
            hostkey::{Ed25519Signer, HostKeyError},
            server::ServerConfig,
        };
        use std::{
            net::{TcpListener, TcpStream},
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            thread,
            time::Duration,
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let contents = b"# deliberately no trust entries\n";
        std::fs::write(&path, contents).unwrap();
        let known = super::load_known_hosts(&path).unwrap();

        // Synthetic test-only host key: no user identity, credential or daemon.
        let signer = Ed25519Signer::from_seed(&mut [42; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        for socket in [&client, &peer] {
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        let server = thread::spawn(move || ServerConfig::new(signer).connect(peer).is_err());
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let result = ClientConfig::new().connect(client, |key| {
            callback_called.store(true, Ordering::SeqCst);
            super::check_host_key(&known, &path, "example.test", key)
        });
        assert!(matches!(
            result,
            Err(HandshakeError::HostKey(HostKeyError::TrustRejected))
        ));
        assert!(
            called.load(Ordering::SeqCst),
            "trust callback was not reached"
        );
        assert!(
            server.join().unwrap(),
            "server unexpectedly completed handshake"
        );
        assert_eq!(std::fs::read(path).unwrap(), contents);
    }

    #[tokio::test]
    async fn supervised_real_handshake_enforces_read_only_trust() {
        use crate::{
            ssh_cancellation::EstablishmentControl,
            ssh_connect::dial,
            ssh_worker::{WORKERS, supervise},
        };
        use neotales_ssh::{hostkey::Ed25519Signer, server::ServerConfig};
        use std::{
            net::TcpListener,
            thread,
            time::{Duration, Instant},
        };

        for scenario in ["trusted", "unknown", "changed"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [41; 32]);
            let other = Ed25519Signer::from_seed(&mut [42; 32]);
            let key = if scenario == "changed" {
                other.public_key()
            } else {
                signer.public_key()
            };
            let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_blob().unwrap());
            let contents = if scenario == "unknown" {
                "# no keys\n".to_owned()
            } else {
                format!("example.test ssh-ed25519 {encoded}\n")
            };
            std::fs::write(&path, &contents).unwrap();
            let snapshot = super::load_known_hosts(&path).unwrap();
            let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let dialed = dial("127.0.0.1", address.port(), control).await.unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let server = thread::spawn(move || ServerConfig::new(signer).connect(peer).is_ok());
            let worker_path = path.clone();
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                supervise(
                    dialed,
                    Duration::from_secs(2),
                    &WORKERS,
                    move |socket, _| {
                        super::checked_handshake(
                            socket,
                            &snapshot,
                            &worker_path,
                            "example.test",
                            "example.test",
                            22,
                        )
                        .map_err(|error| std::io::Error::other(error.to_string()))
                    },
                ),
            )
            .await
            .unwrap();
            if scenario == "trusted" {
                assert!(result.is_ok(), "trusted handshake was refused");
            } else {
                assert!(
                    matches!(result, Err(ref error) if error.to_string().contains("SSH host-key refusal:")),
                    "{scenario} did not reach trust rejection"
                );
            }
            assert_eq!(server.join().unwrap(), scenario == "trusted");
            assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
        }
    }

    #[tokio::test]
    async fn supervised_real_handshake_stall_obeys_deadline_and_cancellation() {
        use crate::{
            ssh_cancellation::EstablishmentControl,
            ssh_connect::dial,
            ssh_worker::{WORKERS, supervise},
        };
        use std::{
            net::TcpListener,
            time::{Duration, Instant},
        };
        use tokio::io::AsyncReadExt;

        for cancel in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            std::fs::write(&path, b"# no keys\n").unwrap();
            let snapshot = super::load_known_hosts(&path).unwrap();
            let control = EstablishmentControl::new(Instant::now() + Duration::from_millis(500));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let dialed = dial("127.0.0.1", address.port(), control.clone())
                .await
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_nonblocking(true).unwrap();
            let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
            let worker_path = path.clone();
            let task = tokio::spawn(supervise(
                dialed,
                Duration::from_secs(2),
                &WORKERS,
                move |socket, _| {
                    super::checked_handshake(
                        socket,
                        &snapshot,
                        &worker_path,
                        "example.test",
                        "example.test",
                        22,
                    )
                    .map_err(|error| std::io::Error::other(error.to_string()))
                },
            ));
            let mut first = [0];
            tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut first))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first[0], b'S');
            if cancel {
                control.request_cancel();
            }
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            let expected = if cancel {
                std::io::ErrorKind::ConnectionAborted
            } else {
                std::io::ErrorKind::TimedOut
            };
            assert!(matches!(result, Err(ref error) if error.kind() == expected));
            let mut tail = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), peer.read_to_end(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(control.shutdown_count(), 1);
            assert_eq!(std::fs::read(&path).unwrap(), b"# no keys\n");
        }
    }

    #[tokio::test]
    async fn supervised_real_auth_channel_and_exec_reach_controlled_peer() {
        use crate::{
            ssh_cancellation::EstablishmentControl,
            ssh_connect::dial,
            ssh_worker::{WORKERS, supervise},
        };
        use neotales_ssh::{
            auth::{ServerAuthPolicy, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{
                OwnedSessionRequest, ServerSessions, SessionDecision, SessionEvent, SessionRequest,
            },
        };
        use std::{
            net::TcpListener,
            thread,
            time::{Duration, Instant},
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        // Test-only server key and opaque auth payload; neither is a credential
        // from the machine or an external service.
        let signer = Ed25519Signer::from_seed(&mut [53; 32]);
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(signer.public_key().to_blob().unwrap());
        let contents = format!("example.test ssh-ed25519 {encoded}\n");
        std::fs::write(&path, &contents).unwrap();
        let options = super::ManagedSshOptions::from_endpoint(
            "ssh://fixture@example.test",
            SshIdentity::Password("test-only".into()),
            Some(&path),
            Duration::from_secs(5),
        )
        .unwrap();

        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dialed = dial("127.0.0.1", address.port(), control.clone())
            .await
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let server = thread::spawn(move || {
            let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
            let policy = ServerAuthPolicy::new(2)
                .unwrap()
                .with_password_callback(|_| true);
            authenticate_server(&mut transport, &policy).unwrap();
            let mut sessions = ServerSessions::with_policy(transport, |request| match request {
                SessionRequest::Exec { command } if command == b"docker system dial-stdio" => {
                    SessionDecision::accept(0)
                }
                _ => SessionDecision::reject(),
            });
            assert!(matches!(
                sessions.dispatch_one().unwrap(),
                SessionEvent::Opened { .. }
            ));
            assert!(matches!(
                sessions.dispatch_one().unwrap(),
                SessionEvent::Request {
                    request: OwnedSessionRequest::Exec(ref command),
                    accepted: true,
                    ..
                } if command == b"docker system dial-stdio"
            ));
        });
        let worker_options = options.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            supervise(
                dialed,
                Duration::from_secs(2),
                &WORKERS,
                move |socket, control| supervised_test_protocol(socket, &control, &worker_options),
            ),
        )
        .await
        .unwrap();
        assert!(
            result.is_ok(),
            "real auth/channel/exec failed: {:?}",
            result.err()
        );
        server.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
    }

    #[tokio::test]
    async fn supervised_real_protocol_cancellation_at_auth_channel_and_exec() {
        use crate::{
            ssh_cancellation::EstablishmentControl,
            ssh_connect::dial,
            ssh_worker::{WORKERS, supervise},
        };
        use neotales_ssh::{
            auth::{ServerAuthPolicy, ServerAuthStep, ServerAuthenticator, authenticate_server},
            hostkey::Ed25519Signer,
            server::ServerConfig,
            session::{ServerSessions, SessionDecision, SessionEvent},
        };
        use std::{
            net::TcpListener,
            sync::mpsc,
            thread,
            time::{Duration, Instant},
        };

        for phase in ["auth", "channel", "exec"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("known_hosts");
            let signer = Ed25519Signer::from_seed(&mut [53; 32]);
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(signer.public_key().to_blob().unwrap());
            let contents = format!("example.test ssh-ed25519 {encoded}\n");
            std::fs::write(&path, &contents).unwrap();
            let options = super::ManagedSshOptions::from_endpoint(
                "ssh://fixture@example.test",
                SshIdentity::Password("test-only".into()),
                Some(&path),
                Duration::from_secs(5),
            )
            .unwrap();
            let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let dialed = dial("127.0.0.1", address.port(), control.clone())
                .await
                .unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let mut transport = ServerConfig::new(signer).connect(peer).unwrap();
                let policy = ServerAuthPolicy::new(2)
                    .unwrap()
                    .with_password_callback(|_| true);
                if phase == "auth" {
                    let mut auth = ServerAuthenticator::new(&mut transport, &policy);
                    assert_eq!(auth.step().unwrap(), ServerAuthStep::ServiceAccepted);
                    let _ = reached_tx.send(());
                    let _ = release_rx.recv_timeout(Duration::from_secs(3));
                    return;
                }
                authenticate_server(&mut transport, &policy).unwrap();
                let mut sessions =
                    ServerSessions::with_policy(transport, |_| SessionDecision::accept(0));
                if phase == "exec" {
                    assert!(matches!(
                        sessions.dispatch_one().unwrap(),
                        SessionEvent::Opened { .. }
                    ));
                }
                let _ = reached_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
            });
            let worker_options = options.clone();
            let task = tokio::spawn(supervise(
                dialed,
                Duration::from_secs(2),
                &WORKERS,
                move |socket, control| supervised_test_protocol(socket, &control, &worker_options),
            ));
            tokio::time::timeout(Duration::from_secs(3), reached_rx)
                .await
                .unwrap()
                .unwrap();
            control.request_cancel();
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionAborted),
                "{phase} did not cancel"
            );
            release_tx.send(()).unwrap();
            server.join().unwrap();
            assert_eq!(control.shutdown_count(), 1);
            assert_eq!(std::fs::read(&path).unwrap(), contents.as_bytes());
        }
    }

    #[tokio::test]
    async fn cancelled_stalled_trust_read_cannot_start_handshake_after_returning() {
        use crate::{
            ssh_cancellation::{EstablishmentControl, Refused},
            ssh_connect::dial,
            ssh_worker::{WORKERS, supervise},
        };
        use std::{
            io::Write,
            net::TcpListener,
            sync::mpsc,
            time::{Duration, Instant},
        };
        use tokio::io::AsyncReadExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        std::fs::write(&path, b"# read-only trust\n").unwrap();
        let control = EstablishmentControl::new(Instant::now() + Duration::from_secs(5));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dialed = dial("127.0.0.1", address.port(), control.clone())
            .await
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut peer = tokio::net::TcpStream::from_std(peer).unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let worker_path = path.clone();
        let task = tokio::spawn(supervise(
            dialed,
            Duration::from_secs(1),
            &WORKERS,
            move |mut socket, control| {
                control.try_effect(|| ()).unwrap(); // Commit a read-only operation.
                let _ = entered_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
                let read = super::load_known_hosts(&worker_path);
                let next = control.try_effect(|| ());
                let _ = finished_tx.send((read.is_ok(), next));
                if next.is_ok() {
                    socket.write_all(b"handshake")?;
                }
                Ok(())
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
            matches!(result, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionAborted)
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.is_empty(), "late worker sent handshake bytes");
        release_tx.send(()).unwrap();
        let (read_succeeded, next) = tokio::time::timeout(Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(read_succeeded);
        assert_eq!(next, Err(Refused::Cancelled));
        assert_eq!(std::fs::read(&path).unwrap(), b"# read-only trust\n");
    }

    #[test]
    fn unknown_host_is_rejected_without_modifying_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        std::fs::write(&path, b"# pre-provisioned\n").unwrap();
        let known = super::load_known_hosts(&path).unwrap();
        let public = neotales_ssh::hostkey::Ed25519PublicKey::from_point(&[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ])
        .unwrap();
        assert!(super::check_host_key(&known, &path, "example.test", &public).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"# pre-provisioned\n");
    }

    #[test]
    fn read_only_snapshot_rejects_revoked_ca_and_accepts_hashed_port() {
        let public = neotales_ssh::hostkey::Ed25519PublicKey::from_point(&[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ])
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(public.to_blob().unwrap());
        let token = "[example.test]:2222";
        let hash = neotales_ssh::known_hosts::hash_host_token_with_salt(token, &[7; 20]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        for (content, accepted) in [
            (format!("{hash} ssh-ed25519 {encoded}\n"), true),
            (format!("@revoked {token} ssh-ed25519 {encoded}\n"), false),
            (
                format!("@cert-authority {token} ssh-ed25519 {encoded}\n"),
                false,
            ),
            (
                format!("{token} ssh-ed25519 {encoded}\n@revoked {token} ssh-ed25519 {encoded}\n"),
                false,
            ),
        ] {
            std::fs::write(&path, &content).unwrap();
            let snapshot = super::load_known_hosts(&path).unwrap();
            assert_eq!(
                super::check_host_key(&snapshot, &path, token, &public).is_ok(),
                accepted
            );
            assert!(super::check_host_key(&snapshot, &path, "example.test", &public).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), content.as_bytes());
        }
    }

    #[test]
    fn invalid_and_unreadable_known_hosts_fail_without_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        for bytes in [b"invalid known hosts\n".as_slice(), b"\xff".as_slice()] {
            std::fs::write(&path, bytes).unwrap();
            assert!(super::load_known_hosts(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        // Reading a directory as a file is rejected independently of uid,
        // unlike chmod-based permission tests in privileged CI environments.
        assert!(super::load_known_hosts(directory.path()).is_err());
    }

    #[test]
    fn atomically_replaced_file_does_not_revise_an_existing_snapshot() {
        let public = neotales_ssh::hostkey::Ed25519PublicKey::from_point(&[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ])
        .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(public.to_blob().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("known_hosts");
        let replacement = directory.path().join("replacement");
        std::fs::write(&path, format!("example.test ssh-ed25519 {encoded}\n")).unwrap();
        let before = super::load_known_hosts(&path).unwrap();
        let revoked = format!("@revoked example.test ssh-ed25519 {encoded}\n");
        std::fs::write(&replacement, &revoked).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let after = super::load_known_hosts(&path).unwrap();
        assert!(super::check_host_key(&before, &path, "example.test", &public).is_ok());
        assert!(super::check_host_key(&after, &path, "example.test", &public).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), revoked.as_bytes());
    }

    #[test]
    fn named_known_hosts_rejects_a_changed_key() {
        // RFC 8032 public keys, deliberately distinct; no private key is used.
        let first = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let second = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let first = neotales_ssh::hostkey::Ed25519PublicKey::from_point(&first).unwrap();
        let second = neotales_ssh::hostkey::Ed25519PublicKey::from_point(&second).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(first.to_blob().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("named_hosts");
        std::fs::write(
            &path,
            format!("[example.test]:2222 ssh-ed25519 {encoded}\n"),
        )
        .unwrap();
        let known = super::load_known_hosts(&path).unwrap();
        assert!(super::check_host_key(&known, &path, "[example.test]:2222", &first).is_ok());
        let error =
            super::check_host_key(&known, &path, "[example.test]:2222", &second).unwrap_err();
        assert_eq!(
            error.managed_ssh_host_key_rejection(),
            Some(crate::ManagedSshHostKeyRejection::Changed)
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("[example.test]:2222 ssh-ed25519 {encoded}\n")
        );
    }

    /// A complete endpoint, as the starting point for the cases below.
    fn options(identity: SshIdentity) -> Result<ManagedSshOptions, crate::Error> {
        ManagedSshOptions::from_endpoint(
            "ssh://deploy@example.test:2222",
            identity,
            Some(Path::new("/keys/known_hosts")),
            Duration::from_secs(30),
        )
    }

    fn key() -> SshIdentity {
        SshIdentity::KeyFile(Path::new("/keys/id_ed25519").to_path_buf())
    }

    /// A missing login name and a missing known-hosts file are each refused with
    /// their own reason, because a caller who supplied one of the two needs to
    /// be told which is absent.
    ///
    /// A credential is not among them any more: a password is a credential, and
    /// refusing the description without one would report a missing password as a
    /// malformed endpoint.
    #[test]
    fn a_managed_endpoint_needs_a_user_and_a_known_hosts_file() {
        assert!(
            ManagedSshOptions::from_endpoint(
                "ssh://example.test",
                key(),
                Some(Path::new("/h")),
                Duration::from_secs(30)
            )
            .is_err_and(|error| error.to_string().contains("named user")),
            "an endpoint naming no login user was accepted"
        );
        assert!(
            ManagedSshOptions::from_endpoint(
                "ssh://deploy@example.test",
                key(),
                None,
                Duration::from_secs(30)
            )
            .is_err_and(|error| error.to_string().contains("known-hosts")),
            "an endpoint with no known-hosts file was accepted"
        );
        assert!(
            options(SshIdentity::Password(crate::SshSecret::new("x"))).is_ok(),
            "a password credential did not build a description"
        );
    }

    #[test]
    fn a_managed_endpoint_becomes_a_stream_target() {
        let options = options(key()).expect("a complete managed endpoint");

        assert_eq!(options.host, "example.test");
        assert_eq!(options.port, 2222);
        assert_eq!(options.user, "deploy");
        // The known-hosts token, not the bare host: a `host:port` spelling is a
        // hostname with a colon in it, which no known-hosts line contains.
        assert_eq!(options.host_token, "[example.test]:2222");

        let target = managed_ssh_target(options);
        assert!(matches!(target, RawTarget::Stream { .. }));
    }

    /// The flag is the only thing that tells a retryable stall from a dead
    /// connection, because the channel layer erases the difference.
    #[test]
    fn a_would_block_is_recorded_once_and_taken_once() {
        let record = WouldBlock::default();
        assert_eq!(record.take(), None, "nothing was recorded yet");

        record.0.store(1, Ordering::Release);
        assert_eq!(record.take(), Some(super::BlockedOn::Read));
        assert_eq!(record.take(), None, "and it is not taken twice");

        record.0.store(2, Ordering::Release);
        record.arm();
        assert_eq!(
            record.take(),
            None,
            "arming clears the previous operation's stall"
        );
    }
}
