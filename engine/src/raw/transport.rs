//! The repository-owned Engine transport.
//!
//! This is the first vertical slice of the owned backend described in
//! `docs/docker/engine-backend-alternatives.md`. It owns the whole request path
//! instead of delegating it: the versioned URI, the connection, the request
//! body, the response status, and the error mapping.
//!
//! # Why a hand-rolled connection rather than a client library
//!
//! `hyper_util`'s legacy client needs a `tower_service` connector, and its stock
//! `HttpConnector` cannot open a Unix socket. the former generated client's answer is a
//! `connect_with_custom_transport` callback layered on top of a client it owns,
//! which is exactly the arrangement that makes proxy, SSH, and cancellation
//! behavior hard to compose. Driving `hyper::client::conn::http1` directly
//! removes the connector abstraction: the socket, the request, and the
//! connection lifetime are all values this module holds.
//!
//! One connection is used per request, which is what the Docker CLI does and
//! what keeps connection-pool bugs out of the transport. Streaming responses
//! keep their connection alive through the response body, so a long pull is not
//! cut short by the request returning.
//!
//! # Cancellation
//!
//! There is no cancel channel. A caller stops polling the response body and
//! drops it; the body and the connection driver are dropped with it, the socket
//! closes, and the daemon observes the disconnect. Cancellation is therefore a
//! consequence of ownership rather than a protocol that has to be implemented
//! correctly on both sides.
//!
//! The connection driver runs as a task, so dropping the request future before
//! the response head arrives must not merely detach it. Every point between
//! spawning that task and handing it to the [`RawResponse`] owns an abort
//! guard: an early return, a response-head timeout, or a cancelled caller stops
//! the driver instead of leaving it to drive a socket nobody owns. Once the
//! response exists it owns the abort handle and decides when the driver stops.
//!
//! An upgrade is not an exception to that ownership; it transfers the socket.
//! [`RawResponse::into_upgraded`] drops the response, which requests an abort
//! through the handle, and the read and write halves it returns own the
//! transferred socket once the upgrade completes. Abort is cooperative: the
//! driver may still be finishing a poll on another thread, so the response drop
//! does not claim to have terminated it synchronously. The halves, not the
//! handle, keep a switched connection alive.
//!
//! Cancellation is not a retraction. If the request was already dispatched, the
//! daemon may have applied it before the socket closed, so a cancelled mutation
//! has an unknown outcome rather than a known failure. No operation retries a
//! dispatched request on its own.
//!
//! # Explicit plain-HTTP forward proxy
//!
//! The facade can route a plain-HTTP Engine endpoint through an explicit
//! [`crate::ProxyPolicy::Http`] proxy. That route is held on [`RawEngine`] and
//! is never selected from `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`,
//! or any other environment variable. When it is present, the transport dials
//! the proxy and writes an absolute-form request target containing the daemon's
//! authority, while `Host` also names the daemon. The configured
//! `Proxy-Authorization` header is added only on that route. A caller-supplied
//! `Proxy-Authorization` is rejected there; on a direct target or a
//! caller-supplied [`RawTarget::Stream`] it is forwarded unchanged, preserving
//! existing custom-transport authentication. A caller-supplied `Host` is ignored
//! on the configured proxy route in favor of the daemon authority; direct and
//! custom targets keep forwarding it. A proxy that cannot be
//! reached is an error, not a reason to connect to the daemon directly.

use std::fmt;
use std::future::Future;
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::Request;
use hyper::body::Body as _;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, PROXY_AUTHORIZATION, TRANSFER_ENCODING,
};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::body::{ConnectionDriver, RawBody, RawResponse};
use crate::{ApiVersion, Error};

/// A byte stream the owned HTTP/1 connection can be driven over.
///
/// This is the object a [`StreamFactory`] hands back, so it is public for the
/// same reason the factory is: a factory outside this crate cannot name a type
/// it cannot return. It is a marker over `AsyncRead + AsyncWrite + Unpin +
/// Send` rather than a new I/O trait, because the transport wraps whatever it
/// is given in `hyper_util::rt::TokioIo` and adds nothing of its own. Anything
/// that satisfies the bounds is a duplex — a socket, a process's piped
/// standard streams, or an SSH session channel.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Records local markers before hyper can discard the original I/O cause.
struct ObservedDuplex {
    inner: Box<dyn Duplex>,
    timeout: crate::TransportTimeoutObservation,
}

impl ObservedDuplex {
    fn observe<T>(&self, result: Poll<std::io::Result<T>>) -> Poll<std::io::Result<T>> {
        if let Poll::Ready(Err(error)) = &result {
            self.timeout.observe(error);
        }
        result
    }
}

impl AsyncRead for ObservedDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        self.observe(result)
    }
}

impl AsyncWrite for ObservedDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        self.observe(result)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.observe(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.observe(result)
    }
}

/// The future a [`StreamFactory`] call returns.
pub type StreamFuture = Pin<Box<dyn Future<Output = Result<Box<dyn Duplex>, Error>> + Send>>;

/// A closure that opens one fresh duplex for one Engine request.
///
/// # The contract, and why it is a factory and not a stream
///
/// **The transport calls this once per request.** Not once per target, not once
/// per connection pool entry: once for each `RawEngine::send` and once for each
/// `RawEngine::send_upgrading`.
///
/// The reason is in [`RawEngine::send`]: it calls `connect()` and then
/// `exchange()`, and `exchange` runs a fresh `hyper` handshake per request and
/// drops the stream when the response is dropped. A target that held a single
/// duplex would therefore serve exactly one request and fail on the second — and
/// it would fail with a protocol error from `hyper` that says nothing about
/// exhaustion, which is the hardest version of this bug to diagnose.
///
/// Two things keep an implementation honest, and they are different in kind.
///
/// *Structurally*, the variant holds a factory and no duplex field, so there is
/// nowhere in [`RawTarget`] to memoise a stream even by accident. The one call
/// site is `RawEngine::connect`, and it is reached from `send` and
/// `send_upgrading` only.
///
/// *By test*, `stream_target_opens_a_fresh_duplex_for_every_request` asserts that
/// two requests over one target each open their own duplex, against a factory
/// that hands out a stream which is already closed on the second call. A factory
/// that cached would serve the dead stream and fail.
///
/// The duplex a call returns is owned by the caller: hyper writes the request
/// through it and the caller reads the response through it, and dropping the
/// response closes it. A factory that hands out the *same* duplex twice is
/// outside what the type can prevent, and the test above is what catches it.
#[derive(Clone)]
pub struct StreamFactory {
    open: Arc<dyn Fn() -> StreamFuture + Send + Sync>,
    managed_ssh: bool,
}

impl StreamFactory {
    /// Wraps a closure that opens one duplex.
    #[must_use]
    pub fn new<F>(open: F) -> Self
    where
        F: Fn() -> StreamFuture + Send + Sync + 'static,
    {
        Self {
            open: Arc::new(open),
            managed_ssh: false,
        }
    }

    /// Wraps an `async fn`-shaped closure that opens one duplex.
    ///
    /// This is the form a caller writes when the work is naturally async, such
    /// as spawning a process or completing a handshake. The future is boxed by
    /// this constructor rather than by the caller, so a closure that already
    /// returns a [`StreamFuture`] should use [`Self::new`] instead and skip the
    /// box:
    ///
    /// ```
    /// # use neotales_docker::Error;
    /// # use neotales_docker::raw::{Duplex, StreamFactory};
    /// /// A duplex that reports end of input immediately. It is a real
    /// /// `Duplex`; it is just not a conversation.
    /// # struct Empty;
    /// # impl tokio::io::AsyncRead for Empty {
    /// #     fn poll_read(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #         _: &mut tokio::io::ReadBuf<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// # }
    /// # impl tokio::io::AsyncWrite for Empty {
    /// #     fn poll_write(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #         bytes: &[u8],
    /// #     ) -> std::task::Poll<std::io::Result<usize>> {
    /// #         std::task::Poll::Ready(Ok(bytes.len()))
    /// #     }
    /// #     fn poll_flush(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// #     fn poll_shutdown(
    /// #         self: std::pin::Pin<&mut Self>,
    /// #         _: &mut std::task::Context<'_>,
    /// #     ) -> std::task::Poll<std::io::Result<()>> {
    /// #         std::task::Poll::Ready(Ok(()))
    /// #     }
    /// # }
    /// let factory = StreamFactory::from_fn(|| async {
    ///     Err::<Box<dyn Duplex>, Error>(Error::transport("no Engine is configured here"))
    /// });
    ///
    /// // The factory is called once per request, and the transport asks for a
    /// // fresh one every time.
    /// let target = neotales_docker::raw::RawTarget::Stream {
    ///     authority: "docker".to_owned(),
    ///     open: factory,
    /// };
    /// assert!(matches!(target, neotales_docker::raw::RawTarget::Stream { .. }));
    /// # let _ = Empty;
    /// ```
    #[must_use]
    pub fn from_fn<F, Fut>(open: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Box<dyn Duplex>, Error>> + Send + 'static,
    {
        Self::new(move || Box::pin(open()))
    }

    /// Opens one duplex. The transport calls this once per request.
    ///
    /// The returned future is already `#[must_use]`, so the attribute is not
    /// repeated here.
    pub fn open(&self) -> StreamFuture {
        (self.open)()
    }

    /// Carries the managed diagnostic policy with the target, including when a
    /// caller constructs a new raw engine from it. Never inferred from authority.
    #[cfg(all(feature = "ssh", unix))]
    pub(crate) fn with_managed_ssh_policy(mut self) -> Self {
        self.managed_ssh = true;
        self
    }
}

impl<F> From<F> for StreamFactory
where
    F: Fn() -> StreamFuture + Send + Sync + 'static,
{
    fn from(open: F) -> Self {
        Self::new(open)
    }
}

// A derive would print the closure's address, which is noise, and would put a
// `Debug` bound on a caller's own closure for no reason they asked for.
impl fmt::Debug for StreamFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StreamFactory(<opaque>)")
    }
}

/// The proxy leg of an owned plain-HTTP Engine target.
///
/// A plain-HTTP Engine request sent through an explicit forward proxy keeps the
/// daemon's authority in the request target and in `Host`, and puts
/// `Proxy-Authorization` on the request only when this route was configured.
/// The proxy is dialed instead of the daemon, so a failure to reach it is an
/// error rather than a direct connection.
///
/// `Debug` redacts the authorization value. It is a base64-encoded Basic
/// credential, and base64 is not a redaction.
#[derive(Clone)]
pub(crate) struct HttpProxyRoute {
    host: String,
    port: u16,
    authorization: Option<hyper::header::HeaderValue>,
    overall_deadline: Duration,
}

impl HttpProxyRoute {
    /// Creates a validated proxy route.
    ///
    /// The caller has already parsed and validated the proxy URL; this type
    /// carries the dial address and the header value without re-parsing either.
    /// `overall_deadline` bounds the whole proxied request through its
    /// response head, matching the generated client's single request timeout.
    pub(crate) fn new(
        host: String,
        port: u16,
        authorization: Option<hyper::header::HeaderValue>,
        overall_deadline: Duration,
    ) -> Self {
        Self {
            host,
            port,
            authorization,
            overall_deadline,
        }
    }

    /// Overrides the overall request budget for a test fixture.
    #[cfg(test)]
    pub(crate) fn set_overall_deadline(&mut self, overall_deadline: Duration) {
        self.overall_deadline = overall_deadline;
    }
}

impl fmt::Debug for HttpProxyRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxyRoute")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("overall_deadline", &self.overall_deadline)
            .finish()
    }
}

/// Where the owned transport connects.
///
/// `Debug`, `Eq`, and `PartialEq` are hand-written rather than derived, because
/// [`RawTarget::Stream`] holds a [`StreamFactory`] and a closure satisfies none
/// of them. One consequence is documented on [`RawTarget::Stream`] and pinned by
/// a test: two `Stream` targets with the same authority compare equal even when
/// their factories differ, because a closure is not a value. Nothing in the
/// crate decides anything with that comparison.
#[derive(Clone)]
pub enum RawTarget {
    /// A Unix domain socket, as used by a local Docker or Podman daemon.
    ///
    /// The variant exists on every target so that a `match` written by a
    /// downstream caller is portable. Connecting to one on a platform that has
    /// no Unix sockets is an error naming the path, not a compile failure — see
    /// `RawEngine::connect`.
    Unix(PathBuf),
    /// A Windows named pipe, as used by a local Windows daemon.
    ///
    /// The canonical Windows path is `\\.\pipe\docker_engine`. Docker context
    /// files and callers also commonly use `//./pipe/docker_engine`; the Windows
    /// transport normalizes either separator spelling before opening the pipe.
    /// As with [`RawTarget::Unix`], the variant is not gated: a target that
    /// cannot open a pipe reports that rather than failing to compile.
    NamedPipe(PathBuf),
    /// A plain TCP endpoint.
    ///
    /// This variant is plaintext. TLS is applied by the facade's HTTPS
    /// constructors, which build a [`RawTarget::Stream`] that opens a fresh TCP
    /// connection, an optional explicit HTTP `CONNECT` tunnel, and a TLS
    /// handshake per request. A caller that constructs this variant directly is
    /// asking for plain TCP and gets it; there is no implicit upgrade and no
    /// plaintext fallback from the HTTPS target.
    Tcp {
        /// The host to connect to.
        host: String,
        /// The TCP port.
        port: u16,
    },
    /// An endpoint the transport cannot name, opened one duplex at a time.
    ///
    /// This is for a daemon reached by running a command whose standard streams
    /// *are* the Engine's HTTP connection — `docker system dial-stdio` over an
    /// SSH session, which is how Docker itself reaches a remote daemon. There is
    /// no host and port to dial, and no socket to open, so the only way to reach
    /// it is to be handed the bytes.
    ///
    /// `open` is a [`StreamFactory`] and **is called once per request**. See that
    /// type for why it is a factory rather than a duplex, and for the test that
    /// holds an implementation to it. The practical rule for a caller: build the
    /// connection inside the closure and do not keep it.
    ///
    /// `authority` is the value sent in the `Host` header. A `dial-stdio` peer
    /// sees one connection per request and has no authority of its own, but
    /// HTTP/1.1 requires a syntactically valid one; `localhost` is what the
    /// socket and pipe variants send for the same reason, and Docker's own
    /// transport sends `http://docker/` for an SSH endpoint.
    Stream {
        /// The value sent in the `Host` header.
        authority: String,
        /// Opens a fresh duplex for one request.
        open: StreamFactory,
    },
}

impl RawTarget {
    /// Returns the value sent in the `Host` header.
    ///
    /// A socket has no meaningful authority, and the Engine ignores the value,
    /// but HTTP/1.1 requires the header to be present and syntactically valid.
    fn authority(&self) -> String {
        match self {
            // A socket and a pipe have no meaningful authority, and the Engine
            // ignores the value, but HTTP/1.1 requires a syntactically valid one.
            Self::Unix(_) | Self::NamedPipe(_) => "localhost".to_owned(),
            Self::Tcp { host, port } => {
                // A bare IPv6 literal must be bracketed to be a valid authority.
                if host.contains(':') && !host.starts_with('[') {
                    format!("[{host}]:{port}")
                } else {
                    format!("{host}:{port}")
                }
            }
            Self::Stream { authority, .. } => authority.clone(),
        }
    }
}

impl fmt::Debug for RawTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => formatter.debug_tuple("Unix").field(path).finish(),
            Self::NamedPipe(path) => formatter.debug_tuple("NamedPipe").field(path).finish(),
            Self::Tcp { host, port } => formatter
                .debug_struct("Tcp")
                .field("host", host)
                .field("port", port)
                .finish(),
            // The factory is not printed. It is an opaque closure, so the only
            // thing a reader could be shown is an address, which tells them
            // nothing and changes every run.
            Self::Stream { authority, open } => formatter
                .debug_struct("Stream")
                .field("authority", authority)
                .field("open", open)
                .finish(),
        }
    }
}

impl PartialEq for RawTarget {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unix(left), Self::Unix(right))
            | (Self::NamedPipe(left), Self::NamedPipe(right)) => left == right,
            (Self::Tcp { host: lh, port: lp }, Self::Tcp { host: rh, port: rp }) => {
                lh == rh && lp == rp
            }
            (
                Self::Stream {
                    authority: left, ..
                },
                Self::Stream {
                    authority: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }
}

impl Eq for RawTarget {}

/// A request the owned transport can send.
///
/// The path is given without the API version prefix: the transport adds it from
/// its negotiated version, so no caller can forget it or disagree about it.
///
/// # Transport-owned headers
///
/// `Host` is the daemon's authority on the owned forward-proxy route. A
/// caller-supplied `Host` is ignored there so the absolute-form request target
/// and `Host` cannot disagree. On a direct target or a caller-supplied
/// [`RawTarget::Stream`], a caller-supplied `Host` is forwarded as before.
///
/// `Proxy-Authorization` follows the route. On a direct target or a
/// caller-supplied [`RawTarget::Stream`], a caller-supplied value is forwarded
/// unchanged: that is how an existing custom transport authenticates to its own
/// proxy. On a configured `ProxyPolicy::Http` route the facade owns that header,
/// so the transport rejects a request that carries one before the proxy is
/// dialed. The configured credential is the only one sent, and only to the
/// configured proxy.
///
/// # `Debug` redacts
///
/// Not derived. `x-registry-auth` and `x-registry-config` carry a registry
/// credential base64-encoded, and a derived `Debug` printed them. Measured, not
/// assumed: a `RawRequest` with a canary in that header rendered as
/// `headers: {"x-registry-auth": "Y2FuYXJ5LXNlY3JldC1oZWFkZXI="}`. Base64 is not
/// a redaction, and this crate has already been bitten twice by a credential
/// reaching somewhere it could be read. `proxy-authorization` is the third
/// redacted name: the transport adds the configured proxy credential itself and
/// ignores a caller-supplied value.
///
/// The **query** is redacted wholesale rather than filtered by name. It is a
/// caller-supplied `String`, and the set of parameters the Engine accepts is not a
/// closed list this crate controls: printed verbatim it leaked a canary before
/// this was noticed, and a name allow-list would have been a guess about a wire
/// protocol. The **path** is not redacted — it is built from names and ids by this
/// crate's own escaping, and it is the part a reader diagnosing a failed request
/// needs.
pub struct RawRequest {
    /// The HTTP method.
    pub method: Method,
    /// The unversioned path, beginning with `/`.
    pub path: String,
    /// An already-encoded query string, without the leading `?`.
    pub query: Option<String>,
    /// Extra request headers.
    pub headers: hyper::HeaderMap,
    /// The request body.
    pub body: RawBody,
}

/// Header names whose value is a credential.
///
/// **This is a deny-list and it fails open**, which the previous version of this
/// comment claimed was not the case. It said the redaction was "an allow-list of
/// what is safe rather than a deny-list of what is not, which is the only
/// direction that fails safe when the Engine grows a new credential header", and
/// then conceded in the same paragraph that a new header prints. The two
/// sentences contradict each other and the first is wrong.
///
/// A header allow-list is not available, and pretending otherwise would be worse
/// than the gap: the honest choices are a deny-list of the credential headers
/// this crate knows about, or redacting every header value, and the second throws
/// away `content-type` and the other headers a reader diagnosing a failed request
/// actually needs. The list covers the two Engine registry headers and the
/// proxy credential the owned plain-HTTP route can carry. **The gap is real and
/// it is named: a credential in any other header prints.** What makes that
/// survivable is the test beside it, which holds a canary in *each* of these
/// headers — so adding a credential header means the test goes quiet on that
/// header, which is a signal to add it here.
///
/// [`RawRequest`]'s own documentation makes the same argument about the query and
/// reaches the opposite conclusion there, for the same reason: the set of names
/// the Engine accepts is not a closed list this crate controls. The difference is
/// that a query value has no non-secret members worth keeping, and a header value
/// does.
const CREDENTIAL_HEADERS: &[&str] = &[
    "x-registry-auth",
    "x-registry-config",
    "proxy-authorization",
];

impl std::fmt::Debug for RawRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RawRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query.as_ref().map(|_| "<redacted>"))
            .field("headers", &RedactedHeaders(&self.headers))
            .field("body", &self.body)
            .finish()
    }
}

/// Prints every header name, and a value only where the name is not a credential.
struct RedactedHeaders<'headers>(&'headers hyper::HeaderMap);

impl std::fmt::Debug for RedactedHeaders<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = formatter.debug_map();
        for name in self.0.keys() {
            let is_credential = CREDENTIAL_HEADERS
                .iter()
                .any(|known| name.as_str().eq_ignore_ascii_case(known));
            let value = if is_credential {
                "<redacted>".to_owned()
            } else {
                self.0
                    .get(name)
                    .map_or_default(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            };
            map.entry(&name.as_str(), &value);
        }
        map.finish()
    }
}

impl RawRequest {
    /// Creates a bodyless request.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            query: None,
            headers: hyper::HeaderMap::new(),
            body: RawBody::Empty,
        }
    }

    /// Sets the query string.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Sets the request body.
    #[must_use]
    pub fn with_body(mut self, body: RawBody) -> Self {
        self.body = body;
        self
    }

    /// Adds one header.
    ///
    /// `Host` is ignored on the configured forward-proxy route, which always
    /// sends the daemon's authority; direct and custom targets forward it as
    /// before. `Proxy-Authorization` is forwarded on a direct or custom target;
    /// a configured `ProxyPolicy::Http` route rejects the request instead of
    /// sending two proxy credentials. See [`RawRequest`]'s "Transport-owned
    /// headers" section.
    #[must_use]
    pub fn with_header(mut self, name: hyper::header::HeaderName, value: &str) -> Self {
        if let Ok(value) = hyper::header::HeaderValue::from_str(value) {
            self.headers.insert(name, value);
        }
        self
    }
}

/// A repository-owned Engine client for the raw backend.
///
/// The type is private to the crate on purpose: it is the implementation under
/// the public facade, not a second public client. The migration order in the
/// decision record promotes it out of the crate only if the differential
/// fixtures justify replacing the former generated client path outright.
#[derive(Clone, Debug)]
pub struct RawEngine {
    target: RawTarget,
    version: ApiVersion,
    /// Overall budget for locally routed node requests through response head.
    local_overall_deadline: Option<Duration>,
    /// The response-head deadline this engine applies, when its target has one.
    ///
    /// `None` is the existing behavior for a Unix socket, a named pipe, plain
    /// TCP, SSH, or a caller-supplied stream. The facade's HTTPS constructors
    /// install the crate's transport deadline, because HTTPS previously reached
    /// the daemon through the former generated client's bounded client.
    response_head_deadline: Option<Duration>,
    /// An overall request deadline covering connect through the response head.
    ///
    /// `None` is the existing behavior. A per-operation engine may set a value
    /// for a read that must be bounded from connect to head; the response body
    /// is read after that future completes and is not covered, matching the
    /// generated client's single request-timeout shape.
    overall_request_deadline: Option<Duration>,
    /// The explicit HTTP forward proxy this engine dials, when one was selected.
    ///
    /// This is set only by the facade for a plain-HTTP endpoint under
    /// `ProxyPolicy::Http`. A `None` here means a direct connection; there is no
    /// environment lookup and no fallback between the two.
    http_proxy: Option<HttpProxyRoute>,
}

impl RawEngine {
    /// Creates a transport for one target and API version.
    ///
    /// The engine has no response-head deadline by default, which preserves the
    /// existing behavior of every target that predates the HTTPS slice.
    #[must_use]
    pub const fn new(target: RawTarget, version: ApiVersion) -> Self {
        Self {
            target,
            version,
            local_overall_deadline: None,
            response_head_deadline: None,
            overall_request_deadline: None,
            http_proxy: None,
        }
    }

    /// Installs the local facade's single request budget.
    #[cfg(all(test, unix))]
    pub(crate) fn with_local_overall_deadline(mut self, deadline: Duration) -> Self {
        self.local_overall_deadline = Some(deadline);
        self
    }

    /// Routes a plain-HTTP target through an explicit forward proxy.
    ///
    /// The facade sets this only for `ProxyPolicy::Http` on an `http://` or
    /// `tcp://` endpoint. The target keeps the daemon's authority, so the
    /// absolute-form request line and the `Host` header describe the daemon,
    /// while the socket is opened to the proxy. A configured route is never
    /// replaced by a direct connection: a proxy that cannot be reached is an
    /// error.
    #[must_use]
    pub(crate) fn with_http_proxy(mut self, proxy: HttpProxyRoute) -> Self {
        self.http_proxy = Some(proxy);
        self
    }

    /// Sets the response-head deadline for this engine.
    ///
    /// The facade's HTTPS constructors use this; other constructors leave it
    /// unset. `None` means the response head may arrive at any time, which is
    /// the existing behavior for a Unix socket, a named pipe, plain TCP, SSH,
    /// and a caller-supplied stream.
    #[must_use]
    pub(crate) fn with_response_head_deadline(
        mut self,
        response_head_deadline: Option<Duration>,
    ) -> Self {
        self.response_head_deadline = response_head_deadline;
        self
    }

    /// Sets an overall request deadline covering connect through the head.
    ///
    /// This is applied around the whole send future, so it includes the connect,
    /// handshake, request write, and response head. It ends when the head
    /// arrives; the body read is outside it. A per-operation engine uses this
    /// for a secret read on a captured local target, without changing the shared
    /// client's response-head field. A timeout is reported with the same
    /// transport deadline marker as the response-head and proxy budgets, and its
    /// diagnostic names only the budget — not the endpoint or any response text.
    #[must_use]
    pub(crate) fn with_overall_request_deadline(
        mut self,
        overall_request_deadline: Option<Duration>,
    ) -> Self {
        self.overall_request_deadline = overall_request_deadline;
        self
    }

    /// Returns the overall request deadline, for the facade's wiring tests.
    #[cfg(all(test, unix))]
    #[must_use]
    pub(crate) const fn overall_request_deadline(&self) -> Option<Duration> {
        self.overall_request_deadline
    }

    /// Returns the API version this transport prefixes onto every path.
    #[must_use]
    pub const fn version(&self) -> ApiVersion {
        self.version
    }

    /// Builds the versioned, query-suffixed request URI.
    ///
    /// Returns an error when the path is not an absolute path, because a
    /// relative path would silently be sent against the wrong resource.
    ///
    /// `pub(crate)` rather than `pub(super)` so the facade's tests can read the
    /// prefix off a real engine. Those tests are where the claim "the owned
    /// transport speaks `API_VERSION`" is checked, and a check that could only
    /// read `version()` would pass even if the prefix were rendered from some
    /// other value. Not `pub`: this is not part of the crate's contract, and a
    /// caller wanting to know the version reads [`Self::version`].
    pub(crate) fn request_uri(&self, request: &RawRequest) -> Result<String, Error> {
        if !request.path.starts_with('/') {
            return Err(Error::invalid_input(format!(
                "Engine request path must start with '/', got '{}'",
                request.path
            )));
        }
        let mut uri = format!("/v{}.{}", self.version.major, self.version.minor);
        uri.push_str(&request.path);
        if let Some(query) = &request.query {
            uri.push('?');
            uri.push_str(query);
        }
        Ok(uri)
    }

    /// Returns the response trust policy for the configured route.
    ///
    /// Any proxy route controls its response headers. Only an authenticated
    /// route has a configured credential that could be echoed into an error
    /// message, so only that route withholds the message.
    fn proxy_response_policy(&self) -> (bool, bool) {
        let proxy_controlled_headers = self.http_proxy.is_some();
        let withhold_error_message = self
            .http_proxy
            .as_ref()
            .is_some_and(|proxy| proxy.authorization.is_some());
        (proxy_controlled_headers, withhold_error_message)
    }

    /// Only fixed method names identify managed operations: paths, queries,
    /// custom method tokens and request/response contents are not diagnostics.
    fn managed_ssh_operation(&self, method: &Method) -> Option<&'static str> {
        match &self.target {
            RawTarget::Stream { open, .. } if open.managed_ssh => Some(match *method {
                Method::GET => "GET",
                Method::HEAD => "HEAD",
                Method::POST => "POST",
                Method::PUT => "PUT",
                Method::DELETE => "DELETE",
                Method::PATCH => "PATCH",
                Method::OPTIONS => "OPTIONS",
                Method::CONNECT => "CONNECT",
                Method::TRACE => "TRACE",
                _ => "custom-method",
            }),
            _ => None,
        }
    }

    fn apply_response_policy(
        &self,
        response: RawResponse,
        managed_operation: Option<&'static str>,
    ) -> RawResponse {
        let (headers, message) = self.proxy_response_policy();
        response
            .with_proxy_response_policy(headers, message)
            .with_managed_ssh_policy(managed_operation)
    }

    /// Refuses a caller-supplied proxy credential on a configured proxy route.
    ///
    /// A direct target and a caller-supplied [`RawTarget::Stream`] keep the
    /// pre-existing behavior: `Proxy-Authorization` is forwarded like any other
    /// caller header, which is how a custom transport authenticates to its own
    /// proxy. A configured `ProxyPolicy::Http` route owns that header instead,
    /// so a second value is rejected before the proxy is dialed rather than
    /// silently dropped or sent alongside the configured credential.
    fn validate_request_headers(&self, request: &RawRequest) -> Result<(), Error> {
        if self.http_proxy.is_some() && request.headers.contains_key(PROXY_AUTHORIZATION) {
            return Err(Error::invalid_input(
                "a caller-supplied Proxy-Authorization header conflicts with the configured \
                 forward proxy credential; remove it, or use a direct/custom target when the \
                 caller owns proxy authentication",
            ));
        }
        Ok(())
    }

    /// Opens a connection, sends the request, and returns the live response.
    ///
    /// The response body must be read on the same runtime that made the call.
    /// hyper's HTTP/1 client only reads from the socket while its connection
    /// future is being polled, and that future runs as a task on the runtime that
    /// dialled, so a body read on a different runtime finds the socket gone.
    /// Reading the body on the same runtime — or on a task of it — always works.
    ///
    /// Dropping the response cancels the transfer: the body is dropped, the
    /// connection task is stopped, and the daemon observes the disconnect. There
    /// is no cancel message to send and therefore no way for the two ends to
    /// disagree about whether a transfer is still wanted.
    ///
    /// Waiting for the response head is bounded only when the engine has a
    /// response-head deadline. The facade's HTTPS target installs a 120-second
    /// response-head budget separately from its establishment budget. The
    /// facade's plain-HTTP forward-proxy route installs one 120-second overall
    /// request budget covering the proxy TCP connect, request-body production and
    /// backpressure, and the response head; it ends when the head arrives and
    /// does not wrap the response body. That is the same shape as the generated
    /// client's single request timeout for the same endpoint, and it also applies
    /// to `send_unbounded`, so `wait`, `stop`, and `restart` are bounded on a
    /// proxied endpoint. A Unix socket, named pipe, direct plain TCP endpoint,
    /// SSH target, or caller-supplied stream is unbounded unless the client
    /// installs a deadline. A secret read on a captured local target builds a
    /// per-operation engine with a 120-second overall request deadline covering
    /// connect through the response head; the body is unbounded. The shared
    /// `connect_local` client does not set its response-head field, so a local
    /// service update is unchanged. When a response-head deadline applies, its
    /// clock starts when
    /// hyper has fully polled the request body, not when the daemon has confirmed
    /// delivery. A producer that stalls before that point is not bounded by that
    /// head clock; on the proxy route the overall budget still bounds it. Socket
    /// backpressure can still let a head deadline fire after the producer
    /// completes, because the signal is producer completion, not delivery; this
    /// is a known limitation, not a hard upload-delivery bound. Dropping the
    /// operation future is how a caller cancels an upload.
    ///
    /// A timeout means the response head did not arrive in time (or, on the
    /// proxy route, the overall budget expired before it did), **not** that
    /// the daemon did nothing. The request may already have been processed, so
    /// the outcome is unknown and must be reconciled before retrying; a retried
    /// stop or restart can repeat the operation. A timed-out proxied request has
    /// the same unknown outcome: the proxy may already have forwarded it.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not absolute, the socket cannot be
    /// opened, the request cannot be written, a caller-supplied
    /// `Proxy-Authorization` conflicts with the configured proxy route, or the
    /// response head does not arrive before the transport deadline. A daemon
    /// that answers with a non-2xx status is **not** an error here: status
    /// interpretation belongs to the operation layer, which knows what a 404 or
    /// a 500 means for that specific call. That layer withholds a non-success
    /// message on an authenticated proxy route and reports only the status plus
    /// fixed safe text.
    pub async fn send(&self, request: RawRequest) -> Result<RawResponse, Error> {
        self.send_with_deadline(request, self.response_head_deadline)
            .await
    }

    /// Sends a request whose response head is allowed to arrive at any time.
    ///
    /// This exists for the daemon-governed waits: `POST /containers/{id}/wait`,
    /// stop, and restart. Their contracts block until the daemon reaches the
    /// requested state, which can be longer than the transport's 120 seconds. A
    /// 120-second response-head deadline would turn a healthy long-running
    /// operation into a transport error. Dropping the operation future is how a
    /// caller cancels the wait. A configured plain-HTTP proxy route still applies
    /// its single 120-second overall budget to these operations, matching the
    /// generated client's previous behavior on that route. Direct plain HTTP,
    /// HTTPS, SSH, and caller-supplied streams remain unbounded here unless an
    /// overall request deadline has been configured.
    pub(crate) async fn send_unbounded(&self, request: RawRequest) -> Result<RawResponse, Error> {
        self.send_with_deadline(request, None).await
    }

    /// [`Self::send`] with an explicit response-head deadline.
    ///
    /// The production callers use the crate's transport deadline, except for
    /// [`Self::send_unbounded`] and the shutdown operations whose requested
    /// grace period can exceed it. This form also lets the bound itself be
    /// tested without waiting two minutes.
    pub(crate) async fn send_with_deadline(
        &self,
        request: RawRequest,
        response_head_deadline: Option<Duration>,
    ) -> Result<RawResponse, Error> {
        self.validate_request_headers(&request)?;
        let uri = self.request_uri(&request)?;
        self.send_to_uri(request, uri, response_head_deadline).await
    }

    /// Sends the unversioned negotiation request with the usual transport policies.
    pub(crate) async fn send_unversioned_version(&self) -> Result<RawResponse, Error> {
        let request = RawRequest::new(Method::GET, "/version");
        self.validate_request_headers(&request)?;
        self.send_to_uri(request, "/version".to_owned(), self.response_head_deadline)
            .await
    }

    async fn send_to_uri(
        &self,
        request: RawRequest,
        uri: String,
        response_head_deadline: Option<Duration>,
    ) -> Result<RawResponse, Error> {
        let future = self.send_inner(request, &uri, response_head_deadline);
        if let Some(overall) = self.overall_request_deadline {
            return match tokio::time::timeout(overall, future).await {
                Ok(result) => result,
                Err(_) => Err(Error::transport_deadline(format!(
                    "timed out after {overall:?} waiting for the Engine request to complete"
                ))),
            };
        }
        if let Some(deadline) = self.local_overall_deadline {
            return match tokio::time::timeout(deadline, future).await {
                Ok(result) => result,
                Err(_) => Err(Error::transport_deadline(
                    "local request timed out; its outcome is unknown",
                )),
            };
        }
        if let Some(proxy) = &self.http_proxy {
            let deadline = proxy.overall_deadline;
            return match tokio::time::timeout(deadline, future).await {
                Ok(result) => result,
                Err(_) => Err(Error::transport_deadline(format!(
                    "timed out after {deadline:?} waiting for the HTTP proxy request to complete"
                ))),
            };
        }
        future.await
    }

    /// Sends a request after header validation, without the proxy's overall
    /// budget. Callers wrap this when `http_proxy` is set.
    async fn send_inner(
        &self,
        request: RawRequest,
        uri: &str,
        response_head_deadline: Option<Duration>,
    ) -> Result<RawResponse, Error> {
        let stream = self.connect().await?;
        self.exchange(stream, request, uri, response_head_deadline)
            .await
    }

    /// Opens the transport connection for the configured target.
    ///
    /// Each variant's arm is gated rather than the variant itself, so the public
    /// enum is the same on every target and a caller can write a portable
    /// `match`. A target the host cannot provide reports why, naming the path it
    /// was asked for — which is the difference between "this platform has no
    /// Unix sockets" and a caller that silently reached for the wrong transport.
    async fn connect(&self) -> Result<Box<dyn Duplex>, Error> {
        // A proxy route is meaningful only for a plain TCP target. The facade
        // never pairs it with another variant, but a future caller of the
        // crate-private builder must not get a direct connection by accident.
        if self.http_proxy.is_some() && !matches!(self.target, RawTarget::Tcp { .. }) {
            return Err(Error::transport(
                "an explicit HTTP proxy route requires a plain TCP Engine target",
            ));
        }
        match &self.target {
            RawTarget::Unix(path) => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(path)
                        .await
                        .map_err(|error| {
                            transport_error(format!("connect to {}", path.display()), error)
                        })?;
                    Ok(Box::new(stream))
                }
                #[cfg(not(unix))]
                {
                    Err(transport_error(
                        format!("connect to {}", path.display()),
                        std::io::Error::other(
                            "this platform has no Unix domain sockets; \
                             a local daemon is reached through a named pipe or TCP",
                        ),
                    ))
                }
            }
            RawTarget::NamedPipe(path) => {
                #[cfg(windows)]
                {
                    let canonical_path = normalize_windows_pipe_path(path);
                    let stream = tokio::net::windows::named_pipe::ClientOptions::new()
                        .open(&canonical_path)
                        .map_err(|error| {
                            transport_error(
                                format!("connect to {}", canonical_path.display()),
                                error,
                            )
                        })?;
                    Ok(Box::new(stream))
                }
                #[cfg(not(windows))]
                {
                    Err(transport_error(
                        format!("connect to {}", path.display()),
                        std::io::Error::other(
                            "this platform has no named pipes; \
                             a local daemon is reached through a Unix socket or TCP",
                        ),
                    ))
                }
            }
            RawTarget::Tcp { host, port } => {
                // A configured proxy replaces the dial address, never the
                // request's target authority. The absolute-form request line is
                // built in `exchange_inner`, and `Host` stays the daemon's.
                // The whole proxied request, including this connect, is bounded
                // by `send_with_deadline`'s overall proxy budget.
                let stream = if let Some(proxy) = &self.http_proxy {
                    TcpStream::connect((proxy.host.as_str(), proxy.port))
                        .await
                        .map_err(|error| {
                            transport_error(
                                format!("connect to the HTTP proxy {}:{}", proxy.host, proxy.port),
                                error,
                            )
                        })?
                } else {
                    TcpStream::connect((host.as_str(), *port))
                        .await
                        .map_err(|error| {
                            transport_error(format!("connect to {host}:{port}"), error)
                        })?
                };
                // The Engine speaks HTTP/1.1, and a Nagle-disabled stream keeps
                // small request/response pairs from paying a delayed-ACK stall.
                let _ignored = stream.set_nodelay(true);
                Ok(Box::new(stream))
            }
            RawTarget::Stream { authority, open } => {
                // Called once per request, and the duplex is handed straight to
                // `exchange`, which drops it with the response. There is no
                // field on the target to cache one in, which is the structural
                // half of the contract `StreamFactory` documents.
                //
                // The factory's error is rendered through its *source chain*
                // rather than its `Display`. A factory may return a transport
                // error whose own summary is generic while the reason is in its
                // source, so formatting the summary here would replace every
                // reason a factory has with the same words. Walking the chain
                // keeps the factory's own words whichever kind it used.
                open.open().await.map_err(|error| {
                    #[cfg(all(feature = "ssh", unix))]
                    if error.managed_ssh_host_key_rejection().is_some()
                        || error.managed_ssh_establishment_failure().is_some()
                    {
                        return error;
                    }
                    let timeout = error.transport_timeout_kind();
                    let message = format!(
                        "open a duplex for the Engine at {authority}: {}",
                        describe(&error)
                    );
                    if let Some(kind) = timeout {
                        Error::transport_timeout(kind, message)
                    } else {
                        Error::transport(message)
                    }
                })
            }
        }
    }

    /// Writes the request over an open stream and hands back the response.
    /// Sends `request` on a connection that can switch protocols, for an
    /// operation the daemon answers with `101`.
    ///
    /// This is the only route to a live bidirectional connection on this
    /// transport. A connection built any other way answers a protocol switch by
    /// failing the pending upgrade with `new_user_manual_upgrade`, and the
    /// response extensions that carry the handle are then never populated, so a
    /// caller would get an opaque error where it asked for a socket.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the connection, handshake, or request
    /// cannot be completed.
    pub(crate) async fn send_upgrading(&self, request: RawRequest) -> Result<RawResponse, Error> {
        self.validate_request_headers(&request)?;
        let uri = self.request_uri(&request)?;
        self.send_upgrading_to_uri(request, &uri).await
    }

    /// Sends the unversioned Engine session request through the normal upgrade path.
    #[allow(dead_code)] // Reserved for the internal session substrate.
    pub(crate) async fn send_upgrading_session(
        &self,
        request: RawRequest,
    ) -> Result<RawResponse, Error> {
        self.validate_request_headers(&request)?;
        self.send_upgrading_to_uri(request, "/session").await
    }

    pub(crate) async fn send_upgrading_grpc(
        &self,
        request: RawRequest,
    ) -> Result<RawResponse, Error> {
        self.validate_request_headers(&request)?;
        self.send_upgrading_to_uri(request, "/grpc").await
    }

    pub(crate) fn grpc_deadline(&self) -> Option<Duration> {
        self.overall_request_deadline
            .or(self.local_overall_deadline)
            .or_else(|| self.http_proxy.as_ref().map(|proxy| proxy.overall_deadline))
            .or(self.response_head_deadline)
    }

    async fn send_upgrading_to_uri(
        &self,
        request: RawRequest,
        uri: &str,
    ) -> Result<RawResponse, Error> {
        let future = self.send_upgrading_inner(request, uri);
        if let Some(overall) = self.overall_request_deadline {
            return match tokio::time::timeout(overall, future).await {
                Ok(result) => result,
                Err(_) => Err(Error::transport_deadline(format!(
                    "timed out after {overall:?} waiting for the Engine request to complete"
                ))),
            };
        }
        if let Some(proxy) = &self.http_proxy {
            let deadline = proxy.overall_deadline;
            return match tokio::time::timeout(deadline, future).await {
                Ok(result) => result,
                Err(_) => Err(Error::transport_deadline(format!(
                    "timed out after {deadline:?} waiting for the HTTP proxy request to complete"
                ))),
            };
        }
        future.await
    }

    /// Sends an upgrade request without the proxy's overall budget. Callers wrap
    /// this when `http_proxy` is set.
    async fn send_upgrading_inner(
        &self,
        request: RawRequest,
        uri: &str,
    ) -> Result<RawResponse, Error> {
        let stream = self.connect().await?;
        self.exchange_inner(stream, request, uri, true, self.response_head_deadline)
            .await
    }

    /// Opens a connection and sends `request`, for an operation that will read a
    /// complete document.
    async fn exchange(
        &self,
        stream: Box<dyn Duplex>,
        request: RawRequest,
        uri: &str,
        response_head_deadline: Option<Duration>,
    ) -> Result<RawResponse, Error> {
        self.exchange_inner(stream, request, uri, false, response_head_deadline)
            .await
    }

    /// Opens a connection and sends `request`, for an operation that expects the
    /// daemon to switch protocols and hand the connection over.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the connection, handshake, or request
    /// cannot be completed, or when the response head does not arrive before
    /// `response_head_deadline`.
    async fn exchange_inner(
        &self,
        stream: Box<dyn Duplex>,
        request: RawRequest,
        uri: &str,
        upgrade: bool,
        response_head_deadline: Option<Duration>,
    ) -> Result<RawResponse, Error> {
        let managed_operation = self.managed_ssh_operation(&request.method);
        let timeout = crate::TransportTimeoutObservation::default();
        let stream = ObservedDuplex {
            inner: stream,
            timeout: timeout.clone(),
        };
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| transport_error("Engine handshake", error))?;
        // A connection that is not upgrade-capable answers a protocol switch by
        // failing the pending upgrade with `new_user_manual_upgrade`, so the
        // caller would see an opaque error instead of the socket it asked for.
        // `with_upgrades` hands the connection's parts to the pending upgrade
        // instead, which is the only way a hyper 1 *client* can end up owning the
        // raw stream after a `101`. The type is unnameable outside hyper, so it
        // is spawned directly and never named.
        let driver = if upgrade {
            spawn_connection_driver(connection.with_upgrades())
        } else {
            // Started before the request so it is already being polled by the time
            // `send_request` is awaited; without it hyper never writes the request.
            spawn_connection_driver(connection)
        };
        // From this point the driver must not outlive this future. Dropping a
        // `JoinHandle` only detaches the task, so an early return or a cancelled
        // caller would leave the connection being driven against a socket nobody
        // owns. The guard aborts it on every such path; the successful path hands
        // the driver to the response, which then owns it.
        let mut driver = DriverGuard::new(driver);

        let known_len = request.body.known_len();
        let (body, body_written_rx) = match response_head_deadline {
            Some(_) => {
                let (written, written_rx) = tokio::sync::oneshot::channel();
                (
                    request.body.into_request_with_completion(written),
                    Some(written_rx),
                )
            }
            None => (request.body.into_request(), None),
        };
        let length = known_len.map_or_else(|| body.size_hint().exact(), Some);

        // The connection is left open rather than closed after the response.
        // With `Connection: close`, hyper finishes the connection as soon as it
        // has the whole message in its buffer, which races the body read and
        // turns a complete response into a truncated one. Leaving it open also
        // matches how the former generated client path behaves, so the differential fixtures
        // compare like with like.
        // A plain-HTTP forward proxy requires absolute-form. The authority is
        // the daemon's, not the proxy's, so the request line and `Host` keep
        // the target's URL semantics; an IPv6 literal is bracketed once by
        // `RawTarget::authority`.
        let mut builder = Request::builder().method(request.method);
        builder = match &self.http_proxy {
            Some(_) => builder.uri(format!("http://{}{uri}", self.target.authority())),
            None => builder.uri(uri),
        };
        builder = builder.header(HOST, self.target.authority());
        if let Some(length) = length {
            builder = builder.header(CONTENT_LENGTH, length);
        } else {
            builder = builder.header(TRANSFER_ENCODING, "chunked");
        }
        for (name, value) in &request.headers {
            // Caller headers are applied last so an operation can override a
            // transport default such as `Content-Type`, but never a framing
            // header, which the body length above already decided.
            if is_framing_header(name) {
                continue;
            }
            // On the owned forward-proxy route, `Host` is transport-owned: the
            // request target and `Host` both describe the daemon, and a
            // caller-supplied value would replace or duplicate the authority the
            // proxy is asked to reach. Direct and caller-supplied stream targets
            // keep the previous behavior and forward the caller's header.
            if self.http_proxy.is_some() && name == HOST {
                continue;
            }
            // `Connection` decides the connection's lifetime, which is why the
            // framing check above refuses it by default. On a request that exists
            // to switch protocols it is the opposite: `Connection: Upgrade` is the
            // request, and withholding it is what makes the daemon answer `200`
            // with an ordinary body instead of handing over the connection. The
            // one value refused even here is `close`, which would ask for the
            // connection to be dropped in the same breath as asking to keep it.
            if name == CONNECTION && (!upgrade || is_connection_close(value)) {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }
        if let Some(proxy) = &self.http_proxy
            && let Some(authorization) = &proxy.authorization
        {
            builder = builder.header(PROXY_AUTHORIZATION, authorization.clone());
        }

        let message = builder
            .body(body)
            .map_err(|error| transport_error("building the Engine request", error))?;

        // `send_request` does not make progress on its own: hyper's HTTP/1
        // client only writes the request and reads the response head while the
        // connection future is being polled. Awaiting the request without
        // driving the connection deadlocks, so the two are polled together.
        //
        // The connection is then handed to the response rather than spawned. A
        // spawned task belongs to the runtime that created it, so a caller that
        // read the body on a later runtime would find the socket closed
        // underneath it with nothing to explain why.
        //
        // The response-head deadline starts only once the request body has been
        // written. A caller-owned upload is not put on a clock it did not ask
        // for; the body's own completion is what starts the wait. A daemon that
        // answers before reading the whole body wins the `select` and is not
        // delayed by a deadline that has not started.
        let send = sender.send_request(message);
        tokio::pin!(send);
        let request_error = |error| {
            timeout
                .error()
                .unwrap_or_else(|| transport_error("sending the Engine request", error))
        };
        let response = match (response_head_deadline, body_written_rx) {
            (Some(response_head_deadline), Some(body_written_rx)) => {
                tokio::select! {
                    result = &mut send => {
                        result.map_err(request_error)?
                    }
                    _ = body_written_rx => {
                        match tokio::time::timeout(response_head_deadline, &mut send).await {
                            Ok(result) => result.map_err(request_error)?,
                            Err(_) => {
                                return Err(Error::transport_deadline(format!(
                                    "timed out after {response_head_deadline:?} waiting for the \
                                     Engine response head"
                                )));
                            }
                        }
                    }
                }
            }
            _ => send.await.map_err(request_error)?,
        };

        let (parts, body) = response.into_parts();
        // The extensions are kept because hyper puts the pending `OnUpgrade` in
        // them when the daemon answers `101`, and that handle is the only route
        // back to the socket. Discarding them with the rest of the parts is what
        // made a protocol switch unusable here: the caller had a status and a
        // body and no way to reach the connection the daemon had just handed over.
        let response = RawResponse::with_extensions(
            parts.status,
            parts.headers,
            parts.extensions,
            body,
            driver.hand_off(),
        )
        .with_transport_timeout(timeout);
        Ok(self.apply_response_policy(response, managed_operation))
    }
}

/// Hyper reports connection failures through the response or upgrade channel.
/// The I/O observer independently retains local markers even when that channel
/// substitutes a generic cancellation for the original error.
fn spawn_connection_driver(
    connection: impl Future<Output = Result<(), hyper::Error>> + Send + 'static,
) -> ConnectionDriver {
    tokio::spawn(async move {
        let _finished = connection.await;
    })
    .abort_handle()
}

/// Keeps a spawned connection driver alive only until a response owns it.
///
/// `tokio::spawn` returns a `JoinHandle` that detaches the task when dropped, so
/// a driver whose abort handle is only stored in the response is still detached
/// by every early return or cancellation before that handoff. Owning the abort
/// handle here makes the driver stop at every point after the task is spawned,
/// until [`Self::hand_off`] transfers ownership to the [`RawResponse`], which
/// then aborts it on drop.
struct DriverGuard {
    driver: Option<ConnectionDriver>,
}

impl DriverGuard {
    fn new(driver: ConnectionDriver) -> Self {
        Self {
            driver: Some(driver),
        }
    }

    /// Transfers the driver to the response that now owns the connection.
    ///
    /// After this call the guard no longer aborts, so the response's own drop
    /// decides the connection's lifetime. That keeps a streaming body alive
    /// after the request future is gone. An upgrade transfers the socket
    /// instead: [`RawResponse::into_upgraded`] drops the response, which
    /// requests an abort through the handle, and the returned halves own the
    /// connection once the upgrade completes.
    fn hand_off(&mut self) -> ConnectionDriver {
        self.driver
            .take()
            .expect("the connection driver is handed off exactly once")
    }
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// Reports whether a header decides message framing.
///
/// `Connection` is handled separately, by the request loop, because whether it
/// is honoured depends on why the request was sent.
fn is_framing_header(name: &hyper::header::HeaderName) -> bool {
    name == CONTENT_LENGTH || name == TRANSFER_ENCODING
}

/// Reports whether a `Connection` header value asks for the socket to be closed.
///
/// Compared token by token rather than by whole value, because the header
/// carries a comma-separated list of directives and `close` is only meaningful
/// as one of them.
fn is_connection_close(value: &hyper::header::HeaderValue) -> bool {
    value.to_str().is_ok_and(|text| {
        text.split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}

/// Wraps a connection or request failure with the target it happened against.
fn transport_error(what: impl std::fmt::Display, error: impl std::error::Error + 'static) -> Error {
    let message = format!("failed to {what}: {error}");
    if let Some(kind) = crate::transport_timeout_in(&error) {
        Error::transport_timeout(kind, message)
    } else {
        Error::transport(message)
    }
}

/// Renders an error together with every cause beneath it.
///
/// `Display` alone is not enough for an [`Error`] in this crate. `ErrorKind::Transport`
/// renders as a fixed string and keeps the composed message — the operation and
/// the target — in its `source`, so a formatter that reads only the summary
/// reports the same eleven words for every failure on every path. That is escape
/// criterion 6 in the project's own notes, and it is still open.
///
/// Two links are joined with `: `, which is the spelling the rest of this
/// module already uses, and the chain is bounded by the `source` chain itself:
/// a cycle would have to be built deliberately, and `Error::source` returns a
/// borrow of the same object rather than a fresh one.
fn describe(error: &Error) -> String {
    let mut rendered = error.to_string();
    let mut current = std::error::Error::source(error);
    while let Some(source) = current {
        rendered.push_str(": ");
        rendered.push_str(&source.to_string());
        current = source.source();
    }
    rendered
}

/// Sets a JSON `Content-Type` on a request.
pub fn json_content_type(request: RawRequest) -> RawRequest {
    request.with_header(CONTENT_TYPE, "application/json")
}

/// Serializes a value as a JSON request body.
///
/// # Errors
///
/// Returns an error when the value cannot be encoded. Serialization happens
/// before the connection is opened, so a caller never has to roll back a request
/// that was partially written.
pub fn json_body<T>(value: &T) -> Result<RawBody, Error>
where
    T: serde::Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(value).map_err(|error| {
        Error::invalid_input(format!("failed to encode the Engine request body: {error}"))
    })?;
    Ok(RawBody::from_bytes(Bytes::from(encoded)))
}

/// Interprets a response status and, when it is not a success, its body.
///
/// An Engine error body is a JSON object with a `message` member. The message is
/// preserved verbatim so a caller can print the daemon's own words under
/// `--raw-error`, but it is never logged, wrapped, or truncated by this layer.
/// A non-2xx answer from an explicit forward proxy (for example a `407`) uses the
/// same channel. On an authenticated proxy route, the response text is withheld
/// and replaced with fixed safe text: a malicious proxy can echo the configured
/// credential in an arbitrary encoding, so no part of its message is trusted. The
/// status is preserved. On an unauthenticated proxy route there is no configured
/// credential to echo, so the response message is preserved. This layer does not
/// claim to know whether the proxy or the daemon produced the status.
///
/// Managed SSH targets withhold peer failure text for **every** operation,
/// preserving HTTP status and safe typed deadline/host-key markers. This
/// shared policy uses fixed HTTP-method and status wording; operation-specific
/// wrappers may use their own fixed content-free errors. This is stricter than
/// native SSH because managed SSH carries arbitrary Engine traffic, including
/// secrets in request bodies. The policy travels with the target, not an operation
/// allowlist; custom streams retain their default policy. Explicit raw response
/// data and successful values are not sanitized.
///
/// # Errors
///
/// Returns an error when the daemon rejected the request, carrying the status
/// and the daemon's message (or the route's fixed safe text) in
/// [`Error::api_error`], or when a success response
/// body could not be read within the document limit.
pub async fn engine_result(response: RawResponse) -> Result<Bytes, Error> {
    let status = response.status;
    if status.is_success() {
        return response.document().await.map_err(Error::from);
    }
    if response.withholds_error_message() {
        // Managed SSH carries arbitrary Engine traffic; an authenticated
        // forward proxy can also echo a credential in any encoding. Neither
        // route trusts failure text. Do not read the body at all.
        return Err(Error::engine_api(status, response.withheld_error_message()));
    }
    let raw = response.document().await.unwrap_or_else(|_| Bytes::new());
    Err(Error::engine_api(status, engine_message(&raw, status)))
}

/// The fixed, trusted error text used instead of an authenticated proxy response.
pub(super) fn withheld_proxy_message(status: StatusCode) -> String {
    format!(
        "response text withheld for an authenticated forward proxy (HTTP {})",
        status.as_u16()
    )
}

/// Extracts the `message` member of an Engine error body.
///
/// A body that is absent, truncated, or not JSON is reported by status alone
/// rather than replacing the daemon's answer with a parsing complaint: a user
/// debugging a daemon failure needs the real status, not this layer's opinion.
pub(super) fn engine_message(raw: &[u8], status: StatusCode) -> String {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| {
            format!(
                "daemon returned HTTP {} {}",
                status.as_u16(),
                status
                    .canonical_reason()
                    .unwrap_or("without a reason phrase")
            )
        })
}

/// Decodes a bounded Engine document into a repository-owned model.
///
/// # Errors
///
/// Returns an error when the document is not the expected shape. The diagnostic
/// names a content-free category, line, and column; it never includes response
/// text or the decoded value. Serde's own message can quote a wrong-typed value,
/// and on a proxied response that value is untrusted.
pub fn decode<T>(raw: &[u8]) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(raw).map_err(|error| {
        Error::invalid_input(format!(
            "failed to decode the Engine response document: {}",
            serde_error_summary(&error)
        ))
    })
}

/// Describes a serde decode failure without quoting response text.
///
/// `serde_json::Error`'s `Display` can include the unexpected value, and a
/// custom deserializer can make its message say anything. The summary therefore
/// uses only the fixed error category and the parser position; no message text,
/// field name, or value is carried into the error.
pub(crate) fn serde_error_summary(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "I/O error",
        serde_json::error::Category::Syntax => "syntax error",
        serde_json::error::Category::Data => "data error",
        serde_json::error::Category::Eof => "unexpected end of input",
    };
    format!(
        "{category} at line {}, column {}",
        error.line(),
        error.column()
    )
}

/// Collects a streaming response into newline-delimited JSON values.
///
/// This is the shape the Engine uses for `build`, `pull`, `push`, and `events`.
/// The records are read one at a time by `FrameStream::next_json`, so an
/// endless event stream never accumulates in memory. A record over
/// [`MAX_RECORD_BYTES`](crate::raw::MAX_RECORD_BYTES) is an error rather than a
/// larger `Vec`, which is the case that stops the accumulation from being the
/// peer's to decide.
///
/// It is the bounded form of that reader: it runs until the daemon closes the
/// body, which is the right shape for a stream that ends (`build`, a finished
/// `pull`) and the wrong one for a stream that does not (`stats` with
/// `stream=true`, `events` with a filter that keeps matching). A caller that
/// wants to stop early drops the `FrameStream` instead of calling this.
///
/// # Errors
///
/// Returns an error when the connection fails mid-transfer or when a record is
/// not JSON. A trailing partial record is reported rather than silently
/// dropped, because a truncated final message would hide a daemon-side failure.
///
/// One behavior changed when this moved onto `FrameStream::next_json`: a
/// final record with no trailing newline used to be parsed and then discarded,
/// and is now returned. The old shape lost a record the daemon had sent.
pub async fn collect_json_frames(response: RawResponse) -> Result<Vec<serde_json::Value>, Error> {
    let mut frames = response.into_frames();
    let mut values = Vec::new();
    while let Some(value) = frames.next_json().await? {
        values.push(value);
    }
    Ok(values)
}

/// Trims ASCII whitespace from both ends of a slice.
pub(super) fn trim_ascii(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &value[start..end]
}

/// Converts `/` separators to the native `\` form without changing any other
/// UTF-16 code units in a Windows named-pipe path.
#[cfg(any(windows, test))]
fn normalize_windows_pipe_separators(units: impl IntoIterator<Item = u16>) -> Vec<u16> {
    units
        .into_iter()
        .map(|unit| {
            if unit == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                unit
            }
        })
        .collect()
}

#[cfg(windows)]
fn normalize_windows_pipe_path(path: &std::path::Path) -> PathBuf {
    let units = normalize_windows_pipe_separators(path.as_os_str().encode_wide());
    PathBuf::from(std::ffi::OsString::from_wide(&units))
}

#[cfg(test)]
mod response_head_tests {
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use futures_util::{StreamExt, stream};
    use hyper::Method;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    use super::{Duplex, HttpProxyRoute, RawBody, RawEngine, RawRequest, RawTarget, StreamFactory};
    use crate::{API_VERSION, ContainerWaitOptions, Error};

    fn engine_at(address: SocketAddr) -> RawEngine {
        RawEngine::new(
            RawTarget::Tcp {
                host: "127.0.0.1".to_owned(),
                port: address.port(),
            },
            API_VERSION,
        )
    }

    /// A mutex-guarded write gate. The blocked flag and the registered waker
    /// live under the same lock, so `unblock` cannot miss a writer that is about
    /// to return `Pending`.
    struct WriteGate {
        state: Mutex<GateState>,
    }

    struct GateState {
        blocked: bool,
        waker: Option<Waker>,
    }

    impl WriteGate {
        fn new() -> Self {
            Self {
                state: Mutex::new(GateState {
                    blocked: true,
                    waker: None,
                }),
            }
        }

        fn should_block(&self, waker: &Waker) -> bool {
            let mut state = self.state.lock().expect("the write gate");
            if state.blocked {
                state.waker = Some(waker.clone());
                true
            } else {
                false
            }
        }

        fn unblock(&self) {
            let waker = {
                let mut state = self.state.lock().expect("the write gate");
                state.blocked = false;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        /// Reports whether the gate is still closing the path.
        ///
        /// `unblock` is the only method that wakes a blocked writer, so this is
        /// how a test shows that a stalled write is gate-induced rather than an
        /// ordinary `poll_write` that happened to be unready.
        fn is_blocked(&self) -> bool {
            self.state.lock().expect("the write gate").blocked
        }
    }

    /// A TCP duplex that records actual `poll_write` Pending results and can
    /// gate body writes until a registered waker is released.
    struct WriteProbe {
        inner: TcpStream,
        /// Every `poll_write` that returned `Pending`, whether the gate caused
        /// it or the TCP write did.
        pending: Arc<AtomicUsize>,
        /// Only the `Pending` results the gate itself produced. A test that
        /// needs to know the connection is blocked *by the gate* must wait on
        /// this, because `pending` can also rise from ordinary socket
        /// backpressure.
        gate_pending: Arc<AtomicUsize>,
        gate: Arc<WriteGate>,
    }

    impl AsyncRead for WriteProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for WriteProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if bytes.len() > 1024 && this.gate.should_block(context.waker()) {
                this.pending.fetch_add(1, Ordering::SeqCst);
                this.gate_pending.fetch_add(1, Ordering::SeqCst);
                return Poll::Pending;
            }
            let result = Pin::new(&mut this.inner).poll_write(context, bytes);
            if matches!(result, Poll::Pending) {
                this.pending.fetch_add(1, Ordering::SeqCst);
            }
            result
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(context)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
        }
    }

    /// A write-gated duplex that records its own drop.
    ///
    /// A connection driver parked on a `poll_write` that never becomes ready is
    /// not waiting on the signal hyper uses to notice a dropped request side, so
    /// only aborting the task releases it. The drop flag is how a test tells that
    /// apart from a task that was merely detached.
    struct DropProbe {
        inner: WriteProbe,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl AsyncRead for DropProbe {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for DropProbe {
        fn poll_write(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(context)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
        }
    }

    async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<()> {
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            head.extend_from_slice(&chunk[..read]);
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(());
            }
        }
    }

    async fn read_request_head_text<S>(stream: &mut S) -> std::io::Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..read]);
            if head.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(String::from_utf8_lossy(&head).into_owned())
    }

    /// Reads a complete chunked request, preserving bytes coalesced with the
    /// head, and returns once the terminating chunk has been seen.
    async fn read_chunked_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut chunk = vec![0_u8; 64 * 1024];
        let mut head_end = None;
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if head_end.is_none()
                && let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                head_end = Some(position + 4);
            }
            if let Some(head_end) = head_end
                && request[head_end..]
                    .windows(5)
                    .any(|window| window == b"0\r\n\r\n")
            {
                break;
            }
        }
        Ok(request)
    }

    /// A large upload used by the cancellation test. It does not claim kernel
    /// socket-buffer saturation; the readiness-faithful backpressure test uses a
    /// controlled write probe instead.
    fn large_upload() -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send {
        stream::iter((0..32).map(|_| Ok(Bytes::from(vec![b'x'; 64 * 1024]))))
    }

    /// A peer that completes the handshake and then says nothing cannot hold the
    /// caller past the response-head deadline.
    #[tokio::test]
    async fn a_silent_peer_is_stopped_at_the_response_head_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });

        let engine = engine_at(address);
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            engine.send_with_deadline(
                RawRequest::new(Method::GET, "/info"),
                Some(Duration::from_millis(100)),
            ),
        )
        .await;
        server.abort();
        let error = match result {
            Ok(Ok(_)) => panic!("a silent peer must not produce a response"),
            Ok(Err(error)) => error,
            Err(error) => panic!("the response-head deadline did not fire: {error}"),
        };

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.to_string().contains("timed out"), "{error}");
        Ok(())
    }

    /// The deadline ends at the response head. A body that arrives later is
    /// still read, which is what keeps a streaming Engine response unbounded.
    #[tokio::test]
    async fn the_response_head_deadline_does_not_wrap_the_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
                .await?;
            stream.flush().await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            stream.write_all(b"{}").await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });

        let engine = engine_at(address);
        let response = engine
            .send_with_deadline(
                RawRequest::new(Method::GET, "/info"),
                Some(Duration::from_millis(100)),
            )
            .await?;
        let document = tokio::time::timeout(Duration::from_secs(5), response.document()).await??;
        server.abort();

        assert_eq!(&document[..], b"{}");
        Ok(())
    }

    /// A producer that stalls before its final chunk is not put on the
    /// response-head clock. The deadline is longer than the stall, and the
    /// request completes once the producer is released. This is producer
    /// backpressure, not socket backpressure.
    #[tokio::test]
    async fn the_response_head_deadline_waits_for_a_stalled_producer()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            let mut body = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
                if body.windows(5).any(|window| window == b"0\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });

        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let upload = stream::once(async move {
            let _ = released.await;
            Ok(Bytes::from_static(b"payload"))
        });
        let request =
            RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(upload));
        let engine = engine_at(address);
        let mut send =
            Box::pin(engine.send_with_deadline(request, Some(Duration::from_millis(100))));

        // The upload is blocked. A 100 ms deadline must not fire while the body
        // is still pending, so a 300 ms observation window still sees Pending.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut send)
                .await
                .is_err(),
            "the response-head deadline fired while the upload was blocked"
        );

        release.send(()).expect("release the blocked upload");
        let response = tokio::time::timeout(Duration::from_secs(5), &mut send).await??;
        let document = tokio::time::timeout(Duration::from_secs(5), response.document()).await??;
        server.abort();

        assert_eq!(&document[..], b"{}");
        Ok(())
    }

    /// A producer that is still incomplete under a controlled write-readiness
    /// probe must not start the response-head clock. The probe records actual
    /// `poll_write` Pending results; the producer counter proves it has produced
    /// data independently. This is a controlled `WouldBlock`, not a large-body
    /// socket-buffer assumption.
    #[tokio::test]
    async fn the_response_head_deadline_waits_for_an_incomplete_producer_under_write_backpressure()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            let mut chunk = vec![0_u8; 64 * 1024];
            let mut body = Vec::new();
            loop {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
                if body.windows(5).any(|window| window == b"0\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });

        let pending = Arc::new(AtomicUsize::new(0));
        let gate_pending = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(WriteGate::new());
        let open = {
            let pending = Arc::clone(&pending);
            let gate_pending = Arc::clone(&gate_pending);
            let gate = Arc::clone(&gate);
            StreamFactory::from_fn(move || {
                let pending = Arc::clone(&pending);
                let gate_pending = Arc::clone(&gate_pending);
                let gate = Arc::clone(&gate);
                async move {
                    let stream = TcpStream::connect(address)
                        .await
                        .map_err(|error| Error::transport(format!("connect: {error}")))?;
                    Ok(Box::new(WriteProbe {
                        inner: stream,
                        pending,
                        gate_pending,
                        gate,
                    }) as Box<dyn Duplex>)
                }
            })
        };
        let target = RawTarget::Stream {
            authority: "test".to_owned(),
            open,
        };
        let engine = RawEngine::new(target, API_VERSION)
            .with_response_head_deadline(Some(Duration::from_millis(100)));

        let produced = Arc::new(AtomicUsize::new(0));
        let produced_for_stream = Arc::clone(&produced);
        let first = stream::once(async move {
            produced_for_stream.fetch_add(64 * 1024, Ordering::SeqCst);
            Ok(Bytes::from(vec![b'x'; 64 * 1024]))
        });
        let (producer_release, producer_released) = tokio::sync::oneshot::channel();
        let tail = stream::once(async move {
            let _ = producer_released.await;
            Ok(Bytes::from_static(b"tail"))
        });
        let upload = first.chain(tail);
        let request =
            RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(upload));
        let send = tokio::spawn(async move { engine.send(request).await });

        let observation_deadline = Instant::now() + Duration::from_secs(3);
        while pending.load(Ordering::SeqCst) == 0 || produced.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < observation_deadline,
                "no write backpressure was observed"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(pending.load(Ordering::SeqCst) > 0);
        assert!(produced.load(Ordering::SeqCst) > 0);
        assert!(
            !send.is_finished(),
            "the send completed while the producer was blocked"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !send.is_finished(),
            "the response-head deadline fired while the producer was incomplete under write backpressure"
        );
        gate.unblock();
        producer_release.send(()).expect("release the producer");
        let response = tokio::time::timeout(Duration::from_secs(2), send)
            .await??
            .expect("the send failed after the write gate was released");
        let document = tokio::time::timeout(Duration::from_secs(5), response.document()).await??;
        server.abort();

        assert_eq!(&document[..], b"{}");
        Ok(())
    }

    /// Once the upload has been fully polled, a silent response head is bounded
    /// by the response-head deadline.
    #[tokio::test]
    async fn the_response_head_deadline_starts_after_a_completed_upload()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (received_sender, received_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_chunked_request(&mut stream).await?;
            let _ignored = received_sender.send(request);
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });

        let upload = stream::once(async { Ok(Bytes::from_static(b"payload")) });
        let request =
            RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(upload));
        let engine = engine_at(address);
        let send = tokio::spawn(async move {
            engine
                .send_with_deadline(request, Some(Duration::from_millis(100)))
                .await
        });
        let received = tokio::time::timeout(Duration::from_secs(5), received_receiver).await??;
        let prefix = crate::raw::api_version_prefix();
        assert!(
            received.starts_with(format!("POST {prefix}/images/load HTTP/1.1\r\n").as_bytes()),
            "{}",
            String::from_utf8_lossy(&received)
        );
        assert!(
            received.windows(5).any(|window| window == b"0\r\n\r\n"),
            "the server did not receive the complete chunked request"
        );
        let error = tokio::time::timeout(Duration::from_secs(3), send)
            .await??
            .expect_err("a silent peer after the upload must hit the response-head deadline");
        server.abort();

        assert!(error.to_string().contains("timed out"), "{error}");
        Ok(())
    }

    /// Cancelling a blocked upload closes the connection, and the peer sees EOF
    /// or a specific reset rather than data or a silent timeout.
    #[tokio::test]
    async fn cancelling_a_blocked_upload_closes_the_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let closed: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let server = tokio::spawn({
            let closed = Arc::clone(&closed);
            async move {
                let (mut stream, _) = listener.accept().await?;
                read_request_head(&mut stream).await?;
                let mut chunk = [0_u8; 1024];
                let outcome =
                    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
                        .await
                    {
                        Ok(Ok(0)) => Ok(()),
                        Ok(Ok(read)) => Err(format!("peer sent {read} byte(s) after cancellation")),
                        Ok(Err(error))
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            Ok(())
                        }
                        Ok(Err(error)) => Err(format!("read failed: {error}")),
                        Err(_) => Err("teardown timed out".to_owned()),
                    };
                *closed.lock().expect("the recorded close outcome") = Some(outcome);
                Ok::<(), std::io::Error>(())
            }
        });

        let (_release, released) = tokio::sync::oneshot::channel::<()>();
        let upload = stream::once(async move {
            let _ = released.await;
            Ok(Bytes::from_static(b"payload"))
        });
        let request =
            RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(upload));
        let engine = engine_at(address);
        let mut send = Box::pin(engine.send_with_deadline(request, Some(Duration::from_secs(1))));

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut send)
                .await
                .is_err(),
            "the upload was not blocked"
        );
        drop(send);

        let deadline = Instant::now() + Duration::from_secs(3);
        let outcome = loop {
            if let Some(outcome) = closed.lock().expect("the recorded close outcome").clone() {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "the cancelled upload did not close within the bound"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        server.abort();
        assert_eq!(
            outcome,
            Ok(()),
            "the cancelled upload peer did not close cleanly: {outcome:?}"
        );
        Ok(())
    }

    /// Cancelling a large upload closes the connection. The peer may drain
    /// bytes already in the socket before it sees EOF or a reset, so data
    /// followed by EOF/reset is accepted; a timeout is not. This test does not
    /// claim the socket was saturated.
    #[tokio::test]
    async fn cancelling_a_large_upload_closes_the_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let closed: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let server = tokio::spawn({
            let closed = Arc::clone(&closed);
            async move {
                let (mut stream, _) = listener.accept().await?;
                read_request_head(&mut stream).await?;
                tokio::time::sleep(Duration::from_millis(300)).await;
                let outcome = match tokio::time::timeout(Duration::from_secs(3), async {
                    let mut chunk = vec![0_u8; 64 * 1024];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) => return Ok(()),
                            Ok(_) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::UnexpectedEof
                                ) =>
                            {
                                return Ok(());
                            }
                            Err(error) => return Err(format!("read failed: {error}")),
                        }
                    }
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("teardown timed out".to_owned()),
                };
                *closed.lock().expect("the recorded close outcome") = Some(outcome);
                Ok::<(), std::io::Error>(())
            }
        });

        let request = RawRequest::new(Method::POST, "/images/load")
            .with_body(RawBody::from_stream(large_upload()));
        let engine = engine_at(address);
        let mut send = Box::pin(engine.send_with_deadline(request, Some(Duration::from_secs(1))));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut send)
                .await
                .is_err(),
            "the large upload was not backpressured"
        );
        drop(send);

        let deadline = Instant::now() + Duration::from_secs(4);
        let outcome = loop {
            if let Some(outcome) = closed.lock().expect("the recorded close outcome").clone() {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "the cancelled socket-pressure upload did not close within the bound"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        server.abort();
        assert_eq!(
            outcome,
            Ok(()),
            "the cancelled socket-pressure peer did not close cleanly: {outcome:?}"
        );
        Ok(())
    }

    /// Dropping the send future while the peer holds the response head closes
    /// the connection, and the peer observes it.
    ///
    /// This is the case a body-drop test cannot see: the connection driver is
    /// spawned before the head arrives, and the abort handle is only handed to
    /// the response once the head is parsed. The peer's read must therefore end
    /// at EOF or a reset, not at a timeout, when the future is dropped in between.
    #[tokio::test]
    async fn cancelling_a_held_response_closes_the_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let closed: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let server = tokio::spawn({
            let closed = Arc::clone(&closed);
            async move {
                let (mut stream, _) = listener.accept().await?;
                read_request_head(&mut stream).await?;
                let _ = seen_tx.send(());
                // Never answer. The client's close is the only event left, and a
                // read that times out means the driver outlived the future.
                let mut chunk = [0_u8; 64];
                let outcome =
                    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
                        .await
                    {
                        Ok(Ok(0)) => Ok(()),
                        Ok(Ok(read)) => Err(format!("peer sent {read} byte(s) after cancellation")),
                        Ok(Err(error))
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            Ok(())
                        }
                        Ok(Err(error)) => Err(format!("read failed: {error}")),
                        Err(_) => Err("teardown timed out".to_owned()),
                    };
                *closed.lock().expect("the recorded close outcome") = Some(outcome);
                Ok::<(), std::io::Error>(())
            }
        });

        let engine = engine_at(address);
        let mut send = Box::pin(engine.send(RawRequest::new(Method::GET, "/info")));
        tokio::select! {
            result = &mut send => {
                panic!("the held response completed instead of being cancelled: {result:?}");
            }
            seen = seen_rx => seen.expect("the fixture recorded the request"),
        }
        drop(send);

        let deadline = Instant::now() + Duration::from_secs(3);
        let outcome = loop {
            if let Some(outcome) = closed.lock().expect("the recorded close outcome").clone() {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "the cancelled held response did not close within the bound"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        server.abort();
        assert_eq!(
            outcome,
            Ok(()),
            "the cancelled held-response peer did not close cleanly: {outcome:?}"
        );
        Ok(())
    }

    /// A response-head timeout stops the driver, and the peer observes the
    /// connection close.
    #[tokio::test]
    async fn a_response_head_timeout_closes_the_connection()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let closed: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let server = tokio::spawn({
            let closed = Arc::clone(&closed);
            async move {
                let (mut stream, _) = listener.accept().await?;
                read_request_head(&mut stream).await?;
                let mut chunk = [0_u8; 64];
                let outcome =
                    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
                        .await
                    {
                        Ok(Ok(0)) => Ok(()),
                        Ok(Ok(read)) => Err(format!("peer sent {read} byte(s) after the timeout")),
                        Ok(Err(error))
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            Ok(())
                        }
                        Ok(Err(error)) => Err(format!("read failed: {error}")),
                        Err(_) => Err("teardown timed out".to_owned()),
                    };
                *closed.lock().expect("the recorded close outcome") = Some(outcome);
                Ok::<(), std::io::Error>(())
            }
        });

        let engine = engine_at(address);
        let error = engine
            .send_with_deadline(
                RawRequest::new(Method::GET, "/info"),
                Some(Duration::from_millis(100)),
            )
            .await
            .expect_err("a silent peer must hit the response-head deadline");
        assert!(error.to_string().contains("timed out"), "{error}");

        let deadline = Instant::now() + Duration::from_secs(3);
        let outcome = loop {
            if let Some(outcome) = closed.lock().expect("the recorded close outcome").clone() {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "the timed-out response head did not close within the bound"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        server.abort();
        assert_eq!(
            outcome,
            Ok(()),
            "the timed-out peer did not close cleanly: {outcome:?}"
        );
        Ok(())
    }

    /// A driver parked on a write that never becomes ready is stopped when the
    /// send future is dropped.
    ///
    /// hyper wakes a connection that is waiting for a response head once the
    /// request side is dropped, but a driver blocked inside `poll_write` is not
    /// waiting on that signal. Only aborting the task releases it and the duplex
    /// it owns, so this is the case that tells an abort from a detached task.
    #[tokio::test]
    async fn cancelling_a_stalled_write_drops_the_connection_driver()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            // Keep the connection open; the client stalls on the body.
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<(), std::io::Error>(())
        });

        let pending = Arc::new(AtomicUsize::new(0));
        let gate_pending = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(WriteGate::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let open = {
            let pending = Arc::clone(&pending);
            let gate_pending = Arc::clone(&gate_pending);
            let gate = Arc::clone(&gate);
            let dropped = Arc::clone(&dropped);
            StreamFactory::from_fn(move || {
                let pending = Arc::clone(&pending);
                let gate_pending = Arc::clone(&gate_pending);
                let gate = Arc::clone(&gate);
                let dropped = Arc::clone(&dropped);
                async move {
                    let stream = TcpStream::connect(address)
                        .await
                        .map_err(|error| Error::transport(format!("connect: {error}")))?;
                    Ok(Box::new(DropProbe {
                        inner: WriteProbe {
                            inner: stream,
                            pending,
                            gate_pending,
                            gate,
                        },
                        dropped,
                    }) as Box<dyn Duplex>)
                }
            })
        };
        let target = RawTarget::Stream {
            authority: "test".to_owned(),
            open,
        };
        let engine = RawEngine::new(target, API_VERSION);

        let upload = stream::once(async { Ok(Bytes::from(vec![b'x'; 64 * 1024])) });
        let request =
            RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(upload));
        let mut send = Box::pin(engine.send(request));

        let observation_deadline = Instant::now() + Duration::from_secs(3);
        while gate_pending.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < observation_deadline,
                "the write gate never blocked a body write"
            );
            // Poll the send until the gate itself returns `Pending`. Ordinary
            // TCP backpressure cannot satisfy this: only the gate branch bumps
            // `gate_pending`.
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut send)
                    .await
                    .is_err(),
                "the send completed while the gate was blocking the producer"
            );
        }
        // `WriteGate` wakes a blocked writer only through `unblock`, which this
        // test never calls, so the block cannot clear on its own. A short
        // observation confirms the gate is still closed before the future is
        // dropped; otherwise the test would not be measuring the abort.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            gate.is_blocked(),
            "the write gate was released without the test unblocking it"
        );
        assert!(
            !dropped.load(Ordering::SeqCst),
            "the driver stopped before the future was dropped"
        );
        drop(send);

        let deadline = Instant::now() + Duration::from_secs(2);
        while !dropped.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "dropping the send left the connection driver running against a stalled write"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        server.abort();
        Ok(())
    }

    /// An engine with no response-head deadline keeps the existing raw
    /// behavior: a delayed response head is waited for.
    #[tokio::test]
    async fn an_engine_without_a_deadline_waits_for_a_delayed_response_head()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });

        let engine = engine_at(address);
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            engine.send(RawRequest::new(Method::GET, "/info")),
        )
        .await??;
        let document = response.document().await?;
        server.abort();

        assert_eq!(&document[..], b"{}");
        Ok(())
    }

    /// `container_wait` is the actual operation, not a stand-in `/info` send.
    /// A short engine deadline bounds an ordinary send but not the wait, because
    /// the operation uses the unbounded path.
    #[tokio::test]
    async fn container_wait_uses_the_unbounded_path_despite_a_short_default_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_request_head(&mut stream).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });
        let engine =
            engine_at(address).with_response_head_deadline(Some(Duration::from_millis(100)));
        let bounded = tokio::time::timeout(
            Duration::from_secs(5),
            engine.send(RawRequest::new(Method::GET, "/info")),
        )
        .await?;
        server.abort();
        let error = bounded.expect_err("the engine deadline did not bound an ordinary send");
        assert!(error.to_string().contains("timed out"), "{error}");

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request_head_text(&mut stream).await?;
            let _ignored = request_sender.send(request);
            tokio::time::sleep(Duration::from_millis(300)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n{\"StatusCode\":0}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });
        let engine =
            engine_at(address).with_response_head_deadline(Some(Duration::from_millis(100)));
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            crate::raw::container_wait(&engine, "test", &ContainerWaitOptions::default()),
        )
        .await??;
        let request = request_receiver
            .await
            .map_err(|_| "the wait fixture did not record the request")?;
        server.abort();

        let prefix = crate::raw::api_version_prefix();
        assert!(
            request.starts_with(&format!("POST {prefix}/containers/test/wait HTTP/1.1\r\n")),
            "{request}"
        );
        assert_eq!(result.status_code, 0);
        Ok(())
    }

    /// Unit test: an actual direct `RawResponse` keeps `HeaderValue`'s
    /// sensitivity flag in its `Debug` rendering.
    #[tokio::test]
    async fn direct_raw_response_debug_preserves_sensitive_header_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ignored = read_request_head_text(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nX-Plain: visible-value\r\nContent-Length: 2\r\n\
                      Connection: close\r\n\r\n{}",
                )
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });
        let engine = engine_at(address);
        let mut response = tokio::time::timeout(
            Duration::from_secs(5),
            engine.send(RawRequest::new(Method::GET, "/info")),
        )
        .await
        .expect("the fixture did not answer")?;
        let mut sensitive = hyper::header::HeaderValue::from_static("canary-sensitive-header");
        sensitive.set_sensitive(true);
        response.headers.insert("x-sensitive", sensitive);

        let rendered = format!("{response:?}");
        assert!(!rendered.contains("canary-sensitive-header"), "{rendered}");
        assert!(
            rendered.contains("Sensitive") || rendered.contains("<sensitive>"),
            "{rendered}"
        );
        assert!(rendered.contains("visible-value"), "{rendered}");
        let _ignored = tokio::time::timeout(Duration::from_secs(5), response.document())
            .await
            .expect("the response body did not finish")?;
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the fixture did not finish")??;
        Ok(())
    }

    /// Unit test (private transport rule): a caller-supplied
    /// `Proxy-Authorization` is forwarded on a direct connection, preserving the
    /// pre-existing custom-transport behavior. `Debug` still redacts it.
    #[tokio::test]
    async fn caller_proxy_authorization_is_forwarded_on_a_direct_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_request_head_text(&mut stream).await?;
            let _ignored = request_sender.send(request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });
        let engine = engine_at(address);
        let request = RawRequest::new(Method::GET, "/info")
            .with_header(hyper::header::PROXY_AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .with_header(hyper::header::HOST, "caller.example");
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("dXNlcjpwYXNz"), "{debug}");

        let response = engine.send(request).await?;
        let _ignored = response.document().await?;
        let head = request_receiver
            .await
            .map_err(|_| "the fixture did not record the request")?;
        server.await??;
        assert!(
            head.to_ascii_lowercase()
                .contains("proxy-authorization: basic dxnlcjpwyxnz"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("host: caller.example"),
            "a direct target must preserve the caller Host: {head}"
        );
        Ok(())
    }

    /// Unit test (private transport rule): a custom `StreamFactory` target keeps
    /// the pre-existing ability to authenticate to its own proxy. The transport
    /// does not strip a caller-supplied `Proxy-Authorization` on that route.
    #[tokio::test]
    async fn caller_proxy_authorization_is_forwarded_on_a_custom_stream_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let (server_sender, mut server_receiver) = tokio::sync::mpsc::unbounded_channel();
        let factory = StreamFactory::from_fn(move || {
            let (client, server) = tokio::io::duplex(4096);
            let _ignored = server_sender.send(server);
            async move { Ok(Box::new(client) as Box<dyn Duplex>) }
        });
        let engine = RawEngine::new(
            RawTarget::Stream {
                authority: "custom".to_owned(),
                open: factory,
            },
            API_VERSION,
        );
        let server = tokio::spawn(async move {
            let mut stream = server_receiver
                .recv()
                .await
                .ok_or_else(|| std::io::Error::other("the factory produced no duplex"))?;
            let request = read_request_head_text(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await?;
            stream.flush().await?;
            Ok::<String, std::io::Error>(request)
        });

        let request = RawRequest::new(Method::GET, "/info")
            .with_header(hyper::header::PROXY_AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .with_header(hyper::header::HOST, "caller.example");
        let response = engine.send(request).await?;
        let _ignored = response.document().await?;
        let head = server.await??;
        assert!(
            head.to_ascii_lowercase()
                .contains("proxy-authorization: basic dxnlcjpwyxnz"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("host: caller.example"),
            "a custom stream target must preserve the caller Host: {head}"
        );
        Ok(())
    }

    /// Unit test (private transport rule): the configured proxy route owns
    /// `Proxy-Authorization`. A caller-supplied value is rejected before the
    /// proxy is dialed, so two credentials can never be sent and the header is
    /// not silently ignored.
    #[tokio::test]
    async fn configured_proxy_rejects_a_caller_proxy_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: "daemon.invalid".to_owned(),
                port: 2375,
            },
            API_VERSION,
        )
        .with_http_proxy(HttpProxyRoute::new(
            "127.0.0.1".to_owned(),
            1,
            None,
            Duration::from_millis(100),
        ));
        let mut request = RawRequest::new(Method::GET, "/info");
        request.headers.append(
            hyper::header::PROXY_AUTHORIZATION,
            hyper::header::HeaderValue::from_static("Basic caller"),
        );
        request.headers.append(
            hyper::header::PROXY_AUTHORIZATION,
            hyper::header::HeaderValue::from_static("Basic duplicate"),
        );

        let error = engine
            .send(request)
            .await
            .expect_err("a configured proxy must reject a caller credential");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput, "{error}");
        assert!(!error.to_string().contains("Basic caller"), "{error}");
        assert!(!error.to_string().contains("Basic duplicate"), "{error}");
        Ok(())
    }

    /// A public HTTP response whose underlying I/O emits a local marker after
    /// the head. Tests the private marker bridge, including hyper's loss of
    /// original I/O causes, without requiring kernel backpressure for each API.
    struct TimeoutReply {
        head: &'static [u8],
        kind: crate::TransportTimeoutKind,
        written: bool,
    }

    impl AsyncRead for TimeoutReply {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if !self.written {
                return Poll::Pending;
            }
            if !self.head.is_empty() {
                let count = self.head.len().min(buffer.remaining());
                buffer.put_slice(&self.head[..count]);
                self.head = &self.head[count..];
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                crate::TransportTimeout {
                    kind: self.kind,
                    message: "local-timeout-source-canary".to_owned(),
                },
            )))
        }
    }

    impl AsyncWrite for TimeoutReply {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written = true;
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn typed_io_timeouts_survive_all_public_response_readers() {
        use crate::TransportTimeoutKind::{
            ManagedSshEstablishment, ManagedSshWriteInactivity, RequestDeadline,
        };
        for kind in [
            RequestDeadline,
            ManagedSshEstablishment,
            ManagedSshWriteInactivity,
        ] {
            for reader in ["document", "data", "json"] {
                let open = StreamFactory::from_fn(move || async move {
                    Ok(Box::new(TimeoutReply {
                        head: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                        kind,
                        written: false,
                    }) as Box<dyn Duplex>)
                });
                let engine = RawEngine::new(
                    RawTarget::Stream {
                        authority: "fixture".to_owned(),
                        open,
                    },
                    API_VERSION,
                );
                let response = engine
                    .send(RawRequest::new(Method::GET, "/info"))
                    .await
                    .unwrap();
                let error: crate::Error = match reader {
                    "document" => response.document().await.unwrap_err().into(),
                    "data" => response.into_frames().next_data().await.unwrap_err().into(),
                    "json" => response.into_frames().next_json().await.unwrap_err(),
                    _ => unreachable!(),
                };
                assert_eq!(
                    error.transport_timeout_kind(),
                    Some(kind),
                    "{reader}: {error:?}"
                );
                assert!(!format!("{error:?}").contains("local-timeout-source-canary"));
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn node_mutation_deadline_is_distinct_from_connection_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::net::UnixListener;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("engine.sock");
        let listener = UnixListener::bind(&path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut data = [0_u8; 4096];
            assert!(stream.read(&mut data).await? > 0);
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut data)).await;
            Ok::<(), std::io::Error>(())
        });
        let engine = RawEngine::new(RawTarget::Unix(path.clone()), API_VERSION)
            .with_local_overall_deadline(Duration::from_millis(100));
        let options = crate::NodeUpdateOptions {
            version: 1,
            spec: crate::NodeSpec::default(),
        };
        let timeout = crate::raw::node_update(&engine, "node-canary-secret", &options)
            .await
            .unwrap_err();
        assert!(
            timeout.to_string().contains("outcome is unknown"),
            "{timeout:?}"
        );
        assert!(timeout.is_transport_deadline());
        server.await??;
        std::fs::remove_file(path)?;
        let failure = crate::raw::node_update(&engine, "node-canary-secret", &options)
            .await
            .unwrap_err();
        assert!(
            !failure.to_string().contains("outcome is unknown"),
            "{failure:?}"
        );
        assert!(!failure.is_transport_deadline());
        assert!(!crate::Error::transport("timed out").is_transport_deadline());
        for error in [&timeout, &failure] {
            assert_eq!(error.kind(), crate::ErrorKind::Transport);
            let mut renderings = vec![error.to_string(), format!("{error:?}")];
            let mut source = std::error::Error::source(error);
            while let Some(cause) = source {
                renderings.push(cause.to_string());
                renderings.push(format!("{cause:?}"));
                source = cause.source();
            }
            for rendering in renderings {
                assert!(!rendering.contains("node-canary-secret"), "{rendering}");
                assert!(!rendering.contains("engine.sock"), "{rendering}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn propagated_deadline_marker_does_not_disclose_factory_text() {
        for marked in [true, false] {
            let open = StreamFactory::from_fn(move || async move {
                let error = if marked {
                    crate::Error::transport_deadline("previous secret canary timed out")
                } else {
                    crate::Error::transport("previous secret canary timed out")
                };
                Err::<Box<dyn Duplex>, _>(error)
            });
            let engine = RawEngine::new(
                RawTarget::Stream {
                    authority: "fixture".to_owned(),
                    open,
                },
                API_VERSION,
            );
            let error = crate::raw::node_remove(
                &engine,
                "node",
                &crate::NodeRemoveOptions { force: false },
            )
            .await
            .unwrap_err();
            assert_eq!(error.is_transport_deadline(), marked);
            if marked {
                let message = error.to_string();
                assert!(
                    message.contains("node mutation outcome is unknown"),
                    "{message}"
                );
                assert!(message.contains("reconcile"), "{message}");
                assert!(
                    !message.contains("the node mutation timed out"),
                    "the diagnostic claimed this mutation timed out: {message}"
                );
            }
            let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(error) = cause {
                assert!(!error.to_string().contains("canary"));
                assert!(!format!("{error:?}").contains("canary"));
                cause = error.source();
            }
        }
    }

    /// Unit test: the local route's overall budget bounds a stalled peer.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_overall_deadline_closes_stalled_unix_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::net::UnixListener;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&path)?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut data = [0_u8; 4096];
            let n = stream.read(&mut data).await?;
            assert!(n > 0, "the mutation was dispatched");
            let closed = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut data)).await;
            assert!(matches!(closed, Ok(Ok(0) | Err(_))), "peer was not closed");
            Ok::<(), std::io::Error>(())
        });
        let engine = RawEngine::new(RawTarget::Unix(path), API_VERSION)
            .with_local_overall_deadline(Duration::from_millis(100));
        let request = RawRequest::new(Method::DELETE, "/nodes/node");
        let error = engine
            .send(request)
            .await
            .expect_err("stalled local peer must time out");
        assert!(error.to_string().contains("outcome is unknown"));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn configured_proxy_overall_deadline_bounds_a_stalled_proxy()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _ignored = read_request_head_text(&mut stream).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });
        let deadline = Duration::from_millis(100);
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: "daemon.invalid".to_owned(),
                port: 2375,
            },
            API_VERSION,
        )
        .with_http_proxy(HttpProxyRoute::new(
            "127.0.0.1".to_owned(),
            address.port(),
            None,
            deadline,
        ));

        let started = Instant::now();
        let error = engine
            .send(RawRequest::new(Method::GET, "/info"))
            .await
            .expect_err("a stalled proxy must hit the transport deadline");
        let elapsed = started.elapsed();
        server.abort();

        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(
            elapsed < Duration::from_secs(2),
            "the transport deadline did not fire: {elapsed:?}"
        );
        Ok(())
    }

    /// Unit test (private transport rule): the proxy route's overall budget
    /// covers a request-body producer that never yields, matching the generated
    /// client's single request timeout.
    #[tokio::test]
    async fn configured_proxy_overall_deadline_bounds_a_stalled_body_producer()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });
        let deadline = Duration::from_millis(100);
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: "daemon.invalid".to_owned(),
                port: 2375,
            },
            API_VERSION,
        )
        .with_http_proxy(HttpProxyRoute::new(
            "127.0.0.1".to_owned(),
            address.port(),
            None,
            deadline,
        ));
        let body =
            RawBody::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let request = RawRequest::new(Method::POST, "/containers/create").with_body(body);

        let started = Instant::now();
        let error = engine
            .send(request)
            .await
            .expect_err("a stalled body producer must hit the proxy budget");
        let elapsed = started.elapsed();
        server.abort();

        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(
            elapsed < Duration::from_secs(2),
            "the proxy budget did not fire: {elapsed:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod pipe_path_tests {
    use super::normalize_windows_pipe_separators;

    #[test]
    fn either_pipe_separator_spelling_becomes_the_native_form() {
        for input in [
            r"\\.\pipe\docker_engine",
            "//./pipe/docker_engine",
            r"\\./pipe/docker_engine",
            r"\\.\pipe/docker_engine",
        ] {
            let normalized = normalize_windows_pipe_separators(input.encode_utf16());
            assert_eq!(
                String::from_utf16(&normalized).expect("valid UTF-16 remains valid"),
                r"\\.\pipe\docker_engine",
                "input: {input:?}"
            );
        }
    }
}
