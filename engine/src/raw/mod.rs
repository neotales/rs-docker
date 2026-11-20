//! The repository-owned Engine backend.
//!
//! This public module implements the owned transport used by the `DockerClient`
//! facade. Requests use the configured API version and no generated fallback.
//!
//! # What the backend covers
//!
//! The first vertical slice is the one the decision record nominates: `ping`,
//! `version`, and `info`, over a Unix socket and over TCP. Those three
//! operations are enough to exercise every part of the transport that matters —
//! versioned paths, query encoding, response decoding, header access, status
//! mapping, and Engine error bodies — without yet depending on streaming,
//! attach, or bidirectional I/O.
//!
//! The second slice is the container lifecycle:
//! [`container_list`],
//! [`container_create`],
//! [`container_start`],
//! [`container_stop`],
//! [`container_restart`],
//! [`container_remove`] and
//! [`container_wait`]. It adds the two request shapes the first
//! slice had no use for — a buffered JSON request body, and a success whose
//! status is the whole answer (`204` with no body) — and it decodes into the
//! repository-owned container models rather than into generated ones. It was
//! verified end to end against Docker Engine 29.8.0 over a Unix socket, not
//! only against fixtures.
//!
//! The third slice is the rest of the container surface: [`inspect`], [`kill`],
//! [`pause`], [`unpause`], [`rename`], [`update`], [`prune`], [`changes`],
//! [`container_top`], [`export_container`], [`container_archive_stat`],
//! [`download_container_archive`], [`upload_container_archive`],
//! [`commit_container`], [`resize`], [`stats`], [`stats_stream`], [`attach`],
//! the four exec operations, and the three container checkpoint operations
//! ([`checkpoint_create`], [`checkpoint_list`], [`checkpoint_remove`]). Some
//! need a streaming answer, one needs a byte stream, one streams its *request*
//! body, and two need a connection the daemon takes over; each of those facts is
//! stated where it is implemented rather than guessed at from the endpoint name.
//!
//! # Which answers are documents and which are streams
//!
//! This is the decision every added operation has to make, so it is recorded
//! once here. An operation's answer is a **document** unless the daemon writes
//! more than the caller can hold, and a document goes through
//! [`RawResponse::document`] and is therefore bounded by
//! [`MAX_DOCUMENT_BYTES`]. A stream is not read that way. Newline-delimited JSON
//! records read through [`FrameStream::next_json`] are bounded separately by
//! [`MAX_RECORD_BYTES`]; this is not a universal limit on every streaming
//! decoder, though the other one is held to the same number. The
//! multiplexed-frame decoder used by [`logs`] is bounded by
//! [`MAX_FRAME_BYTES`], which is [`MAX_RECORD_BYTES`] again: it is the declared
//! length in a frame header rather than a terminator that sets the ceiling
//! there, so the check happens when the header is parsed and before the payload
//! is taken. It bounds a *framed* frame: a TTY body has no header and so no
//! declared length, which is stated at the constant rather than left to be
//! inferred from a name. The streaming cases in this module, and only these:
//!
//! | Operation | Answer | Why it cannot be a document |
//! | --- | --- | --- |
//! | [`logs`] | a frame stream | `follow` keeps writing for as long as the container runs |
//! | [`stats_stream`] | a frame stream | one JSON object per second, forever, while the container runs |
//! | [`export_container`] | a byte stream | a container filesystem archive is as large as the container |
//! | [`download_container_archive`] | a byte stream | the same, for one path inside the container |
//! | [`attach`] | `Ended` without `stream`/`stdin`; otherwise `Started` on `200` (body dropped) or `Upgraded` on `101` | the daemon hijacks the connection and declares no length |
//! | [`attach_stream`] | the `200` body as a byte stream, or `Upgraded` on `101` | the same answer, read rather than discarded |
//! | [`exec_start`] | not read at all | the same, for an attached exec |
//! | [`exec_start_session`] | caller-owned connection | the daemon switches protocols and the session outlives the request |
//!
//! [`exec_start_session`] returns the connection rather than decoding it. A
//! non-TTY session multiplexes stdout and stderr and takes raw stdin; a TTY
//! session is raw in both directions. The caller owns the connection and the
//! framing; see [`ExecSession`]. A start that has been sent is not retracted by
//! dropping the future or the session. [`exec_inspect`] can inform
//! reconciliation, but it cannot prove a retry is safe because the earlier
//! request may still be processed.
//!
//! [`upload_container_archive`] is the one operation whose **request** body
//! streams: a TAR archive is as large as the part of the container it
//! describes, so it is sent as a [`RawBody::Stream`] and never buffered whole.
//! Its answer is an empty success, read and discarded rather than decoded. No
//! size cap is imposed, because a fixed one would refuse a legitimate copy of a
//! large directory and would make the same call succeed or fail depending on
//! which transport served it; the body is bounded by the caller's own stream.
//!
//! Response-head timing is target-specific. Only the facade's HTTPS target
//! installs a 120-second response-head deadline; Unix sockets, named pipes,
//! plain TCP, SSH, and caller-supplied streams keep the existing unbounded
//! behavior. For HTTPS, the clock starts when hyper has fully polled the request
//! body — producer completion, not confirmed socket delivery — and ends at the
//! response head; the response body is not wrapped by it. A stalled producer is
//! not bounded by it, and socket backpressure can still let the deadline fire
//! after producer completion. A timeout means the daemon may have processed the
//! request; the outcome is unknown and must be reconciled before retrying.
//! [`container_wait`], [`container_stop`], and [`container_restart`] use the
//! unbounded send because their contract is a daemon-governed wait, and dropping
//! the operation future is how a caller cancels.
//!
//! # TLS is a facade-built stream
//!
//! The HTTPS constructors on `DockerClient` build a [`RawTarget::Stream`] whose
//! factory opens a fresh TCP connection, optionally negotiates an explicit HTTP
//! `CONNECT` tunnel, and completes a TLS handshake for each request. There is no
//! plaintext fallback: a failed handshake is an error, and the TLS target never
//! returns the underlying socket. SSH is the same shape — `RawTarget::Stream`
//! over `docker system dial-stdio` — so a caller composing its own factory owns
//! that policy.
//!
//! The facade's HTTPS target validates the CA bundle and client identity
//! synchronously, verifies server trust, validity times, and hostname by
//! default, and bounds TCP connect, the proxy `CONNECT` exchange (including its
//! response head), and the TLS handshake with the crate's transport deadline.
//! The deadline stops at the established stream: streaming response bodies are
//! not limited by it. An explicit `TlsServerTrust::AllowExpiredOrUntrusted` is
//! the only way to bypass server trust, time, and hostname checks, and even then
//! certificate parsing and handshake signatures are still verified.
//!
//! # Plain HTTP through an explicit forward proxy
//!
//! For a plain-HTTP endpoint selected with `ProxyPolicy::Http`, the facade
//! builds a [`RawTarget::Tcp`] that keeps the daemon's authority and an
//! internal proxy route. [`RawEngine`] dials the proxy and writes an
//! absolute-form request target, with the daemon's `Host`, and adds
//! `Proxy-Authorization` only on that route. A caller-supplied
//! `Proxy-Authorization` is rejected on that route; a direct target or a
//! caller-supplied [`RawTarget::Stream`] keeps forwarding it for existing custom
//! transport authentication. A caller-supplied `Host` is ignored on the owned
//! forward-proxy route in favor of the daemon authority; direct and custom
//! targets keep forwarding it. The proxy is never chosen from the environment,
//! and a proxy that cannot be reached is an error rather than a direct
//! connection. The route applies one 120-second overall request budget covering
//! the proxy connect, request-body production/backpressure, and the response
//! head. That is the generated client's single request-timeout shape, including
//! `wait`, `stop`, and `restart` on this route; the response body is not wrapped.
//! On an authenticated proxy route, a non-2xx response message is withheld and
//! replaced with fixed safe text because a malicious proxy can echo the
//! credential in any encoding. [`RawResponse`]'s `Debug` withholds
//! proxy-controlled header names and values; the explicit `headers` map and body
//! remain caller-visible, and a caller reading them can still observe a
//! malicious echo. Successful response values such as [`Ping`]'s header-derived
//! fields, image progress records, and raw documents are also caller-visible
//! data and are not sanitized. HTTPS keeps its `CONNECT` tunnel; the two routes
//! are not interchangeable.
//!
//! # Container checkpoints
//!
//! [`checkpoint_create`], [`checkpoint_list`], and [`checkpoint_remove`] are the
//! daemon's experimental checkpoint router, which is not part of the Engine's
//! `OpenAPI` document:
//!
//! | Operation | Request | Success |
//! | --- | --- | --- |
//! | [`checkpoint_create`] | `POST /v{major}.{minor}/containers/{id}/checkpoints` with `CheckpointID`, optional `CheckpointDir`, and `Exit` | `201` |
//! | [`checkpoint_list`] | `GET /v{major}.{minor}/containers/{id}/checkpoints?dir=…` | `200` with a JSON array |
//! | [`checkpoint_remove`] | `DELETE /v{major}.{minor}/containers/{id}/checkpoints/{checkpoint}?dir=…` | `204` |
//!
//! `checkpoint_dir` is optional and empty means the daemon's default, so an
//! absent or empty value is omitted rather than sent as an empty member or an
//! empty query value. A `null` list answer from an older daemon is decoded to an
//! empty vector, and an entry without a string `Name` is a decode failure. Both
//! path segments are percent-encoded, and an empty container reference or
//! checkpoint identifier is refused before a connection is opened. Creation uses
//! the unbounded send because a CRIU dump can outlast the response-head budget;
//! dropping the future leaves the outcome unknown, and none of the three
//! operations retries. The daemon capability and release treatment are recorded
//! in the crate README.
//!
//! # What the backend deliberately does not cover
//!
//! - **A caller-constructed [`RawTarget::Tcp`] is plaintext.** The facade's
//!   HTTPS target is a [`RawTarget::Stream`]; `Tcp` itself has no implicit
//!   upgrade. A caller that builds it directly is asking for plain TCP and gets
//!   it.
//! - **Connection hijack and h2c, partly.** [`attach`] returns the upgraded
//!   (`101`) connection as [`Attached::Upgraded`] only when
//!   [`ContainerAttachOptions::stream`] or [`ContainerAttachOptions::stdin`] is
//!   set. With neither set it reports [`Attached::Ended`]. When either is set
//!   and the daemon answers `200`, it reports [`Attached::Started`] and drops
//!   the body. Only [`attach_stream`] reads a `200` body, returning it as a
//!   readable [`FrameStream`]; a `101` answer is [`AttachedStream::Upgraded`].
//!   What is still missing is h2c. That remains step 6 of the decision record's
//!   migration order.
//!
//!   [`exec_start`] still reports the status and drops the response, which closes
//!   the socket, and still calls `is_attached()` true once the output socket has
//!   been discarded. So the operations named side by side here do not all behave
//!   alike: [`attach_stream`] is the one that reads both documented answers —
//!   the switched `101` connection and the `200` body — while [`attach`] takes
//!   the `101` connection only when `stream` or `stdin` is set, reports
//!   [`Attached::Started`] for a `200` (dropping its body) when either option is
//!   set, and reports [`Attached::Ended`] when neither is.
//!   [`exec_start_session`] is the additive route that takes the `101`
//!   connection and returns it as [`ExecSession`], so a caller that wants the
//!   session has one. `exec_start` keeps its previous behaviour for callers that
//!   only want the start acknowledged.
//! - **Container checkpoints are experimental on the daemon side.** The routes
//!   exist and are implemented here, but a daemon without experimental features
//!   does not serve them, and a runtime that cannot checkpoint reports the
//!   operation as not implemented. That is the daemon's answer, not a gap in
//!   this backend; the loopback fixtures pin the wire contract and no live
//!   daemon is claimed.
//! - **Images, networks, volumes, system, and plugins.** Migration steps 3
//!   through 4. The container surface is done, checkpoints included.
//!
//! - **Socket-level differential fixtures for the Swarm slice.** The Swarm
//!   operations are pinned by request-line and body unit tests and decode the
//!   repository's own Swarm fixture documents, but no fixture *server* stands in
//!   for the daemon, so no claim is made that the owned path and the former generated client path
//!   agree byte for byte over a connection the way the container slice's
//!   differential fixtures show. The container slice is the one with that
//!   evidence; Swarm has the typed-model evidence and not yet the wire evidence.
//!
//! Each of those is a real gap, stated here rather than left for a caller to
//! discover.
//!
//! # Example
//!
//! ```
//! # use neotales_docker::raw::{RawEngine, RawTarget, info, ping};
//! # use neotales_docker::raw::{container_create, container_list, container_start};
//! # use neotales_docker::{ContainerCreateOptions, ContainerListOptions, ContainerStartOptions};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = RawEngine::new(
//!     RawTarget::Unix("/var/run/docker.sock".into()),
//!     neotales_docker::API_VERSION,
//! );
//!
//! // `/_ping` carries its answer in headers, so the owned client returns them
//! // typed instead of collapsing five capabilities into one string.
//! let capabilities = ping(&engine).await?;
//! println!(
//!     "daemon API {:?}, swarm {:?}",
//!     capabilities.api_version, capabilities.swarm
//! );
//!
//! // Versioned paths: the daemon receives `/v1.55/info`, not `/info` -- the
//! // version is `API_VERSION`, so this moves when the ceiling does.
//! let daemon = info(&engine).await?;
//! println!("{}", daemon.get("ServerVersion").and_then(|value| value.as_str()).unwrap_or("?"));
//!
//! // The container slice speaks the same versioned paths and hands back the
//! // repository-owned models rather than generated ones.
//! let containers = container_list(&engine, &ContainerListOptions { all: true, ..Default::default() }).await?;
//! println!("{} containers", containers.len());
//! let created = container_create(&engine, &ContainerCreateOptions {
//!     image: "alpine:3.19".to_owned(),
//!     name: Some("slice".to_owned()),
//!     ..Default::default()
//! })
//! .await?;
//! container_start(&engine, &created.id, &ContainerStartOptions::default()).await?;
//! # Ok(())
//! # }
//! ```

/// Substitutes the crate's live Engine API version into a request-line
/// expectation.
///
/// The request-shape assertions across this module's submodules spell out whole
/// request lines, and every one of them begins `GET /v1.NN/...`. Those are
/// *plumbing* assertions: their subject is the path and the query encoding, not
/// the number in the prefix. Spelling the number as a literal in 130 of them
/// means a legitimate ceiling change breaks 130 tests that were correct, and the
/// result is that whoever raises the ceiling deletes them instead of reading
/// them — which is how a request-shape check stops existing without anyone
/// deciding it should.
///
/// So the expectations carry a `v1.API` marker and this substitutes the live
/// constant. The check is not weakened: the substituted value is
/// `crate::API_VERSION`, so a request that put a *different* version on the
/// wire still fails here. Only the number's spelling is no longer duplicated.
///
/// This is a test-only helper rather than one more piece of public surface,
/// which is why it is `#[cfg(test)]` and `pub(crate)`.
#[cfg(test)]
pub(crate) fn at_api_version(line: &str) -> String {
    const MARKER: &str = "/v1.API";
    let prefix = format!(
        "/v{}.{}",
        crate::API_VERSION.major,
        crate::API_VERSION.minor
    );
    assert!(
        line.contains(MARKER),
        "a request-line expectation must carry the {MARKER} marker so the version is \
         substituted rather than duplicated: {line:?}"
    );
    line.replace(MARKER, &prefix)
}

/// Fixed text used when an authenticated proxy stream carries an in-band error.
pub(crate) const WITHHELD_IN_BAND_MESSAGE: &str =
    "in-band response text withheld for an authenticated forward proxy";

/// The `/v1.NN` prefix the owned transport puts on every path.
#[cfg(test)]
pub(crate) fn api_version_prefix() -> String {
    format!(
        "/v{}.{}",
        crate::API_VERSION.major,
        crate::API_VERSION.minor
    )
}

mod body;
pub(crate) mod buildkit_context;
mod buildkit_filter;
pub(crate) mod buildkit_grpc;
mod checkpoints;
mod containers;
mod control;
mod exec;
mod image_transfer;
mod images;
mod inspect;
mod logs;
mod networks;
mod plugins;
mod registry;
mod resources;
pub(crate) mod session;
mod stats;
mod swarm;
pub(crate) use swarm::task_logs_optional;
pub(crate) use swarm::{
    node_inspect_for_facade, node_list_for_facade, service_inspect_for_facade,
    service_list_for_facade,
};
mod system;
mod transport;
mod volumes;

use hyper::Method;
use hyper::header::HeaderName;

pub use body::{
    ConnectionDriver, FrameStream, MAX_DOCUMENT_BYTES, MAX_RECORD_BYTES, RawBody, RawBodyError,
    RawResponse, RecordLimitError, RequestBody, SwitchedConnection, SwitchedReadHalf,
    SwitchedWriteHalf,
};
pub use checkpoints::{checkpoint_create, checkpoint_list, checkpoint_remove};
pub use containers::{
    commit_container, container_archive_stat, container_create, container_list, container_remove,
    container_restart, container_start, container_stop, container_top, container_wait,
    download_container_archive, export_container, upload_container_archive,
};
pub use control::{
    Attached, AttachedStream, ContainerAttachOptions, ContainerKillOptions, ContainerResizeOptions,
    attach, attach_stream, kill, pause, rename, resize, unpause,
};
pub use exec::{
    ExecCreateResult, ExecInspect, ExecSession, ExecStartOptions, ExecStarted, exec_create,
    exec_inspect, exec_resize, exec_start, exec_start_session,
};
pub use image_transfer::{
    MAX_UPLOAD_BYTES, RegistryAuth, build, import, import_from_url, load, progress_error,
    pull_stream, push_stream, save,
};
pub use images::{
    image_history, image_history_documents, image_inspect, image_inspect_document, image_list,
    image_list_documents, image_prune, image_prune_document, image_pull_document,
    image_push_document, image_remove, image_search, image_search_documents, image_tag,
};
pub use inspect::{ContainerInspect, inspect};
pub use logs::{
    ContainerLogOptions, FRAME_HEADER_BYTES, LogDecoder, LogFrame, LogFrames, LogStream,
    MAX_FRAME_BYTES, logs,
};
pub use networks::{
    NetworkEntry, network_connect, network_create, network_disconnect, network_inspect,
    network_list, network_prune, network_remove,
};
pub use plugins::{
    plugin_create, plugin_disable, plugin_enable, plugin_inspect, plugin_list, plugin_privileges,
    plugin_pull, plugin_pull_with_registry_auth, plugin_push, plugin_push_with_registry_auth,
    plugin_remove, plugin_set, plugin_upgrade, plugin_upgrade_with_registry_auth,
};
pub use registry::{
    RegistryAuthentication, RegistryAuthenticationResult, distribution_inspect, distribution_list,
    registry_authenticate,
};
pub use resources::{changes, prune, update};
pub use stats::{StatsOptions, stats, stats_stream};
pub(crate) use swarm::validate_service_spec;
pub use swarm::{
    SwarmLogFrames, config_create, config_inspect, config_list, config_remove, config_update,
    node_inspect, node_list, node_remove, node_update, secret_create, secret_inspect, secret_list,
    secret_remove, secret_update, service_create, service_create_with_registry_auth,
    service_inspect, service_list, service_logs, service_remove, service_update,
    service_update_with_registry_auth, swarm_certificates, swarm_init, swarm_inspect, swarm_join,
    swarm_join_token, swarm_leave, swarm_unlock, swarm_unlock_key, swarm_update, task_inspect,
    task_list, task_logs,
};
pub use system::{DiskUsageReport, disk_usage, events, prune_build_cache};
pub(crate) use transport::HttpProxyRoute;
pub use transport::{
    Duplex, RawEngine, RawRequest, RawTarget, StreamFactory, StreamFuture, collect_json_frames,
    decode, engine_result, json_body, json_content_type,
};
pub use volumes::{volume_create, volume_inspect, volume_list, volume_prune, volume_remove};

use crate::{DaemonVersion, Error};

/// The `API-Version` header of a `GET /_ping` response.
///
/// The Engine's capability headers are not standard HTTP header names, so
/// `hyper` provides no constants for them and they are spelled here once rather
/// than as string literals at each use.
static API_VERSION: HeaderName = HeaderName::from_static("api-version");
/// The `OSType` header of a `GET /_ping` response.
static OSTYPE: HeaderName = HeaderName::from_static("ostype");
/// The `Docker-Experimental` header of a `GET /_ping` response.
static DOCKER_EXPERIMENTAL: HeaderName = HeaderName::from_static("docker-experimental");
/// The `Builder-Version` header of a `GET /_ping` response.
static BUILDER_VERSION: HeaderName = HeaderName::from_static("builder-version");
/// The `Swarm` header of a `GET /_ping` response.
static SWARM: HeaderName = HeaderName::from_static("swarm");

impl From<RawBodyError> for Error {
    /// Classifies a body read failure as a transport failure.
    ///
    /// A daemon that answers and then drops the connection has not rejected the
    /// request, so reporting that as invalid input would blame the caller for
    /// something they did not do.
    fn from(error: RawBodyError) -> Self {
        if let RawBodyError::Timeout(kind) = error {
            return Error::transport_timeout(
                kind,
                "Engine response transport timeout; peer text withheld",
            );
        }
        if let Some(kind) = crate::transport_timeout_in(&error) {
            return Error::transport_timeout(
                kind,
                "Engine response transport timeout; peer text withheld",
            );
        }
        Error::transport(error.to_string())
    }
}

/// Hands out a response's frame stream once the status says it is one.
///
/// The status is interpreted *before* the body is handed out. An Engine error
/// body is a JSON object, and a `404` whose body happened to parse as a
/// progress record would otherwise arrive as a stream of errors. The archive
/// endpoints have the same problem in a different shape: a refusal body is
/// JSON, not a TAR, so a caller reading chunks would receive the daemon's
/// complaint as archive bytes.
///
/// The returned [`FrameStream`] owns the response and its connection driver, so
/// dropping it cancels the transfer. Reading it with
/// [`FrameStream::next_data`](FrameStream::next_data) hands over transport
/// chunks without accumulating them; reading it with
/// [`FrameStream::next_json`](FrameStream::next_json) is for
/// newline-delimited records and is not what the archive callers use.
pub(super) async fn started(response: RawResponse) -> Result<FrameStream, Error> {
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(response.into_frames())
}

/// The `GET /_ping` answer.
///
/// `/_ping` carries its result in headers, not a body, and the headers are the
/// only way to learn the daemon's API version, operating system, and Swarm state
/// before committing to a request. A `String` return cannot express that, which
/// is the concrete reason the owned backend keeps its own type here.
///
/// # Caller-visible values
///
/// Every field is copied from response headers. On an authenticated forward-proxy
/// route those headers are proxy-controlled, so a malicious proxy can put
/// arbitrary text here. The values are returned as data and are not sanitized;
/// the withholding policy covers non-success error messages and
/// [`RawResponse`] `Debug` headers, not successful
/// response values. A caller that formats this type for a log is choosing to
/// print that text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ping {
    /// The highest Engine API version the daemon serves.
    pub api_version: Option<String>,
    /// The daemon's operating-system family, such as `linux`.
    pub os_type: Option<String>,
    /// Whether the daemon has experimental features enabled.
    pub experimental: Option<bool>,
    /// The daemon's builder version, when it reports one.
    pub builder_version: Option<String>,
    /// The Swarm node state, when the daemon is part of a Swarm.
    pub swarm: Option<String>,
}

impl Ping {
    /// Reads the answer out of the response headers.
    #[must_use]
    pub fn from_headers(headers: &hyper::HeaderMap) -> Self {
        Self {
            api_version: text(headers, &API_VERSION),
            os_type: text(headers, &OSTYPE),
            experimental: flag(headers, &DOCKER_EXPERIMENTAL),
            builder_version: text(headers, &BUILDER_VERSION),
            swarm: text(headers, &SWARM),
        }
    }
}

/// Reads a header as UTF-8 text.
fn text(headers: &hyper::HeaderMap, name: &HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

/// Reads a boolean header, treating an unparsable value as absent.
///
/// The Engine spells this header `true` or `false`. A daemon that sends
/// something else has not made a claim this client can act on, so the field is
/// reported as unknown instead of guessing.
fn flag(headers: &hyper::HeaderMap, name: &HeaderName) -> Option<bool> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| match value {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

/// Pings the daemon and reads its capability headers.
///
/// The status is checked, but the body is not required: a daemon that answers a
/// healthy `/_ping` with an empty body is normal, and one that answers `200`
/// with a failure in the body is a daemon bug rather than a client concern. The
/// headers are the answer.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, or when it rejects the
/// request instead of reporting its capabilities.
pub async fn ping(engine: &RawEngine) -> Result<Ping, Error> {
    let response = engine.send(RawRequest::new(Method::GET, "/_ping")).await?;
    if !response.is_success() {
        return Err(Error::engine_api(
            response.status,
            format!(
                "daemon rejected /_ping with HTTP {}",
                response.status.as_u16()
            ),
        ));
    }
    Ok(Ping::from_headers(&response.headers))
}

/// Reads the daemon version document.
///
/// The document is returned as JSON rather than a generated struct on purpose:
/// the Engine adds members to it between releases, and a client that drops
/// unknown members would report a version the daemon did not send. Callers that
/// want typed fields read them out of the returned value.
///
/// This operation returns the JSON value the daemon sent without imposing the
/// facade's version-document rules. A duplicate known member is kept as
/// [`serde_json::Value`] resolves it, a known member with an unexpected type is
/// still returned, and a non-object JSON value is accepted.
/// [`DockerClient::version`](crate::DockerClient::version) and
/// [`DockerClient::version_value`](crate::DockerClient::version_value) validate
/// those rules separately.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it reports a
/// failure, or when the response body is not JSON.
pub async fn version(engine: &RawEngine) -> Result<serde_json::Value, Error> {
    let response = engine
        .send(RawRequest::new(Method::GET, "/version"))
        .await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Reads the unversioned version document used for API negotiation.
///
/// Unlike the versioned facade report, this does not validate unrelated fields.
pub(crate) async fn negotiation_version(engine: &RawEngine) -> Result<serde_json::Value, Error> {
    let response = engine.send_unversioned_version().await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// The validated `GET /version` answer, with the daemon's document retained.
///
/// The document is parsed from the same response bytes that were validated, so
/// reading it costs no second request and an unknown member or explicit `null`
/// is returned as sent.
pub(crate) struct VersionReport {
    document: serde_json::Value,
    known: VersionDocument,
}

impl VersionReport {
    /// Decodes one response body.
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        // The object check runs first so a non-object body reports its shape
        // rather than a typed-decoder complaint. The value is kept for the
        // caller; validation below reads the *bytes*, because `Value` has
        // already collapsed any duplicate key by the time it exists.
        let document: serde_json::Value = decode(raw)?;
        if !document.is_object() {
            return Err(Error::invalid_input(
                "the Engine version response is not a JSON object",
            ));
        }
        let known: VersionDocument = serde_json::from_slice(raw).map_err(|error| {
            Error::invalid_input(format!(
                "failed to decode the Engine version response: {}",
                transport::serde_error_summary(&error)
            ))
        })?;
        Ok(Self { document, known })
    }

    pub(crate) fn into_document(self) -> serde_json::Value {
        self.document
    }

    pub(crate) fn into_daemon_version(self) -> DaemonVersion {
        self.known.into_daemon_version()
    }
}

/// Reads and validates the daemon version document for the facade.
///
/// The body is read through [`engine_result`], so it is bounded by
/// [`MAX_DOCUMENT_BYTES`](crate::raw::MAX_DOCUMENT_BYTES). Validation and the
/// returned document both come from those same bytes, so neither costs a second
/// request.
pub(crate) async fn version_report(engine: &RawEngine) -> Result<VersionReport, Error> {
    let response = engine
        .send(RawRequest::new(Method::GET, "/version"))
        .await?;
    let raw = engine_result(response).await?;
    VersionReport::decode(&raw)
}

/// The Engine's `GET /version` document, as far as the generated model read it.
///
/// [`DaemonVersion`] names five members, but this type also validates every
/// member the generated model declared. The fields that only exist for
/// validation are underscore-prefixed because no repository type exposes them.
#[derive(serde::Deserialize)]
struct VersionDocument {
    #[serde(rename = "Version", default)]
    version: Option<String>,
    #[serde(rename = "ApiVersion", default)]
    api_version: Option<String>,
    #[serde(rename = "MinAPIVersion", default)]
    min_api_version: Option<String>,
    #[serde(rename = "Os", default)]
    os: Option<String>,
    #[serde(rename = "Arch", default)]
    arch: Option<String>,
    #[serde(rename = "GitCommit", default)]
    _git_commit: Option<String>,
    #[serde(rename = "GoVersion", default)]
    _go_version: Option<String>,
    #[serde(rename = "KernelVersion", default)]
    _kernel_version: Option<String>,
    #[serde(rename = "Experimental", default)]
    _experimental: Option<bool>,
    #[serde(rename = "BuildTime", default)]
    _build_time: Option<String>,
    #[serde(rename = "Platform", default)]
    _platform: Option<VersionPlatform>,
    #[serde(rename = "Components", default)]
    _components: Option<Vec<VersionComponent>>,
}

/// The `Platform` member of the version document.
#[derive(serde::Deserialize)]
struct VersionPlatform {
    #[serde(rename = "Name")]
    _name: String,
}

/// One `Components` entry of the version document.
#[derive(serde::Deserialize)]
struct VersionComponent {
    #[serde(rename = "Name")]
    _name: String,
    #[serde(rename = "Version")]
    _version: String,
    #[serde(rename = "Details", default)]
    _details: Option<std::collections::BTreeMap<String, String>>,
}

impl VersionDocument {
    /// Projects the five members [`DaemonVersion`] exposes.
    fn into_daemon_version(self) -> DaemonVersion {
        DaemonVersion {
            version: self.version,
            api_version: self.api_version,
            min_api_version: self.min_api_version,
            os: self.os,
            arch: self.arch,
        }
    }
}

/// Reads the daemon `info` document.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it reports a
/// failure, or when the response is not a JSON object.
pub async fn info(engine: &RawEngine) -> Result<serde_json::Value, Error> {
    let response = engine.send(RawRequest::new(Method::GET, "/info")).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Decodes a list member the Engine answers with `null` rather than `[]`.
///
/// The Engine sends `"Warnings": null` for an operation that produced none, and
/// `#[serde(default)]` does not help there: it covers an *absent* member, while
/// this is a member that is present and null. Measured on Docker 29.8.0:
/// `POST /containers/{id}/update` answers `{"Warnings":null}`, and so does
/// `POST /services/create` when the service came up without a complaint. Without
/// this, every such response fails to decode and the operation reports an
/// invalid-input error for a request the daemon accepted.
///
/// The alternative — telling the Engine not to send null — does not exist, and
/// treating a null list as empty is what a reader of the response means by it.
pub(crate) fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    // A path through `Option` rather than a match on the deserializer: `null` is
    // the one input that has to become an empty list, and every other input has
    // to be a real list or a real error.
    Ok(<Option<Vec<T>> as serde::Deserialize>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::api_version_prefix;
    use super::at_api_version;
    use super::transport::{engine_message, trim_ascii};
    use super::{Ping, RawEngine, RawRequest, RawTarget};
    use crate::{ApiVersion, ErrorKind};
    use hyper::{Method, StatusCode};

    /// The version this module's assertions build requests at.
    ///
    /// The crate's ceiling, not a literal. Every assertion here is about how the
    /// prefix is *built* — that it is present, that it precedes the path, that
    /// the query follows it — and none of them is about the number, so a literal
    /// would make a correct ceiling change look like a regression.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    #[test]
    fn every_path_is_prefixed_with_the_negotiated_version() {
        let request =
            RawRequest::new(Method::GET, "/containers/json").with_query("all=1&filters=%7B%7D");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(
            uri,
            format!(
                "{}/containers/json?all=1&filters=%7B%7D",
                api_version_prefix()
            )
        );
    }

    /// The prefix is the crate's ceiling, and a literal says so out loud.
    ///
    /// The test above derives its expectation, which is right for what it is
    /// about but means nothing in the file asserts the *number*. If
    /// `at_api_version` or `api_version_prefix` were reading a constant other
    /// than the one `API_VERSION` names, every derived assertion in the module
    /// would still agree with itself and pass. This is the one place that
    /// compares the rendered prefix against the number written by hand, which
    /// is why it keeps a literal where its neighbours do not.
    #[test]
    fn the_prefix_is_the_version_the_crate_claims() {
        let request = RawRequest::new(Method::GET, "/info");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(uri, "/v1.55/info");
        assert_eq!(api_version_prefix(), "/v1.55");
        assert_eq!(
            at_api_version("GET /v1.API/info HTTP/1.1"),
            "GET /v1.55/info HTTP/1.1"
        );
    }

    #[test]
    fn a_relative_path_is_refused_rather_than_guessed() {
        let request = RawRequest::new(Method::GET, "containers/json");
        let error = engine().request_uri(&request).expect_err("relative path");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_query_is_appended_after_the_versioned_path() {
        let request = RawRequest::new(Method::GET, "/containers/json").with_query("all=1");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(
            uri,
            format!("{}/containers/json?all=1", api_version_prefix())
        );
    }

    #[test]
    fn a_request_without_a_query_has_no_question_mark() {
        let request = RawRequest::new(Method::GET, "/info");
        let uri = engine().request_uri(&request).expect("absolute path");
        assert_eq!(uri, format!("{}/info", api_version_prefix()));
        assert!(!uri.contains('?'));
    }

    #[test]
    fn ping_reads_every_capability_header_the_daemon_sends() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("api-version", "1.53".parse().expect("header"));
        headers.insert("ostype", "linux".parse().expect("header"));
        headers.insert("docker-experimental", "true".parse().expect("header"));
        headers.insert("builder-version", "2".parse().expect("header"));
        headers.insert("swarm", "active".parse().expect("header"));
        let ping = Ping::from_headers(&headers);
        assert_eq!(ping.api_version.as_deref(), Some("1.53"));
        assert_eq!(ping.os_type.as_deref(), Some("linux"));
        assert_eq!(ping.experimental, Some(true));
        assert_eq!(ping.builder_version.as_deref(), Some("2"));
        assert_eq!(ping.swarm.as_deref(), Some("active"));
    }

    #[test]
    fn an_unparsable_boolean_header_is_unknown_rather_than_guessed() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("docker-experimental", "maybe".parse().expect("header"));
        assert_eq!(Ping::from_headers(&headers).experimental, None);
    }

    #[test]
    fn a_daemon_error_message_is_preserved_verbatim() {
        let message = engine_message(
            br#"{"message":"no such container: ghost"}"#,
            StatusCode::NOT_FOUND,
        );
        assert_eq!(message, "no such container: ghost");
    }

    #[test]
    fn an_unparsable_error_body_falls_back_to_the_status_rather_than_a_parse_complaint() {
        let message = engine_message(b"<html>gateway timeout</html>", StatusCode::BAD_GATEWAY);
        assert_eq!(message, "daemon returned HTTP 502 Bad Gateway");
        let empty = engine_message(b"", StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(empty, "daemon returned HTTP 500 Internal Server Error");
    }

    #[test]
    fn an_empty_error_message_does_not_become_the_user_facing_text() {
        let message = engine_message(br#"{"message":""}"#, StatusCode::CONFLICT);
        assert_eq!(message, "daemon returned HTTP 409 Conflict");
    }

    #[test]
    fn ascii_trimming_handles_both_ends_and_all_whitespace() {
        assert_eq!(trim_ascii(b"  {} \r\n"), b"{}");
        assert_eq!(trim_ascii(b"{}"), b"{}");
        assert_eq!(trim_ascii(b"   "), b"");
        assert_eq!(trim_ascii(b""), b"");
    }
}
