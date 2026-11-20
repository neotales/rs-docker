//! The owned transport's explicit plain-HTTP forward-proxy route.
//!
//! Every fixture is a loopback listener. The proxy records the request it
//! receives; the target is a second loopback listener that must stay unused.
//! Reaching the public facade is the point: the test builds a `DockerClient`
//! with `ProxyPolicy::Http`, asks it for `raw_engine()`, and lets a raw
//! operation put the request on the wire.
//!
//! # What each test is written to catch
//!
//! The absolute-form test fails if the owned transport sends origin-form, uses
//! the proxy's authority instead of the daemon's, drops the version prefix, or
//! omits the explicit proxy credential. The facade test fails if the operation
//! falls back to the generated client, because Bollard's plain-HTTP proxy route
//! sends the same absolute-form request *without* the version prefix. The IPv6
//! tests fail if a literal is bracketed twice or not at all, or if an IPv6 proxy
//! URL is not reduced to a bare dial address. The failure tests fail if a proxy
//! that closes, refuses, or answers with a malformed/truncated response is
//! replaced by a direct connection. The header tests fail if a caller-supplied
//! `Host` or proxy credential reaches the wire. The forwarding-proxy tests show
//! what a compliant proxy does with the request: it forwards origin-form and the
//! body to the target, strips the hop-by-hop proxy credential, and relays a
//! `101` upgrade in both directions. Those tests describe the proxy leg the
//! client controls; a proxy's own forwarding policy remains the proxy's. The
//! `407` test pins that a proxy echoing the configured credential cannot put it
//! into `Error` display, debug, or source, while direct daemon text is left
//! unchanged. The stalled-proxy tests pin the transport's own overall budget,
//! not an external test timeout.
//!
//! No credential from this machine is used. The proxy username and password are
//! test canaries, and the assertion is that they reach the proxy and nowhere
//! else.

#![allow(missing_docs)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::stream;
use neotales_docker::raw::{self, RawBody, RawRequest};
use neotales_docker::{
    API_VERSION, DockerClient, Endpoint, ErrorKind, ForwardProxy, ImageImportOptions,
    ImagePullOptions, ImagePushOptions, ImageTransferLimits, NodeRemoveOptions, NodeSpec,
    NodeUpdateOptions, ProxyPolicy, SwarmListOptions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[path = "support/build_wire.rs"]
mod build_wire;

/// The Basic value for `user:pass`. Spelled once so a failure shows the bytes
/// that were expected rather than a re-derived string.
const CANARY_AUTHORIZATION: &str = "Basic dXNlcjpwYXNz";

/// The fixed text a node mutation uses instead of daemon or proxy text.
const WITHHELD_NODE_MUTATION: &str =
    "response text withheld for a Swarm node mutation because a peer can echo node metadata";

/// Builds a `200` response with a JSON body.
fn ok_json_body(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A recorded request head and its body.
type RecordedRequest = (String, Vec<u8>);

/// A loopback HTTP server that records request heads and answers each one.
struct Recorder {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Recorder {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the recorded requests").clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
}

/// Starts a recorder that answers every request with `response`.
async fn start_server(response: Vec<u8>) -> Recorder {
    start_server_on("127.0.0.1:0", response).await
}

/// Starts a recorder on `bind` that answers every request with `response`.
async fn start_server_on(bind: &str, response: Vec<u8>) -> Recorder {
    let listener = TcpListener::bind(bind)
        .await
        .expect("bind a loopback fixture");
    let address = listener.local_addr().expect("the fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let requests = Arc::clone(&requests);
        let connections = Arc::clone(&connections);
        async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let Some(head) = read_head(&mut stream).await else {
                    continue;
                };
                requests.lock().expect("the recorded requests").push(head);
                let _ignored = stream.write_all(&response).await;
                let _ignored = stream.flush().await;
                let _ignored = stream.shutdown().await;
            }
        }
    });
    Recorder {
        address,
        requests,
        connections,
        task,
    }
}

/// Starts a listener that accepts and closes without answering.
async fn start_closing_proxy() -> Recorder {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback fixture");
    let address = listener.local_addr().expect("the fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let requests = Arc::clone(&requests);
        let connections = Arc::clone(&connections);
        async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                if let Some(head) = read_head(&mut stream).await {
                    requests.lock().expect("the recorded requests").push(head);
                }
                drop(stream);
            }
        }
    });
    Recorder {
        address,
        requests,
        connections,
        task,
    }
}

async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    for _ in 0..64 {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    (!head.is_empty()).then(|| String::from_utf8_lossy(&head).into_owned())
}

fn api_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Reports whether IPv6 loopback is available. The one test that needs it
/// prints an explicit skip when it is not, rather than panicking or silently
/// passing.
async fn ipv6_loopback_available() -> bool {
    match TcpListener::bind("[::1]:0").await {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

fn proxied_client(target: &Recorder, proxy: &Recorder) -> DockerClient {
    proxied_client_with_credentials(target, proxy, "user", "pass")
}

fn proxied_client_with_credentials(
    target: &Recorder,
    proxy: &Recorder,
    username: &str,
    password: &str,
) -> DockerClient {
    proxied_client_for_proxy(target, &proxy.endpoint(), username, password)
}

fn proxied_client_without_credentials(target: &Recorder, proxy: &Recorder) -> DockerClient {
    DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("the proxy URL")),
    )
    .expect("build the proxied client")
}

fn proxied_client_with_body_proxy(
    target: &Recorder,
    proxy: &BodyRecorder,
    username: &str,
    password: &str,
) -> DockerClient {
    proxied_client_for_proxy(target, &proxy.endpoint(), username, password)
}

fn proxied_client_for_proxy(
    target: &Recorder,
    proxy_endpoint: &str,
    username: &str,
    password: &str,
) -> DockerClient {
    DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(proxy_endpoint, username, password)
                .expect("bounded test credentials"),
        ),
    )
    .expect("build the proxied client")
}

/// Renders every `Display` and `Debug` form in an error chain.
fn error_renderings(error: &dyn std::error::Error) -> Vec<String> {
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(cause) = source {
        rendered.push(cause.to_string());
        rendered.push(format!("{cause:?}"));
        source = cause.source();
    }
    rendered
}

/// Renders an error and every source in its chain.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        rendered.push_str(" | ");
        rendered.push_str(&next.to_string());
        source = next.source();
    }
    rendered
}

/// Renders an error and every source in its chain with `Debug`.
fn error_chain_debug(error: &dyn std::error::Error) -> String {
    let mut rendered = format!("{error:?}");
    let mut source = error.source();
    while let Some(next) = source {
        rendered.push_str(" | ");
        let _ = write!(rendered, "{next:?}");
        source = next.source();
    }
    rendered
}

/// Asserts a withheld error exposes none of the configured credential forms in
/// Display, Debug, or any source in either chain.
fn assert_withheld_without_canaries(error: &dyn std::error::Error, canaries: &CredentialCanaries) {
    let display = format!("{error}");
    let debug = format!("{error:?}");
    let chain = error_chain(error);
    let chain_debug = error_chain_debug(error);
    for rendered in [&display, &debug, &chain, &chain_debug] {
        for variant in canaries.all() {
            assert!(!rendered.contains(variant), "{rendered}");
        }
        assert!(rendered.contains("withheld"), "{rendered}");
    }
}

/// Asserts an error exposes none of the configured credential forms in
/// Display, Debug, or any source in either chain.
fn assert_no_canaries(error: &dyn std::error::Error, canaries: &CredentialCanaries) {
    let display = format!("{error}");
    let debug = format!("{error:?}");
    let chain = error_chain(error);
    let chain_debug = error_chain_debug(error);
    for rendered in [&display, &debug, &chain, &chain_debug] {
        for variant in canaries.all() {
            assert!(!rendered.contains(variant), "{rendered}");
        }
    }
}

/// The synthetic proxy credential in the forms a proxy might echo.
struct CredentialCanaries {
    username: &'static str,
    password: &'static str,
    raw: String,
    encoded: String,
    header: String,
    percent: String,
}

impl CredentialCanaries {
    fn new(username: &'static str, password: &'static str) -> Self {
        let raw = format!("{username}:{password}");
        let encoded = STANDARD.encode(raw.as_bytes());
        let header = format!("Basic {encoded}");
        let percent = url::form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>();
        Self {
            username,
            password,
            raw,
            encoded,
            header,
            percent,
        }
    }

    fn all(&self) -> [&str; 6] {
        [
            &self.raw,
            &self.encoded,
            &self.header,
            self.username,
            self.password,
            &self.percent,
        ]
    }

    fn message(&self, prefix: &str) -> String {
        format!(
            "{prefix} raw={} encoded={} header={} user={} pass={} percent={}",
            self.raw, self.encoded, self.header, self.username, self.password, self.percent
        )
    }
}

/// The owned request is absolute-form, versioned, names the daemon in both the
/// request target and `Host`, and carries the credential only for the proxy.
#[tokio::test]
async fn raw_http_proxy_uses_absolute_form_and_preserves_the_target_authority() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let client = proxied_client(&target, &proxy);

    let engine = client
        .raw_engine()
        .expect("a proxied plain-HTTP endpoint is reachable by the owned transport");
    let document = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the fixture did not answer")
        .expect("the owned request through the proxy");
    assert_eq!(document, serde_json::json!({}));

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    let expected_target = format!(
        "GET http://{}{}/info HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(request.starts_with(&expected_target), "{request}");
    assert!(
        request
            .to_ascii_lowercase()
            .contains(&format!("host: {}\r\n", target.address)),
        "{request}"
    );
    assert!(
        request.contains(&format!("proxy-authorization: {CANARY_AUTHORIZATION}")),
        "{request}"
    );
    assert_eq!(
        target.connections(),
        0,
        "the owned transport connected to the target instead of the proxy"
    );

    let debug = format!("{engine:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("user"), "{debug}");
    assert!(!debug.contains("pass"), "{debug}");
    assert!(!debug.contains("dXNlcjpwYXNz"), "{debug}");
}

/// A facade operation that prefers the owned transport stays on it through the
/// proxy. The version prefix is the discriminator: the generated fallback sends
/// the same absolute-form request without `/v1.NN`.
#[tokio::test]
async fn facade_operation_routes_through_the_owned_proxy() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let client = proxied_client(&target, &proxy);

    let containers = tokio::time::timeout(Duration::from_secs(5), client.list_containers())
        .await
        .expect("the fixture did not answer")
        .expect("the facade operation through the proxy");
    assert!(containers.is_empty(), "expected containers to be empty");

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    let expected_target = format!(
        "GET http://{}{}/containers/json?all=false&size=false HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(request.starts_with(&expected_target), "{request}");
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// An IPv6 daemon authority is bracketed exactly once, in both the absolute-form
/// target and `Host`. The proxy is still IPv4 loopback; nothing dials `::1`.
#[tokio::test]
async fn raw_http_proxy_formats_an_ipv6_target_authority_once() {
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http("http://[::1]:2375".to_owned()),
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("the proxy URL")),
    )
    .expect("build the proxied client");

    let engine = client.raw_engine().expect("the owned proxied target");
    let document = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the fixture did not answer")
        .expect("the owned request through the proxy");
    assert_eq!(document, serde_json::json!({}));

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert!(
        request.starts_with(&format!(
            "GET http://[::1]:2375{}/info HTTP/1.1\r\n",
            api_prefix()
        )),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("host: [::1]:2375\r\n"),
        "{request}"
    );
}

/// A proxy that closes without answering is a transport error. The daemon
/// listener must never see a connection, which is what makes "no direct
/// fallback" observable.
#[tokio::test]
async fn proxy_failure_does_not_fall_back_to_the_target() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let proxy = start_closing_proxy().await;
    let client = proxied_client(&target, &proxy);
    let engine = client
        .raw_engine()
        .expect("the owned transport must be selected before the proxy is dialed");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the proxy fixture did not finish")
        .expect_err("a closed proxy must not produce a response");
    assert!(
        error.to_string().contains("Engine request")
            || error.to_string().contains("HTTP proxy")
            || error.to_string().contains("connect"),
        "{error}"
    );
    assert_eq!(proxy.connections(), 1, "the proxy was not dialed");
    assert_eq!(
        target.connections(),
        0,
        "the transport fell back to a direct connection after the proxy failed"
    );
    assert!(
        !format!("{error:?}").contains("user") && !format!("{error:?}").contains("pass"),
        "{error:?}"
    );
}

/// A proxy's `Location` is the proxy's answer, not an instruction to the client.
/// Following it would connect to the target listener directly.
#[tokio::test]
async fn proxy_redirect_is_not_followed() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let location = target.endpoint();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}/redirected\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        engine.send(RawRequest::new(hyper::Method::GET, "/_ping")),
    )
    .await
    .expect("the fixture did not answer")
    .expect("the proxy's answer");
    assert_eq!(response.status.as_u16(), 302);
    assert_eq!(proxy.requests().len(), 1, "the redirect was followed");
    assert_eq!(
        target.connections(),
        0,
        "a proxy redirect reached the daemon directly"
    );
}

/// A caller-supplied `Host` cannot replace or duplicate the daemon authority.
/// The transport sends exactly one `Host` line, and it is the target's.
#[tokio::test]
async fn caller_host_is_suppressed_and_only_the_target_authority_is_sent() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let request = RawRequest::new(hyper::Method::GET, "/info")
        .with_header(hyper::header::HOST, "attacker.example")
        .with_header(hyper::header::CONNECTION, "close");
    let response = engine.send(request).await.expect("the proxy's answer");
    let _ignored = response.document().await.expect("the response body");

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    let host_lines = request
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("host:"))
        .collect::<Vec<_>>();
    assert_eq!(host_lines.len(), 1, "{request}");
    assert_eq!(
        host_lines[0].to_ascii_lowercase(),
        format!("host: {}", target.address),
        "{request}"
    );
    assert!(!request.contains("attacker.example"), "{request}");
    assert!(
        !request.to_ascii_lowercase().contains("connection: close"),
        "an ordinary request must not let a caller close the connection: {request}"
    );
}

/// The configured proxy route owns `Proxy-Authorization`. A caller-supplied
/// value, including a duplicate, is rejected before the proxy is dialed.
#[tokio::test]
async fn configured_proxy_rejects_a_caller_proxy_authorization() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let mut request = RawRequest::new(hyper::Method::GET, "/info");
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
        .expect_err("the configured proxy must reject a caller credential");
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    assert!(!error.to_string().contains("Basic caller"), "{error}");
    assert!(!error.to_string().contains("Basic duplicate"), "{error}");
    assert_eq!(
        proxy.connections(),
        0,
        "the proxy was dialed before rejection"
    );
    assert_eq!(
        target.connections(),
        0,
        "the target was dialed before rejection"
    );
}

/// A refused proxy connection is a transport error, not a direct connection.
#[tokio::test]
async fn refused_proxy_connection_does_not_fall_back_to_the_target() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    // Port zero is not a connectable TCP port, so this fails deterministically
    // without allocating and releasing a loopback port.
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(ForwardProxy::new("http://127.0.0.1:0").expect("the proxy URL")),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the refused connect did not finish")
        .expect_err("a refused proxy must not produce a response");
    assert_eq!(error.kind(), ErrorKind::Transport, "{error}");
    assert_eq!(
        target.connections(),
        0,
        "a refused proxy fell back to a direct connection"
    );
}

/// A non-HTTP proxy answer is a transport error, not a direct connection.
#[tokio::test]
async fn malformed_proxy_response_is_a_transport_error() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let proxy = start_server(b"NOT HTTP\r\n\r\n".to_vec()).await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the malformed answer did not finish")
        .expect_err("a malformed proxy answer must be an error");
    assert_eq!(error.kind(), ErrorKind::Transport, "{error}");
    assert_eq!(target.connections(), 0);
}

/// A truncated proxy response head is a transport error.
#[tokio::test]
async fn truncated_proxy_response_head_is_a_transport_error() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let proxy = start_server(b"HTTP/1.1 200 OK\r\nContent-Len".to_vec()).await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the truncated head did not finish")
        .expect_err("a truncated proxy head must be an error");
    assert_eq!(error.kind(), ErrorKind::Transport, "{error}");
    assert_eq!(target.connections(), 0);
}

/// A proxy response head with a short body is a transport error, not a
/// truncated document.
#[tokio::test]
async fn truncated_proxy_response_body_is_a_transport_error() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let proxy = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the truncated body did not finish")
        .expect_err("a truncated proxy body must be an error");
    assert_eq!(error.kind(), ErrorKind::Transport, "{error}");
    assert_eq!(target.connections(), 0);
}

/// A proxy `407` is surfaced with its status and message, not retried and not
/// converted into a direct request. The raw layer reports it through the same
/// Engine API error channel as any non-2xx answer.
#[tokio::test]
async fn proxy_407_is_returned_without_a_retry() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let body = r#"{"message":"proxy auth required"}"#;
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client(&target, &proxy);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the 407 answer did not finish")
        .expect_err("a 407 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 407);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 407)"
    );
    assert_eq!(proxy.requests().len(), 1, "the 407 was retried");
    assert_eq!(target.connections(), 0, "the 407 reached the target");
}

/// An IPv6 proxy URL is parsed into a bare `::1` dial address and still keeps
/// the daemon's authority in the absolute-form target.
#[tokio::test]
async fn ipv6_proxy_is_dialed_without_brackets_in_the_socket_address() {
    if !ipv6_loopback_available().await {
        eprintln!(
            "skipping ipv6_proxy_is_dialed_without_brackets_in_the_socket_address: \
             IPv6 loopback is unavailable"
        );
        return;
    }
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let proxy = start_server_on(
        "[::1]:0",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(
            ForwardProxy::new(format!("http://[::1]:{}", proxy.address.port()))
                .expect("the IPv6 proxy URL"),
        ),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let document = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the IPv6 proxy did not answer")
        .expect("the owned request through the IPv6 proxy");
    assert_eq!(document, serde_json::json!({}));

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].starts_with(&format!(
            "GET http://{}{}/info HTTP/1.1\r\n",
            target.address,
            api_prefix()
        )),
        "{}",
        requests[0]
    );
    assert_eq!(target.connections(), 0);
}

/// A recorder that keeps both the request head and its body.
struct BodyRecorder {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for BodyRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl BodyRecorder {
    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("the recorded requests").clone()
    }
}

/// Starts a target that records the complete request, including its body.
async fn start_body_server(response: Vec<u8>) -> BodyRecorder {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback body fixture");
    let address = listener.local_addr().expect("the fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let task = tokio::spawn({
        let requests = Arc::clone(&requests);
        async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let Some((head, body)) = read_request(&mut stream).await else {
                    continue;
                };
                requests
                    .lock()
                    .expect("the recorded requests")
                    .push((head, body));
                let _ignored = stream.write_all(&response).await;
                let _ignored = stream.flush().await;
                let _ignored = stream.shutdown().await;
            }
        }
    });
    BodyRecorder {
        address,
        requests,
        task,
    }
}

/// A target that answers an upgrade request with `101` and echoes four bytes.
struct UpgradeTarget {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for UpgradeTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl UpgradeTarget {
    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the recorded requests").clone()
    }
}

async fn start_upgrade_target() -> UpgradeTarget {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback upgrade fixture");
    let address = listener.local_addr().expect("the fixture address");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let task = tokio::spawn({
        let requests = Arc::clone(&requests);
        async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let Some((head, _body)) = read_request(&mut stream).await else {
                    continue;
                };
                requests.lock().expect("the recorded requests").push(head);
                let _ignored = stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\
                          Upgrade: tcp\r\n\r\n",
                    )
                    .await;
                let _ignored = stream.flush().await;
                let mut ping = [0_u8; 4];
                if stream.read_exact(&mut ping).await.is_ok() {
                    let _ignored = stream.write_all(&ping).await;
                    let _ignored = stream.flush().await;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    });
    UpgradeTarget {
        address,
        requests,
        task,
    }
}

/// A forwarding proxy that rewrites absolute-form to origin-form, strips
/// `Proxy-Authorization` as a compliant proxy would, and relays the response.
struct ForwardingProxy {
    address: SocketAddr,
    received: Arc<Mutex<Vec<RecordedRequest>>>,
    forwarded: Arc<Mutex<Vec<RecordedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ForwardingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ForwardingProxy {
    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    fn received(&self) -> Vec<RecordedRequest> {
        self.received.lock().expect("the received requests").clone()
    }

    fn forwarded(&self) -> Vec<RecordedRequest> {
        self.forwarded
            .lock()
            .expect("the forwarded requests")
            .clone()
    }
}

async fn start_forwarding_proxy() -> ForwardingProxy {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback forwarding proxy");
    let address = listener.local_addr().expect("the proxy address");
    let received = Arc::new(Mutex::new(Vec::new()));
    let forwarded = Arc::new(Mutex::new(Vec::new()));
    let task = tokio::spawn({
        let received = Arc::clone(&received);
        let forwarded = Arc::clone(&forwarded);
        async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    continue;
                };
                let Some((head, body)) = read_request(&mut client).await else {
                    continue;
                };
                received
                    .lock()
                    .expect("the received requests")
                    .push((head.clone(), body.clone()));
                let Ok((forwarded_head, mut target)) = forward_request(&head, &body).await else {
                    continue;
                };
                forwarded
                    .lock()
                    .expect("the forwarded requests")
                    .push((forwarded_head.clone(), body));
                let Ok(response) = read_response(&mut target).await else {
                    continue;
                };
                let _ignored = client.write_all(response.head.as_bytes()).await;
                if response.upgraded {
                    if !response.prefix.is_empty() {
                        let _ignored = client.write_all(&response.prefix).await;
                    }
                    let _ignored = client.flush().await;
                    let _ignored = tokio::io::copy_bidirectional(&mut client, &mut target).await;
                } else {
                    let _ignored = client.write_all(&response.body).await;
                    let _ignored = client.flush().await;
                    let _ignored = client.shutdown().await;
                }
            }
        }
    });
    ForwardingProxy {
        address,
        received,
        forwarded,
        task,
    }
}

/// The response a forwarding proxy relays to its client.
struct RelayedResponse {
    head: String,
    body: Vec<u8>,
    prefix: Vec<u8>,
    upgraded: bool,
}

async fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let (buffer, header_end) = read_head_bytes(stream).await?;
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let length = content_length(&head);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some((head, body))
}

async fn read_response(stream: &mut TcpStream) -> std::io::Result<RelayedResponse> {
    let Some((buffer, header_end)) = read_head_bytes(stream).await else {
        return Err(invalid("the target closed before its response head"));
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .unwrap_or(0);
    if status == 101 {
        return Ok(RelayedResponse {
            head,
            body: Vec::new(),
            prefix: buffer[header_end..].to_vec(),
            upgraded: true,
        });
    }
    let length = content_length(&head);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(invalid("the target closed before its response body"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Ok(RelayedResponse {
        head,
        body,
        prefix: Vec::new(),
        upgraded: false,
    })
}

async fn read_head_bytes(stream: &mut TcpStream) -> Option<(Vec<u8>, usize)> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some((buffer, position + 4));
        }
        if buffer.len() > 64 * 1024 {
            return None;
        }
    }
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

async fn forward_request(head: &str, body: &[u8]) -> std::io::Result<(String, TcpStream)> {
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("the proxy request has no request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| invalid("the proxy request has no method"))?;
    let absolute = parts
        .next()
        .ok_or_else(|| invalid("the proxy request has no absolute target"))?;
    let version = parts
        .next()
        .ok_or_else(|| invalid("the proxy request has no version"))?;
    let url =
        url::Url::parse(absolute).map_err(|_| invalid("the proxy request target is not a URL"))?;
    let host = match url
        .host()
        .ok_or_else(|| invalid("the proxy request target has no host"))?
    {
        url::Host::Domain(domain) => domain.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("the proxy request target has no port"))?;
    let mut target = TcpStream::connect((host, port)).await?;
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let mut forwarded = format!("{method} {path} {version}\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        // A compliant forward proxy consumes the hop-by-hop credential rather
        // than forwarding it to the origin. This fixture does that so the test
        // can distinguish the client's proxy leg from the proxy's own policy.
        if line
            .to_ascii_lowercase()
            .starts_with("proxy-authorization:")
        {
            continue;
        }
        forwarded.push_str(line);
        forwarded.push_str("\r\n");
    }
    forwarded.push_str("\r\n");
    target.write_all(forwarded.as_bytes()).await?;
    target.write_all(body).await?;
    target.flush().await?;
    Ok((forwarded, target))
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// A request body and its response cross a forwarding proxy without losing
/// framing. The proxy receives absolute-form and the configured credential; the
/// target receives origin-form, the body, and no `Proxy-Authorization`.
#[tokio::test]
async fn request_and_response_bodies_cross_a_forwarding_proxy() {
    let target = start_body_server(
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let proxy = start_forwarding_proxy().await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(proxy.endpoint(), "user", "pass")
                .expect("bounded test credentials"),
        ),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let request = RawRequest::new(hyper::Method::POST, "/containers/create")
        .with_query("name=body")
        .with_body(RawBody::from_slice(br#"{"Image":"alpine"}"#));
    let response = tokio::time::timeout(Duration::from_secs(5), engine.send(request))
        .await
        .expect("the forwarding proxy did not answer")
        .expect("the request through the forwarding proxy");
    assert_eq!(response.status.as_u16(), 201);
    let document = response.document().await.expect("the response body");
    assert_eq!(&document[..], b"{}");

    let received = proxy.received();
    assert_eq!(received.len(), 1, "{received:?}");
    let (received_head, received_body) = &received[0];
    let expected_absolute = format!(
        "POST http://{}{}/containers/create?name=body HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(
        received_head.starts_with(&expected_absolute),
        "{received_head}"
    );
    let auth_lines = received_head
        .lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .starts_with("proxy-authorization:")
        })
        .collect::<Vec<_>>();
    assert_eq!(auth_lines.len(), 1, "{received_head}");
    assert_eq!(
        auth_lines[0],
        format!("proxy-authorization: {CANARY_AUTHORIZATION}"),
        "{received_head}"
    );
    assert_eq!(received_body, br#"{"Image":"alpine"}"#);

    let forwarded = proxy.forwarded();
    assert_eq!(forwarded.len(), 1, "{forwarded:?}");
    let (forwarded_head, forwarded_body) = &forwarded[0];
    assert!(
        forwarded_head.starts_with(&format!(
            "POST {}/containers/create?name=body HTTP/1.1\r\n",
            api_prefix()
        )),
        "{forwarded_head}"
    );
    assert!(
        !forwarded_head
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{forwarded_head}"
    );
    assert_eq!(forwarded_body, br#"{"Image":"alpine"}"#);

    let target_requests = target.requests();
    assert_eq!(target_requests.len(), 1, "{target_requests:?}");
    let (target_head, target_body) = &target_requests[0];
    assert!(
        target_head.starts_with(&format!(
            "POST {}/containers/create?name=body HTTP/1.1\r\n",
            api_prefix()
        )),
        "{target_head}"
    );
    assert!(
        target_head
            .to_ascii_lowercase()
            .contains(&format!("host: {}", target.address)),
        "{target_head}"
    );
    assert!(
        !target_head
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{target_head}"
    );
    assert_eq!(target_body, br#"{"Image":"alpine"}"#);
}

/// A `101` upgrade crosses the forwarding proxy, and the switched connection is
/// usable in both directions. This pins the proxy leg for the operations that
/// call `send_upgrading`, not only ordinary documents.
#[tokio::test]
async fn upgrade_101_is_relayed_through_a_forwarding_proxy() {
    let target = start_upgrade_target().await;
    let proxy = start_forwarding_proxy().await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(proxy.endpoint(), "user", "pass")
                .expect("bounded test credentials"),
        ),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let session = tokio::time::timeout(
        Duration::from_secs(5),
        raw::exec_start_session(
            &engine,
            "exec-1",
            &raw::ExecStartOptions {
                detach: false,
                tty: true,
            },
        ),
    )
    .await
    .expect("the upgrade did not finish")
    .expect("the 101 session through the forwarding proxy");
    assert_eq!(session.status().as_u16(), 101);
    let (mut read, mut write) = session.into_connection();
    write
        .write_all(b"ping")
        .await
        .expect("write to the session");
    write.flush().await.expect("flush the session");
    let mut echoed = [0_u8; 4];
    tokio::time::timeout(Duration::from_secs(5), read.read_exact(&mut echoed))
        .await
        .expect("the session echo did not finish")
        .expect("read the session echo");
    assert_eq!(&echoed, b"ping");

    let received = proxy.received();
    assert_eq!(received.len(), 1, "{received:?}");
    let (received_head, _) = &received[0];
    assert!(
        received_head.starts_with(&format!(
            "POST http://{}{}/exec/exec-1/start HTTP/1.1\r\n",
            target.address,
            api_prefix()
        )),
        "{received_head}"
    );
    assert!(
        received_head
            .to_ascii_lowercase()
            .contains("connection: upgrade"),
        "{received_head}"
    );
    let auth_lines = received_head
        .lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .starts_with("proxy-authorization:")
        })
        .collect::<Vec<_>>();
    assert_eq!(auth_lines.len(), 1, "{received_head}");
    assert_eq!(
        auth_lines[0],
        format!("proxy-authorization: {CANARY_AUTHORIZATION}"),
        "{received_head}"
    );

    let target_requests = target.requests();
    assert_eq!(target_requests.len(), 1, "{target_requests:?}");
    assert!(
        target_requests[0].starts_with(&format!(
            "POST {}/exec/exec-1/start HTTP/1.1\r\n",
            api_prefix()
        )),
        "{}",
        target_requests[0]
    );
    assert!(
        !target_requests[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{}",
        target_requests[0]
    );
}

/// An authenticated proxy's `407` body is withheld entirely, so no encoded or
/// decoded credential variant can reach the error's display, debug, or source.
#[tokio::test]
async fn authenticated_proxy_407_withholds_all_untrusted_response_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let username = "canary-proxy-user";
    let password = "canary-proxy-password";
    let raw = format!("{username}:{password}");
    let encoded = STANDARD.encode(raw.as_bytes());
    let percent = url::form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>();
    let body = format!(
        r#"{{"message":"proxy auth required; raw={raw} encoded={encoded} header=Basic {encoded} user={username} pass={password} percent={percent}"}}"#
    );
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the 407 answer did not finish")
        .expect_err("a 407 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 407);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 407)"
    );

    let display = format!("{error}");
    let debug = format!("{error:?}");
    let source = std::error::Error::source(&error).map_or_default(ToString::to_string);
    let chain = error_chain(&error);
    for rendered in [&display, &debug, &source, &chain] {
        for variant in [
            raw.as_str(),
            encoded.as_str(),
            username,
            password,
            percent.as_str(),
            &format!("Basic {encoded}"),
        ] {
            assert!(!rendered.contains(variant), "{rendered}");
        }
        assert!(!rendered.contains("proxy auth required"), "{rendered}");
        assert!(rendered.contains("withheld"), "{rendered}");
    }
    assert_eq!(proxy.requests().len(), 1, "the 407 was retried");
    assert_eq!(target.connections(), 0, "the 407 reached the target");
}

/// A non-407 authenticated-proxy error is withheld for the same reason.
#[tokio::test]
async fn authenticated_proxy_non_407_withholds_untrusted_response_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let username = "canary-proxy-user";
    let password = "canary-proxy-password";
    let raw = format!("{username}:{password}");
    let encoded = STANDARD.encode(raw.as_bytes());
    let body = format!(
        r#"{{"message":"proxy failure raw={raw} encoded={encoded} user={username} pass={password}"}}"#
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    let chain = error_chain(&error);
    for rendered in [format!("{error}"), format!("{error:?}"), chain] {
        for variant in [raw.as_str(), encoded.as_str(), username, password] {
            assert!(!rendered.contains(variant), "{rendered}");
        }
        assert!(!rendered.contains("proxy failure"), "{rendered}");
    }
}

/// `inspect_config` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text. The
/// versioned absolute-form request is what proves the facade did not fall back
/// to Bollard, whose plain-HTTP proxy request has no version prefix.
#[tokio::test]
async fn authenticated_proxy_withholds_inspect_config_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let username = "canary-config-user";
    let password = "canary-config-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"config failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.inspect_config("config-fixture"),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("config failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/configs/config-fixture HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `list_configs` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text. The
/// versioned absolute-form request is what proves the facade did not fall back
/// to Bollard, whose plain-HTTP proxy request has no version prefix. The
/// response text also carries a synthetic config-data canary, because a config
/// answer can be sensitive.
#[tokio::test]
async fn authenticated_proxy_withholds_list_configs_failure_text() {
    const CONFIG_DATA_CANARY: &str = "canary-config-list-data-do-not-log";
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let username = "canary-config-list-user";
    let password = "canary-config-list-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"config list failure raw={} encoded={} header={} data={CONFIG_DATA_CANARY}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.list_configs(None))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
        error_chain_debug(&error),
    ] {
        assert!(!rendered.contains("config list failure"), "{rendered}");
        assert!(!rendered.contains(CONFIG_DATA_CANARY), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/configs HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `inspect_secret` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text. The
/// versioned absolute-form request is what proves the facade did not fall back
/// to Bollard, whose plain-HTTP proxy request has no version prefix.
#[tokio::test]
async fn authenticated_proxy_withholds_inspect_secret_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let username = "canary-secret-user";
    let password = "canary-secret-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"secret failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.inspect_secret("secret-fixture"),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("secret failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/secrets/secret-fixture HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `list_secrets` uses the owned route through an authenticated proxy. The
/// versioned absolute-form request is the discriminator; a status and a
/// withholding diagnostic are what the caller gets.
#[tokio::test]
async fn authenticated_proxy_withholds_list_secrets_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let username = "canary-secret-list-user";
    let password = "canary-secret-list-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"secret list failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.list_secrets(None))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("secret list failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/secrets HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// An unauthenticated proxy can echo response text. A secret read still
/// withholds it while preserving the status, unlike an ordinary operation.
#[tokio::test]
async fn unauthenticated_proxy_withholds_inspect_secret_failure_text() {
    const CANARY: &str = "unauthenticated-proxy-secret-echo-3f9c";
    let canary_base64 = STANDARD.encode(CANARY);
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let body = format!(r#"{{"message":"proxy secret failure {CANARY} {canary_base64}"}}"#);
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("the proxy URL")),
    )
    .expect("build the proxied client");

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.inspect_secret("secret-fixture"),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    for rendered in error_renderings(&error) {
        assert!(
            !rendered.contains(CANARY) && !rendered.contains(&canary_base64),
            "{rendered}"
        );
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/secrets/secret-fixture HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the secret read bypassed the proxy"
    );
}

/// A direct `raw::secret_inspect` through an authenticated proxy withholds the
/// peer's text itself, not only through the facade.
#[tokio::test]
async fn authenticated_proxy_raw_secret_inspect_withholds_failure_text() {
    const CANARY: &str = "proxy-raw-inspect-echo-5b1d";
    let canary_base64 = STANDARD.encode(CANARY);
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let body = format!(r#"{{"message":"raw inspect failure {CANARY} {canary_base64}"}}"#);
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, "user", "pass");
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        raw::secret_inspect(&engine, "secret-fixture"),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    for rendered in error_renderings(&error) {
        assert!(
            !rendered.contains(CANARY) && !rendered.contains(&canary_base64),
            "{rendered}"
        );
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/secrets/secret-fixture HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(target.connections(), 0);
}

/// A direct `raw::secret_list` through an unauthenticated proxy withholds the
/// peer's text itself, not only through the facade.
#[tokio::test]
async fn unauthenticated_proxy_raw_secret_list_withholds_failure_text() {
    const CANARY: &str = "proxy-raw-list-echo-7e2b";
    let canary_base64 = STANDARD.encode(CANARY);
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let body = format!(r#"{{"message":"raw list failure {CANARY} {canary_base64}"}}"#);
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("the proxy URL")),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        raw::secret_list(&engine, &SwarmListOptions::default()),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    for rendered in error_renderings(&error) {
        assert!(
            !rendered.contains(CANARY) && !rendered.contains(&canary_base64),
            "{rendered}"
        );
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/secrets HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(target.connections(), 0);
}

/// `inspect_swarm` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text. The
/// versioned absolute-form request is what proves the facade did not fall back
/// to Bollard, whose plain-HTTP proxy request has no version prefix.
#[tokio::test]
async fn authenticated_proxy_withholds_inspect_swarm_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let username = "canary-swarm-user";
    let password = "canary-swarm-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"swarm failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.inspect_swarm())
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("swarm failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/swarm HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `list_nodes` uses the owned route through an authenticated proxy, so a proxy
/// rejection keeps its status and withholds the proxy's text.
#[tokio::test]
async fn authenticated_proxy_withholds_list_nodes_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n[]"
            .to_vec(),
    )
    .await;
    let username = "canary-node-list-user";
    let password = "canary-node-list-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"node list failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.list_nodes(None))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("node list failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/nodes HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `inspect_node` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text.
#[tokio::test]
async fn authenticated_proxy_withholds_inspect_node_failure_text() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\
          Connection: close\r\n\r\n{}"
            .to_vec(),
    )
    .await;
    let username = "canary-node-inspect-user";
    let password = "canary-node-inspect-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"node inspect failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.inspect_node("node-fixture"))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 500)"
    );
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("node inspect failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "GET http://{}{}/nodes/node-fixture HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `update_node` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text.
#[tokio::test]
async fn authenticated_proxy_withholds_update_node_failure_text() {
    let target = start_server(ok_json_body("{}")).await;
    let username = "canary-node-update-user";
    let password = "canary-node-update-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"node update failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.update_node(
            "node-fixture",
            NodeUpdateOptions {
                version: 4,
                spec: NodeSpec {
                    name: Some("manager-one".to_owned()),
                    ..NodeSpec::default()
                },
            },
        ),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD_NODE_MUTATION);
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("node update failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "POST http://{}{}/nodes/node-fixture/update?version=4 HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// `remove_node` uses the owned route through an authenticated proxy, so a
/// proxy rejection keeps its status and withholds the proxy's text.
#[tokio::test]
async fn authenticated_proxy_withholds_remove_node_failure_text() {
    let target = start_server(ok_json_body("{}")).await;
    let username = "canary-node-remove-user";
    let password = "canary-node-remove-password";
    let canaries = CredentialCanaries::new(username, password);
    let body = format!(
        r#"{{"message":"node remove failure raw={} encoded={} header={}"}}"#,
        canaries.raw, canaries.encoded, canaries.header
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.remove_node("node-fixture", NodeRemoveOptions { force: false }),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD_NODE_MUTATION);
    assert_withheld_without_canaries(&error, &canaries);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
    ] {
        assert!(!rendered.contains("node remove failure"), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "DELETE http://{}{}/nodes/node-fixture?force=false HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// An unauthenticated proxy can still echo node metadata, so the mutation
/// withholds its text even though there is no credential to protect.
#[tokio::test]
async fn unauthenticated_proxy_withholds_node_update_failure_text() {
    let target = start_server(ok_json_body("{}")).await;
    let canary = "canary-node-metadata-via-unauth-proxy-8e1c";
    let body = format!(
        r#"{{"message":"node update failure Name manager-one Labels org.example.node={canary}"}}"#
    );
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_without_credentials(&target, &proxy);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.update_node(
            "node-fixture",
            NodeUpdateOptions {
                version: 4,
                spec: NodeSpec {
                    name: Some("manager-one".to_owned()),
                    ..NodeSpec::default()
                },
            },
        ),
    )
    .await
    .expect("the 500 answer did not finish")
    .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD_NODE_MUTATION);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
        error_chain_debug(&error),
    ] {
        assert!(!rendered.contains(canary), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "POST http://{}{}/nodes/node-fixture/update?version=4 HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// The same withholding applies to a removal that a direct peer answers with
/// node metadata.
#[tokio::test]
async fn unauthenticated_proxy_withholds_node_remove_failure_text() {
    let target = start_server(ok_json_body("{}")).await;
    let canary = "canary-node-metadata-remove-4a7e";
    let body = format!(
        r#"{{"message":"node remove failure for {canary}; Labels org.example.node=fixture"}}"#
    );
    let response = format!(
        "HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_without_credentials(&target, &proxy);

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.remove_node("node-fixture", NodeRemoveOptions { force: false }),
    )
    .await
    .expect("the 409 answer did not finish")
    .expect_err("a 409 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 409);
    assert_eq!(api.message, WITHHELD_NODE_MUTATION);
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error_chain(&error),
        error_chain_debug(&error),
    ] {
        assert!(!rendered.contains(canary), "{rendered}");
    }

    let requests = proxy.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let expected_target = format!(
        "DELETE http://{}{}/nodes/node-fixture?force=false HTTP/1.1\r\n",
        target.address,
        api_prefix()
    );
    assert!(requests[0].starts_with(&expected_target), "{}", requests[0]);
    assert_eq!(
        target.connections(),
        0,
        "the facade operation bypassed the proxy"
    );
}

/// An unauthenticated proxy has no configured credential to echo, so its error
/// message is preserved rather than withheld.
#[tokio::test]
async fn unauthenticated_proxy_error_message_is_preserved() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let body = r#"{"message":"unauthenticated proxy failure"}"#;
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(target.endpoint()),
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("the proxy URL")),
    )
    .expect("build the proxied client");
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the 500 answer did not finish")
        .expect_err("a 500 must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(
        error.api_error().map(|api| api.message.as_str()),
        Some("unauthenticated proxy failure")
    );
}

/// `RawResponse` Debug withholds proxy-controlled header names and values, while
/// the explicit `headers` map remains caller-visible.
#[tokio::test]
async fn proxied_response_debug_withholds_proxy_controlled_headers() {
    let target = start_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
    )
    .await;
    let username = "canary-proxy-user";
    let password = "canary-proxy-password";
    let raw = format!("{username}:{password}");
    let encoded = STANDARD.encode(raw.as_bytes());
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         X-Proxy-Echo: Basic {encoded}\r\n\
         X-Proxy-Raw: {raw}\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    )
    .into_bytes();
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(&target, &proxy, username, password);
    let engine = client.raw_engine().expect("the owned proxied target");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        engine.send(RawRequest::new(hyper::Method::GET, "/info")),
    )
    .await
    .expect("the proxy answer did not finish")
    .expect("the proxy response");
    assert_eq!(response.status.as_u16(), 407);
    let debug = format!("{response:?}");
    for variant in [
        raw.as_str(),
        encoded.as_str(),
        username,
        password,
        &format!("Basic {encoded}"),
    ] {
        assert!(!debug.contains(variant), "{debug}");
    }
    assert!(!debug.contains("x-proxy-echo"), "{debug}");
    assert!(!debug.contains("x-proxy-raw"), "{debug}");
    assert!(debug.contains("withheld"), "{debug}");

    // The explicit header map is caller-visible and is not rewritten. A caller
    // that reads it can still see a malicious proxy's echo; that is documented
    // on `RawResponse`.
    let echoed = response
        .headers
        .get("x-proxy-echo")
        .and_then(|value| value.to_str().ok())
        .expect("the explicit header remains accessible");
    assert!(echoed.contains(&encoded), "{echoed}");
}

/// Direct daemon response headers stay visible in `Debug`, preserving the
/// previous behavior outside the proxy route.
#[tokio::test]
async fn direct_response_debug_keeps_daemon_headers() {
    let response = b"HTTP/1.1 200 OK\r\nX-Daemon: visible\r\nContent-Length: 2\r\n\
        Connection: close\r\n\r\n{}"
        .to_vec();
    let target = start_server(response).await;
    let client = DockerClient::connect_http(&target.endpoint()).expect("the direct client");
    let engine = client.raw_engine().expect("the owned direct target");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        engine.send(RawRequest::new(hyper::Method::GET, "/info")),
    )
    .await
    .expect("the daemon answer did not finish")
    .expect("the daemon response");
    let debug = format!("{response:?}");
    assert!(debug.contains("x-daemon"), "{debug}");
    assert!(debug.contains("visible"), "{debug}");
}

/// Withholding is scoped to an authenticated proxy route. A direct daemon error
/// is left as the daemon wrote it.
#[tokio::test]
async fn direct_daemon_error_message_is_preserved() {
    let body = r#"{"message":"daemon failure: Basic unrelated"}"#;
    let response = format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let target = start_server(response).await;
    let client = DockerClient::connect_http(&target.endpoint()).expect("the direct client");
    let engine = client.raw_engine().expect("the owned direct target");

    let error = tokio::time::timeout(Duration::from_secs(5), raw::info(&engine))
        .await
        .expect("the daemon error did not finish")
        .expect_err("a 500 must be an error");
    assert!(
        error
            .to_string()
            .contains("daemon failure: Basic unrelated"),
        "{error}"
    );
    assert_eq!(error.api_error().map(|api| api.status_code), Some(500));
}

/// An authenticated proxy can answer `200` and put a failure in a progress
/// record. The owned pull document must withhold that text rather than promote
/// it into an error, and none of the configured credential forms may appear in
/// the error or any source.
#[tokio::test]
async fn authenticated_proxy_in_band_pull_error_is_withheld() {
    let canaries = CredentialCanaries::new("canary-inband-pull-user", "canary-inband-pull-pass");
    let body = format!(
        r#"{{"errorDetail":{{"message":"{}"}}}}"#,
        canaries.message("pull failed")
    );
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        raw::image_pull_document(
            &engine,
            "alpine",
            &ImagePullOptions::default(),
            raw::RegistryAuth::none(),
        ),
    )
    .await
    .expect("the pull document did not finish")
    .expect_err("an in-band pull failure must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(error.api_error().map(|api| api.status_code), Some(200));
    assert_withheld_without_canaries(&error, &canaries);
}

/// The push document has the same in-band failure shape.
#[tokio::test]
async fn authenticated_proxy_in_band_push_error_is_withheld() {
    let canaries = CredentialCanaries::new("canary-inband-push-user", "canary-inband-push-pass");
    let body = format!(
        r#"{{"errorDetail":{{"message":"{}"}}}}"#,
        canaries.message("push failed")
    );
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);
    let engine = client.raw_engine().expect("the owned proxied target");

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        raw::image_push_document(
            &engine,
            "alpine",
            &ImagePushOptions::default(),
            raw::RegistryAuth::none(),
        ),
    )
    .await
    .expect("the push document did not finish")
    .expect_err("an in-band push failure must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(error.api_error().map(|api| api.status_code), Some(200));
    assert_withheld_without_canaries(&error, &canaries);
}

/// A facade build stream must not promote a `200` in-band failure to an error
/// carrying the proxy's text.
#[tokio::test]
async fn authenticated_proxy_in_band_build_error_is_withheld() {
    let canaries = CredentialCanaries::new("canary-inband-build-user", "canary-inband-build-pass");
    let body = format!(
        r#"{{"errorDetail":{{"message":"{}"}}}}"#,
        canaries.message("build failed")
    );
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_body_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_body_proxy(&target, &proxy, canaries.username, canaries.password);

    let mut stream = client
        .build_image(build_wire::build_context(), None)
        .expect("the build stream");
    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the build stream did not finish")
        .expect("the build stream produced no item");
    let error = item.expect_err("an in-band build failure must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(error.api_error().map(|api| api.status_code), Some(200));
    assert_withheld_without_canaries(&error, &canaries);
}

/// A facade load stream must not promote a `200` in-band failure to an error
/// carrying the proxy's text.
#[tokio::test]
async fn authenticated_proxy_in_band_load_error_is_withheld() {
    let canaries = CredentialCanaries::new("canary-inband-load-user", "canary-inband-load-pass");
    let body = format!(r#"{{"error":"{}"}}"#, canaries.message("load failed"));
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_body_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_body_proxy(&target, &proxy, canaries.username, canaries.password);
    let source = stream::once(async { Ok::<_, std::io::Error>(b"tar".to_vec()) });

    let mut stream = client
        .load_image(source, None, ImageTransferLimits::default())
        .expect("the load stream");
    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the load stream did not finish")
        .expect("the load stream produced no item");
    let error = item.expect_err("an in-band load failure must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(error.api_error().map(|api| api.status_code), Some(200));
    assert_withheld_without_canaries(&error, &canaries);
}

/// A facade import stream must not promote a `200` in-band failure to an error
/// carrying the proxy's text.
#[tokio::test]
async fn authenticated_proxy_in_band_import_error_is_withheld() {
    let canaries =
        CredentialCanaries::new("canary-inband-import-user", "canary-inband-import-pass");
    let body = format!(
        r#"{{"errorDetail":{{"message":"{}"}}}}"#,
        canaries.message("import failed")
    );
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_body_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_body_proxy(&target, &proxy, canaries.username, canaries.password);
    let source = stream::once(async { Ok::<_, std::io::Error>(b"tar".to_vec()) });

    let mut stream = client
        .import_image_from_stream(
            ImageImportOptions::new("-"),
            source,
            ImageTransferLimits::default(),
        )
        .expect("the import stream");
    let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the import stream did not finish")
        .expect("the import stream produced no item");
    let error = item.expect_err("an in-band import failure must be an error");
    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    assert_eq!(error.api_error().map(|api| api.status_code), Some(200));
    assert_withheld_without_canaries(&error, &canaries);
}

/// The facade push stream keeps the in-band failure as caller-visible event
/// data, not an `Error`. This is the documented boundary: the value is data the
/// caller asked to read.
#[tokio::test]
async fn authenticated_proxy_push_stream_keeps_in_band_error_as_data() {
    let canaries = CredentialCanaries::new("canary-push-stream-user", "canary-push-stream-pass");
    let body = format!(r#"{{"error":"{}"}}"#, canaries.message("push failed"));
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);

    let mut stream = client.push_image("alpine", None);
    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the push stream did not finish")
        .expect("the push stream produced no item")
        .expect("the push stream data item");
    let error = event.error.expect("the in-band data item");
    assert!(error.contains(canaries.raw.as_str()), "{error}");
}

/// The facade pull stream has the same intentional-data boundary.
#[tokio::test]
async fn authenticated_proxy_pull_stream_keeps_in_band_error_as_data() {
    let canaries = CredentialCanaries::new("canary-pull-stream-user", "canary-pull-stream-pass");
    let body = format!(r#"{{"error":"{}"}}"#, canaries.message("pull failed"));
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(ok_json_body(&format!("{body}\n"))).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);

    let mut stream = client.pull_image("alpine", None);
    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("the pull stream did not finish")
        .expect("the pull stream produced no item")
        .expect("the pull stream data item");
    let error = event.error.expect("the in-band data item");
    assert!(error.contains(canaries.raw.as_str()), "{error}");
}

/// Successful proxy values are returned as data and are not sanitized. This
/// pins the documented boundary: the withholding policy covers non-success
/// error messages and `RawResponse` Debug headers, not `Ping`'s header-derived
/// fields.
#[tokio::test]
async fn successful_proxy_ping_value_is_data_and_not_sanitized() {
    let canary = "canary-proxy-ping-value";
    let response = format!(
        "HTTP/1.1 200 OK\r\nApi-Version: {canary}\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
    .into_bytes();
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(response).await;
    let client = proxied_client_with_credentials(
        &target,
        &proxy,
        "canary-proxy-user",
        "canary-proxy-password",
    );
    let engine = client.raw_engine().expect("the owned proxied target");

    let ping = tokio::time::timeout(Duration::from_secs(5), raw::ping(&engine))
        .await
        .expect("the ping did not finish")
        .expect("the ping answer");
    assert_eq!(ping.api_version.as_deref(), Some(canary));
    assert!(
        format!("{ping:?}").contains(canary),
        "a successful value is caller-visible data, not sanitized: {ping:?}"
    );
}

/// A wrong-typed container-list member on an authenticated proxy response must
/// not quote the value in the serde diagnostic.
#[tokio::test]
async fn authenticated_proxy_container_list_wrong_type_does_not_echo_credential() {
    let canaries = CredentialCanaries::new("canary-wrongtype-user", "canary-wrongtype-pass");
    let body = format!(r#"[{{"Created":"{}"}}]"#, canaries.raw);
    let target = start_server(ok_json_body("[]")).await;
    let proxy = start_server(ok_json_body(&body)).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.list_containers())
        .await
        .expect("the container list did not finish")
        .expect_err("a wrong-typed Created member must be an error");
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    assert_no_canaries(&error, &canaries);
    let display = format!("{error}");
    let debug = format!("{error:?}");
    let chain = error_chain(&error);
    let chain_debug = error_chain_debug(&error);
    for rendered in [&display, &debug, &chain, &chain_debug] {
        assert!(rendered.contains("data error"), "{rendered}");
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
    }
}

/// The version document's typed decode has the same content-free diagnostic.
#[tokio::test]
async fn authenticated_proxy_version_wrong_type_does_not_echo_credential() {
    let canaries = CredentialCanaries::new("canary-version-user", "canary-version-pass");
    let body = format!(r#"{{"Experimental":"{}"}}"#, canaries.raw);
    let target = start_server(ok_json_body("{}")).await;
    let proxy = start_server(ok_json_body(&body)).await;
    let client =
        proxied_client_with_credentials(&target, &proxy, canaries.username, canaries.password);

    let error = tokio::time::timeout(Duration::from_secs(5), client.version_value())
        .await
        .expect("the version request did not finish")
        .expect_err("a wrong-typed Experimental member must be an error");
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    assert_no_canaries(&error, &canaries);
    let display = format!("{error}");
    let debug = format!("{error:?}");
    let chain = error_chain(&error);
    let chain_debug = error_chain_debug(&error);
    for rendered in [&display, &debug, &chain, &chain_debug] {
        assert!(rendered.contains("data error"), "{rendered}");
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
    }
}

/// A public generic decoder cannot infer whether a serde message's field name
/// came from the schema or from a custom deserializer. A forged missing-field
/// message must not be trusted even when it carries credential-looking text.
///
/// The name is alphanumeric with underscores only, which is exactly the shape
/// the old extraction allowlist accepted; a hyphenated or colon-bearing canary
/// would have passed even the vulnerable implementation.
const FORGED_CREDENTIAL_NAME: &str = "SYNTHETIC_CANARY_FORGED_PROXY_CREDENTIAL";

#[derive(Debug)]
struct ForgedMissing;

impl<'de> serde::Deserialize<'de> for ForgedMissing {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let _: serde_json::Value = serde::Deserialize::deserialize(deserializer)?;
        Err(serde::de::Error::custom(format!(
            "missing field `{FORGED_CREDENTIAL_NAME}`"
        )))
    }
}

/// The duplicate-field spelling is forged the same way.
#[derive(Debug)]
struct ForgedDuplicate;

impl<'de> serde::Deserialize<'de> for ForgedDuplicate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let _: serde_json::Value = serde::Deserialize::deserialize(deserializer)?;
        Err(serde::de::Error::custom(format!(
            "duplicate field `{FORGED_CREDENTIAL_NAME}`"
        )))
    }
}

fn assert_forged_decode_is_safe<T: serde::de::DeserializeOwned + std::fmt::Debug>(
    canaries: &CredentialCanaries,
) {
    let error =
        raw::decode::<T>(br#"{"value":true}"#).expect_err("the custom deserializer must fail");
    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{error}");
    let display = format!("{error}");
    let debug = format!("{error:?}");
    let chain = error_chain(&error);
    let chain_debug = error_chain_debug(&error);
    for rendered in [&display, &debug, &chain, &chain_debug] {
        for variant in canaries.all() {
            assert!(!rendered.contains(variant), "{rendered}");
        }
        assert!(rendered.contains("data error"), "{rendered}");
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
    }
}

#[test]
fn forged_missing_and_duplicate_field_messages_do_not_echo_credentials() {
    let canaries = CredentialCanaries::new(FORGED_CREDENTIAL_NAME, FORGED_CREDENTIAL_NAME);
    assert_forged_decode_is_safe::<ForgedMissing>(&canaries);
    assert_forged_decode_is_safe::<ForgedDuplicate>(&canaries);
}
