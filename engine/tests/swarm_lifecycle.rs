//! Swarm cluster lifecycle operations on the repository-owned transport.
//!
//! # Why loopback fixtures and not unit assertions
//!
//! The claims this file pins are *transport* claims: `initialize_swarm`,
//! `join_swarm`, `update_swarm`, `swarm_certificates`, and `swarm_unlock_key`
//! must send the versioned owned request and must not fall back to the
//! generated client. Asserting that against a request builder would only show
//! what the builder would produce if it were called; the routing decision is
//! above it. A loopback HTTP fixture is the one place the wire request, the
//! body, and the routing are the same observation.
//!
//! # The failures these tests are written to catch
//!
//! Reintroducing a generated fallback loses the version prefix, and for the
//! join it would trace the join token. The request-line, body, and withholding
//! assertions below compare the whole observation. All five operations replace
//! daemon or proxy failure text with fixed text while preserving the status;
//! plaintext and base64 canaries are checked through `Display`, `Debug`, the
//! API message, and the full source chain. A `101` or `304` is a failure rather
//! than success, a duplicate response key is refused without echoing either
//! value, and a reserved `SwarmSpec::additional` key is refused before dispatch
//! rather than emitted twice. A request that is supposed to be refused locally
//! must not reach the fixture socket.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::FutureExt;
use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, Error, ErrorKind, ForwardProxy, ProxyPolicy,
    SwarmInitOptions, SwarmJoinOptions, SwarmSpec, SwarmUpdateOptions,
};
use tokio::sync::oneshot;

/// A synthetic join token. It is never a real credential; the tests search for
/// it in every rendering the client controls.
const TOKEN: &str = "SWMTKN-1-canary-join-token-7c1e4b-do-not-log-me";
/// A synthetic node key. It is never a real credential.
const NODE_KEY: &str =
    "-----BEGIN PRIVATE KEY-----canary-node-key-4f8b2c19-----END PRIVATE KEY-----";
/// A synthetic manager unlock key. It is never a real credential.
const UNLOCK_KEY: &str = "SWMKEY-1-canary-unlock-key-6d2a9f-do-not-log-me";
/// A synthetic manager address. It is never a real endpoint.
const INIT_ADDRESS: &str = "canary-init-manager-10.9.8.7-do-not-log-me";
/// A synthetic specification value. It is never real cluster data.
const UPDATE_SPEC: &str = "canary-update-spec-3e7b-do-not-log-me";
/// Synthetic proxy credentials. They are never real credentials.
const PROXY_USER: &str = "canary-proxy-user-2c19";
const PROXY_PASSWORD: &str = "canary-proxy-password-8f4d";

/// The fixed text each failure must render instead of untrusted response text.
/// Duplicated here rather than exported: this is the contract a caller sees,
/// and a change to it should fail this suite.
const WITHHELD_JOIN: &str =
    "response text withheld for Swarm join because the request carries a join token";
const WITHHELD_INIT: &str =
    "response text withheld for Swarm init because the request carries manager addresses";
const WITHHELD_UPDATE: &str =
    "response text withheld for a Swarm update because the request carries the Swarm specification";
const WITHHELD_CERTIFICATES: &str =
    "response text withheld for a Swarm certificate read because the answer carries a node key";
const WITHHELD_UNLOCK_KEY: &str = "response text withheld for a Swarm unlock-key read because the answer carries a manager unlock key";

/// A recorded request head and body.
struct Request {
    head: String,
    body: Vec<u8>,
}

impl Request {
    fn line(&self) -> &str {
        self.head.lines().next().expect("the request line")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// A one-request-at-a-time HTTP server that records each request and then waits
/// for the client to release the connection.
struct Fixture {
    endpoint: String,
    requests: Receiver<Request>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept the request");
                let request = read_request(&mut stream);
                let _ = request_tx.send(request);
                stream
                    .write_all(&response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
                wait_for_client_close(&mut stream);
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            requests,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request(&self) -> Request {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A server that rejects one request and then watches for a retry.
///
/// A second connection is the observable form of a fallback after a failed
/// owned request. The watch window exists because a client that retried would
/// do so immediately after the first answer; the first answer has already been
/// read when the window opens.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<Request>,
    retry: Receiver<()>,
    server: JoinHandle<()>,
}

impl RejectingFixture {
    fn start(status: &str, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let response = json_response(status, body);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let request = read_request(&mut stream);
            let _ = request_tx.send(request);
            stream
                .write_all(&response)
                .expect("write the fixture answer");
            stream.flush().expect("flush the fixture answer");
            wait_for_client_close(&mut stream);

            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request(&mut retry_stream);
                        let _ = retry_tx.send(());
                        let _ = retry_stream.write_all(&empty_response("200 OK"));
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            first_request,
            retry,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request(&self) -> Request {
        self.first_request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn saw_retry(&self) -> bool {
        matches!(self.retry.recv_timeout(Duration::from_millis(500)), Ok(()))
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A listening socket that records whether anything connected.
struct NoRequestFixture {
    endpoint: String,
    listener: TcpListener,
}

impl NoRequestFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        Self {
            endpoint: format!("http://{address}"),
            listener,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn saw_request(&self) -> bool {
        let deadline = Instant::now() + Duration::from_millis(150);
        while Instant::now() < deadline {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_request(&mut stream);
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return true,
            }
        }
        false
    }
}

/// A server that accepts one request, never answers it, and then watches for a
/// retry after the client disconnects.
///
/// The observation channels are `tokio::sync::oneshot` and the server join runs
/// on `spawn_blocking`, so the current-thread test runtime stays scheduled while
/// the fixture waits. A blocking receive here would starve the owned transport's
/// connection driver and make a healthy cancellation look like a socket leak.
struct HeldResponseFixture {
    endpoint: String,
    request: Option<oneshot::Receiver<Request>>,
    close: Option<oneshot::Receiver<bool>>,
    retry: Option<oneshot::Receiver<()>>,
    server: JoinHandle<()>,
}

impl HeldResponseFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = oneshot::channel();
        let (close_tx, close) = oneshot::channel();
        let (retry_tx, retry) = oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let recorded = read_request(&mut stream);
            let _ = request_tx.send(recorded);
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set the fixture read timeout");
            let mut buffer = [0_u8; 64];
            let observed = match stream.read(&mut buffer) {
                Ok(0) => true,
                Ok(_) => false,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    false
                }
                Err(_) => true,
            };
            let _ = close_tx.send(observed);
            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request(&mut retry_stream);
                        let _ = retry_tx.send(());
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
            drop(stream);
        });
        Self {
            endpoint: format!("http://{address}"),
            request: Some(request),
            close: Some(close),
            retry: Some(retry),
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    async fn request(&mut self) -> Request {
        let receiver = self.request.take().expect("the request receiver");
        tokio::time::timeout(Duration::from_secs(10), receiver)
            .await
            .expect("the fixture recorded no request")
            .expect("the fixture request sender")
    }

    async fn close_observed(&mut self) -> bool {
        let receiver = self.close.take().expect("the close receiver");
        tokio::time::timeout(Duration::from_secs(2), receiver)
            .await
            .expect("the fixture reported no close observation")
            .expect("the fixture close sender")
    }

    async fn saw_retry(&mut self) -> bool {
        let Some(receiver) = self.retry.take() else {
            return false;
        };
        matches!(
            tokio::time::timeout(Duration::from_millis(500), receiver).await,
            Ok(Ok(()))
        )
    }

    async fn finish(self) {
        let server = self.server;
        tokio::task::spawn_blocking(move || server.join().expect("the fixture thread"))
            .await
            .expect("the fixture join");
    }
}

/// Recorded proxy requests: request head and body.
type RecordedProxyRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A loopback proxy that records each request and rejects it with `status` and
/// a body echoing every lifecycle canary in plaintext and base64.
struct EchoingSwarmProxy {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    recorded: RecordedProxyRequests,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for EchoingSwarmProxy {
    /// An assertion panic must not leave the proxy task detached.
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl EchoingSwarmProxy {
    async fn start(status: &'static str) -> Self {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the proxy fixture");
        let address = listener.local_addr().expect("the proxy address");
        let connections = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let proxy_basic = format!(
            "Basic {}",
            STANDARD.encode(format!("{PROXY_USER}:{PROXY_PASSWORD}"))
        );
        let body = format!(
            r#"{{"message":"proxy rejected a lifecycle request for {INIT_ADDRESS} {UPDATE_SPEC} {TOKEN} {NODE_KEY} {UNLOCK_KEY} {PROXY_USER} {PROXY_PASSWORD} {proxy_basic} encoded {} {} {} {} {} and peer text canary"}}"#,
            STANDARD.encode(INIT_ADDRESS),
            STANDARD.encode(UPDATE_SPEC),
            STANDARD.encode(TOKEN),
            STANDARD.encode(NODE_KEY),
            STANDARD.encode(UNLOCK_KEY),
        );
        let task = tokio::spawn({
            let connections = Arc::clone(&connections);
            let recorded = Arc::clone(&recorded);
            async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    // A partial request must not wedge the fixture: the read is
                    // bounded, and a timeout closes this connection.
                    let read = tokio::time::timeout(
                        Duration::from_secs(5),
                        read_async_request(&mut stream),
                    )
                    .await;
                    let Ok(Ok((head, request_body))) = read else {
                        let _ = stream.shutdown().await;
                        continue;
                    };
                    recorded
                        .lock()
                        .expect("the recorded proxy requests")
                        .push((head, request_body));
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                }
            }
        });
        Self {
            address,
            connections,
            recorded,
            task: Some(task),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Aborts and reaps the proxy task on the success path. Dropping the value
    /// does the same abort without awaiting, so an assertion panic is covered.
    async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn read_async_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, Vec<u8>), std::io::Error> {
    use tokio::io::AsyncReadExt;

    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::other(
                "the request ended before its headers",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
    let length = content_length(&head);
    let body_start = header_end + 4;
    while request.len() < body_start + length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::other("the request body ended early"));
        }
        request.extend_from_slice(&chunk[..read]);
    }
    Ok((head, request[body_start..body_start + length].to_vec()))
}

/// Reads a request head and exactly the body its `Content-Length` names.
fn read_request(stream: &mut TcpStream) -> Request {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let length = content_length(&head);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).expect("read the request body");
        assert_ne!(read, 0, "the request body ended before Content-Length");
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Request { head, body }
}

fn content_length(head: &str) -> usize {
    head.lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().expect("a Content-Length"))
        })
        .unwrap_or(0)
}

fn recorded_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// Waits for the client to release the connection, so the next `accept` is the
/// next operation rather than a retry.
fn wait_for_client_close(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set the fixture read timeout");
    let mut buffer = [0_u8; 64];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn empty_response(status: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

fn json_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Renders an error through `Display`, `Debug`, its API pair, and every source.
fn renderings(error: &Error) -> Vec<String> {
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    if let Some(api) = error.api_error() {
        rendered.push(api.to_string());
        rendered.push(api.message.clone());
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        rendered.push(cause.to_string());
        rendered.push(format!("{cause:?}"));
        source = cause.source();
    }
    rendered
}

/// Asserts a rejection preserves its status, renders only the operation's fixed
/// text, and cannot carry any canary or peer phrase.
fn assert_withheld_api(
    error: &Error,
    status: u16,
    message: &str,
    canaries: &[&str],
    peer_phrase: &str,
) {
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, status);
    assert_eq!(api.message, message);
    for rendered in renderings(error) {
        for canary in canaries {
            assert!(
                !rendered.contains(canary),
                "a withheld rejection leaked a canary: {rendered}"
            );
        }
        assert!(
            !rendered.contains(peer_phrase),
            "a withheld rejection preserved peer text: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }
}

#[tokio::test]
async fn initialize_swarm_sends_the_versioned_engine_body() {
    let fixture = Fixture::start(vec![json_response("200 OK", r#""node-abc123""#)]);

    let node_id = fixture
        .client()
        .initialize_swarm(SwarmInitOptions {
            listen_address: Some("0.0.0.0:2377".to_owned()),
            advertise_address: Some("10.0.0.5:2377".to_owned()),
            data_path_address: Some("10.0.0.5".to_owned()),
            data_path_port: Some(4789),
            force_new_cluster: Some(false),
        })
        .await
        .expect("the fixture initialized the Swarm");

    assert_eq!(node_id, "node-abc123");
    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/init HTTP/1.1", version_prefix()),
        "initialize_swarm did not send the versioned owned path"
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body).expect("the body is JSON"),
        serde_json::json!({
            "ListenAddr": "0.0.0.0:2377",
            "AdvertiseAddr": "10.0.0.5:2377",
            "DataPathAddr": "10.0.0.5",
            "DataPathPort": 4789,
            "ForceNewCluster": false,
        }),
        "the owned init body is not the Engine's document"
    );

    fixture.finish();
}

#[tokio::test]
async fn join_swarm_sends_the_versioned_body_with_the_token() {
    let fixture = Fixture::start(vec![empty_response("200 OK")]);

    fixture
        .client()
        .join_swarm(SwarmJoinOptions {
            token: TOKEN.to_owned(),
            remote_addresses: vec!["tcp://manager:2377".to_owned()],
            listen_address: Some("0.0.0.0:2377".to_owned()),
            advertise_address: Some("10.0.0.6:2377".to_owned()),
            data_path_address: None,
        })
        .await
        .expect("the fixture accepted the join");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/join HTTP/1.1", version_prefix()),
        "join_swarm did not send the versioned owned path"
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body).expect("the body is JSON"),
        serde_json::json!({
            "ListenAddr": "0.0.0.0:2377",
            "AdvertiseAddr": "10.0.0.6:2377",
            "RemoteAddrs": ["tcp://manager:2377"],
            "JoinToken": TOKEN,
        }),
        "the owned join body is not the Engine's document"
    );

    fixture.finish();
}

#[tokio::test]
async fn join_swarm_withholds_failure_text_and_does_not_retry() {
    let encoded = STANDARD.encode(TOKEN.as_bytes());
    let fixture = RejectingFixture::start(
        "503 Service Unavailable",
        &format!(
            r#"{{"message":"peer echoed the join token {TOKEN} encoded {encoded} for tcp://manager:2377"}}"#
        ),
    );

    let error = fixture
        .client()
        .join_swarm(SwarmJoinOptions {
            token: TOKEN.to_owned(),
            remote_addresses: vec!["tcp://manager:2377".to_owned()],
            ..SwarmJoinOptions::default()
        })
        .await
        .expect_err("the fixture rejected the join");

    assert_withheld_api(
        &error,
        503,
        WITHHELD_JOIN,
        &[TOKEN, &encoded],
        "peer echoed the join token",
    );
    assert_eq!(
        fixture.request().line(),
        format!("POST {}/swarm/join HTTP/1.1", version_prefix())
    );
    assert!(!fixture.saw_retry(), "a failed owned join was retried");
    fixture.finish();
}

#[tokio::test]
async fn initialize_swarm_withholds_a_direct_echo_without_a_retry() {
    let encoded = STANDARD.encode(INIT_ADDRESS.as_bytes());
    let fixture = RejectingFixture::start(
        "500 Internal Server Error",
        &format!(r#"{{"message":"init failed for {INIT_ADDRESS} encoded {encoded}"}}"#),
    );

    let error = fixture
        .client()
        .initialize_swarm(SwarmInitOptions {
            listen_address: Some(INIT_ADDRESS.to_owned()),
            ..SwarmInitOptions::new()
        })
        .await
        .expect_err("the fixture rejected the init");

    assert_withheld_api(
        &error,
        500,
        WITHHELD_INIT,
        &[INIT_ADDRESS, &encoded],
        "init failed for",
    );
    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/init HTTP/1.1", version_prefix())
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body)
            .expect("the init body is JSON")
            .get("ListenAddr")
            .and_then(serde_json::Value::as_str),
        Some(INIT_ADDRESS)
    );
    assert!(!fixture.saw_retry(), "a failed owned init was retried");
    fixture.finish();
}

#[tokio::test]
async fn update_swarm_withholds_a_direct_echo_and_keeps_409() {
    let encoded = STANDARD.encode(UPDATE_SPEC.as_bytes());
    let fixture = RejectingFixture::start(
        "409 Conflict",
        &format!(r#"{{"message":"update failed for {UPDATE_SPEC} encoded {encoded}"}}"#),
    );

    let error = fixture
        .client()
        .update_swarm(SwarmUpdateOptions {
            version: 7,
            spec: SwarmSpec {
                name: Some(UPDATE_SPEC.to_owned()),
                labels: None,
                additional: std::collections::BTreeMap::from([(
                    "Org".to_owned(),
                    serde_json::json!(UPDATE_SPEC),
                )]),
            },
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        })
        .await
        .expect_err("the fixture rejected the update");

    assert_withheld_api(
        &error,
        409,
        WITHHELD_UPDATE,
        &[UPDATE_SPEC, &encoded],
        "update failed for",
    );
    assert_eq!(
        fixture.request().line(),
        format!(
            "POST {}/swarm/update?version=7&rotateWorkerToken=false&rotateManagerToken=false&rotateManagerUnlockKey=false HTTP/1.1",
            version_prefix()
        )
    );
    assert!(!fixture.saw_retry(), "a failed owned update was retried");
    fixture.finish();
}

#[tokio::test]
async fn swarm_certificates_withholds_a_direct_echo_without_a_retry() {
    let encoded = STANDARD.encode(NODE_KEY.as_bytes());
    let fixture = RejectingFixture::start(
        "500 Internal Server Error",
        &format!(r#"{{"message":"certificate read failed for {NODE_KEY} encoded {encoded}"}}"#),
    );

    let error = fixture
        .client()
        .swarm_certificates()
        .await
        .expect_err("the fixture rejected the certificate read");

    assert_withheld_api(
        &error,
        500,
        WITHHELD_CERTIFICATES,
        &[NODE_KEY, &encoded],
        "certificate read failed",
    );
    assert_eq!(
        fixture.request().line(),
        format!("GET {}/swarm/cert HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned certificate read was retried"
    );
    fixture.finish();
}

#[tokio::test]
async fn swarm_unlock_key_withholds_a_direct_echo_without_a_retry() {
    let encoded = STANDARD.encode(UNLOCK_KEY.as_bytes());
    let fixture = RejectingFixture::start(
        "500 Internal Server Error",
        &format!(r#"{{"message":"unlock-key read failed for {UNLOCK_KEY} encoded {encoded}"}}"#),
    );

    let error = fixture
        .client()
        .swarm_unlock_key()
        .await
        .expect_err("the fixture rejected the unlock-key read");

    assert_withheld_api(
        &error,
        500,
        WITHHELD_UNLOCK_KEY,
        &[UNLOCK_KEY, &encoded],
        "unlock-key read failed",
    );
    assert_eq!(
        fixture.request().line(),
        format!("GET {}/swarm/unlockkey HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned unlock-key read was retried"
    );
    fixture.finish();
}

#[tokio::test]
async fn join_swarm_without_a_manager_address_sends_nothing() {
    let fixture = NoRequestFixture::start();

    let error = fixture
        .client()
        .join_swarm(SwarmJoinOptions {
            token: TOKEN.to_owned(),
            remote_addresses: Vec::new(),
            ..SwarmJoinOptions::default()
        })
        .await
        .expect_err("a join with no manager address is refused");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("at least one manager address"),
        "{error}"
    );
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(TOKEN),
            "the local refusal leaked the token: {rendered}"
        );
    }
    assert!(
        !fixture.saw_request(),
        "a join with no manager address reached the socket"
    );
}

#[tokio::test]
async fn update_swarm_sends_the_versioned_query_and_body() {
    let fixture = Fixture::start(vec![empty_response("200 OK")]);

    fixture
        .client()
        .update_swarm(SwarmUpdateOptions {
            version: 7,
            spec: SwarmSpec {
                name: Some("prod".to_owned()),
                labels: Some(std::collections::BTreeMap::from([(
                    "org.example.swarm".to_owned(),
                    "prod".to_owned(),
                )])),
                additional: std::collections::BTreeMap::new(),
            },
            rotate_worker_token: true,
            rotate_manager_token: false,
            rotate_manager_unlock_key: true,
        })
        .await
        .expect("the fixture accepted the update");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!(
            "POST {}/swarm/update?version=7&rotateWorkerToken=true&rotateManagerToken=false&rotateManagerUnlockKey=true HTTP/1.1",
            version_prefix()
        ),
        "update_swarm did not spell the version and every rotation flag"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body).expect("the body is JSON"),
        serde_json::json!({
            "Name": "prod",
            "Labels": {"org.example.swarm": "prod"},
        })
    );

    fixture.finish();
}

#[tokio::test]
async fn update_swarm_refuses_a_reserved_spec_member_before_dispatch() {
    let fixture = NoRequestFixture::start();
    let client = fixture.client();
    let options = SwarmUpdateOptions {
        version: 7,
        spec: SwarmSpec {
            name: Some("typed".to_owned()),
            labels: None,
            additional: std::collections::BTreeMap::from([(
                "name".to_owned(),
                serde_json::json!("duplicate"),
            )]),
        },
        rotate_worker_token: false,
        rotate_manager_token: false,
        rotate_manager_unlock_key: false,
    };

    let error = client
        .update_swarm(options.clone())
        .await
        .expect_err("a reserved spec member is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("reserved modeled field"),
        "{error}"
    );

    // The raw writer refuses the same value, so the two routes cannot drift.
    let engine = client.raw_engine().expect("the fixture endpoint is owned");
    let error = neotales_docker::raw::swarm_update(&engine, &options)
        .await
        .expect_err("the raw writer refuses a reserved spec member");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    assert!(
        !fixture.saw_request(),
        "a reserved spec member reached the socket"
    );
}

#[tokio::test]
async fn swarm_certificates_sends_the_versioned_get_and_redacts_the_key() {
    let fixture = Fixture::start(vec![json_response(
        "200 OK",
        &format!(
            r#"{{"NodeID":"node-1","RootCA":"ROOT-CA","Cert":"NODE-CERT","Key":"{NODE_KEY}"}}"#
        ),
    )]);

    let certificates = fixture
        .client()
        .swarm_certificates()
        .await
        .expect("the fixture returned certificates");
    assert_eq!(certificates.node_id(), Some("node-1"));
    assert_eq!(certificates.root_ca(), Some("ROOT-CA"));
    assert_eq!(certificates.cert(), Some("NODE-CERT"));
    assert_eq!(certificates.key(), Some(NODE_KEY));

    let rendered = format!("{certificates:?}");
    assert!(
        !rendered.contains(NODE_KEY),
        "a SwarmCertificates Debug leaked the node key: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("GET {}/swarm/cert HTTP/1.1", version_prefix())
    );
    fixture.finish();
}

#[tokio::test]
async fn swarm_certificates_refuses_a_duplicate_key_without_echoing_it() {
    let fixture = Fixture::start(vec![json_response(
        "200 OK",
        &format!(r#"{{"NodeID":"node-1","Key":"first-{NODE_KEY}","Key":"second-{NODE_KEY}"}}"#),
    )]);

    let error = fixture
        .client()
        .swarm_certificates()
        .await
        .expect_err("a duplicate key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(NODE_KEY),
            "a duplicate-key refusal echoed the key: {rendered}"
        );
    }

    fixture.finish();
}

#[tokio::test]
async fn swarm_unlock_key_sends_the_versioned_get_and_redacts_the_key() {
    let fixture = Fixture::start(vec![json_response(
        "200 OK",
        &format!(r#"{{"UnlockKey":"{UNLOCK_KEY}"}}"#),
    )]);

    let key = fixture
        .client()
        .swarm_unlock_key()
        .await
        .expect("the fixture returned the unlock key");
    assert_eq!(key.key(), Some(UNLOCK_KEY));
    let rendered = format!("{key:?}");
    assert!(
        !rendered.contains(UNLOCK_KEY),
        "a SwarmUnlockKey Debug leaked the key: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("GET {}/swarm/unlockkey HTTP/1.1", version_prefix())
    );
    fixture.finish();
}

#[tokio::test]
async fn swarm_unlock_key_refuses_a_duplicate_key_without_echoing_it() {
    let fixture = Fixture::start(vec![json_response(
        "200 OK",
        &format!(r#"{{"UnlockKey":"first-{UNLOCK_KEY}","UnlockKey":"second-{UNLOCK_KEY}"}}"#),
    )]);

    let error = fixture
        .client()
        .swarm_unlock_key()
        .await
        .expect_err("a duplicate key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(UNLOCK_KEY),
            "a duplicate-key refusal echoed the key: {rendered}"
        );
    }

    fixture.finish();
}

#[tokio::test]
async fn lifecycle_requests_use_the_configured_version() {
    let fixture = Fixture::start(vec![json_response(
        "200 OK",
        &format!(r#"{{"UnlockKey":"{UNLOCK_KEY}"}}"#),
    )]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build the configured-version client");

    client
        .swarm_unlock_key()
        .await
        .expect("the fixture returned the unlock key");

    assert_eq!(
        fixture.request().line(),
        "GET /v1.47/swarm/unlockkey HTTP/1.1"
    );
    fixture.finish();
}

#[tokio::test]
async fn a_304_is_a_failure_rather_than_an_empty_success() {
    let fixture = Fixture::start(vec![empty_response("304 Not Modified")]);

    let error = fixture
        .client()
        .initialize_swarm(SwarmInitOptions::new())
        .await
        .expect_err("304 is not a successful initialization");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error.api_error().map(|api| api.status_code),
        Some(304),
        "the observed status is preserved"
    );
    fixture.finish();
}

#[tokio::test]
async fn a_101_is_a_failure_rather_than_an_empty_success() {
    let fixture = Fixture::start(vec![
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec(),
    ]);

    let error = fixture
        .client()
        .swarm_unlock_key()
        .await
        .expect_err("101 is not a success document");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error.api_error().map(|api| api.status_code),
        Some(101),
        "the observed status is preserved"
    );
    fixture.finish();
}

#[tokio::test]
async fn update_and_certificate_read_reject_non_success_statuses() {
    let update = Fixture::start(vec![empty_response("304 Not Modified")]);
    let error = update
        .client()
        .update_swarm(SwarmUpdateOptions {
            version: 1,
            spec: SwarmSpec::default(),
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        })
        .await
        .expect_err("304 is not a successful update");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error.api_error().map(|api| api.status_code),
        Some(304),
        "the observed update status is preserved"
    );
    assert_eq!(
        error.api_error().map(|api| api.message.clone()),
        Some(WITHHELD_UPDATE.to_owned())
    );
    update.finish();

    let certificates = Fixture::start(vec![
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec(),
    ]);
    let error = certificates
        .client()
        .swarm_certificates()
        .await
        .expect_err("101 is not a certificate document");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error.api_error().map(|api| api.status_code),
        Some(101),
        "the observed certificate status is preserved"
    );
    assert_eq!(
        error.api_error().map(|api| api.message.clone()),
        Some(WITHHELD_CERTIFICATES.to_owned())
    );
    certificates.finish();
}

#[tokio::test]
async fn lifecycle_transport_failures_are_withheld() {
    let canaries = [INIT_ADDRESS, UPDATE_SPEC, NODE_KEY, UNLOCK_KEY];
    let bad = format!("NOT-HTTP {INIT_ADDRESS} {UPDATE_SPEC} {NODE_KEY} {UNLOCK_KEY}\r\n\r\n");
    let fixture = Fixture::start(vec![bad.into_bytes(); 4]);
    let client = fixture.client();

    let errors = vec![
        client
            .initialize_swarm(SwarmInitOptions {
                listen_address: Some(INIT_ADDRESS.to_owned()),
                ..SwarmInitOptions::new()
            })
            .await
            .expect_err("a malformed response head is a transport error"),
        client
            .update_swarm(SwarmUpdateOptions {
                version: 1,
                spec: SwarmSpec {
                    name: Some(UPDATE_SPEC.to_owned()),
                    labels: None,
                    additional: std::collections::BTreeMap::new(),
                },
                rotate_worker_token: false,
                rotate_manager_token: false,
                rotate_manager_unlock_key: false,
            })
            .await
            .expect_err("a malformed response head is a transport error"),
        client
            .swarm_certificates()
            .await
            .expect_err("a malformed response head is a transport error"),
        client
            .swarm_unlock_key()
            .await
            .expect_err("a malformed response head is a transport error"),
    ];

    for error in errors {
        assert_eq!(error.kind(), ErrorKind::Transport);
        assert!(error.api_error().is_none());
        assert!(!error.is_transport_deadline());
        for rendered in renderings(&error) {
            for canary in canaries {
                assert!(
                    !rendered.contains(canary),
                    "a transport failure rendering leaked peer text: {rendered}"
                );
            }
            assert!(
                rendered.contains("withheld"),
                "the withholding must be visible rather than an omission: {rendered}"
            );
        }
    }
    fixture.finish();
}

#[tokio::test]
async fn aborting_a_join_releases_the_connection_without_retrying() {
    let mut fixture = HeldResponseFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move {
        client
            .join_swarm(SwarmJoinOptions {
                token: TOKEN.to_owned(),
                remote_addresses: vec!["tcp://manager:2377".to_owned()],
                ..SwarmJoinOptions::default()
            })
            .await
    });

    let request = fixture.request().await;
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/join HTTP/1.1", version_prefix())
    );
    task.abort();
    let _ = task.await;
    assert!(
        fixture.close_observed().await,
        "the aborted join did not release its connection"
    );
    assert!(
        !fixture.saw_retry().await,
        "an aborted join was retried over a second connection"
    );
    fixture.finish().await;
}

/// Runs all five lifecycle operations through a proxy that echoes every canary
/// in plaintext and base64, and asserts each error is withheld, not retried,
/// and not sent directly to the target.
#[allow(
    clippy::too_many_lines,
    reason = "one fixture script covering all five operations"
)]
async fn assert_proxied_lifecycle_withheld(authenticated: bool, status: &'static str) {
    use tokio::net::TcpListener;

    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the target fixture");
    let target_address = target.local_addr().expect("the target address");
    let proxy = EchoingSwarmProxy::start(status).await;

    // Both a panic and the inner deadline must reach the same cleanup: abort
    // and await the proxy task, then rethrow. The guard's Drop is only a
    // second line of defence.
    let outcome = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let proxy_credential = STANDARD.encode(format!("{PROXY_USER}:{PROXY_PASSWORD}"));
            let proxy_basic = format!("Basic {proxy_credential}");
            let policy = if authenticated {
                ProxyPolicy::Http(
                    ForwardProxy::with_basic_auth(proxy.endpoint(), PROXY_USER, PROXY_PASSWORD)
                        .expect("bounded synthetic proxy credentials"),
                )
            } else {
                ProxyPolicy::Http(
                    ForwardProxy::new(proxy.endpoint()).expect("a loopback proxy URL"),
                )
            };
            let client = DockerClient::connect_endpoint_with_policy(
                &Endpoint::Http(format!("http://{target_address}")),
                policy,
            )
            .expect("build the proxied client");
            let status_code = status
                .split_whitespace()
                .next()
                .expect("the fixture status")
                .parse::<u16>()
                .expect("a numeric fixture status");

            let encoded_init = STANDARD.encode(INIT_ADDRESS);
            let encoded_update = STANDARD.encode(UPDATE_SPEC);
            let encoded_join = STANDARD.encode(TOKEN);
            let encoded_node_key = STANDARD.encode(NODE_KEY);
            let encoded_unlock_key = STANDARD.encode(UNLOCK_KEY);
            let canaries = [
                INIT_ADDRESS,
                UPDATE_SPEC,
                TOKEN,
                NODE_KEY,
                UNLOCK_KEY,
                PROXY_USER,
                PROXY_PASSWORD,
                &proxy_credential,
                &proxy_basic,
                &encoded_init,
                &encoded_update,
                &encoded_join,
                &encoded_node_key,
                &encoded_unlock_key,
            ];

            let calls: Vec<(&str, Result<(), Error>, &str)> = vec![
                (
                    "init",
                    client
                        .initialize_swarm(SwarmInitOptions {
                            listen_address: Some(INIT_ADDRESS.to_owned()),
                            ..SwarmInitOptions::new()
                        })
                        .await
                        .map(|_| ()),
                    WITHHELD_INIT,
                ),
                (
                    "join",
                    client
                        .join_swarm(SwarmJoinOptions {
                            token: TOKEN.to_owned(),
                            remote_addresses: vec!["tcp://manager:2377".to_owned()],
                            ..SwarmJoinOptions::default()
                        })
                        .await,
                    WITHHELD_JOIN,
                ),
                (
                    "update",
                    client
                        .update_swarm(SwarmUpdateOptions {
                            version: 1,
                            spec: SwarmSpec {
                                name: Some(UPDATE_SPEC.to_owned()),
                                labels: None,
                                additional: std::collections::BTreeMap::new(),
                            },
                            rotate_worker_token: false,
                            rotate_manager_token: false,
                            rotate_manager_unlock_key: false,
                        })
                        .await,
                    WITHHELD_UPDATE,
                ),
                (
                    "certificates",
                    client.swarm_certificates().await.map(|_| ()),
                    WITHHELD_CERTIFICATES,
                ),
                (
                    "unlock-key",
                    client.swarm_unlock_key().await.map(|_| ()),
                    WITHHELD_UNLOCK_KEY,
                ),
            ];

            for (what, result, message) in calls {
                let error = result.expect_err(what);
                assert_withheld_api(&error, status_code, message, &canaries, "proxy rejected");
            }

            {
                let requests = proxy.recorded.lock().expect("the recorded proxy requests");
                assert_eq!(requests.len(), 5, "a rejected lifecycle call was retried");
                assert!(
                    requests[0].0.starts_with(&format!(
                        "POST http://{target_address}{}/swarm/init HTTP/1.1\r\n",
                        version_prefix()
                    )),
                    "the proxied init request line changed: {}",
                    requests[0].0
                );
                for (head, _) in requests.iter() {
                    let authorization = recorded_header(head, "proxy-authorization");
                    if authenticated {
                        assert_eq!(
                            authorization,
                            Some(proxy_basic.as_str()),
                            "the synthetic Proxy-Authorization header changed"
                        );
                    } else {
                        assert_eq!(
                            authorization, None,
                            "an unauthenticated proxy received a Proxy-Authorization header"
                        );
                    }
                }
            }

            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                proxy.connections.load(Ordering::SeqCst),
                5,
                "a rejected lifecycle call was retried"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), target.accept())
                    .await
                    .is_err(),
                "a proxied lifecycle call reached the target directly"
            );
        })
        .await
        .expect("the lifecycle proxy fixture exceeded its deadline");
    })
    .catch_unwind()
    .await;

    proxy.shutdown().await;
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

#[tokio::test]
async fn lifecycle_through_an_authenticated_proxy_withholds_an_echo() {
    assert_proxied_lifecycle_withheld(true, "407 Proxy Authentication Required").await;
}

#[tokio::test]
async fn lifecycle_through_an_unauthenticated_proxy_withholds_an_echo() {
    assert_proxied_lifecycle_withheld(false, "500 Internal Server Error").await;
}

#[tokio::test]
async fn swarm_certificates_reports_a_current_daemons_404() {
    let fixture = Fixture::start(vec![json_response(
        "404 Not Found",
        r#"{"message":"page not found"}"#,
    )]);

    let error = fixture
        .client()
        .swarm_certificates()
        .await
        .expect_err("a current daemon does not serve the endpoint");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(
        api.message, WITHHELD_CERTIFICATES,
        "a current daemon's 404 text reached the caller"
    );
    fixture.finish();
}
