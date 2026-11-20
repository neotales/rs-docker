//! `DockerClient::unlock_swarm` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `unlock_swarm` must send
//! `POST /v1.NN/swarm/unlock` through the owned transport, which is the only
//! route it has: there is no generated fallback that could send the unversioned
//! path instead. Asserting that against a request builder would only show what
//! the builder would produce if it were called; the routing decision is above
//! it. A loopback HTTP fixture is the only place the wire request, the body, and
//! the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Sending the unversioned `/swarm/unlock` path, or reintroducing a generated
//! fallback that does, loses the version prefix and fails the request-line
//! assertions below; the configured-version test pins the prefix itself.
//!
//! The rejection test pins two contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], and a failed owned request is
//! returned rather than retried. The redaction assertions hold a synthetic key
//! and check that neither the request's `Debug`, the options' `Debug`, nor any
//! rendering of the error can print it.
//!
//! The proxy test pins the boundary where the payload could leave the client:
//! an authenticated forward proxy that echoes the unlock key in its rejection
//! must not be able to put it into the error, and the request must not be
//! retried or sent directly to the target.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::sync::oneshot;

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ForwardProxy, ProxyPolicy,
    SwarmUnlockOptions,
};

/// A synthetic manager unlock key. It is never a real credential; the tests
/// search for it in every rendering the client controls.
const KEY: &str = "SWMKEY-1-canary-unlock-key-4f8b2c19-do-not-log-me";

/// The fixed text an unlock failure must render instead of untrusted response
/// text. Duplicated here rather than exported: this is the contract a caller
/// sees, and a change to it should fail this suite.
const WITHHELD: &str =
    "response text withheld for Swarm unlock because the request carries a manager unlock key";

/// A recorded request head and body.
struct Request {
    head: String,
    body: Vec<u8>,
}

impl Request {
    fn line(&self) -> &str {
        self.head.lines().next().expect("the request line")
    }

    fn body_text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("the unlock body is UTF-8")
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
        let response = rejected(status, body);
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
                        // Answer the retry so a broken client returns instead of
                        // leaving the test blocked on a socket read.
                        let _ = retry_stream.write_all(&ok_empty());
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
        match self.retry.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A server that accepts one request, never answers it, and then watches for a
/// retry after the client disconnects. When asked, it also reports whether the
/// peer observed the connection close.
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
    fn start(wait_for_close: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = oneshot::channel();
        let (close_tx, close) = oneshot::channel();
        let (retry_tx, retry) = oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let recorded = read_request(&mut stream);
            let _ = request_tx.send(recorded);
            if wait_for_close {
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
            }
            // Hold the response. A retry would open a second connection, which
            // is what the watch below observes; the held connection itself is
            // not a retry signal. The stream stays alive for the watch so the
            // fixture really is holding the response.
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
        match tokio::time::timeout(Duration::from_millis(500), receiver).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    async fn finish(self) {
        let server = self.server;
        tokio::task::spawn_blocking(move || server.join().expect("the fixture thread"))
            .await
            .expect("the fixture join");
    }
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

/// Returns the declared `Content-Length`, which every request in this file
/// sends because its body is buffered before the connection is opened.
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

/// Waits for the client to release the connection, so the next `accept` is the
/// next operation rather than a retry.
fn wait_for_client_close(stream: &mut TcpStream) {
    // Bounded: a client that drops a response without reading its body may leave
    // the socket open until its runtime polls the aborted driver. The fixture
    // only needs to know the client is finished reading, not to block a
    // current-thread runtime that cannot poll the driver while this join runs.
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

/// A `200` answer with no body, which is what `POST /swarm/unlock` returns.
fn ok_empty() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// A JSON rejection with an explicit status.
fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The version prefix the owned transport is expected to send.
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// The owned path sends the versioned `POST` with the Engine's exact body.
#[tokio::test]
async fn unlock_swarm_sends_a_versioned_post_and_the_engine_body() {
    let fixture = Fixture::start(vec![ok_empty()]);
    let options = SwarmUnlockOptions {
        key: KEY.to_owned(),
    };
    let rendered_options = format!("{options:?}");

    fixture
        .client()
        .unlock_swarm(options)
        .await
        .expect("the daemon accepted the unlock");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/unlock HTTP/1.1", version_prefix()),
        "unlock_swarm did not send the versioned owned path"
    );
    assert_eq!(
        request.body_text(),
        format!(r#"{{"UnlockKey":"{KEY}"}}"#),
        "the owned body is not the Engine's exact document"
    );
    assert_eq!(
        request.header("content-type"),
        Some("application/json"),
        "the owned path must declare the body type"
    );
    assert!(
        !rendered_options.contains(KEY),
        "a SwarmUnlockOptions Debug leaked the key: {rendered_options}"
    );
    assert!(
        rendered_options.contains("<redacted>"),
        "{rendered_options}"
    );

    fixture.finish();
}

/// An empty key is sent, not refused locally: the daemon owns that answer and
/// the owned route never validated the key.
#[tokio::test]
async fn unlock_swarm_sends_an_empty_key_instead_of_refusing_it() {
    let fixture = Fixture::start(vec![rejected(
        "500 Internal Server Error",
        r#"{"message":"invalid unlock key"}"#,
    )]);
    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions { key: String::new() })
        .await
        .expect_err("the fixture rejected the empty key");

    assert_eq!(error.kind(), ErrorKind::Docker, "{error}");
    let request = fixture.request();
    assert_eq!(
        request.body_text(),
        r#"{"UnlockKey":""}"#,
        "an empty key must reach the daemon unchanged"
    );
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/unlock HTTP/1.1", version_prefix())
    );

    fixture.finish();
}

/// A malformed response head that carries the key is a transport failure, not
/// an API rejection. The fixed error must not expose the peer's text, and the
/// kind must survive.
#[tokio::test]
async fn unlock_swarm_withholds_a_transport_error_echo() {
    let fixture = Fixture::start(vec![format!("NOT-HTTP {KEY}\r\n\r\n").into_bytes()]);

    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("a malformed response head is a transport error");

    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(
        error.api_error().is_none(),
        "a transport failure has no API status to preserve"
    );
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "a transport error rendering leaked the key: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }

    fixture.finish();
}

/// The owned route rejects `304 Not Modified` as an API error. It does not
/// treat it as success, which the removed generated fallback did.
#[tokio::test]
async fn unlock_swarm_rejects_a_not_modified_response() {
    let fixture = Fixture::start(vec![
        b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ]);

    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("304 is not an accepted unlock");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 304);
    assert_eq!(api.message, WITHHELD);
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "a 304 error rendering leaked the key: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }

    fixture.finish();
}

/// The owned route rejects `101 Switching Protocols` as an API error. It does
/// not treat it as success, which the removed generated fallback did.
#[tokio::test]
async fn unlock_swarm_rejects_a_switching_protocols_response() {
    let fixture = Fixture::start(vec![
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec(),
    ]);

    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("101 is not an accepted unlock");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 101);
    assert_eq!(api.message, WITHHELD);
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "a 101 error rendering leaked the key: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }

    fixture.finish();
}

/// A truncated rejection body does not lose the status: the owned route reads
/// the response head, sees the non-success status, and drops the body unread.
#[tokio::test]
async fn unlock_swarm_preserves_status_from_a_truncated_rejection() {
    let fixture = Fixture::start(vec![
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 100\r\n\r\n{\"message\":\"invalid unlock key".to_vec(),
    ]);

    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("a 500 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error
        .api_error()
        .expect("the status is preserved from the head");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD);
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "a truncated rejection rendering leaked the key: {rendered}"
        );
        assert!(
            !rendered.contains("invalid unlock key"),
            "a truncated rejection rendering preserved the body: {rendered}"
        );
    }

    fixture.finish();
}

/// The owned request carries the version configured on the client, not the
/// crate's ceiling. A daemon older than that version answers `400`; that
/// rejection is the daemon's, and it is returned without a retry.
#[tokio::test]
async fn unlock_swarm_uses_the_configured_version() {
    let fixture = Fixture::start(vec![ok_empty()]);
    let endpoint = Endpoint::parse(&fixture.endpoint).expect("a loopback HTTP endpoint");
    let client = DockerClient::connect_endpoint_with_version(
        &endpoint,
        ApiVersion {
            major: 1,
            minor: 44,
        },
    )
    .expect("a client at the configured version");

    client
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect("the daemon accepted the unlock");

    assert_eq!(
        fixture.request().line(),
        "POST /v1.44/swarm/unlock HTTP/1.1",
        "the owned request did not use the configured API version"
    );

    fixture.finish();
}

/// A held response that is cancelled is not retried. The request was already
/// sent, so the outcome is unknown; the facade must not send the key twice.
#[tokio::test]
async fn unlock_swarm_cancellation_does_not_retry_a_held_response() {
    let mut fixture = HeldResponseFixture::start(false);
    let client = fixture.client();

    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        client.unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        }),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the held response completed instead of being cancelled"
    );

    let request = fixture.request().await;
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/unlock HTTP/1.1", version_prefix())
    );
    assert_eq!(request.body_text(), format!(r#"{{"UnlockKey":"{KEY}"}}"#));
    assert!(
        !fixture.saw_retry().await,
        "a cancelled unlock request was retried"
    );

    fixture.finish().await;
}

/// Cancelling an owned send must be observable to the peer: the connection the
/// transport opened is closed, not left alive by a spawned driver. The retry
/// check alone cannot tell those apart.
///
/// The fixture uses non-blocking oneshot observation and a `spawn_blocking`
/// join, so the current-thread runtime can poll the connection driver while the
/// server waits. A blocking receive here previously starved that driver and made
/// a healthy cancellation look like a socket leak. This passes on the branch
/// base too: it is a fixture-correctness check, not a regression guard for a
/// transport change.
#[tokio::test]
async fn unlock_swarm_cancellation_closes_the_peer_connection() {
    let mut fixture = HeldResponseFixture::start(true);
    let client = fixture.client();

    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        client.unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        }),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the held response completed instead of being cancelled"
    );

    let _ = fixture.request().await;
    assert!(
        fixture.close_observed().await,
        "the peer did not observe a close after the owned send was cancelled; \
         the connection driver outlived the dropped future"
    );
    assert!(
        !fixture.saw_retry().await,
        "a cancelled unlock request was retried"
    );

    fixture.finish().await;
}

/// A direct daemon that echoes the unlock key in its rejection cannot put it
/// into the error, and a failed owned request is not retried.
///
/// The status survives; the message and every source in the chain are the fixed
/// withheld text. This is the direct-daemon half of the echo-canary pair; the
/// fail-closed suite covers the unreachable-endpoint half.
#[tokio::test]
async fn unlock_swarm_withholds_a_direct_daemon_echo_without_a_retry() {
    // The encoded form is the point: a substitution that searched for the raw
    // key would leave this one in the error.
    let encoded = STANDARD.encode(KEY.as_bytes());
    let echoed = format!(r#"{{"message":"invalid unlock key {KEY} encoded {encoded}"}}"#);
    let fixture = RejectingFixture::start("500 Internal Server Error", &echoed);

    let error = fixture
        .client()
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("a 500 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message, WITHHELD,
        "the daemon's echo reached api_error().message"
    );

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!("POST {}/swarm/unlock HTTP/1.1", version_prefix()),
        "the error path must be the owned request"
    );
    assert_eq!(request.body_text(), format!(r#"{{"UnlockKey":"{KEY}"}}"#));
    assert!(
        !fixture.saw_retry(),
        "a failed owned unlock request was retried"
    );

    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "an unlock error rendering leaked the key: {rendered}"
        );
        assert!(
            !rendered.contains(&encoded),
            "an unlock error rendering leaked an encoded key: {rendered}"
        );
        assert!(
            !rendered.contains("invalid unlock key"),
            "an unlock error rendering preserved the daemon's echo: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }

    fixture.finish();
}

/// Renders an error and every source in its chain, with both `Display` and
/// `Debug`.
fn renderings(error: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    let mut source = error.source();
    while let Some(cause) = source {
        rendered.push(cause.to_string());
        rendered.push(format!("{cause:?}"));
        source = cause.source();
    }
    rendered
}

/// Recorded proxy requests: request head and body.
type RecordedProxyRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A loopback proxy that records each request and rejects it with `status` and
/// a body echoing the synthetic key.
struct EchoingProxy {
    address: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    recorded: RecordedProxyRequests,
    task: tokio::task::JoinHandle<()>,
}

impl EchoingProxy {
    async fn start(status: &'static str) -> Self {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the proxy fixture");
        let address = listener.local_addr().expect("the proxy address");
        let connections = Arc::new(AtomicUsize::new(0));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let connections = Arc::clone(&connections);
            let recorded = Arc::clone(&recorded);
            async move {
                loop {
                    let (mut stream, _) =
                        listener.accept().await.expect("accept the proxy request");
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (head, body) = read_async_request(&mut stream).await;
                    recorded
                        .lock()
                        .expect("the recorded proxy requests")
                        .push((head, body));
                    // A malicious proxy echoing the request payload is the case
                    // the unlock operation withholds response text for.
                    let body = format!(r#"{{"message":"proxy rejected unlock for key {KEY}"}}"#);
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
            task,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
}

/// Runs one proxied unlock against a proxy that echoes the key, and asserts the
/// error is withheld, not retried, and not sent directly to the target.
async fn assert_proxied_unlock_withheld(authenticated: bool, status: &'static str) {
    use tokio::net::TcpListener;

    let target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the target fixture");
    let target_address = target.local_addr().expect("the target address");
    let proxy = EchoingProxy::start(status).await;

    let policy = if authenticated {
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(
                proxy.endpoint(),
                "canary-proxy-user",
                "canary-proxy-password",
            )
            .expect("bounded synthetic proxy credentials"),
        )
    } else {
        ProxyPolicy::Http(ForwardProxy::new(proxy.endpoint()).expect("a loopback proxy URL"))
    };
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(format!("http://{target_address}")),
        policy,
    )
    .expect("build the proxied client");

    let error = client
        .unlock_swarm(SwarmUnlockOptions {
            key: KEY.to_owned(),
        })
        .await
        .expect_err("the proxy rejected the unlock");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(
        api.status_code,
        status
            .split_whitespace()
            .next()
            .expect("the fixture status")
            .parse::<u16>()
            .expect("a numeric fixture status")
    );
    assert_eq!(
        api.message, WITHHELD,
        "the proxy's echo reached api_error().message"
    );
    for rendered in renderings(&error) {
        assert!(
            !rendered.contains(KEY),
            "the proxy echoed the key into an error rendering: {rendered}"
        );
        assert!(
            !rendered.contains("proxy rejected unlock"),
            "the proxy's response text was not withheld: {rendered}"
        );
        assert!(
            rendered.contains("withheld"),
            "the withholding must be visible rather than an omission: {rendered}"
        );
    }

    {
        let requests = proxy.recorded.lock().expect("the recorded proxy requests");
        assert_eq!(requests.len(), 1, "the rejected unlock was retried");
        let (head, body) = &requests[0];
        assert!(
            head.starts_with(&format!(
                "POST http://{target_address}{}/swarm/unlock HTTP/1.1\r\n",
                version_prefix()
            )),
            "the proxied request line changed: {head}"
        );
        assert_eq!(
            std::str::from_utf8(body).expect("the unlock body is UTF-8"),
            format!(r#"{{"UnlockKey":"{KEY}"}}"#)
        );
    }

    // A retry would have opened a second proxy connection, and a direct
    // connection would have reached the target. Neither happened.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        proxy.connections.load(Ordering::SeqCst),
        1,
        "the rejected unlock was retried"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err(),
        "the proxied unlock reached the target directly"
    );

    proxy.task.abort();
}

/// An authenticated forward proxy that echoes the unlock key in its rejection
/// cannot put the key into the error, and the request is neither retried nor
/// sent directly to the target.
#[tokio::test]
async fn unlock_swarm_through_an_authenticated_proxy_withholds_an_echoed_key() {
    assert_proxied_unlock_withheld(true, "407 Proxy Authentication Required").await;
}

/// An unauthenticated forward proxy is the case the generic transport keeps
/// response text for. The unlock operation must withhold it anyway, because the
/// request body is the key.
#[tokio::test]
async fn unlock_swarm_through_an_unauthenticated_proxy_withholds_an_echoed_key() {
    assert_proxied_unlock_withheld(false, "500 Internal Server Error").await;
}

/// Reads a proxy request head and its `Content-Length` body.
async fn read_async_request(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("read the proxy request");
        assert_ne!(read, 0, "the proxy request ended before its headers");
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
        let read = stream.read(&mut chunk).await.expect("read the proxy body");
        assert_ne!(read, 0, "the proxy body ended before Content-Length");
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    (head, body)
}
