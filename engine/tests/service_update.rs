//! `DockerClient::update_service` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `update_service` must open
//! `POST /v1.NN/services/{id}/update` through the owned transport. Asserting
//! that against a request builder would only show what the builder would
//! produce if it were called; the routing decision is above it. A loopback HTTP
//! fixture is the only place the wire request and the routing are the same
//! observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the owned routing from `update_service` puts the call on the
//! fail-closed endpoint path, so the request line and body assertions below
//! fail. The generated client is deliberately not a fallback for this
//! operation.
//!
//! # What is deliberately asserted rather than assumed
//!
//! - The query is `version`, then `registryAuthFrom=spec`, then `rollback`
//!   when requested, which is the parameter order the generated client used.
//! - A registry credential is sent only through
//!   `update_service_with_credentials`, on the owned path in the Engine's
//!   URL-safe alphabet, and never rendered by `Debug`.
//! - A daemon rejection keeps its status and message, is returned once, and is
//!   never retried.
//! - A cancelled dispatch has an unknown outcome: the request was written, no
//!   answer was read, and no second request is sent.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ForwardProxy, ProxyPolicy,
    RegistryCredentials, ServicePlacement, ServiceRestartPolicy, ServiceSpec, ServiceUpdateOptions,
};
use tokio::sync::oneshot;

/// The service every request targets.
const SERVICE_ID: &str = "service0123456789abcdef";

/// A value that must never appear in a `Debug` rendering or a local error.
///
/// It is placed in the service environment, which is exactly where a service
/// secret lives (`docker service create --env`).
const ENV_CANARY: &str = "canary-service-env-e4b1f0c7-do-not-log-me";

/// A value that must never appear where the registry credential is not wanted.
const SECRET_CANARY: &str = "canary-registry-secret-57a2d9e1-do-not-log-me";

/// A value used only in a dotted key, independent of the environment canary.
const DOTTED_CANARY: &str = "canary-dotted-placement-2f8c1a-do-not-log-me";

/// The fixed message every service-update failure must carry.
const WITHHELD_UPDATE: &str = "response text withheld for a service update because the request may carry service environment or registry credentials";

/// A recorded request: the request line, headers, and body.
#[derive(Debug)]
struct Captured {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    /// The body as JSON.
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }

    /// One header value, matched case-insensitively.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every value for one header name, matched case-insensitively.
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

/// A one-request-at-a-time HTTP server that records each request and then waits
/// for the client to release the connection.
///
/// The server closes every response with `Connection: close` so the client
/// cannot reuse the connection for the next call. Waiting for the client to
/// disconnect is what makes `finish` a statement about the client having
/// completed, rather than about the fixture having written bytes.
struct Fixture {
    endpoint: String,
    requests: Receiver<Captured>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let mut stream = accept_tcp(&listener);
                let captured = read_request(&mut stream);
                let _ = request_tx.send(captured);
                stream
                    .write_all(&response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
                release(&mut stream);
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

    fn next(&self) -> Captured {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A listener that stays alive for the whole operation and records any
/// connection, so a refusal test cannot pass merely because the port was closed.
///
/// The watcher is stopped only after the operation and its assertions are
/// complete. Any accepted connection is answered so a broken client returns,
/// and is reported by [`finish`](Self::finish) rather than hidden.
struct NoDispatchFixture {
    endpoint: String,
    requests: Receiver<Captured>,
    stop: mpsc::Sender<()>,
    server: JoinHandle<()>,
}

impl NoDispatchFixture {
    fn start() -> Self {
        Self::start_with(Vec::new())
    }

    /// Serves the listed answers first, then watches for any further connection.
    ///
    /// The initial answers let a test inspect through the same fixture and then
    /// prove the refused write opened no second connection.
    fn start_with(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let (request_tx, requests) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let mut stream = accept_tcp(&listener);
                let captured = read_request(&mut stream);
                let _ = request_tx.send(captured);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
            }
            let mut stopping = false;
            let lifetime = Instant::now() + Duration::from_secs(30);
            loop {
                assert!(
                    Instant::now() < lifetime,
                    "the no-dispatch watcher lifetime expired"
                );
                if !stopping {
                    stopping = !matches!(stop_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let captured = read_request(&mut stream);
                        let _ = request_tx.send(captured);
                        let _ = stream.write_all(&ok_json("{}"));
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopping {
                            break;
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            requests,
            stop,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn finish(self) -> Vec<Captured> {
        let _ = self.stop.send(());
        self.server.join().expect("the fixture thread");
        self.requests.try_iter().collect()
    }
}

/// A server that rejects one request and then watches for a retry.
///
/// A second connection is the observable form of a retry after a failed owned
/// request. The fixture sends `Connection: close`, so a retry cannot reuse
/// the first connection and a new connection is the only way to retry. The watch
/// window is bounded: the assertion catches a retry made immediately after the
/// answer, which is how this client would retry, not a retry after an arbitrary
/// delay.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<Captured>,
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
            let mut stream = accept_tcp(&listener);
            let captured = read_request(&mut stream);
            let _ = request_tx.send(captured);
            stream
                .write_all(&response)
                .expect("write the fixture answer");
            stream.flush().expect("flush the fixture answer");
            release(&mut stream);

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
                        let _ = retry_stream.write_all(&ok_json("{}"));
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

    fn request(&self) -> Captured {
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

/// A server that reads one request, never answers it, and then watches for a
/// retry.
///
/// The client is expected to cancel the call after the fixture has received
/// the complete request. The fixture holds the answer until the client sends a
/// release signal after dropping the future, then closes the connection and
/// looks for a second one in the bounded window the rejection fixture uses.
struct HangingFixture {
    endpoint: String,
    first_request: Receiver<Captured>,
    release_tx: mpsc::Sender<()>,
    retry: Receiver<()>,
    server: JoinHandle<()>,
}

impl HangingFixture {
    /// Starts the fixture and returns the signal that the complete request has
    /// been read, so the caller cancels only after dispatch rather than racing
    /// the request's own scheduling.
    fn start() -> (Self, oneshot::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (received_tx, received_rx) = oneshot::channel();
        let server = thread::spawn(move || {
            let mut stream = accept_tcp(&listener);
            let captured = read_request(&mut stream);
            let _ = request_tx.send(captured);
            // The request is complete; only now is the caller allowed to cancel.
            let _ = received_tx.send(());
            // Hold the answer until the caller says the future has been
            // dropped. A fixed close timer can fire before that drop and turn a
            // scheduling delay into a false failure. The wait is bounded so a
            // broken test cannot leave the fixture blocked forever.
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the client never released the held response");
            let _ = stream.shutdown(Shutdown::Both);

            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request(&mut retry_stream);
                        let _ = retry_tx.send(());
                        let _ = retry_stream.write_all(&ok_json("{}"));
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        (
            Self {
                endpoint: format!("http://{address}"),
                first_request,
                release_tx: release,
                retry,
                server,
            },
            received_rx,
        )
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request(&self) -> Captured {
        self.first_request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn release(&self) {
        let _ = self.release_tx.send(());
    }

    fn saw_retry(&self) -> bool {
        match self.retry.recv_timeout(Duration::from_millis(800)) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// Reads the request head and, when `Content-Length` says so, the body.
fn read_request(stream: &mut TcpStream) -> Captured {
    // Bound every accepted connection: a peer that sends a partial request must
    // fail the fixture rather than block the watcher forever. An accepted
    // stream can inherit a nonblocking listener's mode.
    stream
        .set_nonblocking(false)
        .expect("make the fixture stream blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound the fixture read");
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            if request.len() >= header_end + 4 + content_length {
                break (header_end, content_length);
            }
        }
    };
    let head = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
    let mut lines = head.lines();
    let line = lines
        .next()
        .expect("the request has a request line")
        .to_owned();
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Captured {
        line,
        headers,
        body: request[header_end + 4..header_end + 4 + content_length].to_vec(),
    }
}

/// Accepts one request with a bounded wait, and restores blocking mode.
///
/// A fixture that waits forever for a request the client never sends turns a
/// test failure into a hung test run.
fn accept_tcp(listener: &TcpListener) -> TcpStream {
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make the accepted stream blocking");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "the fixture timed out waiting for a request"
                );
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("the fixture could not accept a request: {error}"),
        }
    }
}

/// Waits for the client to release the connection.
fn release(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// A `200` answer carrying `body`, and a header that stops connection reuse.
fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
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
fn version_prefix(major: usize, minor: usize) -> String {
    format!("/v{major}.{minor}")
}

/// The target an owned update for [`SERVICE_ID`] must use.
fn update_target(version: u64) -> String {
    format!(
        "{}/services/{SERVICE_ID}/update?version={version}&registryAuthFrom=spec",
        version_prefix(API_VERSION.major, API_VERSION.minor)
    )
}

/// A specification with a realistic nested task template and every kind of
/// member the two transports disagree about.
fn realistic_spec() -> ServiceSpec {
    ServiceSpec {
        name: Some("web".to_owned()),
        labels: Some(BTreeMap::from([(
            "com.example.stack".to_owned(),
            "web".to_owned(),
        )])),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {
                "Image": "registry.example/web:1.2",
                "Env": [format!("API_TOKEN={ENV_CANARY}")],
                "UnmodelledContainerMember": true
            },
            "Resources": {
                "Limits": {"NanoCPUs": 500_000_000, "UnmodelledLimitMember": 7}
            },
            "UnmodelledTaskMember": 1
        })),
        mode: Some(serde_json::json!({"Replicated": {"Replicas": 3}})),
        endpoint_spec: Some(serde_json::json!({
            "Mode": "vip",
            "Ports": [{
                "Protocol": "tcp",
                "TargetPort": 80,
                "PublishedPort": 8080,
                "PublishMode": "ingress",
                "Name": "http"
            }]
        })),
        networks: Some(serde_json::json!([{
            "Target": "net0123456789abcdef",
            "Aliases": ["web"]
        }])),
        update_config: Some(serde_json::json!({
            "Parallelism": 2,
            "FailureAction": "pause"
        })),
        rollback_config: Some(serde_json::json!({"Parallelism": 1})),
        placement: Some(ServicePlacement {
            constraints: vec!["node.labels.zone == east".to_owned()],
            preferences: vec!["spread=node.labels.zone".to_owned()],
            max_replicas: 2,
        }),
        restart_policy: Some(ServiceRestartPolicy {
            condition: "on-failure".to_owned(),
            delay: Some(5_000_000_000),
            max_attempts: Some(3),
            window: Some(20_000_000_000),
            failure_action: None,
        }),
        additional: BTreeMap::from([("UnmodelledSpecMember".to_owned(), serde_json::json!(true))]),
    }
}

/// The complete body [`realistic_spec`] must produce on the owned route.
fn expected_realistic_body() -> serde_json::Value {
    serde_json::json!({
        "Name": "web",
        "Labels": {"com.example.stack": "web"},
        "TaskTemplate": {
            "ContainerSpec": {
                "Image": "registry.example/web:1.2",
                "Env": [format!("API_TOKEN={ENV_CANARY}")],
                "UnmodelledContainerMember": true
            },
            "Resources": {
                "Limits": {"NanoCPUs": 500_000_000, "UnmodelledLimitMember": 7}
            },
            "UnmodelledTaskMember": 1,
            "Placement": {
                "Constraints": ["node.labels.zone == east"],
                "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}],
                "MaxReplicas": 2
            },
            "RestartPolicy": {
                "Condition": "on-failure",
                "Delay": 5_000_000_000_i64,
                "MaxAttempts": 3,
                "Window": 20_000_000_000_i64
            }
        },
        "Mode": {"Replicated": {"Replicas": 3}},
        "EndpointSpec": {
            "Mode": "vip",
            "Ports": [{
                "Protocol": "tcp",
                "TargetPort": 80,
                "PublishedPort": 8080,
                "PublishMode": "ingress",
                "Name": "http"
            }]
        },
        "Networks": [{"Target": "net0123456789abcdef", "Aliases": ["web"]}],
        "UpdateConfig": {"Parallelism": 2, "FailureAction": "pause"},
        "RollbackConfig": {"Parallelism": 1},
        "UnmodelledSpecMember": true
    })
}

/// The owned route sends the versioned target and the complete specification,
/// with typed placement and restart policy merged into one `TaskTemplate` and
/// the dotted placement member merged into that same object.
#[tokio::test]
async fn owned_update_sends_the_versioned_target_and_a_realistic_nested_body() {
    let fixture = Fixture::start(vec![ok_json(r#"{"Warnings":["image is not pinned"]}"#)]);
    let result = fixture
        .client()
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
        )
        .await
        .expect("the update was accepted");
    assert_eq!(result.warnings, ["image is not pinned"]);

    let update = fixture.next();
    assert_eq!(
        update.line,
        format!("POST {} HTTP/1.1", update_target(7)),
        "update_service did not use the owned route or reordered the query"
    );
    let body = update.json();
    assert_eq!(
        body,
        expected_realistic_body(),
        "the owned update body changed: {body}"
    );
    assert!(
        body.get("Placement").is_none() && body.get("RestartPolicy").is_none(),
        "a typed member was emitted at the specification root: {body}"
    );
    assert_eq!(
        update.header_values("x-registry-auth"),
        Vec::<&str>::new(),
        "update_service must not invent a registry credential"
    );

    fixture.finish();
}

/// A rollback appends the Engine's `previous` spelling after the generated
/// parameter order.
#[tokio::test]
async fn owned_update_sends_rollback_after_the_registry_auth_from_parameter() {
    let fixture = Fixture::start(vec![ok_json("{}")]);
    fixture
        .client()
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 11,
                spec: realistic_spec(),
                rollback: true,
            },
        )
        .await
        .expect("the rollback was accepted");

    assert_eq!(
        fixture.next().line,
        format!(
            "POST {}/services/{SERVICE_ID}/update?version=11&registryAuthFrom=spec&rollback=previous HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )
    );
    fixture.finish();
}

/// The owned request uses the configured version and percent-encodes the
/// reference into one path segment.
#[tokio::test]
async fn owned_update_uses_the_configured_version_and_escapes_the_reference() {
    let fixture = Fixture::start(vec![ok_json("{}")]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 43,
        },
    )
    .expect("a client at the configured version");

    client
        .update_service(
            "a/b",
            ServiceUpdateOptions {
                version: 3,
                spec: realistic_spec(),
                rollback: false,
            },
        )
        .await
        .expect("the update was accepted");

    assert_eq!(
        fixture.next().line,
        "POST /v1.43/services/a%2Fb/update?version=3&registryAuthFrom=spec HTTP/1.1",
        "the owned request did not use the configured version or the escaped reference"
    );
    fixture.finish();
}

/// An empty reference is refused before a connection is opened.
#[tokio::test]
async fn owned_update_refuses_an_empty_reference_without_connecting() {
    let fixture = NoDispatchFixture::start();
    let client = fixture.client();
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .update_service(
            "",
            ServiceUpdateOptions {
                version: 1,
                spec: ServiceSpec::default(),
                rollback: false,
            },
        )
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
    let sent = fixture.finish();
    assert!(
        sent.is_empty(),
        "an empty reference opened a connection: {sent:?}"
    );
}

/// The owned route carries the three registry credential forms: none, a
/// username and password, and an identity token.
#[tokio::test]
async fn owned_update_carries_each_registry_credential_variant() {
    let fixture = Fixture::start(vec![ok_json("{}"), ok_json("{}")]);
    let client = fixture.client();

    let password = "p?ss~word";
    client
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
            "registry.example",
            RegistryCredentials::new("probeuser", password),
        )
        .await
        .expect("the credentialed update was accepted");
    let first = fixture.next();
    assert_eq!(first.line, format!("POST {} HTTP/1.1", update_target(7)));
    let header = first
        .header("x-registry-auth")
        .expect("a credential is sent in X-Registry-Auth");
    assert_eq!(
        first.header_values("x-registry-auth").len(),
        1,
        "the credential header was sent more than once"
    );
    assert_eq!(
        decode_auth(header),
        serde_json::json!({
            "username": "probeuser",
            "password": password,
            "serveraddress": "registry.example"
        }),
        "the owned credential is the Engine's URL-safe single auth object"
    );

    let token = "probe~identity~token";
    client
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
            "registry.example",
            RegistryCredentials::from_identity_token(token),
        )
        .await
        .expect("the token-authenticated update was accepted");
    let second = fixture.next();
    assert_eq!(second.line, format!("POST {} HTTP/1.1", update_target(7)));
    assert_eq!(
        decode_auth(
            second
                .header("x-registry-auth")
                .expect("the token is sent in X-Registry-Auth")
        ),
        serde_json::json!({
            "username": "<token>",
            "password": token,
            "serveraddress": "registry.example",
            "identitytoken": token
        })
    );

    fixture.finish();
}

/// A credential that does not match its registry is refused before dispatch,
/// and no error rendering carries the secret.
#[tokio::test]
async fn owned_update_refuses_a_mismatched_credential_without_dispatching() {
    let fixture = NoDispatchFixture::start();
    let credentials = RegistryCredentials::new("probeuser", SECRET_CANARY)
        .with_server_address("elsewhere.example");
    let error = fixture
        .client()
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: ServiceSpec::default(),
                rollback: false,
            },
            "registry.example",
            credentials,
        )
        .await
        .expect_err("the credential belongs to another registry");
    assert_eq!(error.kind(), ErrorKind::Credentials);
    let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(item) = chain {
        for rendered in [format!("{item}"), format!("{item:?}")] {
            assert!(!rendered.contains(SECRET_CANARY), "leak: {rendered}");
            assert!(!rendered.contains("probeuser"), "leak: {rendered}");
        }
        chain = item.source();
    }
    let sent = fixture.finish();
    assert!(
        sent.is_empty(),
        "a credential that failed validation was sent: {sent:?}"
    );
}

/// The credentialed facade form refuses dotted keys before dispatch too.
#[tokio::test]
async fn credentialed_update_refuses_dotted_keys_without_dispatch() {
    let fixture = NoDispatchFixture::start();
    let mut spec = realistic_spec();
    spec.additional
        .insert("Labels.team".to_owned(), serde_json::json!("platform"));
    let error = fixture
        .client()
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec,
                rollback: false,
            },
            "registry.example",
            RegistryCredentials::new("probeuser", SECRET_CANARY),
        )
        .await
        .expect_err("the credentialed facade refuses dotted keys");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("dotted `additional` key"),
        "the refusal is not actionable: {error}"
    );
    let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(item) = chain {
        for rendered in [format!("{item}"), format!("{item:?}")] {
            assert!(!rendered.contains(SECRET_CANARY), "leak: {rendered}");
            assert!(!rendered.contains("probeuser"), "leak: {rendered}");
        }
        chain = item.source();
    }
    let sent = fixture.finish();
    assert!(
        sent.is_empty(),
        "a credentialed dotted refusal opened a connection: {sent:?}"
    );
}

/// Every daemon rejection keeps its status, replaces its text with fixed
/// content-free text, is returned once, and is never retried.
///
/// The echoed body carries the environment canary raw and URL-safe base64, and
/// the registry canary raw and URL-safe base64. A direct daemon can echo either
/// the request body or a header, and none of it may reach `Display`, `Debug`,
/// `api_error`, or the source chain.
#[tokio::test]
async fn owned_update_reports_each_rejection_without_echoing_and_does_not_retry() {
    let base64_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    let base64_secret = URL_SAFE.encode(SECRET_CANARY);
    for (status, code) in [
        ("400 Bad Request", 400),
        ("404 Not Found", 404),
        ("409 Conflict", 409),
        ("500 Internal Server Error", 500),
    ] {
        let echoed = format!(
            "daemon rejection {code}: {ENV_CANARY} {base64_env} {SECRET_CANARY} {base64_secret}"
        );
        let fixture = RejectingFixture::start(status, &format!(r#"{{"message":"{echoed}"}}"#));
        let error = fixture
            .client()
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: 7,
                    spec: realistic_spec(),
                    rollback: false,
                },
            )
            .await
            .expect_err("a rejection is an error");
        assert_eq!(error.kind(), ErrorKind::Docker);
        let api = error.api_error().expect("the daemon's own rejection");
        assert_eq!(api.status_code, code);
        assert_eq!(api.message, WITHHELD_UPDATE);
        assert_no_update_echo(
            &error,
            &[ENV_CANARY, SECRET_CANARY, &base64_env, &base64_secret],
        );
        assert_eq!(
            fixture.request().line,
            format!("POST {} HTTP/1.1", update_target(7)),
            "the error path must be the owned request"
        );
        assert!(!fixture.saw_retry(), "a rejected owned update was retried");
        fixture.finish();
    }
}

/// A daemon older than the configured version answers the versioned path with
/// its own rejection. That rejection is returned, not retried unversioned.
#[tokio::test]
async fn owned_update_returns_a_too_new_version_rejection_without_retrying() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.43";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));
    let error = fixture
        .client()
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
        )
        .await
        .expect_err("an unsupported version is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, WITHHELD_UPDATE);
    assert_no_update_echo(&error, &[message]);
    assert_eq!(
        fixture.request().line,
        format!("POST {} HTTP/1.1", update_target(7)),
        "the versioned request was not the one refused"
    );
    assert!(!fixture.saw_retry(), "a version rejection was retried");
    fixture.finish();
}

/// A success body that is malformed, wrongly typed, or carries a canary is a
/// content-free decode failure.
#[tokio::test]
async fn owned_update_decode_errors_do_not_echo_the_response() {
    for body in [
        "not JSON at all",
        r#"{"Warnings":5}"#,
        &format!(r#"{{"Warnings":"{ENV_CANARY}"}}"#),
    ] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: 7,
                    spec: ServiceSpec::default(),
                    rollback: false,
                },
            )
            .await
            .expect_err("the success body cannot be decoded");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(item) = chain {
            for rendered in [format!("{item}"), format!("{item:?}")] {
                assert!(!rendered.contains(ENV_CANARY), "leak: {rendered}");
                assert!(!rendered.contains("not JSON"), "leak: {rendered}");
                assert!(!rendered.contains('\n'), "newline: {rendered}");
            }
            chain = item.source();
        }
        fixture.next();
        fixture.finish();
    }
}

/// Local specification errors are fixed diagnostics that do not echo the
/// service environment or the untrusted key that caused them.
#[tokio::test]
async fn owned_update_local_errors_do_not_echo_the_specification() {
    let fixture = NoDispatchFixture::start();
    let mut spec = realistic_spec();
    // The environment canary is in the task template and is deliberately not
    // the same value as the attacker-controlled dotted key. The key itself
    // carries the canary and a newline, and has two dots so the shape refusal is
    // the one exercised.
    spec.additional.insert(
        format!("TaskTemplate.{DOTTED_CANARY}\ninjected.child"),
        serde_json::json!(true),
    );
    let options = ServiceUpdateOptions {
        version: 7,
        spec,
        rollback: false,
    };
    assert!(
        serde_json::to_string(&options.spec)
            .expect("the specification serializes")
            .contains(ENV_CANARY),
        "the env canary must be present in the serialized specification"
    );
    for rendered in [format!("{options:?}"), format!("{:?}", options.spec)] {
        assert!(!rendered.contains(ENV_CANARY), "env leak: {rendered}");
        assert!(!rendered.contains(DOTTED_CANARY), "key leak: {rendered}");
    }
    let error = fixture
        .client()
        .update_service(SERVICE_ID, options)
        .await
        .expect_err("the malformed dotted key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("dotted `additional` key"),
        "the refusal must be actionable: {error}"
    );
    let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(item) = chain {
        for rendered in [format!("{item}"), format!("{item:?}")] {
            assert!(!rendered.contains(ENV_CANARY), "env leak: {rendered}");
            assert!(!rendered.contains(DOTTED_CANARY), "key leak: {rendered}");
            assert!(!rendered.contains('\n'), "newline: {rendered}");
        }
        chain = item.source();
    }
    let sent = fixture.finish();
    assert!(
        sent.is_empty(),
        "a refused specification was sent: {sent:?}"
    );
}

/// Every inspected dotted literal is refused on facade write, including the
/// names the raw writer would treat as retention conventions.
///
/// A `ServiceSpec` carries no provenance for an `additional` key. The facade
/// therefore cannot tell `Placement.Platforms` the convention from
/// `Placement.Platforms` a literal member the daemon sent, so it refuses every
/// dotted key before dispatch. Raw callers that choose the convention call
/// `raw::service_update` explicitly.
#[tokio::test]
async fn inspect_then_update_refuses_every_dotted_literal_without_dispatch() {
    for (key, value) in [
        (
            "Placement.Platforms",
            serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
        ),
        (
            "TaskTemplate.Placement",
            serde_json::json!({"Constraints": ["node.role == worker"]}),
        ),
        ("Vendor.Feature", serde_json::json!({"Enabled": true})),
        (
            "Vendor.Future.Feature",
            serde_json::json!({"Enabled": true}),
        ),
    ] {
        let literal = serde_json::to_string(&value).expect("the literal is JSON");
        let body = format!(
            r#"{{"ID":"{SERVICE_ID}","Version":{{"Index":7}},"Spec":{{"Name":"web","{key}":{literal}}}}}"#
        );
        let fixture = NoDispatchFixture::start_with(vec![ok_json(&body)]);
        let client = fixture.client();
        let service = client
            .inspect_service(SERVICE_ID)
            .await
            .expect("the literal dotted member decodes");
        let spec = service.spec.expect("the daemon sent a spec");
        assert_eq!(
            spec.additional[key], value,
            "the inspected literal was rewritten: {:?}",
            spec.additional
        );

        let error = client
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: 7,
                    spec,
                    rollback: false,
                },
            )
            .await
            .expect_err("a dotted literal must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(
            message.contains("dotted `additional` key"),
            "{key}: {message}"
        );
        assert!(
            message.contains("literal member name")
                && message.contains("first-dot sub-object convention")
                && message.contains("any parent")
                && message.contains("does not preserve a literal top-level key")
                && message.contains("no lossless facade write"),
            "{key}: the refusal must distinguish literal from convention: {message}"
        );
        assert!(
            !message.contains("put the value in `task_template`"),
            "{key}: the refusal must not give lossy advice: {message}"
        );
        assert!(!message.contains(key), "{key}: {message}");
        let sent = fixture.finish();
        assert_eq!(sent.len(), 1, "{key}: the write opened a connection");
        assert!(
            sent[0].line.contains("/services/"),
            "{key}: the recorded request was not the inspect: {}",
            sent[0].line
        );
    }
}

/// A non-dotted top-level `Placement` or `RestartPolicy` is refused even when
/// no typed field competes, and the refusal dispatches nothing.
///
/// The raw writer treats these two root spellings as outside the shape an
/// inspect produces; the Engine reads both inside `TaskTemplate`. Its fixed
/// message is the existing competing-representation text, so this test pins the
/// refusal and the absence of a dispatch, not a promise about that wording.
#[tokio::test]
async fn owned_update_refuses_a_root_placement_or_restart_policy_without_dispatch() {
    for (key, value) in [
        (
            "Placement",
            serde_json::json!({"Constraints": ["node.role == worker"]}),
        ),
        (
            "RestartPolicy",
            serde_json::json!({"Condition": "on-failure"}),
        ),
    ] {
        let fixture = NoDispatchFixture::start();
        let client = fixture.client();
        let spec = ServiceSpec {
            name: Some("web".to_owned()),
            additional: BTreeMap::from([(key.to_owned(), value)]),
            ..ServiceSpec::default()
        };

        let error = client
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: 7,
                    spec,
                    rollback: false,
                },
            )
            .await
            .expect_err("a root placement/restart policy must be refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key}: {error}");
        let message = error.to_string();
        assert!(
            message.contains("TaskTemplate"),
            "{key}: the refusal must name the working representation: {message}"
        );
        assert!(
            !message.contains("node.role == worker") && !message.contains("on-failure"),
            "{key}: the refusal echoed the value: {message}"
        );

        let sent = fixture.finish();
        assert!(
            sent.is_empty(),
            "{key}: the refused update dispatched a request: {sent:?}"
        );
    }
}

/// A cancelled dispatch is an unknown outcome, and the client does not retry./// A cancelled dispatch is an unknown outcome, and the client does not retry.
///
/// The fixture signals only that it read the complete request; it observes
/// neither the peer's close nor when the daemon applies anything. The future is
/// dropped after that signal. The daemon may have applied the update, may still
/// be applying it, or may never have received it. The no-retry check is bounded
/// to the fixture's short watch window and sends `Connection: close`, so a
/// retry could only be a new connection.
#[tokio::test]
async fn owned_update_cancellation_is_unknown_and_not_retried() {
    let (fixture, received) = HangingFixture::start();
    let client = fixture.client();
    {
        let update = client.update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
        );
        tokio::pin!(update);
        tokio::select! {
            result = &mut update => {
                panic!("the fixture did not hold the answer: {result:?}");
            }
            received = received => {
                received.expect("the fixture stopped before reading the request");
            }
        }
        // The pinned future is dropped here, after the server has read the
        // complete request. That is the cancellation under test.
    }

    fixture.release();
    assert_eq!(
        fixture.request().line,
        format!("POST {} HTTP/1.1", update_target(7)),
        "the cancelled call did not dispatch the owned request once"
    );
    assert!(!fixture.saw_retry(), "a cancelled owned update was retried");
    fixture.finish();
}

/// On an authenticated forward-proxy route the peer echoes the actual
/// `X-Registry-Auth` header it received. The error must not carry that header,
/// the secret it encodes, or the service environment, while preserving status.
#[tokio::test]
async fn owned_update_withholds_the_peered_registry_auth_header_on_an_authenticated_proxy() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind the unused target");
    let target_address = target.local_addr().expect("the target address");
    let (proxy_address, first_request, retry, server) =
        credential_echo_proxy(ENV_CANARY, "proxy-user", "proxy-password");

    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(format!("http://{target_address}")),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(
                format!("http://{proxy_address}"),
                "proxy-user",
                "proxy-password",
            )
            .expect("the proxy URL"),
        ),
    )
    .expect("the proxied client");

    let error = client
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
            "registry.example",
            RegistryCredentials::new("probeuser", SECRET_CANARY),
        )
        .await
        .expect_err("a 407 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 407);
    assert_eq!(api.message, WITHHELD_UPDATE);
    let request = first_request
        .recv_timeout(Duration::from_secs(10))
        .expect("the proxy recorded no request");
    let auth = request
        .header("x-registry-auth")
        .expect("the credentialed update sent its header")
        .to_owned();
    assert!(
        !auth.is_empty(),
        "the echoed header must be the one the client sent"
    );
    let base64_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    assert_no_update_echo(
        &error,
        &[
            ENV_CANARY,
            SECRET_CANARY,
            &base64_env,
            &auth,
            "probeuser",
            "proxy-user",
            "proxy-password",
        ],
    );
    assert_eq!(
        request.line,
        format!("POST http://{target_address}{} HTTP/1.1", update_target(7)),
        "the proxied request must use absolute form with the daemon authority"
    );
    assert!(
        retry.recv_timeout(Duration::from_millis(500)).is_err(),
        "a withheld proxy failure was retried"
    );
    server.join().expect("the proxy thread");
}

/// A proxy that echoes the actual `X-Registry-Auth` header it received.
fn credential_echo_proxy(
    env_canary: &str,
    proxy_user: &str,
    proxy_password: &str,
) -> (String, Receiver<Captured>, Receiver<()>, JoinHandle<()>) {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let proxy_address = proxy_listener.local_addr().expect("the proxy address");
    let (request_tx, first_request) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();
    let env_canary = env_canary.to_owned();
    let proxy_user = proxy_user.to_owned();
    let proxy_password = proxy_password.to_owned();
    let server = thread::spawn(move || {
        let mut stream = accept_tcp(&proxy_listener);
        let captured = read_request(&mut stream);
        let auth = captured
            .header("x-registry-auth")
            .expect("the proxy received a registry credential")
            .to_owned();
        let body = format!(
            r#"{{"message":"{auth} API_TOKEN={env_canary} {proxy_user}:{proxy_password}"}}"#
        );
        let response = rejected("407 Proxy Authentication Required", &body);
        let _ = request_tx.send(captured);
        stream.write_all(&response).expect("write the proxy answer");
        stream.flush().expect("flush the proxy answer");
        release(&mut stream);

        proxy_listener
            .set_nonblocking(true)
            .expect("make the proxy listener nonblocking");
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            match proxy_listener.accept() {
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
    });
    (proxy_address.to_string(), first_request, retry, server)
}

/// An unauthenticated proxy has no configured credential to echo, but the/// An unauthenticated proxy has no configured credential to echo, but the
/// request still carries the service environment, so its failure text is
/// withheld just the same.
#[tokio::test]
async fn owned_update_withholds_error_text_on_an_unauthenticated_proxy() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind the unused target");
    let target_address = target.local_addr().expect("the target address");
    let base64_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    let base64_secret = URL_SAFE.encode(SECRET_CANARY);
    let body =
        format!(r#"{{"message":"{ENV_CANARY} {SECRET_CANARY} {base64_env} {base64_secret}"}}"#);
    let (proxy_address, first_request, retry, server) = echo_proxy("502 Bad Gateway", &body);

    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(format!("http://{target_address}")),
        ProxyPolicy::Http(
            ForwardProxy::new(format!("http://{proxy_address}")).expect("the proxy URL"),
        ),
    )
    .expect("the proxied client");

    let error = client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
        )
        .await
        .expect_err("a 502 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 502);
    assert_eq!(api.message, WITHHELD_UPDATE);
    assert_no_update_echo(
        &error,
        &[ENV_CANARY, SECRET_CANARY, &base64_env, &base64_secret],
    );
    let request = first_request
        .recv_timeout(Duration::from_secs(10))
        .expect("the proxy recorded no request");
    assert_eq!(
        request.line,
        format!("POST http://{target_address}{} HTTP/1.1", update_target(7)),
        "the proxied request must use absolute form with the daemon authority"
    );
    assert!(
        retry.recv_timeout(Duration::from_millis(500)).is_err(),
        "a withheld proxy failure was retried"
    );
    server.join().expect("the proxy thread");
}

/// Starts a loopback proxy that answers one request with `status` and `body`,
/// then watches for a retry.
fn echo_proxy(
    status: &'static str,
    body: &str,
) -> (String, Receiver<Captured>, Receiver<()>, JoinHandle<()>) {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let proxy_address = proxy_listener.local_addr().expect("the proxy address");
    let (request_tx, first_request) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();
    let response = rejected(status, body);
    let server = thread::spawn(move || {
        let mut stream = accept_tcp(&proxy_listener);
        let captured = read_request(&mut stream);
        let _ = request_tx.send(captured);
        stream.write_all(&response).expect("write the proxy answer");
        stream.flush().expect("flush the proxy answer");
        release(&mut stream);

        proxy_listener
            .set_nonblocking(true)
            .expect("make the proxy listener nonblocking");
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            match proxy_listener.accept() {
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
    });
    (proxy_address.to_string(), first_request, retry, server)
}

/// Asserts no rendering of an error carries a withheld value.
fn assert_no_update_echo(error: &neotales_docker::Error, needles: &[&str]) {
    let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(item) = chain {
        for rendered in [format!("{item}"), format!("{item:?}")] {
            for needle in needles {
                assert!(
                    !rendered.contains(needle),
                    "a withheld value reached an error rendering: {rendered}"
                );
            }
        }
        chain = item.source();
    }
}

/// A proxy that answers 409 is a real 409, not a direct daemon rejection and
/// not a 407. The status is preserved and the text is still withheld.
#[tokio::test]
async fn owned_update_withholds_a_proxied_409_conflict() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind the unused target");
    let target_address = target.local_addr().expect("the target address");
    let base64_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    let body = format!(
        r#"{{"message":"update out of sequence {ENV_CANARY} {SECRET_CANARY} {base64_env}"}}"#
    );
    let (proxy_address, first_request, retry, server) = echo_proxy("409 Conflict", &body);

    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http(format!("http://{target_address}")),
        ProxyPolicy::Http(
            ForwardProxy::new(format!("http://{proxy_address}")).expect("the proxy URL"),
        ),
    )
    .expect("the proxied client");

    let error = client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: realistic_spec(),
                rollback: false,
            },
        )
        .await
        .expect_err("a proxied 409 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 409);
    assert_eq!(api.message, WITHHELD_UPDATE);
    assert_no_update_echo(&error, &[ENV_CANARY, SECRET_CANARY, &base64_env]);
    let request = first_request
        .recv_timeout(Duration::from_secs(10))
        .expect("the proxy recorded no request");
    assert_eq!(
        request.line,
        format!("POST http://{target_address}{} HTTP/1.1", update_target(7)),
        "the proxied request must use absolute form with the daemon authority"
    );
    assert!(
        retry.recv_timeout(Duration::from_millis(500)).is_err(),
        "a withheld proxy conflict was retried"
    );
    server.join().expect("the proxy thread");
}

/// Decodes an `X-Registry-Auth` value with the alphabet the Engine uses.
fn decode_auth(header: &str) -> serde_json::Value {
    let decoded = URL_SAFE
        .decode(header)
        .expect("the Engine's URL-safe alphabet");
    serde_json::from_slice(&decoded).expect("the header carries JSON")
}
