//! `DockerClient::update_node` and `DockerClient::remove_node` on the
//! repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are *transport* claims: both writes must open
//! `POST /v1.NN/nodes/{id}/update?version=…` and
//! `DELETE /v1.NN/nodes/{id}?force=…` through the owned transport when it can
//! reach the endpoint, rather than the unversioned generated paths. Asserting
//! that against a request builder would only show what the builder would produce
//! if it were called; the routing decision is above it. A loopback HTTP fixture
//! is the one place the request on the wire and the routing are the same
//! observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from either write
//! puts the generated client back on the wire. The request line then loses the
//! version prefix and the percent-encoding, the generated update loses
//! `NodeSpec::additional` or refuses the whole call, and `force=false` stops
//! being spelled at all. The bodies and request lines are compared whole.
//!
//! The rejection tests pin that a daemon rejection keeps its status and message
//! in `Error::api_error()`, and that a failed owned request is returned rather
//! than retried over the generated client. The cancellation tests pin that
//! abandoning the future releases the connection and is not a retry; the daemon
//! may still have processed the write, which is the uncertainty each method's
//! documentation states.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, NodeRemoveOptions, NodeSpec,
    NodeUpdateOptions,
};

const NODE_ID: &str = "node0123456789abcdef";
const VERSION: u64 = 4;
const WITHHELD_NODE_MUTATION: &str =
    "response text withheld for a Swarm node mutation because a peer can echo node metadata";

#[test]
fn public_deadline_predicate_does_not_trust_transport_text() {
    let error = neotales_docker::Error::transport("timed out");
    assert!(!error.is_transport_deadline());
}

/// Renders an error through `Display`, `Debug`, and every source.
fn renderings(error: &neotales_docker::Error) -> Vec<String> {
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

/// Asserts a node mutation failure preserves its status and withholds all peer
/// text and metadata from every rendering.
fn assert_withheld_node_mutation(error: &neotales_docker::Error, status: u16, canaries: &[&str]) {
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error
        .api_error()
        .expect("the rejection status is preserved");
    assert_eq!(api.status_code, status);
    assert_eq!(api.message, WITHHELD_NODE_MUTATION);
    for rendered in renderings(error) {
        for canary in canaries {
            assert!(
                !rendered.contains(canary),
                "a node mutation error echoed {canary:?}: {rendered}"
            );
        }
        assert!(
            !rendered.contains("out of sequence") && !rendered.contains("participating"),
            "a node mutation error echoed peer text: {rendered}"
        );
    }
}

/// A request the fixture recorded: the request line and the body that followed.
struct Captured {
    line: String,
    body: Vec<u8>,
}

impl Captured {
    /// The body parsed as JSON, so the assertion is about members rather than
    /// the order they were serialized in.
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }
}

/// A one-request-at-a-time HTTP server that records each request and then waits
/// for the client to release the connection.
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
                let (mut stream, _) = listener.accept().expect("accept the request");
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

/// A server that rejects one request and then watches for a retry.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<String>,
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
            let head = read_request(&mut stream).line;
            let _ = request_tx.send(head);
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

    fn request_line(&self) -> String {
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

/// A fixture that never answers, so the client's request stays pending.
///
/// It reports the request, whether the connection was released, and whether a
/// second connection arrived. A retry is observable as that second connection,
/// because a client that fell back would open it immediately after abandoning
/// the first.
struct UnansweredFixture {
    endpoint: String,
    request: tokio::sync::oneshot::Receiver<String>,
    released: tokio::sync::oneshot::Receiver<bool>,
    retry: tokio::sync::oneshot::Receiver<()>,
    server: JoinHandle<()>,
}

impl UnansweredFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = tokio::sync::oneshot::channel();
        let (released_tx, released) = tokio::sync::oneshot::channel();
        let (retry_tx, retry) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let head = read_request(&mut stream).line;
            let _ = request_tx.send(head);

            // The daemon never answers. The only thing that ends this read is
            // the client releasing the connection.
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set the fixture read timeout");
            let mut buffer = [0_u8; 64];
            let released = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break true,
                    Ok(_) => {}
                    // A timeout is the only outcome that means the client kept
                    // the connection open. A reset is still the connection going
                    // away, which is what abandoning the request promises.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break false;
                    }
                    Err(_) => break true,
                }
            };
            let _ = released_tx.send(released);

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
            request,
            released,
            retry,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }
}

/// Reads the request head and any `Content-Length` body.
fn read_request(stream: &mut TcpStream) -> Captured {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or_default();
    let body_start = header_end + 4;
    while request.len() < body_start + content_length {
        let read = stream.read(&mut chunk).expect("read the request body");
        assert_ne!(read, 0, "the request body ended early");
        request.extend_from_slice(&chunk[..read]);
    }
    Captured {
        line: head
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned(),
        body: request[body_start..body_start + content_length].to_vec(),
    }
}

/// Writes an answer carrying `body`, then waits for the client to release the
/// connection, so the next `accept` is the next operation rather than a retry.
fn release(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn ok_empty() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
}

fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// A specification carrying every modeled member and two unmodelled ones.
fn full_spec() -> NodeSpec {
    NodeSpec {
        name: Some("manager-one".to_owned()),
        labels: Some(BTreeMap::from([(
            "org.example.node".to_owned(),
            "fixture".to_owned(),
        )])),
        role: Some("overlord".to_owned()),
        availability: Some("someday".to_owned()),
        additional: BTreeMap::from([
            (
                "UnmodelledSpecMember".to_owned(),
                serde_json::json!({"Nested": true}),
            ),
            (
                "FutureSpecMember".to_owned(),
                serde_json::json!(["value", 7]),
            ),
        ]),
    }
}

/// The owned update sends the configured version, the explicit expected
/// version, and the whole specification member for member.
#[tokio::test]
async fn update_node_sends_the_versioned_request_and_the_complete_body() {
    let fixture = Fixture::start(vec![ok_empty()]);
    fixture
        .client()
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION,
                spec: full_spec(),
            },
        )
        .await
        .expect("a 200 update is not an error");

    let update = fixture.next();
    assert_eq!(
        update.line,
        format!(
            "POST {}/nodes/{NODE_ID}/update?version={VERSION} HTTP/1.1",
            version_prefix()
        ),
        "update_node fell back to the unversioned generated path"
    );
    assert_eq!(
        update.json(),
        serde_json::json!({
            "Name": "manager-one",
            "Labels": {"org.example.node": "fixture"},
            "Role": "overlord",
            "Availability": "someday",
            "UnmodelledSpecMember": {"Nested": true},
            "FutureSpecMember": ["value", 7]
        }),
        "the owned update did not send the specification member for member"
    );

    fixture.finish();
}

/// The owned update sends the API version the client was configured with and
/// percent-encodes the reference into one path segment.
#[tokio::test]
async fn update_node_sends_the_configured_version_and_encodes_the_reference() {
    let fixture = Fixture::start(vec![ok_empty()]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .update_node(
            "node id/with?slash",
            NodeUpdateOptions {
                version: VERSION,
                spec: NodeSpec {
                    name: Some("manager-one".to_owned()),
                    ..NodeSpec::default()
                },
            },
        )
        .await
        .expect("a 200 update is not an error");

    let update = fixture.next();
    assert_eq!(
        update.line,
        format!("POST /v1.47/nodes/node%20id%2Fwith%3Fslash/update?version={VERSION} HTTP/1.1"),
        "the owned path did not use the configured version or one encoded segment"
    );
    assert_eq!(update.json(), serde_json::json!({"Name": "manager-one"}));

    fixture.finish();
}

/// The owned path refuses an empty reference before dispatch.
#[tokio::test]
async fn update_node_rejects_an_empty_reference_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .update_node(
            "",
            NodeUpdateOptions {
                version: VERSION,
                spec: NodeSpec::default(),
            },
        )
        .await
        .expect_err("an empty reference is a caller mistake");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the empty reference: {error}"
    );
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("an empty reference reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// A reserved key in `additional` is refused before dispatch on both the
/// typed-absent and the conflicting-typed spelling.
#[tokio::test]
async fn update_node_rejects_reserved_additional_keys_before_dispatch() {
    const CANARY: &str = "canary-reserved-node-key-9a4f";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    for reserved in ["Name", "Labels", "Role", "Availability"] {
        for key in [
            reserved.to_ascii_lowercase(),
            reserved.to_ascii_uppercase(),
            format!(
                "{}{}",
                reserved[..1].to_ascii_lowercase(),
                reserved[1..].to_ascii_uppercase()
            ),
        ] {
            for typed in [false, true] {
                let spec = NodeSpec {
                    name: typed.then(|| "typed-name".to_owned()),
                    labels: typed
                        .then(|| BTreeMap::from([("typed".to_owned(), "label".to_owned())])),
                    role: typed.then(|| "typed-role".to_owned()),
                    availability: typed.then(|| "typed-availability".to_owned()),
                    additional: BTreeMap::from([(key.clone(), serde_json::json!(CANARY))]),
                };
                let error = client
                    .update_node(
                        NODE_ID,
                        NodeUpdateOptions {
                            version: VERSION,
                            spec,
                        },
                    )
                    .await
                    .expect_err("a reserved additional key is refused");
                assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key} typed={typed}");
                assert!(
                    error.to_string().contains("`additional` map cannot carry"),
                    "{key} typed={typed}: the refusal did not name the reserved map: {error}"
                );
                for rendered in renderings(&error) {
                    assert!(
                        !rendered.contains(CANARY),
                        "{key} typed={typed}: the refusal echoed a caller value: {rendered}"
                    );
                }
            }
        }
    }

    let escaped_key: String = serde_json::from_str(r#""Label\u017f""#).unwrap();
    let spec = NodeSpec {
        additional: BTreeMap::from([(escaped_key, serde_json::json!(CANARY))]),
        ..NodeSpec::default()
    };
    let error = client
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION,
                spec,
            },
        )
        .await
        .expect_err("a Unicode-folding key decoded from JSON is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(renderings(&error).iter().all(|text| !text.contains(CANARY)));

    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("a reserved additional key reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// `101` and `304` are non-2xx answers, not success. Both writes preserve the
/// observed status and withhold the answer.
#[tokio::test]
async fn update_and_remove_reject_101_and_304() {
    for (status, code) in [("101 Switching Protocols", 101), ("304 Not Modified", 304)] {
        for operation in ["update", "remove"] {
            let fixture = Fixture::start(vec![rejected(status, "")]);
            let client = fixture.client();
            let error = if operation == "update" {
                client
                    .update_node(
                        NODE_ID,
                        NodeUpdateOptions {
                            version: VERSION,
                            spec: NodeSpec::default(),
                        },
                    )
                    .await
                    .expect_err("a non-2xx status is a failure")
            } else {
                client
                    .remove_node(NODE_ID, NodeRemoveOptions { force: true })
                    .await
                    .expect_err("a non-2xx status is a failure")
            };
            assert_withheld_node_mutation(&error, code, &[]);
            fixture.finish();
        }
    }
}

/// A stale version keeps its `409 Conflict` status, but the daemon's text can
/// echo node metadata, so it is withheld and not retried.
#[tokio::test]
async fn update_node_reports_a_version_conflict_and_withholds_peer_text() {
    const CANARY: &str = "canary-node-metadata-7f3a";
    let body = format!(
        r#"{{"message":"update out of sequence for node {CANARY} Name manager-one Labels org.example.node=fixture"}}"#
    );
    let fixture = RejectingFixture::start("409 Conflict", &body);

    let error = fixture
        .client()
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION,
                spec: NodeSpec::default(),
            },
        )
        .await
        .expect_err("a 409 is an error");

    assert_withheld_node_mutation(&error, 409, &[CANARY]);
    assert_eq!(
        fixture.request_line(),
        format!(
            "POST {}/nodes/{NODE_ID}/update?version={VERSION} HTTP/1.1",
            version_prefix()
        ),
        "the conflict path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned update request was retried through the generated client"
    );

    fixture.finish();
}

/// An older daemon's "client version too new" rejection is not a reason to fall
/// back, and its text is withheld like any other peer text.
#[tokio::test]
async fn update_node_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    const CANARY: &str = "canary-node-old-daemon-1c9e";
    let body = format!(
        r#"{{"message":"client version 1.55 is too new. Maximum supported API version is 1.41 {CANARY}"}}"#
    );
    let fixture = RejectingFixture::start("400 Bad Request", &body);

    let error = fixture
        .client()
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION,
                spec: NodeSpec::default(),
            },
        )
        .await
        .expect_err("a 400 is an error");

    assert_withheld_node_mutation(&error, 400, &[CANARY]);
    assert!(
        !fixture.saw_retry(),
        "an old-daemon rejection was retried through the generated client"
    );

    fixture.finish();
}

/// Dropping the update future releases the connection and does not retry; the
/// daemon may still have applied the update.
#[tokio::test]
async fn update_node_cancellation_releases_the_connection_and_does_not_retry() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();

    let update = client.update_node(
        NODE_ID,
        NodeUpdateOptions {
            version: VERSION,
            spec: NodeSpec::default(),
        },
    );
    let timeout = tokio::time::timeout(Duration::from_millis(100), update).await;
    assert!(timeout.is_err(), "the fixture was expected to keep waiting");
    drop(timeout);

    assert_eq!(
        fixture
            .request
            .await
            .expect("the fixture recorded the request"),
        format!(
            "POST {}/nodes/{NODE_ID}/update?version={VERSION} HTTP/1.1",
            version_prefix()
        )
    );
    assert!(
        fixture
            .released
            .await
            .expect("the fixture reported whether the connection was released"),
        "dropping the future kept the connection open"
    );
    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "a cancelled update was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}

/// `force=true` is sent as a versioned request with the parameter spelled.
#[tokio::test]
async fn remove_node_sends_a_versioned_force_true_request() {
    let fixture = Fixture::start(vec![ok_empty()]);
    fixture
        .client()
        .remove_node(NODE_ID, NodeRemoveOptions { force: true })
        .await
        .expect("a 200 removal is not an error");

    assert_eq!(
        fixture.next().line,
        format!(
            "DELETE {}/nodes/{NODE_ID}?force=true HTTP/1.1",
            version_prefix()
        ),
        "remove_node fell back to the unversioned generated path, or lost force=true"
    );

    fixture.finish();
}

/// `force=false` is spelled rather than omitted, which is the difference a
/// recorded request can state and the generated path cannot.
#[tokio::test]
async fn remove_node_spells_force_false_on_the_owned_path() {
    let fixture = Fixture::start(vec![ok_empty()]);
    fixture
        .client()
        .remove_node(NODE_ID, NodeRemoveOptions { force: false })
        .await
        .expect("a 200 removal is not an error");

    assert_eq!(
        fixture.next().line,
        format!(
            "DELETE {}/nodes/{NODE_ID}?force=false HTTP/1.1",
            version_prefix()
        ),
        "remove_node fell back to the unversioned generated path, or omitted force=false"
    );

    fixture.finish();
}

/// The owned removal uses the configured version and encodes the reference into
/// exactly one path segment.
#[tokio::test]
async fn remove_node_sends_the_configured_version_and_encodes_the_reference() {
    let fixture = Fixture::start(vec![ok_empty()]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .remove_node("node id/with?slash", NodeRemoveOptions { force: false })
        .await
        .expect("a 200 removal is not an error");

    assert_eq!(
        fixture.next().line,
        "DELETE /v1.47/nodes/node%20id%2Fwith%3Fslash?force=false HTTP/1.1",
        "the owned path did not use the configured version or one encoded segment"
    );

    fixture.finish();
}

/// A manager removed without `force` is refused, and the refusal keeps its
/// status while withholding the node metadata a peer could echo.
#[tokio::test]
async fn remove_node_reports_a_manager_rejection_and_withholds_peer_text() {
    const CANARY: &str = "canary-node-manager-4d7b";
    let body = format!(
        r#"{{"message":"node {CANARY} is a manager and cannot be removed without force; Labels org.example.node=fixture"}}"#
    );
    let fixture = RejectingFixture::start("400 Bad Request", &body);

    let error = fixture
        .client()
        .remove_node(NODE_ID, NodeRemoveOptions { force: false })
        .await
        .expect_err("a 400 is an error");

    assert_withheld_node_mutation(&error, 400, &[CANARY]);
    assert_eq!(
        fixture.request_line(),
        format!(
            "DELETE {}/nodes/{NODE_ID}?force=false HTTP/1.1",
            version_prefix()
        ),
        "the rejection path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned removal request was retried through the generated client"
    );

    fixture.finish();
}

/// The owned path refuses an empty reference before dispatch.
#[tokio::test]
async fn remove_node_rejects_an_empty_reference_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .remove_node("", NodeRemoveOptions { force: false })
        .await
        .expect_err("an empty reference is a caller mistake");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the empty reference: {error}"
    );
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("an empty reference reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// Dropping the removal future releases the connection and does not retry; the
/// daemon may still have removed the node.
#[tokio::test]
async fn remove_node_cancellation_releases_the_connection_and_does_not_retry() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();

    let remove = client.remove_node(NODE_ID, NodeRemoveOptions { force: true });
    let timeout = tokio::time::timeout(Duration::from_millis(100), remove).await;
    assert!(timeout.is_err(), "the fixture was expected to keep waiting");
    drop(timeout);

    assert_eq!(
        fixture
            .request
            .await
            .expect("the fixture recorded the request"),
        format!(
            "DELETE {}/nodes/{NODE_ID}?force=true HTTP/1.1",
            version_prefix()
        )
    );
    assert!(
        fixture
            .released
            .await
            .expect("the fixture reported whether the connection was released"),
        "dropping the future kept the connection open"
    );
    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "a cancelled removal was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
