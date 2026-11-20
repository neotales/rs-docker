//! `DockerClient::list_nodes` and `DockerClient::inspect_node` on the
//! repository-owned transport.
//!
//! # Why a loopback fixture
//!
//! The claim is a transport claim: both reads must open the versioned
//! `/v1.NN/nodes` paths through the owned transport when it can reach the
//! endpoint, rather than the unversioned paths the generated client sends.
//! Asserting that against a request builder would only show what the builder
//! would produce if called; the routing decision is above it. A loopback HTTP
//! fixture is the one place the request on the wire and the routing are the same
//! observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from either read puts
//! the generated client back on the wire. The request line then loses the
//! version prefix and the percent-encoding, the unmodelled members disappear
//! into Bollard's 1.53 models, and the owned decode error class changes. The
//! assertions fail with it.
//!
//! # The round trip
//!
//! `ndocker node update`, `promote`, and `demote` read a node and write the
//! specification back through `DockerClient::update_node`. On a reachable
//! endpoint that write now uses the owned route too, so the read and the write
//! share one retention rule: all four modeled members and every unmodelled
//! `Spec` member survive. Both halves are observed here, and the owned write
//! suite covers the bodies and failures in detail.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, Error, ErrorKind, NodeListOptions,
    NodeUpdateOptions,
};

#[path = "support/swarm_node_entries.rs"]
mod swarm_node_entries;

use swarm_node_entries::{
    CANARY, EXPECTED_UPDATE_BODY, MALFORMED_BODY, NODE_BODY, NODE_BODY_WITH_UNMODELLED_SPEC,
    NODE_ID, VERSION_INDEX, WRONG_TYPE_BODY, nodes_body,
};

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
    /// Answers one successful read and then watches for a second request.
    fn start_ok(body: &str) -> Self {
        Self::start("200 OK", body)
    }

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
                        let _ = retry_stream.write_all(&ok_json(NODE_BODY));
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

fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
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

/// Asserts the fixed facade collision error and that no document text leaked.
fn assert_engine_version_collision_error(error: &Error, canaries: &[&str]) {
    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(
        error.api_error().is_none(),
        "a local refusal has no API error"
    );
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    let summary = renderings.join("\n");
    assert!(
        summary.contains(
            "the Engine node document contains a top-level EngineVersion member that the \
             repository view cannot represent unambiguously"
        ),
        "the fixed diagnostic is missing: {summary}"
    );
    for canary in canaries {
        for rendering in &renderings {
            assert!(
                !rendering.contains(canary),
                "the collision error echoed {canary:?}: {rendering}"
            );
        }
    }
    for rendering in &renderings {
        assert!(
            !rendering.contains('\n'),
            "the collision error contains a newline: {rendering}"
        );
    }
}

/// The owned list is versioned and retains members Bollard's 1.53 models drop.
#[tokio::test]
async fn list_nodes_sends_a_versioned_request_and_retains_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(&nodes_body())]);
    let nodes = fixture
        .client()
        .list_nodes(None)
        .await
        .expect("the node array decoded");

    assert_eq!(nodes.len(), 1);
    let node = &nodes[0];
    assert_eq!(node.id.as_deref(), Some(NODE_ID));
    assert_eq!(
        node.version.as_ref().and_then(|version| version.index),
        Some(VERSION_INDEX)
    );
    assert_eq!(node.engine_version.as_deref(), Some("27.1.1"));
    let spec = node.spec.as_ref().expect("the daemon sent a specification");
    assert_eq!(spec.name.as_deref(), Some("manager-one"));
    assert_eq!(
        spec.labels
            .as_ref()
            .and_then(|labels| labels.get("org.example.node"))
            .map(String::as_str),
        Some("fixture")
    );
    assert_eq!(spec.role.as_deref(), Some("manager"));
    assert_eq!(spec.availability.as_deref(), Some("active"));
    assert_eq!(
        node.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": CANARY})),
        "the owned path discarded an unmodelled top-level node member"
    );
    assert!(
        node.additional.contains_key("Description"),
        "the owned path discarded the node description"
    );
    assert_eq!(
        node.additional.get("ManagerStatus.Addr"),
        Some(&serde_json::json!("192.0.2.10:2377")),
        "the raw backend's dotted manager-address retention is missing"
    );
    assert_eq!(
        node.manager_status
            .as_ref()
            .and_then(|manager| manager.additional.get("Addr")),
        Some(&serde_json::json!("192.0.2.10:2377")),
        "the nested manager address was dropped"
    );
    assert_eq!(
        fixture.next().line,
        format!("GET {}/nodes HTTP/1.1", version_prefix()),
        "list_nodes fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// An empty filter map is not sent, and a populated one is sent in `BTreeMap`
/// key order with the caller's value order preserved.
#[tokio::test]
async fn list_nodes_sends_no_empty_filters_and_exact_ordered_filters() {
    let fixture = Fixture::start(vec![ok_json(&nodes_body()), ok_json(&nodes_body())]);
    let client = fixture.client();

    client
        .list_nodes(Some(NodeListOptions::default()))
        .await
        .expect("the unfiltered list decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/nodes HTTP/1.1", version_prefix())
    );

    let mut filters = BTreeMap::new();
    filters.insert("role".to_owned(), vec!["manager".to_owned()]);
    filters.insert(
        "name".to_owned(),
        vec!["manager-one".to_owned(), "manager-two".to_owned()],
    );
    filters.insert(
        "label".to_owned(),
        vec!["org.example.node=fixture".to_owned()],
    );
    client
        .list_nodes(Some(NodeListOptions { filters }))
        .await
        .expect("the filtered list decoded");

    let expected_filters = r#"{"label":["org.example.node=fixture"],"name":["manager-one","manager-two"],"role":["manager"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.next().line,
        format!("GET {}/nodes?{} HTTP/1.1", version_prefix(), query.finish()),
        "the owned list did not send the exact ordered filters"
    );

    fixture.finish();
}

/// The owned list uses the configured version and percent-encodes the filter
/// values as one query value.
#[tokio::test]
async fn list_nodes_sends_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(&nodes_body())]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .list_nodes(None)
        .await
        .expect("the node array decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/nodes HTTP/1.1",
        "the owned list did not use the configured version"
    );

    fixture.finish();
}

/// The owned inspect is versioned and retains the whole node document.
#[tokio::test]
async fn inspect_node_sends_a_versioned_request_and_retains_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(NODE_BODY)]);
    let node = fixture
        .client()
        .inspect_node(NODE_ID)
        .await
        .expect("the node document decoded");

    assert_eq!(node.id.as_deref(), Some(NODE_ID));
    assert_eq!(node.engine_version.as_deref(), Some("27.1.1"));
    assert!(
        node.additional.contains_key("Description"),
        "the owned path discarded the node description"
    );
    assert_eq!(
        node.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": CANARY}))
    );
    assert_eq!(
        fixture.next().line,
        format!("GET {}/nodes/{NODE_ID} HTTP/1.1", version_prefix()),
        "inspect_node fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// An actual top-level `EngineVersion` of any JSON type is refused by the
/// facade for inspect, before projection, with no fallback.
#[tokio::test]
async fn inspect_node_fails_closed_on_an_actual_top_level_engine_version() {
    const STRING_CANARY: &str = "actual-top-level\ncanary-node-string-4a1d";
    const OBJECT_CANARY: &str = "canary-node-object-6e2b";
    const SIBLING_CANARY: &str = "canary-node-sibling-9c3f";
    for (actual, canaries) in [
        (
            serde_json::json!(STRING_CANARY),
            vec![STRING_CANARY, SIBLING_CANARY],
        ),
        (serde_json::Value::Null, vec![SIBLING_CANARY]),
        (
            serde_json::json!({"Message": OBJECT_CANARY}),
            vec![OBJECT_CANARY, SIBLING_CANARY],
        ),
    ] {
        let body = serde_json::json!({
            "ID": NODE_ID,
            "EngineVersion": actual,
            "Description": {"Hostname": SIBLING_CANARY}
        })
        .to_string();
        let fixture = RejectingFixture::start_ok(&body);
        let error = fixture
            .client()
            .inspect_node(NODE_ID)
            .await
            .expect_err("a top-level EngineVersion is refused");
        assert_engine_version_collision_error(&error, &canaries);
        assert!(
            !fixture.saw_retry(),
            "the refused inspect was sent through the generated fallback"
        );
        fixture.finish();
    }
}

/// One colliding node fails the whole list; no partial list and no fallback.
#[tokio::test]
async fn list_nodes_fails_whole_request_on_an_actual_top_level_engine_version() {
    const CANARY: &str = "canary-node-list-collision-7d5e";
    let collision = serde_json::json!({
        "ID": "nodeffffffffffffffff",
        "EngineVersion": CANARY,
        "Description": {"Hostname": CANARY}
    })
    .to_string();
    let body = format!("[{NODE_BODY},{collision}]");
    let fixture = RejectingFixture::start_ok(&body);
    let error = fixture
        .client()
        .list_nodes(None)
        .await
        .expect_err("one colliding node fails the list");
    assert_engine_version_collision_error(&error, &[CANARY]);
    assert!(
        !fixture.saw_retry(),
        "the refused list was sent through the generated fallback"
    );
    fixture.finish();
}

/// A synthetic manager-address view must not overwrite an actual top-level
/// member with the same dotted name.
#[tokio::test]
async fn inspect_node_preserves_actual_manager_address_members() {
    let body = r#"{
      "ID": "node0123456789abcdef",
      "ManagerStatus": {"Addr": "10.0.0.1:2377", "Address": "10.0.0.2:2377"},
      "ManagerStatus.Addr": "caller-addr",
      "ManagerStatus.Address": "caller-address"
    }"#;
    let fixture = Fixture::start(vec![ok_json(body)]);
    let node = fixture
        .client()
        .inspect_node(NODE_ID)
        .await
        .expect("the node document decoded");
    assert_eq!(
        node.additional.get("ManagerStatus.Addr"),
        Some(&serde_json::json!("caller-addr"))
    );
    assert_eq!(
        node.additional.get("ManagerStatus.Address"),
        Some(&serde_json::json!("caller-address"))
    );
    let serialized = serde_json::to_value(&node).expect("the node serializes");
    assert_eq!(serialized["ManagerStatus.Addr"], "caller-addr");
    assert_eq!(serialized["ManagerStatus.Address"], "caller-address");
    assert_eq!(
        node.manager_status
            .as_ref()
            .and_then(|manager| manager.additional.get("Addr")),
        Some(&serde_json::json!("10.0.0.1:2377"))
    );
    let _ = fixture.next();
    fixture.finish();
}

/// The owned inspect sends the configured version and encodes the reference
/// into exactly one path segment.
#[tokio::test]
async fn inspect_node_sends_the_configured_version_and_encodes_the_reference() {
    let fixture = Fixture::start(vec![ok_json(NODE_BODY)]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .inspect_node("node id/with?slash")
        .await
        .expect("the node document decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/nodes/node%20id%2Fwith%3Fslash HTTP/1.1",
        "the owned path did not use the configured version or one encoded segment"
    );

    fixture.finish();
}

/// The owned path retains an unmodelled `Spec` member through the update, so an
/// inspect → update round trip does not clear it.
#[tokio::test]
async fn inspect_node_retains_an_unmodelled_spec_member_and_update_preserves_it() {
    let fixture = Fixture::start(vec![ok_json(NODE_BODY_WITH_UNMODELLED_SPEC), ok_json("{}")]);
    let client = fixture.client();
    let node = client
        .inspect_node(NODE_ID)
        .await
        .expect("the node document decoded");
    let spec = node.spec.expect("the daemon sent a specification");
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true})),
        "the owned path discarded an unmodelled specification member"
    );
    let _ = fixture.next();

    client
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION_INDEX,
                spec,
            },
        )
        .await
        .expect("the owned update carries the unmodelled member");

    let update = fixture.next();
    assert_eq!(
        update.line,
        format!(
            "POST {}/nodes/{NODE_ID}/update?version={VERSION_INDEX} HTTP/1.1",
            version_prefix()
        ),
        "the update did not use the owned versioned route"
    );
    assert_eq!(
        update.json()["UnmodelledSpecMember"],
        serde_json::json!({"Nested": true}),
        "the owned update cleared an unmodelled specification member"
    );

    fixture.finish();
}

/// The owned path refuses an empty reference before dispatch.
#[tokio::test]
async fn inspect_node_rejects_an_empty_reference_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .inspect_node("")
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

/// A daemon rejection keeps its status and message, and is not retried.
#[tokio::test]
async fn inspect_node_reports_a_rejection_and_does_not_retry() {
    let message = "node node0123456789abcdef not found";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_node(NODE_ID)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/nodes/{NODE_ID} HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned inspect request was retried through the generated client"
    );

    fixture.finish();
}

/// An older daemon's version rejection is the daemon's answer, not a fallback
/// signal, and it is not retried.
#[tokio::test]
async fn inspect_node_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.41";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_node(NODE_ID)
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert!(
        !fixture.saw_retry(),
        "an old-daemon rejection was retried through the generated client"
    );

    fixture.finish();
}

/// A malformed or wrongly typed success body is the owned decode class.
#[tokio::test]
async fn node_reads_reject_malformed_and_wrongly_typed_documents() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_node(NODE_ID)
            .await
            .expect_err("a malformed node document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();

        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .list_nodes(None)
            .await
            .expect_err("a malformed node array is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        fixture.finish();
    }
}

/// A repeated top-level, `Spec`, or `Spec.Labels` key is refused before
/// projection, because the read-modify-write path would otherwise use a
/// value serde collapsed.
#[tokio::test]
async fn node_reads_reject_duplicate_keys_without_echoing_values() {
    const CANARY: &str = "canary-duplicate-node-read-2b7e";
    let bodies = [
        ("top", format!(r#"{{"ID":"a","ID":"{CANARY}"}}"#)),
        (
            "spec",
            format!(r#"{{"Spec":{{"Role":"manager","Role":"{CANARY}"}}}}"#),
        ),
        (
            "labels",
            format!(r#"{{"Spec":{{"Labels":{{"zone":"a","zone":"{CANARY}"}}}}}}"#),
        ),
        (
            "nested-array-escaped",
            format!(
                r#"{{"Spec":{{"Extension":[null,{{"{CANARY}":1,"\u0063anary-duplicate-node-read-2b7e":2}}]}}}}"#
            ),
        ),
        ("null-first", r#"{"Spec":null,"Spec":{}}"#.to_owned()),
    ];
    for (level, body) in bodies {
        let fixture = RejectingFixture::start_ok(&body);
        let error = fixture
            .client()
            .inspect_node(NODE_ID)
            .await
            .expect_err("a duplicate key is refused");
        assert_eq!(error.kind(), ErrorKind::Serialization, "{level}");
        let mut renderings = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            renderings.push(cause.to_string());
            renderings.push(format!("{cause:?}"));
            source = cause.source();
        }
        let summary = renderings.join("\n");
        assert!(
            summary.contains(
                "the Engine node document repeats a JSON key the repository view cannot represent \
                 unambiguously"
            ),
            "{level}: the fixed diagnostic is missing: {summary}"
        );
        for rendering in &renderings {
            assert!(
                !rendering.contains(CANARY),
                "{level}: the refusal echoed a value: {rendering}"
            );
        }
        assert!(
            !fixture.saw_retry(),
            "{level}: the refused inspect was dispatched again"
        );
        fixture.finish();
    }

    let body = format!(
        r#"[{{"Spec":null}},{{"Spec":{{"Extension":[null,{{"{CANARY}":1,"\u0063anary-duplicate-node-read-2b7e":2}}]}}}}]"#
    );
    let fixture = RejectingFixture::start_ok(&body);
    let error = fixture
        .client()
        .list_nodes(None)
        .await
        .expect_err("a duplicate key in one node fails the list");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(
        !error.to_string().contains(CANARY),
        "the list refusal echoed a value: {error}"
    );
    assert!(!fixture.saw_retry());
    fixture.finish();
}

/// A node document may carry hostnames, engine labels, TLS information, and
/// manager addresses. A decode failure must not echo any of it through
/// `Display`, `Debug`, or the source chain.
#[tokio::test]
async fn node_decode_errors_do_not_echo_metadata_canaries() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_node(NODE_ID)
            .await
            .expect_err("a malformed node document is refused");

        let mut renderings = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            renderings.push(cause.to_string());
            renderings.push(format!("{cause:?}"));
            source = cause.source();
        }
        for (index, rendering) in renderings.iter().enumerate() {
            assert!(
                !rendering.contains(CANARY),
                "decode error rendering {index} echoed node metadata: {rendering}"
            );
        }

        fixture.finish();
    }
}

/// The read → owned update round trip sends the complete v1.53 body.
#[tokio::test]
async fn the_inspected_node_specification_round_trips_through_the_owned_update() {
    let fixture = Fixture::start(vec![ok_json(NODE_BODY), ok_json("{}")]);
    let client = fixture.client();
    let node = client
        .inspect_node(NODE_ID)
        .await
        .expect("the node document decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/nodes/{NODE_ID} HTTP/1.1", version_prefix())
    );
    let spec = node.spec.expect("the daemon sent a specification");

    client
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: VERSION_INDEX,
                spec,
            },
        )
        .await
        .expect("the owned update was accepted");

    let update = fixture.next();
    assert_eq!(
        update.line,
        format!(
            "POST {}/nodes/{NODE_ID}/update?version={VERSION_INDEX} HTTP/1.1",
            version_prefix()
        ),
        "the update did not use the owned versioned route"
    );
    let expected: serde_json::Value =
        serde_json::from_str(EXPECTED_UPDATE_BODY).expect("the expected body is JSON");
    assert_eq!(
        update.json(),
        expected,
        "the owned update body lost a modeled node specification member"
    );

    fixture.finish();
}
