//! Prove `connect_local` reads nodes through the captured owned endpoint.
//!
//! `connect_local` captures the local endpoint once and builds both clients
//! from it. `raw_engine` still reports the client as unreachable because most
//! operations keep their generated fallback, but node list and inspect use the
//! recorded Unix socket, so node reads and writes share one route and one
//! duplicate-key policy.
//!
//! The assertions are wire assertions: versioned request lines, retained
//! unmodelled members, an empty reference refused before dispatch, a duplicate
//! key refused before projection, and the owned decode class for malformed
//! documents. A generated fallback would fail every one of them.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.

#![cfg(unix)]
#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    sync::{Arc, Mutex},
    thread,
};

use neotales_docker::{
    API_VERSION, DockerClient, ErrorKind, NodeListOptions, NodeRemoveOptions, NodeSpec,
    NodeUpdateOptions,
};
use tracing_subscriber::fmt::MakeWriter;

#[path = "support/swarm_node_entries.rs"]
mod swarm_node_entries;

use swarm_node_entries::{
    MALFORMED_BODY, NODE_BODY, NODE_BODY_TOP_LEVEL_ENGINE_VERSION, NODE_BODY_WITH_UNMODELLED_SPEC,
    NODE_ID, WRONG_TYPE_BODY, nodes_body,
};

const DUPLICATE_CANARY: &str = "canary-local-duplicate-node-9e4c";
const NODE_METADATA_CANARY: &str = "canary-local-node-metadata-5a7d";

/// An in-process TRACE sink for the local dispatch test.
#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl TraceCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the trace buffer")).into_owned()
    }
}

impl<'a> MakeWriter<'a> for TraceCapture {
    type Writer = TraceCaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceCaptureWriter(self.0.clone())
    }
}

struct TraceCaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceCaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the trace buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn public_local_owned_contract() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "local_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("SWARM_NODE_LOCAL_TEST_SOCKET", &socket)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn public_local_mutation_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "local_cancellation_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("SWARM_NODE_LOCAL_TEST_SOCKET", &socket)
        .status()
        .unwrap();
    assert!(status.success());
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_cancellation_worker() {
    use std::time::Duration;
    let listener =
        UnixListener::bind(std::env::var_os("SWARM_NODE_LOCAL_TEST_SOCKET").unwrap()).unwrap();
    let client = DockerClient::connect_local().unwrap();
    for update in [true, false] {
        let listener = listener.try_clone().unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (head, _) = read_request(&mut stream);
            assert!(head.starts_with(if update { "POST " } else { "DELETE " }));
            sent.send(()).unwrap();
            let mut byte = [0; 1];
            match stream.read(&mut byte) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) => {}
                result => panic!("cancelled peer did not close: {result:?}"),
            }
        });
        let client = client.clone();
        let task = tokio::spawn(async move {
            if update {
                client
                    .update_node(
                        NODE_ID,
                        NodeUpdateOptions {
                            version: 4,
                            spec: NodeSpec::default(),
                        },
                    )
                    .await
            } else {
                client
                    .remove_node(NODE_ID, NodeRemoveOptions { force: false })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), received)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        server.join().unwrap();
    }
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    let listener =
        UnixListener::bind(std::env::var_os("SWARM_NODE_LOCAL_TEST_SOCKET").unwrap()).unwrap();
    let nodes = nodes_body();
    let filtered_filters =
        r#"{"label":["org.example.node=fixture"],"name":["manager-one"],"role":["manager"]}"#;
    let mut filtered_query = url::form_urlencoded::Serializer::new(String::new());
    filtered_query.append_pair("filters", filtered_filters);
    let filtered_target = format!("/nodes?{}", filtered_query.finish());
    let duplicate_body =
        format!(r#"{{"Spec":{{"Labels":{{"zone":"a","zone":"{DUPLICATE_CANARY}"}}}}}}"#);

    let server = thread::spawn(move || serve(&listener, nodes, &filtered_target, duplicate_body));

    let client = DockerClient::connect_local().unwrap();
    assert!(
        client.raw_engine().is_ok(),
        "general owned routing must still report connect_local as unreachable"
    );

    let trace = TraceCapture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .without_time()
        .with_writer(trace.clone())
        .try_init()
        .expect("install the trace capture");

    assert_local_lists(&client).await;
    assert_local_inspect(&client).await;
    assert_local_errors(&client).await;
    assert_local_writes(&client).await;

    let logs = trace.text();
    assert!(
        !logs.contains(NODE_METADATA_CANARY),
        "the local owned node write logged node metadata: {logs}"
    );

    server.join().unwrap();
}

async fn assert_local_lists(client: &DockerClient) {
    let nodes = client
        .list_nodes(None)
        .await
        .expect("the local node array decoded through the owned route");
    assert_eq!(nodes.len(), 1);
    assert_owned_list_shape(&nodes[0]);

    let mut filters = std::collections::BTreeMap::new();
    filters.insert(
        "label".to_owned(),
        vec!["org.example.node=fixture".to_owned()],
    );
    filters.insert("name".to_owned(), vec!["manager-one".to_owned()]);
    filters.insert("role".to_owned(), vec!["manager".to_owned()]);
    client
        .list_nodes(Some(NodeListOptions { filters }))
        .await
        .expect("the filtered local list decoded");
}

async fn assert_local_inspect(client: &DockerClient) {
    let node = client
        .inspect_node(NODE_ID)
        .await
        .expect("the local node document decoded");
    assert_eq!(node.id.as_deref(), Some(NODE_ID));
    assert_eq!(
        node.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": "canary-node-metadata-4b7e2c19-do-not-log-me"})),
        "the local route discarded an unmodelled top-level member"
    );

    let node = client
        .inspect_node(NODE_ID)
        .await
        .expect("the local node document decoded");
    assert_eq!(
        node.spec
            .as_ref()
            .and_then(|spec| spec.additional.get("UnmodelledSpecMember")),
        Some(&serde_json::json!({"Nested": true})),
        "the local route discarded an unmodelled specification member"
    );
}

async fn assert_local_errors(client: &DockerClient) {
    let error = client
        .inspect_node(NODE_ID)
        .await
        .expect_err("a duplicate key is refused");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    let summary = renderings.join("\n");
    assert!(
        summary.contains("repeats a JSON key"),
        "the duplicate refusal is missing: {summary}"
    );
    for rendered in &renderings {
        assert!(
            !rendered.contains(DUPLICATE_CANARY),
            "the duplicate refusal echoed a value: {rendered}"
        );
    }

    let error = client
        .inspect_node("")
        .await
        .expect_err("the owned route refuses an empty reference before dispatch");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("must not be empty"));

    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let error = client
            .inspect_node(NODE_ID)
            .await
            .expect_err("a malformed node document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
    }

    let error = client
        .inspect_node(NODE_ID)
        .await
        .expect_err("a 404 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, format!("node {NODE_ID} not found"));

    let error = client
        .list_nodes(None)
        .await
        .expect_err("a top-level EngineVersion collision fails the list");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    let error = client
        .inspect_node(NODE_ID)
        .await
        .expect_err("a top-level EngineVersion collision fails the inspect");
    assert_eq!(error.kind(), ErrorKind::Serialization);
}

/// The captured local endpoint serves the writes too; the generated fallback
/// would not put a versioned request on this socket.
async fn assert_local_writes(client: &DockerClient) {
    client
        .update_node(
            NODE_ID,
            NodeUpdateOptions {
                version: 4,
                spec: NodeSpec {
                    name: Some(format!("manager-{NODE_METADATA_CANARY}")),
                    labels: Some(std::collections::BTreeMap::from([(
                        "org.example.node".to_owned(),
                        NODE_METADATA_CANARY.to_owned(),
                    )])),
                    ..NodeSpec::default()
                },
            },
        )
        .await
        .expect("the local owned update was accepted");
    client
        .remove_node(NODE_ID, NodeRemoveOptions { force: false })
        .await
        .expect("the local owned removal was accepted");
}

/// The shape the owned list route reports for [`NODE_BODY`].
fn assert_owned_list_shape(node: &neotales_docker::SwarmNode) {
    assert_eq!(node.id.as_deref(), Some(NODE_ID));
    assert_eq!(node.engine_version.as_deref(), Some("27.1.1"));
    assert!(
        node.additional.contains_key("UnmodelledMember"),
        "the owned route discarded an unmodelled top-level member"
    );
    assert!(node.additional.contains_key("Description"));
    assert_eq!(
        node.additional.get("ManagerStatus.Addr"),
        Some(&serde_json::json!("192.0.2.10:2377"))
    );
    assert_eq!(
        node.manager_status
            .as_ref()
            .and_then(|manager| manager.additional.get("Addr")),
        Some(&serde_json::json!("192.0.2.10:2377"))
    );
}

/// Answers the owned request sequence the worker makes.
fn serve(listener: &UnixListener, nodes: String, filtered_target: &str, duplicate_body: String) {
    let prefix = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    // Each entry is (expected request target, response status, body).
    let entries = [
        (format!("{prefix}/nodes"), "200 OK", nodes.clone()),
        (format!("{prefix}{filtered_target}"), "200 OK", nodes),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            NODE_BODY.to_owned(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            NODE_BODY_WITH_UNMODELLED_SPEC.to_owned(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            duplicate_body,
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            MALFORMED_BODY.to_owned(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            WRONG_TYPE_BODY.to_owned(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "404 Not Found",
            format!(r#"{{"message":"node {NODE_ID} not found"}}"#),
        ),
        (
            format!("{prefix}/nodes"),
            "200 OK",
            format!("[{NODE_BODY_TOP_LEVEL_ENGINE_VERSION}]"),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}"),
            "200 OK",
            NODE_BODY_TOP_LEVEL_ENGINE_VERSION.to_owned(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}/update?version=4"),
            "200 OK",
            String::new(),
        ),
        (
            format!("{prefix}/nodes/{NODE_ID}?force=false"),
            "200 OK",
            String::new(),
        ),
    ];
    for (target, status, body) in entries {
        let (mut stream, _) = listener.accept().unwrap();
        let (head, _body) = read_request(&mut stream);
        let line = head.lines().next().expect("the request line");
        assert_eq!(
            line.split_whitespace().nth(1),
            Some(target.as_str()),
            "the local request line changed: {line}"
        );
        assert!(
            line.contains("/v1."),
            "the local route sent an unversioned request: {line}"
        );
        respond_json(&mut stream, status, &body);
    }
}

/// Writes an answer carrying `body` and waits for the client to release the
/// connection, so the next `accept` is the next operation rather than a retry.
fn respond_json(stream: &mut UnixStream, status: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
}

fn read_request(stream: &mut UnixStream) -> (String, Vec<u8>) {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
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
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "the request body ended early");
        request.extend_from_slice(&chunk[..read]);
    }
    (
        head,
        request[body_start..body_start + content_length].to_vec(),
    )
}
