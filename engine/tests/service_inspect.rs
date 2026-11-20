//! `DockerClient::inspect_service` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `inspect_service` must open
//! `GET /v1.NN/services/{id}` through the owned transport when that transport
//! can reach the endpoint, rather than the unversioned path the generated
//! client sends. Asserting that against a request builder would only show what
//! the builder would produce if it were called; the routing decision is above
//! it. A loopback HTTP fixture is the only place the wire request and the
//! routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `inspect_service` puts the generated client back on the wire. The request
//! line then loses the version prefix, `TaskTemplate` stops being the daemon's
//! own JSON, `Endpoint` and `PreviousSpec` disappear from the value, and every
//! unmodelled member is dropped one level lower than it should be. The
//! assertions below fail with it.
//!
//! # What the round trip can and cannot carry
//!
//! `ndocker service scale`, `update`, and `rollback` read a service and write
//! the specification back through `DockerClient::update_service`. On this
//! suite's client the owned transport reaches the endpoint, so the write sends
//! the specification member for member: `Spec.TaskTemplate` is the daemon's own
//! JSON, and the nested `Placement`, `RestartPolicy`, and unmodelled members all
//! survive. The update test asserts the *complete* body, so that retention is
//! observed rather than assumed. `service_update_local.rs` covers the local
//! `connect_local` inspect→update path; the generated inspect fallback is no
//! longer reached by that constructor.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ForwardProxy, ProxyPolicy,
    ServicePlacement, ServiceRestartPolicy, ServiceSpec, ServiceUpdateOptions, SwarmListOptions,
};

#[tokio::test]
async fn raw_list_keeps_the_original_port_projection_contract() {
    let fixture = Fixture::start(vec![ok_json(
        r#"[{"Endpoint":{"Spec":"ignored","Ports":[{"Protocol":"future"}]}}]"#,
    )]);
    let engine = fixture.client().raw_engine().unwrap();
    let services = neotales_docker::raw::service_list(&engine, &SwarmListOptions::default())
        .await
        .unwrap();
    assert_eq!(
        services[0].ports.as_ref().unwrap()[0].protocol.as_deref(),
        Some("future")
    );
    fixture.finish();
}

#[tokio::test]
async fn raw_and_facade_keep_distinct_endpoint_contracts() {
    let cases = [
        (
            r#"{"Endpoint":{"Ports":[{"Protocol":"future","PublishMode":"future"}]}}"#,
            true,
            false,
        ),
        (
            r#"{"Endpoint":{"Spec":"malformed","Ports":[]}}"#,
            true,
            false,
        ),
        (r#"{"Endpoint":{"Ports":[{"Name":17}]}}"#, true, false),
        (
            r#"{"Endpoint":{"Ports":[{"TargetPort":4294967296}]}}"#,
            false,
            true,
        ),
        (r#"{"Endpoint":{"Ports":null}}"#, false, true),
        (r#"{"ServiceStatus":{"RunningTasks":1}}"#, false, true),
    ];
    let responses = cases
        .iter()
        .flat_map(|(body, _, _)| [ok_json(body), ok_json(body)])
        .collect();
    let fixture = Fixture::start(responses);
    let client = fixture.client();
    let engine = client.raw_engine().unwrap();
    for (body, raw_ok, facade_ok) in cases {
        let raw = neotales_docker::raw::service_inspect(&engine, SERVICE_ID).await;
        let facade = client.inspect_service(SERVICE_ID).await;
        assert_eq!(raw.is_ok(), raw_ok, "raw {body}");
        assert_eq!(facade.is_ok(), facade_ok, "facade {body}");
        if let Ok(service) = raw
            && body.contains("future")
        {
            let port = &service.ports.unwrap()[0];
            assert_eq!(port.protocol.as_deref(), Some("future"));
            assert_eq!(port.publish_mode.as_deref(), Some("future"));
        }
        if facade_ok && body.contains("4294967296") {
            assert!(facade.unwrap().ports.is_none());
        }
    }
    fixture.finish();
}

#[tokio::test]
async fn raw_invalid_preference_error_does_not_echo_input() {
    let fixture = Fixture::start(Vec::new());
    let engine = fixture.client().raw_engine().unwrap();
    let canary = "preference-canary-do-not-echo";
    let spec = ServiceSpec {
        placement: Some(ServicePlacement {
            preferences: vec![format!("{canary}\ninjected")],
            ..ServicePlacement::default()
        }),
        ..ServiceSpec::default()
    };
    let options = ServiceUpdateOptions {
        version: 1,
        spec: spec.clone(),
        rollback: false,
    };
    let errors = [
        neotales_docker::raw::service_create(&engine, &spec)
            .await
            .unwrap_err(),
        neotales_docker::raw::service_update(&engine, SERVICE_ID, &options)
            .await
            .unwrap_err(),
    ];
    for error in errors {
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(item) = source {
            for rendered in [format!("{item}"), format!("{item:?}")] {
                assert!(!rendered.contains(canary), "leak: {rendered}");
                assert!(!rendered.contains('\n'), "newline: {rendered}");
            }
            source = item.source();
        }
    }
    fixture.finish();
}

#[tokio::test]
async fn raw_conflicting_dotted_key_errors_do_not_echo_input() {
    let fixture = Fixture::start(Vec::new());
    let engine = fixture.client().raw_engine().unwrap();
    let mut spec = ServiceSpec {
        task_template: Some(serde_json::json!("scalar")),
        ..ServiceSpec::default()
    };
    let canary = "canary-do-not-echo";
    spec.additional.insert(
        format!("TaskTemplate.{canary}\ninjected"),
        serde_json::json!(true),
    );
    let options = ServiceUpdateOptions {
        version: 1,
        spec: spec.clone(),
        rollback: false,
    };
    let mut arbitrary_parent = ServiceSpec::default();
    arbitrary_parent
        .additional
        .insert(format!("{canary}\ninjected"), serde_json::json!(42));
    arbitrary_parent
        .additional
        .insert(format!("{canary}\ninjected.child"), serde_json::json!(true));
    let errors = [
        neotales_docker::raw::service_create(&engine, &spec)
            .await
            .unwrap_err(),
        neotales_docker::raw::service_update(&engine, SERVICE_ID, &options)
            .await
            .unwrap_err(),
        neotales_docker::raw::service_create(&engine, &arbitrary_parent)
            .await
            .unwrap_err(),
    ];
    for error in errors {
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(item) = chain {
            for rendered in [format!("{item}"), format!("{item:?}")] {
                assert!(!rendered.contains(canary), "leak: {rendered}");
                assert!(!rendered.contains('\n'), "newline: {rendered}");
            }
            chain = item.source();
        }
    }
    fixture.finish();
}

#[tokio::test]
async fn raw_inspect_preserves_published_ip_projection() {
    let body = r#"{"Endpoint":{"Ports":[{"PublishedIP":"192.0.2.1"}]}}"#;
    let fixture = Fixture::start(vec![ok_json(body)]);
    let engine = fixture.client().raw_engine().unwrap();
    let service = neotales_docker::raw::service_inspect(&engine, SERVICE_ID)
        .await
        .unwrap();
    assert_eq!(
        service.ports.unwrap()[0].published_ip.as_deref(),
        Some("192.0.2.1")
    );
    fixture.finish();
}

#[path = "support/service_inspect_entries.rs"]
mod service_inspect_entries;

use service_inspect_entries::{
    CANARY, MALFORMED_BODY, MALFORMED_PROJECTION_BODIES, PROJECTION_CASES, SERVICE_BODY,
    SERVICE_ID, TASK_TEMPLATE, VERSION_INDEX, WRONG_TYPE_BODY, canary_body,
};

/// A request the fixture recorded: the request line and the body that followed
/// the headers.
struct Captured {
    line: String,
    body: Vec<u8>,
}

impl Captured {
    /// The body parsed as JSON, so the assertion is about members rather than
    /// about the order they were serialized in.
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
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

/// A server that rejects one request and then watches for a retry.
///
/// A second connection is the observable form of a fallback after a failed
/// owned request. The watch window exists because a client that retried would
/// do so immediately after the first answer; the first answer has already been
/// read when the window opens.
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
            let mut stream = accept_tcp(&listener);
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

    fn request_line(&self) -> String {
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

/// Accepts one request with a bounded wait, and restores blocking mode.
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
    let line = head
        .lines()
        .next()
        .expect("the request has a request line")
        .to_owned();
    Captured {
        line,
        body: request[header_end + 4..header_end + 4 + content_length].to_vec(),
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

/// The owned route sends the versioned request, projects the published ports
/// out of the endpoint, and retains the endpoint and the service-level members
/// no typed field names.
#[tokio::test]
async fn inspect_service_sends_a_versioned_request_and_projects_the_endpoint() {
    let fixture = Fixture::start(vec![ok_json(SERVICE_BODY)]);
    let service = fixture
        .client()
        .inspect_service(SERVICE_ID)
        .await
        .expect("the service document decoded");

    assert_eq!(service.id.as_deref(), Some(SERVICE_ID));
    assert_eq!(
        service.version.and_then(|version| version.index),
        Some(VERSION_INDEX)
    );

    // The published ports are a projection of `Endpoint.Ports`; the whole
    // endpoint stays retained so a member the projection cannot hold survives.
    let ports = service.ports.as_ref().expect("the published ports");
    assert_eq!(ports[0].protocol.as_deref(), Some("tcp"));
    assert_eq!(ports[0].target_port, Some(80));
    assert_eq!(ports[0].published_port, Some(8080));
    assert_eq!(ports[0].publish_mode.as_deref(), Some("ingress"));
    assert_eq!(
        service.additional["Endpoint"]["Ports"][0]["Name"], "http",
        "the owned path lost a port member the projection cannot hold"
    );
    assert_eq!(
        service.additional["Endpoint"]["VirtualIPs"][0]["Addr"], "10.0.0.5/24",
        "the owned path lost an endpoint member no typed field names"
    );

    // Service-level members no typed field names, including the one a rollback
    // restores.
    assert_eq!(
        service.additional["PreviousSpec"]["TaskTemplate"]["ContainerSpec"]["Image"],
        "nginx:1.25"
    );
    assert_eq!(service.additional["UpdateStatus"]["State"], "completed");
    assert_eq!(
        service.additional["UnmodelledMember"],
        serde_json::json!({"Value": 7})
    );
    assert_eq!(
        service.status,
        Some(neotales_docker::ServiceStatus {
            running_tasks: 2,
            desired_tasks: 3,
        })
    );

    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/services/{SERVICE_ID} HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        ),
        "inspect_service fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The task template — where the Engine keeps `Placement` and `RestartPolicy` —
/// comes back exactly as the daemon spelled it, including the members no model
/// names.
#[tokio::test]
async fn inspect_service_returns_the_task_template_verbatim() {
    let fixture = Fixture::start(vec![ok_json(SERVICE_BODY)]);
    let service = fixture
        .client()
        .inspect_service(SERVICE_ID)
        .await
        .expect("the service document decoded");
    let spec = service.spec.as_ref().expect("the daemon sent a spec");

    assert_eq!(spec.name.as_deref(), Some("web"));
    assert_eq!(
        spec.labels.as_ref().expect("labels")["org.example.service"],
        "fixture"
    );
    assert_eq!(
        spec.mode.as_ref().and_then(|mode| mode.get("Replicated")),
        Some(&serde_json::json!({"Replicas": 3}))
    );
    assert_eq!(
        spec.update_config
            .as_ref()
            .and_then(|config| config.get("Parallelism")),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        spec.rollback_config
            .as_ref()
            .and_then(|config| config.get("Parallelism")),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        spec.networks
            .as_ref()
            .and_then(|networks| networks.get(0))
            .and_then(|network| network.get("Target")),
        Some(&serde_json::json!("net0123456789abcdef"))
    );
    assert_eq!(
        spec.task_template,
        Some(serde_json::from_str(TASK_TEMPLATE).expect("the template is JSON")),
        "the owned path rewrote the task template instead of keeping it"
    );
    assert_eq!(
        spec.additional["UnmodelledSpecMember"],
        serde_json::json!({"Nested": true})
    );

    // `Placement` and `RestartPolicy` are members of `Spec.TaskTemplate` in the
    // Engine's document, so the top-level specification fields stay empty. The
    // values are not lost — they are in `task_template` above — but a caller
    // reading only `placement` learns nothing, on either route.
    assert!(
        spec.placement.is_none(),
        "a real Engine document carries Placement inside TaskTemplate"
    );
    assert!(
        spec.restart_policy.is_none(),
        "a real Engine document carries RestartPolicy inside TaskTemplate"
    );

    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/services/{SERVICE_ID} HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )
    );

    fixture.finish();
}

/// The two projections accept every shape the generated client accepts.
///
/// `Endpoint` and `ServiceStatus` are members the daemon may omit, null, leave
/// empty, or report partially. The generated client models both as optional and
/// each of their members as optional too, so all of those are accepted there;
/// the owned decoder must not turn one of them into a document-level failure, and
/// must not invent counts a daemon did not send. An absent or unusable member is
/// *no projection*, which is a different answer from an empty port list.
#[tokio::test]
async fn inspect_service_accepts_the_projection_shapes_the_generated_client_accepts() {
    let fixture = Fixture::start(
        PROJECTION_CASES
            .iter()
            .map(|case| ok_json(case.body))
            .collect(),
    );
    let client = fixture.client();

    for case in PROJECTION_CASES {
        let service = client
            .inspect_service(SERVICE_ID)
            .await
            .unwrap_or_else(|error| panic!("the owned path refused {}: {error}", case.what));
        case.assert_projections(&service, "owned");
        // The endpoint is retained whole whenever it is present and not null.
        assert_eq!(
            service.additional.contains_key("Endpoint"),
            case.endpoint_retained,
            "owned ({}): {:?}",
            case.what,
            service.additional
        );
        assert_eq!(
            fixture.next().line,
            format!(
                "GET {}/services/{SERVICE_ID} HTTP/1.1",
                version_prefix(API_VERSION.major, API_VERSION.minor)
            )
        );
    }

    fixture.finish();
}

/// A projection input of the wrong JSON type is refused, not silently projected
/// away.
///
/// The generated models are nullable and optional, not permissive, so every one
/// of these documents is a decode failure there. The owned decoder must not
/// accept a document the facade refuses on the other route.
#[tokio::test]
async fn inspect_service_rejects_malformed_projection_inputs() {
    let fixture = Fixture::start(
        MALFORMED_PROJECTION_BODIES
            .iter()
            .map(|(_, body)| ok_json(body))
            .collect(),
    );
    let client = fixture.client();

    for (what, _body) in MALFORMED_PROJECTION_BODIES {
        let Err(error) = client.inspect_service(SERVICE_ID).await else {
            panic!("the owned path accepted {what}");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}");
        assert!(
            error.to_string().contains("failed to decode"),
            "{what}: {error}"
        );
    }

    fixture.finish();
}

/// Inspect preserves an unknown structured value, but a later write refuses it.
///
#[tokio::test]
async fn inspect_keeps_unknown_structures_but_update_refuses_without_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind live inspect listener");
    let server_listener = listener.try_clone().expect("clone inspect listener");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let server = thread::spawn(move || {
        let mut stream = accept_tcp(&server_listener);
        let request = read_request(&mut stream);
        assert!(request.line.starts_with("GET "));
        stream
            .write_all(&ok_json(SERVICE_BODY))
            .expect("write inspect response");
        stream.flush().expect("flush inspect response");
        release(&mut stream);
    });
    let client = DockerClient::connect_http(&endpoint).expect("build the client");
    let current = client
        .inspect_service(SERVICE_ID)
        .await
        .expect("the service document decoded");
    let spec = current.spec.clone().expect("the daemon sent a spec");
    assert_eq!(
        spec.task_template.as_ref().unwrap()["ContainerSpec"]["UnmodelledContainerMember"],
        serde_json::json!({"Nested": true})
    );
    assert_eq!(
        spec.additional["UnmodelledSpecMember"],
        serde_json::json!({"Nested": true})
    );
    server.join().expect("inspect fixture thread");

    let error = client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: VERSION_INDEX,
                spec,
                rollback: false,
            },
        )
        .await
        .expect_err("unknown structured members must be refused before update");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("unclassified structured value"));
    listener.set_nonblocking(true).expect("set nonblocking");
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "update unexpectedly connected after refusal"
    );
}

/// A task template the generated models cannot decode is writable on the owned
/// route.
///
/// `TaskTemplate` is a JSON value on the repository model. The request validator
/// recognizes the restart-policy structure and leaves its string condition
/// unconstrained, as Moby's decoder does; Bollard's typed model rejects the
/// unknown condition before a request is sent.
#[tokio::test]
async fn owned_writes_accept_a_task_template_the_generated_models_cannot_convert() {
    let condition = "canary-unknown-condition\ninjected";
    let condition_literal = serde_json::to_string(condition).expect("the canary is a JSON string");
    let body = format!(
        r#"{{
          "ID": "service0123456789abcdef",
          "Version": {{"Index": 7}},
          "Spec": {{
            "Name": "web",
            "TaskTemplate": {{
              "ContainerSpec": {{"Image": "nginx:alpine"}},
              "RestartPolicy": {{"Condition": {condition_literal}}}
            }}
          }}
        }}"#
    );
    let fixture = Fixture::start(vec![
        ok_json(&body),
        ok_json(r#"{"ID":"service0123456789abcdef"}"#),
        ok_json("{}"),
    ]);
    let client = fixture.client();
    let service = client
        .inspect_service(SERVICE_ID)
        .await
        .expect("the owned decoder accepts the daemon's task template");
    let template = service
        .spec
        .as_ref()
        .and_then(|spec| spec.task_template.as_ref())
        .expect("the daemon sent a task template");
    assert_eq!(
        template
            .get("RestartPolicy")
            .and_then(|policy| policy.get("Condition")),
        Some(&serde_json::json!(condition))
    );
    fixture.next();

    let spec = service.spec.expect("the daemon sent a spec");
    let created = client
        .create_service(spec.clone())
        .await
        .expect("the owned create sends the task template verbatim");
    assert_eq!(created.id, SERVICE_ID);
    let create = fixture.next();
    assert_eq!(
        create.line,
        format!(
            "POST {}/services/create HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        ),
        "the owned create did not use the versioned route"
    );
    assert_eq!(
        create.json()["TaskTemplate"],
        serde_json::from_str::<serde_json::Value>(&format!(
            r#"{{"ContainerSpec": {{"Image": "nginx:alpine"}}, "RestartPolicy": {{"Condition": {condition_literal}}}}}"#
        ))
        .expect("the expected template is JSON")
    );

    client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: VERSION_INDEX,
                spec,
                rollback: false,
            },
        )
        .await
        .expect("the owned update sends the task template verbatim");
    let update = fixture.next();
    assert_eq!(
        update.line,
        format!(
            "POST {}/services/{SERVICE_ID}/update?version={VERSION_INDEX}&registryAuthFrom=spec \
             HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )
    );
    assert_eq!(
        update.json()["TaskTemplate"],
        serde_json::from_str::<serde_json::Value>(&format!(
            r#"{{"ContainerSpec": {{"Image": "nginx:alpine"}}, "RestartPolicy": {{"Condition": {condition_literal}}}}}"#
        ))
        .expect("the expected template is JSON")
    );

    fixture.finish();
}

/// The specifications a facade service write must accept or refuse.
///
/// The typed fields are the accepted spelling; the dotted `additional` keys are
/// the refused one, because the facade cannot tell a literal member name
/// containing a dot from the raw first-dot retention convention. The boolean is
/// whether the case carries a dotted key.
fn facade_specification_cases() -> Vec<(&'static str, ServiceSpec, bool)> {
    let placement = ServicePlacement {
        constraints: vec!["node.role == worker".to_owned()],
        ..ServicePlacement::default()
    };
    let policy = ServiceRestartPolicy {
        condition: "on-failure".to_owned(),
        ..ServiceRestartPolicy::default()
    };
    let named = |name: &str| ServiceSpec {
        name: Some(name.to_owned()),
        ..ServiceSpec::default()
    };
    let dotted = |key: &str, value: serde_json::Value| {
        let mut spec = named("web");
        spec.additional.insert(key.to_owned(), value);
        (spec, true)
    };

    vec![
        (
            "the typed placement",
            ServiceSpec {
                placement: Some(placement.clone()),
                ..named("web")
            },
            false,
        ),
        (
            "the typed restart policy",
            ServiceSpec {
                restart_policy: Some(policy.clone()),
                ..named("web")
            },
            false,
        ),
        (
            "both typed fields",
            ServiceSpec {
                placement: Some(placement),
                restart_policy: Some(policy),
                ..named("web")
            },
            false,
        ),
        {
            let (spec, dotted) = dotted(
                "Placement.Platforms",
                serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
            );
            ("a dotted placement key", spec, dotted)
        },
        {
            let (spec, dotted) = dotted(
                "RestartPolicy.Window",
                serde_json::json!(20_000_000_000_i64),
            );
            ("a dotted restart-policy key", spec, dotted)
        },
        {
            let (spec, dotted) = dotted(
                "TaskTemplate.Placement",
                serde_json::json!({"Constraints": []}),
            );
            ("a dotted task template key", spec, dotted)
        },
        {
            let (spec, dotted) = dotted(
                "TaskTemplate.canary-do-not-echo\ninjected",
                serde_json::json!(true),
            );
            ("untrusted dotted key", spec, dotted)
        },
    ]
}

/// Both facade service writes carry the typed placement and restart policy and
/// refuse every dotted key.
///
/// The typed fields are moved into `Spec.TaskTemplate` by the raw writer, which
/// is where the Engine reads them. A dotted key is refused before dispatch on
/// both writes; the explicit raw writer remains the escape hatch for a caller
/// that intended the first-dot convention.
#[tokio::test]
async fn facade_service_writes_refuse_dotted_keys_but_carry_typed_fields() {
    let cases = facade_specification_cases();
    let typed_count = cases.iter().filter(|(_, _, dotted)| !dotted).count();
    let responses = (0..typed_count)
        .flat_map(|_| {
            [
                ok_json(r#"{"ID":"service0123456789abcdef"}"#),
                ok_json("{}"),
            ]
        })
        .collect();
    let fixture = Fixture::start(responses);
    let client = fixture.client();

    for (what, spec, dotted) in cases {
        if dotted {
            let error = client
                .create_service(spec.clone())
                .await
                .expect_err("the create refuses a dotted key");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
            let message = error.to_string();
            assert!(
                message.contains("dotted `additional` key"),
                "{what}: the refusal must name the dotted key: {message}"
            );
            assert!(
                message.contains("first dot") && message.contains("no lossless facade write"),
                "{what}: the refusal must distinguish the convention from a literal: {message}"
            );
            assert!(
                !format!("{error:?}").contains("canary-do-not-echo") && !message.contains('\n'),
                "{what}: the refusal echoed the caller's key"
            );

            let error = client
                .update_service(
                    SERVICE_ID,
                    ServiceUpdateOptions {
                        version: VERSION_INDEX,
                        spec,
                        rollback: false,
                    },
                )
                .await
                .expect_err("the update refuses a dotted key");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}");
            assert!(
                error.to_string().contains("dotted `additional` key"),
                "{what}: {error}"
            );
            continue;
        }

        let created = client
            .create_service(spec.clone())
            .await
            .unwrap_or_else(|error| panic!("{what}: the create refused a typed field: {error}"));
        assert_eq!(created.id, SERVICE_ID, "{what}");
        let create = fixture.next();
        assert_eq!(
            create.line,
            format!(
                "POST {}/services/create HTTP/1.1",
                version_prefix(API_VERSION.major, API_VERSION.minor)
            ),
            "{what}: the create did not use the versioned route"
        );
        assert_typed_fields(&create.json(), what);

        client
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: VERSION_INDEX,
                    spec,
                    rollback: false,
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{what}: the update refused a typed field: {error}"));
        let update = fixture.next();
        assert_eq!(
            update.line,
            format!(
                "POST {}/services/{SERVICE_ID}/update?version={VERSION_INDEX}&registryAuthFrom=spec \
                 HTTP/1.1",
                version_prefix(API_VERSION.major, API_VERSION.minor)
            ),
            "{what}: the update did not use the versioned route"
        );
        assert_typed_fields(&update.json(), what);
    }

    fixture.finish();
}

/// Nested request-schema collisions and unclassified structures fail before
/// either raw or facade create/update can write to the fixture.
#[tokio::test]
async fn nested_service_schema_refusals_do_not_dispatch_raw_or_facade_writes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a live no-dispatch listener");
    listener
        .set_nonblocking(true)
        .expect("make the listener nonblocking");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let client = DockerClient::connect_http(&endpoint).expect("build the client");
    let cases = [
        serde_json::json!({"ContainerSpec":{"ReadOnly":true,"readonly":false}}),
        serde_json::json!({"ContainerSpec":{"Mounts":[{"ReadOnly":true,"readonly":false}]}}),
        serde_json::json!({"Mystery":{"structured":true}}),
        serde_json::json!({"containerspec":{"Readonly":true,"readonly":false}}),
        serde_json::json!({"ContainerSpec":{"Mounts":[{"ReadOnly":true,"RеadOnly":false}]}}),
    ];
    for value in cases {
        let spec = ServiceSpec {
            task_template: Some(value.clone()),
            ..ServiceSpec::default()
        };
        assert_schema_refusal(&client, spec).await;
    }
    let mut dotted_collision = ServiceSpec {
        task_template: Some(serde_json::json!({"ContainerSpec":{"Image":"nginx"}})),
        ..ServiceSpec::default()
    };
    dotted_collision.additional.insert(
        "TaskTemplate.ContainerSpec".to_owned(),
        serde_json::json!({}),
    );
    assert_schema_refusal(&client, dotted_collision).await;
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "one of the refused operations opened a connection"
    );
}

async fn assert_schema_refusal(client: &DockerClient, spec: ServiceSpec) {
    let engine = client.raw_engine().unwrap();
    let error = neotales_docker::raw::service_create(&engine, &spec)
        .await
        .expect_err("raw create must refuse the invalid schema");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let error = neotales_docker::raw::service_update(
        &engine,
        SERVICE_ID,
        &ServiceUpdateOptions {
            version: VERSION_INDEX,
            spec: spec.clone(),
            rollback: false,
        },
    )
    .await
    .expect_err("raw update must refuse the invalid schema");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let error = client
        .create_service(spec.clone())
        .await
        .expect_err("facade create must refuse the invalid schema");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let error = client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: VERSION_INDEX,
                spec,
                rollback: false,
            },
        )
        .await
        .expect_err("facade update must refuse the invalid schema");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

/// Asserts a write body carries the typed placement and restart policy inside
/// `TaskTemplate`, with no top-level spelling.
fn assert_typed_fields(body: &serde_json::Value, what: &str) {
    assert!(
        body.get("Placement").is_none() && body.get("RestartPolicy").is_none(),
        "{what}: a typed member was sent at the specification root: {body}"
    );
    if matches!(what, "the typed placement" | "both typed fields") {
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Constraints"][0], "node.role == worker",
            "{what}: the typed placement did not reach TaskTemplate: {body}"
        );
    }
    if matches!(what, "the typed restart policy" | "both typed fields") {
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Condition"], "on-failure",
            "{what}: the typed restart policy did not reach TaskTemplate: {body}"
        );
    }
}

/// The nested representation is accepted by both writes, with no top-level
/// spelling sent alongside it.
///
/// A caller that sets `TaskTemplate.Placement` — the member the Engine reads —
/// gets an owned create and an owned update that carry it exactly.
#[tokio::test]
async fn the_nested_task_template_representation_is_accepted_and_sent() {
    let fixture = Fixture::start(vec![
        ok_json(r#"{"ID":"service0123456789abcdef"}"#),
        ok_json("{}"),
    ]);
    let client = fixture.client();
    let spec = ServiceSpec {
        name: Some("web".to_owned()),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {"Image": "nginx:alpine"},
            "Placement": {"Constraints": ["node.role == worker"]},
            "RestartPolicy": {"Condition": "on-failure", "MaxAttempts": 3}
        })),
        ..ServiceSpec::default()
    };

    let created = client
        .create_service(spec.clone())
        .await
        .expect("the nested representation is accepted");
    assert_eq!(created.id, SERVICE_ID);
    let create = fixture.next();
    assert_eq!(
        create.line,
        format!(
            "POST {}/services/create HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )
    );
    let body = create.json();
    assert_eq!(
        body["TaskTemplate"]["Placement"]["Constraints"][0],
        "node.role == worker"
    );
    assert_eq!(
        body["TaskTemplate"]["RestartPolicy"]["Condition"],
        "on-failure"
    );
    assert!(
        body.get("Placement").is_none() && body.get("RestartPolicy").is_none(),
        "the top-level spelling must not be sent beside the nested one: {body}"
    );

    client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: VERSION_INDEX,
                spec,
                rollback: false,
            },
        )
        .await
        .expect("the nested representation is accepted");
    let update = fixture.next();
    assert_eq!(
        update.line,
        format!(
            "POST {}/services/{SERVICE_ID}/update?version={VERSION_INDEX}&registryAuthFrom=spec \
             HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )
    );
    let body = update.json();
    assert_eq!(
        body["TaskTemplate"]["Placement"]["Constraints"][0],
        "node.role == worker"
    );
    assert_eq!(body["TaskTemplate"]["RestartPolicy"]["MaxAttempts"], 3);

    fixture.finish();
}

/// The owned request carries the version configured on the client, not the
/// crate's default. A daemon that serves an older version is reached by
/// construction, not by a silent fallback.
#[tokio::test]
async fn inspect_service_uses_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(SERVICE_BODY)]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 43,
        },
    )
    .expect("a client at the configured version");

    client
        .inspect_service(SERVICE_ID)
        .await
        .expect("the service document decoded");

    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/services/{SERVICE_ID} HTTP/1.1",
            version_prefix(1, 43)
        ),
        "the owned request did not use the configured API version"
    );

    fixture.finish();
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn inspect_service_reports_a_rejection_and_does_not_retry() {
    let message = "service not found";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_service(SERVICE_ID)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/services/{SERVICE_ID} HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        ),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned inspect_service request was retried through the generated client"
    );

    fixture.finish();
}

/// A daemon older than the configured version answers the versioned path with
/// its own rejection. That rejection is returned; it is not treated as a reason
/// to repeat the request unversioned.
#[tokio::test]
async fn inspect_service_returns_a_too_new_version_rejection() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.43";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_service(SERVICE_ID)
        .await
        .expect_err("an unsupported version is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert!(
        fixture.request_line().starts_with(&format!(
            "GET {}/services/{SERVICE_ID} ",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        )),
        "the owned request was not the one refused"
    );
    assert!(
        !fixture.saw_retry(),
        "a version rejection was retried unversioned through the generated client"
    );

    fixture.finish();
}

/// On an authenticated forward-proxy route the owned transport replaces every
/// non-success response text with fixed safe text.
///
/// A malicious proxy can echo the configured credential in any encoding, so the
/// status is preserved and the words are not. The request is in absolute form
/// with the daemon's authority and the version prefix, it is sent once, and no
/// direct connection to the daemon is attempted.
#[tokio::test]
async fn inspect_service_withholds_error_text_on_an_authenticated_proxy() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind the unused target");
    let target_address = target.local_addr().expect("the target address");
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let proxy_address = proxy_listener.local_addr().expect("the proxy address");
    let (request_tx, first_request) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();

    // The proxy echoes the credential it was configured with, in the plainest
    // possible form, so a leak would be unmistakable.
    let body = r#"{"message":"proxy-user:proxy-password"}"#;
    let response = rejected("407 Proxy Authentication Required", body);
    let server = thread::spawn(move || {
        let mut stream = accept_tcp(&proxy_listener);
        let head = read_request(&mut stream).line;
        let _ = request_tx.send(head);
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
        .inspect_service(SERVICE_ID)
        .await
        .expect_err("a 407 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 407);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 407)"
    );

    // No rendering of the error may carry the proxy's words.
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    for (index, rendering) in renderings.iter().enumerate() {
        assert!(
            !rendering.contains("proxy-password") && !rendering.contains("proxy-user:"),
            "error rendering {index} echoed proxy-controlled text"
        );
    }

    let request_line = first_request
        .recv_timeout(Duration::from_secs(10))
        .expect("the proxy recorded no request");
    assert_eq!(
        request_line,
        format!(
            "GET http://{target_address}{}/services/{SERVICE_ID} HTTP/1.1",
            version_prefix(API_VERSION.major, API_VERSION.minor)
        ),
        "the proxied request is not absolute-form with the daemon authority"
    );
    assert!(
        retry.recv_timeout(Duration::from_millis(500)).is_err(),
        "the 407 was retried"
    );
    target
        .set_nonblocking(true)
        .expect("make the target listener nonblocking");
    assert!(
        target.accept().is_err(),
        "the 407 was followed by a direct connection to the daemon"
    );

    server.join().expect("the proxy thread");
}

/// A success body the owned decoder cannot read is a decode failure in its own
/// error class. The fallback suite sends the same bodies through the generated
/// client, where the same failure is `ErrorKind::Docker`.
#[tokio::test]
async fn inspect_service_rejects_malformed_and_wrongly_typed_documents() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_service(SERVICE_ID)
            .await
            .expect_err("a malformed service document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// An empty reference is refused before dispatch: `/services/` is the list
/// endpoint, not an inspect of nothing.
#[tokio::test]
async fn inspect_service_refuses_an_empty_reference_without_sending() {
    let fixture = Fixture::start(Vec::new());
    let error = fixture
        .client()
        .inspect_service("")
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("empty"),
        "the refusal did not name the empty reference: {error}"
    );
    assert!(
        fixture
            .requests
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "an empty reference was sent as a request"
    );

    fixture.finish();
}

/// A wrong-typed member must not echo response text through `Display`, `Debug`,
/// or the source chain.
///
/// `serde_json::Error`'s own `Display` quotes the unexpected value. The service
/// document is decoded by the generic owned decoder, so a value placed in a
/// wrong-typed member reached the error's `Display` and every source it wraps.
/// Both decode paths are covered: the document members and the projection wire
/// shapes added for `inspect_service`. The regression is load-bearing: it fails
/// on a decoder that embeds the response text and passes once the content-free
/// decode summary is assembled.
#[tokio::test]
async fn inspect_service_decode_errors_do_not_echo_the_canary() {
    for body in [
        canary_body(),
        // A projection input of the wrong type, on the endpoint path.
        format!(r#"{{"ID":"{SERVICE_ID}","Endpoint":{{"Ports":"{CANARY}"}}}}"#),
        // A projection input of the wrong type, on the task-count path.
        format!(r#"{{"ID":"{SERVICE_ID}","ServiceStatus":{{"RunningTasks":"{CANARY}"}}}}"#),
    ] {
        let fixture = Fixture::start(vec![ok_json(&body)]);
        let error = fixture
            .client()
            .inspect_service(SERVICE_ID)
            .await
            .expect_err("a wrongly typed service document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

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
                "decode error rendering {index} echoed response text"
            );
        }

        fixture.finish();
    }
}
