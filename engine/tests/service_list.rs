//! `DockerClient::list_services` on the repository-owned transport.
//!
//! # Why a loopback fixture
//!
//! The claim is a transport claim: the list must open
//! `GET /v1.NN/services?…&status=true` through the owned transport when that
//! transport can reach the endpoint, rather than the unversioned path the
//! generated client sends — and it must send the same query the generated path
//! sent, `filters` before `status`. Asserting that against a request builder
//! would only show what the builder would produce if called; the routing
//! decision is above it. A loopback HTTP fixture is the one place the request on
//! the wire and the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `list_services`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, `Endpoint` and `PreviousSpec` disappear from each value, the
//! task template is rebuilt from Bollard's `TaskSpec`, and the decode error
//! class changes. Dropping `status=true` from the owned request makes the
//! daemon answer with `ServiceStatus: null`, which the status assertions catch.
//! Moving the raw contract — sending `status=true` there too, or applying the
//! facade's nullable projection — fails [`raw_list_keeps_its_original_contract`].
//!
//! # What is deliberately not asserted
//!
//! Nothing here claims a data-loss guarantee for `update_service`. That write
//! path still builds its body from Bollard's 1.53 `ServiceSpec`; the list read
//! does not change it, and `tests/service_inspect.rs` owns the round-trip
//! observation.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ForwardProxy, ProxyPolicy,
    SwarmListOptions,
};

#[path = "support/service_inspect_entries.rs"]
mod service_inspect_entries;

use service_inspect_entries::{
    CANARY, MALFORMED_BODY, MALFORMED_PROJECTION_BODIES, PROJECTION_CASES, SERVICE_BODY,
    SERVICE_ID, VERSION_INDEX, WRONG_TYPE_BODY, canary_body,
};

/// A request the fixture recorded: the request line and the body that followed.
struct Captured {
    line: String,
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

/// A server that answers one request and then watches for a retry.
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
                        let _ = retry_stream.write_all(&ok_json("[]"));
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

/// Reads the request head and, when `Content-Length` says so, the body.
fn read_request(stream: &mut TcpStream) -> Captured {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            assert_eq!(content_length, 0, "a list request carries no body");
            return Captured {
                line: head
                    .lines()
                    .next()
                    .expect("the request has a request line")
                    .to_owned(),
            };
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

/// A one-entry service array, which is the only shape `GET /services` answers.
fn list_body(entry: &str) -> String {
    format!("[{entry}]")
}

/// A service document carrying operator-controlled text at both depths the
/// owned route retains, for the `Debug` test.
fn body_with_secret(canary: &str) -> String {
    serde_json::json!({
        "ID": SERVICE_ID,
        "Version": {"Index": VERSION_INDEX},
        "Spec": {
            "Name": "web",
            "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx:alpine", "Env": [format!("TOKEN={canary}")]}
            }
        },
        "PreviousSpec": {
            "Name": "web",
            "TaskTemplate": {
                "ContainerSpec": {"Image": "nginx:1.25", "Env": [format!("TOKEN={canary}")]}
            }
        }
    })
    .to_string()
}

/// The owned list is versioned, asks for `status`, and keeps what the generated
/// route drops.
#[tokio::test]
async fn list_services_sends_the_versioned_status_query_and_retains_members() {
    let fixture = Fixture::start(vec![ok_json(&list_body(SERVICE_BODY))]);
    let services = fixture
        .client()
        .list_services(None)
        .await
        .expect("the service array decoded");

    assert_eq!(services.len(), 1);
    let service = &services[0];
    assert_eq!(service.id.as_deref(), Some(SERVICE_ID));
    assert_eq!(
        service.version.as_ref().and_then(|version| version.index),
        Some(VERSION_INDEX)
    );
    assert_eq!(
        service.status,
        Some(neotales_docker::ServiceStatus {
            running_tasks: 2,
            desired_tasks: 3,
        }),
        "the owned list did not project the task counts"
    );

    // Published ports are a projection of `Endpoint.Ports`; the endpoint stays
    // in `additional`, so a port member the projection cannot hold survives.
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

    // Members the generated 1.53 models cannot name.
    assert_eq!(
        service.additional["PreviousSpec"]["TaskTemplate"]["ContainerSpec"]["Image"],
        "nginx:1.25"
    );
    assert_eq!(service.additional["UpdateStatus"]["State"], "completed");
    assert_eq!(
        service.additional["UnmodelledMember"],
        serde_json::json!({"Value": 7})
    );
    let spec = service
        .spec
        .as_ref()
        .expect("the daemon sent a specification");
    assert_eq!(
        spec.additional["UnmodelledSpecMember"],
        serde_json::json!({"Nested": true})
    );
    assert_eq!(
        spec.task_template
            .as_ref()
            .and_then(|template| template.get("Placement")),
        Some(
            &serde_json::json!({"Constraints": ["node.role == worker"], "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}], "MaxReplicas": 3, "Platforms": [{"Architecture": "amd64", "OS": "linux"}]})
        ),
        "the owned list rewrote the task template instead of keeping it"
    );

    assert_eq!(
        fixture.next().line,
        format!("GET {}/services?status=true HTTP/1.1", version_prefix()),
        "list_services fell back to the unversioned generated path or dropped status"
    );

    fixture.finish();
}

/// An empty filter map is not sent, and a populated one precedes `status` in
/// `BTreeMap` key order with the caller's value order preserved.
///
/// This is the exact query the generated route sent, so a caller recording the
/// request sees the same line it saw before the transport changed — apart from
/// the version prefix, which is the owned transport's documented difference.
#[tokio::test]
async fn list_services_sends_no_empty_filters_and_filters_before_status() {
    let fixture = Fixture::start(vec![
        ok_json(&list_body(SERVICE_BODY)),
        ok_json(&list_body(SERVICE_BODY)),
    ]);
    let client = fixture.client();

    client
        .list_services(Some(SwarmListOptions::default()))
        .await
        .expect("the unfiltered list decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/services?status=true HTTP/1.1", version_prefix())
    );

    let mut filters = BTreeMap::new();
    filters.insert("name".to_owned(), vec!["web".to_owned(), "api".to_owned()]);
    filters.insert(
        "label".to_owned(),
        vec!["com.docker.stack.namespace=demo".to_owned()],
    );
    client
        .list_services(Some(SwarmListOptions { filters }))
        .await
        .expect("the filtered list decoded");

    let expected_filters = r#"{"label":["com.docker.stack.namespace=demo"],"name":["web","api"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/services?{}&status=true HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the owned list did not send the exact ordered filters before status"
    );

    fixture.finish();
}

/// The owned list uses the version configured on the client, not the crate's
/// default.
#[tokio::test]
async fn list_services_sends_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(&list_body(SERVICE_BODY))]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .list_services(None)
        .await
        .expect("the service array decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/services?status=true HTTP/1.1",
        "the owned list did not use the configured version"
    );

    fixture.finish();
}

/// The facade list accepts every projection shape the generated client accepts
/// and refuses every projection input it refuses.
///
/// `Endpoint` and `ServiceStatus` may be absent or `null`, `Ports` may be `null`
/// or empty, and a partial status is no status rather than zero counts. A member
/// of the wrong JSON type, or a value outside the Engine's enumeration, is a
/// decode failure — the two routes must not disagree about which documents they
/// accept.
#[tokio::test]
async fn list_services_matches_the_generated_projection_contract() {
    let fixture = Fixture::start(
        PROJECTION_CASES
            .iter()
            .map(|case| ok_json(&list_body(case.body)))
            .collect(),
    );
    let client = fixture.client();

    for case in PROJECTION_CASES {
        let services = client
            .list_services(None)
            .await
            .unwrap_or_else(|error| panic!("the owned list refused {}: {error}", case.what));
        assert_eq!(services.len(), 1, "{}", case.what);
        case.assert_projections(&services[0], "owned list");
        assert_eq!(
            services[0].additional.contains_key("Endpoint"),
            case.endpoint_retained,
            "owned list ({}): {:?}",
            case.what,
            services[0].additional
        );
        assert_eq!(
            fixture.next().line,
            format!("GET {}/services?status=true HTTP/1.1", version_prefix())
        );
    }

    let malformed = Fixture::start(
        MALFORMED_PROJECTION_BODIES
            .iter()
            .map(|(_, body)| ok_json(&list_body(body)))
            .collect(),
    );
    let client = malformed.client();
    for (what, _body) in MALFORMED_PROJECTION_BODIES {
        let error = client
            .list_services(None)
            .await
            .expect_err("a wrongly typed projection input is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}");
        assert!(
            error.to_string().contains("failed to decode"),
            "{what}: {error}"
        );
    }
    malformed.finish();
    fixture.finish();
}

/// `Debug` reports sizes and counts for the members the owned route retains.
///
/// The list value carries the previous revision's environment on the owned
/// route, so a `{:?}` in a panic message or a log line must not print it.
#[tokio::test]
async fn list_services_debug_withholds_retained_member_values() {
    const SECRET: &str = "canary-not-a-credential-8b2e";
    let fixture = Fixture::start(vec![ok_json(&list_body(&body_with_secret(SECRET)))]);
    let services = fixture
        .client()
        .list_services(None)
        .await
        .expect("the service array decoded");
    let service = &services[0];

    // Both copies are actually retained, so the assertion is about redaction
    // rather than absence.
    assert!(
        service.additional.contains_key("PreviousSpec"),
        "the owned route lost the previous specification"
    );
    assert!(
        serde_json::to_string(service)
            .expect("the value serializes")
            .contains(SECRET),
        "explicit serialization is not redacted, so the secret must be present"
    );

    let rendered = format!("{service:?}");
    assert!(
        !rendered.contains(SECRET),
        "`Debug` rendered a retained environment: {rendered}"
    );
    assert!(
        rendered.contains("additional: 1 unmodeled member(s)"),
        "`Debug` did not report the retained-member count: {rendered}"
    );

    let spec = service
        .spec
        .as_ref()
        .expect("the daemon sent a specification");
    let rendered = format!("{spec:?}");
    assert!(
        !rendered.contains(SECRET),
        "`Debug` rendered the current environment: {rendered}"
    );

    fixture.finish();
}

/// A malformed success body is the owned decode class.
#[tokio::test]
async fn list_services_rejects_malformed_documents() {
    for body in [
        MALFORMED_BODY.to_owned(),
        WRONG_TYPE_BODY.to_owned(),
        canary_body(),
    ] {
        let fixture = Fixture::start(vec![ok_json(&body)]);
        let error = fixture
            .client()
            .list_services(None)
            .await
            .expect_err("a malformed service array is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// A decode failure must not echo response text through `Display`, `Debug`, or
/// the source chain.
#[tokio::test]
async fn list_services_decode_errors_do_not_echo_the_canary() {
    let body = list_body(&format!(r#"{{"Version":"{CANARY}"}}"#));
    let fixture = Fixture::start(vec![ok_json(&body)]);
    let error = fixture
        .client()
        .list_services(None)
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

/// A daemon rejection keeps its status and message, and is not retried.
#[tokio::test]
async fn list_services_reports_a_rejection_and_does_not_retry() {
    let message = "service listing unavailable";
    let fixture = RejectingFixture::start(
        "500 Internal Server Error",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .list_services(None)
        .await
        .expect_err("a 500 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/services?status=true HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned list request was retried through the generated client"
    );

    fixture.finish();
}

/// On an authenticated forward-proxy route the owned transport replaces every
/// non-success response text with fixed safe text.
#[tokio::test]
async fn list_services_withholds_error_text_on_an_authenticated_proxy() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind the unused target");
    let target_address = target.local_addr().expect("the target address");
    let proxy_listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    let proxy_address = proxy_listener.local_addr().expect("the proxy address");
    let (request_tx, first_request) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();

    // The proxy echoes the credential it was configured with.
    let body = r#"{"message":"proxy-user:proxy-password"}"#;
    let response = rejected("407 Proxy Authentication Required", body);
    let server = thread::spawn(move || {
        let (mut stream, _) = proxy_listener.accept().expect("accept the proxied request");
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
        .list_services(None)
        .await
        .expect_err("a 407 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the proxy status is preserved");
    assert_eq!(api.status_code, 407);
    assert_eq!(
        api.message,
        "response text withheld for an authenticated forward proxy (HTTP 407)"
    );

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
            "GET http://{target_address}{}/services?status=true HTTP/1.1",
            version_prefix()
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

/// The public raw list keeps the request and projection it always had.
///
/// It does not send `status=true`, and it keeps the strict projection: a present
/// `Ports` or `ServiceStatus` that cannot decode is an error, while a value the
/// repository model cannot hold makes the projection absent. The facade is the
/// operation that asks for task counts and applies the nullable rules.
#[tokio::test]
async fn raw_list_keeps_its_original_contract() {
    let fixture = Fixture::start(vec![
        ok_json(&list_body(SERVICE_BODY)),
        ok_json(&list_body(
            r#"{"Endpoint":{"Ports":[{"Protocol":"future"}]}}"#,
        )),
        ok_json(&list_body(r#"{"ServiceStatus":{"RunningTasks":1}}"#)),
    ]);
    let client = fixture.client();
    let engine = client.raw_engine().expect("the owned transport");

    let mut filters = BTreeMap::new();
    filters.insert("name".to_owned(), vec!["web".to_owned()]);
    let services = neotales_docker::raw::service_list(
        &engine,
        &SwarmListOptions {
            filters: filters.clone(),
        },
    )
    .await
    .expect("the raw list decoded");

    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", r#"{"name":["web"]}"#);
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/services?{} HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the raw list must not send status=true"
    );
    assert_eq!(services[0].id.as_deref(), Some(SERVICE_ID));

    // A protocol string outside the Engine's enumeration is accepted by raw.
    let services = neotales_docker::raw::service_list(&engine, &SwarmListOptions::default())
        .await
        .expect("raw accepts an arbitrary protocol string");
    assert_eq!(
        services[0].ports.as_ref().unwrap()[0].protocol.as_deref(),
        Some("future")
    );
    assert_eq!(
        fixture.next().line,
        format!("GET {}/services HTTP/1.1", version_prefix())
    );

    // A partial status is a decode failure on raw and no projection on the
    // facade.
    let error = neotales_docker::raw::service_list(&engine, &SwarmListOptions::default())
        .await
        .expect_err("raw requires both task counts");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let _ = fixture.next();

    fixture.finish();
}
