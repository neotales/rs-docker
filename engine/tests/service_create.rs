//! `DockerClient::create_service` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `create_service` must open
//! `POST /v1.NN/services/create` through the owned transport on an endpoint it
//! reaches, and it must not open a generated request at all. A request-builder
//! assertion would only show what the builder produces; the routing and the
//! fail-closed decision are above it. A loopback HTTP fixture is the only place
//! the wire request, the routing, and the withheld error are the same
//! observation.
//!
//! # What is deliberately asserted rather than assumed
//!
//! - The body carries service environment and service secret references
//!   verbatim, and the typed placement and restart policy land inside
//!   `TaskTemplate` rather than at the specification root.
//! - The credential form sends `X-Registry-Auth` in the Engine's URL-safe
//!   alphabet and never renders the password.
//! - A daemon rejection keeps its status, withholds its text, is sent once, and
//!   is never retried through the generated client.
//! - A malformed success document is a content-free decode error.
//!
//! No test starts a daemon or reads a real credential. The local dispatch and
//! logging behavior is in `service_create_local.rs`.

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
    API_VERSION, DockerClient, ErrorKind, RegistryCredentials, ServicePlacement,
    ServiceRestartPolicy, ServiceSpec,
};

/// The service ID every successful answer reports.
const SERVICE_ID: &str = "service0123456789abcdef";

/// A value placed in the service environment, where a service secret lives.
const ENV_CANARY: &str = "canary-create-service-env-2f81-do-not-log-me";

/// A registry password that must never appear in a body or a rendering.
const SECRET_CANARY: &str = "canary-create-registry-secret-91bd-do-not-log-me";

/// A secret name carried in `ContainerSpec.Secrets`.
const SECRET_NAME_CANARY: &str = "canary-create-secret-name-6c3a";

/// The fixed message every service-create failure must carry.
const WITHHELD_CREATE: &str = "response text withheld for a service create because the request may carry service environment, service secrets, or registry credentials";

/// A recorded request: the request line, headers, and body.
#[derive(Debug)]
struct Captured {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
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

/// The version prefix the owned transport is expected to send.
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// A complete specification with both a secret-bearing task template and the
/// typed placement and restart policy.
fn complete_spec() -> ServiceSpec {
    ServiceSpec {
        name: Some("web".to_owned()),
        labels: Some(BTreeMap::from([(
            "org.example.team".to_owned(),
            "platform".to_owned(),
        )])),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {
                "Image": "registry.example/team/app:stable",
                "Env": [format!("API_TOKEN={ENV_CANARY}")],
                "Secrets": [{
                    "SecretName": SECRET_NAME_CANARY,
                    "File": {"Name": "api-token", "Mode": 256}
                }]
            },
            "Resources": {"Limits": {"NanoCPUs": 500_000_000}}
        })),
        mode: Some(serde_json::json!({"Replicated": {"Replicas": 3}})),
        placement: Some(ServicePlacement {
            constraints: vec!["node.role == worker".to_owned()],
            preferences: vec!["spread=node.labels.zone".to_owned()],
            max_replicas: 2,
        }),
        restart_policy: Some(ServiceRestartPolicy {
            condition: "on-failure".to_owned(),
            delay: Some(5_000_000_000),
            max_attempts: Some(3),
            window: Some(20_000_000_000),
            failure_action: Some("pause".to_owned()),
        }),
        ..ServiceSpec::default()
    }
}

#[tokio::test]
async fn create_service_sends_the_versioned_request_and_the_whole_specification() {
    let fixture = Fixture::start(vec![created(
        r#"{"ID":"service0123456789abcdef","Warnings":["no suitable nodes"]}"#,
    )]);
    let result = fixture
        .client()
        .create_service(complete_spec())
        .await
        .expect("the owned create decoded the answer");

    assert_eq!(result.id, SERVICE_ID);
    assert_eq!(result.warnings, vec!["no suitable nodes".to_owned()]);

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!("POST {}/services/create HTTP/1.1", version_prefix()),
        "the create did not use the versioned owned route"
    );
    assert!(
        request
            .header("content-type")
            .is_some_and(|value| value.starts_with("application/json")),
        "the create body is not declared JSON"
    );
    assert_eq!(
        request.header("x-registry-auth"),
        None,
        "the uncredentialed create sent a credential header"
    );

    let body = request.json();
    assert_eq!(body["Name"], "web");
    assert_eq!(body["Labels"]["org.example.team"], "platform");
    assert_eq!(
        body["TaskTemplate"]["ContainerSpec"]["Env"][0],
        format!("API_TOKEN={ENV_CANARY}")
    );
    assert_eq!(
        body["TaskTemplate"]["ContainerSpec"]["Secrets"][0]["SecretName"],
        SECRET_NAME_CANARY
    );
    assert_eq!(
        body["TaskTemplate"]["Placement"]["Constraints"][0],
        "node.role == worker"
    );
    assert_eq!(
        body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
        "node.labels.zone"
    );
    assert_eq!(
        body["TaskTemplate"]["RestartPolicy"]["Condition"],
        "on-failure"
    );
    assert_eq!(body["TaskTemplate"]["RestartPolicy"]["MaxAttempts"], 3);
    assert!(
        body.get("Placement").is_none() && body.get("RestartPolicy").is_none(),
        "a typed member was sent at the specification root: {body}"
    );

    fixture.finish();
}

#[tokio::test]
async fn create_service_with_credentials_sends_the_engine_auth_header() {
    let fixture = Fixture::start(vec![created(r#"{"ID":"service0123456789abcdef"}"#)]);
    let credentials = RegistryCredentials::new("probeuser", SECRET_CANARY);
    let rendered = format!("{credentials:?} {credentials}");
    assert!(
        !rendered.contains(SECRET_CANARY),
        "the credential rendered its password"
    );

    fixture
        .client()
        .create_service_with_credentials(complete_spec(), "registry.example", credentials)
        .await
        .expect("the credentialed owned create decoded the answer");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!("POST {}/services/create HTTP/1.1", version_prefix())
    );
    let header = request
        .header("x-registry-auth")
        .expect("the credential header is sent");
    let decoded = URL_SAFE
        .decode(header)
        .expect("the Engine's URL-safe alphabet");
    let auth: serde_json::Value =
        serde_json::from_slice(&decoded).expect("the auth header is JSON");
    assert_eq!(
        auth,
        serde_json::json!({
            "username": "probeuser",
            "password": SECRET_CANARY,
            "serveraddress": "registry.example"
        })
    );
    assert!(
        !String::from_utf8_lossy(&request.body).contains(SECRET_CANARY),
        "the password leaked into the request body"
    );
    assert!(
        !String::from_utf8_lossy(&request.body).contains(header),
        "the encoded credential leaked into the request body"
    );

    fixture.finish();
}

#[tokio::test]
async fn create_service_with_an_unrelated_credential_is_refused_before_dispatch() {
    let fixture = Fixture::start(Vec::new());
    let credentials =
        RegistryCredentials::new("probeuser", SECRET_CANARY).with_server_address("other.example");

    let error = fixture
        .client()
        .create_service_with_credentials(complete_spec(), "registry.example", credentials)
        .await
        .expect_err("a credential for another registry is refused");

    assert_eq!(error.kind(), ErrorKind::Credentials);
    assert_error_is_content_free(&error, SECRET_CANARY);
    assert!(
        fixture
            .requests
            .recv_timeout(Duration::from_millis(200))
            .is_err(),
        "a credential mismatch was sent as a request"
    );

    fixture.finish();
}

#[tokio::test]
async fn create_service_withholds_a_daemon_rejection_and_does_not_retry() {
    let fixture = Fixture::start(vec![rejected(
        "400 Bad Request",
        &format!(
            r#"{{"message":"invalid service: API_TOKEN={ENV_CANARY} secret={SECRET_NAME_CANARY}"}}"#
        ),
    )]);

    let error = fixture
        .client()
        .create_service(complete_spec())
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, WITHHELD_CREATE);
    assert_error_is_content_free(&error, ENV_CANARY);
    assert_error_is_content_free(&error, SECRET_NAME_CANARY);
    for rendering in renderings(&error) {
        assert!(
            !rendering.contains("invalid service"),
            "the withheld error echoed the daemon's text: {rendering}"
        );
    }

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!("POST {}/services/create HTTP/1.1", version_prefix()),
        "the rejection path did not use the owned request"
    );
    assert!(
        fixture
            .requests
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "a failed owned create was retried through the generated client"
    );

    fixture.finish();
}

#[tokio::test]
async fn create_service_rejects_a_malformed_success_document_without_echoing_it() {
    let canary = "canary-create-decode-do-not-echo-4e2d";
    for body in [
        format!(r#"{{"ID":"{SERVICE_ID}","unterminated":{canary}"#),
        format!(r#"{{"ID":{canary}}}"#),
        format!(r#"{{"ID":"{SERVICE_ID}","Warnings":"{canary}"}}"#),
    ] {
        let fixture = Fixture::start(vec![created(&body)]);
        let error = fixture
            .client()
            .create_service(complete_spec())
            .await
            .expect_err("a malformed create answer is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_error_is_content_free(&error, canary);
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// A `201` answer carrying `body`.
fn created(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A non-success answer carrying `body`.
fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
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

/// Reads one bounded request and returns its line, headers, and body.
fn read_request(stream: &mut TcpStream) -> Captured {
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

/// Every rendering of an error and its source chain.
fn renderings(error: &neotales_docker::Error) -> Vec<String> {
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    renderings
}

/// Asserts no rendering of an error carries `canary`.
fn assert_error_is_content_free(error: &neotales_docker::Error, canary: &str) {
    let renderings = renderings(error);
    assert!(
        renderings.len() > 1,
        "the error carried no source chain, so the assertion would be vacuous"
    );
    for rendering in renderings {
        assert!(
            !rendering.contains(canary),
            "an error rendering echoed request content: {rendering}"
        );
    }
}
