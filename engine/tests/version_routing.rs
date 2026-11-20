//! `DockerClient::{version, version_value}` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: both methods must open
//! `GET /v1.NN/version` through the owned transport when it can reach the
//! endpoint, rather than the unversioned path the generated client sends.
//! Asserting that against a request builder would only show what the builder
//! would produce if it were called; the routing decision is above it. A
//! loopback HTTP fixture is the only place the wire request and the routing are
//! the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing either `if let Ok(engine) = self.raw_engine()` arm puts the
//! generated client back on the wire, and the request line loses the version
//! prefix. That mutation is the reason the request line is compared whole.
//!
//! The malformed and missing-member tests pin the decoding contract. A known
//! member with the wrong JSON type still fails rather than reading as absent,
//! a missing member reads as `None`, and an unknown member is retained by
//! `version_value` while `version` ignores it. The rejection fixture proves a
//! failed owned request is returned rather than retried over the generated
//! client, and the unanswered fixture proves abandoning the future releases the
//! connection.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, DaemonVersion, DockerClient, ErrorKind};

#[path = "support/version_entries.rs"]
mod version_entries;

use version_entries::{
    DUPLICATE_COMPONENT_VERSION_BODY, DUPLICATE_VERSION_BODY, INVALID_THEN_VALID_COMPONENT_BODY,
    INVALID_THEN_VALID_VERSION_BODY, MALFORMED_COMPONENT_BODY, MALFORMED_JSON_BODY,
    MALFORMED_METADATA_BODY, MALFORMED_VERSION_BODY, MISSING_FIELDS_BODY, NON_OBJECT_BODY,
    NULL_FIELDS_BODY, VERSION_BODY, expected_daemon_version,
};

/// A one-request-at-a-time HTTP server that records each request head and then
/// waits for the client to release the connection.
///
/// The server closes every response with `Connection: close` so the client
/// cannot reuse the connection for the next call. Waiting for the client to
/// disconnect is what makes `finish` a statement about the client having
/// completed, rather than about the fixture having written bytes.
struct Fixture {
    endpoint: String,
    requests: Receiver<String>,
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
                let head = read_request_head(&mut stream);
                let _ = request_tx.send(head);
                stream
                    .write_all(&response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
                let mut buffer = [0_u8; 64];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                }
                let _ = stream.shutdown(Shutdown::Both);
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

    fn request_line(&self) -> String {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
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
        Self::start_response(rejected(status, body))
    }

    /// Answers one request with `response` and then watches for a second
    /// connection, which is what a retry or a second fetch would look like.
    fn start_response(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let head = read_request_head(&mut stream);
            let _ = request_tx.send(head);
            stream
                .write_all(&response)
                .expect("write the fixture answer");
            stream.flush().expect("flush the fixture answer");
            let mut buffer = [0_u8; 64];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
            }

            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request_head(&mut retry_stream);
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
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
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
            let head = read_request_head(&mut stream);
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
                        let _ = read_request_head(&mut retry_stream);
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

/// Reads the request head, which is all a version request sends.
fn read_request_head(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            request.truncate(end);
            return String::from_utf8_lossy(&request).into_owned();
        }
    }
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
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// The public method a test is exercising.
#[derive(Clone, Copy)]
enum Method {
    Version,
    VersionValue,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::VersionValue => "version_value",
        }
    }
}

/// Both methods send the versioned request and project the same five members
/// the generated path did.
///
/// The whole request line is compared because that is the assertion a wrong
/// transport fails: the generated client sends `/version` with no version.
#[tokio::test]
async fn version_sends_a_versioned_request_and_projects_known_fields() {
    let fixture = Fixture::start(vec![ok_json(VERSION_BODY), ok_json(VERSION_BODY)]);
    let client = fixture.client();

    let version = client.version().await.expect("the version decoded");
    assert_eq!(version, expected_daemon_version());
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/version HTTP/1.1", version_prefix()),
        "version fell back to the unversioned generated path"
    );

    let value = client
        .version_value()
        .await
        .expect("the version document decoded");
    assert_eq!(value["Version"].as_str(), Some("29.8.0"));
    assert_eq!(value["ApiVersion"].as_str(), Some("1.55"));
    assert_eq!(value["MinAPIVersion"].as_str(), Some("1.40"));
    assert_eq!(value["Os"].as_str(), Some("linux"));
    assert_eq!(value["Arch"].as_str(), Some("amd64"));
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/version HTTP/1.1", version_prefix()),
        "version_value fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The owned document retains an unknown member, while the projection ignores
/// it.
///
/// The generated path re-serializes a model that declares neither member, so
/// the same answer loses them there. That difference is documented on
/// `DockerClient::version_value`; this test pins the owned half.
#[tokio::test]
async fn version_value_retains_members_the_repository_model_does_not_name() {
    let fixture = Fixture::start(vec![ok_json(VERSION_BODY)]);
    let value = fixture
        .client()
        .version_value()
        .await
        .expect("the version document decoded");

    assert_eq!(
        value
            .get("FutureMember")
            .and_then(|member| member.get("nested"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the owned document dropped a member the generated model does not declare"
    );
    assert_eq!(
        value
            .get("Components")
            .and_then(|components| components.as_array())
            .and_then(|components| components.first())
            .and_then(|component| component.get("FutureComponentMember"))
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the owned document dropped an unknown nested member"
    );

    fixture.finish();
}

/// A missing projected member reads as absent rather than as a default.
#[tokio::test]
async fn version_reports_missing_members_as_absent() {
    let fixture = Fixture::start(vec![ok_json(MISSING_FIELDS_BODY)]);
    let version = fixture
        .client()
        .version()
        .await
        .expect("a document with one member decoded");

    assert_eq!(version.version.as_deref(), Some("29.8.0"));
    assert_eq!(version.api_version, None);
    assert_eq!(version.min_api_version, None);
    assert_eq!(version.os, None);
    assert_eq!(version.arch, None);

    fixture.finish();
}

/// An explicit `null` is absence to the projection but stays in the document.
#[tokio::test]
async fn version_treats_explicit_nulls_as_absent_and_keeps_them_in_the_document() {
    let fixture = Fixture::start(vec![ok_json(NULL_FIELDS_BODY), ok_json(NULL_FIELDS_BODY)]);
    let client = fixture.client();

    let version = client.version().await.expect("null members are absence");
    assert_eq!(
        version,
        DaemonVersion {
            version: None,
            api_version: None,
            min_api_version: None,
            os: None,
            arch: None,
        }
    );

    let value = client
        .version_value()
        .await
        .expect("a null-bearing document decoded");
    assert!(
        value["Version"].is_null(),
        "the owned document did not retain the explicit null"
    );

    fixture.finish();
}

/// A known member with the wrong JSON type still fails the decode.
///
/// The generated path reported this as `ErrorKind::Docker`; the owned decoder
/// reports `ErrorKind::InvalidInput`. The class difference is documented on
/// both methods, and this test pins that the refusal itself did not become a
/// silently absent value.
#[tokio::test]
async fn version_rejects_malformed_known_members() {
    for body in [
        MALFORMED_VERSION_BODY,
        MALFORMED_METADATA_BODY,
        MALFORMED_COMPONENT_BODY,
    ] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .version()
            .await
            .expect_err("a malformed known member must fail");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        let rendered = error.to_string();
        assert!(
            rendered.contains("failed to decode"),
            "the refusal did not name the decode: {rendered}"
        );
        assert!(rendered.contains("data error"), "{rendered}");
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
        fixture.finish();
    }
}

/// A duplicate known member, and an invalid value followed by a valid
/// duplicate, are rejected before the JSON document is projected.
///
/// The invalid-first cases are the ones a value-first validator misses: it
/// keeps the last value and accepts the body. The duplicate cases are the ones
/// `serde_json::Value` hides: it keeps the last key, while the generated model
/// rejects the duplicate. Both public methods must reject both shapes.
#[tokio::test]
async fn version_rejects_duplicate_and_invalid_first_known_members() {
    for body in [
        DUPLICATE_VERSION_BODY,
        DUPLICATE_COMPONENT_VERSION_BODY,
        INVALID_THEN_VALID_VERSION_BODY,
        INVALID_THEN_VALID_COMPONENT_BODY,
    ] {
        for method in [Method::Version, Method::VersionValue] {
            let fixture = Fixture::start(vec![ok_json(body)]);
            let client = fixture.client();
            let error = match method {
                Method::Version => client.version().await.map(|_| ()),
                Method::VersionValue => client.version_value().await.map(|_| ()),
            }
            .expect_err("a duplicate or invalid-first known member must fail");

            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
            let rendered = error.to_string();
            assert!(
                rendered.contains("failed to decode"),
                "{} did not name the decode: {rendered}",
                method.name()
            );
            assert!(rendered.contains("data error"), "{rendered}");
            assert!(rendered.contains("line"), "{rendered}");
            assert!(rendered.contains("column"), "{rendered}");

            fixture.finish();
        }
    }
}

/// Validation reuses the one response rather than fetching the document again.
///
/// A second connection is what a validator that re-requests the document would
/// open. The fixture watches for it after answering the first request.
#[tokio::test]
async fn version_validation_does_not_request_the_document_twice() {
    for method in [Method::Version, Method::VersionValue] {
        let fixture = RejectingFixture::start_response(ok_json(DUPLICATE_VERSION_BODY));
        let client = fixture.client();
        let error = match method {
            Method::Version => client.version().await.map(|_| ()),
            Method::VersionValue => client.version_value().await.map(|_| ()),
        }
        .expect_err("a duplicate Version must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            fixture.request_line(),
            format!("GET {}/version HTTP/1.1", version_prefix()),
            "{} did not send the owned request",
            method.name()
        );
        assert!(
            !fixture.saw_retry(),
            "{} fetched the version document a second time",
            method.name()
        );

        fixture.finish();
    }
}

/// `version_value` validates known members even though it returns the document
/// unchanged.
#[tokio::test]
async fn version_value_rejects_a_malformed_known_member() {
    let fixture = Fixture::start(vec![ok_json(MALFORMED_VERSION_BODY)]);
    let error = fixture
        .client()
        .version_value()
        .await
        .expect_err("a numeric Version is not a version document");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let rendered = error.to_string();
    assert!(rendered.contains("data error"), "{rendered}");
    assert!(rendered.contains("line"), "{rendered}");
    assert!(rendered.contains("column"), "{rendered}");
    fixture.finish();
}

/// A truncated success body is a decode failure rather than a transport
/// failure, because the daemon answered and the answer was not a document.
#[tokio::test]
async fn version_rejects_a_truncated_success_body() {
    let fixture = Fixture::start(vec![ok_json(MALFORMED_JSON_BODY)]);
    let error = fixture
        .client()
        .version()
        .await
        .expect_err("a truncated body is not a version document");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("failed to decode"),
        "the refusal did not name the decode: {error}"
    );
    fixture.finish();
}

/// Valid JSON that is not an object is refused by the document operation.
#[tokio::test]
async fn version_value_rejects_a_non_object_success_body() {
    let fixture = Fixture::start(vec![ok_json(NON_OBJECT_BODY)]);
    let error = fixture
        .client()
        .version_value()
        .await
        .expect_err("an array is not the version document");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("not a JSON object"),
        "the refusal did not name the shape: {error}"
    );
    fixture.finish();
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn version_reports_a_rejection_and_does_not_retry() {
    let message = "daemon is shutting down";
    let fixture = RejectingFixture::start(
        "503 Service Unavailable",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .version()
        .await
        .expect_err("a 503 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 503);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/version HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned version request was retried through the generated client"
    );

    fixture.finish();
}

/// `version_value` has the same rejection and no-retry contract.
#[tokio::test]
async fn version_value_reports_a_rejection_and_does_not_retry() {
    let message = "daemon is shutting down";
    let fixture = RejectingFixture::start(
        "503 Service Unavailable",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .version_value()
        .await
        .expect_err("a 503 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 503);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/version HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned version_value request was retried through the generated client"
    );

    fixture.finish();
}

/// Abandoning the request releases the connection and is not a retry.
///
/// The daemon never answers, so the fixture's read can only end when the client
/// releases the connection. It then watches for a second connection, which is
/// what a fallback after the abandoned request would look like.
#[tokio::test]
async fn version_releases_the_connection_when_the_caller_abandons_it() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move { client.version().await });

    let request = tokio::time::timeout(Duration::from_secs(10), fixture.request)
        .await
        .expect("the fixture saw no request")
        .expect("the fixture reported");
    assert_eq!(
        request
            .lines()
            .next()
            .expect("the request has a request line"),
        format!("GET {}/version HTTP/1.1", version_prefix()),
        "the abandoned request must be the owned one"
    );

    task.abort();
    let released = tokio::time::timeout(Duration::from_secs(10), fixture.released)
        .await
        .expect("the fixture did not observe the disconnect")
        .expect("the fixture reported");
    assert!(
        released,
        "abandoning the version future did not release the connection"
    );

    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "an abandoned owned version request was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
