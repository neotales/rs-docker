//! `DockerClient::list_secrets` and `DockerClient::inspect_secret` on the
//! repository-owned transport.
//!
//! # Why a loopback fixture
//!
//! The claim is a transport claim: both reads must open the versioned
//! `/v1.NN/secrets` paths through the owned transport when it can reach the
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
//! # Secret data
//!
//! The Engine does not return `SecretSpec.Data` from a read. The documents
//! below nevertheless carry an unexpected `Data` member, because the contract
//! for one is what the security half of this suite pins: it is retained in the
//! value (so a caller can see the peer sent it), it never appears in `Debug`,
//! and explicit serialization still carries the peer's document. The synthetic
//! canary is used in every value-bearing member, so a redaction written against
//! `Data` alone fails.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, Error, ErrorKind, SecretListOptions,
    SecretUpdateOptions, SwarmListOptions, SwarmSecretSpec, raw,
};

#[path = "support/swarm_secret_entries.rs"]
mod swarm_secret_entries;

use swarm_secret_entries::{
    MALFORMED_BODY, SECRET_BODY, SECRET_BODY_WITH_ARRAY_DATA, SECRET_BODY_WITH_DATA,
    SECRET_BODY_WITH_DUPLICATE_DATA, SECRET_BODY_WITH_DUPLICATE_ID, SECRET_BODY_WITH_NULL_DATA,
    SECRET_BODY_WITH_NUMBER_DATA, SECRET_BODY_WITH_OBJECT_DATA, SECRET_DATA_BASE64,
    SECRET_DATA_CANARY, SECRET_ID, VERSION_INDEX, WRONG_TYPE_BODY, secrets_body,
    secrets_body_with_data,
};

/// The fixed message every secret-read API rejection reports.
const SECRET_READ_API_WITHHELD: &str =
    "the secret read failed; the Engine response text is withheld";

/// A request the fixture recorded: the request line and any body.
struct Captured {
    line: String,
    body: Vec<u8>,
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
                        let _ = retry_stream.write_all(&ok_json(SECRET_BODY));
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

/// Asserts a rendered value contains no form of the secret canary.
fn assert_no_secret(rendered: &str) {
    assert!(
        !rendered.contains(SECRET_DATA_CANARY),
        "a rendering leaked the secret canary as text: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET_DATA_BASE64),
        "a rendering leaked the base64 secret canary: {rendered}"
    );
    let decimal = SECRET_DATA_CANARY
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !rendered.contains(&decimal),
        "a rendering leaked the secret canary as a decimal byte list: {rendered}"
    );
    let mut hex = String::new();
    for byte in SECRET_DATA_CANARY.as_bytes() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    assert!(
        !rendered.contains(&hex),
        "a rendering leaked the secret canary as a hex byte list: {rendered}"
    );
}

/// Renders the whole `Display`/`Debug`/source chain of an error.
fn error_renderings(error: &Error) -> Vec<String> {
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    renderings
}

/// The owned list is versioned and retains members Bollard's 1.53 models drop.
#[tokio::test]
async fn list_secrets_sends_a_versioned_request_and_retains_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(&secrets_body())]);
    let secrets = fixture
        .client()
        .list_secrets(None)
        .await
        .expect("the secret array decoded");

    assert_eq!(secrets.len(), 1);
    let secret = &secrets[0];
    assert_eq!(secret.id.as_deref(), Some(SECRET_ID));
    assert_eq!(
        secret.version.as_ref().and_then(|version| version.index),
        Some(VERSION_INDEX)
    );
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("fixture-secret"));
    assert_eq!(
        spec.labels
            .as_ref()
            .and_then(|labels| labels.get("org.example.secret"))
            .map(String::as_str),
        Some("fixture")
    );
    assert_eq!(
        spec.driver
            .as_ref()
            .and_then(|driver| driver.get("Name"))
            .and_then(serde_json::Value::as_str),
        Some("vault")
    );
    assert_eq!(
        secret.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": 7})),
        "the owned path discarded an unmodelled top-level secret member"
    );
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true})),
        "the owned path discarded an unmodelled spec member"
    );
    assert_eq!(
        fixture.next().line,
        format!("GET {}/secrets HTTP/1.1", version_prefix()),
        "list_secrets fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// An empty filter map is not sent, and a populated one is sent in `BTreeMap`
/// key order with the caller's value order preserved.
#[tokio::test]
async fn list_secrets_sends_no_empty_filters_and_exact_ordered_filters() {
    let fixture = Fixture::start(vec![ok_json(&secrets_body()), ok_json(&secrets_body())]);
    let client = fixture.client();

    client
        .list_secrets(Some(SecretListOptions::default()))
        .await
        .expect("the unfiltered list decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/secrets HTTP/1.1", version_prefix())
    );

    let mut filters = BTreeMap::new();
    filters.insert("name".to_owned(), vec![SECRET_ID.to_owned()]);
    filters.insert(
        "id".to_owned(),
        vec!["secret-one".to_owned(), "secret-two".to_owned()],
    );
    filters.insert(
        "label".to_owned(),
        vec!["org.example.secret=fixture".to_owned()],
    );
    client
        .list_secrets(Some(SecretListOptions { filters }))
        .await
        .expect("the filtered list decoded");

    let expected_filters = r#"{"id":["secret-one","secret-two"],"label":["org.example.secret=fixture"],"name":["secret-fixture"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/secrets?{} HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the owned list did not send the exact ordered filters"
    );

    fixture.finish();
}

/// The owned list uses the API version the client was configured with.
#[tokio::test]
async fn list_secrets_sends_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(&secrets_body())]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .list_secrets(None)
        .await
        .expect("the secret array decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/secrets HTTP/1.1",
        "the owned list did not use the configured version"
    );

    fixture.finish();
}

/// The owned inspect is versioned and retains the whole secret document.
#[tokio::test]
async fn inspect_secret_sends_a_versioned_request_and_retains_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(SECRET_BODY)]);
    let secret = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect("the secret document decoded");

    assert_eq!(secret.id.as_deref(), Some(SECRET_ID));
    assert_eq!(
        secret.version.as_ref().and_then(|version| version.index),
        Some(VERSION_INDEX)
    );
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("fixture-secret"));
    assert_eq!(
        secret.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": 7}))
    );
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true}))
    );
    assert_eq!(
        fixture.next().line,
        format!("GET {}/secrets/{SECRET_ID} HTTP/1.1", version_prefix()),
        "inspect_secret fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The owned inspect sends the configured version and encodes the reference
/// into exactly one path segment.
#[tokio::test]
async fn inspect_secret_sends_the_configured_version_and_encodes_the_reference() {
    let fixture = Fixture::start(vec![ok_json(SECRET_BODY)]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .inspect_secret("secret id/with?slash")
        .await
        .expect("the secret document decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/secrets/secret%20id%2Fwith%3Fslash HTTP/1.1",
        "the owned path did not use the configured version or one encoded segment"
    );

    fixture.finish();
}

/// The owned path refuses an empty reference before dispatch.
#[tokio::test]
async fn inspect_secret_rejects_an_empty_reference_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .inspect_secret("")
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

/// A daemon rejection keeps its status and withholds its text, and a failed
/// owned request is not retried over the generated client.
#[tokio::test]
async fn inspect_secret_reports_a_rejection_and_does_not_retry() {
    const MESSAGE_CANARY: &str = "daemon-echo-secret-4c1e";
    let message = format!("secret {SECRET_ID} not found {MESSAGE_CANARY}");
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, SECRET_READ_API_WITHHELD);
    for rendering in error_renderings(&error) {
        assert!(
            !rendering.contains(MESSAGE_CANARY),
            "the rejection echoed the daemon text: {rendering}"
        );
    }
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/secrets/{SECRET_ID} HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned inspect_secret request was retried through the generated client"
    );

    fixture.finish();
}

/// An older daemon's "client version too new" rejection is the daemon's answer,
/// not a reason to fall back, and it is not retried.
#[tokio::test]
async fn inspect_secret_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    const MESSAGE_CANARY: &str = "daemon-echo-version-7d2a";
    let message = format!(
        "client version 1.55 is too new. Maximum supported API version is 1.41 {MESSAGE_CANARY}"
    );
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, SECRET_READ_API_WITHHELD);
    for rendering in error_renderings(&error) {
        assert!(
            !rendering.contains(MESSAGE_CANARY),
            "the rejection echoed the daemon text: {rendering}"
        );
    }
    assert!(
        !fixture.saw_retry(),
        "an old-daemon rejection was retried through the generated client"
    );

    fixture.finish();
}

/// A success body the owned decoder cannot read is a decode failure in its own
/// error class, for both reads.
#[tokio::test]
async fn secret_reads_reject_malformed_and_wrongly_typed_documents() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_secret(SECRET_ID)
            .await
            .expect_err("a malformed secret document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();

        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .list_secrets(None)
            .await
            .expect_err("a malformed secret array is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        fixture.finish();
    }
}

/// Secret data must not be echoed through `Display`, `Debug`, or the source
/// chain of a decode failure.
#[tokio::test]
async fn secret_decode_errors_do_not_echo_secret_data_canaries() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_secret(SECRET_ID)
            .await
            .expect_err("a malformed secret document is refused");

        for rendering in error_renderings(&error) {
            assert_no_secret(&rendering);
        }

        fixture.finish();
    }
}

/// An unexpected `Spec.Data` is retained for a caller that asks, and is never
/// printed by `Debug` — including through the update-options wrapper.
#[tokio::test]
async fn unexpected_secret_data_is_retained_but_never_debugged() {
    let fixture = Fixture::start(vec![ok_json(SECRET_BODY_WITH_DATA)]);
    let secret = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect("the secret document decoded");
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");

    assert_eq!(
        spec.additional.get("Data"),
        Some(&serde_json::json!(SECRET_DATA_BASE64)),
        "the unexpected Data member was dropped instead of retained"
    );
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!(SECRET_DATA_CANARY))
    );

    assert_no_secret(&format!("{secret:?}"));
    assert_no_secret(&format!("{spec:?}"));
    let options = SecretUpdateOptions {
        version: VERSION_INDEX,
        spec: spec.clone(),
    };
    assert_no_secret(&format!("{options:?}"));

    let serialized = serde_json::to_string(&secret).expect("the secret serializes");
    assert!(
        serialized.contains(SECRET_DATA_BASE64),
        "explicit serialization must still carry the peer's document: {serialized}"
    );

    fixture.finish();
}

/// The owned list applies the same rule to every entry.
#[tokio::test]
async fn unexpected_secret_data_in_a_list_is_retained_but_never_debugged() {
    let fixture = Fixture::start(vec![ok_json(&secrets_body_with_data())]);
    let secrets = fixture
        .client()
        .list_secrets(None)
        .await
        .expect("the secret array decoded");
    let secret = &secrets[0];
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(
        spec.additional.get("Data"),
        Some(&serde_json::json!(SECRET_DATA_BASE64))
    );
    assert_no_secret(&format!("{secret:?}"));
    assert!(
        serde_json::to_string(secret)
            .expect("the secret serializes")
            .contains(SECRET_DATA_BASE64)
    );

    fixture.finish();
}

/// An unexpected `Data` is refused by the generated write before dispatch, so it
/// is neither forwarded nor quoted.
#[tokio::test]
async fn update_secret_refuses_unexpected_data_without_dispatching() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let mut additional = BTreeMap::new();
    additional.insert("Data".to_owned(), serde_json::json!(SECRET_DATA_BASE64));
    let error = client
        .update_secret(
            SECRET_ID,
            SecretUpdateOptions {
                version: VERSION_INDEX,
                spec: SwarmSecretSpec {
                    name: Some(String::from("fixture-secret")),
                    additional,
                    ..SwarmSecretSpec::default()
                },
            },
        )
        .await
        .expect_err("an unexpected Data member is refused");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let renderings = error_renderings(&error);
    let summary = renderings.join("\n");
    assert!(
        summary.contains("Data member"),
        "the refusal did not name the member: {summary}"
    );
    for rendering in &renderings {
        assert_no_secret(rendering);
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the refused update reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// An owned JSON driver is serialized without a generated model conversion.
#[tokio::test]
async fn update_secret_preserves_an_arbitrary_owned_driver() {
    let fixture = Fixture::start(vec![ok_json("{}")]);
    fixture
        .client()
        .update_secret(
            SECRET_ID,
            SecretUpdateOptions {
                version: VERSION_INDEX,
                spec: SwarmSecretSpec {
                    driver: Some(serde_json::json!(SECRET_DATA_CANARY)),
                    ..SwarmSecretSpec::default()
                },
            },
        )
        .await
        .expect("the owned update is accepted");
    let captured = fixture.next();
    let body: serde_json::Value = serde_json::from_slice(&captured.body).unwrap();
    assert_eq!(body["Driver"], SECRET_DATA_CANARY);
    fixture.finish();
}

/// An unexpected `Data` of every JSON type is retained on the owned path.
///
/// The generated fallback's typed `Data` cannot carry `null` (it reads it as
/// absent) or a non-string (it refuses the type), so this is the route where the
/// value shapes differ. `Debug` withholds all of them and `Serialize` carries
/// the exact JSON the peer sent.
#[tokio::test]
async fn unexpected_secret_data_of_every_json_type_is_retained_and_debug_safe() {
    for (body, expected) in [
        (SECRET_BODY_WITH_NULL_DATA, serde_json::Value::Null),
        (SECRET_BODY_WITH_NUMBER_DATA, serde_json::json!(123)),
        (
            SECRET_BODY_WITH_OBJECT_DATA,
            serde_json::json!({"canary": SECRET_DATA_CANARY}),
        ),
        (
            SECRET_BODY_WITH_ARRAY_DATA,
            serde_json::json!([SECRET_DATA_CANARY]),
        ),
    ] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let secret = fixture
            .client()
            .inspect_secret(SECRET_ID)
            .await
            .expect("the secret document decoded");
        let spec = secret.spec.as_ref().expect("the daemon sent a spec");
        assert_eq!(
            spec.additional.get("Data"),
            Some(&expected),
            "the owned path did not retain the {expected} Data value"
        );

        assert_no_secret(&format!("{secret:?}"));
        let serialized = serde_json::to_value(&secret).expect("the secret serializes");
        assert_eq!(
            serialized["Spec"]["Data"], expected,
            "explicit serialization did not carry the peer's Data value"
        );

        fixture.finish();
    }
}

/// Two unmodelled `Data` keys collapse to the last value in the owned decoder.
///
/// A JSON object cannot carry both, and the model has one `additional` slot.
/// This is a documented limit of the read, not a lossless claim; the value that
/// survives is still withheld from `Debug` and carried by `Serialize`.
#[tokio::test]
async fn duplicate_unmodelled_data_collapses_to_the_last_value() {
    let fixture = Fixture::start(vec![ok_json(SECRET_BODY_WITH_DUPLICATE_DATA)]);
    let secret = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect("the secret document decoded");
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(
        spec.additional.get("Data"),
        Some(&serde_json::json!(SECRET_DATA_BASE64)),
        "the owned decoder did not keep the last duplicate value"
    );
    assert_no_secret(&format!("{secret:?}"));
    assert!(
        serde_json::to_string(&secret)
            .expect("the secret serializes")
            .contains(SECRET_DATA_BASE64)
    );

    fixture.finish();
}

/// A duplicate known key is a decode error, and the error does not echo it.
#[tokio::test]
async fn duplicate_known_keys_are_refused_without_echoing_the_value() {
    for body in [SECRET_BODY_WITH_DUPLICATE_ID, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_secret(SECRET_ID)
            .await
            .expect_err("a duplicate or wrongly typed known member is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        for rendering in error_renderings(&error) {
            assert_no_secret(&rendering);
        }
        fixture.finish();
    }
}

/// A valid specification reaches the owned update with the same body.
#[tokio::test]
async fn update_secret_sends_the_expected_owned_body() {
    let fixture = Fixture::start(vec![ok_json("{}")]);
    let client = fixture.client();
    let mut labels = BTreeMap::new();
    labels.insert("org.example.secret".to_owned(), "fixture".to_owned());
    client
        .update_secret(
            SECRET_ID,
            SecretUpdateOptions {
                version: VERSION_INDEX,
                spec: SwarmSecretSpec {
                    name: Some(String::from("fixture-secret")),
                    labels: Some(labels),
                    ..SwarmSecretSpec::default()
                },
            },
        )
        .await
        .expect("the generated update was accepted");

    let captured = fixture.next();
    assert_eq!(
        captured.line,
        format!(
            "POST {}/secrets/{SECRET_ID}/update?version={VERSION_INDEX} HTTP/1.1",
            version_prefix()
        ),
        "the generated update path or version changed"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&captured.body).expect("the request body is JSON");
    assert_eq!(
        body,
        serde_json::json!({
            "Name": "fixture-secret",
            "Labels": {"org.example.secret": "fixture"}
        }),
        "the generated update body changed"
    );

    fixture.finish();
}

/// A reserved key in `additional` is refused before dispatch, including a
/// case-folded spelling and even when the typed field is absent.
///
/// The Engine's Go decoder matches JSON field names without regard to case, so
/// `data` or `NAME` reaches the daemon as `Data`/`Name` even though this crate's
/// serde models would not bind it. The guard must therefore compare ASCII
/// case-insensitively. A transport error would mean it dispatched; the local
/// `InvalidInput` is the proof it did not.
#[tokio::test]
async fn update_secret_refuses_case_folded_reserved_keys_without_dispatch() {
    for (key, expected) in [
        ("Data", "Data member"),
        ("data", "Data member"),
        ("DATA", "Data member"),
        ("dAtA", "Data member"),
        ("Name", "reserved member"),
        ("name", "reserved member"),
        ("NAME", "reserved member"),
        ("Labels", "reserved member"),
        ("labels", "reserved member"),
        ("Driver", "reserved member"),
        ("driver", "reserved member"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let address = listener.local_addr().expect("the fixture address");
        let client = DockerClient::connect_http(&format!("http://{address}"))
            .expect("build the fixture client");

        let mut additional = BTreeMap::new();
        additional.insert(key.to_owned(), serde_json::json!(SECRET_DATA_CANARY));
        let error = client
            .update_secret(
                SECRET_ID,
                SecretUpdateOptions {
                    version: VERSION_INDEX,
                    // Every typed field is absent: the guard must not depend on
                    // one being set to notice the reserved `additional` key.
                    spec: SwarmSecretSpec {
                        additional,
                        ..SwarmSecretSpec::default()
                    },
                },
            )
            .await
            .expect_err("a case-folded reserved key is refused");

        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key}");
        let summary = error_renderings(&error).join("\n");
        assert!(
            summary.contains(expected),
            "{key}: the refusal did not name the reserved member: {summary}"
        );
        for rendering in error_renderings(&error) {
            assert_no_secret(&rendering);
        }
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("{key}: the refused update reached the wire"),
            Err(error) => panic!("{key}: the fixture listener failed: {error}"),
        }
    }
}

/// A case-folded key would serialize a distinct JSON key beside the typed one.
///
/// This is the raw-bytes hazard the guard prevents: `Name` and `name` are two
/// keys to serde, and the daemon's case-insensitive decoder may treat the
/// second as a duplicate or an override. The spec is serialized only to show
/// the bytes; the update itself is refused before dispatch.
#[test]
fn a_case_folded_reserved_key_would_emit_a_second_json_key() {
    let mut additional = BTreeMap::new();
    additional.insert("name".to_owned(), serde_json::json!("shadow"));
    let spec = SwarmSecretSpec {
        name: Some(String::from("typed")),
        additional,
        ..SwarmSecretSpec::default()
    };
    let value = serde_json::to_value(&spec).expect("the spec serializes");
    let object = value.as_object().expect("a JSON object");
    assert!(object.contains_key("Name"), "{value}");
    assert!(object.contains_key("name"), "{value}");
    assert_eq!(object["Name"], "typed");
    assert_eq!(object["name"], "shadow");
}

/// The raw writer refuses reserved keys before dispatch as well.
///
/// The facade's guard cannot protect a caller of `raw::secret_update`, so the
/// same structural refusal lives in the writer. The comparison covers case
/// variants because the Engine's decoder does. A transport error would mean it
/// dispatched; the local `InvalidInput` is the proof it did not.
#[tokio::test]
async fn raw_secret_update_refuses_case_folded_reserved_keys_without_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let engine = client.raw_engine().expect("the HTTP endpoint is reachable");

    for (key, expected) in [
        ("Data", "Data member"),
        ("data", "Data member"),
        ("DATA", "Data member"),
        ("Name", "reserved member"),
        ("name", "reserved member"),
        ("NAME", "reserved member"),
        ("Labels", "reserved member"),
        ("labels", "reserved member"),
        ("Driver", "reserved member"),
        ("driver", "reserved member"),
    ] {
        let mut additional = BTreeMap::new();
        additional.insert(key.to_owned(), serde_json::json!(SECRET_DATA_CANARY));
        let options = SecretUpdateOptions {
            version: VERSION_INDEX,
            spec: SwarmSecretSpec {
                additional,
                ..SwarmSecretSpec::default()
            },
        };
        let error = raw::secret_update(&engine, SECRET_ID, &options)
            .await
            .expect_err("a case-folded reserved key is refused");

        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key}");
        let summary = error_renderings(&error).join("\n");
        assert!(
            summary.contains(expected),
            "{key}: the raw refusal did not name the reserved member: {summary}"
        );
        for rendering in error_renderings(&error) {
            assert_no_secret(&rendering);
        }
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("a refused raw update reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// A list rejection preserves the status and withholds the daemon's text.
#[tokio::test]
async fn list_secrets_reports_a_rejection_with_withheld_text_and_does_not_retry() {
    const MESSAGE_CANARY: &str = "daemon-echo-list-2b8f";
    let message = format!("secret list failed {MESSAGE_CANARY}");
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .list_secrets(None)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, SECRET_READ_API_WITHHELD);
    for rendering in error_renderings(&error) {
        assert!(
            !rendering.contains(MESSAGE_CANARY),
            "the rejection echoed the daemon text: {rendering}"
        );
    }
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/secrets HTTP/1.1", version_prefix())
    );
    assert!(!fixture.saw_retry());

    fixture.finish();
}

/// An escaped JSON key decodes to a reserved key before the guard sees it.
///
/// `D\u0061ta` is `Data` after JSON decoding, so it lands in `additional` as
/// `Data`, is withheld from `Debug`, and is refused by the update guard. A guard
/// that compared pre-decoding bytes would miss it.
#[tokio::test]
async fn an_escaped_json_key_decodes_to_a_reserved_key_and_is_refused_on_update() {
    const ESCAPED: &str = r#"{
      "ID": "secret-fixture",
      "Version": {"Index": 9},
      "Spec": {
        "Name": "fixture-secret",
        "D\u0061ta": "dGVzdC1zZWNyZXQtZGF0YS1jYW5hcnk="
      }
    }"#;
    let fixture = Fixture::start(vec![ok_json(ESCAPED)]);
    let secret = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect("the secret document decoded");
    let spec = secret.spec.clone().expect("the daemon sent a spec");
    assert_eq!(
        spec.additional.get("Data"),
        Some(&serde_json::json!(SECRET_DATA_BASE64)),
        "the escaped key did not decode to Data"
    );
    assert_no_secret(&format!("{secret:?}"));
    fixture.finish();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let error = client
        .update_secret(
            SECRET_ID,
            SecretUpdateOptions {
                version: VERSION_INDEX,
                spec,
            },
        )
        .await
        .expect_err("the decoded reserved key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let summary = error_renderings(&error).join("\n");
    assert!(summary.contains("Data member"), "{summary}");
    for rendering in error_renderings(&error) {
        assert_no_secret(&rendering);
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the refused update reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// The public raw operations withhold a rejection's text themselves.
///
/// The facade is no longer the only caller: a direct `raw::secret_list` or
/// `raw::secret_inspect` must not return the peer's echo in `Display`, `Debug`,
/// or the source chain. Only the status survives.
#[tokio::test]
async fn raw_secret_reads_withhold_rejection_text_in_the_full_chain() {
    const MESSAGE_CANARY: &str = "raw-secret-echo-canary-8b3d";
    for list in [true, false] {
        let message = format!("raw secret failure {MESSAGE_CANARY} {SECRET_DATA_BASE64}");
        let fixture =
            RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));
        let client = fixture.client();
        let engine = client.raw_engine().expect("the HTTP endpoint is reachable");
        let error = if list {
            raw::secret_list(&engine, &SwarmListOptions::default())
                .await
                .expect_err("a 404 is an error")
        } else {
            raw::secret_inspect(&engine, SECRET_ID)
                .await
                .expect_err("a 404 is an error")
        };

        assert_eq!(error.kind(), ErrorKind::Docker, "list={list}");
        let api = error.api_error().expect("the status is preserved");
        assert_eq!(api.status_code, 404, "list={list}");
        assert_eq!(api.message, SECRET_READ_API_WITHHELD, "list={list}");
        for rendering in error_renderings(&error) {
            assert!(
                !rendering.contains(MESSAGE_CANARY) && !rendering.contains(SECRET_DATA_BASE64),
                "list={list}: the raw rejection echoed the peer: {rendering}"
            );
        }
        let expected = if list {
            format!("GET {}/secrets HTTP/1.1", version_prefix())
        } else {
            format!("GET {}/secrets/{SECRET_ID} HTTP/1.1", version_prefix())
        };
        assert_eq!(fixture.request_line(), expected, "list={list}");
        assert!(!fixture.saw_retry(), "list={list}");
        fixture.finish();
    }
}

/// An escaped Unicode key is decoded on read and refused before any update.
///
/// Go's `encoding/json` folds field names with Unicode case folding, so
/// `Label\u{017f}` (`Labelſ`) can reach `Labels`. The guard refuses the whole
/// non-ASCII class rather than claim a full fold table it does not have.
#[tokio::test]
async fn an_escaped_unicode_key_is_retained_on_read_and_refused_on_update() {
    const UNICODE_KEY: &str = "Label\u{017f}";
    const BODY: &str = r#"{
      "ID": "secret-fixture",
      "Version": {"Index": 9},
      "Spec": {
        "Name": "fixture-secret",
        "Label\u017f": "test-secret-data-canary"
      }
    }"#;
    let fixture = Fixture::start(vec![ok_json(BODY)]);
    let secret = fixture
        .client()
        .inspect_secret(SECRET_ID)
        .await
        .expect("the secret document decoded");
    let spec = secret.spec.clone().expect("the daemon sent a spec");
    assert!(
        spec.additional.contains_key(UNICODE_KEY),
        "the escaped Unicode key did not decode to the expected spelling"
    );
    assert_no_secret(&format!("{secret:?}"));
    fixture.finish();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let error = client
        .update_secret(
            SECRET_ID,
            SecretUpdateOptions {
                version: VERSION_INDEX,
                spec,
            },
        )
        .await
        .expect_err("the non-ASCII key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let summary = error_renderings(&error).join("\n");
    assert!(summary.contains("non-ASCII"), "{summary}");
    for rendering in error_renderings(&error) {
        assert_no_secret(&rendering);
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the refused update reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}

/// The raw writer refuses a non-ASCII `additional` key before dispatch too.
#[tokio::test]
async fn raw_secret_update_refuses_a_unicode_key_before_dispatch() {
    const UNICODE_KEY: &str = "Label\u{017f}";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let engine = client.raw_engine().expect("the HTTP endpoint is reachable");

    let mut additional = BTreeMap::new();
    additional.insert(
        UNICODE_KEY.to_owned(),
        serde_json::json!(SECRET_DATA_CANARY),
    );
    let options = SecretUpdateOptions {
        version: VERSION_INDEX,
        spec: SwarmSecretSpec {
            additional,
            ..SwarmSecretSpec::default()
        },
    };
    let error = raw::secret_update(&engine, SECRET_ID, &options)
        .await
        .expect_err("a non-ASCII key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let summary = error_renderings(&error).join("\n");
    assert!(summary.contains("non-ASCII"), "{summary}");
    for rendering in error_renderings(&error) {
        assert_no_secret(&rendering);
    }
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("the refused raw update reached the wire"),
        Err(error) => panic!("the fixture listener failed: {error}"),
    }
}
