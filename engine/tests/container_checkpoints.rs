//! `DockerClient` container checkpoints on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: `create_checkpoint`,
//! `list_checkpoints`, and `remove_checkpoint` must open the versioned
//! `/v1.NN/containers/{id}/checkpoints` routes through the owned transport when
//! that transport can reach the endpoint, rather than the unversioned paths the
//! generated client sends. Asserting that against a request builder would only
//! show what the builder would produce if it were called; the routing decision is
//! above it. A loopback HTTP fixture is the only place the wire request and the
//! routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from a facade method
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, and an unescaped reference or checkpoint identifier with a
//! slash changes the path shape, so the whole-line comparisons fail. That
//! mutation is the reason each request line is compared whole rather than only
//! checked for one query value.
//!
//! The create body is compared as bytes, not as a parsed value, because the
//! member order and spelling are part of the recorded request: `CheckpointID`,
//! an optional `CheckpointDir`, then `Exit`. An empty directory is the daemon's
//! default and must be omitted rather than sent as `""`.
//!
//! The rejection tests pin three contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], a `501` capability answer is not
//! turned into a local guess, and a failed owned request is returned rather than
//! retried over the generated client. The empty-value tests pin that a caller
//! mistake is refused before a connection is opened — an empty checkpoint
//! identifier on the remove route would otherwise spell the list path.
//!
//! The malformed-list test pins the projection's error class and its `null`
//! handling: an entry without a string `Name` is `ErrorKind::InvalidInput` on the
//! owned path, while a `null` answer from an older daemon is an empty list. The
//! generated fallback reports decode failures as `ErrorKind::Docker`, which is
//! pinned in `container_checkpoints_fallback.rs`.
//!
//! The credential-canary test is the unignored regression for the shared
//! decoder's content-free diagnostic. A malformed list answer that is a JSON
//! string makes serde quote the string in its own message, so an unsanitized
//! decoder would put the response text into `Display`, `Debug`, and the source
//! chain. The canary is checked through all three. That sanitizer is the proxy
//! series' shared `raw::decode` change, not this slice; on a base without it this
//! test fails by design, and it is not ignored so the combination cannot land
//! without it.
//!
//! The cancellation test is about ownership. The fixture never answers, so the
//! only thing that ends its read is the client releasing the connection when the
//! caller abandons the request. It also proves the abandonment is not a retry:
//! the fixture watches for a second connection and reports whether one arrived.
//! What it cannot prove is what the daemon did — a create is not transactional,
//! and any failure leaves the outcome unknown, which is documented on the method
//! rather than asserted here.
//!
//! Every test reaches the public API, and none needs a running daemon. The
//! checkpoint routes are experimental and need CRIU on the daemon side, so no
//! live-daemon claim is made by this file.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, CheckpointOptions, DockerClient, Endpoint, ErrorKind,
};

/// One request as the fixture saw it.
#[derive(Clone, Debug)]
struct Recorded {
    head: String,
    body: Vec<u8>,
}

impl Recorded {
    /// The request line.
    fn line(&self) -> String {
        self.head
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
    }

    /// One request header, matched case-insensitively.
    fn header(&self, name: &str) -> Option<String> {
        self.head
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .find_map(|line| {
                let (header, value) = line.split_once(':')?;
                header
                    .trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
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
    requests: Receiver<Recorded>,
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
                let recorded = read_request(&mut stream);
                let _ = request_tx.send(recorded);
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

    fn request(&self) -> Recorded {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A fixture that answers one rejection and then watches for a retry.
///
/// A second connection is the observable form of a fallback after a failed owned
/// request. The watch window exists because a client that retried would do so
/// immediately after the first answer; the first answer has already been read
/// when the window opens.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<Recorded>,
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
            let recorded = read_request(&mut stream);
            let _ = request_tx.send(recorded);
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
                        let _ = retry_stream.write_all(&no_content());
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

    fn request(&self) -> Recorded {
        self.first_request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn retried(&self) -> bool {
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
    request: tokio::sync::oneshot::Receiver<Recorded>,
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
            let recorded = read_request(&mut stream);
            let _ = request_tx.send(recorded);

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
                        let _ = retry_stream.write_all(&no_content());
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

/// Reads a request head and its declared body.
fn read_request(stream: &mut TcpStream) -> Recorded {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&request[..head_end]).into_owned();
    let length = head
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = request[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).expect("read the request body");
        assert_ne!(read, 0, "the request body ended early");
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Recorded { head, body }
}

/// Reads until the client closes its end, which is how the fixture knows the
/// operation completed rather than that its bytes were written.
fn wait_for_client_close(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// The `201 Created` answer a successful checkpoint creation gets: a status and
/// no body.
fn created() -> Vec<u8> {
    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// The `204 No Content` answer a successful removal gets.
fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

/// A `200` answer carrying a JSON document.
fn ok(body: &str) -> Vec<u8> {
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

/// A client whose endpoint has no listener, for the pre-connection refusals.
///
/// An implementation that tried to connect would report `ErrorKind::Transport`
/// instead of the input error the test asserts.
fn unreachable_client() -> DockerClient {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    client
}

/// Asserts that no rendering of an error carries `canary`.
///
/// The full chain is walked, not just the outer error: the crate keeps the
/// decoder's own failure as the source, and that is where serde's value-bearing
/// message lives. `depth > 0` makes the walk load-bearing — an error with no
/// source would otherwise pass vacuously.
fn assert_error_is_content_free(error: &neotales_docker::Error, canary: &str) {
    assert!(
        !error.to_string().contains(canary),
        "the error's Display echoed the response content: {error}"
    );
    assert!(
        !format!("{error:?}").contains(canary),
        "the error's Debug echoed the response content: {error:?}"
    );
    let mut source = std::error::Error::source(error);
    let mut depth = 0;
    while let Some(cause) = source {
        assert!(
            !cause.to_string().contains(canary),
            "source {depth}'s Display echoed the response content: {cause}"
        );
        assert!(
            !format!("{cause:?}").contains(canary),
            "source {depth}'s Debug echoed the response content: {cause:?}"
        );
        source = cause.source();
        depth += 1;
    }
    assert!(
        depth > 0,
        "the error must expose the decoder failure as its source"
    );
}

/// The create request is the versioned route, and its body is the daemon's
/// members in the generated order.
#[tokio::test]
async fn create_sends_a_versioned_request_with_the_checkpoint_in_the_body() {
    let fixture = Fixture::start(vec![created()]);
    fixture
        .client()
        .create_checkpoint(
            "slice-db-1",
            CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                checkpoint_dir: Some("/var/lib/docker/checkpoints/team a&b".to_owned()),
                exit: true,
            },
        )
        .await
        .expect("a 201 is a successful create");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!(
            "POST {}/containers/slice-db-1/checkpoints HTTP/1.1",
            version_prefix()
        ),
        "create_checkpoint fell back to the unversioned generated path or added a query"
    );
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json"),
        "the checkpoint create body is JSON"
    );
    assert_eq!(
        String::from_utf8(request.body).expect("UTF-8 JSON"),
        r#"{"CheckpointID":"cp1","CheckpointDir":"/var/lib/docker/checkpoints/team a&b","Exit":true}"#,
        "the body must be the daemon's members in the generated order"
    );

    fixture.finish();
}

/// An absent or empty directory is the daemon's default and is omitted, while
/// `Exit` is always spelled because the caller's value is not optional.
#[tokio::test]
async fn create_omits_an_absent_or_empty_directory() {
    let fixture = Fixture::start(vec![created(), created()]);
    let client = fixture.client();

    for directory in [None, Some(String::new())] {
        client
            .create_checkpoint(
                "slice-db-1",
                CheckpointOptions {
                    checkpoint_id: Some("cp1".to_owned()),
                    checkpoint_dir: directory,
                    exit: false,
                },
            )
            .await
            .expect("a 201 is a successful create");

        let request = fixture.request();
        assert_eq!(
            request.line(),
            format!(
                "POST {}/containers/slice-db-1/checkpoints HTTP/1.1",
                version_prefix()
            )
        );
        assert_eq!(
            String::from_utf8(request.body).expect("UTF-8 JSON"),
            r#"{"CheckpointID":"cp1","Exit":false}"#,
            "an absent or empty directory must be omitted rather than sent empty"
        );
    }

    fixture.finish();
}

/// A container reference and a checkpoint identifier are path segments, so
/// their separators are encoded rather than changing the request's shape.
#[tokio::test]
async fn create_encodes_the_container_reference() {
    let fixture = Fixture::start(vec![created()]);
    fixture
        .client()
        .create_checkpoint(
            "a/b",
            CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                ..Default::default()
            },
        )
        .await
        .expect("a 201 is a successful create");

    assert_eq!(
        fixture.request().line(),
        format!(
            "POST {}/containers/a%2Fb/checkpoints HTTP/1.1",
            version_prefix()
        ),
        "the container reference stopped being percent-encoded"
    );

    fixture.finish();
}

/// An empty reference or identifier is refused before a connection is opened.
#[tokio::test]
async fn create_refuses_empty_values_without_connecting() {
    let client = unreachable_client();

    let error = client
        .create_checkpoint("", CheckpointOptions::default())
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );

    for identifier in [None, Some(String::new())] {
        let error = client
            .create_checkpoint(
                "slice-db-1",
                CheckpointOptions {
                    checkpoint_id: identifier,
                    ..Default::default()
                },
            )
            .await
            .expect_err("an empty identifier is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("checkpoint"),
            "the refusal did not name the checkpoint identifier: {error}"
        );
    }
}

/// The owned route carries the client's configured version, not the crate's
/// ceiling.
///
/// The checkpoint routes have existed since Engine API v1.25 and their shape has
/// not changed, so a client built at an older version sends that version and
/// addresses the same handler. The request line is the whole claim: a client
/// that ignored its configured version and always sent the ceiling would pass
/// every other test in this file, because those use the default client.
#[tokio::test]
async fn create_sends_the_clients_configured_version() {
    let fixture = Fixture::start(vec![created()]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 24,
        },
    )
    .expect("a client at v1.24");
    client
        .create_checkpoint(
            "slice-db-1",
            CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                ..Default::default()
            },
        )
        .await
        .expect("a 201 is a successful create");

    assert_eq!(
        fixture.request().line(),
        "POST /v1.24/containers/slice-db-1/checkpoints HTTP/1.1",
        "the owned path must send the client's configured version, not the ceiling"
    );

    fixture.finish();
}

/// A daemon that cannot checkpoint answers `501`; the answer is returned with
/// its message and is not retried over the generated client.
#[tokio::test]
async fn create_reports_a_capability_rejection_and_does_not_retry() {
    let message = "checkpointing is not supported for this container";
    let fixture = RejectingFixture::start(
        "501 Not Implemented",
        &format!(r#"{{"message":"{message}"}}"#),
    );
    let error = fixture
        .client()
        .create_checkpoint(
            "slice-db-1",
            CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                ..Default::default()
            },
        )
        .await
        .expect_err("a 501 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 501);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request().line(),
        format!(
            "POST {}/containers/slice-db-1/checkpoints HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.retried(),
        "a failed owned checkpoint create was retried through the generated client"
    );

    fixture.finish();
}

/// The list request is the versioned route with one percent-encoded `dir`
/// query value, and the answer projects each name.
#[tokio::test]
async fn list_sends_a_versioned_request_with_the_encoded_directory() {
    let fixture = Fixture::start(vec![ok(r#"[{"Name":"cp1"},{"Name":"cp-two"}]"#)]);
    let checkpoints = fixture
        .client()
        .list_checkpoints("slice-db-1", Some("/custom dir&x"))
        .await
        .expect("a checkpoint array");

    assert_eq!(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.name.as_str())
            .collect::<Vec<_>>(),
        vec!["cp1", "cp-two"]
    );
    assert_eq!(
        fixture.request().line(),
        format!(
            "GET {}/containers/slice-db-1/checkpoints?dir=%2Fcustom+dir%26x HTTP/1.1",
            version_prefix()
        ),
        "list_checkpoints fell back to the unversioned path or changed the query encoding"
    );

    fixture.finish();
}

/// An absent or empty directory sends no query at all, and a `null` answer is
/// no checkpoints rather than a decode failure.
#[tokio::test]
async fn list_omits_an_absent_or_empty_directory_and_accepts_null() {
    let fixture = Fixture::start(vec![ok("[]"), ok("null")]);
    let client = fixture.client();

    for directory in [None, Some("")] {
        let checkpoints = client
            .list_checkpoints("slice-db-1", directory)
            .await
            .expect("a checkpoint array");
        assert!(checkpoints.is_empty(), "{directory:?}");
        assert_eq!(
            fixture.request().line(),
            format!(
                "GET {}/containers/slice-db-1/checkpoints HTTP/1.1",
                version_prefix()
            ),
            "{directory:?} must not become an empty query value"
        );
    }

    fixture.finish();
}

/// A malformed list answer is refused, and an empty name is a value.
#[tokio::test]
async fn list_reports_malformed_documents_as_invalid_input() {
    let bodies = [
        "{}",
        r"[{}]",
        r#"[{"Name":7}]"#,
        r#"[{"Name":null}]"#,
        r#"[{"Name":"a","Name":"b"}]"#,
        "[null]",
        "not json",
    ];
    let mut responses: Vec<Vec<u8>> = bodies.iter().map(|body| ok(body)).collect();
    responses.push(ok(r#"[{"Name":""}]"#));
    let fixture = Fixture::start(responses);
    let client = fixture.client();

    for body in bodies {
        let error = client
            .list_checkpoints("slice-db-1", None)
            .await
            .expect_err("an unusable checkpoint entry is refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidInput,
            "the owned path classifies a decode failure as invalid input: {body}"
        );
        assert_eq!(
            fixture.request().line(),
            format!(
                "GET {}/containers/slice-db-1/checkpoints HTTP/1.1",
                version_prefix()
            ),
            "a malformed answer must not change which request was sent"
        );
    }

    // An empty name is a value the generated fallback also accepts, so the owned
    // projection must not turn it into a decode failure.
    let checkpoints = client
        .list_checkpoints("slice-db-1", None)
        .await
        .expect("an empty name is a value");
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].name, "");
    fixture.request();

    fixture.finish();
}

/// A malformed list answer must not echo its content.
///
/// A JSON string is not a checkpoint array, and serde's own diagnostic quotes
/// the unexpected string. A proxied response is untrusted, so the decoder must
/// carry only a content-free category and position. The canary is shaped like a
/// credential name and is checked through `Display`, `Debug`, and every source
/// in the chain.
///
/// This is the unignored regression for the shared decoder's sanitizer. On a
/// base that still formats serde's message it fails with the canary visible, by
/// design; it must not be `#[ignore]`d, because the combination with the proxy
/// series is what makes it pass.
#[tokio::test]
async fn list_does_not_echo_a_credential_from_a_malformed_answer() {
    const CANARY: &str = "SYNTHETIC_CANARY_CHECKPOINT_CREDENTIAL";
    let fixture = Fixture::start(vec![ok(&format!("\"{CANARY}\""))]);
    let error = fixture
        .client()
        .list_checkpoints("slice-db-1", None)
        .await
        .expect_err("a JSON string is not a checkpoint array");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.api_error().is_none(),
        "a malformed success body is not a daemon rejection"
    );
    assert_error_is_content_free(&error, CANARY);
    fixture.request();

    fixture.finish();
}

/// An empty container reference is refused before a connection is opened.
#[tokio::test]
async fn list_refuses_an_empty_reference_without_connecting() {
    let error = unreachable_client()
        .list_checkpoints("", None)
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
}

/// The remove request is the versioned route with both path segments escaped
/// and the directory as one query value.
#[tokio::test]
async fn remove_sends_a_versioned_request_with_both_segments_escaped() {
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .remove_checkpoint("a/b", "cp/one & two", Some("/custom dir"))
        .await
        .expect("a 204 is a successful removal");

    assert_eq!(
        fixture.request().line(),
        format!(
            "DELETE {}/containers/a%2Fb/checkpoints/cp%2Fone%20%26%20two?dir=%2Fcustom+dir HTTP/1.1",
            version_prefix()
        ),
        "remove_checkpoint fell back to the unversioned path or stopped escaping a segment"
    );

    fixture.finish();
}

/// An absent or empty directory sends no query at all.
#[tokio::test]
async fn remove_omits_an_absent_or_empty_directory() {
    let fixture = Fixture::start(vec![no_content(), no_content()]);
    let client = fixture.client();

    for directory in [None, Some("")] {
        client
            .remove_checkpoint("slice-db-1", "cp1", directory)
            .await
            .expect("a 204 is a successful removal");
        assert_eq!(
            fixture.request().line(),
            format!(
                "DELETE {}/containers/slice-db-1/checkpoints/cp1 HTTP/1.1",
                version_prefix()
            ),
            "{directory:?} must not become an empty query value"
        );
    }

    fixture.finish();
}

/// An empty identifier would spell the list route, so it is refused before a
/// connection is opened.
#[tokio::test]
async fn remove_refuses_empty_values_without_connecting() {
    let client = unreachable_client();

    let error = client
        .remove_checkpoint("", "cp1", None)
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let error = client
        .remove_checkpoint("slice-db-1", "", None)
        .await
        .expect_err("an empty checkpoint identifier is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("checkpoint"),
        "the refusal did not name the checkpoint identifier: {error}"
    );
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn remove_reports_a_rejection_and_does_not_retry() {
    let message = "checkpoint cp1 does not exist for container slice-db-1";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));
    let error = fixture
        .client()
        .remove_checkpoint("slice-db-1", "cp1", None)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request().line(),
        format!(
            "DELETE {}/containers/slice-db-1/checkpoints/cp1 HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.retried(),
        "a failed owned checkpoint removal was retried through the generated client"
    );

    fixture.finish();
}

/// Abandoning the create releases the connection and is not a retry.
///
/// The daemon never answers, so the fixture's read can only end when the client
/// releases the connection. It then watches for a second connection, which is
/// what a fallback after the abandoned request would look like.
#[tokio::test]
async fn create_releases_the_connection_when_the_caller_abandons_it() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move {
        client
            .create_checkpoint(
                "slice-db-1",
                CheckpointOptions {
                    checkpoint_id: Some("cp1".to_owned()),
                    ..Default::default()
                },
            )
            .await
    });

    let request = tokio::time::timeout(Duration::from_secs(10), fixture.request)
        .await
        .expect("the fixture saw no request")
        .expect("the fixture reported");
    assert_eq!(
        request.line(),
        format!(
            "POST {}/containers/slice-db-1/checkpoints HTTP/1.1",
            version_prefix()
        ),
        "the abandoned request must be the owned one"
    );

    task.abort();
    let released = tokio::time::timeout(Duration::from_secs(10), fixture.released)
        .await
        .expect("the fixture did not observe the disconnect")
        .expect("the fixture reported");
    assert!(
        released,
        "abandoning the checkpoint create future did not release the connection"
    );

    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "an abandoned owned checkpoint create was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
