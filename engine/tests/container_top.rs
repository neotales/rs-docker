//! `DockerClient::container_top` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `container_top` must open
//! `GET /v1.NN/containers/{id}/top` through the owned transport when that
//! transport can reach the endpoint, rather than the unversioned path the
//! generated client sends. Asserting that against a request builder would only
//! show what the builder would produce if it were called; the routing decision
//! is above it. A loopback HTTP fixture is the only place the wire request and
//! the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `container_top` puts the generated client back on the wire. The request line
//! then loses the version prefix, and an unescaped reference with a slash
//! changes the path shape, so both comparisons fail. That mutation is the
//! reason the request line is compared whole rather than only checked for one
//! query value.
//!
//! The projection tests use the documents in
//! `support/container_top_entries.rs`, which the fallback suite sends through
//! the generated client as well. The rejection test pins two contracts at once:
//! a daemon rejection keeps its status and message in [`Error::api_error`], and
//! a failed owned request is returned rather than retried over the generated
//! client.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, DockerClient, ErrorKind};

#[path = "support/container_top_entries.rs"]
mod container_top_entries;

use container_top_entries::{
    EXTRA_MEMBER_BODY, MISSING_MEMBERS_BODY, NULL_MEMBERS_BODY, NULL_ROW_BODY, TOP_BODY,
    WRONG_TYPE_BODY,
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let response = rejected(status, body);
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

/// Reads the request head, which is all a top request sends.
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

/// The owned path sends the versioned request with the caller's `ps` arguments
/// and projects the two Engine members onto the repository model.
#[tokio::test]
async fn top_sends_a_versioned_request_with_the_ps_arguments() {
    let fixture = Fixture::start(vec![ok_json(TOP_BODY)]);
    let top = fixture
        .client()
        .container_top("slice-db-1", Some("aux"))
        .await
        .expect("the process list decoded");

    assert_eq!(top.titles, ["PID", "CMD"]);
    assert_eq!(
        top.processes,
        [
            ["1".to_owned(), "sleep 60".to_owned()],
            ["7".to_owned(), "sh".to_owned()]
        ]
    );
    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/containers/slice-db-1/top?ps_args=aux HTTP/1.1",
            version_prefix()
        ),
        "container_top fell back to the unversioned generated path or dropped ps_args"
    );

    fixture.finish();
}

/// Unset options are omitted rather than guessed.
#[tokio::test]
async fn top_without_process_options_sends_no_query() {
    let fixture = Fixture::start(vec![ok_json(TOP_BODY)]);
    fixture
        .client()
        .container_top("slice-db-1", None)
        .await
        .expect("the process list decoded");

    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/containers/slice-db-1/top HTTP/1.1",
            version_prefix()
        ),
        "an unset process option became a query value"
    );

    fixture.finish();
}

/// A whitespace-only option is the same "not requested" request as `None`.
///
/// The generated fallback already treated it that way, so the owned path must
/// too. Omitting `ps_args` selects the daemon's own default -- Docker on Unix
/// substitutes `-ef` -- so sending an empty value would only make the request
/// line noisier.
#[tokio::test]
async fn top_treats_a_blank_option_as_not_requested() {
    let fixture = Fixture::start(vec![ok_json(TOP_BODY)]);
    fixture
        .client()
        .container_top("slice-db-1", Some("   "))
        .await
        .expect("the process list decoded");

    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/containers/slice-db-1/top HTTP/1.1",
            version_prefix()
        ),
        "a blank process option was sent as an empty ps_args value"
    );

    fixture.finish();
}

/// The arguments travel as one query value even when they contain a separator.
#[tokio::test]
async fn top_encodes_the_ps_arguments_as_one_query_value() {
    let fixture = Fixture::start(vec![ok_json(TOP_BODY)]);
    fixture
        .client()
        .container_top("slice-db-1", Some("aux -e & x"))
        .await
        .expect("the process list decoded");

    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/containers/slice-db-1/top?ps_args=aux+-e+%26+x HTTP/1.1",
            version_prefix()
        ),
        "ps_args was not encoded as one query value"
    );

    fixture.finish();
}

/// A container reference is one path segment even when it contains a slash.
#[tokio::test]
async fn top_escapes_the_container_reference() {
    let fixture = Fixture::start(vec![ok_json(TOP_BODY)]);
    fixture
        .client()
        .container_top("a/b", None)
        .await
        .expect("the process list decoded");

    assert_eq!(
        fixture.request_line(),
        format!("GET {}/containers/a%2Fb/top HTTP/1.1", version_prefix()),
        "container_top stopped encoding the container reference"
    );

    fixture.finish();
}

/// An empty reference is refused before a connection is opened.
///
/// This test exercises only the owned path; the fallback's empty-reference
/// behavior belongs to the generated client and is not observed here. The
/// difference is documented on `DockerClient::container_top`. The endpoint here
/// has no listener, so a path that tried to connect would report
/// `ErrorKind::Transport` instead.
#[tokio::test]
async fn top_refuses_an_empty_reference_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .container_top("", None)
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
}

/// Absent and `null` members are empty process tables on the owned path, as
/// they are through the generated client.
#[tokio::test]
async fn top_projects_absent_and_null_members_as_empty() {
    for body in [MISSING_MEMBERS_BODY, NULL_MEMBERS_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let top = fixture
            .client()
            .container_top("slice-db-1", None)
            .await
            .expect("an empty process table decoded");
        assert!(top.titles.is_empty(), "{body}");
        assert!(top.processes.is_empty(), "{body}");
        fixture.finish();
    }
}

/// A member the projection does not model is ignored rather than fatal.
#[tokio::test]
async fn top_ignores_members_it_does_not_model() {
    let fixture = Fixture::start(vec![ok_json(EXTRA_MEMBER_BODY)]);
    let top = fixture
        .client()
        .container_top("slice-db-1", None)
        .await
        .expect("an extra member does not fail the projection");
    assert_eq!(top.titles, ["PID"]);
    assert_eq!(top.processes, [["1".to_owned()]]);
    fixture.finish();
}

/// A success body with a member of the wrong type is a decode failure in the
/// owned decoder's class.
///
/// The fallback suite sends the same bodies through the generated client,
/// where the same failure is `ErrorKind::Docker`. That difference is documented
/// on `DockerClient::container_top`; this test pins the owned half of it.
#[tokio::test]
async fn top_rejects_a_member_of_the_wrong_type() {
    for body in [WRONG_TYPE_BODY, NULL_ROW_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .container_top("slice-db-1", None)
            .await
            .expect_err("a wrong member type is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn top_reports_a_rejection_and_does_not_retry() {
    let message = "No such container: missing";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .container_top("missing", None)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/containers/missing/top HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned top request was retried through the generated client"
    );

    fixture.finish();
}
