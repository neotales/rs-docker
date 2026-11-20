//! `DockerClient::commit_container` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: the commit must open the
//! versioned `POST /v1.NN/commit` path through the owned transport, each query
//! value must be percent-encoded, each Dockerfile change must be its own
//! `changes=` parameter, the body must be the empty `ContainerConfig`, and the
//! answer must project onto the image id. Asserting any of those against a
//! request builder would only show what the builder would produce if it were
//! called; the routing decision is above it. A loopback HTTP fixture is the only
//! place the wire request and the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `commit_container` puts the generated client back on the wire. The request
//! line then loses the version prefix, and the whole-line comparisons fail.
//!
//! The all-options test compares the request line whole rather than checking for
//! one value, because three separate regressions are visible only there: the
//! version prefix, the parameter order, and the change encoding. The generated
//! fallback joins the change vector with a newline into one `changes=` value; the
//! owned path must send one parameter per instruction, which is the shape the
//! daemon's handler reads.
//!
//! The rejection test pins two contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], and a failed owned request is
//! returned rather than retried over the generated client.
//!
//! The malformed-response test pins the projection's error class. An absent,
//! `null`, or non-string `Id` is a decode failure, and on the owned path that is
//! `ErrorKind::InvalidInput` where the generated fallback reports
//! `ErrorKind::Docker`. An empty id string is a value neither path rejects, so it
//! is pinned as a success rather than left to be discovered.
//!
//! The cancellation test is about ownership. The fixture never answers, so the
//! only thing that ends its read is the client releasing the connection when the
//! caller abandons the request. It also proves the abandonment is not a retry:
//! the fixture watches for a second connection and reports whether one arrived.
//! What it cannot prove is what the daemon did — a commit is not transactional,
//! and any failure leaves the outcome unknown, which is documented on the method
//! rather than asserted here.
//!
//! Every test reaches the public API, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, CommitContainerOptions, DockerClient, ErrorKind};

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
                        let _ = retry_stream.write_all(&created(r#"{"Id":"retried"}"#));
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

/// The `201 Created` answer a successful commit gets.
fn created(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
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

/// Every option is spelled in the daemon's order, each change is its own
/// parameter, the body is the empty config, and the answer is the image id.
#[tokio::test]
async fn commit_sends_a_versioned_request_with_every_option_and_reads_the_id() {
    let fixture = Fixture::start(vec![created(r#"{"Id":"sha256:committed"}"#)]);
    let id = fixture
        .client()
        .commit_container(CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            repository: Some("team/app".to_owned()),
            tag: Some("v1".to_owned()),
            comment: Some("snapshot".to_owned()),
            author: Some("Ada <ada@example.test>".to_owned()),
            pause: true,
            changes: vec!["CMD [\"/bin/sh\"]".to_owned(), "ENV A=1".to_owned()],
        })
        .await
        .expect("a 201 is a successful commit");
    assert_eq!(id, "sha256:committed");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!(
            "POST {}/commit?container=slice-db-1&repo=team%2Fapp&tag=v1&comment=snapshot&author=Ada+%3Cada%40example.test%3E&pause=true&changes=CMD+%5B%22%2Fbin%2Fsh%22%5D&changes=ENV+A%3D1 HTTP/1.1",
            version_prefix()
        ),
        "commit_container fell back to the unversioned generated path, reordered the parameters, or joined the changes into one value"
    );
    assert_eq!(
        request.header("content-type").as_deref(),
        Some("application/json"),
        "the commit body is JSON"
    );
    assert_eq!(
        request.body, b"{}",
        "the body must be the empty ContainerConfig the fallback sends"
    );

    fixture.finish();
}

/// Unset options are omitted rather than guessed, while `pause` is always
/// spelled because the caller's value is not optional.
#[tokio::test]
async fn commit_without_optional_options_sends_the_container_and_pause_only() {
    let fixture = Fixture::start(vec![created(r#"{"Id":"sha256:committed"}"#)]);
    fixture
        .client()
        .commit_container(CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            pause: false,
            ..Default::default()
        })
        .await
        .expect("a 201 is a successful commit");

    let request = fixture.request();
    assert_eq!(
        request.line(),
        format!(
            "POST {}/commit?container=slice-db-1&pause=false HTTP/1.1",
            version_prefix()
        ),
        "an unset commit option became a query value instead of being omitted"
    );
    assert_eq!(request.body, b"{}");

    fixture.finish();
}

/// A container reference is a query value, so its separators are encoded rather
/// than changing the request's shape.
#[tokio::test]
async fn commit_encodes_the_container_reference_as_one_query_value() {
    let fixture = Fixture::start(vec![created(r#"{"Id":"sha256:committed"}"#)]);
    fixture
        .client()
        .commit_container(CommitContainerOptions {
            container: "a/b&c=d".to_owned(),
            ..Default::default()
        })
        .await
        .expect("a 201 is a successful commit");

    assert_eq!(
        fixture.request().line(),
        format!(
            "POST {}/commit?container=a%2Fb%26c%3Dd&pause=false HTTP/1.1",
            version_prefix()
        ),
        "the container reference stopped being percent-encoded"
    );

    fixture.finish();
}

/// An empty reference is refused before a connection is opened.
///
/// The endpoint here has no listener, so an implementation that tried to
/// connect would report `ErrorKind::Transport` instead.
#[tokio::test]
async fn commit_refuses_an_empty_reference_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .commit_container(CommitContainerOptions::default())
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn commit_reports_a_rejection_and_does_not_retry() {
    let message = "No such container: missing";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (request_tx, request) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();
    let response = rejected("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));
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
                    let _ = retry_stream.write_all(&created(r#"{"Id":"retried"}"#));
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });

    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let error = client
        .commit_container(CommitContainerOptions {
            container: "missing".to_owned(),
            ..Default::default()
        })
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
            .line(),
        format!(
            "POST {}/commit?container=missing&pause=false HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    let retried = match retry.recv_timeout(Duration::from_millis(500)) {
        Ok(()) => true,
        Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => false,
    };
    assert!(
        !retried,
        "a failed owned commit request was retried through the generated client"
    );

    server.join().expect("the fixture thread");
}

/// A malformed answer is refused, and an empty id is not malformed.
#[tokio::test]
async fn commit_reports_malformed_documents_as_invalid_input() {
    let fixture = Fixture::start(vec![
        created("{}"),
        created(r#"{"Id":null}"#),
        created(r#"{"Id":7}"#),
        created("not json"),
        created(r#"{"Id":""}"#),
    ]);
    let client = fixture.client();

    for body in ["{}", r#"{"Id":null}"#, r#"{"Id":7}"#, "not json"] {
        let error = client
            .commit_container(CommitContainerOptions {
                container: "slice-db-1".to_owned(),
                ..Default::default()
            })
            .await
            .expect_err("an unusable id is refused");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidInput,
            "the owned path classifies a decode failure as invalid input: {body}"
        );
        assert_eq!(
            fixture.request().line(),
            format!(
                "POST {}/commit?container=slice-db-1&pause=false HTTP/1.1",
                version_prefix()
            ),
            "a malformed answer must not change which request was sent"
        );
    }

    // An empty id is a value the generated fallback also accepts, so the owned
    // projection must not turn it into a decode failure.
    let id = client
        .commit_container(CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            ..Default::default()
        })
        .await
        .expect("an empty id is a value");
    assert_eq!(id, "");
    fixture.request();

    fixture.finish();
}

/// Abandoning the request releases the connection and is not a retry.
///
/// The daemon never answers, so the fixture's read can only end when the client
/// releases the connection. It then watches for a second connection, which is
/// what a fallback after the abandoned request would look like.
#[tokio::test]
async fn commit_releases_the_connection_when_the_caller_abandons_it() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move {
        client
            .commit_container(CommitContainerOptions {
                container: "slice-db-1".to_owned(),
                ..Default::default()
            })
            .await
    });

    let request = tokio::time::timeout(Duration::from_secs(10), fixture.request)
        .await
        .expect("the fixture saw no request")
        .expect("the fixture reported");
    assert_eq!(
        request.line(),
        format!(
            "POST {}/commit?container=slice-db-1&pause=false HTTP/1.1",
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
        "abandoning the commit future did not release the connection"
    );

    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "an abandoned owned commit request was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
