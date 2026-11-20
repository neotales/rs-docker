//! `DockerClient::restart_container` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `restart_container` must
//! open `POST /v1.NN/containers/{id}/restart` through the owned transport when
//! that transport can reach the endpoint, rather than the unversioned path the
//! generated client sends. Asserting that against a request builder would only
//! show what the builder would produce if it were called; the routing decision
//! is above it. A loopback HTTP fixture is the only place the wire request and
//! the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `restart_container` puts the generated client back on the wire. The request
//! line then loses the version prefix, and an unescaped reference with a slash
//! changes the path shape, so both comparisons fail. That mutation is the
//! reason the request line is compared whole rather than only checked for one
//! query value.
//!
//! The rejection test pins two other contracts at once: a daemon rejection
//! keeps its status and message in [`Error::api_error`], and a failed owned
//! request is returned rather than retried over the generated client. The
//! empty-reference test pins that a caller mistake is refused before a
//! connection is opened.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, ContainerRestartOptions, DockerClient, ErrorKind};

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

/// Reads the request head, which is all a restart request sends.
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

/// The `204 No Content` answer the daemon gives a successful restart.
fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
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

/// The owned path sends the versioned request with the caller's signal and
/// timeout in the daemon's parameter order.
#[tokio::test]
async fn restart_sends_a_versioned_request_with_the_signal_and_timeout() {
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .restart_container(
            "slice-db-1",
            Some(ContainerRestartOptions {
                signal: Some("SIGTERM".to_owned()),
                timeout_seconds: Some(10),
            }),
        )
        .await
        .expect("a 204 is a successful restart");

    assert_eq!(
        fixture.request_line(),
        format!(
            "POST {}/containers/slice-db-1/restart?signal=SIGTERM&t=10 HTTP/1.1",
            version_prefix()
        ),
        "restart_container fell back to the unversioned generated path or reordered the parameters"
    );

    fixture.finish();
}

/// Unset options are omitted rather than guessed, so the daemon's own defaults
/// apply.
#[tokio::test]
async fn restart_without_options_sends_no_query() {
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .restart_container("slice-db-1", None)
        .await
        .expect("a 204 is a successful restart");

    assert_eq!(
        fixture.request_line(),
        format!(
            "POST {}/containers/slice-db-1/restart HTTP/1.1",
            version_prefix()
        ),
        "an unset restart option became a query value instead of the daemon's default"
    );

    fixture.finish();
}

/// A container reference is one path segment even when it contains a slash.
#[tokio::test]
async fn restart_escapes_the_container_reference() {
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .restart_container("a/b", None)
        .await
        .expect("a 204 is a successful restart");

    assert_eq!(
        fixture.request_line(),
        format!(
            "POST {}/containers/a%2Fb/restart HTTP/1.1",
            version_prefix()
        ),
        "restart_container stopped encoding the container reference"
    );

    fixture.finish();
}

/// An empty reference is refused before a connection is opened.
///
/// This test exercises only the owned path; the fallback's empty-reference
/// behavior belongs to the generated client and is not observed here. The
/// difference is documented on `DockerClient::restart_container`. The endpoint
/// here has no listener, so a path that tried to connect would report
/// `ErrorKind::Transport` instead.
#[tokio::test]
async fn restart_refuses_an_empty_reference_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .restart_container("", None)
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
async fn restart_reports_a_rejection_and_does_not_retry() {
    let message = "No such container: missing";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .restart_container("missing", None)
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!(
            "POST {}/containers/missing/restart HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned restart request was retried through the generated client"
    );

    fixture.finish();
}
