//! `DockerClient::leave_swarm` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `leave_swarm` must open
//! `POST /v1.NN/swarm/leave?force=…` through the owned transport when that
//! transport can reach the endpoint, rather than the unversioned path the
//! generated client sends. Asserting that against a request builder would only
//! show what the builder would produce if it were called; the routing decision
//! is above it. A loopback HTTP fixture is the only place the wire request and
//! the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `leave_swarm`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, and `force=false` stops being spelled at all. Both are
//! compared whole.
//!
//! The rejection tests pin two contracts: a daemon rejection keeps its status
//! and message in [`Error::api_error`], and a failed owned request is returned
//! rather than retried over the generated client. The version-rejection case is
//! the one a daemon older than the configured API version sends, and it must
//! not be mistaken for a reason to fall back. The cancellation test pins that
//! abandoning the future releases the connection and is not a retry; the daemon
//! may still have processed the leave, which is the uncertainty the method's
//! documentation states.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind};

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
                        let _ = retry_stream.write_all(&ok_empty());
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
                        let _ = retry_stream.write_all(&ok_empty());
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

/// Reads the request head, which is all a leave request sends.
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

/// A `200` answer with no body, which is what a successful leave sends.
fn ok_empty() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
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

/// `force=true` is sent as a versioned request, and the success is `Ok(())`.
#[tokio::test]
async fn leave_swarm_sends_a_versioned_force_true_request() {
    let fixture = Fixture::start(vec![ok_empty()]);
    fixture
        .client()
        .leave_swarm(neotales_docker::SwarmLeaveOptions { force: true })
        .await
        .expect("a 200 leave is not an error");

    assert_eq!(
        fixture.request_line(),
        format!("POST {}/swarm/leave?force=true HTTP/1.1", version_prefix()),
        "leave_swarm fell back to the unversioned generated path, or lost force=true"
    );

    fixture.finish();
}

/// `force=false` is spelled rather than omitted, which is the difference a
/// recorded request can state and the generated path cannot.
#[tokio::test]
async fn leave_swarm_spells_force_false_on_the_owned_path() {
    let fixture = Fixture::start(vec![ok_empty()]);
    fixture
        .client()
        .leave_swarm(neotales_docker::SwarmLeaveOptions { force: false })
        .await
        .expect("a 200 leave is not an error");

    assert_eq!(
        fixture.request_line(),
        format!("POST {}/swarm/leave?force=false HTTP/1.1", version_prefix()),
        "leave_swarm fell back to the unversioned generated path, or omitted force=false"
    );

    fixture.finish();
}

/// The owned path sends the API version the client was configured with, not
/// the crate's default. A daemon that only serves an older version is reached
/// by configuring that version.
#[tokio::test]
async fn leave_swarm_sends_the_configured_version() {
    let fixture = Fixture::start(vec![ok_empty()]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .leave_swarm(neotales_docker::SwarmLeaveOptions { force: false })
        .await
        .expect("a 200 leave is not an error");

    assert_eq!(
        fixture.request_line(),
        "POST /v1.47/swarm/leave?force=false HTTP/1.1",
        "the owned path did not use the configured API version"
    );

    fixture.finish();
}

/// An older daemon's "client version too new" rejection is the daemon's answer,
/// not a reason to fall back, and it is not retried.
#[tokio::test]
async fn leave_swarm_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.41";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .leave_swarm(neotales_docker::SwarmLeaveOptions { force: false })
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("POST {}/swarm/leave?force=false HTTP/1.1", version_prefix()),
        "the version rejection must be the owned request, not the unversioned one"
    );
    assert!(
        !fixture.saw_retry(),
        "an old daemon's version rejection was retried through the generated client"
    );

    fixture.finish();
}

/// A manager's unforced leave is refused, and the refusal keeps its status and
/// message without a retry.
#[tokio::test]
async fn leave_swarm_reports_a_manager_rejection_and_does_not_retry() {
    let message = "You are attempting to leave the swarm on a node that is participating as a \
                   manager. Removing the last manager erases all current state of the swarm. Use \
                   `--force` to ignore this message.";
    let fixture = RejectingFixture::start(
        "503 Service Unavailable",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .leave_swarm(neotales_docker::SwarmLeaveOptions { force: false })
        .await
        .expect_err("a 503 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 503);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("POST {}/swarm/leave?force=false HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned leave request was retried through the generated client"
    );

    fixture.finish();
}

/// Abandoning the request releases the connection and is not a retry.
///
/// The daemon never answers, so the fixture's read can only end when the client
/// releases the connection. It then watches for a second connection, which is
/// what a fallback after the abandoned request would look like. The daemon may
/// still have processed the leave, which is the uncertainty the method's
/// documentation states; this test can only pin the wire behaviour.
#[tokio::test]
async fn leave_swarm_releases_the_connection_when_the_caller_abandons_it() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move {
        client
            .leave_swarm(neotales_docker::SwarmLeaveOptions { force: true })
            .await
    });

    let request = tokio::time::timeout(Duration::from_secs(10), fixture.request)
        .await
        .expect("the fixture saw no request")
        .expect("the fixture reported");
    assert_eq!(
        request
            .lines()
            .next()
            .expect("the request has a request line"),
        format!("POST {}/swarm/leave?force=true HTTP/1.1", version_prefix()),
        "the abandoned request must be the owned one"
    );

    task.abort();
    let released = tokio::time::timeout(Duration::from_secs(10), fixture.released)
        .await
        .expect("the fixture did not observe the disconnect")
        .expect("the fixture reported");
    assert!(
        released,
        "abandoning the leave future did not release the connection"
    );

    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "an abandoned owned leave request was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
