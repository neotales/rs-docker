//! `DockerClient::remove_service` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim is a transport claim: a reachable endpoint must receive the
//! versioned `DELETE /v1.NN/services/{id}`, and the reference must stay one
//! path segment. A request-builder assertion would not show the routing, and
//! the escaping is only observable on the wire.
//!
//! The generated fallback that remains for a local endpoint is in
//! `service_remove_fallback.rs`; it is Unix-only because it needs a Unix
//! socket, and this file runs on every platform.
#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use neotales_docker::{API_VERSION, DockerClient, ErrorKind};

const SERVICE_ID: &str = "service0123456789abcdef";

/// A reference that would address another path shape if it were interpolated.
const ESCAPED_ID: &str = "web/with space %2F";

/// A loopback server that records one request and answers it.
struct Fixture {
    endpoint: String,
    requests: Receiver<Captured>,
    server: Option<JoinHandle<()>>,
}

impl Fixture {
    fn start(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut stream = accept_tcp(&listener);
            let captured = read_request(&mut stream);
            let _ = request_tx.send(captured);
            stream
                .write_all(&response)
                .expect("write the fixture answer");
            stream.flush().expect("flush the fixture answer");
            release(&mut stream);
        });
        Self {
            endpoint: format!("http://{address}"),
            requests,
            server: Some(server),
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

    fn finish(mut self) {
        self.server.take().expect("the server").join().unwrap();
    }
}

#[tokio::test]
async fn remove_service_sends_a_versioned_escaped_request() {
    let fixture = Fixture::start(no_content());
    fixture
        .client()
        .remove_service(ESCAPED_ID)
        .await
        .expect("a 204 is success");

    let request = fixture.next();
    let escaped = "web%2Fwith%20space%20%252F";
    assert_eq!(
        request.line,
        format!("DELETE {}/services/{escaped} HTTP/1.1", version_prefix()),
        "the owned removal did not version or escape the reference"
    );
    assert_eq!(request.body, Vec::<u8>::new());
    fixture.finish();
}

#[tokio::test]
async fn remove_service_treats_a_200_with_an_empty_body_as_success() {
    let fixture = Fixture::start(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    );
    fixture
        .client()
        .remove_service(SERVICE_ID)
        .await
        .expect("a 200 with no body is success");
    assert_eq!(
        fixture.next().line,
        format!("DELETE {}/services/{SERVICE_ID} HTTP/1.1", version_prefix())
    );
    fixture.finish();
}

#[tokio::test]
async fn remove_service_keeps_the_daemon_message_and_does_not_retry() {
    let message = "service not found";
    let fixture = Fixture::start(
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{{\"message\":\"{message}\"}}",
            format!("{{\"message\":\"{message}\"}}").len()
        )
        .into_bytes(),
    );
    let error = fixture
        .client()
        .remove_service(SERVICE_ID)
        .await
        .expect_err("a 404 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's status");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.next().line,
        format!("DELETE {}/services/{SERVICE_ID} HTTP/1.1", version_prefix())
    );
    assert!(
        fixture
            .requests
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "a failed owned removal was retried"
    );
    fixture.finish();
}

#[tokio::test]
async fn remove_service_refuses_an_empty_reference_before_dispatch() {
    let fixture = NoDispatch::start();
    let error = fixture
        .client()
        .remove_service("")
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("empty"),
        "the refusal did not name the empty reference: {error}"
    );
    fixture.finish();
}

/// A listener that records any connection and is stopped explicitly.
///
/// A fixture that waited for the request an empty-reference refusal must not
/// send would turn a passing test into a ten-second timeout.
struct NoDispatch {
    endpoint: String,
    requests: Receiver<Captured>,
    stop: mpsc::Sender<()>,
    server: JoinHandle<()>,
}

impl NoDispatch {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let (request_tx, requests) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let lifetime = Instant::now() + Duration::from_secs(30);
            loop {
                assert!(
                    Instant::now() < lifetime,
                    "the no-dispatch watcher lifetime expired"
                );
                if !matches!(stop_rx.try_recv(), Err(mpsc::TryRecvError::Empty)) {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let captured = read_request(&mut stream);
                        let _ = request_tx.send(captured);
                        let _ = stream.write_all(&no_content());
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            requests,
            stop,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn finish(self) {
        let _ = self.stop.send(());
        self.server.join().expect("the fixture thread");
        assert!(
            self.requests.try_recv().is_err(),
            "an empty reference was sent as a request"
        );
    }
}

/// A recorded request line and body.
struct Captured {
    line: String,
    body: Vec<u8>,
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
}

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

fn release(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}
