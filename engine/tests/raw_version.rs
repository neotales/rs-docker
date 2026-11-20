//! Public `raw::version` compatibility.
//!
//! `raw::version` is the low-level document operation. Its contract is the JSON
//! value the daemon sent, not the facade's version-document rules: a known
//! member with an unexpected type is still returned, a duplicate key resolves
//! the way `serde_json::Value` resolves it, and a non-object JSON value is
//! accepted. These tests pin that behavior from outside the crate so the strict
//! facade validation cannot leak into the public raw operation.
//!
//! The facade's strict validation is tested separately in `version_routing.rs`
//! and `version_routing_fallback.rs`.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::raw::{MAX_DOCUMENT_BYTES, RawEngine, RawTarget, version};
use neotales_docker::{API_VERSION, ErrorKind};

/// A one-request-at-a-time HTTP fixture that records each request head.
struct Fixture {
    host: String,
    port: u16,
    requests: Receiver<String>,
    second_request: Receiver<()>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        Self::start_inner(responses, false)
    }

    /// Answers one request and then watches for a second connection.
    fn start_watching(response: Vec<u8>) -> Self {
        Self::start_inner(vec![response], true)
    }

    fn start_inner(responses: Vec<Vec<u8>>, watch: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let (second_tx, second_request) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept the request");
                let head = read_request_head(&mut stream);
                let _ = request_tx.send(head);
                stream
                    .write_all(&response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
                wait_for_client_close(&mut stream);
            }

            if watch {
                listener
                    .set_nonblocking(true)
                    .expect("make the fixture listener nonblocking");
                let deadline = Instant::now() + Duration::from_millis(300);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut second, _)) => {
                            let _ = read_request_head(&mut second);
                            let _ = second_tx.send(());
                            let _ = second.write_all(&ok_json("{}"));
                            return;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            }
        });
        Self {
            host: address.ip().to_string(),
            port: address.port(),
            requests,
            second_request,
            server,
        }
    }

    fn engine(&self) -> RawEngine {
        RawEngine::new(
            RawTarget::Tcp {
                host: self.host.clone(),
                port: self.port,
            },
            API_VERSION,
        )
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

    fn saw_second_request(&self) -> bool {
        match self.second_request.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A fixture that writes a document larger than the transport bound and ignores
/// the client's early disconnect.
struct OversizedFixture {
    host: String,
    port: u16,
    server: JoinHandle<()>,
}

impl OversizedFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let _ = read_request_head(&mut stream);
            let length = MAX_DOCUMENT_BYTES + 1024;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {length}\r\n\r\n"
            );
            let _ = stream.write_all(head.as_bytes());
            let chunk = vec![b'x'; 64 * 1024];
            let mut written = 0;
            while written < length {
                let remaining = length - written;
                let take = remaining.min(chunk.len());
                if stream.write_all(&chunk[..take]).is_err() {
                    break;
                }
                written += take;
            }
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        });
        Self {
            host: address.ip().to_string(),
            port: address.port(),
            server,
        }
    }

    fn engine(&self) -> RawEngine {
        RawEngine::new(
            RawTarget::Tcp {
                host: self.host.clone(),
                port: self.port,
            },
            API_VERSION,
        )
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

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

fn wait_for_client_close(stream: &mut TcpStream) {
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

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// A known member with an unexpected type is still the JSON value the daemon
/// sent. The facade rejects it; this operation must not.
#[tokio::test]
async fn raw_version_accepts_a_mistyped_known_member() {
    let fixture = Fixture::start(vec![ok_json(r#"{"Version":29}"#)]);
    let value = version(&fixture.engine())
        .await
        .expect("raw::version returns the JSON value");
    assert_eq!(value["Version"].as_i64(), Some(29));
    fixture.finish();
}

/// Duplicate known members resolve the way `serde_json::Value` resolves them:
/// the last value wins. The facade rejects the duplicate; this operation must
/// not.
#[tokio::test]
async fn raw_version_keeps_the_last_duplicate_known_member() {
    let fixture = Fixture::start(vec![ok_json(r#"{"Version":"29.8.0","Version":"29.8.1"}"#)]);
    let value = version(&fixture.engine())
        .await
        .expect("raw::version returns the JSON value");
    assert_eq!(value["Version"].as_str(), Some("29.8.1"));
    fixture.finish();
}

/// A non-object JSON value was accepted before the facade was routed through
/// the owned transport, and it still is.
#[tokio::test]
async fn raw_version_accepts_a_non_object_json_value() {
    let fixture = Fixture::start(vec![ok_json("[]")]);
    let value = version(&fixture.engine())
        .await
        .expect("raw::version returns the JSON value");
    assert_eq!(
        value.as_array().map(Vec::len),
        Some(0),
        "the array was not returned as sent"
    );
    fixture.finish();
}

/// A body that is not JSON is still a decode failure, as before.
#[tokio::test]
async fn raw_version_rejects_a_non_json_body() {
    let fixture = Fixture::start(vec![ok_json(r#"{"Version":"29.8.0""#)]);
    let error = version(&fixture.engine())
        .await
        .expect_err("a truncated body is not JSON");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("failed to decode"),
        "the refusal did not name the decode: {error}"
    );
    fixture.finish();
}

/// The document is read once: no validation pass opens a second request.
#[tokio::test]
async fn raw_version_reads_the_document_once() {
    let fixture = Fixture::start_watching(ok_json(r#"{"Version":"29.8.0"}"#));
    let value = version(&fixture.engine())
        .await
        .expect("raw::version returns the JSON value");
    assert_eq!(value["Version"].as_str(), Some("29.8.0"));
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/version HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_second_request(),
        "raw::version opened a second request"
    );
    fixture.finish();
}

/// The response body is still bounded by the transport document limit.
#[tokio::test]
async fn raw_version_remains_bounded() {
    let fixture = OversizedFixture::start();
    let error = version(&fixture.engine())
        .await
        .expect_err("an oversized document is refused");
    assert_eq!(error.kind(), ErrorKind::Transport);
    let reason = std::error::Error::source(&error)
        .expect("the transport reason")
        .to_string();
    assert!(
        reason.contains("limit"),
        "the refusal did not name the document limit: {reason}"
    );
    fixture.finish();
}
