//! `DockerClient::inspect_config` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `inspect_config` must open
//! `GET /v1.NN/configs/{id}` through the owned transport when that transport
//! can reach the endpoint, rather than the unversioned path the generated
//! client sends. Asserting that against a request builder would only show what
//! the builder would produce if it were called; the routing decision is above
//! it. A loopback HTTP fixture is the only place the wire request and the
//! routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `inspect_config`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix and the percent-encoding of the reference, and the unmodelled
//! members below are discarded by Bollard's 1.53 models instead of being
//! retained in `SwarmConfig::additional`. The projection assertions fail with
//! it.
//!
//! The rejection tests pin two contracts: a daemon rejection keeps its status
//! and message in [`Error::api_error`], and a failed owned request is returned
//! rather than retried over the generated client. The version-rejection case is
//! the one a daemon older than the configured API version sends, and it must
//! not be mistaken for a reason to fall back.
//!
//! Config data may be sensitive. The fixtures carry a synthetic canary, and the
//! decode tests assert it appears in no `Display`, `Debug`, or source-chain
//! rendering of the failure.
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

#[path = "support/swarm_config_entries.rs"]
mod swarm_config_entries;

use swarm_config_entries::{
    CONFIG_BODY, CONFIG_DATA_BASE64, CONFIG_DATA_CANARY, MALFORMED_BODY, WRONG_TYPE_BODY,
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
                        let _ = retry_stream.write_all(&ok_json(CONFIG_BODY));
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

/// Reads the request head, which is all a config inspect request sends.
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

/// The owned path sends the versioned request, projects the named members,
/// returns the data member, and retains the members it does not model.
#[tokio::test]
async fn inspect_config_sends_a_versioned_request_and_preserves_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(CONFIG_BODY)]);
    let config = fixture
        .client()
        .inspect_config("config-fixture")
        .await
        .expect("the config document decoded");

    assert_eq!(config.id.as_deref(), Some("config-fixture"));
    assert_eq!(config.version.and_then(|version| version.index), Some(9));
    let spec = config.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("fixture-config"));
    assert_eq!(
        spec.data.as_deref(),
        Some(CONFIG_DATA_BASE64),
        "the inspect answer's config data was discarded"
    );
    assert_eq!(
        config.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": 7})),
        "the owned path discarded an unmodelled top-level member"
    );
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true})),
        "the owned path discarded an unmodelled spec member"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs/config-fixture HTTP/1.1", version_prefix()),
        "inspect_config fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The owned path sends the API version the client was configured with, and
/// encodes the reference as a single path segment.
#[tokio::test]
async fn inspect_config_sends_the_configured_version_and_encodes_the_reference() {
    let fixture = Fixture::start(vec![ok_json(CONFIG_BODY)]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .inspect_config("config id/with?slash")
        .await
        .expect("the config document decoded");

    assert_eq!(
        fixture.request_line(),
        "GET /v1.47/configs/config%20id%2Fwith%3Fslash HTTP/1.1",
        "the owned path did not use the configured version or one encoded segment"
    );

    fixture.finish();
}

/// The owned path refuses an empty reference before dispatch, so no connection
/// reaches the fixture. The generated fallback has no such check; the fallback
/// suite pins that difference.
#[tokio::test]
async fn inspect_config_rejects_an_empty_reference_before_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .inspect_config("")
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

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn inspect_config_reports_a_rejection_and_does_not_retry() {
    let message = "config config-fixture not found";
    let fixture =
        RejectingFixture::start("404 Not Found", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_config("config-fixture")
        .await
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs/config-fixture HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned inspect_config request was retried through the generated client"
    );

    fixture.finish();
}

/// An older daemon's "client version too new" rejection is the daemon's answer,
/// not a reason to fall back, and it is not retried.
#[tokio::test]
async fn inspect_config_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.41";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .inspect_config("config-fixture")
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs/config-fixture HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "an old-daemon rejection was retried through the generated client"
    );

    fixture.finish();
}

/// A success body the owned decoder cannot read is a decode failure in its own
/// error class. The fallback suite sends the same bodies through the generated
/// client, where the same failure is `ErrorKind::Docker`.
#[tokio::test]
async fn inspect_config_rejects_malformed_and_wrongly_typed_documents() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_config("config-fixture")
            .await
            .expect_err("a malformed config document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// Config data may be sensitive, so a decode failure must not echo response
/// text through `Display`, `Debug`, or the source chain. The fixtures place the
/// canary in the document and in the wrongly typed value serde would quote.
#[tokio::test]
async fn inspect_config_decode_errors_do_not_echo_config_data_canaries() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_config("config-fixture")
            .await
            .expect_err("a malformed config document is refused");

        let mut renderings = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            renderings.push(cause.to_string());
            renderings.push(format!("{cause:?}"));
            source = cause.source();
        }
        for (index, rendering) in renderings.iter().enumerate() {
            for canary in [CONFIG_DATA_CANARY, CONFIG_DATA_BASE64] {
                assert!(
                    !rendering.contains(canary),
                    "decode error rendering {index} echoed config data: {rendering}"
                );
            }
        }

        fixture.finish();
    }
}
