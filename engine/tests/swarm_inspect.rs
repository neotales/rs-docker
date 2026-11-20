//! `DockerClient::inspect_swarm` and `swarm_join_token` on the
//! repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `inspect_swarm` must open
//! `GET /v1.NN/swarm` through the owned transport when that transport can reach
//! the endpoint, rather than the unversioned path the generated client sends.
//! Asserting that against a request builder would only show what the builder
//! would produce if it were called; the routing decision is above it. A
//! loopback HTTP fixture is the only place the wire request and the routing are
//! the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `inspect_swarm`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, and the unmodelled members below are discarded by Bollard's
//! 1.53 models instead of being retained in `SwarmInfo::additional`. The
//! projection and redaction assertions fail with it.
//!
//! The rejection test pins two contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], and a failed owned request is
//! returned rather than retried over the generated client.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, DockerClient, ErrorKind, SwarmJoinTokenRole};

#[path = "support/swarm_inspect_entries.rs"]
mod swarm_inspect_entries;

use swarm_inspect_entries::{
    BLANK_TOKENS_BODY, MALFORMED_BODY, MANAGER_TOKEN, SWARM_BODY, WORKER_ONLY_BODY, WORKER_TOKEN,
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

/// Reads the request head, which is all a Swarm inspect request sends.
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

/// The owned path sends the versioned request, projects the named members, and
/// retains the members it does not model.
#[tokio::test]
async fn inspect_swarm_sends_a_versioned_request_and_preserves_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(SWARM_BODY)]);
    let swarm = fixture
        .client()
        .inspect_swarm()
        .await
        .expect("the Swarm document decoded");

    assert_eq!(swarm.id.as_deref(), Some("swarm-fixture"));
    assert_eq!(swarm.version.and_then(|version| version.index), Some(12));
    let tokens = swarm.join_tokens.as_ref().expect("the daemon sent tokens");
    assert_eq!(tokens["Worker"], WORKER_TOKEN);
    assert_eq!(tokens["Manager"], MANAGER_TOKEN);
    assert_eq!(
        swarm.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": 7})),
        "the owned path discarded an unmodelled top-level member"
    );
    let spec = swarm.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("fixture-swarm"));
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true})),
        "the owned path discarded an unmodelled spec member"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/swarm HTTP/1.1", version_prefix()),
        "inspect_swarm fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// `swarm_join_token` reads the same `GET /swarm` document through the same
/// routing decision, and treats an absent or blank member as "no token".
#[tokio::test]
async fn join_token_reads_the_engine_members_through_the_owned_route() {
    let fixture = Fixture::start(vec![
        ok_json(SWARM_BODY),
        ok_json(WORKER_ONLY_BODY),
        ok_json(BLANK_TOKENS_BODY),
    ]);
    let client = fixture.client();

    assert_eq!(
        client
            .swarm_join_token(SwarmJoinTokenRole::Worker)
            .await
            .expect("the worker token decoded")
            .as_deref(),
        Some(WORKER_TOKEN)
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/swarm HTTP/1.1", version_prefix())
    );

    assert_eq!(
        client
            .swarm_join_token(SwarmJoinTokenRole::Manager)
            .await
            .expect("a worker's answer is not an error"),
        None,
        "a worker reported a manager token"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/swarm HTTP/1.1", version_prefix())
    );

    assert_eq!(
        client
            .swarm_join_token(SwarmJoinTokenRole::Worker)
            .await
            .expect("a blank token is not an error"),
        None,
        "a blank token was returned as a credential"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/swarm HTTP/1.1", version_prefix())
    );

    fixture.finish();
}

/// The owned path returns the daemon's tokens to the caller but never renders
/// them in `Debug`, and it reports the unmodelled members it retained.
#[tokio::test]
async fn inspect_swarm_redacts_join_tokens_and_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(SWARM_BODY)]);
    let swarm = fixture
        .client()
        .inspect_swarm()
        .await
        .expect("the Swarm document decoded");

    let rendered = format!("{swarm:?}");
    for token in [WORKER_TOKEN, MANAGER_TOKEN] {
        assert!(
            !rendered.contains(token),
            "a SwarmInfo Debug leaked a join token: {rendered}"
        );
    }
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains("1 unmodeled member(s)"), "{rendered}");
    assert!(rendered.contains("swarm-fixture"), "{rendered}");

    fixture.finish();
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn inspect_swarm_reports_a_rejection_and_does_not_retry() {
    let message = "This node is not a swarm manager";
    let fixture = RejectingFixture::start(
        "503 Service Unavailable",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .inspect_swarm()
        .await
        .expect_err("a 503 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 503);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/swarm HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned inspect_swarm request was retried through the generated client"
    );

    fixture.finish();
}

/// A success body the owned decoder cannot read is a decode failure in its own
/// error class. The fallback suite sends the same bodies through the generated
/// client, where the same failure is `ErrorKind::Docker`.
#[tokio::test]
async fn inspect_swarm_rejects_malformed_and_wrongly_typed_documents() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .inspect_swarm()
            .await
            .expect_err("a malformed Swarm document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// A wrong-typed member must not echo response text, including a credential
/// from the same document, through `Display`, `Debug`, or the source chain.
///
/// `serde_json::Error`'s own `Display` quotes the unexpected value. The Swarm
/// document is decoded by the generic owned decoder, so a token placed in a
/// wrong-typed member such as `Version` reached the error's `Display` and every
/// source it wraps. The regression is load-bearing: it fails on the base
/// decoder and passes once the content-free decode summary from the proxy work
/// is assembled. Until then this test is expected to fail; it is deliberately
/// not ignored.
#[tokio::test]
async fn inspect_swarm_decode_errors_do_not_echo_join_token_canaries() {
    let body = format!(
        r#"{{"ID":"swarm-fixture","Version":"{WORKER_TOKEN}","JoinTokens":{{"Worker":"{WORKER_TOKEN}"}}}}"#
    );
    let fixture = Fixture::start(vec![ok_json(&body)]);
    let error = fixture
        .client()
        .inspect_swarm()
        .await
        .expect_err("a wrongly typed Swarm document is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    for (index, rendering) in renderings.iter().enumerate() {
        assert!(
            !rendering.contains(WORKER_TOKEN),
            "decode error rendering {index} echoed response text"
        );
    }

    fixture.finish();
}
