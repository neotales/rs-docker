//! `DockerClient::task_logs` on the repository-owned transport.
//!
//! # Why a loopback fixture
//!
//! The owned route's claims are wire claims: a versioned
//! `GET /v1.NN/tasks/{id}/logs` with the Engine's own query shape, frames
//! decoded from Docker's eight-byte multiplexed headers, a status observed
//! before any frame is handed out, and cancellation that closes the socket.
//! None of that is visible in a request-builder assertion.
//!
//! # Bounded by construction
//!
//! Every read, accept, and stream poll is wrapped in a timeout, and the
//! cancellation fixture ends its connection after the client cancels. No test
//! starts a daemon. The captured local endpoint is in `swarm_task_local.rs`.

#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use neotales_docker::{
    API_VERSION, ContainerLogFrame, ContainerLogStream, ContainerLogsOptions, DockerClient,
    DockerStream, Endpoint, ErrorKind, ForwardProxy, ProxyPolicy,
};

const TASK_ID: &str = "task0123456789abcdef";

#[tokio::test]
async fn task_logs_distinguishes_absent_and_default_options() {
    for (options, query) in [
        (None, ""),
        (
            Some(ContainerLogsOptions::default()),
            "?follow=false&stdout=false&stderr=false&since=0&until=0&timestamps=false&tail=all",
        ),
    ] {
        let fixture = Fixture::start(framed_response(&[]));
        let mut logs = fixture.client().task_logs(TASK_ID, options);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), logs.next())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fixture.line(),
            format!(
                "GET {}/tasks/{TASK_ID}/logs{query} HTTP/1.1",
                version_prefix()
            )
        );
        fixture.finish();
    }
}

/// A loopback server that answers one request with fixed bytes.
struct Fixture {
    endpoint: String,
    requests: Receiver<String>,
    server: Option<JoinHandle<()>>,
}

impl Fixture {
    fn start(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut stream = accept_tcp(&listener);
            let line = read_head(&mut stream);
            let _ = request_tx.send(line);
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

    fn line(&self) -> String {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn finish(mut self) {
        self.server.take().expect("the server").join().unwrap();
    }
}

#[tokio::test]
async fn task_logs_sends_the_versioned_query_and_decodes_frames() {
    let body = [frame(1, b"hello\n"), frame(2, b"oops\n")].concat();
    let fixture = Fixture::start(framed_response(&body));
    let mut logs = fixture.client().task_logs(
        TASK_ID,
        Some(ContainerLogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            since: 1,
            until: 2,
            timestamps: false,
            tail: "10".to_owned(),
        }),
    );

    let frames = collect(&mut logs, 2).await;
    assert_eq!(frames[0].stream, ContainerLogStream::Stdout);
    assert_eq!(frames[0].payload, b"hello\n");
    assert_eq!(frames[1].stream, ContainerLogStream::Stderr);
    assert_eq!(frames[1].payload, b"oops\n");

    let line = fixture.line();
    assert_eq!(
        line,
        format!(
            "GET {}/tasks/{TASK_ID}/logs\
             ?follow=true&stdout=true&stderr=true&since=1&until=2\
             &timestamps=false&tail=10 HTTP/1.1",
            version_prefix()
        ),
        "the owned log request changed"
    );
    fixture.finish();
}

#[tokio::test]
async fn task_logs_reports_a_status_before_any_frame() {
    let body = r#"{"message":"service not found"}"#;
    let fixture = Fixture::start(
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let mut logs = fixture
        .client()
        .task_logs(TASK_ID, Some(ContainerLogsOptions::default()));

    let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the status was observed within the bound")
        .expect("the status is one stream item")
        .expect_err("a 404 is an error item");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 404);
    assert!(!api.message.contains("service not found"));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), logs.next())
            .await
            .expect("the end of the refused stream")
            .is_none(),
        "a refused log stream produced a frame after its status error"
    );

    fixture.finish();
}

#[tokio::test]
async fn task_logs_reports_a_truncated_frame() {
    let mut header = vec![1, 0, 0, 0];
    header.extend_from_slice(&9_u32.to_be_bytes());
    header.extend_from_slice(b"short");
    let fixture = Fixture::start(framed_response(&header));
    let mut logs = fixture
        .client()
        .task_logs(TASK_ID, Some(ContainerLogsOptions::default()));

    let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the truncated frame was reported within the bound")
        .expect("a truncated frame is one stream item")
        .expect_err("a truncated frame is an error item");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(
        error.to_string().contains("mid-frame"),
        "the refusal did not describe the truncation: {error}"
    );
    fixture.finish();
}

#[tokio::test]
async fn task_logs_rejects_a_frame_above_the_shared_limit() {
    let mut header = vec![1, 0, 0, 0];
    let length = u32::try_from(neotales_docker::raw::MAX_FRAME_BYTES + 1).unwrap();
    header.extend_from_slice(&length.to_be_bytes());
    let fixture = Fixture::start(framed_response(&header));
    let mut logs = fixture.client().task_logs(TASK_ID, None);
    let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    fixture.finish();
}

#[tokio::test]
async fn task_logs_refuses_an_empty_reference_without_sending() {
    let fixture = NoDispatch::start();
    let mut logs = fixture
        .client()
        .task_logs("", Some(ContainerLogsOptions::default()));
    let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the refusal was reported within the bound")
        .expect("the refusal is one stream item")
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("empty"),
        "the refusal did not name the empty reference: {error}"
    );
    fixture.finish();
}

#[tokio::test]
async fn cancelling_task_logs_closes_the_following_connection() {
    let (fixture, closed) = FollowFixture::start();
    let mut logs = fixture.client().task_logs(
        TASK_ID,
        Some(ContainerLogsOptions {
            follow: true,
            stdout: true,
            ..Default::default()
        }),
    );

    let first = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the first frame arrived within the bound")
        .expect("the first frame is one item")
        .expect("the first frame decoded");
    assert_eq!(first.payload, b"first\n");
    assert!(!logs.is_closed());

    logs.cancel();
    assert!(logs.is_closed(), "cancel did not close the handle");
    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .expect("cancelling the log handle did not close the socket")
        .expect("the fixture's disconnect signal");

    fixture.finish();
}

#[tokio::test]
async fn dropping_task_logs_closes_the_following_connection_without_retry() {
    let (fixture, closed) = FollowFixture::start();
    let mut logs = fixture.client().task_logs(
        TASK_ID,
        Some(ContainerLogsOptions {
            follow: true,
            stdout: true,
            ..Default::default()
        }),
    );
    let first = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"first\n");
    drop(logs);
    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .unwrap()
        .unwrap();
    fixture.finish();
}

#[tokio::test]
async fn task_logs_withholds_direct_and_proxy_failure_text() {
    use std::error::Error as _;
    use std::fmt::Write as _;
    const SENTINEL: &str = "task-log-output-and-peer-secret-sentinel";
    for proxied in [false, true] {
        let body = format!("{{\"message\":\"{SENTINEL}\"}}");
        let fixture = Fixture::start(
            format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let client = if proxied {
            DockerClient::connect_endpoint_with_policy(
                &Endpoint::Http("http://127.0.0.1:1".to_owned()),
                ProxyPolicy::Http(
                    ForwardProxy::with_basic_auth(
                        &fixture.endpoint,
                        "fixture-user",
                        "fixture-password",
                    )
                    .unwrap(),
                ),
            )
            .unwrap()
        } else {
            fixture.client()
        };
        let mut logs = client.task_logs(TASK_ID, None);
        let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.api_error().unwrap().status_code, 403);
        assert!(error.api_error().unwrap().message.contains("withheld"));
        let mut chain = format!("{error} {error:?}");
        let mut source = error.source();
        while let Some(item) = source {
            write!(chain, " {item} {item:?}").unwrap();
            source = item.source();
        }
        assert!(!chain.contains(SENTINEL), "{chain}");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), logs.next())
                .await
                .unwrap()
                .is_none()
        );
        fixture.finish();
    }
}

#[tokio::test]
async fn task_logs_rejects_informational_and_not_modified_statuses() {
    for status in [101, 304] {
        let fixture = Fixture::start(
            format!("HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .into_bytes(),
        );
        let mut logs = fixture.client().task_logs(TASK_ID, None);
        let error = tokio::time::timeout(Duration::from_secs(5), logs.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.api_error().unwrap().status_code, status);
        fixture.finish();
    }
}

/// A server that writes one frame, then keeps the connection open until the
/// client closes it.
struct FollowFixture {
    endpoint: String,
    line: Receiver<String>,
    server: Option<JoinHandle<()>>,
}

impl FollowFixture {
    fn start() -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (line_tx, line) = mpsc::channel();
        let (closed_tx, closed) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let mut stream = accept_tcp(&listener);
            let _ = line_tx.send(read_head(&mut stream));
            let header = "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: keep-alive\r\n\r\n";
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&frame(1, b"first\n")).unwrap();
            stream.flush().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut buffer = [0_u8; 64];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    let _ = closed_tx.send(());
                    break;
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => panic!("task logs retried after closing"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("retry watcher failed: {error}"),
                }
            }
        });
        (
            Self {
                endpoint: format!("http://{address}"),
                line,
                server: Some(server),
            },
            closed,
        )
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn finish(mut self) {
        let _line = self
            .line
            .recv_timeout(Duration::from_secs(5))
            .expect("the fixture recorded no request");
        self.server.take().expect("the server").join().unwrap();
    }
}

/// A listener that records any connection and is stopped explicitly.
struct NoDispatch {
    endpoint: String,
    requests: Receiver<String>,
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
                        let _ = request_tx.send(read_head(&mut stream));
                        let _ = stream.write_all(&framed_response(&[]));
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

/// Reads `count` frames from a handle within a total bound.
async fn collect(
    logs: &mut DockerStream<ContainerLogFrame>,
    count: usize,
) -> Vec<ContainerLogFrame> {
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        let frame = tokio::time::timeout(Duration::from_secs(5), logs.next())
            .await
            .expect("the frame arrived within the bound")
            .expect("the stream ended before the expected frame")
            .expect("the frame decoded");
        frames.push(frame);
    }
    frames
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// One multiplexed frame: stream selector, three reserved bytes, length, then
/// the payload.
fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![stream, 0, 0, 0];
    let length = u32::try_from(payload.len()).expect("a fixture frame fits in u32");
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn framed_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
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

fn read_head(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound the fixture read");
    read_head_bytes(stream)
}

fn read_head_bytes(stream: &mut impl Read) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&request[..end]).expect("UTF-8 headers");
            return head.lines().next().expect("the request line").to_owned();
        }
    }
}
