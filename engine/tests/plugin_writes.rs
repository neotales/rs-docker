//! Plugin writes on the repository-owned transport: routing, withheld failure
//! text, and the fixed refusals where a generated fallback would be unsafe.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims here are *transport* claims. `set_plugin_config`, `push_plugin`,
//! and the credentialed install, upgrade, and push variants must open their
//! versioned Engine paths through the owned transport, carry the body and the
//! `X-Registry-Auth` header the Engine reads, and never fall back to the
//! generated client. A request builder only shows what the builder would produce;
//! a loopback fixture is the one place the wire request and the routing are the
//! same observation.
//!
//! # What the withholding tests are written to catch
//!
//! `set_plugin_config` and the credentialed registry calls carry a secret. A
//! direct daemon, an unauthenticated plain-HTTP proxy, and an authenticated one
//! can all echo request or response text. The tests place a synthetic setting, a
//! synthetic password, the base64 header, and an endpoint canary in the failure
//! body and in the transport's own text, then walk `Display`, `Debug`, every
//! source, and `api_error` and require that none of them appears. They also pin
//! that the status is preserved, that `101` and `304` are failures rather than
//! success, and that a deadline marker survives without the fixed text claiming
//! this request timed out.
//!
//! Anonymous install, upgrade, and push keep the daemon's own message; the
//! anonymous install test is the control that proves the withholding is limited
//! to the secret-bearing calls.
//!
//! # Fixture bounds
//!
//! Every server here polls a nonblocking listener with a deadline and a stop
//! flag, bounds reads and writes, and joins its thread. `Drop` stops the thread,
//! so a panicking test cannot leave a detached thread blocking on `accept`.
//! Every test reaches the public API, so none needs a running daemon.
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use neotales_docker::raw;
use neotales_docker::{
    API_VERSION, DockerClient, Endpoint, ErrorKind, ForwardProxy, ImageStreamEvent,
    PluginInstallOptions, PluginUpgradeOptions, ProxyPolicy, RegistryCredentials,
};

/// The fixed text a settings write uses instead of daemon or proxy text.
const WITHHELD_SET: &str = "response text withheld for a plugin settings write because the request may carry plugin secrets";

/// The fixed text a credential-bearing registry request uses.
const WITHHELD_CREDENTIAL: &str = "response text withheld for a plugin registry request because the request carries a registry credential";

/// The fixed text a credentialed install uses for an in-band failure record.
const WITHHELD_IN_BAND: &str = "response text withheld for a credentialed plugin install because the registry progress record may echo the registry credential";

/// The fixed status a credentialed install puts on every successful record.
const PROGRESS_STATUS: &str = "plugin install progress (text withheld)";

/// A value that must never appear in a rendered error.
const SETTING_CANARY: &str = "setting-canary-1f7c-do-not-log-me";

/// A synthetic registry password, and the endpoint text that must not leak.
const PASSWORD_CANARY: &str = "password-canary-8b2d-do-not-log-me";
const ENDPOINT_CANARY: &str = "endpoint-canary.example:5000";

/// The longest one fixture instance may run in total.
///
/// A per-read timeout alone is not a bound: a peer that trickles one byte per
/// timeout can keep an operation alive forever. Every read loop checks this
/// absolute deadline (and the stop flag), so the whole fixture — all responses
/// it serves — is bounded, not each read.
const TOTAL_BOUND: Duration = Duration::from_secs(15);

/// The read-poll interval. A blocking read on a socket with this timeout returns
/// periodically so the deadline and stop flag are observed rather than waiting
/// for a full request.
const IO_POLL: Duration = Duration::from_millis(250);

/// How long one answer write or the closing drain may take.
const WRITE_BOUND: Duration = Duration::from_secs(2);

/// A request the fixture recorded.
struct Captured {
    line: String,
    head: String,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }
}

/// A bounded one-request-at-a-time HTTP server that records each request.
struct Fixture {
    endpoint: String,
    requests: Receiver<Captured>,
    server: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

/// Accepts unexpected requests so refusal tests can prove that none connected.
struct ConnectionProbe {
    endpoint: String,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    expired: Arc<AtomicBool>,
    deadline: Instant,
    server: Option<JoinHandle<()>>,
}

impl ConnectionProbe {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the connection probe");
        listener
            .set_nonblocking(true)
            .expect("make the probe nonblocking");
        let address = listener.local_addr().expect("the probe address");
        let connections = Arc::new(AtomicUsize::new(0));
        let thread_connections = Arc::clone(&connections);
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let expired = Arc::new(AtomicBool::new(false));
        let thread_expired = Arc::clone(&expired);
        let deadline = Instant::now() + TOTAL_BOUND;
        let server = thread::spawn(move || {
            let mut drain_until = None;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_connections.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                        if thread_stop.load(Ordering::SeqCst) {
                            drain_until = Some(Instant::now() + Duration::from_millis(100));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if thread_stop.load(Ordering::SeqCst) {
                            let quiet_deadline = *drain_until
                                .get_or_insert_with(|| Instant::now() + Duration::from_millis(100));
                            if Instant::now() >= quiet_deadline {
                                break;
                            }
                        } else if Instant::now() >= deadline {
                            thread_expired.store(true, Ordering::SeqCst);
                            break;
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("the connection probe accept failed: {error}"),
                }
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            connections,
            stop,
            expired,
            deadline,
            server: Some(server),
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the probe client")
    }

    fn finish(mut self, operation_completed: Instant) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("the probe thread");
        }
        assert!(
            operation_completed <= self.deadline,
            "the connection probe deadline expired before the operation finished"
        );
        assert!(
            !self.expired.load(Ordering::SeqCst),
            "the connection probe deadline expired before the operation finished"
        );
        self.connections.load(Ordering::SeqCst)
    }
}

/// Fixture that records one upload, withholds its response, and observes closure.
struct HeldResponseFixture {
    endpoint: String,
    request: Receiver<Captured>,
    closed: Receiver<bool>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl HeldResponseFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the held-response fixture");
        listener
            .set_nonblocking(true)
            .expect("make the held-response listener nonblocking");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = mpsc::channel();
        let (closed_tx, closed) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + TOTAL_BOUND;
            let mut stream = accept_bounded(&listener, &thread_stop, deadline);
            let request = read_request(&mut stream, &thread_stop, deadline);
            let _ = request_tx.send(request);
            let _ = closed_tx.send(wait_for_peer_close(&mut stream, &thread_stop, deadline));
        });
        Self {
            endpoint: format!("http://{address}"),
            request,
            closed,
            stop,
            server: Some(server),
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the held-response client")
    }

    async fn next_request_async(&self) -> Captured {
        let deadline = Instant::now() + TOTAL_BOUND;
        loop {
            match self.request.try_recv() {
                Ok(request) => return request,
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("the held-response fixture ended before recording an upload");
                }
                Err(mpsc::TryRecvError::Empty) => {
                    assert!(Instant::now() < deadline, "the fixture recorded no upload");
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }
    }

    fn peer_closed(&self) -> bool {
        self.closed
            .recv_timeout(TOTAL_BOUND)
            .expect("the fixture did not observe connection closure")
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("the held-response thread");
        }
    }
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let deadline = Instant::now() + TOTAL_BOUND;
        let server = thread::spawn(move || {
            for response in responses {
                let mut stream = accept_bounded(&listener, &thread_stop, deadline);
                let captured = read_request(&mut stream, &thread_stop, deadline);
                let _ = request_tx.send(captured);
                write_bounded(&mut stream, &response, &thread_stop, deadline)
                    .expect("write the fixture answer within its bound");
                release(&mut stream, &thread_stop, deadline);
            }
        });
        Self {
            endpoint: format!("http://{address}"),
            requests,
            server: Some(server),
            stop,
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
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("the fixture thread");
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

/// A bounded server that rejects one request and then watches for a retry.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<Captured>,
    retry: Receiver<()>,
    server: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl RejectingFixture {
    fn start(status: &str, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let response = rejected(status, body);
        let deadline = Instant::now() + TOTAL_BOUND;
        let server = thread::spawn(move || {
            let mut stream = accept_bounded(&listener, &thread_stop, deadline);
            let captured = read_request(&mut stream, &thread_stop, deadline);
            let _ = request_tx.send(captured);
            write_bounded(&mut stream, &response, &thread_stop, deadline)
                .expect("write the fixture answer within its bound");
            release(&mut stream, &thread_stop, deadline);

            let retry_window = Instant::now() + Duration::from_millis(300);
            while Instant::now() < retry_window
                && Instant::now() < deadline
                && !thread_stop.load(Ordering::SeqCst)
            {
                match listener.accept() {
                    Ok((retry_stream, _)) => {
                        let mut retry_stream = bound_stream(retry_stream);
                        let _ = read_request_or_empty(&mut retry_stream, &thread_stop, deadline);
                        if thread_stop.load(Ordering::SeqCst) {
                            return;
                        }
                        let _ = retry_tx.send(());
                        let retry_response = ok_json("{}");
                        write_bounded(&mut retry_stream, &retry_response, &thread_stop, deadline)
                            .expect("write the retry fixture answer within its bound");
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
            server: Some(server),
            stop,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request(&self) -> Captured {
        self.first_request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn saw_retry(&self) -> bool {
        matches!(self.retry.recv_timeout(Duration::from_millis(500)), Ok(()))
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("the fixture thread");
        }
    }
}

impl Drop for RejectingFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

/// A proxy that answers with a body built from the request it received.
///
/// The body echoes the **actual** `X-Registry-Auth` and `Proxy-Authorization`
/// values, not a reconstruction, so a failure to withhold is observable even if
/// the client encodes the credential differently from the test's guess. The
/// body that was sent and the request that produced it are both returned, so the
/// test can prove the canaries really were on the wire.
struct EchoingProxy {
    endpoint: String,
    captured: Receiver<(Captured, String)>,
    server: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl EchoingProxy {
    fn start(plaintext: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
        listener
            .set_nonblocking(true)
            .expect("make the proxy listener nonblocking");
        let address = listener.local_addr().expect("the proxy address");
        let (captured_tx, captured) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let prefix = plaintext.to_owned();
        let deadline = Instant::now() + TOTAL_BOUND;
        let server = thread::spawn(move || {
            let mut stream = accept_bounded(&listener, &thread_stop, deadline);
            let request = read_request(&mut stream, &thread_stop, deadline);
            let registry_auth = request.header("x-registry-auth");
            let proxy_authorization = request.header("proxy-authorization");
            let message = format!(
                "{prefix}; X-Registry-Auth={registry_auth:?}; Proxy-Authorization={proxy_authorization:?}"
            );
            let body = serde_json::json!({
                "message": message,
                "x_registry_auth": request.header("x-registry-auth"),
                "proxy_authorization": request.header("proxy-authorization"),
            })
            .to_string();
            let response = rejected("502 Bad Gateway", &body);
            let _ = captured_tx.send((request, body));
            write_bounded(&mut stream, &response, &thread_stop, deadline)
                .expect("write the proxy answer within its bound");
            release(&mut stream, &thread_stop, deadline);
        });
        Self {
            endpoint: format!("http://{address}"),
            captured,
            server: Some(server),
            stop,
        }
    }

    fn next(&self) -> (Captured, String) {
        self.captured
            .recv_timeout(Duration::from_secs(10))
            .expect("the proxy recorded no request")
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().expect("the proxy thread");
        }
    }
}

impl Drop for EchoingProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

/// Accepts one request with an operation deadline and a stop flag.
fn accept_bounded(listener: &TcpListener, stop: &AtomicBool, deadline: Instant) -> TcpStream {
    loop {
        assert!(
            !stop.load(Ordering::SeqCst),
            "the fixture was stopped before its request arrived"
        );
        assert!(
            Instant::now() < deadline,
            "the fixture exceeded its operation bound"
        );
        match listener.accept() {
            Ok((stream, _)) => return bound_stream(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("the fixture could not accept a request: {error}"),
        }
    }
}

/// Makes an accepted stream blocking with poll-sized read timeouts.
///
/// The per-read timeout is only the interval at which the caller re-checks the
/// operation deadline and the stop flag; it is not the operation bound.
fn bound_stream(stream: TcpStream) -> TcpStream {
    stream
        .set_nonblocking(false)
        .expect("make the accepted stream blocking");
    stream
        .set_read_timeout(Some(IO_POLL))
        .expect("set the fixture poll interval");
    stream
        .set_write_timeout(Some(IO_POLL))
        .expect("bound the fixture write");
    stream
}

/// Reads a request head and body, giving up on stop or the operation deadline.
fn read_request_or_empty(
    stream: &mut TcpStream,
    stop: &AtomicBool,
    deadline: Instant,
) -> Option<Captured> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return None;
        }
        set_read_poll(stream, deadline).ok()?;
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
    };
    let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or_default();
    let body_start = header_end + 4;
    if head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    }) {
        while !request[body_start..]
            .windows(5)
            .any(|window| window == b"0\r\n\r\n")
        {
            if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return None;
            }
            set_read_poll(stream, deadline).ok()?;
            match stream.read(&mut chunk) {
                Ok(0) => return None,
                Ok(read) => request.extend_from_slice(&chunk[..read]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return None,
            }
        }
        let encoded = &request[body_start..];
        let decoded = decode_chunked_body(encoded)?;
        return Some(Captured {
            line: head.lines().next().unwrap_or_default().to_owned(),
            head,
            body: decoded,
        });
    }
    while request.len() < body_start + content_length {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return None;
        }
        set_read_poll(stream, deadline).ok()?;
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(read) => request.extend_from_slice(&chunk[..read]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
    }
    Some(Captured {
        line: head.lines().next().unwrap_or_default().to_owned(),
        head,
        body: request[body_start..body_start + content_length].to_vec(),
    })
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool, deadline: Instant) -> Captured {
    read_request_or_empty(stream, stop, deadline).expect("the fixture read its request")
}

/// Decodes a complete HTTP chunked body, returning `None` for malformed framing.
fn decode_chunked_body(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    loop {
        let line_end = encoded[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")?
            + offset;
        let size = usize::from_str_radix(std::str::from_utf8(&encoded[offset..line_end]).ok()?, 16)
            .ok()?;
        offset = line_end + 2;
        if size == 0 {
            return Some(decoded);
        }
        if encoded.len() < offset + size + 2 {
            return None;
        }
        decoded.extend_from_slice(&encoded[offset..offset + size]);
        offset += size + 2;
    }
}

/// Waits for the peer to close the connection, bounded by the fixture deadline.
fn wait_for_peer_close(stream: &mut TcpStream, stop: &AtomicBool, deadline: Instant) -> bool {
    let mut buffer = [0_u8; 64];
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        if set_read_poll(stream, deadline).is_err() {
            return false;
        }
        match stream.read(&mut buffer) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return true,
        }
    }
    false
}

/// Writes an answer, failing the fixture thread rather than blocking forever.
fn write_bounded(
    stream: &mut TcpStream,
    response: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> std::io::Result<()> {
    let deadline = deadline.min(Instant::now() + WRITE_BOUND);
    let mut written = 0;
    while written < response.len() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fixture response write deadline/stop",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        stream.set_write_timeout(Some(IO_POLL.min(remaining)))?;
        match stream.write(&response[written..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
    stream.flush()
}

/// Waits for the client to release the connection, bounded by the operation
/// deadline and a short closing window.
fn release(stream: &mut TcpStream, stop: &AtomicBool, deadline: Instant) {
    let close_by = deadline.min(Instant::now() + WRITE_BOUND);
    let mut buffer = [0_u8; 64];
    while !stop.load(Ordering::SeqCst) && Instant::now() < close_by {
        if set_read_poll(stream, close_by).is_err() {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn set_read_poll(stream: &TcpStream, deadline: Instant) -> std::io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "fixture read deadline elapsed",
        ));
    }
    stream.set_read_timeout(Some(IO_POLL.min(remaining)))
}

fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn ok_stream(records: &[&str]) -> Vec<u8> {
    let mut body = String::new();
    for record in records {
        body.push_str(record);
        body.push('\n');
    }
    ok_json(&body)
}

/// A `204 No Content` answer.
fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// A `304 Not Modified` answer with no body.
fn not_modified() -> Vec<u8> {
    b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
}

/// A `101 Switching Protocols` answer with no upgrade.
fn switching_protocols() -> Vec<u8> {
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\n\r\n".to_vec()
}

fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

fn auth_header(value: &str) -> serde_json::Value {
    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(value)
        .expect("URL-safe base64");
    serde_json::from_slice(&decoded).expect("the Engine auth object")
}

fn credentials() -> RegistryCredentials {
    RegistryCredentials::new("user", PASSWORD_CANARY)
}

/// Every rendering of an error: `Display`, `Debug`, each source, and the
/// structured API pair if there is one.
fn renderings(error: &neotales_docker::Error) -> Vec<String> {
    let mut rendered = vec![error.to_string(), format!("{error:?}")];
    if let Some(api) = error.api_error() {
        rendered.push(api.message.clone());
        rendered.push(format!("{api:?}"));
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        rendered.push(cause.to_string());
        rendered.push(format!("{cause:?}"));
        source = cause.source();
    }
    rendered
}

/// Asserts that no rendering carries `canary`.
fn assert_concealed(error: &neotales_docker::Error, canaries: &[&str]) {
    for rendering in renderings(error) {
        for canary in canaries {
            assert!(
                !rendering.contains(canary),
                "the error echoed {canary:?}: {rendering}"
            );
        }
    }
}

/// The URL-safe `X-Registry-Auth` value for [`credentials`], as a canary.
fn auth_base64_canary() -> String {
    base64::engine::general_purpose::URL_SAFE.encode(format!(
        r#"{{"username":"user","password":"{PASSWORD_CANARY}"}}"#
    ))
}

/// Asserts that no rendering carries the actual `X-Registry-Auth` header value,
/// the password it encodes, the synthetic endpoint, or the setting canary.
fn assert_withheld_credential(error: &neotales_docker::Error, request: &Captured) {
    let header = request
        .header("x-registry-auth")
        .expect("the credential header");
    let auth = auth_header(header);
    assert_eq!(auth["password"], PASSWORD_CANARY);
    assert_concealed(
        error,
        &[SETTING_CANARY, PASSWORD_CANARY, ENDPOINT_CANARY, header],
    );
}

/// A proxy-labelled body carrying every canary a peer could reflect.
fn canary_body() -> String {
    format!(
        r#"{{"message":"{SETTING_CANARY} {PASSWORD_CANARY} {ENDPOINT_CANARY} {auth}"}}"#,
        auth = auth_base64_canary()
    )
}

#[tokio::test]
async fn set_plugin_config_sends_the_versioned_path_and_body() {
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .set_plugin_config(
            "vieux/sshfs:latest",
            vec!["DEBUG=1".to_owned(), "SSHFS_OPTS=-o x".to_owned()],
        )
        .await
        .expect("the settings write succeeded");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/vieux%2Fsshfs%3Alatest/set HTTP/1.1",
            version_prefix()
        ),
        "set_plugin_config fell back to the unversioned generated path"
    );
    assert_eq!(
        request.json(),
        serde_json::json!(["DEBUG=1", "SSHFS_OPTS=-o x"])
    );

    fixture.finish();
}

#[tokio::test]
async fn create_plugin_streams_bounded_tar_to_versioned_route() {
    let archive = b"opaque tar bytes \0\n".to_vec();
    let fixture = Fixture::start(vec![no_content()]);
    fixture
        .client()
        .create_plugin("example/plugin:latest", archive.clone())
        .await
        .expect("the plugin archive was accepted");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/create?name=example%2Fplugin%3Alatest HTTP/1.1",
            version_prefix()
        )
    );
    assert_eq!(request.header("content-type"), Some("application/x-tar"));
    assert_eq!(request.header("transfer-encoding"), Some("chunked"));
    assert_eq!(request.body, archive);
    fixture.finish();
}

#[tokio::test]
async fn create_plugin_withholds_rejection_text_and_rejects_304_and_101() {
    const ARCHIVE_CANARY: &str = "archive-canary-not-for-errors";
    for response in [
        rejected(
            "500 Internal Server Error",
            &format!(r#"{{"message":"{ARCHIVE_CANARY}"}}"#),
        ),
        not_modified(),
        switching_protocols(),
    ] {
        let status = response
            .split(|byte| *byte == b' ')
            .nth(1)
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.parse::<u16>().ok())
            .expect("fixture status");
        let fixture = Fixture::start(vec![response]);
        let error = fixture
            .client()
            .create_plugin("example/plugin", ARCHIVE_CANARY.as_bytes().to_vec())
            .await
            .expect_err("non-success response must fail");
        assert_eq!(
            error.api_error().expect("status is retained").status_code,
            status
        );
        assert_eq!(
            error.api_error().expect("fixed error").message,
            "response text withheld for a plugin archive upload"
        );
        assert!(
            !renderings(&error)
                .iter()
                .any(|value| value.contains(ARCHIVE_CANARY))
        );
        fixture.next();
        fixture.finish();
    }
}

#[tokio::test]
async fn create_plugin_refuses_an_oversized_archive_before_dispatch() {
    let fixture = ConnectionProbe::start();
    let result = fixture
        .client()
        .create_plugin(
            "example/plugin",
            vec![0; usize::try_from(raw::MAX_UPLOAD_BYTES).expect("limit fits usize") + 1],
        )
        .await;
    let operation_completed = Instant::now();
    let error = result.expect_err("oversized archive must be refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.api_error().is_none());
    assert_eq!(
        fixture.finish(operation_completed),
        0,
        "oversize refusal opened a connection"
    );
}

#[tokio::test]
async fn connection_probe_counts_a_known_dispatch() {
    let fixture = ConnectionProbe::start();
    let result = fixture.client().push_plugin("example/plugin").await;
    let operation_completed = Instant::now();
    let error = result.expect_err("the probe closes the dispatched request");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert_eq!(
        fixture.finish(operation_completed),
        1,
        "the probe missed a known connection"
    );
}

#[tokio::test]
async fn create_plugin_request_future_can_be_cancelled_after_dispatch() {
    let fixture = HeldResponseFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move {
        client
            .create_plugin("example/plugin", b"cancel me".to_vec())
            .await
    });
    let request = fixture.next_request_async().await;
    assert_eq!(request.body, b"cancel me");
    assert!(!task.is_finished(), "create completed before cancellation");
    task.abort();
    assert!(
        task.await.expect_err("aborted task").is_cancelled(),
        "the create task was not cancelled"
    );
    assert!(
        fixture.peer_closed(),
        "cancellation did not close the connection"
    );
    fixture.finish();
}

#[tokio::test]
async fn set_plugin_config_withholds_every_rendering_of_a_rejection() {
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &canary_body())]);
    let error = fixture
        .client()
        .set_plugin_config(
            "vieux/sshfs:latest",
            vec![format!("DEBUG={SETTING_CANARY}")],
        )
        .await
        .expect_err("the daemon rejected the settings write");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD_SET);
    assert!(!error.is_transport_deadline());
    let request = fixture.next();
    assert_eq!(request.header("x-registry-auth"), None);
    assert_concealed(
        &error,
        &[
            SETTING_CANARY,
            PASSWORD_CANARY,
            ENDPOINT_CANARY,
            &auth_base64_canary(),
        ],
    );

    fixture.finish();
}

#[tokio::test]
async fn set_plugin_config_surfaces_a_rejection_without_a_retry() {
    let fixture = RejectingFixture::start(
        "404 Not Found",
        r#"{"message":"plugin \"ghost\" not found"}"#,
    );
    let error = fixture
        .client()
        .set_plugin_config("ghost", vec!["DEBUG=1".to_owned()])
        .await
        .expect_err("the daemon rejected the settings write");

    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        404
    );
    assert_eq!(error.api_error().expect("the status").message, WITHHELD_SET);
    assert_eq!(
        fixture.request().line,
        format!("POST {}/plugins/ghost/set HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "the rejected settings write was sent again through the generated fallback"
    );

    fixture.finish();
}

#[tokio::test]
async fn raw_set_withholds_the_same_way_as_the_facade() {
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &canary_body())]);
    let engine = fixture.client().raw_engine().expect("the owned target");
    let error = raw::plugin_set(
        &engine,
        "vieux/sshfs:latest",
        &[format!("DEBUG={SETTING_CANARY}")],
    )
    .await
    .expect_err("the daemon rejected the settings write");

    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        500
    );
    assert_eq!(error.api_error().expect("the status").message, WITHHELD_SET);
    let request = fixture.next();
    assert_eq!(request.header("x-registry-auth"), None);
    assert_concealed(
        &error,
        &[
            SETTING_CANARY,
            PASSWORD_CANARY,
            ENDPOINT_CANARY,
            &auth_base64_canary(),
        ],
    );

    fixture.finish();
}

#[tokio::test]
async fn set_plugin_config_treats_304_and_101_as_failures() {
    for response in [not_modified(), switching_protocols()] {
        let status = response
            .split(|byte| *byte == b' ')
            .nth(1)
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.parse::<u16>().ok())
            .expect("the fixture status");
        let fixture = Fixture::start(vec![response]);
        let error = fixture
            .client()
            .set_plugin_config("vieux/sshfs:latest", vec!["DEBUG=1".to_owned()])
            .await
            .expect_err("a non-success status is a failure");

        let api = error.api_error().expect("the status is preserved");
        assert_eq!(api.status_code, status);
        assert_eq!(api.message, WITHHELD_SET);

        fixture.finish();
    }
}

#[tokio::test]
async fn push_plugin_sends_the_versioned_path_and_accepts_a_200() {
    let fixture = Fixture::start(vec![ok_stream(&[
        r#"{"status":"Pushing"}"#,
        r#"{"status":"Done"}"#,
    ])]);
    fixture
        .client()
        .push_plugin("vieux/sshfs:latest")
        .await
        .expect("the push was accepted");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/vieux%2Fsshfs%3Alatest/push HTTP/1.1",
            version_prefix()
        ),
        "push_plugin fell back to the unversioned generated path"
    );
    assert_eq!(request.header("x-registry-auth"), None);

    fixture.finish();
}

/// Anonymous push keeps the daemon's own message: it carries no secret.
#[tokio::test]
async fn anonymous_push_surfaces_the_daemon_message() {
    let fixture = RejectingFixture::start(
        "404 Not Found",
        r#"{"message":"plugin \"ghost\" not found"}"#,
    );
    let error = fixture
        .client()
        .push_plugin("ghost")
        .await
        .expect_err("the daemon rejected the push");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(
        error.api_error().expect("the status is preserved").message,
        r#"plugin "ghost" not found"#
    );
    assert!(
        !fixture.saw_retry(),
        "the rejected push was sent again through the generated fallback"
    );
    fixture.finish();
}

#[tokio::test]
async fn push_plugin_with_credentials_sends_a_url_safe_header() {
    let fixture = Fixture::start(vec![ok_json("")]);
    fixture
        .client()
        .push_plugin_with_credentials("registry.example/vieux/sshfs:latest", credentials())
        .await
        .expect("the credentialed push was accepted");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/registry.example%2Fvieux%2Fsshfs%3Alatest/push HTTP/1.1",
            version_prefix()
        )
    );
    let header = request
        .header("x-registry-auth")
        .expect("the credential header");
    let auth = auth_header(header);
    assert_eq!(auth["username"], "user");
    assert_eq!(auth["password"], PASSWORD_CANARY);
    assert_eq!(auth["serveraddress"], "registry.example");
    assert!(
        !header.contains('+') && !header.contains('/'),
        "the credential was not URL-safe base64: {header}"
    );

    fixture.finish();
}

#[tokio::test]
async fn a_withheld_credentialed_push_hides_credential_and_endpoint() {
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &canary_body())]);
    let error = fixture
        .client()
        .push_plugin_with_credentials("registry.example/vieux/sshfs:latest", credentials())
        .await
        .expect_err("the daemon rejected the push");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, WITHHELD_CREDENTIAL);
    let request = fixture.next();
    assert_withheld_credential(&error, &request);
    fixture.finish();
}

#[tokio::test]
async fn a_withheld_credentialed_upgrade_hides_credential_and_endpoint() {
    let fixture = Fixture::start(vec![rejected("404 Not Found", &canary_body())]);
    let error = fixture
        .client()
        .upgrade_plugin_with_credentials(
            "vieux/sshfs",
            PluginUpgradeOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .await
        .expect_err("the daemon rejected the upgrade");
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        404
    );
    assert_eq!(
        error.api_error().expect("the status").message,
        WITHHELD_CREDENTIAL
    );
    let request = fixture.next();
    assert_withheld_credential(&error, &request);
    fixture.finish();
}

#[tokio::test]
async fn a_withheld_credentialed_pull_hides_credential_and_endpoint() {
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &canary_body())]);
    let mut stream = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");
    let error = stream
        .next()
        .await
        .expect("a failure item")
        .expect_err("the daemon rejected the install before the stream");
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        500
    );
    assert_eq!(
        error.api_error().expect("the status").message,
        WITHHELD_CREDENTIAL
    );
    let request = fixture.next();
    assert_withheld_credential(&error, &request);
    fixture.finish();
}

#[tokio::test]
async fn raw_credentialed_push_withholds_the_same_way_as_the_facade() {
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &canary_body())]);
    let client = fixture.client();
    let engine = client.raw_engine().expect("the owned target");
    let credential = credentials();
    let auth =
        raw::RegistryAuth::credentials("registry.example", &credential).expect("the auth header");
    let error =
        raw::plugin_push_with_registry_auth(&engine, "registry.example/vieux/sshfs:latest", auth)
            .await
            .expect_err("the daemon rejected the push");
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        500
    );
    assert_eq!(
        error.api_error().expect("the status").message,
        WITHHELD_CREDENTIAL
    );
    let request = fixture.next();
    assert_withheld_credential(&error, &request);
    fixture.finish();
}

#[tokio::test]
async fn credentialed_pull_and_push_treat_304_and_101_as_failures() {
    for response in [not_modified(), switching_protocols()] {
        let status = response
            .split(|byte| *byte == b' ')
            .nth(1)
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.parse::<u16>().ok())
            .expect("the fixture status");
        for operation in ["pull", "push"] {
            let fixture = Fixture::start(vec![response.clone()]);
            let client = fixture.client();
            let error = if operation == "pull" {
                let mut stream = client
                    .install_plugin_with_credentials(
                        PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
                        credentials(),
                    )
                    .expect("the install stream opened");
                stream
                    .next()
                    .await
                    .expect("a failure item")
                    .expect_err("a non-success status fails the stream")
            } else {
                client
                    .push_plugin_with_credentials(
                        "registry.example/vieux/sshfs:latest",
                        credentials(),
                    )
                    .await
                    .expect_err("a non-success status is a failure")
            };
            let api = error.api_error().expect("the status is preserved");
            assert_eq!(api.status_code, status, "{operation}");
            assert_eq!(api.message, WITHHELD_CREDENTIAL, "{operation}");
            fixture.finish();
        }
    }
}

#[tokio::test]
async fn install_plugin_with_credentials_streams_progress_and_the_header() {
    let fixture = Fixture::start(vec![ok_stream(&[
        r#"{"status":"Installing"}"#,
        r#"{"status":"Done"}"#,
    ])]);
    let mut stream = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");

    let mut events = Vec::new();
    while let Some(item) = stream.next().await {
        events.push(item.expect("a progress event"));
    }
    assert_eq!(
        events,
        [
            ImageStreamEvent {
                status: Some(PROGRESS_STATUS.to_owned()),
                ..ImageStreamEvent::default()
            },
            ImageStreamEvent {
                status: Some(PROGRESS_STATUS.to_owned()),
                ..ImageStreamEvent::default()
            },
        ],
        "a credentialed install exposed peer progress text"
    );

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/pull?remote=registry.example%2Fvieux%2Fsshfs%3Alatest HTTP/1.1",
            version_prefix()
        )
    );
    assert!(request.header("x-registry-auth").is_some());
    assert_eq!(request.json(), serde_json::json!([]));

    fixture.finish();
}

/// A credentialed install's in-band record is fixed text with no source.
#[tokio::test]
async fn credentialed_install_withholds_an_in_band_failure() {
    let failure = format!(
        r#"{{"errorDetail":{{"message":"{SETTING_CANARY} {PASSWORD_CANARY} {ENDPOINT_CANARY}"}}}}"#,
    );
    let fixture = Fixture::start(vec![ok_stream(&[r#"{"status":"Installing"}"#, &failure])]);
    let mut stream = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");

    let first = stream.next().await.expect("a first item");
    assert_eq!(
        first.expect("the progress event").status.as_deref(),
        Some(PROGRESS_STATUS)
    );
    let error = stream
        .next()
        .await
        .expect("a failure item")
        .expect_err("an in-band errorDetail is a failure");
    assert_eq!(error.kind(), neotales_docker::ErrorKind::Docker);
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert!(error.api_error().is_none());
    assert!(
        renderings(&error)
            .iter()
            .any(|rendering| rendering.contains(WITHHELD_IN_BAND)),
        "the fixed in-band message is missing: {error:?}"
    );
    let auth_canary = auth_base64_canary();
    assert_concealed(
        &error,
        &[
            SETTING_CANARY,
            PASSWORD_CANARY,
            ENDPOINT_CANARY,
            &auth_canary,
        ],
    );

    fixture.finish();
}

/// Every record shape a peer can send becomes one fixed event or one fixed
/// error, item ordering and completion survive, and no peer string reaches the
/// event's Debug/serialization or the error's Display/Debug/source.
#[tokio::test]
async fn a_credentialed_install_exposes_no_peer_string_in_any_item() {
    const PEER: &str = "peer-event-canary-4c19-do-not-log-me";
    let records = [
        format!(
            r#"{{"status":"{PEER}","id":"{PEER}","stream":"{PEER}","error":null,"unknown":"{PEER}","nested":{{"deep":"{PEER}"}}}}"#
        ),
        r#"{"status":"Installing","id":"layer-1"}"#.to_owned(),
        format!(r#"{{"status":"safe","nested":{{"error":"{PEER}","unknown":"{PEER}"}}}}"#),
        format!(r#"{{"error":"{PEER}"}}"#),
        format!(r#"{{"errorDetail":"{PEER}"}}"#),
        format!(r#"{{"errorDetail":{{"message":17,"other":"{PEER}"}}}}"#),
        format!(r#"{{"errorDetail":{{"unknown":"{PEER}"}}}}"#),
        format!(r#"{{"errorDetail":null,"status":"{PEER}"}}"#),
    ];
    let refs: Vec<&str> = records.iter().map(String::as_str).collect();
    let fixture = Fixture::start(vec![ok_stream(&refs)]);
    let mut stream = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");

    // Presence of either top-level key is a failure signal, including null.
    // Nested data alone is suppressed, not interpreted. Two successes precede
    // the six fixed failures.
    for (index, expect_ok) in [false, true, true, false, false, false, false, false]
        .into_iter()
        .enumerate()
    {
        let item = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("the stream ended before item {index}"));
        match item {
            Ok(event) => {
                assert!(expect_ok, "record {index} was not treated as a failure");
                assert_eq!(
                    event,
                    ImageStreamEvent {
                        status: Some(PROGRESS_STATUS.to_owned()),
                        ..ImageStreamEvent::default()
                    },
                    "record {index} was not the fixed progress event"
                );
                for rendering in [
                    format!("{event:?}"),
                    serde_json::to_string(&event).expect("a serializable event"),
                ] {
                    assert!(
                        !rendering.contains(PEER),
                        "event {index} carried the peer canary: {rendering}"
                    );
                    assert!(
                        !rendering.contains("Installing") && !rendering.contains("layer-1"),
                        "event {index} carried peer progress text: {rendering}"
                    );
                }
            }
            Err(error) => {
                assert!(!expect_ok, "record {index} was not treated as progress");
                assert_eq!(error.kind(), ErrorKind::Docker);
                assert!(error.api_error().is_none());
                assert!(
                    renderings(&error)
                        .iter()
                        .any(|rendering| rendering.contains(WITHHELD_IN_BAND)),
                    "the fixed failure text is missing: {error:?}"
                );
                assert_concealed(&error, &[PEER]);
            }
        }
    }
    assert!(
        stream.next().await.is_none(),
        "the stream did not complete after the records"
    );

    fixture.finish();
}

/// The anonymous install is the control for the safe representation: peer
/// progress text still reaches the caller there.
#[tokio::test]
async fn anonymous_install_keeps_peer_progress_text() {
    const PEER: &str = "anonymous-progress-canary-7e3a";
    let record = format!(r#"{{"status":"{PEER}","id":"{PEER}"}}"#);
    let fixture = Fixture::start(vec![ok_stream(&[&record])]);
    let mut stream = fixture
        .client()
        .install_plugin(PluginInstallOptions::new("vieux/sshfs:latest"))
        .expect("the install stream opened");

    let event = stream
        .next()
        .await
        .expect("one item")
        .expect("a progress event");
    assert_eq!(event.status.as_deref(), Some(PEER));
    assert_eq!(event.id.as_deref(), Some(PEER));
    assert!(stream.next().await.is_none());

    fixture.finish();
}

/// Malformed framing after a good record is a fixed, content-free item error for
/// a credentialed install: a stream decoder failure can carry peer text.
#[tokio::test]
async fn credentialed_install_withholds_a_malformed_record() {
    let body = format!(
        "{}\n{{\"status\":\"{SETTING_CANARY}\"",
        r#"{"status":"Installing"}"#
    );
    let fixture = Fixture::start(vec![ok_json(&body)]);
    let mut stream = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");

    let first = stream.next().await.expect("a first item");
    assert_eq!(
        first.expect("the progress event").status.as_deref(),
        Some(PROGRESS_STATUS)
    );
    let error = stream
        .next()
        .await
        .expect("a failure item")
        .expect_err("malformed framing is a failure");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.api_error().is_none());
    assert!(
        renderings(&error)
            .iter()
            .any(|rendering| rendering.contains(WITHHELD_IN_BAND)),
        "the fixed in-band message is missing: {error:?}"
    );
    assert_concealed(&error, &[SETTING_CANARY, PASSWORD_CANARY, ENDPOINT_CANARY]);

    fixture.finish();
}

/// The anonymous install is the control: it keeps the daemon's record text.
#[tokio::test]
async fn anonymous_install_surfaces_the_daemon_in_band_message() {
    let fixture = Fixture::start(vec![ok_stream(&[
        r#"{"status":"Installing"}"#,
        r#"{"errorDetail":{"message":"registry denied the install"}}"#,
    ])]);
    let mut stream = fixture
        .client()
        .install_plugin(PluginInstallOptions::new("vieux/sshfs:latest"))
        .expect("the install stream opened");

    let first = stream.next().await.expect("a first item");
    assert_eq!(
        first.expect("the progress event").status.as_deref(),
        Some("Installing"),
        "the anonymous install lost its textual progress"
    );
    let error = stream
        .next()
        .await
        .expect("a failure item")
        .expect_err("an in-band errorDetail is a failure");
    assert!(
        renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("registry denied the install")),
        "the anonymous path lost the daemon's message: {error:?}"
    );

    fixture.finish();
}

#[tokio::test]
async fn upgrade_plugin_with_credentials_sends_the_header_and_drops_progress() {
    let fixture = Fixture::start(vec![ok_stream(&[r#"{"status":"Upgrading"}"#])]);
    fixture
        .client()
        .upgrade_plugin_with_credentials(
            "vieux/sshfs",
            PluginUpgradeOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .await
        .expect("the upgrade was accepted");

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!(
            "POST {}/plugins/vieux%2Fsshfs/upgrade?remote=registry.example%2Fvieux%2Fsshfs%3Alatest HTTP/1.1",
            version_prefix()
        )
    );
    assert!(request.header("x-registry-auth").is_some());
    assert_eq!(request.json(), serde_json::json!([]));

    fixture.finish();
}

#[tokio::test]
async fn a_credential_for_another_registry_is_refused_before_dispatch() {
    let fixture = Fixture::start(Vec::new());
    let error = fixture
        .client()
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials().with_server_address("other.example"),
        )
        .expect_err("the credential is addressed to another registry");
    assert_eq!(error.kind(), ErrorKind::Credentials);
    assert!(error.api_error().is_none());
    fixture.finish();
}

/// Invalid endpoint kinds are rejected instead of creating a client with no target.
#[test]
fn a_client_without_an_owned_target_fails_closed() {
    let error = DockerClient::connect_http("unix:///tmp/plugin-writes-unreachable.sock")
        .expect_err("a socket is not an HTTP target");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

/// A transport failure on a secret-bearing write loses the endpoint and the
/// peer's words, while the deadline marker survives.
#[tokio::test]
async fn a_secret_bearing_transport_failure_is_sanitized() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(client.raw_engine().is_ok());

    let error = client
        .push_plugin_with_credentials("registry.example/vieux/sshfs:latest", credentials())
        .await
        .expect_err("the connection was refused");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(error.api_error().is_none());
    assert!(
        !renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("127.0.0.1")),
        "the transport error carried the endpoint: {error:?}"
    );
    assert_concealed(&error, &[PASSWORD_CANARY, ENDPOINT_CANARY]);

    let error = client
        .set_plugin_config(
            "registry.example/vieux/sshfs:latest",
            vec!["A=1".to_owned()],
        )
        .await
        .expect_err("the connection was refused");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(
        !renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("127.0.0.1")),
        "the transport error carried the endpoint: {error:?}"
    );
}

/// A credentialed install's transport failure is a sanitized stream item, not a
/// peer-authored error and not a fallback request.
#[tokio::test]
async fn a_credentialed_install_transport_failure_is_sanitized() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    let mut stream = client
        .install_plugin_with_credentials(
            PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
            credentials(),
        )
        .expect("the install stream opened");
    let error = stream
        .next()
        .await
        .expect("a failure item")
        .expect_err("the connection was refused");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(error.api_error().is_none());
    assert!(
        !renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("127.0.0.1")),
        "the transport error carried the endpoint: {error:?}"
    );
    assert_concealed(&error, &[PASSWORD_CANARY, ENDPOINT_CANARY]);
}

/// A proxy that reflects the actual credential headers cannot put either of them
/// into the error.
#[tokio::test]
async fn an_authenticated_proxy_cannot_echo_the_credential() {
    const PROXY_USER: &str = "proxy-user-canary";
    const PROXY_PASSWORD: &str = "proxy-password-canary";
    let proxy = EchoingProxy::start(&canary_body());
    let proxy_url = proxy.endpoint.clone();
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http("http://127.0.0.1:1".to_owned()),
        ProxyPolicy::Http(
            ForwardProxy::with_basic_auth(proxy_url, PROXY_USER, PROXY_PASSWORD)
                .expect("the proxy credentials are bounded"),
        ),
    )
    .expect("build the proxied client");

    let error = client
        .push_plugin_with_credentials("registry.example/vieux/sshfs:latest", credentials())
        .await
        .expect_err("the proxy rejected the push");
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        502
    );
    assert_eq!(
        error.api_error().expect("the status").message,
        WITHHELD_CREDENTIAL
    );

    let (request, sent_body) = proxy.next();
    let registry_auth = request
        .header("x-registry-auth")
        .expect("the client sent the registry credential");
    let proxy_auth = request
        .header("proxy-authorization")
        .expect("the client sent the proxy credential");
    let echoed: serde_json::Value =
        serde_json::from_str(&sent_body).expect("the proxy answered with valid JSON");
    assert_eq!(
        echoed["x_registry_auth"], registry_auth,
        "the proxy did not reflect the actual X-Registry-Auth header"
    );
    assert_eq!(
        echoed["proxy_authorization"], proxy_auth,
        "the proxy did not reflect the actual Proxy-Authorization header"
    );
    let message = echoed["message"]
        .as_str()
        .expect("the proxy message is a string");
    assert!(
        message.contains(SETTING_CANARY)
            && message.contains(PASSWORD_CANARY)
            && message.contains(ENDPOINT_CANARY)
            && message.contains(registry_auth)
            && message.contains(proxy_auth),
        "the parsed message did not contain synthetic canaries and exact captured headers: {sent_body}"
    );
    assert_concealed(
        &error,
        &[
            SETTING_CANARY,
            PASSWORD_CANARY,
            ENDPOINT_CANARY,
            registry_auth,
            proxy_auth,
            PROXY_USER,
            PROXY_PASSWORD,
        ],
    );
    assert!(
        !renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("127.0.0.1")),
        "the proxy error carried its endpoint: {error:?}"
    );
    proxy.finish();
}

/// An unauthenticated proxy is not trusted either: its body is proxy text, and
/// it still receives the actual registry credential to reflect.
#[tokio::test]
async fn an_unauthenticated_proxy_cannot_echo_the_endpoint() {
    let proxy = EchoingProxy::start(&canary_body());
    let proxy_url = proxy.endpoint.clone();
    let client = DockerClient::connect_endpoint_with_policy(
        &Endpoint::Http("http://127.0.0.1:1".to_owned()),
        ProxyPolicy::Http(ForwardProxy::new(proxy_url).expect("the proxy URL")),
    )
    .expect("build the proxied client");

    let error = client
        .push_plugin_with_credentials("registry.example/vieux/sshfs:latest", credentials())
        .await
        .expect_err("the proxy rejected the push");
    assert_eq!(
        error
            .api_error()
            .expect("the status is preserved")
            .status_code,
        502
    );
    assert_eq!(
        error.api_error().expect("the status").message,
        WITHHELD_CREDENTIAL
    );

    let (request, sent_body) = proxy.next();
    assert_eq!(
        request.header("proxy-authorization"),
        None,
        "an unauthenticated proxy received a proxy credential"
    );
    let registry_auth = request
        .header("x-registry-auth")
        .expect("the client sent the registry credential");
    let echoed: serde_json::Value =
        serde_json::from_str(&sent_body).expect("the proxy answered with valid JSON");
    assert_eq!(
        echoed["x_registry_auth"], registry_auth,
        "the proxy did not reflect the actual X-Registry-Auth header"
    );
    assert_eq!(
        echoed["proxy_authorization"],
        serde_json::Value::Null,
        "an unauthenticated proxy reported a proxy credential"
    );
    let message = echoed["message"]
        .as_str()
        .expect("the proxy message is a string");
    assert!(
        message.contains(SETTING_CANARY)
            && message.contains(registry_auth)
            && message.contains("Proxy-Authorization=None"),
        "the parsed message did not contain exact captured registry auth / absent proxy auth: {sent_body}"
    );
    assert_concealed(
        &error,
        &[
            SETTING_CANARY,
            PASSWORD_CANARY,
            ENDPOINT_CANARY,
            registry_auth,
        ],
    );
    assert!(
        !renderings(&error)
            .iter()
            .any(|rendering| rendering.contains("127.0.0.1")),
        "the proxy error carried its endpoint: {error:?}"
    );
    proxy.finish();
}
