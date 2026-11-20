//! The owned exec-start session over a loopback fixture.
//!
//! These tests pin the client side of `POST /exec/{id}/start` when the caller
//! asks for a live session. They do not start a daemon: a loopback server
//! answers the exact request and then speaks raw bytes over the upgraded
//! connection. The `101` answer is therefore this client's contract, not a
//! live-daemon measurement.
//!
//! The non-TTY fixture is deliberately asymmetric. It reads the caller's stdin
//! as **raw** bytes and sends stdout and stderr back as separate multiplexed
//! frames, which is the framing Docker uses: stdin is not framed, and only the
//! output streams carry the eight-byte header.
//!
//! `exec_start`'s existing detached and attached-and-dropped behaviour is
//! pinned in the same file, so adding the session route did not change it.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use neotales_docker::raw::{
    ExecStartOptions, LogDecoder, LogStream, RawEngine, RawTarget, exec_start, exec_start_session,
};
use neotales_docker::{API_VERSION, ErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a fixture may wait for the client or the test.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);

/// The stdin bytes the non-TTY fixture expects to read without a frame header.
const RAW_STDIN: &[u8] = b"raw stdin bytes, no frame header";

/// The payload the fixture sends as a stdout frame.
const STDOUT_PAYLOAD: &[u8] = b"stdout payload";

/// The payload the fixture sends as a stderr frame.
const STDERR_PAYLOAD: &[u8] = b"stderr payload";

/// What the fixture does after it answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    /// The client closed the connection.
    Closed,
    /// The fixture gave up waiting, so the client did not close it.
    TimedOut,
}

/// How the fixture answers the start request.
#[derive(Clone, Copy)]
enum Mode {
    /// `101`, then echo raw bytes. Used for a TTY session.
    Echo,
    /// `101`, read raw stdin, then send framed stdout and stderr. Used for a
    /// non-TTY session.
    Framed,
    /// A plain response, with no protocol switch.
    Plain(&'static [u8]),
    /// Read the request, report it, and wait for the test to release the peer.
    Hold,
}

/// One recorded request head and body.
struct RecordedRequest {
    line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl RecordedRequest {
    /// Reads one header by its case-insensitive name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// A loopback HTTP fixture that answers one request.
struct Fixture {
    host: String,
    port: u16,
    request: Receiver<RecordedRequest>,
    stdin: Option<Receiver<Vec<u8>>>,
    lifecycle: Option<Receiver<Lifecycle>>,
    release: Option<Sender<()>>,
    server: JoinHandle<()>,
}

impl Fixture {
    /// Starts a fixture that answers `101` and echoes raw bytes.
    fn start_echoing() -> Self {
        Self::start(Mode::Echo)
    }

    /// Starts a fixture that answers `101`, reads raw stdin, and sends separate
    /// stdout and stderr frames.
    fn start_framed() -> Self {
        Self::start(Mode::Framed)
    }

    /// Starts a fixture that answers one ordinary response and then ends.
    ///
    /// The plain responses exercise the client's status handling, not socket
    /// closure. Closure is a property of the upgraded session and is asserted
    /// there, where the client owns both halves.
    fn start_plain(response: &'static [u8]) -> Self {
        Self::start(Mode::Plain(response))
    }

    /// Starts a fixture that records the request and then waits for
    /// [`Fixture::release`].
    fn start_holding() -> Self {
        Self::start(Mode::Hold)
    }

    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = mpsc::channel();
        let (stdin_tx, stdin) = mpsc::channel();
        let (lifecycle_tx, lifecycle) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let observes_stdin = matches!(mode, Mode::Framed);
        let observes_lifecycle = matches!(mode, Mode::Echo | Mode::Framed);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let recorded = read_request(&mut stream);
            request_tx.send(recorded).expect("record the request");
            let response: &'static [u8] = match mode {
                Mode::Echo | Mode::Framed => {
                    b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"
                }
                Mode::Plain(response) => response,
                Mode::Hold => b"",
            };
            if !response.is_empty() {
                stream
                    .write_all(response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
            }
            match mode {
                Mode::Echo => {
                    stream
                        .set_read_timeout(Some(FIXTURE_TIMEOUT))
                        .expect("set the fixture read timeout");
                    let _sent = lifecycle_tx.send(echo_until_close(&mut stream));
                }
                Mode::Framed => {
                    stream
                        .set_read_timeout(Some(FIXTURE_TIMEOUT))
                        .expect("set the fixture read timeout");
                    let observed = framed_exchange(&mut stream, &stdin_tx);
                    let _sent = lifecycle_tx.send(observed);
                }
                Mode::Plain(_) => {}
                Mode::Hold => {
                    let _released = release.recv_timeout(FIXTURE_TIMEOUT);
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        });
        Self {
            host: address.ip().to_string(),
            port: address.port(),
            request,
            stdin: observes_stdin.then_some(stdin),
            lifecycle: observes_lifecycle.then_some(lifecycle),
            release: matches!(mode, Mode::Hold).then_some(release_tx),
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

    fn request(&self) -> RecordedRequest {
        self.request
            .recv_timeout(FIXTURE_TIMEOUT)
            .expect("the fixture recorded no request")
    }

    fn stdin(&self) -> Vec<u8> {
        self.stdin
            .as_ref()
            .expect("only the framed fixture records stdin")
            .recv_timeout(FIXTURE_TIMEOUT)
            .expect("the fixture recorded no stdin")
    }

    fn saw_close(&self) -> bool {
        matches!(
            self.lifecycle
                .as_ref()
                .expect("only the upgraded fixture observes closure")
                .recv_timeout(FIXTURE_TIMEOUT),
            Ok(Lifecycle::Closed)
        )
    }

    fn release(&self) {
        self.release
            .as_ref()
            .expect("only the holding fixture has a release")
            .send(())
            .expect("release the holding fixture");
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// Reads one request head and its `Content-Length` body.
fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read the request head");
        assert!(read > 0, "the client closed before the request head");
        buffer.extend_from_slice(&chunk[..read]);
        let Some(head_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
            assert!(buffer.len() <= 64 * 1024, "the request head is too large");
            continue;
        };

        let head = std::str::from_utf8(&buffer[..head_end]).expect("an ASCII request head");
        let mut lines = head.split("\r\n");
        let line = lines.next().expect("a request line").to_owned();
        let mut headers = BTreeMap::new();
        for header in lines {
            if let Some((name, value)) = header.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }
        let length: usize = headers
            .get("content-length")
            .map_or(0, |value| value.parse().expect("a Content-Length number"));
        let mut body = buffer[head_end + 4..].to_vec();
        while body.len() < length {
            let read = stream.read(&mut chunk).expect("read the request body");
            assert!(read > 0, "the client closed before the request body");
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
        return RecordedRequest {
            line,
            headers,
            body,
        };
    }
}

/// Echoes every byte until the client closes, so one write proves both
/// directions carry bytes.
fn echo_until_close(stream: &mut TcpStream) -> Lifecycle {
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Lifecycle::Closed,
            Ok(read) => {
                if stream.write_all(&chunk[..read]).is_err() {
                    return Lifecycle::Closed;
                }
                if stream.flush().is_err() {
                    return Lifecycle::Closed;
                }
            }
            Err(error) if is_timeout(&error) => return Lifecycle::TimedOut,
            Err(_) => return Lifecycle::Closed,
        }
    }
}

/// Reads exactly the expected raw stdin, reports it, then sends separate stdout
/// and stderr frames and waits for the client to close.
fn framed_exchange(stream: &mut TcpStream, stdin: &Sender<Vec<u8>>) -> Lifecycle {
    let mut received = vec![0_u8; RAW_STDIN.len()];
    if let Err(error) = stream.read_exact(&mut received) {
        return if is_timeout(&error) {
            Lifecycle::TimedOut
        } else {
            Lifecycle::Closed
        };
    }
    let _sent = stdin.send(received);
    let frames = [frame(1, STDOUT_PAYLOAD), frame(2, STDERR_PAYLOAD)].concat();
    if stream.write_all(&frames).is_err() {
        return Lifecycle::Closed;
    }
    if stream.flush().is_err() {
        return Lifecycle::Closed;
    }
    wait_until_close(stream)
}

/// Waits for the client to close without writing another byte.
fn wait_until_close(stream: &mut TcpStream) -> Lifecycle {
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Lifecycle::Closed,
            Ok(_) => {}
            Err(error) if is_timeout(&error) => return Lifecycle::TimedOut,
            Err(_) => return Lifecycle::Closed,
        }
    }
}

/// Builds one Docker multiplexed frame: stream byte, three zero bytes, a
/// big-endian payload length, then the payload.
fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(8 + payload.len());
    framed.extend_from_slice(&[stream, 0, 0, 0]);
    framed.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("a test payload fits in u32")
            .to_be_bytes(),
    );
    framed.extend_from_slice(payload);
    framed
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn expected_start_line(exec: &str) -> String {
    format!(
        "POST /v{}.{}/exec/{exec}/start HTTP/1.1",
        API_VERSION.major, API_VERSION.minor
    )
}

#[tokio::test]
async fn an_upgraded_session_sends_raw_stdin_and_framed_stdout_and_stderr() {
    let fixture = Fixture::start_framed();
    let engine = fixture.engine();
    let session = exec_start_session(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: false,
            tty: false,
        },
    )
    .await
    .expect("a 101 session");

    assert_eq!(session.status().as_u16(), 101);
    assert!(!session.tty());

    let recorded = fixture.request();
    assert_eq!(recorded.line, expected_start_line("e1"));
    let host = format!("{}:{}", fixture.host, fixture.port);
    assert_eq!(recorded.header("host"), Some(host.as_str()));
    assert_eq!(recorded.header("content-type"), Some("application/json"));
    assert_eq!(recorded.header("connection"), Some("Upgrade"));
    assert_eq!(recorded.header("upgrade"), Some("tcp"));
    assert_eq!(recorded.header("transfer-encoding"), None);
    let length = recorded.body.len().to_string();
    assert_eq!(recorded.header("content-length"), Some(length.as_str()));
    assert_eq!(recorded.body, br#"{"Detach":false,"Tty":false}"#);

    let (mut read, mut write) = session.into_connection();
    write.write_all(RAW_STDIN).await.expect("write raw stdin");
    write.flush().await.expect("flush raw stdin");

    // The peer read exactly the bytes written. A stdin frame header would have
    // appeared here as extra bytes, so this is the raw-stdin assertion.
    assert_eq!(fixture.stdin(), RAW_STDIN);

    let expected = [frame(1, STDOUT_PAYLOAD), frame(2, STDERR_PAYLOAD)].concat();
    let mut wire = vec![0_u8; expected.len()];
    read.read_exact(&mut wire)
        .await
        .expect("read framed output");
    assert_eq!(wire, expected);

    let mut decoder = LogDecoder::new(false);
    let frames = decoder.push(&wire).expect("decode stdout and stderr");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].stream, LogStream::Stdout);
    assert_eq!(frames[0].payload.as_slice(), STDOUT_PAYLOAD);
    assert_eq!(frames[1].stream, LogStream::Stderr);
    assert_eq!(frames[1].payload.as_slice(), STDERR_PAYLOAD);

    drop(read);
    drop(write);
    assert!(fixture.saw_close(), "the fixture did not observe the close");
    fixture.finish();
}

#[tokio::test]
async fn a_tty_session_sends_tty_true_and_is_raw_in_both_directions() {
    let fixture = Fixture::start_echoing();
    let engine = fixture.engine();
    let session = exec_start_session(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: false,
            tty: true,
        },
    )
    .await
    .expect("a 101 session");
    assert!(session.tty());

    let recorded = fixture.request();
    assert_eq!(recorded.body, br#"{"Detach":false,"Tty":true}"#);

    let (mut read, mut write) = session.into_connection();
    // A TTY body has no frame header, so arbitrary bytes are the payload.
    let payload = [0_u8, 1, 2, 0xff];
    write.write_all(&payload).await.expect("write a TTY byte");
    write.flush().await.expect("flush the TTY byte");
    let mut echoed = [0_u8; 4];
    read.read_exact(&mut echoed).await.expect("read a TTY byte");
    assert_eq!(echoed, payload);

    drop(read);
    drop(write);
    assert!(fixture.saw_close(), "the fixture did not observe the close");
    fixture.finish();
}

#[tokio::test]
async fn dropping_the_session_closes_the_connection() {
    let fixture = Fixture::start_framed();
    let engine = fixture.engine();
    let session = exec_start_session(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: false,
            tty: false,
        },
    )
    .await
    .expect("a 101 session");

    // No read and no write: dropping the owned connection is the cancellation.
    drop(session);
    assert!(fixture.saw_close(), "the fixture did not observe the close");
    fixture.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_start_future_after_dispatch_does_not_retract_the_request() {
    let fixture = Fixture::start_holding();
    let engine = fixture.engine();
    let task = tokio::spawn(async move {
        exec_start_session(
            &engine,
            "e1",
            &ExecStartOptions {
                detach: false,
                tty: false,
            },
        )
        .await
    });

    // The fixture reports the request only after reading it from the socket.
    // Reaching this point is the dispatch; aborting afterwards cannot unsend it.
    let recorded = fixture.request();
    assert_eq!(recorded.line, expected_start_line("e1"));
    task.abort();
    let _cancelled = task.await;

    fixture.release();
    fixture.finish();
}

#[tokio::test]
async fn a_detached_exec_start_keeps_its_200_behaviour() {
    let fixture = Fixture::start_plain(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
    );
    let engine = fixture.engine();
    let started = exec_start(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: true,
            tty: false,
        },
    )
    .await
    .expect("a 200 start");

    assert_eq!(started.status.as_u16(), 200);
    assert!(started.detached);
    assert!(!started.is_attached());

    let recorded = fixture.request();
    assert_eq!(recorded.line, expected_start_line("e1"));
    assert_eq!(recorded.header("connection"), None);
    assert_eq!(recorded.header("upgrade"), None);
    assert_eq!(recorded.body, br#"{"Detach":true,"Tty":false}"#);

    fixture.finish();
}

#[tokio::test]
async fn an_attached_exec_start_still_reports_and_drops_the_response() {
    let fixture = Fixture::start_plain(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\nContent-Length: 0\r\n\r\n",
    );
    let engine = fixture.engine();
    let started = exec_start(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: false,
            tty: false,
        },
    )
    .await
    .expect("a 200 start");

    assert_eq!(started.status.as_u16(), 200);
    assert!(!started.detached);
    assert!(started.is_attached());

    let recorded = fixture.request();
    assert_eq!(recorded.line, expected_start_line("e1"));
    assert_eq!(recorded.header("connection"), None);
    assert_eq!(recorded.header("upgrade"), None);
    assert_eq!(recorded.body, br#"{"Detach":false,"Tty":false}"#);

    fixture.finish();
}

#[tokio::test]
async fn a_200_answer_is_refused_after_the_start_is_dispatched() {
    let fixture = Fixture::start_plain(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    );
    let engine = fixture.engine();
    let error = exec_start_session(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: false,
            tty: false,
        },
    )
    .await
    .expect_err("a 200 is not a bidirectional session");

    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(error.to_string().contains("200"), "{error}");
    assert!(!error.to_string().contains("{}"), "{error}");

    // The request was on the wire before the refusal: the 200 does not mean
    // the start was not dispatched. The fixture cannot report the daemon's
    // process state, so the outcome remains unknown here by design.
    let recorded = fixture.request();
    assert_eq!(recorded.line, expected_start_line("e1"));
    assert_eq!(recorded.header("connection"), Some("Upgrade"));
    assert_eq!(recorded.header("upgrade"), Some("tcp"));

    fixture.finish();
}

#[tokio::test]
async fn a_detached_session_is_refused_before_connecting() {
    // Port 1 is used as a target that must not be dialled. If the guard ran
    // after the connection, the failure would be Transport rather than
    // InvalidInput.
    let engine = RawEngine::new(
        RawTarget::Tcp {
            host: "127.0.0.1".to_owned(),
            port: 1,
        },
        API_VERSION,
    );
    let error = exec_start_session(
        &engine,
        "e1",
        &ExecStartOptions {
            detach: true,
            tty: false,
        },
    )
    .await
    .expect_err("a detached start has no session");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
