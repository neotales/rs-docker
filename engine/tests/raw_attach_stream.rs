//! `raw::attach_stream`: the `200` read-only body and the unchanged `101`
//! upgrade.
//!
//! These tests use a real loopback socket rather than an in-memory duplex. An
//! attach is the one operation where the lifetime of the connection *is* the
//! answer: the daemon declares no length, keeps writing until the client leaves,
//! and observes the disconnect only when the socket closes. A pair of buffers
//! cannot show that the client closed a socket, so the drop test here needs the
//! kernel's own EOF.
//!
//! What each test pins:
//!
//! - the `200` body bytes arrive, rather than being dropped and reported as a
//!   successful start;
//! - a non-TTY `200` body's multiplexed frames arrive byte for byte, undecoded;
//! - dropping that body closes the connection, which is the cancellation
//!   mechanism;
//! - a `101` answer still returns both halves, and the write half really reaches
//!   the peer;
//! - a `200` answer has no write half to hand out.
//!
//! No daemon is needed. The fixture is a local TCP listener that answers one
//! request in the shape the Engine was measured to use.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use neotales_docker::raw::{
    Attached, ContainerAttachOptions, FrameStream, LogDecoder, LogStream, RawEngine, RawTarget,
    SwitchedReadHalf, SwitchedWriteHalf, attach, attach_stream,
};
use neotales_docker::{API_VERSION, ErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long one step may take end to end.
///
/// The fixture is local and every step is one write or one read, so this is a
/// hang guard rather than a performance budget.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the client writes on the upgraded connection.
const CLIENT_INPUT: &[u8] = b"from-client";

/// What the fixture writes back once it has read the client's input.
const SERVER_ACK: &[u8] = b"ack";

/// The fixture's initial output on the upgraded connection.
const SERVER_OUTPUT: &[u8] = b"server-output";

/// A non-TTY body in the Engine's multiplexed framing.
///
/// Two frames: stdout with six payload bytes, then stderr with six. The header
/// is `[stream, 0, 0, 0, big-endian u32 length]`; the payload follows. This is
/// the shape `attach_stream` must preserve, not decode, so the fixture hands it
/// over exactly as a daemon would.
const NON_TTY_FRAMED: &[u8] = &[
    1, 0, 0, 0, 0, 0, 0, 6, b's', b't', b'd', b'o', b'u', b't', 2, 0, 0, 0, 0, 0, 0, 6, b's', b't',
    b'd', b'e', b'r', b'r',
];

/// A header whose reserved bytes are not zero, so the framing is invalid.
const MALFORMED_FRAME: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 0];

/// What the fixture does after it has read the request.
enum Mode {
    /// Answer `200` with a close-delimited raw stream and then close.
    Body(&'static [u8]),
    /// Answer `200`, write the first bytes, and keep the connection open until
    /// the client closes it.
    HoldOpen(&'static [u8]),
    /// Answer `101`, write the initial output, read the client's input, and
    /// answer it.
    Upgraded,
}

/// A one-connection loopback Engine fixture.
struct Fixture {
    address: SocketAddr,
    request: Arc<Mutex<Vec<u8>>>,
    closed: Receiver<()>,
}

impl Fixture {
    /// Starts the fixture and returns once it is listening.
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let address = listener.local_addr().expect("read the bound address");
        let request = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&request);
        let (closed_tx, closed_rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the client connection");
            let head = read_head(&mut stream);
            recorded
                .lock()
                .expect("the recorded request")
                .extend_from_slice(&head);
            match mode {
                Mode::Body(body) => {
                    write_head(&mut stream, "200 OK", "");
                    stream.write_all(body).expect("write the response body");
                    stream.flush().expect("flush the response body");
                    // Dropping the stream is the end of the close-delimited
                    // body, which is how the daemon ends a finished attach.
                }
                Mode::HoldOpen(body) => {
                    write_head(&mut stream, "200 OK", "");
                    stream.write_all(body).expect("write the first body bytes");
                    stream.flush().expect("flush the first body bytes");
                    // The only thing this fixture does now is wait for the
                    // client to close the socket. `read` returning zero is the
                    // kernel's EOF, not this fixture's opinion.
                    let mut sink = [0_u8; 256];
                    loop {
                        match stream.read(&mut sink) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                    let _sent = closed_tx.send(());
                }
                Mode::Upgraded => {
                    stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\n\
                              Connection: Upgrade\r\n\
                              Upgrade: tcp\r\n\
                              \r\n",
                        )
                        .expect("write the switching-protocols head");
                    stream
                        .write_all(SERVER_OUTPUT)
                        .expect("write the upgraded output");
                    stream.flush().expect("flush the upgraded output");
                    let mut input = vec![0_u8; CLIENT_INPUT.len()];
                    stream
                        .read_exact(&mut input)
                        .expect("read the client's input");
                    assert_eq!(input, CLIENT_INPUT, "the write half sent other bytes");
                    stream
                        .write_all(SERVER_ACK)
                        .expect("write the acknowledgement");
                    stream.flush().expect("flush the acknowledgement");
                }
            }
        });
        Self {
            address,
            request,
            closed: closed_rx,
        }
    }

    /// An Engine that dials this fixture over plain TCP.
    fn engine(&self) -> RawEngine {
        RawEngine::new(
            RawTarget::Tcp {
                host: "127.0.0.1".to_owned(),
                port: self.address.port(),
            },
            API_VERSION,
        )
    }

    /// The request head the fixture read, as text.
    fn request(&self) -> String {
        String::from_utf8_lossy(&self.request.lock().expect("the recorded request")).into_owned()
    }

    /// Waits for the fixture to observe the client closing the connection.
    ///
    /// This is async rather than a blocking `recv_timeout` on purpose: the
    /// connection driver is a task on the test's runtime, and a blocking wait
    /// would keep that task from ever running the abort that closes the socket.
    async fn wait_for_close(&self) -> bool {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            if self.closed.try_recv().is_ok() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Reads one HTTP request head, stopping at the blank line.
fn read_head(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("read the request head");
        assert!(read != 0, "the client closed before sending a request");
        head.extend_from_slice(&chunk[..read]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            return head;
        }
    }
}

/// Writes a response head with the raw-stream content type.
fn write_head(stream: &mut std::net::TcpStream, status: &str, extra: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/vnd.docker.raw-stream\r\n\
         {extra}\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .expect("write the response head");
    stream.flush().expect("flush the response head");
}

/// Reads a body to end of stream.
async fn collect(body: &mut FrameStream) -> Vec<u8> {
    let mut collected = Vec::new();
    loop {
        let next = tokio::time::timeout(REQUEST_TIMEOUT, body.next_data())
            .await
            .expect("a body read did not finish")
            .expect("the body read failed");
        match next {
            Some(chunk) => collected.extend_from_slice(&chunk),
            None => return collected,
        }
    }
}

/// Attaches with both output streams and asks the daemon to keep the stream
/// open.
fn options() -> ContainerAttachOptions {
    ContainerAttachOptions {
        stream: true,
        stdout: true,
        stderr: true,
        ..Default::default()
    }
}

/// Reads the fixture's output, writes the caller's input, and reads the ack.
///
/// Both the existing `attach` path and the new `attach_stream` path return the
/// same two halves for a `101`, so this is the one check that either of them
/// handed back a working connection rather than a write half that goes nowhere.
async fn exercise_upgraded(mut read: SwitchedReadHalf, mut write: SwitchedWriteHalf) {
    let mut output = vec![0_u8; SERVER_OUTPUT.len()];
    tokio::time::timeout(REQUEST_TIMEOUT, read.read_exact(&mut output))
        .await
        .expect("the upgraded read did not finish")
        .expect("the upgraded read failed");
    assert_eq!(output, SERVER_OUTPUT);

    tokio::time::timeout(REQUEST_TIMEOUT, write.write_all(CLIENT_INPUT))
        .await
        .expect("the upgraded write did not finish")
        .expect("the upgraded write failed");
    tokio::time::timeout(REQUEST_TIMEOUT, write.flush())
        .await
        .expect("the upgraded flush did not finish")
        .expect("the upgraded flush failed");

    let mut ack = vec![0_u8; SERVER_ACK.len()];
    tokio::time::timeout(REQUEST_TIMEOUT, read.read_exact(&mut ack))
        .await
        .expect("the acknowledgement did not finish")
        .expect("the acknowledgement failed");
    assert_eq!(ack, SERVER_ACK);
}

#[tokio::test]
async fn a_200_attach_returns_the_stream_bytes_instead_of_dropping_them() {
    let fixture = Fixture::start(Mode::Body(b"hello\x00world"));
    let engine = fixture.engine();

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options()))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");

    assert!(
        attached.is_read_only(),
        "a 200 answer was reported as a switched connection"
    );
    assert_eq!(attached.status(), hyper::StatusCode::OK);
    let mut body = attached.into_stream().expect("a 200 answer has a body");
    assert_eq!(collect(&mut body).await, b"hello\x00world");

    let request = fixture.request();
    assert!(
        request.starts_with("POST /v1."),
        "the request was not versioned:\n{request}"
    );
    assert!(
        request.contains("/containers/web/attach?"),
        "the request was not the attach endpoint:\n{request}"
    );
    assert!(
        request.contains("stream=true"),
        "the stream flag was not sent:\n{request}"
    );
    // A 200 is the daemon declining an upgrade, not a request that never asked
    // for one. This is what keeps the 101 path meaningful rather than a header
    // that happens to be sent.
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("connection: upgrade"),
        "the request did not ask to upgrade:\n{request}"
    );
    assert!(
        lower.contains("upgrade: tcp"),
        "the request did not name the upgrade protocol:\n{request}"
    );
}

#[tokio::test]
async fn a_200_attach_preserves_non_tty_framed_bytes() {
    // A non-TTY container writes the same eight-byte multiplexed framing as
    // `logs`. `attach_stream` returns the body unchanged, so the headers and
    // payloads must arrive byte for byte. This test deliberately does not
    // decode them on the attach path: the operation makes no claim that it
    // applies a decoder.
    let fixture = Fixture::start(Mode::Body(NON_TTY_FRAMED));
    let engine = fixture.engine();

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options()))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");
    let mut body = attached.into_stream().expect("a 200 answer has a body");
    let bytes = collect(&mut body).await;
    assert_eq!(bytes, NON_TTY_FRAMED);

    // The documented caller-side flow: feed each chunk to the public decoder,
    // then finish at end of stream. This proves the flow is usable rather than
    // a pointer to an internal path.
    let mut decoder = LogDecoder::new(false);
    let frames = decoder
        .push(&bytes)
        .expect("the preserved bytes are valid multiplexed framing");
    decoder
        .finish()
        .expect("the body ended on a frame boundary");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].stream, LogStream::Stdout);
    assert_eq!(frames[0].payload, b"stdout");
    assert_eq!(frames[1].stream, LogStream::Stderr);
    assert_eq!(frames[1].payload, b"stderr");
}

#[tokio::test]
async fn a_malformed_frame_is_refused_before_the_next_read() {
    // The fixture sends one malformed header and then stays silent. `push`
    // latches the refusal for the next decoder call, so the documented flow
    // must call `decode` before awaiting more bytes or this test would hang.
    let fixture = Fixture::start(Mode::HoldOpen(MALFORMED_FRAME));
    let engine = fixture.engine();

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options()))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");
    let mut body = attached.into_stream().expect("a 200 answer has a body");
    let mut decoder = LogDecoder::new(false);
    let mut received = Vec::new();
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    // A TCP read is not a frame: the eight-byte header may arrive in one chunk
    // or in several. Feed each chunk to the decoder and stop as soon as the
    // complete header has been seen. `push` latches the refusal on the chunk
    // that completes it; the assertion below then calls `decode` without
    // another network read.
    while received.len() < MALFORMED_FRAME.len() {
        let chunk = tokio::time::timeout_at(deadline, body.next_data())
            .await
            .expect("the malformed header did not arrive in time")
            .expect("the read failed")
            .expect("the fixture closed before the header completed");
        received.extend_from_slice(&chunk);
        frames.extend(
            decoder
                .push(&chunk)
                .expect("push returns frames before a refusal and defers the refusal"),
        );
    }
    assert_eq!(received, MALFORMED_FRAME);
    assert!(frames.is_empty(), "expected frames to be empty");

    // The complete header is malformed, so the decoder has latched the refusal.
    // The connection is still open and silent; this must surface the refusal
    // now; awaiting `next_data` again instead would block until the daemon
    // closed a connection it has no reason to close.
    let error = tokio::time::timeout(Duration::from_secs(1), async { decoder.decode() })
        .await
        .expect("decode waited for more network data")
        .expect_err("a malformed frame must be refused");
    assert_eq!(error.kind(), ErrorKind::Transport);

    drop(body);
    assert!(
        fixture.wait_for_close().await,
        "the fixture never observed the client closing the connection"
    );
}

#[tokio::test]
async fn a_101_attach_still_returns_both_halves_and_the_write_half_reaches_the_peer() {
    let fixture = Fixture::start(Mode::Upgraded);
    let engine = fixture.engine();
    let options = ContainerAttachOptions {
        stdin: true,
        ..options()
    };

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");

    assert!(
        !attached.is_read_only(),
        "a 101 answer was reported as a read-only body"
    );
    assert_eq!(attached.status(), hyper::StatusCode::SWITCHING_PROTOCOLS);
    let (read, write) = attached
        .into_connection()
        .expect("a 101 answer has both halves");
    exercise_upgraded(read, write).await;
}

#[tokio::test]
async fn attach_still_returns_the_upgraded_connection_on_101() {
    let fixture = Fixture::start(Mode::Upgraded);
    let engine = fixture.engine();
    let options = ContainerAttachOptions {
        stdin: true,
        ..options()
    };

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach(&engine, "web", &options))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");

    let Attached::Upgraded {
        status,
        read,
        write,
    } = attached
    else {
        panic!("the existing attach path stopped upgrading a 101 answer");
    };
    assert_eq!(status, hyper::StatusCode::SWITCHING_PROTOCOLS);
    exercise_upgraded(read, write).await;
}

#[tokio::test]
async fn dropping_the_200_stream_closes_the_connection() {
    let fixture = Fixture::start(Mode::HoldOpen(b"first"));
    let engine = fixture.engine();

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options()))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");
    let mut body = attached.into_stream().expect("a 200 answer has a body");

    let first = tokio::time::timeout(REQUEST_TIMEOUT, body.next_data())
        .await
        .expect("the first body read did not finish")
        .expect("the first body read failed");
    assert_eq!(first.as_deref(), Some(&b"first"[..]));

    // This is the cancellation mechanism: there is no cancel call, so dropping
    // the stream has to be enough to close the socket.
    drop(body);
    assert!(
        fixture.wait_for_close().await,
        "the fixture never observed the client closing the connection"
    );
}

#[tokio::test]
async fn a_200_attach_refuses_to_produce_a_write_half() {
    let fixture = Fixture::start(Mode::Body(b""));
    let engine = fixture.engine();

    let attached = tokio::time::timeout(REQUEST_TIMEOUT, attach_stream(&engine, "web", &options()))
        .await
        .expect("the attach did not finish")
        .expect("the attach failed");

    let error = attached
        .into_connection()
        .expect_err("a 200 answer must not be presented as a write half");
    assert_eq!(error.kind(), ErrorKind::Transport);
}
