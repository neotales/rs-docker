//! Plugin writes through the socket `connect_local` captured, in a child process
//! with an isolated environment.
//!
//! `connect_local` has no repository-owned target for the general routing signal,
//! so a write that must not fall back would otherwise refuse. The local
//! constructor records the concrete socket Bollard was given, and the settings
//! write and the credentialed push use it. This suite proves that from outside:
//! the requests are the versioned owned ones on that socket, and the generated
//! client is not reached.
//!
//! # What must not change
//!
//! - `set_plugin_config` is `POST /v1.NN/plugins/{escaped}/set` with the settings
//!   JSON array as the body, and it does not fall back.
//! - the credentialed push is `POST /v1.NN/plugins/{escaped}/push` with an
//!   `X-Registry-Auth` header the Engine can decode.
//! - the credential is never handed to Bollard, whose encoding the Engine can
//!   silently read as no credential.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.
#![cfg(unix)]
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use neotales_docker::{DockerClient, RegistryCredentials};

#[path = "support/supervised_child.rs"]
mod supervised_child;

/// The variable naming the socket the worker binds.
const SOCKET_VARIABLE: &str = "PLUGIN_WRITES_TEST_SOCKET";

/// How long the parent waits for the worker process.
const WORKER_BOUND: Duration = Duration::from_secs(30);

/// The longest the worker's fixture may run in total. A per-read timeout alone
/// is not a bound: a peer trickling one byte per timeout could keep it alive.
const TOTAL_BOUND: Duration = Duration::from_secs(15);

/// The read-poll interval at which the deadline is re-checked.
const IO_POLL: Duration = Duration::from_millis(250);

/// How long one answer write may take.
const WRITE_BOUND: Duration = Duration::from_secs(2);

/// Runs the ignored worker in a child so `DOCKER_HOST` cannot leak into the
/// parent's environment.
#[test]
fn public_local_contract() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let socket = dir.path().join("engine.sock");
    let mut command = Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args(["--exact", "local_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env(SOCKET_VARIABLE, &socket);
    let status = supervised_child::run(command, WORKER_BOUND);
    assert!(status.success(), "the local worker failed: {status}");
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    let listener =
        UnixListener::bind(std::env::var_os(SOCKET_VARIABLE).expect("the socket variable"))
            .expect("bind the fixture");
    let deadline = Instant::now() + TOTAL_BOUND;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let _stop_on_drop = StopOnDrop(stop);
    let server = thread::spawn(move || {
        let mut stream = accept_bounded(&listener, &worker_stop, deadline);
        let request = read_request(&mut stream, &worker_stop, deadline);
        assert_eq!(
            request.line,
            "POST /v1.55/plugins/vieux%2Fsshfs%3Alatest/set HTTP/1.1"
        );
        assert_eq!(request.body, br#"["DEBUG=1"]"#);
        respond(&mut stream, "204 No Content", "", &worker_stop, deadline)
            .expect("write and drain the settings response within its bound");

        let mut stream = accept_bounded(&listener, &worker_stop, deadline);
        let request = read_request(&mut stream, &worker_stop, deadline);
        assert_eq!(
            request.line,
            "POST /v1.55/plugins/registry.example%2Fvieux%2Fsshfs%3Alatest/push HTTP/1.1"
        );
        let header = request
            .header("x-registry-auth")
            .expect("the credential header");
        let decoded = base64::engine::general_purpose::URL_SAFE
            .decode(header)
            .expect("URL-safe base64");
        let auth: serde_json::Value = serde_json::from_slice(&decoded).expect("the auth object");
        assert_eq!(auth["username"], "user");
        assert_eq!(auth["password"], "secret");
        respond(&mut stream, "200 OK", "", &worker_stop, deadline)
            .expect("write and drain the push response within its bound");
    });

    let client = DockerClient::connect_local().expect("build the local client");
    assert!(
        client.raw_engine().is_ok(),
        "connect_local must expose its captured owned target"
    );
    client
        .set_plugin_config("vieux/sshfs:latest", vec!["DEBUG=1".to_owned()])
        .await
        .expect("the settings write reached the captured socket");
    client
        .push_plugin_with_credentials(
            "registry.example/vieux/sshfs:latest",
            RegistryCredentials::new("user", "secret"),
        )
        .await
        .expect("the credentialed push reached the captured socket");

    server.join().expect("the fixture thread");
}

/// Accepts one connection with an operation deadline, then uses poll-sized reads.
fn accept_bounded(listener: &UnixListener, stop: &AtomicBool, deadline: Instant) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("make the fixture listener nonblocking");
    loop {
        assert!(
            !stop.load(Ordering::SeqCst) && Instant::now() < deadline,
            "the fixture was stopped or exceeded its operation bound"
        );
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make the accepted stream blocking");
                stream
                    .set_read_timeout(Some(IO_POLL))
                    .expect("set the fixture poll interval");
                stream
                    .set_write_timeout(Some(IO_POLL))
                    .expect("bound the fixture write");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("the fixture could not accept a connection: {error}"),
        }
    }
}

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
}

/// Reads the request head and any `Content-Length` body, bounded by the
/// operation deadline.
fn read_request(stream: &mut UnixStream, stop: &AtomicBool, deadline: Instant) -> Captured {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        assert!(
            !stop.load(Ordering::SeqCst) && Instant::now() < deadline,
            "the fixture was stopped or exceeded its operation bound"
        );
        set_read_poll(stream, deadline).expect("set the bounded request read timeout");
        match stream.read(&mut chunk) {
            Ok(0) => panic!("the request ended before its headers"),
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("read the request: {error}"),
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
    while request.len() < body_start + content_length {
        assert!(
            !stop.load(Ordering::SeqCst) && Instant::now() < deadline,
            "the fixture was stopped or exceeded its operation bound"
        );
        set_read_poll(stream, deadline).expect("set the bounded request-body read timeout");
        match stream.read(&mut chunk) {
            Ok(0) => panic!("the request body ended early"),
            Ok(read) => request.extend_from_slice(&chunk[..read]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("read the request body: {error}"),
        }
    }
    Captured {
        line: head
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned(),
        head,
        body: request[body_start..body_start + content_length].to_vec(),
    }
}

/// Writes an answer and waits for the client to release the connection.
fn respond(
    stream: &mut UnixStream,
    status: &str,
    body: &str,
    stop: &AtomicBool,
    deadline: Instant,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    write_bounded(stream, response.as_bytes(), stop, deadline)?;
    let mut buffer = [0_u8; 64];
    let drain_by = deadline.min(Instant::now() + WRITE_BOUND);
    while !stop.load(Ordering::SeqCst) && Instant::now() < drain_by {
        set_read_poll(stream, drain_by)?;
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn set_read_poll(stream: &UnixStream, deadline: Instant) -> std::io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "fixture read deadline elapsed",
        ));
    }
    stream.set_read_timeout(Some(IO_POLL.min(remaining)))
}

fn write_bounded(
    stream: &mut UnixStream,
    response: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> std::io::Result<()> {
    let write_deadline = deadline.min(Instant::now() + WRITE_BOUND);
    let mut written = 0;
    while written < response.len() {
        if stop.load(Ordering::SeqCst) || Instant::now() >= write_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fixture response write deadline/stop",
            ));
        }
        let remaining = write_deadline.saturating_duration_since(Instant::now());
        stream.set_write_timeout(Some(IO_POLL.min(remaining)))?;
        match stream.write(&response[written..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => written += count,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    stream.flush()
}

struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
