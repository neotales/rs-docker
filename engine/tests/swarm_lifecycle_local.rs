//! Prove `connect_local` serves the Swarm lifecycle through the captured
//! owned endpoint.
//!
//! `connect_local` captures the local endpoint once and builds both clients
//! from it. `raw_engine` still reports the client as unreachable because most
//! operations keep their generated fallback, but the Swarm lifecycle operations
//! use the recorded Unix socket. The assertions are wire assertions: versioned
//! request lines for init, join, update, certificates, and unlock-key, and a
//! TRACE capture that never sees the join token or either returned key.
//!
//! A generated fallback would lose the version prefix, and for the join it
//! would trace the token. The local route preserves the previously working
//! `connect_local` behavior without putting Bollard back on the path.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.

#![cfg(unix)]
#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::{Command, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use neotales_docker::{
    API_VERSION, DockerClient, SwarmInitOptions, SwarmJoinOptions, SwarmSpec, SwarmUpdateOptions,
};

/// A synthetic join token. It is never a real credential.
const TOKEN: &str = "SWMTKN-1-canary-local-join-token-4b7e2c19-do-not-log-me";
/// A synthetic node key. It is never a real credential.
const NODE_KEY: &str =
    "-----BEGIN PRIVATE KEY-----canary-local-node-key-5a7d-----END PRIVATE KEY-----";
/// A synthetic manager unlock key. It is never a real credential.
const UNLOCK_KEY: &str = "SWMKEY-1-canary-local-unlock-key-9e4c-do-not-log-me";
/// A synthetic manager address. It is never a real endpoint.
const INIT_ADDRESS: &str = "canary-local-init-manager-10.9.8.6-do-not-log-me";
/// A synthetic specification value. It is never real cluster data.
const UPDATE_SPEC: &str = "canary-local-update-spec-2f8a-do-not-log-me";

/// An in-process TRACE sink for the local dispatch test.
#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl TraceCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the trace buffer")).into_owned()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TraceCapture {
    type Writer = TraceCaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceCaptureWriter(self.0.clone())
    }
}

struct TraceCaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceCaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the trace buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn public_local_owned_contract() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "local_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("SWARM_LIFECYCLE_LOCAL_TEST_SOCKET", &socket);
    let status = supervise_child(command, Duration::from_secs(30));
    assert!(
        status.success(),
        "the local lifecycle child failed: {status}"
    );
}

/// Runs a child to completion under a hard deadline.
///
/// Normal exits are reaped by `try_wait`. A deadline or a `try_wait` failure
/// sends a kill, then polls `try_wait` for a bounded reaping window before
/// panicking; `Child::wait` is never called unbounded. On Unix a successful
/// `kill` means SIGKILL was sent, not that the kernel has already reaped the
/// child, so a child that is still present at the reaping deadline is reported
/// as such rather than silently abandoned.
fn supervise_child(mut command: Command, deadline: Duration) -> ExitStatus {
    let mut child = command.spawn().expect("spawn the lifecycle child");
    let deadline = Instant::now() + deadline;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() >= deadline => {
                let kill = child.kill();
                let (reaped, detail) = reap_bounded(&mut child, Duration::from_secs(5));
                panic!(
                    "the local lifecycle child exceeded its deadline; kill result: {kill:?}; {detail}; reaped within 5s: {reaped} (on Unix a successful kill only sends SIGKILL, so the kernel may still own the process)"
                );
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                let kill = child.kill();
                let (reaped, detail) = reap_bounded(&mut child, Duration::from_secs(5));
                panic!(
                    "polling the local lifecycle child failed: {error}; kill result: {kill:?}; {detail}; reaped within 5s: {reaped} (on Unix a successful kill only sends SIGKILL, so the kernel may still own the process)"
                );
            }
        }
    }
}

/// Polls `try_wait` for a bounded window and reports whether it reaped the
/// child, without ever calling the unbounded `wait`.
fn reap_bounded(child: &mut std::process::Child, deadline: Duration) -> (bool, String) {
    let deadline = Instant::now() + deadline;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (true, format!("child exited with {status}")),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                return (
                    false,
                    String::from("child still present at the reaping deadline"),
                );
            }
            Err(error) => {
                return (false, format!("try_wait failed during reaping: {error}"));
            }
        }
    }
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    let listener =
        UnixListener::bind(std::env::var_os("SWARM_LIFECYCLE_LOCAL_TEST_SOCKET").unwrap()).unwrap();
    let server = thread::spawn(move || serve(&listener));

    let client = DockerClient::connect_local().unwrap();
    assert!(
        client.raw_engine().is_ok(),
        "general owned routing must still report connect_local as unreachable"
    );

    let trace = TraceCapture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .without_time()
        .with_writer(trace.clone())
        .try_init()
        .expect("install the trace capture");

    let node_id = client
        .initialize_swarm(SwarmInitOptions {
            listen_address: Some(INIT_ADDRESS.to_owned()),
            ..SwarmInitOptions::new()
        })
        .await
        .expect("the captured local endpoint initialized the Swarm");
    assert_eq!(node_id, "node-local");

    client
        .join_swarm(SwarmJoinOptions {
            token: TOKEN.to_owned(),
            remote_addresses: vec!["tcp://manager:2377".to_owned()],
            ..SwarmJoinOptions::default()
        })
        .await
        .expect("the captured local endpoint accepted the join");

    client
        .update_swarm(SwarmUpdateOptions {
            version: 3,
            spec: SwarmSpec {
                name: Some(UPDATE_SPEC.to_owned()),
                labels: None,
                additional: std::collections::BTreeMap::new(),
            },
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        })
        .await
        .expect("the captured local endpoint accepted the update");

    let certificates = client
        .swarm_certificates()
        .await
        .expect("the captured local endpoint returned certificates");
    assert_eq!(certificates.key(), Some(NODE_KEY));
    assert!(
        !format!("{certificates:?}").contains(NODE_KEY),
        "the local certificate Debug leaked the node key"
    );

    let key = client
        .swarm_unlock_key()
        .await
        .expect("the captured local endpoint returned the unlock key");
    assert_eq!(key.key(), Some(UNLOCK_KEY));
    assert!(
        !format!("{key:?}").contains(UNLOCK_KEY),
        "the local unlock-key Debug leaked the key"
    );

    let logs = trace.text();
    for canary in [TOKEN, NODE_KEY, UNLOCK_KEY, INIT_ADDRESS, UPDATE_SPEC] {
        assert!(
            !logs.contains(canary),
            "the local owned lifecycle logged sensitive request or response data: {logs}"
        );
    }

    server.join().unwrap();
}

fn serve(listener: &UnixListener) {
    let prefix = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    // Each entry is (expected request target, response status, body).
    let entries = [
        (
            format!("{prefix}/swarm/init"),
            "200 OK",
            r#""node-local""#.to_owned(),
        ),
        (format!("{prefix}/swarm/join"), "200 OK", String::new()),
        (
            format!(
                "{prefix}/swarm/update?version=3&rotateWorkerToken=false&rotateManagerToken=false&rotateManagerUnlockKey=false"
            ),
            "200 OK",
            String::new(),
        ),
        (
            format!("{prefix}/swarm/cert"),
            "200 OK",
            format!(
                r#"{{"NodeID":"node-local","RootCA":"ROOT","Cert":"CERT","Key":"{NODE_KEY}"}}"#
            ),
        ),
        (
            format!("{prefix}/swarm/unlockkey"),
            "200 OK",
            format!(r#"{{"UnlockKey":"{UNLOCK_KEY}"}}"#),
        ),
    ];
    for (target, status, body) in entries {
        let (mut stream, _) = listener.accept().unwrap();
        let (head, _body) = read_request(&mut stream);
        let line = head.lines().next().expect("the request line");
        assert_eq!(
            line.split_whitespace().nth(1),
            Some(target.as_str()),
            "the local lifecycle request line changed: {line}"
        );
        respond_json(&mut stream, status, &body);
    }
}

fn respond_json(stream: &mut UnixStream, status: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
}

fn read_request(stream: &mut UnixStream) -> (String, Vec<u8>) {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
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
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "the request body ended early");
        request.extend_from_slice(&chunk[..read]);
    }
    (
        head,
        request[body_start..body_start + content_length].to_vec(),
    )
}
