//! Prove `connect_local` keeps a successful owned service create, and that the
//! create body never reaches Bollard's request log.
//!
//! `connect_local` captures the local endpoint once and builds both clients
//! from it. `raw_engine` still reports that client as unreachable because most
//! operations keep their generated fallback, but a service create cannot use
//! that fallback safely: Bollard traces a buffered request body, so a generated
//! create would write `ContainerSpec.Env` and the names of
//! `ContainerSpec.Secrets` to a TRACE log. The facade therefore uses the
//! recorded socket, like the owned service update, and fails closed only when
//! no concrete target was captured.
//!
//! The test asserts a versioned request line, the secret-bearing body, the
//! Engine's URL-safe credential header, and a TRACE capture in which a generated
//! `/_ping` request is visible (the positive control) while none of the create
//! canaries are. A generated create would fail all of that.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.

#![cfg(unix)]
#![allow(missing_docs)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use neotales_docker::{
    API_VERSION, DockerClient, RegistryCredentials, ServicePlacement, ServiceRestartPolicy,
    ServiceSpec,
};
use tracing_subscriber::fmt::MakeWriter;

const SERVICE_ID: &str = "service0123456789abcdef";
const ENV_CANARY: &str = "canary-local-create-env-6a1f";
const SECRET_NAME_CANARY: &str = "canary-local-create-secret-name-2d7c";
const SECRET_CANARY: &str = "canary-local-create-registry-secret-8b4e";

/// An in-process TRACE sink for the local dispatch test.
#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl TraceCapture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the trace buffer")).into_owned()
    }
}

impl<'a> MakeWriter<'a> for TraceCapture {
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

/// One request the fixture answers.
struct Entry {
    target: String,
    body: String,
    prefix: &'static str,
}

/// A recorded request.
struct Captured {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON service body")
    }
}

#[test]
fn public_local_contract() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "local_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("SERVICE_CREATE_TEST_SOCKET", &socket)
        .status()
        .unwrap();
    assert!(status.success());
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    let socket_path = std::env::var_os("SERVICE_CREATE_TEST_SOCKET").unwrap();
    let listener = UnixListener::bind(&socket_path).unwrap();
    let other_socket = std::path::PathBuf::from(&socket_path).with_file_name("other.sock");
    let other = UnixListener::bind(&other_socket).unwrap();
    other.set_nonblocking(true).unwrap();
    let version = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    let create_target = format!("{version}/services/create");
    let entries = vec![
        Entry {
            target: format!("{version}/_ping"),
            body: "OK".to_owned(),
            prefix: "GET /v",
        },
        Entry {
            target: create_target.clone(),
            body: format!(r#"{{"ID":"{SERVICE_ID}"}}"#),
            prefix: "POST /v",
        },
        Entry {
            target: create_target,
            body: format!(r#"{{"ID":"{SERVICE_ID}"}}"#),
            prefix: "POST /v",
        },
    ];
    let (request_tx, requests) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        serve(&listener, entries, &request_tx, &done_rx);
    });

    let trace = TraceCapture::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(trace.clone())
        .try_init()
        .expect("install the trace capture");

    let client = DockerClient::connect_local().unwrap();
    assert!(
        client.raw_engine().is_ok(),
        "the local constructor has an owned route"
    );

    // The generated path's own request is the positive control: it proves the
    // TRACE sink observes Bollard's request records for this client at all.
    log::trace!("local-log-capture-control");
    let reply = client
        .ping()
        .await
        .expect("the owned path pings the captured socket");
    let _ = reply;
    assert_eq!(
        next(&requests).line,
        format!("GET {version}/_ping HTTP/1.1")
    );

    let created = client
        .create_service(complete_spec())
        .await
        .expect("the local create dispatches on the owned route");
    assert_eq!(created.id, SERVICE_ID);
    assert_plain_create(&next(&requests), &version);

    let created = client
        .create_service_with_credentials(
            complete_spec(),
            "registry.example",
            RegistryCredentials::new("probeuser", SECRET_CANARY),
        )
        .await
        .expect("the credentialed local create dispatches on the owned route");
    assert_eq!(created.id, SERVICE_ID);
    let header = assert_credentialed_create(&next(&requests), &version);

    done_tx.send(()).expect("signal the fixture");
    let extra = requests.try_iter().next();
    assert!(
        extra.is_none(),
        "the local create sent an unexpected request: {:?}",
        extra.map(|captured| captured.line)
    );
    server.join().unwrap();
    assert!(
        other
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "a client read a later endpoint instead of the captured one"
    );

    assert_trace_is_clean(&trace, &header);
}

/// Asserts the uncredentialed local create carried the whole specification.
fn assert_plain_create(plain: &Captured, version: &str) {
    assert_eq!(
        plain.line,
        format!("POST {version}/services/create HTTP/1.1"),
        "the local create did not use the owned versioned route"
    );
    assert_eq!(plain.header("x-registry-auth"), None);
    let body = plain.json();
    assert_eq!(
        body["TaskTemplate"]["ContainerSpec"]["Env"][0],
        format!("API_TOKEN={ENV_CANARY}")
    );
    assert_eq!(
        body["TaskTemplate"]["ContainerSpec"]["Secrets"][0]["SecretName"],
        SECRET_NAME_CANARY
    );
    assert_eq!(
        body["TaskTemplate"]["Placement"]["Constraints"][0],
        "node.role == worker"
    );
    assert!(
        body.get("Placement").is_none() && body.get("RestartPolicy").is_none(),
        "the local create sent a typed member at the specification root: {body}"
    );
}

/// Asserts the credentialed local create sent the Engine auth header, and
/// returns it.
fn assert_credentialed_create(credentialed: &Captured, version: &str) -> String {
    assert_eq!(
        credentialed.line,
        format!("POST {version}/services/create HTTP/1.1")
    );
    let header = credentialed
        .header("x-registry-auth")
        .expect("the credential header is sent");
    let expected = URL_SAFE.encode(format!(
        r#"{{"username":"probeuser","password":"{SECRET_CANARY}","serveraddress":"registry.example"}}"#
    ));
    assert_eq!(header, expected);
    header.to_owned()
}

/// Asserts Bollard's request log was active and none of the create's secrets
/// reached it.
fn assert_trace_is_clean(trace: &TraceCapture, header: &str) {
    let encoded_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    let encoded_secret = URL_SAFE.encode(SECRET_CANARY);
    let logs = trace.text();
    assert!(
        logs.lines()
            .any(|line| line.contains("local-log-capture-control")),
        "the TRACE capture did not observe Bollard's request record: {logs}"
    );
    for needle in [
        ENV_CANARY,
        SECRET_NAME_CANARY,
        SECRET_CANARY,
        &encoded_env,
        &encoded_secret,
        header,
    ] {
        assert!(
            !logs.contains(needle),
            "the local owned create logged a service secret: {logs}"
        );
    }
}

/// A specification whose task template carries an environment value and a
/// secret reference, plus the typed placement and restart policy.
fn complete_spec() -> ServiceSpec {
    ServiceSpec {
        name: Some("web".to_owned()),
        labels: Some(BTreeMap::from([(
            "org.example.team".to_owned(),
            "platform".to_owned(),
        )])),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {
                "Image": "registry.example/team/app:stable",
                "Env": [format!("API_TOKEN={ENV_CANARY}")],
                "Secrets": [{"SecretName": SECRET_NAME_CANARY, "File": {"Name": "api-token"}}]
            }
        })),
        placement: Some(ServicePlacement {
            constraints: vec!["node.role == worker".to_owned()],
            ..ServicePlacement::default()
        }),
        restart_policy: Some(ServiceRestartPolicy {
            condition: "on-failure".to_owned(),
            max_attempts: Some(3),
            ..ServiceRestartPolicy::default()
        }),
        ..ServiceSpec::default()
    }
}

/// Accepts exactly the expected requests, then watches briefly for an extra.
fn serve(
    listener: &UnixListener,
    entries: Vec<Entry>,
    requests: &mpsc::Sender<Captured>,
    done: &Receiver<()>,
) {
    listener.set_nonblocking(true).unwrap();
    for entry in entries {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if matches!(
                done.try_recv(),
                Ok(()) | Err(mpsc::TryRecvError::Disconnected)
            ) {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let captured = read_request(&mut stream);
                    assert_eq!(
                        captured.line.split_whitespace().nth(1),
                        Some(entry.target.as_str()),
                        "the local create request target changed: {}",
                        captured.line
                    );
                    assert!(
                        captured.line.starts_with(entry.prefix),
                        "the request did not match the captured-route prefix {}: {}",
                        entry.prefix,
                        captured.line
                    );
                    requests.send(captured).expect("record the request");
                    respond(&mut stream, &entry.body);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "the fixture timed out");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return,
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match done.recv_timeout(Duration::from_millis(50)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                assert!(
                    Instant::now() < deadline,
                    "the fixture never received the completion signal"
                );
            }
        }
    }
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let extra = read_request(&mut stream);
                panic!("an unexpected local create request arrived: {}", extra.line);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => break,
        }
    }
}

fn next(requests: &Receiver<Captured>) -> Captured {
    requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the fixture recorded no request")
}

/// Reads the request head and body.
fn read_request(stream: &mut UnixStream) -> Captured {
    stream
        .set_nonblocking(false)
        .expect("make the fixture stream blocking");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound the fixture read");
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
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
    let head = std::str::from_utf8(&request[..header_end]).unwrap();
    let mut lines = head.lines();
    let line = lines.next().expect("the request line").to_owned();
    let headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Captured {
        line,
        headers,
        body: request[header_end + 4..header_end + 4 + content_length].to_vec(),
    }
}

fn respond(stream: &mut UnixStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
}
