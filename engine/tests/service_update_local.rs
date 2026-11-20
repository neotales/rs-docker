//! Prove `connect_local` keeps a successful owned service update.
//!
//! `connect_local` captures the local endpoint once and builds both clients
//! from it (on Unix, `DOCKER_HOST` only when it starts with `unix://`, otherwise
//! `/var/run/docker.sock`). The test pings through the generated client and
//! updates through the owned transport against the same captured socket, and
//! watches a second socket that must receive nothing. General owned routing
//! still reports that local client as unreachable, because the other operations
//! keep their generated fallback. A service update cannot use that fallback safely — Bollard traces
//! the buffered specification and preserves peer text — so it uses the recorded
//! socket and dispatches the owned request instead of failing closed.
//!
//! The assertions are wire assertions: a versioned request line, the repository
//! body with an unmodelled member that Bollard's `TaskSpec` would drop, the
//! Engine's URL-safe credential header, and no second request. A generated
//! fallback would fail all four.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.
#![cfg(unix)]
#![allow(missing_docs)]

use std::{
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
    API_VERSION, DockerClient, RegistryCredentials, ServiceSpec, ServiceUpdateOptions,
};
use tracing_subscriber::fmt::MakeWriter;

const SERVICE_ID: &str = "service0123456789abcdef";
const ENV_CANARY: &str = "canary-local-service-env-8f3d";
const SECRET_CANARY: &str = "canary-local-registry-secret-4a7c";

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
        .env("SERVICE_UPDATE_TEST_SOCKET", &socket)
        .status()
        .unwrap();
    assert!(status.success());
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    let socket_path = std::env::var_os("SERVICE_UPDATE_TEST_SOCKET").unwrap();
    let listener = UnixListener::bind(&socket_path).unwrap();
    let other_socket = std::path::PathBuf::from(&socket_path).with_file_name("other.sock");
    let other = UnixListener::bind(&other_socket).unwrap();
    other.set_nonblocking(true).unwrap();
    let version = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    let plain_target =
        format!("{version}/services/{SERVICE_ID}/update?version=7&registryAuthFrom=spec");
    let rollback_target = format!(
        "{version}/services/{SERVICE_ID}/update?version=7&registryAuthFrom=spec&rollback=previous"
    );
    let inspect_body = format!(
        r#"{{"ID":"{SERVICE_ID}","Version":{{"Index":7}},"Spec":{{
          "Name":"web",
          "Labels":{{"original":"yes"}},
          "TaskTemplate":{{
            "ContainerSpec":{{
              "Image":"registry.example/web:1.2",
              "Env":["API_TOKEN={ENV_CANARY}"],
              "UnmodelledContainerMember":true
            }},
            "Placement":{{"Constraints":["node.role == worker"]}},
            "UnmodelledTaskMember":1
          }},
          "Mode":{{"Replicated":{{"Replicas":3}}}},
          "EndpointSpec":{{"Mode":"vip"}}
        }}}}"#
    );
    let inspect_target = format!("{version}/services/{SERVICE_ID}");
    let entries = vec![
        Entry {
            target: format!("{version}/_ping"),
            body: "OK".to_owned(),
            prefix: "GET /v",
        },
        Entry {
            target: inspect_target,
            body: inspect_body,
            prefix: "GET /v",
        },
        Entry {
            target: plain_target.clone(),
            body: "{}".to_owned(),
            prefix: "POST /v",
        },
        Entry {
            target: plain_target,
            body: "{}".to_owned(),
            prefix: "POST /v",
        },
        Entry {
            target: rollback_target,
            body: "{}".to_owned(),
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

    assert_roundtrip(&client, &requests, &trace).await;

    done_tx.send(()).expect("signal the fixture");
    let extra = requests.try_iter().next();
    assert!(
        extra.is_none(),
        "the local update sent an unexpected request: {:?}",
        extra.map(|captured| captured.line)
    );
    server.join().unwrap();
    assert!(
        other
            .accept()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "a client read a later endpoint instead of the captured one"
    );
}

async fn assert_roundtrip(
    client: &DockerClient,
    requests: &Receiver<Captured>,
    trace: &TraceCapture,
) {
    let version = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    // A generated (Bollard) operation and the owned update must both use the
    // endpoint captured at construction, not a later environment value.
    log::trace!("local-log-capture-control");
    let reply = client
        .ping()
        .await
        .expect("the owned path pings the captured socket");
    let _ = reply;
    let ping = next(requests);
    assert_eq!(ping.line, format!("GET {version}/_ping HTTP/1.1"));

    let current = client
        .inspect_service(SERVICE_ID)
        .await
        .expect("the local inspect uses the owned route");
    let inspect = next(requests);
    assert_eq!(
        inspect.line,
        format!("GET {version}/services/{SERVICE_ID} HTTP/1.1"),
        "the local inspect fell back to the generated unversioned path"
    );
    let mut spec = current.spec.expect("the daemon sent a specification");
    assert_eq!(
        spec.task_template
            .as_ref()
            .and_then(|template| template.get("UnmodelledTaskMember"))
            .cloned(),
        Some(serde_json::json!(1)),
        "the local inspect dropped an unmodelled nested member"
    );
    spec.labels
        .get_or_insert_with(std::collections::BTreeMap::new)
        .insert("updated".to_owned(), "yes".to_owned());

    plain_update(client, &spec, requests).await;
    let auth_header = credentialed_update(client, &spec, requests).await;
    rollback_update(client, &spec, requests).await;

    let base64_env = URL_SAFE.encode(format!("API_TOKEN={ENV_CANARY}"));
    let base64_secret = URL_SAFE.encode(SECRET_CANARY);
    let logs = trace.text();
    assert!(
        logs.lines()
            .any(|line| line.contains("local-log-capture-control")),
        "the TRACE capture did not observe Bollard's target and request in one record: {logs}"
    );
    for needle in [
        ENV_CANARY,
        SECRET_CANARY,
        &base64_env,
        &base64_secret,
        &auth_header,
    ] {
        assert!(
            !logs.contains(needle),
            "the local owned route logged a service secret: {logs}"
        );
    }
}

async fn plain_update(client: &DockerClient, spec: &ServiceSpec, requests: &Receiver<Captured>) {
    client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: spec.clone(),
                rollback: false,
            },
        )
        .await
        .expect("the local update dispatches on the owned route");
    assert_plain(&next(requests), false);
}

async fn credentialed_update(
    client: &DockerClient,
    spec: &ServiceSpec,
    requests: &Receiver<Captured>,
) -> String {
    client
        .update_service_with_credentials(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: spec.clone(),
                rollback: false,
            },
            "registry.example",
            RegistryCredentials::new("probeuser", SECRET_CANARY),
        )
        .await
        .expect("the credentialed local update dispatches on the owned route");
    let captured = next(requests);
    assert_plain(&captured, true);
    let header = captured
        .header("x-registry-auth")
        .expect("the credential header is sent");
    let expected = URL_SAFE.encode(format!(
        r#"{{"username":"probeuser","password":"{SECRET_CANARY}","serveraddress":"registry.example"}}"#
    ));
    assert_eq!(
        header, expected,
        "the sent auth header was not the expected encoded credential"
    );
    let decoded = URL_SAFE
        .decode(header)
        .expect("the Engine's URL-safe alphabet");
    let auth: serde_json::Value =
        serde_json::from_slice(&decoded).expect("the auth header is JSON");
    assert_eq!(
        auth,
        serde_json::json!({
            "username": "probeuser",
            "password": SECRET_CANARY,
            "serveraddress": "registry.example"
        })
    );
    header.to_owned()
}

async fn rollback_update(client: &DockerClient, spec: &ServiceSpec, requests: &Receiver<Captured>) {
    client
        .update_service(
            SERVICE_ID,
            ServiceUpdateOptions {
                version: 7,
                spec: spec.clone(),
                rollback: true,
            },
        )
        .await
        .expect("the local rollback dispatches on the owned route");
    let version = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    let captured = next(requests);
    assert_eq!(
        captured.line,
        format!(
            "POST {version}/services/{SERVICE_ID}/update?version=7&registryAuthFrom=spec&rollback=previous HTTP/1.1"
        )
    );
    assert_eq!(
        captured.json(),
        expected_local_body(),
        "the rollback body changed; observed: {}",
        String::from_utf8_lossy(&captured.body)
    );
}

fn assert_plain(captured: &Captured, credentialed: bool) {
    let version = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    assert_eq!(
        captured.line,
        format!(
            "POST {version}/services/{SERVICE_ID}/update?version=7&registryAuthFrom=spec HTTP/1.1"
        ),
        "the local update did not use the owned versioned route"
    );
    if credentialed {
        assert!(
            captured.header("x-registry-auth").is_some(),
            "the credentialed update did not send its header"
        );
    } else {
        assert_eq!(captured.header("x-registry-auth"), None);
    }
    assert_eq!(
        captured.json(),
        expected_local_body(),
        "the local update body changed; observed: {}",
        String::from_utf8_lossy(&captured.body)
    );
}

/// The complete update body for the inspected specification plus the label
/// change. Compared as JSON values, so key order is not part of the claim.
fn expected_local_body() -> serde_json::Value {
    serde_json::json!({
        "Name": "web",
        "Labels": {"original": "yes", "updated": "yes"},
        "TaskTemplate": {
            "ContainerSpec": {
                "Image": "registry.example/web:1.2",
                "Env": [format!("API_TOKEN={ENV_CANARY}")],
                "UnmodelledContainerMember": true
            },
            "Placement": {"Constraints": ["node.role == worker"]},
            "UnmodelledTaskMember": 1
        },
        "Mode": {"Replicated": {"Replicas": 3}},
        "EndpointSpec": {"Mode": "vip"}
    })
}

/// Accepts exactly the expected requests, then watches briefly for an extra.
///
/// The listener is nonblocking and checks the completion signal while waiting,
/// so a failed operation cannot leave the fixture blocked on an accept that
/// never arrives.
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
                        "the local update request target changed: {}",
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
    // Wait for the child's completion signal, then drain any queued extra
    // connection before returning. The signal keeps this window from ending
    // before the three calls and their assertions finish.
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
                panic!("an unexpected local update request arrived: {}", extra.line);
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
    // Bound every accepted connection: a peer that sends a partial request must
    // fail the fixture rather than block the watcher forever. An accepted
    // stream can inherit a nonblocking listener's mode.
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
    let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
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
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
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
