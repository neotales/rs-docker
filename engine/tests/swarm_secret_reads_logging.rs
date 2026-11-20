//! Secret reads never use the generated client, and this suite proves why.
//!
//! Bollard logs the whole decoded response body at `DEBUG` before it parses the
//! model. That is fine for an ordinary resource and unacceptable for a secret
//! read. The positive control exercises Bollard's generated `list_tasks` directly against
//! a body carrying a synthetic canary and asserts the logger captured it. The
//! negative control clears the log, performs an owned `inspect_secret` against a
//! body carrying the secret canary, and asserts no rendering of it reached the
//! logger at `TRACE` or `DEBUG`.
//!
//! The fixture is a loopback HTTP server and a synthetic document. No daemon or
//! real credential is involved.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use neotales_docker::{API_VERSION, DockerClient};

#[path = "support/swarm_secret_entries.rs"]
mod swarm_secret_entries;

use swarm_secret_entries::{
    SECRET_BODY_WITH_DATA, SECRET_DATA_BASE64, SECRET_DATA_CANARY, SECRET_ID,
};

/// A canary that only the generated client's body log can contain.
const GENERATED_LOG_CANARY: &str = "log-positive-control-task-canary-6a1d";

/// The captured log lines.
static LOGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

/// The capturing logger.
struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            LOGS.get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .expect("the log lock")
                .push(format!("{} {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

static LOGGER: Capture = Capture;

fn install_logger() {
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Trace);
}

fn captured() -> std::sync::MutexGuard<'static, Vec<String>> {
    LOGS.get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .expect("the log lock")
}

/// A loopback server answering one owned task list and one owned secret
/// inspect, in that order.
struct Fixture {
    endpoint: String,
    server: thread::JoinHandle<()>,
}

impl Fixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let task_body = format!(
            r#"[{{"ID":"task-fixture","Name":"{GENERATED_LOG_CANARY}","ServiceID":"svc-fixture","Slot":1,"NodeID":"node-fixture","Status":{{"State":"running"}},"Spec":{{"ContainerSpec":{{"Image":"nginx:1.27"}}}}}}]"#
        );
        let prefix = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
        let secret_target = format!("GET {prefix}/secrets/{SECRET_ID} HTTP/1.1");
        let list_target = format!("GET {prefix}/secrets HTTP/1.1");
        let entries = [
            (format!("GET {prefix}/tasks HTTP/1.1"), task_body),
            (secret_target, SECRET_BODY_WITH_DATA.to_owned()),
            (list_target, format!("[{SECRET_BODY_WITH_DATA}]")),
        ];
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            for (expected, body) in entries {
                let mut stream = accept_within(&listener, deadline).expect("the fixture timed out");
                let head = read_request_head(&mut stream, deadline);
                let line = head.lines().next().expect("the request line");
                assert_eq!(line, expected, "the fixture saw an unexpected request");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
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
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// Accepts one connection within a bounded window and bounds its reads.
fn accept_within(listener: &TcpListener, deadline: Instant) -> Option<TcpStream> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(remaining));
                let _ = stream.set_write_timeout(Some(remaining));
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(remaining.min(Duration::from_millis(20)));
            }
            Err(_) => return None,
        }
    }
}

fn read_request_head(stream: &mut TcpStream, deadline: Instant) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "the fixture read budget expired");
        let _ = stream.set_read_timeout(Some(remaining));
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let mut head = request[..end].to_vec();
            head.extend_from_slice(b"\r\n\r\n");
            return String::from_utf8_lossy(&head).into_owned();
        }
    }
}

#[tokio::test]
async fn owned_task_and_secret_reads_do_not_log_response_bodies() {
    tokio::time::timeout(Duration::from_secs(40), logging_body())
        .await
        .expect("the logging fixture exceeded its 40s total budget");
}

async fn logging_body() {
    install_logger();
    let fixture = Fixture::start();
    let client = fixture.client();

    captured().clear();
    let tasks = tokio::time::timeout(Duration::from_secs(5), client.list_tasks(None))
        .await
        .expect("the task fixture answered")
        .expect("the owned task list decoded");
    assert_eq!(tasks.len(), 1);
    assert!(!captured().join("\n").contains(GENERATED_LOG_CANARY));

    captured().clear();
    let secret = tokio::time::timeout(Duration::from_secs(5), client.inspect_secret(SECRET_ID))
        .await
        .expect("the secret fixture answered")
        .expect("the owned secret document decoded");
    assert_eq!(
        secret.id.as_deref(),
        Some(SECRET_ID),
        "the fixture carried the secret document"
    );
    let negative = captured().join("\n");
    assert!(
        !negative.contains(SECRET_DATA_CANARY) && !negative.contains(SECRET_DATA_BASE64),
        "the owned secret inspect logged the secret: {negative}"
    );

    captured().clear();
    let secrets = tokio::time::timeout(Duration::from_secs(5), client.list_secrets(None))
        .await
        .expect("the secret list fixture answered")
        .expect("the owned secret list decoded");
    assert_eq!(secrets.len(), 1);
    assert!(
        secrets[0]
            .spec
            .as_ref()
            .is_some_and(|spec| spec.additional.contains_key("Data")),
        "the list fixture did not carry the unexpected Data"
    );
    let list_negative = captured().join("\n");
    assert!(
        !list_negative.contains(SECRET_DATA_CANARY) && !list_negative.contains(SECRET_DATA_BASE64),
        "the owned secret list logged the secret: {list_negative}"
    );

    fixture.finish();
}
