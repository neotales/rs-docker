//! Case-folded service specification members are refused before dispatch.
//!
//! The Engine matches JSON member names case-insensitively (Go folds names), so
//! `Placement` and `placement`, or `Labels` and `labels`, are one member to the
//! daemon and the winner depends on the encoded order. A typed field beside a
//! case variant in `additional` or `task_template` must not become two keys on
//! the wire. The facade refuses the specification before it chooses a
//! transport, so these fixtures assert that no connection is opened at all.
//!
//! The allowed control is the other half of the claim: a non-ASCII *label key*
//! and an unknown ASCII task-template member still reach the wire, because the
//! restriction is on member names the Engine models, not on service-defined map
//! keys and unknown members.

#![allow(missing_docs)]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use neotales_docker::{
    API_VERSION, DockerClient, ErrorKind, ServicePlacement, ServiceRestartPolicy, ServiceSpec,
    ServiceUpdateOptions,
};

const SERVICE_ID: &str = "service0123456789abcdef";

/// A value that must not appear in any refusal rendering.
const CANARY: &str = "canary-fold-7b3d-do-not-echo";

#[tokio::test]
async fn facade_service_writes_refuse_case_folded_members_before_dispatch() {
    let fixture = NoDispatch::start();
    let client = fixture.client();
    for (what, spec) in folded_specifications() {
        let error = client
            .create_service(spec.clone())
            .await
            .unwrap_err_or_panic(what);
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
        assert_fold_refusal(what, &error);

        let error = client
            .update_service(
                SERVICE_ID,
                ServiceUpdateOptions {
                    version: 7,
                    spec,
                    rollback: false,
                },
            )
            .await
            .unwrap_err_or_panic(what);
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
        assert_fold_refusal(what, &error);
    }
    fixture.finish();
}

#[tokio::test]
async fn allowed_unknowns_and_non_ascii_map_keys_reach_the_wire() {
    let fixture = Fixture::start(vec![created(r#"{"ID":"service0123456789abcdef"}"#)]);
    let mut spec = ServiceSpec {
        name: Some("web".to_owned()),
        labels: Some(BTreeMap::from([("naïve".to_owned(), "value".to_owned())])),
        task_template: Some(serde_json::json!({
            "ContainerSpec": {
                "Image": "nginx:alpine",
                "Labels": {"ключ": "значение"}
            },
            "UnmodelledTaskMember": true
        })),
        ..ServiceSpec::default()
    };
    spec.additional
        .insert("UnmodelledRoot".to_owned(), serde_json::json!(true));

    let created = fixture
        .client()
        .create_service(spec)
        .await
        .expect("the specification is allowed");
    assert_eq!(created.id, SERVICE_ID);

    let request = fixture.next();
    assert_eq!(
        request.line,
        format!("POST {}/services/create HTTP/1.1", version_prefix())
    );
    let body = request.json();
    assert_eq!(body["Labels"]["naïve"], "value");
    assert_eq!(
        body["TaskTemplate"]["ContainerSpec"]["Labels"]["ключ"],
        "значение"
    );
    assert_eq!(body["TaskTemplate"]["UnmodelledTaskMember"], true);
    assert_eq!(body["UnmodelledRoot"], true);
    assert!(
        !body.to_string().contains(CANARY),
        "the control carried a canary"
    );
    fixture.finish();
}

/// The specifications where one modeled member has two case spellings.
fn folded_specifications() -> Vec<(&'static str, ServiceSpec)> {
    let placement = ServicePlacement {
        constraints: vec!["node.role == worker".to_owned()],
        ..ServicePlacement::default()
    };
    let policy = ServiceRestartPolicy {
        condition: "on-failure".to_owned(),
        ..ServiceRestartPolicy::default()
    };
    let mut typed_labels = ServiceSpec {
        labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
        ..ServiceSpec::default()
    };
    typed_labels
        .additional
        .insert("labels".to_owned(), serde_json::json!({"tier": "other"}));
    let mut duplicate_keys = ServiceSpec::default();
    duplicate_keys
        .additional
        .insert("Unmodelled".to_owned(), serde_json::json!(1));
    duplicate_keys
        .additional
        .insert("unmodelled".to_owned(), serde_json::json!(2));
    let mut non_ascii = ServiceSpec::default();
    non_ascii.additional.insert(
        format!("Labelſ-{CANARY}"),
        serde_json::json!({"kept": true}),
    );

    vec![
        (
            "a typed placement beside a lower-case template member",
            ServiceSpec {
                placement: Some(placement),
                task_template: Some(serde_json::json!({
                    "placement": {"Constraints": []}
                })),
                ..ServiceSpec::default()
            },
        ),
        (
            "a typed restart policy beside a lower-case template member",
            ServiceSpec {
                restart_policy: Some(policy),
                task_template: Some(serde_json::json!({
                    "restartpolicy": {"Condition": "any"}
                })),
                ..ServiceSpec::default()
            },
        ),
        (
            "a typed task template beside a lower-case additional key",
            ServiceSpec {
                task_template: Some(serde_json::json!({"ContainerSpec": {}})),
                additional: BTreeMap::from([(
                    "tasktemplate".to_owned(),
                    serde_json::json!({"ContainerSpec": {}}),
                )]),
                ..ServiceSpec::default()
            },
        ),
        (
            "a typed label map beside a lower-case additional key",
            typed_labels,
        ),
        ("two case spellings of one additional key", duplicate_keys),
        ("a non-ASCII additional key", non_ascii),
    ]
}

/// Asserts the refusal names the fold or the non-ASCII restriction and leaks
/// nothing.
fn assert_fold_refusal(what: &str, error: &neotales_docker::Error) {
    let message = error.to_string();
    assert!(
        message.contains("case spelling")
            || message.contains("case-insensitively")
            || message.contains("non-ASCII"),
        "{what}: the refusal did not name the restriction: {message}"
    );
    let mut renderings = vec![message, format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    assert!(
        renderings.len() > 1,
        "{what}: the error carried no source chain"
    );
    for rendering in renderings {
        assert!(!rendering.contains(CANARY), "{what}: {rendering}");
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
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
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
            "a refused specification was dispatched"
        );
    }
}

/// A one-request fixture for the allowed control.
struct Fixture {
    endpoint: String,
    requests: Receiver<Captured>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let mut stream = accept_tcp(&listener);
                let captured = read_request(&mut stream);
                let _ = request_tx.send(captured);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
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

    fn next(&self) -> Captured {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

struct Captured {
    line: String,
    body: Vec<u8>,
}

impl Captured {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("a JSON request body")
    }
}

fn created(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
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

fn read_request(stream: &mut TcpStream) -> Captured {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound the fixture read");
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let (header_end, content_length) = loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
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
    let head = std::str::from_utf8(&request[..header_end]).expect("UTF-8 headers");
    let line = head
        .lines()
        .next()
        .expect("the request has a request line")
        .to_owned();
    Captured {
        line,
        body: request[header_end + 4..header_end + 4 + content_length].to_vec(),
    }
}

/// `unwrap_err` with the case name in the panic.
trait UnwrapErrOrPanic<T> {
    fn unwrap_err_or_panic(self, what: &str) -> neotales_docker::Error;
}

impl<T: std::fmt::Debug> UnwrapErrOrPanic<T> for Result<T, neotales_docker::Error> {
    fn unwrap_err_or_panic(self, what: &str) -> neotales_docker::Error {
        match self {
            Ok(value) => panic!("{what}: the write was accepted: {value:?}"),
            Err(error) => error,
        }
    }
}
