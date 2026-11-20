//! `DockerClient` plugin reads on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `list_plugins`,
//! `inspect_plugin`, and `plugin_privileges` must open their versioned Engine
//! paths through the owned transport when that transport can reach the endpoint,
//! rather than the unversioned paths the generated client sends. Asserting that
//! against a request builder would only show what the builder would produce if it
//! were called; the routing decision is above it. A loopback HTTP fixture is the
//! one place the request on the wire and the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from any of the three
//! reads puts the generated client back on the wire. The request line then loses
//! the version prefix, `inspect_plugin` stops percent-encoding the reference into
//! one path segment, the ordered filter map is replaced by Bollard's
//! `HashMap`-backed query, and a decode failure is reported as a Docker error
//! instead of a local refusal. The assertions below fail with it.
//!
//! The status tests are the other half: an owned read that fails must report the
//! daemon's status and message, and it must **not** retry on the generated client.
//! A silent second request would turn one failure into two and hide which
//! transport answered.
//!
//! # What is deliberately not asserted
//!
//! Nothing here claims anything about plugin writes. Enable, disable, remove,
//! set, create, install, upgrade, and push are not exercised: the read migration
//! does not change them, and `X-Registry-Auth` handling is owned by the install
//! and upgrade families.
//!
//! Every fixture-backed test reaches the public API through `connect_http`, so
//! none of them needs a running daemon and none touches `/var/run/docker.sock`.
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, PluginListOptions, PluginSummary,
};

#[path = "support/plugin_entries.rs"]
mod plugin_entries;

use plugin_entries::{
    CANARY, CONFIGLESS_PLUGIN_BODY, PLUGIN_DESCRIPTION, PLUGIN_ID, PLUGIN_NAME, PLUGIN_REFERENCE,
    PRIVILEGE_ARRAY, expected_privileges, expected_summary, plugin_array_body, plugin_body,
};

/// A request the fixture recorded: plugin reads send no body, so the request
/// line is the whole observation.
struct Captured {
    line: String,
}

/// The longest one fixture instance may run in total.
///
/// A per-read timeout alone is not a bound: a peer that trickles one byte per
/// timeout can keep an operation alive forever. Every read loop checks this
/// absolute deadline (and the stop flag), so the whole fixture is bounded.
const TOTAL_BOUND: Duration = Duration::from_secs(15);

/// The read-poll interval at which the deadline and stop flag are re-checked.
const IO_POLL: Duration = Duration::from_millis(250);

/// How long one answer write or the closing drain may take.
const WRITE_BOUND: Duration = Duration::from_secs(2);

/// A bounded one-request-at-a-time HTTP server that records each request.
struct Fixture {
    endpoint: String,
    requests: Receiver<Captured>,
    server: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
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
///
/// A second connection is the observable form of a fallback after a failed owned
/// request. The watch window exists because a client that retried would do so
/// immediately after the first answer; the first answer has already been read
/// when the window opens.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<String>,
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
            let head = read_request(&mut stream, &thread_stop, deadline).line;
            let _ = request_tx.send(head);
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
                        // Answer the retry so a broken client returns instead of
                        // leaving the test blocked on a socket read.
                        write_bounded(&mut retry_stream, &ok_json("{}"), &thread_stop, deadline)
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

    fn request_line(&self) -> String {
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

/// Reads a request head, giving up on stop or the operation deadline.
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
    Some(Captured {
        line: head.lines().next().unwrap_or_default().to_owned(),
    })
}

fn read_request(stream: &mut TcpStream, stop: &AtomicBool, deadline: Instant) -> Captured {
    read_request_or_empty(stream, stop, deadline).expect("the fixture read its request")
}

/// Writes an answer, failing the fixture thread rather than blocking forever.
fn write_bounded(
    stream: &mut TcpStream,
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

/// Bounds the next blocking read by both its short poll interval and the
/// remaining absolute operation/drain deadline.
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

fn rejected(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The version prefix the owned transport is expected to send.
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Asserts the error chain never carries `needle`.
fn assert_no_leak(error: &neotales_docker::Error, needle: &str) {
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    for rendering in &renderings {
        assert!(
            !rendering.contains(needle),
            "the error echoed the response text: {rendering}"
        );
    }
}

/// The owned list is versioned, and the five modelled members survive while the
/// unmodelled ones are dropped exactly as the generated path drops them.
#[tokio::test]
async fn list_plugins_sends_a_versioned_request_and_projects_the_summary() {
    let fixture = Fixture::start(vec![ok_json(&plugin_array_body())]);
    let plugins = fixture
        .client()
        .list_plugins(None)
        .await
        .expect("the plugin array decoded");

    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0], expected_summary());
    assert_eq!(
        plugins[1].name, "vieux/empty:latest",
        "the second plugin's name"
    );
    assert!(
        !plugins[1].enabled,
        "`Enabled: false` is installed but not running, not an unknown answer"
    );
    assert_eq!(plugins[1].id, None);
    assert_eq!(plugins[1].plugin_reference, None);
    assert_eq!(plugins[1].description, "");

    // The canary only exists in unmodelled members, so a projection that carried
    // them would be visible here rather than only in the wire bytes.
    let rendered = format!("{plugins:?}");
    assert!(
        !rendered.contains(CANARY),
        "the summary carried an unmodelled member: {rendered}"
    );

    assert_eq!(
        fixture.next().line,
        format!("GET {}/plugins HTTP/1.1", version_prefix()),
        "list_plugins fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The caller's ordered filter map is sent unchanged, in `BTreeMap` key order,
/// and an unknown filter key is forwarded rather than filtered here.
///
/// The Engine validates plugin filter keys; `raw/plugins.rs` records the
/// measured `400 invalid filter '<key>'` for an unknown one. Deciding that
/// client-side would answer a question the daemon owns and would hide a future
/// filter key this crate has not learned.
#[tokio::test]
async fn list_plugins_sends_the_caller_filters_unchanged() {
    let fixture = Fixture::start(vec![ok_json(&plugin_array_body())]);
    let mut filters = BTreeMap::new();
    filters.insert("capability".to_owned(), vec!["volumedriver".to_owned()]);
    filters.insert("enabled".to_owned(), vec!["true".to_owned()]);
    filters.insert("future".to_owned(), vec!["x".to_owned()]);

    let options = PluginListOptions { filters };
    let plugins = fixture
        .client()
        .list_plugins(Some(options))
        .await
        .expect("the filtered list decoded");
    assert_eq!(plugins[0], expected_summary());

    let expected_filters = r#"{"capability":["volumedriver"],"enabled":["true"],"future":["x"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/plugins?{} HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the owned list did not send the exact ordered filters"
    );

    fixture.finish();
}

/// An empty filter map is not sent at all, because an empty filter object is the
/// daemon's own no-filter case and would only make a recorded request noisier.
#[tokio::test]
async fn list_plugins_sends_no_empty_filter_map() {
    let fixture = Fixture::start(vec![
        ok_json(&plugin_array_body()),
        ok_json(&plugin_array_body()),
    ]);
    let client = fixture.client();

    client
        .list_plugins(None)
        .await
        .expect("the unfiltered list decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/plugins HTTP/1.1", version_prefix())
    );

    client
        .list_plugins(Some(PluginListOptions::default()))
        .await
        .expect("the empty-filter list decoded");
    assert_eq!(
        fixture.next().line,
        format!("GET {}/plugins HTTP/1.1", version_prefix()),
        "an empty filter map was serialized onto the wire"
    );

    fixture.finish();
}

/// The owned inspect percent-encodes the reference into exactly one path segment,
/// so a name containing `/` cannot address a different resource.
#[tokio::test]
async fn inspect_plugin_escapes_the_reference_and_projects_the_summary() {
    let fixture = Fixture::start(vec![ok_json(&plugin_body())]);
    let plugin = fixture
        .client()
        .inspect_plugin(PLUGIN_NAME)
        .await
        .expect("the plugin document decoded");

    assert_eq!(plugin, expected_summary());
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/plugins/vieux%2Fsshfs%3Alatest/json HTTP/1.1",
            version_prefix()
        ),
        "inspect_plugin fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The owned privileges read is a `GET` with the subject in the query, and the
/// Engine's `Value` member becomes the repository's `values`.
#[tokio::test]
async fn plugin_privileges_reads_the_engine_spelling() {
    let fixture = Fixture::start(vec![ok_json(PRIVILEGE_ARRAY)]);
    let privileges = fixture
        .client()
        .plugin_privileges(PLUGIN_NAME)
        .await
        .expect("the privilege array decoded");

    assert_eq!(privileges, expected_privileges());
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/plugins/privileges?remote=vieux%2Fsshfs%3Alatest HTTP/1.1",
            version_prefix()
        ),
        "plugin_privileges fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// The path prefix is the version the client was configured with, not a literal
/// compiled into the read.
#[tokio::test]
async fn the_owned_path_uses_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(&plugin_array_body())]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .list_plugins(None)
        .await
        .expect("the plugin array decoded");

    assert_eq!(
        fixture.next().line,
        "GET /v1.47/plugins HTTP/1.1",
        "the owned list did not use the configured version"
    );

    fixture.finish();
}

/// A daemon rejection keeps the status and the daemon's own message, and it does
/// not become a second request on the generated client.
#[tokio::test]
async fn a_daemon_rejection_keeps_its_status_and_message_without_a_retry() {
    let body = r#"{"message":"plugin \"ghost\" not found"}"#;
    let fixture = RejectingFixture::start("404 Not Found", body);
    let error = fixture
        .client()
        .inspect_plugin("ghost")
        .await
        .expect_err("the daemon rejected the inspect");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, r#"plugin "ghost" not found"#);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/plugins/ghost/json HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "the rejected read was sent again through the generated fallback"
    );

    fixture.finish();
}

/// A rejection whose body is not the Engine's JSON is reported by status alone,
/// and none of it is echoed into the error chain.
#[tokio::test]
async fn a_non_json_rejection_is_reported_by_status_without_echoing_it() {
    let body = format!("<html><body>{CANARY}</body></html>");
    let fixture = Fixture::start(vec![rejected("500 Internal Server Error", &body)]);
    let error = fixture
        .client()
        .list_plugins(None)
        .await
        .expect_err("the daemon rejected the list");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 500);
    assert_eq!(
        api.message,
        "daemon returned HTTP 500 Internal Server Error"
    );
    assert_no_leak(&error, CANARY);

    fixture.finish();
}

/// A successful status carrying a document the projection cannot read is a local
/// refusal, not a Docker error, and the response text is not quoted into it.
#[tokio::test]
async fn a_malformed_document_is_refused_without_echoing_it() {
    let list_body = format!(r#"[{{"Name":17,"Future":"{CANARY}"}}]"#);
    let inspect_body = format!(r#"{{"Name":"p","Enabled":"{CANARY}"}}"#);
    let fixture = Fixture::start(vec![ok_json(&list_body), ok_json(&inspect_body)]);
    let client = fixture.client();

    let list_error = client
        .list_plugins(None)
        .await
        .expect_err("a wrong-typed Name fails the list");
    assert_eq!(list_error.kind(), ErrorKind::InvalidInput);
    assert!(
        list_error.api_error().is_none(),
        "a local decode refusal has no API error"
    );
    assert!(
        list_error.to_string().contains("failed to decode"),
        "the decode refusal is not named: {list_error}"
    );
    assert_no_leak(&list_error, CANARY);

    let inspect_error = client
        .inspect_plugin("p")
        .await
        .expect_err("a wrong-typed Enabled fails the inspect");
    assert_eq!(inspect_error.kind(), ErrorKind::InvalidInput);
    assert_no_leak(&inspect_error, CANARY);

    fixture.finish();
}

/// A `null` `Config` is a plugin with no description, not a broken answer: the
/// owned decoder reads it as the empty block.
///
/// Bollard's `Plugin::config` is not optional, so this document is one only the
/// owned path can read; `tests/plugin_reads_fallback.rs` pins that the generated
/// path reports the same answer as a Docker error. It is the case where the two
/// paths' tolerance differs, and the difference is in the owned path's favour.
#[tokio::test]
async fn a_configless_plugin_reads_as_the_empty_block() {
    let fixture = Fixture::start(vec![ok_json(CONFIGLESS_PLUGIN_BODY)]);
    let plugin = fixture
        .client()
        .inspect_plugin("vieux/empty:latest")
        .await
        .expect("the configless plugin decoded");

    assert_eq!(plugin.name, "vieux/empty:latest");
    assert!(!plugin.enabled);
    assert_eq!(plugin.description, "");
    assert_eq!(plugin.id, None);
    assert_eq!(plugin.plugin_reference, None);
    assert_eq!(
        fixture.next().line,
        format!(
            "GET {}/plugins/vieux%2Fempty%3Alatest/json HTTP/1.1",
            version_prefix()
        )
    );

    fixture.finish();
}

/// An empty reference is refused before a connection is opened, so no request
/// can ask the daemon about a plugin the caller never named.
#[tokio::test]
async fn an_empty_reference_is_refused_before_the_socket() {
    // No responses: if either call opened a connection the fixture would block
    // on `accept` and `finish` would never join.
    let fixture = Fixture::start(Vec::new());
    let client = fixture.client();

    for error in [
        client.inspect_plugin("").await.expect_err("empty name"),
        client
            .plugin_privileges("")
            .await
            .expect_err("empty remote"),
        client
            .plugin_privileges("   ")
            .await
            .expect_err("blank remote"),
    ] {
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.api_error().is_none());
    }

    fixture.finish();
}

/// The projected value serializes as the five modelled members and nothing else,
/// which is the shape the generated fallback returns for the same document.
#[test]
fn the_summary_serializes_only_the_five_modelled_members() {
    let summary: PluginSummary = expected_summary();
    assert_eq!(
        serde_json::to_value(&summary).expect("a serializable summary"),
        serde_json::json!({
            "id": PLUGIN_ID,
            "name": PLUGIN_NAME,
            "enabled": true,
            "description": PLUGIN_DESCRIPTION,
            "plugin_reference": PLUGIN_REFERENCE,
        })
    );
}
