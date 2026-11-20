//! `DockerClient::list_configs` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `list_configs` must open
//! `GET /v1.NN/configs` through the owned transport when that transport can
//! reach the endpoint, rather than the unversioned path the generated client
//! sends. Asserting that against a request builder would only show what the
//! builder would produce if it were called; the routing decision is above it.
//! A loopback HTTP fixture is the only place the wire request and the routing
//! are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `list_configs`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, and the unmodelled members below are discarded by Bollard's
//! 1.53 models instead of being retained in `SwarmConfig::additional`. The
//! projection assertions fail with it.
//!
//! The rejection tests pin two contracts: a daemon rejection keeps its status
//! and message in [`Error::api_error`], and a failed owned request is returned
//! rather than retried over the generated client. The version-rejection case is
//! the one a daemon older than the configured API version sends, and it must
//! not be mistaken for a reason to fall back. The cancellation test pins that
//! abandoning the future releases the connection and is not a retry.
//!
//! Config data may be sensitive. The fixtures carry a synthetic canary, and the
//! decode tests assert it appears in no `Display`, `Debug`, or source-chain
//! rendering of the failure.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

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
    API_VERSION, ApiVersion, ConfigListOptions, DockerClient, Endpoint, ErrorKind,
};

#[path = "support/swarm_config_list_entries.rs"]
mod swarm_config_list_entries;

use swarm_config_list_entries::{
    CONFIG_DATA_BASE64, CONFIG_DATA_CANARY, CONFIG_ID, EMPTY_BODY, EMPTY_LIST_BODY, MALFORMED_BODY,
    NULL_BODY, NULL_ENTRY_BODY, VERSION_INDEX, WRONG_TYPE_BODY, list_body,
};

/// A one-request-at-a-time HTTP server that records each request head and then
/// waits for the client to release the connection.
///
/// The server closes every response with `Connection: close` so the client
/// cannot reuse the connection for the next call. Waiting for the client to
/// disconnect is what makes `finish` a statement about the client having
/// completed, rather than about the fixture having written bytes.
struct Fixture {
    endpoint: String,
    requests: Receiver<String>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept the request");
                let head = read_request_head(&mut stream);
                let _ = request_tx.send(head);
                stream
                    .write_all(&response)
                    .expect("write the fixture answer");
                stream.flush().expect("flush the fixture answer");
                release(&mut stream);
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

    fn request_line(&self) -> String {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A server that rejects one request and then watches for a retry.
///
/// A second connection is the observable form of a fallback after a failed
/// owned request. The watch window exists because a client that retried would
/// do so immediately after the first answer; the first answer has already been
/// read when the window opens.
struct RejectingFixture {
    endpoint: String,
    first_request: Receiver<String>,
    retry: Receiver<()>,
    server: JoinHandle<()>,
}

impl RejectingFixture {
    fn start(status: &str, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, first_request) = mpsc::channel();
        let (retry_tx, retry) = mpsc::channel();
        let response = rejected(status, body);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let head = read_request_head(&mut stream);
            let _ = request_tx.send(head);
            stream
                .write_all(&response)
                .expect("write the fixture answer");
            stream.flush().expect("flush the fixture answer");
            release(&mut stream);

            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request_head(&mut retry_stream);
                        let _ = retry_tx.send(());
                        // Answer the retry so a broken client returns instead of
                        // leaving the test blocked on a socket read.
                        let _ = retry_stream.write_all(&ok_json(&list_body()));
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
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request_line(&self) -> String {
        self.first_request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
    }

    fn saw_retry(&self) -> bool {
        match self.retry.recv_timeout(Duration::from_millis(500)) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// A fixture that never answers, so the client's request stays pending.
///
/// It reports the request, whether the connection was released, and whether a
/// second connection arrived. A retry is observable as that second connection,
/// because a client that fell back would open it immediately after abandoning
/// the first.
struct UnansweredFixture {
    endpoint: String,
    request: tokio::sync::oneshot::Receiver<String>,
    released: tokio::sync::oneshot::Receiver<bool>,
    retry: tokio::sync::oneshot::Receiver<()>,
    server: JoinHandle<()>,
}

impl UnansweredFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = tokio::sync::oneshot::channel();
        let (released_tx, released) = tokio::sync::oneshot::channel();
        let (retry_tx, retry) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let head = read_request_head(&mut stream);
            let _ = request_tx.send(head);

            // The daemon never answers. The only thing that ends this read is
            // the client releasing the connection.
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set the fixture read timeout");
            let mut buffer = [0_u8; 64];
            let released = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break true,
                    Ok(_) => {}
                    // A timeout is the only outcome that means the client kept
                    // the connection open. A reset is still the connection going
                    // away, which is what abandoning the request promises.
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break false;
                    }
                    Err(_) => break true,
                }
            };
            let _ = released_tx.send(released);

            listener
                .set_nonblocking(true)
                .expect("make the fixture listener nonblocking");
            let deadline = Instant::now() + Duration::from_millis(300);
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry_stream, _)) => {
                        let _ = read_request_head(&mut retry_stream);
                        let _ = retry_tx.send(());
                        // Answer the retry so a broken client returns instead of
                        // leaving the test blocked on a socket read.
                        let _ = retry_stream.write_all(&ok_json(&list_body()));
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
            request,
            released,
            retry,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }
}

/// Reads the request head, which is all a config list request sends.
fn read_request_head(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read the request");
        assert_ne!(read, 0, "the request ended before its headers");
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            request.truncate(end);
            return String::from_utf8_lossy(&request).into_owned();
        }
    }
}

/// Waits for the client to release the connection, so the next `accept` is the
/// next operation rather than a retry.
fn release(stream: &mut TcpStream) {
    let mut buffer = [0_u8; 64];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// A `200` answer carrying `body`, and a header that stops connection reuse.
fn ok_json(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A JSON rejection with an explicit status.
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

/// The owned list is versioned and retains members Bollard's 1.53 models drop.
#[tokio::test]
async fn list_configs_sends_a_versioned_request_and_retains_unmodelled_members() {
    let fixture = Fixture::start(vec![ok_json(&list_body())]);
    let configs = fixture
        .client()
        .list_configs(None)
        .await
        .expect("the config array decoded");

    assert_eq!(configs.len(), 1);
    let config = &configs[0];
    assert_eq!(config.id.as_deref(), Some(CONFIG_ID));
    assert_eq!(
        config.version.as_ref().and_then(|version| version.index),
        Some(VERSION_INDEX)
    );
    assert_eq!(
        config.created_at.as_deref(),
        Some("2026-09-01T10:00:00.000000000Z"),
        "the owned path did not retain the daemon's timestamp text"
    );
    let spec = config.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("app-config"));
    assert_eq!(
        spec.labels
            .as_ref()
            .and_then(|labels| labels.get("org.example.config"))
            .map(String::as_str),
        Some("fixture")
    );
    assert_eq!(
        spec.data.as_deref(),
        Some(CONFIG_DATA_BASE64),
        "the synthetic list data member was discarded"
    );
    assert_eq!(
        config.additional.get("UnmodelledMember"),
        Some(&serde_json::json!({"Value": 7})),
        "the owned path discarded an unmodelled top-level config member"
    );
    assert_eq!(
        spec.additional.get("UnmodelledSpecMember"),
        Some(&serde_json::json!({"Nested": true})),
        "the owned path discarded an unmodelled spec member"
    );
    assert_eq!(
        spec.additional.get("Templating"),
        Some(&serde_json::json!({
            "Name": "template-driver",
            "Options": {"org.example.option": "fixture"},
            "UnmodelledTemplatingMember": true
        })),
        "the owned path discarded the whole templating member"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs HTTP/1.1", version_prefix()),
        "list_configs fell back to the unversioned generated path"
    );

    fixture.finish();
}

/// An empty filter map is not sent on either input spelling, and a populated
/// one is sent in `BTreeMap` key order with the caller's value order preserved.
#[tokio::test]
async fn list_configs_sends_no_empty_filters_and_exact_ordered_filters() {
    let fixture = Fixture::start(vec![
        ok_json(&list_body()),
        ok_json(&list_body()),
        ok_json(&list_body()),
    ]);
    let client = fixture.client();

    client
        .list_configs(None)
        .await
        .expect("the unfiltered list decoded");
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs HTTP/1.1", version_prefix())
    );

    client
        .list_configs(Some(ConfigListOptions::default()))
        .await
        .expect("the empty filter map list decoded");
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs HTTP/1.1", version_prefix()),
        "an empty filter map was sent as a query value"
    );

    let mut filters = BTreeMap::new();
    filters.insert(
        "label".to_owned(),
        vec!["org.example.config=fixture".to_owned()],
    );
    filters.insert("name".to_owned(), vec!["app-config".to_owned()]);
    filters.insert(
        "id".to_owned(),
        vec!["config-id-one".to_owned(), "config-id-two".to_owned()],
    );
    client
        .list_configs(Some(ConfigListOptions { filters }))
        .await
        .expect("the filtered list decoded");

    let expected_filters = r#"{"id":["config-id-one","config-id-two"],"label":["org.example.config=fixture"],"name":["app-config"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/configs?{} HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the owned list did not send the exact ordered filters"
    );

    fixture.finish();
}

/// An unknown filter name is forwarded unchanged, and the daemon's `400` is
/// returned without a retry.
///
/// Docker Engine validates the filter names the config-list endpoint
/// implements. The facade must not drop or rewrite a name, and it must not
/// turn the rejection into an empty list or a generated fallback.
#[tokio::test]
async fn list_configs_forwards_an_unknown_filter_name_and_does_not_retry() {
    let message = "Invalid filter 'unknown'";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let mut filters = BTreeMap::new();
    filters.insert("unknown".to_owned(), vec!["value".to_owned()]);
    let error = fixture
        .client()
        .list_configs(Some(ConfigListOptions { filters }))
        .await
        .expect_err("an unknown filter name is the daemon's rejection");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);

    let expected_filters = r#"{"unknown":["value"]}"#;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filters", expected_filters);
    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/configs?{} HTTP/1.1",
            version_prefix(),
            query.finish()
        ),
        "the unknown filter name was not forwarded unchanged"
    );
    assert!(
        !fixture.saw_retry(),
        "the daemon's filter rejection was retried through the generated client"
    );

    fixture.finish();
}

/// The owned list uses the configured version, not the crate's default.
#[tokio::test]
async fn list_configs_sends_the_configured_version() {
    let fixture = Fixture::start(vec![ok_json(&list_body())]);
    let client = DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(fixture.endpoint.clone()),
        ApiVersion {
            major: 1,
            minor: 47,
        },
    )
    .expect("build a client at 1.47");

    client
        .list_configs(None)
        .await
        .expect("the config array decoded");

    assert_eq!(
        fixture.request_line(),
        "GET /v1.47/configs HTTP/1.1",
        "the owned list did not use the configured version"
    );

    fixture.finish();
}

/// An empty array is an empty list, not a decode failure.
#[tokio::test]
async fn list_configs_accepts_an_empty_array() {
    let fixture = Fixture::start(vec![ok_json(EMPTY_LIST_BODY)]);
    let configs = fixture
        .client()
        .list_configs(None)
        .await
        .expect("an empty config array decoded");
    assert!(configs.is_empty(), "expected configs to be empty");
    let _ = fixture.request_line();
    fixture.finish();
}

/// A success body the owned decoder cannot read is a decode failure in its own
/// error class. The fallback suite sends the same bodies through the generated
/// client, where the same failure is `ErrorKind::Docker`.
#[tokio::test]
async fn list_configs_rejects_empty_null_and_malformed_documents() {
    for body in [
        EMPTY_BODY,
        NULL_BODY,
        NULL_ENTRY_BODY,
        MALFORMED_BODY,
        WRONG_TYPE_BODY,
    ] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .list_configs(None)
            .await
            .expect_err("a body that is not a config array is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body:?}");
        assert!(
            error.to_string().contains("failed to decode"),
            "the refusal did not name the decode: {error}"
        );
        fixture.finish();
    }
}

/// Config data may be sensitive, so a decode failure must not echo response
/// text through `Display`, `Debug`, or the source chain. The fixtures place the
/// canary in the document and in the wrongly typed value serde would quote.
#[tokio::test]
async fn list_configs_decode_errors_do_not_echo_config_data_canaries() {
    for body in [MALFORMED_BODY, WRONG_TYPE_BODY, NULL_ENTRY_BODY] {
        let fixture = Fixture::start(vec![ok_json(body)]);
        let error = fixture
            .client()
            .list_configs(None)
            .await
            .expect_err("a malformed config array is refused");

        let mut renderings = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            renderings.push(cause.to_string());
            renderings.push(format!("{cause:?}"));
            source = cause.source();
        }
        for (index, rendering) in renderings.iter().enumerate() {
            for canary in [CONFIG_DATA_CANARY, CONFIG_DATA_BASE64] {
                assert!(
                    !rendering.contains(canary),
                    "decode error rendering {index} echoed config data: {rendering}"
                );
            }
        }

        fixture.finish();
    }
}

/// A daemon rejection keeps its status and message, and a failed owned request
/// is not retried over the generated client.
#[tokio::test]
async fn list_configs_reports_a_rejection_and_does_not_retry() {
    let message = "config list failure";
    let fixture = RejectingFixture::start(
        "500 Internal Server Error",
        &format!(r#"{{"message":"{message}"}}"#),
    );

    let error = fixture
        .client()
        .list_configs(None)
        .await
        .expect_err("a 500 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );
    assert!(
        !fixture.saw_retry(),
        "a failed owned list_configs request was retried through the generated client"
    );

    fixture.finish();
}

/// An older daemon's "client version too new" rejection is the daemon's answer,
/// not a reason to fall back, and it is not retried.
#[tokio::test]
async fn list_configs_reports_an_old_daemon_version_rejection_and_does_not_retry() {
    let message = "client version 1.55 is too new. Maximum supported API version is 1.41";
    let fixture =
        RejectingFixture::start("400 Bad Request", &format!(r#"{{"message":"{message}"}}"#));

    let error = fixture
        .client()
        .list_configs(None)
        .await
        .expect_err("a 400 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/configs HTTP/1.1", version_prefix())
    );
    assert!(
        !fixture.saw_retry(),
        "an old-daemon rejection was retried through the generated client"
    );

    fixture.finish();
}

/// Abandoning the request releases the connection and is not a retry.
///
/// The daemon never answers, so the fixture's read can only end when the client
/// releases the connection. It then watches for a second connection, which is
/// what a fallback after the abandoned request would look like.
#[tokio::test]
async fn list_configs_releases_the_connection_when_the_caller_abandons_it() {
    let fixture = UnansweredFixture::start();
    let client = fixture.client();
    let task = tokio::spawn(async move { client.list_configs(None).await });

    let request = tokio::time::timeout(Duration::from_secs(10), fixture.request)
        .await
        .expect("the fixture saw no request")
        .expect("the fixture reported");
    assert_eq!(
        request
            .lines()
            .next()
            .expect("the request has a request line"),
        format!("GET {}/configs HTTP/1.1", version_prefix()),
        "the abandoned request must be the owned one"
    );

    task.abort();
    let released = tokio::time::timeout(Duration::from_secs(10), fixture.released)
        .await
        .expect("the fixture did not observe the disconnect")
        .expect("the fixture reported");
    assert!(
        released,
        "abandoning the list future did not release the connection"
    );

    let retried = matches!(
        tokio::time::timeout(Duration::from_millis(500), fixture.retry).await,
        Ok(Ok(()))
    );
    assert!(
        !retried,
        "an abandoned owned list request was retried through the generated client"
    );

    fixture.server.join().expect("the fixture thread");
}
