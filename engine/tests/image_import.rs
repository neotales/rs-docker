//! `DockerClient::{import_image, import_image_from_stream}` and their
//! credentialed variants on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: an import must open the
//! versioned `/v1.NN/images/create` path, encode the caller's options into that
//! request, send **no body** for a URL source (the daemon fetches it) and a
//! streamed TAR for `-`, and project the daemon's newline-delimited records
//! onto [`ImageStreamEvent`]. Asserting any of that against a request builder
//! would only show what the builder would produce if it were called; the
//! routing decision is above it. A loopback HTTP fixture is the only place
//! where the wire request, the stream, and the routing are the same
//! observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arms puts the generated
//! client back on the wire. The request line then loses the version prefix, so
//! the whole-line comparison fails.
//!
//! The stream tests are about what a `200` means. An import the daemon could
//! not satisfy is an **in-band** record, not a status, and the generated client
//! has always turned an `errorDetail` record into an `Err` item; the owned
//! projection must do the same, or a caller that only handles `Err` reports a
//! failed import as a successful one. The owned route additionally reads the
//! bare `error` string the daemon writes, which the generated create model has
//! no member for. A malformed record must be refused as one item and must not
//! end the stream, which is what lets a caller keep reading after a record this
//! client will not accept.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! writes one record and then reads; the only thing that ends that read is the
//! client releasing the response, which closes the socket.
//!
//! The retry test is the reason the fallback is a routing decision rather than
//! an error path: an import that has already been dispatched must never be
//! re-issued through the generated client, because the daemon may already have
//! fetched the source and created the image.
//!
//! Every test reaches the public API, and none needs a running daemon.

#![allow(missing_docs)]

use std::error::Error as _;
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream;
use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ImageImportOptions,
    ImageStreamEvent, ImageTransferError, ImageTransferLimits, RegistryCredentials, raw,
};

#[path = "support/build_wire.rs"]
mod wire;

use wire::{Recorded, read_request, records, rejected, version_prefix};

/// How long a fixture waits for the request it was started for.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

/// A record the stream can continue with after a refused or failed one.
///
/// `stream` is deliberately not used: the generated create model has no such
/// member, so the projection would be an empty event either way and the test
/// would stop saying which record was read.
const RECOVERY_RECORD: &str = r#"{"status":"after"}"#;

/// Records the owned create decoder must refuse, decoded from its original
/// bytes.
///
/// The known members are the generated `CreateImageInfo` model's — `id`,
/// `errorDetail` with `code`/`message`, `status`, and `progressDetail` with
/// `current`/`total` — plus the bare `error` this route reads. A duplicate known
/// member and a known member of the wrong JSON type are both refused; the last
/// entry is not an object at all.
const CREATE_MEMBER_REGRESSIONS: [&str; 10] = [
    r#"{"status":"one","status":"two"}"#,
    r#"{"id":"one","id":null}"#,
    r#"{"errorDetail":{"message":"failed","message":null}}"#,
    r#"{"errorDetail":{"message":"failed"},"errorDetail":null}"#,
    r#"{"errorDetail":{"code":"not-a-number","message":"failed"}}"#,
    r#"{"errorDetail":{"code":null,"code":1}}"#,
    r#"{"progressDetail":{"current":null,"current":1}}"#,
    r#"{"progressDetail":{"total":1,"total":2}}"#,
    r#"{"error":"first","error":null}"#,
    r#"{"id":5}"#,
];

/// One archive chunk per stream item, so a body that is collected whole before
/// the request is not distinguishable from one that is streamed.
fn archive() -> impl futures_core::Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + 'static {
    stream::iter([Ok(b"first-chunk".to_vec()), Ok(b"second-chunk".to_vec())])
}

/// A fixture that answers a fixed sequence of requests and records each one.
struct Fixture {
    endpoint: String,
    requests: mpsc::Receiver<Recorded>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (sender, requests) = mpsc::channel();
        let server = thread::spawn(move || {
            for response in responses {
                let (stream, _) = listener.accept().expect("accept the request");
                let mut reader = BufReader::new(stream);
                let request = read_request(&mut reader);
                if sender.send(request).is_err() {
                    return;
                }
                reader
                    .get_mut()
                    .write_all(&response)
                    .expect("write the fixture answer");
                reader.get_mut().flush().expect("flush the fixture answer");
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

    fn request(&self) -> Recorded {
        self.requests
            .recv_timeout(FIXTURE_TIMEOUT)
            .expect("the fixture recorded no request")
    }

    fn finish(self) {
        self.server.join().expect("the fixture thread");
    }
}

/// Builds a client whose declared API version is `minor`.
///
/// The endpoint is loopback-only; a test that expects a refusal points it at a
/// closed port so an attempted request would be a transport error instead.
fn client_at(endpoint: &str, minor: usize) -> DockerClient {
    DockerClient::connect_endpoint_with_version(
        &Endpoint::Http(endpoint.to_owned()),
        ApiVersion { major: 1, minor },
    )
    .expect("a client at the requested API version")
}

/// Serves one connection, handing the request to the test and the open stream
/// to a closure that writes the answer.
fn serve_once<F>(handler: F) -> (String, mpsc::Receiver<Recorded>, JoinHandle<()>)
where
    F: FnOnce(&mut BufReader<TcpStream>) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (sender, requests) = mpsc::channel();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the request");
        let mut reader = BufReader::new(stream);
        let request = read_request(&mut reader);
        if sender.send(request).is_err() {
            return;
        }
        handler(&mut reader);
    });
    (format!("http://{address}"), requests, server)
}

/// The URL every wire test imports from.
const SOURCE: &str = "https://example.invalid/rootfs.tar";

/// The options every wire test uses: every supported member is non-default, so
/// a member that stops being passed through changes the request line.
fn every_option() -> ImageImportOptions {
    let mut options = ImageImportOptions::new(SOURCE)
        .with_repository("registry.example/team/app")
        .with_tag("v1")
        .with_platform("linux/arm/v7")
        .with_change("ENV A=1")
        .with_change(r#"CMD ["/app"]"#);
    options.message = Some("imported by the fixture".to_owned());
    options
}

/// A URL import is versioned, carries every caller option, and sends no body.
///
/// The daemon fetches `fromSrc` itself, so the request has `Content-Length: 0`,
/// no `Content-Type`, and no chunked framing. A body here would be a body the
/// daemon does not read, and a `Content-Type` would claim the empty body is an
/// archive.
#[tokio::test]
async fn import_sends_every_option_to_the_versioned_path_without_a_body() {
    let fixture = Fixture::start(vec![records(&[r#"{"status":"Imported"}"#])]);
    let client = fixture.client();
    let mut stream = client
        .import_image(every_option())
        .expect("valid import options");
    while let Some(event) = stream.next().await {
        event.expect("an import event, not an error");
    }

    let request = fixture.request();
    let target = request.target();
    assert!(
        target.starts_with(&format!("{}/images/create?", version_prefix())),
        "the owned transport must send the versioned path: {target}"
    );
    assert_eq!(request.query_value("fromSrc").as_deref(), Some(SOURCE));
    assert_eq!(
        request.query_value("repo").as_deref(),
        Some("registry.example/team/app")
    );
    assert_eq!(request.query_value("tag").as_deref(), Some("v1"));
    assert_eq!(
        request.query_value("message").as_deref(),
        Some("imported by the fixture")
    );
    assert_eq!(
        request.query_value("platform").as_deref(),
        Some("linux/arm/v7"),
        "an import platform is the shorthand, not the JSON OCI object a load carries: {target}"
    );
    assert_eq!(
        request.query_values("changes"),
        ["ENV A=1\nCMD [\"/app\"]".to_owned()],
        "changes is one newline-joined value, which BuildFromConfig joins back to the same list"
    );
    assert_eq!(
        request.header("content-length"),
        Some("0"),
        "a URL import carries no body"
    );
    assert_eq!(
        request.header("transfer-encoding"),
        None,
        "a body-less request is not chunked"
    );
    assert_eq!(
        request.header("content-type"),
        None,
        "the request has no archive to describe"
    );
    assert_eq!(
        request.header("x-registry-auth"),
        None,
        "an import without credentials sends no registry header"
    );
    assert!(request.body.is_empty(), "{:?}", request.body);
    fixture.finish();
}

/// A stream import is versioned, sets the archive type, and streams the body.
#[tokio::test]
async fn import_from_stream_streams_the_body_to_the_versioned_path() {
    let fixture = Fixture::start(vec![records(&[r#"{"status":"Imported"}"#])]);
    let client = fixture.client();
    let mut stream = client
        .import_image_from_stream(
            ImageImportOptions::new(SOURCE).with_platform("linux/amd64"),
            archive(),
            ImageTransferLimits::default(),
        )
        .expect("valid import options");
    while let Some(event) = stream.next().await {
        event.expect("an import event, not an error");
    }

    let request = fixture.request();
    let target = request.target();
    assert!(
        target.starts_with(&format!("{}/images/create?", version_prefix())),
        "the owned transport must send the versioned path: {target}"
    );
    assert_eq!(
        request.query_value("fromSrc").as_deref(),
        Some("-"),
        "the stream form reads the request body, even though the options named a URL"
    );
    assert!(
        !target.contains("example.invalid"),
        "a URL source must never reach the body-shaped request: {target}"
    );
    assert_eq!(
        request.query_value("platform").as_deref(),
        Some("linux/amd64")
    );
    assert_eq!(
        request.header("content-type"),
        Some("application/x-tar"),
        "the body is a TAR archive"
    );
    assert!(
        request
            .header("transfer-encoding")
            .is_some_and(|value| value.eq_ignore_ascii_case("chunked")),
        "the archive is streamed, not sent with a declared length"
    );
    assert_eq!(
        request.header("content-length"),
        None,
        "a streamed body has no length this client could declare"
    );
    assert_eq!(request.body.as_slice(), b"first-chunksecond-chunk");
    fixture.finish();
}

/// Every daemon record is projected onto the public event in daemon order.
#[tokio::test]
async fn import_projects_each_daemon_record() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"status":"Downloading from https://example.invalid/rootfs.tar"}"#,
        r#"{"status":"Importing","progressDetail":{"current":1,"total":2}}"#,
        r#"{"id":"sha256:deadbeef"}"#,
    ])]);
    let client = fixture.client();
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("valid import options");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event.expect("an import event, not an error"));
    }

    assert_eq!(events.len(), 3, "one event per daemon record");
    assert_eq!(
        events[0].status.as_deref(),
        Some("Downloading from https://example.invalid/rootfs.tar")
    );
    assert_eq!(events[1].status.as_deref(), Some("Importing"));
    assert_eq!(
        events[1].progress,
        Some(neotales_docker::ImageProgress {
            current: Some(1),
            total: Some(2)
        })
    );
    assert_eq!(events[2].id.as_deref(), Some("sha256:deadbeef"));
    assert!(
        events.iter().all(|event| event.stream.is_none()),
        "the generated create model has no `stream` member, so the owned route must not invent one"
    );
    assert!(
        events.iter().all(|event| event.error.is_none()),
        "an in-band failure is an Err item, never a success with an error field"
    );
    fixture.finish();
}

/// Both in-band failure spellings are `Err` items, and the stream continues.
#[tokio::test]
async fn import_reports_in_band_errors_as_stream_errors() {
    let measured = "failed to import image: archive is corrupt";
    let bare = format!(r#"{{"error":"{measured}"}}"#);
    let body = records(&[
        r#"{"status":"Importing"}"#,
        bare.as_str(),
        r#"{"errorDetail":{"message":"the archive was corrupt"},"error":"the archive was corrupt"}"#,
        r#"{"error":"","errorDetail":{"message":"an empty bare error must not mask this"}}"#,
        RECOVERY_RECORD,
    ]);
    let fixture = Fixture::start(vec![body]);
    let client = fixture.client();
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("valid import options");

    let event = stream
        .next()
        .await
        .expect("the first record")
        .expect("an import event, not an error");
    assert_eq!(event.status.as_deref(), Some("Importing"));

    let error = stream
        .next()
        .await
        .expect("the bare error is an item")
        .expect_err("a `200` carrying an error record is a failed import");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(error.to_string(), "Docker client error");
    let source = error.source().expect("the daemon failure has a source");
    assert_eq!(
        source.to_string(),
        format!("Docker stream error: {measured}")
    );

    let error = stream
        .next()
        .await
        .expect("the errorDetail record is an item")
        .expect_err("an errorDetail record is a failed import");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(message.contains("the archive was corrupt"), "{message}");

    let error = stream
        .next()
        .await
        .expect("the empty bare error plus errorDetail is an item")
        .expect_err("an empty bare error must not hide the errorDetail");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(
        message.contains("an empty bare error must not mask this"),
        "{message}"
    );

    let event = stream
        .next()
        .await
        .expect("the stream continues after an in-band failure")
        .expect("an import event, not an error");
    assert_eq!(event.status.as_deref(), Some("after"));
    assert!(stream.next().await.is_none());
    fixture.finish();
}

/// Duplicate known members are refused from the original bytes, and the stream
/// continues after each refusal.
#[tokio::test]
async fn import_rejects_duplicate_and_malformed_known_members() {
    for record in CREATE_MEMBER_REGRESSIONS {
        let fixture = Fixture::start(vec![records(&[record, RECOVERY_RECORD])]);
        let client = fixture.client();
        let mut stream = client
            .import_image(ImageImportOptions::new(SOURCE))
            .expect("valid import options");
        let error = stream
            .next()
            .await
            .expect("the malformed record is an item")
            .expect_err("a duplicate or wrong-typed known member is refused");
        assert_eq!(error.kind(), ErrorKind::Serialization, "{record}");
        let message = error
            .source()
            .map_or_else(|| error.to_string(), ToString::to_string);
        assert!(
            message.contains("invalid daemon create record"),
            "{record}: {message}"
        );

        let event = stream
            .next()
            .await
            .expect("the next record is still readable")
            .expect("an import event, not an error");
        assert_eq!(
            event.status.as_deref(),
            Some("after"),
            "{record}: the stream must recover after a refused record"
        );
        assert!(stream.next().await.is_none());
        fixture.finish();
    }
}

/// Dropping or cancelling the handle closes the connection.
#[tokio::test]
async fn import_cancels_the_transfer_when_the_handle_is_released() {
    #[derive(Clone, Copy, Debug)]
    enum Release {
        Drop,
        Cancel,
    }

    for release in [Release::Drop, Release::Cancel] {
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<bool>();
        let (endpoint, _requests, server) = serve_once(move |reader| {
            let stream = reader.get_mut();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: application/json\r\n\
                      Transfer-Encoding: chunked\r\n\
                      \r\n",
                )
                .expect("write the response head");
            let record = b"{\"status\":\"Importing\"}\n";
            write!(stream, "{:X}\r\n", record.len()).expect("write the chunk length");
            stream.write_all(record).expect("write the chunk");
            stream
                .write_all(b"\r\n")
                .expect("write the chunk terminator");
            stream.flush().expect("flush the record");

            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("set the fixture read timeout");
            let mut buffer = [0_u8; 64];
            let closed = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break true,
                    Ok(_) => {}
                    // A timeout is the only outcome that means the client kept
                    // the connection open. A reset is still the connection
                    // going away, which is what releasing the handle promises.
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
            let _ = closed_tx.send(closed);
        });

        let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
        let mut stream = client
            .import_image(ImageImportOptions::new(SOURCE))
            .expect("valid import options");
        let event = stream
            .next()
            .await
            .expect("the first record")
            .expect("an import event, not an error");
        assert_eq!(event.status.as_deref(), Some("Importing"), "{release:?}");

        match release {
            Release::Drop => drop(stream),
            Release::Cancel => stream.cancel(),
        }

        // Awaiting rather than blocking on a std channel is what lets the
        // runtime process the aborted connection driver.
        let closed = tokio::time::timeout(Duration::from_secs(10), closed_rx)
            .await
            .expect("the fixture did not observe the disconnect")
            .expect("the fixture reported");
        assert!(
            closed,
            "{release:?}: releasing the handle did not close the connection"
        );
        server.join().expect("the fixture thread");
    }
}

/// A dispatched import is never retried over the generated client.
#[tokio::test]
async fn import_is_not_retried_after_the_owned_request_is_dispatched() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let connections = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&connections);
    let (request_tx, requests) = mpsc::channel();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the first request");
        observed.fetch_add(1, Ordering::SeqCst);
        let mut reader = BufReader::new(stream);
        let request = read_request(&mut reader);
        let _ = request_tx.send(request);
        reader
            .get_mut()
            .write_all(&rejected(
                "500 Internal Server Error",
                r#"{"message":"import refused"}"#,
            ))
            .expect("write the rejection");
        reader.get_mut().flush().expect("flush the rejection");
        let _ = reader.get_mut().shutdown(Shutdown::Both);

        // A retry would arrive immediately. Poll for a short window so a second
        // connection is counted rather than merely missed.
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut retry, _)) => {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let _ = retry.write_all(&rejected(
                        "500 Internal Server Error",
                        r#"{"message":"import refused"}"#,
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("valid import options");
    let error = stream
        .next()
        .await
        .expect("a rejection is one stream item")
        .expect_err("the daemon rejected the import");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's status and message");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, "import refused");
    assert!(
        stream.next().await.is_none(),
        "the stream must end after the rejection"
    );

    let request = requests
        .recv_timeout(FIXTURE_TIMEOUT)
        .expect("the fixture recorded no request");
    assert!(
        request
            .target()
            .starts_with(&format!("{}/images/create?", version_prefix())),
        "the first request is the owned one: {}",
        request.target()
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the import was dispatched again after it failed"
    );
    server.join().expect("the fixture thread");
}

/// The owned handle opens no connection until it is first polled.
#[tokio::test]
async fn import_is_lazy_until_the_first_poll() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("valid import options");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "creating a handle must not dispatch the request: {accepted:?}"
    );
    drop(stream);
}

/// A platform import on a client built for API 1.31 is refused before
/// connecting.
///
/// Moby's `postImagesCreate` gates the parameter on
/// `versions.GreaterThanOrEqualTo(…, "1.32")` and otherwise ignores it,
/// importing for the host platform. Refusing here is what stops that silent
/// wrong answer. The endpoint has no listener, so an attempted request would be
/// `ErrorKind::Transport`.
#[tokio::test]
async fn import_refuses_a_platform_below_api_1_32_without_connecting() {
    let client = client_at("http://127.0.0.1:1", 31);
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .import_image(ImageImportOptions::new(SOURCE).with_platform("linux/amd64"))
        .expect_err("1.31 ignores the platform");
    assert!(
        matches!(
            error,
            ImageTransferError::InvalidOption {
                name: "platform",
                ..
            }
        ),
        "the refusal did not name the platform option: {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("1.32") && message.contains("1.31"),
        "the refusal did not name both the required and the built-for version: {message}"
    );
}

/// API 1.32 is the exact version that reads the parameter, so it is allowed and
/// the path carries that version.
#[tokio::test]
async fn import_sends_a_platform_at_exactly_api_1_32() {
    let fixture = Fixture::start(vec![records(&[r#"{"status":"Imported"}"#])]);
    let client = client_at(&fixture.endpoint, 32);
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE).with_platform("linux/amd64"))
        .expect("1.32 reads the platform");
    while let Some(event) = stream.next().await {
        event.expect("an import event, not an error");
    }

    let target = fixture.request().target().to_owned();
    assert!(
        target.starts_with("/v1.32/images/create?"),
        "the exact boundary version did not send the owned platform request: {target}"
    );
    fixture.finish();
}

/// The boundary only gates the platform: an import without one still works at
/// 1.31.
#[tokio::test]
async fn import_without_a_platform_works_below_api_1_32() {
    let fixture = Fixture::start(vec![records(&[r#"{"status":"Imported"}"#])]);
    let client = client_at(&fixture.endpoint, 31);
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("an import without a platform is valid at every version");
    while let Some(event) = stream.next().await {
        event.expect("an import event, not an error");
    }

    let target = fixture.request().target().to_owned();
    assert!(
        target.starts_with("/v1.31/images/create?") && !target.contains("platform="),
        "the version guard changed an import that asked for no platform: {target}"
    );
    fixture.finish();
}

/// The raw URL builder refuses a platform below API 1.32 before it opens a
/// connection, so a caller using `raw::import_from_url` gets the same guard.
#[tokio::test]
async fn raw_import_from_url_refuses_a_platform_below_api_1_32_without_connecting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let engine = raw::RawEngine::new(
        raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        ApiVersion {
            major: 1,
            minor: 31,
        },
    );
    let error = raw::import_from_url(
        &engine,
        &ImageImportOptions::new(SOURCE).with_platform("linux/amd64"),
        raw::RegistryAuth::none(),
    )
    .await
    .expect_err("1.31 ignores the platform");
    assert!(error.to_string().contains("1.32"), "{error}");
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused platform must not open a connection: {accepted:?}"
    );
}

/// The raw URL builder refuses `-`, because that spelling reads a body this
/// request deliberately does not send.
#[tokio::test]
async fn raw_import_from_url_refuses_the_stream_source() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let engine = raw::RawEngine::new(
        raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        API_VERSION,
    );
    let error = raw::import_from_url(
        &engine,
        &ImageImportOptions::new("-"),
        raw::RegistryAuth::none(),
    )
    .await
    .expect_err("'-' has no body on this shape");
    assert!(error.to_string().contains("request body"), "{error}");
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused source must not open a connection: {accepted:?}"
    );
}

/// The raw body builder refuses a URL source before dispatch.
///
/// The daemon reads the request body only when `fromSrc` is `-`. A URL source
/// would make the daemon fetch that URL and ignore the supplied archive, which
/// is a different import than the one this function's body describes, so it is
/// refused before a request exists. The listener must see no connection.
#[tokio::test]
async fn raw_import_refuses_a_url_source_before_dispatching() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let engine = raw::RawEngine::new(
        raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        API_VERSION,
    );
    let body = stream::iter([Ok(Bytes::from_static(b"archive"))]);
    let error = raw::import(
        &engine,
        body,
        &ImageImportOptions::new(SOURCE),
        raw::RegistryAuth::none(),
    )
    .await
    .expect_err("a URL source would make the daemon ignore the supplied archive");
    let message = error.to_string();
    assert!(
        message.contains("request body") && message.contains("URL"),
        "{message}"
    );
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused source must not open a connection: {accepted:?}"
    );
}

/// The owned import stream refuses a record larger than its configured bound.
#[tokio::test]
async fn the_owned_import_stream_refuses_a_record_over_its_bound() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"status":"a record that is too long"}"#,
    ])]);
    let address: std::net::SocketAddr = fixture
        .endpoint
        .trim_start_matches("http://")
        .parse()
        .expect("the fixture address");
    let engine = raw::RawEngine::new(
        raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        API_VERSION,
    );
    let body = stream::iter(Vec::<Result<Bytes, std::io::Error>>::new());
    let mut frames = raw::import(
        &engine,
        body,
        &ImageImportOptions::new("-"),
        raw::RegistryAuth::none(),
    )
    .await
    .expect("the daemon accepted the import")
    .with_record_limit(32);
    let error = frames
        .next_json()
        .await
        .expect_err("a record over the bound is refused");
    assert!(
        error.to_string().contains("32-byte record limit"),
        "the refusal names the bound: {error}"
    );
    fixture.finish();
}

/// Invalid input is refused before either route opens a request.
#[tokio::test]
async fn import_refuses_invalid_input_before_opening_a_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let dash = ImageImportOptions::new("-");
    assert!(matches!(
        client.import_image(dash),
        Err(ImageTransferError::InvalidOption { name: "source", .. })
    ));

    let empty = ImageImportOptions::default();
    assert!(matches!(
        client.import_image(empty),
        Err(ImageTransferError::InvalidOption { name: "source", .. })
    ));

    let non_http = ImageImportOptions::new("ftp://example.invalid/rootfs.tar");
    assert!(matches!(
        client.import_image(non_http),
        Err(ImageTransferError::InvalidOption { name: "source", .. })
    ));

    let invalid_platform = ImageImportOptions::new(SOURCE).with_platform("linux//amd64");
    assert!(matches!(
        client.import_image(invalid_platform),
        Err(ImageTransferError::InvalidOption {
            name: "platform",
            ..
        })
    ));

    let invalid_change = ImageImportOptions::new(SOURCE).with_change("");
    assert!(matches!(
        client.import_image(invalid_change),
        Err(ImageTransferError::InvalidOption { name: "change", .. })
    ));

    let mut invalid_message = ImageImportOptions::new(SOURCE);
    invalid_message.message = Some(String::new());
    assert!(matches!(
        client.import_image(invalid_message),
        Err(ImageTransferError::InvalidOption {
            name: "message",
            ..
        })
    ));

    let zero_limit = ImageTransferLimits {
        max_stream_bytes: 0,
        ..ImageTransferLimits::default()
    };
    assert!(matches!(
        client.import_image_from_stream(ImageImportOptions::new(SOURCE), archive(), zero_limit),
        Err(ImageTransferError::InvalidLimits(_))
    ));

    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused import must not open a connection: {accepted:?}"
    );
}

/// A credential addressed to another registry is refused before connecting.
#[tokio::test]
async fn import_refuses_a_credential_for_a_different_registry() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let error = client
        .import_image_with_credentials_for_registry(
            ImageImportOptions::new(SOURCE),
            "ghcr.io",
            RegistryCredentials::new("probeuser", "synthetic-secret")
                .with_server_address("example.invalid"),
        )
        .expect_err("a credential addressed to example.invalid cannot be sent to ghcr.io");
    assert!(
        matches!(error, ImageTransferError::Credentials(_)),
        "{error:?}"
    );
    let rendered = format!("{error} {error:?}");
    assert!(
        !rendered.contains("synthetic-secret"),
        "the refusal must not render the credential: {rendered}"
    );
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused credential must not open a connection: {accepted:?}"
    );
}

/// A successful import event is the public type, and it is `Default`-shaped
/// when the record carried only unknown members.
#[tokio::test]
async fn import_projects_an_unknown_only_record_to_the_default_event() {
    let fixture = Fixture::start(vec![records(&[r#"{"aux":{"ID":"sha256:ignored"}}"#])]);
    let client = fixture.client();
    let mut stream = client
        .import_image(ImageImportOptions::new(SOURCE))
        .expect("valid import options");
    let event = stream
        .next()
        .await
        .expect("the record is an item")
        .expect("an unknown member is not a failure");
    assert_eq!(event, ImageStreamEvent::default());
    assert!(stream.next().await.is_none());
    fixture.finish();
}
