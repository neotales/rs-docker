//! `DockerClient::{load_image, load_image_with_credentials}` on the
//! repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: a load must open the
//! versioned `/v1.NN/images/load` path, encode the caller's options into that
//! request, stream the caller's archive as the body, and project the daemon's
//! newline-delimited records onto [`ImageLoadEvent`]. Asserting any of that
//! against a request builder would only show what the builder would produce if
//! it were called; the routing decision is above it. A loopback HTTP fixture is
//! the only place where the wire request, the stream, and the routing are the
//! same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `load_image`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix, so the whole-line comparison fails.
//!
//! The stream tests are about what a `200` means. A load the daemon could not
//! satisfy is an **in-band** record, not a status, and the generated client has
//! always turned an `errorDetail` record into an `Err` item; the owned
//! projection must do the same, or a caller that only handles `Err` reports a
//! failed load as a successful one. The owned route additionally reads the bare
//! `error` string the daemon writes, which the generated load model has no
//! member for. A malformed record must be refused as one item and must not end
//! the stream, which is what lets a caller keep reading after a record this
//! client will not accept.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! writes one record and then reads; the only thing that ends that read is the
//! client releasing the response, which closes the socket.
//!
//! The retry test is the reason the fallback is a routing decision rather than
//! an error path: a load that has already been dispatched must never be
//! re-issued through the generated client, because the caller's archive stream
//! has been consumed by the attempt and cannot be sent again.
//!
//! Every test reaches the public API, and none needs a running daemon.

#![allow(missing_docs)]

use std::collections::BTreeMap;
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
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ImageLoadOptions,
    ImageTransferError, ImageTransferLimits, RegistryCredentials, raw,
};

#[path = "support/build_wire.rs"]
mod wire;

use wire::{RECOVERY_RECORD, Recorded, read_request, records, rejected, version_prefix};

/// How long a fixture waits for the request it was started for.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

/// Records the owned load decoder must refuse, decoded from its original bytes.
///
/// The known members are the generated load model's plus the bare `error`
/// string the daemon writes. `aux` and its nested `ID` are the generated
/// model's members too: the load event has no field for them, but the generated
/// decoder validates them, so the owned decoder must reject the same records or
/// the two routes disagree about what a malformed load record is.
const LOAD_MEMBER_REGRESSIONS: [&str; 11] = [
    r#"{"stream":"one\n","stream":"two\n"}"#,
    r#"{"errorDetail":{"message":"the archive was corrupt","message":null}}"#,
    r#"{"errorDetail":{"message":"the archive was corrupt"},"errorDetail":null}"#,
    r#"{"errorDetail":{"code":"not-a-number","message":"the archive was corrupt"}}"#,
    r#"{"progressDetail":{"current":null,"current":1}}"#,
    r#"{"progressDetail":{"total":1,"total":2}}"#,
    r#"{"error":"first","error":null}"#,
    r#"{"errorDetail":{"code":null,"code":1}}"#,
    r#"{"aux":{"ID":"sha256:one","ID":null}}"#,
    r#"{"aux":{"ID":5}}"#,
    r#"{"aux":"not-an-object"}"#,
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

/// Decodes every `platform` value in a request target, in request order.
///
/// The Engine's parameter is a JSON-encoded OCI platform object, so a test that
/// compared the shorthand string would pass against a request the daemon
/// refuses.
fn request_platforms(target: &str) -> Vec<serde_json::Value> {
    let query = target.split_once('?').map_or("", |(_, query)| query);
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key.as_ref() == "platform")
        .map(|(_, value)| serde_json::from_str(&value).expect("the platform parameter is JSON"))
        .collect()
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

/// The options every wire test uses: every supported member is non-default, so
/// a member that stops being passed through changes the request line.
fn every_option() -> ImageLoadOptions {
    ImageLoadOptions::new()
        .with_quiet(true)
        .with_platform("linux/arm/v7")
}

/// The owned request is versioned, carries every caller option, and streams the
/// caller's archive as a chunked body.
#[tokio::test]
async fn load_sends_every_option_to_the_versioned_path() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"Loaded image: alpine:3.20\n"}"#,
    ])]);
    let client = fixture.client();
    let mut stream = client
        .load_image(
            archive(),
            Some(every_option()),
            ImageTransferLimits::default(),
        )
        .expect("valid load options");
    while let Some(event) = stream.next().await {
        event.expect("a load event, not an error");
    }

    let request = fixture.request();
    let target = request.target();
    assert!(
        target.starts_with(&format!("{}/images/load?", version_prefix())),
        "the owned transport must send the versioned path: {target}"
    );
    assert_eq!(request.query_value("quiet").as_deref(), Some("true"));
    assert_eq!(
        request.query_values("platform"),
        [r#"{"architecture":"arm","os":"linux","variant":"v7"}"#.to_owned()],
        "the `os/arch[/variant]` shorthand must become the JSON OCI platform object: {target}"
    );
    assert_eq!(
        request.header("content-type"),
        Some("application/x-tar"),
        "the archive is a TAR body"
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
    assert_eq!(
        request.header("x-registry-auth"),
        None,
        "a load without credentials sends no registry header"
    );
    assert_eq!(request.body.as_slice(), b"first-chunksecond-chunk");

    fixture.finish();
}

/// A platform load on a client built for API 1.47 is refused before connecting.
///
/// Moby's `postImagesLoad` gates the parameter on
/// `versions.GreaterThanOrEqualTo(…, "1.48")` and otherwise ignores it, loading
/// the full multi-platform image. Refusing here is what stops that silent wrong
/// answer. The endpoint has no listener, so an attempted request would be
/// `ErrorKind::Transport`.
#[tokio::test]
async fn load_refuses_a_platform_below_api_1_48_without_connecting() {
    let client = client_at("http://127.0.0.1:1", 47);
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .load_image(
            archive(),
            Some(ImageLoadOptions::new().with_platform("linux/amd64")),
            ImageTransferLimits::default(),
        )
        .expect_err("1.47 ignores the platform");
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
        message.contains("1.48") && message.contains("1.47"),
        "the refusal did not name both the required and the built-for version: {message}"
    );
}

/// API 1.48 is the exact version that reads the parameter, so it is allowed and
/// the path carries that version.
#[tokio::test]
async fn load_sends_a_platform_at_exactly_api_1_48() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"Loaded image: alpine:3.20\n"}"#,
    ])]);
    let client = client_at(&fixture.endpoint, 48);
    let mut stream = client
        .load_image(
            archive(),
            Some(ImageLoadOptions::new().with_platform("linux/amd64")),
            ImageTransferLimits::default(),
        )
        .expect("1.48 reads the platform");
    while let Some(event) = stream.next().await {
        event.expect("a load event, not an error");
    }

    let target = fixture.request().target().to_owned();
    assert!(
        target.starts_with("/v1.48/images/load?"),
        "the exact boundary version did not send the owned platform request: {target}"
    );
    assert_eq!(
        request_platforms(&target),
        [serde_json::json!({"architecture": "amd64", "os": "linux"})],
        "the platform did not travel as the JSON OCI object: {target}"
    );
    fixture.finish();
}

/// The boundary only gates the platform: a load without one still works at
/// 1.47.
#[tokio::test]
async fn load_without_a_platform_works_below_api_1_48() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"Loaded image: alpine:3.20\n"}"#,
    ])]);
    let client = client_at(&fixture.endpoint, 47);
    let mut stream = client
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("a load without a platform is valid at every version");
    while let Some(event) = stream.next().await {
        event.expect("a load event, not an error");
    }

    let target = fixture.request().target().to_owned();
    assert!(
        target.starts_with("/v1.47/images/load?") && !target.contains("platform="),
        "the version guard changed a load that asked for no platform: {target}"
    );
    fixture.finish();
}

/// A platform without an architecture is refused before connecting.
///
/// Moby's `DecodePlatform` answers `both OS and Architecture must be provided`,
/// so the shorthand is refused here rather than sent for the daemon to reject.
#[tokio::test]
async fn load_refuses_a_platform_without_an_architecture() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .load_image(
            archive(),
            Some(ImageLoadOptions::new().with_platform("linux")),
            ImageTransferLimits::default(),
        )
        .expect_err("the Engine needs both os and architecture");
    assert!(
        error.to_string().contains("os/architecture"),
        "the refusal did not name the missing part: {error}"
    );
}

/// More than one platform is refused before connecting.
///
/// Moby's load handler answers `400 multiple platform parameters not
/// supported`, so the second entry has no request shape that reaches it.
#[tokio::test]
async fn load_refuses_more_than_one_platform() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    let error = client
        .load_image(
            archive(),
            Some(ImageLoadOptions::new().with_platforms(["linux/amd64", "linux/arm64"])),
            ImageTransferLimits::default(),
        )
        .expect_err("the Engine refuses multiple platform parameters");
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
    assert!(
        error.to_string().contains("more than one"),
        "the refusal does not say what the Engine accepts: {error}"
    );
}

/// The raw builder refuses a platform below API 1.48 before it opens a
/// connection, so a caller using `raw::load` directly gets the same guard.
#[tokio::test]
async fn raw_load_refuses_a_platform_below_api_1_48_without_connecting() {
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
            minor: 47,
        },
    );
    let body = stream::iter(Vec::<Result<Bytes, std::io::Error>>::new());
    let error = raw::load(
        &engine,
        body,
        &ImageLoadOptions::new().with_platform("linux/amd64"),
        raw::RegistryAuth::none(),
    )
    .await
    .expect_err("1.47 ignores the platform");
    assert!(
        error.to_string().contains("1.48"),
        "the refusal does not name the required version: {error}"
    );
    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused platform must not open a connection: {accepted:?}"
    );
}

/// Every daemon record is projected onto the public event in daemon order.
#[tokio::test]
async fn load_projects_each_daemon_record() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"Loaded image: alpine:3.20\n"}"#,
        r#"{"status":"Loading","id":"layer","progressDetail":{"current":1,"total":2}}"#,
        r#"{"id":"sha256:deadbeef"}"#,
        r#"{"aux":{"ID":"sha256:aux"}}"#,
    ])]);
    let client = fixture.client();
    let mut stream = client
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("valid load options");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event.expect("a load event, not an error"));
    }

    assert_eq!(events.len(), 4, "one event per daemon record");
    assert_eq!(
        events[0].stream.as_deref(),
        Some("Loaded image: alpine:3.20\n")
    );
    assert_eq!(events[1].id.as_deref(), Some("layer"));
    assert_eq!(events[1].status.as_deref(), Some("Loading"));
    assert_eq!(
        events[1].progress,
        Some(neotales_docker::ImageProgress {
            current: Some(1),
            total: Some(2)
        })
    );
    assert_eq!(events[2].id.as_deref(), Some("sha256:deadbeef"));
    assert_eq!(
        events[3],
        neotales_docker::ImageLoadEvent::default(),
        "a valid `aux` member is validated and dropped: the load event has no field for it"
    );
    assert!(
        events.iter().all(|event| event.error.is_none()),
        "an in-band failure is an Err item, never a success with an error field"
    );
    fixture.finish();
}

/// Both in-band failure spellings are `Err` items, and the stream continues.
///
/// The daemon writes a bare `error` string and an `errorDetail.message`; the
/// generated load model has no member for the first. The owned route reports
/// both and keeps reading, which is what the recovery record proves. An empty
/// bare `error` is treated as absent, so it cannot mask a real
/// `errorDetail.message` — the fallback ignores the bare member entirely and
/// reports the same `errorDetail`.
#[tokio::test]
async fn load_reports_in_band_errors_as_stream_errors() {
    let measured =
        "image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])";
    let bare = format!(r#"{{"error":"{measured}"}}"#);
    let body = records(&[
        r#"{"stream":"Loaded image: alpine:3.20\n"}"#,
        bare.as_str(),
        r#"{"errorDetail":{"message":"the archive was corrupt"},"error":"the archive was corrupt"}"#,
        r#"{"error":"","errorDetail":{"message":"an empty bare error must not mask this"}}"#,
        RECOVERY_RECORD,
    ]);
    let fixture = Fixture::start(vec![body]);
    let client = fixture.client();
    let mut stream = client
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("valid load options");

    let event = stream
        .next()
        .await
        .expect("the first record")
        .expect("a load event, not an error");
    assert_eq!(event.stream.as_deref(), Some("Loaded image: alpine:3.20\n"));

    let error = stream
        .next()
        .await
        .expect("the bare error is an item")
        .expect_err("a `200` carrying an error record is a failed load");
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
        .expect_err("an errorDetail record is a failed load");
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
        .expect("a load event, not an error");
    assert_eq!(event.stream.as_deref(), Some("after\n"));
    assert!(stream.next().await.is_none());
    fixture.finish();
}

/// A malformed record is one error item, and the stream continues after it.
#[tokio::test]
async fn load_refuses_a_malformed_record_and_continues_with_the_next() {
    let fixture = Fixture::start(vec![records(&[r#"{"id":5}"#, RECOVERY_RECORD, "[]"])]);
    let client = fixture.client();
    let mut stream = client
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("valid load options");

    let error = stream
        .next()
        .await
        .expect("the malformed record is an item")
        .expect_err("a known member of the wrong type is refused");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(message.contains("invalid daemon load record"), "{message}");
    assert!(
        !message.contains('5'),
        "the error must not echo the value the daemon sent: {message}"
    );

    let event = stream
        .next()
        .await
        .expect("the next record is still readable")
        .expect("a load event, not an error");
    assert_eq!(event.stream.as_deref(), Some("after\n"));

    let error = stream
        .next()
        .await
        .expect("the non-object record is an item")
        .expect_err("a load record must be a JSON object");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(stream.next().await.is_none());
    fixture.finish();
}

/// Duplicate known members are refused from the original bytes, not after a
/// `Value` parse.
#[tokio::test]
async fn load_rejects_duplicate_and_malformed_known_members() {
    for record in LOAD_MEMBER_REGRESSIONS {
        let fixture = Fixture::start(vec![records(&[record, RECOVERY_RECORD])]);
        let client = fixture.client();
        let mut stream = client
            .load_image(archive(), None, ImageTransferLimits::default())
            .expect("valid load options");
        let error = stream
            .next()
            .await
            .expect("the malformed record is an item")
            .expect_err("a duplicate or wrong-typed known member is refused");
        assert_eq!(error.kind(), ErrorKind::Serialization);
        let message = error
            .source()
            .map_or_else(|| error.to_string(), ToString::to_string);
        assert!(message.contains("invalid daemon load record"), "{message}");

        let event = stream
            .next()
            .await
            .expect("the next record is still readable")
            .expect("a load event, not an error");
        assert_eq!(
            event.stream.as_deref(),
            Some("after\n"),
            "the stream must recover after a refused record"
        );
        assert!(stream.next().await.is_none());
        fixture.finish();
    }
}

/// Dropping or cancelling the handle closes the connection.
#[tokio::test]
async fn load_cancels_the_transfer_when_the_handle_is_released() {
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
            let record = b"{\"stream\":\"Loaded image: alpine:3.20\\n\"}\n";
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
            .load_image(archive(), None, ImageTransferLimits::default())
            .expect("valid load options");
        let event = stream
            .next()
            .await
            .expect("the first record")
            .expect("a load event, not an error");
        assert_eq!(
            event.stream.as_deref(),
            Some("Loaded image: alpine:3.20\n"),
            "{release:?}"
        );

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

/// A dispatched load is never retried over the generated client.
#[tokio::test]
async fn load_is_not_retried_after_the_owned_request_is_dispatched() {
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
                r#"{"message":"load refused"}"#,
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
                        r#"{"message":"load refused"}"#,
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
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("valid load options");
    let error = stream
        .next()
        .await
        .expect("a rejection is one stream item")
        .expect_err("the daemon rejected the load");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's status and message");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, "load refused");
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
            .starts_with(&format!("{}/images/load?", version_prefix())),
        "the first request is the owned one: {}",
        request.target()
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the load was dispatched again after it failed"
    );
    server.join().expect("the fixture thread");
}

/// The owned handle opens no connection until it is first polled.
#[tokio::test]
async fn load_is_lazy_until_the_first_poll() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let stream = client
        .load_image(archive(), None, ImageTransferLimits::default())
        .expect("valid load options");
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

/// The owned load stream refuses a record larger than its configured bound.
#[tokio::test]
async fn the_owned_load_stream_refuses_a_record_over_its_bound() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"a record that is too long"}"#,
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
    let mut frames = raw::load(
        &engine,
        body,
        &ImageLoadOptions::default(),
        raw::RegistryAuth::none(),
    )
    .await
    .expect("the daemon accepted the load")
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
async fn load_refuses_invalid_input_before_opening_a_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let empty = BTreeMap::new();
    assert!(matches!(
        client.load_image_with_credentials(archive(), None, ImageTransferLimits::default(), empty),
        Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            ..
        })
    ));

    let credentials = BTreeMap::from([
        (
            "registry.example".to_owned(),
            RegistryCredentials::new("probeuser", "one"),
        ),
        (
            "other.example".to_owned(),
            RegistryCredentials::new("probeuser", "two"),
        ),
    ]);
    assert!(matches!(
        client.load_image_with_credentials(
            archive(),
            None,
            ImageTransferLimits::default(),
            credentials
        ),
        Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            ..
        })
    ));

    let invalid_platform = ImageLoadOptions::new().with_platform("linux//amd64");
    assert!(matches!(
        client.load_image(
            archive(),
            Some(invalid_platform),
            ImageTransferLimits::default()
        ),
        Err(ImageTransferError::InvalidOption {
            name: "platform",
            ..
        })
    ));

    let zero_limit = ImageTransferLimits {
        max_stream_bytes: 0,
        ..ImageTransferLimits::default()
    };
    assert!(matches!(
        client.load_image(archive(), None, zero_limit),
        Err(ImageTransferError::InvalidLimits(_))
    ));

    let accepted = listener.accept();
    assert!(
        matches!(
            &accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ),
        "a refused load must not open a connection: {accepted:?}"
    );
}
