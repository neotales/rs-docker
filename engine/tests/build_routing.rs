//! `DockerClient::build_image` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: a build must open the
//! versioned `/v1.NN/build` path, encode every caller option into that request,
//! stream the caller's TAR context as the body, and project the daemon's
//! newline-delimited records onto [`ImageBuildEvent`]. Asserting any of that
//! against a request builder would only show what the builder would produce if
//! it were called; the routing decision is above it. A loopback HTTP fixture is
//! the only place where the wire request, the stream, and the routing are the
//! same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `build_image`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix and the request carries `platform=`/`target=` even when the
//! caller did not set them, so the whole-line and option assertions fail.
//!
//! The stream tests are about what a `200` means. A build step that fails is an
//! **in-band** record, not a status, and the generated client has always turned
//! it into an `Err` item; the owned projection must do the same, or a caller
//! that only handles `Err` reports a failed build as a successful one. A
//! malformed record must be refused as one item and must not end the stream,
//! which is what lets a caller keep reading after a record this client will not
//! accept.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! writes one record and then reads; the only thing that ends that read is the
//! client releasing the response, which closes the socket.
//!
//! The retry test is the reason the fallback is a routing decision rather than
//! an error path: a build that has already been dispatched must never be
//! re-issued through the generated client, because that would build the image
//! twice. The fixture counts connections and fails if a second one arrives.
//!
//! The record-bound test is here because the facade cannot lower
//! `MAX_RECORD_BYTES`, and sending eight megabytes to prove a bound is a slower
//! and weaker test than lowering the bound on the same owned operation.
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

use base64::Engine as _;
use bytes::Bytes;
use neotales_docker::{
    API_VERSION, DockerClient, ErrorKind, ImageBuildBackend, ImageBuildKitOption,
    ImageBuildOptions, ImageOperationError, ImageTransferError, RegistryCredentials, raw,
};

#[path = "support/build_wire.rs"]
mod build_wire;

use build_wire::{
    COMPATIBLE_RECORDS, KNOWN_MEMBER_REGRESSIONS, RECOVERY_RECORD, Recorded, build_context,
    read_request, records, rejected, version_prefix,
};

/// How long a fixture waits for the request it was started for.
const FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::test]
async fn build_ignores_unknown_overflow_numbers() {
    let fixture = Fixture::start(vec![records(&COMPATIBLE_RECORDS)]);
    let client = fixture.client();
    let mut stream = client.build_image(build_context(), None).unwrap();
    let event = stream
        .next()
        .await
        .unwrap()
        .expect("unknown numbers are ignored");
    assert_eq!(event.stream.as_deref(), Some("after\n"));
    let event = stream.next().await.unwrap().unwrap();
    assert_eq!(event.stream.as_deref(), Some("array\n"));
    assert_eq!(event.progress.unwrap().current, Some(1));
    assert_eq!(event.aux.unwrap().image_id.as_deref(), Some("sha256:array"));
    assert!(stream.next().await.is_none());
    fixture.finish();
}

#[tokio::test]
async fn build_ignores_many_unknown_members_and_recovers_from_invalid_json() {
    let unknown = format!(
        "{{\"unknown\":{{{}}},\"stream\":\"large\\n\"}}",
        "\"x\":0,".repeat(100_000) + "\"last\":1e400"
    );
    let fixture = Fixture::start(vec![records(&[
        &unknown,
        r#"{"id":"sensitive-value",}"#,
        RECOVERY_RECORD,
    ])]);
    let client = fixture.client();
    let mut stream = client.build_image(build_context(), None).unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap().stream.as_deref(),
        Some("large\n")
    );
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Serialization);
    assert!(!format!("{error:?}").contains("sensitive-value"));
    assert_eq!(
        stream.next().await.unwrap().unwrap().stream.as_deref(),
        Some("after\n")
    );
    assert!(stream.next().await.is_none());
    fixture.finish();
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
fn every_option() -> ImageBuildOptions {
    ImageBuildOptions {
        dockerfile: "Containerfile".to_owned(),
        tags: vec![
            "registry.example/app:1.2.3".to_owned(),
            "registry.example/app:latest".to_owned(),
        ],
        target: Some("runtime".to_owned()),
        platform: Some("linux/arm64".to_owned()),
        quiet: true,
        no_cache: true,
        pull: Some(true),
        remove_intermediate: false,
        force_remove_intermediate: true,
        build_args: std::collections::BTreeMap::from([
            ("A".to_owned(), "1".to_owned()),
            ("MODE".to_owned(), "test".to_owned()),
        ]),
        labels: std::collections::BTreeMap::from([(
            "org.example.team".to_owned(),
            "platform".to_owned(),
        )]),
        cache_from: vec!["registry.example/app:cache".to_owned()],
        extra_hosts: Some("example.internal:10.0.0.2".to_owned()),
        extra_host_entries: vec!["second.internal:10.0.0.3".to_owned()],
        network_mode: Some("host".to_owned()),
        memory: Some(1024),
        memswap: Some(2048),
        cpu_shares: Some(512),
        cpuset_cpus: Some("0-1".to_owned()),
        cpu_period: Some(100_000),
        cpu_quota: Some(50_000),
        shm_size: Some(67_108_864),
        ulimits: vec![neotales_docker::Ulimit {
            name: "nofile".to_owned(),
            soft: 1024,
            hard: 2048,
        }],
        squash: Some(true),
        registry_credentials: std::collections::BTreeMap::from([(
            "https://REGISTRY.EXAMPLE/v1/".to_owned(),
            RegistryCredentials::new("probeuser", "aa>")
                .with_server_address("https://registry.example/v1/"),
        )]),
        remote: None,
        backend: neotales_docker::ImageBuildBackend::Classic,
        buildkit_options: Vec::new(),
    }
}

/// The owned request is versioned, carries every caller option, and uses the
/// map header for its credential.
#[tokio::test]
async fn build_sends_every_option_to_the_versioned_path() {
    let fixture = Fixture::start(vec![records(&[r#"{"stream":"ok\n"}"#])]);
    let client = fixture.client();
    let mut stream = client
        .build_image(build_context(), Some(every_option()))
        .expect("valid build options");
    while let Some(event) = stream.next().await {
        event.expect("a build event, not an error");
    }

    let request = fixture.request();
    let target = request.target();
    assert!(
        target.starts_with(&format!("{}/build?", version_prefix())),
        "the owned transport must send the versioned path: {target}"
    );
    assert_eq!(
        request.query_value("dockerfile").as_deref(),
        Some("Containerfile")
    );
    assert_eq!(
        request.query_values("t"),
        [
            "registry.example/app:1.2.3".to_owned(),
            "registry.example/app:latest".to_owned()
        ],
        "one `t=` pair per tag, in caller order: {target}"
    );
    assert_eq!(request.query_value("target").as_deref(), Some("runtime"));
    assert_eq!(
        request.query_value("platform").as_deref(),
        Some("linux/arm64")
    );
    assert_eq!(request.query_value("q").as_deref(), Some("true"));
    assert_eq!(request.query_value("nocache").as_deref(), Some("true"));
    assert_eq!(request.query_value("pull").as_deref(), Some("true"));
    assert_eq!(request.query_value("rm").as_deref(), Some("false"));
    assert_eq!(request.query_value("forcerm").as_deref(), Some("true"));
    assert_eq!(
        request.query_values("extrahosts"),
        ["example.internal:10.0.0.2", "second.internal:10.0.0.3"]
    );
    assert_eq!(request.query_value("networkmode").as_deref(), Some("host"));
    assert_eq!(request.query_value("memory").as_deref(), Some("1024"));
    assert_eq!(request.query_value("memswap").as_deref(), Some("2048"));
    assert_eq!(request.query_value("cpushares").as_deref(), Some("512"));
    assert_eq!(request.query_value("cpusetcpus").as_deref(), Some("0-1"));
    assert_eq!(request.query_value("cpuperiod").as_deref(), Some("100000"));
    assert_eq!(request.query_value("cpuquota").as_deref(), Some("50000"));
    assert_eq!(request.query_value("shmsize").as_deref(), Some("67108864"));
    assert_eq!(
        request.query_json("ulimits"),
        serde_json::json!([{"Name": "nofile", "Soft": 1024, "Hard": 2048}])
    );
    assert_eq!(request.query_value("squash").as_deref(), Some("true"));
    assert_eq!(
        request.query_json("buildargs"),
        serde_json::json!({"A": "1", "MODE": "test"})
    );
    assert_eq!(
        request.query_json("labels"),
        serde_json::json!({"org.example.team": "platform"})
    );
    assert_eq!(
        request.query_json("cachefrom"),
        serde_json::json!(["registry.example/app:cache"])
    );

    assert_eq!(
        request.header("x-registry-auth"),
        None,
        "POST /build reads the map header; a single-object header carries nothing"
    );
    let header = request
        .header("x-registry-config")
        .expect("the build sends its credential");
    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(header)
        .expect("the Engine's alphabet decodes it");
    let value: serde_json::Value = serde_json::from_slice(&decoded).expect("a JSON auth map");
    assert!(
        value
            == serde_json::json!({
                "registry.example": {
                    "username": "probeuser",
                    "password": "aa>",
                    "serveraddress": "https://registry.example/v1/"
                }
            }),
        "credential map key or payload differs from the expected synthetic value"
    );

    fixture.finish();
}

/// The owned request streams the validated TAR context and projects every
/// daemon record in order.
#[tokio::test]
async fn build_streams_the_tar_context_and_projects_each_record() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"stream":"Step 1/2 : FROM alpine:3.20\n"}"#,
        r#"{"status":"Pulling","id":"layer","progressDetail":{"current":1,"total":2}}"#,
        r#"{"aux":{"ID":"sha256:deadbeef"}}"#,
    ])]);
    let client = fixture.client();
    let mut stream = client
        .build_image(build_context(), None)
        .expect("valid build options");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event.expect("a build event, not an error"));
    }

    let request = fixture.request();
    let body = String::from_utf8_lossy(&request.body);
    assert!(
        body.contains("FROM alpine:3.20"),
        "the declared Dockerfile must be in the uploaded TAR"
    );
    assert!(
        body.contains("payload"),
        "the rest of the declared context must be uploaded too"
    );

    assert_eq!(events.len(), 3, "one event per daemon record");
    assert_eq!(
        events[0].stream.as_deref(),
        Some("Step 1/2 : FROM alpine:3.20\n")
    );
    assert_eq!(events[1].id.as_deref(), Some("layer"));
    assert_eq!(events[1].status.as_deref(), Some("Pulling"));
    assert_eq!(
        events[1].progress,
        Some(neotales_docker::ImageProgress {
            current: Some(1),
            total: Some(2)
        })
    );
    assert_eq!(
        events[2]
            .aux
            .as_ref()
            .and_then(|aux| aux.image_id.as_deref()),
        Some("sha256:deadbeef")
    );
    fixture.finish();
}

/// A failed build step is an in-band `Err` item, not a status.
#[tokio::test]
async fn build_reports_in_band_errors_as_stream_errors() {
    let failed = records(&[
        r#"{"stream":"Step 1/1 : FROM alpine:3.20\n"}"#,
        r#"{"errorDetail":{"message":"the step failed"},"error":"the step failed"}"#,
    ]);
    let fixture = Fixture::start(vec![failed.clone(), failed]);
    let client = fixture.client();

    let mut stream = client
        .build_image(build_context(), None)
        .expect("valid build options");
    let event = stream
        .next()
        .await
        .expect("the first record")
        .expect("a build event, not an error");
    assert_eq!(
        event.stream.as_deref(),
        Some("Step 1/1 : FROM alpine:3.20\n")
    );
    let error = stream
        .next()
        .await
        .expect("the failure is an item")
        .expect_err("a `200` carrying an error record is a failed build");
    assert_eq!(error.kind(), ErrorKind::Docker);
    assert_eq!(error.to_string(), "Docker client error");
    let source = error.source().expect("the daemon failure has a source");
    assert_eq!(source.to_string(), "Docker stream error: the step failed");
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(
        message.contains("the step failed"),
        "the daemon's message survives: {message}"
    );
    assert!(
        stream.next().await.is_none(),
        "the daemon ends the stream after a failed step"
    );

    let error = client
        .build_image_to_completion(build_context(), None)
        .await
        .expect_err("the collected form must refuse an in-band failure");
    match error {
        ImageOperationError::Docker(error) => {
            assert_eq!(error.kind(), ErrorKind::Docker);
            let message = error
                .source()
                .map_or_else(|| error.to_string(), ToString::to_string);
            assert!(message.contains("the step failed"), "{message}");
        }
        other => panic!("the collected form reported {other:?}"),
    }
    fixture.finish();
}

/// A malformed record is one error item, and the stream continues after it.
#[tokio::test]
async fn build_refuses_a_malformed_record_and_continues_with_the_next() {
    let fixture = Fixture::start(vec![records(&[
        r#"{"id":5}"#,
        r#"{"stream":"after\n"}"#,
        "[]",
    ])]);
    let client = fixture.client();
    let mut stream = client
        .build_image(build_context(), None)
        .expect("valid build options");

    let error = stream
        .next()
        .await
        .expect("the malformed record is an item")
        .expect_err("a known member of the wrong type is refused");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(message.contains("invalid daemon build record"), "{message}");
    assert!(
        !message.contains('5'),
        "the error must not echo the value the daemon sent: {message}"
    );

    let event = stream
        .next()
        .await
        .expect("the next record is still readable")
        .expect("a build event, not an error");
    assert_eq!(event.stream.as_deref(), Some("after\n"));

    let error = stream
        .next()
        .await
        .expect("the non-object record is an item")
        .expect_err("a build record must be a JSON object");
    assert_eq!(error.kind(), ErrorKind::Serialization);
    let message = error
        .source()
        .map_or_else(|| error.to_string(), ToString::to_string);
    assert!(message.contains("invalid daemon build record"), "{message}");
    assert!(stream.next().await.is_none());
    fixture.finish();
}

/// Duplicate known members and a malformed nested `code` are refused from the
/// original bytes, not after a `Value` parse.
#[tokio::test]
async fn build_rejects_duplicate_and_malformed_known_members() {
    for (record, duplicate) in KNOWN_MEMBER_REGRESSIONS {
        let fixture = Fixture::start(vec![records(&[record, RECOVERY_RECORD])]);
        let client = fixture.client();
        let mut stream = client
            .build_image(build_context(), None)
            .expect("valid build options");
        let error = stream
            .next()
            .await
            .expect("the malformed record is an item")
            .expect_err("a duplicate or wrong-typed known member is refused");
        assert_eq!(error.kind(), ErrorKind::Serialization);
        let message = error
            .source()
            .map_or_else(|| error.to_string(), ToString::to_string);
        let _ = duplicate;
        assert!(message.contains("invalid daemon build record"), "{message}");

        let event = stream
            .next()
            .await
            .expect("the next record is still readable")
            .expect("a build event, not an error");
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
async fn build_cancels_the_transfer_when_the_handle_is_released() {
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
            let record = b"{\"stream\":\"first\\n\"}\n";
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
            .build_image(build_context(), None)
            .expect("valid build options");
        let event = stream
            .next()
            .await
            .expect("the first record")
            .expect("a build event, not an error");
        assert_eq!(event.stream.as_deref(), Some("first\n"), "{release:?}");

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

/// A dispatched build is never retried over the generated client.
#[tokio::test]
async fn build_is_not_retried_after_the_owned_request_is_dispatched() {
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
                r#"{"message":"build refused"}"#,
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
                        r#"{"message":"build refused"}"#,
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
        .build_image(build_context(), None)
        .expect("valid build options");
    let error = stream
        .next()
        .await
        .expect("a rejection is one stream item")
        .expect_err("the daemon rejected the build");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's status and message");
    assert_eq!(api.status_code, 500);
    assert_eq!(api.message, "build refused");
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
            .starts_with(&format!("{}/build?", version_prefix())),
        "the first request is the owned one: {}",
        request.target()
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the build was dispatched again after it failed"
    );
    server.join().expect("the fixture thread");
}

/// The owned build stream refuses a record larger than its configured bound.
#[tokio::test]
async fn the_owned_build_stream_refuses_a_record_over_its_bound() {
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
    let body = futures_util::stream::iter(Vec::<Result<Bytes, std::io::Error>>::new());
    let mut frames = raw::build(&engine, body, &ImageBuildOptions::default())
        .await
        .expect("the daemon accepted the build")
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
async fn build_refuses_invalid_input_before_opening_a_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("the fixture address");
    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");

    let buildkit = ImageBuildOptions {
        backend: ImageBuildBackend::BuildKit,
        ..ImageBuildOptions::default()
    };
    assert!(matches!(
        client.build_image(build_context(), Some(buildkit)),
        Err(ImageTransferError::UnsupportedBuildKit(_))
    ));

    let named = ImageBuildOptions {
        buildkit_options: vec![ImageBuildKitOption::CacheTo],
        ..ImageBuildOptions::default()
    };
    assert!(matches!(
        client.build_image(build_context(), Some(named)),
        Err(ImageTransferError::UnsupportedBuildKit(_))
    ));

    let remote = ImageBuildOptions {
        remote: Some("https://example.invalid/context.git".to_owned()),
        ..ImageBuildOptions::default()
    };
    assert!(matches!(
        client.build_image(build_context(), Some(remote)),
        Err(ImageTransferError::InvalidOption { name: "remote", .. })
    ));

    let credentials = ImageBuildOptions {
        registry_credentials: std::collections::BTreeMap::from([(
            "registry.example".to_owned(),
            RegistryCredentials::default(),
        )]),
        ..ImageBuildOptions::default()
    };
    assert!(matches!(
        client.build_image(build_context(), Some(credentials)),
        Err(ImageTransferError::Credentials(_))
    ));

    let missing = ImageBuildOptions {
        dockerfile: "absent".to_owned(),
        ..ImageBuildOptions::default()
    };
    assert!(matches!(
        client.build_image(build_context(), Some(missing)),
        Err(ImageTransferError::DockerfileMissing(_))
    ));

    let accepted = listener.accept();
    let blocked = matches!(
        &accepted,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    );
    assert!(
        blocked,
        "a refused build must not open a connection: {accepted:?}"
    );
}
