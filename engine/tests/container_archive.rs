//! `DockerClient`'s container archive operations on the repository-owned
//! transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: `container_archive` must
//! open a versioned `HEAD` and then a versioned `GET` of
//! `/v1.NN/containers/{id}/archive`, `container_path_stat` must decode the
//! daemon's `X-Docker-Container-Path-Stat` header, and
//! `upload_container_archive` must send a chunked `PUT` of the file. Asserting
//! those against request builders would only show what the builders would
//! produce if they were called; the routing decision is above them. A loopback
//! HTTP fixture is the only place the wire request, the stream behaviour, and
//! the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing an `if let Ok(engine) = self.raw_engine()` arm puts the generated
//! client back on the wire. The request line then loses the version prefix and
//! the reference stops being percent-encoded, so the whole-line comparisons
//! fail. The upload comparison also fails if the body is buffered or the
//! `Content-Type` is dropped.
//!
//! The stat tests pin the header contract: the value is standard base64 JSON,
//! an empty `linkTarget` projects to `None`, a missing or malformed header is a
//! failure rather than an empty stat, and an oversized header is refused before
//! it is decoded. The error-message assertions pin that a failure does not echo
//! the header or the container path.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! reads the request head and then stops reading; the client's send buffer
//! fills, and the only thing that makes the fixture's later read end is the
//! test dropping the upload future, which drops the connection.
//!
//! The rejection test pins two contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], and a failed owned request is
//! returned rather than retried over the generated client.
//!
//! Every test reaches the public API, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{ContainerArchiveUploadOptions, DockerClient, ErrorKind};

#[path = "support/archive_wire.rs"]
mod archive_wire;

use archive_wire::{
    Recorded, archive_response, empty_ok, read_request, read_request_head, rejected, stat_header,
    stat_response, version_prefix,
};

/// A one-connection-at-a-time loopback fixture.
///
/// Each handler reads the request, writes its answer, and returns what it read.
/// The listener is bound on loopback only; nothing outside this process is
/// reached.
struct Fixture {
    endpoint: String,
    requests: Receiver<Recorded>,
    server: JoinHandle<()>,
}

fn serve<F>(connections: usize, mut handler: F) -> Fixture
where
    F: FnMut(&mut TcpStream, usize) -> Recorded + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (request_tx, requests) = mpsc::channel();
    let server = thread::spawn(move || {
        for index in 0..connections {
            let (mut stream, _) = listener.accept().expect("accept the request");
            let recorded = handler(&mut stream, index);
            let _ = request_tx.send(recorded);
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    Fixture {
        endpoint: format!("http://{address}"),
        requests,
        server,
    }
}

impl Fixture {
    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn next_request(&self, what: &str) -> Recorded {
        self.requests
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("the fixture recorded no {what} request"))
    }
}

/// The owned path opens the versioned HEAD, decodes the stat header, and then
/// opens the versioned GET for the same path.
#[tokio::test]
async fn archive_opens_head_then_get_and_projects_the_stat() {
    let document = r#"{"name":"dir","size":0,"mode":2147484141,"mtime":"2026-01-01T00:00:00Z","linkTarget":""}"#;
    let header = stat_header(document);
    let fixture = serve(2, move |stream, index| {
        let mut reader = BufReader::new(&mut *stream);
        let head = read_request_head(&mut reader);
        drop(reader);
        let response = if index == 0 {
            stat_response(Some(&header))
        } else {
            archive_response(&[b"first-", b"second"])
        };
        stream.write_all(&response).expect("write the answer");
        stream.flush().expect("flush the answer");
        head.into()
    });

    let mut archive = fixture
        .client()
        .container_archive("a/b", "/tmp/a b")
        .await
        .expect("open the archive");
    assert_eq!(archive.stat.name, "dir");
    assert_eq!(archive.stat.size, 0);
    assert_eq!(archive.stat.mode, 2_147_484_141);
    assert!(
        archive.stat.is_directory(),
        "the daemon's Go mode bit was not read as a directory"
    );
    assert_eq!(archive.stat.link_target, None);

    let mut bytes = Vec::new();
    while let Some(chunk) = archive.next().await {
        bytes.extend_from_slice(&chunk.expect("an archive chunk"));
    }
    assert_eq!(bytes, b"first-second");

    let head = fixture.next_request("HEAD");
    let get = fixture.next_request("GET");
    let expected = format!(
        "HEAD {}/containers/a%2Fb/archive?path=%2Ftmp%2Fa+b HTTP/1.1",
        version_prefix()
    );
    assert_eq!(
        head.line(),
        expected,
        "container_archive fell back to the unversioned generated path or stopped escaping"
    );
    assert_eq!(get.line(), expected.replacen("HEAD", "GET", 1));
    assert_eq!(head.query_value("path").as_deref(), Some("/tmp/a b"));
    assert_eq!(get.query_value("path").as_deref(), Some("/tmp/a b"));
    fixture.server.join().expect("the fixture thread");
}

/// A symlink's target is projected, and a missing path is `None` rather than an
/// error.
#[tokio::test]
async fn path_stat_projects_a_link_target_and_returns_none_for_a_missing_path() {
    let link = stat_header(
        r#"{"name":"link","size":7,"mode":41471,"mtime":"2026-01-01T00:00:00Z","linkTarget":"target.txt"}"#,
    );
    let fixture = serve(2, move |stream, index| {
        let mut reader = BufReader::new(&mut *stream);
        let head = read_request_head(&mut reader);
        drop(reader);
        let response = if index == 0 {
            stat_response(Some(&link))
        } else {
            rejected(
                "404 Not Found",
                "Could not find the file /nope in container missing",
            )
        };
        stream.write_all(&response).expect("write the answer");
        stream.flush().expect("flush the answer");
        head.into()
    });

    let client = fixture.client();
    let stat = client
        .container_path_stat("web", "/link")
        .await
        .expect("read the stat")
        .expect("the path exists");
    assert_eq!(stat.link_target.as_deref(), Some("target.txt"));
    assert!(!stat.is_directory());

    assert_eq!(
        client
            .container_path_stat("missing", "/nope")
            .await
            .expect("a 404 is an answer"),
        None
    );

    let first = fixture.next_request("first");
    let second = fixture.next_request("second");
    assert_eq!(
        first.line(),
        format!(
            "HEAD {}/containers/web/archive?path=%2Flink HTTP/1.1",
            version_prefix()
        )
    );
    assert_eq!(
        second.line(),
        format!(
            "HEAD {}/containers/missing/archive?path=%2Fnope HTTP/1.1",
            version_prefix()
        )
    );
    fixture.server.join().expect("the fixture thread");
}

/// A missing, malformed, or incomplete stat header is an error, and the error
/// does not echo the header or the container path.
#[tokio::test]
async fn archive_stat_reports_a_missing_or_malformed_header() {
    let incomplete = stat_header(r#"{"name":"x","size":1,"mode":420}"#);
    let fixture = serve(3, move |stream, index| {
        let mut reader = BufReader::new(&mut *stream);
        let head = read_request_head(&mut reader);
        drop(reader);
        let response = match index {
            0 => stat_response(None),
            1 => stat_response(Some("not-base64")),
            _ => stat_response(Some(&incomplete)),
        };
        stream.write_all(&response).expect("write the answer");
        stream.flush().expect("flush the answer");
        head.into()
    });

    let client = fixture.client();
    for case in ["missing header", "invalid base64", "missing linkTarget"] {
        let error = client
            .container_path_stat("web", "/secret-path")
            .await
            .expect_err(case);
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{case}");
        let rendered = error.to_string();
        assert!(
            !rendered.contains("/secret-path"),
            "{case}: the error echoed the container path: {rendered}"
        );
        assert!(
            !rendered.contains("not-base64"),
            "{case}: the error echoed the header value: {rendered}"
        );
    }
    fixture.server.join().expect("the fixture thread");
}

/// A malformed stat field is not echoed in any rendering of the error.
///
/// serde quotes the unexpected value in a wrong-type diagnostic, so attaching
/// that diagnostic would put whatever the daemon put in the header into a
/// message a caller prints. The fixed message must not carry it through
/// `Display`, `Debug`, or the source chain.
#[tokio::test]
async fn archive_stat_does_not_echo_an_untrusted_field() {
    const MARKER: &str = "SYNTHETIC-STAT-SECRET-7f3a";
    let document = format!(r#"{{"name":"x","size":"{MARKER}","mode":420,"linkTarget":""}}"#);
    let header = stat_header(&document);
    let fixture = serve(1, move |stream, _| {
        let mut reader = BufReader::new(&mut *stream);
        let head = read_request_head(&mut reader);
        drop(reader);
        stream
            .write_all(&stat_response(Some(&header)))
            .expect("write the answer");
        stream.flush().expect("flush the answer");
        head.into()
    });

    let error = fixture
        .client()
        .container_path_stat("web", "/tmp")
        .await
        .expect_err("a wrong-type size is not a stat");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let display = error.to_string();
    assert!(
        display.contains("not the expected object"),
        "the stat decode failure stopped naming the shape: {display}"
    );
    assert!(
        !display.contains(MARKER),
        "Display echoed the untrusted field: {display}"
    );
    let debug = format!("{error:?}");
    assert!(
        !debug.contains(MARKER),
        "Debug echoed the untrusted field: {debug}"
    );

    let mut source = std::error::Error::source(&error);
    while let Some(current) = source {
        let rendered = current.to_string();
        assert!(
            !rendered.contains(MARKER),
            "a source echoed the untrusted field: {rendered}"
        );
        let debug = format!("{current:?}");
        assert!(
            !debug.contains(MARKER),
            "a source's Debug echoed the untrusted field: {debug}"
        );
        source = current.source();
    }
    fixture.server.join().expect("the fixture thread");
}

/// An oversized stat header is refused before it is decoded.
#[tokio::test]
async fn archive_stat_refuses_an_oversized_header() {
    // The limit is 16 KiB. A value above it is not a legitimate stat document,
    // and refusing it before base64 decoding is what keeps the allocation this
    // client makes from being the peer's to choose.
    let oversized = "A".repeat(20_000);
    let fixture = serve(1, move |stream, _| {
        let mut reader = BufReader::new(&mut *stream);
        let head = read_request_head(&mut reader);
        drop(reader);
        stream
            .write_all(&stat_response(Some(&oversized)))
            .expect("write the answer");
        stream.flush().expect("flush the answer");
        head.into()
    });

    let error = fixture
        .client()
        .container_path_stat("web", "/tmp")
        .await
        .expect_err("an oversized header is not a stat");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("16384-byte limit"),
        "the refusal did not name the bound: {error}"
    );
    fixture.server.join().expect("the fixture thread");
}

/// The owned upload sends the versioned, escaped, chunked PUT and streams the
/// file without a `Content-Length`.
#[tokio::test]
async fn upload_sends_a_versioned_chunked_put_and_streams_the_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive_path = directory.path().join("upload.tar");
    std::fs::write(&archive_path, b"tar-bytes").expect("write the archive");

    let fixture = serve(1, |stream, _| {
        let mut reader = BufReader::new(&mut *stream);
        let recorded = read_request(&mut reader);
        drop(reader);
        stream.write_all(&empty_ok()).expect("write the answer");
        stream.flush().expect("flush the answer");
        recorded
    });

    fixture
        .client()
        .upload_container_archive(
            "a/b",
            &archive_path,
            ContainerArchiveUploadOptions {
                path: "/dest".to_owned(),
                copy_user_and_group: true,
                no_overwrite_directory_with_file: true,
            },
        )
        .await
        .expect("upload the archive");

    let recorded = fixture.next_request("PUT");
    assert_eq!(
        recorded.line(),
        format!(
            "PUT {}/containers/a%2Fb/archive?path=%2Fdest&noOverwriteDirNonDir=1&copyUIDGID=1 HTTP/1.1",
            version_prefix()
        ),
        "upload_container_archive fell back to the unversioned generated path or stopped escaping"
    );
    assert_eq!(recorded.body, b"tar-bytes");
    assert_eq!(
        recorded.head.header("content-type"),
        Some("application/x-tar")
    );
    assert!(
        recorded.head.header("content-length").is_none(),
        "the archive was announced with a length instead of streamed"
    );
    assert_eq!(
        recorded
            .head
            .header("transfer-encoding")
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("chunked")
    );
    fixture.server.join().expect("the fixture thread");
}

/// A daemon rejection keeps its status and message, and the upload is not
/// retried over the generated client.
#[tokio::test]
async fn upload_reports_a_rejection_and_does_not_retry() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive_path = directory.path().join("upload.tar");
    std::fs::write(&archive_path, b"tar-bytes").expect("write the archive");

    let message = "unexpected EOF";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (retry_tx, retry) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the request");
        let mut reader = BufReader::new(&mut stream);
        let recorded = read_request(&mut reader);
        drop(reader);
        assert!(
            recorded.target().contains("/archive?path=%2Fdest"),
            "the rejection fixture saw a different request: {}",
            recorded.target()
        );
        stream
            .write_all(&rejected("400 Bad Request", message))
            .expect("write the rejection");
        stream.flush().expect("flush the rejection");
        let mut buffer = [0_u8; 64];
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }
        }

        listener
            .set_nonblocking(true)
            .expect("make the fixture listener nonblocking");
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut retry_stream, _)) => {
                    let mut reader = BufReader::new(&mut retry_stream);
                    let _ = read_request(&mut reader);
                    let _ = retry_tx.send(());
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });

    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let error = client
        .upload_container_archive(
            "web",
            &archive_path,
            ContainerArchiveUploadOptions {
                path: "/dest".to_owned(),
                ..ContainerArchiveUploadOptions::default()
            },
        )
        .await
        .expect_err("a 400 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, message);
    assert!(
        retry.recv_timeout(Duration::from_secs(1)).is_err(),
        "the upload was retried over the generated client"
    );
    server.join().expect("the fixture thread");
}

/// Dropping the upload future closes the connection.
///
/// The fixture reads only the request head and then stops reading, so the
/// client's send buffer fills and the future stays pending. The test then drops
/// the future; the fixture's later read is the observation that the socket went
/// away. Bytes already written may have reached the daemon, which is why the
/// method's contract says the effect of an interrupted upload is unknown.
#[tokio::test]
async fn upload_closes_the_connection_when_the_future_is_dropped() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let archive_path = directory.path().join("large.tar");
    std::fs::write(&archive_path, vec![0x5a_u8; 8 * 1024 * 1024]).expect("write the archive");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<bool>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the request");
        let _head = {
            let mut reader = BufReader::new(&mut stream);
            read_request_head(&mut reader)
        };
        // Deliberately do not read the body yet. The client blocks once the
        // socket buffer is full, which keeps the upload future pending until
        // the test drops it.
        thread::sleep(Duration::from_secs(1));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set the fixture read timeout");
        let mut buffer = [0_u8; 64];
        let closed = loop {
            match stream.read(&mut buffer) {
                Ok(0) => break true,
                Ok(_) => {}
                // A timeout is the only outcome that means the client kept the
                // connection open. A reset is still the connection going away.
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

    let client =
        DockerClient::connect_http(&format!("http://{address}")).expect("build the fixture client");
    let mut upload = Box::pin(client.upload_container_archive(
        "web",
        &archive_path,
        ContainerArchiveUploadOptions {
            path: "/dest".to_owned(),
            ..ContainerArchiveUploadOptions::default()
        },
    ));
    let elapsed = tokio::time::timeout(Duration::from_millis(200), upload.as_mut()).await;
    assert!(
        elapsed.is_err(),
        "the upload finished instead of blocking on a fixture that stopped reading"
    );
    drop(upload);

    let closed = tokio::time::timeout(Duration::from_secs(10), closed_rx)
        .await
        .expect("the fixture did not observe the disconnect")
        .expect("the fixture reported");
    assert!(
        closed,
        "dropping the upload future did not close the connection"
    );
    server.join().expect("the fixture thread");
}

/// An empty reference or path is refused before a connection is opened, so a
/// client pointed at a closed port still reports `InvalidInput`.
#[tokio::test]
async fn archive_refuses_empty_inputs_before_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");

    for error in [
        client
            .container_path_stat("", "/tmp")
            .await
            .expect_err("empty reference"),
        client
            .container_path_stat("web", "")
            .await
            .expect_err("empty path"),
        client
            .container_archive("", "/tmp")
            .await
            .expect_err("empty reference"),
        client
            .container_archive("web", "")
            .await
            .expect_err("empty path"),
    ] {
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
}
