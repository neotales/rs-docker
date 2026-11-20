//! `DockerClient::{save_images, save_image}` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: a save must open the
//! versioned `/v1.NN/images/...` path through the owned transport, encode every
//! caller option into that request, and deliver the answer as transport chunks
//! rather than as one collected buffer. Asserting any of that against a request
//! builder would only show what the builder would produce if it were called; the
//! routing decision is above it. A loopback HTTP fixture is the only place where
//! the wire request, the streaming behaviour, and the routing are the same
//! observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from `save_images`
//! puts the generated client back on the wire. The request line then loses the
//! version prefix and, for a single name, changes from `/images/{name}/get` to
//! `/images/get?names=...`, so the whole-line comparisons fail.
//!
//! The streaming test is deliberately written so a facade that collected the
//! body before yielding its first item cannot pass: the fixture holds the second
//! chunk until the test has received the first one, and closes the connection if
//! that acknowledgement does not arrive.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! writes one chunk and then reads; the only thing that ends that read is the
//! client releasing the response, which closes the socket.
//!
//! # What "the answer is not an archive" means here
//!
//! The two error cases are pinned separately because they are different claims.
//! An **incomplete HTTP body** — a `200` whose chunked framing ends without its
//! terminating chunk — is a transport failure item. A **complete body carrying
//! bytes that are not a TAR** is not a failure at all: it is delivered exactly as
//! sent, because this crate does not parse or validate the archive. The second
//! test is what stops a future TAR check from being added here and reported as a
//! save failure the Engine never produced.
//!
//! The rejection test pins two contracts at once: a daemon rejection keeps its
//! status and message in [`Error::api_error`], and a failed owned request is
//! returned as one stream item rather than retried over the generated client.
//!
//! Every test reaches the public API, and none needs a running daemon.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use neotales_docker::{
    API_VERSION, ApiVersion, DockerClient, Endpoint, ErrorKind, ImageSaveOptions,
    ImageTransferError,
};

/// A one-request HTTP server whose answer is written by a closure.
///
/// The request head is recorded before the closure runs, so a test can assert
/// the request line even when the answer is an error or is cut short. The
/// listener is bound on loopback only; nothing outside this process is reached.
fn serve_once<F>(handler: F) -> (String, Receiver<String>, JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (request_tx, requests) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the request");
        let head = read_request_head(&mut stream);
        let _ = request_tx.send(head);
        handler(stream);
    });
    (format!("http://{address}"), requests, server)
}

/// Reads the request head, which is all a save request sends.
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

/// Starts a chunked `200` archive answer.
fn start_archive(stream: &mut TcpStream) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/x-tar\r\n\
              Connection: close\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n",
        )
        .expect("write the archive head");
    stream.flush().expect("flush the archive head");
}

/// Writes one HTTP chunk and flushes it, so the client can see it before the
/// rest of the archive exists.
fn write_chunk(stream: &mut TcpStream, bytes: &[u8]) {
    write!(stream, "{:X}\r\n", bytes.len()).expect("write the chunk length");
    stream.write_all(bytes).expect("write the chunk");
    stream
        .write_all(b"\r\n")
        .expect("write the chunk terminator");
    stream.flush().expect("flush the chunk");
}

/// Ends a chunked answer.
fn end_archive(stream: &mut TcpStream) {
    stream
        .write_all(b"0\r\n\r\n")
        .expect("write the last chunk");
    stream.flush().expect("flush the last chunk");
}

/// The version prefix the owned transport is expected to send.
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Reads one request line from the fixture.
fn request_line(requests: &Receiver<String>) -> String {
    requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the fixture recorded no request")
        .lines()
        .next()
        .expect("the request has a request line")
        .to_owned()
}

/// Decodes every `platform` value in a request target, in request order.
///
/// The Engine's `platform` parameter is a JSON-encoded OCI platform object, so
/// a test that compared the shorthand string would pass against a request the
/// daemon refuses.
fn decoded_platforms(line: &str) -> Vec<serde_json::Value> {
    let target = line.split_whitespace().nth(1).expect("the request target");
    let query = target.split_once('?').map_or("", |(_, query)| query);
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| key.as_ref() == "platform")
        .map(|(_, value)| serde_json::from_str(&value).expect("the platform parameter is JSON"))
        .collect()
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

/// Drains a save stream into one buffer.
async fn collect(mut stream: neotales_docker::DockerStream<Vec<u8>>) -> Vec<u8> {
    let mut archive = Vec::new();
    while let Some(chunk) = stream.next().await {
        archive.extend_from_slice(&chunk.expect("the archive chunk"));
    }
    archive
}

/// The owned path sends the versioned, encoded request for several names and a
/// platform, and yields exactly the bytes the daemon wrote.
///
/// The whole request line is compared because that is the assertion a wrong
/// transport fails: the generated client sends the unversioned `/images/get`,
/// with the platform appended by a request modifier. The platform value is also
/// decoded and compared as an OCI platform object, because the Engine's
/// parameter is JSON and a `os/arch` string would be a `400` on API 1.48 and
/// silently ignored below it.
#[tokio::test]
async fn save_images_sends_a_versioned_encoded_request_and_yields_the_archive() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"first");
        write_chunk(&mut stream, b"-second");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let stream = client
        .save_images(
            ImageSaveOptions::new(["alpine:3.20", "busybox:1.36"]).with_platform("linux/arm64"),
        )
        .expect("valid save options");
    assert_eq!(collect(stream).await, b"first-second");

    let line = request_line(&requests);
    assert_eq!(
        line,
        format!(
            "GET {}/images/get?names=alpine%3A3.20&names=busybox%3A1.36&platform=%7B%22architecture%22%3A%22arm64%22%2C%22os%22%3A%22linux%22%7D HTTP/1.1",
            version_prefix()
        ),
        "save_images fell back to the unversioned generated path, reordered the names, or dropped an option"
    );
    assert_eq!(
        decoded_platforms(&line),
        [serde_json::json!({"architecture": "arm64", "os": "linux"})],
        "the platform was not the JSON OCI object the Engine decodes"
    );

    server.join().expect("the fixture thread");
}

/// A single-name save uses the single-image path and keeps the reference in one
/// escaped segment.
#[tokio::test]
async fn save_one_name_uses_the_single_image_path_with_the_platform() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"archive");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let stream = client
        .save_image("owner/app:v1", Some("linux/amd64".to_owned()))
        .expect("valid save options");
    assert_eq!(collect(stream).await, b"archive");

    assert_eq!(
        request_line(&requests),
        format!(
            "GET {}/images/owner%2Fapp%3Av1/get?names=owner%2Fapp%3Av1&platform=%7B%22architecture%22%3A%22amd64%22%2C%22os%22%3A%22linux%22%7D HTTP/1.1",
            version_prefix()
        ),
        "save_image did not take the owned single-name route, or stopped escaping the reference"
    );

    server.join().expect("the fixture thread");
}

/// `save_image` and `save_images` describe the same request for the same
/// options, with and without a platform.
///
/// The two methods are documented as equivalent, and the only place that
/// equivalence is observable is the wire. Each fixture answers a different body
/// so a crossed stream would also be visible.
#[tokio::test]
async fn save_image_matches_save_images_for_the_same_options() {
    let mut lines = Vec::new();
    let mut bodies = Vec::new();

    for (body, options, image, platform) in [
        (
            b"no-platform".as_slice(),
            ImageSaveOptions::new(["owner/app:v1"]),
            "owner/app:v1",
            None,
        ),
        (
            b"with-platform".as_slice(),
            ImageSaveOptions::new(["owner/app:v1"]).with_platform("linux/amd64"),
            "owner/app:v1",
            Some("linux/amd64".to_owned()),
        ),
    ] {
        let expected_body = body.to_vec();
        let (endpoint, requests, server) = serve_once(move |mut stream| {
            start_archive(&mut stream);
            write_chunk(&mut stream, &expected_body);
            end_archive(&mut stream);
            let _ = stream.shutdown(Shutdown::Both);
        });
        let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
        let stream = client.save_images(options).expect("valid save options");
        assert_eq!(collect(stream).await, body);
        lines.push(request_line(&requests));
        server.join().expect("the fixture thread");

        let expected_body = body.to_vec();
        let (endpoint, requests, server) = serve_once(move |mut stream| {
            start_archive(&mut stream);
            write_chunk(&mut stream, &expected_body);
            end_archive(&mut stream);
            let _ = stream.shutdown(Shutdown::Both);
        });
        let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
        let stream = client
            .save_image(image, platform)
            .expect("valid save options");
        assert_eq!(collect(stream).await, body);
        lines.push(request_line(&requests));
        server.join().expect("the fixture thread");

        bodies.push(body);
    }

    assert_eq!(lines[0], lines[1], "save_image and save_images disagree");
    assert_eq!(lines[2], lines[3], "save_image and save_images disagree");
    assert_eq!(
        bodies,
        [b"no-platform".as_slice(), b"with-platform".as_slice()]
    );
}

/// A `None` platform sends no parameter at all, which is not the same request
/// as an empty one.
#[tokio::test]
async fn save_omits_the_platform_parameter_when_none_is_set() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]))
        .expect("valid save options");
    assert!(
        collect(stream).await.is_empty(),
        "expected collect(stream).await to be empty"
    );

    let line = request_line(&requests);
    assert_eq!(
        line,
        format!(
            "GET {}/images/alpine%3A3.20/get?names=alpine%3A3.20 HTTP/1.1",
            version_prefix()
        ),
        "a default platform changed the request"
    );
    assert!(
        !line.contains("platform="),
        "an unset platform was sent as a parameter: {line}"
    );

    server.join().expect("the fixture thread");
}

/// Empty input is refused before a connection is opened, on either route.
///
/// The endpoint here has no listener, so a path that tried to connect would
/// report `ErrorKind::Transport` instead. Validation is shared by the owned and
/// generated routes, which the fallback suite pins from outside.
#[tokio::test]
async fn save_refuses_empty_input_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );

    let error = client
        .save_images(ImageSaveOptions::default())
        .expect_err("an empty name list is refused");
    assert_eq!(error, ImageTransferError::MissingImageName);
    assert!(error.to_string().contains("at least one image name"));

    let error = client
        .save_images(ImageSaveOptions::new([""]))
        .expect_err("an empty name is refused");
    assert!(
        matches!(
            error,
            ImageTransferError::InvalidOption { name: "name", .. }
        ),
        "the refusal did not name the option: {error:?}"
    );

    let error = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/amd64/v1/extra"))
        .expect_err("a four-part platform is refused");
    assert!(
        matches!(
            error,
            ImageTransferError::InvalidOption {
                name: "platform",
                ..
            }
        ),
        "the refusal did not name the option: {error:?}"
    );
}

/// The first chunk is delivered before the archive ends.
///
/// The fixture holds the second chunk until the test acknowledges the first, so
/// an implementation that collected the body would wait for an end that only
/// arrives after the acknowledgement it is itself waiting to make. The fixture
/// closes the connection on timeout, which turns buffering into a missing second
/// chunk rather than a hung test.
#[tokio::test]
async fn save_yields_the_first_chunk_before_the_archive_finishes() {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (endpoint, _requests, server) = serve_once(move |mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"first");
        if release_rx.recv_timeout(Duration::from_secs(5)).is_err() {
            // The client did not deliver a first chunk, so it is buffering the
            // body. Close the connection: the test then fails on the missing
            // second chunk rather than blocking forever.
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        write_chunk(&mut stream, b"second");
        end_archive(&mut stream);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]))
        .expect("valid save options");

    let first = stream
        .next()
        .await
        .expect("the first chunk")
        .expect("a chunk, not an error");
    assert_eq!(first, b"first", "the first chunk arrived changed");

    release_tx.send(()).expect("release the second chunk");
    let second = stream
        .next()
        .await
        .expect("the second chunk")
        .expect("a chunk, not an error");
    assert_eq!(
        second, b"second",
        "the archive was collected instead of streamed"
    );
    assert!(
        stream.next().await.is_none(),
        "the stream did not end at the last chunk"
    );

    server.join().expect("the fixture thread");
}

/// Dropping or cancelling the handle closes the connection.
///
/// Both spellings are the same contract: the handle owns the response, and
/// releasing it releases the socket. The fixture observes the disconnect by
/// reading until end of input, which a client that merely stopped polling would
/// never produce.
#[tokio::test]
async fn save_cancels_the_transfer_when_the_handle_is_released() {
    #[derive(Clone, Copy, Debug)]
    enum Release {
        Drop,
        Cancel,
    }

    for release in [Release::Drop, Release::Cancel] {
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<bool>();
        let (endpoint, _requests, server) = serve_once(move |mut stream| {
            start_archive(&mut stream);
            write_chunk(&mut stream, b"chunk");
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
            .save_images(ImageSaveOptions::new(["alpine:3.20"]))
            .expect("valid save options");
        let chunk = stream
            .next()
            .await
            .expect("the first chunk")
            .expect("a chunk, not an error");
        assert_eq!(chunk, b"chunk", "{release:?}");

        match release {
            Release::Drop => drop(stream),
            Release::Cancel => stream.cancel(),
        }

        // Awaiting rather than blocking on a std channel is what lets the
        // runtime process the aborted connection driver. A blocking receive
        // here would hold the only runtime thread, so the socket would not be
        // dropped until the fixture's own read timeout expired.
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

/// An incomplete HTTP chunked body on the owned path is a transport error, not
/// a clean end of stream.
///
/// The daemon answered `200` and then the connection failed before the chunked
/// framing was complete. That is an incomplete **HTTP** body, and it is the only
/// truncation this method detects; a short TAR inside a complete body is a
/// different case and is pinned by the next test.
#[tokio::test]
async fn save_reports_an_incomplete_chunked_body_as_a_transport_item() {
    let (endpoint, _requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"partial");
        // No terminating chunk: the HTTP body is cut short mid-transfer.
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]))
        .expect("valid save options");
    let first = stream
        .next()
        .await
        .expect("the partial chunk")
        .expect("a chunk, not an error");
    assert_eq!(first, b"partial");

    let error = stream
        .next()
        .await
        .expect("the incomplete body is a stream item")
        .expect_err("an incomplete HTTP body is an error");
    assert_eq!(error.kind(), ErrorKind::Transport);
    assert!(
        stream.next().await.is_none(),
        "the stream did not end after the transport failure"
    );

    server.join().expect("the fixture thread");
}

/// A complete body whose bytes are not a TAR is delivered unchanged.
///
/// This is the "no TAR integrity claim" half of the contract: the save route
/// moves opaque archive bytes and never parses them. A future implementation
/// that added archive validation would fail here, which is the point — such a
/// check would report a save failure the Engine never produced, and callers that
/// stream the archive elsewhere would lose the bytes they asked for.
#[tokio::test]
async fn save_delivers_a_malformed_tar_as_bytes() {
    let (endpoint, _requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"this is not a tar header");
        write_chunk(&mut stream, b"\x00\x01trailing");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let archive = collect(
        client
            .save_images(ImageSaveOptions::new(["alpine:3.20"]))
            .expect("valid save options"),
    )
    .await;

    assert_eq!(
        archive, b"this is not a tar header\x00\x01trailing",
        "the save route changed bytes it must not interpret"
    );

    server.join().expect("the fixture thread");
}

/// A daemon rejection keeps its status and message, arrives as one item, and is
/// not retried over the generated client.
#[tokio::test]
async fn save_reports_a_rejection_and_does_not_retry() {
    let message = "no such image: missing:latest";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
    let address = listener.local_addr().expect("the fixture address");
    let (request_tx, requests) = mpsc::channel();
    let (retry_tx, retry) = mpsc::channel();
    let body = format!(r#"{{"message":"{message}"}}"#);
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept the request");
        let head = read_request_head(&mut stream);
        let _ = request_tx.send(head);
        stream.write_all(&response).expect("write the rejection");
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
                    let _ = read_request_head(&mut retry_stream);
                    let _ = retry_tx.send(());
                    let _ = retry_stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
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
    let mut stream = client
        .save_images(ImageSaveOptions::new(["missing:latest"]))
        .expect("valid save options");
    let error = stream
        .next()
        .await
        .expect("the rejection is a stream item")
        .expect_err("a 404 is an error");

    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 404);
    assert_eq!(api.message, message);
    assert!(
        stream.next().await.is_none(),
        "the stream did not end after the rejection"
    );

    assert_eq!(
        request_line(&requests),
        format!(
            "GET {}/images/missing%3Alatest/get?names=missing%3Alatest HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    let retried = retry.recv_timeout(Duration::from_millis(500)).is_ok();
    assert!(
        !retried,
        "a failed owned save request was retried through the generated client"
    );

    server.join().expect("the fixture thread");
}

/// A platform with a variant is sent as one JSON object with that member.
///
/// `variant` is omitted rather than sent empty when the caller did not name
/// one, so this pins both shapes and the percent-encoding of the JSON.
#[tokio::test]
async fn save_platform_is_sent_as_a_json_oci_object_with_its_variant() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"variant");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let stream = client
        .save_image("alpine:3.20", Some("linux/arm/v7".to_owned()))
        .expect("valid save options");
    assert_eq!(collect(stream).await, b"variant");

    let line = request_line(&requests);
    assert_eq!(
        decoded_platforms(&line),
        [serde_json::json!({"architecture": "arm", "os": "linux", "variant": "v7"})]
    );
    assert_eq!(
        line,
        format!(
            "GET {}/images/alpine%3A3.20/get?names=alpine%3A3.20&platform=%7B%22architecture%22%3A%22arm%22%2C%22os%22%3A%22linux%22%2C%22variant%22%3A%22v7%22%7D HTTP/1.1",
            version_prefix()
        ),
        "the platform JSON changed shape or lost its percent-encoding"
    );

    server.join().expect("the fixture thread");
}

/// A platform naming only an operating system is refused before connecting.
///
/// The Engine's decoder requires both `os` and `architecture`, so `linux` would
/// be a `400 both OS and Architecture must be provided` on API 1.48 and would be
/// ignored below it. The closed port turns an attempted connection into a
/// transport error, which is what this test would see if the refusal moved.
#[tokio::test]
async fn save_refuses_a_platform_without_an_architecture() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .save_image("alpine:3.20", Some("linux".to_owned()))
        .expect_err("the Engine needs both os and architecture");
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
        error.to_string().contains("os/architecture"),
        "the refusal did not name the missing part: {error}"
    );
}

/// A platform save on a client built for API 1.47 is refused before connecting.
///
/// The daemon does not reject the parameter at 1.47; it skips the whole block
/// and answers with the full multi-platform archive. Refusing here is what stops
/// that silent wrong answer. The endpoint has no listener, so an attempted
/// request would be `ErrorKind::Transport`.
#[tokio::test]
async fn save_refuses_a_platform_below_api_1_48_without_connecting() {
    let client = client_at("http://127.0.0.1:1", 47);
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/amd64"))
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
async fn save_sends_a_platform_at_exactly_api_1_48() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"at-1.48");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = client_at(&endpoint, 48);
    let stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/amd64"))
        .expect("1.48 reads the platform");
    assert_eq!(collect(stream).await, b"at-1.48");

    let line = request_line(&requests);
    assert_eq!(
        line,
        "GET /v1.48/images/alpine%3A3.20/get?names=alpine%3A3.20&platform=%7B%22architecture%22%3A%22amd64%22%2C%22os%22%3A%22linux%22%7D HTTP/1.1",
        "the exact boundary version did not send the owned platform request"
    );

    server.join().expect("the fixture thread");
}

/// The boundary only gates the platform: a save without one still works at 1.47.
#[tokio::test]
async fn save_without_a_platform_works_below_api_1_48() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"no-platform-1.47");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = client_at(&endpoint, 47);
    let stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]))
        .expect("a save without a platform is valid at every version");
    assert_eq!(collect(stream).await, b"no-platform-1.47");

    assert_eq!(
        request_line(&requests),
        "GET /v1.47/images/alpine%3A3.20/get?names=alpine%3A3.20 HTTP/1.1",
        "the version guard changed a save that asked for no platform"
    );

    server.join().expect("the fixture thread");
}

/// A formatted daemon error inside a complete `200` body is delivered as
/// archive bytes, and the writer reports success.
///
/// Moby's export handler writes `streamformatter.FormatError(err)` into the
/// response once it has been flushed, so the failure arrives as a
/// newline-terminated JSON object with a `200` status. A byte stream cannot
/// tell that from a TAR, and this crate does not parse one. The test exists so
/// the documented warning — a clean stream and an `Ok` from the writer do not
/// prove a valid archive — is pinned rather than assumed, and so nobody adds a
/// "detect the error" branch that would corrupt a legitimate archive containing
/// those bytes.
#[tokio::test]
async fn save_delivers_a_formatted_error_body_as_archive_bytes() {
    let message = "failed to export image: unexpected EOF";
    let body = format!(r#"{{"error":{{"message":"{message}"}},"errorMessage":"{message}"}}"#);
    let body = format!("{body}\n");

    let respond = |mut stream: TcpStream, body: String| {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .expect("write the formatted error body");
        stream.flush().expect("flush the formatted error body");
        let mut buffer = [0_u8; 64];
        while let Ok(read) = stream.read(&mut buffer) {
            if read == 0 {
                break;
            }
        }
    };

    let expected = body.clone();
    let (endpoint, _requests, server) = serve_once(move |stream| respond(stream, expected));
    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut stream = client
        .save_images(ImageSaveOptions::new(["alpine:3.20"]))
        .expect("valid save options");
    let mut archive = Vec::new();
    while let Some(chunk) = stream.next().await {
        archive.extend_from_slice(&chunk.expect("the error body is delivered as bytes"));
    }
    assert_eq!(
        archive,
        body.as_bytes(),
        "the formatted error body did not arrive as the archive bytes"
    );
    assert!(
        stream.next().await.is_none(),
        "the stream did not end cleanly after the error body"
    );
    drop(stream);
    server.join().expect("the fixture thread");

    // The writer path has the same blind spot: `Ok` counts bytes written, and
    // the bytes here are a daemon error, not an archive.
    let expected = body.clone();
    let (endpoint, _requests, server) = serve_once(move |stream| respond(stream, expected));
    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut output = Vec::new();
    let result = client
        .save_images_to_writer(ImageSaveOptions::new(["alpine:3.20"]), &mut output)
        .await
        .expect("the writer cannot detect an in-body error");
    assert_eq!(output, body.as_bytes());
    assert_eq!(result.bytes, body.len() as u64);
    assert!(result.chunks >= 1);
    server.join().expect("the fixture thread");
}
