//! `DockerClient::export_container` on the repository-owned transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claims this file pins are transport claims: the archive must open the
//! versioned `GET /v1.NN/containers/{id}/export` path through the owned
//! transport, the container reference must be one escaped path segment, and the
//! answer must arrive as transport chunks rather than as one collected buffer.
//! Asserting any of those against a request builder would only show what the
//! builder would produce if it were called; the routing decision is above it. A
//! loopback HTTP fixture is the only place the wire request, the streaming
//! behaviour, and the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `export_container` puts the generated client back on the wire. The request
//! line then loses the version prefix and stops percent-encoding the reference,
//! so the whole-line comparison fails.
//!
//! The streaming test is deliberately written so a facade that collected the
//! body before yielding its first item cannot pass: the fixture holds the second
//! chunk until the test has received the first one, and closes the connection
//! if that acknowledgement does not arrive. A buffering implementation therefore
//! either hangs until the fixture gives up or loses the second chunk, and the
//! assertion on the second chunk fails either way.
//!
//! The cancellation test is about ownership rather than a protocol. The fixture
//! writes one chunk and then reads; the only thing that makes that read end is
//! the client releasing the response, which closes the socket.
//!
//! The incomplete-chunked-body test pins the other half of the error contract
//! on the owned path: a daemon that answered `200` and then dropped the
//! connection before the chunked framing was complete is a transport failure
//! item, not a clean end of stream. That detects an incomplete **HTTP** body,
//! not a short TAR inside a complete body; archive integrity is not validated.
//! The fallback suite pins the same incomplete body as a `Docker` item, because
//! that is the class every Bollard stream error carries.
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

use neotales_docker::{API_VERSION, DockerClient, ErrorKind};

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

/// Reads the request head, which is all an export request sends.
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

/// The owned path sends the versioned, escaped request and yields the archive
/// bytes the daemon wrote.
#[tokio::test]
async fn export_sends_a_versioned_escaped_request_and_yields_the_archive() {
    let (endpoint, requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"first");
        write_chunk(&mut stream, b"-second");
        end_archive(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut stream = client.export_container("a/b");
    let mut archive = Vec::new();
    while let Some(chunk) = stream.next().await {
        archive.extend_from_slice(&chunk.expect("the archive chunk"));
    }
    drop(stream);

    assert_eq!(archive, b"first-second");
    let line = requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the fixture recorded no request")
        .lines()
        .next()
        .expect("the request has a request line")
        .to_owned();
    assert_eq!(
        line,
        format!("GET {}/containers/a%2Fb/export HTTP/1.1", version_prefix()),
        "export_container fell back to the unversioned generated path or stopped escaping the reference"
    );

    server.join().expect("the fixture thread");
}

/// The first chunk is delivered before the archive ends.
///
/// The fixture holds the second chunk until the test acknowledges the first, so
/// an implementation that collected the body would wait for an end that only
/// arrives after the acknowledgement it is itself waiting to make. The fixture
/// closes the connection on timeout, which turns the buffering into a missing
/// second chunk rather than a hung test.
#[tokio::test]
async fn export_yields_the_first_chunk_before_the_archive_finishes() {
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
    let mut stream = client.export_container("web");

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
async fn export_cancels_the_transfer_when_the_handle_is_released() {
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
        let mut stream = client.export_container("web");
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
/// framing was complete, so this is a transport failure rather than a
/// rejection. The stream ends after reporting it. A TAR that is short inside a
/// complete HTTP body is not detected here, because archive integrity is not
/// validated.
#[tokio::test]
async fn export_reports_an_incomplete_chunked_body_as_a_transport_item() {
    let (endpoint, _requests, server) = serve_once(|mut stream| {
        start_archive(&mut stream);
        write_chunk(&mut stream, b"partial");
        // No terminating chunk: the HTTP body is cut short mid-transfer.
        let _ = stream.shutdown(Shutdown::Both);
    });

    let client = DockerClient::connect_http(&endpoint).expect("build the fixture client");
    let mut stream = client.export_container("web");
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

/// A daemon rejection keeps its status and message, arrives as one item, and is
/// not retried over the generated client.
#[tokio::test]
async fn export_reports_a_rejection_and_does_not_retry() {
    let message = "No such container: missing";
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
    let mut stream = client.export_container("missing");
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

    let line = requests
        .recv_timeout(Duration::from_secs(10))
        .expect("the fixture recorded no request")
        .lines()
        .next()
        .expect("the request has a request line")
        .to_owned();
    assert_eq!(
        line,
        format!(
            "GET {}/containers/missing/export HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    let retried = retry.recv_timeout(Duration::from_millis(500)).is_ok();
    assert!(
        !retried,
        "a failed owned export request was retried through the generated client"
    );

    server.join().expect("the fixture thread");
}

/// An empty reference is refused before a connection is opened.
///
/// The endpoint here has no listener, so an implementation that tried to
/// connect would report `ErrorKind::Transport` instead.
#[tokio::test]
async fn export_refuses_an_empty_reference_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );

    let mut stream = client.export_container("");
    let error = stream
        .next()
        .await
        .expect("the refusal is a stream item")
        .expect_err("an empty reference is refused");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
    assert!(
        stream.next().await.is_none(),
        "the stream did not end after the refusal"
    );
}
