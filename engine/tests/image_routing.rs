//! `DockerClient::{list_images, remove_image}` on the repository-owned
//! transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: both methods must open the
//! versioned `/v1.NN/images/...` paths through the owned transport rather than
//! the unversioned paths the generated client sends. Asserting that against a
//! request builder would only show what the builder would produce if it were
//! called; the routing decision is above it. A loopback HTTP fixture is the only
//! place the wire request and the routing are the same observation.
//!
//! # The failure each test is written to catch
//!
//! Removing either `if let Ok(engine) = self.raw_engine()` arm puts the generated
//! client back on the wire. The request line then loses the version prefix, and
//! for `remove_image` it also stops percent-encoding the reference, so the
//! comparison fails. That mutation is the reason the request line is compared
//! whole rather than only checked for one query value.
//!
//! The malformed-body tests pin the other half of the route. The owned decoder
//! is strict about known members and reports its own failure class, so a body
//! that is not an array of the expected records must fail rather than project an
//! empty value. A daemon rejection is tested separately: it keeps the status and
//! message a caller already reads through `Error::api_error()`.
//!
//! Every test reaches the public API, so none of them asserts the routing
//! decision directly, and none needs a running daemon.

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use neotales_docker::{API_VERSION, DockerClient, ErrorKind, ImageListOptions, ImageRemoveOptions};

#[path = "support/image_entries.rs"]
mod image_entries;

use image_entries::{
    LIST_BODY, MALFORMED_EXPERIMENTAL_BODY, NULL_AND_SENTINEL_BODY, REMOVE_BODY,
    REQUIRED_IMAGE_SUMMARY_MEMBERS, image_list_without_summary_member,
};

/// A one-request-at-a-time HTTP server that records the request head and then
/// waits for the client to release the connection.
///
/// The server closes the response with `Connection: close` so the generated
/// client cannot reuse the connection for the next call. Waiting for the client
/// to disconnect is what makes the fixture's `finish` a statement about the
/// client having completed, rather than about the fixture having written bytes.
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
                // The measured answer is complete once the declared body has
                // been read. Reading here observes the *connection* being
                // released, which a client that only stopped reading would
                // leave open.
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

/// Reads the request head, which is all either image request sends.
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

/// The owned path sends the versioned request with every caller option, and the
/// entries are projected onto the same `ImageSummary` the generated path made.
///
/// The whole request line is compared because that is the assertion a wrong
/// transport fails: the generated client sends `/images/json` with no version,
/// converts the filters to a `HashMap` first, and adds `manifests=false`.
#[tokio::test]
async fn list_images_sends_a_versioned_request_and_projects_entries() {
    let fixture = Fixture::start(vec![ok_json(LIST_BODY)]);
    let mut filters = BTreeMap::new();
    filters.insert(
        "label".to_owned(),
        vec!["org.example.fixture=true".to_owned()],
    );
    filters.insert("reference".to_owned(), vec!["alpine:3.22".to_owned()]);

    let images = fixture
        .client()
        .list_images(Some(ImageListOptions {
            all: true,
            shared_size: true,
            digests: true,
            filters,
        }))
        .await
        .expect("the image list decoded");

    assert_eq!(images.len(), 2);
    let first = &images[0];
    assert_eq!(first.id, "sha256:image-fixture");
    assert_eq!(first.parent_id, "");
    assert_eq!(first.repo_tags, ["registry.example/team/image:latest"]);
    assert_eq!(
        first.repo_digests,
        ["registry.example/team/image@sha256:digest-fixture"]
    );
    assert_eq!(first.created, 1_700_000_000);
    assert_eq!(first.size, 1234);
    assert_eq!(first.shared_size, 12);
    assert_eq!(
        first.labels.get("org.example.fixture").map(String::as_str),
        Some("true")
    );
    assert_eq!(first.containers, 2);

    let second = &images[1];
    assert_eq!(second.id, "sha256:untagged");
    assert_eq!(second.parent_id, "sha256:image-fixture");
    assert!(
        second.repo_tags.is_empty(),
        "expected second.repo_tags to be empty"
    );
    assert!(
        second.repo_digests.is_empty(),
        "expected second.repo_digests to be empty"
    );
    assert!(second.labels.is_empty());
    assert_eq!(second.shared_size, -1);
    assert_eq!(second.containers, -1);

    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/images/json?all=true&shared-size=true&digests=true&filters=%7B%22label%22%3A%5B%22org.example.fixture%3Dtrue%22%5D%2C%22reference%22%3A%5B%22alpine%3A3.22%22%5D%7D HTTP/1.1",
            version_prefix()
        ),
        "list_images fell back to the unversioned generated path, dropped an option, or reordered the filters"
    );

    fixture.finish();
}

/// The owned path spells the three flags even when the caller passed no options.
///
/// This is not cosmetic: a recorded request then says what it meant instead of
/// leaving it to the daemon's defaults, and `false` is what the generated client
/// sends too. The test also pins that `None` means the default options rather
/// than no request.
#[tokio::test]
async fn list_images_spells_default_flags_and_omits_filters() {
    let fixture = Fixture::start(vec![ok_json("[]")]);
    let images = fixture
        .client()
        .list_images(None)
        .await
        .expect("the empty image list decoded");
    assert!(images.is_empty(), "expected images to be empty");
    assert_eq!(
        fixture.request_line(),
        format!(
            "GET {}/images/json?all=false&shared-size=false&digests=false HTTP/1.1",
            version_prefix()
        ),
        "the default image list did not send the owned request"
    );
    fixture.finish();
}

/// Every member the generated `ImageSummary` requires is required here too.
///
/// The failure this catches is a `#[serde(default)]` on one of the scalar
/// members: a response that omits `Created`, `Size`, `SharedSize`, or
/// `Containers` would project `0`, and for the last two `0` is a real value
/// rather than "not calculated". The same applies to the three collection
/// members, which the generated helper makes required while accepting a present
/// `null`.
///
/// `Descriptor` and `Manifests` are absent from the base entry on purpose: they
/// are optional in the generated model and must stay optional here.
#[tokio::test]
async fn list_images_requires_every_member_the_generated_model_requires() {
    for member in REQUIRED_IMAGE_SUMMARY_MEMBERS {
        let body = image_list_without_summary_member(member);
        let fixture = Fixture::start(vec![ok_json(&body)]);
        let result = fixture.client().list_images(None).await;
        let error = match result {
            Ok(images) => panic!(
                "an entry without {member} decoded into {} entries",
                images.len()
            ),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput, "{member}");
        let rendered = error.to_string();
        assert!(
            rendered.contains("data error"),
            "the refusal did not report a data error for {member}: {rendered}"
        );
        assert!(rendered.contains("line"), "{rendered}");
        assert!(rendered.contains("column"), "{rendered}");
        fixture.finish();
    }
}

/// The Engine's present-`null` collections decode as empty, and both
/// "not calculated" sentinels survive projection.
///
/// `null` is not a missing member: the generated helpers accept it, so the owned
/// decoder must too. `-1` is the daemon's statement that it did not calculate
/// `SharedSize` or `Containers`; turning it into `0` would report a measured
/// value that was never measured.
#[tokio::test]
async fn list_images_accepts_null_collections_and_carries_sentinels() {
    let fixture = Fixture::start(vec![ok_json(NULL_AND_SENTINEL_BODY)]);
    let images = fixture
        .client()
        .list_images(None)
        .await
        .expect("a valid entry with null collections and sentinels decoded");
    assert_eq!(images.len(), 1);
    let image = &images[0];
    assert_eq!(image.id, "sha256:sentinel");
    assert_eq!(image.parent_id, "sha256:image-fixture");
    assert!(
        image.repo_tags.is_empty(),
        "expected image.repo_tags to be empty"
    );
    assert!(
        image.repo_digests.is_empty(),
        "expected image.repo_digests to be empty"
    );
    assert!(image.labels.is_empty());
    assert_eq!(image.shared_size, -1);
    assert_eq!(image.containers, -1);
    fixture.finish();
}

/// Experimental members the projection does not model are ignored even when
/// their JSON type would fail the generated decoder.
///
/// The generated fallback has typed `Descriptor` and `Manifests` members; the
/// owned projection has neither. This body therefore succeeds here and fails
/// on the fallback, which the fallback suite pins. The difference is documented
/// on `DockerClient::list_images` because a caller can observe it.
#[tokio::test]
async fn list_images_ignores_malformed_experimental_members() {
    let fixture = Fixture::start(vec![ok_json(MALFORMED_EXPERIMENTAL_BODY)]);
    let images = fixture
        .client()
        .list_images(None)
        .await
        .expect("the owned projection ignores Descriptor and Manifests");
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].id, "sha256:image-fixture");
    fixture.finish();
}

#[tokio::test]
async fn remove_image_sends_a_versioned_escaped_request_and_projects_records() {
    let fixture = Fixture::start(vec![ok_json(REMOVE_BODY)]);
    let records = fixture
        .client()
        .remove_image(
            "registry.example/team/image:latest",
            Some(ImageRemoveOptions {
                force: true,
                no_prune: true,
            }),
        )
        .await
        .expect("the delete records decoded");

    assert_eq!(records.len(), 3);
    assert_eq!(
        records[0].untagged.as_deref(),
        Some("registry.example/team/image:latest")
    );
    assert_eq!(records[0].deleted, None);
    assert_eq!(records[1].untagged, None);
    assert_eq!(records[1].deleted.as_deref(), Some("sha256:image-fixture"));
    assert_eq!(records[2].untagged.as_deref(), Some("image:latest"));
    assert_eq!(records[2].deleted.as_deref(), Some("sha256:image-fixture"));

    assert_eq!(
        fixture.request_line(),
        format!(
            "DELETE {}/images/registry.example%2Fteam%2Fimage%3Alatest?force=true&noprune=true HTTP/1.1",
            version_prefix()
        ),
        "remove_image fell back to the generated path, or stopped encoding the reference"
    );

    fixture.finish();
}

/// The two flags are spelled even when they are false.
#[tokio::test]
async fn remove_image_spells_default_flags() {
    let fixture = Fixture::start(vec![ok_json("[]")]);
    let records = fixture
        .client()
        .remove_image("fixture", None)
        .await
        .expect("the empty delete record list decoded");
    assert!(records.is_empty(), "expected records to be empty");
    assert_eq!(
        fixture.request_line(),
        format!(
            "DELETE {}/images/fixture?force=false&noprune=false HTTP/1.1",
            version_prefix()
        ),
        "the default delete did not send the owned request"
    );
    fixture.finish();
}

/// A success body that is not an image array is a decode failure, and it is the
/// owned decoder's class rather than an empty list.
///
/// This is the one error class that moves with the routing: the generated client
/// reported a malformed body as `ErrorKind::Docker`, while the owned decoder
/// reports `ErrorKind::InvalidInput`. That difference is documented on
/// `DockerClient::list_images`; the test pins it so it cannot drift unnoticed.
#[tokio::test]
async fn list_images_rejects_a_success_body_that_is_not_an_array() {
    let fixture = Fixture::start(vec![ok_json(r#"{"message":"not a list"}"#)]);
    let error = fixture
        .client()
        .list_images(None)
        .await
        .expect_err("an object is not an image array");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("failed to decode"),
        "the refusal did not name the decode: {error}"
    );
    fixture.finish();
}

/// A known member with the wrong JSON type fails the entry instead of being read
/// as an absent value.
#[tokio::test]
async fn list_images_rejects_a_mistyped_known_member() {
    let fixture = Fixture::start(vec![ok_json(r#"[{"Id":7}]"#)]);
    let error = fixture
        .client()
        .list_images(None)
        .await
        .expect_err("a numeric Id is not an image summary");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let rendered = error.to_string();
    assert!(
        rendered.contains("data error"),
        "the refusal did not report a data error: {rendered}"
    );
    assert!(rendered.contains("line"), "{rendered}");
    assert!(rendered.contains("column"), "{rendered}");
    fixture.finish();
}

/// A daemon rejection keeps the status and the daemon's own message, and the
/// request that produced it is still the owned one.
#[tokio::test]
async fn remove_image_reports_a_daemon_rejection_with_its_status_and_message() {
    let message = "conflict: unable to delete sha256:image-fixture (must be forced)";
    let fixture = Fixture::start(vec![rejected(
        "409 Conflict",
        &format!(r#"{{"message":"{message}"}}"#),
    )]);
    let error = fixture
        .client()
        .remove_image("fixture", None)
        .await
        .expect_err("a 409 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 409);
    assert_eq!(api.message, message);
    assert_eq!(
        fixture.request_line(),
        format!(
            "DELETE {}/images/fixture?force=false&noprune=false HTTP/1.1",
            version_prefix()
        ),
        "the error path must be the owned request, not the generated one"
    );
    fixture.finish();
}

/// A success body that is not a delete-record array fails rather than projecting
/// an empty result.
#[tokio::test]
async fn remove_image_rejects_a_success_body_that_is_not_a_record_array() {
    let fixture = Fixture::start(vec![ok_json(r#"{"Untagged":"not-an-array"}"#)]);
    let error = fixture
        .client()
        .remove_image("fixture", None)
        .await
        .expect_err("an object is not a delete-record array");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("failed to decode"),
        "the refusal did not name the decode: {error}"
    );
    fixture.finish();
}

/// An empty reference is refused before a connection is opened.
///
/// The generated client sent `DELETE /images/` and reported the daemon's answer.
/// The owned path refuses locally, which is a deliberate difference documented
/// on `DockerClient::remove_image`. The endpoint here has no listener, so a path
/// that tried to connect would report `ErrorKind::Transport` instead.
#[tokio::test]
async fn remove_image_refuses_an_empty_reference_without_connecting() {
    let client = DockerClient::connect_http("http://127.0.0.1:1").expect("build the client");
    assert!(
        client.raw_engine().is_ok(),
        "the test must exercise the owned path"
    );
    let error = client
        .remove_image("", None)
        .await
        .expect_err("an empty reference is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error.to_string().contains("must not be empty"),
        "the refusal did not name the reference: {error}"
    );
}
