//! `DockerClient::system_events` on the repository-owned event transport.
//!
//! # Why a loopback fixture and not a unit assertion
//!
//! The claim this file pins is a *transport* claim: `system_events` must open
//! `GET /v1.NN/events` through the owned transport, not the unversioned path the
//! generated client sends. Asserting that against a request builder would only
//! show what the builder would produce if it were called; the routing decision
//! is above it. A loopback HTTP fixture is the only place the wire request and
//! the routing are the same observation.
//!
//! The fixture answers once and keeps the connection open until the client
//! drops the response handle. That second half is not incidental: it is how the
//! cancellation assertion sees the handle close the socket rather than merely
//! stop yielding items.
//!
//! # The failure each test is written to catch
//!
//! Removing the `if let Ok(engine) = self.raw_engine()` arm from
//! `system_events` puts the generated client back on the wire. The first
//! assertion then fails because Bollard sends `/events`, not
//! `/v1.NN/events`. That mutation is the reason the request line is compared
//! whole rather than only checked for a `filters` value.
//!
//! The malformed-member test is the other half. The owned projection replaced a
//! typed decode, so a known member with the wrong JSON type must be an error
//! item rather than a silently absent member, and the stream must resume at the
//! next record after that refusal.
//!
//! Every test is a regression test for behaviour a caller reaches through the
//! public API, so none of them reaches into the routing decision itself.

#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use neotales_docker::{API_VERSION, DockerClient, ErrorKind, EventOptions};

/// The daemon's own event spelling, recorded from Docker Engine 29.8.0.
///
/// `Type`, `Action`, and `Actor` are capitalized while `scope`, `time`, and
/// `timeNano` are not, and the actor's members are `ID` and `Attributes`. A
/// casing rule would lose three of the six members, which is why this is the
/// literal shape rather than a tidy one.
const EVENTS: &str = concat!(
    r#"{"Type":"container","Action":"start","Actor":{"ID":"c1","Attributes":{"image":"alpine:3.22","name":"web"}},"scope":"local","time":1790404280,"timeNano":1790404280887841738}"#,
    "\n",
    r#"{"Type":"network","Action":"create","Actor":{"ID":"n1","Attributes":{"name":"evprobe1","type":"bridge"}},"scope":"local","time":1790404281,"timeNano":1790404281887841738}"#,
    "\n",
);

/// One malformed record per known member, then an all-null record, then a valid
/// event.
///
/// The wrong-type records are the regression: the projection must return an
/// error naming the member rather than reading it as absent, which is what an
/// infallible projection did. The all-null record pins the other side of the
/// rule — `null` is the generated model's `Option::None`, not a malformed value
/// — and the final record proves the stream recovered after every refusal.
const MALFORMED_EVENTS: &str = concat!(
    r#"{"Type":1}"#,
    "\n",
    r#"{"Action":false}"#,
    "\n",
    r#"{"scope":[]}"#,
    "\n",
    r#"{"time":"now"}"#,
    "\n",
    r#"{"timeNano":1.5}"#,
    "\n",
    r#"{"Actor":"c1"}"#,
    "\n",
    r#"{"Actor":{"ID":7}}"#,
    "\n",
    r#"{"Actor":{"Attributes":[]}}"#,
    "\n",
    r#"{"Actor":{"Attributes":{"name":42}}}"#,
    "\n",
    r#"{"Type":null,"Action":null,"Actor":null,"scope":null,"time":null,"timeNano":null}"#,
    "\n",
    r#"{"Type":"container","Action":"start","Actor":{"ID":"c1","Attributes":{"name":"web"}},"scope":"local","time":1790404280,"timeNano":1790404280887841738}"#,
    "\n",
);

/// A one-request HTTP server that records the request and then waits for the
/// client to close the connection.
struct Fixture {
    endpoint: String,
    request: Receiver<String>,
    disconnected: tokio::sync::oneshot::Receiver<()>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn start(response: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture");
        let address = listener.local_addr().expect("the fixture address");
        let (request_tx, request) = mpsc::channel();
        let (disconnected_tx, disconnected) = tokio::sync::oneshot::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept the event request");
            let head = read_request_head(&mut stream);
            let _ = request_tx.send(head);
            stream.write_all(&response).expect("write the event answer");
            stream.flush().expect("flush the event answer");

            // The response declares its length, so the client has the whole
            // body already. Reading here observes the *connection* being
            // released when the handle is dropped, which a client that only
            // stopped polling would leave open.
            let mut buffer = [0_u8; 64];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
            }
            let _ = disconnected_tx.send(());
        });
        Self {
            endpoint: format!("http://{address}"),
            request,
            disconnected,
            server,
        }
    }

    fn client(&self) -> DockerClient {
        DockerClient::connect_http(&self.endpoint).expect("build the fixture client")
    }

    fn request_line(&self) -> String {
        self.request
            .recv_timeout(Duration::from_secs(10))
            .expect("the fixture recorded no request")
            .lines()
            .next()
            .expect("the request has a request line")
            .to_owned()
    }

    async fn finish(self) {
        self.disconnected
            .await
            .expect("the client did not close the event connection");
        self.server.join().expect("the fixture thread");
    }
}

/// Reads the request head, which is all an events request sends.
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

/// An ordinary `200` with the records as its body.
fn ok_stream(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The version prefix the owned transport is expected to send.
fn version_prefix() -> String {
    format!("/v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// The owned path sends the versioned request with every caller option, and the
/// records are projected onto the same `SystemEvent` the generated path made.
///
/// The whole request line is compared because that is the assertion a wrong
/// transport fails: the generated client sends `/events` with no version.
#[tokio::test]
async fn system_events_sends_a_versioned_request_and_projects_records() {
    let fixture = Fixture::start(ok_stream(EVENTS));
    let client = fixture.client();
    let options = EventOptions::new()
        .with_since("1790404280")
        .with_until("1790404290")
        .with_filter("type", ["container"]);

    let mut events = client.system_events(Some(options));
    let first = events
        .next()
        .await
        .expect("the first event")
        .expect("the first event decoded");
    assert_eq!(first.resource_type.as_deref(), Some("container"));
    assert_eq!(first.action.as_deref(), Some("start"));
    assert_eq!(first.scope.as_deref(), Some("local"));
    assert_eq!(first.time, Some(1_790_404_280));
    assert_eq!(first.time_nano, Some(1_790_404_280_887_841_738));
    let actor = first.actor.expect("the event actor");
    assert_eq!(actor.id.as_deref(), Some("c1"));
    assert_eq!(
        actor.attributes.get("name").map(String::as_str),
        Some("web")
    );
    assert_eq!(
        actor.attributes.get("image").map(String::as_str),
        Some("alpine:3.22")
    );

    let second = events
        .next()
        .await
        .expect("the second event")
        .expect("the second event decoded");
    assert_eq!(second.resource_type.as_deref(), Some("network"));
    assert_eq!(second.action.as_deref(), Some("create"));

    let expected = format!(
        "GET {}/events?since=1790404280&until=1790404290&filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1",
        version_prefix()
    );
    assert_eq!(
        fixture.request_line(),
        expected,
        "system_events fell back to the unversioned generated path, or dropped an option"
    );

    events.cancel();
    fixture.finish().await;
}

/// A known member with the wrong JSON type is an error item, not an absent
/// member, and the stream continues at the next record.
///
/// This is the regression the reviewer asked for. The owned path replaced a
/// decode into the generated `EventMessage`, so a `Type` number or a non-string
/// `Actor.Attributes` value has to fail the record the way that decode did. The
/// test also pins `null` as absence, which is what the generated model's
/// `Option` fields mean, and proves the frame reader is not left desynchronised
/// after a refusal: the next record is a valid event.
#[tokio::test]
async fn system_events_rejects_malformed_known_fields_and_recovers() {
    let fixture = Fixture::start(ok_stream(MALFORMED_EVENTS));
    let client = fixture.client();
    let mut events = client.system_events(None);

    for member in [
        "`Type`",
        "`Action`",
        "`scope`",
        "`time`",
        "`timeNano`",
        "`Actor`",
        "`Actor.ID`",
        "`Actor.Attributes`",
        "`Actor.Attributes`",
    ] {
        let error = events
            .next()
            .await
            .expect("a malformed record is an item")
            .expect_err("a malformed known member must be an error item");
        assert_eq!(
            error.kind(),
            ErrorKind::Serialization,
            "the refusal was not the decode error for {member}: {error:?}"
        );
        assert!(
            std::error::Error::source(&error)
                .expect("the decoding reason")
                .to_string()
                .contains(member),
            "the refusal did not name {member}: {error}"
        );
    }

    let absent = events
        .next()
        .await
        .expect("the all-null record is an item")
        .expect("null is absence, not a malformed value");
    assert_eq!(absent.resource_type, None);
    assert_eq!(absent.action, None);
    assert_eq!(absent.actor, None);
    assert_eq!(absent.scope, None);
    assert_eq!(absent.time, None);
    assert_eq!(absent.time_nano, None);

    let recovered = events
        .next()
        .await
        .expect("the last record is an item")
        .expect("the stream recovered after the refusals");
    assert_eq!(recovered.resource_type.as_deref(), Some("container"));
    assert_eq!(recovered.action.as_deref(), Some("start"));

    events.cancel();
    fixture.finish().await;
}

#[tokio::test]
async fn owned_events_preserve_unknown_values_and_continue() {
    let fixture = Fixture::start(ok_stream(concat!(
        "{\"Type\":\"new-kind\"}\n",
        "{\"scope\":\"new-scope\"}\n",
        "{\"Action\":\"after\"}\n",
    )));
    let mut events = fixture.client().system_events(None);
    assert_eq!(
        events
            .next()
            .await
            .unwrap()
            .unwrap()
            .resource_type
            .as_deref(),
        Some("new-kind")
    );
    assert_eq!(
        events.next().await.unwrap().unwrap().scope.as_deref(),
        Some("new-scope")
    );
    assert_eq!(
        events.next().await.unwrap().unwrap().action.as_deref(),
        Some("after")
    );
    events.cancel();
    fixture.finish().await;
}

#[tokio::test]
async fn owned_events_report_oversized_record_and_recover() {
    let body = format!(
        "{{\"Action\":\"{}\"}}\n{{\"Action\":\"after\"}}\n",
        "x".repeat(neotales_docker::raw::MAX_RECORD_BYTES)
    );
    let fixture = Fixture::start(ok_stream(&body));
    let mut events = fixture.client().system_events(None);
    let error = events.next().await.unwrap().unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("limit"));
    assert_eq!(
        events.next().await.unwrap().unwrap().action.as_deref(),
        Some("after")
    );
    events.cancel();
    fixture.finish().await;
}

/// A daemon rejection arrives as one stream item, carrying the daemon's own
/// message, and the request is still the owned one.
///
/// The status is not hidden behind end-of-stream: the generated path reported
/// this as an item too, and a caller that only sees `None` cannot tell a
/// rejected subscription from an ended one.
#[tokio::test]
async fn system_events_reports_a_daemon_rejection_as_a_stream_item() {
    let body = r#"{"message":"invalid filter 'nope'"}"#;
    let fixture = Fixture::start(
        format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let client = fixture.client();

    let mut events = client.system_events(None);
    let error = events
        .next()
        .await
        .expect("a rejection is an item")
        .expect_err("a 400 must be an error item");
    let api = error.api_error().expect("the daemon's own rejection");
    assert_eq!(api.status_code, 400);
    assert_eq!(api.message, "invalid filter 'nope'");
    assert!(
        events.next().await.is_none(),
        "the failure is reported once, then the stream ends"
    );
    assert_eq!(
        fixture.request_line(),
        format!("GET {}/events HTTP/1.1", version_prefix()),
        "the error path must be the owned request, not the generated one"
    );

    events.cancel();
    fixture.finish().await;
}

/// Dropping the handle releases the response and closes the connection.
///
/// The fixture declares the body's length but keeps the socket open, so
/// reaching end-of-body is not what makes the server see a disconnect. Only
/// dropping the handle does, which is the owned transport's cancellation
/// contract: ownership of the response is ownership of the connection.
#[tokio::test]
async fn dropping_system_events_closes_the_connection() {
    let fixture = Fixture::start(ok_stream(EVENTS));
    let client = fixture.client();

    let mut events = client.system_events(None);
    let event = events
        .next()
        .await
        .expect("the first event")
        .expect("the first event decoded");
    assert_eq!(event.action.as_deref(), Some("start"));

    drop(events);
    fixture.finish().await;
}

/// The error a transport failure reports is still an `Error`, not a panic or an
/// empty stream.
///
/// This is the case a caller has no other way to observe: the handle is created
/// without connecting, so the failure exists only as the first item. The fixture
/// is dropped before the request is polled, which leaves no listener.
#[tokio::test]
async fn a_transport_failure_is_a_stream_item() {
    let endpoint = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("pick a free port");
        let address = listener.local_addr().expect("the free address");
        // Dropping the listener is what makes the connect fail. The port is
        // still the one this test asks for, which is why it is selected by the
        // operating system rather than written down.
        drop(listener);
        format!("http://{address}")
    };
    let client = DockerClient::connect_http(&endpoint).expect("build the client");

    let mut events = client.system_events(None);
    let error = events
        .next()
        .await
        .expect("a failed request is an item")
        .expect_err("a closed port must fail the subscription");
    assert!(
        std::error::Error::source(&error).is_some(),
        "the transport reason must remain reachable: {error:?}"
    );
    assert!(events.next().await.is_none());
}
