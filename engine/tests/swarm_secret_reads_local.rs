//! Exercise `connect_local`'s captured local endpoint for secret reads.
//!
//! `connect_local` reads `DOCKER_HOST` once and builds the generated client and
//! the captured owned target from the same socket. General
//! `DockerClient::raw_engine` routing still reports the constructor as
//! unreachable, so every other operation keeps its existing fallback behavior;
//! a secret read uses the captured socket because it has no safe generated
//! fallback. The requests on the wire are therefore the owned versioned ones,
//! not Bollard's unversioned ones.
//!
//! The child process is needed because `DOCKER_HOST` is process-wide. It points
//! the local endpoint at a Unix socket this test owns, so no daemon is involved
//! and nothing outside the temporary directory is touched.

#![cfg(unix)]
#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use neotales_docker::{API_VERSION, DockerClient, ErrorKind, SecretListOptions};

#[path = "support/swarm_secret_entries.rs"]
mod swarm_secret_entries;

use swarm_secret_entries::{
    MALFORMED_BODY, SECRET_BODY, SECRET_BODY_WITH_DATA, SECRET_BODY_WITH_DUPLICATE_DATA,
    SECRET_BODY_WITH_DUPLICATE_ID, SECRET_BODY_WITH_NULL_DATA, SECRET_BODY_WITH_OBJECT_DATA,
    SECRET_DATA_BASE64, SECRET_DATA_CANARY, SECRET_ID, WRONG_TYPE_BODY, secrets_body,
};

#[test]
fn public_local_owned_contract() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "local_worker", "--ignored", "--nocapture"])
        .env("DOCKER_HOST", format!("unix://{}", socket.display()))
        .env("SWARM_SECRET_READS_TEST_SOCKET", &socket)
        .spawn()
        .expect("spawn the local worker");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        match child.try_wait().expect("poll the local worker") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                // Best-effort termination after the supervision budget. This is
                // a normal kill plus reap, not an absolute kernel guarantee; the
                // worker's own total budget and fixture budget normally end it
                // first.
                let _ = child.kill();
                let status = child.wait().expect("reap the local worker");
                panic!("the local worker exceeded its 60s supervision budget: {status}");
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    };
    assert!(status.success());
}

#[tokio::test]
#[ignore = "run in a child with an isolated DOCKER_HOST"]
async fn local_worker() {
    tokio::time::timeout(Duration::from_secs(45), local_worker_body())
        .await
        .expect("the local worker exceeded its 45s total budget");
}

async fn local_worker_body() {
    let listener =
        UnixListener::bind(std::env::var_os("SWARM_SECRET_READS_TEST_SOCKET").unwrap()).unwrap();
    listener
        .set_nonblocking(true)
        .expect("make the local fixture listener nonblocking");
    let secrets = secrets_body();
    let filtered_filters = r#"{"id":["secret-fixture"],"label":["org.example.secret=fixture"],"name":["fixture-secret"]}"#;
    let mut filtered_query = url::form_urlencoded::Serializer::new(String::new());
    filtered_query.append_pair("filters", filtered_filters);
    let filtered_target = format!("/secrets?{}", filtered_query.finish());

    let server = thread::spawn(move || serve_local(&listener, secrets, &filtered_target));

    let client = DockerClient::connect_local().unwrap();
    assert!(
        client.raw_engine().is_ok(),
        "general routing still reports the local constructor as unreachable"
    );

    let secrets = client
        .list_secrets(None)
        .await
        .expect("the local owned list decoded");
    assert_eq!(secrets.len(), 1);
    assert_owned_shape(&secrets[0]);

    let mut filters = std::collections::BTreeMap::new();
    filters.insert("id".to_owned(), vec![SECRET_ID.to_owned()]);
    filters.insert(
        "label".to_owned(),
        vec!["org.example.secret=fixture".to_owned()],
    );
    filters.insert("name".to_owned(), vec!["fixture-secret".to_owned()]);
    client
        .list_secrets(Some(SecretListOptions { filters }))
        .await
        .expect("the filtered local list decoded");

    let secret = client
        .inspect_secret(SECRET_ID)
        .await
        .expect("the local owned document decoded");
    assert_eq!(secret.id.as_deref(), Some(SECRET_ID));

    let secret = client
        .inspect_secret(SECRET_ID)
        .await
        .expect("the string Data was retained");
    assert_owned_data(&secret, &serde_json::json!(SECRET_DATA_BASE64));

    let error = client
        .inspect_secret("")
        .await
        .expect_err("an empty reference is refused before dispatch");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    exercise_rejections(&client).await;
    exercise_retention(&client).await;

    server.join().unwrap();
}

/// The malformed, wrong-typed, and API-rejection cases, in wire order.
async fn exercise_rejections(client: &DockerClient) {
    for _ in [MALFORMED_BODY, WRONG_TYPE_BODY] {
        let error = client
            .inspect_secret(SECRET_ID)
            .await
            .expect_err("a malformed document is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        for rendering in error_renderings(&error) {
            assert_no_canary(&rendering);
        }
    }

    let error = client
        .inspect_secret(SECRET_ID)
        .await
        .expect_err("a 404 is an error");
    assert_eq!(error.kind(), ErrorKind::Docker);
    let api = error.api_error().expect("the status is preserved");
    assert_eq!(api.status_code, 404);
    assert_eq!(
        api.message,
        "the secret read failed; the Engine response text is withheld"
    );
    for rendering in error_renderings(&error) {
        assert_no_canary(&rendering);
    }
}

/// The owned `Data` shapes, in wire order.
async fn exercise_retention(client: &DockerClient) {
    let secret = client
        .inspect_secret(SECRET_ID)
        .await
        .expect("null Data is retained on the owned path");
    assert_owned_data(&secret, &serde_json::Value::Null);

    let secret = client
        .inspect_secret(SECRET_ID)
        .await
        .expect("object Data is retained on the owned path");
    assert_owned_data(&secret, &serde_json::json!({"canary": SECRET_DATA_CANARY}));

    let secret = client
        .inspect_secret(SECRET_ID)
        .await
        .expect("duplicate unmodelled Data collapses to one value");
    assert_owned_data(&secret, &serde_json::json!(SECRET_DATA_BASE64));

    let error = client
        .inspect_secret(SECRET_ID)
        .await
        .expect_err("a duplicate known key is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    for rendering in error_renderings(&error) {
        assert_no_canary(&rendering);
    }

    let secrets = client
        .list_secrets(None)
        .await
        .expect("null Data in a list is retained");
    assert_owned_data(&secrets[0], &serde_json::Value::Null);

    let secrets = client
        .list_secrets(None)
        .await
        .expect("object Data in a list is retained");
    assert_owned_data(
        &secrets[0],
        &serde_json::json!({"canary": SECRET_DATA_CANARY}),
    );
}

/// The owned shape: unmodelled object-level members survive.
fn assert_owned_shape(secret: &neotales_docker::SwarmSecret) {
    assert_eq!(secret.id.as_deref(), Some(SECRET_ID));
    assert!(
        secret.additional.contains_key("UnmodelledMember"),
        "the owned path discarded an unmodelled top-level member"
    );
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(spec.name.as_deref(), Some("fixture-secret"));
    assert!(
        spec.additional.contains_key("UnmodelledSpecMember"),
        "the owned path discarded an unmodelled spec member"
    );
}

/// The owned route retains whatever JSON value the peer sent under `Data`.
fn assert_owned_data(secret: &neotales_docker::SwarmSecret, expected: &serde_json::Value) {
    let spec = secret.spec.as_ref().expect("the daemon sent a spec");
    assert_eq!(
        spec.additional.get("Data"),
        Some(expected),
        "the owned path did not retain {expected} Data"
    );
    assert_no_canary(&format!("{secret:?}"));
}

/// Renders the whole `Display`/`Debug`/source chain of an error.
fn error_renderings(error: &neotales_docker::Error) -> Vec<String> {
    let mut renderings = vec![error.to_string(), format!("{error:?}")];
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        renderings.push(cause.to_string());
        renderings.push(format!("{cause:?}"));
        source = cause.source();
    }
    renderings
}

/// Asserts a rendering carries neither the text nor the base64 canary.
fn assert_no_canary(rendered: &str) {
    assert!(
        !rendered.contains(SECRET_DATA_CANARY),
        "a rendering leaked the secret canary: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET_DATA_BASE64),
        "a rendering leaked the base64 canary: {rendered}"
    );
}

/// Answers the exact local request sequence the worker makes.
fn serve_local(listener: &UnixListener, secrets: String, filtered_target: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let prefix = format!("/v{}.{}", API_VERSION.major, API_VERSION.minor);
    let secret_target = format!("{prefix}/secrets/{SECRET_ID}");
    // Each entry is (expected request target, response status, body).
    let entries = [
        (format!("{prefix}/secrets"), "200 OK", secrets.clone()),
        (format!("{prefix}{filtered_target}"), "200 OK", secrets),
        (secret_target.clone(), "200 OK", SECRET_BODY.to_owned()),
        (
            secret_target.clone(),
            "200 OK",
            SECRET_BODY_WITH_DATA.to_owned(),
        ),
        (secret_target.clone(), "200 OK", MALFORMED_BODY.to_owned()),
        (secret_target.clone(), "200 OK", WRONG_TYPE_BODY.to_owned()),
        (
            secret_target.clone(),
            "404 Not Found",
            format!(r#"{{"message":"secret {SECRET_ID} not found {SECRET_DATA_CANARY}"}}"#),
        ),
        (
            secret_target.clone(),
            "200 OK",
            SECRET_BODY_WITH_NULL_DATA.to_owned(),
        ),
        (
            secret_target.clone(),
            "200 OK",
            SECRET_BODY_WITH_OBJECT_DATA.to_owned(),
        ),
        (
            secret_target.clone(),
            "200 OK",
            SECRET_BODY_WITH_DUPLICATE_DATA.to_owned(),
        ),
        (
            secret_target.clone(),
            "200 OK",
            SECRET_BODY_WITH_DUPLICATE_ID.to_owned(),
        ),
        (
            format!("{prefix}/secrets"),
            "200 OK",
            format!("[{SECRET_BODY_WITH_NULL_DATA}]"),
        ),
        (
            format!("{prefix}/secrets"),
            "200 OK",
            format!("[{SECRET_BODY_WITH_OBJECT_DATA}]"),
        ),
    ];
    for (target, status, body) in entries {
        let mut stream = accept_within(listener, deadline).expect("the local fixture timed out");
        let head = read_request_head(&mut stream, deadline);
        let line = head.lines().next().expect("the request line");
        assert_eq!(
            line.split_whitespace().nth(1),
            Some(target.as_str()),
            "the local owned request line changed: {line}"
        );
        assert!(
            line.contains("/v1."),
            "the local owned request lost its version prefix: {line}"
        );
        respond_json(&mut stream, status, &body, deadline);
    }
}

/// Accepts one connection within a bounded window and bounds its reads/writes.
///
/// A failed worker must not leave the fixture thread blocked in `accept` or a
/// read, because the parent joins that thread and a hang would hold the test
/// open. The deadline is generous relative to the loopback operations and short
/// enough that a broken worker fails the child rather than hanging it.
fn accept_within(listener: &UnixListener, deadline: Instant) -> Option<UnixStream> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_read_timeout(Some(remaining));
                let _ = stream.set_write_timeout(Some(remaining));
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(remaining.min(Duration::from_millis(20)));
            }
            Err(_) => return None,
        }
    }
}

/// Writes an answer carrying `body` and waits for the client to release the
/// connection, so the next `accept` is the next operation rather than a retry.
fn respond_json(stream: &mut UnixStream, status: &str, body: &str, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let _ = stream.set_write_timeout(Some(remaining.max(Duration::from_millis(1))));
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut buffer = [0_u8; 64];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(remaining.min(Duration::from_millis(200))));
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn read_request_head(stream: &mut UnixStream, deadline: Instant) -> String {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "the local fixture read budget expired"
        );
        let _ = stream.set_read_timeout(Some(remaining));
        let read = stream.read(&mut chunk).unwrap();
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
