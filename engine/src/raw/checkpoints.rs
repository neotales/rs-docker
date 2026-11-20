//! Container checkpoint operations for the repository-owned Engine backend.
//!
//! The three routes are the daemon's experimental checkpoint router:
//!
//! | Operation | Request | Success |
//! | --- | --- | --- |
//! | [`checkpoint_create`] | `POST /containers/{id}/checkpoints` with a JSON body | `201` |
//! | [`checkpoint_list`] | `GET /containers/{id}/checkpoints?dir=…` | `200` with a JSON array |
//! | [`checkpoint_remove`] | `DELETE /containers/{id}/checkpoints/{checkpoint}?dir=…` | `204` |
//!
//! These routes are **not** in the Engine's `OpenAPI` document, so there is no
//! schema to generate a model from and none was invented. The shape above is
//! the one the daemon's router reads: the create handler decodes
//! `CheckpointID`, `CheckpointDir`, and `Exit` from the request body, while the
//! list and delete handlers read the directory from the `dir` query parameter.
//! `CheckpointDir` in the create body and `dir` on the other two are the same
//! setting under the two spellings the daemon uses; this module does not
//! "correct" either one.
//!
//! # The directory is optional, and empty means the daemon's default
//!
//! `checkpoint_dir` selects a checkpoint storage directory other than the
//! container's configured one. Absent and empty are the same request to the
//! daemon — it substitutes the container's configured checkpoint directory — so
//! this module omits the value in both cases rather than sending
//! `CheckpointDir: ""` or `dir=`. The recorded request then says only what the
//! caller asked for. The generated fallback sends `CheckpointDir: ""` for an
//! empty value and `dir=` for an empty query value; the daemon reads all four
//! spellings identically.
//!
//! # A `null` list answer is no checkpoints
//!
//! The current daemon turns a nil checkpoint list into `[]` before writing it,
//! and the generated client this crate falls back to documents that older
//! daemons answer `null` instead. Both are decoded to an empty vector, so "this
//! container has no checkpoints" is not a decode failure on either spelling.
//! An entry without a string `Name` is a decode failure: that is not a
//! checkpoint the caller can name.
//!
//! # References stay inside their path segment
//!
//! The container reference and the checkpoint identifier are caller-supplied
//! strings that go into path segments, and `/` is a path separator. Both are
//! percent-encoded into exactly one segment, so a reference such as `a/b`
//! cannot address a different resource. An empty container reference or
//! checkpoint identifier is refused as `ErrorKind::InvalidInput` before a
//! connection is opened: `/containers/x/checkpoints/` is the *list* route, and
//! an empty identifier would silently turn a delete into a different request.
//! The generated fallback escapes neither and performs no such pre-check.
//!
//! An empty checkpoint identifier is also refused for creation. The daemon
//! rejects it as an invalid name, so this only moves the same rejection before
//! the connection; a non-empty identifier the daemon considers invalid is still
//! the daemon's `400` with its own message.
//!
//! # A create is daemon-governed work
//!
//! Creation asks the container's runtime to dump a live process tree, which can
//! take longer than the transport's 120-second response-head budget on a large
//! container. Like `wait`, `stop`, and `restart`, [`checkpoint_create`] uses the
//! unbounded send, so the daemon's own work governs how long the answer takes.
//!
//! "Unbounded" is a property of the route, not of the call. On a Unix socket,
//! direct plain HTTP, SSH, and a caller-supplied stream, the unbounded send
//! removes the response-head deadline. On HTTPS the establishment budget still
//! applies, and the response head is not otherwise bounded. On the plain-HTTP
//! forward-proxy route the transport applies one 120-second overall request
//! budget covering the proxy connect, request-body production/backpressure, and
//! the response head, and that budget applies to the unbounded send too — the
//! same shape the generated client's single request timeout had on that route.
//! A create that exceeds a budget, or whose future is dropped, has an **unknown**
//! outcome: the daemon may already have created the checkpoint.
//!
//! # A list is a snapshot, not a retry proof
//!
//! Neither create nor remove is transactional, and neither can tell a caller
//! whether a request that was dispatched and then lost was applied. A list
//! answers what exists at the instant it is read: a create that is still in
//! flight may not appear, and a remove that is still in flight may still
//! appear, so neither observation distinguishes "not applied" from "not yet
//! applied". A retry is therefore only safe under external coordination — for
//! example, one owner serializing checkpoint operations for a container and a
//! record that the dispatched request has settled — and this client cannot
//! supply that record.
//!
//! Container identity makes the snapshot weaker still. If a container is removed
//! and recreated under the same name between dispatch and reconciliation, a
//! name-based list describes the new container, whose checkpoint directory and
//! checkpoints need not be the old container's. A create retried in that window
//! can create a checkpoint on the recreated container; a remove retried can
//! delete one that belongs to it. Nothing here detects that race, so a caller
//! that reconciles by name must also establish that the container was not
//! recreated.
//!
//! Nothing here retries: a failed owned request is returned, not re-issued over
//! the generated client, because a second create would either duplicate the
//! work or be rejected as an already-existing checkpoint, and a second remove
//! may delete a checkpoint the recreated container now owns.
//!
//! # Daemon capability
//!
//! The daemon registers these three routes as experimental. A daemon without
//! experimental features does not serve them at all, and one whose runtime
//! cannot checkpoint reports the operation as not implemented; both arrive here
//! as the daemon's own status and message in [`Error::api_error`]. Checkpoint
//! creation needs CRIU on Linux, and no daemon is started by this crate's tests:
//! the behaviour is pinned against loopback fixtures in
//! `tests/container_checkpoints.rs` and `tests/container_checkpoints_fallback.rs`,
//! not a live daemon.
//!
//! The routes have existed since Engine API v1.25, and the request and response
//! shape above has not changed since, so the versioned path this module sends
//! addresses the same handler at every version. What differs between daemons is
//! whether the experimental router is registered at all, which is a daemon
//! configuration fact rather than an API version one.

use hyper::Method;
use serde::{Deserialize, Serialize};

use super::containers::{Query, completed, container_path, escape_path_segment, with_query};
use super::{RawEngine, RawRequest, decode, engine_result, json_body, json_content_type};
use crate::{Checkpoint, CheckpointOptions, Error};

/// Creates a container checkpoint.
///
/// The identifier and the optional directory travel in the request body; the
/// container reference is one escaped path segment. The daemon answers `201`
/// with no body, so the status is the whole result and nothing is decoded as a
/// document.
///
/// This uses the unbounded send for the reason in the module documentation: a
/// checkpoint dump is daemon-governed work, so no response-head deadline is
/// imposed on a Unix socket, direct plain HTTP, SSH, or a caller-supplied stream.
/// The plain-HTTP proxy route's 120-second overall request budget still applies,
/// and HTTPS keeps its establishment budget. Dropping the future or exceeding a
/// budget leaves the outcome unknown — the checkpoint may exist. This function
/// never retries.
///
/// # Errors
///
/// Returns `ErrorKind::InvalidInput` for an empty container reference or
/// checkpoint identifier, before a connection is opened. Returns a transport
/// error when the daemon cannot be reached, and the daemon's own status and
/// message in [`Error::api_error`] when it rejects the request.
pub async fn checkpoint_create(
    engine: &RawEngine,
    container: &str,
    options: &CheckpointOptions,
) -> Result<(), Error> {
    let request = checkpoint_create_request(container, options)?;
    let response = engine.send_unbounded(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Builds the `POST /containers/{id}/checkpoints` request.
///
/// The body member order is `CheckpointID`, `CheckpointDir`, `Exit`, which is
/// the order the generated fallback serializes its options in, so a recorded
/// body is comparable between the two routes. `Exit` is always written because
/// the caller's value is not optional; the directory is omitted when it is
/// absent or empty.
fn checkpoint_create_request(
    container: &str,
    options: &CheckpointOptions,
) -> Result<RawRequest, Error> {
    let path = container_path(container, "/checkpoints")?;
    let checkpoint_id = checkpoint_identifier(options.checkpoint_id.as_deref())?;
    let checkpoint_dir = optional_checkpoint_dir(options.checkpoint_dir.as_deref());
    let document = CreateCheckpointDocument {
        checkpoint_id,
        checkpoint_dir,
        exit: options.exit,
    };
    Ok(json_content_type(RawRequest::new(Method::POST, &path)).with_body(json_body(&document)?))
}

/// Lists a container's checkpoints.
///
/// The answer is one bounded JSON document read through
/// [`RawResponse::document`](super::RawResponse::document) and capped at
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES), so nothing here is
/// streamed and there is no response handle to cancel. A `null` answer and an
/// empty array both project to an empty vector.
///
/// A decode failure is content-free: the shared decoder reports the fixed serde
/// category and position, never the response text or a decoded value, because a
/// proxied response is untrusted.
///
/// The answer is a snapshot. It cannot show that a create or remove which was
/// dispatched earlier has settled, so it is not proof that a retry is safe; see
/// the module documentation.
///
/// `checkpoint_dir` is the optional `dir` query value. Absent and empty are
/// omitted, which leaves the daemon's default in place.
///
/// # Errors
///
/// Returns `ErrorKind::InvalidInput` for an empty container reference, before a
/// connection is opened. Returns a transport error when the daemon cannot be
/// reached, the daemon's status and message when it rejects the request, and
/// `ErrorKind::InvalidInput` when an answer entry has no string `Name`.
pub async fn checkpoint_list(
    engine: &RawEngine,
    container: &str,
    checkpoint_dir: Option<&str>,
) -> Result<Vec<Checkpoint>, Error> {
    let response = engine
        .send(checkpoint_list_request(container, checkpoint_dir)?)
        .await?;
    let document = engine_result(response).await?;
    let entries: Option<Vec<CheckpointDocument>> = decode(&document)?;
    Ok(entries
        .unwrap_or_default()
        .into_iter()
        .map(Checkpoint::from)
        .collect())
}

/// Builds the `GET /containers/{id}/checkpoints` request.
fn checkpoint_list_request(
    container: &str,
    checkpoint_dir: Option<&str>,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(directory) = optional_checkpoint_dir(checkpoint_dir) {
        query.value("dir", directory);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, &container_path(container, "/checkpoints")?),
        query.finish(),
    ))
}

/// Removes one container checkpoint.
///
/// The checkpoint identifier is escaped into one path segment and the optional
/// directory is the `dir` query value. The daemon answers `204` with no body,
/// so the status is the whole result.
///
/// The removal is not transactional: a transport failure or cancellation after
/// the request was sent leaves the outcome unknown, and this function does not
/// retry. A list is a snapshot and cannot prove the dispatched removal settled;
/// see the module documentation for the coordination that would be required
/// before sending it again.
///
/// # Errors
///
/// Returns `ErrorKind::InvalidInput` for an empty container reference or
/// checkpoint identifier, before a connection is opened. Returns a transport
/// error when the daemon cannot be reached, and the daemon's own status and
/// message in [`Error::api_error`] when it rejects the request.
pub async fn checkpoint_remove(
    engine: &RawEngine,
    container: &str,
    checkpoint: &str,
    checkpoint_dir: Option<&str>,
) -> Result<(), Error> {
    completed(
        engine,
        checkpoint_remove_request(container, checkpoint, checkpoint_dir)?,
    )
    .await
}

/// Builds the `DELETE /containers/{id}/checkpoints/{checkpoint}` request.
fn checkpoint_remove_request(
    container: &str,
    checkpoint: &str,
    checkpoint_dir: Option<&str>,
) -> Result<RawRequest, Error> {
    let checkpoint = checkpoint_identifier(Some(checkpoint))?;
    let suffix = format!("/checkpoints/{}", escape_path_segment(checkpoint));
    let mut query = Query::default();
    if let Some(directory) = optional_checkpoint_dir(checkpoint_dir) {
        query.value("dir", directory);
    }
    Ok(with_query(
        RawRequest::new(Method::DELETE, &container_path(container, &suffix)?),
        query.finish(),
    ))
}

/// Requires a non-empty checkpoint identifier.
///
/// The same rule serves create and remove: an empty identifier is not a
/// checkpoint name, and on the remove route it would spell the list path.
fn checkpoint_identifier(identifier: Option<&str>) -> Result<&str, Error> {
    identifier
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::invalid_input("the Engine checkpoint identifier must not be empty"))
}

/// Treats an empty checkpoint directory as "the daemon's default".
///
/// Absent and empty select the same directory in the daemon, so both are
/// omitted from the request rather than sent as an empty value.
fn optional_checkpoint_dir(directory: Option<&str>) -> Option<&str> {
    directory.filter(|value| !value.is_empty())
}

/// The `POST /containers/{id}/checkpoints` body in the daemon's spelling.
///
/// This is the only wire-shaped value in this module, and it is deliberately
/// not a generated model: importing one would tie the escape path back to the
/// dependency it exists to leave.
#[derive(Debug, Serialize)]
struct CreateCheckpointDocument<'a> {
    #[serde(rename = "CheckpointID")]
    checkpoint_id: &'a str,
    #[serde(rename = "CheckpointDir", skip_serializing_if = "Option::is_none")]
    checkpoint_dir: Option<&'a str>,
    #[serde(rename = "Exit")]
    exit: bool,
}

/// One entry of a `GET /containers/{id}/checkpoints` answer.
#[derive(Debug, Deserialize)]
struct CheckpointDocument {
    #[serde(rename = "Name")]
    name: String,
}

impl From<CheckpointDocument> for Checkpoint {
    fn from(document: CheckpointDocument) -> Self {
        Self {
            name: document.name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CheckpointDocument, checkpoint_create_request, checkpoint_list_request,
        checkpoint_remove_request,
    };
    use crate::raw::{RawBody, RawEngine, RawTarget};
    use crate::{ApiVersion, CheckpointOptions, ErrorKind};

    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &super::RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    /// Renders the request body as the exact bytes that would be sent.
    fn request_body_bytes(request: &super::RawRequest) -> String {
        match &request.body {
            RawBody::Bytes(bytes) => String::from_utf8(bytes.to_vec()).expect("UTF-8 JSON"),
            other => panic!("expected a buffered body, got {other:?}"),
        }
    }

    #[test]
    fn create_sends_the_versioned_path_and_the_body_in_the_daemons_spelling() {
        let request = checkpoint_create_request(
            "slice-db-1",
            &CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                checkpoint_dir: Some("/var/lib/docker/checkpoints/team a&b".to_owned()),
                exit: true,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/slice-db-1/checkpoints HTTP/1.1"),
            "the create route must be the versioned path with no query"
        );
        assert_eq!(
            request_body_bytes(&request),
            r#"{"CheckpointID":"cp1","CheckpointDir":"/var/lib/docker/checkpoints/team a&b","Exit":true}"#,
            "the create body must be the daemon's members, in the generated order"
        );
    }

    #[test]
    fn create_omits_an_absent_or_empty_checkpoint_dir_and_always_spells_exit() {
        for directory in [None, Some(String::new())] {
            let request = checkpoint_create_request(
                "slice-db-1",
                &CheckpointOptions {
                    checkpoint_id: Some("cp1".to_owned()),
                    checkpoint_dir: directory,
                    exit: false,
                },
            )
            .expect("request");
            assert_eq!(
                request_body_bytes(&request),
                r#"{"CheckpointID":"cp1","Exit":false}"#,
                "an absent or empty directory is the daemon default and is omitted"
            );
        }
    }

    #[test]
    fn create_escapes_the_container_reference_and_refuses_empty_values() {
        let request = checkpoint_create_request(
            "a/b",
            &CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                ..Default::default()
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/a%2Fb/checkpoints HTTP/1.1")
        );

        let error = checkpoint_create_request(
            "",
            &CheckpointOptions {
                checkpoint_id: Some("cp1".to_owned()),
                ..Default::default()
            },
        )
        .expect_err("empty container");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        for identifier in [None, Some(String::new())] {
            let error = checkpoint_create_request(
                "slice-db-1",
                &CheckpointOptions {
                    checkpoint_id: identifier,
                    ..Default::default()
                },
            )
            .expect_err("empty checkpoint identifier");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("checkpoint"),
                "the refusal must name the checkpoint identifier: {error}"
            );
        }
    }

    #[test]
    fn list_sends_the_versioned_path_with_the_encoded_dir_query() {
        let request =
            checkpoint_list_request("slice-db-1", Some("/custom dir&x")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/slice-db-1/checkpoints?dir=%2Fcustom+dir%26x HTTP/1.1"
            ),
            "the directory must be one percent-encoded query value"
        );
    }

    #[test]
    fn list_omits_an_absent_or_empty_dir() {
        for directory in [None, Some("")] {
            let request = checkpoint_list_request("slice-db-1", directory).expect("request");
            assert_eq!(
                request_line(&request),
                crate::raw::at_api_version(
                    "GET /v1.API/containers/slice-db-1/checkpoints HTTP/1.1"
                ),
                "{directory:?} is the daemon default, not an empty query value"
            );
            assert!(
                request.query.is_none(),
                "an empty query must not be attached: {directory:?}"
            );
        }
    }

    #[test]
    fn list_escapes_the_container_reference_and_refuses_an_empty_one() {
        let request = checkpoint_list_request("a/b", None).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/a%2Fb/checkpoints HTTP/1.1")
        );
        let error = checkpoint_list_request("", None).expect_err("empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn remove_sends_the_versioned_path_with_both_segments_escaped() {
        let request =
            checkpoint_remove_request("a/b", "cp/one & two", Some("/custom dir")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "DELETE /v1.API/containers/a%2Fb/checkpoints/cp%2Fone%20%26%20two?dir=%2Fcustom+dir HTTP/1.1"
            ),
            "the checkpoint identifier is a path segment and the directory is a query value"
        );
    }

    #[test]
    fn remove_omits_an_absent_or_empty_dir() {
        for directory in [None, Some("")] {
            let request =
                checkpoint_remove_request("slice-db-1", "cp1", directory).expect("request");
            assert_eq!(
                request_line(&request),
                crate::raw::at_api_version(
                    "DELETE /v1.API/containers/slice-db-1/checkpoints/cp1 HTTP/1.1"
                ),
                "{directory:?} is the daemon default, not an empty query value"
            );
        }
    }

    #[test]
    fn remove_refuses_an_empty_container_or_checkpoint_before_a_request_exists() {
        let error = checkpoint_remove_request("", "cp1", None).expect_err("empty container");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);

        // An empty checkpoint would spell `/checkpoints/`, which is the list
        // route, so it is refused rather than sent as a different request.
        let error = checkpoint_remove_request("slice-db-1", "", None)
            .expect_err("empty checkpoint identifier");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("checkpoint"),
            "the refusal must name the checkpoint identifier: {error}"
        );
    }

    #[test]
    fn a_null_list_answer_is_no_checkpoints() {
        // Older daemons answer `null` for a container with no checkpoints; the
        // current one answers `[]`. Both are "none", not a decode failure.
        let document: Option<Vec<CheckpointDocument>> =
            crate::raw::decode(b"null").expect("a null list");
        assert!(document.unwrap_or_default().is_empty());

        let document: Option<Vec<CheckpointDocument>> =
            crate::raw::decode(b"[]").expect("an empty list");
        assert!(document.unwrap_or_default().is_empty());
    }

    #[test]
    fn a_list_answer_projects_each_name() {
        let document: Option<Vec<CheckpointDocument>> =
            crate::raw::decode(br#"[{"Name":"cp1"},{"Name":"cp-two"}]"#).expect("a list");
        let names: Vec<_> = document
            .unwrap_or_default()
            .into_iter()
            .map(crate::Checkpoint::from)
            .map(|checkpoint| checkpoint.name)
            .collect();
        assert_eq!(names, vec!["cp1".to_owned(), "cp-two".to_owned()]);
    }

    #[test]
    fn a_malformed_list_answer_is_refused() {
        // Each of these is not a checkpoint the caller can name: a missing or
        // non-string `Name`, a duplicate member, and an entry that is not an
        // object at all.
        for body in [
            "{}",
            r"[{}]",
            r#"[{"Name":7}]"#,
            r#"[{"Name":null}]"#,
            r#"[{"Name":"a","Name":"b"}]"#,
            "[null]",
            "not json",
        ] {
            assert!(
                crate::raw::decode::<Option<Vec<CheckpointDocument>>>(body.as_bytes()).is_err(),
                "a malformed list answer must be refused: {body}"
            );
        }
    }

    #[test]
    fn a_create_answer_is_a_status_and_carries_no_document() {
        // The daemon answers `201` with an empty body. `engine_result` treats
        // the status as the result, so nothing decodes the empty body as JSON.
        assert!(hyper::StatusCode::CREATED.is_success());
        assert!(hyper::StatusCode::NO_CONTENT.is_success());
    }
}
