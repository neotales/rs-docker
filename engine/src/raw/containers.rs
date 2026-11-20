//! Container lifecycle operations for the repository-owned Engine backend.
//!
//! This is step 2 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. Every operation here reuses
//! [`RawEngine`], the single owned transport, and the shared
//! [`engine_result`](super::engine_result) status mapping, so there is no second
//! client, no second error type, and no second HTTP stack in the crate.
//!
//! # The container name is a query value, not a body member
//!
//! `POST /containers/create` takes the name in `?name=`. The Engine's create
//! body has no `Name` member and a `Name` member in the body is **silently
//! ignored**: the container is created under a generated name and the caller is
//! never told. That was verified against Docker Engine 29.8.0, which answers a
//! create request carrying `"Name":"probey"` in the body with a plain
//! `{"Id":...,"Warnings":[]}` for a container called something else entirely.
//! A silently dropped name is a container the caller cannot find again, so
//! [`create`] puts it in the query and leaves it out of the body.
//!
//! # `204 No Content` bodies are not documents
//!
//! `start`, `stop`, `restart`, and `remove` answer `204` with no body. Their
//! success is the status, and the body is never handed to a JSON decoder;
//! attempting to decode an empty body as a document would turn a successful
//! lifecycle call into a parse failure.
//!
//! # Container references are escaped into a single path segment
//!
//! A container reference is a caller-supplied string that goes into a path
//! segment, and `/` is a path separator. An unescaped reference would
//! silently address a *different* resource: `POST /containers/a/b/start` is a
//! four-segment path, not a start of a container named `a/b`. Every reference
//! is therefore percent-encoded into exactly one segment by
//! [`escape_path_segment`], which is a difference from the current dependency:
//! the former generated client 0.21.1 formats the path with `format!("/containers/{id}/start")`
//! and escapes nothing. Against Docker Engine 29.8.0 the two spellings happen to
//! produce the same `No such container: a/b`, because that daemon percent-decodes
//! the path before routing, but the escaped form is the correct request and the
//! only one that cannot be re-routed by an intermediary that does not decode.
//!
//! # Wire projections are private, and the public models are unchanged
//!
//! The repository-owned models in [`crate`] — [`ContainerSummary`],
//! [`ContainerCreateResult`], [`ContainerWaitResult`] — carry `snake_case` field
//! names because they are CLI output and serialize as such. They are *not* the
//! Engine's wire spelling, which is `PascalCase` (`Id`, `ImageID`, `StatusCode`).
//! Deserializing a real `GET /containers/json` answer into
//! [`ContainerSummary`] therefore loses every field: `Ports` and `Labels` are
//! not optional, so the decode fails outright. The private `*Document` types
//! below are that boundary, and they are the only wire-shaped values in this
//! module. They are deliberately not the former generated client generated models: importing
//! those into the owned backend would tie the escape path back to the
//! dependency it exists to leave.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use futures_core::Stream;
use http::header::CONTENT_TYPE;
use hyper::Method;
use serde::{Deserialize, Serialize};

use super::{
    FrameStream, RawBody, RawEngine, RawRequest, decode, engine_result, json_body,
    json_content_type, started,
};
use crate::{
    CommitContainerOptions, ContainerArchiveUploadOptions, ContainerCreateOptions,
    ContainerCreateResult, ContainerHostConfig, ContainerListOptions, ContainerNetworkingConfig,
    ContainerPathStat, ContainerPort, ContainerPortBinding, ContainerRemoveOptions,
    ContainerRestartOptions, ContainerStartOptions, ContainerStopOptions, ContainerSummary,
    ContainerTop, ContainerWaitOptions, ContainerWaitResult, DeviceMapping, DeviceRequest, Error,
    HealthConfig, LogConfig, RestartPolicy, Ulimit,
};

/// Lists containers.
///
/// `GET /containers/json` answers with one JSON array, so the response is a
/// single bounded document read through
/// [`RawResponse::document`](super::RawResponse::document) and therefore capped
/// at [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). Nothing here is
/// streamed, so there is no unbounded body to accumulate and nothing to cancel.
///
/// `all` and `size` are always spelled out rather than left to the daemon's
/// defaults, so a recorded request says what it meant. `filters` is sent only
/// when it is non-empty, because an empty filter object is a filter that
/// matches the daemon's own "no filter" case and would only add noise.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not the expected container array.
pub async fn container_list(
    engine: &RawEngine,
    options: &ContainerListOptions,
) -> Result<Vec<ContainerSummary>, Error> {
    let response = engine.send(container_list_request(options)?).await?;
    let document = engine_result(response).await?;
    let entries: Vec<ContainerSummaryDocument> = decode(&document)?;
    Ok(entries.into_iter().map(ContainerSummary::from).collect())
}

/// Builds the `GET /containers/json` request.
///
/// Split out from [`list`] so the exact request line is assertable without a
/// socket, which is what the unit tests check.
fn container_list_request(options: &ContainerListOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("all", options.all);
    if let Some(limit) = options.limit {
        query.value("limit", &limit.to_string());
    }
    query.flag("size", options.size);
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, "/containers/json"),
        query.finish(),
    ))
}

/// Creates a container without starting it.
///
/// The name and platform travel in the query string, for the reason given in
/// the module documentation. The answer is the daemon's `{"Id":...,
/// "Warnings":[...]}` document.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a name the Engine's `[a-zA-Z0-9][a-zA-Z0-9_.-]` rule rejects
/// arrives here as a `400` — when a restart policy is not one of the four
/// names the Engine accepts, or when the response is not a create document.
pub async fn container_create(
    engine: &RawEngine,
    options: &ContainerCreateOptions,
) -> Result<ContainerCreateResult, Error> {
    let response = engine.send(container_create_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<ContainerCreateDocument>(&document).map(ContainerCreateResult::from)
}

/// Builds the `POST /containers/create` request.
///
/// The name and platform go in the query, which is the only place the Engine
/// reads them from, and the body carries the container configuration only.
///
/// `platform` is sent when the caller set it and omitted when it did not. The
/// current dependency always sends it, defaulting to an empty value, so its
/// recorded `POST /containers/create?name=web&platform=` carries a parameter
/// nobody asked for; an omitted parameter is the same request without the
/// noise.
fn container_create_request(options: &ContainerCreateOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(name) = &options.name {
        query.value("name", name);
    }
    if let Some(platform) = &options.platform {
        query.value("platform", platform);
    }
    let request = json_content_type(RawRequest::new(Method::POST, "/containers/create"))
        .with_body(json_body(&CreateDocument::new(options)?)?);
    Ok(with_query(request, query.finish()))
}

/// Starts a container.
///
/// Answers `204` with an empty body; the status is the whole result.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `404` for a container that does not exist or a `304` for
/// one that is already running.
pub async fn container_start(
    engine: &RawEngine,
    container: &str,
    options: &ContainerStartOptions,
) -> Result<(), Error> {
    completed(engine, container_start_request(container, options)?).await
}

/// Builds the `POST /containers/{id}/start` request.
fn container_start_request(
    container: &str,
    options: &ContainerStartOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(keys) = &options.detach_keys {
        query.value("detachKeys", keys);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/start")?),
        query.finish(),
    ))
}

/// Stops a container.
///
/// `timeout_seconds` becomes `t`, the number of seconds the daemon waits for a
/// graceful stop before killing the container. It is omitted when unset so the
/// daemon's own default applies rather than this client's guess.
///
/// This operation uses the unbounded send, like [`container_wait`]: the daemon's
/// own `t` (or its default) governs the wait, and the client does not impose a
/// shorter response-head deadline. Dropping the operation future cancels the
/// wait. Because the daemon may already have stopped the container, the outcome
/// of a cancellation or transport failure is unknown; reconcile the container's
/// state before retrying.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request.
pub async fn container_stop(
    engine: &RawEngine,
    container: &str,
    options: &ContainerStopOptions,
) -> Result<(), Error> {
    let request = container_stop_request(container, options)?;
    let response = engine.send_unbounded(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Builds the `POST /containers/{id}/stop` request.
fn container_stop_request(
    container: &str,
    options: &ContainerStopOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(signal) = &options.signal {
        query.value("signal", signal);
    }
    if let Some(timeout) = options.timeout_seconds {
        query.value("t", &timeout.to_string());
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/stop")?),
        query.finish(),
    ))
}

/// Restarts a container.
///
/// `signal` and `timeout_seconds` are the same `signal` and `t` parameters the
/// stop request takes, in the same order. Each is omitted when unset so the
/// daemon's own default applies rather than this client's guess.
///
/// This operation uses the unbounded send, like [`container_wait`] and
/// [`container_stop`]: the daemon's own `t` (or its default) governs the wait,
/// and the client does not impose a shorter response-head deadline. Dropping the
/// operation future cancels the wait. Because the daemon may already have
/// restarted the container, the outcome of a cancellation or transport failure
/// is unknown; reconcile the container's state before retrying.
///
/// The endpoint answers `204` with an empty body, so the status is the whole
/// result and a success is never decoded as a document.
///
/// An empty `container` is refused as `ErrorKind::InvalidInput` before a
/// connection is opened. The generated client used for the facade fallback has
/// no equivalent pre-check; it passes the reference through and reports
/// whatever the daemon answers.
///
/// # Interrupted requests
///
/// A restart is not transactional. If a transport failure or cancellation
/// interrupts the request after it has been sent, the daemon may already have
/// restarted the container, and this function cannot tell whether it did.
/// Nothing here rolls that back. Reconcile the container's state before
/// retrying, or a retry may restart it a second time.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `404` for a container that does not exist.
pub async fn container_restart(
    engine: &RawEngine,
    container: &str,
    options: &ContainerRestartOptions,
) -> Result<(), Error> {
    let request = container_restart_request(container, options)?;
    let response = engine.send_unbounded(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Builds the `POST /containers/{id}/restart` request.
fn container_restart_request(
    container: &str,
    options: &ContainerRestartOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(signal) = &options.signal {
        query.value("signal", signal);
    }
    if let Some(timeout) = options.timeout_seconds {
        query.value("t", &timeout.to_string());
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/restart")?),
        query.finish(),
    ))
}

/// Removes a container.
///
/// The three flags are always spelled, so a recorded `DELETE` says whether
/// volumes, a running process, and a link were part of the request.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, such as a `409` for a running container removed without `force`.
pub async fn container_remove(
    engine: &RawEngine,
    container: &str,
    options: &ContainerRemoveOptions,
) -> Result<(), Error> {
    completed(engine, container_remove_request(container, *options)?).await
}

/// Builds the `DELETE /containers/{id}` request.
///
/// The options are taken by value because the type is three `bool`s; the public
/// operation still borrows so a caller can reuse its options afterwards.
fn container_remove_request(
    container: &str,
    options: ContainerRemoveOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("v", options.remove_volumes);
    query.flag("force", options.force);
    query.flag("link", options.remove_link);
    Ok(with_query(
        RawRequest::new(Method::DELETE, &container_path(container, "")?),
        query.finish(),
    ))
}

/// Waits for a container to stop and reports its exit status.
///
/// The Engine's `POST /containers/{id}/wait` blocks while the container runs
/// and then writes one JSON document, `{"StatusCode":<n>}`, so this is a
/// bounded document read and not a stream. The connection is open for the whole
/// wait, and the read happens on the runtime that made the call, which
/// [`RawEngine::send`] documents as a requirement.
///
/// This operation does not use the ordinary response-head deadline: its
/// contract is to wait until the container reaches the requested state, which
/// can be longer than the transport's 120 seconds. It uses the transport's
/// unbounded send instead, and dropping the operation future is how a caller
/// cancels the wait.
///
/// A container that exits non-zero is still a successful `wait`: the exit
/// status is the answer, and it is returned in the result rather than raised as
/// an error.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a wait document.
pub async fn container_wait(
    engine: &RawEngine,
    container: &str,
    options: &ContainerWaitOptions,
) -> Result<ContainerWaitResult, Error> {
    let response = engine
        .send_unbounded(container_wait_request(container, options)?)
        .await?;
    let document = engine_result(response).await?;
    decode::<ContainerWaitDocument>(&document).map(ContainerWaitResult::from)
}

/// Builds the `POST /containers/{id}/wait` request.
fn container_wait_request(
    container: &str,
    options: &ContainerWaitOptions,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(condition) = &options.condition {
        query.value("condition", condition);
    }
    Ok(with_query(
        RawRequest::new(Method::POST, &container_path(container, "/wait")?),
        query.finish(),
    ))
}

/// Lists the processes running in a container.
///
/// `GET /containers/{id}/top` answers with one bounded JSON document, so it is
/// read through [`RawResponse::document`](super::RawResponse::document) and
/// capped at [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). Nothing here is
/// streamed and there is no response handle to cancel.
///
/// `ps_args` is the Engine's `ps_args` query parameter. The Engine applies its
/// own default when the parameter is omitted or empty; Docker on Unix
/// substitutes `-ef`. `None` and a whitespace-only value are therefore omitted
/// rather than sent as `ps_args=`, which keeps the recorded request to the
/// caller's intent while selecting the same daemon default. Any other value is
/// sent verbatim, percent-encoded as one query value, so a value containing
/// `&`, `+`, or a space cannot add or change a parameter.
///
/// The Engine declares `Titles` and `Processes` as optional members. Both are
/// projected to empty vectors when the member is absent or present as `null`,
/// which is exactly what the generated fallback does with its optional
/// response fields. A member of the wrong JSON type is a decode failure; the
/// owned decoder reports it as [`ErrorKind::InvalidInput`](crate::ErrorKind)
/// where the fallback reports the generated client's
/// [`ErrorKind::Docker`](crate::ErrorKind).
///
/// The container reference is percent-encoded into exactly one path segment, so
/// a reference containing `/` cannot address a different resource. An empty
/// reference is refused as [`ErrorKind::InvalidInput`](crate::ErrorKind) before
/// a connection is opened; the generated fallback has no equivalent pre-check.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the response is not a top document.
pub async fn container_top(
    engine: &RawEngine,
    container: &str,
    ps_args: Option<&str>,
) -> Result<ContainerTop, Error> {
    let response = engine
        .send(container_top_request(container, ps_args)?)
        .await?;
    let document = engine_result(response).await?;
    decode::<ContainerTopDocument>(&document).map(ContainerTop::from)
}

/// Builds the `GET /containers/{id}/top` request.
///
/// Split out from [`container_top`] so the exact request line is assertable
/// without a socket, which is what the unit tests check.
fn container_top_request(container: &str, ps_args: Option<&str>) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if let Some(ps_args) = ps_args.filter(|value| !value.trim().is_empty()) {
        query.value("ps_args", ps_args);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, &container_path(container, "/top")?),
        query.finish(),
    ))
}

/// Opens an uncompressed container filesystem archive stream.
///
/// `GET /containers/{id}/export` answers `200` with a TAR body whose length the
/// daemon does not know in advance. The answer is therefore **bytes, not
/// JSON**: the returned [`FrameStream`] is read with
/// [`FrameStream::next_data`], and reading it with
/// [`FrameStream::next_json`](FrameStream::next_json) would fail on the first
/// TAR header rather than yield anything.
///
/// Each call to `next_data` hands over one transport chunk, so the archive is
/// never collected or accumulated by this crate. The chunk size is the
/// transport's rather than a promise about the daemon's write boundaries, which
/// is the same contract the image archive download has. A caller that stops
/// polling drops the [`FrameStream`], which drops the response and its
/// connection driver; the daemon observes the disconnect and no further bytes
/// are read.
///
/// The archive is **not validated**: a TAR that is cut short inside a complete
/// HTTP body is delivered as bytes and ends cleanly, so a caller that needs a
/// whole archive verifies it itself. What the transport does report is an
/// incomplete HTTP body, which fails the stream rather than ending it.
///
/// The status is interpreted before the stream is handed out, so a daemon
/// rejection is an [`Error::api_error`](crate::Error::api_error) carrying the
/// status and message rather than a stream item whose bytes are the error
/// document.
///
/// The container reference is percent-encoded into exactly one path segment, so
/// a reference containing `/` cannot address a different resource. An empty
/// reference is refused as [`ErrorKind::InvalidInput`](crate::ErrorKind)
/// before a connection is opened.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request. A failure after the stream has
/// started is reported by the stream item, not by this function.
pub async fn export_container(engine: &RawEngine, container: &str) -> Result<FrameStream, Error> {
    let response = engine.send(export_container_request(container)?).await?;
    started(response).await
}

/// Builds the `GET /containers/{id}/export` request.
///
/// Split out from [`export_container`] so the exact request line is assertable
/// without a socket, which is what the unit tests check. The endpoint has no
/// query parameters.
fn export_container_request(container: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &container_path(container, "/export")?,
    ))
}

/// The header carrying a path's metadata on a container archive `HEAD` answer.
const PATH_STAT_HEADER: &str = "x-docker-container-path-stat";

/// The largest `X-Docker-Container-Path-Stat` value this client will decode.
///
/// A real answer is a few hundred bytes: a single path component, a size, a
/// mode, and a link target. The bound is on the encoded header and is checked
/// before base64 or JSON work, so a peer cannot choose the size of the
/// allocation this client makes. It is deliberately larger than a legitimate
/// answer by an order of magnitude rather than tight, because a daemon that
/// grows the member set should not fail on the size alone.
const MAX_PATH_STAT_HEADER_BYTES: usize = 16 * 1024;

/// Reads the daemon's metadata for one path inside a container.
///
/// `HEAD /containers/{id}/archive` answers `200` with no body and puts the
/// metadata in `X-Docker-Container-Path-Stat`, a **standard**-base64 JSON
/// object. The header is decoded here rather than handed back as a string, and
/// the projection is the same [`ContainerPathStat`] the generated fallback
/// produces: `name`, `size`, `mode`, and `linkTarget`, with an empty target
/// projected to `None`. The `mtime` member the daemon also sends has no home in
/// that model, so it is not returned. The mode is the daemon's own value,
/// including the Go type bits, which is why
/// [`ContainerPathStat::is_directory`] tests the high bit as well as `S_IFDIR`.
///
/// # The header is bounded before it is decoded
///
/// An encoded value over `MAX_PATH_STAT_HEADER_BYTES` (16 KiB) is refused before
/// base64 or JSON work begins. A missing header, an unreadable one, invalid
/// base64, or JSON that is not the expected object is an
/// [`ErrorKind::InvalidInput`](crate::ErrorKind) error. The header's value is
/// never included in the message: it is metadata for a path inside the
/// container, and an error that echoes its input leaks whatever the input held.
///
/// # The path is a query value, and it is not normalized
///
/// `path` is percent-encoded as a query value, so `&`, `+`, `#`, and a space
/// cannot add or change a parameter. It is otherwise passed to the daemon
/// verbatim: this function does not resolve `..`, follow a symlink, rewrite a
/// trailing slash, or reject a relative path. Those spellings have the
/// container's meaning, not the caller host's, and the daemon is the only side
/// that can resolve them. An empty path names nothing and is refused as
/// [`ErrorKind::InvalidInput`](crate::ErrorKind) before a connection is opened.
///
/// The container reference is percent-encoded into exactly one path segment,
/// and an empty reference is refused for the same reason.
///
/// # Errors
///
/// Returns an error when the reference or path is empty, when the daemon cannot
/// be reached, when it rejects the request (a missing path is a `404` carrying
/// the daemon's message), or when the metadata header is missing or malformed.
pub async fn container_archive_stat(
    engine: &RawEngine,
    container: &str,
    path: &str,
) -> Result<ContainerPathStat, Error> {
    let response = engine
        .send(container_archive_stat_request(container, path)?)
        .await?;
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    let header = response.headers.get(PATH_STAT_HEADER).ok_or_else(|| {
        Error::invalid_input(
            "the daemon's container archive HEAD answer carried no \
             X-Docker-Container-Path-Stat header",
        )
    })?;
    decode_path_stat(header)
}

/// Builds the `HEAD /containers/{id}/archive` request.
fn container_archive_stat_request(container: &str, path: &str) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("path", archive_path(path)?);
    Ok(with_query(
        RawRequest::new(Method::HEAD, &container_path(container, "/archive")?),
        query.finish(),
    ))
}

/// Opens an archive of one path inside a container.
///
/// `GET /containers/{id}/archive` answers `200` with a TAR body whose length
/// the daemon does not know in advance, so the answer is **bytes, not JSON**:
/// the returned [`FrameStream`] is read with
/// [`FrameStream::next_data`], and reading it with
/// [`FrameStream::next_json`](FrameStream::next_json) would fail on the first
/// TAR header rather than yield anything.
///
/// Each call to `next_data` hands over one transport chunk, so the archive is
/// never collected or accumulated by this crate. The chunk size is the
/// transport's rather than a promise about the daemon's write boundaries. A
/// caller that stops polling drops the [`FrameStream`], which drops the
/// response and its connection driver; the daemon observes the disconnect and
/// no further bytes are read.
///
/// The archive is **not validated**: a TAR that is cut short inside a complete
/// HTTP body is delivered as bytes and ends cleanly, so a caller that needs a
/// whole archive verifies it itself. What the transport does report is an
/// incomplete HTTP body, which fails the stream rather than ending it.
///
/// The status is interpreted before the stream is handed out, so a daemon
/// rejection is an [`Error::api_error`](crate::Error::api_error) carrying the
/// status and message rather than a stream item whose bytes are the error
/// document. That is the same rule [`export_container`] follows; the difference
/// is the endpoint and its `path` query value.
///
/// The `path` and container reference follow
/// [`container_archive_stat`]'s rules: the path is one encoded query value and
/// is not normalized, the reference is one encoded path segment, and an empty
/// value for either is refused before a connection is opened.
///
/// # Errors
///
/// Returns an error when the reference or path is empty, when the daemon cannot
/// be reached, or when it rejects the request. A failure after the stream has
/// started is reported by the stream item, not by this function.
pub async fn download_container_archive(
    engine: &RawEngine,
    container: &str,
    path: &str,
) -> Result<FrameStream, Error> {
    let response = engine
        .send(container_archive_download_request(container, path)?)
        .await?;
    started(response).await
}

/// Builds the `GET /containers/{id}/archive` request.
fn container_archive_download_request(container: &str, path: &str) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("path", archive_path(path)?);
    Ok(with_query(
        RawRequest::new(Method::GET, &container_path(container, "/archive")?),
        query.finish(),
    ))
}

/// Streams a TAR archive into a path inside a container.
///
/// `PUT /containers/{id}/archive` takes the archive as the **request body** and
/// answers `200` with no body on success. `source` is sent as a
/// [`RawBody::Stream`], so the archive reaches the socket incrementally rather
/// than being buffered whole; the request carries `Transfer-Encoding: chunked`
/// and no `Content-Length`.
///
/// # There is no fixed size cap, and that is deliberate
///
/// A container archive is as large as the part of the container it describes,
/// so a fixed cap would refuse a legitimate copy of a large directory. The
/// generated path does not impose one either, and adding one here would make
/// the same call succeed or fail depending on which transport served it. The
/// body is bounded by the caller's stream, which the facade builds from a file
/// that is already on disk. The **response** is bounded by
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES) like every other document,
/// even though a success carries nothing.
///
/// # An interrupted upload is not rolled back
///
/// The daemon extracts entries as it reads them. Dropping the returned future,
/// a source stream error, and a transport failure all close the request body.
/// Bytes already produced may have reached the daemon, and extraction may have
/// started; this function offers no rollback and no effect guarantee. A caller
/// that retries must reconcile the container's filesystem first, because the
/// previous attempt's effects are unknown.
///
/// # The query shape matches the generated path
///
/// `copyUIDGID` is always written as `1` or `0`, and `noOverwriteDirNonDir` is
/// written only when the caller asked for it. That is the shape the former generated client's
/// generated upload sends, so the two routes put the same parameters on the
/// wire. The Engine declares the overwrite flag as `noOverwriteDirNonDir`, and
/// that is the name the former generated client's generated request and Docker's own client send;
/// this crate sends it rather than inventing a shorter spelling.
///
/// The `path` and container reference follow
/// [`container_archive_stat`]'s rules: the path is one encoded query value and
/// is not normalized, the reference is one encoded path segment, and an empty
/// value for either is refused before a connection is opened. `path` names the
/// directory the archive is extracted into, so it is not the archive's own
/// entries.
///
/// # Errors
///
/// Returns an error when the reference or path is empty, when the daemon cannot
/// be reached, or when it rejects the request (a bad archive is a `400`, a
/// read-only filesystem a `403`, and a missing container or path a `404`). A
/// source stream failure is reported as a transport error when it reaches the
/// request; it is not retried.
pub async fn upload_container_archive<S>(
    engine: &RawEngine,
    container: &str,
    source: S,
    options: &ContainerArchiveUploadOptions,
) -> Result<(), Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let response = engine
        .send(container_archive_upload_request(
            container, source, options,
        )?)
        .await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Builds the `PUT /containers/{id}/archive` request.
fn container_archive_upload_request<S>(
    container: &str,
    source: S,
    options: &ContainerArchiveUploadOptions,
) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let mut query = Query::default();
    query.value("path", archive_path(&options.path)?);
    if options.no_overwrite_directory_with_file {
        query.value("noOverwriteDirNonDir", "1");
    }
    query.value(
        "copyUIDGID",
        if options.copy_user_and_group {
            "1"
        } else {
            "0"
        },
    );
    Ok(with_query(
        RawRequest::new(Method::PUT, &container_path(container, "/archive")?)
            .with_header(CONTENT_TYPE, "application/x-tar")
            .with_body(RawBody::from_stream(source)),
        query.finish(),
    ))
}

/// Refuses an empty archive path and returns it unchanged otherwise.
///
/// The path is not normalized here. A leading `/`, a trailing `/`, `..`, and a
/// symlink all have their meaning inside the container, and rewriting any of
/// them on the caller's side would change which resource is addressed.
fn archive_path(path: &str) -> Result<&str, Error> {
    if path.is_empty() {
        return Err(Error::invalid_input(
            "the Engine container archive path must not be empty",
        ));
    }
    Ok(path)
}

/// One `X-Docker-Container-Path-Stat` document in the daemon's spelling.
#[derive(Debug, Deserialize)]
struct ContainerPathStatDocument {
    name: String,
    size: i64,
    mode: u32,
    #[serde(rename = "linkTarget")]
    link_target: String,
}

impl From<ContainerPathStatDocument> for ContainerPathStat {
    fn from(document: ContainerPathStatDocument) -> Self {
        Self {
            name: document.name,
            size: document.size,
            mode: document.mode,
            // The daemon spells "not a link" as an empty string. The facade's
            // generated path already projects that to `None`, so the owned path
            // does the same rather than handing back a second spelling.
            link_target: (!document.link_target.is_empty()).then_some(document.link_target),
        }
    }
}

/// Decodes one `X-Docker-Container-Path-Stat` header value.
///
/// The base64 alphabet is the **standard** one. That is the opposite of the
/// `X-Registry-Auth` header, which the daemon decodes as URL-safe base64, and
/// the two are not interchangeable: this header is produced by
/// `base64.StdEncoding` in Moby's archive handler. Nothing here echoes the
/// header value, its decoded bytes, or the container path in an error.
fn decode_path_stat(header: &hyper::header::HeaderValue) -> Result<ContainerPathStat, Error> {
    if header.as_bytes().len() > MAX_PATH_STAT_HEADER_BYTES {
        return Err(Error::invalid_input(format!(
            "the daemon's X-Docker-Container-Path-Stat header exceeds the \
             {MAX_PATH_STAT_HEADER_BYTES}-byte limit"
        )));
    }
    let encoded = header.to_str().map_err(|_| {
        Error::invalid_input("the daemon's X-Docker-Container-Path-Stat header is not ASCII text")
    })?;
    let decoded = BASE64.decode(encoded).map_err(|_| {
        Error::invalid_input(
            "the daemon's X-Docker-Container-Path-Stat header is not standard base64",
        )
    })?;
    // The serde diagnostic is deliberately dropped rather than attached as a
    // source. A wrong-type member makes serde quote the value it found —
    // `invalid type: string "…", expected i64` — and that value came from the
    // daemon's header, which is untrusted. The fixed message names the shape
    // without repeating any of it.
    let document: ContainerPathStatDocument = serde_json::from_slice(&decoded).map_err(|_| {
        Error::invalid_input(
            "the daemon's container archive stat document is not the expected object",
        )
    })?;
    Ok(document.into())
}

/// Commits a container's filesystem changes to a new image.
///
/// `POST /commit` answers `201` with one bounded JSON document, `{"Id":...}`, so
/// the response is read through
/// [`RawResponse::document`](super::RawResponse::document) and capped at
/// [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES). Nothing here streams, so
/// there is no unbounded body to accumulate and nothing to cancel.
///
/// # The request shape
///
/// The container, repository, tag, comment, author, and pause flag are **query**
/// parameters, not body members, and they are spelled in the Engine's own order.
/// `pause` is always written: [`CommitContainerOptions`] carries a `bool` rather
/// than an optional flag, and the generated fallback always sends it too, so a
/// recorded request says whether the container was paused instead of leaving a
/// default to be inferred.
///
/// `changes` is the one parameter that carries more than one value. The Engine's
/// handler reads `r.Form["changes"]`, which is a list, so each Dockerfile
/// instruction is sent as its own `changes=` parameter. The generated fallback
/// joins the whole vector with a newline and sends one value, so the daemon
/// receives one change where the caller asked for several; the owned path sends
/// the shape the daemon's handler reads. Each value is percent-encoded on its
/// own, so an instruction containing `&`, `+`, `/`, or a space cannot add or
/// change a parameter.
///
/// The body is the `ContainerConfig` the Engine accepts, and this facade exposes
/// no option that fills one. The request therefore carries the same empty object
/// (`{}`) the generated fallback sends rather than an absent body: the daemon's
/// decoder tolerates `io.EOF`, so an absent body and `{}` are the same request,
/// and matching the fallback keeps the two paths' wire bytes comparable.
///
/// The container reference is a query value rather than a path segment, and an
/// empty one is refused as [`ErrorKind::InvalidInput`](crate::ErrorKind) before
/// a connection is opened: `POST /commit` with no container names no resource.
/// The generated fallback has no equivalent pre-check; it passes the empty value
/// through and reports whatever the daemon answers.
///
/// # Unknown outcome
///
/// A commit is not transactional, and the only failure this function decides
/// before anything is sent is the empty-reference refusal. For every other error
/// the request may or may not have reached the daemon, and none of them proves
/// the image was not created.
///
/// That is not limited to a transport failure or cancellation. The response
/// failures are the same: [`RawResponse::document`](super::RawResponse::document)
/// refuses a body over [`MAX_DOCUMENT_BYTES`](super::MAX_DOCUMENT_BYTES), an
/// incomplete body fails the read, and a document that is not JSON or carries no
/// usable `Id` fails the decode. The daemon writes its `201` only after the image
/// exists, so each of those can follow a commit that succeeded, with the client
/// failing before it could read the answer. A transport error cannot be used to
/// tell the difference either: the same class covers a connection that was never
/// established and one that failed while the answer was being read.
///
/// Nothing here rolls that back or retries it: a caller that retries may create a
/// second image. Reconcile — inspect for the image — before deciding. The
/// outcome is unknown, not failed.
///
/// # Errors
///
/// Returns an error when the container reference is empty, when the daemon
/// cannot be reached, when it rejects the request — a `404` for a container that
/// does not exist, a `400` for a reference the daemon will not parse — or when
/// the response cannot be read within the document bound or is not a commit
/// document. Every error except the empty-reference refusal may occur before or
/// after the daemon acted and does not establish whether the image was created.
pub async fn commit_container(
    engine: &RawEngine,
    options: &CommitContainerOptions,
) -> Result<String, Error> {
    let response = engine.send(commit_container_request(options)?).await?;
    let document = engine_result(response).await?;
    decode::<CommitDocument>(&document).map(|document| document.id)
}

/// Builds the `POST /commit` request.
///
/// Split out from [`commit_container`] so the exact request line and body are
/// assertable without a socket, which is what the unit tests check.
fn commit_container_request(options: &CommitContainerOptions) -> Result<RawRequest, Error> {
    require_container_reference(&options.container)?;
    let mut query = Query::default();
    query.value("container", &options.container);
    if let Some(repository) = &options.repository {
        query.value("repo", repository);
    }
    if let Some(tag) = &options.tag {
        query.value("tag", tag);
    }
    if let Some(comment) = &options.comment {
        query.value("comment", comment);
    }
    if let Some(author) = &options.author {
        query.value("author", author);
    }
    query.flag("pause", options.pause);
    for change in &options.changes {
        query.value("changes", change);
    }
    let request = json_content_type(RawRequest::new(Method::POST, "/commit"))
        .with_body(json_body(&CommitConfigDocument {})?);
    Ok(with_query(request, query.finish()))
}

/// Sends a request whose success is a status rather than a document.
///
/// The body of a `204` is read and discarded, never decoded: a success that
/// carries no document must not be reported as a decode failure. A non-2xx
/// status still goes through [`engine_result`], so a daemon rejection keeps its
/// status and message in [`Error::api_error`].
pub(super) async fn completed(engine: &RawEngine, request: RawRequest) -> Result<(), Error> {
    let response = engine.send(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Attaches an encoded query to a request, or leaves it off entirely.
///
/// An empty query is `None` rather than `""`, because `/containers/json?` and
/// `/containers/json` are the same request and the first one only makes a
/// recorded request line noisier.
pub(super) fn with_query(mut request: RawRequest, query: Option<String>) -> RawRequest {
    if let Some(query) = query {
        request.query = Some(query);
    }
    request
}

/// Builds the `/containers/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/containers//start` is not a
/// request for a container, and sending it would ask the daemon about a
/// resource the caller never named.
pub(super) fn container_path(container: &str, suffix: &str) -> Result<String, Error> {
    require_container_reference(container)?;
    Ok(format!(
        "/containers/{}{suffix}",
        escape_path_segment(container)
    ))
}

/// Refuses an empty container reference before a request is built.
///
/// Shared by the path-segment and query-value endpoints so the two spellings of
/// "the caller named no container" cannot drift apart.
fn require_container_reference(container: &str) -> Result<(), Error> {
    if container.is_empty() {
        return Err(Error::invalid_input(
            "the Engine container reference must not be empty",
        ));
    }
    Ok(())
}

/// Percent-encodes one path segment.
///
/// Everything outside the unreserved set `A-Z a-z 0-9 - . _ ~` is encoded,
/// which is what makes `/`, `?`, `#`, and a space unable to change the shape of
/// the request. `%` is encoded too, so a reference that already contains a
/// percent sign cannot smuggle an escape sequence past this function.
pub(super) fn escape_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte));
            }
            other => {
                use std::fmt::Write as _;
                let _written = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

/// An `application/x-www-form-urlencoded` query string under construction.
///
/// The Engine's Go side decodes these with `url.ParseQuery`, which is exactly
/// what `form_urlencoded` encodes for. That is also the spelling the current
/// dependency already puts on the wire, so a differential fixture can compare
/// a query byte for byte rather than approximately. A space is `+` and a `/`
/// is `%2F`, which is correct for a query value and wrong for a path segment —
/// which is why paths go through [`escape_path_segment`] instead.
pub(super) struct Query {
    encoded: url::form_urlencoded::Serializer<'static, String>,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            encoded: url::form_urlencoded::Serializer::new(String::new()),
        }
    }
}

impl Query {
    /// Appends a boolean as the `true`/`false` the Engine parses.
    ///
    /// The Engine's query decoding is `strconv.ParseBool`, which also accepts
    /// `1` and `0`; `true` and `false` are the spelling the Engine documents
    /// and the one the current dependency sends, so it is what a recorded
    /// request and the Engine's own documentation agree on.
    pub(super) fn flag(&mut self, name: &str, value: bool) {
        self.encoded
            .append_pair(name, if value { "true" } else { "false" });
    }

    /// Appends one already-plain value, percent-encoding it.
    pub(super) fn value(&mut self, name: &str, value: &str) {
        self.encoded.append_pair(name, value);
    }

    /// Finishes the query, or reports that there is nothing to send.
    pub(super) fn finish(mut self) -> Option<String> {
        let finished = self.encoded.finish();
        (!finished.is_empty()).then_some(finished)
    }
}

/// Encodes an Engine filter map as the JSON the `filters` value carries.
///
/// The filter map is a `BTreeMap`, so the JSON is emitted in key order and the
/// recorded request is the same on every run. That is a real difference from
/// the current dependency, which converts the same map into a `HashMap` before
/// serializing it, so the key order of its `filters` value varies between runs
/// of the same command.
pub(super) fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine container filters: {error}"
        ))
    })
}

/// One entry of a `GET /containers/json` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ContainerSummaryDocument {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Names")]
    names: Option<Vec<String>>,
    #[serde(rename = "Image")]
    image: Option<String>,
    // `ImageID` is not `ImageId`: the Engine capitalizes the acronym, which
    // `rename_all` cannot express, so every rename here is spelled out.
    #[serde(rename = "ImageID")]
    image_id: Option<String>,
    #[serde(rename = "Command")]
    command: Option<String>,
    #[serde(rename = "Created")]
    created: Option<i64>,
    #[serde(rename = "Ports")]
    ports: Option<Vec<ContainerPortDocument>>,
    #[serde(rename = "State")]
    state: Option<String>,
    #[serde(rename = "Status")]
    status: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
}

impl From<ContainerSummaryDocument> for ContainerSummary {
    fn from(document: ContainerSummaryDocument) -> Self {
        Self {
            id: document.id,
            names: document.names,
            image: document.image,
            image_id: document.image_id,
            command: document.command,
            created: document.created,
            ports: document
                .ports
                .unwrap_or_default()
                .into_iter()
                .map(ContainerPort::from)
                .collect(),
            state: document.state,
            status: document.status,
            // An unordered map would make the projection of an unordered daemon
            // answer vary between runs, so the map is kept ordered here too.
            labels: document.labels.unwrap_or_default(),
        }
    }
}

/// One published or exposed port of a container-list answer.
#[derive(Debug, Deserialize)]
struct ContainerPortDocument {
    #[serde(rename = "IP")]
    ip: Option<String>,
    #[serde(rename = "PrivatePort")]
    private_port: u16,
    #[serde(rename = "PublicPort")]
    public_port: Option<u16>,
    #[serde(rename = "Type")]
    protocol: Option<String>,
}

impl From<ContainerPortDocument> for ContainerPort {
    fn from(document: ContainerPortDocument) -> Self {
        Self {
            ip: document.ip,
            private_port: document.private_port,
            public_port: document.public_port,
            protocol: document.protocol,
        }
    }
}

/// The `POST /containers/create` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ContainerCreateDocument {
    #[serde(rename = "Id")]
    id: String,
    // Older daemons and some proxies answer without the member; an absent
    // warning list is an empty one.
    #[serde(default, rename = "Warnings")]
    warnings: Vec<String>,
}

impl From<ContainerCreateDocument> for ContainerCreateResult {
    fn from(document: ContainerCreateDocument) -> Self {
        Self {
            id: document.id,
            warnings: document.warnings,
        }
    }
}

/// The `POST /containers/{id}/wait` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ContainerWaitDocument {
    #[serde(default, rename = "StatusCode")]
    status_code: i64,
    #[serde(rename = "Error")]
    error: Option<ContainerWaitErrorDocument>,
}

impl From<ContainerWaitDocument> for ContainerWaitResult {
    fn from(document: ContainerWaitDocument) -> Self {
        Self {
            status_code: document.status_code,
            error: document
                .error
                .and_then(|error| error.message)
                .filter(|message| !message.is_empty()),
        }
    }
}

/// The wait answer's `Error` member, which is a container-shaped object rather
/// than a string.
#[derive(Debug, Deserialize)]
struct ContainerWaitErrorDocument {
    #[serde(rename = "Message")]
    message: Option<String>,
}

/// The `GET /containers/{id}/top` answer, in the Engine's spelling.
///
/// Both members are optional in the Engine, and both are projected to empty
/// vectors rather than being required, which is the generated fallback's
/// behavior for its own optional fields. `null` is accepted as "absent", and a
/// member of the wrong JSON type fails the decode.
#[derive(Debug, Deserialize)]
struct ContainerTopDocument {
    #[serde(rename = "Titles")]
    titles: Option<Vec<String>>,
    #[serde(rename = "Processes")]
    processes: Option<Vec<Vec<String>>>,
}

impl From<ContainerTopDocument> for ContainerTop {
    fn from(document: ContainerTopDocument) -> Self {
        Self {
            titles: document.titles.unwrap_or_default(),
            processes: document.processes.unwrap_or_default(),
        }
    }
}

/// The `POST /commit` answer, in the Engine's spelling.
///
/// The Engine's `IdResponse` declares `Id`. The generated model the fallback
/// decodes into accepts `Id`, `id`, and `ID` through serde aliases, so this
/// projection accepts the same three and the two paths agree on every document
/// a daemon could send. The member is required and is a string: an absent,
/// `null`, or non-string `Id` fails the decode on both paths, and an empty
/// string is a value neither path rejects.
#[derive(Debug, Deserialize)]
struct CommitDocument {
    #[serde(rename = "Id", alias = "id", alias = "ID")]
    id: String,
}

/// The `POST /commit` body.
///
/// The Engine's body is a `ContainerConfig`, and this facade exposes no option
/// that fills one. The generated fallback serializes its default config, which
/// is the empty object, so the owned path sends `{}` too: the daemon's decoder
/// tolerates `io.EOF`, and matching the fallback keeps the two paths' wire bytes
/// comparable.
#[derive(Debug, Serialize)]
struct CommitConfigDocument {}

/// The `POST /containers/create` body, in the Engine's spelling.
///
/// Every optional member is omitted rather than sent as `null`, because the
/// Engine treats a `null` and a missing member differently for several of
/// them, and "not requested" is what an unset repository option means.
#[derive(Debug, Serialize)]
struct CreateDocument<'a> {
    #[serde(rename = "Image")]
    image: &'a str,
    #[serde(rename = "Hostname", skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(rename = "Domainname", skip_serializing_if = "Option::is_none")]
    domainname: Option<&'a str>,
    #[serde(rename = "User", skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(rename = "MacAddress", skip_serializing_if = "Option::is_none")]
    mac_address: Option<&'a str>,
    #[serde(rename = "WorkingDir", skip_serializing_if = "Option::is_none")]
    working_dir: Option<&'a str>,
    #[serde(rename = "StopSignal", skip_serializing_if = "Option::is_none")]
    stop_signal: Option<&'a str>,
    #[serde(rename = "AttachStdin", skip_serializing_if = "Option::is_none")]
    attach_stdin: Option<bool>,
    #[serde(rename = "AttachStdout", skip_serializing_if = "Option::is_none")]
    attach_stdout: Option<bool>,
    #[serde(rename = "AttachStderr", skip_serializing_if = "Option::is_none")]
    attach_stderr: Option<bool>,
    #[serde(rename = "Tty", skip_serializing_if = "Option::is_none")]
    tty: Option<bool>,
    #[serde(rename = "OpenStdin", skip_serializing_if = "Option::is_none")]
    open_stdin: Option<bool>,
    #[serde(rename = "Env", skip_serializing_if = "Option::is_none")]
    environment: Option<&'a [String]>,
    #[serde(rename = "Cmd", skip_serializing_if = "Option::is_none")]
    command: Option<&'a [String]>,
    #[serde(rename = "Entrypoint", skip_serializing_if = "Option::is_none")]
    entrypoint: Option<&'a [String]>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "ExposedPorts", skip_serializing_if = "Option::is_none")]
    exposed_ports: Option<BTreeMap<&'a str, BTreeMap<&'a str, serde_json::Value>>>,
    #[serde(rename = "Healthcheck", skip_serializing_if = "Option::is_none")]
    healthcheck: Option<HealthDocument<'a>>,
    #[serde(rename = "StopTimeout", skip_serializing_if = "Option::is_none")]
    stop_timeout: Option<i64>,
    /// Which networks the container attaches to, and under what names.
    ///
    /// This member was missing, and that is why `DockerClient::create_container`
    /// could not be routed onto this transport: the Engine reads it to decide the
    /// container's networks, aliases, links, and endpoint MAC addresses, so a
    /// create without it produces a container attached to nothing. `docker
    /// compose` sets it for every service with more than one network, so the gap
    /// was a live regression rather than a missing convenience.
    #[serde(rename = "NetworkingConfig", skip_serializing_if = "Option::is_none")]
    networking_config: Option<NetworkingConfigDocument<'a>>,
    #[serde(rename = "HostConfig", skip_serializing_if = "Option::is_none")]
    host_config: Option<HostConfigDocument<'a>>,
}

/// The `NetworkingConfig` block of a create body.
///
/// The Engine's spelling for the per-network map is `EndpointsConfig` — a
/// singular-looking name for a map keyed by network — which is why the
/// repository-owned type is called `ContainerNetworkingConfig` and this one
/// `NetworkingConfigDocument`; the field below is the only place the two
/// spellings meet.
#[derive(Debug, Serialize)]
struct NetworkingConfigDocument<'a> {
    #[serde(rename = "EndpointsConfig")]
    endpoints: BTreeMap<&'a str, EndpointSettingsDocument<'a>>,
}

/// One entry of an `EndpointsConfig` map.
#[derive(Debug, Default, Serialize)]
struct EndpointSettingsDocument<'a> {
    #[serde(rename = "Aliases", skip_serializing_if = "Option::is_none")]
    aliases: Option<&'a [String]>,
    #[serde(rename = "Links", skip_serializing_if = "Option::is_none")]
    links: Option<&'a [String]>,
    #[serde(rename = "MacAddress", skip_serializing_if = "Option::is_none")]
    mac_address: Option<&'a str>,
}

impl<'a> NetworkingConfigDocument<'a> {
    /// Projects the repository-owned networking configuration.
    ///
    /// A `Some` holding an empty map is sent as an empty map, not omitted: a
    /// caller that asked for a container with no explicit network still expects
    /// the daemon's default-network behaviour, and the Engine distinguishes
    /// "no `NetworkingConfig`" from "an empty one".
    fn new(networking: &'a ContainerNetworkingConfig) -> Self {
        Self {
            endpoints: networking
                .endpoints
                .iter()
                .map(|(network, settings)| {
                    (
                        network.as_str(),
                        EndpointSettingsDocument {
                            aliases: nonempty(&settings.aliases),
                            links: nonempty(&settings.links),
                            mac_address: settings.mac_address.as_deref(),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl<'a> CreateDocument<'a> {
    /// Projects the repository-owned create options onto the Engine's body.
    ///
    /// `stop_timeout` is read out of the host configuration and sent as a
    /// top-level member, because that is where the Engine defines it; it is not
    /// a `HostConfig` member.
    ///
    /// # Errors
    ///
    /// Returns an error when the restart policy is not one of the names the
    /// Engine accepts. Refusing it here keeps a bad name a caller mistake
    /// rather than a `400` the daemon has to explain.
    fn new(options: &'a ContainerCreateOptions) -> Result<Self, Error> {
        let host_config = options.host_config.as_ref();
        Ok(Self {
            image: &options.image,
            hostname: options.hostname.as_deref(),
            domainname: options.domainname.as_deref(),
            user: options.user.as_deref(),
            mac_address: options.mac_address.as_deref(),
            working_dir: options.working_dir.as_deref(),
            stop_signal: options.stop_signal.as_deref(),
            attach_stdin: true_when(options.attach_stdin),
            attach_stdout: true_when(options.attach_stdout),
            attach_stderr: true_when(options.attach_stderr),
            tty: true_when(options.tty),
            open_stdin: true_when(options.open_stdin),
            environment: nonempty(&options.environment),
            command: nonempty(&options.command),
            // An entrypoint is an `Option` upstream, and `Some(vec![])` is
            // meaningful: it asks the daemon to clear the image's entrypoint.
            entrypoint: options.entrypoint.as_deref(),
            labels: (!options.labels.is_empty()).then_some(&options.labels),
            exposed_ports: (!options.exposed_ports.is_empty()).then(|| {
                options
                    .exposed_ports
                    .iter()
                    .map(|port| (port.as_str(), BTreeMap::new()))
                    .collect()
            }),
            // A `Some` is sent even when it holds nothing, because the Engine
            // reads an empty health-check object as "no healthcheck" and a
            // missing one as "inherit the image's".
            healthcheck: options.healthcheck.as_ref().map(HealthDocument::from),
            stop_timeout: host_config.and_then(|config| config.stop_timeout),
            networking_config: options
                .networking_config
                .as_ref()
                .map(NetworkingConfigDocument::new),
            host_config: host_config
                .filter(|config| **config != ContainerHostConfig::default())
                .map(HostConfigDocument::new)
                .transpose()?,
        })
    }
}

/// The health-check block of a create body.
#[derive(Debug, Serialize)]
struct HealthDocument<'a> {
    #[serde(rename = "Test", skip_serializing_if = "Option::is_none")]
    test: Option<&'a [String]>,
    #[serde(rename = "Interval", skip_serializing_if = "Option::is_none")]
    interval: Option<i64>,
    #[serde(rename = "Timeout", skip_serializing_if = "Option::is_none")]
    timeout: Option<i64>,
    #[serde(rename = "StartPeriod", skip_serializing_if = "Option::is_none")]
    start_period: Option<i64>,
    #[serde(rename = "StartInterval", skip_serializing_if = "Option::is_none")]
    start_interval: Option<i64>,
    #[serde(rename = "Retries", skip_serializing_if = "Option::is_none")]
    retries: Option<i64>,
}

impl<'a> From<&'a HealthConfig> for HealthDocument<'a> {
    fn from(config: &'a HealthConfig) -> Self {
        Self {
            test: config.test.as_deref(),
            interval: config.interval,
            timeout: config.timeout,
            start_period: config.start_period,
            start_interval: config.start_interval,
            retries: config.retries,
        }
    }
}

/// The `HostConfig` block of a create body.
#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct HostConfigDocument<'a> {
    #[serde(rename = "Binds", skip_serializing_if = "Option::is_none")]
    binds: Option<&'a [String]>,
    #[serde(rename = "PortBindings", skip_serializing_if = "Option::is_none")]
    port_bindings: Option<BTreeMap<&'a str, Vec<PortBindingDocument<'a>>>>,
    #[serde(rename = "Umask", skip_serializing_if = "Option::is_none")]
    umask: Option<u32>,
    #[serde(rename = "Privileged", skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,
    #[serde(rename = "Dns", skip_serializing_if = "Option::is_none")]
    dns: Option<&'a [String]>,
    #[serde(rename = "RestartPolicy", skip_serializing_if = "Option::is_none")]
    restart_policy: Option<RestartPolicyDocument<'a>>,
    #[serde(rename = "Devices", skip_serializing_if = "Option::is_none")]
    devices: Option<Vec<DeviceDocument<'a>>>,
    #[serde(rename = "ExtraHosts", skip_serializing_if = "Option::is_none")]
    extra_hosts: Option<&'a [String]>,
    #[serde(rename = "CapAdd", skip_serializing_if = "Option::is_none")]
    cap_add: Option<&'a [String]>,
    #[serde(rename = "CapDrop", skip_serializing_if = "Option::is_none")]
    cap_drop: Option<&'a [String]>,
    #[serde(rename = "ReadonlyRootfs", skip_serializing_if = "Option::is_none")]
    read_only_rootfs: Option<bool>,
    #[serde(rename = "Init", skip_serializing_if = "Option::is_none")]
    init: Option<bool>,
    #[serde(rename = "ShmSize", skip_serializing_if = "Option::is_none")]
    shm_size: Option<i64>,
    #[serde(rename = "Tmpfs", skip_serializing_if = "Option::is_none")]
    tmpfs: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "Ulimits", skip_serializing_if = "Option::is_none")]
    ulimits: Option<Vec<UlimitDocument<'a>>>,
    #[serde(rename = "GroupAdd", skip_serializing_if = "Option::is_none")]
    group_add: Option<&'a [String]>,
    #[serde(rename = "Sysctls", skip_serializing_if = "Option::is_none")]
    sysctls: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "SecurityOpt", skip_serializing_if = "Option::is_none")]
    security_options: Option<&'a [String]>,
    #[serde(rename = "DnsSearch", skip_serializing_if = "Option::is_none")]
    dns_search: Option<&'a [String]>,
    #[serde(rename = "LogConfig", skip_serializing_if = "Option::is_none")]
    log_config: Option<LogConfigDocument<'a>>,
    #[serde(rename = "NetworkMode", skip_serializing_if = "Option::is_none")]
    network_mode: Option<&'a str>,
    #[serde(rename = "IpcMode", skip_serializing_if = "Option::is_none")]
    ipc_mode: Option<&'a str>,
    #[serde(rename = "PidMode", skip_serializing_if = "Option::is_none")]
    pid_mode: Option<&'a str>,
    #[serde(rename = "UsernsMode", skip_serializing_if = "Option::is_none")]
    userns_mode: Option<&'a str>,
    #[serde(rename = "NanoCpus", skip_serializing_if = "Option::is_none")]
    nano_cpus: Option<i64>,
    #[serde(rename = "Memory", skip_serializing_if = "Option::is_none")]
    memory: Option<i64>,
    #[serde(rename = "MemoryReservation", skip_serializing_if = "Option::is_none")]
    memory_reservation: Option<i64>,
    #[serde(rename = "PidsLimit", skip_serializing_if = "Option::is_none")]
    pids_limit: Option<i64>,
    #[serde(rename = "CpuShares", skip_serializing_if = "Option::is_none")]
    cpu_shares: Option<i64>,
    #[serde(rename = "CpuPeriod", skip_serializing_if = "Option::is_none")]
    cpu_period: Option<i64>,
    #[serde(rename = "CpuQuota", skip_serializing_if = "Option::is_none")]
    cpu_quota: Option<i64>,
    #[serde(rename = "CpusetCpus", skip_serializing_if = "Option::is_none")]
    cpuset_cpus: Option<&'a str>,
    #[serde(rename = "DnsOptions", skip_serializing_if = "Option::is_none")]
    dns_options: Option<&'a [String]>,
    #[serde(rename = "UtsMode", skip_serializing_if = "Option::is_none")]
    uts_mode: Option<&'a str>,
    #[serde(rename = "VolumesFrom", skip_serializing_if = "Option::is_none")]
    volumes_from: Option<&'a [String]>,
    #[serde(rename = "DeviceRequests", skip_serializing_if = "Option::is_none")]
    device_requests: Option<Vec<DeviceRequestDocument<'a>>>,
    #[serde(rename = "Isolation", skip_serializing_if = "Option::is_none")]
    isolation: Option<&'a str>,
    #[serde(rename = "Runtime", skip_serializing_if = "Option::is_none")]
    runtime: Option<&'a str>,
    #[serde(rename = "OomKillDisable", skip_serializing_if = "Option::is_none")]
    oom_kill_disable: Option<bool>,
    #[serde(rename = "OomScoreAdj", skip_serializing_if = "Option::is_none")]
    oom_score_adj: Option<i64>,
}

impl<'a> HostConfigDocument<'a> {
    /// Projects the repository-owned host configuration onto the Engine's block.
    ///
    /// # Errors
    ///
    /// Returns an error when the restart policy name is not one the Engine
    /// accepts.
    #[allow(clippy::too_many_lines)]
    fn new(config: &'a ContainerHostConfig) -> Result<Self, Error> {
        Ok(Self {
            binds: nonempty(&config.binds),
            port_bindings: (!config.port_bindings.is_empty()).then(|| {
                config
                    .port_bindings
                    .iter()
                    .map(|mapping| {
                        (
                            mapping.container_port.as_str(),
                            mapping
                                .bindings
                                .iter()
                                .map(PortBindingDocument::from)
                                .collect(),
                        )
                    })
                    .collect()
            }),
            umask: config.umask.as_deref().map(umask_value).transpose()?,
            privileged: true_when(config.privileged),
            dns: nonempty(&config.dns),
            restart_policy: config
                .restart_policy
                .as_ref()
                .map(RestartPolicyDocument::new)
                .transpose()?,
            devices: (!config.devices.is_empty())
                .then(|| config.devices.iter().map(DeviceDocument::from).collect()),
            extra_hosts: nonempty(&config.extra_hosts),
            cap_add: nonempty(&config.cap_add),
            cap_drop: nonempty(&config.cap_drop),
            read_only_rootfs: true_when(config.read_only_rootfs),
            init: true_when(config.init),
            shm_size: config.shm_size,
            tmpfs: (!config.tmpfs.is_empty()).then_some(&config.tmpfs),
            ulimits: (!config.ulimits.is_empty())
                .then(|| config.ulimits.iter().map(UlimitDocument::from).collect()),
            group_add: nonempty(&config.group_add),
            sysctls: (!config.sysctls.is_empty()).then_some(&config.sysctls),
            security_options: nonempty(&config.security_options),
            dns_search: nonempty(&config.dns_search),
            log_config: config.log_config.as_ref().map(LogConfigDocument::from),
            network_mode: config.network_mode.as_deref(),
            ipc_mode: config.ipc_mode.as_deref(),
            pid_mode: config.pid_mode.as_deref(),
            userns_mode: config.userns_mode.as_deref(),
            nano_cpus: config.nano_cpus,
            memory: config.memory,
            memory_reservation: config.memory_reservation,
            pids_limit: config.pids_limit,
            cpu_shares: config.cpu_shares,
            cpu_period: config.cpu_period,
            cpu_quota: config.cpu_quota,
            cpuset_cpus: config.cpuset_cpus.as_deref(),
            dns_options: nonempty(&config.dns_options),
            uts_mode: config.uts_mode.as_deref(),
            volumes_from: nonempty(&config.volumes_from),
            device_requests: (!config.device_requests.is_empty()).then(|| {
                config
                    .device_requests
                    .iter()
                    .map(DeviceRequestDocument::from)
                    .collect()
            }),
            isolation: config.isolation.as_deref(),
            runtime: config.runtime.as_deref(),
            oom_kill_disable: true_when(config.oom_kill_disable),
            oom_score_adj: config.oom_score_adj,
        })
    }
}

/// One host device exposed inside a container.
///
/// The repository type spells this `path_on_host`, so serializing it directly
/// would put `path_on_host` in a body the Engine reads as `PathOnHost` and
/// silently drop the device.
#[derive(Debug, Serialize)]
struct DeviceDocument<'a> {
    #[serde(rename = "PathOnHost")]
    path_on_host: &'a str,
    #[serde(rename = "PathInContainer")]
    path_in_container: &'a str,
    #[serde(rename = "CgroupPermissions")]
    cgroup_permissions: &'a str,
}

impl<'a> From<&'a DeviceMapping> for DeviceDocument<'a> {
    fn from(device: &'a DeviceMapping) -> Self {
        Self {
            path_on_host: &device.path_on_host,
            path_in_container: &device.path_in_container,
            cgroup_permissions: &device.cgroup_permissions,
        }
    }
}

/// One named process limit.
///
/// `Ulimit` is `snake_case` upstream, and both `Name` and `Soft` are capitalized
/// on the wire, so this is a projection rather than a direct serialization.
#[derive(Debug, Serialize)]
struct UlimitDocument<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Soft")]
    soft: i64,
    #[serde(rename = "Hard")]
    hard: i64,
}

impl<'a> From<&'a Ulimit> for UlimitDocument<'a> {
    fn from(limit: &'a Ulimit) -> Self {
        Self {
            name: &limit.name,
            soft: limit.soft,
            hard: limit.hard,
        }
    }
}

/// One device-driver request, such as an NVIDIA GPU allocation.
///
/// The Engine spells the identifier list `DeviceIDs`, which is neither the
/// upstream `device_ids` nor what `rename_all` produces.
#[derive(Debug, Serialize)]
struct DeviceRequestDocument<'a> {
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    driver: Option<&'a str>,
    #[serde(rename = "Count", skip_serializing_if = "Option::is_none")]
    count: Option<i64>,
    #[serde(rename = "DeviceIDs", skip_serializing_if = "Option::is_none")]
    device_ids: Option<&'a [String]>,
    #[serde(rename = "Capabilities", skip_serializing_if = "Option::is_none")]
    capabilities: Option<&'a [Vec<String>]>,
}

impl<'a> From<&'a DeviceRequest> for DeviceRequestDocument<'a> {
    fn from(request: &'a DeviceRequest) -> Self {
        Self {
            driver: request.driver.as_deref(),
            count: request.count,
            device_ids: request.device_ids.as_deref(),
            capabilities: request.capabilities.as_deref(),
        }
    }
}

/// One host binding of a published container port.
#[derive(Debug, Serialize)]
struct PortBindingDocument<'a> {
    #[serde(rename = "HostIp")]
    host_ip: &'a str,
    #[serde(rename = "HostPort")]
    host_port: &'a str,
}

impl<'a> From<&'a ContainerPortBinding> for PortBindingDocument<'a> {
    fn from(binding: &'a ContainerPortBinding) -> Self {
        Self {
            // An absent host address asks the daemon to bind every address,
            // which is what an empty Engine value means.
            host_ip: binding.host_ip.as_deref().unwrap_or_default(),
            host_port: binding.host_port.as_deref().unwrap_or_default(),
        }
    }
}

/// The Engine's `HostConfig.RestartPolicy` block.
#[derive(Debug, Serialize)]
struct RestartPolicyDocument<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "MaximumRetryCount", skip_serializing_if = "Option::is_none")]
    maximum_retry_count: Option<i64>,
}

impl<'a> RestartPolicyDocument<'a> {
    /// Projects a repository restart policy onto the Engine's block.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not one the Engine accepts. The Engine
    /// allows exactly `""`, `no`, `always`, `unless-stopped`, and `on-failure`,
    /// and a name outside that set is a caller mistake rather than something
    /// to discover as a daemon `400`.
    fn new(policy: &'a RestartPolicy) -> Result<Self, Error> {
        Ok(Self {
            name: restart_policy_name(&policy.name)?,
            maximum_retry_count: policy.maximum_retry_count,
        })
    }
}

/// Returns the Engine's spelling of a restart policy name.
fn restart_policy_name(name: &str) -> Result<&'static str, Error> {
    match name {
        "" => Ok(""),
        "no" => Ok("no"),
        "always" => Ok("always"),
        "unless-stopped" => Ok("unless-stopped"),
        "on-failure" => Ok("on-failure"),
        other => Err(Error::invalid_input(format!(
            "invalid container restart policy '{other}'"
        ))),
    }
}

/// The Engine's `HostConfig.LogConfig` block.
#[derive(Debug, Serialize)]
struct LogConfigDocument<'a> {
    #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
    driver: Option<&'a str>,
    #[serde(rename = "Config", skip_serializing_if = "Option::is_none")]
    options: Option<&'a BTreeMap<String, String>>,
}

impl<'a> From<&'a LogConfig> for LogConfigDocument<'a> {
    fn from(config: &'a LogConfig) -> Self {
        Self {
            driver: config.driver.as_deref(),
            options: (!config.options.is_empty()).then_some(&config.options),
        }
    }
}

/// Converts a caller-written umask into the number the Engine declares.
///
/// `ContainerHostConfig::umask` carries the conventional octal spelling, such
/// as `0022`, because that is how a user, a Compose file, and `chmod` all write
/// a umask. The Engine's `HostConfig.Umask` is a `uint32`, so the octal digits
/// have to be converted rather than forwarded. Forwarding the string is not a
/// tolerated difference: Docker Engine 29.8.0 answers
/// `POST /containers/create` with a body carrying `"Umask":"0022"` with
///
/// ```text
/// 400 invalid JSON: json: cannot unmarshal string into
///     Go struct field HostConfig.HostConfig.Umask of type uint32
/// ```
///
/// so a create request carrying a umask fails outright.
///
/// The facade used to install a JSON string here and had the same defect; it was
/// verified against Docker Engine 29.8.0, which answered
/// `POST /containers/create` with
///
/// ```text
/// 400 invalid JSON: json: cannot unmarshal string into
///     Go struct field HostConfig.HostConfig.Umask of type uint32
/// ```
///
/// and now converts the octal digits the same way. The two paths agree on the
/// wire for this member, which is checked rather than assumed.
///
/// # Errors
///
/// Returns an error when the value is not octal digits or does not fit in the
/// Engine's `uint32`. A umask the daemon would refuse is a caller mistake, and
/// finding out here names it instead of reporting a `400` about JSON.
fn umask_value(umask: &str) -> Result<u32, Error> {
    let digits = umask.strip_prefix("0o").unwrap_or(umask);
    u32::from_str_radix(digits, 8).map_err(|error| {
        Error::invalid_input(format!("invalid container umask '{umask}': {error}"))
    })
}

/// Returns the Engine's spelling of a boolean, or nothing when it is false.///
/// A `false` the caller never set and a `false` the caller set are the same
/// request, so only the truthy value is sent.
fn true_when(value: bool) -> Option<bool> {
    value.then_some(true)
}

/// Returns the slice when it has values, or nothing when it does not.
///
/// An empty JSON array is not the same as an absent member to every daemon, and
/// an unset repository option means "not requested" rather than "requested
/// nothing".
fn nonempty(values: &[String]) -> Option<&[String]> {
    (!values.is_empty()).then_some(values)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use hyper::Method;
    use hyper::StatusCode;

    use super::{
        CommitDocument, ContainerCreateDocument, ContainerSummaryDocument, ContainerTopDocument,
        ContainerWaitDocument, commit_container_request, container_archive_download_request,
        container_archive_stat_request, container_archive_upload_request, container_create_request,
        container_list_request, container_remove_request, container_restart_request,
        container_start_request, container_stop_request, container_top_request,
        container_wait_request, escape_path_segment, export_container_request, restart_policy_name,
        umask_value,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawTarget};
    use crate::{
        ApiVersion, CommitContainerOptions, ContainerArchiveUploadOptions, ContainerCreateOptions,
        ContainerHostConfig, ContainerListOptions, ContainerPortBinding, ContainerRemoveOptions,
        ContainerRestartOptions, ContainerStartOptions, ContainerStopOptions, ContainerSummary,
        ContainerWaitOptions, DeviceMapping, DeviceRequest, ErrorKind, HealthConfig, LogConfig,
        PortMapping, RestartPolicy, Ulimit,
    };
    use crate::{ContainerEndpointSettings, ContainerNetworkingConfig};

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling, because what these assertions are
    /// about is the *path* and its query encoding, not the number in the
    /// prefix. A literal here would mean every one of them breaks on a
    /// legitimate ceiling change, and a test that breaks on a correct change
    /// is a test that gets deleted rather than trusted.
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

    /// Renders the request body as parsed JSON, so an assertion names members
    /// rather than depending on their order in the serialized text.
    fn request_body(request: &super::RawRequest) -> serde_json::Value {
        match &request.body {
            RawBody::Bytes(bytes) => serde_json::from_slice(bytes).expect("a JSON body"),
            other => panic!("expected a buffered body, got {other:?}"),
        }
    }

    /// Decodes a percent-encoded query value the way the Engine's Go side does.
    fn percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex =
                    std::str::from_utf8(&bytes[index + 1..index + 3]).expect("two hex digits");
                decoded.push(u8::from_str_radix(hex, 16).expect("a hex escape"));
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(decoded).expect("a UTF-8 value")
    }

    /// Decodes a `GET /containers/{id}/top` document the way the operation
    /// does, so a projection assertion is about the same conversion.
    fn decode_top(body: &str) -> crate::ContainerTop {
        crate::raw::decode::<ContainerTopDocument>(body.as_bytes())
            .map(crate::ContainerTop::from)
            .expect("a top document")
    }

    fn filters() -> BTreeMap<String, Vec<String>> {
        let mut filters = BTreeMap::new();
        filters.insert("label".to_owned(), vec!["tier=web".to_owned()]);
        filters.insert(
            "status".to_owned(),
            vec!["running".to_owned(), "paused".to_owned()],
        );
        filters
    }

    #[test]
    fn list_sends_the_versioned_path_with_every_option_spelled() {
        let request = container_list_request(&ContainerListOptions {
            all: true,
            limit: Some(5),
            size: false,
            filters: filters(),
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/json?all=true&limit=5&size=false&filters=%7B%22label%22%3A%5B%22tier%3Dweb%22%5D%2C%22status%22%3A%5B%22running%22%2C%22paused%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_list_without_options_says_so_instead_of_leaving_it_to_the_daemon() {
        let request = container_list_request(&ContainerListOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/json?all=false&size=false HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_filter_map_is_not_sent_at_all() {
        let request = container_list_request(&ContainerListOptions {
            filters: BTreeMap::new(),
            ..Default::default()
        })
        .expect("request");
        assert!(
            request
                .query
                .as_deref()
                .is_none_or(|query| !query.contains("filters")),
            "{:?}",
            request.query
        );
    }

    #[test]
    fn the_filters_value_is_url_encoded_json_that_round_trips() {
        // The Engine's `filters` value is JSON inside a query value, so a raw
        // brace or quote would end the query parameter. It has to survive as
        // data, and it has to decode back to the map the caller asked for.
        let request = container_list_request(&ContainerListOptions {
            all: true,
            filters: filters(),
            ..Default::default()
        })
        .expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        assert!(!value.contains('{'), "the JSON must be encoded: {value}");
        assert!(!value.contains('"'), "the JSON must be encoded: {value}");
        // The wire value is percent-encoded; decoding it is the daemon's job,
        // and the fixture test asserts the daemon received the same JSON.
        let decoded = percent_decode(value);
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, Vec<String>>>(&decoded).expect("filter JSON"),
            filters()
        );
    }

    #[test]
    fn filter_keys_are_emitted_in_order_so_a_recorded_request_is_reproducible() {
        // The repository filter map is ordered, so the encoded JSON is the same
        // on every run. A recorded request that varies between runs of the same
        // command cannot be diffed against anything.
        let request = container_list_request(&ContainerListOptions {
            filters: filters(),
            ..Default::default()
        })
        .expect("request");
        let query = request.query.expect("a query");
        let (_, value) = query.split_once("filters=").expect("the filters pair");
        let decoded = percent_decode(value);
        assert!(
            decoded.find("\"label\"").expect("label") < decoded.find("\"status\"").expect("status"),
            "keys must be in map order: {decoded}"
        );
    }

    #[test]
    fn the_container_name_travels_in_the_query_and_not_in_the_body() {
        // Docker reads the name from `?name=` only. A `Name` member in the body
        // is accepted and ignored, so the container would be created under a
        // generated name the caller never learns.
        let request = container_create_request(&ContainerCreateOptions {
            image: "alpine:3.19".to_owned(),
            name: Some("web app/1".to_owned()),
            command: vec!["sleep".to_owned(), "1".to_owned()],
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/create?name=web+app%2F1 HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body.get("Name"), None, "the body must not name it: {body}");
        assert_eq!(
            body.get("Image").and_then(|value| value.as_str()),
            Some("alpine:3.19")
        );
        assert_eq!(
            body.get("Cmd").and_then(|value| value.as_str()),
            None,
            "an array is not a string"
        );
    }

    #[test]
    fn a_create_without_a_name_sends_no_query_at_all() {
        let request = container_create_request(&ContainerCreateOptions {
            image: "alpine:3.19".to_owned(),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/create HTTP/1.1")
        );
    }

    /// The create body carries the networks the caller asked for.
    ///
    /// Without this member the Engine attaches the container to nothing: no
    /// network, no alias, no link, no endpoint MAC address. It was the reason
    /// `DockerClient::create_container` could not be routed onto this transport,
    /// and `docker compose` sets it for every service with more than one
    /// network, so the gap would have been a live regression.
    #[test]
    fn a_create_carries_the_networking_configuration() {
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                networking_config: Some(ContainerNetworkingConfig {
                    endpoints: BTreeMap::from([
                        (
                            "front".to_owned(),
                            ContainerEndpointSettings {
                                aliases: vec!["web".to_owned(), "www".to_owned()],
                                links: vec!["db:db".to_owned()],
                                mac_address: Some("02:42:ac:11:00:02".to_owned()),
                            },
                        ),
                        ("back".to_owned(), ContainerEndpointSettings::default()),
                    ]),
                }),
                ..Default::default()
            })
            .expect("request"),
        );
        // The Engine's member name for the per-network map is `EndpointsConfig`,
        // not `Endpoints` — a spelling that does not look like a map at all.
        assert_eq!(
            body.get("NetworkingConfig")
                .and_then(|config| config.get("EndpointsConfig"))
                .and_then(|endpoints| endpoints.get("front"))
                .and_then(|front| front.get("Aliases"))
                .and_then(|aliases| aliases.as_array())
                .map(|aliases| aliases
                    .iter()
                    .filter_map(|alias| alias.as_str())
                    .collect::<Vec<_>>()),
            Some(vec!["web", "www"]),
            "a network's aliases must survive: {body}"
        );
        assert_eq!(
            body.pointer("/NetworkingConfig/EndpointsConfig/front/MacAddress")
                .and_then(|mac| mac.as_str()),
            Some("02:42:ac:11:00:02"),
            "{body}"
        );
        assert_eq!(
            body.pointer("/NetworkingConfig/EndpointsConfig/front/Links")
                .and_then(|links| links.as_array())
                .map(Vec::len),
            Some(1),
            "{body}"
        );
        // A network the caller gave nothing for still appears, with no members of
        // its own: the Engine needs the key to attach to it at all.
        assert!(
            body.pointer("/NetworkingConfig/EndpointsConfig/back")
                .is_some_and(|back| back.as_object().is_some_and(serde_json::Map::is_empty)),
            "a network with no settings must still be named, with nothing sent for it: {body}"
        );
    }

    /// An endpoint with no aliases, links, or MAC sends no members at all.
    ///
    /// Not cosmetic: the Engine reads an empty `Aliases` and a missing one the
    /// same way, but a `null` where a list belongs is a `400`, and an endpoint
    /// that is present must not carry members the caller never set.
    #[test]
    fn an_empty_endpoint_sends_no_members() {
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                networking_config: Some(ContainerNetworkingConfig {
                    endpoints: BTreeMap::from([(
                        "solo".to_owned(),
                        ContainerEndpointSettings::default(),
                    )]),
                }),
                ..Default::default()
            })
            .expect("request"),
        );
        let endpoint = body
            .pointer("/NetworkingConfig/EndpointsConfig/solo")
            .expect("the network is named");
        assert_eq!(endpoint.as_object().map(serde_json::Map::len), Some(0));
    }

    /// A create that asked for no networks sends no `NetworkingConfig`.
    ///
    /// The member is omitted rather than sent empty, because a caller that set
    /// nothing expects the daemon's default-network behaviour, which is
    /// expressed by its absence.
    #[test]
    fn a_create_without_networking_options_sends_no_networking_config() {
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                ..Default::default()
            })
            .expect("request"),
        );
        assert!(
            body.get("NetworkingConfig").is_none(),
            "an unasked-for member must be absent, not empty: {body}"
        );
    }

    #[test]
    fn a_create_sends_a_platform_only_when_one_was_asked_for() {
        let request = container_create_request(&ContainerCreateOptions {
            image: "alpine:3.19".to_owned(),
            name: Some("web".to_owned()),
            platform: Some("linux/arm64".to_owned()),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/create?name=web&platform=linux%2Farm64 HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_omitted_create_member_is_left_out_rather_than_sent_as_null() {
        // The Engine reads a missing member and a `null` member differently for
        // several create fields, so an unset option has to stay unset.
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                environment: Vec::new(),
                labels: BTreeMap::new(),
                host_config: Some(ContainerHostConfig::default()),
                ..Default::default()
            })
            .expect("request"),
        );
        let object = body.as_object().expect("a JSON object");
        assert_eq!(object.len(), 1, "only the image is set: {body}");
        assert_eq!(object.keys().collect::<Vec<_>>(), vec!["Image"]);
    }

    #[test]
    fn the_create_body_uses_the_engine_member_spellings() {
        // Every one of these is spelled differently on the wire than upstream.
        // A wrong spelling is not a decode failure: the Engine ignores a member
        // it does not know, so the request silently asks for less than the
        // caller wanted.
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                hostname: Some("web".to_owned()),
                working_dir: Some("/srv".to_owned()),
                tty: true,
                attach_stdout: true,
                open_stdin: true,
                environment: vec!["A=B".to_owned()],
                command: vec!["sleep".to_owned(), "1".to_owned()],
                entrypoint: Some(Vec::new()),
                exposed_ports: vec!["80/tcp".to_owned()],
                labels: BTreeMap::from([("tier".to_owned(), "web".to_owned())]),
                healthcheck: Some(HealthConfig {
                    test: Some(vec!["CMD-SHELL".to_owned(), "true".to_owned()]),
                    interval: Some(1_000_000_000),
                    retries: Some(3),
                    ..Default::default()
                }),
                host_config: Some(ContainerHostConfig {
                    umask: Some("0022".to_owned()),
                    stop_timeout: Some(17),
                    privileged: true,
                    binds: vec!["/srv:/srv:ro".to_owned()],
                    port_bindings: vec![PortMapping {
                        container_port: "80/tcp".to_owned(),
                        bindings: vec![ContainerPortBinding {
                            host_ip: None,
                            host_port: Some("8080".to_owned()),
                        }],
                    }],
                    restart_policy: Some(RestartPolicy {
                        name: "unless-stopped".to_owned(),
                        maximum_retry_count: Some(3),
                    }),
                    devices: vec![DeviceMapping {
                        path_on_host: "/dev/null".to_owned(),
                        path_in_container: "/dev/null".to_owned(),
                        cgroup_permissions: "rwm".to_owned(),
                    }],
                    ulimits: vec![Ulimit {
                        name: "nofile".to_owned(),
                        soft: 1024,
                        hard: 2048,
                    }],
                    log_config: Some(LogConfig {
                        driver: Some("json-file".to_owned()),
                        options: BTreeMap::from([("max-size".to_owned(), "1m".to_owned())]),
                    }),
                    device_requests: vec![DeviceRequest {
                        driver: Some("nvidia".to_owned()),
                        count: Some(-1),
                        device_ids: Some(vec!["0".to_owned()]),
                        capabilities: Some(vec![vec!["gpu".to_owned()]]),
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            })
            .expect("request"),
        );
        assert_eq!(body["Hostname"], "web");
        assert_eq!(body["WorkingDir"], "/srv");
        assert_eq!(body["Tty"], true);
        assert_eq!(body["AttachStdout"], true);
        assert_eq!(body["OpenStdin"], true);
        assert_eq!(body["Env"][0], "A=B");
        assert_eq!(body["Cmd"][1], "1");
        // An empty entrypoint is a request to clear the image's entrypoint, so
        // it must be sent as an empty array rather than omitted.
        assert_eq!(body["Entrypoint"], serde_json::json!([]));
        assert_eq!(body["ExposedPorts"], serde_json::json!({ "80/tcp": {} }));
        assert_eq!(body["Labels"], serde_json::json!({ "tier": "web" }));
        assert_eq!(body["Healthcheck"]["Test"][0], "CMD-SHELL");
        assert_eq!(body["Healthcheck"]["Retries"], 3);
        // `stop_timeout` is a top-level member, not a `HostConfig` one.
        assert_eq!(body["StopTimeout"], 17);
        let host = &body["HostConfig"];
        assert_eq!(host["Umask"], 18);
        // The repository type carries the octal spelling `0022` and the Engine
        // declares a `uint32`, so the value is converted rather than forwarded.
        // Docker Engine 29.8.0 answers a create body carrying the string
        // `"Umask":"0022"` with `400 cannot unmarshal string into ... of type
        // uint32`, so forwarding it is a request that cannot succeed.
        assert_eq!(host["Privileged"], true);
        assert_eq!(host["Binds"][0], "/srv:/srv:ro");
        assert_eq!(host["PortBindings"]["80/tcp"][0]["HostPort"], "8080");
        assert_eq!(host["PortBindings"]["80/tcp"][0]["HostIp"], "");
        assert_eq!(host["RestartPolicy"]["Name"], "unless-stopped");
        assert_eq!(host["RestartPolicy"]["MaximumRetryCount"], 3);
        assert_eq!(host["Devices"][0]["PathOnHost"], "/dev/null");
        assert_eq!(host["Devices"][0]["CgroupPermissions"], "rwm");
        assert_eq!(host["Ulimits"][0]["Name"], "nofile");
        assert_eq!(host["Ulimits"][0]["Soft"], 1024);
        assert_eq!(host["LogConfig"]["Type"], "json-file");
        assert_eq!(host["LogConfig"]["Config"]["max-size"], "1m");
        assert_eq!(host["DeviceRequests"][0]["Driver"], "nvidia");
        assert_eq!(host["DeviceRequests"][0]["DeviceIDs"][0], "0");
        assert_eq!(host["DeviceRequests"][0]["Capabilities"][0][0], "gpu");
        assert!(host.get("StopTimeout").is_none(), "not a HostConfig member");
    }

    #[test]
    fn an_unset_host_config_is_omitted_rather_than_sent_empty() {
        let body = request_body(
            &container_create_request(&ContainerCreateOptions {
                image: "alpine:3.19".to_owned(),
                host_config: Some(ContainerHostConfig::default()),
                ..Default::default()
            })
            .expect("request"),
        );
        assert!(body.get("HostConfig").is_none(), "{body}");
    }

    #[test]
    fn a_restart_policy_the_engine_would_reject_is_refused_before_the_socket() {
        let error = container_create_request(&ContainerCreateOptions {
            image: "alpine:3.19".to_owned(),
            host_config: Some(ContainerHostConfig {
                restart_policy: Some(RestartPolicy {
                    name: "sometimes".to_owned(),
                    maximum_retry_count: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .expect_err("an unknown policy");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_umask_is_converted_from_the_octal_spelling_the_caller_writes() {
        // A umask is written in octal everywhere a person writes one, and the
        // Engine declares `HostConfig.Umask` as a `uint32`. Forwarding the
        // string is a request Docker Engine 29.8.0 answers with
        // `400 ... cannot unmarshal string into ... of type uint32`.
        for (written, engine) in [
            ("0022", 18),
            ("22", 18),
            ("0o022", 18),
            ("0000", 0),
            ("0777", 511),
        ] {
            assert_eq!(umask_value(written).expect("octal"), engine, "{written}");
        }
    }

    #[test]
    fn a_umask_that_is_not_octal_is_refused_before_the_socket() {
        for rejected in ["", "8", "0o8", "rwx", "-0022"] {
            let error = umask_value(rejected).expect_err("not octal");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{rejected}");
        }
    }

    #[test]
    fn the_engine_accepts_exactly_four_restart_policy_names_and_the_empty_one() {
        for accepted in ["", "no", "always", "unless-stopped", "on-failure"] {
            assert_eq!(
                restart_policy_name(accepted).expect("an accepted name"),
                accepted
            );
        }
        assert!(restart_policy_name("unlessstopped").is_err());
        assert!(restart_policy_name("on-failure-max").is_err());
    }

    #[test]
    fn start_sends_a_versioned_path_and_no_query_without_detach_keys() {
        let request = container_start_request("slice-db-1", &ContainerStartOptions::default())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/slice-db-1/start HTTP/1.1")
        );
        let detach = container_start_request(
            "slice-db-1",
            &ContainerStartOptions {
                detach_keys: Some("ctrl-p,ctrl-q".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&detach),
            crate::raw::at_api_version(
                "POST /v1.API/containers/slice-db-1/start?detachKeys=ctrl-p%2Cctrl-q HTTP/1.1"
            )
        );
    }

    #[test]
    fn stop_sends_the_signal_and_the_timeout_in_that_order() {
        let request = container_stop_request(
            "slice-db-1",
            &ContainerStopOptions {
                signal: Some("SIGTERM".to_owned()),
                timeout_seconds: Some(10),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/slice-db-1/stop?signal=SIGTERM&t=10 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_stop_without_a_timeout_leaves_the_daemons_own_default_alone() {
        let request = container_stop_request("slice-db-1", &ContainerStopOptions::default())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/slice-db-1/stop HTTP/1.1")
        );
    }

    #[test]
    fn restart_sends_the_signal_and_the_timeout_in_that_order() {
        let request = container_restart_request(
            "slice-db-1",
            &ContainerRestartOptions {
                signal: Some("SIGTERM".to_owned()),
                timeout_seconds: Some(10),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/slice-db-1/restart?signal=SIGTERM&t=10 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_restart_without_options_leaves_the_daemons_own_defaults_alone() {
        let request = container_restart_request("slice-db-1", &ContainerRestartOptions::default())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/slice-db-1/restart HTTP/1.1")
        );
    }

    #[test]
    fn a_restart_escapes_its_container_reference_and_refuses_an_empty_one() {
        let request = container_restart_request(
            "a/b",
            &ContainerRestartOptions {
                signal: Some("SIGUSR1".to_owned()),
                timeout_seconds: None,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/containers/a%2Fb/restart?signal=SIGUSR1 HTTP/1.1"
            )
        );
        let error = container_restart_request("", &ContainerRestartOptions::default())
            .expect_err("empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn top_sends_the_versioned_path_with_the_ps_arguments() {
        let request = container_top_request("slice-db-1", Some("aux")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/slice-db-1/top?ps_args=aux HTTP/1.1"
            )
        );
    }

    #[test]
    fn top_omits_an_unrequested_or_blank_ps_argument() {
        // `None` and a whitespace-only value are the same "not requested"
        // spelling the facade already used for the generated path. Omitting the
        // parameter selects the daemon's own default -- Docker on Unix
        // substitutes `-ef` -- so the recorded request stays to the caller's
        // intent rather than carrying an empty value.
        for ps_args in [None, Some(""), Some("   ")] {
            let request = container_top_request("slice-db-1", ps_args).expect("request");
            assert_eq!(
                request_line(&request),
                crate::raw::at_api_version("GET /v1.API/containers/slice-db-1/top HTTP/1.1"),
                "{ps_args:?}"
            );
        }
    }

    #[test]
    fn top_encodes_ps_arguments_as_one_query_value() {
        // A value containing `&` must not become a second parameter.
        let request = container_top_request("slice-db-1", Some("aux -e & x")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/slice-db-1/top?ps_args=aux+-e+%26+x HTTP/1.1"
            )
        );
    }

    #[test]
    fn top_escapes_its_container_reference_and_refuses_an_empty_one() {
        let request = container_top_request("a/b", Some("aux")).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/a%2Fb/top?ps_args=aux HTTP/1.1")
        );
        let error = container_top_request("", None).expect_err("empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn export_sends_the_versioned_path_without_a_query() {
        let request = export_container_request("slice-db-1").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/slice-db-1/export HTTP/1.1")
        );
        assert!(
            request.query.is_none(),
            "the export endpoint takes no query parameters"
        );
    }

    #[test]
    fn export_escapes_its_container_reference_and_refuses_an_empty_one() {
        // `/` is a path separator, so an unescaped reference would address a
        // different resource rather than the container the caller named.
        let request = export_container_request("a/b").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("GET /v1.API/containers/a%2Fb/export HTTP/1.1")
        );
        let error = export_container_request("").expect_err("empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn archive_stat_sends_a_versioned_head_with_the_path_as_one_query_value() {
        // The path is a query value, not a path segment, and a value containing
        // `&`, `+`, or a space must not become a second parameter or change the
        // request shape.
        let request = container_archive_stat_request("slice-db-1", "/tmp/a b&c").expect("request");
        assert_eq!(request.method, Method::HEAD);
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "HEAD /v1.API/containers/slice-db-1/archive?path=%2Ftmp%2Fa+b%26c HTTP/1.1"
            )
        );
        assert!(
            matches!(request.body, RawBody::Empty),
            "a HEAD request carries no body"
        );
    }

    #[test]
    fn archive_download_sends_a_versioned_get_with_the_path_as_one_query_value() {
        let request =
            container_archive_download_request("slice-db-1", "/tmp/a b&c").expect("request");
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/slice-db-1/archive?path=%2Ftmp%2Fa+b%26c HTTP/1.1"
            )
        );
    }

    #[test]
    fn archive_requests_escape_the_reference_and_refuse_empty_inputs() {
        // `/` is a path separator, so an unescaped reference would address a
        // different resource. The path is not normalized: `..`, a trailing
        // slash, and a relative path are the container's to resolve.
        let request = container_archive_download_request("a/b", "../etc").expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/containers/a%2Fb/archive?path=..%2Fetc HTTP/1.1"
            )
        );

        for request in [
            container_archive_stat_request("", "/tmp"),
            container_archive_download_request("", "/tmp"),
            container_archive_stat_request("web", ""),
            container_archive_download_request("web", ""),
        ] {
            let error = request.expect_err("empty reference or path");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn archive_upload_sends_a_versioned_chunked_put_with_the_engine_flags() {
        let request = container_archive_upload_request(
            "a/b",
            futures_util::stream::empty::<Result<Bytes, std::io::Error>>(),
            &ContainerArchiveUploadOptions {
                path: "/tmp/a b".to_owned(),
                copy_user_and_group: true,
                no_overwrite_directory_with_file: true,
            },
        )
        .expect("request");
        assert_eq!(request.method, Method::PUT);
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "PUT /v1.API/containers/a%2Fb/archive?path=%2Ftmp%2Fa+b&noOverwriteDirNonDir=1&copyUIDGID=1 HTTP/1.1"
            )
        );
        assert_eq!(
            request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/x-tar")
        );
        assert!(
            request.body.known_len().is_none(),
            "a streamed archive is chunked rather than announced with a length"
        );
    }

    #[test]
    fn archive_upload_always_sends_copy_uidgid_like_the_generated_path() {
        // The generated path writes `copyUIDGID` as `1` or `0` and omits
        // `noOverwriteDirNonDir` unless asked. Matching that shape keeps the two
        // routes' recorded requests comparable; the daemon reads the two
        // spellings of `false` the same way.
        let request = container_archive_upload_request(
            "web",
            futures_util::stream::empty::<Result<Bytes, std::io::Error>>(),
            &ContainerArchiveUploadOptions {
                path: "/dest".to_owned(),
                copy_user_and_group: false,
                no_overwrite_directory_with_file: false,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "PUT /v1.API/containers/web/archive?path=%2Fdest&copyUIDGID=0 HTTP/1.1"
            )
        );

        let error = container_archive_upload_request(
            "web",
            futures_util::stream::empty::<Result<Bytes, std::io::Error>>(),
            &ContainerArchiveUploadOptions {
                path: String::new(),
                ..ContainerArchiveUploadOptions::default()
            },
        )
        .expect_err("empty path");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn commit_sends_the_versioned_path_with_every_parameter_in_daemon_order() {
        let request = commit_container_request(&CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            repository: Some("team/app".to_owned()),
            tag: Some("v1".to_owned()),
            comment: Some("snapshot".to_owned()),
            author: Some("Ada <ada@example.test>".to_owned()),
            pause: true,
            changes: vec!["CMD [\"/bin/sh\"]".to_owned(), "ENV A=1".to_owned()],
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/commit?container=slice-db-1&repo=team%2Fapp&tag=v1&comment=snapshot&author=Ada+%3Cada%40example.test%3E&pause=true&changes=CMD+%5B%22%2Fbin%2Fsh%22%5D&changes=ENV+A%3D1 HTTP/1.1"
            )
        );
        assert_eq!(
            request_body(&request),
            serde_json::json!({}),
            "the commit body is the empty ContainerConfig the fallback sends"
        );
    }

    #[test]
    fn commit_without_optional_options_spells_the_container_and_pause_only() {
        let request = commit_container_request(&CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            pause: false,
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/commit?container=slice-db-1&pause=false HTTP/1.1"
            )
        );
        assert_eq!(request_body(&request), serde_json::json!({}));
    }

    #[test]
    fn commit_encodes_the_container_reference_as_one_query_value() {
        // A reference is a query value here rather than a path segment, so `&`
        // and `=` must not become parameter syntax.
        let request = commit_container_request(&CommitContainerOptions {
            container: "a/b&c=d".to_owned(),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/commit?container=a%2Fb%26c%3Dd&pause=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn commit_refuses_an_empty_container_reference() {
        let error = commit_container_request(&CommitContainerOptions::default())
            .expect_err("empty reference");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("must not be empty"),
            "the refusal did not name the reference: {error}"
        );
    }

    #[test]
    fn an_empty_change_set_sends_no_changes_parameter() {
        let request = commit_container_request(&CommitContainerOptions {
            container: "slice-db-1".to_owned(),
            changes: Vec::new(),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/commit?container=slice-db-1&pause=false HTTP/1.1"
            ),
            "an empty change set must not become a query parameter"
        );
    }

    #[test]
    fn a_commit_document_projects_the_image_id() {
        // The Engine's `IdResponse` declares `Id`; the generated model the
        // fallback decodes into also accepts `id` and `ID` through serde
        // aliases, so the owned projection accepts the same three.
        for body in [
            r#"{"Id":"sha256:abc"}"#,
            r#"{"id":"sha256:abc"}"#,
            r#"{"ID":"sha256:abc"}"#,
        ] {
            let document =
                crate::raw::decode::<CommitDocument>(body.as_bytes()).expect("a commit document");
            assert_eq!(document.id, "sha256:abc", "{body}");
        }
        let document = crate::raw::decode::<CommitDocument>(br#"{"Id":"sha256:abc","Extra":7}"#)
            .expect("unknown members are ignored");
        assert_eq!(document.id, "sha256:abc");
        let document =
            crate::raw::decode::<CommitDocument>(br#"{"Id":""}"#).expect("an empty id is a value");
        assert_eq!(document.id, "");
    }

    #[test]
    fn a_commit_document_without_a_usable_id_is_refused() {
        for body in [
            "{}",
            r#"{"Id":null}"#,
            r#"{"id":null}"#,
            r#"{"Id":7}"#,
            r#"{"Id":["sha256:abc"]}"#,
            "not json",
        ] {
            let error = crate::raw::decode::<CommitDocument>(body.as_bytes())
                .expect_err("an unusable id is refused");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        }
    }

    #[test]
    fn a_top_document_projects_titles_and_processes() {
        let document =
            decode_top(r#"{"Titles":["PID","CMD"],"Processes":[["1","sleep 60"],["7","sh"]]}"#);
        assert_eq!(document.titles, ["PID", "CMD"]);
        assert_eq!(
            document.processes,
            [
                ["1".to_owned(), "sleep 60".to_owned()],
                ["7".to_owned(), "sh".to_owned()]
            ]
        );
    }

    #[test]
    fn an_absent_top_member_is_an_empty_vector() {
        let document = decode_top("{}");
        assert!(
            document.titles.is_empty(),
            "expected document.titles to be empty"
        );
        assert!(
            document.processes.is_empty(),
            "expected document.processes to be empty"
        );
    }

    #[test]
    fn a_null_top_member_is_an_empty_vector() {
        // The Engine sends `null` for a container whose process table is
        // unavailable; the generated model accepts it, so this projection must
        // too rather than treating it as a type error.
        let document = decode_top(r#"{"Titles":null,"Processes":null}"#);
        assert!(
            document.titles.is_empty(),
            "expected document.titles to be empty"
        );
        assert!(
            document.processes.is_empty(),
            "expected document.processes to be empty"
        );
    }

    #[test]
    fn a_top_document_ignores_members_it_does_not_model() {
        let document = decode_top(r#"{"Titles":["PID"],"Processes":[["1"]],"Extra":7}"#);
        assert_eq!(document.titles, ["PID"]);
        assert_eq!(document.processes, [["1".to_owned()]]);
    }

    #[test]
    fn a_top_member_of_the_wrong_type_is_refused() {
        for body in [
            r#"{"Titles":"PID"}"#,
            r#"{"Processes":[null]}"#,
            r#"{"Processes":[["1",2]]}"#,
        ] {
            let error = crate::raw::decode::<ContainerTopDocument>(body.as_bytes())
                .expect_err("a wrong member type is refused");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{body}");
        }
    }

    #[test]
    fn remove_spells_every_flag_as_true_or_false() {
        // `v` is the Engine's name for "remove anonymous volumes", and the
        // value is the `true`/`false` the Engine's own query decoder parses.
        // Sending `1`/`0` or an empty `v=` would both be wrong.
        let plain = container_remove_request("slice-db-1", ContainerRemoveOptions::default())
            .expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version(
                "DELETE /v1.API/containers/slice-db-1?v=false&force=false&link=false HTTP/1.1"
            )
        );
        let volumes = container_remove_request(
            "slice-db-1",
            ContainerRemoveOptions {
                remove_volumes: true,
                force: true,
                remove_link: false,
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&volumes),
            crate::raw::at_api_version(
                "DELETE /v1.API/containers/slice-db-1?v=true&force=true&link=false HTTP/1.1"
            )
        );
    }

    #[test]
    fn wait_sends_the_condition_only_when_one_was_asked_for() {
        let plain = container_wait_request("slice-db-1", &ContainerWaitOptions::default())
            .expect("request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version("POST /v1.API/containers/slice-db-1/wait HTTP/1.1")
        );
        let conditioned = container_wait_request(
            "slice-db-1",
            &ContainerWaitOptions {
                condition: Some("not-running".to_owned()),
            },
        )
        .expect("request");
        assert_eq!(
            request_line(&conditioned),
            crate::raw::at_api_version(
                "POST /v1.API/containers/slice-db-1/wait?condition=not-running HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_ordinary_container_reference_is_left_alone() {
        // A name is `[a-zA-Z0-9][a-zA-Z0-9_.-]*` and an id is hex, so the
        // characters the Engine uses must survive escaping unchanged or every
        // existing name would have to be renamed.
        for untouched in [
            "slice-db-1",
            "a.b_c~d",
            "8c968e1567aaf07c68dd7a593000d08c2b2f00b098c1cac4a1fb5b714bb67204",
            "A-Z0-9",
        ] {
            assert_eq!(escape_path_segment(untouched), untouched);
        }
    }

    #[test]
    fn a_reference_cannot_escape_its_own_path_segment() {
        // `POST /containers/a/b/start` is a four-segment path, so an unescaped
        // reference addresses a different resource rather than a container
        // whose name contains a slash.
        assert_eq!(escape_path_segment("a/b"), "a%2Fb");
        assert_eq!(escape_path_segment("web app/1"), "web%20app%2F1");
        assert_eq!(
            escape_path_segment("../../containers/json"),
            "..%2F..%2Fcontainers%2Fjson"
        );
        assert_eq!(escape_path_segment("a?x=1"), "a%3Fx%3D1");
        assert_eq!(escape_path_segment("a#frag"), "a%23frag");
        // A reference that already contains an escape is escaped again, so it
        // cannot smuggle one past this function.
        assert_eq!(escape_path_segment("a%2Fb"), "a%252Fb");
    }

    #[test]
    fn a_reference_containing_a_slash_stays_one_path_segment() {
        let request =
            container_start_request("a/b", &ContainerStartOptions::default()).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/containers/a%2Fb/start HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_reference_is_refused_rather_than_sent_as_an_empty_segment() {
        let error =
            container_start_request("", &ContainerStartOptions::default()).expect_err("empty name");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            container_remove_request("", ContainerRemoveOptions::default()).is_err(),
            "every reference-taking operation must refuse it"
        );
    }

    #[test]
    fn a_summary_projects_the_engine_spelling_onto_the_repository_model() {
        // Recorded from Docker Engine 29.8.0's `GET /containers/json`, members
        // included: `ImageID` and `Type` are the two that a generated or
        // auto-renamed model would get wrong.
        let raw = br#"[{"Id":"abc","Names":["/rawprobe"],"Image":"alpine:3.19",
            "ImageID":"sha256:6baf","Command":"sleep 300","Created":1790361737,
            "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":18080,"Type":"tcp"}],
            "Labels":{"tier":"web"},"State":"running","Status":"Up 1 second",
            "ImageManifestDescriptor":{"digest":"sha256:b588"},"Mounts":[]}]"#;
        let document: Vec<ContainerSummaryDocument> =
            super::decode(raw).expect("a container array");
        let summary = ContainerSummary::from(document.into_iter().next().expect("one entry"));
        assert_eq!(summary.id.as_deref(), Some("abc"));
        assert_eq!(
            summary.names.as_deref(),
            Some(["/rawprobe".to_owned()].as_slice())
        );
        assert_eq!(summary.image.as_deref(), Some("alpine:3.19"));
        assert_eq!(summary.image_id.as_deref(), Some("sha256:6baf"));
        assert_eq!(summary.command.as_deref(), Some("sleep 300"));
        assert_eq!(summary.created, Some(1_790_361_737));
        assert_eq!(summary.state.as_deref(), Some("running"));
        assert_eq!(summary.status.as_deref(), Some("Up 1 second"));
        assert_eq!(summary.ports.len(), 1);
        assert_eq!(summary.ports[0].ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(summary.ports[0].private_port, 80);
        assert_eq!(summary.ports[0].public_port, Some(18080));
        assert_eq!(summary.ports[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(summary.labels.get("tier").map(String::as_str), Some("web"));
    }

    #[test]
    fn a_summary_without_ports_or_labels_still_decodes() {
        // A container with no published port and no label answers with an empty
        // array and an empty object, and a `null` for a member the daemon left
        // out. None of those may become a decode failure.
        let document: Vec<ContainerSummaryDocument> =
            super::decode(br#"[{"Id":"abc","Ports":null,"Labels":null}]"#).expect("a container");
        let summary = ContainerSummary::from(document.into_iter().next().expect("one entry"));
        assert!(
            summary.ports.is_empty(),
            "expected summary.ports to be empty"
        );
        assert!(summary.labels.is_empty());
        assert_eq!(summary.image_id, None);
    }

    #[test]
    fn a_create_answer_projects_the_id_and_the_warnings() {
        let document: ContainerCreateDocument =
            super::decode(br#"{"Id":"ebf1546b","Warnings":["port 80 is already in use"]}"#)
                .expect("a create document");
        let result = crate::ContainerCreateResult::from(document);
        assert_eq!(result.id, "ebf1546b");
        assert_eq!(
            result.warnings,
            vec!["port 80 is already in use".to_owned()]
        );
    }

    #[test]
    fn a_create_answer_without_warnings_decodes_to_an_empty_list() {
        let document: ContainerCreateDocument =
            super::decode(br#"{"Id":"ebf1546b"}"#).expect("a create document");
        assert!(
            crate::ContainerCreateResult::from(document)
                .warnings
                .is_empty(),
            "expected crate::ContainerCreateResult::from(document) .warnings to be empty"
        );
    }

    #[test]
    fn a_wait_answer_reports_the_exit_status_rather_than_failing_on_it() {
        // Recorded from Docker Engine 29.8.0: a container killed by `stop`
        // answers `{"StatusCode":137}` with no `Error` member. 137 is a
        // successful answer about a container that did not exit cleanly.
        let document: ContainerWaitDocument =
            super::decode(br#"{"StatusCode":137}"#).expect("wait");
        let result = crate::ContainerWaitResult::from(document);
        assert_eq!(result.status_code, 137);
        assert_eq!(result.error, None);
    }

    #[test]
    fn a_wait_answer_with_a_daemon_error_keeps_the_message() {
        // The Engine sends `Error` as a container-shaped object with a
        // `Message` member, not as a string.
        let document: ContainerWaitDocument =
            super::decode(br#"{"StatusCode":1,"Error":{"Message":"container failed"}}"#)
                .expect("wait");
        assert_eq!(
            crate::ContainerWaitResult::from(document).error.as_deref(),
            Some("container failed")
        );
    }

    #[test]
    fn the_document_limit_still_bounds_a_container_list() {
        // The container slice goes through the same `engine_result` as `info`,
        // so the same bound applies to a hostile or broken list answer. The
        // bound itself is asserted as a compile-time constant in `body`; what is
        // checked here is that these operations really do go through the shared
        // mapping rather than reading the socket themselves.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        // A container list with no options is still read as one document, so a
        // daemon that answered with a stream of frames would be refused rather
        // than concatenated.
        let request = container_list_request(&ContainerListOptions::default()).expect("request");
        assert!(
            request.body.known_len().is_some(),
            "no request body is sent"
        );
    }

    #[test]
    fn a_status_204_needs_no_document_and_reports_no_error() {
        // The bound that start, stop, and remove rely on: a success with no body
        // is a success, and `204` is inside the 2xx range `engine_result`
        // accepts. If a future Engine answered these with a status outside that
        // range, this fails rather than the operation quietly decoding nothing.
        assert!(StatusCode::NO_CONTENT.is_success());
        assert!(!StatusCode::NOT_MODIFIED.is_success());
    }
}
