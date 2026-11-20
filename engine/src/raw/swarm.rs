//! Swarm operations on the repository-owned Engine backend.
//!
//! The owned service writer retains placement and restart policy. The Engine
//! stores these inside `Spec.TaskTemplate`, while the repository model exposes
//! typed top-level fields. [`service_spec_body`] reconciles them into
//! `TaskTemplate` on the way out. An inspect of the daemon reports these values
//! inside `TaskTemplate` rather than in the typed top-level fields.
//!
//! [`service_create`] sends the repository-owned
//! [`ServiceSpec`](crate::ServiceSpec) through the same writer as
//! [`service_update`], with no generated struct in the path. Typed placement and
//! restart policy reach the daemon inside `TaskTemplate`; a top-level
//! `Placement` or `RestartPolicy` supplied through `additional` is refused
//! before dispatch, even with no typed competitor. A literal root member of
//! either name has no lossless path: `TaskTemplate` changes its location and
//! meaning, and this writer refuses the root spelling. Tests verify that the
//! owned body carries `Placement` and `RestartPolicy` inside `TaskTemplate`.
//!
//! # What is covered
//!
//! - The cluster: `swarm_init`, `swarm_join`, `swarm_leave`, `swarm_inspect`,
//!   `swarm_update`, `swarm_unlock`, `swarm_unlock_key`, `swarm_certificates`,
//!   and `swarm_join_token`.
//! - Services: `service_list`, `service_create`, `service_inspect`,
//!   `service_update`, `service_remove`, `service_logs`.
//! - Nodes: `node_list`, `node_inspect`, `node_update`, `node_remove`.
//! - Tasks: `task_list`, `task_inspect`, `task_logs`.
//! - Configs: `config_list`, `config_create`, `config_inspect`,
//!   `config_update`, `config_remove`.
//! - Secrets: `secret_list`, `secret_create`, `secret_inspect`,
//!   `secret_update`, `secret_remove`.
//!
//! The names are prefixed by resource because they share the `raw` namespace
//! with the container slice's `list`, `create`, and `remove`.
//!
//! # The cluster lifecycle has no generated fallback
//!
//! `swarm_init`, `swarm_join`, `swarm_update`, `swarm_certificates`, and
//! `swarm_unlock_key` are the operations the facade serves only through this
//! module. the former generated client 0.21.1 traces a buffered request body, so its generated
//! `init` and `join` would write the address document and the join token to a
//! TRACE log, and `update` would write the specification; its `process_request`
//! also treats `101` and `304` as success without exposing the status. The
//! certificate and unlock-key paths have no generated method at all, and the
//! old facade borrowed `ping` and rewrote its path, which returned the body as
//! text with no status check. None of those is a safe fallback, so an endpoint
//! the caller cannot describe as an owned target fails closed before dispatch.
//! The facade additionally fails closed before calling these functions, with a
//! fixed diagnostic; these functions themselves have no routing knowledge.
//!
//! All five withhold the daemon's or proxy's failure text and keep the HTTP
//! status. `swarm_join` and `swarm_init` carry credentials or internal topology
//! in the request; `swarm_update` carries the specification; the certificate
//! and unlock-key reads return credential material on success. The source chain
//! is replaced with fixed operation-specific text, and a transport deadline
//! marker is kept without claiming this operation itself timed out.
//!
//! # What is deliberately not covered
//!
//! - **Registry authentication for `POST /services/create`.** The Engine reads
//!   it from an `X-Registry-Auth` header. The repository's service-create input
//!   is a bare [`ServiceSpec`](crate::ServiceSpec) and carries no credential, so
//!   this module sends no such header rather than sending an empty one that
//!   would look like an attempt to pull with no credentials.
//! - **The v1.53 `SwarmInitRequest` members the option type does not name**:
//!   `Labels`, `AutoLockManagers`, `DefaultAddrPool`, and `SubnetSize`.
//!   [`SwarmInitOptions`](crate::SwarmInitOptions) has five members, and adding
//!   more would widen the public input shape beyond what the facade has ever
//!   accepted. They are stated here instead.
//! - **`GET /swarm/cert` on a current daemon.** The endpoint is absent from the
//!   Engine's API specification as of v1.35, and a v29.8 daemon answers
//!   `404 page not found` for it. [`swarm_certificates`] exists because the
//!   repository already exposes the material, not because the endpoint is
//!   dependable; a `404` is reported as the daemon's own rejection.
//! - **Key material generation.** `swarm_update` sends the three rotation flags
//!   the Engine declares. Nothing here mints a key.
//!
//! # Conflict safety is the daemon's, not this module's
//!
//! Every update carries the caller's `version` as the Engine declares it, and a
//! stale version stays the daemon's `409 Conflict`. Nothing here retries: a
//! second writer's changes are not overwritten by a retry that usually works.
//! The Engine declares the parameter as `int32` for a service and `int64` for
//! the others, and both conversions are done here rather than truncating one
//! into the other.
//!
//! # Case-folded keys are refused, not resolved
//!
//! The Engine's Go decoder matches JSON member names case-insensitively, and
//! its fold is Unicode-aware. A specification that names one member twice with
//! different case therefore has a meaning decided by the daemon, not by the
//! caller: `Placement` and `placement`, `Labels` and `labels`, or a key such as
//! `Label\u{017f}` that folds onto `Labels`. This writer refuses that class
//! before dispatch. Two keys on one modeled surface may not differ only by
//! ASCII case, and a non-ASCII key on such a surface is refused because this
//! crate has no dependency-free full fold table. The modeled surfaces are the
//! specification root, `TaskTemplate`, its `Placement` and `RestartPolicy`
//! objects, and the top-level objects of `Mode`, `EndpointSpec`, `Networks`,
//! `UpdateConfig`, and `RollbackConfig`. A service-defined map key — a label,
//! a sysctl — is not a modeled member and remains available through the typed
//! `labels` member or inside `task_template`; unknown ASCII members at those
//! levels are still passed through. The refusal is fixed text and names no key
//! or value. See [`ServiceSpec::additional`](crate::ServiceSpec::additional)
//! for the caller-facing statement.
//!
//! # A member a typed field cannot hold is retained, never dropped
//!
//! The repository models are caller-facing, so a few of them cannot express
//! every member the Engine sends. Two of those gaps are structural. The Engine's
//! `Placement.Preferences` is a list of objects —
//! `[{"Spread":{"SpreadDescriptor":"node.labels.zone"}}]` — and not the list of
//! strings a Compose `deploy:` block writes; and `Placement.Platforms` has no
//! counterpart at all. A silently dropped constraint is a *safety* difference,
//! not a formatting one, so this module uses one convention for it: **a member
//! of a typed sub-object that the type cannot express is retained in the
//! enclosing model's `additional` map under the key `"<SubObject>.<Member>"`.**
//!
//! The Engine spells no member with a dot in it, so such a key can never collide
//! with a real member, and it never duplicates a key the typed fields already
//! emit — which is what would happen if the whole sub-object were copied
//! alongside the typed field. [`service_spec_body`] reads those keys back out
//! and merges them into the `Placement` object it sends, so a specification that
//! came from an inspect re-sends what the daemon sent.
//!
//! A whole sub-object that has no typed field at all — a service's `Endpoint`, a
//! node's `Description`, a task's `Spec` — is retained verbatim under its own
//! Engine name, which covers its members with no special case. That is also why
//! a service's published ports survive intact: `ServicePort` has no field for
//! `PortConfig.Name`, but the `Endpoint` those ports came from is still there.
//!
//! # The wire models are private to this module
//!
//! The `*Document` types below are the only wire-shaped values here, for the
//! reason `raw::containers` gives: the public models are ordered for callers,
//! and a few of them differ from the Engine's spelling, so decoding an Engine
//! answer straight into one of them is what loses members. They are not the
//! dependency's generated models. Config and secret update bodies serialize
//! the owned specifications, retaining their unreserved additional members.
//!
//! Every option, result, and specification type is the existing repository-owned
//! model, reused as it is. This module adds no parallel Swarm model, so a caller
//! that moves between the two backends moves between the same types.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use base64::{
    Engine as _,
    engine::{GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use hyper::Method;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::Error;
use crate::raw::body::FrameStream;
use crate::raw::containers::{Query, with_query};
use crate::raw::image_transfer::{RegistryAuth, with_registry_auth};
use crate::raw::logs::{LogDecoder, LogFrame};
use crate::raw::transport::{
    RawEngine, RawRequest, decode, engine_result, json_body, json_content_type,
};
use crate::swarm::{
    ConfigCreateOptions, ConfigUpdateOptions, NodeManagerStatus, NodeRemoveOptions, NodeSpec,
    NodeUpdateOptions, SecretCreateOptions, SecretUpdateOptions, ServiceCreateResult,
    ServicePlacement, ServicePort, ServiceRestartPolicy, ServiceSpec, ServiceStatus,
    ServiceUpdateOptions, ServiceUpdateResult, SwarmCertificates, SwarmConfig, SwarmConfigSpec,
    SwarmInfo, SwarmInitOptions, SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions,
    SwarmListOptions, SwarmLogOptions, SwarmNode, SwarmSecret, SwarmSecretSpec, SwarmService,
    SwarmTask, SwarmTaskStatus, SwarmUnlockKey, SwarmUnlockOptions, SwarmUpdateOptions,
    SwarmVersion, WITHHELD_CERTIFICATES_MESSAGE, WITHHELD_INIT_MESSAGE, WITHHELD_JOIN_MESSAGE,
    WITHHELD_NODE_MUTATION_MESSAGE, WITHHELD_SERVICE_CREATE_MESSAGE,
    WITHHELD_SERVICE_UPDATE_MESSAGE, WITHHELD_UNLOCK_KEY_MESSAGE, WITHHELD_UNLOCK_MESSAGE,
    WITHHELD_UPDATE_MESSAGE, checked_i32, checked_i64, refuse_unrepresentable_secret_update,
    reject_reserved_node_spec_members, reject_reserved_swarm_spec_members, validate_config_spec,
    withhold_secret_read_error,
};

/// Initializes a Swarm on this node and returns the manager node ID.
///
/// `POST /swarm/init` answers `200` with a JSON string, `"nodeid"`, rather than
/// with an object, so the answer is decoded as the string it is and returned as
/// one.
///
/// The request carries manager addresses, which are internal topology. A direct
/// daemon or an unauthenticated forward proxy controls a non-success response,
/// so this operation does not preserve that response's text: the status
/// survives, and the message and source are replaced with fixed text. The
/// response body is dropped without being read. A transport failure is replaced
/// the same way, preserving only its kind and a transport-deadline marker.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — a node that is already in a Swarm answers `500` or `503` here — or
/// when the answer is not a node ID. A rejection keeps its status; its message
/// is withheld. A malformed success document is refused with content-free text.
pub async fn swarm_init(engine: &RawEngine, options: &SwarmInitOptions) -> Result<String, Error> {
    document_withheld(
        engine,
        init_request(options),
        WITHHELD_INIT_MESSAGE,
        "a transport deadline was observed; the Swarm init outcome is unknown; reconcile before retrying",
    )
    .await
}

/// Builds the `POST /swarm/init` request.
fn init_request(options: &SwarmInitOptions) -> RawRequest {
    let body = json_body(&InitDocument {
        listen_address: options.listen_address.as_deref(),
        advertise_address: options.advertise_address.as_deref(),
        data_path_address: options.data_path_address.as_deref(),
        data_path_port: options.data_path_port,
        force_new_cluster: options.force_new_cluster,
    })
    .expect("a document of owned strings always encodes");
    json_content_type(RawRequest::new(Method::POST, "/swarm/init")).with_body(body)
}

/// The `POST /swarm/init` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct InitDocument<'a> {
    #[serde(rename = "ListenAddr", skip_serializing_if = "Option::is_none")]
    listen_address: Option<&'a str>,
    #[serde(rename = "AdvertiseAddr", skip_serializing_if = "Option::is_none")]
    advertise_address: Option<&'a str>,
    #[serde(rename = "DataPathAddr", skip_serializing_if = "Option::is_none")]
    data_path_address: Option<&'a str>,
    #[serde(rename = "DataPathPort", skip_serializing_if = "Option::is_none")]
    data_path_port: Option<u32>,
    #[serde(rename = "ForceNewCluster", skip_serializing_if = "Option::is_none")]
    force_new_cluster: Option<bool>,
}

/// Joins this node to an existing Swarm.
///
/// The request body carries the join token, which is a credential. A direct
/// daemon or an unauthenticated forward proxy controls a non-success response,
/// so this operation does not preserve that response's text: the status
/// survives, and the message and source are replaced with fixed text. The
/// response body is dropped without being read. A transport failure is replaced
/// the same way, preserving only its kind and a transport-deadline marker. A
/// peer that encodes or truncates the token is not a case an exact-match
/// substitution would catch, so withholding is unconditional.
///
/// # Errors
///
/// Returns an error when no manager address was given — a join with nothing to
/// reach is refused here rather than sent for the daemon to reject — when the
/// daemon cannot be reached, or when it rejects the request. The rejection
/// keeps its status; its message is withheld.
pub async fn swarm_join(engine: &RawEngine, options: &SwarmJoinOptions) -> Result<(), Error> {
    completed_withheld(
        engine,
        join_request(options)?,
        WITHHELD_JOIN_MESSAGE,
        "a transport deadline was observed; the Swarm join outcome is unknown; reconcile before retrying",
    )
    .await
}

/// Builds the `POST /swarm/join` request.
///
/// # Errors
///
/// Returns an error when the caller named no manager address.
fn join_request(options: &SwarmJoinOptions) -> Result<RawRequest, Error> {
    if options.remote_addresses.is_empty() {
        return Err(Error::invalid_input(
            "joining a Swarm needs at least one manager address to reach",
        ));
    }
    let body = json_body(&JoinDocument {
        listen_address: options.listen_address.as_deref(),
        advertise_address: options.advertise_address.as_deref(),
        data_path_address: options.data_path_address.as_deref(),
        remote_addresses: &options.remote_addresses,
        token: &options.token,
    })?;
    Ok(json_content_type(RawRequest::new(Method::POST, "/swarm/join")).with_body(body))
}

/// The `POST /swarm/join` body, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct JoinDocument<'a> {
    #[serde(rename = "ListenAddr", skip_serializing_if = "Option::is_none")]
    listen_address: Option<&'a str>,
    #[serde(rename = "AdvertiseAddr", skip_serializing_if = "Option::is_none")]
    advertise_address: Option<&'a str>,
    #[serde(rename = "DataPathAddr", skip_serializing_if = "Option::is_none")]
    data_path_address: Option<&'a str>,
    // Sent always, and never as an empty array: there is no manager to ask
    // otherwise, and an empty `RemoteAddrs` is a join request that cannot
    // succeed. `join_request` refuses the input before this is reached.
    #[serde(rename = "RemoteAddrs")]
    remote_addresses: &'a [String],
    #[serde(rename = "JoinToken")]
    token: &'a str,
}

/// Leaves the Swarm this node belongs to.
///
/// `force` is always spelled, so a recorded request says whether leaving a
/// manager was part of it. The dependency sends the parameter only when it is
/// true, which makes a recorded `POST /swarm/leave` ambiguous between "not
/// forced" and "not sent".
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request.
pub async fn swarm_leave(engine: &RawEngine, options: &SwarmLeaveOptions) -> Result<(), Error> {
    completed(engine, leave_request(*options)).await
}

/// Builds the `POST /swarm/leave` request.
///
/// The options are taken by value for the reason [`node_remove_request`] gives.
fn leave_request(options: SwarmLeaveOptions) -> RawRequest {
    let mut query = Query::default();
    query.flag("force", options.force);
    with_query(
        RawRequest::new(Method::POST, "/swarm/leave"),
        query.finish(),
    )
}

/// Reads the active Swarm.
///
/// `GET /swarm` is also the only endpoint that reports join tokens, so this is
/// the read behind [`swarm_join_token`] and behind
/// [`SwarmInfo::trust_root`](crate::SwarmInfo::trust_root).
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a Swarm document.
pub async fn swarm_inspect(engine: &RawEngine) -> Result<SwarmInfo, Error> {
    let response = engine.send(swarm_inspect_request()).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Builds the `GET /swarm` request.
fn swarm_inspect_request() -> RawRequest {
    RawRequest::new(Method::GET, "/swarm")
}

/// Updates the Swarm at an explicit expected version.
///
/// The three rotation flags are always spelled, for the reason given on
/// [`swarm_leave`], and `version` is converted to the `int64` the Engine
/// declares for this endpoint.
///
/// [`SwarmSpec::additional`](crate::SwarmSpec) is refused when it carries
/// `Name` or `Labels` under any ASCII case spelling, or any non-ASCII key: the
/// flattened map would otherwise emit a duplicate JSON key beside the typed
/// field, and which value the daemon keeps would depend on its decoder. The
/// refusal is [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before
/// dispatch and names no caller value.
///
/// The request carries the Swarm specification, including free-form
/// `additional` values a caller chose. A direct daemon or an unauthenticated
/// forward proxy controls a non-success response, so this operation does not
/// preserve that response's text: the status survives, and the message and
/// source are replaced with fixed text. A transport failure is replaced the
/// same way, preserving only its kind and a transport-deadline marker.
///
/// # Errors
///
/// Returns an error when the version does not fit the Engine's `int64`, when the
/// specification carries a reserved `additional` key, when it cannot be
/// encoded, or when the daemon rejects the request. A stale version stays a
/// `409 Conflict`, with its status preserved and its peer text withheld.
pub async fn swarm_update(engine: &RawEngine, options: &SwarmUpdateOptions) -> Result<(), Error> {
    completed_withheld(
        engine,
        update_request(options)?,
        WITHHELD_UPDATE_MESSAGE,
        "a transport deadline was observed; the Swarm update outcome is unknown; reconcile before retrying",
    )
    .await
}

/// Builds the `POST /swarm/update` request.
///
/// # Errors
///
/// Returns an error when the version does not fit the Engine's `int64` or the
/// specification carries a reserved `additional` key.
fn update_request(options: &SwarmUpdateOptions) -> Result<RawRequest, Error> {
    reject_reserved_swarm_spec_members(&options.spec)?;
    let mut query = Query::default();
    query.value("version", &checked_i64(options.version)?.to_string());
    query.flag("rotateWorkerToken", options.rotate_worker_token);
    query.flag("rotateManagerToken", options.rotate_manager_token);
    query.flag("rotateManagerUnlockKey", options.rotate_manager_unlock_key);
    let request = json_content_type(RawRequest::new(Method::POST, "/swarm/update"))
        .with_body(json_body(&options.spec)?);
    Ok(with_query(request, query.finish()))
}

/// Unlocks a Swarm manager whose key was rotated or lost.
///
/// the former generated client 0.21.1 has no method for this endpoint, so the facade sends it only
/// through the owned transport. It has no generated fallback: the facade fails
/// closed before calling this function on an endpoint the owned transport
/// cannot reach, and the managed SSH gate is handled by the facade before
/// dispatch. The owned transport names the path it means and prefixes the
/// configured API version.
///
/// The request body is the manager unlock key. A direct daemon or an
/// unauthenticated forward proxy controls a non-success response, so this
/// operation does not preserve that response's text: the status survives, and
/// the message and source are replaced with fixed text. The response body is
/// dropped without being read. A transport failure is replaced the same way,
/// preserving its kind and safe typed deadline/host-key markers. A peer that
/// encodes or truncates the key is not a case an exact-match substitution would
/// catch, so withholding is unconditional.
///
/// # Errors
///
/// Returns an error when the key cannot be encoded or when the daemon rejects
/// the request, which is what a wrong key answers. The rejection keeps its
/// status; its message is withheld.
pub async fn swarm_unlock(engine: &RawEngine, options: &SwarmUnlockOptions) -> Result<(), Error> {
    let response = engine
        .send(swarm_unlock_request(options))
        .await
        .map_err(|error| {
            withheld_response_error(
                &error,
                WITHHELD_UNLOCK_MESSAGE,
                "a transport deadline was observed; the Swarm unlock outcome is unknown; reconcile before retrying",
            )
        })?;
    let status = response.status;
    if status.is_success() {
        // `POST /swarm/unlock` has no success document. Dropping the response
        // closes the connection; reading it would give a peer text a place to
        // be collected even though nothing uses it.
        drop(response);
        return Ok(());
    }
    // The daemon or proxy controls this body. It is not read, and its message
    // is not preserved.
    drop(response);
    Err(Error::engine_api_withheld(status, WITHHELD_UNLOCK_MESSAGE))
}

/// Builds the `POST /swarm/unlock` request.
fn swarm_unlock_request(options: &SwarmUnlockOptions) -> RawRequest {
    let body = json_body(&UnlockDocument {
        unlock_key: &options.key,
    })
    .expect("a document of one string always encodes");
    json_content_type(RawRequest::new(Method::POST, "/swarm/unlock")).with_body(body)
}

/// The `POST /swarm/unlock` body, in the Engine's spelling.
///
/// Not `Debug`: the only member is the manager unlock key, and a derived
/// implementation would print a credential that nothing in this crate needs to
/// render. The request body's own `Debug` reports its length instead of its
/// bytes, so a request carrying this document is safe to print.
#[derive(Serialize)]
struct UnlockDocument<'a> {
    #[serde(rename = "UnlockKey")]
    unlock_key: &'a str,
}

/// Reads the manager unlock key of a Swarm with autolock enabled.
///
/// The key is a credential: it is returned to the caller, redacted from `Debug`,
/// and zeroized when dropped. Nothing here logs or formats it.
///
/// The successful answer carries the key, so a non-success body controlled by
/// the daemon or a proxy is not read and its text is not promoted into an error.
/// The status is preserved and the message and source are replaced with fixed
/// text. A transport failure is replaced the same way, preserving only its kind
/// and a transport-deadline marker.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not an unlock-key document. A rejection keeps
/// its status; its message is withheld. A malformed success document is refused
/// with content-free text.
pub async fn swarm_unlock_key(engine: &RawEngine) -> Result<SwarmUnlockKey, Error> {
    document_withheld(
        engine,
        RawRequest::new(Method::GET, "/swarm/unlockkey"),
        WITHHELD_UNLOCK_KEY_MESSAGE,
        "a transport deadline was observed; the Swarm unlock-key read did not complete",
    )
    .await
}

/// Reads the Swarm root CA and the certificates issued for this node.
///
/// See the module documentation: the Engine stopped serving this path, so a
/// current daemon answers `404` and this reports that rejection rather than
/// pretending the material is missing for some other reason.
///
/// The successful answer carries the node's private key, so a non-success body
/// controlled by the daemon or a proxy is not read and its text is not promoted
/// into an error. The status is preserved and the message and source are
/// replaced with fixed text. A transport failure is replaced the same way,
/// preserving only its kind and a transport-deadline marker.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a certificates document. A rejection keeps
/// its status; its message is withheld. A malformed success document is refused
/// with content-free text.
pub async fn swarm_certificates(engine: &RawEngine) -> Result<SwarmCertificates, Error> {
    document_withheld(
        engine,
        RawRequest::new(Method::GET, "/swarm/cert"),
        WITHHELD_CERTIFICATES_MESSAGE,
        "a transport deadline was observed; the Swarm certificate read did not complete",
    )
    .await
}

/// Reads the join token for one role.
///
/// `None` means the daemon reported no token for that role, which is what a
/// worker reports for the manager token. The token is a credential and is
/// returned to the caller and written nowhere else.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not a Swarm document.
pub async fn swarm_join_token(
    engine: &RawEngine,
    role: SwarmJoinTokenRole,
) -> Result<Option<String>, Error> {
    let swarm = swarm_inspect(engine).await?;
    Ok(swarm
        .join_tokens
        .as_ref()
        .and_then(|tokens| tokens.get(role.join_token_member()))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned))
}

/// Lists Swarm services.
///
/// `filters` is sent only when it is non-empty: an empty filter object is a
/// filter that matches the daemon's own no-filter case and would only make a
/// recorded request noisier.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a service
/// array.
pub async fn service_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmService>, Error> {
    let entries = list::<ServiceDocument>(engine, service_list_request(options)?).await?;
    entries.into_iter().map(SwarmService::try_from).collect()
}

/// Lists services for the facade: the same request as [`service_list`] plus
/// `status=true`, and the projection [`service_inspect_for_facade`] uses.
///
/// Two things differ from the public raw operation, and neither may change
/// there:
///
/// - **`status=true` is sent after the filters.** Without it the daemon answers
///   with every service's `ServiceStatus` member set to `null`, so a caller
///   asking for running and desired task counts gets nothing. The raw list keeps
///   its original request because its contract is the request it always sent;
///   the query is `filters=<json>&status=true`, in that order.
/// - **The facade projection accepts nullable documents.** [`SwarmService::try_from`] is the raw contract and stays strict:
///   a present port list or status that cannot decode is an error. The facade
///   uses [`ServiceDocument::into_facade`], which reports no projection for an
///   absent, `null`, or partial member, keeps the endpoint in `additional`, and
///   refuses a member of the wrong JSON type.
///
/// The facade clears [`ServicePort::published_ip`](crate::ServicePort) after
/// this returns.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a service array
/// or carries a projection input of the wrong type.
pub(crate) async fn service_list_for_facade(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmService>, Error> {
    let entries =
        list::<ServiceDocument>(engine, service_list_for_facade_request(options)?).await?;
    entries
        .into_iter()
        .map(ServiceDocument::into_facade)
        .collect()
}

/// The fixed, content-free diagnostic the facade returns for an ambiguous node
/// document. No member value or daemon text is included.
const NODE_ENGINE_VERSION_COLLISION_MESSAGE: &str = "the Engine node document contains a top-level EngineVersion member that the repository view cannot represent unambiguously";

/// Lists Swarm nodes.
///
/// A repeated key at the node top level or in any object under `Spec`
/// is refused before projection, because `serde_json` would otherwise keep the
/// last value and a read-modify-write would send a value the daemon did not
/// send. This is a deliberate raw compatibility change from the last-value
/// collapse.
/// Validation checks at most 65,536 object members across the entire response
/// (not per node); exceeding that limit returns a fixed
/// [`ErrorKind::Serialization`](crate::ErrorKind::Serialization).
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, when the answer is not a node array, or
/// when a node repeats one of those keys. The duplicate refusal is a fixed
/// [`ErrorKind::Serialization`](crate::ErrorKind::Serialization) error that
/// names no key or value.
pub async fn node_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmNode>, Error> {
    let entries = node_documents::<Vec<NodeDocument>>(engine, node_list_request(options)?).await?;
    entries.into_iter().map(SwarmNode::try_from).collect()
}

/// Lists nodes for the facade, refusing an actual top-level `EngineVersion`.
///
/// The raw public operation keeps its original collision behavior. The facade
/// must not return a value whose typed view and flattened map both claim the
/// same JSON key, so it checks the decoded documents before projecting any of
/// them. One colliding node refuses the whole list rather than returning a
/// partial answer that silently omits or rewrites a node.
///
/// # Errors
///
/// Returns the same errors as [`node_list`], plus a fixed
/// [`ErrorKind::Serialization`](crate::ErrorKind::Serialization) error when any
/// decoded node carries a top-level `EngineVersion` member of any JSON type.
pub(crate) async fn node_list_for_facade(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmNode>, Error> {
    let entries = node_documents::<Vec<NodeDocument>>(engine, node_list_request(options)?).await?;
    if entries
        .iter()
        .any(|entry| entry.additional.contains_key("EngineVersion"))
    {
        return Err(Error::serialization_withheld(
            NODE_ENGINE_VERSION_COLLISION_MESSAGE,
        ));
    }
    entries.into_iter().map(SwarmNode::try_from).collect()
}

/// Lists Swarm tasks.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a task array.
pub async fn task_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmTask>, Error> {
    let entries = list::<TaskDocument>(engine, task_list_request(options)?).await?;
    entries.into_iter().map(SwarmTask::try_from).collect()
}

/// Lists Swarm configs.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request, or when the answer is not a config array.
pub async fn config_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmConfig>, Error> {
    let entries = list::<ConfigDocument>(engine, config_list_request(options)?).await?;
    entries.into_iter().map(SwarmConfig::try_from).collect()
}

/// Lists Swarm secrets.
///
/// A list answer does not include secret bytes. If a peer sends a `Spec.Data`
/// member anyway, it is retained at the `Spec` object level in
/// [`SwarmSecretSpec::additional`] and withheld from [`std::fmt::Debug`], exactly
/// as [`secret_inspect`] does. Retention is object-level, not a general lossless
/// claim: a typed sub-object such as `Version` has no catch-all, and duplicate
/// keys cannot both be represented.
///
/// A non-success Engine answer preserves its status in [`crate::Error::api_error`]
/// but withholds the response text with a fixed diagnostic, for direct and
/// proxied routes alike. This is a behavior change for a raw caller: the
/// previous raw operation returned the peer's message and source. A transport or
/// cancellation failure is not an API failure and keeps its kind and text.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded, when the daemon cannot
/// be reached or rejects the request (status preserved, text withheld), or when
/// the answer is not a secret array.
pub async fn secret_list(
    engine: &RawEngine,
    options: &SwarmListOptions,
) -> Result<Vec<SwarmSecret>, Error> {
    let response = engine.send(secret_list_request(options)?).await?;
    let document = engine_result(response)
        .await
        .map_err(withhold_secret_read_error)?;
    let entries = decode::<Vec<SecretDocument>>(&document)?;
    entries.into_iter().map(SwarmSecret::try_from).collect()
}

/// Sends a list request and decodes the one array it answers with.
///
/// Every Swarm list endpoint answers `[{…},{…}]` and nothing else, so one
/// bounded document read per resource is the whole shape of it.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request, or when the answer is not an array.
async fn list<D>(engine: &RawEngine, request: RawRequest) -> Result<Vec<D>, Error>
where
    D: for<'de> Deserialize<'de>,
{
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    decode(&document)
}

/// Fixed text used when a node document repeats a key.
///
/// A repeated top-level key or key in the retained `Spec` subtree is collapsed
/// by `serde_json` before the facade sees it. An inspect followed by an update
/// could then write a different value than the daemon sent. The message names no
/// key or value.
pub(crate) const NODE_DUPLICATE_KEY_MESSAGE: &str = "the Engine node document repeats a JSON key the repository view cannot represent unambiguously";

/// Fixed internal serde error text; classification uses `NodeValidation`, not
/// this text or a parser-provided diagnostic.
const DUPLICATE_NODE_KEY_MARKER: &str = "duplicate node document key";

/// Which part of a node document a key set belongs to.
#[derive(Clone, Copy)]
enum NodeKeyLevel {
    Document,
    Retained,
}

/// Maximum number of checked keys across the complete response.
const NODE_KEY_LIMIT: usize = 65_536;
const NODE_KEY_LIMIT_MARKER: &str = "node document key limit";
#[derive(Default)]
struct NodeValidation {
    keys: usize,
    duplicate: bool,
    limit: bool,
}
struct NodeKeys<'a>(NodeKeyLevel, &'a mut NodeValidation);

impl<'de> DeserializeSeed<'de> for NodeKeys<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NodeKeysVisitor(self.0, self.1))
    }
}

struct NodeKeysVisitor<'a>(NodeKeyLevel, &'a mut NodeValidation);

impl<'de> Visitor<'de> for NodeKeysVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a node document or node document list")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.1.keys += 1;
            if self.1.keys > NODE_KEY_LIMIT {
                self.1.limit = true;
                return Err(de::Error::custom(NODE_KEY_LIMIT_MARKER));
            }
            if !keys.insert(key.clone()) {
                self.1.duplicate = true;
                return Err(de::Error::custom(DUPLICATE_NODE_KEY_MARKER));
            }
            match (self.0, key.as_str()) {
                (NodeKeyLevel::Document, "Spec") | (NodeKeyLevel::Retained, _) => {
                    map.next_value_seed(NodeKeys(NodeKeyLevel::Retained, self.1))?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(NodeKeys(self.0, self.1))?.is_some() {}
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
}

/// Refuses a node document with a repeated key before serde can collapse it.
///
/// Checks top-level keys and every object retained below `Spec`, including in
/// arrays. The bounded response and serde's nesting limit bound input depth and
/// bytes; `NODE_KEY_LIMIT` additionally bounds key-set allocations. Invalid or
/// excessively nested JSON fails closed with a fixed diagnostic.
fn validate_node_document_keys(raw: &[u8]) -> Result<(), Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let mut state = NodeValidation::default();
    let result = NodeKeys(NodeKeyLevel::Document, &mut state).deserialize(&mut deserializer);
    if state.duplicate {
        Err(Error::serialization_withheld(NODE_DUPLICATE_KEY_MESSAGE))
    } else if state.limit {
        Err(Error::serialization_withheld(
            "the Engine node document exceeds JSON validation limits",
        ))
    } else if result.is_err() {
        Err(Error::invalid_input(
            "failed to decode the Engine node document: malformed JSON or nesting limit exceeded",
        ))
    } else {
        Ok(())
    }
}

/// Sends a node request and decodes it only after duplicate keys are refused.
///
/// `D` is either one [`NodeDocument`] or a `Vec<NodeDocument>`; the validator
/// accepts both a JSON object and a JSON array.
async fn node_documents<D>(engine: &RawEngine, request: RawRequest) -> Result<D, Error>
where
    D: for<'de> Deserialize<'de>,
{
    let response = engine.send(request).await?;
    let document = engine_result(response).await?;
    validate_node_document_keys(&document)?;
    decode(&document)
}

/// Builds the `GET /{resource}` list request every list endpoint shares.
///
/// The resource name is a literal at each of the five call sites, never anything
/// a caller supplies, so it cannot become a path the Engine does not serve.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn list_request(resource: &str, options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request_with_status(resource, options, false)
}

/// Builds a list request, optionally asking the daemon for task counts.
///
/// `status=true` follows the filters when both are present, which is the query
/// the facade has always sent for services. The order is not incidental: the
/// facade's generated path built it as `filters` then `status`, and a recorded
/// request must not change just because the transport did. The public
/// [`service_list`] request never sets it, so the raw contract is unchanged.
///
/// # Errors
///
/// Returns an error when the filters cannot be encoded.
fn list_request_with_status(
    resource: &str,
    options: &SwarmListOptions,
    include_status: bool,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    if !options.filters.is_empty() {
        query.value("filters", &encode_filters(&options.filters)?);
    }
    if include_status {
        query.flag("status", true);
    }
    Ok(with_query(
        RawRequest::new(Method::GET, format!("/{resource}")),
        query.finish(),
    ))
}

/// Builds the `GET /services` list request.
fn service_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("services", options)
}

/// Builds the facade's `GET /services?filters=…&status=true` request.
fn service_list_for_facade_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request_with_status("services", options, true)
}

/// Builds the `GET /nodes` list request.
fn node_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("nodes", options)
}

/// Builds the `GET /tasks` list request.
fn task_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("tasks", options)
}

/// Builds the `GET /configs` list request.
fn config_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("configs", options)
}

/// Builds the `GET /secrets` list request.
fn secret_list_request(options: &SwarmListOptions) -> Result<RawRequest, Error> {
    list_request("secrets", options)
}

/// Encodes an Engine filter map as the JSON a `filters` value carries.
///
/// The repository map is a `BTreeMap`, so the JSON is in key order and the
/// recorded request is reproducible. The dependency converts the same map into a
/// `HashMap` before serializing it, so the key order of its `filters` value
/// varies between runs of the same command.
fn encode_filters(filters: &BTreeMap<String, Vec<String>>) -> Result<String, Error> {
    serde_json::to_string(filters).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine swarm filters: {error}"
        ))
    })
}

/// Decodes one member of an Engine answer into a repository-owned model.
///
/// A sub-object that is projected out of a larger document — the published ports
/// out of a service's `Endpoint` — is decoded on its own, and the diagnostic is
/// the one [`decode`](crate::raw::decode) gives, naming the member rather than
/// the whole document, because that is the part that failed.
///
/// # Errors
///
/// Returns an error when the member is not the shape the Engine declares. It is
/// reported rather than dropped: a service whose port list did not decode is not
/// a service with no ports.
fn decode_value<T>(value: &serde_json::Value) -> Result<T, Error>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value.clone()).map_err(|error| {
        Error::invalid_input(format!(
            "failed to decode the Engine response member: {}",
            super::transport::serde_error_summary(&error)
        ))
    })
}

/// Creates a Swarm service and returns its ID with any daemon warnings.
///
/// The body is the repository-owned [`ServiceSpec`] itself, with no generated
/// struct in the path. Typed `Placement` and `RestartPolicy` are merged into
/// `TaskTemplate`; a top-level `additional["Placement"]` or
/// `additional["RestartPolicy"]` is refused before dispatch even when no typed
/// competitor is present. A literal root member of either name has no lossless
/// path: `TaskTemplate` changes its location and meaning, and this writer
/// refuses the root spelling. See the module documentation for the measured
/// reason the dependency cannot do this.
///
/// This form sends no `X-Registry-Auth` header.
/// [`service_create_with_registry_auth`] is the form that carries a credential,
/// and it has the same request otherwise.
///
/// # Failure text is withheld
///
/// A create body can carry `ContainerSpec.Env` and `ContainerSpec.Secrets`, so
/// every failure is content-free: the kind is preserved, a daemon or proxy
/// status is preserved when observed, and the message is fixed withholding
/// text. The response body is not read on a rejection. A malformed success
/// document is a fixed decode error that quotes no value.
///
/// # Errors
///
/// Returns an error when a placement preference is not a spelling the Engine
/// accepts, when the specification cannot be encoded, when competing placement
/// or restart-policy representations are supplied, when a top-level
/// `Placement` or `RestartPolicy` additional entry is supplied, when a task
/// template is not an object, or when the daemon rejects the request — an
/// invalid specification arrives as a `400` with its text withheld.
pub async fn service_create(
    engine: &RawEngine,
    spec: &ServiceSpec,
) -> Result<ServiceCreateResult, Error> {
    service_create_with_registry_auth(engine, spec, RegistryAuth::none()).await
}

/// Creates a Swarm service, carrying one registry credential.
///
/// The credential becomes the Engine's `X-Registry-Auth` header, URL-safe base64
/// over its `AuthConfig` object. [`RegistryAuth::none`] sends no header at all,
/// which is the honest spelling of "no credential was sent".
///
/// The credential is a password and the body can carry service environment and
/// service secrets. Every failure is therefore content-free in the same way as
/// [`service_create`]: the kind and an observed status survive, the peer's text
/// and source chain do not. Safe typed deadline and managed host-key markers
/// survive. A daemon rejection is not retried.
///
/// # Errors
///
/// Returns the errors [`service_create`] documents, plus a credential that does
/// not validate for `registry`, an invalid registry authority, or a credential
/// that cannot be encoded as an HTTP header.
pub async fn service_create_with_registry_auth(
    engine: &RawEngine,
    spec: &ServiceSpec,
    auth: RegistryAuth<'_>,
) -> Result<ServiceCreateResult, Error> {
    let request = service_create_request_with_registry_auth(spec, auth)?;
    // The body can hold service environment and service secrets, and the header
    // can hold a registry password. A peer-controlled failure message may echo
    // either, so no part of a transport failure's source chain is promoted. The
    // kind and safe typed markers are kept, never the original source chain.
    let response = engine
        .send(request)
        .await
        .map_err(|error| {
            withheld_response_error(
                &error,
                WITHHELD_SERVICE_CREATE_MESSAGE,
                "a transport deadline was observed; the service create outcome is unknown; reconcile before retrying",
            )
        })?;
    let status = response.status;
    if !status.is_success() {
        // Do not read the body at all. The status is the only observable fact
        // that survives withholding.
        drop(response);
        return Err(Error::engine_api_withheld(
            status,
            WITHHELD_SERVICE_CREATE_MESSAGE,
        ));
    }
    // A success body is a small `ID` and `Warnings` document. A body read
    // failure is a transport failure whose source is peer-controlled, so it is
    // withheld as well; a malformed JSON body is a content-free decode error.
    let document = response.document().await.map_err(|error| {
        Error::from(error).withhold_transport(
            WITHHELD_SERVICE_CREATE_MESSAGE,
            WITHHELD_SERVICE_CREATE_MESSAGE,
        )
    })?;
    decode::<ServiceCreateDocument>(&document).map(ServiceCreateResult::from)
}

/// Builds the `POST /services/create` request with no registry credential.
///
/// This is the builder the module's request-shape tests exercise; the public
/// entry points call [`service_create_request_with_registry_auth`] so the
/// credential form and the unauthenticated form share one request shape.
///
/// # Errors
///
/// Returns an error when the specification cannot be encoded or a placement
/// preference is not a spelling the Engine accepts.
#[cfg(test)]
fn service_create_request(spec: &ServiceSpec) -> Result<RawRequest, Error> {
    service_create_request_with_registry_auth(spec, RegistryAuth::none())
}

/// Builds the `POST /services/create` request.
///
/// # Errors
///
/// Returns an error when the specification cannot be encoded, when a placement
/// preference is not a spelling the Engine accepts, or when the credential
/// cannot be encoded as a header. The credential is a password, so an encoding
/// failure keeps its kind and replaces its chain with fixed text.
fn service_create_request_with_registry_auth(
    spec: &ServiceSpec,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    let body = json_body(&service_spec_body(spec)?)?;
    let request =
        json_content_type(RawRequest::new(Method::POST, "/services/create")).with_body(body);
    with_registry_auth(request, auth)
        .map_err(|error| Error::withheld(error.kind(), "failed to encode the registry auth header"))
}

/// A task template that is present must be an object.
const TASK_TEMPLATE_NOT_OBJECT: &str = "the service specification's TaskTemplate member is not a JSON object; supply an object before retrying";

/// A typed task template and an additional whole template compete.
const TASK_TEMPLATE_CONFLICT: &str = "the service specification carries both a typed task_template and an additional TaskTemplate; use one representation";

/// A dotted key cannot silently replace a member already supplied.
const DOTTED_MEMBER_CONFLICT: &str = "a dotted service specification key conflicts with a member already supplied in the same object; supply one representation";

/// A `Placement` supplied through `TaskTemplate` must be an object.
const PLACEMENT_NOT_OBJECT: &str =
    "the TaskTemplate Placement member is not a JSON object; supply an object before retrying";

/// A `RestartPolicy` supplied through `TaskTemplate` must be an object.
const RESTART_POLICY_NOT_OBJECT: &str =
    "the TaskTemplate RestartPolicy member is not a JSON object; supply an object before retrying";

/// A dotted member whose parent is not an object cannot be merged.
const DOTTED_PARENT_NOT_OBJECT: &str = "a dotted service specification member conflicts with a non-object parent; replace the parent with an object before retrying";

/// A top-level `Placement` entry or a second spelling of placement is a
/// refusal, not a choice. The fixed message is shared by both cases.
const CONFLICTING_PLACEMENT: &str = "the service specification carries more than one placement representation; use the typed placement, a TaskTemplate Placement, or dotted Placement.* keys, but not more than one";

/// A top-level `RestartPolicy` entry or a second spelling of restart policy is
/// a refusal, not a choice. The fixed message is shared by both cases.
const CONFLICTING_RESTART_POLICY: &str = "the service specification carries more than one restart policy representation; use the typed restart policy, a TaskTemplate RestartPolicy, or dotted RestartPolicy.* keys, but not more than one";

/// Whether the typed placement actually emits one of its members.
fn placement_emits(placement: &ServicePlacement, member: &str) -> bool {
    match member {
        "Constraints" => !placement.constraints.is_empty(),
        "Preferences" => !placement.preferences.is_empty(),
        "MaxReplicas" => placement.max_replicas != 0,
        _ => false,
    }
}

/// Whether the typed restart policy actually emits one of its members.
fn restart_policy_emits(policy: &ServiceRestartPolicy, member: &str) -> bool {
    match member {
        "Condition" => true,
        "Delay" => policy.delay.is_some(),
        "MaxAttempts" => policy.max_attempts.is_some(),
        "Window" => policy.window.is_some(),
        "FailureAction" => policy.failure_action.is_some(),
        _ => false,
    }
}

/// The service specification's root member names as the Engine models them.
///
/// `Placement` and `RestartPolicy` are not valid at the specification root, but
/// they are included so a case variant of either is refused instead of being
/// written as an unknown root member the Engine could fold onto a modeled field.
const MODELED_ROOT_MEMBERS: &[&str] = &[
    "Name",
    "Labels",
    "TaskTemplate",
    "Mode",
    "EndpointSpec",
    "Networks",
    "UpdateConfig",
    "RollbackConfig",
    "Placement",
    "RestartPolicy",
];

/// The members the Engine's `TaskSpec` models and this writer can merge into.
///
/// The list is used to refuse a case variant of a *modeled* member; an unknown
/// member with an ASCII key is still passed through.
const MODELED_TASK_MEMBERS: &[&str] = &[
    "ContainerSpec",
    "Resources",
    "RestartPolicy",
    "Placement",
    "ForceUpdate",
    "Runtime",
    "Networks",
    "LogDriver",
    "PluginSpec",
    "NetworkAttachmentSpec",
    "ShutdownDelay",
];

/// The members the Engine's `Placement` models, plus the retained `Platforms`.
const MODELED_PLACEMENT_MEMBERS: &[&str] =
    &["Constraints", "Preferences", "MaxReplicas", "Platforms"];

/// The members the Engine's `RestartPolicy` models.
const MODELED_RESTART_MEMBERS: &[&str] = &[
    "Condition",
    "Delay",
    "MaxAttempts",
    "Window",
    "FailureAction",
];

/// The members the Engine's `ServiceMode` models.
const MODELED_MODE_MEMBERS: &[&str] = &["Replicated", "Global", "ReplicatedJob", "GlobalJob"];

/// The members the Engine's `EndpointSpec` models.
const MODELED_ENDPOINT_SPEC_MEMBERS: &[&str] = &["Mode", "Ports"];

/// The members the Engine's `UpdateConfig` and `RollbackConfig` models.
const MODELED_UPDATE_CONFIG_MEMBERS: &[&str] = &[
    "Parallelism",
    "Delay",
    "FailureAction",
    "Monitor",
    "MaxFailureRatio",
    "Order",
];

/// Fixed refusal for two service-specification keys that fold onto one member.
///
/// The Engine matches JSON member names case-insensitively (Go's decoder folds
/// names), so `Placement` and `placement`, or `Labels` and `labels`, are two
/// spellings of one member and which one applies is decided by the daemon. The
/// message names no caller key or value.
const SERVICE_SPEC_CASE_COLLISION: &str = "the service specification carries more than one case spelling of a member; the Engine matches member names case-insensitively, so only one spelling can apply and which one is not caller-controlled. Name each modeled member once, in its exact Engine spelling; expose a service-defined map key through the typed `labels` member or inside `task_template`";

/// Fixed refusal for a non-ASCII key on a modeled merge surface.
///
/// Go's case-insensitive field matching uses Unicode folding, so a non-ASCII
/// letter can fold onto an ASCII member name (`Labelſ` folds to `Labels` under
/// simple folding). This writer does not enumerate a daemon's fold table, so it
/// refuses the key rather than sending a member whose meaning is decided by the
/// daemon.
const SERVICE_SPEC_NON_ASCII_KEY: &str = "the service specification carries a non-ASCII member name on a modeled member surface; the Engine's Unicode case folding can map such a name onto an ASCII member, so it is refused rather than sent with an unpredictable effect. A non-ASCII service-defined key belongs in the typed `labels` member or inside `task_template`";

// Go encoding/json's base64 decoder ignores non-zero trailing bits, unlike the
// base64 crate's strict STANDARD engine. Keep its standard alphabet/padding
// checks while matching that trailing-bit behavior for []byte fields.
const MOBY_BYTES_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

fn case_collision() -> Error {
    Error::invalid_input(String::from(SERVICE_SPEC_CASE_COLLISION))
}

fn non_ascii_key() -> Error {
    Error::invalid_input(String::from(SERVICE_SPEC_NON_ASCII_KEY))
}

/// Folds one already-validated ASCII member name for collision comparison.
///
/// Non-ASCII keys are refused before this is called, so leaving a non-ASCII
/// character unchanged here cannot make two distinct keys compare equal.
fn ascii_fold(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// Refuses `additional` keys that the Engine could fold onto one another or onto
/// a modeled member.
///
/// The check runs before any merge, so a collision is reported even though the
/// merge would have produced two JSON keys and let the daemon choose. A dotted
/// key's *parent* is the root member it merges into; its member half is checked
/// against the modeled members of `TaskTemplate`, `Placement`, and
/// `RestartPolicy`. Every key in `additional` must be ASCII: the Engine's
/// Unicode folding is not reproduced here, so a non-ASCII key cannot be proven
/// safe. Service-defined map keys remain available through the typed `labels`
/// member and through `task_template`.
fn reject_service_spec_key_collisions(spec: &ServiceSpec) -> Result<(), Error> {
    let mut root_names: BTreeMap<String, &str> = BTreeMap::new();
    for key in spec.additional.keys() {
        if !key.is_ascii() {
            return Err(non_ascii_key());
        }
        let (root, member) = match key.split_once('.') {
            Some((root, member)) => (root, Some(member)),
            None => (key.as_str(), None),
        };
        // An exact modeled name is the intentional spelling; a different case
        // of it is a second spelling of the same member.
        if let Some(modeled) = MODELED_ROOT_MEMBERS
            .iter()
            .find(|modeled| modeled.eq_ignore_ascii_case(root))
            && root != *modeled
        {
            return Err(case_collision());
        }
        // Two `additional` keys may address the same root only when both spell
        // it exactly: a whole object plus its dotted members is the documented
        // merge. A case variant is not.
        if let Some(previous) = root_names.insert(ascii_fold(root), root)
            && previous != root
        {
            return Err(case_collision());
        }
        if let Some(member) = member {
            reject_dotted_member_collision(spec, root, member)?;
        }
    }
    Ok(())
}

/// Refuses a dotted member that is a case variant of a modeled nested member or
/// that competes with a typed placement/restart policy.
fn reject_dotted_member_collision(
    spec: &ServiceSpec,
    root: &str,
    member: &str,
) -> Result<(), Error> {
    if root.eq_ignore_ascii_case("TaskTemplate") {
        if let Some(modeled) = MODELED_TASK_MEMBERS
            .iter()
            .find(|modeled| modeled.eq_ignore_ascii_case(member))
            && member != *modeled
        {
            return Err(case_collision());
        }
        if member == "Placement" && spec.placement.is_some() {
            return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
        }
        if member == "RestartPolicy" && spec.restart_policy.is_some() {
            return Err(Error::invalid_input(String::from(
                CONFLICTING_RESTART_POLICY,
            )));
        }
        return Ok(());
    }
    let modeled = if root.eq_ignore_ascii_case("Placement") {
        MODELED_PLACEMENT_MEMBERS
    } else if root.eq_ignore_ascii_case("RestartPolicy") {
        MODELED_RESTART_MEMBERS
    } else if root.eq_ignore_ascii_case("Mode") {
        MODELED_MODE_MEMBERS
    } else if root.eq_ignore_ascii_case("EndpointSpec") {
        MODELED_ENDPOINT_SPEC_MEMBERS
    } else if root.eq_ignore_ascii_case("UpdateConfig")
        || root.eq_ignore_ascii_case("RollbackConfig")
    {
        MODELED_UPDATE_CONFIG_MEMBERS
    } else {
        return Ok(());
    };
    if let Some(modeled) = modeled
        .iter()
        .find(|modeled| modeled.eq_ignore_ascii_case(member))
        && member != *modeled
    {
        return Err(case_collision());
    }
    Ok(())
}

/// Validates the merged request recursively against the manually inventoried
/// Moby 1.55 JSON schema.
///
/// Unknown scalar extension fields remain accepted. Unknown structured fields,
/// wrong object/array/map shapes, and case collisions on any struct surface are
/// refused. Declared maps are the exception: their keys are user data and are
/// intentionally unrestricted.
fn reject_service_spec_body_collisions(body: &serde_json::Value) -> Result<(), Error> {
    validate_schema_value(body, "Service")
}

// This deliberately describes the JSON decoding surface, not the daemon's
// semantic validation. Keep it aligned with the pinned Moby 1.55 inventory in
// docs/service-schema-1.55.md. Unknown scalar fields remain forward-compatible;
// unknown objects/arrays are refused because their nested keys cannot be
// distinguished safely from arbitrary map keys.
fn validate_schema_value(value: &serde_json::Value, schema: &str) -> Result<(), Error> {
    use serde_json::Value;
    if value.is_null() {
        return Ok(());
    }
    if schema.starts_with('[') {
        let Value::Array(items) = value else {
            return Err(unknown_service_shape());
        };
        let child = schema
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .ok_or_else(unknown_service_shape)?;
        for item in items {
            validate_schema_value(item, child)?;
        }
        return Ok(());
    }
    if schema == "bytes" {
        if let Some(encoded) = value.as_str() {
            // encoding/json ignores CR and LF while decoding base64 []byte
            // strings; preserve that pinned Go behavior.
            let encoded: String = encoded
                .chars()
                .filter(|character| !matches!(character, '\r' | '\n'))
                .collect();
            return if MOBY_BYTES_BASE64.decode(encoded).is_ok() {
                Ok(())
            } else {
                Err(unknown_service_shape())
            };
        }
        let Some(items) = value.as_array() else {
            return Err(unknown_service_shape());
        };
        return if items
            .iter()
            .all(|item| item.is_null() || item.as_u64().is_some_and(|number| number <= 255))
        {
            Ok(())
        } else {
            Err(unknown_service_shape())
        };
    }
    if schema == "netip" {
        let Some(address) = value.as_str() else {
            return Err(unknown_service_shape());
        };
        let valid = address.is_empty()
            || address.parse::<std::net::IpAddr>().is_ok()
            || address.split_once('%').is_some_and(|(address, zone)| {
                !zone.is_empty() && address.parse::<std::net::Ipv6Addr>().is_ok()
            });
        return if valid {
            Ok(())
        } else {
            Err(unknown_service_shape())
        };
    }
    if schema == "scalar" {
        return if value.is_object() || value.is_array() {
            Err(unknown_service_shape())
        } else {
            Ok(())
        };
    }
    if let Some(value_schema) = schema.strip_prefix("map:") {
        let Some(object) = value.as_object() else {
            return Err(unknown_service_shape());
        };
        // Map key space is user-defined. Its values are still typed.
        if value_schema != "scalar" {
            return Err(unknown_service_shape());
        }
        for item in object.values() {
            if !item.is_null() && !item.is_string() {
                return Err(unknown_service_shape());
            }
        }
        return Ok(());
    }
    if service_schema_fields(schema).is_none() {
        return Err(unknown_service_shape());
    }
    let Some(object) = value.as_object() else {
        return Err(unknown_service_shape());
    };
    reject_object_key_folds(object)?;
    for (key, child) in object {
        let Some(child_schema) = service_field_schema(schema, key) else {
            if child.is_object() || child.is_array() {
                return Err(unknown_service_shape());
            }
            continue;
        };
        validate_schema_value(child, child_schema)?;
    }
    Ok(())
}

fn unknown_service_shape() -> Error {
    Error::invalid_input(String::from(
        "the service specification contains an unclassified structured value; refusing to dispatch it",
    ))
}

fn service_field_schema(parent: &str, key: &str) -> Option<&'static str> {
    service_schema_fields(parent)?
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(_, schema)| *schema)
}

#[allow(clippy::too_many_lines)] // A single searchable inventory mirrors the pinned source note.
fn service_schema_fields(parent: &str) -> Option<&'static [(&'static str, &'static str)]> {
    let fields: &'static [(&str, &str)] = match parent {
        "Service" => &[
            ("Name", "scalar"),
            ("Labels", "map:scalar"),
            ("TaskTemplate", "TaskSpec"),
            ("Mode", "ServiceMode"),
            ("UpdateConfig", "UpdateConfig"),
            ("RollbackConfig", "UpdateConfig"),
            ("EndpointSpec", "EndpointSpec"),
            ("Networks", "[NetworkAttachmentConfig]"),
        ],
        "TaskSpec" => &[
            ("ContainerSpec", "ContainerSpec"),
            ("PluginSpec", "RuntimeSpec"),
            ("NetworkAttachmentSpec", "NetworkAttachmentSpec"),
            ("Resources", "ResourceRequirements"),
            ("RestartPolicy", "RestartPolicy"),
            ("Placement", "Placement"),
            ("Networks", "[NetworkAttachmentConfig]"),
            ("LogDriver", "Driver"),
            ("ForceUpdate", "scalar"),
            ("Runtime", "scalar"),
        ],
        "ServiceMode" => &[
            ("Replicated", "ReplicatedService"),
            ("Global", "Empty"),
            ("ReplicatedJob", "ReplicatedJob"),
            ("GlobalJob", "Empty"),
        ],
        "ReplicatedService" => &[("Replicas", "scalar")],
        "ReplicatedJob" => &[("MaxConcurrent", "scalar"), ("TotalCompletions", "scalar")],
        "UpdateConfig" => &[
            ("Parallelism", "scalar"),
            ("Delay", "scalar"),
            ("FailureAction", "scalar"),
            ("Monitor", "scalar"),
            ("MaxFailureRatio", "scalar"),
            ("Order", "scalar"),
        ],
        "EndpointSpec" => &[("Mode", "scalar"), ("Ports", "[PortConfig]")],
        "PortConfig" => &[
            ("Name", "scalar"),
            ("Protocol", "scalar"),
            ("TargetPort", "scalar"),
            ("PublishedPort", "scalar"),
            ("PublishMode", "scalar"),
        ],
        "NetworkAttachmentConfig" => &[
            ("Target", "scalar"),
            ("Aliases", "[scalar]"),
            ("DriverOpts", "map:scalar"),
        ],
        "Driver" => &[("Name", "scalar"), ("Options", "map:scalar")],
        "ResourceRequirements" => &[
            ("Limits", "Limit"),
            ("Reservations", "Resources"),
            ("SwapBytes", "scalar"),
            ("MemorySwappiness", "scalar"),
        ],
        "Limit" => &[
            ("NanoCPUs", "scalar"),
            ("MemoryBytes", "scalar"),
            ("Pids", "scalar"),
        ],
        "Resources" => &[
            ("NanoCPUs", "scalar"),
            ("MemoryBytes", "scalar"),
            ("GenericResources", "[GenericResource]"),
        ],
        "GenericResource" => &[
            ("NamedResourceSpec", "NamedGenericResource"),
            ("DiscreteResourceSpec", "DiscreteGenericResource"),
        ],
        "NamedGenericResource" | "DiscreteGenericResource" => {
            &[("Kind", "scalar"), ("Value", "scalar")]
        }
        "RestartPolicy" => &[
            ("Condition", "scalar"),
            ("Delay", "scalar"),
            ("MaxAttempts", "scalar"),
            ("Window", "scalar"),
        ],
        "Placement" => &[
            ("Constraints", "[scalar]"),
            ("Preferences", "[PlacementPreference]"),
            ("MaxReplicas", "scalar"),
            ("Platforms", "[Platform]"),
        ],
        "PlacementPreference" => &[("Spread", "SpreadOver")],
        "SpreadOver" => &[("SpreadDescriptor", "scalar")],
        "Platform" => &[("Architecture", "scalar"), ("OS", "scalar")],
        "ContainerSpec" => &[
            ("Image", "scalar"),
            ("Labels", "map:scalar"),
            ("Command", "[scalar]"),
            ("Args", "[scalar]"),
            ("Hostname", "scalar"),
            ("Env", "[scalar]"),
            ("Dir", "scalar"),
            ("User", "scalar"),
            ("Groups", "[scalar]"),
            ("Privileges", "Privileges"),
            ("Init", "scalar"),
            ("StopSignal", "scalar"),
            ("TTY", "scalar"),
            ("OpenStdin", "scalar"),
            ("ReadOnly", "scalar"),
            ("Mounts", "[Mount]"),
            ("StopGracePeriod", "scalar"),
            ("Healthcheck", "Healthcheck"),
            ("Hosts", "[scalar]"),
            ("DNSConfig", "DNSConfig"),
            ("Secrets", "[SecretReference]"),
            ("Configs", "[ConfigReference]"),
            ("Isolation", "scalar"),
            ("Sysctls", "map:scalar"),
            ("CapabilityAdd", "[scalar]"),
            ("CapabilityDrop", "[scalar]"),
            ("Ulimits", "[Ulimit]"),
            ("OomScoreAdj", "scalar"),
        ],
        "Privileges" => &[
            ("CredentialSpec", "CredentialSpec"),
            ("SELinuxContext", "SELinuxContext"),
            ("Seccomp", "Seccomp"),
            ("AppArmor", "AppArmor"),
            ("NoNewPrivileges", "scalar"),
        ],
        "CredentialSpec" => &[
            ("Config", "scalar"),
            ("File", "scalar"),
            ("Registry", "scalar"),
        ],
        "SELinuxContext" => &[
            ("Disable", "scalar"),
            ("User", "scalar"),
            ("Role", "scalar"),
            ("Type", "scalar"),
            ("Level", "scalar"),
        ],
        "Seccomp" => &[("Mode", "scalar"), ("Profile", "bytes")],
        "AppArmor" => &[("Mode", "scalar")],
        "DNSConfig" => &[
            ("Nameservers", "[netip]"),
            ("Search", "[scalar]"),
            ("Options", "[scalar]"),
        ],
        "Healthcheck" => &[
            ("Test", "[scalar]"),
            ("Interval", "scalar"),
            ("Timeout", "scalar"),
            ("StartPeriod", "scalar"),
            ("StartInterval", "scalar"),
            ("Retries", "scalar"),
        ],
        "Ulimit" => &[("Name", "scalar"), ("Hard", "scalar"), ("Soft", "scalar")],
        "SecretReference" => &[
            ("File", "FileTarget"),
            ("SecretID", "scalar"),
            ("SecretName", "scalar"),
        ],
        "ConfigReference" => &[
            ("File", "FileTarget"),
            ("Runtime", "Empty"),
            ("ConfigID", "scalar"),
            ("ConfigName", "scalar"),
        ],
        "FileTarget" => &[
            ("Name", "scalar"),
            ("UID", "scalar"),
            ("GID", "scalar"),
            ("Mode", "scalar"),
        ],
        "Mount" => &[
            ("Type", "scalar"),
            ("Source", "scalar"),
            ("Target", "scalar"),
            ("ReadOnly", "scalar"),
            ("Consistency", "scalar"),
            ("BindOptions", "BindOptions"),
            ("VolumeOptions", "VolumeOptions"),
            ("ImageOptions", "ImageOptions"),
            ("TmpfsOptions", "TmpfsOptions"),
            ("ClusterOptions", "Empty"),
        ],
        "BindOptions" => &[
            ("Propagation", "scalar"),
            ("NonRecursive", "scalar"),
            ("CreateMountpoint", "scalar"),
            ("ReadOnlyNonRecursive", "scalar"),
            ("ReadOnlyForceRecursive", "scalar"),
        ],
        "VolumeOptions" => &[
            ("NoCopy", "scalar"),
            ("Labels", "map:scalar"),
            ("Subpath", "scalar"),
            ("DriverConfig", "Driver"),
        ],
        "ImageOptions" => &[("Subpath", "scalar")],
        "TmpfsOptions" => &[
            ("SizeBytes", "scalar"),
            ("Mode", "scalar"),
            ("Options", "[[scalar]]"),
        ],
        "RuntimeSpec" => &[
            ("name", "scalar"),
            ("remote", "scalar"),
            ("privileges", "[RuntimePrivilege]"),
            ("disabled", "scalar"),
            ("env", "[scalar]"),
        ],
        "RuntimePrivilege" => &[
            ("name", "scalar"),
            ("description", "scalar"),
            ("value", "[scalar]"),
        ],
        "NetworkAttachmentSpec" => &[("ContainerID", "scalar")],
        "Empty" => &[],
        _ => return None,
    };
    Some(fields)
}

/// Refuses a non-ASCII key or two keys that differ only by ASCII case.
fn reject_object_key_folds(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), Error> {
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for key in object.keys() {
        if !key.is_ascii() {
            return Err(non_ascii_key());
        }
        if seen.insert(ascii_fold(key), key).is_some() {
            return Err(case_collision());
        }
    }
    Ok(())
}

/// Validates a service specification without sending it.
///
/// The facade calls this before it selects a transport, and the raw request
/// builders call the same body builder, so both paths share one rule. It is
/// exposed to the facade rather than duplicated there.
pub(crate) fn validate_service_spec(spec: &ServiceSpec) -> Result<(), Error> {
    service_spec_body(spec).map(|_body| ())
}

/// Builds the `POST /services/create` and `POST /services/{id}/update` body.
///
/// Non-dotted `additional` entries are resolved first, so a caller that needs a
/// member this module does not name can send it and have it arrive, except the
/// top-level `Placement` and `RestartPolicy` spellings refused below. An
/// `additional` whole `TaskTemplate` is allowed only when the typed
/// `task_template` is absent; supplying both is refused instead of silently
/// replacing one. The typed placement and restart policy are then moved into
/// the resolved task template, and a member retained under the
/// `"<SubObject>.<Member>"` convention is merged back *into* its sub-object
/// rather than emitted under its dotted key, because `Placement.Platforms` is
/// not an Engine member name and the daemon would ignore it. Any
/// `"<SubObject>.<Member>"` key is an
/// explicit raw convention and merges into that sub-object; only the first dot
/// splits, so a remainder such as `com.example.team` is a literal member name.
/// The facade refuses every dotted key before reaching this writer, so ambiguity
/// there is not possible. A non-dotted `additional` member passes through
/// unchanged, except a top-level `Placement` or `RestartPolicy`: those are
/// refused even with no competing spelling, because the Engine reads them
/// inside `TaskTemplate` and the root shape is not lossless. A literal root
/// member of either name has no lossless path: moving it into `TaskTemplate`
/// changes its location and meaning, and this writer refuses the root spelling.
///
/// A competing *representation* of a member is refused rather than chosen
/// between: two spellings of the same constraint can differ, and a silent
/// winner is a service scheduled somewhere the caller did not ask for. Dotted
/// keys are ordered by depth so a whole object such as
/// `TaskTemplate.Placement` is resolved before `Placement.Platforms` merges into
/// it, and a dotted key that would replace an already-present member is
/// refused.
///
/// # Errors
///
/// Returns an error when a placement preference is not a spelling the Engine
/// accepts, when a task template is not an object, when typed and
/// TaskTemplate/dotted spellings of placement or restart policy compete, when a
/// top-level `Placement` or `RestartPolicy` additional entry is supplied, when a
/// retained dotted key names a parent this module spelled as something other
/// than an object, when two keys fold onto one modeled member under the
/// Engine's case-insensitive matching, or when a non-ASCII key appears on a
/// modeled merge surface. Every diagnostic is fixed text and quotes no caller
/// value. The fold and non-ASCII checks are documented on
/// [`ServiceSpec::additional`](crate::ServiceSpec::additional).
fn service_spec_body(spec: &ServiceSpec) -> Result<serde_json::Value, Error> {
    reject_service_spec_key_collisions(spec)?;
    let typed = ServiceSpecDocument {
        name: spec.name.as_deref(),
        labels: spec.labels.as_ref(),
        task_template: spec.task_template.as_ref(),
        mode: spec.mode.as_ref(),
        endpoint_spec: spec.endpoint_spec.as_ref(),
        networks: spec.networks.as_ref(),
        update_config: spec.update_config.as_ref(),
        rollback_config: spec.rollback_config.as_ref(),
        // `Placement` and `RestartPolicy` are added to `TaskTemplate` below
        // rather than encoded here, because that is where the create request
        // reads them.
        placement: None,
        restart_policy: None,
    };
    // A document of named members always encodes to an object; anything else is
    // a defect here rather than anything a caller controls.
    let Ok(serde_json::Value::Object(members)) = serde_json::to_value(typed) else {
        return Err(Error::invalid_input(String::from(
            "the service specification did not encode as a JSON object",
        )));
    };
    let mut members = members;
    let dotted_members = resolve_spec_members(spec, &mut members)?;
    merge_typed_spec_members(spec, &mut members)?;
    merge_dotted_spec_members(spec, &mut members, dotted_members)?;
    let body = serde_json::Value::Object(members);
    reject_service_spec_body_collisions(&body)?;
    Ok(body)
}

/// One retained `"<SubObject>.<Member>"` value, split into its two halves.
type DottedMember = (String, String, serde_json::Value);

/// Resolves non-dotted `additional` entries and rejects competing spellings.
///
/// A non-dotted entry is the documented override, and `TaskTemplate` has to be
/// resolved before typed and dotted members are merged into it. The previous
/// one-pass map walk let a later ordered `TaskTemplate` insert discard a
/// `TaskTemplate.*` member that had already been merged.
fn resolve_spec_members(
    spec: &ServiceSpec,
    members: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<DottedMember>, Error> {
    if spec.task_template.is_some() && spec.additional.contains_key("TaskTemplate") {
        return Err(Error::invalid_input(String::from(TASK_TEMPLATE_CONFLICT)));
    }
    let mut dotted_members = Vec::new();
    for (key, value) in &spec.additional {
        match dotted(key) {
            Some((parent, member)) => {
                dotted_members.push((parent.to_owned(), member.to_owned(), value.clone()));
            }
            None => {
                members.insert(key.clone(), value.clone());
            }
        }
    }
    dotted_members.sort_by(|a, b| {
        dotted_depth(&a.0, &a.1)
            .cmp(&dotted_depth(&b.0, &b.1))
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    if let Some(template) = members.get("TaskTemplate")
        && !template.is_object()
    {
        return Err(Error::invalid_input(String::from(TASK_TEMPLATE_NOT_OBJECT)));
    }
    // The typed document never emits these at the top level. An `additional`
    // top-level entry is a spelling the Engine ignores, and it would compete
    // with the `TaskTemplate` form this writer produces.
    if members.contains_key("Placement") {
        return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
    }
    if members.contains_key("RestartPolicy") {
        return Err(Error::invalid_input(String::from(
            CONFLICTING_RESTART_POLICY,
        )));
    }
    if let Some(serde_json::Value::Object(template)) = members.get("TaskTemplate") {
        if spec.placement.is_some() && template.contains_key("Placement") {
            return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
        }
        if spec.restart_policy.is_some() && template.contains_key("RestartPolicy") {
            return Err(Error::invalid_input(String::from(
                CONFLICTING_RESTART_POLICY,
            )));
        }
    }
    Ok(dotted_members)
}

/// Moves typed placement and restart policy into `TaskTemplate`.
///
/// Measured rationale: a document asking for `on-failure` with three attempts
/// otherwise *looks* right when the policy is dropped, because the daemon's
/// default delay matches the one requested. A placement constraint has no such
/// consolation: it is simply absent, and a task lands on a node the document
/// forbade.
fn merge_typed_spec_members(
    spec: &ServiceSpec,
    members: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<(), Error> {
    let into_template = |members: &mut serde_json::Map<String, serde_json::Value>,
                         member: &str,
                         value: serde_json::Value| {
        let template = members
            .entry("TaskTemplate".to_owned())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let serde_json::Value::Object(template) = template {
            template.insert(member.to_owned(), value);
        }
    };
    if let Some(policy) = spec.restart_policy.as_ref() {
        let encoded = serde_json::to_value(policy).map_err(|_error| {
            Error::invalid_input(String::from("failed to encode the restart policy"))
        })?;
        into_template(members, "RestartPolicy", encoded);
    }
    if let Some(placement) = spec.placement.as_ref() {
        let encoded =
            serde_json::to_value(PlacementDocument::new(placement)?).map_err(|_error| {
                Error::invalid_input(String::from("failed to encode the placement"))
            })?;
        into_template(members, "Placement", encoded);
    }
    Ok(())
}

/// Position of a dotted key in the expansion tree.
///
/// A `Placement.*` or `RestartPolicy.*` member sits one level below
/// `TaskTemplate`, so its whole-object ancestor (`TaskTemplate.Placement`) is
/// processed first. This is the ordering the previous one-pass map walk lacked.
fn dotted_depth(parent: &str, _member: &str) -> usize {
    match parent {
        "Placement" | "RestartPolicy" => 3,
        _ => 2,
    }
}

/// Ensures the resolved `TaskTemplate` is an object and returns it.
fn task_template_object(
    members: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, Error> {
    let template = members
        .entry("TaskTemplate".to_owned())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let serde_json::Value::Object(template) = template else {
        return Err(Error::invalid_input(String::from(TASK_TEMPLATE_NOT_OBJECT)));
    };
    Ok(template)
}

/// Merges retained dotted members into their sub-objects.
///
/// `Placement` and `RestartPolicy` live inside `TaskTemplate`, so their retained
/// members are restored there. A key that names a member the typed field also
/// emits is a conflict, not an override to choose silently.
fn merge_dotted_spec_members(
    spec: &ServiceSpec,
    members: &mut serde_json::Map<String, serde_json::Value>,
    dotted_members: Vec<DottedMember>,
) -> Result<(), Error> {
    for (parent, member, value) in dotted_members {
        // A dotted key is the retention spelling for a member the typed field
        // cannot express. When it names a member the typed field *does* emit,
        // the two disagree about the same value; choose neither silently.
        if parent == "Placement"
            && spec
                .placement
                .as_ref()
                .is_some_and(|placement| placement_emits(placement, &member))
        {
            return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
        }
        if parent == "RestartPolicy"
            && spec
                .restart_policy
                .as_ref()
                .is_some_and(|policy| restart_policy_emits(policy, &member))
        {
            return Err(Error::invalid_input(String::from(
                CONFLICTING_RESTART_POLICY,
            )));
        }

        if parent == "TaskTemplate" {
            if member == "Placement" {
                if !value.is_object() {
                    return Err(Error::invalid_input(String::from(PLACEMENT_NOT_OBJECT)));
                }
                if spec.placement.is_some() {
                    return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
                }
                let template = task_template_object(members)?;
                if template.contains_key("Placement") {
                    return Err(Error::invalid_input(String::from(CONFLICTING_PLACEMENT)));
                }
                template.insert(member, value);
                continue;
            }
            if member == "RestartPolicy" {
                if !value.is_object() {
                    return Err(Error::invalid_input(String::from(
                        RESTART_POLICY_NOT_OBJECT,
                    )));
                }
                if spec.restart_policy.is_some() {
                    return Err(Error::invalid_input(String::from(
                        CONFLICTING_RESTART_POLICY,
                    )));
                }
                let template = task_template_object(members)?;
                if template.contains_key("RestartPolicy") {
                    return Err(Error::invalid_input(String::from(
                        CONFLICTING_RESTART_POLICY,
                    )));
                }
                template.insert(member, value);
                continue;
            }
            let template = task_template_object(members)?;
            if template.contains_key(&member) {
                return Err(Error::invalid_input(String::from(DOTTED_MEMBER_CONFLICT)));
            }
            template.insert(member, value);
            continue;
        }

        if matches!(parent.as_str(), "Placement" | "RestartPolicy") {
            let template = task_template_object(members)?;
            let target = template
                .entry(parent.clone())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            let serde_json::Value::Object(object) = target else {
                return Err(Error::invalid_input(String::from(DOTTED_PARENT_NOT_OBJECT)));
            };
            if object.contains_key(&member) {
                return Err(Error::invalid_input(if parent == "Placement" {
                    String::from(CONFLICTING_PLACEMENT)
                } else {
                    String::from(CONFLICTING_RESTART_POLICY)
                }));
            }
            object.insert(member, value);
            continue;
        }

        // A dotted top-level member must merge into an object, never replace
        // one that already carries the same member.
        let target = members
            .entry(parent.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        let serde_json::Value::Object(object) = target else {
            return Err(Error::invalid_input(String::from(DOTTED_PARENT_NOT_OBJECT)));
        };
        if object.contains_key(&member) {
            return Err(Error::invalid_input(String::from(DOTTED_MEMBER_CONFLICT)));
        }
        object.insert(member, value);
    }
    Ok(())
}

/// Splits a `"<SubObject>.<Member>"` key into its two halves.
///
/// The Engine spells no member with a dot, so a dotted key is unambiguously a
/// retained member of a sub-object rather than a member of the object itself.
fn dotted(key: &str) -> Option<(&str, &str)> {
    key.split_once('.')
}

/// The `POST /services/create` and `POST /services/{id}/update` body.
#[derive(Debug, Serialize)]
struct ServiceSpecDocument<'a> {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
    #[serde(rename = "TaskTemplate", skip_serializing_if = "Option::is_none")]
    task_template: Option<&'a serde_json::Value>,
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    mode: Option<&'a serde_json::Value>,
    #[serde(rename = "EndpointSpec", skip_serializing_if = "Option::is_none")]
    endpoint_spec: Option<&'a serde_json::Value>,
    #[serde(rename = "Networks", skip_serializing_if = "Option::is_none")]
    networks: Option<&'a serde_json::Value>,
    #[serde(rename = "UpdateConfig", skip_serializing_if = "Option::is_none")]
    update_config: Option<&'a serde_json::Value>,
    #[serde(rename = "RollbackConfig", skip_serializing_if = "Option::is_none")]
    rollback_config: Option<&'a serde_json::Value>,
    #[serde(rename = "Placement", skip_serializing_if = "Option::is_none")]
    placement: Option<PlacementDocument<'a>>,
    #[serde(rename = "RestartPolicy", skip_serializing_if = "Option::is_none")]
    restart_policy: Option<&'a ServiceRestartPolicy>,
}

/// The `Placement` block of a service body, in the Engine's spelling.
///
/// `Preferences` is where the two paths differ most visibly. The Engine's type
/// is a list of objects, while a Compose `deploy:` block — and therefore
/// [`ServicePlacement::preferences`] — carries strings such as
/// `spread=node.labels.zone`. A list of strings sent as-is is a body the Engine
/// cannot decode, so each string is converted here into the object it declares,
/// and a string that is not a `spread=` preference is refused before the socket
/// rather than sent to be rejected.
///
/// `Platforms` has no counterpart in the repository type at all. A caller sets
/// it through the specification's `additional` map under the key
/// `Platforms` or `Placement.Platforms`, and it is merged into this object by
/// [`service_spec_body`].
#[derive(Debug, Serialize)]
struct PlacementDocument<'a> {
    #[serde(rename = "Constraints", skip_serializing_if = "Option::is_none")]
    constraints: Option<&'a [String]>,
    #[serde(rename = "Preferences", skip_serializing_if = "Vec::is_empty")]
    preferences: Vec<PreferenceDocument<'a>>,
    #[serde(rename = "MaxReplicas", skip_serializing_if = "is_zero")]
    max_replicas: u32,
}

impl<'a> PlacementDocument<'a> {
    /// Projects the repository placement onto the Engine's block.
    ///
    /// # Errors
    ///
    /// Returns an error when a preference string is not a `spread=` preference.
    /// The Engine declares exactly one preference kind, so a string outside
    /// that spelling has no translation, and inventing one would place tasks
    /// somewhere the caller did not ask for.
    fn new(placement: &'a ServicePlacement) -> Result<Self, Error> {
        let preferences = placement
            .preferences
            .iter()
            .map(|preference| PreferenceDocument::new(preference))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            constraints: nonempty(&placement.constraints),
            preferences,
            max_replicas: placement.max_replicas,
        })
    }
}

/// One `Placement.Preferences` entry, in the Engine's spelling.
#[derive(Debug, Serialize)]
struct PreferenceDocument<'a> {
    /// The Engine's `Spread` member, the only preference kind it declares.
    #[serde(rename = "Spread")]
    spread: SpreadDocument<'a>,
}

/// The `Spread` member of a placement preference.
#[derive(Debug, Serialize)]
struct SpreadDocument<'a> {
    /// The node-label or node-id expression to spread across.
    #[serde(rename = "SpreadDescriptor")]
    descriptor: &'a str,
}

impl<'a> PreferenceDocument<'a> {
    /// Converts one written preference into the Engine's object.
    ///
    /// # Errors
    ///
    /// Returns an error when the string does not start with `spread=` and names
    /// nothing after it. That is the only form Docker's own CLI accepts, and so
    /// the only one this crate can translate without guessing.
    fn new(preference: &'a str) -> Result<Self, Error> {
        let Some(descriptor) = preference.strip_prefix("spread=") else {
            return Err(Error::invalid_input(
                "invalid swarm placement preference; use 'spread=<label expression>'",
            ));
        };
        if descriptor.is_empty() {
            return Err(Error::invalid_input(String::from(
                "a swarm placement preference must name a label expression after 'spread='",
            )));
        }
        Ok(Self {
            spread: SpreadDocument { descriptor },
        })
    }
}

/// Returns the slice when it has values, or nothing when it does not.
///
/// An empty JSON array is not the same as an absent member to every daemon, and
/// an unset restriction means "no constraint" rather than "an empty list of
/// constraints".
fn nonempty(values: &[String]) -> Option<&[String]> {
    (!values.is_empty()).then_some(values)
}

/// Reports whether a `u32` is zero, for a `skip_serializing_if` that treats zero
/// as unset.
///
/// Takes the value by reference because serde hands a `skip_serializing_if` a
/// reference; the lint about passing it by value does not apply to a function
/// whose whole job is to be handed one.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// The `POST /services/create` answer, in the Engine's spelling.
///
/// The member is `ID`, not `Id`: the container create endpoint answers `Id` and
/// this one answers `ID`, and a client that spelled it the container way would
/// report an empty service ID for a service that was created.
#[derive(Debug, Deserialize)]
struct ServiceCreateDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(
        default,
        rename = "Warnings",
        deserialize_with = "super::null_as_empty"
    )]
    warnings: Vec<String>,
}

impl From<ServiceCreateDocument> for ServiceCreateResult {
    fn from(document: ServiceCreateDocument) -> Self {
        Self {
            id: document.id.unwrap_or_default(),
            warnings: document.warnings,
        }
    }
}

/// Inspects one Swarm service.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a service.
pub async fn service_inspect(engine: &RawEngine, id: &str) -> Result<SwarmService, Error> {
    let response = engine.send(service_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmService::try_from(decode::<ServiceDocument>(&document)?)
}

/// Uses the generated facade's endpoint and status validation rules.
pub(crate) async fn service_inspect_for_facade(
    engine: &RawEngine,
    id: &str,
) -> Result<SwarmService, Error> {
    let response = engine.send(service_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    decode::<ServiceDocument>(&document)?.into_facade()
}

/// Builds the `GET /services/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("services", id, "")?,
    ))
}

/// Updates or rolls back a service at an explicit expected version.
///
/// `rollback` is sent only when the caller asked for it, and as the Engine's
/// `previous` spelling. The Engine reads the parameter as a task ID or the word
/// `previous`, so `rollback=false` would be a request to roll back to a task
/// named `false`. Omitting it is the only correct way to say "do not roll back".
///
/// This form sends no `X-Registry-Auth` header. [`service_update_with_registry_auth`]
/// is the form that carries a credential, and it has the same request otherwise.
///
/// # Failure text is withheld
///
/// A service update body can carry `ContainerSpec.Env`, so every failure is
/// content-free: the kind is preserved, a daemon or proxy status is preserved
/// when observed, and the message is fixed withholding text. The response body
/// is not read on a rejection.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int32`, when a placement preference is not a spelling the
/// Engine accepts, when a top-level `Placement` or `RestartPolicy` additional
/// entry is supplied, or when the daemon rejects the request. A stale version
/// stays a `409 Conflict` with the withheld message.
pub async fn service_update(
    engine: &RawEngine,
    id: &str,
    options: &ServiceUpdateOptions,
) -> Result<ServiceUpdateResult, Error> {
    service_update_with_registry_auth(engine, id, options, RegistryAuth::none()).await
}

/// Updates or rolls back a service, carrying one registry credential.
///
/// The credential becomes the Engine's `X-Registry-Auth` header, URL-safe
/// base64 over its `AuthConfig` object. [`RegistryAuth::none`] is the honest
/// spelling of "no credential" and sends no header at all; an empty header would
/// look like a credential the daemon could not decode. The query always names
/// `registryAuthFrom=spec`, which is the daemon-side fallback the Engine
/// documents when the header is absent, and is what the generated update sends
/// for the same call.
///
/// The credential is a password: it is redacted from every `Debug` rendering in
/// this crate. A failure never carries the peer's response text or a
/// peer-controlled source chain: the status is preserved when one was observed,
/// and the message is the fixed service-update withholding text. That applies on a
/// direct route, an unauthenticated proxy, and an authenticated proxy alike,
/// because the body may also carry `ContainerSpec.Env`.
/// Safe typed deadline and managed host-key markers survive a transport failure.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int32`, when the credential does not match its registry or
/// cannot be encoded as a header, when a placement preference is not a spelling
/// the Engine accepts, when a top-level `Placement` or `RestartPolicy`
/// additional entry is supplied, or when the daemon rejects the request. A stale
/// version stays a `409 Conflict`.
pub async fn service_update_with_registry_auth(
    engine: &RawEngine,
    id: &str,
    options: &ServiceUpdateOptions,
    auth: RegistryAuth<'_>,
) -> Result<ServiceUpdateResult, Error> {
    let request = service_update_request(id, options, auth)?;
    // The request body can hold `ContainerSpec.Env` and the header can hold a
    // registry password. A peer-controlled failure message may echo either, so
    // no part of a transport failure's source chain is promoted. The kind
    // and safe typed markers are kept, never the original source chain.
    let response = engine
        .send(request)
        .await
        .map_err(|error| {
            withheld_response_error(
                &error,
                WITHHELD_SERVICE_UPDATE_MESSAGE,
                "a transport deadline was observed; the service update outcome is unknown; reconcile before retrying",
            )
        })?;
    let status = response.status;
    if !status.is_success() {
        // Do not read the body at all. The status is the only observable fact
        // that survives withholding.
        drop(response);
        return Err(Error::engine_api_withheld(
            status,
            WITHHELD_SERVICE_UPDATE_MESSAGE,
        ));
    }
    // A success body is a small `Warnings` document. A body read failure is a
    // transport failure whose source is peer-controlled, so it is withheld as
    // well; a malformed JSON body is a content-free decode error.
    let document = response.document().await.map_err(|error| {
        Error::from(error).withhold_transport(
            WITHHELD_SERVICE_UPDATE_MESSAGE,
            WITHHELD_SERVICE_UPDATE_MESSAGE,
        )
    })?;
    decode::<ServiceUpdateDocument>(&document).map(ServiceUpdateResult::from)
}

/// Builds the `POST /services/{id}/update` request.
///
/// The query order matches the generated client's parameter order: `version`,
/// then `registryAuthFrom`, then `rollback` when requested. `registryAuthFrom`
/// is always sent as `spec`, including when an `X-Registry-Auth` header is
/// present; the Engine reads the header first and treats the parameter as the
/// fallback location.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int32`, when the specification cannot be encoded, or when the
/// registry credential cannot be encoded as a header.
fn service_update_request(
    id: &str,
    options: &ServiceUpdateOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.value("version", &checked_i32(options.version)?.to_string());
    query.value("registryAuthFrom", "spec");
    if options.rollback {
        query.value("rollback", "previous");
    }
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path("services", id, "/update")?,
        ))
        .with_body(json_body(&service_spec_body(&options.spec)?)?),
        query.finish(),
    );
    with_registry_auth(request, auth).map_err(|error| {
        // Encoding a header happens before the body is sent, but the credential
        // is a password. Keep the kind and replace the chain with fixed text so
        // no encoder detail can carry it.
        Error::withheld(error.kind(), "failed to encode the registry auth header")
    })
}

/// The `POST /services/{id}/update` answer, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ServiceUpdateDocument {
    #[serde(
        default,
        rename = "Warnings",
        deserialize_with = "super::null_as_empty"
    )]
    warnings: Vec<String>,
}

impl From<ServiceUpdateDocument> for ServiceUpdateResult {
    fn from(document: ServiceUpdateDocument) -> Self {
        Self {
            warnings: document.warnings,
        }
    }
}

/// Removes one Swarm service.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `404` for a service that
/// does not exist.
pub async fn service_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed(engine, service_remove_request(id)?).await
}

/// Builds the `DELETE /services/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("services", id, "")?,
    ))
}

/// Inspects one Swarm node.
///
/// A repeated key at the node top level or in any object under `Spec`
/// is refused before projection for the same reason as [`node_list`].
/// The same response-wide 65,536 checked-member limit applies; exceeding it
/// returns a fixed [`ErrorKind::Serialization`](crate::ErrorKind::Serialization).
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, when the answer is not a node, or when it
/// repeats one of those keys. The duplicate refusal is a fixed
/// [`ErrorKind::Serialization`](crate::ErrorKind::Serialization) error that
/// names no key or value.
pub async fn node_inspect(engine: &RawEngine, id: &str) -> Result<SwarmNode, Error> {
    let document = node_documents::<NodeDocument>(engine, node_inspect_request(id)?).await?;
    SwarmNode::try_from(document)
}

/// Inspects one node for the facade, refusing an actual top-level
/// `EngineVersion` before projection.
///
/// # Errors
///
/// Returns the same errors as [`node_inspect`], plus a fixed
/// [`ErrorKind::Serialization`](crate::ErrorKind::Serialization) error when the
/// decoded node carries a top-level `EngineVersion` member of any JSON type.
pub(crate) async fn node_inspect_for_facade(
    engine: &RawEngine,
    id: &str,
) -> Result<SwarmNode, Error> {
    let document = node_documents::<NodeDocument>(engine, node_inspect_request(id)?).await?;
    if document.additional.contains_key("EngineVersion") {
        return Err(Error::serialization_withheld(
            NODE_ENGINE_VERSION_COLLISION_MESSAGE,
        ));
    }
    SwarmNode::try_from(document)
}

/// Builds the `GET /nodes/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn node_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("nodes", id, "")?,
    ))
}

/// Updates one Swarm node at an explicit expected version.
///
/// The request body carries the node's name and labels, which are operator
/// metadata. A direct daemon or an unauthenticated forward proxy controls a
/// non-success answer and can echo request text, so this operation does not
/// preserve peer text. An Engine rejection keeps its status; its message and
/// source chain are replaced with fixed text. A transport failure keeps its
/// kind and loses its source chain. See the facade method for the full
/// compatibility note.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, when the specification cannot be encoded, when
/// [`NodeSpec::additional`] carries a reserved modeled key, or when the daemon
/// rejects the request. A stale version stays a `409 Conflict` with its status
/// preserved and its peer text withheld.
/// Every non-ASCII additional key is also refused conservatively, including
/// unrelated extension keys. A transport deadline marker, including one
/// propagated from an earlier caller-supplied factory operation, reports a
/// fixed deadline message: the mutation outcome is unknown and must be
/// reconciled before retrying. The message does not claim this mutation itself
/// timed out.
pub async fn node_update(
    engine: &RawEngine,
    id: &str,
    options: &NodeUpdateOptions,
) -> Result<(), Error> {
    let request = node_update_request(id, options)?;
    completed_withheld(
        engine,
        request,
        WITHHELD_NODE_MUTATION_MESSAGE,
        NODE_MUTATION_DEADLINE_MESSAGE,
    )
    .await
}

/// Builds the `POST /nodes/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, when the specification carries a reserved
/// `additional` key, or when the specification cannot be encoded.
fn node_update_request(id: &str, options: &NodeUpdateOptions) -> Result<RawRequest, Error> {
    let version = checked_i64(options.version)?;
    reject_reserved_node_spec_members(&options.spec)?;
    let mut query = Query::default();
    query.value("version", &version.to_string());
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path("nodes", id, "/update")?,
        ))
        .with_body(json_body(&options.spec)?),
        query.finish(),
    );
    Ok(request)
}

/// Removes one Swarm node.
///
/// `force` is always spelled, for the reason given on [`swarm_leave`]. A manager
/// cannot be removed without it, and a recorded request that omits the parameter
/// cannot say whether the caller meant to.
///
/// A direct daemon or an unauthenticated forward proxy controls a non-success
/// answer and can echo node metadata, so this operation does not preserve peer
/// text. An Engine rejection keeps its status; its message and source chain are
/// replaced with fixed text. A transport failure keeps its kind and loses its
/// source chain; a deadline marker, including one propagated from an earlier
/// caller-supplied factory operation, reports the fixed deadline diagnostic
/// described on the facade method. See the facade method for the full
/// compatibility note.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `400` for a manager
/// removed without `force`. The status is preserved and the peer text is
/// withheld.
pub async fn node_remove(
    engine: &RawEngine,
    id: &str,
    options: &NodeRemoveOptions,
) -> Result<(), Error> {
    completed_withheld(
        engine,
        node_remove_request(id, *options)?,
        WITHHELD_NODE_MUTATION_MESSAGE,
        NODE_MUTATION_DEADLINE_MESSAGE,
    )
    .await
}

/// Builds the `DELETE /nodes/{id}` request.
///
/// The options are taken by value because the type is one `bool`; the public
/// operation still borrows, so a caller can reuse its options afterwards.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn node_remove_request(id: &str, options: NodeRemoveOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("force", options.force);
    Ok(with_query(
        RawRequest::new(Method::DELETE, &resource_path("nodes", id, "")?),
        query.finish(),
    ))
}

/// Inspects one Swarm task.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, when the answer is not a task, or when it
/// contains a top-level `Image` member (a fixed serialization error).
pub async fn task_inspect(engine: &RawEngine, id: &str) -> Result<SwarmTask, Error> {
    let response = engine.send(task_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmTask::try_from(decode::<TaskDocument>(&document)?)
}

/// Builds the `GET /tasks/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn task_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("tasks", id, "")?,
    ))
}

/// Inspects one Swarm config.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request, or when the answer is not a config.
pub async fn config_inspect(engine: &RawEngine, id: &str) -> Result<SwarmConfig, Error> {
    let response = engine.send(config_inspect_request(id)?).await?;
    let document = engine_result(response).await?;
    SwarmConfig::try_from(decode::<ConfigDocument>(&document)?)
}

/// Builds the `GET /configs/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("configs", id, "")?,
    ))
}

/// Creates a Swarm config and returns its ID.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// `data` is base64-encoded here because the Engine declares `ConfigSpec.Data` as
/// a base64 string. A list answer normally omits the member and an inspect answer
/// includes it, so a config read back carries the bytes the daemon stored.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request,
/// such as a `409` for a name the Swarm already uses.
pub async fn config_create(
    engine: &RawEngine,
    options: &ConfigCreateOptions,
) -> Result<String, Error> {
    let request = config_create_request(options);
    let document: IdDocument = document_withheld(
        engine,
        request,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await?;
    document.id.ok_or_else(|| {
        Error::invalid_input("the Engine created the resource but reported no ID for it")
    })
}

/// Builds the `POST /configs/create` request.
fn config_create_request(options: &ConfigCreateOptions) -> RawRequest {
    let body = json_body(&ResourceCreateDocument {
        name: &options.name,
        labels: options.labels.as_ref(),
        data: options.data.as_deref().map(|data| STANDARD.encode(data)),
    })
    .expect("a document of owned values always encodes");
    json_content_type(RawRequest::new(Method::POST, "/configs/create")).with_body(body)
}

/// Updates a Swarm config at an explicit expected version.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// The owned specification retains Data and additional metadata. Reserved or
/// non-ASCII additional keys are refused to prevent ambiguous keys.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the version does not fit
/// the Engine's `int64`, or when the daemon rejects the request.
pub async fn config_update(
    engine: &RawEngine,
    id: &str,
    options: &ConfigUpdateOptions,
) -> Result<(), Error> {
    completed_withheld(
        engine,
        config_update_request(id, checked_i64(options.version)?, &options.spec)?,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await
}

/// Builds the `POST /configs/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_update_request(
    id: &str,
    version: i64,
    spec: &SwarmConfigSpec,
) -> Result<RawRequest, Error> {
    validate_config_spec(spec)?;
    resource_update_request("configs", id, version, spec)
}

/// Removes one Swarm config.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request, such as a `400` for a config a
/// running task still uses.
pub async fn config_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed_withheld(
        engine,
        config_remove_request(id)?,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await
}

/// Builds the `DELETE /configs/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn config_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("configs", id, "")?,
    ))
}

/// Inspects one Swarm secret.
///
/// The Engine does not return secret data from an inspect or a list. If a peer
/// sends a `Spec.Data` member anyway, it is not a member [`SwarmSecretSpec`]
/// names, so it is retained at the `Spec` object level in
/// [`SwarmSecretSpec::additional`] rather than dropped: the value keeps what the
/// peer sent, [`std::fmt::Debug`] withholds it, and `Serialize` carries it.
/// Retention is object-level, not a general lossless claim — a typed sub-object
/// such as `Version` has no catch-all, and duplicate keys cannot both be
/// represented. The returned value is the caller's to protect.
///
/// A non-success Engine answer preserves its status in [`crate::Error::api_error`]
/// but withholds the response text with a fixed diagnostic, for direct and
/// proxied routes alike. This is a behavior change for a raw caller: the
/// previous raw operation returned the peer's message and source. A transport or
/// cancellation failure is not an API failure and keeps its kind and text.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached or rejects the request (status preserved, text withheld), or when the
/// answer is not a secret.
pub async fn secret_inspect(engine: &RawEngine, id: &str) -> Result<SwarmSecret, Error> {
    let response = engine.send(secret_inspect_request(id)?).await?;
    let document = engine_result(response)
        .await
        .map_err(withhold_secret_read_error)?;
    SwarmSecret::try_from(decode::<SecretDocument>(&document)?)
}

/// Builds the `GET /secrets/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_inspect_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::GET,
        &resource_path("secrets", id, "")?,
    ))
}

/// Creates a Swarm secret and returns its ID.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// The bytes are base64-encoded for the wire, and the caller's own copy is
/// zeroized when it is dropped, which is the handling the repository type gives
/// them everywhere else.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request.
pub async fn secret_create(
    engine: &RawEngine,
    options: &SecretCreateOptions,
) -> Result<String, Error> {
    let request = secret_create_request(options);
    let document: IdDocument = document_withheld(
        engine,
        request,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await?;
    document.id.ok_or_else(|| {
        Error::invalid_input("the Engine created the resource but reported no ID for it")
    })
}

/// Builds the `POST /secrets/create` request.
fn secret_create_request(options: &SecretCreateOptions) -> RawRequest {
    let body = json_body(&ResourceCreateDocument {
        name: &options.name,
        labels: options.labels.as_ref(),
        data: options
            .data
            .as_ref()
            .map(|data| STANDARD.encode(data.as_bytes())),
    })
    .expect("a document of owned values always encodes");
    json_content_type(RawRequest::new(Method::POST, "/secrets/create")).with_body(body)
}

/// Updates secret metadata at an explicit expected version.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// The owned specification retains Driver and unreserved additional metadata.
/// An unexpected Data member is refused before dispatch.
///
/// A specification carrying a reserved member in `additional` is refused before
/// dispatch with the same fixed, content-free diagnostics the facade uses. The
/// comparison is ASCII case-insensitive because the Engine's Go decoder matches
/// field names without regard to case, while this crate's serde models do not:
/// `data` or `DATA` would bypass an exact-key guard on the client but not the
/// daemon. A non-ASCII key is refused conservatively because Go's folding is
/// Unicode (`Label\u{017f}` can reach `Labels`) and this crate has no
/// dependency-free full fold table. `Data` is the security case; `Name`,
/// `Labels`, and `Driver` are refused because this metadata writer would
/// otherwise silently project a value the caller thought it had sent.
///
/// The guard is structural; it does not inspect free-form values.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the specification carries
/// a reserved member in `additional`, when the version does not fit the Engine's
/// `int64`, or when the daemon rejects the request.
pub async fn secret_update(
    engine: &RawEngine,
    id: &str,
    options: &SecretUpdateOptions,
) -> Result<(), Error> {
    refuse_unrepresentable_secret_update(&options.spec)?;
    completed_withheld(
        engine,
        secret_update_request(id, checked_i64(options.version)?, &options.spec)?,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await
}

/// Builds the `POST /secrets/{id}/update` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_update_request(
    id: &str,
    version: i64,
    spec: &SwarmSecretSpec,
) -> Result<RawRequest, Error> {
    resource_update_request("secrets", id, version, spec)
}

/// Removes one Swarm secret.
///
/// Failure text and transport sources are withheld on direct and proxied
/// routes; the status and typed deadline marker survive. A deadline marker
/// only says one was observed, not that this mutation itself timed out.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request.
pub async fn secret_remove(engine: &RawEngine, id: &str) -> Result<(), Error> {
    completed_withheld(
        engine,
        secret_remove_request(id)?,
        RESOURCE_MUTATION_MESSAGE,
        RESOURCE_MUTATION_DEADLINE,
    )
    .await
}

/// Builds the `DELETE /secrets/{id}` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn secret_remove_request(id: &str) -> Result<RawRequest, Error> {
    Ok(RawRequest::new(
        Method::DELETE,
        &resource_path("secrets", id, "")?,
    ))
}

/// The `POST /configs/create` and `POST /secrets/create` body.
#[derive(Debug, Serialize)]
struct ResourceCreateDocument<'a> {
    #[serde(rename = "Name")]
    name: &'a str,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<&'a BTreeMap<String, String>>,
    /// Absent when the caller supplied no bytes, which the Engine reads as a
    /// request for an external object rather than for an empty one.
    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

/// Builds the update request the config and secret endpoints share.
///
/// # Errors
///
/// Returns an error when the reference is empty or the body cannot be encoded.
fn resource_update_request<D>(
    resource: &str,
    id: &str,
    version: i64,
    body: D,
) -> Result<RawRequest, Error>
where
    D: Serialize,
{
    let mut query = Query::default();
    query.value("version", &version.to_string());
    let request = with_query(
        json_content_type(RawRequest::new(
            Method::POST,
            &resource_path(resource, id, "/update")?,
        ))
        .with_body(json_body(&body)?),
        query.finish(),
    );
    Ok(request)
}

/// The `POST /{resource}/create` answer, which is `{"ID":"…"}` for both a config
/// and a secret.
#[derive(Debug, Deserialize)]
struct IdDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
}

/// Opens the service logs stream.
///
/// The body is multiplexed exactly as a container's is — an eight-byte frame
/// header per write — and is decoded by [`SwarmLogFrames`] with the same
/// [`LogDecoder`] the container slice uses, so a service log is read by the same
/// rules rather than by a second set of them.
///
/// `details` is **not** sent. The Engine declares the parameter's default as
/// `false`, so omitting it uses the Engine default. Sending `true` would add task and service context to every
/// record — an answer wider than the caller requested — and this client has no
/// option type that can express that choice.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request. A body that is not multiplexed
/// framing — or one carrying a frame over
/// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) — is reported by
/// [`SwarmLogFrames::next_frame`] rather than here, because one read cannot tell
/// a valid stream from a corrupt one, and cannot tell whether the frames behind
/// the refused one are still coming.
pub async fn service_logs(
    engine: &RawEngine,
    id: &str,
    options: &SwarmLogOptions,
) -> Result<SwarmLogFrames, Error> {
    open_logs(engine, service_log_request(id, options)?).await
}

/// Builds the `GET /services/{id}/logs` request.
///
/// `details` is omitted because the Engine's default is `false`, and there is no option
/// for it here.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn service_log_request(id: &str, options: &SwarmLogOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("follow", options.follow);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    query.value("since", &options.since.to_string());
    query.value("until", &options.until.to_string());
    query.flag("timestamps", options.timestamps);
    query.value("tail", &options.tail);
    Ok(with_query(
        RawRequest::new(Method::GET, &resource_path("services", id, "/logs")?),
        query.finish(),
    ))
}

/// Opens the task logs stream.
///
/// Sends the same query as the generated facade route, including `follow`,
/// `stdout` and `stderr`, so callers retain their stream selections. `details`
/// is omitted as it was by that route. Earlier raw calls omitted those three
/// stream-selection parameters. The response status is checked before decoding,
/// and failure text is withheld on direct and proxy routes because it can
/// contain task output or proxy credentials. A failure retains its HTTP status.
///
/// # Errors
///
/// Returns an error when the reference is empty, when the daemon cannot be
/// reached, or when it rejects the request.
pub async fn task_logs(
    engine: &RawEngine,
    id: &str,
    options: &SwarmLogOptions,
) -> Result<SwarmLogFrames, Error> {
    task_logs_optional(engine, id, Some(options)).await
}

pub(crate) async fn task_logs_optional(
    engine: &RawEngine,
    id: &str,
    options: Option<&SwarmLogOptions>,
) -> Result<SwarmLogFrames, Error> {
    const MESSAGE: &str = "task log response text is withheld";
    let response = engine
        .send(match options {
            Some(options) => task_log_request(id, options)?,
            None => RawRequest::new(Method::GET, &resource_path("tasks", id, "/logs")?),
        })
        .await
        .map_err(|error| {
            withheld_response_error(&error, MESSAGE, "task log transport deadline observed")
        })?;
    if !response.is_success() {
        let status = response.status;
        drop(response);
        return Err(Error::engine_api_withheld(status, MESSAGE));
    }
    Ok(SwarmLogFrames {
        frames: response.into_frames(),
        decoder: LogDecoder::new(false),
        ready: VecDeque::new(),
    })
}

/// Builds the `GET /tasks/{id}/logs` request.
///
/// # Errors
///
/// Returns an error when the reference is empty.
fn task_log_request(id: &str, options: &SwarmLogOptions) -> Result<RawRequest, Error> {
    let mut query = Query::default();
    query.flag("follow", options.follow);
    query.flag("stdout", options.stdout);
    query.flag("stderr", options.stderr);
    query.value("since", &options.since.to_string());
    query.value("until", &options.until.to_string());
    query.flag("timestamps", options.timestamps);
    query.value("tail", &options.tail);
    Ok(with_query(
        RawRequest::new(Method::GET, &resource_path("tasks", id, "/logs")?),
        query.finish(),
    ))
}

/// Sends a logs request and wraps the response in a frame decoder.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or rejects the request.
async fn open_logs(engine: &RawEngine, request: RawRequest) -> Result<SwarmLogFrames, Error> {
    let response = engine.send(request).await?;
    // The status is checked before the body is handed out, or a 404 whose body
    // happened to parse as framing would surface as a log stream.
    if !response.is_success() {
        return Err(engine_result(response)
            .await
            .expect_err("a failure status is an error"));
    }
    Ok(SwarmLogFrames {
        frames: response.into_frames(),
        decoder: LogDecoder::new(false),
        ready: VecDeque::new(),
    })
}

/// A stream of decoded Swarm log frames.
///
/// The logic is the container slice's, duplicated rather than shared because
/// [`LogFrames`](crate::raw::LogFrames) has no public constructor: it can only
/// be built for `/containers/{id}/logs`, and a Swarm task's container cannot be
/// addressed by that path. The *decoding* is not duplicated — the same
/// [`LogDecoder`] and the same frame rules are used — so the two cannot disagree
/// about what a frame is.
///
/// The framing is always the multiplexed one. A Swarm task's container
/// specification has no TTY option, so a task's output is always framed, and a
/// body that is not framed is reported as an error rather than forwarded as
/// plausible-looking garbage. Because every body here is framed, the
/// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) payload bound applies to
/// every task and service log with no TTY exception: unlike the container slice,
/// there is no unframed body for the bound not to cover.
///
/// Dropping this closes the connection and ends the transfer, which is also how
/// a `follow` stream is cancelled.
pub struct SwarmLogFrames {
    frames: FrameStream,
    decoder: LogDecoder,
    /// Frames a single network read completed beyond the first.
    ///
    /// One read can finish several frames, so the ones already complete are
    /// queued rather than dropped, and a caller sees every frame exactly once
    /// and in order.
    ready: VecDeque<LogFrame>,
}

impl std::fmt::Debug for SwarmLogFrames {
    /// Reports how much is buffered, and no payload.
    ///
    /// The same reasoning as [`LogFrames`](crate::raw::LogFrames), which this
    /// type duplicates: `decoder` holds the bytes of a partly-arrived frame and
    /// `ready` holds completed payloads, and both render in full. A task's
    /// output is whatever the task's image chose to print, so it is counted
    /// rather than shown. The framing is not reported because it is always the
    /// multiplexed one — a task specification has no TTY option.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SwarmLogFrames")
            .field("buffered", &self.decoder.buffered())
            .field("ready_frames", &self.ready.len())
            .finish_non_exhaustive()
    }
}

impl SwarmLogFrames {
    /// Reads the next decoded frame, or `None` at end of stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection fails mid-transfer, when the body is
    /// not valid multiplexed framing, or when the body ends part-way through a
    /// frame — which is how a truncated log would otherwise be
    /// indistinguishable from a short one.
    ///
    /// A frame whose header declares more than
    /// [`MAX_FRAME_BYTES`](crate::raw::MAX_FRAME_BYTES) of payload is refused
    /// here as well, with the same kind and the same cause the container slice
    /// reports: the two use one [`LogDecoder`], so a task log cannot fail for a
    /// reason a container log would not. It is stated on this method rather than
    /// left to be discovered, because a Swarm task has no TTY and so no
    /// unframed fallback to explain a large write — the only reason a real task
    /// can produce such a frame is a task producing a single enormous one.
    ///
    /// Every frame the connection delivered is returned before that error. One
    /// read can complete several frames and then carry one this client refuses,
    /// and the completed ones are handed over first.
    pub async fn next_frame(&mut self) -> Result<Option<LogFrame>, Error> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            if let Some(frame) = self.decoder.decode()? {
                return Ok(Some(frame));
            }
            let Some(data) = self.frames.next_data().await.map_err(Error::from)? else {
                self.decoder.finish()?;
                return Ok(None);
            };
            // `push_read`, not `push`: the transport hands the read over as
            // `Bytes`, and `push` would copy the whole of it before the decoder
            // could take the frames out of it. That copy is a second copy of
            // every byte of a task's output, bought for nothing — the frames
            // come out of the read either way — and a Swarm log is read the same
            // way a container log is, so it should cost the same.
            self.ready.extend(self.decoder.push_read(&data)?);
        }
    }
}

/// Sends a request whose success is a status rather than a document.
///
/// A `200` with an empty body is a success: the Engine answers `POST /swarm/join`,
/// `POST /swarm/leave`, `POST /swarm/unlock`, and every node, config, and secret
/// update with no body at all, and decoding that as a document would turn a
/// successful call into a parse failure.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or when it rejects the
/// request, carrying the status and the daemon's own message.
async fn completed(engine: &RawEngine, request: RawRequest) -> Result<(), Error> {
    let response = engine.send(request).await?;
    let _discarded = engine_result(response).await?;
    Ok(())
}

/// Fixed diagnostic for confidential config and secret mutations.
const RESOURCE_MUTATION_MESSAGE: &str =
    "the config or secret mutation failed; response text is withheld";
/// A propagated deadline marker does not establish which operation timed out.
const RESOURCE_MUTATION_DEADLINE: &str = "a transport deadline was observed; the config or secret mutation outcome is unknown; reconcile before retrying";

/// The fixed deadline diagnostic a withheld node mutation reports.
///
/// A deadline marker does not prove the node mutation itself timed out: a
/// caller-supplied stream factory can propagate an earlier marked error.
const NODE_MUTATION_DEADLINE_MESSAGE: &str = "a transport deadline was observed; the node mutation outcome is unknown; reconcile before retrying";

/// Replaces a transport or body-read failure with fixed, content-free text.
///
/// The kind and safe typed deadline/managed host-key markers survive. Only a
/// locally classified host-key reason or fixed operation-specific text is
/// retained, never a peer-controlled message or the original source chain.
fn withheld_response_error(
    error: &Error,
    message: &'static str,
    deadline_message: &'static str,
) -> Error {
    error.withhold_transport(message, deadline_message)
}

/// Sends a request whose success is a JSON document, withholding all failure
/// text.
///
/// A non-success body is dropped without being read, and its status becomes a
/// fixed-message API error. A transport or body-read failure keeps its kind and
/// a deadline marker, and loses its source chain. A successful body is decoded
/// by [`decode`], whose diagnostic is content-free.
///
/// # Errors
///
/// Returns an error when the request cannot be sent, when the daemon or a proxy
/// rejects it, when the response body cannot be read, or when the success
/// document does not decode.
async fn document_withheld<T>(
    engine: &RawEngine,
    request: RawRequest,
    message: &'static str,
    deadline_message: &'static str,
) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    let response = engine
        .send(request)
        .await
        .map_err(|error| withheld_response_error(&error, message, deadline_message))?;
    let status = response.status;
    if !status.is_success() {
        drop(response);
        return Err(Error::engine_api_withheld(status, message));
    }
    let document = response.document().await.map_err(|error| {
        let error = Error::from(error);
        withheld_response_error(&error, message, deadline_message)
    })?;
    decode(&document)
}

/// Sends a mutation whose success is a status and whose failure text is
/// withheld.
///
/// The response body is never read: a success has no document, and a
/// non-success body is peer-controlled text this operation must not collect.
/// The status is preserved, and the message and source chain are the fixed
/// `message`.
///
/// A transport deadline marker is preserved, but it does not prove this
/// mutation itself timed out: a caller-supplied stream factory can propagate an
/// earlier marked error. The fixed `deadline_message` therefore reports only
/// that a deadline was observed and that the mutation outcome is unknown.
///
/// # Errors
///
/// Returns an error when the request cannot be sent or when the daemon rejects
/// it. The response text never reaches the error.
async fn completed_withheld(
    engine: &RawEngine,
    request: RawRequest,
    message: &'static str,
    deadline_message: &'static str,
) -> Result<(), Error> {
    let response = engine
        .send(request)
        .await
        .map_err(|error| error.withhold_transport(message, deadline_message))?;
    let status = response.status;
    if status.is_success() {
        drop(response);
        return Ok(());
    }
    drop(response);
    Err(Error::engine_api_withheld(status, message))
}

/// Builds the `/{resource}/{reference}{suffix}` path with the reference escaped.
///
/// Returns an error for an empty reference: `/services//start` is not a request
/// for a service, and sending it would ask the daemon about a resource the
/// caller never named.
///
/// The reference is percent-encoded into exactly one segment. An unescaped
/// reference would silently address a *different* resource, because `/` is a
/// path separator: `GET /services/a/b` is a four-segment path, not an inspect of
/// a service named `a/b`.
fn resource_path(resource: &str, reference: &str, suffix: &str) -> Result<String, Error> {
    if reference.is_empty() {
        return Err(Error::invalid_input(format!(
            "the Engine {resource} reference must not be empty"
        )));
    }
    Ok(format!(
        "/{resource}/{}{suffix}",
        escape_path_segment(reference)
    ))
}

/// Percent-encodes one path segment.
///
/// Everything outside the unreserved set `A-Z a-z 0-9 - . _ ~` is encoded, and
/// `%` is encoded too, so a reference that already contains a percent sign
/// cannot smuggle an escape sequence past this function. This is the function
/// `raw::containers` already has; it is spelled again here because that
/// module's copy is private to it, and two copies of a twenty-line encoder is
/// cheaper than a helper neither of those modules can be edited into.
fn escape_path_segment(segment: &str) -> String {
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

/// The service endpoint as the facade models it.
///
/// Modelled rather than kept as an opaque value so a member of the wrong JSON
/// type is rejected here. Every
/// member is optional, and `null` is absent. The original value is still
/// retained whole in the service's `additional` map; this type validates it and
/// projects the published ports.
#[derive(Debug, Deserialize)]
struct ServiceEndpointDocument {
    #[serde(rename = "Spec")]
    _spec: Option<ServiceEndpointSpecDocument>,
    #[serde(rename = "Ports")]
    ports: Option<Vec<ServicePortDocument>>,
    #[serde(rename = "VirtualIPs")]
    _virtual_ips: Option<Vec<ServiceEndpointVirtualIpDocument>>,
}

/// The endpoint specification as the Engine declares it.
#[derive(Debug, Deserialize)]
struct ServiceEndpointSpecDocument {
    #[serde(rename = "Mode")]
    _mode: Option<ServiceEndpointMode>,
    #[serde(rename = "Ports")]
    _ports: Option<Vec<ServicePortDocument>>,
}

/// One endpoint virtual IP as the Engine declares it.
#[derive(Debug, Deserialize)]
struct ServiceEndpointVirtualIpDocument {
    #[serde(rename = "NetworkID")]
    _network_id: Option<String>,
    #[serde(rename = "Addr")]
    _addr: Option<String>,
}

/// One published port as the Engine declares it.
///
/// The integer members are `i64` on the wire and `u32` in the repository model.
/// A value the repository cannot hold makes [`project_ports`] omit the whole
/// projection.
#[derive(Debug, Deserialize)]
struct ServicePortDocument {
    #[serde(rename = "Name")]
    _name: Option<String>,
    #[serde(rename = "Protocol")]
    protocol: Option<ServicePortProtocol>,
    #[serde(rename = "TargetPort")]
    target_port: Option<i64>,
    #[serde(rename = "PublishedPort")]
    published_port: Option<i64>,
    #[serde(rename = "PublishMode")]
    publish_mode: Option<ServicePortPublishMode>,
    /// The endpoint retains every value, including non-string values.
    #[serde(rename = "PublishedIP")]
    published_ip: Option<serde_json::Value>,
}

/// The protocol spellings the Engine accepts for a published port.
#[derive(Clone, Copy, Debug, Deserialize)]
enum ServicePortProtocol {
    #[serde(rename = "")]
    Empty,
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
    #[serde(rename = "sctp")]
    Sctp,
}

impl ServicePortProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        }
    }
}

/// The publish-mode spellings the Engine accepts.
#[derive(Clone, Copy, Debug, Deserialize)]
enum ServicePortPublishMode {
    #[serde(rename = "")]
    Empty,
    #[serde(rename = "ingress")]
    Ingress,
    #[serde(rename = "host")]
    Host,
}

impl ServicePortPublishMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::Ingress => "ingress",
            Self::Host => "host",
        }
    }
}

/// The endpoint resolution modes the Engine accepts.
#[derive(Clone, Copy, Debug, Deserialize)]
enum ServiceEndpointMode {
    #[serde(rename = "")]
    Empty,
    #[serde(rename = "vip")]
    Vip,
    #[serde(rename = "dnsrr")]
    Dnsrr,
}

/// The task counts as the Engine declares them.
///
/// `CompletedTasks` is named only so a wrong-typed value rejects the document,
/// before projection.
#[derive(Debug, Deserialize)]
struct ServiceServiceStatusDocument {
    #[serde(rename = "RunningTasks")]
    running: Option<u64>,
    #[serde(rename = "DesiredTasks")]
    desired: Option<u64>,
    #[serde(rename = "CompletedTasks")]
    _completed: Option<u64>,
}

/// Projects published ports, or nothing when one cannot be represented.
///
/// The whole list is omitted rather than truncated: a caller reading a partial
/// port set would be reading a topology the daemon did not report.
fn project_ports(ports: Vec<ServicePortDocument>) -> Option<Vec<ServicePort>> {
    ports
        .into_iter()
        .map(|port| {
            Some(ServicePort {
                protocol: port.protocol.map(|protocol| protocol.as_str().to_owned()),
                target_port: port.target_port.map(u32::try_from).transpose().ok()?,
                published_port: port.published_port.map(u32::try_from).transpose().ok()?,
                published_ip: port.published_ip.and_then(|ip| match ip {
                    serde_json::Value::String(ip) => Some(ip),
                    _ => None,
                }),
                publish_mode: port.publish_mode.map(|mode| mode.as_str().to_owned()),
            })
        })
        .collect()
}

/// Projects the task counts, or nothing when either is missing.
fn project_status(status: &ServiceServiceStatusDocument) -> Option<ServiceStatus> {
    Some(ServiceStatus {
        running_tasks: status.running?,
        desired_tasks: status.desired?,
    })
}

/// A service as the Engine sends it, in the Engine's spelling.
///
/// `Spec` is decoded into the repository's typed specification, whose flexible
/// members stay as JSON, and `Endpoint` is kept as the daemon's own JSON: the
/// repository service model has no field for the endpoint, and the typed views it
/// does have — the published ports and the task counts — are read out of it. A
/// member of the endpoint that no typed field names, such as a port's `Name`, is
/// therefore still there in `additional["Endpoint"]`.
///
/// `ServiceStatus` is consumed, not retained. Conversion depends on the caller:
/// raw operations preserve their original strict `ServiceStatus` and
/// `Vec<ServicePort>` projections, while facade inspect applies the generated
/// client's nullable endpoint and status rules.
#[derive(Debug, Deserialize)]
struct ServiceDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<ServiceSpecDocumentView>,
    #[serde(rename = "Endpoint")]
    endpoint: Option<serde_json::Value>,
    #[serde(rename = "ServiceStatus")]
    service_status: Option<serde_json::Value>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ServiceDocument> for SwarmService {
    type Error = Error;

    fn try_from(document: ServiceDocument) -> Result<Self, Error> {
        let ports = document
            .endpoint
            .as_ref()
            .and_then(|endpoint| endpoint.get("Ports"))
            .map(decode_value::<Vec<ServicePort>>)
            .transpose()?;
        let status = document
            .service_status
            .as_ref()
            .map(decode_value::<ServiceStatus>)
            .transpose()?;
        let mut additional = document.additional;
        if let Some(endpoint) = document.endpoint {
            additional.insert(String::from("Endpoint"), endpoint);
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec.map(ServiceSpec::try_from).transpose()?,
            ports,
            status,
            additional,
        })
    }
}

impl ServiceDocument {
    /// # Errors
    ///
    /// Returns an error when the service specification, the endpoint, or the
    /// task counts are not the shape the Engine declares — including a member of
    /// the wrong JSON type.
    ///
    /// The two *projections* differ from the wire decode in one direction only.
    /// The published ports become [`SwarmService::ports`] and the task counts
    /// become [`SwarmService::status`] when they can be represented: a `null` or
    /// an absent member yields no projection, an empty port list yields a
    /// projection of zero ports, and an incomplete status yields no status rather
    /// than an invented zero. A value the repository model cannot hold — a port
    /// above `u32::MAX` — omits that projection as well. The endpoint is
    /// retained whole in `additional` either way, so the data is still there for
    /// a caller that looks.
    fn into_facade(self) -> Result<SwarmService, Error> {
        let document = self;
        let mut additional = document.additional;
        let ports = match document.endpoint.as_ref() {
            Some(endpoint) => {
                let endpoint: ServiceEndpointDocument = decode_value(endpoint)?;
                endpoint.ports.and_then(project_ports)
            }
            None => None,
        };
        if let Some(endpoint) = document.endpoint {
            additional.insert(String::from("Endpoint"), endpoint);
        }
        let status = match document.service_status.as_ref() {
            Some(status) => {
                let status: ServiceServiceStatusDocument = decode_value(status)?;
                project_status(&status)
            }
            None => None,
        };
        Ok(SwarmService {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec.map(ServiceSpec::try_from).transpose()?,
            ports,
            status,
            additional,
        })
    }
}

/// A service specification as the Engine sends it.
///
/// The named members are decoded into the repository's own specification, and
/// the members that specification cannot express are retained under the
/// `"<SubObject>.<Member>"` convention the module documentation describes.
#[derive(Debug, Deserialize)]
struct ServiceSpecDocumentView {
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "TaskTemplate")]
    task_template: Option<serde_json::Value>,
    #[serde(rename = "Mode")]
    mode: Option<serde_json::Value>,
    #[serde(rename = "EndpointSpec")]
    endpoint_spec: Option<serde_json::Value>,
    #[serde(rename = "Networks")]
    networks: Option<serde_json::Value>,
    #[serde(rename = "UpdateConfig")]
    update_config: Option<serde_json::Value>,
    #[serde(rename = "RollbackConfig")]
    rollback_config: Option<serde_json::Value>,
    #[serde(rename = "Placement")]
    placement: Option<PlacementDocumentView>,
    #[serde(rename = "RestartPolicy")]
    restart_policy: Option<ServiceRestartPolicy>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ServiceSpecDocumentView> for ServiceSpec {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the restart policy is not the shape the Engine
    /// declares. `ServiceRestartPolicy::condition` is not optional, so a policy
    /// without one is reported instead of being read as a policy that restarts
    /// never.
    fn try_from(document: ServiceSpecDocumentView) -> Result<Self, Error> {
        let mut additional = document.additional;
        let placement = match document.placement {
            Some(placement) => {
                let view = ServicePlacement::from(&placement);
                // A daemon's preferences are objects and a `Vec<String>` cannot
                // hold them, so they are retained verbatim under the key that
                // puts them back where they came from.
                let objects = if placement.preferences_are_objects() {
                    Some(serde_json::Value::Array(placement.preferences))
                } else {
                    None
                };
                let mut retained = placement.additional;
                if let Some(preferences) = objects {
                    retained.insert(String::from("Preferences"), preferences);
                }
                for (member, value) in retained {
                    additional.insert(format!("Placement.{member}"), value);
                }
                Some(view)
            }
            None => None,
        };
        Ok(Self {
            name: document.name,
            labels: document.labels,
            task_template: document.task_template,
            mode: document.mode,
            endpoint_spec: document.endpoint_spec,
            networks: document.networks,
            update_config: document.update_config,
            rollback_config: document.rollback_config,
            placement,
            restart_policy: document.restart_policy,
            additional,
        })
    }
}

/// The `Placement` block as the Engine sends it.
///
/// The preferences are inspected in both spellings they can arrive in, because
/// the two are not interchangeable: a caller writes strings, the Engine sends
/// objects.
#[derive(Debug, Deserialize)]
struct PlacementDocumentView {
    #[serde(default, rename = "Constraints")]
    constraints: Vec<String>,
    #[serde(default, rename = "Preferences")]
    preferences: Vec<serde_json::Value>,
    #[serde(default, rename = "MaxReplicas")]
    max_replicas: u32,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl From<&PlacementDocumentView> for ServicePlacement {
    /// Projects the Engine's placement onto the repository type.
    ///
    /// The members this type cannot express — the Engine's object-form
    /// preferences and `Platforms` — are *not* projected here; the caller that
    /// read them is responsible for retaining them, because only the caller
    /// knows which map they belong beside.
    fn from(view: &PlacementDocumentView) -> Self {
        Self {
            constraints: view.constraints.clone(),
            preferences: view.preference_strings(),
            max_replicas: view.max_replicas,
        }
    }
}

impl PlacementDocumentView {
    /// Returns the preferences a caller could have written.
    ///
    /// A mixed array is treated as the Engine's form: one entry that is an
    /// object means the daemon sent its own `Spread` objects, and guessing which
    /// of the remaining entries were meant to be strings would be inventing a
    /// member.
    fn preference_strings(&self) -> Vec<String> {
        self.preferences
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect()
    }

    /// Returns whether any preference arrived in the Engine's object form.
    fn preferences_are_objects(&self) -> bool {
        self.preferences.iter().any(|value| !value.is_string())
    }
}

/// A node as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct NodeDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<NodeSpec>,
    #[serde(rename = "Status")]
    status: Option<serde_json::Value>,
    #[serde(rename = "Description")]
    description: Option<serde_json::Value>,
    #[serde(rename = "ManagerStatus")]
    manager_status: Option<NodeManagerStatus>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<NodeDocument> for SwarmNode {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the manager status or the node specification is not
    /// the shape the Engine declares. `EngineVersion` is a *view* of
    /// `Description.Engine`, and the description itself is retained whole, so a
    /// member of it that the view does not read is not lost.
    ///
    /// # Raw `EngineVersion` collision caveat
    ///
    /// If the daemon also sends a top-level `EngineVersion` member, the
    /// flattened map keeps it beside the typed view of the nested member. This
    /// is the raw projection's original behavior: serializing such a
    /// [`SwarmNode`] can emit `EngineVersion` twice, and `serde_json::Value`
    /// conversion keeps one of the two. The raw API does not promise
    /// round-trip stability for that document. `DockerClient::list_nodes` and
    /// `DockerClient::inspect_node` refuse it before projection instead of
    /// returning this ambiguous value.
    ///
    /// `ManagerStatus.Addr` and `ManagerStatus.Address` are *synthetic* views of
    /// the nested manager status, added so a caller that reads the raw model has
    /// the dotted spelling the rest of this module uses for a sub-object
    /// member. They are inserted only when the daemon did not send a member
    /// with that exact name at the node's top level; an actual member is never
    /// overwritten by a view of another. That is a deliberate raw compatibility
    /// change: the original projection overwrote the actual member.
    fn try_from(document: NodeDocument) -> Result<Self, Error> {
        let mut additional = document.additional;
        let engine_version = document
            .description
            .as_ref()
            .and_then(|description| description.get("Engine"))
            .and_then(|engine| {
                engine
                    .get("EngineVersion")
                    .or_else(|| engine.get("Version"))
            })
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(description) = document.description {
            additional.insert(String::from("Description"), description);
        }
        if let Some(manager) = &document.manager_status {
            for member in ["Addr", "Address"] {
                if let Some(address) = manager.additional.get(member) {
                    additional
                        .entry(format!("ManagerStatus.{member}"))
                        .or_insert_with(|| address.clone());
                }
            }
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            status: document.status,
            manager_status: document.manager_status,
            engine_version,
            additional,
        })
    }
}

/// A task as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct TaskDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "ServiceID", default)]
    service_id: String,
    #[serde(rename = "Slot", default)]
    slot: i64,
    #[serde(rename = "NodeID", default)]
    node_id: String,
    #[serde(rename = "Status")]
    status: Option<SwarmTaskStatus>,
    #[serde(rename = "DesiredState")]
    desired_state: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<serde_json::Value>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<TaskDocument> for SwarmTask {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the task status is not the shape the Engine
    /// declares. The image is a view of `Spec.ContainerSpec.Image` and the
    /// specification is retained whole beside it, so a member of the container
    /// specification the view does not read is not lost.
    fn try_from(document: TaskDocument) -> Result<Self, Error> {
        if document.additional.contains_key("Image") {
            return Err(Error::serialization_withheld(
                "the Engine task document contains a top-level Image member that the repository view cannot represent unambiguously",
            ));
        }
        let mut additional = document.additional;
        let image = document
            .spec
            .as_ref()
            .and_then(|spec| spec.get("ContainerSpec"))
            .and_then(|container| container.get("Image"))
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if let Some(spec) = document.spec.clone() {
            additional.insert(String::from("Spec"), spec);
        }
        if let Some(status) = &document.status
            && let Some(container) = status.additional.get("ContainerStatus")
        {
            additional.insert(String::from("Status.ContainerStatus"), container.clone());
        }
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            name: document.name,
            labels: document.labels,
            image,
            service_id: document.service_id,
            slot: document.slot,
            node_id: document.node_id,
            status: document.status,
            desired_state: document.desired_state,
            spec: document.spec,
            additional,
        })
    }
}

/// A config as the Engine sends it, in the Engine's spelling.
#[derive(Debug, Deserialize)]
struct ConfigDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<SwarmConfigSpec>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<ConfigDocument> for SwarmConfig {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the config specification is not the shape the
    /// Engine declares. Members this model does not name are retained in
    /// `additional` rather than dropped.
    fn try_from(document: ConfigDocument) -> Result<Self, Error> {
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            additional: document.additional,
        })
    }
}

/// A secret as the Engine sends it, in the Engine's spelling.
#[derive(Deserialize)]
struct SecretDocument {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt")]
    updated_at: Option<String>,
    #[serde(rename = "Spec")]
    spec: Option<SwarmSecretSpec>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for SecretDocument {
    /// Never prints the document.
    ///
    /// The decode carries whatever the peer sent. `Spec.Data` would be retained
    /// by [`SwarmSecretSpec`], and a top-level `additional` value could hold
    /// anything, so this rendering reports identity lengths and counts only.
    /// The public value's `Debug` is hand-written for the same reason; this one
    /// is here so a future test or panic message cannot reach the raw map.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let additional = format_args!("{} unmodeled member(s)", self.additional.len());
        formatter
            .debug_struct("SecretDocument")
            .field("id", &self.id.as_ref().map(String::len))
            .field("version", &self.version)
            .field("created_at", &self.created_at.as_ref().map(String::len))
            .field("updated_at", &self.updated_at.as_ref().map(String::len))
            .field("spec", &self.spec)
            .field("additional", &additional)
            .finish_non_exhaustive()
    }
}

impl TryFrom<SecretDocument> for SwarmSecret {
    type Error = Error;

    /// # Errors
    ///
    /// Returns an error when the secret specification is not the shape the
    /// Engine declares. Members this model does not name are retained in
    /// `additional` rather than dropped.
    fn try_from(document: SecretDocument) -> Result<Self, Error> {
        Ok(Self {
            id: document.id,
            version: document.version,
            created_at: document.created_at,
            updated_at: document.updated_at,
            spec: document.spec,
            additional: document.additional,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE};

    use crate::raw::{Duplex, RawBody, RawEngine, RawTarget, RegistryAuth, StreamFactory, decode};
    use crate::swarm::{SwarmSecretData, SwarmUnlockOptions};
    use crate::{
        ApiVersion, ConfigCreateOptions, Error, ErrorKind, NodeRemoveOptions, NodeSpec,
        NodeUpdateOptions, RegistryCredentials, SecretCreateOptions, SecretUpdateOptions,
        ServiceCreateResult, ServicePlacement, ServiceRestartPolicy, ServiceSpec, ServiceStatus,
        ServiceUpdateOptions, ServiceUpdateResult, SwarmConfig, SwarmConfigSpec, SwarmInfo,
        SwarmInitOptions, SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions,
        SwarmListOptions, SwarmLogOptions, SwarmNode, SwarmSecret, SwarmSecretSpec, SwarmService,
        SwarmSpec, SwarmTask, SwarmUpdateOptions, SwarmVersion,
    };

    use super::{
        ConfigDocument, NODE_DUPLICATE_KEY_MESSAGE, NodeDocument, SecretDocument,
        ServiceCreateDocument, ServiceDocument, ServiceSpecDocumentView, ServiceUpdateDocument,
        TaskDocument, config_create_request, config_list_request, config_update_request,
        decode_value, escape_path_segment, init_request, join_request, leave_request,
        node_inspect_request, node_list_request, node_remove_request, node_update_request,
        reject_service_spec_body_collisions, resource_path, secret_create_request,
        secret_list_request, secret_update_request, service_create_request,
        service_inspect_request, service_list_request, service_log_request, service_remove_request,
        service_spec_body, service_update_request, swarm_inspect_request, swarm_unlock_request,
        task_inspect_request, task_list_request, task_log_request, update_request,
        validate_node_document_keys, validate_schema_value,
    };

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    /// The Swarm documents this repository keeps as fixtures.
    const SERVICE: &str = include_str!("../../tests/fixtures/docker/engine/swarm/service.json");
    const SERVICES: &str = include_str!("../../tests/fixtures/docker/engine/swarm/services.json");
    const NODE: &str = include_str!("../../tests/fixtures/docker/engine/swarm/node.json");
    const NODES: &str = include_str!("../../tests/fixtures/docker/engine/swarm/nodes.json");
    const TASK: &str = include_str!("../../tests/fixtures/docker/engine/swarm/task.json");
    const TASKS: &str = include_str!("../../tests/fixtures/docker/engine/swarm/tasks.json");
    const CONFIG: &str = include_str!("../../tests/fixtures/docker/engine/swarm/config.json");
    const CONFIGS: &str = include_str!("../../tests/fixtures/docker/engine/swarm/configs.json");
    const SECRET: &str = include_str!("../../tests/fixtures/docker/engine/swarm/secret.json");
    const SECRETS: &str = include_str!("../../tests/fixtures/docker/engine/swarm/secrets.json");
    const SWARM: &str = include_str!("../../tests/fixtures/docker/engine/swarm/inspect.json");

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

    /// Decodes every entry of a Swarm list fixture and projects it.
    fn project<T, D>(document: &str) -> Vec<T>
    where
        T: TryFrom<D, Error = Error>,
        D: for<'de> serde::Deserialize<'de>,
    {
        decode::<Vec<D>>(document.as_bytes())
            .expect("a list document")
            .into_iter()
            .map(T::try_from)
            .collect::<Result<Vec<_>, _>>()
            .expect("every entry converts")
    }

    /// A service specification with every member the type names, and one it does
    /// not.
    ///
    /// A projection that quietly forgets a member shows up in the assertions that
    /// follow, so the fixture is deliberately exhaustive.
    #[test]
    fn service_body_validation_descends_structs_but_preserves_map_keys() {
        let valid = serde_json::json!({
            "TaskTemplate": {
                "ContainerSpec": {
                    "ReadOnly": true,
                    "Labels": {"ReadOnly": "user-defined", "readonly": "also-user-defined", " arbitrary/µ ": "ok"},
                    "Sysctls": {"net.example/µ": "1"},
                    "Privileges": {"Seccomp": {"Mode": "profile", "Profile": [0, 1, 255]}},
                    "DNSConfig": {"Nameservers": ["::1", ""]},
                    "Mounts": [{"ReadOnly": true}]
                },
                "LogDriver": {"Name": "json-file", "Options": {"Mode": "a", "mode": "b", "µ": "x"}},
                "Resources": {
                    "Limits": {"NanoCPUs": 2},
                    "Reservations": {"GenericResources": [{"NamedResourceSpec": {"Kind": "gpu", "Value": "0"}}]}
                },
                "Placement": {"Preferences": [{"Spread": {"SpreadDescriptor": "zone"}}]}
            },
            "Networks": [{"DriverOpts": {"Mode": "a", "mode": "b", "net/µ": "c"}}],
            "Mode": {"ReplicatedJob": {"MaxConcurrent": 2}},
            "EndpointSpec": {"Ports": [{"TargetPort": 80, "PublishedPort": 8080}]}
        });
        assert!(reject_service_spec_body_collisions(&valid).is_ok());

        for invalid in [
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"ReadOnly":true,"readonly":false}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Mounts":[{"ReadOnly":true,"readonly":false}]}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Mounts":[{"ReadOnly":true,"RеadOnly":false}]}}}),
            serde_json::json!({"TaskTemplate":{"Networks":[{"Target":"a","target":"b"}]}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Privileges":{"Seccomp":{"Profile":[-1]}}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Privileges":{"Seccomp":{"Profile":{"nested":true}}}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"ReadOnly":{"nested":true}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Labels":[{"not":"map"}]}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Labels":{"nested":{"not":"scalar"}}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Sysctls":{"net.example":true}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"DNSConfig":{"Nameservers":["not-an-ip"]}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Mystery":{"x":1}}}}),
            serde_json::json!({"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Mystery":{}}]}}}),
        ] {
            assert!(reject_service_spec_body_collisions(&invalid).is_err());
        }
        let alias = serde_json::json!({"tasktemplate":{"containerspec":{"Readonly":true,"readonly":false}}});
        assert!(reject_service_spec_body_collisions(&alias).is_err());
        assert!(validate_schema_value(&serde_json::json!({}), "UnclassifiedSchema").is_err());
        assert!(validate_schema_value(&serde_json::json!([{}]), "[TaskSpec").is_err());
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":"AA=="}}),
                "Privileges"
            )
            .is_ok()
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":"A\r\nA=="}}),
                "Privileges"
            )
            .is_ok()
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":"/x=="}}),
                "Privileges"
            )
            .is_ok(),
            "Go encoding/json accepts non-zero trailing base64 bits"
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":[0,null,255]}}),
                "Privileges"
            )
            .is_ok()
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":"not-base64"}}),
                "Privileges"
            )
            .is_err()
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":"A==="}}),
                "Privileges"
            )
            .is_err(),
            "malformed padding remains invalid"
        );
        assert!(
            validate_schema_value(
                &serde_json::json!({"Seccomp":{"Profile":[0,256]}}),
                "Privileges"
            )
            .is_err()
        );
    }

    fn complete_spec() -> ServiceSpec {
        ServiceSpec {
            name: Some("web".to_owned()),
            labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
            task_template: Some(serde_json::json!({
                "ContainerSpec": {"Image": "nginx:alpine"},
            })),
            mode: Some(serde_json::json!({"Replicated": {"Replicas": 2}})),
            endpoint_spec: Some(serde_json::json!({"Mode": "vip"})),
            networks: Some(serde_json::json!([{"Target": "net"}])),
            update_config: Some(serde_json::json!({"Parallelism": 1})),
            rollback_config: Some(serde_json::json!({"Parallelism": 1})),
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                preferences: vec!["spread=node.labels.zone".to_owned()],
                max_replicas: 2,
            }),
            restart_policy: Some(ServiceRestartPolicy {
                condition: String::from("on-failure"),
                delay: Some(5_000_000_000),
                max_attempts: Some(3),
                window: Some(120_000_000_000),
                failure_action: Some(String::from("pause")),
            }),
            additional: BTreeMap::from([(String::from("UnknownMember"), serde_json::json!(true))]),
        }
    }

    #[test]
    fn a_wrong_typed_member_does_not_echo_its_value() {
        #[derive(Debug, serde::Deserialize)]
        struct Probe {
            #[serde(rename = "Created")]
            _created: i64,
        }

        let error = decode_value::<Probe>(&serde_json::json!({
            "Created": "canary-proxy-swarm-credential"
        }))
        .expect_err("a wrong-typed member must be an error");
        let rendered = format!("{error} {error:?}");
        assert!(
            !rendered.contains("canary-proxy-swarm-credential"),
            "{rendered}"
        );
        assert!(error.to_string().contains("data error"), "{error}");
        assert!(error.to_string().contains("line"), "{error}");
        assert!(error.to_string().contains("column"), "{error}");
    }

    #[test]
    fn a_service_create_body_carries_placement_and_restart_policy() {
        // This is the whole reason the owned backend exists. The generated
        // `ServiceSpec` in the pinned dependency has neither member, so a
        // specification that names them cannot be sent through it at all; here
        // they are on the wire.
        let body = service_spec_body(&complete_spec()).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Constraints"][0], "node.role == worker",
            "the constraint must reach the daemon: {body}"
        );
        assert_eq!(body["TaskTemplate"]["Placement"]["MaxReplicas"], 2);
        assert!(
            body.get("Placement").is_none(),
            "the top-level spelling must not also go on the wire: {body}"
        );
        // `RestartPolicy` lives inside `TaskTemplate`, and the assertion says so:
        // the top-level spelling is where an inspect *reports* the policy, and a
        // create request that carries it there is silently ignored by the daemon.
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Condition"],
            "on-failure"
        );
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Delay"],
            5_000_000_000i64
        );
        assert_eq!(body["TaskTemplate"]["RestartPolicy"]["MaxAttempts"], 3);
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["Window"],
            120_000_000_000i64
        );
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"]["FailureAction"],
            "pause"
        );
        assert!(
            body.get("RestartPolicy").is_none(),
            "the top-level spelling must not also go on the wire: {body}"
        );
    }

    /// A member addressed by two case spellings is refused before a request.
    ///
    /// The Engine folds JSON member names, so `placement` and `Placement` are
    /// the same member to the daemon and the winner depends on the encoded
    /// order. This writer must not choose between them, and must not let a
    /// typed value and an `additional` or `task_template` variant reach the
    /// socket as two keys.
    #[test]
    fn a_service_spec_case_collision_is_refused_before_a_request() {
        let placement = ServicePlacement {
            constraints: vec!["node.role == worker".to_owned()],
            ..ServicePlacement::default()
        };
        let policy = ServiceRestartPolicy {
            condition: "on-failure".to_owned(),
            ..ServiceRestartPolicy::default()
        };
        let mut typed_labels = ServiceSpec {
            labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
            ..ServiceSpec::default()
        };
        typed_labels
            .additional
            .insert("labels".to_owned(), serde_json::json!({"tier": "other"}));
        let mut duplicate_keys = ServiceSpec::default();
        duplicate_keys
            .additional
            .insert("Unmodelled".to_owned(), serde_json::json!(1));
        duplicate_keys
            .additional
            .insert("unmodelled".to_owned(), serde_json::json!(2));
        let cases = [
            (
                "a typed placement beside a lower-case template member",
                ServiceSpec {
                    placement: Some(placement.clone()),
                    task_template: Some(serde_json::json!({
                        "placement": {"Constraints": []}
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a typed restart policy beside a lower-case template member",
                ServiceSpec {
                    restart_policy: Some(policy),
                    task_template: Some(serde_json::json!({
                        "restartpolicy": {"Condition": "any"}
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a typed task template beside a lower-case additional key",
                ServiceSpec {
                    task_template: Some(serde_json::json!({"ContainerSpec": {}})),
                    additional: BTreeMap::from([(
                        "tasktemplate".to_owned(),
                        serde_json::json!({"ContainerSpec": {}}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a typed label map beside a lower-case additional key",
                typed_labels,
            ),
            ("two case spellings of one additional key", duplicate_keys),
        ];
        for (what, spec) in cases {
            let error = service_create_request(&spec).expect_err(what);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
            assert!(
                error.to_string().contains("case spelling")
                    || error.to_string().contains("case-insensitively"),
                "{what}: the refusal did not name the fold: {error}"
            );
        }
    }

    /// A dotted member that is a case variant of a modeled nested member is
    /// refused before a request.
    ///
    /// The dotted convention is the one place this writer merges a key into a
    /// sub-object. An exact modeled name is the caller's choice; a case variant
    /// would be written as a second member or as an unknown one the Engine
    /// folds onto the modeled member.
    #[test]
    fn a_dotted_service_spec_case_variant_is_refused_before_a_request() {
        let cases = [
            (
                "a lower-case dotted placement parent",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "placement.Platforms".to_owned(),
                        serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a lower-case dotted task-template member",
                ServiceSpec {
                    task_template: Some(serde_json::json!({"ContainerSpec": {}})),
                    additional: BTreeMap::from([(
                        "TaskTemplate.placement".to_owned(),
                        serde_json::json!({"Constraints": []}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a lower-case dotted Mode member",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "Mode.replicated".to_owned(),
                        serde_json::json!({"Replicas": 1}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a lower-case dotted EndpointSpec member",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "EndpointSpec.ports".to_owned(),
                        serde_json::json!([]),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a lower-case dotted UpdateConfig member",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "UpdateConfig.parallelism".to_owned(),
                        serde_json::json!(1),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
        ];
        for (what, spec) in cases {
            let error = service_create_request(&spec).expect_err(what);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
            assert!(
                error.to_string().contains("case spelling")
                    || error.to_string().contains("case-insensitively"),
                "{what}: the refusal did not name the fold: {error}"
            );
        }
    }

    /// A non-ASCII key on a modeled merge surface is refused.
    ///
    /// Go's field matching uses Unicode folding, and this writer does not
    /// reproduce a daemon's fold table, so `Labelſ` cannot be proven to be an
    /// unknown key rather than a spelling of `Labels`.
    #[test]
    fn a_non_ascii_service_spec_key_is_refused_before_a_request() {
        for key in ["Labelſ", "labelſ", "Naïve", "Placement.Ünicode"] {
            let mut spec = ServiceSpec::default();
            spec.additional
                .insert(key.to_owned(), serde_json::json!({"kept": true}));
            let error = service_create_request(&spec).expect_err(key);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key}: {error}");
            assert!(
                error.to_string().contains("non-ASCII"),
                "{key}: the refusal did not name the restriction: {error}"
            );
            assert!(
                !format!("{error} {error:?}").contains(key),
                "{key}: the refusal echoed the key"
            );
        }
    }

    /// A case fold inside a typed root object or a nested placement/restart
    /// object is caught after the merge, before a request.
    #[test]
    fn a_case_fold_inside_a_modeled_object_is_refused_after_the_merge() {
        let cases = [
            (
                "two spellings inside Mode",
                ServiceSpec {
                    mode: Some(serde_json::json!({
                        "Replicated": {"Replicas": 1},
                        "replicated": {"Replicas": 2}
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "two spellings inside Placement",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "Placement": {
                            "Constraints": [],
                            "constraints": []
                        }
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "two spellings inside RestartPolicy",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "RestartPolicy": {
                            "Condition": "any",
                            "condition": "none"
                        }
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "two spellings inside an EndpointSpec port",
                ServiceSpec {
                    endpoint_spec: Some(serde_json::json!({
                        "Ports": [{"TargetPort": 80, "targetport": 81}]
                    })),
                    ..ServiceSpec::default()
                },
            ),
            (
                "two spellings inside a Networks entry",
                ServiceSpec {
                    networks: Some(serde_json::json!([
                        {"Target": "net-a", "target": "net-b"}
                    ])),
                    ..ServiceSpec::default()
                },
            ),
        ];
        for (what, spec) in cases {
            let error = service_create_request(&spec).expect_err(what);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
            assert!(
                error.to_string().contains("case spelling")
                    || error.to_string().contains("case-insensitively"),
                "{what}: the refusal did not name the fold: {error}"
            );
        }
    }

    /// Legitimate unknown members and service-defined non-ASCII keys still
    /// build a request.
    #[test]
    fn legitimate_unknowns_and_non_ascii_map_keys_still_build() {
        let mut spec = ServiceSpec {
            labels: Some(BTreeMap::from([("naïve".to_owned(), "value".to_owned())])),
            task_template: Some(serde_json::json!({
                "ContainerSpec": {
                    "Image": "nginx:alpine",
                    "Labels": {"ключ": "значение"}
                },
                "UnmodelledTaskMember": true
            })),
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                ..ServicePlacement::default()
            }),
            endpoint_spec: Some(serde_json::json!({
                "Ports": [{"TargetPort": 80, "PublishedPort": 8080}]
            })),
            networks: Some(serde_json::json!([{"Target": "net-a"}])),
            ..ServiceSpec::default()
        };
        spec.additional
            .insert("UnmodelledRoot".to_owned(), serde_json::json!(true));
        spec.additional.insert(
            "Placement.Platforms".to_owned(),
            serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
        );
        spec.additional
            .insert("unmodelledlower".to_owned(), serde_json::json!(true));

        let request = service_create_request(&spec).expect("the specification is allowed");
        let body = request_body(&request);
        assert_eq!(body["Labels"]["naïve"], "value");
        assert_eq!(
            body["TaskTemplate"]["ContainerSpec"]["Labels"]["ключ"],
            "значение"
        );
        assert_eq!(body["TaskTemplate"]["UnmodelledTaskMember"], true);
        assert_eq!(body["UnmodelledRoot"], true);
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Platforms"][0]["Architecture"],
            "amd64"
        );
        assert_eq!(body["unmodelledlower"], true);
    }

    #[test]
    fn the_owned_body_keeps_every_member_the_typed_specification_names() {
        // A projection that dropped a member would be a silent request for less
        // than the caller asked for, so the typed body is compared member for
        // member against a plain serialization of the same specification. The
        // one expected difference is `Placement.Preferences`, which the Engine
        // spells as objects.
        let spec = complete_spec();
        let typed = serde_json::to_value(&spec).expect("the specification encodes");
        let body = service_spec_body(&spec).expect("an encodable specification");
        for member in [
            "Name",
            "Labels",
            "Mode",
            "EndpointSpec",
            "Networks",
            "UpdateConfig",
            "RollbackConfig",
        ] {
            assert_eq!(body[member], typed[member], "{member} must survive");
        }
        // `Placement` is compared apart from its preferences, which the
        // projection rewrites into the Engine's object form because a Compose
        // `deploy:` block writes strings and the Engine declares objects. That
        // rewrite has its own test below.
        // `Placement` moves into `TaskTemplate` like the restart policy, and its
        // preferences are rewritten into the Engine's object form. The comparison
        // is made where the value actually lands.
        let mut expected_placement = typed["Placement"].clone();
        expected_placement["Preferences"] =
            body["TaskTemplate"]["Placement"]["Preferences"].clone();
        assert_eq!(body["TaskTemplate"]["Placement"], expected_placement);
        // `TaskTemplate` is compared apart from the restart policy, which is the
        // one member the projection *adds* to it — see below.
        // Two members are *moved* into the task template rather than copied, and
        // both are compared where they land rather than exempted from the
        // comparison.
        let mut expected_template = typed["TaskTemplate"].clone();
        expected_template["RestartPolicy"] = typed["RestartPolicy"].clone();
        let mut moved_placement = typed["Placement"].clone();
        moved_placement["Preferences"] = body["TaskTemplate"]["Placement"]["Preferences"].clone();
        expected_template["Placement"] = moved_placement;
        assert_eq!(
            body["TaskTemplate"], expected_template,
            "TaskTemplate must survive with the restart policy and the placement added to \
             it"
        );
        // `RestartPolicy` is the one member that is *moved* rather than copied:
        // the typed specification carries it at the top level because that is
        // where an inspect reports it, and the create request wants it inside
        // `TaskTemplate`. Every other member must be identical, and this one
        // must be identical once relocated — so the two are compared after the
        // move rather than exempted from the comparison.
        assert_eq!(
            body["TaskTemplate"]["RestartPolicy"], typed["RestartPolicy"],
            "the restart policy must survive the move into the task template"
        );
        assert_eq!(body["UnknownMember"], true);
        assert_eq!(
            typed["Placement"]["Preferences"][0],
            "spread=node.labels.zone"
        );
    }

    #[test]
    fn placement_preferences_are_sent_in_the_shape_the_engine_declares() {
        // The Engine's `Placement.Preferences` is a list of objects. A list of
        // strings is a body it cannot decode, and a Compose `deploy:` block
        // writes strings, so the conversion has to happen here or a working
        // stack file stops deploying.
        let body = service_spec_body(&complete_spec()).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
    }

    #[test]
    fn a_preference_the_engine_would_reject_is_refused_before_the_socket() {
        for rejected in ["node.labels.zone", "spread=", "spread", "", "SPREAD=x"] {
            let spec = ServiceSpec {
                placement: Some(ServicePlacement {
                    preferences: vec![rejected.to_owned()],
                    ..ServicePlacement::default()
                }),
                ..ServiceSpec::default()
            };
            let error = service_spec_body(&spec).expect_err("an untranslatable preference");
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{rejected}");
        }
    }

    #[test]
    fn an_unrepresentable_placement_member_survives_a_round_trip_through_the_daemon() {
        // `Platforms` has no field on the repository type and the Engine's
        // preferences are objects, so an answer carrying them keeps both — and a
        // specification read back from an inspect re-sends them inside
        // `Placement`, where the Engine reads them, rather than under a name the
        // Engine would ignore.
        let document: ServiceSpecDocumentView = decode(
            br#"{"Name":"web","Placement":{"Constraints":["node.role == worker"],
                "Platforms":[{"Architecture":"amd64","OS":"linux"}],
                "Preferences":[{"Spread":{"SpreadDescriptor":"node.labels.zone"}}],
                "MaxReplicas":2}}"#,
        )
        .expect("a service specification");
        let spec = ServiceSpec::try_from(document).expect("it converts");
        let placement = spec.placement.as_ref().expect("a placement");
        assert_eq!(
            placement.constraints,
            vec!["node.role == worker".to_owned()]
        );
        assert_eq!(placement.max_replicas, 2);
        // The daemon's preferences are objects, so they are kept verbatim rather
        // than forced into the string list a caller writes.
        assert!(
            placement.preferences.is_empty(),
            "expected placement.preferences to be empty"
        );
        assert_eq!(
            spec.additional["Placement.Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
        assert_eq!(
            spec.additional["Placement.Platforms"][0]["Architecture"],
            "amd64"
        );

        let body = service_spec_body(&spec).expect("it encodes again");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Platforms"][0]["OS"],
            "linux"
        );
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.zone"
        );
        // A dotted key is a retention convention, not an Engine member name, so
        // it must never reach the wire as one.
        assert!(
            body.get("Placement.Platforms").is_none()
                && body.get("Placement.Preferences").is_none(),
            "{body}"
        );
    }

    #[test]
    fn the_placement_block_is_exactly_the_shape_the_engine_declares() {
        // The whole block, asserted at once. A member spelled wrongly here is
        // not a decode failure: the Engine ignores a member it does not know, so
        // a wrong spelling is a service that schedules somewhere the caller did
        // not ask for.
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                preferences: vec!["spread=node.labels.zone".to_owned()],
                max_replicas: 1,
            }),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"],
            serde_json::json!({
                "Constraints": ["node.role == worker"],
                "Preferences": [
                    {"Spread": {"SpreadDescriptor": "node.labels.zone"}},
                ],
                "MaxReplicas": 1,
            })
        );
    }

    #[test]
    fn a_spread_descriptor_keeps_the_expression_the_caller_wrote() {
        // Only the leading `spread=` is consumed. A descriptor is a label
        // expression and routinely contains dots, dashes, and further separators;
        // rewriting any of them would spread across a different set of nodes.
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                preferences: vec!["spread=node.labels.tier-web".to_owned()],
                ..ServicePlacement::default()
            }),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("an encodable specification");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Preferences"][0]["Spread"]["SpreadDescriptor"],
            "node.labels.tier-web"
        );
    }

    #[test]
    fn an_additional_task_template_is_resolved_before_typed_and_dotted_members() {
        // The non-dotted `additional` task template is the only whole template,
        // and the typed placement and dotted `Placement.Platforms` must be merged
        // into *that* object rather than being discarded by map order.
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                ..ServicePlacement::default()
            }),
            additional: BTreeMap::from([
                (
                    "TaskTemplate".to_owned(),
                    serde_json::json!({
                        "ContainerSpec": {"Image": "from-additional"},
                        "UnmodelledTaskMember": 1
                    }),
                ),
                (
                    "Placement.Platforms".to_owned(),
                    serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
                ),
            ]),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("an encodable specification");
        assert_eq!(
            body,
            serde_json::json!({
                "TaskTemplate": {
                    "ContainerSpec": {"Image": "from-additional"},
                    "UnmodelledTaskMember": 1,
                    "Placement": {
                        "Constraints": ["node.role == worker"],
                        "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
                    }
                }
            }),
            "the resolved task template changed: {body}"
        );
    }

    #[test]
    fn conflicting_typed_and_dotted_placement_members_are_refused_without_echoing() {
        let canary = "canary-typed-dotted-placement-6b2f";
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec![canary.to_owned()],
                ..ServicePlacement::default()
            }),
            additional: BTreeMap::from([(
                "Placement.Constraints".to_owned(),
                serde_json::json!([format!("{canary}-dotted")]),
            )]),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("two placement representations");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(message.contains("placement"), "{message}");
        assert!(message.contains("more than one"), "{message}");
        assert!(!message.contains(canary));
        let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(item) = chain {
            for rendered in [format!("{item}"), format!("{item:?}")] {
                assert!(!rendered.contains(canary), "leak: {rendered}");
            }
            chain = item.source();
        }
    }

    #[test]
    fn conflicting_typed_and_dotted_restart_policy_members_are_refused_without_echoing() {
        let canary = "canary-typed-dotted-restart-2d7a";
        let spec = ServiceSpec {
            restart_policy: Some(ServiceRestartPolicy {
                condition: canary.to_owned(),
                ..ServiceRestartPolicy::default()
            }),
            additional: BTreeMap::from([(
                "RestartPolicy.Condition".to_owned(),
                serde_json::json!(format!("{canary}-dotted")),
            )]),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("two restart-policy representations");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(message.contains("restart policy"), "{message}");
        assert!(message.contains("more than one"), "{message}");
        assert!(!message.contains(canary));
        let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(item) = chain {
            for rendered in [format!("{item}"), format!("{item:?}")] {
                assert!(!rendered.contains(canary), "leak: {rendered}");
            }
            chain = item.source();
        }
    }

    #[test]
    fn a_whole_object_task_template_placement_is_resolved_before_its_dotted_member() {
        // The map is ordered, and `Placement.Platforms` sorts before
        // `TaskTemplate.Placement`. With the current conflict checks, removing
        // the depth sort would reject the second key as a duplicate placement
        // representation rather than replace the merged object. The exact body
        // pins the allowed merge; no mutation is executed here.
        let spec = ServiceSpec {
            additional: BTreeMap::from([
                (
                    "Placement.Platforms".to_owned(),
                    serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
                ),
                (
                    "TaskTemplate.Placement".to_owned(),
                    serde_json::json!({
                        "Constraints": ["node.role == worker"],
                        "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}]
                    }),
                ),
            ]),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("a mergeable specification");
        assert_eq!(
            body,
            serde_json::json!({
                "TaskTemplate": {
                    "Placement": {
                        "Constraints": ["node.role == worker"],
                        "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}],
                        "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
                    }
                }
            }),
            "the whole-object placement and its dotted member did not merge: {body}"
        );
    }

    #[test]
    fn a_typed_and_additional_task_template_are_refused_together() {
        let spec = ServiceSpec {
            task_template: Some(serde_json::json!({"ContainerSpec": {"Image": "typed"}})),
            additional: BTreeMap::from([(
                "TaskTemplate".to_owned(),
                serde_json::json!({"ContainerSpec": {"Image": "additional"}}),
            )]),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("two task-template representations");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("task_template"));
        assert!(error.to_string().contains("one representation"));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one table of duplicate-representation cases"
    )]
    fn duplicate_representation_cases() -> Vec<(&'static str, ServiceSpec)> {
        vec![
            (
                "the whole-object key repeats TaskTemplate.Placement",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "Placement": {"Constraints": ["node.role == worker"]}
                    })),
                    additional: BTreeMap::from([(
                        "TaskTemplate.Placement".to_owned(),
                        serde_json::json!({"Constraints": ["node.labels.zone == east"]}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a dotted member repeats one in the whole object",
                ServiceSpec {
                    additional: BTreeMap::from([
                        (
                            "TaskTemplate.Placement".to_owned(),
                            serde_json::json!({
                                "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
                            }),
                        ),
                        (
                            "Placement.Platforms".to_owned(),
                            serde_json::json!([{"Architecture": "arm64", "OS": "linux"}]),
                        ),
                    ]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "the typed placement repeats a TaskTemplate placement",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "Placement": {"Constraints": ["node.role == worker"]}
                    })),
                    placement: Some(ServicePlacement {
                        constraints: vec!["node.labels.zone == east".to_owned()],
                        ..ServicePlacement::default()
                    }),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a scalar TaskTemplate cannot receive a dotted member",
                ServiceSpec {
                    additional: BTreeMap::from([
                        (
                            "TaskTemplate".to_owned(),
                            serde_json::json!("not-an-object"),
                        ),
                        (
                            "Placement.Platforms".to_owned(),
                            serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
                        ),
                    ]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "the whole-object key repeats TaskTemplate.RestartPolicy",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "RestartPolicy": {"Condition": "on-failure"}
                    })),
                    additional: BTreeMap::from([(
                        "TaskTemplate.RestartPolicy".to_owned(),
                        serde_json::json!({"Condition": "any"}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a dotted restart member repeats one in the whole object",
                ServiceSpec {
                    additional: BTreeMap::from([
                        (
                            "TaskTemplate.RestartPolicy".to_owned(),
                            serde_json::json!({"Window": 20_000_000_000_i64}),
                        ),
                        (
                            "RestartPolicy.Window".to_owned(),
                            serde_json::json!(10_000_000_000_i64),
                        ),
                    ]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "the typed restart policy repeats a TaskTemplate policy",
                ServiceSpec {
                    task_template: Some(serde_json::json!({
                        "RestartPolicy": {"Condition": "on-failure"}
                    })),
                    restart_policy: Some(ServiceRestartPolicy {
                        condition: "any".to_owned(),
                        ..ServiceRestartPolicy::default()
                    }),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a scalar TaskTemplate restart policy cannot receive a dotted member",
                ServiceSpec {
                    additional: BTreeMap::from([
                        (
                            "TaskTemplate.RestartPolicy".to_owned(),
                            serde_json::json!("not-an-object"),
                        ),
                        (
                            "RestartPolicy.Window".to_owned(),
                            serde_json::json!(20_000_000_000_i64),
                        ),
                    ]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a dotted top-level member repeats a typed object member",
                ServiceSpec {
                    mode: Some(serde_json::json!({"Replicated": {"Replicas": 3}})),
                    additional: BTreeMap::from([(
                        "Mode.Replicated".to_owned(),
                        serde_json::json!({"Replicas": 5}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a scalar TaskTemplate placement cannot receive a dotted member",
                ServiceSpec {
                    additional: BTreeMap::from([
                        (
                            "TaskTemplate.Placement".to_owned(),
                            serde_json::json!("not-an-object"),
                        ),
                        (
                            "Placement.Platforms".to_owned(),
                            serde_json::json!([{"Architecture": "amd64", "OS": "linux"}]),
                        ),
                    ]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a top-level Placement additional entry",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "Placement".to_owned(),
                        serde_json::json!({"Constraints": ["node.role == worker"]}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
            (
                "a top-level RestartPolicy additional entry",
                ServiceSpec {
                    additional: BTreeMap::from([(
                        "RestartPolicy".to_owned(),
                        serde_json::json!({"Condition": "on-failure"}),
                    )]),
                    ..ServiceSpec::default()
                },
            ),
        ]
    }

    #[test]
    fn a_supported_top_level_dotted_member_still_merges_into_its_object() {
        // Pre-existing raw behavior: `Mode.Replicated` is an explicit convention
        // merge, not an inspected literal. The facade refuses every dotted key,
        // so this path is reached only by a caller choosing the raw writer.
        let spec = ServiceSpec {
            mode: Some(serde_json::json!({"Global": {}})),
            additional: BTreeMap::from([(
                "Mode.Replicated".to_owned(),
                serde_json::json!({"Replicas": 3}),
            )]),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("a mergeable specification");
        assert_eq!(
            body["Mode"],
            serde_json::json!({"Global": {}, "Replicated": {"Replicas": 3}})
        );
    }

    #[test]
    fn a_whole_object_task_template_restart_policy_is_resolved_before_its_dotted_member() {
        // The RestartPolicy analogue of the Placement ordering test. With the
        // current conflict checks, removing the depth sort would reject the
        // second key as a duplicate restart-policy representation rather than
        // overwrite the merged `Window`. The exact body pins the allowed merge;
        // no mutation is executed here.
        let spec = ServiceSpec {
            additional: BTreeMap::from([
                (
                    "RestartPolicy.Window".to_owned(),
                    serde_json::json!(20_000_000_000_i64),
                ),
                (
                    "TaskTemplate.RestartPolicy".to_owned(),
                    serde_json::json!({
                        "Condition": "on-failure",
                        "MaxAttempts": 3
                    }),
                ),
            ]),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("a mergeable specification");
        assert_eq!(
            body,
            serde_json::json!({
                "TaskTemplate": {
                    "RestartPolicy": {
                        "Condition": "on-failure",
                        "MaxAttempts": 3,
                        "Window": 20_000_000_000_i64
                    }
                }
            }),
            "the whole-object restart policy and its dotted member did not merge: {body}"
        );
    }

    #[test]
    fn a_dotted_member_cannot_replace_a_member_already_in_the_resolved_object() {
        let cases = duplicate_representation_cases();
        for (what, spec) in cases {
            let error = service_spec_body(&spec).expect_err(what);
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "{what}: {error}");
            assert!(
                error.to_string().contains("more than one")
                    || error.to_string().contains("not a JSON object")
                    || error.to_string().contains("already supplied"),
                "{what}: the refusal is not actionable: {error}"
            );
        }
    }

    #[test]
    fn the_raw_writer_keeps_its_split_once_sub_object_convention() {
        // The facade refuses every dotted key, so the raw writer keeps the
        // explicit convention it has always documented: only the first dot
        // splits, and the remainder is a literal member name. `Labels.team`,
        // `Labels.com.example.team`, and `Mode.Replicated` are ordinary
        // examples, not unknown literals.
        let spec = ServiceSpec {
            labels: Some(BTreeMap::from([("role".to_owned(), "web".to_owned())])),
            mode: Some(serde_json::json!({"Global": {}})),
            additional: BTreeMap::from([
                ("Labels.team".to_owned(), serde_json::json!("platform")),
                (
                    "Labels.com.example.team".to_owned(),
                    serde_json::json!("platform"),
                ),
                (
                    "Mode.Replicated".to_owned(),
                    serde_json::json!({"Replicas": 3}),
                ),
            ]),
            ..ServiceSpec::default()
        };
        let body = service_spec_body(&spec).expect("the raw convention merges");
        assert_eq!(
            body["Labels"],
            serde_json::json!({
                "role": "web",
                "team": "platform",
                "com.example.team": "platform"
            })
        );
        assert_eq!(
            body["Mode"],
            serde_json::json!({"Global": {}, "Replicated": {"Replicas": 3}})
        );

        // Create and update share the same body builder.
        let namespaced = ServiceSpec {
            labels: Some(BTreeMap::from([("role".to_owned(), "web".to_owned())])),
            additional: BTreeMap::from([(
                "Labels.com.example.team".to_owned(),
                serde_json::json!("platform"),
            )]),
            ..ServiceSpec::default()
        };
        let create = service_create_request(&namespaced).expect("create request");
        let update = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 1,
                spec: namespaced,
                rollback: false,
            },
            RegistryAuth::none(),
        )
        .expect("update request");
        for request in [create, update] {
            let body = request_body(&request);
            assert_eq!(
                body["Labels"],
                serde_json::json!({"role": "web", "com.example.team": "platform"})
            );
            assert!(
                body.get("Labels.com.example.team").is_none(),
                "the namespaced key was not merged: {body}"
            );
        }
    }

    #[test]
    fn create_and_update_requests_share_the_dotted_rejection() {
        let canary = "canary-shared-dotted-9e1c";
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec![canary.to_owned()],
                ..ServicePlacement::default()
            }),
            additional: BTreeMap::from([(
                "Placement.Constraints".to_owned(),
                serde_json::json!([format!("{canary}-dotted")]),
            )]),
            ..ServiceSpec::default()
        };
        let create = service_create_request(&spec).expect_err("create must refuse");
        let update = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 1,
                spec,
                rollback: false,
            },
            RegistryAuth::none(),
        )
        .expect_err("update must refuse");
        for error in [create, update] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            let message = error.to_string();
            assert!(message.contains("more than one placement"), "{message}");
            assert!(!message.contains(canary), "{message}");
        }
    }

    #[test]
    fn a_task_template_that_is_not_an_object_is_refused_without_echoing() {
        let canary = "canary-task-template-scalar-9c4e";
        let spec = ServiceSpec {
            task_template: Some(serde_json::json!(canary)),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("a scalar task template");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let message = error.to_string();
        assert!(message.contains("TaskTemplate"), "{message}");
        assert!(message.contains("JSON object"), "{message}");
        assert!(!message.contains(canary));
    }

    #[test]
    fn typed_placement_and_a_task_template_placement_are_refused() {
        let spec = ServiceSpec {
            placement: Some(ServicePlacement {
                constraints: vec!["node.role == worker".to_owned()],
                ..ServicePlacement::default()
            }),
            task_template: Some(serde_json::json!({
                "ContainerSpec": {"Image": "nginx:alpine"},
                "Placement": {"Constraints": ["node.labels.zone == east"]}
            })),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("two placement representations");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("more than one placement"));
    }

    #[test]
    fn typed_restart_policy_and_a_dotted_task_template_policy_are_refused() {
        let spec = ServiceSpec {
            restart_policy: Some(ServiceRestartPolicy {
                condition: "on-failure".to_owned(),
                ..ServiceRestartPolicy::default()
            }),
            additional: BTreeMap::from([(
                "TaskTemplate.RestartPolicy".to_owned(),
                serde_json::json!({"Condition": "any"}),
            )]),
            ..ServiceSpec::default()
        };
        let error = service_spec_body(&spec).expect_err("two restart-policy representations");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("more than one restart policy"));
    }

    #[test]
    fn members_that_mean_nothing_are_omitted_rather_than_sent_empty() {
        // `MaxReplicas: 0` means "no limit", and an unset restriction is left
        // out rather than sent as an empty constraint list.
        let body = service_spec_body(&ServiceSpec::default()).expect("an empty specification");
        assert!(body.as_object().expect("an object").is_empty(), "{body}");
        let request = init_request(&SwarmInitOptions::default());
        assert!(
            request_body(&request)
                .as_object()
                .expect("an object")
                .is_empty()
        );
    }

    #[test]
    fn a_service_create_sends_the_versioned_path_and_the_whole_specification() {
        let request = service_create_request(&complete_spec()).expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/services/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "web");
        assert_eq!(
            body["TaskTemplate"]["Placement"]["Constraints"][0],
            "node.role == worker"
        );
    }

    #[test]
    fn a_service_update_carries_the_version_and_a_rollback_only_when_asked() {
        let plain = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: false,
            },
            RegistryAuth::none(),
        )
        .expect("a request");
        assert_eq!(
            request_line(&plain),
            crate::raw::at_api_version(
                "POST /v1.API/services/web/update?version=7&registryAuthFrom=spec HTTP/1.1"
            )
        );
        assert!(
            plain.headers.get("x-registry-auth").is_none(),
            "an update with no credential must send no registry header"
        );
        // An update carries the same specification as a create, placement and
        // restart policy included: a conflict-safe update built from an inspect
        // has to keep the constraints it read.
        assert_eq!(
            request_body(&plain)["TaskTemplate"]["Placement"]["MaxReplicas"],
            2
        );
        assert_eq!(
            request_body(&plain)["TaskTemplate"]["RestartPolicy"]["Condition"],
            "on-failure"
        );
        // The Engine reads `rollback` as a task ID or the word `previous`, so
        // `rollback=false` would name a task called `false`.
        let rolled_back = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: true,
            },
            RegistryAuth::none(),
        )
        .expect("a request");
        assert_eq!(
            request_line(&rolled_back),
            crate::raw::at_api_version(
                "POST /v1.API/services/web/update?version=7&registryAuthFrom=spec&rollback=previous HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_service_update_carries_a_registry_credential_without_rendering_it() {
        let credentials = RegistryCredentials::new("probeuser", "probe-password");
        let auth = RegistryAuth::credentials("registry.example", &credentials)
            .expect("a valid credential");
        let request = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: false,
            },
            auth,
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/services/web/update?version=7&registryAuthFrom=spec HTTP/1.1"
            ),
            "the credential must not change the request target"
        );
        let header = request
            .headers
            .get("x-registry-auth")
            .expect("the credential is sent");
        let decoded = URL_SAFE
            .decode(header.as_bytes())
            .expect("the Engine's URL-safe alphabet");
        let value: serde_json::Value =
            serde_json::from_slice(&decoded).expect("the header carries JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "username": "probeuser",
                "password": "probe-password",
                "serveraddress": "registry.example"
            })
        );

        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("probe-password"),
            "the request Debug rendered the registry credential: {rendered}"
        );
        assert!(
            !rendered.contains("probeuser"),
            "the request Debug rendered the registry account: {rendered}"
        );
    }

    #[test]
    fn a_service_update_identity_token_uses_the_engine_placeholder_account() {
        let token = "probe-identity-token";
        let auth =
            RegistryAuth::identity_token("registry.example", token).expect("a valid credential");
        let request = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: 7,
                spec: complete_spec(),
                rollback: false,
            },
            auth,
        )
        .expect("a request");
        let header = request
            .headers
            .get("x-registry-auth")
            .expect("the token is sent");
        let decoded = URL_SAFE
            .decode(header.as_bytes())
            .expect("the Engine's URL-safe alphabet");
        let value: serde_json::Value =
            serde_json::from_slice(&decoded).expect("the header carries JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "username": "<token>",
                "password": token,
                "serveraddress": "registry.example",
                "identitytoken": token
            })
        );
    }

    #[test]
    fn a_version_the_engine_cannot_express_is_refused_before_the_socket() {
        // The Engine declares the service parameter as `int32` and the others as
        // `int64`; a version that does not fit is a caller mistake rather than a
        // silent truncation into a different version.
        let service = service_update_request(
            "web",
            &ServiceUpdateOptions {
                version: u64::from(u32::MAX) + 1,
                spec: ServiceSpec::default(),
                rollback: false,
            },
            RegistryAuth::none(),
        )
        .expect_err("too large for int32");
        assert_eq!(service.kind(), ErrorKind::InvalidVersion);
        let node = node_update_request(
            "node-1",
            &NodeUpdateOptions {
                version: u64::MAX,
                spec: NodeSpec::default(),
            },
        )
        .expect_err("too large for int64");
        assert_eq!(node.kind(), ErrorKind::InvalidVersion);
        let swarm = update_request(&SwarmUpdateOptions {
            version: u64::MAX,
            spec: SwarmSpec::default(),
            rotate_worker_token: false,
            rotate_manager_token: false,
            rotate_manager_unlock_key: false,
        })
        .expect_err("too large for int64");
        assert_eq!(swarm.kind(), ErrorKind::InvalidVersion);
    }

    #[test]
    fn every_list_sends_its_filters_only_when_there_are_some() {
        for (resource, request) in [
            (
                "services",
                service_list_request(&SwarmListOptions::default()),
            ),
            ("nodes", node_list_request(&SwarmListOptions::default())),
            ("tasks", task_list_request(&SwarmListOptions::default())),
            ("configs", config_list_request(&SwarmListOptions::default())),
            ("secrets", secret_list_request(&SwarmListOptions::default())),
        ] {
            assert_eq!(
                request_line(&request.expect("a request")),
                format!(
                    "GET {}/{resource} HTTP/1.1",
                    crate::raw::api_version_prefix()
                )
            );
        }
        let filtered = service_list_request(
            &SwarmListOptions::new()
                .with_filter("name", ["web"])
                .with_filter("label", ["tier=web"]),
        )
        .expect("a request");
        assert_eq!(
            request_line(&filtered),
            crate::raw::at_api_version(
                "GET /v1.API/services?filters=%7B%22label%22%3A%5B%22tier%3Dweb%22%5D%2C%22name%22%3A%5B%22web%22%5D%7D HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_reference_cannot_escape_its_own_path_segment() {
        assert_eq!(escape_path_segment("a/b"), "a%2Fb");
        assert_eq!(escape_path_segment("a%2Fb"), "a%252Fb");
        for untouched in ["web", "8c968e1567aaf07c", "a.b_c~d", "web.1.abc"] {
            assert_eq!(escape_path_segment(untouched), untouched);
        }
        assert_eq!(
            request_line(&service_inspect_request("a/b").expect("a request")),
            crate::raw::at_api_version("GET /v1.API/services/a%2Fb HTTP/1.1")
        );
        assert_eq!(
            request_line(&task_inspect_request("a/b").expect("a request")),
            crate::raw::at_api_version("GET /v1.API/tasks/a%2Fb HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_reference_is_refused_by_every_operation_that_takes_one() {
        let spec = ServiceSpec::default();
        let refusals: Vec<Error> = vec![
            service_inspect_request("").expect_err("empty"),
            service_remove_request("").expect_err("empty"),
            service_log_request("", &SwarmLogOptions::default()).expect_err("empty"),
            task_log_request("", &SwarmLogOptions::default()).expect_err("empty"),
            node_inspect_request("").expect_err("empty"),
            node_remove_request("", NodeRemoveOptions::default()).expect_err("empty"),
            service_update_request(
                "",
                &ServiceUpdateOptions {
                    version: 1,
                    spec: spec.clone(),
                    rollback: false,
                },
                RegistryAuth::none(),
            )
            .expect_err("empty"),
            config_update_request("", 1, &SwarmConfigSpec::default()).expect_err("empty"),
            secret_update_request("", 1, &SwarmSecretSpec::default()).expect_err("empty"),
        ];
        assert_eq!(refusals.len(), 9);
        for error in refusals {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_reference_stays_one_path_segment_next_to_the_endpoint_suffix() {
        assert_eq!(
            resource_path("services", "web", "/update").expect("a path"),
            "/services/web/update"
        );
        assert_eq!(
            resource_path("tasks", "web.1.abc", "/logs").expect("a path"),
            "/tasks/web.1.abc/logs"
        );
    }

    #[test]
    fn swarm_init_sends_only_the_options_that_were_set() {
        assert_eq!(
            request_line(&init_request(&SwarmInitOptions::default())),
            crate::raw::at_api_version("POST /v1.API/swarm/init HTTP/1.1")
        );
        let request = init_request(&SwarmInitOptions {
            listen_address: Some("0.0.0.0:2377".to_owned()),
            advertise_address: Some("10.0.0.1:2377".to_owned()),
            data_path_address: Some("10.0.0.1".to_owned()),
            data_path_port: Some(4789),
            force_new_cluster: Some(true),
        });
        let body = request_body(&request);
        assert_eq!(body["ListenAddr"], "0.0.0.0:2377");
        assert_eq!(body["AdvertiseAddr"], "10.0.0.1:2377");
        assert_eq!(body["DataPathAddr"], "10.0.0.1");
        assert_eq!(body["DataPathPort"], 4789);
        assert_eq!(body["ForceNewCluster"], true);
    }

    #[test]
    fn a_join_with_no_manager_address_is_refused_rather_than_sent() {
        let error = join_request(&SwarmJoinOptions {
            token: "SWMTKN-1-x".to_owned(),
            ..SwarmJoinOptions::default()
        })
        .expect_err("no address to reach");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn a_join_carries_the_token_and_the_manager_addresses() {
        let request = join_request(&SwarmJoinOptions {
            token: "SWMTKN-1-x".to_owned(),
            remote_addresses: vec!["10.0.0.1:2377".to_owned()],
            ..SwarmJoinOptions::default()
        })
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/swarm/join HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["JoinToken"], "SWMTKN-1-x");
        assert_eq!(body["RemoteAddrs"][0], "10.0.0.1:2377");
        assert!(
            body.get("ListenAddr").is_none(),
            "an unset address is left out: {body}"
        );
    }

    #[test]
    fn a_leave_and_a_node_removal_spell_their_force_flag() {
        assert_eq!(
            request_line(&leave_request(SwarmLeaveOptions { force: true })),
            crate::raw::at_api_version("POST /v1.API/swarm/leave?force=true HTTP/1.1")
        );
        assert_eq!(
            request_line(&leave_request(SwarmLeaveOptions { force: false })),
            crate::raw::at_api_version("POST /v1.API/swarm/leave?force=false HTTP/1.1")
        );
        assert_eq!(
            request_line(
                &node_remove_request("node-1", NodeRemoveOptions { force: true })
                    .expect("a request")
            ),
            crate::raw::at_api_version("DELETE /v1.API/nodes/node-1?force=true HTTP/1.1")
        );
    }

    #[test]
    fn a_swarm_update_carries_the_version_and_every_rotation_flag() {
        let request = update_request(&SwarmUpdateOptions {
            version: 12,
            spec: SwarmSpec {
                name: Some("default".to_owned()),
                labels: Some(BTreeMap::from([("tier".to_owned(), "prod".to_owned())])),
                // A member the repository type does not name: the Engine's
                // `Orchestration` block. It has to reach the daemon, or a
                // conflict-safe update built from an inspect would delete it.
                additional: BTreeMap::from([(
                    String::from("Orchestration"),
                    serde_json::json!({"TaskHistoryRetentionLimit": 5}),
                )]),
            },
            rotate_worker_token: true,
            rotate_manager_token: false,
            rotate_manager_unlock_key: true,
        })
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/swarm/update?version=12&rotateWorkerToken=true&rotateManagerToken=false&rotateManagerUnlockKey=true HTTP/1.1"
            )
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "default");
        assert_eq!(body["Orchestration"]["TaskHistoryRetentionLimit"], 5);
    }

    #[test]
    fn an_unlock_names_the_endpoint_the_dependency_has_no_method_for() {
        let request = swarm_unlock_request(&SwarmUnlockOptions {
            key: "SWMKEY-1-x".to_owned(),
        });
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/swarm/unlock HTTP/1.1")
        );
        assert_eq!(request_body(&request)["UnlockKey"], "SWMKEY-1-x");
    }

    #[test]
    fn an_unlock_request_prints_no_unlock_key() {
        // The request's own `Debug` is the last place the key could be printed:
        // the body is buffered JSON, and a `Debug` that rendered the bytes would
        // publish the credential to a panic message or a tracing field. The
        // path and the body's length have to survive, or this test would also
        // pass against a `Debug` that printed nothing.
        const KEY: &str = "SWMKEY-1-canary-unlock-request-do-not-log-me";
        let request = swarm_unlock_request(&SwarmUnlockOptions {
            key: KEY.to_owned(),
        });
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(KEY), "{rendered}");
        assert!(rendered.contains("/swarm/unlock"), "{rendered}");
        assert!(rendered.contains("RawBody::Bytes"), "{rendered}");
    }

    #[test]
    fn an_empty_unlock_key_is_sent_rather_than_refused_locally() {
        // The generated route sent whatever the caller supplied, and the daemon
        // owns the answer for an empty key. Refusing it here would be a new
        // behavior on one route only, which is exactly the difference this
        // migration is supposed to remove.
        let request = swarm_unlock_request(&SwarmUnlockOptions { key: String::new() });
        assert_eq!(request_body(&request)["UnlockKey"], "");
    }

    #[test]
    fn the_swarm_inspect_path_is_the_one_join_tokens_come_from() {
        assert_eq!(
            request_line(&swarm_inspect_request()),
            crate::raw::at_api_version("GET /v1.API/swarm HTTP/1.1")
        );
    }

    #[test]
    fn a_join_token_is_read_from_the_members_the_engine_spells_capitalized() {
        // `GET /swarm` is the only endpoint that reports tokens, and the members
        // are `Worker` and `Manager` — capitalized, unlike the role names the
        // CLI takes. A worker reports no manager token, and an empty token is
        // `None` rather than an empty string a caller could paste into a join.
        let document: SwarmInfo = decode(
            br#"{"ID":"sw","JoinTokens":{"Worker":"SWMTKN-1-worker","Manager":"SWMTKN-1-manager"}}"#,
        )
        .expect("a swarm document");
        assert_eq!(
            document
                .join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get(SwarmJoinTokenRole::Worker.join_token_member()))
                .and_then(serde_json::Value::as_str),
            Some("SWMTKN-1-worker")
        );
        assert_eq!(
            document
                .join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get(SwarmJoinTokenRole::Manager.join_token_member()))
                .and_then(serde_json::Value::as_str),
            Some("SWMTKN-1-manager")
        );
        let bare: SwarmInfo =
            decode(br#"{"ID":"sw","JoinTokens":{"Worker":""}}"#).expect("a swarm document");
        assert_eq!(
            bare.join_tokens
                .as_ref()
                .and_then(|tokens| tokens.get("Manager"))
                .and_then(serde_json::Value::as_str),
            None
        );
    }

    #[test]
    fn a_swarm_document_keeps_the_members_the_typed_fields_do_not_name() {
        // `Orchestration` and `Dispatcher` are blocks of the specification that
        // the repository type does not name, and the token block is a member no
        // field names at all. A conflict-safe update built from this document has
        // to carry all three, or the daemon loses the settings and the caller
        // cannot join another node.
        let swarm: SwarmInfo = decode(SWARM.as_bytes()).expect("a swarm document");
        assert_eq!(swarm.id.as_deref(), Some("swarm-fixture"));
        assert_eq!(swarm.version, Some(SwarmVersion { index: Some(12) }));
        let spec = swarm.spec.as_ref().expect("the specification");
        assert_eq!(spec.name.as_deref(), Some("fixture-swarm"));
        assert_eq!(
            spec.additional["Orchestration"]["TaskHistoryRetentionLimit"],
            5
        );
        assert_eq!(
            spec.additional["Dispatcher"]["HeartbeatPeriod"],
            5_000_000_000i64
        );
        let tokens = swarm.join_tokens.as_ref().expect("the join tokens");
        assert_eq!(tokens["Worker"], "worker-token");
        assert_eq!(tokens["Manager"], "manager-token");
    }

    #[test]
    fn a_service_document_projects_the_typed_views_and_keeps_the_endpoint() {
        // `Endpoint` is where the published ports live, and the repository model
        // names them as a top-level member. The endpoint is also kept whole, so a
        // member of it that no typed field names — a port's `Name`, say — is not
        // lost on the way through.
        let document: ServiceDocument = decode(SERVICE.as_bytes()).expect("a service document");
        let service = SwarmService::try_from(document).expect("it converts");
        assert_eq!(service.id.as_deref(), Some("service0123456789abcdef"));
        assert_eq!(service.version, Some(SwarmVersion { index: Some(7) }));
        assert_eq!(
            service.additional["Endpoint"]["Ports"][0]["PublishedPort"],
            8080
        );
        let ports = service.ports.as_ref().expect("the published ports");
        assert_eq!(ports[0].protocol.as_deref(), Some("tcp"));
        assert_eq!(ports[0].target_port, Some(80));
        assert_eq!(ports[0].published_port, Some(8080));
        assert_eq!(
            service.status,
            Some(ServiceStatus {
                running_tasks: 2,
                desired_tasks: 2,
            })
        );
        let spec = service.spec.as_ref().expect("the specification");
        assert_eq!(spec.name.as_deref(), Some("web"));
        assert_eq!(
            spec.task_template
                .as_ref()
                .and_then(|template| template.get("ContainerSpec")),
            Some(&serde_json::json!({"Image": "nginx:alpine"}))
        );
    }

    #[test]
    fn every_list_answer_decodes_into_its_own_model() {
        let services = project::<SwarmService, ServiceDocument>(SERVICES);
        let nodes = project::<SwarmNode, NodeDocument>(NODES);
        let tasks = project::<SwarmTask, TaskDocument>(TASKS);
        let configs = project::<SwarmConfig, ConfigDocument>(CONFIGS);
        let secrets = project::<SwarmSecret, SecretDocument>(SECRETS);
        assert_eq!(services.len(), 1);
        assert_eq!(nodes.len(), 1);
        assert_eq!(tasks.len(), 1);
        assert_eq!(configs.len(), 1);
        assert_eq!(secrets.len(), 1);
        // `PreviousSpec` is what a rollback restores, and no typed field names
        // it, so it is retained beside the specification the model does have.
        // A decode that dropped it would leave a rollback with nothing to
        // restore.
        assert_eq!(
            services[0].additional["PreviousSpec"]["TaskTemplate"]["ContainerSpec"]["Image"],
            "nginx:1.25"
        );
        assert_eq!(
            nodes[0]
                .status
                .as_ref()
                .and_then(|status| status.get("Addr"))
                .and_then(serde_json::Value::as_str),
            Some("192.0.2.10")
        );
        assert_eq!(
            tasks[0]
                .status
                .as_ref()
                .and_then(|status| status.error.as_deref()),
            Some("pull access denied")
        );
    }

    #[test]
    fn a_node_document_reads_the_engine_version_out_of_the_description() {
        let document: NodeDocument = decode(NODE.as_bytes()).expect("a node document");
        let node = SwarmNode::try_from(document).expect("it converts");
        assert_eq!(node.engine_version.as_deref(), Some("27.1.1"));
        // The description is kept whole, so a member of it the projection does
        // not read is not lost.
        assert_eq!(
            node.additional["Description"]["Engine"]["EngineVersion"],
            "27.1.1"
        );
        let spec = node.spec.as_ref().expect("the node specification");
        assert_eq!(spec.role.as_deref(), Some("manager"));
        assert_eq!(spec.availability.as_deref(), Some("active"));
        let manager = node.manager_status.as_ref().expect("the manager status");
        assert_eq!(manager.leader, Some(true));
        assert_eq!(manager.reachability.as_deref(), Some("reachable"));
    }

    #[test]
    fn a_synthetic_manager_address_does_not_overwrite_an_actual_top_level_member() {
        // `ManagerStatus.Addr` and `ManagerStatus.Address` are views of the
        // nested manager status, not members the daemon sent at the top level.
        // A caller that round-trips an edited document can have a real member
        // with exactly that name, and the synthetic view must not win.
        let document = br#"{
          "ID": "node-1",
          "ManagerStatus": {"Addr": "10.0.0.1:2377", "Address": "10.0.0.2:2377"},
          "ManagerStatus.Addr": "caller-addr",
          "ManagerStatus.Address": "caller-address"
        }"#;
        let node = SwarmNode::try_from(decode::<NodeDocument>(document).expect("a node document"))
            .expect("it converts");

        assert_eq!(node.additional["ManagerStatus.Addr"], "caller-addr");
        assert_eq!(node.additional["ManagerStatus.Address"], "caller-address");
        let serialized = serde_json::to_value(&node).expect("the node serializes");
        assert_eq!(serialized["ManagerStatus.Addr"], "caller-addr");
        assert_eq!(serialized["ManagerStatus.Address"], "caller-address");
        // The nested members are still where the daemon put them.
        let manager = node.manager_status.as_ref().expect("the manager status");
        assert_eq!(manager.additional["Addr"], "10.0.0.1:2377");
        assert_eq!(manager.additional["Address"], "10.0.0.2:2377");

        // Without a collision, the synthetic views are added as before.
        let document = br#"{
          "ID": "node-2",
          "ManagerStatus": {"Addr": "10.0.0.1:2377", "Address": "10.0.0.2:2377"}
        }"#;
        let node = SwarmNode::try_from(decode::<NodeDocument>(document).expect("a node document"))
            .expect("it converts");
        assert_eq!(node.additional["ManagerStatus.Addr"], "10.0.0.1:2377");
        assert_eq!(node.additional["ManagerStatus.Address"], "10.0.0.2:2377");
    }

    #[test]
    fn an_actual_top_level_engine_version_keeps_the_raw_collision_contract() {
        // The raw projection deliberately keeps its original behavior: the
        // typed view is the nested one, the actual top-level member stays in
        // `additional`, and serialization can emit both. Raw does not promise
        // round-trip stability, and this test does not claim it.
        for actual in [
            serde_json::json!("actual-top-level"),
            serde_json::Value::Null,
            serde_json::json!({"Nested": true}),
        ] {
            let document = serde_json::json!({
                "ID": "node-1",
                "EngineVersion": actual,
                "Description": {"Engine": {"EngineVersion": "nested-view"}}
            })
            .to_string();
            let node = SwarmNode::try_from(
                decode::<NodeDocument>(document.as_bytes()).expect("a node document"),
            )
            .expect("it converts");
            assert_eq!(node.engine_version.as_deref(), Some("nested-view"));
            assert_eq!(node.additional["EngineVersion"], actual);
            let serialized = serde_json::to_string(&node).expect("the node serializes");
            assert_eq!(
                serialized.matches("\"EngineVersion\"").count(),
                3,
                "the raw projection emits the typed view, the actual member, and the nested description: {serialized}"
            );
            let value = serde_json::to_value(&node).expect("the node converts");
            assert!(
                value.get("EngineVersion").is_some(),
                "the duplicate-key Value conversion keeps one of the two values"
            );
            assert_eq!(
                value["Description"]["Engine"]["EngineVersion"],
                "nested-view"
            );
        }
    }

    #[test]
    fn a_task_document_reads_the_image_out_of_the_container_specification() {
        let document: TaskDocument = decode(TASK.as_bytes()).expect("a task document");
        let task = SwarmTask::try_from(document).expect("it converts");
        assert_eq!(task.image.as_deref(), Some("nginx:alpine"));
        assert_eq!(task.service_id, "service0123456789abcdef");
        assert_eq!(task.slot, 1);
        assert_eq!(task.node_id, "node0123456789abcdef");
        assert_eq!(task.name.as_deref(), Some("web.1"));
        let status = task.status.as_ref().expect("the task status");
        assert_eq!(status.state.as_deref(), Some("running"));
        assert_eq!(status.message.as_deref(), Some("started"));
        // The specification is kept whole beside the typed image.
        assert_eq!(
            task.additional["Spec"]["ContainerSpec"]["Image"],
            "nginx:alpine"
        );
    }

    #[test]
    fn a_task_that_has_not_been_assigned_still_decodes() {
        // An unassigned task reports an empty `NodeID`, and a task document that
        // omits the member entirely must not become a decode failure: waiting for
        // a node is a normal state, not a broken answer.
        let document: TaskDocument =
            decode(br#"{"ID":"t","ServiceID":"s","Slot":0,"Status":{"State":"pending"}}"#)
                .expect("a task document");
        let task = SwarmTask::try_from(document).expect("it converts");
        assert_eq!(task.node_id, "");
        assert_eq!(task.slot, 0);
        assert_eq!(task.image, None);
    }

    #[test]
    fn a_config_document_keeps_its_data_and_a_secret_document_keeps_its_driver() {
        let config = SwarmConfig::try_from(
            decode::<ConfigDocument>(CONFIG.as_bytes()).expect("a config document"),
        )
        .expect("it converts");
        assert_eq!(config.id.as_deref(), Some("config0123456789abcdef"));
        let spec = config.spec.as_ref().expect("the config specification");
        assert_eq!(spec.name.as_deref(), Some("app-config"));
        // The Engine base64-encodes config data on the wire.
        assert_eq!(spec.data.as_deref(), Some("aGVsbG8="));

        let secret = SwarmSecret::try_from(
            decode::<SecretDocument>(SECRET.as_bytes()).expect("a secret document"),
        )
        .expect("it converts");
        assert_eq!(secret.id.as_deref(), Some("secret0123456789abcdef"));
        let spec = secret.spec.as_ref().expect("the secret specification");
        assert_eq!(spec.name.as_deref(), Some("db-password"));
        assert_eq!(
            spec.driver.as_ref().and_then(|driver| driver.get("Name")),
            Some(&serde_json::json!("vault"))
        );
    }

    #[test]
    fn a_config_create_base64_encodes_the_data_the_engine_declares() {
        let request = config_create_request(&ConfigCreateOptions {
            name: "app-config".to_owned(),
            data: Some(b"hello".to_vec()),
            labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
        });
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/configs/create HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "app-config");
        assert_eq!(body["Labels"]["tier"], "web");
        assert_eq!(body["Data"], "aGVsbG8=");
    }

    #[test]
    fn a_create_with_no_bytes_omits_the_data_member() {
        // A missing `Data` asks the daemon for an external object; an empty
        // string asks it to store nothing at all.
        let config = request_body(&config_create_request(&ConfigCreateOptions {
            name: "external".to_owned(),
            data: None,
            labels: None,
        }));
        assert!(config.get("Data").is_none(), "{config}");
        let secret = request_body(&secret_create_request(&SecretCreateOptions::new(
            "external", None,
        )));
        assert!(secret.get("Data").is_none(), "{secret}");
    }

    #[test]
    fn a_secret_create_base64_encodes_the_callers_bytes() {
        let request = secret_create_request(&SecretCreateOptions::new(
            "db-password",
            Some(SwarmSecretData::new(b"s3cret".to_vec())),
        ));
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/secrets/create HTTP/1.1")
        );
        assert_eq!(request_body(&request)["Data"], "czNjcmV0");
    }

    #[test]
    fn a_config_update_retains_data_as_the_facade_did() {
        // The Engine's update endpoint cannot change a config's data, and the
        // repository specification carries it because an inspect answer does.
        let request = config_update_request(
            "app-config",
            3,
            &SwarmConfigSpec {
                name: Some("app-config".to_owned()),
                labels: Some(BTreeMap::from([("tier".to_owned(), "web".to_owned())])),
                data: Some("aGVsbG8=".to_owned()),
                additional: BTreeMap::new(),
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/configs/app-config/update?version=3 HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "app-config");
        assert_eq!(body["Labels"]["tier"], "web");
        assert_eq!(body["Data"], "aGVsbG8=");
    }

    #[test]
    fn a_secret_update_sends_the_version_and_the_metadata() {
        let request = secret_update_request(
            "db-password",
            2,
            &SwarmSecretSpec {
                name: Some("db-password".to_owned()),
                labels: None,
                driver: Some(serde_json::json!({"Name": "vault"})),
                additional: BTreeMap::new(),
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/secrets/db-password/update?version=2 HTTP/1.1"
            )
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "db-password");
        assert_eq!(body["Driver"]["Name"], "vault");
    }

    /// The raw writer refuses an unexpected Data before dispatch.
    ///
    /// The engine under this test points at a socket that does not exist. A
    /// dispatch would be a transport failure; the local `InvalidInput` is the
    /// proof the guard ran first.
    #[tokio::test]
    async fn a_secret_update_refuses_unexpected_data_before_dispatch() {
        let mut additional = BTreeMap::new();
        additional.insert("Data".to_owned(), serde_json::json!("aGVsbG8="));
        let error = super::secret_update(
            &engine(),
            "db-password",
            &SecretUpdateOptions {
                version: 2,
                spec: SwarmSecretSpec {
                    name: Some("db-password".to_owned()),
                    additional,
                    ..SwarmSecretSpec::default()
                },
            },
        )
        .await
        .expect_err("an unexpected Data member is refused");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("Data member"),
            "the refusal did not name the member: {error}"
        );
        assert!(!error.to_string().contains("aGVsbG8="), "{error}");
    }

    #[test]
    fn a_node_update_sends_the_repository_node_specification() {
        let request = node_update_request(
            "node-1",
            &NodeUpdateOptions {
                version: 4,
                spec: NodeSpec {
                    name: Some("manager-one".to_owned()),
                    role: Some("manager".to_owned()),
                    availability: Some("drain".to_owned()),
                    labels: Some(BTreeMap::from([(
                        "org.example.node".to_owned(),
                        "fixture".to_owned(),
                    )])),
                    additional: BTreeMap::new(),
                },
            },
        )
        .expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/nodes/node-1/update?version=4 HTTP/1.1")
        );
        let body = request_body(&request);
        assert_eq!(body["Name"], "manager-one");
        assert_eq!(body["Role"], "manager");
        assert_eq!(body["Availability"], "drain");
        assert_eq!(body["Labels"]["org.example.node"], "fixture");
    }

    #[test]
    fn reproduce_nested_escaped_duplicate() {
        for body in [
            r#"{"Spec":{"extra":{"x":1,"\u0078":2}}}"#,
            r#"[{"Spec":null},{"Spec":{"extra":[null,{"x":1,"\u0078":2}]}}]"#,
        ] {
            assert!(validate_node_document_keys(body.as_bytes()).is_err());
        }
    }

    #[test]
    fn reproduce_null_before_duplicate() {
        let body = r#"{"Spec":null,"Spec":{}}"#;
        assert!(validate_node_document_keys(body.as_bytes()).is_err());
    }

    #[test]
    fn reproduce_unicode_reserved_key() {
        let mut spec = NodeSpec::default();
        spec.additional
            .insert("Labelſ".to_owned(), serde_json::json!({}));
        assert!(crate::swarm::reject_reserved_node_spec_members(&spec).is_err());
    }

    #[test]
    fn node_key_and_nesting_limits_fail_closed() {
        let fields = (0..super::NODE_KEY_LIMIT)
            .map(|i| format!(r#""k{i}":null"#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            validate_node_document_keys(format!(r#"{{"Spec":{{{fields}}}}}"#).as_bytes()).is_err()
        );
        let nested = format!(r#"{{"Spec":{}null{}}}"#, "[".repeat(130), "]".repeat(130));
        assert!(validate_node_document_keys(nested.as_bytes()).is_err());
    }

    #[test]
    fn duplicate_node_document_keys_are_refused_at_every_consumed_level() {
        const CANARY: &str = "canary-duplicate-node-key-6c9f";
        let bodies = [
            ("top", format!(r#"{{"ID":"node-a","ID":"{CANARY}"}}"#)),
            (
                "spec",
                format!(r#"{{"Spec":{{"Role":"manager","Role":"{CANARY}"}}}}"#),
            ),
            (
                "labels",
                format!(r#"{{"Spec":{{"Labels":{{"zone":"a","zone":"{CANARY}"}}}}}}"#),
            ),
            ("list", format!(r#"[{{"ID":"node-a","ID":"{CANARY}"}}]"#)),
        ];
        for (level, body) in bodies {
            let error = validate_node_document_keys(body.as_bytes()).expect_err(level);
            assert_eq!(error.kind(), ErrorKind::Serialization, "{level}");
            let mut renderings = vec![error.to_string(), format!("{error:?}")];
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                renderings.push(cause.to_string());
                renderings.push(format!("{cause:?}"));
                source = cause.source();
            }
            let summary = renderings.join("\n");
            assert!(
                summary.contains(NODE_DUPLICATE_KEY_MESSAGE),
                "{level}: the fixed diagnostic is missing: {summary}"
            );
            for rendering in &renderings {
                assert!(
                    !rendering.contains(CANARY),
                    "{level}: the duplicate diagnostic echoed a value: {rendering}"
                );
            }
        }
    }

    #[test]
    fn malformed_node_documents_are_left_to_the_decoder() {
        assert!(validate_node_document_keys(b"{").is_err());
        validate_node_document_keys(br#"{"Spec":{"Labels":[]}}"#)
            .expect("valid JSON is left to the normal typed decoder");
    }

    #[test]
    fn reserved_node_specification_keys_are_refused_before_encoding() {
        const CANARY: &str = "canary-reserved-node-spec-2f8c";
        for reserved in ["Name", "Labels", "Role", "Availability"] {
            for key in [
                reserved.to_ascii_lowercase(),
                reserved.to_ascii_uppercase(),
                format!(
                    "{}{}",
                    reserved[..1].to_ascii_lowercase(),
                    reserved[1..].to_ascii_uppercase()
                ),
            ] {
                for typed in [false, true] {
                    let mut spec = NodeSpec {
                        name: typed.then(|| "typed-name".to_owned()),
                        labels: typed
                            .then(|| BTreeMap::from([("typed".to_owned(), "label".to_owned())])),
                        role: typed.then(|| "typed-role".to_owned()),
                        availability: typed.then(|| "typed-availability".to_owned()),
                        ..NodeSpec::default()
                    };
                    spec.additional
                        .insert(key.clone(), serde_json::json!(CANARY));
                    let error =
                        node_update_request("node-1", &NodeUpdateOptions { version: 4, spec })
                            .expect_err("a reserved additional key is refused");
                    assert_eq!(error.kind(), ErrorKind::InvalidInput, "{key} typed={typed}");
                    let mut renderings = vec![error.to_string(), format!("{error:?}")];
                    let mut source = std::error::Error::source(&error);
                    while let Some(cause) = source {
                        renderings.push(cause.to_string());
                        renderings.push(format!("{cause:?}"));
                        source = cause.source();
                    }
                    for rendering in &renderings {
                        assert!(
                            !rendering.contains(CANARY),
                            "{key} typed={typed}: the refusal echoed a caller value: {rendering}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_service_create_answer_is_read_from_the_id_member_not_the_container_one() {
        // The container create endpoint answers `{"Id":…}` and this one answers
        // `{"ID":…}`. A client that spelled it the container way would report an
        // empty service ID for a service that was created.
        let document: ServiceCreateDocument =
            decode(br#"{"ID":"svc-1","Warnings":["no suitable nodes"]}"#)
                .expect("a create document");
        let result = ServiceCreateResult::from(document);
        assert_eq!(result.id, "svc-1");
        assert_eq!(result.warnings, vec!["no suitable nodes".to_owned()]);
        let bare: ServiceCreateDocument =
            decode(r#"{"ID":"svc-1"}"#.as_bytes()).expect("a create document");
        assert!(
            ServiceCreateResult::from(bare).warnings.is_empty(),
            "expected ServiceCreateResult::from(bare).warnings to be empty"
        );
    }

    #[test]
    fn a_service_update_answer_carries_only_warnings() {
        let document: ServiceUpdateDocument =
            decode(br#"{"Warnings":["rolling back"]}"#).expect("an update document");
        assert_eq!(
            ServiceUpdateResult::from(document).warnings,
            vec!["rolling back".to_owned()]
        );
        let empty: ServiceUpdateDocument = decode(b"{}").expect("an update document");
        assert!(
            ServiceUpdateResult::from(empty).warnings.is_empty(),
            "expected ServiceUpdateResult::from(empty).warnings to be empty"
        );
    }

    #[test]
    fn service_and_task_logs_send_the_generated_route_parameters() {
        // Match the generated facade routes, without adding `details`.
        let options = SwarmLogOptions {
            follow: true,
            stdout: true,
            stderr: true,
            since: 1,
            until: 2,
            timestamps: true,
            tail: "50".to_owned(),
        };
        assert_eq!(
            request_line(&service_log_request("web", &options).expect("a request")),
            crate::raw::at_api_version(
                "GET /v1.API/services/web/logs?follow=true&stdout=true&stderr=true\
             &since=1&until=2&timestamps=true&tail=50 HTTP/1.1"
            )
        );
        assert_eq!(
            request_line(&task_log_request("web.1.abc", &options).expect("a request")),
            crate::raw::at_api_version(
                "GET /v1.API/tasks/web.1.abc/logs?follow=true&stdout=true&stderr=true\
                 &since=1&until=2&timestamps=true&tail=50 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_logs_query_says_what_it_meant_even_when_nothing_is_selected() {
        // The repository's log options default both streams to `false`, so a
        // caller that only sets `tail` gets an empty body. That is the option
        // type's choice, and it is visible in the request line rather than
        // hidden, which is the point of spelling every parameter.
        let request = service_log_request("web", &SwarmLogOptions::default()).expect("a request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/services/web/logs?follow=false&stdout=false&stderr=false\
             &since=0&until=0&timestamps=false&tail=all HTTP/1.1"
            )
        );
    }

    /// All five lifecycle operations preserve a propagated deadline marker and
    /// never carry the earlier factory's text.
    ///
    /// The marker is not a claim that *this* operation timed out: a
    /// caller-supplied factory can propagate an earlier marked error before the
    /// request is written. The fixed diagnostics therefore report only that the
    /// outcome is unknown (mutations) or that the read did not complete.
    #[tokio::test]
    async fn lifecycle_failures_preserve_the_deadline_marker_without_factory_text() {
        const CANARY: &str = "previous Swarm canary 6c1e2b-do-not-log-me";

        for marked in [true, false] {
            let open = StreamFactory::from_fn(move || async move {
                let error = if marked {
                    crate::Error::transport_deadline(CANARY)
                } else {
                    crate::Error::transport(CANARY)
                };
                Err::<Box<dyn Duplex>, _>(error)
            });
            let engine = RawEngine::new(
                RawTarget::Stream {
                    authority: "fixture".to_owned(),
                    open,
                },
                VERSION,
            );
            let errors = vec![
                super::swarm_init(&engine, &SwarmInitOptions::new())
                    .await
                    .expect_err("the factory failed"),
                super::swarm_join(
                    &engine,
                    &SwarmJoinOptions {
                        token: "synthetic-join-token".to_owned(),
                        remote_addresses: vec!["tcp://manager:2377".to_owned()],
                        ..SwarmJoinOptions::default()
                    },
                )
                .await
                .expect_err("the factory failed"),
                super::swarm_update(
                    &engine,
                    &SwarmUpdateOptions {
                        version: 1,
                        spec: SwarmSpec::default(),
                        rotate_worker_token: false,
                        rotate_manager_token: false,
                        rotate_manager_unlock_key: false,
                    },
                )
                .await
                .expect_err("the factory failed"),
                super::swarm_certificates(&engine)
                    .await
                    .expect_err("the factory failed"),
                super::swarm_unlock_key(&engine)
                    .await
                    .expect_err("the factory failed"),
            ];

            for error in errors {
                assert_eq!(error.is_transport_deadline(), marked);
                assert_eq!(error.kind(), ErrorKind::Transport);
                let mut renderings = vec![error.to_string(), format!("{error:?}")];
                if let Some(api) = error.api_error() {
                    renderings.push(api.to_string());
                    renderings.push(api.message.clone());
                }
                let mut source = std::error::Error::source(&error);
                while let Some(cause) = source {
                    renderings.push(cause.to_string());
                    renderings.push(format!("{cause:?}"));
                    source = cause.source();
                }
                for rendered in renderings {
                    assert!(
                        !rendered.contains(CANARY),
                        "a lifecycle failure rendering kept the factory text: {rendered}"
                    );
                    assert!(
                        rendered.contains("withheld")
                            || rendered.contains("transport deadline was observed"),
                        "the fixed diagnostic is missing: {rendered}"
                    );
                }
            }
        }
    }
    /// A factory can propagate a deadline from an earlier operation; never
    /// preserve its text or claim that this particular write timed out.
    #[tokio::test]
    async fn resource_mutations_withhold_factory_errors_and_keep_deadline_markers() {
        const CANARY: &str = "prior-confidential-factory-canary";
        for marked in [false, true] {
            let open = StreamFactory::from_fn(move || async move {
                let error = if marked {
                    crate::Error::transport_deadline(CANARY)
                } else {
                    crate::Error::transport(CANARY)
                };
                Err::<Box<dyn Duplex>, _>(error)
            });
            let engine = RawEngine::new(
                RawTarget::Stream {
                    authority: "fixture".into(),
                    open,
                },
                VERSION,
            );
            let errors = [
                super::config_create(&engine, &ConfigCreateOptions::default())
                    .await
                    .unwrap_err(),
                super::config_update(
                    &engine,
                    "id",
                    &crate::ConfigUpdateOptions {
                        version: 1,
                        spec: SwarmConfigSpec::default(),
                    },
                )
                .await
                .unwrap_err(),
                super::config_remove(&engine, "id").await.unwrap_err(),
                super::secret_create(&engine, &SecretCreateOptions::new("fixture", None))
                    .await
                    .unwrap_err(),
                super::secret_update(
                    &engine,
                    "id",
                    &SecretUpdateOptions {
                        version: 1,
                        spec: SwarmSecretSpec::default(),
                    },
                )
                .await
                .unwrap_err(),
                super::secret_remove(&engine, "id").await.unwrap_err(),
            ];
            for error in errors {
                assert_eq!(error.is_transport_deadline(), marked);
                let mut text = vec![format!("{error} {error:?}")];
                let mut source = std::error::Error::source(&error);
                while let Some(cause) = source {
                    text.push(format!("{cause} {cause:?}"));
                    source = cause.source();
                }
                for rendering in text {
                    assert!(!rendering.contains(CANARY));
                    if marked {
                        assert!(rendering.contains("deadline was observed"));
                    }
                }
            }
        }
    }
}
