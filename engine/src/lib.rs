//! Repository-native Docker Engine API access using the owned transport.
//!
//! The compatibility ceiling is Docker Engine API version 1.55. The facade
//! exposes repository-owned models and caller-owned streaming handles.
#![doc = include_str!("../README.md")]

use std::fmt;
use std::time::Duration;

mod build_ignore;
pub use build_ignore::IgnoreMatcher;
mod buildkit;
mod config;
mod containers;
mod context;
mod context_archive;
mod context_store;
mod credentials;
mod endpoint;
mod engine;
mod image_transfer;
mod images;
mod link_guard;
mod networks;
mod plugins;
mod proxy;
pub mod raw;
mod registry_auth;
mod streams;
mod swarm;
mod system;
mod volumes;

pub use buildkit::{
    BuildKitBuildError, BuildKitBuildOptions, BuildKitProgress, SshForward, parse_registry_cache,
    validate_buildkit_cache,
};

#[cfg(all(feature = "ssh", unix))]
mod ssh_auth;

// Managed establishment shares one cancellation/effect-ordering control.
#[cfg(all(feature = "ssh", unix))]
#[allow(dead_code)]
mod ssh_cancellation;

// Async DNS and TCP dialing precede the supervised SSH worker.
#[cfg(all(feature = "ssh", unix))]
#[allow(dead_code)]
mod ssh_connect;

// Capacity-limited worker ownership survives blocked filesystem reads.
#[cfg(all(feature = "ssh", unix))]
#[allow(dead_code)]
mod ssh_worker;

#[cfg(all(feature = "ssh", unix))]
mod ssh_dial_stdio;

#[cfg(all(feature = "ssh", unix))]
mod ssh_neotales;

#[cfg(all(feature = "ssh", unix))]
#[cfg(all(feature = "ssh", unix))]
pub use ssh_auth::{
    ManagedSshClient, ManagedSshEstablishmentFailure, ManagedSshHostKeyRejection, SshIdentity,
    SshSecret,
};

pub use streams::{
    ContainerLogFrame, ContainerLogStream, ContainerLogsOptions, ContainerStats,
    ContainerStatsOptions, ContainerStatsResponse, DockerEvent, DockerEventActor,
    DockerEventResponse, DockerEventsOptions, DockerStream, EventsOptions, ImageProgress,
    ImageProgressEvent, ImagePullOptions, ImagePushOptions, ImageStreamEvent, LogFrame, LogStream,
    LogsOptions, StatsOptions,
};

pub use config::{
    DOCKER_HUB_REGISTRY, DockerConfigError, DockerConfigSummary, RegistryConfigStore,
    RegistryLogoutResult, display_server, registry_key,
};
pub use containers::{
    AttachedSession, Checkpoint, CheckpointOptions, CommitContainerOptions, ContainerArchive,
    ContainerArchiveUploadOptions, ContainerCreateOptions, ContainerCreateResult, ContainerDetails,
    ContainerEndpointSettings, ContainerHostConfig, ContainerListOptions,
    ContainerNetworkingConfig, ContainerPathStat, ContainerPort, ContainerPortBinding,
    ContainerPruneOptions, ContainerPruneResult, ContainerRemoveOptions, ContainerRestartOptions,
    ContainerStartOptions, ContainerStopOptions, ContainerSummary, ContainerTop,
    ContainerUpdateOptions, ContainerUpdateResult, ContainerWaitOptions, ContainerWaitResult,
    DeviceMapping, DeviceRequest, ExecOptions, ExecResizeOptions, ExecSession, ExecState,
    FilesystemChange, HealthConfig, LogConfig, PortMapping, RestartPolicy, SessionInput, Ulimit,
};
pub use context::{
    CONTAINER_HOST_VARIABLE, ContextError, ContextResolver, EndpointSource, NERDCTL_ROOTFUL_SOCKET,
    PODMAN_ROOTFUL_SOCKET, PathProbe, ResolvedEndpoint, nerdctl_socket_candidates,
    nerdctl_socket_sources, podman_socket_candidates, podman_socket_sources,
};
pub use context_archive::{
    ContextArchiveError, ContextArchiveLimits, ContextArchiveStore, ContextArchiveSummary,
};
pub use context_store::{
    ContextCreateOptions, ContextStore, ContextTlsFiles, ContextUpdateOptions, DockerContext,
};
pub use credentials::{
    CredentialError, DockerCredentialHelper, InMemoryRegistryCredentialProvider,
    RegistryCredentialProvider, RegistryCredentials, normalize_registry, registry_for_image,
};
pub use endpoint::{Endpoint, EndpointError, TlsMaterial};
pub use engine::{
    ENGINE_ENVIRONMENT_VARIABLE, EngineCapability, EngineError, EngineKind, EngineProfile,
    EngineSource, UnsupportedCapability,
};
pub use image_transfer::{
    ImageBuildAux, ImageBuildBackend, ImageBuildContext, ImageBuildError, ImageBuildEvent,
    ImageBuildKitOption, ImageBuildOptions, ImageBuildResponse, ImageBuildResult,
    ImageContextError, ImageImportEvent, ImageImportOptions, ImageLoadEvent, ImageLoadOptions,
    ImageLoadResponse, ImageLoadResult, ImageOperationError, ImageSaveError, ImageSaveOptions,
    ImageSaveResult, ImageTransferError, ImageTransferLimits,
};
pub use images::{
    ImageConfig, ImageDeleteResult, ImageGraphDriver, ImageHealthcheck, ImageHistory,
    ImageHistoryEntry, ImageHistoryOptions, ImageHistoryResponse, ImageInspect,
    ImageInspectOptions, ImageInspectResponse, ImageListOptions, ImageMetadata, ImagePruneDelete,
    ImagePruneOptions, ImagePruneResponse, ImagePruneResult, ImageRemoveOptions, ImageRootFs,
    ImageSearchOptions, ImageSearchResponse, ImageSearchResult, ImageSearchResultItem,
    ImageSummary, ImageTagOptions,
};
pub use link_guard::{is_link_or_reparse_point, path_is_link_or_reparse_point};
pub use networks::{
    NetworkConnectOptions, NetworkCreateOptions, NetworkCreateResponse, NetworkCreateResult,
    NetworkDisconnectOptions, NetworkEndpoint, NetworkEndpointOptions, NetworkInspect,
    NetworkInspectOptions, NetworkIpam, NetworkIpamConfig, NetworkListOptions, NetworkPruneOptions,
    NetworkPruneResponse, NetworkPruneResult, NetworkResponse, NetworkSummary,
};
pub use plugins::{
    PluginDisableOptions, PluginEnableOptions, PluginInstallOptions, PluginListOptions,
    PluginPrivilege, PluginRemoveOptions, PluginSummary, PluginUpgradeOptions,
};
#[cfg(feature = "tls")]
pub use proxy::TlsServerTrust;
pub use proxy::{
    ForwardProxy, MAX_PROXY_AUTHORIZATION_BYTES, MAX_PROXY_PASSWORD_BYTES, MAX_PROXY_URL_BYTES,
    MAX_PROXY_USERNAME_BYTES, ProxyCredentials, ProxyError, ProxyPolicy,
};
pub use proxy::{TlsConfigError, TlsMaterialRole, TlsMaterialSource};
pub use registry_auth::RegistryAuthenticationResult;
pub use swarm::{
    ConfigCreateOptions, ConfigListOptions, ConfigUpdateOptions, NodeListOptions,
    NodeManagerStatus, NodeRemoveOptions, NodeSpec, NodeUpdateOptions, SecretCreateOptions,
    SecretListOptions, SecretUpdateOptions, ServiceCreateResult, ServiceListOptions,
    ServicePlacement, ServicePort, ServiceRestartPolicy, ServiceSpec, ServiceStatus,
    ServiceUpdateOptions, ServiceUpdateResult, SwarmCertificates, SwarmConfig, SwarmConfigSpec,
    SwarmInfo, SwarmInitOptions, SwarmJoinOptions, SwarmJoinTokenRole, SwarmLeaveOptions,
    SwarmListOptions, SwarmLogOptions, SwarmNode, SwarmSecret, SwarmSecretData, SwarmSecretSpec,
    SwarmService, SwarmSpec, SwarmTask, SwarmTaskStatus, SwarmUnlockKey, SwarmUnlockOptions,
    SwarmUpdateOptions, SwarmVersion, TaskListOptions,
};
pub use system::{
    BuildCachePruneOptions, BuildCachePruneResult, DiskUsage, DiskUsageCategory, DiskUsageItem,
    DiskUsageOptions, DiskUsageType, EventActor, EventOptions, EventStream, SystemEvent,
    SystemInfo,
};
pub use volumes::{
    VolumeCreateOptions, VolumeListOptions, VolumeListResponse, VolumeListResult,
    VolumePruneOptions, VolumePruneResponse, VolumePruneResult, VolumeRemoveOptions,
    VolumeResponse, VolumeSummary, VolumeUsage,
};

const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

/// Docker Engine API version used by the initial client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    /// Major API version.
    pub major: usize,
    /// Minor API version.
    pub minor: usize,
}

/// The Engine API version targeted by the repository-owned client.
pub const API_VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 55,
};

/// The Engine API changes in 1.54 and 1.55 that this crate does not implement.
///
/// Raising [`API_VERSION`] above the former generated client's 1.53 ceiling is a claim, and a claim
/// needs a boundary as much as it needs the number. This is the list, derived
/// from the difference between moby's `api/docs/v1.53.yaml` and `v1.55.yaml`
/// (which is purely additive: no path, definition, field, or required member was
/// removed across the two versions) crossed with `api/docs/CHANGELOG.md`'s
/// per-version notes, which record two daemon behaviour changes that no schema
/// diff can show.
///
/// Each entry is `(version, what the version added, what this crate does)`. All
/// four gaps are real and none of them is visible in this crate's types, which
/// is the whole reason the list is written down rather than inferred.
///
/// The user-facing copy of this table is in `README.md`, which is the crate's
/// documentation through `#![doc = include_str!("../README.md")]`. Keeping it
/// here as well is not duplication for its own sake: `conformance_table_matches_
/// the_readme` fails if the two disagree, so neither copy can quietly fall
/// behind the other.
///
/// Two further 1.55 changes are documentation-only and are recorded in the
/// README rather than here: a `StopTimeout` description that now names the
/// `default-stop-timeout` setting, and clarifications to the `/secrets` and
/// `/configs` filter documentation.
///
/// # Provenance
///
/// So a later reader can re-derive the table rather than trust it:
///
/// - Changelog, per-version notes:
///   <https://github.com/moby/moby/blob/master/api/docs/CHANGELOG.md>
/// - Schema, both documents:
///   <https://github.com/moby/moby/blob/master/api/docs/v1.53.yaml> and
///   <https://github.com/moby/moby/blob/master/api/docs/v1.55.yaml>
/// - The live daemon, whose version gate is the ceiling this crate claims:
///   `GET /v1.56/_ping` answers `400` with `client version 1.56 is too new.
///   Maximum supported API version is 1.55`.
///
/// The two schema documents differ only by addition, which is the finding that
/// makes raising the ceiling safe for everything already implemented: nothing in
/// 1.53 was removed by 1.55, so no existing request shape or response field can
/// have become wrong. The two entries a schema diff cannot show -- the
/// `MacAddress` fix and the per-device blkio fix -- are in the changelog, and
/// both are daemon behaviour changes to fields that already existed.
///
/// This is scoped to `cfg(test)` because it is documentation a test reads rather
/// than code that runs: compiling it only is what lets
/// `every_recorded_addition_is_a_change_above_former_generated_client_and_at_or_below_the_ceiling`
/// and `conformance_table_matches_the_readme` have something to check, which is
/// what keeps it from drifting. An `allow(dead_code)` in a normal build would be
/// the alternative and would be worse — it would suppress the lint on a table
/// nobody was reading.
#[cfg(test)]
pub(crate) const API_VERSION_ADDITIONS: &[(&str, &str, &str)] = &[
    (
        "1.54",
        "`GET /images/json` gains an `identity` query parameter, and each manifest summary gains an `Identity` member",
        "not implemented: the owned list request does not send `identity` and no repository-owned model carries `Identity`",
    ),
    (
        "1.54",
        "`POST /networks/{id}/connect` now applies the `MacAddress` in `EndpointSettings`, which the daemon had accepted and ignored since 1.44",
        "implemented by not needing to be: the owned connect body has always sent `MacAddress`, so the field becomes live rather than inert",
    ),
    (
        "1.55",
        "`GET /images/{name}/attestations`, a new endpoint returning in-toto attestation statements filtered by `platform`, `type`, and `statement`",
        "not implemented: no owned function reaches the endpoint and no model describes an `AttestationStatement`",
    ),
    (
        "1.55",
        "`POST /containers/{id}/update` honours the per-device blkio members it had always accepted and ignored",
        "not implemented and not reachable: `ContainerUpdateOptions` carries only `cpu_shares` and `memory`",
    ),
];

/// The crate's Engine API ceiling, spelled the way the error text spells it.
///
/// Three error messages name the version this crate supports, and all three used
/// to carry a literal. A literal in a message is a claim about the world that no
/// compile step checks and no test notices, so a raised ceiling would leave all
/// three saying a version the crate no longer targets. They read this instead.
pub(crate) fn api_version_ceiling() -> String {
    format!("v{}.{}", API_VERSION.major, API_VERSION.minor)
}

/// Splits a `host:port` endpoint address into an owned-transport target.
///
/// A bare host is given the Engine's default port, which is what Docker's own
/// endpoint resolution does. An address that cannot be split returns `None`
/// rather than a guess, so a caller never dials a port it invented.
fn raw_target_for_address(address: &str) -> Option<raw::RawTarget> {
    let authority = address.rsplit_once("://").map_or(address, |(_, rest)| rest);
    let authority = authority.split('/').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    // A bracketed IPv6 literal keeps its brackets in the authority, and the port
    // separator is the one after the closing bracket.
    let parse_port = |text: &str| text.parse::<u16>().ok();
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let port = remainder
            .strip_prefix(':')
            .map_or(Some(DEFAULT_ENGINE_PORT), parse_port)?;
        (host.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), parse_port(port)?),
            None => (authority.to_owned(), DEFAULT_ENGINE_PORT),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(raw::RawTarget::Tcp {
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
    })
}

/// The port a Docker endpoint uses when the address does not name one.
const DEFAULT_ENGINE_PORT: u16 = 2375;

fn validate_client_version(version: ApiVersion) -> Result<ApiVersion, Error> {
    if version.major != 1 || version.minor > API_VERSION.minor {
        return Err(Error::invalid_api_version());
    }
    Ok(version)
}

/// Selected daemon version fields exposed by the foundation facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonVersion {
    /// Docker daemon version.
    pub version: Option<String>,
    /// Highest API version advertised by the daemon.
    pub api_version: Option<String>,
    /// Minimum API version supported by the daemon.
    pub min_api_version: Option<String>,
    /// Operating system reported by the daemon.
    pub os: Option<String>,
    /// Architecture reported by the daemon.
    pub arch: Option<String>,
}

/// A Docker Engine API error returned by the daemon.
///
/// This is a repository-owned projection of the status and message returned by
/// the Engine. The underlying transport error remains available through
/// [`std::error::Error::source`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerApiError {
    /// HTTP status code returned by the Engine API.
    pub status_code: u16,
    /// Message returned in the Engine API error response.
    pub message: String,
}

impl fmt::Display for DockerApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "daemon returned HTTP {}: {}",
            self.status_code, self.message
        )
    }
}

impl std::error::Error for DockerApiError {}

/// Error category for the facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// The underlying Docker client rejected the request or configuration.
    Docker,
    /// A zero timeout would not provide a useful transport deadline.
    InvalidTimeout,
    /// A socket path was not valid UTF-8.
    InvalidSocketPath,
    /// An SSH identity path was not valid UTF-8.
    InvalidIdentityPath,
    /// The HTTPS endpoint has no context-local TLS material.
    TlsMaterialUnavailable,
    /// The `tls` feature is required for HTTPS endpoints.
    TlsFeatureUnavailable,
    /// The `ssh` feature is required for SSH endpoints.
    SshFeatureUnavailable,
    /// A directly supplied SSH endpoint is invalid.
    InvalidEndpoint,
    /// Docker context resolution failed.
    Context,
    /// A request or response could not be converted between models.
    ///
    /// The `Display` text says "response serialization" for historical
    /// compatibility, including when request conversion fails.
    Serialization,
    /// A repository-owned command option is invalid.
    InvalidInput,
    /// A Swarm resource version cannot be represented by the v1.53 request.
    InvalidVersion,
    /// The selected Engine API version is outside the supported v1.53 range.
    InvalidApiVersion,
    /// Registry credentials are unavailable, invalid, or oversized.
    Credentials,
    /// A caller-owned operation requires an asynchronous runtime.
    Runtime,
    /// Explicit proxy policy or TLS transport configuration is invalid.
    Proxy,
    /// The connection to the daemon failed, or the request or response could not
    /// be completed.
    ///
    /// This is distinct from `InvalidInput`: the caller's request was valid. It
    /// does **not** mean the request had no effect. A transport failure can
    /// happen after dispatch, and a mutation whose response was lost may have
    /// completed; retry only after reconciling the resource.
    Transport,
}

/// Errors returned while constructing or using a Docker client.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    api: Option<DockerApiError>,
}

/// The locally observed transport timeout policy.
///
/// A propagated marker need not belong to the current request. None of these
/// classifications proves a mutation was not processed; reconcile before retrying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportTimeoutKind {
    /// A total request or response-head deadline, not an SSH establishment bound.
    RequestDeadline,
    /// Managed SSH resolution, dialing or session establishment exceeded its bound.
    ManagedSshEstablishment,
    /// An established SSH session accepted no write bytes while a reply or rekey
    /// was outstanding. This is inactivity, not a total request deadline.
    ManagedSshWriteInactivity,
}

/// A timeout marker originally generated by this crate's transport.
#[derive(Debug)]
struct TransportTimeout {
    kind: TransportTimeoutKind,
    message: String,
}

impl fmt::Display for TransportTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TransportTimeout {}

/// Per-request typed I/O observation, retained before hyper can replace a
/// socket failure with a generic cancelled-request error. Never stores text.
#[derive(Clone, Debug, Default)]
pub(crate) struct TransportTimeoutObservation(
    std::sync::Arc<std::sync::Mutex<Option<TransportTimeoutKind>>>,
);

impl TransportTimeoutObservation {
    fn observe(&self, error: &(dyn std::error::Error + 'static)) {
        if let Some(kind) = transport_timeout_in(error) {
            self.0.lock().unwrap().get_or_insert(kind);
        }
    }

    fn kind(&self) -> Option<TransportTimeoutKind> {
        *self.0.lock().unwrap()
    }

    fn error(&self) -> Option<Error> {
        self.kind().map(|kind| {
            Error::transport_timeout(
                kind,
                "a local transport timeout was observed; peer text withheld",
            )
        })
    }
}

/// Recognizes only typed local markers, never text or an OS timeout kind.
fn transport_timeout_in(
    mut error: &(dyn std::error::Error + 'static),
) -> Option<TransportTimeoutKind> {
    loop {
        if let Some(timeout) = error.downcast_ref::<TransportTimeout>() {
            return Some(timeout.kind);
        }
        // io::Error may hide the wrapped value from its ordinary source chain.
        if let Some(inner) = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            && let Some(timeout) = transport_timeout_in(inner)
        {
            return Some(timeout);
        }
        error = error.source()?;
    }
}

impl Error {
    fn serialization(error: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Serialization,
            source: Some(Box::new(error)),
            api: None,
        }
    }

    fn serialization_withheld(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Serialization,
            source: Some(Box::new(std::io::Error::other(message))),
            api: None,
        }
    }

    /// Withholds an Engine rejection's message while preserving its status.
    ///
    /// Used by secret reads: the response text is untrusted, and a daemon or a
    /// proxy can echo secret material in it. The kind and status survive so a
    /// caller can still tell a 404 from a 409; the message and source become
    /// fixed text. Non-API failure text is likewise replaced, retaining locally
    /// typed timeout and managed host-key markers but not the old source chain.
    pub(crate) fn withhold_api_message(self, message: &'static str) -> Self {
        if self.api.is_none() {
            return self.withhold_transport(message, message);
        }
        let api = self.api.map(|api| DockerApiError {
            status_code: api.status_code,
            message: message.to_owned(),
        });
        Self {
            kind: self.kind,
            source: Some(Box::new(std::io::Error::other(message))),
            api,
        }
    }

    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::InvalidInput,
            source: Some(Box::new(std::io::Error::other(message.into()))),
            api: None,
        }
    }

    pub(crate) fn invalid_version() -> Self {
        Self {
            kind: ErrorKind::InvalidVersion,
            source: None,
            api: None,
        }
    }

    /// Records an Engine API rejection reported by the repository-owned
    /// transport.
    ///
    /// The daemon's message is carried through unchanged in
    /// [`Error::api_error`] so a caller can print the daemon's own words under
    /// `--raw-error`. It is stored, never logged or reformatted.
    /// Records a failure to reach the daemon at all.
    ///
    /// The message names both the operation and the target, because
    /// "connection refused" on its own does not say which socket was tried.
    ///
    /// This is public so that a [`StreamFactory`](raw::StreamFactory) written
    /// outside this crate can report a failed open. A factory is handed a
    /// request it has to answer with an [`Error`], and a constructor that is
    /// `pub(crate)` leaves a factory outside the crate with no way to build one.
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Transport,
            source: Some(Box::new(std::io::Error::other(message.into()))),
            api: None,
        }
    }

    pub(crate) fn transport_deadline(message: impl Into<String>) -> Self {
        Self::transport_timeout(TransportTimeoutKind::RequestDeadline, message)
    }

    pub(crate) fn transport_timeout(
        kind: TransportTimeoutKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind: ErrorKind::Transport,
            source: Some(Box::new(TransportTimeout {
                kind,
                message: message.into(),
            })),
            api: None,
        }
    }

    pub(crate) fn transport_source_withheld(
        error: &(dyn std::error::Error + 'static),
        message: &'static str,
    ) -> Self {
        transport_timeout_in(error).map_or_else(
            || Self::withheld(ErrorKind::Transport, message),
            |kind| Self::transport_timeout(kind, message),
        )
    }

    /// Whether this error carries a deadline marker created by this crate's
    /// transport. This does not prove that the current operation itself timed
    /// out: a caller-supplied stream factory can propagate an earlier marked
    /// error. It also does not classify every possible timeout from an external
    /// transport or operating system.
    ///
    /// For a mutation, a deadline does not prove that the daemon did nothing;
    /// reconcile its state before retrying.
    ///
    /// The marker's immediate error source is no longer [`std::io::Error`].
    /// Callers previously downcasting that source for transport deadline
    /// detection should use this predicate instead.
    /// Returns true for request and managed SSH establishment deadlines, but
    /// false for write inactivity. Use [`Self::transport_timeout_kind`] to
    /// distinguish all three policies.
    #[must_use]
    pub fn is_transport_deadline(&self) -> bool {
        matches!(
            self.transport_timeout_kind(),
            Some(
                TransportTimeoutKind::RequestDeadline
                    | TransportTimeoutKind::ManagedSshEstablishment
            )
        )
    }

    /// Returns the locally typed timeout policy, including SSH write inactivity.
    ///
    /// Unlike [`Self::is_transport_deadline`], this distinguishes establishment,
    /// request deadlines and write inactivity. It never infers a classification
    /// from peer text or an arbitrary operating-system timeout.
    #[must_use]
    pub fn transport_timeout_kind(&self) -> Option<TransportTimeoutKind> {
        transport_timeout_in(self)
    }

    /// Replaces unsafe diagnostics while retaining all bounded local markers.
    ///
    /// The marker kind, never its old text or source chain, is copied. Deadline
    /// wording remains operation-specific; write inactivity uses the ordinary
    /// withheld wording but remains distinguishable by its typed kind.
    pub(crate) fn withhold_transport(
        &self,
        message: &'static str,
        deadline_message: &'static str,
    ) -> Self {
        #[cfg(all(feature = "ssh", unix))]
        if let Some(reason) = self.managed_ssh_host_key_rejection() {
            return Self::ssh_host_key_rejected(reason);
        }
        #[cfg(all(feature = "ssh", unix))]
        if let Some(reason) = self.managed_ssh_establishment_failure() {
            return Self::ssh_establishment_failed(reason);
        }
        if let Some(kind) = self.transport_timeout_kind() {
            let message = if self.is_transport_deadline() {
                deadline_message
            } else {
                message
            };
            Self::transport_timeout(kind, message)
        } else {
            Self::withheld(self.kind(), message)
        }
    }

    pub(crate) fn engine_api(status: http::StatusCode, message: String) -> Self {
        let api = DockerApiError {
            status_code: status.as_u16(),
            message,
        };
        Self {
            kind: ErrorKind::Docker,
            // `DockerApiError` is both the source and the structured report, so
            // the message is cloned once here rather than being reconstructed by
            // `Display` and losing the distinction between them.
            source: Some(Box::new(DockerApiError {
                status_code: api.status_code,
                message: api.message.clone(),
            })),
            api: Some(api),
        }
    }

    /// Records an Engine rejection whose response text is withheld.
    ///
    /// Used by operations whose request body is a credential. The status is
    /// preserved; the message is fixed text supplied by the caller, and the
    /// untrusted response body is never read. The fixed text is both
    /// [`Error::api_error`]'s message and the error's source, so `Display`,
    /// `Debug`, and the source chain cannot carry the peer's words.
    pub(crate) fn engine_api_withheld(status: http::StatusCode, message: &'static str) -> Self {
        Self::engine_api(status, message.to_owned())
    }

    /// Replaces a non-API failure with fixed, content-free text of the same
    /// kind.
    ///
    /// Used by operations whose request body is a credential when the failure
    /// did not come from an Engine rejection. A transport or non-API source
    /// chain can carry peer-controlled text, so the original chain is dropped
    /// rather than filtered. The kind is preserved; nothing else is.
    pub(crate) fn withheld(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            source: Some(Box::new(std::io::Error::other(message))),
            api: None,
        }
    }

    fn invalid_api_version() -> Self {
        Self {
            kind: ErrorKind::InvalidApiVersion,
            source: None,
            api: None,
        }
    }

    /// The class of failure, for a caller that wants to branch on it rather than
    /// match on the message.
    ///
    /// The [`Display`](std::fmt::Display) rendering is what a log wants; this is
    /// what a `match` wants.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the Engine API status and message when the daemon rejected the
    /// request.
    #[must_use]
    pub fn api_error(&self) -> Option<&DockerApiError> {
        self.api.as_ref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            // The daemon's own words are included when there are any. A bare
            // "Docker client error" is useless in a log line or a panic message:
            // it is the one case where the underlying cause is known and was
            // simply not being shown. The CLI already reads `api_error()` and
            // formats its own message, so this does not change what a user sees
            // there — it makes the error readable wherever it is printed.
            ErrorKind::Docker => match &self.api {
                Some(api) => write!(
                    formatter,
                    "Docker API error {}: {}",
                    api.status_code, api.message
                ),
                None => write!(formatter, "Docker client error"),
            },
            ErrorKind::InvalidTimeout => {
                write!(formatter, "Docker client timeout must be positive")
            }
            ErrorKind::InvalidSocketPath => {
                write!(formatter, "Docker socket path is not valid UTF-8")
            }
            ErrorKind::InvalidIdentityPath => {
                write!(formatter, "Docker SSH identity path is not valid UTF-8")
            }
            ErrorKind::TlsMaterialUnavailable => {
                write!(formatter, "Docker HTTPS endpoint has no TLS material")
            }
            ErrorKind::TlsFeatureUnavailable => {
                write!(formatter, "Docker HTTPS support requires the tls feature")
            }
            ErrorKind::SshFeatureUnavailable => {
                write!(formatter, "Docker SSH support requires the ssh feature")
            }
            ErrorKind::InvalidEndpoint => write!(formatter, "Docker SSH endpoint is invalid"),
            ErrorKind::Context => write!(formatter, "Docker context resolution failed"),
            ErrorKind::Serialization => {
                write!(formatter, "Docker response serialization error")
            }
            // The specific reason is included, as `Runtime` does. An
            // invalid-input error that cannot say *what* was invalid is the one
            // a caller cannot act on: the category alone is the same text for
            // every bad argument the crate rejects.
            ErrorKind::InvalidInput => {
                if let Some(source) = &self.source {
                    write!(formatter, "Docker command input is invalid: {source}")
                } else {
                    write!(formatter, "Docker command input is invalid")
                }
            }
            ErrorKind::InvalidVersion => {
                write!(
                    formatter,
                    "Docker resource version is outside the {} range",
                    api_version_ceiling()
                )
            }
            ErrorKind::InvalidApiVersion => {
                write!(
                    formatter,
                    "Docker Engine API version must be v{}.x no higher than {}",
                    API_VERSION.major,
                    api_version_ceiling()
                )
            }
            ErrorKind::Credentials => write!(formatter, "Docker registry credentials are invalid"),
            ErrorKind::Runtime => {
                if let Some(source) = &self.source {
                    write!(formatter, "Docker operation failed: {source}")
                } else {
                    write!(formatter, "Docker operation requires a Tokio runtime")
                }
            }
            ErrorKind::Proxy => {
                if let Some(source) = &self.source {
                    write!(
                        formatter,
                        "Docker proxy or TLS configuration is invalid: {source}"
                    )
                } else {
                    write!(formatter, "Docker proxy configuration is invalid")
                }
            }
            // Names the operation and the target, as `Error::transport`'s
            // documentation promises. It did not: every transport failure
            // rendered as the bare string "Docker transport error", and the
            // message was reachable only through `source()` -- which nothing
            // documented as the way to read it. Measured: a response truncated
            // mid-body printed `truncated HTTP: Some("Docker transport error")`
            // where the parse cause alongside it printed in full.
            //
            // The reason is rendered here rather than hidden, because this crate
            // keeps daemon and transport text out of *types that carry payloads*:
            // `raw/logs.rs` records that rule for log frames, and a
            // `std::io::Error`'s message is a diagnostic string with no payload
            // in it. What must not happen is a secret reaching it, and a
            // connection error carries a socket path, not a credential.
            ErrorKind::Transport => {
                let reason = self.source.as_ref().map(std::string::ToString::to_string);
                match reason {
                    Some(reason) => write!(formatter, "Docker transport error: {reason}"),
                    None => formatter.write_str("Docker transport error"),
                }
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<ContextError> for Error {
    fn from(error: ContextError) -> Self {
        Self {
            kind: ErrorKind::Context,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

impl From<CredentialError> for Error {
    fn from(error: CredentialError) -> Self {
        Self {
            kind: ErrorKind::Credentials,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

impl From<ProxyError> for Error {
    fn from(error: ProxyError) -> Self {
        Self {
            kind: ErrorKind::Proxy,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

impl From<TlsConfigError> for Error {
    fn from(error: TlsConfigError) -> Self {
        // TLS material is an explicit transport configuration failure. It keeps
        // the existing `Proxy` kind, and the typed role/source is preserved in
        // the source chain instead of adding a public enum variant.
        Self {
            kind: ErrorKind::Proxy,
            source: Some(Box::new(error)),
            api: None,
        }
    }
}

/// A Docker Engine client using the repository's initial API version.
#[derive(Clone, Debug)]
pub struct DockerClient {
    proxy_policy: ProxyPolicy,
    /// Where the owned transport connects, when that transport can reach the
    /// endpoint at all.
    ///
    /// `None` is a real answer, not a placeholder: an SSH endpoint needs an
    /// OpenSSH child process, and the owned transport has none until one is
    /// described. Keeping that apart rather than guessing is what lets
    /// [`Self::raw_engine`] say which endpoint kind it cannot serve instead of
    /// failing later with a connection error.
    raw_target: OwnedTarget,
    /// Whether the captured target came from the local constructor.
    local_target: bool,
    /// The response-head deadline for the owned transport, when one applies.
    ///
    /// This is `None` for every existing target: a Unix socket, a named pipe,
    /// plain HTTP, SSH, or a caller-supplied stream keeps the raw transport's
    /// existing unbounded response-head behavior. Only the HTTPS constructors
    /// install a deadline, because HTTPS is the route whose response head was
    /// previously reached through the former generated client's bounded client.
    raw_response_head_deadline: Option<Duration>,
    /// The API version the owned transport prefixes onto every path.
    raw_version: ApiVersion,
    /// Test-only override for the local secret-read overall budget.
    ///
    /// Production has no setter and this field does not exist outside a test
    /// build. It lets the facade's short-budget test drive the public
    /// `inspect_secret` path without waiting 120 seconds.
    #[cfg(test)]
    secret_read_budget_override: Option<Duration>,
}

/// The owned endpoint selected when the client is built.
///
/// Operations use this target exclusively. An unavailable target returns an
/// error; no generated-client fallback is attempted.
#[derive(Clone, Debug)]
enum OwnedTarget {
    /// The owned transport reaches this endpoint.
    Reachable(raw::RawTarget),
    /// The owned transport reaches this endpoint under a managed SSH policy.
    ///
    /// It is kept apart from [`Self::Reachable`] so an operation that must not
    /// dispatch a credential can return the stable local gate diagnostic before
    /// sending anything. Other operations still reach the gate through
    /// [`DockerClient::raw_engine`], where it reports the same fixed message.
    #[cfg_attr(
        not(all(feature = "ssh", unix)),
        allow(
            dead_code,
            reason = "the managed SSH constructor is compiled only with ssh on unix"
        )
    )]
    ManagedSsh(raw::RawTarget, Option<Duration>, bool),
    /// The owned transport reaches this endpoint through an explicit plain-HTTP
    /// forward proxy.
    ///
    /// The target keeps the daemon's authority so the owned request preserves
    /// the target URL and `Host`; the proxy route is what the transport dials.
    ProxiedHttp {
        /// The daemon target, whose authority is sent in the request.
        target: raw::RawTarget,
        /// The proxy the transport dials instead of the daemon.
        proxy: raw::HttpProxyRoute,
    },
    /// It does not, and this is the reason it could not be built.
    #[cfg(test)]
    Unreachable(String),
}

impl OwnedTarget {}

/// The fixed reason a secret read fails when no owned target exists.
///
/// A secret read never falls back to the generated client: the former generated client logs the
/// whole response body at debug level before decoding it, and this crate cannot
/// make that safe. The message says no request was sent and names the ways to
/// build a client whose owned transport can dial.
const SECRET_READ_UNREACHABLE: &str = "secret reads require the repository-owned transport and \
    do not fall back to the generated client, which logs the response body at debug level; this \
    endpoint has no owned target, so no request was sent. Build the client with an explicit Unix \
    socket, TCP, or fully described ssh:// endpoint, or use connect_local, which captures the \
    platform's local socket";

impl DockerClient {
    /// Authenticate with the Engine's registry endpoint. Error diagnostics and
    /// Debug output withhold response text and credentials.
    ///
    /// # Errors
    /// Returns a content-free error on failure, retaining an observed HTTP status.
    pub async fn registry_authenticate(
        &self,
        auth: &raw::RegistryAuthentication<'_>,
    ) -> Result<raw::RegistryAuthenticationResult, Error> {
        let engine = self.raw_engine().map_err(|e| {
            e.withhold_transport(
                "registry authentication response withheld",
                "registry authentication response withheld",
            )
        })?;
        raw::registry_authenticate(&engine, auth).await
    }

    /// Inspect distribution metadata, including the Engine's platform list.
    /// This does not return downloaded manifests or layers.
    ///
    /// # Errors
    /// Returns an error on an invalid name, transport failure, rejection, or malformed JSON.
    pub async fn distribution_inspect(&self, name: &str) -> Result<serde_json::Value, Error> {
        raw::distribution_inspect(&self.raw_engine()?, name).await
    }

    /// List platforms reported by the Engine for an image distribution.
    /// This is not a registry repository listing.
    ///
    /// # Errors
    /// Returns an error on transport, rejection, or malformed metadata.
    pub async fn distribution_list(&self, name: &str) -> Result<Vec<serde_json::Value>, Error> {
        raw::distribution_list(&self.raw_engine()?, name).await
    }

    fn from_target(
        raw_target: OwnedTarget,
        proxy_policy: ProxyPolicy,
        raw_version: ApiVersion,
    ) -> Self {
        Self {
            proxy_policy,
            raw_target,
            local_target: false,
            raw_response_head_deadline: None,
            raw_version,
            #[cfg(test)]
            secret_read_budget_override: None,
        }
    }

    /// Builds the owned transport for this client.
    ///
    /// Local clients use the endpoint captured at construction. HTTPS and
    /// explicit proxy routes retain their configured deadlines and policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the client has no reachable owned target.
    pub fn raw_engine(&self) -> Result<raw::RawEngine, Error> {
        match &self.raw_target {
            OwnedTarget::Reachable(target) => {
                Ok(raw::RawEngine::new(target.clone(), self.raw_version)
                    .with_response_head_deadline(self.raw_response_head_deadline))
            }
            OwnedTarget::ManagedSsh(target, deadline, _) => {
                Ok(raw::RawEngine::new(target.clone(), self.raw_version)
                    .with_response_head_deadline(self.raw_response_head_deadline)
                    .with_overall_request_deadline(*deadline))
            }
            OwnedTarget::ProxiedHttp { target, proxy } => {
                Ok(raw::RawEngine::new(target.clone(), self.raw_version)
                    .with_response_head_deadline(self.raw_response_head_deadline)
                    .with_http_proxy(proxy.clone()))
            }
            #[cfg(test)]
            OwnedTarget::Unreachable(reason) => Err(Error::invalid_input(format!(
                "the owned transport cannot reach this endpoint: {reason}"
            ))),
        }
    }

    /// Builds a secret-read engine, preserving the local request deadline.
    ///
    /// The local budget covers connection through the response head, but not
    /// the response body. Other routes retain their configured policy.
    ///
    /// # Errors
    ///
    /// Returns a fixed error if no owned target exists.
    pub(crate) fn secret_read_engine(&self) -> Result<raw::RawEngine, Error> {
        let engine = self
            .raw_engine()
            .map_err(|_| Error::invalid_input(SECRET_READ_UNREACHABLE))?;
        if self.local_target {
            #[cfg(test)]
            let budget = self
                .secret_read_budget_override
                .unwrap_or(LOCAL_SECRET_READ_BUDGET);
            #[cfg(not(test))]
            let budget = LOCAL_SECRET_READ_BUDGET;
            Ok(engine.with_overall_request_deadline(Some(budget)))
        } else {
            Ok(engine)
        }
    }

    /// Returns whether the owned target is a managed SSH client.
    ///
    /// The gate is open by default, but may be explicitly closed. An
    /// operation that must not dispatch a credential can ask this and return the
    /// stable local gate diagnostic instead of sending a request whose fixed
    /// error would otherwise be replaced by a generic withheld message.
    pub(crate) fn uses_managed_ssh_gate(&self) -> bool {
        matches!(self.raw_target, OwnedTarget::ManagedSsh(..))
    }

    /// Returns the authoritative managed SSH gate decision, when this target is
    /// managed SSH.
    ///
    /// `None` means the target is not managed SSH. `Some(Ok(()))` means the gate
    /// is open and the caller must follow its normal route; `Some(Err(_))` is
    /// the transport's own fixed local gate diagnostic. The decision comes from
    /// [`crate::ssh_neotales::managed_establishment_gate`], the same function
    /// the managed transport calls before opening a session, so the facade and
    /// the transport cannot disagree.
    pub(crate) fn managed_ssh_gate(&self) -> Option<Result<(), Error>> {
        if !self.uses_managed_ssh_gate() {
            return None;
        }
        #[cfg(all(feature = "ssh", unix))]
        {
            let OwnedTarget::ManagedSsh(_, _, require_closed) = &self.raw_target else {
                unreachable!("managed target checked above")
            };
            Some(crate::ssh_neotales::managed_establishment_gate(
                *require_closed,
            ))
        }
        #[cfg(not(all(feature = "ssh", unix)))]
        {
            // `OwnedTarget::ManagedSsh` is constructed only by the managed SSH
            // constructor, which is compiled under the same cfg.
            None
        }
    }

    /// Connects using Docker's configured endpoint and environment defaults.
    ///
    /// This honors `DOCKER_HOST` when set and otherwise uses the platform
    /// default. Endpoint resolution selects the crate's API ceiling (v1.55);
    /// all facade requests use the owned transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured endpoint is invalid or unsupported.
    pub fn connect_defaults() -> Result<Self, Error> {
        let resolver = ContextResolver::from_environment()?;
        let selection = resolver.resolve()?;
        Self::connect_endpoint_with_version(&selection.endpoint, selection.client_version)
    }

    /// Connects using Docker's configured endpoint and an explicit proxy
    /// policy.
    ///
    /// Context and endpoint selection remain unchanged; only the caller's
    /// explicit `ProxyPolicy` chooses the TCP transport route.
    ///
    /// # Errors
    ///
    /// Returns an error when context resolution fails or the policy is not
    /// valid for the selected endpoint.
    pub fn connect_defaults_with_policy(policy: ProxyPolicy) -> Result<Self, Error> {
        let resolver = ContextResolver::from_environment()?;
        let selection = resolver.resolve()?;
        Self::connect_endpoint_with_version_and_policy(
            &selection.endpoint,
            policy,
            selection.client_version,
        )
    }

    /// Connects to a typed Docker endpoint without a proxy.
    ///
    /// This method is the direct-policy path. It does not inspect process
    /// proxy environment variables. Use
    /// [`Self::connect_endpoint_with_policy`] for an explicit forward proxy.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is unavailable or its required
    /// transport feature is not enabled.
    pub fn connect_endpoint(endpoint: &Endpoint) -> Result<Self, Error> {
        Self::connect_endpoint_with_version(endpoint, API_VERSION)
    }

    /// Connects to a typed Docker endpoint with an explicit Engine API version.
    ///
    /// The version is applied to HTTP, socket, TLS, and SSH transports. It must
    /// be a v1 version no higher than the facade's v1.55 ceiling. The method
    /// does not contact the daemon while constructing the client.
    ///
    /// For an HTTPS endpoint, the CA bundle and client identity are loaded and
    /// validated while the client is built, so malformed material is reported
    /// here rather than on the first request. The owned transport's HTTPS target
    /// receives the same explicit version. A material failure is
    /// [`ErrorKind::Proxy`] with a [`TlsConfigError`] source carrying the failed
    /// role and a content-free reason.
    ///
    /// The owned transport uses the caller's selected version on every route.
    ///
    /// # Errors
    ///
    /// Returns an error when the version is outside the supported range, the
    /// endpoint is unavailable, or its required transport feature is not
    /// enabled.
    pub fn connect_endpoint_with_version(
        endpoint: &Endpoint,
        version: ApiVersion,
    ) -> Result<Self, Error> {
        let version = validate_client_version(version)?;
        match endpoint {
            Endpoint::Unix(path) => Ok(Self::from_target(
                OwnedTarget::Reachable(raw::RawTarget::Unix(path.clone())),
                ProxyPolicy::Direct,
                version,
            )),
            Endpoint::NamedPipe(path) => Ok(Self::from_target(
                OwnedTarget::Reachable(raw::RawTarget::NamedPipe(path.into())),
                ProxyPolicy::Direct,
                version,
            )),
            Endpoint::Http(address) => Self::connect_http_with_version(address, version),
            Endpoint::Https { address, material } => {
                #[cfg(feature = "tls")]
                {
                    let material = material.as_ref().ok_or(Error {
                        kind: ErrorKind::TlsMaterialUnavailable,
                        source: None,
                        api: None,
                    })?;
                    let target = proxy::raw_https_target(
                        address,
                        material,
                        &ProxyPolicy::Direct,
                        TlsServerTrust::Verify,
                    )?;
                    let mut client = Self::from_target(
                        OwnedTarget::Reachable(target),
                        ProxyPolicy::Direct,
                        version,
                    );
                    client.raw_response_head_deadline =
                        Some(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
                    Ok(client)
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = (address, material);
                    Err(Error {
                        kind: ErrorKind::TlsFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
            Endpoint::Ssh {
                address,
                identity_path,
            } => {
                #[cfg(all(feature = "ssh", unix))]
                {
                    Self::connect_ssh_inner(
                        address,
                        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
                        identity_path.as_deref(),
                        version,
                    )
                }
                #[cfg(not(all(feature = "ssh", unix)))]
                {
                    let _ = (address, identity_path);
                    Err(Error {
                        kind: ErrorKind::SshFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
        }
    }

    /// Connects to a typed Docker endpoint with an explicit version and proxy.
    ///
    /// This is the version-aware counterpart to
    /// [`Self::connect_endpoint_with_policy`]. Proxy selection and validation
    /// are otherwise unchanged. TLS material for an HTTPS endpoint is loaded and
    /// validated while the client is built, for the direct and proxied paths
    /// alike.
    ///
    /// A plain-HTTP endpoint under `ProxyPolicy::Http` gets an owned proxy route
    /// with one 120-second overall request budget covering the proxy connect,
    /// request-body production/backpressure, and the response head. The response
    /// body is not wrapped by it. The configured proxy credential is sent only on
    /// that route; a caller-supplied `Proxy-Authorization` is rejected by the
    /// owned transport. A proxy that cannot be reached is an error, not a direct
    /// connection.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, invalid proxy policy, or
    /// unsupported endpoint/proxy combination.
    pub fn connect_endpoint_with_version_and_policy(
        endpoint: &Endpoint,
        policy: ProxyPolicy,
        version: ApiVersion,
    ) -> Result<Self, Error> {
        let version = validate_client_version(version)?;
        match (&policy, endpoint) {
            (ProxyPolicy::Direct, _) => Self::connect_endpoint_with_version(endpoint, version),
            (ProxyPolicy::Http(proxy), Endpoint::Http(address)) => {
                let (target, proxy) = proxy::raw_http_target(address, proxy)?;
                Ok(Self::from_target(
                    OwnedTarget::ProxiedHttp { target, proxy },
                    policy,
                    version,
                ))
            }
            (ProxyPolicy::Http(_), Endpoint::Https { address, material }) => {
                let material = material.as_ref().ok_or(Error {
                    kind: ErrorKind::TlsMaterialUnavailable,
                    source: None,
                    api: None,
                })?;
                #[cfg(feature = "tls")]
                {
                    let target = proxy::raw_https_target(
                        address,
                        material,
                        &policy,
                        TlsServerTrust::Verify,
                    )?;
                    let mut client =
                        Self::from_target(OwnedTarget::Reachable(target), policy, version);
                    client.raw_response_head_deadline =
                        Some(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
                    Ok(client)
                }
                #[cfg(not(feature = "tls"))]
                {
                    let _ = (address, material);
                    Err(Error {
                        kind: ErrorKind::TlsFeatureUnavailable,
                        source: None,
                        api: None,
                    })
                }
            }
            (ProxyPolicy::Http(_), _) => Err(ProxyError::EndpointNotProxyable.into()),
        }
    }

    /// Connects to a typed Docker endpoint with an explicit proxy policy.
    ///
    /// The default [`ProxyPolicy::Direct`] never reads process proxy variables.
    /// A [`ProxyPolicy::Http`] policy is accepted only for TCP HTTP/HTTPS
    /// endpoints; Unix sockets, named pipes, and SSH are rejected rather than
    /// silently ignoring the policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid proxy policy, an unsupported endpoint
    /// combination, missing TLS material, or an unavailable required feature.
    pub fn connect_endpoint_with_policy(
        endpoint: &Endpoint,
        policy: ProxyPolicy,
    ) -> Result<Self, Error> {
        Self::connect_endpoint_with_version_and_policy(endpoint, policy, API_VERSION)
    }

    /// Connects to an HTTPS daemon with an explicit server trust policy.
    ///
    /// Existing constructors always verify. Only an explicit
    /// [`TlsServerTrust::AllowExpiredOrUntrusted`] bypasses server trust, time,
    /// and hostname checks. Client identity and CA files remain required and
    /// must load successfully; missing files never enable a bypass. A material
    /// failure is [`ErrorKind::Proxy`] with a [`TlsConfigError`] source carrying
    /// the failed role and a content-free reason. This replaces the proxied
    /// route's previous [`ProxyError::TlsConfiguration`] source and the direct
    /// route's former generated-client error; source downcasts must target
    /// [`TlsConfigError`].
    /// No proxy environment variables are read.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid addresses, proxy policy, or TLS material.
    #[cfg(feature = "tls")]
    pub fn connect_https_with_trust(
        address: &str,
        material: &TlsMaterial,
        policy: ProxyPolicy,
        trust: TlsServerTrust,
    ) -> Result<Self, Error> {
        let target = proxy::raw_https_target(address, material, &policy, trust)?;
        let mut client = Self::from_target(OwnedTarget::Reachable(target), policy, API_VERSION);
        client.raw_response_head_deadline = Some(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS));
        Ok(client)
    }

    /// Connects to the platform's default local Docker endpoint.
    ///
    /// The owned transport uses the captured socket or named pipe directly.
    ///
    /// # Errors
    ///
    /// Returns an error when the local endpoint cannot be constructed.
    pub fn connect_local() -> Result<Self, Error> {
        // Capture the endpoint once so later environment changes cannot move it.
        let host = std::env::var("DOCKER_HOST").ok();
        let endpoint = local_endpoint_from_host(host.as_deref()).ok_or_else(|| {
            Error::invalid_input(String::from(
                "this platform has no default local Docker endpoint",
            ))
        })?;
        Ok(connect_local_from_endpoint(endpoint))
    }

    /// Connects to an explicit plain HTTP endpoint without a proxy.
    ///
    /// Use [`Self::connect_endpoint_with_policy`] with an explicit
    /// [`ProxyPolicy::Http`] when forwarding is required. This direct method
    /// does not inspect process proxy environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is invalid.
    pub fn connect_http(endpoint: &str) -> Result<Self, Error> {
        Self::connect_http_with_version(endpoint, API_VERSION)
    }

    /// Builds a plain-HTTP client using the selected owned API version.
    fn connect_http_with_version(endpoint: &str, version: ApiVersion) -> Result<Self, Error> {
        let parsed = Endpoint::parse(endpoint).map_err(|source| Error {
            kind: ErrorKind::InvalidEndpoint,
            source: Some(Box::new(source)),
            api: None,
        })?;
        let Endpoint::Http(address) = parsed else {
            return Err(Error::invalid_input("expected a plain HTTP endpoint"));
        };
        let target = raw_target_for_address(&address)
            .ok_or_else(|| Error::invalid_input("invalid plain HTTP endpoint"))?;
        Ok(Self::from_target(
            OwnedTarget::Reachable(target),
            ProxyPolicy::Direct,
            version,
        ))
    }

    /// Connects to a Unix socket or Windows named pipe path.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is invalid or unavailable.
    pub fn connect_socket(path: &std::path::Path) -> Result<Self, Error> {
        std::fs::metadata(path).map_err(|source| Error {
            kind: ErrorKind::Docker,
            source: Some(Box::new(source)),
            api: None,
        })?;
        #[cfg(windows)]
        let target = raw::RawTarget::NamedPipe(path.to_path_buf());
        #[cfg(not(windows))]
        let target = raw::RawTarget::Unix(path.to_path_buf());
        Ok(Self::from_target(
            OwnedTarget::Reachable(target),
            ProxyPolicy::Direct,
            API_VERSION,
        ))
    }

    /// Connects to Docker over native OpenSSH.
    ///
    /// This requires the crate's `ssh` feature. The owned transport spawns
    /// the native `ssh` binary and runs `docker system dial-stdio`.
    /// Host-key checking, identity discovery, the agent, and connection
    /// multiplexing are the invoking user's OpenSSH configuration, so an
    /// unknown or changed host is handled by that policy rather than by an
    /// option this crate injects. A port named by the endpoint, including
    /// `:22`, is passed as `-p`; a port the endpoint did not name is left to
    /// `ssh_config`.
    ///
    /// The managed [`Self::connect_ssh_with_known_hosts`] alternative is a
    /// separate, explicit choice; its failures never downgrade to native OpenSSH.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid timeout or SSH configuration.
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
    ) -> Result<Self, Error> {
        Self::connect_ssh_inner(endpoint, timeout, identity_path, API_VERSION)
    }

    /// Builds a managed SSH client with an explicit known-hosts file.
    ///
    /// Managed SSH is open by default; see
    /// [`Self::connect_ssh_managed`]. This constructor never falls back to
    /// native OpenSSH.
    ///
    /// This describes the managed `neotales-ssh` mechanism, not native
    /// OpenSSH. The client is built without connecting; requests can read the
    /// named file and use the credential.
    ///
    /// This is [`Self::connect_ssh_managed`] with the two settings this signature
    /// can express named as arguments: a timeout, and an unencrypted identity
    /// file if a path was given. Everything else the managed client can do — an
    /// encrypted identity and its passphrase, or an SSH password — is a method
    /// on the builder this is built from, because each of those needs a value of
    /// its own and a fifth positional parameter is what makes a signature
    /// unreadable.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing credential, invalid endpoint, or invalid
    /// timeout. It does not validate or read the identity or known-hosts file.
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh_with_known_hosts(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
        known_hosts_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let builder = Self::connect_ssh_managed(endpoint, known_hosts_path).timeout(timeout);
        let builder = match identity_path {
            Some(path) => builder.identity_file(path),
            None => builder,
        };
        builder.connect()
    }

    /// Starts describing a managed `neotales-ssh` connection to a remote Engine.
    ///
    /// The gate is open by default: managed requests can resolve, dial, read
    /// `known_hosts` and identity material, handshake, authenticate, run
    /// `docker system dial-stdio` remotely and carry Engine requests.
    /// Building a client does not connect. [`ManagedSshClient::require_closed`]
    /// explicitly refuses requests before DNS, file or network work.
    ///
    /// A named known-hosts path supplies pre-provisioned, read-only trust rather
    /// than ambient OpenSSH config.
    ///
    /// A credential must be supplied before calling `connect`; no ambient
    /// identity or agent is consulted.
    ///
    /// Establishment timeout defaults to 30 seconds, write inactivity to 120
    /// seconds, and the connection-through-response-head `request_deadline` to
    /// none (body excluded). Without `request_deadline`, a silent peer can leave
    /// a request waiting for a response head indefinitely. Control traffic
    /// interleaved with a blocked write instead reaches the write-inactivity
    /// bound and fails the session closed: a bounded failure, not a hang.
    ///
    /// The opt-in no-socket password fixture requires
    /// `NEOTALES_DOCKER_OPENSSH_PASSWORD=1` and a Docker daemon. Verified locally
    /// against OpenSSH 9.2, it is not in the default gate and does not prove PAM
    /// or real Docker `dial-stdio`.
    /// Native `ssh` remains a separate, explicit choice; managed failures never
    /// silently downgrade to it.
    ///
    /// Managed response diagnostics withhold peer failure text for every
    /// operation, preserving HTTP status and safe typed deadline/host-key
    /// markers. Wording may be operation-specific, but is content-free. This is
    /// stricter than native SSH because managed SSH carries arbitrary Engine
    /// traffic. See [`ManagedSshClient::connect`] for the policy and fixed wording.
    /// Server authentication refusal remains distinguishable through
    /// [`Error::is_managed_ssh_authentication_rejected`]; it does not imply a
    /// password is necessarily wrong. Unclassified establishment details,
    /// including channel-open refusal descriptions, are withheld at the boundary.
    /// [`Error::managed_ssh_establishment_failure`] distinguishes unavailable
    /// authentication methods/signature algorithms, channel-open refusal and
    /// local identity-file failure. The handshake requests RFC 8308
    /// `server-sig-algs`; an incompatible key need not be offered at all.
    ///
    /// # Errors
    ///
    /// This cannot fail; the error comes from [`ManagedSshClient::connect`].
    #[cfg(all(feature = "ssh", unix))]
    pub fn connect_ssh_managed(
        endpoint: &str,
        known_hosts_path: &std::path::Path,
    ) -> ManagedSshClient {
        ManagedSshClient::new(endpoint, known_hosts_path)
    }

    /// The body of [`ManagedSshClient::connect`].
    ///
    /// # Errors
    ///
    /// Returns an error for a zero timeout, a path that is not valid UTF-8, and
    /// a connection policy whose limits cannot be honoured. The endpoint and the
    /// credential have already been checked by the time this is called.
    #[cfg(all(feature = "ssh", unix))]
    pub(crate) fn connect_ssh_managed_inner(
        options: crate::ssh_neotales::ManagedSshOptions,
    ) -> Result<Self, Error> {
        options.validate()?;
        let request_deadline = options.request_deadline;
        let require_closed = options.require_closed;
        Ok(Self::from_target(
            OwnedTarget::ManagedSsh(
                crate::ssh_neotales::managed_ssh_target(options),
                request_deadline,
                require_closed,
            ),
            ProxyPolicy::Direct,
            API_VERSION,
        ))
    }

    /// Builds the owned `RawTarget` for an `ssh://` endpoint reached with the
    /// native `ssh` binary.
    ///
    /// The managed `neotales-ssh` mechanism has its own constructor,
    /// [`Self::connect_ssh_managed`], because it needs a credential and a
    /// connection policy that this four-argument signature has nowhere to put.
    /// There is no reason for a managed target to pass through here, so it does
    /// not.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is not an `ssh://` endpoint or cannot
    /// be split into a destination.
    #[cfg(all(feature = "ssh", unix))]
    fn ssh_raw_target(
        endpoint: &str,
        identity_path: Option<&std::path::Path>,
    ) -> Result<raw::RawTarget, Error> {
        let parsed = Endpoint::parse(endpoint).map_err(|source| Error {
            kind: ErrorKind::InvalidEndpoint,
            source: Some(Box::new(source)),
            api: None,
        })?;
        if !matches!(parsed, Endpoint::Ssh { .. }) {
            return Err(Error {
                kind: ErrorKind::InvalidEndpoint,
                source: None,
                api: None,
            });
        }
        let destination = ssh_dial_stdio::SshDestination::parse(endpoint)?;
        Ok(crate::ssh_dial_stdio::native_ssh_target(
            destination.native_options(
                "ssh",
                identity_path.map(std::path::Path::to_path_buf),
                None,
            ),
        ))
    }

    /// The shared body of both `ssh://` constructors, for the native `ssh`
    /// binary only.
    ///
    /// # Errors
    ///
    /// Returns an error for an address that is not an `ssh://` endpoint, a zero
    /// timeout, or a path that is not valid UTF-8.
    #[cfg(all(feature = "ssh", unix))]
    fn connect_ssh_inner(
        endpoint: &str,
        timeout: Duration,
        identity_path: Option<&std::path::Path>,
        version: ApiVersion,
    ) -> Result<Self, Error> {
        if timeout.as_secs() == 0 {
            return Err(Error {
                kind: ErrorKind::InvalidTimeout,
                source: None,
                api: None,
            });
        }
        let target = Self::ssh_raw_target(endpoint, identity_path)?;
        Ok(Self::from_target(
            OwnedTarget::Reachable(target),
            ProxyPolicy::Direct,
            version,
        ))
    }

    /// Returns the explicit proxy policy selected for this client.
    #[must_use]
    pub const fn proxy_policy(&self) -> &ProxyPolicy {
        &self.proxy_policy
    }

    /// Returns the response-head deadline installed for the owned transport.
    ///
    /// This is a test-only view of the per-endpoint policy: HTTPS installs the
    /// transport deadline; every other endpoint leaves it unset.
    #[cfg(test)]
    pub(crate) fn raw_response_head_deadline_for_test(&self) -> Option<Duration> {
        self.raw_response_head_deadline
    }

    /// Shortens the overall budget of a configured plain-HTTP proxy route.
    ///
    /// This exists so a unit test can exercise the facade's `wait`, `stop`, and
    /// `restart` policy without waiting the production 120 seconds. It has no
    /// effect on a client without a plain-HTTP proxy route.
    #[cfg(test)]
    pub(crate) fn set_proxy_overall_deadline_for_test(&mut self, deadline: Duration) {
        if let OwnedTarget::ProxiedHttp { proxy, .. } = &mut self.raw_target {
            proxy.set_overall_deadline(deadline);
        }
    }

    /// Returns the API version used by the owned transport.
    #[must_use]
    pub fn client_version(&self) -> ApiVersion {
        self.raw_version
    }

    /// Negotiates the API version down to the daemon's supported version.
    ///
    /// The client never raises its configured version; negotiation only lowers.
    ///
    /// # Errors
    ///
    /// Returns an error when the daemon version cannot be read or parsed.
    pub async fn negotiate_version(mut self) -> Result<Self, Error> {
        let document = raw::negotiation_version(&self.raw_engine()?).await?;
        let text = document
            .get("ApiVersion")
            .and_then(|value| value.as_str())
            .ok_or_else(Error::invalid_version)?;
        let mut parts = text.split('.');
        let parse = |part: Option<&str>| -> Result<usize, Error> {
            let part = part.ok_or_else(Error::invalid_version)?;
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::invalid_version());
            }
            part.parse().map_err(|_| Error::invalid_version())
        };
        let advertised = ApiVersion {
            major: parse(parts.next())?,
            minor: parse(parts.next())?,
        };
        if parts.next().is_some() {
            return Err(Error::invalid_version());
        }
        if (advertised.major, advertised.minor) < (self.raw_version.major, self.raw_version.minor) {
            self.raw_version = advertised;
        }
        Ok(self)
    }

    /// Sends a ping request and returns the daemon's capability headers.
    ///
    /// The value contains the advertised API version, operating system,
    /// experimental flag, builder version, and Swarm status when present.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the daemon is unavailable.
    pub async fn ping(&self) -> Result<raw::Ping, Error> {
        raw::ping(&self.raw_engine()?).await
    }

    /// Returns selected daemon version information from the owned transport.
    ///
    /// # Errors
    ///
    /// Returns a transport, daemon, or response decoding error.
    pub async fn version(&self) -> Result<DaemonVersion, Error> {
        Ok(raw::version_report(&self.raw_engine()?)
            .await?
            .into_daemon_version())
    }

    /// Returns the validated daemon version response as repository-owned JSON.
    ///
    /// # Errors
    ///
    /// Returns a transport, daemon, or response decoding error.
    pub async fn version_value(&self) -> Result<serde_json::Value, Error> {
        Ok(raw::version_report(&self.raw_engine()?)
            .await?
            .into_document())
    }

    /// Lists images using repository-owned options.
    ///
    /// The response contains the stable v1.53 image-summary fields supported by
    /// this crate. Experimental manifest and descriptor fields remain outside
    /// this first resource boundary.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn list_images(
        &self,
        options: Option<ImageListOptions>,
    ) -> Result<Vec<ImageSummary>, Error> {
        raw::image_list(&self.raw_engine()?, &options.unwrap_or_default()).await
    }

    /// Removes an image and returns the daemon's untagged/deleted records.
    ///
    /// Registry authentication headers are intentionally not accepted by this
    /// first boundary; image pull/push and credential integration remain a
    /// separate operation slice.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn remove_image(
        &self,
        name: &str,
        options: Option<ImageRemoveOptions>,
    ) -> Result<Vec<ImageDeleteResult>, Error> {
        raw::image_remove(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }
}

/// The concrete endpoint captured once when a local Docker client is built.
struct LocalEndpoint {
    /// The socket or pipe the owned transport dials.
    raw_target: raw::RawTarget,
}

/// Default local operation timeout in seconds.
const LOCAL_CONNECT_TIMEOUT_SECONDS: u64 = 120;

/// The per-operation overall request budget for a secret read on a captured
/// local target.
///
/// It covers connect through the response head, like the generated client's
/// single request timeout, and ends when the head arrives; the body is
/// unbounded. It is deliberately not stored on the shared client.
const LOCAL_SECRET_READ_BUDGET: Duration = Duration::from_secs(LOCAL_CONNECT_TIMEOUT_SECONDS);

/// Default Unix socket used by the local client.
#[cfg(unix)]
const DEFAULT_LOCAL_SOCKET: &str = "unix:///var/run/docker.sock";

/// Resolves the platform's local endpoint from one captured host value.
///
/// On Unix, `DOCKER_HOST` is honored only when it starts with `unix://`, and
/// `/var/run/docker.sock` is the fallback. On Windows the default named pipe is
/// used and `DOCKER_HOST` is ignored, matching the former generated client's local constructors
/// exactly.
#[allow(
    clippy::unnecessary_wraps,
    reason = "a platform with neither Unix sockets nor named pipes has no local default"
)]
fn local_endpoint_from_host(host: Option<&str>) -> Option<LocalEndpoint> {
    #[cfg(unix)]
    {
        let local_host = host
            .filter(|value| value.starts_with("unix://"))
            .unwrap_or(DEFAULT_LOCAL_SOCKET)
            .to_owned();
        let path = std::path::PathBuf::from(local_host.replacen("unix://", "", 1));
        Some(LocalEndpoint {
            raw_target: raw::RawTarget::Unix(path),
        })
    }
    #[cfg(windows)]
    {
        let _ = host;
        Some(LocalEndpoint {
            raw_target: raw::RawTarget::NamedPipe(std::path::PathBuf::from(
                "//./pipe/docker_engine",
            )),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = host;
        None
    }
}

/// Constructs both halves of a local client from one captured endpoint.
fn connect_local_from_endpoint(endpoint: LocalEndpoint) -> DockerClient {
    let mut client = DockerClient::from_target(
        OwnedTarget::Reachable(endpoint.raw_target),
        ProxyPolicy::Direct,
        API_VERSION,
    );
    client.local_target = true;
    client
}

#[cfg(test)]
mod tests {
    use super::{ApiVersion, DockerClient, Endpoint, Error, ErrorKind};

    #[tokio::test]
    async fn task_logs_fail_closed_without_an_owned_target() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client =
            DockerClient::connect_http(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        client.raw_target = super::OwnedTarget::Unreachable("fixture".to_owned());
        let mut logs = client.task_logs("task", None);
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), logs.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("task logs require an owned transport endpoint")
        );
        assert!(logs.next().await.is_none());
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn task_logs_withhold_factory_errors_and_preserve_deadline() {
        use std::error::Error as _;
        const SENTINEL: &str = "factory-error-content-sentinel";
        for deadline in [false, true] {
            let open = super::raw::StreamFactory::from_fn(move || async move {
                let error = if deadline {
                    Error::transport_deadline(SENTINEL)
                } else {
                    Error::transport(SENTINEL)
                };
                Err::<Box<dyn super::raw::Duplex>, Error>(error)
            });
            let mut client = DockerClient::connect_http("http://127.0.0.1:1").unwrap();
            client.raw_target = super::OwnedTarget::Reachable(super::raw::RawTarget::Stream {
                authority: "fixture".to_owned(),
                open,
            });
            let mut logs = client.task_logs("task", None);
            let error = tokio::time::timeout(std::time::Duration::from_secs(5), logs.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::Transport);
            assert_eq!(error.is_transport_deadline(), deadline);
            assert!(!format!("{error} {error:?}").contains(SENTINEL));
            let mut source = error.source();
            while let Some(item) = source {
                assert!(!format!("{item} {item:?}").contains(SENTINEL));
                source = item.source();
            }
            assert!(logs.next().await.is_none());
        }
    }

    /// Pins the number the crate claims to target.
    ///
    /// This one keeps a literal on purpose, and it is the deliberate exception
    /// to the rule every other test in this crate follows. Almost everything
    /// else here derives from `API_VERSION` because its subject is plumbing --
    /// the path a request takes, the prefix it carries -- and a literal in those
    /// would only mean the ceiling had to be re-typed in 30 places before a
    /// legitimate change to it could be made. This test's subject *is* the
    /// number. Derive it and it asserts that `API_VERSION` equals itself, which
    /// is the same as asserting nothing, and the crate's central claim becomes
    /// untested.
    #[test]
    fn api_version_claims_one_fifty_five() {
        assert_eq!(
            super::API_VERSION,
            ApiVersion {
                major: 1,
                minor: 55,
            }
        );
    }

    /// The response-head deadline is installed for HTTPS only. Existing raw
    /// targets keep their unbounded default.
    #[cfg(feature = "tls")]
    #[test]
    fn https_constructors_install_the_response_head_deadline_and_others_do_not()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use super::{DEFAULT_TIMEOUT_SECONDS, ProxyPolicy, TlsServerTrust};

        let directory = tempfile::tempdir()?;
        let (material, _config) = crate::proxy::tests::tls_fixture_material(directory.path())?;
        let https = DockerClient::connect_https_with_trust(
            "https://localhost:2376",
            &material,
            ProxyPolicy::Direct,
            TlsServerTrust::Verify,
        )?;
        assert_eq!(
            https.raw_response_head_deadline_for_test(),
            Some(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        );

        let http = DockerClient::connect_http("http://localhost:2375")?;
        assert_eq!(http.raw_response_head_deadline_for_test(), None);
        Ok(())
    }

    /// Fails if the conformance table drifts from the version it describes.
    ///
    /// Every entry claims to be a change in a version at or below the ceiling
    /// and above the former generated client's. An entry naming a version the crate does not
    /// target is a claim about a version this crate makes no conformance
    /// promise for, and an entry naming 1.53 or below is a change this crate
    /// already implemented or already never had.
    #[test]
    fn every_recorded_addition_is_a_change_above_former_generated_client_and_at_or_below_the_ceiling()
     {
        let floor = 53;
        for (version, change, status) in super::API_VERSION_ADDITIONS {
            let minor: usize = version
                .strip_prefix("v1.")
                .or_else(|| version.strip_prefix("1."))
                .unwrap_or_else(|| panic!("entry {change:?} names version {version:?}"))
                .parse()
                .unwrap_or_else(|_| panic!("entry {change:?} names version {version:?}"));
            assert!(
                minor > floor && minor <= super::API_VERSION.minor,
                "entry {change:?} is recorded against {version}, which is outside the \
                 band this crate raised its ceiling across ({floor} < v <= {})",
                super::API_VERSION.minor
            );
            assert!(
                !status.trim().is_empty(),
                "entry {change:?} has an empty status, which reads as 'nothing to say' \
                 rather than as a decision"
            );
        }
    }

    /// The README is the crate's public documentation, so its copy of the
    /// conformance table has to be the same table.
    ///
    /// Two copies of the same list is duplication with a failure mode, and the
    /// failure mode is the one this repository keeps finding: a doc that asserts
    /// a check catches something it does not. `API_VERSION_ADDITIONS` is what a
    /// test can check, and the README is what a reader reads, so this test is
    /// what stops the second from quietly describing a different boundary.
    #[test]
    fn conformance_table_matches_the_readme() {
        let readme = include_str!("../README.md");
        for (version, change, status) in super::API_VERSION_ADDITIONS {
            for (what, needle) in [
                ("version", *version),
                ("change", *change),
                ("status", *status),
            ] {
                assert!(
                    readme.contains(needle),
                    "the README's conformance table does not carry the {what} of the \
                     {version} entry ({needle:?}); README.md is the crate's documentation \
                     through #![doc = include_str!], so a reader sees a boundary the code \
                     no longer holds"
                );
            }
        }
    }

    #[test]
    fn reports_invalid_timeout() {
        let error = Error {
            kind: ErrorKind::InvalidTimeout,
            source: None,
            api: None,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidTimeout);
        assert_eq!(error.to_string(), "Docker client timeout must be positive");
    }

    #[tokio::test]
    async fn former_generated_client_stays_at_1_53_while_the_owned_transport_reaches_the_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let mut request = [0; 2048];
            let length = stream
                .read(&mut request)
                .map_err(|error| error.to_string())?;
            let request =
                std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
            assert!(
                request.starts_with("GET /v1.55/_ping ")
                    || request.starts_with("GET /v1.47/_ping "),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_http(&format!("http://{address}"))?;

        // The the former generated client half, and the reason `FORMER_GENERATED_CLIENT_API_VERSION` exists.
        assert_eq!(
            client.client_version(),
            super::API_VERSION,
            "the former generated client must stay at the version its models are generated for"
        );

        // The owned half, and the reason it is a separate value at all. This
        // assertion is the whole decoupling: before the split, `raw_version`
        // was read back out of the argument passed to the former generated client, so it was 1.53
        // here for no reason anyone had stated, and no test could have said so
        // because `client_version()` and `raw_version` agreed by construction.
        let engine = client.raw_engine()?;
        assert_eq!(engine.version(), super::API_VERSION);
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(hyper::Method::GET, "/info"))
            .expect("an absolute path");
        assert_eq!(
            uri,
            format!(
                "/v{}.{}/info",
                super::API_VERSION.major,
                super::API_VERSION.minor
            ),
            "the owned transport must speak the crate's ceiling, not the former generated client's pin"
        );

        assert_eq!(client.ping().await?.api_version, None);
        server
            .join()
            .expect("HTTP fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[tokio::test]
    async fn selected_client_version_is_used_over_http() -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let mut request = [0; 2048];
            let length = stream
                .read(&mut request)
                .map_err(|error| error.to_string())?;
            let request =
                std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
            assert!(
                request.starts_with("GET /v1.55/_ping ")
                    || request.starts_with("GET /v1.47/_ping "),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http(format!("http://{address}")),
            ApiVersion {
                major: 1,
                minor: 47,
            },
        )?;
        assert_eq!(
            client.client_version(),
            ApiVersion {
                major: 1,
                minor: 47
            }
        );
        assert_eq!(client.ping().await?.api_version, None);
        server
            .join()
            .expect("HTTP fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    /// The boundary itself: 1.55 in, 1.56 and 2.0 out.
    ///
    /// This replaced a test that rejected 1.54, which is the boundary this
    /// crate had when its ceiling was the former generated client's 1.53. It is worth naming what
    /// changed, because the old test was not merely stale -- it asserted the
    /// *opposite* of the decision, and it passed. A test that says 1.54 must be
    /// rejected keeps passing right up to the moment the ceiling is raised, and
    /// then has to be deleted rather than trusted, which is the shape of change
    /// that quietly removes a check.
    ///
    /// The accepted half matters as much as the rejected half. Checking only
    /// that 1.56 fails would also pass against a ceiling of 1.40, and this is
    /// the test that says 1.55 is reachable.
    #[test]
    fn accepts_the_ceiling_and_rejects_just_above_it() {
        let endpoint = Endpoint::Http("http://127.0.0.1:2375".to_owned());

        let accepted = DockerClient::connect_endpoint_with_version(
            &endpoint,
            ApiVersion {
                major: 1,
                minor: 55,
            },
        )
        .expect("the crate's own API version must be accepted");
        assert_eq!(accepted.client_version(), super::API_VERSION);

        for version in [
            ApiVersion {
                major: 1,
                minor: 56,
            },
            ApiVersion { major: 2, minor: 0 },
            ApiVersion {
                major: 1,
                minor: 900,
            },
        ] {
            let error = DockerClient::connect_endpoint_with_version(&endpoint, version)
                .expect_err("unsupported API version must fail before transport setup");
            assert_eq!(error.kind(), ErrorKind::InvalidApiVersion);
        }
    }

    /// 1.54 is below the new ceiling and above the old one, and must be valid.
    ///
    /// This is the version a raise quietly gets wrong. It is the only value
    /// that separates "the ceiling moved" from "the check was deleted", so it
    /// is asserted on its own rather than folded into the test above: a ceiling
    /// left at 1.53 rejects it, and a ceiling left un-bounded accepts 1.56 as
    /// well, and neither mistake is visible in the other test alone.
    #[test]
    fn one_fifty_four_is_below_the_ceiling_and_still_valid() {
        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http("http://127.0.0.1:2375".to_owned()),
            ApiVersion {
                major: 1,
                minor: 54,
            },
        )
        .expect("1.54 is below the ceiling and must be accepted");
        assert_eq!(
            client.client_version(),
            ApiVersion {
                major: 1,
                minor: 54
            }
        );
    }

    /// The API-version error text has to name the version the crate targets.
    ///
    /// This reads the rendered string and then pins the number separately,
    /// because the failure being guarded against is a message that formats the
    /// *wrong* number while everything else in the file derives correctly. A
    /// test that built its expectation from the same helper the message uses
    /// would pass in exactly that case -- the helper would be wrong too.
    #[test]
    fn the_invalid_api_version_message_names_the_live_ceiling() {
        assert_eq!(
            super::api_version_ceiling(),
            "v1.55",
            "the rendered ceiling must be the live number, not the former generated client's 1.53"
        );

        let rendered = Error {
            kind: ErrorKind::InvalidApiVersion,
            source: None,
            api: None,
        }
        .to_string();
        assert_eq!(
            rendered,
            "Docker Engine API version must be v1.x no higher than v1.55"
        );
    }

    /// The Swarm resource-version message names the same live ceiling.
    ///
    /// This one is a resource version rather than an API version, so it is easy
    /// to leave behind when the other two move: it reads like a statement about
    /// a Swarm document version, and the version in it looks like part of that
    /// sentence rather than a claim about this crate.
    #[test]
    fn the_resource_version_message_names_the_live_ceiling() {
        let rendered = Error {
            kind: ErrorKind::InvalidVersion,
            source: None,
            api: None,
        }
        .to_string();
        assert_eq!(
            rendered,
            "Docker resource version is outside the v1.55 range"
        );
    }

    /// No reachable error text may still name the former generated client's 1.53 as this crate's
    /// ceiling.
    ///
    /// The three messages are checked one at a time above, which catches a
    /// change to any of them. This catches the fourth: one added later, or one
    /// in a module nobody looked at. It cannot enumerate future messages, so it
    /// is a backstop rather than the primary check, and the primary checks are
    /// the ones that would say which message moved.
    #[test]
    fn no_error_kind_renders_a_stale_ceiling() {
        for kind in [ErrorKind::InvalidApiVersion, ErrorKind::InvalidVersion] {
            let rendered = Error {
                kind,
                source: None,
                api: None,
            }
            .to_string();
            assert!(
                !rendered.contains("v1.53"),
                "{kind:?} renders {rendered:?}, which names the former generated client's 1.53 rather than \
                 this crate's ceiling"
            );
        }
    }

    /// The socket constructor decouples the two versions too.
    ///
    /// The plain-HTTP case above already fails if `raw_version` is derived from
    /// the former generated client argument, so the coupling was not invisible. It was invisible
    /// *here*, on the socket constructor, which is the one almost every caller
    /// reaches — `connect_defaults` and `connect_endpoint` both land on it. The
    /// reason it is a separate test rather than another assertion in the first
    /// one is that it is a separate line of code: `connect_socket_with_version`
    /// assigns `raw_version` itself rather than going through the struct
    /// literal the HTTP path uses, so a fix to one does nothing for the other.
    /// Both were re-coupled during this change and only the HTTP one was
    /// caught, which is the reason this test exists.
    #[test]
    fn the_socket_constructor_speaks_the_ceiling_to_the_owned_transport() {
        // A real socket file, because the former generated client resolves the path when the client
        // is built and refuses one that does not exist. It is never dialled:
        // the owned transport's version is decided before any connection is
        // attempted, and nothing here sends a byte.
        let path = std::env::temp_dir().join("api155-decoupling-probe.sock");
        std::fs::write(&path, b"").expect("a placeholder socket path");
        let client = DockerClient::connect_socket(&path)
            .expect("a client can be built for a path that exists");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            client.client_version(),
            super::API_VERSION,
            "the former generated client is pinned at 1.53 by its generated models"
        );
        let engine = client.raw_engine().expect("a Unix socket is reachable");
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(
                hyper::Method::GET,
                "/containers/json",
            ))
            .expect("an absolute path");
        assert_eq!(
            uri,
            format!(
                "/v{}.{}/containers/json",
                super::API_VERSION.major,
                super::API_VERSION.minor
            ),
            "the socket constructor must not hand the owned transport the former generated client's 1.53"
        );
    }

    /// A caller-selected version reaches both paths, and both report it.
    ///
    /// The decoupling above is about the *defaults*. This is the other
    /// direction: `connect_endpoint_with_version` takes one version, and the
    /// owned transport follows the caller rather than reverting to
    /// `API_VERSION`. A caller who asked for 1.47 asked for it everywhere, so a
    /// test that only checked the defaults would not notice the owned half
    /// ignoring an explicit choice — and would not notice it reverting either.
    #[test]
    fn a_caller_selected_version_reaches_the_owned_transport_too() {
        let client = DockerClient::connect_endpoint_with_version(
            &Endpoint::Http("http://127.0.0.1:2375".to_owned()),
            ApiVersion {
                major: 1,
                minor: 47,
            },
        )
        .expect("1.47 is below the ceiling");
        let engine = client
            .raw_engine()
            .expect("a plain HTTP endpoint is reachable");
        let uri = engine
            .request_uri(&crate::raw::RawRequest::new(hyper::Method::GET, "/info"))
            .expect("an absolute path");
        assert_eq!(
            uri, "/v1.47/info",
            "the owned transport must follow the caller's choice, not the ceiling"
        );
    }

    #[tokio::test]
    async fn exercises_container_lifecycle_request_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || {
            for expected in [
                ("POST", "/containers/demo/start"),
                ("POST", "/containers/demo/stop?signal=SIGTERM&t=7"),
                ("DELETE", "/containers/demo?v=true&force=true&link=false"),
            ] {
                let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
                let mut request = [0; 4096];
                let length = stream
                    .read(&mut request)
                    .map_err(|error| error.to_string())?;
                let request =
                    std::str::from_utf8(&request[..length]).map_err(|error| error.to_string())?;
                let request_line = request.lines().next().ok_or("missing request line")?;
                assert!(request_line.starts_with(expected.0), "{request_line}");
                assert!(request_line.contains(expected.1), "{request_line}");
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(())
        });

        let client = DockerClient::connect_http(&format!("http://{address}"))?;
        client.start_container("demo").await?;
        client
            .stop_container(
                "demo",
                Some(super::ContainerStopOptions {
                    signal: Some("SIGTERM".to_owned()),
                    timeout_seconds: Some(7),
                }),
            )
            .await?;
        client
            .remove_container(
                "demo",
                Some(super::ContainerRemoveOptions {
                    remove_volumes: true,
                    force: true,
                    remove_link: false,
                }),
            )
            .await?;
        server
            .join()
            .expect("container lifecycle fixture thread panicked")
            .map_err(std::io::Error::other)?;
        Ok(())
    }

    #[test]
    fn reports_missing_socket() {
        let path = std::path::Path::new("/path/that/does/not/exist/docker.sock");
        assert!(matches!(
            DockerClient::connect_socket(path),
            Err(error) if error.kind() == ErrorKind::Docker
        ));
    }

    #[cfg(all(feature = "ssh", unix))]
    #[test]
    fn rejects_invalid_direct_ssh_endpoint_before_connecting() {
        let result = DockerClient::connect_ssh(
            "ssh://user:password@example.com",
            std::time::Duration::from_secs(1),
            None,
        );
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidEndpoint));
    }

    #[cfg(all(feature = "ssh", unix))]
    #[test]
    fn rejects_zero_ssh_timeout_before_connecting() {
        let result =
            DockerClient::connect_ssh("ssh://example.invalid", std::time::Duration::ZERO, None);
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidTimeout));
    }

    /// Starts a loopback proxy that accepts and never answers.
    async fn stalling_proxy() -> (
        String,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the stalling proxy");
        let address = listener.local_addr().expect("the stalling proxy address");
        let connections = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let connections = Arc::clone(&connections);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        continue;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        drop(stream);
                    });
                }
            }
        });
        (format!("http://{address}"), connections, task)
    }

    /// The proxied facade's `wait`, `stop`, and `restart` operations use the
    /// proxy route's single overall budget. Without it they would inherit the
    /// raw transport's unbounded wait policy and never return from a stalled
    /// proxy.
    #[tokio::test]
    async fn proxied_wait_stop_and_restart_use_the_overall_budget() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        use super::{ForwardProxy, ProxyPolicy};

        let (proxy, connections, proxy_task) = stalling_proxy().await;
        let mut client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://daemon.invalid:2375".to_owned()),
            ProxyPolicy::Http(ForwardProxy::new(proxy).expect("the proxy URL")),
        )
        .expect("build the proxied client");
        client.set_proxy_overall_deadline_for_test(Duration::from_millis(100));
        assert_eq!(client.raw_response_head_deadline_for_test(), None);

        let stop = tokio::time::timeout(Duration::from_secs(2), client.stop_container("x", None))
            .await
            .expect("proxied stop did not finish")
            .expect_err("proxied stop must be bounded");
        assert!(stop.to_string().contains("timed out"), "{stop}");

        let restart =
            tokio::time::timeout(Duration::from_secs(2), client.restart_container("x", None))
                .await
                .expect("proxied restart did not finish")
                .expect_err("proxied restart must be bounded");
        assert!(restart.to_string().contains("timed out"), "{restart}");

        let mut wait = client.wait_container("x", None);
        let item = tokio::time::timeout(Duration::from_secs(2), wait.next())
            .await
            .expect("proxied wait did not finish")
            .expect("proxied wait produced no item");
        let wait = item.expect_err("proxied wait must be bounded");
        assert!(wait.to_string().contains("timed out"), "{wait}");

        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "each operation must dial the proxy exactly once, with no timeout retry"
        );
        proxy_task.abort();
    }

    /// A facade operation with a caller-owned request stream is bounded by the
    /// proxy route's overall budget even when the producer never yields. This is
    /// the producer-stall case the generated client's single request timeout
    /// covered.
    #[tokio::test]
    async fn proxied_import_stream_uses_the_overall_budget_for_a_stalled_producer() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        use super::{ForwardProxy, ImageImportOptions, ImageTransferLimits, ProxyPolicy};

        let (proxy, connections, proxy_task) = stalling_proxy().await;
        let mut client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://daemon.invalid:2375".to_owned()),
            ProxyPolicy::Http(ForwardProxy::new(proxy).expect("the proxy URL")),
        )
        .expect("build the proxied client");
        client.set_proxy_overall_deadline_for_test(Duration::from_millis(100));

        let source = futures_util::stream::pending::<Result<Vec<u8>, std::io::Error>>();
        let mut stream = client
            .import_image_from_stream(
                ImageImportOptions::new("-"),
                source,
                ImageTransferLimits::default(),
            )
            .expect("the import stream");
        let item = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("proxied import did not finish")
            .expect("proxied import produced no item");
        let error = item.expect_err("a stalled producer must hit the proxy budget");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(
            connections.load(Ordering::SeqCst) >= 1,
            "the proxy was not dialed"
        );
        proxy_task.abort();
    }

    /// A secret read fails closed when the endpoint has no owned target.
    ///
    /// The endpoint points at a closed loopback port, so a dispatch would be a
    /// transport error. The local `InvalidInput` is the proof no request was
    /// sent.
    #[tokio::test]
    async fn secret_reads_fail_closed_without_an_owned_target() {
        // An active listener, not a closed port: a dispatch would be observed
        // here rather than inferred from a connection-refused error.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the listener");
        let address = listener.local_addr().expect("the listener address");
        listener
            .set_nonblocking(true)
            .expect("make the listener nonblocking");

        let mut client =
            DockerClient::connect_http(&format!("http://{address}")).expect("build the client");
        client.raw_target = super::OwnedTarget::Unreachable("a test endpoint".to_owned());

        for error in [
            client
                .list_secrets(None)
                .await
                .expect_err("the list fails closed"),
            client
                .inspect_secret("secret-fixture")
                .await
                .expect_err("the inspect fails closed"),
        ] {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            let rendered = error.to_string();
            assert!(
                rendered.contains("repository-owned transport"),
                "{rendered}"
            );
            assert!(rendered.contains("no request was sent"), "{rendered}");
        }
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("a refused secret read reached the wire"),
            Err(error) => panic!("the listener failed: {error}"),
        }
    }

    /// The Swarm lifecycle fails closed when the endpoint has no owned target.
    ///
    /// The endpoint points at an active loopback listener, so a dispatch would
    /// be observed here rather than inferred from a connection-refused error.
    /// Every operation is checked, including the two that would otherwise be
    /// reads, because the fail-closed decision is shared and must not depend on
    /// the request method.
    #[tokio::test]
    async fn swarm_lifecycle_fails_closed_without_an_owned_target() {
        use super::{
            DockerClient, ErrorKind, SwarmInitOptions, SwarmJoinOptions, SwarmSpec,
            SwarmUpdateOptions,
        };

        const TOKEN: &str = "SWMTKN-1-canary-fail-closed-join-2c19-do-not-log-me";

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the listener");
        let address = listener.local_addr().expect("the listener address");
        listener
            .set_nonblocking(true)
            .expect("make the listener nonblocking");

        let mut client =
            DockerClient::connect_http(&format!("http://{address}")).expect("build the client");
        client.raw_target = super::OwnedTarget::Unreachable("a test endpoint".to_owned());

        let errors = vec![
            client
                .initialize_swarm(SwarmInitOptions::new())
                .await
                .expect_err("init fails closed"),
            client
                .join_swarm(SwarmJoinOptions {
                    token: TOKEN.to_owned(),
                    remote_addresses: vec!["tcp://manager:2377".to_owned()],
                    ..SwarmJoinOptions::default()
                })
                .await
                .expect_err("join fails closed"),
            client
                .update_swarm(SwarmUpdateOptions {
                    version: 1,
                    spec: SwarmSpec::default(),
                    rotate_worker_token: false,
                    rotate_manager_token: false,
                    rotate_manager_unlock_key: false,
                })
                .await
                .expect_err("update fails closed"),
            client
                .swarm_certificates()
                .await
                .expect_err("certificates fail closed"),
            client
                .swarm_unlock_key()
                .await
                .expect_err("unlock-key fails closed"),
        ];
        for error in errors {
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("Swarm lifecycle"),
                "the refusal did not name the lifecycle gap: {error}"
            );
            assert!(
                !format!("{error:?}").contains(TOKEN),
                "a fail-closed rendering leaked the join token: {error:?}"
            );
        }
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("a refused Swarm lifecycle request reached the wire"),
            Err(error) => panic!("the listener failed: {error}"),
        }
    }

    /// A local client keeps the endpoint it captured even if a later read of
    /// `DOCKER_HOST` would name a different socket.
    ///
    /// Mutation of the process environment is `unsafe` in Rust 2024 and is
    /// forbidden in this workspace, so the test models the later read directly
    /// and checks the constructed client's stored target rather than calling
    /// `set_var`. The child-process suite exercises the actual wire target.
    #[cfg(unix)]
    #[test]
    fn local_endpoint_capture_is_stable_across_a_later_read() {
        use super::{connect_local_from_endpoint, local_endpoint_from_host, raw};

        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.sock");
        let second = directory.path().join("second.sock");
        std::fs::write(&first, b"").unwrap();
        let first_host = format!("unix://{}", first.display());
        let second_host = format!("unix://{}", second.display());

        let client = connect_local_from_endpoint(
            local_endpoint_from_host(Some(&first_host)).expect("the first endpoint"),
        );
        let later = local_endpoint_from_host(Some(&second_host)).expect("the second endpoint");

        match &client.raw_target {
            super::OwnedTarget::Reachable(raw::RawTarget::Unix(path)) => assert_eq!(path, &first),
            other => panic!("the client did not retain the first socket: {other:?}"),
        }
        // The shared field stays unset so the service-update assembly's local
        // inspect/update path is unchanged.
        assert!(client.raw_response_head_deadline.is_none());
        assert_eq!(
            client
                .secret_read_engine()
                .expect("the local secret engine")
                .overall_request_deadline(),
            Some(std::time::Duration::from_secs(
                super::LOCAL_CONNECT_TIMEOUT_SECONDS
            )),
            "the production local secret budget is not 120 seconds"
        );
        match later.raw_target {
            raw::RawTarget::Unix(path) => assert_eq!(path, second),
            other => panic!("the later read did not select the second socket: {other:?}"),
        }
    }

    /// A real `connect_local` Unix capture uses the same per-operation budget.
    ///
    /// The client is built through `connect_local_from_endpoint`, so the Unix
    /// socket is the captured target rather than a TCP seam. The shared
    /// response-head field is asserted unset; the production secret engine is
    /// asserted at 120 seconds; an injected one-second engine proves the
    /// timeout. The peer asserts the exact request line and that the partial
    /// head was written before the test waits for the timeout.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connect_local_unix_secret_read_honours_a_short_injected_budget() {
        const HEAD_CANARY: &str = "unix-stall-head-canary-4c2a";
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = directory.path().join("engine.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the stalled peer");
        let host = format!("unix://{}", socket.display());
        let client = super::connect_local_from_endpoint(
            super::local_endpoint_from_host(Some(&host)).expect("the captured endpoint"),
        );

        assert!(client.raw_response_head_deadline.is_none());
        assert_eq!(
            client
                .secret_read_engine()
                .expect("the local secret engine")
                .overall_request_deadline(),
            Some(std::time::Duration::from_secs(
                super::LOCAL_CONNECT_TIMEOUT_SECONDS
            )),
            "the production local secret budget is not 120 seconds"
        );

        let target = match &client.raw_target {
            super::OwnedTarget::Reachable(super::raw::RawTarget::Unix(path)) => path.clone(),
            other => panic!("the client did not capture the Unix socket: {other:?}"),
        };
        let budget = std::time::Duration::from_secs(1);
        let engine =
            super::raw::RawEngine::new(super::raw::RawTarget::Unix(target), super::API_VERSION)
                .with_overall_request_deadline(Some(budget));

        let expected = format!(
            "GET /v{}.{}/secrets/secret-fixture HTTP/1.1",
            super::API_VERSION.major,
            super::API_VERSION.minor
        );
        let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_stalled_unix(
            listener,
            expected,
            HEAD_CANARY,
            stalled_tx,
            closed_tx,
        ));
        let engine_for_task = engine.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let client_task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let _ = started_tx.send(started);
            let result = super::raw::secret_inspect(&engine_for_task, "secret-fixture").await;
            let finished = std::time::Instant::now();
            (started, finished, result)
        });
        let request_started = tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await
            .expect("the client task did not start")
            .expect("the client start signal was dropped");
        tokio::time::timeout(std::time::Duration::from_secs(5), stalled_rx)
            .await
            .expect("the peer did not reach the stalled head")
            .expect("the peer did not signal the stalled head");
        let (started, finished, result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
                .await
                .expect("the secret read did not finish")
                .expect("the secret read task");
        let error = result.expect_err("the stalled head must time out");

        assert_eq!(started, request_started, "the start signal changed");
        assert_secret_read_timeout(&error, budget);
        let elapsed = finished.duration_since(started);
        assert!(
            elapsed >= std::time::Duration::from_millis(900),
            "the timeout fired before the one-second budget from the request start: {elapsed:?}"
        );
        assert!(
            elapsed <= std::time::Duration::from_secs(3),
            "the timeout stayed open past the deadline upper bound: {elapsed:?}"
        );
        for rendered in render_error_chain(&error) {
            assert!(!rendered.contains(HEAD_CANARY), "{rendered}");
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
            .await
            .expect("the peer did not observe the close")
            .expect("the peer did not signal the close");
        assert_peer_finished(&mut server).await;
    }

    /// The public facade's `inspect_secret` uses the same local budget seam.
    ///
    /// The client is a real `connect_local_from_endpoint` client; the test-only
    /// override changes only the local secret-read budget, so the facade path
    /// (not a separately built raw engine) is what is exercised. The peer
    /// asserts the exact request line and the partial-head write before the test
    /// waits for the timeout; the close accepts only EOF or a reset.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connect_local_facade_secret_read_honours_a_short_test_budget() {
        const HEAD_CANARY: &str = "unix-facade-head-canary-2e7b";
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = directory.path().join("engine.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the stalled peer");
        let host = format!("unix://{}", socket.display());
        let mut client = super::connect_local_from_endpoint(
            super::local_endpoint_from_host(Some(&host)).expect("the captured endpoint"),
        );

        assert!(client.raw_response_head_deadline.is_none());
        let budget = std::time::Duration::from_secs(1);
        client.secret_read_budget_override = Some(budget);
        assert_eq!(
            client
                .secret_read_engine()
                .expect("the local secret engine")
                .overall_request_deadline(),
            Some(budget),
            "the test seam did not override the secret budget"
        );

        let expected = format!(
            "GET /v{}.{}/secrets/secret-fixture HTTP/1.1",
            super::API_VERSION.major,
            super::API_VERSION.minor
        );
        let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_stalled_unix(
            listener,
            expected,
            HEAD_CANARY,
            stalled_tx,
            closed_tx,
        ));
        let client_for_task = client.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let client_task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let _ = started_tx.send(started);
            let result = client_for_task.inspect_secret("secret-fixture").await;
            let finished = std::time::Instant::now();
            (started, finished, result)
        });
        let request_started = tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await
            .expect("the client task did not start")
            .expect("the client start signal was dropped");
        tokio::time::timeout(std::time::Duration::from_secs(5), stalled_rx)
            .await
            .expect("the peer did not reach the stalled head")
            .expect("the peer did not signal the stalled head");
        let (started, finished, result) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
                .await
                .expect("the secret read did not finish")
                .expect("the secret read task");
        let error = result.expect_err("the stalled head must time out");

        assert_eq!(started, request_started, "the start signal changed");
        assert!(
            error.is_transport_deadline(),
            "the public secret read timeout lost its typed marker: {error:?}"
        );
        assert_secret_read_timeout(&error, budget);
        let elapsed = finished.duration_since(started);
        assert!(
            elapsed >= std::time::Duration::from_millis(900),
            "the timeout fired before the one-second budget from the request start: {elapsed:?}"
        );
        assert!(
            elapsed <= std::time::Duration::from_secs(3),
            "the timeout stayed open past the deadline upper bound: {elapsed:?}"
        );
        for rendered in render_error_chain(&error) {
            assert!(!rendered.contains(HEAD_CANARY), "{rendered}");
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
            .await
            .expect("the peer did not observe the close")
            .expect("the peer did not signal the close");
        assert_peer_finished(&mut server).await;
    }

    /// A secret-read deadline marker survives a caller-supplied stream factory
    /// and a node mutation.
    ///
    /// The marker comes from a real public `inspect_secret` timeout on a
    /// captured local socket. It is then returned by a `StreamFactory`, so the
    /// node mutation sees a deadline it did not itself observe. The mutation
    /// must keep the typed marker, report that the deadline was observed and
    /// the outcome is unknown, and withhold both the factory's text and the
    /// endpoint.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_propagated_secret_read_deadline_reaches_a_node_mutation_marked_and_redacted() {
        const HEAD_CANARY: &str = "unix-propagated-head-canary-7d31";
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = directory.path().join("engine.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the stalled peer");
        let host = format!("unix://{}", socket.display());
        let mut client = super::connect_local_from_endpoint(
            super::local_endpoint_from_host(Some(&host)).expect("the captured endpoint"),
        );
        let budget = std::time::Duration::from_secs(1);
        client.secret_read_budget_override = Some(budget);

        let expected = format!(
            "GET /v{}.{}/secrets/secret-fixture HTTP/1.1",
            super::API_VERSION.major,
            super::API_VERSION.minor
        );
        let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_stalled_unix(
            listener,
            expected,
            HEAD_CANARY,
            stalled_tx,
            closed_tx,
        ));
        let client_for_task = client.clone();
        let client_task =
            tokio::spawn(async move { client_for_task.inspect_secret("secret-fixture").await });
        tokio::time::timeout(std::time::Duration::from_secs(5), stalled_rx)
            .await
            .expect("the peer did not reach the stalled head")
            .expect("the peer did not signal the stalled head");
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), client_task)
            .await
            .expect("the secret read did not finish")
            .expect("the secret read task")
            .expect_err("the stalled head must time out");
        assert!(
            error.is_transport_deadline(),
            "the secret marker is missing: {error:?}"
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
            .await
            .expect("the peer did not observe the close")
            .expect("the peer did not signal the close");
        assert_peer_finished(&mut server).await;

        // The exact marker is handed to a factory, which the node mutation
        // treats as a deadline it cannot attribute to its own request.
        let slot = std::sync::Mutex::new(Some(error));
        let open = super::raw::StreamFactory::from_fn(move || {
            let taken = slot.lock().expect("the factory slot").take();
            async move {
                match taken {
                    Some(error) => Err::<Box<dyn super::raw::Duplex>, Error>(error),
                    None => Err(Error::transport("the factory was reused")),
                }
            }
        });
        let engine = super::raw::RawEngine::new(
            super::raw::RawTarget::Stream {
                authority: String::from("fixture"),
                open,
            },
            super::API_VERSION,
        );
        let propagated = super::raw::node_remove(
            &engine,
            "node-fixture",
            &super::NodeRemoveOptions { force: false },
        )
        .await
        .expect_err("the propagated deadline must fail the mutation");
        assert!(
            propagated.is_transport_deadline(),
            "the node mutation dropped the propagated marker: {propagated:?}"
        );
        let message = propagated.to_string();
        assert!(
            message.contains("a transport deadline was observed"),
            "{message}"
        );
        assert!(
            message.contains("node mutation outcome is unknown"),
            "{message}"
        );
        assert!(message.contains("reconcile"), "{message}");
        assert!(
            !message.contains("timed out after"),
            "the mutation reused the factory's diagnostic: {message}"
        );
        for rendered in render_error_chain(&propagated) {
            assert!(!rendered.contains(HEAD_CANARY), "{rendered}");
            assert!(!rendered.contains("engine.sock"), "{rendered}");
        }
    }

    /// Serves one stalled Unix secret read.
    ///
    /// The request head is read fully and its exact request line asserted, then
    /// the partial head is written and its result asserted, then `stalled` is
    /// signalled. The close loop accepts only EOF or a connection reset, so a
    /// timeout or another error is a fixture failure, not cancellation evidence.
    #[cfg(unix)]
    async fn serve_stalled_unix(
        listener: tokio::net::UnixListener,
        expected_line: String,
        canary: &'static str,
        stalled: tokio::sync::oneshot::Sender<()>,
        closed: tokio::sync::oneshot::Sender<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.expect("accept the secret request");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read the request");
            assert_ne!(read, 0, "the request ended before its head");
            request.extend_from_slice(&chunk[..read]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]);
                let line = head.lines().next().expect("the request line");
                assert_eq!(line, expected_line, "the secret read request line changed");
                break;
            }
        }
        let partial = format!("HTTP/1.1 200 OK\r\nX-Canary: {canary}\r\n");
        stream
            .write_all(partial.as_bytes())
            .await
            .expect("write the partial response head");
        stream
            .flush()
            .await
            .expect("flush the partial response head");
        let _ = stalled.send(());
        let mut buffer = [0_u8; 64];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("the peer saw an unexpected close error: {error}"),
            }
        }
        let _ = closed.send(());
    }

    /// Aborts a peer task that does not finish, so teardown cannot hang.
    #[cfg(unix)]
    async fn assert_peer_finished(server: &mut tokio::task::JoinHandle<()>) {
        // The peer already signalled close, so this is a short join rather than
        // a wait on the network. Abort is the bounded fallback.
        if let Ok(result) =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut *server).await
        {
            result.expect("the peer task");
        } else {
            server.abort();
            panic!("the peer task did not finish after the close");
        }
    }

    /// The raw transport's fixed overall-deadline message.
    fn secret_read_timeout_message(budget: std::time::Duration) -> String {
        format!("timed out after {budget:?} waiting for the Engine request to complete")
    }

    /// Whether the error is the raw transport's overall-deadline timeout.
    ///
    /// The budget reports the crate's typed transport deadline marker, so
    /// [`Error::is_transport_deadline`] is the discriminator. The fixed message
    /// is still checked to prove the marker came from this budget rather than a
    /// different marked deadline. Text alone is not accepted: an unmarked
    /// transport error carrying the same words is false.
    fn is_secret_read_timeout(error: &Error, budget: std::time::Duration) -> bool {
        if error.kind() != ErrorKind::Transport || !error.is_transport_deadline() {
            return false;
        }
        let expected = secret_read_timeout_message(budget);
        render_error_chain(error)
            .iter()
            .any(|rendered| rendered == &expected)
    }

    /// Asserts the error is the overall-deadline timeout, not another transport
    /// failure.
    fn assert_secret_read_timeout(error: &Error, budget: std::time::Duration) {
        let renderings = render_error_chain(error);
        assert!(
            is_secret_read_timeout(error, budget),
            "the exact timeout marker is missing: {renderings:?}"
        );
    }

    /// Asserts the positive predicate rejects a different transport failure.
    fn assert_not_secret_read_timeout(error: &Error, budget: std::time::Duration) {
        let renderings = render_error_chain(error);
        assert!(
            !is_secret_read_timeout(error, budget),
            "the timeout predicate accepted a different transport error: {renderings:?}"
        );
    }

    /// Serves one request and closes without a response head.
    #[cfg(unix)]
    async fn serve_aborted_unix(
        listener: tokio::net::UnixListener,
        expected_line: String,
        closed: tokio::sync::oneshot::Sender<()>,
    ) {
        use tokio::io::AsyncReadExt;
        let (mut stream, _) = listener.accept().await.expect("accept the secret request");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read the request");
            assert_ne!(read, 0, "the request ended before its head");
            request.extend_from_slice(&chunk[..read]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]);
                assert_eq!(
                    head.lines().next(),
                    Some(expected_line.as_str()),
                    "the aborted read request line changed"
                );
                break;
            }
        }
        drop(stream);
        let _ = closed.send(());
    }

    /// Every `Display` and `Debug` rendering in an error chain.
    fn render_error_chain(error: &dyn std::error::Error) -> Vec<String> {
        let mut rendered = vec![error.to_string(), format!("{error:?}")];
        let mut source = error.source();
        while let Some(cause) = source {
            rendered.push(cause.to_string());
            rendered.push(format!("{cause:?}"));
            source = cause.source();
        }
        rendered
    }

    /// A peer that closes without a head is a transport failure, not a timeout.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_different_transport_error_is_not_a_secret_read_timeout() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = directory.path().join("engine.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the aborted peer");
        let host = format!("unix://{}", socket.display());
        let client = super::connect_local_from_endpoint(
            super::local_endpoint_from_host(Some(&host)).expect("the captured endpoint"),
        );
        let target = match &client.raw_target {
            super::OwnedTarget::Reachable(super::raw::RawTarget::Unix(path)) => path.clone(),
            other => panic!("the client did not capture the Unix socket: {other:?}"),
        };
        let budget = std::time::Duration::from_secs(1);
        let engine =
            super::raw::RawEngine::new(super::raw::RawTarget::Unix(target), super::API_VERSION)
                .with_overall_request_deadline(Some(budget));
        let expected = format!(
            "GET /v{}.{}/secrets/secret-fixture HTTP/1.1",
            super::API_VERSION.major,
            super::API_VERSION.minor
        );
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_aborted_unix(listener, expected, closed_tx));

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::raw::secret_inspect(&engine, "secret-fixture"),
        )
        .await
        .expect("the aborted read did not finish")
        .expect_err("a close without a head is a transport error");
        assert_eq!(error.kind(), ErrorKind::Transport);
        assert!(
            !error.is_transport_deadline(),
            "a close without a head must not carry the deadline marker: {error:?}"
        );
        assert_not_secret_read_timeout(&error, budget);
        // The marker, not the words, identifies the deadline: an unmarked error
        // carrying the same fixed text must still be rejected.
        let imitated = Error::transport(secret_read_timeout_message(budget));
        assert!(!imitated.is_transport_deadline());
        assert_not_secret_read_timeout(&imitated, budget);

        tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
            .await
            .expect("the aborted peer did not finish")
            .expect("the aborted peer did not signal");
        assert_peer_finished(&mut server).await;
    }

    /// Without the overall deadline the library waits; the harness timeout
    /// fires. This is the mutation control for the deadline itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_missing_overall_deadline_does_not_produce_the_secret_read_timeout() {
        const HEAD_CANARY: &str = "unix-mutation-canary-5c1a";
        let directory = tempfile::tempdir().expect("a temporary directory");
        let socket = directory.path().join("engine.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind the stalled peer");
        let host = format!("unix://{}", socket.display());
        let client = super::connect_local_from_endpoint(
            super::local_endpoint_from_host(Some(&host)).expect("the captured endpoint"),
        );
        let target = match &client.raw_target {
            super::OwnedTarget::Reachable(super::raw::RawTarget::Unix(path)) => path.clone(),
            other => panic!("the client did not capture the Unix socket: {other:?}"),
        };
        // No with_overall_request_deadline: the mutation under test.
        let engine =
            super::raw::RawEngine::new(super::raw::RawTarget::Unix(target), super::API_VERSION);
        let expected = format!(
            "GET /v{}.{}/secrets/secret-fixture HTTP/1.1",
            super::API_VERSION.major,
            super::API_VERSION.minor
        );
        let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let mut server = tokio::spawn(serve_stalled_unix(
            listener,
            expected,
            HEAD_CANARY,
            stalled_tx,
            closed_tx,
        ));

        // Start the client first. The peer's staged-head signal is awaited on its
        // own bounded setup, so the 300 ms pending assertion starts only after
        // the partial head is on the wire.
        let mut client_task =
            tokio::spawn(
                async move { super::raw::secret_inspect(&engine, "secret-fixture").await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(2), stalled_rx)
            .await
            .expect("the peer did not reach the stalled head")
            .expect("the peer did not signal the stalled head");

        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut client_task).await;
        assert!(
            pending.is_err(),
            "an engine without the overall deadline returned instead of remaining pending"
        );
        client_task.abort();
        // Abort is best-effort, not an absolute kernel guarantee. Bound the reap
        // so a task that does not stop cannot hang the test, and require the
        // join to be a cancellation: a task that returned a value, an error, or
        // a panic is not the pending behavior this control is asserting.
        let joined = tokio::time::timeout(std::time::Duration::from_secs(2), client_task)
            .await
            .expect("the aborted no-deadline client task did not finish");
        let join_error = joined
            .expect_err("the no-deadline client task produced a result instead of being cancelled");
        assert!(
            join_error.is_cancelled(),
            "the no-deadline client task ended with an unexpected join error: {join_error}"
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), closed_rx)
            .await
            .expect("the peer did not observe the close")
            .expect("the peer did not signal the close");
        assert_peer_finished(&mut server).await;
    }
}
