//! Repository-owned Docker Engine Swarm service, node, config, secret, and
//! task operations.
//!
//! Operations use the repository-owned transport and never fall back to a
//! generated client. An endpoint without an owned target fails closed. Owned
//! reads and writes preserve status and apply their documented withholding rules.
//!
//! Public models follow the Engine API contract. Flexible specification members
//! remain JSON values and specification objects retain unknown members.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    ContainerLogFrame, DockerClient, DockerStream, Error, RegistryCredentials, raw,
    streams::{OwnedResponse, map_owned_log_frame, owned_response},
};

/// Ordered filters shared by Swarm list endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SwarmListOptions {
    /// Docker filters, such as `name`, `label`, `service`, or `node`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl SwarmListOptions {
    /// Creates options without filters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one filter key.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// Compatibility name for service-list options.
pub type ServiceListOptions = SwarmListOptions;
/// Compatibility name for node-list options.
pub type NodeListOptions = SwarmListOptions;
/// Compatibility name for config-list options.
pub type ConfigListOptions = SwarmListOptions;
/// Compatibility name for secret-list options.
pub type SecretListOptions = SwarmListOptions;
/// Compatibility name for task-list options.
pub type TaskListOptions = SwarmListOptions;

/// Monotonic version used for conflict-safe Swarm updates.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmVersion {
    /// Engine object version index.
    #[serde(rename = "Index", skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
}

/// Options for initializing a Swarm.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SwarmInitOptions {
    /// Manager listen address.
    pub listen_address: Option<String>,
    /// Manager advertise address.
    pub advertise_address: Option<String>,
    /// Data-path address.
    pub data_path_address: Option<String>,
    /// Data-path port.
    pub data_path_port: Option<u32>,
    /// Request creation of a new cluster.
    pub force_new_cluster: Option<bool>,
}

impl SwarmInitOptions {
    /// Creates empty initialization options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            listen_address: None,
            advertise_address: None,
            data_path_address: None,
            data_path_port: None,
            force_new_cluster: None,
        }
    }
}

/// Options for joining a Swarm.
///
/// `Debug` is hand-written rather than derived, because `token` is a credential:
/// it is the same value [`SwarmJoinTokenRole`] reads back out of a `SwarmInfo`,
/// and it is exactly what the crate refuses to render in
/// [`SwarmCertificates::key`] and [`SwarmUnlockKey::key`]. A derived impl here
/// printed it in full and undid that, on the *input* side of the same operation.
///
/// The addresses survive, because they are what a caller diagnosing a join
/// needs and they are not secret. The redaction is visible rather than an
/// omission, so a reader can tell "no token was set" from "a token was withheld".
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SwarmJoinOptions {
    /// Join token.
    pub token: String,
    /// Existing manager addresses.
    pub remote_addresses: Vec<String>,
    /// Optional local listen address.
    pub listen_address: Option<String>,
    /// Optional local advertise address.
    pub advertise_address: Option<String>,
    /// Optional local data-path address.
    pub data_path_address: Option<String>,
}

impl fmt::Debug for SwarmJoinOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmJoinOptions")
            .field("token", &RedactedToken::new(&self.token))
            .field("remote_addresses", &self.remote_addresses)
            .field("listen_address", &self.listen_address)
            .field("advertise_address", &self.advertise_address)
            .field("data_path_address", &self.data_path_address)
            .finish_non_exhaustive()
    }
}

/// Options for leaving a Swarm.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SwarmLeaveOptions {
    /// Leave even when this node is a manager.
    pub force: bool,
}

/// Fixed text used when a Swarm unlock failure's response text is withheld.
///
/// The unlock request body is a manager unlock key. A direct daemon or an
/// unauthenticated forward proxy can echo request text in a failure message, so
/// the operation never promotes that text into an error. The status is
/// preserved; this text is the whole message. It is fixed rather than a
/// search-and-replace of the key, because a peer can encode or truncate the
/// credential in ways an exact match would miss.
pub(crate) const WITHHELD_UNLOCK_MESSAGE: &str =
    "response text withheld for Swarm unlock because the request carries a manager unlock key";

/// Fixed text used when a Swarm join failure's response text is withheld.
///
/// The join request body carries the join token, which is a credential. A direct
/// daemon or an unauthenticated forward proxy can echo request text in a failure
/// message, so the operation does not promote that text into an error. The
/// status is preserved; this text is the whole message and the whole source
/// chain. Withholding is unconditional rather than a search for the token,
/// because a peer can encode or truncate it in a way an exact match would miss.
pub(crate) const WITHHELD_JOIN_MESSAGE: &str =
    "response text withheld for Swarm join because the request carries a join token";

/// Fixed text used when a Swarm init failure's response text is withheld.
///
/// The init request carries manager addresses, which are internal topology. A
/// direct daemon or an unauthenticated forward proxy can echo request text in a
/// failure message, so no such text is promoted into an error. The status is
/// preserved; this text is the whole message and the whole source chain.
pub(crate) const WITHHELD_INIT_MESSAGE: &str =
    "response text withheld for Swarm init because the request carries manager addresses";

/// Fixed text used when a Swarm update failure's response text is withheld.
///
/// The update request carries the Swarm specification, including free-form
/// `additional` values a caller may have chosen. A direct daemon or an
/// unauthenticated forward proxy can echo request text in a failure message, so
/// no such text is promoted into an error. The status is preserved; this text is
/// the whole message and the whole source chain.
pub(crate) const WITHHELD_UPDATE_MESSAGE: &str =
    "response text withheld for a Swarm update because the request carries the Swarm specification";

/// Fixed text used when a Swarm certificate read failure's response text is
/// withheld.
///
/// The successful answer carries the node's private key. A peer controls a
/// non-success body, and a search for a value the client never sent would be a
/// guess about the encoding, so no response text is promoted into an error. The
/// status is preserved; this text is the whole message and the whole source
/// chain.
pub(crate) const WITHHELD_CERTIFICATES_MESSAGE: &str =
    "response text withheld for a Swarm certificate read because the answer carries a node key";

/// Fixed text used when a Swarm unlock-key read failure's response text is
/// withheld.
///
/// The successful answer carries the manager unlock key. A peer controls a
/// non-success body, and a search for a value the client never sent would be a
/// guess about the encoding, so no response text is promoted into an error. The
/// status is preserved; this text is the whole message and the whole source
/// chain.
pub(crate) const WITHHELD_UNLOCK_KEY_MESSAGE: &str = "response text withheld for a Swarm unlock-key read because the answer carries a manager unlock key";

/// Why a Swarm lifecycle operation refuses an endpoint with no owned target.
///
/// The generated fallback is disabled rather than weakened. the former generated client 0.21.1
/// traces buffered request bodies (`process_request`) and treats `101` and `304`
/// as success without exposing the status; the certificate and unlock-key reads
/// have no generated method at all, so the old facade borrowed a unit-returning
/// `ping` and rewrote its path, which returns the body as text and gives no
/// status check. No public the former generated client API carries these operations without one of
/// those problems, so the safe behavior is to send nothing and say why. The
/// endpoint reason is not quoted because it can contain a host or path.
pub(crate) const SWARM_LIFECYCLE_UNREACHABLE: &str = "the Swarm lifecycle operation cannot be dispatched: the owned transport cannot reach this endpoint, and no generated fallback is used. the former generated client traces buffered request bodies and can report a non-success status as success, and the certificate and unlock-key reads have no generated method at all. Build the client with connect_local or an explicit endpoint the owned transport reaches.";

/// Fixed text used when a service update failure's response text is withheld.
///
/// A service update body can carry `TaskTemplate.ContainerSpec.Env`, and the
/// credential-bearing form carries a registry password in `X-Registry-Auth`.
/// A direct daemon or an unauthenticated proxy can
/// echo either in a failure message, so no such text is promoted into an error.
/// The status is preserved when it is observable; this text is the whole
/// message and the whole source chain.
pub(crate) const WITHHELD_SERVICE_UPDATE_MESSAGE: &str = "response text withheld for a service update because the request may carry service environment or registry credentials";

/// Fixed text used when a service create failure's response text is withheld.
///
/// A create body can carry `TaskTemplate.ContainerSpec.Env` and
/// `TaskTemplate.ContainerSpec.Secrets`, and the credential-bearing form carries
/// a registry password in `X-Registry-Auth`. A direct daemon, a proxy, or
/// A peer can echo any of them in a failure message, so no
/// such text is promoted into an error. The status is preserved when it is
/// observable; this text is the whole message and the whole source chain.
pub(crate) const WITHHELD_SERVICE_CREATE_MESSAGE: &str = "response text withheld for a service create because the request may carry service environment, service secrets, or registry credentials";

/// Why an endpoint the owned transport cannot reach refuses a service create.
///
/// The generated fallback is disabled rather than weakened: the former generated client 0.21.1
/// traces a buffered request body, so a fallback send would put the service
/// environment and any service secret name into a TRACE log before any error
/// path is involved. Its failure path can also echo the same text. There is no
/// facade switch that removes either behavior, so the safe behavior is to send
/// nothing and say why.
const SERVICE_CREATE_UNREACHABLE: &str = "service create is not available on this endpoint: the owned transport cannot reach it, and the generated fallback is disabled because the former generated client 0.21.1 traces the buffered service specification, which may contain service environment, service secrets, or registry credentials";

/// Why an endpoint the owned transport cannot reach refuses a service update.
///
/// The generated fallback is disabled rather than weakened: the former generated client 0.21.1
/// traces a buffered request body (`process_request`), so a fallback send would
/// put the service environment into a TRACE log before any error path is
/// involved. There is no facade switch that removes that logging, so the safe
/// behavior is to send nothing and say why.
const SERVICE_UPDATE_UNREACHABLE: &str = "service update is not available on this endpoint: the owned transport cannot reach it, and the generated fallback is disabled because the former generated client 0.21.1 traces the buffered service specification, which may contain service environment or registry credentials";

/// Options for unlocking a Swarm manager.
///
/// `Debug` is hand-written rather than derived, because `key` is the manager
/// unlock key — the value [`SwarmUnlockKey`] reads back and refuses to render.
/// Redacting the response type and deriving on the request type would protect
/// the credential on the way out and print it on the way in.
///
/// [`SwarmUnlockKey`]: crate::SwarmUnlockKey
#[derive(Clone, Eq, PartialEq)]
pub struct SwarmUnlockOptions {
    /// Manager unlock key.
    pub key: String,
}

impl fmt::Debug for SwarmUnlockOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmUnlockOptions")
            .field("key", &RedactedToken::new(&self.key))
            .finish_non_exhaustive()
    }
}

/// A credential rendered as its presence, never its value.
///
/// Used by the `Debug` impls of the types whose fields *are* credentials, so
/// that "the caller set one" and "the caller left it empty" stay distinguishable
/// — a rendering that simply omitted the field would make a failed join and a
/// join with no token look identical, and both are ordinary misconfigurations a
/// reader of a log line has to tell apart.
///
/// An empty value renders as `None` rather than `<redacted>` on purpose: the
/// absence of a credential is not itself sensitive, and printing `<redacted>` for
/// a field that holds nothing teaches a reader to stop looking at the marker.
struct RedactedToken<'a>(&'a str);

impl<'a> RedactedToken<'a> {
    const fn new(value: &'a str) -> Self {
        Self(value)
    }
}

impl fmt::Debug for RedactedToken<'_> {
    /// Renders `None` for an empty credential and `Some(<redacted>)` otherwise.
    ///
    /// The `if` is load-bearing in one direction only: it must be a *branch on
    /// emptiness*, never a rendering of the value. `match self.0.is_empty()` was
    /// the first spelling and clippy's `match_bool` is right to reject it — a
    /// `match` on a bare bool reads like a decision about the credential rather
    /// than about its length, and the next edit to it could plausibly move the
    /// value into an arm. The redaction does not depend on which branch is taken,
    /// only on the fact that neither arm can reach `self.0`.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            formatter.write_str("None")
        } else {
            formatter.write_str("Some(<redacted>)")
        }
    }
}

/// The role a Swarm join token admits a node as.
///
/// A worker token makes the node a worker; a manager token makes it a manager,
/// which is the only role that can run the Swarm's control plane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwarmJoinTokenRole {
    /// A node that runs tasks.
    Worker,
    /// A node that runs tasks and takes part in the control plane.
    Manager,
}

impl SwarmJoinTokenRole {
    /// Returns the Docker command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Manager => "manager",
        }
    }

    /// Returns the `GET /swarm` `JoinTokens` member that holds this role's token.
    ///
    /// The Engine capitalizes both members, which is the opposite of the role
    /// names its own CLI takes, so the two spellings are mapped here once rather
    /// than at each read.
    pub(crate) const fn join_token_member(self) -> &'static str {
        match self {
            Self::Worker => "Worker",
            Self::Manager => "Manager",
        }
    }
}

/// The root CA certificate and the certificates issued for this node.
///
/// The node key is a credential. It is reachable only through [`Self::key`], it
/// is redacted from `Debug`, and it is zeroized when the value is dropped, so
/// formatting one of these cannot carry it into a log line.
///
/// The type decodes the Engine's `GET /swarm/cert` document directly. It used
/// to be decoded through a private document type, and having two spellings of
/// the same wire shape is how the two drift apart; the manual `Debug`, `Drop`,
/// and accessors below are unaffected by the derive.
#[derive(Deserialize)]
pub struct SwarmCertificates {
    /// The node the certificates were issued for.
    #[serde(rename = "NodeID")]
    node_id: Option<String>,
    /// The PEM-encoded Swarm root CA certificate.
    #[serde(rename = "RootCA")]
    root_ca: Option<String>,
    /// The PEM-encoded certificate issued for this node.
    #[serde(rename = "Cert")]
    cert: Option<String>,
    /// The PEM-encoded private key issued for this node.
    #[serde(rename = "Key")]
    key: Option<String>,
}

impl SwarmCertificates {
    /// Returns the node the certificates were issued for.
    #[must_use]
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }

    /// Returns the PEM-encoded Swarm root CA certificate.
    #[must_use]
    pub fn root_ca(&self) -> Option<&str> {
        self.root_ca.as_deref()
    }

    /// Returns the PEM-encoded certificate issued for this node.
    #[must_use]
    pub fn cert(&self) -> Option<&str> {
        self.cert.as_deref()
    }

    /// Returns the PEM-encoded private key issued for this node.
    ///
    /// The key is a private credential of the Swarm. A caller that prints it is
    /// the caller's decision; nothing in this crate logs, formats, or
    /// serializes it on the way here.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl fmt::Debug for SwarmCertificates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmCertificates")
            .field("node_id", &self.node_id)
            .field("root_ca", &self.root_ca)
            .field("cert", &self.cert)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for SwarmCertificates {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

/// The manager unlock key of a Swarm with autolock enabled.
///
/// The key is a credential: it is redacted from `Debug` and zeroized when the
/// value is dropped.
///
/// The type decodes the Engine's `GET /swarm/unlockkey` document directly, for
/// the reason [`SwarmCertificates`] gives.
#[derive(Deserialize)]
pub struct SwarmUnlockKey {
    /// The unlock key, when the Swarm has autolock enabled.
    #[serde(rename = "UnlockKey")]
    key: Option<String>,
}

impl SwarmUnlockKey {
    /// Returns the unlock key, when the Swarm has one.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl fmt::Debug for SwarmUnlockKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmUnlockKey")
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for SwarmUnlockKey {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}

/// Complete, conflict-safe Swarm update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwarmUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: SwarmSpec,
    /// Rotate the worker join token.
    pub rotate_worker_token: bool,
    /// Rotate the manager join token.
    pub rotate_manager_token: bool,
    /// Rotate the manager unlock key.
    pub rotate_manager_unlock_key: bool,
}

/// A `#[serde(flatten)]` catch-all map, rendered as a count instead of itself.
///
/// Every type with a flattened `additional` accepts **arbitrary daemon JSON** in
/// that map. It is not a typed projection with a known member set; it is whatever
/// the peer sent that the named fields did not consume, at any depth. So the map
/// is a channel the daemon — or anyone standing in for it — chooses, and a
/// `Debug` that renders it renders daemon-chosen strings verbatim.
///
/// That is not hypothetical here. A `GET /swarm` document reports the same
/// cluster state under two spellings: the Engine's own top-level `JoinTokens`,
/// which [`SwarmInfo`] names and so redacts, and swarmkit's `ClusterInfo`, which
/// nests a second `JoinTokens` and is *not* a named field, so it lands here. One
/// Engine version change, or one daemon choosing the other spelling, puts the
/// join tokens back into a `Debug` output through a field that looks like
/// forward-compatibility plumbing.
///
/// Hence the count, and only the count. Key names were considered and rejected:
/// a name is daemon-chosen too, so printing one is printing daemon-controlled
/// text, and the count already answers the question a reader actually has —
/// "did the daemon send me anything this crate does not model?"
///
/// [`SwarmInfo`]: crate::SwarmInfo
struct AdditionalCount(usize);

impl fmt::Debug for AdditionalCount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} unmodeled member(s)", self.0)
    }
}

/// Reports the size of a free-form member, never its content.
///
/// The size is worth printing: it distinguishes "the daemon sent this member"
/// from "it did not", and "this specification sets five labels" from "it sets
/// none", which is the question a log line about a service asks. The content is
/// not, because these members are operator- or daemon-written text.
/// `TaskTemplate` is where a task's environment lives — the `docker service
/// create --env` credential location — and `PreviousSpec` is the same document
/// one revision back, so a derived `Debug` on a service renders a credential
/// from two directions. The same is true one level up: a label value and a
/// placement constraint are free-form strings, and an operator can put anything
/// in either.
struct Redacted {
    size: usize,
    unit: &'static str,
}

impl Redacted {
    /// A counted collection, such as labels, constraints, or preferences.
    const fn values(count: usize) -> Self {
        Self {
            size: count,
            unit: "value(s)",
        }
    }

    /// A byte length, such as a JSON member or a free-form string.
    const fn bytes(length: usize) -> Self {
        Self {
            size: length,
            unit: "byte(s)",
        }
    }

    /// A JSON member, summarized by its serialized size.
    fn json(value: Option<&serde_json::Value>) -> Option<Self> {
        value.map(|value| Self::bytes(value.to_string().len()))
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<redacted; {} {}>", self.size, self.unit)
    }
}

/// User-modifiable Swarm specification.
///
/// Unknown members returned by the v1.53 Engine are retained in stable key
/// order so conflict-safe updates do not silently discard daemon state.
///
/// `Debug` is hand-written rather than derived, because `additional` is an
/// arbitrary daemon-supplied map rather than a set of typed members, and a
/// derive renders it in full. That matters past this type: [`SwarmUpdateOptions`]
/// holds a `SwarmSpec`, so a derived `Debug` there routes the same untrusted
/// values into every panic message about an update.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSpec {
    /// Swarm name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// User-defined labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Additional v1.53 specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmSpec {
    /// Reports the members this crate models, and how much it does not.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSpec")
            .field("name", &self.name)
            .field("labels", &self.labels)
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Docker Swarm metadata.
///
/// `Debug` is hand-written rather than derived, and for two separate reasons —
/// either of which alone would defeat a redaction that handled only the other.
///
/// - `join_tokens` holds the worker and manager join tokens, which are
///   credentials. That is the same class of value as [`SwarmCertificates::key`]
///   and [`SwarmUnlockKey::key`], which are redacted beside this type, and the
///   inconsistency was the defect: a caller printing a `SwarmInfo` for its ID and
///   version has no way to ask for the tokens and no way to stop them.
/// - `additional` is a `#[serde(flatten)]` catch-all holding arbitrary daemon
///   JSON, and the join tokens arrive there too under swarmkit's `ClusterInfo`
///   spelling. The catch-all is therefore reported as a count of unmodelled
///   members rather than as itself — key names withheld too, since a key name is
///   daemon-chosen — so redacting the named field alone is not a redaction with
///   a documented bypass.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmInfo {
    /// Swarm ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Swarm version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Complete Swarm specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSpec>,
    /// Join tokens, when returned by the daemon.
    #[serde(rename = "JoinTokens", skip_serializing_if = "Option::is_none")]
    pub join_tokens: Option<serde_json::Value>,
    /// Additional stable v1.53 Swarm members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmInfo {
    /// Reports the Swarm's identity, and how much of its state is not modelled.
    ///
    /// The tokens themselves are never formatted, in either spelling. A derived
    /// `Debug` renders `join_tokens` in full because `serde_json::Value`'s own
    /// `Debug` prints its strings verbatim, and it renders `additional` in full
    /// for the same reason — which is where the tokens come back under
    /// `ClusterInfo`. `docker swarm join --token` accepts what is printed, so a
    /// rendered `SwarmInfo` is an invitation to join somebody else's Swarm.
    ///
    /// The redactions are *visible* rather than omissions. A reader has to be
    /// able to tell "the daemon sent no tokens" from "the tokens were withheld",
    /// which are different facts about a node, and has to be able to tell that
    /// unmodelled members were received rather than silently dropped — that is
    /// what makes a `SwarmInfo` worth logging at all.
    ///
    /// `finish_non_exhaustive` is deliberate: a member added to this type later
    /// renders as `..` rather than appearing in full by default. That is the
    /// property this impl exists to have, and a plain `finish()` would quietly
    /// give it back the moment someone added a field and kept deriving.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmInfo")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("spec", &self.spec)
            .field(
                "join_tokens",
                &self.join_tokens.as_ref().map(|_| "<redacted>"),
            )
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

impl SwarmInfo {
    /// Returns the root CA certificate the Swarm validates node certificates
    /// against, as PEM.
    ///
    /// This is what `docker swarm ca` prints, read from `GET /swarm`. The Engine
    /// reports it as a **top-level** `TLSInfo.TrustRoot`; the `swarmkit` store
    /// nests the same value under `ClusterInfo`, so a document carrying
    /// both spellings is read from the Engine's one first. During a root
    /// rotation the value holds more than one certificate, so it is returned
    /// whole rather than split.
    #[must_use]
    pub fn trust_root(&self) -> Option<&str> {
        fn trust_root_in(tls_info: &serde_json::Value) -> Option<&str> {
            tls_info
                .get("TrustRoot")
                .and_then(serde_json::Value::as_str)
        }
        trust_root_in(self.additional.get("TLSInfo")?)
            .or_else(|| self.additional.get("ClusterInfo").and_then(trust_root_in))
    }
}

/// The port a Swarm manager listens on when the spec does not say.
///
/// 2377 is Docker's Swarm default, and it is what `Swarm.RemoteManagers[].Addr`
/// reports on a Swarm left at the default. A Swarm that listens elsewhere
/// reports that port in the same field, so this is only the fallback for a
/// document that has no manager address at all.
const DEFAULT_SWARM_PORT: u16 = 2377;

/// Complete service specification used for create, update, and rollback.
///
/// `task_template`, `mode`, `endpoint_spec`, and the two update configurations are
/// carried as [`serde_json::Value`] because each is a tagged union in the Engine
/// model — `Replicated` or `Global`, a port list or a mode string — and a typed
/// wrapper would have to encode a grammar the Engine owns. The members that *are*
/// structures are typed here, so a caller building a spec does not hand-assemble
/// JSON for them.
///
/// # `Debug` is summarized rather than derived
///
/// Every JSON-valued member is daemon-chosen at any depth, and `task_template`
/// reaches `ContainerSpec.Env` — the `docker service create --env` credential
/// location. The typed members are not uniformly safe either: labels are
/// operator-written key/value pairs and a placement constraint or restart action
/// is a free-form string. A derived `Debug` renders all of it, and it reaches a
/// panic message, a test failure, and a log line. This impl summarizes the name, the
/// size of each JSON member, the count of labels, the shape of the placement and
/// restart policy, and a count of unmodelled members. `Serialize` is unchanged: a
/// caller that wants the document serializes it deliberately.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceSpec {
    /// Service name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Service labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Task template.
    #[serde(rename = "TaskTemplate", skip_serializing_if = "Option::is_none")]
    pub task_template: Option<serde_json::Value>,
    /// Replicated, global, or job mode.
    #[serde(rename = "Mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<serde_json::Value>,
    /// Endpoint specification.
    #[serde(rename = "EndpointSpec", skip_serializing_if = "Option::is_none")]
    pub endpoint_spec: Option<serde_json::Value>,
    /// Deprecated service-level network attachments.
    #[serde(rename = "Networks", skip_serializing_if = "Option::is_none")]
    pub networks: Option<serde_json::Value>,
    /// Update configuration.
    #[serde(rename = "UpdateConfig", skip_serializing_if = "Option::is_none")]
    pub update_config: Option<serde_json::Value>,
    /// Rollback configuration.
    #[serde(rename = "RollbackConfig", skip_serializing_if = "Option::is_none")]
    pub rollback_config: Option<serde_json::Value>,
    /// Which nodes may run this service's tasks.
    ///
    /// Typed rather than left in `additional`, because it is the member a caller
    /// most often sets from a document's `placement:` block and hand-writing its
    /// `Constraints` array is how a misspelled key turns into a service that
    /// schedules everywhere.
    ///
    /// The Engine reads and reports this inside `Spec.TaskTemplate`, not at the
    /// specification root. [`DockerClient::create_service`] and
    /// [`DockerClient::update_service`] move the typed field into `TaskTemplate`,
    /// and refuse a second placement representation supplied beside it; so do
    /// `raw::service_create` and `raw::service_update`. An inspect of a real
    /// daemon leaves this empty and the value is in `task_template`.
    #[serde(rename = "Placement", skip_serializing_if = "Option::is_none")]
    pub placement: Option<ServicePlacement>,
    /// When and how often a failed task is restarted.
    ///
    /// A member of `Spec.TaskTemplate` on the wire, with the same routing and
    /// refusal rules as [`Self::placement`]. Like a placement, it is read from
    /// [`Self::task_template`] after an inspect.
    #[serde(rename = "RestartPolicy", skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<ServiceRestartPolicy>,
    /// Additional v1.53 specification members.
    ///
    /// A member of a typed sub-object that the type cannot express is retained
    /// here under a `"<SubObject>.<Member>"` key for the raw writers.
    /// `raw::service_create` and `raw::service_update` split only at the first
    /// dot and merge the remainder as a literal member name into that object;
    /// this is an explicit interpretation, not preservation of a literal
    /// top-level key. The facade refuses every dotted key because it cannot
    /// distinguish the two. Unknown non-dotted members are retained on read; a
    /// top-level `Placement` or `RestartPolicy` entry is refused by
    /// [`DockerClient::create_service`], [`DockerClient::update_service`], and
    /// the raw writers even when no typed competitor is present, and it has no
    /// lossless write because `TaskTemplate` changes its location and meaning.
    ///
    /// # Case-folded and non-ASCII keys are refused
    ///
    /// Every key here is **ASCII**, and no key may differ from a typed root
    /// member or from another key only by ASCII case. The Engine matches JSON
    /// member names case-insensitively (Go folds names), so `Labels` and
    /// `labels`, or `Placement` and `placement`, are one member to the daemon
    /// and the winner depends on the encoded order. The facade and the raw
    /// writers therefore refuse a second spelling before dispatch rather than
    /// send a request whose meaning the daemon decides. The same rule applies
    /// to keys inside `TaskTemplate`, its `Placement` and `RestartPolicy`
    /// objects, and the top-level objects of the other typed root members.
    ///
    /// Non-ASCII keys are refused on those surfaces because Go's fold is
    /// Unicode-aware: a key such as `Labelſ` can fold onto `Labels`, and this
    /// crate does not reproduce a daemon's fold table. A service-defined map
    /// key with a non-ASCII or case-variant spelling — a label key, a sysctl —
    /// belongs in the typed [`Self::labels`] map or inside
    /// [`Self::task_template`], where declared user maps are preserved without
    /// interpreting their keys as modeled members. ASCII unknown scalar members
    /// remain accepted, but object/array values outside the manually inventoried
    /// Moby 1.55 schema are refused before a create or update is dispatched.
    /// Inspect still preserves such structured values, so an inspected spec
    /// containing one may need the unknown member removed or converted before it
    /// can be written back. The inventory is not a guarantee for future daemon
    /// schemas; see the crate's service schema compatibility note.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for ServiceSpec {
    /// Reports the typed members, and how much of the document is not modelled.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceSpec")
            .field(
                "name",
                &self.name.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field(
                "labels",
                &self
                    .labels
                    .as_ref()
                    .map(|labels| Redacted::values(labels.len())),
            )
            .field(
                "task_template",
                &Redacted::json(self.task_template.as_ref()),
            )
            .field("mode", &Redacted::json(self.mode.as_ref()))
            .field(
                "endpoint_spec",
                &Redacted::json(self.endpoint_spec.as_ref()),
            )
            .field("networks", &Redacted::json(self.networks.as_ref()))
            .field(
                "update_config",
                &Redacted::json(self.update_config.as_ref()),
            )
            .field(
                "rollback_config",
                &Redacted::json(self.rollback_config.as_ref()),
            )
            .field("placement", &self.placement)
            .field("restart_policy", &self.restart_policy)
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Node selection for a Swarm service.
///
/// `Debug` is hand-written for the same reason [`ServiceSpec`]'s is:
/// `constraints` and `preferences` are free-form expressions an operator writes,
/// and a derived impl renders them in full.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServicePlacement {
    /// Constraints a node must satisfy, such as `node.role == worker`.
    #[serde(rename = "Constraints", default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    /// Soft placement preferences, applied in order.
    #[serde(rename = "Preferences", default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<String>,
    /// Tasks this service may place on one node. Zero means no limit.
    #[serde(rename = "MaxReplicas", default, skip_serializing_if = "is_zero")]
    pub max_replicas: u32,
}

impl fmt::Debug for ServicePlacement {
    /// Reports the placement's shape, and how many values it carries.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServicePlacement")
            .field("constraints", &Redacted::values(self.constraints.len()))
            .field("preferences", &Redacted::values(self.preferences.len()))
            .field("max_replicas", &self.max_replicas)
            .finish_non_exhaustive()
    }
}

/// When and how often Swarm restarts a failed task.
///
/// `Debug` is hand-written: `condition` and `failure_action` are strings the
/// daemon sends, so a derived impl would render them verbatim.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceRestartPolicy {
    /// `none`, `on-failure`, or `any`.
    #[serde(rename = "Condition")]
    pub condition: String,
    /// How long to wait before restarting, in nanoseconds.
    #[serde(rename = "Delay", skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,
    /// Retries allowed within `window`.
    #[serde(rename = "MaxAttempts", skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<i64>,
    /// Window retries are counted in, in nanoseconds.
    #[serde(rename = "Window", skip_serializing_if = "Option::is_none")]
    pub window: Option<i64>,
    /// `pause`, `continue`, or `rollback`.
    #[serde(rename = "FailureAction", skip_serializing_if = "Option::is_none")]
    pub failure_action: Option<String>,
}

impl fmt::Debug for ServiceRestartPolicy {
    /// Reports the policy's shape and numbers, never its free-form strings.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceRestartPolicy")
            .field("condition", &Redacted::bytes(self.condition.len()))
            .field("delay", &self.delay)
            .field("max_attempts", &self.max_attempts)
            .field("window", &self.window)
            .field(
                "failure_action",
                &self
                    .failure_action
                    .as_ref()
                    .map(|action| Redacted::bytes(action.len())),
            )
            .finish_non_exhaustive()
    }
}

/// Whether a `u32` is zero, for a `skip_serializing_if` that treats zero as unset.
///
/// Takes the value by reference because serde calls a `skip_serializing_if` with a
/// reference; the lint about passing it by value does not apply to a function
/// whose whole job is to be handed one.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Published or exposed service port.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServicePort {
    /// IP protocol.
    #[serde(rename = "Protocol", skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Container target port.
    #[serde(rename = "TargetPort", skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u32>,
    /// Published host port.
    #[serde(rename = "PublishedPort", skip_serializing_if = "Option::is_none")]
    pub published_port: Option<u32>,
    /// Published host IP. Raw inspect projects string values; facade inspect
    /// omits it and retains the endpoint.
    #[serde(rename = "PublishedIP", skip_serializing_if = "Option::is_none")]
    pub published_ip: Option<String>,
    /// Endpoint publishing mode.
    #[serde(rename = "PublishMode", skip_serializing_if = "Option::is_none")]
    pub publish_mode: Option<String>,
}

impl fmt::Debug for ServicePort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServicePort")
            .field(
                "protocol",
                &self.protocol.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field("target_port", &self.target_port)
            .field("published_port", &self.published_port)
            .field(
                "published_ip",
                &self.published_ip.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field(
                "publish_mode",
                &self.publish_mode.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .finish()
    }
}

/// Running and desired task counts for a service.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceStatus {
    /// Running task count.
    #[serde(rename = "RunningTasks")]
    pub running_tasks: u64,
    /// Desired task count.
    #[serde(rename = "DesiredTasks")]
    pub desired_tasks: u64,
}

/// Docker service metadata.
///
/// # `Debug` is summarized rather than derived
///
/// The owned inspect route retains the daemon's document whole: `additional`
/// carries the endpoint, `PreviousSpec`, and any member this crate does not
/// name, and `spec` carries the task template. `PreviousSpec` is a complete
/// service specification one revision back, so it holds the environment the old
/// revision ran with — the same credential class `TaskTemplate.ContainerSpec.Env`
/// holds in the current one. A derived `Debug` renders both in full from a value
/// a caller commonly prints after a failed update, so this impl summarizes identity,
/// published ports, task counts, and a count of unmodelled members, and
/// [`ServiceSpec`]'s own `Debug` summarizes its JSON members.
///
/// `Serialize` is unchanged. `ndocker service inspect --json`, and a caller that
/// serializes deliberately, still see the whole document; the redaction is only
/// what `{:?}` puts into a panic or a log.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmService {
    /// Service ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Service version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Current service specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<ServiceSpec>,
    /// Published/exposed ports.
    #[serde(rename = "Ports", skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<ServicePort>>,
    /// Current task counts.
    #[serde(rename = "ServiceStatus", skip_serializing_if = "Option::is_none")]
    pub status: Option<ServiceStatus>,
    /// Additional stable v1.53 service members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmService {
    /// Reports the service's identity and state, and how much is not modelled.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmService")
            .field("id", &self.id.as_ref().map(|s| Redacted::bytes(s.len())))
            .field("version", &self.version)
            .field(
                "created_at",
                &self.created_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field(
                "updated_at",
                &self.updated_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field("spec", &self.spec)
            .field("ports", &self.ports)
            .field("status", &self.status)
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// ID and warnings returned by service creation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceCreateResult {
    /// Created service ID.
    pub id: String,
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Warnings returned by service update or rollback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceUpdateResult {
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Complete conflict-safe service update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: ServiceSpec,
    /// Ask the daemon to roll back to `PreviousSpec`.
    pub rollback: bool,
}

/// User-modifiable node specification.
///
/// # `Debug` withholds the values
///
/// A node name, a label key and value, and the values of `additional` are
/// free-form strings an operator or a daemon writes. Node labels are commonly
/// used for placement constraints and can name hosts, zones, teams, or other
/// metadata a log line should not carry. The type therefore reports sizes,
/// counts, and the numeric members rather than the text, and `Serialize` is
/// unchanged so `ndocker node inspect --json` still carries the document.
///
/// # Reserved `additional` keys
///
/// `additional` is flattened into the same JSON object as the modeled fields,
/// so it may not carry `Name`, `Labels`, `Role`, or `Availability`. A second
/// spelling would either emit a duplicate key or reach a modeled member while
/// the typed field is absent. The node writers refuse such a specification
/// before dispatch. All non-ASCII additional keys are also refused
/// conservatively because Unicode simple folding can match modeled names;
/// unrelated non-ASCII extensions therefore cannot be written either.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeSpec {
    /// Node name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Node labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// `worker`, `manager`, or the empty string for unspecified.
    #[serde(rename = "Role", skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// `active`, `pause`, `drain`, or the empty string for unspecified.
    #[serde(rename = "Availability", skip_serializing_if = "Option::is_none")]
    pub availability: Option<String>,
    /// Additional v1.53 node-specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for NodeSpec {
    /// Reports the shape and the label count, not the free-form values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeSpec")
            .field(
                "name",
                &self.name.as_ref().map(|name| Redacted::bytes(name.len())),
            )
            .field(
                "labels",
                &self
                    .labels
                    .as_ref()
                    .map(|labels| Redacted::values(labels.len())),
            )
            .field(
                "role",
                &self.role.as_ref().map(|role| Redacted::bytes(role.len())),
            )
            .field(
                "availability",
                &self
                    .availability
                    .as_ref()
                    .map(|value| Redacted::bytes(value.len())),
            )
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Manager reachability and leadership state.
///
/// `Addr`, the address other members use to reach this manager, is one of the
/// members the Engine sends and this type does not name, so it is retained in
/// `additional` rather than dropped.
///
/// # `Debug` withholds the address
///
/// `additional` is an arbitrary daemon map and `reachability` is a daemon
/// string, so a derived `Debug` would print peer-chosen text.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeManagerStatus {
    /// Whether this manager is the leader.
    #[serde(rename = "Leader", skip_serializing_if = "Option::is_none")]
    pub leader: Option<bool>,
    /// Manager reachability.
    #[serde(rename = "Reachability", skip_serializing_if = "Option::is_none")]
    pub reachability: Option<String>,
    /// Additional stable v1.53 manager-status members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for NodeManagerStatus {
    /// Reports leadership and the amount of unmodelled state, not its text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeManagerStatus")
            .field("leader", &self.leader)
            .field(
                "reachability",
                &self
                    .reachability
                    .as_ref()
                    .map(|value| Redacted::bytes(value.len())),
            )
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Docker node metadata.
///
/// # `Debug` withholds the document's free-form members
///
/// The owned route retains the daemon's `Description`, `Status`, and every
/// member this type does not name in `additional`. `Description` is where a
/// node reports its hostname, engine labels and plugins, and `TLSInfo`, and
/// `Status` and `additional` are daemon-chosen at every depth. A derived
/// `Debug` would print all of it, which is the wrong thing to hand a panic
/// message or a log line about a node. This impl reports identity sizes,
/// version, the specification summary, the manager-status summary, and a count
/// of unmodelled members instead. `Serialize` is unchanged, so
/// `ndocker node inspect --json` still sees the whole document.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmNode {
    /// Node ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Node version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Node specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<NodeSpec>,
    /// Runtime state.
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
    /// Manager status.
    #[serde(rename = "ManagerStatus", skip_serializing_if = "Option::is_none")]
    pub manager_status: Option<NodeManagerStatus>,
    /// Engine version reported by the node.
    ///
    /// On the owned raw route this is a view of
    /// `Description.Engine.EngineVersion`. If the document also carried an
    /// actual top-level `EngineVersion`, the raw projection keeps it in
    /// [`SwarmNode::additional`] beside this view. Serializing such a raw value
    /// can therefore emit duplicate `EngineVersion` keys, and the raw API does
    /// not promise round-trip stability for it. On an endpoint the owned
    /// transport reaches, `DockerClient::list_nodes` and
    /// `DockerClient::inspect_node` refuse that document before projection, so
    /// a node they return never has both readers populated. A caller that
    /// mutates the public fields can recreate the duplicate.
    #[serde(rename = "EngineVersion", skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,
    /// Additional stable v1.53 node members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmNode {
    /// Reports the node's identity, shape, and how much is not modelled.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmNode")
            .field("id", &self.id.as_ref().map(|s| Redacted::bytes(s.len())))
            .field("version", &self.version)
            .field(
                "created_at",
                &self.created_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field(
                "updated_at",
                &self.updated_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field("spec", &self.spec)
            .field("status", &Redacted::json(self.status.as_ref()))
            .field("manager_status", &self.manager_status)
            .field(
                "engine_version",
                &self
                    .engine_version
                    .as_ref()
                    .map(|s| Redacted::bytes(s.len())),
            )
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Complete conflict-safe node update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: NodeSpec,
}

/// Options for removing a node.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NodeRemoveOptions {
    /// Remove even when the node is a manager.
    pub force: bool,
}

/// Config specification retained at the v1.53 boundary.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmConfigSpec {
    /// Config name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Config labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Base64-encoded config data returned by Docker.
    #[serde(rename = "Data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Additional v1.53 config-specification members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Options for creating a config.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigCreateOptions {
    /// Config name.
    pub name: String,
    /// Config data.
    pub data: Option<Vec<u8>>,
    /// Config labels.
    pub labels: Option<BTreeMap<String, String>>,
}

/// Docker config metadata.
///
/// Members this type does not name are retained in `additional`, in the order
/// the daemon sent them, so a decode never reports a config that is missing
/// something the Engine reported.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmConfig {
    /// Config ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Config version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Config specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmConfigSpec>,
    /// Additional stable v1.53 config members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Complete conflict-safe config update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement specification.
    pub spec: SwarmConfigSpec,
}

/// Secret bytes with redacted diagnostics and zeroizing destruction.
pub struct SwarmSecretData(Vec<u8>);

impl SwarmSecretData {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the secret bytes without creating another owning copy.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SwarmSecretData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSecretData")
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Drop for SwarmSecretData {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret specification returned by Docker.
///
/// # Secret data has no typed member
///
/// The Engine declares `SecretSpec.Data` for *creation* only and does not return
/// it from an inspect or a list. If a peer sends `Data` anyway — a daemon bug, a
/// substituted response, or a proxy — it is not a member this type names, so it
/// is retained in [`SwarmSecretSpec::additional`] like any other unmodelled
/// object-level member. The value can therefore carry secret bytes: `Serialize`
/// (and therefore `ndocker secret inspect`, in either output format) emits what
/// the peer sent.
///
/// # What retention does and does not mean
///
/// Retention is **object-level and at this depth**: a member of the `Spec`
/// object that this type does not name lands in `additional`. It is not a claim
/// that the read is lossless. `Version` is a typed [`SwarmVersion`] with no
/// catch-all, so a member inside `Version` is dropped. A duplicate JSON key
/// cannot be represented: a duplicate known key (`Name`, `Labels`, `Driver`,
/// `Spec`, ...) is a decode error, and a duplicate unmodelled key (for example
/// two `Spec.Data` members) collapses to one value in the owned decoder rather
/// than retaining both. A `null` or non-string `Data` is retained as the JSON
/// value it is; there is no generated secret-read route with a typed `Data`
/// field to omit it or refuse it.
///
/// # `Debug` withholds the values
///
/// `Data`, a label value, and the driver document are peer-chosen, and `Data`
/// is secret material. A derived `Debug` would print them into a panic message,
/// a test failure, or a log line, so this impl reports sizes and counts instead.
/// `Serialize` is deliberately unchanged: a caller that serializes gets the
/// document it asked for, and the contract above says what that document can
/// contain.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSecretSpec {
    /// Secret name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Secret labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// External secret driver, when configured.
    #[serde(rename = "Driver", skip_serializing_if = "Option::is_none")]
    pub driver: Option<serde_json::Value>,
    /// Additional v1.53 secret-specification members.
    ///
    /// An unexpected `Data` member lands here at this object level. It is
    /// retained rather than dropped, [`Debug`] never prints it, and a duplicate
    /// unmodelled key collapses to one value rather than retaining both.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmSecretSpec {
    /// Reports the shape, never the values.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSecretSpec")
            .field(
                "name",
                &self.name.as_ref().map(|name| Redacted::bytes(name.len())),
            )
            .field(
                "labels",
                &self
                    .labels
                    .as_ref()
                    .map(|labels| Redacted::values(labels.len())),
            )
            .field("driver", &Redacted::json(self.driver.as_ref()))
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Options for creating a secret.
#[derive(Debug)]
pub struct SecretCreateOptions {
    /// Secret name.
    pub name: String,
    /// Secret data.
    pub data: Option<SwarmSecretData>,
    /// Secret labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl SecretCreateOptions {
    /// Creates named secret options.
    #[must_use]
    pub fn new(name: impl Into<String>, data: Option<SwarmSecretData>) -> Self {
        Self {
            name: name.into(),
            data,
            labels: None,
        }
    }
}

/// Docker secret metadata.
///
/// Members this type does not name are retained in `additional`, in the order
/// the daemon sent them, so a decode never reports a secret that is missing
/// something the Engine reported.
///
/// # Secret data
///
/// The Engine does not return `SecretSpec.Data` from an inspect or a list. If a
/// peer sends it anyway, it is retained in [`SwarmSecretSpec::additional`] rather
/// than typed or dropped; `Serialize` emits it and [`Debug`] does not. See
/// [`SwarmSecretSpec`] for the full contract.
///
/// # `Debug` withholds the values
///
/// The id and timestamps are identifiers, the specification has its own
/// withholding impl, and `additional` is arbitrary peer JSON. A derived `Debug`
/// would print all of it, including an unexpected `Data`, into a panic message
/// or a log line, so this impl reports identity lengths and a count instead.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmSecret {
    /// Secret ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Secret version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Secret specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSecretSpec>,
    /// Additional stable v1.53 secret members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

impl fmt::Debug for SwarmSecret {
    /// Reports the secret's identity, shape, and how much is not modelled.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwarmSecret")
            .field("id", &self.id.as_ref().map(|s| Redacted::bytes(s.len())))
            .field("version", &self.version)
            .field(
                "created_at",
                &self.created_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field(
                "updated_at",
                &self.updated_at.as_ref().map(|s| Redacted::bytes(s.len())),
            )
            .field("spec", &self.spec)
            .field("additional", &AdditionalCount(self.additional.len()))
            .finish_non_exhaustive()
    }
}

/// Complete conflict-safe secret update input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretUpdateOptions {
    /// Version read by the caller.
    pub version: u64,
    /// Complete replacement metadata. Secret data cannot be changed by the
    /// Engine update endpoint and is therefore not part of this type.
    pub spec: SwarmSecretSpec,
}

/// Task state and failure information.
///
/// `ContainerStatus`, the container's own exit and health state, is a member the
/// Engine sends and this type does not name, so it is retained in `additional`
/// rather than dropped.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwarmTaskStatus {
    /// Runtime state.
    #[serde(rename = "State", skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Human-readable daemon message.
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Daemon error.
    #[serde(rename = "Err", skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Status timestamp.
    #[serde(rename = "Timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Additional stable v1.53 task-status members.
    #[serde(flatten)]
    pub additional: BTreeMap<String, serde_json::Value>,
}

/// Docker Swarm task metadata.
///
/// `spec` is the sole authority for serialized `Spec`; `additional["Spec"]` is a read-time compatibility snapshot whose mutation or removal is ignored during serialization.
///
/// This changes behavior for callers who previously mutated the mirror expecting
/// serialization to reflect it. Unmodelled `Spec` members survive only inside a
/// non-null `Spec`; owned reads retain unmodelled top-level members in
/// `additional`. This is not byte-for-byte JSON fidelity. Setting `spec` to
/// `None` removes `Spec`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "SwarmTaskWire")]
pub struct SwarmTask {
    /// Task ID.
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Task version.
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<SwarmVersion>,
    /// Creation timestamp.
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Last-update timestamp.
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Task name.
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Task labels.
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    /// Container image used by the task.
    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Owning service ID.
    #[serde(rename = "ServiceID")]
    pub service_id: String,
    /// Replica slot.
    #[serde(rename = "Slot")]
    pub slot: i64,
    /// Assigned node ID.
    #[serde(rename = "NodeID")]
    pub node_id: String,
    /// Runtime status.
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    pub status: Option<SwarmTaskStatus>,
    /// Desired state.
    #[serde(rename = "DesiredState", skip_serializing_if = "Option::is_none")]
    pub desired_state: Option<String>,
    /// Complete task specification.
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
    /// Additional stable v1.53 task members.
    #[serde(flatten, serialize_with = "serialize_task_additional")]
    pub additional: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct SwarmTaskWire {
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<SwarmVersion>,
    #[serde(rename = "CreatedAt", skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(rename = "UpdatedAt", skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "Labels", skip_serializing_if = "Option::is_none")]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "Image", skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(rename = "ServiceID")]
    service_id: String,
    #[serde(rename = "Slot")]
    slot: i64,
    #[serde(rename = "NodeID")]
    node_id: String,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<SwarmTaskStatus>,
    #[serde(rename = "DesiredState", skip_serializing_if = "Option::is_none")]
    desired_state: Option<String>,
    #[serde(rename = "Spec", skip_serializing_if = "Option::is_none")]
    spec: Option<serde_json::Value>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl From<SwarmTaskWire> for SwarmTask {
    fn from(wire: SwarmTaskWire) -> Self {
        let mut additional = wire.additional;
        if let Some(spec) = &wire.spec {
            additional.insert("Spec".to_owned(), spec.clone());
        }
        Self {
            id: wire.id,
            version: wire.version,
            created_at: wire.created_at,
            updated_at: wire.updated_at,
            name: wire.name,
            labels: wire.labels,
            image: wire.image,
            service_id: wire.service_id,
            slot: wire.slot,
            node_id: wire.node_id,
            status: wire.status,
            desired_state: wire.desired_state,
            spec: wire.spec,
            additional,
        }
    }
}

fn serialize_task_additional<S>(
    additional: &BTreeMap<String, serde_json::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(None)?;
    for (key, value) in additional {
        if key != "Spec" {
            map.serialize_entry(key, value)?;
        }
    }
    map.end()
}

/// Options for service or task log streams.
pub type SwarmLogOptions = crate::ContainerLogsOptions;

/// Refuses ambiguous config update fields before serialization.
pub(crate) fn validate_config_spec(spec: &SwarmConfigSpec) -> Result<(), Error> {
    if spec.additional.keys().any(|key| {
        !key.is_ascii()
            || ["name", "labels", "data", "templating"]
                .iter()
                .any(|reserved| key.eq_ignore_ascii_case(reserved))
    }) {
        return Err(Error::invalid_input(
            "the config specification carries a reserved or non-ASCII member in additional",
        ));
    }
    Ok(())
}

/// The fixed refusal for a secret update that carries an unexpected `Data`.
///
/// The message names the member, never its value. It is shared by the facade
/// and the raw writer so both refuse before dispatch and neither can drift into
/// forwarding secret bytes on a request that cannot use them.
pub(crate) const SECRET_DATA_UPDATE_REFUSAL: &str = "the secret specification carries a Data member, which a secret read does not return and a secret update cannot change";

/// The fixed refusal for a duplicate reserved member in `additional`.
///
/// `Name`, `Labels`, and `Driver` are typed fields on `SwarmSecretSpec`. A
/// second spelling in the flattened map can serialize a duplicate JSON key or
/// bypass the typed field, and which value survives depends on the decoder
/// rather than the caller. The message names the reserved set, never a value.
const SECRET_RESERVED_UPDATE_REFUSAL: &str = "the secret specification carries a reserved member in additional that belongs in the typed Name, Labels, or Driver field";

/// The typed secret members, lowercased for a case-insensitive comparison.
const SECRET_RESERVED_KEYS: [&str; 3] = ["name", "labels", "driver"];

/// The fixed refusal for a non-ASCII member in `additional`.
///
/// Go's `encoding/json` matches field names with Unicode case folding, so a
/// key such as `Label\u{017f}` can reach `Labels`. This crate has no
/// dependency-free full Unicode fold table, so it refuses the whole non-ASCII
/// class conservatively. This is not a claim that only ASCII can collide; it is
/// the bound the guard can actually enforce.
const SECRET_NON_ASCII_UPDATE_REFUSAL: &str = "the secret specification carries a non-ASCII member in additional; the Engine's decoder folds field names with Unicode case folding, and this crate has no dependency-free full fold table, so the key is refused conservatively before dispatch";

/// Refuses ambiguous or unchangeable secret update members.
///
/// This is not a secret detector. It rejects structural cases that would send
/// secret bytes (`Data`) or
/// emitting a duplicate or untracked key (`Name`, `Labels`, `Driver` in
/// `additional`). ASCII keys are compared case-insensitively because the
/// Engine's Go decoder matches JSON field names without regard to case, while
/// this crate's serde models are case-sensitive: `data` and `DATA` would bypass
/// an exact-key guard on the client but not the daemon. A non-ASCII key is
/// refused conservatively because Go's folding is Unicode and this crate has no
/// dependency-free full fold table: `Label\u{017f}` can reach `Labels`, so the
/// guard refuses the class instead of claiming it can enumerate every Unicode
/// spelling. A value a caller placed in a free-form name, label, or driver is
/// not inspected or classified.
pub(crate) fn refuse_unrepresentable_secret_update(spec: &SwarmSecretSpec) -> Result<(), Error> {
    // A non-ASCII key is refused before the ASCII comparison: Go's case folding
    // is Unicode, and a full no-dependency fold table is not available here, so
    // the conservative bound is to refuse the class rather than guess.
    if spec.additional.keys().any(|key| !key.is_ascii()) {
        return Err(Error::invalid_input(SECRET_NON_ASCII_UPDATE_REFUSAL));
    }
    if spec
        .additional
        .keys()
        .any(|key| key.eq_ignore_ascii_case("data"))
    {
        return Err(Error::invalid_input(SECRET_DATA_UPDATE_REFUSAL));
    }
    if spec.additional.keys().any(|key| {
        SECRET_RESERVED_KEYS
            .iter()
            .any(|reserved| key.eq_ignore_ascii_case(reserved))
    }) {
        return Err(Error::invalid_input(SECRET_RESERVED_UPDATE_REFUSAL));
    }
    Ok(())
}

/// The fixed message a secret read reports for an Engine rejection.
///
/// The status is preserved in [`Error::api_error`]; the peer's text is not.
/// A daemon or a proxy can echo secret material in an error message, so every
/// secret-read API failure uses this one message.
pub(crate) const SECRET_READ_API_WITHHELD: &str =
    "the secret read failed; the Engine response text is withheld";

/// Withholds an Engine rejection's message for a secret read.
///
/// The status survives so a caller can still tell a 404 from a 409. A non-API
/// failure is left alone: its source is the local transport's, not the peer's,
/// so a transport or cancellation error keeps its kind and text. Both the raw
/// operations and the facade apply this; the raw operation is the single
/// withholding point so a direct raw caller cannot get the peer's echo either.
pub(crate) fn withhold_secret_read_error(error: Error) -> Error {
    if error.api_error().is_some() {
        error.withhold_api_message(SECRET_READ_API_WITHHELD)
    } else {
        error
    }
}

/// Converts a caller's version to the `int64` the Engine declares for it.
///
/// The Engine's specification is not uniform: a service update parameter is an
/// `int32` and the swarm, node, config, and secret parameters are `int64`. A
/// version that does not fit is a caller mistake rather than a number to
/// truncate into a *different* version, which is a conflict against the wrong
/// object.
pub(crate) fn checked_i64(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::invalid_version())
}

/// Converts a caller's version to the `int32` a service update parameter is.
pub(crate) fn checked_i32(value: u64) -> Result<i32, Error> {
    i32::try_from(value).map_err(|_| Error::invalid_version())
}

/// Refuses every dotted `additional` key on the facade service writes.
///
/// A dotted key has no provenance on [`ServiceSpec`]: the raw retention
/// convention (`Placement.Platforms`) and an inspected unmodelled member with a
/// literal dot are the same string. The facade therefore cannot safely choose
/// between merging and preserving it. The explicit raw writer treats the first
/// dot as a sub-object separator for any parent, so a caller who intended that
/// convention can use it, but raw does not preserve a literal top-level key
/// containing a dot. An arbitrary literal key containing a dot has no lossless
/// facade write. This runs before dispatch on both
/// [`DockerClient::create_service`] and [`DockerClient::update_service`].
fn reject_dotted_additional(spec: &ServiceSpec) -> Result<(), Error> {
    if spec.additional.keys().any(|key| key.contains('.')) {
        return Err(Error::invalid_input(String::from(
            "the facade service write refuses every dotted `additional` key: it cannot tell \
             a literal member name containing a dot from the explicit first-dot sub-object \
             convention. The explicit raw writer can carry a first-dot convention for any \
             parent, but it splits at the first dot and does not preserve a literal top-level \
             key. An arbitrary literal key containing a dot has no lossless facade write.",
        )));
    }
    Ok(())
}

/// Clears published IP in facade reads. Raw service inspection retains it.
fn clear_facade_published_ip(service: &mut SwarmService) {
    if let Some(ports) = &mut service.ports {
        for port in ports {
            port.published_ip = None;
        }
    }
}

/// Fixed text used when a Swarm node update or removal failure's response text
/// is withheld.
///
/// A node update body carries the node's name and labels, which are operator
/// metadata, and a direct daemon or an unauthenticated forward proxy can echo
/// request text in a failure message. The two node mutations therefore do not
/// promote peer text into an error. The status is preserved; this text is the
/// whole message and the whole source chain, so `Display`, `Debug`,
/// `api_error()`, and every source carry only this text. Withholding is
/// unconditional rather than a search for the metadata, because a peer can
/// encode or truncate it in a way an exact match would miss.
pub(crate) const WITHHELD_NODE_MUTATION_MESSAGE: &str =
    "response text withheld for a Swarm node mutation because a peer can echo node metadata";

/// Fixed text used when a node write has no owned transport to reach.
///
/// The generated fallback is not safe: the former generated client traces a buffered node request
/// body, and it treats `101` and `304` as success without exposing the status.
/// The endpoint reason is not quoted because it can contain a host or path.
const NODE_WRITE_UNREACHABLE: &str = "the node write cannot be dispatched: the owned transport cannot reach this endpoint, and the generated fallback is not used because it traces the node specification and can report a non-success status as success. Build the client with connect_local or an explicit endpoint the owned transport reaches.";

/// The four node-specification keys the modeled fields own.
///
/// `NodeSpec::additional` is flattened into the same JSON object as `Name`,
/// `Labels`, `Role`, and `Availability`. A reserved key there would either emit
/// a duplicate JSON key or let a value reach a modeled member while the typed
/// field is absent, so no node writer may carry one.
const RESERVED_NODE_SPEC_MEMBERS: [&str; 4] = ["Name", "Labels", "Role", "Availability"];

/// Refuses a reserved key in [`NodeSpec::additional`] before dispatch.
///
/// The diagnostic is fixed and names no caller value, so a key or value the
/// caller supplied is never echoed through `Display`, `Debug`, or a source.
/// Both the raw writer and the facade call this, so the refusal is the same
/// even when the corresponding typed field is absent.
pub(crate) fn reject_reserved_node_spec_members(spec: &NodeSpec) -> Result<(), Error> {
    if spec.additional.keys().any(|key| !key.is_ascii()) {
        return Err(Error::invalid_input(
            "the node specification `additional` map cannot carry non-ASCII keys: \
             they are refused conservatively because Unicode case folding can match a reserved name",
        ));
    }
    if spec.additional.keys().any(|key| {
        RESERVED_NODE_SPEC_MEMBERS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(key))
    }) {
        return Err(Error::invalid_input(
            "the node specification `additional` map cannot carry a reserved modeled field \
             under any ASCII case spelling; set the modeled field instead",
        ));
    }
    Ok(())
}

/// The two Swarm-specification keys the modeled fields own.
///
/// `SwarmSpec::additional` is flattened into the same JSON object as `Name` and
/// `Labels`. A reserved key there would emit a duplicate JSON key, and which
/// value the daemon keeps depends on its decoder rather than on the caller.
const RESERVED_SWARM_SPEC_MEMBERS: [&str; 2] = ["Name", "Labels"];

/// Refuses a reserved key in [`SwarmSpec::additional`] before dispatch.
///
/// The diagnostic is fixed and names no caller value, so a key or value the
/// caller supplied is never echoed through `Display`, `Debug`, or a source.
/// Both the raw writer and the facade call this, so the refusal is the same
/// even when the corresponding typed field is absent.
pub(crate) fn reject_reserved_swarm_spec_members(spec: &SwarmSpec) -> Result<(), Error> {
    if spec.additional.keys().any(|key| !key.is_ascii()) {
        return Err(Error::invalid_input(
            "the Swarm specification `additional` map cannot carry non-ASCII keys: \
             they are refused conservatively because Unicode case folding can match a reserved name",
        ));
    }
    if spec.additional.keys().any(|key| {
        RESERVED_SWARM_SPEC_MEMBERS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(key))
    }) {
        return Err(Error::invalid_input(
            "the Swarm specification `additional` map cannot carry a reserved modeled field \
             under any ASCII case spelling; set the modeled field instead",
        ));
    }
    Ok(())
}

impl DockerClient {
    /// Initializes a Swarm and returns the manager node ID.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only, including the local endpoint
    /// [`Self::connect_local`] captured. The request is
    /// `POST /v<owned>/swarm/init`, where `<owned>` is the API version
    /// configured for the client: v1.55 by default, and either an explicit
    /// constructor version or negotiation can lower it. The answer is the
    /// Engine's JSON string, `"nodeid"`, and it is decoded as that string.
    ///
    /// There is no generated fallback. the former generated client 0.21.1 traces a buffered request
    /// body and treats `101` and `304` as success without exposing the status,
    /// so a fallback could report `Ok` for a status the Engine did not mean as
    /// an accepted initialization. An endpoint with no concrete owned target
    /// therefore fails closed before dispatch with a fixed diagnostic.
    ///
    /// # Failure text is withheld
    ///
    /// The request carries manager addresses, which are internal topology. A
    /// direct daemon or an unauthenticated forward proxy can echo request text
    /// in a failure message, so this method does not preserve untrusted failure
    /// text: an Engine rejection keeps its HTTP status in [`Error::api_error`],
    /// and its message is replaced with fixed text that names the withholding.
    /// The error's source chain is replaced too, so `Display`, `Debug`,
    /// `api_error`, and every source carry only the fixed text. A non-API
    /// failure keeps its kind and loses its source chain the same way. A
    /// transport deadline keeps its marker so the caller can tell that the
    /// outcome is unknown rather than that the request was rejected.
    ///
    /// A daemon older than `<owned>` can reject the versioned request as too
    /// new. That rejection keeps its status and withholds its text; it is not
    /// retried over the generated client. Build the client with a version the
    /// daemon serves, for example through
    /// [`Self::connect_endpoint_with_version`], or upgrade the daemon.
    ///
    /// # Cancellation and retries
    ///
    /// `POST /swarm/init` is a mutation. Dropping the future after dispatch
    /// closes the connection but does not retract the request: the daemon may
    /// have created the cluster, may still be creating it, or may never have
    /// received it. Nothing here retries, and a later
    /// [`Self::inspect_swarm`] is a snapshot rather than proof that an earlier
    /// init settled.
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization or the transport fails, when
    /// the endpoint has no concrete owned target, or when the Engine rejects
    /// the request or answers with a document that is not a node ID.
    pub async fn initialize_swarm(&self, options: SwarmInitOptions) -> Result<String, Error> {
        let engine = self.swarm_lifecycle_engine()?;
        raw::swarm_init(&engine, &options).await
    }

    /// Joins the local Engine to a Swarm.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only, including the local endpoint
    /// [`Self::connect_local`] captured. The request is
    /// `POST /v<owned>/swarm/join` with the Engine's `JoinToken`, `RemoteAddrs`,
    /// and optional address members. At least one manager address is required:
    /// a join with nothing to reach is refused locally before dispatch, because
    /// no manager can answer it.
    ///
    /// There is no generated fallback. The request body carries a join token,
    /// and the former generated client 0.21.1 traces a buffered request body, so a fallback would
    /// put the credential into a TRACE log before any error handling runs. An
    /// endpoint with no concrete owned target therefore fails closed before
    /// dispatch with a fixed diagnostic.
    ///
    /// # Failure text is withheld
    ///
    /// A direct daemon or an unauthenticated forward proxy can echo request
    /// text in a failure message. Because the body is a join token, this method
    /// does not preserve untrusted failure text: an Engine rejection keeps its
    /// HTTP status in [`Error::api_error`], and its message is replaced with
    /// fixed text that names the withholding. The error's source chain is
    /// replaced too, so `Display`, `Debug`, `api_error`, and every source carry
    /// only the fixed text. A non-API failure keeps its kind and loses its
    /// source chain the same way. This is unconditional rather than a search
    /// for the token, because a peer can encode or truncate it in a way an
    /// exact match would miss. A transport deadline keeps its marker so the
    /// caller can tell that the outcome is unknown rather than that the request
    /// was rejected.
    ///
    /// # Managed SSH
    ///
    /// A native `ssh://` endpoint reached with the system `ssh` binary is an
    /// ordinary reachable target. The managed `neotales-ssh` client is
    /// open by default. If explicitly closed by client policy, this method
    /// returns the shared local diagnostic before dispatch. The diagnostic is a
    /// fixed local string, not peer input.
    ///
    /// # Cancellation and retries
    ///
    /// `POST /swarm/join` is a mutation. Dropping the future after dispatch
    /// closes the connection but does not retract the request: the daemon may
    /// have joined the node or may never have received the request. Nothing here
    /// retries. A later [`Self::inspect_swarm`] is a snapshot, not proof that an
    /// earlier join settled.
    ///
    /// # Errors
    ///
    /// Returns an error when no manager address was given, when the endpoint
    /// has no concrete owned target, or when the daemon rejects the request.
    /// The rejection keeps its status; its message is withheld as described
    /// above.
    pub async fn join_swarm(&self, options: SwarmJoinOptions) -> Result<(), Error> {
        let engine = self.swarm_lifecycle_engine()?;
        raw::swarm_join(&engine, &options).await
    }

    /// Leaves the Swarm with `POST /v<owned>/swarm/leave?force=<bool>`.
    ///
    /// The configured API version is used, including for captured local endpoints.
    /// No owned target fails closed before dispatch. Daemon failures retain status;
    /// authenticated proxy response text is withheld. `101` and `304` are errors.
    ///
    /// A forced leave of the last manager destroys the Swarm state. Once dispatched,
    /// a failed or cancelled request may still have taken effect; do not retry without
    /// operator coordination and an appropriate backup.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable endpoint, a rejected request, or a transport failure.
    pub async fn leave_swarm(&self, options: SwarmLeaveOptions) -> Result<(), Error> {
        raw::swarm_leave(&self.swarm_lifecycle_engine()?, &options).await
    }

    /// Unlocks an encrypted Swarm manager.
    ///
    /// On an endpoint [`Self::raw_engine`] can reach, the request is
    /// `POST /v<owned>/swarm/unlock` through the repository-owned transport,
    /// where `<owned>` is the API version configured for the client. the former generated client
    /// 0.21.1 has no method for the endpoint, and there is no generated
    /// fallback: an endpoint the owned transport cannot reach fails closed
    /// before dispatch.
    ///
    /// The owned route prefixes the configured version. A daemon older than
    /// that version rejects the request as too new where the unversioned
    /// generated request would have been accepted. The rejection is returned,
    /// not retried. Build the client with a version the daemon serves, for
    /// example through [`Self::connect_endpoint_with_version`], or upgrade the
    /// daemon.
    ///
    /// The body is `{"UnlockKey":"..."}`. The key is a credential: this method
    /// does not log it, [`SwarmUnlockOptions`] redacts it from `Debug`, and the
    /// owned transport renders a request body as its length rather than its
    /// bytes.
    ///
    /// # Failure text is withheld
    ///
    /// A direct daemon or an unauthenticated forward proxy can echo request text
    /// in a failure message. Because the request body is the unlock key, this
    /// method does not preserve untrusted failure text: an Engine rejection
    /// keeps its HTTP status in [`Error::api_error`], and its message is
    /// replaced with fixed text that names the withholding. The error's source
    /// chain is replaced too, so `Display`, `Debug`, `api_error`, and every
    /// source carry only the fixed text. A non-API failure keeps its kind and
    /// loses its source chain the same way. This is unconditional rather than a
    /// search for the key, because a peer can encode or truncate it in a way an
    /// exact match would miss.
    ///
    /// The migration cost is real: a caller that read
    /// `api_error().message` for unlock used to get the daemon's or proxy's
    /// words. It now gets the fixed text and must branch on the status.
    ///
    /// # Unreachable endpoints fail closed
    ///
    /// the former generated client 0.21.1 has no method for `POST /swarm/unlock`, and its public
    /// generated path cannot be used safely as a fallback: it traces a buffered
    /// request body, which would print the key, and it treats `304 Not Modified`
    /// and `101 Switching Protocols` as success without exposing the status to
    /// the caller. A fallback would therefore either leak the key at trace
    /// level or report success for a status the Engine did not mean as an
    /// accepted unlock.
    ///
    /// On an endpoint [`Self::raw_engine`] cannot reach, this method returns an
    /// error before sending any request. This is a deliberate compatibility
    /// change: `connect_local()` and an SSH endpoint whose owned transport
    /// cannot be described no longer unlock through a fallback. Build the client
    /// with an endpoint description the owned transport can reach, such as
    /// [`Self::connect_endpoint_with_version`] for a Unix socket, TCP, or a
    /// fully described `ssh://` endpoint. The endpoint is never inferred from
    /// `DOCKER_HOST` here.
    ///
    /// # Native and managed SSH
    ///
    /// A native `ssh://` endpoint reached with the system `ssh` binary is an
    /// ordinary reachable target and uses the owned request. The managed
    /// `neotales-ssh` gate is open by default; explicit client closure refuses
    /// before DNS, file or network work. This method asks the transport's own gate
    /// before dispatch; a closed gate returns that shared local diagnostic, and
    /// the default open gate follows the normal owned route. The diagnostic is
    /// a fixed local string, not peer input.
    ///
    /// # Cancellation and retries
    ///
    /// A failed request is returned and is not retried. A cancelled call has an
    /// unknown outcome rather than a known failure: the daemon may have
    /// processed the unlock before the connection was dropped, and the caller
    /// cannot tell that apart from an unlock that never arrived. Read the Swarm
    /// state before deciding whether to send the key again.
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization, the transport, or the
    /// Engine operation fails, and when the endpoint is one the owned transport
    /// cannot reach. A daemon rejection keeps its status in
    /// [`Error::api_error`]; its message is withheld as described above.
    pub async fn unlock_swarm(&self, options: SwarmUnlockOptions) -> Result<(), Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        let engine = match self.raw_engine() {
            Ok(engine) => engine,
            Err(error) => {
                let reason = std::error::Error::source(&error)
                    .map_or_else(|| error.to_string(), ToString::to_string);
                return Err(Error::invalid_input(format!(
                    "Swarm unlock is not available on this endpoint: the owned transport cannot reach it ({reason}), and the generated fallback is disabled because the former generated client 0.21.1 cannot report a response status without a buffered request body that its trace logs"
                )));
            }
        };
        raw::swarm_unlock(&engine, &options).await
    }

    /// Reads the Swarm root CA and the certificates issued for this node.
    ///
    /// `GET /swarm/cert` is the only endpoint that has ever returned the node
    /// certificate and key, and the Engine no longer serves it: it is absent
    /// from the API specification as of v1.35, and a v29.8 daemon answers
    /// `404 page not found` for it at every version prefix. A caller therefore
    /// gets a `404` API error from a current daemon, which it can report, and
    /// this method is the only way to read the material where it does exist.
    /// The root CA itself is read from [`SwarmInfo::trust_root`] instead, which
    /// is where `docker swarm ca` reads it.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only, including the local endpoint
    /// [`Self::connect_local`] captured. The request is
    /// `GET /v<owned>/swarm/cert`. There is no generated fallback: the former generated client
    /// 0.21.1 has no method for the path, and the previous facade borrowed a
    /// unit-returning `ping`, rewrote its path, and read the body as text, which
    /// gave no response-status check. An endpoint with no concrete owned target
    /// fails closed before dispatch with a fixed diagnostic.
    ///
    /// The node key in the answer is a credential: it is redacted from
    /// [`SwarmCertificates`]' `Debug` and zeroized when the value is dropped.
    /// The owned transport does not log a response body.
    ///
    /// # Failure text is withheld
    ///
    /// The successful answer carries the node's private key. A peer controls a
    /// non-success body, and the status is the only part this method trusts: an
    /// Engine rejection keeps its HTTP status in [`Error::api_error`], and its
    /// message and whole source chain are replaced with fixed text that names
    /// the withholding. A non-API failure keeps its kind and loses its source
    /// chain the same way. A transport deadline keeps its marker. A malformed
    /// success document is refused with content-free text and does not echo the
    /// document or the key.
    ///
    /// A daemon older than `<owned>` can reject the versioned request as too
    /// new; that rejection keeps its status and withholds its text. Build the
    /// client with a version the daemon serves, or upgrade the daemon.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint has no concrete owned target, when the
    /// Engine rejects the request, or when the answer is a document this crate
    /// cannot decode. A rejection keeps its status; its message is withheld.
    pub async fn swarm_certificates(&self) -> Result<SwarmCertificates, Error> {
        let engine = self.swarm_lifecycle_engine()?;
        raw::swarm_certificates(&engine).await
    }

    /// Reads the manager unlock key of a Swarm with autolock enabled.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only, including the local endpoint
    /// [`Self::connect_local`] captured. The request is
    /// `GET /v<owned>/swarm/unlockkey`. There is no generated fallback: the former generated client
    /// 0.21.1 has no method for the path, and the previous facade borrowed a
    /// unit-returning `ping` and rewrote its path, which gave no response-status
    /// check. An endpoint with no concrete owned target fails closed before
    /// dispatch with a fixed diagnostic.
    ///
    /// The key is a credential: it is returned to the caller, redacted from
    /// [`SwarmUnlockKey`]' `Debug`, and zeroized when the value is dropped.
    /// Nothing here logs or formats it.
    ///
    /// # Failure text is withheld
    ///
    /// The successful answer carries the manager unlock key. A peer controls a
    /// non-success body, and the status is the only part this method trusts: an
    /// Engine rejection keeps its HTTP status in [`Error::api_error`], and its
    /// message and whole source chain are replaced with fixed text that names
    /// the withholding. A non-API failure keeps its kind and loses its source
    /// chain the same way. A transport deadline keeps its marker. A malformed
    /// success document is refused with content-free text and does not echo the
    /// document or the key.
    ///
    /// A daemon older than `<owned>` can reject the versioned request as too
    /// new; that rejection keeps its status and withholds its text.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint has no concrete owned target, when the
    /// Engine rejects the request, or when the answer is a document this crate
    /// cannot decode. A rejection keeps its status; its message is withheld.
    pub async fn swarm_unlock_key(&self) -> Result<SwarmUnlockKey, Error> {
        let engine = self.swarm_lifecycle_engine()?;
        raw::swarm_unlock_key(&engine).await
    }

    /// Reads the join token for one role from `GET /swarm`.
    ///
    /// `None` means the daemon reported no token for that role, which is what a
    /// worker sees for the manager token. The token is a credential: it is
    /// returned to the caller and written nowhere else in this crate.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn swarm_join_token(
        &self,
        role: SwarmJoinTokenRole,
    ) -> Result<Option<String>, Error> {
        let swarm = self.inspect_swarm().await?;
        Ok(swarm
            .join_tokens
            .as_ref()
            .and_then(|tokens| tokens.get(role.join_token_member()))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned))
    }

    /// Reads the address other Swarm members use to reach this node.
    ///
    /// This is the `Swarm.NodeAddr` member of `GET /info`, which the Engine
    /// documents as the address at which this node can be reached by other nodes
    /// in the Swarm. `None` means the daemon is not part of a Swarm, or reported
    /// no address, so a caller that needs an address to hand to another machine
    /// has nothing to print.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine operation or its decoding fails.
    pub async fn swarm_advertise_address(&self) -> Result<Option<String>, Error> {
        let info = self.info_value().await?;
        let text = |value: Option<&serde_json::Value>| {
            value
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(ToOwned::to_owned)
        };
        // A manager address is preferred, and it already carries the swarm port:
        // `127.0.0.1:2377`. `Swarm.NodeAddr` is the bare host with no port, and a
        // join command built from it is not runnable — `docker swarm join
        // --token … 127.0.0.1` has no port to connect to, which is why the CLI
        // prints the manager's address rather than this one.
        if let Some(manager) = info
            .pointer("/Swarm/RemoteManagers/0/Addr")
            .and_then(serde_json::Value::as_str)
        {
            let manager = manager.trim();
            if !manager.is_empty() {
                return Ok(Some(manager.to_owned()));
            }
        }
        // The fallback keeps the Swarm default port, because NodeAddr never
        // carries one and a join line with no port cannot work.
        Ok(text(info.pointer("/Swarm/NodeAddr"))
            .map(|address| format!("{address}:{DEFAULT_SWARM_PORT}")))
    }

    /// Inspects the Swarm using `GET /v<owned>/swarm`.
    ///
    /// The owned transport uses the configured version and captured local endpoint.
    /// An unavailable target fails closed before dispatch; requests are not retried.
    /// The owned model retains unknown fields. Malformed responses are invalid input;
    /// rejections retain status and direct peer text, while authenticated proxy text
    /// is withheld. `101` and `304` are errors.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable, the daemon rejects the request,
    /// or its answer cannot be decoded.
    pub async fn inspect_swarm(&self) -> Result<SwarmInfo, Error> {
        raw::swarm_inspect(&self.swarm_lifecycle_engine()?).await
    }

    /// Updates the Swarm using an explicitly supplied expected version.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only, including the local endpoint
    /// [`Self::connect_local`] captured. The request is
    /// `POST /v<owned>/swarm/update?version=…`, with all three rotation flags
    /// spelled as `true` or `false` so a recorded request states which
    /// credential changes were part of it. `<owned>` is the API version
    /// configured for the client: v1.55 by default, and either an explicit
    /// constructor version or negotiation can lower it.
    ///
    /// There is no generated fallback. the former generated client 0.21.1 traces a buffered request
    /// body and treats `101` and `304` as success without exposing the status,
    /// so a fallback could put the specification into a TRACE log or report
    /// `Ok` for a status the Engine did not mean as an accepted update. An
    /// endpoint with no concrete owned target fails closed before dispatch with
    /// a fixed diagnostic.
    ///
    /// # Failure text is withheld
    ///
    /// The request carries the Swarm specification, including free-form
    /// `additional` values a caller chose. A direct daemon or an unauthenticated
    /// forward proxy can echo request text in a failure message, so this method
    /// does not preserve untrusted failure text: an Engine rejection keeps its
    /// HTTP status in [`Error::api_error`], and its message is replaced with
    /// fixed text that names the withholding. The source chain is replaced too,
    /// so `Display`, `Debug`, `api_error`, and every source carry only the fixed
    /// text. A non-API failure keeps its kind and loses its source chain the
    /// same way. A transport deadline keeps its marker so the caller can tell
    /// that the outcome is unknown rather than that the request was rejected.
    ///
    /// # Conflict safety is the daemon's
    ///
    /// The caller's `version` is sent as the Engine's `int64`. A stale version
    /// remains an Engine `409 Conflict`; the facade does not silently retry and
    /// overwrite another writer's changes. A manager token or unlock key rotated
    /// by another writer is not repaired here. The `409` status is preserved and
    /// its peer text is withheld like every other rejection.
    ///
    /// # Reserved specification members
    ///
    /// [`SwarmSpec::additional`] is flattened into the same object as the typed
    /// `Name` and `Labels`. A `Name` or `Labels` key there would emit a
    /// duplicate JSON key, and the value the daemon keeps would depend on its
    /// decoder rather than on the caller. Such a key is refused as
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before
    /// dispatch, under any ASCII case spelling. Non-ASCII keys are refused
    /// conservatively because the Engine's decoder folds field names with
    /// Unicode case folding and this crate has no dependency-free full fold
    /// table. The diagnostic names no caller value.
    ///
    /// # Cancellation and retries
    ///
    /// `POST /swarm/update` is a mutation. Dropping the future after dispatch
    /// closes the connection but does not retract the request; the daemon may
    /// have applied it or may never have received it. Nothing here retries. A
    /// later [`Self::inspect_swarm`] is a snapshot, not proof that an earlier
    /// update settled.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version or reserved specification
    /// member, when the endpoint has no concrete owned target, when
    /// serialization fails, or when the Engine rejects the request. A stale
    /// version is an API error with status `409`.
    pub async fn update_swarm(&self, options: SwarmUpdateOptions) -> Result<(), Error> {
        reject_reserved_swarm_spec_members(&options.spec)?;
        let engine = self.swarm_lifecycle_engine()?;
        raw::swarm_update(&engine, &options).await
    }

    /// Lists Swarm services with `GET /v<owned>/services`.
    ///
    /// The configured version and captured local endpoint are used. Filters are
    /// encoded deterministically and `status=true` requests service status. No owned
    /// target fails closed before dispatch; no request is retried. The facade projects
    /// ports and status, clears published IP, and retains other endpoint and unknown
    /// members in the owned model. Malformed documents are invalid input. A rejection
    /// preserves status and direct peer text; authenticated proxy text is withheld.
    /// `101` and `304` are errors.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unavailable, filters cannot be encoded,
    /// the daemon rejects the request, or the answer cannot be decoded.
    pub async fn list_services(
        &self,
        options: Option<ServiceListOptions>,
    ) -> Result<Vec<SwarmService>, Error> {
        let options = options.unwrap_or_default();
        let engine = self.service_engine().ok_or_else(|| {
            Error::invalid_input("service reads require an owned transport endpoint")
        })?;
        let mut services = raw::service_list_for_facade(&engine, &options).await?;
        for service in &mut services {
            clear_facade_published_ip(service);
        }
        Ok(services)
    }

    /// Creates a Swarm service.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only. There is deliberately no generated
    /// fallback: the former generated client 0.21.1 traces a buffered request body before sending
    /// it, so a generated create would put `TaskTemplate.ContainerSpec.Env` and
    /// the names of `ContainerSpec.Secrets` into a TRACE log before any error
    /// handling runs, and its failure path can echo the same text. The facade
    /// has no switch that removes either behavior.
    ///
    /// An endpoint the owned transport can reach sends
    /// `POST /v<owned>/services/create`, where `<owned>` is the API version
    /// configured for the client. On any other endpoint nothing is sent and the
    /// error is [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) with
    /// a fixed diagnostic naming the two reasons. A managed SSH target returns
    /// its stable local gate diagnostic first, before dispatch.
    /// [`DockerClient::connect_local`] records the local socket the former generated client
    /// selected, and this method uses it when no other owned target exists, so
    /// the ordinary local client keeps working.
    ///
    /// A daemon older than the owned version can reject the versioned request
    /// as too new. That rejection is returned, not retried over a fallback.
    /// Build the client with a version the daemon serves, for example through
    /// [`DockerClient::connect_endpoint_with_version`], or upgrade the daemon.
    ///
    /// # Placement and restart policy
    ///
    /// The Engine reads both inside `Spec.TaskTemplate`, and this method's body
    /// moves them there: a populated [`ServiceSpec::placement`] or
    /// [`ServiceSpec::restart_policy`] is emitted inside `TaskTemplate`, not at
    /// the specification root. That is the same reconciliation
    /// [`Self::update_service`] and `raw::service_create` perform. A second
    /// representation of either value — the typed field beside a
    /// `TaskTemplate.Placement`, a dotted retention key for a member the typed
    /// field emits, or a top-level `additional["Placement"]`/`["RestartPolicy"]`
    /// — is refused before dispatch, because choosing silently could schedule
    /// the service somewhere the caller did not ask for.
    ///
    /// Every dotted key in [`ServiceSpec::additional`] is refused before
    /// dispatch, for the reason [`Self::update_service`] documents: the facade
    /// cannot tell a literal member name containing a dot from the raw
    /// first-dot retention convention. A caller who intended that convention can
    /// call `raw::service_create` directly.
    ///
    /// The same validation refuses a second ASCII-case spelling of a modeled
    /// member and any non-ASCII key on a modeled merge surface, because the
    /// Engine matches member names case-insensitively. See
    /// [`ServiceSpec::additional`] for the exact restriction and the supported
    /// place for a non-ASCII service-defined key.
    ///
    /// # Failure text is withheld
    ///
    /// Every failure is content-free because the request may carry service
    /// environment, service secret names, or registry credentials. A transport
    /// failure keeps its kind and drops its peer-controlled source chain. A
    /// daemon or proxy rejection keeps its HTTP status in [`Error::api_error`]
    /// and uses the fixed message `response text withheld for a service create
    /// because the request may carry service environment, service secrets, or
    /// registry credentials`. The response body is not read. This applies on a
    /// direct route and on both authenticated and unauthenticated proxy routes.
    /// A malformed success body is a content-free
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput).
    ///
    /// # Registry credentials
    ///
    /// This method sends no `X-Registry-Auth` header. Use
    /// [`Self::create_service_with_credentials`] to send one registry's
    /// credential. The daemon-side `registryAuthFrom=spec` parameter is not part
    /// of `POST /services/create`; the Engine reads only the header there.
    ///
    /// # Cancellation and retry
    ///
    /// A create is a mutation. Dropping the future after dispatch closes the
    /// connection without retracting the request: the daemon may have created
    /// the service, may still be creating it, or may never have received it.
    /// This method does not retry. A caller whose dispatch was cancelled must
    /// inspect the cluster (for example by name through [`Self::list_services`])
    /// before deciding whether to send it again.
    ///
    /// # Errors
    ///
    /// Returns an error for a conflicting or unrepresentable specification, an
    /// endpoint the owned transport cannot reach, a daemon rejection, or an
    /// answer the owned decoder cannot read.
    pub async fn create_service(&self, spec: ServiceSpec) -> Result<ServiceCreateResult, Error> {
        reject_dotted_additional(&spec)?;
        raw::validate_service_spec(&spec)?;
        let engine = self.service_create_engine()?;
        raw::service_create(&engine, &spec).await
    }

    /// Creates a Swarm service, sending one registry credential.
    ///
    /// This is [`Self::create_service`] with a credential for the
    /// `X-Registry-Auth` header, which is how the daemon authenticates an image
    /// pull for a service that is not already local. The credential is validated
    /// against `registry` before dispatch, so an incomplete credential, an
    /// oversized field, or a credential addressed to a different registry is
    /// [`ErrorKind::Credentials`](crate::ErrorKind::Credentials) without a
    /// request. The header is URL-safe base64 over the Engine's `AuthConfig`
    /// object.
    ///
    /// The credential is a password. It is not rendered by any `Debug`
    /// implementation on [`RegistryCredentials`] or this crate's request type,
    /// and every failure is content-free: the status is preserved when it was
    /// observed, and the message is the fixed service-create withholding text.
    /// That withholding is unconditional because the body may also carry service
    /// environment or service secrets. Nothing here retries after dispatch.
    ///
    /// All specification, routing, version, and cancellation behavior is the
    /// same as [`Self::create_service`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::create_service`], plus a credential
    /// that does not validate for `registry`, an invalid registry authority, or
    /// a credential that cannot be encoded as an HTTP header.
    pub async fn create_service_with_credentials(
        &self,
        spec: ServiceSpec,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<ServiceCreateResult, Error> {
        reject_dotted_additional(&spec)?;
        raw::validate_service_spec(&spec)?;
        let engine = self.service_create_engine()?;
        let auth = raw::RegistryAuth::credentials(registry, &credentials)?;
        raw::service_create_with_registry_auth(&engine, &spec, auth).await
    }

    /// Returns the owned engine, or the fail-closed service-create refusal.
    ///
    /// There is deliberately no generated fallback. the former generated client 0.21.1 traces the
    /// buffered request body, so a generated create would write the service
    /// environment and secret names to a TRACE log before any error handling
    /// runs. A facade cannot remove that logging, so an unreachable endpoint
    /// sends nothing.
    fn service_create_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.service_engine()
            .ok_or_else(|| Error::invalid_input(SERVICE_CREATE_UNREACHABLE))
    }

    /// Inspects one service with `GET /v<owned>/services/{id}`.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch; the reference is encoded as one path segment and
    /// an empty reference is refused. The facade projects ports and status, clears
    /// published IP, and retains other endpoint and unknown members. Its owned decoder
    /// rejects malformed or ambiguous documents rather than dropping fields. A daemon
    /// rejection retains status and direct peer text; authenticated proxy text is
    /// withheld. `101` and `304` are errors. The request is never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid reference or document, or
    /// a daemon or transport failure.
    pub async fn inspect_service(&self, id: &str) -> Result<SwarmService, Error> {
        let engine = self.service_engine().ok_or_else(|| {
            Error::invalid_input("service reads require an owned transport endpoint")
        })?;
        let mut service = raw::service_inspect_for_facade(&engine, id).await?;
        clear_facade_published_ip(&mut service);
        Ok(service)
    }

    /// Updates or rolls back a service at an explicit expected version.
    ///
    /// # Routing and the fail-closed endpoint
    ///
    /// This method uses the repository-owned transport only. On an endpoint it
    /// reaches, the request is
    /// `POST /v<owned>/services/{id}/update?version=<n>&registryAuthFrom=spec`,
    /// with `&rollback=previous` appended when a rollback was requested.
    ///
    /// There is deliberately no generated fallback. An update body can contain
    /// `TaskTemplate.ContainerSpec.Env`, and the former generated client 0.21.1 traces a buffered
    /// request body before sending it, so a generated fallback would write the
    /// service environment to a TRACE log. Its failure path can also echo the
    /// same text. The facade has no switch that removes either behavior, so an
    /// endpoint without a concrete owned target fails closed before dispatch:
    /// no request is sent, and the error is
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) with a fixed
    /// diagnostic naming the two reasons. The endpoint reason itself is not
    /// quoted, because it can contain a host or path. A managed SSH target
    /// returns its stable local gate diagnostic instead, before dispatch, just
    /// as `unlock_swarm` does. [`DockerClient::connect_local`] records the exact
    /// local socket the former generated client selected, so a local client keeps a successful owned
    /// update instead of falling into that refusal.
    ///
    /// A daemon older than the owned version can reject the versioned request as
    /// too new. That rejection is returned, not retried over a fallback. Build
    /// the client with a version the daemon serves, for example through
    /// [`DockerClient::connect_endpoint_with_version`], or upgrade the daemon.
    ///
    /// # Specification handling
    ///
    /// The body is the [`ServiceSpec`] through [`raw::service_update`], not a
    /// blanket member-for-member promise: dotted keys and the two top-level
    /// `Placement`/`RestartPolicy` entries described below are refused.
    /// Placement and restart policy are members of `Spec.TaskTemplate` on the
    /// wire, so a populated [`ServiceSpec::placement`] or
    /// [`ServiceSpec::restart_policy`] is moved into `TaskTemplate` rather than
    /// emitted at the specification root.
    ///
    /// **Every dotted key in [`ServiceSpec::additional`] is refused by the
    /// facade before dispatch.** A `ServiceSpec` carries no provenance for an
    /// `additional` key, so a literal `Placement.Platforms` an inspect retained
    /// from the daemon is indistinguishable from the raw retention convention of
    /// the same name. Merging it could silently rewrite the literal. A caller
    /// who intended the Engine's documented placement or restart-policy member
    /// can express it inside [`ServiceSpec::task_template`]. A literal key
    /// containing a dot has no lossless facade write; it is refused rather than
    /// rewritten. An explicit [`raw::service_update`] call interprets the first
    /// dot as a sub-object convention, but it does not preserve a literal
    /// top-level key either.
    ///
    /// A non-dotted `additional` member is considered for the request body,
    /// subject to recursive validation against the manually inventoried Moby
    /// 1.55 schema. Unknown scalar extensions remain accepted; unclassified
    /// structured values, invalid shapes, and conflicting spellings are refused
    /// before dispatch. Inspect still retains unknown structured members, so
    /// callers may need to remove or convert them before updating. The top-level
    /// `additional["Placement"]` and `additional["RestartPolicy"]` entries are
    /// also refused even without a typed competitor: the Engine reads those
    /// inside `TaskTemplate`, and the root spelling is not a lossless alternate
    /// shape. If either is the Engine's placement or restart policy, express it
    /// in [`ServiceSpec::task_template`]; [`raw::service_update`] applies the
    /// same schema and root-member checks. See `docs/service-schema-1.55.md` for
    /// the compatibility boundary and migration note.
    ///
    /// An `additional` entry otherwise overrides a top-level typed member of the
    /// same name, except that a whole `TaskTemplate` beside the typed
    /// [`ServiceSpec::task_template`] is refused, and the two root
    /// placement/restart-policy entries above are refused rather than treated as
    /// overrides. The raw writer resolves an `additional` `TaskTemplate` before
    /// the typed placement, restart policy, and dotted members merge into it, and
    /// orders dotted keys by depth so a whole object cannot overwrite a member
    /// already merged. The facade never reaches that path with a dotted key; it
    /// refuses every one. Conflicting or duplicate representations are refused
    /// before dispatch with a fixed, content-free
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput): two task
    /// templates, a typed placement or restart policy beside a `TaskTemplate`
    /// member of the same name, any top-level `Placement`/`RestartPolicy`
    /// additional entry with or without a typed competitor, a typed field beside
    /// a dotted key for a member the typed field emits, a dotted key that would
    /// replace an existing member, or a `TaskTemplate` that is not a JSON
    /// object.
    ///
    /// # Compatibility note
    ///
    /// An inspect of a real daemon reports `Placement` and `RestartPolicy`
    /// inside `TaskTemplate`, not at the specification root. If the value is the
    /// Engine's placement or restart policy, express it in
    /// `ServiceSpec::task_template` (or set the typed field, which is moved
    /// there). A literal root member that is not the Engine's member has no
    /// lossless path: `task_template` changes its location and meaning, and
    /// `raw::service_update` refuses the root spelling too. The refusal is a
    /// known migration step, not an indication that every non-dotted
    /// `additional` key is accepted. This paragraph is the pending release note
    /// because the crate has no release-notes file.
    ///
    /// # Registry credentials
    ///
    /// This method sends no `X-Registry-Auth` header. The daemon-side
    /// `registryAuthFrom=spec` parameter is sent, which is what the generated
    /// client sent before this routing. Use
    /// [`Self::update_service_with_credentials`] to send one registry's
    /// credential.
    ///
    /// # Failure text is withheld
    ///
    /// Every failure on this operation is content-free because the request may
    /// carry service environment or registry credentials. A transport failure
    /// keeps its kind and drops its peer-controlled source chain. A daemon or
    /// proxy rejection keeps its HTTP status in [`Error::api_error`] and uses
    /// the fixed message `response text withheld for a service update because
    /// the request may carry service environment or registry credentials`. The
    /// response body is not read. This applies on a direct route and on both
    /// authenticated and unauthenticated proxy routes. A malformed success body
    /// is a content-free
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput).
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, an unrepresentable or
    /// conflicting specification, a reference the owned route refuses, an
    /// endpoint the owned transport cannot reach, or an Engine rejection. A
    /// version conflict remains a `409 Conflict` API error with the withheld
    /// message and the original status.
    ///
    /// # Cancellation and retry
    ///
    /// An update is a mutation. Dropping the future after dispatch closes the
    /// connection without retracting the request: the daemon may have applied
    /// it, may still be applying it, or may never have received it. This method
    /// does not retry, and a second call is a new mutation against the same
    /// expected version, which a settled update would report as a conflict. The
    /// outcome of a cancelled dispatch is therefore unknown, and reconciling it
    /// requires reading the service again before deciding what to send.
    pub async fn update_service(
        &self,
        id: &str,
        options: ServiceUpdateOptions,
    ) -> Result<ServiceUpdateResult, Error> {
        reject_dotted_additional(&options.spec)?;
        raw::validate_service_spec(&options.spec)?;
        let engine = self.service_update_engine()?;
        raw::service_update(&engine, id, &options).await
    }

    /// Updates or rolls back a service, sending one registry credential.
    ///
    /// This is [`Self::update_service`] with a registry credential for the
    /// `X-Registry-Auth` header. The credential is validated against `registry`
    /// before dispatch, so an incomplete credential, an oversized field, or a
    /// credential addressed to a different registry is
    /// [`ErrorKind::Credentials`](crate::ErrorKind::Credentials) without a
    /// request. The header is URL-safe base64 over the Engine's `AuthConfig`
    /// object.
    ///
    /// The credential is a password. It is not rendered by any `Debug`
    /// implementation on [`RegistryCredentials`] or this crate's request type,
    /// and every failure is content-free: the status is preserved when it was
    /// observed, and the message is
    /// `response text withheld for a service update because the request may
    /// carry service environment or registry credentials`. That withholding is
    /// unconditional because the body may also carry `ContainerSpec.Env`.
    /// Nothing here retries after dispatch.
    ///
    /// All specification, routing, version, and cancellation behavior is the
    /// same as [`Self::update_service`], including the owned-path retention of
    /// unmodelled members and the conflict refusals in `ServiceSpec`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::update_service`], plus a credential
    /// that does not validate for `registry`, an invalid registry authority, or
    /// a credential that cannot be encoded as an HTTP header.
    pub async fn update_service_with_credentials(
        &self,
        id: &str,
        options: ServiceUpdateOptions,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<ServiceUpdateResult, Error> {
        reject_dotted_additional(&options.spec)?;
        raw::validate_service_spec(&options.spec)?;
        let engine = self.service_update_engine()?;
        let auth = raw::RegistryAuth::credentials(registry, &credentials)?;
        raw::service_update_with_registry_auth(&engine, id, &options, auth).await
    }

    /// Returns the owned engine, or the fail-closed service-update refusal.
    ///
    /// There is deliberately no generated fallback. the former generated client 0.21.1 traces the
    /// buffered request body, so a generated update would write the service
    /// environment to a TRACE log before any error handling runs. A facade
    /// cannot remove that logging, so an unreachable endpoint sends nothing.
    fn service_update_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.service_engine()
            .ok_or_else(|| Error::invalid_input(SERVICE_UPDATE_UNREACHABLE))
    }

    /// Returns the engine that serves a Swarm lifecycle request, or fails
    /// closed.
    ///
    /// The Swarm init, join, update, certificate, and unlock-key operations have
    /// no generated fallback. An explicitly closed managed SSH target returns
    /// its fixed closed-gate diagnostic before dispatch. `raw_engine` is the general routing signal
    /// and remains unreachable for `connect_local`; the local constructor
    /// records one concrete socket, so these operations use it when that is the
    /// only concrete target. An endpoint with neither fails closed with
    /// [`SWARM_LIFECYCLE_UNREACHABLE`].
    ///
    /// # Errors
    ///
    /// Returns the managed SSH gate diagnostic, or a fixed
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) when the
    /// endpoint has no concrete owned target.
    fn swarm_lifecycle_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        if let Ok(engine) = self.raw_engine() {
            return Ok(engine);
        }
        Err(Error::invalid_input(SWARM_LIFECYCLE_UNREACHABLE))
    }

    /// Returns the engine that serves service inspect, create, update, remove, and logs.
    ///
    /// `raw_engine` is the general routing signal and remains unreachable for
    /// `connect_local`. The local constructor records one concrete socket, so
    /// service inspect, create, and update use it when that is the only
    /// concrete target. A service write has no generated fallback, so this is
    /// also the fail-closed decision point for an endpoint with neither.
    fn service_engine(&self) -> Option<raw::RawEngine> {
        self.raw_engine().ok()
    }

    /// Removes a service with `DELETE /v<owned>/services/{id}`.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. The reference is encoded as one path segment and
    /// an empty reference is refused. A daemon rejection retains status and direct peer
    /// text; authenticated proxy text is withheld. `101` and `304` are errors. A
    /// failed or cancelled mutation can have taken effect and is never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid reference, daemon rejection,
    /// or transport failure.
    pub async fn remove_service(&self, id: &str) -> Result<(), Error> {
        let engine = self.service_engine().ok_or_else(|| {
            Error::invalid_input("service removal requires an owned transport endpoint")
        })?;
        raw::service_remove(&engine, id).await
    }

    /// Streams service logs from `GET /v<owned>/services/{id}/logs`.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed as the first stream error before dispatch. The query uses the
    /// requested options and does not request `details`. Non-success status, including
    /// `101` and `304`, is an error before any frame; status and direct peer text are
    /// preserved, while authenticated proxy text is withheld. Multiplexed frames are
    /// size-limited and malformed or truncated frames are errors. The stream is lazy;
    /// cancellation or drop releases the response, without retry.
    ///
    /// # Errors
    ///
    /// A request or decoding failure appears as a stream item.
    pub fn service_logs(
        &self,
        id: &str,
        options: Option<SwarmLogOptions>,
    ) -> DockerStream<ContainerLogFrame> {
        let engine = self.service_engine();
        let id = id.to_owned();
        let options = options.unwrap_or_default();
        owned_response(async move {
            let engine = engine.ok_or_else(|| {
                Error::invalid_input("service logs require an owned transport endpoint")
            })?;
            let frames = raw::service_logs(&engine, &id, &options).await?;
            Ok(OwnedResponse::LogFrames {
                frames,
                map: map_owned_log_frame,
            })
        })
    }

    /// Returns the engine that serves node reads and writes.
    ///
    /// [`Self::raw_engine`] remains the general routing signal and is
    /// unreachable for `connect_local`. The local constructor records one
    /// concrete socket, so node list, inspect, update, and removal use it when
    /// that is the only concrete target.
    fn node_engine(&self) -> Option<raw::RawEngine> {
        self.raw_engine().ok()
    }

    /// Returns the owned engine for a node write, or fails closed.
    ///
    /// An explicitly closed managed SSH gate refuses before a request. An
    /// endpoint with no owned target gets the fixed [`NODE_WRITE_UNREACHABLE`] diagnostic instead
    /// of the generated fallback.
    fn node_write_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.node_engine()
            .ok_or_else(|| Error::invalid_input(NODE_WRITE_UNREACHABLE))
    }

    /// Selects the captured owned endpoint for confidential resource writes.
    fn resource_write_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.node_engine().ok_or_else(|| {
            Error::invalid_input("config and secret writes require an owned transport endpoint")
        })
    }

    /// Lists nodes with `GET /v<owned>/nodes` and deterministic filters.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. The owned model retains unknown members and
    /// projects `Description.Engine.EngineVersion`; a top-level `EngineVersion`
    /// collision rejects the entire list. Malformed documents are invalid input. A
    /// daemon rejection retains status and direct peer text; authenticated proxy text
    /// is withheld. `101` and `304` are errors. Requests are never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid filter or document, or a
    /// daemon or transport failure.
    pub async fn list_nodes(
        &self,
        options: Option<NodeListOptions>,
    ) -> Result<Vec<SwarmNode>, Error> {
        let engine = self.node_engine().ok_or_else(|| {
            Error::invalid_input("list_nodes requires an owned transport endpoint")
        })?;
        raw::node_list_for_facade(&engine, &options.unwrap_or_default()).await
    }

    /// Inspects a node with `GET /v<owned>/nodes/{id}`.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. The reference is encoded as one path segment and
    /// an empty reference is refused. Unknown members are retained; an actual top-level
    /// `EngineVersion` collision is rejected. A daemon rejection retains status and
    /// direct peer text; authenticated proxy text is withheld. `101` and `304` are
    /// errors. Requests are never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid reference or document, or a
    /// daemon or transport failure.
    pub async fn inspect_node(&self, id: &str) -> Result<SwarmNode, Error> {
        let engine = self.node_engine().ok_or_else(|| {
            Error::invalid_input("inspect_node requires an owned transport endpoint")
        })?;
        raw::node_inspect_for_facade(&engine, id).await
    }

    /// Updates one Swarm node at an explicit expected version.
    ///
    /// # Owned transport only
    ///
    /// The request is `POST /v<owned>/nodes/{id}/update?version=<n>` through the
    /// repository-owned transport, with the reference percent-encoded into one
    /// path segment. There is deliberately no generated fallback. the former generated client
    /// 0.21.1 traces a buffered node request body at `TRACE` and may serialize
    /// the payload at `DEBUG`; that body carries the node's name and labels. It
    /// also treats `101 Switching Protocols` and `304 Not Modified` as success
    /// without exposing the status. A facade cannot remove either behavior, so
    /// an endpoint without a concrete owned target fails closed before
    /// dispatch: no request is sent, and the error is
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) with a fixed
    /// diagnostic. [`DockerClient::connect_local`] records the exact local
    /// socket the former generated client selected, so a local client keeps a working owned update
    /// instead of falling into that refusal. A managed SSH target returns its
    /// stable local gate diagnostic first, before dispatch.
    ///
    /// # The body carries the specification member for member
    ///
    /// The owned path serializes [`NodeSpec`] as it stands: `Name`, `Labels`,
    /// `Role`, `Availability`, and every member of [`NodeSpec::additional`].
    /// When this specification came from the owned [`Self::inspect_node`]
    /// route — the only route that retains every daemon member — an inspect →
    /// update round trip changes only what the caller changed, provided its
    /// additional keys are accepted by the guard below. A specification read
    /// from an external source may already have lost unmodelled members;
    /// this write sends what it is given and cannot restore them. A `Role` or
    /// `Availability` outside the former generated client's generated enums is sent as the string
    /// the caller supplied, and a newer daemon's unmodelled member is preserved
    /// instead of cleared when the caller supplied it. The daemon decides
    /// whether it accepts them; a rejection is returned and not retried.
    ///
    /// # Reserved keys in `additional`
    ///
    /// `additional` is flattened into the same JSON object as the modeled
    /// members. It therefore may not carry `Name`, `Labels`, `Role`, or
    /// `Availability` under any ASCII case spelling: Go's JSON decoder matches
    /// field names case-insensitively, so a second spelling could either emit a
    /// duplicate key or reach a modeled member while the typed field is absent.
    /// The owned writer refuses such a specification with a fixed
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before
    /// dispatch, even when the corresponding typed field is `None`. The
    /// diagnostic names no caller value.
    /// All non-ASCII additional keys are also refused conservatively, including
    /// unrelated extension keys, because Go's Unicode folding can match ASCII.
    ///
    /// # Version, the configured API version, and conflicts
    ///
    /// `version` is the Engine object version the caller read. It is converted
    /// to the Engine's `int64`, and a value that does not fit is
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before
    /// dispatch. A stale version remains a `409 Conflict` API error with its
    /// status preserved and its peer text withheld.
    ///
    /// The owned request carries the API version the client was configured
    /// with. A daemon older than that version can reject it as too new with
    /// `400 Bad Request`, which is returned rather than retried. Build the
    /// client with a version the daemon serves, or upgrade the daemon.
    ///
    /// # Empty reference
    ///
    /// An empty reference is refused as
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before a
    /// request is sent.
    ///
    /// # Failure text is withheld, and non-2xx is a failure
    ///
    /// The request body carries the node's name and labels. A direct daemon or
    /// an unauthenticated forward proxy controls a non-success answer and can
    /// echo request text in its message, so this operation does not preserve
    /// peer text. Any status outside `200..=299`, including `101` and `304`, is
    /// a failure: the observed status is preserved in [`Error::api_error`], and
    /// its message and source chain are replaced with fixed text that names the
    /// withholding. The response body is dropped without being read, so an
    /// unbounded error body is never collected. `Display`, `Debug`,
    /// `api_error`, and every source carry only the fixed text. A non-API
    /// failure keeps its kind and loses its source chain; a deadline marker
    /// uses the fixed deadline diagnostic under Cancellation and retry, and
    /// every other non-API failure uses the fixed withholding text. The
    /// withholding is unconditional rather than a search for the metadata,
    /// because a peer can encode or truncate it in a way an exact match would
    /// miss.
    ///
    /// The migration cost is real: `ndocker --raw-error` used to print the
    /// daemon's words for this operation. It now prints the fixed text, and a
    /// caller that needs to distinguish a conflict branches on the preserved
    /// status.
    ///
    /// # Cancellation and retry
    ///
    /// An update is a mutation. Dropping the future after dispatch closes the
    /// connection but does not retract the request: the daemon may already have
    /// applied it, may still be applying it, or may never have received it.
    /// Nothing here retries, and a blind retry after a transport error can be
    /// wrong. Reconcile with [`Self::inspect_node`] before deciding what to do.
    /// A transport deadline marker, including one propagated from an earlier
    /// caller-supplied factory operation, produces a fixed deadline message
    /// stating that the outcome is unknown; it does not claim this mutation
    /// itself timed out. Other transport errors retain their fixed withholding
    /// message.
    ///
    /// # Errors
    ///
    /// Returns an error when the owned transport cannot reach the endpoint,
    /// when the reference is empty, when the version does not fit, when the
    /// specification carries a reserved `additional` key, when the daemon
    /// rejects the request with a non-2xx status including `101` or `304`, or
    /// when the selected transport cannot complete it. A version conflict
    /// remains a `409 Conflict` API error with its status preserved and its
    /// peer text withheld.
    pub async fn update_node(&self, id: &str, options: NodeUpdateOptions) -> Result<(), Error> {
        reject_reserved_node_spec_members(&options.spec)?;
        let engine = self.node_write_engine()?;
        raw::node_update(&engine, id, &options).await
    }

    /// Removes one Swarm node.
    ///
    /// # Owned transport only
    ///
    /// The request is `DELETE /v<owned>/nodes/{id}?force=<bool>` through the
    /// repository-owned transport, with the reference percent-encoded into one
    /// path segment. There is deliberately no generated fallback: the former generated client
    /// preserves peer failure text and treats `101` and `304` as success
    /// without exposing the status. An endpoint without a concrete owned target
    /// fails closed before dispatch with a fixed
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) diagnostic.
    /// [`DockerClient::connect_local`] records the local socket, so a local
    /// client keeps a working owned removal.
    ///
    /// # `force`
    ///
    /// The request always spells the parameter, `force=true` or `force=false`,
    /// so a recorded request says whether removing a manager was part of it. A
    /// manager cannot be removed without `force`, and that refusal is the
    /// daemon's own `400 Bad Request` answer with its status preserved and its
    /// text withheld.
    ///
    /// # Empty reference
    ///
    /// An empty reference is refused as
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) before a
    /// request is sent.
    ///
    /// # Failure text is withheld, and non-2xx is a failure
    ///
    /// A direct daemon or an unauthenticated forward proxy controls a
    /// non-success answer and can echo node metadata in its message, so this
    /// operation does not preserve peer text. Any status outside `200..=299`,
    /// including `101` and `304`, is a failure: the observed status is preserved
    /// in [`Error::api_error`], and its message and source chain are replaced
    /// with fixed text. The response body is dropped without being read. A
    /// non-API failure keeps its kind and loses its source chain; a deadline
    /// marker uses the fixed deadline diagnostic under Cancellation and retry,
    /// and every other non-API failure uses the fixed withholding text. The
    /// withholding is unconditional rather than a search for the metadata.
    ///
    /// The migration cost is real: `ndocker --raw-error` used to print the
    /// daemon's words for this operation. It now prints the fixed text, and a
    /// caller must branch on the preserved status.
    ///
    /// # Cancellation and retry
    ///
    /// A removal is a mutation. Dropping the future after dispatch closes the
    /// connection but does not retract the request: the daemon may already have
    /// removed the node, may still be processing it, or may never have received
    /// it. Nothing here retries, and a blind retry after a transport error can
    /// be wrong. Reconcile with [`Self::list_nodes`] before deciding what to do.
    /// A transport deadline marker, including one propagated from an earlier
    /// caller-supplied factory operation, produces a fixed deadline message
    /// stating that the outcome is unknown; it does not claim this removal
    /// itself timed out.
    ///
    /// # Errors
    ///
    /// Returns an error when the owned transport cannot reach the endpoint,
    /// when the reference is empty, when the daemon rejects the request with a
    /// non-2xx status including `101` or `304`, such as a `400` for a manager
    /// removed without `force` or a `404` for a node that does not exist, or
    /// when the selected transport cannot complete it. The status is preserved
    /// and the peer text is withheld.
    pub async fn remove_node(&self, id: &str, options: NodeRemoveOptions) -> Result<(), Error> {
        let engine = self.node_write_engine()?;
        raw::node_remove(&engine, id, &options).await
    }

    /// Lists configs with `GET /v<owned>/configs` and deterministic filters.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. The owned model retains unknown fields and config
    /// Data; treat the returned value as potentially sensitive. Decode diagnostics do
    /// not quote response content. Daemon rejection status and direct peer text are
    /// preserved; authenticated proxy text is withheld. `101` and `304` are errors.
    /// Requests are never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid filter or document, or a
    /// daemon or transport failure.
    pub async fn list_configs(
        &self,
        options: Option<ConfigListOptions>,
    ) -> Result<Vec<SwarmConfig>, Error> {
        let engine = self.node_engine().ok_or_else(|| {
            Error::invalid_input("list_configs requires an owned transport endpoint")
        })?;
        raw::config_list(&engine, &options.unwrap_or_default()).await
    }

    /// Creates a Swarm config.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved.
    ///
    /// # Errors
    ///
    /// Returns an error when encoding or the Engine operation fails.
    pub async fn create_config(&self, options: ConfigCreateOptions) -> Result<String, Error> {
        let engine = self.resource_write_engine()?;
        raw::config_create(&engine, &options).await
    }

    /// Inspects a config with `GET /v<owned>/configs/{id}`.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. The reference is encoded as one path segment and
    /// an empty reference is refused. The owned model retains unknown fields and Data;
    /// treat the returned value as potentially sensitive. Decode diagnostics do not
    /// quote response content. Daemon rejection status and direct peer text are
    /// preserved; authenticated proxy text is withheld. `101` and `304` are errors.
    /// Requests are never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid reference or document, or a
    /// daemon or transport failure.
    pub async fn inspect_config(&self, id: &str) -> Result<SwarmConfig, Error> {
        let engine = self.node_engine().ok_or_else(|| {
            Error::invalid_input("inspect_config requires an owned transport endpoint")
        })?;
        raw::config_inspect(&engine, id).await
    }

    /// Updates one Swarm config at an explicit expected version.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved. An empty reference is refused.
    ///
    ///
    /// `Name`, `Labels`, `Data`, and `Templating` in `additional` are
    /// refused case-insensitively; non-ASCII keys are refused conservatively
    /// because the Engine uses Unicode case folding. This prevents ambiguous
    /// duplicate or folded members. Other members and config Data are retained
    /// in the owned update body.
    /// A deadline marker says only that a deadline was observed; the mutation
    /// outcome is unknown and must be reconciled before retrying.
    /// # Errors
    ///
    /// Returns an error for an invalid version, conversion failure, or Engine
    /// rejection.
    pub async fn update_config(&self, id: &str, options: ConfigUpdateOptions) -> Result<(), Error> {
        let engine = self.resource_write_engine()?;
        raw::config_update(&engine, id, &options).await
    }

    /// Removes one Swarm config.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved. An empty reference is refused.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_config(&self, id: &str) -> Result<(), Error> {
        let engine = self.resource_write_engine()?;
        raw::config_remove(&engine, id).await
    }

    /// Lists Swarm secrets using deterministic filter encoding.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only. A secret read has no generated
    /// fallback: the former generated client logs the whole response body at debug level before
    /// decoding it, and this crate cannot make that log line safe. The owned
    /// request is `GET /v<owned>/secrets`, where `<owned>` is the API version
    /// configured for the client. A `connect_local` client uses the socket or
    /// pipe it captured; any other endpoint with no owned target fails closed
    /// before dispatch with a fixed diagnostic and sends nothing.
    ///
    /// A failure is returned; it is never retried. A non-success Engine answer
    /// preserves its status in [`Error::api_error`] but withholds the response
    /// text with a fixed diagnostic, because a daemon or a proxy can echo secret
    /// bytes in it. A malformed success document is
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput), and its owned
    /// decode diagnostic is content-free (a category and position).
    ///
    /// # Filters
    ///
    /// `SecretListOptions::filters` is an ordered `BTreeMap`. The whole map is
    /// sent as Docker's JSON `filters` query value in key order, the values under
    /// one key keep the caller's order, and an empty map is not sent at all. The
    /// facade forwards the caller's map without validating a name; the daemon may
    /// reject an unknown filter name rather than treat it as no match. The
    /// loopback fixture is synthetic: it proves the encoding, not that a daemon
    /// accepts a particular name.
    ///
    /// # Value shape
    ///
    /// The owned decoder retains an object-level member of [`SwarmSecret`] and of
    /// its `Spec` in `additional`. `Version` is typed with no catch-all, so a
    /// member inside it is dropped; a duplicate known key is a decode error, and a
    /// duplicate unmodelled key collapses to one value. `Spec.Data` is retained as
    /// the JSON value the peer sent (`null`, number, object, array, or string);
    /// [`Debug`] withholds it and `Serialize` carries it.
    ///
    /// # Deadlines and cancellation
    ///
    /// On a `connect_local` client the read runs against the captured local
    /// target with a fixed per-operation deadline of 120 seconds. It covers the
    /// connect through the arrival of the response head. It does not bound the
    /// response body: once the head arrives the body is read without a deadline,
    /// so a peer that stalls mid-body keeps the call open until the connection
    /// fails. A caller that needs an upper bound on total time must impose one
    /// and cancel the read when it expires. A timeout from that budget carries
    /// the transport deadline marker, so [`Error::is_transport_deadline`] is
    /// true, and its diagnostic names only the budget. On any other owned target
    /// no secret-specific budget is added; the transport's own response-head
    /// deadline applies where one is configured, and the body is likewise
    /// unbounded.
    ///
    /// # Errors
    ///
    /// Returns an error when the filters cannot be encoded, when the endpoint has
    /// no owned target (no request is sent), when the Engine rejects the request
    /// (status preserved, text withheld), or when the answer cannot be decoded.
    pub async fn list_secrets(
        &self,
        options: Option<SecretListOptions>,
    ) -> Result<Vec<SwarmSecret>, Error> {
        let options = options.unwrap_or_default();
        let engine = self.secret_read_engine()?;
        raw::secret_list(&engine, &options).await
    }

    /// Creates a Swarm secret from caller-owned bytes.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved.
    ///
    /// # Errors
    ///
    /// Returns an error when base64 encoding or the Engine operation fails.
    pub async fn create_secret(&self, options: SecretCreateOptions) -> Result<String, Error> {
        let engine = self.resource_write_engine()?;
        raw::secret_create(&engine, &options).await
    }

    /// Inspects one Swarm secret.
    ///
    /// # Which transport serves this operation
    ///
    /// The repository-owned transport only. A secret read has no generated
    /// fallback: the former generated client logs the whole response body at debug level before
    /// decoding it, and this crate cannot make that log line safe. The owned
    /// request is `GET /v<owned>/secrets/{id}`, with the reference
    /// percent-encoded as one path segment. A `connect_local` client uses the
    /// socket or pipe it captured; any other endpoint with no owned target fails
    /// closed before dispatch with a fixed diagnostic and sends nothing.
    ///
    /// A failure is returned; it is never retried. A non-success Engine answer
    /// preserves its status in [`Error::api_error`] but withholds the response
    /// text with a fixed diagnostic, because a daemon or a proxy can echo secret
    /// bytes in it. An empty reference is refused before dispatch. A malformed
    /// success document is [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput),
    /// and its owned decode diagnostic is content-free (a category and position).
    ///
    /// # Value shape and secret data
    ///
    /// The Engine does not return secret bytes from an inspect. If a peer sends a
    /// `Spec.Data` member anyway, it is retained in
    /// [`SwarmSecretSpec::additional`] at the `Spec` object level as the JSON
    /// value it is: `null`, a number, an object, an array, or a string. That is
    /// object-level retention, not an unqualified lossless claim: a member inside
    /// the typed `Version` is dropped, a duplicate known key is a decode error,
    /// and a duplicate unmodelled key collapses to one value. [`Debug`] never
    /// prints the value. Explicit serialization — and therefore `ndocker secret
    /// inspect` and `--format json secret ls`, in either output format — emits
    /// what the peer sent, so treat that output as secret material.
    ///
    /// # Deadlines and cancellation
    ///
    /// On a `connect_local` client the read runs against the captured local
    /// target with a fixed per-operation deadline of 120 seconds. It covers the
    /// connect through the arrival of the response head. It does not bound the
    /// response body: once the head arrives the body is read without a deadline,
    /// so a peer that stalls mid-body keeps the call open until the connection
    /// fails. A caller that needs an upper bound on total time must impose one
    /// and cancel the read when it expires. A timeout from that budget carries
    /// the transport deadline marker, so [`Error::is_transport_deadline`] is
    /// true, and its diagnostic names only the budget. On any other owned target
    /// no secret-specific budget is added; the transport's own response-head
    /// deadline applies where one is configured, and the body is likewise
    /// unbounded.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is empty, when the endpoint has no
    /// owned target (no request is sent), when the Engine rejects the request
    /// (status preserved, text withheld), or when the answer cannot be decoded.
    pub async fn inspect_secret(&self, id: &str) -> Result<SwarmSecret, Error> {
        let engine = self.secret_read_engine()?;
        raw::secret_inspect(&engine, id).await
    }

    /// Updates secret metadata at an explicit expected version.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved. An empty reference is refused.
    ///
    /// The owned writer serializes the owned specification, including Driver
    /// and unreserved additional members.
    ///
    /// A specification carrying an unexpected `Data` member is refused before
    /// dispatch. The Engine does not return `Data` from a read, so such a value
    /// can only have come from a peer that put it there, and forwarding it to
    /// the update endpoint would send secret bytes on a request that cannot use
    /// them. A `Name`, `Labels`, or `Driver` member in the flattened
    /// `additional` map is refused too, because the typed field owns that key:
    /// a second spelling is either a duplicate or an untracked duplicate of a modeled field. ASCII keys are compared case-insensitively because
    /// the Engine's Go decoder matches field names without regard to case while
    /// this crate's serde models do not. A non-ASCII key is refused
    /// conservatively: Go's folding is Unicode (`Label\u{017f}` can reach
    /// `Labels`) and this crate has no dependency-free full fold table, so the
    /// guard refuses the class rather than claim it can enumerate every
    /// spelling. An escaped JSON key is decoded before the guard sees it. These
    /// refusals are fixed, content-free
    /// [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) messages that
    /// name the member or the reserved set, not the value. The guard is
    /// structural: it does not scan a free-form name, label, or driver for
    /// secret material and makes no claim to detect one.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid version, an unexpected `Data` or
    /// reserved member, a conversion failure, or an Engine rejection.
    pub async fn update_secret(&self, id: &str, options: SecretUpdateOptions) -> Result<(), Error> {
        let engine = self.resource_write_engine()?;
        raw::secret_update(&engine, id, &options).await
    }

    /// Removes one Swarm secret.
    ///
    /// Uses the owned, versioned transport only, including the captured local
    /// endpoint. Unavailable endpoints fail closed; failures are never retried.
    /// Failure text and transport sources are withheld while status and the
    /// transport deadline marker are preserved. An empty reference is refused.
    ///
    /// # Errors
    ///
    /// Returns an error when the Engine rejects the request.
    pub async fn remove_secret(&self, id: &str) -> Result<(), Error> {
        let engine = self.resource_write_engine()?;
        raw::secret_remove(&engine, id).await
    }

    /// Selects the existing captured local endpoint or another owned target.
    fn task_read_engine(&self) -> Option<raw::RawEngine> {
        self.node_engine()
    }

    /// Lists tasks with `GET /v<owned>/tasks` and deterministic filters.
    ///
    /// The configured version and captured local endpoint are used. No owned target
    /// fails closed before dispatch. A top-level `Image` collision rejects the whole
    /// response. Rejections preserve status and direct peer text; authenticated proxy
    /// text is withheld. `101` and `304` are errors. Requests are never retried.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable target, invalid filter or document, or a
    /// daemon or transport failure.
    pub async fn list_tasks(
        &self,
        options: Option<TaskListOptions>,
    ) -> Result<Vec<SwarmTask>, Error> {
        let engine = self.task_read_engine().ok_or_else(|| {
            Error::invalid_input("list_tasks requires an owned transport endpoint")
        })?;
        raw::task_list(&engine, &options.unwrap_or_default()).await
    }

    /// Inspects one Swarm task.
    ///
    /// Routes as [`Self::list_tasks`], rejecting an actual top-level `Image`
    /// member on the owned path and never retrying an owned request.
    ///
    /// # Errors
    ///
    /// Returns an error when response conversion or the Engine operation fails.
    pub async fn inspect_task(&self, id: &str) -> Result<SwarmTask, Error> {
        let engine = self.task_read_engine().ok_or_else(|| {
            Error::invalid_input("inspect_task requires an owned transport endpoint")
        })?;
        raw::task_inspect(&engine, id).await
    }

    /// Streams task log frames through a caller-owned handle.
    ///
    /// Uses the owned versioned task endpoint, including the captured local
    /// socket. No generated fallback remains: its errors can expose log output
    /// or proxy credentials. An unavailable owned endpoint fails before sending.
    /// With options, the query includes `follow`,
    /// `stdout`, and `stderr`, and does not send `details`. With `None` the
    /// request has no query, preserving the endpoint's defaults.
    ///
    /// A non-success status is the first error item, with peer text withheld.
    /// Frames use the shared size-limited decoder; malformed or truncated
    /// frames are error items. The stream is lazy, and cancellation or drop
    /// releases its response without retrying.
    pub fn task_logs(
        &self,
        id: &str,
        options: Option<SwarmLogOptions>,
    ) -> DockerStream<ContainerLogFrame> {
        let engine = self.task_read_engine();
        let id = id.to_owned();
        owned_response(async move {
            let engine = engine.ok_or_else(|| {
                Error::invalid_input("task logs require an owned transport endpoint")
            })?;
            let frames = raw::task_logs_optional(&engine, &id, options.as_ref()).await?;
            Ok(OwnedResponse::LogFrames {
                frames,
                map: map_owned_log_frame,
            })
        })
    }
}

#[cfg(test)]
mod trust_root_probe {
    use super::SwarmInfo;

    /// A `GET /swarm` document, trimmed to the members a reader depends on but
    /// otherwise exactly as a v29.8 daemon sent it.
    const DOCUMENT: &str = r#"{"ID":"tpruk002s2087sl5n8njv8ex5","Version":{"Index":10},"CreatedAt":"2026-09-25T23:55:58.494057145Z","UpdatedAt":"2026-09-25T23:55:59.042379153Z","TLSInfo":{"TrustRoot":"-----BEGIN CERTIFICATE-----\nMIIBajCCARCgAwIBAgIUB28pCWqKAZc+lxt6+AwKx+dGdLEwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjYwOTI1MjM1MTAwWhcNNDYwOTIwMjM1\nMTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABC5j2g8W6ju209OT0HT2GcHSWZQswEiiCD+cCZo5Yvbz8RxFQbuLpJXchGPg\ntkE2Rx5kCy97cFFKJbFBp2n9xZCjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBQHQh+LrsEveVL16S9A0IMveHO1njAKBggqhkjO\nPQQDAgNIADBFAiADpWFkXjrmtxETJ8y/GCEajZvW8lIyHpXy2PtTIDcldAIhAOj4\nLyVyX23Tqm5rI36T0sNNZaPxLA7CUUsTegmPwAhN\n-----END CERTIFICATE-----\n","CertIssuerSubject":"MBMxETAPBgNVBAMTCHN3YXJtLWNh","CertIssuerPublicKey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELmPaDxbqO7bT05PQdPYZwdJZlCzASKIIP5wJmjli9vPxHEVBu4ukldyEY+C2QTZHHmQLL3twUUolsUGnaf3FkA=="},"DataPathPort":4789,"RootRotationInProgress":false,"DefaultAddrPool":null,"SubnetSize":24,"Spec":{"Name":"default"},"JoinTokens":{"Worker":"<redacted>","Manager":"<redacted>"}}"#;

    /// The root CA is read from the Engine's own spelling of the document.
    ///
    /// `docker swarm ca` prints `TLSInfo.TrustRoot` from `GET /swarm`, and its
    /// output is byte-identical to that member. Reading it from the wrong place
    /// is what made the command report "no root CA certificate" against a
    /// perfectly healthy Swarm, so the member's position is pinned here.
    #[test]
    fn the_root_ca_is_read_from_the_engines_top_level_tls_info() {
        let info: SwarmInfo = serde_json::from_str(DOCUMENT).expect("the document decodes");
        let trust_root = info.trust_root().expect("a Swarm manager has a root CA");
        assert!(
            trust_root.starts_with("-----BEGIN CERTIFICATE-----"),
            "{trust_root}"
        );
        assert!(
            trust_root.trim_end().ends_with("-----END CERTIFICATE-----"),
            "{trust_root}"
        );
    }

    /// A document with no `TLSInfo` has no root CA, rather than an empty one.
    ///
    /// A worker node is given the CA too, but a document that genuinely omits it
    /// must not be reported as a Swarm with a blank certificate.
    #[test]
    fn a_document_without_tls_info_reports_no_root_ca() {
        let info: SwarmInfo =
            serde_json::from_str(r#"{"ID":"x","DataPathPort":2377}"#).expect("decodes");
        assert_eq!(info.trust_root(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::{DockerClient, NodeRemoveOptions, NodeSpec, NodeUpdateOptions};
    use crate::ErrorKind;

    #[test]
    fn node_spec_refusals_explain_reserved_and_non_ascii_separately() {
        for (key, expected, forbidden) in [
            ("labels", "modeled field", "non-ASCII"),
            ("zoneé", "non-ASCII", "modeled field"),
        ] {
            let mut spec = NodeSpec::default();
            spec.additional
                .insert(key.to_owned(), serde_json::Value::Null);
            let error = super::reject_reserved_node_spec_members(&spec).unwrap_err();
            let text = format!("{error:?} {error}");
            assert!(text.contains(expected), "{text}");
            assert!(!text.contains(forbidden), "{text}");
            assert!(!text.contains(key), "{text}");
        }
    }

    /// A client with no endpoint description has no owned target and no safe
    /// generated fallback. Both node writes refuse before a request.
    #[tokio::test]
    async fn node_writes_fail_closed_without_an_owned_target() {
        let client = DockerClient::from_target(
            crate::OwnedTarget::Unreachable("test endpoint".to_owned()),
            crate::ProxyPolicy::Direct,
            crate::API_VERSION,
        );

        let error = client
            .update_node(
                "node-1",
                NodeUpdateOptions {
                    version: 1,
                    spec: NodeSpec::default(),
                },
            )
            .await
            .expect_err("an unreachable node update fails closed");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("the generated fallback is not used"),
            "the refusal did not name the disabled fallback: {error}"
        );
        assert!(
            !error.to_string().contains("127.0.0.1"),
            "the refusal quoted an endpoint: {error}"
        );

        let error = client
            .remove_node("node-1", NodeRemoveOptions { force: false })
            .await
            .expect_err("an unreachable node removal fails closed");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("the generated fallback is not used"),
            "the refusal did not name the disabled fallback: {error}"
        );
    }
}
