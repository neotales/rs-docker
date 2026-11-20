//! Repository-owned Docker Engine plugin operations.
//!
//! Credentialed install progress and failures are withheld to avoid exposing
//! registry credentials; anonymous installs retain the daemon's messages.
//! Upgrade and push check status and then drop the progress stream.

use std::collections::BTreeMap;

use serde::Serialize;
use tokio::sync::mpsc;

use crate::{
    DockerClient, DockerStream, Error, ImageStreamEvent, RegistryCredentialProvider,
    RegistryCredentials, raw, streams,
};

/// Options for listing installed plugins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PluginListOptions {
    /// Ordered plugin filters, such as `capability` or `enabled`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl PluginListOptions {
    /// Creates empty plugin-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one plugin filter.
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

/// Stable fields returned by plugin list and inspect operations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PluginSummary {
    /// Plugin ID.
    pub id: Option<String>,
    /// Installed plugin name.
    pub name: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Human-readable plugin description.
    pub description: String,
    /// Remote reference used to pull or push the plugin.
    pub plugin_reference: Option<String>,
}

/// A plugin privilege and its accepted values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PluginPrivilege {
    /// Privilege name.
    pub name: Option<String>,
    /// Human-readable privilege description.
    pub description: Option<String>,
    /// Values granted for the privilege.
    pub values: Vec<String>,
}

/// Options for enabling a plugin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginEnableOptions {
    /// Daemon-side enable timeout in seconds.
    pub timeout_seconds: i32,
}

impl PluginEnableOptions {
    /// Creates plugin-enable options.
    #[must_use]
    pub const fn new(timeout_seconds: i32) -> Self {
        Self { timeout_seconds }
    }
}

/// Options for disabling a plugin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PluginDisableOptions {
    /// Disable even when the plugin is in use.
    pub force: Option<bool>,
}

/// Options for removing a plugin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PluginRemoveOptions {
    /// Disable the plugin before removing it.
    pub force: Option<bool>,
}

/// Options for installing a remote plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInstallOptions {
    /// Remote plugin reference.
    pub remote: String,
    /// Optional local plugin name.
    pub name: Option<String>,
    /// Privileges granted to the plugin.
    pub privileges: Vec<PluginPrivilege>,
}

impl PluginInstallOptions {
    /// Creates options for a remote plugin.
    #[must_use]
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            name: None,
            privileges: Vec::new(),
        }
    }
}

/// Options for upgrading an installed plugin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginUpgradeOptions {
    /// Remote reference to upgrade to.
    pub remote: String,
    /// Privileges granted to the upgraded plugin.
    pub privileges: Vec<PluginPrivilege>,
}

impl PluginUpgradeOptions {
    /// Creates options for a remote plugin upgrade.
    #[must_use]
    pub fn new(remote: impl Into<String>) -> Self {
        Self {
            remote: remote.into(),
            privileges: Vec::new(),
        }
    }
}

/// Fixed text used when a plugin settings write has no owned transport.
///
/// The settings body may contain a plugin secret, and the former generated client traces a buffered
/// request body at TRACE level before any error handling runs. The endpoint reason
/// is not quoted because it can contain a host or path.
const PLUGIN_SET_UNREACHABLE: &str = "the plugin settings write cannot be dispatched: the owned transport cannot reach this endpoint, and the generated fallback is not used because it traces the request body. Build the client with connect_local or an explicit endpoint the owned transport reaches.";
const PLUGIN_CREATE_UNREACHABLE: &str = "the plugin archive cannot be dispatched: the owned transport cannot reach this endpoint, and the generated fallback is not used because it traces the buffered archive. Build the client with connect_local or an explicit endpoint the owned transport reaches.";

/// Fixed text used when a credential-bearing plugin request has no owned
/// transport.
///
/// the former generated client encodes `X-Registry-Auth` with the standard base64 alphabet and the
/// Engine decodes it with the URL-safe one, silently treating a header it cannot
/// decode as no credential. A credential is never handed to that path.
const PLUGIN_CREDENTIAL_UNREACHABLE: &str = "the plugin request cannot be dispatched: it carries a registry credential, the owned transport cannot reach this endpoint, and the generated fallback is not used because it encodes X-Registry-Auth in a form the Engine can silently read as no credential. Build the client with connect_local or an explicit endpoint the owned transport reaches.";

/// Fixed text used when a credentialed install's progress stream reports a
/// failure in band.
///
/// The record is the registry's answer, relayed by the daemon, and it can echo
/// the credential or the registry endpoint. The original message is dropped
/// rather than filtered, and no source chain retains it.
const PLUGIN_IN_BAND_WITHHELD: &str = "response text withheld for a credentialed plugin install because the registry progress record may echo the registry credential";

/// The fixed status a credentialed install puts on every progress item.
///
/// A credentialed install does not expose the daemon's textual progress. Every
/// successful record becomes one event carrying this status and no other field,
/// so ordering and completion survive while status, stream, id, numeric progress,
/// error text, and every unknown or nested member are dropped. A record that
/// reports a failure becomes a fixed error item instead. See the module
/// documentation for why this is a breaking loss of textual progress and why the
/// anonymous install is unchanged.
const CREDENTIALED_PROGRESS_STATUS: &str = "plugin install progress (text withheld)";

/// Bridges the owned backend's progress stream onto the facade's event stream.
///
/// The owned backend answers a plugin install with a [`raw::FrameStream`] — one
/// JSON record per line, read as it arrives — while the facade's contract is a
/// [`DockerStream`] of [`ImageStreamEvent`]. The records go through the same
/// [`streams::map_image_event`] the generated path uses, so the event values a
/// caller sees do not change when the transport does.
///
/// The request is opened inside the spawned task rather than before it, because
/// the owned transport is asynchronous and the facade's install contract is a
/// synchronous call that returns a stream. An empty remote is therefore
/// reported as the first stream item rather than as the returned `Err`, which
/// is where the generated path puts a request-build failure too.
///
/// A credential is validated by the caller before this runs, so the rebuild here
/// exists only because [`raw::RegistryAuth`] borrows the credential it encodes.
/// A rebuild that somehow fails is reported as the first stream item rather than
/// dropped.
///
/// A record carrying `errorDetail` is a failure, not progress, and the Engine
/// reports one *inside* a `200` body. The generated client turns that record
/// into a stream item error; this does the same, so a caller that matches on an
/// item error keeps matching. The two members are read straight out of the
/// record rather than through the generated model, because decoding through it
/// is the truncation this migration exists to remove — a progress record whose
/// shape the model cannot express would be dropped on the owned path and
/// accepted on the generated one, which is the wrong way round.
///
/// **A credentialed install does not surface the record at all.** A successful
/// record becomes one fixed [`ImageStreamEvent`] carrying
/// `plugin install progress (text withheld)` and no other member; a record carrying
/// `error` or `errorDetail` in any form becomes a fixed item error with no source
/// retaining the original. Ordering and completion survive; textual progress,
/// numeric progress, identifiers, and unknown or nested members do not. An
/// anonymous install surfaces the daemon's events and in-band message as before.
fn owned_progress_stream(
    engine: raw::RawEngine,
    options: PluginInstallOptions,
    credentials: Option<(String, RegistryCredentials)>,
) -> Result<DockerStream<ImageStreamEvent>, Error> {
    let confidential = credentials.is_some();
    let runtime = tokio::runtime::Handle::try_current().map_err(|error| Error {
        kind: crate::ErrorKind::Runtime,
        source: Some(Box::new(error)),
        api: None,
    })?;
    let (sender, receiver) = mpsc::channel(16);
    runtime.spawn(async move {
        let auth = match credentials.as_ref() {
            Some((registry, credentials)) => {
                match raw::RegistryAuth::credentials(registry, credentials) {
                    Ok(auth) => auth,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                }
            }
            None => raw::RegistryAuth::none(),
        };
        let mut frames = match raw::plugin_pull_with_registry_auth(&engine, &options, auth).await {
            Ok(frames) => frames,
            Err(error) => {
                let _ = sender.send(Err(error)).await;
                return;
            }
        };
        loop {
            let item = match frames.next_json().await {
                Ok(Some(value)) if confidential => {
                    if reports_failure(&value) {
                        Err(Error::withheld(
                            crate::ErrorKind::Docker,
                            PLUGIN_IN_BAND_WITHHELD,
                        ))
                    } else {
                        Ok(sanitized_progress_event())
                    }
                }
                Ok(Some(value)) => match in_band_failure(&value) {
                    Some(message) => Err(Error {
                        kind: crate::ErrorKind::Docker,
                        source: Some(Box::new(std::io::Error::other(message))),
                        api: None,
                    }),
                    None => Ok(streams::map_image_event(&value)),
                },
                Ok(None) => break,
                Err(error) if confidential => Err(withheld_stream_error(&error)),
                Err(error) => Err(error),
            };
            if sender.send(item).await.is_err() {
                break;
            }
        }
    });
    Ok(streams::map_owned_stream(
        futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|item| (item, receiver))
        }),
        Ok,
    ))
}

/// Replaces a bundled stream's own read or decode failure for a confidential
/// install.
///
/// `next_json` can fail on a malformed record, an oversized record, or a
/// transport read. The first two are already content-free summaries, but a
/// transport source is peer-adjacent and the kind is the caller's discriminator,
/// so the kind is preserved and the source chain is replaced. A deadline marker
/// survives, with text that says a deadline was observed rather than claiming
/// this install timed out.
fn withheld_stream_error(error: &Error) -> Error {
    error.withhold_transport(PLUGIN_IN_BAND_WITHHELD,
        "a transport deadline was observed; the credentialed plugin install outcome is unknown; reconcile before retrying")
}

/// Whether a progress record reports a failure.
///
/// Only the **presence** of a top-level `error` or `errorDetail` key is read,
/// including a `null` value. The key's JSON type, its members, and any nested
/// data are not interpreted, and the record is not exposed either way: a
/// credentialed install returns a fixed failure item, so a malformed, unknown, or
/// null detail cannot become a successful event and cannot carry peer text into
/// one. Nested and unknown data is suppressed rather than inspected.
fn reports_failure(record: &serde_json::Value) -> bool {
    record.get("error").is_some() || record.get("errorDetail").is_some()
}

/// The only progress event a credentialed install emits for a successful record.
///
/// Every peer-controlled string, the numeric progress, and every unknown or
/// nested member are dropped: the record becomes one fixed event, so ordering and
/// completion are preserved without carrying peer content into the event's
/// `Debug`, `Display`, or serialization.
fn sanitized_progress_event() -> ImageStreamEvent {
    ImageStreamEvent {
        id: None,
        status: Some(CREDENTIALED_PROGRESS_STATUS.to_owned()),
        stream: None,
        progress: None,
        error: None,
    }
}

/// Reads the message of a progress record that reports a failure in band.
///
/// The Engine's plugin handlers write progress through a flush-on-write writer
/// and check it afterwards, so a failure *after* the first record is already a
/// `200` and can only be reported as one more progress object. That is the
/// daemon's answer, preserved rather than rewritten.
fn in_band_failure(record: &serde_json::Value) -> Option<String> {
    record
        .get("errorDetail")
        .and_then(|detail| detail.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

impl DockerClient {
    /// Returns the owned engine for a plugin operation, or `None` when the
    /// endpoint has no owned target.
    ///
    /// `raw_engine` is the general routing signal and remains unreachable for
    /// `connect_local`. That constructor records one concrete socket, so a plugin
    /// write that must not fall back uses it when it is the only owned target, for
    /// the same reason service update and the node writes do.
    fn plugin_engine(&self) -> Option<raw::RawEngine> {
        self.raw_engine().ok()
    }

    /// Returns the owned engine for a write that must not fall back, or the fixed
    /// refusal.
    ///
    /// The managed SSH establishment gate is consulted first: a write whose body
    /// can carry a secret must not dispatch it through a gate the transport has
    /// already judged unsafe.
    fn plugin_private_engine(&self, unreachable: &'static str) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.plugin_engine()
            .ok_or_else(|| Error::invalid_input(unreachable))
    }

    /// Lists installed plugins with deterministic filter ordering.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_plugins(
        &self,
        options: Option<PluginListOptions>,
    ) -> Result<Vec<PluginSummary>, Error> {
        raw::plugin_list(&self.raw_engine()?, &options.unwrap_or_default()).await
    }

    /// Inspects one installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn inspect_plugin(&self, name: &str) -> Result<PluginSummary, Error> {
        raw::plugin_inspect(&self.raw_engine()?, name).await
    }

    /// Enables an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for invalid options, transport, or daemon
    /// failures.
    pub async fn enable_plugin(
        &self,
        name: &str,
        options: Option<PluginEnableOptions>,
    ) -> Result<(), Error> {
        raw::plugin_enable(
            &self.raw_engine()?,
            name,
            &options.unwrap_or_else(|| PluginEnableOptions::new(0)),
        )
        .await
    }

    /// Disables an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn disable_plugin(
        &self,
        name: &str,
        options: Option<PluginDisableOptions>,
    ) -> Result<(), Error> {
        raw::plugin_disable(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Removes an installed plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn remove_plugin(
        &self,
        name: &str,
        options: Option<PluginRemoveOptions>,
    ) -> Result<PluginSummary, Error> {
        raw::plugin_remove(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Changes plugin settings using Docker's `KEY=VALUE` wire shape.
    ///
    /// The body is a list of `KEY=VALUE` strings and may contain a plugin secret,
    /// so this operation has **no generated fallback**: the former generated client traces a buffered
    /// request body at TRACE level before any error handling runs. The owned
    /// transport does not log the body. On an endpoint with no owned target — not
    /// even the socket `connect_local` captured — the call fails closed with a
    /// fixed [`crate::ErrorKind::InvalidInput`] before dispatch.
    ///
    /// # Errors
    ///
    /// Returns a fixed input error when the owned transport cannot reach the
    /// endpoint. A daemon rejection keeps its status, but the message is fixed
    /// text: the peer's body is never read, because the settings may contain a
    /// secret. A transport failure is replaced the same way, except that a
    /// deadline marker is preserved.
    pub async fn set_plugin_config(&self, name: &str, settings: Vec<String>) -> Result<(), Error> {
        let engine = self.plugin_private_engine(PLUGIN_SET_UNREACHABLE)?;
        raw::plugin_set(&engine, name, &settings).await
    }

    /// Creates a plugin from an in-memory TAR archive.
    ///
    /// The archive is limited to [`raw::MAX_UPLOAD_BYTES`] and is sent to the
    /// versioned route through the owned transport. Failure response text is
    /// withheld because a peer can echo archive contents. This fails closed on
    /// endpoint kinds the owned transport cannot reach; it never uses
    /// the former generated client's generated path, which traces the buffered archive.
    ///
    /// # Errors
    ///
    /// Returns an input error when `name` is empty or the archive exceeds
    /// [`raw::MAX_UPLOAD_BYTES`]. The status is retained on a daemon rejection,
    /// but peer response text and transport sources are withheld. Endpoint
    /// kinds the owned transport cannot reach fail before dispatch.
    pub async fn create_plugin(&self, name: &str, archive: Vec<u8>) -> Result<(), Error> {
        let engine = self.plugin_private_engine(PLUGIN_CREATE_UNREACHABLE)?;
        raw::plugin_create(&engine, name, archive).await
    }

    /// Reads the privileges required by a remote plugin.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn plugin_privileges(&self, remote: &str) -> Result<Vec<PluginPrivilege>, Error> {
        raw::plugin_privileges(&self.raw_engine()?, remote).await
    }

    /// Installs a plugin without registry credentials.
    ///
    /// This is the canonical form of the install family: the credentialed
    /// variants differ from it only in how a registry credential is resolved,
    /// so all three converge on `DockerClient::install_plugin_with_optional_credentials`
    /// and the transport decision is made once, there.
    ///
    /// # Errors
    ///
    /// Returns an error when no asynchronous runtime is available. Engine
    /// request and response failures are delivered as stream items.
    pub fn install_plugin(
        &self,
        options: PluginInstallOptions,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        self.install_plugin_with_optional_credentials(options, None)
    }

    /// Installs a plugin with caller-owned registry credentials.
    ///
    /// The credential is sent in `X-Registry-Auth`, encoded URL-safely by the
    /// owned transport. There is no generated fallback: the generated client's
    /// header spelling is the one the Engine can silently read as no credential.
    /// See the module documentation.
    ///
    /// # Errors
    ///
    /// Returns a credential error before opening the stream when credentials
    /// are invalid, and a fixed input error when the owned transport cannot reach
    /// the endpoint. Request and response failures are delivered as stream items.
    /// The credential is never handed to the generated client; failure text from
    /// the daemon, registry, or proxy is replaced with fixed text. Every
    /// successful progress record becomes one fixed event whose only member is
    /// the status `plugin install progress (text withheld)`, and any record
    /// whose top-level keys include `error` or `errorDetail` (any value, `null`
    /// included) becomes a fixed error item. Only presence is read; nested data is
    /// suppressed, not interpreted. Textual and numeric progress are lost by
    /// design; the anonymous install is unchanged.
    pub fn install_plugin_with_credentials(
        &self,
        options: PluginInstallOptions,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        self.install_plugin_with_optional_credentials(options, Some((registry, credentials)))
    }

    /// Installs a plugin with credentials from an explicit provider.
    ///
    /// The credential is sent the same way as
    /// [`DockerClient::install_plugin_with_credentials`].
    ///
    /// # Errors
    ///
    /// Returns a provider or validation error before opening the stream, and a
    /// fixed input error when the owned transport cannot reach the endpoint.
    pub fn install_plugin_with_provider(
        &self,
        options: PluginInstallOptions,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        let credentials = provider.credentials_for(&registry)?;
        self.install_plugin_with_optional_credentials(options, Some((registry, credentials)))
    }

    fn install_plugin_with_optional_credentials(
        &self,
        options: PluginInstallOptions,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<DockerStream<ImageStreamEvent>, Error> {
        if let Some((registry, credentials)) = credentials {
            let _ = raw::RegistryAuth::credentials(&registry, &credentials)?;
            let engine = self.plugin_private_engine(PLUGIN_CREDENTIAL_UNREACHABLE)?;
            return owned_progress_stream(engine, options, Some((registry, credentials)));
        }
        owned_progress_stream(self.raw_engine()?, options, None)
    }

    /// Upgrades a plugin without registry credentials.
    ///
    /// This is the canonical form of the upgrade family: the credentialed
    /// variants differ from it only in how a registry credential is resolved,
    /// so all three converge on
    /// `DockerClient::upgrade_plugin_with_optional_credentials` and the
    /// transport decision is made once, there.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn upgrade_plugin(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
    ) -> Result<(), Error> {
        self.upgrade_plugin_with_optional_credentials(name, options, None)
            .await
    }

    /// Upgrades a plugin with caller-owned registry credentials.
    ///
    /// The credential is sent in `X-Registry-Auth`, URL-encoded by the owned
    /// transport. There is no generated fallback: the generated client's header
    /// spelling is the one the Engine can silently read as no credential.
    ///
    /// # Errors
    ///
    /// Returns a credential error, a fixed input error when the owned transport
    /// cannot reach the endpoint, or a transport or daemon error. The status is
    /// preserved; the message is fixed text and no response or transport source
    /// retains the credential or the endpoint.
    pub async fn upgrade_plugin_with_credentials(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        credentials: RegistryCredentials,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        self.upgrade_plugin_with_optional_credentials(name, options, Some((registry, credentials)))
            .await
    }

    /// Upgrades a plugin with credentials from an explicit provider.
    ///
    /// The credential is sent the same way as
    /// [`DockerClient::upgrade_plugin_with_credentials`].
    ///
    /// # Errors
    ///
    /// Returns a provider, credential, transport, or daemon error, or the fixed
    /// input error when the owned transport cannot reach the endpoint.
    pub async fn upgrade_plugin_with_provider(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(&options.remote)?;
        let credentials = provider.credentials_for(&registry)?;
        self.upgrade_plugin_with_optional_credentials(name, options, Some((registry, credentials)))
            .await
    }

    async fn upgrade_plugin_with_optional_credentials(
        &self,
        name: &str,
        options: PluginUpgradeOptions,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<(), Error> {
        if let Some((registry, credentials)) = credentials {
            let auth = raw::RegistryAuth::credentials(&registry, &credentials)?;
            let engine = self.plugin_private_engine(PLUGIN_CREDENTIAL_UNREACHABLE)?;
            let _progress =
                raw::plugin_upgrade_with_registry_auth(&engine, name, &options, auth).await?;
            return Ok(());
        }
        let _progress = raw::plugin_upgrade(&self.raw_engine()?, name, &options).await?;
        Ok(())
    }

    /// Pushes a plugin without registry credentials.
    ///
    /// The owned transport checks the status before handing out the progress
    /// stream, and this signature is `Result<(), Error>`, so the stream is
    /// dropped and the connection closes. The generated client's
    /// `process_into_unit` does the same, which is why neither path can see an
    /// in-band `errorDetail` record.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or daemon failures.
    pub async fn push_plugin(&self, name: &str) -> Result<(), Error> {
        self.push_plugin_with_optional_credentials(name, None).await
    }

    /// Pushes a plugin with caller-owned registry credentials.
    ///
    /// The credential is sent in `X-Registry-Auth`, URL-encoded by the owned
    /// transport. There is no generated fallback: the generated client's header
    /// spelling is the one the Engine can silently read as no credential.
    ///
    /// # Errors
    ///
    /// Returns a credential error, a fixed input error when the owned transport
    /// cannot reach the endpoint, or a transport or daemon error. The status is
    /// preserved; the message is fixed text and no response or transport source
    /// retains the credential or the endpoint.
    pub async fn push_plugin_with_credentials(
        &self,
        name: &str,
        credentials: RegistryCredentials,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(name)?;
        self.push_plugin_with_optional_credentials(name, Some((registry, credentials)))
            .await
    }

    /// Pushes a plugin with credentials from an explicit provider.
    ///
    /// The credential is sent the same way as
    /// [`DockerClient::push_plugin_with_credentials`].
    ///
    /// # Errors
    ///
    /// Returns a provider, credential, transport, or daemon error, or the fixed
    /// input error when the owned transport cannot reach the endpoint.
    pub async fn push_plugin_with_provider(
        &self,
        name: &str,
        provider: &dyn RegistryCredentialProvider,
    ) -> Result<(), Error> {
        let registry = crate::registry_for_image(name)?;
        let credentials = provider.credentials_for(&registry)?;
        self.push_plugin_with_optional_credentials(name, Some((registry, credentials)))
            .await
    }

    async fn push_plugin_with_optional_credentials(
        &self,
        name: &str,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<(), Error> {
        if let Some((registry, credentials)) = credentials {
            let auth = raw::RegistryAuth::credentials(&registry, &credentials)?;
            let engine = self.plugin_private_engine(PLUGIN_CREDENTIAL_UNREACHABLE)?;
            let _progress = raw::plugin_push_with_registry_auth(&engine, name, auth).await?;
            return Ok(());
        }
        let _progress = raw::plugin_push(&self.raw_engine()?, name).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PLUGIN_IN_BAND_WITHHELD, withheld_stream_error};
    use crate::ErrorKind;

    const PASSWORD_CANARY: &str = "password-canary";
    const ENDPOINT_CANARY: &str = "test endpoint";
    /// A client with no owned target refuses the writes whose generated fallback is
    /// unsafe instead of handing them to the former generated client.
    #[tokio::test]
    async fn a_client_without_an_owned_target_fails_closed() {
        let client = crate::DockerClient::from_target(
            crate::OwnedTarget::Unreachable("test endpoint".to_owned()),
            crate::ProxyPolicy::Direct,
            crate::API_VERSION,
        );
        assert!(
            client.raw_engine().is_err(),
            "the probe client unexpectedly has an owned target"
        );

        let error = client
            .set_plugin_config(
                "registry.example/vieux/sshfs:latest",
                vec!["A=1".to_owned()],
            )
            .await
            .expect_err("the settings write refuses without an owned target");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.api_error().is_none());
        assert!(
            error.to_string().contains("traces the request body"),
            "the refusal does not name the tracing hazard: {error}"
        );

        let error = client
            .create_plugin("example/plugin", b"opaque tar".to_vec())
            .await
            .expect_err("plugin create refuses without an owned target");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("traces the buffered archive"),
            "the refusal does not name the archive tracing hazard: {error}"
        );

        let error = client
            .install_plugin_with_credentials(
                super::PluginInstallOptions::new("registry.example/vieux/sshfs:latest"),
                crate::RegistryCredentials::new("user", PASSWORD_CANARY),
            )
            .expect_err("the credentialed install refuses without an owned target");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains(
                "X-Registry-Auth in a form the Engine can silently read as no credential"
            ),
            "the refusal does not name the header hazard: {error}"
        );
        assert!(
            renderings(&error)
                .iter()
                .all(|text| !text.contains(PASSWORD_CANARY) && !text.contains(ENDPOINT_CANARY))
        );

        let error = client
            .push_plugin_with_credentials(
                "registry.example/vieux/sshfs:latest",
                crate::RegistryCredentials::new("user", PASSWORD_CANARY),
            )
            .await
            .expect_err("the credentialed push refuses without an owned target");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            renderings(&error)
                .iter()
                .all(|text| !text.contains(PASSWORD_CANARY) && !text.contains(ENDPOINT_CANARY))
        );
    }

    /// Walks `Display`, `Debug`, and every source of an error.
    fn renderings(error: &crate::Error) -> Vec<String> {
        let mut rendered = vec![error.to_string(), format!("{error:?}")];
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            rendered.push(cause.to_string());
            rendered.push(format!("{cause:?}"));
            source = cause.source();
        }
        rendered
    }

    #[test]
    fn a_confidential_stream_error_keeps_the_kind_and_drops_the_source() {
        for (source, kind) in [
            (
                crate::Error::transport("source-canary"),
                ErrorKind::Transport,
            ),
            (
                crate::Error::invalid_input("record-canary"),
                ErrorKind::InvalidInput,
            ),
        ] {
            let error = withheld_stream_error(&source);
            assert_eq!(error.kind(), kind);
            assert!(!error.is_transport_deadline());
            assert!(error.api_error().is_none());
            let rendered = renderings(&error);
            for canary in ["source-canary", "record-canary"] {
                assert!(
                    rendered.iter().all(|text| !text.contains(canary)),
                    "the sanitized error echoed {canary:?}: {rendered:?}"
                );
            }
            assert!(
                rendered
                    .iter()
                    .any(|text| text.contains(PLUGIN_IN_BAND_WITHHELD)),
                "the fixed text is missing: {rendered:?}"
            );
        }
    }

    #[test]
    fn a_confidential_stream_deadline_keeps_its_marker_without_claiming_a_timeout() {
        let error =
            withheld_stream_error(&crate::Error::transport_deadline("deadline-source-canary"));
        assert_eq!(error.kind(), ErrorKind::Transport);
        assert!(error.is_transport_deadline());
        let rendered = renderings(&error);
        for text in &rendered {
            assert!(
                !text.contains("deadline-source-canary"),
                "the sanitized error echoed its source: {text}"
            );
            assert!(
                !text.contains("timed out"),
                "the fixed text claimed a timeout: {text}"
            );
        }
    }
}
