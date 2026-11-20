//! Repository-owned Docker Engine networks operations.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{DockerClient, Error, raw, raw::NetworkEntry};

/// Options for the Engine network-list operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkListOptions {
    /// Docker network filters, such as `name`, `driver`, `label`, or `scope`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl NetworkListOptions {
    /// Creates empty network-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one network filter.
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

/// Options for the Engine network-inspect operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkInspectOptions {
    /// Request verbose inspect output.
    pub verbose: bool,
    /// Restrict a swarm-scoped lookup to a scope.
    pub scope: Option<String>,
}

impl NetworkInspectOptions {
    /// Creates empty network-inspect options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            verbose: false,
            scope: None,
        }
    }

    /// Enables or disables verbose output.
    #[must_use]
    pub const fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Sets the optional network scope.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }
}

/// A typed IPAM pool used by network creation and inspection.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkIpamConfig {
    /// IPv4 subnet in CIDR notation.
    pub subnet: Option<String>,
    /// IPv4 address range.
    pub ip_range: Option<String>,
    /// IPv4 gateway.
    pub gateway: Option<String>,
    /// Named auxiliary addresses.
    pub auxiliary_addresses: BTreeMap<String, String>,
}

/// Typed IPAM configuration for a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkIpam {
    /// IPAM driver name.
    pub driver: Option<String>,
    /// Address pools.
    pub config: Vec<NetworkIpamConfig>,
    /// IPAM driver options.
    pub options: BTreeMap<String, String>,
}

/// Options for creating a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkCreateOptions {
    /// Required network name.
    pub name: String,
    /// Network driver name.
    pub driver: Option<String>,
    /// Network scope, such as `local` or `swarm`.
    pub scope: Option<String>,
    /// Restrict external access to the network.
    pub internal: Option<bool>,
    /// Allow regular containers to attach to a global network.
    pub attachable: Option<bool>,
    /// Mark the network as the Swarm ingress network.
    pub ingress: Option<bool>,
    /// Create a config-only network.
    pub config_only: Option<bool>,
    /// Name of a config-only network providing this network's configuration.
    pub config_from: Option<String>,
    /// Enable IPv4 on the network.
    pub enable_ipv4: Option<bool>,
    /// Enable IPv6 on the network.
    pub enable_ipv6: Option<bool>,
    /// IPAM configuration.
    pub ipam: Option<NetworkIpam>,
    /// Network-driver options.
    pub options: Option<BTreeMap<String, String>>,
    /// User-defined labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl NetworkCreateOptions {
    /// Creates options for a named network.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

/// A network endpoint requested when connecting a container.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkEndpointOptions {
    /// DNS aliases for the endpoint.
    pub aliases: Option<Vec<String>>,
    /// Legacy container links.
    pub links: Option<Vec<String>>,
    /// Requested endpoint MAC address.
    pub mac_address: Option<String>,
    /// Driver-specific endpoint options.
    pub driver_options: Option<BTreeMap<String, String>>,
    /// Requested IPv4 address.
    pub ipv4_address: Option<String>,
    /// Requested IPv6 address.
    pub ipv6_address: Option<String>,
    /// Requested link-local IPv6 addresses.
    pub link_local_ips: Option<Vec<String>>,
}

/// Options for connecting a container to a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkConnectOptions {
    /// Container ID or name.
    pub container: String,
    /// Optional endpoint settings.
    pub endpoint: Option<NetworkEndpointOptions>,
}

impl NetworkConnectOptions {
    /// Creates options for a container connection.
    #[must_use]
    pub fn new(container: impl Into<String>) -> Self {
        Self {
            container: container.into(),
            endpoint: None,
        }
    }
}

/// Options for disconnecting a container from a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkDisconnectOptions {
    /// Container ID or name.
    pub container: String,
    /// Force disconnection when the container is running.
    pub force: Option<bool>,
}

impl NetworkDisconnectOptions {
    /// Creates options for a container disconnection.
    #[must_use]
    pub fn new(container: impl Into<String>) -> Self {
        Self {
            container: container.into(),
            force: None,
        }
    }
}

/// Options for pruning unused networks.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkPruneOptions {
    /// Docker network-prune filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl NetworkPruneOptions {
    /// Creates empty network-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one network-prune filter.
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

/// Stable network fields returned by list and inspect operations.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkSummary {
    /// Network name.
    pub name: Option<String>,
    /// Network ID.
    pub id: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: Option<String>,
    /// Network scope.
    pub scope: Option<String>,
    /// Network driver.
    pub driver: Option<String>,
    /// Whether IPv4 is enabled.
    pub enable_ipv4: Option<bool>,
    /// Whether IPv6 is enabled.
    pub enable_ipv6: Option<bool>,
    /// IPAM configuration.
    pub ipam: Option<NetworkIpam>,
    /// Whether the network is internal.
    pub internal: Option<bool>,
    /// Whether regular containers may attach to the network.
    pub attachable: Option<bool>,
    /// Whether the network is the Swarm ingress network.
    pub ingress: Option<bool>,
    /// Whether the network is config-only.
    pub config_only: Option<bool>,
    /// Network-driver options.
    pub options: BTreeMap<String, String>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
}

/// A typed endpoint attached to an inspected network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkEndpoint {
    /// Container name reported by Docker.
    pub name: Option<String>,
    /// Endpoint ID.
    pub endpoint_id: Option<String>,
    /// Endpoint MAC address.
    pub mac_address: Option<String>,
    /// Endpoint IPv4 address.
    pub ipv4_address: Option<String>,
    /// Endpoint IPv6 address.
    pub ipv6_address: Option<String>,
}

/// A typed network-inspect result.
///
/// Daemon-specific service, peer, and status objects are intentionally omitted
/// from this bounded projection.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkInspect {
    /// Stable network fields.
    pub network: NetworkSummary,
    /// Containers attached to the network.
    pub containers: BTreeMap<String, NetworkEndpoint>,
}

/// Result of creating a network.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkCreateResult {
    /// ID of the created network.
    pub id: String,
    /// Warning returned by the daemon, when present.
    pub warning: Option<String>,
}

/// Result of pruning unused networks.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct NetworkPruneResult {
    /// IDs or names of deleted networks.
    pub networks_deleted: Vec<String>,
}

/// Compatibility name matching the Engine response terminology.
pub type NetworkResponse = NetworkSummary;
/// Compatibility name matching the Engine response terminology.
pub type NetworkCreateResponse = NetworkCreateResult;
/// Compatibility name matching the Engine response terminology.
pub type NetworkPruneResponse = NetworkPruneResult;

impl DockerClient {
    /// Lists networks using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_networks(
        &self,
        options: Option<NetworkListOptions>,
    ) -> Result<Vec<NetworkSummary>, Error> {
        raw::network_list(&self.raw_engine()?, &options.unwrap_or_default())
            .await
            .map(|entries| entries.iter().map(NetworkEntry::summary).collect())
    }

    /// Inspects one network using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn inspect_network(
        &self,
        name: &str,
        options: Option<NetworkInspectOptions>,
    ) -> Result<NetworkInspect, Error> {
        raw::network_inspect(&self.raw_engine()?, name, &options.unwrap_or_default())
            .await
            .map(|entry| entry.inspect())
    }

    /// Creates a network from repository-owned options.
    ///
    /// # Examples
    ///
    /// This example does not create a network because nothing is listening at
    /// the configured address.
    ///
    /// ```
    /// use neotales_docker::{DockerClient, NetworkCreateOptions};
    ///
    /// let runtime = tokio::runtime::Builder::new_current_thread()
    ///     .enable_all()
    ///     .build()
    ///     .expect("runtime");
    /// runtime.block_on(async {
    ///     let client = DockerClient::connect_http("http://127.0.0.1:1")?;
    ///     let created = client
    ///         .create_network(NetworkCreateOptions::new("docs-example"))
    ///         .await;
    ///     // Nothing is listening, so this does not create a network.
    ///     // A successful create is removed by id. Drop does not remove it.
    ///     if let Ok(network) = &created {
    ///         client.remove_network(&network.id).await?;
    ///     }
    ///     assert!(created.is_err());
    ///     Ok::<(), neotales_docker::Error>(())
    /// })
    /// .expect("example completes");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or response
    /// decoding failures.
    pub async fn create_network(
        &self,
        options: NetworkCreateOptions,
    ) -> Result<NetworkCreateResult, Error> {
        raw::network_create(&self.raw_engine()?, &options).await
    }

    /// Removes a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn remove_network(&self, name: &str) -> Result<(), Error> {
        raw::network_remove(&self.raw_engine()?, name).await
    }

    /// Connects a container to a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or daemon
    /// failures.
    pub async fn connect_network(
        &self,
        name: &str,
        options: NetworkConnectOptions,
    ) -> Result<(), Error> {
        raw::network_connect(&self.raw_engine()?, name, &options).await
    }

    /// Disconnects a container from a network.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or daemon
    /// failures.
    pub async fn disconnect_network(
        &self,
        name: &str,
        options: NetworkDisconnectOptions,
    ) -> Result<(), Error> {
        raw::network_disconnect(&self.raw_engine()?, name, &options).await
    }

    /// Prunes unused networks using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn prune_networks(
        &self,
        options: Option<NetworkPruneOptions>,
    ) -> Result<NetworkPruneResult, Error> {
        raw::network_prune(&self.raw_engine()?, &options.unwrap_or_default()).await
    }
}
