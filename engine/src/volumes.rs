//! Repository-owned Docker Engine volumes operations.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{DockerClient, Error, raw};

/// Options for the Engine volume-list operation.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeListOptions {
    /// Docker volume filters, such as `name`, `driver`, `label`, or `dangling`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl VolumeListOptions {
    /// Creates empty volume-list options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one volume filter.
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

/// Options for creating a volume.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeCreateOptions {
    /// Optional volume name. The daemon generates one when omitted.
    pub name: Option<String>,
    /// Volume driver name.
    pub driver: Option<String>,
    /// Driver-specific options.
    pub driver_options: Option<BTreeMap<String, String>>,
    /// User-defined labels.
    pub labels: Option<BTreeMap<String, String>>,
}

impl VolumeCreateOptions {
    /// Creates unnamed volume options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name: None,
            driver: None,
            driver_options: None,
            labels: None,
        }
    }

    /// Sets an explicit volume name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds or replaces one user-defined label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), value.into());
        self
    }
}

/// Options for removing a volume.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VolumeRemoveOptions {
    /// Force removal of a volume that is still in use.
    pub force: bool,
}

impl VolumeRemoveOptions {
    /// Creates default volume-removal options.
    #[must_use]
    pub const fn new() -> Self {
        Self { force: false }
    }

    /// Enables or disables forced removal.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }
}

/// Options for pruning unused volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumePruneOptions {
    /// Docker volume-prune filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl VolumePruneOptions {
    /// Creates empty volume-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one volume-prune filter.
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

/// Volume usage fields returned by Engine volume endpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct VolumeUsage {
    /// Disk space used by the volume in bytes, or `-1` when unavailable.
    pub size: i64,
    /// Number of containers referencing the volume, or `-1` when unavailable.
    pub reference_count: i64,
}

/// Stable volume fields returned by list, create, and inspect operations.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeSummary {
    /// Volume name.
    pub name: String,
    /// Volume driver.
    pub driver: String,
    /// Host mount point.
    pub mountpoint: String,
    /// RFC 3339 creation timestamp.
    pub created_at: Option<String>,
    /// Volume scope.
    pub scope: Option<String>,
    /// Driver status rows.
    pub status: Option<Vec<String>>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Driver-specific options.
    pub options: BTreeMap<String, String>,
    /// Optional usage details.
    pub usage: Option<VolumeUsage>,
}

/// Result of listing volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumeListResult {
    /// Matching volumes.
    pub volumes: Vec<VolumeSummary>,
    /// Warnings returned by the daemon.
    pub warnings: Vec<String>,
}

/// Result of pruning unused volumes.
#[derive(Clone, Debug, Serialize, Default, Eq, PartialEq)]
pub struct VolumePruneResult {
    /// Names of deleted volumes.
    pub volumes_deleted: Vec<String>,
    /// Reclaimed disk space in bytes.
    pub space_reclaimed: Option<i64>,
}

/// Compatibility name matching the Engine response terminology.
pub type VolumeResponse = VolumeSummary;
/// Compatibility name matching the Engine response terminology.
pub type VolumeListResponse = VolumeListResult;
/// Compatibility name matching the Engine response terminology.
pub type VolumePruneResponse = VolumePruneResult;

impl DockerClient {
    /// Lists volumes using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn list_volumes(
        &self,
        options: Option<VolumeListOptions>,
    ) -> Result<VolumeListResult, Error> {
        raw::volume_list(&self.raw_engine()?, &options.unwrap_or_default()).await
    }

    /// Creates a volume from repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for serialization, transport, or response
    /// decoding failures.
    pub async fn create_volume(
        &self,
        options: VolumeCreateOptions,
    ) -> Result<VolumeSummary, Error> {
        raw::volume_create(&self.raw_engine()?, &options).await
    }

    /// Inspects one volume.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn inspect_volume(&self, name: &str) -> Result<VolumeSummary, Error> {
        raw::volume_inspect(&self.raw_engine()?, name).await
    }

    /// Removes a volume.
    ///
    /// # Errors
    ///
    /// Returns a repository error when the daemon rejects the request.
    pub async fn remove_volume(
        &self,
        name: &str,
        options: Option<VolumeRemoveOptions>,
    ) -> Result<(), Error> {
        raw::volume_remove(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Prunes unused volumes using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns a repository error for transport or response-decoding failures.
    pub async fn prune_volumes(
        &self,
        options: Option<VolumePruneOptions>,
    ) -> Result<VolumePruneResult, Error> {
        raw::volume_prune(&self.raw_engine()?, &options.unwrap_or_default()).await
    }
}
