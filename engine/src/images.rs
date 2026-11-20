//! Repository-owned Docker Engine image operations.
//!
//! Image operations use the repository-owned Engine transport.
//! Public values contain the stable Engine image fields used by the facade;
//! experimental manifest/descriptor data and other daemon-specific nested
//! objects are deliberately not exposed.

use std::collections::BTreeMap;

use crate::{DockerClient, Error, raw};

/// Options for the Engine image-list operation.
///
/// Filters use the Docker Engine JSON filter representation. The map is kept
/// ordered at the public boundary so caller policy is stable; the fixture suite
/// asserts decoded query values.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageListOptions {
    /// Include intermediate image layers.
    pub all: bool,
    /// Ask the daemon to calculate shared image sizes.
    pub shared_size: bool,
    /// Ask the daemon to include repository digests.
    pub digests: bool,
    /// Docker image filters, such as `label` or `reference`.
    pub filters: BTreeMap<String, Vec<String>>,
}

/// Options for the Engine image-delete operation.
///
/// Platform-specific deletion is intentionally omitted.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageRemoveOptions {
    /// Remove the image even when it is referenced by stopped containers or
    /// has other tags.
    pub force: bool,
    /// Do not delete untagged parent images.
    pub no_prune: bool,
}

/// Query options for the Engine image-inspect operation.
///
/// `platform` is the JSON-encoded OCI platform accepted by the Engine API. It
/// remains a string at this boundary so callers do not need to depend on a
/// the former generated client OCI model.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageInspectOptions {
    /// JSON-encoded OCI platform used to select an image variant.
    pub platform: Option<String>,
}

impl ImageInspectOptions {
    /// Creates default image-inspect options.
    #[must_use]
    pub const fn new() -> Self {
        Self { platform: None }
    }

    /// Sets a JSON-encoded OCI platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }
}

/// Query options for the Engine image-history operation.
///
/// `platform` is the JSON-encoded OCI platform accepted by the Engine API.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHistoryOptions {
    /// JSON-encoded OCI platform used to select an image variant.
    pub platform: Option<String>,
}

impl ImageHistoryOptions {
    /// Creates default image-history options.
    #[must_use]
    pub const fn new() -> Self {
        Self { platform: None }
    }

    /// Sets a JSON-encoded OCI platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }
}

/// Query options for the Engine image-tag operation.
///
/// The optional `force` flag is sent when specified.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageTagOptions {
    /// Target repository, without a registry scheme.
    pub repo: Option<String>,
    /// Target tag.
    pub tag: Option<String>,
    /// Overwrite an existing target tag.
    pub force: Option<bool>,
}

impl ImageTagOptions {
    /// Creates options for a target repository.
    #[must_use]
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            repo: Some(repo.into()),
            tag: None,
            force: None,
        }
    }

    /// Sets the target repository.
    #[must_use]
    pub fn with_repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    /// Sets the target tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Enables or disables replacement of an existing target tag.
    #[must_use]
    pub const fn with_force(mut self, force: bool) -> Self {
        self.force = Some(force);
        self
    }
}

/// Query options for the Engine image-search operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageSearchOptions {
    /// Required registry search term.
    pub term: String,
    /// Maximum number of results requested from the registry.
    pub limit: Option<i32>,
    /// Docker search filters, such as `is-official` or `stars`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl ImageSearchOptions {
    /// Creates options for a required search term.
    #[must_use]
    pub fn new(term: impl Into<String>) -> Self {
        Self {
            term: term.into(),
            limit: None,
            filters: BTreeMap::new(),
        }
    }

    /// Sets the maximum result count.
    #[must_use]
    pub const fn with_limit(mut self, limit: i32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Adds or replaces one image-search filter.
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

/// Query options for the Engine image-prune operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImagePruneOptions {
    /// Docker image-prune filters, such as `dangling`, `until`, or `label`.
    pub filters: BTreeMap<String, Vec<String>>,
}

impl ImagePruneOptions {
    /// Creates empty image-prune options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            filters: BTreeMap::new(),
        }
    }

    /// Adds or replaces one image-prune filter.
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

/// Stable image-list values exposed by the repository facade.
///
/// Experimental manifest and descriptor fields from newer Engine responses
/// are intentionally not included in this first slice.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ImageSummary {
    /// Content-addressable image ID.
    pub id: String,
    /// Parent image ID, when one is present.
    pub parent_id: String,
    /// Local repository tags.
    pub repo_tags: Vec<String>,
    /// Repository digests reported by the daemon.
    pub repo_digests: Vec<String>,
    /// Creation time as a Unix timestamp.
    pub created: i64,
    /// Total image size in bytes.
    pub size: i64,
    /// Shared layer size in bytes, or `-1` when it was not calculated.
    pub shared_size: i64,
    /// User-defined image labels.
    pub labels: BTreeMap<String, String>,
    /// Number of containers using the image, or `-1` when unknown.
    pub containers: i64,
}

/// A typed health-check policy from an inspected image configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHealthcheck {
    /// Health-check command, including its `CMD` or `CMD-SHELL` selector.
    pub test: Option<Vec<String>>,
    /// Interval in nanoseconds.
    pub interval: Option<i64>,
    /// Timeout in nanoseconds.
    pub timeout: Option<i64>,
    /// Number of retries.
    pub retries: Option<i64>,
    /// Start period in nanoseconds.
    pub start_period: Option<i64>,
    /// Start interval in nanoseconds.
    pub start_interval: Option<i64>,
}

/// Stable image configuration values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageConfig {
    /// User used for commands run inside the image.
    pub user: Option<String>,
    /// Ports declared by the image.
    pub exposed_ports: Option<Vec<String>>,
    /// Environment variables declared by the image.
    pub env: Option<Vec<String>>,
    /// Default command.
    pub cmd: Option<Vec<String>>,
    /// Health-check policy.
    pub healthcheck: Option<ImageHealthcheck>,
    /// Whether Windows arguments are escaped.
    pub args_escaped: Option<bool>,
    /// Volumes declared by the image.
    pub volumes: Option<Vec<String>>,
    /// Default working directory.
    pub working_dir: Option<String>,
    /// Default entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// ONBUILD instructions.
    pub on_build: Option<Vec<String>>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Stop signal.
    pub stop_signal: Option<String>,
    /// Default shell.
    pub shell: Option<Vec<String>>,
}

/// Stable root-filesystem values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageRootFs {
    /// Root filesystem type, normally `layers`.
    pub typ: String,
    /// Content-addressable layer IDs.
    pub layers: Vec<String>,
}

/// Stable storage-driver values returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageGraphDriver {
    /// Storage-driver name.
    pub name: String,
    /// Driver-specific metadata.
    pub data: BTreeMap<String, String>,
}

/// Stable local-cache metadata returned by image inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageMetadata {
    /// RFC 3339 timestamp of the most recent local tag operation.
    pub last_tag_time: Option<String>,
}

/// A typed, bounded projection of an inspected local image.
///
/// Experimental OCI descriptors, manifest summaries, and identity records are
/// intentionally outside this first v1.53 facade.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageInspect {
    /// Content-addressable image ID.
    pub id: String,
    /// Local repository tags.
    pub repo_tags: Vec<String>,
    /// Repository digests.
    pub repo_digests: Vec<String>,
    /// Optional image comment.
    pub comment: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created: Option<String>,
    /// Image author.
    pub author: Option<String>,
    /// CPU architecture.
    pub architecture: Option<String>,
    /// CPU architecture variant.
    pub variant: Option<String>,
    /// Operating-system name.
    pub os: Option<String>,
    /// Operating-system version.
    pub os_version: Option<String>,
    /// Total image size in bytes.
    pub size: Option<i64>,
    /// Image configuration.
    pub config: Option<ImageConfig>,
    /// Storage-driver information.
    pub graph_driver: Option<ImageGraphDriver>,
    /// Root filesystem layer information.
    pub root_fs: Option<ImageRootFs>,
    /// Local image-store metadata.
    pub metadata: Option<ImageMetadata>,
}

/// One layer in an image history response.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageHistory {
    /// Layer image ID.
    pub id: String,
    /// Layer creation time as a Unix timestamp.
    pub created: i64,
    /// Command that created the layer.
    pub created_by: String,
    /// Tags associated with the layer.
    pub tags: Vec<String>,
    /// Layer size in bytes.
    pub size: i64,
    /// Layer comment.
    pub comment: String,
}

/// One result returned by the Engine image-search operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageSearchResult {
    /// Repository name.
    pub name: String,
    /// Repository description.
    pub description: String,
    /// Number of repository stars.
    pub star_count: i64,
    /// Whether the repository is official.
    pub is_official: bool,
    /// Whether the repository is automated.
    ///
    /// Docker marks this field deprecated, but it remains part of the v1.53
    /// response projection for callers that need the legacy field.
    pub is_automated: bool,
}

/// One record returned by the Engine image-prune operation.
pub type ImagePruneDelete = ImageDeleteResult;

/// Result of pruning unused images.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImagePruneResult {
    /// Images that were deleted or untagged.
    pub images_deleted: Vec<ImageDeleteResult>,
    /// Reclaimed disk space in bytes.
    pub space_reclaimed: Option<i64>,
}

/// One record returned by the Engine image-delete operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageDeleteResult {
    /// Image reference that was untagged, when applicable.
    pub untagged: Option<String>,
    /// Image ID that was deleted, when applicable.
    pub deleted: Option<String>,
}

/// Compatibility names matching Engine response terminology.
pub type ImageInspectResponse = ImageInspect;
/// Compatibility name for an image-history entry.
pub type ImageHistoryEntry = ImageHistory;
/// Compatibility name for an image-history response item.
pub type ImageHistoryResponse = ImageHistory;
/// Compatibility name for an image-search response item.
pub type ImageSearchResponse = ImageSearchResult;
/// Compatibility name for an image-search result.
pub type ImageSearchResultItem = ImageSearchResult;
/// Compatibility name for an image-prune response.
pub type ImagePruneResponse = ImagePruneResult;

impl DockerClient {
    /// Inspects one local image.
    ///
    /// The default request uses the Engine's ordinary v1.53 inspect shape.
    /// Use [`Self::inspect_image_with_options`] when a platform selector is
    /// required.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn inspect_image(&self, name: &str) -> Result<ImageInspect, Error> {
        self.inspect_image_with_options(name, None).await
    }

    /// Inspects one local image using repository-owned query options.
    ///
    /// **This is the canonical image inspect.** [`Self::inspect_image`] is an
    /// alias for the no-options case and delegates here, so the owned transport
    /// is reached once, from one place, rather than per spelling.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn inspect_image_with_options(
        &self,
        name: &str,
        options: Option<ImageInspectOptions>,
    ) -> Result<ImageInspect, Error> {
        raw::image_inspect(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Returns the layer history for one local image.
    ///
    /// The default request uses the Engine's ordinary v1.53 history shape. Use
    /// [`Self::image_history_with_options`] to select a platform variant.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn image_history(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history_with_options(name, None).await
    }

    /// Returns the layer history using repository-owned query options.
    ///
    /// **This is the canonical image history.** [`Self::image_history`],
    /// [`Self::history_image`], and [`Self::get_image_history`] are three
    /// spellings of the no-options case and all delegate here, so the transport
    /// is chosen once. Giving each its own `raw::image_history` call would be
    /// four copies of the same routing decision to keep in step.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn image_history_with_options(
        &self,
        name: &str,
        options: Option<ImageHistoryOptions>,
    ) -> Result<Vec<ImageHistory>, Error> {
        raw::image_history(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Compatibility name for [`Self::image_history`].
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn history_image(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history(name).await
    }

    /// Compatibility name for [`Self::image_history`].
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn get_image_history(&self, name: &str) -> Result<Vec<ImageHistory>, Error> {
        self.image_history(name).await
    }

    /// Tags one local image using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn tag_image(
        &self,
        name: &str,
        options: Option<ImageTagOptions>,
    ) -> Result<(), Error> {
        raw::image_tag(&self.raw_engine()?, name, &options.unwrap_or_default()).await
    }

    /// Searches the registry for images using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn search_images(
        &self,
        options: ImageSearchOptions,
    ) -> Result<Vec<ImageSearchResult>, Error> {
        raw::image_search(&self.raw_engine()?, &options).await
    }

    /// Prunes unused images using repository-owned filters.
    ///
    /// # Errors
    ///
    /// Returns the underlying Docker API error when the request fails.
    pub async fn prune_images(
        &self,
        options: Option<ImagePruneOptions>,
    ) -> Result<ImagePruneResult, Error> {
        raw::image_prune(&self.raw_engine()?, &options.unwrap_or_default()).await
    }
}
