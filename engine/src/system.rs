//! Repository-owned Docker Engine system operations.

use std::{
    collections::BTreeMap,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::Stream;
use serde::Serialize;
use serde_json::Value;

use crate::streams::{DockerEventResponse, OwnedResponse, map_event_record_strict, owned_response};
use crate::{DockerClient, DockerStream, Error, raw};

/// Resource categories accepted by `GET /system/df`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum DiskUsageType {
    /// Container usage.
    Container,
    /// Image usage.
    Image,
    /// Volume usage.
    Volume,
    /// Build-cache usage.
    BuildCache,
}

impl DiskUsageType {
    /// Returns the Engine query value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Image => "image",
            Self::Volume => "volume",
            Self::BuildCache => "build-cache",
        }
    }
}

impl fmt::Display for DiskUsageType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Query options for `GET /system/df`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiskUsageOptions {
    /// Resource categories to request. `None` leaves selection to the daemon.
    pub types: Option<Vec<DiskUsageType>>,
    /// Request detailed usage entries.
    pub verbose: bool,
}

impl DiskUsageOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            types: None,
            verbose: false,
        }
    }

    /// Sets the resource categories.
    #[must_use]
    pub fn with_types<I>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = DiskUsageType>,
    {
        self.types = Some(types.into_iter().collect());
        self
    }

    /// Enables or disables detailed entries.
    #[must_use]
    pub const fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

/// Aggregate usage for one Docker resource category.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsageCategory {
    /// Number of active resources.
    pub active_count: Option<i64>,
    /// Number of known resources.
    pub total_count: Option<i64>,
    /// Reclaimable bytes.
    pub reclaimable: Option<i64>,
    /// Bytes in use.
    pub total_size: Option<i64>,
    /// Typed projections of verbose entries.
    pub items: Vec<DiskUsageItem>,
}

/// A bounded, repository-owned projection of a verbose disk-usage entry.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsageItem {
    /// Resource identifier.
    pub id: Option<String>,
    /// Resource name, tag, or container name.
    pub name: Option<String>,
    /// Parent identifier, when applicable.
    pub parent_id: Option<String>,
    /// Resource size in bytes.
    pub size: Option<i64>,
    /// Volume reference count, when available.
    pub reference_count: Option<i64>,
    /// Build-cache in-use flag, when available.
    pub in_use: Option<bool>,
    /// Creation timestamp, when available.
    pub created: Option<i64>,
    /// Resource labels.
    pub labels: BTreeMap<String, String>,
    /// Image tags or container names.
    pub references: Vec<String>,
    /// Volume storage driver.
    pub driver: Option<String>,
    /// Category that produced this projection.
    pub resource_type: Option<DiskUsageType>,
}

/// Disk usage returned by Engine API v1.53.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DiskUsage {
    /// Image usage.
    pub image_usage: Option<DiskUsageCategory>,
    /// Container usage.
    pub container_usage: Option<DiskUsageCategory>,
    /// Volume usage.
    pub volume_usage: Option<DiskUsageCategory>,
    /// Build-cache usage.
    pub build_cache_usage: Option<DiskUsageCategory>,
}

/// Stable scalar fields selected from `GET /info`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SystemInfo {
    /// Daemon identifier.
    pub id: Option<String>,
    /// Total containers.
    pub containers: Option<i64>,
    /// Running containers.
    pub containers_running: Option<i64>,
    /// Paused containers.
    pub containers_paused: Option<i64>,
    /// Stopped containers.
    pub containers_stopped: Option<i64>,
    /// Total images.
    pub images: Option<i64>,
    /// Storage driver.
    pub storage_driver: Option<String>,
    /// Storage-driver status rows.
    pub driver_status: Option<Vec<Vec<String>>>,
    /// Docker state directory.
    pub docker_root_dir: Option<String>,
    /// Host operating system.
    pub operating_system: Option<String>,
    /// Host operating-system version.
    pub os_version: Option<String>,
    /// Generic operating-system type.
    pub os_type: Option<String>,
    /// Daemon architecture.
    pub architecture: Option<String>,
    /// Logical CPU count.
    pub cpu_count: Option<i64>,
    /// Total memory in bytes.
    pub memory_total: Option<i64>,
    /// Hostname.
    pub name: Option<String>,
    /// Docker daemon version.
    pub server_version: Option<String>,
    /// Host kernel version.
    pub kernel_version: Option<String>,
    /// Daemon system time.
    pub system_time: Option<String>,
    /// Default logging driver.
    pub logging_driver: Option<String>,
    /// Default OCI runtime.
    pub default_runtime: Option<String>,
    /// Cgroup driver.
    pub cgroup_driver: Option<String>,
    /// Cgroup version.
    pub cgroup_version: Option<String>,
    /// Host capability flags.
    pub memory_limit: Option<bool>,
    /// Host capability flags.
    pub swap_limit: Option<bool>,
    /// Host capability flags.
    pub cpu_cfs_period: Option<bool>,
    /// Host capability flags.
    pub cpu_cfs_quota: Option<bool>,
    /// Host capability flags.
    pub cpu_shares: Option<bool>,
    /// Host capability flags.
    pub cpu_set: Option<bool>,
    /// Host capability flags.
    pub pids_limit: Option<bool>,
    /// Host capability flags.
    pub oom_kill_disable: Option<bool>,
    /// IPv4 forwarding state.
    pub ipv4_forwarding: Option<bool>,
    /// Debug-mode state.
    pub debug: Option<bool>,
    /// Active event-listener count.
    pub event_listeners: Option<i64>,
    /// Daemon labels.
    pub labels: Option<Vec<String>>,
    /// Security options.
    pub security_options: Option<Vec<String>>,
    /// Daemon warnings.
    pub warnings: Option<Vec<String>>,
    /// Experimental-build state.
    pub experimental_build: Option<bool>,
    /// Live-restore state.
    pub live_restore_enabled: Option<bool>,
    /// Isolation technology.
    pub isolation: Option<String>,
    /// docker-init binary name.
    pub init_binary: Option<String>,
}

/// Actor metadata attached to a Docker event.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EventActor {
    /// Resource identifier.
    pub id: Option<String>,
    /// Resource attributes.
    pub attributes: BTreeMap<String, String>,
}

/// A repository-owned Docker event projection.
///
/// Type and scope remain strings so daemon-specific values can pass through
/// without exposing the former generated client generated enums.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SystemEvent {
    /// Resource type, such as `container` or `image`.
    pub resource_type: Option<String>,
    /// Event action, such as `start` or `die`.
    pub action: Option<String>,
    /// Resource that emitted the event.
    pub actor: Option<EventActor>,
    /// Event scope.
    pub scope: Option<String>,
    /// Unix event time in seconds.
    pub time: Option<i64>,
    /// Unix event time in nanoseconds.
    pub time_nano: Option<i64>,
}

/// Query options for `GET /events`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventOptions {
    /// Lower event-time bound.
    pub since: Option<String>,
    /// Upper event-time bound.
    pub until: Option<String>,
    /// Docker event filters.
    pub filters: Option<BTreeMap<String, Vec<String>>>,
}

impl EventOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            since: None,
            until: None,
            filters: None,
        }
    }

    /// Sets the lower event-time bound.
    #[must_use]
    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = Some(since.into());
        self
    }

    /// Sets the upper event-time bound.
    #[must_use]
    pub fn with_until(mut self, until: impl Into<String>) -> Self {
        self.until = Some(until.into());
        self
    }

    /// Adds or replaces one event filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// An owned response stream for `GET /events`.
///
/// The handle owns the response body independently of the client borrow. Drop
/// or [`EventStream::cancel`] releases the body and cancels the HTTP response.
/// The request is not sent until the handle is first polled, so creating a
/// handle and dropping it opens no connection.
#[must_use = "an EventStream must be consumed or explicitly cancelled"]
pub struct EventStream {
    stream: DockerStream<SystemEvent>,
}

impl std::fmt::Debug for EventStream {
    /// Prints the handle's name, because there is nothing else it may print.
    ///
    /// The field is a [`DockerStream`] and renders no item of its own; this
    /// wrapper does not widen that. The items are the daemon's event log —
    /// container ids, image names, and the attribute map the daemon attaches to
    /// each — and none of it has been read yet, so there is no progress to
    /// report either.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EventStream")
    }
}

impl EventStream {
    fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<SystemEvent, Error>> + Send + 'static,
    {
        Self {
            stream: DockerStream::new(stream),
        }
    }

    /// Waits for the next event or stream error.
    #[must_use]
    pub async fn next(&mut self) -> Option<Result<SystemEvent, Error>> {
        self.stream.next().await
    }

    /// Explicitly cancels and releases the response stream.
    pub fn cancel(mut self) {
        self.stream.cancel();
    }
}

impl Stream for EventStream {
    type Item = Result<SystemEvent, Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream).poll_next(context)
    }
}

impl Unpin for EventStream {}

/// Query options for `POST /build/prune`.
///
/// Engine API v1.53 has no daemon-wide `/system/prune` endpoint. This type
/// covers the native build-cache prune operation; resource-specific prune
/// calls are not silently composed here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BuildCachePruneOptions {
    /// Cache bytes to retain.
    pub reserved_space: Option<i64>,
    /// Maximum cache bytes to retain.
    pub max_used_space: Option<i64>,
    /// Target free space after pruning.
    pub min_free_space: Option<i64>,
    /// Remove all cache types.
    pub all: Option<bool>,
    /// Build-cache filters.
    pub filters: Option<BTreeMap<String, Vec<String>>>,
}

impl BuildCachePruneOptions {
    /// Creates empty options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reserved_space: None,
            max_used_space: None,
            min_free_space: None,
            all: None,
            filters: None,
        }
    }

    /// Sets retained cache bytes.
    #[must_use]
    pub const fn with_reserved_space(mut self, bytes: i64) -> Self {
        self.reserved_space = Some(bytes);
        self
    }

    /// Sets maximum retained cache bytes.
    #[must_use]
    pub const fn with_max_used_space(mut self, bytes: i64) -> Self {
        self.max_used_space = Some(bytes);
        self
    }

    /// Sets target free space.
    #[must_use]
    pub const fn with_min_free_space(mut self, bytes: i64) -> Self {
        self.min_free_space = Some(bytes);
        self
    }

    /// Selects all cache types.
    #[must_use]
    pub const fn with_all(mut self, all: bool) -> Self {
        self.all = Some(all);
        self
    }

    /// Adds or replaces one build-cache filter.
    #[must_use]
    pub fn with_filter<K, V, I>(mut self, key: K, values: I) -> Self
    where
        K: Into<String>,
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.filters
            .get_or_insert_with(BTreeMap::new)
            .insert(key.into(), values.into_iter().map(Into::into).collect());
        self
    }
}

/// Result of `POST /build/prune`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BuildCachePruneResult {
    /// Removed cache identifiers.
    pub caches_deleted: Vec<String>,
    /// Reclaimed bytes.
    pub space_reclaimed: Option<i64>,
}

impl DockerClient {
    /// Reads selected fields from `GET /info`.
    ///
    /// # Errors
    ///
    /// Returns a repository error for a daemon, transport, or decode failure.
    pub async fn info(&self) -> Result<SystemInfo, Error> {
        Ok(map_info_document(&raw::info(&self.raw_engine()?).await?))
    }

    /// Returns the complete `GET /info` object as repository-owned JSON.
    ///
    /// # Errors
    ///
    /// Returns a transport or serialization error.
    pub async fn info_value(&self) -> Result<Value, Error> {
        raw::info(&self.raw_engine()?).await
    }

    /// Reads `GET /system/df` using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a repository error for query serialization, transport, or
    /// response-decoding failures.
    pub async fn disk_usage(&self, options: Option<DiskUsageOptions>) -> Result<DiskUsage, Error> {
        let report = raw::disk_usage(&self.raw_engine()?, &options.unwrap_or_default()).await?;
        Ok(report.usage())
    }

    /// Opens a lazy owned event stream. Errors are delivered as stream items.
    /// Dropping or cancelling the stream closes the response.
    pub fn system_events(&self, options: Option<EventOptions>) -> EventStream {
        let engine = self.raw_engine();
        let options = options.unwrap_or_default();
        EventStream::new(owned_response(async move {
            let frames = raw::events(&engine?, &options).await?;
            Ok(OwnedResponse::Records {
                frames,
                map: Box::new(|record| map_event_record_to_system(&record)),
            })
        }))
    }

    /// Removes unused build-cache records with `POST /build/prune`.
    ///
    /// The Engine API reference documents a daemon-wide `POST /system/prune`,
    /// but no Docker daemon serves it: the route is absent at every version,
    /// while `POST /containers/prune` beside it answers normally. `docker
    /// system prune` therefore composes the per-resource prune calls itself,
    /// which is why it can name the networks it deleted while a single
    /// summary could not.
    ///
    /// This method composes nothing. Reclaiming a category is destructive and
    /// irreversible, and calling the prune endpoints one after another means a
    /// failure part way through leaves the daemon in a state neither the caller
    /// nor the user asked for, with no summary of what was already gone. The CLI
    /// reports that rather than performing it.
    ///
    /// # Errors
    ///
    /// Returns a repository error for query serialization, transport, or
    /// response-decoding failures.
    pub async fn prune_build_cache(
        &self,
        options: Option<BuildCachePruneOptions>,
    ) -> Result<BuildCachePruneResult, Error> {
        raw::prune_build_cache(&self.raw_engine()?, &options.unwrap_or_default()).await
    }
}

/// Projects the daemon's `GET /info` document onto the repository's model.
///
/// This is the same projection previously performed over the generated
/// model, spelled out over the document the owned transport returned as sent.
/// Every member the generated model declares is read here, and three of them —
/// `CgroupDriver`, `CgroupVersion`, and `Isolation` — are closed enums there,
/// so a value this client does not enumerate fails the whole decode on that
/// path and reads as the daemon's own text here.
///
/// A member the daemon did not send reads as absent rather than as a zero, and
/// the whole document is still available from [`raw::info`] for a member this
/// model has no field for.
fn map_info_document(info: &Value) -> SystemInfo {
    SystemInfo {
        id: string_field(info, "ID"),
        containers: integer_field(info, "Containers"),
        containers_running: integer_field(info, "ContainersRunning"),
        containers_paused: integer_field(info, "ContainersPaused"),
        containers_stopped: integer_field(info, "ContainersStopped"),
        images: integer_field(info, "Images"),
        storage_driver: string_field(info, "Driver"),
        driver_status: string_rows_field(info, "DriverStatus"),
        docker_root_dir: string_field(info, "DockerRootDir"),
        operating_system: string_field(info, "OperatingSystem"),
        os_version: string_field(info, "OSVersion"),
        os_type: string_field(info, "OSType"),
        architecture: string_field(info, "Architecture"),
        cpu_count: integer_field(info, "NCPU"),
        memory_total: integer_field(info, "MemTotal"),
        name: string_field(info, "Name"),
        server_version: string_field(info, "ServerVersion"),
        kernel_version: string_field(info, "KernelVersion"),
        system_time: string_field(info, "SystemTime"),
        logging_driver: string_field(info, "LoggingDriver"),
        default_runtime: string_field(info, "DefaultRuntime"),
        cgroup_driver: string_field(info, "CgroupDriver"),
        cgroup_version: string_field(info, "CgroupVersion"),
        memory_limit: bool_field(info, "MemoryLimit"),
        swap_limit: bool_field(info, "SwapLimit"),
        cpu_cfs_period: bool_field(info, "CpuCfsPeriod"),
        cpu_cfs_quota: bool_field(info, "CpuCfsQuota"),
        cpu_shares: bool_field(info, "CPUShares"),
        cpu_set: bool_field(info, "CPUSet"),
        pids_limit: bool_field(info, "PidsLimit"),
        oom_kill_disable: bool_field(info, "OomKillDisable"),
        ipv4_forwarding: bool_field(info, "IPv4Forwarding"),
        debug: bool_field(info, "Debug"),
        event_listeners: integer_field(info, "NEventsListener"),
        labels: string_list_field(info, "Labels"),
        security_options: string_list_field(info, "SecurityOptions"),
        warnings: string_list_field(info, "Warnings"),
        experimental_build: bool_field(info, "ExperimentalBuild"),
        live_restore_enabled: bool_field(info, "LiveRestoreEnabled"),
        isolation: string_field(info, "Isolation"),
        init_binary: string_field(info, "InitBinary"),
    }
}

/// Projects one owned-event record onto the same [`SystemEvent`] the generated
/// path produces.
///
/// The record is the daemon's own JSON, read by
/// [`map_event_record_strict`](crate::streams::map_event_record_strict) — which
/// refuses a known member whose JSON type is wrong — and then wrapped in the
/// repository type. That refusal is why this projection is fallible: the
/// generated path failed the whole record on a malformed member, and this entry
/// point must not silently read the member as absent instead.
fn map_event_record_to_system(record: &Value) -> Result<SystemEvent, Error> {
    let DockerEventResponse {
        event_type,
        action,
        actor,
        scope,
        time,
        time_nano,
    } = map_event_record_strict(record)?;
    Ok(SystemEvent {
        resource_type: event_type,
        action,
        actor: actor.map(|actor| EventActor {
            id: actor.id,
            attributes: actor.attributes,
        }),
        scope,
        time,
        time_nano,
    })
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn string_list_field(value: &Value, key: &str) -> Option<Vec<String>> {
    value.get(key)?.as_array().map(|values| {
        values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn integer_field(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

/// Reads a member the Engine sends as a list of label/value rows.
///
/// `DriverStatus` is the only such member the repository's model names, and the
/// generated type it is read from is `Option<Vec<Vec<String>>>`, so a row with
/// no strings in it is preserved as an empty row rather than dropped: the row's
/// *position* is the pairing.
fn string_rows_field(value: &Value, key: &str) -> Option<Vec<Vec<String>>> {
    value.get(key)?.as_array().map(|rows| {
        rows.iter()
            .map(|row| {
                row.as_array().map_or_else(Vec::new, |values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
            })
            .collect()
    })
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    struct DropStream {
        dropped: Arc<AtomicBool>,
    }

    impl Stream for DropStream {
        type Item = Result<SystemEvent, Error>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    impl Drop for DropStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[test]
    fn cancel_drops_the_owned_response_stream() {
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = EventStream::new(DropStream {
            dropped: Arc::clone(&dropped),
        });
        stream.cancel();
        assert!(dropped.load(Ordering::Acquire));
    }
}
