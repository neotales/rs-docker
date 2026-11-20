//! Repository-owned Engine container operations.

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;

use futures_util::stream;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::streams::{OwnedResponse, owned_response};
use super::{ContainerLogFrame, DockerClient, DockerStream, Error};
use crate::raw;

const STREAM_FAILURE: &str = "container stream operation failed; peer text withheld";

pub(crate) fn sanitize_stream_error(error: &Error) -> Error {
    if let Some(api) = error.api_error()
        && let Ok(status) = hyper::StatusCode::from_u16(api.status_code)
    {
        return Error::engine_api_withheld(status, STREAM_FAILURE);
    }
    error.withhold_transport(STREAM_FAILURE, STREAM_FAILURE)
}

impl DockerClient {
    pub(crate) fn container_stream_engine(&self) -> Result<raw::RawEngine, Error> {
        if let Some(gate) = self.managed_ssh_gate() {
            gate?;
        }
        self.raw_engine()
    }
}

/// Options for `GET /containers/json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerListOptions {
    /// Include stopped containers.
    pub all: bool,
    /// Limit the number of returned containers.
    pub limit: Option<i32>,
    /// Ask the daemon to include size fields.
    pub size: bool,
    /// Ordered Engine filters.
    pub filters: BTreeMap<String, Vec<String>>,
}

/// One published or exposed port in a container-list response.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPort {
    /// Host IP address.
    pub ip: Option<String>,
    /// Container port.
    pub private_port: u16,
    /// Published host port.
    pub public_port: Option<u16>,
    /// Transport protocol.
    pub protocol: Option<String>,
}

/// Stable fields used by Docker-compatible container-list output.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummary {
    /// Container ID.
    pub id: Option<String>,
    /// Container names.
    pub names: Option<Vec<String>>,
    /// Image reference used to create the container.
    pub image: Option<String>,
    /// Image ID used to create the container.
    pub image_id: Option<String>,
    /// Quoted command displayed by `ps`.
    pub command: Option<String>,
    /// Creation time as Unix seconds.
    pub created: Option<i64>,
    /// Published and exposed ports.
    pub ports: Vec<ContainerPort>,
    /// Daemon state name.
    pub state: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// User-defined metadata reported by the daemon.
    ///
    pub labels: BTreeMap<String, String>,
}

/// A host port binding for container creation or inspection.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPortBinding {
    /// Host IP address. An empty value asks Docker to choose the default.
    pub host_ip: Option<String>,
    /// Host port.
    pub host_port: Option<String>,
}

/// A normalized published-port mapping.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortMapping {
    /// Container port key such as `80/tcp`.
    pub container_port: String,
    /// Host bindings for the container port.
    pub bindings: Vec<ContainerPortBinding>,
}

/// A host device exposed inside a container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceMapping {
    /// Host path.
    pub path_on_host: String,
    /// Container path.
    pub path_in_container: String,
    /// cgroup permission set.
    pub cgroup_permissions: String,
}

/// A device-driver request such as an NVIDIA GPU allocation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// Device driver name.
    pub driver: Option<String>,
    /// Requested device count.
    pub count: Option<i64>,
    /// Explicit device identifiers.
    pub device_ids: Option<Vec<String>>,
    /// Driver capabilities.
    pub capabilities: Option<Vec<Vec<String>>>,
}

/// A named process limit.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ulimit {
    /// Limit name.
    pub name: String,
    /// Soft limit.
    pub soft: i64,
    /// Hard limit.
    pub hard: i64,
}

/// Restart policy for a newly-created container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// `no`, `always`, `unless-stopped`, or `on-failure`.
    pub name: String,
    /// Maximum retries for `on-failure`.
    pub maximum_retry_count: Option<i64>,
}

/// Container logging configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LogConfig {
    /// Logging driver.
    pub driver: Option<String>,
    /// Driver options.
    pub options: BTreeMap<String, String>,
}

/// Container health-check configuration. Durations are nanoseconds.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Literal test array, such as `CMD-SHELL` plus its command.
    pub test: Option<Vec<String>>,
    /// Check interval.
    pub interval: Option<i64>,
    /// Check timeout.
    pub timeout: Option<i64>,
    /// Consecutive failures before unhealthy.
    pub retries: Option<i64>,
    /// Initialization period.
    pub start_period: Option<i64>,
    /// Check interval during the start period.
    pub start_interval: Option<i64>,
}

/// Host-specific options for a newly-created container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerHostConfig {
    /// Bind mount specifications.
    pub binds: Vec<String>,
    /// Published port mappings.
    pub port_bindings: Vec<PortMapping>,
    /// Initial umask.
    pub umask: Option<String>,
    /// Extended privileges.
    pub privileged: bool,
    /// DNS server addresses.
    pub dns: Vec<String>,
    /// Restart policy.
    pub restart_policy: Option<RestartPolicy>,
    /// Host device mappings.
    pub devices: Vec<DeviceMapping>,
    /// Additional `/etc/hosts` entries.
    pub extra_hosts: Vec<String>,
    /// Added Linux capabilities.
    pub cap_add: Vec<String>,
    /// Dropped Linux capabilities.
    pub cap_drop: Vec<String>,
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// Run an init process.
    pub init: bool,
    /// Size of `/dev/shm` in bytes.
    pub shm_size: Option<i64>,
    /// Stop timeout in seconds.
    pub stop_timeout: Option<i64>,
    /// Temporary filesystem mounts.
    pub tmpfs: BTreeMap<String, String>,
    /// Process limits.
    pub ulimits: Vec<Ulimit>,
    /// Additional groups.
    pub group_add: Vec<String>,
    /// Kernel parameters.
    pub sysctls: BTreeMap<String, String>,
    /// Security options.
    pub security_options: Vec<String>,
    /// DNS search domains.
    pub dns_search: Vec<String>,
    /// Logging configuration.
    pub log_config: Option<LogConfig>,
    /// Network mode or custom network name.
    pub network_mode: Option<String>,
    /// IPC namespace mode.
    pub ipc_mode: Option<String>,
    /// PID namespace mode.
    pub pid_mode: Option<String>,
    /// User namespace mode.
    pub userns_mode: Option<String>,
    /// Available CPU quota in nano-CPUs.
    pub nano_cpus: Option<i64>,
    /// Memory limit in bytes.
    pub memory: Option<i64>,
    /// Memory reservation in bytes.
    pub memory_reservation: Option<i64>,
    /// Maximum process and thread count.
    pub pids_limit: Option<i64>,
    /// Relative CPU weight.
    pub cpu_shares: Option<i64>,
    /// CFS period in microseconds.
    pub cpu_period: Option<i64>,
    /// CFS quota in microseconds.
    pub cpu_quota: Option<i64>,
    /// Allowed CPU set.
    pub cpuset_cpus: Option<String>,
    /// Resolver options.
    pub dns_options: Vec<String>,
    /// UTS namespace mode.
    pub uts_mode: Option<String>,
    /// Containers whose volumes are inherited.
    pub volumes_from: Vec<String>,
    /// Device-driver requests.
    pub device_requests: Vec<DeviceRequest>,
    /// Windows isolation technology.
    pub isolation: Option<String>,
    /// OCI runtime.
    pub runtime: Option<String>,
    /// Disable the out-of-memory killer.
    pub oom_kill_disable: bool,
    /// Out-of-memory score adjustment.
    pub oom_score_adj: Option<i64>,
}

/// The networks a container is attached to when it is created.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerNetworkingConfig {
    /// Endpoint settings keyed by network name or ID.
    pub endpoints: BTreeMap<String, ContainerEndpointSettings>,
}

/// Per-network settings for a container endpoint.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerEndpointSettings {
    /// DNS aliases the container answers to on this network.
    pub aliases: Vec<String>,
    /// Links to other containers on the same network.
    pub links: Vec<String>,
    /// A MAC address to assign to this endpoint.
    pub mac_address: Option<String>,
}

/// Repository-owned `POST /containers/create` body and query values.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainerCreateOptions {
    /// Image reference.
    pub image: String,
    /// Literal command argv.
    pub command: Vec<String>,
    /// Optional entrypoint override. One empty string resets the image entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Environment entries in `NAME=value` form.
    pub environment: Vec<String>,
    /// User-defined labels.
    pub labels: BTreeMap<String, String>,
    /// Exposed container ports, such as `80/tcp`.
    pub exposed_ports: Vec<String>,
    /// Hostname.
    pub hostname: Option<String>,
    /// NIS domain name.
    pub domainname: Option<String>,
    /// MAC address.
    pub mac_address: Option<String>,
    /// User used to run the container.
    pub user: Option<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Stop signal.
    pub stop_signal: Option<String>,
    /// Allocate a pseudo-TTY.
    pub tty: bool,
    /// Keep standard input open.
    pub open_stdin: bool,
    /// Attach standard input.
    pub attach_stdin: bool,
    /// Attach standard output.
    pub attach_stdout: bool,
    /// Attach standard error.
    pub attach_stderr: bool,
    /// Health-check configuration.
    pub healthcheck: Option<HealthConfig>,
    /// Host-specific configuration.
    pub host_config: Option<ContainerHostConfig>,
    /// The networks the container is attached to at creation.
    ///
    /// A container created with `NetworkMode` of `none` can never be attached to
    /// another network, so the networks a Compose service declares have to be
    /// part of the create request. Attaching them afterwards with a separate
    /// connect request works only for a container the daemon is willing to move,
    /// and leaves the declared DNS aliases unapplied in the meantime.
    pub networking_config: Option<ContainerNetworkingConfig>,
    /// Optional container name query value.
    pub name: Option<String>,
    /// Optional target platform query value.
    pub platform: Option<String>,
}

/// Result of `POST /containers/create`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerCreateResult {
    /// Created container ID.
    pub id: String,
    /// Daemon warnings.
    pub warnings: Vec<String>,
}

/// Options for `POST /containers/{id}/start`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerStartOptions {
    /// Optional detach-key sequence.
    pub detach_keys: Option<String>,
}

/// Options for `POST /containers/{id}/stop`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerStopOptions {
    /// Optional signal name or number.
    pub signal: Option<String>,
    /// Seconds to wait before killing the container.
    pub timeout_seconds: Option<i32>,
}

/// Options for `POST /containers/{id}/restart`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerRestartOptions {
    /// Optional signal name or number.
    pub signal: Option<String>,
    /// Seconds to wait before killing the container.
    pub timeout_seconds: Option<i32>,
}

/// Options for `DELETE /containers/{id}`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerRemoveOptions {
    /// Remove anonymous volumes associated with the container.
    pub remove_volumes: bool,
    /// Kill a running container before removing it.
    pub force: bool,
    /// Remove the specified link.
    pub remove_link: bool,
}

/// Options for `POST /containers/prune`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPruneOptions {
    /// Ordered Engine filters such as `until` or `label`.
    pub filters: BTreeMap<String, Vec<String>>,
}

/// Result of a resource-specific container prune.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPruneResult {
    /// IDs of containers removed by this request.
    pub deleted: Vec<String>,
    /// Bytes reclaimed by the daemon.
    pub space_reclaimed: i64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
/// Resource limits to apply to a running container.
///
/// Every field is optional and every `None` is left unchanged, which mirrors the
/// Engine API: the update request is a patch, and omitting a field does not mean
/// "unlimited".
pub struct ContainerUpdateOptions {
    /// Relative CPU weight.
    pub cpu_shares: Option<i64>,
    /// Memory limit in bytes.
    pub memory: Option<i64>,
}

/// Result of a successful resource update.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerUpdateResult {
    /// Warnings returned by API versions that expose them.
    ///
    pub warnings: Vec<String>,
}

/// Options for `POST /containers/{id}/wait`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitOptions {
    /// `not-running` or `removed`.
    pub condition: Option<String>,
}

/// One completed container wait operation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitResult {
    /// Container exit status.
    pub status_code: i64,
    /// Daemon-reported wait error.
    pub error: Option<String>,
}

/// A process list returned by `GET /containers/{id}/top`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerTop {
    /// Column titles.
    pub titles: Vec<String>,
    /// Process rows.
    pub processes: Vec<Vec<String>>,
}

/// One filesystem change returned by `GET /containers/{id}/changes`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemChange {
    /// Absolute path in the container.
    pub path: String,
    /// Docker numeric change kind.
    pub kind: i32,
}

/// Select container-inspect fields needed by attach, port, exit, and readiness
/// handling.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerDetails {
    /// Whether the container has a pseudo-TTY.
    pub tty: bool,
    /// Last process exit code.
    pub exit_code: Option<i64>,
    /// Current status.
    pub status: Option<String>,
    /// Published ports keyed by normalized container port.
    pub ports: BTreeMap<String, Vec<ContainerPortBinding>>,
    /// Docker health status reported by the daemon, lowercased.
    ///
    /// The daemon spells this `healthy`, `unhealthy`, `starting`, or `none`.
    /// The projection is `None` when the container has no health state at all,
    /// which is how a container without a healthcheck appears, so a caller can
    /// tell "no healthcheck" apart from a healthcheck that has not run yet.
    pub health: Option<String>,
    /// Whether the daemon reports the container as running.
    ///
    /// A running container can also be paused, so this is a convenience
    /// projection of `State.Running` rather than a state name. It is `None`
    /// when the daemon omits the field.
    pub running: Option<bool>,
}

/// HEAD metadata for a path downloaded from a container.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerPathStat {
    /// Base name reported by the daemon.
    pub name: String,
    /// File size.
    pub size: i64,
    /// Unix-style file mode.
    pub mode: u32,
    /// Symbolic-link target, when present.
    pub link_target: Option<String>,
}

impl ContainerPathStat {
    /// Whether the path is a directory.
    ///
    /// The type bits are not where a `chmod`-shaped mode would put them, and
    /// getting this wrong is not a detail. Measured against a live daemon, the
    /// `X-Docker-Container-Path-Stat` header reports:
    ///
    /// | path          | reported mode    |
    /// |---------------|------------------|
    /// | a directory   | `2147484141` (`0x800001ED`) |
    /// | a regular file| `420` (`0o644`)  |
    ///
    /// So the low twelve bits are the permissions and the type is carried in the
    /// high bits. A `mode & 0xf000 == 0o4000` test — the obvious one, and the one
    /// this used — reads `0x1ED` there and answers "not a directory", which made
    /// `docker cp ctr:/dir ./dir` treat the directory as a file and
    /// `docker cp local.txt ctr:/existing-dir` overwrite that directory with a
    /// file. The POSIX `S_IFDIR` spelling is accepted too, because a different
    /// daemon or a transport that reshapes the header may use it.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        const S_IFDIR: u32 = 0o040_000;
        const GO_MODE_DIR: u32 = 0x8000_0000;
        self.mode & S_IFDIR == S_IFDIR || self.mode & GO_MODE_DIR != 0
    }
}

/// Caller-owned container archive response.
#[must_use = "a ContainerArchive owns a response and should be consumed or cancelled"]
pub struct ContainerArchive {
    /// Path metadata used to decide extraction semantics.
    pub stat: ContainerPathStat,
    /// Archive byte stream.
    pub stream: DockerStream<Vec<u8>>,
}

impl std::fmt::Debug for ContainerArchive {
    /// Reports the path metadata and the handle, and no archive byte.
    ///
    /// `#[derive(Debug)]` would compile here, because [`DockerStream`]'s own
    /// `Debug` prints no item, and it is tempting for exactly that reason. It is
    /// hand-written anyway: the safety of this rendering would then rest on a
    /// decision taken in another module about another type, and the archive is
    /// the container's filesystem — whatever the caller copied out of it may be
    /// a credential file. The guarantee belongs to the type that owns the
    /// archive, not to the layer below it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerArchive")
            .field("stat", &self.stat)
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl ContainerArchive {
    /// Reads the next archive chunk.
    pub async fn next(&mut self) -> Option<Result<Vec<u8>, Error>> {
        self.stream.next().await
    }

    /// Cancels and releases the response stream.
    pub fn cancel(&mut self) {
        self.stream.cancel();
    }
}

/// Options for `PUT /containers/{id}/archive`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainerArchiveUploadOptions {
    /// Absolute destination directory in the container.
    pub path: String,
    /// Preserve numeric user/group IDs from archive entries.
    pub copy_user_and_group: bool,
    /// Reject directory/non-directory replacement.
    pub no_overwrite_directory_with_file: bool,
}

/// Options for `POST /commit`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitContainerOptions {
    /// Source container ID or name.
    pub container: String,
    /// Target repository.
    pub repository: Option<String>,
    /// Target tag.
    pub tag: Option<String>,
    /// Commit message.
    pub comment: Option<String>,
    /// Commit author.
    pub author: Option<String>,
    /// Pause the container during commit.
    pub pause: bool,
    /// Dockerfile changes. The command parser currently accepts `CMD` and `ENV`.
    pub changes: Vec<String>,
}

/// Options shared by checkpoint create/list/remove operations.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointOptions {
    /// Checkpoint identifier for create/remove.
    pub checkpoint_id: Option<String>,
    /// Custom checkpoint directory.
    pub checkpoint_dir: Option<String>,
    /// Stop the container after checkpoint creation.
    ///
    /// This is the Engine's `Exit`. The default is `false`, which leaves the
    /// container running; the Docker CLI's `checkpoint create` stops it unless
    /// `--leave-running` is given, so a caller porting that behavior must set
    /// this to `true`.
    pub exit: bool,
}

/// One container checkpoint name.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint name.
    pub name: String,
}

/// Options for creating an exec instance.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExecOptions {
    /// Attach standard input.
    pub attach_stdin: bool,
    /// Attach standard output.
    pub attach_stdout: bool,
    /// Attach standard error.
    pub attach_stderr: bool,
    /// Allocate a pseudo-TTY.
    pub tty: bool,
    /// Detach-key sequence.
    pub detach_keys: Option<String>,
    /// Additional environment.
    pub environment: Vec<String>,
    /// Literal command argv.
    pub command: Vec<String>,
    /// Run with extended privileges.
    pub privileged: bool,
    /// User override.
    pub user: Option<String>,
    /// Working directory.
    pub working_dir: Option<String>,
}

/// State returned by `GET /exec/{id}/json`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecState {
    /// Exec instance ID.
    pub id: Option<String>,
    /// Whether the command is still running.
    pub running: bool,
    /// Exit code after completion.
    pub exit_code: Option<i64>,
}

/// Options for `POST /exec/{id}/resize`.
///
/// The daemon only honors these values for an exec instance created with a
/// pseudo-TTY.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecResizeOptions {
    /// Terminal height in characters.
    pub height: u16,
    /// Terminal width in characters.
    pub width: u16,
}

/// Caller-owned write half of an upgraded Engine connection.
pub struct SessionInput {
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    enabled: bool,
}

impl SessionInput {
    fn new(inner: Pin<Box<dyn AsyncWrite + Send>>, enabled: bool) -> Self {
        Self {
            writer: Box::new(inner),
            enabled,
        }
    }

    /// Writes all input bytes to the Engine connection.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error if stdin was not requested, or a Docker
    /// transport error when the upgraded connection fails.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !self.enabled {
            return Err(Error::invalid_input("session stdin was not requested"));
        }
        self.writer
            .write_all(bytes)
            .await
            .map_err(|error| Error::transport_source_withheld(&error, STREAM_FAILURE))
    }

    /// Half-closes the Engine input stream.
    ///
    /// # Errors
    ///
    /// Returns a Docker transport error when the upgraded connection fails.
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.writer
            .shutdown()
            .await
            .map_err(|error| Error::transport_source_withheld(&error, STREAM_FAILURE))
    }
}

impl std::fmt::Debug for SessionInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionInput")
    }
}

/// An attached or exec session that owns both upgraded connection halves.
///
/// Dropping the session releases its output body and input socket. Callers can
/// also cancel output explicitly while retaining the input half if needed.
pub struct AttachedSession {
    output: DockerStream<ContainerLogFrame>,
    input: SessionInput,
}

fn from_raw_log(frame: raw::LogFrame) -> ContainerLogFrame {
    let stream = match frame.stream {
        raw::LogStream::Stdin => super::ContainerLogStream::Stdin,
        raw::LogStream::Stdout => super::ContainerLogStream::Stdout,
        raw::LogStream::Stderr => super::ContainerLogStream::Stderr,
        raw::LogStream::Console => super::ContainerLogStream::Console,
    };
    ContainerLogFrame::new(stream, frame.payload)
}

fn raw_log_reader_stream<R>(mut reader: R, tty: bool) -> DockerStream<ContainerLogFrame>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    DockerStream::spawn(move |mut cancellation, sender| async move {
        let mut decoder = raw::LogDecoder::new(tty);
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            match decoder.decode() {
                Ok(Some(frame)) => {
                    if sender.send(Ok(from_raw_log(frame))).await.is_err() {
                        return;
                    }
                    continue;
                }
                Err(error) => {
                    let _ = sender.send(Err(sanitize_stream_error(&error))).await;
                    return;
                }
                Ok(None) => {}
            }
            let read = tokio::select! {
                _ = &mut cancellation => return,
                result = reader.read(&mut chunk) => result,
            };
            match read {
                Ok(0) => {
                    if let Err(error) = decoder.finish() {
                        let _ = sender.send(Err(error)).await;
                    }
                    return;
                }
                Ok(read) => match decoder.push(&chunk[..read]) {
                    Ok(frames) => {
                        for frame in frames {
                            if sender.send(Ok(from_raw_log(frame))).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                },
                Err(error) => {
                    let failure = Error::transport_source_withheld(&error, STREAM_FAILURE);
                    let _ = sender.send(Err(failure)).await;
                    return;
                }
            }
        }
    })
}

impl std::fmt::Debug for AttachedSession {
    /// Reports both halves by name, and no byte from either.
    ///
    /// The input half is where a caller types into an attached container and the
    /// output half is what the container types back, so a rendering of this value
    /// is a rendering of a live terminal session — including whatever a caller
    /// pasted into it, and whatever the container answered with. `SessionInput`
    /// already prints only its own name for this reason, and the pair keeps that
    /// shape here, where both halves are owned.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachedSession")
            .field("output", &self.output)
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

impl AttachedSession {
    /// Returns the caller-owned output stream.
    #[must_use]
    pub const fn output(&self) -> &DockerStream<ContainerLogFrame> {
        &self.output
    }

    /// Returns the caller-owned output stream for polling.
    pub fn output_mut(&mut self) -> &mut DockerStream<ContainerLogFrame> {
        &mut self.output
    }

    /// Returns the caller-owned input stream.
    pub const fn input_mut(&mut self) -> &mut SessionInput {
        &mut self.input
    }

    /// Cancels output while preserving the input handle.
    pub fn cancel_output(&mut self) {
        self.output.cancel();
    }

    /// Splits the session into its two explicitly owned connection halves.
    pub fn into_parts(self) -> (DockerStream<ContainerLogFrame>, SessionInput) {
        (self.output, self.input)
    }

    /// Drops both connection halves and releases their resources.
    pub fn cancel(self) {}
}

/// Exec sessions use the same upgraded, bidirectional connection contract.
pub type ExecSession = AttachedSession;

impl DockerClient {
    /// Lists containers using the daemon's default options.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>, Error> {
        self.list_containers_with_options(None).await
    }

    /// Lists containers using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or response error.
    pub async fn list_containers_with_options(
        &self,
        options: Option<ContainerListOptions>,
    ) -> Result<Vec<ContainerSummary>, Error> {
        //
        let engine = self.raw_engine()?;
        raw::container_list(&engine, &options.unwrap_or_default()).await
    }

    /// Creates a container without starting it.
    ///
    /// # Errors
    ///
    /// Returns a validation, transport, or response error.
    pub async fn create_container(
        &self,
        options: ContainerCreateOptions,
    ) -> Result<ContainerCreateResult, Error> {
        //
        // This one needed a change in `raw/` before it could move. The owned
        // create body had no `NetworkingConfig` member, so a container created
        // through it was attached to no network — with no alias, no link, and no
        // endpoint MAC address — while the caller had asked for all of them, and
        // nothing said so. `docker compose` sets that member for every service
        // on more than one network, so the shortfall was not a missing
        // convenience: it was a container that could reach nothing, discovered
        // when the service failed its first request. `raw::containers` now
        // carries the member, and this method can finally prefer the owned
        // transport.
        let engine = self.raw_engine()?;
        raw::container_create(&engine, &options).await
    }

    /// Starts a container with daemon defaults.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn start_container(&self, container: &str) -> Result<(), Error> {
        self.start_container_with_options(container, None).await
    }

    /// Starts a container using repository-owned options.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn start_container_with_options(
        &self,
        container: &str,
        options: Option<ContainerStartOptions>,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::container_start(&engine, container, &options.unwrap_or_default()).await
    }

    /// Stops a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn stop_container(
        &self,
        container: &str,
        options: Option<ContainerStopOptions>,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::container_stop(&engine, container, &options.unwrap_or_default()).await
    }

    /// Restarts a container.
    ///
    /// `signal` and `timeout_seconds` mean what they mean on
    /// [`Self::stop_container`]: the signal is sent instead of the daemon's
    /// default, and the timeout bounds the graceful wait. Each is omitted when
    /// unset, so the daemon's own default applies.
    ///
    /// # Interrupted requests
    ///
    /// A dispatched request may still complete after a transport failure; reconcile
    /// the container state before retrying.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn restart_container(
        &self,
        container: &str,
        options: Option<ContainerRestartOptions>,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::container_restart(&engine, container, &options.unwrap_or_default()).await
    }

    /// Removes a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn remove_container(
        &self,
        container: &str,
        options: Option<ContainerRemoveOptions>,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::container_remove(&engine, container, &options.unwrap_or_default()).await
    }

    /// Prunes stopped containers using a resource-specific Engine request.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or Engine API error.
    pub async fn prune_containers(
        &self,
        options: Option<ContainerPruneOptions>,
    ) -> Result<ContainerPruneResult, Error> {
        let engine = self.raw_engine()?;
        raw::prune(&engine, &options.unwrap_or_default()).await
    }

    /// Renames a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn rename_container(&self, container: &str, name: &str) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::rename(&engine, container, name).await
    }

    /// Sends a signal to a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn kill_container(&self, container: &str, signal: Option<&str>) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        return raw::kill(
            &engine,
            container,
            &raw::ContainerKillOptions {
                signal: signal.map(ToOwned::to_owned),
            },
        )
        .await;
    }

    /// Pauses a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn pause_container(&self, container: &str) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::pause(&engine, container).await
    }

    /// Unpauses a container.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn unpause_container(&self, container: &str) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::unpause(&engine, container).await
    }

    /// Opens a caller-owned wait stream.
    ///
    /// The signature is a stream rather than a `Result`, so the owned path
    /// cannot simply `await` here: the request has to be built lazily, at the
    /// first poll, or `wait_container` would open a connection before the caller
    /// asked for one. `stream::once` over an `async` block gives exactly that —
    /// constructing the future performs no I/O, because the body does not run
    /// until the block is polled — and it preserves the laziness the generated
    /// client's own stream had.
    pub fn wait_container(
        &self,
        container: &str,
        options: Option<ContainerWaitOptions>,
    ) -> DockerStream<ContainerWaitResult> {
        let engine = match self.raw_engine() {
            Ok(engine) => engine,
            Err(error) => return DockerStream::new(stream::once(async move { Err(error) })),
        };
        let container = container.to_owned();
        let options = options.unwrap_or_default();
        DockerStream::new(stream::once(async move {
            raw::container_wait(&engine, &container, &options).await
        }))
    }

    /// Updates mutable container resources.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn update_container(
        &self,
        container: &str,
        options: ContainerUpdateOptions,
    ) -> Result<ContainerUpdateResult, Error> {
        //
        let engine = self.raw_engine()?;
        raw::update(&engine, container, &options).await
    }

    /// Returns the raw Engine v1.53 container-inspect object.
    ///
    /// # Errors
    ///
    /// Returns a transport or serialization error.
    pub async fn inspect_container(&self, container: &str) -> Result<serde_json::Value, Error> {
        let engine = self.raw_engine()?;
        Ok(raw::inspect(&engine, container).await?.into_document())
    }

    /// Returns repository-owned container details used by CLI commands.
    ///
    /// The projection carries the daemon health status and running flag, so a
    /// caller can evaluate a readiness condition with one request instead of
    /// re-reading the raw inspect object.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn container_details(&self, container: &str) -> Result<ContainerDetails, Error> {
        let engine = self.raw_engine()?;
        Ok(raw::inspect(&engine, container).await?.details())
    }

    /// Lists processes in a container.
    ///
    /// `process_options` is passed to the container's `ps` as its arguments.
    /// `None` and a whitespace-only value are the same request: no `ps_args`
    /// parameter is sent, so the daemon's own default applies. That is the
    /// daemon's choice, not this client's: Docker on Unix substitutes `-ef`
    /// when the value is omitted or empty. Any other value is sent as the
    /// `ps_args` query value.
    ///
    /// The Engine's `Titles` and `Processes` members are optional. An absent or
    /// `null` member projects to an empty vector, so a container
    /// whose process list is empty is a successful answer.
    ///
    /// # Errors
    ///
    /// Returns a transport, query, or response error.
    pub async fn container_top(
        &self,
        container: &str,
        process_options: Option<&str>,
    ) -> Result<ContainerTop, Error> {
        let engine = self.raw_engine()?;
        raw::container_top(&engine, container, process_options).await
    }

    /// Lists container filesystem changes.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn container_changes(&self, container: &str) -> Result<Vec<FilesystemChange>, Error> {
        let engine = self.raw_engine()?;
        raw::changes(&engine, container).await
    }

    /// Opens a bidirectional container attachment.
    ///
    /// The container's owned inspect is read first to select the decoder mode;
    /// a missing TTY member fails closed instead of guessing. A `101` answer
    /// supplies both session halves. A `200` answer is refused with its status:
    /// it has no writable connection, regardless of the initial stdin option.
    /// Rejections and transport sources are withheld because they can echo
    /// sensitive stream content.
    ///
    /// # Errors
    ///
    /// Returns a transport or HTTP-upgrade error.
    pub async fn attach_container(
        &self,
        container: &str,
        stdin: bool,
        logs: bool,
        detach_keys: Option<&str>,
    ) -> Result<AttachedSession, Error> {
        let engine = self
            .container_stream_engine()
            .map_err(|error| sanitize_stream_error(&error))?;
        let tty = raw::inspect(&engine, container)
            .await
            .map_err(|error| sanitize_stream_error(&error))?
            .tty()
            .ok_or_else(|| Error::transport("container inspect omitted its TTY setting"))?;
        let attached = raw::attach_stream(
            &engine,
            container,
            &raw::ContainerAttachOptions {
                stream: true,
                stdin,
                stdout: true,
                stderr: true,
                logs,
                detach_keys: detach_keys.map(str::to_owned),
            },
        )
        .await
        .map_err(|error| sanitize_stream_error(&error))?;
        match attached {
            raw::AttachedStream::Upgraded { read, write, .. } => Ok(AttachedSession {
                output: raw_log_reader_stream(read, tty),
                input: SessionInput::new(Box::pin(write), stdin),
            }),
            raw::AttachedStream::Streaming { status, .. } => {
                Err(Error::engine_api_withheld(status, STREAM_FAILURE))
            }
        }
    }

    /// Opens an uncompressed container filesystem archive stream.
    ///
    /// The archive is never collected or buffered by the facade; each poll
    /// yields the next transport chunk. Dropping the returned handle, or calling
    /// [`DockerStream::cancel`], drops the response body and closes the
    /// connection, so a caller that stops reading a large export stops the
    /// transfer rather than draining it.
    ///
    /// **Archive integrity is not validated.** The stream reports bytes; it does
    /// not parse the TAR. What is detected is an incomplete HTTP body — a
    /// connection that ends before the declared or chunked framing is complete.
    /// A TAR that is cut short while the HTTP response is complete, such as a
    /// daemon that finishes a `Content-Length` or chunked body after writing
    /// half an archive, is delivered as bytes and ends cleanly. A caller that
    /// needs to know the archive is whole must verify it itself.
    ///
    /// # Errors
    ///
    /// Transport, decoding, or Engine API failures arrive as items on the
    /// returned stream rather than as a return value, which is the contract this
    /// method has always had.
    pub fn export_container(&self, container: &str) -> DockerStream<Vec<u8>> {
        let engine = match self.raw_engine() {
            Ok(engine) => engine,
            Err(error) => return DockerStream::new(stream::once(async move { Err(error) })),
        };
        let container = container.to_owned();
        owned_response(async move {
            Ok(OwnedResponse::Chunks {
                frames: raw::export_container(&engine, &container).await?,
                into_item: |chunk| chunk.to_vec(),
            })
        })
    }

    /// Commits container filesystem changes to an image.
    ///
    /// `POST /commit` carries its container, pause flag, repository, tag,
    /// comment, author, and Dockerfile changes as query parameters and answers
    /// with the id of the image the daemon created.
    ///
    /// The request sends an empty JSON body and always spells `pause`. The
    /// response accepts `Id`, `id`, or `ID`, including an empty id.
    ///
    /// This method does not retry, because a retry may create a second image. A
    /// caller that must not risk a duplicate must reconcile — inspect for the
    /// image — before retrying.
    ///
    /// # Errors
    ///
    /// Returns a transport, Engine API, read, or decode error, or the local refusal of an empty container
    /// reference. No other error establishes whether the image was created; see
    /// above.
    pub async fn commit_container(&self, options: CommitContainerOptions) -> Result<String, Error> {
        let engine = self.raw_engine()?;
        raw::commit_container(&engine, &options).await
    }

    /// Opens a container path archive after fetching its HEAD metadata.
    ///
    /// When the owned transport serves the call:
    ///
    /// - the requests are the versioned `HEAD` and `GET` of
    ///   `/v{major}.{minor}/containers/{id}/archive`;
    /// - the container reference is percent-encoded into exactly one path
    ///   segment and `path` is percent-encoded as one query value, so a
    ///   reference or path containing `/`, `&`, `+`, or a space cannot change
    ///   the request;
    /// - the HEAD metadata comes from `X-Docker-Container-Path-Stat`, standard
    ///   base64 JSON, and an empty `linkTarget` projects to `None`. A missing or malformed header is an
    ///   `ErrorKind::InvalidInput` error rather than an empty stat;
    /// - the HEAD is awaited before this method returns, while the `GET` is
    ///   opened when the returned stream is first polled. A HEAD success
    ///   followed by a GET rejection therefore surfaces as the first stream
    ///   item, and the archive's bytes are never collected by this crate.
    ///
    /// The `path` is passed to the daemon verbatim. Neither this method nor the
    /// owned transport resolves `..`, follows a symlink, or rewrites a trailing
    /// slash, because those spellings have the container's meaning. An empty
    /// reference or path is refused as `ErrorKind::InvalidInput` before a
    /// connection is opened.
    ///
    /// # Errors
    ///
    /// Returns a transport, missing-header, or response error.
    pub async fn container_archive(
        &self,
        container: &str,
        path: &str,
    ) -> Result<ContainerArchive, Error> {
        let engine = self.raw_engine()?;
        let stat = raw::container_archive_stat(&engine, container, path).await?;
        let container = container.to_owned();
        let path = path.to_owned();
        let stream = owned_response(async move {
            Ok(OwnedResponse::Chunks {
                frames: raw::download_container_archive(&engine, &container, &path).await?,
                into_item: |chunk| chunk.to_vec(),
            })
        });
        Ok(ContainerArchive { stat, stream })
    }

    /// Reports what a path inside a container is, without reading it.
    ///
    /// The copy path needs this to tell a destination directory from a
    /// destination *file name*, and the two are not distinguishable from the
    /// local side: `docker cp a.txt web:/tmp/b.txt` and `docker cp a.txt
    /// web:/tmp/existing-dir` differ only in what the container already holds.
    ///
    /// The Engine answers a missing path with 404, which is an answer rather
    /// than a failure: "not there" is exactly what a caller asking whether a
    /// destination exists wants to know. Every other error is returned, because
    /// a caller that cannot tell a missing path from an unreachable daemon
    /// would guess.
    ///
    /// # Errors
    ///
    /// Returns an Engine API or transport error other than a 404 for the path.
    pub async fn container_path_stat(
        &self,
        container: &str,
        path: &str,
    ) -> Result<Option<ContainerPathStat>, Error> {
        let engine = self.raw_engine()?;
        match raw::container_archive_stat(&engine, container, path).await {
            Ok(stat) => Ok(Some(stat)),
            Err(error) if error.api_error().is_some_and(|api| api.status_code == 404) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Streams an archive file into a container path.
    ///
    /// On the owned path the request is the versioned
    /// `PUT /v{major}.{minor}/containers/{id}/archive`, the reference is one
    /// escaped path segment, and `path` is one percent-encoded query value. The file is
    /// sent as a chunked `application/x-tar` body with no `Content-Length` and
    /// is never buffered whole. `copyUIDGID` is always written as `1` or `0`
    /// and `noOverwriteDirNonDir` only when requested.
    ///
    /// The `path` is passed to the daemon verbatim: this method does not
    /// resolve `..`, follow a symlink, or rewrite a trailing slash. Those
    /// spellings have the container's meaning, and the daemon resolves them
    /// when it extracts the archive.
    ///
    /// # Cancellation and unknown effects
    ///
    /// The file handle is owned by the request body and is dropped only after
    /// upload completion, cancellation, or a source error. The daemon extracts
    /// entries as it reads them, so dropping this future or failing to finish
    /// the body can leave the container's filesystem partially updated. There
    /// is no rollback and no completion guarantee; a caller that retries must
    /// reconcile the destination first.
    ///
    /// # Errors
    ///
    /// Returns a file-open, transport, or Engine API error. A bad archive is a
    /// `400`, a read-only filesystem a `403`, and a missing container or path a
    /// `404`, with the daemon's message in [`Error::api_error`].
    pub async fn upload_container_archive(
        &self,
        container: &str,
        archive_path: &Path,
        options: ContainerArchiveUploadOptions,
    ) -> Result<(), Error> {
        let file = tokio::fs::File::open(archive_path).await.map_err(|error| {
            Error::invalid_input(format!(
                "failed to open copy archive '{}': {error}",
                archive_path.display()
            ))
        })?;
        let bytes = stream::unfold(Some(file), |state| async move {
            let mut file = state?;
            let mut buffer = vec![0_u8; 64 * 1024];
            match file.read(&mut buffer).await {
                Ok(0) => None,
                Ok(read) => {
                    buffer.truncate(read);
                    Some((Ok(buffer.into()), Some(file)))
                }
                Err(error) => Some((Err(error), None)),
            }
        });
        let engine = self.raw_engine()?;
        raw::upload_container_archive(&engine, container, bytes, &options).await
    }

    /// Creates a container checkpoint.
    ///
    /// When the owned transport serves the call:
    ///
    /// - the request is the versioned
    ///   `POST /v1.NN/containers/{id}/checkpoints`, with the container reference
    ///   percent-encoded into exactly one path segment;
    /// - `checkpoint_id` and `checkpoint_dir` travel in the body as
    ///   `CheckpointID` and `CheckpointDir`, and `exit` as `Exit`;
    /// - an absent or empty `checkpoint_dir` is omitted, which selects the
    ///   container's configured checkpoint directory, and an empty
    ///   `checkpoint_id` is refused as `ErrorKind::InvalidInput` before a
    ///   connection is opened;
    /// - the `201` answer carries no body, so the status is the whole result.
    ///
    /// Creation asks the container's runtime to dump a live process tree, which
    /// can take longer than the transport's response-head budget, so the owned
    /// path does not impose a response-head deadline on a Unix socket, direct
    /// plain HTTP, SSH, or a caller-supplied stream. The plain-HTTP proxy route's
    /// 120-second overall request budget still applies, and HTTPS keeps its
    /// establishment budget. Dropping the future or exceeding a budget leaves the
    /// outcome unknown: the checkpoint may already exist.
    ///
    /// A list is a snapshot and cannot prove that a create which was dispatched
    /// and then lost has settled, so it does not make a retry safe. Retrying
    /// safely requires coordination outside this API — one owner serializing
    /// checkpoint operations and a record that the request settled — and a
    /// container recreated under the same name makes a name-based list describe a
    /// different container. See [`Self::list_checkpoints`].
    ///
    /// The checkpoint routes are registered by the daemon as experimental, and
    /// creation needs CRIU on Linux. A daemon without experimental features does
    /// not serve the route, and a runtime that cannot checkpoint reports the
    /// operation as not implemented; both are the daemon's own status and
    /// message in [`Error::api_error`].
    ///
    /// # Errors
    ///
    /// Returns a transport or daemon-capability error when checkpointing is not
    /// enabled by the daemon, and `ErrorKind::InvalidInput` for an empty
    /// container reference or checkpoint identifier on the owned path.
    pub async fn create_checkpoint(
        &self,
        container: &str,
        options: CheckpointOptions,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::checkpoint_create(&engine, container, &options).await
    }

    /// Lists checkpoints for a container.
    ///
    /// The answer is a snapshot, not a retry proof. A create or remove that was
    /// dispatched and then lost may still be in flight, so the list cannot show
    /// that it settled; retrying safely requires coordination outside this API.
    /// A container recreated under the same name between dispatch and
    /// reconciliation is a different container to a name-based list, and the
    /// recreated container may own different checkpoints.
    ///
    /// # Errors
    ///
    /// Returns a transport, response, or daemon-capability error.
    pub async fn list_checkpoints(
        &self,
        container: &str,
        checkpoint_dir: Option<&str>,
    ) -> Result<Vec<Checkpoint>, Error> {
        let engine = self.raw_engine()?;
        raw::checkpoint_list(&engine, container, checkpoint_dir).await
    }

    /// Removes a container checkpoint.
    ///
    /// When the owned transport serves the call:
    ///
    /// - the request is the versioned
    ///   `DELETE /v1.NN/containers/{id}/checkpoints/{checkpoint}`, with both the
    ///   container reference and the checkpoint identifier percent-encoded into
    ///   one path segment each;
    /// - an absent or empty `checkpoint_dir` is omitted from the `dir` query,
    ///   which selects the container's configured directory;
    /// - an empty container reference or checkpoint identifier is refused as
    ///   `ErrorKind::InvalidInput` before a connection is opened — an empty
    ///   identifier would spell the list route, not a delete;
    /// - the `204` answer carries no body, so the status is the whole result.
    ///
    /// A removal that was dispatched and then lost may still be in flight, and a
    /// list cannot show that it settled. Retrying safely requires coordination
    /// outside this API; a container recreated under the same name may own
    /// different checkpoints, so a name-based reconciliation is not proof.
    ///
    /// # Errors
    ///
    /// Returns a transport or daemon-capability error.
    pub async fn remove_checkpoint(
        &self,
        container: &str,
        checkpoint: &str,
        checkpoint_dir: Option<&str>,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::checkpoint_remove(&engine, container, checkpoint, checkpoint_dir).await
    }

    ///
    /// # Errors
    ///
    /// Returns a transport, HTTP-upgrade, or response error.
    pub async fn start_exec(
        &self,
        container: &str,
        options: ExecOptions,
    ) -> Result<(String, ExecSession), Error> {
        let engine = self
            .container_stream_engine()
            .map_err(|error| sanitize_stream_error(&error))?;
        let tty = options.tty;
        let created = raw::exec_create(&engine, container, &options)
            .await
            .map_err(|error| sanitize_stream_error(&error))?;
        let session = raw::exec_start_session(
            &engine,
            &created.id,
            &raw::ExecStartOptions { detach: false, tty },
        )
        .await
        .map_err(|error| sanitize_stream_error(&error))?;
        let (read, write) = session.into_connection();
        Ok((
            created.id,
            AttachedSession {
                output: raw_log_reader_stream(read, tty),
                input: SessionInput::new(Box::pin(write), options.attach_stdin),
            },
        ))
    }

    /// Reads exec state after an attached session ends.
    ///
    /// # Errors
    ///
    /// Returns a transport or response error.
    pub async fn exec_state(&self, exec_id: &str) -> Result<ExecState, Error> {
        let engine = self.raw_engine()?;
        Ok(raw::exec_inspect(&engine, exec_id).await?.state())
    }

    /// Resizes the pseudo-TTY of an exec instance.
    ///
    /// The daemon ignores the request when the exec instance was created
    /// without `tty`.
    ///
    /// # Errors
    ///
    /// Returns a transport or Engine API error.
    pub async fn resize_exec(
        &self,
        exec_id: &str,
        options: ExecResizeOptions,
    ) -> Result<(), Error> {
        let engine = self.raw_engine()?;
        raw::exec_resize(&engine, exec_id, &options).await
    }
}
