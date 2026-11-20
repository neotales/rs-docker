//! Explicit, opt-in `BuildKit` build route. Classic builds remain unchanged.

use crate::{
    DockerClient,
    raw::{RawEngine, buildkit_context, buildkit_grpc, session},
};
use std::{
    collections::BTreeMap,
    fmt,
    path::{Component, PathBuf},
    sync::Arc,
};
use zeroize::Zeroize;

/// Explicit SSH agent source for a `BuildKit` session.
pub enum SshForward {
    /// Forward to this Unix-domain agent socket, never an ambient socket.
    Socket(PathBuf),
    /// Serve these explicit signers using a read-only agent.
    /// Supported Ed25519 and RSA private keys wipe their secret material on drop.
    Key(Vec<neotales_ssh::auth::PublicKeySigner>),
}

impl fmt::Debug for SshForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SshForward(<withheld>)")
    }
}

/// Inputs for the explicit `BuildKit` build route.
#[derive(Default)]
pub struct BuildKitBuildOptions {
    /// Directory snapshotted as the local context, or a single Dockerfile.
    pub context: PathBuf,
    /// Dockerfile path within the context.
    pub dockerfile: String,
    /// Image name for the Engine exporter.
    pub image: String,
    /// Push the exported image to its registry instead of loading it locally.
    pub push: bool,
    /// Image exporter compression algorithm.
    pub compression: Option<String>,
    /// Whether the image exporter should use OCI media types.
    pub oci_mediatypes: Option<bool>,
    /// Frontend build arguments.
    pub build_args: BTreeMap<String, String>,
    /// Optional target stage.
    pub target: Option<String>,
    /// Explicitly supplied secret IDs and bytes.
    pub secrets: BTreeMap<String, Vec<u8>>,
    /// Explicit SSH agent IDs and sources.
    pub ssh: BTreeMap<String, SshForward>,
    /// Registry cache import specifications.
    pub cache_from: Vec<String>,
    /// Cache export specifications.
    pub cache_to: Vec<String>,
}

impl fmt::Debug for BuildKitBuildOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BuildKitBuildOptions")
            .field("context", &"<withheld>")
            .field("dockerfile", &"<withheld>")
            .field("image", &"<withheld>")
            .field("push", &self.push)
            .field("compression", &self.compression)
            .field("oci_mediatypes", &self.oci_mediatypes)
            .field("build_args", &"<withheld>")
            .field("target", &"<withheld>")
            .field("secrets", &"<withheld>")
            .field("ssh", &"<withheld>")
            .field("cache_from", &"<withheld>")
            .field("cache_to", &"<withheld>")
            .finish()
    }
}

/// Parse a registry cache entry. Unsupported cache types are returned by name;
/// invalid cache mode returns `mode`, and other invalid attributes return an empty string.
///
/// # Errors
/// Returns the unsupported type or an empty string for malformed attributes.
pub fn parse_registry_cache(value: &str) -> Result<String, String> {
    parse_registry_cache_entry(value).map(|(reference, _)| reference)
}

/// Validate a cache specification for the Engine `BuildKit` route.
///
/// # Errors
/// Returns the unsupported cache type or a bounded validation category.
pub fn validate_buildkit_cache(value: &str) -> Result<(), String> {
    cache_entry(value, true, false).map(|_| ())
}

fn cache_entry(
    value: &str,
    export: bool,
    apply_defaults: bool,
) -> Result<neotales_docker_buildkit::proto::CacheOptionsEntry, String> {
    let kind = value
        .split(',')
        .find_map(|part| part.strip_prefix("type="))
        .unwrap_or("registry");
    if kind == "registry" {
        let (reference, mode) = parse_registry_cache_entry(value)?;
        let mut attrs = BTreeMap::from([("ref".into(), reference)]);
        if export && let Some(mode) = mode {
            attrs.insert("mode".into(), mode);
        }
        return Ok(neotales_docker_buildkit::proto::CacheOptionsEntry {
            kind: kind.into(),
            attrs,
        });
    }
    if !matches!(kind, "gha" | "s3") {
        return Err(kind.to_owned());
    }
    let mut attrs = BTreeMap::new();
    let mut saw_type = false;
    for part in value.split(',') {
        let (key, val) = part.split_once('=').ok_or_else(String::new)?;
        if key == "type" {
            if saw_type || val != kind {
                return Err(String::new());
            }
            saw_type = true;
        } else if key.is_empty()
            || val.is_empty()
            || attrs.insert(key.to_owned(), val.to_owned()).is_some()
        {
            return Err(String::new());
        }
    }
    // Buildx supplies these client environment defaults to BuildKit's daemon.
    // Explicit attributes always win. Never include their values in diagnostics.
    let defaults: &[(&str, &str)] = if kind == "gha" {
        &[
            ("token", "ACTIONS_RUNTIME_TOKEN"),
            ("url", "ACTIONS_CACHE_URL"),
            ("url_v2", "ACTIONS_RESULTS_URL"),
        ]
    } else {
        &[
            ("bucket", "AWS_BUCKET"),
            ("region", "AWS_REGION"),
            ("access_key_id", "AWS_ACCESS_KEY_ID"),
            ("secret_access_key", "AWS_SECRET_ACCESS_KEY"),
            ("session_token", "AWS_SESSION_TOKEN"),
        ]
    };
    for (key, env) in defaults.iter().filter(|_| apply_defaults) {
        if !attrs.contains_key(*key)
            && let Ok(value) = std::env::var(env)
            && !value.is_empty()
        {
            attrs.insert((*key).to_owned(), value);
        }
    }
    Ok(neotales_docker_buildkit::proto::CacheOptionsEntry {
        kind: kind.into(),
        attrs,
    })
}

fn parse_registry_cache_entry(value: &str) -> Result<(String, Option<String>), String> {
    if !value.contains('=') {
        return if value.is_empty() {
            Err(String::new())
        } else {
            Ok((value.to_owned(), None))
        };
    }
    let mut kind = "registry";
    let mut reference = None;
    let mut mode = None;
    let mut unknown = false;
    for part in value.split(',') {
        let (key, val) = part.split_once('=').ok_or_else(String::new)?;
        match key {
            "type" => kind = val,
            "ref" if reference.is_none() && !val.is_empty() => reference = Some(val),
            "mode" if mode.is_none() && matches!(val, "min" | "max") => mode = Some(val),
            "mode" => return Err("mode".into()),
            _ => unknown = true,
        }
    }
    if kind != "registry" {
        return Err(kind.to_owned());
    }
    if unknown {
        return Err(String::new());
    }
    reference
        .map(|reference| (reference.to_owned(), mode.map(str::to_owned)))
        .ok_or_else(String::new)
}

impl Drop for BuildKitBuildOptions {
    fn drop(&mut self) {
        for value in self.secrets.values_mut() {
            value.zeroize();
        }
        for value in self.cache_from.iter_mut().chain(&mut self.cache_to) {
            value.zeroize();
        }
    }
}

fn ssh_registry(
    sources: BTreeMap<String, SshForward>,
) -> Result<session::SshRegistry, BuildKitBuildError> {
    let mut forwards = BTreeMap::new();
    for (id, source) in sources {
        if id.is_empty()
            || id.len() > 256
            || id.chars().any(char::is_control)
            || forwards.len() >= 128
        {
            return Err(BuildKitBuildError::InvalidInput);
        }
        let source = match source {
            SshForward::Socket(path) => session::SshForward::Socket(path),
            SshForward::Key(signers) => session::SshForward::Key(std::sync::Mutex::new(
                neotales_ssh::agent_server::AgentServer::from_signers(signers)
                    .map_err(|_| BuildKitBuildError::InvalidInput)?,
            )),
        };
        forwards.insert(id, source);
    }
    Ok(session::SshRegistry::new(forwards))
}

/// A single solver vertex update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildKitProgress {
    /// Display name supplied by the builder.
    pub name: String,
    /// Whether this vertex was cached.
    pub cached: bool,
    /// Whether this vertex reported an error.
    pub failed: bool,
}

/// A bounded `BuildKit` build failure. Peer-provided text is withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildKitBuildError {
    /// Input was invalid or unsafe.
    InvalidInput,
    /// The local context could not be snapshotted safely.
    Context,
    /// A requested feature is not supported by this build path.
    Unsupported,
    /// An exporter option has an unsupported value.
    UnsupportedOption(&'static str),
    /// Local cache needs the session content store, not filesync.
    LocalCacheContentStore,
    /// The Engine connection failed.
    Transport,
    /// A configured request deadline elapsed.
    Timeout,
    /// A malformed response was received.
    Protocol,
    /// A configured wire bound was exceeded.
    Oversized,
    /// The builder returned a nonzero gRPC status, without its message.
    Status(u32),
    /// The builder requested an SSH agent ID which was not supplied.
    MissingSshAgent(String),
}

impl fmt::Display for BuildKitBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::LocalCacheContentStore {
            f.write_str("BuildKit cache type local requires the session content store service; filesync is insufficient")
        } else {
            write!(f, "BuildKit build error: {self:?}")
        }
    }
}
impl std::error::Error for BuildKitBuildError {}

fn parse_cache_entries(
    values: &[String],
    export: bool,
) -> Result<Vec<neotales_docker_buildkit::proto::CacheOptionsEntry>, BuildKitBuildError> {
    values
        .iter()
        .map(|value| {
            cache_entry(value, export, true).map_err(|kind| {
                if kind == "local" {
                    BuildKitBuildError::LocalCacheContentStore
                } else {
                    BuildKitBuildError::Unsupported
                }
            })
        })
        .collect()
}

impl From<buildkit_grpc::RpcError> for BuildKitBuildError {
    fn from(value: buildkit_grpc::RpcError) -> Self {
        match value {
            buildkit_grpc::RpcError::Transport => Self::Transport,
            buildkit_grpc::RpcError::Timeout => Self::Timeout,
            buildkit_grpc::RpcError::Protocol => Self::Protocol,
            buildkit_grpc::RpcError::Oversized => Self::Oversized,
            buildkit_grpc::RpcError::Status(code) => Self::Status(code),
            buildkit_grpc::RpcError::Unsupported(_) => Self::Unsupported,
        }
    }
}

// Fields drop in declaration order. Neither future borrows the session, so
// cancellation closes the session before the solve and status connections.
struct BuildWork<S, U> {
    _session: buildkit_grpc::BuildSession,
    solve: S,
    updates: U,
}

/// Resolved frontend, exporter, and cache inputs for one solve request.
struct SolveRequest {
    attrs: BTreeMap<String, String>,
    exporter: neotales_docker_buildkit::proto::Exporter,
    cache: neotales_docker_buildkit::proto::CacheOptions,
}

/// Validate exporter and path options, returning the normalized Dockerfile path.
fn validate_options(options: &BuildKitBuildOptions) -> Result<PathBuf, BuildKitBuildError> {
    if options
        .compression
        .as_deref()
        .is_some_and(|value| !matches!(value, "gzip" | "zstd" | "uncompressed" | "estargz"))
    {
        return Err(BuildKitBuildError::UnsupportedOption("compression"));
    }
    let normalized = normalize_dockerfile(&options.dockerfile)?;
    if options.image.is_empty() || normalized.as_os_str().is_empty() {
        return Err(BuildKitBuildError::InvalidInput);
    }
    Ok(normalized)
}

fn normalize_dockerfile(dockerfile: &str) -> Result<PathBuf, BuildKitBuildError> {
    let mut normalized = PathBuf::new();
    for part in std::path::Path::new(dockerfile).components() {
        match part {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            _ => return Err(BuildKitBuildError::InvalidInput),
        }
    }
    Ok(normalized)
}

fn cache_options(
    options: &BuildKitBuildOptions,
) -> Result<neotales_docker_buildkit::proto::CacheOptions, BuildKitBuildError> {
    Ok(neotales_docker_buildkit::proto::CacheOptions {
        imports: parse_cache_entries(&options.cache_from, false)?,
        exports: parse_cache_entries(&options.cache_to, true)?,
    })
}

fn context_snapshot(
    options: &BuildKitBuildOptions,
) -> Result<buildkit_context::Snapshot, BuildKitBuildError> {
    let snapshot = buildkit_context::snapshot(&options.context, std::path::Path::new(""))
        .or_else(|_| buildkit_context::single_file(&options.context, &options.dockerfile))
        .map_err(|_| BuildKitBuildError::Context)?;
    refuse_unsafe_ignore_files(&snapshot, &options.dockerfile)?;
    Ok(snapshot)
}

fn refuse_unsafe_ignore_files(
    snapshot: &buildkit_context::Snapshot,
    dockerfile: &str,
) -> Result<(), BuildKitBuildError> {
    let specific = format!("{dockerfile}.dockerignore");
    for entry in &snapshot.entries {
        if (entry.stat.path == ".dockerignore" || entry.stat.path == specific)
            && let Some(bytes) = &entry.data
            && (bytes.len() > 64 * 1024 || std::str::from_utf8(bytes).is_err())
        {
            return Err(BuildKitBuildError::InvalidInput);
        }
    }
    Ok(())
}

/// Register the caller's secrets and SSH forwards, then open the build session.
async fn open_session(
    engine: &RawEngine,
    options: &mut BuildKitBuildOptions,
    context: buildkit_context::Snapshot,
) -> Result<(buildkit_grpc::BuildSession, Arc<session::SshRegistry>), BuildKitBuildError> {
    let secrets = session::Secrets::new(std::mem::take(&mut options.secrets))
        .map_err(|_| BuildKitBuildError::InvalidInput)?;
    let ssh = Arc::new(ssh_registry(std::mem::take(&mut options.ssh))?);
    let session = buildkit_grpc::BuildSession::open(
        engine,
        Some(Arc::new(secrets)),
        Some(Arc::new(context)),
        Some(ssh.clone()),
    )
    .await?;
    Ok((session, ssh))
}

fn frontend_attrs(options: &BuildKitBuildOptions) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::from([
        ("context".to_owned(), ".".to_owned()),
        ("filename".to_owned(), options.dockerfile.clone()),
    ]);
    for (key, value) in &options.build_args {
        attrs.insert(format!("build-arg:{key}"), value.clone());
    }
    if let Some(target) = &options.target {
        attrs.insert("target".to_owned(), target.clone());
    }
    attrs
}

fn image_exporter(options: &BuildKitBuildOptions) -> neotales_docker_buildkit::proto::Exporter {
    let mut attrs = BTreeMap::from([("name".into(), options.image.clone())]);
    if options.push {
        attrs.insert("push".into(), "true".into());
    }
    if let Some(compression) = &options.compression {
        attrs.insert("compression".into(), compression.clone());
    }
    if let Some(oci_mediatypes) = options.oci_mediatypes {
        attrs.insert("oci-mediatypes".into(), oci_mediatypes.to_string());
    }
    neotales_docker_buildkit::proto::Exporter {
        kind: if options.push { "image" } else { "moby" }.into(),
        attrs,
    }
}

async fn pump_progress(
    engine: &RawEngine,
    session_id: &str,
    mut progress: impl FnMut(BuildKitProgress),
) -> Result<(), buildkit_grpc::RpcError> {
    let mut stream = buildkit_grpc::status_stream_for(engine, session_id).await?;
    while let Some(status) = stream.next_status().await? {
        for vertex in status.vertexes {
            progress(BuildKitProgress {
                name: vertex.name,
                cached: vertex.cached,
                failed: !vertex.error.is_empty(),
            });
        }
    }
    Ok(())
}

async fn run_solve(
    engine: &RawEngine,
    session: buildkit_grpc::BuildSession,
    request: SolveRequest,
    ssh: &session::SshRegistry,
    progress: impl FnMut(BuildKitProgress),
) -> Result<String, BuildKitBuildError> {
    let id = session.id.clone();
    let solve = buildkit_grpc::solve_with_exporter(
        engine,
        &id,
        request.attrs,
        vec![request.exporter],
        request.cache,
    );
    let updates = pump_progress(engine, &id, progress);
    let mut work = BuildWork {
        _session: session,
        solve: Box::pin(solve),
        updates: Box::pin(updates),
    };
    let response = tokio::select! {
        result = &mut work.solve => result,
        result = &mut work.updates => {
            match result {
                Ok(()) => work.solve.as_mut().await,
                Err(error) => Err(error),
            }
        }
    };
    if let Some(id) = ssh.missing() {
        return Err(BuildKitBuildError::MissingSshAgent(id));
    }
    let response = response?;
    response
        .exporter_response
        .get("containerimage.digest")
        .cloned()
        .ok_or(BuildKitBuildError::Protocol)
}

impl DockerClient {
    /// Build from a local directory or a single Dockerfile using the Engine's `BuildKit` session.
    ///
    /// This is explicitly selected; the classic build route never falls back
    /// to it. The Dockerfile frontend reads ignore files through the bounded
    /// session snapshot and supplies the resulting patterns to filesync.
    /// Absolute or parent-escaping filter patterns, glob patterns with a bare
    /// `^`, and backslash-escaped `followpaths` are refused. Symlinks and special files
    /// in the context are refused.
    ///
    /// # Errors
    /// Returns a typed error for unsafe input, unsupported features, transport
    /// failures, malformed replies, and nonzero builder status.
    pub async fn build_image_buildkit(
        &self,
        mut options: BuildKitBuildOptions,
        progress: impl FnMut(BuildKitProgress),
    ) -> Result<String, BuildKitBuildError> {
        let normalized = validate_options(&options)?;
        let cache = cache_options(&options)?;
        options.dockerfile = normalized
            .to_str()
            .ok_or(BuildKitBuildError::InvalidInput)?
            .to_owned();
        let context = context_snapshot(&options)?;
        let engine = self
            .raw_engine()
            .map_err(|_| BuildKitBuildError::Transport)?;
        let (session, ssh) = open_session(&engine, &mut options, context).await?;
        let request = SolveRequest {
            attrs: frontend_attrs(&options),
            exporter: image_exporter(&options),
            cache,
        };
        run_solve(&engine, session, request, &ssh, progress).await
    }
}

#[cfg(test)]
#[path = "buildkit_registry_test.rs"]
mod registry_test;

#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore = "opt-in: requires a BuildKit-enabled Docker daemon and network"]
    async fn live_buildkit_ssh_key_and_missing() {
        use super::*;
        session::check_missing_default_for_test().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"),
            b"FROM alpine:3.21.3\nARG CACHEBUST\nRUN --mount=type=ssh apk add --no-cache openssh-client && ssh-add -L\n").unwrap();
        let image = format!("neotales-buildkit-ssh:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        let options = |ssh| BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            ssh,
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::from([("CACHEBUST".into(), nonce.clone())]),
            target: None,
            secrets: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let negative = client
            .build_image_buildkit(options(BTreeMap::new()), |_| {})
            .await;
        println!("SSH NEGATIVE: {}", negative.as_ref().unwrap_err());
        assert_eq!(
            negative,
            Err(BuildKitBuildError::MissingSshAgent("default".into()))
        );
        let signer = neotales_ssh::auth::PublicKeySigner::ed25519(
            neotales_ssh::hostkey::Ed25519Signer::from_seed(&mut [81; 32]),
        );
        let result = client
            .build_image_buildkit(
                options(BTreeMap::from([(
                    "default".into(),
                    SshForward::Key(vec![signer]),
                )])),
                |_| {},
            )
            .await;
        let id = result.expect("key-backed SSH build");
        println!("SSH IMAGE ID: {id}");
        let _ = client.remove_image(&image, None).await;
    }
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn invalid_compression_is_refused_before_context_or_dispatch() {
        let client = DockerClient::connect_local().unwrap();
        let mut options = BuildKitBuildOptions::default();
        options.compression = Some("invalid".into());
        assert_eq!(
            client.build_image_buildkit(options, |_| {}).await,
            Err(BuildKitBuildError::UnsupportedOption("compression"))
        );
    }

    #[tokio::test]
    #[ignore = "requires explicit local Docker BuildKit opt-in"]
    async fn live_export_zstd() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Dockerfile"),
            b"FROM scratch\nCOPY payload /payload\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("payload"), b"zstd exporter test\n").unwrap();
        let image = format!("neotales-buildkit-zstd:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let mut options = BuildKitBuildOptions::default();
        options.context = dir.path().into();
        options.dockerfile = "Dockerfile".into();
        options.image = image.clone();
        options.compression = Some("zstd".into());
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options, |_| {}),
        )
        .await;
        let inspect = if matches!(result, Ok(Ok(_))) {
            Some(client.inspect_image(&image).await)
        } else {
            None
        };
        let _ = client.remove_image(&image, None).await;
        let id = result.expect("build deadline").expect("zstd build");
        assert_eq!(inspect.unwrap().unwrap().id, id);
    }

    #[test]
    fn registry_cache_specs_require_supported_types_and_attributes() {
        assert_eq!(parse_registry_cache("app:cache"), Ok("app:cache".into()));
        assert_eq!(
            parse_registry_cache("ref=app:cache,type=registry"),
            Ok("app:cache".into())
        );
        assert_eq!(
            parse_registry_cache("type=gha,scope=app"),
            Err("gha".into())
        );
        assert_eq!(
            parse_registry_cache("type=registry,ref=app:cache,mode=max"),
            Ok("app:cache".into())
        );
        assert_eq!(
            parse_registry_cache("ref=app,mode=whatever"),
            Err("mode".into())
        );
        let spec = vec!["type=registry,ref=app,mode=max".into()];
        assert_eq!(
            parse_cache_entries(&spec, true).unwrap()[0].attrs["mode"],
            "max"
        );
        assert!(
            !parse_cache_entries(&spec, false).unwrap()[0]
                .attrs
                .contains_key("mode")
        );
    }

    #[test]
    fn remote_cache_attributes_are_forwarded_and_local_is_typed() {
        for value in [
            "type=s3,bucket=test,region=example,endpoint_url=http://localhost",
            "type=gha,scope=test,url=https://example.invalid,token=fixture",
        ] {
            let entry = parse_cache_entries(&[value.into()], true)
                .unwrap()
                .remove(0);
            assert_eq!(
                entry.kind,
                if value.contains("type=s3") {
                    "s3"
                } else {
                    "gha"
                }
            );
            assert!(!entry.attrs.contains_key("type"));
            assert!(!format!("{entry:?}").contains("fixture"));
        }
        assert_eq!(
            parse_cache_entries(&["type=local,dest=cache".into()], true).unwrap_err(),
            BuildKitBuildError::LocalCacheContentStore
        );
        assert!(validate_buildkit_cache("type=s3,bucket=a,bucket=b").is_err());
    }

    #[tokio::test]
    #[ignore = "requires Docker, registry:2, and explicit BuildKit opt-in"]
    async fn live_registry_cache_roundtrip() {
        let mut registry = super::registry_test::Registry::start();
        let dir = tempfile::tempdir().unwrap();
        let dockerfile = dir.path().join("Dockerfile");
        std::fs::write(
            &dockerfile,
            b"FROM alpine:3.21.3\nRUN echo cache-proof > /cache-proof\nENV CHANGE=first\n",
        )
        .unwrap();
        let image = registry.image_tag.clone();
        let reference = format!("127.0.0.1:{}/neotales-cache-test:cache", registry.port);
        let client = DockerClient::connect_local().unwrap();
        let options = |cache_from: Vec<String>, cache_to: Vec<String>| BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            cache_from,
            cache_to,
            build_args: BTreeMap::new(),
            target: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
        };
        let result = async {
            let first_id = client
                .build_image_buildkit(
                    options(
                        vec![],
                        vec![format!("type=registry,ref={reference},mode=max")],
                    ),
                    |_| {},
                )
                .await?;
            println!("FIRST IMAGE ID: {first_id}");
            registry.image_ids.push(first_id);
            registry.assert_manifest_put();
            let status = registry.request("HEAD", "/v2/neotales-cache-test/manifests/cache");
            assert_eq!(
                status,
                Some(200),
                "registry cache manifest HEAD must succeed"
            );
            println!("REGISTRY EVIDENCE: HEAD cache manifest 200");
            std::fs::write(
                &dockerfile,
                b"FROM alpine:3.21.3\nRUN echo cache-proof > /cache-proof\nENV CHANGE=second\n",
            )
            .unwrap();
            let mut cached = Vec::new();
            let second_id = client
                .build_image_buildkit(
                    options(
                        vec![format!("type=registry,ref={reference},mode=max")],
                        vec![],
                    ),
                    |p| {
                        if p.cached {
                            cached.push(p.name);
                        }
                    },
                )
                .await?;
            println!("SECOND IMAGE ID: {second_id}");
            registry.image_ids.push(second_id);
            let mut push = options(vec![], vec![]);
            push.image = reference;
            push.push = true;
            client.build_image_buildkit(push, |_| {}).await?;
            Ok::<_, BuildKitBuildError>(cached)
        }
        .await;
        let cached = result.expect("registry cache roundtrip");
        assert!(!cached.is_empty(), "no cached vertex");
        for name in cached {
            println!("CACHED VERTEX: {name}");
        }
        registry.finish();
    }

    // The context snapshot this refuses is Linux-only: it pins the tree with
    // `openat2` and reads entries back through procfs, and every other platform
    // gets `ContextError::Unsupported`. Without the cfg the test asserts a
    // Linux `InvalidInput` against a non-Linux `Context` refusal.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn oversized_ignore_files_are_refused_before_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), b"FROM scratch\n").unwrap();
        std::fs::write(dir.path().join(".dockerignore"), vec![b'x'; 64 * 1024 + 1]).unwrap();
        let options = BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: "test:local".into(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::new(),
            target: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let client = DockerClient::connect_local().unwrap();
        assert_eq!(
            client.build_image_buildkit(options, |_| {}).await,
            Err(BuildKitBuildError::InvalidInput)
        );
    }

    #[tokio::test]
    #[ignore = "requires explicit local Docker BuildKit opt-in"]
    async fn live_buildkit_single_file_context() {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1")
        );
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("input");
        std::fs::write(&file, b"FROM scratch\nENV SINGLE_FILE=yes\n").unwrap();
        let image = format!("neotales-buildkit-single-file:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let options = BuildKitBuildOptions {
            context: file,
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::new(),
            target: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options, |_| {}),
        )
        .await;
        let inspect = match &result {
            Ok(Ok(_)) => Some(client.inspect_image(&image).await),
            _ => None,
        };
        let _ = client.remove_image(&image, None).await;
        let id = result
            .expect("build deadline")
            .expect("single-file BuildKit solve");
        assert_eq!(inspect.unwrap().unwrap().id, id);
        println!("SINGLE FILE IMAGE ID: {id}");
    }

    #[tokio::test]
    #[ignore = "requires explicit local Docker BuildKit opt-in"]
    async fn live_buildkit_build_and_inspect() {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1")
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Dockerfile"),
            b"FROM alpine:3.21.3\nRUN echo hi > /hi\n",
        )
        .unwrap();
        let image = format!("neotales-buildkit-test:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let options = BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::new(),
            target: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options, |_| {}),
        )
        .await;
        let inspect = match &result {
            Ok(Ok(_)) => Some(client.inspect_image(&image).await),
            _ => None,
        };
        let _ = client.remove_image(&image, None).await;
        let id = result.expect("build deadline").expect("BuildKit solve");
        assert_eq!(inspect.unwrap().unwrap().id, id);
        println!("BuildKit exported image: {id}");
    }

    #[tokio::test]
    #[ignore = "requires explicit local Docker BuildKit opt-in"]
    async fn live_buildkit_dockerignore_filters() {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1")
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), b"FROM alpine:3.21.3\nCOPY . /src\nRUN test -f /src/keep.txt && test ! -e /src/drop.key\n").unwrap();
        std::fs::write(dir.path().join(".dockerignore"), b"*.key\n").unwrap();
        std::fs::write(dir.path().join("keep.txt"), b"safe").unwrap();
        std::fs::write(dir.path().join("drop.key"), b"excluded").unwrap();
        let image = format!("neotales-buildkit-filter:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let options = BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::new(),
            target: None,
            secrets: BTreeMap::new(),
            ssh: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options, |_| {}),
        )
        .await;
        let inspect = match &result {
            Ok(Ok(_)) => Some(client.inspect_image(&image).await),
            _ => None,
        };
        let _ = client.remove_image(&image, None).await;
        let id = result
            .expect("build deadline")
            .expect("BuildKit filter solve");
        assert_eq!(inspect.unwrap().unwrap().id, id);
        println!("BuildKit filtered image: {id}");
    }

    #[tokio::test]
    #[ignore = "requires explicit local Docker BuildKit opt-in"]
    async fn live_buildkit_secrets_do_not_enter_image() {
        assert_eq!(
            std::env::var("NEOTALES_DOCKER_BUILDKIT").as_deref(),
            Ok("1")
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Dockerfile"), b"FROM alpine:3.21.3\nRUN --mount=type=secret,id=token,uid=1000,gid=1000,mode=0400 test \"$(stat -c '%u:%g:%a' /run/secrets/token)\" = 1000:1000:400 && cat /run/secrets/token > /dev/null\n").unwrap();
        let image = format!("neotales-buildkit-secret:{}", std::process::id());
        let client = DockerClient::connect_local().unwrap();
        let token = b"neotales-test-secret-6d82bdac";
        let options = |with_secret: bool| BuildKitBuildOptions {
            context: dir.path().into(),
            dockerfile: "Dockerfile".into(),
            image: image.clone(),
            push: false,
            compression: None,
            oci_mediatypes: None,
            build_args: BTreeMap::new(),
            target: None,
            secrets: if with_secret {
                [("token".into(), token.to_vec())].into()
            } else {
                BTreeMap::new()
            },
            ssh: BTreeMap::new(),
            cache_from: Vec::new(),
            cache_to: Vec::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options(true), |_| {}),
        )
        .await;
        let id = match result {
            Ok(Ok(id)) => id,
            other => {
                let _ = client.remove_image(&image, None).await;
                panic!("secret build failed: {other:?}");
            }
        };
        assert_secret_absent_from_image(&client, &image, token).await;
        println!("BuildKit secret image: {id}; filesystem and history do not contain test token");

        // Change the shell operation to prevent a previous successful secret
        // layer from satisfying the missing-secret control from cache.
        std::fs::write(dir.path().join("Dockerfile"), b"FROM alpine:3.21.3\nRUN --mount=type=secret,id=token cat /run/secrets/token >/dev/null\n").unwrap();
        let missing = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options(false), |_| {}),
        )
        .await;
        let _ = client.remove_image(&image, None).await;
        println!("BuildKit missing-secret control: {missing:?}");
        assert!(
            matches!(missing, Ok(Err(BuildKitBuildError::Status(_)))),
            "missing secret did not produce a builder status"
        );

        // Supplying a secret alone must not expose it without a RUN mount.
        std::fs::write(
            dir.path().join("Dockerfile"),
            b"FROM alpine:3.21.3\nRUN cat /run/secrets/token >/dev/null\n",
        )
        .unwrap();
        let no_mount = tokio::time::timeout(
            Duration::from_secs(90),
            client.build_image_buildkit(options(true), |_| {}),
        )
        .await;
        let _ = client.remove_image(&image, None).await;
        println!("BuildKit no-mount control: {no_mount:?}");
        assert!(
            matches!(no_mount, Ok(Err(BuildKitBuildError::Status(_)))),
            "unmounted secret did not produce a builder status"
        );
    }

    /// Assert the image filesystem and history contain no copy of the secret.
    async fn assert_secret_absent_from_image(client: &DockerClient, image: &str, token: &[u8]) {
        let history = client.image_history(image).await;
        let created = client
            .create_container(crate::ContainerCreateOptions {
                image: image.to_owned(),
                ..Default::default()
            })
            .await;
        let created = match created {
            Ok(created) => created,
            Err(error) => {
                let _ = client.remove_image(image, None).await;
                panic!("container creation failed: {error}");
            }
        };
        let mut archive = client.export_container(&created.id);
        let mut bytes = Vec::new();
        let read_result = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(chunk) = archive.next().await {
                let chunk = chunk.map_err(|_| ())?;
                if bytes.len().saturating_add(chunk.len()) > 64 * 1024 * 1024 {
                    return Err(());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok::<(), ()>(())
        })
        .await;
        drop(archive);
        let _ = client.remove_container(&created.id, None).await;
        let _ = client.remove_image(image, None).await;
        assert!(read_result.unwrap().is_ok());
        assert!(!bytes.windows(token.len()).any(|window| window == token));
        assert!(!format!("{:?}", history.unwrap()).contains(std::str::from_utf8(token).unwrap()));
    }
}
