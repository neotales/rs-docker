#![allow(clippy::doc_markdown)]
//! Repository-owned Engine image build, import, load, and save operations.
//!
//! The operations in this module use the repository-owned transport. Build contexts are inspected as bounded
//! TAR archives before an Engine request is opened, while load/import bodies
//! remain caller-owned streams. The classic Engine builder is used here; the
//! separate `neotales-docker-buildkit` crate is a transport-free contract and
//! is not silently substituted for a real Engine build.
//!
//! # The registry-credential header is base64 **URL-safe**
//!
//! The Engine decodes both `X-Registry-Auth` and `X-Registry-Config` with Go's
//! `base64.URLEncoding`, and a value it cannot decode is **not** an error: the
//! daemon proceeds as though no credential had been sent at all. The two
//! alphabets differ only in `+` against `-` and `/` against `_`, so a
//! standard-alphabet header is byte-for-byte an anonymous request whenever the
//! encoded JSON happens to contain one of those four characters.
//!
//! Measured against Docker Engine 29.7.2, a pull of
//! `ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz:latest` answers:
//!
//! | `X-Registry-Auth` | Answer |
//! | --- | --- |
//! | header absent | `500 error from registry: denied\ndenied` |
//! | **standard** base64 of a real credential | `500 error from registry: denied\ndenied` — byte-identical to no header |
//! | **URL-safe** base64 of the same credential | `403 error from registry: denied` — the credential was read |
//!
//! `POST /build` is quieter still: a standard-alphabet or outright unparseable
//! `X-Registry-Config` is **ignored** and the build runs, so an authenticated
//! build against a private registry silently builds anonymously and fails later
//! at the layer-fetch step. So the encoding here is
//! `base64::engine::general_purpose::URL_SAFE`.
//!
//! # The two registry headers are not interchangeable
//!
//! | Request | Header | Value |
//! | --- | --- | --- |
//! | `POST /build` | `X-Registry-Config` | a **map** of registry to auth object |
//! | `POST /images/load` | `X-Registry-Auth` | **one** auth object |
//! | `POST /images/create?fromSrc=` | `X-Registry-Auth` | **one** auth object |
//!
//! The Engine decodes at most one auth object out of `X-Registry-Auth` and
//! nowhere else — the daemon wraps that object in a one-entry map itself — so a
//! request carrying `X-Registry-Config` carries a credential the daemon does not
//! read, and a map of two or more registries has no faithful spelling for this
//! endpoint at all. The second is refused, with both header names in the
//! message, rather than sent as the nearest available approximation.
//!
//! **Moby's import branch does not read the credential at all.** Its
//! `postImagesCreate` reads `X-Registry-Auth` in the *pull* branch and fetches an
//! import's `fromSrc` with `remotecontext.GetWithStatusError`, which takes no
//! credential. The header is still carried because the public contract has
//! always carried it and the caller asked for it, but it does not authenticate
//! an import.
//!
//! **The header name is documented, not measured, and the code says so.** Every
//! spelling of `X-Registry-Auth` and `X-Registry-Config` was tried against
//! Docker Engine 29.7.2 on a real three-megabyte archive, with the control
//! request alongside it, and all six answers were
//! `200 {"stream":"Loaded image: alpine:3.20\n"}` — the archive is parsed
//! before the credential is read, and this archive needed no fetch. So the
//! claim that one header is ignored and the other honoured rests on the
//! Engine's API reference and its source, not on a measurement, and
//! `tests/registry_credential_headers.rs` asserts the header this crate
//! *sends* rather than pretending to have observed the daemon's reaction to it.

use crate::link_guard::is_link_or_reparse_point;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File},
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::Arc,
};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::{StreamExt, stream};
use tar::{Builder as TarBuilder, EntryType, Header};

use crate::{
    ApiVersion, CredentialError, DockerClient, DockerStream, Error, ImageProgress,
    ImageStreamEvent, RegistryCredentialProvider, RegistryCredentials, normalize_registry, raw,
    registry_for_image,
    streams::{OwnedResponse, owned_response},
};

const MEBIBYTE: u64 = 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const DEFAULT_MAX_CONTEXT_BYTES: u64 = 64 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_ENTRIES: usize = 16_384;
const DEFAULT_MAX_CONTEXT_ENTRY_BYTES: u64 = 32 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_TOTAL_BYTES: u64 = 128 * MEBIBYTE;
const DEFAULT_MAX_CONTEXT_PATH_BYTES: usize = 4096;
const DEFAULT_MAX_STREAM_BYTES: u64 = 256 * MEBIBYTE;
const MAX_REFERENCE_BYTES: usize = 4096;
const MAX_PLATFORM_BYTES: usize = 255;
const MAX_TAG_BYTES: usize = 1024;
/// Resource limits applied to a build context or an upload stream.
///
/// The defaults are intentionally finite so a caller cannot accidentally turn
/// a Docker image operation into an unbounded memory or disk operation. A
/// caller can choose stricter limits, but cannot disable them with zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageTransferLimits {
    /// Maximum number of TAR records in a build context.
    pub max_entries: usize,
    /// Maximum declared and observed size of one context file.
    pub max_entry_bytes: u64,
    /// Maximum combined size of context files.
    pub max_total_bytes: u64,
    /// Maximum physical size of the context TAR.
    pub max_archive_bytes: u64,
    /// Maximum UTF-8 byte length of a TAR path.
    pub max_path_bytes: usize,
    /// Maximum number of bytes accepted from a load/import stream.
    pub max_stream_bytes: u64,
}

impl Default for ImageTransferLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_CONTEXT_ENTRIES,
            max_entry_bytes: DEFAULT_MAX_CONTEXT_ENTRY_BYTES,
            max_total_bytes: DEFAULT_MAX_CONTEXT_TOTAL_BYTES,
            max_archive_bytes: DEFAULT_MAX_CONTEXT_BYTES,
            max_path_bytes: DEFAULT_MAX_CONTEXT_PATH_BYTES,
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
        }
    }
}

impl ImageTransferLimits {
    fn validate(self) -> Result<Self, ImageTransferError> {
        if self.max_entries == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_entries must be positive",
            ));
        }
        if self.max_entry_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_entry_bytes must be positive",
            ));
        }
        if self.max_total_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_total_bytes must be positive",
            ));
        }
        if self.max_archive_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_archive_bytes must be positive",
            ));
        }
        if self.max_path_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_path_bytes must be positive",
            ));
        }
        if self.max_stream_bytes == 0 {
            return Err(ImageTransferError::InvalidLimits(
                "max_stream_bytes must be positive",
            ));
        }
        if self.max_entry_bytes > self.max_total_bytes {
            return Err(ImageTransferError::InvalidLimits(
                "max_entry_bytes cannot exceed max_total_bytes",
            ));
        }
        if self.max_archive_bytes < 512 {
            return Err(ImageTransferError::InvalidLimits(
                "max_archive_bytes must be at least one TAR record",
            ));
        }
        Ok(self)
    }

    /// Returns a copy with a different upload-stream ceiling.
    #[must_use]
    pub const fn with_max_stream_bytes(mut self, max_stream_bytes: u64) -> Self {
        self.max_stream_bytes = max_stream_bytes;
        self
    }
}

/// Errors raised before an Engine image-transfer request is opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageTransferError {
    /// A configured limit is unusable.
    InvalidLimits(&'static str),
    /// The TAR is malformed, truncated, or has trailing data.
    InvalidArchive(String),
    /// A TAR path is absolute, traversing, or otherwise ambiguous.
    UnsafeArchivePath(String),
    /// The TAR contains the same logical path more than once.
    DuplicateArchiveEntry(String),
    /// The TAR contains an unsupported link, device, FIFO, or other special record.
    UnsupportedArchiveEntry {
        /// Archive entry name.
        entry: String,
        /// Stable description of the rejected entry kind.
        kind: &'static str,
    },
    /// The TAR has too many records.
    TooManyEntries {
        /// Observed record count.
        actual: usize,
        /// Configured record limit.
        limit: usize,
    },
    /// A TAR file is larger than its per-file limit.
    EntryTooLarge {
        /// Archive entry name.
        entry: String,
        /// Observed or declared size.
        actual: u64,
        /// Configured per-file limit.
        limit: u64,
    },
    /// The combined TAR payload is too large.
    TotalSizeExceeded {
        /// Configured combined-size limit.
        limit: u64,
    },
    /// The physical TAR is too large.
    ArchiveTooLarge {
        /// Observed or attempted size.
        actual: u64,
        /// Configured physical-size limit.
        limit: u64,
    },
    /// A selected Dockerfile is missing or names a directory.
    DockerfileMissing(String),
    /// An image reference, tag, platform, or source is invalid.
    InvalidOption {
        /// Option name.
        name: &'static str,
        /// Safe validation detail.
        detail: String,
    },
    /// A save request did not contain an image name.
    MissingImageName,
    /// A classic Engine build cannot represent a requested BuildKit option.
    UnsupportedBuildKit(ImageBuildKitOption),
    /// A registry credential policy is invalid.
    Credentials(CredentialError),
    /// A filesystem operation failed.
    Io(String),
}

impl fmt::Display for ImageTransferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(message) => {
                write!(formatter, "image transfer limits are invalid: {message}")
            }
            Self::InvalidArchive(message) => {
                write!(formatter, "image build context is invalid: {message}")
            }
            Self::UnsafeArchivePath(path) => {
                write!(formatter, "image build context path is unsafe: {path}")
            }
            Self::DuplicateArchiveEntry(path) => {
                write!(
                    formatter,
                    "image build context contains duplicate path: {path}"
                )
            }
            Self::UnsupportedArchiveEntry { entry, kind } => {
                write!(
                    formatter,
                    "image build context entry {entry} is an unsupported {kind}"
                )
            }
            Self::TooManyEntries { actual, limit } => write!(
                formatter,
                "image build context has {actual} entries; limit is {limit}"
            ),
            Self::EntryTooLarge {
                entry,
                actual,
                limit,
            } => write!(
                formatter,
                "image build context entry {entry} is {actual} bytes; limit is {limit}"
            ),
            Self::TotalSizeExceeded { limit } => write!(
                formatter,
                "image build context exceeds the total-size limit of {limit} bytes"
            ),
            Self::ArchiveTooLarge { actual, limit } => write!(
                formatter,
                "image build context is or would be {actual} bytes; limit is {limit}"
            ),
            Self::DockerfileMissing(path) => {
                write!(
                    formatter,
                    "build context does not contain Dockerfile: {path}"
                )
            }
            Self::InvalidOption { name, detail } => {
                write!(formatter, "image {name} option is invalid: {detail}")
            }
            Self::MissingImageName => write!(formatter, "at least one image name is required"),
            Self::UnsupportedBuildKit(option) => write!(
                formatter,
                "BuildKit image option {option} is not supported by the Engine facade"
            ),
            Self::Credentials(error) => write!(formatter, "image registry credentials: {error}"),
            Self::Io(message) => write!(formatter, "image transfer I/O failed: {message}"),
        }
    }
}

impl std::error::Error for ImageTransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Credentials(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialError> for ImageTransferError {
    fn from(error: CredentialError) -> Self {
        Self::Credentials(error)
    }
}

impl From<io::Error> for ImageTransferError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Compatibility name for callers that treat context validation as a build
/// error.
pub type ImageBuildError = ImageTransferError;
/// Compatibility name for the bounded context constructor.
pub type ImageContextError = ImageTransferError;
/// Compatibility name for save setup errors.
pub type ImageSaveError = ImageTransferError;

/// A BuildKit-only option that is intentionally not silently downgraded to a
/// classic Engine build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageBuildKitOption {
    /// BuildKit builder/session selection.
    BuilderSession,
    /// BuildKit cache export configuration.
    CacheTo,
    /// BuildKit output/export configuration.
    Outputs,
    /// BuildKit secret mounts.
    Secrets,
    /// BuildKit SSH mounts.
    Ssh,
    /// BuildKit provenance attestation.
    Provenance,
    /// BuildKit SBOM attestation.
    Sbom,
    /// BuildKit entitlement requests.
    Entitlements,
    /// BuildKit named build contexts.
    NamedContexts,
    /// BuildKit frontend selection.
    Frontend,
    /// Multi-platform BuildKit output selection.
    MultiPlatform,
}

impl fmt::Display for ImageBuildKitOption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::BuilderSession => "builder/session",
            Self::CacheTo => "cache-to",
            Self::Outputs => "outputs",
            Self::Secrets => "secret",
            Self::Ssh => "ssh",
            Self::Provenance => "provenance",
            Self::Sbom => "sbom",
            Self::Entitlements => "entitlements",
            Self::NamedContexts => "named-context",
            Self::Frontend => "frontend",
            Self::MultiPlatform => "multi-platform",
        };
        formatter.write_str(name)
    }
}

/// The Engine builder selected for a build request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ImageBuildBackend {
    /// The real Docker Engine legacy builder exposed by `/build`.
    #[default]
    Classic,
    /// Reserved for a future real BuildKit transport; rejected by this slice.
    BuildKit,
}

/// A bounded, validated TAR build context.
///
/// Construction reads and validates the complete archive before any HTTP
/// request is opened. Clones of the context share immutable archive bytes.
/// When a build is started, its request body eagerly copies the complete
/// archive into chunks before returning the stream, on both transport routes.
/// This temporarily requires an additional archive-sized allocation; a cloned
/// context retains the original bytes while the request holds the copies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildContext {
    bytes: Arc<[u8]>,
    files: BTreeSet<String>,
    limits: ImageTransferLimits,
}

impl ImageBuildContext {
    /// Reads and validates a TAR archive from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe paths, special entries,
    /// malformed TARs, or exceeded limits.
    pub fn from_tar<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ImageTransferError> {
        Self::from_tar_with_limits(bytes, ImageTransferLimits::default())
    }

    /// Reads and validates a TAR archive with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid limits, unsafe paths,
    /// special entries, malformed TARs, or exceeded limits.
    pub fn from_tar_with_limits<B: AsRef<[u8]>>(
        bytes: B,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let bytes = bytes.as_ref();
        if bytes.len() as u64 > limits.max_archive_bytes {
            return Err(ImageTransferError::ArchiveTooLarge {
                actual: bytes.len() as u64,
                limit: limits.max_archive_bytes,
            });
        }
        let files = inspect_tar(bytes, limits)?;
        Ok(Self {
            bytes: Arc::<[u8]>::from(bytes.to_vec().into_boxed_slice()),
            files,
            limits,
        })
    }

    /// Alias for [`Self::from_tar`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_tar`].
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> Result<Self, ImageTransferError> {
        Self::from_tar(bytes)
    }

    /// Reads and validates a TAR archive from a synchronous reader.
    ///
    /// The reader is consumed at most one byte beyond the configured archive
    /// limit, which makes an oversized reader fail without unbounded buffering.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for I/O, malformed archives, or limits.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, ImageTransferError> {
        Self::from_reader_with_limits(reader, ImageTransferLimits::default())
    }

    /// Reads and validates a TAR archive with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for I/O, malformed archives, or limits.
    pub fn from_reader_with_limits<R: Read>(
        reader: R,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let mut bytes = Vec::new();
        let mut reader = reader.take(limits.max_archive_bytes.saturating_add(1));
        reader.read_to_end(&mut bytes)?;
        Self::from_tar_with_limits(bytes, limits)
    }

    /// Reads and validates a regular TAR file.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an unsafe/non-regular path, an
    /// oversized file, or invalid TAR contents.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ImageTransferError> {
        Self::from_path_with_limits(path, ImageTransferLimits::default())
    }

    /// Reads and validates a regular TAR file with explicit limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe/non-regular paths, an
    /// oversized file, or invalid TAR contents.
    pub fn from_path_with_limits(
        path: impl AsRef<Path>,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", path.display())))?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: path.display().to_string(),
                kind: "filesystem path",
            });
        }
        if metadata.len() > limits.max_archive_bytes {
            return Err(ImageTransferError::ArchiveTooLarge {
                actual: metadata.len(),
                limit: limits.max_archive_bytes,
            });
        }
        let file = File::open(path)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", path.display())))?;
        Self::from_reader_with_limits(file, limits)
    }

    /// Creates a deterministic, bounded TAR from a directory tree.
    ///
    /// Symbolic links are archived as links without following their targets,
    /// including targets outside the context. Device nodes, FIFOs, and other
    /// special filesystem entries are rejected.
    /// Hard-linked regular files are archived as independent regular files.
    /// Packing assumes the tree is not concurrently mutated; path replacement
    /// races are not prevented.
    /// Unix permission bits are preserved; other platforms use 0755 for
    /// directories and 0644 for files. Modification times are normalized to
    /// zero for reproducible archives.
    ///
    /// A Dockerfile-specific `Dockerfile.dockerignore` takes precedence over
    /// the context root `.dockerignore`. Patterns support `*`, `?`, and `**`,
    /// negation with `!`, comments in column
    /// one, and whitespace trimming. Leading and trailing slashes are ignored.
    /// Character classes and backslash handling follow the platform: Windows
    /// treats backslashes as separators; other platforms treat them as escapes.
    /// Dot components and repeated separators are cleaned. Malformed patterns
    /// are refused. The ignore file is limited to 64 KiB and 4096 patterns.
    /// Ignored entries count toward the traversal entry limit.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe trees, I/O failures, or
    /// exceeded limits.
    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self, ImageTransferError> {
        Self::from_directory_with_limits(path, ImageTransferLimits::default())
    }

    /// Creates a deterministic, bounded TAR from a directory with limits.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for unsafe trees, I/O failures, or
    /// exceeded limits.
    pub fn from_directory_with_limits(
        path: impl AsRef<Path>,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        Self::from_directory_for_dockerfile_with_limits(path, "Dockerfile", limits)
    }

    /// Creates a bounded context using the selected Dockerfile's ignore file.
    ///
    /// # Errors
    /// Returns an error for invalid paths, unsupported ignore patterns, unsafe
    /// trees, I/O failures, or exceeded limits.
    pub fn from_directory_for_dockerfile_with_limits(
        path: impl AsRef<Path>,
        dockerfile: &str,
        limits: ImageTransferLimits,
    ) -> Result<Self, ImageTransferError> {
        let limits = limits.validate()?;
        let dockerfile = validate_relative_path(dockerfile, "dockerfile").map_err(|detail| {
            ImageTransferError::InvalidOption {
                name: "dockerfile",
                detail,
            }
        })?;
        let root = path.as_ref();
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| ImageTransferError::Io(format!("{}: {error}", root.display())))?;
        if is_link_or_reparse_point(&metadata) || !metadata.is_dir() {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: root.display().to_string(),
                kind: "filesystem directory",
            });
        }
        let ignore = crate::build_ignore::BuildIgnore::load(root, &dockerfile, limits)?;
        let mut entries = Vec::new();
        let mut visited = 0;
        collect_directory_entries(
            root,
            root,
            &mut entries,
            limits,
            &ignore,
            &dockerfile,
            &mut visited,
        )?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let mut builder = TarBuilder::new(Vec::new());
        for entry in entries {
            match entry.kind {
                DirectoryEntryKind::Directory => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Directory);
                    header.set_mode(entry.mode);
                    header.set_size(0);
                    header.set_mtime(0);
                    header.set_cksum();
                    let path = format!("{}/", entry.path);
                    builder
                        .append_data(&mut header, path, io::empty())
                        .map_err(ImageTransferError::from)?;
                }
                DirectoryEntryKind::File { size } => {
                    let file =
                        File::open(root.join(&entry.path)).map_err(ImageTransferError::from)?;
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Regular);
                    header.set_mode(entry.mode);
                    header.set_size(size);
                    header.set_mtime(0);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, &entry.path, file)
                        .map_err(ImageTransferError::from)?;
                }
                DirectoryEntryKind::Symlink => {
                    let target = fs::read_link(root.join(&entry.path))?;
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Symlink);
                    header.set_mode(entry.mode);
                    header.set_size(0);
                    header.set_mtime(0);
                    builder.append_link(&mut header, &entry.path, target)?;
                }
            }
        }
        let bytes = builder.into_inner().map_err(ImageTransferError::from)?;
        Self::from_tar_with_limits(bytes, limits)
    }

    /// Returns the number of validated context files.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Returns the physical archive size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the validated context has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the validated context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validates that the selected Dockerfile is a regular file in the context.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError::DockerfileMissing`] for an unsafe or
    /// missing Dockerfile path.
    pub fn validate_for(&self, options: &ImageBuildOptions) -> Result<(), ImageTransferError> {
        let path = validate_relative_path(&options.dockerfile, "dockerfile").map_err(|detail| {
            ImageTransferError::InvalidOption {
                name: "dockerfile",
                detail,
            }
        })?;
        if !self.files.contains(&path) {
            return Err(ImageTransferError::DockerfileMissing(path));
        }
        Ok(())
    }

    fn request_body(&self) -> impl Stream<Item = Bytes> + Send + 'static {
        let bytes = Arc::clone(&self.bytes);
        stream::iter(
            bytes
                .chunks(COPY_BUFFER_SIZE)
                .map(Bytes::copy_from_slice)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug)]
struct DirectoryEntry {
    path: String,
    kind: DirectoryEntryKind,
    mode: u32,
}

#[cfg(unix)]
fn context_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(unix)]
fn special_filesystem_kind(metadata: &fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let kind = metadata.file_type();
    if kind.is_fifo() {
        "FIFO"
    } else if kind.is_char_device() {
        "character device"
    } else if kind.is_block_device() {
        "block device"
    } else if kind.is_socket() {
        "socket"
    } else {
        "special filesystem entry"
    }
}

#[cfg(not(unix))]
fn special_filesystem_kind(_metadata: &fs::Metadata) -> &'static str {
    "special filesystem entry"
}

#[cfg(not(unix))]
fn context_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.is_dir() { 0o755 } else { 0o644 }
}

#[derive(Clone, Copy, Debug)]
enum DirectoryEntryKind {
    Directory,
    File { size: u64 },
    Symlink,
}

#[allow(clippy::too_many_lines)]
fn collect_directory_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<DirectoryEntry>,
    limits: ImageTransferLimits,
    ignore: &crate::build_ignore::BuildIgnore,
    dockerfile: &str,
    visited: &mut usize,
) -> Result<(), ImageTransferError> {
    let mut children = fs::read_dir(current)
        .map_err(|error| ImageTransferError::Io(format!("{}: {error}", current.display())))?
        .take(
            limits
                .max_entries
                .saturating_sub(*visited)
                .saturating_add(1),
        )
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ImageTransferError::Io(format!("{}: {error}", current.display())))?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        *visited = visited.saturating_add(1);
        if *visited > limits.max_entries {
            return Err(ImageTransferError::TooManyEntries {
                actual: *visited,
                limit: limits.max_entries,
            });
        }
        let metadata = fs::symlink_metadata(child.path()).map_err(|error| {
            ImageTransferError::Io(format!("{}: {error}", child.path().display()))
        })?;
        let relative = child
            .path()
            .strip_prefix(root)
            .map_err(|_| ImageTransferError::UnsafeArchivePath(child.path().display().to_string()))?
            .to_str()
            .ok_or_else(|| {
                ImageTransferError::UnsafeArchivePath(child.path().display().to_string())
            })?
            .replace('\\', "/");
        let path = validate_relative_path(&relative, "context path")
            .map_err(ImageTransferError::UnsafeArchivePath)?;
        let excluded = path != dockerfile
            && path != "Dockerfile"
            && path != ".dockerignore"
            && path != ignore.selected
            && ignore.excluded(&path);
        if excluded {
            if metadata.is_dir() && !is_link_or_reparse_point(&metadata) {
                collect_directory_entries(
                    root,
                    &child.path(),
                    entries,
                    limits,
                    ignore,
                    dockerfile,
                    visited,
                )?;
            }
            continue;
        }
        if is_link_or_reparse_point(&metadata) {
            if !metadata.file_type().is_symlink() {
                return Err(ImageTransferError::UnsupportedArchiveEntry {
                    entry: child.path().display().to_string(),
                    kind: "reparse point",
                });
            }
            entries.push(DirectoryEntry {
                path,
                kind: DirectoryEntryKind::Symlink,
                mode: context_mode(&metadata),
            });
            continue;
        }
        if entries.len() >= limits.max_entries {
            return Err(ImageTransferError::TooManyEntries {
                actual: entries.len().saturating_add(1),
                limit: limits.max_entries,
            });
        }
        if metadata.is_dir() {
            entries.push(DirectoryEntry {
                path: path.clone(),
                kind: DirectoryEntryKind::Directory,
                mode: context_mode(&metadata),
            });
            collect_directory_entries(
                root,
                &child.path(),
                entries,
                limits,
                ignore,
                dockerfile,
                visited,
            )?;
        } else if metadata.is_file() {
            if metadata.len() > limits.max_entry_bytes {
                return Err(ImageTransferError::EntryTooLarge {
                    entry: path,
                    actual: metadata.len(),
                    limit: limits.max_entry_bytes,
                });
            }
            let mut total = 0_u64;
            for entry in entries
                .iter()
                .filter(|entry| matches!(entry.kind, DirectoryEntryKind::File { .. }))
            {
                if let DirectoryEntryKind::File { size } = entry.kind {
                    total = total.saturating_add(size);
                }
            }
            let new_total = total.checked_add(metadata.len()).ok_or({
                ImageTransferError::InvalidArchive("context size overflow".to_owned())
            })?;
            if new_total > limits.max_total_bytes {
                return Err(ImageTransferError::TotalSizeExceeded {
                    limit: limits.max_total_bytes,
                });
            }
            entries.push(DirectoryEntry {
                path,
                kind: DirectoryEntryKind::File {
                    size: metadata.len(),
                },
                mode: context_mode(&metadata),
            });
        } else {
            return Err(ImageTransferError::UnsupportedArchiveEntry {
                entry: path,
                kind: special_filesystem_kind(&metadata),
            });
        }
    }
    Ok(())
}

fn display_archive_path(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

fn tar_entry_kind(kind: EntryType) -> &'static str {
    if kind.is_symlink() {
        "symbolic link"
    } else if kind.is_hard_link() {
        "hard link"
    } else if kind.is_character_special() {
        "character device"
    } else if kind.is_block_special() {
        "block device"
    } else if kind.is_fifo() {
        "FIFO"
    } else {
        "special TAR entry"
    }
}

#[allow(clippy::too_many_lines)]
fn inspect_tar(
    bytes: &[u8],
    limits: ImageTransferLimits,
) -> Result<BTreeSet<String>, ImageTransferError> {
    let archive_length = bytes.len() as u64;
    let mut reader = Cursor::new(bytes);
    let mut archive = tar::Archive::new(&mut reader);
    archive.set_ignore_zeros(false);
    let mut files = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut links = BTreeSet::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    let mut last_entry_end = 0_u64;
    {
        let entries = archive
            .entries_with_seek()
            .map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
        for entry in entries {
            let mut entry =
                entry.map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
            count = count.checked_add(1).ok_or_else(|| {
                ImageTransferError::InvalidArchive("entry count overflow".to_owned())
            })?;
            if count > limits.max_entries {
                return Err(ImageTransferError::TooManyEntries {
                    actual: count,
                    limit: limits.max_entries,
                });
            }
            let kind = entry.header().entry_type();
            if !kind.is_dir() && !kind.is_file() && !kind.is_symlink() {
                let path = display_archive_path(&entry.path_bytes());
                return Err(ImageTransferError::UnsupportedArchiveEntry {
                    entry: path,
                    kind: tar_entry_kind(kind),
                });
            }
            let path_bytes = entry.path_bytes().into_owned();
            if path_bytes.len() > limits.max_path_bytes {
                return Err(ImageTransferError::UnsafeArchivePath(display_archive_path(
                    &path_bytes,
                )));
            }
            let path = std::str::from_utf8(&path_bytes)
                .map_err(|_| {
                    ImageTransferError::UnsafeArchivePath(display_archive_path(&path_bytes))
                })?
                .to_owned();
            let path = if kind.is_dir() {
                path.strip_suffix('/').unwrap_or(&path)
            } else {
                &path
            };
            let normalized = validate_relative_path(path, "context path")
                .map_err(ImageTransferError::UnsafeArchivePath)?;
            if !seen.insert(normalized.clone()) {
                return Err(ImageTransferError::DuplicateArchiveEntry(normalized));
            }
            let size = entry.size();
            if kind.is_dir() || kind.is_symlink() {
                if size != 0 {
                    return Err(ImageTransferError::UnsupportedArchiveEntry {
                        entry: normalized,
                        kind: "directory or symbolic link with data",
                    });
                }
                if kind.is_symlink() {
                    let target = entry.link_name_bytes().ok_or_else(|| {
                        ImageTransferError::InvalidArchive("symbolic link has no target".to_owned())
                    })?;
                    if target.is_empty() || target.len() > limits.max_path_bytes {
                        return Err(ImageTransferError::UnsafeArchivePath(normalized));
                    }
                    links.insert(normalized);
                }
            } else {
                if size > limits.max_entry_bytes {
                    return Err(ImageTransferError::EntryTooLarge {
                        entry: normalized,
                        actual: size,
                        limit: limits.max_entry_bytes,
                    });
                }
                total = total.checked_add(size).ok_or_else(|| {
                    ImageTransferError::InvalidArchive("context size overflow".to_owned())
                })?;
                if total > limits.max_total_bytes {
                    return Err(ImageTransferError::TotalSizeExceeded {
                        limit: limits.max_total_bytes,
                    });
                }
                let copied = io::copy(&mut entry.by_ref().take(size), &mut io::sink())
                    .map_err(|error| ImageTransferError::InvalidArchive(error.to_string()))?;
                if copied != size {
                    return Err(ImageTransferError::InvalidArchive(format!(
                        "entry {normalized} ended at {copied} bytes; declared {size}"
                    )));
                }
                files.insert(normalized);
            }
            let padded_size = size
                .checked_add(511)
                .map(|value| value / 512 * 512)
                .ok_or_else(|| {
                    ImageTransferError::InvalidArchive("TAR size overflow".to_owned())
                })?;
            let entry_end = entry
                .raw_file_position()
                .checked_add(padded_size)
                .ok_or_else(|| {
                    ImageTransferError::InvalidArchive("TAR offset overflow".to_owned())
                })?;
            last_entry_end = last_entry_end.max(entry_end);
        }
    }
    if count == 0 {
        return Err(ImageTransferError::InvalidArchive(
            "TAR contains no entries".to_owned(),
        ));
    }
    for path in &seen {
        for (index, _) in path.match_indices('/') {
            if links.contains(&path[..index]) {
                return Err(ImageTransferError::UnsafeArchivePath(path.clone()));
            }
        }
    }
    validate_tar_tail(bytes, last_entry_end, archive_length)?;
    Ok(files)
}

fn validate_tar_tail(
    bytes: &[u8],
    last_entry_end: u64,
    archive_length: u64,
) -> Result<(), ImageTransferError> {
    if last_entry_end > archive_length {
        return Err(ImageTransferError::InvalidArchive(
            "TAR entry extends beyond the archive".to_owned(),
        ));
    }
    let tail = &bytes[usize::try_from(last_entry_end).map_err(|_| {
        ImageTransferError::InvalidArchive("TAR tail offset does not fit usize".to_owned())
    })?..];
    if tail.iter().any(|byte| *byte != 0) {
        return Err(ImageTransferError::InvalidArchive(
            "TAR contains trailing or concatenated data".to_owned(),
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &str, option: &str) -> Result<String, String> {
    if path.is_empty() || path.len() > MAX_REFERENCE_BYTES {
        return Err(format!("{option} path is empty or too long"));
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return Err(format!(
            "{option} path must be relative and use '/' separators"
        ));
    }
    if path
        .chars()
        .any(|character| character.is_control() || character == '\0')
    {
        return Err(format!("{option} path contains a control character"));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "{option} path contains an empty or traversing component"
            ));
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err(format!("{option} path is empty"));
    }
    Ok(components.join("/"))
}

fn validate_image_name(name: &str, option: &'static str) -> Result<(), ImageTransferError> {
    if name.is_empty() || name.len() > MAX_REFERENCE_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: option,
            detail: "name is empty or too long".to_owned(),
        });
    }
    if name
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || name.contains('?')
        || name.contains('#')
    {
        return Err(ImageTransferError::InvalidOption {
            name: option,
            detail: "name contains whitespace, control, query, or fragment characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_tag(tag: &str) -> Result<(), ImageTransferError> {
    if tag.is_empty() || tag.len() > MAX_TAG_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "tag",
            detail: "tag is empty or too long".to_owned(),
        });
    }
    if tag
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ImageTransferError::InvalidOption {
            name: "tag",
            detail: "tag contains whitespace or a control character".to_owned(),
        });
    }
    Ok(())
}

fn validate_platform(platform: &str) -> Result<(), ImageTransferError> {
    if platform.is_empty() || platform.len() > MAX_PLATFORM_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "platform is empty or too long".to_owned(),
        });
    }
    if platform
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        || platform.contains('?')
        || platform.contains('#')
    {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "platform contains unsafe characters".to_owned(),
        });
    }
    let parts: Vec<_> = platform.split('/').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "use os[/architecture[/variant]]".to_owned(),
        });
    }
    Ok(())
}

/// The first Engine API version that accepts `platform` on an image load or
/// export.
///
/// Moby's v1.48 API changelog records it: "`POST /images/{name}/load` and
/// `GET /images/{name}/get` now support a `platform` parameter (JSON encoded
/// OCI Platform type) that allows to specify a platform to load/save. Not
/// passing this parameter will result in loading/saving the full multi-platform
/// image."
///
/// The daemon does not reject the parameter below that version: both handlers
/// gate the whole block on `versions.GreaterThanOrEqualTo(…, "1.48")` —
/// `postImagesLoad` and `getImagesGet` in
/// `api/server/router/image/image_routes.go` — so a v1.47 request carrying
/// `platform` is answered with the **full multi-platform image or archive** and
/// no error. That is why this crate refuses the request instead of sending a
/// parameter the daemon will silently ignore.
///
/// At or above that version each handler decodes one `platform` value with
/// `httputils.DecodePlatform`, which is `json.Unmarshal` into
/// `ocispec.Platform` and requires both `os` and `architecture`. Both handlers
/// also refuse more than one `platform` parameter with
/// `400 multiple platform parameters not supported`, so an operation carries at
/// most one.
pub(crate) const IMAGE_PLATFORM_API_VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 48,
};

/// Whether `version` is new enough for a platform-selective image load or save.
pub(crate) fn image_platform_supported(version: ApiVersion) -> bool {
    (version.major, version.minor)
        >= (
            IMAGE_PLATFORM_API_VERSION.major,
            IMAGE_PLATFORM_API_VERSION.minor,
        )
}

/// The first Engine API version that reads `platform` on `POST /images/create`.
///
/// Moby's `postImagesCreate` reads the import/pull `platform` inside
/// `versions.GreaterThanOrEqualTo(version, "1.32")` and otherwise ignores it,
/// importing for the host platform. The parameter is the
/// `os[/architecture[/variant]]` shorthand decoded with `platforms.Parse`,
/// **not** the JSON OCI object a load or save carries, so it travels verbatim
/// rather than through [`image_platform_json`].
pub(crate) const IMAGE_IMPORT_PLATFORM_API_VERSION: ApiVersion = ApiVersion {
    major: 1,
    minor: 32,
};

/// Whether `version` is new enough for a platform-selective image import.
pub(crate) fn import_platform_supported(version: ApiVersion) -> bool {
    (version.major, version.minor)
        >= (
            IMAGE_IMPORT_PLATFORM_API_VERSION.major,
            IMAGE_IMPORT_PLATFORM_API_VERSION.minor,
        )
}

/// The refusal a platform import gets on a route that cannot prove the version.
fn import_platform_refusal(version: ApiVersion) -> ImageTransferError {
    ImageTransferError::InvalidOption {
        name: "platform",
        detail: format!(
            "the Engine accepts an import platform from API {}.{}; this client would send {}.{}, \
             where the parameter is ignored and the image is imported for the host platform",
            IMAGE_IMPORT_PLATFORM_API_VERSION.major,
            IMAGE_IMPORT_PLATFORM_API_VERSION.minor,
            version.major,
            version.minor
        ),
    }
}

/// One Engine `platform` query value: the JSON-encoded OCI platform object.
///
/// The Engine decodes this value with `json.Unmarshal` into `ocispec.Platform`
/// and refuses a document whose `os` or `architecture` is empty, so the
/// `os[/architecture[/variant]]` shorthand these options accept is parsed here
/// rather than put on the wire. The field order follows Moby's own struct, and
/// `variant` is omitted when the caller did not name one.
#[derive(serde::Serialize)]
struct ImagePlatform<'a> {
    architecture: &'a str,
    os: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    variant: Option<&'a str>,
}

/// Encodes a load or save platform as the JSON the Engine's parameter takes.
///
/// `platform` is first checked by [`validate_platform`], so the parts are
/// non-empty and there are at most three of them. A platform without an
/// architecture is refused here: the Engine's decoder answers
/// `both OS and Architecture must be provided`, and on a pre-1.48 request it
/// would be ignored altogether.
pub(crate) fn image_platform_json(platform: &str) -> Result<String, ImageTransferError> {
    validate_platform(platform)?;
    let mut parts = platform.split('/');
    let os = parts.next().unwrap_or_default();
    let Some(architecture) = parts.next() else {
        return Err(ImageTransferError::InvalidOption {
            name: "platform",
            detail: "a selected platform needs os/architecture; the Engine refuses a platform \
                     without both"
                .to_owned(),
        });
    };
    serde_json::to_string(&ImagePlatform {
        architecture,
        os,
        variant: parts.next(),
    })
    .map_err(|error| ImageTransferError::InvalidOption {
        name: "platform",
        detail: format!("the platform could not be encoded as JSON: {error}"),
    })
}

/// How to reach a route that can version a platform request.
///
/// Shared by the save and load refusals so the recovery steps cannot drift.
/// `https://` is named because switching it to plain HTTP to obtain a versioned
/// request would drop TLS, which is not an acceptable trade.
fn validate_source(source: &str) -> Result<(), ImageTransferError> {
    if source == "-" {
        return Ok(());
    }
    if source.is_empty() || source.len() > MAX_REFERENCE_BYTES {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source is empty or too long".to_owned(),
        });
    }
    if source
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source contains whitespace or a control character".to_owned(),
        });
    }
    let url = url::Url::parse(source).map_err(|_| ImageTransferError::InvalidOption {
        name: "source",
        detail: "source must be an HTTP(S) URL or '-'".to_owned(),
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ImageTransferError::InvalidOption {
            name: "source",
            detail: "source must be an HTTP(S) URL or '-'".to_owned(),
        });
    }
    Ok(())
}

/// Options for the Engine `/build` endpoint.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageBuildOptions {
    /// Dockerfile path relative to the validated TAR context.
    pub dockerfile: String,
    /// Optional image names/tags to apply.
    pub tags: Vec<String>,
    /// Optional target stage.
    pub target: Option<String>,
    /// Optional target platform in `os/architecture[/variant]` form.
    pub platform: Option<String>,
    /// Suppress verbose build output.
    pub quiet: bool,
    /// Disable the Engine build cache.
    pub no_cache: bool,
    /// Pull newer base images when true; leave unset to use daemon behavior.
    pub pull: Option<bool>,
    /// Remove intermediate containers after success.
    pub remove_intermediate: bool,
    /// Remove intermediate containers after failure.
    pub force_remove_intermediate: bool,
    /// Ordered build arguments.
    pub build_args: BTreeMap<String, String>,
    /// Ordered image labels.
    pub labels: BTreeMap<String, String>,
    /// Cache image references.
    pub cache_from: Vec<String>,
    /// Optional `/etc/hosts` additions.
    pub extra_hosts: Option<String>,
    /// Further host additions, sent as repeated `extrahosts` query values.
    pub extra_host_entries: Vec<String>,
    /// Optional build network mode.
    pub network_mode: Option<String>,
    /// Optional memory limit in bytes.
    pub memory: Option<i32>,
    /// Optional memory-plus-swap limit in bytes.
    pub memswap: Option<i32>,
    /// Optional CPU shares.
    pub cpu_shares: Option<i32>,
    /// Optional CPU affinity list.
    pub cpuset_cpus: Option<String>,
    /// Optional CPU period.
    pub cpu_period: Option<i32>,
    /// Optional CPU quota.
    pub cpu_quota: Option<i32>,
    /// Optional `/dev/shm` size.
    pub shm_size: Option<i64>,
    /// Process resource limits for containers started by the classic builder.
    pub ulimits: Vec<crate::containers::Ulimit>,
    /// Optional classic-builder squash flag.
    pub squash: Option<bool>,
    /// Optional remote context URL. It is rejected by this bounded-context
    /// operation rather than downloading unvalidated input.
    pub remote: Option<String>,
    /// Explicit registry credentials keyed by registry authority.
    pub registry_credentials: BTreeMap<String, RegistryCredentials>,
    /// Builder backend. BuildKit is rejected until a real transport exists.
    pub backend: ImageBuildBackend,
    /// Explicitly requested unsupported BuildKit options.
    pub buildkit_options: Vec<ImageBuildKitOption>,
}

impl Default for ImageBuildOptions {
    fn default() -> Self {
        Self {
            dockerfile: "Dockerfile".to_owned(),
            tags: Vec::new(),
            target: None,
            platform: None,
            quiet: false,
            no_cache: false,
            pull: None,
            remove_intermediate: true,
            force_remove_intermediate: false,
            build_args: BTreeMap::new(),
            labels: BTreeMap::new(),
            cache_from: Vec::new(),
            extra_hosts: None,
            extra_host_entries: Vec::new(),
            network_mode: None,
            memory: None,
            memswap: None,
            cpu_shares: None,
            cpuset_cpus: None,
            cpu_period: None,
            cpu_quota: None,
            shm_size: None,
            ulimits: Vec::new(),
            squash: None,
            remote: None,
            registry_credentials: BTreeMap::new(),
            backend: ImageBuildBackend::Classic,
            buildkit_options: Vec::new(),
        }
    }
}

impl ImageBuildOptions {
    /// Creates default classic Engine build options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Dockerfile path.
    #[must_use]
    pub fn with_dockerfile(mut self, dockerfile: impl Into<String>) -> Self {
        self.dockerfile = dockerfile.into();
        self
    }

    /// Adds one image tag/name.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Replaces the image tag/name list.
    #[must_use]
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Enables or disables quiet build output.
    #[must_use]
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Sets the target build stage.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Sets the target platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Enables or disables base-image pulling.
    #[must_use]
    pub const fn with_pull(mut self, pull: bool) -> Self {
        self.pull = Some(pull);
        self
    }

    /// Disables the build cache.
    #[must_use]
    pub const fn with_no_cache(mut self, no_cache: bool) -> Self {
        self.no_cache = no_cache;
        self
    }

    /// Adds one ordered build argument.
    #[must_use]
    pub fn with_build_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.build_args.insert(key.into(), value.into());
        self
    }

    /// Adds one ordered image label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Adds one cache-from image reference.
    #[must_use]
    pub fn with_cache_from(mut self, image: impl Into<String>) -> Self {
        self.cache_from.push(image.into());
        self
    }

    /// Adds explicit registry credentials for base-image pulls.
    #[must_use]
    pub fn with_registry_credentials(
        mut self,
        registry: impl Into<String>,
        credentials: RegistryCredentials,
    ) -> Self {
        self.registry_credentials
            .insert(registry.into(), credentials);
        self
    }

    /// Marks a BuildKit-only option as requested.
    #[must_use]
    pub fn with_buildkit_option(mut self, option: ImageBuildKitOption) -> Self {
        self.buildkit_options.push(option);
        self
    }

    /// Selects the real classic Engine builder.
    #[must_use]
    pub const fn with_classic_builder(mut self) -> Self {
        self.backend = ImageBuildBackend::Classic;
        self
    }

    /// Selects BuildKit. The current Engine facade rejects this explicitly.
    #[must_use]
    pub const fn with_buildkit(mut self) -> Self {
        self.backend = ImageBuildBackend::BuildKit;
        self
    }

    /// Validates options that can be checked without contacting a daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid names, paths, options, or
    /// explicitly requested BuildKit-only features.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        validate_relative_path(&self.dockerfile, "dockerfile").map_err(|detail| {
            ImageTransferError::InvalidOption {
                name: "dockerfile",
                detail,
            }
        })?;
        for tag in &self.tags {
            validate_image_name(tag, "tag")?;
        }
        if let Some(platform) = &self.platform {
            validate_platform(platform)?;
        }
        if let Some(target) = &self.target
            && (target.is_empty() || target.chars().any(char::is_control))
        {
            return Err(ImageTransferError::InvalidOption {
                name: "target",
                detail: "target is empty or contains a control character".to_owned(),
            });
        }
        if let Some(remote) = &self.remote {
            validate_source(remote)?;
            return Err(ImageTransferError::InvalidOption {
                name: "remote",
                detail: "remote contexts are not accepted by the bounded TAR operation".to_owned(),
            });
        }
        if self.memory.is_some_and(|value| value <= 0)
            || self.memswap.is_some_and(|value| value == 0 || value < -1)
            || self.cpu_shares.is_some_and(|value| value <= 0)
            || self.cpu_period.is_some_and(|value| value <= 0)
            || self.cpu_quota.is_some_and(|value| value == 0)
            || self.shm_size.is_some_and(|value| value < 0)
        {
            return Err(ImageTransferError::InvalidOption {
                name: "resource",
                detail:
                    "resource limits must be positive (memswap may be -1; shm size may be zero)"
                        .to_owned(),
            });
        }
        for image in &self.cache_from {
            validate_image_name(image, "cache-from")?;
        }
        validate_key_values(&self.build_args, "build-arg")?;
        validate_key_values(&self.labels, "label")?;
        if self.backend == ImageBuildBackend::BuildKit {
            return Err(ImageTransferError::UnsupportedBuildKit(
                ImageBuildKitOption::BuilderSession,
            ));
        }
        if let Some(option) = self.buildkit_options.first().copied() {
            return Err(ImageTransferError::UnsupportedBuildKit(option));
        }
        Ok(())
    }
}

fn validate_key_values(
    values: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), ImageTransferError> {
    for (key, value) in values {
        if key.is_empty()
            || key.len() > 4096
            || value.len() > 128 * 1024
            || key.chars().chain(value.chars()).any(char::is_control)
        {
            return Err(ImageTransferError::InvalidOption {
                name,
                detail: "key or value is empty, too long, or contains a control character"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

/// Options for importing an image from a remote TAR source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageImportOptions {
    /// HTTP(S) source URL, or `-` for a caller-owned request stream.
    pub source: String,
    /// Optional destination repository.
    pub repository: Option<String>,
    /// Optional destination tag.
    pub tag: Option<String>,
    /// Optional import commit message.
    pub message: Option<String>,
    /// Dockerfile changes applied while importing.
    pub changes: Vec<String>,
    /// Optional imported platform.
    pub platform: Option<String>,
}

impl ImageImportOptions {
    /// Creates import options for a source URL.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            ..Self::default()
        }
    }

    /// Sets the destination repository.
    #[must_use]
    pub fn with_repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    /// Sets the destination tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Sets the import platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Adds one Dockerfile change.
    #[must_use]
    pub fn with_change(mut self, change: impl Into<String>) -> Self {
        self.changes.push(change.into());
        self
    }

    /// Validates options without contacting a daemon.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid source, repository, tag,
    /// platform, or change.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        validate_source(&self.source)?;
        if let Some(repository) = &self.repository {
            validate_image_name(repository, "repository")?;
        }
        if let Some(tag) = &self.tag {
            validate_tag(tag)?;
        }
        if let Some(platform) = &self.platform {
            validate_platform(platform)?;
        }
        for change in &self.changes {
            if change.is_empty()
                || change.len() > 128 * 1024
                || change.chars().any(char::is_control)
            {
                return Err(ImageTransferError::InvalidOption {
                    name: "change",
                    detail: "change is empty, too long, or contains a control character".to_owned(),
                });
            }
        }
        if self.message.as_ref().is_some_and(|message| {
            message.is_empty()
                || message.len() > 128 * 1024
                || message.chars().any(char::is_control)
        }) {
            return Err(ImageTransferError::InvalidOption {
                name: "message",
                detail: "message is empty, too long, or contains a control character".to_owned(),
            });
        }
        Ok(())
    }
}

/// Options for loading a Docker image archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadOptions {
    /// Suppress progress details.
    pub quiet: bool,
    /// Platform selector, written as `os[/architecture[/variant]]`.
    ///
    /// The Engine's `platform` parameter is **one JSON-encoded OCI platform
    /// object**, not this shorthand and not a list: its load handler decodes a
    /// single value with `httputils.DecodePlatform` and refuses a request
    /// carrying more than one (`400 multiple platform parameters not
    /// supported`). The shorthand is converted to that JSON on the wire, and at
    /// most one entry is accepted. The parameter is read from API 1.48; below
    /// that version the daemon ignores it and loads the full multi-platform
    /// image, so this client refuses a platform load below 1.48 rather than send
    /// a parameter the daemon will ignore.
    pub platforms: Vec<String>,
}

impl ImageLoadOptions {
    /// Creates default load options.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            quiet: false,
            platforms: Vec::new(),
        }
    }

    /// Enables or disables quiet progress.
    #[must_use]
    pub const fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Adds one platform selector.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platforms.push(platform.into());
        self
    }

    /// Replaces the platform selector list.
    #[must_use]
    pub fn with_platforms<I, S>(mut self, platforms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.platforms = platforms.into_iter().map(Into::into).collect();
        self
    }

    /// Validates load options.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid platform selector, a
    /// selector without both an operating system and an architecture, or for
    /// more than one selector. Moby's load handler refuses a request carrying
    /// more than one `platform` parameter, so the second entry has no request
    /// shape that reaches the daemon.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        if self.platforms.len() > 1 {
            return Err(ImageTransferError::InvalidOption {
                name: "platform",
                detail: "the Engine's load handler refuses more than one `platform` parameter \
                         (`400 multiple platform parameters not supported`); request one platform \
                         or none"
                    .to_owned(),
            });
        }
        for platform in &self.platforms {
            // Encoded here rather than only checked as shorthand: the Engine's
            // decoder requires both `os` and `architecture`, so `linux` alone
            // must be refused before either route opens a request.
            image_platform_json(platform)?;
        }
        Ok(())
    }
}

/// Options for saving one or more images as a Docker archive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageSaveOptions {
    /// Image names or IDs to include in the archive.
    pub names: Vec<String>,
    /// Optional target platform, written as `os[/architecture[/variant]]`.
    ///
    /// The Engine receives this as a JSON-encoded OCI platform object, not as
    /// this shorthand, and requires both `os` and `architecture`. It reads the
    /// parameter from API 1.48 onward. A platform save is refused when the
    /// owned transport's version is older than that, because such a daemon would
    /// silently return the full multi-platform archive. See
    /// [`DockerClient::save_images`].
    pub platform: Option<String>,
}

impl ImageSaveOptions {
    /// Creates save options for one or more image names.
    #[must_use]
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            names: names.into_iter().map(Into::into).collect(),
            platform: None,
        }
    }

    /// Adds one image name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.names.push(name.into());
        self
    }

    /// Sets the target platform.
    #[must_use]
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Validates names and platform selection.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] when no valid image name is supplied, or
    /// when the platform is malformed or does not name both an operating system
    /// and an architecture. The Engine decodes the save platform as a JSON OCI
    /// platform object and refuses one without both, so `linux` alone is
    /// refused here rather than sent for the daemon to reject.
    pub fn validate(&self) -> Result<(), ImageTransferError> {
        if self.names.is_empty() {
            return Err(ImageTransferError::MissingImageName);
        }
        for name in &self.names {
            validate_image_name(name, "name")?;
        }
        if let Some(platform) = &self.platform {
            image_platform_json(platform)?;
        }
        Ok(())
    }
}

/// A typed build response line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageBuildEvent {
    /// Layer or operation identifier.
    pub id: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// Raw textual build output.
    pub stream: Option<String>,
    /// Structured progress details.
    pub progress: Option<ImageProgress>,
    /// Error text embedded in a successful HTTP stream.
    ///
    /// Retained for compatibility with the generated model. The build stream turns `errorDetail.message` into a Docker-kind [`Error`] item
    /// instead, so this member is `None` for a failed build; a caller must
    /// handle the stream's `Err` item.
    pub error: Option<String>,
    /// Classic builder auxiliary image ID, when supplied.
    pub aux: Option<ImageBuildAux>,
}

/// Auxiliary values emitted by a build response.
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ImageBuildAux {
    /// Resulting image ID.
    pub image_id: Option<String>,
    /// Resulting digest, when supplied by a newer daemon.
    pub digest: Option<String>,
    /// BuildKit reference, when supplied by a newer daemon.
    pub build_ref: Option<String>,
}

/// A typed load response line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadEvent {
    /// Layer or image identifier.
    pub id: Option<String>,
    /// Human-readable status.
    pub status: Option<String>,
    /// Raw textual output.
    pub stream: Option<String>,
    /// Structured progress details.
    pub progress: Option<ImageProgress>,
    /// Error text embedded in a successful HTTP stream.
    ///
    /// Always `None` from [`DockerClient::load_image`]: an in-band failure is
    /// an `Err` item, so a caller that only inspects this field
    /// cannot mistake a failed load for a successful one. The field remains on
    /// the public type for compatibility.
    pub error: Option<String>,
}

/// Alias matching the Engine terminology.
pub type ImageBuildResponse = ImageBuildEvent;
/// Alias matching the Engine terminology.
pub type ImageLoadResponse = ImageLoadEvent;
/// Import uses the same progress shape as pull/push.
pub type ImageImportEvent = ImageStreamEvent;

/// A collected successful build result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageBuildResult {
    /// The resulting image ID, when the daemon emitted one.
    pub image_id: Option<String>,
    /// All typed response lines in daemon order.
    pub events: Vec<ImageBuildEvent>,
}

/// A collected successful load result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImageLoadResult {
    /// IDs observed in load progress events.
    pub image_ids: Vec<String>,
    /// All typed response lines in daemon order.
    pub events: Vec<ImageLoadEvent>,
}

/// A high-level save result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImageSaveResult {
    /// Number of response chunks written.
    pub chunks: u64,
    /// Total bytes written.
    pub bytes: u64,
}

/// Errors returned while consuming a build/load/save response stream.
#[derive(Debug)]
pub enum ImageOperationError {
    /// Invalid request options or context.
    Transfer(ImageTransferError),
    /// Docker transport/API error.
    Docker(Error),
    /// The daemon embedded an error in an otherwise successful stream.
    ///
    /// Retained for compatibility. The build path reports an in-band failure as
    /// a Docker-kind error, so it
    /// arrives as [`Self::Docker`]; this variant remains for callers that match
    /// exhaustively.
    Daemon(String),
    /// Caller-owned output/input I/O failed.
    Io(String),
}

impl fmt::Display for ImageOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transfer(error) => write!(formatter, "{error}"),
            Self::Docker(error) => write!(formatter, "{error}"),
            Self::Daemon(message) => write!(formatter, "Docker image operation failed: {message}"),
            Self::Io(message) => write!(formatter, "image operation I/O failed: {message}"),
        }
    }
}

impl std::error::Error for ImageOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transfer(error) => Some(error),
            Self::Docker(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImageTransferError> for ImageOperationError {
    fn from(error: ImageTransferError) -> Self {
        Self::Transfer(error)
    }
}

impl From<Error> for ImageOperationError {
    fn from(error: Error) -> Self {
        Self::Docker(error)
    }
}

// Field order, names and types mirror the generated classic BuildInfo schema.
// Derive uses IgnoredAny for unknown values and rejects duplicate known fields,
// including after null; it also accepts the generated model's sequence form.
#[derive(serde::Deserialize)]
struct BuildRecord {
    id: Option<String>,
    stream: Option<String>,
    #[serde(rename = "errorDetail")]
    error_detail: Option<BuildRecordError>,
    status: Option<String>,
    #[serde(rename = "progressDetail")]
    progress_detail: Option<BuildRecordProgress>,
    aux: Option<BuildRecordAux>,
}

#[derive(serde::Deserialize)]
struct BuildRecordError {
    #[allow(dead_code)]
    code: Option<i64>,
    message: Option<String>,
}

#[derive(serde::Deserialize)]
struct BuildRecordProgress {
    current: Option<i64>,
    total: Option<i64>,
}

#[derive(serde::Deserialize)]
struct BuildRecordAux {
    #[serde(rename = "ID")]
    id: Option<String>,
}

// The Engine writes the same progress record for a build and a load, with one
// difference that matters here: a load failure can be a bare `error` string.
// A separate top-level struct rather than a shared one keeps the build
// projection from starting to reject a duplicate `error` member it ignores
// today, while `LoadRecord` can name that member and refuse it twice.
//
// `aux` is validated and not projected: the generated load model knows it, so a
// duplicate `aux`, a duplicate nested `ID`, or either of the wrong JSON type is
// refused by the generated decoder. Dropping the member from this schema would
// make the owned route accept a record the fallback rejects.
#[derive(serde::Deserialize)]
struct LoadRecord {
    id: Option<String>,
    stream: Option<String>,
    error: Option<String>,
    #[serde(rename = "errorDetail")]
    error_detail: Option<BuildRecordError>,
    status: Option<String>,
    #[serde(rename = "progressDetail")]
    progress_detail: Option<BuildRecordProgress>,
    // Validated for parity with the generated model; the load event has no
    // `aux` field to project it onto.
    #[serde(rename = "aux")]
    _aux: Option<BuildRecordAux>,
}

// A `POST /images/create` record is the generated `CreateImageInfo` model: `id`,
// `status`, `errorDetail` (`code`, `message`), and `progressDetail` (`current`,
// `total`). There is deliberately no `stream` member: the generated model has
// none either, so the projection leaves [`ImageStreamEvent::stream`] empty on
// both routes rather than inventing a member the fallback drops. The bare
// `error` string is the one member the generated model does not know; it is read
// here so a failure the daemon wrote only that way is not reported as a
// successful import, and that is the documented route difference.
#[derive(serde::Deserialize)]
struct CreateRecord {
    id: Option<String>,
    error: Option<String>,
    #[serde(rename = "errorDetail")]
    error_detail: Option<BuildRecordError>,
    status: Option<String>,
    #[serde(rename = "progressDetail")]
    progress_detail: Option<BuildRecordProgress>,
}

#[derive(Debug)]
struct StreamError(String);

// The stream error has a repository-owned source.
impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Docker stream error: {}", self.0)
    }
}

impl std::error::Error for StreamError {}

/// Decode from original bytes, not `Value`, without retaining unknown trees.
///
/// Do not expose serde's diagnostic: it can include daemon-supplied values.
fn parse_build_event_record(bytes: &[u8]) -> Result<ImageBuildEvent, Error> {
    let info: BuildRecord = serde_json::from_slice(bytes).map_err(|error| {
        Error::serialization(<serde_json::Error as serde::de::Error>::custom(format!(
            "invalid daemon build record (line {}, column {})",
            error.line(),
            error.column()
        )))
    })?;
    if let Some(message) = info.error_detail.and_then(|detail| detail.message) {
        return Err(Error {
            kind: crate::ErrorKind::Docker,
            source: Some(Box::new(StreamError(message))),
            api: None,
        });
    }
    Ok(ImageBuildEvent {
        id: info.id,
        status: info.status,
        stream: info.stream,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: None,
        aux: info.aux.map(|aux| ImageBuildAux {
            image_id: aux.id,
            digest: None,
            build_ref: None,
        }),
    })
}

/// Decodes one `POST /images/load` progress record from its original bytes.
///
/// The daemon writes the failure twice on this endpoint — a bare `error` string
/// and an `errorDetail.message` — and either is a failed load. The bare string
/// is read first, which is the precedence
/// [`raw::progress_error`](crate::raw::progress_error) documents, but an
/// **empty** bare string is treated as absent so it cannot mask a real
/// `errorDetail.message`.
///
/// Decoding from the record's bytes rather than a [`serde_json::Value`] is what
/// lets a duplicate known member be refused: a `Value` keeps only the last one,
/// so a failure followed by `"errorDetail":null` would read as success. The
/// known members are the generated load model's, including `aux` and its nested
/// `ID`, even though the load event has no field for `aux` — the generated
/// decoder validates that member, so it remains validated here. The daemon's diagnostic is not echoed: a serde message can
/// quote daemon-supplied values, so only the position is reported.
fn parse_load_event_record(bytes: &[u8]) -> Result<ImageLoadEvent, Error> {
    let info: LoadRecord = serde_json::from_slice(bytes).map_err(|error| {
        Error::serialization(<serde_json::Error as serde::de::Error>::custom(format!(
            "invalid daemon load record (line {}, column {})",
            error.line(),
            error.column()
        )))
    })?;
    let message = info
        .error
        .filter(|message| !message.is_empty())
        .or_else(|| {
            info.error_detail
                .and_then(|detail| detail.message)
                .filter(|message| !message.is_empty())
        });
    if let Some(message) = message {
        return Err(Error {
            kind: crate::ErrorKind::Docker,
            source: Some(Box::new(StreamError(message))),
            api: None,
        });
    }
    Ok(ImageLoadEvent {
        id: info.id,
        status: info.status,
        stream: info.stream,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: None,
    })
}

/// Decodes one `POST /images/create` progress record from its original bytes.
///
/// An `errorDetail.message` (even empty), or a nonempty bare `error`, is
/// reported as a stream error.
///
/// Decoding from the record's bytes rather than a [`serde_json::Value`] is what
/// lets a duplicate known member be refused: a `Value` keeps only the last one,
/// so `"errorDetail":{"message":"failed"}` followed by `"errorDetail":null`
/// would read as success. The known members are the generated create model's
/// (`id`, `status`, `errorDetail` with `code`/`message`, `progressDetail` with
/// `current`/`total`) plus the bare `error`. The daemon's diagnostic is not
/// echoed: a serde message can quote daemon-supplied values, so only the
/// position is reported.
fn parse_create_event_record(bytes: &[u8]) -> Result<ImageStreamEvent, Error> {
    let info: CreateRecord = serde_json::from_slice(bytes).map_err(|error| {
        Error::serialization(<serde_json::Error as serde::de::Error>::custom(format!(
            "invalid daemon create record (line {}, column {})",
            error.line(),
            error.column()
        )))
    })?;
    let message = info
        .error_detail
        .and_then(|detail| detail.message)
        .or_else(|| info.error.filter(|message| !message.is_empty()));
    if let Some(message) = message {
        return Err(Error {
            kind: crate::ErrorKind::Docker,
            source: Some(Box::new(StreamError(message))),
            api: None,
        });
    }
    Ok(ImageStreamEvent {
        id: info.id,
        status: info.status,
        stream: None,
        progress: info.progress_detail.map(|progress| ImageProgress {
            current: progress.current,
            total: progress.total,
        }),
        error: None,
    })
}

/// Selects the one registry credential a load or import request may carry.
///
/// `POST /images/load` and `POST /images/create?fromSrc=` both read a single
/// auth object from `X-Registry-Auth`, and the Engine decodes exactly one: the
/// daemon wraps the object in a one-entry map itself. A map of two or more
/// registries therefore has no faithful spelling for either endpoint and is
/// refused with both header names in the message rather than sent as something
/// the daemon will not read.
///
/// The returned registry keeps the caller's spelling; the credential has been
/// validated against it through the repository's own rules. Both routes of
/// [`DockerClient::load_image_with_credentials`] call this before opening a
/// request, so an empty or multi-entry map is the [`ImageTransferError`] that
/// method promises rather than a stream item.
fn single_registry_entry(
    values: BTreeMap<String, RegistryCredentials>,
) -> Result<(String, RegistryCredentials), ImageTransferError> {
    let count = values.len();
    let mut entries = values.into_iter();
    let Some((registry, credentials)) = entries.next() else {
        return Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: "credential map must not be empty".to_owned(),
        });
    };
    if count > 1 {
        let others = entries
            .map(|(registry, _)| registry)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ImageTransferError::InvalidOption {
            name: "registry-credentials",
            detail: format!(
                "POST /images/load reads one registry from X-Registry-Auth, and \
                 X-Registry-Config is the header POST /build reads, so {count} \
                 registries have no faithful spelling here; {registry}, {others} \
                 were given"
            ),
        });
    }
    let normalized = normalize_registry(&registry)?;
    credentials.validate_for(&normalized)?;
    Ok((registry, credentials))
}

fn bounded_upload<S, E>(
    source: S,
    max_bytes: u64,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
{
    let source = Box::pin(source);
    stream::unfold(
        (source, 0_u64, max_bytes, false),
        |(mut source, total, max_bytes, failed)| async move {
            if failed {
                return None;
            }
            let item = source.as_mut().next().await?;
            match item {
                Ok(chunk) => {
                    let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    let Some(next_total) = total.checked_add(length) else {
                        return Some((
                            Err(io::Error::other("image upload size overflow")),
                            (source, total, max_bytes, true),
                        ));
                    };
                    if next_total > max_bytes {
                        return Some((
                            Err(io::Error::other(format!(
                                "image upload exceeds the {max_bytes}-byte limit"
                            ))),
                            (source, next_total, max_bytes, true),
                        ));
                    }
                    Some((
                        Ok(Bytes::from(chunk)),
                        (source, next_total, max_bytes, false),
                    ))
                }
                Err(error) => Some((
                    Err(io::Error::other(error)),
                    (source, total, max_bytes, true),
                )),
            }
        },
    )
}

impl DockerClient {
    /// Builds an image from a validated, bounded TAR context.
    ///
    /// Options and credentials are validated before the stream is returned.
    /// Request and daemon errors arrive as stream items. Dropping the stream
    /// cancels the request. The owned transport enforces its upload bound.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    #[allow(clippy::needless_pass_by_value)]
    pub fn build_image(
        &self,
        context: ImageBuildContext,
        options: Option<ImageBuildOptions>,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError> {
        let options = options.unwrap_or_default();
        options.validate()?;
        context.validate_for(&options)?;
        {
            let engine = self.raw_engine();
            // Validate the credential map here rather than in the request
            // builder, so an invalid credential is still the
            // `ImageTransferError` this method promises before a request opens.
            // The owned builder validates it again through the same repository
            // rules when it composes the header.
            for (registry, credentials) in &options.registry_credentials {
                let registry = normalize_registry(registry)?;
                credentials.validate_for(&registry)?;
            }
            let body = context.request_body().map(Ok::<Bytes, io::Error>);
            Ok(owned_response(async move {
                Ok(OwnedResponse::RawRecords {
                    frames: raw::build(&engine?, body, &options).await?,
                    map: Box::new(parse_build_event_record),
                })
            }))
        }
    }

    /// Builds an image using an explicit credential map, replacing the map in
    /// `options`.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid options or credentials.
    pub fn build_image_with_credentials(
        &self,
        context: ImageBuildContext,
        mut options: ImageBuildOptions,
        credentials: BTreeMap<String, RegistryCredentials>,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError> {
        options.registry_credentials = credentials;
        self.build_image(context, Some(options))
    }

    /// Builds an image with credentials supplied by a caller-owned provider.
    ///
    /// The provider is queried synchronously before the request task is
    /// created. Registry names are explicit because a provider must not be
    /// allowed to discover arbitrary registries from a Dockerfile.
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for an invalid registry, provider
    /// failure, or invalid build options.
    pub fn build_image_with_provider<P, I>(
        &self,
        context: ImageBuildContext,
        mut options: ImageBuildOptions,
        provider: &P,
        registries: I,
    ) -> Result<DockerStream<ImageBuildEvent>, ImageTransferError>
    where
        P: RegistryCredentialProvider + ?Sized,
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut credentials = BTreeMap::new();
        for registry in registries {
            let registry = normalize_registry(registry.as_ref())?;
            let value = provider.credentials_for(&registry)?;
            credentials.insert(registry, value);
        }
        options.registry_credentials = credentials;
        self.build_image(context, Some(options))
    }

    /// Builds an image and collects all response lines.
    ///
    /// The stream is [`Self::build_image`]'s, so the route, the request shape,
    /// the record bound, and the cancellation behaviour are that method's. An
    /// in-band build failure arrives as a Docker-kind error, as on the
    /// a stream item, and is returned here as
    /// [`ImageOperationError::Docker`]. On an authenticated proxy route that
    /// error is the fixed safe [`Error::engine_api`](crate::Error) with status
    /// `200`; direct and unauthenticated routes keep the daemon `StreamError`
    /// source.
    ///
    /// # Errors
    ///
    /// Returns [`ImageOperationError`] for request validation, transport/API
    /// errors, or an in-band failure from the response stream.
    pub async fn build_image_to_completion(
        &self,
        context: ImageBuildContext,
        options: Option<ImageBuildOptions>,
    ) -> Result<ImageBuildResult, ImageOperationError> {
        let mut stream = self
            .build_image(context, options)
            .map_err(ImageOperationError::Transfer)?;
        let mut result = ImageBuildResult::default();
        while let Some(item) = stream.next().await {
            let event = item.map_err(ImageOperationError::Docker)?;
            if let Some(error) = &event.error {
                return Err(ImageOperationError::Daemon(error.clone()));
            }
            if let Some(image_id) = event.aux.as_ref().and_then(|aux| aux.image_id.clone()) {
                result.image_id = Some(image_id);
            }
            result.events.push(event);
        }
        Ok(result)
    }

    /// Imports an image from a remote source.
    ///
    /// Invalid options are rejected before returning; request and daemon errors
    /// arrive as stream items. A platform requires Engine API 1.32 or newer.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image(
        &self,
        options: ImageImportOptions,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        options.validate()?;
        if options.source == "-" {
            return Err(ImageTransferError::InvalidOption {
                name: "source",
                detail: "use import_image_from_stream for '-'".to_owned(),
            });
        }
        self.import_url_stream(options, None)
    }

    /// Imports an archive as a bounded caller-owned stream.
    ///
    /// Cancellation or an upload error can leave bytes already sent to the
    /// daemon; reconcile image state before retrying with a fresh stream.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    pub fn import_image_from_stream<S, E>(
        &self,
        mut options: ImageImportOptions,
        source: S,
        limits: ImageTransferLimits,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        options.source.clear();
        options.source.push('-');
        options.validate()?;
        let limits = limits.validate()?;
        {
            let engine = self.raw_engine();
            // The owned request is versioned, so this version is the one the
            // daemon sees. Below 1.32 it ignores the parameter and imports for
            // the host platform; at or above it, an older daemon rejects the
            // request as too new rather than answering for the wrong image.
            if let Ok(engine) = &engine
                && options.platform.is_some()
                && !import_platform_supported(engine.version())
            {
                return Err(import_platform_refusal(engine.version()));
            }
            let body = bounded_upload(source, limits.max_stream_bytes);
            Ok(owned_response(async move {
                Ok(OwnedResponse::RawRecords {
                    frames: raw::import(&engine?, body, &options, raw::RegistryAuth::none())
                        .await?,
                    map: Box::new(parse_create_event_record),
                })
            }))
        }
    }

    /// Imports a remote image with a single registry credential.
    ///
    /// The registry is derived from [`ImageImportOptions::source`] with the
    /// repository's own [`registry_for_image`] rule, then the call is
    /// [`Self::import_image_with_credentials_for_registry`].
    ///
    /// # Errors
    ///
    /// Returns [`ImageTransferError`] for invalid import options or credentials.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image_with_credentials(
        &self,
        options: ImageImportOptions,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        let registry =
            registry_for_image(&options.source).map_err(ImageTransferError::Credentials)?;
        self.import_image_with_credentials_for_registry(options, &registry, credentials)
    }

    /// Imports a remote image with a single registry credential.
    ///
    /// Credentials are validated before the request; the owned transport encodes
    /// registry authentication and withholds sensitive error details.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    #[allow(clippy::needless_pass_by_value)]
    pub fn import_image_with_credentials_for_registry(
        &self,
        options: ImageImportOptions,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        options.validate()?;
        if options.source == "-" {
            return Err(ImageTransferError::InvalidOption {
                name: "source",
                detail: "use import_image_from_stream for '-'".to_owned(),
            });
        }
        // Validated here, before either route opens a request, so an invalid
        // credential is the `ImageTransferError` this method promises rather
        // than a stream item. The owned builder validates it again through the
        // same repository rules when it composes the header.
        let registry = normalize_registry(registry)?;
        credentials.validate_for(&registry)?;
        self.import_url_stream(options, Some((registry, credentials)))
    }

    /// Routes a validated URL import to the owned transport.
    ///
    /// Both URL-shaped public methods reach the transport through here, so the
    /// platform gate and the credential spelling have one implementation.
    /// `credentials` is the already-validated single registry entry, or `None`
    /// for the unauthenticated form.
    fn import_url_stream(
        &self,
        options: ImageImportOptions,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<DockerStream<ImageStreamEvent>, ImageTransferError> {
        {
            let engine = self.raw_engine();
            if let Ok(engine) = &engine
                && options.platform.is_some()
                && !import_platform_supported(engine.version())
            {
                return Err(import_platform_refusal(engine.version()));
            }
            Ok(owned_response(async move {
                // Built here rather than when the handle was created, so a
                // credential that cannot be encoded arrives as a stream item —
                // the same place every other request failure does. The entry
                // was validated before this call, and there is no path that
                // sends an empty auth object instead.
                let auth = match &credentials {
                    Some((registry, credentials)) => {
                        raw::RegistryAuth::credentials(registry, credentials)?
                    }
                    None => raw::RegistryAuth::none(),
                };
                Ok(OwnedResponse::RawRecords {
                    frames: raw::import_from_url(&engine?, &options, auth).await?,
                    map: Box::new(parse_create_event_record),
                })
            }))
        }
    }

    /// Loads an image archive from a bounded caller-owned stream.
    ///
    /// A platform requires Engine API 1.48 or newer. Cancellation can leave
    /// bytes already sent to the daemon; reconcile state before retrying.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    pub fn load_image<S, E>(
        &self,
        source: S,
        options: Option<ImageLoadOptions>,
        limits: ImageTransferLimits,
    ) -> Result<DockerStream<ImageLoadEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let options = options.unwrap_or_default();
        options.validate()?;
        let limits = limits.validate()?;
        self.load_stream(source, options, limits, None)
    }

    /// Loads an image archive with one registry credential.
    ///
    /// An empty or multi-entry credential map is rejected before the request.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    #[allow(clippy::needless_pass_by_value)]
    pub fn load_image_with_credentials<S, E>(
        &self,
        source: S,
        options: Option<ImageLoadOptions>,
        limits: ImageTransferLimits,
        credentials: BTreeMap<String, RegistryCredentials>,
    ) -> Result<DockerStream<ImageLoadEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let options = options.unwrap_or_default();
        options.validate()?;
        let limits = limits.validate()?;
        let (registry, credentials) = single_registry_entry(credentials)?;
        self.load_stream(source, options, limits, Some((registry, credentials)))
    }

    /// Routes a validated load to the owned transport, refusing unsupported platforms.
    ///
    /// Both public load methods reach the transport through here, so the
    /// platform gate, the body bound, and the credential spelling have one
    /// implementation. `credentials` is the already-selected and validated
    /// single registry entry, or `None` for the unauthenticated form.
    fn load_stream<S, E>(
        &self,
        source: S,
        options: ImageLoadOptions,
        limits: ImageTransferLimits,
        credentials: Option<(String, RegistryCredentials)>,
    ) -> Result<DockerStream<ImageLoadEvent>, ImageTransferError>
    where
        S: Stream<Item = Result<Vec<u8>, E>> + Send + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let has_platform = !options.platforms.is_empty();
        match self.raw_engine() {
            Ok(engine) => {
                // The owned request is versioned, so this version is the one the
                // daemon sees. Below 1.48 the daemon ignores the parameter and
                // loads the full multi-platform image; at or above it, an older
                // daemon rejects the request as too new rather than answering
                // for the wrong image.
                if has_platform && !image_platform_supported(engine.version()) {
                    return Err(ImageTransferError::InvalidOption {
                        name: "platform",
                        detail: format!(
                            "the Engine accepts a load platform from API {}.{}; this client \
                             would send {}.{}, where the parameter is ignored and the full \
                             multi-platform image is loaded",
                            IMAGE_PLATFORM_API_VERSION.major,
                            IMAGE_PLATFORM_API_VERSION.minor,
                            engine.version().major,
                            engine.version().minor
                        ),
                    });
                }
                let body = bounded_upload(source, limits.max_stream_bytes);
                Ok(owned_response(async move {
                    // Built here rather than when the handle was created, so a
                    // credential that cannot be encoded arrives as a stream
                    // item — the same place every other request failure does.
                    // The entry was validated before this call, and there is no
                    // path that sends an empty auth object instead.
                    let auth = match &credentials {
                        Some((registry, credentials)) => {
                            raw::RegistryAuth::credentials(registry, credentials)?
                        }
                        None => raw::RegistryAuth::none(),
                    };
                    Ok(OwnedResponse::RawRecords {
                        frames: raw::load(&engine, body, &options, auth).await?,
                        map: Box::new(parse_load_event_record),
                    })
                }))
            }
            Err(error) => Ok(owned_response(async move { Err(error) })),
        }
    }

    /// Saves images as a caller-owned archive stream.
    ///
    /// Names retain caller order. A platform requires an architecture and
    /// Engine API 1.48 or newer. Daemon export errors after response start may
    /// appear as archive bytes; transport failures are stream errors.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    pub fn save_images(
        &self,
        options: ImageSaveOptions,
    ) -> Result<DockerStream<Vec<u8>>, ImageTransferError> {
        options.validate()?;
        let platform = match options.platform.as_deref() {
            Some(platform) => Some(image_platform_json(platform)?),
            None => None,
        };
        match self.raw_engine() {
            Ok(engine) => {
                // The owned request is versioned, so this version is the one the
                // daemon sees. Below 1.48 the daemon would ignore the parameter;
                // at or above it, an older daemon rejects the request as too new
                // rather than answering with the wrong archive.
                if platform.is_some() && !image_platform_supported(engine.version()) {
                    return Err(ImageTransferError::InvalidOption {
                        name: "platform",
                        detail: format!(
                            "the Engine accepts a save platform from API {}.{}; this client \
                             would send {}.{}, where the parameter is ignored and the full \
                             multi-platform archive is returned",
                            IMAGE_PLATFORM_API_VERSION.major,
                            IMAGE_PLATFORM_API_VERSION.minor,
                            engine.version().major,
                            engine.version().minor
                        ),
                    });
                }
                Ok(owned_response(async move {
                    Ok(OwnedResponse::Chunks {
                        frames: raw::save(&engine, &options).await?,
                        into_item: |chunk| chunk.to_vec(),
                    })
                }))
            }
            Err(error) => Ok(owned_response(async move { Err(error) })),
        }
    }

    /// Saves one image as a caller-owned archive stream.
    ///
    /// See [`Self::save_images`] for platform and error semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when options, credentials, or input validation fail.
    pub fn save_image(
        &self,
        name: impl Into<String>,
        platform: Option<String>,
    ) -> Result<DockerStream<Vec<u8>>, ImageTransferError> {
        let mut options = ImageSaveOptions::new([name.into()]);
        options.platform = platform;
        self.save_images(options)
    }

    /// Saves all requested images into a caller-owned writer.
    ///
    /// The response is the stream [`Self::save_images`] returns, so it is read
    /// one transport chunk at a time on whichever route serves the endpoint and
    /// is never collected into a second archive buffer. Dropping the stream on a
    /// write error releases the HTTP response.
    ///
    /// **`Ok` means the bytes were written, not that they are an archive.** The
    /// daemon can write a JSON error body into a response it has already
    /// started, and this method cannot tell that from TAR bytes; an HTTP
    /// transport failure is still returned as an [`ImageOperationError`]. See
    /// [`Self::save_images`]. Validate the complete archive and its expected
    /// contents before trusting it.
    ///
    /// # Errors
    ///
    /// Returns [`ImageOperationError`] for validation, API/transport, or output
    /// errors.
    pub async fn save_images_to_writer<W: Write>(
        &self,
        options: ImageSaveOptions,
        writer: &mut W,
    ) -> Result<ImageSaveResult, ImageOperationError> {
        let mut stream = self
            .save_images(options)
            .map_err(ImageOperationError::Transfer)?;
        let mut result = ImageSaveResult::default();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(ImageOperationError::Docker)?;
            writer
                .write_all(&chunk)
                .map_err(|error| ImageOperationError::Io(error.to_string()))?;
            result.chunks += 1;
            result.bytes = result
                .bytes
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    ImageOperationError::Io("saved chunk length does not fit u64".to_owned())
                })?)
                .ok_or_else(|| ImageOperationError::Io("saved byte count overflow".to_owned()))?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{IMAGE_PLATFORM_API_VERSION, image_platform_json, image_platform_supported};
    use crate::ApiVersion;

    /// The load/save platform boundary is exactly API 1.48, and the encoder
    /// emits the JSON object the Engine decodes.
    ///
    /// Moby's v1.48 changelog adds the parameter, and both handlers
    /// (`postImagesLoad` and `getImagesGet`) gate it on
    /// `versions.GreaterThanOrEqualTo(…, "1.48")`. Both sides of the boundary
    /// are asserted, because an off-by-one here is silent: 1.47 would send a
    /// parameter the daemon ignores and 1.48 would refuse a request it reads.
    #[test]
    fn the_image_platform_boundary_is_the_version_moby_added_it() {
        assert_eq!(IMAGE_PLATFORM_API_VERSION.major, 1);
        assert_eq!(IMAGE_PLATFORM_API_VERSION.minor, 48);
        assert!(!image_platform_supported(ApiVersion {
            major: 1,
            minor: 47
        }));
        assert!(image_platform_supported(ApiVersion {
            major: 1,
            minor: 48
        }));
        assert!(image_platform_supported(ApiVersion {
            major: 1,
            minor: 55
        }));
        assert!(image_platform_supported(ApiVersion { major: 2, minor: 0 }));
    }

    /// The option's `os[/architecture[/variant]]` shorthand becomes the OCI
    /// platform document, with `variant` omitted when it was not named.
    #[test]
    fn an_image_platform_encodes_as_an_oci_platform_document() {
        assert_eq!(
            image_platform_json("linux/arm64").expect("a platform"),
            r#"{"architecture":"arm64","os":"linux"}"#
        );
        assert_eq!(
            image_platform_json("linux/arm/v7").expect("a platform"),
            r#"{"architecture":"arm","os":"linux","variant":"v7"}"#
        );

        // The Engine's decoder requires both `os` and `architecture`, and the
        // shorthand rules are still the shared ones.
        for refused in [
            "linux",
            "linux/",
            "/amd64",
            "linux/amd64/v1/x",
            "linux amd64",
        ] {
            assert!(
                image_platform_json(refused).is_err(),
                "{refused} must be refused"
            );
        }
    }
}
