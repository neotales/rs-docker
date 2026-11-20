//! Authority for document-directed reads.
//!
//! The Compose loader must not open a file named by an untrusted document.
//! Implementations of this interface are supplied by the caller and decide
//! which paths may be read and how glob patterns are expanded.

/// A file supplied by a caller-controlled resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposeResolvedFile {
    /// Stable identity of the referenced file, also used as its declaring
    /// path. Aliases of the same file must have the same identity.
    pub path: String,
    /// File contents, already read under the caller's authority.
    pub contents: String,
}

/// Why a document-directed read was not performed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeFileReadError {
    /// No file or glob match exists at the requested path.
    NotFound,
    /// The path is outside the caller's permitted root.
    OutsideRoot,
    /// The caller's policy refuses this operation.
    Refused,
    /// The caller cannot determine a unique, stable file identity.
    Ambiguous,
}

/// Caller-owned authority for files referenced by Compose documents.
///
/// `declaring_file` is the path of the file containing the reference;
/// `reference` is the path written in that file. The resolver interprets the
/// reference relative to that file, applies all authorization and containment
/// checks, and returns a stable identity for cycle detection. Implementations
/// must not return contents for a path they would refuse to read directly.
///
/// The crate does not provide a filesystem implementation. Supplying an
/// implementation is an explicit trust decision by the caller.
pub trait ComposeFileResolver {
    /// Authorizes a document-directed project directory and returns its
    /// absolute, stable path. The default grants no directory authority.
    ///
    /// # Errors
    ///
    /// Returns the reason the directory could not be authorized.
    fn resolve_directory(
        &self,
        _declaring_file: &str,
        _reference: &str,
    ) -> Result<String, ComposeFileReadError> {
        Err(ComposeFileReadError::Refused)
    }

    /// Returns the stable identity for an explicitly selected source, without
    /// changing the source path used to resolve relative declarations.
    fn source_identity(&self, source: &str) -> String {
        source.to_owned()
    }

    /// Reads one exact reference.
    ///
    /// # Errors
    ///
    /// Returns the reason the reference could not be authorized or read.
    fn read(
        &self,
        declaring_file: &str,
        reference: &str,
    ) -> Result<ComposeResolvedFile, ComposeFileReadError>;

    /// Reads an auxiliary env or label file when the caller explicitly grants
    /// that separate authority. The default refuses it.
    ///
    /// # Errors
    ///
    /// Returns the reason the referenced file cannot be read.
    fn read_auxiliary(
        &self,
        _declaring_file: &str,
        _reference: &str,
    ) -> Result<ComposeResolvedFile, ComposeFileReadError> {
        Err(ComposeFileReadError::Refused)
    }

    /// Expands a glob relative to its declaring file.
    ///
    /// Each returned file must obey the same policy as [`Self::read`] and have
    /// the same stable identity as an exact read. Return files in deterministic
    /// path order and return [`ComposeFileReadError::NotFound`] for no matches.
    ///
    /// # Errors
    ///
    /// Returns the reason the pattern or any matching file was refused.
    fn glob(
        &self,
        declaring_file: &str,
        pattern: &str,
    ) -> Result<Vec<ComposeResolvedFile>, ComposeFileReadError>;
}
