//! How the managed Engine SSH client proves who it is, and what it must never
//! print while doing it.
//!
//! The managed client in [`super::ssh_neotales`] speaks a transport, not a
//! console. That is the whole reason a password and a key passphrase are
//! **caller-supplied values** rather than something this crate asks for: a
//! library that blocked on a terminal prompt inside a request would hang in
//! exactly the situation a caller cannot interrupt — a daemon, a CI job, a
//! server. So the answer to "where does the secret come from" is the caller, and
//! this module is the boundary that keeps it the caller's.
//!
//! Three rules hold here, and each is asserted in
//! `tests/debug_surface.rs` rather than argued for in a comment:
//!
//! * a secret is redacted from `Debug` *and* from `Display`. `Debug` is the one
//!   that leaks — it is a panic message, a test failure, and a log line — but a
//!   credential that renders in `format!("{credential}")` is one `{}` away from
//!   a log line, and this crate has already leaked a credential three times.
//! * a secret is zeroized when the value is dropped.
//! * a secret never becomes a `RawRequest`. It goes into the SSH
//!   authenticator and nowhere else, so there is no query, no header, and
//!   nothing for `RawRequest`'s own redaction to have to catch. That is why no
//!   entry was added to `raw::transport`'s credential-header list: this secret
//!   is not an Engine credential and never goes near the wire the Engine sees.
//!
//! The two private secret holders in `credentials.rs` and `proxy.rs` are
//! different things and this is not a third of either. Those wrap a value the
//! crate discovered and uses internally; [`SshSecret`] is a value the *caller*
//! hands in, holds, and is responsible for. It has to be nameable in a public
//! signature for that to work, which is why it is public and those are not.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::Error;

/// A local, content-free managed SSH host-key refusal.
///
/// Available through [`Error::managed_ssh_host_key_rejection`]. No variant
/// contains a key, hostname, path or peer-supplied text. A refusal never
/// provisions or changes trust; the administrator must reconcile it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSshHostKeyRejection {
    /// No applicable host entry exists; provision trust before connecting.
    Unknown,
    /// A recorded host key does not match; investigate before replacing trust.
    Changed,
    /// The offered host key is explicitly revoked.
    Revoked,
    /// Only a CA entry matches; this client requires a plain host-key entry.
    CertificateAuthorityOnly,
}

impl fmt::Display for ManagedSshHostKeyRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => {
                "SSH host-key refusal: unknown host; provision trust before connecting"
            }
            Self::Changed => {
                "SSH host-key refusal: recorded key changed; investigate before replacing trust"
            }
            Self::Revoked => "SSH host-key refusal: recorded key revoked",
            Self::CertificateAuthorityOnly => {
                "SSH host-key refusal: CA-only entry; a plain host-key entry is required"
            }
        })
    }
}

impl std::error::Error for ManagedSshHostKeyRejection {}

/// A content-free managed SSH establishment classification.
///
/// No variant retains paths, credentials, algorithms or peer text. Other
/// establishment failures remain unclassified; host-key and timeout markers
/// have their own accessors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManagedSshEstablishmentFailure {
    /// Authentication ended after a validated server authentication-failure
    /// response. This does not prove that a password is wrong.
    AuthenticationRejected,
    /// No usable authentication method or signature algorithm remained, without
    /// an observed server authentication-failure response. A key may never have
    /// been offered.
    NoUsableAuthenticationMethod,
    /// The authenticated peer refused the session-channel open. Its description,
    /// language and numeric reason are discarded.
    ChannelOpenRefused,
    /// Local identity material could not be read, parsed or decrypted, or
    /// exceeded a policy limit. This does not diagnose a wrong passphrase.
    IdentityFile,
}

impl fmt::Display for ManagedSshEstablishmentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationRejected => "managed SSH authentication was rejected by the server",
            Self::NoUsableAuthenticationMethod => {
                "managed SSH has no usable authentication method or signature algorithm"
            }
            Self::ChannelOpenRefused => {
                "managed SSH session-channel open was refused; peer text withheld"
            }
            Self::IdentityFile => {
                "managed SSH identity file could not be used; file details withheld"
            }
        })
    }
}

impl std::error::Error for ManagedSshEstablishmentFailure {}

impl Error {
    /// Whether the managed SSH server refused the offered authentication.
    ///
    /// This does not establish that a password is wrong: server account/method
    /// policy or unmet authentication requirements can also prevent acceptance.
    /// A validated server failure response is required. A key skipped before
    /// offering it is [`ManagedSshEstablishmentFailure::NoUsableAuthenticationMethod`],
    /// not a server rejection.
    /// It is distinct from timeouts, host-key refusals, malformed authentication
    /// responses and channel/exec failures. The classification survives worker,
    /// raw transport and withholding boundaries without retaining peer text or
    /// the old source chain. A propagated marker need not belong to this request.
    #[must_use]
    pub fn is_managed_ssh_authentication_rejected(&self) -> bool {
        self.managed_ssh_establishment_failure()
            == Some(ManagedSshEstablishmentFailure::AuthenticationRejected)
    }

    /// Returns a safe local establishment classification, when available.
    ///
    /// Distinguishes server authentication rejection, unavailable methods,
    /// channel-open refusal and local identity-file failure. Markers survive
    /// worker/raw/withholding boundaries without the old source chain. A marker
    /// can be propagated from an earlier request and is not proof of its outcome.
    #[must_use]
    pub fn managed_ssh_establishment_failure(&self) -> Option<ManagedSshEstablishmentFailure> {
        self.source.as_ref()?.downcast_ref().copied()
    }

    pub(crate) fn ssh_establishment_failed(reason: ManagedSshEstablishmentFailure) -> Self {
        Self {
            kind: crate::ErrorKind::Transport,
            source: Some(Box::new(reason)),
            api: None,
        }
    }

    /// Returns the safe local host-key refusal classification for managed SSH.
    ///
    /// `None` includes other handshake failures and an explicitly closed managed
    /// gate; it is not evidence of accepted host trust. The classification
    /// survives the managed handshake, worker and raw transport boundaries.
    /// For these refusals the immediate source is [`ManagedSshHostKeyRejection`],
    /// not [`std::io::Error`].
    #[must_use]
    pub fn managed_ssh_host_key_rejection(&self) -> Option<ManagedSshHostKeyRejection> {
        self.source.as_ref()?.downcast_ref().copied()
    }

    pub(crate) fn ssh_host_key_rejected(reason: ManagedSshHostKeyRejection) -> Self {
        Self {
            kind: crate::ErrorKind::Transport,
            source: Some(Box::new(reason)),
            api: None,
        }
    }
}

/// What `Debug` and `Display` print in place of a secret.
///
/// Named rather than written inline so the redaction in the `Debug` surface
/// suite has a literal to search for: a test that asserts "the output does not
/// contain the secret" passes just as happily against a `Debug` that prints
/// nothing at all, and one that asserts the marker *is* present cannot.
pub(crate) const REDACTED: &str = "[REDACTED]";

/// A secret the caller supplies to the managed Engine SSH client.
///
/// Used for an SSH password and for the passphrase on an encrypted identity
/// file. `Debug` and `Display` both print `[REDACTED]`, the value is zeroized
/// when the value is dropped, and nothing in this crate ever puts it in a
/// `RawRequest`.
///
/// `Clone` is implemented and is not a mistake: the options struct is cloned
/// once per request, and refusing to clone would mean either a
/// reference-counted secret or a factory that cannot be `Send`. The copies are
/// zeroized the same way the original is.
///
/// The secret is exposed through [`SshSecret::expose`], which is named for what
/// it does. There is no `Deref`, no `AsRef<str>`, and no accessor that returns
/// a `&String`, so a value cannot reach a format argument or a log by accident
/// through a trait that reads as ordinary data.
#[derive(Clone, Eq, PartialEq)]
pub struct SshSecret(Zeroizing<String>);

impl SshSecret {
    /// Wraps a value the caller already has.
    ///
    /// The caller keeps ownership of whatever produced the value; this is a
    /// copy that is zeroized on drop, and the caller's own copy is its own
    /// business.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Returns the secret.
    ///
    /// Every call site is the transport handing the value to
    /// `neotales-ssh`. There is no other reason to call this, and it is public
    /// only because a caller building its own [`SshIdentity`] may need it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns a copy of the secret in the mutable buffer `OpenSshPrivateKey`
    /// zeroizes in place.
    ///
    /// `neotales-ssh`'s key parser takes `&mut [u8]` and promises to zeroize it
    /// before returning, so a passphrase is passed as a throwaway buffer rather
    /// than as the secret's own storage. Reusing `SshSecret`'s storage would
    /// hand the parser a slice of a value that is still live afterwards, and the
    /// promise would be about a copy rather than the secret.
    pub(crate) fn expose_throwaway(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.as_bytes().to_vec())
    }
}

impl fmt::Debug for SshSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Display for SshSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl From<&str> for SshSecret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SshSecret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// The credential the managed Engine SSH client authenticates with.
///
/// One enum rather than a field per mechanism on the options struct, because the
/// mechanisms are *alternatives* and a struct with four `Option`s has sixteen
/// states of which three are meaningful. A caller names exactly one.
///
/// An encrypted identity file is a separate variant rather than a flag on
/// [`SshIdentity::KeyFile`] because a passphrase is a secret and a
/// `Option<SshSecret>` in a public field is a secret a caller can forget to
/// redact in their own `Debug`. Naming it in the variant means the type system
/// says the difference out loud.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshIdentity {
    /// A private key file, unencrypted.
    KeyFile(PathBuf),
    /// A private key file and the passphrase that decrypts it.
    EncryptedKeyFile {
        /// The private key file to read.
        path: PathBuf,
        /// The passphrase for the key file.
        passphrase: SshSecret,
    },
    /// An SSH password, sent with the `password` method.
    ///
    /// Up front, by design. The alternative — a callback this crate invokes
    /// when the server answers `SSH_MSG_USERAUTH_FAILURE` — is what OpenSSH
    /// does, and it is refused here for the reason in this module's
    /// documentation: the prompt belongs to whoever is driving the program, not
    /// to a request already in flight on someone else's task.
    Password(SshSecret),
}

impl SshIdentity {
    /// Names the mechanism, for a diagnostic. Never the value.
    pub(crate) fn mechanism(&self) -> &'static str {
        match self {
            Self::KeyFile(_) => "an identity file",
            Self::EncryptedKeyFile { .. } => "an encrypted identity file",
            Self::Password(_) => "a password",
        }
    }
}

/// A managed `neotales-ssh` connection to a remote Engine, under construction.
///
/// Built by [`crate::DockerClient::connect_ssh_managed`]. Every setting has a
/// defined default and every one of them is a method rather than a positional
/// parameter: the set of things a caller may need to say about an `ssh://`
/// endpoint — who, which key or password, which known-hosts file, how long to
/// wait, and whether to reuse connections — is five settings, and a
/// five-argument constructor whose fifth argument is a password is a signature
/// nobody reads correctly. There is deliberately no connection-reuse setting on
/// it: see the `ssh_neotales` module's own documentation for the two
/// mechanisms that were considered and the one reason neither is offered.
///
/// # What is not a default
///
/// The credential. There is no `identity_file` default and no reading of the
/// invoking user's `~/.ssh`, because the reason this mechanism exists is to be
/// explicit about host keys and about who is authenticating. A client built
/// without a credential is refused on first use, with a message naming what to
/// set — see [`SshIdentity`] for the three that exist.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct ManagedSshClient {
    endpoint: String,
    known_hosts_path: PathBuf,
    timeout: Duration,
    write_inactivity_timeout: Duration,
    request_deadline: Option<Duration>,
    require_closed: bool,
    identity: Option<SshIdentity>,
}

impl ManagedSshClient {
    /// Starts from an endpoint and the known-hosts file to check it against.
    ///
    /// The timeout defaults to thirty seconds and the connection policy to one
    /// connection per request, so the two settings a caller almost always wants
    /// are the two that are already right.
    pub(crate) fn new(endpoint: &str, known_hosts_path: &Path) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            known_hosts_path: known_hosts_path.to_path_buf(),
            timeout: Duration::from_secs(30),
            write_inactivity_timeout: crate::ssh_neotales::WRITE_STALL_BOUND,
            request_deadline: None,
            require_closed: false,
            identity: None,
        }
    }

    /// Sets the establishment timeout (default 30 seconds). It covers dialing,
    /// handshake, authentication and exec, not the subsequent request or body.
    /// Raise it for an establishment timeout; it is not a total deadline.
    /// It does not cover the response head or body after establishment.
    /// Failures retain [`crate::TransportTimeoutKind::ManagedSshEstablishment`]
    /// through every managed operation's withholding policy; they also satisfy
    /// [`Error::is_transport_deadline`].
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the SSH write-inactivity bound (default 120 seconds). It applies
    /// only while a reply or rekey is blocked on socket writes, resets on
    /// positive bytes, and is not a total deadline. Raise it if the session
    /// reports that the socket accepted no write bytes.
    /// Failures retain [`crate::TransportTimeoutKind::ManagedSshWriteInactivity`],
    /// distinct from a total deadline; [`Error::is_transport_deadline`] is false.
    pub fn write_inactivity_timeout(mut self, timeout: Duration) -> Self {
        self.write_inactivity_timeout = timeout;
        self
    }

    /// Refuses every managed request before DNS, file access or network work.
    ///
    /// The gate is open by default. This explicit per-client closure also
    /// applies to cloned clients and their raw engines; it never selects native
    /// `ssh` as a fallback.
    pub fn require_closed(mut self) -> Self {
        self.require_closed = true;
        self
    }

    /// Sets an optional total request deadline (default none), from connection
    /// through the response head, including establishment and uploads but not
    /// the response body. It expires even with continuous progress. Raise it
    /// for an Engine request deadline error, not a write-inactivity error. A
    /// timed-out request may already have been processed; reconcile its outcome
    /// before retrying.
    /// Without this deadline a silent peer can leave a request waiting for a
    /// response head indefinitely; the other two timeouts do not bound that wait.
    /// Expiration retains [`crate::TransportTimeoutKind::RequestDeadline`], not
    /// the managed establishment or write-inactivity classification.
    pub fn request_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.request_deadline = deadline;
        self
    }

    /// Authenticates with an unencrypted private key file.
    pub fn identity_file(self, path: &Path) -> Self {
        self.identity(SshIdentity::KeyFile(path.to_path_buf()))
    }

    /// Authenticates with an encrypted private key file and its passphrase.
    ///
    /// The passphrase is a value, not a prompt. See this module's documentation
    /// for why: the managed client speaks a transport and not a console.
    pub fn identity_file_with_passphrase(self, path: &Path, passphrase: SshSecret) -> Self {
        self.identity(SshIdentity::EncryptedKeyFile {
            path: path.to_path_buf(),
            passphrase,
        })
    }

    /// Authenticates with an SSH password.
    ///
    /// [`Error::is_managed_ssh_authentication_rejected`] distinguishes server
    /// refusal; it does not prove the password is wrong rather than that the
    /// server's authentication policy refused the offered mechanism.
    ///
    /// The opt-in no-socket fixture requires `NEOTALES_DOCKER_OPENSSH_PASSWORD=1`
    /// and a Docker daemon; it was verified locally against OpenSSH 9.2. It is
    /// not in the default gate and does not prove PAM or real Docker `dial-stdio`.
    pub fn password(self, password: SshSecret) -> Self {
        self.identity(SshIdentity::Password(password))
    }

    /// Replaces the credential, which is what each of the three above does.
    pub fn identity(mut self, identity: SshIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Builds the client without connecting.
    ///
    /// The gate is open by default: requests can resolve, dial, read
    /// `known_hosts` and identity material, handshake, authenticate, run
    /// `docker system dial-stdio` remotely and carry Engine requests. Building
    /// the client performs none of that work. [`Self::require_closed`] refuses
    /// requests before DNS, file or network work.
    ///
    /// The three timeout policies are independent: [`Self::timeout`] defaults
    /// to 30 seconds for establishment; [`Self::write_inactivity_timeout`]
    /// defaults to 120 seconds while a reply or rekey write is blocked;
    /// [`Self::request_deadline`] defaults to none and bounds connection through
    /// the response head, excluding the body. Without `request_deadline`, a
    /// silent peer can leave a request waiting for a response head indefinitely.
    /// A peer interleaving control traffic with a blocked write is a bounded
    /// failure, not a hang: it reaches the write-inactivity bound and the
    /// session fails closed.
    ///
    /// The opt-in no-socket password fixture requires
    /// `NEOTALES_DOCKER_OPENSSH_PASSWORD=1` and a Docker daemon. Verified locally
    /// against OpenSSH 9.2, it is not in the default gate and does not prove PAM
    /// or real Docker `dial-stdio`.
    /// Native `ssh` remains a separate, explicit choice; managed failures never
    /// silently downgrade to it.
    ///
    /// The managed target carries a content-free response diagnostic policy
    /// for every Engine operation, including raw requests and streaming
    /// failures. It preserves HTTP rejection status, typed timeout kinds and
    /// safe host-key classification, but never promotes peer failure text into
    /// an error or source. Wording may be operation-specific: some
    /// operations use their own fixed content-free errors. The shared response
    /// policy uses `managed SSH Engine <METHOD> operation failed
    /// (HTTP <STATUS>); response text withheld`. Here the operation is a fixed
    /// HTTP method label (`custom-method` for extension methods), not a path or
    /// query.
    /// This is stricter than native SSH because managed SSH carries arbitrary
    /// Engine traffic, including secret-bearing request bodies. Raw response
    /// data and successful values remain caller-visible, not sanitized.
    ///
    /// Local host-key refusals retain [`ManagedSshHostKeyRejection`] through
    /// [`Error::managed_ssh_host_key_rejection`]; no peer text or key is included.
    /// Authentication refusals retain [`Error::is_managed_ssh_authentication_rejected`],
    /// not peer text. [`Error::managed_ssh_establishment_failure`] separately
    /// identifies unavailable methods/signature algorithms, channel-open refusal
    /// and local identity-file failures; details and paths are withheld.
    /// The handshake requests RFC 8308 `server-sig-algs` to negotiate signature
    /// compatibility before offering a key.
    ///
    /// # Errors
    ///
    /// Returns an error when no credential was named, when the endpoint is not
    /// an `ssh://` address or names no login user, or when a configured timeout
    /// is zero or out of range. Each of those is reported separately
    /// rather than as one "incomplete configuration", because a caller who set
    /// three of the four needs to be told which one is wrong.
    pub fn connect(self) -> Result<crate::DockerClient, Error> {
        let identity = self.identity.clone().ok_or_else(|| {
            Error::invalid_input(
                "the managed Engine SSH client was given no credential; set one with \
                 identity_file, identity_file_with_passphrase, or password",
            )
        })?;
        let mut options = crate::ssh_neotales::ManagedSshOptions::from_endpoint(
            &self.endpoint,
            identity,
            Some(&self.known_hosts_path),
            self.timeout,
        )?;
        options.write_inactivity_timeout = self.write_inactivity_timeout;
        options.request_deadline = self.request_deadline;
        options.require_closed = self.require_closed;
        options.validate()?;
        crate::DockerClient::connect_ssh_managed_inner(options)
    }
}

#[cfg(test)]
mod tests {
    use super::{SshIdentity, SshSecret};

    /// The canary is what a leak would carry, and the assertion is that neither
    /// rendering contains it. Both are checked because a secret that is redacted
    /// in `Debug` and printed by `Display` is one `{}` away from a log line.
    #[test]
    fn a_secret_renders_as_a_redaction_and_nothing_else() {
        const CANARY: &str = "canary-ssh-secret-2b7f41c9-do-not-log-me";
        let secret = SshSecret::new(CANARY);

        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        for rendered in [&debug, &display] {
            assert!(
                !rendered.contains(CANARY),
                "a secret rendered in {rendered:?}"
            );
            assert!(
                rendered.contains("[REDACTED]"),
                "the redaction has to be visible rather than an omission: {rendered:?}"
            );
        }
    }

    /// The secret is the caller's to read back, so `expose` has to work — and
    /// this is the check that it is the *only* way out. A `Deref<Target = str>`
    /// or an `AsRef<str>` here would put the value back within reach of a
    /// `{}`.
    #[test]
    fn a_secret_is_readable_only_by_asking_for_it_explicitly() {
        let secret = SshSecret::from("hunter2");
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(SshSecret::from(String::from("hunter2")), secret);
    }

    /// Every variant has to name a mechanism, because the mechanism is what a
    /// failed authentication has to say. The value is never in it.
    #[test]
    fn an_identity_names_its_mechanism_and_never_its_secret() {
        const CANARY: &str = "canary-ssh-passphrase-6d0a5e13-do-not-log-me";
        let identity = SshIdentity::EncryptedKeyFile {
            path: "/keys/id_ed25519".into(),
            passphrase: SshSecret::new(CANARY),
        };
        let rendered = format!("{identity:?}");

        assert!(
            !rendered.contains(CANARY),
            "the passphrase leaked: {rendered}"
        );
        assert_eq!(identity.mechanism(), "an encrypted identity file");
        assert_eq!(
            SshIdentity::Password(SshSecret::new("x")).mechanism(),
            "a password"
        );
    }

    /// A builder with nothing set is refused when it is built, not when it is
    /// first used, and the message names the three calls that would work — a
    /// caller who forgot one setting should not have to make a request to find
    /// out which.
    #[test]
    fn a_managed_client_with_no_credential_names_the_three_ways_to_set_one() {
        let error = crate::DockerClient::connect_ssh_managed(
            "ssh://deploy@example.test",
            std::path::Path::new("/keys/known_hosts"),
        )
        .connect()
        .expect_err("a client with no credential must be refused");
        let rendered = error.to_string();
        for setting in ["identity_file", "identity_file_with_passphrase", "password"] {
            assert!(
                rendered.contains(setting),
                "the refusal must name {setting}: {rendered}"
            );
        }
    }
}

#[cfg(test)]
mod timeout_policy_tests {
    use super::ManagedSshClient;
    use std::{path::Path, time::Duration};

    fn client() -> ManagedSshClient {
        ManagedSshClient::new("ssh://user@localhost", Path::new("known_hosts"))
            .password("test".into())
    }

    #[test]
    fn rejects_invalid_named_timeouts() {
        for value in [Duration::ZERO, Duration::MAX] {
            for (name, builder) in [
                (
                    "write_inactivity_timeout",
                    client().write_inactivity_timeout(value),
                ),
                ("request_deadline", client().request_deadline(Some(value))),
                ("establishment_timeout", client().timeout(value)),
            ] {
                let error = builder.connect().unwrap_err().to_string();
                assert!(error.contains(name), "{name}: {error}");
            }
        }
    }

    #[test]
    fn defaults_and_explicit_deadline_reach_the_owned_engine() {
        let default = client();
        assert_eq!(default.timeout, Duration::from_secs(30));
        assert_eq!(default.write_inactivity_timeout, Duration::from_secs(120));
        assert_eq!(default.request_deadline, None);
        assert_eq!(
            default
                .connect()
                .unwrap()
                .raw_engine()
                .unwrap()
                .overall_request_deadline(),
            None
        );
        let deadline = Duration::from_millis(300);
        assert_eq!(
            client()
                .request_deadline(Some(deadline))
                .connect()
                .unwrap()
                .raw_engine()
                .unwrap()
                .overall_request_deadline(),
            Some(deadline)
        );
    }

    #[tokio::test]
    async fn total_deadline_expires_while_response_bytes_trickle() {
        trickling_response_deadline(false).await;
    }

    #[tokio::test]
    async fn total_deadline_also_bounds_upgrades() {
        trickling_response_deadline(true).await;
    }

    #[tokio::test]
    async fn total_deadline_includes_connection() {
        let mut client = client()
            .request_deadline(Some(Duration::from_millis(40)))
            .connect()
            .unwrap();
        let crate::OwnedTarget::ManagedSsh(target, _, _) = &mut client.raw_target else {
            panic!("managed target")
        };
        *target = crate::raw::RawTarget::Stream {
            authority: "engine.invalid".to_owned(),
            open: crate::raw::StreamFactory::from_fn(|| async {
                std::future::pending::<Result<Box<dyn crate::raw::Duplex>, crate::Error>>().await
            }),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client
                .raw_engine()
                .unwrap()
                .send(crate::raw::RawRequest::new(http::Method::GET, "/info")),
        )
        .await
        .expect("request hung");
        let Err(error) = result else {
            panic!("deadline should expire");
        };
        assert!(error.to_string().contains("timed out after"), "{error}");
    }

    async fn trickling_response_deadline(upgrade: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" {
                if socket.write_all(&[*byte]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        let deadline = Duration::from_millis(180);
        let mut client = client().request_deadline(Some(deadline)).connect().unwrap();
        let crate::OwnedTarget::ManagedSsh(target, _, _) = &mut client.raw_target else {
            panic!("managed target")
        };
        *target = crate::raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        };
        let engine = client.raw_engine().unwrap();
        let request = crate::raw::RawRequest::new(http::Method::GET, "/info");
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            if upgrade {
                engine.send_upgrading(request).await
            } else {
                engine.send(request).await
            }
        })
        .await
        .expect("request hung");
        let Err(error) = result else {
            panic!("deadline should expire");
        };
        assert!(error.to_string().contains("timed out after"), "{error}");
        server.abort();
    }
}
