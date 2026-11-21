//! Explicit HTTP forward-proxy policy and Hyper 1 transport support.
//!
//! Proxy routing is deliberately opt-in. This module never reads
//! `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, or container/build
//! environment variables. The only supported proxy URL is an explicit HTTP
//! proxy. Plain HTTP Engine requests use absolute-form forwarding; HTTPS
//! Engine endpoints use an HTTP `CONNECT` tunnel before TLS is negotiated.
//! The owned route preserves the daemon authority and `Host`, applies one
//! 120-second overall budget, and has no direct fallback. Only the configured
//! proxy credential is sent; caller-supplied `Proxy-Authorization` is rejected.
//! WebSocket and h2c support are outside this transport's current scope.

use std::fmt;
#[cfg(feature = "tls")]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::header::HeaderValue;
#[cfg(test)]
use hyper_util::client::legacy::connect::HttpConnector;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
#[cfg(feature = "tls")]
use std::fs::File;
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "tls")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(feature = "tls")]
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio_rustls::TlsConnector;

use crate::DEFAULT_TIMEOUT_SECONDS;
use crate::Error;
#[cfg(feature = "tls")]
use crate::TlsMaterial;
#[cfg(feature = "tls")]
use crate::raw::{Duplex, StreamFactory};
use crate::raw::{HttpProxyRoute, RawTarget};

/// Explicit server-certificate trust policy; never selected from the environment.
///
/// The opt-out is deliberately feature-gated; rustdoc compiles this example when
/// doctests are run with the crate's `tls` feature enabled.
///
/// ```rust,no_run
/// # fn example(material: &neotales_docker::TlsMaterial) -> Result<(), neotales_docker::Error> {
/// use neotales_docker::{DockerClient, ProxyPolicy, TlsServerTrust};
///
/// let client = DockerClient::connect_https_with_trust(
///     "https://docker.example:2376",
///     material,
///     ProxyPolicy::Direct,
///     TlsServerTrust::AllowExpiredOrUntrusted,
/// )?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "tls")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TlsServerTrust {
    /// Verify certificate trust, validity times, and the server hostname.
    ///
    /// Trust is the union of the platform root store and the CA bundle in the
    /// `TlsMaterial`; the supplied bundle is required but is not an exclusive
    /// pin.
    #[default]
    Verify,
    /// Accept expired or untrusted certificates, but require parseable certificates
    /// and valid TLS handshake signatures. Also bypasses hostname checks: an
    /// untrusted certificate has no name to trust. This permits impersonation;
    /// use only when the caller explicitly accepts that risk.
    AllowExpiredOrUntrusted,
}

/// Maximum accepted length of an explicit proxy URL, in bytes.
pub const MAX_PROXY_URL_BYTES: usize = 2048;
/// Maximum accepted length of a Basic proxy username, in bytes.
pub const MAX_PROXY_USERNAME_BYTES: usize = 256;
/// Maximum accepted length of a Basic proxy password, in bytes.
pub const MAX_PROXY_PASSWORD_BYTES: usize = 4096;
/// Maximum accepted length of the generated Proxy-Authorization header.
pub const MAX_PROXY_AUTHORIZATION_BYTES: usize = 8192;

/// Maximum bytes read while waiting for an HTTP proxy's CONNECT response head.
///
/// This bounds the proxy's answer, not the tunnel that follows it. A proxy that
/// never terminates its response headers is refused at this limit rather than
/// being allowed to grow the client's buffer.
#[cfg(feature = "tls")]
const MAX_CONNECT_RESPONSE_HEADER_BYTES: usize = 8192;

/// The TLS material role that failed to load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMaterialRole {
    /// The CA bundle used to verify the server.
    Ca,
    /// The client certificate presented to the server.
    Cert,
    /// The client private key.
    Key,
    /// The combined client-auth certificate and key.
    ClientAuth,
    /// The TLS protocol-version configuration.
    ProtocolVersions,
}

impl fmt::Display for TlsMaterialRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ca => "CA bundle",
            Self::Cert => "client certificate",
            Self::Key => "client key",
            Self::ClientAuth => "client authentication",
            Self::ProtocolVersions => "protocol version",
        })
    }
}

/// The safe, content-free reason a TLS material role failed.
///
/// This deliberately carries no file path, PEM text, key bytes, or parser
/// payload. A caller gets the role and the kind of failure; the detail that
/// could contain sensitive material stays out of every error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMaterialSource {
    /// A file could not be opened, with the standard I/O error kind.
    Open(std::io::ErrorKind),
    /// A file opened but could not be read, with the standard I/O error kind.
    Read(std::io::ErrorKind),
    /// The material could not be parsed as the expected PEM shape.
    Parse,
    /// The material parsed but contained an invalid entry.
    Invalid,
    /// The material parsed but contained no usable entry.
    Empty,
    /// The key file contained more than one key.
    MultipleKeys,
    /// The material parsed but the TLS client configuration rejected it.
    Configuration,
}

impl fmt::Display for TlsMaterialSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(kind) => write!(formatter, "could not be opened ({kind:?})"),
            Self::Read(kind) => write!(formatter, "could not be read ({kind:?})"),
            Self::Parse => formatter.write_str("could not be parsed"),
            Self::Invalid => formatter.write_str("contains an invalid entry"),
            Self::Empty => formatter.write_str("is empty"),
            Self::MultipleKeys => formatter.write_str("contains more than one key"),
            Self::Configuration => formatter.write_str("could not be configured"),
        }
    }
}

/// A TLS material failure with its role and a content-free source.
///
/// This is the source of the crate's [`crate::Error`] for a TLS material
/// failure. The error kind remains [`crate::ErrorKind::Proxy`], so the existing
/// public enum shapes are preserved; callers that need the detail downcast the
/// source to this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsConfigError {
    /// The material or configuration role that failed.
    pub role: TlsMaterialRole,
    /// The safe, content-free reason.
    pub source: TlsMaterialSource,
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Docker TLS {} {}", self.role, self.source)
    }
}

impl std::error::Error for TlsConfigError {}

/// Errors returned while validating or applying explicit proxy policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyError {
    /// The proxy URL was not a valid absolute URL.
    InvalidUrl,
    /// The Docker TCP endpoint was not a valid absolute URL.
    InvalidEndpointUrl,
    /// Only `http://` proxy URLs are supported.
    UnsupportedScheme,
    /// Proxy credentials must not be embedded in a URL.
    CredentialsInUrl,
    /// A proxy URL must address the proxy root and contain no path.
    UrlPathNotAllowed,
    /// A proxy URL must not contain a query or fragment.
    QueryOrFragment,
    /// The proxy URL exceeded its bounded input size.
    UrlTooLong {
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The proxy URL did not contain a host.
    MissingHost,
    /// The Docker endpoint was not an HTTP or HTTPS TCP endpoint.
    EndpointNotProxyable,
    /// The Docker endpoint scheme is not valid for the selected HTTP policy.
    UnsupportedEndpointScheme,
    /// The Docker endpoint contained a path that is not valid for a daemon
    /// origin.
    EndpointPathNotAllowed,
    /// A proxy username was empty or contained the Basic separator colon.
    InvalidUsername,
    /// Proxy authentication contained a control character.
    CredentialControlCharacter,
    /// One proxy authentication component exceeded its bound.
    CredentialComponentTooLong {
        /// Component name (`username` or `password`).
        component: &'static str,
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The generated proxy authorization header exceeded its bound.
    AuthorizationHeaderTooLong {
        /// Maximum accepted byte length.
        max: usize,
    },
    /// The generated proxy authorization header was not a valid HTTP header.
    AuthorizationHeaderInvalid,
    /// TLS material could not be loaded into a verifying rustls client.
    ///
    /// Retained for compatibility with callers that already match this variant.
    /// New CA, certificate, and key failures are returned as [`TlsConfigError`]
    /// through [`crate::Error`]'s source chain.
    TlsConfiguration,
    /// the former generated client could not initialize the custom transport.
    TransportInitialization,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl => write!(formatter, "Docker proxy URL is not a valid URL"),
            Self::InvalidEndpointUrl => {
                write!(formatter, "Docker TCP endpoint is not a valid URL")
            }
            Self::UnsupportedScheme => {
                write!(formatter, "Docker proxy URL must use the http scheme")
            }
            Self::CredentialsInUrl => {
                write!(formatter, "Docker proxy URL must not contain credentials")
            }
            Self::UrlPathNotAllowed => {
                write!(formatter, "Docker proxy URL must not contain a path")
            }
            Self::QueryOrFragment => {
                write!(
                    formatter,
                    "Docker proxy URL must not contain a query or fragment"
                )
            }
            Self::UrlTooLong { max } => {
                write!(formatter, "Docker proxy URL exceeds {max} bytes")
            }
            Self::MissingHost => write!(formatter, "Docker proxy URL has no host"),
            Self::EndpointNotProxyable => {
                write!(
                    formatter,
                    "HTTP proxy policy applies only to TCP Docker endpoints"
                )
            }
            Self::UnsupportedEndpointScheme => write!(
                formatter,
                "Docker endpoint scheme is not valid for the selected HTTP policy"
            ),
            Self::EndpointPathNotAllowed => {
                write!(formatter, "Docker TCP endpoint must not contain a path")
            }
            Self::InvalidUsername => {
                write!(
                    formatter,
                    "Docker proxy username is empty or contains a colon"
                )
            }
            Self::CredentialControlCharacter => {
                write!(
                    formatter,
                    "Docker proxy authentication contains a control character"
                )
            }
            Self::CredentialComponentTooLong { component, max } => {
                write!(formatter, "Docker proxy {component} exceeds {max} bytes")
            }
            Self::AuthorizationHeaderTooLong { max } => write!(
                formatter,
                "Docker proxy authorization header exceeds {max} bytes"
            ),
            Self::AuthorizationHeaderInvalid => {
                write!(formatter, "Docker proxy authorization header is invalid")
            }
            Self::TlsConfiguration => {
                write!(formatter, "Docker TLS material could not be configured")
            }
            Self::TransportInitialization => {
                write!(formatter, "Docker proxy transport could not be initialized")
            }
        }
    }
}

impl std::error::Error for ProxyError {}

/// A bounded, redacted Basic-auth value for an HTTP proxy.
///
/// Only Basic authentication is accepted by this small explicit policy. The
/// password is zeroized when the value is dropped, and both fields are
/// redacted from `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyCredentials {
    username: String,
    password: SecretString,
}

impl ProxyCredentials {
    /// Creates bounded Basic proxy credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or colon-containing username, control
    /// characters, or a component larger than its documented bound.
    pub fn basic(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let username = username.into();
        let password = password.into();

        if username.is_empty() || username.contains(':') {
            return Err(ProxyError::InvalidUsername);
        }
        validate_credential_component("username", &username, MAX_PROXY_USERNAME_BYTES)?;
        validate_credential_component("password", &password, MAX_PROXY_PASSWORD_BYTES)?;

        Ok(Self {
            username,
            password: SecretString(password),
        })
    }

    fn authorization(&self) -> Result<HeaderValue, ProxyError> {
        let raw = Zeroizing::new(format!("{}:{}", self.username, self.password.0));
        let encoded = STANDARD.encode(raw.as_bytes());
        let value = format!("Basic {encoded}");
        if value.len() > MAX_PROXY_AUTHORIZATION_BYTES {
            return Err(ProxyError::AuthorizationHeaderTooLong {
                max: MAX_PROXY_AUTHORIZATION_BYTES,
            });
        }

        let mut header =
            HeaderValue::from_str(&value).map_err(|_| ProxyError::AuthorizationHeaderInvalid)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct SecretString(String);

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn validate_credential_component(
    component: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ProxyError> {
    if value.len() > max {
        return Err(ProxyError::CredentialComponentTooLong { component, max });
    }
    if value.chars().any(char::is_control) {
        return Err(ProxyError::CredentialControlCharacter);
    }
    Ok(())
}

/// An explicitly configured HTTP forward proxy.
///
/// The URL is normalized and validated at construction. Proxy authentication
/// is optional and is never represented in the URL.
#[derive(Clone, Eq, PartialEq)]
pub struct ForwardProxy {
    address: String,
    credentials: Option<ProxyCredentials>,
}

impl ForwardProxy {
    /// Creates an explicit HTTP proxy without authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HTTP URL, embedded credentials, a path,
    /// query/fragment, missing host, or an overlong URL.
    pub fn new(address: impl Into<String>) -> Result<Self, ProxyError> {
        let address = normalize_proxy_url(&address.into())?;
        Ok(Self {
            address,
            credentials: None,
        })
    }

    /// Creates an explicit HTTP proxy with bounded Basic authentication.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid proxy URL or invalid credentials.
    pub fn with_basic_auth(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        let credentials = ProxyCredentials::basic(username, password)?;
        Self::new(address)?.with_credentials(credentials)
    }

    /// Adds bounded Basic authentication to this proxy.
    ///
    /// # Errors
    ///
    /// Returns an error only when the proxy has not passed URL validation.
    pub fn with_credentials(mut self, credentials: ProxyCredentials) -> Result<Self, ProxyError> {
        // `new` is the only public constructor, but retaining this check makes
        // the invariant explicit if another constructor is added later.
        let _ = normalize_proxy_url(&self.address)?;
        self.credentials = Some(credentials);
        Ok(self)
    }

    /// Returns the validated, credential-free proxy URL.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns whether Basic proxy authentication is configured.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    fn authorization(&self) -> Result<Option<HeaderValue>, ProxyError> {
        self.credentials
            .as_ref()
            .map(ProxyCredentials::authorization)
            .transpose()
    }
}

impl fmt::Debug for ForwardProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardProxy")
            .field("address", &self.address)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Explicit proxy selection for a Docker client.
///
/// `Direct` is the default and does not consult process proxy variables. The
/// `Http` variant is the only supported forward-proxy route. It is valid only
/// for `Endpoint::Http` and `Endpoint::Https`; callers receive a validation
/// error for Unix sockets, named pipes, and SSH rather than silently routing
/// those transports through an HTTP proxy.
#[derive(Clone, Default, Eq, PartialEq)]
pub enum ProxyPolicy {
    /// Connect directly to the selected Docker endpoint.
    #[default]
    Direct,
    /// Connect to a TCP Docker endpoint through the explicit HTTP proxy.
    ///
    /// The owned plain-HTTP route dials the proxy, sends the daemon's authority
    /// in absolute-form, and applies one 120-second overall request budget
    /// covering the proxy connect, request-body production/backpressure, and the
    /// response head. The response body is not wrapped by it. Only the configured
    /// proxy credential is sent on that route; a caller-supplied
    /// `Proxy-Authorization` is rejected. HTTPS keeps its `CONNECT` tunnel. The
    /// error-message withholding described on [`RawResponse`](crate::raw::RawResponse)
    /// applies to the owned raw route; an operation that still falls back to the
    /// generated client keeps the former generated client's error behavior.
    Http(ForwardProxy),
}

impl ProxyPolicy {
    /// Creates a direct policy.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Creates a policy for an explicit HTTP proxy.
    #[must_use]
    pub const fn http(proxy: ForwardProxy) -> Self {
        Self::Http(proxy)
    }

    /// Creates an HTTP proxy policy from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not a supported explicit HTTP proxy.
    pub fn from_http_url(address: impl Into<String>) -> Result<Self, ProxyError> {
        ForwardProxy::new(address).map(Self::Http)
    }

    /// Creates an authenticated HTTP proxy policy from a URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL or Basic credentials are invalid.
    pub fn with_basic_auth(
        address: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, ProxyError> {
        ForwardProxy::with_basic_auth(address, username, password).map(Self::Http)
    }

    /// Returns whether this policy selects a direct connection.
    #[must_use]
    pub const fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    /// Returns the configured forward proxy, if any.
    #[must_use]
    pub const fn forward_proxy(&self) -> Option<&ForwardProxy> {
        match self {
            Self::Direct => None,
            Self::Http(proxy) => Some(proxy),
        }
    }
}

impl fmt::Debug for ProxyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::Http(proxy) => formatter.debug_tuple("Http").field(proxy).finish(),
        }
    }
}

fn authority_contains_userinfo(address: &str) -> bool {
    address
        .split_once("://")
        .map_or_default(|(_, remainder)| remainder.split('/').next().unwrap_or_default())
        .contains('@')
}

fn normalize_proxy_url(address: &str) -> Result<String, ProxyError> {
    if address.is_empty() {
        return Err(ProxyError::InvalidUrl);
    }
    if address.len() > MAX_PROXY_URL_BYTES {
        return Err(ProxyError::UrlTooLong {
            max: MAX_PROXY_URL_BYTES,
        });
    }

    let url = Url::parse(address).map_err(|_| ProxyError::InvalidUrl)?;
    if url.scheme() != "http" {
        return Err(ProxyError::UnsupportedScheme);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::QueryOrFragment);
    }
    if url.path() != "/" {
        return Err(ProxyError::UrlPathNotAllowed);
    }
    if url.host_str().is_none() {
        return Err(ProxyError::MissingHost);
    }

    // `Url::username()` is empty both for no user-info and an explicitly
    // empty user. Inspect the authority as well so `http://@host` is not
    // accepted as a surprising credential-bearing form.
    if authority_contains_userinfo(address)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProxyError::CredentialsInUrl);
    }

    let normalized = url.to_string();
    if normalized.len() > MAX_PROXY_URL_BYTES {
        return Err(ProxyError::UrlTooLong {
            max: MAX_PROXY_URL_BYTES,
        });
    }
    Ok(normalized)
}

fn target_origin(address: &str, secure: bool) -> Result<String, ProxyError> {
    let mut url = Url::parse(address).map_err(|_| ProxyError::InvalidEndpointUrl)?;
    let original_scheme = url.scheme();
    let expected_schemes = if secure {
        ["https", "tcp"]
    } else {
        ["http", "tcp"]
    };
    if !expected_schemes.contains(&original_scheme) {
        return Err(ProxyError::UnsupportedEndpointScheme);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::QueryOrFragment);
    }
    if authority_contains_userinfo(address)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ProxyError::CredentialsInUrl);
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(ProxyError::EndpointPathNotAllowed);
    }
    if url.host_str().is_none() {
        return Err(ProxyError::MissingHost);
    }

    let scheme = if secure { "https" } else { "http" };
    url.set_scheme(scheme)
        .map_err(|()| ProxyError::UnsupportedScheme)?;
    let port = url.port_or_known_default().ok_or(ProxyError::MissingHost)?;
    let host = url.host_str().ok_or(ProxyError::MissingHost)?;
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(format!("{scheme}://{host}:{port}"))
}

/// Builds the owned transport's plain-HTTP proxy route.
///
/// The returned target keeps the daemon's host and port, so the owned request
/// carries the daemon's authority in both the absolute-form request line and
/// `Host`. The route carries the proxy's dial address, its optional
/// authorization header, and the 120-second overall request budget the generated
/// client previously applied to the same endpoint. The transport dials the proxy
/// instead of the daemon and never falls back to a direct connection.
pub(crate) fn raw_http_target(
    address: &str,
    proxy: &ForwardProxy,
) -> Result<(RawTarget, HttpProxyRoute), Error> {
    // Normalize exactly as the generated path does, so both routes agree that
    // `tcp://` becomes `http://` and a missing port takes the HTTP default.
    let target = target_origin(address, false)?;
    let target_url = Url::parse(&target).map_err(|_| ProxyError::InvalidEndpointUrl)?;
    let target_host = url_host(&target_url).ok_or(ProxyError::MissingHost)?;
    let target_port = target_url
        .port_or_known_default()
        .ok_or(ProxyError::MissingHost)?;

    let proxy_url = Url::parse(proxy.address()).map_err(|_| ProxyError::InvalidUrl)?;
    let proxy_host = url_host(&proxy_url).ok_or(ProxyError::MissingHost)?;
    let proxy_port = proxy_url
        .port_or_known_default()
        .ok_or(ProxyError::MissingHost)?;

    Ok((
        RawTarget::Tcp {
            host: target_host,
            port: target_port,
        },
        HttpProxyRoute::new(
            proxy_host,
            proxy_port,
            proxy.authorization()?,
            Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
        ),
    ))
}

#[cfg(feature = "tls")]
fn tls_config(
    material: &TlsMaterial,
    trust: TlsServerTrust,
) -> Result<Arc<rustls::ClientConfig>, TlsConfigError> {
    let mut roots = rustls::RootCertStore::empty();

    // Platform roots are added, and a store that only partly loads is tolerated
    // rather than fatal.
    //
    // `TlsMaterial` makes `ca_path` mandatory, so a caller always supplies the
    // authority the endpoint is expected to use. The platform store is
    // additional reach, not an exclusive pin: a certificate from either set is
    // trusted. Treating a partial platform-store read as fatal meant a host
    // whose keychain returns one unreadable store could not talk to a server
    // whose CA it had already supplied, on three platforms, with an error naming
    // neither the cause nor the step.
    //
    // Tolerating a partial load cannot weaken anything: it adds *fewer* platform
    // roots, so the trusted set shrinks. The supplied CA is still required to be
    // present and usable, which is the condition that actually matters and is
    // checked immediately below.
    // `load_native_certs` returns a result struct rather than a `Result`, so
    // partial failure arrives as a non-empty `errors` list beside the roots that
    // did load. Read both and ignore the former, for the reason above.
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        // A single unusable platform root is the same case again, and skipping it
        // keeps the remaining ones.
        let _ = roots.add(certificate);
    }

    let ca_file = File::open(&material.ca_path).map_err(|error| {
        tls_config_error(TlsMaterialRole::Ca, TlsMaterialSource::Open(error.kind()))
    })?;
    let ca_certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(ca_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| tls_config_error(TlsMaterialRole::Ca, pem_read_source(error)))?;
    let (valid, invalid) = roots.add_parsable_certificates(ca_certificates);
    if invalid != 0 {
        return Err(tls_config_error(
            TlsMaterialRole::Ca,
            TlsMaterialSource::Invalid,
        ));
    }
    if valid == 0 {
        return Err(tls_config_error(
            TlsMaterialRole::Ca,
            TlsMaterialSource::Empty,
        ));
    }

    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(&material.cert_path)
            .map_err(|error| {
                let source = match error {
                    rustls_pki_types::pem::Error::Io(error) => {
                        TlsMaterialSource::Open(error.kind())
                    }
                    _ => TlsMaterialSource::Parse,
                };
                tls_config_error(TlsMaterialRole::Cert, source)
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| tls_config_error(TlsMaterialRole::Cert, pem_read_source(error)))?;
    if certificates.is_empty() {
        return Err(tls_config_error(
            TlsMaterialRole::Cert,
            TlsMaterialSource::Empty,
        ));
    }
    let key_file = File::open(&material.key_path).map_err(|error| {
        tls_config_error(TlsMaterialRole::Key, TlsMaterialSource::Open(error.kind()))
    })?;
    let mut keys = PrivateKeyDer::pem_reader_iter(key_file);
    let key: PrivateKeyDer<'static> = keys
        .next()
        .ok_or_else(|| tls_config_error(TlsMaterialRole::Key, TlsMaterialSource::Empty))?
        .map_err(|error| tls_config_error(TlsMaterialRole::Key, pem_read_source(error)))?;
    match keys.next() {
        None => {}
        Some(Ok(_)) => {
            return Err(tls_config_error(
                TlsMaterialRole::Key,
                TlsMaterialSource::MultipleKeys,
            ));
        }
        Some(Err(error)) => {
            return Err(tls_config_error(
                TlsMaterialRole::Key,
                pem_read_source(error),
            ));
        }
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            tls_config_error(
                TlsMaterialRole::ProtocolVersions,
                TlsMaterialSource::Configuration,
            )
        })?;
    let builder = match trust {
        TlsServerTrust::Verify => builder.with_root_certificates(roots),
        TlsServerTrust::AllowExpiredOrUntrusted => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ExplicitServerTrust)),
    };
    let config = builder
        .with_client_auth_cert(certificates, key)
        .map_err(|_| {
            tls_config_error(
                TlsMaterialRole::ClientAuth,
                TlsMaterialSource::Configuration,
            )
        })?;
    Ok(Arc::new(config))
}

/// Builds a role-tagged, content-free TLS material error.
#[cfg(feature = "tls")]
fn tls_config_error(role: TlsMaterialRole, source: TlsMaterialSource) -> TlsConfigError {
    TlsConfigError { role, source }
}

/// Maps a PEM iteration error to a safe read or parse source.
#[cfg(feature = "tls")]
fn pem_read_source(error: rustls_pki_types::pem::Error) -> TlsMaterialSource {
    match error {
        rustls_pki_types::pem::Error::Io(error) => TlsMaterialSource::Read(error.kind()),
        _ => TlsMaterialSource::Parse,
    }
}

/// Builds the owned transport's HTTPS target for one Docker endpoint.
///
/// The target is a [`RawTarget::Stream`] whose factory opens a fresh
/// TCP connection, optionally negotiates an HTTP `CONNECT` tunnel, and then
/// completes a TLS handshake for **each** Engine request. It never returns the
/// plain TCP stream, so a failed handshake is an error rather than a plaintext
/// fallback.
///
/// `material` is loaded and validated here, synchronously, through the same
/// [`tls_config`] the generated-client transport uses: the CA bundle must parse
/// and contain at least one certificate, the client certificate must parse and
/// contain at least one certificate, and the private key must parse as exactly
/// one key. This is stricter than the former generated client's direct `connect_with_ssl` path,
/// which tolerates an empty or partly invalid CA bundle and loads the client
/// identity only when a handshake needs it.
///
/// `trust` is passed through unchanged. [`TlsServerTrust::Verify`] verifies
/// server trust, validity times, and hostname; only an explicit
/// [`TlsServerTrust::AllowExpiredOrUntrusted`] bypasses those checks, and even
/// then certificate parsing and handshake signatures are still verified.
///
/// # Errors
///
/// Returns an [`Error`] with `ErrorKind::Proxy` for an invalid endpoint or
/// proxy URL, or for TLS material that cannot be loaded. The TLS role and
/// content-free source are preserved in the source chain as [`TlsConfigError`].
#[cfg(feature = "tls")]
pub(crate) fn raw_https_target(
    address: &str,
    material: &TlsMaterial,
    policy: &ProxyPolicy,
    trust: TlsServerTrust,
) -> Result<RawTarget, Error> {
    raw_https_target_with_deadline(
        address,
        material,
        policy,
        trust,
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
    )
}

/// The deadline-aware form of [`raw_https_target`].
///
/// The deadline covers the whole establishment: TCP connect, the proxy
/// `CONNECT` exchange and its bounded response head, and the TLS handshake. It
/// deliberately does not wrap the Engine request or response, so a streaming
/// body is never cut short by the connection deadline.
#[cfg(feature = "tls")]
fn raw_https_target_with_deadline(
    address: &str,
    material: &TlsMaterial,
    policy: &ProxyPolicy,
    trust: TlsServerTrust,
    deadline: Duration,
) -> Result<RawTarget, Error> {
    let target = target_origin(address, true)?;
    let url = Url::parse(&target).map_err(|_| ProxyError::InvalidEndpointUrl)?;
    // `host_str` keeps the brackets around an IPv6 literal, which is right for
    // an HTTP authority but wrong for both a TLS server name and a socket
    // address. `host` is the parsed form, so each consumer gets the spelling it
    // needs.
    let host = url_host(&url).ok_or(ProxyError::MissingHost)?;
    let port = url.port_or_known_default().ok_or(ProxyError::MissingHost)?;
    let authority = endpoint_authority(&host, port);

    let config = tls_config(material, trust)?;
    let proxy = match policy {
        ProxyPolicy::Direct => None,
        ProxyPolicy::Http(proxy) => {
            let url = Url::parse(proxy.address()).map_err(|_| ProxyError::InvalidUrl)?;
            Some(RawProxyRoute {
                host: url_host(&url).ok_or(ProxyError::MissingHost)?,
                port: url.port_or_known_default().ok_or(ProxyError::MissingHost)?,
                authorization: proxy.authorization()?,
            })
        }
    };

    let open = {
        let host = host.clone();
        let authority = authority.clone();
        let proxy = proxy.clone();
        StreamFactory::from_fn(move || {
            let host = host.clone();
            let authority = authority.clone();
            let proxy = proxy.clone();
            let config = Arc::clone(&config);
            async move {
                let established = tokio::time::timeout(
                    deadline,
                    establish_https(&host, port, &authority, proxy.as_ref(), config),
                )
                .await;
                match established {
                    Ok(Ok(stream)) => Ok(Box::new(stream) as Box<dyn Duplex>),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(Error::transport_deadline(format!(
                        "timed out after {deadline:?} establishing TLS to the Engine at {authority}"
                    ))),
                }
            }
        })
    };

    Ok(RawTarget::Stream { authority, open })
}

/// The proxy leg of a raw HTTPS target, with its credential redacted in `Debug`.
#[cfg(feature = "tls")]
#[derive(Clone)]
struct RawProxyRoute {
    host: String,
    port: u16,
    authorization: Option<HeaderValue>,
}

#[cfg(feature = "tls")]
impl fmt::Debug for RawProxyRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawProxyRoute")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A TCP stream with bytes already read past the CONNECT response head.
///
/// A proxy may send bytes immediately after its `200` head. They are not the
/// client's to discard: they belong to the tunnel and are handed to TLS before
/// the socket. TLS cannot send a server record before the client hello, but the
/// client does not rely on that protocol fact to justify losing bytes.
#[cfg(feature = "tls")]
struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: TcpStream,
}

#[cfg(feature = "tls")]
impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

#[cfg(feature = "tls")]
impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let length = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..length]);
            this.offset += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

#[cfg(feature = "tls")]
impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }
}

/// Extracts a host from a parsed URL without IPv6 brackets.
///
/// `Url::host_str` keeps the brackets around an IPv6 literal because they are
/// part of the URL syntax. A TLS server name, a `TcpStream` address, and a proxy
/// dial address want the bare address instead, so both the target and the proxy
/// go through here.
fn url_host(url: &Url) -> Option<String> {
    match url.host()? {
        url::Host::Domain(domain) => Some(domain.to_owned()),
        url::Host::Ipv4(address) => Some(address.to_string()),
        url::Host::Ipv6(address) => Some(address.to_string()),
    }
}

/// Formats a target host and port the way an HTTP authority spells it.
#[cfg(feature = "tls")]
fn endpoint_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Opens the TCP connection and completes TLS, with no plaintext fallback.
#[cfg(feature = "tls")]
async fn establish_https(
    host: &str,
    port: u16,
    authority: &str,
    proxy: Option<&RawProxyRoute>,
    config: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<PrefixedStream>, Error> {
    // The server name is the endpoint's host, not the proxy's and not the
    // authority string: SNI and certificate verification both belong to the
    // daemon being addressed. A host that cannot be a TLS server name is
    // refused before a socket is opened.
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
        Error::transport(format!(
            "Docker endpoint host {host} is not a valid TLS server name"
        ))
    })?;

    let (stream, prefix) = match proxy {
        Some(proxy) => connect_through_proxy(proxy, authority).await?,
        None => (
            TcpStream::connect((host, port))
                .await
                .map_err(|error| Error::transport(format!("connect to {authority}: {error}")))?,
            Vec::new(),
        ),
    };
    let _ignored = stream.set_nodelay(true);
    let stream = PrefixedStream::new(prefix, stream);

    TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            Error::transport(format!("TLS handshake with {authority} failed: {error}"))
        })
}

/// Negotiates an HTTP `CONNECT` tunnel and returns the still-plain stream.
///
/// The caller completes TLS over the returned stream. This function bounds the
/// proxy's response head; the tunnel that follows is not read here, so a
/// streaming Engine body is not limited by this code.
#[cfg(feature = "tls")]
async fn connect_through_proxy(
    proxy: &RawProxyRoute,
    authority: &str,
) -> Result<(TcpStream, Vec<u8>), Error> {
    let stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|error| {
            Error::transport(format!(
                "connect to HTTP proxy {}:{}: {error}",
                proxy.host, proxy.port
            ))
        })?;
    let _ignored = stream.set_nodelay(true);
    connect_through_proxy_stream(stream, authority, proxy.authorization.as_ref()).await
}

/// The stream-generic CONNECT exchange.
///
/// The real TCP path and the deterministic parser tests use this. It bounds only
/// the response header and returns bytes read past the header as the second
/// element; it never discards them.
#[cfg(feature = "tls")]
async fn connect_through_proxy_stream<S>(
    mut stream: S,
    authority: &str,
    authorization: Option<&HeaderValue>,
) -> Result<(S, Vec<u8>), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(authorization) = authorization {
        let authorization = std::str::from_utf8(authorization.as_bytes())
            .map_err(|_| Error::transport("HTTP proxy authorization header is not valid text"))?;
        request.push_str("Proxy-Authorization: ");
        request.push_str(authorization);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| {
            Error::transport(format!(
                "write the CONNECT request to the HTTP proxy: {error}"
            ))
        })?;
    stream.flush().await.map_err(|error| {
        Error::transport(format!(
            "flush the CONNECT request to the HTTP proxy: {error}"
        ))
    })?;

    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.map_err(|error| {
            Error::transport(format!("read the HTTP proxy CONNECT response: {error}"))
        })?;
        if read == 0 {
            return Err(Error::transport(format!(
                "HTTP proxy closed the connection before answering CONNECT {authority}"
            )));
        }
        head.extend_from_slice(&chunk[..read]);
        if let Some(position) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = position + 4;
            if header_end > MAX_CONNECT_RESPONSE_HEADER_BYTES {
                return Err(Error::transport(format!(
                    "HTTP proxy CONNECT response headers exceeded \
                     {MAX_CONNECT_RESPONSE_HEADER_BYTES} bytes"
                )));
            }
            break header_end;
        }
        if head.len() > MAX_CONNECT_RESPONSE_HEADER_BYTES {
            return Err(Error::transport(format!(
                "HTTP proxy CONNECT response headers exceeded \
                 {MAX_CONNECT_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
    };

    let status = connect_status(&head[..header_end]).ok_or_else(|| {
        Error::transport(format!(
            "HTTP proxy returned a malformed CONNECT response for {authority}"
        ))
    })?;
    if !(200..300).contains(&status) {
        return Err(Error::transport(format!(
            "HTTP proxy CONNECT to {authority} returned status {status}"
        )));
    }

    // Bytes after the head belong to the tunnel. Keep them; `PrefixedStream`
    // hands them to TLS before reading the socket. This is not justified by
    // "TLS cannot send a server record before the client hello" -- it is simply
    // the client's rule not to drop bytes it has already read.
    Ok((stream, head[header_end..].to_vec()))
}

/// Reads the status code from a CONNECT response head without retaining it.
#[cfg(feature = "tls")]
fn connect_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut fields = line.split_ascii_whitespace();
    if !fields.next()?.starts_with("HTTP/") {
        return None;
    }
    fields.next()?.parse().ok()
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct ExplicitServerTrust;

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for ExplicitServerTrust {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        for certificate in std::iter::once(end_entity).chain(intermediates) {
            rustls::server::ParsedCertificate::try_from(certificate)?;
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // Public policy contract: relaxing trust requires a distinct explicit value.
    #[cfg(feature = "tls")]
    #[test]
    fn server_trust_defaults_to_verify() {
        assert_eq!(
            super::TlsServerTrust::default(),
            super::TlsServerTrust::Verify
        );
        assert_ne!(
            super::TlsServerTrust::default(),
            super::TlsServerTrust::AllowExpiredOrUntrusted,
        );
    }

    // Private verifier branch: even the explicit bypass must reject malformed DER.
    #[cfg(feature = "tls")]
    #[test]
    fn explicit_server_trust_rejects_malformed_certificates() {
        use rustls::client::danger::ServerCertVerifier;

        assert!(
            super::ExplicitServerTrust
                .verify_server_cert(
                    &rustls_pki_types::CertificateDer::from(vec![0, 1, 2]),
                    &[],
                    &"localhost".try_into().expect("server name"),
                    &[],
                    rustls_pki_types::UnixTime::now(),
                )
                .is_err()
        );
    }
    #[cfg(feature = "tls")]
    use std::collections::VecDeque;
    #[cfg(feature = "tls")]
    use std::pin::Pin;
    #[cfg(feature = "tls")]
    use std::sync::Arc;
    #[cfg(feature = "tls")]
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        task::JoinHandle,
    };

    #[cfg(feature = "tls")]
    use tokio::io::{AsyncWrite, ReadBuf};

    use super::{
        ForwardProxy, HttpConnector, MAX_PROXY_PASSWORD_BYTES, ProxyCredentials, ProxyError,
        ProxyPolicy,
    };
    use crate::{DockerClient, Endpoint, ErrorKind};

    async fn read_headers<S>(stream: &mut S) -> std::io::Result<String>
    where
        S: AsyncRead + Unpin,
    {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "proxy fixture closed before headers",
                ));
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(request)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error));
            }
            if request.len() > 16 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy fixture headers exceeded the test bound",
                ));
            }
        }
    }

    /// Deterministic in-memory duplex for the CONNECT parser.
    #[cfg(feature = "tls")]
    struct MemoryIo {
        read: VecDeque<u8>,
        written: Vec<u8>,
    }

    #[cfg(feature = "tls")]
    impl MemoryIo {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                read: VecDeque::from(bytes),
                written: Vec::new(),
            }
        }
    }

    #[cfg(feature = "tls")]
    impl AsyncRead for MemoryIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.as_mut().get_mut();
            let count = this.read.len().min(buffer.remaining());
            let bytes: Vec<u8> = this.read.drain(..count).collect();
            buffer.put_slice(&bytes);
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "tls")]
    impl AsyncWrite for MemoryIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.as_mut().get_mut().written.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Builds a CONNECT response header of exactly `total` bytes.
    #[cfg(feature = "tls")]
    fn connect_response_header(total: usize) -> Vec<u8> {
        let prefix = b"HTTP/1.1 200 OK\r\nX-Pad: ";
        let suffix = b"\r\n\r\n";
        assert!(total >= prefix.len() + suffix.len());
        let mut header = prefix.to_vec();
        header.extend(vec![b'a'; total - prefix.len() - suffix.len()]);
        header.extend_from_slice(suffix);
        assert_eq!(header.len(), total);
        header
    }

    async fn start_proxy(
        response: &'static [u8],
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_headers(&mut stream).await?;
            let _ = request_sender.send(request);
            stream.write_all(response).await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[test]
    fn rejects_ambiguous_proxy_urls_without_echoing_them() {
        let error = ForwardProxy::new("https://user:password@proxy.example:8443")
            .expect_err("HTTPS proxy URLs are not accepted");
        assert_eq!(error, ProxyError::UnsupportedScheme);

        let error = ForwardProxy::new("http://user:password@proxy.example:8080")
            .expect_err("URL credentials are not accepted");
        assert_eq!(error, ProxyError::CredentialsInUrl);
        assert!(!error.to_string().contains("password"));
    }

    #[test]
    fn rejects_proxy_routes_for_wrong_endpoint_scheme() {
        let proxy = ForwardProxy::new("http://proxy.example:8080").expect("proxy");
        let error = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("ftp://docker.example:2375".to_owned()),
            ProxyPolicy::Http(proxy),
        )
        .expect_err("only HTTP/TCP endpoints may be forwarded");
        assert_eq!(error.kind(), ErrorKind::Proxy);
    }

    #[test]
    fn bounds_and_redacts_proxy_authentication() {
        let credentials =
            ProxyCredentials::basic("proxy-user", "proxy-password").expect("bounded credentials");
        let output = format!("{credentials:?}");
        assert!(output.contains("<redacted>"));
        assert!(!output.contains("proxy-user"));
        assert!(!output.contains("proxy-password"));
        let proxy = ForwardProxy::with_basic_auth(
            "http://proxy.example:8080",
            "proxy-user",
            "proxy-password",
        )
        .expect("proxy");
        let policy = format!("{:?}", ProxyPolicy::Http(proxy));
        assert!(!policy.contains("proxy-user"));
        assert!(!policy.contains("proxy-password"));

        let too_long = "x".repeat(MAX_PROXY_PASSWORD_BYTES + 1);
        assert!(matches!(
            ProxyCredentials::basic("user", too_long),
            Err(ProxyError::CredentialComponentTooLong {
                component: "password",
                ..
            })
        ));
        assert_eq!(
            ProxyCredentials::basic("user\n", "password"),
            Err(ProxyError::CredentialControlCharacter)
        );
        assert_eq!(
            ProxyCredentials::basic("user", "password\r\n"),
            Err(ProxyError::CredentialControlCharacter)
        );
    }

    #[cfg(feature = "tls")]
    async fn start_tls_target(
        config: Arc<rustls::ServerConfig>,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let acceptor = TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = acceptor.accept(stream).await?;
            let request = read_headers(&mut stream).await?;
            let _ = request_sender.send(request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
                )
                .await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[cfg(feature = "tls")]
    async fn start_tls_proxy(
        target: std::net::SocketAddr,
    ) -> std::io::Result<(
        std::net::SocketAddr,
        oneshot::Receiver<String>,
        JoinHandle<std::io::Result<()>>,
    )> {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (request_sender, request_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await?;
            let request = read_headers(&mut client).await?;
            let _ = request_sender.send(request);
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let mut upstream = TcpStream::connect(target).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok(())
        });
        Ok((address, request_receiver, server))
    }

    #[cfg(feature = "tls")]
    pub(crate) fn tls_fixture_material(
        directory: &std::path::Path,
    ) -> Result<(crate::TlsMaterial, Arc<rustls::ServerConfig>), Box<dyn std::error::Error>> {
        tls_fixture_material_with_expiry(directory, false)
    }

    #[cfg(feature = "tls")]
    fn tls_fixture_material_with_expiry(
        directory: &std::path::Path,
        expired: bool,
    ) -> Result<(crate::TlsMaterial, Arc<rustls::ServerConfig>), Box<dyn std::error::Error>> {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        use rustls::{RootCertStore, pki_types::PrivateKeyDer};
        use std::fs;

        let ca_key = KeyPair::generate()?;
        let mut ca_parameters = CertificateParams::new(Vec::new())?;
        ca_parameters
            .distinguished_name
            .push(DnType::CommonName, "neotales docker test CA");
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_certificate = ca_parameters.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_parameters, ca_key);

        let server_key = KeyPair::generate()?;
        let mut server_parameters = CertificateParams::new(vec!["localhost".to_owned()])?;
        if expired {
            server_parameters.not_before = rcgen::date_time_ymd(2000, 1, 1);
            server_parameters.not_after = rcgen::date_time_ymd(2001, 1, 1);
        }
        server_parameters
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_certificate = server_parameters.signed_by(&server_key, &issuer)?;

        let client_key = KeyPair::generate()?;
        let mut client_parameters = CertificateParams::new(Vec::new())?;
        client_parameters
            .distinguished_name
            .push(DnType::CommonName, "docker test client");
        client_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_certificate = client_parameters.signed_by(&client_key, &issuer)?;

        let ca_path = directory.join("ca.pem");
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        fs::write(&ca_path, ca_certificate.pem())?;
        fs::write(&cert_path, client_certificate.pem())?;
        fs::write(&key_path, client_key.serialize_pem())?;

        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate.der().clone())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()?;
        let server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_certificate.der().clone()],
                PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )?;

        Ok((
            crate::TlsMaterial {
                ca_path,
                cert_path,
                key_path,
            },
            Arc::new(server_config),
        ))
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn expired_server_requires_explicit_trust_override()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::TlsServerTrust;

        for proxied in [false, true] {
            for trust in [
                TlsServerTrust::default(),
                TlsServerTrust::AllowExpiredOrUntrusted,
            ] {
                let directory = tempfile::tempdir()?;
                let (material, config) = tls_fixture_material_with_expiry(directory.path(), true)?;
                let (address, request, server) = start_tls_target(config).await?;
                let (policy, proxy_server) = if proxied {
                    let (proxy_address, _request, server) = start_tls_proxy(address).await?;
                    (
                        ProxyPolicy::Http(ForwardProxy::new(format!("http://{proxy_address}"))?),
                        Some(server),
                    )
                } else {
                    (ProxyPolicy::Direct, None)
                };
                let client = DockerClient::connect_https_with_trust(
                    &format!("https://localhost:{}", address.port()),
                    &material,
                    policy,
                    trust,
                )?;
                let result = tokio::time::timeout(Duration::from_secs(5), client.ping()).await?;
                if trust == TlsServerTrust::Verify {
                    assert!(result.is_err(), "default must reject expired server");
                    server.abort();
                    let _ = server.await;
                } else {
                    result?;
                    assert!(request.await?.starts_with("GET /v1.55/_ping HTTP/1.1\r\n"));
                    server.await??;
                }
                if let Some(server) = proxy_server {
                    server.abort();
                    let _ = server.await;
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn sends_https_docker_ping_through_connect_proxy()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use tempfile::tempdir;

        let directory = tempdir()?;
        let (material, server_config) = tls_fixture_material(directory.path())?;
        let (target_address, target_request, target_server) =
            start_tls_target(server_config).await?;
        let (proxy_address, proxy_request, proxy_server) = start_tls_proxy(target_address).await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{proxy_address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Https {
                address: format!("https://localhost:{}", target_address.port()),
                material: Some(material),
            },
            ProxyPolicy::Http(proxy),
        )?;

        let result = tokio::time::timeout(Duration::from_secs(5), client.ping()).await??;
        assert_eq!(result.api_version, None);
        let connect_request = proxy_request
            .await
            .map_err(|_| "TLS proxy fixture did not report a CONNECT request")?;
        let request = target_request
            .await
            .map_err(|_| "TLS target fixture did not report a request")?;
        proxy_server.await??;
        target_server.await??;
        assert!(
            connect_request.starts_with(&format!(
                "CONNECT localhost:{} HTTP/1.1\r\n",
                target_address.port()
            )),
            "{connect_request}"
        );
        assert!(
            connect_request
                .contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==\r\n"),
            "{connect_request}"
        );
        assert!(
            request.starts_with("GET /v1.55/_ping HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
        Ok(())
    }

    #[tokio::test]
    async fn forwards_plain_http_in_absolute_form_with_explicit_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        let (address, request_receiver, server) = start_proxy(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nOK",
        )
        .await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let client = DockerClient::connect_endpoint_with_policy(
            &Endpoint::Http("http://docker.example:2375".to_owned()),
            ProxyPolicy::Http(proxy),
        )?;

        let result = tokio::time::timeout(Duration::from_secs(5), client.ping()).await??;
        assert_eq!(result.api_version, None);
        let request = request_receiver
            .await
            .map_err(|_| "proxy fixture did not report a request")?;
        server.await??;
        assert!(
            request.starts_with("GET http://docker.example:2375/v1.55/_ping HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic chjvehktdxnlcjpwcm94es1wyxnzd29yza==\r\n"),
            "{request}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn constructs_hyper_connect_tunnel_with_explicit_auth()
    -> Result<(), Box<dyn std::error::Error>> {
        use hyper_util::client::legacy::connect::proxy::Tunnel;
        use tower_service::Service;

        let (address, request_receiver, server) =
            start_proxy(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let proxy = ForwardProxy::with_basic_auth(
            format!("http://{address}"),
            "proxy-user",
            "proxy-password",
        )?;
        let mut tunnel = Tunnel::new(proxy.address().parse()?, HttpConnector::new())
            .with_auth(proxy.authorization()?.expect("proxy auth"));
        let connection = tunnel.call("https://docker.example:2376".parse()?).await?;
        drop(connection);

        let request = request_receiver
            .await
            .map_err(|_| "proxy fixture did not report a CONNECT request")?;
        server.await??;
        assert!(
            request.starts_with("CONNECT docker.example:2376 HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("Host: docker.example:2376\r\n"));
        assert!(
            request.contains("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==\r\n")
        );
        Ok(())
    }

    #[test]
    fn rejects_proxy_policy_for_local_and_ssh_endpoints() {
        let proxy = ForwardProxy::new("http://proxy.example:8080").expect("proxy");
        let policy = ProxyPolicy::Http(proxy);

        for endpoint in [
            Endpoint::Unix("/var/run/docker.sock".into()),
            Endpoint::NamedPipe(r"\\.\pipe\docker_engine".to_owned()),
            Endpoint::Ssh {
                address: "ssh://docker.example".to_owned(),
                identity_path: None,
            },
        ] {
            let error = DockerClient::connect_endpoint_with_policy(&endpoint, policy.clone())
                .expect_err("proxy must not be applied to a non-TCP endpoint");
            assert_eq!(error.kind(), ErrorKind::Proxy);
        }
    }

    /// Opens the target's factory and returns its error, or panics on success.
    #[cfg(feature = "tls")]
    async fn open_error(target: &crate::raw::RawTarget) -> crate::Error {
        match target {
            crate::raw::RawTarget::Stream { open, .. } => match open.open().await {
                Ok(_) => panic!("the fixture must not produce a usable duplex"),
                Err(error) => error,
            },
            _ => panic!("an HTTPS target must be a Stream target"),
        }
    }

    /// IPv6 literals are unbracketed for TLS and dialing and bracketed exactly
    /// once in the HTTP authority, for the direct and proxied paths alike.
    #[cfg(feature = "tls")]
    #[test]
    fn raw_https_formats_ipv6_authorities_once() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let policies = [
            ProxyPolicy::Direct,
            ProxyPolicy::Http(ForwardProxy::new("http://proxy.example:8080")?),
        ];
        for policy in policies {
            let target = super::raw_https_target_with_deadline(
                "https://[::1]:2376",
                &material,
                &policy,
                super::TlsServerTrust::Verify,
                Duration::from_secs(1),
            )?;
            match target {
                crate::raw::RawTarget::Stream { authority, .. } => {
                    assert_eq!(authority, "[::1]:2376");
                }
                _ => panic!("an HTTPS target must be a Stream target"),
            }
        }
        // The proxy leg has the same problem: `http::Uri::host` keeps the
        // brackets, and `TcpStream::connect` does not accept them.
        let proxy_url = url::Url::parse("http://[::1]:8080")?;
        assert_eq!(super::url_host(&proxy_url).as_deref(), Some("::1"));
        let target_url = url::Url::parse("https://[::1]:2376")?;
        assert_eq!(super::url_host(&target_url).as_deref(), Some("::1"));
        Ok(())
    }

    /// A stalled TLS handshake is stopped by the establishment deadline.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_deadline_bounds_a_stalled_tls_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
            Ok::<(), std::io::Error>(())
        });

        let target = super::raw_https_target_with_deadline(
            &format!("https://localhost:{}", address.port()),
            &material,
            &ProxyPolicy::Direct,
            super::TlsServerTrust::Verify,
            Duration::from_millis(100),
        )?;
        let started = Instant::now();
        let error = open_error(&target).await;
        let elapsed = started.elapsed();
        server.abort();

        assert!(
            elapsed < Duration::from_secs(2),
            "the deadline did not fire: {elapsed:?}"
        );
        assert!(error.to_string().contains("timed out"), "{error}");
        Ok(())
    }

    /// The establishment deadline does not wrap the Engine request or a
    /// streaming response body. The handshake succeeds inside the deadline, and
    /// the response arrives well after it.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_deadline_stops_before_the_engine_body()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempfile::tempdir()?;
        let (material, config) = tls_fixture_material(directory.path())?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            use tokio_rustls::TlsAcceptor;

            let (stream, _) = listener.accept().await?;
            let mut stream = TlsAcceptor::from(config).accept(stream).await?;
            let _request = read_headers(&mut stream).await?;
            // The handshake must finish inside the establishment deadline; the
            // body must not. Keep a wide gap between the two so a loaded
            // Windows or macOS runner does not turn a scheduling delay into a
            // handshake timeout, which is not the property under test.
            tokio::time::sleep(Duration::from_secs(6)).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await?;
            Ok::<(), std::io::Error>(())
        });

        let target = super::raw_https_target_with_deadline(
            &format!("https://localhost:{}", address.port()),
            &material,
            &ProxyPolicy::Direct,
            super::TlsServerTrust::Verify,
            Duration::from_secs(5),
        )?;
        let engine = crate::raw::RawEngine::new(target, crate::API_VERSION);
        let document =
            tokio::time::timeout(Duration::from_secs(15), crate::raw::info(&engine)).await??;
        server.abort();
        assert_eq!(document, serde_json::json!({}));
        Ok(())
    }

    /// A proxy that never ends its CONNECT response head is refused at the bound.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_bounds_the_proxy_connect_response_head()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _request = read_headers(&mut stream).await?;
            let bytes = vec![b'A'; super::MAX_CONNECT_RESPONSE_HEADER_BYTES + 1024];
            stream.write_all(&bytes).await?;
            stream.flush().await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });

        let proxy = ForwardProxy::new(format!("http://{address}"))?;
        let target = super::raw_https_target_with_deadline(
            "https://localhost:2376",
            &material,
            &ProxyPolicy::Http(proxy),
            super::TlsServerTrust::Verify,
            Duration::from_secs(5),
        )?;
        let error = tokio::time::timeout(Duration::from_secs(2), open_error(&target)).await?;
        server.abort();

        assert!(error.to_string().contains("exceeded"), "{error}");
        Ok(())
    }

    /// A non-2xx CONNECT response is refused, not tunneled.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_rejects_a_proxy_connect_status() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let (address, _request, server) = start_proxy(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        let proxy = ForwardProxy::new(format!("http://{address}"))?;
        let target = super::raw_https_target_with_deadline(
            "https://localhost:2376",
            &material,
            &ProxyPolicy::Http(proxy),
            super::TlsServerTrust::Verify,
            Duration::from_secs(1),
        )?;
        let error = open_error(&target).await;
        server.abort();

        assert!(error.to_string().contains("status 403"), "{error}");
        Ok(())
    }

    /// A CONNECT response that is not an HTTP status line is refused.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_rejects_a_malformed_connect_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let (address, _request, server) = start_proxy(b"NOT HTTP\r\n\r\n").await?;
        let proxy = ForwardProxy::new(format!("http://{address}"))?;
        let target = super::raw_https_target_with_deadline(
            "https://localhost:2376",
            &material,
            &ProxyPolicy::Http(proxy),
            super::TlsServerTrust::Verify,
            Duration::from_secs(1),
        )?;
        let error = open_error(&target).await;
        server.abort();

        assert!(
            error.to_string().contains("malformed CONNECT response"),
            "{error}"
        );
        Ok(())
    }

    /// A proxy that accepts the CONNECT request and never answers is stopped by
    /// the establishment deadline.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn raw_https_deadline_bounds_a_stalled_connect_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let (material, _config) = tls_fixture_material(directory.path())?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let _request = read_headers(&mut stream).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<(), std::io::Error>(())
        });

        let proxy = ForwardProxy::new(format!("http://{address}"))?;
        let target = super::raw_https_target_with_deadline(
            "https://localhost:2376",
            &material,
            &ProxyPolicy::Http(proxy),
            super::TlsServerTrust::Verify,
            Duration::from_millis(100),
        )?;
        let error = open_error(&target).await;
        server.abort();

        assert!(error.to_string().contains("timed out"), "{error}");
        Ok(())
    }

    /// Bytes read past the CONNECT head are handed to TLS, not discarded.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn prefixed_stream_drains_the_tunnel_prefix_before_the_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(b"inner").await?;
            stream.flush().await?;
            Ok::<(), std::io::Error>(())
        });

        let inner = tokio::net::TcpStream::connect(address).await?;
        let mut stream = super::PrefixedStream::new(b"prefix".to_vec(), inner);
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        server.abort();

        assert_eq!(bytes, b"prefixinner");
        Ok(())
    }

    /// The parser accepts a header exactly at the 8 KiB bound and preserves the
    /// tunnel bytes that follow it.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn connect_parser_accepts_exact_header_bound_and_preserves_tunnel_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let tunnel = vec![b'Z'; 4096];
        let mut response = connect_response_header(super::MAX_CONNECT_RESPONSE_HEADER_BYTES);
        response.extend_from_slice(&tunnel);
        let io = MemoryIo::new(response);
        let (mut io, leftover) =
            super::connect_through_proxy_stream(io, "localhost:2376", None).await?;

        assert!(leftover.is_empty(), "expected leftover to be empty");
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await?;
        assert_eq!(rest, tunnel);
        assert!(
            io.written
                .starts_with(b"CONNECT localhost:2376 HTTP/1.1\r\n")
        );
        Ok(())
    }

    /// Coalesced tunnel bytes are preserved, and they do not count against the
    /// header bound.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn connect_parser_preserves_coalesced_tunnel_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let tunnel = vec![b'Z'; 4096];
        let mut response = connect_response_header(super::MAX_CONNECT_RESPONSE_HEADER_BYTES - 512);
        response.extend_from_slice(&tunnel);
        let io = MemoryIo::new(response);
        let (mut io, leftover) =
            super::connect_through_proxy_stream(io, "localhost:2376", None).await?;

        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await?;
        let mut combined = leftover;
        combined.extend_from_slice(&rest);
        assert_eq!(combined, tunnel);
        Ok(())
    }

    /// One byte over the header bound is refused even without tunnel bytes.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn connect_parser_rejects_header_one_byte_over_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let io = MemoryIo::new(connect_response_header(
            super::MAX_CONNECT_RESPONSE_HEADER_BYTES + 1,
        ));
        let Err(error) = super::connect_through_proxy_stream(io, "localhost:2376", None).await
        else {
            panic!("an over-bound CONNECT header must be refused");
        };
        assert!(error.to_string().contains("exceeded"), "{error}");
        Ok(())
    }
}
