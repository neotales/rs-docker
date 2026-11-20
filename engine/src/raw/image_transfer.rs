//! Authenticated, streaming image transfer on the repository-owned Engine
//! backend.
//!
//! This is the streaming half of step 3 of the migration order in
//! `docs/docker/engine-backend-alternatives.md`. It covers the six operations
//! that cannot be a single buffered document — `pull_stream`, `push_stream`,
//! `load`, `save`, `import`, and `build` — and it is the first slice in the
//! owned backend to send a [`RawBody::Stream`] request body and to read an
//! answer as newline-delimited JSON.
//!
//! Everything here reuses the existing plumbing: [`RawEngine`] for the
//! connection, [`engine_result`] for the status mapping, [`Query`] and
//! [`with_query`](super::containers::with_query) for the query string,
//! [`escape_path_segment`](super::containers::escape_path_segment) for a
//! reference in a path, and [`FrameStream::next_json`] for the progress
//! records. There is no second HTTP client, no second error type, and no
//! second streaming decoder in the crate.
//!
//! # Why these are streams and the rest of the image surface is not
//!
//! A pull, a push, a load, an import, and a build all write one JSON value per
//! line for as long as the transfer takes. Measured against Docker Engine
//! 29.8.0, an already-current pull is three records and a `save` is 3 731 968
//! bytes of `application/x-tar` with `Transfer-Encoding: chunked` and no
//! length. Buffering either would be buffering a transfer whose size the client
//! cannot know in advance, so each operation here returns the live
//! [`FrameStream`] and the caller reads a record — or, for `save`, a byte
//! chunk — at a time. Dropping the stream closes the connection, which is the
//! cancellation mechanism; there is no separate cancel protocol to get wrong.
//!
//! [`raw::images`](super::images) is the other half of the step: the
//! document-shaped operations, plus the *collected* form of a pull and a push
//! for a caller that wants a bounded answer rather than a live one.
//!
//! # The registry-auth header, and the one thing that is easy to get wrong
//!
//! The Engine reads a pull and a push credential from **`X-Registry-Auth`**, and
//! a build credential from **`X-Registry-Config`**. They are different headers
//! with different shapes: `X-Registry-Auth` carries one registry's auth object,
//! `X-Registry-Config` carries a map of registry to auth object. Both are
//! base64-encoded JSON.
//!
//! **The base64 alphabet is URL-safe, and the pinned dependency sends the
//! standard alphabet under a function named `base64_url_encode`.** Measured
//! against Docker Engine 29.8.0, the same pull of
//! `ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz:latest` answers:
//!
//! | Header | Answer |
//! | --- | --- |
//! | absent | `500` `error from registry: denied\ndenied` |
//! | standard base64 of `{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}` | `500` `error from registry: denied\ndenied` |
//! | URL-safe base64 of the same value | `403` `error from registry: denied` |
//!
//! The middle row is the defect. The daemon decodes the header with
//! `base64.URLEncoding`; when that fails it does not reject the request, it
//! **proceeds with an empty auth configuration**, so the answer is byte for
//! byte the answer to a request that carried no credentials at all. The
//! standard and URL-safe alphabets differ only in `+` and `/`, which the
//! encoding of ASCII JSON can only produce when a credential field ends in `>`
//! or `~` at a 3-byte-aligned offset — uncommon, and a real password, and a
//! password that is silently not sent.
//!
//! So [`RegistryAuth`] encodes with `general_purpose::URL_SAFE` and this module
//! says so at the point of encoding. A credential this client cannot encode is
//! an error, never an empty header: an `X-Registry-Auth` that decodes to nothing
//! is indistinguishable from anonymous, which is the worse of the two failures.
//!
//! A header is also *omitted* rather than sent empty when the caller has no
//! credential. `RegistryAuth::none` sends no header, and a caller can tell that
//! apart from a header that was sent — the difference between "no credentials
//! were sent" and "credentials were sent and the registry refused".
//!
//! # A `200` is not a result
//!
//! Measured against Docker Engine 29.8.0:
//!
//! - A **pull** that the registry refuses answers a non-2xx status with a JSON
//!   error body — `403` or `500` — so [`engine_result`] turns it into an error
//!   with the daemon's own words.
//! - A **push** that the registry refuses answers **`200`** and puts the failure
//!   in the stream:
//!
//!   ```text
//!   {"status":"The push refers to repository [docker.io/library/alpine]"}
//!   {"status":"Layer already exists","progressDetail":{},"id":"25f1d6b1951a"}
//!   {"error":"failed commit on ref \"manifest-sha256:c64c…\": server message: insufficient_scope: authorization failed",
//!    "errorDetail":{"message":"…insufficient_scope: authorization failed"}}
//!   HTTP 200
//!   ```
//!
//! - A **load** whose requested platform is missing answers `200` and puts
//!   `{"error":"image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])"}`
//!   in the stream.
//! - A **build** that never starts answers `500` with a JSON error body, so the
//!   failure is still a status.
//!
//! The status therefore decides only whether the stream *starts*. A caller of
//! [`push_stream`], [`load`], or [`build`] must read its records and pass them
//! to [`progress_error`] to learn the outcome; that is stated on each function
//! and is what [`raw::images::image_push_document`](super::images::image_push_document)
//! does for the collected form.
//!
//! # Where the request differs from the current facade
//!
//! | Member | Facade | Owned backend | Why |
//! | --- | --- | --- | --- |
//! | `X-Registry-Auth` / `X-Registry-Config` encoding | standard base64, through a function named `base64_url_encode` | URL-safe base64 | Measured above. The standard spelling is silently decoded as *no credential*. |
//! | `POST /images/create` `platform` | always sent, defaulting to `platform=` | sent only when the caller set one | The generated option is a non-optional `String`, so the recorded request carries a parameter nobody asked for. An omitted parameter is the same request without the noise. |
//! | `POST /build` `platform`, `target` | always sent, defaulting to empty | sent only when the caller set one | Same reason, same measurement family as the container slice's `platform`. |
//! | `POST /build` `t` | sent through a request modifier, one pair per tag | sent as one `t=` pair per tag, from the builder | The generated option holds a single tag, so a multi-tag build needed a modifier to be expressible at all. |
//! | `POST /images/load` `platform` | one repeated pair per entry, passed through verbatim | one pair, from the `os/arch[/variant]` shorthand | Moby's `postImagesLoad` decodes one JSON OCI platform object and refuses more than one pair with `400 multiple platform parameters not supported`; an array in one value is refused with `400 failed to parse platform: json: cannot unmarshal array into Go value of type v1.Platform`. |
//! | `POST /build` `buildargs`, `labels` | JSON object in one query value, from a `HashMap` | JSON object in one query value, from the ordered `BTreeMap` | Same gain the container slice records: a recorded request is reproducible, because the key order of the facade's `HashMap` varies between runs. |
//! | `POST /build` `version` / BuildKit parameters | `version=1` and the BuildKit-only parameters are sent by the generated option | never sent | There is no BuildKit session transport in this crate. `ImageBuildBackend::BuildKit` and any named `buildkit_options` are refused here rather than silently downgraded to a classic build, which is the failure the option type already documents. |
//! | `POST /images/load` and `/import` request bodies | a bounded caller-owned stream | a bounded caller-owned stream | Same shape. The bound is [`MAX_UPLOAD_BYTES`] here. |

use std::borrow::Cow;
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use bytes::Bytes;
use futures_core::Stream;
use futures_util::StreamExt;
use hyper::Method;
use hyper::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;

use super::containers::{Query, escape_path_segment, with_query};
use super::started;
use super::transport::{RawEngine, RawRequest};
use crate::image_transfer::{
    IMAGE_IMPORT_PLATFORM_API_VERSION, IMAGE_PLATFORM_API_VERSION, image_platform_json,
    image_platform_supported, import_platform_supported,
};
use crate::raw::body::{FrameStream, RawBody};
use crate::{
    Error, ImageBuildBackend, ImageBuildOptions, ImageImportOptions, ImageLoadOptions,
    ImagePullOptions, ImagePushOptions, ImageSaveOptions, RegistryCredentials, normalize_registry,
};

/// The `X-Registry-Auth` header the Engine reads a pull and a push credential
/// from.
///
/// The Engine's header names are not standard HTTP names, so they are spelled
/// once here rather than as string literals at each use.
static X_REGISTRY_AUTH: HeaderName = HeaderName::from_static("x-registry-auth");
/// The `X-Registry-Config` header the Engine reads a build credential from.
static X_REGISTRY_CONFIG: HeaderName = HeaderName::from_static("x-registry-config");

/// The largest upload body this slice will stream to the daemon.
///
/// `load`, `import`, and `build` all send a caller-owned archive as a
/// [`RawBody::Stream`], and none of them is bounded by a `Content-Length` this
/// client can check afterwards. The bound is therefore enforced *while* the
/// chunks are produced, and exceeding it fails the transfer rather than
/// streaming an unbounded body to a socket.
pub const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// The registry credential one Engine transfer request carries.
///
/// This is a borrow of the repository-owned
/// [`RegistryCredentials`]; nothing here is discovered, read from a
/// configuration file, or persisted. A caller that has no credential says so
/// with [`RegistryAuth::none`], and the difference between "no header" and "a
/// header the registry refused" is preserved rather than blurred.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryAuth<'a> {
    username: Option<&'a str>,
    secret: Option<&'a str>,
    identity_token: bool,
    /// Borrowed when the caller named a normalized authority, owned when this
    /// module normalized the spelling itself. A caller that already holds a
    /// normalized authority pays no allocation; a caller that does not still
    /// gets a validated one.
    server_address: Cow<'a, str>,
}

impl std::fmt::Debug for RegistryAuth<'_> {
    /// Names the registry and whether a secret is present, and nothing else.
    ///
    /// A registry credential is a password. Rendering one into a log line, an
    /// error message, or a test failure is how it ends up in a build log, so
    /// this implementation never formats a username or a secret.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryAuth")
            .field("server_address", &self.server_address)
            .field("has_secret", &self.secret.is_some())
            .field("identity_token", &self.identity_token)
            .finish()
    }
}

impl<'a> RegistryAuth<'a> {
    /// No credential: no `X-Registry-Auth` header is sent at all.
    ///
    /// An absent header is the honest spelling of "no credentials were sent",
    /// and it is deliberately *not* the same as a header carrying an empty auth
    /// object. Measured against Docker Engine 29.8.0, a registry refusal with
    /// no header answers `500 error from registry: denied\ndenied` and with
    /// credentials answers `403 error from registry: denied`; a request whose
    /// header the daemon could not decode answers the first one.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            username: None,
            secret: None,
            identity_token: false,
            server_address: Cow::Borrowed(""),
        }
    }

    /// A credential for one registry, taken from the caller's own value.
    ///
    /// The credential is validated through the repository's own
    /// [`RegistryCredentials::validate_for`](crate::RegistryCredentials), so an
    /// incomplete secret, an oversized field, or a server address that does not
    /// match the registry is refused before a connection is opened — the same
    /// refusal the current facade makes, through the same code.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not a usable authority, or when
    /// the credentials are empty, oversized, or addressed to a different
    /// registry.
    pub fn credentials(
        registry: &str,
        credentials: &'a RegistryCredentials,
    ) -> Result<Self, Error> {
        let normalized = normalize_registry(registry)?;
        credentials.validate_for(&normalized)?;
        // A token-only credential has no username; the repository spells that
        // case as the `<token>` placeholder, and the Engine's `AuthConfig` has a
        // separate `IdentityToken` member for it, so both are sent.
        let (username, secret) = credentials.secret_parts().ok_or_else(|| {
            Error::invalid_input(format!(
                "the registry credential for {normalized} carries no secret"
            ))
        })?;
        Ok(Self {
            identity_token: credentials.username().is_none(),
            username: Some(username),
            secret: Some(secret),
            server_address: match credentials.server_address() {
                // `validate_for` has already checked this against the registry,
                // so the borrow is safe and no normalization is repeated.
                Some(named) => Cow::Borrowed(named),
                None => Cow::Owned(normalized),
            },
        })
    }

    /// A bearer credential for one registry, with no username.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry is not a usable authority.
    pub fn identity_token(registry: &str, token: &'a str) -> Result<Self, Error> {
        if token.is_empty() {
            return Err(Error::invalid_input(
                "an identity-token registry credential must not be empty",
            ));
        }
        Ok(Self {
            username: Some(TOKEN_USERNAME),
            secret: Some(token),
            identity_token: true,
            server_address: Cow::Owned(normalize_registry(registry)?),
        })
    }

    /// Returns whether a credential will actually be sent.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.secret.is_some() && self.username.is_some()
    }

    /// Returns the registry authority the credential is addressed to.
    #[must_use]
    pub fn server_address(&self) -> &str {
        &self.server_address
    }
}

/// The placeholder account name the Engine expects beside a bearer token.
///
/// The repository's own credential handling spells a token-only credential this
/// way — `RegistryCredentials::into_auth_parts` substitutes it — and the
/// Engine's `AuthConfig` still wants a `username` beside the token, so the
/// placeholder is sent rather than an empty account name.
const TOKEN_USERNAME: &str = "<token>";

/// The Engine's registry auth object, in the spelling its Go struct expects.
///
/// Every member is lower-case: `registrytypes.AuthConfig` declares `username`,
/// `password`, `auth`, `email`, `serveraddress`, `identitytoken`, and
/// `registrytoken`, and this is a `#[derive(Serialize)]` projection rather than
/// the dependency's own struct.
#[derive(Debug, Serialize)]
struct EngineAuthConfig<'a> {
    /// The account name, or the `<token>` placeholder for a bearer credential.
    username: &'a str,
    /// The password, or the token.
    password: &'a str,
    /// The registry the credential is addressed to.
    ///
    /// Owned rather than borrowed: it is a normalized authority this module may
    /// have produced itself, and it outlives the `RegistryAuth` a build's
    /// credential map is built from.
    serveraddress: String,
    /// Set only for a bearer credential, alongside `password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    identitytoken: Option<&'a str>,
}

impl<'a> EngineAuthConfig<'a> {
    /// Projects a borrowed [`RegistryAuth`] onto the Engine's auth object.
    ///
    /// Returns `None` for [`RegistryAuth::none`], which is what makes "no
    /// header" and "an empty header" different requests.
    fn new(auth: &RegistryAuth<'a>) -> Option<Self> {
        if !auth.is_present() {
            return None;
        }
        let secret = auth.secret?;
        Some(Self {
            username: auth.username?,
            password: secret,
            serveraddress: auth.server_address().to_owned(),
            identitytoken: auth.identity_token.then_some(secret),
        })
    }
}

/// Encodes an auth value into the header the Engine reads it from.
///
/// The alphabet is [`AUTH_ALPHABET`] rather than the standard one, for the
/// reason the module documentation gives: the daemon decodes with the URL-safe
/// alphabet and silently treats anything it cannot decode as *no credential*.
pub(super) fn encoded_auth_header<T>(value: &T) -> Result<HeaderValue, Error>
where
    T: Serialize + ?Sized,
{
    let encoded = serde_json::to_vec(value).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine registry auth configuration: {error}"
        ))
    })?;
    let text = URL_SAFE.encode(encoded);
    HeaderValue::from_str(&text).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode the Engine registry auth header: {error}"
        ))
    })
}

/// Sets `X-Registry-Auth` on a request, or leaves the header off.
///
/// # Errors
///
/// Returns an error when the credential cannot be encoded or does not fit an
/// HTTP header. There is deliberately no fallback that sends an empty auth
/// object: a header the daemon cannot read is the same as no header, and
/// reporting it as success would hide the difference.
#[allow(clippy::needless_pass_by_value)]
pub(super) fn with_registry_auth(
    mut request: RawRequest,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    let Some(config) = EngineAuthConfig::new(&auth) else {
        return Ok(request);
    };
    let value = encoded_auth_header(&config)?;
    request.headers.insert(X_REGISTRY_AUTH.clone(), value);
    Ok(request)
}

/// Sets `X-Registry-Config` on a build request, or leaves the header off.
///
/// The build endpoint reads a *map* of registry to auth object, not the single
/// object `X-Registry-Auth` carries, and the two headers are not
/// interchangeable: a build with an `X-Registry-Auth` header has no
/// credentials, and one with an `X-Registry-Config` header has them.
///
/// # Errors
///
/// Returns an error when the credential map cannot be encoded or does not fit an
/// HTTP header.
pub(super) fn with_registry_config(
    mut request: RawRequest,
    credentials: &BTreeMap<String, RegistryCredentials>,
) -> Result<RawRequest, Error> {
    if credentials.is_empty() {
        return Ok(request);
    }
    let mut canonical: BTreeMap<String, EngineAuthConfig<'_>> = BTreeMap::new();
    for (registry, credential) in credentials {
        let auth = RegistryAuth::credentials(registry, credential)?;
        if let Some(config) = EngineAuthConfig::new(&auth) {
            canonical.insert(normalize_registry(registry)?, config);
        }
    }
    if canonical.is_empty() {
        return Ok(request);
    }
    let value = encoded_auth_header(&canonical)?;
    request.headers.insert(X_REGISTRY_CONFIG.clone(), value);
    Ok(request)
}

/// Reads the failure a daemon embeds in an otherwise successful stream.
///
/// Measured against Docker Engine 29.8.0, a refused push, a load whose platform
/// is missing, and a build step that fails all answer `200` and carry the
/// failure in a record, so a caller that only looks at the status reports a
/// failed transfer as a successful one. Pass every record to this and treat a
/// returned message as the result.
///
/// The daemon spells the failure twice — a bare `error` string and an
/// `errorDetail.message` — and the bare `error` wins when both are present.
/// **An empty member is treated as absent before that choice**: a record such as
/// `{"error":"","errorDetail":{"message":"…"}}` is a failure with the
/// `errorDetail` message, not a success. Filtering after the choice instead
/// would let the empty bare string hide the detail, which is the defect this
/// ordering fixes; the facade's load projection applies the same rule. A record
/// whose members are all empty, absent, or the wrong JSON type is not a
/// failure.
///
/// The returned text is the daemon's own message, unchanged: this helper adds no
/// context and redacts nothing, so it must not be handed a record whose members
/// carry a credential. On a managed SSH or authenticated owned forward-proxy route,
/// [`FrameStream::withholds_error_message`] is true; a caller must not promote
/// this text into an [`Error`](crate::Error) on that route. The record remains
/// caller-visible data. The crate's own document and facade decoders replace
/// the message with fixed safe text.
#[must_use]
pub fn progress_error(frame: &serde_json::Value) -> Option<String> {
    frame
        .get("error")
        .and_then(serde_json::Value::as_str)
        .filter(|message| !message.is_empty())
        .or_else(|| {
            frame
                .get("errorDetail")
                .and_then(|detail| detail.get("message"))
                .and_then(serde_json::Value::as_str)
                .filter(|message| !message.is_empty())
        })
        .map(ToOwned::to_owned)
}

/// Opens an image pull and returns the daemon's progress stream.
///
/// `POST /images/create` with `fromImage` is the pull, and the same path with
/// `fromSrc` is the import; the two are separate functions here because the
/// request bodies and the query values are different, and because a caller that
/// means one of them should not be able to spell the other by accident.
///
/// The answer is a [`FrameStream`], not a buffered document: the daemon writes
/// one JSON value per line and does not declare a length. Read it with
/// [`FrameStream::next_json`] and pass each record to [`progress_error`]. A
/// pull the registry refuses is *not* in-band — measured against Docker Engine
/// 29.8.0, it is a `403` or a `500` with a JSON error body — so the status is
/// checked before the stream is handed out, and a refused pull is an error
/// carrying the daemon's own words rather than a stream of progress records.
///
/// Dropping the stream closes the connection, which is how a caller stops a
/// pull early.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request — including a registry refusal, measured at `403` and `500` — or
/// when the credential cannot be encoded.
pub async fn pull_stream(
    engine: &RawEngine,
    image: &str,
    options: &ImagePullOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error> {
    let response = engine.send(pull_request(image, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/create` request for a pull.
///
/// `platform` is sent only when the caller set one. The generated option in the
/// current dependency is a non-optional `String`, so the recorded facade request
/// always carries `platform=` — even for the pull that asked for nothing.
pub(super) fn pull_request(
    image: &str,
    options: &ImagePullOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    if image.is_empty() {
        return Err(Error::invalid_input(
            "the Engine image reference to pull must not be empty",
        ));
    }
    let mut query = Query::default();
    query.value("fromImage", image);
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    let request = with_query(
        RawRequest::new(Method::POST, "/images/create"),
        query.finish(),
    );
    with_registry_auth(request, auth)
}

/// Opens an image push and returns the daemon's progress stream.
///
/// The answer is a [`FrameStream`]. **A `200` here is not a result.** Measured
/// against Docker Engine 29.8.0, a push the registry refuses answers `200` and
/// carries the refusal in a record:
///
/// ```text
/// {"error":"failed commit on ref \"manifest-sha256:c64c…\": server message: insufficient_scope: authorization failed", …}
/// HTTP 200
/// ```
///
/// Read the records and pass each to [`progress_error`], or use
/// [`raw::images::image_push_document`](super::images::image_push_document),
/// which does that for a caller that wants a bounded answer.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached, when it rejects the
/// request before the stream starts, or when the credential cannot be encoded.
pub async fn push_stream(
    engine: &RawEngine,
    image: &str,
    options: &ImagePushOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error> {
    let response = engine.send(push_request(image, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/{name}/push` request.
pub(super) fn push_request(
    image: &str,
    options: &ImagePushOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    if image.is_empty() {
        return Err(Error::invalid_input(
            "the Engine image reference to push must not be empty",
        ));
    }
    let mut query = Query::default();
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    let request = with_query(
        RawRequest::new(
            Method::POST,
            format!("/images/{}/push", escape_path_segment(image)),
        ),
        query.finish(),
    );
    with_registry_auth(request, auth)
}

/// Streams a Docker image archive into the daemon and returns its progress.
///
/// The archive is the caller's own stream of bytes, sent as a
/// [`RawBody::Stream`] so it reaches the socket incrementally rather than being
/// buffered whole; [`MAX_UPLOAD_BYTES`] bounds it while it is produced. The
/// request therefore carries `Transfer-Encoding: chunked` and no
/// `Content-Length`, which is what the Engine accepts for this endpoint.
///
/// The answer is a [`FrameStream`], and again **a `200` is not a result**:
/// measured, a load whose requested platform is missing answers `200` and
/// carries `{"error":"image alpine:3.20 was loaded, but doesn't provide the
/// requested platform ([plan9/amd64])"}` in the stream.
///
/// # The platform is a JSON OCI object, from API 1.48
///
/// `ImageLoadOptions::platforms` is the `os[/architecture[/variant]]` shorthand,
/// and the request carries the JSON-encoded OCI platform object Moby's
/// `postImagesLoad` decodes with `httputils.DecodePlatform` —
/// `linux/arm64` becomes `platform={"architecture":"arm64","os":"linux"}`.
/// The handler gates the parameter on API 1.48 and ignores it below that,
/// answering by loading the full multi-platform image, so a transport speaking
/// an older version refuses the request here instead of returning progress for
/// an image the caller did not select.
///
/// Moby's handler also refuses more than one `platform` parameter
/// (`400 multiple platform parameters not supported`), so at most one is
/// accepted here.
///
/// # An interrupted upload is not rolled back
///
/// Dropping the returned stream, a source stream error, and the
/// [`MAX_UPLOAD_BYTES`] bound all close the request body. Bytes already
/// produced may have reached the daemon before that close, and this function
/// offers no rollback and no effect guarantee: the daemon may have begun
/// importing them. A caller that retries must reconcile the daemon's image
/// state first; the source stream has been consumed and the previous attempt's
/// effects are unknown.
///
/// # Errors
///
/// Returns an error when the platform is malformed or more than one was named,
/// when the transport speaks an API version below 1.48 and a platform was
/// requested, when the daemon cannot be reached, when it rejects the request
/// before the stream starts, or when the credential cannot be encoded.
pub async fn load<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageLoadOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    if !options.platforms.is_empty() && !image_platform_supported(engine.version()) {
        return Err(Error::invalid_input(format!(
            "the Engine accepts a load platform from API {}.{}; this transport speaks {}.{}, \
             where the parameter is ignored and the full multi-platform image is loaded",
            IMAGE_PLATFORM_API_VERSION.major,
            IMAGE_PLATFORM_API_VERSION.minor,
            engine.version().major,
            engine.version().minor
        )));
    }
    let response = engine.send(load_request(source, options, auth)?).await?;
    started(response).await
}

/// Builds the `POST /images/load` request.
fn load_request<S>(
    source: S,
    options: &ImageLoadOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let mut query = Query::default();
    query.flag("quiet", options.quiet);
    // Moby's `postImagesLoad` reads one `platform` value, decodes it with
    // `httputils.DecodePlatform`, and answers `400 multiple platform parameters
    // not supported` when more than one is present. An array in one value is
    // not an alternative either: measured, `platform=["{…}"]` is refused with
    // `400 failed to parse platform: json: cannot unmarshal array into Go value
    // of type v1.Platform`.
    if options.platforms.len() > 1 {
        return Err(Error::invalid_input(
            "the Engine accepts at most one load platform; it refuses a request with more \
             than one `platform` parameter (`400 multiple platform parameters not supported`)",
        ));
    }
    if let Some(platform) = options.platforms.first() {
        let platform = image_platform_json(platform)
            .map_err(|error| Error::invalid_input(error.to_string()))?;
        query.value("platform", &platform);
    }
    let request = with_query(
        RawRequest::new(Method::POST, "/images/load").with_body(RawBody::from_stream(
            bounded_upload(source, MAX_UPLOAD_BYTES),
        )),
        query.finish(),
    );
    with_registry_auth(request.with_header(CONTENT_TYPE, "application/x-tar"), auth)
}

/// Downloads one or more images as a Docker archive.
///
/// The answer here is **bytes, not JSON**: measured against Docker Engine
/// 29.8.0, `GET /images/{name}/get` answers `200` with
/// `Content-Type: application/x-tar`, `Transfer-Encoding: chunked`, and no
/// length, and a three-megabyte archive arrived in many chunks. So the returned
/// [`FrameStream`] is read with [`FrameStream::next_data`], and reading it with
/// [`FrameStream::next_json`](crate::raw::FrameStream::next_json) would fail on
/// the first TAR header rather than yield anything.
///
/// A single name goes to `/images/{name}/get` and more than one to
/// `/images/get` with one repeated `names=` pair each, which is the spelling the
/// Engine declares.
///
/// # The platform is a JSON OCI object, from API 1.48
///
/// `ImageSaveOptions::platform` is the `os[/architecture[/variant]]` shorthand,
/// and the request carries the JSON-encoded OCI platform object the Engine
/// decodes with `json.Unmarshal` — `linux/arm64` becomes
/// `platform={"architecture":"arm64","os":"linux"}`. The Engine gates the
/// parameter on API 1.48 and ignores it below that, answering with the full
/// multi-platform archive, so a transport speaking an older version refuses the
/// request here instead of returning an archive that does not match.
///
/// # An error can arrive as archive bytes
///
/// The daemon writes the archive as it goes. If the export fails after the
/// response has started, Moby's handler writes `streamformatter.FormatError` —
/// a JSON object such as `{"error":{"message":"…"},"errorMessage":"…"}` — into
/// the body, completes the framing, and returns `200`. A byte reader cannot
/// tell that from TAR bytes, so a clean end of stream is not a valid archive;
/// the caller must validate the complete archive and its expected contents.
/// That daemon error is **not** reported. What is reported is an incomplete
/// HTTP body — a transport failure — and a rejection **before** the response
/// starts.
///
/// # Errors
///
/// Returns an error when no image name was given, when the platform cannot be
/// encoded, when the transport speaks an API version below 1.48 and a platform
/// was requested, when the daemon cannot be reached, or when it rejects the
/// request before the response starts.
pub async fn save(engine: &RawEngine, options: &ImageSaveOptions) -> Result<FrameStream, Error> {
    if options.platform.is_some() && !image_platform_supported(engine.version()) {
        return Err(Error::invalid_input(format!(
            "the Engine accepts a save platform from API {}.{}; this transport speaks {}.{}, \
             where the parameter is ignored and the full multi-platform archive is returned",
            IMAGE_PLATFORM_API_VERSION.major,
            IMAGE_PLATFORM_API_VERSION.minor,
            engine.version().major,
            engine.version().minor
        )));
    }
    let response = engine.send(save_request(options)?).await?;
    started(response).await
}

/// Builds the `GET /images/{name}/get` or `GET /images/get` request.
fn save_request(options: &ImageSaveOptions) -> Result<RawRequest, Error> {
    if options.names.is_empty() {
        return Err(Error::invalid_input(
            "saving an image archive needs at least one image name",
        ));
    }
    let mut query = Query::default();
    for name in &options.names {
        query.value("names", name);
    }
    if let Some(platform) = options.platform.as_deref() {
        let platform = image_platform_json(platform)
            .map_err(|error| Error::invalid_input(error.to_string()))?;
        query.value("platform", &platform);
    }
    let path = match options.names.as_slice() {
        [only] => format!("/images/{}/get", escape_path_segment(only)),
        _ => "/images/get".to_owned(),
    };
    Ok(with_query(
        RawRequest::new(Method::GET, path),
        query.finish(),
    ))
}

/// Streams a root-filesystem archive into the daemon as a new image.
///
/// This is the `fromSrc=-` half of `POST /images/create`: the same path as a
/// pull with a different query, which is exactly why it is a separate function.
/// [`import_from_url`] is the other half, where the daemon fetches the source
/// itself and the request carries no body.
///
/// **The source must be `-`.** The caller's archive is the request body, and the
/// daemon only reads that body when `fromSrc` is `-`. A URL source would make
/// the daemon fetch that URL and ignore the supplied archive, which is a
/// different import than the one this function's body describes, so any other
/// source is refused before the request is dispatched rather than sent.
///
/// `changes` is sent as one newline-joined value rather than as repeated pairs.
/// That is byte-for-byte the same instruction list, not an approximation: Moby's
/// `dockerfile.BuildFromConfig` joins the values it received with `\n` before
/// parsing them as a Dockerfile, so `["a","b"]` and `["a\nb"]` reach the parser
/// as the same text. The body is a [`RawBody::Stream`] bounded by
/// [`MAX_UPLOAD_BYTES`].
///
/// # The platform is the shorthand, and it is read from API 1.32
///
/// Unlike a load or a save, whose `platform` is a JSON-encoded OCI object
/// decoded with `httputils.DecodePlatform`, an import's `platform` is the
/// `os[/architecture[/variant]]` shorthand decoded with `platforms.Parse` in
/// Moby's `postImagesCreate`. The handler reads it only when the request version
/// is at least 1.32 and otherwise imports for the host platform without an
/// error, so a transport speaking an older version refuses the request here
/// rather than returning progress for an image the caller did not select.
///
/// # An interrupted upload is not rolled back
///
/// Dropping the returned stream, a source stream error, and the
/// [`MAX_UPLOAD_BYTES`] bound all close the request body. Bytes already
/// produced may have reached the daemon before that close, and this function
/// offers no rollback and no effect guarantee: the daemon may have begun
/// importing them. A caller that retries must reconcile the daemon's image
/// state first; the source stream has been consumed and the previous attempt's
/// effects are unknown.
///
/// The answer is a [`FrameStream`], and **a `200` is not a result**: an import
/// that fails reports it in a record.
///
/// # Errors
///
/// Returns an error when the source is empty or is not `-`, when a platform was
/// requested and the transport speaks a version below API 1.32, when the daemon
/// cannot be reached or rejects the request, or when the credential cannot be
/// encoded.
pub async fn import<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    ensure_import_platform_supported(engine, options)?;
    let response = engine.send(import_request(source, options, auth)?).await?;
    started(response).await
}

/// Imports an image from a URL the daemon fetches itself.
///
/// This is the `fromSrc=<url>` half of `POST /images/create`. The daemon reads
/// the URL with its own HTTP client, so the request carries **no body**:
/// `Content-Length: 0` and no `Content-Type`. [`import`] is the `fromSrc=-`
/// form, where the caller supplies the archive as the request body.
///
/// # The daemon fetches the URL, so the caller owns the destination decision
///
/// `fromSrc` is a destination the **daemon** resolves and fetches from its own
/// network position, not one this client opens. This function performs no
/// authorization of the destination and does not block an internal address; it
/// only requires a source that is not empty and not `-`. A local block would be
/// ineffective anyway: the daemon performs its own DNS lookup, follows its own
/// redirects, and sees its own routes and proxies after this request has been
/// accepted.
///
/// The caller must therefore decide that the destination is allowed before
/// calling this: whether the daemon may make outbound requests at all, what it
/// can reach from where it runs (loopback, private, link-local, and cloud
/// metadata addresses on the daemon's host or network), how the name resolves,
/// and where a redirect leads. **URL syntax is not authorization.**
///
/// # The credential header is sent, and the daemon does not read it
///
/// A credential the caller supplied is carried in `X-Registry-Auth`, URL-safe
/// base64 of one auth object, exactly as [`import`] and the load path carry it.
/// Moby's `postImagesCreate` reads that header in its **pull** branch only; its
/// import branch fetches the URL with `remotecontext.GetWithStatusError`, which
/// takes no credential. So the header is carried because the caller asked for
/// it, but it does not authenticate this request. Nothing here reads, logs, or
/// retains the credential.
///
/// # The platform is the shorthand, from API 1.32
///
/// [`import`] documents the gate; this shape applies the same one.
///
/// The answer is a [`FrameStream`], and **a `200` is not a result**: an import
/// that fails reports it in a record.
///
/// # Errors
///
/// Returns an error when the source is empty or `-`, when a platform was
/// requested and the transport speaks a version below API 1.32, when the daemon
/// cannot be reached or rejects the request, or when the credential cannot be
/// encoded.
pub async fn import_from_url(
    engine: &RawEngine,
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<FrameStream, Error> {
    ensure_import_platform_supported(engine, options)?;
    let response = engine.send(import_url_request(options, auth)?).await?;
    started(response).await
}

/// Refuses a platform import the transport's version cannot put on the wire.
///
/// Moby's `postImagesCreate` wraps the platform block in
/// `versions.GreaterThanOrEqualTo(version, "1.32")`, so a lower request version
/// is answered by importing for the host platform with no error. Sending the
/// parameter there would return progress for an image the caller did not ask
/// for.
fn ensure_import_platform_supported(
    engine: &RawEngine,
    options: &ImageImportOptions,
) -> Result<(), Error> {
    if options.platform.is_some() && !import_platform_supported(engine.version()) {
        return Err(Error::invalid_input(format!(
            "the Engine accepts an import platform from API {}.{}; this transport speaks {}.{}, \
             where the parameter is ignored and the image is imported for the host platform",
            IMAGE_IMPORT_PLATFORM_API_VERSION.major,
            IMAGE_IMPORT_PLATFORM_API_VERSION.minor,
            engine.version().major,
            engine.version().minor
        )));
    }
    Ok(())
}

/// Builds the `fromSrc` query shared by both import shapes.
///
/// The two shapes differ only in their body, so every query member is encoded
/// here once. `changes` is one newline-joined value for the reason [`import`]
/// records.
fn import_query(options: &ImageImportOptions) -> Result<Query, Error> {
    if options.source.is_empty() {
        return Err(Error::invalid_input(
            "importing an image needs a source URL or '-'",
        ));
    }
    let mut query = Query::default();
    query.value("fromSrc", &options.source);
    if let Some(repository) = options.repository.as_deref() {
        query.value("repo", repository);
    }
    if let Some(tag) = options.tag.as_deref() {
        query.value("tag", tag);
    }
    if let Some(message) = options.message.as_deref() {
        query.value("message", message);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    if !options.changes.is_empty() {
        query.value("changes", &options.changes.join("\n"));
    }
    Ok(query)
}

/// Builds the `POST /images/create` request for an import from a request body.
///
/// A source other than `-` is refused: the daemon reads the request body only
/// when `fromSrc` is `-`, so a URL source would fetch that URL and silently
/// ignore the archive this request is carrying.
fn import_request<S>(
    source: S,
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    if options.source != "-" {
        return Err(Error::invalid_input(
            "importing from a request body needs the source '-'; a URL source is fetched by \
             the daemon, so the supplied archive would be ignored and the URL imported instead",
        ));
    }
    let query = import_query(options)?;
    let request = with_query(
        RawRequest::new(Method::POST, "/images/create").with_body(RawBody::from_stream(
            bounded_upload(source, MAX_UPLOAD_BYTES),
        )),
        query.finish(),
    );
    with_registry_auth(request.with_header(CONTENT_TYPE, "application/x-tar"), auth)
}

/// Builds the `POST /images/create` request for an import from a URL.
///
/// No body and no `Content-Type`: the daemon fetches the URL itself. `-` is
/// refused rather than sent, because that spelling asks the daemon to read the
/// request body this shape deliberately does not send.
fn import_url_request(
    options: &ImageImportOptions,
    auth: RegistryAuth<'_>,
) -> Result<RawRequest, Error> {
    if options.source == "-" {
        return Err(Error::invalid_input(
            "importing from a URL needs a source other than '-'; '-' reads the request body, \
             and this request sends none",
        ));
    }
    let query = import_query(options)?;
    let request = with_query(
        RawRequest::new(Method::POST, "/images/create"),
        query.finish(),
    );
    with_registry_auth(request, auth)
}

/// Builds an image from a caller's build context and returns the daemon's build
/// stream.
///
/// The context is the caller's own stream of bytes, sent as a
/// [`RawBody::Stream`] bounded by [`MAX_UPLOAD_BYTES`]; it is never buffered
/// here. The credentials go out in `X-Registry-Config`, which is a **map** of
/// registry to auth object — the header a pull does not read and the one a
/// build does.
///
/// `t` is sent as one `t=` pair per tag. The generated option in the current
/// dependency holds a single tag, so a multi-tag build is only expressible there
/// through a request modifier, and the owned request spells the tags out.
///
/// The answer is a [`FrameStream`], and **a `200` is not a result**: a build
/// step that fails reports it in a record. A build that never starts — a
/// `dockerfile` the context does not contain, measured as `500 Cannot locate
/// specified Dockerfile: Nopefile` — is a status, and is reported as an error
/// before the stream is handed out.
///
/// # Errors
///
/// Returns an error when the `BuildKit` backend or a named `BuildKit` option was
/// asked for — there is no `BuildKit` session transport in this crate, and a
/// silent downgrade to a classic build is the failure the option type already
/// documents — when a remote context was named and would have to be downloaded,
/// when the daemon cannot be reached or rejects the request, or when a
/// credential cannot be encoded.
pub async fn build<S>(
    engine: &RawEngine,
    source: S,
    options: &ImageBuildOptions,
) -> Result<FrameStream, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let response = engine.send(build_request(source, options)?).await?;
    started(response).await
}

/// Builds the `POST /build` request.
fn build_request<S>(source: S, options: &ImageBuildOptions) -> Result<RawRequest, Error>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    if options.backend == ImageBuildBackend::BuildKit {
        return Err(Error::invalid_input(
            "the Engine /build endpoint is the classic builder; BuildKit needs a session transport this crate does not have",
        ));
    }
    if let Some(option) = options.buildkit_options.first().copied() {
        return Err(Error::invalid_input(format!(
            "BuildKit image option {option} is not available on the classic Engine /build endpoint"
        )));
    }
    if options.remote.is_some() {
        return Err(Error::invalid_input(
            "a remote build context would have to be downloaded, and this operation builds from a caller-owned stream",
        ));
    }

    let mut query = Query::default();
    if !options.dockerfile.is_empty() {
        query.value("dockerfile", &options.dockerfile);
    }
    for tag in &options.tags {
        query.value("t", tag);
    }
    query.flag("q", options.quiet);
    query.flag("nocache", options.no_cache);
    query.flag("rm", options.remove_intermediate);
    query.flag("forcerm", options.force_remove_intermediate);
    if let Some(pull) = options.pull {
        query.flag("pull", pull);
    }
    if let Some(target) = options.target.as_deref() {
        query.value("target", target);
    }
    if let Some(platform) = options.platform.as_deref() {
        query.value("platform", platform);
    }
    if let Some(extra_hosts) = options.extra_hosts.as_deref() {
        query.value("extrahosts", extra_hosts);
    }
    for host in &options.extra_host_entries {
        query.value("extrahosts", host);
    }
    if let Some(network_mode) = options.network_mode.as_deref() {
        query.value("networkmode", network_mode);
    }
    if let Some(memory) = options.memory {
        query.value("memory", &memory.to_string());
    }
    if let Some(memswap) = options.memswap {
        query.value("memswap", &memswap.to_string());
    }
    if let Some(cpu_shares) = options.cpu_shares {
        query.value("cpushares", &cpu_shares.to_string());
    }
    if let Some(cpu_period) = options.cpu_period {
        query.value("cpuperiod", &cpu_period.to_string());
    }
    if let Some(cpu_quota) = options.cpu_quota {
        query.value("cpuquota", &cpu_quota.to_string());
    }
    if let Some(cpuset_cpus) = options.cpuset_cpus.as_deref() {
        query.value("cpusetcpus", cpuset_cpus);
    }
    if let Some(shm_size) = options.shm_size {
        query.value("shmsize", &shm_size.to_string());
    }
    if !options.ulimits.is_empty() {
        // Moby's build_routes.go unmarshals `ulimits` into []*container.Ulimit.
        let limits: Vec<_> = options.ulimits.iter().map(|limit| {
            serde_json::json!({"Name": limit.name, "Soft": limit.soft, "Hard": limit.hard})
        }).collect();
        query.value("ulimits", &json_query_value(&limits)?);
    }
    if let Some(squash) = options.squash {
        query.flag("squash", squash);
    }
    if !options.build_args.is_empty() {
        query.value("buildargs", &json_query_value(&options.build_args)?);
    }
    if !options.labels.is_empty() {
        query.value("labels", &json_query_value(&options.labels)?);
    }
    if !options.cache_from.is_empty() {
        // The Engine declares `cachefrom` as an array of strings, and the
        // current dependency sends it as a JSON array in one value; that form is
        // what is sent here, from an ordered list rather than a `HashMap`.
        query.value("cachefrom", &json_query_value(&options.cache_from)?);
    }

    let request = with_query(
        RawRequest::new(Method::POST, "/build")
            .with_body(RawBody::from_stream(bounded_upload(
                source,
                MAX_UPLOAD_BYTES,
            )))
            .with_header(CONTENT_TYPE, "application/x-tar"),
        query.finish(),
    );
    with_registry_config(request, &options.registry_credentials)
}

/// Encodes a value for a query parameter the Engine declares as JSON.
fn json_query_value<T>(value: &T) -> Result<String, Error>
where
    T: Serialize + ?Sized,
{
    serde_json::to_string(value).map_err(|error| {
        Error::invalid_input(format!(
            "failed to encode an Engine build query value: {error}"
        ))
    })
}

/// Wraps a caller-owned upload in a byte bound.
///
/// The bound is checked on every chunk rather than once at the end, so an
/// oversized archive fails while it is still small instead of after the whole
/// body has been written to a socket. The stream is left finished after the
/// first failure: retrying past a limit that has already been exceeded would
/// just exceed it again.
fn bounded_upload<S>(
    source: S,
    limit: u64,
) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Send
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    let source = Box::pin(source);
    futures_util::stream::unfold(
        (source, 0_u64, limit, false),
        |(mut source, total, limit, failed)| async move {
            if failed {
                return None;
            }
            let item = source.as_mut().next().await?;
            match item {
                Ok(chunk) => {
                    let length = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                    let Some(next_total) = total.checked_add(length) else {
                        return Some((
                            Err(std::io::Error::other("image upload size overflow")),
                            (source, total, limit, true),
                        ));
                    };
                    if next_total > limit {
                        return Some((
                            Err(std::io::Error::other(format!(
                                "image upload exceeds the {limit}-byte limit"
                            ))),
                            (source, next_total, limit, true),
                        ));
                    }
                    Some((Ok(chunk), (source, next_total, limit, false)))
                }
                Err(error) => Some((
                    Err(std::io::Error::other(error)),
                    (source, total, limit, true),
                )),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use futures_util::stream;
    use hyper::Method;

    use super::{
        MAX_UPLOAD_BYTES, RegistryAuth, build_request, import_request, load_request,
        progress_error, pull_request, push_request, save, save_request,
    };
    use crate::raw::{MAX_DOCUMENT_BYTES, RawBody, RawEngine, RawRequest, RawTarget};
    use crate::{
        ApiVersion, ErrorKind, ImageBuildBackend, ImageBuildOptions, ImageImportOptions,
        ImageLoadOptions, ImagePullOptions, ImagePushOptions, ImageSaveOptions,
        RegistryCredentials,
    };

    /// The API version every request-shape assertion pins.
    ///
    /// Derived from the crate's ceiling. What these assertions are about is
    /// the path and its query encoding, not the number in the prefix, and a
    /// literal here would turn a legitimate ceiling change into failures that
    /// the next person removes rather than reads. The number itself is asserted
    /// once, in `raw::mod::tests::the_prefix_is_the_version_the_crate_claims`.
    const VERSION: ApiVersion = crate::API_VERSION;

    fn engine() -> RawEngine {
        RawEngine::new(
            RawTarget::Unix(std::path::PathBuf::from("/tmp/does-not-matter.sock")),
            VERSION,
        )
    }

    /// Renders the exact request line a request would put on the wire.
    fn request_line(request: &RawRequest) -> String {
        let uri = engine().request_uri(request).expect("absolute path");
        format!("{} {uri} HTTP/1.1", request.method)
    }

    fn upload() -> impl futures_core::Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static
    {
        stream::iter(vec![Ok(Bytes::from_static(b"archive"))])
    }

    fn auth() -> RegistryAuth<'static> {
        RegistryAuth {
            username: Some("nobody"),
            secret: Some("aa>"),
            identity_token: false,
            server_address: std::borrow::Cow::Borrowed("ghcr.io"),
        }
    }

    #[test]
    fn the_auth_header_is_url_safe_base64_because_the_daemon_decodes_that() {
        // The value below is the one measured against Docker Engine 29.8.0: a
        // standard-base64 header decodes to nothing on the daemon's side, the
        // pull proceeds with no credential, and the answer is byte for byte the
        // answer to a request with no header at all (`500 error from registry:
        // denied`). The URL-safe spelling of the same value is the one the
        // daemon reads (`403 error from registry: denied`).
        let request = pull_request(
            "ghcr.io/nonexistent-owner-xyz/nonexistent-repo-xyz",
            &ImagePullOptions {
                tag: Some("latest".to_owned()),
                platform: None,
            },
            auth(),
        )
        .expect("request");
        let header = request
            .headers
            .get("x-registry-auth")
            .expect("an X-Registry-Auth header")
            .to_str()
            .expect("a header value");
        assert_eq!(
            header,
            "eyJ1c2VybmFtZSI6Im5vYm9keSIsInBhc3N3b3JkIjoiYWE-Iiwic2VydmVyYWRkcmVzcyI6ImdoY3IuaW8ifQ=="
        );
        assert!(
            !header.contains('+'),
            "the standard alphabet is the defect: {header}"
        );
        assert!(
            !header.contains('/'),
            "the standard alphabet is the defect: {header}"
        );
        assert!(header.ends_with('='), "URL_SAFE is padded: {header}");
    }

    #[test]
    fn the_measured_standard_alphabet_spelling_really_is_different() {
        // The other half of the measurement: the two alphabets agree on almost
        // every credential and differ on this one, so a test that only checked
        // "the header is base64" would have passed against the defect.
        let standard = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            br#"{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}"#,
        );
        let url_safe = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE,
            br#"{"username":"nobody","password":"aa>","serveraddress":"ghcr.io"}"#,
        );
        assert_ne!(standard, url_safe, "the alphabets must differ here");
        assert!(standard.contains('+'), "{standard}");
    }

    #[test]
    fn a_request_with_no_credential_carries_no_auth_header() {
        // An absent header and a header holding an empty auth object are
        // different requests, and only the first one can say "no credentials
        // were sent".
        let request = pull_request("alpine", &ImagePullOptions::default(), RegistryAuth::none())
            .expect("request");
        assert!(request.headers.get("x-registry-auth").is_none());
        let push = push_request("alpine", &ImagePushOptions::default(), RegistryAuth::none())
            .expect("request");
        assert!(push.headers.get("x-registry-auth").is_none());
    }

    #[test]
    fn a_credential_is_only_sent_when_it_carries_a_secret() {
        assert!(!RegistryAuth::none().is_present());
        assert!(auth().is_present());
        assert_eq!(auth().server_address(), "ghcr.io");
    }

    #[test]
    fn a_registry_credential_is_validated_before_a_connection_is_opened() {
        let credentials = RegistryCredentials::new("nobody", "aa>");
        let valid = RegistryAuth::credentials("ghcr.io", &credentials).expect("a credential");
        assert!(valid.is_present());
        assert_eq!(valid.server_address(), "ghcr.io");
        assert!(!valid.identity_token);

        // Credentials addressed to a different registry are refused here, not
        // sent to the wrong one. The repository's own validation classifies it as
        // a credential problem rather than invalid input, and that is the more
        // useful of the two for a caller deciding whether to re-read a store.
        let elsewhere = credentials.clone().with_server_address("registry.example");
        assert_eq!(
            RegistryAuth::credentials("ghcr.io", &elsewhere)
                .expect_err("a mismatched registry")
                .kind(),
            ErrorKind::Credentials
        );
        // A credential with no secret is refused rather than sent empty.
        assert_eq!(
            RegistryAuth::credentials("ghcr.io", &RegistryCredentials::default())
                .expect_err("no secret")
                .kind(),
            ErrorKind::Credentials
        );
        // A registry that is not an authority is refused, and refused by the
        // repository's own normalizer rather than by a private rule here.
        assert_eq!(
            RegistryAuth::credentials("not a registry", &credentials)
                .expect_err("a bad registry")
                .kind(),
            ErrorKind::Credentials
        );
    }

    #[test]
    fn a_token_credential_sends_the_identity_token_member_too() {
        let credentials = RegistryCredentials::from_identity_token("a-token");
        let token = RegistryAuth::credentials("ghcr.io", &credentials).expect("a credential");
        assert!(token.is_present());
        assert!(
            token.identity_token,
            "a token-only credential is an identity token"
        );
        assert_eq!(token.server_address(), "ghcr.io");
    }

    #[test]
    fn the_debug_rendering_of_a_credential_never_prints_the_secret() {
        // A registry credential is a password. Rendering one into a log line or
        // a test failure is how it ends up in a build log.
        let rendered = format!("{:?}", auth());
        assert!(!rendered.contains("aa>"), "{rendered}");
        assert!(rendered.contains("has_secret: true"), "{rendered}");
        assert!(rendered.contains("ghcr.io"), "{rendered}");
    }

    #[test]
    fn a_pull_sends_the_image_the_tag_and_nothing_else() {
        let request = pull_request(
            "ghcr.io/owner/app",
            &ImagePullOptions {
                tag: Some("1.2.3".to_owned()),
                platform: Some("linux/arm64".to_owned()),
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/create?fromImage=ghcr.io%2Fowner%2Fapp&tag=1.2.3&platform=linux%2Farm64 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_pull_without_a_platform_sends_no_platform() {
        // The generated option is a non-optional `String`, so the facade's
        // recorded request always carries `platform=`; an omitted parameter is
        // the same request without the noise.
        let request = pull_request("alpine", &ImagePullOptions::default(), RegistryAuth::none())
            .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/create?fromImage=alpine HTTP/1.1")
        );
    }

    #[test]
    fn an_empty_image_reference_is_refused_before_a_connection_is_opened() {
        assert_eq!(
            pull_request("", &ImagePullOptions::default(), RegistryAuth::none())
                .expect_err("an empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            push_request("", &ImagePushOptions::default(), RegistryAuth::none())
                .expect_err("an empty reference")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_push_escapes_its_reference_into_one_segment() {
        let request = push_request(
            "owner/app",
            &ImagePushOptions {
                tag: Some("v1".to_owned()),
                platform: None,
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version("POST /v1.API/images/owner%2Fapp/push?tag=v1 HTTP/1.1")
        );
    }

    #[test]
    fn a_load_streams_its_body_and_encodes_its_platform() {
        // The public option is the `os[/architecture[/variant]]` shorthand, and
        // the wire value is the JSON OCI platform object Moby decodes with
        // `httputils.DecodePlatform`. An array in one value is refused with
        // `400 failed to parse platform: json: cannot unmarshal array into Go
        // value of type v1.Platform`.
        let request = load_request(
            upload(),
            &ImageLoadOptions {
                quiet: true,
                platforms: vec!["linux/arm/v7".to_owned()],
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/load?quiet=true&platform=%7B%22architecture%22%3A%22arm%22%2C%22os%22%3A%22linux%22%2C%22variant%22%3A%22v7%22%7D HTTP/1.1"
            )
        );
        assert_eq!(
            request.body.known_len(),
            None,
            "a streamed body has no length"
        );
    }

    /// Moby's load handler refuses more than one platform pair, so the request
    /// builder refuses it before opening a connection.
    #[test]
    fn a_load_refuses_more_than_one_platform() {
        let error = load_request(
            upload(),
            &ImageLoadOptions {
                quiet: false,
                platforms: vec!["linux/amd64".to_owned(), "linux/arm64".to_owned()],
            },
            RegistryAuth::none(),
        )
        .expect_err("the Engine refuses multiple platform parameters");
        assert!(
            error.to_string().contains("at most one"),
            "the refusal does not say what the Engine accepts: {error}"
        );
    }

    /// A platform without an architecture is refused by the same encoder the
    /// save path uses, before it reaches the wire.
    #[test]
    fn a_load_refuses_a_platform_without_an_architecture() {
        let error = load_request(
            upload(),
            &ImageLoadOptions {
                quiet: false,
                platforms: vec!["linux".to_owned()],
            },
            RegistryAuth::none(),
        )
        .expect_err("the Engine's decoder needs both os and architecture");
        assert!(
            error.to_string().contains("os/architecture"),
            "the refusal does not name the missing part: {error}"
        );
    }

    #[test]
    fn a_load_sends_its_archive_as_a_tar_content_type() {
        let request = load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none())
            .expect("request");
        assert_eq!(
            request.headers.get("content-type").expect("a content type"),
            "application/x-tar"
        );
    }

    #[test]
    fn an_import_sends_from_src_and_joins_its_changes_with_newlines() {
        let request = import_request(
            upload(),
            &ImageImportOptions {
                source: "-".to_owned(),
                repository: Some("imported".to_owned()),
                tag: Some("v1".to_owned()),
                message: Some("a message".to_owned()),
                changes: vec!["ENV A=1".to_owned(), "ENV B=2".to_owned()],
                platform: Some("linux/amd64".to_owned()),
            },
            RegistryAuth::none(),
        )
        .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "POST /v1.API/images/create?fromSrc=-&repo=imported&tag=v1&message=a+message&platform=linux%2Famd64&changes=ENV+A%3D1%0AENV+B%3D2 HTTP/1.1"
            )
        );
    }

    #[test]
    fn an_import_without_a_source_is_refused() {
        assert_eq!(
            import_request(
                upload(),
                &ImageImportOptions {
                    source: String::new(),
                    ..ImageImportOptions::default()
                },
                RegistryAuth::none(),
            )
            .expect_err("no source")
            .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_spells_every_tag_and_leaves_out_what_was_not_asked_for() {
        let request = build_request(
            upload(),
            &ImageBuildOptions {
                dockerfile: "docker/Dockerfile".to_owned(),
                tags: vec!["probe/a".to_owned(), "probe/b".to_owned()],
                build_args: BTreeMap::from([("V".to_owned(), "1".to_owned())]),
                labels: BTreeMap::from([("L".to_owned(), "x".to_owned())]),
                cache_from: vec!["probe/a".to_owned()],
                ..ImageBuildOptions::default()
            },
        )
        .expect("request");
        let line = request_line(&request);
        assert!(
            line.starts_with(&crate::raw::at_api_version(
                "POST /v1.API/build?dockerfile=docker%2FDockerfile&"
            )),
            "{line}"
        );
        assert!(
            line.contains("&t=probe%2Fa&t=probe%2Fb"),
            "one pair per tag: {line}"
        );
        assert!(
            line.contains("&buildargs=%7B%22V%22%3A%221%22%7D"),
            "{line}"
        );
        assert!(line.contains("&labels=%7B%22L%22%3A%22x%22%7D"), "{line}");
        assert!(line.contains("&cachefrom=%5B%22probe%2Fa%22%5D"), "{line}");
        assert!(line.contains("&rm=true"), "{line}");
        // `platform` and `target` are non-optional `String`s in the generated
        // option, so the facade's recorded request always carries them empty.
        assert!(
            !line.contains("platform"),
            "an unset platform is not sent: {line}"
        );
        assert!(
            !line.contains("target"),
            "an unset target is not sent: {line}"
        );
        // The BuildKit-only `version` parameter is never sent.
        assert!(
            !line.contains("version="),
            "there is no BuildKit session: {line}"
        );
    }

    #[test]
    fn a_build_refuses_buildkit_rather_than_downgrading_it_silently() {
        let options = ImageBuildOptions {
            backend: ImageBuildBackend::BuildKit,
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &options)
                .expect_err("BuildKit")
                .kind(),
            ErrorKind::InvalidInput
        );
        let named = ImageBuildOptions {
            buildkit_options: vec![crate::ImageBuildKitOption::CacheTo],
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &named)
                .expect_err("a named BuildKit option")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_refuses_a_remote_context_it_would_have_to_download() {
        let options = ImageBuildOptions {
            remote: Some("https://example.invalid/context.git".to_owned()),
            ..ImageBuildOptions::default()
        };
        assert_eq!(
            build_request(upload(), &options)
                .expect_err("a remote context")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_build_with_credentials_sends_the_config_map_and_not_the_single_auth() {
        // The two headers are not interchangeable: `/build` reads
        // `X-Registry-Config`, a map of registry to auth object.
        let options = ImageBuildOptions {
            registry_credentials: BTreeMap::from([(
                "ghcr.io".to_owned(),
                RegistryCredentials::new("nobody", "aa>"),
            )]),
            ..ImageBuildOptions::default()
        };
        let request = build_request(upload(), &options).expect("request");
        assert!(request.headers.get("x-registry-auth").is_none());
        let header = request
            .headers
            .get("x-registry-config")
            .expect("an X-Registry-Config header")
            .to_str()
            .expect("a header value");
        assert!(!header.contains('+'), "{header}");
        assert!(!header.contains('/'), "{header}");
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, header)
            .expect("the daemon's own alphabet decodes it");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("a JSON auth map");
        let entry = &value["ghcr.io"];
        assert_eq!(entry["username"], "nobody");
        assert_eq!(entry["password"], "aa>");
        assert_eq!(entry["serveraddress"], "ghcr.io");
    }

    #[test]
    fn a_build_without_credentials_sends_no_config_header() {
        let request = build_request(upload(), &ImageBuildOptions::default()).expect("request");
        assert!(request.headers.get("x-registry-config").is_none());
    }

    #[test]
    fn a_save_of_one_name_uses_the_single_image_path() {
        let request = save_request(&ImageSaveOptions::new(["alpine:3.20"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/alpine%3A3.20/get?names=alpine%3A3.20 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_save_of_several_names_repeats_the_names_pair() {
        let request =
            save_request(&ImageSaveOptions::new(["alpine:3.20", "busybox:1.36"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/get?names=alpine%3A3.20&names=busybox%3A1.36 HTTP/1.1"
            )
        );
    }

    #[test]
    fn a_save_of_a_reference_with_a_slash_keeps_it_in_one_segment() {
        let request = save_request(&ImageSaveOptions::new(["owner/app:v1"])).expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/owner%2Fapp%3Av1/get?names=owner%2Fapp%3Av1 HTTP/1.1"
            )
        );
    }

    /// The save platform is the JSON OCI object the Engine decodes, not the
    /// `os/arch` shorthand the option is written in.
    ///
    /// The Engine's decoder is `json.Unmarshal` into `ocispec.Platform` and
    /// refuses a document without both `os` and `architecture`; sending
    /// `platform=linux%2Famd64` would be a `400 failed to parse platform` on
    /// API 1.48 and would be ignored entirely below it.
    #[test]
    fn a_save_platform_is_the_json_oci_object_the_engine_decodes() {
        let request =
            save_request(&ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/arm/v7"))
                .expect("request");
        assert_eq!(
            request_line(&request),
            crate::raw::at_api_version(
                "GET /v1.API/images/alpine%3A3.20/get?names=alpine%3A3.20&platform=%7B%22architecture%22%3A%22arm%22%2C%22os%22%3A%22linux%22%2C%22variant%22%3A%22v7%22%7D HTTP/1.1"
            )
        );

        // A platform without a variant omits the member rather than sending it
        // empty: `"variant":""` is a value the daemon would have to interpret.
        let request =
            save_request(&ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/amd64"))
                .expect("request");
        let line = request_line(&request);
        assert!(
            line.contains(
                "platform=%7B%22architecture%22%3A%22amd64%22%2C%22os%22%3A%22linux%22%7D"
            ),
            "{line}"
        );
        assert!(!line.contains("variant"), "{line}");
    }

    /// A platform with no architecture is refused before it is encoded.
    #[test]
    fn a_save_platform_without_an_architecture_is_refused() {
        let error = save_request(&ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux"))
            .expect_err("the Engine needs both os and architecture");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("os/architecture"),
            "the refusal did not name the missing part: {error}"
        );
    }

    /// A platform save below API 1.48 is refused before a connection is opened.
    ///
    /// The daemon does not reject the parameter below 1.48; its handler skips
    /// the whole block and answers with the full multi-platform archive. Sending
    /// it would therefore be a silent wrong answer, so the transport refuses.
    /// The target here is a closed port, so a request that was attempted would
    /// report a transport failure instead of this input error.
    #[tokio::test]
    async fn a_save_platform_below_the_api_that_reads_it_is_refused_before_connecting() {
        let engine = RawEngine::new(
            RawTarget::Tcp {
                host: "127.0.0.1".to_owned(),
                port: 1,
            },
            ApiVersion {
                major: 1,
                minor: 47,
            },
        );
        let error = save(
            &engine,
            &ImageSaveOptions::new(["alpine:3.20"]).with_platform("linux/amd64"),
        )
        .await
        .expect_err("1.47 ignores the platform");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("1.48") && error.to_string().contains("1.47"),
            "the refusal did not name both versions: {error}"
        );
    }

    #[test]
    fn a_save_with_no_names_is_refused() {
        // `POST /images/{name}/tag` with no repository answers `200` and changes
        // nothing, and a save with no name has nothing to save; both are refused
        // here rather than sent for the daemon to accept silently.
        assert_eq!(
            save_request(&ImageSaveOptions::default())
                .expect_err("no names")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn the_daemon_writes_a_push_failure_into_a_two_hundred() {
        // The measured record, and the reason `progress_error` exists: a refused
        // push is `HTTP 200` with the refusal in the body.
        let frame = serde_json::json!({
            "status": "Layer already exists",
            "progressDetail": {},
            "id": "25f1d6b1951a",
        });
        assert_eq!(progress_error(&frame), None);

        let failure = serde_json::json!({
            "error": "failed commit on ref \"manifest-sha256:c64c\": server message: insufficient_scope: authorization failed",
            "errorDetail": {"message": "failed commit on ref \"manifest-sha256:c64c\": server message: insufficient_scope: authorization failed"},
        });
        assert!(
            progress_error(&failure)
                .expect("the daemon's own words")
                .contains("insufficient_scope")
        );

        // A load failure arrives the same way, and its bare `error` is the
        // spelling this reads first.
        let load_failure = serde_json::json!({
            "error": "image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])",
        });
        assert_eq!(
            progress_error(&load_failure).expect("a load failure"),
            "image alpine:3.20 was loaded, but doesn't provide the requested platform ([plan9/amd64])"
        );
    }

    #[test]
    fn an_empty_error_member_is_not_a_failure() {
        // A record that carries an empty `error` is not a failure, and reporting
        // one as a failure would fail a transfer that worked.
        assert_eq!(progress_error(&serde_json::json!({"error": ""})), None);
        assert_eq!(progress_error(&serde_json::json!({"error": null})), None);
    }

    #[test]
    fn an_empty_bare_error_does_not_hide_the_error_detail() {
        // The empty member is filtered *before* the choice, so it cannot mask a
        // real detail. Filtering after the choice was the defect.
        assert_eq!(
            progress_error(&serde_json::json!({
                "error": "",
                "errorDetail": {"message": "the archive was corrupt"},
            })),
            Some("the archive was corrupt".to_owned())
        );

        // An empty detail is no more a failure than an empty bare string.
        assert_eq!(
            progress_error(&serde_json::json!({
                "error": "",
                "errorDetail": {"message": ""},
            })),
            None
        );
        assert_eq!(
            progress_error(&serde_json::json!({"errorDetail": {"message": ""}})),
            None
        );

        // A member of the wrong type is treated as absent, not as a failure and
        // not as a reason to stop looking at the other member.
        assert_eq!(
            progress_error(&serde_json::json!({
                "error": 5,
                "errorDetail": {"message": "the archive was corrupt"},
            })),
            Some("the archive was corrupt".to_owned())
        );
        assert_eq!(progress_error(&serde_json::json!({})), None);
    }

    #[test]
    fn a_non_empty_bare_error_wins_over_the_error_detail() {
        // The precedence the facade and the documented record both use: the
        // daemon's bare string is the one reported when both are present. The
        // text is returned unchanged, with no context added.
        assert_eq!(
            progress_error(&serde_json::json!({
                "error": "the archive was corrupt",
                "errorDetail": {"message": "a longer detail"},
            })),
            Some("the archive was corrupt".to_owned())
        );
    }

    #[tokio::test]
    async fn a_streamed_upload_is_capped_while_it_is_produced() {
        // The bound is checked per chunk, not once at the end, and the stream is
        // left finished after the first failure.
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            (0..4).map(|_| Ok(Bytes::from(vec![b'x'; 8]))).collect();
        let mut upload = Box::pin(super::bounded_upload(stream::iter(chunks), 20));
        let mut sent = 0_u64;
        let mut failure = None;
        while let Some(item) = futures_util::StreamExt::next(&mut upload).await {
            match item {
                Ok(chunk) => sent += u64::try_from(chunk.len()).unwrap_or(0),
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        assert_eq!(sent, 16, "two 8-byte chunks fit under the 20-byte bound");
        assert!(failure.expect("the limit is refused").contains("20-byte"));
    }

    #[tokio::test]
    async fn an_upload_under_the_bound_is_passed_through_whole() {
        let mut upload = Box::pin(super::bounded_upload(
            stream::iter(vec![
                Ok(Bytes::from_static(b"one")),
                Ok(Bytes::from_static(b"two")),
            ]),
            MAX_UPLOAD_BYTES,
        ));
        let mut whole = Vec::new();
        while let Some(item) = futures_util::StreamExt::next(&mut upload).await {
            whole.extend_from_slice(&item.expect("a chunk"));
        }
        assert_eq!(whole, b"onetwo");
    }

    #[test]
    fn a_stream_request_declares_no_length_and_uses_the_documented_method() {
        for request in [
            load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none()).expect("load"),
            import_request(
                upload(),
                &ImageImportOptions::new("-"),
                RegistryAuth::none(),
            )
            .expect("import"),
            build_request(upload(), &ImageBuildOptions::default()).expect("build"),
        ] {
            assert!(matches!(request.body, RawBody::Stream(_)), "{request:?}");
            assert_eq!(request.body.known_len(), None);
        }
        assert_eq!(
            load_request(upload(), &ImageLoadOptions::new(), RegistryAuth::none())
                .expect("load")
                .method,
            Method::POST
        );
    }

    #[test]
    fn the_import_body_request_refuses_a_url_source() {
        // The daemon reads the request body only when `fromSrc` is `-`. A URL
        // source would make it fetch that URL and ignore the archive this
        // builder carries, so the builder refuses it before a request exists.
        let error = import_request(
            upload(),
            &ImageImportOptions::new("https://example.invalid/i.tar"),
            RegistryAuth::none(),
        )
        .expect_err("a URL source has no body shape");
        assert!(error.to_string().contains("'-'"), "{error}");
    }

    #[test]
    fn the_document_bound_is_still_the_one_the_rest_of_the_backend_uses() {
        // The collected pull and push forms in `raw::images` bound their answer
        // by the same constant as every other document here, so a stream that
        // never ends cannot be turned into an unbounded buffer by going through
        // the document form.
        const { assert!(MAX_DOCUMENT_BYTES > 0) };
        assert_eq!(MAX_DOCUMENT_BYTES, 16 * 1024 * 1024);
    }
}
