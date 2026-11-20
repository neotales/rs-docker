//! Registry authentication and distribution metadata over the owned transport.

use super::containers::escape_path_segment;
use super::transport::{RawEngine, RawRequest, decode, json_body, json_content_type};
use crate::{Error, ErrorKind};
use hyper::Method;
use serde::{Deserialize, Serialize};

const WITHHELD: &str = "registry authentication response withheld";
const DISTRIBUTION_WITHHELD: &str = "distribution response withheld";

/// Credentials sent in the JSON body of `POST /auth`. Debug withholds all fields.
#[derive(Serialize)]
pub struct RegistryAuthentication<'a> {
    /// Registry username.
    pub username: &'a str,
    /// Registry password.
    pub password: &'a str,
    /// Registry server address.
    pub serveraddress: &'a str,
    /// Optional identity token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identitytoken: Option<&'a str>,
    /// Optional registry token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrytoken: Option<&'a str>,
}
impl std::fmt::Debug for RegistryAuthentication<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryAuthentication(<redacted>)")
    }
}

/// Authentication response; Debug withholds both peer-controlled fields.
#[derive(Deserialize)]
pub struct RegistryAuthenticationResult {
    /// Status text returned by the Engine.
    #[serde(rename = "Status", default)]
    pub status: String,
    /// Identity token returned by the Engine.
    #[serde(rename = "IdentityToken", default)]
    pub identity_token: String,
}
impl std::fmt::Debug for RegistryAuthenticationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryAuthenticationResult(<redacted>)")
    }
}

/// Authenticate against a registry. Failures withhold all peer and transport
/// text and source chains; a rejection retains its HTTP status. Response bodies
/// are bounded by the normal document limit and are never logged.
///
/// # Errors
/// Returns a content-free error on transport, rejection, or decoding failure.
pub async fn registry_authenticate(
    engine: &RawEngine,
    auth: &RegistryAuthentication<'_>,
) -> Result<RegistryAuthenticationResult, Error> {
    let body = json_body(auth).map_err(|e| Error::withheld(e.kind(), WITHHELD))?;
    let request = json_content_type(RawRequest::new(Method::POST, "/auth")).with_body(body);
    let response = engine
        .send(request)
        .await
        .map_err(|e| e.withhold_transport(WITHHELD, WITHHELD))?;
    if !response.status.is_success() {
        return Err(Error::engine_api_withheld(response.status, WITHHELD));
    }
    let body = response
        .document()
        .await
        .map_err(|error| Error::from(error).withhold_transport(WITHHELD, WITHHELD))?;
    decode(&body).map_err(|e| Error::withheld(e.kind(), WITHHELD))
}

/// Inspect distribution metadata, retaining `Descriptor`, `Platforms`, and
/// unknown fields. This does not fetch manifest bodies or layers. The complete
/// JSON document is bounded by the normal document limit.
///
/// # Errors
/// Returns transport, status, or JSON decoding errors; empty names are refused.
pub async fn distribution_inspect(
    engine: &RawEngine,
    name: &str,
) -> Result<serde_json::Value, Error> {
    if name.is_empty() {
        return Err(Error::invalid_input("distribution name is empty"));
    }
    let path = format!("/distribution/{}/json", escape_path_segment(name));
    let response = engine
        .send(RawRequest::new(Method::GET, path))
        .await
        .map_err(|e| e.withhold_transport(DISTRIBUTION_WITHHELD, DISTRIBUTION_WITHHELD))?;
    if !response.status.is_success() {
        return Err(Error::engine_api_withheld(
            response.status,
            DISTRIBUTION_WITHHELD,
        ));
    }
    let body = response.document().await.map_err(|error| {
        Error::from(error).withhold_transport(DISTRIBUTION_WITHHELD, DISTRIBUTION_WITHHELD)
    })?;
    let value: serde_json::Value =
        decode(&body).map_err(|e| Error::withheld(e.kind(), DISTRIBUTION_WITHHELD))?;
    if !value.is_object() {
        return Err(Error::withheld(
            ErrorKind::InvalidInput,
            DISTRIBUTION_WITHHELD,
        ));
    }
    Ok(value)
}

/// List the platforms reported in a distribution inspection. Missing or null
/// `Platforms` is an empty list. This is not a list of registry repositories.
///
/// # Errors
/// Returns the same errors as [`distribution_inspect`], or a malformed platform list.
pub async fn distribution_list(
    engine: &RawEngine,
    name: &str,
) -> Result<Vec<serde_json::Value>, Error> {
    let value = distribution_inspect(engine, name).await?;
    match value.get("Platforms") {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::Array(platforms)) => Ok(platforms.clone()),
        Some(_) => Err(Error::withheld(
            ErrorKind::InvalidInput,
            "distribution response withheld",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{RegistryAuthentication, RegistryAuthenticationResult};

    #[test]
    fn authentication_debug_withholds_all_fields() {
        let auth = RegistryAuthentication {
            username: "username-canary",
            password: "password-canary",
            serveraddress: "server-canary",
            identitytoken: Some("identity-canary"),
            registrytoken: Some("registry-canary"),
        };
        let debug = format!("{auth:?}");
        assert!(!debug.contains("canary"));
        let result = RegistryAuthenticationResult {
            status: "status-canary".into(),
            identity_token: "token-canary".into(),
        };
        assert!(!format!("{result:?}").contains("canary"));
    }
}
