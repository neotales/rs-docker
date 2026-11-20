//! Engine registry authentication without exposing transport credentials.

use http::{Method, header};
use serde::Serialize;

use crate::{DockerClient, Error, RegistryCredentials};

/// Result of authenticating with a registry through `POST /auth`.
///
/// The daemon status is safe to display. The stored credentials retain the
/// facade's redacted `Debug` implementation and zeroization behavior.
#[derive(Clone, Debug)]
pub struct RegistryAuthenticationResult {
    /// Registry authentication status returned by Docker.
    pub status: String,
    /// Credentials to persist after successful login.
    pub credentials: RegistryCredentials,
}

impl RegistryAuthenticationResult {
    /// Returns whether Docker reported a successful login.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status.contains("Login Succeeded")
    }
}

#[derive(Serialize)]
struct AuthRequest<'a> {
    username: &'a str,
    password: &'a str,
    serveraddress: &'a str,
}

impl DockerClient {
    /// Authenticates a registry through the Docker Engine API.
    ///
    /// The owned transport sends a versioned JSON request and reads a bounded
    /// response document.
    ///
    /// # Errors
    ///
    /// Returns a credential, transport, daemon, or response-decoding error.
    pub async fn authenticate_registry(
        &self,
        registry: &str,
        credentials: RegistryCredentials,
    ) -> Result<RegistryAuthenticationResult, Error> {
        credentials.validate_for(registry)?;
        let (username, secret, configured_server) = credentials.into_auth_parts();
        let server_address = if configured_server.is_empty() {
            registry.to_owned()
        } else {
            configured_server
        };
        let payload = serde_json::to_vec(&AuthRequest {
            username: &username,
            password: &secret,
            serveraddress: &server_address,
        })
        .map_err(Error::serialization)?;
        let request = crate::raw::RawRequest::new(Method::POST, "/auth")
            .with_header(header::CONTENT_TYPE, "application/json")
            .with_body(crate::raw::RawBody::from_bytes(payload.into()));
        let response = self.raw_engine()?.send(request).await?;
        let body = crate::raw::engine_result(response)
            .await
            .map_err(|error| error.withhold_api_message("registry authentication failed"))?;
        let document: serde_json::Value =
            serde_json::from_slice(&body).map_err(Error::serialization)?;
        let status = document
            .get("Status")
            .and_then(serde_json::Value::as_str)
            .filter(|status| !status.trim().is_empty())
            .ok_or_else(|| {
                Error::serialization(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "registry authentication response has no Status",
                )))
            })?
            .to_owned();
        let credentials = document
            .get("IdentityToken")
            .and_then(serde_json::Value::as_str)
            .filter(|token| !token.is_empty())
            .map_or_else(
                || RegistryCredentials::new(username, secret),
                RegistryCredentials::from_identity_token,
            )
            .with_server_address(server_address);
        Ok(RegistryAuthenticationResult {
            status,
            credentials,
        })
    }
}
