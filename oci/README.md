# neotales-oci-distribution

Normalize OCI Distribution references, verify content digests, negotiate media types, and keep registry credentials separate from the Docker Engine.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-oci-distribution
```

## What you can do

🏷️ **Normalize a registry reference.** User information, query strings, fragments, and path traversal are rejected instead of being carried into a request URL.

```rust
use neotales_oci_distribution::RegistryReference;

let reference = RegistryReference::parse("ghcr.io/example/app:2026.11")?;
assert_eq!(reference.registry(), "ghcr.io");
assert_eq!(reference.repository(), "example/app");
assert_eq!(reference.tag(), Some("2026.11"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

🔐 **Verify the body as well as the header.** `Digest::verify_content` checks that a `Docker-Content-Digest` value matches the bytes the registry returned. `Digest::verify_header` additionally checks it against the digest the caller expected.

```rust
use neotales_oci_distribution::{Digest, HeaderDigestError};

let content = b"manifest bytes";
let advertised = Digest::sha256(content);
let verified = Digest::verify_content(Some(advertised.as_str()), content)?;
assert_eq!(verified, advertised);
assert!(matches!(
    Digest::verify_content(Some(advertised.as_str()), b"other bytes"),
    Err(HeaderDigestError::Mismatch)
));
# Ok::<(), Box<dyn std::error::Error>>(())
```

🧭 **Negotiate manifest media types explicitly.** `ContentPolicy::manifests` accepts the OCI and Docker schema 2 manifest types, bounds the response, and requires a digest header by default.

```rust
use neotales_oci_distribution::{
    ContentPolicy, MediaType, OCI_IMAGE_MANIFEST,
};

let policy = ContentPolicy::manifests();
let content_type = OCI_IMAGE_MANIFEST;
let body = b"{}";
let digest = neotales_oci_distribution::Digest::sha256(body);
let verified = policy.verify(Some(content_type), Some(digest.as_str()), body)?;
assert_eq!(verified.media_type().essence(), OCI_IMAGE_MANIFEST);
assert!(policy.accepts_upload(&MediaType::constant(OCI_IMAGE_MANIFEST)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

🧪 **Round-trip against a deterministic local registry.** `LocalRegistryFixture` stores blobs and manifests in memory. It needs no daemon, network, Engine socket, or ambient Docker configuration.

```rust
use neotales_oci_distribution::{
    FIXTURE_REPOSITORY, FIXTURE_TAG, LocalRegistryFixture, MediaType, OCI_IMAGE_MANIFEST,
};

let fixture = LocalRegistryFixture::deterministic();
let manifest = fixture.get_manifest(
    FIXTURE_REPOSITORY,
    FIXTURE_TAG,
    &[MediaType::constant(OCI_IMAGE_MANIFEST)],
    fixture.default_policy(),
)?;
assert_eq!(manifest.media_type().essence(), OCI_IMAGE_MANIFEST);
# Ok::<(), Box<dyn std::error::Error>>(())
```

🔑 **Keep registry credentials out of Engine state.** A `RegistryCredential` is zeroized on drop and redacted from `Debug` and `Display`. The crate never reads Docker Engine `X-Registry-Auth` or a credential helper.

```rust
use neotales_oci_distribution::{CredentialScheme, RegistryCredential};

let credential = RegistryCredential::try_basic("robot", "registry-token")?;
assert_eq!(credential.scheme(), CredentialScheme::Basic);
assert!(!format!("{credential:?}").contains("registry-token"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Limits

This is a policy and fixture layer, not an HTTP client. It does not implement transport, retries, resumable uploads, mirroring, or Buildx/imagetools behavior. A future transport must use this crate's credential provider rather than Engine `X-Registry-Auth` state. The fixture proves the policy against deterministic content; it does not claim a live registry accepted the same request.

## Licence

[MIT](LICENSE.md)
