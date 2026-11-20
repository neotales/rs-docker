# neotales-docker-buildkit

Define a BuildKit builder, solve request, status stream, and cancellation handle without hiding a daemon behind a generated client.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-docker-buildkit
```

## What you can do

🧱 **Name the builder explicitly.** `BuilderSelection` carries the endpoint the caller chose. It does not fall back to `DOCKER_HOST`, a Docker context, Buildx, or a local Engine socket.

```rust
use neotales_docker_buildkit::{BuilderEndpoint, BuilderSelection};

let builder = BuilderSelection::new(
    "contract-fixture",
    BuilderEndpoint::parse("https://builder.fixture:9443")?,
)?;
assert_eq!(builder.label(), "contract-fixture");
# Ok::<(), Box<dyn std::error::Error>>(())
```

📦 **Bound the context before it is sent.** `BuildContext` caps the bytes, and `DockerfilePath` keeps the Dockerfile inside that context.

```rust
use neotales_docker_buildkit::{
    BuildContext, BuilderEndpoint, BuilderSelection, DockerfilePath, SolveRequest,
};

let builder = BuilderSelection::new(
    "contract-fixture",
    BuilderEndpoint::parse("https://builder.fixture:9443")?,
)?;
let request = SolveRequest::new(
    builder,
    BuildContext::new(b"FROM scratch\n".to_vec())?,
    DockerfilePath::new("Dockerfile")?,
);
assert_eq!(request.context.as_bytes(), b"FROM scratch\n");
# Ok::<(), Box<dyn std::error::Error>>(())
```

🔁 **Read status until one terminal state.** `SolveHandle` yields status updates and owns the end of the solve. Dropping the handle requests cancellation.

```rust,no_run
use neotales_docker_buildkit::{
    BuildContext, BuildKitAdapter, BuildKitAdapterFixture, BuilderEndpoint, BuilderSelection,
    DockerfilePath, SolveRequest,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let builder = BuilderSelection::new(
    "contract-fixture",
    BuilderEndpoint::parse("https://builder.fixture:9443")?,
)?;
let fixture = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/solve-success.json"));
let adapter = BuildKitAdapterFixture::from_json(builder.clone(), fixture)?;
let request = SolveRequest::new(
    builder,
    BuildContext::new(b"FROM scratch\n".to_vec())?,
    DockerfilePath::new("Dockerfile")?,
);
let mut solve = adapter.start_solve(request).await?;
while let Some(status) = solve.next_status().await {
    println!("{status:?}");
}
# Ok(())
# }
```

🛑 **Cancel once, cooperatively.** `SolveCancellation` is idempotent, and the adapter owns remote-session cleanup and the final status. Requesting cancellation does not synchronously tear down a remote session.

## Limits

This release is a fixture adapter, not a transport. It replays versioned status JSON for one exact builder endpoint. It does not implement remote BuildKit sessions, cache import or export, h2c transport, local context walking, Dockerfile transfer, build arguments, secrets, credentials, SSH forwarding, named contexts, cache selectors, exporters, multi-platform solves, Buildx behavior, or the classic Engine `POST /build` route. Bollard's optional BuildKit support is not enabled. A solve cannot fall back to a different builder when its endpoint does not match.

## Licence

[MIT](LICENSE.md)
