# neotales-docker

Talk to the Docker Engine API through a repository-owned transport, with typed models and caller-owned streams instead of a generated client.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-docker
```

TLS and managed SSH are features:

```sh
cargo add neotales-docker --features tls,ssh
```

The `ssh` feature is Unix-only. It runs the system `ssh` binary for `docker system dial-stdio`, so the invoking user's `ssh_config`, known-hosts files, identity discovery, and host-key policy apply.

## What you can do

🔌 **Connect to the daemon you name.** `connect_local`, `connect_http`, `connect_socket`, `connect_ssh_managed`, and the versioned endpoint constructors capture one target. An unavailable endpoint fails before dispatch; requests are not retried over another transport.

```rust
use neotales_docker::DockerClient;

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
client.ping().await?;
# Ok(())
# }
```

📋 **Read containers and images as owned values.** `ContainerSummary`, `ImageSummary`, `ImageInspect`, and their neighbours belong to this crate. Docker's JSON filter maps are ordered `BTreeMap` values, so the encoded query is deterministic.

```rust,no_run
use neotales_docker::{DockerClient, ImageListOptions};

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
let containers = client.list_containers().await?;
let images = client.list_images(Some(ImageListOptions::default())).await?;
println!("{} containers, {} images", containers.len(), images.len());
# Ok(())
# }
```

📜 **Stream logs, stats, and events.** A stream handle is independent of the client. Dropping it, or calling `cancel()` or `close()`, releases the response and closes the connection.

```rust,no_run
use neotales_docker::{ContainerLogsOptions, DockerClient};

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
let mut logs = client.logs(
    "demo",
    Some(ContainerLogsOptions {
        follow: true,
        stdout: true,
        stderr: true,
        ..Default::default()
    }),
);
while let Some(frame) = logs.next().await {
    let frame = frame?;
    println!("{:?}: {:?}", frame.stream, frame.payload);
}
# Ok(())
# }
```

🏗️ **Build from a bounded context.** The classic `/build` route is the default. `build_image_buildkit` uses the `/session` h2c upgrade, filesync context transfer, secrets, and `Control.Solve`/`Status`; `ndocker build --buildkit` selects it. Neither path silently falls back to the other.

```rust,no_run
use neotales_docker::{DockerClient, ImageBuildContext, ImageBuildOptions};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = DockerClient::connect_local()?;
let context = ImageBuildContext::from_directory(".")?;
let mut build = client.build_image(
    context,
    Some(ImageBuildOptions {
        tags: vec!["app:dev".to_owned()],
        ..Default::default()
    }),
)?;
while let Some(event) = build.next().await {
    println!("{:?}", event?);
}
# Ok(())
# }
```

🔒 **Keep secret reads on the owned path.** `list_secrets` and `inspect_secret` have no generated fallback. A non-success answer preserves the HTTP status but withholds daemon or proxy text, because that text can echo secret bytes. `SwarmSecret` and `SwarmSecretSpec` have hand-written `Debug` implementations that report identity lengths and counts, never names, labels, drivers, or unexpected `Data`.

🛠️ **Reach the versioned raw API when a typed model is too narrow.** `raw` exposes the same owned transport with `RawEngine`, `RawTarget`, and typed operation functions. The wire path carries the API version, and unmodelled members survive where the document functions retain them.

## Limits

The compatibility ceiling is Docker Engine API 1.55. That is the path prefix and request shape, not a claim that every 1.54 or 1.55 field has a typed member. In particular, image-list `identity`, `GET /images/{name}/attestations`, and per-device blkio members on container update are not implemented; some document functions preserve the daemon's JSON instead. There is no generated-client fallback: a route that the owned transport cannot reach fails closed, and a failed request is returned rather than retried through another client. Bollard models are not part of the public contract. Compose, Bake, `BuildKit` contracts, OCI Distribution policy, and environment discovery live in separate crates. The conformance table, resource slices, security rationale, and migration notes are in [`docs/engine-api.md`](docs/engine-api.md).

## Licence

[MIT](LICENSE.md)
