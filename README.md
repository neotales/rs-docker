# rs-docker

Five crates for talking to Docker without a generated client: a Bake planner, a BuildKit contract, a Compose resolver, an Engine API client, and an OCI Distribution policy layer.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate names and first versions exist. -->

## Install

```sh
cargo add neotales-docker-bake neotales-docker-buildkit neotales-docker-compose neotales-docker neotales-oci-distribution
```

Add features only where the crate offers them:

```sh
cargo add neotales-docker-bake --features templates
cargo add neotales-docker-compose --features templates
cargo add neotales-docker --features tls,ssh
```

## What you can do

🧱 **Plan a Bake build.** `neotales-docker-bake` parses Bake JSON, merges target inheritance, and returns an ordered target graph without contacting a builder.

🧩 **Resolve Compose without a daemon.** `neotales-docker-compose` normalizes documents, applies explicit values and includes, and plans or binds a local runtime. It never reads the process environment on its own.

🛠️ **Call the Engine API directly.** `neotales-docker` owns the transport, typed models, streaming handles, Swarm resources, BuildKit sessions, and credential redaction. There is no generated-client fallback.

🔒 **Verify registry content.** `neotales-oci-distribution` normalizes references, checks content digests, negotiates media types, and keeps registry credentials separate from Engine state.

🧪 **Test against fixtures, not a daemon.** `neotales-docker-buildkit` exposes the builder and solve contract with a deterministic fixture adapter. The other crates carry loopback fixtures for the wire paths they own.

```rust
use neotales_docker::DockerClient;

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
client.ping().await?;
# Ok(())
# }
```

## Crates

This repository is a virtual Cargo workspace. Every crate directory is shippable, and all five share one version.

| Crate | Directory | What it does |
| --- | --- | --- |
| `neotales-docker-bake` | `bake/` | Normalized Docker Bake document parsing and target planning |
| `neotales-docker-buildkit` | `buildkit/` | Explicit BuildKit builder and solve contracts with a fixture adapter |
| `neotales-docker-compose` | `compose/` | Explicit, daemon-free Compose document and resolution primitives |
| `neotales-docker` | `engine/` | Repository-native Docker Engine API client |
| `neotales-oci-distribution` | `oci/` | OCI Distribution references, digests, media types, and registry policy |

Each crate has its own README with samples: [bake](bake/README.md), [buildkit](buildkit/README.md), [compose](compose/README.md), [engine](engine/README.md), [oci](oci/README.md).

The Engine client and the Compose resolver do not share code: `neotales-docker` speaks to a daemon over its own transport, and `neotales-docker-compose` is daemon-free. A program that needs both depends on both.

`fixtures/` at the repository root holds deterministic documents used by repository-level tests and documentation. Each package keeps its own copy of the fixtures its tests read, because a package does not ship the repository root. `fixtures/` is not a crate.

## Licence

[MIT](LICENSE.md)
