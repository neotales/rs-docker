# rs-docker

Five crates for talking to Docker without a generated client: a Bake planner, a
BuildKit contract, a Compose resolver, an Engine API client and an OCI
Distribution policy layer.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

This repository is a virtual Cargo workspace. Every directory is a shippable
crate, and all five share one version:

| Crate | Directory | What it does |
| --- | --- | --- |
| `neotales-docker-bake` | `bake/` | Normalized Docker Bake document parsing and target planning |
| `neotales-docker-buildkit` | `buildkit/` | Explicit BuildKit builder and solve contracts with a fixture adapter |
| `neotales-docker-compose` | `compose/` | Explicit, daemon-free Compose document and resolution primitives |
| `neotales-docker` | `engine/` | Repository-native Docker Engine API client |
| `neotales-oci-distribution` | `oci/` | OCI Distribution references, digests, media types and registry policy |

Each crate has its own README with samples: [bake](bake/README.md),
[buildkit](buildkit/README.md), [compose](compose/README.md),
[engine](engine/README.md), [oci](oci/README.md).

The Engine client and the Compose resolver do not share code: `neotales-docker`
speaks to a daemon over its own transport, and `neotales-docker-compose` is
daemon-free. A program that needs both depends on both.

`fixtures/` holds the deterministic documents the tests and the Engine README
read. It is not a crate.

## Licence

[MIT](LICENSE.md)
