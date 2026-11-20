# neotales-docker-compose

Parse and resolve Compose documents, then plan and bind a local runtime without embedding a Docker daemon.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-docker-compose
```

Templates and values files are opt-in:

```sh
cargo add neotales-docker-compose --features templates
```

## What you can do

🧩 **Resolve a Compose document against values you supply.** `ComposeResolver` applies interpolation, includes, merge policy, and validation. It never reads the process environment.

```rust
use neotales_docker_compose::{
    ComposeDocument, ComposePolicy, ComposeResolver, InterpolationValues,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let document = ComposeDocument::parse_yaml(
    "services:\n  web:\n    image: ghcr.io/example/web:${TAG:-dev}\n    environment:\n      MODE: test\n",
    "compose.yaml",
)?;
let values = InterpolationValues::from_pairs([("TAG", "2026.11")]);
let resolved = ComposeResolver::resolve(&[document], &values, ComposePolicy::default())?;
assert!(resolved.to_json()?.contains("ghcr.io/example/web:2026.11"));
# Ok(())
# }
```

🔐 **Keep dotenv and the process environment separate.** `load_dotenv`, `load_dotenv_path`, and `load_dotenv_sources` parse only the source you name. `DotenvPolicy` chooses invalid-node handling, invalid-key handling, interpolation, and whether caller values or later assignments win.

```rust,no_run
use neotales_docker_compose::{DotenvOptions, load_dotenv_path};

let loaded = load_dotenv_path(".env", DotenvOptions::new())?;
let values = loaded.into_parts().1;
# Ok::<(), neotales_docker_compose::ComposeError>(())
```

🧭 **Plan the lifecycle, then bind concrete requests.** The planner emits deterministic create, start, and teardown operations with ownership labels. `ComposeRuntime::bind` produces image, argv, environment, ports, mounts, networks, and labels for a caller's Engine facade. The plan is redacted; the binding is not.

```rust
use neotales_docker_compose::{
    ComposePlanOptions, ComposePlanner, ComposeProject, ComposeProjectOptions, ComposeRuntime,
    InterpolationValues,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let values = InterpolationValues::from_pairs([("TAG", "2026.11")]);
let project = ComposeProject::parse_yaml(
    "name: demo\nservices:\n  web:\n    image: ghcr.io/example/web:${TAG}\n",
    "compose.yaml",
    &values,
    ComposeProjectOptions::default(),
)?;
let plan = ComposePlanner::create(&project, ComposePlanOptions::applied_up())?;
let runtime = ComposeRuntime::bind(&project, &plan)?;
assert_eq!(runtime.project_name, "demo");
# Ok(())
# }
```

🧮 **Merge values files for templates.** With `templates`, `parse_values` decodes JSON or YAML into the structured map a template ranges over, and `merge_values` recurses into nested mappings instead of replacing them. Numbers, booleans, and nulls stay distinct from strings.

```rust,ignore
use neotales_docker_compose::{merge_values, parse_values};
use neotales_sprig::Value;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut values =
    parse_values(r#"{"services":{"api":{"image":"api:1","replicas":3}}}"#, "values.json")?;
merge_values(
    &mut values,
    parse_values(r#"{"services":{"api":{"image":"api:2"}}}"#, "override.json")?,
);
let services = values.get("services").expect("services");
let Value::Map(services) = services else { unreachable!() };
let Value::Map(api) = services.get("api").expect("api") else { unreachable!() };
assert_eq!(api.get("image"), Some(&Value::String("api:2".into())));
assert_eq!(api.get("replicas"), Some(&Value::Number(3.0)));
# Ok(())
# }
```

A doctest cannot enable a feature of the crate under test, so this sample is not compiled by the default doctest pass. It compiles under `--all-features`.

## Limits

The default schema is bounded and strict. Unsupported fields are diagnosed rather than applied. The crate does not contact a Docker daemon, shell out to `docker compose`, or read ambient Docker configuration. Profiles, external network and volume attachment, build execution, Swarm `deploy` semantics, config and secret materialization, and the full container host configuration surface are outside this slice. The detailed planner, executor, binding, and label model is in [`docs/compose-runtime.md`](docs/compose-runtime.md).

## Licence

[MIT](LICENSE.md)
