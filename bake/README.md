# neotales-docker-bake

Parse Docker Bake JSON, resolve target inheritance, and plan an ordered target graph without contacting a builder.

By [x0craft](https://github.com/x0craft).

[![Neotales](https://github.com/neotales/brand/raw/main/assets/logo.png)](https://github.com/neotales/rs-docker)

<!-- badges: crates.io, docs.rs, CI. Add once the crate name and first version exist. -->

## Install

```sh
cargo add neotales-docker-bake
```

Templates are opt-in:

```sh
cargo add neotales-docker-bake --features templates
```

## What you can do

📦 **Plan the targets a build needs.** `parse_and_plan` normalizes the document, validates groups and named contexts, and returns an owned graph in dependency order.

```rust
use neotales_docker_bake::parse_and_plan;

let graph = parse_and_plan(
    r#"{
        "target": {
            "base": {"context": ".", "dockerfile": "Dockerfile"},
            "app": {"inherits": ["base"], "tags": ["example/app:latest"]}
        },
        "group": {"default": {"targets": ["app"]}}
    }"#,
    &["default"],
)?;
assert_eq!(graph.target("app").unwrap().dockerfile, "Dockerfile");
# Ok::<(), neotales_docker_bake::BakeError>(())
```

🧬 **Inherit and merge targets deterministically.** Target fields merge in declaration order. Maps merge by key; scalar lists replace. A cycle is reported with the inheritance trace instead of being flattened.

```rust
use neotales_docker_bake::parse_normalized_json;

let document = parse_normalized_json(
    r#"{
        "variable": {"TAG": {"default": "2026.11"}},
        "target": {
            "base": {"args": {"MODE": "release"}, "tags": ["base:latest"]},
            "app": {
                "inherits": ["base"],
                "args": {"MODE": "debug"},
                "tags": ["app:${TAG}"]
            }
        }
    }"#,
)?;
let graph = document.plan(&["app"])?;
let app = graph.target("app").unwrap();
assert_eq!(app.args.get("MODE").and_then(Option::as_deref), Some("debug"));
assert_eq!(app.tags, ["app:2026.11"]);
# Ok::<(), neotales_docker_bake::BakeError>(())
```

🔐 **Keep variable lookup explicit.** `VariableValues` is an ordered map with the host platform's key rules. Nothing reads the process environment or discovers a `.env` file on its own.

```rust
use neotales_docker_bake::{VariableValues, normalize_with_values, parse_json};

let document = parse_json(
    r#"{
        "variable": {"TAG": {"description": "image tag"}},
        "target": {"app": {"tags": ["app:${TAG}"]}}
    }"#,
)?;
let values = VariableValues::from_pairs([("TAG", "2026.11")]);
let normalized = normalize_with_values(&document, &values)?;
assert_eq!(normalized.plan(&["app"])?.target("app").unwrap().tags, ["app:2026.11"]);
# Ok::<(), neotales_docker_bake::BakeError>(())
```

🧾 **Load dotenv only when you name it.** `load_dotenv_path` returns ordered `VariableValues` and a document that preserves where each assignment came from. `DotenvPolicy` makes invalid nodes, invalid keys, interpolation, and precedence explicit.

```rust,no_run
use neotales_docker_bake::{DotenvOptions, load_dotenv_path};

let loaded = load_dotenv_path(".env.build", DotenvOptions::new())?;
let values = loaded.into_parts().1;
# Ok::<(), neotales_docker_bake::BakeError>(())
```

🎨 **Render templates before parsing.** With the `templates` feature, `render_template` accepts explicit source and caller-owned values, applies finite limits, and returns source without `{{` unchanged. The normalized JSON parser does not require the feature.

```rust,ignore
use neotales_docker_bake::{TemplateOptions, VariableValues, render_template};

let values = VariableValues::from_pairs([("TAG", "2026.11")]);
let source = render_template("tags: [app:{{ .TAG }}]", &values, &TemplateOptions::new())?;
assert_eq!(source, "tags: [app:2026.11]");
# Ok::<(), neotales_docker_bake::TemplateError>(())
```

## Limits

The default crate accepts Docker Bake's JSON shape, not HCL. The bounded target fields are `inherits`, `context`, `dockerfile`, `args`, `labels`, `contexts`, `tags`, `platforms`, `target`, `no-cache`, `pull`, and `description`; other fields are rejected rather than ignored. Complex variable types and typed evaluation are deferred; string defaults expand during normalization. The crate never contacts a builder, injects a solver, reads the process environment, or converts Compose files. `neotales-docker` and `neotales-docker-buildkit` are not dependencies.

## Licence

[MIT](LICENSE.md)
