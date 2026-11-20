# Compose runtime model

This page carries the detailed lifecycle, planner, executor, and binding notes that the crate README does not repeat. The README is the front page; this is the model behind it.

## Lifecycle model, planner, and executor

The normalized `ComposeProject` adds the bounded local lifecycle fields needed
by a Compose adapter: services, dependency order, replicas, image pull/build intent,
ports, bind/volume/tmpfs mounts, networks, labels, and typed project name. The
source parser records bind paths but never opens them. `ComposePlanner` emits a
canonical, SHA-256-addressed plan with explicit pull/build/resource/container/
start/teardown operations, ownership labels, destructive markers, and
redaction-safe intent. `ComposeConfigRenderer` and `ComposeBridgeDocument` are
daemon-free projections; neither is a Kubernetes manifest or an Engine request.

`ComposeExecutor` is an operation-sink boundary rather than a second Docker
client. It checks cooperative cancellation before each operation and rolls back
only resources reported as created by the current invocation. The deterministic
`planner_executor` fixture records the exact operation order; callers can adapt
the sink to the public `neotales-docker` facade without exposing Bollard models.

## Applied runtime binding

`ComposeRuntime` is the inverse of the planner. A plan is redacted and
serializable, so it is the right artifact to print and diff but not the right
artifact to send: environment values, bind sources, and user labels are
`<redacted>` in a plan. `ComposeRuntime::bind` produces the concrete typed
values an Engine request needs — container image, argv, `NAME=value`
environment, exposed ports and publications, bind and tmpfs mounts, network
attachments with aliases, and unredacted labels — while staying free of any
daemon client. A caller maps these specs onto its own Engine facade.

Binding is where unsupported input is rejected, so no request is issued for a
service that cannot be created:

| Code | Rejected because |
| --- | --- |
| `compose_runtime_project_mismatch` | The plan and project describe different projects. |
| `compose_undeclared_network` | A service attaches to a network the project does not declare. |
| `compose_undeclared_volume` | A service mounts a volume the project does not declare. |
| `compose_external_volume_not_attached` | The attached slice does not create or mount external volumes. |
| `compose_bind_mount_requires_source` | A `type: bind` mount has no source. |
| `compose_runtime_unbound_operation` | A plan create operation has no request specification. |
| `compose_runtime_unplanned_network` | A container attaches to a network the plan does not create. |
| `compose_runtime_missing_image` | A service has no image. |

Every spec carries the Compose ownership labels
(`com.docker.compose.project`, `com.docker.compose.version`,
`com.neotales.compose.config-digest`); containers add the service,
container-number, oneoff, depends-on, and network labels. The exported label
key constants are `COMPOSE_PROJECT_LABEL`, `COMPOSE_SERVICE_LABEL`,
`COMPOSE_VERSION_LABEL`, `COMPOSE_CONFIG_DIGEST_LABEL`,
`COMPOSE_CONTAINER_NUMBER_LABEL`, `COMPOSE_ONEOFF_LABEL`, `COMPOSE_ONEOFF_VALUE`,
`COMPOSE_NETWORK_LABEL`, `COMPOSE_DEPENDS_ON_LABEL`, and
`COMPOSE_DEFAULT_NETWORK_KEY`.

`ComposePlanOptions::default_network` makes the planner create the implicit
`<project>_default` network that Compose attaches services without a declared
network to. The library default is `false`, so an explicitly modeled project is
planned exactly as written; a caller that executes containers against a daemon
enables it. `ComposePlanOptions::applied_create` and `applied_up` set it together
with the matching start behavior, and also apply the same flag in teardown plans
so `down` removes the default network.

`ComposeProject::select_services_with_dependencies` selects services together
with everything they require, in dependency order.
`ComposeProject::narrow` returns a project limited to those services and the
networks and volumes they reference, so an applied plan never creates an orphan.
Neither changes the project name, so ownership labels, Engine names, and the
configuration digest are unaffected.

`depends_on` conditions are normalized here, and a condition outside
`service_started`, `service_healthy`, and `service_completed_successfully` is
rejected with `compose_invalid_dependency_condition` at parse time rather than
normalized to something a caller would have to second-guess. The crate stays
daemon-free: it carries the condition on `ComposeDependency` and does not decide
when it is satisfied. A Compose adapter evaluates it by polling
`DockerClient::container_details` and gates the dependent container's create on
the result; see the Compose adapter's own documentation for the bounded-wait policy.

`ComposeExecutionError` carries a stable code, a safe message, and an optional
`raw` string for lower-layer text a caller may print in raw-error mode. The raw
text is never used to build the message.

## Bounded specification areas

Docker Compose 5.6.1 reference check: `docker compose config` rejects
`environment` and `file` directly in an item of `services.app.build.secrets`
as additional properties. A top-level `secrets.token.external: true` referenced
by `build.secrets: [token]` is accepted and renders as a `source: token` grant
and a top-level external secret with `name: token`. Secret source definitions
belong at the top level, not inside a build grant.
The same reference accepts build-grant `uid`, `gid`, and `mode` and preserves
them in the normalized output; ndocker currently refuses those attributes
because they cannot be expressed in the `BuildKit` secret session response.

The project intentionally diagnoses rather than silently applies areas outside
this local slice:

- profiles and profile-based service selection;
- attaching external networks or external volumes;
- build execution, so a `build` declaration only ever becomes plan intent here.
  The declaration is normalized in full (`context`, `dockerfile`, `target`,
  `platform`, `no_cache`, `pull`, `args`, `labels`, `cache_from`), and any
  `BuildKit`-only field it declares is recorded by name in
  `ComposeBuild::buildkit` rather than dropped, so an executor can refuse it
  explicitly instead of quietly building something else;
- `include` forms outside the filesystem-backed subset above;
- Swarm `deploy`/task semantics;
- configs, secrets, and credential-spec materialization;
- classic image-build request bodies and `BuildKit` session/negotiation, which
  belong to the `neotales-docker` image facade rather than to this model;
- extensions with engine semantics and cross-project composition providers;
- the full runtime host configuration surface (devices, capabilities, resource
  limits, health/readiness polling, and lifecycle hooks).

The model supports `develop.watch` actions including `sync+exec`.
`ndocker compose watch` and `ndocker compose publish` are implemented by the
CLI; they are not daemon-free library lifecycle operations.

The small supported subset still has deterministic policy gates for host
paths, devices, privileged services, published ports, pulls, builds, and Docker
socket mounts. Callers must opt in to the corresponding gate before planning a
plan that contains that intent.
