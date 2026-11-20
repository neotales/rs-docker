# neotales-docker

Repository-native Docker Engine API access through the owned transport. The
compatibility target is Docker Engine API v1.55. Facade operations use only the
owned transport, including the endpoint captured by `connect_local`; an
unavailable endpoint fails rather than falling back to a generated client.
Requests are not retried through another transport after a failure.

Bollard 0.21.1's generated API v1.53 client was used before this migration.
Comparisons with it below are historical, not descriptions of active routing.

## Conformance boundary for 1.54 and 1.55

Targeting 1.55 is a claim, and this is the other side of it: what 1.54 and 1.55
added that this crate does **not** implement. The list is not a caveat on the
ceiling, it is the ceiling's boundary. Nothing in it is a regression against
1.53, because moby's `v1.53.yaml` and `v1.55.yaml` differ only by addition — no
path, definition, field, or required member was removed across the two
versions, checked by diffing both documents key-by-key at every depth.

| Version | Added | This crate |
| --- | --- | --- |
| 1.54 | `GET /images/json` gains an `identity` query parameter, and each manifest summary gains an `Identity` member | not implemented: the owned list request does not send `identity` and no repository-owned model carries `Identity` |
| 1.54 | `POST /networks/{id}/connect` now applies the `MacAddress` in `EndpointSettings`, which the daemon had accepted and ignored since 1.44 | implemented by not needing to be: the owned connect body has always sent `MacAddress`, so the field becomes live rather than inert |
| 1.55 | `GET /images/{name}/attestations`, a new endpoint returning in-toto attestation statements filtered by `platform`, `type`, and `statement` | not implemented: no owned function reaches the endpoint and no model describes an `AttestationStatement` |
| 1.55 | `POST /containers/{id}/update` honours the per-device blkio members it had always accepted and ignored | not implemented and not reachable: `ContainerUpdateOptions` carries only `cpu_shares` and `memory` |

Two further 1.55 changes are documentation-only: a `StopTimeout` description
that now names the `default-stop-timeout` setting, and clarifications to the
`/secrets` and `/configs` filter documentation.

**The `MacAddress` row is a behaviour change, not a gap.** A caller who set
`mac_address` on a network connect and watched the daemon ignore it will, at
1.55, watch the daemon apply it. That is the daemon correcting a bug, and code
that measured "I asked for this MAC and got whatever the pool handed out" should
not be relying on it.

**Raising the path version does not implement every model.** Some 1.54 and
1.55 fields remain outside the typed API. Where offered, owned document
functions such as `raw::image_list_documents` retain the daemon's JSON.

The crate exposes bounded Engine resource, stream, system, and context-archive
slices over the foundation: typed image list/inspect/history/tag/search/prune
values, network and volume operations, Swarm services/nodes/configs/secrets/tasks,
container and Swarm log streams, stats, daemon events, authenticated image
pull/push progress, image archive downloads, container filesystem archive
stat/download/upload, and safe Docker context TAR/ZIP import/export. Bollard request, response, stream, and credential models are not
part of the public contract. `BuildKit`, `Compose`, `Bake`, `OCI`
Distribution, and environment policy remain separate concerns.

## Usage

```rust,no_run
use neotales_docker::DockerClient;

# async fn example() -> Result<(), neotales_docker::Error> {
let client = DockerClient::connect_local()?;
client.ping().await?;
let containers = client.list_containers().await?;
println!("{} containers", containers.len());
# Ok(())
# }
```

## Image resource slice

### Build boundary

Classic Engine `/build` remains the default. `BuildKit` is implemented through
the `/session` h2c upgrade, HTTP/2 stream dispatch, `moby.filesync.v1`
`DiffCopy` context transfer (including ordered include/exclude filters and
`.dockerignore`), the secrets provider, and `Control.Solve`/`Status`.
`BuildKitBuildOptions` is exposed by this crate. `ndocker build --buildkit`
selects `BuildKit` and `--secret` supplies build secrets; neither path silently
falls back to classic. Contexts remain bounded local inputs, not remote
downloads. Registry cache imports and exports are supported, with `mode=min`
or `mode=max` on exports; a valid mode on imports is ignored, as it is by the
upstream registry importer. `gha` and `s3` attributes are forwarded to the
daemon, which performs their transfers if its backend is enabled; neither has
been verified with a successful round-trip. In particular the tested Docker
Engine 29.9.2 daemon reports `unknown cache exporter: "s3"`. `local` is
refused: pinned `BuildKit`'s `cache/remotecache/local/local.go` calls the
session content store service, not filesync. Supporting it requires that
service plus client-side OCI index and blob-store management (see
`client/solve.go` at `BuildKit` commit 6aebc64bd145fdf0bc27d439a75a47890fee80ba).
A single Dockerfile can be supplied as the context; it is sent as
the requested Dockerfile name through the same bounded filesync session.
SSH mounts and backslash-escaped followpaths are refused.

`DockerClient` exposes the repository-owned image operations
`list_images`, `inspect_image` (plus `inspect_image_with_options`),
`image_history` (plus `image_history_with_options`), `tag_image`,
`search_images`, `prune_images`, and `remove_image`. Results use
`ImageSummary`, `ImageInspect`, `ImageHistory`, `ImageSearchResult`, and
`ImagePruneResult`; their request/response conversions and all nested values
are private to the facade. Search and prune filters are ordered `BTreeMap`
values and are encoded as Docker's JSON filter query deterministically.
`ImageInspectOptions` and `ImageHistoryOptions` carry the v1.55 JSON-encoded
platform selector without exposing a Bollard OCI model. `ImageTagOptions` also
preserves the Engine `force` query flag, which is absent from Bollard 0.21.1's
generated tag option type; the owned transport encodes this query directly.

Image inspection includes stable configuration, root-filesystem, storage-driver,
and local-metadata projections. Experimental OCI descriptors, manifest
summaries, and identity records remain outside the typed models — `Identity`
is a 1.54 addition, so it is named in the
[conformance table](#conformance-boundary-for-154-and-155) above rather than
carried here. The client's API ceiling is v1.55. That is a statement about the
path prefix the owned transport sends and about the request shapes it encodes;
it is **not** a claim that every field 1.54 or 1.55 defined is reachable through
a type in this crate, and it is not a claim about v1.56.

Build, load, and import use bounded owned request-body streams; save and
export provide owned archive streams. Platform-specific image deletion remains
outside this typed slice.

`tests/engine_resources.rs` and `tests/image_operations.rs`, together with the
JSON files under `../fixtures/docker/engine/images/` (fixture paths in this
README are relative to this file), provide deterministic local HTTP fixtures
for response mapping, request paths, query encoding, and Docker API errors. API
failures are available as `Error::api_error()` with a repository-owned
status/message pair.

## Container list projection

`list_containers` and `list_containers_with_options` return repository-owned
`ContainerSummary` values. The projection carries container id, names, image and
image id, command, creation time, ports, daemon state, human-readable status,
and the container's `labels`. The owned decoder projects labels into an ordered `BTreeMap<String, String>`
rather than a hash map: a caller that compares, hashes, or prints them gets the
same ordering every call, and a container with no labels projects to an empty
map. No existing field or behavior changes with the addition.

## Container readiness projection

`container_details` returns repository-owned `ContainerDetails`. Alongside the
existing `tty`, `exit_code`, `status`, and `ports`, the projection carries the
two fields a readiness decision needs, both read from the same daemon state so
one request answers the whole question:

- `health: Option<String>` is the daemon's health status, lowercased:
  `healthy`, `unhealthy`, `starting`, or `none`. It is `None` when the container
  has no health state at all, which is how a container without a healthcheck
  appears. That distinction is the point: a caller can tell "no healthcheck
  configured" apart from "the healthcheck has not reported yet" and refuse the
  first instead of waiting for a status that can never appear. An empty daemon
  spelling also projects to `None` so the value is never a bare empty string.
- `running: Option<bool>` is `State.Running`, or `None` when the daemon omits it.

Bollard's `ContainerState`, `Health`, and `HealthStatusEnum` models stay
private to this adapter, exactly like every other generated model. No existing
field or behavior changes with the addition. The Compose adapter in this repository is the
current consumer: it polls this projection to honor `depends_on`
`service_healthy` and `service_completed_successfully`.

## Container archive slice

`container_archive`, `container_path_stat`, and `upload_container_archive`
cover the Engine's `HEAD`, `GET`, and `PUT /containers/{id}/archive` endpoints.
Each uses the owned transport selected by `DockerClient::raw_engine`.
An unavailable target fails before dispatch; a failed upload is never retried.

On the owned path the requests carry the API version prefix, the container
reference is percent-encoded into exactly one path segment, and `path` is
percent-encoded as one query value. The path is otherwise passed to the daemon
verbatim: the client does not resolve `..`, follow a symlink, or rewrite a
trailing slash, because those spellings have the container's meaning. An empty
reference or path is refused as `ErrorKind::InvalidInput` before a connection is
opened; the former generated path passed it through.

The `HEAD` answer carries its metadata in `X-Docker-Container-Path-Stat`, a
**standard**-base64 JSON object — the opposite alphabet from
`X-Registry-Auth`, which the daemon decodes as URL-safe base64. The owned path
decodes the header into the same `ContainerPathStat` projection the generated
path produces: `name`, `size`, `mode`, and `linkTarget`, with an empty target
projected to `None`. The `mtime` member the daemon also sends has no home in
that model. A missing, malformed, or incomplete header is an
`ErrorKind::InvalidInput` error rather than an empty stat, an encoded value over
16 KiB is refused before base64 or JSON work begins, and no error echoes the
header value or the container path. A `404` means "not there" and
`container_path_stat` reports it as `None` on the owned route; `container_archive`
reports it as the daemon's API error.

The download is a byte stream, never a collected archive: each item is one
transport chunk, an incomplete HTTP body is a transport error item, and dropping
or cancelling the handle closes the connection. TAR integrity is not validated,
so a caller that needs a whole archive verifies it itself. The `HEAD` is awaited
before `container_archive` returns, while the `GET` is opened when the returned
stream is first polled.

The upload sends the file as a chunked `application/x-tar` body with no
`Content-Length`, never buffered whole. `copyUIDGID` is always written as `1` or
`0` and `noOverwriteDirNonDir` only when requested, which is the shape the
former generated path sent. The former generated path additionally appended its default
`application/json` content type after the archive type, so its upload carried
two `Content-Type` values; the owned path sends only `application/x-tar`, which
is the type this endpoint declares. There is deliberately no fixed size cap: a
container archive is as large as the part of the container it describes, a fixed
cap would refuse a legitimate large copy, and it would make the same call
succeed or fail depending on which transport served it. The daemon extracts
entries as it reads them, so dropping the upload future, a source error, or a
transport failure can leave the destination partially updated; there is no
rollback and no effect guarantee, and a retry must reconcile the container
first.

`tests/container_archive.rs` pins the versioned requests, stat header,
streamed upload, cancellation, and no-retry behavior using loopback fixtures.
The former fallback fixture was removed with that route.

## Network and volume resource slice

`DockerClient` exposes repository-owned `list_networks`, `inspect_network`,
`create_network`, `remove_network`, `connect_network`, `disconnect_network`, and
`prune_networks` operations. Network filters are ordered `BTreeMap` values and
are encoded as Docker's JSON filter query deterministically. IPAM, endpoint,
creation, label, and driver values are projected into repository-owned types;
daemon-specific service, peer, status, and cluster-volume objects are outside
this bounded slice.

`list_volumes`, `inspect_volume`, `create_volume`, `remove_volume`, and
`prune_volumes` provide the corresponding typed volume boundary, including
volume warnings, usage data, labels, driver options, and forced removal. The
owned transport handles the request and response, and API failures are
mapped through the same `Error::api_error()` status/message projection as the
image boundary. `tests/engine_resources_networks_volumes.rs` and the JSON files
under `../fixtures/docker/engine/networks/` and
`../fixtures/docker/engine/volumes/` cover request paths, deterministic
filter encoding, payload/response mapping, and daemon errors.

## Swarm and task slice

`DockerClient` owns repository-owned Swarm operations for initialization,
join/leave/unlock, inspection, metadata updates, service create/list/inspect/
update/rollback/remove, node list/inspect/update/remove, config and secret
CRUD, and task list/inspect. Service and task log methods return the same
caller-owned `DockerStream<ContainerLogFrame>` used by container logs. Filters
are `BTreeMap` values and are encoded in stable key order, so request fixtures
do not depend on Bollard's unordered filter maps.

Swarm, service, node, config, secret, and task operations use the owned
transport and repository models. Flexible specification members use ordered JSON;
unavailable targets fail closed. Sensitive operations withhold peer failure
text while preserving status where documented. The captured local endpoint is
used for local clients.

> **Historical migration notes:** The detailed comparisons below record the
> former generated-client behavior. References to a generated fallback describe
> the old implementation only; no operation currently uses that fallback.

`inspect_swarm`, the `swarm_join_token` method built on it, and `leave_swarm`
use the owned transport and fail when no owned target is available. The request is `GET /v<owned>/swarm`, where `<owned>` is
the API version configured for the client: v1.55 by default, and either an
explicit constructor version or negotiation can lower it. The former generated
fallback used the unversioned `GET /swarm`. Both returned `SwarmInfo` and
redacted join tokens from `Debug`; the historical differences were:

- The owned path decodes the daemon's document directly, so an unmodelled
  member survives in `SwarmInfo::additional` (or `SwarmSpec::additional`
  inside `Spec`). Bollard's generated 1.53 models have no catch-all, so the
  former fallback discarded those members before the facade converts the value.
- A malformed or wrongly typed success body is `ErrorKind::InvalidInput`; the
  former generated fallback reported `ErrorKind::Docker`.
- A daemon rejection keeps its status and direct message in `Error::api_error()`.
  An authenticated forward proxy's message is replaced by a fixed withholding
  diagnostic.

A failed owned request is returned, not retried through the generated client.
The former fallback was selected before dispatch; it no longer exists. On a
daemon older than the owned version, the versioned request can be rejected as
too new where the unversioned generated request would have been accepted; that
rejection is returned rather than retried over the fallback. A caller targeting
such a daemon can build the client with a version the daemon serves, for
example through `DockerClient::connect_endpoint_with_version`, or upgrade the
daemon.

`list_configs` uses the owned versioned `GET /v<owned>/configs` request. It
encodes ordered filters deterministically, preserves unmodelled members and
refuses malformed documents. A daemon rejection is returned without retry.
The former generated route and its unversioned request are historical only.

Release treatment: no public type or signature changes, but this is a behavior
change for reachable endpoints: the request is versioned, unmodelled members
are retained, and a malformed answer is `ErrorKind::InvalidInput`. The alpha
release notes should call this out for callers that relied on the unversioned
generated request or on Bollard's decode error class.

`inspect_config` uses the owned request `GET /v<owned>/configs/{id}` with
the reference encoded as one path segment. An empty reference is refused before
dispatch; malformed success bodies are `ErrorKind::InvalidInput`. A daemon
rejection retains its status and direct message; authenticated proxy text is
withheld. Unmodelled members survive in the corresponding `additional` maps.

An inspect answer includes the config's `Data` member, which a list answer
normally omits, so the returned value can contain sensitive bytes. The owned path does
not log request or response bodies, and its decode failure is content-free: a
category and position, never document text. The former generated decoder
could log response content; that route no longer exists.

A failed owned request is returned rather than retried through the generated
client: the former fallback was selected before dispatch; it no longer exists.

The versioned request can be rejected by a daemon older than `<owned>` where the
unversioned fallback would have been accepted; the rejection is returned, not
retried over the fallback. Build the client with a version the daemon serves,
or upgrade the daemon.

Release treatment: no public type or signature changes, but this is a behavior
change for reachable endpoints: the request is versioned, unmodelled members
are retained, an empty reference is refused locally, and a malformed answer is
`ErrorKind::InvalidInput`. The alpha release notes should call this out for
callers that relied on the unversioned generated request, on its permissive
empty reference, or on Bollard's decode error class.

### Secret reads

`list_secrets` and `inspect_secret` use the repository-owned transport only.
They have **no generated fallback**. Bollard logs the whole decoded response
body at `DEBUG` before it parses the model, and this crate cannot make that log
line safe, so a secret read must never reach it. The owned requests are
`GET /v<owned>/secrets` and `GET /v<owned>/secrets/{id}`, with the reference
percent-encoded as one path segment and an empty reference refused before
dispatch.

`connect_local` reads `DOCKER_HOST` once and captures the local socket or named
pipe as the owned target. Secret reads and all other facade operations use that
target. An unavailable target fails before dispatch, with no retry.

A non-success Engine answer preserves its status in `Error::api_error()` but
withholds the response text with a fixed diagnostic, on every route, direct or
proxied, authenticated or not. A daemon or a proxy can echo secret bytes in the
message, so every secret-read API failure uses the same fixed text. The
withholding lives in `raw::secret_list` and `raw::secret_inspect`, not only in
the facade: a direct raw caller gets the same status-preserving fixed diagnostic.
That is a behavior change for the raw API. A malformed success document is
`ErrorKind::InvalidInput`, and its owned decode diagnostic is content-free (a
category and position, never document text). Transport and cancellation failures
are not API failures and keep their kind and text.

A secret read on the captured local target uses a per-operation 120-second
overall request budget covering connect through the response head; the body is
unbounded. The shared `connect_local` client's `raw_response_head_deadline` stays
unset, so the service-update assembly's local inspect/update behavior is
unchanged. A stalled local peer therefore times out instead of becoming an
unbounded wait, and the timeout error carries no partial head or body. Tests
build a real `connect_local` Unix client for both the facade and the raw
operation, assert the shared response-head field is unset and the production
secret budget is 120 seconds, then inject a one-second budget and a stalled Unix
peer. The peer asserts the exact request line and that the partial head was
written before the test waits for the timeout; it accepts only EOF or a
connection reset as the close. The start instant is captured inside the client
task immediately before the public call, so scheduler delay before the task runs
is not counted. The tests assert the typed transport deadline marker
(`Error::is_transport_deadline`) and its fixed diagnostic
(`timed out after 1s waiting for the Engine request to complete`); a separate
test feeds that marker through a `StreamFactory` into a node mutation and pins
the observed/outcome-unknown wording plus redaction. The 0.9–3 s
elapsed range measured from that request start is an approximate wall-clock
sanity band, not a controlled timer-start proof: scheduler delay after the
timestamp and the exact point the transport arms its deadline mean the band
permits some early or late firing, and it does not by itself reject every
early/late deadline. The exact marker is the discriminator, and the separate
fixture that closes without a head proves the positive predicate rejects that
different transport failure. A mutation test removes the deadline, starts the
client, waits separately for the peer's staged-head signal, then asserts the
client remains pending for 300 ms before aborting and reaping it under a
two-second bound; the join must report a cancellation, not a value, error, or
panic. Abort is best-effort, not an absolute kernel guarantee.
This is an injected budget, not a production real-time measurement.

**Limits of this evidence.** The elapsed band is approximate, not a controlled
timer-start proof. The no-deadline control aborts and reaps the client task under
a two-second bound and requires a cancelled join, not a value, error, or panic;
abort is best-effort, not an absolute kernel guarantee. The
deadline tests stage a stalled response head
after connect; a stalled connect is not staged, because doing so needs network
shaping or a privileged fixture. Windows named-pipe capture is compiled but not
exercised by these Linux tests. The response body is outside the overall budget
by construction; a stalled-body case is not claimed. The parent's kill and reap
is best-effort supervision after its budget, not an absolute kernel guarantee.

### Secret filters

`SecretListOptions::filters` is the same ordered `BTreeMap` the other Swarm
lists use. The whole map is sent as Docker's JSON `filters` query value in key
order, the values under one key keep the caller's order, and an empty map is not
sent at all. The Engine documents `id`, `label`, `name` (prefix match), and
`names` (exact match) for `GET /secrets`; this facade forwards the caller's map
without validating a name. **A daemon may reject an unknown filter name rather
than treat it as no match**, so a typo can be a diagnostic from the daemon. The
loopback fixture is synthetic: it proves the exact encoding of the caller's map,
not that a particular daemon accepts a particular name.

### Config `Data` versus secret `Data`

They are not the same contract, and the difference is deliberate.

- A **config** inspect answer includes `Spec.Data`, and a list answer omits it.
  `SwarmConfigSpec::data` is a typed, inspect-only member: the read returns it,
  and `SwarmConfigSpec`'s derived `Debug` still prints it. The value is the
  caller's to protect.
- A **secret** answer never includes `Spec.Data`; the Engine declares it for
  creation only. `SwarmSecretSpec` therefore has no `data` member. If a peer
  sends one anyway — a daemon bug, a substituted response, or a proxy — it is
  **not** typed and **not** dropped: it is retained in
  `SwarmSecretSpec::additional` at the `Spec` object level as the JSON value the
  peer sent.

**Retention is object-level, not a general lossless claim.** The owned decoder
keeps an unmodelled member of the `SwarmSecret` object and of its `Spec` object.
It does not keep a member of a typed sub-object: `Version` is a typed
`SwarmVersion` with no catch-all, so one there is dropped. It cannot represent
duplicate JSON keys either: a duplicate known key (`ID`, `Name`, `Labels`,
`Driver`, `Spec`, ...) is a decode error, and a duplicate unmodelled key (for
example two `Spec.Data` members) collapses to one value rather than retaining
both. Because there is no generated secret-read route, there is no second set of
`Data` shapes to reconcile: `null`, a number, an object, an array, and a string
are all retained as the JSON value they are.

`SwarmSecret` and `SwarmSecretSpec` have hand-written `Debug` impls. They report
identity lengths and counts, never a name, label, driver document, catch-all
value, or an unexpected `Data`. `SecretUpdateOptions` inherits the
specification's impl.

`Serialize` is **not** redacted. `serde_json::to_string(&secret)` carries the
peer's document, and so do `ndocker secret inspect` and `--format json secret
ls` — **both list and inspect JSON output are secret-bearing** when a peer sends
an unexpected `Data`. That is the explicit-output contract; treat that output as
secret material and do not pipe it into a log. The text `ndocker secret ls`
table prints only the short id, name, driver, and timestamps, so it does not
print `Spec.Data`; it is **not** a blanket guarantee, because those are peer
values too and a peer can put secret bytes in the id, name, driver, or
timestamps it already prints.

The write path refuses a reserved member in `additional` before dispatch, in
**both** `update_secret` and `raw::secret_update`. `Data` is the security case: a
secret update cannot change data, so forwarding it would send secret bytes on a
request that cannot use them. `Name`, `Labels`, and `Driver` are refused because
the typed field owns that key and a second spelling is either a duplicate or an
untracked projection. **ASCII keys are compared case-insensitively**, because
the Engine's Go decoder matches JSON field names without regard to case while
this crate's serde models do not: `data`, `DATA`, or `nAmE` would bypass an
exact-key guard on the client but not the daemon. A **non-ASCII key is refused
conservatively**: Go's folding is Unicode, so `Labelſ` can reach `Labels`, and
this crate has no dependency-free full fold table. The guard refuses the whole
non-ASCII class rather than claim it can enumerate every spelling; that is a
bound it can enforce, not a false complete guarantee. A JSON key that is escaped
in the document (`D\u0061ta`, `Label\u017f`) is decoded before the guard sees it
and is refused the same way. The refusals are fixed, content-free
`ErrorKind::InvalidInput`
messages that name the reserved set, not the value. The guard is structural: it
does not scan a free-form name, label, or driver and makes no claim to detect
secret material. A specification the generated model cannot convert is replaced
with a fixed `ErrorKind::Serialization` diagnostic, so serde cannot quote a
peer-supplied driver or value in `Display`, `Debug`, or the source chain.

The owned transport logs no request or response body. The former generated
secret-read route was removed because it logged decoded bodies. The logging
suite captures `TRACE` output and verifies that canaries from owned task-list,
secret-inspect, and secret-list responses do not appear in it.

Release treatment: **this is a significant compatibility change**, not a
documentation fix. A `connect_local` client now reads `DOCKER_HOST` once and
uses the captured socket for secret reads, so those requests are versioned and
owned where they used to be unversioned and generated. An endpoint with no owned
target now fails closed for secret reads and sends nothing. Every secret-read
API failure, including one from `raw::secret_list`/`raw::secret_inspect`, loses
the daemon's or proxy's text, retaining only the status and a fixed diagnostic.
The update guards are ASCII case-insensitive, refuse non-ASCII keys
conservatively, and cover both writers. A secret read on the captured local
target uses a per-operation 120-second overall request budget covering connect
through the head, without changing the shared local client. Callers that relied
on the generated fallback,
on preserved daemon error text from either the facade or raw, or on a
case-variant or non-ASCII `additional` key must migrate. The alpha release notes
must call this out explicitly.

`inspect_service` follows the same routing rule and the same
no-retry-over-the-fallback rule. The owned request is
`GET /v<owned>/services/{id}`; the former generated fallback was the unversioned
`GET /services/{id}`. The configured-version risk above applies the same way: a
daemon older than `<owned>` can refuse the versioned request as too new, and
that rejection is returned rather than retried.

The owned route projects `Endpoint.Ports` into `SwarmService::ports`. The owned path decodes the daemon's document
directly, so it additionally keeps the whole `Endpoint` in
`SwarmService::additional` — including a port's `Name` and the `VirtualIPs` —
along with `PreviousSpec`, `UpdateStatus`, every unmodelled service and
specification member, and `Spec.TaskTemplate` exactly as the daemon spelled it.
The former generated fallback discarded `Endpoint`, `PreviousSpec` and
unmodelled members. The owned route retains them in the daemon document and
retains port `PublishedIP` in `additional["Endpoint"]`.
Raw inspect and list retain their original decoding contract: they accept
arbitrary protocol and publish-mode strings, ignore unprojected endpoint fields,
and reject a present port list or status that cannot decode into the repository
types. Facade inspect validates the endpoint shape and handles
nullable and partial projections as described below.

The projections read members the Engine declares as optional. The wire shapes are
modelled before projection, so the rule is about the *document*, not about the
projection: `Endpoint` and `ServiceStatus` may be absent or an explicit `null`;
`Endpoint.Ports` may be `null` or an empty list; a status may carry one of its
two counts. The first two yield *no projection*, `Ports: []` yields a projection
of zero ports — a different answer from no projection — and a partial status
yields no status rather than zero counts, because a daemon that answered with one
count did not answer with zero for the other. The endpoint stays in `additional`
either way, so the raw member is still readable.

A member of the wrong JSON type, or a value outside the enumeration the Engine
declares, is **rejected on the owned route** — a string `Endpoint`, a string `Ports`,
a numeric `ServiceStatus`, a task count that is not a number, a port protocol
outside `tcp`/`udp`/`sctp`, a negative count. A value the repository model
cannot hold — a port above `u32::MAX` — omits the whole port projection.

`Placement` and `RestartPolicy` are members of `Spec.TaskTemplate`, not of
`Spec`. The owned route reports `ServiceSpec::placement` and
`ServiceSpec::restart_policy` as `None` for a document a real daemon sends; the
values are read verbatim from `ServiceSpec::task_template`. A malformed or
wrongly typed success body is `ErrorKind::InvalidInput`. A daemon rejection
retains its status and direct message in `Error::api_error()`; an authenticated
proxy's message is withheld. There is no generated fallback.

`ServiceSpec::placement` and `ServiceSpec::restart_policy` are the repository
model's top-level spelling of members the Engine reads inside `Spec.TaskTemplate`.
Both `create_service` and `update_service` move a populated typed field into
`TaskTemplate` and refuse a competing representation, so a constraint is either
sent where the Engine reads it or the call fails before dispatch. **Every dotted
key in `ServiceSpec::additional` is refused** by both facade writes, because a
`ServiceSpec` has no provenance: an inspected literal such as
`Placement.Platforms` cannot be distinguished from the raw retention
convention, and merging it could rewrite the literal. The refusal is
`ErrorKind::InvalidInput`, describes the rejected class without echoing
untrusted keys, and distinguishes a documented retention key from an arbitrary
literal dotted key. It is raised before a request is written. The explicit raw
writers keep the split-once convention and remain the escape hatch for a caller
that intended it.

`ServiceSpec::task_template` is sent verbatim by both facade writes. The owned
writers send the typed fields, merge their explicit split-once keys into the
named sub-object, and otherwise pass the caller's document through, including a
member no typed field names. The Engine's task environment and secret
references are therefore part of the body rather than something this crate
reconstructs. A top-level `Placement` or `RestartPolicy` in `additional` is
refused by `DockerClient::create_service`, `DockerClient::update_service`, and
the raw writers even with no typed competitor; a literal root member of either
name has no lossless write, because `task_template` changes its location and
meaning and raw refuses the root spelling. The explicit raw writer can carry an
intentionally chosen first-dot convention for any parent, but it splits at the
first dot and does not preserve a literal top-level key. An arbitrary literal
top-level dotted key has no lossless facade write; using raw would change its
meaning.

This is a **behavior change, not a documentation fix**. A service create used to
go through Bollard's 1.53 `ServiceSpec`: the typed placement and restart policy,
and every dotted key, were refused because the conversion would silently drop
them, and a task-template member Bollard's `TaskSpec` did not name was dropped
without an error. The owned create now carries all of those, refuses the dotted
ambiguity, and sends the task template unchanged. A program that relied on the
silent drop now gets either the value it asked for or a fixed refusal. There is
no release-notes file in this crate, so this paragraph is the pending note until
one exists.

#### Case-folded and non-ASCII member names

The Engine decodes JSON member names case-insensitively, and Go's fold is
Unicode-aware. `Placement` and `placement` are therefore one member to the
daemon, as are `Labels` and `labels`; a key such as `Labelſ` can fold onto
`Labels`. When both spellings are present, which one applies depends on the
encoded order, and the crate cannot let the daemon make that choice. The facade
and `raw::service_create`/`raw::service_update` share one validation pass and
refuse the specification before dispatch:

- Two keys on any recursively modeled struct or array entry that differ only by
  ASCII case are refused, including members under `ContainerSpec`, mounts,
  resources, placement preferences, network attachments, and endpoint ports.
- Non-ASCII keys on modeled struct surfaces are refused. The guard does not
  reproduce Go's version-specific Unicode `SimpleFold` table. Keys inside known
  string-to-string maps (`Labels`, `Sysctls`, driver `Options`, and
  `DriverOpts`) remain arbitrary, including Unicode and case-distinct keys.
- An `additional` key that is a case variant of a modeled root member, or a
  dotted parent/member that is a case variant of a modeled nested member, is
  refused even when the exact spelling is absent. A lone `placement` would
  otherwise be written as an unknown root member the Engine ignores, which is a
  silent loss rather than the request the caller asked for.

The restrictions are exact rather than a blanket sanitization. Non-ASCII map
keys are retained at the declared map boundaries. Unknown scalar extension
members remain forward-compatible, but unknown objects and arrays are refused:
the validator cannot safely decide whether their keys are struct members or
user-defined map keys. Null values retain Go's ordinary decoder behavior. The refusal is
`ErrorKind::InvalidInput`, carries fixed text with no key or value, and happens
before a connection is opened.

This is a security boundary, not a formatting preference: without it, an
`additional` or `task_template` spelling could silently replace a placement
constraint, a restart policy, or a label map. The tests are
`tests/service_case_collisions.rs` (facade, zero dispatch), and the raw unit
tests `a_service_spec_case_collision_is_refused_before_a_request`,
`a_non_ascii_service_spec_key_is_refused_before_a_request`,
`a_case_fold_inside_a_modeled_object_is_refused_after_the_merge`, and
`legitimate_unknowns_and_non_ascii_map_keys_still_build`.
The schema is a manually researched snapshot of Moby Engine 1.55, not a
guarantee for future daemon versions. Its complete transitive inventory,
including maps, arrays, byte slices and `netip.Addr`, is in
[`docs/moby-service-schema-1.55.md`](docs/moby-service-schema-1.55.md).

**Service create uses the owned transport only.** `create_service` sends
`POST /v<owned>/services/create`; `create_service_with_credentials` sends the
same request with the Engine's URL-safe `X-Registry-Auth` `AuthConfig` object.
There is no generated fallback, for the reason the update has none and one more:
the create body carries `TaskTemplate.ContainerSpec.Env` and
`TaskTemplate.ContainerSpec.Secrets`, and Bollard traces a buffered request body
before sending it. An endpoint the owned transport cannot reach fails closed
before dispatch with a fixed `ErrorKind::InvalidInput`; an explicitly closed
managed SSH target returns its stable local gate diagnostic first. `connect_local` supplies its
captured local socket, so the ordinary local client dispatches the owned
request rather than entering the refusal. The create body is not reconstructed
through a generated model: the task template, including environment and secret
references, is the caller's document, and the typed placement and restart
policy are merged into it.

Every create failure is content-free. A transport failure keeps its kind and
drops its peer-controlled source chain; a daemon or proxy rejection keeps its
HTTP status in `Error::api_error()` and replaces the message with
`response text withheld for a service create because the request may carry
service environment, service secrets, or registry credentials`; the response
body is not read. A malformed success body is a content-free
`ErrorKind::InvalidInput`. A cancelled dispatch has an unknown outcome — the
daemon may have created the service — and this crate does not retry it.

`remove_service` uses `DELETE /v<owned>/services/{id}` with the reference
encoded as one path segment. An empty reference is refused before connecting;
proxy credentials and sensitive peer failures are withheld. No generated
fallback or retry exists.

`service_logs` uses the owned transport. The owned request is `GET /v<owned>/services/{id}/logs` with
`follow`, `stdout`, `stderr`, `since`, `until`, `timestamps`, and `tail`.
`details` is omitted on the owned route: the Engine's default is `false`, and this
facade has no option that asks for the wider answer. A
non-success status is observed before any frame, so a `404` is an error item
carrying the daemon's status and, on a direct or unauthenticated route, its
message, rather than a body that happened to look like framing. On an owned
authenticated forward-proxy route the transport replaces the peer text with
fixed withholding text, because the proxy can echo the configured credential.
Frames are decoded by the same `raw::SwarmLogFrames` the
owned task log stream uses: Docker's eight-byte multiplexed headers stay
internal, each poll yields at most one frame, a truncated frame or a declared
payload over `raw::MAX_FRAME_BYTES` is an error item, and the payload is not
buffered. A service task has no TTY option, so there is no unframed body to
classify as `Console`. Cancellation is ownership: dropping the handle or calling
`cancel()` releases the response body and closes the socket, which is also how
a `follow` stream ends; the handle is lazy and opens no connection until it is
first polled.

`task_logs` uses the owned transport, including the local socket captured at
construction, with no generated fallback: generated failures can expose task
output or proxy credentials. An endpoint without an owned target fails closed.
The versioned `GET /v1.NN/tasks/{id}/logs` sends the generated route's `follow`,
`stdout`, `stderr`, `since`, `until`, `timestamps` and `tail` parameters.
It sends no query when the caller passes `None`; `Some(default())` explicitly
sends all seven.
Neither route sends `details=true`. Status
is observed before frames, including rejection of 101 and 304, and peer
failure text is withheld on both direct and proxied routes while preserving
status. The shared frame decoder reports malformed, oversized and truncated
frames as error items. The lazy handle owns the response; cancel or drop closes
it without retry. The public raw task-log operation now also sends the three
stream-selection parameters; it previously omitted them.

| Operation | Owned request | Failure text |
| --- | --- | --- |
| `create_service` | `POST /v1.NN/services/create` | status preserved; sensitive peer text withheld |
| `create_service_with_credentials` | create plus `X-Registry-Auth` | status preserved; credential withheld |
| `remove_service` | `DELETE /v1.NN/services/{id}` | direct message preserved; authenticated proxy text withheld |
| `service_logs` | `GET /v1.NN/services/{id}/logs?...` | status before frames; authenticated proxy text withheld |

All four use the owned transport, including the captured local socket. An
unavailable target fails before dispatch and no generated fallback is attempted.

**Service update uses the owned transport only.** `update_service` sends
`POST /v<owned>/services/{id}/update?version=<n>&registryAuthFrom=spec`, with
`&rollback=previous` appended when a rollback was requested. There is no
generated fallback. An endpoint the owned transport cannot reach fails closed
before dispatch with a fixed `ErrorKind::InvalidInput`: Bollard 0.21.1 traces a
buffered request body before sending it, so a generated update would write the
service environment to a TRACE log, and its failure path preserves peer text
that can echo the same body or the registry header. The facade cannot remove
either behavior. The fail-closed message names the two reasons and does not
quote the endpoint, which can contain a host or path. An explicitly closed
managed SSH target returns its stable local gate diagnostic before dispatch, just as
`unlock_swarm` does. `connect_local` captures the local endpoint once and
captures it as the owned target — `DOCKER_HOST` only when it is `unix://`,
otherwise the platform default — so a later environment value cannot move
either half and a local client dispatches a successful owned update instead of
entering the refusal.

The owned body is the [`ServiceSpec`] itself rather than Bollard's 1.53 model:

- `Spec.TaskTemplate` is the caller's document. A nested member no typed field
  names is sent rather than dropped, and the task environment is part of it.
- A populated `ServiceSpec::placement` or `::restart_policy` is moved into
  `TaskTemplate` as the Engine reads it. The typed fields are never emitted at
  the specification root.
- The facade **refuses every dotted `additional` key** before dispatch. A
  `ServiceSpec` has no provenance, so an inspected literal such as
  `Placement.Platforms` cannot be distinguished from the raw retention
  convention; merging it could rewrite the literal. A typed placement or restart
  policy can be expressed under `task_template`. The explicit raw writer can
  carry an intentionally chosen first-dot convention for any parent, but it
  splits at the first dot and does not preserve a literal top-level key. An
  arbitrary literal key containing a dot has no lossless facade write; using raw
  would change its meaning.
- The raw writers keep the explicit split-once convention for any parent, so
  `Labels.team`, `Labels.com.example.team`, and `Mode.Replicated` still merge
  into their objects; only the first dot splits and the remainder is a literal
  member name. This raw convention is not available through the facade. A
  non-dotted member passes through, except a top-level `Placement` or
  `RestartPolicy`, which is refused even with no typed competitor; a literal
  member with a dot in its name is refused by the facade.
- A non-dotted `additional` entry is resolved first. An `additional` whole
  `TaskTemplate` is allowed only when the typed `task_template` is absent; both
  together are refused rather than silently replacing one. The raw writer then
  merges typed placement, restart policy, and its explicit dotted members into
  the resolved template; the facade refuses every dotted key before this point.
  The previous one-pass merge could let the ordered `TaskTemplate` entry discard
  a `TaskTemplate.*` member that had already been merged.
- Conflicting representations are refused before dispatch with a fixed,
  content-free, actionable `ErrorKind::InvalidInput`: a typed placement or
  restart policy beside a `TaskTemplate` member of the same name, any top-level
  `Placement`/`RestartPolicy` additional entry (the Engine ignores that
  spelling), with or without a typed competitor, a typed field beside a dotted
  key for a member the typed field emits, a `TaskTemplate` that is not a JSON
  object, or a dotted key that would replace a member already present in the
  resolved object. Whole-object
  dotted members are ordered before their descendants, so
  `TaskTemplate.Placement` cannot overwrite a `Placement.Platforms` merged into
  it; if the whole object already carries that member, the merge is refused
  rather than replaced. A dotted key for a member the typed field does not emit
  — the Engine's object-form `Placement.Preferences` or `Placement.Platforms` —
  still merges when the leaf is absent, which is what makes an inspect round
  trip work.

The same writer backs `raw::service_create`, so the ordering fix and the
conflict refusals apply there too: an `additional` `TaskTemplate` is now
resolved before typed/dotted members merge into it, a typed template and an
additional whole template together are refused, a non-object template is
refused, and competing or duplicate placement/restart-policy spellings are
refused instead of letting one representation silently win. A caller that
relied on an additional `TaskTemplate` overriding a typed one, or on a dotted
key replacing an already-supplied member, now gets a fixed refusal.

Every update failure is content-free because the request can carry
`TaskTemplate.ContainerSpec.Env` or a registry password. A transport failure
keeps its kind and drops its peer-controlled source chain. A daemon or proxy
rejection keeps its HTTP status in `Error::api_error()` and uses the fixed
message `response text withheld for a service update because the request may
carry service environment or registry credentials`; the response body is not
read. That applies to a direct route, an unauthenticated proxy, and an
authenticated proxy. A malformed success body is a content-free
`ErrorKind::InvalidInput`, never a success with invented warnings.

`update_service` sends no `X-Registry-Auth` header. The additive
`update_service_with_credentials` is the credential-bearing form: it validates
the credential against the named registry before dispatch and sends the Engine's
URL-safe `AuthConfig` object. A credential is not rendered by any `Debug`
implementation, and the failure rules above apply unchanged.

A cancelled update is an unknown outcome. Dropping the future after dispatch
closes the connection without retracting the request, and the daemon may have
applied it, may still be applying it, or may never have received it. The facade
does not retry, and the next call is a new mutation against the same expected
version, which a settled update would report as a conflict. Reading the service
again is how a caller reconciles the uncertainty before sending another write.

Release treatment: **not simply additive.** `update_service` keeps its signature
and result type, but on a reachable endpoint the request is versioned, the body
is the specification rather than Bollard's model, typed placement and restart
policy are carried instead of refused, unmodelled scalar members survive,
unclassified structured members are refused, the top-level
`Placement`/`RestartPolicy` spellings are refused, unknown dotted literals are
refused, and a malformed success body is
`ErrorKind::InvalidInput`. On an endpoint the owned
transport cannot reach, the generated fallback is **removed**: the call fails
closed instead of sending a body Bollard would trace and an error it would echo.
`update_service_with_credentials` is a new method rather than a new field on
`ServiceUpdateOptions`, so existing struct literals keep compiling. `create_service`
keeps its signature and result type too, and makes the same move from the
generated model to the repository specification; `create_service_with_credentials`
is new for the same reason `update_service_with_credentials` is. `remove_service`
and `service_logs` keep their signatures and use owned routes only, but a
reachable endpoint now gets the versioned owned request. A removal's reference
is percent-encoded into one path segment, an empty one is refused before
connecting, and an observed `304` is no longer accepted as success. Owned log
frames are decoded by the shared reader, so a truncated frame, a bad header, or
an oversized frame is an error item rather than a body Bollard classified as
`ErrorKind::Docker`; the log query omits `details`, whose Engine default is
`false`. Both service writes now refuse a specification with two case spellings
of a modeled member, or a non-ASCII key on a modeled merge surface, before
dispatch. This crate
has no release-notes file; this paragraph is the pending note until one exists.
Callers that relied on the generated body's omissions, on the unversioned
request, on daemon failure text, or on a local-endpoint fallback should audit
the deployment before upgrading.

| Difference | Before | Now |
| --- | --- | --- |
| Reachable inspect request line | unversioned `GET /services/{id}` | versioned `/v1.NN/services/{id}` |
| `Endpoint`, `PreviousSpec`, unmodelled inspect members | discarded by the 1.53 models | retained, with the endpoint kept whole |
| `Spec.TaskTemplate` from an inspect | rebuilt from Bollard's `TaskSpec` | the daemon's own JSON |
| Reachable update request line | unversioned `POST /services/{id}/update` | versioned `/v1.NN/services/{id}/update?version=...&registryAuthFrom=spec` |
| Reachable create request line | unversioned `POST /services/create` | versioned `/v1.NN/services/create` |
| Reachable create body | Bollard's 1.53 `ServiceSpec`; typed placement/restart policy refused; unmodelled members dropped | the repository specification; typed placement/restart policy merged; task environment and secret references retained; unclassified structured members refused |
| A case variant or non-ASCII key on a modeled merge surface | written as a second JSON key; the daemon's case fold decided which one applied | refused before dispatch with fixed text; no request |
| A create on an endpoint with no concrete owned target | generated fallback traced the body and preserved peer text | fails closed before dispatch; no request and no trace of the body. `connect_local` supplies its concrete local socket and dispatches |
| Create failure text | daemon or proxy words, through the generated transport | status preserved when observable; fixed withholding text on every route |
| A registry credential on create | no facade input; the generated call passed none | `create_service_with_credentials` sends one on the owned route |
| Reachable removal request line | unversioned `DELETE /services/{id}` | versioned, percent-encoded `DELETE /v1.NN/services/{id}` |
| Reachable service log request line | unversioned `GET /services/{id}/logs?...`, no `details` | versioned `GET /v1.NN/services/{id}/logs?...` |
| A removal on an endpoint with no concrete owned target | generated fallback | fails closed before dispatch |
| Service log frames on the owned path | Bollard decoded the response and reported a malformed body as `ErrorKind::Docker` | the shared owned decoder yields error items for truncation, a bad header, or an oversized frame |
| Reachable update body | Bollard's 1.53 `ServiceSpec`; unmodelled members dropped | the repository specification; typed placement/restart policy merged; unknown scalar members retained; unclassified structured members and unknown dotted literals refused |
| An update on an endpoint with no concrete owned target | generated fallback sent the body and preserved peer text | fails closed before dispatch; no request and no trace of the body. `connect_local` supplies its concrete local socket and dispatches |
| Update failure text | daemon or proxy words, through either transport | status preserved when observable; fixed withholding text on every route |
| `ServiceSpec::placement`, `::restart_policy`, or a dotted key for either | silently dropped by the generated update | typed fields carried by the owned update; every dotted key refused by the facade before dispatch |
| A task-template value Bollard cannot decode | the generated update failed | recognized Moby 1.55 structures are retained; unclassified object/array values are refused before dispatch |
| An older daemon | the unversioned request was accepted | the versioned request can be refused as too new; returned, not retried |
| A malformed inspect success body | `ErrorKind::Docker` | `ErrorKind::InvalidInput` |
| A malformed update success body | `ErrorKind::Docker` | content-free `ErrorKind::InvalidInput`; no false success |
| A registry credential | no facade input; the generated call passed none | `update_service_with_credentials` sends one on the owned route |
| An authenticated or unauthenticated proxy rejection | the proxy's words | fixed withholding text; status preserved |
| A reserved `Name`, `Labels`, `Role`, or `Availability` key in `NodeSpec::additional`, under any ASCII case spelling, or any non-ASCII additional key | carried into the body, potentially reaching a modeled member through Go Unicode case folding | refused with a fixed `ErrorKind::InvalidInput` before dispatch on the owned route, even when the typed field is `None`. This conservative rule also rejects unrelated non-ASCII extension keys. |
| A daemon, proxy, or transport failure on a node write | the peer's message or source chain | any node update/removal failure keeps its status (or kind) and replaces the message and every source with fixed withholding or deadline text |

`SwarmService`, `ServiceSpec`, `ServicePlacement`, and `ServiceRestartPolicy`
also gained hand-written `Debug` impls. The owned route retains the daemon's
document whole, which means `{:?}` would otherwise print `PreviousSpec` — the
previous revision's `ContainerSpec.Env` — and any unmodelled member at any
depth. The typed members are not uniformly safe either: a label is a free-form
key/value pair, and a placement constraint or a restart action is a free-form
string an operator writes. All four now report identity and shape — the size of
each JSON-valued member, the count of labels, constraints, and preferences, the
numbers of a restart policy, and a count of unmodelled members — and none of them
renders the values. `Serialize` is untouched: `ndocker service inspect --json`,
and any caller that serializes deliberately, sees the selected route's retained
document, including `PreviousSpec` on the owned route. The
redaction is only what `{:?}` puts into a panic message or a log line.

| `{:?}` exposure | Before | Now |
| --- | --- | --- |
| Task environment and retained unmodelled members | rendered in full by the derived impl; generated inspect discarded `PreviousSpec` | the JSON members are sized and the catch-alls counted, including retained `PreviousSpec` on the owned route |
| Labels | rendered as keys and values | the entry count |
| Placement constraints and preferences | rendered as strings | the value counts and `max_replicas` |
| Restart policy `Condition` and `FailureAction` | rendered as strings | the byte sizes and the numeric members |
| `serde_json::to_string` / `--json` | the generated route's retained document | the selected route's retained document; serialization is not redacted |

`list_services` follows the same routing rule and the same
no-retry-over-the-fallback rule. The owned request is
`GET /v<owned>/services?status=true`, with `filters=<json>` before it when the
caller supplied a non-empty filter map; the former generated fallback sent the same
query on the unversioned `GET /services`. `<owned>` is the configured API
version, so the older-daemon caveat above applies unchanged: a versioned request
can be refused as too new, and that rejection is returned rather than retried
unversioned.

**`status=true` is part of the contract, and it is facade-only.** Without it the
daemon answers with `ServiceStatus: null` for every service, so `REPLICAS` in
`ndocker service ls` has nothing to print and the `0/1` of a service whose image
cannot be pulled is not derivable from its specification. The facade has always
sent it; this change keeps it on the owned request rather than losing it with the
generated path. `raw::service_list` deliberately does **not** send it: its
contract is the filters-only request it has always sent, and a caller that wants
task counts reads the facade or asks the daemon itself.

The facade's projection is the one `inspect_service` documents, because both
operations now share it: `Endpoint` and `ServiceStatus` may be absent or `null`,
`Ports` may be `null` or empty, a partial status is no status rather than
invented zero counts, a projection input of the wrong JSON type is refused, and
the whole `Endpoint` is retained in `additional`. The port projection omits
`PublishedIP` on the owned route, which is what the generated route always did. Raw
list keeps its own strict projection: a present `Ports` or `ServiceStatus` that
cannot decode is an error there, and an arbitrary protocol string is accepted,
which is why `raw::service_list` remains the lossless read for a document the
facade rejects.

| Difference | Before | Now |
| --- | --- | --- |
| Reachable request line | unversioned `GET /services?…&status=true` | versioned `/v1.NN/services?…&status=true` |
| `Endpoint`, `PreviousSpec`, unmodelled members | discarded by the 1.53 models | retained, with the endpoint kept whole |
| `Spec.TaskTemplate` | rebuilt from Bollard's `TaskSpec` | the daemon's own JSON |
| A malformed success body | `ErrorKind::Docker` | `ErrorKind::InvalidInput` |
| An old daemon | the unversioned request was accepted | the versioned request can be refused as too new; returned, not retried |
| An authenticated proxy rejection | the fallback's own message | fixed text naming the withholding; status preserved |
| `Endpoint` or `ServiceStatus` absent, `null`, empty, or partial | accepted; no projection | unchanged, with `Ports: []` distinct from no projection |
| A projection input of the wrong JSON type | rejected by the 1.53 models | rejected on the owned route |
| A document carrying a protocol string outside the enumeration | rejected by the 1.53 models | rejected by the facade on the owned route; `raw::service_list` still accepts it |
| `{:?}` on a returned `SwarmService` | rendered the generated route's subset | identity, counts, and sizes; retained values are withheld |
| `ndocker service ls --json` | the generated route's subset | the owned document, including `Endpoint` and `PreviousSpec` |

Release treatment: **not simply additive.** The public surface is unchanged —
`list_services`, its option and result types, and its error projection keep their
signatures — but behavior on a reachable endpoint differs: the request is
versioned, unmodelled members and `PreviousSpec` are retained, `Spec.TaskTemplate`
is the daemon's own JSON, a malformed answer is `ErrorKind::InvalidInput`, and
`ndocker service ls --format json` carries the extra members. `ndocker stack ls`,
`stack services`, and `stack ps` now read the same versioned route. The
`status=true` query and the filter encoding callers could already observe are
unchanged, and the former generated fallback was unchanged. The alpha release notes
should call this out for callers that relied on the unversioned generated
request, on its narrower JSON shape, or on Bollard's decode error class.

`list_nodes` and `inspect_node` follow the same routing rule and the same
no-retry-over-the-fallback rule, including the local endpoint `connect_local`
captured. The owned requests are
`GET /v<owned>/nodes` and `GET /v<owned>/nodes/{id}`. The former generated
fallback sent unversioned paths and pasted the reference in as given. The configured-version risk applies here too: a daemon
older than `<owned>` can refuse the versioned request as too new, and that
rejection is returned rather than retried over the fallback. Build the client
with a version the daemon serves, or upgrade the daemon.

A repeated JSON key at the node top level or in any object below `Spec`
(including inside arrays) is refused before projection with a fixed, content-free
`ErrorKind::Serialization` error. `serde_json` would otherwise keep the last
value, and an inspect followed by an update would write a value the daemon did
not send. A list containing one such node fails whole, with no retry.
`raw::node_list` and `raw::node_inspect` apply the same refusal; that is a
deliberate raw compatibility change from the original last-value collapse. The former generated fallback could not apply this check; it is no longer used.
The 16 MiB document bound and serde nesting limit apply; validation also
refuses documents containing more than 65,536 checked object members.

### Node filters

`NodeListOptions::filters` is the same ordered `BTreeMap` the other Swarm
lists use. The whole map is sent as Docker's JSON `filters` query value in key
order, the values under one key keep the caller's order, and an empty map is not
sent at all, so the owned route makes an unfiltered request. The Engine
documents `id`, `label`, `membership`, `name`, and `role` for `GET /nodes`. It
validates the filter names it implements, so an unknown name can be rejected
with a `400` before the list runs; that rejection is returned without a retry.
This facade forwards the caller's map without rewriting or dropping a name, so
acceptance and the diagnostic are the daemon's. Another Engine implementation
may validate differently; do not rely on a typo producing a shorter list.

### Node document retention

The owned path decodes the daemon's array or object directly instead of through
Bollard's 1.53 models. A top-level member this crate does not name is retained
in `SwarmNode::additional`, a member of `Spec` is retained in
`NodeSpec::additional`, and `Description` is retained whole in `additional`.
`SwarmNode::engine_version` is a view of
`Description.Engine.EngineVersion` on the owned route; the description itself is not
dropped by either. `Status` is JSON on the repository model, and
`ManagerStatus` has its own catch-all.

**Actual top-level `EngineVersion`:** the raw projection keeps that member in
`SwarmNode::additional` beside the typed view. Serializing such a raw value can
emit duplicate `EngineVersion` keys, and raw does not promise round-trip
stability for it. That is the raw backend's original behavior, deliberately
preserved; the facade does not try to repair it. On an endpoint the owned
transport reaches, `DockerClient::list_nodes` and `DockerClient::inspect_node`
refuse the document **before projection**, for any JSON type including `null`,
with a fixed content-free `ErrorKind::Serialization` error. A list containing
one such node fails whole; the error is not retried and is never sent through
the generated fallback. The availability tradeoff is explicit: such a node
cannot be read through the owned route. An unreachable endpoint fails; no
generated fallback exists. `raw::node_list` / `raw::node_inspect`
still return the raw `EngineVersion` value with its projection caveat. A caller
that mutates the public `SwarmNode` fields can recreate a duplicate on
serialization.

**Dotted manager-address views:** the raw projection adds
`ManagerStatus.Addr` and `ManagerStatus.Address` to `SwarmNode::additional` under
their dotted keys, while the nested `ManagerStatus` keeps them too. The views
are synthetic, not members the daemon sent at the top level. The projection
inserts each only when the document did not already carry a member with that
exact name, so an actual top-level member wins. This is a deliberate raw
compatibility change: the original projection overwrote the actual member. It is
observable only for a document carrying one of those two dotted names at the top
level.

The former generated fallback decoded into Bollard's 1.53 `Node` and `NodeSpec`
models and discarded members those models did not name. The owned decoder keeps
unmodelled members and accepts JSON `Status` and `Description` values;
`Spec.Role`, `Spec.Availability`, and `ManagerStatus.Reachability` are strings.

| Difference | Before | Now |
| --- | --- | --- |
| Reachable request line | unversioned `GET /nodes` or `/nodes/{id}` | versioned `/v1.NN/nodes` or `/v1.NN/nodes/{id}` |
| Unmodelled top-level and `Spec` members | discarded by the 1.53 models | retained on the owned route |
| `Description`, `Status`, `ManagerStatus` | Bollard names them; the facade keeps `Description` in `additional` | unchanged, with the owned route also adding the dotted manager address |
| Empty reference | sent as `GET /nodes/` | refused as `InvalidInput` before dispatch on the owned route |
| A malformed success body | `ErrorKind::Docker` | `ErrorKind::InvalidInput` |
| A repeated key at the node top level or in an object anywhere under `Spec` | serde kept the last value | refused with a fixed content-free `Serialization` error before projection; raw applies the same refusal |
| An older daemon | the unversioned request was accepted | the versioned request can be refused as too new; returned, not retried |
| An authenticated proxy rejection | the fallback's own message | fixed text naming the withholding; status preserved |
| A `Role` or `Availability` outside Bollard's 1.53 enums | the generated inspect rejected the document at read time | the owned read accepts the string and the owned write sends it back; there is no generated write route |
| A synthetic `ManagerStatus.Addr`/`ManagerStatus.Address` colliding with an actual top-level member | the synthetic view overwrote the actual member | the actual member is preserved; the view is added only when absent |
| An actual top-level `EngineVersion` member of any JSON type, including `null` | the raw typed view and the flattened map both claimed the key; serialization could emit it twice and `Value` conversion kept one | the owned route refuses the whole list or inspect before projection with a fixed content-free `Serialization` error, no retry, no fallback; the former generated read dropped the actual member and returned the nested view; raw keeps the `EngineVersion` projection caveat but refuses repeated keys |
| `{:?}` on a node, specification, or manager status | rendered labels, hostname, engine metadata, addresses, and unmodelled members | identity sizes, counts, and numbers; the values are withheld |

### Node writes

`update_node` and `remove_node` use the repository-owned transport only; there is
no generated fallback. The requests are
`POST /v<owned>/nodes/{id}/update?version=…` and
`DELETE /v<owned>/nodes/{id}?force=true|false`, with the reference
percent-encoded into exactly one segment and an empty reference refused before
dispatch. `connect_local` records the exact local socket Bollard selected, so a
local client keeps a working owned write. An endpoint with no concrete owned
target fails closed before dispatch with a fixed
`ErrorKind::InvalidInput` diagnostic; it names the disabled fallback and does
not quote the endpoint, which can contain a host or path.

The fallback is disabled rather than guarded because Bollard 0.21.1 traces a
buffered node request body at `TRACE` and may serialize the payload at `DEBUG`.
That body carries the node's name and labels, and the facade has no switch that
removes the logging. Bollard also treats `101 Switching Protocols` and `304 Not
Modified` as success without exposing the status, and it can preserve an error
body of unbounded size. The owned path rejects every status outside `200..=299`,
including `101` and `304`, preserving the observed status and dropping the body
unread.

`update_node` is the write half of `ndocker node update`, `promote`, and
`demote`. Its body is the repository `NodeSpec` member for member: `Name`,
`Labels`, `Role`, `Availability`, and every entry of `NodeSpec::additional`.
When that specification came from the owned `inspect_node` route — the only
route that retains every daemon member — an inspect → update round trip changes
only what the caller changed, including a newer daemon's unmodelled member and
a `Role` or `Availability` string outside Bollard's 1.53 enums. A fallback read
may already have dropped unmodelled members, and the write cannot restore them.
The daemon decides whether it accepts them; a rejection is returned, not retried.

`NodeSpec::additional` is flattened into the same JSON object as the modeled
members, so it may not carry `Name`, `Labels`, `Role`, or `Availability` under
any ASCII-case spelling. Go's JSON decoder matches field names
case-insensitively, so a second spelling could either emit a duplicate JSON key
or reach a modeled member while its typed field was `None`. The owned writer
refuses such a specification with a fixed, content-free
`ErrorKind::InvalidInput` before dispatch, even when the typed field is `None`.
`raw::node_update` applies the same refusal. All non-ASCII additional keys are
also refused conservatively because Go's Unicode simple folding can match an
ASCII field name; this includes unrelated extension keys, so their round trip
is unavailable.

On `connect_local`, node operations have a single 120-second overall budget
through the response head, matching the former generated local request. The
response body is not covered. Timeout or cancellation after dispatch leaves the
mutation outcome unknown; inspect the node before retrying.

A node write never promotes peer text into an error. A direct daemon or an
unauthenticated forward proxy can echo the request body's name and labels in a
failure message, so any non-2xx answer keeps its status in `Error::api_error()`
but replaces its message and every source with fixed text that names the
withholding. The response body is dropped without being read, so an unbounded
error body is never collected. `Display`, `Debug`, `api_error()`, and every
source carry only the fixed text. A non-API failure keeps its kind and loses its
source chain. The withholding is unconditional rather than a search for the
metadata, because a peer can encode or truncate it in a way an exact match would
miss. This includes `--raw-error`, which used to print the daemon's words for
these two operations; a caller that needs to distinguish a conflict branches on
the preserved status.

`remove_node` has no request body, but it shares the failure policy because a
peer can still echo node metadata in its answer. It always spells `force`,
`force=true` or `force=false`, so a recorded request states whether removing a
manager was part of it. A manager removed without `force` is refused by the
daemon with its own `400` status and its text withheld.

Both are mutations. Dropping the future after dispatch closes the connection but
does not retract the request: the daemon may already have applied the write, may
still be applying it, or may never have received it. Nothing here retries, and a
blind retry after a transport error can be wrong; reconcile with `inspect_node`
or `list_nodes` before deciding what to do.

Node documents carry operator- and daemon-controlled metadata: node labels,
`Description.Hostname`, engine labels and plugins, `Description.TLSInfo`, and the
manager address. The returned value carries them, so `Serialize` output and
`ndocker node inspect --json` are that metadata. `SwarmNode`, `NodeSpec`, and
`NodeManagerStatus` gained hand-written `Debug` impls that report identity
sizes, label counts, and unmodelled-member counts, and print no values;
`NodeUpdateOptions` inherits the `NodeSpec` redaction through its derived
`Debug`. Explicit serialization is not redacted.

Release treatment: **not simply additive.** Existing method signatures remain,
but behavior differs on a reachable endpoint and on `connect_local`.
`Error::is_transport_deadline()` is a new predicate for crate-generated
transport deadline markers. The immediate error source for these timeouts was
previously `std::io::Error`; it is now a private marker type. Code downcasting
the immediate source should migrate to the predicate. The marker establishes
where the error originated, not necessarily which operation timed out: a custom
stream factory can propagate an earlier marked error. External or OS timeouts
are not necessarily classified. For node mutations the original source chain
is dropped and a fixed safe deadline message is returned; it does not claim the
current mutation timed out, because the marker may have propagated from an
earlier factory operation. The outcome remains unknown and requires
reconciliation before retry.

- Node reads on `connect_local` now use the captured owned endpoint instead of
  Bollard. They send the versioned request, retain unmodelled members, and
  refuse a repeated top-level key or key in any object beneath `Spec` instead of using the
  value serde kept last. `raw::node_list` and `raw::node_inspect` apply the same
  duplicate-key refusal; that is a deliberate raw compatibility change.
- Node writes have no generated fallback. `connect_local` keeps a working local
  write through the captured socket. An endpoint with no concrete owned target
  now fails closed with a fixed `InvalidInput` diagnostic; previously Bollard
  would send the request, trace its body, and could report `101` or `304` as
  success. A caller on such an endpoint must build the client with
  `connect_local` or an explicit endpoint the owned transport reaches.
- `update_node` sends an unmodelled specification member or a `Role`/
  `Availability` outside Bollard's models member for member, so a newer daemon's
  state is preserved. A specification whose `additional` map carries `Name`,
  `Labels`, `Role`, or `Availability` under any ASCII-case spelling is refused
  before dispatch, even when the typed field is `None`. Non-ASCII additional
  keys are also refused conservatively.
- Any node-write status outside `200..=299`, including `101` and `304`, is a
  failure. The observed status is preserved, the message and every source are
  replaced with fixed withholding text, and the response body is not read.
  `--raw-error` prints that fixed text rather than daemon words. The ndocker
  node-write conflict diagnostic is classified from the status and uses generic
  "resource conflict" wording; other Swarm operations keep their existing
  version-conflict meaning.
- Both writes keep their unknown-outcome-on-cancellation contract.

On the owned route, a node carrying an actual top-level `EngineVersion` of any
JSON type, including `null`, is now unavailable: the whole list or inspect fails
before projection with a fixed `Serialization` error, and a list containing one
such node fails whole. The former generated fallback did not refuse it; Bollard's 1.53
`Node` model dropped the actual member and returned the node with the nested typed
view, so the actual value was silently absent there. Raw applies the
duplicate-key refusal but still keeps the top-level `EngineVersion` projection
caveat. The dotted manager-address views preserve an actual top-level member of
the same name; that is a deliberate raw compatibility change from the original
overwrite behavior.
The alpha release notes should call this out for callers that relied on the
unversioned generated request, its permissive empty reference, its decode error
class, the last-value collapse of a duplicate node key, the generated node
write on an endpoint with no owned target, the silent `NodeSpec` drop, or the
raw `ManagerStatus.Addr` overwrite.

`leave_swarm` follows the same routing rule, and the same no-retry-over-the-
fallback rule. The owned request is `POST /v<owned>/swarm/leave?force=true` or
`POST /v<owned>/swarm/leave?force=false`, spelling the parameter in both cases
so a recorded request states whether leaving a manager was part of it. The
former generated fallback sent the unversioned `POST /swarm/leave` and sent
`?force=true` only when force is requested, so its request cannot distinguish
"not forced" from "not sent". On a reachable endpoint the owned request is used;
An unavailable owned endpoint fails before dispatch, and a failed request is
returned without retry.

A daemon older than the configured version can reject the versioned leave
request as too new where the unversioned fallback would have been accepted.
That rejection keeps the daemon's status and message in `Error::api_error()` and
is not retried over the fallback; build the client with a version the daemon
serves, or upgrade the daemon.

`force = true` leaves even when this node is the last manager. In that case the
daemon removes the last manager and erases the Swarm's current state (services,
networks, configs, and secrets), leaving the Engine standalone. An unforced
leave of a manager is refused with the cluster intact, and a leave from a worker
or from one of several managers does not erase the cluster. The client cannot
tell which case it is in from the request alone. Recovery from a last-manager
leave is not provided by this facade: it depends on a Swarm state backup
secured before the call and restored through Docker's documented procedure.
Without such a backup the state loss is irreversible.

A leave is a mutation, so dropping the future after dispatch closes the
connection without retracting the request: the daemon may have processed it,
may still be processing it, or may never have received it. A later
`inspect_swarm` or node list is a snapshot rather than proof that an earlier
leave settled — the daemon can apply the leave after the snapshot, and the
leaving node's own view can be stale — so it cannot make a retry safe.
Resolving that uncertainty requires coordination with the operator or another
manager, outside this client, before a retry is considered.

`unlock_swarm` uses the same owned transport, but it has no generated fallback.
On an endpoint `DockerClient::raw_engine` cannot reach it fails closed before
dispatch: no request is sent, and the error names the endpoint gap. The owned
request is `POST /v<owned>/swarm/unlock` with the Engine's
`{"UnlockKey":"..."}` body. The configured-version risk above applies: a daemon
older than `<owned>` rejects the versioned request as too new, and that
rejection is returned, not retried.

The fallback was removed rather than weakened. Bollard 0.21.1 has no method for
`POST /swarm/unlock`; borrowing a unit-returning generated method would put the
key in Bollard's buffered-request `trace!` and would treat `304 Not Modified`
and `101 Switching Protocols` as success without exposing the status. A caller
would either leak the key at trace level or see `Ok(())` for a status the Engine
did not mean as an accepted unlock. No public Bollard API exposes the response
status without that buffered path, and the endpoint is never inferred from
`DOCKER_HOST` here.

The key is a credential; it is redacted from `Debug`, never logged, and the
owned transport renders a request body as its length rather than its bytes. A
failed or cancelled unlock is returned as it happened: the facade does not
retry, and a cancelled request has an unknown outcome because the daemon may
have unlocked before the connection was dropped. Read `GET /swarm` before
deciding to send the key again.

Failure text is withheld on the owned route. A direct daemon or an
unauthenticated forward proxy can echo request text in a failure message, and
the request body is the key. When the failure is an Engine rejection, its HTTP
status survives in `Error::api_error()`; the message and the whole source chain
are fixed text that names the withholding. A non-API failure keeps its kind and
loses its source chain the same way. This is unconditional, not a search for
the key, because a peer can encode or truncate it in a way an exact match would
miss. A caller that read `api_error().message` for unlock must now branch on the
status.

Release treatment: **not simply additive.** The public surface is unchanged —
`unlock_swarm` keeps its signature and `Error::api_error()` keeps its type — but
behavior changes on an endpoint the owned transport cannot reach, and the
migration decision is pending rather than made by this slice. This crate has no
release-notes file; this paragraph is the pending note until one exists.

| Difference | Before | Now |
| --- | --- | --- |
| Reachable request line | versioned `/v1.NN/swarm/unlock` | unchanged |
| Unreachable endpoint | generated fallback could report `Ok(())` for `304` or `101` and trace the buffered key | an error before dispatch; no request |
| Failure text | the fallback preserved or traced untrusted text | the owned route withholds it; an unreachable endpoint sends nothing |
| Cancellation | unknown outcome; no retry | unchanged; the corrected non-blocking fixture observes the peer close, and no cooperative cancellation guarantee is claimed before the separate transport guard lands |

The cancellation row is deliberately not a guarantee. The older fixture blocked
the current-thread runtime, so its "no close" result was test starvation, not a
transport leak. The corrected fixture uses non-blocking oneshot observation and a
`spawn_blocking` join; it observes the close and also passes on the branch base,
so it is a fixture-correctness check rather than a regression guard for a
transport change. A cooperative task-cancellation guarantee is not claimed here;
it waits for the separate transport guard to be integrated.

The compatibility change is explicit: `connect_local()` and an SSH endpoint
whose owned transport cannot be described can no longer unlock. Build the client
with an endpoint description the owned transport can reach, for example
`DockerClient::connect_endpoint_with_version` for a Unix socket, TCP, or a fully
described `ssh://` endpoint. The endpoint is not inferred from `DOCKER_HOST`.
The owned route sends the JSON body with a `Content-Length`; no chunked
intermediary is assumed, and the fail-closed path never sends the key to one.

Native and managed SSH differ here. A native `ssh://` endpoint reached with the
system `ssh` binary is an ordinary reachable target and uses the owned request.
The managed `neotales-ssh` establishment gate is open by default.
`ManagedSshClient::require_closed()` explicitly closes it before DNS, file or
network work, including for cloned clients and raw engines. `unlock_swarm` asks
the transport's own per-client gate before dispatch. A closed gate returns that same
fixed local diagnostic, rather than sending the key and having it replaced by
the generic withheld transport message; an open gate follows the normal owned
route. The message has one source in
`ssh_neotales`, and the diagnostic is a fixed local string, not peer input.

This is a wire-path change for reachable targets, not a public type or
signature change: `inspect_swarm` and `swarm_join_token` change together
because the latter reads the former's document, and `inspect_config`,
`inspect_service`, `leave_swarm`, and `unlock_swarm` each change independently.
All listed operations fail closed before dispatch if the owned transport
cannot reach the endpoint; no generated route remains. The cluster lifecycle operations
(`initialize_swarm`, `join_swarm`, `update_swarm`, `swarm_certificates`, and
`swarm_unlock_key`) also have no generated fallback and fail closed the same
way; they use the captured `connect_local` socket, so the ordinary local client
keeps working. `join_swarm` replaces an Engine or proxy failure message with
fixed text because the body is a join token; its status is preserved.
`update_swarm` refuses `Name` or `Labels` in `SwarmSpec::additional` under any
ASCII case spelling, and any non-ASCII additional key, before dispatch: the
flattened map would otherwise emit a duplicate JSON key beside the typed field.
The generated route silently let the flattened value replace the typed field,
so this is a deliberate refusal rather than a shape the caller can rely on.
`swarm_certificates` and `swarm_unlock_key` now send versioned `GET
/v<owned>/swarm/cert` and `GET /v<owned>/swarm/unlockkey` requests instead of
borrowing Bollard's unversioned `ping` and rewriting its path. All Swarm operations now use the owned transport. The pending release notes above record the
behavior change for callers that relied on the unversioned request or on the
generated fallback.

Secret creation accepts a redacted, zeroizing `SwarmSecretData`. A list or
inspect answer does not contain secret bytes; an unexpected `Spec.Data` a peer
sends anyway is retained at the `Spec` object level in
`SwarmSecretSpec::additional` without being printed by `Debug`, as described
under [config `Data` versus secret
`Data`](#config-data-versus-secret-data). Both `ndocker secret inspect` and
`--format json secret ls` serialize that value, so their JSON output is
secret-bearing. Secret reads have no generated fallback and fail closed when no
owned target exists. Update methods require the version read by the caller and
preserve a daemon `409 Conflict`'s status as an API error while withholding its
text. Callers must inspect again and decide whether to retry; the facade does
not perform an implicit write/retry loop.

### Swarm lifecycle failure text

The five owned-only cluster operations replace every failure message and source
chain with fixed, operation-specific text. The HTTP status is preserved when the
peer answered; a non-API failure preserves only its kind. The response body of a
non-success answer is dropped without being read. A transport deadline keeps the
typed marker so a caller can tell "the outcome is unknown" from a rejection, and
the fixed text does not claim this operation itself timed out.

| Operation | What the fixed text names | Status |
| --- | --- | --- |
| `initialize_swarm` | manager addresses in the request | preserved |
| `join_swarm` | the join token in the request | preserved |
| `update_swarm` | the Swarm specification in the request, including `additional` values | preserved, including `409` |
| `swarm_certificates` | the node key in a successful answer | preserved |
| `swarm_unlock_key` | the manager unlock key in a successful answer | preserved |

This is a release-relevant behavior change: a caller that read
`api_error().message` for one of these operations used to get the daemon's or
proxy's words. It now gets the fixed text and must branch on the status. Success
answers are unchanged: init returns the node ID, update has no document, and the
certificate and unlock-key reads return the same repository-owned values with
their existing `Debug` redaction and zeroization. A malformed success document
is still `ErrorKind::InvalidInput` with a content-free decode summary.

The client is capped at Engine API v1.55. The request fixtures assert the paths
and query encodings the owned transport produces at that version; they do not
assert anything about v1.56, and the fields that 1.54 and 1.55 added are
enumerated in the conformance table rather than implied. The `unlock` request
uses the owned `POST /v<owned>/swarm/unlock` on every endpoint the owned
transport can reach. It has no generated fallback: an unreachable endpoint fails
closed before dispatch. No independent Engine HTTP client or shell fallback is
used.
`GET /swarm/unlockkey` is served by `DockerClient::swarm_unlock_key` through the
repository-owned transport as `GET /v<owned>/swarm/unlockkey`; there is no
generated fallback. The owned-transport route uses the captured `connect_local`
socket, and an endpoint with no concrete owned target fails closed before
dispatch. The document decodes into `SwarmUnlockKey`; the key is redacted from
`Debug` and zeroized when dropped. `GET /swarm/cert` is served the same way as
`GET /v<owned>/swarm/cert`, and a current daemon's `404` is returned as the
daemon's own rejection rather than masked as a missing document.

**v1.56 support is backlog work, after the alpha packages are shipped.** A daemon
may advertise a maximum above v1.55 (Docker Engine 29.8 advertises v1.56); that
does not raise this crate's ceiling. Before changing `API_VERSION`, audit the
v1.56 schema and behavior, implement the additions this facade claims to expose,
update the conformance table and fixtures, and verify against a daemon that
supports v1.56. The live ceiling tests deliberately distinguish the crate's cap
from a daemon's independently reported maximum.

Deterministic fixtures live in `../fixtures/docker/engine/swarm/`. The Swarm
inspect wire path is pinned by `tests/swarm_inspect.rs` on a loopback fixture:
the versioned `GET /v<owned>/swarm`, the join-token read through the same
request, unmodelled top-level and specification members retained, join tokens
redacted from `Debug`, a daemon rejection returned without a retry, and decode
failures that do not echo a token canary. Previously, `tests/swarm_inspect_fallback.rs`
pinned the generated fallback on a platform-local endpoint: the unversioned
generated request, the discard of unmodelled members, and the
`ErrorKind::Docker` decode class. The leave wire path is pinned by `tests/swarm_leave.rs`. The owned suite
compares the exact versioned request lines for both force values and for a
configured version, while the former fallback suite compared only the unversioned
request target — its path and query — rather than the whole request line. The
owned fixture uses synthetic daemon answers and checks for retry during a
bounded watch window after the answer. The owned suite additionally checks
that dropping the future releases the connection. The unlock wire path is
pinned by `tests/swarm_unlock.rs` on a loopback fixture: the exact versioned
`POST` and body, the configured version, an empty key, redaction, withheld
failure text, synthetic `101` and `304` rejections, and a held response that
proves no retry. The former `tests/swarm_unlock_fallback.rs` checked the fail-closed contract
and was removed with the generated route. The cluster lifecycle
wire paths are pinned by `tests/swarm_lifecycle.rs` on loopback fixtures: the
versioned init, join, update, certificate, and unlock-key requests; the exact
init and join bodies; the spelled update query and body; a reserved
`SwarmSpec::additional` key and a join with no manager address refused before
dispatch; failure text withheld for all five operations with plaintext and
base64 canaries in the error's `Display`, `Debug`, API message, and full source
chain, with no retry; transport failures withheld; authenticated and
unauthenticated proxy echoes withheld for all five without a direct connection;
duplicate certificate and unlock-key response keys refused without echoing a
canary; a configured version; and synthetic `101` and `304` answers rejected as
failures. A raw unit test propagates a marked transport deadline through every
operation and proves the marker survives while the earlier factory text does
not. `tests/swarm_lifecycle_local.rs` runs in a child with an isolated
`DOCKER_HOST` and proves the captured `connect_local` socket serves all five
with versioned request lines while a TRACE capture never sees the join token,
the node key, the unlock key, the init address, or the update specification.
The config
inspect wire path is pinned by `tests/swarm_config_inspect.rs` on a loopback
fixture: the exact versioned `GET` for the default and a configured version,
percent-encoding of the reference, an empty reference refused before dispatch,
unmodelled members retained, the inspect-only data member, a not-found
rejection and an old-daemon version rejection with no retry, and content-free
decode failures checked against synthetic config-data canaries. The config list
wire path is pinned by `tests/swarm_config_list.rs` on a loopback fixture: the
exact versioned `GET` for the default and a configured version, no query for an
empty filter map, exact ordered filters, an unknown filter name forwarded with
its `400` returned without a retry, `[]`, `null`, empty, malformed, and
`null`-entry answers, unmodelled members retained, a daemon rejection returned
without a retry, an abandoned request releasing its connection without a retry,
and content-free decode failures checked against synthetic config-data canaries.
`tests/swarm_config_list_fallback.rs` formerly pinned the unversioned generated request and
ordered filters, the discard of unmodelled members, and the
`ErrorKind::Docker` decode class on a local endpoint. The
authenticated-proxy withholding exception for `Error::api_error()` is pinned by
`tests/raw_http_proxy.rs` through `list_configs`, `inspect_config`,
`list_nodes`, `inspect_node`, `inspect_swarm`, `update_node`, and
`remove_node`.
`tests/swarm_config_inspect_fallback.rs` formerly pinned the unversioned generated
request, the discard of unmodelled members, the unstripped empty reference, and
the `ErrorKind::Docker` decode class on a local endpoint. The service inspect
wire path is pinned by `tests/service_inspect.rs` on a loopback fixture: the
exact versioned `GET` for the default and a configured version, the whole
`Endpoint`, `PreviousSpec`, and `UpdateStatus` retained, `Spec.TaskTemplate`
read verbatim, the accepted nested task-template create and update body, typed
placement and restart policy carried by both writes with every dotted
`additional` key refused before dispatch, an empty reference refused before
dispatch, malformed
and wrongly typed projections rejected, a daemon rejection returned without a
retry, a too-new-version rejection, the authenticated-proxy withholding on that
route, and decode failures checked against a canary.
`connect_local` captures one local socket and uses it for service inspect and
update, so the local inspect→modify→update path keeps unmodelled nested members
instead of dropping them in a generated read. `tests/service_update_local.rs`
pins that path with an exact versioned inspect, a modified specification, and an
exact update body. An endpoint without an owned target now fails before
dispatch; no generated inspect fallback remains.

The service list path is pinned by
`tests/service_list.rs` on a loopback fixture: the exact versioned
`GET /v1.NN/services?…&status=true` for the default and a configured version,
filters before `status` in `BTreeMap` order, `Ports: []` distinct from no
projection, `Endpoint` and `ServiceStatus` absent, `null`, empty, and partial,
malformed projection inputs rejected, `Endpoint`, `PreviousSpec`, `UpdateStatus`,
the task template, and unmodelled members retained, `Debug` with the retained
environment withheld, a rejection and an authenticated-proxy 407 without a
retry, decode failures checked against a canary, and the raw list's
filters-only request and strict projection unchanged.
`tests/service_list_fallback.rs` formerly pinned the unversioned generated request and its
narrower projection on a platform-local endpoint.
The service create wire path is pinned by `tests/service_create.rs` on a
loopback fixture: the exact versioned `POST /v1.NN/services/create`, the
complete body with `ContainerSpec.Env` and `Secrets` intact and typed placement
and restart policy inside `TaskTemplate`, the Engine's URL-safe
`X-Registry-Auth` header, a credential for another registry refused before
dispatch, a rejection whose status survives while all peer text is withheld
without a retry, and decode failures checked against a canary.
`tests/service_create_local.rs` pins `connect_local` on a captured Unix socket:
the owned create and credentialed create reach it. A synthetic TRACE record,
`local-log-capture-control`, verifies that capture works, while neither the
service environment, the secret name, the registry password, the encoded
environment, nor the credential header appears in the log.
`tests/service_case_collisions.rs` pins the facade refusal of a typed member
beside a lower-case `additional`/`task_template` spelling, a non-ASCII
`additional` key, and two case spellings of one key, for both create and
update; the fixture records any connection and every case proves zero dispatch.
Its allowed control sends a non-ASCII label key and an unknown ASCII
task-template member unchanged.
`tests/service_remove.rs` pins the versioned escaped `DELETE`, a `200` with an
empty body, the preserved `404` message without a retry, and the
empty-reference refusal; `tests/service_remove_fallback.rs` previously pinned the
unversioned generated fallback on a local endpoint.
`tests/service_logs.rs` pins the versioned query, multiplexed frame decoding,
the status reported before any frame, a truncated-frame error item, the
empty-reference refusal, and cancellation closing a following connection;
`tests/service_logs_fallback.rs` previously pinned the unversioned generated fallback on a
local endpoint. The former fallback files were removed; the owned-path files run on every
platform.
The node read paths are pinned
by `tests/swarm_node_reads.rs` on a
loopback fixture: the versioned list and inspect for the default and a
configured version, an empty and an exactly-ordered filter map, the retained
`Description`, `Status`, manager status, and unmodelled top-level and
specification members, an empty reference refused before dispatch, a not-found
rejection and a too-new-version rejection without a retry, malformed and wrongly
typed documents, duplicate top-level, `Spec`, and `Spec.Labels` keys refused
before projection with their values not echoed, and the complete owned update
body after an owned inspect, with an unmodelled `Spec` member retained.
`tests/swarm_node_writes.rs` pins the owned write wire path on a loopback
fixture: the exact versioned update and removal request lines for both `force`
values and a configured version, percent-encoding of the reference, the
complete update body including unmodelled members and enum strings outside
Bollard's models, both empty-reference refusals before dispatch, reserved
`additional` keys refused before dispatch for every ASCII-case spelling and
for both the typed-absent and conflicting-typed form, a `409` conflict and a
too-new-version rejection whose status survives while all peer text is
withheld, the manager rejection with withheld text, `101` and `304` rejected as
non-2xx with the observed status preserved, and cancellation releasing the
connection without a retry. Its `src/swarm.rs` unit test pins the fail-closed
diagnostic for a client with no owned target. `tests/swarm_node_local.rs` pins
`connect_local` on a captured Unix socket: versioned list, inspect, update, and
removal, retained unmodelled members, duplicate-key refusal, an empty reference
refused before dispatch, the owned decode class, and a TRACE capture proving the
owned node writes do not log the synthetic node name or label. A unit test pins
that a later `DOCKER_HOST` read cannot move the already-captured socket. `tests/raw_http_proxy.rs` adds the
authenticated- and unauthenticated-proxy withholding for both node writes. Raw
unit tests pin the duplicate-key refusal at each consumed level and the
reserved-key refusal before encoding.
The secret read paths are pinned by `tests/swarm_secret_reads.rs` on a
loopback fixture: the versioned list and inspect for the default and a
configured version, an empty and an exactly-ordered filter map,
percent-encoding of the reference, an empty reference refused before dispatch,
a not-found and a too-new-version rejection whose status survives with the text
withheld, malformed and wrongly typed documents, decode failures checked against
a secret-data canary, an unexpected `Data` of every JSON type retained but
withheld from `Debug` (including through `SecretUpdateOptions`) and still
present in explicit serialization, a duplicate unmodelled key collapsing to one
value, a duplicate known key refused without echoing, the accepted generated
update body, case-folded `Data`/`Name`/`Labels`/`Driver` keys (with the typed
fields absent) refused by the facade and by `raw::secret_update` before
dispatch, a serialized spec proving the duplicate-key hazard the guard
prevents, an escaped JSON key that decodes to `Data` and is refused, an escaped
Unicode key (`Label\u017f`) retained on read and refused by both writers, and a
direct `raw::secret_list`/`raw::secret_inspect` rejection whose full chain
carries the fixed diagnostic rather than the peer's echo.
`tests/swarm_secret_reads_local.rs` pins `connect_local`: `raw_engine` and
secret reads use the captured Unix socket, send versioned paths, and
retain/refuse the same value shapes. Unit tests inject a one-second overall budget and a stalled Unix peer
through both the facade and the raw operation, assert the exact request line and
the partial-head write, require the fixed timeout marker, and record an
approximate 0.9-3 s wall-clock sanity band with a scheduling caveat; they also
include a no-head transport-error negative and a no-deadline mutation control,
without waiting 120 seconds.
The fail-closed unit test uses an active listener and asserts no connection; the
local fixture uses bounded accepts and reads, so a broken worker fails the child
instead of hanging the join. `tests/swarm_secret_reads_logging.rs` installs a
capturing `log` logger at `TRACE` and checks that canaries from owned task-list,
secret-inspect, and secret-list responses do not reach it. None of these suites
starts a daemon.

## Resource and registry slice

The facade exposes repository-owned plugin, registry-auth, local context, and
Docker-config credential boundaries in addition to network/volume and system
operations. Plugin list/inspect/enable/disable/remove/set, bounded plugin TAR
creation,
privilege lookup, install progress, upgrade, and push keep Bollard models
private. Registry authentication uses Engine v1.55 `POST /auth`; credentials
are bounded, redacted, and zeroized. `RegistryConfigStore` honors
`credHelpers` before `credsStore`, preserves unrelated config keys, and invokes
only validated `docker-credential-*` helpers directly. `ContextStore` handles
named context list/create/update/remove/use and delegates archive operations to
the bounded `ContextArchiveStore`.

The CLI resource parser covers network, volume, system, plugin, context, builder,
resource-specific prune, and registry login/logout. Non-interactive prune calls
require `--force`; interactive calls require an affirmative `y`. The explicit
`system prune` policy is confirmed but never composed into resource calls
because no Engine API version through v1.55 defines a daemon-wide
`/system/prune` endpoint.

## Streams

`logs`, `stats`, and `events` return a `DockerStream<T>` rather than a Bollard
stream. The handle owns the response body, implements the standard
`futures_core::Stream` trait, and also provides an inherent async `next`
method. It does not buffer: each poll yields at most one decoded item.

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

Docker's multiplexed log frames remain separate and retain their source
(`Stdout` or `Stderr`); the eight-byte transport header is not exposed. Raw
TTY output is represented as `ContainerLogStream::Console` rather than being
misclassified as multiplexed stdout. Image pull/push progress is exposed as
`ImageStreamEvent`, and image archive downloads yield caller-owned byte chunks.

The response handle is independent of `DockerClient`: callers may drop the
client after creating it. Call `cancel()` or `close()` when a response is no
longer needed; dropping the handle has the same ownership behavior. Cancelling
drops the underlying response body, with immediate socket closure dependent on
the owned transport. Transport and decode errors are returned by `next()`.

The current facade exposes typed container attach and exec session boundaries
with caller-owned input/output handles. WebSocket and h2c upgrades remain
explicitly outside this slice and require their own transport/ownership
fixtures. Build/load request-body streams are implemented by the separate
bounded image-transfer boundary below. The owned frame decoder handles malformed multiplexed frames.

### Build streams

Directory contexts use the selected Dockerfile's `<Dockerfile>.dockerignore`
if present; otherwise they use the context-root `.dockerignore`. Use
`ImageBuildContext::from_directory_for_dockerfile_with_limits` when selecting
a non-default Dockerfile. Both the default `Dockerfile` and the selected
Dockerfile, the context-root `.dockerignore`, and selected ignore file are
included even if matched by an exclusion.

The supported ignore patterns include `*`, `?`, `**`, character classes,
platform-specific backslash handling, `!` exceptions in last-match order, comments
beginning in column one, blank lines, and surrounding whitespace. Leading and
trailing slashes are disregarded; dot components and repeated separators are
cleaned. Malformed patterns are refused with a line number. Windows treats
backslashes as separators; other platforms treat them as escapes. Ignore files are limited to 64 KiB and 4096
patterns; ignored entries count toward the context traversal limit.

Symbolic links are archived as links, without dereferencing their targets,
including targets outside the context. Archives with entries beneath a
symbolic link are rejected. Unix files and directories retain their permission
bits; modification times are normalized to zero for reproducibility. Unix
devices, FIFOs, and sockets are refused with their path and type. Hard-linked
regular files are archived as independent regular files. On non-Unix platforms
modes use the best-effort defaults `0644` for files and `0755` for
directories. Ignore files must be regular files, not symbolic links. Directory
packing assumes the tree is not mutated concurrently; it is not a security
boundary against path replacement races.

`build_image` uses the owned, versioned `POST /v1.NN/build` request and a
validated TAR context as a streamed body. An unavailable target fails and a
request is never retried through another client.

`ImageBuildOptions::remote` is explicitly rejected before a request is opened.
This operation accepts a caller-owned, validated TAR, not a remote context for
the daemon to download. Fetch and validate a context separately before building.

The owned request sends `platform` and `target` only when the caller set them,
one `t=` pair per tag, `buildargs`/`labels` from the ordered maps, and no
`version=1` `BuildKit` selector. `X-Registry-Config` is the map header
`POST /build` reads on the owned route, in URL-safe base64; the owned route omits
absent optional members from each auth object instead of writing them as `null`.
Credentials are validated before the handle is returned.

The classic route accepts one JSON `buildargs` map. It reads only the first
query value and unmarshals it into a map, so BuildKit-style repeated buildargs
list semantics are not supported; repeated query values would be discarded.

**A `200` is not a result.** The daemon reports a failed step as a record
carrying `errorDetail.message`, and the owned route turns it into a Docker-kind
`Err` item. The daemon message is available through `std::error::Error::source`;
the outer error displays `Docker client error`. The source is a repository-owned error; the former generated route no longer
exists. On an
authenticated owned proxy route, an in-band Docker failure is instead
`Error::engine_api(200, fixed safe text)`: `api_error` carries status `200` and
the fixed message, and the source is the fixed `DockerApiError`, not a
`StreamError`. Direct and unauthenticated proxy routes keep the `StreamError`
source. A caller
must handle `Err`;
`ImageBuildEvent::error` is `None` on the owned route. A record with a duplicate known
member, or a known member of the wrong JSON type, is an error item on the owned route: the owned route validates the record's original bytes (so a failed
`errorDetail` followed by `"errorDetail":null` cannot hide the failure), reports
`ErrorKind::Serialization`, and continues with the next record, while the
former generated fallback reported every Bollard stream failure as `ErrorKind::Docker`
and ended the stream. The known members are the generated model's: `id`,
`stream`, `status`, `errorDetail` (`code`, `message`), `progressDetail`
(`current`, `total`), and `aux.ID`. A record over `raw::MAX_RECORD_BYTES` is
refused before it is assembled. The owned route also bounds the streamed upload at
`raw::MAX_UPLOAD_BYTES` (256 MiB); the default context limit is 64 MiB, so this
is reached only by a caller that raises `ImageTransferLimits`. Cancelling or
dropping the handle releases the response body.

## Registry-authenticated image streams

Registry credentials are never read from Docker configuration implicitly. A
caller can supply an owned `RegistryCredentials` value, use the synchronous
`RegistryCredentialProvider` boundary, or explicitly select the bounded
`DockerCredentialHelper` adapter:

```rust,no_run
use neotales_docker::{
    DockerClient, DockerCredentialHelper, ImagePullOptions,
    InMemoryRegistryCredentialProvider, RegistryCredentials,
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = DockerClient::connect_local()?;
let mut provider = InMemoryRegistryCredentialProvider::new();
provider.insert(
    "registry.example",
    RegistryCredentials::new("alice", "password-from-caller-owned-storage"),
);
let mut pull = client.pull_image_with_provider(
    "registry.example/team/app",
    Some(ImagePullOptions {
        tag: Some("stable".to_owned()),
        ..Default::default()
    }),
    &provider,
)?;
while let Some(event) = pull.next().await {
    println!("{:?}", event?);
}
# let _ = DockerCredentialHelper::new("docker-credential-example", std::time::Duration::from_secs(1));
# Ok(())
# }
```

`pull_image_with_provider` and `push_image_with_provider` resolve the registry
from the image reference before constructing the stream. Explicit
`*_for_registry` variants are available when a local image name needs a
registry selected by the caller. The `*_with_credentials` methods provide the
same path for an already-owned value. `*_with_credential_helper` resolves the
helper asynchronously before opening the response; the helper receives its
action as a direct argument and registry/payload over stdin, with a validated
executable name, no shell, a timeout, bounded stdout, and redacted errors. None
of these methods stores credentials in the client or edits `config.json`.

Credentials are validated before opening a request and encoded by the owned
transport in the request-scoped `X-Registry-Auth` header. Owned credential
values are zeroized when dropped and are not included in `Debug`, `Display`, or
facade errors. The returned `DockerStream<ImageStreamEvent>` owns the response
body and may be cancelled or dropped independently of the client. No generated
client is used for authenticated image operations.


Network operations cover list, inspect, create, remove, connect/disconnect,
and resource-specific prune; volume operations cover list, inspect, create,
remove, and resource-specific prune. Image build, load, import, high-level
save/archive writing, and platform-specific delete are exposed by the bounded
image-transfer and image-operation boundaries. Cluster-volume objects and other
daemon-specific nested fields remain outside this slice. Attach and exec
sessions are typed and caller-owned; `resize_exec` resizes an exec pseudo-TTY
through repository-owned `ExecResizeOptions`. Container creation serializes
`ContainerHostConfig::umask` as the Engine `HostConfig.Umask` value through a
request modifier, because Bollard 0.21.1's generated host-config model has no
such field. The repository type carries the octal spelling a person writes
(`0022`) while the Engine declares a `uint32`, so the modifier sends a JSON
**number** (`18`); sending the string is rejected outright by Docker Engine
29.8.0, and a non-octal value is refused locally rather than becoming a `400`
about JSON types. WebSocket and h2c ownership are not claimed by this slice and
still require their own fixtures or a narrow extension/fork decision.

The former generated client was limited to v1.53; the owned transport targets
v1.55. Typed coverage limitations are listed in the
[conformance table](#conformance-boundary-for-154-and-155).

Enable transport features as needed:

```toml
[dependencies]
neotales-docker = { path = "../lib/neotales-docker", features = ["ssh", "tls"] }
```

`connect_defaults` resolves `DOCKER_CONTEXT`, the Docker config current
context, `DOCKER_HOST`, and platform defaults through the repository-owned
resolver. Context-local TLS material is used when present, and contexts that
request `SkipTLSVerify` are rejected.

TLS verifies server trust, validity times, and hostname by default. Trust is
the union of the platform root store and the CA bundle in `TlsMaterial`; the
supplied bundle is required but is not an exclusive pin. With the `tls` feature,
a caller can explicitly accept impersonation risk:

```rust,ignore
use neotales_docker::{DockerClient, Error, ProxyPolicy, TlsMaterial, TlsServerTrust};

fn connect_with_explicit_trust(material: &TlsMaterial) -> Result<DockerClient, Error> {
    DockerClient::connect_https_with_trust(
        "https://docker.example:2376",
        material,
        ProxyPolicy::Direct,
        TlsServerTrust::AllowExpiredOrUntrusted,
    )
}
```

## Engine profiles

`EngineKind` and `EngineProfile` select which engine's Docker-compatible
endpoint is addressed. The selection is always explicit, from a caller option
or from `NDOCKER_ENGINE`; it is never inferred from which socket exists,
because Docker, Podman, and nerdctl are routinely installed side by side and
silently talking to the wrong engine is worse than failing.

```rust,no_run
use std::collections::BTreeMap;

use neotales_docker::{ContextResolver, EngineKind, EngineProfile};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let environment = BTreeMap::from([("NDOCKER_ENGINE".to_owned(), "nerdctl".to_owned())]);
let resolver = ContextResolver::new("/tmp/docker-config", environment);
let selection = resolver.resolve_for(EngineProfile::explicit(EngineKind::Nerdctl))?;
println!("{} {:?} {:?}", selection.profile.kind, selection.profile.source, selection.source);
# Ok(())
# }
```

`ContextResolver::resolve` uses the environment-selected profile, and
`ContextResolver::resolve_for` takes one explicitly. `ResolvedEndpoint` carries
the `profile` alongside the `source`, so a caller can always report both the
engine and the endpoint provenance.

Docker profile order, unchanged: `DOCKER_CONTEXT`, the current Docker context,
`DOCKER_HOST`, then the platform default. The two Docker-compatible service
profiles share one shape — an explicit `CONTAINER_HOST`, then an explicit
`DOCKER_HOST`, then the first declared service socket that exists:

| Order | Source | Podman | nerdctl |
| --- | --- | --- | --- |
| 1 | `CONTAINER_HOST` | The variable Podman itself honors. | An explicit override only: `nerdctl` itself addresses containerd through `CONTAINERD_ADDRESS`. |
| 2 | `DOCKER_HOST` | An explicit user override under every profile; this is how a Docker client is pointed at a Podman service socket. | The same explicit override; this is how a Docker client reaches a `nerdctl.sock`. |
| 3 | rootful socket | `/run/podman/podman.sock` | `/run/nerdctl/nerdctl.sock` |
| 4 | `$XDG_RUNTIME_DIR` socket | `$XDG_RUNTIME_DIR/podman/podman.sock` | `$XDG_RUNTIME_DIR/nerdctl/nerdctl.sock` |
| 5 | `UID` socket | `/run/user/<uid>/podman/podman.sock`; omitted when `UID` is not numeric. | `/run/user/<uid>/nerdctl/nerdctl.sock`; omitted when `UID` is not numeric. |

`podman_socket_candidates`/`podman_socket_sources` and
`nerdctl_socket_candidates`/`nerdctl_socket_sources` expose those orders without
probing anything. When no candidate exists, resolution fails with
`ContextError::PodmanSocketNotFound` or `ContextError::NerdctlSocketNotFound`
listing the probed paths. Neither ever falls back to a Docker socket, and a
non-Docker profile with a non-default `DOCKER_CONTEXT` fails instead of silently
using Docker context metadata.

`PathProbe` is the existence seam for platform discovery. The default probes
the real filesystem; `PathProbe::declared` treats an explicit set of paths as
existing, which is how `ContextResolver::new_with_probe` makes the Docker
platform default and both service candidate orders testable without `/run`
access, a daemon, or process-global state.

### What the Podman profile does not provide

Podman's Docker compatibility layer is a different conformance surface. The
repository rejects these Docker-only capabilities up front through
`EngineKind::unsupported_reason`, `EngineProfile::require`, and
`EngineProfile::rejection` instead of forwarding a request that can only fail
with a confusing daemon error:

| Capability | Why it is rejected |
| --- | --- |
| `EngineCapability::Swarm` | Services, nodes, tasks, configs, and secrets have no compatibility endpoints. |
| `EngineCapability::Stack` | `stack` deployment requires Swarm mode. |
| `EngineCapability::Plugin` | The Docker plugin manager endpoints are not implemented. |
| `EngineCapability::Checkpoint` | Container checkpoint endpoints are Docker-specific. |
| `EngineCapability::DockerContext` | Contexts are Docker CLI metadata under `DOCKER_CONFIG`. |
| `EngineCapability::DockerCredentialStore` | Docker keeps credentials in `config.json`, Podman in `auth.json`. |

Nothing else is claimed. Build, prune, system, and event behavior under the
Podman profile is unverified by this repository, and the v1.55 API ceiling,
TLS, SSH, proxy, and credential rules are identical for every profile. There is
no Libpod client here: this crate speaks the Docker-compatible API only.

### What the nerdctl profile does not provide

nerdctl's conformance surface rejects **fewer** capabilities than Podman's, and
the difference is grounded in nerdctl's own published documentation rather than
guessed. nerdctl's `docs/command-reference.md` has an "Unimplemented Docker
commands" section, and this profile rejects exactly what it lists:

| Capability | Verdict | Grounding |
| --- | --- | --- |
| `EngineCapability::Swarm` | rejected | "Swarm commands are unimplemented and will not be implemented: `docker swarm\|node\|service\|config\|secret\|stack *`." `task` is a Swarm-mode object with no `nerdctl` command. |
| `EngineCapability::Stack` | rejected | The same sentence includes `stack *`. |
| `EngineCapability::Plugin` | rejected | "Plugin commands are unimplemented and will not be implemented: `docker plugin *`." |
| `EngineCapability::DockerContext` | rejected | `docker context` is listed under "Others". A nerdctl endpoint is selected with an address or socket, not with context metadata. |
| `EngineCapability::Checkpoint` | **allowed** | nerdctl ships `nerdctl checkpoint create\|list\|remove`. |
| `EngineCapability::DockerCredentialStore` | **allowed** | nerdctl `docs/registry.md`: "nerdctl uses `${DOCKER_CONFIG}/config.json` for the authentication with image registries. `$DOCKER_CONFIG` defaults to `$HOME/.docker`." That is the same store this crate's caller writes. |

Nothing beyond that table is claimed. Whether a given `nerdctl.sock` provider
exposes `/build`, checkpoint, or system endpoints is unverified by this
repository, and the classic `POST /build` endpoint is not gated by this profile
at all. Also note that upstream `nerdctl` is a CLI for containerd and does not
ship a Docker-compatible API server: `/run/nerdctl/nerdctl.sock` and
`$XDG_RUNTIME_DIR/nerdctl/nerdctl.sock` are the locations documented by the
separate daemons that do, and this crate treats them as the profile's candidate
paths without verifying any one of those daemons.

The native SSH path uses the owned transport to spawn the system `ssh` binary
and run the remote Docker CLI's `docker system dial-stdio` command. No host-key
option is injected: `StrictHostKeyChecking`,
known-hosts files, identity discovery, the agent, and connection multiplexing
are the invoking user's OpenSSH configuration, so an unknown or changed host is
rejected under the user's own policy and never accepted on their behalf. An
endpoint that names a port — including `ssh://host:22` — passes it as `-p`; an
endpoint that names none omits the argument, so `Port` in `ssh_config` still
applies.

The managed `neotales-ssh` gate is **open by default**, including for clients
created by `DockerClient::connect_ssh_with_known_hosts`. Open means requests can
resolve, dial, read `known_hosts` and identity material, handshake, authenticate,
run `docker system dial-stdio` remotely and carry Engine requests. Constructing
a client still does not connect. `ManagedSshClient::require_closed()` is an
explicit per-client refusal before DNS, file or network work; it also applies
to cloned clients and their raw engines. Build features do not change this gate.
The managed policy requires a pre-provisioned, readable known-hosts file:
it accepts only a matching plain
Ed25519 host key and never creates, appends to, or replaces the file. Unknown,
changed, revoked and CA-only keys, and missing, unreadable or malformed files,
are refused. This replaces the legacy managed path's accept-new
behavior; it does not change native SSH policy.

Managed SSH applies a content-free response diagnostic policy to **every**
Engine operation, including arbitrary raw requests and streaming failures.
Peer-controlled failure text never reaches diagnostics on the managed route;
HTTP rejection status and safe typed timeout/host-key/establishment markers survive. Wording may be
operation-specific: some operations use their own fixed content-free errors.
The shared response-policy wording is
`managed SSH Engine <METHOD> operation failed (HTTP <STATUS>); response text withheld`.
Here the operation is a fixed HTTP method label (`custom-method` for extension
methods), never a path, query or request/response value. Peer failure text is not
promoted into `Display`, `Debug`, `api_error().message` or any error source. This
is stricter than the native path because managed SSH carries arbitrary Engine traffic,
including secret-bearing request bodies. Explicit raw response headers/bodies
and successful values remain caller-visible data, not sanitized diagnostics.
The policy follows the managed target, not an operation allowlist.
Plugin, container-stream, registry/distribution and Swarm withholding wrappers
all retain these local markers rather than replacing them with an untyped
error. For example, plugin deadlines use
`a transport deadline was observed; the plugin request outcome is unknown; reconcile before retrying`;
registry authentication uses `registry authentication response withheld`, and
container streams use `container stream operation failed; peer text withheld`.
These operation-specific words do not change the marker. Host-key refusals
retain only their fixed local classification and never peer text.
The public establishment boundary also discards unclassified worker/factory
details and substitutes `managed SSH establishment failed; peer text withheld`.
In particular, channel-open refusal descriptions and language strings are
discarded, not decoded into diagnostics; their numeric SSH reason is not
retained as an Engine HTTP status. No HTTP response exists at that point.

Managed host-key refusals retain the safe local classification through the
handshake, worker and raw transport. Use
`Error::managed_ssh_host_key_rejection()` to distinguish
`ManagedSshHostKeyRejection::{Unknown, Changed, Revoked, CertificateAuthorityOnly}`.
Unknown means provision trust before connecting; changed or revoked means
investigate, not accept automatically; CA-only requires a plain host-key entry.
No classification contains a key, hostname, file path or peer text. The
explicitly closed gate returns no host-key classification.

Use `Error::managed_ssh_establishment_failure()` for the content-free,
non-exhaustive `ManagedSshEstablishmentFailure` classification:

| Variant | Meaning |
| --- | --- |
| `AuthenticationRejected` | Authentication ended after a validated server authentication-failure response. Not proof of a wrong password; account/method policy or another required factor can prevent acceptance. |
| `NoUsableAuthenticationMethod` | No usable method or signature algorithm remained without an observed server refusal. The key may never have been offered. |
| `ChannelOpenRefused` | The authenticated peer refused the session-channel open. Description, language and numeric reason remain discarded. |
| `IdentityFile` | Local key material could not be read, parsed or decrypted, or exceeded a policy limit. Paths, key bytes and parser details are withheld. This does not assert a wrong passphrase. |

`Error::is_managed_ssh_authentication_rejected()` is true **only** for
`AuthenticationRejected`, not for skipped/incompatible methods. The managed
handshake requests RFC 8308 `server-sig-algs`, so an incompatible advertised
algorithm can be refused locally before sending a public-key query. No
classification is inferred from peer text or the attempt counter.

Identity failures deliberately get one coarse, cheap local category rather
than an unreliable wrong-passphrase diagnosis. Other failures, including
malformed authentication and an unclassified connection/exec failure, still
return fixed generic establishment text. Timeouts and host-key refusals retain
their separate markers. All these safe classifications survive the worker,
raw transport and withholding wrappers without the old source chain; a marker
can be propagated from an earlier request.

For each managed establishment, the file is read into a snapshot before
the handshake. An atomic replacement concurrent with opening selects either the
old or new file; a replacement after the read does not revise that snapshot.
Existing sessions and snapshots are not immediately revoked when the file
changes. Administrators must provision and protect the file and use atomic
replacement rather than modifying it in place while it is being read.

The managed builder has three independent timeout policies:

- `timeout`: **30 seconds** by default, measured once per open across resolution,
  TCP dialing, handshake, authentication, channel open and exec. This is the
  establishment budget, not the caller's remaining request deadline.
- `write_inactivity_timeout`: **120 seconds** by default while a reply or retained
  rekey is blocked on socket writes. Positive written bytes reset it; incoming
  control traffic does not. It is not a total request deadline.
- `request_deadline`: **none** by default; when set, bounds connection through
  the response head, including establishment and uploads, but excludes the
  response body. It expires even with continuous progress. Without
  `request_deadline`, a silent peer can leave a request waiting for a response
  head indefinitely; neither of the other timeouts bounds that wait.

Use `Error::transport_timeout_kind()` rather than matching diagnostic words:

| Kind | Meaning | `is_transport_deadline()` |
| --- | --- | --- |
| `TransportTimeoutKind::ManagedSshEstablishment` | Local DNS/dial/handshake/authentication/channel/exec bound | `true` |
| `TransportTimeoutKind::RequestDeadline` | Overall request or response-head deadline, including an explicitly configured `request_deadline` | `true` |
| `TransportTimeoutKind::ManagedSshWriteInactivity` | Established-session write inactivity while a reply or rekey is outstanding | `false` |

Only typed local observations create these markers; arbitrary timeout-like peer
text and operating-system errors do not. Markers survive the worker, HTTP
driver, response-body readers and operation-specific withholding wrappers.
`RawBodyError::Timeout` retains the kind when a caller reads raw response bytes;
converting it to `Error` retains `transport_timeout_kind()`. As with host-key
markers, a caller-supplied stream can propagate an earlier error: a marker does
not prove the current mutation itself timed out.

**Source-compatibility change:** `RawBodyError` is a public exhaustive enum.
Adding its `Timeout` variant can make downstream exhaustive `match` expressions
stop compiling. Callers must update those matches to handle
`RawBodyError::Timeout(kind)` (or deliberately use a catch-all). This is a
source-breaking enum addition, not merely an additive diagnostic.

The known stall pattern is a **bounded failure, not a hang**: a peer that
interleaves control traffic with a blocked write reaches the write-inactivity
bound and the session fails closed. Raising the establishment timeout does not
change that bound. A deadline does not prove a mutation was not processed;
reconcile its outcome before retrying.

The native SSH constructor rejects timeout durations below one second. The managed path limits a
known-hosts file to 4 MiB, an identity file to 1 MiB, and OpenSSH bcrypt to
128 rounds; RSA component magnitudes are limited to 8192 bits each by the SSH
identity parser. Excessive bcrypt rounds are refused before KDF work; oversized
RSA components are refused before integer conversion and RSA validation, after
decryption when necessary. Filesystem syscalls can still block indefinitely: a
capacity-limited registry owns stalled workers, and saturation refuses new
work. Cancellation cannot retract an operation already committed.

Native `ssh` remains a separate, explicit choice under the invoking user's
OpenSSH policy. Managed failures never silently downgrade to it. The
hermetic native-policy and managed fail-closed tests are in `tests/ssh_policy.rs`
and `tests/managed_ssh_fail_closed.rs`. The opt-in real-server lane in
`tests/ssh_dial_stdio.rs` keeps the eight `managed_` scenarios ignored and opt-in:
they require provisioned host trust and a real peer and are not part of the
default gate. Opening the managed gate is not a claim that those scenarios
passed. **Password authentication over managed SSH is unverified against a real
server.** The internal fixture mounts the Docker socket, so running it grants
daemon-level power; that is why it is not exercised by the default gate.
The native live-lane command still excludes managed scenarios. An operator who
has provisioned trust on a disposable host can explicitly select them with
`--test ssh_dial_stdio managed_ -- --include-ignored --test-threads=1` through
the reviewed wrapper. The lane requires the disposable Docker SSH
fixture and runs only through `eng/ci/with-private-account-db.sh`. That helper is
privileged checkout code; review the exact revision before running it. It
creates a root-owned workspace after sudo and gives the disposable account its
own account databases, `/tmp`, and PID namespace. Invoking the ignored tests
directly would write that account into the host databases. Excluding the
managed scenarios is not managed interoperability coverage.

Registry credentials are supplied through a caller-owned
`RegistryCredentialProvider` or an explicit `RegistryCredentials` value; the
client does not read or persist Docker credential configuration implicitly.
Secret values are redacted and zeroized when owned by this facade. The
optional `DockerCredentialHelper` adapter executes only validated
`docker-credential-*` names without a shell and bounds its output and
lifetime.

The system facade exposes `version`, `version_value`, `info`, `disk_usage`,
`events`, and the native `prune_build_cache` operation. `version` and
`version_value` use the owned transport's versioned
`GET /v<owned>/version`. An unavailable target or rejected request fails without
retry. The owned document keeps members the repository
model does not name, while the five selected fields project identically, and a
known member with the wrong JSON type or a duplicate known member is still a
decode failure. `DiskUsageOptions` and `EventOptions` preserve the Engine query
shape, including repeated `type` parameters and JSON-encoded filters.
`EventStream` owns the response body; call `next()` while consuming it and call
`cancel()` (or drop the handle) to release/cancel the response.

No Engine API version through v1.55 defines a daemon-wide `/system/prune`
endpoint, and
Bollard 0.21.1 does not expose one. This crate deliberately does not compose
container, image, network, and volume prune calls under a misleading system
method. Those resource-specific operations remain part of RD-003d, while
`prune_build_cache` maps only to Docker's `/build/prune` endpoint. Verbose
disk-usage entries are projected into repository-owned types; daemon-specific
nested fields are intentionally omitted.

`ContextArchiveStore` imports and exports Docker's root-level `meta.json` and
`tls/<endpoint>/<file>` archive layout. TAR export is deterministic; TAR and
ZIP import are both supported. The default limits bound entry count, individual
and total uncompressed size, physical container size, path length, and ZIP
compression ratio. `ContextArchiveLimits` can tighten those bounds for an
application.

```rust,no_run
use std::fs::File;
use neotales_docker::ContextArchiveStore;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let store = ContextArchiveStore::from_environment()?;
let mut archive = File::open("remote.dockercontext")?;
store.import("copied", &mut archive)?;
# Ok(())
# }
```

Import validates the complete entry table before extraction, rejects unsafe
paths, duplicates, links, and special entries, stages below the Docker
configuration root, and publishes metadata last. Existing unrelated Docker
configuration is untouched, TLS private keys are mode `0600` on Unix, and
path-based export uses a synced sibling temporary file followed by an atomic
rename. Explicit plain-HTTP and HTTPS proxy routing is implemented; the
remaining WebSocket/h2c proxy gap is tracked as later RD-002 work.

## The owned raw backend (`raw`)

`neotales-docker::raw` provides the repository-owned Engine transport used
by the public facade. It sends versioned requests and exposes lower-level
operations for callers that need them. The previous generated client had a
version-prefix defect; that comparison is historical.

```rust,no_run
use neotales_docker::raw::{
    RawEngine, RawTarget, container_create, container_list, container_start, info, ping, version,
};
use neotales_docker::{ContainerCreateOptions, ContainerListOptions, ContainerStartOptions};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let engine = RawEngine::new(
    RawTarget::Unix("/var/run/docker.sock".into()),
    neotales_docker::API_VERSION,
);

// `/_ping` carries its answer in headers, so the owned client returns them
// typed instead of collapsing five capabilities into one string.
let capabilities = ping(&engine).await?;
println!("daemon API {:?}, swarm {:?}", capabilities.api_version, capabilities.swarm);

// Versioned paths: the daemon receives `/v1.55/info`, not `/info` -- the
// version is `API_VERSION`, so this line moves when the ceiling does.
let daemon = info(&engine).await?;
let _version = version(&engine).await?;

// The container lifecycle speaks the same versioned paths and decodes into the
// repository-owned models rather than generated ones.
let containers =
    container_list(&engine, &ContainerListOptions { all: true, ..Default::default() }).await?;
println!("{} containers", containers.len());
let created = container_create(&engine, &ContainerCreateOptions {
    image: "alpine:3.19".into(),
    name: Some("slice".into()),
    ..Default::default()
}).await?;
container_start(&engine, &created.id, &ContainerStartOptions::default()).await?;
# Ok(())
# }
```

## What the backend covers

Two vertical slices, matching the first two steps of the migration order in the
decision record:

| Operation | Request |
| --- | --- |
| `ping` | `GET /v{major}.{minor}/_ping`, answer read from the capability headers |
| `version` | `GET /v{major}.{minor}/version` |
| `info` | `GET /v{major}.{minor}/info` |
| `list` | `GET /v{major}.{minor}/containers/json?all=…&size=…&filters=…` |
| `create` | `POST /v{major}.{minor}/containers/create?name=…` with a JSON body |
| `start` | `POST /v{major}.{minor}/containers/{id}/start` |
| `stop` | `POST /v{major}.{minor}/containers/{id}/stop?signal=…&t=…` |
| `remove` | `DELETE /v{major}.{minor}/containers/{id}?v=…&force=…&link=…` |
| `wait` | `POST /v{major}.{minor}/containers/{id}/wait?condition=…` |
| `checkpoint create` | `POST /v{major}.{minor}/containers/{id}/checkpoints` with a JSON body |
| `checkpoint list` | `GET /v{major}.{minor}/containers/{id}/checkpoints?dir=…` |
| `checkpoint remove` | `DELETE /v{major}.{minor}/containers/{id}/checkpoints/{checkpoint}?dir=…` |

### Container checkpoints

`create_checkpoint`, `list_checkpoints`, and `remove_checkpoint` use the
owned transport. An unavailable target fails without a generated fallback. The three routes are the daemon's experimental checkpoint router,
which is not part of the Engine's `OpenAPI` document, so the shape below is the one
the daemon reads rather than one generated from a schema:

| Operation | Request | Success |
| --- | --- | --- |
| create | `POST /v{major}.{minor}/containers/{id}/checkpoints` with `CheckpointID`, optional `CheckpointDir`, and `Exit` in the body | `201` |
| list | `GET /v{major}.{minor}/containers/{id}/checkpoints?dir=…` | `200` with a `Name` array |
| remove | `DELETE /v{major}.{minor}/containers/{id}/checkpoints/{checkpoint}?dir=…` | `204` |

`checkpoint_dir` is optional, and absent and empty both select the container's
configured checkpoint directory. The owned path omits the member or the `dir`
query value in both cases rather than sending it empty; the former generated fallback
sent `CheckpointDir:""` and `dir=` for an empty value, which the daemon reads
the same way. A `null` list answer from an older daemon and an empty array both
project to an empty vector; an entry without a string `Name` is a decode failure.
The container reference and the checkpoint identifier are each percent-encoded
into one path segment, and an empty one is refused as `ErrorKind::InvalidInput`
before a connection is opened — an empty identifier would otherwise spell the
list route. The former generated fallback escaped neither and passed an empty identifier
through.

Creation uses the unbounded send because a checkpoint dump can outlast the
transport's response-head budget; as with `wait`, `stop`, and `restart`, the
daemon's own work governs how long the answer takes on a Unix socket, direct
plain HTTP, SSH, and a caller-supplied stream. The plain-HTTP forward-proxy route
applies one 120-second overall request budget covering the proxy connect,
request-body production/backpressure, and the response head, and that budget
applies even to the unbounded send; HTTPS keeps its establishment budget and has
no response-head deadline for this call. A budget expiry or a dropped future
leaves the outcome unknown: the daemon may already have created the checkpoint.

A `list_checkpoints` answer is a snapshot, not a retry proof. A create or remove
that was dispatched and then lost may still be in flight, so the list cannot show
that it settled, and a retry is only safe under coordination outside this API —
for example one owner serializing checkpoint operations and a record that the
request settled. A container removed and recreated under the same name is a
different container to a name-based list, and it may own different checkpoints; a
create retried in that window can create one on the new container, and a remove
retried can delete one it owns. None of the three operations retries: a failed
owned request is returned rather than re-issued over the generated client.

Release treatment: **not simply additive.** The public surface is unchanged —
the three methods, their option and result types, and the daemon-error projection
keep their signatures — but behavior on an endpoint the owned transport reaches
differs from the former generated path in the historical comparison below:

| Difference | Owned route | Former generated fallback |
| --- | --- | --- |
| Request line | versioned `/v1.NN/…` | unversioned |
| Older daemon | a daemon older than the client's configured version can reject the versioned path as too new; the rejection is returned, not retried over the fallback | the unversioned path was accepted at the daemon's own maximum |
| Malformed list answer | `ErrorKind::InvalidInput`, content-free | `ErrorKind::Docker` |
| Empty reference or identifier | refused locally before connecting | passed through to the daemon |
| Create timing | no response-head deadline on direct, SSH, and stream targets; HTTPS establishment only; the plain-HTTP proxy route keeps its 120-second overall budget | Bollard's single 120-second request timeout on every route |
| Empty `checkpoint_dir` | omitted | `CheckpointDir:""` or `dir=`, which the daemon reads identically |

All but the last are observable behavior changes, not additions: a caller that
relied on the generated client's 120-second timeout, its error class for a
malformed answer, or its acceptance of an empty reference will see different
behavior on a reachable endpoint. The crate version is not changed here; whether
this ships as a patch or a minor, and what migration note it needs, is a release
decision still pending.

The `exit` default is the same on the owned route — `false`, which leaves the
container running — and it is not the Docker CLI's default: `checkpoint create`
stops the container unless `--leave-running` is given. A caller porting CLI
behavior must set `exit: true`.

The daemon registers the routes as experimental. A daemon without experimental
features does not serve them, and a runtime that cannot checkpoint reports the
operation as not implemented; both arrive as the daemon's own status and message
in `Error::api_error`, so a `501` is returned rather than replaced with a local
guess. Checkpoint creation needs CRIU on Linux. The routes have existed since
Engine API v1.25, and their request and response shape has not changed since;
what differs between daemons is whether the router is registered, which is a
daemon configuration fact rather than an API version one. The loopback suites in
`tests/container_checkpoints.rs` and
the former `tests/container_checkpoints_fallback.rs` pinned the exact request lines, the body
and query encodings, the status and error projection, malformed list handling,
cancellation, and the no-retry rule. Neither suite starts a daemon, so no live
checkpoint claim is made.

### Exec sessions

`raw::exec_start` keeps its documented behaviour: it reports the daemon's status
and whether the caller asked to detach, and drops an attached response, which
closes the connection and discards the output.

`raw::exec_start_session` is the additive route for a caller that wants the
session. It sends the same `POST /v{major}.{minor}/exec/{id}/start` body with
`Connection: Upgrade` and `Upgrade: tcp`, and returns `ExecSession` only when the
daemon answers `101`. `ExecSession` owns the split socket;
`into_connection()` hands both halves to the caller. Dropping both halves closes
the socket, which the daemon observes as the session ending; it is not a request
to stop the process, and the exit status comes from `exec_inspect`.

The framing is the caller's. With `tty: false` the daemon multiplexes **stdout
and stderr only** in the same eight-byte frames as `logs`; standard input is
raw in both modes and is written without a frame header (`raw::LogDecoder`
decodes output but does not write input). With `tty: true` both directions are
raw bytes with no headers. The session does not decode, buffer, or validate
either direction.

A dispatched start is not retractable. Dropping the future or the session stops
this client from receiving the result, but the daemon may already have started
the exec, or may not have processed the request yet, so the outcome is unknown
rather than "not started". `exec_inspect` can inform reconciliation, but it
cannot prove a retry is safe: a "not running" answer can still be followed by
the earlier start. The start endpoint is not a safe retry for an exec whose
state is unknown. A `200` refusal has the same consequence: the daemon accepted
the start and may already be running the command, and dropping the response does
not undo it.

A daemon that answers `200` instead of `101` has not given this transport a
writable connection: the `200` body is readable but the socket is not. The
session API reports that as `ErrorKind::Transport` and drops the response. That
is a transport limitation, not an Engine one. The loopback fixture in
`tests/exec_start_session.rs` pins both answers; no live-daemon claim is made.

The container archive operations (`container_archive_stat`,
`download_container_archive`, and `upload_container_archive`) are the owned
backend's `HEAD`, `GET`, and `PUT
/v{major}.{minor}/containers/{id}/archive`; their wire and stream contracts are
described in [Container archive slice](#container-archive-slice).

The container slice was verified end to end against Docker Engine 29.8.0 over a
Unix socket — create, start, list, stop, wait, remove, a `404` carrying the
daemon's message, and an escaped reference — not only against the fixtures in
`tests/raw_backend_containers.rs`.
Those results were recorded in rust-libraries at 765e715; this pipeline does not start a daemon or re-run that check.

What the slices guarantee, and how each is tested in
`tests/raw_backend_differential.rs` and `tests/raw_backend_containers.rs`:

- **Versioned paths.** `RawEngine::request_uri` prefixes the negotiated version
  and refuses a path that is not absolute rather than guessing at a target.
- **Bounded documents.** `RawResponse::document` refuses to buffer past
  `MAX_DOCUMENT_BYTES`, enforced per chunk rather than from `Content-Length`,
  since a streaming or dishonest response does not carry an accurate one.
- **Bounded records and multiplexed log frames.** `FrameStream::next_json` caps
  each assembled record at `MAX_RECORD_BYTES`; container and Swarm multiplexed
  log decoders refuse a declared payload over `MAX_FRAME_BYTES` before buffering
  it. Both defaults are 8 MiB. The log-frame bound applies only to multiplexed
  framing: TTY output has no declared frame length, and the decoder yields it by
  transport read rather than buffering the complete stream.
- **Unbounded streams are never buffered.** `RawResponse::into_frames` yields
  frames as they arrive.
- **Cancellation is ownership.** Dropping the response drops the body, which
  closes the socket so the daemon observes a disconnect, and aborts the driver
  task. No cancel message exists for the two ends to disagree about.
- **Engine errors keep the daemon's words by default.** A non-2xx status becomes
  `ErrorKind::Docker` with the status and message in `Error::api_error`, so
  `--raw-error` still prints what the daemon said. An unparsable error body falls
  back to the status rather than replacing the daemon's answer with a parsing
  complaint.
  Managed SSH always withholds peer failure text as described above;
  authenticated forward-proxy routes also use fixed safe text.
- **Transport failures can happen after dispatch.** `ErrorKind::Transport`
  covers a request that never reached the daemon and a request whose outcome is
  unknown after it was sent: a broken connection, a missing upgrade, or a
  response that could not be read. It is distinct from `ErrorKind::InvalidInput`,
  but it is not a claim that nothing happened. A caller must not retry a
  dispatched mutation solely because the error kind is `Transport`.
- **No silent truncation.** `version` and `info` return the document as sent
  rather than a generated struct, so members this client does not know about are
  not dropped. The container operations project onto the existing
  repository-owned models, which are `snake_case` CLI output types rather than wire
  types; the wire spelling is confined to private `*Document` projections, and
  each is a separate rename because `ImageID`, `DeviceIDs`, `Type`, and
  `StatusCode` are not what a casing rule produces.
- **The container name is a query value.** Docker reads it from `?name=` and
  *silently ignores* a `Name` member in the create body: a create request
  carrying `"Name":"probey"` in the body answers
  `{"Id":...,"Warnings":[]}` for a container under a generated name, verified
  against Docker Engine 29.8.0. A name in the body is a container the caller
  cannot find again.
- **A `204` is a success, not an empty document.** `start`, `stop`, and `remove`
  answer `204` with no body. The body is read and discarded and never handed to
  a JSON decoder, so a successful lifecycle call is not reported as a parse
  failure.
- **A container reference stays inside one path segment.** `/` is a path
  separator, so an unescaped reference would silently address a different
  resource: `POST /containers/a/b/start` is a four-segment path. Every reference
  is percent-encoded into exactly one segment, `%` included, so a reference
  cannot smuggle an escape sequence either. An empty reference is refused before
  a connection is opened. This is a difference from Bollard `0.21.1`, which
  formats the path with `format!("/containers/{id}/start")` and escapes nothing.
- **The recorded request is reproducible.** `filters` is built from the ordered
  `BTreeMap` the repository model already uses, so the key order of the encoded
  JSON is the same on every run. The current dependency converts that map into a
  `HashMap` before serializing it, so its `filters` key order varies between
  runs of the same command.
- **A create member is validated, not forwarded.** A restart-policy name outside
  the Engine's `""`/`no`/`always`/`unless-stopped`/`on-failure` set, and a umask
  that is not octal, are refused as `ErrorKind::InvalidInput` rather than
  forwarded for the daemon to reject with a `400`.

One constraint is load-bearing and documented on `RawEngine::send`: **the
response body must be read on the runtime that made the call**, or on a task of
it. hyper's HTTP/1 client only reads the socket while its connection future is
being polled, and that future runs as a task on the calling runtime. An earlier
revision tried to own the connection inline to avoid this; it deadlocked on
`send_request` and then raced hyper's internals. The constraint is documented
rather than hidden.

## Historical comparison with the former generated facade

Recorded here rather than in a comment, because the two paths differ on the wire
for three members and a difference that is not written down reads as a bug:

| Member | Facade | Owned backend | Why |
| --- | --- | --- | --- |
| `HostConfig.Umask` | `"Umask": 18` (a number) | `"Umask": 18` (a number) | The Engine declares `uint32`, and `ContainerHostConfig::umask` carries the octal spelling a person writes (`0022`), so both paths convert it. The facade used to install a JSON string, which Docker Engine 29.8.0 rejects with `400 invalid JSON: json: cannot unmarshal string into Go struct field HostConfig.HostConfig.Umask of type uint32` — a create carrying a umask could not succeed. Found by running the real code against a real daemon and **fixed**; a non-octal umask is now rejected locally as `InvalidInput` instead of becoming a `400` about JSON types. |
| `platform` | always sent, defaulting to `platform=` | sent only when the caller set one | An unrequested parameter on every create request. The recorded create line is `POST /containers/create?name=web&platform=` through the facade and `POST /v1.55/containers/create?name=web` through the owned backend. |
| Container reference | interpolated into the path unescaped | percent-encoded into one segment | A reference containing `/` addresses a different path shape through the facade. |

The table above is the first container slice, not the whole backend. TLS, SSH,
and streaming request bodies are implemented through the same transport: the
facade's HTTPS constructors build a `RawTarget::Stream` that opens a fresh TCP
connection, an optional explicit HTTP `CONNECT` tunnel, and a TLS handshake per
request; SSH is the same `Stream` shape over `docker system dial-stdio`; and
image build/load/import send `RawBody::Stream` request bodies. `RawTarget::Tcp`
itself remains plaintext, and a caller that builds it directly gets plain TCP.
The HTTPS target has two separate budgets: one for establishment (TCP, CONNECT,
TLS), and a 120-second response-head budget for the owned transport. The value is
the same 120 seconds the former generated client used for its single request timeout,
but the shape is not the same: establishment and the response head are bounded
separately. The plain-HTTP forward-proxy route applies one 120-second overall
request budget covering the proxy TCP connect, request-body
production/backpressure, and the response head. That is the same shape as the
generated client's single request timeout for the same endpoint, and it also
applies to `wait`, `stop`, and `restart` on that route. It does not wrap the
response body. Unix sockets, named pipes, direct plain HTTP, SSH, and
caller-supplied streams keep the existing unbounded response-head behavior. For
a non-proxy response-head deadline, the clock starts when the request body has
been fully polled by hyper, not when the daemon has confirmed delivery. A
producer that stalls before that point is not bounded by the head clock; on the
proxy route the overall budget still bounds it. Socket backpressure can still let
a head deadline fire after the producer completes, because the signal is producer
completion, not delivery; this is a known limitation, not a hard
upload-delivery bound, and a saturated kernel socket was not used to prove it.
The deadline ends at the response head, not the response body. `wait`, `stop`, and
`restart` use the unbounded send on direct and HTTPS routes because their
contract is a daemon-governed wait; on a proxied endpoint the overall budget
still applies. A timeout or cancellation means the outcome is unknown — the
daemon may already have processed the request — so reconcile state before
retrying. A timed-out proxied request has the same unknown outcome: the proxy may
already have forwarded it. A caller-supplied `StreamFactory` owns its own
establishment deadline. TLS material failures keep
`ErrorKind::Proxy` and expose a `TlsConfigError` source with the failed role and a
content-free reason. This is an observable change from the pre-slice behavior:
the proxied route previously exposed `ProxyError::TlsConfiguration` as the
source, and the direct route previously exposed Bollard's `ErrorKind::Docker`.
Source downcasts for TLS material failures must now target `TlsConfigError`.
`ProxyError` and `ErrorKind` are unchanged; `ProxyError::TlsConfiguration`
remains for compatibility but is not emitted for CA, certificate, or key
failures. Release/version treatment of this change is pending. See the `raw`
module documentation for the current operation surface and the decision record
for the migration order.

### Explicit plain-HTTP forward proxy

A client built with `ProxyPolicy::Http` for an `http://` or `tcp://` endpoint now
uses the owned transport for the operations that prefer it. The owned route
dials the configured proxy and writes an absolute-form request target containing
the daemon's authority; `Host` names the same daemon. The configured
`Proxy-Authorization` value is added only on that leg. A caller-supplied
`Proxy-Authorization` is rejected on the configured route rather than being
silently dropped or sent beside the configured credential; on a direct target or
a caller-supplied `RawTarget::Stream`, the header is forwarded unchanged so an
existing custom transport can keep authenticating to its own proxy. A
caller-supplied `Host` is suppressed on the configured route in favor of the
daemon authority; direct and custom targets keep forwarding it.

This is the migration from the generated proxy path: the request shape changes
from the generated client's unversioned absolute-form request to the owned
transport's versioned absolute-form request, and the single overall request
budget is applied by the owned transport rather than by Bollard's request
timeout. The proxy is never selected from `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
`NO_PROXY`, or another environment variable. A proxy that cannot be reached is
an error, not a direct connection. A proxy `407` is surfaced through the same
non-2xx error channel as an Engine rejection, with its HTTP status preserved and
no retry. On an authenticated proxy route the response text is withheld entirely
and replaced with fixed safe text: a malicious proxy can echo the configured
credential in an arbitrary encoding, so no part of its message is trusted.
Unauthenticated proxy routes preserve the response message because there is no
configured credential to echo. The explicit raw response headers and body remain
caller-visible, and `RawResponse` `Debug` withholds proxy-controlled header names
and values; a caller that reads those fields directly can still observe a
malicious proxy's echo. Successful response values — including `Ping`'s
header-derived fields, image progress records, and raw documents — are also
returned as caller-visible data and are not sanitized. This withholding applies to the owned proxy route; there is no generated
fallback. On an authenticated proxy route, in-band Docker failures from build/load/import are
`Error::engine_api(200, fixed safe text)` with `api_error` status `200`; the
source is the fixed `DockerApiError`, not the daemon `StreamError`. Typed
response decode failures report a content-free category, line, and column;
serde's own message is not used because it can quote the wrong-typed value.
HTTPS keeps its `CONNECT` tunnel.
WebSocket and h2c upgrades remain outside this transport.

## Per-request duplex factory

`RawTarget::Stream` carries a `StreamFactory` that is called once per request.
`RawEngine::send` opens a fresh duplex, and `exchange` runs a fresh hyper
HTTP/1.1 handshake over it. The SSH and HTTPS paths use it, and its contract is
documented on `StreamFactory`. A target that held one duplex would serve one
request and fail on the second, which is why the variant holds a factory.

### Config and secret mutation transport migration

Config and secret create, update and remove now use only the versioned owned
transport, including the already captured local endpoint; an unavailable owned
endpoint fails closed instead of using Bollard. There is no retry. A daemon that
only accepts an older API version can reject the new requests. The reference is
escaped as one path segment and empty references are refused. Rejection status
is retained but peer text and transport sources are withheld, including for raw
writers; an observed deadline marker does not prove this mutation timed out, so
reconcile its outcome before retrying. Config update now refuses reserved or
non-ASCII additional keys before dispatch. Both update projections retain the
previous facade's generated-model behavior, including config Data and secret
Driver; the raw writers previously omitted these. These are compatibility
changes that need an alpha release note.

Capture-once is structural: `connect_local` reads the environment once, and
the owned engines consume the captured owned target. The stability test
checks that stored target after a later modelled read; it does not change the
environment after construction, because `std::env::set_var` is unsafe in Rust
2024 and the workspace forbids unsafe code. The six-write local test separately
proves route reuse against the captured socket.

### Task read compatibility

Task list, inspect, and logs use the owned, versioned transport, including the
endpoint captured by `connect_local`; unavailable targets fail closed and
failures are not retried. Task reads reject a top-level `Image`, including null,
because `image` is a synthetic view of `Spec.ContainerSpec.Image`.

`SwarmTask::spec` is the sole authority for serialized `Spec`. The
`additional["Spec"]` entry is a read-time compatibility snapshot, and changes
or removal of that mirror no longer affect serialization. This changes behavior
for callers that previously mutated the mirror. Setting `spec` to `None`
removes `Spec`. Unmodelled `Spec` members survive only inside a non-null `Spec`;
owned reads retain unmodelled top-level members in `additional`. The
representation is not byte-for-byte JSON fidelity. Owned reads preserve status
on rejected requests (including 101 and 304); direct peer rejection messages
are retained while authenticated proxy rejection text is withheld.
