# Moby Engine 1.55 service JSON decoding boundary

Scope: Moby Engine API 1.55 at commit [`70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5`](https://github.com/moby/moby/tree/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5). This is the JSON decoding boundary, not swarm's subsequent semantic validation. Both handlers decode the same `serviceWithLegacy` value. API 1.55 is confirmed by the commit's [Swagger source](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/swagger.yaml) and [daemon configuration](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/daemon/config/config.go).

The inventory below covers the transitively reachable declared fields traced in pinned source. It has **not been mechanically checked against a compiled type graph**, so treat exhaustiveness as high-confidence manual research, not verified by execution.

## Inventory notation

- `T?` means Go `*T`; `[T]` means Go slice; `map<string,T>` is an actual Go map and **must allow arbitrary keys**, not a fixed-field object.
- `str`, `bool`, `i64`, `u32`, `u64`, `f32`, `int`, `u32mode` denote Go types. `int` is architecture-dependent; `u32mode` is `os.FileMode`, underlying `uint32`. `duration` is `time.Duration`, underlying `int64`.
- Fields are JSON names, case-sensitive spellings shown. Except the explicit lowercase `RuntimeSpec` and `RuntimePrivilege` names below, names equal exported Go field names. `omitempty` and `omitzero` are encoding options, not decoding restrictions. No reachable field uses `,string`.
- `[]byte` is special: JSON base64 string **or** an array of byte numbers, in addition to `null`.
- `null` is accepted for ordinary values: it clears pointers, maps and slices; for non-pointer primitives and structs it has no effect. See custom text type exception notes below.

```text
serviceWithLegacy = {
  Name: str, Labels: map<string,str>,                      # embedded Annotations
  TaskTemplate: TaskSpec, Mode: ServiceMode,
  UpdateConfig: UpdateConfig?, RollbackConfig: UpdateConfig?,
  EndpointSpec: EndpointSpec?, Networks: [NetworkAttachmentConfig]
}

ServiceMode = {
  Replicated: ReplicatedService?, Global: Empty?,
  ReplicatedJob: ReplicatedJob?, GlobalJob: Empty?
}
ReplicatedService = { Replicas: u64? }
ReplicatedJob = { MaxConcurrent: u64?, TotalCompletions: u64? }
Empty = {}

UpdateConfig = {
  Parallelism: u64, Delay: duration, FailureAction: str,
  Monitor: duration, MaxFailureRatio: f32, Order: str
}

EndpointSpec = { Mode: str, Ports: [PortConfig] }
PortConfig = {
  Name: str, Protocol: str, TargetPort: u32,
  PublishedPort: u32, PublishMode: str
}

TaskSpec = {
  ContainerSpec: ContainerSpec?, PluginSpec: RuntimeSpec?,
  NetworkAttachmentSpec: NetworkAttachmentSpec?,
  Resources: ResourceRequirements?, RestartPolicy: RestartPolicy?,
  Placement: Placement?, Networks: [NetworkAttachmentConfig],
  LogDriver: Driver?, ForceUpdate: u64, Runtime: str
}
NetworkAttachmentSpec = { ContainerID: str }
RuntimeSpec = {
  name: str, remote: str, privileges: [RuntimePrivilege?],
  disabled: bool, env: [str]
}
RuntimePrivilege = { name: str, description: str, value: [str] }
NetworkAttachmentConfig = {
  Target: str, Aliases: [str], DriverOpts: map<string,str>
}
Driver = { Name: str, Options: map<string,str> }

ResourceRequirements = {
  Limits: Limit?, Reservations: Resources?,
  SwapBytes: i64?, MemorySwappiness: i64?
}
Limit = { NanoCPUs: i64, MemoryBytes: i64, Pids: i64 }
Resources = { NanoCPUs: i64, MemoryBytes: i64, GenericResources: [GenericResource] }
GenericResource = {
  NamedResourceSpec: NamedGenericResource?,
  DiscreteResourceSpec: DiscreteGenericResource?
}
NamedGenericResource = { Kind: str, Value: str }
DiscreteGenericResource = { Kind: str, Value: i64 }

RestartPolicy = { Condition: str, Delay: duration?, MaxAttempts: u64?, Window: duration? }
Placement = {
  Constraints: [str], Preferences: [PlacementPreference],
  MaxReplicas: u64, Platforms: [Platform]
}
PlacementPreference = { Spread: SpreadOver? }
SpreadOver = { SpreadDescriptor: str }
Platform = { Architecture: str, OS: str }

ContainerSpec = {
  Image: str, Labels: map<string,str>, Command: [str], Args: [str],
  Hostname: str, Env: [str], Dir: str, User: str, Groups: [str],
  Privileges: Privileges?, Init: bool?, StopSignal: str, TTY: bool,
  OpenStdin: bool, ReadOnly: bool, Mounts: [Mount],
  StopGracePeriod: duration?, Healthcheck: HealthcheckConfig?,
  Hosts: [str], DNSConfig: DNSConfig?, Secrets: [SecretReference?],
  Configs: [ConfigReference?], Isolation: str, Sysctls: map<string,str>,
  CapabilityAdd: [str], CapabilityDrop: [str], Ulimits: [Ulimit?],
  OomScoreAdj: i64
}
Privileges = {
  CredentialSpec: CredentialSpec?, SELinuxContext: SELinuxContext?,
  Seccomp: SeccompOpts?, AppArmor: AppArmorOpts?, NoNewPrivileges: bool
}
CredentialSpec = { Config: str, File: str, Registry: str }
SELinuxContext = { Disable: bool, User: str, Role: str, Type: str, Level: str }
SeccompOpts = { Mode: str, Profile: bytes }
AppArmorOpts = { Mode: str }

DNSConfig = { Nameservers: [netip.Addr], Search: [str], Options: [str] }
HealthcheckConfig = {
  Test: [str], Interval: duration, Timeout: duration,
  StartPeriod: duration, StartInterval: duration, Retries: int
}
Ulimit = { Name: str, Hard: i64, Soft: i64 }

SecretReference = { File: SecretReferenceFileTarget?, SecretID: str, SecretName: str }
SecretReferenceFileTarget = { Name: str, UID: str, GID: str, Mode: u32mode }
ConfigReference = { File: ConfigReferenceFileTarget?, Runtime: Empty?, ConfigID: str, ConfigName: str }
ConfigReferenceFileTarget = { Name: str, UID: str, GID: str, Mode: u32mode }

Mount = {
  Type: str, Source: str, Target: str, ReadOnly: bool, Consistency: str,
  BindOptions: BindOptions?, VolumeOptions: VolumeOptions?,
  ImageOptions: ImageOptions?, TmpfsOptions: TmpfsOptions?,
  ClusterOptions: Empty?
}
BindOptions = {
  Propagation: str, NonRecursive: bool, CreateMountpoint: bool,
  ReadOnlyNonRecursive: bool, ReadOnlyForceRecursive: bool
}
VolumeOptions = {
  NoCopy: bool, Labels: map<string,str>, Subpath: str, DriverConfig: MountDriver?
}
MountDriver = { Name: str, Options: map<string,str> }
ImageOptions = { Subpath: str }
TmpfsOptions = { SizeBytes: i64, Mode: u32mode, Options: [[str]] }
```

`serviceWithLegacy` embeds `ServiceSpec`, which embeds `Annotations`; `Name` and `Labels` therefore occur at the **root**, not inside wrapper objects. Both root `Networks` and `TaskTemplate.Networks` are decoded regardless of whether later API-version adjustment uses the legacy field.

## Decoder behavior needed by the Rust validator

1. [Pinned handler source](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/daemon/server/router/swarm/cluster_routes.go) calls [`httputils.ReadJSON`](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/daemon/server/httputils/httputils.go). It checks content type, accepts a nil body or `ContentLength == 0` without decoding, otherwise uses a standard `json.Decoder`, then checks `dec.More()`. Reproduce that code rather than assuming a generic “exactly one JSON document” policy; every trailing-token edge case was not tested.
2. Struct field lookup prefers an exact name, then a case-insensitive match. Unknown struct fields are ignored; values of actual maps are still type-checked, with arbitrary string keys. Duplicate members are processed in input order and can replace **or merge** earlier values. Preserve duplicate members if parity matters.
3. Named string types such as protocol, mode and failure action are **strings at decode time**, not decoder-enforced enums. JSON integers must fit their Go widths; `f32` must fit float32; duration values are numeric integers in nanoseconds. Semantic constraints come later.
4. The reachable custom text decoder is `netip.Addr` in `DNSConfig.Nameservers`: JSON strings go through `UnmarshalText`, which accepts the empty string as the zero address and otherwise uses `ParseAddr`; malformed address strings fail. Non-string, non-null inputs fail. For a non-pointer element, `null` is a no-op. Pinned standard-library implementation: [Go 1.26.4 `netip.go`](https://github.com/golang/go/blob/go1.26.4/src/net/netip/netip.go).
5. The pinned swarm, mount, container and relevant vendored dependency source were searched for `UnmarshalJSON` and `UnmarshalText`; no other reachable custom method was found. `HealthConfig` aliases the vendored `HealthcheckConfig`; `Ulimit` aliases vendored `go-units.Ulimit`. This is a source search, **not** a compiled method-set proof.
6. Go's [1.26.4 JSON decoder source](https://github.com/golang/go/blob/go1.26.4/src/encoding/json/decode.go) specifies replacement of invalid UTF-8 and invalid UTF-16 surrogate pairs with U+FFFD. Its [fold implementation](https://github.com/golang/go/blob/go1.26.4/src/encoding/json/fold.go) uses Unicode `SimpleFold`, not ASCII-only lowercasing. A Rust approximation must be explicitly bounded or tested against the actual daemon's Go toolchain and Unicode tables.

## Primary type sources

All are source files at the pinned Moby commit:

- [Service types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/service.go), [common/annotations](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/common.go), [task types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/task.go).
- [Container types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/container.go), [network types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/network.go), [runtime types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/runtime.go), [platform](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/node.go).
- [Config references](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/config.go), [secret references](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/swarm/secret.go), [mount types](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/api/types/mount/mount.go).
- Vendored primary dependency source: [health check](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/vendor/github.com/moby/docker-image-spec/specs-go/v1/image.go), [ulimit](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/vendor/github.com/docker/go-units/ulimit.go).

## Uncertainty and prototype

- The pinned [Dockerfile](https://github.com/moby/moby/blob/70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5/Dockerfile) defaults to Go **1.26.4**, but that does not establish the Go version or build experiments of every deployed daemon. The root module's `go` directive is a minimum, not proof of the binary's compiler. Unicode folding, `int` width and experimental JSON builds need target-specific confirmation.
- No unresolved **declared field types** were identified in the manual traversal; completeness and method sets remain unverified mechanically. Later swarm validation and API versions other than 1.55 are outside this inventory.
- **Prototype:** none. The actionable artifact is the table above; no daemon was run and no project worktree was edited. A useful follow-up is a throwaway reflection-based type/method-set walk and differential tests against a binary built with the target Go version.
