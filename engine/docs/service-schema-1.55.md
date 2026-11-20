# Service request schema inventory

The create/update validator's structured-field inventory is based on Moby Engine
1.55 at commit `70eaf5ef6f274623ddcca8eb634ccf7cba15cbc5`. See
[`moby-service-schema-1.55.md`](moby-service-schema-1.55.md) for the transitive
field/map/array inventory and primary source links.
The validator descends recognized objects and arrays, permits arbitrary keys only
at declared map fields (`ServiceSpec.Labels`, `ContainerSpec.Labels`,
`ContainerSpec.Sysctls`, `VolumeOptions.Labels`, `NetworkAttachmentConfig.DriverOpts`,
`Driver.Options`, and `MountDriver.Options`), and refuses unknown structured
values. Scalar unknown members remain allowed for forward compatibility. Runtime and future daemon schemas are not guaranteed:
this is a manually researched 1.55 boundary, not an exhaustive guarantee for
later daemon releases.
