//! `GET /services/{id}` documents shared by the owned and fallback routing
//! suites.
//!
//! Both suites must send the *same* recorded answer through both transports, or
//! a difference in their results would be a difference in the fixture rather
//! than in the code.
//!
//! # The shape is the Engine's, not a convenient one
//!
//! The document nests the specification the way a daemon reports it: `Placement`
//! and `RestartPolicy` are members of **`Spec.TaskTemplate`**, not of `Spec`.
//! Putting them at the spec root would exercise a document no daemon sends and
//! would measure a conversion path that never runs — which is how an earlier
//! version of this suite came to claim the generated update dropped them. The
//! Engine's `ServiceSpec` has eight members (`Name`, `Labels`, `TaskTemplate`,
//! `Mode`, `UpdateConfig`, `RollbackConfig`, `Networks`, `EndpointSpec`), and
//! `TaskSpec` is where the placement and the restart policy live.
//!
//! The document also carries an unmodelled member at each depth, because the
//! transports disagree exactly there: the owned path decodes the daemon's JSON
//! and keeps it verbatim, while the generated path decodes into Bollard's 1.53
//! models, which have no catch-all.
//!
//! | Member | Owned | Generated |
//! | --- | --- | --- |
//! | `TaskTemplate.UnmodelledTaskMember` | kept verbatim | dropped |
//! | `TaskTemplate.ContainerSpec.UnmodelledContainerMember` | kept verbatim | dropped |
//! | `TaskTemplate.Resources.Limits.UnmodelledLimitMember` | kept verbatim | dropped |
//! | `Spec.UnmodelledSpecMember` | kept in `ServiceSpec::additional` | dropped |
//! | `Endpoint` (whole) | kept in `SwarmService::additional` | removed by `service_from_bollard` |
//! | `PreviousSpec` | kept in `SwarmService::additional` | dropped |
//! | `UpdateStatus` | kept in `SwarmService::additional` | kept (Bollard names it) |
//! | `UnmodelledMember` (service level) | kept in `SwarmService::additional` | dropped |

// Two test binaries include this module and each uses a subset of the entries,
// so an entry one of them does not read is not dead code.
#![allow(dead_code)]

/// The service ID every document in this module inspects.
pub(super) const SERVICE_ID: &str = "service0123456789abcdef";

/// The version index the daemon reports and the update must echo.
pub(super) const VERSION_INDEX: u64 = 7;

/// A value that must never appear in a decode error's rendering.
///
/// It is not a credential; it is placed inside a member whose declared type is
/// an object, so a decode failure would quote it if the error echoed response
/// text.
pub(super) const CANARY: &str = "canary-not-a-credential-6f1c";

/// A complete service document in the shape a Docker Engine reports.
pub(super) const SERVICE_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "web",
    "Labels": {"org.example.service": "fixture"},
    "TaskTemplate": {
      "ContainerSpec": {
        "Image": "nginx:alpine",
        "Command": ["nginx", "-g", "daemon off;"],
        "UnmodelledContainerMember": {"Nested": true}
      },
      "Resources": {"Limits": {"NanoCPUs": 500000000, "UnmodelledLimitMember": 1}},
      "RestartPolicy": {
        "Condition": "on-failure",
        "Delay": 5000000000,
        "MaxAttempts": 3,
        "Window": 20000000000
      },
      "Placement": {
        "Constraints": ["node.role == worker"],
        "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}],
        "MaxReplicas": 3,
        "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
      },
      "ForceUpdate": 0,
      "UnmodelledTaskMember": {"Value": 1}
    },
    "Mode": {"Replicated": {"Replicas": 3}},
    "Networks": [{"Target": "net0123456789abcdef", "Aliases": ["web"]}],
    "UpdateConfig": {"Parallelism": 2, "FailureAction": "pause"},
    "RollbackConfig": {"Parallelism": 1},
    "EndpointSpec": {
      "Mode": "vip",
      "Ports": [
        {
          "Protocol": "tcp",
          "TargetPort": 80,
          "PublishedPort": 8080,
          "PublishMode": "ingress",
          "Name": "http"
        }
      ]
    },
    "UnmodelledSpecMember": {"Nested": true}
  },
  "PreviousSpec": {
    "Name": "web",
    "TaskTemplate": {"ContainerSpec": {"Image": "nginx:1.25"}},
    "Mode": {"Replicated": {"Replicas": 2}}
  },
  "Endpoint": {
    "Spec": {"Mode": "vip"},
    "Ports": [
      {
        "Protocol": "tcp",
        "TargetPort": 80,
        "PublishedPort": 8080,
        "PublishMode": "ingress",
        "Name": "http"
      }
    ],
    "VirtualIPs": [{"NetworkID": "net0123456789abcdef", "Addr": "10.0.0.5/24"}]
  },
  "UpdateStatus": {"State": "completed", "StartedAt": "2026-09-02T11:00:00.000000000Z"},
  "ServiceStatus": {"RunningTasks": 2, "DesiredTasks": 3},
  "UnmodelledMember": {"Value": 7}
}"#;

/// The `Spec.TaskTemplate` the daemon sent, exactly as [`SERVICE_BODY`] spells
/// it.
///
/// The owned transport hands this back verbatim inside
/// [`neotales_docker::ServiceSpec::task_template`], so the assertion is a
/// complete-object comparison rather than a list of member checks.
pub(super) const TASK_TEMPLATE: &str = r#"{
  "ContainerSpec": {
    "Image": "nginx:alpine",
    "Command": ["nginx", "-g", "daemon off;"],
    "UnmodelledContainerMember": {"Nested": true}
  },
  "Resources": {"Limits": {"NanoCPUs": 500000000, "UnmodelledLimitMember": 1}},
  "RestartPolicy": {
    "Condition": "on-failure",
    "Delay": 5000000000,
    "MaxAttempts": 3,
    "Window": 20000000000
  },
  "Placement": {
    "Constraints": ["node.role == worker"],
    "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}],
    "MaxReplicas": 3,
    "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
  },
  "ForceUpdate": 0,
  "UnmodelledTaskMember": {"Value": 1}
}"#;

/// The `Spec.TaskTemplate` the *generated* route reports for the same document:
/// Bollard's 1.53 `TaskSpec`, which names `Placement` and `RestartPolicy` but
/// neither the unmodelled members nor the limit's unknown member.
pub(super) const GENERATED_TASK_TEMPLATE: &str = r#"{
  "ContainerSpec": {"Image": "nginx:alpine", "Command": ["nginx", "-g", "daemon off;"]},
  "Resources": {"Limits": {"NanoCPUs": 500000000}},
  "RestartPolicy": {
    "Condition": "on-failure",
    "Delay": 5000000000,
    "MaxAttempts": 3,
    "Window": 20000000000
  },
  "Placement": {
    "Constraints": ["node.role == worker"],
    "Preferences": [{"Spread": {"SpreadDescriptor": "node.labels.zone"}}],
    "MaxReplicas": 3,
    "Platforms": [{"Architecture": "amd64", "OS": "linux"}]
  },
  "ForceUpdate": 0
}"#;

/// The service document reduced to the members one projection case needs.
///
/// `Endpoint` and `ServiceStatus` are the only two members the projections read.
/// The generated client models both as optional and each of their members as
/// optional too, so `null`, an empty list, and a partial status are all valid
/// documents; a member of the wrong JSON type is not. The table below is the
/// acceptance half of that contract, [`MALFORMED_PROJECTION_BODIES`] is the
/// rejection half, and both routing suites assert both.
pub(super) const ENDPOINT_ABSENT_BODY: &str =
    r#"{"ID":"service0123456789abcdef","Version":{"Index":7},"Spec":{"Name":"web"}}"#;

/// An `Endpoint` that is an explicit `null`, which is the same as absent.
pub(super) const ENDPOINT_NULL_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "Spec": {"Name": "web"},
  "Endpoint": null
}"#;

/// An `Endpoint` whose `Ports` member is an explicit `null`.
pub(super) const PORTS_NULL_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "Spec": {"Name": "web"},
  "Endpoint": {"Ports": null}
}"#;

/// An `Endpoint` whose `Ports` member is an empty list.
pub(super) const PORTS_EMPTY_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "Spec": {"Name": "web"},
  "Endpoint": {"Ports": []}
}"#;

/// A `ServiceStatus` carrying one of its two counts.
pub(super) const STATUS_PARTIAL_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "Spec": {"Name": "web"},
  "ServiceStatus": {"RunningTasks": 2}
}"#;

/// A `ServiceStatus` that is an explicit `null`.
pub(super) const STATUS_NULL_BODY: &str = r#"{
  "ID": "service0123456789abcdef",
  "Version": {"Index": 7},
  "Spec": {"Name": "web"},
  "ServiceStatus": null
}"#;

/// One projection input, and what both routes must report for it.
pub(super) struct ProjectionCase {
    /// What the case is, for a failure message.
    pub what: &'static str,
    /// The daemon's answer.
    pub body: &'static str,
    /// How many published ports are projected, or `None` for no projection.
    pub ports: Option<usize>,
    /// The task counts that are projected, or `None` for no projection.
    pub status: Option<(u64, u64)>,
    /// Whether the owned route retains the endpoint in `additional`.
    ///
    /// The generated route removes `Endpoint` whenever it is present, so it is
    /// asserted absent there for every case.
    pub endpoint_retained: bool,
}

/// Every projection case both suites assert, so the two routes are compared
/// against one table rather than two.
pub(super) const PROJECTION_CASES: &[ProjectionCase] = &[
    ProjectionCase {
        what: "published IP and port name",
        body: r#"{"Endpoint":{"Ports":[{"Name":"web","PublishedIP":"192.0.2.1"}],"Spec":{"Ports":[{"Name":"web"}]}}}"#,
        ports: Some(1),
        status: None,
        endpoint_retained: true,
    },
    ProjectionCase {
        what: "full document",
        body: SERVICE_BODY,
        ports: Some(1),
        status: Some((2, 3)),
        endpoint_retained: true,
    },
    ProjectionCase {
        what: "no endpoint",
        body: ENDPOINT_ABSENT_BODY,
        ports: None,
        status: None,
        endpoint_retained: false,
    },
    ProjectionCase {
        what: "endpoint null",
        body: ENDPOINT_NULL_BODY,
        ports: None,
        status: None,
        endpoint_retained: false,
    },
    ProjectionCase {
        what: "ports null",
        body: PORTS_NULL_BODY,
        ports: None,
        status: None,
        endpoint_retained: true,
    },
    ProjectionCase {
        what: "ports empty",
        body: PORTS_EMPTY_BODY,
        ports: Some(0),
        status: None,
        endpoint_retained: true,
    },
    ProjectionCase {
        what: "status partial",
        body: STATUS_PARTIAL_BODY,
        ports: None,
        status: None,
        endpoint_retained: false,
    },
    ProjectionCase {
        what: "status null",
        body: STATUS_NULL_BODY,
        ports: None,
        status: None,
        endpoint_retained: false,
    },
];

/// Documents whose projection input is the wrong JSON type, or a value outside
/// the enumeration the Engine declares.
///
/// The generated models reject every one of these, so the owned decoder must
/// too; the point of the pair is that the facade does not accept a document on
/// one route that it refuses on the other.
pub(super) const MALFORMED_PROJECTION_BODIES: &[(&str, &str)] = &[
    (
        "endpoint port name",
        r#"{"Endpoint":{"Ports":[{"Name":42}]}}"#,
    ),
    (
        "endpoint spec port name",
        r#"{"Endpoint":{"Spec":{"Ports":[{"Name":42}]}}}"#,
    ),
    (
        "an Endpoint that is a string",
        r#"{"ID":"service0123456789abcdef","Endpoint":"not-an-object"}"#,
    ),
    (
        "Ports that is a string",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"Ports":"not-an-array"}}"#,
    ),
    (
        "a port member of the wrong type",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"Ports":[{"PublishedPort":"eighty"}]}}"#,
    ),
    (
        "a port protocol outside the Engine's enumeration",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"Ports":[{"Protocol":"bogus"}]}}"#,
    ),
    (
        "an endpoint specification that is not an object",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"Spec":"vip"}}"#,
    ),
    (
        "an endpoint mode outside the Engine's enumeration",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"Spec":{"Mode":"bogus"}}}"#,
    ),
    (
        "a virtual IP member of the wrong type",
        r#"{"ID":"service0123456789abcdef","Endpoint":{"VirtualIPs":[{"Addr":5}]}}"#,
    ),
    (
        "a ServiceStatus that is a string",
        r#"{"ID":"service0123456789abcdef","ServiceStatus":"not-an-object"}"#,
    ),
    (
        "a task count of the wrong type",
        r#"{"ID":"service0123456789abcdef","ServiceStatus":{"RunningTasks":"two"}}"#,
    ),
    (
        "a negative task count",
        r#"{"ID":"service0123456789abcdef","ServiceStatus":{"RunningTasks":-1}}"#,
    ),
];

impl ProjectionCase {
    /// Asserts the projections one route must report for this document.
    ///
    /// `None` is a projection that did not happen, and it is distinct from an
    /// empty list: the daemon that answered with no ports at all and the daemon
    /// that answered with an empty port list are different answers.
    pub(super) fn assert_projections(&self, service: &neotales_docker::SwarmService, route: &str) {
        match self.ports {
            Some(count) => {
                let ports = service.ports.as_ref().unwrap_or_else(|| {
                    panic!(
                        "{route} ({}): expected {count} projected port(s)",
                        self.what
                    )
                });
                assert_eq!(
                    ports.len(),
                    count,
                    "{route} ({}): {:?}",
                    self.what,
                    service.ports
                );
                if self.what == "published IP and port name" {
                    assert_eq!(ports[0].published_ip, None, "{route}");
                }
            }
            None => assert!(
                service.ports.is_none(),
                "{route} ({}) projected ports from a document without a usable list: {:?}",
                self.what,
                service.ports
            ),
        }
        match self.status {
            Some((running, desired)) => {
                let status = service.status.unwrap_or_else(|| {
                    panic!("{route} ({}): expected a projected status", self.what)
                });
                assert_eq!(
                    (status.running_tasks, status.desired_tasks),
                    (running, desired),
                    "{route} ({})",
                    self.what
                );
            }
            None => assert!(
                service.status.is_none(),
                "{route} ({}) projected counts from an incomplete status: {:?}",
                self.what,
                service.status
            ),
        }
    }
}

/// A success body that is not JSON at all.
pub(super) const MALFORMED_BODY: &str = r#"{"ID":"#;

/// A success body whose `Version` carries the wrong JSON type.
pub(super) const WRONG_TYPE_BODY: &str = r#"{"Version":"not-an-object"}"#;

/// A success body whose `Version` carries the wrong JSON type instead of the
/// declared object, with [`CANARY`] in that position.
pub(super) fn canary_body() -> String {
    format!(r#"{{"ID":"{SERVICE_ID}","Version":"{CANARY}"}}"#)
}

/// Asserts the complete generated update body.
///
/// Both routing suites call this with the same [`EXPECTED_UPDATE_BODY`], so
/// The complete `POST /services/{id}/update` body the owned route produces for
/// [`SERVICE_BODY`].
///
/// The owned writer sends [`ServiceSpec`] member for member, so the body is the
/// specification the daemon returned, including the whole `TaskTemplate` and
/// the unmodelled specification member. `PreviousSpec`, `Endpoint`,
/// `UpdateStatus`, and `ServiceStatus` are service members, not specification
/// members, so they are not part of an update and are absent here.
///
/// Built from [`TASK_TEMPLATE`] rather than copied so the template has one
/// spelling in this module and a change to it cannot leave this expectation
/// describing a document no route sends.
pub(super) fn expected_owned_update_body() -> serde_json::Value {
    serde_json::json!({
        "Name": "web",
        "Labels": {"org.example.service": "fixture"},
        "TaskTemplate": serde_json::from_str::<serde_json::Value>(TASK_TEMPLATE)
            .expect("the task template is JSON"),
        "Mode": {"Replicated": {"Replicas": 3}},
        "Networks": [{"Target": "net0123456789abcdef", "Aliases": ["web"]}],
        "UpdateConfig": {"Parallelism": 2, "FailureAction": "pause"},
        "RollbackConfig": {"Parallelism": 1},
        "EndpointSpec": {
            "Mode": "vip",
            "Ports": [{
                "Protocol": "tcp",
                "TargetPort": 80,
                "PublishedPort": 8080,
                "PublishMode": "ingress",
                "Name": "http"
            }]
        },
        "UnmodelledSpecMember": {"Nested": true}
    })
}

/// Asserts the owned update body exactly.
pub(super) fn assert_owned_update_body(body: &serde_json::Value) {
    assert_eq!(
        body,
        &expected_owned_update_body(),
        "the owned update body changed; observed body: {body}"
    );
}
