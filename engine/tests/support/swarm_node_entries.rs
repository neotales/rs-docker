//! Node documents shared by the owned and fallback routing suites.
//!
//! Both suites send the same recorded answers through both transports, so a
//! difference in their results is a difference in the code rather than in the
//! fixture.
//!
//! # The shape is the Engine's
//!
//! A v1.53 `NodeSpec` has exactly four members — `Name`, `Labels`, `Role`, and
//! `Availability` — and all four are modeled by the repository and by Bollard.
//! The document below therefore carries no unmodelled *spec* member, so the
//! owned inspect → update round trip can assert that all four survive.
//!
//! Unmodelled members are present at the levels the transports disagree about:
//! one at the node root, one inside `Description`, one inside `Status`, and the
//! manager address inside `ManagerStatus`. The owned path retains them; the
//! generated fallback drops what Bollard's 1.53 `Node` does not name, except
//! `Description`, `Status`, and `ManagerStatus`, which it does name.
//!
//! A separate document carries an unmodelled `Spec` member: the owned read
//! retains it and the generated read drops it, the owned write preserves it,
//! and a reserved key is refused before dispatch.

// Two test binaries include this module, and each uses a subset of the entries,
// so an entry one of them does not read is not dead code.
#![allow(dead_code)]

/// The node ID every document in this module inspects.
pub(super) const NODE_ID: &str = "node0123456789abcdef";

/// The version index the daemon reports and the update must echo.
pub(super) const VERSION_INDEX: u64 = 4;

/// A value that must never appear in a `Debug` rendering or a decode error.
///
/// It is placed in unmodelled, daemon-chosen members rather than in a typed
/// member, so a redaction written against one named field would miss it.
pub(super) const CANARY: &str = "canary-node-metadata-4b7e2c19-do-not-log-me";

/// A node document in the shape a Docker Engine reports.
///
/// `Spec` is the complete v1.53 node specification, so this document is also the
/// one the inspect → update round trip serializes.
pub(super) const NODE_BODY: &str = r#"{
  "ID": "node0123456789abcdef",
  "Version": {"Index": 4},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "manager-one",
    "Labels": {"org.example.node": "fixture"},
    "Role": "manager",
    "Availability": "active"
  },
  "Description": {
    "Hostname": "mgr-1",
    "Engine": {
      "EngineVersion": "27.1.1",
      "Labels": {"engine.label": "canary-node-metadata-4b7e2c19-do-not-log-me"}
    },
    "TLSInfo": {"TrustRoot": "canary-node-metadata-4b7e2c19-do-not-log-me"}
  },
  "Status": {
    "State": "ready",
    "Message": "canary-node-metadata-4b7e2c19-do-not-log-me",
    "Addr": "192.0.2.10"
  },
  "ManagerStatus": {
    "Leader": true,
    "Reachability": "reachable",
    "Addr": "192.0.2.10:2377",
    "UnmodelledManagerMember": true
  },
  "UnmodelledMember": {"Value": "canary-node-metadata-4b7e2c19-do-not-log-me"}
}"#;

/// The same inspect answer with one member inside `Spec` that v1.53 does not
/// define.
///
/// The owned path retains it in `NodeSpec::additional`, and `update_node` must
/// refuse that specification rather than silently clearing it.
pub(super) const NODE_BODY_WITH_UNMODELLED_SPEC: &str = r#"{
  "ID": "node0123456789abcdef",
  "Version": {"Index": 4},
  "Spec": {
    "Name": "manager-one",
    "Labels": {"org.example.node": "fixture"},
    "Role": "manager",
    "Availability": "active",
    "UnmodelledSpecMember": {"Nested": true}
  }
}"#;

/// A list answer containing [`NODE_BODY`].
pub(super) fn nodes_body() -> String {
    format!("[{NODE_BODY}]")
}

/// A node whose daemon sent an actual top-level `EngineVersion`, beside the
/// usual nested `Description.Engine.EngineVersion`.
pub(super) const NODE_BODY_TOP_LEVEL_ENGINE_VERSION: &str = r#"{
  "ID": "node0123456789abcdef",
  "EngineVersion": "actual-top-level",
  "Description": {"Engine": {"EngineVersion": "nested-view"}}
}"#;

/// A truncated answer.
pub(super) const MALFORMED_BODY: &str = r#"{"ID":"canary-node-metadata-4b7e2c19-do-not-log-me","#;

/// A correctly shaped document with one member of the wrong JSON type.
///
/// `Labels` is an object in the Engine; an array carrying the canary is the
/// value a serde error would quote if this crate used serde's own message.
pub(super) const WRONG_TYPE_BODY: &str = r#"{
  "ID": "node0123456789abcdef",
  "Spec": {"Labels": ["canary-node-metadata-4b7e2c19-do-not-log-me"]}
}"#;

/// The complete `POST /nodes/{id}/update` body the generated write produces
/// from [`NODE_BODY`].
pub(super) const EXPECTED_UPDATE_BODY: &str = r#"{
  "Name": "manager-one",
  "Labels": {"org.example.node": "fixture"},
  "Role": "manager",
  "Availability": "active"
}"#;
