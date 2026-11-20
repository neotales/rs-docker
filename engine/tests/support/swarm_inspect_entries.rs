//! `GET /swarm` documents shared by the owned and fallback routing suites.
//!
//! Both suites must send the *same* recorded answers through both transports,
//! or a difference in their results would be a difference in the fixture
//! rather than in the code. The documents deliberately contain members the
//! repository model does not name: the owned transport decodes the daemon's
//! answer directly and retains them, while the generated fallback has no
//! catch-all and discards them.

/// The worker join token in [`SWARM_BODY`]. It is not a real credential; it is
/// a canary the redaction test looks for in `Debug` output.
pub(super) const WORKER_TOKEN: &str = "test-worker-join-token";

/// The manager join token in [`SWARM_BODY`]. It is not a real credential.
pub(super) const MANAGER_TOKEN: &str = "test-manager-join-token";

/// A Swarm document with every member the facade names, plus one unmodelled
/// top-level member and one unmodelled member inside `Spec`.
pub(super) const SWARM_BODY: &str = r#"{
  "ID": "swarm-fixture",
  "Version": {"Index": 12},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "fixture-swarm",
    "Labels": {"org.example.swarm": "fixture"},
    "Orchestration": {"TaskHistoryRetentionLimit": 5},
    "UnmodelledSpecMember": {"Nested": true}
  },
  "JoinTokens": {
    "Worker": "test-worker-join-token",
    "Manager": "test-manager-join-token"
  },
  "UnmodelledMember": {"Value": 7}
}"#;

/// A worker node's answer: the manager token is absent rather than empty.
pub(super) const WORKER_ONLY_BODY: &str =
    r#"{"ID":"swarm-fixture","JoinTokens":{"Worker":"test-worker-join-token"}}"#;

/// A document whose tokens are present but blank. The facade treats a blank
/// token as "no token", because pasting it into a join command cannot work.
pub(super) const BLANK_TOKENS_BODY: &str =
    r#"{"ID":"swarm-fixture","JoinTokens":{"Worker":"   ","Manager":""}}"#;

/// A success body that is not JSON at all.
pub(super) const MALFORMED_BODY: &str = r#"{"ID":"#;

/// A success body whose `Version` has the wrong JSON type.
pub(super) const WRONG_TYPE_BODY: &str = r#"{"Version":"not-an-object"}"#;
