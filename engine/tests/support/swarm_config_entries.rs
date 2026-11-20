//! `GET /configs/{id}` documents shared by the owned and fallback routing
//! suites.
//!
//! Both suites must send the *same* recorded answers through both transports,
//! or a difference in their results would be a difference in the fixture
//! rather than in the code. The documents deliberately contain members the
//! repository model does not name: the owned transport decodes the daemon's
//! answer directly and retains them, while the generated fallback has no
//! catch-all and discards them.
//!
//! The config data here is synthetic. It is a canary the error tests look for
//! in every rendering of a decode failure, never a stored value.

/// Synthetic config bytes, chosen so a leaked error is unmistakable.
///
/// The fallback suite sends the same document but cannot make the no-echo
/// assertion: Bollard's own decode error quotes the response. The constant is
/// shared so both suites describe one fixture.
#[allow(dead_code)]
pub(super) const CONFIG_DATA_CANARY: &str = "test-config-data-canary";

/// [`CONFIG_DATA_CANARY`], base64-encoded as the Engine declares `Data`.
pub(super) const CONFIG_DATA_BASE64: &str = "dGVzdC1jb25maWctZGF0YS1jYW5hcnk=";

/// A config with every member the facade names, the inspect-only `Data`
/// member, one unmodelled top-level member, and one unmodelled `Spec` member.
pub(super) const CONFIG_BODY: &str = r#"{
  "ID": "config-fixture",
  "Version": {"Index": 9},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "fixture-config",
    "Labels": {"org.example.config": "fixture"},
    "Data": "dGVzdC1jb25maWctZGF0YS1jYW5hcnk=",
    "UnmodelledSpecMember": {"Nested": true}
  },
  "UnmodelledMember": {"Value": 7}
}"#;

/// A success body that is not JSON at all.
///
/// The truncated tail is the config data member, so a decoder that echoed the
/// document would put the canary in the error.
pub(super) const MALFORMED_BODY: &str = concat!(
    r#"{"ID":"config-fixture","Spec":{"Data":"#,
    r#""dGVzdC1jb25maWctZGF0YS1jYW5hcnk=""#
);

/// A success body whose `Version` has the wrong JSON type.
///
/// The unexpected value is the canary itself: serde's own `Display` quotes it,
/// which is the leak the content-free summary prevents.
pub(super) const WRONG_TYPE_BODY: &str =
    r#"{"ID":"config-fixture","Version":"test-config-data-canary"}"#;
