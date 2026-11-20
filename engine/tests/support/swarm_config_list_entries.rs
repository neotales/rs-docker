//! Config-list documents shared by the owned and fallback routing suites.
//!
//! Both suites send the *same* recorded answers through both transports, so a
//! difference in their results is a difference in the code rather than in the
//! fixture. The documents deliberately contain members the repository model
//! does not name: the owned transport decodes the daemon's array directly and
//! retains them, while the generated fallback has no catch-all and discards
//! them.
//!
//! The config data here is synthetic. It is a canary the error tests look for
//! in every rendering of a decode failure, never a stored value. A list answer
//! normally omits `Data`; one document includes it so the data boundary is
//! pinned on the route that reads the daemon's own document.

// Two test binaries include this module, and each uses a subset of the entries,
// so an entry one of them does not read is not dead code.
#![allow(dead_code)]

/// The config ID every document in this module lists.
pub(super) const CONFIG_ID: &str = "config0123456789abcdef";

/// The version index the daemon reports.
pub(super) const VERSION_INDEX: u64 = 3;

/// Synthetic config bytes, chosen so a leaked error is unmistakable.
///
/// The fallback suite sends the same document but cannot make the no-echo
/// assertion: Bollard's own decode error quotes the response. The constant is
/// shared so both suites describe one fixture.
pub(super) const CONFIG_DATA_CANARY: &str = "test-config-list-data-canary";

/// [`CONFIG_DATA_CANARY`], base64-encoded as the Engine declares `Data`.
pub(super) const CONFIG_DATA_BASE64: &str = "dGVzdC1jb25maWctbGlzdC1kYXRhLWNhbmFyeQ==";

/// A config with every member the facade names, one unmodelled top-level
/// member, one unmodelled `Spec` member, and a `Data` member a list answer
/// normally omits.
pub(super) const CONFIG_BODY: &str = r#"{
  "ID": "config0123456789abcdef",
  "Version": {"Index": 3},
  "CreatedAt": "2026-09-01T10:00:00.000000000Z",
  "UpdatedAt": "2026-09-02T11:00:00.000000000Z",
  "Spec": {
    "Name": "app-config",
    "Labels": {"org.example.config": "fixture"},
    "Data": "dGVzdC1jb25maWctbGlzdC1kYXRhLWNhbmFyeQ==",
    "Templating": {
      "Name": "template-driver",
      "Options": {"org.example.option": "fixture"},
      "UnmodelledTemplatingMember": true
    },
    "UnmodelledSpecMember": {"Nested": true}
  },
  "UnmodelledMember": {"Value": 7}
}"#;

/// The list answer containing [`CONFIG_BODY`].
pub(super) fn list_body() -> String {
    format!("[{CONFIG_BODY}]")
}

/// The empty list. Both routes return an empty vector.
pub(super) const EMPTY_LIST_BODY: &str = "[]";

/// A success body with no bytes at all.
pub(super) const EMPTY_BODY: &str = "";

/// A JSON `null` instead of the array the endpoint declares.
pub(super) const NULL_BODY: &str = "null";

/// An array containing `null` instead of a config object.
pub(super) const NULL_ENTRY_BODY: &str = "[null]";

/// A success body that is not JSON at all.
///
/// The truncated tail is the config data member, so a decoder that echoed the
/// document would put the canary in the error.
pub(super) const MALFORMED_BODY: &str = concat!(
    r#"[{"ID":"config0123456789abcdef","Spec":{"Data":"#,
    r#""dGVzdC1jb25maWctbGlzdC1kYXRhLWNhbmFyeQ==""#
);

/// A correctly shaped array with one member of the wrong JSON type.
///
/// The unexpected value is the canary itself: serde's own `Display` quotes it,
/// which is the leak the content-free summary prevents.
pub(super) const WRONG_TYPE_BODY: &str =
    r#"[{"ID":"config0123456789abcdef","Version":"test-config-list-data-canary"}]"#;
