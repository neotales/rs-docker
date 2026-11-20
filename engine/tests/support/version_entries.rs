//! Version documents shared by the owned and fallback routing suites.
//!
//! The two suites send the *same* recorded answer through both transports, so a
//! difference in their results is a difference in the code rather than in the
//! fixture. The expected projection is defined here for the same reason: both
//! paths are compared against one value instead of each spelling its own.
//!
//! Each test binary includes this module separately, so a constant used by only
//! one of them is unused in the other.
#![allow(dead_code)]

use neotales_docker::DaemonVersion;

/// A `GET /version` answer recorded from Docker Engine 29.8.0, with the
/// members a newer daemon may add.
///
/// `FutureMember` and `FutureComponentMember` are deliberately not part of the
/// generated model. They pin the documented difference between the paths: the
/// owned document keeps them, while the generated path drops them when it
/// re-serializes its model. `Experimental` is present as `false`, which the
/// generated model carries as `Some(false)` rather than dropping as absent.
pub(super) const VERSION_BODY: &str = r#"{
    "Platform": {"Name": "Docker Engine - Community"},
    "Components": [
        {
            "Name": "Engine",
            "Version": "29.8.0",
            "Details": {
                "ApiVersion": "1.55",
                "Arch": "amd64",
                "BuildTime": "2026-09-01T00:00:00.000000000+00:00",
                "Experimental": "false",
                "GitCommit": "fixture",
                "GoVersion": "go1.24.0",
                "KernelVersion": "6.12.0",
                "MinAPIVersion": "1.40",
                "Os": "linux"
            },
            "FutureComponentMember": true
        }
    ],
    "Version": "29.8.0",
    "ApiVersion": "1.55",
    "MinAPIVersion": "1.40",
    "GitCommit": "fixture",
    "GoVersion": "go1.24.0",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "6.12.0",
    "Experimental": false,
    "BuildTime": "2026-09-01T00:00:00.000000000+00:00",
    "FutureMember": {"nested": true}
}"#;

/// Only one of the five members the repository model names.
pub(super) const MISSING_FIELDS_BODY: &str = r#"{"Version":"29.8.0"}"#;

/// Every projected member explicitly `null`.
///
/// `null` is absence to the generated model's `Option` fields, but the owned
/// document retains the member as the daemon sent it.
pub(super) const NULL_FIELDS_BODY: &str =
    r#"{"Version":null,"ApiVersion":null,"MinAPIVersion":null,"Os":null,"Arch":null}"#;

/// A known scalar member with the wrong JSON type.
pub(super) const MALFORMED_VERSION_BODY: &str = r#"{"Version":29}"#;

/// A known metadata member with the wrong JSON type. The repository projection
/// does not expose it, but the generated model still declared it, so routing
/// must not silently ignore the malformed value.
pub(super) const MALFORMED_METADATA_BODY: &str = r#"{"Version":"29.8.0","Experimental":"maybe"}"#;

/// A `Components` entry missing the `Version` member the generated model
/// requires.
pub(super) const MALFORMED_COMPONENT_BODY: &str =
    r#"{"Version":"29.8.0","Components":[{"Name":"Engine"}]}"#;

/// Two `Version` members with different values.
///
/// `serde_json::Value` keeps the last one, so a validator that projects a parsed
/// value cannot see the duplicate. The generated model rejects it, and the owned
/// path must too.
pub(super) const DUPLICATE_VERSION_BODY: &str = r#"{"Version":"29.8.0","Version":"29.8.1"}"#;

/// Two nested `Components[].Version` members with different values.
pub(super) const DUPLICATE_COMPONENT_VERSION_BODY: &str = r#"{
    "Version": "29.8.0",
    "Components": [
        {"Name": "Engine", "Version": "29.8.0", "Version": "29.8.1"}
    ]
}"#;

/// A `Version` member with an invalid value followed by a valid duplicate.
///
/// A value-first validator would keep the valid second value and accept the
/// body; the generated decoder rejects the first value before it ever reaches
/// the second.
pub(super) const INVALID_THEN_VALID_VERSION_BODY: &str = r#"{"Version":29,"Version":"29.8.0"}"#;

/// The same invalid-first, valid-second shape inside `Components`.
pub(super) const INVALID_THEN_VALID_COMPONENT_BODY: &str = r#"{
    "Version": "29.8.0",
    "Components": [
        {"Name": "Engine", "Version": 29, "Version": "29.8.0"}
    ]
}"#;

/// A truncated success body.
pub(super) const MALFORMED_JSON_BODY: &str = r#"{"Version":"29.8.0""#;

/// Valid JSON that is not the object this endpoint answers with.
pub(super) const NON_OBJECT_BODY: &str = "[]";

/// The projection both transports must produce for [`VERSION_BODY`].
pub(super) fn expected_daemon_version() -> DaemonVersion {
    DaemonVersion {
        version: Some("29.8.0".to_owned()),
        api_version: Some("1.55".to_owned()),
        min_api_version: Some("1.40".to_owned()),
        os: Some("linux".to_owned()),
        arch: Some("amd64".to_owned()),
    }
}
