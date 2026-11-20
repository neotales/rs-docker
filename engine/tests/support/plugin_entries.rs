//! Plugin documents shared by the owned and fallback routing suites.
//!
//! Both suites send the same recorded answers through both transports, so a
//! difference in their results is a difference in the code rather than in the
//! fixture.
//!
//! # The shape is the Engine's, and it is wider than the repository model
//!
//! A plugin document carries `Id`, `Name`, `Enabled`, `Settings`,
//! `PluginReference`, and a fourteen-member `Config`. The repository's
//! [`PluginSummary`] names five of those, and both transports project into it:
//! the owned path decodes the Engine's spelling directly, while the generated
//! path decodes Bollard's 1.53 `Plugin` first. Every member outside the five is
//! therefore dropped on **both** paths, which is why the document below carries
//! an unmodelled member at the document root, inside `Config`, and inside
//! `Settings`: a difference between the paths would show up as one of them
//! surviving.
//!
//! `Settings` and `Config` are fully populated because Bollard's generated
//! models require them. The owned path is more tolerant — it reads a `null`
//! `Config` as the empty block — but a document both transports can decode has
//! to satisfy the stricter one for the parity assertions to mean anything.
//!
//! The canary lives in an unmodelled member, so a redaction written against one
//! named field would miss it.

// Two test binaries include this module, and each uses a subset of the entries,
// so an entry one of them does not read is not dead code.
#![allow(dead_code)]

use neotales_docker::{PluginPrivilege, PluginSummary};

/// The plugin the parity assertions inspect.
pub(super) const PLUGIN_NAME: &str = "vieux/sshfs:latest";

/// The remote reference the same document reports.
pub(super) const PLUGIN_REFERENCE: &str = "vieux/sshfs:latest";

/// The plugin id the full document reports.
pub(super) const PLUGIN_ID: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The description nested in `Config`, the one member the summary nests.
pub(super) const PLUGIN_DESCRIPTION: &str = "Slow SSHFS";

/// A value that must never appear in a rendered error or a projected summary.
pub(super) const CANARY: &str = "canary-plugin-metadata-58c1-do-not-log-me";

/// A plugin document in the shape a Docker Engine reports.
///
/// `FutureMember`, `Config.FutureConfigMember`, and `Settings.FutureDevice` are
/// members no Engine version declares yet; they are the ones the projection
/// must ignore rather than fail on.
pub(super) fn plugin_body() -> String {
    serde_json::json!({
        "Id": PLUGIN_ID,
        "Name": PLUGIN_NAME,
        "Enabled": true,
        "Settings": {
            "Mounts": [],
            "Env": [],
            "Args": [],
            "Devices": [],
            "FutureDevice": {"Message": CANARY}
        },
        "PluginReference": PLUGIN_REFERENCE,
        "Config": {
            "Description": PLUGIN_DESCRIPTION,
            "Documentation": "https://docs.example.invalid/sshfs",
            "Interface": {
                "Types": ["docker.volumedriver/1.0"],
                "Socket": "sshfs.sock"
            },
            "Entrypoint": ["/usr/bin/sshfs"],
            "WorkDir": "/home",
            "Network": {"Type": "host"},
            "Linux": {
                "Capabilities": ["CAP_SYS_ADMIN"],
                "AllowAllDevices": false,
                "Devices": []
            },
            "PropagatedMount": "/var/lib/docker/plugins",
            "IpcHost": false,
            "PidHost": false,
            "Mounts": [],
            "Env": [],
            "Args": {
                "Name": "args",
                "Description": "fixture",
                "Settable": [],
                "Value": []
            },
            "FutureConfigMember": {"Message": CANARY}
        },
        "FutureMember": {"Message": CANARY}
    })
    .to_string()
}

/// A list answer carrying the full document and a disabled plugin that has no
/// id, no remote reference, and no description.
///
/// The second entry is the "installed but not running" case: `Enabled` is a bare
/// boolean, so `false` is a measurement rather than a missing answer.
pub(super) fn plugin_array_body() -> String {
    let disabled = serde_json::json!({
        "Name": "vieux/empty:latest",
        "Enabled": false,
        "Settings": {"Mounts": [], "Env": [], "Args": [], "Devices": []},
        "Config": {
            "Description": "",
            "Documentation": "",
            "Interface": {"Types": [], "Socket": ""},
            "Entrypoint": [],
            "WorkDir": "",
            "Network": {"Type": "host"},
            "Linux": {"Capabilities": [], "AllowAllDevices": false, "Devices": []},
            "PropagatedMount": "",
            "IpcHost": false,
            "PidHost": false,
            "Mounts": [],
            "Env": [],
            "Args": {"Name": "args", "Description": "", "Settable": [], "Value": []}
        }
    });
    format!("[{},{}]", plugin_body(), disabled)
}

/// A plugin whose `Config` the daemon sent as `null`.
///
/// Only the owned path reads this: Bollard's `Plugin::config` is not optional,
/// and a `null` there is a decode failure. The owned decoder reads the member as
/// the empty block because a plugin with no config is not a broken answer.
pub(super) const CONFIGLESS_PLUGIN_BODY: &str =
    r#"{"Name":"vieux/empty:latest","Enabled":false,"Config":null}"#;

/// The privilege array a `GET /plugins/privileges` answer carries.
///
/// The last entry omits `Value`, which the Engine does for a privilege that
/// grants nothing; an absent member and an explicit `null` are both empty
/// grants rather than unknown ones.
pub(super) const PRIVILEGE_ARRAY: &str = r#"[
    {"Name":"network","Description":"Allow access to host network","Value":["host"]},
    {"Name":"mount","Description":"Allow local mounts"},
    {"Name":"device","Description":"Allow device access","Value":null,"FutureMember":"ignored"}
]"#;

/// The projection both transports must produce for [`plugin_body`].
pub(super) fn expected_summary() -> PluginSummary {
    PluginSummary {
        id: Some(PLUGIN_ID.to_owned()),
        name: PLUGIN_NAME.to_owned(),
        enabled: true,
        description: PLUGIN_DESCRIPTION.to_owned(),
        plugin_reference: Some(PLUGIN_REFERENCE.to_owned()),
    }
}

/// The projection both transports must produce for [`PRIVILEGE_ARRAY`].
pub(super) fn expected_privileges() -> Vec<PluginPrivilege> {
    vec![
        PluginPrivilege {
            name: Some("network".to_owned()),
            description: Some("Allow access to host network".to_owned()),
            values: vec!["host".to_owned()],
        },
        PluginPrivilege {
            name: Some("mount".to_owned()),
            description: Some("Allow local mounts".to_owned()),
            values: Vec::new(),
        },
        PluginPrivilege {
            name: Some("device".to_owned()),
            description: Some("Allow device access".to_owned()),
            values: Vec::new(),
        },
    ]
}

/// The projection both transports must produce for the disabled entry of
/// [`plugin_array_body`].
pub(super) fn expected_disabled_summary() -> PluginSummary {
    PluginSummary {
        id: None,
        name: "vieux/empty:latest".to_owned(),
        enabled: false,
        description: String::new(),
        plugin_reference: None,
    }
}
