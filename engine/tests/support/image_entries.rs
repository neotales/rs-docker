//! Image documents shared by the owned and fallback routing suites.
//!
//! The two suites must send the *same* recorded answers through both transports,
//! or a difference in their results would be a difference in the fixture rather
//! than in the code. The generated model's required members are listed here for
//! the same reason: a missing-member test on one path is only comparable to the
//! other if both remove the same member from the same entry.

/// Two entries recorded from the shape Docker Engine 29.8.0 answers.
///
/// The first carries the metadata the projection names. The second is an
/// untagged image: `RepoTags`, `RepoDigests`, and `Labels` are `null`, which the
/// projection reports as empty rather than as a missing list. `Descriptor` is
/// present on the first entry because a v29.8 entry carries it and
/// `ImageSummary` has no member for it; its presence proves the extra member is
/// ignored rather than fatal. The second entry proves the `-1` sentinels are
/// carried through, not zeroed.
pub(super) const LIST_BODY: &str = r#"[
        {
            "Id": "sha256:image-fixture",
            "ParentId": "",
            "RepoTags": ["registry.example/team/image:latest"],
            "RepoDigests": ["registry.example/team/image@sha256:digest-fixture"],
            "Created": 1700000000,
            "Size": 1234,
            "SharedSize": 12,
            "Labels": {"org.example.fixture": "true"},
            "Containers": 2,
            "Descriptor": {"mediaType": "application/vnd.oci.image.index.v1+json"}
        },
        {
            "Id": "sha256:untagged",
            "ParentId": "sha256:image-fixture",
            "RepoTags": null,
            "RepoDigests": null,
            "Created": 1700000001,
            "Size": 10,
            "SharedSize": -1,
            "Labels": null,
            "Containers": -1
        }
    ]"#;

/// A valid entry that carries every value the Engine may send as `null` and both
/// "not calculated" sentinels, and nothing else.
///
/// There is no `Descriptor` and no `Manifests` member, because the generated
/// model marks those optional; their absence must not change the result.
pub(super) const NULL_AND_SENTINEL_BODY: &str = r#"[
        {
            "Id": "sha256:sentinel",
            "ParentId": "sha256:image-fixture",
            "RepoTags": null,
            "RepoDigests": null,
            "Created": 1700000002,
            "Size": 0,
            "SharedSize": -1,
            "Labels": null,
            "Containers": -1
        }
    ]"#;

/// The two records a delete usually answers with: one untag, one delete, and
/// one record that carries both members.
pub(super) const REMOVE_BODY: &str = r#"[
        {"Untagged": "registry.example/team/image:latest"},
        {"Deleted": "sha256:image-fixture"},
        {"Untagged": "image:latest", "Deleted": "sha256:image-fixture"}
    ]"#;

/// A valid entry whose experimental members carry the wrong JSON type.
///
/// The generated `ImageSummary` has typed `Descriptor` and `Manifests` members
/// and decodes them when a daemon sends them, so this answer fails that decoder.
/// The owned projection does not model either member and ignores both, so it
/// succeeds. The two suites pin both sides of that difference.
pub(super) const MALFORMED_EXPERIMENTAL_BODY: &str = r#"[
        {
            "Id": "sha256:image-fixture",
            "ParentId": "",
            "RepoTags": ["registry.example/team/image:latest"],
            "RepoDigests": ["registry.example/team/image@sha256:digest-fixture"],
            "Created": 1700000000,
            "Size": 1234,
            "SharedSize": 12,
            "Labels": {"org.example.fixture": "true"},
            "Containers": 2,
            "Descriptor": 7,
            "Manifests": 7
        }
    ]"#;

/// The `GET /images/json` members the generated `ImageSummary` requires.
///
/// Read from `bollard-stubs` 1.53.1: `Id`, `ParentId`, `Created`, `Size`,
/// `SharedSize`, and `Containers` are plain required fields, while `RepoTags`,
/// `RepoDigests`, and `Labels` are also required but deserialized through
/// helpers that turn a present `null` into an empty value. `Manifests` and
/// `Descriptor` are `Option`s and are not here.
pub(super) const REQUIRED_IMAGE_SUMMARY_MEMBERS: [&str; 9] = [
    "Id",
    "ParentId",
    "RepoTags",
    "RepoDigests",
    "Created",
    "Size",
    "SharedSize",
    "Labels",
    "Containers",
];

/// Builds a one-entry image list with `member` removed.
///
/// The generated model requires every member listed in
/// [`REQUIRED_IMAGE_SUMMARY_MEMBERS`], so an answer that omits one is the case
/// that distinguishes a decoder which refuses it from one that defaults it to
/// zero or to an empty value.
pub(super) fn image_list_without_summary_member(member: &str) -> String {
    let mut entry = serde_json::json!({
        "Id": "sha256:image-fixture",
        "ParentId": "",
        "RepoTags": ["registry.example/team/image:latest"],
        "RepoDigests": ["registry.example/team/image@sha256:digest-fixture"],
        "Created": 1_700_000_000,
        "Size": 1234,
        "SharedSize": 12,
        "Labels": {"org.example.fixture": "true"},
        "Containers": 2,
    });
    entry
        .as_object_mut()
        .expect("the entry is an object")
        .remove(member);
    serde_json::to_string(&[entry]).expect("encode the image list")
}
