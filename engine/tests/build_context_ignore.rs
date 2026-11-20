//! Directory build context ignore semantics.
use neotales_docker::{ImageBuildContext, ImageTransferLimits};
use std::{collections::BTreeSet, fs, io::Cursor};

fn paths(context: &ImageBuildContext) -> BTreeSet<String> {
    tar::Archive::new(Cursor::new(context.as_bytes()))
        .entries()
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .path()
                .unwrap()
                .to_string_lossy()
                .trim_end_matches('/')
                .to_owned()
        })
        .collect()
}

#[test]
fn excludes_and_negates_in_order() {
    let root = tempfile::tempdir().unwrap();
    for (name, content) in [
        ("Dockerfile", "FROM scratch\n"),
        (
            ".dockerignore",
            "# comment\n*.txt\n!keep.txt\n/nested/secret\n**/*.log\nDockerfile\n.dockerignore\n",
        ),
        ("drop.txt", ""),
        ("keep.txt", ""),
        ("nested/secret", ""),
        ("nested/drop.log", ""),
        ("nested/keep.txt", ""),
    ] {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    let found = paths(&ImageBuildContext::from_directory(root.path()).unwrap());
    assert!(found.contains("Dockerfile") && found.contains(".dockerignore"));
    assert!(found.contains("keep.txt") && found.contains("nested/keep.txt"));
    assert!(
        !found.contains("drop.txt")
            && !found.contains("nested/secret")
            && !found.contains("nested/drop.log")
    );
}

#[test]
fn dockerfile_specific_ignore_takes_precedence_and_selected_file_survives() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("build")).unwrap();
    for (name, content) in [
        (".dockerignore", "root-only\n"),
        ("root-only", ""),
        ("selected-only", ""),
        ("build/custom", "FROM scratch\n"),
        ("build/custom.dockerignore", "selected-only\nbuild\n"),
    ] {
        fs::write(root.path().join(name), content).unwrap();
    }
    let context = ImageBuildContext::from_directory_for_dockerfile_with_limits(
        root.path(),
        "build/custom",
        ImageTransferLimits::default(),
    )
    .unwrap();
    let found = paths(&context);
    assert!(
        found.contains("build/custom")
            && found.contains("build/custom.dockerignore")
            && found.contains(".dockerignore")
    );
    assert!(found.contains("root-only"));
    assert!(!found.contains("selected-only"));
}

#[test]
fn refuses_unsupported_patterns_and_preserves_no_ignore_control() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("file.txt"), "content").unwrap();
    assert_eq!(
        paths(&ImageBuildContext::from_directory(root.path()).unwrap()),
        ["Dockerfile", "file.txt"]
            .into_iter()
            .map(String::from)
            .collect()
    );
    fs::write(root.path().join(".dockerignore"), "[ab\n").unwrap();
    let err = ImageBuildContext::from_directory(root.path())
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported pattern") && err.contains("line 1"));
}

#[test]
fn default_and_selected_dockerfile_are_always_included() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("other"), "FROM scratch\n").unwrap();
    fs::write(root.path().join(".dockerignore"), "Dockerfile\nother\n").unwrap();
    let context = ImageBuildContext::from_directory_for_dockerfile_with_limits(
        root.path(),
        "other",
        ImageTransferLimits::default(),
    )
    .unwrap();
    let found = paths(&context);
    assert!(found.contains("Dockerfile") && found.contains("other"));
}

#[test]
#[cfg(not(windows))]
fn moby_classes_escapes_and_cleaned_paths() {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "Dockerfile",
        "a1",
        "a9",
        "aX",
        "literal.txt",
        "literalXtxt",
        "target",
        "dir/drop",
        "dir/keep",
    ] {
        let path = root.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "").unwrap();
    }
    fs::write(
        root.path().join(".dockerignore"),
        "a[0-9]\nliteral\\.txt\n./target\ndir//drop\n",
    )
    .unwrap();
    let context = ImageBuildContext::from_directory(root.path()).unwrap();
    let found = paths(&context);
    for name in ["a1", "a9", "literal.txt", "target", "dir/drop"] {
        assert!(!found.contains(name), "{name}");
    }
    for name in ["aX", "literalXtxt", "dir/keep"] {
        assert!(found.contains(name), "{name}");
    }
}

#[test]
fn whitespace_question_mark_double_star_and_last_rule() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("a/b")).unwrap();
    for name in ["Dockerfile", "one1", "one12", "a/b/x.log", "a/b/safe.log"] {
        fs::write(root.path().join(name), "").unwrap();
    }
    fs::write(
        root.path().join(".dockerignore"),
        "\n# comment\none?  \n**/*.log\n! **/safe.log   \n",
    )
    .unwrap();
    let found = paths(&ImageBuildContext::from_directory(root.path()).unwrap());
    assert!(!found.contains("one1"));
    assert!(found.contains("one12"));
    assert!(!found.contains("a/b/x.log"));
    assert!(found.contains("a/b/safe.log"));
}

#[test]
#[cfg(windows)]
fn windows_ignore_backslash_excludes_secret() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("secrets")).unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("secrets").join("token"), "private").unwrap();
    fs::write(root.path().join(".dockerignore"), "secrets\\*\n").unwrap();
    let context = ImageBuildContext::from_directory(root.path()).unwrap();
    assert!(!paths(&context).contains("secrets/token"));
}
