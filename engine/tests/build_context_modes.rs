//! Directory archive permission regressions.
#![cfg(unix)]
use neotales_docker::ImageBuildContext;
use std::{fs, io::Cursor, os::unix::fs::PermissionsExt};
#[test]
fn context_preserves_executable_and_private_modes() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("run.sh"), "#!/bin/sh\n").unwrap();
    fs::set_permissions(
        root.path().join("run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::write(root.path().join("private"), "private").unwrap();
    fs::set_permissions(
        root.path().join("private"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::create_dir(root.path().join("dir")).unwrap();
    fs::set_permissions(root.path().join("dir"), fs::Permissions::from_mode(0o700)).unwrap();
    let context = ImageBuildContext::from_directory(root.path()).unwrap();
    let mut archive = tar::Archive::new(Cursor::new(context.as_bytes()));
    let modes: std::collections::BTreeMap<_, _> = archive
        .entries()
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .trim_end_matches('/')
                    .to_owned(),
                entry.header().mode().unwrap(),
            )
        })
        .collect();
    assert_eq!(modes["run.sh"], 0o755);
    assert_eq!(modes["private"], 0o600);
    assert_eq!(modes["dir"], 0o700);
}
