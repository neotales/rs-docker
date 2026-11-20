//! Special filesystem entries are rejected with a useful type and path.
#![cfg(unix)]
use neotales_docker::ImageBuildContext;
use std::{fs, process::Command};

#[test]
fn archives_hardlinks_as_regular_files() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("original"), "data").unwrap();
    fs::hard_link(root.path().join("original"), root.path().join("hardlink")).unwrap();
    fs::write(outside.path().join("external"), "outside data").unwrap();
    fs::hard_link(
        outside.path().join("external"),
        root.path().join("external-link"),
    )
    .unwrap();
    let context = ImageBuildContext::from_directory(root.path()).unwrap();
    let mut archive = tar::Archive::new(std::io::Cursor::new(context.as_bytes()));
    let mut files = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        use std::io::Read;
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        assert!(entry.header().entry_type().is_file());
        let mut data = String::new();
        entry.read_to_string(&mut data).unwrap();
        files.insert(name, data);
    }
    assert_eq!(files["original"], "data");
    assert_eq!(files["hardlink"], "data");
    assert_eq!(files["external-link"], "outside data");
}

#[test]
fn rejects_fifo_with_path_and_type() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(root.path().join("pipe"))
            .status()
            .unwrap()
            .success()
    );
    let error = ImageBuildContext::from_directory(root.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("FIFO") && error.contains("pipe"), "{error}");
}

#[test]
fn rejects_device_records_with_path_and_type() {
    for (kind, label) in [
        (tar::EntryType::Char, "character device"),
        (tar::EntryType::Block, "block device"),
        (tar::EntryType::Fifo, "FIFO"),
    ] {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(0o600);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "special", std::io::empty())
            .unwrap();
        let error = ImageBuildContext::from_tar(builder.into_inner().unwrap())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(label) && error.contains("special"),
            "{error}"
        );
    }
}
