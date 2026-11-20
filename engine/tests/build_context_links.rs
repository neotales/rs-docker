//! Symlinks are archived without dereferencing their targets.
#![cfg(unix)]
use neotales_docker::ImageBuildContext;
use std::{collections::BTreeMap, fs, io::Cursor, os::unix::fs::symlink};

#[test]
fn links_inside_and_outside_are_recorded_without_reading_targets() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Dockerfile"), "FROM scratch\n").unwrap();
    fs::write(root.path().join("target"), "inside").unwrap();
    fs::write(outside.path().join("outside"), "secret").unwrap();
    symlink("target", root.path().join("in")).unwrap();
    symlink(outside.path().join("outside"), root.path().join("out")).unwrap();
    let context = ImageBuildContext::from_directory(root.path()).unwrap();
    let links: BTreeMap<_, _> = tar::Archive::new(Cursor::new(context.as_bytes()))
        .entries()
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.path().unwrap().into_owned(),
                (
                    entry.header().entry_type(),
                    entry.link_name().unwrap().map(std::borrow::Cow::into_owned),
                ),
            )
        })
        .collect();
    assert!(links[std::path::Path::new("in")].0.is_symlink());
    assert_eq!(
        links[std::path::Path::new("in")].1.as_deref(),
        Some(std::path::Path::new("target"))
    );
    assert!(links[std::path::Path::new("out")].0.is_symlink());
    assert_eq!(
        links[std::path::Path::new("out")].1.as_deref(),
        Some(outside.path().join("outside").as_path())
    );
    assert!(
        !context
            .as_bytes()
            .windows(6)
            .any(|window| window == b"secret")
    );
}

#[test]
fn refuses_archive_entries_nested_beneath_symlinks_in_either_order() {
    for link_first in [false, true] {
        let mut builder = tar::Builder::new(Vec::new());
        let append_link = |builder: &mut tar::Builder<Vec<u8>>| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o777);
            header.set_size(0);
            builder
                .append_link(&mut header, "link", "../../outside")
                .unwrap();
        };
        let append_file = |builder: &mut tar::Builder<Vec<u8>>| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "link/file", std::io::empty())
                .unwrap();
        };
        if link_first {
            append_link(&mut builder);
            append_file(&mut builder);
        } else {
            append_file(&mut builder);
            append_link(&mut builder);
        }
        assert!(ImageBuildContext::from_tar(builder.into_inner().unwrap()).is_err());
    }
}
