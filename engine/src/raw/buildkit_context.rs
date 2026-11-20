//! Race-resistant, bounded snapshots for a future fsutil `DiffCopy` sender.
//! This does not implement the wire state machine or daemon filters.

#![allow(dead_code)] // Not advertised until the full DiffCopy protocol exists.

use neotales_docker_buildkit::proto::FileStat;
use std::path::Path;

const MAX_ENTRIES: usize = 10_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContextError {
    InvalidPath,
    Refused,
    Limit,
    Changed,
    Unsupported,
}

pub(crate) struct Entry {
    pub(crate) stat: FileStat,
    pub(crate) data: Option<Vec<u8>>,
}

pub(crate) struct Snapshot {
    pub(crate) entries: Vec<Entry>,
}

/// Pin a single regular file and expose it under the requested Dockerfile name.
/// `DiffCopy` sends a filesystem, not a tar stream; synthesize the equivalent
/// root entries without ever reading siblings of the supplied file.
#[cfg(target_os = "linux")]
pub(crate) fn single_file(path: &Path, name: &str) -> Result<Snapshot, ContextError> {
    use rustix::fs::{Mode, OFlags, open};
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        path::Component,
    };

    let components: Vec<_> = Path::new(name).components().collect();
    if components.is_empty()
        || components.len() > 128
        || name.len() > 4096
        || components
            .iter()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(ContextError::InvalidPath);
    }
    let fd = open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ContextError::Refused)?;
    let pinned: std::fs::File = fd.into();
    let meta = pinned.metadata().map_err(|_| ContextError::Refused)?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(ContextError::Refused);
    }
    let size = meta.len();
    if size > MAX_BYTES {
        return Err(ContextError::Limit);
    }
    let mut file = std::fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| ContextError::Refused)?;
    let opened = file.metadata().map_err(|_| ContextError::Refused)?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
        return Err(ContextError::Changed);
    }
    let mut data = Vec::new();
    file.by_ref()
        .take(size + 1)
        .read_to_end(&mut data)
        .map_err(|_| ContextError::Refused)?;
    let after = file.metadata().map_err(|_| ContextError::Refused)?;
    if data.len() as u64 != size
        || after.len() != size
        || after.mtime() != meta.mtime()
        || after.mtime_nsec() != meta.mtime_nsec()
    {
        return Err(ContextError::Changed);
    }
    let mut entries = Vec::new();
    let mut prefix = std::path::PathBuf::new();
    for component in &components[..components.len() - 1] {
        prefix.push(component.as_os_str());
        entries.push(Entry {
            stat: FileStat {
                path: prefix.to_str().ok_or(ContextError::InvalidPath)?.to_owned(),
                mode: (1_u32 << 31) | 0o755,
                ..FileStat::default()
            },
            data: None,
        });
    }
    entries.push(Entry {
        stat: FileStat {
            path: name.to_owned(),
            mode: go_mode(meta.mode(), false),
            uid: meta.uid(),
            gid: meta.gid(),
            size: i64::try_from(size).map_err(|_| ContextError::Limit)?,
            mod_time: meta
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(meta.mtime_nsec()),
            ..FileStat::default()
        },
        data: Some(data),
    });
    Ok(Snapshot { entries })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn single_file(_path: &Path, _name: &str) -> Result<Snapshot, ContextError> {
    Err(ContextError::Unsupported)
}

/// Opens each entry under the held root using openat2, never following links.
#[cfg(target_os = "linux")]
pub(crate) fn snapshot(root: &Path, relative: &Path) -> Result<Snapshot, ContextError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
    use std::path::Component;
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(ContextError::InvalidPath);
    }
    let root = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ContextError::Refused)?;
    let directory = openat2(
        &root,
        if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        },
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| ContextError::Refused)?;
    let mut result = Snapshot {
        entries: Vec::new(),
    };
    let mut total = 0;
    walk(&directory, "", &mut result.entries, &mut total)?;
    Ok(result)
}

#[cfg(target_os = "linux")]
fn walk(
    directory: &impl std::os::fd::AsFd,
    prefix: &str,
    entries: &mut Vec<Entry>,
    total: &mut u64,
) -> Result<(), ContextError> {
    use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, openat2};
    use std::{
        io::Read,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };

    let mut dir = Dir::read_from(directory).map_err(|_| ContextError::Refused)?;
    let mut names = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry.map_err(|_| ContextError::Refused)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| ContextError::InvalidPath)?;
        if name == "." || name == ".." {
            continue;
        }
        if names.len().saturating_add(entries.len()) >= MAX_ENTRIES {
            return Err(ContextError::Limit);
        }
        names.push(name.to_owned());
    }
    names.sort_unstable();
    for name in names {
        if entries.len() >= MAX_ENTRIES {
            return Err(ContextError::Limit);
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if path.len() > 4096 || path.bytes().filter(|b| *b == b'/').count() >= 128 {
            return Err(ContextError::Limit);
        }
        let fd = openat2(
            directory,
            name.as_str(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| ContextError::Refused)?;
        let pinned: std::fs::File = fd.into();
        let meta = pinned.metadata().map_err(|_| ContextError::Refused)?;
        if !meta.is_dir() && !meta.is_file() {
            return Err(ContextError::Refused);
        }
        if meta.is_file() && meta.nlink() != 1 {
            return Err(ContextError::Refused);
        }
        // Reopen the pinned inode rather than the name, which might have been
        // swapped for a device or symlink since it was inspected. If procfs is
        // unavailable this fails closed.
        let mut file = std::fs::File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
            .map_err(|_| ContextError::Refused)?;
        let opened = file.metadata().map_err(|_| ContextError::Refused)?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err(ContextError::Changed);
        }
        let size = if meta.is_file() { meta.len() } else { 0 };
        *total = total.checked_add(size).ok_or(ContextError::Limit)?;
        if *total > MAX_BYTES {
            return Err(ContextError::Limit);
        }
        // fsutil serializes Go's os.FileMode, whose special bits differ
        // from POSIX mode_t even though the low permission bits agree.
        let stat = FileStat {
            path: path.clone(),
            mode: go_mode(meta.mode(), meta.is_dir()),
            uid: meta.uid(),
            gid: meta.gid(),
            size: i64::try_from(size).map_err(|_| ContextError::Limit)?,
            mod_time: meta
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(meta.mtime_nsec()),
            ..FileStat::default()
        };
        if meta.is_dir() {
            entries.push(Entry { stat, data: None });
            walk(&file, &path, entries, total)?;
        } else {
            let mut data = Vec::new();
            file.by_ref()
                .take(size + 1)
                .read_to_end(&mut data)
                .map_err(|_| ContextError::Refused)?;
            let after = file.metadata().map_err(|_| ContextError::Refused)?;
            if data.len() as u64 != size
                || after.len() != size
                || after.mtime() != meta.mtime()
                || after.mtime_nsec() != meta.mtime_nsec()
            {
                return Err(ContextError::Changed);
            }
            entries.push(Entry {
                stat,
                data: Some(data),
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn go_mode(unix_mode: u32, is_directory: bool) -> u32 {
    let mut mode = unix_mode & 0o777;
    if is_directory {
        mode |= 1_u32 << 31;
    }
    if unix_mode & 0o4000 != 0 {
        mode |= 1_u32 << 23;
    }
    if unix_mode & 0o2000 != 0 {
        mode |= 1_u32 << 22;
    }
    if unix_mode & 0o1000 != 0 {
        mode |= 1_u32 << 20;
    }
    mode
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn snapshot(_root: &Path, _relative: &Path) -> Result<Snapshot, ContextError> {
    Err(ContextError::Unsupported)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    #[test]
    fn snapshots_nested_files_and_refuses_escapes() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/file"), b"contents").unwrap();
        fs::set_permissions(
            root.path().join("sub/file"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        let result = snapshot(root.path(), Path::new("")).unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].stat.path, "sub");
        assert_eq!(result.entries[1].stat.path, "sub/file");
        assert_eq!(result.entries[1].stat.mode, 0o750);
        assert_eq!(
            result.entries[1].data.as_deref(),
            Some(b"contents".as_slice())
        );
        assert!(matches!(
            snapshot(root.path(), Path::new("../other")),
            Err(ContextError::InvalidPath)
        ));
        symlink("/etc", root.path().join("escape")).unwrap();
        assert!(matches!(
            snapshot(root.path(), Path::new("")),
            Err(ContextError::Refused)
        ));
    }

    #[test]
    fn rejects_multiple_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("one"), b"x").unwrap();
        fs::hard_link(root.path().join("one"), root.path().join("two")).unwrap();
        assert!(matches!(
            snapshot(root.path(), Path::new("")),
            Err(ContextError::Refused)
        ));
    }

    #[test]
    fn refuses_oversized_file_before_reading_it() {
        let root = tempfile::tempdir().unwrap();
        let file = fs::File::create(root.path().join("large")).unwrap();
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(matches!(
            snapshot(root.path(), Path::new("")),
            Err(ContextError::Limit)
        ));
    }

    #[test]
    fn single_file_snapshot_is_bounded_and_does_not_include_siblings() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("input");
        fs::write(&file, b"FROM scratch\n").unwrap();
        fs::write(root.path().join("sibling"), b"private").unwrap();
        let result = single_file(&file, "sub/Dockerfile").unwrap();
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].stat.path, "sub");
        assert_eq!(result.entries[1].stat.path, "sub/Dockerfile");
        assert_eq!(
            result.entries[1].data.as_deref(),
            Some(b"FROM scratch\n".as_slice())
        );
        assert!(matches!(
            single_file(&file, "../escape"),
            Err(ContextError::InvalidPath)
        ));
        symlink(&file, root.path().join("link")).unwrap();
        assert!(matches!(
            single_file(&root.path().join("link"), "Dockerfile"),
            Err(ContextError::Refused)
        ));
        fs::hard_link(&file, root.path().join("hardlink")).unwrap();
        assert!(matches!(
            single_file(&file, "Dockerfile"),
            Err(ContextError::Refused)
        ));
    }
}
