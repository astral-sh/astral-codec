//! Applying archived Unix attributes through an already opened capability.
//!
//! On other platforms, extraction rejects an enabled [`MetadataPolicy`] before
//! touching the destination, so these functions only report that it is unsupported.

use std::{io, path::Path};

#[cfg(unix)]
use std::os::fd::AsFd;

use cap_std::fs::Dir;
#[cfg(unix)]
use cap_std::fs::{OpenOptions, OpenOptionsExt as _};

use super::MetadataPolicy;
use crate::{ExtractError, MemberMetadata, UnixXattr};

/// The subset of [`crate::UnixMetadata`] selected by [`MetadataPolicy`].
#[derive(Clone, Debug, Default)]
pub(in crate::extract) struct PreservedMetadata {
    pub(in crate::extract) mode: Option<u32>,
    pub(in crate::extract) uid: Option<u32>,
    pub(in crate::extract) gid: Option<u32>,
    pub(in crate::extract) mtime: Option<i64>,
    pub(in crate::extract) xattrs: Vec<UnixXattr>,
}

/// A filesystem failure while applying one preserved attribute.
pub(in crate::extract) struct MetadataError {
    pub(in crate::extract) operation: &'static str,
    pub(in crate::extract) source: io::Error,
}

impl MetadataError {
    pub(in crate::extract) fn new(operation: &'static str, source: impl Into<io::Error>) -> Self {
        Self {
            operation,
            source: source.into(),
        }
    }
}

impl PreservedMetadata {
    pub(in crate::extract) fn prepare<E>(
        metadata: &MemberMetadata,
        policy: MetadataPolicy,
    ) -> Result<Self, ExtractError<E>> {
        let position = metadata.position;
        let unix = &metadata.unix;
        let (uid, gid) = if policy.preserve_ownership {
            (
                owner_id(position, "user id", unix.uid)?,
                owner_id(position, "group id", unix.gid)?,
            )
        } else {
            (None, None)
        };
        let mtime = unix
            .mtime
            .filter(|_| policy.preserve_mtime)
            .map(|value| {
                i64::try_from(value).map_err(|_| {
                    ExtractError::unapplicable_metadata(position, "modification time", value)
                })
            })
            .transpose()?;
        Ok(Self {
            mode: unix.mode.filter(|_| policy.preserve_permissions),
            uid,
            gid,
            mtime,
            xattrs: if policy.preserve_xattrs {
                unix.xattrs.clone()
            } else {
                Vec::new()
            },
        })
    }

    pub(in crate::extract) fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.mtime.is_none()
            && self.xattrs.is_empty()
    }
}

/// Converts an archived owner id, rejecting `u32::MAX`, which `fchown` reads as "unchanged".
fn owner_id<E>(
    position: u64,
    field: &'static str,
    value: Option<u64>,
) -> Result<Option<u32>, ExtractError<E>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match u32::try_from(value) {
        Ok(raw) if raw != u32::MAX => Ok(Some(raw)),
        _ => Err(ExtractError::unapplicable_metadata(position, field, value)),
    }
}

/// Applies ownership, mode, extended attributes, then mtime to an open inode.
///
/// Ownership goes first because `chown` clears setuid and setgid bits, and
/// mtime goes last so the earlier changes cannot disturb it.
#[cfg(unix)]
pub(in crate::extract) fn apply_fd(
    fd: impl AsFd,
    metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    let fd = fd.as_fd();
    if metadata.uid.is_some() || metadata.gid.is_some() {
        rustix::fs::fchown(
            fd,
            metadata.uid.map(rustix::fs::Uid::from_raw),
            metadata.gid.map(rustix::fs::Gid::from_raw),
        )
        .map_err(|error| MetadataError::new("set ownership", error))?;
    }
    if let Some(mode) = metadata.mode {
        rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode(mode))
            .map_err(|error| MetadataError::new("set permissions", error))?;
    }
    apply_fd_xattrs(fd, &metadata.xattrs)?;
    if let Some(mtime) = metadata.mtime {
        rustix::fs::futimens(fd, &timestamps(mtime))
            .map_err(|error| MetadataError::new("set modification time", error))?;
    }
    Ok(())
}

/// Applies metadata to the directory at `path`, or to `directory` itself when `path` is empty.
///
/// Capability directories are opened with `O_PATH`, which rejects `fchown`,
/// `fchmod`, `futimens`, and `fsetxattr`, so the directory is reopened for reading.
#[cfg(unix)]
pub(in crate::extract) fn apply_directory(
    directory: &Dir,
    path: &Path,
    metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    let opened;
    let directory = if path.as_os_str().is_empty() {
        directory
    } else {
        opened = directory
            .open_dir(path)
            .map_err(|source| MetadataError::new("open directory", source))?;
        &opened
    };
    let fd = rustix::fs::openat(
        directory,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| MetadataError::new("open directory", error))?;
    apply_fd(fd, metadata)
}

/// Applies metadata to the file at `path` without following a final symbolic link.
#[cfg(unix)]
pub(in crate::extract) fn apply_file(
    directory: &Dir,
    path: &Path,
    metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    let file = directory
        .open_with(path, &options)
        .map_err(|source| MetadataError::new("open file", source))?;
    apply_fd(&file, metadata)
}

/// Applies metadata to a symbolic link without following it.
#[cfg(unix)]
pub(in crate::extract) fn apply_symlink(
    directory: &Dir,
    path: &Path,
    metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    if metadata.uid.is_some() || metadata.gid.is_some() {
        rustix::fs::chownat(
            directory,
            path,
            metadata.uid.map(rustix::fs::Uid::from_raw),
            metadata.gid.map(rustix::fs::Gid::from_raw),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| MetadataError::new("set ownership", error))?;
    }
    if !metadata.xattrs.is_empty() {
        #[cfg(target_os = "linux")]
        {
            let fd = rustix::fs::openat(
                directory,
                path,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| MetadataError::new("open symbolic link", error))?;
            apply_fd_xattrs(fd, &metadata.xattrs)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(MetadataError::new(
                "set extended attribute",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "symbolic link extended attributes are not supported on this platform",
                ),
            ));
        }
    }
    if let Some(mtime) = metadata.mtime {
        rustix::fs::utimensat(
            directory,
            path,
            &timestamps(mtime),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| MetadataError::new("set modification time", error))?;
    }
    Ok(())
}

/// Sets the modification time while leaving the access time unchanged.
#[cfg(unix)]
fn timestamps(mtime: i64) -> rustix::fs::Timestamps {
    rustix::fs::Timestamps {
        last_access: rustix::fs::Timespec {
            tv_sec: 0,
            tv_nsec: rustix::fs::UTIME_OMIT,
        },
        last_modification: rustix::fs::Timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
    }
}

#[cfg(unix)]
fn apply_fd_xattrs(fd: impl AsFd, xattrs: &[UnixXattr]) -> Result<(), MetadataError> {
    if xattrs.is_empty() {
        return Ok(());
    }
    #[cfg(any(
        target_os = "android",
        target_os = "hurd",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    {
        let fd = fd.as_fd();
        for xattr in xattrs {
            rustix::fs::fsetxattr(
                fd,
                xattr.name.as_str(),
                &xattr.value,
                rustix::fs::XattrFlags::empty(),
            )
            .map_err(|error| MetadataError::new("set extended attribute", error))?;
        }
        Ok(())
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "hurd",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    )))]
    {
        let _ = fd;
        Err(MetadataError::new(
            "set extended attribute",
            io::Error::new(
                io::ErrorKind::Unsupported,
                "extended attributes are not supported on this platform",
            ),
        ))
    }
}

#[cfg(not(unix))]
pub(in crate::extract) fn apply_fd(
    _fd: impl Sized,
    _metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    Err(unsupported())
}

#[cfg(not(unix))]
pub(in crate::extract) fn apply_directory(
    _directory: &Dir,
    _path: &Path,
    _metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    Err(unsupported())
}

#[cfg(not(unix))]
pub(in crate::extract) fn apply_file(
    _directory: &Dir,
    _path: &Path,
    _metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    Err(unsupported())
}

#[cfg(not(unix))]
pub(in crate::extract) fn apply_symlink(
    _directory: &Dir,
    _path: &Path,
    _metadata: &PreservedMetadata,
) -> Result<(), MetadataError> {
    Err(unsupported())
}

#[cfg(not(unix))]
fn unsupported() -> MetadataError {
    MetadataError::new(
        "apply unix metadata",
        io::Error::new(
            io::ErrorKind::Unsupported,
            "preserving archived Unix metadata is not supported on this platform",
        ),
    )
}
