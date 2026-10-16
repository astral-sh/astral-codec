//! Single-task creation of parent directories and validated small files.

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cap_std::fs::{Dir, File as CapFile, Metadata};

use super::{
    DirectoryHandles, EntryId, ExtractedEntry, FileOpenMode, directory_is_empty, entry_capability,
    metadata_is_link, remove_file_or_symlink,
};
use crate::ExtractError;

/// Whether a buffered file may replace an existing destination leaf.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum BufferedFileReplacement {
    /// An existing leaf is a collision.
    Disallowed,
    /// An existing leaf may be replaced after no-follow inspection.
    Allowed,
    /// The leaf is an archive-owned file and may use the direct replacement path.
    ExpectedFile,
}

/// A failure while creating a parent or writing a validated buffered file.
pub(super) enum BufferedError {
    Collision,
    Filesystem {
        operation: &'static str,
        source: io::Error,
    },
}

/// One fully validated small file prepared for ordered batch creation.
pub(super) struct BufferedFile {
    pub(super) entry: EntryId,
    pub(super) parent: EntryId,
    pub(super) path: PathBuf,
    pub(super) executable: bool,
    pub(super) contents: Vec<u8>,
    pub(super) replacement: BufferedFileReplacement,
}

/// Parent creation and payload writes execute in archive order.
pub(super) enum BufferedOperation {
    Directory {
        entry: EntryId,
        parent: EntryId,
        path: PathBuf,
    },
    File(BufferedFile),
}

/// The reusable buffers and first error produced by an ordered file batch.
pub(super) struct BufferedBatchResult {
    pub(super) handles: DirectoryHandles,
    pub(super) directories: Vec<(EntryId, ExtractedEntry)>,
    pub(super) buffers: Vec<Vec<u8>>,
    pub(super) error: Option<(PathBuf, BufferedError)>,
}

impl BufferedError {
    fn filesystem(operation: &'static str, source: io::Error) -> Self {
        Self::Filesystem { operation, source }
    }

    pub(super) fn into_extract<E>(self, path: &Path) -> ExtractError<E> {
        match self {
            Self::Collision => ExtractError::PathCollision {
                path: path.to_owned(),
            },
            Self::Filesystem { operation, source } => {
                ExtractError::filesystem(operation, path.to_owned(), source)
            }
        }
    }
}

/// Creates buffered files in archive order and stops after cancellation or the first failure.
pub(super) fn write_buffered_files(
    root: Arc<Dir>,
    mut handles: DirectoryHandles,
    operations: Vec<BufferedOperation>,
    cancellation: &AtomicBool,
) -> BufferedBatchResult {
    let mut buffers = Vec::new();
    let mut directories = Vec::new();
    let mut error = None;
    for operation in operations {
        let execute = error.is_none() && !cancellation.load(Ordering::Acquire);
        match operation {
            BufferedOperation::Directory {
                entry,
                parent,
                path,
            } => {
                if execute {
                    let (directory, relative_path) =
                        entry_capability(&root, &handles, &path, parent);
                    match create_parent(&directory, &relative_path) {
                        Ok((opened, state)) => {
                            handles.insert(entry, parent, Arc::new(opened));
                            directories.push((entry, state));
                        }
                        Err(source) => error = Some((path, source)),
                    }
                }
            }
            BufferedOperation::File(file) => {
                if execute {
                    handles.remove(file.entry);
                    let (directory, relative_path) =
                        entry_capability(&root, &handles, &file.path, file.parent);
                    if let Err(source) = write_buffered_file(
                        &directory,
                        &relative_path,
                        file.executable,
                        &file.contents,
                        file.replacement,
                    ) {
                        error = Some((file.path, source));
                    }
                }
                buffers.push(file.contents);
            }
        }
    }
    BufferedBatchResult {
        handles,
        directories,
        buffers,
        error,
    }
}

/// Match implicit-parent creation: accept real ambient directories, and never
/// follow or replace a symbolic link or another non-directory ancestor.
fn create_parent(directory: &Dir, path: &Path) -> Result<(Dir, ExtractedEntry), BufferedError> {
    let create_error = match directory
        .create_dir(path)
        .and_then(|()| directory.open_dir(path))
    {
        Ok(opened) => return Ok((opened, ExtractedEntry::CreatedDirectory)),
        Err(error) => error,
    };
    match directory.symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata_is_link(&metadata) => {}
        Ok(_) => return Err(BufferedError::Collision),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(BufferedError::filesystem("create directory", create_error));
        }
        Err(error) => return Err(BufferedError::filesystem("inspect", error)),
    }
    directory
        .open_dir(path)
        .map(|opened| (opened, ExtractedEntry::AmbientDirectory))
        .map_err(|source| BufferedError::filesystem("open directory", source))
}

/// Creates or safely replaces and writes one fully validated small file.
pub(super) fn write_buffered_file(
    directory: &Dir,
    path: &Path,
    executable: bool,
    contents: &[u8],
    replacement: BufferedFileReplacement,
) -> Result<(), BufferedError> {
    // Unique destination access makes this the common duplicate-member path.
    // If the leaf changed unexpectedly, fall through to no-follow inspection.
    if replacement == BufferedFileReplacement::ExpectedFile && directory.remove_file(path).is_ok() {
        let file = open_new_file(directory, path, executable)
            .map_err(|source| BufferedError::filesystem("create file", source))?;
        return write_buffered_contents(file, contents);
    }

    let create_error = match open_new_file(directory, path, executable) {
        Ok(file) => return write_buffered_contents(file, contents),
        Err(error) => error,
    };
    let metadata = match directory.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(BufferedError::filesystem("create file", create_error));
        }
        Err(error) => return Err(BufferedError::filesystem("inspect", error)),
    };
    if replacement == BufferedFileReplacement::Disallowed {
        return Err(BufferedError::Collision);
    }
    remove_buffered_leaf(directory, path, &metadata)?;
    let file = open_new_file(directory, path, executable)
        .map_err(|source| BufferedError::filesystem("create file", source))?;
    write_buffered_contents(file, contents)
}

fn write_buffered_contents(mut file: CapFile, contents: &[u8]) -> Result<(), BufferedError> {
    file.write_all(contents)
        .map_err(|source| BufferedError::filesystem("write file", source))
}

fn open_new_file(directory: &Dir, path: &Path, executable: bool) -> io::Result<CapFile> {
    let options = FileOpenMode::CreateNew { executable }.options();
    directory.open_with(path, &options)
}

fn remove_buffered_leaf(
    directory: &Dir,
    path: &Path,
    metadata: &Metadata,
) -> Result<(), BufferedError> {
    if metadata.is_dir() && !metadata_is_link(metadata) {
        let is_empty = directory_is_empty(directory, path)
            .map_err(|source| BufferedError::filesystem("inspect directory", source))?;
        if !is_empty {
            return Err(BufferedError::Collision);
        }
        return directory
            .remove_dir(path)
            .map_err(|source| BufferedError::filesystem("remove directory", source));
    }

    remove_file_or_symlink(directory, path, metadata_is_link(metadata))
        .map_err(|source| BufferedError::filesystem("remove file", source))
}
