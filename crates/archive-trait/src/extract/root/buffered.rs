//! Single-task creation and replacement of validated small files.

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
    EntryId, ExtractedEntry, FileOpenMode, NormalizedPath, directory_is_empty, entry_capability,
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

/// A failure while creating or replacing a validated buffered file.
pub(super) enum BufferedFileError {
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
    pub(super) path: NormalizedPath,
    pub(super) executable: bool,
    pub(super) contents: Vec<u8>,
    pub(super) replacement: BufferedFileReplacement,
}

/// Implicit parents and files share one bounded, archive-ordered queue.
pub(super) enum BufferedEntry {
    Directory {
        entry: EntryId,
        parent: EntryId,
        path: NormalizedPath,
    },
    File(BufferedFile),
}

/// The reusable buffers and first error produced by an ordered file batch.
pub(super) struct BufferedFileBatchResult {
    pub(super) buffers: Vec<Vec<u8>>,
    pub(super) directories: Vec<(EntryId, ExtractedEntry)>,
    pub(super) directory_handle: Option<(EntryId, Arc<Dir>)>,
    pub(super) error: Option<(PathBuf, BufferedFileError)>,
}

impl BufferedFileError {
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
    files: Vec<BufferedEntry>,
    root: &Arc<Dir>,
    mut directory_handle: Option<(EntryId, Arc<Dir>)>,
    cancellation: &AtomicBool,
) -> BufferedFileBatchResult {
    let mut buffers = Vec::with_capacity(files.len());
    let mut directories = Vec::new();
    let mut error = None;
    for file in files {
        match file {
            BufferedEntry::Directory {
                entry,
                parent,
                path,
            } => {
                if error.is_none() && !cancellation.load(Ordering::Acquire) {
                    let (directory, relative) =
                        entry_capability(root, directory_handle.as_ref(), &path, parent);
                    match create_parent(&directory, &relative) {
                        Ok((directory, state)) => {
                            directories.push((entry, state));
                            directory_handle = Some((entry, Arc::new(directory)));
                        }
                        Err(source) => error = Some((path.to_path_buf(), source)),
                    }
                }
            }
            BufferedEntry::File(file) => {
                if error.is_none() && !cancellation.load(Ordering::Acquire) {
                    // Drop an old handle before replacement (required on Windows).
                    if directory_handle
                        .as_ref()
                        .is_some_and(|(entry, _)| *entry == file.entry)
                    {
                        directory_handle = None;
                    }
                    let (directory, relative) =
                        entry_capability(root, directory_handle.as_ref(), &file.path, file.parent);
                    if let Err(source) = write_buffered_file(
                        &directory,
                        &relative,
                        file.executable,
                        &file.contents,
                        file.replacement,
                    ) {
                        error = Some((file.path.to_path_buf(), source));
                    }
                }
                buffers.push(file.contents);
            }
        }
    }
    BufferedFileBatchResult {
        buffers,
        directories,
        directory_handle,
        error,
    }
}

fn create_parent(directory: &Dir, path: &Path) -> Result<(Dir, ExtractedEntry), BufferedFileError> {
    let create_error = match directory
        .create_dir(path)
        .and_then(|()| directory.open_dir(path))
    {
        Ok(created) => return Ok((created, ExtractedEntry::CreatedDirectory)),
        Err(error) => error,
    };
    match directory.symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata_is_link(&metadata) => directory
            .open_dir(path)
            .map(|directory| (directory, ExtractedEntry::AmbientDirectory))
            .map_err(|source| BufferedFileError::filesystem("open directory", source)),
        Ok(_) => Err(BufferedFileError::Collision),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(
            BufferedFileError::filesystem("create directory", create_error),
        ),
        Err(source) => Err(BufferedFileError::filesystem("inspect", source)),
    }
}

/// Creates or safely replaces and writes one fully validated small file.
pub(super) fn write_buffered_file(
    directory: &Dir,
    path: &Path,
    executable: bool,
    contents: &[u8],
    replacement: BufferedFileReplacement,
) -> Result<(), BufferedFileError> {
    // Unique destination access makes this the common duplicate-member path.
    // If the leaf changed unexpectedly, fall through to no-follow inspection.
    if replacement == BufferedFileReplacement::ExpectedFile && directory.remove_file(path).is_ok() {
        let file = open_new_file(directory, path, executable)
            .map_err(|source| BufferedFileError::filesystem("create file", source))?;
        return write_buffered_contents(file, contents);
    }

    let create_error = match open_new_file(directory, path, executable) {
        Ok(file) => return write_buffered_contents(file, contents),
        Err(error) => error,
    };
    let metadata = match directory.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(BufferedFileError::filesystem("create file", create_error));
        }
        Err(error) => return Err(BufferedFileError::filesystem("inspect", error)),
    };
    if replacement == BufferedFileReplacement::Disallowed {
        return Err(BufferedFileError::Collision);
    }
    remove_buffered_leaf(directory, path, &metadata)?;
    let file = open_new_file(directory, path, executable)
        .map_err(|source| BufferedFileError::filesystem("create file", source))?;
    write_buffered_contents(file, contents)
}

fn write_buffered_contents(mut file: CapFile, contents: &[u8]) -> Result<(), BufferedFileError> {
    file.write_all(contents)
        .map_err(|source| BufferedFileError::filesystem("write file", source))
}

fn open_new_file(directory: &Dir, path: &Path, executable: bool) -> io::Result<CapFile> {
    let options = FileOpenMode::CreateNew { executable }.options();
    directory.open_with(path, &options)
}

fn remove_buffered_leaf(
    directory: &Dir,
    path: &Path,
    metadata: &Metadata,
) -> Result<(), BufferedFileError> {
    if metadata.is_dir() && !metadata_is_link(metadata) {
        let is_empty = directory_is_empty(directory, path)
            .map_err(|source| BufferedFileError::filesystem("inspect directory", source))?;
        if !is_empty {
            return Err(BufferedFileError::Collision);
        }
        return directory
            .remove_dir(path)
            .map_err(|source| BufferedFileError::filesystem("remove directory", source));
    }

    remove_file_or_symlink(directory, path, metadata_is_link(metadata))
        .map_err(|source| BufferedFileError::filesystem("remove file", source))
}
