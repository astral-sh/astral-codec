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

use super::{FileOpenMode, metadata_is_link, remove_directory_error, remove_file_or_symlink};
use crate::ExtractError;
use crate::extract::metadata::{PreservedMetadata, apply_fd};

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
    RemoveDirectory(io::Error),
    Filesystem {
        operation: &'static str,
        source: io::Error,
    },
}

/// One fully validated small file prepared for ordered batch creation.
pub(super) struct BufferedFile {
    pub(super) directory: Arc<Dir>,
    pub(super) relative_path: PathBuf,
    pub(super) error_path: PathBuf,
    pub(super) executable: bool,
    pub(super) contents: Vec<u8>,
    pub(super) replacement: BufferedFileReplacement,
    pub(super) metadata: PreservedMetadata,
}

/// The reusable buffers and first error produced by an ordered file batch.
pub(super) struct BufferedFileBatchResult {
    pub(super) buffers: Vec<Vec<u8>>,
    pub(super) error: Option<(PathBuf, BufferedFileError)>,
}

impl BufferedFileError {
    fn filesystem(operation: &'static str, source: io::Error) -> Self {
        Self::Filesystem { operation, source }
    }

    pub(super) fn into_extract<E>(self, path: PathBuf) -> ExtractError<E> {
        match self {
            Self::Collision => ExtractError::PathCollision { path },
            Self::RemoveDirectory(source) => remove_directory_error(path, source),
            Self::Filesystem { operation, source } => {
                ExtractError::filesystem(operation, path, source)
            }
        }
    }
}

/// Creates buffered files in archive order and stops after cancellation or the first failure.
pub(super) fn write_buffered_files(
    files: Vec<BufferedFile>,
    cancellation: &AtomicBool,
) -> BufferedFileBatchResult {
    let mut buffers = Vec::with_capacity(files.len());
    let mut error = None;
    for file in files {
        if error.is_none()
            && !cancellation.load(Ordering::Acquire)
            && let Err(source) = write_buffered_file(
                &file.directory,
                &file.relative_path,
                file.executable,
                &file.contents,
                file.replacement,
                &file.metadata,
            )
        {
            error = Some((file.error_path, source));
        }
        buffers.push(file.contents);
    }
    BufferedFileBatchResult { buffers, error }
}

/// Creates or safely replaces and writes one fully validated small file.
pub(super) fn write_buffered_file(
    directory: &Dir,
    path: &Path,
    executable: bool,
    contents: &[u8],
    replacement: BufferedFileReplacement,
    preserved: &PreservedMetadata,
) -> Result<(), BufferedFileError> {
    let mode = FileOpenMode::CreateNew { executable };
    // Unique destination access makes this the common duplicate-member path.
    // If the leaf changed unexpectedly, fall through to no-follow inspection.
    if replacement == BufferedFileReplacement::ExpectedFile && directory.remove_file(path).is_ok() {
        let file = mode
            .open(directory, path)
            .map_err(|source| BufferedFileError::filesystem("create file", source))?;
        return write_buffered_contents(file, contents, preserved);
    }

    let create_error = match mode.open(directory, path) {
        Ok(file) => return write_buffered_contents(file, contents, preserved),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => error,
        Err(error) => return Err(BufferedFileError::filesystem("create file", error)),
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
    let file = mode
        .open(directory, path)
        .map_err(|source| BufferedFileError::filesystem("create file", source))?;
    write_buffered_contents(file, contents, preserved)
}

fn write_buffered_contents(
    mut file: CapFile,
    contents: &[u8],
    metadata: &PreservedMetadata,
) -> Result<(), BufferedFileError> {
    file.write_all(contents)
        .map_err(|source| BufferedFileError::filesystem("write file", source))?;
    if metadata.is_empty() {
        return Ok(());
    }
    apply_fd(&file, metadata)
        .map_err(|error| BufferedFileError::filesystem(error.operation, error.source))
}

fn remove_buffered_leaf(
    directory: &Dir,
    path: &Path,
    metadata: &Metadata,
) -> Result<(), BufferedFileError> {
    if metadata.is_dir() && !metadata_is_link(metadata) {
        return directory
            .remove_dir(path)
            .map_err(BufferedFileError::RemoveDirectory);
    }

    remove_file_or_symlink(directory, path, metadata_is_link(metadata))
        .map_err(|source| BufferedFileError::filesystem("remove file", source))
}
