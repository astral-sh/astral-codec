//! Single-task creation and replacement of validated small files.

use std::{
    io::{self, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cap_std::fs::{Dir, File as CapFile};

use super::{FileOpenMode, LeafError, remove_existing_leaf};

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

/// One fully validated small file prepared for ordered batch creation.
pub(super) struct BufferedFile {
    pub(super) directory: Arc<Dir>,
    pub(super) relative_path: PathBuf,
    pub(super) error_path: PathBuf,
    pub(super) executable: bool,
    pub(super) contents: Vec<u8>,
    pub(super) replacement: BufferedFileReplacement,
}

/// The reusable buffers and first error produced by an ordered file batch.
pub(super) struct BufferedFileBatchResult {
    pub(super) buffers: Vec<Vec<u8>>,
    pub(super) error: Option<(PathBuf, LeafError)>,
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
) -> Result<(), LeafError> {
    let mode = FileOpenMode::CreateNew { executable };
    // Unique destination access makes this the common duplicate-member path.
    // If the leaf changed unexpectedly, fall through to no-follow inspection.
    if replacement == BufferedFileReplacement::ExpectedFile && directory.remove_file(path).is_ok() {
        let file = mode
            .open(directory, path)
            .map_err(|source| LeafError::filesystem("create file", source))?;
        return write_buffered_contents(file, contents);
    }

    let create_error = match mode.open(directory, path) {
        Ok(file) => return write_buffered_contents(file, contents),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => error,
        Err(error) => return Err(LeafError::filesystem("create file", error)),
    };
    let metadata = match directory.symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(LeafError::filesystem("create file", create_error));
        }
        Err(error) => return Err(LeafError::filesystem("inspect", error)),
    };
    if replacement == BufferedFileReplacement::Disallowed {
        return Err(LeafError::Collision);
    }
    remove_existing_leaf(directory, path, &metadata)?;
    let file = mode
        .open(directory, path)
        .map_err(|source| LeafError::filesystem("create file", source))?;
    write_buffered_contents(file, contents)
}

fn write_buffered_contents(mut file: CapFile, contents: &[u8]) -> Result<(), LeafError> {
    file.write_all(contents)
        .map_err(|source| LeafError::filesystem("write file", source))
}
