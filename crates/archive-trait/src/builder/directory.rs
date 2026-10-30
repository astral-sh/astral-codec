//! Filesystem-backed archive construction.
//!
//! This module provides [`Builder::add_directory_all`] and the filesystem
//! constructors for [`FilePayload`]. It requires the `fs` feature.

use std::{
    collections::VecDeque,
    io::{self, Read},
    mem,
    ops::Range,
    path::{Path, PathBuf},
};

use tokio::io::AsyncSeekExt;

use super::{
    ArchiveBuilder, ArchivedEntry, BuildEntries, BuildError, BuildFailure, Builder, EntryMetadata,
    FILE_PAYLOAD_CHUNK_BYTES, FilePayload, arithmetic_overflow,
    traversal::{TraversalEntry, TraversalKind, TraversalStream, stream_directory_entries},
};

const BUFFERED_SOURCE_FILE_BYTES: usize = 1024 * 1024;
// A preparation batch may exceed this target by one buffered file, so its
// payload storage remains below twice this value.
const SOURCE_FILE_PREPARATION_BATCH_BYTES: usize = BUFFERED_SOURCE_FILE_BYTES;

impl FilePayload<'static> {
    /// Opens `path` and creates a payload from the complete regular file.
    pub async fn from_path<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = tokio::fs::File::open(path).await?;
        Self::from_file(file).await
    }

    /// Creates a payload from the unread contents of a [`tokio::fs::File`].
    ///
    /// The declared size is the file length minus its current stream position.
    /// This constructor rejects filesystem objects that are not regular files.
    pub async fn from_file(mut file: tokio::fs::File) -> io::Result<Self> {
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(io::Error::other(
                "file payload source is not a regular file",
            ));
        }
        let position = file.stream_position().await?;
        Ok(Self::new(metadata.len().saturating_sub(position), file))
    }
}

impl<B: ArchiveBuilder> Builder<B> {
    /// Recursively adds a filesystem directory beneath its UTF-8 basename.
    ///
    /// Entries are visited in deterministic sorted order and files are streamed
    /// with bounded memory. Source symbolic links are rejected by default;
    /// [`BuilderPolicy::symlink_policy`](super::BuilderPolicy::symlink_policy) can instead preserve them. A late
    /// traversal or validation failure may leave partial output and poison
    /// this builder.
    pub async fn add_directory_all<P: AsRef<Path>>(
        &mut self,
        source: P,
    ) -> Result<(), BuildError<B::Error>> {
        self.state.ensure_active()?;
        let source = source.as_ref().to_path_buf();
        let mut entries = stream_directory_entries(
            source,
            self.state.policy.name_validation,
            self.state.policy.symlink_policy,
        )
        .map_err(BuildError::Traversal)?;
        self.state.begin_write();
        let mut traversal = DirectoryBuild {
            entries: &mut self.state.entries,
            source_buffer: mem::take(&mut self.state.source_buffer),
            emitted: false,
        };
        let write_result =
            write_directory_entries(&mut self.backend, &mut entries, &mut traversal).await;
        let traversal_result = entries
            .finish()
            .await
            .map_err(BuildError::Traversal)
            .map_err(BuildFailure::recoverable);
        let result = write_result.and(traversal_result);
        let DirectoryBuild {
            entries: _,
            source_buffer,
            emitted,
        } = traversal;
        self.state.complete_write();
        self.state.source_buffer = source_buffer;
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let (error, hook_poisoned) = error.into_parts();
                if emitted || hook_poisoned {
                    self.state.poison();
                }
                Err(error)
            }
        }
    }
}

async fn write_directory_entries<B: ArchiveBuilder>(
    builder: &mut B,
    entries: &mut TraversalStream,
    traversal: &mut DirectoryBuild<'_>,
) -> Result<(), BuildFailure<B::Error>> {
    while let Some(entries) = entries.recv().await {
        let mut entries = VecDeque::from(entries);
        while !entries.is_empty() {
            let buffer = mem::take(&mut traversal.source_buffer);
            let (prepared, remaining) = prepare_directory_entries(entries, buffer)
                .await
                .map_err(SourceError::into_build_error)
                .map_err(BuildFailure::recoverable)?;
            entries = remaining;
            let PreparedDirectoryBatch {
                entries: prepared_entries,
                mut buffer,
            } = prepared;
            let result =
                write_prepared_directory_entries(builder, prepared_entries, &mut buffer, traversal)
                    .await;
            traversal.source_buffer = buffer;
            result?;
        }
    }
    Ok(())
}

async fn write_prepared_directory_entries<B: ArchiveBuilder>(
    builder: &mut B,
    entries: Vec<PreparedTraversalEntry>,
    buffer: &mut Vec<u8>,
    traversal: &mut DirectoryBuild<'_>,
) -> Result<(), BuildFailure<B::Error>> {
    for entry in entries {
        let reservation = traversal
            .entries
            .preflight_entry(
                &entry.archive_path,
                if matches!(&entry.kind, PreparedTraversalKind::Directory) {
                    ArchivedEntry::Directory { explicit: true }
                } else {
                    ArchivedEntry::NonDirectory
                },
            )
            .map_err(BuildFailure::recoverable)?;
        match entry.kind {
            PreparedTraversalKind::Directory => {
                builder.write_directory_member(&entry.archive_path).await?;
            }
            PreparedTraversalKind::BufferedFile { range, executable } => {
                let data = buffer.get(range).ok_or_else(|| {
                    BuildFailure::recoverable(arithmetic_overflow(
                        "prepared source file buffer range",
                    ))
                })?;
                let mut payload = FilePayload::from(data);
                builder
                    .write_file_member(
                        &entry.archive_path,
                        &mut payload,
                        EntryMetadata::default().executable(executable),
                    )
                    .await?;
            }
            PreparedTraversalKind::StreamingFile {
                file,
                path,
                size,
                executable,
            } => {
                let mut file = tokio::fs::File::from_std(file);
                file.set_max_buf_size(FILE_PAYLOAD_CHUNK_BYTES);
                let mut payload =
                    FilePayload::streaming(size, file, mem::take(buffer), Some(path.as_path()));
                let result = builder
                    .write_file_member(
                        &entry.archive_path,
                        &mut payload,
                        EntryMetadata::default().executable(executable),
                    )
                    .await;
                payload.swap_buffer(buffer);
                result?;
            }
            PreparedTraversalKind::SymbolicLink { target } => {
                builder
                    .write_symbolic_link_member(&entry.archive_path, &target)
                    .await?;
            }
        }
        traversal
            .entries
            .commit_entry(&entry.archive_path, reservation);
        traversal.emitted = true;
    }
    Ok(())
}

struct DirectoryBuild<'entries> {
    entries: &'entries mut BuildEntries,
    source_buffer: Vec<u8>,
    emitted: bool,
}

struct PreparedDirectoryBatch {
    entries: Vec<PreparedTraversalEntry>,
    buffer: Vec<u8>,
}

struct PreparedTraversalEntry {
    archive_path: String,
    kind: PreparedTraversalKind,
}

enum PreparedTraversalKind {
    Directory,
    BufferedFile {
        range: Range<usize>,
        executable: bool,
    },
    StreamingFile {
        file: std::fs::File,
        path: PathBuf,
        size: u64,
        executable: bool,
    },
    SymbolicLink {
        target: String,
    },
}

async fn prepare_directory_entries(
    mut entries: VecDeque<TraversalEntry>,
    mut buffer: Vec<u8>,
) -> Result<(PreparedDirectoryBatch, VecDeque<TraversalEntry>), SourceError> {
    tokio::task::spawn_blocking(move || {
        buffer.clear();
        let mut prepared = Vec::with_capacity(entries.len());
        while let Some(entry) = entries.pop_front() {
            let TraversalEntry {
                source,
                archive_path,
                kind,
            } = entry;
            let (kind, batch_complete) = match kind {
                TraversalKind::Directory => (PreparedTraversalKind::Directory, false),
                TraversalKind::Regular => prepare_regular_file(source, &mut buffer)?,
                TraversalKind::SymbolicLink { target } => {
                    (PreparedTraversalKind::SymbolicLink { target }, false)
                }
            };
            prepared.push(PreparedTraversalEntry { archive_path, kind });
            if batch_complete {
                break;
            }
        }
        Ok((
            PreparedDirectoryBatch {
                entries: prepared,
                buffer,
            },
            entries,
        ))
    })
    .await
    .map_err(SourceError::BlockingTask)?
}

fn prepare_regular_file(
    path: PathBuf,
    buffer: &mut Vec<u8>,
) -> Result<(PreparedTraversalKind, bool), SourceError> {
    let file = std::fs::File::open(&path)
        .map_err(|source| SourceError::filesystem("open source file", &path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| SourceError::filesystem("inspect source file", &path, source))?;
    if !metadata.is_file() {
        return Err(SourceError::filesystem(
            "inspect source file",
            &path,
            io::Error::other("source is not a regular file"),
        ));
    }
    let size = metadata.len();
    let executable = is_executable(&metadata);
    if size > BUFFERED_SOURCE_FILE_BYTES as u64 {
        return Ok((
            PreparedTraversalKind::StreamingFile {
                file,
                path,
                size,
                executable,
            },
            true,
        ));
    }
    let payload_size = usize::try_from(size).map_err(|_| SourceError::ArithmeticOverflow {
        context: "buffered source file size",
    })?;
    let start = buffer.len();
    let end = start
        .checked_add(payload_size)
        .ok_or(SourceError::ArithmeticOverflow {
            context: "buffered source batch size",
        })?;
    buffer.resize(end, 0);
    (&file)
        .read_exact(&mut buffer[start..end])
        .map_err(|source| SourceError::filesystem("read source file", &path, source))?;
    Ok((
        PreparedTraversalKind::BufferedFile {
            range: start..end,
            executable,
        },
        buffer.len() >= SOURCE_FILE_PREPARATION_BATCH_BYTES,
    ))
}

enum SourceError {
    Filesystem {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    BlockingTask(tokio::task::JoinError),
    ArithmeticOverflow {
        context: &'static str,
    },
}

impl SourceError {
    fn filesystem(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Filesystem {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }

    fn into_build_error<E>(self) -> BuildError<E> {
        match self {
            Self::Filesystem {
                operation,
                path,
                source,
            } => BuildError::Filesystem {
                operation,
                path,
                source,
            },
            Self::BlockingTask(error) => BuildError::BlockingTask(error),
            Self::ArithmeticOverflow { context } => BuildError::ArithmeticOverflow { context },
        }
    }
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}
