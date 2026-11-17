//! Streaming ZIP64 encoding.
//!
//! ## Compatibility notes
//!
//! - The decoder rejects archives with multiple apparent end-of-central-directory
//!   records. Encoding can finish successfully and still produce an archive that
//!   [`ZipArchive::open`](crate::ZipArchive::open) rejects if bytes in a member look
//!   like a second end record. [`CompressionMethod::Stored`] copies member bytes
//!   verbatim, and the default DEFLATE encoder can also preserve those bytes in
//!   uncompressed blocks.

use std::io::{self, SeekFrom};

use archive_trait::{
    ArchiveBuilder, BuildError, EntryMetadata, FilePayload, builder::BuildFailure,
};
use crc32fast::Hasher;
use flate2::{Compress, Compression, FlushCompress, Status};
use thiserror::Error;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use zip_framing::{
    Budget, BudgetError, CompressionMethod, LimitExceeded, Limits,
    constants::size,
    write::{END_RECORDS_SIZE, EntryKind, PendingMember, end_records},
};

use crate::payload::CHUNK_SIZE;

/// Options for one regular ZIP file.
///
/// Construct from [`EntryMetadata`] to set format-neutral file metadata.
/// Default options inherit the method configured by [`ZipEncoder::with_compression`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZipFileOptions {
    metadata: EntryMetadata,
    compression: Option<CompressionMethod>,
}

impl ZipFileOptions {
    /// Selects the compression method for this file.
    ///
    /// Empty files are always stored, regardless of this setting.
    pub fn with_compression(mut self, method: CompressionMethod) -> Self {
        self.compression = Some(method);
        self
    }
}

impl From<EntryMetadata> for ZipFileOptions {
    fn from(metadata: EntryMetadata) -> Self {
        Self {
            metadata,
            compression: None,
        }
    }
}

/// A streaming UTF-8 ZIP64 writer for [`ArchiveBuilder::builder`].
///
/// Output must be seekable, empty, and positioned at byte zero. Payloads are
/// streamed; only bounded directory metadata is retained. Local headers are
/// filled in after each payload, once its CRC and compressed size are known.
pub struct ZipEncoder<W> {
    writer: W,
    method: CompressionMethod,
    budget: Budget,
    position: u64,
    count: usize,
    directory: Vec<u8>,
    finished: bool,
}

impl<W> ZipEncoder<W> {
    /// Creates a DEFLATE encoder with default resource budgets.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            method: CompressionMethod::default(),
            budget: Budget::new(Limits::default()),
            position: 0,
            count: 0,
            directory: Vec::new(),
            finished: false,
        }
    }

    /// Selects the default compression method for nonempty regular files.
    ///
    /// Individual files can override this with [`ZipFileOptions::with_compression`].
    pub fn with_compression(mut self, method: CompressionMethod) -> Self {
        self.method = method;
        self
    }

    /// Sets archive, member, metadata, entry-count, and total-input budgets.
    ///
    /// The archive-size limit includes the central directory and end records.
    /// For DEFLATE members, compressed bytes are checked as they are written.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.budget.set_limits(limits);
        self
    }

    /// Returns the output without finalizing an unfinished archive.
    ///
    /// Use [`archive_trait::Builder::finish_into_inner`] before calling this
    /// method to obtain a completed archive.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: AsyncWrite + AsyncSeek + Unpin> ZipEncoder<W> {
    fn prepare_member<'a>(
        &'a mut self,
        path: &'a str,
        method: CompressionMethod,
        kind: EntryKind,
        size: u64,
    ) -> Result<MemberWriter<'a, W>, EncodeError> {
        let header = PendingMember::new(path, method, kind)?;
        if self.finished {
            return Err(EncodeError::Finished);
        }

        let local_header_size = header.local_header_size() as u64;
        let central_header_size = header.central_header_size() as u64;
        let mut budget = self.budget;
        budget.check_entry_count(self.count as u64 + 1)?;
        budget.charge_metadata(local_header_size + central_header_size)?;
        budget.charge_member(size)?;
        check_end_metadata(budget)?;

        let directory_size = (self.directory.len() as u64)
            .checked_add(central_header_size)
            .ok_or(EncodeError::Overflow)?;

        // Stored data has a known encoded size. DEFLATE can use the remaining
        // space after accounting for the headers and the end records.
        let known_payload_size = if method == CompressionMethod::Stored {
            size
        } else {
            0
        };
        let minimum_size = local_header_size
            .checked_add(known_payload_size)
            .ok_or(EncodeError::Overflow)?;
        let output = MemberWriter {
            header,
            writer: &mut self.writer,
            directory: &mut self.directory,
            budget,
            position: self.position,
            directory_size,
        };
        output.check_append(minimum_size)?;

        Ok(output)
    }

    async fn add_member(
        &mut self,
        path: &str,
        method: CompressionMethod,
        kind: EntryKind,
        payload: &mut FilePayload<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        let (position, budget) = self
            .prepare_member(path, method, kind, payload.size())
            .map_err(BuildFailure::recoverable)?
            .write_member(payload)
            .await
            .map_err(BuildFailure::poisoned)?;

        self.position = position;
        self.count += 1;
        self.budget = budget;

        Ok(())
    }

    fn prepare_end(&self) -> Result<Vec<u8>, EncodeError> {
        if self.finished {
            return Err(EncodeError::Finished);
        }

        check_end_metadata(self.budget)?;
        let directory_size = self.directory.len() as u64;
        check_archive_size(&self.budget, self.position, directory_size)?;
        Ok(end_records(
            self.count as u64,
            self.position,
            directory_size,
        )?)
    }

    async fn write_end(&mut self, end: &[u8]) -> Result<(), EncodeError> {
        self.writer.write_all(&self.directory).await?;
        self.writer.write_all(end).await?;
        self.writer.flush().await?;
        self.finished = true;

        Ok(())
    }
}

/// Writes one member with space reserved for the complete directory and end records.
struct MemberWriter<'a, W> {
    header: PendingMember<'a>,
    writer: &'a mut W,
    directory: &'a mut Vec<u8>,
    budget: Budget,
    position: u64,
    directory_size: u64,
}

impl<W: AsyncWrite + AsyncSeek + Unpin> MemberWriter<'_, W> {
    fn check_append(&self, length: u64) -> Result<u64, EncodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(EncodeError::Overflow)?;
        check_archive_size(&self.budget, end, self.directory_size)?;
        Ok(end)
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self.check_append(bytes.len() as u64)?;
        self.writer.write_all(bytes).await?;
        self.position = end;

        Ok(())
    }

    async fn compress_chunk(
        &mut self,
        compressor: &mut Compress,
        mut input: &[u8],
        finish: bool,
        output: &mut [u8],
    ) -> Result<(), EncodeError> {
        loop {
            let before_input = compressor.total_in();
            let before_output = compressor.total_out();
            let status = compressor
                .compress(
                    input,
                    output,
                    if finish {
                        FlushCompress::Finish
                    } else {
                        FlushCompress::None
                    },
                )
                .map_err(|_| EncodeError::Compression)?;

            let consumed = (compressor.total_in() - before_input) as usize;
            let produced = (compressor.total_out() - before_output) as usize;
            input = &input[consumed..];
            self.write_bytes(&output[..produced]).await?;

            if status == Status::StreamEnd || (!finish && input.is_empty()) {
                return Ok(());
            }

            if consumed == 0 && produced == 0 {
                return Err(EncodeError::Compression);
            }

            tokio::task::consume_budget().await;
        }
    }

    async fn write_member(
        mut self,
        payload: &mut FilePayload<'_>,
    ) -> Result<(u64, Budget), BuildError<EncodeError>> {
        let size = payload.size();
        let offset = self.position;
        self.write_bytes(&vec![0; self.header.local_header_size()])
            .await?;

        let start = self.position;
        let mut crc = Hasher::new();
        let mut compressor = match self.header.method() {
            CompressionMethod::Stored => None,
            CompressionMethod::Deflate => Some(Compress::new(Compression::default(), false)),
            _ => return Err(EncodeError::Compression.into()),
        };
        let mut output = if compressor.is_some() {
            vec![0; CHUNK_SIZE]
        } else {
            Vec::new()
        };

        while let Some(chunk) = payload.next_chunk().await? {
            for chunk in chunk.chunks(CHUNK_SIZE) {
                crc.update(chunk);
                if let Some(compressor) = &mut compressor {
                    self.compress_chunk(compressor, chunk, false, &mut output)
                        .await?;
                } else {
                    self.write_bytes(chunk).await?;
                }

                tokio::task::consume_budget().await;
            }
        }

        if let Some(compressor) = &mut compressor {
            self.compress_chunk(compressor, &[], true, &mut output)
                .await?;
        }

        let member = self
            .header
            .finish(crc.finalize(), self.position - start, size, offset)
            .map_err(EncodeError::Framing)?;

        // Rewriting the reserved header does not advance the archive's end.
        self.writer
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(EncodeError::Io)?;
        self.writer
            .write_all(&member.local_header())
            .await
            .map_err(EncodeError::Io)?;
        self.writer
            .seek(SeekFrom::Start(self.position))
            .await
            .map_err(EncodeError::Io)?;

        member.append_central_header(self.directory);
        debug_assert_eq!(self.directory.len() as u64, self.directory_size);
        Ok((self.position, self.budget))
    }
}

impl<W: AsyncWrite + AsyncSeek + Unpin> ArchiveBuilder for ZipEncoder<W> {
    type Error = EncodeError;
    type FileOptions = ZipFileOptions;

    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>> {
        let end = self.prepare_end().map_err(BuildFailure::recoverable)?;

        self.write_end(&end).await.map_err(BuildFailure::poisoned)
    }

    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut FilePayload<'_>,
        options: Self::FileOptions,
    ) -> Result<(), BuildFailure<Self::Error>> {
        let method = if payload.size() == 0 {
            CompressionMethod::Stored
        } else {
            options.compression.unwrap_or(self.method)
        };
        self.add_member(
            path,
            method,
            EntryKind::File {
                executable: options.metadata.is_executable(),
            },
            payload,
        )
        .await
    }

    async fn write_directory_member(
        &mut self,
        path: &str,
    ) -> Result<(), BuildFailure<Self::Error>> {
        let path = if path.ends_with('/') {
            path.to_owned()
        } else {
            format!("{path}/")
        };
        self.add_member(
            &path,
            CompressionMethod::Stored,
            EntryKind::Directory,
            &mut FilePayload::from(&b""[..]),
        )
        .await
    }

    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildFailure<Self::Error>> {
        if target.is_empty() || target.len() > usize::from(u16::MAX) || target.contains('\0') {
            return Err(BuildFailure::recoverable(EncodeError::InvalidLink));
        }

        // Store the target in the member payload: readers such as libarchive do not
        // read symbolic-link targets from the PKWARE UNIX extra field (0x000d).
        self.add_member(
            path,
            CompressionMethod::Stored,
            EntryKind::SymbolicLink,
            &mut FilePayload::from(target.as_bytes()),
        )
        .await
    }
}

/// Check a copy so successive members reserve the same end record.
fn check_end_metadata(mut budget: Budget) -> Result<(), BudgetError> {
    budget.charge_metadata(size::ZIP64_END as u64)
}

fn check_archive_size(
    budget: &Budget,
    directory_offset: u64,
    directory_size: u64,
) -> Result<(), EncodeError> {
    let archive_size = directory_offset
        .checked_add(directory_size)
        .and_then(|end| end.checked_add(END_RECORDS_SIZE as u64))
        .ok_or(EncodeError::Overflow)?;
    Ok(budget.check_archive_size(archive_size)?)
}

/// A failure while encoding ZIP records or payloads.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Metadata could not be represented in ZIP.
    #[error(transparent)]
    Framing(#[from] zip_framing::Error),
    /// Writing, seeking, or flushing the output failed.
    #[error("ZIP output I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A compressor failed or made no progress.
    #[error("DEFLATE compression failed")]
    Compression,
    /// Output arithmetic exceeded the ZIP64 range.
    #[error("ZIP output size overflow")]
    Overflow,
    /// A symbolic-link target cannot be represented safely.
    #[error("empty, oversized, or NUL-containing symbolic-link target")]
    InvalidLink,
    /// A resource budget was exceeded.
    #[error(transparent)]
    Limit(#[from] LimitExceeded),
    /// The writer has already emitted its directory and terminators.
    #[error("ZIP writer is already finalized")]
    Finished,
}

impl From<EncodeError> for BuildError<EncodeError> {
    fn from(error: EncodeError) -> Self {
        Self::Encoder(error)
    }
}

impl From<BudgetError> for EncodeError {
    fn from(error: BudgetError) -> Self {
        match error {
            BudgetError::Limit(limit) => Self::Limit(limit),
            BudgetError::Overflow(_) => Self::Overflow,
        }
    }
}
