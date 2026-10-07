//! Streaming ZIP64 encoding for the format-neutral archive builder.

use std::io::{self, SeekFrom};

use archive_trait::{
    ArchiveBuilder, BuildError, EntryMetadata, FilePayload, builder::BuildFailure,
};
use crc32fast::Hasher;
use flate2::{Compress, Compression, FlushCompress, Status};
use thiserror::Error;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use zip_framing::{
    Budget, BudgetError, CompressionMethod, Limits,
    write::{EntryKind, PendingMember, end_records},
};

use crate::payload::CHUNK_SIZE;

/// Per-file ZIP settings for [`archive_trait::Builder::add_file_with_options`].
///
/// Default options inherit the method configured by [`ZipEncoder::with_compression`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZipFileOptions {
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
            method: CompressionMethod::Deflate,
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
        &self,
        path: &'a str,
        method: CompressionMethod,
        kind: EntryKind,
        size: u64,
    ) -> Result<(PendingMember<'a>, Budget), EncodeError> {
        let header = PendingMember::new(path, method, kind)?;
        if self.finished {
            return Err(EncodeError::Finished);
        }

        let mut pending_budget = self.budget;
        pending_budget.check_entry_count(self.count as u64 + 1)?;
        pending_budget.charge_metadata(
            header.local_header_size() as u64 + header.central_header_size() as u64,
        )?;
        pending_budget.charge_member(size)?;

        Ok((header, pending_budget))
    }

    async fn add_member(
        &mut self,
        path: &str,
        method: CompressionMethod,
        kind: EntryKind,
        payload: &mut FilePayload<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        let (header, pending_budget) = self
            .prepare_member(path, method, kind, payload.size())
            .map_err(BuildFailure::recoverable)?;

        self.write_member(header, payload)
            .await
            .map_err(BuildFailure::poisoned)?;
        self.budget = pending_budget;

        Ok(())
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .position
            .checked_add(bytes.len() as u64)
            .ok_or(EncodeError::Overflow)?;
        self.budget.check_archive_size(end)?;

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
        &mut self,
        header: PendingMember<'_>,
        payload: &mut FilePayload<'_>,
    ) -> Result<(), BuildError<EncodeError>> {
        let size = payload.size();
        let offset = self.position;
        self.write_bytes(&vec![0; header.local_header_size()])
            .await?;

        let start = self.position;
        let mut crc = Hasher::new();
        let mut compressor = match header.method() {
            CompressionMethod::Stored => None,
            CompressionMethod::Deflate => Some(Compress::new(Compression::default(), false)),
            _ => return Err(EncodeError::Compression.into()),
        };
        let mut output = if compressor.is_some() {
            vec![0; CHUNK_SIZE]
        } else {
            Vec::new()
        };
        let mut consumed = 0_u64;

        while let Some(chunk) = payload.next_chunk().await? {
            consumed = consumed
                .checked_add(chunk.len() as u64)
                .ok_or(EncodeError::Overflow)?;
            if consumed > size {
                return Err(EncodeError::SizeMismatch.into());
            }

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

        if consumed != size {
            return Err(EncodeError::SizeMismatch.into());
        }

        if let Some(compressor) = &mut compressor {
            self.compress_chunk(compressor, &[], true, &mut output)
                .await?;
        }

        let member = header
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

        self.directory.extend_from_slice(&member.central_header());
        self.count += 1;

        Ok(())
    }

    fn prepare_end(&self) -> Result<(Vec<u8>, u64), EncodeError> {
        if self.finished {
            return Err(EncodeError::Finished);
        }

        let end = end_records(
            self.count as u64,
            self.position,
            self.directory.len() as u64,
        )?;

        let position = self
            .position
            .checked_add(self.directory.len() as u64)
            .and_then(|position| position.checked_add(end.len() as u64))
            .ok_or(EncodeError::Overflow)?;
        self.budget.check_archive_size(position)?;

        Ok((end, position))
    }

    async fn write_end(&mut self, end: &[u8], position: u64) -> Result<(), EncodeError> {
        self.writer.write_all(&self.directory).await?;
        self.writer.write_all(end).await?;
        self.writer.flush().await?;

        self.position = position;
        self.finished = true;

        Ok(())
    }
}

impl<W: AsyncWrite + AsyncSeek + Unpin> ArchiveBuilder for ZipEncoder<W> {
    type Error = EncodeError;
    type FileOptions = ZipFileOptions;

    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>> {
        let (end, position) = self.prepare_end().map_err(BuildFailure::recoverable)?;

        self.write_end(&end, position)
            .await
            .map_err(BuildFailure::poisoned)
    }

    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut FilePayload<'_>,
        metadata: EntryMetadata,
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
                executable: metadata.is_executable(),
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

        self.add_member(
            path,
            CompressionMethod::Stored,
            EntryKind::SymbolicLink,
            &mut FilePayload::from(target.as_bytes()),
        )
        .await
    }
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
    /// A source did not produce its declared size.
    #[error("ZIP source payload size mismatch")]
    SizeMismatch,
    /// Output arithmetic exceeded the ZIP64 range.
    #[error("ZIP output size overflow")]
    Overflow,
    /// A symbolic-link target cannot be represented safely.
    #[error("empty, oversized, or NUL-containing symbolic-link target")]
    InvalidLink,
    /// A resource budget was exceeded.
    #[error("ZIP exceeds {resource} limit ({limit})")]
    Limit {
        /// The exhausted resource.
        resource: &'static str,
        /// Configured maximum.
        limit: u64,
    },
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
        let (resource, limit) = match error {
            BudgetError::ArchiveSize(limit) => ("archive bytes", limit),
            BudgetError::EntryCount(limit) => ("entry count", limit),
            BudgetError::MetadataSize(limit) => ("metadata bytes", limit),
            BudgetError::MemberSize(limit) => ("member bytes", limit),
            BudgetError::TotalSize(limit) => ("total member bytes", limit),
            BudgetError::Overflow(_) => return Self::Overflow,
        };
        Self::Limit { resource, limit }
    }
}
