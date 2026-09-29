//! Streaming ZIP64 encoding for the format-neutral archive builder.

use std::io;

use archive_trait::{
    ArchiveBuilder, BuildError, EntryMetadata, FilePayload, builder::BuildFailure,
};
use flate2::{Compress, Compression, Crc, FlushCompress, Status};
use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zip_framing::{
    CompressionMethod, Limits,
    write::{EntryKind, MemberHeader, end_records},
};

use crate::payload::CHUNK_SIZE;

/// A streaming UTF-8 ZIP64 writer for [`ArchiveBuilder::builder`].
///
/// Output starts at the writer's current position, which must be the start of
/// an empty archive. Payloads are streamed; only bounded directory metadata is
/// retained. ZIP64 descriptors avoid seeking or estimating compressed sizes.
pub struct ZipEncoder<W> {
    writer: W,
    method: CompressionMethod,
    limits: Limits,
    position: u64,
    count: usize,
    metadata: u64,
    total_size: u64,
    directory: Vec<u8>,
    finished: bool,
}

impl<W> ZipEncoder<W> {
    /// Creates a DEFLATE encoder with default resource budgets.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            method: CompressionMethod::Deflate,
            limits: Limits::default(),
            position: 0,
            count: 0,
            metadata: 0,
            total_size: 0,
            directory: Vec::new(),
            finished: false,
        }
    }

    /// Selects the compression method for nonempty regular files.
    pub fn compression(mut self, method: CompressionMethod) -> Self {
        self.method = method;
        self
    }

    /// Sets archive, member, metadata, entry-count, and total-input budgets.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
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

impl<W: AsyncWrite + Unpin> ZipEncoder<W> {
    fn preflight(&self, header: &MemberHeader<'_>, size: u64) -> Result<(), EncodeError> {
        if self.finished {
            return Err(EncodeError::Finished);
        }

        limit(
            self.count as u64 + 1,
            self.limits.entries as u64,
            "entry count",
        )?;

        limit(
            checked_add(self.metadata, header.metadata_size())?,
            self.limits.metadata_size,
            "metadata bytes",
        )?;

        limit(size, self.limits.member_size, "member bytes")?;
        limit(
            checked_add(self.total_size, size)?,
            self.limits.total_size,
            "total member bytes",
        )?;

        Ok(())
    }

    async fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = checked_add(self.position, bytes.len() as u64)?;
        limit(end, self.limits.archive_size, "archive bytes")?;

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

            tokio::task::yield_now().await;
        }
    }

    async fn write_member(
        &mut self,
        header: MemberHeader<'_>,
        payload: &mut FilePayload<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        let size = payload.size();
        self.preflight(&header, size).map_err(recoverable)?;

        let offset = self.position;
        self.write_bytes(&header.local_header())
            .await
            .map_err(poisoned)?;

        let start = self.position;
        let mut crc = Crc::new();
        let mut compressor = match header.method() {
            CompressionMethod::Stored => None,
            CompressionMethod::Deflate => Some(Compress::new(Compression::default(), false)),
            _ => return Err(poisoned(EncodeError::Compression)),
        };
        let mut output = vec![0; CHUNK_SIZE];
        let mut consumed = 0;

        while let Some(chunk) = payload.next_chunk().await.map_err(BuildFailure::poisoned)? {
            consumed = checked_add(consumed, chunk.len() as u64).map_err(poisoned)?;
            if consumed > size {
                return Err(poisoned(EncodeError::SizeMismatch));
            }

            for chunk in chunk.chunks(CHUNK_SIZE) {
                crc.update(chunk);
                if let Some(compressor) = &mut compressor {
                    self.compress_chunk(compressor, chunk, false, &mut output)
                        .await
                        .map_err(poisoned)?;
                } else {
                    self.write_bytes(chunk).await.map_err(poisoned)?;
                }

                tokio::task::yield_now().await;
            }
        }

        if consumed != size {
            return Err(poisoned(EncodeError::SizeMismatch));
        }

        if let Some(compressor) = &mut compressor {
            self.compress_chunk(compressor, &[], true, &mut output)
                .await
                .map_err(poisoned)?;
        }

        let metadata_size = header.metadata_size();
        let member = header
            .finish(crc.sum(), self.position - start, size, offset)
            .map_err(poisoned)?;
        self.write_bytes(&member.descriptor())
            .await
            .map_err(poisoned)?;

        self.directory.extend_from_slice(&member.central_header());
        self.count += 1;
        self.metadata += metadata_size;
        self.total_size += size;

        Ok(())
    }
}

impl<W: AsyncWrite + Unpin> ArchiveBuilder for ZipEncoder<W> {
    type Error = EncodeError;

    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>> {
        if self.finished {
            return Err(recoverable(EncodeError::Finished));
        }

        let end = end_records(
            self.count as u64,
            self.position,
            self.directory.len() as u64,
        )
        .map_err(recoverable)?;

        let position = checked_add(self.position, self.directory.len() as u64)
            .and_then(|position| checked_add(position, end.len() as u64))
            .map_err(recoverable)?;
        limit(position, self.limits.archive_size, "archive bytes").map_err(recoverable)?;

        self.writer
            .write_all(&self.directory)
            .await
            .map_err(poisoned)?;

        self.writer.write_all(&end).await.map_err(poisoned)?;

        self.writer.flush().await.map_err(poisoned)?;

        self.position = position;
        self.finished = true;

        Ok(())
    }

    async fn write_file_member(
        &mut self,
        path: &str,
        payload: &mut FilePayload<'_>,
        metadata: EntryMetadata,
    ) -> Result<(), BuildFailure<Self::Error>> {
        let method = if payload.size() == 0 {
            CompressionMethod::Stored
        } else {
            self.method
        };
        let header = MemberHeader::new(
            path,
            method,
            EntryKind::File {
                executable: metadata.is_executable(),
            },
        )
        .map_err(recoverable)?;

        self.write_member(header, payload).await
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
        let header = MemberHeader::new(&path, CompressionMethod::Stored, EntryKind::Directory)
            .map_err(recoverable)?;

        self.write_member(header, &mut FilePayload::from(&b""[..]))
            .await
    }

    async fn write_symbolic_link_member(
        &mut self,
        path: &str,
        target: &str,
    ) -> Result<(), BuildFailure<Self::Error>> {
        if target.is_empty() || target.len() > usize::from(u16::MAX) || target.contains('\0') {
            return Err(recoverable(EncodeError::InvalidLink));
        }

        let header = MemberHeader::new(path, CompressionMethod::Stored, EntryKind::SymbolicLink)
            .map_err(recoverable)?;

        self.write_member(header, &mut FilePayload::from(target.as_bytes()))
            .await
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, EncodeError> {
    left.checked_add(right).ok_or(EncodeError::Overflow)
}

fn limit(value: u64, limit: u64, resource: &'static str) -> Result<(), EncodeError> {
    if value > limit {
        return Err(EncodeError::Limit { resource, limit });
    }

    Ok(())
}

fn recoverable(error: impl Into<EncodeError>) -> BuildFailure<EncodeError> {
    BuildFailure::recoverable(BuildError::Encoder(error.into()))
}

fn poisoned(error: impl Into<EncodeError>) -> BuildFailure<EncodeError> {
    BuildFailure::poisoned(BuildError::Encoder(error.into()))
}

/// A failure while encoding ZIP records or payloads.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// Metadata could not be represented in ZIP.
    #[error(transparent)]
    Framing(#[from] zip_framing::Error),
    /// Writing or flushing the output failed.
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
