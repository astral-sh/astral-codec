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
    write::{EndRecords, EntryKind, PendingHeaders, PendingMember},
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
    limits: Limits,
    layout: Option<ArchiveLayout>,
    finished: bool,
}

impl<W> ZipEncoder<W> {
    /// Creates a DEFLATE encoder with default resource budgets.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            method: CompressionMethod::default(),
            limits: Limits::default(),
            layout: None,
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
    /// Call before adding members.
    /// The archive-size limit includes the central directory and end records.
    /// For DEFLATE members, compressed bytes are checked as they are written.
    pub fn with_limits(mut self, limits: Limits) -> Self {
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

        let layout = ArchiveLayout::get_or_create(&mut self.layout, self.limits)?;
        let headers = header.prepare_headers(layout.directory_offset());
        let header_size = (headers.local().len() + headers.central_len()) as u64;
        let mut budget = layout.budget;
        budget.check_entry_count(layout.count + 1)?;
        budget.charge_metadata(header_size)?;
        budget.charge_member(size)?;

        // Stored data has a known encoded size. DEFLATE can use the remaining
        // space after accounting for the headers and the end records.
        let mut space = layout.space;
        space.spend(header_size)?;
        if method == CompressionMethod::Stored {
            space.check_available(size)?;
        }
        Ok(MemberWriter {
            headers,
            writer: &mut self.writer,
            layout,
            budget,
            space,
        })
    }

    async fn add_member(
        &mut self,
        path: &str,
        method: CompressionMethod,
        kind: EntryKind,
        payload: &mut FilePayload<'_>,
    ) -> Result<(), BuildFailure<EncodeError>> {
        self.prepare_member(path, method, kind, payload.size())
            .map_err(BuildFailure::recoverable)?
            .write_member(payload)
            .await
            .map_err(BuildFailure::poisoned)
    }
}

/// The available output bytes after paying for the complete archive so far.
#[derive(Clone, Copy)]
struct ArchiveSpace {
    limit: u64,
    remaining: u64,
}

impl ArchiveSpace {
    fn new(limit: u64) -> Result<Self, LimitExceeded> {
        let remaining = limit
            .checked_sub(EndRecords::SIZE as u64)
            .ok_or(LimitExceeded::ArchiveSize(limit))?;
        Ok(Self { limit, remaining })
    }

    fn check_available(&self, length: u64) -> Result<(), LimitExceeded> {
        if length > self.remaining {
            return Err(LimitExceeded::ArchiveSize(self.limit));
        }
        Ok(())
    }

    fn spend(&mut self, length: u64) -> Result<(), LimitExceeded> {
        self.check_available(length)?;
        self.remaining -= length;
        Ok(())
    }
}

/// A finalizable archive. Its space accounts for the written local records,
/// the buffered directory, and the fixed-length end records.
struct ArchiveLayout {
    count: u64,
    directory: Vec<u8>,
    budget: Budget,
    space: ArchiveSpace,
}

impl ArchiveLayout {
    fn get_or_create(slot: &mut Option<Self>, limits: Limits) -> Result<&mut Self, EncodeError> {
        if let Some(layout) = slot {
            return Ok(layout);
        }

        let mut budget = Budget::new(limits);
        budget.charge_metadata(size::ZIP64_END as u64)?;
        Ok(slot.insert(Self {
            count: 0,
            directory: Vec::new(),
            budget,
            space: ArchiveSpace::new(limits.archive_size)?,
        }))
    }

    fn directory_offset(&self) -> u64 {
        let paid = self.space.limit - self.space.remaining;
        paid - self.directory.len() as u64 - EndRecords::SIZE as u64
    }

    async fn write_tail(
        &self,
        writer: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), BuildFailure<EncodeError>> {
        let end = EndRecords::new(
            self.count,
            self.directory_offset(),
            self.directory.len() as u64,
        )
        .map_err(EncodeError::Framing)
        .map_err(BuildFailure::recoverable)?;
        let result = async {
            writer.write_all(&self.directory).await?;
            writer.write_all(end.as_bytes()).await?;
            writer.flush().await
        };

        result
            .await
            .map_err(EncodeError::Io)
            .map_err(BuildFailure::poisoned)
    }
}

/// Writes one member with space reserved for the complete directory and end records.
struct MemberWriter<'a, W> {
    headers: PendingHeaders<'a>,
    writer: &'a mut W,
    layout: &'a mut ArchiveLayout,
    budget: Budget,
    space: ArchiveSpace,
}

impl<W: AsyncWrite + AsyncSeek + Unpin> MemberWriter<'_, W> {
    async fn write_payload(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.space.spend(bytes.len() as u64)?;
        self.writer.write_all(bytes).await?;

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
            self.write_payload(&output[..produced]).await?;

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
    ) -> Result<(), BuildError<EncodeError>> {
        let size = payload.size();
        let offset = self.layout.directory_offset();
        let payload_space = self.space.remaining;
        self.writer
            .write_all(self.headers.local())
            .await
            .map_err(EncodeError::Io)?;

        let mut crc = Hasher::new();
        let mut compressor = match self.headers.method() {
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
                    self.write_payload(chunk).await?;
                }

                tokio::task::consume_budget().await;
            }
        }

        if let Some(compressor) = &mut compressor {
            self.compress_chunk(compressor, &[], true, &mut output)
                .await?;
        }

        let compressed = payload_space - self.space.remaining;
        let headers = self
            .headers
            .finish(crc.finalize(), compressed, size)
            .map_err(EncodeError::Framing)?;

        // Rewriting the reserved header does not advance the archive's end.
        self.writer
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(EncodeError::Io)?;
        self.writer
            .write_all(&headers.local)
            .await
            .map_err(EncodeError::Io)?;
        self.writer
            .seek(SeekFrom::Start(
                offset + headers.local.len() as u64 + compressed,
            ))
            .await
            .map_err(EncodeError::Io)?;

        self.layout.directory.extend_from_slice(&headers.central);
        self.layout.space = self.space;
        self.layout.budget = self.budget;
        self.layout.count += 1;
        Ok(())
    }
}

impl<W: AsyncWrite + AsyncSeek + Unpin> ArchiveBuilder for ZipEncoder<W> {
    type Error = EncodeError;
    type FileOptions = ZipFileOptions;

    async fn finish_archive(&mut self) -> Result<(), BuildFailure<Self::Error>> {
        if self.finished {
            return Err(BuildFailure::recoverable(EncodeError::Finished));
        }
        let layout = ArchiveLayout::get_or_create(&mut self.layout, self.limits)
            .map_err(BuildFailure::recoverable)?;
        layout.write_tail(&mut self.writer).await?;
        self.finished = true;
        Ok(())
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
