//! ZIP member projection and seekable archive access.

use std::{
    io::{self, SeekFrom},
    str,
};

use archive_trait::{Archive, Member, MemberMetadata, MemberPayload, SpecialKind};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt};
use zip_framing::{DirectoryEntry, Entry, Index, Limits};

use crate::payload::{CHUNK_SIZE, Payload};

/// An indexed ZIP archive over an immutable, seekable source.
pub struct ZipArchive<R> {
    state: DecoderState<R>,
    poisoned: bool,
}

struct DecoderState<R> {
    reader: R,
    index: Index,
    next: usize,
    active: Option<Payload>,
}

struct Operation<'a, R> {
    state: &'a mut DecoderState<R>,
    poisoned: &'a mut bool,
}

impl<R> Operation<'_, R> {
    fn commit(self) {
        *self.poisoned = false;
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> ZipArchive<R> {
    /// Opens and validates the central directory using default resource limits.
    pub async fn open(reader: R) -> Result<Self, DecodeError> {
        Self::open_with_limits(reader, Limits::default()).await
    }

    /// Opens and validates the central directory using explicit resource limits.
    ///
    /// Local records are checked on member access. Use [`Self::validate_all`]
    /// to check metadata for every member before reading any payloads.
    pub async fn open_with_limits(mut reader: R, limits: Limits) -> Result<Self, DecodeError> {
        let index = Index::read(&mut reader, limits).await?;

        Ok(Self {
            state: DecoderState {
                reader,
                index,
                next: 0,
                active: None,
            },
            poisoned: false,
        })
    }

    /// Returns directory metadata without fetching local records or payloads.
    pub fn entries(&self) -> &[DirectoryEntry] {
        self.state.index.entries()
    }

    /// Selects a member by central-directory index.
    ///
    /// The selected local header and descriptor must agree with the directory
    /// before a member is returned. Successful metadata checks are cached.
    /// An unfinished prior payload is drained and validated first. The next
    /// sequential read resumes immediately after the selected entry. Repeated
    /// explicit selections repeat the associated I/O and decompression work.
    /// Errors and cancellation poison the archive; subsequent operations fail.
    pub async fn member(
        &mut self,
        index: usize,
    ) -> Result<Option<Member<ZipMemberPayload<'_, R>>>, DecodeError> {
        let operation = self.begin_operation()?;
        let member = operation.state.prepare_member(index).await?;
        operation.commit();

        Ok(member.map(|member| attach_payload(member, self)))
    }

    /// Checks metadata for all members, including those never selected.
    ///
    /// An active payload is drained first. Other payloads are not decoded;
    /// their CRCs and decoded sizes are still checked when they are read.
    pub async fn validate_all(&mut self) -> Result<(), DecodeError> {
        let operation = self.begin_operation()?;
        operation.state.validate_all().await?;
        operation.commit();

        Ok(())
    }

    /// Borrows the source for operations such as HTTP range prefetching.
    ///
    /// Drains and validates an active payload before lending the reader. The
    /// caller may change its cursor, but must not replace the source or change
    /// its contents. Subsequent member selection seeks to the checked offset.
    pub async fn reader_mut(&mut self) -> Result<&mut R, DecodeError> {
        let operation = self.begin_operation()?;
        operation.state.drain().await?;
        operation.commit();

        Ok(&mut self.state.reader)
    }

    /// Returns the source without validating any remaining payloads.
    pub fn into_inner(self) -> R {
        self.state.reader
    }

    fn begin_operation(&mut self) -> Result<Operation<'_, R>, DecodeError> {
        if self.poisoned {
            return Err(DecodeError::Poisoned);
        }

        // Poison before any work starts. Only a committed operation restores
        // usability; errors and cancellation leave the archive poisoned without
        // relying on Drop to run.
        self.poisoned = true;

        Ok(Operation {
            state: &mut self.state,
            poisoned: &mut self.poisoned,
        })
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> DecoderState<R> {
    // Finish all fallible work before lending the archive to a payload.
    async fn prepare_member(&mut self, index: usize) -> Result<Option<Member<()>>, DecodeError> {
        self.drain().await?;

        let Some(entry) = self.index.entry(&mut self.reader, index).await? else {
            return Ok(None);
        };

        let kind = kind(&entry)?;
        let metadata = MemberMetadata {
            path: entry.path().to_owned(),
            position: entry.position(),
        };
        let size = entry.size();

        self.active = Some(Payload::new(&entry)?);
        self.reader
            .seek(SeekFrom::Start(entry.data_offset()))
            .await?;
        self.next = index + 1;

        let member = match kind {
            Kind::File(executable) => Member::File {
                metadata,
                size,
                executable,
                payload: (),
            },
            Kind::Directory => {
                self.drain().await?;
                Member::Directory { metadata }
            }
            Kind::HardLink(target) => Member::HardLink {
                metadata,
                target,
                size,
                payload: (),
            },
            Kind::SymbolicLink(expected) => {
                let mut target = Vec::new();
                let mut chunk = Vec::new();
                while self.read_chunk(&mut chunk, CHUNK_SIZE).await? {
                    target.extend_from_slice(&chunk);
                }

                let mut target = String::from_utf8(target).map_err(|_| DecodeError::Integrity {
                    position: metadata.position,
                    reason: "non-UTF-8 symbolic-link target",
                })?;
                if target.contains('\0') {
                    return Err(DecodeError::Integrity {
                        position: metadata.position,
                        reason: "NUL in symbolic-link target",
                    });
                }

                if let Some(expected) = expected {
                    if size == 0 {
                        target = expected;
                    } else if target != expected {
                        return Err(DecodeError::Integrity {
                            position: metadata.position,
                            reason: "symbolic-link payload and UNIX extra field disagree",
                        });
                    }
                }

                Member::SymbolicLink { metadata, target }
            }
            Kind::Special(kind) => {
                self.drain().await?;
                Member::Special { metadata, kind }
            }
        };

        Ok(Some(member))
    }

    async fn validate_all(&mut self) -> Result<(), DecodeError> {
        self.drain().await?;
        self.index.validate_all(&mut self.reader).await?;

        for entry in self
            .index
            .entries()
            .iter()
            .filter_map(DirectoryEntry::resolved)
        {
            kind(&entry)?;
        }

        Ok(())
    }

    async fn read_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, DecodeError> {
        let Some(active) = &mut self.active else {
            return Ok(false);
        };

        active.next(&mut self.reader, buffer, target_len).await
    }

    async fn drain(&mut self) -> Result<(), DecodeError> {
        let mut buffer = Vec::new();
        while self.read_chunk(&mut buffer, CHUNK_SIZE).await? {
            tokio::task::yield_now().await;
        }

        self.active = None;

        Ok(())
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> Archive for ZipArchive<R> {
    type Error = DecodeError;
    type Payload<'a>
        = ZipMemberPayload<'a, R>
    where
        Self: 'a;

    async fn next_member(&mut self) -> Result<Option<Member<Self::Payload<'_>>>, Self::Error> {
        self.member(self.state.next).await
    }
}

/// A lending cursor over one member's decoded, integrity-checked bytes.
pub struct ZipMemberPayload<'a, R> {
    archive: &'a mut ZipArchive<R>,
}

impl<R: AsyncRead + AsyncSeek + Unpin> MemberPayload for ZipMemberPayload<'_, R> {
    type Error = DecodeError;

    async fn next_chunk(
        &mut self,
        buffer: &mut Vec<u8>,
        target_len: usize,
    ) -> Result<bool, DecodeError> {
        let operation = self.archive.begin_operation()?;
        let result = operation.state.read_chunk(buffer, target_len).await?;
        operation.commit();

        Ok(result)
    }

    async fn skip(self) -> Result<(), DecodeError> {
        let operation = self.archive.begin_operation()?;
        operation.state.drain().await?;
        operation.commit();

        Ok(())
    }
}

fn attach_payload<R>(
    member: Member<()>,
    archive: &mut ZipArchive<R>,
) -> Member<ZipMemberPayload<'_, R>> {
    match member {
        Member::File {
            metadata,
            size,
            executable,
            ..
        } => Member::File {
            metadata,
            size,
            executable,
            payload: ZipMemberPayload { archive },
        },
        Member::HardLink {
            metadata,
            target,
            size,
            ..
        } => Member::HardLink {
            metadata,
            target,
            size,
            payload: ZipMemberPayload { archive },
        },
        Member::Directory { metadata } => Member::Directory { metadata },
        Member::SymbolicLink { metadata, target } => Member::SymbolicLink { metadata, target },
        Member::Special { metadata, kind } => Member::Special { metadata, kind },
    }
}

enum Kind {
    File(bool),
    Directory,
    SymbolicLink(Option<String>),
    HardLink(String),
    Special(SpecialKind),
}

fn kind(entry: &Entry<'_>) -> Result<Kind, DecodeError> {
    let attributes = entry.external_attributes();
    let unix = matches!(entry.host_system(), 3 | 19);
    let mode = if unix { attributes >> 16 } else { 0 };

    let extra = entry.unix_extra_data().filter(|data| !data.is_empty());
    let link = if let Some(data) = extra
        && matches!(mode & 0o170000, 0 | 0o100000 | 0o120000)
    {
        let target = str::from_utf8(data).map_err(|_| DecodeError::Integrity {
            position: entry.position(),
            reason: "non-UTF-8 UNIX link target",
        })?;
        if target.contains('\0') {
            return Err(DecodeError::Integrity {
                position: entry.position(),
                reason: "NUL in UNIX link target",
            });
        }

        Some(target.to_owned())
    } else {
        None
    };

    let dos = matches!(entry.host_system(), 0 | 3 | 6 | 10 | 14 | 19);
    let directory = entry.path().ends_with('/') || (dos && attributes & 0x10 != 0);
    if dos && attributes & 8 != 0 {
        return Err(DecodeError::Unsupported {
            position: entry.position(),
            feature: "volume label",
        });
    }

    let kind = match mode & 0o170000 {
        0 if directory => Kind::Directory,
        0 | 0o100000 if !directory => match link {
            Some(target) => Kind::HardLink(target),
            None => Kind::File(mode & 0o111 != 0),
        },
        0o040000 => Kind::Directory,
        0o120000 if !directory => Kind::SymbolicLink(link),
        0o020000 if !directory => Kind::Special(SpecialKind::CharacterDevice),
        0o060000 if !directory => Kind::Special(SpecialKind::BlockDevice),
        0o010000 if !directory => Kind::Special(SpecialKind::Fifo),
        _ => {
            return Err(DecodeError::Unsupported {
                position: entry.position(),
                feature: "inconsistent or unsupported file attributes",
            });
        }
    };

    if matches!(kind, Kind::Directory | Kind::Special(_))
        && (entry.size() != 0 || entry.crc32() != 0)
    {
        return Err(DecodeError::Integrity {
            position: entry.position(),
            reason: "non-file member has payload data",
        });
    }

    if matches!(kind, Kind::Directory) && entry.version_needed() < 20 {
        return Err(DecodeError::Integrity {
            position: entry.position(),
            reason: "directory requires extraction version 2.0",
        });
    }

    if matches!(kind, Kind::SymbolicLink(_))
        && ((entry.size() == 0 && matches!(kind, Kind::SymbolicLink(None)))
            || entry.size() > u64::from(u16::MAX))
    {
        return Err(DecodeError::Integrity {
            position: entry.position(),
            reason: "empty or oversized symbolic-link target",
        });
    }

    if extra.is_some() && matches!(kind, Kind::Directory | Kind::Special(SpecialKind::Fifo)) {
        return Err(DecodeError::Integrity {
            position: entry.position(),
            reason: "unexpected UNIX file-type data",
        });
    }

    if let Some(data) = extra
        && matches!(
            kind,
            Kind::Special(SpecialKind::CharacterDevice | SpecialKind::BlockDevice)
        )
        && data.len() != 8
    {
        return Err(DecodeError::Integrity {
            position: entry.position(),
            reason: "invalid UNIX device numbers",
        });
    }

    Ok(kind)
}

/// A ZIP framing, payload, or member-projection failure.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// ZIP record parsing failed.
    #[error(transparent)]
    Framing(#[from] zip_framing::Error),
    /// Payload I/O failed.
    #[error("ZIP payload I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Member data did not agree with its declared metadata.
    #[error("at byte {position}: invalid ZIP payload: {reason}")]
    Integrity {
        /// Local-header offset.
        position: u64,
        /// Failed integrity requirement.
        reason: &'static str,
    },
    /// A member cannot be represented by this codec.
    #[error("at byte {position}: unsupported ZIP {feature}")]
    Unsupported {
        /// Local-header offset.
        position: u64,
        /// The unsupported member feature.
        feature: &'static str,
    },
    /// A prior error or interrupted operation invalidated the cursor.
    #[error("ZIP reader is poisoned after an error or cancelled operation")]
    Poisoned,
}
