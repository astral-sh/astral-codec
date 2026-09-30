use std::str;

use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    Error, ExtraHeaderId, Limits, add,
    constants::{signature, size, version},
    extra::Extras,
    invalid,
    record::{RecordReader, array_at},
};

mod entry;

pub use entry::{DirectoryEntry, Entry, IndexedEntry};

/// A ZIP member index.
///
/// This is constructed from the central directory, with referenced
/// local file entries being resolved lazily upon access through
/// [`Self::entry`].
#[derive(Debug)]
pub struct Index {
    /// The indexed members, in central directory order.
    entries: Vec<IndexedEntry>,
    /// The parse budget. This is debited against when parsing local
    /// file entries and reconciling local/central metadata.
    budget: Budget,
}

impl Index {
    /// Borrows indexed members, without fetching local records or payloads.
    pub fn entries(&self) -> &[IndexedEntry] {
        &self.entries
    }

    /// Indexes the directory and checks bounds derivable from its records.
    ///
    /// Local headers and descriptors are checked by [`Self::entry`] on access,
    /// or by [`Self::validate_all`]. The source must remain unchanged and be the
    /// same source passed to subsequent operations. A cancelled read may leave
    /// its cursor anywhere; another call restarts from the end.
    pub async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut R,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut budget = Budget::new(limits);
        let mut buffered = RecordReader::new(reader, 64 * 1024);
        let end = CentralDirectory::read(&mut buffered, &mut budget).await?;
        let entries = end.read_entries(&mut buffered, &mut budget).await?;

        // Preserve directory order while assigning boundaries in physical order.
        // Only local reads can establish exact coverage inside these spans.
        let mut order: Vec<_> = (0..entries.len()).collect();
        order.sort_unstable_by_key(|&index| entries[index].position());
        if order
            .first()
            .map_or(end.offset, |&index| entries[index].position())
            != 0
        {
            return Err(invalid(0, "unaccounted bytes before the first member"));
        }

        let mut boundaries = vec![end.offset; entries.len()];
        for (ordinal, &index) in order.iter().enumerate() {
            boundaries[index] = order
                .get(ordinal + 1)
                .map_or(end.offset, |&next| entries[next].position());
        }
        let entries = entries
            .into_iter()
            .zip(boundaries)
            .map(|(directory, boundary)| IndexedEntry::new(directory, boundary))
            .collect::<Result<_, _>>()?;

        Ok(Self { entries, budget })
    }

    /// Checks one member's local header, extras and descriptor before exposing it.
    ///
    /// Successful resolutions are cached. This does not decode or check payload
    /// contents. The source must be the immutable source used by [`Self::read`].
    pub async fn entry<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
        index: usize,
    ) -> Result<Option<Entry<'_>>, Error> {
        let Some(entry) = self.entries.get_mut(index) else {
            return Ok(None);
        };

        Ok(Some(entry.resolve(reader, &mut self.budget).await?))
    }

    /// Checks every local header, descriptor, and kind, including unselected members.
    ///
    /// Success establishes complete, nonoverlapping record coverage and
    /// agreement of redundant and kind-specific metadata. Payload sizes and
    /// CRCs still need to be verified when decoding. Already checked members
    /// require no I/O.
    pub async fn validate_all<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<(), Error> {
        for entry in &mut self.entries {
            entry.resolve(reader, &mut self.budget).await?;
            tokio::task::yield_now().await;
        }

        Ok(())
    }
}

/// Our ZIP parsing budget.
#[derive(Clone, Copy, Debug)]
struct Budget {
    /// The parse's cumulative metadata usage, in bytes.
    ///
    /// This is enforced against [`Limits::metadata_size`].
    metadata: u64,

    /// The parse's cumulative uncompressed member sizes,
    /// as reported through the central directory.
    ///
    /// Each individual member's size is enforced against
    /// [`Limits::member_size`], while the cumulative total
    /// is enforced against [`Limits::total_size`].
    output: u64,

    /// The budget's enforced limits.
    limits: Limits,
}

impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            metadata: 0,
            output: 0,
            limits,
        }
    }

    /// Check the archive's size against its limit.
    fn check_archive_size(&self, size: u64) -> Result<(), Error> {
        if size > self.limits.archive_size {
            return Err(Error::Limit {
                resource: "archive bytes",
                limit: self.limits.archive_size,
            });
        }

        Ok(())
    }

    /// Check the central directory's entry count against its limit.
    fn check_entry_count(&self, count: u64) -> Result<(), Error> {
        if count > self.limits.entries as u64 {
            return Err(Error::Limit {
                resource: "entry count",
                limit: self.limits.entries as u64,
            });
        }

        Ok(())
    }

    /// Debit from the metadata budget.
    fn metadata(&mut self, length: u64) -> Result<(), Error> {
        let metadata = add(self.metadata, length)?;
        if metadata > self.limits.metadata_size {
            return Err(Error::Limit {
                resource: "metadata bytes",
                limit: self.limits.metadata_size,
            });
        }

        self.metadata = metadata;
        Ok(())
    }

    /// Debit from the output size budgets.
    fn output(&mut self, size: u64) -> Result<(), Error> {
        if size > self.limits.member_size {
            return Err(Error::Limit {
                resource: "decoded member bytes",
                limit: self.limits.member_size,
            });
        }

        let output = add(self.output, size)?;
        if output > self.limits.total_size {
            return Err(Error::Limit {
                resource: "total decoded bytes",
                limit: self.limits.total_size,
            });
        }

        self.output = output;
        Ok(())
    }
}

/// A ZIP archive's central directory's location and extent.
struct CentralDirectory {
    /// The absolute offset to the central directory, relative to the
    /// start of the source.
    offset: u64,
    /// The overall size of the central directory in bytes.
    ///
    /// Note that this does not include the size of the EOCD or any other
    /// trailing records that may follow the central directory.
    size: u64,
    /// The total number of central directory entries.
    count: u64,
}

impl CentralDirectory {
    /// Reads the central directory's location and extent from the end records.
    ///
    /// Validates its bounds and entry count, and charges directory and ZIP64 end
    /// metadata before returning. Failed or cancelled reads leave the budget
    /// unchanged.
    async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<Self, Error> {
        let length = reader.length().await?;
        budget.check_archive_size(length)?;
        if length < size::END as u64 {
            return Err(invalid(0, "missing end of central directory"));
        }

        // EOCD has a 16-bit comment length. Never scan the payload for signatures.
        let tail_size = length.min(size::END as u64 + u64::from(u16::MAX)) as usize;
        let tail_start = length - tail_size as u64;
        let tail = reader.read_vec(tail_start, tail_size, length).await?;

        let mut candidate = None;
        for (offset, header) in tail.windows(size::END).enumerate() {
            if header.starts_with(&signature::END.to_le_bytes())
                && let Some(header) = header.first_chunk::<{ size::END }>()
                && offset
                    + size::END
                    + usize::from(u16::from_le_bytes(array_at::<20, 2, _>(header)))
                    == tail.len()
                && candidate.replace((offset, header)).is_some()
            {
                return Err(invalid(tail_start + offset as u64, "ambiguous end records"));
            }
        }

        let (offset, end) =
            candidate.ok_or_else(|| invalid(length, "missing end record or trailing bytes"))?;
        let position = tail_start + offset as u64;
        str::from_utf8(&tail[offset + size::END..])
            .map_err(|_| invalid(position, "non-UTF-8 archive comment"))?;

        let mut offset = u64::from(u32::from_le_bytes(array_at::<16, 4, _>(end)));
        let mut size = u64::from(u32::from_le_bytes(array_at::<12, 4, _>(end)));
        let mut count = u64::from(u16::from_le_bytes(array_at::<10, 2, _>(end)));

        let mut boundary = position;
        let mut locator = [0; size::ZIP64_LOCATOR];
        let has_locator = if position >= size::ZIP64_LOCATOR as u64 {
            reader
                .read_at(
                    position - size::ZIP64_LOCATOR as u64,
                    &mut locator,
                    position,
                )
                .await?;
            u32::from_le_bytes(array_at::<0, 4, _>(&locator)) == signature::ZIP64_LOCATOR
        } else {
            false
        };

        if has_locator {
            if u32::from_le_bytes(array_at::<4, 4, _>(&locator)) != 0
                || u32::from_le_bytes(array_at::<16, 4, _>(&locator)) != 1
            {
                return Err(Error::Unsupported {
                    position: position - size::ZIP64_LOCATOR as u64,
                    feature: "multiple volumes",
                });
            }

            boundary = u64::from_le_bytes(array_at::<8, 8, _>(&locator));
            let mut zip64 = [0; size::ZIP64_END];
            reader
                .read_at(boundary, &mut zip64, position - size::ZIP64_LOCATOR as u64)
                .await?;
            if u32::from_le_bytes(array_at::<0, 4, _>(&zip64)) != signature::ZIP64_END {
                return Err(invalid(boundary, "invalid ZIP64 end signature"));
            }

            let end_size = u64::from_le_bytes(array_at::<4, 8, _>(&zip64));
            if end_size < size::ZIP64_END_BODY as u64
                || add(boundary, add(size::ZIP64_END_PREFIX as u64, end_size)?)?
                    != position - size::ZIP64_LOCATOR as u64
            {
                return Err(invalid(boundary, "invalid ZIP64 end length"));
            }

            if u16::from_le_bytes(array_at::<14, 2, _>(&zip64)) >= version::ZIP64_V2 {
                return Err(Error::Unsupported {
                    position: boundary,
                    feature: "ZIP64 version-2 directory",
                });
            }
            if u16::from_le_bytes(array_at::<14, 2, _>(&zip64)) != version::ZIP64 {
                return Err(invalid(boundary, "invalid ZIP64 extraction version"));
            }

            if u32::from_le_bytes(array_at::<16, 4, _>(&zip64)) != 0
                || u32::from_le_bytes(array_at::<20, 4, _>(&zip64)) != 0
            {
                return Err(Error::Unsupported {
                    position: boundary,
                    feature: "multiple volumes",
                });
            }

            if u64::from_le_bytes(array_at::<24, 8, _>(&zip64))
                != u64::from_le_bytes(array_at::<32, 8, _>(&zip64))
            {
                return Err(invalid(boundary, "ZIP64 entry counts disagree"));
            }

            offset = u64::from_le_bytes(array_at::<48, 8, _>(&zip64));
            size = u64::from_le_bytes(array_at::<40, 8, _>(&zip64));
            count = u64::from_le_bytes(array_at::<32, 8, _>(&zip64));
            for (small, large, sentinel) in [
                (
                    u64::from(u16::from_le_bytes(array_at::<4, 2, _>(end))),
                    0,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<6, 2, _>(end))),
                    0,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<8, 2, _>(end))),
                    count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<10, 2, _>(end))),
                    count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<12, 4, _>(end))),
                    size,
                    u64::from(u32::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<16, 4, _>(end))),
                    offset,
                    u64::from(u32::MAX),
                ),
            ] {
                if small != sentinel && small != large {
                    return Err(invalid(position, "classic and ZIP64 end records disagree"));
                }
            }
        } else {
            if u16::from_le_bytes(array_at::<4, 2, _>(end)) != 0
                || u16::from_le_bytes(array_at::<6, 2, _>(end)) != 0
            {
                return Err(Error::Unsupported {
                    position,
                    feature: "multiple volumes",
                });
            }

            if u16::from_le_bytes(array_at::<8, 2, _>(end))
                != u16::from_le_bytes(array_at::<10, 2, _>(end))
            {
                return Err(invalid(position, "entry counts disagree"));
            }

            if count == u64::from(u16::MAX)
                || size == u64::from(u32::MAX)
                || offset == u64::from(u32::MAX)
            {
                return Err(invalid(position, "ZIP64 sentinel without locator"));
            }
        }

        if add(offset, size)? != boundary {
            return Err(invalid(offset, "central directory boundary mismatch"));
        }

        let mut pending_budget = *budget;
        pending_budget.check_entry_count(count)?;
        pending_budget.metadata(size)?;
        if count > size / size::CENTRAL as u64 {
            return Err(invalid(offset, "entry count exceeds directory capacity"));
        }

        if has_locator {
            pending_budget.metadata(position - size::ZIP64_LOCATOR as u64 - boundary)?;
            read_extensible_sector(
                reader,
                boundary + size::ZIP64_END as u64,
                position - size::ZIP64_LOCATOR as u64,
            )
            .await?;
        }

        *budget = pending_budget;
        Ok(Self {
            offset,
            size,
            count,
        })
    }
}

async fn read_extensible_sector<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut RecordReader<'_, R>,
    mut position: u64,
    end: u64,
) -> Result<(), Error> {
    let length = end
        .checked_sub(position)
        .ok_or_else(|| invalid(position, "invalid ZIP64 extension bounds"))?;
    let length = usize::try_from(length)
        .map_err(|_| invalid(position, "ZIP64 extensions exceed addressable memory"))?;
    // Buffer extensions once so tiny fields cannot force millions of seeks.
    let buffer = reader.read_vec(position, length, end).await?;

    let mut bytes = buffer.as_slice();
    let mut records = 0usize;
    while !bytes.is_empty() {
        let Some((header, remaining)) = bytes.split_first_chunk::<{ size::ZIP64_EXTENSION }>()
        else {
            return Err(invalid(position, "truncated ZIP64 extension header"));
        };

        let [
            identifier_low,
            identifier_high,
            length_0,
            length_1,
            length_2,
            length_3,
        ] = *header;
        match ExtraHeaderId::from(u16::from_le_bytes([identifier_low, identifier_high])) {
            ExtraHeaderId::PatchDescriptor
            | ExtraHeaderId::Pkcs7Store
            | ExtraHeaderId::X509File
            | ExtraHeaderId::X509Directory
            | ExtraHeaderId::StrongEncryption
            | ExtraHeaderId::EncryptionRecipients
            | ExtraHeaderId::Aes => {
                return Err(Error::Unsupported {
                    position,
                    feature: "ZIP64 security or patch extension",
                });
            }
            _ => {}
        }

        let length = u32::from_le_bytes([length_0, length_1, length_2, length_3]) as usize;
        bytes = remaining
            .get(length..)
            .ok_or_else(|| invalid(position, "truncated ZIP64 extension"))?;
        position += size::ZIP64_EXTENSION as u64 + length as u64;
        records += 1;

        // Parsing buffered records performs no I/O. Periodically yield to give
        // other tasks a chance to run while processing many small extensions.
        if records.is_multiple_of(1024) {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

impl CentralDirectory {
    /// Reads the entries from this checked directory and charges their output sizes.
    ///
    /// Failed or cancelled reads leave the budget unchanged.
    async fn read_entries<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<Vec<DirectoryEntry>, Error> {
        let mut pending_budget = *budget;
        let end = add(self.offset, self.size)?;
        let mut position = self.offset;
        let mut entries = Vec::new();

        // The archive extra record is part of the directory's declared size.
        if self.size >= size::ARCHIVE_EXTRA as u64 {
            let mut header = [0; size::ARCHIVE_EXTRA];
            reader.read_at(position, &mut header, end).await?;
            if u32::from_le_bytes(array_at::<0, 4, _>(&header)) == signature::ARCHIVE_EXTRA {
                let length = u32::from_le_bytes(array_at::<4, 4, _>(&header)) as usize;
                if add(position, size::ARCHIVE_EXTRA as u64 + length as u64)? > end {
                    return Err(invalid(position, "truncated archive extra record"));
                }

                let bytes = reader
                    .read_vec(position + size::ARCHIVE_EXTRA as u64, length, end)
                    .await?;
                Extras::parse(&bytes, position)?;
                position += size::ARCHIVE_EXTRA as u64 + length as u64;
            }
        }

        for _ in 0..self.count {
            let (entry, next) =
                DirectoryEntry::read(reader, position, end, &mut pending_budget).await?;
            entries.push(entry);
            position = next;

            tokio::task::yield_now().await;
        }

        if position != end {
            return Err(invalid(
                position,
                "unaccounted directory bytes or digital signature",
            ));
        }

        *budget = pending_budget;
        Ok(entries)
    }
}
