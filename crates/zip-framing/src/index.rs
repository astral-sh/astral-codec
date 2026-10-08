use std::str;

use memchr::memmem;
use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    Budget, Error, ExtraHeaderId, Limits, add,
    constants::{extra, signature, size, version},
    extra::Extras,
    invalid,
    record::{RecordReader, array_at},
};

mod entry;

use entry::ResolvedMember;
pub use entry::{CentralDirectoryEntry, Entry, IndexedEntry};

/// A ZIP member index.
///
/// This is constructed from the central directory, with referenced
/// local file entries being resolved lazily upon access through
/// [`Self::entry`].
#[derive(Debug)]
pub struct Index {
    /// The indexed members, in central directory order.
    entries: Vec<IndexedEntry>,
    /// Cached resolutions, with the same length and order as [`Self::entries`].
    resolved: Vec<Option<ResolvedMember>>,
    /// The parse budget. This is debited against when parsing local
    /// file entries and reconciling local/central metadata.
    budget: Budget,
    /// Scratch space for local records, cleared between resolutions.
    buffer: Vec<u8>,
}

impl Index {
    /// Borrows indexed members, without fetching local records or payloads.
    pub fn entries(&self) -> &[IndexedEntry] {
        &self.entries
    }

    /// Returns a previously checked entry by index, without performing I/O.
    ///
    /// Returns [`None`] if the index is out of bounds or the member is unresolved.
    pub fn resolved(&self, index: usize) -> Option<Entry<'_>> {
        Some(Entry {
            indexed: self.entries.get(index)?,
            resolved: self.resolved.get(index)?.as_ref()?,
        })
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
        let mut buffer = Vec::new();
        let mut buffered = RecordReader::new(reader, 64 * 1024, &mut buffer);
        let end = CentralDirectory::read(&mut buffered, &mut budget).await?;
        let entries = end.read_entries(&mut buffered, &mut budget).await?;

        let entries = if entries.is_sorted_by_key(CentralDirectoryEntry::position) {
            if entries
                .first()
                .map_or(end.offset, CentralDirectoryEntry::position)
                != 0
            {
                return Err(invalid(0, "unaccounted bytes before the first member"));
            }

            // Most directories follow physical order. Derive their boundaries
            // directly, without allocating a permutation and a boundary table.
            let mut directory = entries.into_iter().peekable();
            let mut entries = Vec::with_capacity(directory.len());
            while let Some(entry) = directory.next() {
                let boundary = directory
                    .peek()
                    .map_or(end.offset, CentralDirectoryEntry::position);
                entries.push(IndexedEntry::new(entry, boundary)?);
            }
            entries
        } else {
            // APPNOTE 4.4.1.3 permits central entries out of physical order.
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
            entries
                .into_iter()
                .zip(boundaries)
                .map(|(directory, boundary)| IndexedEntry::new(directory, boundary))
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self {
            resolved: (0..entries.len()).map(|_| None).collect(),
            entries,
            budget,
            buffer: Vec::new(),
        })
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
        let Some(indexed) = self.entries.get(index) else {
            return Ok(None);
        };

        let resolved = match &mut self.resolved[index] {
            Some(resolved) => resolved,
            slot => {
                // Cover the fixed header, matching filename, and ZIP64 sizes
                // without speculatively copying a large prefix of the payload.
                let capacity = (size::LOCAL
                    + indexed.directory().path().len()
                    + extra::HEADER_SIZE
                    + extra::ZIP64_LOCAL_SIZE)
                    .min(4096);
                let mut buffered = RecordReader::new(reader, capacity, &mut self.buffer);
                // Failed or cancelled resolution must not charge the same metadata
                // again on retry. Publish the cache and budget only after success.
                let mut pending_budget = self.budget;
                let resolved = indexed
                    .read_local(&mut buffered, &mut pending_budget)
                    .await?;
                self.budget = pending_budget;
                slot.insert(resolved)
            }
        };

        Ok(Some(Entry { indexed, resolved }))
    }

    /// Checks every local header, descriptor, and kind, including unselected members.
    ///
    /// Success establishes complete, non-overlapping record coverage and
    /// agreement of redundant and kind-specific metadata. Payload sizes and
    /// CRCs still need to be verified when decoding. Already checked members
    /// require no I/O.
    pub async fn validate_all<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<(), Error> {
        for index in 0..self.entries.len() {
            self.entry(reader, index).await?;
            tokio::task::consume_budget().await;
        }

        Ok(())
    }
}

/// A ZIP archive's central directory's validated location and extent.
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

        // EOCD has a 16-bit comment length. Never search before this bounded tail.
        let tail_size = length.min(size::END as u64 + u64::from(u16::MAX)) as usize;
        let tail_start = length - tail_size as u64;
        let tail = reader.read_slice(tail_start, tail_size, length).await?;

        let mut candidate = None;
        // Scan the whole tail: a second valid EOCD is ambiguous even
        // when the last 22 bytes already look like an end record.
        for offset in memmem::find_iter(tail, &signature::END.to_le_bytes()) {
            if let Some(header) = tail[offset..].first_chunk::<{ size::END }>()
                && offset
                    + size::END
                    + usize::from(u16::from_le_bytes(array_at::<20, 2, _>(header)))
                    == tail.len()
                && candidate.replace((offset, *header)).is_some()
            {
                return Err(invalid(tail_start + offset as u64, "ambiguous end records"));
            }
        }

        let (offset, end) =
            candidate.ok_or_else(|| invalid(length, "missing end record or trailing bytes"))?;
        let position = tail_start + offset as u64;
        str::from_utf8(&tail[offset + size::END..])
            .map_err(|_| invalid(position, "non-UTF-8 archive comment"))?;

        let mut pending_budget = *budget;
        let (offset, size, count, boundary) = if let Some(record) =
            Zip64EndRecord::read_if_present(reader, position, &mut pending_budget).await?
        {
            for (small, large, sentinel) in [
                (
                    u64::from(u16::from_le_bytes(array_at::<4, 2, _>(&end))),
                    0,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<6, 2, _>(&end))),
                    0,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<8, 2, _>(&end))),
                    record.entry_count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<10, 2, _>(&end))),
                    record.entry_count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<12, 4, _>(&end))),
                    record.directory_size,
                    u64::from(u32::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<16, 4, _>(&end))),
                    record.directory_offset,
                    u64::from(u32::MAX),
                ),
            ] {
                if small != sentinel && small != large {
                    return Err(invalid(position, "classic and ZIP64 end records disagree"));
                }
            }

            (
                record.directory_offset,
                record.directory_size,
                record.entry_count,
                record.position,
            )
        } else {
            if u16::from_le_bytes(array_at::<4, 2, _>(&end)) != 0
                || u16::from_le_bytes(array_at::<6, 2, _>(&end)) != 0
            {
                return Err(Error::Unsupported {
                    position,
                    feature: "multiple volumes",
                });
            }

            if u16::from_le_bytes(array_at::<8, 2, _>(&end))
                != u16::from_le_bytes(array_at::<10, 2, _>(&end))
            {
                return Err(invalid(position, "entry counts disagree"));
            }

            let offset = u64::from(u32::from_le_bytes(array_at::<16, 4, _>(&end)));
            let size = u64::from(u32::from_le_bytes(array_at::<12, 4, _>(&end)));
            let count = u64::from(u16::from_le_bytes(array_at::<10, 2, _>(&end)));
            if count == u64::from(u16::MAX)
                || size == u64::from(u32::MAX)
                || offset == u64::from(u32::MAX)
            {
                return Err(invalid(position, "ZIP64 sentinel without locator"));
            }

            pending_budget.check_entry_count(count)?;
            pending_budget.charge_metadata(size)?;
            (offset, size, count, position)
        };

        if add(offset, size)? != boundary {
            return Err(invalid(offset, "central directory boundary mismatch"));
        }

        if count > size / size::CENTRAL as u64 {
            return Err(invalid(offset, "entry count exceeds directory capacity"));
        }

        *budget = pending_budget;
        Ok(Self {
            offset,
            size,
            count,
        })
    }

    /// Reads the entries from this checked directory and charges their output sizes.
    ///
    /// Failed or cancelled reads leave the budget unchanged.
    async fn read_entries<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<Vec<CentralDirectoryEntry>, Error> {
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
                CentralDirectoryEntry::read(reader, position, end, &mut pending_budget).await?;
            entries.push(entry);
            position = next;

            tokio::task::consume_budget().await;
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

/// A ZIP64 end record with a validated locator, fixed fields, and extensible sector.
struct Zip64EndRecord {
    /// The absolute offset of the ZIP64 end record.
    position: u64,
    /// The declared central directory offset.
    directory_offset: u64,
    /// The declared central directory size in bytes.
    directory_size: u64,
    /// The declared number of central directory entries.
    entry_count: u64,
}

impl Zip64EndRecord {
    /// Reads the record if a ZIP64 locator precedes the classic end record.
    ///
    /// Charges both the directory and this record before reading extensions.
    /// Failed or cancelled reads leave the budget unchanged.
    async fn read_if_present<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut RecordReader<'_, R>,
        end_position: u64,
        budget: &mut Budget,
    ) -> Result<Option<Self>, Error> {
        let Some(locator_position) = end_position.checked_sub(size::ZIP64_LOCATOR as u64) else {
            return Ok(None);
        };
        let mut locator = [0; size::ZIP64_LOCATOR];
        reader
            .read_at(locator_position, &mut locator, end_position)
            .await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&locator)) != signature::ZIP64_LOCATOR {
            return Ok(None);
        }

        if u32::from_le_bytes(array_at::<4, 4, _>(&locator)) != 0
            || u32::from_le_bytes(array_at::<16, 4, _>(&locator)) != 1
        {
            return Err(Error::Unsupported {
                position: locator_position,
                feature: "multiple volumes",
            });
        }

        let position = u64::from_le_bytes(array_at::<8, 8, _>(&locator));
        let mut header = [0; size::ZIP64_END];
        reader
            .read_at(position, &mut header, locator_position)
            .await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != signature::ZIP64_END {
            return Err(invalid(position, "invalid ZIP64 end signature"));
        }

        let end_size = u64::from_le_bytes(array_at::<4, 8, _>(&header));
        if end_size < size::ZIP64_END_BODY as u64
            || add(position, add(size::ZIP64_END_PREFIX as u64, end_size)?)? != locator_position
        {
            return Err(invalid(position, "invalid ZIP64 end length"));
        }

        if u16::from_le_bytes(array_at::<14, 2, _>(&header)) >= version::ZIP64_V2 {
            return Err(Error::Unsupported {
                position,
                feature: "ZIP64 version-2 directory",
            });
        }
        if u16::from_le_bytes(array_at::<14, 2, _>(&header)) != version::ZIP64 {
            return Err(invalid(position, "invalid ZIP64 extraction version"));
        }

        if u32::from_le_bytes(array_at::<16, 4, _>(&header)) != 0
            || u32::from_le_bytes(array_at::<20, 4, _>(&header)) != 0
        {
            return Err(Error::Unsupported {
                position,
                feature: "multiple volumes",
            });
        }

        let entry_count = u64::from_le_bytes(array_at::<32, 8, _>(&header));
        if u64::from_le_bytes(array_at::<24, 8, _>(&header)) != entry_count {
            return Err(invalid(position, "ZIP64 entry counts disagree"));
        }

        let directory_size = u64::from_le_bytes(array_at::<40, 8, _>(&header));
        let mut pending_budget = *budget;
        pending_budget.check_entry_count(entry_count)?;
        pending_budget.charge_metadata(directory_size)?;
        pending_budget.charge_metadata(locator_position - position)?;
        Self::check_extensible_sector(reader, position + size::ZIP64_END as u64, locator_position)
            .await?;

        *budget = pending_budget;
        Ok(Some(Self {
            position,
            directory_offset: u64::from_le_bytes(array_at::<48, 8, _>(&header)),
            directory_size,
            entry_count,
        }))
    }

    async fn check_extensible_sector<R: AsyncRead + AsyncSeek + Unpin>(
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
                tokio::task::consume_budget().await;
            }
        }

        Ok(())
    }
}
