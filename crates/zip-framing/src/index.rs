use std::{cell::RefCell, mem, str};

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

thread_local! {
    static DIRECTORY_WINDOW: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Owns its window across awaits, returning a bounded allocation for later opens.
struct DirectoryWindow(Vec<u8>);

impl DirectoryWindow {
    fn take() -> Self {
        Self(
            DIRECTORY_WINDOW
                .try_with(|window| {
                    window
                        .try_borrow_mut()
                        .map(|mut window| mem::take(&mut *window))
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
        )
    }
}

impl Drop for DirectoryWindow {
    fn drop(&mut self) {
        // Variable records can require a larger window; retain only the usual
        // bounded end-record scan allocation, at most one per thread.
        if self.0.capacity() <= size::END + usize::from(u16::MAX) {
            self.0.clear();
            let _ = DIRECTORY_WINDOW.try_with(|window| {
                if let Ok(mut window) = window.try_borrow_mut()
                    && window.capacity() < self.0.capacity()
                {
                    *window = mem::take(&mut self.0);
                }
            });
        }
    }
}

/// A ZIP member index.
///
/// This is constructed from the central directory, with referenced
/// local file entries being resolved lazily upon access through
/// [`Self::entry`].
#[derive(Debug)]
pub struct Index {
    /// The indexed members, in central directory order.
    entries: Vec<IndexedEntry>,
    /// Cached resolutions in directory order, allocated on first access.
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
        // Opening owns this budget until the index is complete. Errors and
        // cancellation discard all charges made by the opening helpers.
        let mut budget = Budget::new(limits);
        let mut buffer = DirectoryWindow::take();
        let mut buffered = RecordReader::new(reader, 64 * 1024, &mut buffer.0);
        let end = CentralDirectory::read(&mut buffered, &mut budget).await?;
        let mut entries = end.read_entries(&mut buffered, &mut budget).await?;

        if entries.is_sorted_by_key(|entry| entry.directory().position()) {
            if entries
                .first()
                .map_or(end.offset, |entry| entry.directory().position())
                != 0
            {
                return Err(invalid(0, "unaccounted bytes before the first member"));
            }

            // Most directories follow physical order. Assign their boundaries
            // in place, without a second allocation for the indexed entries.
            let mut directory = entries.iter_mut().peekable();
            while let Some(entry) = directory.next() {
                entry.set_boundary(
                    directory
                        .peek()
                        .map_or(end.offset, |next| next.directory().position()),
                )?;
            }
        } else {
            // APPNOTE 4.4.1.3 permits central entries out of physical order.
            // Preserve directory order while assigning boundaries in physical order.
            // Only local reads can establish exact coverage inside these spans.
            let mut order: Vec<_> = (0..entries.len()).collect();
            order.sort_unstable_by_key(|&index| entries[index].directory().position());
            if order
                .first()
                .map_or(end.offset, |&index| entries[index].directory().position())
                != 0
            {
                return Err(invalid(0, "unaccounted bytes before the first member"));
            }

            // The last entry already has the directory offset as its boundary.
            // Keep the earliest directory-order error even though assignment
            // proceeds in physical order.
            let mut first_error = None;
            for (&index, &next) in order.iter().zip(order.iter().skip(1)) {
                let boundary = entries[next].directory().position();
                if let Err(error) = entries[index].set_boundary(boundary)
                    && first_error.as_ref().is_none_or(|(first, _)| index < *first)
                {
                    first_error = Some((index, error));
                }
            }
            if let Some((_, error)) = first_error {
                return Err(error);
            }
        }

        Ok(Self {
            resolved: Vec::new(),
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

        if self.resolved.is_empty() {
            self.resolved.resize_with(self.entries.len(), || None);
        }

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
    /// metadata before returning.
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

        let (offset, end) = find_end(tail, tail_start)?;
        let position = tail_start + offset as u64;
        str::from_utf8(&tail[offset + size::END..])
            .map_err(|_| invalid(position, "non-UTF-8 archive comment"))?;

        let (offset, size, count, boundary) = if let Some(record) =
            Zip64EndRecord::read_if_present(reader, position, budget).await?
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

            budget.check_entry_count(count)?;
            budget.charge_metadata(size)?;
            (offset, size, count, position)
        };

        if add(offset, size)? != boundary {
            return Err(invalid(offset, "central directory boundary mismatch"));
        }

        if count > size / size::CENTRAL as u64 {
            return Err(invalid(offset, "entry count exceeds directory capacity"));
        }

        Ok(Self {
            offset,
            size,
            count,
        })
    }

    /// Reads the entries from this checked directory and charges their output sizes.
    async fn read_entries<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<Vec<IndexedEntry>, Error> {
        let end = add(self.offset, self.size)?;
        let mut position = self.offset;
        // The entry count and directory size have already passed their budgets.
        let mut entries = Vec::with_capacity(self.count as usize);

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
            let (entry, next) = CentralDirectoryEntry::read(reader, position, end, budget).await?;
            entries.push(IndexedEntry::new(entry, self.offset)?);
            position = next;

            tokio::task::consume_budget().await;
        }

        if position != end {
            return Err(invalid(
                position,
                "unaccounted directory bytes or digital signature",
            ));
        }

        Ok(entries)
    }
}

/// Scans the whole tail: a second EOCD reaching EOF is ambiguous even when the
/// last 22 bytes already look like an end record.
fn find_end(tail: &[u8], tail_start: u64) -> Result<(usize, [u8; size::END]), Error> {
    const SIGNATURE: [u8; 4] = signature::END.to_le_bytes();
    let mut candidate = None;
    let mut scan = |bytes: &[u8], start: usize| {
        for offset in memmem::find_iter(bytes, &SIGNATURE).map(|offset| start + offset) {
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
        Ok(())
    };

    // Filter short blocks by the EOCD suffix, avoiding the common PK prefix of
    // other ZIP records. The reduction permits vectorization without intrinsics.
    let candidates = tail.len() - (size::END - 1);
    let (blocks, remainder) = tail[2..2 + candidates].as_chunks::<64>();
    for (ordinal, first) in blocks.iter().enumerate() {
        let start = ordinal * 64;
        let second = &tail[start + 3..start + 3 + 64];
        let candidate = first
            .iter()
            .zip(second)
            .fold(0, |found, (&first, &second)| {
                found | (u8::from(first == SIGNATURE[2]) & u8::from(second == SIGNATURE[3]))
            });
        if candidate != 0 {
            // Include the next three bytes for signatures crossing a block
            // boundary. Each possible starting position is checked once.
            scan(&tail[start..start + 64 + 3], start)?;
        }
    }
    let start = blocks.len() * 64;
    scan(&tail[start..start + remainder.len() + 3], start)?;

    candidate.ok_or_else(|| {
        invalid(
            tail_start + tail.len() as u64,
            "missing end record or trailing bytes",
        )
    })
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
        budget.check_entry_count(entry_count)?;
        budget.charge_metadata(directory_size)?;
        budget.charge_metadata(locator_position - position)?;
        Self::check_extensible_sector(reader, position + size::ZIP64_END as u64, locator_position)
            .await?;

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
