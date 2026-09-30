use std::str;

use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    Error, Limits, add, check_limit,
    extra::Extras,
    invalid,
    record::{ARCHIVE_EXTRA, END, LOCATOR, RecordReader, ZIP64_END, array_at},
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
        let mut buffered = RecordReader::new(reader, 64 * 1024);
        let end = CentralDirectory::read(&mut buffered, limits).await?;
        check_limit(end.count, limits.entries as u64, "entry count")?;
        check_limit(end.size, limits.metadata_size, "metadata bytes")?;
        if end.count > end.size / 46 {
            return Err(invalid(
                end.offset,
                "entry count exceeds directory capacity",
            ));
        }

        let mut budget = Budget {
            metadata: end.size,
            output: 0,
            limits,
        };
        let entries = read_central(&mut buffered, &end, &mut budget).await?;

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

    /// Checks every local header and descriptor, including unselected members.
    ///
    /// Success establishes complete, nonoverlapping record coverage and
    /// agreement of redundant metadata. Payload sizes and CRCs still need to
    /// be verified when decoding. Already checked members require no I/O.
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
    /// Debit from the metadata budget.
    fn metadata(&mut self, length: u64) -> Result<(), Error> {
        self.metadata = add(self.metadata, length)?;
        check_limit(self.metadata, self.limits.metadata_size, "metadata bytes")
    }

    /// Debit from the output size budgets.
    fn output(&mut self, size: u64) -> Result<(), Error> {
        check_limit(size, self.limits.member_size, "decoded member bytes")?;

        self.output = add(self.output, size)?;
        check_limit(self.output, self.limits.total_size, "total decoded bytes")
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
    async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut RecordReader<'_, R>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let length = reader.length().await?;
        check_limit(length, limits.archive_size, "archive bytes")?;
        if length < 22 {
            return Err(invalid(0, "missing end of central directory"));
        }

        // EOCD has a 16-bit comment length. Never scan the payload for signatures.
        let tail_size = length.min(22 + u64::from(u16::MAX)) as usize;
        let tail_start = length - tail_size as u64;
        let mut tail = vec![0; tail_size];
        reader.read_at(tail_start, &mut tail, length).await?;

        let mut candidate = None;
        for (offset, header) in tail.windows(22).enumerate() {
            if header.starts_with(&END.to_le_bytes())
                && let Some(header) = header.first_chunk::<22>()
                && offset + 22 + usize::from(u16::from_le_bytes(array_at::<20, 2, _>(header)))
                    == tail.len()
                && candidate.replace((offset, header)).is_some()
            {
                return Err(invalid(tail_start + offset as u64, "ambiguous end records"));
            }
        }

        let (offset, end) =
            candidate.ok_or_else(|| invalid(length, "missing end record or trailing bytes"))?;
        let position = tail_start + offset as u64;
        str::from_utf8(&tail[offset + 22..])
            .map_err(|_| invalid(position, "non-UTF-8 archive comment"))?;

        let mut directory = Self {
            offset: u64::from(u32::from_le_bytes(array_at::<16, 4, _>(end))),
            size: u64::from(u32::from_le_bytes(array_at::<12, 4, _>(end))),
            count: u64::from(u16::from_le_bytes(array_at::<10, 2, _>(end))),
        };

        let mut boundary = position;
        let mut locator = [0; 20];
        let has_locator = if position >= 20 {
            reader
                .read_at(position - 20, &mut locator, position)
                .await?;
            u32::from_le_bytes(array_at::<0, 4, _>(&locator)) == LOCATOR
        } else {
            false
        };

        if has_locator {
            if u32::from_le_bytes(array_at::<4, 4, _>(&locator)) != 0
                || u32::from_le_bytes(array_at::<16, 4, _>(&locator)) != 1
            {
                return Err(Error::Unsupported {
                    position: position - 20,
                    feature: "multiple volumes",
                });
            }

            boundary = u64::from_le_bytes(array_at::<8, 8, _>(&locator));
            let mut zip64 = [0; 56];
            reader.read_at(boundary, &mut zip64, position - 20).await?;
            if u32::from_le_bytes(array_at::<0, 4, _>(&zip64)) != ZIP64_END {
                return Err(invalid(boundary, "invalid ZIP64 end signature"));
            }

            let size = u64::from_le_bytes(array_at::<4, 8, _>(&zip64));
            if size < 44 || add(boundary, add(12, size)?)? != position - 20 {
                return Err(invalid(boundary, "invalid ZIP64 end length"));
            }
            check_limit(size, limits.metadata_size, "ZIP64 end bytes")?;

            if u16::from_le_bytes(array_at::<14, 2, _>(&zip64)) >= 62 {
                return Err(Error::Unsupported {
                    position: boundary,
                    feature: "ZIP64 version-2 directory",
                });
            }
            if u16::from_le_bytes(array_at::<14, 2, _>(&zip64)) != 45 {
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

            directory = Self {
                offset: u64::from_le_bytes(array_at::<48, 8, _>(&zip64)),
                size: u64::from_le_bytes(array_at::<40, 8, _>(&zip64)),
                count: u64::from_le_bytes(array_at::<32, 8, _>(&zip64)),
            };
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
                    directory.count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u16::from_le_bytes(array_at::<10, 2, _>(end))),
                    directory.count,
                    u64::from(u16::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<12, 4, _>(end))),
                    directory.size,
                    u64::from(u32::MAX),
                ),
                (
                    u64::from(u32::from_le_bytes(array_at::<16, 4, _>(end))),
                    directory.offset,
                    u64::from(u32::MAX),
                ),
            ] {
                if small != sentinel && small != large {
                    return Err(invalid(position, "classic and ZIP64 end records disagree"));
                }
            }

            read_extensible_sector(reader, boundary + 56, position - 20).await?;
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

            if directory.count == u64::from(u16::MAX)
                || directory.size == u64::from(u32::MAX)
                || directory.offset == u64::from(u32::MAX)
            {
                return Err(invalid(position, "ZIP64 sentinel without locator"));
            }
        }

        if add(directory.offset, directory.size)? != boundary {
            return Err(invalid(
                directory.offset,
                "central directory boundary mismatch",
            ));
        }

        Ok(directory)
    }
}

async fn read_extensible_sector<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut RecordReader<'_, R>,
    mut position: u64,
    end: u64,
) -> Result<(), Error> {
    // The enclosing end record has already passed the metadata budget. Buffer
    // its extensions once so tiny fields cannot force millions of seeks.
    let length = usize::try_from(end - position)
        .map_err(|_| invalid(position, "ZIP64 extensions exceed addressable memory"))?;
    let mut buffer = vec![0; length];
    reader.read_at(position, &mut buffer, end).await?;

    let mut bytes = buffer.as_slice();
    let mut records = 0usize;
    while !bytes.is_empty() {
        let Some((header, remaining)) = bytes.split_first_chunk::<6>() else {
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
        match u16::from_le_bytes([identifier_low, identifier_high]) {
            0x000f | 0x0014..=0x0017 | 0x0019 | 0x9901 => {
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
        position += 6 + length as u64;
        records += 1;

        // Parsing buffered records performs no I/O. Periodically yield to give
        // other tasks a chance to run while processing many small extensions.
        if records.is_multiple_of(1024) {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

async fn read_central<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut RecordReader<'_, R>,
    directory: &CentralDirectory,
    budget: &mut Budget,
) -> Result<Vec<DirectoryEntry>, Error> {
    let end = add(directory.offset, directory.size)?;
    let mut position = directory.offset;
    let mut entries = Vec::new();

    // The archive extra record is part of the directory's declared size.
    if directory.size >= 8 {
        let mut header = [0; 8];
        reader.read_at(position, &mut header, end).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) == ARCHIVE_EXTRA {
            let length = u32::from_le_bytes(array_at::<4, 4, _>(&header)) as usize;
            if add(position, 8 + length as u64)? > end {
                return Err(invalid(position, "truncated archive extra record"));
            }

            let mut bytes = vec![0; length];
            reader.read_at(position + 8, &mut bytes, end).await?;
            Extras::parse(&bytes, position)?;
            position += 8 + length as u64;
        }
    }

    for _ in 0..directory.count {
        let (entry, next) = DirectoryEntry::read(reader, position, end, budget).await?;
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

    Ok(entries)
}
