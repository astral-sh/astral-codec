use std::{io::SeekFrom, str};

use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt};

use crate::{
    Error, Limits, add, check_limit,
    extra::Extras,
    invalid,
    record::{ARCHIVE_EXTRA, END, LOCATOR, ZIP64_END, read_at, u16_at, u32_at, u64_at},
};

mod entry;

use entry::CentralEntry;
pub use entry::Entry;

/// The validated index of an archive, in central-directory order.
#[derive(Debug)]
pub struct Index {
    entries: Vec<Entry>,
}

impl Index {
    /// Borrows all indexed entries.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Consumes the index and returns its entries.
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }

    /// Indexes an entire input, starting at byte zero regardless of its cursor.
    ///
    /// All local headers, central records, and descriptors are checked before
    /// this returns. No file payloads are decompressed. A cancelled call may
    /// leave the source cursor anywhere; another call restarts from the end.
    pub async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut R,
        limits: Limits,
    ) -> Result<Self, Error> {
        let end = find_directory(reader, limits).await?;
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
        let central = read_central(reader, &end, &mut budget).await?;

        // Directory order need not match physical order. Sorting offsets also
        // detects shared local headers, overlaps, gaps, and unindexed members.
        let mut order: Vec<_> = central.into_iter().enumerate().collect();
        order.sort_unstable_by_key(|(_, entry)| entry.local_offset());

        let mut entries = Vec::with_capacity(order.len());
        let mut physical = order.into_iter().peekable();
        let mut position = 0;
        while let Some((ordinal, central)) = physical.next() {
            if central.local_offset() != position {
                return Err(invalid(
                    position,
                    "overlapping entries or unaccounted bytes",
                ));
            }

            let boundary = physical
                .peek()
                .map_or(end.offset, |(_, next)| next.local_offset());
            let entry = central.into_entry(reader, boundary, &mut budget).await?;
            entries.push((ordinal, entry));
            position = boundary;

            tokio::task::yield_now().await;
        }

        if position != end.offset {
            return Err(invalid(
                position,
                "unaccounted bytes before central directory",
            ));
        }

        // Restore directory order after consuming the records in physical order.
        entries.sort_unstable_by_key(|(ordinal, _)| *ordinal);

        Ok(Self {
            entries: entries.into_iter().map(|(_, entry)| entry).collect(),
        })
    }
}

struct Budget {
    metadata: u64,
    output: u64,
    limits: Limits,
}

impl Budget {
    fn metadata(&mut self, length: u64) -> Result<(), Error> {
        self.metadata = add(self.metadata, length)?;
        check_limit(self.metadata, self.limits.metadata_size, "metadata bytes")
    }

    fn output(&mut self, size: u64) -> Result<(), Error> {
        check_limit(size, self.limits.member_size, "decoded member bytes")?;

        self.output = add(self.output, size)?;
        check_limit(self.output, self.limits.total_size, "total decoded bytes")
    }
}

struct Directory {
    offset: u64,
    size: u64,
    count: u64,
}

async fn find_directory<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
    limits: Limits,
) -> Result<Directory, Error> {
    let length = reader.seek(SeekFrom::End(0)).await?;
    check_limit(length, limits.archive_size, "archive bytes")?;
    if length < 22 {
        return Err(invalid(0, "missing end of central directory"));
    }

    // EOCD has a 16-bit comment length. Never scan the payload for signatures.
    let tail_size = length.min(22 + u64::from(u16::MAX)) as usize;
    let tail_start = length - tail_size as u64;
    let mut tail = vec![0; tail_size];
    read_at(reader, tail_start, &mut tail, length).await?;

    let mut candidate = None;
    for offset in 0..=tail.len() - 22 {
        if u32_at(&tail, offset) == END
            && offset + 22 + usize::from(u16_at(&tail, offset + 20)) == tail.len()
            && candidate.replace(offset).is_some()
        {
            return Err(invalid(tail_start + offset as u64, "ambiguous end records"));
        }
    }

    let offset =
        candidate.ok_or_else(|| invalid(length, "missing end record or trailing bytes"))?;
    let position = tail_start + offset as u64;
    str::from_utf8(&tail[offset + 22..])
        .map_err(|_| invalid(position, "non-UTF-8 archive comment"))?;

    let end = &tail[offset..offset + 22];
    let mut directory = Directory {
        offset: u64::from(u32_at(end, 16)),
        size: u64::from(u32_at(end, 12)),
        count: u64::from(u16_at(end, 10)),
    };

    let mut boundary = position;
    let mut locator = [0; 20];
    let has_locator = if position >= 20 {
        read_at(reader, position - 20, &mut locator, position).await?;
        u32_at(&locator, 0) == LOCATOR
    } else {
        false
    };

    if has_locator {
        if u32_at(&locator, 4) != 0 || u32_at(&locator, 16) != 1 {
            return Err(Error::Unsupported {
                position: position - 20,
                feature: "multiple volumes",
            });
        }

        boundary = u64_at(&locator, 8);
        let mut zip64 = [0; 56];
        read_at(reader, boundary, &mut zip64, position - 20).await?;
        if u32_at(&zip64, 0) != ZIP64_END {
            return Err(invalid(boundary, "invalid ZIP64 end signature"));
        }

        let size = u64_at(&zip64, 4);
        if size < 44 || add(boundary, add(12, size)?)? != position - 20 {
            return Err(invalid(boundary, "invalid ZIP64 end length"));
        }
        check_limit(size, limits.metadata_size, "ZIP64 end bytes")?;

        if u16_at(&zip64, 14) >= 62 {
            return Err(Error::Unsupported {
                position: boundary,
                feature: "ZIP64 version-2 directory",
            });
        }
        if u16_at(&zip64, 14) != 45 {
            return Err(invalid(boundary, "invalid ZIP64 extraction version"));
        }

        if u32_at(&zip64, 16) != 0 || u32_at(&zip64, 20) != 0 {
            return Err(Error::Unsupported {
                position: boundary,
                feature: "multiple volumes",
            });
        }

        if u64_at(&zip64, 24) != u64_at(&zip64, 32) {
            return Err(invalid(boundary, "ZIP64 entry counts disagree"));
        }

        directory = Directory {
            offset: u64_at(&zip64, 48),
            size: u64_at(&zip64, 40),
            count: u64_at(&zip64, 32),
        };
        for (small, large, sentinel) in [
            (u64::from(u16_at(end, 4)), 0, u64::from(u16::MAX)),
            (u64::from(u16_at(end, 6)), 0, u64::from(u16::MAX)),
            (
                u64::from(u16_at(end, 8)),
                directory.count,
                u64::from(u16::MAX),
            ),
            (
                u64::from(u16_at(end, 10)),
                directory.count,
                u64::from(u16::MAX),
            ),
            (
                u64::from(u32_at(end, 12)),
                directory.size,
                u64::from(u32::MAX),
            ),
            (
                u64::from(u32_at(end, 16)),
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
        if u16_at(end, 4) != 0 || u16_at(end, 6) != 0 {
            return Err(Error::Unsupported {
                position,
                feature: "multiple volumes",
            });
        }

        if u16_at(end, 8) != u16_at(end, 10) {
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

async fn read_extensible_sector<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
    mut position: u64,
    end: u64,
) -> Result<(), Error> {
    // The enclosing end record has already passed the metadata budget. Buffer
    // its extensions once so tiny fields cannot force millions of seeks.
    let length = usize::try_from(end - position)
        .map_err(|_| invalid(position, "ZIP64 extensions exceed addressable memory"))?;
    let mut buffer = vec![0; length];
    read_at(reader, position, &mut buffer, end).await?;

    let mut bytes = buffer.as_slice();
    let mut records = 0usize;
    while !bytes.is_empty() {
        if bytes.len() < 6 {
            return Err(invalid(position, "truncated ZIP64 extension header"));
        }

        match u16_at(bytes, 0) {
            0x000f | 0x0014..=0x0017 | 0x0019 | 0x9901 => {
                return Err(Error::Unsupported {
                    position,
                    feature: "ZIP64 security or patch extension",
                });
            }
            _ => {}
        }

        let length = u32_at(bytes, 2) as usize;
        bytes = bytes[6..]
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
    reader: &mut R,
    directory: &Directory,
    budget: &mut Budget,
) -> Result<Vec<CentralEntry>, Error> {
    let end = add(directory.offset, directory.size)?;
    let mut position = directory.offset;
    let mut entries = Vec::new();

    // The archive extra record is part of the directory's declared size.
    if directory.size >= 8 {
        let mut header = [0; 8];
        read_at(reader, position, &mut header, end).await?;
        if u32_at(&header, 0) == ARCHIVE_EXTRA {
            let length = u32_at(&header, 4) as usize;
            if add(position, 8 + length as u64)? > end {
                return Err(invalid(position, "truncated archive extra record"));
            }

            let mut bytes = vec![0; length];
            read_at(reader, position + 8, &mut bytes, end).await?;
            Extras::parse(&bytes, position)?;
            position += 8 + length as u64;
        }
    }

    for _ in 0..directory.count {
        let (entry, next) = CentralEntry::read(reader, position, end, budget).await?;
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
