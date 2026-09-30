use std::ops::{Deref, Range};

use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    CompressionMethod, Error, add,
    extra::{Extras, ResolvedExtras},
    invalid,
    record::{CENTRAL, Common, DESCRIPTOR, LOCAL, RecordReader, array_at, bytes_at},
};

use super::Budget;

/// Central directory metadata for a ZIP member.
#[derive(Clone, Debug)]
struct Metadata {
    /// The member's path.
    path: String,
    common: Common,
    compressed_size: u64,
    size: u64,
    local_offset: u64,
    made_by: u16,
    attributes: u32,
}

/// A member whose local records have been reconciled with the directory.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    directory: &'a DirectoryEntry,
    local: &'a LocalEntry,
}

impl Entry<'_> {
    /// Returns the absolute position of the encoded payload.
    pub fn data_offset(&self) -> u64 {
        self.local.data_offset
    }

    /// Returns reconciled APPNOTE UNIX data for links or device numbers.
    ///
    /// The timestamp/ownership prefix is excluded. Interpret this data with
    /// the external Unix file type.
    pub fn unix_extra_data(&self) -> Option<&[u8]> {
        self.local.extras.unix_data()
    }
}

impl Deref for Entry<'_> {
    type Target = DirectoryEntry;

    fn deref(&self) -> &Self::Target {
        self.directory
    }
}

#[derive(Debug)]
struct LocalEntry {
    data_offset: u64,
    extras: ResolvedExtras,
}

/// Metadata declared by a central-directory record.
///
/// The local header and descriptor are checked only when [`super::Index::entry`]
/// selects this member. Only a checked [`Entry`] exposes a payload offset and
/// reconciled UNIX extra-field data.
#[derive(Debug)]
pub struct DirectoryEntry {
    metadata: Metadata,
    extra: Vec<u8>,
    boundary: u64,
    local: Option<LocalEntry>,
}

impl DirectoryEntry {
    /// Returns the exact UTF-8 archive path, without filesystem normalization.
    pub fn path(&self) -> &str {
        &self.metadata.path
    }

    /// Returns the raw compression method selected by the headers.
    pub fn method(&self) -> CompressionMethod {
        self.metadata.common.method
    }

    /// Returns the expected CRC-32 of the decoded payload.
    pub fn crc32(&self) -> u32 {
        self.metadata.common.crc
    }

    /// Returns the decoded payload length.
    pub fn size(&self) -> u64 {
        self.metadata.size
    }

    /// Returns the encoded payload length, excluding headers and descriptors.
    pub fn compressed_size(&self) -> u64 {
        self.metadata.compressed_size
    }

    /// Returns the absolute position of the local header.
    pub fn position(&self) -> u64 {
        self.metadata.local_offset
    }

    /// Returns the host-system identifier for the external attributes.
    pub fn host_system(&self) -> u8 {
        (self.metadata.made_by >> 8) as u8
    }

    /// Returns the external file attributes, interpreted according to the host.
    pub fn external_attributes(&self) -> u32 {
        self.metadata.attributes
    }

    /// Returns the version needed to extract this member.
    pub fn version_needed(&self) -> u16 {
        self.metadata.common.version
    }

    /// Returns the span assigned to this member by the directory's offsets.
    ///
    /// This range can be prefetched before selection. Its local records have
    /// not necessarily been checked, and it includes headers and any descriptor.
    pub fn record_range(&self) -> Range<u64> {
        self.position()..self.boundary
    }

    /// Returns the previously checked entry, without performing I/O.
    pub fn resolved(&self) -> Option<Entry<'_>> {
        self.local.as_ref().map(|local| Entry {
            directory: self,
            local,
        })
    }

    pub(super) fn set_boundary(&mut self, boundary: u64) -> Result<(), Error> {
        // Even without a local read, the fixed header, filename and payload
        // must fit. Exact coverage and descriptor sizes are checked on access.
        let minimum = add(30 + self.metadata.path.len() as u64, self.compressed_size())?;
        let minimum = add(
            minimum,
            if self.metadata.common.descriptor() {
                12
            } else {
                0
            },
        )?;
        if add(self.position(), minimum)? > boundary {
            return Err(invalid(
                self.position(),
                "member cannot fit before the next record",
            ));
        }

        self.boundary = boundary;
        Ok(())
    }

    pub(super) async fn resolve<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
        budget: &mut Budget,
    ) -> Result<Entry<'_>, Error> {
        if self.local.is_none() {
            let mut buffered = RecordReader::new(reader, 4096);
            // Failed or cancelled resolution must not charge the same metadata
            // again on retry. Publish the cache and budget only after success.
            let mut pending_budget = *budget;
            let local = self.read_local(&mut buffered, &mut pending_budget).await?;
            self.local = Some(local);
            *budget = pending_budget;
        }

        self.resolved()
            .ok_or_else(|| invalid(self.position(), "missing resolved local record"))
    }

    pub(super) async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut RecordReader<'_, R>,
        position: u64,
        end: u64,
        budget: &mut Budget,
    ) -> Result<(Self, u64), Error> {
        let mut header = [0; 46];
        reader.read_at(position, &mut header, end).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != CENTRAL {
            return Err(invalid(position, "invalid central header signature"));
        }

        let common = Common::parse(&array_at::<6, 22, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<30, 2, _>(&header)));
        let comment_length = usize::from(u16::from_le_bytes(array_at::<32, 2, _>(&header)));
        let mut variable = vec![0; name_length + extra_length + comment_length];
        reader.read_at(position + 46, &mut variable, end).await?;

        let extras = Extras::parse(&variable[name_length..name_length + extra_length], position)?;
        let sizes = extras.zip64(
            common,
            Some(u32::from_le_bytes(array_at::<42, 4, _>(&header))),
            Some(u16::from_le_bytes(array_at::<34, 2, _>(&header))),
            position,
        )?;

        let path = extras.name(&variable[..name_length], common.flags, position)?;
        extras.comment(&variable[name_length + extra_length..], position)?;

        budget.output(sizes.uncompressed)?;
        if common.method == CompressionMethod::Stored && sizes.compressed != sizes.uncompressed {
            return Err(invalid(position, "stored member sizes differ"));
        }

        if sizes.uncompressed == 0 && common.crc != 0 {
            return Err(invalid(position, "empty member has nonzero CRC"));
        }

        let entry = Self {
            metadata: Metadata {
                path: path.to_owned(),
                common,
                compressed_size: sizes.compressed,
                size: sizes.uncompressed,
                local_offset: sizes.offset,
                made_by: u16::from_le_bytes(array_at::<4, 2, _>(&header)),
                attributes: u32::from_le_bytes(array_at::<38, 4, _>(&header)),
            },
            extra: variable[name_length..name_length + extra_length].to_vec(),
            boundary: end,
            local: None,
        };

        Ok((entry, position + 46 + variable.len() as u64))
    }

    async fn read_local<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<LocalEntry, Error> {
        let metadata = &self.metadata;
        let boundary = self.boundary;
        let position = metadata.local_offset;
        let mut header = [0; 30];
        reader.read_at(position, &mut header, boundary).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != LOCAL {
            return Err(invalid(position, "invalid local header signature"));
        }

        let common = Common::parse(&array_at::<4, 22, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<26, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        budget.metadata(30 + (name_length + extra_length) as u64)?;

        let mut variable = vec![0; name_length + extra_length];
        reader
            .read_at(position + 30, &mut variable, boundary)
            .await?;

        let extras = Extras::parse(&variable[name_length..], position)?;
        let sizes = extras.zip64(common, None, None, position)?;
        if extras.name(&variable[..name_length], common.flags, position)? != metadata.path {
            return Err(invalid(position, "local and central filenames disagree"));
        }

        let extras = extras.resolve(Extras::parse(&self.extra, position)?, position)?;

        if (Common {
            crc: metadata.common.crc,
            compressed: metadata.common.compressed,
            uncompressed: metadata.common.uncompressed,
            ..common
        }) != metadata.common
        {
            return Err(invalid(position, "local and central headers disagree"));
        }

        if common.descriptor() {
            if common.crc != 0 || sizes.compressed != 0 || sizes.uncompressed != 0 {
                return Err(invalid(
                    position,
                    "descriptor member has nonzero local CRC or sizes",
                ));
            }
        } else if common.crc != metadata.common.crc
            || sizes.compressed != metadata.compressed_size
            || sizes.uncompressed != metadata.size
        {
            return Err(invalid(position, "local and central CRC or sizes disagree"));
        }

        let data_offset = add(position, 30 + variable.len() as u64)?;
        let data_end = add(data_offset, metadata.compressed_size)?;
        if data_end > boundary {
            return Err(invalid(position, "payload overlaps the next record"));
        }

        if common.descriptor() {
            let zip64 = sizes.zip64
                || metadata.common.compressed == u32::MAX
                || metadata.common.uncompressed == u32::MAX;
            read_descriptor(reader, metadata, data_end, boundary, zip64).await?;
        } else if data_end != boundary {
            return Err(invalid(data_end, "unaccounted bytes after payload"));
        }

        Ok(LocalEntry {
            data_offset,
            extras,
        })
    }
}

async fn read_descriptor<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut RecordReader<'_, R>,
    metadata: &Metadata,
    position: u64,
    end: u64,
    zip64: bool,
) -> Result<(), Error> {
    let unsigned_length = if zip64 { 20 } else { 12 };
    let length = end - position;
    if length != unsigned_length && length != unsigned_length + 4 {
        return Err(invalid(position, "invalid data descriptor length"));
    }

    let mut bytes = [0; 24];
    reader
        .read_at(position, &mut bytes[..length as usize], end)
        .await?;

    // Length disambiguates a signature-less descriptor whose CRC is itself
    // 0x08074b50. Never search for a descriptor inside compressed data.
    let offset = if length == unsigned_length + 4 {
        if u32::from_le_bytes(array_at::<0, 4, _>(&bytes)) != DESCRIPTOR {
            return Err(invalid(position, "invalid data descriptor signature"));
        }

        4
    } else {
        0
    };

    let crc = u32::from_le_bytes(bytes_at(&bytes, offset, position)?);
    let compressed = if zip64 {
        u64::from_le_bytes(bytes_at(&bytes, offset + 4, position)?)
    } else {
        u64::from(u32::from_le_bytes(bytes_at(&bytes, offset + 4, position)?))
    };
    let uncompressed = if zip64 {
        u64::from_le_bytes(bytes_at(&bytes, offset + 12, position)?)
    } else {
        u64::from(u32::from_le_bytes(bytes_at(&bytes, offset + 8, position)?))
    };

    if crc != metadata.common.crc
        || compressed != metadata.compressed_size
        || uncompressed != metadata.size
    {
        return Err(invalid(
            position,
            "data descriptor disagrees with central header",
        ));
    }

    Ok(())
}
