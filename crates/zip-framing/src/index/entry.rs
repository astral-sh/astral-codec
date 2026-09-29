use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    CompressionMethod, Error, add,
    extra::{Extras, ResolvedExtras},
    invalid,
    record::{CENTRAL, Common, DESCRIPTOR, LOCAL, read_at, u16_at, u32_at, u64_at},
};

use super::Budget;

#[derive(Clone, Debug)]
struct Metadata {
    path: String,
    common: Common,
    compressed_size: u64,
    size: u64,
    local_offset: u64,
    made_by: u16,
    attributes: u32,
}

/// A member whose record boundaries and redundant headers have been checked.
#[derive(Clone, Debug)]
pub struct Entry {
    metadata: Metadata,
    data_offset: u64,
    extras: ResolvedExtras,
}

impl Entry {
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

    /// Returns the absolute position of the encoded payload.
    pub fn data_offset(&self) -> u64 {
        self.data_offset
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

    /// Returns APPNOTE UNIX extra-field data for links or device numbers.
    ///
    /// The fixed timestamp/ownership prefix is excluded. Consumers must
    /// interpret this data together with the external Unix file type.
    pub fn unix_extra_data(&self) -> Option<&[u8]> {
        self.extras.unix_data()
    }
}

// A central record is provisional until its local record and descriptor agree.
// Keep Entry's fields private to this module so the index cannot construct one
// from central metadata alone.
pub(super) struct CentralEntry {
    metadata: Metadata,
    extra: Vec<u8>,
}

impl CentralEntry {
    pub(super) fn local_offset(&self) -> u64 {
        self.metadata.local_offset
    }

    pub(super) async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut R,
        position: u64,
        end: u64,
        budget: &mut Budget,
    ) -> Result<(Self, u64), Error> {
        let mut header = [0; 46];
        read_at(reader, position, &mut header, end).await?;
        if u32_at(&header, 0) != CENTRAL {
            return Err(invalid(position, "invalid central header signature"));
        }

        let common = Common::parse(&header[6..], position)?;
        let name_length = usize::from(u16_at(&header, 28));
        let extra_length = usize::from(u16_at(&header, 30));
        let comment_length = usize::from(u16_at(&header, 32));
        let mut variable = vec![0; name_length + extra_length + comment_length];
        read_at(reader, position + 46, &mut variable, end).await?;

        let extras = Extras::parse(&variable[name_length..name_length + extra_length], position)?;
        let sizes = extras.zip64(
            common,
            Some(u32_at(&header, 42)),
            Some(u16_at(&header, 34)),
            position,
        )?;

        let path = extras.name(&variable[..name_length], common.flags, position)?;
        extras.comment(
            &variable[name_length + extra_length..],
            common.flags,
            position,
        )?;

        budget.output(sizes.uncompressed)?;
        if common.method == CompressionMethod::Stored && sizes.compressed != sizes.uncompressed {
            return Err(invalid(position, "stored member sizes differ"));
        }

        if sizes.uncompressed == 0 && common.crc != 0 {
            return Err(invalid(position, "empty member has nonzero CRC"));
        }

        let entry = Self {
            metadata: Metadata {
                path,
                common,
                compressed_size: sizes.compressed,
                size: sizes.uncompressed,
                local_offset: sizes.offset,
                made_by: u16_at(&header, 4),
                attributes: u32_at(&header, 38),
            },
            extra: variable[name_length..name_length + extra_length].to_vec(),
        };

        Ok((entry, position + 46 + variable.len() as u64))
    }

    pub(super) async fn into_entry<R: AsyncRead + AsyncSeek + Unpin>(
        self,
        reader: &mut R,
        boundary: u64,
        budget: &mut Budget,
    ) -> Result<Entry, Error> {
        let Self { metadata, extra } = self;
        let position = metadata.local_offset;
        let mut header = [0; 30];
        read_at(reader, position, &mut header, boundary).await?;
        if u32_at(&header, 0) != LOCAL {
            return Err(invalid(position, "invalid local header signature"));
        }

        let common = Common::parse(&header[4..], position)?;
        let name_length = usize::from(u16_at(&header, 26));
        let extra_length = usize::from(u16_at(&header, 28));
        budget.metadata(30 + (name_length + extra_length) as u64)?;

        let mut variable = vec![0; name_length + extra_length];
        read_at(reader, position + 30, &mut variable, boundary).await?;

        let extras = Extras::parse(&variable[name_length..], position)?;
        let sizes = extras.zip64(common, None, None, position)?;
        if extras.name(&variable[..name_length], common.flags, position)? != metadata.path {
            return Err(invalid(position, "local and central filenames disagree"));
        }

        let extras = extras.resolve(Extras::parse(&extra, position)?, position)?;

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
            read_descriptor(reader, &metadata, data_end, boundary, zip64).await?;
        } else if data_end != boundary {
            return Err(invalid(data_end, "unaccounted bytes after payload"));
        }

        Ok(Entry {
            metadata,
            data_offset,
            extras,
        })
    }
}

async fn read_descriptor<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
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
    read_at(reader, position, &mut bytes[..length as usize], end).await?;

    // Length disambiguates a signature-less descriptor whose CRC is itself
    // 0x08074b50. Never search for a descriptor inside compressed data.
    let offset = if length == unsigned_length + 4 {
        if u32_at(&bytes, 0) != DESCRIPTOR {
            return Err(invalid(position, "invalid data descriptor signature"));
        }

        4
    } else {
        0
    };

    let crc = u32_at(&bytes, offset);
    let compressed = if zip64 {
        u64_at(&bytes, offset + 4)
    } else {
        u64::from(u32_at(&bytes, offset + 4))
    };
    let uncompressed = if zip64 {
        u64_at(&bytes, offset + 12)
    } else {
        u64::from(u32_at(&bytes, offset + 8))
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
