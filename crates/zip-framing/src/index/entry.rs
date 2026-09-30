use std::ops::{Deref, Range};

use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    CompressionMethod, EntryKind, Error, HostSystem, add,
    constants::{signature, size},
    extra::{Extras, ResolvedExtras},
    invalid,
    kind::ExternalAttributes,
    record::{Common, RecordReader, array_at, bytes_at},
};

use super::Budget;

/// Central directory metadata for a ZIP member.
#[derive(Clone, Debug)]
struct Metadata {
    /// The member's path.
    path: String,
    /// Common (fixed size) metadata in a central directory entry.
    common: Common,
    /// The effective compressed size declared by the central directory.
    ///
    /// If [`Common::compressed`] is `u32::MAX`, this comes from the ZIP64
    /// extra field; otherwise it is [`Common::compressed`] widened to `u64`.
    compressed_size: u64,
    /// The effective uncompressed size declared by the central directory.
    ///
    /// If [`Common::uncompressed`] is `u32::MAX`, this comes from the ZIP64
    /// extra field; otherwise it is [`Common::uncompressed`] widened to `u64`.
    size: u64,
    /// An absolute offset to the central directory entry's corresponding
    /// local file entry.
    ///
    /// If the central directory's 32-bit offset is `u32::MAX`, this comes
    /// from the ZIP64 extra field; otherwise it is that offset widened to `u64`.
    ///
    /// Note that our parser is conservative and rejects ZIPs with arbitrary
    /// prefixed content, so this is always the offset from the start of the
    /// source.
    local_offset: u64,
    /// The "version made by" field in the central directory entry.
    made_by: u16,
    /// The central directory entry's raw external file attributes.
    ///
    /// The semantics of this field depend on the system identifier
    /// within [`Metadata::made_by`].
    attributes: u32,
}

/// A member whose local file entry, extras, and optional data descriptor
/// have been reconciled with the directory and checked for a consistent kind.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// The indexed member.
    indexed: &'a IndexedEntry,
    /// The reconciled member state.
    resolved: &'a ResolvedMember,
}

impl Entry<'_> {
    /// Returns the member's kind, validated during local record resolution.
    ///
    /// This does not decode payloads or apply an extraction policy.
    pub fn kind(&self) -> EntryKind {
        self.resolved.kind
    }

    /// Returns the UNIX file type and permission bits from external attributes.
    ///
    /// This is zero for hosts other than UNIX and Darwin.
    pub fn unix_mode(&self) -> u16 {
        self.resolved.unix_mode
    }

    /// Returns the absolute position of the encoded payload.
    pub fn data_offset(&self) -> u64 {
        self.resolved.data_offset
    }

    /// Returns reconciled APPNOTE UNIX data for links or device numbers.
    ///
    /// The timestamp/ownership prefix is excluded. Interpret this data with
    /// the member's [`Self::kind`]. Link-target contents have not been validated.
    pub fn unix_extra_data(&self) -> Option<&[u8]> {
        self.resolved.extras.unix_data()
    }
}

impl Deref for Entry<'_> {
    type Target = IndexedEntry;

    fn deref(&self) -> &Self::Target {
        self.indexed
    }
}

#[derive(Debug)]
struct ResolvedMember {
    data_offset: u64,
    extras: ResolvedExtras,
    kind: EntryKind,
    unix_mode: u16,
}

/// Metadata retained from a member's central directory entry.
#[derive(Debug)]
pub struct DirectoryEntry {
    /// Central directory entry metadata.
    metadata: Metadata,
    /// Raw extra data for the central directory entry.
    extra: Vec<u8>,
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

    /// Returns the host-system interpretation of the external attributes.
    ///
    /// Unrecognized identifiers are preserved as [`HostSystem::Unknown`].
    pub fn host_system(&self) -> HostSystem {
        HostSystem::from((self.metadata.made_by >> 8) as u8)
    }

    /// Returns the raw external file attributes, whose meaning depends on the host.
    pub fn external_attributes(&self) -> u32 {
        self.metadata.attributes
    }

    /// Returns the version needed to extract this member.
    pub fn version_needed(&self) -> u16 {
        self.metadata.common.version
    }
}

/// An indexed ZIP member and its central directory entry.
///
/// Its directory metadata is available through [`Self::directory`].
/// The member's local records are checked on demand by [`super::Index::entry`]
/// or [`super::Index::validate_all`]. Successful checks are cached and exposed
/// through [`Self::resolved`].
#[derive(Debug)]
pub struct IndexedEntry {
    directory: DirectoryEntry,
    /// The exclusive end offset of the span assigned to the local header,
    /// filename, extras, data, and optional data descriptor.
    boundary: u64,
    resolved: Option<ResolvedMember>,
}

impl IndexedEntry {
    /// Returns the member's central directory entry.
    pub fn directory(&self) -> &DirectoryEntry {
        &self.directory
    }

    /// Returns the span assigned to this member by the directory's offsets.
    ///
    /// This range can be prefetched before selection. Its local records have
    /// not necessarily been checked, and it includes headers and any descriptor.
    pub fn record_range(&self) -> Range<u64> {
        self.directory.position()..self.boundary
    }

    /// Returns the previously checked entry, without performing I/O.
    pub fn resolved(&self) -> Option<Entry<'_>> {
        self.resolved.as_ref().map(|resolved| Entry {
            indexed: self,
            resolved,
        })
    }

    pub(super) fn new(directory: DirectoryEntry, boundary: u64) -> Result<Self, Error> {
        // Even without a local read, the fixed header, filename and payload
        // must fit. Exact coverage and descriptor sizes are checked on access.
        let minimum = add(
            size::LOCAL as u64 + directory.metadata.path.len() as u64,
            directory.compressed_size(),
        )?;
        let minimum = add(
            minimum,
            if directory.metadata.common.descriptor() {
                size::DESCRIPTOR as u64
            } else {
                0
            },
        )?;
        if add(directory.position(), minimum)? > boundary {
            return Err(invalid(
                directory.position(),
                "member cannot fit before the next record",
            ));
        }

        Ok(Self {
            directory,
            boundary,
            resolved: None,
        })
    }

    pub(super) async fn resolve<R: AsyncRead + AsyncSeek + Unpin>(
        &mut self,
        reader: &mut R,
        budget: &mut Budget,
    ) -> Result<Entry<'_>, Error> {
        if self.resolved.is_none() {
            let mut buffered = RecordReader::new(reader, 4096);
            // Failed or cancelled resolution must not charge the same metadata
            // again on retry. Publish the cache and budget only after success.
            let mut pending_budget = *budget;
            let resolved = self.read_local(&mut buffered, &mut pending_budget).await?;
            self.resolved = Some(resolved);
            *budget = pending_budget;
        }

        self.resolved()
            .ok_or_else(|| invalid(self.directory.position(), "missing resolved local record"))
    }
}

impl DirectoryEntry {
    pub(super) async fn read<R: AsyncRead + AsyncSeek + Unpin>(
        reader: &mut RecordReader<'_, R>,
        position: u64,
        end: u64,
        budget: &mut Budget,
    ) -> Result<(Self, u64), Error> {
        let mut header = [0; size::CENTRAL];
        reader.read_at(position, &mut header, end).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != signature::CENTRAL {
            return Err(invalid(position, "invalid central header signature"));
        }

        let common = Common::parse(&array_at::<6, { size::COMMON }, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<30, 2, _>(&header)));
        let comment_length = usize::from(u16::from_le_bytes(array_at::<32, 2, _>(&header)));
        let variable = reader
            .read_vec(
                position + size::CENTRAL as u64,
                name_length + extra_length + comment_length,
                end,
            )
            .await?;

        let extras = Extras::parse(&variable[name_length..name_length + extra_length], position)?;
        let sizes = extras.zip64(
            common,
            Some(u32::from_le_bytes(array_at::<42, 4, _>(&header))),
            Some(u16::from_le_bytes(array_at::<34, 2, _>(&header))),
            position,
        )?;

        let path = extras.name(&variable[..name_length], common.flags, position)?;
        extras.comment(&variable[name_length + extra_length..], position)?;

        if common.method == CompressionMethod::Stored && sizes.compressed != sizes.uncompressed {
            return Err(invalid(position, "stored member sizes differ"));
        }

        if sizes.uncompressed == 0 && common.crc != 0 {
            return Err(invalid(position, "empty member has nonzero CRC"));
        }

        budget.output(sizes.uncompressed)?;
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
        };

        Ok((
            entry,
            position + size::CENTRAL as u64 + variable.len() as u64,
        ))
    }
}

impl IndexedEntry {
    async fn read_local<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<ResolvedMember, Error> {
        let metadata = &self.directory.metadata;
        let boundary = self.boundary;
        let position = metadata.local_offset;
        let mut header = [0; size::LOCAL];
        reader.read_at(position, &mut header, boundary).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != signature::LOCAL {
            return Err(invalid(position, "invalid local header signature"));
        }

        let common = Common::parse(&array_at::<4, { size::COMMON }, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<26, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        budget.metadata((size::LOCAL + name_length + extra_length) as u64)?;

        let variable = reader
            .read_vec(
                position + size::LOCAL as u64,
                name_length + extra_length,
                boundary,
            )
            .await?;

        let extras = Extras::parse(&variable[name_length..], position)?;
        let sizes = extras.zip64(common, None, None, position)?;
        if extras.name(&variable[..name_length], common.flags, position)? != metadata.path {
            return Err(invalid(position, "local and central filenames disagree"));
        }

        let extras = extras.resolve(Extras::parse(&self.directory.extra, position)?, position)?;

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

        let data_offset = add(position, size::LOCAL as u64 + variable.len() as u64)?;
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

        let attributes = ExternalAttributes::new(
            self.directory.host_system(),
            self.directory.external_attributes(),
        );
        let kind = EntryKind::resolve(&self.directory, extras.unix_data(), &attributes)?;

        Ok(ResolvedMember {
            data_offset,
            extras,
            kind,
            unix_mode: attributes.unix_mode,
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
    let unsigned_length = if zip64 {
        size::ZIP64_DESCRIPTOR as u64
    } else {
        size::DESCRIPTOR as u64
    };
    let length = end - position;
    if length != unsigned_length && length != unsigned_length + size::SIGNATURE as u64 {
        return Err(invalid(position, "invalid data descriptor length"));
    }

    let mut bytes = [0; size::SIGNATURE + size::ZIP64_DESCRIPTOR];
    reader
        .read_at(position, &mut bytes[..length as usize], end)
        .await?;

    // Length disambiguates a signature-less descriptor whose CRC is itself
    // 0x08074b50. Never search for a descriptor inside compressed data.
    let offset = if length == unsigned_length + size::SIGNATURE as u64 {
        if u32::from_le_bytes(array_at::<0, 4, _>(&bytes)) != signature::DESCRIPTOR {
            return Err(invalid(position, "invalid data descriptor signature"));
        }

        size::SIGNATURE
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
