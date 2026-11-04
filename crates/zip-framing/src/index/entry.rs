use std::ops::Range;

use tokio::io::{AsyncRead, AsyncSeek};

use crate::{
    Budget, CompressionMethod, EntryKind, Error, HostSystem, add,
    constants::{signature, size},
    extra::{Extras, Header},
    invalid,
    kind::ExternalAttributes,
    record::{Common, GeneralPurposeFlags, RecordReader, array_at, bytes_at, parse_name},
};

/// A member whose local file entry, extras, and optional data descriptor
/// have been reconciled with the directory and checked for a consistent kind.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// The indexed member.
    pub(super) indexed: &'a IndexedEntry,
    /// The reconciled member state.
    pub(super) resolved: &'a ResolvedMember,
}

impl Entry<'_> {
    /// Returns the member's central directory entry.
    pub fn directory(&self) -> &CentralDirectoryEntry {
        &self.indexed.directory
    }

    /// Returns the member's full byte range, including headers and any descriptor.
    pub fn record_range(&self) -> Range<u64> {
        self.indexed.record_range()
    }

    /// Returns the member's kind, validated during local record resolution.
    ///
    /// This does not decode payloads or apply an extraction policy.
    pub fn kind(&self) -> &EntryKind {
        &self.resolved.kind
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

    /// Returns whether a PKWARE UNIX extra field was present in either header.
    ///
    /// A field containing only the timestamp and ownership prefix counts as
    /// present. Any file-type data is available through [`Self::kind`].
    pub fn has_unix_extra(&self) -> bool {
        self.resolved.has_unix_extra
    }
}

#[derive(Debug)]
pub(super) struct ResolvedMember {
    data_offset: u64,
    has_unix_extra: bool,
    kind: EntryKind,
    unix_mode: u16,
}

/// Metadata retained from a member's central directory entry.
#[derive(Debug)]
pub struct CentralDirectoryEntry {
    /// The member's path.
    path: Box<str>,
    /// Common (fixed size) metadata in a central directory entry.
    common: Common,
    /// The effective compressed size declared by the central directory.
    ///
    /// If [`Common::compressed`] is a ZIP64 sentinel, this comes from the
    /// ZIP64 extra field; otherwise it is the inline value widened to `u64`.
    compressed_size: u64,
    /// The effective uncompressed size declared by the central directory.
    ///
    /// If [`Common::uncompressed`] is a ZIP64 sentinel, this comes from the
    /// ZIP64 extra field; otherwise it is the inline value widened to `u64`.
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
    /// within [`Self::made_by`].
    attributes: u32,
    /// Extra data retained for local/central reconciliation. ZIP64-only extras
    /// need no copy: their resolved values and presence are already retained.
    extra: Box<[u8]>,
    /// Whether the central directory entry contained a ZIP64 extra field.
    has_zip64_extra: bool,
}

impl CentralDirectoryEntry {
    /// Returns the exact UTF-8 archive path, without filesystem normalization.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the raw compression method selected by the headers.
    pub fn method(&self) -> CompressionMethod {
        self.common.method
    }

    /// Returns the expected CRC-32 of the decoded payload.
    pub fn crc32(&self) -> u32 {
        self.common.crc
    }

    /// Returns the decoded payload length.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the encoded payload length, excluding headers and descriptors.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Returns the absolute position of the local header.
    pub fn position(&self) -> u64 {
        self.local_offset
    }

    /// Returns the host-system interpretation of the external attributes.
    ///
    /// Unrecognized identifiers are preserved as [`HostSystem::Unknown`].
    pub fn host_system(&self) -> HostSystem {
        HostSystem::from((self.made_by >> 8) as u8)
    }

    /// Returns the raw external file attributes, whose meaning depends on the host.
    pub fn external_attributes(&self) -> u32 {
        self.attributes
    }

    /// Returns the version needed to extract this member.
    pub fn version_needed(&self) -> u16 {
        self.common.version
    }

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

        let common = Common::parse(&array_at::<6, { Common::SIZE }, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<30, 2, _>(&header)));
        let comment_length = usize::from(u16::from_le_bytes(array_at::<32, 2, _>(&header)));
        let variable = reader
            .read_slice(
                position + size::CENTRAL as u64,
                name_length + extra_length + comment_length,
                end,
            )
            .await?;

        let extras = Extras::parse(
            &variable[name_length..name_length + extra_length],
            Header::Central,
            position,
        )?;
        let (sizes, local_offset) = extras.central_sizes(
            common,
            u32::from_le_bytes(array_at::<42, 4, _>(&header)),
            u16::from_le_bytes(array_at::<34, 2, _>(&header)),
            position,
        )?;

        let path = parse_name(&variable[..name_length], common.flags, position)?;
        extras.check_name(path, position)?;
        extras.comment(&variable[name_length + extra_length..], position)?;

        if common.method == CompressionMethod::Stored && sizes.compressed != sizes.uncompressed {
            return Err(invalid(position, "stored member sizes differ"));
        }

        if sizes.uncompressed == 0 && common.crc != 0 {
            return Err(invalid(position, "empty member has nonzero CRC"));
        }

        budget.charge_member(sizes.uncompressed)?;
        let entry = Self {
            path: path.into(),
            common,
            compressed_size: sizes.compressed,
            size: sizes.uncompressed,
            local_offset,
            made_by: u16::from_le_bytes(array_at::<4, 2, _>(&header)),
            attributes: u32::from_le_bytes(array_at::<38, 4, _>(&header)),
            extra: if extras.needs_reconciliation() {
                variable[name_length..name_length + extra_length].into()
            } else {
                Box::default()
            },
            has_zip64_extra: sizes.zip64,
        };

        Ok((
            entry,
            position + size::CENTRAL as u64 + variable.len() as u64,
        ))
    }
}

/// An indexed ZIP member and its central directory entry.
///
/// Its directory metadata is available through [`Self::directory`].
/// The member's local records are checked on demand by [`super::Index::entry`]
/// or [`super::Index::validate_all`]. Successful checks are cached by the index
/// and exposed through [`super::Index::resolved`].
#[derive(Debug)]
pub struct IndexedEntry {
    directory: CentralDirectoryEntry,
    /// The exclusive end offset of the span assigned to the local header,
    /// filename, extras, data, and optional data descriptor.
    boundary: u64,
}

impl IndexedEntry {
    /// Returns the member's central directory entry.
    pub fn directory(&self) -> &CentralDirectoryEntry {
        &self.directory
    }

    /// Returns the span assigned to this member by the directory's offsets.
    ///
    /// This range can be prefetched before selection. Its local records have
    /// not necessarily been checked, and it includes headers and any descriptor.
    pub fn record_range(&self) -> Range<u64> {
        self.directory.position()..self.boundary
    }

    #[inline]
    pub(super) fn new(directory: CentralDirectoryEntry, boundary: u64) -> Result<Self, Error> {
        let mut entry = Self {
            directory,
            boundary,
        };
        entry.set_boundary(boundary)?;
        Ok(entry)
    }

    #[inline]
    pub(super) fn set_boundary(&mut self, boundary: u64) -> Result<(), Error> {
        // Even without a local read, the fixed header, filename and payload
        // must fit. Exact coverage and descriptor sizes are checked on access.
        let minimum = add(
            size::LOCAL as u64 + self.directory.path.len() as u64,
            self.directory.compressed_size(),
        )?;
        let minimum = add(
            minimum,
            if self
                .directory
                .common
                .flags
                .contains(GeneralPurposeFlags::DATA_DESCRIPTOR)
            {
                size::DESCRIPTOR as u64
            } else {
                0
            },
        )?;
        if add(self.directory.position(), minimum)? > boundary {
            return Err(invalid(
                self.directory.position(),
                "member cannot fit before the next record",
            ));
        }

        self.boundary = boundary;
        Ok(())
    }

    /// Read and validate an indexed entry's local header, filename, extras, and optional descriptor
    /// against its corresponding central directory entry.
    pub(super) async fn read_local<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        budget: &mut Budget,
    ) -> Result<ResolvedMember, Error> {
        let directory = &self.directory;
        let boundary = self.boundary;
        let position = directory.local_offset;
        let mut header = [0; size::LOCAL];
        reader.read_at(position, &mut header, boundary).await?;
        if u32::from_le_bytes(array_at::<0, 4, _>(&header)) != signature::LOCAL {
            return Err(invalid(position, "invalid local header signature"));
        }

        let common = Common::parse(&array_at::<4, { Common::SIZE }, _>(&header), position)?;
        let name_length = usize::from(u16::from_le_bytes(array_at::<26, 2, _>(&header)));
        let extra_length = usize::from(u16::from_le_bytes(array_at::<28, 2, _>(&header)));
        budget.charge_metadata((size::LOCAL + name_length + extra_length) as u64)?;

        let variable = reader
            .read_slice(
                position + size::LOCAL as u64,
                name_length + extra_length,
                boundary,
            )
            .await?;

        let extras = Extras::parse(&variable[name_length..], Header::Local, position)?;
        let sizes = extras.local_sizes(common, position)?;
        // Equal bytes inherit the directory's UTF-8 and filename validation.
        // Header agreement below also requires identical encoding flags.
        if &variable[..name_length] != directory.path.as_bytes() {
            return Err(invalid(position, "local and central filenames disagree"));
        }
        extras.check_name(&directory.path, position)?;

        let unix_data = extras.resolve(
            Extras::parse(&directory.extra, Header::Central, position)?,
            position,
        )?;

        if (Common {
            crc: directory.common.crc,
            compressed: directory.common.compressed,
            uncompressed: directory.common.uncompressed,
            ..common
        }) != directory.common
        {
            return Err(invalid(position, "local and central headers disagree"));
        }

        if common.flags.contains(GeneralPurposeFlags::DATA_DESCRIPTOR) {
            if common.crc != 0 || sizes.compressed != 0 || sizes.uncompressed != 0 {
                return Err(invalid(
                    position,
                    "descriptor member has nonzero local CRC or sizes",
                ));
            }
        } else if common.crc != directory.common.crc
            || sizes.compressed != directory.compressed_size
            || sizes.uncompressed != directory.size
        {
            return Err(invalid(position, "local and central CRC or sizes disagree"));
        }

        let data_offset = add(position, size::LOCAL as u64 + variable.len() as u64)?;
        let data_end = add(data_offset, directory.compressed_size)?;
        if data_end > boundary {
            return Err(invalid(position, "payload overlaps the next record"));
        }

        if common.flags.contains(GeneralPurposeFlags::DATA_DESCRIPTOR) {
            self.check_descriptor(reader, data_end, sizes.zip64 || directory.has_zip64_extra)
                .await?;
        } else if data_end != boundary {
            return Err(invalid(data_end, "unaccounted bytes after payload"));
        }

        let attributes =
            ExternalAttributes::new(directory.host_system(), directory.external_attributes());
        Ok(ResolvedMember {
            data_offset,
            has_unix_extra: unix_data.is_some(),
            kind: EntryKind::resolve(directory, unix_data, &attributes)?,
            unix_mode: attributes.unix_mode,
        })
    }

    /// Validate a data descriptor after a member's compressed contents.
    ///
    /// The data descriptor supplies a local entry's sizes and CRC32 when
    /// the local header leaves them as placeholders (and the general purpose
    /// flag indicates that a descriptor follows the contents).
    async fn check_descriptor<R: AsyncRead + AsyncSeek + Unpin>(
        &self,
        reader: &mut RecordReader<'_, R>,
        position: u64,
        zip64: bool,
    ) -> Result<(), Error> {
        let directory = &self.directory;
        let unsigned_length = if zip64 {
            size::ZIP64_DESCRIPTOR as u64
        } else {
            size::DESCRIPTOR as u64
        };
        let length = self.boundary - position;
        if length != unsigned_length && length != unsigned_length + size::SIGNATURE as u64 {
            return Err(invalid(position, "invalid data descriptor length"));
        }

        let mut bytes = [0; size::SIGNATURE + size::ZIP64_DESCRIPTOR];
        reader
            .read_at(position, &mut bytes[..length as usize], self.boundary)
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

        if crc != directory.common.crc
            || compressed != directory.compressed_size
            || uncompressed != directory.size
        {
            return Err(invalid(
                position,
                "data descriptor disagrees with central header",
            ));
        }

        Ok(())
    }
}
