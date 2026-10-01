//! Canonical UTF-8, single-volume ZIP64 record serialization.
//!
//! Completed members serialize matching local and central headers without data
//! descriptors. Writers can reserve local header space before streaming data.

use crate::{
    CompressionMethod, Error, ExtraHeaderId, HostSystem, add,
    constants::{extra, signature, size, version},
    invalid,
    kind::{ExternalAttributes, UnixFileType},
    record::{Common, GeneralPurposeFlags, SizeField, validate_name},
};

// APPNOTE 4.4.2: the high byte identifies the host system for external
// attributes; the low byte is the ZIP specification version (45 = 4.5).
// We always emit UNIX mode bits, regardless of the platform running the encoder.
const VERSION_MADE_BY: u16 = ((HostSystem::Unix.to_byte() as u16) << 8) | version::ZIP64;

// 00:00:00, 1980-01-01 in the DOS date/time format.
const DEFAULT_TIME: u16 = 0;
const DEFAULT_DATE: u16 = 0x0021;

/// A portable file type represented by the encoder's Unix attributes.
#[derive(Clone, Copy, Debug)]
pub enum EntryKind {
    /// A regular file, optionally carrying executable intent.
    File { executable: bool },
    /// A directory, whose serialized name ends in `/`.
    Directory,
    /// A symbolic link with its UTF-8 target stored in the payload.
    SymbolicLink,
}

/// Validated metadata for a ZIP64 member awaiting its final CRC and sizes.
///
/// Once the payload's CRC and sizes are known, [`Self::finish`] produces a
/// [`CompletedMember`] that can serialize the local and central headers.
pub struct PendingMember<'a> {
    path: &'a str,
    method: CompressionMethod,
    kind: EntryKind,
}

impl<'a> PendingMember<'a> {
    /// Checks the path and method before any output is written.
    pub fn new(path: &'a str, method: CompressionMethod, kind: EntryKind) -> Result<Self, Error> {
        if path.is_empty() || path.len() > usize::from(u16::MAX) {
            return Err(invalid(0, "empty or oversized filename"));
        }

        validate_name(path, 0)?;
        if path.ends_with('/') != matches!(kind, EntryKind::Directory) {
            return Err(invalid(0, "filename suffix disagrees with member kind"));
        }

        if matches!(kind, EntryKind::Directory) && method != CompressionMethod::Stored {
            return Err(invalid(0, "directories must be stored without file data"));
        }

        Ok(Self { path, method, kind })
    }

    /// Returns the payload compression method.
    pub fn method(&self) -> CompressionMethod {
        self.method
    }

    /// Returns the space to reserve for the completed local header.
    pub fn local_header_size(&self) -> usize {
        size::LOCAL + extra::HEADER_SIZE + extra::ZIP64_LOCAL_SIZE + self.path.len()
    }

    /// Returns the central header size in bytes, including the filename and
    /// ZIP64 extra field.
    pub fn central_header_size(&self) -> usize {
        size::CENTRAL + extra::HEADER_SIZE + extra::ZIP64_CENTRAL_SIZE + self.path.len()
    }

    /// Completes metadata after the payload's CRC and sizes are known.
    pub fn finish(
        self,
        crc: u32,
        compressed: u64,
        uncompressed: u64,
        offset: u64,
    ) -> Result<CompletedMember<'a>, Error> {
        if self.method == CompressionMethod::Stored && compressed != uncompressed {
            return Err(invalid(offset, "stored member sizes differ"));
        }

        if uncompressed == 0 && (compressed != 0 || crc != 0) {
            return Err(invalid(offset, "empty member has file data or nonzero CRC"));
        }

        if matches!(self.kind, EntryKind::Directory) && uncompressed != 0 {
            return Err(invalid(offset, "directory has file data"));
        }

        Ok(CompletedMember {
            header: self,
            crc,
            compressed,
            uncompressed,
            offset,
        })
    }
}

/// Final member metadata with a consistent method, CRC, and size tuple.
pub struct CompletedMember<'a> {
    header: PendingMember<'a>,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    offset: u64,
}

impl CompletedMember<'_> {
    /// Serializes the local header with the final CRC and sizes.
    pub fn local_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.local_header_size());
        push32(&mut bytes, signature::LOCAL);
        bytes.extend_from_slice(&self.common().to_bytes());
        push16(&mut bytes, self.header.path.len() as u16);
        push16(
            &mut bytes,
            (extra::HEADER_SIZE + extra::ZIP64_LOCAL_SIZE) as u16,
        );

        bytes.extend_from_slice(self.header.path.as_bytes());

        push16(&mut bytes, u16::from(ExtraHeaderId::Zip64));
        push16(&mut bytes, extra::ZIP64_LOCAL_SIZE as u16);
        push64(&mut bytes, self.uncompressed);
        push64(&mut bytes, self.compressed);

        bytes
    }

    /// Serializes the matching central-directory header.
    pub fn central_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.central_header_size());
        push32(&mut bytes, signature::CENTRAL);
        push16(&mut bytes, VERSION_MADE_BY);
        bytes.extend_from_slice(&self.common().to_bytes());
        push16(&mut bytes, self.header.path.len() as u16);
        push16(
            &mut bytes,
            (extra::HEADER_SIZE + extra::ZIP64_CENTRAL_SIZE) as u16,
        );
        push16(&mut bytes, 0); // Comment length.
        push16(&mut bytes, 0); // Starting disk.
        push16(&mut bytes, 0); // Internal attributes.

        let (file_type, permissions) = match self.header.kind {
            EntryKind::File { executable: true } => (UnixFileType::Regular, 0o755),
            EntryKind::File { executable: false } => (UnixFileType::Regular, 0o644),
            EntryKind::Directory => (UnixFileType::Directory, 0o755),
            EntryKind::SymbolicLink => (UnixFileType::SymbolicLink, 0o777),
        };
        let dos = if matches!(self.header.kind, EntryKind::Directory) {
            ExternalAttributes::DOS_DIRECTORY
        } else {
            0
        };
        push32(
            &mut bytes,
            (u32::from(u16::from(file_type) | permissions) << ExternalAttributes::UNIX_MODE_SHIFT)
                | dos,
        );
        push32(&mut bytes, u32::MAX);

        bytes.extend_from_slice(self.header.path.as_bytes());

        push16(&mut bytes, u16::from(ExtraHeaderId::Zip64));
        push16(&mut bytes, extra::ZIP64_CENTRAL_SIZE as u16);
        push64(&mut bytes, self.uncompressed);
        push64(&mut bytes, self.compressed);
        push64(&mut bytes, self.offset);

        bytes
    }

    /// Returns a [`Common`] for this completed member's common metadata.
    fn common(&self) -> Common {
        Common {
            version: version::ZIP64,
            flags: GeneralPurposeFlags::UTF8,
            method: self.header.method,
            time: DEFAULT_TIME,
            date: DEFAULT_DATE,
            crc: self.crc,
            compressed: SizeField::Zip64,
            uncompressed: SizeField::Zip64,
        }
    }
}

/// Serializes the ZIP64 end record, locator, and classic end record.
///
/// See [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
/// sections 4.3.14 through 4.3.16 for the record layouts.
pub fn end_records(count: u64, offset: u64, size: u64) -> Result<Vec<u8>, Error> {
    let position = add(offset, size)?;
    let mut bytes = Vec::with_capacity(size::ZIP64_END + size::ZIP64_LOCATOR + size::END);

    // ZIP64 end of central directory record (APPNOTE 4.3.14): stores the
    // entry count and central directory size and offset as 64-bit values.
    push32(&mut bytes, signature::ZIP64_END);
    // The size excludes the 12-byte signature/size prefix (APPNOTE 4.3.14.1).
    push64(&mut bytes, size::ZIP64_END_BODY as u64);
    push16(&mut bytes, VERSION_MADE_BY);
    push16(&mut bytes, version::ZIP64);
    push32(&mut bytes, 0); // This disk.
    push32(&mut bytes, 0); // Disk containing the central directory.
    push64(&mut bytes, count); // Entries on this disk.
    push64(&mut bytes, count); // Total entries.
    push64(&mut bytes, size);
    push64(&mut bytes, offset);

    // ZIP64 end of central directory locator (APPNOTE 4.3.15): points to
    // the ZIP64 end record above. This single-volume archive uses disk 0.
    push32(&mut bytes, signature::ZIP64_LOCATOR);
    push32(&mut bytes, 0);
    push64(&mut bytes, position);
    push32(&mut bytes, 1); // Total disks.

    // End of central directory record (APPNOTE 4.3.16): the required archive
    // terminator. The maximum count, size, and offset values select the ZIP64
    // fields above (APPNOTE 4.4.21 through 4.4.24).
    push32(&mut bytes, signature::END);
    push16(&mut bytes, 0);
    push16(&mut bytes, 0);
    push16(&mut bytes, u16::MAX);
    push16(&mut bytes, u16::MAX);
    push32(&mut bytes, u32::MAX);
    push32(&mut bytes, u32::MAX);
    push16(&mut bytes, 0); // No archive comment.

    Ok(bytes)
}

fn push16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
