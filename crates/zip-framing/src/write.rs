//! Canonical UTF-8, single-volume ZIP64 record serialization.
//!
//! Completed members serialize matching local and central headers without data
//! descriptors. Writers can reserve local header space before streaming data.

use crate::{
    CompressionMethod, Error, ExtraHeaderId, HostSystem, add,
    constants::{extra, signature, size, version},
    invalid,
    kind::{ExternalAttributes, UnixFileType},
    record::{
        Common, GeneralPurposeFlags, MemberHeader, MemberPayload, PayloadFields, SizeField,
        validate_name,
    },
};

// APPNOTE 4.4.2: the high byte identifies the host system for external
// attributes; the low byte is the ZIP specification version (45 = 4.5).
// We always emit UNIX mode bits, regardless of the platform running the encoder.
const VERSION_MADE_BY: u16 = ((HostSystem::Unix.to_wire() as u16) << 8) | version::ZIP64;

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

    /// Serializes both headers with space for the final CRC and payload sizes.
    /// Completing the headers keeps their lengths fixed.
    pub fn prepare_headers(self, offset: u64) -> PendingHeaders<'a> {
        let mut local = Vec::with_capacity(self.local_header_size());
        let mut central = Vec::with_capacity(self.central_header_size());
        let payload = PayloadFields::default();
        let local_fields = self.append_local_header(&mut local, payload);
        let central_fields = self.append_central_header(&mut central, payload, offset);
        PendingHeaders {
            member: self,
            offset,
            local_fields,
            central_fields,
            headers: MemberHeaders {
                local: local.into_boxed_slice(),
                central: central.into_boxed_slice(),
            },
        }
    }

    /// Completes metadata after the payload's CRC and sizes are known.
    pub fn finish(
        self,
        crc: u32,
        compressed: u64,
        uncompressed: u64,
        offset: u64,
    ) -> Result<CompletedMember<'a>, Error> {
        let payload = PayloadFields {
            crc,
            compressed,
            uncompressed,
        }
        .validate(self.method, offset)?;

        if uncompressed == 0 && compressed != 0 {
            return Err(invalid(offset, "empty member has file data"));
        }

        if matches!(self.kind, EntryKind::Directory) && uncompressed != 0 {
            return Err(invalid(offset, "directory has file data"));
        }

        if matches!(self.kind, EntryKind::SymbolicLink) && uncompressed == 0 {
            return Err(invalid(offset, "empty symbolic-link target"));
        }

        Ok(CompletedMember {
            header: self,
            payload,
            offset,
        })
    }

    fn append_local_header(&self, bytes: &mut Vec<u8>, payload: PayloadFields) -> HeaderFields {
        push32(bytes, signature::LOCAL);
        let common = self.append_common(bytes, extra::ZIP64_LOCAL_SIZE, payload.crc);
        let sizes = self.append_name_and_sizes(bytes, extra::ZIP64_LOCAL_SIZE, payload);
        HeaderFields { common, sizes }
    }

    fn append_central_header(
        &self,
        bytes: &mut Vec<u8>,
        payload: PayloadFields,
        offset: u64,
    ) -> HeaderFields {
        push32(bytes, signature::CENTRAL);
        push16(bytes, VERSION_MADE_BY);
        let common = self.append_common(bytes, extra::ZIP64_CENTRAL_SIZE, payload.crc);
        push16(bytes, 0); // Comment length.
        push16(bytes, 0); // Starting disk.
        push16(bytes, 0); // Internal attributes.

        let (file_type, permissions) = match self.kind {
            EntryKind::File { executable: true } => (UnixFileType::Regular, 0o755),
            EntryKind::File { executable: false } => (UnixFileType::Regular, 0o644),
            EntryKind::Directory => (UnixFileType::Directory, 0o755),
            EntryKind::SymbolicLink => (UnixFileType::SymbolicLink, 0o777),
        };
        let dos = if matches!(self.kind, EntryKind::Directory) {
            ExternalAttributes::DOS_DIRECTORY
        } else {
            0
        };
        push32(
            bytes,
            (u32::from(u16::from(file_type) | permissions) << ExternalAttributes::UNIX_MODE_SHIFT)
                | dos,
        );
        push32(bytes, u32::MAX);

        let sizes = self.append_name_and_sizes(bytes, extra::ZIP64_CENTRAL_SIZE, payload);
        push64(bytes, offset);
        HeaderFields { common, sizes }
    }

    fn append_name_and_sizes(
        &self,
        bytes: &mut Vec<u8>,
        zip64_size: usize,
        payload: PayloadFields,
    ) -> usize {
        bytes.extend_from_slice(self.path.as_bytes());
        push16(bytes, u16::from(ExtraHeaderId::Zip64));
        push16(bytes, zip64_size as u16);
        let start = bytes.len();
        bytes.extend_from_slice(&zip64_sizes(payload));
        start
    }

    fn append_common(&self, bytes: &mut Vec<u8>, zip64_size: usize, crc: u32) -> usize {
        let start = bytes.len();
        bytes.extend_from_slice(&self.common_bytes(crc));
        push16(bytes, self.path.len() as u16);
        push16(bytes, (extra::HEADER_SIZE + zip64_size) as u16);
        start
    }

    fn common_bytes(&self, crc: u32) -> [u8; MemberHeader::SIZE] {
        MemberHeader {
            common: Common {
                version: version::ZIP64,
                flags: GeneralPurposeFlags::UTF8,
                method: self.method,
                time: DEFAULT_TIME,
                date: DEFAULT_DATE,
            },
            payload: PayloadFields {
                crc,
                compressed: SizeField::Zip64,
                uncompressed: SizeField::Zip64,
            },
        }
        .to_bytes()
    }
}

/// Final member metadata with a consistent method, CRC, and size tuple.
pub struct CompletedMember<'a> {
    header: PendingMember<'a>,
    payload: MemberPayload,
    offset: u64,
}

impl CompletedMember<'_> {
    /// Serializes the local header with the final CRC and sizes.
    pub fn local_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.local_header_size());
        self.header
            .append_local_header(&mut bytes, self.payload.fields());
        bytes
    }

    /// Serializes the matching central-directory header.
    pub fn central_header(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.append_central_header(&mut bytes);
        bytes
    }

    /// Appends the matching central-directory header to `bytes`.
    pub fn append_central_header(&self, bytes: &mut Vec<u8>) {
        bytes.reserve(self.header.central_header_size());
        self.header
            .append_central_header(bytes, self.payload.fields(), self.offset);
    }
}

/// A pair of fixed-length header buffers awaiting the final CRC and sizes.
pub struct PendingHeaders<'a> {
    member: PendingMember<'a>,
    offset: u64,
    local_fields: HeaderFields,
    central_fields: HeaderFields,
    headers: MemberHeaders,
}

impl PendingHeaders<'_> {
    /// Returns the compression method for the payload.
    pub fn method(&self) -> CompressionMethod {
        self.member.method
    }

    /// Returns the provisional local header with placeholders for the final CRC and sizes.
    pub fn local(&self) -> &[u8] {
        &self.headers.local
    }

    /// Returns the length of the matching central-directory header.
    pub fn central_len(&self) -> usize {
        self.headers.central.len()
    }

    /// Validates the payload metadata and fills both headers in place.
    pub fn finish(
        mut self,
        crc: u32,
        compressed: u64,
        uncompressed: u64,
    ) -> Result<MemberHeaders, Error> {
        let member = self
            .member
            .finish(crc, compressed, uncompressed, self.offset)?;
        let common = member.header.common_bytes(crc);
        let sizes = zip64_sizes(member.payload.fields());
        self.local_fields
            .patch(&mut self.headers.local, &common, &sizes);
        self.central_fields
            .patch(&mut self.headers.central, &common, &sizes);
        Ok(self.headers)
    }
}

/// The serialized headers of a completed member.
pub struct MemberHeaders {
    /// Local header to write before the payload.
    pub local: Box<[u8]>,
    /// Matching header to append to the central directory.
    pub central: Box<[u8]>,
}

struct HeaderFields {
    common: usize,
    sizes: usize,
}

impl HeaderFields {
    fn patch(&self, bytes: &mut [u8], common: &[u8; MemberHeader::SIZE], sizes: &[u8; 16]) {
        bytes[self.common..][..common.len()].copy_from_slice(common);
        bytes[self.sizes..][..sizes.len()].copy_from_slice(sizes);
    }
}

fn zip64_sizes(payload: PayloadFields) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&payload.uncompressed.to_le_bytes());
    bytes[8..].copy_from_slice(&payload.compressed.to_le_bytes());
    bytes
}

/// The fixed-length ZIP64 end record, locator, and classic end record.
pub struct EndRecords([u8; Self::SIZE]);

impl EndRecords {
    /// The total number of bytes written at the end of the archive.
    pub const SIZE: usize = size::ZIP64_END + size::ZIP64_LOCATOR + size::END;

    /// Serializes the end records for a single-volume archive without a comment.
    pub fn new(count: u64, offset: u64, directory_size: u64) -> Result<Self, Error> {
        let position = add(offset, directory_size)?;
        let mut bytes = [0; Self::SIZE];
        let (zip64, rest) = bytes.split_at_mut(size::ZIP64_END);
        let (locator, classic) = rest.split_at_mut(size::ZIP64_LOCATOR);

        // APPNOTE 4.3.14: both disk fields are zero for a single-volume archive.
        zip64[..4].copy_from_slice(&signature::ZIP64_END.to_le_bytes());
        zip64[4..12].copy_from_slice(&(size::ZIP64_END_BODY as u64).to_le_bytes());
        zip64[12..14].copy_from_slice(&VERSION_MADE_BY.to_le_bytes());
        zip64[14..16].copy_from_slice(&version::ZIP64.to_le_bytes());
        zip64[24..32].copy_from_slice(&count.to_le_bytes());
        zip64[32..40].copy_from_slice(&count.to_le_bytes());
        zip64[40..48].copy_from_slice(&directory_size.to_le_bytes());
        zip64[48..56].copy_from_slice(&offset.to_le_bytes());

        // APPNOTE 4.3.15: the locator points to the ZIP64 end record on disk zero.
        locator[..4].copy_from_slice(&signature::ZIP64_LOCATOR.to_le_bytes());
        locator[8..16].copy_from_slice(&position.to_le_bytes());
        locator[16..20].copy_from_slice(&1u32.to_le_bytes());

        // APPNOTE 4.3.16: maximum count, size, and offset select the ZIP64 values.
        classic[..4].copy_from_slice(&signature::END.to_le_bytes());
        classic[8..20].fill(u8::MAX);

        Ok(Self(bytes))
    }

    /// Borrows the serialized end records in archive order.
    pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }
}

/// Serializes the ZIP64 end record, locator, and classic end record into a buffer.
pub fn end_records(count: u64, offset: u64, size: u64) -> Result<Vec<u8>, Error> {
    Ok(EndRecords::new(count, offset, size)?.0.into())
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
