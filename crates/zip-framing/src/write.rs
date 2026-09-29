//! Canonical UTF-8, single-volume ZIP64 record serialization.
//!
//! Completed members serialize matching local and central headers without data
//! descriptors. Writers can reserve local header space before streaming data.

use crate::{
    CompressionMethod, Error, add, invalid,
    record::{CENTRAL, END, LOCAL, LOCATOR, ZIP64_END, parse_name},
};

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

/// Validated metadata for one streaming ZIP64 member.
pub struct MemberHeader<'a> {
    path: &'a str,
    method: CompressionMethod,
    kind: EntryKind,
}

impl<'a> MemberHeader<'a> {
    /// Checks the path and method before any output is written.
    pub fn new(path: &'a str, method: CompressionMethod, kind: EntryKind) -> Result<Self, Error> {
        if path.is_empty() || path.len() > usize::from(u16::MAX) {
            return Err(invalid(0, "empty or oversized filename"));
        }

        parse_name(path.as_bytes(), 0x0800, 0)?;
        if path.ends_with('/') != matches!(kind, EntryKind::Directory) {
            return Err(invalid(0, "filename suffix disagrees with member kind"));
        }

        if matches!(kind, EntryKind::Directory) && method != CompressionMethod::Stored {
            return Err(invalid(0, "directories must be stored without file data"));
        }

        Ok(Self { path, method, kind })
    }

    /// Returns total local and central metadata bytes.
    pub fn metadata_size(&self) -> u64 {
        (30 + 20 + 46 + 28 + 2 * self.path.len()) as u64
    }

    /// Returns the payload compression method.
    pub fn method(&self) -> CompressionMethod {
        self.method
    }

    /// Returns the space to reserve for the completed local header.
    pub fn local_header_size(&self) -> usize {
        50 + self.path.len()
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

    fn common(&self, bytes: &mut Vec<u8>, crc: u32) {
        push16(bytes, 45);
        push16(bytes, 0x0800); // UTF-8.
        push16(bytes, self.method.number());
        push16(bytes, 0); // 00:00:00, 1980-01-01.
        push16(bytes, 0x0021);
        push32(bytes, crc);
        push32(bytes, u32::MAX);
        push32(bytes, u32::MAX);
    }
}

/// Final member metadata with a consistent method, CRC, and size tuple.
pub struct CompletedMember<'a> {
    header: MemberHeader<'a>,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    offset: u64,
}

impl CompletedMember<'_> {
    /// Serializes the local header with the final CRC and sizes.
    pub fn local_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.local_header_size());
        push32(&mut bytes, LOCAL);
        self.header.common(&mut bytes, self.crc);
        push16(&mut bytes, self.header.path.len() as u16);
        push16(&mut bytes, 20);

        bytes.extend_from_slice(self.header.path.as_bytes());

        push16(&mut bytes, 1);
        push16(&mut bytes, 16);
        push64(&mut bytes, self.uncompressed);
        push64(&mut bytes, self.compressed);

        bytes
    }

    /// Serializes the matching central-directory header.
    pub fn central_header(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(74 + self.header.path.len());
        push32(&mut bytes, CENTRAL);
        push16(&mut bytes, 0x032d); // Unix, ZIP 4.5.
        self.header.common(&mut bytes, self.crc);
        push16(&mut bytes, self.header.path.len() as u16);
        push16(&mut bytes, 28);
        push16(&mut bytes, 0); // Comment length.
        push16(&mut bytes, 0); // Starting disk.
        push16(&mut bytes, 0); // Internal attributes.

        let mode = match self.header.kind {
            EntryKind::File { executable: true } => 0o100755,
            EntryKind::File { executable: false } => 0o100644,
            EntryKind::Directory => 0o040755,
            EntryKind::SymbolicLink => 0o120777,
        };
        let dos = if matches!(self.header.kind, EntryKind::Directory) {
            0x10
        } else {
            0
        };
        push32(&mut bytes, (mode << 16) | dos);
        push32(&mut bytes, u32::MAX);

        bytes.extend_from_slice(self.header.path.as_bytes());

        push16(&mut bytes, 1);
        push16(&mut bytes, 24);
        push64(&mut bytes, self.uncompressed);
        push64(&mut bytes, self.compressed);
        push64(&mut bytes, self.offset);

        bytes
    }
}

/// Serializes the ZIP64 end record, locator, and classic end record.
pub fn end_records(count: u64, offset: u64, size: u64) -> Result<Vec<u8>, Error> {
    let position = add(offset, size)?;
    let mut bytes = Vec::with_capacity(98);
    push32(&mut bytes, ZIP64_END);
    push64(&mut bytes, 44);
    push16(&mut bytes, 0x032d);
    push16(&mut bytes, 45);
    push32(&mut bytes, 0);
    push32(&mut bytes, 0);
    push64(&mut bytes, count);
    push64(&mut bytes, count);
    push64(&mut bytes, size);
    push64(&mut bytes, offset);

    push32(&mut bytes, LOCATOR);
    push32(&mut bytes, 0);
    push64(&mut bytes, position);
    push32(&mut bytes, 1);

    push32(&mut bytes, END);
    push16(&mut bytes, 0);
    push16(&mut bytes, 0);
    push16(&mut bytes, u16::MAX);
    push16(&mut bytes, u16::MAX);
    push32(&mut bytes, u32::MAX);
    push32(&mut bytes, u32::MAX);
    push16(&mut bytes, 0);

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
