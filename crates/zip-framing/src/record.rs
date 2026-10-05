use std::{io::SeekFrom, str};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::{CompressionMethod, Error, add, constants::version, invalid};

/// A bounded read-ahead window that survives absolute seeks within the window.
/// Ordinary buffered readers discard their buffer on those seeks.
pub(crate) struct RecordReader<'a, R> {
    inner: &'a mut R,
    buffer: &'a mut Vec<u8>,
    start: u64,
    capacity: usize,
}

impl<'a, R: AsyncRead + AsyncSeek + Unpin> RecordReader<'a, R> {
    pub(crate) fn new(inner: &'a mut R, capacity: usize, buffer: &'a mut Vec<u8>) -> Self {
        // Reuse allocation, never bytes from a previous reader or operation.
        buffer.clear();
        Self {
            inner,
            buffer,
            start: 0,
            capacity,
        }
    }

    pub(crate) async fn length(&mut self) -> Result<u64, Error> {
        Ok(self.inner.seek(SeekFrom::End(0)).await?)
    }

    /// Checks the requested span before allocating and reading its bytes.
    pub(crate) async fn read_vec(
        &mut self,
        position: u64,
        length: usize,
        end: u64,
    ) -> Result<Vec<u8>, Error> {
        if add(position, length as u64)? > end {
            return Err(invalid(position, "record extends beyond its container"));
        }

        let mut bytes = vec![0; length];
        self.read_at(position, &mut bytes, end).await?;
        Ok(bytes)
    }

    /// Borrows a checked span, filling the read-ahead window when necessary.
    pub(crate) async fn read_slice(
        &mut self,
        position: u64,
        length: usize,
        end: u64,
    ) -> Result<&[u8], Error> {
        let requested_end = add(position, length as u64)?;
        if requested_end > end {
            return Err(invalid(position, "record extends beyond its container"));
        }

        if length == 0 {
            return Ok(&[]);
        }

        if position < self.start || requested_end > self.start + self.buffer.len() as u64 {
            self.inner.seek(SeekFrom::Start(position)).await?;
            let read_length = (end - position).min(self.capacity.max(length) as u64) as usize;
            self.buffer.resize(read_length, 0);
            self.inner.read_exact(self.buffer).await?;
            self.start = position;
        }

        let offset = (position - self.start) as usize;
        Ok(&self.buffer[offset..offset + length])
    }

    // Every read, including read-ahead, is bounded by its containing record span.
    pub(crate) async fn read_at(
        &mut self,
        position: u64,
        bytes: &mut [u8],
        end: u64,
    ) -> Result<(), Error> {
        let requested_end = add(position, bytes.len() as u64)?;
        if requested_end > end {
            return Err(invalid(position, "record extends beyond its container"));
        }

        if bytes.is_empty() {
            return Ok(());
        }

        if position >= self.start && requested_end <= self.start + self.buffer.len() as u64 {
            let offset = (position - self.start) as usize;
            bytes.copy_from_slice(&self.buffer[offset..offset + bytes.len()]);
            return Ok(());
        }

        self.inner.seek(SeekFrom::Start(position)).await?;
        if bytes.len() >= self.capacity {
            self.inner.read_exact(bytes).await?;
            return Ok(());
        }

        let length = (end - position).min(self.capacity as u64) as usize;
        self.buffer.resize(length, 0);
        self.inner.read_exact(self.buffer).await?;
        self.start = position;
        bytes.copy_from_slice(&self.buffer[..bytes.len()]);

        Ok(())
    }
}

/// Extracts a field from a fixed-size array, checking its bounds at compile time.
pub(crate) fn array_at<const OFFSET: usize, const WIDTH: usize, const LEN: usize>(
    bytes: &[u8; LEN],
) -> [u8; WIDTH] {
    const { assert!(OFFSET <= LEN && WIDTH <= LEN - OFFSET) };
    std::array::from_fn(|index| bytes[OFFSET + index])
}

/// Extracts a fixed-size field after checking its offset and length.
pub(crate) fn bytes_at<const N: usize>(
    bytes: &[u8],
    offset: usize,
    position: u64,
) -> Result<[u8; N], Error> {
    bytes
        .get(offset..)
        .and_then(<[u8]>::first_chunk)
        .copied()
        .ok_or_else(|| invalid(position, "truncated integer field"))
}

pub(crate) fn parse_name(
    bytes: &[u8],
    flags: GeneralPurposeFlags,
    position: u64,
) -> Result<&str, Error> {
    let name = str::from_utf8(bytes).map_err(|_| invalid(position, "non-UTF-8 filename"))?;
    if !flags.contains(GeneralPurposeFlags::UTF8) && !name.is_ascii() {
        return Err(invalid(position, "non-ASCII filename without UTF-8 flag"));
    }

    validate_name(name, position)?;
    Ok(name)
}

pub(crate) fn validate_name(name: &str, position: u64) -> Result<(), Error> {
    let bytes = name.as_bytes();
    if name.starts_with('\u{feff}')
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
        || name.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(invalid(position, "invalid ZIP filename"));
    }

    Ok(())
}

/// General-purpose header flags (APPNOTE 4.4.4).
///
/// [`Self::parse`] rejects unsupported flags and flags inapplicable to the
/// compression method.
/// DEFLATE option bits are preserved for local/central comparison and serialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GeneralPurposeFlags(u16);

impl GeneralPurposeFlags {
    /// Member encryption (bit 0).
    const ENCRYPTED: Self = Self(0x0001);
    /// Compression-level bits for DEFLATE members (bits 1 and 2).
    const DEFLATE_OPTIONS: Self = Self(0x0006);
    /// A descriptor follows the payload; local CRC and sizes are placeholders (bit 3).
    pub(crate) const DATA_DESCRIPTOR: Self = Self(0x0008);
    /// Compressed patched data (bit 5).
    const PATCHED_DATA: Self = Self(0x0020);
    /// Strong encryption (bit 6).
    const STRONG_ENCRYPTION: Self = Self(0x0040);
    /// Names and comments are UTF-8 encoded (bit 11).
    pub(crate) const UTF8: Self = Self(0x0800);
    /// Local header values are masked for central directory encryption (bit 13).
    const MASKED_HEADER: Self = Self(0x2000);

    /// Validates the flag bits for the member's compression method.
    pub(crate) fn parse(
        bits: u16,
        method: CompressionMethod,
        position: u64,
    ) -> Result<Self, Error> {
        let flags = Self(bits);
        if flags.contains(Self::ENCRYPTED)
            || flags.contains(Self::STRONG_ENCRYPTION)
            || flags.contains(Self::MASKED_HEADER)
        {
            return Err(Error::Unsupported {
                position,
                feature: "encryption",
            });
        }

        if flags.contains(Self::PATCHED_DATA) {
            return Err(Error::Unsupported {
                position,
                feature: "patched data",
            });
        }

        let allowed = Self::UTF8.0
            | Self::DATA_DESCRIPTOR.0
            | if method == CompressionMethod::Deflate {
                Self::DEFLATE_OPTIONS.0
            } else {
                0
            };
        if bits & !allowed != 0 {
            return Err(invalid(
                position,
                "reserved or inapplicable general-purpose flags",
            ));
        }

        Ok(flags)
    }

    fn bits(self) -> u16 {
        self.0
    }

    pub(crate) fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }
}

/// A 32-bit payload-size field (APPNOTE 4.4.8, 4.4.9, and 4.5.3).
///
/// With a data descriptor, zero sizes in a local header or its ZIP64 extra
/// field are placeholders. That interpretation belongs to local resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SizeField {
    /// A value smaller than `u32::MAX` stored directly in the header.
    Value(u32),
    /// The `0xFFFFFFFF` sentinel referring to the ZIP64 extra field.
    Zip64,
}

impl From<u32> for SizeField {
    fn from(value: u32) -> Self {
        match value {
            u32::MAX => Self::Zip64,
            _ => Self::Value(value),
        }
    }
}

impl From<SizeField> for u32 {
    fn from(value: SizeField) -> Self {
        match value {
            SizeField::Value(value) => value,
            SizeField::Zip64 => u32::MAX,
        }
    }
}

/// Common fixed-length components of both local file and central directory entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Common {
    /// The minimum ZIP specification version needed to extract this member.
    pub(crate) version: u16,
    /// The member's general-purpose bit flags.
    pub(crate) flags: GeneralPurposeFlags,
    /// The member's compression method.
    pub(crate) method: CompressionMethod,
    /// The member's last-modified time, in MS-DOS format.
    /// See: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime>
    pub(crate) time: u16,
    /// The member's last-modified date, in MS-DOS format.
    /// See: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime>
    pub(crate) date: u16,
    /// The CRC-32 of the member's uncompressed data.
    ///
    /// This will be `0` for a local file entry whose [`Common::flags`] indicate that a data descriptor
    /// conveys the CRC-32 instead.
    pub(crate) crc: u32,
    /// The member's size in the ZIP modulo any headers and (optional) data descriptor.
    ///
    /// [`SizeField::Zip64`] refers to the corresponding ZIP64 extra field.
    /// A local descriptor placeholder is resolved when checking the local record.
    pub(crate) compressed: SizeField,
    /// The member's true (i.e. uncompressed) size.
    ///
    /// [`SizeField::Zip64`] refers to the corresponding ZIP64 extra field.
    /// A local descriptor placeholder is resolved when checking the local record.
    pub(crate) uncompressed: SizeField,
}

impl Common {
    /// Size of the serialized common fields in bytes.
    pub(crate) const SIZE: usize = 22;

    /// Parse a local file or central directory [`Common`] from the given bytes.
    pub(crate) fn parse(bytes: &[u8; Self::SIZE], position: u64) -> Result<Self, Error> {
        let method =
            CompressionMethod::parse(u16::from_le_bytes(array_at::<4, 2, _>(bytes)), position)?;
        let flags = GeneralPurposeFlags::parse(
            u16::from_le_bytes(array_at::<2, 2, _>(bytes)),
            method,
            position,
        )?;

        let version = u16::from_le_bytes(array_at::<0, 2, _>(bytes));
        if version > version::ZIP64 {
            return Err(Error::Unsupported {
                position,
                feature: "extraction version",
            });
        }

        if version
            < if method == CompressionMethod::Deflate {
                version::V2_0
            } else {
                version::BASE
            }
        {
            return Err(invalid(position, "extraction version is too low"));
        }

        Ok(Self {
            version,
            flags,
            method,
            time: u16::from_le_bytes(array_at::<6, 2, _>(bytes)),
            date: u16::from_le_bytes(array_at::<8, 2, _>(bytes)),
            crc: u32::from_le_bytes(array_at::<10, 4, _>(bytes)),
            compressed: SizeField::from(u32::from_le_bytes(array_at::<14, 4, _>(bytes))),
            uncompressed: SizeField::from(u32::from_le_bytes(array_at::<18, 4, _>(bytes))),
        })
    }

    /// Serializes the common header fields in little-endian order.
    pub(crate) fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.version.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.flags.bits().to_le_bytes());
        bytes[4..6].copy_from_slice(&(self.method as u16).to_le_bytes());
        bytes[6..8].copy_from_slice(&self.time.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.date.to_le_bytes());
        bytes[10..14].copy_from_slice(&self.crc.to_le_bytes());
        bytes[14..18].copy_from_slice(&u32::from(self.compressed).to_le_bytes());
        bytes[18..22].copy_from_slice(&u32::from(self.uncompressed).to_le_bytes());
        bytes
    }

    pub(crate) fn check_zip64(self, zip64: bool, position: u64) -> Result<(), Error> {
        if zip64 && self.version < version::ZIP64 {
            return Err(invalid(position, "ZIP64 requires extraction version 4.5"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Common, GeneralPurposeFlags, RecordReader, SizeField, array_at, bytes_at};
    use crate::{CompressionMethod, Error};

    #[tokio::test]
    async fn bounds_reads_before_allocation() -> Result<(), Error> {
        let mut source = Cursor::new([1, 2, 3, 4]);
        let mut buffer = Vec::new();
        let mut reader = RecordReader::new(&mut source, 4, &mut buffer);

        // An allocation of this size would fail before any I/O could occur.
        assert!(matches!(
            reader.read_vec(0, usize::MAX, 4).await,
            Err(Error::Invalid {
                position: 0,
                reason: "record extends beyond its container",
            })
        ));
        assert_eq!(reader.read_vec(1, 2, 4).await?, [2, 3]);

        assert!(matches!(
            reader.read_slice(0, usize::MAX, 4).await,
            Err(Error::Invalid {
                position: 0,
                reason: "record extends beyond its container",
            })
        ));
        assert_eq!(reader.read_slice(1, 2, 4).await?, [2, 3]);

        Ok(())
    }

    #[test]
    fn parses_and_serializes_common_header_fields() -> Result<(), Error> {
        let bytes = [
            20, 0, 0x0a, 0x08, 8, 0, 0x34, 0x12, 0x78, 0x56, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let common = Common {
            version: 20,
            flags: GeneralPurposeFlags::parse(0x080a, CompressionMethod::Deflate, 42)?,
            method: CompressionMethod::Deflate,
            time: 0x1234,
            date: 0x5678,
            crc: 0x4433_2211,
            compressed: SizeField::Value(0x8877_6655),
            uncompressed: SizeField::Value(0xccbb_aa99),
        };
        assert_eq!(Common::parse(&bytes, 42)?, common);
        assert_eq!(common.to_bytes(), bytes);

        Ok(())
    }

    #[test]
    fn extracts_fields_from_fixed_arrays() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(array_at::<0, 8, _>(&bytes), bytes);
        assert_eq!(array_at::<1, 2, _>(&bytes), [2, 3]);
        assert_eq!(array_at::<4, 4, _>(&bytes), [5, 6, 7, 8]);
        assert_eq!(array_at::<8, 0, _>(&bytes), []);
    }

    #[test]
    fn reads_fixed_width_fields_and_rejects_out_of_bounds_offsets() -> Result<(), Error> {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(u16::from_le_bytes(bytes_at(&bytes, 1, 42)?), 0x0302);
        assert_eq!(u32::from_le_bytes(bytes_at(&bytes, 2, 42)?), 0x0605_0403);
        assert_eq!(
            u64::from_le_bytes(bytes_at(&bytes, 0, 42)?),
            0x0807_0605_0403_0201
        );

        for offset in [7, 8, usize::MAX] {
            assert!(matches!(
                bytes_at::<2>(&bytes, offset, 42),
                Err(Error::Invalid {
                    position: 42,
                    reason: "truncated integer field"
                })
            ));
        }
        assert!(bytes_at::<8>(&bytes, 1, 42).is_err());

        Ok(())
    }
}
