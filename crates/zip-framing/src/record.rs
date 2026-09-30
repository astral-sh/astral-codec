use std::{io::SeekFrom, str};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::{CompressionMethod, Error, add, invalid};

pub(crate) const LOCAL: u32 = 0x0403_4b50;
pub(crate) const CENTRAL: u32 = 0x0201_4b50;
pub(crate) const DESCRIPTOR: u32 = 0x0807_4b50;
pub(crate) const END: u32 = 0x0605_4b50;
pub(crate) const ZIP64_END: u32 = 0x0606_4b50;
pub(crate) const LOCATOR: u32 = 0x0706_4b50;
pub(crate) const ARCHIVE_EXTRA: u32 = 0x0806_4b50;

/// A bounded read-ahead window that survives absolute seeks within the window.
/// Ordinary buffered readers discard their buffer on those seeks.
pub(crate) struct RecordReader<'a, R> {
    inner: &'a mut R,
    buffer: Vec<u8>,
    start: u64,
    capacity: usize,
}

impl<'a, R: AsyncRead + AsyncSeek + Unpin> RecordReader<'a, R> {
    pub(crate) fn new(inner: &'a mut R, capacity: usize) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            start: 0,
            capacity,
        }
    }

    pub(crate) async fn length(&mut self) -> Result<u64, Error> {
        Ok(self.inner.seek(SeekFrom::End(0)).await?)
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
        self.inner.read_exact(&mut self.buffer).await?;
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

pub(crate) fn parse_name(bytes: &[u8], flags: u16, position: u64) -> Result<&str, Error> {
    let name = str::from_utf8(bytes).map_err(|_| invalid(position, "non-UTF-8 filename"))?;
    if flags & 0x0800 == 0 && !name.is_ascii() {
        return Err(invalid(position, "non-ASCII filename without UTF-8 flag"));
    }

    if name.starts_with('\u{feff}')
        || name.contains(['\0', '\\'])
        || name.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        return Err(invalid(position, "invalid ZIP filename"));
    }

    Ok(name)
}

/// Common fixed-length components of both local file and central directory entries.
///
/// TODO(ww): Do more type-state modeling here, e.g. [`Common::compressed`] should probably
/// be an enum with `{ Size(size), SeeZip64, SeeDescriptor }` and [`Common::flags`] should probably be
/// some kind of bitflags enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Common {
    /// The minimum ZIP specification version needed to extract this member.
    pub(crate) version: u16,
    /// The member's general-purpose bit flags.
    pub(crate) flags: u16,
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
    /// `0xFFFFFFFF` indicates that the corresponding ZIP64 extra field should be consulted instead.
    /// Note that this field or its ZIP64 equivalent can be `0` in the local file entry if
    /// [`Common::flags`] indicates that a data descriptor conveys the compressed size instead.
    pub(crate) compressed: u32,
    /// The member's true (i.e. uncompressed) size.
    ///
    /// `0xFFFFFFFF` indicates that the corresponding ZIP64 extra field should be consulted instead.
    /// Note that this field or its ZIP64 equivalent can be `0` in the local file entry if
    /// [`Common::flags`] indicates that a data descriptor conveys the uncompressed size instead.
    pub(crate) uncompressed: u32,
}

impl Common {
    /// Parse a local file or central directory [`Common`] from the given bytes.
    pub(crate) fn parse(bytes: &[u8; 22], position: u64) -> Result<Self, Error> {
        let flags = u16::from_le_bytes(array_at::<2, 2, _>(bytes));
        if flags & 0x2041 != 0 {
            return Err(Error::Unsupported {
                position,
                feature: "encryption",
            });
        }

        if flags & 0x20 != 0 {
            return Err(Error::Unsupported {
                position,
                feature: "patched data",
            });
        }

        let method =
            CompressionMethod::parse(u16::from_le_bytes(array_at::<4, 2, _>(bytes)), position)?;
        let allowed = 0x0808
            | if method == CompressionMethod::Deflate {
                6
            } else {
                0
            };
        if flags & !allowed != 0 {
            return Err(invalid(
                position,
                "reserved or inapplicable general-purpose flags",
            ));
        }

        let version = u16::from_le_bytes(array_at::<0, 2, _>(bytes));
        if version > 45 {
            return Err(Error::Unsupported {
                position,
                feature: "extraction version",
            });
        }

        if version
            < if method == CompressionMethod::Deflate {
                20
            } else {
                10
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
            compressed: u32::from_le_bytes(array_at::<14, 4, _>(bytes)),
            uncompressed: u32::from_le_bytes(array_at::<18, 4, _>(bytes)),
        })
    }

    pub(crate) fn descriptor(self) -> bool {
        self.flags & 8 != 0
    }

    pub(crate) fn check_zip64(self, zip64: bool, position: u64) -> Result<(), Error> {
        if zip64 && self.version < 45 {
            return Err(invalid(position, "ZIP64 requires extraction version 4.5"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Common, array_at, bytes_at};
    use crate::{CompressionMethod, Error};

    #[test]
    fn parses_common_header_fields() -> Result<(), Error> {
        let bytes = [
            20, 0, 0x0a, 0x08, 8, 0, 0x34, 0x12, 0x78, 0x56, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        assert_eq!(
            Common::parse(&bytes, 42)?,
            Common {
                version: 20,
                flags: 0x080a,
                method: CompressionMethod::Deflate,
                time: 0x1234,
                date: 0x5678,
                crc: 0x4433_2211,
                compressed: 0x8877_6655,
                uncompressed: 0xccbb_aa99,
            }
        );

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
