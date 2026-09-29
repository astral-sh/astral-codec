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
}

// Every read, including read-ahead, is bounded by its containing record span.
pub(crate) async fn read_at<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut RecordReader<'_, R>,
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

    if position >= reader.start && requested_end <= reader.start + reader.buffer.len() as u64 {
        let offset = (position - reader.start) as usize;
        bytes.copy_from_slice(&reader.buffer[offset..offset + bytes.len()]);
        return Ok(());
    }

    reader.inner.seek(SeekFrom::Start(position)).await?;
    if bytes.len() >= reader.capacity {
        reader.inner.read_exact(bytes).await?;
        return Ok(());
    }

    let length = (end - position).min(reader.capacity as u64) as usize;
    reader.buffer.resize(length, 0);
    reader.inner.read_exact(&mut reader.buffer).await?;
    reader.start = position;
    bytes.copy_from_slice(&reader.buffer[..bytes.len()]);

    Ok(())
}

pub(crate) fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from(u16_at(bytes, offset)) | (u32::from(u16_at(bytes, offset + 2)) << 16)
}

pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from(u32_at(bytes, offset)) | (u64::from(u32_at(bytes, offset + 4)) << 32)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Common {
    pub(crate) version: u16,
    pub(crate) flags: u16,
    pub(crate) method: CompressionMethod,
    pub(crate) time: u16,
    pub(crate) date: u16,
    pub(crate) crc: u32,
    pub(crate) compressed: u32,
    pub(crate) uncompressed: u32,
}

impl Common {
    // Call only on the fixed, length-checked header starting at version-needed.
    pub(crate) fn parse(bytes: &[u8], position: u64) -> Result<Self, Error> {
        let flags = u16_at(bytes, 2);
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

        let method = CompressionMethod::parse(u16_at(bytes, 4), position)?;
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

        let version = u16_at(bytes, 0);
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
            time: u16_at(bytes, 6),
            date: u16_at(bytes, 8),
            crc: u32_at(bytes, 10),
            compressed: u32_at(bytes, 14),
            uncompressed: u32_at(bytes, 18),
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
