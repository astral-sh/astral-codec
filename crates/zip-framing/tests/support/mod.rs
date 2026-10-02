use std::{
    io::{self, Cursor, SeekFrom},
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use flate2::Crc;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

#[derive(Default)]
pub(super) struct Fixture {
    pub(super) name: Vec<u8>,
    pub(super) payload: Option<Vec<u8>>,
    pub(super) local_extra: Vec<u8>,
    pub(super) central_extra: Vec<u8>,
    pub(super) member_comment: Vec<u8>,
    pub(super) archive_comment: Vec<u8>,
    pub(super) archive_extra: Option<Vec<u8>>,
    pub(super) zip64: bool,
    pub(super) zip64_extensions: Vec<u8>,
    pub(super) zip64_version: Option<u16>,
    pub(super) descriptor: Option<bool>,
    pub(super) crc: Option<u32>,
    pub(super) flags: Option<u16>,
    pub(super) made_by: Option<u16>,
    pub(super) external_attributes: u32,
    pub(super) local_offset: u32,
}

pub(super) struct Archive {
    pub(super) bytes: Vec<u8>,
    pub(super) central: usize,
    pub(super) descriptor: usize,
    pub(super) zip64_end: Option<usize>,
    pub(super) end: usize,
}

pub(super) fn field(identifier: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = identifier.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend_from_slice(data);

    bytes
}

pub(super) fn set16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn end_record(count: u16, offset: u32, size: u32, comment: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 22];
    set32(&mut bytes, 0, 0x0605_4b50);
    set16(&mut bytes, 8, count);
    set16(&mut bytes, 10, count);
    set32(&mut bytes, 12, size);
    set32(&mut bytes, 16, offset);
    set16(&mut bytes, 20, comment.len() as u16);
    bytes.extend_from_slice(comment);

    bytes
}

impl Fixture {
    pub(super) fn build(self) -> Archive {
        let name = if self.name.is_empty() {
            b"file".to_vec()
        } else {
            self.name
        };

        let payload = self.payload.unwrap_or_else(|| b"payload".to_vec());
        let mut crc = Crc::new();
        crc.update(&payload);
        let checksum = self.crc.unwrap_or_else(|| crc.sum());

        let version = if self.zip64 { 45 } else { 20 };
        let flags = self
            .flags
            .unwrap_or(0x0800 | if self.descriptor.is_some() { 8 } else { 0 });
        let local_size = if self.descriptor.is_some() {
            0
        } else {
            payload.len() as u64
        };

        let mut local_extra = self.local_extra;
        let mut central_extra = self.central_extra;
        if self.zip64 {
            local_extra.extend(field(
                1,
                &[local_size.to_le_bytes(), local_size.to_le_bytes()].concat(),
            ));
            central_extra.extend(field(1, &(payload.len() as u64).to_le_bytes().repeat(2)));
        }

        let mut bytes = vec![0; 30];
        set32(&mut bytes, 0, 0x0403_4b50);
        set16(&mut bytes, 4, version);
        set16(&mut bytes, 6, flags);
        set32(
            &mut bytes,
            14,
            if self.descriptor.is_some() {
                0
            } else {
                checksum
            },
        );

        let size = if self.zip64 {
            u32::MAX
        } else {
            local_size as u32
        };
        set32(&mut bytes, 18, size);
        set32(&mut bytes, 22, size);
        set16(&mut bytes, 26, name.len() as u16);
        set16(&mut bytes, 28, local_extra.len() as u16);

        bytes.extend_from_slice(&name);
        bytes.extend(local_extra);
        bytes.extend_from_slice(&payload);

        let descriptor = bytes.len();
        if let Some(signed) = self.descriptor {
            if signed {
                bytes.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            }

            bytes.extend_from_slice(&checksum.to_le_bytes());
            if self.zip64 {
                bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes().repeat(2));
            } else {
                bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes().repeat(2));
            }
        }

        let central = bytes.len();
        if let Some(extra) = self.archive_extra {
            bytes.extend_from_slice(&0x0806_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&(extra.len() as u32).to_le_bytes());
            bytes.extend(extra);
        }
        let mut header = vec![0; 46];
        set32(&mut header, 0, 0x0201_4b50);
        set16(&mut header, 4, self.made_by.unwrap_or(0x032d));
        set16(&mut header, 6, version);
        set16(&mut header, 8, flags);
        set32(&mut header, 16, checksum);

        let size = if self.zip64 {
            u32::MAX
        } else {
            payload.len() as u32
        };
        set32(&mut header, 20, size);
        set32(&mut header, 24, size);
        set16(&mut header, 28, name.len() as u16);
        set16(&mut header, 30, central_extra.len() as u16);
        set16(&mut header, 32, self.member_comment.len() as u16);
        set32(&mut header, 38, self.external_attributes);
        set32(&mut header, 42, self.local_offset);

        bytes.extend(header);
        bytes.extend(name);
        bytes.extend(central_extra);
        bytes.extend(self.member_comment);

        let central_size = bytes.len() - central;
        let zip64_end = self.zip64.then_some(bytes.len());
        if let Some(position) = zip64_end {
            let mut record = vec![0; 56];
            set32(&mut record, 0, 0x0606_4b50);
            record[4..12].copy_from_slice(&(44 + self.zip64_extensions.len() as u64).to_le_bytes());
            set16(&mut record, 12, 45);
            set16(&mut record, 14, self.zip64_version.unwrap_or(45));
            record[24..32].copy_from_slice(&1u64.to_le_bytes());
            record[32..40].copy_from_slice(&1u64.to_le_bytes());
            record[40..48].copy_from_slice(&(central_size as u64).to_le_bytes());
            record[48..56].copy_from_slice(&(central as u64).to_le_bytes());
            bytes.extend(record);
            bytes.extend(self.zip64_extensions);
            bytes.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(position as u64).to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }

        let end = bytes.len();
        bytes.extend(end_record(
            if self.zip64 { u16::MAX } else { 1 },
            if self.zip64 { u32::MAX } else { central as u32 },
            if self.zip64 {
                u32::MAX
            } else {
                central_size as u32
            },
            &self.archive_comment,
        ));

        Archive {
            bytes,
            central,
            descriptor,
            zip64_end,
            end,
        }
    }
}

pub(super) struct Sparse {
    pub(super) prefix: Vec<u8>,
    pub(super) suffix: Vec<u8>,
    pub(super) suffix_offset: u64,
    pub(super) position: u64,
    pub(super) bytes_read: usize,
}

impl AsyncRead for Sparse {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        if self.position < self.prefix.len() as u64 {
            let start = self.position as usize;
            let length = buffer.remaining().min(self.prefix.len() - start);
            buffer.put_slice(&self.prefix[start..start + length]);
        } else if self.position < self.suffix_offset {
            let length =
                (buffer.remaining() as u64).min(self.suffix_offset - self.position) as usize;
            buffer.put_slice(&vec![0; length]);
        } else if self.position < self.suffix_offset + self.suffix.len() as u64 {
            let start = (self.position - self.suffix_offset) as usize;
            let length = buffer.remaining().min(self.suffix.len() - start);
            buffer.put_slice(&self.suffix[start..start + length]);
        }

        let read = buffer.filled().len() - before;
        self.position += read as u64;
        self.bytes_read += read;

        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for Sparse {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        self.position = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => {
                (self.suffix_offset + self.suffix.len() as u64).checked_add_signed(delta)
            }
        }
        .ok_or_else(|| io::Error::other("invalid seek"))?;

        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

/// Records source reads rather than parser calls, as a range backend would see them.
pub(super) struct Observed {
    pub(super) inner: Cursor<Vec<u8>>,
    pub(super) reads: Vec<Range<u64>>,
    pub(super) fail_at: Option<u64>,
    pub(super) max_read: usize,
}

impl Observed {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            reads: Vec::new(),
            fail_at: None,
            max_read: usize::MAX,
        }
    }
}

impl AsyncRead for Observed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = self.inner.position();
        if self.fail_at == Some(start) {
            self.fail_at = None;
            return Poll::Ready(Err(io::Error::other("injected read failure")));
        }

        let length = self.max_read.min(buffer.remaining());
        let mut limited = ReadBuf::new(&mut buffer.initialize_unfilled()[..length]);
        let result = Pin::new(&mut self.inner).poll_read(context, &mut limited);
        let length = limited.filled().len();
        buffer.advance(length);
        if length != 0 {
            self.reads.push(start..start + length as u64);
        }
        result
    }
}

impl AsyncSeek for Observed {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.inner).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.inner).poll_complete(context)
    }
}
