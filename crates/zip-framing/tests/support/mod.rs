use std::{
    io::{self, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};

use flate2::Crc;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

#[derive(Default)]
pub(super) struct Fixture {
    pub(super) name: Vec<u8>,
    pub(super) local_extra: Vec<u8>,
    pub(super) central_extra: Vec<u8>,
    pub(super) zip64: bool,
    pub(super) descriptor: Option<bool>,
    pub(super) crc: Option<u32>,
}

pub(super) struct Archive {
    pub(super) bytes: Vec<u8>,
    pub(super) central: usize,
    pub(super) descriptor: usize,
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

impl Fixture {
    pub(super) fn build(self) -> Archive {
        let name = if self.name.is_empty() {
            b"file".to_vec()
        } else {
            self.name
        };

        let mut crc = Crc::new();
        crc.update(b"payload");
        let checksum = self.crc.unwrap_or_else(|| crc.sum());

        let version = if self.zip64 { 45 } else { 20 };
        let flags = 0x0800 | if self.descriptor.is_some() { 8 } else { 0 };
        let local_size = if self.descriptor.is_some() { 0u64 } else { 7 };

        let mut local_extra = self.local_extra;
        let mut central_extra = self.central_extra;
        if self.zip64 {
            local_extra.extend(field(
                1,
                &[local_size.to_le_bytes(), local_size.to_le_bytes()].concat(),
            ));
            central_extra.extend(field(1, &[7u64.to_le_bytes(), 7u64.to_le_bytes()].concat()));
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
        bytes.extend_from_slice(b"payload");

        let descriptor = bytes.len();
        if let Some(signed) = self.descriptor {
            if signed {
                bytes.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
            }

            bytes.extend_from_slice(&checksum.to_le_bytes());
            if self.zip64 {
                bytes.extend_from_slice(&7u64.to_le_bytes().repeat(2));
            } else {
                bytes.extend_from_slice(&7u32.to_le_bytes().repeat(2));
            }
        }

        let central = bytes.len();
        let mut header = vec![0; 46];
        set32(&mut header, 0, 0x0201_4b50);
        set16(&mut header, 4, 0x032d);
        set16(&mut header, 6, version);
        set16(&mut header, 8, flags);
        set32(&mut header, 16, checksum);

        let size = if self.zip64 { u32::MAX } else { 7 };
        set32(&mut header, 20, size);
        set32(&mut header, 24, size);
        set16(&mut header, 28, name.len() as u16);
        set16(&mut header, 30, central_extra.len() as u16);

        bytes.extend(header);
        bytes.extend(name);
        bytes.extend(central_extra);

        let central_size = bytes.len() - central;
        if self.zip64 {
            let position = bytes.len();
            let mut record = vec![0; 56];
            set32(&mut record, 0, 0x0606_4b50);
            record[4..12].copy_from_slice(&44u64.to_le_bytes());
            set16(&mut record, 12, 45);
            set16(&mut record, 14, 45);
            record[24..32].copy_from_slice(&1u64.to_le_bytes());
            record[32..40].copy_from_slice(&1u64.to_le_bytes());
            record[40..48].copy_from_slice(&(central_size as u64).to_le_bytes());
            record[48..56].copy_from_slice(&(central as u64).to_le_bytes());
            bytes.extend(record);
            bytes.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(position as u64).to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
        }

        let end = bytes.len();
        let mut record = vec![0; 22];
        set32(&mut record, 0, 0x0605_4b50);
        set16(&mut record, 8, if self.zip64 { u16::MAX } else { 1 });
        set16(&mut record, 10, if self.zip64 { u16::MAX } else { 1 });
        set32(
            &mut record,
            12,
            if self.zip64 {
                u32::MAX
            } else {
                central_size as u32
            },
        );
        set32(
            &mut record,
            16,
            if self.zip64 { u32::MAX } else { central as u32 },
        );
        bytes.extend(record);

        Archive {
            bytes,
            central,
            descriptor,
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
