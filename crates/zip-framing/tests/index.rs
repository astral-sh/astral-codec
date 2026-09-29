use std::{
    error::Error,
    io::{self, Cursor, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use flate2::Crc;
use zip_framing::{Error as FrameError, Index, Limits};

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Default)]
struct Fixture {
    name: Vec<u8>,
    local_extra: Vec<u8>,
    central_extra: Vec<u8>,
    zip64: bool,
    descriptor: Option<bool>,
    crc: Option<u32>,
}

struct Archive {
    bytes: Vec<u8>,
    central: usize,
    descriptor: usize,
    end: usize,
}

fn field(identifier: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = identifier.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(data.len() as u16).to_le_bytes());
    bytes.extend_from_slice(data);

    bytes
}

fn set16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

impl Fixture {
    fn build(self) -> Archive {
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

#[tokio::test]
async fn resolves_classic_zip64_and_all_descriptor_forms() -> TestResult {
    for zip64 in [false, true] {
        for descriptor in [None, Some(false), Some(true)] {
            // This CRC also tests the unsigned descriptor/signature ambiguity.
            let archive = Fixture {
                zip64,
                descriptor,
                crc: Some(0x0807_4b50),
                ..Fixture::default()
            }
            .build();

            let index = Index::read(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
            assert_eq!(index.entries().len(), 1);

            let entry = &index.entries()[0];
            assert_eq!(entry.path(), "file");
            assert_eq!(entry.size(), 7);
            assert_eq!(entry.compressed_size(), 7);
            assert_eq!(entry.crc32(), 0x0807_4b50);
            assert_eq!(
                &archive.bytes[entry.data_offset() as usize..archive.descriptor],
                b"payload"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn rejects_redundant_header_disagreements_and_unsupported_flags() {
    for (label, offset, value) in [
        ("version", 4, 10),
        ("flags", 7, 0),
        ("method", 8, 8),
        ("time", 10, 1),
        ("date", 12, 1),
        ("crc", 14, 1),
        ("compressed size", 18, 6),
        ("size", 22, 6),
        ("name", 30, b'x'),
    ] {
        let mut archive = Fixture::default().build();
        archive.bytes[offset] = value;

        assert!(
            Index::read(&mut Cursor::new(archive.bytes), Limits::default())
                .await
                .is_err(),
            "{label}"
        );
    }

    for flags in [
        1, 2, 4, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x1000, 0x2000, 0x4000, 0x8000,
    ] {
        let mut archive = Fixture::default().build();
        set16(&mut archive.bytes, 6, flags);
        set16(&mut archive.bytes, archive.central + 8, flags);

        assert!(
            Index::read(&mut Cursor::new(archive.bytes), Limits::default())
                .await
                .is_err(),
            "flags {flags:#x}"
        );
    }
}

#[tokio::test]
async fn rejects_security_extras_in_either_header() {
    for identifier in [0x000f, 0x0014, 0x0015, 0x0016, 0x0017, 0x0019, 0x9901] {
        for local in [false, true] {
            let mut fixture = Fixture::default();
            if local {
                fixture.local_extra = field(identifier, &[]);
            } else {
                fixture.central_extra = field(identifier, &[]);
            }

            let result =
                Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default()).await;

            assert!(
                matches!(result, Err(FrameError::Unsupported { .. })),
                "{identifier:#x}, local={local}"
            );
        }
    }
}

#[tokio::test]
async fn validates_utf8_and_unicode_path_extras() -> TestResult {
    let name = "café".as_bytes();
    let mut crc = Crc::new();
    crc.update(name);
    let unicode = [vec![1], crc.sum().to_le_bytes().to_vec(), name.to_vec()].concat();
    let fixture = Fixture {
        name: name.to_vec(),
        local_extra: field(0x7075, &unicode),
        central_extra: field(0x7075, &unicode),
        ..Fixture::default()
    };

    assert_eq!(
        Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default())
            .await?
            .entries()[0]
            .path(),
        "café"
    );

    for name in [
        vec![0xff],
        b"/absolute".to_vec(),
        b"C:/drive".to_vec(),
        b"back\\slash".to_vec(),
        b"nul\0name".to_vec(),
    ] {
        assert!(
            Index::read(
                &mut Cursor::new(
                    Fixture {
                        name,
                        ..Fixture::default()
                    }
                    .build()
                    .bytes
                ),
                Limits::default()
            )
            .await
            .is_err()
        );
    }

    for change in [0, 1, 5] {
        let mut value = unicode.clone();
        value[change] ^= 1;
        let fixture = Fixture {
            name: name.to_vec(),
            central_extra: field(0x7075, &value),
            ..Fixture::default()
        };

        assert!(
            Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default())
                .await
                .is_err()
        );
    }

    Ok(())
}

#[tokio::test]
async fn enforces_resource_budgets_before_exposing_members() {
    let bytes = Fixture::default().build().bytes;
    for limits in [
        Limits {
            archive_size: 1,
            ..Limits::default()
        },
        Limits {
            entries: 0,
            ..Limits::default()
        },
        Limits {
            metadata_size: 1,
            ..Limits::default()
        },
        Limits {
            member_size: 6,
            ..Limits::default()
        },
        Limits {
            total_size: 6,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Index::read(&mut Cursor::new(&bytes), limits).await,
            Err(FrameError::Limit { .. })
        ));
    }
}

#[tokio::test]
async fn rejects_truncation_bad_offsets_descriptors_and_end_records() {
    for zip64 in [false, true] {
        let archive = Fixture {
            zip64,
            descriptor: Some(true),
            ..Fixture::default()
        }
        .build();

        for length in 0..archive.bytes.len() {
            assert!(
                Index::read(
                    &mut Cursor::new(&archive.bytes[..length]),
                    Limits::default()
                )
                .await
                .is_err(),
                "prefix {length}, zip64={zip64}"
            );
        }

        for offset in [
            archive.central + 42,
            archive.descriptor,
            archive.descriptor + 4,
            archive.descriptor + 8,
            archive.end + 4,
            archive.end + 8,
            archive.end + 12,
            archive.end + 16,
        ] {
            let mut bytes = archive.bytes.clone();
            bytes[offset] ^= 1;

            assert!(
                Index::read(&mut Cursor::new(bytes), Limits::default())
                    .await
                    .is_err(),
                "offset {offset}, zip64={zip64}"
            );
        }

        let mut bytes = archive.bytes;
        bytes.push(0);

        assert!(
            Index::read(&mut Cursor::new(bytes), Limits::default())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn accepts_empty_archives_and_comments_but_rejects_ambiguous_end_records() -> TestResult {
    let mut empty = vec![0; 22];
    set32(&mut empty, 0, 0x0605_4b50);

    assert!(
        Index::read(&mut Cursor::new(&empty), Limits::default())
            .await?
            .entries()
            .is_empty()
    );

    let mut archive = Fixture::default().build();
    set16(&mut archive.bytes, archive.end + 20, 3);
    archive.bytes.extend_from_slice(b"zip");

    Index::read(&mut Cursor::new(&archive.bytes), Limits::default()).await?;

    archive.bytes.truncate(archive.end + 22);
    set16(&mut archive.bytes, archive.end + 20, 22);
    archive.bytes.extend(empty);

    assert!(
        Index::read(&mut Cursor::new(archive.bytes), Limits::default())
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn resolves_unix_extension_data_and_checks_redundant_values() -> TestResult {
    let mut data = vec![0; 12];
    data.extend_from_slice(b"target");

    for (local_extra, central_extra) in [
        (field(0x000d, &data), field(0x000d, &data[..12])),
        (field(0x000d, &data), Vec::new()),
        (Vec::new(), field(0x000d, &data)),
    ] {
        let fixture = Fixture {
            local_extra,
            central_extra,
            ..Fixture::default()
        };

        let index = Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default()).await?;

        assert_eq!(
            index.entries()[0].unix_extra_data(),
            Some(b"target".as_slice())
        );
    }

    for data in [vec![0; 11], [vec![1; 12], b"different".to_vec()].concat()] {
        let fixture = Fixture {
            local_extra: field(0x000d, &data),
            central_extra: field(0x000d, &[0; 12]),
            ..Fixture::default()
        };

        assert!(
            Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default())
                .await
                .is_err()
        );
    }

    Ok(())
}

#[tokio::test]
async fn requires_complete_agreement_for_opaque_member_extras() {
    for (local, central, valid) in [
        (b"same".as_slice(), b"same".as_slice(), true),
        (b"local", b"other", false),
        (b"prefix-suffix", b"prefix", false),
    ] {
        let fixture = Fixture {
            local_extra: field(0xbeef, local),
            central_extra: field(0xbeef, central),
            ..Fixture::default()
        };

        let result = Index::read(&mut Cursor::new(fixture.build().bytes), Limits::default()).await;

        if valid {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(FrameError::Invalid {
                    reason: "local and central extra fields disagree",
                    ..
                })
            ));
        }
    }
}

#[tokio::test]
async fn respects_directory_order_but_rejects_shared_or_unindexed_local_members() -> TestResult {
    let first = Fixture::default().build();
    let unix_data = [vec![0; 12], b"target".to_vec()].concat();
    let second = Fixture {
        name: b"next".to_vec(),
        local_extra: field(0x000d, &unix_data),
        descriptor: Some(true),
        ..Fixture::default()
    }
    .build();

    let mut bytes = first.bytes[..first.central].to_vec();
    bytes.extend_from_slice(&second.bytes[..second.central]);

    let central = bytes.len();
    let mut second_header = second.bytes[second.central..second.end].to_vec();
    set32(&mut second_header, 42, first.central as u32);
    bytes.extend_from_slice(&second_header);
    bytes.extend_from_slice(&first.bytes[first.central..first.end]);

    let end = bytes.len();
    bytes.extend_from_slice(&first.bytes[first.end..]);
    set16(&mut bytes, end + 8, 2);
    set16(&mut bytes, end + 10, 2);
    set32(&mut bytes, end + 12, (end - central) as u32);
    set32(&mut bytes, end + 16, central as u32);

    let index = Index::read(&mut Cursor::new(&bytes), Limits::default()).await?;

    assert_eq!(
        index
            .entries()
            .iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        ["next", "file"]
    );
    assert_eq!(index.entries()[0].position(), first.central as u64);
    assert_eq!(
        index.entries()[0].unix_extra_data(),
        Some(b"target".as_slice())
    );
    assert_eq!(index.entries()[1].position(), 0);
    assert_eq!(index.entries()[1].unix_extra_data(), None);

    let mut shared = bytes.clone();
    set32(&mut shared, central + 42, 0);

    assert!(
        Index::read(&mut Cursor::new(shared), Limits::default())
            .await
            .is_err()
    );

    bytes.drain(central..central + second_header.len());
    let end = bytes.len() - 22;
    set16(&mut bytes, end + 8, 1);
    set16(&mut bytes, end + 10, 1);
    set32(&mut bytes, end + 12, (end - central) as u32);

    assert!(
        Index::read(&mut Cursor::new(bytes), Limits::default())
            .await
            .is_err()
    );

    Ok(())
}

struct Sparse {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    suffix_offset: u64,
    position: u64,
    bytes_read: usize,
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

#[tokio::test]
async fn indexes_zip64_sizes_above_four_gib_without_reading_the_payload() -> TestResult {
    let archive = Fixture {
        zip64: true,
        ..Fixture::default()
    }
    .build();

    let size = u64::from(u32::MAX) + 1;
    let data_offset = archive.central - 7;
    let mut prefix = archive.bytes[..data_offset].to_vec();
    for offset in [38, 46] {
        prefix[offset..offset + 8].copy_from_slice(&size.to_le_bytes());
    }

    let mut suffix = archive.bytes[archive.central..].to_vec();
    for offset in [54, 62] {
        suffix[offset..offset + 8].copy_from_slice(&size.to_le_bytes());
    }

    let central_size = 70;
    let suffix_offset = data_offset as u64 + size;
    suffix[central_size + 48..central_size + 56].copy_from_slice(&suffix_offset.to_le_bytes());
    suffix[central_size + 56 + 8..central_size + 56 + 16]
        .copy_from_slice(&(suffix_offset + central_size as u64).to_le_bytes());

    let mut source = Sparse {
        prefix,
        suffix,
        suffix_offset,
        position: 0,
        bytes_read: 0,
    };

    let index = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(index.entries()[0].size(), size);
    assert_eq!(index.entries()[0].compressed_size(), size);
    assert!(source.bytes_read < 70_000);

    Ok(())
}

#[tokio::test]
async fn rejects_malformed_extras_and_zip64_version_two() {
    for extra in [
        vec![0],
        vec![1, 0, 8, 0],
        field(1, &[]),
        [field(0xbeef, &[]), field(0xbeef, &[])].concat(),
    ] {
        let archive = Fixture {
            central_extra: extra,
            ..Fixture::default()
        }
        .build();

        assert!(
            Index::read(&mut Cursor::new(archive.bytes), Limits::default())
                .await
                .is_err()
        );
    }

    let mut archive = Fixture {
        zip64: true,
        ..Fixture::default()
    }
    .build();
    set16(&mut archive.bytes, archive.end - 76 + 14, 62);

    assert!(matches!(
        Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await,
        Err(FrameError::Unsupported {
            feature: "ZIP64 version-2 directory",
            ..
        })
    ));
}

#[tokio::test]
async fn bounds_and_checks_zip64_extensible_records() -> TestResult {
    for (extension, valid) in [
        ([0xef, 0xbe, 0, 0, 0, 0].repeat(2048), true),
        (vec![0xef], false),
        (vec![0xef, 0xbe, 1, 0, 0, 0], false),
        (vec![0x14, 0, 0, 0, 0, 0], false),
    ] {
        let mut archive = Fixture {
            zip64: true,
            ..Fixture::default()
        }
        .build();

        let end_offset = archive.end - 76;
        archive.bytes[end_offset + 4..end_offset + 12]
            .copy_from_slice(&(44 + extension.len() as u64).to_le_bytes());
        archive
            .bytes
            .splice(archive.end - 20..archive.end - 20, extension);

        let result = Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await;

        assert_eq!(result.is_ok(), valid);
    }

    Ok(())
}
