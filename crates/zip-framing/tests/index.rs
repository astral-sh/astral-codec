mod support;

use std::{error::Error, io::Cursor};

use flate2::Crc;
use tokio::io::{AsyncRead, AsyncSeek};
use zip_framing::{Error as FrameError, Index, Limits};

use support::{Fixture, Observed, Sparse, field, set16, set32};

type TestResult = Result<(), Box<dyn Error>>;

// Format-validation cases exercise the complete metadata check. Lazy access
// and its I/O behavior are covered separately below.
async fn read_validated<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
    limits: Limits,
) -> Result<Index, FrameError> {
    let mut index = Index::read(reader, limits).await?;
    index.validate_all(reader).await?;
    Ok(index)
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

            let index = read_validated(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
            assert_eq!(index.entries().len(), 1);

            let entry = index.entries()[0].resolved().ok_or("unresolved entry")?;
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
            read_validated(&mut Cursor::new(archive.bytes), Limits::default())
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
            read_validated(&mut Cursor::new(archive.bytes), Limits::default())
                .await
                .is_err(),
            "flags {flags:#x}"
        );
    }
}

#[tokio::test]
async fn rejects_unsupported_extras_in_either_header() {
    for (identifier, expected) in [
        (0x0007, "authenticity verification"),
        (0x0008, "alternate name encoding"),
        (0x000f, "patch descriptor"),
        (0x0014, "digital signature"),
        (0x0015, "digital signature"),
        (0x0016, "digital signature"),
        (0x0017, "encryption extra field"),
        (0x0019, "encryption extra field"),
        (0x9901, "encryption extra field"),
    ] {
        for local in [false, true] {
            let mut fixture = Fixture::default();
            if local {
                fixture.local_extra = field(identifier, &[]);
            } else {
                fixture.central_extra = field(identifier, &[]);
            }

            let archive = fixture.build();
            let offset = if local { 0 } else { archive.central as u64 };
            let result = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;

            assert!(
                matches!(result, Err(FrameError::Unsupported { position, feature })
                    if position == offset && feature == expected),
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
        read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
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
        "\u{feff}name".as_bytes().to_vec(),
    ] {
        assert!(
            read_validated(
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
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
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
            read_validated(&mut Cursor::new(&bytes), limits).await,
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
                read_validated(
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
                read_validated(&mut Cursor::new(bytes), Limits::default())
                    .await
                    .is_err(),
                "offset {offset}, zip64={zip64}"
            );
        }

        let mut bytes = archive.bytes;
        bytes.push(0);

        assert!(
            read_validated(&mut Cursor::new(bytes), Limits::default())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn requires_utf8_archive_and_member_comments() {
    for (comment, valid) in [
        (b"zip".as_slice(), true),
        ("café".as_bytes(), true),
        (b"\xff".as_slice(), false),
        (b"\xe2\x82".as_slice(), false),
    ] {
        for zip64 in [false, true] {
            for (member, flags) in [(false, 0x0800), (true, 0x0800), (true, 0)] {
                let mut fixture = Fixture {
                    zip64,
                    ..Fixture::default()
                };
                if member {
                    fixture.member_comment = comment.to_vec();
                } else {
                    fixture.archive_comment = comment.to_vec();
                }

                let mut archive = fixture.build();
                set16(&mut archive.bytes, 6, flags);
                set16(&mut archive.bytes, archive.central + 8, flags);

                let (offset, expected) = if member {
                    (archive.central as u64, "non-UTF-8 member comment")
                } else {
                    (archive.end as u64, "non-UTF-8 archive comment")
                };
                let result =
                    read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;

                if valid {
                    assert!(
                        result.is_ok(),
                        "{comment:?}, member={member}, flags={flags:#x}, zip64={zip64}: {result:?}"
                    );
                } else {
                    assert!(
                        matches!(result, Err(FrameError::Invalid { position, reason })
                            if position == offset && reason == expected),
                        "{comment:?}, member={member}, flags={flags:#x}, zip64={zip64}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn accepts_empty_archives_but_rejects_ambiguous_end_records() -> TestResult {
    let mut empty = vec![0; 22];
    set32(&mut empty, 0, 0x0605_4b50);

    assert!(
        read_validated(&mut Cursor::new(&empty), Limits::default())
            .await?
            .entries()
            .is_empty()
    );

    let mut archive = Fixture::default().build();
    set16(&mut archive.bytes, archive.end + 20, 22);
    archive.bytes.extend(empty);

    assert!(
        read_validated(&mut Cursor::new(archive.bytes), Limits::default())
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

        let index =
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await?;

        assert_eq!(
            index.entries()[0]
                .resolved()
                .ok_or("unresolved entry")?
                .unix_extra_data(),
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
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
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

        let result =
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await;

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

    let index = read_validated(&mut Cursor::new(&bytes), Limits::default()).await?;

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
        index.entries()[0]
            .resolved()
            .ok_or("unresolved entry")?
            .unix_extra_data(),
        Some(b"target".as_slice())
    );
    assert_eq!(index.entries()[1].position(), 0);
    assert_eq!(
        index.entries()[1]
            .resolved()
            .ok_or("unresolved entry")?
            .unix_extra_data(),
        None
    );

    let mut shared = bytes.clone();
    set32(&mut shared, central + 42, 0);

    assert!(
        read_validated(&mut Cursor::new(shared), Limits::default())
            .await
            .is_err()
    );

    bytes.drain(central..central + second_header.len());
    let end = bytes.len() - 22;
    set16(&mut bytes, end + 8, 1);
    set16(&mut bytes, end + 10, 1);
    set32(&mut bytes, end + 12, (end - central) as u32);

    assert!(
        read_validated(&mut Cursor::new(bytes), Limits::default())
            .await
            .is_err()
    );

    Ok(())
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

    let index = read_validated(&mut source, Limits::default()).await?;
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
            read_validated(&mut Cursor::new(archive.bytes), Limits::default())
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
        read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
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

        let result = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;

        assert_eq!(result.is_ok(), valid);
    }

    Ok(())
}

#[tokio::test]
async fn buffers_directory_and_resolves_only_selected_records() -> TestResult {
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    let mut positions = Vec::new();
    for ordinal in 0..2000 {
        let fixture = Fixture {
            name: format!("file-{ordinal}").into_bytes(),
            ..Fixture::default()
        }
        .build();
        positions.push(bytes.len() as u64);
        let mut central = fixture.bytes[fixture.central..fixture.end].to_vec();
        set32(&mut central, 42, bytes.len() as u32);
        directory.extend(central);
        bytes.extend_from_slice(&fixture.bytes[..fixture.central]);
    }

    // Keep the tail search outside both the directory and local records.
    let central = bytes.len();
    bytes.extend_from_slice(&directory);
    let end = bytes.len();
    let footer = Fixture {
        archive_comment: vec![b'a'; usize::from(u16::MAX)],
        ..Fixture::default()
    }
    .build();
    bytes.extend_from_slice(&footer.bytes[footer.end..]);
    set16(&mut bytes, end + 8, 2000);
    set16(&mut bytes, end + 10, 2000);
    set32(&mut bytes, end + 12, directory.len() as u32);
    set32(&mut bytes, end + 16, central as u32);
    bytes[30] = b'x';

    let mut source = Observed::new(bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(index.entries().len(), 2000);
    assert!(
        index
            .entries()
            .iter()
            .all(|entry| entry.resolved().is_none())
    );
    assert!(
        source
            .reads
            .iter()
            .all(|range| range.start >= central as u64)
    );
    // Tail, locator probe, and a few bounded directory windows, not 4000 reads.
    assert!(source.reads.len() <= 5, "{:?}", source.reads);

    source.reads.clear();
    let entry = index.entry(&mut source, 7).await?.ok_or("missing member")?;
    assert_eq!(entry.path(), "file-7");
    assert_eq!(source.reads.len(), 1);
    assert_eq!(source.reads[0], positions[7]..positions[8]);
    assert_eq!(entry.record_range(), positions[7]..positions[8]);

    source.reads.clear();
    assert!(index.entry(&mut source, 7).await?.is_some());
    assert!(index.entry(&mut source, 2000).await?.is_none());
    assert!(source.reads.is_empty());
    assert!(index.entries()[0].resolved().is_none());
    assert!(index.validate_all(&mut source).await.is_err());
    assert!(index.entries()[0].resolved().is_none());

    Ok(())
}

#[tokio::test]
async fn charges_local_metadata_once_after_successful_resolution() -> TestResult {
    let extra = field(0xbeef, &vec![0; 5000]);
    let archive = Fixture {
        local_extra: extra.clone(),
        central_extra: extra,
        ..Fixture::default()
    }
    .build();
    let exact_budget = (archive.end - archive.central + archive.central - 7) as u64;

    for (budget, valid) in [(exact_budget - 1, false), (exact_budget, true)] {
        let mut source = Observed::new(archive.bytes.clone());
        let mut index = Index::read(
            &mut source,
            Limits {
                metadata_size: budget,
                ..Limits::default()
            },
        )
        .await?;
        if !valid {
            assert!(matches!(
                index.entry(&mut source, 0).await,
                Err(FrameError::Limit { .. })
            ));
            continue;
        }

        // The variable fields require a second read after checking the budget.
        // An I/O failure there must not leave a charge or a checked entry behind.
        source.fail_at = Some(30);
        assert!(matches!(
            index.entry(&mut source, 0).await,
            Err(FrameError::Io(_))
        ));
        assert!(index.entries()[0].resolved().is_none());
        assert!(index.entry(&mut source, 0).await?.is_some());
        source.reads.clear();
        index.validate_all(&mut source).await?;
        assert!(source.reads.is_empty());
    }

    Ok(())
}
