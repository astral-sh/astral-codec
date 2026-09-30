mod support;

use std::{error::Error, io::Cursor};

use flate2::Crc;
use tokio::io::{AsyncRead, AsyncSeek};
use zip_framing::{
    CompressionMethod, DirectoryEntry, Error as FrameError, Index, IndexedEntry, Limits,
    write::{EntryKind, MemberHeader, end_records},
};

use support::{Fixture, Observed, Sparse, end_record, field, set32};

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
            assert_eq!(entry.directory().path(), "file");
            assert_eq!(entry.directory().size(), 7);
            assert_eq!(entry.directory().compressed_size(), 7);
            assert_eq!(entry.directory().crc32(), 0x0807_4b50);
            assert_eq!(
                &archive.bytes[entry.data_offset() as usize..archive.descriptor],
                b"payload"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn reads_entry_header_fields_with_multibyte_lengths() -> TestResult {
    let extra = field(0xcafe, &[0x51; 257]);
    let archive = Fixture {
        name: vec![b'n'; 258],
        local_extra: extra.clone(),
        central_extra: extra,
        member_comment: vec![b'c'; 259],
        made_by: Some(0x1234),
        external_attributes: 0x1234_5678,
        ..Fixture::default()
    }
    .build();
    let mut reader = Cursor::new(archive.bytes);
    let index = read_validated(&mut reader, Limits::default()).await?;
    let entry = index.entries()[0].resolved().ok_or("unresolved entry")?;
    assert_eq!(entry.directory().path(), "n".repeat(258));
    assert_eq!(entry.directory().host_system(), 0x12);
    assert_eq!(entry.directory().external_attributes(), 0x1234_5678);
    assert_eq!(entry.data_offset(), 30 + 258 + 261);
    assert_eq!(entry.directory().size(), 7);

    Ok(())
}

#[tokio::test]
async fn reads_and_bounds_archive_extra_record() -> TestResult {
    let mut archive = Fixture {
        archive_extra: Some(field(0xcafe, &[0x51; 257])),
        ..Fixture::default()
    }
    .build();

    let index = read_validated(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
    assert_eq!(index.entries()[0].directory().path(), "file");

    set32(&mut archive.bytes, archive.central + 4, u32::MAX);
    assert!(matches!(
        Index::read(&mut Cursor::new(&archive.bytes), Limits::default()).await,
        Err(FrameError::Invalid {
            position,
            reason: "truncated archive extra record"
        }) if position == archive.central as u64
    ));

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
        let archive = Fixture {
            flags: Some(flags),
            ..Fixture::default()
        }
        .build();

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
            .directory()
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
    for (limits, expected_resource, expected_limit) in [
        (
            Limits {
                archive_size: 1,
                ..Limits::default()
            },
            "archive bytes",
            1,
        ),
        (
            Limits {
                entries: 0,
                ..Limits::default()
            },
            "entry count",
            0,
        ),
        (
            Limits {
                metadata_size: 1,
                ..Limits::default()
            },
            "metadata bytes",
            1,
        ),
        (
            Limits {
                member_size: 6,
                ..Limits::default()
            },
            "decoded member bytes",
            6,
        ),
        (
            Limits {
                total_size: 6,
                ..Limits::default()
            },
            "total decoded bytes",
            6,
        ),
    ] {
        assert!(matches!(
            read_validated(&mut Cursor::new(&bytes), limits).await,
            Err(FrameError::Limit { resource, limit })
                if resource == expected_resource && limit == expected_limit
        ));
    }
}

#[tokio::test]
async fn rejects_directory_limits_before_reading_entries() {
    for zip64 in [false, true] {
        let archive = Fixture {
            zip64,
            archive_comment: vec![b'a'; usize::from(u16::MAX)],
            ..Fixture::default()
        }
        .build();
        let directory_size = (archive.end - archive.central - if zip64 { 76 } else { 0 }) as u64;

        for (limits, expected_resource) in [
            (
                Limits {
                    entries: 0,
                    ..Limits::default()
                },
                "entry count",
            ),
            (
                Limits {
                    metadata_size: directory_size - 1,
                    ..Limits::default()
                },
                "metadata bytes",
            ),
        ] {
            let mut source = Observed::new(archive.bytes.clone());
            // Keep the end-record scan separate from the directory body, and
            // fail if parsing reaches that body before enforcing the limits.
            source.fail_at = Some(archive.central as u64);
            assert!(matches!(
                Index::read(&mut source, limits).await,
                Err(FrameError::Limit { resource, .. }) if resource == expected_resource
            ));
            assert_eq!(source.fail_at, Some(archive.central as u64));
        }
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
                    flags: Some(flags),
                    ..Fixture::default()
                };
                if member {
                    fixture.member_comment = comment.to_vec();
                } else {
                    fixture.archive_comment = comment.to_vec();
                }

                let archive = fixture.build();

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
    let empty = end_record(0, 0, 0, &[]);

    assert!(
        read_validated(&mut Cursor::new(&empty), Limits::default())
            .await?
            .entries()
            .is_empty()
    );

    let archive = Fixture {
        archive_comment: empty,
        ..Fixture::default()
    }
    .build();

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
async fn reconciles_shortened_info_zip_extras() -> TestResult {
    for (identifier, local, central) in [
        (0x5855, vec![1; 12], vec![1; 8]),
        (0x5455, vec![7; 13], vec![7; 5]),
        (0x7855, vec![1; 4], Vec::new()),
    ] {
        let fixture = Fixture {
            local_extra: field(identifier, &local),
            central_extra: field(identifier, &central),
            ..Fixture::default()
        };
        read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await?;

        let fixture = Fixture {
            local_extra: field(identifier, &local),
            central_extra: field(identifier, &[0]),
            ..Fixture::default()
        };
        assert!(
            matches!(
                read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await,
                Err(FrameError::Invalid {
                    reason: "local and central extra fields disagree",
                    ..
                })
            ),
            "extra {identifier:#x}"
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
        local_offset: first.central as u32,
        ..Fixture::default()
    }
    .build();

    let mut bytes = first.bytes[..first.central].to_vec();
    bytes.extend_from_slice(&second.bytes[..second.central]);

    let central = bytes.len();
    bytes.extend_from_slice(&second.bytes[second.central..second.end]);
    bytes.extend_from_slice(&first.bytes[first.central..first.end]);

    let end = bytes.len();
    bytes.extend(end_record(2, central as u32, (end - central) as u32, &[]));

    let mut source = Cursor::new(&bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;

    let entries: &[IndexedEntry] = index.entries();
    let directory: &DirectoryEntry = entries[0].directory();
    assert_eq!(directory.path(), "next");
    assert_eq!(
        entries[0].record_range(),
        first.central as u64..central as u64
    );
    assert_eq!(entries[1].record_range(), 0..first.central as u64);
    assert!(entries.iter().all(|entry| entry.resolved().is_none()));

    let entry = index.entry(&mut source, 0).await?.ok_or("missing entry")?;
    assert_eq!(entry.directory().path(), "next");
    assert_eq!(entry.record_range(), first.central as u64..central as u64);
    assert_eq!(entry.unix_extra_data(), Some(b"target".as_slice()));
    assert!(index.entries()[0].resolved().is_some());
    assert!(index.entries()[1].resolved().is_none());

    index.validate_all(&mut source).await?;

    assert_eq!(
        index
            .entries()
            .iter()
            .map(|entry| entry.directory().path())
            .collect::<Vec<_>>(),
        ["next", "file"]
    );
    assert_eq!(
        index.entries()[0].directory().position(),
        first.central as u64
    );
    assert_eq!(
        index.entries()[0]
            .resolved()
            .ok_or("unresolved entry")?
            .unix_extra_data(),
        Some(b"target".as_slice())
    );
    assert_eq!(index.entries()[1].directory().position(), 0);
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

    let mut unindexed = bytes[..central].to_vec();
    unindexed.extend_from_slice(&first.bytes[first.central..first.end]);
    unindexed.extend(end_record(
        1,
        central as u32,
        (first.end - first.central) as u32,
        &[],
    ));

    assert!(
        read_validated(&mut Cursor::new(unindexed), Limits::default())
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn indexes_zip64_sizes_above_four_gib_without_reading_the_payload() -> TestResult {
    let size = u64::from(u32::MAX) + 1;
    let member = MemberHeader::new(
        "file",
        CompressionMethod::Stored,
        EntryKind::File { executable: false },
    )?
    .finish(0, size, size, 0)?;
    let prefix = member.local_header();
    let mut suffix = member.central_header();
    let suffix_offset = prefix.len() as u64 + size;
    suffix.extend(end_records(1, suffix_offset, suffix.len() as u64)?);

    let mut source = Sparse {
        prefix,
        suffix,
        suffix_offset,
        position: 0,
        bytes_read: 0,
    };

    let index = read_validated(&mut source, Limits::default()).await?;
    assert_eq!(index.entries()[0].directory().size(), size);
    assert_eq!(index.entries()[0].directory().compressed_size(), size);
    assert!(source.bytes_read < 70_000);

    Ok(())
}

#[tokio::test]
async fn rejects_malformed_extras_and_zip64_version_two() {
    for extra in [
        vec![0],
        vec![0, 0],
        vec![0, 0, 0],
        vec![1, 0, 8, 0],
        vec![1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0],
        field(1, &[]),
        [field(0xbeef, &[]), field(0xbeef, &[])].concat(),
    ] {
        for local in [false, true] {
            let mut fixture = Fixture::default();
            if local {
                fixture.local_extra.clone_from(&extra);
            } else {
                fixture.central_extra.clone_from(&extra);
            }

            assert!(
                read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
                    .await
                    .is_err(),
                "extra {extra:?}, local={local}"
            );
        }
    }

    let archive = Fixture {
        zip64: true,
        zip64_version: Some(62),
        ..Fixture::default()
    }
    .build();
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
    ]
    .into_iter()
    .chain(
        [
            (0x000fu16, false),
            (0x0013, true),
            (0x0014, false),
            (0x0015, false),
            (0x0016, false),
            (0x0017, false),
            (0x0018, true),
            (0x0019, false),
            (0x001a, true),
            (0x9900, true),
            (0x9901, false),
            (0x9902, true),
        ]
        .map(|(identifier, valid)| {
            (
                [identifier.to_le_bytes().as_slice(), &[0; 4]].concat(),
                valid,
            )
        }),
    ) {
        let archive = Fixture {
            zip64: true,
            zip64_extensions: extension,
            ..Fixture::default()
        }
        .build();

        let result = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;

        assert_eq!(result.is_ok(), valid);
    }

    Ok(())
}

#[tokio::test]
async fn charges_zip64_end_records_to_metadata_budget() -> TestResult {
    let archive = Fixture {
        zip64: true,
        zip64_extensions: [0xef, 0xbe, 0, 0, 0, 0].repeat(11_000),
        archive_comment: vec![b'a'; usize::from(u16::MAX)],
        ..Fixture::default()
    }
    .build();
    let end_offset = archive.zip64_end.ok_or("missing ZIP64 end")?;
    let directory_budget = (archive.end - 20 - archive.central) as u64;
    let total_budget = directory_budget + (archive.central - b"payload".len()) as u64;
    // Directory, ZIP64 end, and local metadata share one cumulative budget.
    for metadata_size in [total_budget - 1, total_budget] {
        let mut source = Cursor::new(&archive.bytes);
        let mut index = Index::read(
            &mut source,
            Limits {
                metadata_size,
                ..Limits::default()
            },
        )
        .await?;
        let result = index.validate_all(&mut source).await;
        if metadata_size == total_budget {
            result?;
        } else {
            assert!(matches!(
                result,
                Err(FrameError::Limit {
                    resource: "metadata bytes",
                    limit,
                }) if limit == metadata_size
            ));
        }
    }

    let mut source = Observed::new(archive.bytes);
    // The extension exceeds the read-ahead window and requires its own read.
    // The combined directory and end-record charge must precede that read.
    source.fail_at = Some(end_offset as u64 + 56);
    assert!(matches!(
        read_validated(
            &mut source,
            Limits {
                metadata_size: directory_budget - 1,
                ..Limits::default()
            },
        )
        .await,
        Err(FrameError::Limit {
            resource: "metadata bytes",
            limit,
        }) if limit == directory_budget - 1
    ));
    assert_eq!(source.fail_at, Some(end_offset as u64 + 56));

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
            local_offset: bytes.len() as u32,
            ..Fixture::default()
        }
        .build();
        positions.push(bytes.len() as u64);
        directory.extend_from_slice(&fixture.bytes[fixture.central..fixture.end]);
        bytes.extend_from_slice(&fixture.bytes[..fixture.central]);
    }

    // Keep the tail search outside both the directory and local records.
    let central = bytes.len();
    bytes.extend_from_slice(&directory);
    bytes.extend(end_record(
        2000,
        central as u32,
        directory.len() as u32,
        &vec![b'a'; usize::from(u16::MAX)],
    ));
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
    assert_eq!(entry.directory().path(), "file-7");
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
