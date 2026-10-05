mod support;

use std::{error::Error, io::Cursor};

use flate2::Crc;
use tokio::io::{AsyncRead, AsyncSeek};
use zip_framing::{
    CentralDirectoryEntry, CompressionMethod, EntryKind, Error as FrameError, HostSystem, Index,
    IndexedEntry, Limits, UnixData,
    write::{EntryKind as WriteEntryKind, PendingMember, end_records},
};

use support::{Fixture, Observed, Sparse, end_record, field, set16, set32};

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
            // The nonempty payload's CRC is also the optional descriptor signature.
            for (payload, crc) in [(b"\xac\x0a\x7a\xd5".as_slice(), 0x0807_4b50), (b"", 0)] {
                let archive = Fixture {
                    zip64,
                    descriptor,
                    payload: Some(payload.to_vec()),
                    ..Fixture::default()
                }
                .build();

                let index =
                    read_validated(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
                assert_eq!(index.entries().len(), 1);

                let entry = index.resolved(0).ok_or("unresolved entry")?;
                assert_eq!(entry.directory().path(), "file");
                assert_eq!(entry.directory().size(), payload.len() as u64);
                assert_eq!(entry.directory().compressed_size(), payload.len() as u64);
                assert_eq!(entry.directory().crc32(), crc);
                assert_eq!(
                    &archive.bytes[entry.data_offset() as usize..archive.descriptor],
                    payload
                );
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn resolves_partial_zip64_extras_in_central_headers() -> TestResult {
    // Central ZIP64 values are present only for sentinel fields, in specification
    // order. Local ZIP64 extras must contain both sizes (APPNOTE 4.5.3).
    for mask in 1..16 {
        let mut central_extra = Vec::new();
        for (bit, value, width) in [(1, 17_u64, 8), (2, 7, 8), (4, 0, 8), (8, 0, 4)] {
            if mask & bit != 0 {
                central_extra.extend_from_slice(&value.to_le_bytes()[..width]);
            }
        }
        let mut archive = Fixture {
            local_extra: if mask & 3 != 0 {
                field(1, &[17_u64.to_le_bytes(), 7_u64.to_le_bytes()].concat())
            } else {
                Vec::new()
            },
            central_extra: field(1, &central_extra),
            ..Fixture::default()
        }
        .build();
        set16(&mut archive.bytes, 4, 45);
        set16(&mut archive.bytes, archive.central + 6, 45);
        // Different decoded and compressed sizes expose swapped or shifted fields.
        set16(&mut archive.bytes, 8, 8);
        set16(&mut archive.bytes, archive.central + 10, 8);
        set32(&mut archive.bytes, 22, 17);
        set32(&mut archive.bytes, archive.central + 24, 17);
        if mask & 3 != 0 {
            set32(&mut archive.bytes, 18, u32::MAX);
            set32(&mut archive.bytes, 22, u32::MAX);
        }
        for (bit, central) in [(1, 24), (2, 20)] {
            if mask & bit != 0 {
                set32(&mut archive.bytes, archive.central + central, u32::MAX);
            }
        }
        if mask & 4 != 0 {
            set32(&mut archive.bytes, archive.central + 42, u32::MAX);
        }
        if mask & 8 != 0 {
            set16(&mut archive.bytes, archive.central + 34, u16::MAX);
        }

        let index = read_validated(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.directory().position(), 0);
        assert_eq!(entry.directory().size(), 17);
        assert_eq!(entry.directory().compressed_size(), 7);
        assert_eq!(
            &archive.bytes[entry.data_offset() as usize..archive.central],
            b"payload"
        );

        // A well-formed unknown field cannot substitute for the required ZIP64 field.
        for position in [0, archive.central] {
            if position == 0 && mask & 3 == 0 {
                continue;
            }
            let mut bytes = archive.bytes.clone();
            let extra = position + if position == 0 { 30 } else { 46 } + 4;
            set16(&mut bytes, extra, 0xcafe);
            assert!(
                matches!(
                    read_validated(&mut Cursor::new(bytes), Limits::default()).await,
                    Err(FrameError::Invalid {
                        position: error_position,
                        reason: "missing or superfluous ZIP64 values",
                    }) if error_position == position as u64
                ),
                "mask={mask}, position={position}"
            );
        }
    }

    for offset in [18, 22] {
        let mut archive = Fixture {
            zip64: true,
            ..Fixture::default()
        }
        .build();
        set32(&mut archive.bytes, offset, 7);
        assert!(matches!(
            read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
            Err(FrameError::Invalid {
                position: 0,
                reason: "local ZIP64 must contain both sizes"
            })
        ));
    }

    Ok(())
}

#[tokio::test]
async fn reconciles_each_concrete_zip64_end_field() -> TestResult {
    let archive = Fixture {
        zip64: true,
        ..Fixture::default()
    }
    .build();
    let directory_size = archive.zip64_end.ok_or("missing ZIP64 end")? - archive.central;
    for (offset, width, expected) in [
        (4, 2, 0),
        (6, 2, 0),
        (8, 2, 1),
        (10, 2, 1),
        (12, 4, directory_size as u32),
        (16, 4, archive.central as u32),
    ] {
        // Hold every other classic field at its sentinel. Agreement must be
        // checked independently even when only one concrete value is present.
        for (value, valid) in [(expected, true), (expected + 1, false)] {
            let mut bytes = archive.bytes.clone();
            bytes[archive.end + 4..archive.end + 20].fill(0xff);
            bytes[archive.end + offset..archive.end + offset + width]
                .copy_from_slice(&value.to_le_bytes()[..width]);
            let result = Index::read(&mut Cursor::new(bytes), Limits::default()).await;
            if valid {
                assert_eq!(result?.entries().len(), 1);
            } else {
                assert!(
                    matches!(result, Err(FrameError::Invalid {
                        position,
                        reason: "classic and ZIP64 end records disagree",
                    }) if position == archive.end as u64),
                    "offset={offset}"
                );
            }
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
    let entry = index.resolved(0).ok_or("unresolved entry")?;
    assert_eq!(entry.directory().path(), "n".repeat(258));
    assert_eq!(entry.directory().host_system(), HostSystem::Os400);
    assert_eq!(entry.directory().external_attributes(), 0x1234_5678);
    assert_eq!(entry.data_offset(), 30 + 258 + 261);
    assert_eq!(entry.directory().size(), 7);

    Ok(())
}

#[tokio::test]
async fn resolves_member_kinds_and_caches_them_with_local_metadata() -> TestResult {
    for (name, host, attributes, expected, mode) in [
        ("file", 3, 0, EntryKind::File, 0),
        ("file", 3, 0o106755 << 16, EntryKind::File, 0o106755),
        ("file", 0, 0o120777 << 16, EntryKind::File, 0),
        ("file", 255, (0o040755 << 16) | 0x18, EntryKind::File, 0),
        ("directory/", 3, 0, EntryKind::Directory, 0),
        ("directory", 0, 0x10, EntryKind::Directory, 0),
        (
            "directory",
            3,
            0o040755 << 16,
            EntryKind::Directory,
            0o040755,
        ),
        (
            "directory",
            19,
            0o040755 << 16,
            EntryKind::Directory,
            0o040755,
        ),
        ("link", 3, 0o120777 << 16, EntryKind::SymbolicLink, 0o120777),
        (
            "device",
            3,
            0o020600 << 16,
            EntryKind::CharacterDevice,
            0o020600,
        ),
        (
            "device",
            3,
            0o060600 << 16,
            EntryKind::BlockDevice,
            0o060600,
        ),
        ("fifo", 3, 0o010600 << 16, EntryKind::Fifo, 0o010600),
        ("socket", 3, 0o140600 << 16, EntryKind::Socket, 0o140600),
        ("volume", 0, 0x08, EntryKind::VolumeLabel, 0),
        (
            "unknown",
            3,
            0o030600 << 16,
            EntryKind::Unknown(0o030000),
            0o030600,
        ),
    ] {
        let archive = Fixture {
            name: name.as_bytes().to_vec(),
            payload: Some(if expected == EntryKind::SymbolicLink {
                b"target".to_vec()
            } else {
                Vec::new()
            }),
            made_by: Some((host << 8) | 20),
            external_attributes: attributes,
            ..Fixture::default()
        }
        .build();
        let mut source = Observed::new(archive.bytes);
        let mut index = Index::read(&mut source, Limits::default()).await?;
        assert!(index.resolved(0).is_none());

        let entry = index.entry(&mut source, 0).await?.ok_or("missing entry")?;
        assert_eq!(entry.kind(), expected, "{name}, host {host}");
        assert_eq!(entry.unix_mode(), mode, "{name}, host {host}");

        source.reads.clear();
        let cached = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(cached.kind(), expected);
        index.validate_all(&mut source).await?;
        assert!(source.reads.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn resolves_kinds_and_reconciled_unix_data() -> TestResult {
    let device_numbers = [0x78, 0x56, 0x34, 0x92, 0xef, 0xcd, 0xab, 0x80];
    let device = UnixData::Device {
        major: 0x9234_5678,
        minor: 0x80ab_cdef,
    };
    for (attributes, data, payload, expected, expected_data) in [
        (
            0,
            b"target".as_slice(),
            b"".as_slice(),
            EntryKind::HardLink,
            &UnixData::LinkTarget("target".to_owned()),
        ),
        (
            0o100644 << 16,
            b"target",
            b"data",
            EntryKind::HardLink,
            &UnixData::LinkTarget("target".to_owned()),
        ),
        (
            0o120777 << 16,
            "../café".as_bytes(),
            b"",
            EntryKind::SymbolicLink,
            &UnixData::LinkTarget("../café".to_owned()),
        ),
        (
            0o120777 << 16,
            b"target",
            b"target",
            EntryKind::SymbolicLink,
            &UnixData::LinkTarget("target".to_owned()),
        ),
        (
            0o100644 << 16,
            b"",
            b"data",
            EntryKind::File,
            &UnixData::Empty,
        ),
        (
            0o020600 << 16,
            device_numbers.as_slice(),
            b"",
            EntryKind::CharacterDevice,
            &device,
        ),
        (
            0o060600 << 16,
            device_numbers.as_slice(),
            b"",
            EntryKind::BlockDevice,
            &device,
        ),
        (
            0o140600 << 16,
            b"opaque",
            b"",
            EntryKind::Socket,
            &UnixData::Opaque(b"opaque".to_vec()),
        ),
        (
            0o030600 << 16,
            b"opaque",
            b"",
            EntryKind::Unknown(0o030000),
            &UnixData::Opaque(b"opaque".to_vec()),
        ),
        (
            0x08,
            b"opaque",
            b"",
            EntryKind::VolumeLabel,
            &UnixData::Opaque(b"opaque".to_vec()),
        ),
    ] {
        let archive = Fixture {
            payload: Some(payload.to_vec()),
            external_attributes: attributes,
            local_extra: field(0x000d, &[&[0; 12], data].concat()),
            central_extra: field(0x000d, &[0; 12]),
            ..Fixture::default()
        }
        .build();
        let index = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await?;
        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.kind(), expected);
        assert_eq!(entry.unix_data(), Some(expected_data));
    }

    Ok(())
}

#[tokio::test]
async fn rejects_inconsistent_kind_metadata_before_caching_or_charging_it() -> TestResult {
    for (name, attributes, payload, data, version, expected) in [
        (
            "file",
            (0o100644 << 16) | 0x10,
            b"".as_slice(),
            None,
            20,
            "inconsistent file attributes",
        ),
        (
            "link/",
            0o120777 << 16,
            b"target",
            None,
            20,
            "inconsistent file attributes",
        ),
        (
            "directory/",
            0,
            b"data",
            None,
            20,
            "non-file member has payload data",
        ),
        (
            "fifo",
            0o010600 << 16,
            b"data",
            None,
            20,
            "non-file member has payload data",
        ),
        (
            "directory/",
            0,
            b"",
            None,
            10,
            "directory requires extraction version 2.0",
        ),
        (
            "link",
            0o120777 << 16,
            b"",
            None,
            20,
            "empty symbolic-link target",
        ),
        (
            "link",
            0o100644 << 16,
            b"",
            Some(b"\xff".as_slice()),
            20,
            "non-UTF-8 UNIX link target",
        ),
        (
            "link",
            0o120777 << 16,
            b"",
            Some(b"target\0"),
            20,
            "NUL in UNIX link target",
        ),
        (
            "directory/",
            0,
            b"",
            Some(b"target".as_slice()),
            20,
            "unexpected UNIX file-type data",
        ),
        (
            "fifo",
            0o010600 << 16,
            b"",
            Some(b"target"),
            20,
            "unexpected UNIX file-type data",
        ),
        (
            "device",
            0o020600 << 16,
            b"",
            Some(&[0; 7]),
            20,
            "invalid UNIX device numbers",
        ),
        (
            "device",
            0o060600 << 16,
            b"",
            Some(&[0; 9]),
            20,
            "invalid UNIX device numbers",
        ),
    ] {
        let mut archive = Fixture {
            name: name.as_bytes().to_vec(),
            payload: Some(payload.to_vec()),
            external_attributes: attributes,
            local_extra: data
                .map_or_else(Vec::new, |data| field(0x000d, &[&[0; 12], data].concat())),
            ..Fixture::default()
        }
        .build();
        set16(&mut archive.bytes, 4, version);
        set16(&mut archive.bytes, archive.central + 6, version);
        let mut source = Cursor::new(&archive.bytes);
        let mut index = Index::read(
            &mut source,
            Limits {
                metadata_size: (archive.end - payload.len()) as u64,
                ..Limits::default()
            },
        )
        .await?;

        // Each failure must leave enough budget to retry the same metadata.
        for full_validation in [false, true, false] {
            let result = if full_validation {
                index.validate_all(&mut source).await
            } else {
                index.entry(&mut source, 0).await.map(|_| ())
            };
            assert!(
                matches!(result, Err(FrameError::Invalid { position: 0, reason }) if reason == expected),
                "{name}, attributes {attributes:#x}: {result:?}"
            );
            assert!(index.resolved(0).is_none());
        }
    }

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
async fn checks_extraction_versions_even_when_both_headers_agree() -> TestResult {
    for (method, minimum) in [(0, 10), (8, 20)] {
        for version in [minimum - 1, minimum, 45, 46, 0x0314] {
            let mut archive = Fixture::default().build();
            set16(&mut archive.bytes, 8, method);
            set16(&mut archive.bytes, archive.central + 10, method);
            set16(&mut archive.bytes, 4, version);
            set16(&mut archive.bytes, archive.central + 6, version);
            let result = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;
            if version < minimum {
                assert!(matches!(
                    result,
                    Err(FrameError::Invalid {
                        reason: "extraction version is too low",
                        ..
                    })
                ));
            } else if version > 45 {
                // Unlike rs-async-zip, we do not discard a nonzero high byte.
                assert!(matches!(
                    result,
                    Err(FrameError::Unsupported {
                        feature: "extraction version",
                        ..
                    })
                ));
            } else {
                result?;
            }
        }
    }

    Ok(())
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

    let mut invalid = Vec::new();
    for change in [0, 1, 5] {
        let mut value = unicode.clone();
        value[change] ^= 1;
        invalid.push(value);
    }
    for replacement in [
        b"\xff".as_slice(),
        b"\xef\xbb\xbfcaf\xc3\xa9",
        b"",
        b"caf\xc3",
    ] {
        invalid.push([unicode[..5].to_vec(), replacement.to_vec()].concat());
    }
    for value in invalid {
        for local in [false, true] {
            let mut fixture = Fixture {
                name: name.to_vec(),
                ..Fixture::default()
            };
            if local {
                fixture.local_extra = field(0x7075, &value);
            } else {
                fixture.central_extra = field(0x7075, &value);
            }
            assert!(
                read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
                    .await
                    .is_err(),
                "Unicode field={value:?}, local={local}"
            );
        }
    }

    // A valid Unicode extra is corroborating metadata, not a replacement for
    // a legacy-encoded name or a missing UTF-8 flag on a non-ASCII name.
    for original in [b"caf\xe9".as_slice(), name] {
        let mut crc = Crc::new();
        crc.update(original);
        let extra = field(
            0x7075,
            &[vec![1], crc.sum().to_le_bytes().to_vec(), name.to_vec()].concat(),
        );
        let archive = Fixture {
            name: original.to_vec(),
            flags: Some(0),
            local_extra: extra.clone(),
            central_extra: extra,
            ..Fixture::default()
        }
        .build();
        assert!(matches!(
            read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
            Err(FrameError::Invalid {
                reason: "non-UTF-8 filename" | "non-ASCII filename without UTF-8 flag",
                ..
            })
        ));
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

        let mut corrupt_offsets = vec![
            archive.central + 42,
            archive.end + 4,
            archive.end + 8,
            archive.end + 12,
            archive.end + 16,
        ];
        if let Some(position) = archive.zip64_end {
            // Signature, length, version, disks, counts, and directory extent.
            corrupt_offsets
                .extend([0, 4, 14, 16, 20, 24, 32, 40, 48].map(|offset| position + offset));
            // Locator disk, end-record offset, and total disks.
            corrupt_offsets.extend([4, 8, 16].map(|offset| archive.end - 20 + offset));
        }

        for offset in corrupt_offsets {
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
async fn rejects_missing_and_corrupt_descriptors_before_resolving_members() -> TestResult {
    for zip64 in [false, true] {
        for signed in [false, true] {
            let archive = Fixture {
                zip64,
                descriptor: Some(signed),
                ..Fixture::default()
            }
            .build();
            let fields = archive.descriptor + if signed { 4 } else { 0 };
            let mut corrupt_offsets = vec![fields, fields + 4, archive.central - 1];
            if signed {
                corrupt_offsets.push(archive.descriptor);
            }
            for offset in corrupt_offsets {
                let mut bytes = archive.bytes.clone();
                bytes[offset] ^= 1;
                let mut source = Cursor::new(bytes);
                let mut index = Index::read(&mut source, Limits::default()).await?;
                assert!(
                    matches!(
                        index.entry(&mut source, 0).await,
                        Err(FrameError::Invalid {
                            position,
                            reason: "invalid data descriptor signature" | "data descriptor disagrees with central header",
                        }) if position == archive.descriptor as u64
                    ),
                    "zip64={zip64}, signed={signed}, offset={offset}"
                );
                assert!(index.resolved(0).is_none());
            }

            let descriptor = &archive.bytes[archive.descriptor..archive.central];
            for length in [0, descriptor.len() - 1, descriptor.len() + 1] {
                // Rebuild the directory and footer so only the descriptor's span
                // is wrong; truncating the whole archive would test its footer.
                let mut bytes = archive.bytes[..archive.descriptor].to_vec();
                bytes.extend_from_slice(&descriptor[..length.min(descriptor.len())]);
                bytes.resize(archive.descriptor + length, 0);
                let central = bytes.len();
                bytes.extend_from_slice(
                    &archive.bytes[archive.central..archive.zip64_end.unwrap_or(archive.end)],
                );
                let size = bytes.len() - central;
                bytes.extend(end_record(1, central as u32, size as u32, &[]));
                assert!(
                    matches!(
                        read_validated(&mut Cursor::new(bytes), Limits::default()).await,
                        Err(FrameError::Invalid {
                            reason: "member cannot fit before the next record"
                                | "invalid data descriptor length",
                            ..
                        })
                    ),
                    "zip64={zip64}, signed={signed}, length={length}"
                );
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn requires_utf8_archive_and_member_comments() -> TestResult {
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

    // Incomplete Unicode comments remain invalid even when the ordinary comment
    // is usable; do not fall back to treating a recognized field as opaque data.
    let comment = b"comment";
    let mut crc = Crc::new();
    crc.update(comment);
    let unicode = [vec![1], crc.sum().to_le_bytes().to_vec(), comment.to_vec()].concat();
    for length in (0..5).chain([unicode.len()]) {
        let archive = Fixture {
            member_comment: comment.to_vec(),
            central_extra: field(0x6375, &unicode[..length]),
            ..Fixture::default()
        }
        .build();
        let result = Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await;
        if length == unicode.len() {
            result?;
        } else {
            assert!(
                matches!(
                    result,
                    Err(FrameError::Invalid {
                        position,
                        reason: "invalid Unicode extra field",
                    }) if position == archive.central as u64
                ),
                "length={length}"
            );
        }
    }

    Ok(())
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
async fn rejects_prefixed_and_concatenated_archives_with_consistent_offsets() -> TestResult {
    let first = Fixture::default().build();
    for (prefix, payload_size) in [
        (b"junk".as_slice(), 7),
        (&first.bytes, 7),
        (&first.bytes, 131_072),
    ] {
        let archive = Fixture {
            payload: Some(vec![b'x'; payload_size]),
            local_offset: prefix.len() as u32,
            ..Fixture::default()
        }
        .build();
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&archive.bytes);
        // All offsets identify real records, including when the earlier footer
        // is outside the search window. The selected archive must start at zero.
        set32(
            &mut bytes,
            prefix.len() + archive.end + 16,
            (prefix.len() + archive.central) as u32,
        );
        assert!(matches!(
            Index::read(&mut Cursor::new(bytes), Limits::default()).await,
            Err(FrameError::Invalid {
                position: 0,
                reason: "unaccounted bytes before the first member"
            })
        ));
    }

    // Referencing the first archive's local member does not account for the
    // directory, footer, and second local record between it and the selected CD.
    let mut bytes = first.bytes.repeat(2);
    set32(
        &mut bytes,
        first.bytes.len() + first.end + 16,
        (first.bytes.len() + first.central) as u32,
    );
    let mut source = Cursor::new(bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;
    assert!(matches!(
        index.entry(&mut source, 0).await,
        Err(FrameError::Invalid { position, reason: "unaccounted bytes after payload" })
            if position == first.central as u64
    ));
    assert!(index.resolved(0).is_none());

    Ok(())
}

#[tokio::test]
async fn bounds_end_record_search_with_short_reads() -> TestResult {
    for byte in [0, b'a'] {
        let mut comment = vec![byte; usize::from(u16::MAX)];
        // A signature whose declared comment does not reach EOF is not another
        // end record. Place it across a short-read boundary near the real EOCD.
        comment[1..5].copy_from_slice(b"PK\x05\x06");
        let mut source = Observed::new(end_record(0, 0, 0, &comment));
        source.max_read = 3;
        assert!(
            read_validated(&mut source, Limits::default())
                .await?
                .entries()
                .is_empty()
        );
    }

    // Failed searches must stay within the maximum EOCD + comment span even
    // when the source is large and every read is short.
    let mut source = Observed::new(vec![0; 2 * 1024 * 1024]);
    source.max_read = 3;
    assert!(matches!(
        Index::read(&mut source, Limits::default()).await,
        Err(FrameError::Invalid {
            reason: "missing end record or trailing bytes",
            ..
        })
    ));
    assert!(
        source
            .reads
            .iter()
            .all(|range| range.start >= 2 * 1024 * 1024 - 65_557)
    );
    assert_eq!(
        source
            .reads
            .iter()
            .map(|range| range.end - range.start)
            .sum::<u64>(),
        65_557
    );

    Ok(())
}

#[tokio::test]
async fn rejects_unaccounted_records_inside_the_directory() {
    let archive = Fixture::default().build();
    for suffix in [
        vec![0],
        // A well-formed digital signature is still outside the supported format.
        b"PK\x05\x05\x03\x00sig".to_vec(),
        archive.bytes[archive.central..archive.end].to_vec(),
    ] {
        let mut bytes = archive.bytes[..archive.end].to_vec();
        bytes.extend(suffix);
        let directory_size = (bytes.len() - archive.central) as u32;
        bytes.extend(end_record(1, archive.central as u32, directory_size, &[]));
        assert!(matches!(
            Index::read(&mut Cursor::new(bytes), Limits::default()).await,
            Err(FrameError::Invalid { position, reason: "unaccounted directory bytes or digital signature" })
                if position == archive.end as u64
        ));
    }
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

        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.kind(), EntryKind::HardLink);
        assert_eq!(
            entry.unix_data(),
            Some(&UnixData::LinkTarget("target".to_owned()))
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
            // Distinct unknown IDs must remain separate keys, independent of
            // their order in each header or their shared low byte.
            local_extra: [field(0xbeef, local), field(0xcaef, b"other field")].concat(),
            central_extra: [field(0xcaef, b"other field"), field(0xbeef, central)].concat(),
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
    let directory: &CentralDirectoryEntry = entries[0].directory();
    assert_eq!(directory.path(), "next");
    assert_eq!(
        entries[0].record_range(),
        first.central as u64..central as u64
    );
    assert_eq!(entries[1].record_range(), 0..first.central as u64);
    assert!((0..entries.len()).all(|ordinal| index.resolved(ordinal).is_none()));

    let entry = index.entry(&mut source, 0).await?.ok_or("missing entry")?;
    assert_eq!(entry.directory().path(), "next");
    assert_eq!(entry.record_range(), first.central as u64..central as u64);
    assert_eq!(
        entry.unix_data(),
        Some(&UnixData::LinkTarget("target".to_owned()))
    );
    assert!(index.resolved(0).is_some());
    assert!(index.resolved(1).is_none());

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
        index.resolved(0).ok_or("unresolved entry")?.unix_data(),
        Some(&UnixData::LinkTarget("target".to_owned()))
    );
    assert_eq!(index.entries()[1].directory().position(), 0);
    assert_eq!(
        index.resolved(1).ok_or("unresolved entry")?.unix_data(),
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
    let member = PendingMember::new(
        "file",
        CompressionMethod::Stored,
        WriteEntryKind::File { executable: false },
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
async fn indexes_zip64_counts_above_the_classic_limit() -> TestResult {
    let count = u64::from(u16::MAX) + 2;
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    for ordinal in 0..count {
        let name = format!("{ordinal}.txt");
        let member = PendingMember::new(
            &name,
            CompressionMethod::Stored,
            WriteEntryKind::File { executable: false },
        )?
        .finish(0, 0, 0, bytes.len() as u64)?;
        bytes.extend(member.local_header());
        directory.extend(member.central_header());
    }
    let offset = bytes.len() as u64;
    let size = directory.len() as u64;
    bytes.extend(directory);
    bytes.extend(end_records(count, offset, size)?);
    let mut source = Cursor::new(bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(index.entries().len() as u64, count);
    // Select both sides of the classic sentinel, in reverse directory order.
    for ordinal in [count - 1, count - 2, count - 3, 0] {
        let entry = index
            .entry(&mut source, ordinal as usize)
            .await?
            .ok_or("missing entry")?;
        assert_eq!(entry.directory().path(), format!("{ordinal}.txt"));
        assert_eq!(entry.directory().size(), 0);
    }

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
    assert!((0..index.entries().len()).all(|ordinal| index.resolved(ordinal).is_none()));
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
    assert!(index.resolved(2000).is_none());
    assert!(source.reads.is_empty());
    assert!(index.resolved(0).is_none());
    assert!(index.validate_all(&mut source).await.is_err());
    assert!(index.resolved(0).is_none());

    Ok(())
}

#[tokio::test]
async fn preserves_variable_metadata_across_read_ahead_windows() -> TestResult {
    let names = ["first".to_owned(), "é".repeat(30_000), "last".to_owned()];
    let extra = field(0xbeef, &vec![0xa5; 6000]);
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    for name in &names {
        let fixture = Fixture {
            name: name.as_bytes().to_vec(),
            local_extra: extra.clone(),
            central_extra: extra.clone(),
            member_comment: vec![b'c'; 6000],
            local_offset: bytes.len() as u32,
            ..Fixture::default()
        }
        .build();
        bytes.extend_from_slice(&fixture.bytes[..fixture.central]);
        directory.extend_from_slice(&fixture.bytes[fixture.central..fixture.end]);
    }
    let central = bytes.len();
    bytes.extend_from_slice(&directory);
    bytes.extend(end_record(
        names.len() as u16,
        central as u32,
        directory.len() as u32,
        &[],
    ));

    let mut source = Observed::new(bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(index.entries().len(), names.len());
    for (entry, name) in index.entries().iter().zip(&names) {
        assert_eq!(entry.directory().path(), name);
    }

    // Resolve in reverse order after the directory window has been replaced.
    // The middle member exceeds both local and directory read-ahead windows.
    for ordinal in (0..names.len()).rev() {
        let entry = index
            .entry(&mut source, ordinal)
            .await?
            .ok_or("missing member")?;
        assert_eq!(entry.directory().path(), names[ordinal]);
        assert_eq!(entry.directory().size(), 7);
    }
    index.validate_all(&mut source).await?;

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
        assert!(index.resolved(0).is_none());
        assert!(index.entry(&mut source, 0).await?.is_some());
        source.reads.clear();
        index.validate_all(&mut source).await?;
        assert!(source.reads.is_empty());
    }

    Ok(())
}
