mod support;

use std::{error::Error, io::Cursor};

use crc32fast::hash as crc32;
use tokio::io::{AsyncRead, AsyncSeek};
use zip_framing::{
    CentralDirectoryEntry, CompressionMethod, DeviceNumbers, EntryKind, Error as FrameError,
    HostSystem, Index, IndexedEntry, LimitExceeded, Limits,
    write::{EntryKind as WriteEntryKind, PendingMember, end_records},
};

use support::{Fixture, Observed, Sparse, end_record, field, set16, set32};

type TestResult = Result<(), Box<dyn Error>>;

fn unicode_data(value: &[u8]) -> Vec<u8> {
    let mut data = vec![1];
    data.extend(crc32(value).to_le_bytes());
    data.extend_from_slice(value);
    data
}

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

    // A ZIP64 extra containing only the local-header offset still selects
    // 64-bit descriptor sizes (APPNOTE 4.3.9.2).
    let mut archive = Fixture {
        payload: Some(Vec::new()),
        descriptor: Some(false),
        local_offset: u32::MAX,
        central_extra: field(1, &0_u64.to_le_bytes()),
        ..Fixture::default()
    }
    .build();
    set16(&mut archive.bytes, 4, 45);
    set16(&mut archive.bytes, archive.central + 6, 45);
    let central_header = &archive.bytes[archive.central..archive.end];
    for (descriptor_length, valid) in [(12, false), (20, true)] {
        let mut bytes = archive.bytes[..archive.descriptor].to_vec();
        // Both descriptor widths are all zeros for the empty payload.
        bytes.resize(archive.descriptor + descriptor_length, 0);
        let central = bytes.len();
        bytes.extend_from_slice(central_header);
        bytes.extend(end_records(1, central as u64, central_header.len() as u64)?);

        let result = read_validated(&mut Cursor::new(bytes), Limits::default()).await;
        if valid {
            assert_eq!(result?.entries().len(), 1);
        } else {
            assert!(matches!(
                result,
                Err(FrameError::Invalid {
                    reason: "invalid data descriptor length",
                    ..
                })
            ));
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
        let local_extra = if mask & 3 != 0 {
            field(1, &[17_u64.to_le_bytes(), 7_u64.to_le_bytes()].concat())
        } else {
            Vec::new()
        };
        let central_extra = field(1, &central_extra);
        let build = |local_extra, central_extra| {
            let mut archive = Fixture {
                local_extra,
                central_extra,
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
            archive
        };
        let archive = build(local_extra.clone(), central_extra.clone());

        let index = read_validated(&mut Cursor::new(&archive.bytes), Limits::default()).await?;
        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.directory().position(), 0);
        assert_eq!(entry.directory().size(), 17);
        assert_eq!(entry.directory().compressed_size(), 7);
        assert_eq!(
            &archive.bytes[entry.data_offset() as usize..archive.central],
            b"payload"
        );

        // Each sentinel still needs its own header's ZIP64 field.
        for local in [false, true] {
            if local && local_extra.is_empty() {
                continue;
            }
            let missing = if local {
                build(Vec::new(), central_extra.clone())
            } else {
                build(local_extra.clone(), Vec::new())
            };
            let expected = if local { 0 } else { missing.central as u64 };
            assert!(
                matches!(
                    read_validated(&mut Cursor::new(missing.bytes), Limits::default()).await,
                    Err(FrameError::Invalid {
                        position,
                        reason: "missing or superfluous ZIP64 values",
                    }) if position == expected
                ),
                "mask={mask}, local={local}"
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
    let name = vec![b'n'; 258];
    let extra = field(0x7075, &unicode_data(&name));
    let archive = Fixture {
        name,
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
    assert_eq!(entry.data_offset(), 30 + 258 + (4 + 5 + 258));
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
        (
            "link",
            3,
            0o120777 << 16,
            EntryKind::SymbolicLink { unix_target: None },
            0o120777,
        ),
        (
            "device",
            3,
            0o020600 << 16,
            EntryKind::CharacterDevice { numbers: None },
            0o020600,
        ),
        (
            "device",
            3,
            0o060600 << 16,
            EntryKind::BlockDevice { numbers: None },
            0o060600,
        ),
        ("fifo", 3, 0o010600 << 16, EntryKind::Fifo, 0o010600),
        ("socket", 3, 0o140600 << 16, EntryKind::Socket, 0o140600),
        ("volume", 0, 0x08, EntryKind::VolumeLabel, 0),
        (
            "unknown",
            3,
            0o030600 << 16,
            EntryKind::Unknown { mode: 0o030000 },
            0o030600,
        ),
    ] {
        let archive = Fixture {
            name: name.as_bytes().to_vec(),
            payload: Some(if matches!(expected, EntryKind::SymbolicLink { .. }) {
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
        assert_eq!(entry.kind(), &expected, "{name}, host {host}");
        assert_eq!(entry.unix_mode(), mode, "{name}, host {host}");

        source.reads.clear();
        let cached = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(cached.kind(), &expected);
        index.validate_all(&mut source).await?;
        assert!(source.reads.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn resolves_kinds_and_reconciled_unix_data() -> TestResult {
    let device_numbers = [0x78, 0x56, 0x34, 0x92, 0xef, 0xcd, 0xab, 0x80];
    let device = DeviceNumbers {
        major: 0x9234_5678,
        minor: 0x80ab_cdef,
    };
    for (attributes, data, payload, expected) in [
        (
            0o120777 << 16,
            "../café".as_bytes(),
            b"".as_slice(),
            EntryKind::SymbolicLink {
                unix_target: Some("../café".to_owned()),
            },
        ),
        (
            0o120777 << 16,
            b"target",
            b"target",
            EntryKind::SymbolicLink {
                unix_target: Some("target".to_owned()),
            },
        ),
        (0o100644 << 16, b"", b"data", EntryKind::File),
        (
            0o020600 << 16,
            device_numbers.as_slice(),
            b"",
            EntryKind::CharacterDevice {
                numbers: Some(device),
            },
        ),
        (
            0o060600 << 16,
            device_numbers.as_slice(),
            b"",
            EntryKind::BlockDevice {
                numbers: Some(device),
            },
        ),
    ] {
        let unix_extra = field(0x000d, &[&[0; 12], data].concat());
        let archive = Fixture {
            payload: Some(payload.to_vec()),
            external_attributes: attributes,
            local_extra: unix_extra.clone(),
            central_extra: unix_extra,
            ..Fixture::default()
        }
        .build();
        let index = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await?;
        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.kind(), &expected);
        assert!(entry.has_unix_extra());
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
            0o120777 << 16,
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
            Some(&[]),
            20,
            "invalid UNIX device numbers",
        ),
        (
            "link",
            0o120777 << 16,
            b"target",
            Some(&[]),
            20,
            "empty symbolic-link target",
        ),
        (
            "socket",
            0o140600 << 16,
            b"",
            Some(b"opaque"),
            20,
            "unexpected UNIX file-type data",
        ),
        (
            "unknown",
            0o030600 << 16,
            b"",
            Some(b"opaque"),
            20,
            "unexpected UNIX file-type data",
        ),
        (
            "volume",
            0x08,
            b"",
            Some(b"opaque"),
            20,
            "unexpected UNIX file-type data",
        ),
        (
            "volume/",
            0x08,
            b"",
            None,
            20,
            "inconsistent file attributes",
        ),
        (
            "volume",
            (0o100644 << 16) | 0x08,
            b"",
            None,
            20,
            "inconsistent file attributes",
        ),
        (
            "volume",
            0x08,
            b"data",
            None,
            20,
            "non-file member has payload data",
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
async fn rejects_archive_extra_data_records() {
    for data in [Vec::new(), field(0xcafe, &[0x51; 257])] {
        let archive = Fixture {
            archive_extra: Some(data),
            ..Fixture::default()
        }
        .build();
        assert!(matches!(
            Index::read(&mut Cursor::new(&archive.bytes), Limits::default()).await,
            Err(FrameError::Unsupported { position, feature: "archive extra data record" })
                if position == archive.central as u64
        ));
    }
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
    for identifier in [
        0x0007, 0x0008, 0x000f, 0x0014, 0x0015, 0x0016, 0x0017, 0x0019, 0x2605, 0x6c78, 0x756e,
        0x9901, 0xbeef,
    ] {
        let extra = field(identifier, &[]);
        for (local, central) in [(true, false), (false, true), (true, true)] {
            let archive = Fixture {
                local_extra: if local { extra.clone() } else { Vec::new() },
                central_extra: if central { extra.clone() } else { Vec::new() },
                ..Fixture::default()
            }
            .build();
            let offset = if central { archive.central as u64 } else { 0 };
            assert!(
                matches!(
                    read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
                    Err(FrameError::UnsupportedExtraField { position, identifier: rejected })
                        if position == offset && rejected == identifier
                ),
                "{identifier:#06x}, local={local}, central={central}"
            );
        }
    }
}

#[tokio::test]
async fn validates_utf8_and_unicode_path_extras() -> TestResult {
    let name = "café".as_bytes();
    let unicode = unicode_data(name);
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
        let extra = field(
            0x7075,
            &[
                vec![1],
                crc32(original).to_le_bytes().to_vec(),
                name.to_vec(),
            ]
            .concat(),
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

    // Valid directory names do not excuse malformed local names or a local
    // encoding flag disagreement, even when both filename byte strings match.
    for zip64 in [false, true] {
        for change in [None, Some(0), Some(0xff), Some(b'/')] {
            let mut archive = Fixture {
                name: name.to_vec(),
                zip64,
                ..Fixture::default()
            }
            .build();
            if let Some(byte) = change {
                archive.bytes[30] = byte;
            } else {
                set16(&mut archive.bytes, 6, 0);
            }
            let mut source = Cursor::new(archive.bytes);
            let mut index = Index::read(&mut source, Limits::default()).await?;
            assert!(matches!(
                index.entry(&mut source, 0).await,
                Err(FrameError::Invalid { position: 0, .. })
            ));
            assert!(index.resolved(0).is_none());
        }
    }

    Ok(())
}

#[tokio::test]
async fn enforces_resource_budgets_before_exposing_members() {
    let bytes = Fixture::default().build().bytes;
    for (limits, expected) in [
        (
            Limits {
                archive_size: 1,
                ..Limits::default()
            },
            LimitExceeded::ArchiveSize(1),
        ),
        (
            Limits {
                entries: 0,
                ..Limits::default()
            },
            LimitExceeded::EntryCount(0),
        ),
        (
            Limits {
                metadata_size: 1,
                ..Limits::default()
            },
            LimitExceeded::MetadataSize(1),
        ),
        (
            Limits {
                member_size: 6,
                ..Limits::default()
            },
            LimitExceeded::MemberSize(6),
        ),
        (
            Limits {
                total_size: 6,
                ..Limits::default()
            },
            LimitExceeded::TotalSize(6),
        ),
    ] {
        assert!(matches!(
            read_validated(&mut Cursor::new(&bytes), limits).await,
            Err(FrameError::Limit(limit)) if limit == expected
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

        for (limits, expected) in [
            (
                Limits {
                    entries: 0,
                    ..Limits::default()
                },
                LimitExceeded::EntryCount(0),
            ),
            (
                Limits {
                    metadata_size: directory_size - 1,
                    ..Limits::default()
                },
                LimitExceeded::MetadataSize(directory_size - 1),
            ),
        ] {
            let mut source = Observed::new(archive.bytes.clone());
            // Keep the end-record scan separate from the directory body, and
            // fail if parsing reaches that body before enforcing the limits.
            source.fail_at = Some(archive.central as u64);
            assert!(matches!(
                Index::read(&mut source, limits).await,
                Err(FrameError::Limit(limit)) if limit == expected
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
    let unicode = unicode_data(comment);
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

    let unicode_comment = |bytes: &[u8]| field(0x6375, bytes);
    for (local_extra, central_extra, expected) in [
        (unicode_comment(&unicode), unicode_comment(&unicode), None),
        (
            unicode_comment(&unicode),
            Vec::new(),
            Some("local Unicode comment has no central copy"),
        ),
        // Correct CRC for "comment", but the Unicode text is empty.
        (
            Vec::new(),
            unicode_comment(&unicode[..5]),
            Some("Unicode comment disagrees with member comment"),
        ),
    ] {
        let archive = Fixture {
            member_comment: comment.to_vec(),
            local_extra,
            central_extra,
            ..Fixture::default()
        }
        .build();
        let result = read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await;
        if let Some(expected) = expected {
            assert!(
                matches!(result, Err(FrameError::Invalid { reason, .. }) if reason == expected)
            );
        } else {
            result?;
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

    // The signature can straddle the comment length (little-endian "PK").
    let mut split = vec![0; usize::from(u16::from_le_bytes(*b"PK"))];
    split[..2].copy_from_slice(b"\x05\x06");
    for (comment, shadow_offset) in [
        ([empty.as_slice(), b"x"].concat(), 22), // Fake EOCD stops before EOF.
        (empty, 22),                             // Both records reach EOF.
        (b"dataPK\x05\x06".to_vec(), 26),        // Too short for a second EOCD.
        (split, 20),
    ] {
        let archive = Fixture {
            archive_comment: comment,
            ..Fixture::default()
        }
        .build();
        assert!(matches!(
            Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await,
            Err(FrameError::Invalid { position, reason: "ambiguous end records" })
                if position == archive.end as u64 + shadow_offset
        ));
    }

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
async fn finds_end_records_across_scan_groups() -> TestResult {
    for zip64 in [false, true] {
        for length in 0..64 {
            // With a full search window, changing the comment length moves the
            // EOCD through every alignment, including split signatures/headers.
            let archive = Fixture {
                zip64,
                payload: Some(vec![b'P'; 70_000]),
                archive_comment: vec![b'P'; length],
                ..Fixture::default()
            }
            .build();
            assert_eq!(
                Index::read(&mut Cursor::new(&archive.bytes), Limits::default())
                    .await?
                    .entries()
                    .len(),
                1
            );

            // Both end records reach EOF. Neither the earlier match nor one in
            // the final partial scan group may hide the other candidate.
            let mut comment = vec![b'P'; length];
            comment.extend(end_record(0, 0, 0, &[]));
            let archive = Fixture {
                zip64,
                archive_comment: comment,
                ..Fixture::default()
            }
            .build();
            assert!(matches!(
                Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await,
                Err(FrameError::Invalid {
                    reason: "ambiguous end records",
                    ..
                })
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn bounds_end_record_search_with_short_reads() -> TestResult {
    for byte in [0, b'a'] {
        let mut comment = vec![byte; usize::from(u16::MAX)];
        // Partial signatures, even at EOF, are ordinary comment bytes.
        comment[1..4].copy_from_slice(b"PK\x05");
        comment[usize::from(u16::MAX) - 3..].copy_from_slice(b"PK\x05");
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
        (field(0x000d, &data), field(0x000d, &data)),
        (field(0x000d, &data), Vec::new()),
        (Vec::new(), field(0x000d, &data)),
    ] {
        let fixture = Fixture {
            external_attributes: 0o120777 << 16,
            payload: Some(Vec::new()),
            local_extra: local_extra.clone(),
            central_extra: central_extra.clone(),
            ..Fixture::default()
        };

        let index =
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await?;

        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(
            entry.kind(),
            &EntryKind::SymbolicLink {
                unix_target: Some("target".to_owned())
            }
        );

        // The same target on an untyped or regular file can be read as a hard
        // link, even if the entry also has its own file contents.
        for attributes in [0, 0o100644 << 16] {
            for payload in [b"".as_slice(), b"replacement"] {
                let archive = Fixture {
                    external_attributes: attributes,
                    payload: Some(payload.to_vec()),
                    local_extra: local_extra.clone(),
                    central_extra: central_extra.clone(),
                    ..Fixture::default()
                }
                .build();
                assert!(matches!(
                    read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
                    Err(FrameError::Unsupported {
                        position: 0,
                        feature: "ambiguous UNIX hard link"
                    })
                ));
            }
        }
    }

    for (data, expected) in [
        (vec![0; 11], "truncated UNIX extra field"),
        (
            [vec![1; 12], b"different".to_vec()].concat(),
            "local and central extra fields disagree",
        ),
        (data, "local and central extra fields disagree"),
    ] {
        let fixture = Fixture {
            local_extra: field(0x000d, &data),
            central_extra: field(0x000d, &[0; 12]),
            ..Fixture::default()
        };

        assert!(matches!(
            read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await,
            Err(FrameError::Invalid { reason, .. }) if reason == expected
        ));
    }

    Ok(())
}

#[tokio::test]
async fn reconciles_shortened_info_zip_extras() -> TestResult {
    for (identifier, local, central) in [
        (0x5855, vec![1; 12], vec![1; 8]),
        (0x5855, vec![1; 8], vec![1; 8]),
        (0x5455, vec![3; 9], vec![3; 5]),
        (0x5455, vec![2; 5], vec![2]),
        (0x5455, vec![7; 13], vec![7; 5]),
        (0x7855, vec![1; 4], Vec::new()),
    ] {
        let fixture = Fixture {
            local_extra: field(identifier, &local),
            central_extra: field(identifier, &central),
            ..Fixture::default()
        };
        read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await?;
    }

    for (local, central, expected) in [
        (
            field(0x5855, &[1; 12]),
            field(0x5855, &[1; 7]),
            "invalid Info-ZIP extra field layout",
        ),
        (
            field(0x5855, &[1; 10]),
            Vec::new(),
            "invalid Info-ZIP extra field layout",
        ),
        (
            field(0x5855, &[1; 12]),
            field(0x5855, &[2; 8]),
            "local and central extra fields disagree",
        ),
        (
            field(0x5455, &[3; 9]),
            field(0x5455, &[3]),
            "invalid Info-ZIP extra field layout",
        ),
        (
            field(0x5455, &[8; 5]),
            Vec::new(),
            "invalid Info-ZIP extra field layout",
        ),
        (
            field(0x5455, &[]),
            Vec::new(),
            "missing Info-ZIP timestamp flags",
        ),
        (
            field(0x5455, &[3; 9]),
            field(0x5455, &[1; 5]),
            "local and central extra fields disagree",
        ),
        (
            field(0x7855, &[1; 4]),
            field(0x7855, &[1; 4]),
            "invalid Info-ZIP extra field layout",
        ),
        (
            field(0x7855, &[1; 2]),
            Vec::new(),
            "invalid Info-ZIP extra field layout",
        ),
        (
            Vec::new(),
            field(0x7855, &[]),
            "central Info-ZIP field has no local copy",
        ),
        (
            Vec::new(),
            field(0x5455, &[3; 5]),
            "central Info-ZIP field has no local copy",
        ),
        (
            field(0x5855, &[0; 12]),
            field(0x5455, &[1; 5]),
            "mixed old and new Info-ZIP UNIX metadata",
        ),
    ] {
        let archive = Fixture {
            local_extra: local,
            central_extra: central,
            ..Fixture::default()
        }
        .build();
        assert!(
            matches!(
                read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
                Err(FrameError::Invalid { reason, .. }) if reason == expected
            ),
            "{expected}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn validates_info_zip_ownership() -> TestResult {
    // Info-ZIP zip 3.0 writes both timestamps and variable-width ownership.
    let ownership = field(0x7875, &[1, 4, 0xf5, 1, 0, 0, 4, 20, 0, 0, 0]);
    let short = field(0x7875, &[1, 1, 42, 2, 0xff, 1]);
    for (local_extra, central_extra) in [
        (
            [field(0x5455, &[3; 9]), ownership.clone()].concat(),
            [ownership.clone(), field(0x5455, &[3; 5])].concat(),
        ),
        (short.clone(), Vec::new()),
        (Vec::new(), short),
    ] {
        let archive = Fixture {
            local_extra,
            central_extra,
            ..Fixture::default()
        }
        .build();
        read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await?;
    }

    for data in [
        &[][..],
        &[2, 1, 1, 1, 2],
        &[1, 0, 1, 2],
        &[1, 4, 0],
        &[1, 1, 1],
        &[1, 1, 1, 0],
        &[1, 1, 1, 2, 2],
        &[1, 1, 1, 1, 2, 3],
    ] {
        for local in [false, true] {
            let mut fixture = Fixture::default();
            if local {
                fixture.local_extra = field(0x7875, data);
            } else {
                fixture.central_extra = field(0x7875, data);
            }
            assert!(
                matches!(
                    read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default())
                        .await,
                    Err(FrameError::Invalid {
                        reason: "invalid Info-ZIP extra field layout",
                        ..
                    })
                ),
                "data={data:?}, local={local}"
            );
        }
    }

    for (local_extra, reason) in [
        (
            field(0x7875, &[1, 4, 0xf5, 1, 0, 0, 4, 21, 0, 0, 0]),
            "local and central extra fields disagree",
        ),
        (
            field(0x5855, &[0; 12]),
            "mixed old and new Info-ZIP UNIX metadata",
        ),
        (
            field(0x7855, &[0; 4]),
            "mixed old and new Info-ZIP UNIX metadata",
        ),
    ] {
        let archive = Fixture {
            local_extra,
            central_extra: ownership.clone(),
            ..Fixture::default()
        }
        .build();
        assert!(matches!(
            read_validated(&mut Cursor::new(archive.bytes), Limits::default()).await,
            Err(FrameError::Invalid { reason: actual, .. }) if actual == reason
        ));
    }
    Ok(())
}

#[tokio::test]
async fn respects_directory_order_but_rejects_shared_or_unindexed_local_members() -> TestResult {
    let first = Fixture::default().build();
    let unix_data = [vec![0; 12], b"target".to_vec()].concat();
    let second = Fixture {
        name: b"next".to_vec(),
        external_attributes: 0o120777 << 16,
        payload: Some(Vec::new()),
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
    let expected_link = EntryKind::SymbolicLink {
        unix_target: Some("target".to_owned()),
    };
    assert_eq!(entry.kind(), &expected_link);
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
        index.resolved(0).ok_or("unresolved entry")?.kind(),
        &expected_link
    );
    assert_eq!(index.entries()[1].directory().position(), 0);
    assert!(
        !index
            .resolved(1)
            .ok_or("unresolved entry")?
            .has_unix_extra()
    );

    // The ordered path must derive the same physical spans without sorting.
    let mut ordered = bytes[..central].to_vec();
    ordered.extend_from_slice(&first.bytes[first.central..first.end]);
    ordered.extend_from_slice(&second.bytes[second.central..second.end]);
    ordered.extend_from_slice(&bytes[end..]);
    let mut source = Cursor::new(ordered);
    let mut ordered = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(ordered.entries()[0].record_range(), 0..first.central as u64);
    assert_eq!(
        ordered.entries()[1].record_range(),
        first.central as u64..central as u64
    );
    ordered.validate_all(&mut source).await?;
    assert_eq!(
        ordered.resolved(1).ok_or("unresolved entry")?.kind(),
        &expected_link
    );

    let mut shared = bytes.clone();
    set32(&mut shared, central + 42, 0);

    // Repeated offsets must fail during indexing, before any local resolution.
    assert!(
        Index::read(&mut Cursor::new(shared), Limits::default())
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

    let mut index = Index::read(&mut source, Limits::default()).await?;
    let opening_bytes = source.bytes_read;
    index.validate_all(&mut source).await?;
    assert_eq!(source.bytes_read - opening_bytes, source.prefix.len());
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
        [field(0x5455, &[0]), field(0x5455, &[0])].concat(),
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

    // An inline ZIP64 field must still reject a later duplicate, including
    // when the first field is empty or another identifier separates the two.
    for data in [&[][..], &[0; 16][..]] {
        for local in [false, true] {
            let mut fixture = Fixture {
                zip64: true,
                ..Fixture::default()
            };
            let extra = [field(1, data), field(0x5455, &[0])].concat();
            if local {
                fixture.local_extra = extra;
            } else {
                fixture.central_extra = extra;
            }
            assert!(matches!(
                read_validated(&mut Cursor::new(fixture.build().bytes), Limits::default()).await,
                Err(FrameError::Invalid {
                    reason: "duplicate extra-field identifier",
                    ..
                })
            ));
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
async fn rejects_nonempty_zip64_extensible_data_sectors() -> TestResult {
    for extension in [vec![0xef], vec![0xef, 0xbe, 0, 0, 0, 0]] {
        let archive = Fixture {
            zip64: true,
            zip64_extensions: extension,
            ..Fixture::default()
        }
        .build();

        let end = archive.zip64_end.ok_or("missing ZIP64 end")? as u64;
        assert!(matches!(
            Index::read(&mut Cursor::new(archive.bytes), Limits::default()).await,
            Err(FrameError::Unsupported { position, feature: "ZIP64 extensible data sector" })
                if position == end
        ));
    }

    Ok(())
}

#[tokio::test]
async fn charges_zip64_end_records_to_metadata_budget() -> TestResult {
    let archive = Fixture {
        zip64: true,
        ..Fixture::default()
    }
    .build();
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
                Err(FrameError::Limit(LimitExceeded::MetadataSize(limit))) if limit == metadata_size
            ));
        }
    }

    assert!(matches!(
        Index::read(
            &mut Cursor::new(archive.bytes),
            Limits {
                metadata_size: directory_budget - 1,
                ..Limits::default()
            },
        )
        .await,
        Err(FrameError::Limit(LimitExceeded::MetadataSize(limit))) if limit == directory_budget - 1
    ));

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
    let comment = vec![b'c'; 6000];
    let extra = field(0x6375, &unicode_data(&comment));
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    for name in &names {
        let fixture = Fixture {
            name: name.as_bytes().to_vec(),
            local_extra: extra.clone(),
            central_extra: extra.clone(),
            member_comment: comment.clone(),
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
        // A partial read into reused scratch space must not publish stale
        // bytes or a resolution. Retrying the unchanged source must succeed.
        source.max_read = 3;
        source.fail_at = Some(index.entries()[ordinal].directory().position() + 3);
        assert!(matches!(
            index.entry(&mut source, ordinal).await,
            Err(FrameError::Io(_))
        ));
        assert!(index.resolved(ordinal).is_none());
        source.max_read = usize::MAX;
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
    let name = vec![b'n'; 5000];
    let extra = field(0x7075, &unicode_data(&name));
    let archive = Fixture {
        name,
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
                Err(FrameError::Limit(_))
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
