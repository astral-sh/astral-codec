mod support;

use std::{error::Error, io::Cursor};

use crc32fast::hash as crc32;
use tokio::io::{AsyncRead, AsyncSeek};
use zip_framing::{
    CentralDirectoryEntry, CommentPolicy,
    CommentRule::{AllowAll, AllowUtf8, Reject},
    CompressionMethod, DeviceNumbers, EntryKind, Error as FrameError,
    ExtraFieldPolicy::{AllowKnown, AllowListed, Permissive},
    ExtraHeaderId::{self, ExtendedTimestamp, JarMagic, Ntfs, NtfsSecurityDescriptor},
    ExtraHeaderIdSet, HostSystem, Index, IndexPolicy, IndexPolicyViolation, IndexedEntry,
    LimitExceeded, Limits,
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

fn ntfs_data(fill: u8) -> Vec<u8> {
    let mut data = vec![fill; 32];
    set16(&mut data, 4, 1);
    set16(&mut data, 6, 24);
    data
}

// Exercise the format checks for features that require an opt-in.
fn all_features() -> IndexPolicy {
    IndexPolicy::default()
        .extra_field_policy(AllowKnown)
        .comment_policy(CommentPolicy {
            per_member: AllowAll,
            archive: AllowAll,
        })
        .allow_stored_data_descriptors(true)
        .allow_ambiguous_symlink_modes(true)
        .allow_backslashes(true)
}

async fn read_validated(bytes: &[u8]) -> Result<Index, FrameError> {
    read_validated_with(&mut Cursor::new(bytes), all_features()).await
}

async fn read_validated_with<R: AsyncRead + AsyncSeek + Unpin>(
    reader: &mut R,
    policy: IndexPolicy,
) -> Result<Index, FrameError> {
    let mut index = Index::read_with_policy(reader, policy).await?;
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

                let index = read_validated(&archive.bytes).await?;
                assert_eq!(index.entries().len(), 1);

                let entry = index.resolved(0).ok_or("unresolved entry")?;
                assert_eq!(entry.directory().path(), "file");
                assert_eq!(entry.directory().size(), payload.len() as u64);
                assert_eq!(entry.directory().compressed_size(), payload.len() as u64);
                assert_eq!(entry.directory().crc32(), crc);
                assert_eq!(
                    &archive.bytes[entry.data_offset() as usize..archive.payload.end],
                    payload
                );
            }
        }
    }

    // A ZIP64 extra containing only the local-header offset still selects
    // 64-bit descriptor sizes (APPNOTE 4.3.9.2).
    let archive = Fixture {
        payload: Some(Vec::new()),
        version: Some(45),
        descriptor: Some(false),
        local_offset: u32::MAX,
        central_extra: field(1, &0_u64.to_le_bytes()),
        ..Fixture::default()
    }
    .build();
    let central_header = &archive.bytes[archive.central..archive.end];
    for (descriptor_length, valid) in [(12, false), (20, true)] {
        let mut bytes = archive.bytes[..archive.payload.end].to_vec();
        // Both descriptor widths are all zeros for the empty payload.
        bytes.resize(archive.payload.end + descriptor_length, 0);
        let central = bytes.len();
        bytes.extend_from_slice(central_header);
        bytes.extend(end_records(1, central as u64, central_header.len() as u64)?);

        let result = read_validated(&bytes).await;
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
async fn resolves_classic_local_header_with_zip64_central_offset() -> TestResult {
    // CPython uses ZIP64 only in the central header when just the offset needs it.
    let mut archive = Fixture {
        local_offset: u32::MAX,
        central_extra: field(1, &0_u64.to_le_bytes()),
        ..Fixture::default()
    }
    .build();
    assert!(matches!(
        read_validated(&archive.bytes).await,
        Err(FrameError::Invalid { position, reason: "ZIP64 requires extraction version 4.5" })
            if position == archive.central as u64
    ));

    set16(&mut archive.bytes, archive.central + 6, 45);
    let index = read_validated(&archive.bytes).await?;
    let entry = index.resolved(0).ok_or("unresolved entry")?;
    assert_eq!(entry.directory().version_needed(), 45);
    assert_eq!(
        &archive.bytes[entry.data_offset() as usize..archive.central],
        b"payload"
    );
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
                version: Some(45),
                method: 8,
                local_extra,
                central_extra,
                ..Fixture::default()
            }
            .build();
            // Different decoded and compressed sizes expose swapped or shifted fields.
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

        let index = read_validated(&archive.bytes).await?;
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
                    read_validated(&missing.bytes).await,
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
            read_validated(&archive.bytes).await,
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
            let result = Index::read(&mut Cursor::new(bytes)).await;
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
        name: Some(name),
        local_extra: extra.clone(),
        central_extra: extra,
        member_comment: vec![b'c'; 259],
        made_by: Some(0x1234),
        external_attributes: 0x1234_5678,
        ..Fixture::default()
    }
    .build();
    let index = read_validated(&archive.bytes).await?;
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
        ("file", 2, 0o100666 << 16, EntryKind::File, 0),
        ("file", 255, (0o040755 << 16) | 0x18, EntryKind::File, 0),
        ("directory/", 3, 0, EntryKind::Directory, 0),
        ("directory/", 0, 0x10, EntryKind::Directory, 0),
        (
            "directory/",
            3,
            0o040755 << 16,
            EntryKind::Directory,
            0o040755,
        ),
        (
            "directory/",
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
            name: Some(name.as_bytes().to_vec()),
            version: matches!(expected, EntryKind::VolumeLabel).then_some(11),
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
        let mut index = Index::read(&mut source).await?;
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
            local_extra: unix_extra.clone(),
            central_extra: unix_extra,
            ..Fixture::member("file", attributes, payload)
        }
        .build();
        let index = read_validated(&archive.bytes).await?;
        let entry = index.resolved(0).ok_or("unresolved entry")?;
        assert_eq!(entry.kind(), &expected);
        assert!(entry.has_unix_extra());
    }

    Ok(())
}

#[tokio::test]
async fn version_1_directories_require_opt_in() -> TestResult {
    let mut archive = Fixture {
        version: Some(10),
        ..Fixture::member("empty/", (0o040755 << 16) | 0x10, b"")
    }
    .build();
    let mut source = Cursor::new(&archive.bytes);
    let mut index = Index::read(&mut source).await?;
    assert!(matches!(
        index.entry(&mut source, 0).await,
        Err(FrameError::PolicyViolation {
            position: 0,
            violation: IndexPolicyViolation::Version1Directory
        })
    ));

    let policy = IndexPolicy::default().allow_version_1_directories(true);
    let index = read_validated_with(&mut Cursor::new(&archive.bytes), policy).await?;
    let entry = index.resolved(0).ok_or("unresolved entry")?;
    assert_eq!(entry.kind(), &EntryKind::Directory);
    assert_eq!(entry.directory().version_needed(), 10);

    // Only the local header declares version 1.0.
    set16(&mut archive.bytes, archive.central + 6, 20);
    assert!(matches!(
        read_validated(&archive.bytes).await,
        Err(FrameError::PolicyViolation {
            violation: IndexPolicyViolation::Version1Directory,
            ..
        })
    ));
    read_validated_with(&mut Cursor::new(&archive.bytes), policy).await?;
    Ok(())
}

#[tokio::test]
async fn rejects_inconsistent_kind_metadata_before_caching_or_charging_it() -> TestResult {
    let member = Fixture::member;
    let link = |payload: &[u8]| member("link", 0o120777 << 16, payload);
    let directory = |payload: &[u8]| member("directory/", 0, payload);
    let fifo = |payload: &[u8]| member("fifo", 0o010600 << 16, payload);
    let volume = |payload: &[u8]| member("volume", 0x08, payload);
    let inconsistent = "inconsistent file attributes";
    let missing_suffix = "directory filename must end with '/'";
    let non_file = "non-file member has payload data";
    let unexpected = "unexpected UNIX file-type data";
    let bad_device = "invalid UNIX device numbers";

    for (fixture, expected) in [
        (member("file", (0o100644 << 16) | 0x10, b""), inconsistent),
        (member("file/", 0o100644 << 16, b""), inconsistent),
        (member("link/", 0o120777 << 16, b"target"), inconsistent),
        (member("directory", 0o040755 << 16, b""), missing_suffix),
        (member("directory", 0x10, b""), missing_suffix),
        (
            Fixture {
                made_by: Some(20),
                ..member("directory", 0x10, b"")
            },
            missing_suffix,
        ),
        (member("volume/", 0x08, b""), inconsistent),
        (member("volume", (0o100644 << 16) | 0x08, b""), inconsistent),
        (directory(b"data"), non_file),
        (fifo(b"data"), non_file),
        (volume(b"data"), non_file),
        (
            Fixture {
                version: Some(11),
                ..directory(b"")
            },
            "directory requires extraction version 2.0",
        ),
        (
            Fixture {
                made_by: Some(20),
                version: Some(10),
                ..volume(b"")
            },
            "volume label requires extraction version 1.1",
        ),
        (link(b""), "empty symbolic-link target"),
        (
            link(b"target").with_unix_data(b""),
            "empty symbolic-link target",
        ),
        (
            link(b"").with_unix_data(b"\xff"),
            "non-UTF-8 UNIX link target",
        ),
        (
            link(b"").with_unix_data(b"target\0"),
            "NUL in UNIX link target",
        ),
        (directory(b"").with_unix_data(b"target"), unexpected),
        (fifo(b"").with_unix_data(b"target"), unexpected),
        (
            member("socket", 0o140600 << 16, b"").with_unix_data(b"opaque"),
            unexpected,
        ),
        (
            member("unknown", 0o030600 << 16, b"").with_unix_data(b"opaque"),
            unexpected,
        ),
        (volume(b"").with_unix_data(b"opaque"), unexpected),
        (
            member("device", 0o020600 << 16, b"").with_unix_data(&[]),
            bad_device,
        ),
        (
            member("device", 0o020600 << 16, b"").with_unix_data(&[0; 7]),
            bad_device,
        ),
        (
            member("device", 0o060600 << 16, b"").with_unix_data(&[0; 9]),
            bad_device,
        ),
    ] {
        let archive = fixture.build();
        let mut source = Cursor::new(&archive.bytes);
        let mut index = Index::read_with_policy(
            &mut source,
            IndexPolicy::default()
                .allow_version_1_directories(true)
                .limits(Limits {
                    metadata_size: (archive.end - archive.payload.len()) as u64,
                    ..Limits::default()
                })
                .extra_field_policy(AllowKnown),
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
                "{}: expected {expected}, got {result:?}",
                index.entries()[0].directory().path()
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
            Index::read(&mut Cursor::new(&archive.bytes)).await,
            Err(FrameError::Unsupported { position, feature: "archive extra data record" })
                if position == archive.central as u64
        ));
    }
}

#[tokio::test]
async fn rejects_redundant_header_disagreements_and_unsupported_flags() -> TestResult {
    for (label, offset, value) in [
        ("flags", 7, 0),
        ("method", 8, 8),
        ("crc", 14, 1),
        ("compressed size", 18, 6),
        ("size", 22, 6),
        ("name", 30, b'x'),
    ] {
        let mut archive = Fixture::default().build();
        archive.bytes[offset] = value;

        assert!(read_validated(&archive.bytes).await.is_err(), "{label}");
    }

    let mut archive = Fixture::default().build();
    // Even invalid packed DOS times and dates may differ between headers.
    set32(&mut archive.bytes, 10, u32::MAX);
    read_validated_with(&mut Cursor::new(&archive.bytes), IndexPolicy::default()).await?;

    let mut archive = Fixture::default().build();
    for flags in [2, 4, 6] {
        set16(&mut archive.bytes, 6, flags);
        set16(&mut archive.bytes, archive.central + 8, flags);
        read_validated_with(&mut Cursor::new(&archive.bytes), IndexPolicy::default()).await?;
    }

    set16(&mut archive.bytes, 6, 0);
    for flags in [2, 4] {
        set16(&mut archive.bytes, archive.central + 8, flags);
        assert!(matches!(
            read_validated(&archive.bytes).await,
            Err(FrameError::Invalid {
                reason: "local and central headers disagree",
                ..
            })
        ));
    }

    for flags in [
        1, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x1000, 0x2000, 0x4000, 0x8000,
    ] {
        let archive = Fixture {
            flags: Some(flags),
            ..Fixture::default()
        }
        .build();

        assert!(
            read_validated(&archive.bytes).await.is_err(),
            "flags {flags:#x}"
        );
    }

    // One length-prefixed record containing "x" (APPNOTE 4.4.14.2).
    let mut archive = Fixture::member("file", 0, b"\x01\0\0\0x").build();
    set16(&mut archive.bytes, archive.central + 36, 0x0001); // Text only.
    Index::read(&mut Cursor::new(&archive.bytes)).await?;
    for attributes in [0x0002, 0x0003] {
        set16(&mut archive.bytes, archive.central + 36, attributes);
        assert!(matches!(
            Index::read(&mut Cursor::new(&archive.bytes)).await,
            Err(FrameError::Unsupported { position, feature: "record-oriented member" })
                if position == archive.central as u64
        ));
    }

    Ok(())
}

#[tokio::test]
async fn rejects_nonempty_deflate_member_with_zero_compressed_size_at_open() -> TestResult {
    let mut archive = Fixture {
        zip64: true,
        method: 8,
        payload: Some(Vec::new()),
        crc: Some(crc32(b"x")),
        ..Fixture::default()
    }
    .build();

    // Both ZIP64 extras end with the uncompressed size followed by the compressed size.
    let end = archive.zip64_end.ok_or("missing ZIP64 end")?;
    archive.bytes[archive.payload.start - 16] = 1;
    archive.bytes[end - 16] = 1;

    assert!(matches!(
        Index::read(&mut Cursor::new(archive.bytes)).await,
        Err(FrameError::Invalid { position, reason: "nonempty DEFLATE member has zero compressed size" })
            if position == archive.central as u64
    ));
    Ok(())
}

#[tokio::test]
async fn checks_extraction_versions_independently() -> TestResult {
    for (method, minimum) in [(0, 10), (8, 20)] {
        let archive = Fixture {
            method,
            ..Fixture::default()
        }
        .build();
        for (offset, position) in [(4, 0), (archive.central + 6, archive.central as u64)] {
            for (version, high_byte) in [
                (minimum - 1, 0),
                (minimum, 0),
                (45, 0),
                (46, 0),
                (19, 3),
                (20, 3),
                (46, 3),
            ] {
                let mut bytes = archive.bytes.clone();
                bytes[offset..offset + 2].copy_from_slice(&[version, high_byte]);
                let result = read_validated(&bytes).await;
                if version < minimum {
                    assert!(matches!(
                        result,
                        Err(FrameError::Invalid {
                            reason: "extraction version is too low",
                            position: actual,
                        }) if actual == position
                    ));
                } else if version > 45 {
                    assert!(matches!(
                        result,
                        Err(FrameError::Unsupported {
                            feature: "extraction version",
                            position: actual,
                        }) if actual == position
                    ));
                } else {
                    result?;
                }
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn rejects_optional_extras_by_default_even_alongside_zip64() -> TestResult {
    // Version 0 with an unknown method, opaque data, and a conflicting size.
    let mut security_descriptor = vec![0xff; 12];
    security_descriptor[4] = 0;
    for (identifier, local, directory) in [
        // With NTFS enabled, reserved bytes and timestamps may differ.
        (0x000a, ntfs_data(0), ntfs_data(0xff)),
        (0x000d, vec![0; 12], vec![0; 12]),
        (0x4453, security_descriptor, vec![0; 4]),
        (0x5455, vec![0], vec![0]),
        (0x5855, vec![0; 12], vec![0; 8]),
        (0x6375, unicode_data(b""), unicode_data(b"")),
        (0x7075, unicode_data(b"file"), unicode_data(b"file")),
        (0x7855, vec![0; 4], Vec::new()),
        (0x7875, vec![1, 1, 2, 1, 3], vec![1, 1, 2, 1, 3]),
        (0xcafe, Vec::new(), Vec::new()),
    ] {
        for (central, central_extra) in [(true, field(identifier, &directory)), (false, vec![])] {
            let archive = Fixture {
                zip64: true,
                local_extra: field(identifier, &local),
                central_extra,
                ..Fixture::default()
            }
            .build();
            let offset = if central { archive.central as u64 } else { 0 };
            let mut reader = Cursor::new(archive.bytes);
            let result = if central {
                Index::read(&mut reader).await.map(|_| ())
            } else {
                let mut index = Index::read(&mut reader).await?;
                index.entry(&mut reader, 0).await.map(|_| ())
            };
            assert!(
                matches!(
                    result,
                    Err(FrameError::PolicyViolation {
                        position,
                        violation: IndexPolicyViolation::ExtraField { identifier: rejected },
                    }) if position == offset && u16::from(rejected) == identifier
                ),
                "{identifier:#06x}, central={central}: {result:?}"
            );
            if central {
                read_validated_with(&mut reader, all_features()).await?;
            }
        }
    }

    for (fixture, expected) in [
        (
            Fixture::default().with_extra(false, field(0x000a, &ntfs_data(0)[..31])),
            "invalid NTFS extra field layout",
        ),
        (
            Fixture::default().with_extra(false, field(0x000d, &[0; 11])),
            "truncated UNIX extra field",
        ),
        (
            Fixture::default().with_extra(false, field(0x4453, &[0; 11])),
            "invalid NT security descriptor extra field layout",
        ),
        (
            Fixture {
                zip64: true,
                local_offset: u32::MAX,
                central_extra: field(0x000d, &[0; 12]),
                ..Fixture::default()
            },
            "missing or superfluous ZIP64 values",
        ),
    ] {
        let archive = fixture.build();
        let result = Index::read(&mut Cursor::new(archive.bytes)).await;
        assert!(
            matches!(
                result,
                Err(FrameError::Invalid { position, reason })
                    if position == archive.central as u64 && reason == expected
            ),
            "expected {expected}: {result:?}"
        );
    }

    let mut missing_size = Fixture {
        zip64: true,
        local_extra: field(0x000d, &[0; 12]),
        ..Fixture::default()
    }
    .build();
    set32(&mut missing_size.bytes, 18, 0);
    let mut reader = Cursor::new(missing_size.bytes);
    let mut index = Index::read(&mut reader).await?;
    assert!(matches!(
        index.entry(&mut reader, 0).await,
        Err(FrameError::Invalid {
            position: 0,
            reason: "local ZIP64 must contain both sizes",
        })
    ));
    Ok(())
}

#[test]
fn extra_header_id_sets_distinguish_all_known_identifiers() {
    let known: Vec<_> = (0..=u16::MAX)
        .filter_map(|raw| ExtraHeaderId::try_from(raw).ok())
        .collect();
    for &identifier in &known {
        let set = ExtraHeaderIdSet::from([identifier]);
        for &other in &known {
            assert_eq!(set.contains(other), identifier == other);
        }
    }
}

#[tokio::test]
async fn checks_every_optional_extra_against_the_allowlist() -> TestResult {
    let policy = |allowed| IndexPolicy::default().extra_field_policy(AllowListed(allowed));
    let archive = Fixture {
        zip64: true,
        ..Fixture::default()
    }
    .build();
    read_validated_with(&mut Cursor::new(archive.bytes), policy([].into())).await?;

    let timestamp = field(0x5455, &[0]);
    let archive = Fixture {
        local_extra: [timestamp.clone(), field(0xcafe, &[])].concat(),
        central_extra: timestamp,
        ..Fixture::default()
    }
    .build();
    let mut reader = Cursor::new(archive.bytes);
    for (allowed, rejected, offset) in [
        (JarMagic, ExtendedTimestamp, archive.central as u64),
        (ExtendedTimestamp, JarMagic, 0),
    ] {
        assert!(matches!(
            read_validated_with(&mut reader, policy([allowed].into())).await,
            Err(FrameError::PolicyViolation {
                position,
                violation: IndexPolicyViolation::ExtraField { identifier },
            }) if position == offset && identifier == rejected
        ));
    }
    read_validated_with(&mut reader, policy([ExtendedTimestamp, JarMagic].into())).await?;

    for (local, data) in [(true, &[0; 11][..]), (false, &[0; 4][..])] {
        let archive = Fixture::default()
            .with_extra(local, field(0x4453, data))
            .build();
        read_validated_with(
            &mut Cursor::new(archive.bytes),
            policy([NtfsSecurityDescriptor].into()),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn rejects_unsupported_extras_in_either_header() {
    for identifier in [
        0x0007, 0x0008, 0x000f, 0x0014, 0x0015, 0x0016, 0x0017, 0x0019, 0x2605, 0x6c78, 0x756e,
        0x9901, 0xbeef,
    ] {
        for local in [false, true] {
            let archive = Fixture::default()
                .with_extra(local, field(identifier, &[]))
                .build();
            let offset = if local { 0 } else { archive.central as u64 };
            for policy in [IndexPolicy::default(), all_features()] {
                let result = read_validated_with(&mut Cursor::new(&archive.bytes), policy).await;
                assert!(
                    matches!(
                        result,
                        Err(FrameError::UnsupportedExtraField { position, identifier: rejected })
                            if position == offset && rejected == identifier
                    ),
                    "{identifier:#06x}, local={local}: {result:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn permissive_policy_skips_only_unknown_field_contents() -> TestResult {
    let archive = |extra| {
        Fixture {
            local_extra: [field(0xbeef, b"local"), field(0x0007, &[]), extra].concat(),
            central_extra: [field(0xbeef, b"central"), field(0x000d, &[0; 12])].concat(),
            ..Fixture::default()
        }
        .build()
    };
    let mut reader = Cursor::new(archive(field(0x000d, &[0; 12])).bytes);
    let listed =
        IndexPolicy::default().extra_field_policy(AllowListed([ExtraHeaderId::Unix].into()));
    assert!(matches!(
        Index::read_with_policy(&mut reader, listed).await,
        Err(FrameError::UnsupportedExtraField {
            identifier: 0xbeef,
            ..
        })
    ));
    let permissive = IndexPolicy::default().extra_field_policy(Permissive);
    read_validated_with(&mut reader, permissive).await?;

    let invalid_descriptor = "invalid NT security descriptor extra field layout";
    for (extra, expected) in [
        (vec![0xad, 0xde, 1, 0], "truncated extra-field data"),
        (field(0xbeef, &[]), "duplicate extra-field identifier"),
        (field(0x000d, &[0; 11]), "truncated UNIX extra field"),
        (field(0x4453, &[0; 10]), invalid_descriptor),
        (field(0x4453, &[1; 11]), invalid_descriptor),
        (
            field(0x000d, &[1; 12]),
            "local and central extra fields disagree",
        ),
    ] {
        let mut reader = Cursor::new(archive(extra).bytes);
        let mut index = Index::read_with_policy(&mut reader, permissive).await?;
        let result = index.entry(&mut reader, 0).await;
        assert!(
            matches!(result, Err(FrameError::Invalid { position: 0, reason }) if reason == expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejects_empty_filename_when_indexing() {
    let archive = Fixture::member("", 0, b"payload").build();
    assert!(matches!(
        Index::read(&mut Cursor::new(archive.bytes)).await,
        Err(FrameError::Invalid {
            position,
            reason: "empty filename",
        }) if position == archive.central as u64
    ));
}

#[tokio::test]
async fn validates_utf8_and_unicode_path_extras() -> TestResult {
    let name = "café".as_bytes();
    let unicode = unicode_data(name);
    let fixture = Fixture {
        name: Some(name.to_vec()),
        local_extra: field(0x7075, &unicode),
        central_extra: field(0x7075, &unicode),
        ..Fixture::default()
    };

    assert_eq!(
        read_validated(&fixture.build().bytes).await?.entries()[0]
            .directory()
            .path(),
        "café"
    );

    for name in [
        vec![0xff],
        b"/absolute".to_vec(),
        b"C:/drive".to_vec(),
        b"nul\0name".to_vec(),
        "\u{feff}name".as_bytes().to_vec(),
    ] {
        assert!(
            read_validated(
                &Fixture {
                    name: Some(name),
                    ..Fixture::default()
                }
                .build()
                .bytes
            )
            .await
            .is_err()
        );
    }

    let malformed = Fixture::member("nul\0\\name", 0, b"payload").build();
    assert!(matches!(
        Index::read(&mut Cursor::new(malformed.bytes)).await,
        Err(FrameError::Invalid {
            position,
            reason: "invalid ZIP filename",
        }) if position == malformed.central as u64
    ));

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
            let fixture = Fixture {
                name: Some(name.to_vec()),
                ..Fixture::default()
            }
            .with_extra(local, field(0x7075, &value));
            assert!(
                read_validated(&fixture.build().bytes).await.is_err(),
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
            name: Some(original.to_vec()),
            flags: Some(0),
            local_extra: extra.clone(),
            central_extra: extra,
            ..Fixture::default()
        }
        .build();
        assert!(matches!(
            read_validated(&archive.bytes).await,
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
                name: Some(name.to_vec()),
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
            let mut index = Index::read(&mut source).await?;
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
            read_validated_with(&mut Cursor::new(&bytes), all_features().limits(limits)).await,
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
                Index::read_with_policy(&mut source, IndexPolicy::default().limits(limits)).await,
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
                read_validated(&archive.bytes[..length]).await.is_err(),
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
                read_validated(&bytes).await.is_err(),
                "offset {offset}, zip64={zip64}"
            );
        }

        let mut bytes = archive.bytes;
        bytes.push(0);

        assert!(read_validated(&bytes).await.is_err());
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
            let fields = archive.payload.end + if signed { 4 } else { 0 };
            let mut corrupt_offsets = vec![fields, fields + 4, archive.central - 1];
            if signed {
                corrupt_offsets.push(archive.payload.end);
            }
            for offset in corrupt_offsets {
                let mut bytes = archive.bytes.clone();
                bytes[offset] ^= 1;
                let mut source = Cursor::new(bytes);
                let mut index = Index::read_with_policy(&mut source, all_features()).await?;
                assert!(
                    matches!(
                        index.entry(&mut source, 0).await,
                        Err(FrameError::Invalid {
                            position,
                            reason: "invalid data descriptor signature" | "data descriptor disagrees with central header",
                        }) if position == archive.payload.end as u64
                    ),
                    "zip64={zip64}, signed={signed}, offset={offset}"
                );
                assert!(index.resolved(0).is_none());
            }

            let descriptor = &archive.bytes[archive.payload.end..archive.central];
            for length in [0, descriptor.len() - 1, descriptor.len() + 1] {
                // Rebuild the directory and footer so only the descriptor's span
                // is wrong; truncating the whole archive would test its footer.
                let mut bytes = archive.bytes[..archive.payload.end].to_vec();
                bytes.extend_from_slice(&descriptor[..length.min(descriptor.len())]);
                bytes.resize(archive.payload.end + length, 0);
                let central = bytes.len();
                bytes.extend_from_slice(
                    &archive.bytes[archive.central..archive.zip64_end.unwrap_or(archive.end)],
                );
                let size = bytes.len() - central;
                bytes.extend(end_record(1, central as u32, size as u32, &[]));
                assert!(
                    matches!(
                        read_validated(&bytes).await,
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
async fn checks_the_member_comment_encoding_flag() {
    let utf8 = "café".as_bytes();
    for (comment, per_member, flags, accepted) in [
        (b"zip".as_slice(), AllowUtf8, 0, true),
        (utf8, AllowUtf8, 0, false),
        (utf8, AllowUtf8, 0x0800, true),
        (b"\xff", AllowAll, 0, true),
        (b"\xff", AllowAll, 0x0800, false),
        (b"\xff", Reject, 0x0800, false),
    ] {
        let archive = Fixture {
            flags: Some(flags),
            member_comment: comment.into(),
            ..Fixture::default()
        }
        .build();
        let policy = IndexPolicy::default().comment_policy(CommentPolicy {
            per_member,
            ..CommentPolicy::default()
        });
        let mut source = Cursor::new(archive.bytes);
        let result = Index::read_with_policy(&mut source, policy).await;
        let expected = if accepted {
            result.is_ok()
        } else if flags == 0x0800 && str::from_utf8(comment).is_err() {
            matches!(
                result,
                Err(FrameError::Invalid { position, reason: "non-UTF-8 comment" })
                    if position == archive.central as u64
            )
        } else {
            matches!(
                result,
                Err(FrameError::PolicyViolation {
                    position,
                    violation: IndexPolicyViolation::MemberComment { rule },
                }) if position == archive.central as u64 && rule == per_member
            )
        };
        assert!(expected, "{per_member:?}, flags={flags:#x}: {result:?}");
    }
}

#[tokio::test]
async fn reconciles_unicode_comment_extra_fields() -> TestResult {
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
        let mut source = Cursor::new(archive.bytes);
        let result = Index::read_with_policy(&mut source, all_features()).await;
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
        let result = read_validated(&archive.bytes).await;
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

    assert!(read_validated(&empty).await?.entries().is_empty());

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
            Index::read(&mut Cursor::new(archive.bytes)).await,
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
            Index::read(&mut Cursor::new(bytes)).await,
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
    let mut index = Index::read(&mut source).await?;
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
                Index::read(&mut Cursor::new(&archive.bytes))
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
                Index::read(&mut Cursor::new(archive.bytes)).await,
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
            read_validated_with(&mut source, all_features())
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
        Index::read(&mut source).await,
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
            Index::read(&mut Cursor::new(bytes)).await,
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

        let index = read_validated(&fixture.build().bytes).await?;

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
                    local_extra: local_extra.clone(),
                    central_extra: central_extra.clone(),
                    ..Fixture::member("file", attributes, payload)
                }
                .build();
                assert!(matches!(
                    read_validated(&archive.bytes).await,
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
            read_validated(&fixture.build().bytes).await,
            Err(FrameError::Invalid { reason, .. }) if reason == expected
        ));
    }

    Ok(())
}

#[tokio::test]
async fn validates_ntfs_timestamp_layout_in_each_header() -> TestResult {
    let policy =
        IndexPolicy::default().extra_field_policy(AllowListed([Ntfs, ExtendedTimestamp].into()));
    let extras = [field(0x000a, &ntfs_data(0)), field(0x5455, &[1; 5])].concat();
    for local in [false, true] {
        let archive = Fixture::default().with_extra(local, extras.clone()).build();
        read_validated_with(&mut Cursor::new(archive.bytes), policy).await?;
    }

    let policy = IndexPolicy::default().extra_field_policy(Permissive);
    for (length, tag, size) in [(36, 1, 24), (32, 2, 24), (32, 1, 16)] {
        let mut data = vec![0; length];
        set16(&mut data, 4, tag);
        set16(&mut data, 6, size);
        let archive = Fixture::default()
            .with_extra(true, field(0x000a, &data))
            .build();
        let mut reader = Cursor::new(archive.bytes);
        let mut index = Index::read_with_policy(&mut reader, policy).await?;
        assert!(matches!(
            index.entry(&mut reader, 0).await,
            Err(FrameError::Invalid {
                position: 0,
                reason: "invalid NTFS extra field layout"
            })
        ));
    }
    Ok(())
}

#[tokio::test]
async fn reconciles_unix_extra_fields() -> TestResult {
    // Four-byte tags distinguish the timestamps. PKWARE stores each ID in two bytes.
    let prefix = b"atimmtimu\0g\0";
    let unix = || field(0x000d, prefix);
    let padded_owner = &[1, 1, b'u', 3, b'g', 0, 0];
    for (identifier, local, central) in [
        (0x5855, &prefix[..], &b"diffdiff"[..]),
        (0x5855, &prefix[..8], &prefix[..8]),
        (0x5455, b"\x03diffdiff", b"\x01mtim"),
        (0x5455, b"\x02atim", b"\x02"),
        (0x5455, b"\x07mtimatimctim", b"\x07mtim"),
        (0x7855, &prefix[8..], &[]),
        (0x7875, padded_owner, padded_owner),
    ] {
        let archive = Fixture {
            local_extra: field(identifier, local),
            central_extra: [unix(), field(identifier, central)].concat(),
            ..Fixture::default()
        }
        .build();
        read_validated(&archive.bytes).await?;
    }

    // The central-only extended timestamp may disagree with both older formats.
    let archive = Fixture {
        local_extra: field(0x000d, b"diffdiffu\0g\0"),
        central_extra: [
            unix(),
            field(0x5855, &prefix[..8]),
            field(0x5455, b"\x01time"),
        ]
        .concat(),
        ..Fixture::default()
    }
    .build();
    read_validated(&archive.bytes).await?;

    let bad_layout = "invalid Info-ZIP extra field layout";
    let conflict = "conflicting UNIX metadata in extra fields";
    for (local, central, expected) in [
        (field(0x5855, &[1; 12]), field(0x5855, &[1; 7]), bad_layout),
        (field(0x5855, &[1; 10]), vec![], bad_layout),
        (field(0x5455, &[3; 9]), field(0x5455, &[3]), bad_layout),
        (field(0x5455, &[8; 5]), vec![], bad_layout),
        (
            field(0x5455, &[]),
            vec![],
            "missing Info-ZIP timestamp flags",
        ),
        (field(0x7855, &[1; 4]), field(0x7855, &[1; 4]), bad_layout),
        (field(0x7855, &[1; 2]), vec![], bad_layout),
        (
            vec![],
            field(0x7855, &[]),
            "central Info-ZIP field has no local copy",
        ),
        (field(0x5855, b"atimmtimu\0x\0"), unix(), conflict),
        (
            [unix(), field(0x7855, b"u\0x\0")].concat(),
            vec![],
            conflict,
        ),
        (
            unix(),
            field(0x7875, &[1, 3, b'u', 0, 1, 1, b'g']),
            conflict,
        ),
        (unix(), field(0x7875, &[1, 1, b'u', 1, b'x']), conflict),
    ] {
        let archive = Fixture {
            local_extra: local,
            central_extra: central,
            ..Fixture::default()
        }
        .build();
        assert!(
            matches!(
                read_validated(&archive.bytes).await,
                Err(FrameError::Invalid { reason, .. }) if reason == expected
            ),
            "{expected}"
        );
    }

    // Reject conflicting ownership in the directory before reading the local header.
    let central = [unix(), field(0x7875, &[1, 1, b'u', 1, b'x'])].concat();
    let archive = Fixture::default().with_extra(false, central).build();
    assert!(matches!(
        Index::read_with_policy(&mut Cursor::new(archive.bytes), all_features()).await,
        Err(FrameError::Invalid { position, reason }) if position == archive.central as u64 && reason == conflict
    ));
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
        read_validated(&archive.bytes).await?;
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
            let fixture = Fixture::default().with_extra(local, field(0x7875, data));
            assert!(
                matches!(
                    read_validated(&fixture.build().bytes).await,
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
            read_validated(&archive.bytes).await,
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
        name: Some(b"next".to_vec()),
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
    let mut index = Index::read_with_policy(&mut source, all_features()).await?;

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
    // Even an unselected member with a Stored descriptor must fail at open.
    assert!(matches!(
        Index::read_with_policy(&mut source, IndexPolicy::default().extra_field_policy(AllowKnown)).await,
        Err(FrameError::PolicyViolation {
            position,
            violation: IndexPolicyViolation::StoredDataDescriptor,
        }) if position == (central + first.end - first.central) as u64
    ));
    let mut ordered = Index::read_with_policy(&mut source, all_features()).await?;
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
        Index::read_with_policy(&mut Cursor::new(shared), all_features())
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

    assert!(read_validated(&unindexed).await.is_err());

    Ok(())
}

#[tokio::test]
async fn duplicate_destinations_must_preserve_local_order() -> TestResult {
    let mut local = Vec::new();
    let mut members = Vec::new();
    for path in [
        "d/config",
        "./d//./config/",
        "d/config",
        "d/Config",
        "d/../d/config",
    ] {
        let kind = if path.ends_with('/') {
            WriteEntryKind::Directory
        } else {
            WriteEntryKind::File { executable: false }
        };
        let offset = local.len() as u64;
        let member =
            PendingMember::new(path, CompressionMethod::Stored, kind)?.finish(0, 0, 0, offset)?;
        local.extend(member.local_header());
        members.push((offset, member.central_header()));
    }

    // The first three members share a destination. The last two can move freely.
    for (order, backwards) in [
        ([0, 1, 2, 3, 4], None),
        ([4, 3, 0, 1, 2], None),
        ([0, 2, 3, 4, 1], Some(1)),
        ([2, 0, 1, 3, 4], Some(0)),
    ] {
        let mut bytes = local.clone();
        for index in order {
            bytes.extend_from_slice(&members[index].1);
        }
        bytes.extend(end_records(
            members.len() as u64,
            local.len() as u64,
            (bytes.len() - local.len()) as u64,
        )?);

        let mut source = Cursor::new(bytes);
        let result = Index::read(&mut source).await;
        if let Some(index) = backwards {
            assert!(
                matches!(
                    result,
                    Err(FrameError::Invalid { position, reason: "duplicate destination order disagrees with local headers" })
                        if position == members[index].0
                ),
                "{order:?}"
            );
        } else {
            result?.validate_all(&mut source).await?;
        }
    }
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

    let mut index = Index::read(&mut source).await?;
    let opening_bytes = source.bytes_read;
    index.validate_all(&mut source).await?;
    assert_eq!(source.bytes_read - opening_bytes, source.prefix.len());
    assert_eq!(index.entries()[0].directory().size(), size);
    assert_eq!(index.entries()[0].directory().compressed_size(), size);
    assert!(source.bytes_read < 70_000);

    Ok(())
}

#[tokio::test]
async fn indexes_counts_at_and_above_the_classic_limit() -> TestResult {
    for count in [u64::from(u16::MAX), u64::from(u16::MAX) + 2] {
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
        if let Ok(classic_count) = u16::try_from(count) {
            bytes.extend(end_record(
                classic_count,
                offset.try_into()?,
                size.try_into()?,
                &[],
            ));
        } else {
            bytes.extend(end_records(count, offset, size)?);
        }
        let mut source = Cursor::new(bytes);
        let mut index = Index::read(&mut source).await?;
        assert_eq!(index.entries().len() as u64, count);
        // Include the entries across the classic count boundary in the ZIP64 case.
        for ordinal in [count - 1, count - 2, count - 3, 0] {
            let entry = index
                .entry(&mut source, ordinal as usize)
                .await?
                .ok_or("missing entry")?;
            assert_eq!(entry.directory().path(), format!("{ordinal}.txt"));
            assert_eq!(entry.directory().size(), 0);
        }
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
        field(0xcafe, &[0]),
        field(0x000a, &ntfs_data(0)).repeat(2),
        [field(0x5455, &[0]), field(0x5455, &[0])].concat(),
    ] {
        for local in [false, true] {
            let fixture = Fixture::default().with_extra(local, extra.clone());

            assert!(
                read_validated(&fixture.build().bytes).await.is_err(),
                "extra {extra:?}, local={local}"
            );
        }
    }

    // An inline ZIP64 field must still reject a later duplicate, including
    // when the first field is empty or another identifier separates the two.
    for data in [&[][..], &[0; 16][..]] {
        for local in [false, true] {
            let extra = [field(1, data), field(0x5455, &[0])].concat();
            let fixture = Fixture {
                zip64: true,
                ..Fixture::default()
            }
            .with_extra(local, extra);
            assert!(matches!(
                read_validated(&fixture.build().bytes).await,
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
        read_validated(&archive.bytes).await,
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
            Index::read(&mut Cursor::new(archive.bytes)).await,
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
    let total_budget = directory_budget + (archive.central - archive.payload.len()) as u64;
    // Directory, ZIP64 end, and local metadata share one cumulative budget.
    for metadata_size in [total_budget - 1, total_budget] {
        let mut source = Cursor::new(&archive.bytes);
        let mut index = Index::read_with_policy(
            &mut source,
            IndexPolicy::default().limits(Limits {
                metadata_size,
                ..Limits::default()
            }),
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
        Index::read_with_policy(
            &mut Cursor::new(archive.bytes),
            IndexPolicy::default().limits(Limits {
                metadata_size: directory_budget - 1,
                ..Limits::default()
            }),
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
            name: Some(format!("file-{ordinal}").into_bytes()),
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
    let mut index = Index::read(&mut source).await?;
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
            name: Some(name.as_bytes().to_vec()),
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
    let mut index = Index::read_with_policy(&mut source, all_features()).await?;
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
        name: Some(name),
        local_extra: extra.clone(),
        central_extra: extra,
        ..Fixture::default()
    }
    .build();
    let exact_budget = (archive.end - archive.payload.len()) as u64;

    for (budget, valid) in [(exact_budget - 1, false), (exact_budget, true)] {
        let mut source = Observed::new(archive.bytes.clone());
        let mut index = Index::read_with_policy(
            &mut source,
            IndexPolicy::default()
                .limits(Limits {
                    metadata_size: budget,
                    ..Limits::default()
                })
                .extra_field_policy(AllowKnown),
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
