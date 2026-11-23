pub mod support;

use std::{
    error::Error,
    io,
    ops::Range,
    pin::pin,
    task::{Context, Poll, Waker},
};

use support::{
    ArchiveBuilder, ArchiveFormat, header, pax_record, raw_pax_record, set_checksum,
    single_pax_member,
};
use tar_codec::{
    Archive as _, DecodeError, DecodePolicy, DecodePolicyViolation, Member, MemberPayload,
    PaxDecodePolicy, SpecialKind, TarArchive, TrailingDataPolicy,
};
use tar_framing::{
    BLOCK_SIZE, Block, FrameError, FrameErrorInner, GnuKind, PaxError, PaxKeyword, StreamPolicy,
    header::{GID_RANGE, GNAME_RANGE, MODE_RANGE, MTIME_RANGE, UID_RANGE, UNAME_RANGE},
    logical::{MemberExtensions, TarReader},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

type TestResult = Result<(), Box<dyn Error>>;

async fn read_payload<P: MemberPayload<Error = DecodeError>>(
    mut payload: P,
) -> Result<Vec<u8>, DecodeError> {
    let mut data = Vec::new();
    let mut chunk = Vec::new();
    while payload.next_chunk(&mut chunk, 3).await? {
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

#[tokio::test]
async fn trailing_zero_padding_stops_at_the_record_boundary() -> TestResult {
    // An empty archive ends at block two. A third zero block is optional padding.
    let bytes = [0; 20 * BLOCK_SIZE + 1];
    let mut short_record = TarArchive::new(&bytes[..3 * BLOCK_SIZE]);
    assert!(short_record.next_member().await?.is_none());
    let with_trailing = |policy| DecodePolicy::default().trailing_data_policy(policy);
    for (policy, blocks) in [
        (DecodePolicy::default(), 20),
        (with_trailing(TrailingDataPolicy::BlockingFactor(0)), 2),
        (with_trailing(TrailingDataPolicy::BlockingFactor(2)), 2),
        (with_trailing(TrailingDataPolicy::BlockingFactor(3)), 3),
        (with_trailing(TrailingDataPolicy::Strict), 2),
    ] {
        let boundary = blocks * BLOCK_SIZE;
        let mut valid = TarArchive::new(&bytes[..boundary]).with_policy(policy.clone());
        assert!(valid.next_member().await?.is_none(), "{policy:?}");
        let mut excess = TarArchive::new(&bytes[..=boundary]).with_policy(policy);
        assert!(matches!(
            excess.next_member().await,
            Err(DecodeError::Framing(FrameError {
                position,
                inner: FrameErrorInner::TrailingData,
            })) if position == boundary as u64
        ));
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_trailing_padding_read_preserves_the_partial_block() -> TestResult {
    let bytes = [0; 3 * BLOCK_SIZE + 1];
    let (reader, mut writer) = duplex(bytes.len());
    writer.write_all(&bytes).await?;
    let mut members = TarArchive::new(reader).members();
    let mut context = Context::from_waker(Waker::noop());
    assert!(pin!(members.next()).poll(&mut context).is_pending());
    // A retry must account for the first byte of the unfinished padding block.
    drop(writer);
    assert!(matches!(
        members.next().await,
        Err(DecodeError::Framing(FrameError {
            position,
            inner: FrameErrorInner::IncompleteBlock { read: 1 },
        })) if position == (3 * BLOCK_SIZE) as u64
    ));
    Ok(())
}

#[tokio::test]
async fn trailing_nonzero_byte_fails_before_eof() -> TestResult {
    let mut bytes = [0; 3 * BLOCK_SIZE + 8];
    bytes[3 * BLOCK_SIZE + 7] = 1;
    let (reader, mut writer) = duplex(bytes.len());
    writer.write_all(&bytes).await?;
    let mut archive = TarArchive::new(reader);
    assert!(matches!(
        pin!(archive.next_member()).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(DecodeError::Framing(FrameError {
            position,
            inner: FrameErrorInner::TrailingData,
        }))) if position == (3 * BLOCK_SIZE + 7) as u64
    ));
    assert!(matches!(
        archive.next_member().await,
        Err(DecodeError::Poisoned)
    ));
    Ok(())
}

#[tokio::test]
async fn ignoring_trailing_data_leaves_the_reader_at_the_marker() -> TestResult {
    let next_archive = single_pax_member("next", b'0', b"", "", 0o644);
    let mut bytes = ArchiveBuilder::new().finish();
    bytes.extend_from_slice(&next_archive);
    let mut unread = bytes.as_slice();
    let mut archive = TarArchive::new(&mut unread)
        .with_policy(DecodePolicy::default().trailing_data_policy(TrailingDataPolicy::Ignore));
    for _ in 0..2 {
        assert!(archive.next_member().await?.is_none());
    }
    assert_eq!(unread, next_archive);
    Ok(())
}

#[tokio::test]
async fn projects_every_member_kind_and_streams_payloads() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("file", b'0', b"contents", "", 0o755)
        .ustar("contiguous", b'7', b"contiguous", "", 0o644)
        .ustar("directory", b'5', b"", "", 0o755)
        .ustar("symbolic", b'2', b"", "file", 0o777)
        .ustar("hard", b'1', b"", "file", 0o644)
        .ustar("character", b'3', b"", "", 0o644)
        .ustar("block", b'4', b"", "", 0o644)
        .ustar("fifo", b'6', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    let Some(Member::File {
        metadata,
        size,
        executable,
        payload,
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected regular file member").into());
    };
    assert_eq!(metadata.path, "file");
    assert_eq!(metadata.position, 0);
    assert_eq!(size, 8);
    assert!(executable);
    assert_eq!(read_payload(payload).await?, b"contents");

    let Some(Member::File {
        metadata, payload, ..
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected contiguous file member").into());
    };
    assert_eq!(metadata.path, "contiguous");
    assert_eq!(read_payload(payload).await?, b"contiguous");

    assert!(matches!(
        members.next().await?,
        Some(Member::Directory { metadata }) if metadata.path == "directory"
    ));
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink {
            metadata,
            target,
        }) if metadata.path == "symbolic" && target == "file"
    ));

    let Some(Member::HardLink {
        metadata,
        target,
        size,
        payload,
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected hard-link member").into());
    };
    assert_eq!(metadata.path, "hard");
    assert_eq!(target, "file");
    assert_eq!(size, 0);
    assert!(read_payload(payload).await?.is_empty());

    for (path, kind) in [
        ("character", SpecialKind::CharacterDevice),
        ("block", SpecialKind::BlockDevice),
        ("fifo", SpecialKind::Fifo),
    ] {
        assert!(matches!(
            members.next().await?,
            Some(Member::Special {
                metadata,
                kind: actual,
            }) if metadata.path == path && actual == kind
        ));
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn rejects_pax_sizes_with_leading_zeros() {
    for (typeflag, size) in [(b'x', "0777"), (b'g', "00")] {
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(typeflag, &pax_record(PaxKeyword::Size, size))
            .ustar("a", b'0', b"", "", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            TarArchive::new(bytes.as_slice()).members().next().await,
            Err(DecodeError::Framing(FrameError {
                position: 0,
                inner: FrameErrorInner::InvalidPaxRecord {
                    source: PaxError::InvalidInteger { keyword: "size", value },
                },
            })) if value == size
        ));
    }
}

/// In tar-minefield F34 and F35, the hard-link payload is itself a valid member header.
#[tokio::test]
async fn pax_hard_link_payloads_require_opt_in() -> TestResult {
    let policy = DecodePolicy::default()
        .pax_policy(PaxDecodePolicy::default().allow_hardlink_linkdata(true));
    let linkdata = header(ArchiveFormat::Pax, "smuggled", b'0', 0, "", 0o644);
    let mut header_size = ArchiveBuilder::new();
    header_size.ustar("link", b'1', &linkdata, "target", 0o644);
    let mut pax_size = ArchiveBuilder::new();
    pax_size
        .pax(b'x', &pax_record(PaxKeyword::Size, "512"))
        .ustar("link", b'1', b"", "target", 0o644)
        .block(&linkdata);

    for mut archive in [header_size, pax_size] {
        archive.ustar("after", b'0', b"", "", 0o644);
        let bytes = archive.finish();
        assert!(matches!(
            TarArchive::new(bytes.as_slice()).members().next().await,
            Err(DecodeError::Framing(FrameError {
                inner: FrameErrorInner::InvalidMemberSize { .. },
                ..
            }))
        ));

        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(policy.clone())
            .members();
        let Some(Member::HardLink { payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected hard-link member").into());
        };
        assert_eq!(read_payload(payload).await?, linkdata);
        assert!(matches!(
            members.next().await?,
            Some(Member::File { metadata, .. }) if metadata.path == "after"
        ));
    }
    Ok(())
}

const NUMERIC_FIELDS: [(&str, Range<usize>); 4] = [
    ("mode", MODE_RANGE),
    ("uid", UID_RANGE),
    ("gid", GID_RANGE),
    ("mtime", MTIME_RANGE),
];

/// Edits the file header (`0`) or its preceding pax header (`x` or `g`).
fn edited_pax_member(typeflag: u8, edit: impl FnOnce(&mut Block)) -> Vec<u8> {
    let mut archive = ArchiveBuilder::new();
    if typeflag != b'0' {
        archive.pax(typeflag, &pax_record(PaxKeyword::Comment, "metadata"));
    }
    archive.ustar("file", b'0', b"", "", 0o755);
    let mut bytes = archive.finish();
    let block = bytes.first_chunk_mut().expect("archive contains a header");
    edit(block);
    set_checksum(block);
    bytes
}

#[tokio::test]
async fn pax_extension_headers_reject_invalid_numeric_fields() -> TestResult {
    let prefix = header(ArchiveFormat::Pax, "prefix", b'0', 0, "", 0o644);
    for &typeflag in b"xg" {
        for (field, range) in NUMERIC_FIELDS {
            let bytes = edited_pax_member(typeflag, |block| block[range.start + 4] = b'8');
            let mut members = TarArchive::new(prefix.as_slice().chain(bytes.as_slice())).members();
            assert!(matches!(
                members.next().await?,
                Some(Member::File { metadata, .. }) if metadata.path == "prefix"
            ));
            assert!(matches!(
                members.next().await,
                Err(DecodeError::Framing(FrameError {
                    position,
                    inner: FrameErrorInner::InvalidNumericField { field: invalid, .. },
                })) if position == BLOCK_SIZE as u64 && invalid == field
            ));
        }
    }
    Ok(())
}

#[tokio::test]
async fn pax_extension_headers_allow_absent_numeric_fields_under_strict_policy() -> TestResult {
    for &typeflag in b"xg" {
        let bytes = edited_pax_member(typeflag, |block| {
            for (_, range) in NUMERIC_FIELDS {
                block[range].fill(0);
            }
        });
        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(DecodePolicy::default().allow_all_nul_numeric_fields(false))
            .members();
        assert!(matches!(members.next().await?, Some(Member::File { .. })));
    }
    Ok(())
}

#[tokio::test]
async fn all_nul_numeric_fields_are_policy_controlled() -> TestResult {
    let strict_policy = DecodePolicy::default().allow_all_nul_numeric_fields(false);

    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        for (field, range) in NUMERIC_FIELDS {
            let path = format!("empty-{format:?}-{field}");
            let mut block = header(format, &path, b'0', 0, "", 0o644);
            block[range].fill(0);
            set_checksum(&mut block);

            let mut archive = ArchiveBuilder::new();
            archive.block(&block);
            let bytes = archive.finish();
            {
                let mut members = TarArchive::new(bytes.as_slice()).members();
                assert!(matches!(
                    members.next().await?,
                    Some(Member::File {
                        metadata,
                        executable: false,
                        ..
                    }) if metadata.path == path
                ));
                assert!(members.next().await?.is_none());
            }

            let mut members = TarArchive::new(bytes.as_slice())
                .with_policy(strict_policy.clone())
                .members();
            assert!(
                matches!(members.next().await, Err(DecodeError::Framing(_))),
                "strict policy should reject an all-NUL {format:?} {field} field"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn base256_uid_and_gid_are_policy_controlled() -> TestResult {
    // Only the ordinary header supplies the member's metadata.
    for (typeflag, uid, gid, mtime) in [
        (b'0', 241_306_344, 1_954_207_199, 3),
        (b'x', 0, 0, 0),
        (b'g', 0, 0, 0),
    ] {
        let bytes = edited_pax_member(typeflag, |block| {
            block[UID_RANGE].copy_from_slice(&[0x80, 0, 0, 0, 0x0e, 0x62, 0x0a, 0xe8]);
            block[GID_RANGE].copy_from_slice(&[0x80, 0, 0, 0, 0x74, 0x7a, 0xd5, 0xdf]);
            block[MTIME_RANGE].copy_from_slice(b"00000000003\0");
        });

        let mut members = TarArchive::new(bytes.as_slice()).members();
        assert!(matches!(
            members.next().await,
            Err(DecodeError::Framing(FrameError {
                inner: FrameErrorInner::InvalidNumericField { field: "uid", .. },
                ..
            }))
        ));

        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_base256_uid_and_gid(true)),
            )
            .members();
        assert!(matches!(members.next().await?, Some(Member::File { .. })));
        assert!(members.next().await?.is_none());

        let mut reader = TarReader::new(bytes.as_slice())
            .with_policy(StreamPolicy::default().allow_pax_base256_uid_and_gid(true));
        let member = reader.next_frame().await?.expect("expected file member");
        assert_eq!(member.header.mode, Some(0o755));
        assert_eq!(member.header.uid, Some(uid));
        assert_eq!(member.header.gid, Some(gid));
        assert_eq!(member.header.mtime, Some(mtime));
        assert!(reader.next_frame().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn base256_uid_and_gid_policy_keeps_other_pax_numeric_fields_octal() -> TestResult {
    for (field, range) in [("mode", MODE_RANGE), ("mtime", MTIME_RANGE)] {
        let bytes = edited_pax_member(b'0', |block| {
            block[range.clone()].fill(0);
            block[range.start] = 0x80;
        });
        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(
                DecodePolicy::default()
                    .pax_policy(PaxDecodePolicy::default().allow_base256_uid_and_gid(true)),
            )
            .members();
        assert!(
            matches!(members.next().await, Err(DecodeError::Framing(_))),
            "base-256 {field} field should be rejected"
        );
    }
    Ok(())
}

#[tokio::test]
async fn unterminated_owner_names_are_policy_controlled() -> TestResult {
    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        for (field, range) in [("uname", UNAME_RANGE), ("gname", GNAME_RANGE)] {
            let mut block = header(format, "file", b'0', 0, "", 0o644);
            block[range].fill(b'n');
            set_checksum(&mut block);

            let mut archive = ArchiveBuilder::new();
            archive.block(&block);
            let bytes = archive.finish();

            let mut members = TarArchive::new(bytes.as_slice()).members();
            assert!(matches!(
                members.next().await,
                Err(DecodeError::Framing(FrameError {
                    inner: FrameErrorInner::UnterminatedUstarStringField { field: found },
                    ..
                })) if found == field
            ));

            let mut members = TarArchive::new(bytes.as_slice())
                .with_policy(
                    DecodePolicy::default().allow_header_uname_and_gname_without_terminator(true),
                )
                .members();
            assert!(matches!(members.next().await?, Some(Member::File { .. })));
            assert!(members.next().await?.is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn unterminated_owner_names_preserve_all_bytes() -> TestResult {
    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        let mut block = header(format, "file", b'0', 0, "", 0o644);
        block[UNAME_RANGE].fill(b'u');
        block[GNAME_RANGE].fill(b'g');
        set_checksum(&mut block);

        let mut archive = ArchiveBuilder::new();
        archive.block(&block);
        let bytes = archive.finish();
        let mut reader = TarReader::new(bytes.as_slice()).with_policy(
            StreamPolicy::default().allow_header_uname_and_gname_without_terminator(true),
        );
        let member = reader.next_frame().await?.expect("expected file member");
        assert_eq!(member.header.uname, &[b'u'; 32]);
        assert_eq!(member.header.gname, &[b'g'; 32]);
        assert!(reader.next_frame().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn unterminated_gnu_extensions_are_policy_controlled() -> TestResult {
    for (typeflag, kind, expected_path, expected_target) in [
        (b'L', GnuKind::LongName, "long/value", "raw-target"),
        (b'K', GnuKind::LongLink, "raw", "long/value"),
    ] {
        let mut archive = ArchiveBuilder::new();
        archive
            .gnu("extension", typeflag, b"long/value", "", 0o644)
            .gnu("raw", b'2', b"", "raw-target", 0o644);
        let bytes = archive.finish();

        let mut members = TarArchive::new(bytes.as_slice()).members();
        assert!(matches!(
            members.next().await,
            Err(DecodeError::Framing(FrameError {
                inner: FrameErrorInner::InvalidGnuExtension { kind: found, .. },
                ..
            })) if found == kind
        ));

        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(DecodePolicy::default().allow_gnu_extensions_without_terminator(true))
            .members();
        let Some(Member::SymbolicLink { metadata, target }) = members.next().await? else {
            return Err(io::Error::other("expected symbolic link member").into());
        };
        assert_eq!(metadata.path, expected_path);
        assert_eq!(target, expected_target);
        assert!(members.next().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn validates_detached_gnu_extensions_with_the_selected_policy() -> TestResult {
    let long_name = [b'n'; BLOCK_SIZE];
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', &long_name, "", 0o644)
        .gnu("longlink", b'K', b"link\0bad", "", 0o644)
        .gnu("raw", b'2', b"", "", 0o644);
    let bytes = archive.finish();
    let mut reader = TarReader::new(bytes.as_slice());
    let member = reader.next_frame().await?.expect("expected link member");
    let MemberExtensions::Gnu {
        long_name: Some(name),
        long_link: Some(link),
    } = member.extensions
    else {
        return Err(io::Error::other("expected both GNU extensions").into());
    };
    assert!(reader.next_frame().await?.is_none());
    let policy = StreamPolicy::default().allow_gnu_extensions_without_terminator(true);
    assert_eq!(name.value(GnuKind::LongName, &policy)?, long_name);
    assert!(matches!(
        link.value(GnuKind::LongLink, &policy),
        Err(FrameError {
            position,
            inner: FrameErrorInner::InvalidGnuExtension {
                kind: GnuKind::LongLink,
                ..
            },
        }) if position == (2 * BLOCK_SIZE) as u64
    ));
    Ok(())
}

#[tokio::test]
async fn resolves_format_metadata_but_leaves_extraction_paths_raw() -> TestResult {
    let records = [
        pax_record(PaxKeyword::Path, "../effective"),
        pax_record(PaxKeyword::LinkPath, "../target"),
    ]
    .concat();
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &records)
        .ustar("raw", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink { metadata, target })
            if metadata.path == "../effective" && target == "../target"
    ));

    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"effective\0", "", 0o644)
        .gnu("longlink", b'K', b"target\0", "", 0o644)
        .gnu("raw", b'2', b"", "ignored", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    assert!(matches!(
        members.next().await?,
        Some(Member::SymbolicLink { metadata, target })
            if metadata.path == "effective" && target == "target"
    ));
    Ok(())
}

#[tokio::test]
async fn advancing_drains_payload_and_applies_tar_policy() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .ustar("first", b'0', &[b'a'; 1024], "", 0o644)
        .ustar("second", b'0', b"next", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    {
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected first file member").into());
        };
        let mut chunk = Vec::new();
        assert!(payload.next_chunk(&mut chunk, 1).await?);
    }
    let Some(Member::File { payload, .. }) = members.next().await? else {
        return Err(io::Error::other("expected second file member").into());
    };
    assert_eq!(read_payload(payload).await?, b"next");

    let mut archive = ArchiveBuilder::new();
    archive.ustar("truncated", b'0', &[b'x'; 1024], "", 0o644);
    let mut bytes = archive.finish();
    bytes.truncate(1025);
    let mut members = TarArchive::new(bytes.as_slice()).members();
    {
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected truncated file member").into());
        };
        let mut chunk = Vec::new();
        assert!(payload.next_chunk(&mut chunk, 1).await?);
    }
    assert!(matches!(members.next().await, Err(DecodeError::Framing(_))));

    let mut archive = ArchiveBuilder::new();
    archive.gnu("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(DecodePolicy::default().allow_gnu(false))
        .members();
    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation { .. })
    ));

    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record(PaxKeyword::Comment, "metadata"))
        .ustar("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(
            DecodePolicy::default().pax_policy(PaxDecodePolicy::default().max_extension_size(1)),
        )
        .members();
    assert!(matches!(members.next().await, Err(DecodeError::Framing(_))));
    Ok(())
}

#[tokio::test]
async fn payload_chunk_preflight_errors_poison_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &pax_record(PaxKeyword::Size, &u64::MAX.to_string()))
        .ustar("oversized", b'0', b"", "", 0o644);
    let bytes = archive.into_unterminated();
    let mut members = TarArchive::new(bytes.as_slice()).members();
    let Some(Member::File { mut payload, .. }) = members.next().await? else {
        return Err(io::Error::other("expected oversized file member").into());
    };

    let mut chunk = Vec::new();
    assert!(matches!(
        payload.next_chunk(&mut chunk, usize::MAX).await,
        Err(DecodeError::Framing(FrameError {
            inner: FrameErrorInner::ArithmeticOverflow {
                context: "member payload chunk physical length",
            },
            ..
        }))
    ));
    assert!(matches!(
        payload.next_chunk(&mut chunk, 1).await,
        Err(DecodeError::Poisoned)
    ));
    assert!(matches!(payload.skip().await, Err(DecodeError::Poisoned)));

    for attempt in 1..=2 {
        assert!(
            matches!(members.next().await, Err(DecodeError::Poisoned)),
            "iteration {attempt}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn payload_errors_poison_member_iteration() -> TestResult {
    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Read,
        Skip,
    }

    let bytes = header(ArchiveFormat::Pax, "truncated", b'0', 5, "", 0o644);

    for operation in [Operation::Read, Operation::Skip] {
        let mut members = TarArchive::new(bytes.as_slice()).members();
        let Some(Member::File { mut payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected truncated file member").into());
        };

        let result = match operation {
            Operation::Read => {
                let mut chunk = Vec::new();
                payload.next_chunk(&mut chunk, 1).await.map(|_| ())
            }
            Operation::Skip => payload.skip().await,
        };
        assert!(
            matches!(result, Err(DecodeError::Framing(_))),
            "{operation:?}"
        );

        for attempt in 1..=2 {
            assert!(
                matches!(members.next().await, Err(DecodeError::Poisoned)),
                "{operation:?}, iteration {attempt}"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn rejects_zero_length_gnu_extensions_at_their_header() -> TestResult {
    for (typeflag, kind, other) in [
        (b'L', GnuKind::LongName, b'K'),
        (b'K', GnuKind::LongLink, b'L'),
    ] {
        for previous in [None, Some(other)] {
            let mut archive = ArchiveBuilder::new();
            let header_position = if let Some(previous) = previous {
                archive.gnu("metadata", previous, b"value\0", "", 0o644);
                2 * BLOCK_SIZE
            } else {
                0
            };
            archive
                .gnu("metadata", typeflag, b"", "", 0o644)
                .gnu("link", b'2', b"", "target", 0o644);
            let bytes = archive.finish();
            let mut unread = bytes.as_slice();
            let mut members = TarArchive::new(&mut unread).members();

            assert!(matches!(
                members.next().await,
                Err(DecodeError::Framing(FrameError {
                    position,
                    inner: FrameErrorInner::InvalidGnuExtension { kind: found, .. },
                })) if position == header_position as u64 && found == kind
            ));
            assert!(matches!(members.next().await, Err(DecodeError::Poisoned)));
            assert_eq!(
                bytes.len() - unread.len(),
                header_position + BLOCK_SIZE,
                "reader must stop after the empty {kind:?} header at byte {header_position}",
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_member_read_can_be_retried() -> TestResult {
    let header = header(ArchiveFormat::Pax, "file", b'0', 1, "", 0o644);
    let (input, mut writer) = duplex(BLOCK_SIZE);
    let mut members = TarArchive::new(input).members();
    writer.write_all(&header[..1]).await?;
    let mut context = Context::from_waker(Waker::noop());
    assert!(pin!(members.next()).poll(&mut context).is_pending());

    writer.write_all(&header[1..]).await?;
    let Some(Member::File {
        metadata,
        mut payload,
        ..
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected file member").into());
    };
    assert_eq!(metadata.path, "file");

    let mut chunk = Vec::new();
    writer.write_all(b"x").await?;
    assert!(
        pin!(payload.next_chunk(&mut chunk, 1))
            .poll(&mut context)
            .is_pending()
    );
    writer.write_all(&[0; BLOCK_SIZE - 1]).await?;
    drop(writer);
    assert!(payload.next_chunk(&mut chunk, 1).await?);
    assert_eq!(chunk, b"x");
    Ok(())
}

#[tokio::test]
async fn framing_errors_poison_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .gnu("longname", b'L', b"no-nul", "", 0o644)
        .gnu("first", b'0', b"", "", 0o644)
        .gnu("second", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    assert!(matches!(
        members.next().await,
        Err(DecodeError::Framing(FrameError {
            inner: FrameErrorInner::InvalidGnuExtension {
                kind: GnuKind::LongName,
                ..
            },
            ..
        }))
    ));
    assert!(matches!(members.next().await, Err(DecodeError::Poisoned)));

    Ok(())
}

#[tokio::test]
async fn invalid_utf8_projection_errors_poison_member_iteration() -> TestResult {
    let mut binary_path = pax_record(PaxKeyword::HdrCharset, "BINARY");
    binary_path.extend_from_slice(&raw_pax_record(PaxKeyword::Path, &[0xff]));

    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &binary_path)
        .ustar("first", b'0', b"", "", 0o644)
        .ustar("second", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    assert!(matches!(
        members.next().await,
        Err(DecodeError::InvalidUtf8 { field: "path", .. })
    ));
    assert!(matches!(members.next().await, Err(DecodeError::Poisoned)));

    Ok(())
}

#[tokio::test]
async fn policy_errors_poison_member_iteration() -> TestResult {
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record(PaxKeyword::Path, "forbidden"))
        .ustar("first", b'0', b"", "", 0o644)
        .ustar("second", b'0', b"payload", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice()).members();

    assert!(matches!(
        members.next().await,
        Err(DecodeError::PolicyViolation {
            violation: DecodePolicyViolation::GlobalPaxMemberMetadata { keyword: "path" },
            ..
        })
    ));
    assert!(matches!(members.next().await, Err(DecodeError::Poisoned)));
    Ok(())
}
