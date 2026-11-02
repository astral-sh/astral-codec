pub mod support;

use std::{error::Error, io};

use support::{ArchiveBuilder, ArchiveFormat, header, pax_record, raw_pax_record, set_checksum};
use tar_codec::{
    Archive as _, ByteMember, DecodeError, DecodePolicy, Member, MemberPayload, PaxDecodePolicy,
    SpecialKind, TarArchive,
};
use tar_framing::{
    PaxKeyword,
    header::{LINK_NAME_RANGE, NAME_RANGE, PREFIX_RANGE},
};

type TestResult = Result<(), Box<dyn Error>>;

async fn read_payload<P: MemberPayload<Error = DecodeError>>(
    mut payload: P,
) -> Result<Vec<u8>, DecodeError> {
    let mut bytes = Vec::new();
    let mut chunk = Vec::new();
    while payload.next_chunk(&mut chunk, 3).await? {
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[tokio::test]
async fn binary_pax_projects_every_kind_and_streams_payloads() -> TestResult {
    let mut records = pax_record(PaxKeyword::HdrCharset, "BINARY");
    records.extend(raw_pax_record(PaxKeyword::Path, b"dir/name-\xff"));
    let mut archive = ArchiveBuilder::new();
    for kind in *b"07521346" {
        let payload = if matches!(kind, b'0' | b'7') {
            &b"contents"[..]
        } else {
            &b""[..]
        };
        let mut member_records = records.clone();
        let target = if matches!(kind, b'2' | b'1') {
            member_records.extend(raw_pax_record(PaxKeyword::LinkPath, b"../target-\xfe"));
            "fallback-target"
        } else {
            ""
        };
        archive
            .pax(b'x', &member_records)
            .ustar("fallback", kind, payload, target, 0o755);
    }
    let bytes = archive.finish();
    let mut archive = TarArchive::new(bytes.as_slice());
    for index in 0..2 {
        let Some(ByteMember::File {
            metadata,
            size,
            executable,
            payload,
        }) = archive.next_byte_member().await?
        else {
            return Err(io::Error::other("expected byte file member").into());
        };
        assert_eq!(metadata.path, b"dir/name-\xff");
        assert_eq!(metadata.position, 1024 + index * 2048);
        assert_eq!(size, 8);
        assert!(executable);
        assert_eq!(read_payload(payload).await?, b"contents");
    }
    let Some(directory) = archive.next_byte_member().await? else {
        return Err(io::Error::other("expected byte directory member").into());
    };
    assert_eq!(directory.metadata().path, b"dir/name-\xff");
    assert!(matches!(directory, ByteMember::Directory { .. }));
    assert!(
        matches!(archive.next_byte_member().await?, Some(ByteMember::SymbolicLink { metadata, target })
        if metadata.path == b"dir/name-\xff" && target == b"../target-\xfe")
    );
    let Some(ByteMember::HardLink {
        metadata,
        target,
        size,
        payload,
    }) = archive.next_byte_member().await?
    else {
        return Err(io::Error::other("expected byte hard-link member").into());
    };
    assert_eq!(metadata.path, b"dir/name-\xff");
    assert_eq!(target, b"../target-\xfe");
    assert_eq!(size, 0);
    payload.skip().await?;
    for kind in [
        SpecialKind::CharacterDevice,
        SpecialKind::BlockDevice,
        SpecialKind::Fifo,
    ] {
        assert!(
            matches!(archive.next_byte_member().await?, Some(ByteMember::Special { metadata, kind: actual })
            if metadata.path == b"dir/name-\xff" && actual == kind)
        );
    }
    assert!(archive.next_byte_member().await?.is_none());
    assert!(archive.next_member().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn preserves_ustar_and_gnu_header_bytes_and_gnu_extensions() -> TestResult {
    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        for kind in *b"021" {
            let mut block = header(format, "", kind, 0, "", 0o644);
            block[NAME_RANGE.start..NAME_RANGE.start + 6].copy_from_slice(b"name-\xff");
            if matches!(kind, b'2' | b'1') {
                block[LINK_NAME_RANGE.start..LINK_NAME_RANGE.start + 8]
                    .copy_from_slice(b"target-\xfe");
            }
            if format == ArchiveFormat::Pax {
                block[PREFIX_RANGE.start..PREFIX_RANGE.start + 5].copy_from_slice(b"dir-\xfd");
            }
            set_checksum(&mut block);
            let mut builder = ArchiveBuilder::new();
            builder.block(&block);
            let bytes = builder.finish();
            let mut archive = TarArchive::new(bytes.as_slice());
            let Some(member) = archive.next_byte_member().await? else {
                return Err(io::Error::other("expected header byte member").into());
            };
            assert_eq!(
                member.metadata().path,
                if format == ArchiveFormat::Pax {
                    &b"dir-\xfd/name-\xff"[..]
                } else {
                    &b"name-\xff"[..]
                }
            );
            match member {
                ByteMember::SymbolicLink { target, .. } | ByteMember::HardLink { target, .. } => {
                    assert_eq!(target, b"target-\xfe")
                }
                ByteMember::File { payload, .. } => payload.skip().await?,
                _ => return Err(io::Error::other("unexpected header byte member").into()),
            }
        }
    }

    let name = [vec![b'a'; 120], b"\xff".to_vec()].concat();
    let target = [vec![b'b'; 120], b"\xfe".to_vec()].concat();
    let mut builder = ArchiveBuilder::new();
    builder
        .gnu(
            "longname",
            b'L',
            &[name.as_slice(), b"\0"].concat(),
            "",
            0o644,
        )
        .gnu(
            "longlink",
            b'K',
            &[target.as_slice(), b"\0"].concat(),
            "",
            0o644,
        )
        .gnu("fallback", b'2', b"", "fallback", 0o644);
    let bytes = builder.finish();
    assert!(
        matches!(TarArchive::new(bytes.as_slice()).next_byte_member().await?,
        Some(ByteMember::SymbolicLink { metadata, target: actual }) if metadata.path == name && actual == target)
    );
    Ok(())
}

#[tokio::test]
async fn pax_requires_binary_and_respects_charset_inheritance_and_reset() -> TestResult {
    for keyword in [PaxKeyword::Path, PaxKeyword::LinkPath] {
        for charset in [None, Some("")] {
            let mut builder = ArchiveBuilder::new();
            if charset.is_some() {
                builder.pax(b'g', &pax_record(PaxKeyword::HdrCharset, "BINARY"));
            }
            let mut records = raw_pax_record(keyword.clone(), b"name-\xff");
            if let Some(charset) = charset {
                records.extend(pax_record(PaxKeyword::HdrCharset, charset));
            }
            builder
                .pax(b'x', &records)
                .ustar("fallback", b'2', b"", "fallback", 0o644)
                .ustar("after", b'0', b"", "", 0o644);
            let bytes = builder.finish();
            let mut archive = TarArchive::new(bytes.as_slice());
            assert!(matches!(
                archive.next_byte_member().await,
                Err(DecodeError::Framing(_))
            ));
            assert!(archive.next_byte_member().await?.is_none());
            assert!(archive.next_member().await?.is_none());
        }
    }
    let mut builder = ArchiveBuilder::new();
    builder
        .pax(b'g', &pax_record(PaxKeyword::HdrCharset, "BINARY"))
        .pax(b'x', &raw_pax_record(PaxKeyword::Path, b"global-\xff"))
        .ustar("fallback", b'0', b"", "", 0o644);
    let bytes = builder.finish();
    assert!(
        matches!(TarArchive::new(bytes.as_slice()).next_byte_member().await?,
        Some(ByteMember::File { metadata, .. }) if metadata.path == b"global-\xff")
    );
    Ok(())
}

#[tokio::test]
async fn byte_and_utf8_reads_share_cursor_drain_payloads_and_fuse_errors() -> TestResult {
    let mut records = pax_record(PaxKeyword::HdrCharset, "BINARY");
    records.extend(raw_pax_record(PaxKeyword::LinkPath, b"target-\xff"));
    let mut builder = ArchiveBuilder::new();
    builder
        .ustar("first", b'0', b"unread contents", "", 0o644)
        .ustar("second", b'0', b"more contents", "", 0o644)
        .pax(b'x', &records)
        .ustar("link", b'2', b"", "fallback", 0o644)
        .ustar("after", b'0', b"", "", 0o644);
    let bytes = builder.finish();
    let mut archive = TarArchive::new(bytes.as_slice());
    assert!(
        matches!(archive.next_byte_member().await?, Some(ByteMember::File { metadata, .. }) if metadata.path == b"first")
    );
    assert!(
        matches!(archive.next_member().await?, Some(Member::File { metadata, .. }) if metadata.path == "second")
    );
    assert!(matches!(
        archive.next_member().await,
        Err(DecodeError::InvalidUtf8 {
            field: "linkpath",
            ..
        })
    ));
    assert!(archive.next_byte_member().await?.is_none());
    assert!(archive.next_member().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn byte_members_enforce_decode_policy_and_fuse_on_rejection() -> TestResult {
    let mut gnu = ArchiveBuilder::new();
    gnu.gnu("file", b'0', b"", "", 0o644);
    let mut vendor = ArchiveBuilder::new();
    vendor
        .pax(
            b'x',
            &raw_pax_record(
                PaxKeyword::Vendor {
                    vendor: "GNU".into(),
                    name: "sparse.map".into(),
                },
                b"0,1",
            ),
        )
        .ustar("file", b'0', b"", "", 0o644);
    let mut global = ArchiveBuilder::new();
    global
        .pax(b'g', &pax_record(PaxKeyword::Path, "global"))
        .ustar("file", b'0', b"", "", 0o644);
    for (bytes, policy) in [
        (gnu.finish(), DecodePolicy::default().allow_gnu(false)),
        (vendor.finish(), DecodePolicy::default()),
        (global.finish(), DecodePolicy::default()),
    ] {
        let mut archive = TarArchive::new(bytes.as_slice()).with_policy(policy);
        assert!(matches!(
            archive.next_byte_member().await,
            Err(DecodeError::PolicyViolation { .. })
        ));
        assert!(archive.next_byte_member().await?.is_none());
        assert!(archive.next_member().await?.is_none());
    }

    let mut builder = ArchiveBuilder::new();
    builder
        .pax(b'x', &pax_record(PaxKeyword::Path, "long"))
        .ustar("file", b'0', b"", "", 0o644);
    let bytes = builder.finish();
    let mut archive = TarArchive::new(bytes.as_slice()).with_policy(
        DecodePolicy::default().pax_policy(PaxDecodePolicy::default().max_extension_size(1)),
    );
    assert!(matches!(
        archive.next_byte_member().await,
        Err(DecodeError::Framing(_))
    ));
    assert!(archive.next_byte_member().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn byte_hard_link_payloads_still_require_opt_in() -> TestResult {
    let mut records = pax_record(PaxKeyword::HdrCharset, "BINARY");
    records.extend(raw_pax_record(PaxKeyword::LinkPath, b"target-\xff"));
    let mut builder = ArchiveBuilder::new();
    builder
        .pax(b'x', &records)
        .ustar("link", b'1', b"replacement", "fallback", 0o644);
    let bytes = builder.finish();
    assert!(matches!(
        TarArchive::new(bytes.as_slice()).next_byte_member().await,
        Err(DecodeError::Framing(_))
    ));
    let mut archive = TarArchive::new(bytes.as_slice()).with_policy(
        DecodePolicy::default()
            .pax_policy(PaxDecodePolicy::default().allow_hardlink_linkdata(true)),
    );
    let Some(ByteMember::HardLink {
        target,
        size,
        payload,
        ..
    }) = archive.next_byte_member().await?
    else {
        return Err(io::Error::other("expected byte hard link with payload").into());
    };
    assert_eq!(target, b"target-\xff");
    assert_eq!(size, 11);
    assert_eq!(read_payload(payload).await?, b"replacement");
    Ok(())
}
