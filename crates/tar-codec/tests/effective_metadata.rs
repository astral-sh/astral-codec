pub mod support;

use std::{error::Error, io, sync::Arc};

use support::{ArchiveBuilder, ArchiveFormat, header, pax_record, raw_pax_record, set_checksum};
use tar_codec::{
    Archive as _, DecodeError, DecodePolicy, DecodePolicyViolation, Member, MemberPayload,
    PaxDecodePolicy, PaxRecord, PaxValue, PaxVendorExtensionPolicy, TarArchive,
};
use tar_framing::{Block, PaxKeyword, header::MTIME_RANGE};

type TestResult = Result<(), Box<dyn Error>>;

fn timed_header(format: ArchiveFormat, mtime: Option<u64>) -> Block {
    let mut block = header(format, "file", b'0', 0, "", 0o644);
    if let Some(mtime) = mtime {
        block[MTIME_RANGE].copy_from_slice(format!("{mtime:011o}\0").as_bytes());
    } else {
        block[MTIME_RANGE].fill(0);
    }
    set_checksum(&mut block);
    block
}

fn vendor_keyword(name: &str) -> PaxKeyword {
    PaxKeyword::Vendor {
        vendor: Arc::from("Acme"),
        name: Arc::from(name),
    }
}

fn vendor_record(name: &str, value: &[u8]) -> Vec<u8> {
    raw_pax_record(vendor_keyword(name), value)
}

#[tokio::test]
async fn metadata_preserves_header_mtime_including_zero_and_absence() -> TestResult {
    for format in [ArchiveFormat::Pax, ArchiveFormat::Gnu] {
        for expected in [None, Some(0), Some(1_704_164_645)] {
            let mut archive = ArchiveBuilder::new();
            archive.block(&timed_header(format, expected));
            let bytes = archive.finish();
            let mut members = TarArchive::new(bytes.as_slice()).members();
            let Some(Member::File {
                metadata, payload, ..
            }) = members.next().await?
            else {
                return Err(io::Error::other("expected file with header metadata").into());
            };
            assert_eq!(metadata.format.mtime(), expected, "{format:?}");
            assert_eq!(
                metadata.format.pax.is_some(),
                matches!(format, ArchiveFormat::Pax)
            );
            if let Some(pax) = metadata.format.pax {
                assert!(pax.effective_records().next().is_none());
            }
            payload.skip().await?;
            assert!(members.next().await?.is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn metadata_mtime_resolves_inheritance_overrides_and_deletions() -> TestResult {
    let member_header = timed_header(ArchiveFormat::Pax, Some(42));
    let mut global = pax_record(PaxKeyword::Mtime, "50");
    global.extend(pax_record(PaxKeyword::Mtime, "100.75"));
    let mut local = pax_record(PaxKeyword::Mtime, "150");
    local.extend(pax_record(PaxKeyword::Mtime, "200.99"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &global)
        .pax(b'x', &local)
        .block(&member_header)
        .block(&member_header)
        .pax(b'x', &pax_record(PaxKeyword::Mtime, ""))
        .block(&member_header)
        .block(&member_header)
        .pax(b'g', &pax_record(PaxKeyword::Mtime, ""))
        .block(&member_header)
        .pax(b'x', &pax_record(PaxKeyword::Mtime, "300"))
        .block(&member_header)
        .block(&member_header);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(
            DecodePolicy::default()
                .pax_policy(PaxDecodePolicy::default().allow_duplicate_pax_records(true)),
        )
        .members();

    for expected in [Some(200), Some(100), None, Some(100), None, Some(300), None] {
        let Some(Member::File {
            metadata, payload, ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with effective PAX mtime").into());
        };
        assert_eq!(metadata.format.mtime(), expected);
        payload.skip().await?;
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn pax_metadata_resolves_scope_and_preserves_payloads() -> TestResult {
    let binary_value = b"\xff\0\n=value";
    let mut global = vendor_record("attribute", b"first");
    global.extend(vendor_record("attribute", b"global"));
    global.extend(vendor_record("Attribute", b"case-sensitive"));
    global.extend(vendor_record("metadata.Content-Type", binary_value));
    global.extend(pax_record(PaxKeyword::Comment, "not a vendor record"));
    global.extend(pax_record(PaxKeyword::Mtime, "123"));
    let mut local = vendor_record("attribute", b"first");
    local.extend(vendor_record("attribute", b"local"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &global)
        .pax(b'x', &local)
        .ustar("local", b'0', b"payload", "", 0o644)
        .ustar("inherited", b'0', b"payload", "", 0o644)
        .pax(b'x', &vendor_record("attribute", b""))
        .ustar("local-deletion", b'0', b"payload", "", 0o644)
        .ustar("restored-global", b'0', b"payload", "", 0o644)
        .pax(b'g', &vendor_record("attribute", b"replacement"))
        .ustar("replacement", b'0', b"payload", "", 0o644)
        .pax(b'g', &vendor_record("attribute", b""))
        .ustar("global-deletion", b'0', b"payload", "", 0o644)
        .ustar("inherited-deletion", b'0', b"payload", "", 0o644);
    let bytes = archive.finish();
    let expected_values = [
        Some(b"local".as_slice()),
        Some(b"global".as_slice()),
        None,
        Some(b"global".as_slice()),
        Some(b"replacement".as_slice()),
        None,
        None,
    ];
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .allow_duplicate_pax_records(true)
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        )
        .members();

    for expected in expected_values {
        let Some(Member::File {
            metadata,
            mut payload,
            ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with PAX metadata").into());
        };
        assert_eq!(metadata.format.mtime(), Some(123));
        let pax = metadata
            .format
            .pax
            .ok_or_else(|| io::Error::other("expected PAX state"))?;
        let attribute = PaxRecord::Vendor {
            vendor: Arc::from("Acme"),
            name: Arc::from("attribute"),
            value: expected.map_or(PaxValue::Deleted, |value| PaxValue::Value(Arc::from(value))),
        };
        assert_eq!(
            pax.effective_record(&vendor_keyword("attribute")),
            Some(&attribute)
        );
        assert_eq!(
            pax.effective_record(&vendor_keyword("metadata.content-type")),
            None
        );
        let actual: Vec<_> = pax.effective_records().collect();
        let expected_records = [
            attribute,
            PaxRecord::Vendor {
                vendor: Arc::from("Acme"),
                name: Arc::from("Attribute"),
                value: PaxValue::Value(Arc::from(b"case-sensitive".as_slice())),
            },
            PaxRecord::Vendor {
                vendor: Arc::from("Acme"),
                name: Arc::from("metadata.Content-Type"),
                value: PaxValue::Value(Arc::from(binary_value.as_slice())),
            },
            PaxRecord::Comment(PaxValue::Value(Arc::from("not a vendor record"))),
            PaxRecord::Mtime(PaxValue::Value(123)),
        ];
        assert_eq!(actual.len(), expected_records.len());
        for record in &expected_records {
            assert!(
                actual.contains(&record),
                "missing effective record: {record:?}"
            );
        }
        let mut contents = Vec::new();
        let mut chunk = Vec::new();
        while payload.next_chunk(&mut chunk, 3).await? {
            contents.extend_from_slice(&chunk);
        }
        assert_eq!(contents, b"payload");
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn metadata_is_available_for_members_without_payloads() -> TestResult {
    let mut global = vendor_record("attribute", b"inherited");
    global.extend(pax_record(PaxKeyword::Mtime, "123"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &global)
        .ustar("directory", b'5', b"", "", 0o755)
        .ustar("symlink", b'2', b"", "directory", 0o777)
        .ustar("fifo", b'6', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        )
        .members();
    for path in ["directory", "symlink", "fifo"] {
        let Some(member) = members.next().await? else {
            return Err(io::Error::other("expected member without payload").into());
        };
        assert!(matches!(
            member,
            Member::Directory { .. } | Member::SymbolicLink { .. } | Member::Special { .. }
        ));
        let metadata = member.metadata();
        assert_eq!(metadata.path, path);
        assert_eq!(metadata.format.mtime(), Some(123));
        let pax = metadata
            .format
            .pax
            .as_ref()
            .ok_or_else(|| io::Error::other("expected PAX state"))?;
        assert!(matches!(pax.effective_record(&vendor_keyword("attribute")),
            Some(PaxRecord::Vendor { value: PaxValue::Value(value), .. }) if value.as_ref() == b"inherited"));
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn overwritten_invalid_vendor_values_still_fail_policy() -> TestResult {
    for scope in *b"xg" {
        let mut records = vendor_record("attribute", b"\xff");
        records.extend(vendor_record("attribute", b"valid replacement"));
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(scope, &records)
            .ustar("rejected", b'0', b"", "", 0o644);
        let bytes = archive.finish();
        let mut members = TarArchive::new(bytes.as_slice())
            .with_policy(
                DecodePolicy::default().pax_policy(
                    PaxDecodePolicy::default()
                        .allow_duplicate_pax_records(true)
                        .allow_non_utf8_pax_vendor_values(false)
                        .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
                ),
            )
            .members();
        assert!(matches!(
            members.next().await,
            Err(DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::NonUtf8PaxVendorValue { vendor, name },
            }) if vendor == "Acme" && name == "attribute"
        ));
        assert!(members.next().await?.is_none());
    }
    Ok(())
}
