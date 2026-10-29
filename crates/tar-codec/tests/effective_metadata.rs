pub mod support;

use std::{error::Error, io, sync::Arc};

use support::{ArchiveBuilder, ArchiveFormat, header, pax_record, raw_pax_record, set_checksum};
use tar_codec::{
    Archive as _, DecodeError, DecodePolicy, DecodePolicyViolation, Member, MemberPayload,
    PaxDecodePolicy, PaxVendorExtensionPolicy, PaxVendorValue, TarArchive,
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

fn vendor_record(name: &str, value: &[u8]) -> Vec<u8> {
    raw_pax_record(
        PaxKeyword::Vendor {
            vendor: Arc::from("Acme"),
            name: Arc::from(name),
        },
        value,
    )
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
            assert_eq!(metadata.mtime, expected, "{format:?}");
            assert!(metadata.pax_vendor_records.is_empty());
            assert_eq!(metadata.pax_vendor_records.len(), 0);
            assert_eq!(metadata.pax_vendor_records.get("Acme.attribute"), None);
            assert!(metadata.pax_vendor_records.iter().next().is_none());
            payload.skip().await?;
            assert!(members.next().await?.is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn metadata_mtime_resolves_inheritance_overrides_and_deletions() -> TestResult {
    let member_header = timed_header(ArchiveFormat::Pax, Some(42));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &pax_record(PaxKeyword::Mtime, "100.75"))
        .pax(b'x', &pax_record(PaxKeyword::Mtime, "200.99"))
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
    let mut members = TarArchive::new(bytes.as_slice()).members();

    for expected in [Some(200), Some(100), None, Some(100), None, Some(300), None] {
        let Some(Member::File {
            metadata, payload, ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with effective PAX mtime").into());
        };
        assert_eq!(metadata.mtime, expected);
        assert!(metadata.pax_vendor_records.is_empty());
        payload.skip().await?;
    }
    assert!(members.next().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn retaining_vendor_metadata_is_optional_without_changing_mtime_or_payload() -> TestResult {
    let mut records = vendor_record("attribute", b"value");
    records.extend(pax_record(PaxKeyword::Mtime, "123"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &records)
        .ustar("file", b'0', b"payload", "", 0o644);
    let bytes = archive.finish();

    for disable_explicitly in [false, true] {
        let mut archive = TarArchive::new(bytes.as_slice()).with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        );
        if disable_explicitly {
            archive = archive
                .retain_pax_vendor_records(true)
                .retain_pax_vendor_records(false);
        }
        let mut members = archive.members();
        let Some(Member::File {
            metadata,
            mut payload,
            ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with omitted vendor metadata").into());
        };
        assert!(metadata.pax_vendor_records.is_empty());
        assert_eq!(metadata.mtime, Some(123));
        let mut contents = Vec::new();
        let mut chunk = Vec::new();
        while payload.next_chunk(&mut chunk, 3).await? {
            contents.extend_from_slice(&chunk);
        }
        assert_eq!(contents, b"payload");
        assert!(members.next().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn vendor_metadata_snapshots_resolve_scope_and_preserve_payloads() -> TestResult {
    let mut global = vendor_record("attribute", b"global");
    global.extend(vendor_record("inherited", b"kept"));
    global.extend(pax_record(PaxKeyword::Comment, "not a vendor record"));
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'g', &global)
        .pax(b'x', &vendor_record("attribute", b"local"))
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
    let mut members = TarArchive::new(bytes.as_slice())
        .retain_pax_vendor_records(true)
        .with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
            ),
        )
        .members();
    let mut snapshots = Vec::new();
    let expected_values = [
        PaxVendorValue::Value(b"local".as_slice()),
        PaxVendorValue::Value(b"global".as_slice()),
        PaxVendorValue::Deleted,
        PaxVendorValue::Value(b"global".as_slice()),
        PaxVendorValue::Value(b"replacement".as_slice()),
        PaxVendorValue::Deleted,
        PaxVendorValue::Deleted,
    ];

    for expected in &expected_values {
        let Some(Member::File {
            metadata,
            mut payload,
            ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with vendor metadata").into());
        };
        assert_eq!(metadata.pax_vendor_records.len(), 2);
        assert!(!metadata.pax_vendor_records.is_empty());
        assert_eq!(metadata.pax_vendor_records.get("Acme.missing"), None);
        assert_eq!(
            metadata.pax_vendor_records.get("Acme.attribute"),
            Some(*expected),
        );
        let mut records: Vec<_> = metadata.pax_vendor_records.iter().collect();
        records.sort_unstable_by_key(|(key, _)| *key);
        assert_eq!(
            records,
            [
                ("Acme.attribute", *expected),
                ("Acme.inherited", PaxVendorValue::Value(b"kept".as_slice())),
            ],
        );
        let mut contents = Vec::new();
        let mut chunk = Vec::new();
        while payload.next_chunk(&mut chunk, 3).await? {
            contents.extend_from_slice(&chunk);
        }
        assert_eq!(contents, b"payload");
        snapshots.push(metadata);
    }
    assert!(members.next().await?.is_none());
    drop(members);
    for (snapshot, expected) in snapshots.iter().zip(expected_values) {
        assert_eq!(
            snapshot.pax_vendor_records.get("Acme.attribute"),
            Some(expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn allowed_duplicate_metadata_uses_the_last_record() -> TestResult {
    let mut records = vendor_record("attribute", b"first");
    records.extend(pax_record(PaxKeyword::Mtime, "100"));
    records.extend(vendor_record("attribute", b"last"));
    records.extend(pax_record(PaxKeyword::Mtime, "200"));
    for scope in *b"xg" {
        let mut archive = ArchiveBuilder::new();
        archive
            .pax(scope, &records)
            .ustar("file", b'0', b"", "", 0o644);
        let bytes = archive.finish();
        let mut rejected = TarArchive::new(bytes.as_slice())
            .retain_pax_vendor_records(true)
            .with_policy(
                DecodePolicy::default().pax_policy(
                    PaxDecodePolicy::default()
                        .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
                ),
            )
            .members();
        assert!(matches!(
            rejected.next().await,
            Err(DecodeError::PolicyViolation {
                position: 0,
                violation: DecodePolicyViolation::DuplicatePaxRecord { keyword },
            }) if keyword == "Acme.attribute"
        ));
        assert!(rejected.next().await?.is_none());
        let mut members = TarArchive::new(bytes.as_slice())
            .retain_pax_vendor_records(true)
            .with_policy(
                DecodePolicy::default().pax_policy(
                    PaxDecodePolicy::default()
                        .allow_duplicate_pax_records(true)
                        .vendor_extension_policy(PaxVendorExtensionPolicy::ignore(["Acme"])),
                ),
            )
            .members();
        let Some(Member::File {
            metadata, payload, ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected file with duplicate metadata").into());
        };
        assert_eq!(metadata.mtime, Some(200));
        assert_eq!(metadata.pax_vendor_records.len(), 1);
        assert_eq!(
            metadata.pax_vendor_records.get("Acme.attribute"),
            Some(PaxVendorValue::Value(b"last".as_slice())),
        );
        assert_eq!(
            metadata.pax_vendor_records.iter().collect::<Vec<_>>(),
            [("Acme.attribute", PaxVendorValue::Value(b"last".as_slice()))],
        );
        payload.skip().await?;
        assert!(members.next().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn vendor_metadata_preserves_bytes_when_policy_allows_them() -> TestResult {
    let value = b"\xff\0\n=value";
    let mut archive = ArchiveBuilder::new();
    archive
        .pax(b'x', &vendor_record("metadata.Content-Type", value))
        .ustar("file", b'0', b"", "", 0o644);
    let bytes = archive.finish();
    let mut members = TarArchive::new(bytes.as_slice())
        .retain_pax_vendor_records(true)
        .with_policy(
            DecodePolicy::default().pax_policy(
                PaxDecodePolicy::default()
                    .allow_non_utf8_pax_vendor_values(true)
                    .vendor_extension_policy(PaxVendorExtensionPolicy::AllowUnknown),
            ),
        )
        .members();
    let Some(Member::File {
        metadata, payload, ..
    }) = members.next().await?
    else {
        return Err(io::Error::other("expected file with binary vendor metadata").into());
    };
    assert_eq!(metadata.pax_vendor_records.len(), 1);
    assert_eq!(
        metadata
            .pax_vendor_records
            .get("Acme.metadata.Content-Type"),
        Some(PaxVendorValue::Value(value.as_slice())),
    );
    assert_eq!(
        metadata
            .pax_vendor_records
            .get("Acme.metadata.content-type"),
        None,
    );
    assert_eq!(
        metadata.pax_vendor_records.iter().collect::<Vec<_>>(),
        [(
            "Acme.metadata.Content-Type",
            PaxVendorValue::Value(value.as_slice())
        )],
    );
    payload.skip().await?;
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
            .retain_pax_vendor_records(true)
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
