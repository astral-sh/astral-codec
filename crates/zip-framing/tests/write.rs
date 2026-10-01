use std::{error::Error, io::Cursor};

use flate2::Crc;
use zip_framing::{
    CompressionMethod, Error as FrameError, HostSystem, Index, Limits,
    write::{EntryKind, MemberHeader, end_records},
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn rejects_invalid_member_headers() {
    let file = EntryKind::File { executable: false };
    let oversized = "x".repeat(usize::from(u16::MAX) + 1);

    for (path, method, kind) in [
        ("", CompressionMethod::Stored, file),
        (oversized.as_str(), CompressionMethod::Stored, file),
        ("back\\slash", CompressionMethod::Stored, file),
        ("café\0file", CompressionMethod::Stored, file),
        ("café\\file", CompressionMethod::Stored, file),
        ("\u{feff}file", CompressionMethod::Stored, file),
        ("/file", CompressionMethod::Stored, file),
        ("C:file", CompressionMethod::Stored, file),
        ("file/", CompressionMethod::Stored, file),
        ("directory", CompressionMethod::Stored, EntryKind::Directory),
        (
            "directory/",
            CompressionMethod::Deflate,
            EntryKind::Directory,
        ),
    ] {
        assert!(matches!(
            MemberHeader::new(path, method, kind),
            Err(FrameError::Invalid { position: 0, .. })
        ));
    }
}

#[test]
fn rejects_inconsistent_completed_metadata() -> TestResult {
    let file = EntryKind::File { executable: false };

    for (method, kind, crc, compressed, size, expected) in [
        (
            CompressionMethod::Stored,
            file,
            0,
            2,
            1,
            "stored member sizes differ",
        ),
        (
            CompressionMethod::Stored,
            file,
            1,
            0,
            0,
            "empty member has file data or nonzero CRC",
        ),
        (
            CompressionMethod::Deflate,
            file,
            0,
            2,
            0,
            "empty member has file data or nonzero CRC",
        ),
        (
            CompressionMethod::Stored,
            EntryKind::Directory,
            0,
            1,
            1,
            "directory has file data",
        ),
    ] {
        let path = if matches!(kind, EntryKind::Directory) {
            "directory/"
        } else {
            "file"
        };
        let header = MemberHeader::new(path, method, kind)?;

        assert!(matches!(
            header.finish(crc, compressed, size, 47),
            Err(FrameError::Invalid { position: 47, reason }) if reason == expected
        ));
    }

    Ok(())
}

#[tokio::test]
async fn serializes_consistent_zip64_records() -> TestResult {
    let payload = b"payload";
    let mut crc = Crc::new();
    crc.update(payload);

    let header = MemberHeader::new(
        "café",
        CompressionMethod::Stored,
        EntryKind::File { executable: false },
    )?;
    let metadata_size = header.metadata_size();
    let data_offset = header.local_header_size();
    let member = header.finish(crc.sum(), payload.len() as u64, payload.len() as u64, 0)?;
    let mut bytes = member.local_header();
    assert_eq!(bytes.len(), data_offset);
    // Keep wire values independent of the constants shared by reader and writer.
    assert_eq!(
        &bytes[..14],
        b"PK\x03\x04\x2d\x00\x00\x08\x00\x00\x00\x00\x21\x00"
    );
    assert_eq!(&bytes[26..30], &[5, 0, 20, 0]);
    assert_eq!(&bytes[35..39], &[1, 0, 16, 0]);
    bytes.extend_from_slice(payload);

    let directory_offset = bytes.len() as u64;
    let central = member.central_header();
    let directory_size = central.len() as u64;
    assert_eq!(metadata_size, data_offset as u64 + directory_size);
    assert_eq!(
        &central[..12],
        b"PK\x01\x02\x2d\x03\x2d\x00\x00\x08\x00\x00"
    );
    assert_eq!(&central[28..32], &[5, 0, 28, 0]);
    assert_eq!(&central[38..42], &(0o100644u32 << 16).to_le_bytes());
    assert_eq!(&central[51..55], &[1, 0, 24, 0]);
    bytes.extend(central);
    let end = end_records(1, directory_offset, directory_size)?;
    assert_eq!(end.len(), 98);
    assert_eq!(&end[..4], b"PK\x06\x06");
    assert_eq!(&end[4..12], &44u64.to_le_bytes());
    assert_eq!(&end[12..16], &[45, 3, 45, 0]);
    assert_eq!(&end[56..60], b"PK\x06\x07");
    assert_eq!(&end[76..80], b"PK\x05\x06");
    bytes.extend(end);

    let mut source = Cursor::new(&bytes);
    let mut index = Index::read(&mut source, Limits::default()).await?;
    assert_eq!(index.entries().len(), 1);

    let entry = index.entry(&mut source, 0).await?.ok_or("missing member")?;
    assert_eq!(entry.directory().path(), "café");
    assert_eq!(entry.directory().host_system(), HostSystem::Unix);
    assert_eq!(entry.directory().version_needed(), 45);
    assert_eq!(entry.data_offset(), data_offset as u64);
    assert_eq!(entry.directory().size(), payload.len() as u64);
    assert_eq!(entry.directory().crc32(), crc.sum());

    Ok(())
}
