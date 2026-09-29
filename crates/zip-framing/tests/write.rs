use std::{error::Error, io::Cursor};

use flate2::Crc;
use zip_framing::{
    CompressionMethod, Error as FrameError, Index, Limits,
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
    assert_eq!(&bytes[6..8], &0x0800u16.to_le_bytes());
    bytes.extend_from_slice(payload);

    let directory_offset = bytes.len() as u64;
    let central = member.central_header();
    let directory_size = central.len() as u64;
    assert_eq!(metadata_size, data_offset as u64 + directory_size);
    bytes.extend(central);
    bytes.extend(end_records(1, directory_offset, directory_size)?);

    let index = Index::read(&mut Cursor::new(&bytes), Limits::default()).await?;
    assert_eq!(index.entries().len(), 1);

    let entry = &index.entries()[0];
    assert_eq!(entry.path(), "café");
    assert_eq!(entry.version_needed(), 45);
    assert_eq!(entry.data_offset(), data_offset as u64);
    assert_eq!(entry.size(), payload.len() as u64);
    assert_eq!(entry.crc32(), crc.sum());

    Ok(())
}
