use std::{
    cell::Cell,
    error::Error,
    future::{Future, poll_fn},
    io::{self, Cursor, SeekFrom},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt, ReadBuf};
use zip_codec::{Archive, DecodeError, Member, MemberPayload, ZipArchive, extract::ExtractPolicy};

type TestResult = Result<(), Box<dyn Error>>;

const STORED: &[u8] = include_bytes!("fixtures/stored.zip");
const DEFLATE: &[u8] = include_bytes!("fixtures/deflate.zip");

// Only interoperability spans the record-layout matrix. Codec workflows below
// use one fixture per compression method; framing owns the layout edge cases.
const FIXTURES: &[(&str, &[u8])] = &[
    ("stored", STORED),
    (
        "stored descriptor",
        include_bytes!("fixtures/stored-descriptor.zip"),
    ),
    ("stored ZIP64", include_bytes!("fixtures/stored-zip64.zip")),
    ("deflate", DEFLATE),
    (
        "deflate descriptor",
        include_bytes!("fixtures/deflate-descriptor.zip"),
    ),
    (
        "deflate ZIP64",
        include_bytes!("fixtures/deflate-zip64.zip"),
    ),
];

async fn contents<P: MemberPayload<Error = DecodeError>>(
    mut payload: P,
) -> Result<Vec<u8>, DecodeError> {
    let mut output = Vec::new();
    let mut chunk = Vec::new();
    while payload.next_chunk(&mut chunk, 257).await? {
        output.extend_from_slice(&chunk);
    }

    Ok(output)
}

#[tokio::test]
async fn reads_python_archives_and_projects_members() -> TestResult {
    for (label, bytes) in FIXTURES {
        let mut members = ZipArchive::open(Cursor::new(bytes)).await?.members();

        assert!(
            matches!(members.next().await?, Some(Member::Directory { metadata }) if metadata.path == "directory/"),
            "{label}"
        );

        let Some(Member::File {
            metadata,
            size,
            executable,
            payload,
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected executable file").into());
        };

        assert_eq!(metadata.path, "directory/file");
        assert_eq!(size, 140_000);
        assert!(executable);
        assert_eq!(
            contents(payload).await?,
            b"hello ZIP\n".repeat(14000),
            "{label}"
        );

        let Some(Member::File {
            metadata, payload, ..
        }) = members.next().await?
        else {
            return Err(io::Error::other("expected Unicode file").into());
        };

        assert_eq!(metadata.path, "café");
        assert_eq!(contents(payload).await?, b"UTF-8 filename");

        let Some(Member::File { size, payload, .. }) = members.next().await? else {
            return Err(io::Error::other("expected empty file").into());
        };

        assert_eq!(size, 0);
        assert!(contents(payload).await?.is_empty());

        assert!(
            matches!(members.next().await?, Some(Member::SymbolicLink { target, .. }) if target == "directory/file")
        );
        assert!(members.next().await?.is_none());
    }

    Ok(())
}

#[tokio::test]
async fn bounds_payload_chunks_and_preserves_the_buffer_at_eof() -> TestResult {
    for (label, bytes, index) in [
        ("stored", STORED, 1),
        ("deflate", DEFLATE, 1),
        ("empty", STORED, 3),
        (
            "empty DEFLATE stream",
            include_bytes!("fixtures/empty-deflate.zip").as_slice(),
            0,
        ),
    ] {
        let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
        let Some(Member::File {
            size, mut payload, ..
        }) = archive.member(index).await?
        else {
            return Err(io::Error::other("expected file").into());
        };

        let mut buffer = vec![0xa5; 16];
        let mut total = 0;
        loop {
            let previous = buffer.clone();
            if !payload.next_chunk(&mut buffer, usize::MAX).await? {
                assert_eq!(buffer, previous, "first EOF: {label}");
                break;
            }

            assert!(!buffer.is_empty(), "{label}");
            assert!(buffer.len() <= 64 * 1024, "{label}");
            total += buffer.len() as u64;
            assert!(total <= size, "{label}");
        }

        assert_eq!(total, size, "{label}");
        let previous = buffer.clone();
        assert!(!payload.next_chunk(&mut buffer, usize::MAX).await?);
        assert_eq!(buffer, previous, "repeated EOF: {label}");
    }

    Ok(())
}

#[tokio::test]
async fn seeks_by_index_and_drains_partially_read_payloads() -> TestResult {
    for bytes in [STORED, DEFLATE] {
        let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
        assert_eq!(archive.entries().len(), 5);
        assert_eq!(archive.entries()[1].directory().path(), "directory/file");
        assert!(archive.entries()[1].resolved().is_none());

        {
            let Some(Member::File { mut payload, .. }) = archive.member(1).await? else {
                return Err(io::Error::other("expected file").into());
            };

            let mut chunk = Vec::new();
            assert!(payload.next_chunk(&mut chunk, 1).await?);
            assert_eq!(chunk, b"h");
        }

        let entry = archive.entries()[1].resolved().ok_or("unresolved entry")?;
        assert_eq!(entry.directory().path(), "directory/file");
        assert_eq!(entry.directory().size(), 140_000);
        assert!(entry.data_offset() > entry.directory().position());
        assert!(archive.entries()[2].resolved().is_none());

        // Source access drains the preceding payload and permits explicit
        // prefetching or seeking before the next member restores its cursor.
        archive.reader_mut().await?.seek(SeekFrom::End(0)).await?;

        let Some(Member::File { payload, .. }) = archive.member(2).await? else {
            return Err(io::Error::other("expected selected file").into());
        };

        assert_eq!(contents(payload).await?, b"UTF-8 filename");

        assert!(matches!(
            archive.next_member().await?,
            Some(Member::File { size: 0, .. })
        ));

        assert!(matches!(
            archive.member(0).await?,
            Some(Member::Directory { .. })
        ));

        let Some(Member::File { payload, .. }) = archive.next_member().await? else {
            return Err(io::Error::other("expected sequential file").into());
        };

        payload.skip().await?;
        assert!(archive.member(usize::MAX).await?.is_none());
    }

    Ok(())
}

#[tokio::test]
async fn verifies_corrupt_payloads_when_read_skipped_or_dropped() -> TestResult {
    for original in [STORED, DEFLATE] {
        let mut archive = ZipArchive::open(Cursor::new(original)).await?;
        archive.validate_all().await?;
        let position = archive.entries()[2]
            .resolved()
            .ok_or("unresolved entry")?
            .data_offset() as usize;

        for operation in ["read", "skip", "drop", "reader", "validate"] {
            let mut bytes = original.to_vec();
            bytes[position] ^= 0x40;

            let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
            let Some(Member::File { payload, .. }) = archive.member(2).await? else {
                return Err(io::Error::other("expected corrupt file").into());
            };

            let result = match operation {
                "read" => contents(payload).await.map(|_| ()),
                "skip" => payload.skip().await,
                "reader" => archive.reader_mut().await.map(|_| ()),
                "validate" => archive.validate_all().await,
                _ => archive.next_member().await.map(|_| ()),
            };

            assert!(
                matches!(result, Err(DecodeError::Integrity { .. })),
                "{operation}"
            );
            assert!(matches!(
                archive.member(0).await,
                Err(DecodeError::Poisoned)
            ));
        }
    }

    Ok(())
}

fn replace_payload(original: &[u8], start: usize, payload: &[u8], size: u32) -> Vec<u8> {
    // Keep a single entry and regenerate its directory/end offsets, so each
    // fixture reaches payload validation with mutually consistent headers.
    let central = original
        .windows(4)
        .rposition(|bytes| bytes == b"PK\x01\x02")
        .expect("central header");
    let end = original.len() - 22;

    let mut bytes = original[..start].to_vec();
    bytes.extend_from_slice(payload);

    let new_central = bytes.len();
    bytes.extend_from_slice(&original[central..end]);

    let central_size = bytes.len() - new_central;
    bytes.extend_from_slice(&original[end..]);

    for offset in [18, new_central + 20] {
        bytes[offset..offset + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    }
    for offset in [22, new_central + 24] {
        bytes[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
    }

    let end = bytes.len() - 22;
    bytes[end + 12..end + 16].copy_from_slice(&(central_size as u32).to_le_bytes());
    bytes[end + 16..end + 20].copy_from_slice(&(new_central as u32).to_le_bytes());

    bytes
}

#[tokio::test]
async fn rejects_deflate_size_lies_truncation_and_trailing_streams() -> TestResult {
    let bytes = include_bytes!("fixtures/single-deflate.zip");
    let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
    archive.validate_all().await?;
    let entry = archive.entries()[0].resolved().ok_or("unresolved entry")?;
    let start = entry.data_offset() as usize;
    let length = entry.directory().compressed_size() as usize;
    let encoded = &bytes[start..start + length];

    for (label, payload, size) in [
        ("short size", encoded.to_vec(), 1),
        ("long size", encoded.to_vec(), 1000),
        ("truncated", encoded[..encoded.len() - 1].to_vec(), 7),
        ("trailing byte", [encoded, &[0]].concat(), 7),
        ("concatenated stream", encoded.repeat(2), 7),
        ("invalid stream", vec![0xff; 5], 7),
    ] {
        let bytes = replace_payload(bytes, start, &payload, size);
        let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
        let Some(Member::File { payload, .. }) = archive.member(0).await? else {
            return Err(io::Error::other("expected file").into());
        };

        assert!(
            matches!(payload.skip().await, Err(DecodeError::Integrity { .. })),
            "{label}"
        );
    }

    Ok(())
}

struct Interruptible {
    source: Cursor<Vec<u8>>,
    interrupt: Rc<Cell<bool>>,
    read_bytes: Rc<Cell<usize>>,
}

impl AsyncRead for Interruptible {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.interrupt.get() && self.read_bytes.get() != 0 {
            return Poll::Pending;
        }

        let limit = if self.interrupt.get() {
            2
        } else {
            buffer.remaining()
        };
        let start = self.source.position() as usize;
        let length = limit
            .min(buffer.remaining())
            .min(self.source.get_ref().len() - start);

        buffer.put_slice(&self.source.get_ref()[start..start + length]);
        self.source.set_position((start + length) as u64);
        if self.interrupt.get() {
            self.read_bytes.set(length);
        }

        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for Interruptible {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        io::Seek::seek(&mut self.source, position)?;

        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.source.position()))
    }
}

#[tokio::test]
async fn cancellation_after_partial_io_poisoning_prevents_resume() -> TestResult {
    for operation in ["payload", "skip", "member", "validate", "reader"] {
        let interrupt = Rc::new(Cell::new(false));
        let read_bytes = Rc::new(Cell::new(0));
        let source = Interruptible {
            source: Cursor::new(STORED.to_vec()),
            interrupt: interrupt.clone(),
            read_bytes: read_bytes.clone(),
        };
        let mut archive = ZipArchive::open(source).await?;
        if operation == "reader" {
            // Leave a payload active so lending the reader must drain it.
            assert!(matches!(
                archive.member(1).await?,
                Some(Member::File { .. })
            ));
        }

        let mut future = Box::pin(async {
            if matches!(operation, "payload" | "skip") {
                let Some(Member::File { mut payload, .. }) = archive.member(1).await? else {
                    return Err(DecodeError::Io(io::Error::other("expected file")));
                };

                interrupt.set(true);
                if operation == "skip" {
                    payload.skip().await
                } else {
                    payload.next_chunk(&mut Vec::new(), 100).await.map(|_| ())
                }
            } else {
                interrupt.set(true);
                match operation {
                    "member" => archive.member(1).await.map(|_| ()),
                    "validate" => archive.validate_all().await,
                    _ => archive.reader_mut().await.map(|_| ()),
                }
            }
        });
        for _ in 0..2 {
            assert!(
                poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await
            );
        }
        assert_eq!(read_bytes.get(), 2, "{operation}");
        drop(future);

        assert!(
            matches!(archive.next_member().await, Err(DecodeError::Poisoned)),
            "{operation}"
        );
        assert!(matches!(
            archive.reader_mut().await,
            Err(DecodeError::Poisoned)
        ));
        assert!(matches!(
            archive.validate_all().await,
            Err(DecodeError::Poisoned)
        ));
    }

    Ok(())
}

#[tokio::test]
async fn extracts_with_shared_archive_policy() -> TestResult {
    let destination = tempfile::tempdir()?;
    let bytes = include_bytes!("fixtures/extract.zip");
    ZipArchive::open(Cursor::new(bytes))
        .await?
        .extract_in(destination.path(), ExtractPolicy::default())
        .await?;

    assert_eq!(
        std::fs::read(destination.path().join("nested/file"))?,
        b"payload"
    );

    Ok(())
}

#[tokio::test]
async fn projects_appnote_unix_links_and_compares_redundant_targets() -> TestResult {
    let mut archive =
        ZipArchive::open(Cursor::new(include_bytes!("fixtures/unix-links.zip"))).await?;

    assert!(
        matches!(archive.next_member().await?, Some(Member::SymbolicLink { target, .. }) if target == "target")
    );

    let Some(Member::HardLink {
        target,
        size,
        payload,
        ..
    }) = archive.next_member().await?
    else {
        return Err(io::Error::other("expected UNIX hard link").into());
    };

    assert_eq!(target, "target");
    assert_eq!(size, 0);
    payload.skip().await?;

    assert!(
        matches!(archive.next_member().await?, Some(Member::SymbolicLink { target, .. }) if target == "target")
    );

    assert!(matches!(
        archive.next_member().await,
        Err(DecodeError::Integrity { .. })
    ));

    Ok(())
}

#[tokio::test]
async fn interprets_external_attributes_according_to_the_host() -> TestResult {
    let original = include_bytes!("fixtures/empty-deflate.zip");
    let central = original
        .windows(4)
        .position(|bytes| bytes == b"PK\x01\x02")
        .ok_or("missing central header")?;

    for (host, dos, unix) in [
        (0, true, false),
        (3, true, true),
        (6, true, false),
        (10, true, false),
        (14, true, false),
        (19, true, true),
        (1, false, false),
    ] {
        for (attributes, directory, executable) in [
            (0x10u32, dos, false),
            (0o040755 << 16, unix, false),
            (0o100111 << 16, false, unix),
        ] {
            let mut bytes = original.to_vec();
            bytes[central + 5] = host;
            bytes[central + 38..central + 42].copy_from_slice(&attributes.to_le_bytes());
            let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;

            match archive.next_member().await? {
                Some(Member::Directory { .. }) => assert!(directory, "host {host}"),
                Some(Member::File {
                    executable: actual,
                    payload,
                    ..
                }) => {
                    assert!(!directory, "host {host}");
                    assert_eq!(actual, executable, "host {host}");
                    payload.skip().await?;
                }
                _ => return Err(io::Error::other("expected file or directory").into()),
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn validates_empty_deflate_streams_in_directories() -> TestResult {
    let bytes = include_bytes!("fixtures/empty-deflate.zip");
    let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;

    assert!(matches!(
        archive.member(1).await?,
        Some(Member::Directory { .. })
    ));
    assert!(archive.next_member().await?.is_none());

    let position = archive.entries()[1]
        .resolved()
        .ok_or("unresolved entry")?
        .data_offset() as usize;
    let mut corrupt = bytes.to_vec();
    corrupt[position] = 0xff;

    let mut archive = ZipArchive::open(Cursor::new(&corrupt)).await?;

    assert!(matches!(
        archive.member(1).await,
        Err(DecodeError::Integrity { .. })
    ));

    Ok(())
}

#[tokio::test]
async fn local_metadata_errors_poison_selection_and_full_validation() -> TestResult {
    let original = STORED;
    let archive = ZipArchive::open(Cursor::new(original)).await?;
    let mut corrupt = original.to_vec();
    corrupt[archive.entries()[1].directory().position() as usize + 30] ^= 1;

    for full_validation in [false, true] {
        let mut archive = ZipArchive::open(Cursor::new(&corrupt)).await?;
        let Some(Member::File { payload, .. }) = archive.member(2).await? else {
            return Err(io::Error::other("expected unaffected member").into());
        };
        assert_eq!(contents(payload).await?, b"UTF-8 filename");

        let result = if full_validation {
            archive.validate_all().await
        } else {
            archive.member(1).await.map(|_| ())
        };
        assert!(matches!(result, Err(DecodeError::Framing(_))));
        assert!(matches!(
            archive.member(2).await,
            Err(DecodeError::Poisoned)
        ));
    }

    Ok(())
}
