use std::{
    cell::Cell,
    error::Error,
    future::{Future, poll_fn},
    io::{self, Cursor, SeekFrom, Write},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use flate2::{Compression, Crc, write::DeflateEncoder};
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt, ReadBuf};
use zip_codec::{
    Archive, CompressionMethod, DecodeError, EntryKind as DecodedEntryKind, Member, MemberPayload,
    ZipArchive, extract::ExtractPolicy,
};
use zip_framing::{
    Error as FrameError,
    write::{EntryKind, PendingMember, end_records},
};

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

fn member_with_attributes(payload: &[u8], attributes: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut crc = Crc::new();
    crc.update(payload);
    let member = PendingMember::new(
        "member",
        CompressionMethod::Stored,
        EntryKind::File { executable: false },
    )?
    .finish(crc.sum(), payload.len() as u64, payload.len() as u64, 0)?;
    let mut bytes = member.local_header();
    bytes.extend_from_slice(payload);
    let offset = bytes.len() as u64;
    let mut central = member.central_header();
    central[38..42].copy_from_slice(&attributes.to_le_bytes());
    let size = central.len() as u64;
    bytes.extend(central);
    bytes.extend(end_records(1, offset, size)?);

    Ok(bytes)
}

#[tokio::test]
async fn enforces_kind_projection_after_metadata_resolution() -> TestResult {
    for (attributes, expected_kind, expected_error) in [
        (0x08, Some(DecodedEntryKind::VolumeLabel), "volume label"),
        (
            0o140600 << 16,
            Some(DecodedEntryKind::Socket),
            "unsupported file attributes",
        ),
        (
            0o030600 << 16,
            Some(DecodedEntryKind::Unknown(0o030000)),
            "unsupported file attributes",
        ),
        (
            (0o100644 << 16) | 0x10,
            None,
            "inconsistent file attributes",
        ),
    ] {
        let bytes = member_with_attributes(&[], attributes)?;
        for full_validation in [false, true] {
            let mut archive = ZipArchive::open(Cursor::new(&bytes)).await?;
            let result = if full_validation {
                archive.validate_all().await
            } else {
                archive.member(0).await.map(|_| ())
            };

            if let Some(expected_kind) = expected_kind {
                assert!(
                    matches!(result, Err(DecodeError::Unsupported { position: 0, feature }) if feature == expected_error)
                );
                assert_eq!(
                    archive.resolved(0).ok_or("unresolved entry")?.kind(),
                    expected_kind
                );
            } else {
                assert!(
                    matches!(result, Err(DecodeError::Framing(FrameError::Invalid { position: 0, reason })) if reason == expected_error)
                );
                assert!(archive.resolved(0).is_none());
            }

            assert!(matches!(
                archive.member(0).await,
                Err(DecodeError::Poisoned)
            ));
        }
    }

    Ok(())
}

#[tokio::test]
async fn limits_symbolic_link_targets_in_the_codec() -> TestResult {
    for length in [usize::from(u16::MAX), usize::from(u16::MAX) + 1] {
        let bytes = member_with_attributes(&vec![b'x'; length], 0o120777 << 16)?;
        for full_validation in [false, true] {
            let mut archive = ZipArchive::open(Cursor::new(&bytes)).await?;
            let result = if full_validation {
                archive.validate_all().await
            } else {
                archive.member(0).await.map(|_| ())
            };
            assert_eq!(
                archive.resolved(0).ok_or("unresolved entry")?.kind(),
                DecodedEntryKind::SymbolicLink
            );

            if length == usize::from(u16::MAX) {
                result?;
            } else {
                assert!(matches!(
                    result,
                    Err(DecodeError::Integrity {
                        position: 0,
                        reason: "oversized symbolic-link target",
                    })
                ));
                assert!(matches!(
                    archive.member(0).await,
                    Err(DecodeError::Poisoned)
                ));
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn reads_python_archives_and_projects_members() -> TestResult {
    for (label, bytes) in FIXTURES {
        // Short reads must work across headers, descriptors, and payloads,
        // including when a DEFLATE input buffer needs more than one read.
        let mut members = ZipArchive::open(Interruptible {
            source: Cursor::new(bytes.to_vec()),
            interrupt: Rc::new(Cell::new(false)),
            read_bytes: Rc::new(Cell::new(0)),
            max_read: 3,
            yield_reads: true,
            pending: false,
        })
        .await?
        .members();

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
        for initial_length in [0, 16] {
            let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
            let Some(Member::File {
                size, mut payload, ..
            }) = archive.member(index).await?
            else {
                return Err(io::Error::other("expected file").into());
            };

            let mut buffer = vec![0xa5; initial_length];
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
    }

    Ok(())
}

#[tokio::test]
async fn appends_remaining_payload_and_preserves_prefixes() -> TestResult {
    for bytes in [STORED, DEFLATE] {
        let mut archive = ZipArchive::open(Interruptible {
            source: Cursor::new(bytes.to_vec()),
            interrupt: Rc::new(Cell::new(false)),
            read_bytes: Rc::new(Cell::new(0)),
            max_read: 3,
            yield_reads: true,
            pending: false,
        })
        .await?;
        let Some(Member::File { mut payload, .. }) = archive.member(1).await? else {
            return Err(io::Error::other("expected file").into());
        };
        let expected = b"hello ZIP\n".repeat(14000);
        let mut first = Vec::new();
        assert!(payload.next_chunk(&mut first, 7).await?);
        assert_eq!(first, expected[..first.len()]);

        let mut output = b"prefix".to_vec();
        assert_eq!(
            payload.read_to_end(&mut output).await?,
            expected.len() - first.len()
        );
        assert_eq!(&output[..6], b"prefix");
        assert_eq!(&output[6..], &expected[first.len()..]);
        let previous = output.clone();
        assert_eq!(payload.read_to_end(&mut output).await?, 0);
        assert_eq!(output, previous);

        let Some(Member::File { mut payload, .. }) = archive.member(3).await? else {
            return Err(io::Error::other("expected empty file").into());
        };
        assert_eq!(payload.read_to_end(&mut output).await?, 0);
        assert_eq!(output, previous);
    }

    // A compressed empty stream still invokes the decoder, which must not
    // expose scratch bytes appended while looking for output.
    let mut archive = ZipArchive::open(Cursor::new(
        include_bytes!("fixtures/empty-deflate.zip").as_slice(),
    ))
    .await?;
    let Some(Member::File { mut payload, .. }) = archive.member(0).await? else {
        return Err(io::Error::other("expected empty DEFLATE file").into());
    };
    let mut output = b"prefix".to_vec();
    assert_eq!(payload.read_to_end(&mut output).await?, 0);
    assert_eq!(output, b"prefix");
    Ok(())
}

#[tokio::test]
async fn seeks_by_index_and_drains_partially_read_payloads() -> TestResult {
    for bytes in [STORED, DEFLATE] {
        let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
        assert_eq!(archive.entries().len(), 5);
        assert_eq!(archive.entries()[1].directory().path(), "directory/file");
        assert!(archive.resolved(1).is_none());

        {
            let Some(Member::File { mut payload, .. }) = archive.member(1).await? else {
                return Err(io::Error::other("expected file").into());
            };

            let mut chunk = Vec::new();
            assert!(payload.next_chunk(&mut chunk, 1).await?);
            assert_eq!(chunk, b"h");
        }

        let entry = archive.resolved(1).ok_or("unresolved entry")?;
        assert_eq!(entry.directory().path(), "directory/file");
        assert_eq!(entry.directory().size(), 140_000);
        assert!(entry.data_offset() > entry.directory().position());
        assert!(archive.resolved(2).is_none());

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
        for entry_index in [1, 2] {
            let position = archive
                .resolved(entry_index)
                .ok_or("unresolved entry")?
                .data_offset() as usize;

            for operation in ["read", "collect", "skip", "drop", "reader", "validate"] {
                let mut bytes = original.to_vec();
                bytes[position] ^= 0x40;

                let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
                let Some(Member::File { mut payload, .. }) = archive.member(entry_index).await?
                else {
                    return Err(io::Error::other("expected corrupt file").into());
                };

                let result = match operation {
                    "read" => contents(payload).await.map(|_| ()),
                    "collect" => payload.read_to_end(&mut Vec::new()).await.map(|_| ()),
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
    }

    Ok(())
}

#[tokio::test]
async fn rejects_deflate_size_lies_truncation_and_trailing_streams() -> TestResult {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"payload")?;
    let encoded = encoder.finish()?;
    let mut crc = Crc::new();
    crc.update(b"payload");

    for (label, payload, size) in [
        ("short size", encoded.clone(), 1),
        ("long size", encoded.clone(), 1000),
        ("truncated", encoded[..encoded.len() - 1].to_vec(), 7),
        ("trailing byte", [encoded.as_slice(), &[0]].concat(), 7),
        // StreamEnd can arrive while declared bytes remain outside the input buffer.
        (
            "unread trailing bytes",
            [encoded.as_slice(), &vec![0; 64 * 1024]].concat(),
            7,
        ),
        ("concatenated stream", encoded.repeat(2), 7),
        ("invalid stream", vec![0xff; 5], 7),
    ] {
        let member = PendingMember::new(
            "file",
            CompressionMethod::Deflate,
            EntryKind::File { executable: false },
        )?
        .finish(crc.sum(), payload.len() as u64, size, 0)?;
        let mut bytes = member.local_header();
        bytes.extend(payload);
        let central_offset = bytes.len() as u64;
        let central = member.central_header();
        let central_size = central.len() as u64;
        bytes.extend(central);
        bytes.extend(end_records(1, central_offset, central_size)?);
        for collect in [false, true] {
            let mut archive = ZipArchive::open(Cursor::new(&bytes)).await?;
            let Some(Member::File { mut payload, .. }) = archive.member(0).await? else {
                return Err(io::Error::other("expected file").into());
            };

            let result = if collect {
                payload.read_to_end(&mut Vec::new()).await.map(|_| ())
            } else {
                payload.skip().await
            };
            assert!(
                matches!(result, Err(DecodeError::Integrity { .. })),
                "{label}"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn reads_nested_zip_payload_without_interpreting_its_records() -> TestResult {
    let mut archive =
        ZipArchive::open(Cursor::new(member_with_attributes(STORED, 0o100644 << 16)?)).await?;
    assert_eq!(archive.entries().len(), 1);
    let Some(Member::File { payload, .. }) = archive.next_member().await? else {
        return Err(io::Error::other("expected outer file").into());
    };
    assert_eq!(contents(payload).await?, STORED);
    assert!(archive.next_member().await?.is_none());

    Ok(())
}

struct Interruptible {
    source: Cursor<Vec<u8>>,
    interrupt: Rc<Cell<bool>>,
    read_bytes: Rc<Cell<usize>>,
    max_read: usize,
    yield_reads: bool,
    pending: bool,
}

impl AsyncRead for Interruptible {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.interrupt.get() && self.read_bytes.get() != 0 {
            return Poll::Pending;
        }
        if self.pending {
            self.pending = false;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }

        let limit = if self.interrupt.get() {
            2
        } else {
            self.max_read
        };
        let start = self.source.position() as usize;
        let length = limit
            .min(buffer.remaining())
            .min(self.source.get_ref().len() - start);

        buffer.put_slice(&self.source.get_ref()[start..start + length]);
        self.source.set_position((start + length) as u64);
        self.pending = self.yield_reads;
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
    for operation in ["payload", "collect", "skip", "member", "validate", "reader"] {
        let interrupt = Rc::new(Cell::new(false));
        let read_bytes = Rc::new(Cell::new(0));
        let source = Interruptible {
            source: Cursor::new(STORED.to_vec()),
            interrupt: interrupt.clone(),
            read_bytes: read_bytes.clone(),
            max_read: usize::MAX,
            yield_reads: false,
            pending: false,
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
            if matches!(operation, "payload" | "collect" | "skip") {
                let Some(Member::File { mut payload, .. }) = archive.member(1).await? else {
                    return Err(DecodeError::Io(io::Error::other("expected file")));
                };

                interrupt.set(true);
                match operation {
                    "skip" => payload.skip().await,
                    "collect" => payload.read_to_end(&mut Vec::new()).await.map(|_| ()),
                    _ => payload.next_chunk(&mut Vec::new(), 100).await.map(|_| ()),
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
async fn validates_empty_deflate_streams_in_directories() -> TestResult {
    let bytes = include_bytes!("fixtures/empty-deflate.zip");
    let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;

    assert!(matches!(
        archive.member(1).await?,
        Some(Member::Directory { .. })
    ));
    assert!(archive.next_member().await?.is_none());

    let position = archive.resolved(1).ok_or("unresolved entry")?.data_offset() as usize;
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
