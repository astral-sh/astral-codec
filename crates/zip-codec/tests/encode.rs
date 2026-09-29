use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Cursor},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;
use zip_codec::{
    Archive, ArchiveBuilder, BuildError, CompressionMethod, EntryMetadata, FilePayload, Limits,
    Member, MemberPayload, ZipArchive, ZipEncoder,
};

#[cfg(unix)]
use zip_codec::builder::{BuilderPolicy, SymlinkPolicy};

type TestResult = Result<(), Box<dyn Error>>;

fn source_bytes(length: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;

    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;

            state as u8
        })
        .collect()
}

#[tokio::test]
async fn streams_stored_and_deflate_payloads_with_matching_zip64_records() -> TestResult {
    for method in [CompressionMethod::Stored, CompressionMethod::Deflate] {
        for length in [0, 1, 131_089, 2 * 1024 * 1024 + 3] {
            let source = source_bytes(length);
            let mut builder = ZipEncoder::new(Vec::new()).compression(method).builder();
            builder.add_directory("directory").await?;
            builder
                .add_file(
                    "directory/café",
                    FilePayload::new(source.len() as u64, Cursor::new(&source)),
                    EntryMetadata::default().executable(true),
                )
                .await?;
            let bytes = builder.finish_into_inner().await?.into_inner();

            let mut archive = ZipArchive::open(Cursor::new(bytes)).await?;
            assert_eq!(archive.entries().len(), 2);
            assert!(matches!(
                archive.next_member().await?,
                Some(Member::Directory { .. })
            ));

            let Some(Member::File {
                metadata,
                size,
                executable,
                mut payload,
            }) = archive.next_member().await?
            else {
                return Err(io::Error::other("expected encoded file").into());
            };

            assert_eq!(metadata.path, "directory/café");
            assert_eq!(size, source.len() as u64);
            assert!(executable);

            let mut decoded = Vec::new();
            let mut chunk = Vec::new();
            while payload.next_chunk(&mut chunk, usize::MAX).await? {
                assert!(chunk.len() <= 64 * 1024);
                decoded.extend_from_slice(&chunk);
            }

            assert_eq!(decoded, source, "{method:?}, length={length}");
            assert!(archive.next_member().await?.is_none());
        }
    }

    Ok(())
}

#[tokio::test]
async fn finalizes_empty_archives_and_recovers_from_preflight_failures() -> TestResult {
    let bytes = ZipEncoder::new(Vec::new())
        .builder()
        .finish_into_inner()
        .await?
        .into_inner();

    assert!(
        ZipArchive::open(Cursor::new(bytes))
            .await?
            .entries()
            .is_empty()
    );

    for limits in [
        Limits {
            member_size: 3,
            ..Limits::default()
        },
        Limits {
            total_size: 3,
            ..Limits::default()
        },
    ] {
        let mut builder = ZipEncoder::new(Vec::new()).limits(limits).builder();
        assert!(matches!(
            builder
                .add_file("file", &b"long"[..], EntryMetadata::default())
                .await,
            Err(BuildError::Encoder(_))
        ));

        builder
            .add_file("file", &b"ok"[..], EntryMetadata::default())
            .await?;
        let bytes = builder.finish_into_inner().await?.into_inner();

        assert_eq!(
            ZipArchive::open(Cursor::new(bytes)).await?.entries().len(),
            1
        );
    }

    Ok(())
}

struct FailingWriter {
    remaining: usize,
    fail_flush: bool,
}

impl AsyncWrite for FailingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::other("injected write error")));
        }

        let length = bytes.len().min(self.remaining);
        self.remaining -= length;

        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(if self.fail_flush {
            Err(io::Error::other("injected flush error"))
        } else {
            Ok(())
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn output_and_short_source_errors_poison_builders() -> TestResult {
    for remaining in [0, 1, 55, 80] {
        let mut builder = ZipEncoder::new(FailingWriter {
            remaining,
            fail_flush: false,
        })
        .builder();

        let result = builder
            .add_file("file", &b"payload"[..], EntryMetadata::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));
    }

    let mut builder = ZipEncoder::new(Vec::new()).builder();
    let payload = FilePayload::new(100, Cursor::new(b"short"));

    assert!(
        builder
            .add_file("file", payload, EntryMetadata::default())
            .await
            .is_err()
    );

    assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));

    let builder = ZipEncoder::new(FailingWriter {
        remaining: usize::MAX,
        fail_flush: true,
    })
    .builder();

    assert!(matches!(
        builder.finish().await,
        Err(BuildError::Encoder(_))
    ));

    Ok(())
}

#[tokio::test]
async fn cancellation_after_output_starts_poisoning_the_builder() -> TestResult {
    let mut bytes = Vec::new();
    let mut builder = ZipEncoder::new(&mut bytes).builder();

    {
        let mut future =
            Box::pin(builder.add_file("file", &b"payload"[..], EntryMetadata::default()));
        assert!(poll_fn(|context| Poll::Ready(future.as_mut().poll(context).is_pending())).await);
    }

    assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));
    assert!(!bytes.is_empty());

    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_build_preserves_symlink_payloads() -> TestResult {
    let source = tempfile::tempdir()?;
    std::fs::write(source.path().join("target"), b"payload")?;
    std::os::unix::fs::symlink("target", source.path().join("link"))?;

    let mut builder = ZipEncoder::new(Vec::new())
        .builder()
        .with_policy(BuilderPolicy::default().symlink_policy(SymlinkPolicy::Preserve));
    builder.add_directory_all(source.path()).await?;
    let bytes = builder.finish_into_inner().await?.into_inner();

    let mut members = ZipArchive::open(Cursor::new(bytes)).await?.members();
    let mut found = false;
    while let Some(member) = members.next().await? {
        if let Member::SymbolicLink { target, .. } = member {
            assert_eq!(target, "target");
            found = true;
        }
    }

    assert!(found);

    Ok(())
}
