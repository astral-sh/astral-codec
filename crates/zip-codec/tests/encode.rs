use std::{
    cell::Cell,
    error::Error,
    future::{Future, poll_fn},
    io::{self, Cursor, SeekFrom},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use tokio::io::{AsyncSeek, AsyncWrite};
use zip_codec::{
    Archive, ArchiveBuilder, BuildError, CompressionMethod, EncodeError, EntryMetadata,
    FilePayload, Limits, Member, MemberPayload, ZipArchive, ZipEncoder, ZipFileOptions,
};
use zip_framing::write::{EntryKind, PendingMember};

#[cfg(unix)]
use tokio::fs::File;
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

async fn assert_cooperates<T>(operation: impl Future<Output = T>) -> T {
    let polled = Cell::new(false);
    let (result, ()) = tokio::join!(
        biased;
        async {
            let result = operation.await;
            assert!(polled.get(), "ready archive work must let another future run");
            result
        },
        async { polled.set(true) },
    );
    result
}

#[tokio::test]
async fn ready_sources_cooperate_during_encoding_indexing_and_decoding() -> TestResult {
    for method in [CompressionMethod::Stored, CompressionMethod::Deflate] {
        let source = vec![42; 256 * 64 * 1024];
        let output = assert_cooperates(async {
            let mut builder = ZipEncoder::new(Cursor::new(Vec::new()))
                .with_compression(method)
                .builder();
            for index in 0..256 {
                builder
                    .add_file(
                        format!("small-{index}"),
                        b"x".as_slice(),
                        EntryMetadata::default(),
                    )
                    .await?;
            }
            builder
                .add_file("large", source.as_slice(), EntryMetadata::default())
                .await?;
            builder.finish_into_inner().await
        })
        .await?
        .into_inner();

        let mut archive = assert_cooperates(ZipArchive::open(output)).await?;
        let decoded = assert_cooperates(async {
            let mut decoded = 0;
            let mut chunk = Vec::new();
            while let Some(member) = archive.next_member().await? {
                let Member::File { mut payload, .. } = member else {
                    return Err(io::Error::other("expected encoded file").into());
                };
                while payload.next_chunk(&mut chunk, 64 * 1024).await? {
                    decoded += chunk.len();
                }
            }
            Ok::<_, Box<dyn Error>>(decoded)
        })
        .await?;
        assert_eq!(decoded, source.len() + 256);
    }
    Ok(())
}

#[tokio::test]
async fn streams_stored_and_deflate_payloads_with_matching_zip64_records() -> TestResult {
    for method in [CompressionMethod::Stored, CompressionMethod::Deflate] {
        for length in [0, 1, 131_089, 2 * 1024 * 1024 + 3] {
            let source = source_bytes(length);
            let mut builder = ZipEncoder::new(Cursor::new(Vec::new()))
                .with_compression(method)
                .builder();
            builder.add_directory("directory").await?;
            builder
                .add_file(
                    "directory/café",
                    FilePayload::new(source.len() as u64, Cursor::new(&source)),
                    EntryMetadata::default().executable(true),
                )
                .await?;
            let output = builder.finish_into_inner().await?.into_inner();

            let mut archive = ZipArchive::open(output).await?;
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
async fn per_file_compression_overrides_preserve_encoder_defaults() -> TestResult {
    let source = b"contents contents contents".as_slice();

    for default_method in [CompressionMethod::Stored, CompressionMethod::Deflate] {
        let cases = [
            (
                "stored",
                ZipFileOptions::default().with_compression(CompressionMethod::Stored),
                source,
                CompressionMethod::Stored,
            ),
            (
                "default-after-stored",
                ZipFileOptions::default(),
                source,
                default_method,
            ),
            (
                "deflated",
                ZipFileOptions::default().with_compression(CompressionMethod::Deflate),
                source,
                CompressionMethod::Deflate,
            ),
            (
                "default-after-deflated",
                ZipFileOptions::default(),
                source,
                default_method,
            ),
            (
                "empty",
                ZipFileOptions::default().with_compression(CompressionMethod::Deflate),
                b"".as_slice(),
                CompressionMethod::Stored,
            ),
        ];
        let mut builder = ZipEncoder::new(Cursor::new(Vec::new()))
            .with_compression(default_method)
            .builder();

        for (path, options, contents, _) in cases {
            builder
                .add_file_with_options(path, contents, EntryMetadata::default(), options)
                .await?;
        }

        let mut archive = ZipArchive::open(builder.finish_into_inner().await?.into_inner()).await?;
        assert_eq!(archive.entries().len(), cases.len());

        for (index, (path, _, contents, method)) in cases.into_iter().enumerate() {
            assert_eq!(
                archive.entries()[index].directory().method(),
                method,
                "{path}"
            );

            let Some(Member::File {
                metadata,
                mut payload,
                ..
            }) = archive.next_member().await?
            else {
                return Err(io::Error::other("expected encoded file").into());
            };
            assert_eq!(metadata.path, path);

            let mut decoded = Vec::new();
            let mut chunk = Vec::new();
            while payload.next_chunk(&mut chunk, usize::MAX).await? {
                decoded.extend_from_slice(&chunk);
            }

            assert_eq!(decoded, contents, "{path}");
        }
    }

    Ok(())
}

#[tokio::test]
async fn finalizes_empty_archives_and_recovers_from_preflight_failures() -> TestResult {
    let output = ZipEncoder::new(Cursor::new(Vec::new()))
        .builder()
        .finish_into_inner()
        .await?
        .into_inner();

    assert!(ZipArchive::open(output).await?.entries().is_empty());

    let header = PendingMember::new(
        "file",
        CompressionMethod::Deflate,
        EntryKind::File { executable: false },
    )?;
    let limits = Limits {
        metadata_size: header.local_header_size() as u64 + header.central_header_size() as u64,
        ..Limits::default()
    };
    for limits in [
        Limits {
            member_size: 3,
            ..limits
        },
        Limits {
            total_size: 3,
            ..limits
        },
    ] {
        let mut builder = ZipEncoder::new(Cursor::new(Vec::new()))
            .with_limits(limits)
            .builder();
        assert!(matches!(
            builder
                .add_file("file", &b"long"[..], EntryMetadata::default())
                .await,
            Err(BuildError::Encoder(_))
        ));

        builder
            .add_file("file", &b"ok"[..], EntryMetadata::default())
            .await?;
        assert!(matches!(
            builder
                .add_file("next", &b""[..], EntryMetadata::default())
                .await,
            Err(BuildError::Encoder(EncodeError::Limit { resource: "metadata bytes", limit }))
                if limit == limits.metadata_size
        ));
        let output = builder.finish_into_inner().await?.into_inner();

        assert_eq!(ZipArchive::open(output).await?.entries().len(), 1);
    }

    Ok(())
}

#[derive(Default)]
struct FailingWriter {
    inner: Cursor<Vec<u8>>,
    remaining: usize,
    fail_flush: bool,
    pause_write: bool,
    fail_seek: Option<usize>,
    pause_seek: Option<usize>,
    seeks: Rc<Cell<usize>>,
}

impl AsyncWrite for FailingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pause_write && !self.inner.get_ref().is_empty() {
            return Poll::Pending;
        }

        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::other("injected write error")));
        }

        let length = bytes.len().min(self.remaining);
        self.remaining -= length;

        Pin::new(&mut self.inner).poll_write(context, &bytes[..length])
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

impl AsyncSeek for FailingWriter {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        self.seeks.set(self.seeks.get() + 1);
        Pin::new(&mut self.inner).start_seek(position)
    }

    fn poll_complete(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<u64>> {
        if self.fail_seek == Some(self.seeks.get()) {
            return Poll::Ready(Err(io::Error::other("injected seek error")));
        }

        // The cancellation test drops the future when this seek becomes pending.
        if self.pause_seek == Some(self.seeks.get()) {
            return Poll::Pending;
        }

        Pin::new(&mut self.inner).poll_complete(context)
    }
}

#[tokio::test]
async fn output_and_short_source_errors_poison_builders() -> TestResult {
    for remaining in [0, 1, 55, 80] {
        let mut builder = ZipEncoder::new(FailingWriter {
            remaining,
            ..FailingWriter::default()
        })
        .builder();

        let result = builder
            .add_file("file", &b"payload"[..], EntryMetadata::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));
    }

    for fail_seek in [1, 2] {
        let mut builder = ZipEncoder::new(FailingWriter {
            remaining: usize::MAX,
            fail_seek: Some(fail_seek),
            ..FailingWriter::default()
        })
        .builder();

        assert!(
            builder
                .add_file("file", &b"payload"[..], EntryMetadata::default())
                .await
                .is_err()
        );
        assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));
    }

    let mut builder = ZipEncoder::new(Cursor::new(Vec::new())).builder();
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
        ..FailingWriter::default()
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
    for pause_seek in [None, Some(1), Some(2)] {
        let mut writer = FailingWriter {
            remaining: usize::MAX,
            pause_write: pause_seek.is_none(),
            pause_seek,
            ..FailingWriter::default()
        };
        let seeks = Rc::clone(&writer.seeks);
        let mut builder = ZipEncoder::new(&mut writer).builder();

        {
            let mut future =
                Box::pin(builder.add_file("file", &b"payload"[..], EntryMetadata::default()));
            poll_fn(|context| {
                assert!(future.as_mut().poll(context).is_pending());

                if pause_seek.is_none_or(|count| seeks.get() == count) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }

        assert!(matches!(builder.finish().await, Err(BuildError::Poisoned)));
        assert!(!writer.inner.get_ref().is_empty());
    }

    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn recursive_build_preserves_symlink_payloads() -> TestResult {
    let source = tempfile::tempdir()?;
    std::fs::write(source.path().join("target"), b"payload")?;
    std::os::unix::fs::symlink("target", source.path().join("link"))?;

    let mut builder = ZipEncoder::new(File::from_std(tempfile::tempfile()?))
        .builder()
        .with_policy(BuilderPolicy::default().symlink_policy(SymlinkPolicy::Preserve));
    builder.add_directory_all(source.path()).await?;
    let output = builder.finish_into_inner().await?.into_inner();

    let mut members = ZipArchive::open(output).await?.members();
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
