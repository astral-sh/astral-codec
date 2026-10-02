use std::{fmt, hint::black_box, io::Cursor};

use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use zip_codec::{
    Archive, ArchiveBuilder, CompressionMethod, EntryMetadata, Member, MemberPayload, ZipArchive,
    ZipEncoder,
};

const LARGE_FILE_BYTES: usize = 4 * 1024 * 1024;
const SMALL_FILE_BYTES: usize = 1024;
const SMALL_FILE_COUNT: usize = 1024;
const PAYLOAD_CHUNK_BYTES: usize = 64 * 1024;

struct Case {
    id: &'static str,
    method: CompressionMethod,
    entry_count: usize,
    file_bytes: usize,
    incompressible: bool,
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{}-entries/{:?}",
            self.id, self.entry_count, self.method
        )
    }
}

struct Entry {
    path: String,
    data: Vec<u8>,
}

struct Fixture {
    entries: Vec<Entry>,
    archive: Vec<u8>,
    payload_bytes: u64,
}

fn runtime() -> Runtime {
    RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build")
}

fn cases() -> impl Iterator<Item = Case> {
    [CompressionMethod::Stored, CompressionMethod::Deflate]
        .into_iter()
        .flat_map(|method| {
            [
                ("large-compressible", 1, LARGE_FILE_BYTES, false),
                ("large-incompressible", 1, LARGE_FILE_BYTES, true),
                ("many-small", SMALL_FILE_COUNT, SMALL_FILE_BYTES, false),
            ]
            .into_iter()
            .map(move |(id, entry_count, file_bytes, incompressible)| Case {
                id,
                method,
                entry_count,
                file_bytes,
                incompressible,
            })
        })
}

fn payload(length: usize, salt: usize, incompressible: bool) -> Vec<u8> {
    let mut state = 0x1234_5678u32.wrapping_add(salt as u32);
    (0..length)
        .map(|index| {
            if incompressible {
                // Deterministic xorshift bytes, matching the encoder test fixtures.
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            } else {
                ((index + salt) % 251) as u8
            }
        })
        .collect()
}

fn fixture(case: &Case, runtime: &Runtime) -> Fixture {
    let entries: Vec<_> = (0..case.entry_count)
        .map(|index| Entry {
            path: format!("package/file-{index:04}.bin"),
            data: payload(case.file_bytes, index, case.incompressible),
        })
        .collect();
    let archive = runtime.block_on(encode_archive(&entries, case.method));
    // Check paths, methods, and every decoded byte outside the measurement.
    runtime.block_on(validate_fixture(&archive, &entries, case.method));
    Fixture {
        entries,
        archive,
        payload_bytes: (case.entry_count * case.file_bytes) as u64,
    }
}

async fn encode_archive(entries: &[Entry], method: CompressionMethod) -> Vec<u8> {
    let mut builder = ZipEncoder::new(Cursor::new(Vec::new()))
        .with_compression(method)
        .builder();
    for entry in entries {
        builder
            .add_file(&entry.path, entry.data.as_slice(), EntryMetadata::default())
            .await
            .expect("fixture file should encode");
    }
    builder
        .finish_into_inner()
        .await
        .expect("fixture archive should finish")
        .into_inner()
        .into_inner()
}

async fn validate_fixture(bytes: &[u8], entries: &[Entry], method: CompressionMethod) {
    let mut archive = ZipArchive::open(Cursor::new(bytes))
        .await
        .expect("fixture archive should open");
    assert_eq!(archive.entries().len(), entries.len());
    let mut chunk = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(archive.entries()[index].directory().method(), method);
        let member = archive
            .next_member()
            .await
            .expect("fixture member should decode");
        assert!(matches!(member, Some(Member::File { .. })));
        if let Some(Member::File {
            metadata,
            size,
            mut payload,
            ..
        }) = member
        {
            assert_eq!(metadata.path, entry.path);
            assert_eq!(size, entry.data.len() as u64);
            let mut offset = 0;
            while payload
                .next_chunk(&mut chunk, PAYLOAD_CHUNK_BYTES)
                .await
                .expect("fixture payload should decode")
            {
                assert_eq!(chunk, entry.data[offset..offset + chunk.len()]);
                offset += chunk.len();
            }
            assert_eq!(offset, entry.data.len());
        }
    }
    assert!(
        archive
            .next_member()
            .await
            .expect("fixture archive should end")
            .is_none()
    );
}

async fn decode_members(archive: &mut ZipArchive<Cursor<&[u8]>>) -> (usize, u64) {
    let mut entries = 0;
    let mut payload_bytes = 0;
    let mut chunk = Vec::new();
    while let Some(Member::File { mut payload, .. }) = archive
        .next_member()
        .await
        .expect("fixture member should decode")
    {
        entries += 1;
        while payload
            .next_chunk(&mut chunk, PAYLOAD_CHUNK_BYTES)
            .await
            .expect("fixture payload should decode")
        {
            payload_bytes += black_box(&chunk).len() as u64;
        }
    }
    (entries, payload_bytes)
}

#[divan::bench(args = cases())]
fn encode(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(case, &runtime);
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        .bench_local(|| {
            black_box(runtime.block_on(encode_archive(black_box(&fixture.entries), case.method)));
        });
}

#[divan::bench(args = cases(), sample_size = 1)]
fn decode_payload(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(case, &runtime);
    let mut archive = runtime
        .block_on(ZipArchive::open(Cursor::new(fixture.archive.as_slice())))
        .expect("fixture archive should open");
    assert_eq!(
        runtime.block_on(decode_members(&mut archive)),
        (fixture.entries.len(), fixture.payload_bytes)
    );
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        // Directory indexing is measured separately in zip-framing. Each input
        // starts with unresolved local records and unread payloads.
        .with_inputs(|| {
            runtime
                .block_on(ZipArchive::open(Cursor::new(fixture.archive.as_slice())))
                .expect("fixture archive should open")
        })
        .bench_local_refs(|archive| {
            black_box(runtime.block_on(decode_members(black_box(archive))));
        });
}

fn main() {
    divan::main();
}
