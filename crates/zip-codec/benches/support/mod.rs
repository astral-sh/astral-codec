use std::{fmt, io::Cursor};

use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use zip_codec::{
    Archive, ArchiveBuilder, CompressionMethod, EntryMetadata, Member, MemberPayload, ZipArchive,
    ZipEncoder,
};

const LARGE_FILE_BYTES: usize = 4 * 1024 * 1024;
const SMALL_FILE_BYTES: usize = 1024;
const SMALL_FILE_COUNT: usize = 1024;
pub(super) const PAYLOAD_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) struct Case {
    id: &'static str,
    pub(super) method: CompressionMethod,
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

pub(super) struct Entry {
    pub(super) path: String,
    pub(super) data: Vec<u8>,
}

pub(super) struct Fixture {
    pub(super) entries: Vec<Entry>,
    pub(super) archive: Vec<u8>,
    pub(super) payload_bytes: u64,
}

pub(super) fn runtime() -> Runtime {
    RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build")
}

pub(super) fn cases() -> impl Iterator<Item = Case> {
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

pub(super) fn fixture(case: &Case, runtime: &Runtime) -> Fixture {
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

pub(super) async fn encode_archive(entries: &[Entry], method: CompressionMethod) -> Vec<u8> {
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

pub(super) async fn validate_fixture(bytes: &[u8], entries: &[Entry], method: CompressionMethod) {
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
