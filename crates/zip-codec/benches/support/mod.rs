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
    file_sizes: &'static [usize],
    content: Content,
}

#[derive(Clone, Copy)]
enum Content {
    Repeating,
    Random,
    Package,
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
                (
                    "large-compressible",
                    1,
                    &[LARGE_FILE_BYTES][..],
                    Content::Repeating,
                ),
                (
                    "large-incompressible",
                    1,
                    &[LARGE_FILE_BYTES][..],
                    Content::Random,
                ),
                (
                    "many-small",
                    SMALL_FILE_COUNT,
                    &[SMALL_FILE_BYTES][..],
                    Content::Repeating,
                ),
                ("small", 1, &[128][..], Content::Repeating),
                (
                    "mixed-package",
                    64,
                    &[64, 128, 512, 1024, 4096, 16384, 65536, 262144][..],
                    Content::Package,
                ),
            ]
            .into_iter()
            .map(move |(id, entry_count, file_sizes, content)| Case {
                id,
                method,
                entry_count,
                file_sizes,
                content,
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

pub(super) fn entries(case: &Case) -> Vec<Entry> {
    (0..case.entry_count)
        .map(|index| {
            let length = case.file_sizes[index % case.file_sizes.len()];
            let (path, data) = match case.content {
                Content::Package if index % 8 != 7 => {
                    // Synthetic source and metadata files, with varying lengths
                    // and contents. Every eighth member is a larger binary file.
                    let source = format!(
                        "# package/module_{index}.py\n\
                         def describe(value):\n    return {{\"module\": {index}, \"value\": value}}\n"
                    );
                    (
                        format!("package/subpackage_{}/module_{index}.py", index / 8),
                        source.bytes().cycle().take(length).collect(),
                    )
                }
                Content::Package | Content::Random => (
                    format!("package/file-{index:04}.bin"),
                    payload(length, index, true),
                ),
                Content::Repeating => (
                    format!("package/file-{index:04}.bin"),
                    payload(length, index, false),
                ),
            };
            Entry { path, data }
        })
        .collect()
}

pub(super) fn fixture(case: &Case, runtime: &Runtime) -> Fixture {
    let entries = entries(case);
    let archive = runtime.block_on(encode_archive(&entries, case.method, 0));
    // Check paths, methods, and every decoded byte outside the measurement.
    runtime.block_on(validate_fixture(&archive, &entries, case.method));
    let payload_bytes = entries.iter().map(|entry| entry.data.len() as u64).sum();
    Fixture {
        entries,
        archive,
        payload_bytes,
    }
}

pub(super) async fn encode_archive(
    entries: &[Entry],
    method: CompressionMethod,
    output_capacity: usize,
) -> Vec<u8> {
    let mut builder = ZipEncoder::new(Cursor::new(Vec::with_capacity(output_capacity)))
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
