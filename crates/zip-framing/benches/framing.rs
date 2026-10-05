use std::{fmt, hint::black_box, io::Cursor};

use divan::{Bencher, counter::ItemsCount};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use zip_framing::{
    CompressionMethod, Index, Limits,
    write::{EntryKind, PendingMember, end_records},
};

const MANY_ENTRY_COUNT: usize = 1024;

struct Fixture {
    id: &'static str,
    paths: Vec<String>,
    archive_capacity: usize,
    directory_capacity: usize,
}

impl fmt::Display for Fixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}-{}-entries", self.id, self.paths.len())
    }
}

fn runtime() -> Runtime {
    RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build")
}

fn fixtures() -> Vec<Fixture> {
    [
        ("single", 1, "package".to_owned()),
        ("many", MANY_ENTRY_COUNT, "package".to_owned()),
        (
            "long-unicode-paths",
            MANY_ENTRY_COUNT,
            format!("{}package", "café/".repeat(32)),
        ),
    ]
    .into_iter()
    .map(|(id, count, prefix)| {
        let paths: Vec<_> = (0..count)
            .map(|index| format!("{prefix}/file-{index:04}.txt"))
            .collect();
        let (local_size, directory_capacity) =
            paths.iter().fold((0, 0), |(local, central), path| {
                let member = PendingMember::new(
                    path,
                    CompressionMethod::Stored,
                    EntryKind::File { executable: false },
                )
                .expect("fixture path should be valid");
                (
                    local + member.local_header_size(),
                    central + member.central_header_size(),
                )
            });
        let end = end_records(count as u64, local_size as u64, directory_capacity as u64)
            .expect("fixture end records should serialize");
        Fixture {
            id,
            paths,
            archive_capacity: local_size + directory_capacity + end.len(),
            directory_capacity,
        }
    })
    .collect()
}

// Empty files isolate metadata serialization and validation from payload work.
fn encode_metadata(fixture: &Fixture) -> Vec<u8> {
    let mut archive = Vec::with_capacity(fixture.archive_capacity);
    let mut directory = Vec::with_capacity(fixture.directory_capacity);
    for path in &fixture.paths {
        let member = PendingMember::new(
            path,
            CompressionMethod::Stored,
            EntryKind::File { executable: false },
        )
        .expect("fixture path should be valid")
        .finish(0, 0, 0, archive.len() as u64)
        .expect("empty fixture member should be valid");
        archive.extend(member.local_header());
        directory.extend(member.central_header());
    }
    let end = end_records(
        fixture.paths.len() as u64,
        archive.len() as u64,
        directory.len() as u64,
    )
    .expect("fixture end records should serialize");
    debug_assert_eq!(directory.len(), fixture.directory_capacity);
    debug_assert_eq!(directory.capacity(), fixture.directory_capacity);
    archive.extend(directory);
    archive.extend(end);
    archive
}

fn validate_fixture(fixture: &Fixture, archive: &Vec<u8>, runtime: &Runtime) {
    assert_eq!(archive.len(), fixture.archive_capacity);
    assert_eq!(archive.capacity(), fixture.archive_capacity);
    runtime.block_on(async {
        let mut reader = Cursor::new(archive.as_slice());
        let mut index = Index::read(&mut reader, Limits::default())
            .await
            .expect("fixture directory should index");
        assert_eq!(index.entries().len(), fixture.paths.len());
        index
            .validate_all(&mut reader)
            .await
            .expect("fixture local records should validate");
        for (ordinal, (entry, path)) in index.entries().iter().zip(&fixture.paths).enumerate() {
            assert_eq!(entry.directory().path(), path);
            assert!(index.resolved(ordinal).is_some());
        }
    });
}

#[divan::bench(args = fixtures())]
fn encode_headers_preallocated(bencher: Bencher, fixture: &Fixture) {
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        .bench_local(|| {
            black_box(encode_metadata(black_box(fixture)));
        });
    // Keep reader allocations out of encoding setup.
    validate_fixture(fixture, &encode_metadata(fixture), &runtime());
}

#[divan::bench(args = fixtures())]
fn index_directory(bencher: Bencher, fixture: &Fixture) {
    let runtime = runtime();
    let archive = encode_metadata(fixture);
    validate_fixture(fixture, &archive, &runtime);
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        .bench_local(|| {
            black_box(
                runtime
                    .block_on(Index::read(
                        &mut Cursor::new(black_box(archive.as_slice())),
                        Limits::default(),
                    ))
                    .expect("fixture directory should index"),
            );
        });
}

#[divan::bench(args = fixtures(), sample_size = 1)]
fn validate_local_records(bencher: Bencher, fixture: &Fixture) {
    let runtime = runtime();
    let archive = encode_metadata(fixture);
    validate_fixture(fixture, &archive, &runtime);
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        // Index outside the measurement, with a fresh resolution cache each time.
        .with_inputs(|| {
            let mut reader = Cursor::new(archive.as_slice());
            let index = runtime
                .block_on(Index::read(&mut reader, Limits::default()))
                .expect("fixture directory should index");
            (reader, index)
        })
        .bench_local_refs(|(reader, index)| {
            runtime
                .block_on(index.validate_all(black_box(reader)))
                .expect("fixture local records should validate");
            black_box(index);
        });
}

fn main() {
    divan::main();
}
