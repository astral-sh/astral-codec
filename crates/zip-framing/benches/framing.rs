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
    archive: Vec<u8>,
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
    let runtime = runtime();
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
        let archive = encode_metadata(&paths);
        runtime.block_on(async {
            let mut reader = Cursor::new(archive.as_slice());
            let mut index = Index::read(&mut reader, Limits::default())
                .await
                .expect("fixture directory should index");
            assert_eq!(index.entries().len(), paths.len());
            index
                .validate_all(&mut reader)
                .await
                .expect("fixture local records should validate");
            for (ordinal, (entry, path)) in index.entries().iter().zip(&paths).enumerate() {
                assert_eq!(entry.directory().path(), path);
                assert!(index.resolved(ordinal).is_some());
            }
        });
        Fixture { id, paths, archive }
    })
    .collect()
}

// Empty files isolate metadata serialization and validation from payload work.
fn encode_metadata(paths: &[String]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut directory = Vec::new();
    for path in paths {
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
        paths.len() as u64,
        archive.len() as u64,
        directory.len() as u64,
    )
    .expect("fixture end records should serialize");
    archive.extend(directory);
    archive.extend(end);
    archive
}

#[divan::bench(args = fixtures())]
fn encode_headers(bencher: Bencher, fixture: &Fixture) {
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        .bench_local(|| {
            black_box(encode_metadata(black_box(&fixture.paths)));
        });
}

#[divan::bench(args = fixtures())]
fn index_directory(bencher: Bencher, fixture: &Fixture) {
    let runtime = runtime();
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        .bench_local(|| {
            black_box(
                runtime
                    .block_on(Index::read(
                        &mut Cursor::new(black_box(fixture.archive.as_slice())),
                        Limits::default(),
                    ))
                    .expect("fixture directory should index"),
            );
        });
}

#[divan::bench(args = fixtures(), sample_size = 1)]
fn validate_local_records(bencher: Bencher, fixture: &Fixture) {
    let runtime = runtime();
    bencher
        .counter(ItemsCount::new(fixture.paths.len()))
        // Index outside the measurement, with a fresh resolution cache each time.
        .with_inputs(|| {
            let mut reader = Cursor::new(fixture.archive.as_slice());
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
