mod wheels;

use std::{
    hint::black_box,
    io::{Cursor, Read},
};

use async_zip::base::read::seek::ZipFileReader;
use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use tokio::runtime::Runtime;
use zip::ZipArchive as SyncZipArchive;
use zip_codec::{Member, ZipArchive};

use wheels::{Case, Fixture, Implementation, cases, is_metadata, runtime};

fn read(
    fixture: &Fixture,
    implementation: Implementation,
    metadata_only: bool,
    runtime: &Runtime,
    mut consume: impl FnMut(&str, Option<&[u8]>),
) {
    let mut data = Vec::new();
    match implementation {
        Implementation::ZipCodec => runtime.block_on(async {
            let mut archive = ZipArchive::open(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("zip-codec should open wheel");
            for index in 0..archive.entries().len() {
                let path = archive.entries()[index].directory().path();
                if metadata_only && !is_metadata(path) {
                    continue;
                }
                let member = archive
                    .member(index)
                    .await
                    .expect("zip-codec wheel entry")
                    .expect("entry index in bounds");
                if let Member::File {
                    metadata,
                    mut payload,
                    ..
                } = member
                {
                    data.clear();
                    payload
                        .read_to_end(&mut data)
                        .await
                        .expect("zip-codec wheel CRC and payload");
                    consume(&metadata.path, Some(&data));
                } else {
                    assert!(
                        matches!(member, Member::Directory { .. }),
                        "unexpected wheel member"
                    );
                    consume(&member.metadata().path, None);
                }
            }
        }),
        Implementation::Zip => {
            let mut archive = SyncZipArchive::new(Cursor::new(black_box(&fixture.bytes)))
                .expect("zip should open wheel");
            for index in 0..archive.len() {
                // Opening the local header is deliberately inside the selection:
                // metadata-only does not decompress or resolve unselected files.
                if metadata_only
                    && !is_metadata(
                        archive
                            .name_for_index(index)
                            .expect("entry index in bounds"),
                    )
                {
                    continue;
                }
                let mut entry = archive.by_index(index).expect("zip wheel entry");
                if entry.is_dir() {
                    consume(entry.name(), None);
                } else {
                    data.clear();
                    entry
                        .read_to_end(&mut data)
                        .expect("zip wheel CRC and payload");
                    consume(entry.name(), Some(&data));
                }
            }
        }
        Implementation::AsyncZip => runtime.block_on(async {
            let mut archive = ZipFileReader::with_tokio(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("async zip should open wheel");
            for index in 0..archive.file().entries().len() {
                let directory = &archive.file().entries()[index];
                let path = directory.filename().as_str().expect("UTF-8 wheel path");
                if metadata_only && !is_metadata(path) {
                    continue;
                }
                if directory.dir().expect("wheel kind") {
                    consume(path, None);
                } else {
                    let mut entry = archive
                        .reader_with_entry(index)
                        .await
                        .expect("async zip wheel entry");
                    data.clear();
                    entry
                        .read_to_end_checked(&mut data)
                        .await
                        .expect("async zip wheel CRC and payload");
                    consume(
                        entry.entry().filename().as_str().expect("UTF-8 wheel path"),
                        Some(&data),
                    );
                }
            }
        }),
    }
}

fn bench_read(bencher: Bencher, case: &Case, metadata_only: bool) {
    let runtime = runtime();
    let fixture = Fixture::load(case);
    let mut expected = fixture
        .entries
        .iter()
        .filter(|entry| !metadata_only || is_metadata(&entry.path));
    // Check every selected path, length, and CRC outside the measurement.
    read(
        &fixture,
        case.implementation,
        metadata_only,
        &runtime,
        |path, data| {
            let entry = expected.next().expect("unexpected wheel entry");
            assert_eq!(path, entry.path);
            assert_eq!(data.is_none(), entry.directory);
            if let Some(data) = data {
                assert_eq!(data.len() as u64, entry.size);
                assert_eq!(crc32fast::hash(data), entry.crc);
            }
        },
    );
    assert!(expected.next().is_none(), "missing wheel entries");
    let entries = fixture
        .entries
        .iter()
        .filter(|entry| !metadata_only || is_metadata(&entry.path));
    let bytes = if metadata_only {
        entries.clone().map(|entry| entry.size).sum()
    } else {
        fixture.payload_bytes
    };
    bencher
        .counter(ItemsCount::new(entries.count()))
        .counter(BytesCount::new(bytes))
        .bench_local(|| {
            read(
                &fixture,
                case.implementation,
                metadata_only,
                &runtime,
                |path, data| {
                    black_box((path, data));
                },
            );
        });
}

#[divan::bench(args = cases())]
fn open(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = Fixture::load(case);
    let bencher = bencher.counter(ItemsCount::new(fixture.entries.len()));
    match case.implementation {
        Implementation::ZipCodec => {
            assert_eq!(
                runtime
                    .block_on(ZipArchive::open(Cursor::new(&fixture.bytes)))
                    .expect("zip-codec should open wheel")
                    .entries()
                    .len(),
                fixture.entries.len()
            );
            bencher.bench_local(|| {
                black_box(
                    runtime
                        .block_on(ZipArchive::open(Cursor::new(black_box(&fixture.bytes))))
                        .expect("zip-codec should open wheel"),
                );
            });
        }
        Implementation::Zip => {
            assert_eq!(
                SyncZipArchive::new(Cursor::new(&fixture.bytes))
                    .expect("zip should open wheel")
                    .len(),
                fixture.entries.len()
            );
            bencher.bench_local(|| {
                black_box(
                    SyncZipArchive::new(Cursor::new(black_box(&fixture.bytes)))
                        .expect("zip should open wheel"),
                );
            });
        }
        Implementation::AsyncZip => {
            assert_eq!(
                runtime
                    .block_on(ZipFileReader::with_tokio(Cursor::new(&fixture.bytes)))
                    .expect("async zip should open wheel")
                    .file()
                    .entries()
                    .len(),
                fixture.entries.len()
            );
            bencher.bench_local(|| {
                black_box(
                    runtime
                        .block_on(ZipFileReader::with_tokio(Cursor::new(black_box(
                            &fixture.bytes,
                        ))))
                        .expect("async zip should open wheel"),
                );
            });
        }
    }
}

#[divan::bench(args = cases())]
fn metadata(bencher: Bencher, case: &Case) {
    bench_read(bencher, case, true);
}

#[divan::bench(args = cases())]
fn decode(bencher: Bencher, case: &Case) {
    bench_read(bencher, case, false);
}

fn main() {
    divan::main();
}
