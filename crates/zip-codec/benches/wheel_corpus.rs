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

use wheels::{Case, Fixture, Implementation, cases, runtime};

fn read_index(
    fixture: &Fixture,
    implementation: Implementation,
    runtime: &Runtime,
    mut consume: impl FnMut(&str, u64, u32),
) {
    match implementation {
        Implementation::ZipCodec => runtime.block_on(async {
            let archive = ZipArchive::open(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("zip-codec should open wheel");
            for entry in archive.entries() {
                let directory = entry.directory();
                consume(directory.path(), directory.size(), directory.crc32());
            }
        }),
        Implementation::Zip => {
            let mut archive = SyncZipArchive::new(Cursor::new(black_box(&fixture.bytes)))
                .expect("zip should open wheel");
            for index in 0..archive.len() {
                // zip exposes sizes and CRCs through ZipFile, not its directory
                // metadata. The raw reader avoids constructing decompressors.
                let entry = archive.by_index_raw(index).expect("zip wheel entry");
                consume(entry.name(), entry.size(), entry.crc32());
            }
        }
        Implementation::AsyncZip => runtime.block_on(async {
            let archive = ZipFileReader::with_tokio(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("async zip should open wheel");
            for entry in archive.file().entries() {
                consume(
                    entry.filename().as_str().expect("UTF-8 wheel path"),
                    entry.uncompressed_size(),
                    entry.crc32(),
                );
            }
        }),
    }
}

fn read(
    fixture: &Fixture,
    implementation: Implementation,
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

#[divan::bench(args = cases())]
fn index(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = Fixture::load(case);
    let mut expected = fixture.entries.iter();
    read_index(
        &fixture,
        case.implementation,
        &runtime,
        |path, size, crc| {
            let entry = expected.next().expect("unexpected wheel entry");
            assert_eq!(path, entry.path);
            assert_eq!(size, entry.size);
            assert_eq!(crc, entry.crc);
        },
    );
    assert!(expected.next().is_none(), "missing wheel entries");
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .bench_local(|| {
            read_index(
                &fixture,
                case.implementation,
                &runtime,
                |path, size, crc| {
                    black_box((path, size, crc));
                },
            );
        });
}

#[divan::bench(args = cases())]
fn decode(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = Fixture::load(case);
    let mut expected = fixture.entries.iter();
    // Check every path, length, and CRC outside the measurement.
    read(&fixture, case.implementation, &runtime, |path, data| {
        let entry = expected.next().expect("unexpected wheel entry");
        assert_eq!(path, entry.path);
        assert_eq!(data.is_none(), entry.directory);
        if let Some(data) = data {
            assert_eq!(data.len() as u64, entry.size);
            assert_eq!(crc32fast::hash(data), entry.crc);
        }
    });
    assert!(expected.next().is_none(), "missing wheel entries");
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        .bench_local(|| {
            read(&fixture, case.implementation, &runtime, |path, data| {
                black_box((path, data));
            });
        });
}

fn main() {
    divan::main();
}
