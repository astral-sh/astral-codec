mod wheels;

use std::{fs, hint::black_box, io::Cursor, path::Path};

use async_zip::base::read::seek::ZipFileReader;
use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use tempfile::tempdir;
use tokio::runtime::Runtime;
use zip::ZipArchive as SyncZipArchive;
use zip_codec::{Archive, ZipArchive, extract::ExtractPolicy};

use wheels::{Case, Fixture, Implementation, cases, runtime};

fn extract(
    fixture: &Fixture,
    implementation: Implementation,
    destination: &Path,
    runtime: &Runtime,
) {
    match implementation {
        Implementation::ZipCodec => runtime.block_on(async {
            ZipArchive::open(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("zip-codec should open wheel")
                .extract_in(destination, ExtractPolicy::default())
                .await
                .expect("zip-codec should extract wheel");
        }),
        Implementation::Zip => {
            SyncZipArchive::new(Cursor::new(black_box(&fixture.bytes)))
                .expect("zip should open wheel")
                .extract(destination)
                .expect("zip should extract wheel");
        }
        // astral_async_zip has no filesystem extraction API. Use its checked
        // whole-entry reader and Tokio files. Fixture::load checks these paths.
        Implementation::AsyncZip => runtime.block_on(async {
            let mut archive = ZipFileReader::with_tokio(Cursor::new(black_box(&fixture.bytes)))
                .await
                .expect("async zip should open wheel");
            tokio::fs::create_dir_all(destination)
                .await
                .expect("wheel destination");
            let mut data = Vec::new();
            for index in 0..archive.file().entries().len() {
                let directory = &archive.file().entries()[index];
                let path =
                    destination.join(directory.filename().as_str().expect("UTF-8 wheel path"));
                if directory.dir().expect("wheel kind") {
                    tokio::fs::create_dir_all(&path)
                        .await
                        .expect("wheel directory");
                    continue;
                }
                tokio::fs::create_dir_all(path.parent().expect("file parent"))
                    .await
                    .expect("wheel file parents");
                let mut entry = archive
                    .reader_with_entry(index)
                    .await
                    .expect("async zip wheel entry");
                data.clear();
                entry
                    .read_to_end_checked(&mut data)
                    .await
                    .expect("async zip wheel CRC and payload");
                tokio::fs::write(path, &data)
                    .await
                    .expect("write wheel file");
            }
        }),
    }
}

#[divan::bench(args = cases(), sample_size = 1)]
fn wheel_extract(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = Fixture::load(case);
    // Verify the selected extractor outside timing, including explicit dirs.
    let check = tempdir().expect("temporary verification directory");
    let destination = check.path().join("out");
    extract(&fixture, case.implementation, &destination, &runtime);
    for entry in &fixture.entries {
        let path = destination.join(&entry.path);
        if entry.directory {
            assert!(path.is_dir(), "missing wheel directory: {}", entry.path);
        } else {
            let data = fs::read(path).expect("missing wheel file");
            assert_eq!(data.len() as u64, entry.size, "{}", entry.path);
            assert_eq!(crc32fast::hash(&data), entry.crc, "{}", entry.path);
        }
    }
    drop(check);
    // Match the tar comparison: a fresh destination and cleanup per iteration,
    // both outside timing. Opening, CRC checks, and writes are included.
    bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        .with_inputs(|| tempdir().expect("temporary extraction directory"))
        .bench_local_refs(|temp| {
            extract(
                &fixture,
                case.implementation,
                &temp.path().join("out"),
                &runtime,
            );
        });
}

fn main() {
    divan::main();
}
