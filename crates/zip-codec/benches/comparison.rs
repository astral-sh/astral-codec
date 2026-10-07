mod support;

use std::{
    fmt,
    hint::black_box,
    io::{Cursor, Read, Write},
};

use async_zip::{
    Compression, ZipEntryBuilder,
    base::{read::seek::ZipFileReader, write::ZipFileWriter},
};
use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use zip::{
    CompressionMethod as ZipCompressionMethod, ZipArchive as SyncZipArchive, ZipWriter,
    write::SimpleFileOptions,
};
use zip_codec::{Archive, CompressionMethod, Member, MemberPayload, ZipArchive};

use support::{
    Entry, PAYLOAD_CHUNK_BYTES, encode_archive, entries, fixture, runtime, validate_fixture,
};

#[derive(Clone, Copy)]
enum Implementation {
    ZipCodec,
    Zip,
    AsyncZip,
}

impl fmt::Display for Implementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZipCodec => "zip-codec",
            Self::Zip => "zip",
            Self::AsyncZip => "astral_async_zip",
        })
    }
}

struct Case {
    workload: support::Case,
    implementation: Implementation,
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.workload, self.implementation)
    }
}

fn cases() -> impl Iterator<Item = Case> {
    support::cases().flat_map(|workload| {
        [
            Implementation::ZipCodec,
            Implementation::Zip,
            Implementation::AsyncZip,
        ]
        .into_iter()
        .map(move |implementation| Case {
            workload,
            implementation,
        })
    })
}

fn encode_zip(entries: &[Entry], method: CompressionMethod, output_capacity: usize) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::with_capacity(output_capacity)));
    let method = match method {
        CompressionMethod::Stored => Some(ZipCompressionMethod::Stored),
        CompressionMethod::Deflate => Some(ZipCompressionMethod::Deflated),
        _ => None,
    }
    .expect("zip should support the fixture compression method");
    let options = SimpleFileOptions::default().compression_method(method);
    for entry in entries {
        writer
            .start_file(&entry.path, options)
            .expect("zip should start fixture file");
        writer
            .write_all(&entry.data)
            .expect("zip should encode fixture file");
    }
    writer
        .finish()
        .expect("zip archive should finish")
        .into_inner()
}

async fn encode_async_zip(
    entries: &[Entry],
    method: CompressionMethod,
    output_capacity: usize,
) -> Vec<u8> {
    let mut writer = ZipFileWriter::with_tokio(Cursor::new(Vec::with_capacity(output_capacity)));
    let method = Compression::try_from(method as u16)
        .expect("astral_async_zip should support the fixture compression method");
    for entry in entries {
        writer
            .write_entry_whole(
                ZipEntryBuilder::new(entry.path.clone().into(), method),
                &entry.data,
            )
            .await
            .expect("astral_async_zip should encode fixture file");
    }
    writer
        .close()
        .await
        .expect("astral_async_zip archive should finish")
        .into_inner()
        .into_inner()
}

// Each decoder opens the archive and collects one file at a time into a reusable
// Vec. CRC checks are enabled for all three implementations. The callback checks
// every path and byte during setup and observes the output during measurements.
async fn decode_zip_codec(bytes: &[u8], mut consume: impl FnMut(&str, &[u8])) -> (usize, u64) {
    let mut archive = ZipArchive::open(Cursor::new(bytes))
        .await
        .expect("zip-codec archive should open");
    let mut data = Vec::new();
    let mut entries = 0;
    let mut payload_bytes = 0;
    while let Some(member) = archive
        .next_member()
        .await
        .expect("zip-codec member should decode")
    {
        assert!(matches!(member, Member::File { .. }));
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
                .expect("zip-codec payload should decode");
            consume(&metadata.path, &data);
            entries += 1;
            payload_bytes += data.len() as u64;
        }
    }
    (entries, payload_bytes)
}

fn decode_zip(bytes: &[u8], mut consume: impl FnMut(&str, &[u8])) -> (usize, u64) {
    let mut archive = SyncZipArchive::new(Cursor::new(bytes)).expect("zip archive should open");
    let mut data = Vec::new();
    let mut payload_bytes = 0;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("zip member should decode");
        data.clear();
        entry
            .read_to_end(&mut data)
            .expect("zip payload should decode and pass CRC validation");
        consume(entry.name(), &data);
        payload_bytes += data.len() as u64;
    }
    (archive.len(), payload_bytes)
}

async fn decode_async_zip(bytes: &[u8], mut consume: impl FnMut(&str, &[u8])) -> (usize, u64) {
    let mut archive = ZipFileReader::with_tokio(Cursor::new(bytes))
        .await
        .expect("astral_async_zip archive should open");
    let mut data = Vec::new();
    let mut payload_bytes = 0;
    for index in 0..archive.file().entries().len() {
        let mut entry = archive
            .reader_with_entry(index)
            .await
            .expect("astral_async_zip member should decode");
        data.clear();
        entry
            .read_to_end_checked(&mut data)
            .await
            .expect("astral_async_zip payload should decode and pass CRC validation");
        consume(
            entry
                .entry()
                .filename()
                .as_str()
                .expect("fixture filename should be UTF-8"),
            &data,
        );
        payload_bytes += data.len() as u64;
    }
    (archive.file().entries().len(), payload_bytes)
}

// Compare bounded streaming separately from collection. astral_async_zip's
// checked helper collects the whole file; using its streaming traits here would
// require another direct benchmark dependency.
async fn stream_zip_codec(bytes: &[u8], mut consume: impl FnMut(&str, &[u8])) -> (usize, u64) {
    let mut archive = ZipArchive::open(Cursor::new(bytes))
        .await
        .expect("zip-codec archive should open");
    let mut chunk = Vec::new();
    let mut entries = 0;
    let mut payload_bytes = 0;
    while let Some(member) = archive
        .next_member()
        .await
        .expect("zip-codec member should decode")
    {
        assert!(matches!(member, Member::File { .. }));
        if let Member::File {
            metadata,
            mut payload,
            ..
        } = member
        {
            while payload
                .next_chunk(&mut chunk, PAYLOAD_CHUNK_BYTES)
                .await
                .expect("zip-codec payload should decode")
            {
                consume(&metadata.path, &chunk);
                payload_bytes += chunk.len() as u64;
            }
            entries += 1;
        }
    }
    (entries, payload_bytes)
}

fn stream_zip(bytes: &[u8], mut consume: impl FnMut(&str, &[u8])) -> (usize, u64) {
    let mut archive = SyncZipArchive::new(Cursor::new(bytes)).expect("zip archive should open");
    let mut chunk = vec![0; PAYLOAD_CHUNK_BYTES];
    let mut payload_bytes = 0;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("zip member should decode");
        loop {
            let length = entry
                .read(&mut chunk)
                .expect("zip payload should decode and pass CRC validation");
            if length == 0 {
                break;
            }
            consume(entry.name(), &chunk[..length]);
            payload_bytes += length as u64;
        }
    }
    (archive.len(), payload_bytes)
}

fn streaming_cases() -> impl Iterator<Item = Case> {
    cases().filter(|case| !matches!(case.implementation, Implementation::AsyncZip))
}

#[divan::bench(args = streaming_cases())]
fn decode_stream(bencher: Bencher, case: &Case) {
    assert!(!matches!(case.implementation, Implementation::AsyncZip));
    let runtime = runtime();
    let fixture = fixture(&case.workload, &runtime);
    let mut index = 0;
    let mut offset = 0;
    let check = |path: &str, data: &[u8]| {
        let expected = &fixture.entries[index];
        assert_eq!(path, expected.path);
        assert_eq!(data, &expected.data[offset..offset + data.len()]);
        offset += data.len();
        if offset == expected.data.len() {
            index += 1;
            offset = 0;
        }
    };
    let decoded = match case.implementation {
        Implementation::ZipCodec => runtime.block_on(stream_zip_codec(&fixture.archive, check)),
        Implementation::Zip => stream_zip(&fixture.archive, check),
        Implementation::AsyncZip => return,
    };
    assert_eq!(index, fixture.entries.len());
    assert_eq!(offset, 0);
    assert_eq!(decoded, (fixture.entries.len(), fixture.payload_bytes));
    let consume = |path: &str, chunk: &[u8]| {
        black_box((path, chunk));
    };
    let bencher = bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes));
    match case.implementation {
        Implementation::ZipCodec => bencher.bench_local(|| {
            black_box(runtime.block_on(stream_zip_codec(black_box(&fixture.archive), consume)));
        }),
        Implementation::Zip => bencher.bench_local(|| {
            black_box(stream_zip(black_box(&fixture.archive), consume));
        }),
        Implementation::AsyncZip => {}
    }
}

#[divan::bench(args = cases())]
fn open(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(&case.workload, &runtime);
    // All readers receive the same ZIP64 bytes, including the compressed data.
    // Opening measures only the work each constructor performs, not equivalent
    // validation: the libraries differ in how much they check eagerly.
    let entry_count = match case.implementation {
        Implementation::ZipCodec => runtime
            .block_on(ZipArchive::open(Cursor::new(fixture.archive.as_slice())))
            .expect("zip-codec archive should open")
            .entries()
            .len(),
        Implementation::Zip => SyncZipArchive::new(Cursor::new(fixture.archive.as_slice()))
            .expect("zip archive should open")
            .len(),
        Implementation::AsyncZip => runtime
            .block_on(ZipFileReader::with_tokio(Cursor::new(
                fixture.archive.as_slice(),
            )))
            .expect("astral_async_zip archive should open")
            .file()
            .entries()
            .len(),
    };
    assert_eq!(entry_count, fixture.entries.len());
    let bencher = bencher.counter(ItemsCount::new(fixture.entries.len()));
    match case.implementation {
        Implementation::ZipCodec => bencher.bench_local(|| {
            black_box(
                runtime
                    .block_on(ZipArchive::open(Cursor::new(black_box(
                        fixture.archive.as_slice(),
                    ))))
                    .expect("zip-codec archive should open"),
            );
        }),
        Implementation::Zip => bencher.bench_local(|| {
            black_box(
                SyncZipArchive::new(Cursor::new(black_box(fixture.archive.as_slice())))
                    .expect("zip archive should open"),
            );
        }),
        Implementation::AsyncZip => bencher.bench_local(|| {
            black_box(
                runtime
                    .block_on(ZipFileReader::with_tokio(Cursor::new(black_box(
                        fixture.archive.as_slice(),
                    ))))
                    .expect("astral_async_zip archive should open"),
            );
        }),
    }
}

#[divan::bench(args = cases())]
fn encode(bencher: Bencher, case: &Case) {
    let entries = entries(&case.workload);
    bench_encode(bencher, case, &entries, 0);
}

#[divan::bench(args = cases())]
fn encode_preallocated(bencher: Bencher, case: &Case) {
    let entries = entries(&case.workload);
    // Use the same allowance for all three encoders, independent of their
    // output layouts or compression ratios. Post-measurement checks ensure
    // this covers DEFLATE expansion and ZIP metadata for every fixture.
    let output_capacity = 1024
        + entries
            .iter()
            .map(|entry| 2 * entry.data.len() + 2 * entry.path.len() + 1024)
            .sum::<usize>();
    bench_encode(bencher, case, &entries, output_capacity);
}

fn bench_encode(bencher: Bencher, case: &Case, entries: &[Entry], output_capacity: usize) {
    let runtime = runtime();
    let method = case.workload.method;
    let bencher = bencher
        .counter(ItemsCount::new(entries.len()))
        .counter(BytesCount::new(
            entries.iter().map(|entry| entry.data.len()).sum::<usize>(),
        ));
    match case.implementation {
        Implementation::ZipCodec => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_archive(
                black_box(entries),
                method,
                output_capacity,
            )));
        }),
        Implementation::Zip => bencher.bench_local(|| {
            black_box(encode_zip(black_box(entries), method, output_capacity));
        }),
        Implementation::AsyncZip => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_async_zip(
                black_box(entries),
                method,
                output_capacity,
            )));
        }),
    }
    // Check the selected encoder after timing to keep reader allocations out
    // of this case's setup.
    let encoded = match case.implementation {
        Implementation::ZipCodec => {
            runtime.block_on(encode_archive(entries, method, output_capacity))
        }
        Implementation::Zip => encode_zip(entries, method, output_capacity),
        Implementation::AsyncZip => {
            runtime.block_on(encode_async_zip(entries, method, output_capacity))
        }
    };
    if output_capacity != 0 {
        assert!(encoded.len() <= output_capacity);
        assert_eq!(
            encoded.capacity(),
            output_capacity,
            "output buffer must not grow"
        );
    }
    runtime.block_on(validate_fixture(&encoded, entries, method));
}

#[divan::bench(args = cases())]
fn decode(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = fixture(&case.workload, &runtime);
    let mut index = 0;
    let check = |path: &str, data: &[u8]| {
        let expected = &fixture.entries[index];
        assert_eq!(path, expected.path);
        assert_eq!(data, expected.data);
        index += 1;
    };
    let decoded = match case.implementation {
        Implementation::ZipCodec => runtime.block_on(decode_zip_codec(&fixture.archive, check)),
        Implementation::Zip => decode_zip(&fixture.archive, check),
        Implementation::AsyncZip => runtime.block_on(decode_async_zip(&fixture.archive, check)),
    };
    assert_eq!(index, fixture.entries.len());
    assert_eq!(decoded, (fixture.entries.len(), fixture.payload_bytes));
    let consume = |path: &str, data: &[u8]| {
        black_box((path, data));
    };
    let bencher = bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes));
    match case.implementation {
        Implementation::ZipCodec => bencher.bench_local(|| {
            black_box(runtime.block_on(decode_zip_codec(black_box(&fixture.archive), consume)));
        }),
        Implementation::Zip => bencher.bench_local(|| {
            black_box(decode_zip(black_box(&fixture.archive), consume));
        }),
        Implementation::AsyncZip => bencher.bench_local(|| {
            black_box(runtime.block_on(decode_async_zip(black_box(&fixture.archive), consume)));
        }),
    }
}

fn main() {
    divan::main();
}
