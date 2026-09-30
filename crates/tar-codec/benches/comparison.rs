mod support;

use std::{
    fmt, fs,
    hint::black_box,
    io::{self, Write},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use support::{
    Entry, SMALL_FILE_BYTES, SMALL_FILE_COUNT, configure_tar_header, payload, runtime,
    ustar_archive_entries,
};
use tar_codec::{
    Archive as _, ArchiveBuilder as _, EntryMetadata, TarArchive, TarEncoder,
    extract::ExtractPolicy,
};
use tempfile::{TempDir, tempdir};
use tokio::io::AsyncWrite;

const LARGE_FILE_BYTES: usize = 16 * 1024 * 1024;
const SMALL_DIRECTORY_COUNT: usize = 32;

#[derive(Default)]
/// A sink for measuring framing work without touching payload bytes.
struct FramingSink {
    bytes_written: u64,
}

impl FramingSink {
    fn record_write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("write length cannot be represented"))?;
        self.bytes_written = self
            .bytes_written
            .checked_add(len)
            .ok_or_else(|| io::Error::other("counting writer overflow"))?;
        Ok(buffer.len())
    }
}

impl Write for FramingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.record_write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for FramingSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.record_write(buffer))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Fixture {
    _temp: TempDir,
    id: &'static str,
    source: PathBuf,
    entries: Vec<Entry>,
    payload_bytes: u64,
}

#[derive(Clone, Copy)]
enum Workload {
    Large,
    ManySmall,
}

impl fmt::Display for Workload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Large => formatter.write_str("large-1-entries"),
            Self::ManySmall => write!(formatter, "many-small-{SMALL_FILE_COUNT}-entries"),
        }
    }
}

#[derive(Clone, Copy)]
enum Implementation {
    TarCodec,
    Tar,
    TokioTar,
}

impl fmt::Display for Implementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TarCodec => "tar-codec",
            Self::Tar => "tar",
            Self::TokioTar => "astral-tokio-tar",
        })
    }
}

struct Case {
    workload: Workload,
    implementation: Implementation,
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.workload, self.implementation)
    }
}

fn cases() -> impl Iterator<Item = Case> {
    [Workload::Large, Workload::ManySmall]
        .into_iter()
        .flat_map(|workload| {
            [
                Implementation::TarCodec,
                Implementation::Tar,
                Implementation::TokioTar,
            ]
            .into_iter()
            .map(move |implementation| Case {
                workload,
                implementation,
            })
        })
}

#[derive(Clone, Copy)]
enum Format {
    Pax,
    Ustar,
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pax => "pax",
            Self::Ustar => "ustar",
        })
    }
}

struct ExtractionCase {
    case: Case,
    format: Format,
}

impl fmt::Display for ExtractionCase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.format, self.case)
    }
}

fn extraction_cases() -> impl Iterator<Item = ExtractionCase> {
    [Format::Pax, Format::Ustar]
        .into_iter()
        .flat_map(|format| cases().map(move |case| ExtractionCase { case, format }))
}

fn workload_fixture(workload: Workload) -> Fixture {
    match workload {
        Workload::Large => fixture(
            "large",
            vec![("payload.bin".to_owned(), payload(LARGE_FILE_BYTES, 0))],
        ),
        Workload::ManySmall => fixture(
            "many-small",
            (0..SMALL_FILE_COUNT)
                .map(|index| {
                    (
                        format!(
                            "directory-{:02}/file-{index:04}.txt",
                            index % SMALL_DIRECTORY_COUNT
                        ),
                        payload(SMALL_FILE_BYTES, index),
                    )
                })
                .collect(),
        ),
    }
}

fn fixture(id: &'static str, files: Vec<(String, Vec<u8>)>) -> Fixture {
    let temp = tempdir().expect("fixture temporary directory should be created");
    let source = temp.path().join(id);
    fs::create_dir(&source).expect("fixture root should be created");
    let mut payload_bytes = 0;
    let entries = files
        .into_iter()
        .map(|(relative_path, data)| {
            let path = source.join(&relative_path);
            fs::create_dir_all(path.parent().expect("fixture file should have a parent"))
                .expect("fixture parent directories should be created");
            fs::write(&path, &data).expect("fixture file should be written");
            payload_bytes +=
                u64::try_from(data.len()).expect("fixture payload length should be representable");
            Entry {
                archive_path: format!("{id}/{relative_path}"),
                data,
            }
        })
        .collect();
    Fixture {
        _temp: temp,
        id,
        source,
        entries,
        payload_bytes,
    }
}

async fn encode_entries_tar_codec(fixture: &Fixture) -> u64 {
    let mut sink = FramingSink::default();
    let mut encoder = TarEncoder::new(&mut sink).builder();
    for entry in &fixture.entries {
        encoder
            .add_file(
                &entry.archive_path,
                entry.data.as_slice(),
                EntryMetadata::default(),
            )
            .await
            .expect("tar-codec should encode fixture entry");
    }
    encoder
        .finish()
        .await
        .expect("tar-codec archive should finish");
    sink.bytes_written
}

fn encode_entries_tar(fixture: &Fixture) -> u64 {
    let mut builder = tar::Builder::new(FramingSink::default());
    for entry in &fixture.entries {
        let mut header = tar::Header::new_ustar();
        configure_tar_header(&mut header, entry.data.len());
        builder
            .append_data(&mut header, &entry.archive_path, entry.data.as_slice())
            .expect("tar should encode fixture entry");
    }
    builder
        .into_inner()
        .expect("tar archive should finish")
        .bytes_written
}

async fn encode_entries_tokio_tar(fixture: &Fixture) -> u64 {
    let mut builder = tokio_tar::Builder::new(FramingSink::default());
    for entry in &fixture.entries {
        let mut header = tokio_tar::Header::new_ustar();
        configure_tokio_tar_header(&mut header, entry.data.len());
        builder
            .append_data(&mut header, &entry.archive_path, entry.data.as_slice())
            .await
            .expect("astral-tokio-tar should encode fixture entry");
    }
    builder
        .into_inner()
        .await
        .expect("astral-tokio-tar archive should finish")
        .bytes_written
}

async fn encode_directory_tar_codec(fixture: &Fixture) -> u64 {
    let mut sink = FramingSink::default();
    let mut encoder = TarEncoder::new(&mut sink).builder();
    encoder
        .add_directory_all(&fixture.source)
        .await
        .expect("tar-codec should encode fixture directory");
    encoder
        .finish()
        .await
        .expect("tar-codec archive should finish");
    sink.bytes_written
}

fn encode_directory_tar(fixture: &Fixture) -> u64 {
    let mut builder = tar::Builder::new(FramingSink::default());
    builder.follow_symlinks(false);
    builder
        .append_dir_all(fixture.id, &fixture.source)
        .expect("tar should encode fixture directory");
    builder
        .into_inner()
        .expect("tar archive should finish")
        .bytes_written
}

async fn encode_directory_tokio_tar(fixture: &Fixture) -> u64 {
    let mut builder = tokio_tar::Builder::new(FramingSink::default());
    builder.follow_symlinks(false);
    builder
        .append_dir_all(fixture.id, &fixture.source)
        .await
        .expect("astral-tokio-tar should encode fixture directory");
    builder
        .into_inner()
        .await
        .expect("astral-tokio-tar archive should finish")
        .bytes_written
}

fn configure_tokio_tar_header(header: &mut tokio_tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_cksum();
}

async fn pax_archive(fixture: &Fixture) -> Vec<u8> {
    pax_archive_entries(&fixture.entries).await
}

async fn pax_archive_entries(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    for entry in entries {
        encoder
            .add_file(
                &entry.archive_path,
                entry.data.as_slice(),
                EntryMetadata::default(),
            )
            .await
            .expect("tar-codec should encode pax fixture entry");
    }
    encoder
        .finish()
        .await
        .expect("tar-codec pax archive should finish");
    bytes
}

fn ustar_archive(fixture: &Fixture) -> Vec<u8> {
    ustar_archive_entries(&fixture.entries)
}

#[divan::bench(args = cases())]
fn encode_entries_framing(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = workload_fixture(case.workload);
    let bencher = bencher.counter(ItemsCount::new(fixture.entries.len()));
    match case.implementation {
        Implementation::TarCodec => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_entries_tar_codec(black_box(&fixture))));
        }),
        Implementation::Tar => bencher.bench_local(|| {
            black_box(encode_entries_tar(black_box(&fixture)));
        }),
        Implementation::TokioTar => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_entries_tokio_tar(black_box(&fixture))));
        }),
    }
}

#[divan::bench(args = cases())]
fn encode_directory(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = workload_fixture(case.workload);
    let bencher = bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes));
    match case.implementation {
        Implementation::TarCodec => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_directory_tar_codec(black_box(&fixture))));
        }),
        Implementation::Tar => bencher.bench_local(|| {
            black_box(encode_directory_tar(black_box(&fixture)));
        }),
        Implementation::TokioTar => bencher.bench_local(|| {
            black_box(runtime.block_on(encode_directory_tokio_tar(black_box(&fixture))));
        }),
    }
}

#[divan::bench(args = extraction_cases(), sample_size = 1)]
fn extract(bencher: Bencher, case: &ExtractionCase) {
    let runtime = runtime();
    let fixture = workload_fixture(case.case.workload);
    let input = match case.format {
        Format::Pax => runtime.block_on(pax_archive(&fixture)),
        Format::Ustar => ustar_archive(&fixture),
    };
    // Prepare and remove each destination outside the measurement.
    let bencher = bencher
        .counter(ItemsCount::new(fixture.entries.len()))
        .counter(BytesCount::new(fixture.payload_bytes))
        .with_inputs(|| tempdir().expect("temporary extraction directory should be created"));
    match case.case.implementation {
        Implementation::TarCodec => bencher.bench_local_refs(|temp| {
            let destination = temp.path().join("out");
            runtime.block_on(async {
                TarArchive::new(black_box(input.as_slice()))
                    .extract_in(destination, ExtractPolicy::default())
                    .await
                    .expect("tar-codec should extract fixture archive");
            });
        }),
        Implementation::Tar => bencher.bench_local_refs(|temp| {
            let destination = temp.path().join("out");
            tar::Archive::new(black_box(input.as_slice()))
                .unpack(destination)
                .expect("tar should extract fixture archive");
        }),
        Implementation::TokioTar => bencher.bench_local_refs(|temp| {
            let destination = temp.path().join("out");
            runtime.block_on(async {
                tokio_tar::Archive::new(black_box(input.as_slice()))
                    .unpack(destination)
                    .await
                    .expect("astral-tokio-tar should extract fixture archive");
            });
        }),
    }
}

fn main() {
    divan::main();
}
