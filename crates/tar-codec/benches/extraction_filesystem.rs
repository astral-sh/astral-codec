mod support;

use std::{fmt, fs};

use divan::{
    Bencher,
    counter::{BytesCount, ItemsCount},
};
use support::{Entry, SMALL_FILE_BYTES, SMALL_FILE_COUNT, payload, runtime, ustar_archive_entries};
use tar_codec::{Archive as _, TarArchive, extract::ExtractPolicy};
use tempfile::{TempDir, tempdir};

const DIRECTORY_HEAVY_FILE_COUNT: usize = 256;
const BUFFERED_BOUNDARY_FILE_COUNT: usize = 16;
const DUPLICATE_FILE_COUNT: usize = 256;

struct ExtractionFixture {
    id: &'static str,
    entries: Vec<Entry>,
    payload_bytes: u64,
    prepopulate_destination: bool,
}

#[derive(Clone, Copy)]
enum Implementation {
    TarCodec,
    Tar,
    TarNoMtime,
}

impl fmt::Display for Implementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TarCodec => "tar-codec",
            Self::Tar => "tar",
            Self::TarNoMtime => "tar-no-mtime",
        })
    }
}

struct Case {
    fixture: ExtractionFixture,
    implementation: Implementation,
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-{}-entries/{}",
            self.fixture.id,
            self.fixture.entries.len(),
            self.implementation
        )
    }
}

fn cases() -> impl Iterator<Item = Case> {
    [
        Implementation::TarCodec,
        Implementation::Tar,
        Implementation::TarNoMtime,
    ]
    .into_iter()
    .flat_map(|implementation| {
        extraction_filesystem_fixtures()
            .into_iter()
            .map(move |fixture| Case {
                fixture,
                implementation,
            })
    })
}

fn extraction_filesystem_fixtures() -> Vec<ExtractionFixture> {
    // Decompose fixed root setup, per-file work, directory topology,
    // replacement behavior, and the buffered/streamed size boundary.
    vec![
        extraction_fixture("empty-archive", Vec::new()),
        extraction_fixture(
            "flat-empty",
            (0..SMALL_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-empty-directory-control",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "shared-parent-empty",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("directory/file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "unique-parent-empty",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("directory-{index:04}/file.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-small",
            (0..SMALL_FILE_COUNT)
                .map(|index| {
                    (
                        format!("file-{index:04}.txt"),
                        payload(SMALL_FILE_BYTES, index),
                    )
                })
                .collect(),
        ),
        extraction_fixture(
            "duplicate-empty",
            (0..DUPLICATE_FILE_COUNT * 2)
                .map(|index| {
                    (
                        format!("file-{:04}.txt", index % DUPLICATE_FILE_COUNT),
                        Vec::new(),
                    )
                })
                .collect(),
        ),
        prepopulated_extraction_fixture(
            "ambient-empty",
            (0..DUPLICATE_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-buffered-boundary",
            (0..BUFFERED_BOUNDARY_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.bin"), payload(1024 * 1024, index)))
                .collect(),
        ),
        extraction_fixture(
            "flat-streamed-boundary",
            (0..BUFFERED_BOUNDARY_FILE_COUNT)
                .map(|index| {
                    (
                        format!("file-{index:04}.bin"),
                        payload(1024 * 1024 + 1, index),
                    )
                })
                .collect(),
        ),
    ]
}

fn extraction_fixture(id: &'static str, files: Vec<(String, Vec<u8>)>) -> ExtractionFixture {
    let payload_bytes = files.iter().fold(0_u64, |total, (_, data)| {
        total
            .checked_add(
                u64::try_from(data.len()).expect("fixture payload length should be representable"),
            )
            .expect("fixture payload byte count should be representable")
    });
    ExtractionFixture {
        id,
        entries: files
            .into_iter()
            .map(|(archive_path, data)| Entry { archive_path, data })
            .collect(),
        payload_bytes,
        prepopulate_destination: false,
    }
}

fn prepopulated_extraction_fixture(
    id: &'static str,
    files: Vec<(String, Vec<u8>)>,
) -> ExtractionFixture {
    ExtractionFixture {
        prepopulate_destination: true,
        ..extraction_fixture(id, files)
    }
}

fn extraction_temp(fixture: &ExtractionFixture) -> TempDir {
    let temp = tempdir().expect("temporary extraction directory should be created");
    if fixture.prepopulate_destination {
        let destination = temp.path().join("out");
        fs::create_dir(&destination).expect("prepopulated destination should be created");
        for entry in &fixture.entries {
            let path = destination.join(&entry.archive_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .expect("prepopulated destination parent should be created");
            }
            fs::write(path, b"ambient").expect("ambient fixture file should be written");
        }
    }
    temp
}

#[divan::bench(args = cases(), sample_size = 1)]
fn extract_filesystem(bencher: Bencher, case: &Case) {
    let runtime = runtime();
    let fixture = &case.fixture;
    // Use one-header USTAR members so metadata framing does not obscure
    // filesystem and task-scheduling costs.
    let input = ustar_archive_entries(&fixture.entries);
    let mut bencher = bencher;
    if !fixture.entries.is_empty() {
        bencher = bencher.counter(ItemsCount::new(fixture.entries.len()));
    }
    if fixture.payload_bytes != 0 {
        bencher = bencher.counter(BytesCount::new(fixture.payload_bytes));
    }
    // Prepare and remove each destination outside the measurement.
    let bencher = bencher.with_inputs(|| extraction_temp(fixture));
    match case.implementation {
        Implementation::TarCodec => bencher.bench_local_refs(|temp| {
            let destination = temp.path().join("out");
            runtime.block_on(async {
                TarArchive::new(input.as_slice())
                    .extract_in(destination, ExtractPolicy::default())
                    .await
                    .expect("tar-codec should extract filesystem fixture");
            });
        }),
        // Keep the default tar policy alongside a leaner reference that
        // disables tar's additional mtime restoration. Other metadata semantics
        // still differ between the extractors.
        Implementation::Tar | Implementation::TarNoMtime => bencher.bench_local_refs(|temp| {
            let destination = temp.path().join("out");
            let mut archive = tar::Archive::new(input.as_slice());
            archive.set_preserve_mtime(matches!(case.implementation, Implementation::Tar));
            archive
                .unpack(destination)
                .expect("tar should extract filesystem fixture");
        }),
    }
}

fn main() {
    divan::main();
}
