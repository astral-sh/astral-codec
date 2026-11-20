use std::{
    error::Error,
    fs,
    io::{self, Cursor},
    path::Path,
    process::{Command, Output},
};

use zip_codec::{ArchiveBuilder as _, CompressionMethod, EntryMetadata, FilePayload, ZipEncoder};

type TestResult = Result<(), Box<dyn Error>>;

const FIXTURES: &str = "../zip-codec/tests/fixtures";

fn ziptie(command: &str, archive: &Path) -> Command {
    let mut process = Command::new(env!("CARGO_BIN_EXE_ziptie"));
    process.arg(command).arg(archive);
    process
}

#[track_caller]
fn stdout(output: Output) -> Result<String, Box<dyn Error>> {
    assert!(
        output.status.success(),
        "{}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

#[test]
fn frames_reports_offsets_including_the_descriptor() -> TestResult {
    let archive = Path::new(FIXTURES).join("extract.zip");
    let dump = stdout(ziptie("frames", &archive).output()?)?;
    assert!(
        dump.ends_with(
            r#"frames:
    [0] record=0..66 path="nested/file"
        data @41 method=Deflate compressed=9 uncompressed=7 crc32=422c6a15
"#
        ),
        "{dump}"
    );
    Ok(())
}

#[test]
fn logical_reports_member_kinds_and_decoded_sizes() -> TestResult {
    let archive = Path::new(FIXTURES).join("deflate.zip");
    let dump = stdout(ziptie("logical", &archive).output()?)?;
    assert!(dump.contains(r#"directory path="directory/""#), "{dump}");
    assert!(
        dump.contains(
            r#"regular path="directory/file" executable=true
        decoded=140000"#
        ),
        "{dump}"
    );
    assert!(
        dump.contains(r#"symbolic-link path="link" link="directory/file""#),
        "{dump}"
    );
    Ok(())
}

#[test]
fn extract_writes_members_to_the_destination() -> TestResult {
    let archive = Path::new(FIXTURES).join("extract.zip");
    let destination = tempfile::tempdir()?;
    let output = ziptie("extract", &archive)
        .arg(destination.path())
        .output()?;
    assert!(stdout(output)?.is_empty());
    assert_eq!(
        fs::read(destination.path().join("nested/file"))?,
        b"payload"
    );
    Ok(())
}

#[tokio::test]
async fn corrupt_final_payload_passes_frames_and_fails_logical() -> TestResult {
    let payload = b"stored payload";
    let mut bytes = Vec::new();
    let mut builder = ZipEncoder::new(Cursor::new(&mut bytes))
        .with_compression(CompressionMethod::Stored)
        .builder();
    builder
        .add_file(
            "file",
            FilePayload::new(payload.len() as u64, payload.as_slice()),
            EntryMetadata::default(),
        )
        .await?;
    builder.finish().await?;
    let offset = bytes
        .windows(payload.len())
        .position(|window| window == payload)
        .ok_or_else(|| io::Error::other("missing stored payload"))?;
    bytes[offset] ^= 1;

    let directory = tempfile::tempdir()?;
    let archive = directory.path().join("corrupt.whl");
    fs::write(&archive, bytes)?;
    let dump = stdout(ziptie("frames", &archive).output()?)?;
    assert!(
        dump.contains(&format!("data @{offset} method=Stored")),
        "{dump}"
    );

    let output = ziptie("logical", &archive).output()?;
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr)?;
    assert!(error.contains("payload CRC mismatch"), "{error}");
    assert!(!String::from_utf8(output.stdout)?.contains("decoded="));
    Ok(())
}
