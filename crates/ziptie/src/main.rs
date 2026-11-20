use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use thiserror::Error;
use tokio::fs::File;
use zip_codec::{
    Archive as _, DecodeError, ExtractError, Member, MemberPayload as _, SpecialKind, ZipArchive,
    extract::ExtractPolicy,
};
use zip_framing::{Error as FrameError, Index};

/// Inspect and extract ZIP archives.
#[derive(Debug, Parser)]
enum Command {
    /// Check local records and dump their offsets and central directory metadata.
    Frames {
        /// The ZIP archive to inspect.
        archive: PathBuf,
    },
    /// Dump decoded members and verify their payloads.
    Logical {
        /// The ZIP archive to inspect.
        archive: PathBuf,
    },
    /// Securely extract a ZIP archive.
    Extract {
        /// The ZIP archive to extract.
        archive: PathBuf,
        /// The directory to extract into.
        destination: PathBuf,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("failed to open {path:?}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Framing(#[from] FrameError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Extract(#[from] ExtractError<DecodeError>),
    #[error("failed to write archive dump: {0}")]
    Output(#[from] io::Error),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Command::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Frames { archive } => dump_frames(&archive, &mut io::stdout().lock()).await,
        Command::Logical { archive } => dump_logical(&archive, &mut io::stdout().lock()).await,
        Command::Extract {
            archive,
            destination,
        } => {
            ZipArchive::open(open_archive(&archive).await?)
                .await?
                .extract_in(destination, ExtractPolicy::default())
                .await?;
            Ok(())
        }
    }
}

async fn open_archive(path: &Path) -> Result<File, CliError> {
    File::open(path).await.map_err(|source| CliError::Open {
        path: path.to_owned(),
        source,
    })
}

async fn dump_frames(path: &Path, output: &mut impl Write) -> Result<(), CliError> {
    let mut file = open_archive(path).await?;
    let mut index = Index::read(&mut file).await?;
    writeln!(output, "archive: {path:?}\nformat: zip\nframes:")?;
    let mut number = 0;
    while let Some(entry) = index.entry(&mut file, number).await? {
        let directory = entry.directory();
        writeln!(
            output,
            "    [{number}] record={:?} path={:?}",
            entry.record_range(),
            directory.path()
        )?;
        writeln!(
            output,
            "        data @{} method={:?} compressed={} uncompressed={} crc32={:08x}",
            entry.data_offset(),
            directory.method(),
            directory.compressed_size(),
            directory.size(),
            directory.crc32()
        )?;
        number += 1;
    }
    output.flush()?;
    Ok(())
}

async fn dump_logical(path: &Path, output: &mut impl Write) -> Result<(), CliError> {
    let mut archive = ZipArchive::open(open_archive(path).await?).await?;
    writeln!(output, "archive: {path:?}\nformat: zip\nmembers:")?;
    let mut buffer = Vec::new();
    let mut number = 0usize;
    while let Some(member) = archive.next_member().await? {
        let metadata = member.metadata();
        let path = &metadata.path;
        write!(output, "    [{number}] @{} ", metadata.position)?;
        match &member {
            Member::File { executable, .. } => {
                writeln!(output, "regular path={path:?} executable={executable}")?;
            }
            Member::Directory { .. } => writeln!(output, "directory path={path:?}")?,
            Member::SymbolicLink { target, .. } => {
                writeln!(output, "symbolic-link path={path:?} link={target:?}")?;
            }
            Member::HardLink { target, .. } => {
                writeln!(output, "hard-link path={path:?} link={target:?}")?;
            }
            Member::Special { kind, .. } => {
                let kind = match kind {
                    SpecialKind::CharacterDevice => "character-device",
                    SpecialKind::BlockDevice => "block-device",
                    SpecialKind::Fifo => "fifo",
                };
                writeln!(output, "{kind} path={path:?}")?;
            }
        }
        if let Member::File { mut payload, .. } | Member::HardLink { mut payload, .. } = member {
            let mut decoded = 0u64;
            while payload.next_chunk(&mut buffer, 64 * 1024).await? {
                decoded += buffer.len() as u64;
            }
            writeln!(output, "        decoded={decoded}")?;
        }
        number += 1;
    }
    output.flush()?;
    Ok(())
}
