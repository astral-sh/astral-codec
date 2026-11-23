use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use thiserror::Error;
use tokio::fs::File;
use zip_codec::{
    Archive as _, DecodeError, DecodePolicy, ExtractError, Member, MemberPayload as _, SpecialKind,
    ZipArchive, extract::ExtractPolicy,
};
use zip_framing::{Error as FrameError, ExtraFieldPolicy, Index, IndexPolicy};

/// Inspect and extract ZIP archives.
#[derive(Debug, Parser)]
struct Cli {
    /// Accept ZIP extra fields on the reader's allowlist (default: ZIP64 only).
    #[arg(long, global = true)]
    allow_known_extras: bool,
    /// Accept empty, uncompressed directory entries that declare extraction version 1.0.
    #[arg(long, global = true)]
    allow_version_1_directories: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
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
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let extras = if cli.allow_known_extras {
        ExtraFieldPolicy::AllowListed
    } else {
        ExtraFieldPolicy::default()
    };
    let decode_policy = DecodePolicy::default()
        .extra_field_policy(extras)
        .allow_version_1_directories(cli.allow_version_1_directories);
    match cli.command {
        Command::Frames { archive } => {
            let index_policy = IndexPolicy::default()
                .extra_field_policy(extras)
                .allow_version_1_directories(cli.allow_version_1_directories);
            dump_frames(&archive, index_policy, &mut io::stdout().lock()).await
        }
        Command::Logical { archive } => {
            dump_logical(&archive, decode_policy, &mut io::stdout().lock()).await
        }
        Command::Extract {
            archive,
            destination,
        } => {
            open_archive(&archive, decode_policy)
                .await?
                .extract_in(destination, ExtractPolicy::default())
                .await?;
            Ok(())
        }
    }
}

async fn open_file(path: &Path) -> Result<File, CliError> {
    File::open(path).await.map_err(|source| CliError::Open {
        path: path.to_owned(),
        source,
    })
}

async fn open_archive(path: &Path, policy: DecodePolicy) -> Result<ZipArchive<File>, CliError> {
    Ok(ZipArchive::open_with_policy(open_file(path).await?, policy).await?)
}

async fn dump_frames(
    path: &Path,
    policy: IndexPolicy,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let mut file = open_file(path).await?;
    let mut index = Index::read_with_policy(&mut file, policy).await?;
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

async fn dump_logical(
    path: &Path,
    policy: DecodePolicy,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let mut archive = open_archive(path, policy).await?;
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
