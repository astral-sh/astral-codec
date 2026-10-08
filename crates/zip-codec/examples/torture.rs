//! Validate a downloaded archive without creating any extracted files.

use std::{env, error::Error, fs, io, io::Cursor, process::ExitCode};

use zip_codec::{Archive, Member, MemberPayload, ZipArchive};

async fn inspect() -> Result<(), Box<dyn Error>> {
    let path = env::args_os().nth(1).ok_or("usage: torture ARCHIVE")?;
    let mut archive = ZipArchive::open(Cursor::new(fs::read(path)?))
        .await
        .map_err(|error| io::Error::other(format!("open: {error} ({error:?})")))?;
    let entries = archive.entries().len();
    let declared_bytes: u64 = archive
        .entries()
        .iter()
        .map(|entry| entry.directory().size())
        .sum();
    println!("{{\"stage\":\"open\",\"entries\":{entries},\"declared_bytes\":{declared_bytes}}}");

    archive
        .validate_all()
        .await
        .map_err(|error| io::Error::other(format!("metadata: {error} ({error:?})")))?;
    println!("{{\"stage\":\"metadata\"}}");

    let mut members = 0;
    let mut payload_bytes = 0_u64;
    let mut buffer = Vec::new();
    while let Some(member) = archive
        .next_member()
        .await
        .map_err(|error| io::Error::other(format!("member {members}: {error} ({error:?})")))?
    {
        if let Member::File {
            metadata,
            mut payload,
            ..
        }
        | Member::HardLink {
            metadata,
            mut payload,
            ..
        } = member
        {
            while payload
                .next_chunk(&mut buffer, 64 * 1024)
                .await
                .map_err(|error| {
                    io::Error::other(format!(
                        "payload {members} {:?}: {error} ({error:?})",
                        metadata.path
                    ))
                })?
            {
                payload_bytes += buffer.len() as u64;
            }
        }
        members += 1;
    }

    if members != entries {
        return Err(io::Error::other("member count differs from the index").into());
    }
    println!("{{\"stage\":\"complete\",\"members\":{members},\"payload_bytes\":{payload_bytes}}}");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match inspect().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
