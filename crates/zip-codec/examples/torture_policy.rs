//! Emit decoded member metadata and drain payloads without extracting files.
//! Path and policy observations are evaluated by scripts/torture_policy.py.

use std::{env, error::Error, fs, io, io::Cursor, process::ExitCode};

use zip_codec::{Archive, Member, MemberPayload, SpecialKind, ZipArchive, default_name_validator};

// Hex keeps arbitrary UTF-8 member names unambiguous in the JSON-lines protocol.
fn hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn inspect() -> Result<(), Box<dyn Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: torture_policy ARCHIVE")?;
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
    let modes: Vec<_> = archive
        .entries()
        .iter()
        .map(|entry| {
            entry
                .resolved()
                .map(|entry| entry.unix_mode())
                .ok_or("unresolved member")
        })
        .collect::<Result<_, _>>()?;
    println!("{{\"stage\":\"metadata\"}}");

    let mut members = 0;
    let mut payload_bytes = 0_u64;
    let mut buffer = Vec::new();
    while let Some(member) = archive
        .next_member()
        .await
        .map_err(|error| io::Error::other(format!("member {members}: {error} ({error:?})")))?
    {
        let (kind, target) = match &member {
            Member::File { .. } => ("file", ""),
            Member::Directory { .. } => ("directory", ""),
            Member::SymbolicLink { target, .. } => ("symlink", target.as_str()),
            Member::HardLink { target, .. } => ("hardlink", target.as_str()),
            Member::Special { kind, .. } => (
                match kind {
                    SpecialKind::CharacterDevice => "character_device",
                    SpecialKind::BlockDevice => "block_device",
                    SpecialKind::Fifo => "fifo",
                },
                "",
            ),
        };
        let metadata = member.metadata();
        println!(
            "{{\"stage\":\"member\",\"index\":{members},\"position\":{},\"path_hex\":\"{}\",\"kind\":\"{kind}\",\"target_hex\":\"{}\",\"name_accepted\":{},\"target_name_accepted\":{},\"unix_mode\":{}}}",
            metadata.position,
            hex(&metadata.path),
            hex(target),
            default_name_validator(&metadata.path),
            default_name_validator(target),
            modes
                .get(members)
                .ok_or("member is absent from the index")?,
        );
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
