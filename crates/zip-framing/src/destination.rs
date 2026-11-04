//! Destination comparisons for ZIP member names.

use std::{borrow::Cow, collections::HashSet};

use crc32fast::hash as crc32;
use memchr::memrchr;

use crate::{Error, IndexedEntry, invalid};

/// Returns the case-sensitive destination used to detect duplicate ZIP members.
///
/// Empty and `.` components do not change a destination. All other components,
/// including `..`, are compared literally. This does not validate a path for
/// filesystem extraction.
pub fn member_destination(path: &str) -> Cow<'_, str> {
    let path = path.trim_matches('/');
    if !path.starts_with('.') && !path.contains("/.") && !path.contains("//") {
        return Cow::Borrowed(path);
    }

    let mut destination = String::with_capacity(path.len());
    for part in path.split('/').filter(|part| !matches!(*part, "" | ".")) {
        if !destination.is_empty() {
            destination.push('/');
        }
        destination.push_str(part);
    }
    Cow::Owned(destination)
}

/// Rejects the first duplicate in central-directory order.
pub(crate) async fn check_destinations(entries: &[IndexedEntry]) -> Result<(), Error> {
    if entries.len() < 2 || distinct_fingerprints(entries).await {
        return Ok(());
    }

    let mut destinations = HashSet::with_capacity(entries.len());
    for entry in entries {
        let directory = entry.directory();
        if !destinations.insert(member_destination(directory.path())) {
            return Err(invalid(
                directory.position(),
                "duplicate member destination",
            ));
        }
        tokio::task::consume_budget().await;
    }
    Ok(())
}

/// Splits off the final component that survives destination normalization.
fn destination_parts(mut path: &str) -> (&str, &str) {
    loop {
        let Some(slash) = memrchr(b'/', path.as_bytes()) else {
            return ("", if path == "." { "" } else { path });
        };
        let (parent, rest) = path.split_at(slash);
        let name = &rest[1..];
        if !matches!(name, "" | ".") {
            return (parent, name);
        }
        path = parent;
    }
}

/// Hash each normalized parent once per run of siblings. Equal destinations have
/// equal parent and filename checksums. A matching pair needs an exact comparison.
async fn distinct_fingerprints(entries: &[IndexedEntry]) -> bool {
    let mut fingerprints = Vec::with_capacity(entries.len());
    let mut previous_parent = "";
    let mut parent_crc = crc32(b"");
    for chunk in entries.chunks(128) {
        for entry in chunk {
            let (parent, name) = destination_parts(entry.directory().path());
            if parent != previous_parent {
                parent_crc = crc32(member_destination(parent).as_bytes());
                previous_parent = parent;
            }
            fingerprints.push((u64::from(parent_crc) << 32) | u64::from(crc32(name.as_bytes())));
        }
        tokio::task::consume_budget().await;
    }
    fingerprints.sort_unstable();
    fingerprints.windows(2).all(|pair| pair[0] != pair[1])
}
