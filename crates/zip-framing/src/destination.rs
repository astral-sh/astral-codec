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
    let path = path.trim_end_matches('/');
    if !path.split('/').any(|part| matches!(part, "" | ".")) {
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
    if entries.len() < 2 || unique_sibling_groups(entries).await {
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

/// Proves uniqueness when each parent directory occurs in a single run.
async fn unique_sibling_groups(entries: &[IndexedEntry]) -> bool {
    let mut members = entries
        .iter()
        .map(|entry| destination_parts(entry.directory().path()))
        .peekable();
    let mut parents = Vec::new();
    let mut siblings = Vec::new();
    let mut checksums = Vec::new();
    while let Some((parent, name)) = members.next() {
        siblings.push(name);
        while let Some((_, name)) = members.next_if(|(next, _)| *next == parent) {
            siblings.push(name);
            if siblings.len().is_multiple_of(128) {
                tokio::task::consume_budget().await;
            }
        }
        if !siblings.is_sorted_by(|left, right| left < right) {
            for chunk in siblings.chunks(128) {
                checksums.extend(chunk.iter().map(|name| crc32(name.as_bytes())));
                tokio::task::consume_budget().await;
            }
            if !distinct_checksums(&mut checksums) {
                return false;
            }
            checksums.clear();
        }
        siblings.clear();
        if !parents.is_empty() || members.peek().is_some() {
            parents.push(crc32(member_destination(parent).as_bytes()));
        }
        tokio::task::consume_budget().await;
    }
    distinct_checksums(&mut parents)
}

// Different checksums prove the strings differ. A match only selects the
// exact, directory-order check; it never rejects a member by itself.
fn distinct_checksums(checksums: &mut [u32]) -> bool {
    checksums.sort_unstable();
    checksums.windows(2).all(|pair| pair[0] != pair[1])
}
