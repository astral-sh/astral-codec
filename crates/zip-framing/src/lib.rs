//! Strict ZIP record framing for asynchronous, seekable inputs.
//!
//! The core API in this crate is [`Index`], which can be built from a ZIP's
//! central directory and used to access individual members (after reconciling
//! their central and local states).
//!
//! Potentially relevant internals:
//!
//! - [`CentralDirectoryEntry`], [`IndexedEntry`], and [`Entry`] represent a refinement
//!   type hierarchy, i.e. they go from fewest invariants preserved (just parsing
//!   the central directory entry) to the most invariants preserved (a member whose
//!   central and local states are fully reconciled).
//!
//! - zip-framing enforces that all parsed filenames, UNIX extra-field link targets,
//!   and archive/per-member comments are UTF-8. This is an intentional limitation.
//!
//! - zip-framing does not decode or validate member payloads. It exposes their
//!   offsets and compressed sizes so consumers can read and decode them,
//!   then verify their decoded sizes and CRC32s.
//!
//! - zip-framing assumes that the ZIP source does not change.

#![forbid(unsafe_code)]

pub mod constants;
mod extra;
mod host;
mod index;
mod kind;
mod record;
pub mod write;

use std::io;

use thiserror::Error;

pub use extra::{ExtraHeaderId, UnixData};
pub use host::HostSystem;
pub use index::{CentralDirectoryEntry, Entry, Index, IndexedEntry};
pub use kind::EntryKind;

/// A supported ZIP compression method.
///
/// Cast to [`u16`] to obtain the APPNOTE method number.
/// New methods can be added without changing the record or archive APIs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum CompressionMethod {
    /// Uncompressed bytes (method 0).
    #[default]
    Stored = 0,
    /// Raw DEFLATE (method 8).
    Deflate = 8,
}

impl CompressionMethod {
    pub(crate) fn parse(value: u16, position: u64) -> Result<Self, Error> {
        match value {
            value if value == Self::Stored as u16 => Ok(Self::Stored),
            value if value == Self::Deflate as u16 => Ok(Self::Deflate),
            _ => Err(Error::Unsupported {
                position,
                feature: "compression method",
            }),
        }
    }
}

/// Budgets applied before indexing or consuming payloads.
///
/// Raising these values permits correspondingly more memory, I/O, or CPU work.
/// Compressed input and decoded output have independent bounds; no compression
/// ratio heuristic is needed to bound highly compressible files.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum source length (default: 128 GiB).
    pub archive_size: u64,
    /// Maximum number of members (default: 100,000).
    pub entries: usize,
    /// Total central directory, resolved local, and ZIP64 end record metadata
    /// bytes (default: 64 MiB).
    pub metadata_size: u64,
    /// Maximum decoded size of one member (default: 8 GiB).
    pub member_size: u64,
    /// Maximum sum of decoded member sizes (default: 64 GiB).
    pub total_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            archive_size: 128 * 1024 * 1024 * 1024,
            entries: 100_000,
            metadata_size: 64 * 1024 * 1024,
            member_size: 8 * 1024 * 1024 * 1024,
            total_size: 64 * 1024 * 1024 * 1024,
        }
    }
}

/// A malformed, unsupported, or over-budget ZIP archive.
#[derive(Debug, Error)]
pub enum Error {
    /// An input operation failed.
    #[error("ZIP I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Record structure or redundant information was inconsistent.
    #[error("at byte {position}: invalid ZIP: {reason}")]
    Invalid {
        /// Offset of the relevant record.
        position: u64,
        /// The violated format requirement.
        reason: &'static str,
    },
    /// The archive uses an excluded feature.
    #[error("at byte {position}: unsupported ZIP {feature}")]
    Unsupported {
        /// Offset of the relevant record.
        position: u64,
        /// The unsupported feature.
        feature: &'static str,
    },
    /// A configured resource budget was exceeded.
    #[error("ZIP exceeds {resource} limit ({limit})")]
    Limit {
        /// The exhausted resource.
        resource: &'static str,
        /// Configured maximum.
        limit: u64,
    },
}

pub(crate) fn invalid(position: u64, reason: &'static str) -> Error {
    Error::Invalid { position, reason }
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or_else(|| invalid(left, "offset or size overflow"))
}
