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

mod budget;
pub mod constants;
mod extra;
mod host;
mod index;
mod kind;
mod record;
pub mod write;

use std::io;

use thiserror::Error;

pub use budget::{Budget, BudgetError, Limits};
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

impl From<BudgetError> for Error {
    fn from(error: BudgetError) -> Self {
        let (resource, limit) = match error {
            BudgetError::ArchiveSize(limit) => ("archive bytes", limit),
            BudgetError::EntryCount(limit) => ("entry count", limit),
            BudgetError::MetadataSize(limit) => ("metadata bytes", limit),
            BudgetError::MemberSize(limit) => ("decoded member bytes", limit),
            BudgetError::TotalSize(limit) => ("total decoded bytes", limit),
            BudgetError::Overflow(usage) => return invalid(usage, "offset or size overflow"),
        };
        Self::Limit { resource, limit }
    }
}

pub(crate) fn invalid(position: u64, reason: &'static str) -> Error {
    Error::Invalid { position, reason }
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or_else(|| invalid(left, "offset or size overflow"))
}
