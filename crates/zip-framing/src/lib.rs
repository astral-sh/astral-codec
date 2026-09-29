//! Strict ZIP record framing for asynchronous, seekable inputs.
//!
//! [`Index::read`] validates all record boundaries and redundant member metadata.
//! It does not read file contents: consumers must verify decoded sizes and CRCs.
//! The source must remain unchanged while the index and its payloads are used.

#![forbid(unsafe_code)]

mod extra;
mod index;
mod record;

use std::io;

use thiserror::Error;

pub use index::{Entry, Index};

/// A supported ZIP compression method.
///
/// New methods can be added without changing the record or archive APIs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CompressionMethod {
    /// Uncompressed bytes (method 0).
    #[default]
    Stored,
    /// Raw DEFLATE (method 8).
    Deflate,
}

impl CompressionMethod {
    /// Returns the APPNOTE method number.
    pub fn number(self) -> u16 {
        match self {
            Self::Stored => 0,
            Self::Deflate => 8,
        }
    }

    pub(crate) fn parse(value: u16, position: u64) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Stored),
            8 => Ok(Self::Deflate),
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
    /// Total local and central metadata bytes (default: 64 MiB).
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

pub(crate) fn check_limit(value: u64, limit: u64, resource: &'static str) -> Result<(), Error> {
    if value > limit {
        return Err(Error::Limit { resource, limit });
    }

    Ok(())
}
