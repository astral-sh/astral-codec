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
//! - Filenames and UNIX extra-field link targets must be UTF-8.
//!
//! - zip-framing does not decode or validate member payloads. It exposes their
//!   offsets and compressed sizes so consumers can read and decode them,
//!   then verify their decoded sizes and CRC32s.
//!
//! - zip-framing assumes that the ZIP source does not change.
//!
//! ## ZIP compatibility
//!
//! - zip-framing rejects empty filenames, including unnamed members from
//!   standard input (APPNOTE 4.4.17.1).
//!
//! - Directory member names must end in `/` so readers can identify their type
//!   from the filename alone. For empty Stored directories written by Info-ZIP 3.0
//!   with extraction version 1.0, see [`IndexPolicy::allow_version_1_directories`].
//!
//! - APPNOTE 4.4.17.1 requires forward slashes as path separators. By default,
//!   zip-framing rejects backslashes in member names. See
//!   [`IndexPolicy::allow_backslashes`].
//!
//! - By default, zip-framing rejects stored members that use a data descriptor,
//!   since other streaming ZIP parsers frequently misinterpret them.
//!   See [`IndexPolicy::allow_stored_data_descriptors`].
//!
//! - By default, zip-framing does not honor symlink mode bits unless the host
//!   system indicated by the "version made by" field indicates a UNIX host (3).
//!   See [`IndexPolicy::allow_ambiguous_symlink_modes`].
//!
//! - zip-framing rejects members that have the "record-oriented" bit set in their
//!   internal file attributes (APPNOTE 4.4.14.2).
//!
//! - zip-framing is conservative about which ZIP extras it accepts. By default,
//!   it only accepts the ZIP64 indicator extra (`0x0001`). Users can opt into
//!   a larger subset of "well-known" extras with [`ExtraFieldPolicy::AllowListed`].

#![forbid(unsafe_code)]

mod budget;
pub mod constants;
mod extra;
mod host;
mod index;
mod kind;
mod record;
mod wire;
pub mod write;

use std::io;

use thiserror::Error;

pub use budget::{Budget, BudgetError, LimitExceeded, Limits};
pub use extra::{ExtraFieldPolicy, ExtraHeaderId};
pub use host::HostSystem;
pub use index::{
    CentralDirectoryEntry, CommentPolicy, CommentRule, Entry, Index, IndexPolicy, IndexedEntry,
};
pub use kind::{DeviceNumbers, EntryKind};

/// A supported ZIP compression method.
///
/// Cast to [`u16`] to obtain the APPNOTE method number.
/// New methods can be added without changing the record or archive APIs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum CompressionMethod {
    /// Uncompressed bytes (method 0).
    Stored = 0,
    /// Raw DEFLATE (method 8, the default).
    #[default]
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

/// A supported ZIP feature excluded by the selected [`IndexPolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum IndexPolicyViolation {
    /// A known member extra field was excluded by the extra-field policy.
    #[error("extra field {:#06x}", u16::from(*identifier))]
    ExtraField {
        /// The supported extra-field identifier from the member header.
        identifier: ExtraHeaderId,
    },
    /// The archive comment did not meet the configured comment rule.
    #[error("archive comment rejected by {rule:?}")]
    ArchiveComment {
        /// The rule for the end-record comment.
        rule: CommentRule,
    },
    /// A member comment did not meet the configured comment rule.
    #[error("member comment rejected by {rule:?}")]
    MemberComment {
        /// The rule for central-directory comments.
        rule: CommentRule,
    },
    /// A Stored member uses a data descriptor.
    #[error("data descriptor for Stored member")]
    StoredDataDescriptor,
    /// A DEFLATE member with zero uncompressed size declares compressed bytes.
    #[error("empty DEFLATE stream")]
    EmptyDeflateStream,
    /// An empty Stored directory declares extraction version 1.0.
    #[error("directory declares extraction version 1.0")]
    Version1Directory,
    /// A non-Unix creator supplied Unix symlink mode bits.
    #[error("symlink mode from a non-Unix creator system")]
    AmbiguousSymlinkMode,
    /// A member name contains a literal backslash.
    #[error("backslash in member name")]
    BackslashInName,
}

/// A failure while reading or writing ZIP records.
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
    /// A member header contains an extra field that the reader does not support.
    #[error("at byte {position}: unsupported ZIP extra field {identifier:#06x}")]
    UnsupportedExtraField {
        /// Offset of the member header.
        position: u64,
        /// Extra-field identifier from the header.
        identifier: u16,
    },
    /// A supported feature was rejected by the index policy.
    #[error("at byte {position}: index policy rejected input: {violation}")]
    PolicyViolation {
        /// Offset of the relevant record.
        position: u64,
        /// The policy rule that rejected the feature.
        violation: IndexPolicyViolation,
    },
    /// A configured resource budget was exceeded.
    #[error(transparent)]
    Limit(#[from] LimitExceeded),
}

impl From<BudgetError> for Error {
    fn from(error: BudgetError) -> Self {
        match error {
            BudgetError::Limit(limit) => Self::Limit(limit),
            BudgetError::Overflow(usage) => invalid(usage, "offset or size overflow"),
        }
    }
}

pub(crate) fn invalid(position: u64, reason: &'static str) -> Error {
    Error::Invalid { position, reason }
}

pub(crate) fn policy_violation(position: u64, violation: IndexPolicyViolation) -> Error {
    Error::PolicyViolation {
        position,
        violation,
    }
}

pub(crate) fn add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right)
        .ok_or_else(|| invalid(left, "offset or size overflow"))
}
