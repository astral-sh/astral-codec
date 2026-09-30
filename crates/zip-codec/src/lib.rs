//! Asynchronous, seekable ZIP archives with bounded payload processing.
//!
//! [`ZipArchive::open`] checks the directory; member access reconciles local
//! records. [`ZipArchive::validate_all`] checks metadata for unselected members.
//! Payload integrity is checked during consumption, including skipped payloads.
//! Filesystem containment and link policy belong to [`Archive::extract_in`].
//! The source must remain unchanged until all archive operations finish.

#![forbid(unsafe_code)]

pub mod decode;
pub mod encode;
mod payload;

pub use archive_trait::{
    Archive, ArchiveBuilder, BuildError, Builder, EntryMetadata, ExtractError,
    ExtractPolicyViolation, FilePayload, LentPayload, Member, MemberMetadata, MemberPayload,
    Members, NameValidator, SpecialKind, TraversalError, builder, default_name_validator, extract,
};
pub use decode::{DecodeError, ZipArchive, ZipMemberPayload};
pub use encode::{EncodeError, ZipEncoder, ZipFileOptions};
pub use zip_framing::{CompressionMethod, DirectoryEntry, Entry, EntryKind, IndexedEntry, Limits};
