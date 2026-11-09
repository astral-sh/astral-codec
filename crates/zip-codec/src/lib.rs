//! High-level encoding and decoding for ZIP archives.
//!
//! See [`decode`] for ZIP decoding, [`encode`] for ZIP64 encoding,
//! [`Builder`] for format-neutral construction, and
//! [`Archive::extract_in`] for format-neutral extraction.
//!
//! ## Security and correctness
//!
//! See the [repository's SECURITY.md](https://github.com/astral-sh/astral-codec/blob/main/SECURITY.md)
//! for more information.

#![forbid(unsafe_code)]

pub mod decode;
pub mod encode;
mod payload;

pub use archive_trait::{
    Archive, ArchiveBuilder, BuildError, Builder, EntryMetadata, ExtractError,
    ExtractPolicyViolation, FilePayload, LentPayload, Member, MemberMetadata, MemberPayload,
    Members, NameValidator, SpecialKind, TraversalError, builder, default_name_validator, extract,
};
pub use decode::{DecodeError, ZipArchive, ZipArchiveBuilder, ZipMemberPayload};
pub use encode::{EncodeError, ZipEncoder, ZipFileOptions};
pub use zip_framing::{
    CentralDirectoryEntry, CommentPolicy, CompressionMethod, DeviceNumbers, Entry, EntryKind,
    ExtraFieldPolicy, HostSystem, IndexedEntry, LimitExceeded, Limits,
};
