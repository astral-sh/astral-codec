//! High-level decoding and encoding for tar archives.
//!
//! See [`decode`] for tar decoding, [`encode`] for pax encoding, and
//! [`Builder`] for format-neutral construction.
#![cfg_attr(
    feature = "fs",
    doc = "See [`Archive::extract_in`] for format-neutral extraction."
)]
//!
//! ## Security and correctness
//!
//! Like other tar parsers, tar-codec assumes that it has unique access
//! to the target directory (the "extraction root") when extracting,
//! and to any targeted inputs when building a new archive.
//! Concurrent mutation of files under the extraction root
//! or of files being added to an archive is outside of the threat model.
//!
//! See the [repository's SECURITY.md](https://github.com/astral-sh/astral-codec/blob/main/SECURITY.md)
//! for more information.

pub mod decode;
pub mod encode;

pub use archive_trait::builder;
pub use archive_trait::{
    Archive, ArchiveBuilder, BuildError, Builder, EntryMetadata, FilePayload, LentPayload, Member,
    MemberMetadata, MemberPayload, Members, NameValidator, SpecialKind, default_name_validator,
};
#[cfg(feature = "fs")]
pub use archive_trait::{ExtractError, ExtractPolicyViolation, TraversalError, extract};
pub use decode::{
    DecodeError, DecodePolicy, DecodePolicyViolation, PaxDecodePolicy, PaxVendorAllowlist,
    PaxVendorExtensionPolicy, TarArchive, TarMemberPayload,
};
pub use encode::{EncodeError, TarEncoder};
