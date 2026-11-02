//! Byte-preserving tar members.
//!
//! Paths and targets are effective archive bytes, with extensions applied but
//! without normalization or extraction validation. Consumers must validate
//! them before using them as filesystem paths.

use archive_trait::{Member, MemberMetadata, SpecialKind};

use super::DecodeError;

/// Byte-preserving metadata for one tar member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteMemberMetadata {
    /// The archive-relative member path before extraction normalization.
    pub path: Vec<u8>,
    /// The member's byte position in the source archive.
    pub position: u64,
}

/// One tar member with byte-preserving paths and link targets.
#[derive(Debug)]
pub enum ByteMember<P> {
    /// A regular file with a streaming payload.
    File {
        /// Common member metadata.
        metadata: ByteMemberMetadata,
        /// The logical, decoded payload size in bytes.
        ///
        /// `payload` must yield exactly this many bytes before completing
        /// successfully. Format-level framing and compression are excluded.
        size: u64,
        /// Whether the archived mode carries executable intent.
        executable: bool,
        /// The streaming member payload.
        payload: P,
    },
    /// A directory.
    Directory {
        /// Common member metadata.
        metadata: ByteMemberMetadata,
    },
    /// A symbolic link.
    SymbolicLink {
        /// Common member metadata.
        metadata: ByteMemberMetadata,
        /// The archive-provided link target.
        target: Vec<u8>,
    },
    /// A hard link, optionally followed by replacement payload bytes.
    HardLink {
        /// Common member metadata.
        metadata: ByteMemberMetadata,
        /// The archive-provided link target.
        target: Vec<u8>,
        /// The logical, decoded replacement-payload size in bytes.
        ///
        /// `payload` must yield exactly this many bytes before completing
        /// successfully. Format-level framing and compression are excluded.
        size: u64,
        /// The streaming member payload.
        payload: P,
    },
    /// A parsed special file that cannot be extracted safely.
    Special {
        /// Common member metadata.
        metadata: ByteMemberMetadata,
        /// The special-file kind.
        kind: SpecialKind,
    },
}

impl<P> ByteMember<P> {
    /// Returns this member's common metadata.
    pub fn metadata(&self) -> &ByteMemberMetadata {
        match self {
            Self::File { metadata, .. }
            | Self::Directory { metadata }
            | Self::SymbolicLink { metadata, .. }
            | Self::HardLink { metadata, .. }
            | Self::Special { metadata, .. } => metadata,
        }
    }

    pub(super) fn into_utf8(self) -> Result<Member<P>, DecodeError> {
        let position = self.metadata().position;
        let path = |metadata: ByteMemberMetadata| -> Result<MemberMetadata, DecodeError> {
            Ok(MemberMetadata {
                path: String::from_utf8(metadata.path).map_err(|_| DecodeError::InvalidUtf8 {
                    position,
                    field: "path",
                })?,
                position,
            })
        };
        let target = |target| {
            String::from_utf8(target).map_err(|_| DecodeError::InvalidUtf8 {
                position,
                field: "linkpath",
            })
        };
        Ok(match self {
            Self::File {
                metadata,
                size,
                executable,
                payload,
            } => Member::File {
                metadata: path(metadata)?,
                size,
                executable,
                payload,
            },
            Self::Directory { metadata } => Member::Directory {
                metadata: path(metadata)?,
            },
            Self::SymbolicLink {
                metadata,
                target: link_target,
            } => Member::SymbolicLink {
                metadata: path(metadata)?,
                target: target(link_target)?,
            },
            Self::HardLink {
                metadata,
                target: link_target,
                size,
                payload,
            } => Member::HardLink {
                metadata: path(metadata)?,
                target: target(link_target)?,
                size,
                payload,
            },
            Self::Special { metadata, kind } => Member::Special {
                metadata: path(metadata)?,
                kind,
            },
        })
    }
}
