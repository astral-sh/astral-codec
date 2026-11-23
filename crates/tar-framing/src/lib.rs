//! Low level framing of tar streams.
//!
//! This crate provides two APIs:
//!
//! - [`stream`] is a low-level, lossless per-block framing API.
//! - [`logical`] is a medium-level, assembled member reader API.
//!
//! [`stream`] provides the basic static machine enforcement for a tar
//! stream, including ensuring that any given stream is either strictly
//! pax *or* GNU and not a mix of the two. [`logical`] is layered on top
//! of [`stream`] and provides APIs for accessing the "effective" metadata
//! for each assembled member.
//!
//! This crate tries to faithfully extract pax or GNU entries without mixing the
//! two. See the sections below for compatibility notes.
//!
//! ## pax compatibility
//!
//! When decoding pax-formatted tar streams, tar-framing attempts to conform to
//! pax as specified in [POSIX.1-2024], i.e. "issue 8" of the POSIX specification.
//! See the [pax specification] for full details.
//!
//! However, there are a few small deviations from a pedantic reading of [POSIX.1-2024]
//! that are worth noting:
//!
//! - tar-framing permits a `ctime` pax record, despite not being specified in [POSIX.1-2024].
//!   The ctime record was removed from pax in [POSIX.1-2004] (which is itself a minor edit
//!   of POSIX.1-2001). However, many real-world pax archives still contain it, and its
//!   presence does not compromise or introduce ambiguity during framing.
//!
//! - tar-framing permits implementation-defined vendor pax records to contain arbitrary
//!   bytes, including invalid UTF-8. POSIX requires extended-header values to default
//!   to UTF-8, but real-world writers including star, GNU tar, and libarchive use raw
//!   `SCHILY.xattr.*` values. Standard and reserved pax record values remain strict UTF-8.
//!
//! - tar-framing requires multi-digit pax `size` values to start with a nonzero digit.
//!   POSIX specifies decimal, so `0777` means 777 bytes. However,
//!   some misbehaving parsers will interpret `0777` as octal (511)
//!   instead, so tar-framing rejects this form.
//!
//! - tar-framing rejects directory entries (typeflag `'5'`) that present a nonzero size
//!   in their ustar header or pax `size` record. pax says that this size should be treated
//!   as a filesystem allocation hint rather than a physical size, but real-world parsers vary
//!   widely in how they handle it (some ignore it, others skip over that number of bytes, etc.).
//!
//! - By default, tar-framing rejects hard links (typeflag `'1'`) with a nonzero size in
//!   their ustar header or effective pax `size` record. Readers disagree on whether the
//!   block after such a link contains payload bytes or the next member header. To read
//!   archives written with `pax -o linkdata`, enable [`StreamPolicy::allow_pax_hardlink_linkdata`].
//!
//! - tar-framing does not change a member type because of a path suffix. For example, it preserves
//!   a trailing slash in an effective member path. Before ustar, tar used a trailing slash to
//!   identify a directory. pax does not require an implementation to use this behavior. Therefore,
//!   a path suffix can conflict with the header type. The extraction layer in tar-codec rejects
//!   this conflict.
//!
//! - tar-framing rejects negative timestamps as well as timestamps that would exceed the
//!   precision of a `u64`. pax allows both of these, although it notes that portable timestamps
//!   cannot be negative and that tools may reject such timestamps.
//!
//! - tar-framing silently removes fractional components from parsed timestamps. Timestamps
//!   are truncated to second precision.
//!
//! - tar-framing rejects typeflags that are not explicitly defined in pax. pax says to handle
//!   these as regular files (i.e. assuming their size is a physical size), but this has marginal
//!   benefit in practice.
//!
//! - tar-framing rejects `hdrcharset` pax records that aren't UTF-8 or `BINARY`. pax says
//!   that "additional names may be agreed between the originator and the recipient," but
//!   we are the recipient and we don't accept any other `hdrcharset` names.
//!
//! ## GNU compatibility
//!
//! When decoding GNU-formatted tar streams, tar-framing attempts to follow the
//! ["Basic Tar Format"] in the GNU docs. Specifically, tar-framing attempts
//! to follow the rules for the "old GNU" format, i.e. GNU tar's non-pax format.
//!
//! tar-framing intentionally only supports a subset of the GNU tar format:
//!
//! - The GNU "longname" and "longlink" (`'L'` and `'K'`) typeflags are supported,
//!   with similar path-precedence semantics as their pax record equivalents.
//!
//! - Other GNU-specific typeflags are **not** supported whatsoever, and produce
//!   a framing error. This includes sparse files (`'S'`) and multivolume headers
//!   (`'M'`).
//!
//! - tar-framing accepts the GNU-specific "base-256" encoding for numbers, but rejects
//!   negative encodings as well as any value that would exceed the precision of a `u64`.
//!   tar-framing also allows "base-256" encodings where the numeric value _would_ fit
//!   into an octal encoding in the alloted buffer/byte span; GNU technically says that
//!   this is reserved for future use.
//!
//! ## General compatibility
//!
//! Because pax and GNU both use ustar as their baseline, any compatibility aspect of pax
//! that is derived from ustar also applies during GNU tar decoding.
//!
//! tar-framing does not support tar families other than pax and GNU. That includes the "legacy" (V7) and star families.
//!
//! POSIX ustar permits the blocks after the two-block end-of-archive marker
//! in the final physical record to contain undefined data. GNU tar and Python's
//! `tarfile` normally pad the final record with zeros to a 20-block boundary.
//! By default, tar-framing accepts whole zero blocks after the marker up to
//! that boundary. EOF may follow the marker or any accepted padding block.
//! [`StreamPolicy::trailing_data_policy`] configures this behavior.
//!
//! Only hard links and symbolic links may carry a link target in the ordinary
//! `linkname` field, a pax `linkpath` record, or a GNU long-link extension.
//! A pax deletion cannot hide a populated `linkname` on a non-link member.
//! Some older Docker layers leave a stale `linkname` on regular-file whiteouts;
//! [`StreamPolicy::allow_header_linkname_on_non_link_members`] ignores that field instead.
//!
//! tar-framing accepts wholly NUL `mode`, `uid`, `gid`, and `mtime` fields by default for
//! compatibility with real-world writers in both families. These fields are represented as
//! missing rather than assigned a value. This can be disabled with
//! [`StreamPolicy::allow_all_nul_numeric_fields`].
//!
//! By default, tar-framing requires the numeric fields of pax/ustar headers to be octal.
//! Some writers, including the Rust `tar` crate, encode large `uid` and `gid` values
//! with GNU base-256 notation even in ustar headers. These two fields can be accepted with
//! [`StreamPolicy::allow_pax_base256_uid_and_gid`].
//!
//! By default, tar-framing follows a strict reading of pax and requires the `uname` and `gname`
//! header fields to be NUL terminated (the `magic` field is also required to be NUL terminated, but
//! is so by definition). However, some encoders will incorrectly pack a 32-byte value into
//! these fields, rather than honoring the 31-byte + NUL terminator limit.
//! CPython's `tarfile` in particular does this.
//! This can be disabled with [`StreamPolicy::allow_header_uname_and_gname_without_terminator`].
//!
//! tar-framing also requires GNU long-name and long-link payloads to be NUL terminated by default.
//! The Rust `tar` crate from 0.3.3 to 0.4.3 wrote long-name payloads without the terminator.
//! These payloads can be accepted with [`StreamPolicy::allow_gnu_extensions_without_terminator`].
//!
//! Separately, higher-level crates (like tar-codec) may choose to apply additional
//! restrictions when processing logical archive members. For example, a consumer
//! of tar-framing may choose to reject vendor-specific pax records, or member names
//! that contain forbidden characters, or any other additional restriction.
//!
//! [POSIX.1-2024]: https://pubs.opengroup.org/onlinepubs/9799919799/
//! [pax specification]: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/pax.html
//! [POSIX.1-2004]: https://pubs.opengroup.org/onlinepubs/009695399/toc.htm
//! ["Basic Tar Format"]: https://www.gnu.org/software/tar/manual/html_node/Standard.html

use std::fmt;

mod error;
pub mod header;
pub mod logical;
mod pax;
pub mod stream;
#[cfg(test)]
mod test_support;
pub mod write;

pub use error::{FrameError, FrameErrorInner};
pub use pax::{
    HdrCharset, PaxError, PaxExtension, PaxKeyword, PaxRecord, PaxState, PaxString, PaxValue,
};
pub use stream::StreamPolicy;

/// The size of a logical tar record.
pub const BLOCK_SIZE: usize = 512;

/// The default maximum size in bytes of one local or global pax extension.
///
/// This is 256 KiB.
pub const DEFAULT_MAX_PAX_EXTENSION_SIZE: u64 = 256 * 1024;

/// The default maximum total payload size of all global pax extensions.
///
/// This limit applies to the full archive. It does not reset after an ordinary
/// member.
///
/// This is 1 MiB.
pub const DEFAULT_MAX_GLOBAL_PAX_EXTENSIONS_SIZE: u64 = 4 * DEFAULT_MAX_PAX_EXTENSION_SIZE;

/// The default maximum size in bytes of one GNU extension.
///
/// This is 128 KiB.
pub const DEFAULT_MAX_GNU_EXTENSION_SIZE: u64 = 128 * 1024;

/// A single tar block.
pub type Block = [u8; BLOCK_SIZE];

/// Controls what the reader accepts after the two-block end-of-archive marker.
///
/// The default is [`BlockingFactor(20)`](Self::BlockingFactor), a 10,240-byte record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrailingDataPolicy {
    /// Require EOF immediately after the marker.
    Strict,
    /// Permit whole 512-byte zero blocks up to the end of the current record.
    ///
    /// The blocking factor is the number of blocks per record, measured from
    /// the start of the archive. EOF may occur immediately after the marker or
    /// after any allowed padding block. If the marker ends on a record boundary,
    /// or the factor is 0 or 1, EOF must immediately follow the marker.
    BlockingFactor(u8),
    /// Stop at the marker and leave all following bytes unread.
    Ignore,
}

impl Default for TrailingDataPolicy {
    fn default() -> Self {
        // NOTE: a blocking factor of 20 matches the default in GNU tar
        // and Python's `tarfile`.
        Self::BlockingFactor(20)
    }
}

/// An automatically detected, mutually exclusive tar archive family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    /// pax ustar headers with optional pax extended headers.
    Pax,
    /// Old GNU tar headers with optional `L` and `K` extension entries.
    Gnu,
}

impl fmt::Display for ArchiveFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pax => formatter.write_str("pax"),
            Self::Gnu => formatter.write_str("GNU"),
        }
    }
}

/// The scope of a pax extended header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaxKind {
    /// A typeflag `x` header applying to the next ordinary member.
    Local,
    /// A typeflag `g` header updating persistent global values.
    Global,
}

/// The supported GNU extension kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GnuKind {
    /// A typeflag `L` extension giving a long name for the next member.
    LongName,
    /// A typeflag `K` extension giving a long link name for the next member.
    LongLink,
}

/// A supported ordinary ustar member type.
///
/// These are shared across both pax and GNU tar streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UstarKind {
    /// A regular file (`'0'` or NUL).
    Regular,
    /// A hard link (`'1'`).
    HardLink,
    /// A symbolic link (`'2'`).
    SymbolicLink,
    /// A character device (`'3'`).
    CharacterDevice,
    /// A block device (`'4'`).
    BlockDevice,
    /// A directory (`'5'`).
    Directory,
    /// A FIFO (`'6'`).
    Fifo,
    /// A contiguous file (`'7'`).
    Contiguous,
}
