//! ZIP wire-format values shared by record parsing, serialization, and codecs.
//!
//! These identify fields and features; they do not imply support for them.
//! See the [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

/// Record signatures (APPNOTE section 4.3).
pub mod signature {
    /// Local file header.
    pub const LOCAL: u32 = 0x0403_4b50;
    /// Central directory file header.
    pub const CENTRAL: u32 = 0x0201_4b50;
    /// Optional data descriptor signature.
    pub const DESCRIPTOR: u32 = 0x0807_4b50;
    /// End of central directory.
    pub const END: u32 = 0x0605_4b50;
    /// ZIP64 end of central directory.
    pub const ZIP64_END: u32 = 0x0606_4b50;
    /// ZIP64 end of central directory locator.
    pub const ZIP64_LOCATOR: u32 = 0x0706_4b50;
    /// Archive extra data record.
    pub const ARCHIVE_EXTRA: u32 = 0x0806_4b50;
}

/// Fixed record lengths in bytes, excluding variable data (APPNOTE section 4.3).
pub mod size {
    /// Record signature.
    pub const SIGNATURE: usize = 4;
    /// Local file header, including its signature.
    pub const LOCAL: usize = 30;
    /// Central directory file header, including its signature.
    pub const CENTRAL: usize = 46;
    /// Classic data descriptor without a signature.
    pub const DESCRIPTOR: usize = 12;
    /// ZIP64 data descriptor without a signature.
    pub const ZIP64_DESCRIPTOR: usize = 20;
    /// End of central directory, including its signature.
    pub const END: usize = 22;
    /// ZIP64 end record signature and size field, excluded from its declared size.
    pub const ZIP64_END_PREFIX: usize = 12;
    /// ZIP64 version-1 end record body, excluding extensible data.
    pub const ZIP64_END_BODY: usize = 44;
    /// ZIP64 version-1 end record, including its signature and size field.
    pub const ZIP64_END: usize = ZIP64_END_PREFIX + ZIP64_END_BODY;
    /// ZIP64 end of central directory locator, including its signature.
    pub const ZIP64_LOCATOR: usize = 20;
    /// Archive extra data record header, including its signature.
    pub const ARCHIVE_EXTRA: usize = 8;
    /// ZIP64 extensible data sector field header (two-byte ID, four-byte size).
    pub const ZIP64_EXTENSION: usize = 6;
}

/// Extra-field layouts (APPNOTE sections 4.5 and 4.6).
///
/// Header identifiers are represented by [`crate::ExtraHeaderId`].
pub mod extra {
    /// Extra-field header length in bytes (two-byte ID, two-byte size).
    pub const HEADER_SIZE: usize = 4;
    /// PKWARE UNIX timestamp and ownership prefix length in bytes.
    pub const UNIX_PREFIX_SIZE: usize = 12;
    /// ZIP64 local extra data length in bytes (both sizes).
    pub const ZIP64_LOCAL_SIZE: usize = 16;
    /// ZIP64 central extra data length in bytes when both sizes and the offset are present.
    pub const ZIP64_CENTRAL_SIZE: usize = 24;
}

/// Extraction versions, encoded as major version times ten plus minor version.
pub mod version {
    /// ZIP 1.0, the baseline extraction version.
    pub const BASE: u16 = 10;
    /// ZIP 2.0, required for DEFLATE and directory entries.
    pub const V2_0: u16 = 20;
    /// ZIP 4.5, required for ZIP64.
    pub const ZIP64: u16 = 45;
    /// ZIP 6.2, introducing encrypted central directories and ZIP64 version-2 end records.
    pub const ZIP64_V2: u16 = 62;
}

/// UNIX permission bits carried in external file attributes.
pub mod attributes {
    /// Any UNIX execute permission.
    pub const UNIX_EXECUTABLE: u16 = 0o111;
}
