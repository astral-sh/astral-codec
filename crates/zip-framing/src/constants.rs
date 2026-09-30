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
    /// Fields shared by local and central headers, starting at the extraction version.
    pub const COMMON: usize = 22;
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

/// Extra-field identifiers and layouts (APPNOTE sections 4.5 and 4.6).
pub mod extra {
    /// ZIP64 sizes, local offset, and disk number.
    pub const ZIP64: u16 = 0x0001;
    /// Authenticity verification information.
    pub const AV_INFO: u16 = 0x0007;
    /// Reserved extended language encoding data.
    pub const EXTENDED_LANGUAGE_ENCODING: u16 = 0x0008;
    /// PKWARE UNIX metadata.
    pub const UNIX: u16 = 0x000d;
    /// Patch descriptor.
    pub const PATCH_DESCRIPTOR: u16 = 0x000f;
    /// PKCS#7 certificate store.
    pub const PKCS7_STORE: u16 = 0x0014;
    /// X.509 certificate and signature for a file.
    pub const X509_FILE: u16 = 0x0015;
    /// X.509 certificate for the central directory.
    pub const X509_DIRECTORY: u16 = 0x0016;
    /// Strong encryption header.
    pub const STRONG_ENCRYPTION: u16 = 0x0017;
    /// PKCS#7 encryption recipient certificates.
    pub const ENCRYPTION_RECIPIENTS: u16 = 0x0019;
    /// Extended timestamps.
    pub const EXTENDED_TIMESTAMP: u16 = 0x5455;
    /// Original Info-ZIP UNIX metadata.
    pub const INFO_ZIP_UNIX: u16 = 0x5855;
    /// Info-ZIP Unicode comment.
    pub const UNICODE_COMMENT: u16 = 0x6375;
    /// Info-ZIP Unicode path.
    pub const UNICODE_PATH: u16 = 0x7075;
    /// Info-ZIP UNIX UID/GID metadata (the "new" UNIX field).
    pub const INFO_ZIP_UNIX_NEW: u16 = 0x7855;
    /// WinZip AES encryption metadata.
    pub const AES: u16 = 0x9901;

    /// Extra-field header length in bytes (two-byte ID, two-byte size).
    pub const HEADER_SIZE: usize = 4;
    /// PKWARE UNIX timestamp and ownership prefix length in bytes.
    pub const UNIX_PREFIX_SIZE: usize = 12;
    /// ZIP64 local extra data length in bytes (both sizes).
    pub const ZIP64_LOCAL_SIZE: usize = 16;
    /// ZIP64 central extra data length in bytes when both sizes and the offset are present.
    pub const ZIP64_CENTRAL_SIZE: usize = 24;
    /// Version of the Info-ZIP Unicode path and comment fields.
    pub const UNICODE_VERSION: u8 = 1;
}

/// General-purpose header flag masks (APPNOTE section 4.4.4).
pub mod flags {
    /// Member encryption.
    pub const ENCRYPTED: u16 = 0x0001;
    /// Compression-level bits for DEFLATE members.
    pub const DEFLATE_OPTIONS: u16 = 0x0006;
    /// CRC and sizes follow the payload in a data descriptor.
    pub const DATA_DESCRIPTOR: u16 = 0x0008;
    /// Compressed patched data.
    pub const PATCHED_DATA: u16 = 0x0020;
    /// Strong encryption.
    pub const STRONG_ENCRYPTION: u16 = 0x0040;
    /// UTF-8 filename and comment encoding.
    pub const UTF8: u16 = 0x0800;
    /// Local header values are masked for central directory encryption.
    pub const MASKED_HEADER: u16 = 0x2000;
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

/// Host-system identifiers in the high byte of "version made by" (APPNOTE section 4.4.2).
pub mod host {
    /// MS-DOS and OS/2 FAT filesystems.
    pub const MS_DOS: u8 = 0;
    /// UNIX.
    pub const UNIX: u8 = 3;
    /// OS/2 HPFS.
    pub const OS2_HPFS: u8 = 6;
    /// Windows NTFS.
    pub const WINDOWS_NTFS: u8 = 10;
    /// VFAT.
    pub const VFAT: u8 = 14;
    /// OS X (Darwin).
    pub const OS_X: u8 = 19;
}

/// DOS attributes and UNIX mode bits carried in external file attributes.
pub mod attributes {
    /// DOS volume label.
    pub const DOS_VOLUME_LABEL: u32 = 0x08;
    /// DOS directory.
    pub const DOS_DIRECTORY: u32 = 0x10;
    /// Bit offset of the UNIX mode in external file attributes.
    pub const UNIX_MODE_SHIFT: u32 = 16;
    /// UNIX file-type mask, applied after shifting out the DOS attributes.
    pub const UNIX_TYPE_MASK: u16 = 0o170000;
    /// UNIX regular file.
    pub const UNIX_REGULAR: u16 = 0o100000;
    /// UNIX directory.
    pub const UNIX_DIRECTORY: u16 = 0o040000;
    /// UNIX symbolic link.
    pub const UNIX_SYMLINK: u16 = 0o120000;
    /// UNIX character device.
    pub const UNIX_CHARACTER_DEVICE: u16 = 0o020000;
    /// UNIX block device.
    pub const UNIX_BLOCK_DEVICE: u16 = 0o060000;
    /// UNIX named pipe.
    pub const UNIX_FIFO: u16 = 0o010000;
    /// Any UNIX execute permission.
    pub const UNIX_EXECUTABLE: u16 = 0o111;
}
