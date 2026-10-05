use std::{collections::BTreeMap, str};

use flate2::Crc;

use crate::{
    EntryKind, Error,
    constants::extra,
    invalid,
    record::{Common, GeneralPurposeFlags, SizeField, array_at, bytes_at, parse_name},
};

/// Version of the Info-ZIP Unicode path and comment fields.
const UNICODE_VERSION: u8 = 1;

/// An extra-field header identifier (APPNOTE sections 4.5 and 4.6).
///
/// Named variants identify headers recognized by this crate, including features
/// it rejects. Other identifiers are preserved as [`Self::Unknown`]. Convert to
/// or from [`u16`] to access the wire representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
pub enum ExtraHeaderId {
    /// ZIP64 sizes, local offset, and disk number.
    Zip64,
    /// Authenticity verification information.
    AvInfo,
    /// Reserved extended language encoding data.
    ExtendedLanguageEncoding,
    /// PKWARE UNIX metadata.
    Unix,
    /// Patch descriptor.
    PatchDescriptor,
    /// PKCS#7 certificate store.
    Pkcs7Store,
    /// X.509 certificate and signature for a file.
    X509File,
    /// X.509 certificate for the central directory.
    X509Directory,
    /// Strong encryption header.
    StrongEncryption,
    /// PKCS#7 encryption recipient certificates.
    EncryptionRecipients,
    /// Extended timestamps.
    ExtendedTimestamp,
    /// Original Info-ZIP UNIX metadata.
    InfoZipUnix,
    /// Info-ZIP Unicode comment.
    UnicodeComment,
    /// Info-ZIP Unicode path.
    UnicodePath,
    /// Info-ZIP UNIX UID/GID metadata (the "new" UNIX field).
    InfoZipUnixNew,
    /// WinZip AES encryption metadata.
    Aes,
    /// An unrecognized header identifier.
    Unknown(u16),
}

impl From<u16> for ExtraHeaderId {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => Self::Zip64,
            0x0007 => Self::AvInfo,
            0x0008 => Self::ExtendedLanguageEncoding,
            0x000d => Self::Unix,
            0x000f => Self::PatchDescriptor,
            0x0014 => Self::Pkcs7Store,
            0x0015 => Self::X509File,
            0x0016 => Self::X509Directory,
            0x0017 => Self::StrongEncryption,
            0x0019 => Self::EncryptionRecipients,
            0x5455 => Self::ExtendedTimestamp,
            0x5855 => Self::InfoZipUnix,
            0x6375 => Self::UnicodeComment,
            0x7075 => Self::UnicodePath,
            0x7855 => Self::InfoZipUnixNew,
            0x9901 => Self::Aes,
            _ => Self::Unknown(value),
        }
    }
}

impl From<ExtraHeaderId> for u16 {
    fn from(value: ExtraHeaderId) -> Self {
        match value {
            ExtraHeaderId::Zip64 => 0x0001,
            ExtraHeaderId::AvInfo => 0x0007,
            ExtraHeaderId::ExtendedLanguageEncoding => 0x0008,
            ExtraHeaderId::Unix => 0x000d,
            ExtraHeaderId::PatchDescriptor => 0x000f,
            ExtraHeaderId::Pkcs7Store => 0x0014,
            ExtraHeaderId::X509File => 0x0015,
            ExtraHeaderId::X509Directory => 0x0016,
            ExtraHeaderId::StrongEncryption => 0x0017,
            ExtraHeaderId::EncryptionRecipients => 0x0019,
            ExtraHeaderId::ExtendedTimestamp => 0x5455,
            ExtraHeaderId::InfoZipUnix => 0x5855,
            ExtraHeaderId::UnicodeComment => 0x6375,
            ExtraHeaderId::UnicodePath => 0x7075,
            ExtraHeaderId::InfoZipUnixNew => 0x7855,
            ExtraHeaderId::Aes => 0x9901,
            ExtraHeaderId::Unknown(value) => value,
        }
    }
}

pub(crate) struct Extras<'a> {
    // ZIP64 sizes are reconciled separately and need no map allocation.
    zip64: Option<&'a [u8]>,
    fields: BTreeMap<ExtraHeaderId, &'a [u8]>,
}

/// File-type data from the PKWARE UNIX extra field (APPNOTE 4.5.7).
///
/// The timestamp and ownership prefix is excluded. The member's reconciled
/// [`EntryKind`] determines how the remaining bytes are interpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnixData {
    /// The field contains only the timestamp and ownership prefix.
    Empty,
    /// A nonempty UTF-8 link target without NUL bytes.
    LinkTarget(String),
    /// Device numbers decoded from two little-endian 32-bit integers.
    Device {
        /// The device's major number.
        major: u32,
        /// The device's minor number.
        minor: u32,
    },
    /// Nonempty data for a socket, volume label, or unrecognized file type.
    Opaque(Vec<u8>),
}

impl UnixData {
    pub(crate) fn parse(kind: EntryKind, data: Vec<u8>, position: u64) -> Result<Self, Error> {
        if data.is_empty() {
            return Ok(Self::Empty);
        }

        match kind {
            EntryKind::HardLink | EntryKind::SymbolicLink => {
                let target = String::from_utf8(data)
                    .map_err(|_| invalid(position, "non-UTF-8 UNIX link target"))?;
                if target.contains('\0') {
                    return Err(invalid(position, "NUL in UNIX link target"));
                }
                Ok(Self::LinkTarget(target))
            }
            EntryKind::CharacterDevice | EntryKind::BlockDevice => {
                let bytes: [u8; 8] = data
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid(position, "invalid UNIX device numbers"))?;
                Ok(Self::Device {
                    major: u32::from_le_bytes(array_at::<0, 4, _>(&bytes)),
                    minor: u32::from_le_bytes(array_at::<4, 4, _>(&bytes)),
                })
            }
            EntryKind::File | EntryKind::Directory | EntryKind::Fifo => {
                Err(invalid(position, "unexpected UNIX file-type data"))
            }
            EntryKind::Socket | EntryKind::VolumeLabel | EntryKind::Unknown(_) => {
                Ok(Self::Opaque(data))
            }
        }
    }
}

impl<'a> Extras<'a> {
    pub(crate) fn parse(mut bytes: &'a [u8], position: u64) -> Result<Self, Error> {
        let mut zip64 = None;
        let mut fields = BTreeMap::new();

        while !bytes.is_empty() {
            let Some((header, remaining)) = bytes.split_first_chunk::<{ extra::HEADER_SIZE }>()
            else {
                return Err(invalid(position, "truncated extra-field header"));
            };

            let [identifier_low, identifier_high, length_low, length_high] = *header;
            let identifier =
                ExtraHeaderId::from(u16::from_le_bytes([identifier_low, identifier_high]));
            let length = usize::from(u16::from_le_bytes([length_low, length_high]));
            let Some((data, remaining)) = remaining.split_at_checked(length) else {
                return Err(invalid(position, "truncated extra-field data"));
            };

            let unsupported = match identifier {
                ExtraHeaderId::AvInfo => Some("authenticity verification"),
                ExtraHeaderId::PatchDescriptor => Some("patch descriptor"),
                ExtraHeaderId::Pkcs7Store
                | ExtraHeaderId::X509File
                | ExtraHeaderId::X509Directory => Some("digital signature"),
                ExtraHeaderId::StrongEncryption
                | ExtraHeaderId::EncryptionRecipients
                | ExtraHeaderId::Aes => Some("encryption extra field"),
                ExtraHeaderId::ExtendedLanguageEncoding => Some("alternate name encoding"),
                _ => None,
            };
            if let Some(feature) = unsupported {
                return Err(Error::Unsupported { position, feature });
            }

            let previous = if identifier == ExtraHeaderId::Zip64 {
                zip64.replace(data)
            } else {
                fields.insert(identifier, data)
            };
            if previous.is_some() {
                return Err(invalid(position, "duplicate extra-field identifier"));
            }

            if identifier == ExtraHeaderId::Unix && data.len() < extra::UNIX_PREFIX_SIZE {
                return Err(invalid(position, "truncated UNIX extra field"));
            }

            bytes = remaining;
        }

        Ok(Self { zip64, fields })
    }

    /// Whether any fields need comparison beyond the resolved ZIP64 sizes.
    pub(crate) fn needs_reconciliation(&self) -> bool {
        !self.fields.is_empty()
    }

    fn unix_data(&self) -> Option<&[u8]> {
        self.fields
            .get(&ExtraHeaderId::Unix)
            .map(|data| &data[extra::UNIX_PREFIX_SIZE..])
    }

    pub(crate) fn local_sizes(&self, common: Common, position: u64) -> Result<Sizes, Error> {
        if (common.uncompressed == SizeField::Zip64) != (common.compressed == SizeField::Zip64) {
            return Err(invalid(position, "local ZIP64 must contain both sizes"));
        }

        self.zip64_sizes(common, 0, position)
            .map(|(sizes, _)| sizes)
    }

    pub(crate) fn central_sizes(
        &self,
        common: Common,
        offset: u32,
        disk: u16,
        position: u64,
    ) -> Result<(Sizes, u64), Error> {
        let (sizes, bytes) = self.zip64_sizes(
            common,
            usize::from(offset == u32::MAX) * 8 + usize::from(disk == u16::MAX) * 4,
            position,
        )?;
        let (offset, bytes) = if offset == u32::MAX {
            let (offset, bytes) = bytes
                .split_first_chunk::<8>()
                .ok_or_else(|| invalid(position, "missing or superfluous ZIP64 values"))?;
            (u64::from_le_bytes(*offset), bytes)
        } else {
            (u64::from(offset), bytes)
        };
        let disk = if disk == u16::MAX {
            u32::from_le_bytes(bytes_at(bytes, 0, position)?)
        } else {
            u32::from(disk)
        };
        if disk != 0 {
            return Err(Error::Unsupported {
                position,
                feature: "multiple volumes",
            });
        }

        Ok((sizes, offset))
    }

    fn zip64_sizes(
        &self,
        common: Common,
        location_size: usize,
        position: u64,
    ) -> Result<(Sizes, &[u8]), Error> {
        let expected = usize::from(common.uncompressed == SizeField::Zip64) * 8
            + usize::from(common.compressed == SizeField::Zip64) * 8
            + location_size;
        let field = self.zip64;
        if field.map(<[u8]>::len) != (expected != 0).then_some(expected) {
            return Err(invalid(position, "missing or superfluous ZIP64 values"));
        }
        common.check_zip64(field.is_some(), position)?;

        let mut bytes = field.unwrap_or_default();
        let mut take_size = |size: SizeField| -> Result<u64, Error> {
            match size {
                SizeField::Value(size) => Ok(u64::from(size)),
                SizeField::Zip64 => {
                    let (value, remaining) = bytes
                        .split_first_chunk::<8>()
                        .ok_or_else(|| invalid(position, "missing or superfluous ZIP64 values"))?;
                    bytes = remaining;
                    Ok(u64::from_le_bytes(*value))
                }
            }
        };

        let uncompressed = take_size(common.uncompressed)?;
        let compressed = take_size(common.compressed)?;
        Ok((
            Sizes {
                uncompressed,
                compressed,
                zip64: field.is_some(),
            },
            bytes,
        ))
    }

    pub(crate) fn name<'name>(
        &self,
        bytes: &'name [u8],
        flags: GeneralPurposeFlags,
        position: u64,
    ) -> Result<&'name str, Error> {
        let name = parse_name(bytes, flags, position)?;

        if let Some(field) = self.fields.get(&ExtraHeaderId::UnicodePath) {
            let unicode = unicode_field(field, bytes, position)?;
            if unicode != name {
                return Err(invalid(
                    position,
                    "Unicode path extra field disagrees with filename",
                ));
            }
        }

        Ok(name)
    }

    pub(crate) fn comment(&self, bytes: &[u8], position: u64) -> Result<(), Error> {
        str::from_utf8(bytes).map_err(|_| invalid(position, "non-UTF-8 member comment"))?;

        if let Some(field) = self.fields.get(&ExtraHeaderId::UnicodeComment) {
            unicode_field(field, bytes, position)?;
        }

        Ok(())
    }

    /// Reconciles extra fields and returns the UNIX file-type bytes, if present.
    pub(crate) fn resolve(
        self,
        central: Extras<'_>,
        position: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        for (identifier, local) in &self.fields {
            let Some(other) = central.fields.get(identifier) else {
                continue;
            };

            // APPNOTE and Info-ZIP define shorter central forms for these
            // fields. ZIP64 values are resolved and compared separately.
            let equal = match *identifier {
                ExtraHeaderId::Unix | ExtraHeaderId::InfoZipUnix => {
                    local.get(..other.len()) == Some(*other)
                }
                ExtraHeaderId::ExtendedTimestamp => {
                    local.first() == other.first() && local.get(..other.len()) == Some(*other)
                }
                ExtraHeaderId::InfoZipUnixNew => other.is_empty() || local == other,
                _ => local == other,
            };
            if !equal {
                return Err(invalid(position, "local and central extra fields disagree"));
            }
        }

        Ok(self
            .unix_data()
            .or_else(|| central.unix_data())
            .map(<[u8]>::to_vec))
    }
}

fn unicode_field<'a>(field: &'a [u8], original: &[u8], position: u64) -> Result<&'a str, Error> {
    let Some((&UNICODE_VERSION, field)) = field.split_first() else {
        return Err(invalid(position, "invalid Unicode extra field"));
    };
    let Some((expected_crc, value)) = field.split_first_chunk::<4>() else {
        return Err(invalid(position, "invalid Unicode extra field"));
    };

    let mut crc = Crc::new();
    crc.update(original);
    if u32::from_le_bytes(*expected_crc) != crc.sum() {
        return Err(invalid(position, "Unicode extra field CRC mismatch"));
    }

    let value =
        str::from_utf8(value).map_err(|_| invalid(position, "non-UTF-8 Unicode extra field"))?;
    if value.starts_with('\u{feff}') {
        return Err(invalid(position, "Unicode extra field contains a BOM"));
    }

    Ok(value)
}

pub(crate) struct Sizes {
    pub(crate) uncompressed: u64,
    pub(crate) compressed: u64,
    pub(crate) zip64: bool,
}
