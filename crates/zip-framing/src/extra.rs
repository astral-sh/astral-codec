use std::{collections::BTreeMap, str};

use crc32fast::hash as crc32;

use crate::{
    Error,
    constants::extra,
    invalid,
    record::{Common, SizeField, bytes_at},
};

/// Version of the Info-ZIP Unicode path and comment fields.
const UNICODE_VERSION: u8 = 1;

/// Which extra fields a reader accepts in local and central member headers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExtraFieldPolicy {
    /// Accept only ZIP64 values required by the member header's sentinel fields.
    #[default]
    Zip64Only,
    /// Accept all fields in [`ExtraHeaderId`], with their layout and agreement checks.
    AllowListed,
}

/// A supported ZIP member extra-field identifier. The discriminant is the wire value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
#[repr(u16)]
pub enum ExtraHeaderId {
    /// ZIP64 sizes, local offset, and disk number.
    Zip64 = 0x0001,
    /// PKWARE UNIX metadata.
    Unix = 0x000d,
    /// Info-ZIP extended timestamps.
    ExtendedTimestamp = 0x5455,
    /// Original Info-ZIP UNIX timestamps and optional ownership.
    InfoZipUnix = 0x5855,
    /// Info-ZIP Unicode comment.
    UnicodeComment = 0x6375,
    /// Info-ZIP Unicode path.
    UnicodePath = 0x7075,
    /// Info-ZIP 16-bit UID and GID.
    InfoZipOwnership16 = 0x7855,
    /// Info-ZIP variable-width UID and GID.
    InfoZipOwnership = 0x7875,
}

impl TryFrom<u16> for ExtraHeaderId {
    type Error = u16;

    fn try_from(identifier: u16) -> Result<Self, Self::Error> {
        [
            Self::Zip64,
            Self::Unix,
            Self::ExtendedTimestamp,
            Self::InfoZipUnix,
            Self::UnicodeComment,
            Self::UnicodePath,
            Self::InfoZipOwnership16,
            Self::InfoZipOwnership,
        ]
        .into_iter()
        .find(|&field| field as u16 == identifier)
        .ok_or(identifier)
    }
}

impl From<ExtraHeaderId> for u16 {
    fn from(value: ExtraHeaderId) -> Self {
        value as Self
    }
}

#[derive(Default)]
pub(crate) struct Extras<'a> {
    // ZIP64 sizes are reconciled separately and need no map allocation.
    zip64: Option<&'a [u8]>,
    fields: BTreeMap<ExtraHeaderId, &'a [u8]>,
}

#[derive(Clone, Copy)]
pub(crate) enum Header {
    Local,
    Central,
}

impl<'a> Extras<'a> {
    pub(crate) fn parse(
        mut bytes: &'a [u8],
        header: Header,
        position: u64,
        policy: ExtraFieldPolicy,
    ) -> Result<Self, Error> {
        let mut zip64 = None;
        let mut fields = BTreeMap::new();

        while !bytes.is_empty() {
            let Some((prefix, remaining)) = bytes.split_first_chunk::<{ extra::HEADER_SIZE }>()
            else {
                return Err(invalid(position, "truncated extra-field header"));
            };

            let [identifier_low, identifier_high, length_low, length_high] = *prefix;
            let length = usize::from(u16::from_le_bytes([length_low, length_high]));
            let Some((data, remaining)) = remaining.split_at_checked(length) else {
                return Err(invalid(position, "truncated extra-field data"));
            };

            let raw_id = u16::from_le_bytes([identifier_low, identifier_high]);
            let identifier = ExtraHeaderId::try_from(raw_id)
                .ok()
                .filter(|&field| {
                    field == ExtraHeaderId::Zip64 || policy == ExtraFieldPolicy::AllowListed
                })
                .ok_or(Error::UnsupportedExtraField {
                    position,
                    identifier: raw_id,
                })?;

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
            // Info-ZIP defines different layouts for the two member headers.
            let valid = match (identifier, header) {
                (ExtraHeaderId::ExtendedTimestamp, _) => {
                    let Some((&flags, times)) = data.split_first() else {
                        return Err(invalid(position, "missing Info-ZIP timestamp flags"));
                    };
                    let stored = match header {
                        Header::Local => flags,
                        Header::Central => flags & 1,
                    };
                    flags & !0b111 == 0 && times.len() == 4 * stored.count_ones() as usize
                }
                (ExtraHeaderId::InfoZipUnix, Header::Local) => matches!(data.len(), 8 | 12),
                (ExtraHeaderId::InfoZipUnix, Header::Central) => data.len() == 8,
                (ExtraHeaderId::InfoZipOwnership16, Header::Local) => data.len() == 4,
                (ExtraHeaderId::InfoZipOwnership16, Header::Central) => data.is_empty(),
                (ExtraHeaderId::InfoZipOwnership, _) => ownership_ids(data).is_some(),
                // ZIP64, UNIX and Unicode fields are checked against the member metadata.
                (
                    ExtraHeaderId::Zip64
                    | ExtraHeaderId::Unix
                    | ExtraHeaderId::UnicodePath
                    | ExtraHeaderId::UnicodeComment,
                    _,
                ) => true,
            };
            if !valid {
                return Err(invalid(position, "invalid Info-ZIP extra field layout"));
            }

            bytes = remaining;
        }

        let extras = Self { zip64, fields };
        if let Some(unix) = extras.fields.get(&ExtraHeaderId::Unix) {
            extras.check_unix_agreement(unix, position)?;
        }
        Ok(extras)
    }

    /// Whether any fields need comparison beyond the resolved ZIP64 sizes.
    pub(crate) fn needs_reconciliation(&self) -> bool {
        !self.fields.is_empty()
    }

    /// Compare the fixed PKWARE UNIX prefix (atime, mtime, UID, GID) with
    /// the Info-ZIP fields in this header.
    fn check_unix_agreement(&self, unix: &[u8], position: u64) -> Result<(), Error> {
        for (identifier, &data) in &self.fields {
            let agrees = match identifier {
                ExtraHeaderId::InfoZipUnix => unix.starts_with(data),
                ExtraHeaderId::InfoZipOwnership16 => unix[8..12].starts_with(data),
                ExtraHeaderId::InfoZipOwnership => ownership_ids(data).is_some_and(|(uid, gid)| {
                    significant_bytes(uid) == significant_bytes(&unix[8..10])
                        && significant_bytes(gid) == significant_bytes(&unix[10..12])
                }),
                ExtraHeaderId::ExtendedTimestamp => {
                    // UT stores mtime before atime. Only the local field stores atime,
                    // even when the central flags announce it.
                    let (times, _) = data[1..].as_chunks::<4>();
                    [(1, &unix[4..8]), (2, &unix[..4])]
                        .into_iter()
                        .filter(|(flag, _)| data[0] & flag != 0)
                        .zip(times)
                        .all(|((_, expected), time)| time == expected)
                }
                _ => true,
            };
            if !agrees {
                return Err(invalid(
                    position,
                    "conflicting UNIX metadata in extra fields",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn local_sizes(&self, common: Common, position: u64) -> Result<Sizes, Error> {
        if (common.uncompressed == SizeField::Zip64) != (common.compressed == SizeField::Zip64) {
            return Err(invalid(position, "local ZIP64 must contain both sizes"));
        }

        self.zip64_sizes(common, 0, position)
            .map(|(sizes, _)| sizes)
    }

    #[inline]
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

    #[inline]
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

    /// Checks Unicode metadata against an already validated filename.
    pub(crate) fn check_name(&self, name: &str, position: u64) -> Result<(), Error> {
        if let Some(field) = self.fields.get(&ExtraHeaderId::UnicodePath) {
            let unicode = unicode_field(field, name.as_bytes(), position)?;
            if unicode != name {
                return Err(invalid(
                    position,
                    "Unicode path extra field disagrees with filename",
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn comment(&self, bytes: &[u8], position: u64) -> Result<(), Error> {
        let comment =
            str::from_utf8(bytes).map_err(|_| invalid(position, "non-UTF-8 member comment"))?;

        if let Some(field) = self.fields.get(&ExtraHeaderId::UnicodeComment)
            && unicode_field(field, bytes, position)? != comment
        {
            return Err(invalid(
                position,
                "Unicode comment disagrees with member comment",
            ));
        }

        Ok(())
    }

    /// Reconciles extra fields and returns the UNIX file-type bytes, if present.
    pub(crate) fn resolve(
        self,
        central: Extras<'_>,
        position: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let has = |id| self.fields.contains_key(&id) || central.fields.contains_key(&id);
        let ownership = has(ExtraHeaderId::InfoZipOwnership);
        let ownership16 = has(ExtraHeaderId::InfoZipOwnership16);
        if (has(ExtraHeaderId::InfoZipUnix)
            && (has(ExtraHeaderId::ExtendedTimestamp) || ownership16 || ownership))
            || (ownership16 && ownership)
        {
            return Err(invalid(
                position,
                "mixed old and new Info-ZIP UNIX metadata",
            ));
        }

        // These central forms describe timestamps or ownership in the local header.
        for identifier in [
            ExtraHeaderId::ExtendedTimestamp,
            ExtraHeaderId::InfoZipOwnership16,
        ] {
            if central.fields.contains_key(&identifier) && !self.fields.contains_key(&identifier) {
                return Err(invalid(
                    position,
                    "central Info-ZIP field has no local copy",
                ));
            }
        }

        for (identifier, local) in &self.fields {
            let Some(other) = central.fields.get(identifier) else {
                // Only the central header has the original member comment.
                if *identifier == ExtraHeaderId::UnicodeComment {
                    return Err(invalid(
                        position,
                        "local Unicode comment has no central copy",
                    ));
                }
                continue;
            };

            // The validated Info-ZIP central forms contain only the shared
            // leading fields. The PKWARE UNIX field has one layout (APPNOTE 4.5.7).
            let equal = match *identifier {
                ExtraHeaderId::InfoZipUnix
                | ExtraHeaderId::ExtendedTimestamp
                | ExtraHeaderId::InfoZipOwnership16 => local.starts_with(other),
                _ => local == other,
            };
            if !equal {
                return Err(invalid(position, "local and central extra fields disagree"));
            }
        }

        let local_unix = self.fields.get(&ExtraHeaderId::Unix);
        let central_unix = central.fields.get(&ExtraHeaderId::Unix);
        // Each header was checked on its own. If only one carries PKWARE UNIX,
        // its values must also agree with the Info-ZIP fields in the other.
        match (local_unix, central_unix) {
            (Some(unix), None) => central.check_unix_agreement(unix, position)?,
            (None, Some(unix)) => self.check_unix_agreement(unix, position)?,
            _ => {}
        }
        Ok(local_unix
            .or(central_unix)
            .map(|unix| unix[extra::UNIX_PREFIX_SIZE..].to_vec()))
    }
}

/// Version 1 stores two length-prefixed integers: UID, then GID.
fn ownership_ids(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let [1, uid_size, rest @ ..] = data else {
        return None;
    };
    let (uid, rest) = rest.split_at_checked(usize::from(*uid_size))?;
    let (&gid_size, gid) = rest.split_first()?;
    (!uid.is_empty() && !gid.is_empty() && gid.len() == usize::from(gid_size)).then_some((uid, gid))
}

/// Ignore high zero bytes when comparing unsigned little-endian IDs of different widths.
fn significant_bytes(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = bytes {
        bytes = rest;
    }
    bytes
}

fn unicode_field<'a>(field: &'a [u8], original: &[u8], position: u64) -> Result<&'a str, Error> {
    let Some((&UNICODE_VERSION, field)) = field.split_first() else {
        return Err(invalid(position, "invalid Unicode extra field"));
    };
    let Some((expected_crc, value)) = field.split_first_chunk::<4>() else {
        return Err(invalid(position, "invalid Unicode extra field"));
    };

    if u32::from_le_bytes(*expected_crc) != crc32(original) {
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
