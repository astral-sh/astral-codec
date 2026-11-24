use std::{
    collections::{BTreeMap, BTreeSet},
    str,
};

use crc32fast::hash as crc32;

use crate::{
    Error, IndexPolicyViolation,
    constants::extra,
    invalid, policy_violation,
    record::{
        GeneralPurposeFlags, MemberHeader, MemberPayload, PayloadFields, SizeField, bytes_at,
    },
};

/// Version of the Info-ZIP Unicode path and comment fields.
const UNICODE_VERSION: u8 = 1;

/// Which extra fields a reader accepts in local and central member headers.
///
/// All policies accept required ZIP64 values. Redundant local sizes require
/// [a separate opt-in](crate::IndexPolicy::allow_redundant_zip64_sizes).
/// Known fields must pass the same layout and agreement checks under
/// every policy. Timestamps and Windows NT security descriptor sizes need
/// not agree between headers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExtraFieldPolicy {
    /// Accept only ZIP64 extra fields.
    #[default]
    Zip64Only,
    /// Accept only the optional fields in the set. An empty set is equivalent
    /// to [`Self::Zip64Only`].
    AllowListed(ExtraHeaderIdSet),
    /// Accept all fields in [`ExtraHeaderId`].
    AllowKnown,
    /// Accept known fields and skip unknown fields without interpreting or
    /// comparing their contents. Truncation and duplicate identifiers are errors.
    ///
    /// Other ZIP readers may interpret the skipped fields and report different
    /// metadata for the same member.
    Permissive,
}

/// A supported ZIP member extra-field identifier. The discriminant is the wire value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[non_exhaustive]
#[repr(u16)]
pub enum ExtraHeaderId {
    /// ZIP64 sizes, local offset, and disk number.
    Zip64 = 0x0001,
    /// NTFS timestamps (attribute tag `0x0001` only).
    Ntfs = 0x000a,
    /// PKWARE UNIX metadata.
    Unix = 0x000d,
    /// Windows NT security descriptor (version 0). The descriptor is ignored.
    NtfsSecurityDescriptor = 0x4453,
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
    /// Empty marker written by Java's `JarOutputStream`.
    JarMagic = 0xcafe,
}

impl TryFrom<u16> for ExtraHeaderId {
    type Error = u16;

    fn try_from(identifier: u16) -> Result<Self, Self::Error> {
        [
            Self::Zip64,
            Self::Ntfs,
            Self::Unix,
            Self::NtfsSecurityDescriptor,
            Self::ExtendedTimestamp,
            Self::InfoZipUnix,
            Self::UnicodeComment,
            Self::UnicodePath,
            Self::InfoZipOwnership16,
            Self::InfoZipOwnership,
            Self::JarMagic,
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

/// A set of known ZIP extra-field identifiers for [`ExtraFieldPolicy::AllowListed`].
///
/// ```
/// use zip_framing::{ExtraFieldPolicy, ExtraHeaderId};
///
/// let policy = ExtraFieldPolicy::AllowListed([ExtraHeaderId::ExtendedTimestamp].into());
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtraHeaderIdSet(u16);

impl ExtraHeaderIdSet {
    /// Returns whether the set contains the given identifier.
    pub fn contains(self, identifier: ExtraHeaderId) -> bool {
        self.0 & identifier.bit() != 0
    }
}

impl FromIterator<ExtraHeaderId> for ExtraHeaderIdSet {
    fn from_iter<T: IntoIterator<Item = ExtraHeaderId>>(iter: T) -> Self {
        Self(iter.into_iter().fold(0, |bits, id| bits | id.bit()))
    }
}

impl<const N: usize> From<[ExtraHeaderId; N]> for ExtraHeaderIdSet {
    fn from(identifiers: [ExtraHeaderId; N]) -> Self {
        identifiers.into_iter().collect()
    }
}

struct Extras<'a> {
    // ZIP64 sizes are reconciled separately and need no map allocation.
    zip64: Option<&'a [u8]>,
    fields: BTreeMap<ExtraHeaderId, &'a [u8]>,
    owner: Option<UnixOwner<'a>>,
}

/// Checked central extra fields retained for reconciliation with the local header.
#[derive(Debug)]
pub(crate) struct CentralExtras {
    /// ZIP64 alone needs no copy once its values have been resolved.
    bytes: Box<[u8]>,
    pub(crate) has_zip64: bool,
}

#[derive(Clone, Copy)]
enum Header {
    Local,
    Central,
}

impl CentralExtras {
    pub(crate) fn parse(
        bytes: &[u8],
        header: MemberHeader,
        location: (u32, u16),
        path: &str,
        comment: &[u8],
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<(Self, MemberPayload, u64), Error> {
        let extras = Extras::parse(bytes, Header::Central, policy, position)?;
        let (offset, disk) = location;
        let (fields, local_offset) = extras.central_payload(header, offset, disk, position)?;
        let payload = fields.validate(header.common.method, position)?;
        extras.validate(path, Some(comment), policy, position)?;
        let central = Self {
            bytes: if extras.fields.is_empty() {
                Box::default()
            } else {
                bytes.into()
            },
            has_zip64: extras.zip64.is_some(),
        };
        Ok((central, payload, local_offset))
    }

    /// Checks local extras under the same policy and reconciles them with this header.
    pub(crate) fn resolve_local(
        &self,
        bytes: &[u8],
        header: MemberHeader,
        path: &str,
        policy: ExtraFieldPolicy,
        allow_redundant_zip64_sizes: bool,
        position: u64,
    ) -> Result<(PayloadFields, bool, Option<Vec<u8>>), Error> {
        let extras = Extras::parse(bytes, Header::Local, policy, position)?;
        let payload = extras.local_payload(header, allow_redundant_zip64_sizes, position)?;
        extras.validate(path, None, policy, position)?;
        // A descriptor uses ZIP64 widths if either header has ZIP64 extra values.
        let zip64 = extras.zip64.is_some() || self.has_zip64;
        let unix_data = extras.resolve(self, policy, position)?;
        Ok((payload, zip64, unix_data))
    }
}

impl<'a> Extras<'a> {
    fn validate(
        &self,
        path: &str,
        comment: Option<&[u8]>,
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<(), Error> {
        if self.fields.is_empty() {
            return Ok(());
        }
        self.check_name(path, position)?;
        if let Some(comment) = comment {
            self.check_comment(comment, position)?;
        }
        let allowed = match policy {
            ExtraFieldPolicy::Zip64Only => ExtraHeaderIdSet::default(),
            ExtraFieldPolicy::AllowListed(allowed) => allowed,
            ExtraFieldPolicy::AllowKnown | ExtraFieldPolicy::Permissive => return Ok(()),
        };
        if let Some(&identifier) = self.fields.keys().find(|&&id| !allowed.contains(id)) {
            return Err(policy_violation(
                position,
                IndexPolicyViolation::ExtraField { identifier },
            ));
        }
        Ok(())
    }

    fn parse(
        mut bytes: &'a [u8],
        header: Header,
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<Self, Error> {
        let mut extras = Self {
            zip64: None,
            fields: BTreeMap::new(),
            owner: None,
        };

        let mut unknown = BTreeSet::new();
        let duplicate = || invalid(position, "duplicate extra-field identifier");
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
            match ExtraHeaderId::try_from(raw_id) {
                Ok(ExtraHeaderId::Zip64) => {
                    if extras.zip64.replace(data).is_some() {
                        return Err(duplicate());
                    }
                }
                Ok(identifier) => {
                    if extras.fields.insert(identifier, data).is_some() {
                        return Err(duplicate());
                    }
                    let owner = identifier.validate_layout(header, data, position)?;
                    extras.owner = merge_owners(extras.owner, owner, position)?;
                }
                Err(identifier) if policy == ExtraFieldPolicy::Permissive => {
                    if !unknown.insert(identifier) {
                        return Err(duplicate());
                    }
                }
                Err(identifier) => {
                    return Err(Error::UnsupportedExtraField {
                        position,
                        identifier,
                    });
                }
            }
            bytes = remaining;
        }

        Ok(extras)
    }

    fn local_payload(
        &self,
        header: MemberHeader,
        allow_redundant_zip64_sizes: bool,
        position: u64,
    ) -> Result<PayloadFields, Error> {
        let required = header.payload.uncompressed == SizeField::Zip64;
        if required != (header.payload.compressed == SizeField::Zip64) {
            return Err(invalid(position, "local ZIP64 must contain both sizes"));
        }

        // Older CPython repeated the 32-bit sizes without declaring version 4.5.
        // Set aside that pair and check it against the resolved sizes below.
        let mut field = self.zip64;
        let redundant = field.take_if(|data| {
            !required
                && data.len() == extra::ZIP64_LOCAL_SIZE
                && !header
                    .common
                    .flags
                    .contains(GeneralPurposeFlags::DATA_DESCRIPTOR)
        });
        let (payload, _) = Self::resolve_payload(field, header, 0, position)?;
        if let Some(data) = redundant {
            if data[..8] != payload.uncompressed.to_le_bytes()
                || data[8..] != payload.compressed.to_le_bytes()
            {
                return Err(invalid(position, "redundant local ZIP64 sizes disagree"));
            }
            if !allow_redundant_zip64_sizes {
                return Err(policy_violation(
                    position,
                    IndexPolicyViolation::RedundantZip64Sizes,
                ));
            }
        }
        Ok(payload)
    }

    #[inline]
    fn central_payload(
        &self,
        header: MemberHeader,
        offset: u32,
        disk: u16,
        position: u64,
    ) -> Result<(PayloadFields, u64), Error> {
        let (payload, bytes) = Self::resolve_payload(
            self.zip64,
            header,
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

        Ok((payload, offset))
    }

    #[inline]
    fn resolve_payload(
        field: Option<&[u8]>,
        header: MemberHeader,
        location_size: usize,
        position: u64,
    ) -> Result<(PayloadFields, &[u8]), Error> {
        let expected = usize::from(header.payload.uncompressed == SizeField::Zip64) * 8
            + usize::from(header.payload.compressed == SizeField::Zip64) * 8
            + location_size;
        if field.map(<[u8]>::len) != (expected != 0).then_some(expected) {
            return Err(invalid(position, "missing or superfluous ZIP64 values"));
        }

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

        let uncompressed = take_size(header.payload.uncompressed)?;
        let compressed = take_size(header.payload.compressed)?;
        Ok((
            PayloadFields {
                crc: header.payload.crc,
                uncompressed,
                compressed,
            },
            bytes,
        ))
    }

    /// Checks Unicode metadata against an already validated filename.
    fn check_name(&self, name: &str, position: u64) -> Result<(), Error> {
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

    fn check_comment(&self, bytes: &[u8], position: u64) -> Result<(), Error> {
        if let Some(field) = self.fields.get(&ExtraHeaderId::UnicodeComment)
            && unicode_field(field, bytes, position)?.as_bytes() != bytes
        {
            return Err(invalid(
                position,
                "Unicode comment disagrees with member comment",
            ));
        }

        Ok(())
    }

    /// Reconciles extra fields and returns the UNIX file-type bytes, if present.
    fn resolve(
        self,
        central: &'a CentralExtras,
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.fields.is_empty() && central.bytes.is_empty() {
            return Ok(None);
        }
        let central = Self::parse(&central.bytes, Header::Central, policy, position)?;
        let has = |id| self.fields.contains_key(&id) || central.fields.contains_key(&id);
        let ownership = has(ExtraHeaderId::InfoZipOwnership);
        let ownership16 = has(ExtraHeaderId::InfoZipOwnership16);
        if (has(ExtraHeaderId::InfoZipUnix) && (ownership16 || ownership))
            || (ownership16 && ownership)
        {
            return Err(invalid(
                position,
                "mixed old and new Info-ZIP UNIX metadata",
            ));
        }

        // The empty central marker refers to ownership stored in the local header.
        if ownership16 && !self.fields.contains_key(&ExtraHeaderId::InfoZipOwnership16) {
            return Err(invalid(
                position,
                "central Info-ZIP field has no local copy",
            ));
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

            let equal = match *identifier {
                // These central forms contain only timestamps, a security
                // descriptor size, or an empty ownership marker.
                ExtraHeaderId::Ntfs
                | ExtraHeaderId::NtfsSecurityDescriptor
                | ExtraHeaderId::ExtendedTimestamp
                | ExtraHeaderId::InfoZipUnix
                | ExtraHeaderId::InfoZipOwnership16 => continue,
                // Skip atime and mtime, preserving ownership and file-type data.
                ExtraHeaderId::Unix => local[8..] == other[8..],
                _ => local == other,
            };
            if !equal {
                return Err(invalid(position, "local and central extra fields disagree"));
            }
        }

        merge_owners(self.owner, central.owner, position)?;
        Ok(self
            .fields
            .get(&ExtraHeaderId::Unix)
            .or_else(|| central.fields.get(&ExtraHeaderId::Unix))
            .map(|unix| unix[extra::UNIX_PREFIX_SIZE..].to_vec()))
    }
}

/// UID and GID, with high zero bytes removed for comparison across formats.
type UnixOwner<'a> = (&'a [u8], &'a [u8]);

impl ExtraHeaderId {
    /// A dense bit assignment independent of the ZIP wire values.
    fn bit(self) -> u16 {
        match self {
            Self::Zip64 => 1 << 0,
            Self::Unix => 1 << 1,
            Self::ExtendedTimestamp => 1 << 2,
            Self::InfoZipUnix => 1 << 3,
            Self::UnicodeComment => 1 << 4,
            Self::UnicodePath => 1 << 5,
            Self::InfoZipOwnership16 => 1 << 6,
            Self::InfoZipOwnership => 1 << 7,
            Self::JarMagic => 1 << 8,
            Self::Ntfs => 1 << 9,
            Self::NtfsSecurityDescriptor => 1 << 10,
        }
    }

    /// Checks the field layout and returns any UNIX ownership for reconciliation.
    fn validate_layout(
        self,
        header: Header,
        data: &[u8],
        position: u64,
    ) -> Result<Option<UnixOwner<'_>>, Error> {
        let invalid_layout = || invalid(position, "invalid Info-ZIP extra field layout");
        let owner = match (self, header, data.len()) {
            // Four reserved bytes precede tag 1, size 24, and three FILETIMEs (APPNOTE 4.5.5).
            (Self::Ntfs, _, 32) if data[4..8] == [1, 0, 24, 0] => None,
            (Self::Ntfs, _, _) => return Err(invalid(position, "invalid NTFS extra field layout")),
            // Info-ZIP's SD field stores the uncompressed size in both headers.
            // Only the local form adds a version, method, CRC32, and descriptor.
            (Self::NtfsSecurityDescriptor, Header::Central, 4) => None,
            (Self::NtfsSecurityDescriptor, Header::Local, 11..) if data[4] == 0 => None,
            (Self::NtfsSecurityDescriptor, _, _) => {
                return Err(invalid(
                    position,
                    "invalid NT security descriptor extra field layout",
                ));
            }
            (Self::Unix, _, 0..extra::UNIX_PREFIX_SIZE) => {
                return Err(invalid(position, "truncated UNIX extra field"));
            }
            (Self::InfoZipUnix, _, 8) => None,
            (Self::Unix, _, _) | (Self::InfoZipUnix, Header::Local, 12) => {
                Some(data[8..12].split_at(2))
            }
            (Self::ExtendedTimestamp, _, _) => {
                let Some((&flags, times)) = data.split_first() else {
                    return Err(invalid(position, "missing Info-ZIP timestamp flags"));
                };
                let stored = match header {
                    Header::Local => flags,
                    Header::Central => flags & 1,
                };
                if flags & !0b111 != 0 || times.len() != 4 * stored.count_ones() as usize {
                    return Err(invalid_layout());
                }
                None
            }
            (Self::InfoZipOwnership16, Header::Local, 4) => Some(data.split_at(2)),
            (Self::InfoZipOwnership16, Header::Central, 0) => None,
            (Self::InfoZipOwnership, _, _) => Some(ownership_ids(data).ok_or_else(invalid_layout)?),
            (Self::JarMagic, _, 1..) => return Err(invalid(position, "JAR marker must be empty")),
            (Self::Zip64 | Self::UnicodePath | Self::UnicodeComment | Self::JarMagic, _, _) => None,
            (Self::InfoZipUnix | Self::InfoZipOwnership16, _, _) => {
                return Err(invalid_layout());
            }
        };
        Ok(owner.map(|(uid, gid)| (significant_bytes(uid), significant_bytes(gid))))
    }
}

fn merge_owners<'a>(
    left: Option<UnixOwner<'a>>,
    right: Option<UnixOwner<'a>>,
    position: u64,
) -> Result<Option<UnixOwner<'a>>, Error> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => Err(invalid(
            position,
            "conflicting UNIX metadata in extra fields",
        )),
        (left, right) => Ok(left.or(right)),
    }
}

/// Version 1 stores two length-prefixed integers: UID, then GID.
fn ownership_ids(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut data = data.strip_prefix(&[1])?;
    let mut next_id = || {
        let length = usize::from(*data.split_off_first()?);
        data.split_off(..length).filter(|id| !id.is_empty())
    };
    let owner = (next_id()?, next_id()?);
    data.is_empty().then_some(owner)
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
