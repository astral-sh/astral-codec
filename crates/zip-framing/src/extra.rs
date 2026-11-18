use std::{collections::BTreeMap, str};

use crc32fast::hash as crc32;

use crate::{
    Error, IndexPolicyViolation,
    constants::extra,
    invalid, policy_violation,
    record::{MemberHeader, MemberPayload, PayloadFields, SizeField, bytes_at},
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

struct ParsedExtras<'a> {
    // ZIP64 sizes are reconciled separately and need no map allocation.
    zip64: Option<&'a [u8]>,
    fields: BTreeMap<ExtraHeaderId, &'a [u8]>,
    unix: UnixMetadata<'a>,
}

/// Checked central extra fields retained for reconciliation with the local header.
/// An empty slice represents a header with no fields apart from ZIP64.
#[derive(Debug)]
pub(crate) struct RetainedCentralExtras(Box<[u8]>);

/// The checked, resolved extra fields of a central header.
pub(crate) struct CentralExtras<'a> {
    pub(crate) payload: MemberPayload,
    pub(crate) local_offset: u64,
    pub(crate) has_zip64: bool,
    retained: &'a [u8],
}

impl<'a> CentralExtras<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        header: MemberHeader,
        location: (u32, u16),
        path: &str,
        comment: &[u8],
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<Self, Error> {
        let extras = ParsedExtras::parse(bytes, Header::Central, position)?;
        let (offset, disk) = location;
        let (fields, local_offset) = extras.central_payload(header, offset, disk, position)?;
        let payload = fields.validate(header.common.method, position)?;
        extras.validate(path, Some(comment), policy, position)?;
        Ok(Self {
            payload,
            local_offset,
            has_zip64: extras.zip64.is_some(),
            retained: if extras.fields.is_empty() { &[] } else { bytes },
        })
    }

    pub(crate) fn retain(self) -> RetainedCentralExtras {
        RetainedCentralExtras(self.retained.into())
    }
}

/// The checked, resolved extra fields of a local header.
pub(crate) struct LocalExtras<'a> {
    pub(crate) payload: PayloadFields,
    extras: ParsedExtras<'a>,
}

impl<'a> LocalExtras<'a> {
    pub(crate) fn parse(
        bytes: &'a [u8],
        header: MemberHeader,
        path: &str,
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<Self, Error> {
        let extras = ParsedExtras::parse(bytes, Header::Local, position)?;
        let payload = extras.local_payload(header, position)?;
        extras.validate(path, None, policy, position)?;
        Ok(Self { payload, extras })
    }

    pub(crate) fn has_zip64(&self) -> bool {
        self.extras.zip64.is_some()
    }

    /// Reconciles local and central extra fields and returns the UNIX file-type bytes.
    pub(crate) fn resolve(
        self,
        central: &'a RetainedCentralExtras,
        position: u64,
    ) -> Result<Option<Vec<u8>>, Error> {
        let central = ParsedExtras::parse(&central.0, Header::Central, position)?;
        self.extras.resolve(central, position)
    }
}

#[derive(Clone, Copy)]
enum Header {
    Local,
    Central,
}

impl<'a> ParsedExtras<'a> {
    fn validate(
        &self,
        path: &str,
        comment: Option<&[u8]>,
        policy: ExtraFieldPolicy,
        position: u64,
    ) -> Result<(), Error> {
        let Some(&identifier) = self.fields.keys().next() else {
            return Ok(());
        };
        self.check_name(path, position)?;
        if let Some(comment) = comment {
            self.check_comment(comment, position)?;
        }
        if policy == ExtraFieldPolicy::Zip64Only {
            return Err(policy_violation(
                position,
                IndexPolicyViolation::ExtraField { identifier },
            ));
        }
        Ok(())
    }

    fn parse(mut bytes: &'a [u8], header: Header, position: u64) -> Result<Self, Error> {
        let mut extras = Self {
            zip64: None,
            fields: BTreeMap::new(),
            unix: UnixMetadata::default(),
        };

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
            let identifier = ExtraHeaderId::try_from(raw_id).map_err(|identifier| {
                Error::UnsupportedExtraField {
                    position,
                    identifier,
                }
            })?;

            let previous = if identifier == ExtraHeaderId::Zip64 {
                extras.zip64.replace(data)
            } else {
                extras.fields.insert(identifier, data)
            };
            if previous.is_some() {
                return Err(invalid(position, "duplicate extra-field identifier"));
            }

            if identifier != ExtraHeaderId::Zip64 {
                let field = identifier.unix_metadata(header, data, position)?;
                extras.unix = extras.unix.merge(field, position)?;
            }
            bytes = remaining;
        }

        Ok(extras)
    }

    fn local_payload(&self, header: MemberHeader, position: u64) -> Result<PayloadFields, Error> {
        if (header.payload.uncompressed == SizeField::Zip64)
            != (header.payload.compressed == SizeField::Zip64)
        {
            return Err(invalid(position, "local ZIP64 must contain both sizes"));
        }

        self.resolve_payload(header, 0, position)
            .map(|(payload, _)| payload)
    }

    #[inline]
    fn central_payload(
        &self,
        header: MemberHeader,
        offset: u32,
        disk: u16,
        position: u64,
    ) -> Result<(PayloadFields, u64), Error> {
        let (payload, bytes) = self.resolve_payload(
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
        &self,
        header: MemberHeader,
        location_size: usize,
        position: u64,
    ) -> Result<(PayloadFields, &[u8]), Error> {
        let expected = usize::from(header.payload.uncompressed == SizeField::Zip64) * 8
            + usize::from(header.payload.compressed == SizeField::Zip64) * 8
            + location_size;
        let field = self.zip64;
        if field.map(<[u8]>::len) != (expected != 0).then_some(expected) {
            return Err(invalid(position, "missing or superfluous ZIP64 values"));
        }
        header.check_zip64(field.is_some(), position)?;

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
    fn resolve(self, central: Self, position: u64) -> Result<Option<Vec<u8>>, Error> {
        if self.fields.is_empty() && central.fields.is_empty() {
            return Ok(None);
        }
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

        self.unix.merge(central.unix, position)?;
        Ok(self
            .fields
            .get(&ExtraHeaderId::Unix)
            .or_else(|| central.fields.get(&ExtraHeaderId::Unix))
            .map(|unix| unix[extra::UNIX_PREFIX_SIZE..].to_vec()))
    }
}

/// The values shared by PKWARE and Info-ZIP, independent of their wire layouts.
#[derive(Default)]
struct UnixMetadata<'a> {
    atime: Option<&'a [u8; 4]>,
    mtime: Option<&'a [u8; 4]>,
    owner: Option<(&'a [u8], &'a [u8])>,
}

impl ExtraHeaderId {
    fn unix_metadata(
        self,
        header: Header,
        data: &[u8],
        position: u64,
    ) -> Result<UnixMetadata<'_>, Error> {
        let invalid_layout = || invalid(position, "invalid Info-ZIP extra field layout");
        let mut fields = UnixMetadata::default();
        let owner = match (self, header, data.len()) {
            (Self::Unix, _, 0..extra::UNIX_PREFIX_SIZE) => {
                return Err(invalid(position, "truncated UNIX extra field"));
            }
            (Self::Unix, _, _)
            | (Self::InfoZipUnix, _, 8)
            | (Self::InfoZipUnix, Header::Local, 12) => {
                fields.atime = data.first_chunk();
                fields.mtime = data[4..].first_chunk();
                data.get(8..12).map(|ids| ids.split_at(2))
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
                let mut times = times.as_chunks::<4>().0.iter();
                if stored & 1 != 0 {
                    fields.mtime = times.next();
                }
                if stored & 2 != 0 {
                    fields.atime = times.next();
                }
                None
            }
            (Self::InfoZipOwnership16, Header::Local, 4) => Some(data.split_at(2)),
            (Self::InfoZipOwnership16, Header::Central, 0) => None,
            (Self::InfoZipOwnership, _, _) => Some(ownership_ids(data).ok_or_else(invalid_layout)?),
            (Self::Zip64 | Self::UnicodePath | Self::UnicodeComment, _, _) => None,
            (Self::InfoZipUnix | Self::InfoZipOwnership16, _, _) => {
                return Err(invalid_layout());
            }
        };
        fields.owner = owner.map(|(uid, gid)| (significant_bytes(uid), significant_bytes(gid)));
        Ok(fields)
    }
}

impl UnixMetadata<'_> {
    fn merge(self, other: Self, position: u64) -> Result<Self, Error> {
        Ok(Self {
            atime: agree(self.atime, other.atime, position)?,
            mtime: agree(self.mtime, other.mtime, position)?,
            owner: agree(self.owner, other.owner, position)?,
        })
    }
}

fn agree<T: Eq>(left: Option<T>, right: Option<T>, position: u64) -> Result<Option<T>, Error> {
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
