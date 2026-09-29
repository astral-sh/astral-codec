use std::{collections::BTreeMap, str};

use flate2::Crc;

use crate::{
    Error, invalid,
    record::{Common, parse_name, u16_at, u32_at, u64_at},
};

pub(crate) struct Extras<'a> {
    fields: BTreeMap<u16, &'a [u8]>,
}

/// Member metadata obtained by reconciling local and central extra fields.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedExtras {
    unix_data: Option<Vec<u8>>,
}

impl ResolvedExtras {
    pub(crate) fn unix_data(&self) -> Option<&[u8]> {
        self.unix_data.as_deref()
    }
}

impl<'a> Extras<'a> {
    pub(crate) fn parse(mut bytes: &'a [u8], position: u64) -> Result<Self, Error> {
        let mut fields = BTreeMap::new();

        while !bytes.is_empty() {
            if bytes.len() < 4 {
                return Err(invalid(position, "truncated extra-field header"));
            }

            let identifier = u16_at(bytes, 0);
            let length = usize::from(u16_at(bytes, 2));
            bytes = &bytes[4..];
            let Some(data) = bytes.get(..length) else {
                return Err(invalid(position, "truncated extra-field data"));
            };

            let unsupported = match identifier {
                0x0007 => Some("authenticity verification"),
                0x000f => Some("patch descriptor"),
                0x0014..=0x0016 => Some("digital signature"),
                0x0017 | 0x0019 | 0x9901 => Some("encryption extra field"),
                0x0008 => Some("alternate name encoding"),
                _ => None,
            };
            if let Some(feature) = unsupported {
                return Err(Error::Unsupported { position, feature });
            }

            if fields.insert(identifier, data).is_some() {
                return Err(invalid(position, "duplicate extra-field identifier"));
            }

            if identifier == 0x000d && data.len() < 12 {
                return Err(invalid(position, "truncated UNIX extra field"));
            }

            bytes = &bytes[length..];
        }

        Ok(Self { fields })
    }

    fn unix_data(&self) -> Option<&[u8]> {
        self.fields.get(&0x000d).map(|data| &data[12..])
    }

    pub(crate) fn zip64(
        &self,
        common: Common,
        offset: Option<u32>,
        disk: Option<u16>,
        position: u64,
    ) -> Result<Sizes, Error> {
        let local = offset.is_none();
        let mut expected = 0;
        let uncompressed = common.uncompressed == u32::MAX;
        let compressed = common.compressed == u32::MAX;
        if local && uncompressed != compressed {
            return Err(invalid(position, "local ZIP64 must contain both sizes"));
        }

        expected += usize::from(uncompressed) * 8;
        expected += usize::from(compressed) * 8;
        expected += usize::from(offset == Some(u32::MAX)) * 8;
        expected += usize::from(disk == Some(u16::MAX)) * 4;

        let field = self.fields.get(&1).copied();
        if field.map(<[u8]>::len) != (expected != 0).then_some(expected) {
            return Err(invalid(position, "missing or superfluous ZIP64 values"));
        }
        common.check_zip64(field.is_some(), position)?;

        let mut bytes = field.unwrap_or_default();
        let mut take_size = |small: u32| {
            if small == u32::MAX {
                let value = u64_at(bytes, 0);
                bytes = &bytes[8..];
                value
            } else {
                u64::from(small)
            }
        };

        let uncompressed = take_size(common.uncompressed);
        let compressed = take_size(common.compressed);
        let offset = offset.map(&mut take_size).unwrap_or_default();

        let disk = match disk {
            Some(u16::MAX) => u32_at(bytes, 0),
            Some(disk) => u32::from(disk),
            None => 0,
        };
        if disk != 0 {
            return Err(Error::Unsupported {
                position,
                feature: "multiple volumes",
            });
        }

        Ok(Sizes {
            uncompressed,
            compressed,
            offset,
            zip64: field.is_some(),
        })
    }

    pub(crate) fn name(&self, bytes: &[u8], flags: u16, position: u64) -> Result<String, Error> {
        let name = parse_name(bytes, flags, position)?;

        if let Some(field) = self.fields.get(&0x7075) {
            let unicode = unicode_field(field, bytes, position)?;
            if unicode != name {
                return Err(invalid(
                    position,
                    "Unicode path extra field disagrees with filename",
                ));
            }
        }

        Ok(name.to_owned())
    }

    pub(crate) fn comment(&self, bytes: &[u8], flags: u16, position: u64) -> Result<(), Error> {
        if flags & 0x0800 != 0 && str::from_utf8(bytes).is_err() {
            return Err(invalid(position, "non-UTF-8 comment with UTF-8 flag"));
        }

        if let Some(field) = self.fields.get(&0x6375) {
            unicode_field(field, bytes, position)?;
        }

        Ok(())
    }

    pub(crate) fn resolve(
        self,
        central: Extras<'_>,
        position: u64,
    ) -> Result<ResolvedExtras, Error> {
        for (identifier, local) in &self.fields {
            let Some(other) = central.fields.get(identifier) else {
                continue;
            };

            // APPNOTE and Info-ZIP define shorter central forms for these
            // fields. ZIP64 values are resolved and compared separately.
            let equal = match identifier {
                1 => true,
                0x000d | 0x5855 => local.get(..other.len()) == Some(*other),
                0x5455 => {
                    local.first() == other.first() && local.get(..other.len()) == Some(*other)
                }
                0x7855 => other.is_empty() || local == other,
                _ => local == other,
            };
            if !equal {
                return Err(invalid(position, "local and central extra fields disagree"));
            }
        }

        Ok(ResolvedExtras {
            unix_data: self
                .unix_data()
                .or_else(|| central.unix_data())
                .map(<[u8]>::to_vec),
        })
    }
}

fn unicode_field<'a>(field: &'a [u8], original: &[u8], position: u64) -> Result<&'a str, Error> {
    if field.len() < 5 || field[0] != 1 {
        return Err(invalid(position, "invalid Unicode extra field"));
    }

    let mut crc = Crc::new();
    crc.update(original);
    if u32_at(field, 1) != crc.sum() {
        return Err(invalid(position, "Unicode extra field CRC mismatch"));
    }

    let value = str::from_utf8(&field[5..])
        .map_err(|_| invalid(position, "non-UTF-8 Unicode extra field"))?;
    if value.starts_with('\u{feff}') {
        return Err(invalid(position, "Unicode extra field contains a BOM"));
    }

    Ok(value)
}

pub(crate) struct Sizes {
    pub(crate) uncompressed: u64,
    pub(crate) compressed: u64,
    pub(crate) offset: u64,
    pub(crate) zip64: bool,
}
