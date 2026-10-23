use crate::{
    CentralDirectoryEntry, Error, HostSystem, constants::version, invalid, record::array_at,
};

/// A ZIP member's kind, determined from its reconciled metadata.
///
/// This describes the archive entry without imposing an extraction policy. Link
/// targets from a PKWARE UNIX extra field are nonempty UTF-8 without NUL bytes.
/// Targets in payloads have not been validated.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file, including entries with no explicit file type.
    File,
    /// A directory.
    Directory,
    /// A symbolic link with a target in the UNIX extra field or payload.
    SymbolicLink {
        /// The target from the PKWARE UNIX extra field, if any.
        unix_target: Option<String>,
    },
    /// A character device.
    CharacterDevice {
        /// Device numbers from the PKWARE UNIX extra field, if any.
        numbers: Option<DeviceNumbers>,
    },
    /// A block device.
    BlockDevice {
        /// Device numbers from the PKWARE UNIX extra field, if any.
        numbers: Option<DeviceNumbers>,
    },
    /// A named pipe.
    Fifo,
    /// A UNIX socket.
    Socket,
    /// A DOS volume label.
    VolumeLabel,
    /// An unrecognized UNIX file type, masked from the mode.
    Unknown {
        /// The masked UNIX file-type bits.
        mode: u16,
    },
}

impl EntryKind {
    pub(crate) fn resolve(
        directory: &CentralDirectoryEntry,
        unix_data: Option<Vec<u8>>,
        attributes: &ExternalAttributes,
    ) -> Result<Self, Error> {
        let position = directory.position();
        let file_type = match (
            UnixFileType::from(attributes.unix_mode),
            directory.path().ends_with('/') || attributes.dos_directory,
        ) {
            (UnixFileType::Unspecified | UnixFileType::Directory, true) => UnixFileType::Directory,
            (file_type, false) => file_type,
            _ => return Err(invalid(position, "inconsistent file attributes")),
        };
        if attributes.dos_volume_label && file_type != UnixFileType::Unspecified {
            return Err(invalid(position, "inconsistent file attributes"));
        }

        if (attributes.dos_volume_label
            || matches!(
                file_type,
                UnixFileType::Directory
                    | UnixFileType::CharacterDevice
                    | UnixFileType::BlockDevice
                    | UnixFileType::Fifo
                    | UnixFileType::Socket
            ))
            && (directory.size() != 0 || directory.crc32() != 0)
        {
            return Err(invalid(position, "non-file member has payload data"));
        }

        if file_type == UnixFileType::Directory && directory.version_needed() < version::V2_0 {
            return Err(invalid(
                position,
                "directory requires extraction version 2.0",
            ));
        }

        if file_type == UnixFileType::SymbolicLink && directory.size() == 0 && unix_data.is_none() {
            return Err(invalid(position, "empty symbolic-link target"));
        }

        let has_type_data = unix_data.as_ref().is_some_and(|data| !data.is_empty());
        Ok(match file_type {
            UnixFileType::SymbolicLink => Self::SymbolicLink {
                unix_target: unix_data
                    .map(|data| parse_link_target(data, position))
                    .transpose()?,
            },
            UnixFileType::CharacterDevice => Self::CharacterDevice {
                numbers: DeviceNumbers::parse(unix_data, position)?,
            },
            UnixFileType::BlockDevice => Self::BlockDevice {
                numbers: DeviceNumbers::parse(unix_data, position)?,
            },
            // APPNOTE 4.5.7 gives hard links a target but no distinct file type.
            UnixFileType::Unspecified | UnixFileType::Regular
                if has_type_data && !attributes.dos_volume_label =>
            {
                return Err(Error::Unsupported {
                    position,
                    feature: "ambiguous UNIX hard link",
                });
            }
            _ if has_type_data => return Err(invalid(position, "unexpected UNIX file-type data")),
            UnixFileType::Unspecified if attributes.dos_volume_label => Self::VolumeLabel,
            UnixFileType::Unspecified | UnixFileType::Regular => Self::File,
            UnixFileType::Directory => Self::Directory,
            UnixFileType::Fifo => Self::Fifo,
            UnixFileType::Socket => Self::Socket,
            UnixFileType::Unknown(mode) => Self::Unknown { mode },
        })
    }
}

/// Device numbers from a PKWARE UNIX extra field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceNumbers {
    /// The device's major number.
    pub major: u32,
    /// The device's minor number.
    pub minor: u32,
}

impl DeviceNumbers {
    fn parse(data: Option<Vec<u8>>, position: u64) -> Result<Option<Self>, Error> {
        let Some(data) = data else {
            return Ok(None);
        };

        let bytes: [u8; 8] = data
            .as_slice()
            .try_into()
            .map_err(|_| invalid(position, "invalid UNIX device numbers"))?;
        Ok(Some(Self {
            major: u32::from_le_bytes(array_at::<0, 4, _>(&bytes)),
            minor: u32::from_le_bytes(array_at::<4, 4, _>(&bytes)),
        }))
    }
}

fn parse_link_target(data: Vec<u8>, position: u64) -> Result<String, Error> {
    if data.is_empty() {
        return Err(invalid(position, "empty symbolic-link target"));
    }
    let target =
        String::from_utf8(data).map_err(|_| invalid(position, "non-UTF-8 UNIX link target"))?;
    if target.contains('\0') {
        return Err(invalid(position, "NUL in UNIX link target"));
    }
    Ok(target)
}

/// The file-type bits of a UNIX mode, excluding permissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnixFileType {
    Unspecified,
    Regular,
    Directory,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown(u16),
}

impl UnixFileType {
    /// The top 4 bits of a UNIX file mode, indicating the file type.
    /// This is equivalent extracting the `S_IFMT` masked bits from a `st_mode`.
    const TYPE_MASK: u16 = 0o170000;
}

impl From<u16> for UnixFileType {
    fn from(mode: u16) -> Self {
        match mode & Self::TYPE_MASK {
            0 => Self::Unspecified,
            0o100000 => Self::Regular,
            0o040000 => Self::Directory,
            0o120000 => Self::SymbolicLink,
            0o020000 => Self::CharacterDevice,
            0o060000 => Self::BlockDevice,
            0o010000 => Self::Fifo,
            0o140000 => Self::Socket,
            mode => Self::Unknown(mode),
        }
    }
}

impl From<UnixFileType> for u16 {
    fn from(file_type: UnixFileType) -> Self {
        match file_type {
            UnixFileType::Unspecified => 0,
            UnixFileType::Regular => 0o100000,
            UnixFileType::Directory => 0o040000,
            UnixFileType::SymbolicLink => 0o120000,
            UnixFileType::CharacterDevice => 0o020000,
            UnixFileType::BlockDevice => 0o060000,
            UnixFileType::Fifo => 0o010000,
            UnixFileType::Socket => 0o140000,
            UnixFileType::Unknown(mode) => mode,
        }
    }
}

/// An extracted form of a central directory entry's "external attributes" field.
///
/// See [`CentralDirectoryEntry::external_attributes`].
pub(crate) struct ExternalAttributes {
    /// The UNIX file mode.
    ///
    /// This is not standardized in the APPNOTE, but implementations that want to convey
    /// UNIX-style file modes conventionally store the lower 16 bits of `st_mode` into
    /// the upper 16 bits of the external attributes.
    pub(crate) unix_mode: u16,

    /// Whether the entry is marked with the DOS directory attribute.
    ///
    /// APPNOTE defines this for MS-DOS, but implementations widely use it to hint whether a
    /// member is a directory regardless of host platform. We reconcile this attribute with the
    /// conventional `/` suffix and the UNIX file type when determining the member's kind.
    /// See [`crate::Entry::kind`].
    dos_directory: bool,

    /// Whether the entry represents the disk/volume's name, rather than a regular file.
    ///
    /// This is classified as [`EntryKind::VolumeLabel`].
    dos_volume_label: bool,
}

impl ExternalAttributes {
    /// The DOS/FAT volume-label attribute.
    ///
    /// APPNOTE 4.4.15 places DOS attributes in the low byte for MS-DOS entries.
    /// The bit value is `FAT_DIRENT_ATTR_VOLUME_ID` in
    /// [Microsoft's FAT header](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/fastfat/fat.h).
    const DOS_VOLUME_LABEL: u32 = 0x08;

    /// The DOS/FAT directory attribute.
    ///
    /// APPNOTE 4.4.15 places DOS attributes in the low byte for MS-DOS entries.
    /// The bit value is `FAT_DIRENT_ATTR_DIRECTORY` in
    /// [Microsoft's FAT header](https://github.com/microsoft/Windows-driver-samples/blob/main/filesys/fastfat/fat.h).
    pub(crate) const DOS_DIRECTORY: u32 = 0x10;

    /// See the comment on [`ExternalAttributes::unix_mode`].
    pub(crate) const UNIX_MODE_SHIFT: u32 = 16;

    pub(crate) fn new(host_system: HostSystem, raw: u32) -> Self {
        let has_dos_attributes = matches!(
            host_system,
            HostSystem::MsDos
                | HostSystem::Unix
                | HostSystem::Os2Hpfs
                | HostSystem::WindowsNtfs
                | HostSystem::Vfat
                | HostSystem::Darwin
        );

        Self {
            unix_mode: if matches!(host_system, HostSystem::Unix | HostSystem::Darwin) {
                (raw >> Self::UNIX_MODE_SHIFT) as u16
            } else {
                0
            },
            dos_directory: has_dos_attributes && raw & Self::DOS_DIRECTORY != 0,
            dos_volume_label: has_dos_attributes && raw & Self::DOS_VOLUME_LABEL != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::HostSystem;

    use super::ExternalAttributes;

    #[test]
    fn interprets_external_attributes_according_to_the_host() {
        for (host, unix_mode, has_dos_attributes) in [
            (HostSystem::MsDos, 0, true),
            (HostSystem::Unix, 0o100755, true),
            (HostSystem::Os2Hpfs, 0, true),
            (HostSystem::WindowsNtfs, 0, true),
            (HostSystem::Vfat, 0, true),
            (HostSystem::Darwin, 0o100755, true),
            (HostSystem::Amiga, 0, false),
            (HostSystem::Unknown(255), 0, false),
        ] {
            let attributes = ExternalAttributes::new(host, (0o100755 << 16) | 0x10);
            assert_eq!(attributes.unix_mode, unix_mode, "host {host:?}");
            assert_eq!(
                attributes.dos_directory, has_dos_attributes,
                "host {host:?}"
            );
            assert!(!attributes.dos_volume_label, "host {host:?}");

            let attributes = ExternalAttributes::new(host, 0x08);
            assert_eq!(attributes.unix_mode, 0, "host {host:?}");
            assert!(!attributes.dos_directory, "host {host:?}");
            assert_eq!(
                attributes.dos_volume_label, has_dos_attributes,
                "host {host:?}"
            );
        }
    }
}
