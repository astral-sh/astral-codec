use crate::{CentralDirectoryEntry, Error, HostSystem, constants::version, invalid};

/// A ZIP member's kind, determined from its reconciled metadata.
///
/// This describes the archive entry without imposing an extraction policy.
/// Link targets remain available through [`crate::Entry::unix_extra_data`] or
/// the member's payload; their contents have not been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file, including entries with no explicit file type.
    File,
    /// A directory.
    Directory,
    /// A symbolic link with a target in the UNIX extra field or payload.
    SymbolicLink,
    /// A hard link with a nonempty target in the UNIX extra field.
    HardLink,
    /// A character device.
    CharacterDevice,
    /// A block device.
    BlockDevice,
    /// A named pipe.
    Fifo,
    /// A UNIX socket.
    Socket,
    /// A DOS volume label.
    VolumeLabel,
    /// An unrecognized UNIX file type, masked from the mode.
    Unknown(u16),
}

impl EntryKind {
    pub(crate) fn resolve(
        directory: &CentralDirectoryEntry,
        unix_data: Option<&[u8]>,
        attributes: &ExternalAttributes,
    ) -> Result<Self, Error> {
        let extra = unix_data.filter(|data| !data.is_empty());
        let is_directory = directory.path().ends_with('/') || attributes.dos_directory;
        if attributes.dos_volume_label {
            return Ok(Self::VolumeLabel);
        }

        let kind = match UnixFileType::from(attributes.unix_mode) {
            UnixFileType::Unspecified if is_directory => Self::Directory,
            UnixFileType::Unspecified | UnixFileType::Regular if !is_directory => {
                if extra.is_some() {
                    Self::HardLink
                } else {
                    Self::File
                }
            }
            UnixFileType::Directory => Self::Directory,
            UnixFileType::SymbolicLink if !is_directory => Self::SymbolicLink,
            UnixFileType::CharacterDevice if !is_directory => Self::CharacterDevice,
            UnixFileType::BlockDevice if !is_directory => Self::BlockDevice,
            UnixFileType::Fifo if !is_directory => Self::Fifo,
            UnixFileType::Socket if !is_directory => Self::Socket,
            UnixFileType::Unknown(mode) if !is_directory => Self::Unknown(mode),
            _ => {
                return Err(invalid(
                    directory.position(),
                    "inconsistent file attributes",
                ));
            }
        };

        if matches!(
            kind,
            Self::Directory | Self::CharacterDevice | Self::BlockDevice | Self::Fifo | Self::Socket
        ) && (directory.size() != 0 || directory.crc32() != 0)
        {
            return Err(invalid(
                directory.position(),
                "non-file member has payload data",
            ));
        }

        if matches!(kind, Self::Directory) && directory.version_needed() < version::V2_0 {
            return Err(invalid(
                directory.position(),
                "directory requires extraction version 2.0",
            ));
        }

        if matches!(kind, Self::SymbolicLink) && directory.size() == 0 && extra.is_none() {
            return Err(invalid(directory.position(), "empty symbolic-link target"));
        }

        if extra.is_some() && matches!(kind, Self::Directory | Self::Fifo) {
            return Err(invalid(
                directory.position(),
                "unexpected UNIX file-type data",
            ));
        }

        if let Some(data) = extra
            && matches!(kind, Self::CharacterDevice | Self::BlockDevice)
            && data.len() != 8
        {
            return Err(invalid(directory.position(), "invalid UNIX device numbers"));
        }

        Ok(kind)
    }
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
