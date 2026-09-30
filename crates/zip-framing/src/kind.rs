use crate::{
    DirectoryEntry, Error,
    constants::{attributes, host, version},
    invalid,
};

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
        directory: &DirectoryEntry,
        unix_data: Option<&[u8]>,
        attributes: &ExternalAttributes,
    ) -> Result<Self, Error> {
        let extra = unix_data.filter(|data| !data.is_empty());
        let is_directory = directory.path().ends_with('/') || attributes.dos_directory;
        if attributes.dos_volume_label {
            return Ok(Self::VolumeLabel);
        }

        let kind = match attributes.unix_mode & attributes::UNIX_TYPE_MASK {
            0 if is_directory => Self::Directory,
            0 | attributes::UNIX_REGULAR if !is_directory => {
                if extra.is_some() {
                    Self::HardLink
                } else {
                    Self::File
                }
            }
            attributes::UNIX_DIRECTORY => Self::Directory,
            attributes::UNIX_SYMLINK if !is_directory => Self::SymbolicLink,
            attributes::UNIX_CHARACTER_DEVICE if !is_directory => Self::CharacterDevice,
            attributes::UNIX_BLOCK_DEVICE if !is_directory => Self::BlockDevice,
            attributes::UNIX_FIFO if !is_directory => Self::Fifo,
            attributes::UNIX_SOCKET if !is_directory => Self::Socket,
            mode if !is_directory => Self::Unknown(mode),
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

/// An extracted form of a central directory entry's "external attributes" field.
///
/// See [`DirectoryEntry::external_attributes`].
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
    pub(crate) fn new(host_system: u8, raw: u32) -> Self {
        let has_dos_attributes = matches!(
            host_system,
            host::MS_DOS
                | host::UNIX
                | host::OS2_HPFS
                | host::WINDOWS_NTFS
                | host::VFAT
                | host::OS_X
        );

        Self {
            unix_mode: if matches!(host_system, host::UNIX | host::OS_X) {
                (raw >> attributes::UNIX_MODE_SHIFT) as u16
            } else {
                0
            },
            dos_directory: has_dos_attributes && raw & attributes::DOS_DIRECTORY != 0,
            dos_volume_label: has_dos_attributes && raw & attributes::DOS_VOLUME_LABEL != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExternalAttributes;

    #[test]
    fn interprets_external_attributes_according_to_the_host() {
        for (host, unix_mode, has_dos_attributes) in [
            (0, 0, true),
            (3, 0o100755, true),
            (6, 0, true),
            (10, 0, true),
            (14, 0, true),
            (19, 0o100755, true),
            (1, 0, false),
            (255, 0, false),
        ] {
            let attributes = ExternalAttributes::new(host, (0o100755 << 16) | 0x10);
            assert_eq!(attributes.unix_mode, unix_mode, "host {host}");
            assert_eq!(attributes.dos_directory, has_dos_attributes, "host {host}");
            assert!(!attributes.dos_volume_label, "host {host}");

            let attributes = ExternalAttributes::new(host, 0x08);
            assert_eq!(attributes.unix_mode, 0, "host {host}");
            assert!(!attributes.dos_directory, "host {host}");
            assert_eq!(
                attributes.dos_volume_label, has_dos_attributes,
                "host {host}"
            );
        }
    }
}
