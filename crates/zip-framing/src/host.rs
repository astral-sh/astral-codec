use crate::constants::host;

/// The host-system interpretation of a ZIP member's external attributes.
///
/// This is the high byte of "version made by" (APPNOTE section 4.4.2).
/// It identifies attribute compatibility, not necessarily the writer's OS.
/// Conversions to and from [`u8`] preserve unrecognized identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostSystem {
    /// MS-DOS and OS/2 FAT, VFAT, and FAT32 filesystems (0).
    MsDos,
    /// Amiga (1).
    Amiga,
    /// OpenVMS (2).
    OpenVms,
    /// UNIX (3).
    Unix,
    /// VM/CMS (4).
    VmCms,
    /// Atari ST (5).
    AtariSt,
    /// OS/2 HPFS (6).
    Os2Hpfs,
    /// Macintosh (7).
    Macintosh,
    /// Z-System (8).
    ZSystem,
    /// CP/M (9).
    Cpm,
    /// Windows NTFS (10).
    WindowsNtfs,
    /// MVS, OS/390, and z/OS (11).
    Mvs,
    /// VSE (12).
    Vse,
    /// Acorn RISC (13).
    AcornRisc,
    /// VFAT (14).
    Vfat,
    /// Alternate MVS (15).
    AlternateMvs,
    /// BeOS (16).
    BeOs,
    /// Tandem (17).
    Tandem,
    /// OS/400 (18).
    Os400,
    /// OS X (Darwin) (19).
    Darwin,
    /// An unrecognized host-system identifier.
    Unknown(u8),
}

impl From<u8> for HostSystem {
    fn from(value: u8) -> Self {
        match value {
            host::MS_DOS => Self::MsDos,
            1 => Self::Amiga,
            2 => Self::OpenVms,
            host::UNIX => Self::Unix,
            4 => Self::VmCms,
            5 => Self::AtariSt,
            host::OS2_HPFS => Self::Os2Hpfs,
            7 => Self::Macintosh,
            8 => Self::ZSystem,
            9 => Self::Cpm,
            host::WINDOWS_NTFS => Self::WindowsNtfs,
            11 => Self::Mvs,
            12 => Self::Vse,
            13 => Self::AcornRisc,
            host::VFAT => Self::Vfat,
            15 => Self::AlternateMvs,
            16 => Self::BeOs,
            17 => Self::Tandem,
            18 => Self::Os400,
            host::OS_X => Self::Darwin,
            _ => Self::Unknown(value),
        }
    }
}

impl From<HostSystem> for u8 {
    fn from(value: HostSystem) -> Self {
        match value {
            HostSystem::MsDos => host::MS_DOS,
            HostSystem::Amiga => 1,
            HostSystem::OpenVms => 2,
            HostSystem::Unix => host::UNIX,
            HostSystem::VmCms => 4,
            HostSystem::AtariSt => 5,
            HostSystem::Os2Hpfs => host::OS2_HPFS,
            HostSystem::Macintosh => 7,
            HostSystem::ZSystem => 8,
            HostSystem::Cpm => 9,
            HostSystem::WindowsNtfs => host::WINDOWS_NTFS,
            HostSystem::Mvs => 11,
            HostSystem::Vse => 12,
            HostSystem::AcornRisc => 13,
            HostSystem::Vfat => host::VFAT,
            HostSystem::AlternateMvs => 15,
            HostSystem::BeOs => 16,
            HostSystem::Tandem => 17,
            HostSystem::Os400 => 18,
            HostSystem::Darwin => host::OS_X,
            HostSystem::Unknown(value) => value,
        }
    }
}
