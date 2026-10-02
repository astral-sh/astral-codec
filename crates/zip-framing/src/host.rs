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
            0 => Self::MsDos,
            1 => Self::Amiga,
            2 => Self::OpenVms,
            3 => Self::Unix,
            4 => Self::VmCms,
            5 => Self::AtariSt,
            6 => Self::Os2Hpfs,
            7 => Self::Macintosh,
            8 => Self::ZSystem,
            9 => Self::Cpm,
            10 => Self::WindowsNtfs,
            11 => Self::Mvs,
            12 => Self::Vse,
            13 => Self::AcornRisc,
            14 => Self::Vfat,
            15 => Self::AlternateMvs,
            16 => Self::BeOs,
            17 => Self::Tandem,
            18 => Self::Os400,
            19 => Self::Darwin,
            _ => Self::Unknown(value),
        }
    }
}

impl From<HostSystem> for u8 {
    fn from(value: HostSystem) -> Self {
        value.to_byte()
    }
}

impl HostSystem {
    pub(crate) const fn to_byte(self) -> u8 {
        match self {
            Self::MsDos => 0,
            Self::Amiga => 1,
            Self::OpenVms => 2,
            Self::Unix => 3,
            Self::VmCms => 4,
            Self::AtariSt => 5,
            Self::Os2Hpfs => 6,
            Self::Macintosh => 7,
            Self::ZSystem => 8,
            Self::Cpm => 9,
            Self::WindowsNtfs => 10,
            Self::Mvs => 11,
            Self::Vse => 12,
            Self::AcornRisc => 13,
            Self::Vfat => 14,
            Self::AlternateMvs => 15,
            Self::BeOs => 16,
            Self::Tandem => 17,
            Self::Os400 => 18,
            Self::Darwin => 19,
            Self::Unknown(value) => value,
        }
    }
}
