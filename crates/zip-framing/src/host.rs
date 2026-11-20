use crate::wire::wire_enum;

wire_enum! {
    /// The host-system interpretation of a ZIP member's external attributes.
    ///
    /// This is the high byte of "version made by" (APPNOTE section 4.4.2).
    /// It identifies attribute compatibility, not necessarily the writer's OS.
    /// Conversions to and from [`u8`] preserve unrecognized identifiers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[non_exhaustive]
    pub enum HostSystem(u8) {
        /// MS-DOS and OS/2 FAT, VFAT, and FAT32 filesystems.
        MsDos = 0,
        /// Amiga.
        Amiga = 1,
        /// OpenVMS.
        OpenVms = 2,
        /// UNIX.
        Unix = 3,
        /// VM/CMS.
        VmCms = 4,
        /// Atari ST.
        AtariSt = 5,
        /// OS/2 HPFS.
        Os2Hpfs = 6,
        /// Macintosh.
        Macintosh = 7,
        /// Z-System.
        ZSystem = 8,
        /// CP/M.
        Cpm = 9,
        /// Windows NTFS.
        WindowsNtfs = 10,
        /// MVS, OS/390, and z/OS.
        Mvs = 11,
        /// VSE.
        Vse = 12,
        /// Acorn RISC.
        AcornRisc = 13,
        /// VFAT.
        Vfat = 14,
        /// Alternate MVS.
        AlternateMvs = 15,
        /// BeOS.
        BeOs = 16,
        /// Tandem.
        Tandem = 17,
        /// OS/400.
        Os400 = 18,
        /// OS X (Darwin).
        Darwin = 19,
    }
}

#[cfg(test)]
mod tests {
    use super::HostSystem;

    #[test]
    fn preserves_host_identifiers() {
        for value in u8::MIN..=u8::MAX {
            let host = HostSystem::from(value);
            if value >= 20 {
                assert_eq!(host, HostSystem::Unknown(value));
            }
            assert_eq!(u8::from(host), value);
        }
    }
}
