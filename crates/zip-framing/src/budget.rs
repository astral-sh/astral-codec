use thiserror::Error;

const ONE_MIB: u64 = 1024 * 1024;
const ONE_GIB: u64 = 1024 * ONE_MIB;

/// Limits applied when reading or writing ZIP archives.
///
/// Raising these values permits correspondingly more memory, I/O, or CPU work.
/// Compressed input and decoded output have independent bounds; no compression
/// ratio heuristic is needed to bound highly compressible files.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded archive length (default: 128 GiB).
    pub archive_size: u64,
    /// Maximum number of members (default: 100,000).
    pub entries: usize,
    /// Maximum cumulative metadata size (default: 64 MiB).
    ///
    /// Readers charge central directory, resolved local, and ZIP64 end records.
    /// Encoders charge local and central headers.
    pub metadata_size: u64,
    /// Maximum uncompressed size of one member (default: 8 GiB).
    pub member_size: u64,
    /// Maximum sum of uncompressed member sizes (default: 64 GiB).
    pub total_size: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            archive_size: 128 * ONE_GIB,
            entries: 100_000,
            metadata_size: 64 * ONE_MIB,
            member_size: 8 * ONE_GIB,
            total_size: 64 * ONE_GIB,
        }
    }
}

/// ZIP resource limits and cumulative metadata and uncompressed-size usage.
///
/// Failed charges leave usage unchanged. To commit several charges together,
/// charge a copy and replace the original only after the operation succeeds.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    metadata: u64,
    uncompressed: u64,
    limits: Limits,
}

impl Budget {
    /// Creates a budget with no accumulated usage.
    pub fn new(limits: Limits) -> Self {
        Self {
            metadata: 0,
            uncompressed: 0,
            limits,
        }
    }

    /// Replaces the limits without resetting usage. Subsequent checks use them.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Checks the encoded archive's size against its limit.
    pub fn check_archive_size(&self, size: u64) -> Result<(), BudgetError> {
        if size > self.limits.archive_size {
            return Err(BudgetError::ArchiveSize(self.limits.archive_size));
        }

        Ok(())
    }

    /// Checks the archive's entry count against its limit.
    pub fn check_entry_count(&self, count: u64) -> Result<(), BudgetError> {
        if count > self.limits.entries as u64 {
            return Err(BudgetError::EntryCount(self.limits.entries as u64));
        }

        Ok(())
    }

    /// Charges metadata bytes against [`Limits::metadata_size`].
    pub fn charge_metadata(&mut self, length: u64) -> Result<(), BudgetError> {
        let metadata = self
            .metadata
            .checked_add(length)
            .ok_or(BudgetError::Overflow(self.metadata))?;
        if metadata > self.limits.metadata_size {
            return Err(BudgetError::MetadataSize(self.limits.metadata_size));
        }

        self.metadata = metadata;
        Ok(())
    }

    /// Charges one member's uncompressed size against [`Limits::member_size`]
    /// and [`Limits::total_size`].
    #[inline]
    pub fn charge_member(&mut self, size: u64) -> Result<(), BudgetError> {
        if size > self.limits.member_size {
            return Err(BudgetError::MemberSize(self.limits.member_size));
        }

        let uncompressed = self
            .uncompressed
            .checked_add(size)
            .ok_or(BudgetError::Overflow(self.uncompressed))?;
        if uncompressed > self.limits.total_size {
            return Err(BudgetError::TotalSize(self.limits.total_size));
        }

        self.uncompressed = uncompressed;
        Ok(())
    }
}

/// A failed budget check or charge.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// The encoded archive exceeded the given byte limit.
    #[error("ZIP exceeds archive bytes limit ({0})")]
    ArchiveSize(u64),
    /// The archive exceeded the given entry-count limit.
    #[error("ZIP exceeds entry count limit ({0})")]
    EntryCount(u64),
    /// Metadata exceeded the given byte limit.
    #[error("ZIP exceeds metadata bytes limit ({0})")]
    MetadataSize(u64),
    /// A member's uncompressed size exceeded the given byte limit.
    #[error("ZIP exceeds member bytes limit ({0})")]
    MemberSize(u64),
    /// Cumulative uncompressed sizes exceeded the given byte limit.
    #[error("ZIP exceeds total member bytes limit ({0})")]
    TotalSize(u64),
    /// Adding to the given cumulative usage overflowed [`u64`].
    #[error("ZIP budget size overflow")]
    Overflow(u64),
}
