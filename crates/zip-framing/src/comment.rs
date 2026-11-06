use std::str;

use crate::{Error, invalid};

/// Which ZIP comment bytes the reader accepts. Empty comments are always accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommentPolicy {
    /// Reject nonempty comments.
    Reject,
    /// Accept only ASCII bytes.
    AllowAscii,
    /// Accept UTF-8. Non-ASCII member comments must set the UTF-8 flag (bit 11).
    AllowUtf8,
    /// Accept arbitrary bytes. Member comments with bit 11 set must still be UTF-8.
    AllowAll,
}

impl CommentPolicy {
    pub(crate) fn for_member(self, utf8: bool) -> Self {
        match (self, utf8) {
            (Self::AllowUtf8, false) => Self::AllowAscii,
            (Self::AllowAll, true) => Self::AllowUtf8,
            _ => self,
        }
    }

    pub(crate) fn check(self, bytes: &[u8], position: u64) -> Result<(), Error> {
        match self {
            Self::Reject if !bytes.is_empty() => Err(Error::Unsupported {
                position,
                feature: "nonempty comment",
            }),
            Self::AllowAscii if !bytes.is_ascii() => Err(Error::Unsupported {
                position,
                feature: "non-ASCII comment",
            }),
            Self::AllowUtf8 => str::from_utf8(bytes)
                .map(|_| ())
                .map_err(|_| invalid(position, "non-UTF-8 comment")),
            Self::Reject | Self::AllowAscii | Self::AllowAll => Ok(()),
        }
    }
}
