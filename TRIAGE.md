# ZIP APPNOTE triage

Findings from comparing `ww/zip-codec` at `af490d4` with the ZIP format
specification. [PKWARE APPNOTE 6.3.9]

## 1. Central-directory entry length

Sections 4.4.10–12 recommend keeping the entire central-directory entry within
65,535 bytes, including its fixed header, filename, extra fields, and comment.
Before the cap, the writer accepted a 65,535-byte filename. With the 46-byte
fixed header and 28-byte ZIP64 extra, that produced a 65,609-byte entry.
The larger entry fits the wire format because each variable-length field has
its own 16-bit length.

**Decision.** The writer caps the complete central-directory entry at 65,535
bytes in `PendingMember::new`, before any output. The current layout leaves
65,461 UTF-8 bytes for the filename, including any trailing slash.
[PR #358](https://github.com/astral-sh/astral-codec/pull/358) ·
[Writer check](crates/zip-framing/src/write.rs#L52)

## 2. Unicode path and comment extras

Sections 4.6.8–9 define optional UTF-8 copies of the filename and comment.
Their CRCs cover the corresponding original bytes in the header. If a tool
renames `old.txt` to `new.txt` and leaves the extra untouched, the APPNOTE
recommends using `new.txt`. It also recommends ignoring Unicode extras
with unknown versions.

With `ExtraFieldPolicy::AllowListed`, we reject a stale CRC or an unknown
version. We require the extra's text to agree with the header. A legacy name
such as `café` encoded in IBM Code Page 437 also fails, even with a valid
Unicode Path extra. The reader validates the header filename as ASCII or
UTF-8 with bit 11 set before inspecting the extra.
[Name parsing](crates/zip-framing/src/record.rs#L145) ·
[Unicode extra validation](crates/zip-framing/src/extra.rs#L242)

**Decision.** Treat these rejections as an intentional compatibility
restriction. Requiring agreement gives readers that use either representation
the same filename or comment for entries we accept.

## 3. DEFLATE streams for empty members

Section 4.3.8 requires zero bytes of file data for empty files and
directories. A valid DEFLATE stream such as `03 00` occupies two bytes and
decodes to zero bytes. Our reader accepts and validates that representation
for empty files and directories. The writer emits both as Stored with zero
payload bytes.
[Reader test](crates/zip-codec/tests/decode.rs#L800) ·
[Writer](crates/zip-codec/src/encode.rs#L358)

## 4. Filename policy

- Section 4.4.17.1 describes a zero-length name for input from stdin. The
  reader rejects it when indexing the central directory.
  [Index check](crates/zip-framing/src/index/entry.rs#L179)
- Section 4.4.17.1 specifies forward slashes as separators. The reader
  rejects backslashes by default. `DecodePolicy::allow_backslashes(true)`
  preserves them literally for metadata and payload reads. Filesystem
  extraction returns `UnsafePath` for those names.
  [Decode policy](crates/zip-codec/src/decode.rs#L67) ·
  [Extraction check](crates/archive-trait/src/extract/path.rs#L233)
- The codec requires directory names to end in `/`. This makes the name
  agree with the type for readers that classify directories by suffix and
  readers that use external attributes.
  [Directory check](crates/zip-framing/src/kind.rs#L65)

## 5. DOS modification date and time

Section 4.4.6 requires MS-DOS encoding for the modification date and time.
The reader compares the packed fields in the local and central headers.
Matching `0x0000` dates pass, even though they encode month and day zero.
The decoded member model carries no timestamp. The writer emits midnight
on January 1, 1980.
[Header parsing](crates/zip-framing/src/record.rs#L394) ·
[Writer defaults](crates/zip-framing/src/write.rs#L22)

## 6. DOS volume-label extraction version

Section 4.4.3.2 specifies a minimum extraction version of 1.1 for DOS volume
labels. `zip-framing` returns `EntryKind::VolumeLabel` for a member whose
local and central headers both declare version 1.0. The high-level
`zip-codec` rejects volume labels during member validation.
[Framing classification](crates/zip-framing/src/kind.rs#L117) ·
[Codec validation](crates/zip-codec/src/decode.rs#L361)

[PKWARE APPNOTE 6.3.9]: https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT
