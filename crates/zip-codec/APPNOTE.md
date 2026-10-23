# ZIP compatibility and open policy questions

The reader targets [PKWARE APPNOTE 6.3.3](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT).
Section numbers below refer to that version. The [security model](../../SECURITY.md#zip-archives)
describes the checks the reader enforces.

## Writer conventions we keep

- **Symbolic links.** Section 4.4.15 leaves external attributes to the host.
  We read the high 16 bits as a Unix mode for Unix and Darwin entries.
  For a symlink, §4.5.7 puts the target in the PKWARE UNIX field (`0x000d`).
  Info-ZIP, libarchive, and our encoder write it in the payload. Member
  selection requires the targets to match when both forms are present.
  A symlink with a PKWARE UNIX field must supply a target there. Framing
  rejects a target on a regular or untyped file because it cannot distinguish
  a hard link from a regular file with unexpected metadata.
- **Empty DEFLATE streams.** Section 4.3.8 says an empty file or directory has
  no file data. Python can write a two-byte DEFLATE stream that decodes to
  zero bytes for either. The reader checks the stream boundary, decoded size,
  and CRC when it consumes the payload. Our encoder stores empty members.
  [Python fixtures](tests/fixtures/generate.py)
- **ZIP64 in a streaming member.** Python can set bit 3, put `0xffffffff` in
  both local size fields and zero sizes in the local ZIP64 extra, then supply
  the real sizes in a 64-bit descriptor. It can finish with just a classic
  end record when the directory counts, size, and offset fit. We accept that
  combination (§§4.3.9.2, 4.4.3.3, 4.5.3). The descriptor must agree with the
  directory. A sentinel in the classic end record still requires a ZIP64
  locator. Our encoder always writes ZIP64 end records.
  [Streaming fixtures](tests/fixtures/generate.py)

## Member extra fields

By default, the reader accepts only ZIP64 (`0x0001`), which supplies sizes,
offsets, or disk numbers when the ordinary header uses a sentinel. Our encoder
uses this field even for small members. `ExtraFieldPolicy::AllowListed` opts in
to the other seven fields below.

Section 4.6.2 permits skipping third-party fields by length. Both policies
reject IDs outside the table in either member header. Identical copies can still change
how another reader interprets a member: [libarchive's `xl` field](https://github.com/libarchive/libarchive/blob/v3.7.4/libarchive/archive_read_support_format_zip.c#L676)
can mark a regular file as a symlink, and ZipIt `0x2605` can supply another name
and mark the payload as MacBinary (§4.6.4).

| ID | Field | What we check |
| --- | --- | --- |
| `0x0001` | ZIP64 | Sizes, offsets, and disk numbers correspond to sentinels in the header (§4.5.3). |
| `0x000d` | PKWARE UNIX | The field has its fixed prefix, copies agree, and any file-type data matches the member kind (§4.5.7). |
| `0x6375`, `0x7075` | Unicode comment and path | The CRC and UTF-8 text agree with the ordinary comment or filename (§§4.6.8–9). |
| `0x5455` | Info-ZIP extended timestamps | Flags account for the timestamps; a central copy must agree with the local flags and modification time, if present. |
| `0x5855` | Original Info-ZIP UNIX | Each copy carries two timestamps. They must agree across headers; the local field may also carry a 16-bit UID and GID. |
| `0x7855` | Info-ZIP 16-bit ownership | The local field carries a UID and GID; an empty central marker requires a local copy. |
| `0x7875` | Info-ZIP variable-width ownership | Version 1 carries a UID and GID, each with a nonzero byte length. The two values must fill the field and copies must agree. |

macOS `ditto` writes `0x5855`; Info-ZIP `zip` writes `0x5455` and `0x7875` together.
We validate these [Info-ZIP layouts](https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt)
without applying timestamps or ownership. We reject `0x5855` alongside any
newer Info-ZIP timestamp or ownership field, and reject `0x7855` alongside
`0x7875`, rather than choosing which copy takes precedence.

## Open policy questions

- **What makes a directory?** The reader accepts a trailing `/`, a Unix
  directory mode, or the DOS directory bit. It reads DOS attributes on MS-DOS,
  Unix, OS/2 HPFS, Windows NTFS, VFAT, and Darwin entries. An empty Unix
  entry named `dir` with only the DOS directory bit becomes a directory here
  and a file in Python. Requiring a trailing `/` for directories would close
  that differential. Our encoder writes the slash, mode, and DOS bit. All 90
  directories in the four [benchmark wheels](benches/wheels/corpus.json) have
  a trailing slash.
  [Python's directory test](https://docs.python.org/3.14/library/zipfile.html#zipfile.ZipInfo.is_dir)
- **Record-oriented payloads.** The reader ignores the central header's
  internal file attributes. Bit `0x0002` declares that each logical record
  has a four-byte length prefix (§4.4.14.2). A member with this bit set
  passes validation as an ordinary byte stream. Rejecting the flag would
  prevent that interpretation.
- **Which extraction versions do we accept?** Python and `ditto` declare 2.0
  for ordinary stored files. Info-ZIP `zip` declares 1.0 for a stored file
  with extra fields, although §4.4.28 describes an empty extra field in 1.0.
  Those cases have known writers. The reader also accepts unlisted values such
  as 1.9 for stored files, a 4.5 declaration without ZIP64, and a 1.0 volume
  label (minimum 1.1 in §4.4.3.2). Framing could reject unlisted versions
  and enforce the volume-label minimum. Requiring an exact feature/version
  match would reject ordinary Python archives.
