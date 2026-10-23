# ZIP compatibility

`zip-codec` targets [PKWARE APPNOTE 6.3.3][appnote]. See the
[security model](../../SECURITY.md#zip-archives) for validation and limits.

## Writer conventions

**Symlink targets.** Info-ZIP, libarchive, and our encoder put the target in
the payload. APPNOTE puts it in the PKWARE UNIX extra field (`0x000d`, §4.5.7).
We accept either form for Unix and Darwin entries whose mode marks them as
symlinks. If the UNIX field is present, it must contain a target. A target
in the payload must agree with it. We reject UNIX targets on regular or
untyped files because they can also denote hard links.

**Empty files and directories.** Python can write a two-byte DEFLATE stream
for either, though §4.3.8 calls for zero bytes of file data. We accept the
stream after checking its boundary, CRC, and zero decoded size. Our encoder
stores empty members uncompressed.
[Python fixtures](tests/fixtures/generate.py)

**Streaming ZIP64.** Python can put a member's sizes in a 64-bit data
descriptor and finish the archive with a classic end record. We accept this
when the descriptor agrees with the central directory and the directory's
entry count, size, and offset fit in the classic record. A sentinel in the end
record still requires a ZIP64 locator (§§4.3.9.2, 4.4.3.3, 4.5.3).

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

**Require `/` on directories?** An empty Unix entry named `dir` with only the
DOS directory bit set is a directory to `zip-codec` and a file to Python.
Our encoder adds the slash, as do all 90 directories in the four
[benchmark wheels](benches/wheels/corpus.json). [Python's directory test][is-dir]

**Reject record-oriented files?** Internal attribute `0x0002` means each
record starts with a four-byte length (§4.4.14.2). We currently return those
lengths as part of the file contents.

**Tighten extraction versions?** Framing accepts unlisted versions such as
1.9 and volume labels below the 1.1 minimum (§4.4.3.2). We also accept 4.5
without ZIP64. For ordinary stored files, Python and `ditto` declare 2.0,
and Info-ZIP `zip` declares 1.0 even with extra fields (§4.4.28).

[appnote]: https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT
[is-dir]: https://docs.python.org/3.14/library/zipfile.html#zipfile.ZipInfo.is_dir
