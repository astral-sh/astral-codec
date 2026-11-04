# ZIP compatibility

`zip-codec` targets [PKWARE APPNOTE 6.3.3][appnote]. See the
[security model](../../SECURITY.md#zip-archives) for validation and limits.

## Writer conventions

**Symlink targets.** Info-ZIP, libarchive, and our encoder put the target in
the payload. APPNOTE puts it in the PKWARE UNIX extra field (`0x000d`, §4.5.7).
We accept either form for Unix and Darwin entries whose mode marks them as
symlinks. If both carry a target, the bytes must match.

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

**Timestamps and ownership.** macOS `ditto` writes two timestamps in both
copies of `0x5855` and a UID/GID pair in the local header. Info-ZIP `zip`
writes timestamps in `0x5455` and ownership in `0x7875`. We ignore these
values when extracting. [Info-ZIP field layouts][infozip]

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

**Skip unknown extra fields?** APPNOTE permits skipping fields by length
(§4.6.2). We accept unknown IDs in either header and require matching bytes
when both carry the field. ZipIt's `0x2605` can supply another filename and
mark the payload as MacBinary (§4.6.4).
An allowlist would rule that out. It would need to include Info-ZIP's
`0x7875` ownership field to keep reading archives written by `zip`.

[appnote]: https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT
[infozip]: https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt
[is-dir]: https://docs.python.org/3.14/library/zipfile.html#zipfile.ZipInfo.is_dir
