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
- **Info-ZIP timestamps and ownership.** Section 4.6.1 lists `0x5455`,
  `0x5855`, and `0x7855`. On macOS, `ditto` writes `0x5855` with two
  timestamps in each header and a local UID/GID pair (12 bytes locally,
  8 centrally).
  Info-ZIP `zip` writes `0x5455` with only the modification time repeated
  centrally, alongside the newer ownership field `0x7875`. These metadata
  fields do not affect the decoded member type, payload, or permissions.
  [Info-ZIP field layouts](https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt)

## Open policy questions

- **Which member extra fields may we skip?** Section 4.6.2 permits skipping
  third-party fields by length. We check bounds and reject duplicate IDs.
  For an unknown ID, copies in both headers must be identical, but a single
  copy is accepted. This says nothing about the meaning of its bytes. For
  example, ZipIt `0x2605` identifies MacBinary-encoded contents and can
  supply another filename (§4.6.4). We expose the ordinary name and payload.
  An allowlist would exclude such fields. To keep reading ordinary Info-ZIP
  archives, we would first need to recognize its `0x7875` ownership field.
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

## Proposed restrictions

- **UNIX file types.** A target in `0x000d` can turn a regular or untyped file
  into a hard link whose payload can overwrite the target on extraction. Section
  4.5.7 names hard links but gives no independent type marker or replacement
  semantics. Reject this ambiguity, incomplete device numbers, UNIX type data
  on unrelated kinds, and volume labels that override another type. The ASi UNIX
  field (`0x756e`) can also supply a second mode or symlink target.
- **Unicode comments.** The CRC in `0x6375` covers the original member comment.
  It can be correct while the Unicode text differs (§4.6.8).
  The reader already requires UTF-8 for both. Require the same text and check
  a local copy against the validated central field.
- **Archive-level extensions.** The reader parses the archive extra data
  record using member-field rules and accepts unknown ZIP64 extensible data
  sector IDs. The former has security-related uses (§7.5.2). The latter has
  its own ID namespace (§4.3.14.4, Appendix C). Reject these unsupported
  records at archive open.
- **Info-ZIP field reconciliation.** The current prefix checks accept a
  seven-byte `0x5855` central field, which ends partway through a timestamp.
  Validate the documented local and central layouts of `0x5855`, `0x5455`,
  and `0x7855` before comparing the shared values.
