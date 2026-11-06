# ZIP differential triage

Triage is complete for all nine findings. The first three items affect which
members a reader sees, which bytes it returns, or which filesystem object it
creates. Results are from `ww/zip-codec` at `33a197b`. The format reference is
[PKWARE APPNOTE 6.3.3][appnote].

## 1. Stored members with data descriptors

A 187-byte ZIP has one central directory entry, `outer`. Its 63-byte Stored
payload begins with `PUBLIC`, followed by a valid data descriptor for those
six bytes and a local file record for `ghost` containing `SECRET`. The real
descriptor follows all 63 bytes. Both CRCs and both sets of sizes check out.

`zip-codec` at `33a197b` and macOS `bsdtar -xf` on a file extract only the 63-byte
`outer`. Pipe the same bytes into `bsdtar -xf -` and it successfully writes
two files, `outer` containing `PUBLIC` and `ghost` containing `SECRET`.
The split occurs with either a signed or an unsigned real descriptor.
Clearing bit 3 or switching the member to DEFLATE made the readers agree.

**Decision.** Stored members with data descriptors require an opt-in.

<details>
<summary>Reproduce the member lists on macOS</summary>

```sh
archive=crates/zip-codec/tests/fixtures/stored-descriptor-ghost.zip
/usr/bin/bsdtar -tf "$archive"         # outer
cat "$archive" | /usr/bin/bsdtar -tf - # outer, ghost
```

</details>

## 2. Duplicate names in consistent order

Two members named `same` contain `FIRST` and `LAST`, in that order in both
the local headers and the central directory. `zip-codec` enumerates both.
Go's `archive/zip.Reader.Open("same")` returns `FIRST`. Python's
`ZipFile.read("same")` returns `LAST`. Rust's `zip` 9.0.4 exposes only the
latter entry even during iteration by index.

**Decision.** Accept repeated destinations when their relative order agrees
in the central directory and local headers. Callers that write members to disk
themselves decide how to handle collisions. [`Archive::members` documentation](crates/archive-trait/src/lib.rs#L258-L263).

## 3. Creator systems and symlink mode bits

With `0120777` in the upper 16 external attribute bits and `target` in the
payload, changing the creator system changes what readers extract.

| Creator system | `zip-codec` | Apple's Info-ZIP `unzip` | Seekable libarchive |
| --- | --- | --- | --- |
| OpenVMS (2), Atari ST (5), BeOS (16), ID 30 | File containing `target` | Symlink to `target` | File containing `target` |
| Darwin (19) | Symlink to `target` | File containing `target` | File containing `target` |

With an MS-DOS creator (0), mode `0120666`, and clear DOS attributes, Apple's
`unzip` also creates a symlink. Both `zip-codec` at `33a197b` and seekable
libarchive read a regular file.

**Decision.** Symlink mode bits from creators other than Unix (3) require an opt-in.

## 4. Unix symlinks in streaming readers

Our encoder puts a Unix symlink's mode in the central directory and its target
in the payload. Given a symlink produced by the encoder, macOS `bsdtar`
created a symlink when reading from a file. Reading from a pipe, it created a
regular file containing the target text. Both extractions succeeded.

**Decision.** Won't fix. Our seekable reader gets the file type from the
central directory, and our encoder uses the conventional Unix symlink layout.
[Writer conventions](crates/zip-codec/APPNOTE.md#writer-conventions).

## 5. Info-ZIP strips version suffixes

Our encoder accepts `config` containing `FIRST` and `config;1` containing
`LAST`. Our default extractor writes both. On the same filesystem, Apple's
Info-ZIP `unzip -o` writes only `config`, containing `LAST`. It also strips
a trailing bare `;` and preserves `;1x`.

**Decision.** Won't fix. `zip-codec` preserves these names literally. Stripping
VMS version suffixes is an Info-ZIP extraction convention.

## 6. AppleDouble sidecars

Given `ordinary` and `__MACOSX/._ordinary`, both `zip-codec` and CPython
3.15.2's `zipfile` extract the two files byte-for-byte.
On macOS, seekable libarchive 3.8.10 exposes only `ordinary` and attaches the
sidecar's 46 bytes as metadata. Its streaming reader exposes both files.
Our encoder accepts both names. [Libarchive sidecar handling](https://github.com/libarchive/libarchive/blob/v3.8.10/libarchive/archive_read_support_format_zip.c#L4501-L4556).

**Decision.** Won't fix. AppleDouble sidecars are ordinary members in our
archive model.

## 7. Conflicting timestamps and ownership across extra fields

At `33a197b`, `ExtraFieldPolicy::AllowListed` accepted fields with different
values for the same property. With modification time in both PKWARE UNIX
(`0x000d`) and Info-ZIP extended timestamp (`0x5455`),
Java reported 2021-01-01 and libarchive reported 2000-01-01 for the same
bytes. With ownership in both `0x000d` and `0x7875`, reversing field order
changed libarchive's UID/GID from 50/51 to 42/43. The default ZIP64-only
policy rejects these fields.

**Decision.** Require PKWARE and Info-ZIP extra fields to agree wherever both
supply an access time, modification time, UID, or GID, including across local
and central headers. [Extra-field policy](crates/zip-codec/APPNOTE.md#member-extra-fields).

## 8. Invalid DOS dates

Framing accepts 2024-02-31 when both headers contain that date. Python
exposes the tuple `(2024, 2, 31, 0, 0, 0)`. Java reports 2024-03-02.
APPNOTE §4.4.6 specifies the MS-DOS date and time format.

**Decision.** Won't fix. Framing requires the two headers to agree on the DOS
timestamp. The filesystem supplies timestamps during extraction.

## 9. Member comments with the UTF-8 flag clear

Framing at `33a197b` accepted the member-comment bytes `c3 a9` with general
purpose bit 11 clear. Java reads them as `é` with its UTF-8 default and as `├⌐` with
IBM437 selected. Setting bit 11 made both reads return `é`. APPNOTE
Appendix D.2 applies the encoding flag to both names and member comments.

**Decision.** Reject nonempty member comments and require ASCII archive
comments by default. Callers can set the two policies independently. A
survey of 4,619 PyPI ZIPs found no member comments and eight archive comments,
all `zip-rs`. PyPI checks the member comment length and skips the declared
archive comment. [Warehouse ZIP validator](https://github.com/pypi/warehouse/blob/c781d360f6a5435b54af7b6a242d0cbfc733b49a/warehouse/utils/zipfiles.py#L165-L204).

## Coverage

The analysis exercised 145 generated archives and nine checked-in ZIP
fixtures. It validated framing and consumed file payloads through
`zip-codec`. All 21 malformed ZIP64 controls were rejected, as were
reversed duplicate order, mismatched local names, bad payload CRCs, and
truncated DEFLATE streams or bytes following the stream.

All 6,545 entries across six cached wheels decoded successfully. Counts were
zero for data descriptors, repeated exact names, symlink mode bits, version
suffixes, and AppleDouble sidecar names in that sample.

[appnote]: https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT
