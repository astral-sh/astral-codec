# ZIP differential triage

Items 2–9 are open. The first three items affect which members a reader
sees, which bytes it returns, or which filesystem object it creates. Results
are from `ww/zip-codec` at `33a197b`. The format reference is
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

**Decision.** Reject Stored members with general purpose bit 3 set when
opening the central directory. APPNOTE §§4.3.9 and 4.4.4 permit these members,
and Python produces them when writing Stored data to a pipe. Call
`allow_stored_data_descriptors(true)` to read them using the central
directory's sizes and CRC. DEFLATE descriptors are accepted by default
because DEFLATE marks its own stream boundary.

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

**Open question.** Should framing reject repeated destinations even when their
order agrees? Under the current rule, a validator and a consumer can look up
the same name successfully and get different bytes. [Current duplicate policy](SECURITY.md#zip-archives).

## 3. Creator systems and symlink mode bits

With `0120777` in the upper 16 external attribute bits and `target` in the
payload, changing the creator system changes what readers extract.

| Creator system | `zip-codec` | Apple's Info-ZIP `unzip` | Seekable libarchive |
| --- | --- | --- | --- |
| OpenVMS (2), Atari ST (5), BeOS (16) | File containing `target` | Symlink to `target` | File containing `target` |
| Darwin (19) | Symlink to `target` | File containing `target` | File containing `target` |

**Open question.** Which creator systems can we accept with symlink mode bits?
APPNOTE §4.4.15 leaves the meaning of external attributes to the creator
system. [Attribute interpretation](crates/zip-framing/src/kind.rs).

## 4. Unix symlinks in streaming readers

Our encoder puts a Unix symlink's mode in the central directory and its target
in the payload. Given a symlink produced by the encoder, macOS `bsdtar`
created a symlink when reading from a file. Reading from a pipe, it created a
regular file containing the target text. Both extractions succeeded.

**Open question.** Does the agreement requirement include streaming readers
for member types? That decision affects the symlinks we write ourselves.
[Writer conventions](crates/zip-codec/APPNOTE.md#writer-conventions).

## 5. Info-ZIP strips version suffixes

Our encoder accepts `config` containing `FIRST` and `config;1` containing
`LAST`. Our default extractor writes both. On the same filesystem, Apple's
Info-ZIP `unzip -o` writes only `config`, containing `LAST`. It also strips
a trailing bare `;` and preserves `;1x`.

**Open question.** Should ZIP reading and writing reject a final filename
component ending in a semicolon followed by zero or more ASCII digits?

## 6. AppleDouble sidecars

Given `ordinary` and `__MACOSX/._ordinary`, `zip-codec` exposes two files.
On macOS, seekable libarchive 3.8.10 exposes only `ordinary` and attaches the
sidecar's 46 bytes as metadata. Its streaming reader exposes both files.
Our encoder accepts both names. [Libarchive sidecar handling](https://github.com/libarchive/libarchive/blob/v3.8.10/libarchive/archive_read_support_format_zip.c#L4501-L4556).

**Open question.** Should we reject AppleDouble sidecar names under
`__MACOSX/` on read and write?

## 7. Conflicting timestamps and ownership across extra fields

With `ExtraFieldPolicy::AllowListed`, each header can contain the same pair
of fields with different values for the same property. With modification time
in both PKWARE UNIX (`0x000d`) and Info-ZIP extended timestamp (`0x5455`),
Java reported 2021-01-01 and libarchive reported 2000-01-01 for the same
bytes. With ownership in both `0x000d` and `0x7875`, reversing field order
changed libarchive's UID/GID from 50/51 to 42/43. The default ZIP64-only
policy rejects these fields.

**Open question.** Should the opt-in policy require agreement on overlapping
values across field IDs? The common `0x5455` and `0x7875` pair carries
different properties. [Extra-field policy](crates/zip-codec/APPNOTE.md#member-extra-fields).

## 8. Invalid DOS dates

Framing accepts 2024-02-31 when both headers contain that date. Python
exposes the tuple `(2024, 2, 31, 0, 0, 0)`. Java reports 2024-03-02.
APPNOTE §4.4.6 specifies the MS-DOS date and time format.

**Open question.** Should framing validate the calendar date and clock fields
as well as checking agreement between headers?

## 9. Member comments with the UTF-8 flag clear

Framing accepts the member-comment bytes `c3 a9` with general purpose bit 11
clear. Java reads them as `é` with its UTF-8 default and as `├⌐` with
IBM437 selected. Setting bit 11 made both reads return `é`. APPNOTE
Appendix D.2 applies the encoding flag to both names and member comments.

**Open question.** Should member comments follow the filename rule that
non-ASCII text requires bit 11? [Current comment policy](SECURITY.md#zip-archives).

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
