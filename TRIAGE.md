# ZIP correctness review

Reviewed `ww/zip-codec` at `ced194eb524480495526cf9d57294d5ffa4a277d`, including the shared builder and extractor used by the ZIP APIs. The priority for extraction is checking symlink target ownership after publishing deferred links. Finding 5 shows how a case-insensitive volume can bypass the default policy.

A valid archive that fails closed is a compatibility problem. A successful interpretation can be a differential without qualifying as a vulnerability, particularly when APPNOTE supports that interpretation or the difference comes solely from the destination filesystem and stays inside the root. [Security model](SECURITY.md)

## End records and ZIP64

### 1. A Stored payload can make the encoder's output unreadable (accepted)

With an empty seekable output, use `ZipEncoder::with_compression(CompressionMethod::Stored)`. Add a single regular file named `a` containing these 22 bytes and finish the builder.

```python
payload = b"PK\x05\x06" + bytes(16) + (173).to_bytes(2, "little")
```

The resulting ZIP is 246 bytes. The payload at offset 51 resembles a classic end-of-central-directory record (EOCD) with a comment reaching EOF. The real EOCD starts at 224. The apparent record advertises an empty directory at offset zero, which cannot end at 51. Only the real record accounts for the local header, payload, central directory, ZIP64 end and locator. Default `ZipArchive::open` reports “ambiguous end records” at 224. Python returns the original 22 bytes, and Info-ZIP, bsdtar and 7-Zip read the archive successfully.

We accept this round-trip failure. Other readers can use different rules to locate the end record, so `find_end` deliberately rejects two candidates whose comment lengths both reach EOF, even when our directory checks could distinguish them. [End-record search](crates/zip-framing/src/index.rs#L542)

### 2. Central-directory bytes can masquerade as a ZIP64 locator

Write a classic ZIP containing one Stored byte and use the 20-byte filename `b"PK\x06\x07" + b"A" * 16`, with no extras or comments. The last 20 bytes of the central directory are the filename. The reader treats them as a ZIP64 locator and reports “unsupported ZIP multiple volumes.” This occurs during indexing, before any extraction filename policy. A printable name and a 20-byte member comment with the same prefix reproduce it when member comments are enabled.

Python also rejects the filename case. Info-ZIP, bsdtar and 7-Zip accept it. The classic count, size and offset describe the entire central directory through the EOCD, including the putative locator. Distinguish this layout from a malformed ZIP64 archive by proving the complete classic directory extent. Merely ignoring every broken locator could admit contradictory end records. [Locator detection](crates/zip-framing/src/index.rs#L594)

### 3. An exact classic count of 65,535 is treated as an unresolved sentinel

Using Python's default ZIP64 settings, write 65,535 empty, uniquely named Stored files. Python emits a classic single-disk end record with both counts equal to `0xffff` and no locator. Python reads every member, and `unzip -tqq` succeeds. Our default index rejects the archive with “ZIP64 sentinel without locator.” The same generator passes here at 65,534 (classic) and 65,536 (ZIP64). All three fit the default entry and metadata limits.

This is a compatibility boundary in the documented sentinel policy. A literal count of 65,535 can be established by counting the complete central records and matching the directory extent. A count mismatch, missing records, or a truncated ZIP64 archive should still fail. The reproducer exercises the count boundary only. [Classic count handling](crates/zip-framing/src/index.rs#L421) · [Current policy](crates/zip-codec/APPNOTE.md#writer-conventions) · [APPNOTE §§4.4.1.4, 4.4.21–24](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)

### 4. A central-only ZIP64 offset can raise the version independently

Python can produce this layout with two tiny files. The threshold override makes its normal large-offset writer path reproducible without a multi-gigabyte fixture.

```python
import zipfile

zipfile.ZIP64_LIMIT = 100
with zipfile.ZipFile("offset.zip", "w") as archive:
    archive.writestr("a" * 75, b"0")
    archive.writestr("b", b"1")
```

The second local header starts at 106 and declares version 2.0. Its sizes fit in classic fields. The central header declares version 4.5 and uses a ZIP64 extra for the local-header offset. There is no corresponding offset field in the local header. Indexing succeeds, but selecting that member or calling `validate_all` fails at 106 with “local and central headers disagree.” Python, Info-ZIP, bsdtar and 7-Zip read both files.

The reader already checks each header's feature minimum, then compares the entire common header including its version. Consider allowing this specific pair when the central-only ZIP64 field accounts for the difference. Keep the independent minimum-version checks and ordinary mismatch rejection. This is an interoperability finding with a concrete producer. [Header comparison](crates/zip-framing/src/index/entry.rs#L378) · [APPNOTE §§4.4.3, 4.5.3](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)

## Extraction and member identity

### 5. Deferred symlinks can reach pre-existing targets under the default policy

On a case-insensitive macOS volume, put a regular file named `ambient` in the extraction root. Create two ordinary ZIP symlink members (Unix creator, mode `0120777`, Stored target bytes) in this order.

| Member | Target |
| --- | --- |
| `Gate` | `.` |
| `link` | `gate/ambient` |

Default extraction succeeds. Opening `link` reads the pre-existing `ambient` file. Change just the target to `Gate/ambient` or `ambient` and extraction rejects it with “ambient target is not allowed.” No concurrent filesystem mutation is involved.

The pre-publication graph compares archive path components by spelling. At that stage `gate` is absent on disk, so the target qualifies as missing, which defaults allow. Once `Gate` is published the filesystem resolves the alternate spelling. The final capability-relative check only asks whether the target exists. Repeat the ownership and target-kind check against the published graph or reject an alias whose provenance cannot be established. A regression needs a case-insensitive filesystem and a pre-existing file.

The observed effect stays inside the extraction root and falls within the security model's filesystem-specific exclusion. In controls with the same capitalization trick, an ambient symlink leading outside the root failed the final capability check, and an ambient cycle produced a loop error. [Symlink validation and publication](crates/archive-trait/src/extract/root.rs#L562) · [Extraction guarantees](SECURITY.md#archive-trait)

### 6. Builder collision tracking uses a different name from the ZIP writer

On one new `ZipEncoder::builder()`, call `add_directory("d")`, then `add_directory("d/")`, then finish. Both calls succeed. The reverse order also succeeds. Python's `infolist()` shows two byte-identical names, `["d/", "d/"]`. The shared builder reserves the literal slash-separated components, including an empty final component. The ZIP writer independently adds a slash to a directory name that lacks one.

The same distinction matters for different payloads. Add files `a/b` containing `x` and `a/./b` containing `y`. Both survive in the archive. Default extraction writes one file containing `y`. Directory duplication is directly introduced by the ZIP encoder's spelling rule. The file example also involves the shared builder's deliberate preservation of textual components. A separate portability boundary is that the default builder accepts a file named `../x`, while the default extractor rejects its parent component. Use the serialized directory name for collision checks, and decide explicitly whether the builder permits multiple spellings of one extraction destination. [Builder reservations](crates/archive-trait/src/builder.rs#L900) · [ZIP directory writer](crates/zip-codec/src/encode.rs#L327) · [Extraction path normalization](crates/archive-trait/src/extract/path.rs#L163)

## Metadata and resource limits

### 7. Identical ownership values can fail the allowlisted extra-field check

Use Info-ZIP field `0x7875` with these two version-1 bodies on an otherwise ordinary empty file. Hex bytes exclude the four-byte extra-field header.

| Header | Field body | UID | GID |
| --- | --- | ---: | ---: |
| Local | `01 01 01 01 02` | 1 | 2 |
| Central | `01 02 01 00 02 02 00` | 1 | 2 |

Under `ExtraFieldPolicy::AllowListed`, indexing succeeds and `validate_all` rejects the member because the local and central bytes differ. Info-ZIP and 7-Zip test it successfully, and seekable bsdtar reports UID 1 and GID 2. The integers are little-endian and each carries its own width. The parser already strips high zero bytes when comparing ownership across field types. Use the same value comparison across these two copies while retaining layout checks and rejecting genuinely different IDs. [Extra-field reconciliation](crates/zip-framing/src/extra.rs#L261) · [Supported layouts](crates/zip-codec/APPNOTE.md#member-extra-fields)

### 8. The same metadata limit admits writer output that the reader rejects

With `Limits { metadata_size: 0, ..Limits::default() }`, finish an empty ZIP encoder. It succeeds and produces 98 bytes. Opening those bytes with the same limits fails. The encoder charges only local and central headers. The reader also charges the 56-byte ZIP64 end record. The discrepancy is constant for this encoder and matters at any tight boundary. The behavior is documented on `Limits`, but shared limits cannot currently guarantee a round trip.

The classic EOCD, its archive comment, and the ZIP64 locator are outside the reader's metadata charge. An empty classic ZIP with a 65,535-byte ASCII comment opens at a zero metadata limit. The archive-length limit still applies. If round trips are intended, charge the ZIP64 end consistently on both sides. Independently specify whether a caller's metadata budget should include archive comments. [Limit contract](crates/zip-framing/src/budget.rs#L12) · [Writer finalization](crates/zip-codec/src/encode.rs#L260) · [Reader accounting](crates/zip-framing/src/index.rs#L594)

### 9. Low-level framing can serialize an impossible DEFLATE size pair

For a regular DEFLATE member, `PendingMember::finish(crc32(b"x"), 0, 1, 0)` accepts a zero-byte compressed stream with a one-byte decoded length. Both headers can then be serialized. The index and full metadata validation accept that size tuple. Reading the payload fails with “truncated or stalled DEFLATE stream.” Compressed length zero cannot encode nonempty output, which is knowable from the headers alone. Reject the tuple in the framing writer and reader. The streaming encoder derives these lengths from the actual compressor, and a consumer that drains the payload already fails closed. [Writer size checks](crates/zip-framing/src/write.rs#L80) · [Central metadata checks](crates/zip-framing/src/index/entry.rs#L169)

## Previously documented differences and limits of the supported subset

- **Record-oriented files.** Internal attribute bit 1 (`0x0002`) declares four-byte record-length controls. A Stored file with this bit and the single byte `ff` passes default full decoding despite being too short for a length word. A payload `01 00 00 00 78` yields all five bytes. Reject the bit if the codec cannot validate the record structure. This is a concrete malformed-input consequence of an existing open policy question. [Compatibility notes](crates/zip-codec/APPNOTE.md#open-policy-questions) · [APPNOTE §4.4.14.2](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)
- **Kind and filename interpretation.** A slashless, zero-length `d` with Unix directory mode is a directory here and in seekable bsdtar, but a file to Python's `ZipInfo.is_dir()` and streaming bsdtar. Version suffixes also affect the resulting filesystem. With physical order `config=A`, `config;1=B` and reversed central order, Info-ZIP's normal overwrite extraction leaves just `config=A`. Our archive API and seekable bsdtar expose two distinct names. Streamed symlinks and AppleDouble sidecars are further known producer/consumer differences. [Compatibility notes](crates/zip-codec/APPNOTE.md#writer-conventions) · [Directory projection](crates/zip-framing/src/kind.rs#L47)
- **Legacy names.** A CRC-correct Unicode Path extra (`0x7075`) accompanying ordinary CP437 filename bytes `63 61 66 82` can unambiguously describe `café`. Even with allowlisted extras, the ordinary bytes must independently pass the UTF-8 and flag checks, so indexing fails. bsdtar extracts the Unicode name. Supporting this layout would require decoding the ordinary name under a defined legacy encoding and validating the extra against the original bytes. The current policy deliberately accepts a narrower set. [Filename checks](crates/zip-framing/src/record.rs#L145) · [APPNOTE §4.6.9 and Appendix D](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)
- **Invalid DOS timestamps.** Matching DOS time and date words `0xffff` and `0x01ff` pass full default decoding. They encode, among other out-of-range values, hour 31 and month 15. The common-header comparison catches disagreement but does not validate either value. The codec does not apply these timestamps during extraction. This is malformed metadata acceptance if strict MS-DOS time conformance is intended. [Common header parsing](crates/zip-framing/src/record.rs#L315) · [APPNOTE §4.4.6](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)
- **Version and header-size edges.** A Stored file with matching extraction versions 1.9 passes despite the unlisted version. A 65,535-byte ASCII filename passes the builder's field-width check, but its central header plus ZIP64 extra exceeds the 65,535-byte total recommended by APPNOTE. Python and bsdtar read the long header, Info-ZIP warns about truncation, and 7-Zip rejects the archive. The recommendation affects writer portability. [Version policy](crates/zip-codec/APPNOTE.md#open-policy-questions) · [Filename size check](crates/zip-framing/src/write.rs#L42) · [APPNOTE §§4.4.3.2, 4.4.10–12](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT)

## Compatibility with other writers

The following small producer tests add context to the six Python wheels. Each archive contained an empty file and a nonempty file or, in the Go case, an explicit directory and a DEFLATE file. “Allowlisted” here enables the supported optional fields and descriptors.

| Producer | Default | Allowlisted | Cause or control |
| --- | --- | --- | --- |
| Go 1.27.3, `archive/zip.Writer.Create` | Reads both members | Reads both members | Streaming DEFLATE and ordinary directory |
| macOS `ditto -c -k --norsrc --noextattr` | Rejects `0x5855` | Reads both files | Original Info-ZIP UNIX extra |
| Info-ZIP `zip -r` including directories | Rejects `0x5455` | Rejects directory version 1.0 | `zip -X -r` isolates the version failure even with default settings. Omitting directory entries with `-D` passes with allowlisted extras. |
| libarchive 3.7.4, `bsdtar --format zip -cf` | Rejects `0x7875` | Rejects `0x5455` copy agreement | Local flags are 7, central flags are 1, and the modification times agree. Python, Info-ZIP, bsdtar and 7-Zip read the file data. |
| OpenJDK 27 `jar --create` | Rejects `0xcafe` | Rejects `0xcafe` | The tool emits its JAR marker even with `--no-manifest`. Unknown extras are deliberately outside the allowlist. |

The two recursive archivers reveal practical costs of strictness. APPNOTE specifies 2.0 for directories. The Info-ZIP timestamp specification says both copies' flags describe the timestamps in the *local* field, even though the central field stores only modification time. The reader enforces both rules. Treat support for these producer conventions as a compatibility decision and preserve rejection of conflicting modification times. [APPNOTE §4.4.3.2](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT) · [Info-ZIP timestamp format](https://github.com/LuaDist/zip/blob/master/proginfo/extrafld.txt#L746-L778)

## Verification and scope

- Ran `cargo test --locked -p zip-framing -p zip-codec -p archive-trait --tests`. Reviewed physical coverage, reordered and overlapping entries, shadow end records, descriptor widths/signatures, extra-field reconciliation, kind projection, payload integrity, cancellation, encoder finalization, and the shared builder and extractor.
- Exercised default extraction against a sentinel outside the root. A `../sentinel` member and a file under a pre-existing parent symlink to `..` were rejected. Replacing a leaf symlink or hard link to the sentinel created a new file inside the root. The outside sentinel retained its original contents in all four cases.
- Compared strict raw DEFLATE decoding with zlib for 584 whole ZIP fixtures across four source payloads, four compression levels, bit flips, truncations, trailing bytes and concatenated streams. With chunk sizes 256, 4,096 and 65,536, both accepted the same 102 cases each time. A 120-case subset also agreed for one-byte chunks. Independently flipping each of eight bits at eleven local-header/name offsets gave 88 rejections with the central record unchanged.
- Opened, validated and drained six wheels with default settings and again with optional fields enabled. Member counts, total file bytes and CRC-32 over concatenated file data in directory order agreed with Python for all 6,545 entries. The wheels were botocore 1.35.60, cryptography 43.0.3, Django 5.1.3, NumPy 2.1.3, requests 2.32.3 and urllib3 2.2.3.
- Local comparisons used Python 3.15.2, Info-ZIP UnZip 6.00, bsdtar backed by libarchive 3.7.4, and p7zip 17.05 on arm64 macOS. Counts and address boundaries are independent. The offset fixture exercised the 64-bit format by lowering the producer's threshold. Native Windows and Linux extraction and physical multi-gigabyte payloads were outside this run.
- `ZipArchive::open` checks the directory. `validate_all` additionally checks local framing and projection. Payload CRC, exact DEFLATE consumption, and agreement of symlink target bytes require member access and draining. The negative payload tests exercised that last step. Findings above distinguish these stages. The ZIP subset intentionally excludes encryption, multiple volumes, and arbitrary unknown extra fields. Stored data descriptors and non-default symlink-host interpretations require explicit opt-in. [Architecture](CONTRIBUTING.md#zip-archives) · [ZIP compatibility](crates/zip-codec/APPNOTE.md)
