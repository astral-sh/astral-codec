# Security policy and model

## Security policy

See our [organization-wide security policy](https://github.com/astral-sh/.github/blob/main/SECURITY.md)
for how to report issues in astral-codec.

## Security model

### Tar archives

tar-codec is intended to be resilient to many common differentials when parsing tar streams.

General properties:

- By default, an attacker should never be able to extract files or other stream contents
  outside of the extraction root. A user must explicitly opt into a non-default extraction
  policy to allow this.
- By default, an attacker should never be able to cause a hang during decoding, such as
  via symlink loops. A user must explicitly opt into a non-default extraction policy
  to allow this.
- If a tar stream is ambiguous (i.e. not well-formed under pax or GNU rules), tar-codec
  should reject it rather than picking an arbitrary interpretation.
- All asynchronous consumer-facing APIs should be cancellation safe. In other words,
  dropping a future produced by a direct-use API should _never_ result in state corruption that
  breaks our parsing or encoding properties.
- All consumer-facing APIs should be deadlock safe.
- Encoding should always produce a valid, unambiguous, pax-only tar.
- By default, both encoding and decoding should remain linear in time and memory with respect
  to their input. Enabling non-default policies during encoding and decoding may change this
  property.

The format-writing methods on `ArchiveBuilder` are implementation hooks, not
direct-use APIs. Archive construction must go through `Builder` for policy,
collision-tracking, poisoning, and cancellation-safety guarantees.

In addition, the following are *never* considered security vulnerabilities
within tar-codec:

- Race conditions during extraction that are caused by concurrent, external
  mutations of the extraction root. tar-codec assumes that it has unique write
  access to the extraction root.
- Race conditions during archive construction that are caused by concurrent,
  external mutations of the file(s) being archived. tar-codec assumes that it has
  unique read access to any requested files at the time of archival.
- Differentials where tar-codec fails closed. Failing closed _may_ be a logical
  bug, but it is never a security-relevant differential.
- Differentials where tar-codec picks a different interpretation of a tar stream,
  _if_ that interpretation is substantiated by the pax or GNU specification. If the
  other implementation fails to follow the relevant specification, the
  security-relevant differential is there instead.
- Differentials that are caused purely by OS- or filesystem-specific behaviors.
  For example, a filesystem that performs unicode path normalization
  may coalesce multiple members into a single path on disk, but this is not a
  concern within tar-codec itself.

### ZIP archives

ZIP framing targets [PKWARE APPNOTE 6.3.3](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT).
The supported profile includes stored and DEFLATE members, classic and ZIP64
version-1 directories, and signed or unsigned data descriptors. Encryption,
digital signatures, patched data, multi-volume archives, and ZIP64 version-2
directories are rejected. Self-extracting prefixes, padding outside records,
trailing bytes, and ambiguous end records are also rejected.

Opening an archive validates the whole index before exposing members. Local
headers, central headers, ZIP64 fields, and descriptors must agree. Payload
extents cannot overlap, refer to shared local headers, or conceal unindexed
records. Extra fields must be bounded, complete records with unique identifiers.
Unknown extensions remain opaque and do not supply effective names or file types.

Names must be UTF-8. Non-ASCII names require the UTF-8 flag; ASCII names are
accepted without it. Unicode path extra fields must have a valid CRC and agree
with the raw filename. APPNOTE Unix link metadata is interpreted, and a symbolic
link's extra-field target must agree with its payload when both are present.
Filesystem containment and configurable name/link policy remain in `archive-trait`.

Archive and member comments must be UTF-8, even without the UTF-8 flag. This
restricts binary comment data; UTF-8 alone does not exclude all embedded ZIP
records.

File contents are checked during consumption. Successful completion requires the
declared decoded size, CRC, and exact DEFLATE stream boundary. A dropped payload
is drained and checked before another member is returned. Seeking to an entry
does not validate the contents of unselected entries. Dropping the entire archive
or recovering its source likewise does not validate remaining contents.

Default budgets cap the archive at 128 GiB, entries at 100,000, local and central
metadata at 64 MiB, decoded members at 8 GiB each, and their sum at 64 GiB. End
comments have their format-defined 65,535-byte bound; ZIP64 end extensions have
an additional metadata-size bound. Payload processing uses chunks of at most
64 KiB and yields between bounded units of work. Symbolic-link targets are capped
at 65,535 bytes. Raising limits permits additional resource use. Repeated explicit
random-access reads repeat the associated work; the total-size budget describes
the indexed archive, not a cumulative quota across caller-requested rereads.

Index memory is proportional to bounded metadata and entry count. Physical-order
validation sorts member offsets in O(n log n) time. Payload work is bounded by
encoded input and decoded output, including streams that produce no output.

Read errors or cancellation poison the archive cursor. Construction uses
`archive-trait::Builder` poisoning and never seeks backward to repair partial
output. The ZIP crates forbid unsafe Rust; CRC and DEFLATE use `flate2` with its
`zlib-rs` backend. No native compression library is required.

As with tar, concurrent mutation of the input, build sources, or extraction root
is outside the threat model. Extraction may leave partial destination state after
a late failure. CRC-32 detects corruption; it does not authenticate archives.
