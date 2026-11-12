# Security policy and model

## Security policy

See our [organization-wide security policy](https://github.com/astral-sh/.github/blob/main/SECURITY.md)
for how to report issues in astral-codec.

## Security model

### General

These are properties that apply to all crates within astral-codec, regardless of the format
they target.

- All components of astral-codec are intended to be resilient to differentials when
  parsing their respective formats.
- By default, an attacker should never be able to cause a hang during decoding, such as
  via symlink loops. A user must explicitly opt into a non-default extraction policy
  to allow this.
- All asynchronous consumer-facing APIs should be cancellation safe. In other words,
  dropping a future produced by a direct-use API should _never_ result in state corruption that
  breaks our parsing or encoding properties.
- All consumer-facing APIs should be deadlock safe.

In addition, the following are **never** considered security vulnerabilities anywhere
within astral-codec:

- Differentials where the astral-codec implementation fails closed. Failing closed _may_
  be a logical bug, but it is never a security-relevant differential.
- Panics that are caused by platform limitations, e.g. Rust's allocator choosing to
  panic when failing to reserve adequate capacity on smaller address spaces.

### archive-trait

archive-trait is intended to provide safe high-level APIs for inspecting
and extracting arbitrary archive formats.

General properties:

- By default, an attacker should never be able to extract files or other stream contents
  outside of the extraction root. A user must explicitly opt into a non-default extraction
  policy to allow this.
- When extraction succeeds with the default policy, resolving the target of any extracted
  symbolic link must stay within the extraction root. The target may be missing.
- If you drop an `Archive::extract_in` future, pending filesystem operations can still
  modify the extraction root. Retry a cancelled extraction in a fresh directory.

In addition, the following are **never** considered security vulnerabilities within
archive-trait:

- Race conditions during extraction that are caused by concurrent, external
  mutations of the extraction root. tar-codec assumes that it has unique write
  access to the extraction root.
- Race conditions during archive construction that are caused by concurrent,
  external mutations of the file(s) being archived. tar-codec assumes that it has
  unique read access to any requested files at the time of archival.
- Differentials caused purely by OS- or filesystem-specific behaviors, provided
  extraction and symbolic-link resolution stay within the extraction root.
  For example, case folding or Unicode normalization may cause two member names
  to refer to the same file on some filesystems.

### tar-codec

Here, tar-codec refers to both the tar-codec and tar-framing crates.

General properties:

- If a tar stream is ambiguous (i.e. not well-formed under pax or GNU rules), tar-codec
  should reject it rather than picking an arbitrary interpretation.
- Encoding should always produce a valid, unambiguous, pax-only tar.
- By default, both encoding and decoding should remain linear in time and memory with respect
  to their input. Amplification caused solely by how the caller uses the API is out of scope.
  Enabling non-default policies during encoding and decoding may change this property.

In addition, the following are *never* considered security vulnerabilities
within tar-codec:

- Differentials where tar-codec picks a different interpretation of a tar stream,
  _if_ that interpretation is substantiated by the pax or GNU specification.

### zip-codec

Here, zip-codec refers to both the zip-codec and zip-framing crates.

General properties:

- zip-codec targets a subset of [PKWARE APPNOTE 6.3.3].
- If a ZIP is ambiguous (i.e. not well-formed), zip-codec should reject it rather than
  picking an arbitrary interpretation.
- zip-codec should reject ZIPs that contain inconsistent states, e.g. where the local file headers
  and central directory disagree.
- Encoding should always produce a valid, unambiguous ZIP.

[PKWARE APPNOTE 6.3.3]: https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.3.TXT

In addition, the following are *never* considered security vulnerabilities
within zip-codec:

- Differentials where zip-codec picks a different interpretation of a ZIP, _if_
  that interpretation is substantiated by the APPNOTE specification.