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
- When extraction succeeds with the default policy, resolving the target of any extracted
  symbolic link must stay within the extraction root. The target may be missing.
- By default, an attacker should never be able to cause a hang during decoding, such as
  via symlink loops. A user must explicitly opt into a non-default extraction policy
  to allow this.
- If a tar stream is ambiguous (i.e. not well-formed under pax or GNU rules), tar-codec
  should reject it rather than picking an arbitrary interpretation.
- All asynchronous consumer-facing APIs should be cancellation safe. In other words,
  dropping a future produced by a direct-use API should _never_ result in state corruption that
  breaks our parsing or encoding properties.
  If you drop an `Archive::extract_in` future, pending filesystem operations can still
  modify the extraction root. Retry a cancelled extraction in a fresh directory.
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
- Differentials caused purely by OS- or filesystem-specific behaviors, provided
  extraction and symbolic-link resolution stay within the extraction root.
  For example, case folding or Unicode normalization may cause two member names
  to refer to the same file.
- Panics that are caused by platform limitations, e.g. Rust's allocator choosing to
  panic when failing to reserve adequate capacity on smaller address spaces.
