# ZIP implementation

## Scope and decisions

- Target: PKWARE APPNOTE 6.3.3, stored and DEFLATE, UTF-8 paths, safe Rust,
  asynchronous seekable input, and `archive-trait` construction/extraction.
- Reject encryption, signatures, patched data, multi-volume archives, and
  inconsistent redundant records. The user also approved rejecting unaccounted
  bytes (including SFX prefixes/padding) and ZIP64 version-2 directories.
- `zip-framing` owns records, ZIP64, descriptors, and index consistency.
  `zip-codec` owns payload compression/integrity and format-neutral adapters.
- Only new runtime dependency: `flate2`, with defaults disabled and `zlib-rs`.
- Resource limits are checked before allocation/decompression. Dropped payloads
  are drained and checked before advancing; interrupted operations fail closed.

## Stack

1. `ww/zip-framing`: bounded indexing and physical record validation.
2. Planned: ZIP decoding and `Archive` integration.
3. Planned: ZIP encoding and `ArchiveBuilder` integration.
4. Planned: interoperability, adversarial coverage, and security documentation.

## Verification / remaining work

- Read CONTRIBUTING.md, archive-trait contracts, tar implementations/tests,
  and APPNOTE sections 4, 7.3, and appendices C/D.
- Framing implemented: bounded EOCD lookup, ZIP64, UTF-8/Unicode-field agreement,
  local/central consistency, descriptors, and complete nonoverlapping coverage.
- `cargo test -p zip-framing --test index`: 7 tests passed, including table-driven
  field mutations and every truncation of classic/ZIP64 descriptor fixtures.
- Next: payload decoding, integrity checks, lending iteration, random access.
