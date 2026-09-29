# ZIP implementation

## Sparse ZIP access

- User approved buffering and lazy local-header validation for HTTP range inputs.
- `ww/zip-index` builds on the merged framing layer in `ww/zip-codec`; it belongs
  below decoder PR #123. Directory metadata and checked entries are distinct.
- `Index::entry` resolves and caches one member; `validate_all` retains the full
  metadata-validation path. Limits charge local metadata only after success.
- Source reads use bounded windows: 64 KiB for directory records and 4 KiB for
  selected local records. Declared record spans support explicit prefetching.
- Framing tests: 16 pass, including a 2,000-member read-count test, deferred
  local corruption, cached resolution, and metadata-budget retry behavior.
- Decoder integration: `ZipArchive::member` resolves local records on demand;
  `validate_all` checks all metadata and member kinds. `reader_mut().await` drains
  the active payload before exposing the source for prefetching.
- Decoder tests cover cancellation in payload, local resolution, full validation,
  and source lending, plus poisoned local failures and preserved drain checks.
- Remaining: documentation, full-stack checks, and stack push.

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
2. `ww/zip-decode`: ZIP decoding and `Archive` integration.
3. Planned: ZIP encoding and `ArchiveBuilder` integration.
4. Planned: interoperability, adversarial coverage, and security documentation.

## Verification / remaining work

- Read CONTRIBUTING.md, archive-trait contracts, tar implementations/tests,
  and APPNOTE sections 4, 7.3, and appendices C/D.
- Framing implemented: bounded EOCD lookup, ZIP64, UTF-8/Unicode-field agreement,
  local/central consistency, descriptors, and complete nonoverlapping coverage.
- `cargo test -p zip-framing --test index`: 7 tests passed, including table-driven
  field mutations and every truncation of classic/ZIP64 descriptor fixtures.
- Decoding implemented: raw DEFLATE via zlib-rs, CRC/exact-size/exact-stream
  checks, 64 KiB processing, poisoned cancellation, lending/random access.
- `cargo test -p zip-codec --test decode`: 6 tests passed against reproducible
  Python fixtures, corruption, size lies, trailing streams, and partial-I/O
  cancellation.
- Next: audit Unix extra-field link metadata, then encoding.
