# ZIP implementation

## Scope and decisions

- PKWARE APPNOTE 6.3.3; stored/DEFLATE, UTF-8 paths/comments, safe Rust,
  asynchronous seekable input, and `archive-trait` construction/extraction.
- Reject encryption, signatures, patched data, multi-volume archives, and
  inconsistent redundant records. Approved exclusions also include unaccounted
  bytes (SFX/padding) and ZIP64 version-2 directories.
- Opening checks end records and central metadata. Local checks are deferred
  until selection or `validate_all`; payload integrity is checked on consumption.
- Directory reads use 64 KiB windows; selected local records use 4 KiB windows
  bounded by their declared spans. The source must remain immutable.
- `reader_mut().await` drains an active payload before lending the source for
  explicit prefetching/seeking. HTTP cache policy remains caller-controlled.
- A private decoder operation guard poisons before I/O; consuming `commit`
  restores usability. Member preparation finishes before lending a payload.
- Writing uses ZIP64 throughout, including small archives. The pending encoder
  requires seekable output and backpatches local headers without descriptors.
- Per-file settings use `ArchiveBuilder::FileOptions` and
  `Builder::add_file_with_options`. Plain `add_file` and recursive builds use
  default options; `EntryMetadata` remains format-neutral.
- `ZipFileOptions::compression` overrides the method for one nonempty file.
  Default options inherit the encoder's method; empty files remain stored.
- Only added runtime dependency: `flate2` with the `zlib-rs` backend.

## Merged-layer audit

Reviewed the merged framing, index, extras, decoder, payload, and serialization
implementations, their integration tests and fixtures, and crate dependencies.
Compared ownership boundaries with tar-codec and archive-trait contracts.

- Framing owns record bounds, ZIP64 resolution, redundant metadata agreement,
  and budgets. `CentralDirectoryEntry` remains distinct from checked `Entry`;
  resolved extras and cached local metadata are published only after successful checks.
- The codec owns member projection, decompression, CRC/decoded-size checks,
  lending, draining, and poisoning. Extraction policy stays in `archive-trait`.
- Serialization uses validated `PendingMember` and `CompletedMember` states to
  emit consistent local/central records. Streaming and I/O belong to the encoder.
- Cleanup: move buffered reads onto `RecordReader`; return borrowed validated
  filenames and allocate only the directory's retained name. Public APIs and
  accepted/rejected input behavior are unchanged.

Test ownership after cleanup:

- Framing index tests own layout permutations, malformed records, metadata
  limits, sparse access, cache publication, and retry accounting (16 tests).
- Framing write tests own construction validation and record serialization
  round-trips (3 tests). These exercise the writer's independent entry points.
- Decoder tests own projection, integrity, navigation, poisoning and buffer
  contracts (10 tests). Keep all six Python layouts in the interoperability test;
  seeking and corrupt-payload workflows use one fixture per compression method.
- EOF assertions live in one focused test, covering first/repeated EOF for
  nonempty, empty, and encoded-empty payloads, plus bounded chunk requests.
  The separate empty-directory test covers validation during member selection.
- Retain failure/cancellation cases for each public operation: they verify
  distinct guard/drain paths. Framing rejects malformed metadata; codec tests
  additionally verify that those errors poison the lending archive.
- Keep one extraction smoke test. Filesystem containment and link-policy cases
  remain owned by `archive-trait`, rather than repeated for ZIP.

## Stack

- Development base `ww/zip-codec` is at `c6eafe4`: #122, #130, #123, #127, and
  cleanup #132 merged.
- Pending feature stack #131: #124 (`ww/zip-encode`) then #125 (`ww/zip-docs`).
- #133 (`ww/archive-file-options`) adds the shared API and adapts format writers;
  #134 (`ww/zip-file-options`) adds ZIP compression overrides and a mixed-method
  test above #125.

## Verification

- `cargo test -p zip-framing -p zip-codec --tests`: 29 tests pass. Rechecked the
  empty-directory test after removing its redundant empty-file assertion.
- Existing checks cover buffering/read counts, retry budgets, exact record
  coverage, unsupported features, UTF-8, ZIP64/descriptors, payload integrity,
  cancellation, interoperability, and extraction.
- Workspace clippy, formatting, and ZIP documentation checks pass with warnings
  denied. The cleanup adds no dependencies, unsafe code, or public API changes.
- File-options plumbing passes all 13 shared builder integration tests, 5
  builder unit tests, and 10 tar encoder tests. Existing tests now check option
  forwarding, collision rejection, and defaults for buffered and streamed
  recursive files.
- All 6 ZIP encoder tests pass. The new table-driven case checks mixed methods,
  inherited defaults after overrides, and stored empty files with both encoder
  defaults. Shared, tar, and ZIP docs build with warnings denied; workspace
  clippy and formatting pass. No dependencies changed.
