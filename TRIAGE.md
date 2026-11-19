# ZIP and extraction triage

Five findings from reviewing `ww/zip-codec` at `9292997` against
`6759246`. The reproductions used the default policies on macOS arm64.
Record each decision and its child PR under the corresponding finding.

## 1. ZIP extraction retains superseded symlink targets (high)

A 159,849-byte ZIP contained 1,024 DEFLATE symlinks named `p`, each with a
target of 65,535 repeated `x` bytes, followed by a regular file named `p`
containing `final`. Extraction succeeded with a peak RSS of 134 MiB. The
five-byte file was the only entry on disk.

ZIP stores these targets in member payloads. The reader bounds each decoded
target at 65,535 bytes and charges it against the 64 GiB total payload limit.
The extractor keeps the original and normalized target in each `PendingSymlink`
until it has read the archive. An overwrite updates the index in the path tree
and leaves the old strings allocated. The 8 MiB resolution budget takes effect
at finalization, after allocation, and skips superseded links. At the default
entry limit, 99,999 such links and one file would require about 12 GiB for
target strings alone. This figure is an extrapolation from the record layout.
[ZIP target decoding](crates/zip-codec/src/decode.rs#L233) ·
[Reservation at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L464) ·
[Finalization at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L549)

**Decision.** The shared extractor limits deferred symlink records and their
string allocations to 8 MiB per archive. Each record counts even if a later
member overwrites it. This lets the extractor keep its append-only vector and
check one byte counter before reserving a link. The ZIP above now fails at
the 64th symlink with peak RSS of 12.5 MiB. A ZIP with 63 such links followed
by the regular file extracts successfully.
[PR #376](https://github.com/astral-sh/astral-codec/pull/376)

## 2. Failed extraction can leave an escaping symlink (out of scope)

Start with an empty directory `pivot` and a symlink `ambient -> pivot/../outside`
inside the destination. Place a sentinel named `outside` beside the destination.
Extract two symlinks in order, `alias -> ambient` and `pivot -> .`.

Reserving the second link removes the empty directory. The filesystem check
then encounters a missing `pivot` while following `ambient` and accepts
`alias` as dangling. Once both links exist, `pivot` resolves to the destination
itself, so the following `..` reaches its parent. The final check returns
`PermissionDenied` and leaves both links on disk. Opening `alias` after the
error reads the sentinel. This reproduced with tar and ZIP. At `6759246`,
tar extraction rejected the pre-existing link before creating `alias`.
[Target inspection at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L982) ·
[Validation before creation](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L553) ·
[Final check](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L632)

**Decision.** Close as out of scope. The extractor made all filesystem
changes inside the destination and reported the escape as an error. The
caller read the sentinel by following `alias` in the partial destination
after that error. The security model guarantees containment of symlink
targets when extraction succeeds, and `extract_in` documents that a failure
can leave a partial destination. [Security model](SECURITY.md#archive-trait) ·
[`extract_in` contract](crates/archive-trait/src/lib.rs#L293)

## 3. Implicit parent creation copies every path prefix (medium)

For a small file named `a/b/c/file`, `queue_parents` constructs separate paths
for `a`, `a/b`, and `a/b/c`. With *n* one-character parents, the prefixes
contain *n*² bytes in total. Flushing every 64 operations bounds the number
held at once. Each prefix still gets constructed during extraction.
[Parent batching at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/root.rs#L755) ·
[Path construction at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/archive-trait/src/extract/path.rs#L95)

For one empty PAX file under 1,000 one-character parents, instrumenting
`NormalizedPath::to_path_buf` counted 2,004 bytes of path text at `6759246`
and 1,002,004 bytes at `9292997`. At 500 parents the counts were 1,004 and
251,004 bytes respectively. Both codecs use this path through the extractor.

**Decision.** Share the buffered file's native path with its queued parents.
Each parent stores the byte offset of its trailing separator. The worker
borrows the leaf when it has a cached parent handle and the full prefix when
it uses the root handle. Repeating the PAX reproduction on macOS arm64,
including the shared path allocation in the count, gave 1,004 bytes at
500 parents and 2,004 bytes at 1,000 parents.
[PR #377](https://github.com/astral-sh/astral-codec/pull/377)

## 4. Named lookup and extraction disagree on duplicate destinations (medium, deferred)

For two members named `config` containing `first` and `last` in that order,
`validate_all()` succeeds, Go's `archive/zip.Reader.Open("config")` reads
`first`, and `extract_in` writes `last`. The ZIP reader permits duplicates
when the local headers and central directory agree on their relative order.
[Destination order check](crates/zip-framing/src/index.rs#L574)

The default ZIP builder also accepts `config` followed by `./config` because
its collision check compares literal components. Python's
`ZipFile.read("config")` reads `first` from the resulting archive, and
`extract_in` writes `last` to `config`. A consumer that verifies a member by
name before installation can therefore verify different bytes from those it
installs. [Builder collision check](crates/archive-trait/src/builder.rs#L964)

**Decision.** Defer until we know how often ZIP archives on PyPI contain
duplicate member names or distinct names that normalize to the same destination.
Use those counts to decide whether the ZIP reader and builder should reject
either case and whether rejection should be the default.

## 5. A local directory header bypasses the version 1.0 opt-in (low)

An empty Stored member named `dir/` passes `validate_all()` and member
selection with local extraction version 1.0 and central version 2.0. Swapping
the versions produces `Version1Directory`. APPNOTE §4.4.3.2 sets the minimum
directory version at 2.0, and `allow_version_1_directories` defaults to false.
The parser checks the compression method's minimum in each header. The
subsequent check for the resolved member kind receives only the central version.
[Version check at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/zip-framing/src/index.rs#L372) ·
[Kind-specific minimum at review](https://github.com/astral-sh/astral-codec/blob/9292997/crates/zip-framing/src/kind.rs#L120) ·
[PKWARE APPNOTE 6.3.9](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT)

**Decision.** Check each header's extraction version against the resolved
member kind before caching the entry. Directories require at least 2.0 in
each header, with an opt-in for 1.0. DOS volume labels require at least 1.1
in each header. The central header can declare a higher version when its
local-header offset needs ZIP64.
[PR #378](https://github.com/astral-sh/astral-codec/pull/378)
