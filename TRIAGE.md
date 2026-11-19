# ZIP and extraction triage

Five open findings from reviewing `ww/zip-codec` at `9292997` against
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
[Reservation](crates/archive-trait/src/extract/root.rs#L464) ·
[Finalization](crates/archive-trait/src/extract/root.rs#L549)

**Open question.** Should the shared extractor bound the bytes retained by
live symlinks at reservation time and release their storage on overwrite?
Releasing superseded targets alone would still allow distinct names to
accumulate until finalization.

## 2. Failed extraction can leave an escaping symlink (high)

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
[Target inspection](crates/archive-trait/src/extract/root.rs#L982) ·
[Validation before creation](crates/archive-trait/src/extract/root.rs#L553) ·
[Final check](crates/archive-trait/src/extract/root.rs#L632)

**Open question.** How should validation resolve a pre-existing symlink whose
target traverses a pending archive link? In this example it needs to account
for the pending `pivot -> .` before interpreting `..` or creating `alias`.

## 3. Implicit parent creation copies every path prefix (medium)

For a small file named `a/b/c/file`, `queue_parents` constructs separate paths
for `a`, `a/b`, and `a/b/c`. With *n* one-character parents, the prefixes
contain *n*² bytes in total. Flushing every 64 operations bounds the number
held at once. Each prefix still gets constructed during extraction.
[Parent batching](crates/archive-trait/src/extract/root.rs#L755) ·
[Path construction](crates/archive-trait/src/extract/path.rs#L95)

For one empty PAX file under 1,000 one-character parents, instrumenting
`NormalizedPath::to_path_buf` counted 2,004 bytes of path text at `6759246`
and 1,002,004 bytes at `9292997`. At 500 parents the counts were 1,004 and
251,004 bytes respectively. Both codecs use this path through the extractor.

**Open question.** Can queued parents share the member path and store an end
offset for each prefix? The worker needs the leaf for a cached parent and the
full prefix for a cache miss or an error.

## 4. Named lookup and extraction disagree on duplicate destinations (medium)

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

**Open question.** Should ZIP offer a policy that rejects repeated normalized
destinations? If so, should the reader and builder enforce it by default?

## 5. A local directory header bypasses the version 1.0 opt-in (low)

An empty Stored member named `dir/` passes `validate_all()` and member
selection with local extraction version 1.0 and central version 2.0. Swapping
the versions produces `Version1Directory`. APPNOTE §4.4.3.2 sets the minimum
directory version at 2.0, and `allow_version_1_directories` defaults to false.
The parser checks the compression method's minimum in each header. The
subsequent check for the resolved member kind receives only the central version.
[Version check](crates/zip-framing/src/index.rs#L372) ·
[Kind-specific minimum](crates/zip-framing/src/kind.rs#L120) ·
[PKWARE APPNOTE 6.3.9](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT)

**Open question.** Should the kind-specific minimum apply independently to
both headers? Independent checks would allow the central header to declare a
higher version when only its local-header offset needs ZIP64.
