# CONTRIBUTING

## Architecture

### Tar archives

There are a few important architectural divisions/separations of concerns
to be aware of when making changes.

Archive reading has four abstraction layers, from lowest to highest:

- tar-framing: the _physical_ layer turns an asynchronous input source into a
  stream of tar blocks according to the pax or GNU tar state machine.
  This is the lowest level of abstraction.
- tar-framing: the _logical_ layer turns a stream of blocks from the physical layer
  into a stream of _assembled members_, i.e. tar entries along with
  their relevant pax or GNU metadata.
- tar-codec: the _decode_ layer validates tar-specific policy and projects
  assembled tar members into the format-neutral archive member model.
- archive-trait: the _extract_ layer turns format-neutral archive members into
  files, directories, links, and other destination state on disk.

Archive building follows the same separation in reverse:

- archive-trait: the _build_ layer wraps format writers in a stateful engine
  that owns entry addition, name validation, collision tracking, recursive
  filesystem traversal, source streaming, and poisoning semantics.
  It forwards format-specific file options to the writer; each codec defines
  and interprets its own options type.
- tar-codec: the _encode_ layer implements the format-writer hooks that project
  generic build operations into pax members and owns tar framing, padding,
  sequence numbers, and terminators.
- tar-framing: the _physical_ write layer serializes individual pax members.

These layers/concerns should be preserved when making changes.
For example, any change that affects framing (which blocks are considered
headers, extensions, data, etc.) should occur in the physical layer, while a
change to source traversal, path containment, or filesystem behavior belongs in
`archive-trait`.

### ZIP archives

ZIP reading starts from a seekable source. `zip-framing` finds the end records,
resolves ZIP64 fields, and reads the central directory through a bounded window.
The index preserves directory order and derives each member's physical boundary
from sorted local offsets, without fetching local records during opening.

`IndexedEntry` owns a `CentralDirectoryEntry` with declared metadata and tracks the
derived record boundary and cached resolution. `Index::entry` checks a selected
local header, extras, descriptor, exact record extent, and kind-specific metadata
before constructing a borrowed `Entry`. The resolved member data is cached only
after every check succeeds; payload offsets, reconciled UNIX extras, and the
ZIP-native `EntryKind` are available only through that checked type.
`Entry::kind` returns the cached kind without I/O or further validation.
`Index::validate_all` checks all members without decoding payloads. Local metadata
budgets are charged once per successful resolution.

Parsing constructors own their resource checks. Callers must not need separate
validation or budget calls to make a returned value usable. Check limits before
allocating variable-size metadata and commit usage only after successful
construction.

`zip-codec` resolves entries before projecting them into `archive-trait` members.
It owns raw DEFLATE processing, decoded-size and CRC checks, payload lending,
random access, and cursor poisoning. Advancing past an unfinished member drains
and validates its payload. `ZipArchive::validate_all` also checks whether member
kinds can be projected, link-target text in UNIX extras, and the symbolic-link
size limit. Framing exposes volume labels, sockets, and unknown UNIX types;
the codec rejects these kinds because they cannot be projected.
`reader_mut().await` drains an active payload before lending the immutable source
for caller-controlled prefetching or seeking. Filesystem extraction remains in
`archive-trait`.

Decoder I/O runs through a private operation guard. The archive remains poisoned
unless the operation commits after all fallible work succeeds. Member preparation
returns owned metadata before attaching a payload that borrows the archive.

Writing follows the same separation. `archive-trait::Builder` handles names,
collisions, traversal, and cancellation. `zip-codec::ZipEncoder` streams payloads
and retains bounded central-directory metadata. `zip-framing::write` serializes
UTF-8 ZIP64 headers and end records. ZIP output requires seeking so the encoder
can fill in each local header after streaming its payload, without descriptors.

Test record-layout behavior in `zip-framing/tests` and compression, projection,
or builder behavior in `zip-codec/tests`. The checked-in Python-generated ZIP
fixtures can be reproduced with
`python3 crates/zip-codec/tests/fixtures/generate.py`; Python is not required to
run the Rust tests.

## Formatting and linting

Linting and formatting:

```shell
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Run tests:

```shell
cargo test
```

In general, integration tests are preferred over unit tests. Unit tests
should be used primarily for small, pure private helpers.

## Benchmarking

The benchmarks use [CodSpeed's Divan adapter](https://codspeed.io/docs/reference/codspeed-rust/divan).
Run local wall-clock benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison --locked
cargo bench -p tar-framing --bench framing --locked
cargo bench -p zip-framing --bench framing --locked
cargo bench -p zip-codec --bench codec --locked
```

The `comparison` target compares `tar-codec`, `tar`, and `astral-tokio-tar` on
recursive directory encoding and USTAR extraction.

The ZIP benchmarks use in-memory ZIP64 archives. `zip-framing` measures header
serialization, directory indexing, and uncached local-record validation with
single-entry, many-entry, and long Unicode path fixtures. `zip-codec` measures
encoding and payload decoding with stored and DEFLATE compression, using large
compressible files, large incompressible files, and many small files. Decoding
includes local-record validation, member projection, and integrity checks;
directory indexing is excluded. Encoding includes builder bookkeeping and output
allocation. Fixture generation and correctness checks run outside measurements.

Smoke-test the ZIP benchmarks in the test profile with:

```shell
cargo test -p zip-framing --bench framing --locked -- --test
cargo test -p zip-codec --bench codec --locked -- --test
```

### CodSpeed

[The benchmark workflow](.github/workflows/benchmark.yml) runs on pull requests
and pushes to `main`, and supports manual runs:

- `tar-framing`, `zip-framing`, and `zip-codec`: CPU simulation on GitHub-hosted
  Linux runners.
- `comparison`: walltime on a CodSpeed Graviton macro runner, including time
  spent in filesystem operations and other system calls.

By default, the workflow runs all framing and ZIP codec cases and the four
`tar-codec` cases in `comparison`. Add the `benchmarks:compare` PR label or enable
**Compare implementations** in a manual run to include the other implementations.

Build and check all instrumented benchmarks locally with:

```shell
uv run --only-dev --locked cargo codspeed build -p tar-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-codec --bench codec --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p tar-codec --bench comparison --locked -m walltime
uv run --only-dev --locked cargo codspeed run -p tar-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench codec -m simulation
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime
```

To select only `tar-codec` in the comparison target, use:

```shell
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime -- '/tar-codec(\]|$)'
```
