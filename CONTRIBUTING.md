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
derived record boundary. `Index` owns the resolution cache, accessible through
`Index::resolved`. `Index::entry` checks a selected local header, extras,
descriptor, exact record extent, and kind-specific metadata
before constructing a borrowed `Entry`. The resolved member data is cached only
after every check succeeds; payload offsets, reconciled UNIX extras, and the
ZIP-native `EntryKind` are available only through that checked type.
Link targets in UNIX extras must be UTF-8 and contain no NUL bytes.
`Entry::kind` returns the cached kind without I/O or further validation.
`Index::validate_all` checks all members without decoding payloads. Local metadata
budgets are charged once per successful resolution.

Parsing constructors own their resource checks. Callers must not need separate
validation or budget calls to make a returned value usable. Check limits before
allocating variable-size metadata and commit usage only after successful
construction. The index and encoder share `zip-framing::Budget` for limit checks
and cumulative metadata and uncompressed-size accounting. Both charge a pending
copy and commit it after the operation succeeds.

`zip-codec` resolves entries before projecting them into `archive-trait` members.
It owns raw DEFLATE processing, decoded-size and CRC checks, payload lending,
random access, and cursor poisoning. Advancing past an unfinished member drains
and validates its payload. `ZipArchive::validate_all` also checks whether member
kinds can be projected and enforces the symbolic-link size limit. Symbolic-link
payloads are decoded and validated by the codec. Framing exposes volume labels,
sockets, and unknown UNIX types; the codec rejects these kinds because they
cannot be projected.
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
cargo bench -p zip-codec --bench comparison --locked
```

The `tar-codec` comparison target compares `tar-codec`, `tar`, and `astral-tokio-tar` on
recursive directory encoding and USTAR extraction.

The ZIP benchmarks use in-memory ZIP64 archives. `zip-framing` measures header
serialization, directory indexing, and uncached local-record validation with
single-entry, many-entry, and long Unicode path fixtures. `encode_headers_preallocated`
reserves the exact archive and directory capacities before writing; the initial
allocations and per-record allocations remain inside the measurement. `zip-codec`
measures encoding and payload decoding with stored and DEFLATE compression, using large
compressible files, large incompressible files, and many small files. Decoding
includes local-record validation, member projection, and integrity checks;
directory indexing is excluded. Encoding includes builder bookkeeping and output
allocation. Fixture generation and correctness checks run outside measurements.
Encoding fixtures contain only input paths and payloads. Their output is validated
after timing, so reader allocations do not affect encoding setup.

The `zip-codec` comparison target compares `zip-codec`, `zip`, and `astral_async_zip`
on in-memory archive opening, encoding, and decoding with the same workloads.
The ZIP fixtures also include a single 128-byte file and a synthetic package of
64 files ranging from 64 bytes to 256 KiB. The package mixes source-like text
with larger incompressible binaries; it measures changing file sizes and buffer
reuse rather than repeating one file size throughout the archive.
Opening and decoding use identical ZIP64 archives generated by `zip-codec`.
Opening measures each constructor's work; eager validation differs between
implementations. Decoding includes opening, member reads, CRC checks, and
collecting each file into a reusable `Vec`. Collection uses each library's checked
collection API, including `ZipMemberPayload::read_to_end`, to append to the
destination. `decode_stream` compares `zip-codec`
and `zip` with a reusable 64 KiB chunk buffer and no full-file collection. Both
read to EOF and validate CRCs. `astral_async_zip` is omitted from this case because
its checked helper collects the whole file, and its streaming traits require an
additional direct dependency. Streaming and collection are separate workloads;
compare implementations within the same workload. Encoding uses each library's
buffered input API and includes output allocation and finalization; output record
layouts may differ. `encode` starts with an empty output buffer and includes its
growth. `encode_preallocated` gives all three encoders the same capacity, with
room for DEFLATE expansion and their different headers. It includes the initial
output allocation and internal allocations, but checks that output needs no
growth. Compare these cases separately. The preallocated cases, including the
renamed header serialization benchmark, start new baselines.
All three use the default DEFLATE level and the shared `zlib-rs`
backend. Every encoder's output and every decoder's paths and payloads are checked
outside measurements. These comparisons do not imply equivalent validation or
resource policies.

Smoke-test the ZIP benchmarks in the test profile with:

```shell
cargo test -p zip-framing --bench framing --locked -- --test
cargo test -p zip-codec --bench codec --locked -- --test
cargo test -p zip-codec --bench comparison --locked -- --test
```

### CodSpeed

[The benchmark workflow](.github/workflows/benchmark.yml) runs on pull requests
and pushes to `main`, and supports manual runs:

- `tar-framing`, `zip-framing`, and both `zip-codec` targets: CPU simulation on
  GitHub-hosted Linux runners.
- `tar-codec` and `zip-codec` comparisons: walltime on CodSpeed Graviton macro runners,
  including time spent in filesystem operations and other system calls. Each
  comparison target runs in its own job. ZIP comparisons run in both modes;
  compare results within the same mode and runner architecture.

ZIP walltime comparisons run each operation, workload, compression method, and
implementation in a fresh process via `scripts/bench-zip.py`. This isolates each
case from earlier cases' allocation history, including glibc's adaptive mmap
threshold. Setup and repeated measurements within a case still share a process;
output allocation, growth, and deallocation remain part of the encoding cases.
Each case has a minimum 250 ms sampling window, including harness overhead.
This collects more samples for tiny operations that otherwise stop at the
default 100 samples. The driver accepts `--min-time` to change this floor,
including `--min-time 0` to investigate the default sample count.
On Linux, `scripts/bench-zip.py --fixed-layout` uses
`setarch --addr-no-randomize` for benchmark children when investigating layout
sensitivity. CI leaves this disabled: repeated runs did not consistently reduce
outliers with fixed layouts. The option does not change the runner's system policy.
Compare repeated CI runs before attributing small changes to the parser.

By default, the workflow runs all framing and ZIP codec cases and only our
implementation in each comparison target. Add the `benchmarks:compare` PR label or
enable **Compare implementations** in a manual run to include the other
implementations in both comparison targets.

Build and check all instrumented benchmarks locally with:

```shell
uv run --only-dev --locked cargo codspeed build -p tar-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-codec --bench codec --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-codec --bench comparison --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p tar-codec --bench comparison --locked -m walltime
uv run --only-dev --locked cargo codspeed build -p zip-codec --bench comparison --locked -m walltime
uv run --only-dev --locked cargo codspeed run -p tar-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench codec -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench comparison -m simulation
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench comparison -m walltime
```

To select only our implementation in either comparison target, use:

```shell
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime -- '/tar-codec(\]|$)'
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench comparison -m simulation -- '/zip-codec(\]|$)'
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench comparison -m walltime -- '/zip-codec(\]|$)'
```
