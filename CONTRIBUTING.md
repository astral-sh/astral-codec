# Contributing

## Architecture

`archive-trait` defines the shared member model and owns format-neutral
filesystem extraction and archive building. Its builder handles name validation,
collision tracking, filesystem traversal, and cancellation. Each codec defines
and interprets its own file options.

### Tar archives

Reading proceeds through three format-specific layers:

- `tar-framing`'s _physical_ layer turns an asynchronous input source into a
  stream of tar blocks according to the pax or GNU tar state machine.
- `tar-framing`'s _logical_ layer assembles those blocks into members with their
  pax or GNU metadata.
- `tar-codec` validates tar-specific policy and projects assembled members into
  the shared member model.

When writing, `tar-codec` projects generic build operations into pax members and
owns padding, sequence numbers, and terminators. `tar-framing` serializes each
member.

### ZIP archives

ZIP reading requires a seekable source whose contents remain unchanged.
`zip-framing` validates the end records and central directory, preserves
directory order, and derives each member's physical bounds. It checks local
records on member access or full metadata validation. Only checked entries
expose payload offsets and reconciled metadata.

`zip-codec` projects checked entries into the shared member model and owns
random access, decompression, and payload integrity checks. It drains and
validates an unfinished payload before advancing to another member; errors or
cancellation poison the reader. `ZipArchive::validate_all` checks every member's
metadata and projection, but does not verify unread payloads.

When writing, `zip-codec` streams payloads and retains bounded central-directory
metadata; `zip-framing` serializes UTF-8 ZIP64 headers and end records. The
encoder requires seekable output to fill in each local header after streaming
its payload. See [SECURITY.md](SECURITY.md#zip-archives) for validation
guarantees and resource limits.

## Development checks

Run linting, formatting, and tests:

```shell
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
cargo test
```

Prefer integration tests; use unit tests primarily for small, pure private
helpers. For ZIP changes, test record layout in `crates/zip-framing/tests` and
compression, projection, or builder behavior in `crates/zip-codec/tests`.

Regenerate the checked-in ZIP fixtures with
`python3 crates/zip-codec/tests/fixtures/generate.py`. Python is not required to
run the Rust tests.

## Benchmarking

The benchmarks use [CodSpeed's Divan adapter](https://codspeed.io/docs/reference/codspeed-rust/divan).
Run local tar wall-clock benchmarks with:

```shell
cargo bench -p tar-codec --bench comparison --locked
cargo bench -p tar-framing --bench framing --locked
```

The `tar-codec` comparison target measures recursive directory encoding and
USTAR extraction across `tar-codec`, `tar`, and `astral-tokio-tar`.

The ZIP CodSpeed targets use in-memory ZIP64 archives:

- `zip-framing --bench framing`: header serialization, directory indexing, and
  uncached local-record validation.
- `zip-codec --bench codec`: encoding and payload decoding for stored and
  DEFLATE members. Decoding excludes directory indexing.

CodSpeed enables `bench-allocator` for `zip-codec --bench codec`: reallocations
always move, so buffer growth has a consistent cost. Smoke-test both targets with:

```shell
cargo test -p zip-framing --bench framing --locked -- --test
cargo test -p zip-codec --bench codec --locked -- --test
```

### ZIP wheel corpus

Run the local ZIP comparisons (index, decode, extract) with:

```shell
uv run --locked crates/zip-codec/benches/wheels/fetch.py
cargo bench -p zip-codec --bench wheel_corpus --locked
```

Set `WHEEL_CORPUS_DIR` to override the default cache in `target/wheel-corpus`.

### CodSpeed

[The benchmark workflow](.github/workflows/benchmark.yml) runs for relevant
changes in pull requests and pushes to `main`, and supports manual runs:

- `tar-framing --bench framing`, `zip-framing --bench framing`, and
  `zip-codec --bench codec`: CPU simulation on GitHub-hosted Linux runners.
- `tar-codec --bench comparison`: walltime on CodSpeed Graviton macro runners,
  including filesystem operations.

Simulation estimates CPU cost, not elapsed time; compare results within the same
mode.

By default, the workflow runs all framing and ZIP codec cases and only
`tar-codec` in the tar comparison. Add the `benchmarks:compare` PR label or
enable **Compare tar implementations** in a manual run to include `tar` and
`astral-tokio-tar`.

Build and check all instrumented benchmarks locally with:

```shell
uv run --only-dev --locked cargo codspeed build -p tar-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p zip-codec --bench codec --locked -m simulation --features bench-allocator
uv run --only-dev --locked cargo codspeed build -p tar-codec --bench comparison --locked -m walltime
uv run --only-dev --locked cargo codspeed run -p tar-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p zip-codec --bench codec -m simulation
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime
```

To select only our implementation in the tar comparison target, use:

```shell
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime -- '/tar-codec(\]|$)'
```

## Releases

1. Run [Prepare release](https://github.com/astral-sh/astral-codec/actions/workflows/release-prepare.yml)
   from `main` with the version to release, without a `v` prefix.
2. Review and merge the version bump PR.
3. Run [Release](https://github.com/astral-sh/astral-codec/actions/workflows/release.yml)
   from `main` with the same version.
4. Approve the `release-gate` deployment.
