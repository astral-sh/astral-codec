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
- tar-codec: the _encode_ layer implements the format-writer hooks that project
  generic build operations into pax members and owns tar framing, padding,
  sequence numbers, and terminators.
- tar-framing: the _physical_ write layer serializes individual pax members.

These layers/concerns should be preserved when making changes.
For example, any change that affects framing (which blocks are considered
headers, extensions, data, etc.) should occur in the physical layer, while a
change to source traversal, path containment, or filesystem behavior belongs in
`archive-trait`.

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
```

The `comparison` target compares `tar-codec`, `tar`, and `astral-tokio-tar` on
recursive directory encoding and USTAR extraction. Each operation uses two
fixtures: one 16 MiB file and 1,024 files of 1 KiB across 32 directories. This
gives 12 comparison cases. The separate `framing` target measures in-memory
framing, payload reading, and global pax updates.

Fixture generation and runtime construction happen outside measurements.
Extraction uses a fresh destination per iteration; temporary-directory creation
and cleanup also happen outside measurements. Async operations include
`Runtime::block_on` in each measured iteration. Local Divan runs report entry
and byte throughput where applicable.

Pass a name filter after `--`, or use `--test` to execute each case once. The
smoke tests use the debug profile and also run in CI:

```shell
cargo bench -p tar-codec --bench comparison --locked -- many-small
cargo test -p tar-codec --bench comparison --locked -- --test
cargo test -p tar-framing --bench framing --locked -- --test
```

### CodSpeed

[The benchmark workflow](.github/workflows/benchmark.yml) runs on pull requests
and pushes to `main`, and supports manual runs:

- `framing`: CPU simulation on a GitHub-hosted Linux runner.
- `comparison`: walltime on a CodSpeed Graviton macro runner, including time
  spent in filesystem operations and other system calls.

Uploads use OIDC; no token secret is needed. Enable the repository in CodSpeed
and allow public repositories in the organization's default runner group for
[macro runner access](https://codspeed.io/docs/integrations/ci/github-actions/macro-runners).
The CLI comes from the locked
`astral-dev-toolchain-cargo-codspeed` development dependency, installed through
`uv run`.

By default, the workflow runs all framing cases and the four `tar-codec` cases
in `comparison`. Add the `benchmarks:compare` PR label or enable
**Compare implementations** in a manual run to include the other implementations.
Adding or removing the label reruns the workflow. To establish comparison
baselines, dispatch it on `main` with **Compare implementations** enabled.

Build and check all instrumented benchmarks locally with:

```shell
uv run --only-dev --locked cargo codspeed build -p tar-framing --bench framing --locked -m simulation
uv run --only-dev --locked cargo codspeed build -p tar-codec --bench comparison --locked -m walltime
uv run --only-dev --locked cargo codspeed run -p tar-framing --bench framing -m simulation
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime
```

To select only `tar-codec` in the comparison target, use:

```shell
uv run --only-dev --locked cargo codspeed run -p tar-codec --bench comparison -m walltime -- '/tar-codec(\]|$)'
```

Outside the CodSpeed runner, simulation runs check execution without collecting
performance measurements; walltime runs collect local timings. Add `--profile dev`
to the build commands to check without an optimized build. Add `-- --test` to
the walltime run command to execute each case once without collecting timings.

Walltime results need a baseline from the same runner; earlier simulation
results cannot serve as that baseline. See the
[recorded local timings](crates/tar-codec/BENCHMARKS.md) for an implementation
comparison on macOS.
