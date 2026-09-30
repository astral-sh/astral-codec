# tar-codec benchmarks

Benchmarks now use CodSpeed's Divan adapter. See
[CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for local commands and the
CodSpeed workflow.

## Local comparison (2026-09-30)

These tables retain measurements from the larger suite at source `7aeee4f`,
using `tar` 0.4.46, `astral-tokio-tar` 0.7.0, and `codspeed-divan-compat` 5.0.2.
They ran on macOS 26.7 with an Apple M5 Max (18 cores, 128 GiB RAM), APFS on the
internal SSD, and Rust 1.98.1, using Cargo's default optimized bench profile.

Each value is the median of six run medians. Runs alternated ascending and
descending benchmark order. The original run also included workloads since
removed from this suite. Divan used a minimum of one second and a maximum of
1.2 seconds per case, including harness overhead in that time budget.
Encoding used Divan's automatic
sample sizing; extraction used one iteration per sample. Fixture generation,
runtime construction, and extraction-directory setup and cleanup were outside
the measured operations.

These are wall-clock timings, not CodSpeed simulation results. CPU placement,
frequency, and background load were not controlled, and filesystem caches were
not explicitly flushed. Results depend on the host and filesystem. Parentheses
show elapsed time relative to `tar-codec`; values below 1.00× are faster.

For a given case, the range of run medians reached about 20% of its reported
median. This variation was larger than some of the smaller differences between
implementations.

### Recursive directory encoding

This target walks the source directory and encodes into a sink that counts
bytes without storing an archive. It does not measure archive output to disk.
The many-small fixture spreads its files across 32 directories. The encoders use
their default archive formats and metadata behavior, so their output is not
format-equivalent.

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 × 16 MiB | 0.8289 ms | 1.078 ms (1.30×) | 12.27 ms (14.80×) |
| many-small: 1,024 × 1 KiB | 17.89 ms | 20.48 ms (1.14×) | 54.54 ms (3.05×) |

### Extraction

All implementations extract the same in-memory USTAR archive into a fresh
directory. The large and many-small fixtures have the same payload sizes as above.

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| ustar large | 1.641 ms | 7.521 ms (4.58×) | 2.744 ms (1.67×) |
| ustar many-small | 99.53 ms | 108.3 ms (1.09×) | 116.3 ms (1.17×) |

### Reproduction

To refresh the retained workloads, run from the repository root:

```shell
cargo bench -p tar-codec --bench comparison --locked -- --min-time 1 --max-time 1.2 --sort name
```

Repeat for six rounds, replacing `--sort name` with `--sortr name` on even
rounds. Aggregate each case using the median of the six reported medians.
