# tar-codec benchmarks

See [CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for benchmark instructions.

## Results (2026-09-30)

Wall-clock measurements at `7aeee4f`, built with Rust 1.98.1 and Cargo's default
bench profile, using `tar` 0.4.46, `astral-tokio-tar` 0.7.0, and
`codspeed-divan-compat` 5.0.2.
The host was an Apple M5 Max (18 cores, 128 GiB RAM) running macOS 26.7, with
APFS on the internal SSD.

Times are medians of six run medians, alternating benchmark order between runs.
Parentheses give elapsed time relative to `tar-codec`; below 1.00× is faster.

Divan used 1–1.2 seconds per case, including harness overhead. Encoding used
automatic sample sizing; extraction used one iteration per sample. Fixture
generation, runtime creation, and temporary-directory setup and cleanup were
untimed.

CPU placement, frequency, and background load were uncontrolled; caches were not
flushed. Per-case run medians spanned up to about 20% of the reported median,
exceeding some of the differences between implementations.

### Recursive directory encoding

Encoding walks the source directory and writes to a counting sink; archive
output is discarded. The many-small fixture uses 32 directories. `tar-codec`
emits pax archives; `tar` and `astral-tokio-tar` use GNU headers. Each encoder
uses its default metadata settings.

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 × 16 MiB | 0.8289 ms | 1.078 ms (1.30×) | 12.27 ms (14.80×) |
| many-small: 1,024 × 1 KiB | 17.89 ms | 20.48 ms (1.14×) | 54.54 ms (3.05×) |

### Extraction

Extraction uses the same in-memory USTAR archive and a fresh destination for
each implementation, with the file sizes and counts above.

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| ustar large | 1.641 ms | 7.521 ms (4.58×) | 2.744 ms (1.67×) |
| ustar many-small | 99.53 ms | 108.3 ms (1.09×) | 116.3 ms (1.17×) |

### Reproduction

Run from the repository root:

```shell
cargo bench -p tar-codec --bench comparison --locked -- --min-time 1 --max-time 1.2 --sort name
```

Run six times, alternating `--sort name` and `--sortr name`, and take the median
of each case's six medians.
