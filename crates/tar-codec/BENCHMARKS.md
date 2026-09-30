# tar-codec benchmarks

See [CONTRIBUTING](../../CONTRIBUTING.md#benchmarking) for benchmark instructions.

## Results (2026-09-30)

Wall-clock measurements at `b6c7f43`, on a CodSpeed Graviton macro runner
(ARM64, Ubuntu 22.04).

Built with Rust 1.98.1 and Cargo's default bench profile, using `tar` 0.4.46,
`astral-tokio-tar` 0.7.0, and `codspeed-divan-compat` 5.0.2.

Times are medians of 100 samples from one run, with one iteration per sample.
Parentheses give elapsed time relative to `tar-codec`; below 1.00× is faster.

### Recursive directory encoding

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| large: 1 × 16 MiB | 9.21 ms | 6.44 ms (0.70×) | 67.16 ms (7.29×) |
| many-small: 1,024 × 1 KiB | 20.91 ms | 37.27 ms (1.78×) | 178.10 ms (8.52×) |

### Extraction

| Workload | `tar-codec` | `tar` | `astral-tokio-tar` |
| --- | ---: | ---: | ---: |
| ustar large | 46.12 ms | 46.46 ms (1.01×) | 45.46 ms (0.99×) |
| ustar many-small | 64.33 ms | 101.62 ms (1.58×) | 138.32 ms (2.15×) |

### Reproduction

Run the Benchmarks workflow with **Compare implementations** enabled.
