# ZIP wheel torture test

Run date: 2026-10-01. Branch: `ww/zc-torture`.
Codec revision: `874cb09cb17e07ee71d1328d18c715b16ebf9822` (the feature branch
after merging the initial benchmarks and ZIP optimizations).

## Member policy audit

**The second pass found no member-policy issues in the same 962 pinned wheels.**
Every wheel was downloaded again, verified against its pinned size and SHA-256,
and iterated through zip-codec without extraction. All 269,037 decoded members
were inspected. The inventory is 266,704 regular files and 2,333 directories;
there are no hardlinks, symlinks, or special members.

| Checked property | Findings |
| --- | ---: |
| Absolute paths, drive prefixes, backslashes, or parent components | 0 |
| Names rejected by `default_name_validator` | 0 |
| Invalid root/directory destinations | 0 |
| Hardlinks, symlinks, special members, or unsafe link targets | 0 |
| Duplicate destinations, file/directory conflicts, non-directory ancestors | 0 |
| Noncanonical paths or portable path collisions | 0 |
| Windows reserved names/characters or trailing dots/spaces | 0 |
| Setuid, setgid, or sticky mode bits | 0 |

There were also no parser failures, crashes, timeouts, or input failures. Every
wheel reached end-of-archive and passed payload size/CRC validation, covering
11,606,083,115 decoded bytes. Each wheel's member count and payload size match
the original run and Python's independent ZIP metadata. All six previously
oversized wheels are included. The remaining 38 project exclusions are unchanged.

This sample identifies no member-property incompatibility or codec fix. It does
not establish that arbitrary extraction destinations would be safe or usable;
the scope below is deliberately limited to member metadata and lexical checks.

The new [Rust example](crates/zip-codec/examples/torture_policy.rs) emits a record
for each decoded `Member`, including its kind, path, link target, UNIX mode,
and the result of the public `default_name_validator`. Strings are hex-encoded
in the wire protocol to preserve control characters and arbitrary UTF-8 without
ambiguity. The [Python audit](scripts/torture_policy.py) checks those records and
keeps findings separate from parser failures. It inspects every member even if an
earlier member has a policy finding.

The checks cover:

- Absolute paths, backslashes, drive prefixes, `..` components, default name
  rejection, and invalid root/directory destinations. Leading absolute names,
  drive prefixes, backslashes, and BOM-prefixed names are already rejected by
  ZIP framing; those are parser errors before member iteration.
- Hardlinks and special members, rejected by the default extraction behavior.
  All symlinks are inventoried as policy candidates; their targets are checked
  for name restrictions, absolute paths, escaping `..`, and ambiguous traversal.
- Duplicate normalized destinations, file/directory conflicts, non-directory
  ancestors, and noncanonical names such as `a/./b`. These are review candidates;
  the default extractor permits overwrites and normalizes some spellings.
- Windows reserved names/characters and trailing dots/spaces, following the
  [Win32 naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
  Collision candidates also include parent directory prefixes, after NFC
  normalization, case folding, and trailing-dot/space trimming. This is a
  portability heuristic, not an exact filesystem emulation.
- Setuid, setgid, and sticky mode bits, recorded as policy candidates.

The current-policy classification follows
[default name validation](crates/archive-trait/src/name.rs),
[path validation](crates/archive-trait/src/extract/path.rs), and
[link/extraction defaults](crates/archive-trait/src/extract.rs). It is a member
and lexical-path audit, not a call to the extractor. It does not inspect a real
destination, follow or create links, resolve the full archive symlink graph, or
model filesystem races, ambient paths, ACLs, or OS-specific path-length limits.
No package content is executed or extracted. These metadata observations
do not establish that extraction would succeed on a particular filesystem.

The positive controls in [test_torture_policy.py](scripts/test_torture_policy.py)
exercise actual ZIP hardlink records, symlinks with safe and unsafe targets,
FIFO members, permission bits, unsafe names, directory aliases, and Unicode/case
collisions. They also verify that framing rejects absolute, drive-prefixed,
backslash, and BOM-prefixed member names. All five tests passed, along with the
example build, Clippy, and format check. Codec and extraction policy source are
unchanged; only the audit harness was added.

Evidence for this pass:

- [policy/manifest.json](torture/policy/manifest.json): an exact copy of the
  combined 962-wheel manifest, including the 1 GiB download cap.
- [policy/results.jsonl](torture/policy/results.jsonl): per-wheel parser stages,
  visited-member counts, kind inventory, all findings, and a digest of the full
  decoded metadata event stream. These digests do not replace wheel hashes.
- [policy/summary.json](torture/policy/summary.json): totals, counts for every
  checked category, and completeness/provenance checks.
- [policy/environment.json](torture/policy/environment.json) and
  [policy/checks.json](torture/policy/checks.json): binary, source, and manifest
  hashes, runtime settings, and test commands. This pass used four workers and
  a 600-second timeout per parser process, with the codec's default limits.

The full metadata event streams were consumed in memory rather than stored as
separate artifacts. Only counts, digests, and findings are retained. All clean
temporary wheel downloads were deleted after validation.

Replay this audit into a fresh output directory:

```sh
cargo build -p zip-codec --example torture_policy --locked
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_torture_policy.py' -v
cargo clippy -p zip-codec --example torture_policy --locked -- -D warnings
cargo fmt --all --check
mkdir -p /tmp/zc-policy-replay
cp torture/policy/manifest.json /tmp/zc-policy-replay/
PYTHONDONTWRITEBYTECODE=1 python3 scripts/torture_policy.py --output /tmp/zc-policy-replay --workers 4 --timeout 600
```

The runner resumes completed wheel hashes in its output directory. It refuses
to resume if the manifest, parser binary, or audit source changed. `pass` records
parser success; policy findings are recorded independently and do not stop later
member inspection. A failed or flagged wheel is kept temporarily for diagnosis.

## Structural and payload validation baseline

**All 962 selected wheels passed.** They contain 269,037 members and
11,606,083,115 bytes of uncompressed payloads (11.61 GB). There were no recorded
parser rejections, CRC/size failures, parser crashes, or parser timeouts in the
completed results. This sample identifies no codec fix to make.

| Outcome | Count |
| --- | ---: |
| Sampled projects | 1,000 |
| Wheels downloaded and fully validated | 962 |
| Parser failures | 0 |
| Download or hash-verification failures | 0 |
| No non-yanked wheel in the selected release | 37 |
| Selected wheel exceeds the 1 GiB download cap | 0 |
| Project metadata unavailable (HTTP 404) | 1 |

Every selected wheel has exactly one final result. All downloads matched their
pinned size and SHA-256. For every passing wheel, the codec's indexed and visited
member counts and declared uncompressed sizes agree with Python's independent
central-directory inspection. The runner consumed all 11,606,083,115 payload
bytes and reached end-of-archive. Compressed downloads totaled 4,726,616,015
bytes (4.73 GB). Both baseline batches used the same parser binary. The current harness
matches the additional batch's source hash; the original harness is preserved
under its recorded hash. Codec source and `Cargo.lock` are unchanged.

| Download rank | Sampled | Passed | No wheel | Over size cap | Metadata error |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1–1,000 | 200 | 198 | 2 | 0 | 0 |
| 1,001–2,000 | 200 | 197 | 3 | 0 | 0 |
| 2,001–3,000 | 200 | 191 | 9 | 0 | 0 |
| 3,001–4,000 | 200 | 188 | 11 | 0 | 1 |
| 4,001–5,000 | 200 | 188 | 12 | 0 | 0 |

The tested wheels target `any` (816), Linux (55), Windows (45), macOS (45),
and WebAssembly (1). Their members use DEFLATE (266,614) and stored compression
(2,423), with UNIX (255,962) and MS-DOS (13,075) creator identifiers. The sample
includes 2,333 directory entries and 407 entries with the UTF-8 flag. No entries
use data descriptors, and no archives have an archive comment.

The largest member count was `homeassistant==2026.9.4`: 54,165 members and
231,486,699 uncompressed bytes. The largest download was
`nvidia-cudnn-cu12==9.27.0.42`: 743,068,852 bytes. The largest uncompressed
archive was `flashinfer-cubin==0.6.13`: 1,912,029,530 bytes. All passed.

### Exclusions and their causes

The 37 `no_wheel` projects had no non-yanked `bdist_wheel` in the release
returned by PyPI. They never reached the ZIP parser. Their names and selected
versions are preserved in the manifest.

The project `aaaaaaaaa` (rank 3,683) returned HTTP 404 from its PyPI project
JSON endpoint after retries. No wheel was selected for it. The API response
does not establish why the project is unavailable. These 38 projects are the
only remaining exclusions.

### Previously oversized wheels

The initial 128 MiB cap excluded six wheels. At the user's request, the cap was
raised to 1 GiB and all six were tested using their originally selected URLs,
versions, and hashes. No release or platform was reselected. All six passed
metadata validation and complete payload decoding, including size and CRC checks.

| Project and version | Wheel bytes | Members | Decoded bytes | Result |
| --- | ---: | ---: | ---: | --- |
| `nvidia-nccl-cu12==2.32.3` | 351,519,937 | 77 | 493,333,806 | Pass |
| `nvidia-cudnn-cu13==9.27.0.42` | 436,469,905 | 24 | 627,231,598 | Pass |
| `nvidia-cudnn-cu12==9.27.0.42` | 743,068,852 | 24 | 1,149,159,283 | Pass |
| `nvidia-cusparse-cu12==12.5.10.65` | 366,359,408 | 8 | 482,200,557 | Pass |
| `flashinfer-cubin==0.6.13` | 457,984,995 | 16,017 | 1,912,029,530 | Pass |
| `rerun-sdk==0.38.1` | 162,987,040 | 537 | 442,773,457 | Pass |

This batch adds 16,687 members, 2,518,390,137 downloaded bytes, and
5,106,728,231 decoded bytes. It used two workers and a 600-second parser timeout
per wheel. The codec's own resource limits were unchanged. Its manifest,
environment, and raw results are preserved separately under
[torture/large-wheels](torture/large-wheels/manifest.json) and included in the
combined manifest, results, and summary.

### Execution history

The monitoring session disconnected after 758 saved results, and a process check
found no running harness or parser. The termination reason was not observed.
The remaining 198 wheels were run using the same manifest and binary. Unfinished
attempts from the interruption have no recorded outcome; all 956 final outcomes
passed in that initial batch. The six large wheels were then tested without
interruption. These events are preserved in [run-events.json](torture/run-events.json).

## Method

The population is ranks 1–5,000 of the
[top-pypi-packages 30-day download ranking](https://github.com/hugovk/top-pypi-packages),
snapshot timestamp `2026-10-01 12:40:51`. The source now contains 15,000 projects;
only the first 5,000 participate in this sample. The complete downloaded snapshot
is retained in [torture/ranking.json](torture/ranking.json), with SHA-256
`55fee05ed02b628f05350a51780ec436efae39ea0810df5d5419e15b850c7041`.

Selection is deterministic: take 200 projects from each consecutive band of
1,000 ranks, ordered by SHA-256 of
`astral-codec-zip-torture-2026-10-01:project:<project>`. For each of these 1,000
projects, query the [PyPI JSON API](https://docs.pypi.org/api/json/) and choose
one non-yanked wheel from the release returned in `info.version`/`urls`, ordered
by SHA-256 of `astral-codec-zip-torture-2026-10-01:wheel:<filename>`. Selection
does not filter by the host's Python version, ABI, or operating system.

Projects without a wheel in that release are recorded without falling back to
older versions. The initial download cap was 128 MiB; it is now 1 GiB, which
includes every pinned wheel in this sample. Larger wheels would be recorded as
size skips rather than replaced by smaller wheels. Each downloaded wheel must
match the size and SHA-256 supplied by PyPI before it reaches the codec.

The [Rust runner](crates/zip-codec/examples/torture.rs) uses the unchanged codec
and its default resource limits. It opens the central directory, calls
`ZipArchive::validate_all`, then visits every member and drains file and hard-link
payloads in 64 KiB chunks. This exercises local headers, extra fields, member
projection, DEFLATE decoding, decoded-size checks, and CRC checks. Descriptors
would also be checked if present, but none occurred in this corpus. The runner
advances to end-of-archive to validate the final member.

The runner reads each downloaded archive into memory. Payload chunks are
discarded; no archive members are written to disk and no package code is loaded
or executed. Compressed wheel downloads use temporary files, removed after
success and retained after failure for investigation. The initial batch used
a 120-second parser timeout; the six large wheels used 600 seconds. Timeout,
crash, download error, parser rejection, and success are separate outcomes.

Python's `zipfile` independently records central-directory counts and metadata;
this initial metadata inspection alone is not a payload-integrity check.

## Reproduction and evidence

- [manifest.json](torture/manifest.json): all 1,000 sampled projects, including
  selection skips, wheel URLs, filenames, versions, sizes, and SHA-256 hashes.
- [results.jsonl](torture/results.jsonl): one result per selected wheel, including
  parser output, return code, duration, and Python ZIP metadata.
- [environment.json](torture/environment.json): initial batch's compiler, host,
  parser binary and source hashes, revision, concurrency, and timeout.
- [large-wheels/environment.json](torture/large-wheels/environment.json): the
  additional batch's settings, raised download cap, and updated harness hash.
- [large-wheels/results.jsonl](torture/large-wheels/results.jsonl): separate raw
  outcomes for the six previously excluded wheels.
- [initial-manifest.json](torture/initial-manifest.json) and
  [initial-runner.py](torture/initial-runner.py): original selection and harness
  source, retained to interpret the initial batch's provenance.
- [summary.json](torture/summary.json): audited counts, coverage, largest inputs,
  and agreement checks between the manifest, parser output, and ZIP metadata.
- [smoke-tests.json](torture/smoke-tests.json): stored/DEFLATE success and explicit
  CRC/local-filename corruption checks of the runner before the corpus run.

Both baseline batches used macOS 26.7 on ARM64, Python 3.14.6, and Rust 1.98.1. The initial
batch used eight workers; the six-wheel extension used two.
The harness's offline sampling and corruption tests, example build, Clippy, and
format check passed. The report contains no wall-clock performance comparison.

Build and check the harness without a release build:

```sh
cargo build -p zip-codec --example torture --locked
python3 -m unittest discover -s scripts -p 'test_torture_wheels.py' -v
cargo clippy -p zip-codec --example torture --locked -- -D warnings
cargo fmt --all --check
```

Replay the pinned corpus into a fresh directory (the runner resumes an existing
results file, so use a new one for a complete replay):

```sh
mkdir -p /tmp/zc-torture-replay
cp torture/manifest.json /tmp/zc-torture-replay/
python3 scripts/torture_wheels.py run --output /tmp/zc-torture-replay --workers 2 --timeout 600
```

To replay just the six large wheels, copy
`torture/large-wheels/manifest.json` into a fresh output directory and use the
same `run` command. The harness's default download cap is now 1 GiB.

To select a fresh corpus, use `select --output <new-directory>` instead of
copying the manifest; pass `--ranking torture/ranking.json` to reuse the ranking
snapshot. Release metadata may have changed since this run.

For a future rejection, `scripts/inspect_wheel_failure.py ARCHIVE --position N`
can independently drain its payloads with Python and print the local/central
headers at the error offset. It does not extract files. Bound that diagnostic
with an external process timeout, as the main runner does for the Rust process.

## Baseline scope

This is a compatibility sample, not an exhaustive test of the top 5,000 projects
or all their releases and wheels. The per-project selection is uniform by hash
within each rank band, not weighted by downloads. One wheel cannot represent all
build backends, platform variants, or historical releases of a project.

This corpus provides no data-descriptor or archive-comment coverage, uses only
stored and DEFLATE compression, and has a 1 GiB download cap. No selected wheel
is excluded by that cap.
It does not establish coverage of ZIP64 layouts or the codec's resource limits.
Follow-up torture runs can target those gaps and historical/platform variants;
the results here do not justify relaxing any parser check.

The baseline runs test the ZIP container and payloads, not wheel-specific
`RECORD` hashes, packaging metadata, installation, extraction policy, or
filesystem behavior. The member policy pass above adds the listed metadata
checks while still avoiding filesystem extraction.
The input is a complete seekable archive, so this does not exercise HTTP range
readers or interrupted network streams. These are published wheels, not mutated
fuzz inputs. The size cap and latest-release-only selection also limit coverage.
