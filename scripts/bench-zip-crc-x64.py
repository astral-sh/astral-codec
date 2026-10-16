"""Compare the current and x64-interleaved CRC paths on one native runner."""

import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import subprocess


ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "baseline"
RESULTS = Path(os.environ.get("BENCHMARK_RESULTS", ROOT / "target/zip-crc-results"))
BINARIES = Path(os.environ.get("BENCHMARK_BINARIES", ROOT / "target/zip-crc-binaries"))

# name, executable, filter, iterations per sample, paired rounds
CASES = [
    ("requests", "wheel_corpus", r"decode.*requests.*/zip-codec$", 50, 60),
    ("botocore", "wheel_corpus", r"decode.*botocore.*/zip-codec$", 1, 24),
    ("django", "wheel_corpus", r"decode.*django.*/zip-codec$", 1, 24),
    ("numpy", "wheel_corpus", r"decode.*numpy.*/zip-codec$", 1, 24),
    ("medium-stored", "codec", r"decode_payload.*medium-crc.*Stored", 20, 24),
    ("medium-deflate", "codec", r"decode_payload.*medium-crc.*Deflate", 10, 24),
    ("small-control", "codec", r"decode_payload.*small-1-entries/Stored", 200, 24),
    ("large-control", "codec", r"decode_payload.*large-incompressible.*Stored", 5, 24),
    ("index-control", "wheel_corpus", r"index.*requests.*/zip-codec$", 500, 24),
]


def output(command, directory=ROOT):
    return subprocess.check_output(command, cwd=directory, text=True, timeout=60).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(variant, directory):
    command = [
        "cargo", "bench", "-p", "zip-codec", "--bench", "codec", "--bench",
        "wheel_corpus", "--no-run", "--locked", "--message-format=json-render-diagnostics",
    ]
    path = RESULTS / f"build-{variant}.log"
    environment = dict(os.environ)
    # Identically named path packages from separate checkouts can otherwise
    # reuse an executable whose source timestamps happen to be newer.
    environment["CARGO_TARGET_DIR"] = str(
        Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target/zip-crc-target")) / variant
    )
    print(f"Building {variant}", flush=True)
    with path.open("w") as log:
        subprocess.run(command, cwd=directory, env=environment,
                       stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=900)
    executables = {}
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("reason") != "compiler-artifact" or not record.get("executable"):
            continue
        target = record["target"]
        if "bench" not in target["kind"] or target["name"] not in ("codec", "wheel_corpus"):
            continue
        destination = BINARIES / f"{variant}-{target['name']}"
        shutil.copy2(record["executable"], destination)
        executables[target["name"]] = str(destination)
    if set(executables) != {"codec", "wheel_corpus"}:
        raise RuntimeError(f"Missing {variant} benchmark binaries: {executables}")
    return executables


def median_microseconds(text):
    matches = re.findall(r"│[^│]*│\s*([\d.]+)\s+(ns|µs|ms|s)\s*│", text)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one timing row, found {len(matches)}:\n{text}")
    value, unit = matches[0]
    return float(value) * {"ns": 0.001, "µs": 1, "ms": 1000, "s": 1000000}[unit]


def measure(executable, case, cpu, path, warmup=False):
    _, _, selector, sample_size, _ = case
    command = [
        "taskset", "--cpu-list", str(cpu), executable, "--bench", selector,
        "--sample-count", "2" if warmup else "20",
        "--sample-size", "1" if warmup else str(sample_size),
    ]
    run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    path.write_text(run.stdout + run.stderr)
    run.check_returncode()
    return median_microseconds(run.stdout)


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    BINARIES.mkdir(parents=True, exist_ok=True)
    if platform.machine() != "x86_64":
        raise RuntimeError("This comparison requires native x86_64")
    cpu_info = Path("/proc/cpuinfo").read_text()
    if "pclmulqdq" not in cpu_info or "sse4_1" not in cpu_info:
        raise RuntimeError("The runner must exercise the PCLMUL candidate path")
    cpu = max(os.sched_getaffinity(0))
    trial = int(os.environ.get("BENCHMARK_TRIAL", "1"))
    randomizer = random.Random(20261016 + trial)
    metadata = {
        "baseline": output(["git", "rev-parse", "HEAD"], BASELINE),
        "candidate": output(["git", "rev-parse", "HEAD"]),
        "rustc": output(["rustc", "-Vv"]),
        "cpu": output(["lscpu"]),
        "kernel": output(["uname", "-a"]),
        "pinned_cpu": cpu,
        "trial": trial,
        "runner_image": os.environ.get("ImageVersion"),
        "rustflags": os.environ.get("RUSTFLAGS", ""),
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
    }
    assert metadata["baseline"] == "b2dea04fa6822a5969f83968fce6df923c8e8488"
    assert digest(BASELINE / "Cargo.lock") == metadata["cargo_lock_sha256"]

    # Both variants receive identical fixtures, including the medium-size CRC case.
    fixture = Path("crates/zip-codec/benches/support/mod.rs")
    shutil.copyfile(ROOT / fixture, BASELINE / fixture)
    metadata["benchmark_fixture_sha256"] = digest(ROOT / fixture)
    metadata["baseline_benchmark_diff"] = output(["git", "diff", "--", str(fixture)], BASELINE)
    executables = {"baseline": build("baseline", BASELINE), "candidate": build("candidate", ROOT)}
    metadata["binaries"] = {
        variant: {name: digest(Path(path)) for name, path in binaries.items()}
        for variant, binaries in executables.items()
    }
    (RESULTS / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for name in ("codec", "wheel_corpus"):
        if metadata["binaries"]["baseline"][name] == metadata["binaries"]["candidate"][name]:
            raise RuntimeError(f"The {name} variants are identical; refusing to measure")
    print(json.dumps(metadata, indent=2), flush=True)

    for case in CASES:
        for variant in ("baseline", "candidate"):
            measure(executables[variant][case[1]], case, cpu,
                    RESULTS / f"warmup-{case[0]}-{variant}.txt", warmup=True)

    schedule = []
    for case in CASES:
        orders = [("baseline", "candidate"), ("candidate", "baseline")] * (case[4] // 2)
        randomizer.shuffle(orders)
        schedule.extend((case, round_number, order) for round_number, order in enumerate(orders))
    randomizer.shuffle(schedule)
    observations = []
    for case, round_number, order in schedule:
        values = {}
        for variant in order:
            path = RESULTS / f"{case[0]}-{round_number:02}-{variant}.txt"
            values[variant] = measure(executables[variant][case[1]], case, cpu, path)
        observation = {
            "case": case[0], "round": round_number, "order": order,
            "baseline_us": values["baseline"], "candidate_us": values["candidate"],
            "ratio": values["candidate"] / values["baseline"],
        }
        observations.append(observation)
        with (RESULTS / "observations.jsonl").open("a") as log:
            log.write(json.dumps(observation) + "\n")
        print(json.dumps(observation), flush=True)

    summary = []
    lines = [
        "| Case | Baseline µs | Candidate µs | Candidate / baseline | 95% interval |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for case in CASES:
        selected = [row for row in observations if row["case"] == case[0]]
        ratios = [row["ratio"] for row in selected]
        bootstrap = sorted(statistics.median(randomizer.choices(ratios, k=len(ratios)))
                           for _ in range(10000))
        row = {
            "case": case[0], "rounds": len(ratios),
            "baseline_us": statistics.median(row["baseline_us"] for row in selected),
            "candidate_us": statistics.median(row["candidate_us"] for row in selected),
            "median_ratio": statistics.median(ratios),
            "ratio_ci95": [bootstrap[250], bootstrap[9749]],
        }
        summary.append(row)
        lines.append(f"| {row['case']} | {row['baseline_us']:.3f} | {row['candidate_us']:.3f} "
                     f"| {row['median_ratio']:.4f} | {bootstrap[250]:.4f}–{bootstrap[9749]:.4f} |")
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    report = "\n".join(lines) + "\n\nRatios above 1 mean the candidate is slower.\n"
    (RESULTS / "summary.md").write_text(report)
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary_path).open("a") as destination:
            destination.write(report)
    print(report, flush=True)


if __name__ == "__main__":
    main()
