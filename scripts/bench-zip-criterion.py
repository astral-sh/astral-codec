"""Compare Criterion and Divan on identical operations in fresh CI processes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time


PROTOCOLS = {
    "d0": "Divan: current 250 ms elapsed sampling window",
    "d1": "Divan: 3 s warmup, 5 s measured work, batches 256 tiny / 1 many",
    "c0": "Criterion: default 3 s warmup, 5 s measurement, 100 samples, Auto",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--rounds", type=int, default=5)
    arguments = parser.parse_args()
    if not 1 <= arguments.rounds <= 5:
        parser.error("--rounds must be between 1 and 5")
    destination = Path("target/zip-criterion")
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path("target/codspeed").rglob("*")
        if path.is_file() and os.access(path, os.X_OK)
    }
    (destination / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    (destination / "protocols.json").write_text(json.dumps(PROTOCOLS, indent=2) + "\n")
    print("Artifact hashes:", json.dumps(artifacts), flush=True)
    command = [
        "cargo", "codspeed", "run", "-p", "zip-codec", "--bench", "comparison",
        "-m", "walltime", "--",
    ]
    cases = subprocess.run(
        [*command, "--list-cases"], check=True, capture_output=True, text=True, timeout=60
    ).stdout.splitlines()
    selected = [
        (operation, case)
        for operation in ["open", "decode", "encode"]
        for case in cases
        if case.startswith(("many-small-1024-entries/Stored/", "small-1-entries/Stored/"))
        and case.rsplit("/", 1)[1] in {"zip-codec", "zip"}
    ]
    assert len(selected) == 12 and len(set(selected)) == 12, selected
    rows = []
    units = {"ns": 1e-9, "µs": 1e-6, "μs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1}
    protocols = list(PROTOCOLS)
    for repetition in range(arguments.rounds):
        for case_index, (operation, case) in enumerate(selected):
            # Rotate order, but retain a fresh process for every observation.
            for offset in range(len(protocols)):
                protocol = protocols[(offset + repetition + case_index) % len(protocols)]
                label = f"{protocol}-r{repetition}"
                identifier = f"{operation}-{case.replace('/', '-')}-{label}"
                output = destination / identifier
                environment = os.environ.copy()
                environment.update({
                    "ZIP_BENCH_SAMPLE_LABEL": label,
                    "ZIP_BENCH_WARMUP_SECONDS": "0",
                    "ZIP_BENCH_HARNESS": "criterion" if protocol == "c0" else "divan",
                    "ZIP_BENCH_CASE": f"{case}/{label}",
                    "ZIP_BENCH_OPERATION": operation,
                    "ZIP_BENCH_OUTPUT": str(output),
                })
                if protocol == "c0":
                    # cargo-codspeed already supplies --bench. Criterion rejects
                    # a second copy, even though Divan accepts repeated flags.
                    options = ["--noplot"]
                    if arguments.test:
                        options += ["--test"]
                else:
                    pattern = rf"::{operation}(\[|::){re.escape(case)}/{label}(\]|$)"
                    options = [pattern, "--min-time", "0.25"]
                    if protocol == "d1":
                        environment["ZIP_BENCH_WARMUP_SECONDS"] = "3"
                        options = [pattern, "--min-time", "5", "--skip-ext-time", "--sample-size",
                                   "256" if case.startswith("small-") else "1"]
                    if arguments.test:
                        environment["ZIP_BENCH_WARMUP_SECONDS"] = "0"
                        options = [pattern, "--test"]
                print(f"Harness observation: {operation}[{case}/{label}]", flush=True)
                started = time.monotonic()
                result = subprocess.run(
                    [*command, *options], env=environment,
                    capture_output=True, text=True, timeout=120,
                )
                elapsed = time.monotonic() - started
                log = result.stdout + result.stderr
                (destination / f"{identifier}.log").write_text(log)
                print(log, end="", flush=True)
                result.check_returncode()
                if arguments.test:
                    if f"{case}/{label}" not in log:
                        raise ValueError(f"No smoke case matched {identifier}")
                    continue
                row = {
                    "operation": operation, "case": case, "protocol": protocol,
                    "repetition": repetition, "elapsed_seconds": elapsed,
                }
                if protocol == "c0":
                    estimates_paths = list(output.rglob("new/estimates.json"))
                    samples_paths = list(output.rglob("new/sample.json"))
                    if len(estimates_paths) != 1 or len(samples_paths) != 1:
                        raise ValueError(f"Expected one Criterion result in {output}")
                    estimates = json.loads(estimates_paths[0].read_text())
                    samples = json.loads(samples_paths[0].read_text())
                    row.update({
                        "median": estimates["median"]["point_estimate"] * 1e-9,
                        "mean": estimates["mean"]["point_estimate"] * 1e-9,
                        "criterion_estimates": estimates,
                        "criterion_samples": samples,
                    })
                else:
                    matches = [line for line in log.splitlines() if f"{case}/{label}" in line]
                    if len(matches) != 1:
                        raise ValueError(f"Expected one Divan result: {matches}")
                    values = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s+(ns|µs|μs|us|ms|s)\b", matches[0])
                    if len(values) != 4:
                        raise ValueError(f"Missing timings: {matches[0]}")
                    times = [float(value) * units[unit] for value, unit in values]
                    row.update(dict(zip(["fastest", "slowest", "median", "mean"], times)))
                rows.append(row)
                (destination / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
    if arguments.test:
        print(f"Checked {len(selected) * len(protocols) * arguments.rounds} isolated smoke observations.")
        return
    assert len(rows) == len(selected) * len(protocols) * arguments.rounds
    summaries = []
    for operation, case in selected:
        for protocol in protocols:
            times = [row["median"] for row in rows if (row["operation"], row["case"], row["protocol"]) == (operation, case, protocol)]
            summaries.append({
                "operation": operation, "case": case, "protocol": protocol,
                "median": statistics.median(times), "range": max(times) / min(times) - 1,
                "repetitions": times,
            })
    (destination / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    print("Completed harness experiment:", len(rows), "observations", flush=True)


if __name__ == "__main__":
    main()
