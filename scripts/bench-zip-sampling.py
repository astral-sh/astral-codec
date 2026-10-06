"""Compare walltime sampling protocols on one artifact in fresh processes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--rounds", type=int, default=5)
    arguments = parser.parse_args()
    if not 1 <= arguments.rounds <= 5:
        parser.error("--rounds must be between 1 and 5")
    destination = Path("target/zip-sampling")
    destination.mkdir(parents=True, exist_ok=True)
    artifacts = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path("target/codspeed").rglob("*")
        if path.is_file() and os.access(path, os.X_OK)
    }
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
        for operation in ["open", "decode", "decode_stream", "encode", "encode_preallocated"]
        for case in cases
        if (case.startswith("small-1-entries/") or case.startswith("many-small-1024-entries/Stored/"))
        and not (operation == "decode_stream" and case.endswith("/astral_async_zip"))
    ]
    assert len(selected) == 42 and len(set(selected)) == 42, selected
    rows = []
    units = {"ns": 1e-9, "µs": 1e-6, "μs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1}
    for repetition in range(arguments.rounds):
        for case_index, (operation, case) in enumerate(selected):
            # Rotate protocol order to avoid always giving one protocol the
            # first position. Each observation still uses a fresh process.
            for offset in range(3):
                protocol = (offset + repetition + case_index) % 3
                label = f"c{protocol}-r{repetition}"
                pattern = rf"::{operation}(\[|::){re.escape(case)}/{label}(\]|$)"
                environment = os.environ.copy()
                environment["ZIP_BENCH_SAMPLE_LABEL"] = label
                environment["ZIP_BENCH_WARMUP_ITERATIONS"] = "32" if protocol == 2 else "0"
                options = ["--min-time", "0.25"]
                if protocol:
                    options += [
                        "--skip-ext-time", "--sample-size",
                        "64" if case.startswith("small-1-entries/") else "1",
                        "--max-time", "1",
                    ]
                if arguments.test:
                    options = ["--test"]
                print(f"Sampling observation: {operation}[{case}/{label}]", flush=True)
                result = subprocess.run(
                    [*command, pattern, *options], env=environment,
                    check=True, capture_output=True, text=True, timeout=120,
                )
                print(result.stdout, end="", flush=True)
                filename = f"{operation}-{case.replace('/', '-')}-{label}.log"
                (destination / filename).write_text(result.stdout + result.stderr)
                if arguments.test:
                    if f"{case}/{label}" not in result.stdout:
                        raise ValueError(f"No smoke case matched {pattern}")
                    continue
                matches = [line for line in result.stdout.splitlines() if f"{case}/{label}" in line]
                if len(matches) != 1:
                    raise ValueError(f"Expected one result for {pattern}: {matches}")
                values = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s+(ns|µs|μs|us|ms|s)\b", matches[0])
                if len(values) != 4:
                    raise ValueError(f"Missing timings: {matches[0]}")
                times = [float(value) * units[unit] for value, unit in values]
                rows.append({
                    "operation": operation, "case": case, "protocol": protocol,
                    "repetition": repetition, "fastest": times[0], "slowest": times[1],
                    "median": times[2], "mean": times[3],
                })
                (destination / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
    if arguments.test:
        print(f"Checked {len(selected) * 3 * arguments.rounds} isolated smoke observations.")
        return
    assert len(rows) == len(selected) * 3 * arguments.rounds
    summaries = []
    for operation, case in selected:
        for protocol in range(3):
            times = [row["median"] for row in rows if (row["operation"], row["case"], row["protocol"]) == (operation, case, protocol)]
            summaries.append({
                "operation": operation, "case": case, "protocol": protocol,
                "median": statistics.median(times), "range": max(times) / min(times) - 1,
                "repetitions": times,
            })
    (destination / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    (destination / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    print("Completed sampling experiment:", len(rows), "observations", flush=True)


if __name__ == "__main__":
    main()
