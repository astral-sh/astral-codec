"""Measure CPU placement and allocator effects using one baseline artifact."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time


PROTOCOLS = {
    "d0": {"pinned": False, "malloc": False},
    "d1": {"pinned": True, "malloc": False},
    "d2": {"pinned": False, "malloc": True},
    "d3": {"pinned": True, "malloc": True},
}


def snapshot():
    commands = {
        "cpus": ["lscpu", "--json"],
        "kernel": ["uname", "-a"],
        "glibc": ["getconf", "GNU_LIBC_VERSION"],
        "slice": ["systemctl", "show", "codspeed.slice", "-p", "AllowedCPUs", "-p", "EffectiveCPUs", "-p", "AllowedMemoryNodes", "-p", "ControlGroup"],
        "slice_definition": ["systemctl", "cat", "codspeed.slice"],
    }
    result = {"affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else [],
              "allocator_environment": {key: value for key, value in os.environ.items() if key.startswith("MALLOC_") or key == "GLIBC_TUNABLES"}}
    for key, command in commands.items():
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=15)
            result[key] = {"status": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        except FileNotFoundError:
            result[key] = None
    files = [Path("/proc/self/status"), Path("/proc/self/cgroup"), Path("/proc/cmdline"),
             Path("/proc/sys/kernel/randomize_va_space"),
             Path("/sys/kernel/mm/transparent_hugepage/enabled"),
             Path("/sys/kernel/mm/transparent_hugepage/defrag")]
    files.extend(Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor"))
    files.extend(Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_cur_freq"))
    files.extend(Path("/sys/devices/system/cpu").glob("cpu*/cache/index*/shared_cpu_list"))
    files.extend(Path("/sys/fs/cgroup").glob("**/cpuset.cpus.effective"))
    result["files"] = {}
    for path in files:
        try:
            result["files"][str(path)] = path.read_text()
        except (OSError, UnicodeError) as error:
            result["files"][str(path)] = str(error)
    result["hooks"] = {}
    for name in ["pre", "wrap", "post"]:
        path = Path(f"/usr/local/bin/codspeed-{name}-bench")
        if path.is_file():
            result["hooks"][str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    result["processes"] = []
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            result["processes"].append({
                "pid": int(directory.name),
                "status": [line for line in (directory / "status").read_text().splitlines()
                           if line.startswith(("Name:", "PPid:", "Cpus_allowed_list:"))],
                "cgroup": (directory / "cgroup").read_text(),
            })
        except (OSError, UnicodeError):
            pass
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--profile", choices=["true", "false"], required=True)
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--end", type=int, required=True)
    parser.add_argument("--block", type=int, required=True)
    arguments = parser.parse_args()
    if not 0 <= arguments.start < arguments.end <= 6:
        parser.error("require 0 <= start < end <= 6")
    if not arguments.test and os.environ.get("CODSPEED_PROFILER_ENABLED") != arguments.profile:
        parser.error("--profile must match CODSPEED_PROFILER_ENABLED")
    if arguments.profile == "false" and not arguments.test:
        # Runner 5.2.1 leaves its FIFOs behind after a profiled action. Without
        # a reader, instrument-hooks waits for acknowledgements before falling
        # back to unprofiled timing. There is no live profiler in this block.
        for name in ["ctl", "ack"]:
            path = Path(f"/tmp/runner.{name}.fifo")
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise ValueError(f"Refusing to remove a non-FIFO or another user's FIFO: {path}")
            path.unlink()
            print(f"Removed stale profiling FIFO: {path}", flush=True)
    destination = Path("target/zip-runtime")
    destination.mkdir(parents=True, exist_ok=True)
    environment_snapshot = snapshot()
    (destination / f"environment-{arguments.block}.json").write_text(json.dumps(environment_snapshot, indent=2) + "\n")
    affinity = environment_snapshot["affinity"]
    if not affinity and not arguments.test:
        raise ValueError("Linux CPU affinity is required for measurements")
    selected_cpu = max(affinity) if affinity else None
    print("Runtime environment:", json.dumps(environment_snapshot), flush=True)
    artifacts = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path("target/codspeed").rglob("*")
        if path.is_file() and os.access(path, os.X_OK)
    }
    (destination / "artifacts.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    (destination / "protocols.json").write_text(json.dumps(PROTOCOLS, indent=2) + "\n")
    command = ["cargo", "codspeed", "run", "-p", "zip-codec", "--bench", "comparison", "-m", "walltime", "--"]
    cases = subprocess.run([*command, "--list-cases"], check=True, capture_output=True, text=True, timeout=60).stdout.splitlines()
    selected = [
        (operation, case)
        for operation in ["open", "decode", "encode"]
        for case in cases
        if case.startswith(("many-small-1024-entries/Stored/", "small-1-entries/Stored/"))
        and case.rsplit("/", 1)[1] in {"zip-codec", "zip"}
    ]
    selected += [
        (operation, case)
        for operation in ["decode", "encode", "encode_preallocated"]
        for case in cases
        if case.startswith("large-incompressible-1-entries/Stored/")
        and case.rsplit("/", 1)[1] in {"zip-codec", "zip"}
    ]
    assert len(selected) == len(set(selected)) == 18, selected
    rows = []
    units = {"ns": 1e-9, "µs": 1e-6, "μs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1}
    protocols = list(PROTOCOLS)
    for repetition in range(arguments.start, arguments.end):
        for case_index, (operation, case) in enumerate(selected):
            for offset in range(len(protocols)):
                protocol = protocols[(offset + repetition + case_index) % len(protocols)]
                treatment = PROTOCOLS[protocol]
                label = f"p{int(arguments.profile == 'true')}-{protocol}-r{repetition}"
                identifier = f"{operation}-{case.replace('/', '-')}-{label}"
                environment = os.environ.copy()
                environment.update({"ZIP_BENCH_SAMPLE_LABEL": label, "ZIP_BENCH_DIAGNOSTICS": "1"})
                if treatment["malloc"]:
                    for key in list(environment):
                        if key.startswith("MALLOC_"):
                            del environment[key]
                    tunables = [value for value in environment.get("GLIBC_TUNABLES", "").split(":") if value and not value.startswith("glibc.malloc.")]
                    # Freeze glibc at its 64-bit maximum adaptive mmap threshold and
                    # corresponding trim threshold, retaining these fixture buffers.
                    tunables.extend(["glibc.malloc.mmap_threshold=33554432", "glibc.malloc.trim_threshold=67108864"])
                    environment["GLIBC_TUNABLES"] = ":".join(tunables)
                invocation = command
                if treatment["pinned"] and selected_cpu is not None:
                    invocation = ["taskset", "--cpu-list", str(selected_cpu), *command]
                # Keep regex compilation and its allocations identical across treatments.
                # Only the emitted benchmark name carries the observation label.
                pattern = rf"::{operation}(\[|::){re.escape(case)}/p[01]-d[0-3]-r[0-5](\]|$)"
                options = ["--test"] if arguments.test else ["--min-time", "0.25"]
                print(f"Runtime observation: {operation}[{case}/{label}]", flush=True)
                started = time.monotonic()
                result = subprocess.run([*invocation, pattern, *options], env=environment, capture_output=True, text=True, timeout=120)
                elapsed = time.monotonic() - started
                log = result.stdout + result.stderr
                (destination / f"{identifier}.log").write_text(log)
                print(log, end="", flush=True)
                result.check_returncode()
                if arguments.test:
                    if f"{case}/{label}" not in log:
                        raise ValueError(f"No smoke case matched {identifier}")
                    continue
                matches = [line for line in result.stdout.splitlines() if f"{case}/{label}" in line]
                if len(matches) != 1:
                    raise ValueError(f"Expected one Divan result: {matches}")
                values = re.findall(r"([0-9]+(?:\.[0-9]+)?)\s+(ns|µs|μs|us|ms|s)\b", matches[0])
                if len(values) != 4:
                    raise ValueError(f"Missing timings: {matches[0]}")
                times = [float(value) * units[unit] for value, unit in values]
                diagnostics = [line for line in result.stderr.splitlines() if line.startswith("ZIP_DIAGNOSTIC ")]
                allowed = [line.split("Cpus_allowed_list:", 1)[1].strip() for line in diagnostics if "Cpus_allowed_list:" in line]
                if len(allowed) != 2:
                    raise ValueError(f"Missing process affinity: {diagnostics}")
                if treatment["pinned"] and allowed != [str(selected_cpu)] * 2:
                    raise ValueError(f"CPU pinning failed: {allowed}")
                row = {"operation": operation, "case": case, "protocol": protocol,
                       "profile": arguments.profile, "repetition": repetition, "block": arguments.block,
                       "elapsed_seconds": elapsed, "diagnostics": diagnostics,
                       "selected_cpu": selected_cpu, "allocator": environment.get("GLIBC_TUNABLES")}
                row.update(dict(zip(["fastest", "slowest", "median", "mean"], times)))
                rows.append(row)
                (destination / f"observations-{arguments.block}.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"Completed block {arguments.block}: {len(selected) * len(protocols) * (arguments.end - arguments.start)} observations.", flush=True)


if __name__ == "__main__":
    main()
