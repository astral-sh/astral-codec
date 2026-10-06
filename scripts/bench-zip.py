"""Run each ZIP comparison in a fresh process, retaining its normal CodSpeed URI."""

import argparse
import math
import os
import platform
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--mode", choices=["walltime", "simulation"], default="walltime")
    parser.add_argument("--test", action="store_true", help="Smoke-test walltime cases without timing")
    parser.add_argument(
        "--pin-cpu", action="store_true",
        help="Pin Linux walltime cases to the last CPU in the current affinity mask",
    )
    parser.add_argument(
        "--min-time", type=float, default=0.25,
        help="Minimum walltime sampling window per case in seconds (default: 0.25)",
    )
    parser.add_argument(
        "--fixed-layout", action="store_true",
        help="Disable Linux address randomization for benchmark child processes",
    )
    arguments = parser.parse_args()
    if not math.isfinite(arguments.min_time) or arguments.min_time < 0:
        parser.error("--min-time must be a finite, nonnegative number")
    if arguments.test and arguments.mode == "simulation":
        parser.error("simulation runs each case once; omit --test")
    if arguments.pin_cpu:
        if arguments.mode != "walltime" or platform.system() != "Linux":
            parser.error("--pin-cpu requires Linux walltime benchmarks")
        # Stay within the CPUs reserved by the runner. Children inherit this
        # affinity, so the benchmark cannot migrate between CPU caches.
        os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
        print(f"Benchmark CPUs: {sorted(os.sched_getaffinity(0))}", flush=True)
    command = [
        "cargo", "codspeed", "run", "-p", "zip-codec", "--bench", "comparison",
        "-m", arguments.mode, "--",
    ]
    if arguments.fixed_layout:
        # The personality flag is inherited by benchmark children. This changes
        # only these processes, without changing the runner's system policy.
        command = ["setarch", platform.machine(), "--addr-no-randomize", *command]
    cases = subprocess.run(
        [*command, "--list-cases"], check=True, capture_output=True, text=True, timeout=60
    ).stdout.splitlines()
    # Reject unexpected CLI output instead of silently running an empty filter.
    if not cases or any(
        not re.fullmatch(r"[\w-]+/(Stored|Deflate)/(zip-codec|zip|astral_async_zip)", case)
        for case in cases
    ):
        raise ValueError(f"Unexpected benchmark case list: {cases!r}")
    for operation in ["open", "decode", "decode_stream", "encode", "encode_preallocated"]:
        for case in cases:
            implementation = case.rsplit("/", 1)[1]
            if not arguments.compare and implementation != "zip-codec":
                continue
            if operation == "decode_stream" and implementation == "astral_async_zip":
                continue
            # Divan filters use :: separators; CodSpeed's adapter also accepts
            # bracketed argument names. Anchor both ends to select just one case.
            pattern = rf"::{operation}(\[|::){re.escape(case)}(\]|$)"
            print(f"Isolated comparison: {operation}[{case}]", flush=True)
            options = []
            if arguments.test:
                options = ["--test"]
            elif arguments.mode == "walltime":
                options = ["--min-time", str(arguments.min_time)]
            subprocess.run(
                [*command, pattern, *options],
                check=True,
                timeout=300,
            )


if __name__ == "__main__":
    main()
