import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"])
STUDY = Path(os.environ["RUNNER_TEMP"]) / "zip-simulation-study"
SOURCE = STUDY / "source"
RESULTS = STUDY / "results"
TARGET = STUDY / "target"
VERSIONS = {
    "pr159": "78d828a61e6abf0a670260adaa28797e48662f2b",
    "pr160": "01fd28fa4e850cbf5cc32cb9ab09e133fd1bfe92",
    "pr163": "7e1abdbd935883c7c0e81d2ce02d260e50a4a06d",
}
CASES = {
    "open": r"::open\[large-incompressible-1-entries/Deflate/zip\]$",
    "encode": r"::encode\[large-compressible-1-entries/Stored/zip\]$",
    "decode": r"::decode\[large-incompressible-1-entries/Stored/zip\]$",
}


def run(command, *, cwd=SOURCE, env=None, timeout=600, output=None):
    print("+", " ".join(map(str, command)), flush=True)
    started = time.monotonic()
    result = subprocess.run(
        list(map(str, command)),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE if output else None,
        stderr=subprocess.STDOUT if output else None,
        timeout=timeout,
        check=False,
    )
    if output:
        output.write_text(result.stdout)
    print(f"elapsed={time.monotonic() - started:.1f}s status={result.returncode}", flush=True)
    result.check_returncode()
    return result


def main():
    RESULTS.mkdir(parents=True)
    TARGET.mkdir()
    env = os.environ | {"CARGO_TARGET_DIR": str(TARGET)}
    for command, filename in [
        (["rustc", "-vV"], "rustc.txt"),
        (["valgrind", "--version"], "valgrind.txt"),
        (["lscpu"], "cpu.txt"),
        (["ldd", "--version"], "libc.txt"),
        (["uname", "-a"], "uname.txt"),
    ]:
        run(command, cwd=WORKSPACE, output=RESULTS / filename)

    manifest = []
    for version, revision in VERSIONS.items():
        run(["git", "worktree", "add", "--detach", SOURCE, revision], cwd=WORKSPACE)
        for mode in ("original", "batch"):
            if mode == "batch":
                shutil.copyfile(
                    WORKSPACE / "crates/zip-codec/benches/comparison.rs",
                    SOURCE / "crates/zip-codec/benches/comparison.rs",
                )
            run(
                ["uv", "run", "--only-dev", "--locked", "cargo", "codspeed", "build",
                 "-p", "zip-codec", "--bench", "comparison", "--locked", "-m", "simulation"],
                env=env,
                timeout=1200,
            )
            binaries = list((TARGET / "codspeed").glob("*/zip-codec/comparison"))
            if len(binaries) != 1:
                raise RuntimeError(f"expected one simulation binary, got {binaries}")
            binary = binaries[0]
            digest = hashlib.file_digest(binary.open("rb"), "sha256").hexdigest()
            (RESULTS / f"{version}-{mode}.sha256").write_text(f"{digest}  {binary}\n")
            for repeat in range(1, 4):
                # Reverse order on the second run to detect time or host load drift.
                batches = [1] if mode == "original" else [1, 8, 32]
                if repeat == 2:
                    batches.reverse()
                for batch in batches:
                    for case, selector in CASES.items():
                        name = f"{version}-{mode}-n{batch}-r{repeat}-{case}"
                        profiles = RESULTS / name
                        profiles.mkdir()
                        measured = run(
                            [
                                "setarch", "x86_64", "--addr-no-randomize",
                                "valgrind", "-q", "--trace-children=yes",
                                "--cache-sim=yes", "--I1=32768,8,64", "--D1=32768,8,64",
                                "--LL=8388608,16,64", "--collect-systime=nsec",
                                "--read-inline-info=yes", "--instr-atstart=no",
                                "--separate-threads=no", "--cycle-estimation=yes",
                                "--tool=callgrind", "--compress-strings=no", "--combine-dumps=yes",
                                "--dump-line=no", f"--callgrind-out-file={profiles}/%p.out",
                                f"--log-file={profiles}/valgrind.%p.log", binary, selector,
                            ],
                            cwd=SOURCE / "crates/zip-codec",
                            env=env | {"ZIP_STUDY_BATCH": str(batch)},
                            timeout=600,
                            output=profiles / "benchmark.log",
                        )
                        matches = [line for line in measured.stdout.splitlines() if line.startswith("Measured:")]
                        if len(matches) != 1 or f"::{case}[" not in matches[0]:
                            raise RuntimeError(f"{name}: expected exactly one measurement, got {matches}")
                        if not list(profiles.glob("*.out")):
                            raise RuntimeError(f"{name}: no Callgrind profiles")
                        manifest.append({
                            "version": version, "revision": revision, "mode": mode,
                            "batch": batch, "repeat": repeat, "case": case,
                            "binary_sha256": digest, "measurement": matches[0],
                            "directory": name,
                        })
                        (RESULTS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        run(["git", "worktree", "remove", "--force", SOURCE], cwd=WORKSPACE)


if __name__ == "__main__":
    main()
