#!/usr/bin/env -S uv run --locked --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Update the workspace version, internal dependencies, and lockfile for a release."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        capture_output=capture_output,
        text=True,
    )


def update_manifest(version: str) -> None:
    match = re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        version,
    )
    if match is None or any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")
        for identifier in (match.group(1) or "").split(".")
    ):
        raise SystemExit(f"invalid Cargo version: {version!r}")

    manifest = ROOT / "Cargo.toml"
    contents = manifest.read_text()
    workspace = tomllib.loads(contents)["workspace"]
    if workspace["package"]["version"] == version:
        raise SystemExit(f"Cargo.toml is already at version {version}")

    dependencies = {
        name
        for name, dependency in workspace["dependencies"].items()
        if isinstance(dependency, dict) and "path" in dependency
    }
    updated = set()
    table = ""
    lines = contents.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("["):
            table = line.strip()
        name = line.partition("=")[0].strip()
        if (table == "[workspace.package]" and name == "version") or (
            table == "[workspace.dependencies]" and name in dependencies
        ):
            lines[index], count = re.subn(
                r'\bversion\s*=\s*"[^"]+"', f'version = "{version}"', line
            )
            if count != 1:
                raise SystemExit(f"expected one version for {table} {name}")
            updated.add(name)
    if updated != dependencies | {"version"}:
        raise SystemExit("could not update all workspace versions")
    manifest.write_text("".join(lines))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} <version>")

    version = sys.argv[1]
    update_manifest(version)

    # Updating one workspace package refreshes all inherited versions, while
    # preserving the locked versions of registry dependencies.
    run("cargo", "update", "-p", "archive-trait", "--precise", version)
    run(
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
        capture_output=True,
    )
    run("git", "diff", "--check")
    changed = set(
        run("git", "diff", "--name-only", capture_output=True).stdout.splitlines()
    )
    expected = {"Cargo.toml", "Cargo.lock"}
    if changed != expected:
        raise SystemExit(
            f"release preparation changed {sorted(changed)}, expected {sorted(expected)}"
        )


if __name__ == "__main__":
    main()
