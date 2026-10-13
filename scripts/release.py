#!/usr/bin/env -S uv run --locked --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["tomlkit"]
# ///
"""Update the workspace version, internal dependencies, and lockfile for a release."""

import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import tomlkit

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} <version>")

    version = sys.argv[1]
    manifest = ROOT / "Cargo.toml"
    contents = tomlkit.parse(manifest.read_text())
    workspace = contents["workspace"]
    workspace["package"]["version"] = version
    for dependency in workspace["dependencies"].values():
        if isinstance(dependency, Mapping) and "path" in dependency:
            dependency["version"] = version
    manifest.write_text(tomlkit.dumps(contents))

    # Cargo validates the version and refreshes all inherited workspace versions
    # without upgrading registry dependencies.
    subprocess.run(
        ["cargo", "update", "-p", "archive-trait", "--precise", version],
        cwd=ROOT,
        check=True,
    )


if __name__ == "__main__":
    main()
