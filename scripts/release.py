#!/usr/bin/env -S uv run --locked --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["tomlkit"]
# ///
"""Prepare or validate a workspace release."""

import argparse
import json
import subprocess
from collections.abc import Mapping
from pathlib import Path

import tomlkit

ROOT = Path(__file__).resolve().parent.parent


def validate_release(version: str) -> None:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
        )
    )
    if not metadata["workspace_members"] or any(
        package["version"] != version
        for package in metadata["packages"]
        if package["id"] in metadata["workspace_members"]
    ):
        raise SystemExit(
            f"Requested version {version} does not match all workspace packages"
        )
    if subprocess.check_output(["git", "tag", "--list", f"v{version}"], cwd=ROOT):
        raise SystemExit(f"Tag v{version} already exists")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Check the version and tag without changing files",
    )
    arguments = parser.parse_args()
    version = arguments.version
    if arguments.validate:
        validate_release(version)
        return

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
