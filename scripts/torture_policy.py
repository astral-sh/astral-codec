#!/usr/bin/env python3
"""Audit zip-codec members without extraction; keep policy findings separate from parsing.

Current-policy observations use the Rust default_name_validator and lexical rules
from archive-trait/src/extract/path.rs. Candidate observations are not claims that
the current extractor rejects a member. No filesystem or symlink-graph simulation.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time
import unicodedata
from urllib.parse import urlparse

from torture_wheels import MAX_DOWNLOAD, digest, fetch, now, write_json, zip_metadata


RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789¹²³"
}


def normalized(value):
    return "/".join(part for part in value.split("/") if part not in ("", "."))


def portable_key(value):
    return "/".join(unicodedata.normalize("NFC", part.rstrip(" .")).casefold()
                    for part in value.split("/"))


class MemberAudit:
    def __init__(self):
        self.kinds = Counter()
        self.findings = []
        self.paths = {}
        self.required_directories = {}
        self.portable_paths = {}
        self.reported_portable_pairs = set()
        self.inventory_hash = hashlib.sha256()

    def record(self, member, category, classification="candidate", **details):
        self.findings.append({"category": category, "classification": classification,
                              "index": member["index"], "position": member["position"],
                              "path": member["path"], "kind": member["kind"], **details})

    def check_value(self, member, value, field, accepted):
        if not accepted:
            self.record(member, "default_name_rejected", "current_policy", field=field, value=value)
        if value.startswith(("/", "\\")):
            self.record(member, "absolute_path", "current_policy", field=field, value=value)
        if "\\" in value:
            self.record(member, "backslash_separator", "current_policy", field=field, value=value)
        if any(re.match(r"^[a-zA-Z]:", component) for component in value.split("/")):
            self.record(member, "windows_drive_prefix", "current_policy", field=field, value=value)
        for component in value.split("/"):
            if component in ("", ".", ".."):
                continue
            if component.split(".", 1)[0].rstrip(" ").upper() in RESERVED:
                self.record(member, "windows_reserved_name", field=field, component=component)
            if any(character in '<>"|?*' for character in component):
                self.record(member, "windows_reserved_character", field=field, component=component)
            if component.endswith((".", " ")):
                self.record(member, "windows_trailing_dot_or_space", field=field, component=component)

    def add(self, event):
        member = dict(event, path=bytes.fromhex(event["path_hex"]).decode("utf-8"),
                      target=bytes.fromhex(event["target_hex"]).decode("utf-8"))
        path, kind, target = member["path"], member["kind"], member["target"]
        if member["index"] != sum(self.kinds.values()):
            raise ValueError("member events are missing or out of order")
        self.inventory_hash.update((json.dumps(event, sort_keys=True) + "\n").encode())
        self.kinds[kind] += 1
        self.check_value(member, path, "path", member["name_accepted"])
        components = path.split("/")
        if ".." in components:
            self.record(member, "parent_component", "current_policy", field="path")
        if kind != "directory" and (path.endswith("/") or components[-1] in (".", "..")):
            self.record(member, "directory_suffix_on_non_directory", "current_policy")
        destination = normalized(path)
        if not destination and kind != "directory":
            self.record(member, "root_destination_on_non_directory", "current_policy")
        if "." in components or "" in components[:-1]:
            self.record(member, "noncanonical_path")
        if member["unix_mode"] & 0o7000:
            self.record(member, "privileged_mode_bits", mode=oct(member["unix_mode"]))

        if kind in ("hardlink", "symlink"):
            self.record(member, kind, "current_policy" if kind == "hardlink" else "candidate", target=target)
            self.check_value(member, target, "target", member["target_name_accepted"])
            if not target:
                self.record(member, "empty_link_target", "current_policy")
            depth = max(0, len(destination.split("/")) - 1) if kind == "symlink" else 0
            normal_seen = False
            for component in target.split("/"):
                if component in ("", "."):
                    continue
                if component == "..":
                    if kind == "symlink" and normal_seen:
                        self.record(member, "ambiguous_symlink_target", "current_policy", target=target)
                        break
                    if depth == 0:
                        self.record(member, "escaping_link_target", "current_policy", target=target)
                        break
                    depth -= 1
                else:
                    normal_seen = True
                    depth += 1
        elif kind not in ("file", "directory"):
            self.record(member, "special_member", "current_policy")

        # Unsafe names are reported above, without pretending to normalize them
        # into a contained extraction namespace.
        if path.startswith(("/", "\\")) or "\\" in path or ".." in components or not destination:
            return
        if destination in self.paths:
            previous = self.paths[destination]
            self.record(member, "duplicate_destination", previous_path=previous["path"],
                        previous_kind=previous["kind"], previous_index=previous["index"])
            if (kind == "directory") != (previous["kind"] == "directory"):
                self.record(member, "file_directory_conflict", previous_path=previous["path"])
        if kind != "directory" and destination in self.required_directories:
            self.record(member, "non_directory_ancestor", descendant=self.required_directories[destination])
        parts = destination.split("/")
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            if parent in self.paths and self.paths[parent]["kind"] != "directory":
                self.record(member, "non_directory_ancestor", ancestor=self.paths[parent]["path"])
            self.required_directories.setdefault(parent, path)
        self.paths.setdefault(destination, member)
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            key = portable_key(prefix)
            previous = self.portable_paths.setdefault(key, prefix)
            pair = (previous, prefix)
            if previous != prefix and pair not in self.reported_portable_pairs:
                self.reported_portable_pairs.add(pair)
                self.record(member, "portable_path_collision", previous_prefix=previous, prefix=prefix)

    def result(self):
        return {"members": sum(self.kinds.values()), "kinds": dict(self.kinds),
                "inventory_sha256": self.inventory_hash.hexdigest(),
                "categories": dict(Counter(row["category"] for row in self.findings)),
                "classifications": dict(Counter(row["classification"] for row in self.findings)),
                "findings": self.findings}


def parse_output(stdout):
    audit = MemberAudit()
    stages = []
    for line in stdout.splitlines():
        event = json.loads(line)
        if event["stage"] == "member":
            audit.add(event)
        else:
            stages.append(event)
    if stages and stages[-1]["stage"] == "complete" and stages[-1]["members"] != sum(audit.kinds.values()):
        raise ValueError("audit did not see every decoded member")
    return stages, audit.result()


def inspect_wheel(project, binary, cache, timeout):
    result = {key: project[key] for key in ("project", "rank", "version", "filename", "sha256")}
    started = time.monotonic()
    path = cache / f"{project['sha256']}.whl"
    try:
        if urlparse(project["url"]).hostname != "files.pythonhosted.org":
            raise ValueError("unexpected wheel download host")
        data = fetch(project["url"], MAX_DOWNLOAD)
        if len(data) != project["size"] or digest(data) != project["sha256"]:
            raise ValueError("wheel size or SHA-256 differs from the pinned manifest")
        path.write_bytes(data)
        del data
        result["download_bytes"] = project["size"]
    except Exception as error:
        return dict(result, status="input_error", error=f"{type(error).__name__}: {error}")
    try:
        result["zip_metadata"] = zip_metadata(path)
    except Exception as error:
        result["reference_metadata_error"] = f"{type(error).__name__}: {error}"
    try:
        process = subprocess.run([str(binary), str(path)], capture_output=True, text=True, timeout=timeout)
        result.update(returncode=process.returncode, stderr=process.stderr)
        result["stages"], result["audit"] = parse_output(process.stdout)
        if process.returncode == 0 and result["stages"][-1]["stage"] == "complete":
            result["status"] = "pass"
        else:
            result["status"] = "crash" if process.returncode < 0 else "parser_error"
    except subprocess.TimeoutExpired:
        result.update(status="timeout")
    except Exception as error:
        result.update(status="harness_error", error=f"{type(error).__name__}: {error}")
    if result["status"] == "pass" and not result["audit"]["findings"]:
        path.unlink()
    else:
        result["retained_archive"] = str(path)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("torture/policy"))
    parser.add_argument("--binary", type=Path, default=Path("target/debug/examples/torture_policy"))
    parser.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "astral-codec-zc-policy")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=600)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    arguments.cache.mkdir(parents=True, exist_ok=True)
    binary = arguments.binary.resolve(strict=True)
    manifest_path = arguments.output / "manifest.json"
    if not manifest_path.exists():
        parser.error("copy a pinned manifest into the output directory first")
    sources = [Path(__file__), Path("scripts/torture_wheels.py"), Path("crates/zip-codec/examples/torture_policy.rs")]
    environment = {"started_at": now(), "binary_sha256": digest(binary.read_bytes()),
                   "manifest_sha256": digest(manifest_path.read_bytes()),
                   "source_sha256": {str(path): digest(path.read_bytes()) for path in sources},
                   "python": platform.python_version(), "platform": platform.platform(),
                   "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                   "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                   "max_download_bytes": MAX_DOWNLOAD, "workers": arguments.workers,
                   "timeout_seconds": arguments.timeout}
    environment_path = arguments.output / "environment.json"
    if environment_path.exists():
        previous = json.loads(environment_path.read_text())
        if any(previous[key] != environment[key] for key in ("binary_sha256", "manifest_sha256", "source_sha256")):
            parser.error("inputs or audit changed; choose a new output directory")
    else:
        write_json(environment_path, environment)
    results_path = arguments.output / "results.jsonl"
    previous = [json.loads(line) for line in results_path.read_text().splitlines()] if results_path.exists() else []
    finished = {row["sha256"] for row in previous}
    projects = [row for row in json.loads(manifest_path.read_text())["projects"]
                if row["selection"] == "selected" and row["sha256"] not in finished]
    counts = Counter(row["status"] for row in previous)
    with results_path.open("a") as stream, ThreadPoolExecutor(max_workers=arguments.workers) as pool:
        futures = [pool.submit(inspect_wheel, project, binary, arguments.cache, arguments.timeout) for project in projects]
        for future in as_completed(futures):
            result = future.result()
            stream.write(json.dumps(result, sort_keys=True) + "\n")
            stream.flush()
            counts[result["status"]] += 1
            findings = len(result.get("audit", {}).get("findings", []))
            if findings or result["status"] != "pass" or sum(counts.values()) % 25 == 0:
                print(f"Wheels: {sum(counts.values())}; {dict(counts)}; {result['project']}: {result['status']}, findings={findings}", flush=True)
    print("Completed:", dict(counts), flush=True)


if __name__ == "__main__":
    main()
