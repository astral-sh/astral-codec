#!/usr/bin/env python3
"""Sample PyPI wheels, then validate their ZIP streams without extracting them.

Uses only the Python standard library and the built zip-codec torture example.
The manifest pins filenames, URLs and hashes so replay does not reselect releases.
Downloaded archives are temporary; failed archives are retained for investigation.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen
import zipfile


SEED = "astral-codec-zip-torture-2026-10-01"
MAX_DOWNLOAD = 128 * 1024 * 1024
RANKING_URL = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/"
    "main/top-pypi-packages-30-days.min.json"
)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fetch(url, limit):
    for attempt in range(3):
        try:
            request = Request(url, headers={"User-Agent": "astral-codec-wheel-torture/1"})
            with urlopen(request, timeout=30) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f"response exceeds {limit} bytes")
            return data
        except (HTTPError, URLError, TimeoutError, OSError):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def select_projects(ranking):
    projects = [dict(row, rank=index + 1) for index, row in enumerate(ranking["rows"][:5000])]
    if len(projects) != 5000:
        raise ValueError("ranking has fewer than 5,000 projects")
    selected = []
    for offset in range(0, 5000, 1000):
        selected.extend(sorted(
            projects[offset:offset + 1000],
            key=lambda row: digest(f"{SEED}:project:{row['project']}".encode()),
        )[:200])
    return sorted(selected, key=lambda row: row["rank"])


def select_wheel(project):
    result = dict(project)
    try:
        data = json.loads(fetch(f"https://pypi.org/pypi/{quote(project['project'])}/json", 64 * 1024 * 1024))
        result["version"] = data["info"]["version"]
        wheels = [item for item in data["urls"]
                  if item["packagetype"] == "bdist_wheel" and not item["yanked"]]
        result["available_wheels"] = len(wheels)
        if not wheels:
            return dict(result, selection="no_wheel")
        wheel = min(wheels, key=lambda item: digest(f"{SEED}:wheel:{item['filename']}".encode()))
        result.update({key: wheel[key] for key in ("filename", "url", "size", "upload_time_iso_8601")})
        result["sha256"] = wheel["digests"]["sha256"]
        result["selection"] = "oversized" if wheel["size"] > MAX_DOWNLOAD else "selected"
        return result
    except Exception as error:
        return dict(result, selection="metadata_error", error=f"{type(error).__name__}: {error}")


def make_manifest(output, ranking_path):
    ranking_bytes = ranking_path.read_bytes() if ranking_path else fetch(RANKING_URL, 4 * 1024 * 1024)
    (output / "ranking.json").write_bytes(ranking_bytes)
    ranking = json.loads(ranking_bytes)
    selected = select_projects(ranking)
    projects = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(select_wheel, project) for project in selected]
        for future in as_completed(futures):
            projects.append(future.result())
            if len(projects) % 100 == 0:
                print(f"Metadata: {len(projects)}/1000", flush=True)
    manifest = {
        "created_at": now(), "seed": SEED, "ranking_url": RANKING_URL,
        "ranking_sha256": digest(ranking_bytes), "ranking_last_update": ranking["last_update"],
        "max_download_bytes": MAX_DOWNLOAD,
        "projects": sorted(projects, key=lambda row: row["rank"]),
    }
    write_json(output / "manifest.json", manifest)
    print("Selection:", dict(Counter(row["selection"] for row in projects)), flush=True)


def zip_metadata(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        return {
            "entries": len(entries),
            "declared_bytes": sum(entry.file_size for entry in entries),
            "methods": dict(Counter(str(entry.compress_type) for entry in entries)),
            "hosts": dict(Counter(str(entry.create_system) for entry in entries)),
            "descriptor_entries": sum(bool(entry.flag_bits & 8) for entry in entries),
            "utf8_entries": sum(bool(entry.flag_bits & 2048) for entry in entries),
            "directory_entries": sum(entry.is_dir() for entry in entries),
            "archive_comment_bytes": len(archive.comment),
        }


def inspect_wheel(project, binary, cache, timeout):
    result = {key: project[key] for key in ("project", "rank", "version", "filename", "sha256")}
    started = time.monotonic()
    path = cache / f"{project['sha256']}.whl"
    try:
        if urlparse(project["url"]).hostname != "files.pythonhosted.org":
            raise ValueError("unexpected wheel download host")
        data = fetch(project["url"], MAX_DOWNLOAD)
        if len(data) != project["size"] or digest(data) != project["sha256"]:
            raise ValueError("wheel size or SHA-256 differs from PyPI metadata")
        path.write_bytes(data)
        del data
        result["download_bytes"] = project["size"]
    except Exception as error:
        return dict(result, status="download_error", error=f"{type(error).__name__}: {error}")

    try:
        result["zip_metadata"] = zip_metadata(path)
    except Exception as error:
        result["zip_metadata_error"] = f"{type(error).__name__}: {error}"

    try:
        process = subprocess.run([str(binary), str(path)], capture_output=True, text=True, timeout=timeout)
        result.update(returncode=process.returncode, stdout=process.stdout, stderr=process.stderr)
        stages = [json.loads(line) for line in process.stdout.splitlines()]
        result["stages"] = stages
        if process.returncode == 0 and stages and stages[-1].get("stage") == "complete":
            result["status"] = "pass"
        elif process.returncode < 0:
            result["status"] = "crash"
        else:
            result["status"] = "parser_error"
    except subprocess.TimeoutExpired as error:
        result.update(status="timeout", stdout=(error.stdout or b"").decode(errors="replace"),
                      stderr=(error.stderr or b"").decode(errors="replace"))
    except Exception as error:
        result.update(status="harness_error", error=f"{type(error).__name__}: {error}")

    if result["status"] == "pass":
        path.unlink()
    else:
        result["retained_archive"] = str(path)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result


def run_manifest(output, binary, cache, timeout, workers):
    manifest = json.loads((output / "manifest.json").read_text())
    projects = [row for row in manifest["projects"] if row["selection"] == "selected"]
    results_path = output / "results.jsonl"
    existing = [json.loads(line) for line in results_path.read_text().splitlines()] if results_path.exists() else []
    finished = {row["sha256"] for row in existing}
    projects = [row for row in projects if row["sha256"] not in finished]
    counts = Counter(row["status"] for row in existing)
    with results_path.open("a") as stream, ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(inspect_wheel, project, binary, cache, timeout) for project in projects]
        for future in as_completed(futures):
            result = future.result()
            stream.write(json.dumps(result, sort_keys=True) + "\n")
            stream.flush()
            counts[result["status"]] += 1
            completed = sum(counts.values())
            if result["status"] != "pass" or completed % 25 == 0:
                print(f"Wheels: {completed}; {dict(counts)}; {result['project']}: {result['status']}", flush=True)
    print("Completed:", dict(counts), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["select", "run"])
    parser.add_argument("--output", type=Path, default=Path("torture"))
    parser.add_argument("--ranking", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/examples/torture"))
    parser.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "astral-codec-zc-torture")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--workers", type=int, default=4)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    if arguments.operation == "select":
        if (arguments.output / "manifest.json").exists():
            parser.error("manifest already exists; choose a new output directory")
        make_manifest(arguments.output, arguments.ranking)
    else:
        arguments.cache.mkdir(parents=True, exist_ok=True)
        binary = arguments.binary.resolve(strict=True)
        environment_path = arguments.output / "environment.json"
        environment = {
            "started_at": now(), "python": platform.python_version(), "platform": platform.platform(),
            "binary_sha256": digest(binary.read_bytes()),
            "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
            "timeout_seconds": arguments.timeout, "workers": arguments.workers,
            "source_sha256": {
                str(path): digest(path.read_bytes()) for path in (
                    Path("scripts/torture_wheels.py"),
                    Path("crates/zip-codec/examples/torture.rs"),
                )
            },
        }
        if environment_path.exists():
            previous = json.loads(environment_path.read_text())
            if previous["binary_sha256"] != environment["binary_sha256"]:
                parser.error("binary changed; choose a new output directory")
        else:
            write_json(environment_path, environment)
        run_manifest(arguments.output, binary, arguments.cache, arguments.timeout, arguments.workers)


if __name__ == "__main__":
    main()
