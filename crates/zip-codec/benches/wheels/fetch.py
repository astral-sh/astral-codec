"""Fetch the exact wheels in corpus.txt into the benchmark cache."""

import hashlib
import os
from pathlib import Path
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
DESTINATION = Path(
    os.environ.get("WHEEL_CORPUS_DIR", HERE.parents[3] / "target" / "wheel-corpus")
)


def main():
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for line in (HERE / "corpus.txt").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, digest, url = line.split()
        destination = DESTINATION / f"{name}.whl"
        if destination.is_file():
            actual = hashlib.sha256(destination.read_bytes()).hexdigest()
            if actual == digest:
                print(f"Verified {name}")
                continue
        with urlopen(url, timeout=60) as response:
            data = response.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise ValueError(f"{name}: expected sha256 {digest}, got {actual}")
        pending = destination.with_suffix(".partial")
        pending.write_bytes(data)
        pending.replace(destination)
        print(f"Fetched {name}")


if __name__ == "__main__":
    main()
