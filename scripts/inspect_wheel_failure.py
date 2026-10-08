#!/usr/bin/env python3
"""Read a wheel with Python's zipfile and inspect a failing local-header offset.

No extraction or package execution. Invoke with an external process timeout.
Python's acceptance is interoperability evidence, not proof of ZIP conformance.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile


def inspect(path, position):
    result = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    checked = 0
    decoded = 0
    failures = []
    with zipfile.ZipFile(path) as archive, path.open("rb") as source:
        entries = archive.infolist()
        result["entries"] = len(entries)
        central_offset = archive.start_dir
        for entry in entries:
            source.seek(central_offset + 28)
            name_size, extra_size, comment_size = struct.unpack("<3H", source.read(6))
            if position in (entry.header_offset, central_offset):
                source.seek(entry.header_offset)
                header = source.read(30)
                fields = struct.unpack("<4s5H3I2H", header)
                name = source.read(fields[-2])
                extra = source.read(fields[-1])
                result["member_at_position"] = {
                    "filename": entry.filename,
                    "offset": entry.header_offset,
                    "central_offset": central_offset,
                    "central": {
                        "version": entry.extract_version, "flags": entry.flag_bits,
                        "method": entry.compress_type, "crc": entry.CRC,
                        "compressed": entry.compress_size, "uncompressed": entry.file_size,
                        "host": entry.create_system, "attributes": entry.external_attr,
                        "extra_hex": entry.extra.hex(),
                    },
                    "local": {
                        "signature_hex": fields[0].hex(), "version": fields[1],
                        "flags": fields[2], "method": fields[3], "time": fields[4],
                        "date": fields[5], "crc": fields[6], "compressed": fields[7],
                        "uncompressed": fields[8], "name_hex": name.hex(),
                        "extra_hex": extra.hex(),
                    },
                }
            central_offset += 46 + name_size + extra_size + comment_size
            try:
                with archive.open(entry) as payload:
                    while chunk := payload.read(64 * 1024):
                        decoded += len(chunk)
                checked += 1
            except Exception as error:
                failures.append({"filename": entry.filename, "error": f"{type(error).__name__}: {error}"})
    result.update(checked_members=checked, decoded_bytes=decoded, failures=failures)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--position", type=int, default=0)
    arguments = parser.parse_args()
    print(json.dumps(inspect(arguments.archive, arguments.position), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
