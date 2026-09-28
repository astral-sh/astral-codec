"""Regenerate deterministic interoperability fixtures with Python's zipfile."""

import io
from pathlib import Path
import zipfile


class Streaming(io.BytesIO):
    def seekable(self):
        return False

    def seek(self, *args):
        raise io.UnsupportedOperation("streaming fixture")


root = Path(__file__).parent
for method, label in [(zipfile.ZIP_STORED, "stored"), (zipfile.ZIP_DEFLATED, "deflate")]:
    for streaming, zip64 in [(False, False), (True, False), (True, True)]:
        output = Streaming() if streaming else io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=method) as archive:
            for name, payload, mode in [
                ("directory/", b"", 0o040755),
                ("directory/file", b"hello ZIP\n" * 14000, 0o100755),
                ("caf\u00e9", b"UTF-8 filename", 0o100644),
                ("empty", b"", 0o100644),
                ("link", b"directory/file", 0o120777),
            ]:
                entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = mode << 16
                if name.endswith("/"):
                    entry.external_attr |= 0x10
                entry.compress_type = method if payload else zipfile.ZIP_STORED
                with archive.open(entry, "w", force_zip64=zip64) as member:
                    member.write(payload)
        suffix = "-zip64" if zip64 else "-descriptor" if streaming else ""
        (root / f"{label}{suffix}.zip").write_bytes(output.getvalue())

for filename, name in [("single-deflate.zip", "file"), ("extract.zip", "nested/file")]:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, b"payload")
    (root / filename).write_bytes(output.getvalue())

output = io.BytesIO()
with zipfile.ZipFile(output, "w") as archive:
    for name, mode, payload in [
        ("symbolic", 0o120777, b""),
        ("hard", 0o100644, b""),
        ("redundant", 0o120777, b"target"),
        ("conflicting", 0o120777, b"different"),
    ]:
        entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        entry.external_attr = mode << 16
        entry.extra = b"\x0d\x00\x12\x00" + bytes(12) + b"target"
        archive.writestr(entry, payload)
(root / "unix-links.zip").write_bytes(output.getvalue())
