"""Offline checks for the sampling and parser harness. Build the example first."""

import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zipfile

from torture_wheels import select_projects


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target/debug/examples/torture"


class SamplingTests(unittest.TestCase):
    def test_repeatable_sample_covers_every_rank_band(self):
        ranking = {"rows": [{"project": f"package-{index}"} for index in range(6000)]}
        selected = select_projects(ranking)
        self.assertEqual(selected, select_projects(ranking))
        self.assertEqual(len({row["project"] for row in selected}), 1000)
        for lower in range(1, 5001, 1000):
            self.assertEqual(sum(lower <= row["rank"] < lower + 1000 for row in selected), 200)


class ParserHarnessTests(unittest.TestCase):
    def test_success_and_corruption_without_extraction(self):
        with tempfile.TemporaryDirectory(prefix="zc-torture-smoke-") as directory:
            root = Path(directory)
            for label, method in [("stored", zipfile.ZIP_STORED), ("deflate", zipfile.ZIP_DEFLATED)]:
                with self.subTest(compression=label):
                    path = root / f"{label}.zip"
                    with zipfile.ZipFile(path, "w", compression=method) as archive:
                        archive.writestr("payload.txt", b"wheel torture test\n" * 1000)
                    result = subprocess.run([str(BINARY), str(path)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    stages = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(stages[-1], {"stage": "complete", "members": 1, "payload_bytes": 19000})

            original = (root / "stored.zip").read_bytes()
            name_length, extra_length = struct.unpack_from("<HH", original, 26)
            for label, offset, expected in [
                ("crc", 30 + name_length + extra_length, "payload CRC mismatch"),
                ("name", 30, "local and central filenames disagree"),
            ]:
                with self.subTest(corruption=label):
                    damaged = bytearray(original)
                    damaged[offset] ^= 1
                    path = root / f"{label}.zip"
                    path.write_bytes(damaged)
                    result = subprocess.run([str(BINARY), str(path)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(expected, result.stderr)
            self.assertFalse((root / "payload.txt").exists())


if __name__ == "__main__":
    unittest.main()
