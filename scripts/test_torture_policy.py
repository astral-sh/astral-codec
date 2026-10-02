"""Exercise the member audit through real ZIPs and zip-codec, without extraction."""

from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import warnings
import zipfile

from torture_policy import parse_output


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / "target/debug/examples/torture_policy"


def run_archive(entries):
    with tempfile.TemporaryDirectory(prefix="zc-policy-test-") as directory:
        path = Path(directory) / "input.zip"
        with warnings.catch_warnings(record=True), zipfile.ZipFile(path, "w") as archive:
            for name, payload, mode, extra in entries:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                entry.extra = extra
                archive.writestr(entry, payload)
        result = subprocess.run([str(BINARY), str(path)], capture_output=True, text=True, timeout=10)
        if list(Path(directory).iterdir()) != [path]:
            raise AssertionError("the parser created output beside the ZIP")
        return result


class PolicyTests(unittest.TestCase):
    def test_paths_collisions_and_portability(self):
        names = ["directory/C:relative", "parent/../escape", "name:stream", "control\x1fname",
                 " leading", "NUL.txt", "trailing./file", "wild?card", "prefix", "prefix/child",
                 "Case/file", "case/other", "alias/./file", "alias/file", "repeat", "repeat", ".",
                 "quote\"and\nnewline", "normal/café", "child-first/file", "child-first",
                 "COM¹.log", "Café/first", "cafe\u0301/second"]
        process = run_archive([(name, b"payload", 0o100644, b"") for name in names])
        self.assertEqual(process.returncode, 0, process.stderr)
        stages, audit = parse_output(process.stdout)
        self.assertEqual(stages[-1]["members"], len(names))
        self.assertEqual(stages[-1]["payload_bytes"], 7 * len(names))
        self.assertEqual(audit["members"], len(names))
        categories = audit["categories"]
        for category in ("windows_drive_prefix", "parent_component", "default_name_rejected",
                         "windows_reserved_name", "windows_trailing_dot_or_space", "windows_reserved_character",
                         "non_directory_ancestor", "portable_path_collision", "duplicate_destination",
                         "noncanonical_path", "root_destination_on_non_directory"):
            self.assertGreater(categories.get(category, 0), 0, category)
        self.assertFalse(any(row["path"] == "normal/café" for row in audit["findings"]))
        self.assertTrue(any(row["path"] == "quote\"and\nnewline" for row in audit["findings"]))
        self.assertTrue(any(row.get("previous_prefix") == "Case" and row.get("prefix") == "case"
                            for row in audit["findings"]))
        self.assertTrue(any(row.get("previous_prefix") == "Café" and row.get("prefix") == "cafe\u0301"
                            for row in audit["findings"]))
        self.assertTrue(any(row.get("descendant") == "child-first/file" for row in audit["findings"]))

    def test_real_hardlinks_symlinks_specials_and_permissions(self):
        extra = struct.pack("<HH", 0x000D, 18) + bytes(12) + b"target"
        entries = [("target", b"data", 0o100644, b""),
                   ("hard", b"", 0o100644, extra),
                   ("link", b"target", 0o120777, b""),
                   ("nested/escaping", b"../../escape", 0o120777, b""),
                   ("nested/ambiguous", b"dir/../target", 0o120777, b""),
                   ("a/b/safe", b"../../target", 0o120777, b""),
                   ("absolute-link", b"/outside", 0o120777, b""),
                   ("pipe", b"", 0o010644, b""),
                   ("setuid", b"payload", 0o104755, b"")]
        process = run_archive(entries)
        self.assertEqual(process.returncode, 0, process.stderr)
        stages, audit = parse_output(process.stdout)
        self.assertEqual(stages[-1]["members"], len(entries))
        self.assertEqual(audit["kinds"], {"file": 2, "hardlink": 1, "symlink": 5, "fifo": 1})
        self.assertEqual(audit["categories"]["hardlink"], 1)
        self.assertEqual(audit["categories"]["symlink"], 5)
        self.assertEqual(audit["categories"]["absolute_path"], 1)
        self.assertEqual(audit["categories"]["escaping_link_target"], 1)
        self.assertEqual(audit["categories"]["ambiguous_symlink_target"], 1)
        self.assertEqual(audit["categories"]["special_member"], 1)
        self.assertEqual(audit["categories"]["privileged_mode_bits"], 1)
        self.assertFalse(any(row["classification"] == "current_policy" and row["path"] in ("link", "a/b/safe")
                             for row in audit["findings"]))

    def test_clean_directory_and_file_have_no_findings(self):
        process = run_archive([("directory/", b"", 0o040755, b""),
                               ("directory/file", b"hello", 0o100644, b"")])
        self.assertEqual(process.returncode, 0, process.stderr)
        _, audit = parse_output(process.stdout)
        self.assertEqual(audit["findings"], [])
        self.assertEqual(audit["kinds"], {"directory": 1, "file": 1})

    def test_file_directory_alias_is_a_policy_candidate(self):
        process = run_archive([("conflict/", b"", 0o040755, b""),
                               ("conflict", b"payload", 0o100644, b"")])
        self.assertEqual(process.returncode, 0, process.stderr)
        _, audit = parse_output(process.stdout)
        self.assertEqual(audit["categories"]["file_directory_conflict"], 1)
        self.assertEqual(audit["categories"]["duplicate_destination"], 1)
        self.assertTrue(all(row["classification"] == "candidate" for row in audit["findings"]))

    def test_framing_rejections_remain_parser_errors(self):
        for name in ("/absolute", "C:/absolute", "C:relative", "back\\slash", "\ufeffname"):
            with self.subTest(name=name):
                process = run_archive([(name, b"", 0o100644, b"")])
                self.assertEqual(process.returncode, 1)
                self.assertIn("invalid ZIP filename", process.stderr)
                _, audit = parse_output(process.stdout)
                self.assertEqual(audit["members"], 0)


if __name__ == "__main__":
    unittest.main()
