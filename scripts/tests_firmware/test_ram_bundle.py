"""Small format fixtures independent of the retained vendor package."""
import struct
import tempfile
from pathlib import Path
import unittest

from cuktech_pc.ram_bundle import parse, unpack


class RamBundleTest(unittest.TestCase):
    def test_holes_and_exact_roundtrip(self):
        # Two slots: module 0 absent, module 1 starts after five startup bytes.
        blob = bytes.fromhex("e5d10bfb0200000005000000") + struct.pack("<IIII", 0, 0, 5, 5) + b"boot\0code\0"
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "main.bundle"
            source.write_bytes(blob)
            report = unpack(source, Path(tmp) / "out")
            self.assertEqual(report["populated_slots"], 1)
            self.assertEqual(report["code_blob_offset"], 28)
            self.assertTrue(report["roundtrip_verified"])
            self.assertEqual((Path(tmp) / "out/modules/module-1.js").read_bytes(), b"code")

    def test_exact_aliases_are_one_physical_section(self):
        blob = bytes.fromhex("e5d10bfb0200000005000000") + struct.pack("<IIII", 5, 5, 5, 5) + b"boot\0code\0"
        report = parse(blob)
        self.assertEqual(report["populated_slots"], 2)
        self.assertEqual(report["unique_module_sections"], 1)
        self.assertEqual(report["sections"][-1]["module_ids"], [0, 1])

    def test_rejects_truncation_bad_ranges_overlap_and_nontext(self):
        header = bytes.fromhex("e5d10bfb0200000005000000")
        rows = [(header, ValueError, "module table"),
                (header + struct.pack("<IIII", 0, 0, 2, 5) + b"boot\0code\0", ValueError, "invalid module range"),
                (header + struct.pack("<IIII", 5, 5, 7, 3) + b"boot\0code\0", ValueError, "overlapping"),
                (header + struct.pack("<IIII", 0, 0, 5, 5) + b"boot\0codex", ValueError, "null-terminated"),
                (header + struct.pack("<IIII", 0, 0, 5, 5) + b"boot\0cod\xff\0", UnicodeDecodeError, "utf-8")]
        for blob, error, message in rows:
            with self.subTest(message=message), self.assertRaisesRegex(error, message):
                parse(blob)


if __name__ == "__main__":
    unittest.main()
