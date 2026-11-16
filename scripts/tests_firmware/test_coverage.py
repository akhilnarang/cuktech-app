"""Meaningful coverage boundaries: identity, duplicates, missing entries and byte checks."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cuktech_pc.firmware_coverage import audit


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        image = bytes(range(16))
        (self.root / "image.bin").write_bytes(image)
        digest = hashlib.sha256(image).hexdigest()
        self.write_json("analysis.json", {"sha256": digest})
        self.write_json("focus-meta.json", {"sha256": digest})
        self.write_rows("inventory.jsonl", [
            {"address": "403000", "decompiled": "a", "references": [
                {"to": "104500", "type": "UNCONDITIONAL_CALL"},
                {"to": "104600", "type": "DATA"}]},
            {"address": "403004", "decompiled": "b"},
            {"address": "403008", "decompiled": "c"}])
        self.write_rows("one.jsonl", [{"address": "403000", "decompiled": "a"},
                                     {"requested_address": "403006", "error": "no exact function"}])
        self.write_rows("two.jsonl", [{"address": "403000", "decompiled": "a"},
                                     {"address": "40300a", "decompiled": "new"}])
        self.write_rows("instructions.jsonl", [
            {"address": "403000", "bytes": "00010203"},
            {"address": "403002", "bytes": "0203"},
            {"address": "403000", "bytes": "00010203"}])
        self.manifest = {"image": "image.bin", "sha256": digest, "flash_base": "403000",
                         "analysis_metadata": "analysis.json", "inventory": "inventory.jsonl",
                         "focused": [{"functions": "one.jsonl", "metadata": "focus-meta.json"},
                                     {"functions": "two.jsonl"}], "instructions": ["instructions.jsonl"]}
        self.write_json("manifest.json", self.manifest)

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def write_rows(self, name, values):
        (self.root / name).write_text("\n".join(json.dumps(v) for v in values), encoding="utf-8")

    def run_audit(self):
        return audit(self.root / "manifest.json")

    def test_deduplicates_and_keeps_missing_and_revised_entries(self):
        result = self.run_audit()
        self.assertEqual(result["focused_unique_entries"], 2)
        self.assertEqual(result["focused_entries_in_inventory"], 1)
        self.assertEqual(result["focused_entries_outside_inventory"], ["0040300a"])
        self.assertEqual(len(result["focused_sources"][0]["missing_requests"]), 1)
        self.assertEqual(len(result["unselected_inventory_entries"]), 2)
        self.assertIsNone(result["semantic_review_count"])
        self.assertIsNone(result["hardware_validation_count"])
        self.assertEqual(result["direct_rom_call_targets"], ["00104500"])

    def test_overlapping_bytes_and_instruction_deduplication(self):
        result = self.run_audit()
        self.assertEqual(result["byte_checked_instruction_addresses"], 2)
        self.assertEqual(result["byte_checked_unique_flash_bytes"], 4)

    def test_rejects_image_and_sidecar_identity_mismatches(self):
        (self.root / "image.bin").write_bytes(b"bad")
        with self.assertRaisesRegex(ValueError, "image SHA"):
            self.run_audit()
        (self.root / "image.bin").write_bytes(bytes(range(16)))
        self.write_json("focus-meta.json", {"sha256": "wrong"})
        with self.assertRaisesRegex(ValueError, "focused metadata"):
            self.run_audit()

    def test_rejects_wrong_and_out_of_image_instruction_bytes(self):
        self.write_rows("instructions.jsonl", [{"address": "403000", "bytes": "ff"}])
        with self.assertRaisesRegex(ValueError, "bytes mismatch"):
            self.run_audit()
        self.write_rows("instructions.jsonl", [{"address": "402fff", "bytes": "00"}])
        with self.assertRaisesRegex(ValueError, "outside"):
            self.run_audit()

    def test_rejects_duplicate_inventory_and_duplicate_focus_entries(self):
        self.write_rows("inventory.jsonl", [{"address": "403000"}, {"address": "403000"}])
        with self.assertRaisesRegex(ValueError, "duplicate inventory"):
            self.run_audit()
        self.write_rows("inventory.jsonl", [{"address": "403000"}])
        self.write_rows("one.jsonl", [{"address": "403000"}, {"address": "403000"}])
        with self.assertRaisesRegex(ValueError, "duplicate focused"):
            self.run_audit()


if __name__ == "__main__":
    unittest.main()
