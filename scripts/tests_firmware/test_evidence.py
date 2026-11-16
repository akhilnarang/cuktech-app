"""Offline evidence lookup boundaries, provenance, and command-line failures."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from cuktech_pc.firmware_evidence import AnalysisIndex, address, address_range, main


def reference(source, target, kind, owner=None):
    result = {"from": source, "to": target, "type": kind}
    if owner:
        result["function"] = owner
    return result


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.functions = [
            {"address": "00403000", "name": "entry", "decompiled": "hello world",
             "references": [reference("00403002", "2000c934", "READ"),
                            reference("00403004", "2000c938", "WRITE"),
                            reference("00403006", "00403100", "UNCONDITIONAL_CALL"),
                            reference("00403008", "00403200", "DATA")], "callers": []},
            {"address": "00403100", "name": "worker", "references": [],
             "callers": [reference("00403006", "00403100", "UNCONDITIONAL_CALL", "00403000"),
                         reference("00403008", "00403100", "DATA", "00403000")]},
            {"address": "00403200", "name": "data_target", "references": []},
        ]
        self.strings = [{"address": "00404000", "value": "BEAST MODE",
                         "references": [reference("00403102", "00404000", "PARAM", "00403100")]}]
        self.write()

    def write(self):
        (self.root / "analysis.json").write_text(json.dumps({"program": "fixture.bin", "sha256": "abc",
                                                              "limitations": ["fixture only"]}))
        for name, rows in [("functions.jsonl", self.functions), ("strings.jsonl", self.strings)]:
            (self.root / name).write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    def test_hexadecimal_and_inclusive_address_ranges(self):
        self.assertEqual(address("10"), 16)
        self.assertEqual(address("0X2000C934"), 0x2000c934)
        self.assertEqual(address_range("0000:ffff"), (0, 65535))
        self.assertEqual(address_range("ffffffffffffffff"), (2**64 - 1, 2**64 - 1))
        for value in ("", "-1", "12:11", "1:2:3", ":2", "ram:2000", "10000000000000000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                address_range(value)
        with self.assertRaises(ValueError):
            address(True)

    def test_incoming_read_write_range_and_empty_boundary(self):
        index = AnalysisIndex(self.root)
        result = index.incoming("2000c934:2000c938", [], 20, 0)["references"]
        self.assertEqual(result["total"], 2)
        self.assertEqual([r["type"] for r in result["items"]], ["READ", "WRITE"])
        self.assertEqual(result["items"][0]["function"], "00403000")
        self.assertEqual(index.incoming("2000c935:2000c937", [], 20, 0)["references"]["total"], 0)
        self.assertEqual(index.incoming("2000c934:2000c938", ["write"], 20, 0)["references"]["total"], 1)
        self.assertEqual(index.incoming("2000c934", [], 20, 0)["references"]["total"], 1)

    def test_deduplication_and_string_reference_provenance(self):
        index = AnalysisIndex(self.root)
        refs = index.incoming("00403100", ["UNCONDITIONAL_CALL"], 20, 0)["references"]
        self.assertEqual(refs["total"], 1)  # Present in outgoing references AND callers.
        string = index.search_strings("beast", 5, 0, 4)["strings"]["items"][0]
        self.assertEqual(string["value"], {"text": "BEAS", "characters": 10, "truncated": True})
        self.assertEqual(string["references"]["items"][0]["function"], "00403100")
        with self.assertRaises(ValueError):
            index.search_strings("", 5, 0, 5)

    def test_exact_function_lookup_text_clipping_and_pagination(self):
        index = AnalysisIndex(self.root)
        self.assertEqual(index.function("entry", 1, 5)["decompiled"]["text"], "hello")
        self.assertEqual(index.function("00403000", 1, 0)["references"]["total"], 4)
        with self.assertRaises(ValueError):
            index.function("00403002", 1, 5)  # Interior address is not an entry point.
        refs = index.incoming("2000c934:2000c938", [], 1, 1)["references"]
        self.assertEqual(refs["items"][0]["type"], "WRITE")
        self.assertTrue(refs["truncated"])
        self.assertEqual(index.incoming("2000c934", [], 2, 99)["references"]["returned"], 0)

    def test_neighborhood_excludes_data_and_stops_at_search_budget(self):
        index = AnalysisIndex(self.root)
        graph = index.neighborhood("00403000", "callees", 1, 20, 20)
        self.assertEqual([n["address"] for n in graph["nodes"]["items"]], ["00403000", "00403100"])
        self.assertEqual(graph["edges"]["total"], 1)
        callers = index.neighborhood("00403100", "callers", 1, 20, 20)
        self.assertEqual(callers["edges"]["items"], [{"caller": "00403000", "callee": "00403100"}])
        self.assertTrue(index.neighborhood("00403000", "both", 2, 20, 1)["search_truncated"])
        self.assertEqual(index.neighborhood("00403000", "both", 0, 20, 20)["edges"]["total"], 0)

    def test_empty_exports_and_malformed_rows(self):
        self.functions = []
        self.strings = []
        self.write()
        self.assertEqual(AnalysisIndex(self.root).identity()["loaded_function_count"], 0)
        (self.root / "functions.jsonl").write_text('{"address":"oops"}')
        with self.assertRaisesRegex(ValueError, "functions.jsonl:1"):
            AnalysisIndex(self.root)
        (self.root / "functions.jsonl").write_text("[]")
        with self.assertRaisesRegex(ValueError, "record must be an object"):
            AnalysisIndex(self.root)
        (self.root / "functions.jsonl").write_text('{"address":"00403000","references":[{}]}')
        with self.assertRaisesRegex(ValueError, "functions.jsonl:1"):
            AnalysisIndex(self.root)

    def test_ghidra_stack_targets_preserved_but_not_numeric_references(self):
        self.functions[0]["references"].append(reference("0040300a", "Stack[-0x28]", "WRITE"))
        self.write()
        index = AnalysisIndex(self.root)
        self.assertEqual(index.identity()["excluded_stack_reference_occurrences"], 1)
        self.assertEqual(index.function("entry", 20, 0)["references"]["items"][-1]["to"], "Stack[-0x28]")
        self.assertEqual(index.incoming("0:ffffffffffffffff", ["WRITE"], 20, 0)["references"]["total"], 1)

    def test_cli_identity_fingerprints_bounds_and_failures(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["--analysis", str(self.root), "--limit", "1", "refs", "2000c934:2000c938"])
        self.assertEqual(status, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["analysis"]["program"], "fixture.bin")
        # Independent digest of the fixture file on disk.
        self.assertEqual(payload["analysis"]["export_file_sha256"]["functions.jsonl"],
                         hashlib.sha256((self.root / "functions.jsonl").read_bytes()).hexdigest())
        self.assertEqual(payload["result"]["references"]["returned"], 1)
        self.assertIn("fixture only", payload["limitations"])
        error = io.StringIO()
        with redirect_stderr(error):
            self.assertEqual(main(["--analysis", str(self.root), "refs", "3:2"]), 2)
        self.assertIn("precedes", error.getvalue())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(["--analysis", str(self.root), "--limit", "0", "identity"])
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
