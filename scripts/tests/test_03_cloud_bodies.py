"""Exact request-body schemas for the two bind endpoints (h37.java)."""


import json
import unittest

from cuktech_pc import cloud


class ApplyDidBody(unittest.TestCase):
    def test_minimal(self):
        body = json.loads(
            cloud.build_applydid_body(
                "AA:BB:CC:DD:EE:FF", "njcuk.fitting.ad1204", "ab" * 12
            )
        )
        self.assertEqual(
            body,
            {
                "mac": "AA:BB:CC:DD:EE:FF",
                "model": "njcuk.fitting.ad1204",
                "token": "ab" * 12,
            },
        )
        self.assertNotIn("did", body)  # omitted when empty (app L1781-1783)

    def test_key_order_matches_app(self):
        raw = cloud.build_applydid_body(
            "AA:BB:CC:DD:EE:FF", "njcuk.fitting.ad1204", "ab" * 12,
            did="123", home={"homeId": 1, "uid": 2},
        )
        # key order and values (app h37 L1772-1790)
        self.assertEqual(
            list(json.loads(raw).items()),
            [("mac", "AA:BB:CC:DD:EE:FF"), ("model", "njcuk.fitting.ad1204"),
             ("token", "ab" * 12), ("homeId", 1), ("uid", 2), ("did", "123")],
        )


class StandardBindBody(unittest.TestCase):
    def test_exact_schema(self):
        raw = cloud.build_standard_bind_body(
            "1234567890123456789", "ab" * 12, "cd" * 16, "FF:EE:DD:CC:BB:AA"
        )
        body = json.loads(raw)
        self.assertEqual(
            body,
            {
                "did": "1234567890123456789",
                "token": "ab" * 12,
                "props": [
                    {"type": "prop", "key": "bind_key", "value": "cd" * 16},
                    {"type": "prop", "key": "smac", "value": "FF:EE:DD:CC:BB:AA"},
                ],
                "beacon_key": "cd" * 16,
            },
        )

    def test_home_fields_appended_last(self):
        raw = cloud.build_standard_bind_body(
            "d", "t", "cd" * 16, "S", home={"homeId": 9, "uid": 8}
        )
        self.assertEqual(
            list(json.loads(raw).keys()),
            ["did", "token", "props", "beacon_key", "homeId", "uid"],
        )


if __name__ == "__main__":
    unittest.main()
