"""DID normalization (cutBeforeBytes + fillBeforeBytes) and devinfo parsing."""


import asyncio
import unittest

from cuktech_pc import crypto
from cuktech_pc.blebind import MiAuthError, V2RegisterClient
from tests.fakepeer import FakeBleClient

DEVINFO_24 = b"\x02\x00\x00\x00\x00" + b"1234567890123456789"


class NormalizeDid(unittest.TestCase):
    def test_19_ascii_net(self):
        # strip the leading 0x00 byte, then left-pad back to 20
        self.assertEqual(
            crypto.normalize_did(b"\x00" + b"1234567890123456789"),
            b"\x00" + b"1234567890123456789",
        )
        # already-stripped input pads identically
        self.assertEqual(
            crypto.normalize_did(b"1234567890123456789"),
            b"\x00" + b"1234567890123456789",
        )

    def test_shorter_did_left_padded(self):
        self.assertEqual(
            crypto.normalize_did(b"12345"),
            b"\x00" * 15 + b"12345",
        )

    def test_full_20_passthrough(self):
        raw = bytes(range(1, 21))
        self.assertEqual(crypto.normalize_did(raw), raw)

    def test_too_long_rejected(self):
        with self.assertRaises(ValueError):
            crypto.normalize_did(b"x" * 21)

    def test_all_zero_bytes_become_20_zeros(self):
        self.assertEqual(crypto.normalize_did(b"\x00" * 8), b"\x00" * 20)

    def test_string_input(self):
        self.assertEqual(
            crypto.normalize_did("1234567890123456789"),
            b"\x00" + b"1234567890123456789",
        )

    def test_only_strips_leading_zero_bytes_not_zero_digits(self):
        # an ASCII '0' digit is NOT stripped (b23 cuts 0x00 bytes only)
        self.assertEqual(
            crypto.normalize_did(b"0123456789012345678"),
            b"\x00" + b"0123456789012345678"[:19],
        )
        self.assertEqual(len(crypto.normalize_did(b"0" * 19)), 20)


class ParseDevInfo(unittest.TestCase):
    def test_v2_blob(self):
        info = crypto.parse_devinfo(DEVINFO_24)
        self.assertEqual(info.version, 2)
        self.assertEqual(info.caps_in_out, 0)
        self.assertEqual(info.caps2, 0)
        self.assertEqual(info.factory_did_text, "1234567890123456789")
        self.assertEqual(info.did_field, b"\x00" + b"1234567890123456789")

    def test_version_gate(self):
        with self.assertRaises(crypto.DevInfoError):
            crypto.parse_devinfo(b"\x04\x00\x00\x00")
        with self.assertRaises(crypto.DevInfoError):
            crypto.parse_devinfo(b"\x01\x02")  # too short

    def test_get_devinfo_rejects_non_v2_and_oob_devices(self):
        did = b"\x00" + b"1234567890123456789"
        rows = {
            "v1": b"\x01\x00\x00\x00" + did,
            "v3": b"\x03\x00\x00\x00" + did,
            "oob input caps": b"\x02\x00\x01\x00" + did,
        }
        for name, blob in rows.items():
            with self.subTest(name):
                peer = FakeBleClient(devinfo=blob)

                async def scenario():
                    async with V2RegisterClient(peer, timeout=1.0) as reg:
                        await reg.get_devinfo()

                with self.assertRaises(MiAuthError):
                    asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
