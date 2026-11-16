"""Scan guards: FE95 registered bit, pid table (CN + overseas), smac format."""


import unittest

from cuktech_pc import cloud
from cuktech_pc.fe95 import (
    AD1204U_PRODUCT_IDS,
    PID_MODEL_HINTS,
    parse_fe95,
    smac_matches_address,
)

MAC_INCLUDE = 0x0010  # frame-control bit: payload carries the MAC


def frame(fc: int, pid: int, mac_le: bytes = b"\x11\x22\x33\x44\x55\x66",
          extra: bytes = b"") -> bytes:
    return fc.to_bytes(2, "little") + pid.to_bytes(2, "little") + b"\x07" + mac_le + extra


class FrameControlBits(unittest.TestCase):
    def test_registered_bit(self):
        self.assertTrue(parse_fe95(frame(0x0100, 0x660E)).registered)
        self.assertFalse(parse_fe95(frame(0x0000, 0x660E)).registered)

    def test_solicited_bit(self):
        self.assertTrue(parse_fe95(frame(0x0200, 0x660E)).solicited)
        self.assertFalse(parse_fe95(frame(0x0000, 0x660E)).solicited)

    def test_auth_mode_bits(self):
        self.assertEqual(parse_fe95(frame(0x0C00, 0x660E)).auth_mode, 3)
        self.assertEqual(parse_fe95(frame(0x0800, 0x660E)).auth_mode, 2)
        self.assertEqual(parse_fe95(frame(0x0000, 0x660E)).auth_mode, 0)

    def test_two_byte_frame_still_has_bits(self):
        # the minimum parseable frame (fc only) still reports the bits
        f = parse_fe95(b"\x00\x01")  # fc = 0x0100 -> registered
        self.assertTrue(f.registered)
        self.assertFalse(f.solicited)
        self.assertEqual(f.product_id, None)


class ProductIdTable(unittest.TestCase):
    def test_cn_and_overseas_pids_accepted(self):
        self.assertIn(0x660E, AD1204U_PRODUCT_IDS)  # CN, 26126 decimal
        self.assertIn(0x8AB9, AD1204U_PRODUCT_IDS)  # overseas, 35513 decimal
        self.assertEqual(PID_MODEL_HINTS[0x660E], "njcuk.fitting.ad1204")
        self.assertEqual(PID_MODEL_HINTS[0x8AB9], "njcuk.fitting.1204e")

    def test_transcription_error_pid_rejected(self):
        # 0x8AD9 is the known wrong transcription of the overseas pid
        self.assertNotIn(0x8AD9, AD1204U_PRODUCT_IDS)


class SmacFormat(unittest.TestCase):
    def test_uppercase_colon_reversed(self):
        # the MAC field is little-endian: the text is the bytes reversed,
        # uppercase hex, colon-separated
        for mac_le, text in (
            ("112233445566", "66:55:44:33:22:11"),
            ("aabbccddeeff", "FF:EE:DD:CC:BB:AA"),
        ):
            with self.subTest(mac_le):
                f = parse_fe95(frame(MAC_INCLUDE, 0x660E, mac_le=bytes.fromhex(mac_le)))
                self.assertTrue(f.mac_include)
                self.assertEqual(f.mac_address, text)

    def test_frame_without_mac(self):
        f = parse_fe95(b"\x00\x00\x0e\x66\x07")
        self.assertIsNone(f.mac_address)


class MacIncludeBit(unittest.TestCase):
    """Positional bytes are only a MAC when the flag says so."""

    def test_no_flag_no_mac_even_with_11_bytes(self):
        f = parse_fe95(frame(0x0000, 0x660E))  # 11 bytes, bit clear
        self.assertIsNone(f.mac_address)
        self.assertTrue(f.mac_include is False)


class SmacMatchGuard(unittest.TestCase):
    """The smac must belong to the selected address, else abort."""

    def _frame(self, mac_le: bytes) -> object:
        return parse_fe95(frame(MAC_INCLUDE, 0x660E, mac_le=mac_le))

    def test_same_bytes_same_order(self):
        f = self._frame(bytes.fromhex("213243546576"))  # LE of 76:65:54:43:32:21
        self.assertTrue(smac_matches_address(f, "76:65:54:43:32:21"))

    def test_same_bytes_reversed_order(self):
        f = self._frame(bytes.fromhex("213243546576"))
        # the decoded smac is 76:65:54:43:32:21; selecting the LE-written
        # form 21:32:43:54:65:76 must still match (same bytes, either order)
        self.assertTrue(smac_matches_address(f, "21:32:43:54:65:76"))

    def test_different_bytes_rejected(self):
        f = self._frame(bytes.fromhex("213243546576"))
        self.assertFalse(smac_matches_address(f, "AA:BB:CC:DD:EE:FF"))
        # a single-byte difference is still a mismatch (non-palindromic MAC)
        self.assertFalse(smac_matches_address(f, "76:65:54:43:32:20"))

    def test_no_mac_never_matches(self):
        f = parse_fe95(frame(0x0000, 0x660E))
        self.assertFalse(smac_matches_address(f, "76:65:54:43:32:21"))


class NonPalindromeByteReversal(unittest.TestCase):
    """MAC reversal must be BYTE-wise, not character-wise."""

    def test_reverse_mac_bytes_non_palindromic(self):
        # 12:34:56:78:9A:BC -> BC:9A:78:56:34:12 (bytes), NOT "cb:a9:..." (chars)
        self.assertEqual(
            cloud.reverse_mac_bytes("12:34:56:78:9A:BC"), "bc9a78563412"
        )

    def test_device_list_guard_uses_byte_reversal(self):
        api = cloud.MiCloudApi(
            session=object(), auth=cloud.CloudSession("1", "AAAA", "BBBB"),
        )
        for listed, expected in (
            ("12:34:56:78:9A:BC", True),   # raw order
            ("BC:9A:78:56:34:12", True),   # byte-reversed
            ("cb:a9:87:65:43:21", False),  # char-reversed
        ):
            with self.subTest(listed):
                api.list_devices = lambda m=listed: [{"mac": m}]
                self.assertEqual(api.device_list_contains("12:34:56:78:9A:BC"), expected)


if __name__ == "__main__":
    unittest.main()
