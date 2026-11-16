import struct
import unittest
import zlib

from cuktech_pc.firmware_bitmaps import bitmap_assets, decode_rgb565, rgb565_png


class BitmapTests(unittest.TestCase):
    def test_literal_and_marker_runs_preserve_color_words(self):
        encoded = bytes.fromhex("00f8 0301 e007 1f00")
        words, consumed = decode_rgb565(encoded + b"tail", 5, 1)
        self.assertEqual(words, bytes.fromhex("00f8 e007 e007 e007 1f00"))
        self.assertEqual(consumed, len(encoded))

    def test_zero_marker_is_raw_and_zero_count_wraps_to_256(self):
        self.assertEqual(decode_rgb565(bytes.fromhex("0000 0100"), 2, 0), (bytes.fromhex("0000 0100"), 4))
        self.assertEqual(decode_rgb565(bytes.fromhex("0006 3412"), 256, 6), (bytes.fromhex("3412") * 256, 4))

    def test_rejects_truncation_overrun_and_invalid_budget(self):
        for data, pixels, marker in [(b"\x00", 1, 0), (b"\x02\x01", 2, 1),
                                     (bytes.fromhex("0301 0000"), 2, 1), (b"", 0, 1), (b"", 1, 256)]:
            with self.subTest(data=data, pixels=pixels, marker=marker):
                with self.assertRaises(ValueError):
                    decode_rgb565(data, pixels, marker)

    def test_descriptor_scan_rejects_bad_dimensions_and_source(self):
        base = 0x403000
        payload = bytearray(100)
        struct.pack_into("<HHHHI", payload, 0, 2, 1, 16, 1, base + 80)
        struct.pack_into("<HHHHI", payload, 12, 2, 0, 16, 1, base + 80)
        struct.pack_into("<HHHHI", payload, 24, 2, 1, 16, 1, base + 100)
        payload[80:84] = bytes.fromhex("0201 00f8")
        records = bitmap_assets(bytes(payload), base)
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0]["width"], records[0]["height"], records[0]["source_size"]), (2, 1, 4))

    def test_png_encodes_rgb565_endpoints_and_valid_chunk_crcs(self):
        png = rgb565_png(bytes.fromhex("00f8 e007 1f00"), 3, 1)
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        cursor, compressed = 8, bytearray()
        while cursor < len(png):
            length = struct.unpack_from(">I", png, cursor)[0]
            tag, payload = png[cursor+4:cursor+8], png[cursor+8:cursor+8+length]
            crc = struct.unpack_from(">I", png, cursor+8+length)[0]
            self.assertEqual(crc, zlib.crc32(tag + payload))
            if tag == b"IDAT":
                compressed.extend(payload)
            cursor += length + 12
        self.assertEqual(zlib.decompress(compressed), b"\x00\xff\x00\x00\x00\xff\x00\x00\x00\xff")
        with self.assertRaises(ValueError):
            rgb565_png(b"", 3, 1)


if __name__ == "__main__":
    unittest.main()
