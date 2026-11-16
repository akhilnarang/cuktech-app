import hashlib
import unittest

from cuktech_pc.firmware_data_audit import aes_sbox, sha256_constants, gaps


class DataAuditTests(unittest.TestCase):
    def test_independent_crypto_tables_match_retained_table_identities(self):
        # FIPS-197 Figure 7: S-box row 0, and S(0x53) = 0xed (Section 5.1.1 example).
        self.assertEqual(aes_sbox()[:16], bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"))
        self.assertEqual(aes_sbox()[0x53], 0xed)
        # FIPS 180-4 Section 4.2.2: K0 = 0x428a2f98, K1 = 0x71374491, K63 = 0xc67178f2, little-endian words.
        self.assertEqual(sha256_constants()[:8], bytes.fromhex("982f8a4291443771"))
        self.assertEqual(sha256_constants()[-4:], bytes.fromhex("f27871c6"))
        # Whole-table digests of the two standard tables above.
        self.assertEqual(hashlib.sha256(aes_sbox()).hexdigest(),
                         'c2d8e5eed6cbebd8625fc18f81486a7733c04f9b0129ffbe974c68b90308b4f2')
        self.assertEqual(hashlib.sha256(sha256_constants()).hexdigest(),
                         '74ef7306e7452d6859b6463ce496b8df30925f69e1b2969e1f3f34bbc9c6af04')

    def test_gaps_clip_merge_overlap_and_keep_end_exclusive(self):
        self.assertEqual(gaps(10, 30, [(0, 12), (11, 15), (18, 20), (20, 24), (28, 50)]),
                         [(15, 18), (24, 28)])
        self.assertEqual(gaps(10, 30, []), [(10, 30)])
        self.assertEqual(gaps(10, 10, [(0, 99)]), [])
        with self.assertRaises(ValueError):
            gaps(30, 10, [])
