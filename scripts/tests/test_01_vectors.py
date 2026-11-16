"""External crypto vectors for cuktech_pc.crypto.

The vectors come from RFC 5869 (HKDF-SHA256), RFC 3610 (AES-CCM) and
RFC 5903 (P-256 ECDH), fetched 2026-10-12. The Mi key-schedule vectors come
from an HKDF in this file that uses only hmac and hashlib.
"""


import hashlib
import hmac
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cuktech_pc import crypto


def h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


def stdlib_hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 from RFC 5869 section 2, with only hmac and hashlib."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    block, okm = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


class HkdfRfc5869Vectors(unittest.TestCase):
    """RFC 5869 Appendix A, test cases 1-3 (SHA-256)."""

    def test_a1_basic(self):
        okm = crypto.hkdf(
            h("0b" * 22),
            salt=h("000102030405060708090a0b0c"),
            info=h("f0f1f2f3f4f5f6f7f8f9"),
            length=42,
        )
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        )

    def test_a2_longer(self):
        okm = crypto.hkdf(
            bytes(range(0x00, 0x50)),
            salt=bytes(range(0x60, 0xB0)),
            info=bytes(range(0xB0, 0x100)),
            length=82,
        )
        self.assertEqual(
            okm.hex(),
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87",
        )

    def test_a3_zero_salt_and_info(self):
        okm = crypto.hkdf(h("0b" * 22), salt=b"", info=b"", length=42)
        self.assertEqual(
            okm.hex(),
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
        )



class MiKeySchedule(unittest.TestCase):
    """Mi register and login key schedule against an independent HKDF.

    The expected hex comes from ``stdlib_hkdf`` above. It does not use
    ``cuktech_pc.crypto``. Register: salt 16 zero bytes, info
    "mible-setup-info", split 12/16/16 (docs/firmware/findings-bind.md).
    Login: salt app_rand || dev_rand, info "mible-login-info", split 16/16/4/4.
    """

    SHARED = bytes(range(0x20, 0x40))
    TOKEN = bytes(range(12))
    APP_RAND = bytes(range(0x80, 0x90))
    DEV_RAND = bytes(range(0x40, 0x50))

    def test_stdlib_hkdf_matches_rfc5869_a1(self):
        okm = stdlib_hkdf(h("0b" * 22), h("000102030405060708090a0b0c"),
                          h("f0f1f2f3f4f5f6f7f8f9"), 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_register_vector(self):
        expected = (
            "815f1b1c6aaa5178191dfbc9"  # token [0:12]
            "89b7ae80e0097ffc02c3fd41a5bbd3fe"  # bind_key [12:28]
            "b040d9a69001ce9b959a7cc82fb9562a"  # a_key [28:44]
        )
        self.assertEqual(
            stdlib_hkdf(self.SHARED, bytes(16), b"mible-setup-info", 44).hex(),
            expected,
        )
        got = crypto.derive_register(self.SHARED)
        self.assertEqual((got.token + got.bind_key + got.a_key).hex(), expected)

    def test_login_vector(self):
        expected = (
            "6fb13ed90b7904e39d535e6113ca2501"  # dev_key [0:16]
            "2853c1821b44057601eec78e61986ce6"  # app_key [16:32]
            "d26ff43f"  # dev_iv [32:36]
            "e52020cc"  # app_iv [36:40]
        )
        self.assertEqual(
            stdlib_hkdf(self.TOKEN, self.APP_RAND + self.DEV_RAND,
                        b"mible-login-info", 40).hex(),
            expected,
        )
        got = crypto.derive_login(self.TOKEN, self.APP_RAND, self.DEV_RAND)
        self.assertEqual(
            (got.dev_key + got.app_key + got.dev_iv + got.app_iv).hex(), expected
        )


class CcmRfc3610Vectors(unittest.TestCase):
    """RFC 3610 Section 8 packet vectors #1 and #13 (M=8, L=2)."""

    def test_packet_vector_1(self):
        ct = crypto.ccm_encrypt(
            h("C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF"),
            h("00 00 00 03 02 01 00 A0 A1 A2 A3 A4 A5"),
            h("08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E"),
            h("00 01 02 03 04 05 06 07"),
            tag_length=8,
        )
        self.assertEqual(
            ct.hex(),
            "588c979a61c663d2f066d0c2c0f98980"
            "6d5f6b61dac38417e8d12cfdf926e0",
        )

    def test_packet_vector_13(self):
        ct = crypto.ccm_encrypt(
            h("D7 82 8D 13 B2 B0 BD C3 25 A7 62 36 DF 93 CC 6B"),
            h("00 41 2B 4E A9 CD BE 3C 96 96 76 6C FA"),
            h(
                "08 E8 CF 97 D8 20 EA 25 84 60 E9 6A D9 CF 52 89"
                " 05 4D 89 5C EA C4 7C"
            ),
            h("0B E1 A8 8B AC E0 18 B1"),
            tag_length=8,
        )
        self.assertEqual(
            ct.hex(),
            "4cb97f86a2a4689a877947ab8091ef53"
            "86a6ffbdd080f8e78cf7cb0cddd7b3",
        )


class BindBlobCrypto(unittest.TestCase):
    """The 92-byte v2 blob layout and its CCM parameters."""

    DID = b"\x00" + b"1234567890123456789"
    SIGN = bytes(range(64))
    A_KEY = b"\x77" * 16

    def test_layout_and_roundtrip(self):
        blob = crypto.build_bind_blob(self.DID, self.SIGN, 0x660E13, self.A_KEY)
        self.assertEqual(len(blob), 92)
        # buildEncryptData: nonce 0x10..0x1b, AAD "devID", 4-byte tag
        ccm = AESCCM(self.A_KEY, tag_length=4)
        pt = ccm.decrypt(bytes(range(0x10, 0x1C)), blob, b"devID")
        self.assertEqual(pt[:20], self.DID)
        self.assertEqual(pt[20:84], self.SIGN)
        self.assertEqual(pt[84:88], (0x660E13).to_bytes(4, "little"))
        with self.assertRaises(InvalidTag):
            ccm.decrypt(bytes(range(0x10, 0x1C)), blob, b"devid")

    def test_rejects_bad_material(self):
        with self.assertRaises(ValueError):
            crypto.build_bind_blob(b"\x00" * 19, self.SIGN, 1, self.A_KEY)
        with self.assertRaises(ValueError):
            crypto.build_bind_blob(self.DID, b"\x00" * 63, 1, self.A_KEY)
        with self.assertRaises(ValueError):
            crypto.build_bind_blob(self.DID, self.SIGN, 0, self.A_KEY)
        with self.assertRaises(ValueError):
            crypto.build_bind_blob(self.DID, self.SIGN, 0x1_0000_0000, self.A_KEY)


class EcdhRfc5903(unittest.TestCase):
    """RFC 5903 section 8.1 (P-256) through the 64-byte X||Y wire form."""

    I = int("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433", 16)
    GI = h("DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180"
           "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3")
    GR = h("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63"
           "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB")
    GIRX = h("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")

    def test_public_key_wire_form(self):
        priv = ec.derive_private_key(self.I, ec.SECP256R1())
        self.assertEqual(crypto.public_key_to_bytes(priv.public_key()), self.GI)

    def test_shared_secret(self):
        priv = ec.derive_private_key(self.I, ec.SECP256R1())
        peer = crypto.bytes_to_public_key(self.GR)
        self.assertEqual(crypto.ecdh_shared(priv, peer), self.GIRX)

    def test_bytes_to_public_key_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            crypto.bytes_to_public_key(b"\x04" + self.GI)  # 65 B
        with self.assertRaises(ValueError):
            crypto.bytes_to_public_key(self.GI[:63] + bytes([self.GI[63] ^ 1]))  # off curve


if __name__ == "__main__":
    unittest.main()
