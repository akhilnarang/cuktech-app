"""RC4 request envelope: known-answer vectors, nonce layout and response decoding.

The RC4 vector is from RFC 6229. The envelope vector was derived by hand,
without cuktech_pc: hashlib for SHA-256 and SHA-1, and a separate RC4
implementation that gives the RFC 6229 rows. The steps are in the comment
above GOLDEN_FORM.
"""


import base64
import gzip
import unittest
from unittest import mock

from cuktech_pc import cloud

# fixed inputs (never real secrets)
SEC = base64.b64encode(bytes(range(16))).decode()  # "AAECAwQFBgcICQoLDA0ODw=="
# 8 bytes 0x64..0x6b, then the BE u32 minute bucket of 1234567890000 ms:
# 1234567890000 // 60000 = 20576131 = 0x0139f783.
NONCE = "ZGVmZ2hpamsBOfeD"
# b64(SHA-256(b64d(SEC) || b64d(NONCE))). This is also the RC4 key.
SN = "InCAKumOW67IXJ+64Ub9fbSAWb461ETbqtftEyQNqBY="
DATA = '{"mac":"AA:BB:CC:DD:EE:FF"}'
PATH = "/device/bltapplydid"

# Hand derivation of the /app form (laq.encrypt, vo4.generateSignature):
# 1. rc4_hash__ plain = b64(SHA-1("POST&/device/bltapplydid&data=<DATA>&<SN>"))
#    = "khsFbGwXB0eS2a1DjCjVUPlCa2U=".
# 2. One RC4-drop1024 stream with key b64d(SN) encrypts the params in
#    sorted-key order: "data" uses keystream bytes 0..27 after the drop,
#    "rc4_hash__" continues at byte 28. A per-param reset gives
#    "PFyfARZnil/BE73zLrtxUs05nW71S1YmIjp/ww==" for rc4_hash__ (wrong).
# 3. signature = b64(SHA-1("POST&<PATH>&data=<enc>&rc4_hash__=<enc>&<SN>")).
#    Without the path, the value is "KXeQ9VfwNImaN53rG1oHuBZJ5Yw=" (wrong).
GOLDEN_FORM = {
    "data": "LBaBJhcCxyXCYuLiXuADVZ0+swLlXgAjBSpX",
    "rc4_hash__": "lSsvBIsBsExGsICN6vz8vWf/GmyctuJ+Nw68EA==",
    "signature": "ncPMEDcOyGOhmW6C5gxCIE+nUaE=",
    "ssecurity": SEC,
    "_nonce": NONCE,
}


class NonceAndSignature(unittest.TestCase):
    def test_nonce_layout(self):
        with mock.patch.object(cloud.os, "urandom",
                               return_value=bytes(range(100, 108))):
            nonce = cloud.generate_nonce(now_ms=1234567890000)
        self.assertEqual(nonce, NONCE)
        raw = base64.b64decode(nonce)
        self.assertEqual(raw[:8], bytes(range(100, 108)))  # randomness
        self.assertEqual(raw[8:], bytes.fromhex("0139f783"))  # BE minute bucket


class RequestForm(unittest.TestCase):
    def test_golden_form(self):
        self.assertEqual(cloud.signed_nonce(SEC, NONCE), SN)
        form = cloud.build_request_form(SEC, NONCE, SN, DATA, PATH)
        self.assertEqual(form, GOLDEN_FORM)

    def test_rc4_drop_1024(self):
        # RFC 6229 section 2, key length 256 bits, key 0x0102...20,
        # row "DEC 1024 HEX 400". Encrypting zero bytes gives the keystream.
        key = bytes(range(1, 33))
        expected = bytes.fromhex("7fec5bfd9f9b89ce6548309092d7e958")
        self.assertEqual(cloud.rc4_crypt(key, bytes(16)), expected)
        self.assertEqual(cloud.rc4_crypt(key, expected), bytes(16))  # symmetric


class ResponseDecoding(unittest.TestCase):
    def _enc(self, payload: bytes) -> str:
        return base64.b64encode(
            cloud.rc4_crypt(base64.b64decode(SN), payload)
        ).decode()

    def test_gzip_branch(self):
        gz = gzip.compress(b'{"ok":true}')
        body = self._enc(gz)
        self.assertEqual(
            cloud.decode_response_body(SEC, NONCE, body, "GZIP"),
            {"ok": True},
        )

    def test_gzip_header_without_magic_rejected(self):
        body = self._enc(b"not-gzip-at-all")
        with self.assertRaises(cloud.CloudResponseError):
            cloud.decode_response_body(SEC, NONCE, body, "GZIP")

    def test_b64_field_urlsafe_wrapped_unpadded(self):
        # the app decodes with URL_SAFE (flags 24); live server sent '-'/'_'
        sign = bytes(range(192, 256))  # encodes with '-' and '_' chars
        enc = base64.urlsafe_b64encode(sign).decode()
        self.assertTrue("-" in enc or "_" in enc)
        wrapped = enc.rstrip("=")[:40] + "\n" + enc.rstrip("=")[40:]
        self.assertEqual(cloud.decode_b64_field(wrapped), sign)

    def test_b64_field_bounds(self):
        with self.assertRaises(cloud.CloudResponseError):
            cloud.decode_b64_field("")
        with self.assertRaises(cloud.CloudResponseError):
            cloud.decode_b64_field("!!!not-base64!!!")

    def test_gunzip_size_cap(self):
        bomb = gzip.compress(b"\x00" * (cloud.GUNZIP_MAX_BYTES + 100))
        with self.assertRaises(cloud.CloudResponseError):
            cloud.gunzip_bounded(bomb)


if __name__ == "__main__":
    unittest.main()
