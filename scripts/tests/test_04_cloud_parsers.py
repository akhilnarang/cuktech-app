"""Response parsers for the two bind endpoints, incl. rejection rules."""


import base64
import gzip
import unittest

from cuktech_pc import cloud

SIGN = bytes(range(64))
CERT = bytes.fromhex("30 82 01 77") + b"\x00" * 100  # pseudo-DER, non-empty


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def gz_b64(data: bytes) -> str:
    return base64.b64encode(gzip.compress(data)).decode()


class ParseApplyDid(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(
            cloud.parse_applydid({"result": {"did": "12345678901234567"}}),
            "12345678901234567",
        )

    def test_ok_unwrapped(self):
        # some /app responses deliver the payload at top level
        self.assertEqual(
            cloud.parse_applydid({"did": "98765432109876543"}),
            "98765432109876543",
        )

    def test_missing_or_empty(self):
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_applydid({"result": {}})
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_applydid({"result": {"did": "  "}})
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_applydid({})


class ParseBindResponse(unittest.TestCase):
    def base(self, **over):
        obj = {"success": True, "cloud_sign": b64(SIGN), "cloud_cert": b64(CERT), "utc": 1760000000}
        obj.update(over)
        for k, v in list(obj.items()):
            if v is None:
                del obj[k]
        return obj

    def test_ok_plain_b64(self):
        m = cloud.parse_bind_response(self.base())
        self.assertEqual(m.cloud_sign, SIGN)
        self.assertEqual(m.cloud_cert, CERT)
        self.assertEqual(m.utc, 1760000000)

    def test_ok_gzipped_fields(self):
        m = cloud.parse_bind_response(
            self.base(cloud_sign=gz_b64(SIGN), cloud_cert=gz_b64(CERT))
        )
        self.assertEqual(m.cloud_sign, SIGN)
        self.assertEqual(m.cloud_cert, CERT)

    def test_ok_result_wrapped(self):
        m = cloud.parse_bind_response({"result": self.base()})
        self.assertEqual(m.cloud_sign, SIGN)
        self.assertEqual(m.utc, 1760000000)

    def test_success_false_rejected(self):
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(success=False))

    def test_cloud_sign_must_be_64_bytes(self):
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(cloud_sign=b64(bytes(63))))
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(cloud_sign=b64(bytes(65))))

    def test_missing_fields_rejected(self):
        for key in ("cloud_sign", "cloud_cert", "utc"):
            with self.assertRaises(cloud.CloudResponseError):
                cloud.parse_bind_response(self.base(**{key: None}))

    def test_utc_range(self):
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(utc=0))
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(utc=0x1_0000_0000))
        with self.assertRaises(cloud.CloudResponseError):
            cloud.parse_bind_response(self.base(utc="not-a-number"))


if __name__ == "__main__":
    unittest.main()
