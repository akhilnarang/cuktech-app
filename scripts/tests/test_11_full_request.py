"""End-to-end request schema: MiCloudApi against a decoding fake session.

The fake session *decodes* the RC4 envelope the way the server would and
serves encoded responses back, pinning the full request shape (URL, headers,
cookies, form fields) for both bind endpoints.
"""


import base64
import json
import unittest
from typing import Any

from cuktech_pc import cloud

SSEC = base64.b64encode(b"\x42" * 16).decode()
SIGN = bytes(range(64))
CERT = bytes.fromhex("30 82 01 77") + bytes(range(96))


class FakeServerSession:
    """Implements the server half of the RC4 envelope for testing."""

    def __init__(self, responder):
        self.responder = responder  # path -> decoded-JSON dict
        self.requests: list[dict[str, Any]] = []
        self.cookies = FakeCookies()

    def request(self, method, url, **kw):
        return self.post(url, **kw)

    def post(self, url, data=None, headers=None, cookies=None, **_kw):
        form = {k: v[0] if isinstance(v, list) else v for k, v in (data or {}).items()}
        self.requests.append(
            {"url": url, "headers": headers, "cookies": cookies, "form": dict(form)}
        )
        ssecurity = form["ssecurity"]
        nonce = form["_nonce"]
        signed = cloud.signed_nonce(ssecurity, nonce)
        key = base64.b64decode(signed)
        # decrypt every encrypted field with ONE continuing keystream
        ks = cloud._rc4_keystream(key)
        decoded = {}
        for name in sorted(k for k in form if k in ("data", "rc4_hash__")):
            raw = base64.b64decode(form[name])
            decoded[name] = bytes(b ^ next(ks) for b in raw).decode()
        path = url.split("/app", 1)[1]
        # server-side checks (path-signed): rc4_hash__ over the plain data
        # map, and signature over the encrypted map
        expect_rc4h = cloud.envelope_signature(
            "POST", path, {"data": decoded["data"]}, signed
        )
        assert expect_rc4h == decoded.get(
            "rc4_hash__"
        ), "rc4_hash__ does not survive the round trip"
        expect_sig = cloud.envelope_signature(
            "POST", path, {"data": form["data"], "rc4_hash__": form["rc4_hash__"]},
            signed,
        )
        assert expect_sig == form.get(
            "signature"
        ), "signature does not survive the round trip"
        response_obj = self.responder(path, json.loads(decoded["data"]))
        payload = json.dumps(response_obj).encode()
        body = base64.b64encode(cloud.rc4_crypt(key, payload)).decode()
        return FakeResponse(200, body)


class FakeResponse:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self._content = text.encode() if text else b""
        self._content_consumed = True
        self.content = self._content


class FakeCookies(dict):
    def get(self, name, default="", domain=None):
        return dict.get(self, name, default)

    def set(self, name, value, domain=None):
        self[name] = value


def make_api(responder, region="cn"):
    session = FakeServerSession(responder)
    auth = cloud.CloudSession(user_id="424242", ssecurity=SSEC, service_token="STOK")
    return cloud.MiCloudApi(session, auth, region=region), session


class EnvelopeRoundTrip(unittest.TestCase):
    def test_applydid_full_request_schema(self):
        def responder(path, body):
            assert path == "/device/bltapplydid"
            assert body == {
                "mac": "AA:BB:CC:DD:EE:FF",
                "model": "njcuk.fitting.ad1204",
                "token": "ab" * 12,
                "did": "1234567890123456789",
            }
            return {"result": {"did": "9876543210987654321"}}

        api, session = make_api(responder)
        server_did = api.applydid(
            "AA:BB:CC:DD:EE:FF", "njcuk.fitting.ad1204", "ab" * 12,
            did="1234567890123456789",
        )
        self.assertEqual(server_did, "9876543210987654321")
        req = session.requests[0]
        self.assertEqual(req["url"], "https://api.io.mi.com/app/device/bltapplydid")
        headers = req["headers"]
        self.assertEqual(headers["MIOT-ENCRYPT-ALGORITHM"], "ENCRYPT-RC4")
        self.assertEqual(headers["Accept-Encoding"], "identity")
        self.assertEqual(headers["x-xiaomi-protocal-flag-cli"], "PROTOCAL-HTTP2")
        cookies = req["cookies"]
        self.assertEqual(cookies["userId"], "424242")
        self.assertEqual(cookies["serviceToken"], "STOK")
        form = req["form"]
        self.assertEqual(
            sorted(form),
            ["_nonce", "data", "rc4_hash__", "signature", "ssecurity"],
        )

    def test_standard_bind_full_request_schema(self):
        def responder(path, body):
            assert path == "/v2/device/ble_standard_bind"
            assert body["did"] == "9876543210987654321"
            assert body["beacon_key"] == body["props"][0]["value"]
            assert body["props"][1]["key"] == "smac"
            assert body["props"][1]["value"] == "FF:EE:DD:CC:BB:AA"
            return {
                "success": True,
                "cloud_sign": base64.b64encode(SIGN).decode(),
                "cloud_cert": base64.b64encode(CERT).decode(),
                "utc": 1760000000,
            }

        api, _ = make_api(responder)
        material = api.standard_bind(
            "9876543210987654321", "ab" * 12, "cd" * 16, "FF:EE:DD:CC:BB:AA"
        )
        self.assertEqual(material.cloud_sign, SIGN)
        self.assertEqual(material.cloud_cert, CERT)
        self.assertEqual(material.utc, 1760000000)

    def test_region_prefix(self):
        api, session = make_api(lambda p, b: {"result": {"list": []}}, region="de")
        self.assertFalse(api.device_list_contains("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(
            session.requests[0]["url"].startswith("https://de.api.io.mi.com/app/")
        )

    def test_list_devices_guard_decodes(self):
        def responder(path, body):
            assert path == "/home/device_list"
            return {"result": {"list": [{"mac": "AA:BB:CC:DD:EE:FF"}]}}

        api, _ = make_api(responder)
        self.assertTrue(api.device_list_contains("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(api.device_list_contains("ff:ee:dd:cc:bb:aa"))  # reversed
        self.assertFalse(api.device_list_contains("11:22:33:44:55:66"))

    def test_list_devices_fails_closed(self):
        # an empty list would disable the "already on account" guard
        # before a bind, so a bad answer must raise
        rows = {
            "error envelope": {"code": -8, "result": {"list": []}},
            "no result": {"code": 0},
            "result not an object": {"code": 0, "result": []},
            "no list": {"code": 0, "result": {}},
        }
        for name, answer in rows.items():
            with self.subTest(name):
                api, _ = make_api(lambda p, b, answer=answer: answer)
                with self.assertRaises(cloud.CloudError):
                    api.list_devices()

    def test_remove_device_request_body(self):
        seen = []

        def responder(path, body):
            seen.append((path, body))
            return {"code": 0}

        api, _ = make_api(responder)
        api.remove_device("blt.3.1qhp5dkqc4000", "6")
        # app DeviceApi.unbindDevice: pid is an int in the body
        self.assertEqual(seen, [(
            "/user/del_owner_device_batch",
            {"devList": [{"did": "blt.3.1qhp5dkqc4000", "pid": 6}]},
        )])

    def test_http_error_surfaces_without_body_leak(self):
        class ErrSession(FakeServerSession):
            def post(self, url, **kw):
                return FakeResponse(401, "unauthorized-detail-with-no-secrets")

        auth = cloud.CloudSession("1", SSEC, "ST")
        api = cloud.MiCloudApi(ErrSession(lambda p, b: {}), auth)
        with self.assertRaises(cloud.CloudError) as ctx:
            api.list_devices()
        msg = str(ctx.exception)
        # cli._is_confirmed_auth_rejection matches this exact token
        self.assertIn("HTTP 401", msg)
        self.assertNotIn("unauthorized-detail", msg)


if __name__ == "__main__":
    unittest.main()
