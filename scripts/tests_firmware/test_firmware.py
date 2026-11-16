"""Offline package-boundary, signature and download tests. No accounts or Bluetooth."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
import requests

from cuktech_pc.firmware import fetch, inspect_image, official_download_url, verify_package_signature
from tests_firmware.fixtures import image, raw_image, signed_package

MODEL_TLV = b"\x04\x14njcuk.fitting.ad1204"

# A tripwire at the transport boundary. A test that expects HTTP patches it again with a fake.
_network_guard = patch("requests.adapters.HTTPAdapter.send", side_effect=AssertionError("network is forbidden in firmware tests"))


def setUpModule():
    _network_guard.start()


def tearDownModule():
    _network_guard.stop()


class FirmwareTests(unittest.TestCase):
    def test_signed_tag_model_version_and_lengths(self):
        result = inspect_image(image())
        self.assertEqual(result["model"], "njcuk.fitting.ad1204")
        self.assertEqual(result["version"], "2.1.2_0073")
        self.assertEqual(result["product_id"], 0x660E)
        self.assertEqual(result["signature_size"], 9)

    def test_raw_image_is_not_claimed_as_signed(self):
        self.assertFalse(inspect_image(image(False))["signed_package"])

    def test_rejects_malformed_or_foreign_packages(self):
        tlv_overrun = bytearray(image())
        tlv_overrun[1024 + 29] = 255  # Length byte of the first TLV (tag header is 28 bytes, then the type byte).
        rows = [("1204e product ID on an ad1204 model", image(pid=0x8AB9), "unknown model"),
                ("certificate length past the end", image(cert_size=65535), "boundaries"),
                ("tag header cut at 16 bytes", image()[:1040], "truncated signed-package header"),
                ("TLV length past the tag", bytes(tlv_overrun), "TLV"),
                ("HTML body", b"<html>" + b"x" * 1024, "R2SF"),
                ("declared tag size under 32", image(tag_size=31), "boundaries"),
                ("one stray byte after the last TLV", image(tlv=MODEL_TLV + b"\x07"), "truncated signed-package TLV"),
                ("no version TLV", image(tlv=MODEL_TLV), "missing its version"),
                ("version TLV 4 bytes long", image(tlv=b"\x01\x04\x02\x01\x02\x49" + MODEL_TLV), "missing its version")]
        for name, blob, message in rows:
            with self.subTest(name), self.assertRaisesRegex(ValueError, message):
                inspect_image(blob)

    def test_official_cdn_and_lookalike_hosts(self):
        good = "https://iot-ota-cdn.io.mi.com/miio_fw/example.bin"
        self.assertEqual(official_download_url(good), good)
        for value in ("http://iot-ota-cdn.io.mi.com/a", "https://mi.com.attacker.example/a",
                      "https://attacker-mi.com/a", "https://user:secret@iot-ota-cdn.io.mi.com/a",
                      "https://iot-ota-cdn.io.mi.com:8443/a"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                official_download_url(value)

    def test_package_signature_chain_and_image_signature(self):
        verify_package_signature(package := signed_package(), inspect_image(package))
        rows = [("image signed by an unrelated key", "image", InvalidSignature, ""),
                ("developer certificate signed by an unrelated key", "developer", InvalidSignature, ""),
                ("only one certificate", "one-certificate", ValueError, "server and developer")]
        for name, forge, error, message in rows:
            package = signed_package(forge)
            with self.subTest(name), self.assertRaisesRegex(error, message):
                verify_package_signature(package, inspect_image(package))
        tampered = bytearray(signed_package())
        tampered[100] ^= 1  # One payload bit inside the signed range.
        with self.assertRaises(InvalidSignature):
            verify_package_signature(bytes(tampered), inspect_image(bytes(tampered)))


CDN = "https://iot-ota-cdn.io.mi.com/miio_fw/ad1204.bin"
MIRROR = "https://cdn.cnbj1.fds.api.mi-fds.com/fw/ad1204.bin"
DEVICE = {"mac": "AA:BB:CC:DD:EE:FF", "model": "njcuk.fitting.ad1204", "did": "blt.1.test"}


class FakeAccountApi:
    """The cloud API after login. Its session holds the account cookies."""

    def __init__(self, offer):
        self.offer = offer
        self.session = requests.Session()
        self.session.cookies.set("serviceToken", "account-secret", domain=".mi.com")

    def list_devices(self):
        return [DEVICE]

    def encrypted_post(self, path, body):
        return {"code": 0, "result": self.offer}


def http_response(request, status, body=b"", location=None):
    response = requests.Response()
    response.status_code, response.raw, response.url, response.request = status, io.BytesIO(body), request.url, request
    if location:
        response.headers["Location"] = location
    return response


class FetchTests(unittest.TestCase):
    def test_download_safety(self):
        package, forged = signed_package(), signed_package("image")
        # (name, CDN responses by URL, MD5 in the offer, output setup, expected error or None)
        rows = [
            ("redirect to the mirror is followed", {CDN: (302, b"", MIRROR), MIRROR: (200, package, None)},
             package, None, None),
            ("redirect off the allowlist", {CDN: (302, b"", "https://evil.example/ad1204.bin")},
             package, None, "official Xiaomi"),
            ("body over 8 MiB", {CDN: (200, b"\0" * (8 * 1024 * 1024 + 1), None)}, package, None, "too large"),
            ("MD5 mismatch", {CDN: (200, package, None)}, package + b"x", None, "checksum"),
            ("forged image signature", {CDN: (200, forged, None)}, forged, None, "InvalidSignature"),
            ("output file is a symlink", {CDN: (200, package, None)}, package, "symlink", "symlink"),
            ("modern endpoint serves a raw image", {CDN: (200, raw_image(), None)}, raw_image(), None, "signed package"),
            ("signed version differs from the offer", {CDN: (200, package, None)}, package, None, "model/version", "2.1.3_0001"),
        ]
        for name, responses, md5_source, setup, error, *offered in rows:
            with self.subTest(name), tempfile.TemporaryDirectory() as temp:
                out = Path(temp) / "out"
                target = out / "njcuk.fitting.ad1204-2.1.2_0073-signed.bin"
                outside = Path(temp) / "outside.bin"
                if setup == "symlink":
                    out.mkdir()
                    outside.write_bytes(b"keep")
                    os.symlink(outside, target)
                requests_sent = []

                def send(adapter, request, sent=requests_sent, served=responses, **kwargs):
                    sent.append(request)
                    status, body, location = served[request.url]
                    return http_response(request, status, body, location)

                offer = {"version": offered[0] if offered else "2.1.2_0073", "md5": hashlib.md5(md5_source).hexdigest(), "safe_url": CDN}
                api = FakeAccountApi(offer)
                args = SimpleNamespace(address=None, region=None, legacy=False, output=str(out))
                with (patch("cuktech_pc.firmware.cached_api", return_value=(api, {"charger": {"address": DEVICE["mac"]}})),
                      patch("requests.adapters.HTTPAdapter.send", send), patch("builtins.print")):
                    if error is None:
                        fetch(args)
                    else:
                        with self.assertRaises(Exception) as caught:
                            fetch(args)
                        self.assertRegex(f"{type(caught.exception).__name__}: {caught.exception}", error)
                # The CDN never gets the account cookies, and only allowlisted hosts get requests.
                for request in requests_sent:
                    self.assertIsNone(request.headers.get("Cookie"))
                    self.assertTrue(request.url.startswith((CDN, MIRROR)), request.url)
                if error is None:
                    self.assertEqual([r.url for r in requests_sent], [CDN, MIRROR])
                    self.assertEqual(target.read_bytes(), package)
                elif setup == "symlink":
                    self.assertEqual(outside.read_bytes(), b"keep")
                else:
                    self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
