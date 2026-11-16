"""remove-device: y/N consent, removes only the named entry."""


import argparse
import asyncio
import base64
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from cuktech_pc import cli, cloud, sessioncache

DID = "blt.3.1qhp5dkqc4000"
SEC = base64.b64encode(b"\x01" * 16).decode()


class _Api:
    def __init__(self, session=None, auth=None, **kw):
        self.devs = [{"did": DID, "pid": "6", "model": "m", "mac": "AA"},
                     {"did": "other", "pid": "0"}]
        self.removed: list[tuple[str, int]] = []
        _Api.last = self

    def list_devices(self):
        return list(self.devs)

    def remove_device(self, did, pid):
        self.removed.append((did, pid))
        self.devs = [d for d in self.devs if d["did"] != did]


class RemoveDevice(unittest.TestCase):
    def _run(self, typed):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "cloud-session.json"
            sessioncache.save_session(
                path, cloud.CloudSession("424242", SEC, "ST"),
                device_id="D" * 16, agent="a", region="cn",
                username_tag=sessioncache.username_tag("u@example.com"),
            )
            args = argparse.Namespace(did=DID, session_cache=path)
            with mock.patch.object(cloud, "MiCloudApi", _Api), \
                    mock.patch("builtins.input", return_value=typed):
                rc = asyncio.run(cli.cmd_remove_device(args))
        return rc, _Api.last

    def test_declined_consent_changes_nothing(self):
        rc, api = self._run("nope")
        self.assertEqual(rc, 1)
        self.assertEqual(api.removed, [])

    def test_consent_removes_only_that_did(self):
        rc, api = self._run("y")
        self.assertEqual(rc, 0)
        self.assertEqual(api.removed, [(DID, 6)])

    def test_error_code_raises(self):
        api = cloud.MiCloudApi(None, cloud.CloudSession("1", SEC, "ST"))
        with mock.patch.object(api, "encrypted_post",
                               return_value={"code": -1, "message": "x"}):
            with self.assertRaises(cloud.CloudError):
                api.remove_device(DID, 6)
