"""Negative controls: the offline guard of ``tests/__init__`` is real.

These tests prove that the harness blocks external IO, and that a blocked
attempt makes the test run fail. Thus a green run means that the tests
did no network and no BLE IO.
"""


import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import tests
from cuktech_pc import cli, cloud
from cuktech_pc.blebind import V2RegisterClient
from tests.fakepeer import FakeBleClient
from tests.test_13_security_adversarial import (
    _FakeAccount,
    _FakeApi,
    _args_setup,
    make_hit,
    run,
)


class _DiscardsOwnProbes(unittest.TestCase):
    """The tests in these classes trigger the guard on purpose.

    tearDown removes only the attempts that the test recorded. Thus the
    exit check of the harness sees only unexpected IO from other tests.
    """

    def setUp(self):
        self._recorded_before = len(tests.BLOCKED_IO_ATTEMPTS)

    def tearDown(self):
        del tests.BLOCKED_IO_ATTEMPTS[self._recorded_before:]


class NetGuard(_DiscardsOwnProbes):
    def test_socket_primitives_are_blocked(self):
        rows = {
            "socket.connect": lambda s: s.connect(("93.184.216.34", 443)),
            "socket.connect_ex": lambda s: s.connect_ex(("93.184.216.34", 443)),
            "create_connection": lambda s: socket.create_connection(("account.xiaomi.com", 443)),
            "getaddrinfo": lambda s: socket.getaddrinfo("account.xiaomi.com", 443),
            "sendto": lambda s: s.sendto(b"x", ("10.0.0.1", 53)),
            "sendmsg": lambda s: s.sendmsg([b"x"]),
        }
        for what, attempt in rows.items():
            with self.subTest(what), socket.socket() as sock, \
                    self.assertRaises(tests._BlockedIO):
                attempt(sock)

    def test_blocked_io_is_base_exception_not_swallowable(self):
        # an ordinary except-Exception in the code under test must
        # not be able to hide a blocked attempt
        self.assertTrue(issubclass(tests._BlockedIO, BaseException))
        self.assertNotIsInstance(tests._BlockedIO("x"), Exception)
        with self.assertRaises(tests._BlockedIO):
            try:
                socket.getaddrinfo("anything", 443)
            except Exception:  # noqa: BLE001 — deliberately insufficient
                self.fail("blocked IO was swallowed by except Exception")

    def test_setup_bind_phase_does_not_swallow_blocked_io(self):
        # cmd_setup catches errors in the cloud phase (before 0x13) and in
        # the confirm phase (after 0x13). A blocked IO attempt in either
        # phase must leave cmd_setup. It must not become a plain rc 1.
        rows = {
            "cloud phase": mock.patch.object(
                _FakeApi, "applydid",
                side_effect=lambda *a: socket.getaddrinfo("api.io.mi.com", 443)),
            "confirm phase": mock.patch.object(
                V2RegisterClient, "wait_final",
                side_effect=lambda *a, **k: socket.getaddrinfo("api.io.mi.com", 443)),
        }
        for phase, injection in rows.items():
            with self.subTest(phase), TemporaryDirectory() as tmp:
                peer = FakeBleClient(outcome="ok")

                async def scenario():
                    with mock.patch.object(
                        cli, "scan_for_ad1204u", return_value=[make_hit()]
                    ), mock.patch.object(
                        cloud, "MiAccount", _FakeAccount
                    ), mock.patch.object(
                        cloud, "MiCloudApi", _FakeApi
                    ), mock.patch(
                        "cuktech_pc.blebind.connect", return_value=peer
                    ), mock.patch(
                        "builtins.input", lambda prompt="": "y"
                    ), mock.patch(
                        "getpass.getpass", lambda *a, **k: "pw"
                    ), injection:
                        return await cli.cmd_setup(
                            _args_setup(Path(tmp) / "journal.json"))

                with self.assertRaises(tests._BlockedIO):
                    run(scenario())


class RunFailsOnBlockedIO(unittest.TestCase):
    """A child ``unittest`` run fails if a test catches a blocked attempt."""

    PROBE = textwrap.dedent("""\
        import socket
        import unittest

        import tests


        class Probe(unittest.TestCase):
            def test_probe(self):
                %s
        """)

    def _run_child(self, body: str) -> subprocess.CompletedProcess:
        with TemporaryDirectory() as tmp:
            Path(tmp, "probe_guard.py").write_text(self.PROBE % body)
            env = dict(os.environ, PYTHONPATH=str(tests.PROJECT_DIR))
            return subprocess.run(
                [sys.executable, "-m", "unittest", "probe_guard"],
                cwd=tmp, env=env, capture_output=True, text=True, timeout=60,
            )

    def test_swallowed_attempt_fails_the_run(self):
        sentinel = tests.SCRATCH_DIR / "sentinel"
        sentinel.write_text("parent run")
        try:
            swallowed = self._run_child(
                "try:\n"
                "            socket.getaddrinfo('account.xiaomi.com', 443)\n"
                "        except BaseException:\n"
                "            pass")
            # the test itself passed, but the process failed
            self.assertIn("OK", swallowed.stderr)
            self.assertIn("OFFLINE GUARD VIOLATED", swallowed.stderr)
            self.assertEqual(swallowed.returncode, tests.GUARD_EXIT_STATUS)
            # control row: the same child run with no IO attempt passes
            clean = self._run_child("pass")
            self.assertEqual(clean.returncode, 0, clean.stderr)
            # the child runs used their own scratch directory: the
            # scratch files of this run are still there
            self.assertEqual(sentinel.read_text(), "parent run")
        finally:
            sentinel.unlink(missing_ok=True)


class BleImportGuard(_DiscardsOwnProbes):
    def test_bleak_import_is_blocked(self):
        with self.assertRaises(tests._BlockedIO):
            __import__("bleak")

    def test_dbus_import_is_blocked(self):
        import importlib

        with self.assertRaises(tests._BlockedIO):
            importlib.import_module("dbus")


class ScratchSpace(unittest.TestCase):
    def test_tempdir_is_project_local_not_tmp(self):
        # test scratch lives inside the project, never /tmp
        self.assertEqual(tests.SCRATCH_DIR.parent, tests.PROJECT_DIR / ".test-scratch")
        self.assertEqual(tempfile.gettempdir(), str(tests.SCRATCH_DIR))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(str(tmp).startswith(str(tests.SCRATCH_DIR)))
            # and it is cleaned on exit
        self.assertFalse(Path(tmp).exists())

    def test_scratch_dir_is_private(self):
        mode = os.stat(tests.SCRATCH_DIR).st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_home_is_scratch(self):
        # tests never touch the real HOME (~/.cuktech_pc, ~/.cuktech_ble)
        self.assertEqual(os.environ["HOME"], str(tests.SCRATCH_DIR))


if __name__ == "__main__":
    unittest.main()
