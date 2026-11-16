"""Security fixtures for the tool's safety properties.

Every test here is offline: cloud transports are fakes, BLE is the
scripted fake peer, and the suite-wide IO guard (tests/__init__) would
fail any real attempt.

Covers: intent journal, archive + identity pinning, secure file writes,
export overwrite refusal, timeouts, URL allowlist, sanitized errors (the
password-hash leak), hidden 2FA wiring, consent-before-connect and 0x14 on
interruption, token validation and inconclusive resume, and size bounds.
"""


import asyncio
import contextlib
import getpass as getpass_mod
import io
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import requests

from cuktech_pc import cli, cloud, crypto, journal as J
from cuktech_pc.blebind import ScanHit
from cuktech_pc.fe95 import parse_fe95
from tests.fakepeer import FakeBleClient

# Bind result commands, from the app (docs/firmware/findings-bind.md):
# 0x13 = bind success (confirm), 0x14 = bind failure (abort).
CMD_BIND_RESULT_OK = bytes.fromhex("13 00 00 00")
CMD_BIND_RESULT_FAIL = bytes.fromhex("14 00 00 00")

ADDRESS = "AA:BB:CC:DD:EE:FF"
MODEL = "njcuk.fitting.ad1204"
# FE95 frame: mac_include bit set, pid 0x660E, MAC field = LE of ADDRESS
FE95_BYTES = (
    (0x0010).to_bytes(2, "little")
    + (0x660E).to_bytes(2, "little")
    + b"\x07"
    + bytes.fromhex("ffeeddccbbaa")
)


def make_hit(address: str = ADDRESS) -> ScanHit:
    return ScanHit(
        address=address, name=MODEL, rssi=-50, frame=parse_fe95(FE95_BYTES)
    )


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------


class IntentJournal(unittest.TestCase):
    def _journal(self, tmp: str) -> tuple[J.BindJournal, J.JournalState]:
        journal = J.BindJournal(Path(tmp) / "journal.json")
        state = J.JournalState(mac=ADDRESS, model=MODEL)
        journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="1234567890123456789",
        )
        return journal, state

    def test_interrupted_applydid_is_pending_not_never_called(self):
        # the intent record is written BEFORE the call, so a crash
        # mid-request can never look like "cloud never called"
        with TemporaryDirectory() as tmp:
            journal, state = self._journal(tmp)
            journal.record_intent_applydid(state)
            # simulate: request never returned (crash right here)
            loaded = journal.load()
            self.assertEqual(loaded.cloud_bind, "applydid-pending")
            action, reason = J.resume_action(loaded)
            self.assertEqual(action, "verify-first")
            self.assertIn("in flight", reason)
            self.assertIn("not automatic", reason)

    def test_interrupted_bind_is_pending(self):
        with TemporaryDirectory() as tmp:
            journal, state = self._journal(tmp)
            journal.record_did_allocated(state, "9876543210123456789")
            journal.record_intent_bind(state)
            loaded = journal.load()
            self.assertEqual(loaded.cloud_bind, "bind-pending")
            _, reason = J.resume_action(loaded)
            self.assertIn("in flight", reason)

    def test_success_overwrites_pending(self):
        with TemporaryDirectory() as tmp:
            journal, state = self._journal(tmp)
            journal.record_intent_applydid(state)
            journal.record_did_allocated(state, "9876543210123456789")
            self.assertEqual(journal.load().cloud_bind, "applydid")
            journal.record_intent_bind(state)
            journal.record_cloud_signed(
                state, utc=1760000000, cloud_sign_b64="cw==", cloud_cert_b64="Zg=="
            )
            self.assertEqual(journal.load().cloud_bind, "standard_bind")


class ArchiveNotOverwrite(unittest.TestCase):
    def _filled(self, tmp: str) -> J.BindJournal:
        journal = J.BindJournal(Path(tmp) / "journal.json")
        state = J.JournalState(mac=ADDRESS, model=MODEL, token_hex="ab" * 12)
        journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="1234567890123456789",
        )
        journal.record_did_allocated(state, "9876543210123456789")
        return journal

    def test_archive_preserves_content_and_original(self):
        # a fresh start archives — never deletes — the old journal
        with TemporaryDirectory() as tmp:
            journal = self._filled(tmp)
            before = Path(tmp, "journal.json").read_text()
            archived = journal.archive("test reason")
            self.assertTrue(archived.exists())
            self.assertTrue(Path(tmp, "journal.json").exists())  # original kept
            # the archived copy holds the same secrets + an archive note
            obj = json.loads(archived.read_text())
            self.assertEqual(obj["token_hex"], "ab" * 12)
            self.assertEqual(obj["server_did"], "9876543210123456789")
            self.assertIn("archived before fresh restart", obj["attempts"][-1]["note"])
            self.assertEqual(stat.S_IMODE(archived.stat().st_mode), 0o600)
            # and the original is untouched
            self.assertEqual(Path(tmp, "journal.json").read_text(), before)


# ---------------------------------------------------------------------


class SecureFileWrites(unittest.TestCase):
    def test_journal_dir_is_0700_file_is_0600(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "journal.json"
            journal = J.BindJournal(path)
            state = J.JournalState(mac=ADDRESS, model=MODEL, token_hex="ab" * 12)
            journal.record_derived(
                state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                a_key_hex="ef" * 16, factory_did="1234567890123456789",
            )
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            # no leftover temp files
            leftovers = [p for p in path.parent.iterdir() if p.name != "journal.json"]
            self.assertEqual(leftovers, [])
            loaded = J.BindJournal(path).load()
            self.assertEqual((loaded.token_hex, loaded.stage), ("ab" * 12, "derived"))

    def test_save_refuses_symlink_target(self):
        with TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside.txt"
            outside.write_text("payload")
            target = Path(tmp) / "journal.json"
            target.symlink_to(outside)
            journal = J.BindJournal(target)
            state = J.JournalState(mac=ADDRESS, model=MODEL)
            with self.assertRaises(J.JournalError):
                journal.record_derived(
                    state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                    a_key_hex="ef" * 16, factory_did="d" * 19,
                )
            # the symlink and its target are untouched
            self.assertTrue(target.is_symlink())
            self.assertEqual(outside.read_text(), "payload")

    def test_load_refuses_symlink(self):
        with TemporaryDirectory() as tmp:
            outside = Path(tmp) / "real.json"
            outside.write_text("{}")
            target = Path(tmp) / "journal.json"
            target.symlink_to(outside)
            with self.assertRaises(J.JournalError) as ctx:
                J.BindJournal(target).load()
            self.assertIn("symlink", str(ctx.exception))

    def test_load_refuses_wide_permissions(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            journal = J.BindJournal(path)
            state = J.JournalState(mac=ADDRESS, model=MODEL, token_hex="ab" * 12)
            journal.record_derived(
                state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                a_key_hex="ef" * 16, factory_did="d" * 19,
            )
            os.chmod(path, 0o644)  # widened (e.g. by a careless copy)
            with self.assertRaises(J.JournalError) as ctx:
                J.BindJournal(path).load()
            self.assertIn("0600", str(ctx.exception))

    def test_no_world_readable_window_on_write(self):
        # the temp file is created 0600 by mkstemp (O_EXCL) — verify by
        # watching the directory during a save
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "journal.json"
            journal = J.BindJournal(path)
            state = J.JournalState(mac=ADDRESS, model=MODEL)
            modes: list[int] = []
            real_replace = os.replace

            def watching_replace(a, b):
                for p in Path(tmp).iterdir():
                    if p.name != "journal.json":
                        modes.append(stat.S_IMODE(p.stat().st_mode))
                return real_replace(a, b)

            with mock.patch("os.replace", side_effect=watching_replace):
                journal.record_derived(
                    state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                    a_key_hex="ef" * 16, factory_did="d" * 19,
                )
            self.assertTrue(modes)
            self.assertTrue(all(m == 0o600 for m in modes), modes)


# ---------------------------------------------------------------------


class ExportTokenOverwriteRefusal(unittest.TestCase):
    def _bound_journal(self, tmp: str) -> Path:
        path = Path(tmp) / "journal.json"
        journal = J.BindJournal(path)
        state = J.JournalState(
            mac=ADDRESS, model=MODEL, token_hex="ab" * 12,
            stage="bound", bound_verified=True,
        )
        journal.save(state)
        return path

    def test_refuses_existing_different_file(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._bound_journal(tmp)
            out = Path(tmp) / "token.json"
            out.write_text(json.dumps(
                {"address": "11:22:33:44:55:66", "token_hex": "99" * 12}) + "\n")
            # a "y" at any prompt must not matter: without --force the tool
            # never asks, it refuses
            with mock.patch("builtins.input", lambda prompt="": "y"):
                rc = cli.main(
                    ["export-token", "--journal", str(journal_path),
                     "--output", str(out)]
                )
            self.assertEqual(rc, 1)
            # the existing (working) token file is untouched
            self.assertIn("11:22:33:44:55:66", out.read_text())

    def test_same_content_is_a_noop(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._bound_journal(tmp)
            out = Path(tmp) / "token.json"
            out.write_text(json.dumps(
                {"address": ADDRESS, "token_hex": "ab" * 12}) + "\n")
            rc = cli.main(
                ["export-token", "--journal", str(journal_path), "--output", str(out)]
            )
            self.assertEqual(rc, 0)

    def test_force_requires_typed_confirmation(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._bound_journal(tmp)
            out = Path(tmp) / "token.json"
            out.write_text(json.dumps(
                {"address": "11:22:33:44:55:66", "token_hex": "99" * 12}) + "\n")
            inputs = iter(["wrong phrase"])
            with mock.patch("builtins.input", lambda prompt="": next(inputs)):
                rc = cli.main(
                    ["export-token", "--journal", str(journal_path),
                     "--output", str(out), "--force"]
                )
            self.assertEqual(rc, 1)
            self.assertIn("11:22:33:44:55:66", out.read_text())  # still untouched
            # correct typed confirmation replaces it
            inputs = iter(["y"])
            with mock.patch("builtins.input", lambda prompt="": next(inputs)):
                rc = cli.main(
                    ["export-token", "--journal", str(journal_path),
                     "--output", str(out), "--force"]
                )
            self.assertEqual(rc, 0)
            self.assertIn("AA:BB:CC:DD:EE:FF", out.read_text())
            self.assertIn("abababababababababababab", out.read_text())

    def test_refuses_symlink_output(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._bound_journal(tmp)
            victim = Path(tmp) / "victim.txt"
            victim.write_text("do not touch")
            out = Path(tmp) / "token.json"
            out.symlink_to(victim)
            rc = cli.main(
                ["export-token", "--journal", str(journal_path), "--output", str(out)]
            )
            self.assertEqual(rc, 1)
            self.assertEqual(victim.read_text(), "do not touch")


# -----------------------------------------------------------------


class _RecordingSession:
    def __init__(self, responses=None):
        self.calls: list[dict] = []
        self.responses = responses or []

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        if self.responses:
            resp = self.responses.pop(0)
            if isinstance(resp, Exception):
                raise resp
            return resp
        raise requests.ConnectionError("never reached")


class _Resp:
    def __init__(self, status=200, text="{}", headers=None, location=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        if location:
            self.headers["Location"] = location
        self._content = text.encode()
        self._content_consumed = True


class TimeoutsAndAllowlist(unittest.TestCase):
    def test_every_call_carries_timeouts(self):
        # no request may leave the tool without bounded timeouts
        session = _RecordingSession([_Resp()])
        cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")
        call = session.calls[0]
        self.assertIn("timeout", call)
        tt = call["timeout"]
        self.assertIsInstance(tt, tuple)
        self.assertGreater(tt[0], 0)
        self.assertGreater(tt[1], 0)
        # and redirects are never automatic
        self.assertFalse(call["allow_redirects"])

    def test_off_allowlist_host_refused(self):
        for url in (
            "http://account.xiaomi.com/captcha",
            "https://user:pw@account.xiaomi.com/captcha",
            "https://evil.com/captcha",
            "https://account.xiaomi.com.evil.com/captcha",
            "https://api.io.mi.com.evil.com/x",
            "ftp://account.xiaomi.com/x",
        ):
            with self.assertRaises(cloud.UnsafeURLError, msg=url):
                cloud.validate_url(url)

    def test_allowlisted_hosts_accepted(self):
        for url in (
            "https://account.xiaomi.com/pass/serviceLogin",
            "https://sts.api.io.mi.com/sts",
            "https://api.io.mi.com/app/home/device_list",
            "https://de.api.io.mi.com/app/device/bltapplydid",
        ):
            self.assertEqual(cloud.validate_url(url), url)

    def test_redirect_hop_off_allowlist_hands_off_not_followed(self):
        # a Location to an evil host is never fetched; with
        # explicit hop-following the user is handed a manual action
        session = _RecordingSession(
            [_Resp(status=302, location="https://evil.com/steal?hash=XYZ")]
        )
        with self.assertRaises(cloud.ManualActionRequired):
            cloud.request(session, "GET", "https://account.xiaomi.com/x",
                          stage="t", follow_get_hops=True)
        # exactly one request was made (the allowlisted one); the evil hop
        # was validated BEFORE any fetch
        self.assertEqual(len(session.calls), 1)
        self.assertIn("account.xiaomi.com", session.calls[0]["url"])

    def test_redirect_chain_within_allowlist_is_followed(self):
        # only with the explicit opt-in, and only for GETs
        session = _RecordingSession(
            [_Resp(status=302, location="https://sts.api.io.mi.com/sts?x=1"),
             _Resp(status=200, text='{"ok":1}')]
        )
        resp = cloud.request(session, "GET", "https://account.xiaomi.com/x",
                             stage="t", follow_get_hops=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(session.calls), 2)
        self.assertIn("sts.api.io.mi.com", session.calls[1]["url"])
        # hop GETs must be bare: no params/data/cookies forwarded
        second = session.calls[1]
        self.assertNotIn("params", second)
        self.assertNotIn("data", second)
        self.assertNotIn("cookies", second)

    def test_default_is_no_follow_raw_30x_returned(self):
        # without the opt-in, the raw 30x comes back so the 2FA
        # chain can read extension-pragma/Location itself
        session = _RecordingSession(
            [_Resp(status=302, location="https://sts.api.io.mi.com/sts?x=1")]
        )
        resp = cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(len(session.calls), 1)  # nothing followed

    def test_post_redirect_never_replayed(self):
        # a 3xx answer to a POST (login or cloud mutation) is a
        # sanitized error; the POST is made exactly ONCE
        session = _RecordingSession([_Resp(status=307, location="https://api.io.mi.com/elsewhere")])
        with self.assertRaises(cloud.CloudError) as ctx:
            cloud.request(session, "POST",
                          "https://api.io.mi.com/app/device/bltapplydid",
                          stage="api call /device/bltapplydid",
                          data={"secret": "x"})
        self.assertEqual(len(session.calls), 1)  # never re-POSTed
        self.assertIn("does not send POSTs again", str(ctx.exception))
        self.assertNotIn("http", str(ctx.exception))

    def test_relative_official_location_resolved_before_fetch(self):
        session = _RecordingSession(
            [_Resp(status=302, location="/identity/auth/Auth2/end?x=1"),
             _Resp(status=200, text='{"ok":1}')]
        )
        resp = cloud.request(session, "GET",
                             "https://account.xiaomi.com/identity/result/check",
                             stage="t", follow_get_hops=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(session.calls[1]["url"].startswith(
            "https://account.xiaomi.com/identity/auth/Auth2/end"))

    def test_nonstandard_port_redirect_refused_before_fetch(self):
        session = _RecordingSession(
            [_Resp(status=302, location="https://account.xiaomi.com:8443/x")]
        )
        with self.assertRaises(cloud.ManualActionRequired):
            cloud.request(session, "GET", "https://account.xiaomi.com/x",
                          stage="t", follow_get_hops=True)
        self.assertEqual(len(session.calls), 1)  # hop never fetched

    def test_relative_url_resolved_against_account_origin(self):
        self.assertEqual(
            cloud.abs_account_url("/getCaptcha"),
            "https://account.xiaomi.com/getCaptcha",
        )
        self.assertEqual(
            cloud.abs_account_url("https://api.io.mi.com/x"),
            "https://api.io.mi.com/x",
        )


class SanitizedErrors(unittest.TestCase):
    """The password hash travels in a query parameter — no error
    path may ever echo a URL."""

    FAKE_HASH = "5F4DCC3B5AA765D61D8327DEB882CF99"  # not a real password hash

    def _leaky_exception(self) -> Exception:
        return requests.ConnectionError(
            "Max retries exceeded with url: "
            "/pass/serviceLoginAuth2?sid=xiaomiio&hash="
            + self.FAKE_HASH
            + "&user=victim (caused by None)"
        )

    def test_request_wrapper_sanitizes_url(self):
        session = _RecordingSession([self._leaky_exception()])
        with self.assertRaises(cloud.CloudError) as ctx:
            cloud.request(
                session, "POST",
                "https://account.xiaomi.com/pass/serviceLoginAuth2",
                stage="login step 2",
            )
        msg = str(ctx.exception)
        self.assertNotIn(self.FAKE_HASH, msg)
        self.assertNotIn("http", msg)
        self.assertNotIn("serviceLoginAuth2", msg)
        self.assertIn("login step 2", msg)  # stage name survives

    def test_cli_fatal_handler_prints_no_url_no_traceback(self):
        # end-to-end: a login-phase ConnectionError reaches main() and the
        # printed output stays clean
        captured_err = io.StringIO()
        captured_out = io.StringIO()

        reached = []

        class ExplodingAccount:
            def __init__(self, *a, **kw):
                pass

            def login(self, u, p):
                reached.append("login")
                raise self._leaky()

            @staticmethod
            def _leaky():
                return requests.ConnectionError(
                    "connection to account.xiaomi.com failed; url="
                    "/pass/serviceLoginAuth2?hash=" + SanitizedErrors.FAKE_HASH
                )

        async def noop_scan(duration=0):
            return []

        with TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(captured_err), \
                    contextlib.redirect_stdout(captured_out), \
                    mock.patch.object(cloud, "MiAccount", ExplodingAccount), \
                    mock.patch.object(cloud, "new_session", lambda: object()), \
                    mock.patch.object(cli, "scan_for_ad1204u", noop_scan), \
                    mock.patch.object(
                        getpass_mod, "getpass", lambda *a, **k: "pw"), \
                    mock.patch("builtins.input", lambda prompt="": "user"):
                rc = cli.main(_setup_argv(Path(tmp) / "journal.json"))
            self.assertEqual(rc, 1)
        self.assertEqual(reached, ["login"])  # the leaky exception was raised
        combined = captured_err.getvalue() + captured_out.getvalue()
        self.assertNotIn(self.FAKE_HASH, combined)
        self.assertNotIn("serviceLoginAuth2", combined)
        self.assertNotIn("Traceback", combined)

    def test_did_field_bounds_enforced(self):
        # an over-long or non-ASCII DID parcel is rejected, never
        # forwarded to the cloud
        with self.assertRaises(crypto.DevInfoError):
            crypto.parse_devinfo(b"\x02\x00\x00\x00\x00" + b"1" * 25)
        with self.assertRaises(crypto.DevInfoError):
            crypto.parse_devinfo(b"\x02\x00\x00\x00\x00" + "dïd".encode())


# ---------------------------------------------------------------------


class HiddenTwoFactorWiring(unittest.TestCase):
    def test_cli_passes_getpass_as_hidden_input(self):
        # the emailed 2FA code is a credential: cmd_setup must give
        # getpass.getpass to MiAccount as the hidden prompt
        prompts: list[str] = []

        def recording_getpass(prompt=""):
            prompts.append(prompt)
            return "pw"

        class TwoFactorAccount(_FakeAccount):
            def __init__(self, *a, hidden_input=None, **kw):
                self.hidden_input = hidden_input

            def login(self, u, p):
                self.hidden_input("2FA code from email: ")
                return super().login(u, p)

        async def scenario(journal_path):
            with mock.patch.object(
                cli, "scan_for_ad1204u", return_value=[]
            ), mock.patch.object(
                cloud, "MiAccount", TwoFactorAccount
            ), mock.patch.object(
                cloud, "MiCloudApi", _FakeApi
            ), mock.patch.object(getpass_mod, "getpass", recording_getpass):
                return await cli.cmd_setup(_args_setup(journal_path))

        with TemporaryDirectory() as tmp:
            rc = run(scenario(Path(tmp) / "journal.json"))
        self.assertEqual(rc, 1)  # no charger found after the login
        # the password prompt, then the 2FA code prompt, both hidden
        self.assertEqual(prompts, ["", "2FA code from email: "])


# ---------------------------------------------------------------------


def _setup_argv(journal_path: Path) -> list[str]:
    """Setup arguments with a session cache next to the journal.

    Each test has its own session cache. Thus a login that one test saves
    does not change the login path of a different test.
    """
    return ["setup", "--journal", str(journal_path),
            "--session-cache", str(journal_path.parent / "cloud-session.json"),
            "--username", "user"]


def _args_setup(journal_path: Path):
    return cli.build_parser().parse_args(_setup_argv(journal_path))


class ConsentBeforeAnyDeviceWrite(unittest.TestCase):
    def test_declined_consent_never_connects(self):
        # the typed gate comes BEFORE connect/ECDH/cloud mutation
        async def scenario(journal_path):
            with mock.patch.object(
                cli, "scan_for_ad1204u", return_value=[make_hit()]
            ), mock.patch.object(
                cloud, "MiAccount", _FakeAccount
            ), mock.patch.object(
                cloud, "MiCloudApi", _FakeApi
            ), mock.patch(
                "cuktech_pc.blebind.connect",
                side_effect=AssertionError("connect before consent!"),
            ), mock.patch(
                "builtins.input", lambda prompt="": "nope"
            ), mock.patch(
                getpass_mod.__name__ + ".getpass", lambda *a, **k: "pw"
            ):
                return await cli.cmd_setup(_args_setup(journal_path))

        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            rc = run(scenario(journal_path))
            self.assertEqual(rc, 1)
            self.assertFalse(journal_path.exists())


class _FakeAccount:
    def __init__(self, *a, **kw):
        pass

    def login(self, u, p):
        return cloud.CloudSession("424242", "QUJDREVGR0hJSktMTU5A", "STOK")

    _skew_seconds = 0.0
    device_id = "FAKEDEVICEID0000"
    agent = "fake-agent"
    session = None


class _FakeApi:
    def __init__(self, session=None, auth=None, **kw):
        self.auth = auth

    def list_devices(self):
        return []  # authenticated success (round-6 validation gate)

    def device_list_contains(self, *macs):
        return False

    def applydid(self, *a, **kw):
        return "9876543210123456789"

    def standard_bind(self, *a, **kw):
        return cloud.BindCloudMaterial(
            cloud_sign=bytes(64), cloud_cert=b"\x30\x82" + bytes(96), utc=1760000000
        )


class InterruptHandling(unittest.TestCase):
    """An unexpected interruption after the pubkey exchange writes
    0x14 exactly once; before it, never."""

    def _run(self, fail_applydid_with, tmp: str):
        # through cli.main: the rc is the real exit code (130 on Ctrl-C)
        peer = FakeBleClient(outcome="ok")
        journal_path = Path(tmp) / "journal.json"
        injection = (
            contextlib.nullcontext() if fail_applydid_with is None
            else mock.patch.object(_FakeApi, "applydid", side_effect=fail_applydid_with)
        )
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
            getpass_mod.__name__ + ".getpass", lambda *a, **k: "pw"
        ), injection:
            rc = cli.main(_setup_argv(journal_path))
        return rc, peer, journal_path

    def test_interrupt_after_pubkey_writes_0x14_once(self):
        with TemporaryDirectory() as tmp:
            rc, peer, journal_path = self._run(KeyboardInterrupt(), tmp)
            self.assertEqual(rc, 130)  # main()'s KeyboardInterrupt code
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_FAIL), 1)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_OK), 0)
            # the journal survived with the pending intent
            state = J.BindJournal(journal_path).load()
            self.assertEqual(state.cloud_bind, "applydid-pending")

    def test_cloud_failure_after_pubkey_writes_0x14_once(self):
        with TemporaryDirectory() as tmp:
            rc, peer, journal_path = self._run(
                cloud.CloudError("ble_standard_bind failed"), tmp
            )
            self.assertEqual(rc, 1)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_FAIL), 1)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_OK), 0)
            state = J.BindJournal(journal_path).load()
            self.assertIn("cloud-bind", state.attempts[-1]["note"])

    def test_failure_before_pubkey_writes_no_0x14(self):
        # a transport failure during GET_INFO leaves the device untouched
        with TemporaryDirectory() as tmp:
            peer = FakeBleClient(outcome="ok")
            peer.fail_on_write = 1  # the very first write (a2) fails
            journal_path = Path(tmp) / "journal.json"

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
                    getpass_mod.__name__ + ".getpass", lambda *a, **k: "pw"
                ):
                    return await cli.cmd_setup(_args_setup(journal_path))

            rc = run(scenario())
            self.assertEqual(rc, 1)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_FAIL), 0)
            self.assertFalse(journal_path.exists())  # nothing derived yet

    def test_happy_path_never_writes_0x14(self):
        with TemporaryDirectory() as tmp:
            rc, peer, journal_path = self._run(None, tmp)
            self.assertEqual(rc, 0)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_FAIL), 0)
            self.assertEqual(peer.count_writes(CMD_BIND_RESULT_OK), 1)
            state = J.BindJournal(journal_path).load()
            self.assertEqual(state.stage, "bound")
            self.assertTrue(state.bound_verified)


# ---------------------------------------------------------------------


def _hit_from(fc: int = 0x0010, pid: int = 0x660E, *,
              address: str = ADDRESS, name: str = MODEL) -> ScanHit:
    """A scan hit. The FE95 frame has the MAC field of ADDRESS (LE)."""
    raw = (fc.to_bytes(2, "little") + pid.to_bytes(2, "little") + b"\x07"
           + bytes.fromhex("ffeeddccbbaa"))
    return ScanHit(address=address, name=name, rssi=-50, frame=parse_fe95(raw))


class SetupRefusals(unittest.TestCase):
    """cmd_setup refuses a charger that it must not bind.

    The hard guards stop before the consent prompt and before connect.
    A 0x12 reply from the charger stops after the device write, with no
    0x14 and no cloud call after the reply (no automatic unbind).
    """

    def test_setup_refusals(self):
        # row: (hit, already on account, peer outcome,
        #       expected: consent asked, text in output)
        rows = {
            "registered bit set": (
                _hit_from(fc=0x0010 | 0x0100), False, "ok", False,
                "'registered' bit is set"),
            "no FE95 MAC": (
                _hit_from(fc=0x0000), False, "ok", False, "has no FE95 MAC"),
            "smac of a different device": (
                _hit_from(address="11:22:33:44:55:66"), False, "ok", False,
                "does not match the selected address"),
            "unknown pid": (  # 0x8AD9: the wrong transcription of 0x8AB9
                _hit_from(pid=0x8AD9), False, "ok", False,
                "has no known model mapping"),
            "name of a different family": (
                _hit_from(name="yeelink.light.x"), False, "ok", False,
                "does not match the expected"),
            "already on the account": (
                _hit_from(), True, "ok", False, "already on this account"),
            "device rejects with 0x12": (
                _hit_from(), False, "reject", True, "REJECTED the bind (0x12)"),
        }
        for label, (hit, on_account, outcome, consent, text) in rows.items():
            with self.subTest(label), TemporaryDirectory() as tmp:
                journal_path = Path(tmp) / "journal.json"
                peer = FakeBleClient(outcome=outcome)
                prompts: list[str] = []
                api_calls: list[str] = []

                class StrictApi(_FakeApi):
                    """Records the cloud calls. Any other API use fails."""

                    def device_list_contains(self, *macs):
                        return on_account

                    def applydid(self, *a, **kw):
                        api_calls.append("applydid")
                        return super().applydid(*a, **kw)

                    def standard_bind(self, *a, **kw):
                        api_calls.append("standard_bind")
                        return super().standard_bind(*a, **kw)

                    def __getattr__(self, name):
                        raise AssertionError(f"unexpected cloud call: {name}")

                def answer(prompt=""):
                    prompts.append(prompt)
                    return "y"

                out = io.StringIO()
                with mock.patch.object(
                    cli, "scan_for_ad1204u", return_value=[hit]
                ), mock.patch.object(
                    cloud, "MiAccount", _FakeAccount
                ), mock.patch.object(
                    cloud, "MiCloudApi", StrictApi
                ), mock.patch(
                    "cuktech_pc.blebind.connect", return_value=peer
                ), mock.patch.object(
                    cli, "verify_token_login",
                    side_effect=AssertionError("no verify after a refusal"),
                ), mock.patch(
                    "builtins.input", answer
                ), mock.patch.object(
                    getpass_mod, "getpass", lambda *a, **k: "pw"
                ), contextlib.redirect_stdout(out):
                    rc = cli.main(_setup_argv(journal_path))

                self.assertEqual(rc, 1)
                self.assertIn(text, out.getvalue())
                self.assertEqual(peer.count_writes(CMD_BIND_RESULT_FAIL), 0)
                if not consent:
                    self.assertEqual(prompts, [])
                    self.assertEqual(peer.writes, [])  # never connected
                    self.assertEqual(api_calls, [])
                    self.assertFalse(journal_path.exists())
                    continue
                self.assertEqual(len(prompts), 1)
                self.assertEqual(peer.count_writes(CMD_BIND_RESULT_OK), 1)
                # no cloud call after the 0x12 reply
                self.assertEqual(api_calls, ["applydid", "standard_bind"])
                state = J.BindJournal(journal_path).load()
                self.assertEqual(state.device_committed, "no")
                self.assertEqual(state.attempts[-1]["note"], "device-rejected (0x12)")


class TokenValidationOnLoad(unittest.TestCase):
    def test_corrupt_token_refused_at_load(self):
        # the journal JSON can come from outside the tool: load checks it
        for token_hex, error in (("xyz!", "24 lowercase hex"), ("ab" * 12, None)):
            with self.subTest(token_hex), TemporaryDirectory() as tmp:
                path = Path(tmp) / "journal.json"
                obj = {
                    "schema": 2, "mac": ADDRESS, "model": MODEL,
                    "token_hex": token_hex, "stage": "derived", "cloud_bind": "no",
                }
                path.write_text(json.dumps(obj))
                os.chmod(path, 0o600)
                if error is None:  # positive control row
                    self.assertEqual(J.BindJournal(path).load().token_hex, token_hex)
                    continue
                with self.assertRaises(J.JournalError) as ctx:
                    J.BindJournal(path).load()
                self.assertIn(error, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
