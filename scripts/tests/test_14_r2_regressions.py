"""Regression tests for transport realism, redirects, the bind phase guard,
secure parent directories and typed device error codes.

Every test is offline. Realism rules: HTTP fixtures are
**real ``requests.models.Response`` objects** built with
``raw=io.BytesIO(...)`` and ``_content=False`` (the streaming path), never
fake pre-filled bodies — so the code under test exercises exactly the
code a live response would.
"""


import base64
import io
import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import requests.models

from cuktech_pc import cli, cloud, crypto, journal as J, sessioncache
from cuktech_pc.blebind import V2RegisterClient
from cuktech_pc.cli import INCONCLUSIVE, NOT_REGISTERED, REJECTED
from cuktech_pc.fe95 import parse_fe95
from cuktech_pc.journal import BindJournal, JournalState
from tests.fakepeer import FakeBleClient
from tests.test_13_security_adversarial import (
    ADDRESS,
    MODEL,
    _FakeAccount,
    _FakeApi,
    _args_setup,
    make_hit,
    run,
)

# Bind result commands (docs/firmware/findings-bind.md step 2), written as
# a 4-byte word on UPNP: 0x13 = confirm, 0x14 = abort.
ZERO13 = bytes.fromhex("13 00 00 00")
ZERO14 = bytes.fromhex("14 00 00 00")


def real_response(status=200, body=b"{}", headers=None,
                  url="https://account.xiaomi.com/x", method="GET"):
    """A REAL requests.Response on the streaming path (never pre-buffered)."""
    r = requests.models.Response()
    r.status_code = status
    r.headers.update(headers or {})
    r.raw = io.BytesIO(body)
    r._content = False
    r._content_consumed = False
    r.url = url
    r.request = requests.models.Request(method, url).prepare()
    return r


class FakeRawSession:
    """Routes to real Response objects; records every request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []
        self.cookies = _Jar()

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _Jar(dict):
    def set(self, name, value, domain=None):
        self[name] = value

    def get(self, name, default="", domain=None):
        return dict.get(self, name, default)


# ---------------------------------------------------------------------


class RealResponseDrain(unittest.TestCase):
    """_drain_bounded must work on REAL requests.Response objects."""

    def test_200_json_body_readable(self):
        body = json.dumps(
            {"code": 0, "result": {"did": "12345678901234567"}}
        ).encode()
        session = FakeRawSession([real_response(200, body)])
        resp = cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")
        self.assertEqual(resp.status_code, 200)
        # the .text/.content/.json() properties work — no AttributeError
        self.assertEqual(resp.json()["result"]["did"], "12345678901234567")
        self.assertEqual(resp.text.encode(), body)
        self.assertEqual(resp.content, body)

    def test_utf8_body_decoded(self):
        session = FakeRawSession(
            [real_response(200, '{"desc":"成功"}'.encode())]
        )
        resp = cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")
        self.assertIn("成功", resp.text)

    def test_truncated_stream_is_sanitized(self):
        class TruncRaw(io.BytesIO):
            def read(self, *a):
                raise OSError("connection reset")

        r = real_response(200, b"{}")
        r.raw = TruncRaw(b"{}")
        session = FakeRawSession([r])
        with self.assertRaises(cloud.CloudError) as ctx:
            cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")
        self.assertIn("reading response", str(ctx.exception))
        self.assertNotIn("http", str(ctx.exception))

    def test_max_body_cap_on_real_stream(self):
        big = b"x" * (cloud.MAX_RESPONSE_BYTES + 1)
        session = FakeRawSession([real_response(200, big)])
        with self.assertRaises(cloud.CloudResponseError):
            cloud.request(session, "GET", "https://account.xiaomi.com/x", stage="t")


# ---------------------------------------------------------------------


class Real302TwoFactorChain(unittest.TestCase):
    """2FA modeled the way the real server behaves: intermediate 302s with
    Location + extension-pragma, read by the caller from raw responses."""

    def test_full_2fa_chain_with_real_302s(self):
        sec = base64.b64encode(b"\x01" * 16).decode()
        session = FakeRawSession([
            real_response(200, b'&&&START&&&{"_sign":"SIG"}'),
            real_response(200, json.dumps(
                {"notificationUrl": "https://account.xiaomi.com/identity/authStart?context=CTX"}
            ).encode(), method="POST"),
            real_response(200, b"ok"),                                # authStart
            real_response(200, b"ok"),                                # list
            real_response(200, b"ok"),                                # sendEmailTicket
            real_response(200, json.dumps({"location": ""}).encode(), method="POST"),  # verifyEmail
            # result/check -> raw 302 to Auth2/end
            real_response(
                302, b"",
                headers={"Location": "https://account.xiaomi.com/identity/auth/Auth2/end?x=1"},
            ),
            # Auth2/end -> raw 302 with extension-pragma (ssecurity)
            real_response(
                302, b"",
                headers={
                    "extension-pragma": json.dumps({"ssecurity": sec}),
                    "Location": "https://sts.api.io.mi.com/sts?t=1",
                },
            ),
            real_response(200, b"ok"),  # STS final
        ])
        # real jar, userId on TWO domains as after a live 2FA: a plain
        # cookies.get("userId") raises CookieConflictError (live HTTP 401)
        session.cookies = requests.cookies.RequestsCookieJar()
        # (a non-numeric value first in jar order: the numeric id must win)
        session.cookies.set("userId", "user@example.com", domain=".xiaomi.com")
        session.cookies.set("serviceToken", "STS", domain=".sts.api.io.mi.com")
        session.cookies.set("userId", "424242", domain=".sts.api.io.mi.com")
        acct = cloud.MiAccount(
            session, hidden_input=lambda p: "654321",
            visible_input=lambda p: "1234",
        )
        sess = acct.login("user@example.com", "correct-horse")
        self.assertEqual(acct._sign, "SIG")  # step 1 read the real stream
        self.assertEqual(sess.ssecurity, sec)
        self.assertEqual(sess.service_token, "STS")
        self.assertEqual(sess.user_id, "424242")
        # no request was replayed
        self.assertEqual(len(session.calls), 9)

    def test_mutation_redirect_is_ambiguous_error_single_post(self):
        """A 302 on the /app envelope POST: sanitized ambiguous error; the
        POST happened exactly ONCE (mutations are never replayed)."""
        session = FakeRawSession([
            real_response(
                302, b"",
                headers={"Location": "https://api.io.mi.com/app/other"},
                url="https://api.io.mi.com/app/home/device_list",
                method="POST",
            )
        ])
        sec = base64.b64encode(b"k" * 16).decode()
        auth = cloud.CloudSession(
            "1", sec, "ST"
        )
        api = cloud.MiCloudApi(session, auth)
        with self.assertRaises(cloud.CloudError) as ctx:
            api.list_devices()
        self.assertIn("unknown", str(ctx.exception))
        self.assertEqual(len(session.calls), 1)

    def test_login_post_redirect_never_replays_password_hash(self):
        session = FakeRawSession([
            real_response(200, b'&&&START&&&{"_sign":"SIG"}'),
            real_response(
                307, b"",
                headers={"Location": "https://account.xiaomi.com/pass/x?next=1"},
                url="https://account.xiaomi.com/pass/serviceLoginAuth2",
                method="POST",
            ),
        ])
        acct = cloud.MiAccount(session)
        with self.assertRaises(cloud.CloudError) as ctx:
            acct.login("user@example.com", "pw")
        # step1 + step2 exactly; the 307 was NOT re-POSTed
        self.assertEqual(len(session.calls), 2)
        self.assertNotIn("http", str(ctx.exception))


# ---------------------------------------------------------------------


def _drive_setup(peer, journal_path, *, extra_patches=()):
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
        ):
            for cm in extra_patches:
                cm.__enter__()
            try:
                return await cli.cmd_setup(_args_setup(journal_path))
            finally:
                for cm in extra_patches:
                    cm.__exit__(None, None, None)

    try:
        return run(scenario())
    except KeyboardInterrupt:
        return 130


class BindConfirmTiming(unittest.TestCase):
    """0x14 only in the pre-confirm window; never after 0x13 / 0x11."""

    def test_ctrlc_during_cert_upload_after_0x13_no_0x14(self):
        peer = FakeBleClient(outcome="ok")
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            injection = mock.patch.object(
                V2RegisterClient, "send_cloud_cert",
                side_effect=KeyboardInterrupt,
            )
            rc = _drive_setup(peer, journal_path, extra_patches=[injection])
            self.assertEqual(rc, 130)
            self.assertEqual(peer.count_writes(ZERO14), 0)  # never after 0x13
            self.assertGreaterEqual(peer.count_writes(ZERO13), 1)
            state = BindJournal(journal_path).load()
            # confirm-pending was journalled before 0x13; the interrupt
            # handler may have additionally recorded unknown — both are
            # honest; the invariant is: no 0x14, 0x13 was sent, journal kept
            self.assertIn(state.device_committed, ("confirm-pending", "unknown"))

    def test_ctrlc_during_wait_final_after_0x13_no_0x14(self):
        peer = FakeBleClient(outcome="ok")
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            injection = mock.patch.object(
                V2RegisterClient, "wait_final", side_effect=KeyboardInterrupt,
            )
            rc = _drive_setup(peer, journal_path, extra_patches=[injection])
            self.assertEqual(rc, 130)
            self.assertEqual(peer.count_writes(ZERO14), 0)
            self.assertGreaterEqual(peer.count_writes(ZERO13), 1)
            state = BindJournal(journal_path).load()
            # unknown retained: the device may or may not have committed
            self.assertIn(
                state.device_committed, ("confirm-pending", "unknown")
            )

    def test_timeout_after_0x13_no_0x14_unknown_outcome(self):
        peer = FakeBleClient(outcome="silent")
        real_wait_final = V2RegisterClient.wait_final

        async def short_wait_final(self, timeout=None):
            # the fake is synchronous: a silent device stays silent
            return await real_wait_final(self, timeout=0.01)

        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            rc = _drive_setup(peer, journal_path, extra_patches=[
                mock.patch.object(V2RegisterClient, "wait_final", short_wait_final)])
            self.assertEqual(rc, 1)
            self.assertEqual(peer.count_writes(ZERO14), 0)
            state = BindJournal(journal_path).load()
            self.assertEqual(state.device_committed, "unknown")

    def test_write_failure_after_0x13_no_0x14_unknown_outcome(self):
        # a BLE write failure in the blob or cert upload after 0x13
        for label, method in (("blob", "send_bind_blob"), ("cert", "send_cloud_cert")):
            with self.subTest(label), TemporaryDirectory() as tmp:
                peer = FakeBleClient(outcome="ok")
                journal_path = Path(tmp) / "journal.json"
                injection = mock.patch.object(
                    V2RegisterClient, method, side_effect=OSError("link lost"))
                rc = _drive_setup(peer, journal_path, extra_patches=[injection])
                self.assertEqual(rc, 1)
                self.assertEqual(peer.count_writes(ZERO13), 1)
                self.assertEqual(peer.count_writes(ZERO14), 0)
                state = BindJournal(journal_path).load()
                self.assertEqual(state.device_committed, "unknown")
                self.assertEqual(state.attempts[-1]["note"],
                                 "unknown outcome: BLE failure: link lost")

    def test_journal_failure_after_0_11_no_0_14(self):
        peer = FakeBleClient(outcome="ok")
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            injection = mock.patch.object(
                BindJournal, "record_device_committed",
                side_effect=J.JournalError("disk full"),
            )
            rc = _drive_setup(peer, journal_path, extra_patches=[injection])
            self.assertEqual(rc, 1)
            self.assertEqual(peer.count_writes(ZERO14), 0)  # never after 0x11
            self.assertGreaterEqual(peer.count_writes(ZERO13), 1)
            # the failure was recorded as unknown (nothing lost)
            state = BindJournal(journal_path).load()
            self.assertEqual(state.device_committed, "unknown")
            self.assertIn("unexpected interruption: JournalError",
                          state.attempts[-1]["note"])


# ---------------------------------------------------------------------


class NoChmodOfUserDirs(unittest.TestCase):
    """_secure_write must never chmod an existing (user) directory."""

    def test_tool_private_dir_created_0700_base_untouched(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            base_mode = stat.S_IMODE(base.stat().st_mode)
            private = base / ".cuktech_pc"
            cloud._secure_write(private / "journal.json", b"{}")
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            # the EXISTING base directory was not chmodded
            self.assertEqual(stat.S_IMODE(base.stat().st_mode), base_mode)

    def test_world_writable_parent_refused(self):
        with TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad"
            bad.mkdir()
            os.chmod(bad, 0o777)
            with self.assertRaises(cloud.CloudError) as ctx:
                cloud._secure_write(bad / "f", b"x")
            self.assertIn("writable", str(ctx.exception))

    def test_foreign_owner_refused(self):
        # a different euid makes the files of this test "not owned by you"
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            journal_path = base / "journal.json"
            BindJournal(journal_path).save(JournalState(mac=ADDRESS, model=MODEL))
            cache = base / "cloud-session.json"
            cache.write_text("{}")
            os.chmod(cache, 0o600)
            rows = {
                "_secure_write parent": (
                    lambda: cloud._secure_write(base / "f", b"x"), cloud.CloudError),
                "journal load": (
                    lambda: BindJournal(journal_path).load(), J.JournalError),
                "session cache load": (
                    lambda: sessioncache.load_session(cache),
                    sessioncache.SessionCacheError),
            }
            for label, (call, error) in rows.items():
                with self.subTest(label), mock.patch(
                    "os.geteuid", return_value=os.geteuid() + 1
                ), self.assertRaises(error) as ctx:
                    call()
                self.assertRegex(str(ctx.exception), "not own|not owned")
            self.assertFalse((base / "f").exists())

    def test_cli_export_into_0755_dir_preserves_it(self):
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            journal = BindJournal(journal_path)
            journal.save(JournalState(
                mac=ADDRESS, model=MODEL, token_hex="ab" * 12,
                stage="bound", bound_verified=True,
            ))
            out_dir = Path(tmp) / "outhere"
            out_dir.mkdir()
            os.chmod(out_dir, 0o755)
            out = out_dir / "token.json"
            rc = cli.main(
                ["export-token", "--journal", str(journal_path), "--output", str(out)]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(stat.S_IMODE(out_dir.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(list(out_dir.iterdir()), [out])  # no temp file left


# ---------------------------------------------------------------------


class NotRegisteredResume(unittest.TestCase):
    """e0 = ERR_NOT_REGISTERED: typed consent + live unregistered advert
    required before a fresh bind; never automatic."""

    def _journal(self, tmp) -> Path:
        journal_path = Path(tmp) / "journal.json"
        journal = BindJournal(journal_path)
        state = JournalState(mac=ADDRESS, model=MODEL, token_hex="ab" * 12)
        journal.record_derived(
            state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
            a_key_hex="ef" * 16, factory_did="1234567890123456789",
        )
        journal.record_intent_applydid(state)
        journal.record_did_allocated(state, "9876543210123456789")
        return journal_path

    def test_e0_peer_yields_typed_error(self):
        from cuktech_pc.blebind import MiAuthNotRegisteredError

        peer = FakeBleClient(login_error=bytes.fromhex("e0 00 00 00"))

        async def scenario():
            reg = V2RegisterClient(peer, timeout=1.0)
            async with reg:
                await reg.greet()
                await reg.login(b"\x99" * 12)

        with self.assertRaises(MiAuthNotRegisteredError):
            run(scenario())

    def test_declined_consent_after_e0_leaves_journal_intact(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._journal(tmp)

            async def scenario():
                with mock.patch.object(
                    cli, "verify_token_login", return_value=NOT_REGISTERED
                ), mock.patch.object(
                    cli, "scan_for_ad1204u", return_value=[make_hit()]
                ), mock.patch.object(
                    cloud, "MiAccount", _FakeAccount
                ), mock.patch(
                    "builtins.input", lambda prompt="": "declined"
                ), mock.patch(
                    "getpass.getpass", lambda *a, **k: "pw"
                ):
                    return await cli.cmd_setup(_args_setup(journal_path))

            rc = run(scenario())
            self.assertEqual(rc, 1)
            state = BindJournal(journal_path).load()
            self.assertEqual(state.token_hex, "ab" * 12)
            # no archive: consent not given
            self.assertFalse(any(
                p.name.startswith("journal.json.archived-")
                for p in Path(tmp).iterdir()
            ))

    def test_registered_advert_blocks_before_consent(self):
        from cuktech_pc.blebind import ScanHit

        registered_frame = parse_fe95(
            (0x0010 | 0x0100).to_bytes(2, "little")
            + (0x660E).to_bytes(2, "little")
            + b"\x07"
            + bytes.fromhex("ffeeddccbbaa")
        )
        hit = ScanHit(address=ADDRESS, name=MODEL, rssi=-50,
                      frame=registered_frame)
        with TemporaryDirectory() as tmp:
            journal_path = self._journal(tmp)

            async def scenario():
                with mock.patch.object(
                    cli, "verify_token_login", return_value=NOT_REGISTERED
                ), mock.patch.object(
                    cli, "scan_for_ad1204u", return_value=[hit]
                ), mock.patch.object(
                    cloud, "MiAccount", _FakeAccount
                ), mock.patch(
                    "builtins.input",
                    side_effect=AssertionError("consent prompt must not appear"),
                ):
                    return await cli.cmd_setup(_args_setup(journal_path))

            rc = run(scenario())
            self.assertEqual(rc, 1)
            # journal intact, no archive
            state = BindJournal(journal_path).load()
            self.assertEqual(state.token_hex, "ab" * 12)

    def test_e0_with_consent_archives_and_proceeds_fresh(self):
        with TemporaryDirectory() as tmp:
            journal_path = self._journal(tmp)
            peer = FakeBleClient(outcome="ok")

            async def scenario():
                real_verify = cli.verify_token_login
                calls = {"n": 0}

                async def verify_once(mac, token, journal_, state_):
                    calls["n"] += 1
                    if calls["n"] == 1:
                        return NOT_REGISTERED  # the e0 verdict
                    # the re-entered setup's final verification is real
                    return await real_verify(mac, token, journal_, state_)

                with mock.patch.object(
                    cli, "verify_token_login", side_effect=verify_once
                ), mock.patch.object(
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
                ):
                    return await cli.cmd_setup(_args_setup(journal_path))

            rc = run(scenario())
            self.assertEqual(rc, 0)
            # the old journal was archived and a fresh bind completed
            archives = [p for p in Path(tmp).iterdir()
                        if p.name.startswith("journal.json.archived-")]
            self.assertEqual(len(archives), 1)
            state = BindJournal(journal_path).load()
            self.assertEqual(state.stage, "bound")
            self.assertTrue(state.bound_verified)

    def _inconclusive_unsigned(self, tmp, hits, answer):
        journal_path = self._journal(tmp)  # no cloud signature received

        async def scenario():
            with mock.patch.object(
                cli, "verify_token_login", return_value=INCONCLUSIVE
            ), mock.patch.object(
                cli, "scan_for_ad1204u", return_value=hits
            ), mock.patch.object(
                cloud, "MiAccount", side_effect=AssertionError("no cloud")
            ), mock.patch("builtins.input", answer):
                return await cli.cmd_setup(_args_setup(journal_path))

        rc = run(scenario())
        self.assertEqual(rc, 1)
        self.assertEqual(BindJournal(journal_path).load().token_hex, "ab" * 12)
        self.assertFalse(any(p.name.startswith("journal.json.archived-")
                             for p in Path(tmp).iterdir()))

    def test_inconclusive_unsigned_needs_live_advert(self):
        """Never got the cloud signature + device not advertising: no
        prompt, nothing changed."""
        with TemporaryDirectory() as tmp:
            self._inconclusive_unsigned(
                tmp, [], mock.Mock(side_effect=AssertionError("no prompt")))

    def test_inconclusive_unsigned_offers_typed_consent(self):
        """Never got the cloud signature + live unregistered advert: the
        typed-consent gate is offered; declining changes nothing."""
        prompts: list[str] = []
        with TemporaryDirectory() as tmp:
            self._inconclusive_unsigned(
                tmp, [make_hit()],
                lambda p="": (prompts.append(p), "declined")[1])
        self.assertTrue(any("fresh bind" in p for p in prompts))


# ------------------------------------------------------------- misc shoulds


class ShouldFixRegressions(unittest.TestCase):
    def test_factory_did_must_be_digits(self):
        # punctuation/NUL in the DID is a malformed parcel
        with self.assertRaises(crypto.DevInfoError):
            crypto.parse_devinfo(b"\x02\x00\x00\x00\x00" + b"12-345678901234567")
        # 20 digits (no leading NUL) is fine
        info = crypto.parse_devinfo(b"\x02\x00\x00\x00" + b"1" * 20)
        self.assertEqual(info.factory_did_text, "1" * 20)

    def test_status_lists_archives_without_secrets(self):
        import contextlib
        import io as _io

        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            journal = BindJournal(journal_path)
            state = JournalState(
                mac=ADDRESS, model=MODEL, token_hex="ab" * 12,
                stage="cloud-signed", cloud_bind="standard_bind",
                server_did="9876543210123456789",
            )
            journal.save(state)
            journal.archive("test")
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["status", "--journal", str(journal_path)])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("archived-", out)
            self.assertIn("9876543210123456789", out)  # identity shown
            self.assertNotIn("ab" * 12, out)           # token never shown
            self.assertIn("present", out)              # only its presence

    def test_fresh_restart_always_archives(self):
        """Even a cloud-never-called journal is archived on the consented
        fresh restart."""
        with TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.json"
            journal = BindJournal(journal_path)
            state = JournalState(mac=ADDRESS, model=MODEL, token_hex="ab" * 12)
            journal.record_derived(
                state, token_hex="ab" * 12, bind_key_hex="cd" * 16,
                a_key_hex="ef" * 16, factory_did="1234567890123456789",
            )  # cloud_bind stays "no"
            peer = FakeBleClient(outcome="ok")

            async def scenario():
                real_verify = cli.verify_token_login
                calls = {"n": 0}

                async def verify_once(mac, token, journal_, state_):
                    calls["n"] += 1
                    if calls["n"] == 1:
                        return REJECTED
                    return await real_verify(mac, token, journal_, state_)

                with mock.patch.object(
                    cli, "verify_token_login", side_effect=verify_once
                ), mock.patch.object(
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
                ):
                    return await cli.cmd_setup(_args_setup(journal_path))

            rc = run(scenario())
            self.assertEqual(rc, 0)
            archives = [p for p in Path(tmp).iterdir()
                        if p.name.startswith("journal.json.archived-")]
            self.assertEqual(len(archives), 1)


if __name__ == "__main__":
    unittest.main()
