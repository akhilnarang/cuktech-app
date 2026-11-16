"""Empty-userId + 401 after 2FA — the live user failure (2026-10-12, round 6).

USER SYMPTOM: after 2FA completed (the new continuation got past it), the
CLI printed ``logged in as user  (skew -0.6s from server Date header)``
— an EMPTY userId — then ``scanning 10s...`` then
``cloud error: api call failed: HTTP 401``. Pre-binding: no consent, no
actions.

ROOT SHAPE: the old-chain 2FA continuation (result/check 302 → Auth2/end
extension-pragma → STS) sets ``_ssecurity`` and ``_service_token`` but
NEVER ingests the account identity — ``_user_id`` stays None because
``_load_success`` only runs in step-1/step-2 responses, and the chain's
``self._user_id or self._session_cookie("userId")`` fallback finds no
userId cookie on the modern front-end. The /app envelope then sends an
empty ``userId`` cookie → the server answers HTTP 401.

Fix contract (this file):
- ``login()`` must REFUSE to return a session with an empty user_id (no
  missing credential accepted);
- any successful 2FA continuation must leave the identity populated (the
  in-session step-1 re-check ingests userId/ssecurity/location);
- the printed success line must never show a raw (empty or not) userId —
  "Xiaomi login completed" only after validated fields;
- the session cache is saved only AFTER a successful authenticated
  device_list (full account-API validation), never merely on login.
"""


import base64
import contextlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import requests.models

from cuktech_pc import cloud, sessioncache
from tests.test_11_full_request import FakeServerSession
from tests.test_15_2fa_login_handoff import (
    LOCATION_URL,
    NOTIFICATION_URL,
    RoutingSession,
    real_response,
)

SEC = base64.b64encode(b"\x01" * 16).decode()


def oldchain_steps():
    """2FA that completes via the OLD chain, with the modern wrinkle the
    live server showed: no ``userId`` cookie is set anywhere, and the
    serviceLoginAuth2 notificationUrl response carries no identity.
    The step-1 RE-CHECK response (which _session_satisfied would fetch)
    DOES carry userId/ssecurity/location — the identity source."""
    steps = [
        real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                      url="https://account.xiaomi.com/pass/serviceLogin"),
        real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "code": 0, "desc": "ok",
                "notificationUrl": NOTIFICATION_URL,
            })).encode(),
            method="POST",
            url="https://account.xiaomi.com/pass/serviceLoginAuth2",
        ),
        real_response(200, b"ok", url=NOTIFICATION_URL),
        real_response(200, json.dumps({"flag": 8, "options": [8]}).encode(),
                      set_cookies=[("identity_session", "REDACTED-IS")],
                      url="https://account.xiaomi.com/identity/list"),
        real_response(200, json.dumps({"code": 0}).encode(), method="POST",
                      url="https://account.xiaomi.com/identity/auth/sendEmailTicket"),
        real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "code": 0,
                "location": "https://account.xiaomi.com/identity/result/check?x=1",
            })).encode(),
            method="POST",
            url="https://account.xiaomi.com/identity/auth/verifyEmail",
        ),
        # result/check -> 302 to Auth2/end
        real_response(
            302, b"",
            headers={"Location": "https://account.xiaomi.com/identity/auth/Auth2/end?x=1"},
            url="https://account.xiaomi.com/identity/result/check?x=1",
        ),
        # Auth2/end -> 302 with extension-pragma + STS location
        real_response(
            302, b"",
            headers={
                "extension-pragma": json.dumps({"ssecurity": SEC}),
                "Location": "https://sts.api.io.mi.com/sts?t=1",
            },
            url="https://account.xiaomi.com/identity/auth/Auth2/end?x=1",
        ),
        # STS 200 + serviceToken cookie (NO userId cookie — modern shape)
        real_response(
            200, b"ok",
            set_cookies=[("serviceToken", "REDACTED-ST")],
            url="https://sts.api.io.mi.com/sts?t=1",
        ),
        # step-1 re-check (fetched by the fixed continuation): the identity
        real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "ssecurity": SEC, "userId": 424242, "cUserId": "c-REDACTED",
                "passToken": "p", "location": LOCATION_URL, "code": 0,
            })).encode(),
            url="https://account.xiaomi.com/pass/serviceLogin",
        ),
        # step 3 for the re-check's NEW ssecurity: its matching serviceToken
        real_response(200, b"ok",
                      set_cookies=[("serviceToken", "REDACTED-ST-FRESH")],
                      url=LOCATION_URL),
    ]
    return steps


def make_account(session):
    return cloud.MiAccount(
        session,
        visible_input=lambda prompt: "",
        hidden_input=lambda prompt: "REDACTED-CODE",
    )


class EmptyUserIdAfterTwoFactor(unittest.TestCase):
    """The user's exact symptom as fixtures."""

    def test_oldchain_without_userid_cookie_yields_nonempty_userid(self):
        """RED-GREEN: the old chain completing must leave user_id
        populated (via the step-1 re-check), and login() must refuse an
        empty identity rather than returning a session that 401s."""
        session = RoutingSession(oldchain_steps())
        sess = make_account(session).login("user@example.com", "pw")
        # the missing-credential contract: no empty identity accepted
        self.assertTrue(sess.user_id, "user_id must be non-empty after 2FA")
        self.assertEqual(sess.ssecurity, SEC)
        # never the chain's token: it pairs with the OLD ssecurity (401)
        self.assertEqual(sess.service_token, "REDACTED-ST-FRESH")

    def test_api_envelope_sends_nonempty_userid_cookie(self):
        """The /app call must carry a non-empty userId cookie (the 401's
        direct cause) — verified through the REAL encrypted_post path."""
        session = RoutingSession(oldchain_steps())
        sess = make_account(session).login("user@example.com", "pw")
        seen: dict[str, str] = {}

        class ApiSpy:
            def __init__(self):
                self.cookies = requests.cookies.RequestsCookieJar()

            def request(self, method, url, **kw):
                seen.update(kw.get("cookies") or {})
                # a minimal valid base64 body; the decoder is patched
                return real_response(
                    200, base64.b64encode(b"{}").decode().encode(),
                    method="POST", url=url,
                )

        api = cloud.MiCloudApi(ApiSpy(), sess)
        with mock.patch.object(
            cloud, "decode_response_body",
            return_value={"code": 0, "result": {"list": []}},
        ):
            api.list_devices()
        self.assertEqual(seen.get("userId"), "424242")
        self.assertEqual(seen.get("serviceToken"), "REDACTED-ST-FRESH")
        self.assertEqual(seen.get("yetAnotherServiceToken"), "REDACTED-ST-FRESH")

    def test_login_refuses_empty_identity(self):
        """Even if a continuation somehow completed without identity,
        login() must fail loudly, not return a 401-bound session."""
        steps = oldchain_steps()
        # poison the identity source: step-1 re-check WITHOUT userId
        steps[9] = real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "ssecurity": SEC, "location": LOCATION_URL, "code": 0,
            })).encode(),
            url="https://account.xiaomi.com/pass/serviceLogin",
        )
        session = RoutingSession(steps)
        with self.assertRaises(cloud.CloudError) as ctx:
            make_account(session).login("user@example.com", "pw")
        self.assertIn("identity", str(ctx.exception).lower())


class SessionCacheSaveOnlyAfterValidation(unittest.TestCase):
    """The cache is written only after an AUTHENTICATED device_list."""

    def test_cached_401_discarded_then_fresh_login_once(self):
        """A cached session that the server 401s is discarded and the
        hidden login runs ONCE — no loop, journal untouched."""
        import asyncio

        from cuktech_pc import cli

        with TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "cloud-session.json"
            journal_path = Path(tmp) / "journal.json"
            # seed a cache with an EXPIRED serviceToken
            sessioncache.save_session(
                cache_path,
                cloud.CloudSession("424242", SEC, "EXPIRED-ST"),
                device_id="REDACTED-DEV",
                agent="UA",
                region="cn",
                username_tag=sessioncache.username_tag("user@example.com"),
            )
            login_calls = {"n": 0}

            class OnceAccount:
                def __init__(self, *a, **kw):
                    self.device_id = "REDACTED-DEV"
                    self.agent = "UA"
                    self._skew_seconds = 0.0
                    # the fresh login's device list succeeds
                    self.session = FakeServerSession(
                        lambda path, body: {"code": 0, "result": {"list": []}})

                def login(self, u, p):
                    login_calls["n"] += 1
                    return cloud.CloudSession("424242", SEC, "FRESH-ST")

            # the real MiCloudApi of the cached session gets HTTP 401
            expired = RoutingSession([real_response(
                401, b"unauthorized", method="POST",
                url="https://api.io.mi.com/app/home/device_list",
            )])

            async def scenario():
                with mock.patch.object(
                    cloud, "MiAccount", OnceAccount
                ), mock.patch.object(
                    cloud, "new_session",
                    side_effect=[expired, RoutingSession([])],
                ), mock.patch.object(
                    cli, "scan_for_ad1204u", return_value=[]  # BLE empty
                ), mock.patch(
                    "getpass.getpass", lambda *a, **k: "pw"
                ), mock.patch(
                    "builtins.input", lambda prompt="": "user@example.com"
                ):
                    args = cli.build_parser().parse_args([
                        "setup", "--journal", str(journal_path),
                        "--session-cache", str(cache_path),
                        "--username", "user@example.com",
                    ])
                    return await cli.cmd_setup(args)

            rc = asyncio.run(scenario())
            self.assertEqual(expired.steps, [])  # the 401 was served
            # BLE found nothing -> rc 1, but the login flow completed
            self.assertEqual(rc, 1)
            self.assertEqual(login_calls["n"], 1)  # exactly one fresh login
            # the cache now holds the FRESH token
            cached = sessioncache.load_session(
                cache_path,
                expected_username="user@example.com",
                expected_region="cn",
            )
            self.assertIsNotNone(cached)
            self.assertEqual(cached.service_token, "FRESH-ST")
            # no journal was created (pre-binding failure)
            self.assertFalse(journal_path.exists())

    def test_transient_failure_keeps_cache_and_aborts(self):
        import asyncio

        from cuktech_pc import cli

        with TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "cloud-session.json"
            journal_path = Path(tmp) / "journal.json"
            sessioncache.save_session(
                cache_path,
                cloud.CloudSession("424242", SEC, "CACHED-ST"),
                device_id="REDACTED-DEV", agent="UA", region="cn",
                username_tag=sessioncache.username_tag("user@example.com"),
            )
            login_calls = {"n": 0}

            class NeverAccount:
                def __init__(self, *a, **kw):
                    pass

                def login(self, u, p):
                    login_calls["n"] += 1
                    return cloud.CloudSession("1", "A", "B")

            class TimeoutApi:
                def __init__(self, *a, **kw):
                    pass

                def list_devices(self):
                    raise cloud.CloudError("network error during api call")

            async def scenario():
                with mock.patch.object(
                    cloud, "MiAccount", NeverAccount
                ), mock.patch.object(
                    cloud, "MiCloudApi", TimeoutApi
                ), mock.patch.object(
                    cloud, "new_session", return_value=RoutingSession([]),
                ), mock.patch.object(
                    cli, "scan_for_ad1204u", return_value=[]
                ), mock.patch(
                    "getpass.getpass", lambda *a, **k: "pw"
                ), mock.patch(
                    "builtins.input", lambda prompt="": "user@example.com"
                ):
                    args = cli.build_parser().parse_args([
                        "setup", "--journal", str(journal_path),
                        "--session-cache", str(cache_path),
                        "--username", "user@example.com",
                    ])
                    return await cli.cmd_setup(args)

            rc = asyncio.run(scenario())
            self.assertEqual(rc, 1)
            self.assertEqual(login_calls["n"], 0)  # no re-prompt
            # the cache was KEPT (transient failure must not discard it)
            cached = sessioncache.load_session(
                cache_path, expected_username="user@example.com",
                expected_region="cn",
            )
            self.assertIsNotNone(cached)
            self.assertEqual(cached.service_token, "CACHED-ST")
            self.assertFalse(journal_path.exists())


class CachedSkewRoundTrip(unittest.TestCase):
    """A re-run with the saved login signs with the skew learnt at login."""

    def test_skew_saved_and_loaded(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "cloud-session.json"
            sessioncache.save_session(
                path, cloud.CloudSession("424242", SEC, "ST"),
                device_id="D" * 16, agent="a", region="cn",
                username_tag=sessioncache.username_tag("u@example.com"),
                skew_seconds=-42.5,
            )
            cached = sessioncache.load_session(path)
            self.assertEqual(cached.skew_seconds, -42.5)


class SessionCacheRefusal(unittest.TestCase):
    """load_session refuses an unsafe or wrong-account cache and keeps the file."""

    def test_unsafe_cache_is_refused(self):
        def symlink(path):
            target = path.with_name("real-session.json")
            path.rename(target)
            path.symlink_to(target)
            return {}

        def foreign_owner(path):
            uid = os.geteuid() + 1
            return {"patch": mock.patch.object(sessioncache.os, "geteuid",
                                               return_value=uid)}

        def mode_0644(path):
            path.chmod(0o644)
            return {}

        def wrong_account(path):
            return {"expected_username": "other@example.com"}

        rows = [
            (symlink, "is a symlink"),
            (foreign_owner, "not owned by you"),
            (mode_0644, "has mode 0o644"),
            (wrong_account, "DIFFERENT account"),
        ]
        for change, reason in rows:
            with self.subTest(change.__name__), TemporaryDirectory() as tmp:
                path = Path(tmp) / "cloud-session.json"
                sessioncache.save_session(
                    path, cloud.CloudSession("424242", SEC, "ST"),
                    device_id="D" * 16, agent="a", region="cn",
                    username_tag=sessioncache.username_tag("u@example.com"),
                )
                opts = change(path)
                with opts.pop("patch", contextlib.nullcontext()):
                    with self.assertRaises(sessioncache.SessionCacheError) as ctx:
                        sessioncache.load_session(
                            path, expected_username=opts.get(
                                "expected_username", "u@example.com"))
                self.assertIn(reason, str(ctx.exception))
                self.assertTrue(path.exists())  # refused, never deleted


if __name__ == "__main__":
    unittest.main()
