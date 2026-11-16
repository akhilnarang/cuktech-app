"""2FA login handoff bug — deterministic red/green loop (user failure).

USER SYMPTOM (2026-10-12, live account): after entering the emailed 2FA
code, the CLI printed "manual action needed: 2FA finished but the account
wants further confirmation — open the account login in any browser,
complete it, then re-run this tool" plus the official
account.xiaomi.com/fe/service/identity/authStart challenge URL. The user
completed the SAME code in a browser and re-ran: identical result. The
"open browser + re-run" advice can never work: a re-run creates a FRESH
session that re-triggers 2FA.

These tests model the response shapes with REAL ``requests.Response``
objects on the streaming path. The new-shape fixture models what the
newer account front-end (``/fe/service/`` paths, non-en_US locale)
returns: ``verifyEmail`` answers ``{"code": 0}`` with NO ``location``,
and ``result/check`` answers 200 JSON with NO ``Location`` header — the
verification SUCCEEDED but the old continuation chain (result/check 302 →
Auth2/end → extension-pragma → STS) never materializes.
"""


import base64
import contextlib
import io
import json
import unittest
import urllib.parse

import requests.models

from cuktech_pc import cloud

# redacted fixture values (never real secrets)
SEC = base64.b64encode(b"\x01" * 16).decode()
CONTEXT = "REDACTED-CONTEXT"
NOTIFICATION_URL = (
    "https://account.xiaomi.com/fe/service/identity/authStart"
    f"?sid=xiaomiio&context={CONTEXT}&_locale=en_IN"
)
LOCALE = "en_IN"
LOCATION_URL = "https://sts.api.io.mi.com/sts?d=REDACTED"


def real_response(status=200, body=b"{}", headers=None, set_cookies=None,
                  url="https://account.xiaomi.com/x", method="GET"):
    r = requests.models.Response()
    r.status_code = status
    r.headers.update(headers or {})
    if set_cookies:
        for name, value in set_cookies:
            r.cookies.set(name, value)
        r.headers["Set-Cookie"] = ", ".join(f"{n}={v}" for n, v in set_cookies)
    r.raw = io.BytesIO(body)
    r._content = False
    r._content_consumed = False
    r.url = url
    r.request = requests.models.Request(method, url).prepare()
    return r


class RoutingSession:
    """Routes by call order; real Response objects; a real cookie jar.

    Each step must answer the URL path that the code requests. Thus a
    fixture with a step in the wrong position fails.
    """

    def __init__(self, steps):
        self.steps = list(steps)  # list[Response | Exception | callable]
        self.calls: list[tuple[str, str]] = []
        self.cookies = requests.cookies.RequestsCookieJar()

    def request(self, method, url, **kw):
        params = kw.get("params") or {}
        self.calls.append((method, url, dict(params)))
        item = self.steps.pop(0)
        if callable(item) and not isinstance(item, requests.models.Response):
            item = item(method, url)
        if isinstance(item, Exception):
            raise item
        want = urllib.parse.urlsplit(item.url).path
        got = urllib.parse.urlsplit(url).path
        if got != want:
            raise AssertionError(f"step {len(self.calls)}: {method} {got}, fixture has {want}")
        # merge Set-Cookie headers into the jar with the response host's
        # domain (requests behaviour), so domain-scoped lookups work
        host = urllib.parse.urlsplit(item.url).hostname or ""
        for line in item.headers.get("Set-Cookie", "").split(","):
            if "=" in line:
                name, _, value = line.partition("=")
                self.cookies.set(name.strip(), value.strip(), domain="." + host)
        return item


def jsonp(obj, method="POST"):
    return real_response(
        200, ("&&&START&&&" + json.dumps(obj)).encode(), method=method,
        url="https://account.xiaomi.com/pass/serviceLoginAuth2",
    )


def newshape_steps():
    """The full login with the NEW-shape 2FA responses.

    Call order:
      1 GET  serviceLogin            -> _sign
      2 POST serviceLoginAuth2       -> notificationUrl (fe/service, en_IN)
      3 GET  authStart               -> 200
      4 GET  identity/list           -> 200 flag/options + identity_session
      5 POST sendEmailTicket         -> 200 {"code":0}
      6 POST verifyEmail             -> 200 {"code":0} NO location   <- new
      7 GET  result/check            -> 200 {"code":0} NO Location  <- new
      8 GET  serviceLogin (re-run)   -> ssecurity + location (session satisfied)
      9 GET  location                -> 200 + serviceToken cookie
    """
    return [
        real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                      url="https://account.xiaomi.com/pass/serviceLogin"),
        jsonp({"notificationUrl": NOTIFICATION_URL, "code": 0, "desc": "ok"}),
        real_response(200, b"ok", url=NOTIFICATION_URL),
        real_response(200, json.dumps({"flag": 8, "options": [8]}).encode(),
                      set_cookies=[("identity_session", "REDACTED-IS")],
                      url="https://account.xiaomi.com/identity/list"),
        real_response(200, json.dumps({"code": 0}).encode(), method="POST",
                      url="https://account.xiaomi.com/identity/auth/sendEmailTicket"),
        real_response(200, json.dumps({"code": 0}).encode(), method="POST",
                      url="https://account.xiaomi.com/identity/auth/verifyEmail"),
        real_response(200, json.dumps({"code": 0}).encode(),
                      url="https://account.xiaomi.com/identity/result/check"),
        real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "ssecurity": SEC, "userId": 424242, "passToken": "p",
                "location": LOCATION_URL, "code": 0,
            })).encode(),
            url="https://account.xiaomi.com/pass/serviceLogin",
        ),
        real_response(200, b"ok",
                      set_cookies=[("serviceToken", "REDACTED-ST")],
                      url=LOCATION_URL),
    ]


def make_account(session):
    return cloud.MiAccount(
        session,
        visible_input=lambda prompt: "",
        hidden_input=lambda prompt: "REDACTED-CODE",
    )


def login_quiet(session):
    """Log in with ``make_account`` and return (session, printed text)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        sess = make_account(session).login("user@example.com", "pw")
    return sess, out.getvalue()


class NewShapeTwoFactor(unittest.TestCase):
    def test_code0_no_location_completes_login(self):
        """The user's exact symptom as a fixture: verifyEmail succeeds
        (code 0, no location), result/check is 200 JSON (no redirect) —
        login must still complete (same-session continuation), not raise
        ManualActionRequired."""
        session = RoutingSession(newshape_steps())
        acct = make_account(session)
        sess = acct.login("user@example.com", "pw")
        self.assertEqual(sess.ssecurity, SEC)
        self.assertEqual(sess.service_token, "REDACTED-ST")
        # the locale from the challenge URL must be used, not en_US
        identity_calls = [
            (u, p) for (_m, u, p) in session.calls
            if any(k in u for k in (
                "identity/result/check", "identity/list",
                "verifyEmail", "sendEmailTicket",
            ))
        ]
        self.assertTrue(identity_calls)
        for url, params in identity_calls:
            self.assertEqual(params.get("_locale"), LOCALE, url)


class SameSessionBrowserHandoff(unittest.TestCase):
    def delayed_steps(self):
        """New shape, but the session is only satisfied AFTER the user
        completes the challenge in a browser (second step1 re-run)."""
        steps = newshape_steps()
        # step1 re-run #1: still not satisfied (returns _sign again)
        steps[7] = real_response(
            200, b'&&&START&&&{"_sign":"SIG"}',
            url="https://account.xiaomi.com/pass/serviceLogin",
        )
        # after the Enter prompt: result/check again, then step1 satisfied
        steps.insert(
            8,
            real_response(200, json.dumps({"code": 0}).encode(),
                          url="https://account.xiaomi.com/identity/result/check"),
        )
        steps.insert(
            9,
            real_response(
                200,
                ("&&&START&&&" + json.dumps({
                    "ssecurity": SEC, "userId": 424242, "passToken": "p",
                    "location": LOCATION_URL, "code": 0,
                })).encode(),
                url="https://account.xiaomi.com/pass/serviceLogin",
            ),
        )
        return steps

    def test_press_enter_continues_same_session(self):
        session = RoutingSession(self.delayed_steps())
        prompts: list[str] = []
        acct = cloud.MiAccount(
            session,
            visible_input=lambda prompt: (prompts.append(prompt), "")[-1],
            hidden_input=lambda prompt: "REDACTED-CODE",
        )
        sess = acct.login("user@example.com", "pw")
        self.assertEqual(sess.ssecurity, SEC)
        # the handoff prompt asked for Enter in THIS session
        self.assertTrue(prompts and "Enter" in prompts[0])
        # the session continued without a restart and used every step
        self.assertEqual(session.steps, [])


class DiagnoseLoginCommand(unittest.TestCase):
    """The sanitized-trace fallback: phase/status/keys/code only."""

    def test_trace_is_sanitized(self):
        # a new-shape login through the diagnostic session: the trace must
        # contain phase + status + key names + numeric code, and NONE of
        # the secrets (context, code, ssecurity, serviceToken, password)
        session = RoutingSession(newshape_steps())
        diag = cloud.DiagnosticSession(session)
        acct = cloud.MiAccount(
            diag,
            visible_input=lambda prompt: "",
            hidden_input=lambda prompt: "REDACTED-CODE",
        )
        sess = acct.login("user@example.com", "hunter2-password")
        self.assertEqual(sess.service_token, "REDACTED-ST")
        text = diag.format_trace()
        self.assertIn("status=200", text)
        self.assertIn("keys=code", text)               # key names present
        self.assertIn("account.xiaomi.com/pass/serviceLogin", text)  # path only
        # NO secrets of any kind
        for secret in (
            CONTEXT, "REDACTED-CODE", "hunter2-password", SEC,
            "REDACTED-ST", "REDACTED-IS", "serviceToken", "ssecurity",
        ):
            self.assertNotIn(secret, text, secret)
        # no query strings at all (the context lives there)
        for line in text.splitlines():
            self.assertNotIn("?", line, line)


class MfaA_PrefixedVerifyEmail(unittest.TestCase):
    """Account-host bodies carry &&&START&&& — verifyEmail and the
    diagnostic trace must parse with the prefix-tolerant _to_json."""

    def _steps_with_verify(self, verify_body: bytes):
        steps = newshape_steps()
        steps[5] = real_response(
            200, verify_body, method="POST",
            url="https://account.xiaomi.com/identity/auth/verifyEmail",
        )
        return steps

    def test_prefixed_code0_completes(self):
        body = ("&&&START&&&" + json.dumps({"code": 0})).encode()
        session = RoutingSession(self._steps_with_verify(body))
        sess, printed = login_quiet(session)
        self.assertEqual(sess.service_token, "REDACTED-ST")
        # code 0 was parsed: the ambiguous path did not run
        self.assertNotIn("verification result unknown", printed)

    def test_prefixed_nonzero_is_rejected_not_handoff(self):
        payload = json.dumps({"code": 70016, "description": "wrong"})
        for name, body in (("plain", payload),
                           ("prefixed", "&&&START&&&" + payload)):
            with self.subTest(name):
                steps = self._steps_with_verify(body.encode())[:6]
                with self.assertRaises(cloud.CloudError) as ctx:
                    make_account(RoutingSession(steps)).login(
                        "user@example.com", "pw")
                msg = str(ctx.exception)
                self.assertIn("rejected", msg)
                self.assertIn("70016", msg)
                self.assertNotIn("browser", msg)
                self.assertNotIn("re-run", msg)

    def test_prefixed_location_feeds_chain(self):
        body = ("&&&START&&&" + json.dumps(
            {"code": 0,
             "location": "https://account.xiaomi.com/identity/result/check?x=1"}
        )).encode()
        steps = self._steps_with_verify(body)
        # result/check -> 302 Auth2/end; Auth2/end -> 302 + pragma + STS
        steps[6] = real_response(
            302, b"",
            headers={"Location": "https://account.xiaomi.com/identity/auth/Auth2/end?x=1"},
            url="https://account.xiaomi.com/identity/result/check?x=1")
        steps[7] = real_response(
            302, b"",
            headers={
                "extension-pragma": json.dumps({"ssecurity": SEC}),
                "Location": "https://sts.api.io.mi.com/sts?t=9",
            },
            url="https://account.xiaomi.com/identity/auth/Auth2/end?x=1")
        steps[8] = real_response(200, b"ok",
                                 set_cookies=[("serviceToken", "ST-CHAIN"), ("userId", "424242")],
                                 url="https://sts.api.io.mi.com/sts?t=9")
        session = RoutingSession(steps)
        sess, printed = login_quiet(session)
        self.assertEqual(sess.service_token, "ST-CHAIN")
        # the location came from the parsed JSON, not the body scrape
        self.assertNotIn("verification result unknown", printed)

    def test_missing_code_is_ambiguous_not_success_not_rejected(self):
        # garbage body: neither code 0 nor nonzero — must continue with
        # in-session checks (here: step-1 satisfied) and never claim
        # rejection
        steps = self._steps_with_verify(b"<html>garbage</html>")
        session = RoutingSession(steps)
        sess = make_account(session).login("user@example.com", "pw")
        self.assertEqual(sess.service_token, "REDACTED-ST")

    def test_diagnostic_keys_and_codes_for_prefixed_bodies(self):
        body = ("&&&START&&&" + json.dumps({"code": 0})).encode()
        session = RoutingSession(self._steps_with_verify(body))
        diag = cloud.DiagnosticSession(session)
        cloud.MiAccount(
            diag,
            visible_input=lambda prompt: "",
            hidden_input=lambda prompt: "REDACTED-CODE",
        ).login("user@example.com", "pw")
        text = diag.format_trace()
        # prefixed verifyEmail now shows keys + code (was blind before)
        self.assertIn(
            "POST https://account.xiaomi.com/identity/auth/verifyEmail "
            "status=200 keys=code code=0", text)
        # missing-code phases show code=unknown, never a fabricated 0
        self.assertIn("keys=_sign code=unknown", text)


class MfaB_NoBrowserRerunAdvice(unittest.TestCase):
    """Every continuation variant funnels to the same-session retry
    + bounded Enter handoff — no branch advises browser-then-re-run."""

    def _no_rerun(self, captured):
        for text in captured:
            self.assertNotIn("re-run this tool", text)
            self.assertNotIn("then re-run", text)

    def test_location_then_resultcheck_200_json_falls_back_to_step1(self):
        # verifyEmail -> location (result/check); result/check answers
        # 200 JSON without Location -> same-session step-1 succeeds
        body = json.dumps({
            "code": 0,
            "location": "https://account.xiaomi.com/identity/result/check?x=1",
        }).encode()
        steps = newshape_steps()
        steps[5] = real_response(200, body, method="POST",
                                 url="https://account.xiaomi.com/identity/auth/verifyEmail")
        # _continue_2fa GETs the provided location (result/check?x=1),
        # then result/check itself, then step-1: supply both 200-JSON
        # non-redirect responses before the satisfied step-1
        steps[6] = real_response(200, json.dumps({"code": 0}).encode(),
                                 url="https://account.xiaomi.com/identity/result/check?x=1")
        steps.insert(7, real_response(200, json.dumps({"code": 0}).encode(),
                                      url="https://account.xiaomi.com/identity/result/check"))
        session = RoutingSession(steps)
        sess = make_account(session).login("user@example.com", "pw")
        self.assertEqual(sess.service_token, "REDACTED-ST")

    def test_auth2end_without_extension_pragma_falls_back(self):
        # the chain reaches Auth2/end but it lacks extension-pragma ->
        # quiet None -> step-1 continuation, not a hard error
        steps = newshape_steps()
        steps[5] = real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "code": 0,
                "location": "https://account.xiaomi.com/identity/result/check?x=1",
            })).encode(),
            method="POST",
            url="https://account.xiaomi.com/identity/auth/verifyEmail")
        steps[6] = real_response(
            302, b"",
            headers={"Location": "https://account.xiaomi.com/identity/auth/Auth2/end?x=1"},
            url="https://account.xiaomi.com/identity/result/check?x=1")
        steps[7] = real_response(
            200, b"<html>no pragma</html>",  # no extension-pragma
            url="https://account.xiaomi.com/identity/auth/Auth2/end?x=1")
        # the quiet chain gave None: result/check, then the step-1 re-run
        steps[8] = real_response(200, json.dumps({"code": 0}).encode(),
                                 url="https://account.xiaomi.com/identity/result/check")
        steps.append(real_response(
            200,
            ("&&&START&&&" + json.dumps({
                "ssecurity": SEC, "userId": 424242, "passToken": "p",
                "location": LOCATION_URL, "code": 0,
            })).encode(),
            url="https://account.xiaomi.com/pass/serviceLogin"))
        steps.append(real_response(200, b"ok",
                                   set_cookies=[("serviceToken", "ST-FALLBACK")],
                                   url=LOCATION_URL))
        session = RoutingSession(steps)
        sess = make_account(session).login("user@example.com", "pw")
        self.assertEqual(sess.service_token, "ST-FALLBACK")

    def test_password_never_reposted_during_continuation(self):
        # count serviceLoginAuth2 POSTs across a full stalled continuation
        steps = newshape_steps()
        # make step-1 never satisfy; handoff rounds exhaust
        steps[7] = real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                                 url="https://account.xiaomi.com/pass/serviceLogin")
        steps.insert(8, real_response(200, json.dumps({"code": 0}).encode(),
                                      url="https://account.xiaomi.com/identity/result/check"))
        steps.insert(9, real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                                      url="https://account.xiaomi.com/pass/serviceLogin"))
        session = RoutingSession(steps)
        prompts: list[str] = []

        answers = iter(["", "skip"])  # Enter (round 1), skip (round 2)

        def visible(prompt):
            prompts.append(prompt)
            return next(answers)

        acct = cloud.MiAccount(
            session, visible_input=visible,
            hidden_input=lambda p: "REDACTED-CODE",
        )
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), \
                self.assertRaises(cloud.CloudError) as ctx:
            acct.login("user@example.com", "pw")
        auth_posts = [u for (m, u, _p) in session.calls
                      if m == "POST" and "serviceLoginAuth2" in u]
        self.assertEqual(len(auth_posts), 1)  # password POST exactly once
        self.assertEqual(len(prompts), 2)      # bounded handoff
        self.assertIn("press Enter HERE", prompts[0])  # same-session wording
        # in normal mode, each round shows the challenge URL
        self.assertEqual(printed.getvalue().count(NOTIFICATION_URL), 2)
        # the error points to the diagnostic command, never to a re-run
        self.assertIn("diagnose-login", str(ctx.exception))
        self.assertNotIn("re-run this tool", str(ctx.exception))


class MfaC_DiagnosticOutputSanitized(unittest.TestCase):
    """The ENTIRE diagnose-login output (stdout+stderr, success and
    failure paths) contains no identifiers, URLs, context, or server free
    text — asserted against sentinel values via the real CLI."""

    EMAIL = "victim@example.com"
    PASSWORD = "hunter2-sentinel"
    USER_ID_SENTINEL = "424242"

    def _run_cli(self, steps):
        import contextlib
        import io as _io
        from unittest import mock as _mock

        from cuktech_pc import cli

        buf_out, buf_err = _io.StringIO(), _io.StringIO()
        with _mock.patch.object(
            cloud, "new_session", return_value=RoutingSession(steps)
        ), _mock.patch(
            "getpass.getpass", lambda *a, **k: self.PASSWORD
        ), _mock.patch(
            "builtins.input", lambda prompt="": self.EMAIL
        ):
            with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
                rc = cli.main(["diagnose-login"])
        return rc, buf_out.getvalue(), buf_err.getvalue()

    def test_success_output_has_no_identifiers(self):
        rc, out, err = self._run_cli(newshape_steps())
        self.assertEqual(rc, 0)
        combined = out + err
        self.assertIn("outcome: success", combined)
        self.assertNotIn("scanning", combined)  # login only, no BLE scan
        for sentinel in (
            self.EMAIL, self.PASSWORD, self.USER_ID_SENTINEL,
            CONTEXT, "REDACTED-CODE", "REDACTED-ST", "REDACTED-IS",
            "ssecurity", "serviceToken", "passToken",
        ):
            self.assertNotIn(sentinel, combined, sentinel)
        for line in combined.splitlines():
            self.assertNotIn("?", line, line)  # no query strings at all

    def test_failure_output_has_no_server_text_or_identifiers(self):
        # a malicious server embeds free-text descs and echo-prone data
        steps = [
            real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                          url="https://account.xiaomi.com/pass/serviceLogin"),
            real_response(
                200,
                ("&&&START&&&" + json.dumps({
                    "code": 0,
                    "desc": "LEAK-" + self.EMAIL,
                    "description": "LEAK-" + self.PASSWORD,
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
            # rejected code: server free text must not reach the output
            real_response(
                200,
                ("&&&START&&&" + json.dumps({
                    "code": 70016,
                    "description": "LEAK-REJECTED-" + self.PASSWORD,
                })).encode(),
                method="POST",
                url="https://account.xiaomi.com/identity/auth/verifyEmail",
            ),
        ]
        rc, out, err = self._run_cli(steps)
        self.assertEqual(rc, 1)
        combined = out + err
        for sentinel in (
            self.EMAIL, self.PASSWORD, "LEAK-", CONTEXT,
            "REDACTED-CODE", "REDACTED-IS",
        ):
            self.assertNotIn(sentinel, combined, sentinel)
        self.assertIn("failure phase=2fa", combined)
        self.assertIn("code=unknown", combined)  # no server msg in outcome

    def test_handoff_url_hidden_in_diagnostic_mode(self):
        # a stalled continuation in DIAGNOSTIC mode: the challenge URL
        # (with context) must never be printed
        steps = newshape_steps()
        steps[7] = real_response(200, b'&&&START&&&{"_sign":"SIG"}',
                                 url="https://account.xiaomi.com/pass/serviceLogin")
        rc, out, err = self._run_cli(steps)
        combined = out + err
        self.assertNotIn("authStart?context=", combined)
        self.assertNotIn(CONTEXT, combined)
        self.assertIn("URL hidden in diagnostic mode", combined)


if __name__ == "__main__":
    unittest.main()
