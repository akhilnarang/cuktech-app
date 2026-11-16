"""Login branches: captcha (incl. 87001), scripted email 2FA, clock skew, env refusal.

All transport is a scripted fake session — no network, no credentials.
"""


import base64
import json
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import requests

from cuktech_pc import cloud

PASSWORD = "correct-horse"
PASSWORD_HASH = __import__("hashlib").md5(PASSWORD.encode()).hexdigest().upper()
SSEC = base64.b64encode(b"\x01" * 16).decode()


class FakeResponse:
    def __init__(self, status=200, text="", headers=None, cookies=None, content=b""):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies if cookies is not None else FakeCookies()
        self.content = content
        # pre-buffered body: lets cloud._drain_bounded skip streaming
        self._content = content if content else (text.encode() if text else b"")
        self._content_consumed = True

    def json(self):
        return json.loads(self.text)


class FakeCookies(dict):
    def get(self, name, default="", domain=None):  # requests-like
        return dict.get(self, name, default)

    def set(self, name, value, domain=None):
        self[name] = value


class FakeSession:
    """Routes GET/POST by URL substring to scripted responses."""

    def __init__(self, routes: list[tuple[str, FakeResponse]]):
        self.routes = routes
        self.calls: list[tuple[str, str]] = []
        self.cookies = FakeCookies()

    def _route(self, method: str, url: str) -> FakeResponse:
        self.calls.append((method, url))
        for needle, resp in self.routes:
            if needle in url:
                for k, v in resp.cookies.items():
                    self.cookies[k] = v  # mimic the cookie jar
                return resp
        return FakeResponse(status=404, text="{}")

    def get(self, url, **kw):
        return self._route("GET", url)

    def post(self, url, **kw):
        return self._route("POST", url)

    def request(self, method, url, **kw):
        # dispatch through get/post so per-test overrides keep working
        if str(method).upper() == "GET":
            return self.get(url, **kw)
        return self.post(url, **kw)


def jsonp(obj) -> str:
    return "&&&START&&&" + json.dumps(obj)


def login_ok_response() -> FakeResponse:
    return FakeResponse(
        text=jsonp({"ssecurity": SSEC, "userId": 424242, "passToken": "p",
                    "location": "https://sts.api.io.mi.com/sts?x=1"}),
        cookies=FakeCookies({"serviceToken": "STOK"}),
    )


def step1_sign_response() -> FakeResponse:
    return FakeResponse(
        text=jsonp({"_sign": "SIG"}),
        headers={"Date": "Mon, 12 Oct 2026 10:00:00 GMT"},
    )


def make_account(routes, visible=None, hidden=None, captcha_dir=None):
    return cloud.MiAccount(
        FakeSession(routes),
        visible_input=(visible or (lambda prompt: "1234")),
        hidden_input=(hidden or (lambda prompt: "654321")),
        captcha_dir=captcha_dir,
    )


class PasswordLoginNo2FA(unittest.TestCase):
    def test_straight_login(self):
        acct = make_account([
            ("pass/serviceLogin?", step1_sign_response()),
            ("serviceLoginAuth2", login_ok_response()),
            ("sts.api.io.mi.com", FakeResponse(cookies=FakeCookies({"serviceToken": "SVC-SENTINEL"}))),
        ])
        session = acct.login("user@example.com", PASSWORD)
        self.assertEqual(session.user_id, "424242")
        self.assertEqual(session.ssecurity, SSEC)
        self.assertEqual(session.service_token, "SVC-SENTINEL")
        # repr must not show the secret values
        self.assertNotIn(SSEC, repr(session))
        self.assertNotIn("SVC-SENTINEL", repr(session))

    def test_wrong_password_is_actionable_not_silent(self):
        acct = make_account([
            ("pass/serviceLogin?", step1_sign_response()),
            ("serviceLoginAuth2", FakeResponse(text=jsonp({"code": 70016, "description": "wrong password"}))),
        ])
        with self.assertRaises(cloud.CloudError) as ctx:
            acct.login("user@example.com", "nope")
        self.assertIn("wrong password", str(ctx.exception))


IMAGE = b"\x89PNG fake image"


class CaptchaBranch(unittest.TestCase):
    def _login(self, tmp, post_answers, codes):
        """Log in. The serviceLoginAuth2 POSTs get ``post_answers`` in order.

        Returns the session and the captCode value of each POST.
        """
        session = FakeSession([
            ("pass/serviceLogin?", step1_sign_response()),
            ("getCaptcha", FakeResponse(content=IMAGE)),
            ("sts.api.io.mi.com", FakeResponse(cookies=FakeCookies({"serviceToken": "ST"}))),
        ])
        answers = iter(post_answers)
        sent_codes: list[str | None] = []
        original_post = session.post

        def post(url, **kw):
            if "serviceLoginAuth2" in url:
                session.calls.append(("POST", url))
                sent_codes.append(kw["params"].get("captCode"))
                return next(answers)
            return original_post(url, **kw)

        session.post = post
        typed = iter(codes)
        acct = cloud.MiAccount(
            session,
            visible_input=lambda prompt: next(typed),
            hidden_input=lambda prompt: "654321",
            captcha_dir=Path(tmp),
        )
        return acct, session, sent_codes

    def _captcha_gets(self, session):
        return [u for (m, u) in session.calls if m == "GET" and "getCaptcha" in u]

    def test_captcha_then_success(self):
        with TemporaryDirectory() as tmp:
            acct, session, sent_codes = self._login(
                tmp,
                [FakeResponse(text=jsonp({"captchaUrl": "/getCaptcha"})),
                 login_ok_response()],
                ["AB12"],
            )
            result = acct.login("user@example.com", PASSWORD)
            self.assertEqual(result.user_id, "424242")
            image = Path(tmp) / "captcha.png"
            self.assertEqual(image.read_bytes(), IMAGE)
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
        self.assertEqual(sent_codes, [None, "AB12"])

    def test_invalid_captcha_87001_then_success(self):
        # POST 1: captchaUrl. POST 2: 87001 (bad code). POST 3: ok.
        with TemporaryDirectory() as tmp:
            acct, session, sent_codes = self._login(
                tmp,
                [FakeResponse(text=jsonp({"captchaUrl": "/getCaptcha"})),
                 FakeResponse(text=jsonp({"code": 87001, "captchaUrl": "/getCaptcha"})),
                 login_ok_response()],
                ["AB12", "CD34"],
            )
            result = acct.login("user@example.com", PASSWORD)
        self.assertEqual(result.user_id, "424242")
        # a fresh image for each prompt; the rejected code is not sent again
        self.assertEqual(len(self._captcha_gets(session)), 2)
        self.assertEqual(sent_codes, [None, "AB12", "CD34"])

    def test_captcha_exhaustion_is_actionable_not_silent(self):
        rejected = FakeResponse(text=jsonp({"code": 87001, "captchaUrl": "/getCaptcha"}))
        with TemporaryDirectory() as tmp:
            acct, _session, sent_codes = self._login(
                tmp, [rejected] * 10, ["AB12"] * 10)
            with self.assertRaises(cloud.CloudError) as ctx:
                acct.login("user@example.com", PASSWORD)
        self.assertIn("captcha", str(ctx.exception))
        self.assertIn("Try again", str(ctx.exception))  # actionable advice
        # bounded: the first login POST, then one answer POST for each of
        # the 3 captcha prompts, then an actionable stop
        self.assertEqual(len(sent_codes), 4)


class TwoFactorBranch(unittest.TestCase):
    def test_scripted_email_2fa(self):
        end_headers = {
            "extension-pragma": json.dumps({"ssecurity": SSEC}),
            "Location": "https://sts.api.io.mi.com/sts?t=1",
        }
        routes = [
            ("pass/serviceLogin?", step1_sign_response()),
            ("serviceLoginAuth2", FakeResponse(text=jsonp({"notificationUrl": "https://account.xiaomi.com/identity/authStart?context=CTX"}))),
            ("identity/authStart", FakeResponse()),
            ("identity/list", FakeResponse()),
            ("sendEmailTicket", FakeResponse()),
            ("verifyEmail", FakeResponse(text=json.dumps({"code": 0, "location": "https://account.xiaomi.com/identity/auth/Auth2/end?x=1"}))),
            ("Auth2/end", FakeResponse(headers=end_headers)),
            ("sts.api.io.mi.com", FakeResponse(cookies=FakeCookies({"serviceToken": "STS", "userId": "424242"}))),
        ]
        seen_hidden: list[str] = []
        acct = make_account(
            routes,
            hidden=lambda prompt: (seen_hidden.append(prompt), "654321")[1],
        )
        session = acct.login("user@example.com", PASSWORD)
        self.assertEqual(session.ssecurity, SSEC)
        self.assertEqual(session.service_token, "STS")
        self.assertTrue(seen_hidden and "code" in seen_hidden[0])  # hidden prompt
        # Auth2/end can be single-use. The verify location is Auth2/end, so
        # the login must GET it one time only.
        end_gets = [u for (m, u) in acct.session.calls
                    if m == "GET" and "Auth2/end" in u]
        self.assertEqual(len(end_gets), 1, end_gets)


# "Mon, 12 Oct 2026 10:00:00 GMT" in Unix seconds:
# 20738 days * 86400 + 10 h * 3600 = 1791799200.
DATE_TS = 1791799200.0


class CaptureSession:
    """Keeps the posted form, then fails like a network error."""

    def __init__(self):
        self.cookies = FakeCookies()
        self.forms: list[dict[str, str]] = []

    def request(self, method, url, **kw):
        self.forms.append(kw["data"])
        raise requests.ConnectionError("stop after the form is captured")


class ClockSkew(unittest.TestCase):
    def test_server_date_header_learned(self):
        acct = make_account([
            ("pass/serviceLogin?", step1_sign_response()),
            ("serviceLoginAuth2", login_ok_response()),
            ("sts.api.io.mi.com", FakeResponse(cookies=FakeCookies({"serviceToken": "ST"}))),
        ])
        with mock.patch.object(cloud.time, "time", return_value=DATE_TS - 90.5):
            acct.login("user@example.com", PASSWORD)
        self.assertEqual(acct._skew_seconds, 90.5)

    def test_nonce_uses_skewed_clock(self):
        session = CaptureSession()
        api = cloud.MiCloudApi(
            session, cloud.CloudSession("1", SSEC, "ST"), skew_seconds=600.0,
        )
        with mock.patch.object(cloud.time, "time", return_value=1_800_000_000.0):
            with self.assertRaises(cloud.CloudError):
                api.list_devices()
        # (1800000000 s + 600 s) * 1000 // 60000 = 30000010
        nonce = base64.b64decode(session.forms[0]["_nonce"])
        self.assertEqual(int.from_bytes(nonce[8:], "big"), 30_000_010)


class EnvRefusal(unittest.TestCase):
    def test_proxy_env_refused_any_case(self):
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                     "ALL_PROXY", "all_proxy"):
            with self.assertRaises(cloud.ProxyRefusedError, msg=name):
                cloud.assert_safe_env({name: "http://evil:8080"})
        # no false refusal: a clean env, or a proxy variable with no value
        for env in ({"HOME": "/home/x"}, {"HTTPS_PROXY": ""}):
            with self.subTest(env=env):
                cloud.assert_safe_env(env)

    def test_sslkeylogfile_refused_any_case(self):
        for name in ("SSLKEYLOGFILE", "sslkeylogfile"):
            with self.assertRaises(cloud.ProxyRefusedError, msg=name):
                cloud.assert_safe_env({name: "/tmp/keys"})

    def test_session_trust_env_disabled(self):
        self.assertIs(cloud.new_session().trust_env, False)


if __name__ == "__main__":
    unittest.main()
