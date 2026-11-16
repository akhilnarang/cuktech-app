"""Xiaomi cloud client for the one-time AD1204U bind, without Mi Home or a QR code.

The session login (password, captcha, email 2FA) and the RC4-signed /app API
envelope are adapted from ha-cuk-ble (https://github.com/zuyan9/ha-cuk-ble, Apache
License 2.0), which adapts PiotrMachowski/Xiaomi-cloud-tokens-extractor
(https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor, MIT);
originals at ``tools/ad1204u_fetch_token.py`` and
``custom_components/cuktech_ble/lib/xiaomi_cloud.py`` in ha-cuk-ble.

The envelope follows the decompiled Mi Home 11.9.521 APK exactly
(``laq``/``vo4``/``jql``/``fu4``):

- ``_nonce`` = b64(8 random bytes || BE-int32 minute bucket)
- ``signed_nonce`` = b64(SHA256(b64d(ssecurity) || b64d(nonce)))
- ``rc4_hash__`` = b64(SHA1(upper(method) & path & sorted "k=v" plain params
  & signed_nonce))
- One continuing RC4-drop-1024 keystream encrypts each param value
  (``data`` and ``rc4_hash__``) in sorted-key order. The key is the 32-byte
  signed-nonce digest. The app uses one RC4DropCoder instance. The common
  OSS extractors reset the keystream for each param. The ciphertext of the
  first param is the same in both cases, so both methods work.
- ``signature`` = the same SHA1 construction over the encrypted map.
- Response body: b64 -> RC4(signed_nonce) -> gunzip if
  ``MIOT-CONTENT-ENCODING: GZIP`` -> JSON.

The two bind endpoints are transcribed from ``_m_j/h37.java`` (DeviceApi):
``/device/bltapplydid`` (L1772-1790) and ``/v2/device/ble_standard_bind``
(L1625-1652). Their responses come from ``h37$OooOmo00`` (L301-316) and
``BleStandardAuthRegisterConnector$13`` (L288-304).

Security rules:

- All HTTP calls go through :func:`request`. It sets (connect, read)
  timeouts and a response-body size cap. It does not follow redirects
  automatically: it validates each hop against the allowlist before it
  fetches it. It changes exceptions into sanitized :class:`CloudError`
  messages that contain no URL. The password hash is in a query parameter,
  so a raw requests/urllib3 message can leak it.
- Each server-supplied URL (captcha, 2FA notification, redirects, STS) must
  use ``https``, have no userinfo and have a host on the official allowlist.
  If not, the module raises :class:`ManualActionRequired` and does not
  follow the URL.
- Proxy variables (any case) and ``SSLKEYLOGFILE`` are refused.
- Account cookies, ssecurity and the password stay in memory in this
  module. It does not save or log them. :mod:`cuktech_pc.sessioncache` can
  save the session (never the password).
- The 2FA ticket is read with hidden input.
- Each captcha attempt fetches a new captcha. A rejected code is not sent
  again.
- ``list_devices`` fails closed. An error envelope stops the guard. It does
  not look like an empty device list.
- The only device-delete call is :meth:`MiCloudApi.remove_device`. The CLI
  asks for user consent before it uses it.
"""


import base64
import hashlib
import json
import os
import random
import stat
import string
import time
import urllib.parse
import zlib
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from collections.abc import Callable

import requests

from .out import print  # noqa: A004 — rich-backed

SERVERS = ("cn", "de", "us", "ru", "tw", "sg", "in", "i2")
USER_AGENT = (
    "Android-7.1.1-1.0.0-ONEPLUS A3010-136-"
    # Mi Home style User-Agent that the cloud API expects, for interoperability (as in Xiaomi-cloud-tokens-extractor).
    "%s APP/xiaomi.smarthome APPV/62830"
) % "".join(random.choices(string.ascii_uppercase, k=13))

# ---- hardening constants --------------------------------
CONNECT_TIMEOUT = 10.0   # seconds, per HTTP call
READ_TIMEOUT = 30.0      # seconds, per HTTP call
MAX_REDIRECT_HOPS = 5
MAX_RESPONSE_BYTES = 1 << 20       # 1 MiB cap on any decoded body
MAX_CAPTCHA_BYTES = 512 << 10      # 512 KiB cap on the captcha image
MAX_USERNAME_LEN = 128

# Official Xiaomi hosts only. Server-supplied URLs must land here.
ALLOWED_HOSTS = frozenset(
    {"account.xiaomi.com", "sts.api.io.mi.com", "api.io.mi.com"}
    | {f"{region}.api.io.mi.com" for region in SERVERS}
)

PROXY_ENV_NAMES = ("http_proxy", "https_proxy", "all_proxy")
DANGEROUS_ENV_NAMES = ("sslkeylogfile",)

RC4_DROP = 1024
GUNZIP_MAX_BYTES = 65536


class CloudError(Exception):
    """A cloud operation failed. The message must contain no secrets."""


class ManualActionRequired(CloudError):
    """The login needs a manual step that this tool does not automate.

    Examples are the phone-confirmation page after 2FA, or a redirect to a
    host that is not on the allowlist.

    Attributes:
        url: Page for the user to open. It is always on the allowlist, or None.
    """

    def __init__(self, message: str, url: str | None = None) -> None:
        super().__init__(message)
        self.url = url


class ProxyRefusedError(CloudError):
    """A proxy variable or ``SSLKEYLOGFILE`` is set, so the tool does not run."""

    pass


class UnsafeURLError(CloudError):
    """A server-supplied URL failed the allowlist check. It is not followed."""


class CloudResponseError(CloudError):
    """A cloud response body is not valid: bad base64, gzip, size or fields."""

    pass


# --------------------------------------------------------------------- hygiene


def assert_safe_env(env: dict[str, str] | None = None) -> None:
    """Refuse to run if a proxy variable (any case) or SSLKEYLOGFILE is set.

    urllib3 uses SSLKEYLOGFILE also when ``trust_env`` is False. It then
    writes each TLS session key to disk. These keys protect the password
    hash, serviceToken and ssecurity.

    Args:
        env: Environment to check. If None, the function uses ``os.environ``.
            Empty values are ignored.

    Raises:
        ProxyRefusedError: If ``http_proxy``, ``https_proxy``, ``all_proxy``
            or ``SSLKEYLOGFILE`` is set.
    """
    env = os.environ if env is None else env
    lowered = {name.lower(): value for name, value in env.items() if value}
    present = [n for n in PROXY_ENV_NAMES if lowered.get(n)]
    if present:
        raise ProxyRefusedError(
            "the tool does not send account credentials through a proxy. Unset: "
            + ", ".join(sorted(set(present)))
        )
    if lowered.get("sslkeylogfile"):
        raise ProxyRefusedError(
            "SSLKEYLOGFILE is set. TLS session keys can then go to the "
            "disk. Unset it before you run this tool."
        )



def new_session() -> requests.Session:
    """Make a ``requests.Session`` that ignores environment proxy settings.

    Returns:
        A new session with ``trust_env`` set to False.
    """
    session = requests.Session()
    session.trust_env = False
    return session


# ------------------------------------------------------------------ URL policy


def validate_url(url: str) -> str:
    """Check one URL against the allowlist before the tool fetches it.

    The URL must use https, port 443 (or no port), no userinfo and a host in
    ``ALLOWED_HOSTS``. The error message never contains the URL, because
    query strings can contain credentials.

    Args:
        url: Absolute URL to check.

    Returns:
        The same URL, unchanged.

    Raises:
        UnsafeURLError: If the URL is malformed or fails one of the checks.
    """
    try:
        parts = urllib.parse.urlsplit(url)
    except (ValueError, AttributeError):
        raise UnsafeURLError("server sent a malformed URL") from None
    if parts.scheme != "https":
        raise UnsafeURLError("server sent a non-https URL (refused)")
    if parts.username or parts.password:
        raise UnsafeURLError("server sent a URL with userinfo (refused)")
    if parts.port is not None and parts.port != 443:
        raise UnsafeURLError("server sent a non-443 port (refused)")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise UnsafeURLError(
            "server sent a URL on an unexpected host (refused; "
            "official hosts: account.xiaomi.com, sts.api.io.mi.com, "
            "{region.}api.io.mi.com)"
        )
    return url


def _hop_location(response: Any, url: str) -> str | None:
    """Extract the next redirect target, resolved against the current URL."""
    loc = None
    try:
        loc = response.headers.get("Location")
    except Exception:  # noqa: BLE001 — fake transports
        loc = None
    if not loc:
        return None
    return urllib.parse.urljoin(url, loc)


def abs_account_url(url: str) -> str:
    """Make a server-supplied relative URL absolute on the account origin.

    Xiaomi sends some fields (``captchaUrl``, 2FA redirects) as bare paths.
    The function joins them to ``https://account.xiaomi.com`` before the
    allowlist check, so a relative path cannot skip the validation.

    Args:
        url: Relative or absolute URL. It can be empty.

    Returns:
        The absolute URL. An empty value, or a URL that already has a
        scheme or host, is returned unchanged.
    """
    if not url:
        return url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme or parts.netloc:
        return url
    return urllib.parse.urljoin("https://account.xiaomi.com", url)


# ------------------------------------------------------------------ RC4 math


def _rc4_keystream(key: bytes):
    """Yield RC4 keystream bytes after ``RC4_DROP`` bytes are discarded."""
    if not key:
        raise ValueError("empty RC4 key")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for _ in range(RC4_DROP):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    while True:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) & 0xFF]


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt with RC4-drop1024 (the RC4DropCoder of the app).

    Args:
        key: RC4 key. It must not be empty.
        data: Plaintext or ciphertext.

    Returns:
        ``data`` XORed with the keystream. It has the same length as ``data``.

    Raises:
        ValueError: If ``key`` is empty.
    """
    ks = _rc4_keystream(key)
    return bytes(b ^ next(ks) for b in data)


# ------------------------------------------------------------- envelope math


def generate_nonce(*, now_ms: int | None = None) -> str:
    """Make a request nonce: b64(8 random bytes || BE int32 minute bucket).

    This follows vo4 L20-31. The random bytes come from ``os.urandom``.

    Args:
        now_ms: Current time in milliseconds since the Unix epoch. Include
            the server clock skew. If None, the function uses local time.

    Returns:
        The base64 nonce string (12 bytes before encoding).
    """
    rand = os.urandom(8)
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return base64.b64encode(rand + (now_ms // 60000).to_bytes(4, "big")).decode()


def signed_nonce(ssecurity_b64: str, nonce_b64: str) -> str:
    """Calculate b64(SHA256(b64d(ssecurity) || b64d(nonce))).

    Args:
        ssecurity_b64: Base64 ssecurity from the login.
        nonce_b64: Base64 nonce from :func:`generate_nonce`.

    Returns:
        The base64 SHA-256 digest (32 bytes before encoding). The decoded
        digest is also the RC4 key.

    Raises:
        binascii.Error: If an input is not valid base64.
    """
    digest = hashlib.sha256(
        base64.b64decode(ssecurity_b64) + base64.b64decode(nonce_b64)
    ).digest()
    return base64.b64encode(digest).decode()


def envelope_signature(
    method: str, path: str, params: dict[str, str], signed_nonce_b64: str
) -> str:
    """Calculate b64(SHA1(upper(method) & path & sorted k=v pairs & signed_nonce)).

    Args:
        method: HTTP method. The function converts it to upper case.
        path: Request path without the ``/app`` prefix.
        params: Form parameters. The function sorts them by key.
        signed_nonce_b64: Value from :func:`signed_nonce`.

    Returns:
        The base64 SHA-1 digest.
    """
    parts = [method.upper(), path]
    parts.extend(f"{k}={v}" for k, v in sorted(params.items()))
    parts.append(signed_nonce_b64)
    digest = hashlib.sha1("&".join(parts).encode()).digest()
    return base64.b64encode(digest).decode()


def build_request_form(
    ssecurity_b64: str,
    nonce_b64: str,
    signed_nonce_b64: str,
    data_json: str,
    path: str,
) -> dict[str, str]:
    """Make the encrypted /app form fields (laq.encrypt L59-117).

    The app signs method + encoded path + sorted params + signed_nonce
    (vo4.generateSignature L48-80). The OSS extractors that work in the
    field do the same. One continuing RC4 keystream encrypts all plain
    params (``data`` and the new ``rc4_hash__``) in sorted-key order, as the
    app does.

    Args:
        ssecurity_b64: Base64 ssecurity from the login.
        nonce_b64: Base64 nonce from :func:`generate_nonce`.
        signed_nonce_b64: Value from :func:`signed_nonce`.
        data_json: JSON request body for the ``data`` field.
        path: Request path without the ``/app`` prefix, for example
            ``/device/bltapplydid``.

    Returns:
        Form fields ``data``, ``rc4_hash__``, ``signature``, ``ssecurity``
        and ``_nonce``. The first two are RC4-encrypted and base64-encoded.
    """
    plain: dict[str, str] = {"data": data_json}
    plain["rc4_hash__"] = envelope_signature("POST", path, plain, signed_nonce_b64)
    key = base64.b64decode(signed_nonce_b64)
    ks = _rc4_keystream(key)
    encrypted: dict[str, str] = {}
    for name in sorted(plain):
        value = plain[name].encode()
        enc = bytes(b ^ next(ks) for b in value)
        encrypted[name] = base64.b64encode(enc).decode()
    encrypted["signature"] = envelope_signature("POST", path, encrypted, signed_nonce_b64)
    encrypted["ssecurity"] = ssecurity_b64
    encrypted["_nonce"] = nonce_b64
    return encrypted


def gunzip_bounded(data: bytes, max_bytes: int = GUNZIP_MAX_BYTES) -> bytes:
    """Decompress gzip data with a size cap, to stop decompression bombs.

    Args:
        data: Gzip container bytes.
        max_bytes: Largest permitted output size, in bytes. The default is
            65536.

    Returns:
        The decompressed bytes.

    Raises:
        CloudResponseError: If the gzip stream is not valid or the output
            is larger than ``max_bytes``.
    """
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip container
    try:
        out = d.decompress(data, max_bytes + 1)
    except zlib.error as exc:
        raise CloudResponseError("invalid gzip stream") from exc
    if len(out) > max_bytes:
        raise CloudResponseError("gunzipped response exceeds size cap")
    return out


def decode_response_body(
    ssecurity_b64: str,
    nonce_b64: str,
    body_text: str,
    content_encoding: str | None = None,
) -> dict[str, Any]:
    """Decrypt an /app response body, gunzip it if necessary and parse the JSON.

    Args:
        ssecurity_b64: Base64 ssecurity of the request.
        nonce_b64: Base64 nonce of the request.
        body_text: Base64 RC4 ciphertext from the response.
        content_encoding: Value of the ``MIOT-CONTENT-ENCODING`` header. If
            it is ``GZIP`` (any case), the function decompresses the body.

    Returns:
        The parsed JSON object. A ``&&&START&&&`` prefix is removed first.

    Raises:
        CloudResponseError: If the body is not valid base64, or it is GZIP
            without the gzip magic bytes, or the gzip data is not valid.
        ValueError: If the decrypted text is not valid JSON.
    """
    key = base64.b64decode(signed_nonce(ssecurity_b64, nonce_b64))
    try:
        decrypted = rc4_crypt(key, base64.b64decode(body_text))
    except (ValueError, TypeError) as exc:
        raise CloudResponseError("response body is not valid base64/RC4") from exc
    if (content_encoding or "").upper() == "GZIP":
        if not decrypted[:2] == b"\x1f\x8b":
            raise CloudResponseError("GZIP response missing gzip magic")
        decrypted = gunzip_bounded(decrypted)
    text = decrypted.decode("utf-8", errors="replace")
    return _to_json(text)


def decode_b64_field(value: str) -> bytes:
    """Decode a cloud field from base64, then gunzip it if it has the gzip magic.

    This does the same as ``vq1.OooO0oO`` (Base64Coder.decode, vq1.java
    L131-185). The app uses it for ``cloud_sign`` and ``cloud_cert``. The
    function accepts the URL-safe alphabet, whitespace and missing padding.

    Args:
        value: Base64 text from the server.

    Returns:
        The decoded bytes, decompressed if they start with ``1f 8b``.

    Raises:
        CloudResponseError: If ``value`` is empty, is not valid base64, or
            contains gzip data that is not valid or too large.
    """
    if not value:
        raise CloudResponseError("cloud field is empty")
    # the app decodes with flags 24 (URL_SAFE|NO_CLOSE): '-'/'_' alphabet,
    # whitespace skipped, padding optional (live failure 2026-10-12)
    text = "".join(str(value).split()).replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise CloudResponseError("cloud field is not valid base64") from exc
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        raw = gunzip_bounded(raw)
    return raw


# ------------------------------------------------------------ body builders


def build_applydid_body(
    mac: str, model: str, token_hex: str, did: str = "", home: dict[str, Any] | None = None
) -> str:
    """Make the JSON body for POST /device/bltapplydid (h37.OooOOO0 L1772-1790).

    The key order is the same as in the app: mac, model, token,
    [homeId, uid], did (only if not empty).

    Args:
        mac: BLE address as the BLE stack reports it.
        model: Device model string.
        token_hex: Device token, as a hex string.
        did: Existing device ID. Empty means no ``did`` key.
        home: Optional dict with ``homeId`` and ``uid``.

    Returns:
        Compact JSON text.

    Raises:
        KeyError: If ``home`` is set but has no ``homeId`` or ``uid``.
    """
    body: dict[str, Any] = {"mac": mac, "model": model, "token": token_hex}
    if home:
        body["homeId"] = home["homeId"]
        body["uid"] = home["uid"]
    if did:
        body["did"] = did
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def build_standard_bind_body(
    did: str,
    token_hex: str,
    bind_key_hex: str,
    smac: str,
    home: dict[str, Any] | None = None,
) -> str:
    """Make the JSON body for POST /v2/device/ble_standard_bind (h37.OooO0o L1625-1652).

    The key order is the same as in the app: did, token,
    props[bind_key, smac], beacon_key (= bind_key), [homeId, uid].

    Args:
        did: Device ID from :func:`parse_applydid`.
        token_hex: Device token, as a hex string.
        bind_key_hex: Bind key, as a hex string. It is also the beacon key.
        smac: Value of the ``smac`` prop.
        home: Optional dict with ``homeId`` and ``uid``.

    Returns:
        Compact JSON text.

    Raises:
        KeyError: If ``home`` is set but has no ``homeId`` or ``uid``.
    """
    body: dict[str, Any] = {
        "did": did,
        "token": token_hex,
        "props": [
            {"type": "prop", "key": "bind_key", "value": bind_key_hex},
            {"type": "prop", "key": "smac", "value": smac},
        ],
        "beacon_key": bind_key_hex,
    }
    if home:
        body["homeId"] = home["homeId"]
        body["uid"] = home["uid"]
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


# ------------------------------------------------------------ response parsing


def _payload(obj: dict[str, Any]) -> dict[str, Any]:
    """Unwrap {"result": {...}} if the server put the payload there.

    The /app envelope sometimes puts the endpoint payload in ``result``, as
    /home/device_list does. The function accepts both shapes.
    """
    result = obj.get("result")
    if isinstance(result, dict) and (
        "did" in result or "success" in result or "list" in result
    ):
        return result
    return obj


def parse_applydid(obj: dict[str, Any]) -> str:
    """Get the device ID from a /device/bltapplydid response.

    Args:
        obj: Decoded response, flat or with a ``result`` object.

    Returns:
        The ``did`` value, with whitespace stripped.

    Raises:
        CloudResponseError: If the response has no ``did`` or it is empty.
    """
    payload = _payload(obj)
    did = str(payload.get("did") or "").strip()
    if not did:
        raise CloudResponseError("bltapplydid response has no did")
    return did


@dataclass(frozen=True)
class BindCloudMaterial:
    """Signed cloud data from /v2/device/ble_standard_bind.

    Attributes:
        cloud_sign: Cloud signature. Exactly 64 bytes.
        cloud_cert: Cloud certificate, X.509 DER. Not empty.
        utc: Server time in seconds since the Unix epoch, in the u32 range.
    """

    cloud_sign: bytes  # exactly 64 bytes
    cloud_cert: bytes  # X.509 DER, non-empty
    utc: int


def parse_bind_response(obj: dict[str, Any]) -> BindCloudMaterial:
    """Parse a /v2/device/ble_standard_bind response (RegisterConnector$13 L288-304).

    Args:
        obj: Decoded response, flat or with a ``result`` object.

    Returns:
        The decoded ``cloud_sign``, ``cloud_cert`` and ``utc``.

    Raises:
        CloudResponseError: If ``success`` is false, ``cloud_sign`` is not
            64 bytes, a field cannot be decoded, or ``utc`` is missing or
            not in the range 1 to 0xFFFFFFFF.
    """
    payload = _payload(obj)
    if not payload.get("success"):
        raise CloudResponseError(
            "ble_standard_bind reported success=false"
        )
    cloud_sign = decode_b64_field(str(payload.get("cloud_sign") or ""))
    if len(cloud_sign) != 64:
        raise CloudResponseError(
            f"cloud_sign must decode to 64 bytes, got {len(cloud_sign)}"
        )
    cloud_cert = decode_b64_field(str(payload.get("cloud_cert") or ""))
    try:
        utc = int(payload["utc"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CloudResponseError("ble_standard_bind response has no valid utc") from exc
    if not 0 < utc <= 0xFFFFFFFF:
        raise CloudResponseError(f"utc out of u32 range: {utc}")
    return BindCloudMaterial(cloud_sign=cloud_sign, cloud_cert=cloud_cert, utc=utc)


# ------------------------------------------------------------------- helpers


def _to_json(text: str) -> dict[str, Any]:
    """Parse JSON after the removal of the ``&&&START&&&`` account prefix."""
    return json.loads(text.replace("&&&START&&&", "", 1))


FLAG_SMS, FLAG_EMAIL = 4, 8


def _verify_flag(list_text: str) -> int:
    """Select the 2FA method from identity/list: 4 = SMS, 8 = email.

    If the method is not known, the function returns email (the old behaviour).
    """
    try:
        j = _to_json(list_text)
    except ValueError:
        return FLAG_EMAIL
    options = [o for o in (j.get("options") or []) if isinstance(o, int)]
    preferred = j.get("flag")
    if preferred in (FLAG_SMS, FLAG_EMAIL) and (not options or preferred in options):
        return preferred
    if FLAG_EMAIL in options:
        return FLAG_EMAIL
    if FLAG_SMS in options:
        return FLAG_SMS
    return FLAG_EMAIL


def normalize_mac(mac: str) -> str:
    """Make a compact lowercase MAC.

    Args:
        mac: MAC address with or without ``:`` or ``-`` separators.

    Returns:
        The MAC without separators and whitespace, in lowercase.
    """
    return mac.replace(":", "").replace("-", "").strip().lower()


def reverse_mac_bytes(mac: str) -> str:
    """Reverse the byte order of a MAC. The function reverses hex pairs.

    Example: "123456789abc" -> "bc9a78563412". The FE95 payload stores the
    address little-endian, so the cloud can show either byte order.

    Args:
        mac: MAC address in any form that :func:`normalize_mac` accepts.

    Returns:
        The byte-reversed compact MAC. If the compact MAC is not
        12 characters long, the compact MAC without change.
    """
    compact = normalize_mac(mac)
    if len(compact) != 12:
        return compact
    return "".join(
        compact[i : i + 2] for i in range(len(compact) - 2, -1, -2)
    )


def _mac_candidates(mac: str) -> set[str]:
    """The compact MAC and its byte-reversed form."""
    compact = normalize_mac(mac)
    return {compact, reverse_mac_bytes(mac)}


class CloudSession:
    """Account session data, in memory only.

    This class does not save or log the data. ``repr`` hides the secrets.

    Attributes:
        user_id: Xiaomi userId.
        ssecurity: Base64 secret that signs the RC4 envelope.
        service_token: Bearer serviceToken cookie value.
    """

    __slots__ = ("user_id", "ssecurity", "service_token")

    def __init__(self, user_id: str, ssecurity: str, service_token: str) -> None:
        self.user_id = user_id
        self.ssecurity = ssecurity
        self.service_token = service_token

    def __repr__(self) -> str:  # deliberately secret-free
        return f"<CloudSession user_id={self.user_id!r} ssecurity=*** serviceToken=***>"


# ------------------------------------------------------------------- requests


def request(
    session: Any,
    method: str,
    url: str,
    *,
    stage: str,
    timeout: tuple[float, float] = (CONNECT_TIMEOUT, READ_TIMEOUT),
    max_bytes: int = MAX_RESPONSE_BYTES,
    follow_get_hops: bool = False,
    **kwargs: Any,
) -> Any:
    """Send one HTTP request. All HTTP calls of this module use this function.

    Redirect rules (the function never follows redirects automatically):

    - A POST is never redirected. A 3xx answer to a POST raises a sanitized
      ``CloudError``. The password hash and the cloud mutations
      (``bltapplydid``, ``ble_standard_bind``) must never go to a different
      hop. Login and 2FA code that needs redirect responses uses
      ``method="GET"``. The upstream 2FA chain uses GET after the first
      POST. The intermediate 302 responses carry the
      ``extension-pragma``/``Location`` data that the caller reads.
    - The function follows GET hops only if ``follow_get_hops=True``. It
      validates each hop with ``validate_url`` before it fetches it. A hop
      has no params, data or per-request cookies. The chain has a limit of
      ``MAX_REDIRECT_HOPS``. Without the flag, the function returns the raw
      30x response (2FA reads its headers).
    - For each call, the function validates the URL first (https, port 443
      only, no userinfo, official host). It sets a ``(connect, read)``
      timeout and reads a streamed body with a hard size cap.

    Args:
        session: ``requests.Session`` or a fake with the same ``request``
            method.
        method: HTTP method, for example ``"GET"`` or ``"POST"``.
        url: Absolute URL. It must pass :func:`validate_url`.
        stage: Short name of the step. Error messages show it in place of
            the URL.
        timeout: (connect, read) timeout in seconds.
        max_bytes: Largest permitted response body, in bytes.
        follow_get_hops: If True, follow GET redirects after validation.
        **kwargs: Other arguments for ``session.request`` (``params``,
            ``data``, ``headers``, ``cookies``). The function sets
            ``allow_redirects=False``, ``timeout`` and ``stream=True`` if
            they are not given.

    Returns:
        The response, with the body already read into memory. It can be a
        30x response if redirects are not followed.

    Raises:
        UnsafeURLError: If ``url`` fails the allowlist check.
        CloudError: For a network error, a redirect of a non-GET request, or
            too many redirects. The message never contains a URL.
        CloudResponseError: If the body is larger than ``max_bytes``.
        ManualActionRequired: If a redirect goes to a host outside the
            allowlist.
    """
    current = validate_url(url)
    kwargs.setdefault("allow_redirects", False)
    kwargs.setdefault("timeout", timeout)
    kwargs.setdefault("stream", True)
    for _hop in range(MAX_REDIRECT_HOPS + 1):
        try:
            response = session.request(method, current, **kwargs)
            _drain_bounded(response, max_bytes)
        except requests.RequestException:
            raise CloudError(f"network error during {stage}") from None
        except OSError:
            raise CloudError(f"network error during {stage}") from None
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        if method.upper() != "GET":
            raise CloudError(
                f"unexpected redirect during {stage}. The tool does not send "
                "POSTs again. It is not known if the server processed the "
                "operation. Treat the outcome as unknown."
            )
        if not follow_get_hops:
            return response  # raw 30x to the caller (2FA reads headers)
        nxt = _hop_location(response, current)
        if nxt is None:
            return response
        try:
            current = validate_url(nxt)
        except UnsafeURLError:
            raise ManualActionRequired(
                "the server redirected to a host outside the official "
                "Xiaomi allowlist. Open the login in a browser.",
                None,
            ) from None
        # hop GETs are bare: no params, no data, no per-request cookies
        kwargs.pop("params", None)
        kwargs.pop("data", None)
        kwargs.pop("cookies", None)
    raise CloudError(f"too many redirects during {stage}")


def _drain_bounded(response: Any, max_bytes: int) -> None:
    """Read a streamed body into the response, with a hard size cap.

    On a real ``requests.Response``, ``text`` is a read-only property. The
    function sets only the fields that the property reads:
    ``_content``, ``_content_consumed`` and, if possible, ``encoding``. It
    skips fakes that already have a buffered body.
    """
    if getattr(response, "_content", False) is not False and getattr(
        response, "_content_consumed", True
    ):
        return  # already fully buffered by a fake transport
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise CloudResponseError("response body exceeds size cap")
            chunks.append(chunk)
    except CloudResponseError:
        raise
    except Exception:  # noqa: BLE001 — fake transports raise assorted errors
        raise CloudError("network error while reading response") from None
    body = b"".join(chunks)
    # real requests.Response: setting _content + encoding makes .text/.content
    # work; .text itself is read-only and must never be assigned
    response._content = body
    response._content_consumed = True
    encoding = getattr(response, "encoding", None)
    if encoding is None:
        try:
            response.encoding = "utf-8"  # supported on requests.Response
        except AttributeError:
            pass  # minimal fakes without the setter


# ------------------------------------------------------------------- login


class MiAccount:
    """Log in to a Xiaomi account with a password, with captcha and 2FA steps.

    Tests can replace the input functions: ``visible_input`` reads captcha
    codes and ``hidden_input`` reads passwords and 2FA tickets (hidden on
    the terminal).

    Args:
        session: HTTP session. If None, the class uses :func:`new_session`.
        visible_input: Prompt function for captcha codes.
        hidden_input: Prompt function for secrets such as 2FA tickets.
        captcha_dir: Directory for captcha images. If None, the class uses
            ``~/.cuktech_pc``.
        max_captcha_attempts: Largest number of captcha attempts.
        diagnostic_mode: If True, the class never prints the manual
            confirmation URL, because it carries the login context.

    Attributes:
        session: The HTTP session with the account cookies.
        device_id: Random 16-letter account deviceId for this login.
        agent: User-Agent sent with each login request.
    """

    def __init__(
        self,
        session: Any | None = None,
        *,
        visible_input: Callable[[str], str] = input,
        hidden_input: Callable[[str], str] = input,
        captcha_dir: str | Path | None = None,
        max_captcha_attempts: int = 3,
        diagnostic_mode: bool = False,
    ) -> None:
        self.session = session if session is not None else new_session()
        self._diagnostic_mode = diagnostic_mode
        self.device_id = "".join(random.choices(string.ascii_letters, k=16))
        self.agent = USER_AGENT
        for domain in ("mi.com", "xiaomi.com"):
            self.session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain=domain)
            self.session.cookies.set("deviceId", self.device_id, domain=domain)
        self._visible_input = visible_input
        self._hidden_input = hidden_input
        self._captcha_dir = Path(captcha_dir) if captcha_dir else None
        self._max_captcha_attempts = max_captcha_attempts
        self._skew_seconds = 0.0
        self._sign: str | None = None
        self._ssecurity: str | None = None
        self._location: str | None = None
        self._service_token: str | None = None
        self._user_id: str | None = None
        self._cuser_id: str | None = None
        self._pass_token: str | None = None

    # -- public ------------------------------------------------------------

    def login(self, username: str, password: str) -> CloudSession:
        """Do the full login and return a complete session.

        The function can prompt for captcha codes and 2FA tickets. If the
        2FA chain gives no userId, it runs step 1 again (read-only) and gets
        a matching serviceToken. It refuses an incomplete session.

        Args:
            username: Account email, phone number or ID. Not more than
                ``MAX_USERNAME_LEN`` (128) characters.
            password: Account password. It stays in memory only.

        Returns:
            A session with userId, ssecurity and serviceToken.

        Raises:
            CloudError: If an input is missing or too long, a login step
                fails, or the session has no serviceToken or userId.
            ManualActionRequired: If the login needs a manual browser step.
        """
        if not username or not password:
            raise CloudError("username and password are required")
        if len(username) > MAX_USERNAME_LEN:
            raise CloudError("username is too long")
        if not self._step1(username):
            raise CloudError("login step 1 failed (invalid username?)")
        data = self._step2(username, password)
        if data is None:
            raise CloudError("login step 2 failed")
        if self._ssecurity and self._location:
            if not self._step3():
                raise CloudError("could not get serviceToken (step 3)")
        # Round-6 root fix: a 2FA continuation can complete the session
        # without ever ingesting the account identity (the modern
        # front-end sets no userId cookie, and _load_success only runs on
        # step-1/step-2 JSON). The /app envelope then sends an EMPTY
        # userId cookie and the server answers HTTP 401. Re-run step 1
        # in-session (read-only) to ingest userId/ssecurity/location, and
        # REFUSE any missing credential — no half-populated session.
        if not (self._user_id and str(self._user_id).strip()):
            # step 1 issues a NEW ssecurity: fetch its matching serviceToken,
            # a mixed old/new pair is rejected by the API with HTTP 401
            if not (self._session_satisfied(username) and self._step3()):
                raise CloudError(
                    "login completed, but the server did not return the account "
                    "identity (userId). The tool does not continue with an "
                    "incomplete session."
                )
        if not (self._ssecurity and self._ssecurity_ok and self._service_token):
            raise CloudError("login incomplete (no serviceToken)")
        if not (self._user_id and str(self._user_id).strip()):
            raise CloudError(
                "login completed, but the account identity (userId) is "
                "missing. The tool does not continue."
            )
        return CloudSession(
            user_id=str(self._user_id or ""),
            ssecurity=self._ssecurity,
            service_token=self._service_token,
        )

    # -- internals ---------------------------------------------------------

    @property
    def _ssecurity_ok(self) -> bool:
        return bool(self._ssecurity) and len(self._ssecurity) > 4

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.agent,
            "Content-Type": "application/x-www-form-urlencoded",
        }

    def _learn_skew(self, response: Any) -> None:
        """Trust the server's Date header for the nonce minute bucket."""
        date = None
        try:
            date = response.headers.get("Date")
        except Exception:  # noqa: BLE001
            date = None
        if not date:
            return
        try:
            server_ts = parsedate_to_datetime(date).timestamp()
            self._skew_seconds = server_ts - time.time()
        except (TypeError, ValueError):
            pass

    def _get(self, url: str, *, stage: str, **kw: Any) -> Any:
        return request(self.session, "GET", url, stage=stage, **kw)

    def _post(self, url: str, *, stage: str, **kw: Any) -> Any:
        return request(self.session, "POST", url, stage=stage, **kw)

    def _step1(self, username: str) -> bool:
        r = self._get(
            "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true",
            stage="login step 1",
            headers=self._headers(),
            cookies={"userId": username},
        )
        self._learn_skew(r)
        if r.status_code != 200:
            return False
        j = _to_json(r.text)
        if "_sign" in j:
            self._sign = j["_sign"]
            return True
        if "ssecurity" in j:
            self._load_success(j)
            return True
        return False

    def _step2_fields(self, username: str, password: str) -> dict[str, str]:
        return {
            "sid": "xiaomiio",
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": username,
            "_sign": self._sign or "",
            "_json": "true",
        }

    def _step2(self, username: str, password: str) -> dict[str, Any] | None:
        fields = self._step2_fields(username, password)
        captcha_seen = 0
        # each captcha costs a fetch POST + an answer POST; count captcha
        # prompts (captcha_seen), not POSTs
        for _attempt in range(1, 2 * self._max_captcha_attempts + 2):
            r = self._post(
                "https://account.xiaomi.com/pass/serviceLoginAuth2",
                stage="login step 2",
                headers=self._headers(),
                params=fields,
            )
            if r.status_code != 200:
                raise CloudError(f"serviceLoginAuth2 HTTP {r.status_code}")
            j = _to_json(r.text)
            if j.get("code") == 87001:
                # wrong captcha answer: drop the stale code so the retry
                # fetches a FRESH captcha (a rejected code is never re-sent)
                print("captcha rejected (code 87001)")
                fields.pop("captCode", None)
                if not j.get("captchaUrl"):
                    continue
            if j.get("captchaUrl"):
                captcha_seen += 1
                if captcha_seen > self._max_captcha_attempts:
                    raise CloudError(
                        "captcha still fails after "
                        f"{self._max_captcha_attempts} attempts. Examine the "
                        "saved image. Do not use a VPN or proxy network. Try "
                        "again after some minutes."
                    )
                fields["captCode"] = self._fetch_captcha(str(j["captchaUrl"]))
                continue
            if "ssecurity" in j and len(str(j["ssecurity"])) > 4:
                self._load_success(j)
                return j
            if "notificationUrl" in j:
                return self._do_2fa(j["notificationUrl"], username)
            raise CloudError(
                "password login rejected: "
                f"code={j.get('code')} desc={j.get('description') or j.get('desc')}"
            )
        raise CloudError(
            "captcha still fails after "
            f"{self._max_captcha_attempts} attempts. Examine the saved image. "
            "Do not use a VPN or proxy network. Try again after some minutes."
        )

    def _fetch_captcha(self, url: str) -> str:
        """Download the captcha image (allowlisted, size-capped), ask for the code."""
        img = self._get(abs_account_url(url), stage="captcha image",
                        headers=self._headers(),
                        max_bytes=MAX_CAPTCHA_BYTES)
        if img.status_code != 200:
            raise CloudError(f"captcha image HTTP {img.status_code}")
        content = getattr(img, "content", b"") or b""
        if len(content) > MAX_CAPTCHA_BYTES:
            raise CloudResponseError("captcha image exceeds size cap")
        out_dir = self._captcha_dir or Path.home() / ".cuktech_pc"
        out = _secure_write(out_dir / "captcha.png", content)
        print(f"captcha necessary. Image saved to {out}")
        return self._visible_input("enter the captcha code: ").strip()

    def _load_success(self, j: dict[str, Any]) -> None:
        self._ssecurity = j.get("ssecurity")
        self._user_id = j.get("userId")
        self._cuser_id = j.get("cUserId")
        self._pass_token = j.get("passToken")
        self._location = j.get("location")

    def _step3(self) -> bool:
        r = self._get(self._location or "", stage="service token exchange",
                      headers=self._headers())
        if r.status_code != 200:
            return False
        self._service_token = self._cookie(r, "serviceToken")
        return bool(self._service_token)

    def _cookie(self, response: Any, name: str) -> str:
        try:
            return response.cookies.get(name, "")
        except Exception:  # noqa: BLE001 — fake transports in tests
            return ""

    # -- scripted email 2FA (ported from ha-cuk-ble tools/ad1204u_fetch_token.py,
    #    https://github.com/zuyan9/ha-cuk-ble, Apache-2.0; the continuation
    #    follows the same-session patterns in Tasshack/dreame-vacuum,
    #    al-one/hass-xiaomi-miot (Apache-2.0) and
    #    PiotrMachowski/Xiaomi-cloud-tokens-extractor (MIT))

    @staticmethod
    def _locale_from(url: str) -> str:
        """Carry the challenge's own _locale through the identity calls
        (the live failure used en_IN while the old code sent en_US)."""
        try:
            vals = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).get(
                "_locale"
            )
            if vals:
                return vals[0]
        except ValueError:
            pass
        return "en_US"

    def _do_2fa(self, notification_url: str, username: str) -> dict[str, Any] | None:
        headers = self._headers()
        locale = self._locale_from(notification_url)
        self._get(notification_url, stage="2fa start")
        try:
            context = urllib.parse.parse_qs(
                urllib.parse.urlsplit(notification_url).query
            )["context"][0]
        except (KeyError, ValueError) as exc:
            raise CloudError(
                "the tool could not parse the 2FA challenge. Run "
                "uv run -m cuktech_pc.cli diagnose-login and share the "
                "sanitized output."
            ) from exc
        r_list = self._get(
            "https://account.xiaomi.com/identity/list",
            stage="2fa identity list",
            params={"sid": "xiaomiio", "context": context, "_locale": locale},
            headers=headers,
        )
        # the newer front-end ties verification to the identity_session
        # cookie (upstream passes it explicitly on verify)
        identity_session = (
            self._cookie(r_list, "identity_session")
            or self._session_cookie("identity_session")
        )
        # the identity list is a hint only: if Xiaomi refuses one channel
        # (e.g. 66108, no email on a phone-only account), try the other
        first = _verify_flag(r_list.text)
        refused: list[str] = []
        flag = first
        for f in (first, FLAG_EMAIL if first == FLAG_SMS else FLAG_SMS):
            sent = self._post(
                "https://account.xiaomi.com/identity/auth/send"
                f"{'Phone' if f == FLAG_SMS else 'Email'}Ticket",
                stage="2fa code dispatch",
                params={
                    "_dc": str(int(time.time() * 1000)),
                    "sid": "xiaomiio",
                    "context": context,
                    "mask": "0",
                    "_locale": locale,
                },
                data={
                    "retry": "0",
                    "icode": "",
                    "_json": "true",
                    "ick": self._session_cookie("ick"),
                },
                headers=headers,
            )
            try:
                sent_code = _to_json(sent.text).get("code")
            except ValueError:
                sent_code = None
            if isinstance(sent_code, (int, float)) and not isinstance(sent_code, bool) and sent_code != 0:
                refused.append(f"{'SMS' if f == FLAG_SMS else 'email'} code={sent_code}")
                continue
            flag, refused = f, []
            break
        if refused:
            raise CloudError("Xiaomi refused to send a verification code ("
                             + ", ".join(refused) + "). Wait some minutes and try again.")
        kind = "Phone" if flag == FLAG_SMS else "Email"
        where = "phone by SMS" if flag == FLAG_SMS else "account email"
        print(f"2FA necessary. Xiaomi sent a code to your {where}")
        code = self._hidden_input("enter the code: ").strip()
        verify_kwargs: dict[str, Any] = {}
        if identity_session:
            verify_kwargs["cookies"] = {"identity_session": identity_session}
        r = self._post(
            f"https://account.xiaomi.com/identity/auth/verify{kind}",
            stage="2fa code verification",
            params={
                "_flag": str(flag),
                "_json": "true",
                "sid": "xiaomiio",
                "context": context,
                "mask": "0",
                "_locale": locale,
            },
            data={
                "_flag": str(flag),
                "ticket": code,
                "trust": "false",
                "_json": "true",
                "ick": self._session_cookie("ick"),
            },
            headers=headers,
            **verify_kwargs,
        )
        if r.status_code != 200:
            raise CloudError("2FA verification failed (HTTP error)")
        # account-host JSON carries the &&&START&&& prefix — always
        # parse with the prefix-tolerant _to_json, never r.json()
        try:
            jr = _to_json(r.text)
        except ValueError:
            jr = {}
        verify_code = jr.get("code")
        if isinstance(verify_code, bool) or not isinstance(verify_code, (int, float)):
            # no numeric code -> ambiguous, never success and never
            # "rejected"; only a server-confirmed continuation may succeed
            print("verification result unknown (no numeric code in the "
                  "response). The tool continues with the in-session checks.")
        elif verify_code != 0:
            # an explicit numeric rejection must say so — never
            # fall through to a browser handoff (the code may be single-use)
            raise CloudError(
                f"the server rejected the verification code (code={verify_code}). "
                "Get a new code and start setup again."
            )
        finish_loc = jr.get("location")
        if not finish_loc:
            # upstream-master fallback: Location header / body scrape
            finish_loc = _hop_location(
                r, f"https://account.xiaomi.com/identity/auth/verify{kind}"
            )
            if not finish_loc and r.text:
                idx = r.text.find("https://account.xiaomi.com/identity/result/check")
                if idx != -1:
                    end = r.text.find('"', idx)
                    finish_loc = r.text[idx : end if end != -1 else idx + 300]
        # ONE central continuation — no branch may advise a browser
        # "re-run". Location present (validated, fetched in-session), then
        # result/check, then the old redirect chain if it materializes,
        # then same-session step-1, then the bounded Enter handoff.
        return self._continue_2fa(
            finish_loc, context, locale, headers, notification_url, username
        )

    def _continue_2fa(
        self,
        finish_loc: str | None,
        context: str,
        locale: str,
        headers: dict[str, str],
        notification_url: str,
        username: str,
    ) -> dict[str, Any]:
        """Central 2FA continuation: every variant funnels here.

        Order: (1) GET any provided location in-session (validated);
        (2) result/check (a 302 Location feeds the old Auth2/end chain);
        (3) same-session serviceLogin step-1 re-run; (4) bounded
        same-process Enter handoff (max 2 rounds); (5) diagnose-login
        pointer. No branch ever suggests completing in a browser and
        re-running the tool, and the password POST is never re-sent.
        """
        if finish_loc:
            finish_loc = abs_account_url(finish_loc)
            try:
                r_loc = self._get(finish_loc, stage="2fa redirect", headers=headers)
            except (UnsafeURLError, ManualActionRequired):
                # off-allowlist location: do NOT follow; fall through to
                # the in-session continuation below
                r_loc = None
            if r_loc is not None:
                # the location GET is part of the chain: a 302 Location
                # here feeds it directly (no double fetch)
                chained = self._finish_2fa_chain_from(
                    r_loc, finish_loc, headers, notification_url
                )
                if chained:
                    return chained
        # result/check: a 302 Location here feeds the old chain
        r0 = self._get(
            "https://account.xiaomi.com/identity/result/check",
            stage="2fa result check",
            params={"sid": "xiaomiio", "context": context, "_locale": locale},
            headers=headers,
        )
        loc = _hop_location(
            r0, "https://account.xiaomi.com/identity/result/check"
        )
        if loc:
            chained = self._finish_2fa_chain_quiet(
                loc, headers, notification_url
            )
            if chained:
                return chained
        # same-session step-1 re-run (the upstream verify->GET->re-run
        # pattern); step 1 only — the password POST is never re-sent
        if self._session_satisfied(username):
            return {"ok": True}
        # bounded same-process handoff. Completing the challenge in a
        # browser and RE-RUNNING the tool can never work (a re-run is a
        # fresh session that re-triggers 2FA) — the continuation must
        # happen in THIS process, with THIS session's cookies.
        for _round in range(2):
            if self._diagnostic_mode:
                # in diagnostic mode never print the challenge URL
                # (it carries the context); record the need only.
                print(
                    "manual browser confirmation necessary (URL hidden in "
                    "diagnostic mode). To use it, run setup in normal mode."
                )
                break
            print(
                "the account wants additional confirmation. Open this URL "
                "in a browser and complete the steps:\n  " + notification_url
            )
            answer = self._visible_input(
                "then press Enter HERE to continue in this session "
                "(or type 'skip'): "
            ).strip()
            if answer.lower() == "skip":
                break
            r0 = self._get(
                "https://account.xiaomi.com/identity/result/check",
                stage="2fa result check",
                params={"sid": "xiaomiio", "context": context, "_locale": locale},
                headers=headers,
            )
            loc = _hop_location(
                r0, "https://account.xiaomi.com/identity/result/check"
            )
            if loc:
                chained = self._finish_2fa_chain_quiet(
                    loc, headers, notification_url
                )
                if chained:
                    return chained
            if self._session_satisfied(username):
                return {"ok": True}
        raise CloudError(
            "the tool could not complete 2FA verification in this session. Run: "
            "uv run -m cuktech_pc.cli diagnose-login "
            "and share the sanitized output."
        )

    def _session_satisfied(self, username: str) -> bool:
        """Re-run serviceLogin step 1 in this session; True when it now
        returns ssecurity + location (the session is verified)."""
        self._step1(username)
        return bool(self._ssecurity and self._location)

    def _finish_2fa_chain_from(
        self,
        response: Any,
        fetched_url: str,
        headers: dict[str, str],
        notification_url: str,
    ) -> dict[str, Any] | None:
        """Continue the old redirect chain from an ALREADY-FETCHED response.

        If the fetched URL is result/check, its 302 Location is the
        Auth2/end URL. Otherwise the fetched response is the Auth2/end
        answer. The function does not fetch it again, because Auth2/end
        can be single-use. Any dead end returns None.
        """
        if "identity/result/check" in fetched_url:
            end_url = _hop_location(response, fetched_url)
            if not end_url:
                return None
            return self._finish_2fa_chain_quiet(
                end_url, headers, notification_url
            )
        return self._finish_2fa_from_end(response, fetched_url, headers)

    def _finish_2fa_chain_quiet(
        self,
        finish_loc: str,
        headers: dict[str, str],
        notification_url: str,
    ) -> dict[str, Any] | None:
        """The old redirect chain (result/check 302 → Auth2/end
        extension-pragma → STS), as a *quiet* attempt: any non-terminal
        dead end (missing Location, missing extension-pragma, missing STS
        pointer) returns None so the central continuation can fall back
        to the same-session step-1 — never a browser "re-run".
        Returns a dict on full success.
        """
        finish_loc = abs_account_url(finish_loc)
        if "identity/result/check" in finish_loc:
            r = self._get(finish_loc, stage="2fa redirect", headers=headers)
            end_url = _hop_location(r, finish_loc)
        else:
            end_url = finish_loc
        if not end_url:
            return None  # fall back, no browser advice
        end_url = abs_account_url(end_url)
        r = self._get(end_url, stage="2fa finish", headers=headers)
        return self._finish_2fa_from_end(r, end_url, headers)

    def _finish_2fa_from_end(
        self,
        r: Any,
        end_url: str,
        headers: dict[str, str],
    ) -> dict[str, Any] | None:
        """Read the Auth2/end answer, then get the serviceToken from STS.

        Auth2/end answers 302 with extension-pragma (ssecurity) and a
        Location that points to the STS step. Both come from the raw 30x.
        Any dead end returns None.
        """
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self._get(end_url, stage="2fa finish", headers=headers)
        ext = None
        try:
            ext = r.headers.get("extension-pragma")
        except Exception:  # noqa: BLE001
            ext = None
        if ext:
            try:
                self._ssecurity = json.loads(ext).get("ssecurity") or self._ssecurity
            except ValueError:
                pass
        if not self._ssecurity:
            return None  # fall back to step-1, no hard error
        sts_url = _hop_location(r, end_url)
        if not sts_url and r.text:
            idx = r.text.find("https://sts.api.io.mi.com/sts")
            if idx != -1:
                end = r.text.find('"', idx)
                sts_url = r.text[idx : end if end != -1 else idx + 300]
        if not sts_url:
            return None
        sts_url = abs_account_url(sts_url)
        r = self._get(sts_url, stage="service token exchange", headers=headers)
        if r.status_code != 200:
            return None
        self._service_token = self._session_cookie_domain(
            "serviceToken", ".sts.api.io.mi.com"
        )
        if not self._service_token:
            return None
        for domain in (".api.io.mi.com", ".io.mi.com", ".mi.com"):
            self.session.cookies.set("serviceToken", self._service_token, domain=domain)
            self.session.cookies.set(
                "yetAnotherServiceToken", self._service_token, domain=domain
            )
        self._user_id = self._user_id or self._session_cookie("userId")
        return {"ok": True}

    def _session_cookie(self, name: str) -> str:
        try:
            return self.session.cookies.get(name, "")
        except requests.cookies.CookieConflictError:
            # Xiaomi sets userId on several domains after 2FA; this used to
            # be swallowed as "" -> empty userId -> HTTP 401 (live 2026-10-12)
            values = [c.value for c in self.session.cookies
                      if c.name == name and c.value]
            # the account id is numeric; prefer it over any stray value
            return next((v for v in values if v.isdigit()),
                        values[0] if values else "")
        except Exception:  # noqa: BLE001
            return ""

    def _session_cookie_domain(self, name: str, domain: str) -> str:
        try:
            return self.session.cookies.get(name, "", domain=domain)
        except Exception:  # noqa: BLE001
            return self._session_cookie(name)


# ------------------------------------------------------------------ diagnostics


class DiagnosticSession:
    """Wrap a real HTTP session and record a redacted trace that is safe to share.

    For each request, the trace contains the method and scheme://host/path.
    It does not contain the query string, because queries carry the context
    and credentials. After the body is read, the trace also contains the
    HTTP status, the top-level JSON key names, a numeric ``code`` and a
    boolean ``success``. The trace never contains cookies, header values,
    bodies or other secrets. Credential key names are removed also.

    Args:
        inner: The real HTTP session.

    Attributes:
        inner: The wrapped session.
        cookies: The cookie jar of ``inner``.
        trace: One dict for each request, in order.
    """

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.cookies = inner.cookies
        self.trace: list[dict[str, Any]] = []
        self._pending: list[tuple[dict[str, Any], Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Send the request with the inner session and add a trace entry.

        :meth:`finalize` adds the response details later.

        Args:
            method: HTTP method.
            url: Request URL. Only scheme, host and path go into the trace.
            **kwargs: Arguments for ``inner.request``.

        Returns:
            The response from the inner session.
        """
        parts = urllib.parse.urlsplit(url)
        redacted_url = f"{parts.scheme}://{parts.netloc}{parts.path}"
        entry: dict[str, Any] = {
            "method": str(method).upper(),
            "url": redacted_url,
        }
        self.trace.append(entry)
        response = self.inner.request(method, url, **kwargs)
        self._pending.append((entry, response))
        return response

    def finalize_entry(self, entry: dict[str, Any], response: Any) -> None:
        """Add status, safe JSON key names, ``code`` and ``success`` to a trace entry.

        Args:
            entry: Trace entry to update in place.
            response: Response for the entry. Its body must be read already.
        """
        try:
            entry["status"] = response.status_code
        except Exception:  # noqa: BLE001
            entry["status"] = None
        # account-host JSON carries the &&&START&&& prefix — parse
        # with the same prefix-tolerant helper the login path uses, never
        # response.json()
        obj = None
        try:
            obj = _to_json(response.text)
        except Exception:  # noqa: BLE001 — non-JSON bodies are fine
            obj = None
        if isinstance(obj, dict):
            # key names are metadata, but drop credential-ish names
            # entirely so even the word never appears in shareable output
            sensitive_names = {
                "ssecurity", "psecurity", "passToken", "serviceToken",
                "password", "token", "ticket", "context", "userId",
            }
            entry["keys"] = sorted(
                k for k in obj.keys()
                if isinstance(k, str) and k not in sensitive_names
            )
            code = obj.get("code")
            if isinstance(code, bool) or not isinstance(code, (int, float)):
                entry["code"] = "unknown"  # never fabricate 0
            else:
                entry["code"] = code
            if isinstance(obj.get("success"), bool):
                entry["success"] = obj["success"]

    def finalize(self) -> None:
        """Complete all pending trace entries from their responses."""
        for entry, response in self._pending:
            self.finalize_entry(entry, response)
        self._pending.clear()

    def format_trace(self) -> str:
        """Complete pending entries and format the trace as text.

        Returns:
            One line for each request, between start and end marker lines.
        """
        self.finalize()
        lines = ["--- sanitized login trace (no secrets) ---"]
        for e in self.trace:
            bits = [e.get("method", "?"), e.get("url", "?")]
            bits.append(f"status={e.get('status')}")
            if "keys" in e:
                bits.append("keys=" + ",".join(e["keys"]))
            if "code" in e:
                bits.append(f"code={e['code']}")
            if "success" in e:
                bits.append(f"success={e['success']}")
            lines.append(" ".join(bits))
        lines.append("--- end trace ---")
        return "\n".join(lines)


# --------------------------------------------------------- secure file writes

def _secure_write(path: Path, data: bytes, *, mode: int = 0o600) -> Path:
    """Write a file atomically, with mode 0600 from creation, and refuse symlinks.

    - The function never changes the mode of a directory that the tool did
      not create. It creates its own private directory (``~/.cuktech_pc``)
      with mode 0700. It only validates an existing parent (real directory,
      owned by the user, not group/world-writable) and does not change it.
      The mode of HOME or of a project directory must not change silently.
    - It creates the temp file exclusively (O_EXCL, mode 0600) with a random
      name. Secrets are never world-readable, and a planted symlink is not
      followed.
    - It writes and fsyncs the data, then renames the file over the target.
    - It fsyncs the parent directory, so the rename survives a crash.
    - It refuses an existing symlink at the target and does not replace it.

    Raises CloudError if a check fails.
    """
    path = Path(path)
    parent = path.parent
    if parent.is_symlink():
        raise CloudError(f"the tool does not write in a symlinked directory: {parent}")
    if parent.exists():
        if not parent.is_dir():
            raise CloudError(f"not a directory: {parent}")
        # validate an existing parent WITHOUT modifying it
        info = parent.stat()
        if info.st_uid != os.geteuid():
            raise CloudError(
                f"the tool does not write in a directory that you do not own: {parent}"
            )
        pmode = stat.S_IMODE(info.st_mode)
        if pmode & 0o022 and not (pmode & 0o1000):
            raise CloudError(
                f"the tool does not write secrets in a group/world-writable "
                f"directory: {parent} (make its permissions stricter first)"
            )
    else:
        # only a directory the tool itself creates gets mode 0700
        parent.mkdir(mode=0o700, parents=False)
        if parent.is_symlink():  # raced
            raise CloudError(f"symlink appeared at {parent}")
    if path.is_symlink():
        raise CloudError(f"the tool does not overwrite a symlink: {path}")
    import tempfile as _tempfile

    fd, tmp_name = _tempfile.mkstemp(
        dir=str(parent), prefix="." + path.name + "-", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    dir_fd = os.open(str(parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return path


# ------------------------------------------------------------------ API


class MiCloudApi:
    """Call the RC4-signed /app API (api.io.mi.com, sid xiaomiio).

    ``applydid``, ``standard_bind`` and ``remove_device`` change account or
    cloud data. The CLI asks for typed user consent before it calls them.

    Args:
        session: HTTP session for :func:`request`.
        auth: Session from a login or the session cache.
        region: Server region, one of ``SERVERS``. ``cn`` uses
            ``api.io.mi.com``. Other regions use ``<region>.api.io.mi.com``.
        skew_seconds: Server clock offset in seconds, added to local time
            for the nonce.

    Raises:
        CloudError: If ``region`` is not in ``SERVERS``.
    """

    def __init__(
        self,
        session: Any,
        auth: CloudSession,
        *,
        region: str = "cn",
        skew_seconds: float = 0.0,
    ) -> None:
        if region not in SERVERS:
            raise CloudError(f"unknown region {region!r}")
        self.session = session
        self.auth = auth
        self.region = region
        self.skew_seconds = skew_seconds

    def _api_base(self) -> str:
        prefix = "" if self.region == "cn" else self.region + "."
        return f"https://{prefix}api.io.mi.com/app"

    def _now_ms(self) -> int:
        return int((time.time() + self.skew_seconds) * 1000)

    def encrypted_post(self, path: str, data_json: str) -> dict[str, Any]:
        """Send one signed, RC4-encrypted POST to /app and decode the answer.

        Args:
            path: API path without the ``/app`` prefix, for example
                ``/home/device_list``.
            data_json: JSON request body.

        Returns:
            The decrypted JSON response.

        Raises:
            CloudError: If the HTTP status is not 200, or :func:`request`
                fails.
            CloudResponseError: If the response body cannot be decoded.
        """
        url = self._api_base() + path
        nonce = generate_nonce(now_ms=self._now_ms())
        signed = signed_nonce(self.auth.ssecurity, nonce)
        form = build_request_form(
            self.auth.ssecurity, nonce, signed, data_json, path
        )
        r = request(
            self.session,
            "POST",
            url,
            stage=f"api call {path}",
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
                "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
            },
            cookies={
                "userId": str(self.auth.user_id),
                "serviceToken": str(self.auth.service_token),
                "yetAnotherServiceToken": str(self.auth.service_token),
                "locale": "en_GB",
                "timezone": "GMT+00:00",
                "is_daylight": "0",
                "dst_offset": "0",
                "channel": "MI_APP_STORE",
            },
            data=form,
        )
        if r.status_code != 200:
            raise CloudError(f"api call failed: HTTP {r.status_code}")
        return decode_response_body(
            self.auth.ssecurity, nonce, r.text, r.headers.get("MIOT-CONTENT-ENCODING")
        )

    # -- read-only ----------------------------------------------------------

    def list_devices(self) -> list[dict[str, Any]]:
        """Get the device list of the account. This call is read-only.

        The function fails closed. An error envelope raises an error. It does
        not return an empty list.

        Returns:
            The device dicts from ``result.list``.

        Raises:
            CloudError: If ``code`` is not 0, or ``result`` or ``list`` is
                missing, or the request fails.
        """
        resp = self.encrypted_post(
            "/home/device_list",
            '{"getVirtualModel":true,"getHuamiDevices":1}',
        )
        code = resp.get("code")
        if code is not None and code != 0:
            raise CloudError(f"device list error envelope: code={code}")
        result = resp.get("result")
        if not isinstance(result, dict):
            raise CloudError("device list response has no result object")
        lst = result.get("list")
        if not isinstance(lst, list):
            raise CloudError("device list response has no list")
        return lst

    def device_list_contains(self, *macs: str) -> bool:
        """Check if one of the MACs is already on the account.

        The function compares each MAC in raw and byte-reversed form. Give
        all identity addresses of the charger.

        Args:
            *macs: MAC addresses in any form that :func:`normalize_mac`
                accepts.

        Returns:
            True if a listed device has one of the MACs.

        Raises:
            CloudError: If :meth:`list_devices` fails.
        """
        candidates: set[str] = set()
        for mac in macs:
            candidates |= _mac_candidates(mac)
        for dev in self.list_devices():
            if normalize_mac(str(dev.get("mac", ""))) in candidates:
                return True
        return False

    # -- mutations (consent-gated by the CLI) --------------------------------

    def applydid(
        self,
        mac: str,
        model: str,
        token_hex: str,
        did: str = "",
        home: dict[str, Any] | None = None,
    ) -> str:
        """Ask the cloud for a device ID (POST /device/bltapplydid).

        This call changes cloud data. The CLI asks for consent first.

        Args:
            mac: BLE address as the BLE stack reports it.
            model: Device model string.
            token_hex: Device token, as a hex string.
            did: Existing device ID, or empty.
            home: Optional dict with ``homeId`` and ``uid``.

        Returns:
            The device ID.

        Raises:
            CloudError: If the request fails.
            CloudResponseError: If the response has no ``did``.
        """
        resp = self.encrypted_post(
            "/device/bltapplydid",
            build_applydid_body(mac, model, token_hex, did, home),
        )
        return parse_applydid(resp)

    def standard_bind(
        self,
        did: str,
        token_hex: str,
        bind_key_hex: str,
        smac: str,
        home: dict[str, Any] | None = None,
    ) -> BindCloudMaterial:
        """Bind the device to the account (POST /v2/device/ble_standard_bind).

        This call changes cloud data. The CLI asks for consent first.

        Args:
            did: Device ID from :meth:`applydid`.
            token_hex: Device token, as a hex string.
            bind_key_hex: Bind key, as a hex string.
            smac: Value of the ``smac`` prop.
            home: Optional dict with ``homeId`` and ``uid``.

        Returns:
            The signed cloud data for the BLE register step.

        Raises:
            CloudError: If the request fails.
            CloudResponseError: If the response is not valid.
        """
        resp = self.encrypted_post(
            "/v2/device/ble_standard_bind",
            build_standard_bind_body(did, token_hex, bind_key_hex, smac, home),
        )
        return parse_bind_response(resp)

    def remove_device(self, did: str, pid: int) -> None:
        """Remove an owned device from the account (POST /user/del_owner_device_batch).

        This is DeviceApi.unbindDevice of the app (h37.java). The CLI asks
        for consent first.

        Args:
            did: Device ID to remove.
            pid: ``pid`` value of the device entry in the account device
                list. The function converts it to int.

        Raises:
            CloudError: If the request fails or ``code`` is not 0.
        """
        resp = self.encrypted_post(
            "/user/del_owner_device_batch",
            json.dumps({"devList": [{"did": did, "pid": int(pid)}]}),
        )
        if resp.get("code") != 0:
            raise CloudError(
                f"remove device failed: code={resp.get('code')} "
                f"message={resp.get('message')}"
            )
