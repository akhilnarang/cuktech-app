"""Cache the authenticated Xiaomi session. The password is never saved.

A charger reboot (for example, to force BT discovery) must not make the
user log in again. This module keeps only the session data that is
necessary to sign /app requests again after a successful login:

- ``user_id``: the userId cookie and header.
- ``service_token``: the bearer serviceToken cookie.
- ``ssecurity``: the secret that signs the RC4 envelope.
- ``device_id``: the account deviceId cookie (nonce identity).
- ``agent``: the User-Agent of the login. The same value is used again.
- ``region``: the account region.
- ``username_tag``: a SHA-256 tag of the username (stripped, lowercase).
  The tool uses it to refuse a session of a different account. The raw
  username is not stored.

The module does not save the password, cookies, 2FA codes, challenge URLs
or email codes. ``_secure_write`` writes the file to
``~/.cuktech_pc/cloud-session.json`` (mode 0600, atomic, symlinks refused,
no chmod of HOME). The file contains bearer-secret credentials. Do not
share or export it. Diagnostics do not include it and logs do not show it.

Validation in the CLI:

1. A read-only ``/home/device_list`` call validates a cached session before
   all other steps. A fresh login uses the same guard.
2. Only a confirmed auth rejection (HTTP 401) deletes the cache. The CLI
   then shows the hidden password prompt. Transient failures (timeouts,
   DNS, 5xx, network errors) do not delete the cache, do not prompt again
   and do not change cloud data. The run stops and the journal does not
   change.
3. The CLI writes the cache after a fresh login only when the device-list
   guard succeeds, and before BLE discovery. A later BLE failure or charger
   reboot can then use the session again without username, password or 2FA.

The CLI command ``forget-login`` deletes only this cache file.
"""


import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cloud import CloudError, CloudSession, _secure_write

SCHEMA_VERSION = 1
DEFAULT_CACHE = Path.home() / ".cuktech_pc" / "cloud-session.json"


class SessionCacheError(CloudError):
    """The session cache is not readable or not safe to use.

    The message is safe to show to the user. The tool refuses the cache and
    does not delete it.
    """


def username_tag(username: str) -> str:
    """Make a SHA-256 tag of the normalized username for the wrong-account guard.

    The raw username is never stored. The tag is only for comparison.

    Args:
        username: Xiaomi account username. The function strips whitespace
            and converts it to lowercase.

    Returns:
        The SHA-256 hex digest (64 characters) of the normalized username.
    """
    normalized = username.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CachedSession:
    """Validated session data read from the cache file.

    Attributes:
        user_id: Xiaomi userId.
        service_token: Bearer serviceToken cookie value.
        ssecurity: Secret that signs the RC4 envelope.
        device_id: Account deviceId cookie value.
        agent: User-Agent of the original login.
        region: Account region.
        username_tag: SHA-256 tag from :func:`username_tag`.
        saved_at: Save time, in seconds since the Unix epoch.
        skew_seconds: Server clock offset learnt at login, in seconds.
    """

    user_id: str
    service_token: str
    ssecurity: str
    device_id: str
    agent: str
    region: str
    username_tag: str
    saved_at: float
    skew_seconds: float = 0.0  # server clock offset learnt at login

    def to_cloud_session(self) -> CloudSession:
        """Make a :class:`CloudSession` for request signing.

        Returns:
            A CloudSession with ``user_id``, ``ssecurity`` and ``service_token``.
        """
        return CloudSession(
            user_id=self.user_id,
            ssecurity=self.ssecurity,
            service_token=self.service_token,
        )


def save_session(
    path: Path,
    auth: CloudSession,
    *,
    device_id: str,
    agent: str,
    region: str,
    username_tag: str,
    skew_seconds: float = 0.0,
) -> None:
    """Write the authenticated session to the cache file with mode 0600.

    The password is never written.

    Args:
        path: Cache file path.
        auth: Session from a successful login.
        device_id: Account deviceId cookie value.
        agent: User-Agent of the login.
        region: Account region.
        username_tag: Tag from :func:`username_tag`.
        skew_seconds: Server clock offset, in seconds.

    Raises:
        CloudError: If ``_secure_write`` refuses the path or cannot write it.
    """
    payload = {
        "schema": SCHEMA_VERSION,
        "user_id": str(auth.user_id),
        "service_token": str(auth.service_token),
        "ssecurity": str(auth.ssecurity),
        "device_id": str(device_id),
        "agent": str(agent),
        "region": str(region),
        "username_tag": str(username_tag),
        "saved_at": time.time(),
        "skew_seconds": float(skew_seconds),
    }
    _secure_write(Path(path), (json.dumps(payload, indent=2) + "\n").encode())


def load_session(
    path: Path,
    *,
    expected_username: str | None = None,
    expected_region: str | None = None,
) -> CachedSession | None:
    """Read and validate the cached session.

    The function does not delete anything. The caller refuses a bad cache.

    Args:
        path: Cache file path.
        expected_username: If set, the cached username tag must match it.
        expected_region: If set, the cached region must match it.

    Returns:
        The cached session, or None if the cache file does not exist.

    Raises:
        SessionCacheError: If the file is a symlink, has a different owner,
            has a mode other than 0600, is not valid JSON, has an unknown
            schema or a missing field, or is for a different username or
            region. A different account is never used silently.
    """
    path = Path(path)
    if not path.exists():
        return None
    if path.is_symlink():
        raise SessionCacheError(
            f"session cache at {path} is a symlink. The tool does not use it. "
            "Examine it manually or remove it yourself."
        )
    info = path.lstat()
    if info.st_uid != os.geteuid():
        raise SessionCacheError(
            f"session cache at {path} is not owned by you. The tool does not use it."
        )
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise SessionCacheError(
            f"session cache at {path} has mode "
            f"{oct(stat.S_IMODE(info.st_mode))} (expected 0600). Run "
            "`chmod 600` on it, or remove it yourself."
        )
    try:
        obj = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise SessionCacheError(
            f"session cache at {path} is unreadable ({type(exc).__name__}). "
            "It contains account credentials. Examine it manually or "
            "remove it yourself."
        ) from exc
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA_VERSION:
        raise SessionCacheError(
            f"session cache at {path} has an unknown schema. Remove it "
            "yourself or run: cuktech_pc.cli forget-login"
        )
    required = ("user_id", "service_token", "ssecurity", "device_id",
                "agent", "region", "username_tag")
    for field in required:
        if not str(obj.get(field) or ""):
            raise SessionCacheError(
                f"session cache at {path} does not have '{field}'. Remove it "
                "yourself or run: cuktech_pc.cli forget-login"
            )
    cached = CachedSession(
        user_id=str(obj["user_id"]),
        service_token=str(obj["service_token"]),
        ssecurity=str(obj["ssecurity"]),
        device_id=str(obj["device_id"]),
        agent=str(obj["agent"]),
        region=str(obj["region"]),
        username_tag=str(obj["username_tag"]),
        saved_at=float(obj.get("saved_at", 0.0)),
        skew_seconds=float(obj.get("skew_seconds", 0.0)),
    )
    if expected_username is not None:
        if cached.username_tag != username_tag(expected_username):
            raise SessionCacheError(
                "the saved login is for a DIFFERENT account. The tool does "
                "not use it. To change to a different account, run "
                "forget-login first."
            )
    if expected_region is not None and cached.region != expected_region:
        raise SessionCacheError(
            f"the saved login is for region {cached.region!r}, not "
            f"{expected_region!r}. To change the region, run forget-login."
        )
    return cached


def forget_session(path: Path) -> bool:
    """Delete only the session cache file.

    The function does not touch the journal, token exports, archives or
    account entries.

    Args:
        path: Cache file path.

    Returns:
        True if a file was deleted. False if no file exists.

    Raises:
        SessionCacheError: If ``path`` is a symlink or not a regular file.
    """
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink():
        raise SessionCacheError(
            f"session cache at {path} is a symlink. The tool does not remove "
            "it automatically. Examine it yourself."
        )
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SessionCacheError(
            f"session cache at {path} is not a regular file. The tool does not remove it."
        )
    path.unlink()
    return True


def restore_request_environment(
    session: Any,
    cached: CachedSession,
) -> None:
    """Set the account cookies again on a new HTTP session.

    After this call, the cached serviceToken and ssecurity sign requests in
    the same way as the original login. The function uses only the public
    cookie-set API.

    Args:
        session: HTTP session with a ``cookies.set`` method, for example a
            ``requests.Session``.
        cached: Cached session that supplies deviceId and serviceToken.
    """
    for domain in ("mi.com", "xiaomi.com"):
        session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain=domain)
        session.cookies.set("deviceId", cached.device_id, domain=domain)
    for domain in (".api.io.mi.com", ".io.mi.com", ".mi.com"):
        session.cookies.set("serviceToken", cached.service_token, domain=domain)
        session.cookies.set(
            "yetAnotherServiceToken", cached.service_token, domain=domain
        )
