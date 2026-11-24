"""Store the cloud session of the firmware tool.

- Windows: ``windows_private`` (DPAPI for the signed-in user).
- Linux and macOS: ``~/.cuktech_pc/firmware-session.json``, mode 0600,
  written atomically, symlinks refused (``cloud._secure_write``).

The session holds bearer credentials (service token, ssecurity, cookies) and
the charger token, if known. The password is never stored.
"""

import json
import os
import stat
from pathlib import Path

from . import windows_private
from .cloud import _secure_write

POSIX_PATH = Path.home() / ".cuktech_pc" / "firmware-session.json"
MAX_BYTES = 256 * 1024


class SessionStoreError(Exception):
    """The session file is not safe or not valid. The message has no secrets."""


def location() -> Path:
    """Return the session location on this platform.

    Returns:
        The DPAPI cache path on Windows, else the POSIX session file.
    """
    return windows_private.DEFAULT_PATH if os.name == "nt" else POSIX_PATH


def save(payload: dict, path: Path | None = None) -> None:
    """Save ``payload`` to the platform store.

    Args:
        payload: The session dict. It must have ``"schema": 1``.
        path: Override for the POSIX file (tests). Ignored on Windows.

    Raises:
        windows_private.PrivateStorageError: On Windows, if DPAPI fails.
        cloud.CloudError: On Linux/macOS, if the path is not safe to write.
    """
    if os.name == "nt":
        windows_private.save(payload)
        return
    _secure_write(Path(path or POSIX_PATH), (json.dumps(payload) + "\n").encode())


def load(path: Path | None = None) -> dict | None:
    """Load the session from the platform store.

    Args:
        path: Override for the POSIX file (tests). Ignored on Windows.

    Returns:
        The session dict, or ``None`` if no session is saved.

    Raises:
        SessionStoreError: On Linux/macOS, if the file is a symlink, is not
            owned by the user, is readable by others, is too large or is not valid.
        windows_private.PrivateStorageError: On Windows, if the cache is not valid.
    """
    if os.name == "nt":
        return windows_private.load()
    path = Path(path or POSIX_PATH)
    if path.is_symlink() or path.parent.is_symlink():
        raise SessionStoreError("the session file must not be a symlink")
    if not path.exists():
        return None
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SessionStoreError(f"{path} must be owned by you with mode 0600")
    if info.st_size > MAX_BYTES:
        raise SessionStoreError("the session file is too large")
    try:
        payload = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise SessionStoreError("the session file is not valid") from None
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise SessionStoreError("the session file has an unknown format")
    return payload
