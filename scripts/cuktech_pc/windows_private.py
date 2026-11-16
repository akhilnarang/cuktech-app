"""Store the optional cloud-session cache with Windows DPAPI for the current user.

The module does not store passwords. The private directory does not inherit
broad ACLs. Windows encrypts the payload with the DPAPI key of the signed-in
user. The functions work only on Windows (``os.name == "nt"``).
"""


import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import uuid

DEFAULT_PATH = Path(__file__).resolve().parents[1] / ".private" / "xiaomi-session.dpapi"


class PrivateStorageError(Exception):
    """The private cache is not available, not safe, or not valid.

    The message is safe to show to the user. It contains no secret data.
    """

    pass


def _transform(data: bytes, *, decrypt: bool) -> bytes:
    """Encrypt or decrypt ``data`` with CryptProtectData/CryptUnprotectData."""
    if os.name != "nt":
        raise PrivateStorageError("this cache requires Windows DPAPI")

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = Blob()
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise PrivateStorageError("Windows could not unlock the private cache" if decrypt
                                  else "Windows could not encrypt the private cache")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel.LocalFree(output.data)


def save(payload: dict, path: Path = DEFAULT_PATH) -> None:
    """Encrypt ``payload`` with DPAPI and write it atomically to ``path``.

    The function first limits the ACL of the parent directory to the SID of
    the current user (``icacls /inheritance:r``). Then it writes a temporary
    file, calls ``fsync`` and replaces the target file.

    Args:
        payload: JSON-serializable session data. Use ``"schema": 1`` so that
            :func:`load` accepts it.
        path: Target file. The default is ``scripts/.private/xiaomi-session.dpapi``.

    Raises:
        PrivateStorageError: If the platform is not Windows, ``path`` or its
            parent is a symlink, the user SID is not valid, ``icacls`` fails,
            or DPAPI cannot encrypt the data.
        subprocess.CalledProcessError: If PowerShell cannot read the user SID.
    """
    if os.name != "nt":
        raise PrivateStorageError("this cache requires Windows DPAPI")
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise PrivateStorageError("private cache must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    sid = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
        capture_output=True, text=True, check=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    ).stdout.strip()
    if not sid.startswith("S-1-") or any(c not in "S0123456789-" for c in sid):
        raise PrivateStorageError("could not identify the current Windows user")
    secured = subprocess.run(
        ["icacls.exe", str(path.parent), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if secured.returncode:
        raise PrivateStorageError("could not restrict the private directory permissions")
    blob = _transform(json.dumps(payload, separators=(",", ":")).encode(), decrypt=False)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as target:
            target.write(blob)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load(path: Path = DEFAULT_PATH) -> dict | None:
    """Read and decrypt the DPAPI session cache.

    Args:
        path: Cache file. The default is ``scripts/.private/xiaomi-session.dpapi``.

    Returns:
        The decrypted payload dict, or None if the file does not exist.

    Raises:
        PrivateStorageError: If ``path`` or its parent is a symlink, the file
            is larger than 256 KiB, DPAPI cannot decrypt it, the content is
            not valid JSON, or the schema is not 1.
    """
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise PrivateStorageError("private cache must not be a symlink")
    if not path.exists():
        return None
    blob = path.read_bytes()
    if len(blob) > 256 * 1024:
        raise PrivateStorageError("private cache is too large")
    try:
        payload = json.loads(_transform(blob, decrypt=True))
    except (ValueError, UnicodeError):
        raise PrivateStorageError("private cache is invalid") from None
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise PrivateStorageError("private cache has an unknown format")
    return payload
