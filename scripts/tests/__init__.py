"""Offline test harness for cuktech_pc.

The ``unittest`` runner imports this package before any test module.
On import, the harness does these steps:

1. It makes a private scratch directory for this process only, at
   ``scripts/.test-scratch/<pid>-XXXX``. ``tempfile`` and ``HOME`` point to
   it. The system /tmp and the real HOME are not used.
2. It replaces the socket primitives (connect, connect_ex,
   create_connection, getaddrinfo, sendto, sendmsg) with a function that
   raises ``_BlockedIO``. ``_BlockedIO`` is a ``BaseException``, so an
   ``except Exception`` in the code under test cannot catch it. Each
   attempt is also recorded in ``BLOCKED_IO_ATTEMPTS``.
3. It blocks imports of ``bleak`` and ``dbus*``. There is no BLE stack in
   the tests.
4. It removes proxy and SSLKEYLOGFILE variables from the environment.
5. It registers an exit handler. The handler removes only the scratch
   directory of this process. If ``BLOCKED_IO_ATTEMPTS`` is not empty, the
   handler stops the process with exit status 1. This occurs also if the
   code under test caught the ``_BlockedIO`` exception.

Other test runs in the same checkout use a different scratch directory.
Thus parallel runs cannot delete the files of a different run.
"""


import atexit
import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TESTS_DIR.parent
SCRATCH_ROOT = PROJECT_DIR / ".test-scratch"

BLOCKED_IO_ATTEMPTS: list[str] = []

# The exit status when a blocked IO attempt occurred during the run.
GUARD_EXIT_STATUS = 3


class _BlockedIO(BaseException):
    """A blocked external IO attempt.

    It is a ``BaseException``, so an ``except Exception`` handler in the
    code under test cannot catch it.
    """

    def __init__(self, what: str):
        super().__init__(f"external network IO attempted during the offline test suite: {what}")
        BLOCKED_IO_ATTEMPTS.append(what)


def _blocked(what: str):
    def _raise(*_args, **_kwargs):
        raise _BlockedIO(what)

    return _raise


def _install_net_guard() -> None:
    socket.socket.connect = _blocked("socket.connect")  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked("socket.connect_ex")  # type: ignore[method-assign]
    socket.create_connection = _blocked("create_connection")  # type: ignore[assignment]
    socket.getaddrinfo = _blocked("getaddrinfo")  # type: ignore[assignment]
    socket.socket.sendto = _blocked("sendto")  # type: ignore[method-assign]
    socket.socket.sendmsg = _blocked("sendmsg")  # type: ignore[method-assign]


def _is_ble_module(fullname: str) -> bool:
    return (fullname == "bleak" or fullname.startswith("bleak.")
            or fullname.startswith("dbus"))


class _BleBlocker:
    """Import finder that refuses bleak/dbus imports inside tests."""

    def find_spec(self, fullname, path=None, target=None):
        if _is_ble_module(fullname):
            raise _BlockedIO(f"BLE stack import: {fullname}")
        return None


def _install_ble_blocker() -> None:
    # Python returns a module from sys.modules without a meta_path lookup.
    # Thus remove the BLE modules from sys.modules before the hook starts.
    for name in [n for n in sys.modules if _is_ble_module(n)]:
        del sys.modules[name]
    sys.meta_path.insert(0, _BleBlocker())


def _setup_scratch() -> Path:
    SCRATCH_ROOT.mkdir(mode=0o700, exist_ok=True)
    # mkdtemp makes a new directory with mode 0700 and a unique name.
    scratch = Path(tempfile.mkdtemp(prefix=f"{os.getpid()}-", dir=SCRATCH_ROOT))
    tempfile.tempdir = str(scratch)
    os.environ["HOME"] = str(scratch)
    for name in (
        "http_proxy", "https_proxy", "all_proxy",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "SSLKEYLOGFILE", "sslkeylogfile",
    ):
        os.environ.pop(name, None)
    return scratch


def _cleanup_and_enforce() -> None:
    # Remove only the scratch directory of this process.
    shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
    try:
        SCRATCH_ROOT.rmdir()  # only if no other run uses it
    except OSError:
        pass
    if BLOCKED_IO_ATTEMPTS:
        sys.stderr.write(
            "OFFLINE GUARD VIOLATED: the test run attempted external IO: "
            + ", ".join(BLOCKED_IO_ATTEMPTS) + "\n"
        )
        sys.stdout.flush()
        sys.stderr.flush()
        # Python ignores SystemExit in an atexit handler. os._exit sets
        # the exit status of the process.
        os._exit(GUARD_EXIT_STATUS)


# ---- install on import (unittest imports this package first) ----
_install_net_guard()
_install_ble_blocker()
SCRATCH_DIR = _setup_scratch()
atexit.register(_cleanup_and_enforce)
