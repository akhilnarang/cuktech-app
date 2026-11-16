"""Staged bind journal: crash-safe storage for the one-time bind.

The setup command uses this module. It is not a CLI entry point.

Design rules:

- An intent record is saved BEFORE each network mutation
  (``applydid-pending`` / ``bind-pending``). Thus an interrupted mutation
  is never mistaken for "cloud never called".
- Secrets that must survive a crash (pairing token, beacon key, a_key,
  cloud material) are saved at four points. Each point is *before* the
  next operation whose completion is not certain.
- The file is written atomically through a secure helper: private 0700
  directory, exclusively-created 0600 temp file (no symlink window), fsync
  of file and directory.
- A load refuses symlinks, wrong ownership, and secret-bearing files with
  wide permissions.
- The saved charger identity (MAC) does not change through a resume. A
  re-run pins itself to ``state.mac``. A fresh start ARCHIVES the old
  journal. It never deletes or silently overwrites it.
- A re-run NEVER blindly restarts. It must first try an offline token login
  with the saved token. A fresh restart needs explicit typed consent
  if cloud state can exist. This includes a pending intent.
- This module never does or suggests an automatic unbind or re-allocation.
  Cloud cleanup is a separate human action.
"""


import json
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STAGES = ("derived", "did-allocated", "cloud-signed", "device-committed", "bound")
STAGE_INDEX = {name: i for i, name in enumerate(STAGES)}

# cloud_bind lifecycle: no -> (intent) applydid-pending -> applydid ->
# (intent) bind-pending -> standard_bind
CLOUD_BIND_STATES = (
    "no",
    "applydid-pending",
    "applydid",
    "bind-pending",
    "standard_bind",
)
PENDING_STATES = ("applydid-pending", "bind-pending")

SCHEMA_VERSION = 2
TOKEN_HEX_RE = re.compile(r"^[0-9a-f]{24}$")


class JournalError(Exception):
    """The journal is unsafe to load, corrupt, or cannot be written."""

    pass


def validate_token_hex(token_hex: str) -> str:
    """Make sure that a saved pairing token has the correct format.

    Args:
        token_hex: The pairing token as hex text. It must be exactly 24
            lowercase hex characters (12 bytes).

    Returns:
        The same ``token_hex`` value, unchanged.

    Raises:
        JournalError: If ``token_hex`` is empty or has a different format.
    """
    if not TOKEN_HEX_RE.fullmatch(token_hex or ""):
        raise JournalError(
            "journal token_hex is not 24 lowercase hex characters. The "
            "journal is corrupt. It can hold your only copy of the pairing "
            "token. Do not delete it. Examine it manually."
        )
    return token_hex


@dataclass
class JournalState:
    """All data that the journal keeps for one charger bind.

    Attributes:
        mac: BLE MAC address of the charger. A resume does not change it.
        model: Device model name, for example ``cuktech.adapter.ad1204u``.
        region: Xiaomi cloud region code. Default ``"cn"``.
        smac: MAC address text in the form that the cloud API uses.
        factory_did: Device ID that the charger reported (factory value).
        server_did: Device ID that ``/device/bltapplydid`` allocated.
        token_hex: Pairing token, 24 lowercase hex characters.
        bind_key_hex: Beacon (bind) key as hex text.
        a_key_hex: ``a_key`` from the ECDH key derivation, as hex text.
        utc: Server time (Unix seconds) from ``ble_standard_bind``, or None.
        cloud_sign_b64: Cloud signature from ``ble_standard_bind``, base64.
        cloud_cert_b64: Cloud certificate from ``ble_standard_bind``, base64.
        stage: Current stage. One of ``STAGES``. It only moves forward.
        device_committed: Charger confirm state: ``"unknown"``,
            ``"confirm-pending"``, ``"yes"`` or ``"no"``.
        cloud_bind: Cloud bind state. One of ``CLOUD_BIND_STATES``.
        bound_verified: True after an offline token login passed.
        created_at: Creation time, Unix seconds.
        updated_at: Time of the last save, Unix seconds.
        attempts: Log entries, each a dict with ``ts`` and ``note`` keys.
    """

    mac: str
    model: str
    region: str = "cn"
    smac: str = ""
    factory_did: str = ""
    server_did: str = ""
    token_hex: str = ""
    bind_key_hex: str = ""
    a_key_hex: str = ""
    utc: int | None = None
    cloud_sign_b64: str = ""
    cloud_cert_b64: str = ""
    stage: str = "derived"
    # "unknown" | "confirm-pending" | "yes" | "no" — device confirm state
    device_committed: str = "unknown"
    # "no" | "applydid-pending" | "applydid" | "bind-pending" | "standard_bind"
    cloud_bind: str = "no"
    bound_verified: bool = False
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the state to a JSON-ready dict.

        Returns:
            A dict with all fields and a ``schema`` key that holds
            ``SCHEMA_VERSION``.
        """
        return {
            "schema": SCHEMA_VERSION,
            "mac": self.mac,
            "model": self.model,
            "region": self.region,
            "smac": self.smac,
            "factory_did": self.factory_did,
            "server_did": self.server_did,
            "token_hex": self.token_hex,
            "bind_key_hex": self.bind_key_hex,
            "a_key_hex": self.a_key_hex,
            "utc": self.utc,
            "cloud_sign_b64": self.cloud_sign_b64,
            "cloud_cert_b64": self.cloud_cert_b64,
            "stage": self.stage,
            "device_committed": self.device_committed,
            "cloud_bind": self.cloud_bind,
            "bound_verified": self.bound_verified,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "attempts": self.attempts,
        }

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> JournalState:
        """Make a state from a dict that ``to_dict`` wrote.

        Missing optional keys get their default values.

        Args:
            obj: The parsed journal JSON. It must have a ``mac`` key.

        Returns:
            The new ``JournalState``.

        Raises:
            JournalError: If ``stage`` or ``cloud_bind`` has an unknown
                value, or if ``token_hex`` has a bad format.
            KeyError: If ``mac`` is missing.
        """
        stage = obj.get("stage", "derived")
        if stage not in STAGE_INDEX:
            raise JournalError(f"journal has unknown stage {stage!r}")
        cloud_bind = str(obj.get("cloud_bind", "no"))
        if cloud_bind not in CLOUD_BIND_STATES:
            raise JournalError(f"journal has unknown cloud_bind {cloud_bind!r}")
        token_hex = str(obj.get("token_hex", ""))
        if token_hex:
            validate_token_hex(token_hex)
        return cls(
            mac=str(obj["mac"]),
            model=str(obj.get("model", "")),
            region=str(obj.get("region", "cn")),
            smac=str(obj.get("smac", "")),
            factory_did=str(obj.get("factory_did", "")),
            server_did=str(obj.get("server_did", "")),
            token_hex=token_hex,
            bind_key_hex=str(obj.get("bind_key_hex", "")),
            a_key_hex=str(obj.get("a_key_hex", "")),
            utc=obj.get("utc"),
            cloud_sign_b64=str(obj.get("cloud_sign_b64", "")),
            cloud_cert_b64=str(obj.get("cloud_cert_b64", "")),
            stage=stage,
            device_committed=str(obj.get("device_committed", "unknown")),
            cloud_bind=cloud_bind,
            bound_verified=bool(obj.get("bound_verified", False)),
            created_at=float(obj.get("created_at", time.time())),
            updated_at=float(obj.get("updated_at", time.time())),
            attempts=list(obj.get("attempts", [])),
        )


def resume_action(state: JournalState | None) -> tuple[str, str]:
    """Decide what a re-run must do FIRST. It never starts a blind fresh ECDH.

    A pending cloud intent (``applydid-pending`` / ``bind-pending``) has the
    same effect as known cloud state. The mutation can have reached the
    server before the interruption. Thus a fresh restart always needs
    explicit typed consent.

    Args:
        state: The loaded journal state, or None if there is no journal.

    Returns:
        A tuple ``(action, reason)``. ``reason`` is text for the user.
        ``action`` is one of these values:

        - ``"fresh"``: no journal or no derived token. A fresh start is safe.
        - ``"verify-only"``: the journal has a verified bind. Verify again.
        - ``"verify-first"``: a token exists. The offline-login verification
          MUST run before a cloud call or a new ECDH. If it fails,
          ``cloud_bind`` decides between a safe fresh restart and a restart
          that needs consent (see cli.py).
    """
    if state is None:
        return "fresh", "no previous journal"
    if state.stage == "bound" and state.bound_verified:
        return "verify-only", "the journal already has a verified bind"
    if state.stage == "bound":
        return "verify-first", "bound, but verification did not complete"
    if not state.token_hex:
        return "fresh", "the previous run stopped before it derived a secret"
    if state.cloud_bind == "no":
        return (
            "verify-first",
            "the cloud was not called. After a failed verification, a fresh "
            "restart is safe",
        )
    if state.cloud_bind in PENDING_STATES:
        return (
            "verify-first",
            f"a cloud call was in flight when the previous run stopped "
            f"(cloud_bind={state.cloud_bind}). It is not known if the server "
            "processed it. A fresh restart needs explicit typed "
            "consent and is not automatic",
        )
    return (
        "verify-first",
        "cloud state from the previous run can exist "
        f"(cloud_bind={state.cloud_bind}). A fresh restart needs explicit "
        "typed consent and is not automatic",
    )


class BindJournal:
    """Atomic 0600 staged journal for one charger bind.

    Each ``record_*`` method changes the state and saves it at once.

    Attributes:
        path: Path of the journal JSON file.
    """

    def __init__(self, path: str | Path) -> None:
        """Make a journal object. This does not read or write the file.

        Args:
            path: Path of the journal JSON file.
        """
        self.path = Path(path)

    # ------------------------------------------------------------ load/save

    def load(self) -> JournalState | None:
        """Read the journal file after safety checks.

        Returns:
            The saved state, or None if the file does not exist.

        Raises:
            JournalError: If the file is a symlink, has a different owner,
                has a mode other than 0600, or cannot be read or parsed.
        """
        if not self.path.exists():
            return None
        if self.path.is_symlink():
            raise JournalError(
                f"journal at {self.path} is a symlink. The tool does not load it. "
                "Examine it manually."
            )
        info = self.path.lstat()
        if info.st_uid != os.geteuid():
            raise JournalError(
                f"journal at {self.path} is not owned by you. The tool does not load it."
            )
        mode = stat.S_IMODE(info.st_mode)
        if mode != 0o600:
            raise JournalError(
                f"journal at {self.path} has mode {oct(mode)} (expected "
                "0600). Run `chmod 600` on it, then continue."
            )
        try:
            obj = json.loads(self.path.read_text())
            return JournalState.from_dict(obj)
        except (OSError, ValueError, KeyError, JournalError) as exc:
            raise JournalError(
                f"journal at {self.path} is unreadable ({exc}). It can hold "
                "your only copy of the pairing token. Examine it manually. "
                "Do not delete it."
            ) from exc

    def save(self, state: JournalState) -> None:
        """Write the state atomically with mode 0600.

        This also sets ``state.updated_at`` to the current time.

        Args:
            state: The state to write.

        Raises:
            JournalError: If the secure write fails.
        """
        state.updated_at = time.time()
        payload = (json.dumps(state.to_dict(), indent=2) + "\n").encode()
        from .cloud import CloudError, _secure_write

        try:
            _secure_write(self.path, payload)
        except CloudError as exc:
            raise JournalError(str(exc)) from exc

    # ------------------------------------------------------------ archive

    def archive(self, reason: str = "fresh restart") -> Path:
        """Keep a copy of the current journal before a fresh run.

        The copy goes to ``<path>.archived-<timestamp>`` (0600, atomic). A
        ``-<n>`` suffix is added if that name exists. This method does not
        delete the original. The caller replaces it only when it starts a
        new bind.

        Args:
            reason: Text that is added to the ``attempts`` log of the copy.

        Returns:
            The path of the archive copy.

        Raises:
            JournalError: If there is no journal file or the copy fails.
        """
        if not self.path.exists():
            raise JournalError("nothing to archive")
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = self.path.with_name(f"{self.path.name}.archived-{stamp}")
        n = 1
        while dest.exists():
            dest = self.path.with_name(
                f"{self.path.name}.archived-{stamp}-{n}"
            )
            n += 1
        data = self.path.read_bytes()
        from .cloud import CloudError, _secure_write

        try:
            _secure_write(dest, data)
        except CloudError as exc:
            raise JournalError(f"could not archive old journal: {exc}") from exc
        self._append_note_to(dest, reason)
        return dest

    @staticmethod
    def _append_note_to(dest: Path, reason: str) -> None:
        try:
            obj = json.loads(dest.read_text())
            obj.setdefault("attempts", []).append(
                {"ts": time.time(), "note": f"archived before fresh restart: {reason}"}
            )
            dest.write_text(json.dumps(obj, indent=2) + "\n")
            os.chmod(dest, 0o600)
        except (OSError, ValueError):
            pass  # the archive copy itself is the important artifact

    # ------------------------------------------------------------ staged writes

    def _advance(
        self,
        state: JournalState,
        stage: str,
        **fields: Any,
    ) -> None:
        if stage not in STAGE_INDEX:
            raise JournalError(f"unknown stage {stage!r}")
        if STAGE_INDEX[stage] < STAGE_INDEX[state.stage]:
            raise JournalError(
                f"the journal stage cannot move backwards ({state.stage} -> {stage})"
            )
        state.stage = stage
        for name, value in fields.items():
            setattr(state, name, value)
        self.save(state)

    def record_derived(
        self,
        state: JournalState,
        *,
        token_hex: str,
        bind_key_hex: str,
        a_key_hex: str,
        factory_did: str,
    ) -> None:
        """Save the derived secrets (stage 1). Call this BEFORE /device/bltapplydid.

        Args:
            state: The state to change and save.
            token_hex: Pairing token, 24 lowercase hex characters.
            bind_key_hex: Beacon (bind) key as hex text.
            a_key_hex: ``a_key`` as hex text.
            factory_did: Device ID that the charger reported.

        Raises:
            JournalError: If ``token_hex`` has a bad format, or the stage
                cannot move to ``derived``, or the save fails.
        """
        validate_token_hex(token_hex)
        self._advance(
            state,
            "derived",
            token_hex=token_hex,
            bind_key_hex=bind_key_hex,
            a_key_hex=a_key_hex,
            factory_did=factory_did,
            cloud_bind="no",
        )

    # -- intent records: persisted BEFORE the network mutation --------

    def record_intent_applydid(self, state: JournalState) -> None:
        """Save the intent to call /device/bltapplydid (a cloud mutation).

        Args:
            state: The state to change and save.
        """
        state.cloud_bind = "applydid-pending"
        self._append_attempt(state, "intent: calling /device/bltapplydid")
        self.save(state)

    def record_intent_bind(self, state: JournalState) -> None:
        """Save the intent to call /v2/device/ble_standard_bind (a mutation).

        Args:
            state: The state to change and save.
        """
        state.cloud_bind = "bind-pending"
        self._append_attempt(state, "intent: calling /v2/device/ble_standard_bind")
        self.save(state)

    def record_did_allocated(self, state: JournalState, server_did: str) -> None:
        """Save the allocated device ID. Call this after bltapplydid returns, BEFORE ble_standard_bind.

        Args:
            state: The state to change and save.
            server_did: Device ID that the cloud allocated.
        """
        self._advance(
            state,
            "did-allocated",
            server_did=server_did,
            cloud_bind="applydid",
        )

    def record_cloud_signed(
        self,
        state: JournalState,
        *,
        utc: int,
        cloud_sign_b64: str,
        cloud_cert_b64: str,
    ) -> None:
        """Save the cloud signature. Call this after ble_standard_bind returns, BEFORE a BLE bind write.

        Args:
            state: The state to change and save.
            utc: Server time, Unix seconds.
            cloud_sign_b64: Cloud signature, base64.
            cloud_cert_b64: Cloud certificate, base64.
        """
        self._advance(
            state,
            "cloud-signed",
            utc=utc,
            cloud_sign_b64=cloud_sign_b64,
            cloud_cert_b64=cloud_cert_b64,
            cloud_bind="standard_bind",
        )

    def record_device_confirm_pending(self, state: JournalState) -> None:
        """Save that the bind confirm starts. Call this BEFORE the first 0x13 write.

        If an interruption occurs in the confirm phase, the journal already
        tells that the charger got the commit command. Thus the outcome is
        unknown, and a silent unfinished bind cannot occur.

        Args:
            state: The state to change and save.
        """
        state.device_committed = "confirm-pending"
        self._append_attempt(state, "sending 0x13 (bind confirm) to device")
        self.save(state)

    def record_device_committed(self, state: JournalState) -> None:
        """Save that the charger answered 0x11 (bind committed).

        Args:
            state: The state to change and save.
        """
        self._advance(state, "device-committed", device_committed="yes")

    def record_device_rejected(self, state: JournalState) -> None:
        """Save that the charger answered 0x12 (it rejected the bind blob).

        Args:
            state: The state to change and save.
        """
        state.device_committed = "no"
        self._append_attempt(state, "device-rejected (0x12)")
        self.save(state)

    def record_unknown_outcome(self, state: JournalState, why: str) -> None:
        """Save a timeout, disconnect or interrupt before the final charger reply.

        This is the most dangerous state: the charger can have committed
        or not.

        Args:
            state: The state to change and save.
            why: Short text that tells the cause.
        """
        state.device_committed = "unknown"
        self._append_attempt(state, f"unknown outcome: {why}")
        self.save(state)

    def record_bound_verified(self, state: JournalState) -> None:
        """Save that the offline token login passed (stage ``bound``).

        Args:
            state: The state to change and save.
        """
        self._advance(state, "bound", bound_verified=True)

    def record_verify_failed(self, state: JournalState, why: str) -> None:
        """Add a failed offline verification to the log.

        Args:
            state: The state to change and save.
            why: Short text that tells the cause.
        """
        self._append_attempt(state, f"offline verification failed: {why}")
        self.save(state)

    def record_verify_inconclusive(self, state: JournalState, why: str) -> None:
        """Add an inconclusive offline verification to the log.

        This is not a rejection. It does not cause a restart.

        Args:
            state: The state to change and save.
            why: Short text that tells the cause.
        """
        self._append_attempt(state, f"offline verification inconclusive: {why}")
        self.save(state)

    def record_failure(self, state: JournalState, where: str, error: str) -> None:
        """Add a failure record. This NEVER moves the stage back or removes secrets.

        Args:
            state: The state to change and save.
            where: Name of the step that failed.
            error: Error text.
        """
        self._append_attempt(state, f"{where}: {error}")
        self.save(state)

    def _append_attempt(self, state: JournalState, note: str) -> None:
        state.attempts.append({"ts": time.time(), "note": note})


def recovery_instructions(state: JournalState) -> str:
    """Make the manual recovery text. The tool prints it and never runs it.

    Args:
        state: The journal state. Its ``server_did`` goes into the text.

    Returns:
        Multi-line text with numbered recovery options.
    """
    lines = [
        "Recovery options. All of them are manual. This tool does not",
        "unbind or re-allocate anything automatically.",
        "  1. Run setup again. Setup first tries the offline token login",
        "     with the persisted token. If the charger committed, you are",
        "     done. Setup makes no cloud calls in this case.",
        "  2. If verification cannot reach the device (it is off, far away",
        "     or busy), correct this and run setup again. An inconclusive",
        "     result does not restart the bind automatically.",
        "  3. If a previous bind reached the cloud (bltapplydid or",
        "     ble_standard_bind ran), the account can have an entry for",
        f"     this device (did={state.server_did or 'unknown'}). You MUST",
        "     remove it (uv run -m cuktech_pc.cli remove-device --did <did>)",
        "     before a fresh bind can pass the device-list guard.",
        "  4. To start fully fresh: factory-reset the charger (see its",
        "     manual). Remove the account entry (step 3). Then run setup",
        "     again and give consent to a fresh bind. The old journal is",
        "     archived. It is not deleted.",
        "  5. The journal file keeps all derived secrets. Keep it private",
        "     (mode 0600). Do not paste it anywhere.",
    ]
    return "\n".join(lines)
