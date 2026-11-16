"""Mi BLE standard-auth v2 register client over a bleak-style GATT client.

The CLI uses this module. It is not a CLI entry point.

The channel and parcel code is adapted from ha-cuk-ble
(https://github.com/zuyan9/ha-cuk-ble, Apache License 2.0). The original is
``custom_components/cuktech_ble/lib/xiaomi/auth.py``. Changes from the
original:

- Register uses only the v2 flow. This flow is verified against the
  decompiled Mi Home 11.9.521 ``BleStandardAuthRegisterConnector``:

  - caps-echo ``15`` uses the 3-byte form of the app;
  - the cloud phase is between the pubkey exchange and the ``0x13``
    bind-result write;
  - the code-0 92-byte blob and the code-7 certificate uploads come before
    the final ``0x11``.
- ``write_bind_result(False)`` writes ``0x14``. Then the charger leaves its
  pending-bind state when the cloud phase fails. The app does this on each
  bind-phase cloud failure after the pubkey exchange (applyDid handler
  L143-144 and $3.onResponse L403-406).
- Frame contents are never logged. Only the uuid and the length are logged.
  Thus no derived or cloud-issued secret can go into a log.
- ``scan_for_ad1204u`` and ``connect`` import bleak lazily. Thus this module
  and its tests (which inject a fake client) do not need a BLE stack.

Login and greeting have no changes. They are the hardware-verified offline
verification path.
"""


import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

from . import crypto
from .fe95 import AD1204U_PRODUCT_IDS, PID_MODEL_HINTS, parse_fe95

LOGGER = logging.getLogger(__name__)

UPNP_UUID = "00000010-0000-1000-8000-00805f9b34fb"
AVDTP_UUID = "00000019-0000-1000-8000-00805f9b34fb"
FE95_SERVICE_DATA_KEY = "0000fe95-0000-1000-8000-00805f9b34fb"

# UPNP commands (host -> device control channel, 4-byte LE frames)
CMD_GET_INFO = bytes.fromhex("a2 00 00 00")
CMD_LOGIN = bytes.fromhex("24 00 00 00")
CMD_BIND_RESULT_OK = bytes.fromhex("13 00 00 00")  # app: bind success
CMD_BIND_RESULT_FAIL = bytes.fromhex("14 00 00 00")  # app: bind failure

# AVDTP parcel announcements: 00 00 <variant> <code> <count LE16>
ANN_SEND_DATA = bytes.fromhex("00 00 00 03 04 00")  # code 3: our ECDH pubkey
ANN_SEND_BLOB = bytes.fromhex("00 00 00 00 06 00")  # code 0: 92-B bind blob
ANN_SEND_CERT = bytes.fromhex("00 00 00 07 16 00")  # code 7: cloud cert
CMD_SEND_KEY = bytes.fromhex("00 00 00 0b 01 00")  # login: our 16-B random
CMD_SEND_INFO = bytes.fromhex("00 00 00 0a 02 00")  # login: 32-B HMAC

RCV_RDY = bytes.fromhex("00 00 01 01")
RCV_OK = bytes.fromhex("00 00 01 00")
GREETING_TRIGGER = bytes.fromhex("a4")
OFFICIAL_ACK = bytes.fromhex("00 00 03 00")

CFM_REGISTER_OK = bytes.fromhex("11 00 00 00")
CFM_REGISTER_ERR = bytes.fromhex("12 00 00 00")
CFM_LOGIN_OK = bytes.fromhex("21 00 00 00")
CFM_LOGIN_ERR = bytes.fromhex("23 00 00 00")

AUTH_ERRORS = {
    bytes.fromhex("e0 00 00 00"),
    bytes.fromhex("e1 00 00 00"),
    bytes.fromhex("e2 00 00 00"),
    bytes.fromhex("e3 00 00 00"),
}

# Device auth-error codes (mible_standard_auth.h L32-36): the exact SDK
# meaning of each e0-e3 frame, used for typed classification.
ERR_NOT_REGISTERED = bytes.fromhex("e0 00 00 00")   # device holds no binding
ERR_REGISTERED = bytes.fromhex("e1 00 00 00")       # device is bound to another key
ERR_REPEAT_LOGIN = bytes.fromhex("e2 00 00 00")     # login repeated in one session
ERR_INVALID_OOB = bytes.fromhex("e3 00 00 00")      # invalid OOB data

PARCEL_CHUNK_SIZE = 18
MAX_AUTH_PARCELS = 64
FINAL_RESULT_TIMEOUT = 15.0  # app arms a 15 s timeout (msg 4102, 15000L)


class MiAuthError(Exception):
    """A BLE auth step failed: timeout, bad frame, or a charger auth error."""

    pass


class MiAuthInvalidTokenError(MiAuthError):
    """The supplied token cannot authenticate this device."""


class MiAuthNotRegisteredError(MiAuthError):
    """The charger answered e0 (ERR_NOT_REGISTERED).

    The match uses the exact SDK code, not error text. The charger holds no
    binding. A token login cannot pass until a register (bind) runs.
    """


@dataclass
class _ChannelQueue:
    uuid: str
    maxsize: int = 64
    queue: asyncio.Queue[bytes] = field(init=False)
    dropped: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.queue = asyncio.Queue(maxsize=self.maxsize)

    def handler(self) -> Callable[[Any, bytearray], None]:
        """Make a notify callback that puts frames into this queue.

        If the queue is full, the oldest frame is removed and ``dropped``
        increases. The next receive then fails.

        Returns:
            A callback with the bleak signature ``(sender, data)``.
        """
        def _on(_: Any, data: bytearray) -> None:
            if self.queue.full():
                # keep memory bounded; the consumer reconnects instead of
                # silently continuing with missing protocol frames
                self.queue.get_nowait()
                self.dropped += 1
            self.queue.put_nowait(bytes(data))

        return _on


def _chunk_parcel(data: bytes, chunk_size: int = PARCEL_CHUNK_SIZE) -> list[bytes]:
    if not data:
        return [b""]
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


# --------------------------------------------------------------------- client


class V2RegisterClient:
    """Run the v2 register and the login on a connected bleak-style client.

    The client object must have ``start_notify(uuid, handler)``,
    ``stop_notify(uuid)`` and ``write_gatt_char(uuid, bytearray, response=bool)``.
    The bleak ``BleakClient`` has them. The
    test suite injects a scripted fake.

    Use it as an async context manager to subscribe and unsubscribe. The
    methods are not safe for concurrent use on one object.
    """

    def __init__(
        self,
        client: Any,
        *,
        timeout: float = 10.0,
    ) -> None:
        """Make the client wrapper. This does not do BLE I/O.

        Args:
            client: A connected bleak-style GATT client.
            timeout: Time limit in seconds for each frame receive.
        """
        self._client = client
        self._timeout = timeout
        self._upnp = _ChannelQueue(UPNP_UUID)
        self._avdtp = _ChannelQueue(AVDTP_UUID)
        self._upnp_sub = False
        self._avdtp_sub = False

    async def __aenter__(self) -> V2RegisterClient:
        await self.subscribe()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.unsubscribe()

    async def subscribe(self, *, upnp: bool = True) -> None:
        """Start notifications on the AVDTP channel and on the UPNP channel.

        A channel that is already subscribed is not subscribed again.

        Args:
            upnp: If False, do not subscribe the UPNP control channel now.
                Subscribe it after the greeting. This is the login order of
                Mi Home and of ha-cuk-ble (proven on hardware).
        """
        if not self._avdtp_sub:
            await self._client.start_notify(
                AVDTP_UUID, self._avdtp.handler()
            )
            self._avdtp_sub = True
        if upnp and not self._upnp_sub:
            await self._client.start_notify(
                UPNP_UUID, self._upnp.handler()
            )
            self._upnp_sub = True

    async def unsubscribe(self) -> None:
        """Stop notifications on all subscribed channels.

        A ``stop_notify`` failure is logged at debug level and ignored.
        """
        to_stop = []
        if self._upnp_sub:
            to_stop.append(UPNP_UUID)
            self._upnp_sub = False
        if self._avdtp_sub:
            to_stop.append(AVDTP_UUID)
            self._avdtp_sub = False
        for uuid in to_stop:
            try:
                await self._client.stop_notify(uuid)
            except Exception:  # noqa: BLE001
                LOGGER.debug("stop_notify(%s) failed", uuid, exc_info=True)

    # ------------------------------------------------------------------ IO

    async def _recv(self, channel: _ChannelQueue) -> bytes:
        if channel.dropped:
            raise MiAuthError(
                f"notification queue overflow on {channel.uuid} "
                f"({channel.dropped} frame(s) dropped)"
            )
        try:
            data = await asyncio.wait_for(channel.queue.get(), self._timeout)
        except TimeoutError as exc:
            raise MiAuthError(f"timeout waiting for {channel.uuid}") from exc
        LOGGER.debug("← %s len=%d", channel.uuid, len(data))
        if data == ERR_NOT_REGISTERED:
            # typed classification by exact SDK code: e0 during a
            # login attempt means the device holds no binding at all
            raise MiAuthNotRegisteredError(
                "device reports ERR_NOT_REGISTERED (e0): it holds no binding"
            )
        if data in AUTH_ERRORS:
            raise MiAuthError(f"device auth error: {data.hex()}")
        return data

    async def _recv_until(self, channel: _ChannelQueue, expected: bytes) -> None:
        while True:
            data = await self._recv(channel)
            if data == expected:
                return
            LOGGER.debug(
                "discarding unexpected frame on %s (len=%d)",
                channel.uuid,
                len(data),
            )

    async def _write(self, uuid: str, payload: bytes) -> None:
        LOGGER.debug("→ %s len=%d", uuid, len(payload))
        await self._client.write_gatt_char(uuid, bytearray(payload), response=False)

    async def _send_parcel(self, uuid: str, announcement: bytes, data: bytes) -> None:
        """Send announcement, await RCV_RDY, stream parcels, await RCV_OK.

        Chunks are always 18 bytes (the firmware's un-negotiated fragment
        size); the announcement's frame count is rewritten to match.
        """
        if len(announcement) < 6:
            raise MiAuthError(
                f"parcel announcement is shorter than 6 bytes: {announcement.hex()}"
            )
        # fw 0x41eeb4 drops any non-last frame that is not exactly 2 + 18
        # bytes, unless a fragment-size negotiation ran (we never run it)
        frames = _chunk_parcel(data)
        if len(frames) > MAX_AUTH_PARCELS:
            raise MiAuthError(
                f"auth payload needs {len(frames)} parcels; "
                f"maximum is {MAX_AUTH_PARCELS}"
            )
        announcement = (
            announcement[:4]
            + len(frames).to_bytes(2, "little")
            + announcement[6:]
        )
        await self._write(uuid, announcement)
        await self._recv_until(self._avdtp, RCV_RDY)
        for idx, chunk in enumerate(frames, start=1):
            frame = bytes([idx & 0xFF, (idx >> 8) & 0xFF]) + chunk
            await self._write(AVDTP_UUID, frame)
        await self._recv_until(self._avdtp, RCV_OK)

    async def _recv_parcel(self, announcement: bytes) -> bytes:
        if len(announcement) < 6:
            raise MiAuthError(
                f"parcel announcement is shorter than 6 bytes: {announcement.hex()}"
            )
        expected = int.from_bytes(announcement[4:6], "little")
        if not 1 <= expected <= MAX_AUTH_PARCELS:
            raise MiAuthError(
                f"invalid auth parcel count {expected}; "
                f"maximum is {MAX_AUTH_PARCELS}"
            )
        await self._write(AVDTP_UUID, RCV_RDY)
        frames: dict[int, bytes] = {}
        while len(frames) < expected:
            data = await self._recv(self._avdtp)
            if len(data) < 2:
                raise MiAuthError(f"short auth parcel: {data.hex()}")
            idx = int.from_bytes(data[:2], "little")
            if idx == 0 or idx > expected:
                raise MiAuthError(
                    f"auth parcel index {idx} outside 1..{expected}"
                )
            if idx in frames:
                raise MiAuthError(f"duplicate auth parcel index {idx}")
            frames[idx] = data[2:]
        await self._write(AVDTP_UUID, RCV_OK)
        return b"".join(frames[i] for i in sorted(frames))

    async def _upnp_queue_get(self) -> bytes:
        """Await one raw frame from the control channel (login e0 race)."""
        if self._upnp.dropped:
            raise MiAuthError("notification queue overflow on 0x0010")
        return await asyncio.wait_for(self._upnp.queue.get(), self._timeout)

    async def _recv_payload(self, expected_code: int) -> bytes:
        announcement = await self._recv(self._avdtp)
        if len(announcement) < 4:
            raise MiAuthError(f"short announcement: {announcement.hex()}")
        if announcement[3] != expected_code:
            raise MiAuthError(
                f"expected announcement code 0x{expected_code:02x}, "
                f"got {announcement.hex()}"
            )
        variant = announcement[2]
        if variant == 0x02:
            payload = announcement[4:]
            await self._write(AVDTP_UUID, OFFICIAL_ACK)
            return payload
        if variant == 0x00:
            return await self._recv_parcel(announcement)
        raise MiAuthError(
            f"unknown variant byte 0x{variant:02x} in {announcement.hex()}"
        )

    # -------------------------------------------------------------- REGISTER

    async def get_devinfo(self) -> crypto.DevInfo:
        """Send GET_INFO and read the v2 device-info parcel.

        Returns:
            The parsed device info (version, IO caps, DID).

        Raises:
            MiAuthError: If a receive fails, the auth version is not 2, or
                the charger needs OOB input.
            crypto.DevInfoError: If the device-info parcel cannot be parsed.
        """
        await self._write(UPNP_UUID, CMD_GET_INFO)
        raw = await self._recv_payload(0x00)
        devinfo = crypto.parse_devinfo(raw)
        if devinfo.version != 2:
            raise MiAuthError(
                f"device is standard-auth v{devinfo.version}. This tool "
                "supports only v2."
            )
        if devinfo.caps_in_out & 0x0F:
            raise MiAuthError(
                "device needs OOB input (IO caps != 0). This is not supported."
            )
        return devinfo

    async def send_caps_echo(self, devinfo: crypto.DevInfo) -> None:
        """Send the register-continue frame ``15 <caps byte2> <caps byte3>`` (app form).

        Args:
            devinfo: Device info from ``get_devinfo``. Its caps bytes are
                sent back.
        """
        await self._write(UPNP_UUID, bytes([0x15, devinfo.caps_in_out, devinfo.caps2]))

    async def send_pubkey(self, pub_bytes: bytes) -> None:
        """Send the ECDH public key of the host as a code-3 parcel.

        Args:
            pub_bytes: Raw P-256 public key, X and Y, 64 bytes.

        Raises:
            MiAuthError: If the key is not 64 bytes or the parcel transfer fails.
        """
        if len(pub_bytes) != 64:
            raise MiAuthError(f"pubkey must be 64 bytes, got {len(pub_bytes)}")
        await self._send_parcel(AVDTP_UUID, ANN_SEND_DATA, pub_bytes)

    async def recv_peer_pubkey(self) -> bytes:
        """Receive the ECDH public key of the charger (code-3 payload).

        Returns:
            Raw P-256 public key of the charger, X and Y, 64 bytes.

        Raises:
            MiAuthError: If the receive fails or the key is not 64 bytes.
        """
        peer = await self._recv_payload(0x03)
        if len(peer) != 64:
            raise MiAuthError(f"device pubkey must be 64 bytes, got {len(peer)}")
        return peer

    async def write_bind_result(self, ok: bool) -> None:
        """Write the bind result. The charger then leaves its pending-bind state.

        Args:
            ok: True writes 0x13 (success). False writes 0x14 (failure).
        """
        await self._write(UPNP_UUID, CMD_BIND_RESULT_OK if ok else CMD_BIND_RESULT_FAIL)

    async def send_bind_blob(self, blob: bytes) -> None:
        """Send the 92-byte AES-CCM bind blob as a code-0 parcel.

        Args:
            blob: The encrypted bind blob, 92 bytes.

        Raises:
            MiAuthError: If the blob is not 92 bytes or the transfer fails.
        """
        if len(blob) != 92:
            raise MiAuthError(f"bind blob must be 92 bytes, got {len(blob)}")
        await self._send_parcel(AVDTP_UUID, ANN_SEND_BLOB, blob)

    async def send_cloud_cert(self, cert: bytes) -> None:
        """Send the cloud-issued X.509 certificate as a code-7 parcel.

        Args:
            cert: The certificate bytes from the cloud.

        Raises:
            MiAuthError: If ``cert`` is empty or the transfer fails.
        """
        if not cert:
            raise MiAuthError("cloud cert is empty")
        await self._send_parcel(AVDTP_UUID, ANN_SEND_CERT, cert)

    async def wait_final(self, timeout: float = FINAL_RESULT_TIMEOUT) -> str:
        """Wait for the final reply of the charger after the cert upload.

        A timeout is a return value. It does not raise.

        Args:
            timeout: Time limit in seconds. The default (15 s) is the
                same as the app.

        Returns:
            ``"ok"`` (0x11), ``"fail"`` (0x12), ``"auth-error"`` (e0-e3),
            ``"timeout"``, or ``"unexpected:<hex>"``.

        Raises:
            MiAuthError: If the UPNP notification queue dropped frames.
        """
        if self._upnp.dropped:
            raise MiAuthError("notification queue overflow on 0x0010")
        try:
            frame = await asyncio.wait_for(self._upnp.queue.get(), timeout)
        except TimeoutError:
            return "timeout"
        frame = bytes(frame)
        if frame == CFM_REGISTER_OK:
            return "ok"
        if frame == CFM_REGISTER_ERR:
            return "fail"
        if frame in AUTH_ERRORS:
            return "auth-error"
        return f"unexpected:{frame.hex()}"

    # ---------------------------------------------------------------- LOGIN

    async def greet(self) -> None:
        """Do the a4 challenge-echo handshake before the login.

        Verified on hardware. The charger sends two challenges. Each one
        is echoed back.

        Raises:
            MiAuthError: If a receive fails or a challenge has a bad header.
        """
        await self._write(UPNP_UUID, GREETING_TRIGGER)
        for _ in range(2):
            challenge = await self._recv(self._avdtp)
            if len(challenge) < 3 or challenge[:3] != b"\x00\x00\x04":
                raise MiAuthError(
                    f"unexpected greeting challenge (len={len(challenge)})"
                )
            echo = b"\x00\x00\x05" + challenge[3:]
            await self._write(AVDTP_UUID, echo)

    async def login(self, token: bytes) -> crypto.SessionKeys:
        """Do the offline token login. This is the final bind verification.

        Args:
            token: Pairing token, 12 bytes.

        Returns:
            The session keys from the login.

        Raises:
            MiAuthNotRegisteredError: If the charger answers e0. It holds no
                binding.
            MiAuthInvalidTokenError: If the HMAC of the charger does not
                match, or the charger answers 0x23 (login failure).
            MiAuthError: If the token is not 12 bytes, or for other receive,
                frame or auth errors.
        """
        if len(token) != 12:
            raise MiAuthError(f"token must be 12 bytes, got {len(token)}")

        import secrets as _secrets

        app_rand = _secrets.token_bytes(16)

        # announce login and send our random without pause (a pause makes
        # some firmwares fire an e0 reject)
        await self._write(UPNP_UUID, CMD_LOGIN)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_KEY, app_rand)

        # An unbound device answers e0 (ERR_NOT_REGISTERED) on the control
        # channel instead of the dev-random parcel. Race both channels so
        # the typed error surfaces instead of an AVDTP timeout.
        dev_rand_task = asyncio.create_task(self._recv_payload(0x0D))
        upnp_task = asyncio.create_task(self._upnp_queue_get())
        done, _ = await asyncio.wait(
            {dev_rand_task, upnp_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if upnp_task in done:
            # a control-channel timeout is not a verdict: fall through
            frame = None if upnp_task.exception() else upnp_task.result()
            if frame in AUTH_ERRORS:
                dev_rand_task.cancel()
                if frame == ERR_NOT_REGISTERED:
                    raise MiAuthNotRegisteredError(
                        "device reports ERR_NOT_REGISTERED (e0): it holds no binding"
                    )
                raise MiAuthError(f"device auth error: {frame.hex()}")
        else:
            upnp_task.cancel()
        # a harmless control frame must not cancel the dev-random wait
        dev_rand = await dev_rand_task
        if len(dev_rand) != 16:
            raise MiAuthError(f"device random has wrong length: {len(dev_rand)}")

        dev_info = await self._recv_payload(0x0C)

        keys = crypto.derive_login(token, app_rand, dev_rand)
        expected_dev_info = crypto.hmac_sha256(keys.dev_key, dev_rand + app_rand)
        if dev_info != expected_dev_info:
            raise MiAuthInvalidTokenError(
                "device HMAC mismatch. The token is wrong, or the device must be registered."
            )

        app_info = crypto.hmac_sha256(keys.app_key, app_rand + dev_rand)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_INFO, app_info)

        conf = await self._recv(self._upnp)
        if conf == CFM_LOGIN_OK:
            return keys
        if conf == CFM_LOGIN_ERR:
            raise MiAuthInvalidTokenError(
                "device reported login failure (23 00 00 00)"
            )
        raise MiAuthError(f"unexpected login confirmation (len={len(conf)})")


# ------------------------------------------------------------------ scanning


@dataclass(frozen=True)
class ScanHit:
    """One AD1204U-family charger that a scan found.

    Attributes:
        address: BLE address of the charger.
        name: Advertised local name, or an empty string.
        rssi: Signal strength in dBm. 0 if unknown.
        frame: The parsed FE95 frame (``fe95.FE95Frame``).
    """

    address: str
    name: str
    rssi: int
    frame: Any  # fe95.FE95Frame

    @property
    def model_hint(self) -> str | None:
        """Model name for the advertised product ID, or None if not known."""
        if self.frame.product_id in PID_MODEL_HINTS:
            return PID_MODEL_HINTS[self.frame.product_id]
        return None


async def scan_for_ad1204u(duration: float = 10.0) -> list[ScanHit]:
    """Scan for FE95 advertisements with a known AD1204U-family pid.

    The scan does not assume the SKU. It reports the CN unit (pid 0x660E)
    and the overseas unit (pid 0x8AB9) with the live advertised name. It
    is read-only and makes no connection. It imports bleak lazily.

    Args:
        duration: Scan time in seconds.

    Returns:
        The found chargers, one per address, strongest RSSI first.
    """
    from bleak import BleakScanner  # lazy: tests never import bleak

    found: dict[str, ScanHit] = {}
    devices = await BleakScanner.discover(timeout=duration, return_adv=True)
    for address, (_device, adv) in devices.items():
        data = adv.service_data.get(FE95_SERVICE_DATA_KEY)
        if not data:
            continue
        try:
            frame = parse_fe95(data)
        except ValueError:
            continue
        if frame.product_id not in AD1204U_PRODUCT_IDS:
            continue
        found[address] = ScanHit(
            address=address,
            name=adv.local_name or "",
            rssi=adv.rssi if adv.rssi is not None else 0,
            frame=frame,
        )
    return sorted(found.values(), key=lambda hit: hit.rssi, reverse=True)


async def connect(address: str, *, timeout: float = 30.0) -> Any:
    """Find an advertising charger and connect to it with bleak.

    bleak is imported lazily.

    Args:
        address: BLE address from a scan.
        timeout: Time limit in seconds for the search and for the connection.

    Returns:
        A connected ``BleakClient``. The caller must disconnect it.

    Raises:
        MiAuthError: If no device with ``address`` advertises in time.
    """
    from bleak import BleakClient, BleakScanner

    device = await BleakScanner.find_device_by_address(address, timeout=timeout)
    if device is None:
        raise MiAuthError(f"device {address} is not advertising")
    client = BleakClient(device, timeout=timeout)
    await client.connect()
    return client
