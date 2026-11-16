"""Scripted fake BLE charger for the offline v2-bind tests.

The fake has the bleak-client interface (start_notify, stop_notify,
write_gatt_char). It plays the charger side of the Mi standard-auth v2
register and login. Thus the tests can run
``cuktech_pc.blebind.V2RegisterClient`` with no Bluetooth hardware.

The fake has its own key schedule and HMAC code. It does not import
``cuktech_pc.crypto``. The code follows docs/firmware/findings-bind.md and
the Mi standard-auth login (ha-cuk-ble ``auth.py``). Thus a crypto bug
that is the same on both sides of ``cuktech_pc.crypto`` makes the tests fail.

There is no network and no real BLE. All work is synchronous and in memory.
"""


import hashlib
import hmac
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

UPNP = "00000010-0000-1000-8000-00805f9b34fb"
AVDTP = "00000019-0000-1000-8000-00805f9b34fb"

RCV_RDY = bytes.fromhex("00 00 01 01")
RCV_OK = bytes.fromhex("00 00 01 00")
CFM_REGISTER_OK = bytes.fromhex("11 00 00 00")
CFM_REGISTER_ERR = bytes.fromhex("12 00 00 00")
CFM_LOGIN_OK = bytes.fromhex("21 00 00 00")
CFM_LOGIN_ERR = bytes.fromhex("23 00 00 00")

# Firmware fragment size: fw 0x41eeb4 drops a non-last frame that is not
# 2 + 18 bytes.
FRAME_CHUNK = 18

# 24-byte v2 device-info blob: version 2, io caps 0/0, DID 00||19 ASCII
DEVINFO = b"\x02\x00\x00\x00\x00" + b"1234567890123456789"


class FakePeerError(Exception):
    pass


def _chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]


def _hkdf64(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(ikm)


def register_token(shared: bytes) -> bytes:
    """Charger side of the register key schedule (findings-bind.md step 1).

    HKDF-SHA256(shared, salt = 16 zero bytes, "mible-setup-info", 64).
    The token is bytes 0..11.
    """
    return _hkdf64(shared, bytes(16), b"mible-setup-info")[0:12]


def login_keys(token: bytes, app_rand: bytes, dev_rand: bytes) -> tuple[bytes, bytes]:
    """Charger side of the login key schedule.

    HKDF-SHA256(token, salt = app_rand || dev_rand, "mible-login-info", 64).
    dev_key is bytes 0..15. app_key is bytes 16..31.
    """
    out = _hkdf64(token, app_rand + dev_rand, b"mible-login-info")
    return out[0:16], out[16:32]


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class FakeBleClient:
    """Charger simulator with scriptable outcome knobs."""

    def __init__(
        self,
        *,
        outcome: str = "ok",  # ok | reject | silent | e1
        token: bytes | None = None,
        fail_on_write: int | None = None,  # 1-based write counter -> raise
        login_error: bytes | None = None,  # e.g. e0 -> typed error class
        devinfo: bytes = DEVINFO,
    ) -> None:
        self.outcome = outcome
        self.token = token
        self.fail_on_write = fail_on_write
        self._login_error = login_error
        self._devinfo = devinfo
        self.handlers: dict[str, Any] = {}
        self.writes: list[tuple[str, bytes]] = []
        self._write_counter = 0
        # charger ECDH key for the register exchange
        self._dev_priv = ec.generate_private_key(ec.SECP256R1())
        # token from the register exchange (used for a later login if no
        # explicit token is set)
        self._register_token: bytes | None = None
        self._upload: dict[int, bytes] = {}
        self._upload_code: int | None = None
        self._upload_count = 0
        self.parcel_frames: dict[int, list[bytes]] = {}  # code -> frame payloads
        self._bind_result: bytes | None = None
        self._got_blob: bytes | None = None
        self._got_cert: bytes | None = None
        self._app_rand: bytes | None = None
        self._dev_rand = bytes(range(0x40, 0x50))
        self._pending_app_key: bytes | None = None

    # ------------------------------------------------------ bleak interface

    async def start_notify(self, uuid: str, handler: Any, **_kw: Any) -> None:
        self.handlers[uuid] = handler

    async def stop_notify(self, uuid: str) -> None:
        self.handlers.pop(uuid, None)

    async def write_gatt_char(
        self, uuid: str, data: bytearray, response: bool = False
    ) -> None:
        self._write_counter += 1
        if self.fail_on_write is not None and self._write_counter == self.fail_on_write:
            raise FakePeerError(f"injected write failure #{self._write_counter}")
        payload = bytes(data)
        self.writes.append((uuid, payload))
        if uuid == UPNP:
            self._on_upnp(payload)
        elif uuid == AVDTP:
            self._on_avdtp(payload)

    async def disconnect(self) -> None:
        pass

    # ------------------------------------------------------ charger behavior

    def _notify(self, uuid: str, data: bytes) -> None:
        handler = self.handlers.get(uuid)
        if handler is not None:
            handler(uuid, bytearray(data))

    def _announce_and_parcels(self, code: int, payload: bytes) -> None:
        frames = _chunks(payload, FRAME_CHUNK)
        self._notify(
            AVDTP,
            bytes([0, 0, 0, code]) + len(frames).to_bytes(2, "little"),
        )
        for idx, chunk in enumerate(frames, start=1):
            self._notify(AVDTP, idx.to_bytes(2, "little") + chunk)

    def _on_upnp(self, payload: bytes) -> None:
        if payload == bytes.fromhex("a2 00 00 00"):  # GET_INFO
            self._announce_and_parcels(0x00, self._devinfo)
        elif payload[0:1] == b"\x15":  # caps echo (reg continue)
            pass
        elif payload == bytes.fromhex("13 00 00 00"):
            self._bind_result = payload
        elif payload == bytes.fromhex("14 00 00 00"):
            self._bind_result = payload
        elif payload == bytes.fromhex("24 00 00 00"):  # LOGIN start
            pass  # wait for the app random parcel
        elif payload == b"\xa4":  # greeting trigger
            self._notify(AVDTP, bytes.fromhex("00 00 04 01"))
            self._notify(AVDTP, bytes.fromhex("00 00 04 02"))

    def _on_avdtp(self, payload: bytes) -> None:
        if payload in (RCV_RDY, RCV_OK):
            return  # client-side receive control frames
        if (
            len(payload) >= 3
            and payload[0] == 0
            and payload[1] == 0
            and payload[2] in (0x03, 0x05)
        ):
            return  # OFFICIAL_ACK / greeting echo from the client
        if len(payload) >= 6 and payload[0] == 0 and payload[1] == 0:
            if payload[2] == 0x00:  # upload announcement (variant 0)
                self._upload_code = payload[3]
                self._upload_count = int.from_bytes(payload[4:6], "little")
                self._upload = {}
                self._notify(AVDTP, RCV_RDY)
                return
            return
        # parcel frame: 2-byte LE index + payload
        idx = int.from_bytes(payload[0:2], "little")
        if idx < self._upload_count and len(payload) != 2 + FRAME_CHUNK:
            raise FakePeerError(
                f"non-last parcel frame {idx} is {len(payload)} bytes; "
                f"the firmware needs {2 + FRAME_CHUNK}"
            )
        self._upload[idx] = payload[2:]
        self.parcel_frames.setdefault(self._upload_code or 0, []).append(payload)
        if len(self._upload) == self._upload_count:
            self._notify(AVDTP, RCV_OK)
            data = b"".join(self._upload[i] for i in sorted(self._upload))
            self._on_upload_complete(self._upload_code or 0, data)

    def _on_upload_complete(self, code: int, data: bytes) -> None:
        if code == 0x03:  # app ECDH pubkey, 64 B X||Y
            app_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b"\x04" + data
            )
            shared = self._dev_priv.exchange(ec.ECDH(), app_pub)
            self._register_token = register_token(shared)
            dev_pub = self._dev_priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            self._announce_and_parcels(0x03, dev_pub[1:])
        elif code == 0x0B:  # login: app random
            self._app_rand = data
            if self._login_error is not None:
                self._notify(UPNP, self._login_error)
                return
            token = self.token if self.token is not None else self._register_token
            if token is None:
                self._notify(UPNP, CFM_LOGIN_ERR)
                return
            # charger sends its random + HMAC, then checks the app HMAC
            dev_key, app_key = login_keys(token, data, self._dev_rand)
            self._announce_and_parcels(0x0D, self._dev_rand)
            self._announce_and_parcels(0x0C, _mac(dev_key, self._dev_rand + data))
            self._pending_app_key = app_key
        elif code == 0x0A:  # login: app HMAC
            expected = _mac(self._pending_app_key, self._app_rand + self._dev_rand)
            ok = hmac.compare_digest(data, expected)
            self._notify(UPNP, CFM_LOGIN_OK if ok else CFM_LOGIN_ERR)
        elif code == 0x00:  # bind blob
            self._got_blob = data
        elif code == 0x07:  # cloud cert
            self._got_cert = data
            if self._bind_result == bytes.fromhex("13 00 00 00"):
                if self.outcome == "ok":
                    self._notify(UPNP, CFM_REGISTER_OK)
                elif self.outcome == "reject":
                    self._notify(UPNP, CFM_REGISTER_ERR)
                elif self.outcome == "e1":
                    self._notify(UPNP, bytes.fromhex("e1 00 00 00"))
                # "silent": send nothing

    # ----------------------------------------------------------- assertions

    def count_writes(self, payload: bytes) -> int:
        return sum(1 for (_, p) in self.writes if p == payload)
