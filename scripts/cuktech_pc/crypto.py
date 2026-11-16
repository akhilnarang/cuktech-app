"""Crypto primitives for the Xiaomi Mi BLE standard-auth v2 bind flow.

Adapted from ha-cuk-ble (https://github.com/zuyan9/ha-cuk-ble, Apache License 2.0),
original at ``custom_components/cuktech_ble/lib/xiaomi/crypto.py``.
Additions for this tool (marked "Addition"): ``ccm_encrypt``,
``normalize_did``, ``build_bind_blob`` and ``parse_devinfo``. They come from
the decompiled Mi Home 11.9.521 APK (``BleStandardAuthRegisterConnector``).
"""


from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SETUP_INFO = b"mible-setup-info"
LOGIN_INFO = b"mible-login-info"

# Addition: fixed AES-CCM parameters for the v2 bind blob
# (BleStandardAuthRegisterConnector.buildEncryptData L1034-1048: nonce
# 0x10..0x1b, AAD "devID", 4-byte tag).
BLOB_NONCE = bytes(range(16, 28))  # 12 bytes: 0x10..0x1b
BLOB_AAD = b"devID"
BLOB_TAG_LENGTH = 4


@dataclass(frozen=True)
class RegisterSecrets:
    """Secrets that HKDF derives from the register-time ECDH shared secret.

    Attributes:
        token: 12 bytes. Keep it: every later login uses it.
        bind_key: 16 bytes. The cloud also receives it as ``beacon_key``.
        a_key: 16 bytes. AES-CCM key for the v2 bind blob.
    """
    token: bytes  # 12 bytes, persisted for future logins
    bind_key: bytes  # 16 bytes (also uploaded as beacon_key)
    a_key: bytes  # 16 bytes, used to encrypt the v2 bind blob


@dataclass(frozen=True)
class SessionKeys:
    """Per-login session keys that HKDF derives from the token and both randoms.

    Attributes:
        dev_key: 16-byte AES key. Decrypts frames from the charger to the app.
        app_key: 16-byte AES key. Encrypts frames from the app to the charger.
        dev_iv: 4-byte nonce prefix for frames from the charger.
        app_iv: 4-byte nonce prefix for frames from the app.
    """
    dev_key: bytes  # 16 bytes (device -> app decrypt)
    app_key: bytes  # 16 bytes (app -> device encrypt)
    dev_iv: bytes  # 4 bytes
    app_iv: bytes  # 4 bytes


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Make a new random P-256 (SECP256R1) key pair for one ECDH exchange.

    Returns:
        A ``(private_key, public_key)`` tuple.
    """
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return priv, priv.public_key()


def public_key_to_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize a P-256 public key as 64 bytes (X||Y, no 0x04 prefix).

    Args:
        key: The P-256 public key.

    Returns:
        The 32-byte X coordinate followed by the 32-byte Y coordinate.

    Raises:
        ValueError: If the library returns an encoding that is not a
            65-byte uncompressed point.
    """
    raw = key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("unexpected public key encoding")
    return raw[1:]


def bytes_to_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from the 64-byte X||Y form that the charger sends.

    Args:
        data: 64 bytes, X||Y, without the 0x04 prefix.

    Returns:
        The public key.

    Raises:
        ValueError: If ``data`` is not 64 bytes or is not a point on the curve.
    """
    if len(data) != 64:
        raise ValueError(f"P-256 public key must be 64 bytes, got {len(data)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b"\x04" + data
    )


def ecdh_shared(private_key: ec.EllipticCurvePrivateKey, peer_public: ec.EllipticCurvePublicKey) -> bytes:
    """Calculate the ECDH shared secret.

    Args:
        private_key: Our P-256 private key.
        peer_public: The P-256 public key of the charger.

    Returns:
        The 32-byte shared secret (the X coordinate).
    """
    return private_key.exchange(ec.ECDH(), peer_public)


def hkdf(ikm: bytes, *, salt: bytes | None, info: bytes, length: int) -> bytes:
    """Derive key material with HKDF-SHA256 (RFC 5869).

    Args:
        ikm: Input key material.
        salt: HKDF salt. ``None`` means 32 zero bytes.
        info: HKDF context string.
        length: Number of output bytes.

    Returns:
        ``length`` bytes of derived key material.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    ).derive(ikm)


def derive_register(shared: bytes) -> RegisterSecrets:
    """Derive the register secrets from the ECDH shared secret.

    Uses HKDF with no salt and ``SETUP_INFO``. The 64-byte output is split
    as token ``[0:12]``, bind_key ``[12:28]`` and a_key ``[28:44]``.

    Args:
        shared: The ECDH shared secret from the register exchange.

    Returns:
        The derived secrets.
    """
    # salt=None is bit-identical to Mi Home's no-OOB 16-zero-byte salt
    # (RFC 5869: an absent salt is 32 zero bytes for SHA-256, and HMAC
    # zero-pads any short key to its 64-byte block, so both keys match).
    out = hkdf(shared, salt=None, info=SETUP_INFO, length=64)
    return RegisterSecrets(token=out[0:12], bind_key=out[12:28], a_key=out[28:44])


def derive_login(token: bytes, app_rand: bytes, dev_rand: bytes) -> SessionKeys:
    """Derive the session keys for one login.

    Uses HKDF with salt ``app_rand || dev_rand`` and ``LOGIN_INFO``. The
    64-byte output is split as dev_key ``[0:16]``, app_key ``[16:32]``,
    dev_iv ``[32:36]`` and app_iv ``[36:40]``.

    Args:
        token: The 12-byte token from the register step.
        app_rand: The random value that the app sent.
        dev_rand: The random value that the charger sent.

    Returns:
        The session keys.
    """
    salt = app_rand + dev_rand
    out = hkdf(token, salt=salt, info=LOGIN_INFO, length=64)
    return SessionKeys(
        dev_key=out[0:16],
        app_key=out[16:32],
        dev_iv=out[32:36],
        app_iv=out[36:40],
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Calculate HMAC-SHA256.

    Args:
        key: The HMAC key.
        data: The message.

    Returns:
        The 32-byte MAC.
    """
    mac = HMAC(key, hashes.SHA256(), backend=default_backend())
    mac.update(data)
    return mac.finalize()


# ------------------------------------------------------------------ additions

def ccm_encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes, *, tag_length: int = 4) -> bytes:
    """Encrypt with AES-CCM and an explicit tag length.

    The tag length is a parameter so that RFC 3610 test vectors can use it.

    Args:
        key: AES key (16, 24 or 32 bytes).
        nonce: CCM nonce (7 to 13 bytes).
        data: Plaintext.
        aad: Additional authenticated data.
        tag_length: Tag length in bytes. Default is 4.

    Returns:
        The ciphertext followed by the tag.
    """
    return AESCCM(key, tag_length=tag_length).encrypt(nonce, data, aad)


def normalize_did(did: bytes | str) -> bytes:
    """Normalize a DID to the 20-byte field used in the v2 bind blob.

    Mirrors the APK helpers exactly:
    ``b23.OooO`` (cutBeforeBytes) strips *leading 0x00 bytes*, then
    ``b23.OooOOO`` (fillBeforeBytes) left-pads with 0x00 to 20 bytes.
    For a 19-character numeric DID the net result is ``0x00 || 19 ASCII``.

    Args:
        did: The DID as ASCII text or as raw bytes.

    Returns:
        The 20-byte DID field.

    Raises:
        ValueError: If the DID is longer than 20 bytes after the strip.
    """
    raw = did.encode("ascii") if isinstance(did, str) else bytes(did)
    stripped = raw
    for i, b in enumerate(stripped):
        if b != 0x00:
            stripped = stripped[i:]
            break
    else:
        stripped = b""  # all zero bytes -> empty (matches cutBeforeBytes)
    if len(stripped) > 20:
        raise ValueError(
            f"DID is {len(stripped)} bytes after stripping; maximum is 20"
        )
    return stripped.rjust(20, b"\x00")


def build_bind_blob(did20: bytes, cloud_sign: bytes, utc: int, a_key: bytes) -> bytes:
    """Build the 92-byte code-0 bind blob (88-byte plaintext + 4-byte CCM tag).

    Plaintext layout (buildEncryptData L1034-1048):
    ``normalizeDID(serverDID)[20] || decode(cloud_sign)[64] || utc_le[4]``.

    Args:
        did20: The 20-byte DID field from ``normalize_did``.
        cloud_sign: The 64-byte signature from the cloud, already decoded.
        utc: UNIX time in seconds, 1 to 0xFFFFFFFF.
        a_key: The 16-byte a_key from ``derive_register``.

    Returns:
        The 92-byte encrypted blob.

    Raises:
        ValueError: If a length or ``utc`` is out of range.
    """
    if len(did20) != 20:
        raise ValueError(f"DID field must be 20 bytes, got {len(did20)}")
    if len(cloud_sign) != 64:
        raise ValueError(f"cloud_sign must decode to 64 bytes, got {len(cloud_sign)}")
    if not 0 < utc <= 0xFFFFFFFF:
        raise ValueError(f"utc out of range: {utc}")
    plaintext = did20 + cloud_sign + utc.to_bytes(4, "little")
    if len(plaintext) != 88:
        raise AssertionError("bind blob plaintext must be 88 bytes")
    return ccm_encrypt(a_key, BLOB_NONCE, plaintext, BLOB_AAD, tag_length=BLOB_TAG_LENGTH)


@dataclass(frozen=True)
class DevInfo:
    """Parsed v2 device-info parcel (the 24-byte blob from GET_INFO).

    Attributes:
        version: Auth version (u16 LE). The value is 3 or less.
        caps_in_out: byte[2]. Bits 0-3 are input caps, bits 4-7 are output caps.
        caps2: byte[3]. The second capability byte, echoed in the 0x15 command.
        did_field: The raw DID field as delivered (v2: ``raw[4:24]``).
        factory_did_text: The ASCII DID text without leading zero bytes. The
            app sends this value to ``bltapplydid``.
    """

    version: int
    caps_in_out: int  # byte[2]: bits 0-3 input caps, bits 4-7 output caps
    caps2: int  # byte[3]: second capability byte (echoed in the 0x15 command)
    did_field: bytes  # raw DID field as delivered (v2: raw[4:24])
    factory_did_text: str  # zero-stripped ASCII DID text (what the app sends to bltapplydid)


class DevInfoError(ValueError):
    """The device-info parcel is malformed or not supported."""
    pass


def parse_devinfo(raw: bytes) -> DevInfo:
    """Parse the device-info parcel per recvDeviceInfo (L997-1032).

    v2 layout: ``[0:2] version u16 LE, [2] IO caps, [3] second caps byte,
    [4:24] DID field``. The app aborts on version > 3, rejects input caps
    != 0, and stores the DID as cutBeforeBytes(raw[4:], 0).

    Args:
        raw: The parcel bytes from GET_INFO.

    Returns:
        The parsed device info.

    Raises:
        DevInfoError: If the parcel is shorter than 4 bytes, the version is
            more than 3, or the DID is longer than 20 bytes or has non-digit
            characters.
    """
    data = bytes(raw)
    if len(data) < 4:
        raise DevInfoError(f"device info too short: {len(data)} bytes")
    version = data[0] | (data[1] << 8)
    if version > 3:
        raise DevInfoError(f"device reports unsupported auth version {version}")
    caps_in_out = data[2]
    caps2 = data[3]
    if len(data) > 4:
        if version < 3:
            did_field = data[4:]
        else:
            did_field = data[4:24]
    else:
        did_field = b""
    # cutBeforeBytes semantics: strip leading 0x00 bytes for the text form
    stripped = did_field
    for i, b in enumerate(stripped):
        if b != 0x00:
            stripped = stripped[i:]
            break
    else:
        stripped = b""
    # The DID field is exactly 20 bytes on the wire and the server DIDs are
    # numeric. An over-long, non-ASCII or non-digit value is a malformed
    # parcel. Never send it to the cloud.
    if len(stripped) > 20:
        raise DevInfoError(
            f"device-info DID field is {len(stripped)} bytes; maximum is 20"
        )
    if stripped and not stripped.isdigit():
        raise DevInfoError(
            "device-info DID field contains non-digit characters"
        )
    factory_did_text = stripped.decode("ascii")
    return DevInfo(
        version=version,
        caps_in_out=caps_in_out,
        caps2=caps2,
        did_field=did_field,
        factory_did_text=factory_did_text,
    )
