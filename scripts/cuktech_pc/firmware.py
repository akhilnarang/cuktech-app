"""Read-only AD1204U firmware download and offline inspection.

The cloud session is stored by ``firmware_session``: DPAPI on Windows, a mode
0600 file in ``~/.cuktech_pc`` on Linux and macOS. The password is never stored. This module contains no
Bluetooth or flashing operations.
Protocol sources and observed results: docs/firmware-research.md.
Run: ``uv run -m cuktech_pc.firmware {login,fetch,inspect,status,forget-login}``.
"""

import argparse
import getpass
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time
from urllib.parse import urljoin, urlsplit

from . import cloud, firmware_session

MODELS = {"njcuk.fitting.ad1204": 0x660E, "njcuk.fitting.1204e": 0x8AB9}
MAGIC = bytes.fromhex("000000004d49ef54464f544182562647")
DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "artifacts" / "firmware"


class UserError(ValueError):
    """A problem that the user can fix. The message has no secrets, so the CLI prints it."""


class ChargerNotOnAccount(UserError):
    """No device on the account has the given MAC address."""


def official_download_url(value: str) -> str:
    """Accept only an official Xiaomi HTTPS download URL.

    The host must be ``mi.com``, ``xiaomi.com``, ``mi-img.com`` or
    ``mi-fds.com``, or a subdomain of one. The port must be 443 and the URL
    must not contain user info.

    Args:
        value: The URL to check.

    Returns:
        ``value`` without changes.

    Raises:
        ValueError: If the URL is not an official Xiaomi HTTPS URL.
    """
    p = urlsplit(value)
    host = (p.hostname or "").lower()
    if (p.scheme != "https" or p.port not in (None, 443) or p.username or p.password
            or not any(host == d or host.endswith("." + d)
                       for d in ("mi.com", "xiaomi.com", "mi-img.com", "mi-fds.com"))):
        raise ValueError("firmware requires an official Xiaomi HTTPS URL")
    return value


def inspect_image(blob: bytes) -> dict:
    """Inspect an AD1204U-family R2SF image or signed package offline.

    The function reads the vector table and the hashes. If the image ends
    with a signed-package tag (``MAGIC``), the function also parses the tag
    TLVs and checks the model, product id and version.

    Args:
        blob: The complete file, at least 1024 bytes.

    Returns:
        A dict with ``bytes``, ``md5``, ``sha256``, ``initial_stack``,
        ``reset_vector`` and ``signed_package``. A signed package also adds
        the tag fields, ``model`` and ``version`` (``M.m.r_bbbb``).

    Raises:
        ValueError: If the file is not an R2SF image, or the signed-package
            header, boundaries, TLVs, model or version are not valid.
    """
    if len(blob) < 1024 or blob[40:44] != b"R2SF":
        raise ValueError("not an AD1204U-family R2SF image")
    stack, reset = struct.unpack_from("<II", blob)
    result = {"bytes": len(blob), "md5": hashlib.md5(blob).hexdigest(),
              "sha256": hashlib.sha256(blob).hexdigest(),
              "initial_stack": hex(stack), "reset_vector": hex(reset), "signed_package": False}
    offset = blob.rfind(MAGIC)
    if offset < 0:
        return result
    if offset + 28 > len(blob):
        raise ValueError("truncated signed-package header")
    size, pid, firmware_size, cert_size, flags, _ = struct.unpack_from("<HHIHBB", blob, offset + 16)
    if size < 32 or firmware_size != offset or offset + size + cert_size >= len(blob):
        raise ValueError("invalid signed-package boundaries")
    fields = {}
    cursor, end = offset + 28, offset + size - 4
    while cursor < end:
        if cursor + 2 > end:
            raise ValueError("truncated signed-package TLV")
        kind, length = blob[cursor:cursor + 2]
        if cursor + 2 + length > end or kind in fields:
            raise ValueError("invalid or duplicate signed-package TLV")
        fields[kind] = blob[cursor + 2:cursor + 2 + length]
        cursor += 2 + length
    model = fields.get(4, b"").decode("ascii")
    if model not in MODELS or pid != MODELS[model]:
        raise ValueError("signed package has an unknown model or product ID")
    version = fields.get(1, b"")
    if len(version) != 5:
        raise ValueError("signed package is missing its version")
    major, minor, revision, build = struct.unpack("<BBBH", version)
    result.update(signed_package=True, tag_offset=offset, tag_size=size, product_id=pid,
                  firmware_size=firmware_size, certification_size=cert_size, flags=flags,
                  signature_size=len(blob) - firmware_size - size - cert_size,
                  model=model, version=f"{major}.{minor}.{revision}_{build:04d}")
    return result


def verify_package_signature(blob: bytes, info: dict) -> None:
    """Verify the developer certificate and the image signature.

    This is NOT an independent root of trust. The server certificate comes
    from the package itself. The function checks that it signs the developer
    certificate, and that the developer key signs the image with
    ECDSA-SHA256.

    Args:
        blob: The complete signed package.
        info: The result of ``inspect_image`` for ``blob``.

    Raises:
        ValueError: If the package does not have exactly 2 certificates.
        cryptography.exceptions.InvalidSignature: If a signature is not valid.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    offset = info["firmware_size"] + info["tag_size"]
    end = offset + info["certification_size"]
    certificates = x509.load_pem_x509_certificates(blob[offset:end])
    if len(certificates) != 2:
        raise ValueError("expected server and developer certificates")
    server, developer = certificates
    server.public_key().verify(developer.signature, developer.tbs_certificate_bytes,
                               ec.ECDSA(developer.signature_hash_algorithm))
    developer.public_key().verify(blob[end:], blob[:offset], ec.ECDSA(hashes.SHA256()))


def cached_api(region: str | None = None):
    """Make a cloud API client from the saved session.

    Args:
        region: The expected cloud region, or ``None`` to use the saved one.

    Returns:
        A ``(cloud.MiCloudApi, payload)`` tuple. ``payload`` is the saved
        session dict.

    Raises:
        ValueError: If there is no complete saved session, or ``region`` is
            not the saved region.
    """
    cloud.assert_safe_env()
    payload = firmware_session.load()
    if not payload or not all(payload.get(k) for k in ("user_id", "ssecurity", "service_token", "region")):
        raise UserError("no saved cloud session; run the login command")
    if region and region != payload["region"]:
        raise UserError("the saved login uses a different region")
    session = cloud.new_session()
    for cookie in payload.get("cookies", []):
        session.cookies.set(cookie["name"], cookie["value"], domain=cookie["domain"],
                            path=cookie["path"], secure=cookie["secure"], expires=cookie["expires"])
    auth = cloud.CloudSession(payload["user_id"], payload["ssecurity"], payload["service_token"])
    api = cloud.MiCloudApi(session, auth, region=payload["region"], skew_seconds=payload.get("skew_seconds", 0))
    return api, payload


def find_charger(api, address: str) -> dict:
    """Find the one supported charger on the account that has a given MAC.

    Args:
        api: A ``cloud.MiCloudApi`` client.
        address: The BLE MAC of the charger, in any byte order.

    Returns:
        The device dict from the cloud device list.

    Raises:
        ChargerNotOnAccount: If no device has the MAC address.
        UserError: If there is more than one match, or the match is not a
            supported model.
    """
    candidates = cloud._mac_candidates(address)
    hits = [d for d in api.list_devices() if cloud.normalize_mac(str(d.get("mac", ""))) in candidates]
    if not hits:
        raise ChargerNotOnAccount("the charger is not on this account and region")
    if len(hits) != 1 or hits[0].get("model") not in MODELS:
        raise UserError("expected one matching supported charger on this account and region")
    return hits[0]


def login(args) -> None:
    """Log in to the Xiaomi cloud and save the session and, if found, the charger token.

    Asks for the password with ``getpass``. A captcha image goes to
    ``DEFAULT_OUTPUT/captcha.png``. The password is not saved. The session and
    cookies are saved with ``firmware_session.save``. If the charger is not on
    the account (for example, the app removed it after the bind), the session
    is still saved, and only ``fetch --legacy`` can work.

    Args:
        args: Parsed arguments with ``username``, ``address`` and ``region``.

    Raises:
        ValueError: If the charger token has an unexpected format.
        cloud.CloudError: If the login or the captcha download fails.
    """
    cloud.assert_safe_env()
    username = args.username or input("Xiaomi account: ").strip()
    password = getpass.getpass("Password: ")
    class CaptchaFileAccount(cloud.MiAccount):
        def _fetch_captcha(self, url):
            r = self._get(cloud.abs_account_url(url), stage="captcha fetch", headers=self._headers(),
                          max_bytes=cloud.MAX_CAPTCHA_BYTES)
            if r.status_code != 200:
                raise cloud.CloudError("captcha download failed")
            DEFAULT_OUTPUT.mkdir(parents=True, exist_ok=True)
            path = DEFAULT_OUTPUT / "captcha.png"
            if path.is_symlink():
                raise cloud.CloudError("captcha destination must not be a symlink")
            path.write_bytes(r.content)
            print(f"Captcha image: {path}")
            return input("Captcha characters: ").strip()

    account = CaptchaFileAccount(session=cloud.new_session(), hidden_input=getpass.getpass, diagnostic_mode=True)
    try:
        auth = account.login(username, password)
    finally:
        password = None
    api = cloud.MiCloudApi(account.session, auth, region=args.region, skew_seconds=account._skew_seconds)
    try:
        device = find_charger(api, args.address)
    except ChargerNotOnAccount:
        device = None
        print("The charger is not on this account. Only 'fetch --legacy' (raw image by model) can work.")
    charger = {}
    if device is not None:
        token = str(device.get("token") or "").lower()
        if not re.fullmatch("[0-9a-f]{24}", token):
            raise ValueError("charger token has an unexpected format")
        charger = {"address": str(device["mac"]), "model": str(device["model"]),
                   "did": str(device["did"]), "token_hex": token}
    payload = {"schema": 1, "saved_at": time.time(), "region": args.region,
               "username_tag": hashlib.sha256(username.strip().lower().encode()).hexdigest(),
               "user_id": auth.user_id, "service_token": auth.service_token, "ssecurity": auth.ssecurity,
               "device_id": account.device_id, "agent": account.agent, "skew_seconds": account._skew_seconds,
               "charger": charger,
               "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
                            "secure": c.secure, "expires": c.expires}
                           for c in account.session.cookies if c.name in
                           {"userId", "cUserId", "serviceToken", "yetAnotherServiceToken", "deviceId", "sdkVersion", "passToken"}]}
    firmware_session.save(payload)
    print(f"Saved the cloud session to {firmware_session.location()}. No password was saved.")


def fetch(args) -> None:
    """Download the latest official firmware for the saved charger and verify it.

    The function asks the cloud for the latest version, downloads the file
    without account cookies (4 redirects maximum, 8 MiB maximum), and checks
    the MD5. For a signed package it also checks the model, version and
    signatures. It writes ``<model>-<version>-{raw,signed}.bin`` and a
    ``.json`` metadata file. It does not install the firmware.

    Args:
        args: Parsed arguments with ``address``, ``region``, ``legacy``,
            ``model`` and ``output``.

    Raises:
        ValueError: If a metadata, URL, size, checksum or signature check
            fails, the destination is a symlink or a different file, or the
            signed package is asked for but the charger is not on the account.
    """
    api, saved = cached_api(args.region)
    address = args.address or (saved.get("charger") or {}).get("address")
    device = None
    if address:
        try:
            device = find_charger(api, address)  # Validate the saved login and current account ownership.
        except ChargerNotOnAccount:
            if not args.legacy:
                raise
    if device is None:
        if not args.legacy:
            raise UserError("the signed package needs the charger on this account; use --legacy for the raw image")
        device = {"model": getattr(args, "model", None) or "njcuk.fitting.ad1204"}
    path, body = (("/home/latest_version", {"model": device["model"]}) if args.legacy
                  else ("/v2/device/latest_ver", {"did": str(device["did"])}))
    response = api.encrypted_post(path, json.dumps(body, separators=(",", ":")))
    if response.get("code") != 0 or not isinstance(response.get("result"), dict):
        raise ValueError("Xiaomi did not offer a firmware package")
    data = response["result"]
    version, expected = str(data.get("version", "")), str(data.get("md5", "")).lower()
    if not re.fullmatch(r"\d+\.\d+\.\d+_\d+", version) or not re.fullmatch("[0-9a-f]{32}", expected):
        raise ValueError("firmware metadata is incomplete")
    url = official_download_url(str(data.get("safe_url") or data.get("url") or ""))
    session = cloud.new_session()  # Never forward account cookies to the CDN.
    blob = None
    for _ in range(4):
        with session.get(url, timeout=(10, 30), stream=True, allow_redirects=False) as r:
            if r.status_code in (301, 302, 303, 307, 308):
                url = official_download_url(urljoin(url, r.headers.get("Location", "")))
                continue
            r.raise_for_status()
            chunks, size = [], 0
            for chunk in r.iter_content(65536):
                size += len(chunk)
                if size > 8 * 1024 * 1024:
                    raise ValueError("firmware package is too large")
                chunks.append(chunk)
            blob = b"".join(chunks)
            break
    if blob is None or hashlib.md5(blob).hexdigest() != expected:
        raise ValueError("firmware download did not match Xiaomi's checksum")
    inspection = inspect_image(blob)
    if inspection.get("signed_package"):
        if inspection["model"] != device["model"] or inspection["version"] != version:
            raise ValueError("signed-package model/version does not match account metadata")
        verify_package_signature(blob, inspection)
        inspection["developer_and_image_signature_verified"] = True
    elif not args.legacy:
        raise ValueError("the modern firmware endpoint did not return a signed package")
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    name = f"{device['model']}-{version}-{'raw' if args.legacy else 'signed'}.bin"
    target = out / name
    if out.is_symlink() or target.is_symlink():
        raise ValueError("firmware destination must not be a symlink")
    if target.exists() and target.read_bytes() != blob:
        raise ValueError("the tool does not replace a different existing firmware file")
    target.write_bytes(blob)
    parsed = urlsplit(url)
    metadata = {**inspection, "source": f"https://{parsed.netloc}{parsed.path}", "api_path": path,
                "changelog": str(data.get("changeLog", "")), "md5_verified": True}
    target.with_suffix(".json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Downloaded and verified {version}: {target}")
    print("SHA-256: " + inspection["sha256"])


def main() -> int:
    """Run the command-line entry point.

    Errors print only the exception type, because HTTP errors can contain
    credentials in URLs.

    Returns:
        The process exit code: 0 on success, 1 on error or cancel.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("login", help="sign in and save the cloud session (DPAPI on Windows, mode 0600 file elsewhere)")
    p.add_argument("--username", default="")
    p.add_argument("--address", required=True)
    p.add_argument("--region", choices=cloud.SERVERS, default="cn")
    p = commands.add_parser("fetch", help="download official firmware (the tool does not install it)")
    p.add_argument("--address")
    p.add_argument("--region", choices=cloud.SERVERS)
    p.add_argument("--legacy", action="store_true", help="inspect the legacy raw image instead of the signed package")
    p.add_argument("--model", choices=sorted(MODELS), default="njcuk.fitting.ad1204",
                   help="model for --legacy when the charger is not on the account (else the charger's own model is used)")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT))
    p = commands.add_parser("inspect", help="inspect a downloaded file offline")
    p.add_argument("file", type=Path)
    commands.add_parser("status", help="show if private session/token material exists (not its values)")
    commands.add_parser("forget-login", help="remove cloud credentials and keep the charger token")
    args = parser.parse_args()
    try:
        if args.command == "login": login(args)
        elif args.command == "fetch": fetch(args)
        elif args.command == "inspect":
            info = inspect_image(args.file.read_bytes())
            if info.get("signed_package"):
                verify_package_signature(args.file.read_bytes(), info)
                info["developer_and_image_signature_verified"] = True
            print(json.dumps(info, indent=2))
        elif args.command == "status":
            p = firmware_session.load() or {}
            print(json.dumps({"cloud_session_saved": bool(p.get("service_token")),
                              "charger_token_saved": bool(p.get("charger", {}).get("token_hex")),
                              "region": p.get("region")}))
        elif args.command == "forget-login":
            p = firmware_session.load()
            if p:
                firmware_session.save({"schema": 1, "region": p.get("region"), "charger": p.get("charger", {})})
            print("Cloud login forgotten; the charger token was kept.")
        return 0
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 1
    except (UserError, firmware_session.SessionStoreError) as exc:
        print(f"Firmware operation failed: {exc}. No charger settings were changed.", file=sys.stderr)
        return 1
    except Exception as exc:
        # Exceptions from HTTP libraries can contain URLs and credential-bearing queries.
        print(f"Firmware operation failed ({type(exc).__name__}). No charger settings were changed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
