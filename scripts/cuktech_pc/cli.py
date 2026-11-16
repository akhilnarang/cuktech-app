"""CLI for the one-time cloud-assisted bind of an AD1204U charger. Mi Home is not used.

Run one command at a time. An import of this module does nothing:

    uv run -m cuktech_pc.cli scan [--duration 10]
    uv run -m cuktech_pc.cli setup [--username U] [--region cn] [--address AA:..]
                                    [--journal PATH] [--dry-run]
    uv run -m cuktech_pc.cli status [--journal PATH]
    uv run -m cuktech_pc.cli export-token [--journal PATH] [--output PATH] [--force]
    uv run -m cuktech_pc.cli fetch-token [--username U] [--region R] [--address MAC]
    uv run -m cuktech_pc.cli diagnose-login [--username U]
    uv run -m cuktech_pc.cli forget-login [--session-cache PATH]
    uv run -m cuktech_pc.cli remove-device --did DID [--session-cache PATH]

Safety properties:

- Typed-MAC consent comes BEFORE a charger write, the ECDH exchange, or a
  cloud mutation. The consent needs only the advertisement identity.
- After the charger goes into the key-exchange state, an unexpected
  interruption writes ``0x14`` exactly one time (phase guard). Thus the
  charger is never silently left in pending-bind.
- An intent record goes into the journal BEFORE each cloud mutation. Thus
  an interrupted call is never mistaken for "cloud never called".
- A fresh start ARCHIVES the old journal and does not delete it. A resume
  is pinned to the charger MAC in the journal.
- export-token does not replace a different token file. It does so only
  with ``--force`` and a typed confirmation.
- Verification has three results: verified, rejected, inconclusive. An
  inconclusive result never causes a restart.
- Credentials come only through getpass. The 2FA code is hidden too.
- Proxy variables (any case) and SSLKEYLOGFILE are refused.
- A fatal error prints one sanitized stage line. It never prints a
  traceback or a URL, because the password hash is in a query string.
- The model string comes only from the live pid mapping. The FE95 smac
  must match the selected address byte by byte.
"""


import argparse
import asyncio
import base64
import getpass
import json
import logging
import sys
from pathlib import Path

from . import cloud, crypto, journal as journal_mod
from . import sessioncache
from .out import confirm, panel, print  # noqa: A004 — rich-backed
from .blebind import (
    MiAuthError,
    MiAuthInvalidTokenError,
    MiAuthNotRegisteredError,
    V2RegisterClient,
    scan_for_ad1204u,
)
from .cloud import normalize_mac
from .fe95 import PID_MODEL_HINTS, smac_matches_address
from .journal import BindJournal, JournalState, recovery_instructions, resume_action

LOGGER = logging.getLogger(__name__)

DEFAULT_JOURNAL = Path.home() / ".cuktech_pc" / "journal.json"
DEFAULT_TOKEN_OUT = Path.home() / ".cuktech_ble.token"
# authenticated-session cache (never the password) — see sessioncache.py
DEFAULT_SESSION_CACHE = Path.home() / ".cuktech_pc" / "cloud-session.json"

MODEL_NAME_PREFIX = "njcuk.fitting."

VERIFIED = "verified"
REJECTED = "rejected"
INCONCLUSIVE = "inconclusive"
# the device answered e0 = ERR_NOT_REGISTERED (exact SDK code) —
# it holds no binding, so the persisted token can never log in. Treated
# like REJECTED for restart purposes (typed consent + archive first), but
# a fresh bind additionally requires a live unregistered advertisement.
NOT_REGISTERED = "not-registered"

_ACTIVE_JOURNAL: Path | None = None

# The exceptions that the bind phase of cmd_setup catches to write 0x14 or
# to record an unknown outcome. Ctrl-C arrives as KeyboardInterrupt or as
# asyncio.CancelledError. Other BaseException types (SystemExit,
# GeneratorExit, the IO guard of the test harness) are not caught.
_SETUP_ABORTS = (Exception, KeyboardInterrupt, asyncio.CancelledError)


# ------------------------------------------------------------------- helpers


def _configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    # never let HTTP/transport debug logs appear (they print headers with
    # serviceToken cookies); our own loggers never log frame contents
    for name in ("urllib3", "requests", "bleak", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _print_journalsafe(state: JournalState) -> None:
    print(f"  journal        : {_ACTIVE_JOURNAL or '-'}")
    print(f"  device         : {state.mac} ({state.model or 'unknown model'})")
    print(f"  factory DID    : {state.factory_did or '-'}")
    print(f"  server DID     : {state.server_did or '-'}")
    print(f"  stage          : {state.stage}")
    print(f"  device committed: {state.device_committed}")
    print(f"  cloud bind     : {state.cloud_bind}")
    print(f"  bound verified : {'yes' if state.bound_verified else 'no'}")
    print(
        f"  token          : "
        f"{'present (24 hex chars)' if state.token_hex else 'absent'}"
    )
    print(f"  attempts so far: {len(state.attempts)}")


def request_consent(
    *,
    address: str,
    model: str,
    user_id: str,
    identity_note: str = "",
) -> bool:
    """Show the bind summary and ask for consent.

    This is the hard gate before a charger write, the ECDH exchange, or a
    cloud mutation. It uses only the advertisement identity. It needs no
    charger pubkey and no token derivation.

    Args:
        address: BLE MAC address of the charger.
        model: Model name from the pid mapping.
        user_id: Xiaomi account user ID to show.
        identity_note: Optional extra line about the charger identity.

    Returns:
        True if the user gave consent, else False.
    """
    lines = [
        f"account  {user_id}",
        f"device   {address} ({model})",
    ]
    if identity_note:
        lines.append(f"         {identity_note}")
    lines += [
        "",
        "This will:",
        "  1. connect to the charger and run the BLE binding exchange",
        "  2. call Xiaomi cloud bltapplydid + ble_standard_bind (account changes)",
        "  3. write binding data to the charger",
        "",
        "To undo: factory-reset the charger and run remove-device. The tool does not do this automatically.",
    ]
    panel("Bind this charger to your Xiaomi account", lines)
    return confirm("Bind now?")


# ------------------------------------------------------------------ commands


async def cmd_scan(args: argparse.Namespace) -> int:
    """Run the ``scan`` command: list AD1204U-family chargers. Read-only.

    Args:
        args: Parsed arguments. Uses ``duration`` (seconds).

    Returns:
        Exit code 0.
    """
    hits = await scan_for_ad1204u(args.duration)
    if not hits:
        print("no AD1204U-family (FE95 pid 0x660E CN / 0x8AB9 overseas) "
              "advertisements found")
        return 0
    print(f"{'#':>2}  {'address':<20} {'name':<24} {'pid':<7} "
          f"{'smac':<20} {'reg':<4} {'sol':<4} rssi")
    for i, hit in enumerate(hits):
        f = hit.frame
        print(
            f"{i:>2}  {hit.address:<20} {hit.name or '-':<24} "
            f"{f.product_id_hex or '?':<7} {f.mac_address or '-':<20} "
            f"{'yes' if f.registered else 'no':<4} "
            f"{'yes' if f.solicited else 'no':<4} {hit.rssi}"
        )
    print()
    print("reg=yes means that the device already has a binding. Factory-reset")
    print("the charger before a new bind. Give the selected address to setup.")
    return 0


async def verify_token_login(
    address: str,
    token: bytes,
    journal: BindJournal,
    state: JournalState,
) -> str:
    """Do an offline token login on a new connection and record the result.

    The result goes into the journal. BLE and auth errors do not raise.

    Args:
        address: BLE MAC address of the charger.
        token: Pairing token, 12 bytes.
        journal: The journal that records the result.
        state: The journal state to update.

    Returns:
        One of these values:

        - ``VERIFIED``: the login passed.
        - ``REJECTED``: the charger refused the token.
        - ``NOT_REGISTERED``: the charger answered e0. It holds no binding.
        - ``INCONCLUSIVE``: no verdict (connect or protocol failure). This
          is never a reason to restart.
    """
    from .blebind import connect

    try:
        client = await connect(address)
    except Exception as exc:  # noqa: BLE001 — BLE transport errors
        journal.record_verify_inconclusive(state, f"connect failed: {type(exc).__name__}")
        return INCONCLUSIVE
    try:
        # ha-cuk-ble's hardware-proven login order (and the Android
        # controller's): real MTU, AVDTP only, greet, THEN UPNP, login
        backend = getattr(client, "_backend", None)
        if hasattr(backend, "_acquire_mtu"):
            try:
                await backend._acquire_mtu()
            except Exception:  # noqa: BLE001 — falls back to 18-B chunks
                LOGGER.debug("_acquire_mtu failed", exc_info=True)
        reg = V2RegisterClient(client, timeout=8.0)
        await reg.subscribe(upnp=False)
        try:  # not `async with`: its __aenter__ would subscribe UPNP early
            try:
                await reg.greet()
            except MiAuthNotRegisteredError:
                # e0 can arrive during greeting on some firmwares; same
                # typed classification as during login
                journal.record_verify_failed(state, "device reports e0 (not registered)")
                return NOT_REGISTERED
            except MiAuthError:
                LOGGER.debug("greeting skipped/failed; continuing to login")
            await reg.subscribe()  # UPNP, after the greeting
            try:
                await reg.login(token)
            except MiAuthNotRegisteredError:
                journal.record_verify_failed(
                    state, "device reports e0 (not registered)"
                )
                return NOT_REGISTERED
            except MiAuthInvalidTokenError:
                journal.record_verify_failed(
                    state, "device rejected the persisted token"
                )
                return REJECTED
            except MiAuthError as exc:
                journal.record_verify_inconclusive(
                    state, f"login error: {exc}"
                )
                return INCONCLUSIVE
        finally:
            await reg.unsubscribe()
        journal.record_bound_verified(state)
        return VERIFIED
    except Exception as exc:  # noqa: BLE001
        journal.record_verify_inconclusive(
            state, f"verification error: {type(exc).__name__}"
        )
        return INCONCLUSIVE
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass


async def _abort_pre_confirm(
    reg: V2RegisterClient,
    phase: dict,
    journal: BindJournal,
    state: JournalState | None,
    why: str,
) -> None:
    """Pre-confirm abort: 0x14 exactly once (cloud-failure handler)."""
    if phase.get("sent_0x14") or not phase.get("device_pending"):
        return
    try:
        await reg.write_bind_result(False)
        phase["sent_0x14"] = True
        print(f"wrote 0x14 ({why}). The device now exits its pending-bind state.")
    except Exception as exc:  # noqa: BLE001
        if state is not None:
            journal.record_unknown_outcome(state, f"0x14 write failed: {exc}")


async def _consented_fresh_restart(
    args: argparse.Namespace,
    journal: BindJournal,
    state: JournalState,
    *,
    require_unregistered_advert: bool,
) -> int:
    """Typed-consent fresh-restart path.

    Guards before any consent is even asked (a bound device never reaches
    the prompt); then typed MAC consent; then the old journal is ARCHIVED
    (every fresh restart, even when cloud was never called) and the caller
    continues with a blank state.
    Returns 0 to signal "continue with a fresh bind", 1 to abort.
    """
    if require_unregistered_advert:
        # a live advertisement of the pinned device must show registered=no
        print(f"scanning for {state.mac} to make sure that it is not bound...")
        hits = await scan_for_ad1204u(args.scan_duration)
        live = [
            h for h in hits
            if normalize_mac(h.address) == normalize_mac(state.mac)
        ]
        if not live:
            print("the device does not advertise. No state was changed. Move the "
                  "charger near and run the command again.")
            return 1
        if live[0].frame.registered:
            print("the device now advertises as REGISTERED (bound). It "
                  "has a binding that is not in this journal. "
                  "No state was changed. Factory-reset the charger (see "
                  "its manual) before a fresh bind.")
            return 1
        print("the live advertisement shows that the device is not registered")
    panel("Start a fresh bind?", [
        f"device   {state.mac}",
        "",
        "The tool makes new keys and sends the cloud calls again.",
        "The old journal is archived. It is not deleted.",
    ])
    if not confirm("Start a fresh bind?"):
        print("stopped. No cloud or device action was done.")
        return 1
    # every fresh restart archives the old journal: secrets and
    # attempt history are never lost, even when cloud was never called
    archived = journal.archive("typed fresh-bind consent")
    print(f"old journal archived at {archived} (not deleted)")
    return 0


async def _fresh_restart_and_continue(
    args: argparse.Namespace,
    journal: BindJournal,
    state: JournalState,
    *,
    require_unregistered_advert: bool,
) -> int:
    """Consent gate + archive, then re-enter cmd_setup with a clear journal."""
    rc = await _consented_fresh_restart(
        args, journal, state,
        require_unregistered_advert=require_unregistered_advert,
    )
    if rc != 0:
        return rc
    # the journal file still exists (archive keeps a copy; the original is
    # only replaced when the new bind derives secrets). Remove the original
    # now so the re-entered setup sees a clean state and pins nothing.
    try:
        journal.path.unlink()
    except OSError:
        pass
    return await cmd_setup(args)


def _is_confirmed_auth_rejection(exc: cloud.CloudError) -> bool:
    """True only for a DEFINITE auth rejection — HTTP 401 from the /app
    envelope. Transient failures (timeouts, DNS, 5xx, network errors)
    must never be treated as an expired session (they keep the cache)."""
    return "HTTP 401" in str(exc)


async def cmd_forget_login(args: argparse.Namespace) -> int:
    """Run the ``forget-login`` command: delete ONLY the saved-login cache.

    The binding journal, token exports, archives and account entries do not
    change. No cloud request is sent.

    Args:
        args: Parsed arguments. Uses ``session_cache`` (path).

    Returns:
        Exit code: 0 if the cache was removed or did not exist, 1 on error.
    """
    cloud.assert_safe_env()
    cache_path = Path(args.session_cache)
    try:
        removed = sessioncache.forget_session(cache_path)
    except sessioncache.SessionCacheError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if removed:
        print(f"removed {cache_path} (the saved Xiaomi login). The binding "
              "journal, the tokens and the account entries did not change.")
    else:
        print(f"no saved login at {cache_path}")
    return 0


async def cmd_remove_device(args: argparse.Namespace) -> int:
    """Run the ``remove-device`` command: remove ONE device entry from the account.

    Use it for the half-bound entry of a failed bind. It uses the saved
    login and asks for consent. The binding journal does not change. The
    charger keeps its binding.

    Args:
        args: Parsed arguments. Uses ``did`` and ``session_cache``.

    Returns:
        Exit code: 0 if the entry is removed or is not on the account,
        1 if there is no usable login, no consent, or the entry stays.
    """
    cloud.assert_safe_env()
    try:
        cached = sessioncache.load_session(Path(args.session_cache))
    except sessioncache.SessionCacheError as exc:
        print(f"saved login unusable: {exc}")
        return 1
    if cached is None:
        print("no saved login. Run setup one time to sign in first.")
        return 1
    session_obj = cloud.new_session()
    sessioncache.restore_request_environment(session_obj, cached)
    api = cloud.MiCloudApi(session_obj, cached.to_cloud_session(),
                           region=cached.region,
                           skew_seconds=cached.skew_seconds)
    devs = await asyncio.to_thread(api.list_devices)
    match = [d for d in devs if str(d.get("did", "")) == args.did]
    if not match:
        print(f"{args.did} is not on the account. There is nothing to remove.")
        return 0
    dev = match[0]
    try:
        pid = int(dev.get("pid"))
    except (TypeError, ValueError):
        print(f"the account entry has no usable pid ({dev.get('pid')!r}). "
              "The tool does not guess a pid.")
        return 1
    panel("Remove from Xiaomi account", [
        f"account  {cached.user_id}",
        f"did      {args.did}",
        f"device   {dev.get('name')} ({dev.get('model')})",
        f"mac      {dev.get('mac')}",
        "",
        "The charger keeps its binding. Only the account entry is removed.",
    ])
    if not confirm("Remove it?"):
        print("no consent. Nothing was changed.")
        return 1
    await asyncio.to_thread(api.remove_device, args.did, pid)
    devs = await asyncio.to_thread(api.list_devices)
    if any(str(d.get("did", "")) == args.did for d in devs):
        print("the server accepted the request, but the device is still "
              "on the list. Check again after one minute.")
        return 1
    print(f"removed {args.did} from the account")
    return 0


async def cmd_setup(args: argparse.Namespace) -> int:
    """Run the ``setup`` command: the interactive, consent-gated one-time bind.

    If a journal exists, setup first verifies the saved token offline. It
    restarts only after typed consent. The module docstring gives the
    safety properties.

    Args:
        args: Parsed arguments. Uses ``username``, ``region``, ``address``,
            ``journal``, ``session_cache``, ``scan_duration``, ``dry_run``.

    Returns:
        Exit code: 0 after a verified bind (or a dry run), else 1.
    """
    global _ACTIVE_JOURNAL
    cloud.assert_safe_env()
    journal = BindJournal(args.journal)
    _ACTIVE_JOURNAL = journal.path

    state = journal.load()  # JournalError -> instructions, never clobber
    pinned_address = ""
    if args.address and state and normalize_mac(state.mac) != normalize_mac(args.address):
        print(
            f"journal holds device {state.mac}, but --address is "
            f"{args.address}. Fix the old journal manually "
            f"({journal.path}) or remove --address."
        )
        return 1
    if state:
        # a resume is pinned to the journalled device — the scan may
        # never pick a different charger and overwrite this journal.
        pinned_address = state.mac

    action, reason = resume_action(state)
    print(f"resume decision: {action} ({reason})")

    if args.dry_run:
        print("dry-run: the tool does no network, BLE or account action.")
        print("phases that the tool will run:")
        if action == "fresh":
            print("  1. cloud login (password + captcha/2FA prompts)")
            print("  2. device-list guard (abort if the MAC is on the account)")
            print("  3. BLE scan/select + bound-guard (FE95 registered bit)")
            print("  4. typed-MAC consent gate (BEFORE connecting)")
            print("  5. connect, GET_INFO, caps echo, ECDH pubkey exchange")
            print("  6. journal stage 'derived' (persist secrets)")
            print("  7. cloud: bltapplydid, ble_standard_bind (mutations;")
            print("     intent journalled before each call)")
            print("  8. BLE: 0x13, code-0 blob (92 B), code-7 cert, await 0x11")
            print("  9. fresh-connection offline token login to verify")
        elif action == "verify-only":
            print("  1. offline token login with the persisted token")
        else:  # verify-first
            print("  1. offline token login with the persisted token")
            print("  2. verified: done. rejected: fresh restart only with")
            print("     typed consent (old journal archived). inconclusive:")
            print("     try again later. The tool does not restart automatically.")
        return 0

    # ------------------------------------------------- resume: verify first
    if state and action in ("verify-only", "verify-first"):
        print(f"verifying existing binding for {state.mac} (offline login)...")
        status = await verify_token_login(
            state.mac, bytes.fromhex(state.token_hex), journal, state
        )
        if status == VERIFIED:
            print("SUCCESS: the charger is already bound. The persisted "
                  "token logs in offline. No cloud or device writes were made.")
            print("next: uv run -m cuktech_pc.cli export-token")
            return 0
        if status == INCONCLUSIVE and action == "verify-first" \
                and not state.cloud_sign_b64:
            # the cloud signature never arrived, so 0x13/the bind blob were
            # never sent: the device cannot hold this journal's binding.
            # An unbound charger may just stay silent on login (live
            # 2026-10-12), so offer the gated fresh restart (live
            # unregistered advert + typed consent + archive)
            print("verification was INCONCLUSIVE. The previous run did not "
                  "receive the cloud signature. Thus the charger did not get "
                  "the command to commit this binding.")
            return await _fresh_restart_and_continue(
                args, journal, state, require_unregistered_advert=True,
            )
        if status == INCONCLUSIVE:
            # never a rejection, never a restart trigger
            print("verification was INCONCLUSIVE. The tool did not reach the "
                  "device, or the device did not finish the login. Nothing was changed.")
            print("  1. Make sure that the charger has power and is near.")
            print("  2. Make sure that no other client (phone app) is connected to it.")
            print("  3. Run again: uv run -m cuktech_pc.cli setup")
            print("  To see the journal at any time: cuktech_pc.cli status")
            print("  WARNING: Do NOT delete the journal. It can hold the only")
            print("  copy of the pairing token.")
            return 1
        if status == NOT_REGISTERED:
            # the device answered e0 (ERR_NOT_REGISTERED) — it holds
            # no binding, so this journal's token can never work. A fresh
            # bind needs: a LIVE unregistered advertisement + the account
            # device-list guard + typed consent + archive. Never automatic.
            print("the device reports ERR_NOT_REGISTERED (e0). It has no "
                  "binding. Thus the persisted token cannot log in.")
            if action == "verify-only":
                print(recovery_instructions(state))
                return 1
            print("a fresh bind is possible, but only with your explicit consent")
            return await _fresh_restart_and_continue(
                args, journal, state, require_unregistered_advert=True,
            )
        print("offline login with the persisted token was REJECTED by the device.")
        if action == "verify-only":
            print(recovery_instructions(state))
            return 1
        # cloud state may exist (incl. a pending intent) — explicit consent
        # only, never automatic
        return await _fresh_restart_and_continue(
            args, journal, state, require_unregistered_advert=False,
        )

    # ---------------------------------------------------------- cloud login
    # The user asked to save credentials for re-use: the authenticated
    # SESSION (never the password) is cached after a successful login, so
    # a re-run after a BLE failure or charger reboot skips
    # username/password/2FA entirely. The cache is SAVED only after the
    # login's identity fields are complete AND an authenticated
    # device_list succeeds (round-6: a login that "completes" without
    # userId produced a 401-bound session — never cache or accept that).
    # asked only when a fresh login is needed; a saved login is used as-is
    # (the consent screen still shows which account it belongs to)
    username = args.username
    cache_path = args.session_cache
    api: cloud.MiCloudApi | None = None

    def _fresh_login_prompt() -> str:
        print(f"password for {username} (input hidden):")
        return getpass.getpass("")

    # try the cached session first (never during diagnostics)
    try:
        cached = sessioncache.load_session(
            Path(cache_path),
            expected_username=username if username else None,
            expected_region=args.region,
        )
    except sessioncache.SessionCacheError as exc:
        # unsafe/corrupt/wrong-account cache: refuse human-safely; the
        # file is the user's own known regular file — tell them, don't
        # delete anything broadly
        print(f"saved login unusable: {exc}")
        print("fix or remove the file yourself, or run: "
              "uv run -m cuktech_pc.cli forget-login")
        return 1

    if cached is not None:
        print("Using saved Xiaomi login")
        session_obj = cloud.new_session()
        sessioncache.restore_request_environment(session_obj, cached)
        api = cloud.MiCloudApi(
            session_obj,
            cached.to_cloud_session(),
            region=cached.region,
            skew_seconds=cached.skew_seconds,
        )
        # validate with the READ-ONLY device list — the same guard as a
        # fresh login; NO password resend, NO mutations
        try:
            await asyncio.to_thread(api.list_devices)
        except cloud.CloudError as exc:
            if not _is_confirmed_auth_rejection(exc):
                # transient (timeout/DNS/server): keep the cache, abort;
                # nothing mutated, journal untouched — just re-run later
                print(f"could not reach Xiaomi cloud to validate the saved "
                      f"login ({exc}). The saved login was KEPT. Run "
                      "setup again when the network is available.")
                return 1
            # confirmed auth failure only: delete the cache (own known
            # regular file) and fall through to one hidden login prompt
            try:
                sessioncache.forget_session(Path(cache_path))
                print("the saved login expired. Sign in again.")
            except sessioncache.SessionCacheError as exc2:
                print(f"could not clear the saved login: {exc2}")
                return 1
            api = None  # the cached api is dead: force the fresh login
        else:
            # cached session validated: continue with it (no login prompt)
            print("Xiaomi login completed (saved session validated)")

    if api is None:
        # fresh (or re-)login: hidden password, hidden 2FA
        username = username or input("Xiaomi account username: ").strip()
        password = _fresh_login_prompt()
        account = cloud.MiAccount(
            session=cloud.new_session(),
            # the emailed 2FA code is a session credential — hidden input
            hidden_input=getpass.getpass,
            captcha_dir=journal.path.parent,
        )
        try:
            session = account.login(username, password)
        finally:
            # drop the password reference as soon as login is done
            password = None
            del password
        if session is None:
            print("login failed")
            return 1
        api = cloud.MiCloudApi(
            account.session, session, region=args.region,
            skew_seconds=account._skew_seconds,
        )
        # ROUND-6 GATE: validate the full account API (read-only
        # device_list) BEFORE saving the cache and BEFORE any BLE work.
        # A serviceToken alone does not prove a usable session.
        try:
            await asyncio.to_thread(api.list_devices)
        except cloud.CloudError as exc:
            print(f"the account API rejected the fresh login "
                  f"({exc}). Nothing was saved or changed.")
            return 1
        # only a fully validated session is persisted (never the password)
        try:
            sessioncache.save_session(
                Path(cache_path),
                session,
                device_id=account.device_id,
                agent=account.agent,
                region=args.region,
                username_tag=sessioncache.username_tag(username),
                skew_seconds=account._skew_seconds,
            )
            print("login saved locally for the next run (to remove it: "
                  "uv run -m cuktech_pc.cli forget-login)")
        except cloud.CloudError as exc:
            # a failed save must not block the bind — just note it
            print(f"could not save the login for the next run: {exc}")
        print("Xiaomi login completed")

    # -------------------------------------------------------- device select
    print(f"scanning {args.scan_duration:.0f}s for AD1204U-family devices...")
    hits = await scan_for_ad1204u(args.scan_duration)
    if not hits:
        print("no matching advertisement found. Make sure that the charger has "
              "power and is near. (CN pid 0x660E / overseas pid 0x8AB9)")
        return 1
    if pinned_address:
        # resume identity — only the journalled device may be used
        hits = [
            h for h in hits
            if normalize_mac(h.address) == normalize_mac(pinned_address)
        ]
        if not hits:
            print(f"the journalled device {pinned_address} does not "
                  "advertise. The journal did NOT change. Move the same "
                  "charger near and run again.")
            return 1
    if args.address:
        hits = [
            h for h in hits
            if normalize_mac(h.address) == normalize_mac(args.address)
        ]
        if not hits:
            print(f"{args.address} does not advertise an AD1204U-family FE95 frame")
            return 1
    if len(hits) == 1:
        hit = hits[0]
    else:
        for i, h in enumerate(hits):
            print(f"  [{i}] {h.address}  {h.name or '-'}  "
                  f"reg={'yes' if h.frame.registered else 'no'}  rssi={h.rssi}")
        idx = input("select device index: ").strip()
        try:
            hit = hits[int(idx)]
        except (ValueError, IndexError):
            print("invalid selection")
            return 1
    frame = hit.frame
    address = hit.address

    # hard guards
    if frame.registered:
        print("FE95 'registered' bit is set. This device already has a "
              "binding. Factory-reset the charger first (see its manual). "
              "This tool does not bind a bound device again.")
        return 1
    if not frame.mac_include or not frame.mac_address:
        print("advertisement has no FE95 MAC (mac_include bit unset). "
              "The tool cannot verify the smac. Move nearer and scan again.")
        return 1
    if not smac_matches_address(frame, address):
        print(
            f"FE95 MAC {frame.mac_address} does not match the selected "
            f"address {address} in either byte order. The tool does not upload "
            "an smac of a different device."
        )
        return 1
    smac = frame.mac_address
    # the model comes ONLY from the live pid mapping — never free text
    model = PID_MODEL_HINTS.get(frame.product_id or -1)
    if not model:
        print(f"FE95 pid {frame.product_id_hex} has no known model mapping. "
              "The tool does not bind an unknown product.")
        return 1
    if hit.name and not hit.name.startswith(MODEL_NAME_PREFIX):
        print(f"advertised name {hit.name!r} does not match the expected "
              f"{MODEL_NAME_PREFIX}* family for pid {frame.product_id_hex}. "
              "The tool does not bind a device that does not match.")
        return 1

    # cloud guard: neither the address nor the smac may already be on the
    # account (raw + byte-reversed forms, both identity addresses)
    if await asyncio.to_thread(api.device_list_contains, address, smac):
        print(f"{address} (or its reversed/smac form) is already on "
              "this account. Do not bind it. Get its token with "
              "ha-cuk-ble/tools/ad1204u_fetch_token.py.")
        return 1

    identity_note = (
        f"pid {frame.product_id_hex}, smac {smac}, "
        f"FE95 registered bit clear"
    )
    print(f"selected {address} ({model}, smac {smac})")

    # --------------------------- consent BEFORE any device write ----
    if not request_consent(
        address=address, model=model, user_id=api.auth.user_id,
        identity_note=identity_note,
    ):
        print("no consent. The tool did only the account login. Nothing was "
              "connected, written or changed.")
        return 1

    # -------------------------------------------- BLE: exchange + journal 1
    from .blebind import connect

    client = await connect(address)
    # phase guard (exact semantics):
    # - ``confirm_started`` flips True immediately BEFORE the first 0x13
    #   write attempt — from that moment on, 0x14 is NEVER sent (the app
    #   never sends it after 0x13; what firmware would do is unknown);
    #   an interrupt there only records unknown-outcome;
    # - before that (post-pubkey pre-confirm cloud phase), an unexpected
    #   exit writes 0x14 exactly once so the device leaves pending-bind;
    # - bind_completed/device_rejected flip BEFORE their journal writes, so
    #   a journal failure after 0x11 can never trigger a 0x14 either.
    phase = {"device_pending": False, "confirm_started": False, "sent_0x14": False,
             "bind_completed": False, "device_rejected": False}
    reg: V2RegisterClient | None = None
    try:
        reg = V2RegisterClient(client, timeout=10.0)
        async with reg:
            devinfo = await reg.get_devinfo()
            print(f"device info: auth v{devinfo.version}, "
                  f"caps {devinfo.caps_in_out:02x}/{devinfo.caps2:02x}, "
                  f"factory DID {devinfo.factory_did_text or '-'}")
            await reg.send_caps_echo(devinfo)
            priv, pub = crypto.generate_keypair()
            phase["device_pending"] = True  # pubkey upload is next
            await reg.send_pubkey(crypto.public_key_to_bytes(pub))
            peer_pub = await reg.recv_peer_pubkey()
            shared = crypto.ecdh_shared(priv, crypto.bytes_to_public_key(peer_pub))
            secrets = crypto.derive_register(shared)

            state = JournalState(
                mac=address, model=model, region=args.region, smac=smac,
                factory_did=devinfo.factory_did_text,
            )
            journal.record_derived(
                state,
                token_hex=secrets.token.hex(),
                bind_key_hex=secrets.bind_key.hex(),
                a_key_hex=secrets.a_key.hex(),
                factory_did=devinfo.factory_did_text,
            )
            print(f"journal stage 'derived' persisted ({journal.path})")

            # ------------------------------------- cloud mutations
            token_hex = secrets.token.hex()
            bind_key_hex = secrets.bind_key.hex()
            try:
                # intent journalled BEFORE the call — an interrupted
                # mutation is never mistaken for "cloud never called"
                journal.record_intent_applydid(state)
                server_did = await asyncio.to_thread(
                    api.applydid, address, model, token_hex,
                    devinfo.factory_did_text,
                )
                journal.record_did_allocated(state, server_did)
                print(f"cloud allocated DID {server_did} "
                      f"(journal stage 'did-allocated')")
                journal.record_intent_bind(state)
                material = await asyncio.to_thread(
                    api.standard_bind, server_did, token_hex, bind_key_hex, smac,
                )
                journal.record_cloud_signed(
                    state,
                    utc=material.utc,
                    cloud_sign_b64=base64.b64encode(material.cloud_sign).decode(),
                    cloud_cert_b64=base64.b64encode(material.cloud_cert).decode(),
                )
                print(f"cloud bind material received (utc {material.utc}, "
                      f"sign 64 B, cert {len(material.cloud_cert)} B; "
                      f"journal stage 'cloud-signed')")
                blob = crypto.build_bind_blob(
                    crypto.normalize_did(server_did),
                    material.cloud_sign,
                    material.utc,
                    secrets.a_key,
                )
            except _SETUP_ABORTS as exc:
                # cloud/validation failed after the pubkey exchange (still
                # pre-confirm): tell the device 0x14 so it exits
                # pending-bind (exact app semantics, M3); never write 0x13
                # on bad material
                if isinstance(exc, KeyboardInterrupt):
                    await _abort_pre_confirm(reg, phase, journal, state, "Ctrl-C")
                    raise
                journal.record_failure(state, "cloud-bind", str(exc))
                print(f"cloud bind failed: {exc}")
                await _abort_pre_confirm(reg, phase, journal, state, "cloud failure")
                print(recovery_instructions(state))
                return 1

            # --------------------------------------- BLE bind writes
            try:
                phase["confirm_started"] = True  # BEFORE the first 0x13 write
                journal.record_device_confirm_pending(state)
                await reg.write_bind_result(True)
                await reg.send_bind_blob(blob)
                await reg.send_cloud_cert(material.cloud_cert)
                outcome = await reg.wait_final()
            except _SETUP_ABORTS as exc:
                # post-0x13: NEVER send 0x14 — only record unknown outcome
                if isinstance(exc, KeyboardInterrupt):
                    journal.record_unknown_outcome(state, "Ctrl-C after 0x13")
                    raise
                journal.record_unknown_outcome(state, f"BLE failure: {exc}")
                print(f"BLE failure during bind: {exc}")
                print(recovery_instructions(state))
                return 1

            if outcome == "ok":
                # flags BEFORE the journal write: a journal failure after
                # 0x11 must not trigger the guard's 0x14
                phase["bind_completed"] = True
                journal.record_device_committed(state)
                print("device confirmed the bind (0x11)")
            elif outcome == "fail":
                # 0x12: the device itself rejected the blob. Mi Home
                # auto-unbinds the cloud entry here — this tool NEVER does.
                phase["device_rejected"] = True
                journal.record_device_rejected(state)
                print("device REJECTED the bind (0x12). The cloud entry "
                      "from this run stays. If you try again, remove it "
                      "manually in the account web UI.")
                print(recovery_instructions(state))
                return 1
            elif outcome == "timeout":
                journal.record_unknown_outcome(
                    state, "no final frame within 15 s (device may or may "
                    "not have committed)"
                )
                print("device sent no response after the certificate upload. "
                      "The commit status is unknown.")
                print(recovery_instructions(state))
                return 1
            else:
                journal.record_unknown_outcome(state, outcome)
                print(f"unexpected device response: {outcome}")
                print(recovery_instructions(state))
                return 1
    except _SETUP_ABORTS as exc:
        # 0x14 only in the pre-confirm window (post-pubkey,
        # pre-0x13), exactly once; never once confirm started, the device
        # committed/rejected, or a 0x14 was already sent.
        if (
            phase["device_pending"]
            and not phase["confirm_started"]
            and not phase["bind_completed"]
            and not phase["device_rejected"]
            and not phase["sent_0x14"]
            and reg is not None
        ):
            try:
                await reg.write_bind_result(False)
                phase["sent_0x14"] = True
                print("interrupted. Wrote 0x14. The device now exits its "
                      "pending-bind state.")
            except Exception:  # noqa: BLE001
                pass
        if isinstance(exc, KeyboardInterrupt):
            raise
        if state is not None:
            journal.record_unknown_outcome(
                state, f"unexpected interruption: {type(exc).__name__}"
            )
        print(f"setup stopped unexpectedly ({type(exc).__name__}). "
              "The journal is kept.")
        print(recovery_instructions(state) if state is not None else
              "no journal was written. There is nothing to recover.")
        return 1
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    # -------------------------------------- offline verification (separate)
    print("verifying: fresh connection + offline token login...")
    status = await verify_token_login(address, secrets.token, journal, state)
    if status == VERIFIED:
        print("SUCCESS: charger bound and verified offline.")
        print("next: uv run -m cuktech_pc.cli export-token")
        return 0
    if status == REJECTED:
        print("device committed (0x11), but offline login failed. The journal "
              "is kept. See the recovery options.")
        print(recovery_instructions(state))
        return 1
    print("verification was INCONCLUSIVE. The device committed 0x11, but "
          "the tool could not check it again. The journal is kept. Run setup "
          "again. Setup verifies first and finishes with no cloud calls.")
    return 1


async def cmd_diagnose_login(args: argparse.Namespace) -> int:
    """Run the ``diagnose-login`` command: ONLY the account login, with a sanitized trace.

    It never scans, binds, or changes the charger or the cloud. All of the
    output is safe to share. It shows no username, userId, URLs, context,
    server free text or credentials. The outcome is only a phase and a
    numeric code. A browser handoff is recorded, but its URL is not printed.

    Args:
        args: Parsed arguments. Uses ``username``. If empty, it is asked.

    Returns:
        Exit code: 0 if the login passed, else 1.
    """
    cloud.assert_safe_env()
    # generic prompt: never echo the account name into shareable output
    username = args.username or input("Xiaomi account username: ").strip()
    password = getpass.getpass("password (input hidden): ")
    inner = cloud.new_session()
    diag = cloud.DiagnosticSession(inner)
    account = cloud.MiAccount(
        diag,
        hidden_input=getpass.getpass,
        captcha_dir=None,
        diagnostic_mode=True,
    )
    outcome = "failure phase=login code=unknown"
    try:
        account.login(username, password)
        # no userId in the outcome — success is just success
        outcome = "success"
        rc = 0
    except cloud.CloudError as exc:
        # no server free text — classify by type only
        outcome = f"failure phase=2fa code=unknown ({type(exc).__name__})"
        rc = 1
    finally:
        password = None
        del password
    print(diag.format_trace())
    print(f"outcome: {outcome}")
    if rc != 0:
        print("for analysis, share the trace above. It contains no secrets.")
    return rc


def cmd_status(args: argparse.Namespace) -> int:
    """Run the ``status`` command: show the journal state with no secrets.

    It also lists archived journals.

    Args:
        args: Parsed arguments. Uses ``journal`` (path).

    Returns:
        Exit code 0.
    """
    global _ACTIVE_JOURNAL
    journal = BindJournal(args.journal)
    _ACTIVE_JOURNAL = journal.path
    state = journal.load()
    if state is None:
        print(f"no journal at {journal.path}. No device is bound.")
        _print_archives(journal.path)
        return 0
    _print_journalsafe(state)
    if state.cloud_bind in journal_mod.PENDING_STATES:
        print("NOTE: a cloud call was in flight when the last run stopped.")
        print("It is not known if the server processed it. A fresh restart")
        print("needs explicit typed consent.")
    if state.stage == "bound" and state.bound_verified:
        print("next: run export-token. Then set the HA integration or the "
              "standalone app to use the token file.")
    _print_archives(journal.path)
    return 0


def _print_archives(journal_path: Path) -> None:
    """List archived journals (non-secret identity/stage only) so an
    old cloud entry is not forgotten."""
    parent = journal_path.parent
    if not parent.is_dir():
        return
    archives = sorted(
        p for p in parent.iterdir()
        if p.name.startswith(journal_path.name + ".archived-")
    )
    if not archives:
        return
    print(f"archived journals in {parent}:")
    for path in archives:
        note = ""
        try:
            obj = json.loads(path.read_text())
            bits = []
            if obj.get("server_did"):
                bits.append(f"server_did={obj['server_did']}")
            bits.append(f"stage={obj.get('stage', '?')}")
            bits.append(f"cloud_bind={obj.get('cloud_bind', '?')}")
            note = " (" + ", ".join(bits) + ")"
        except (OSError, ValueError):
            note = " (unreadable)"
        print(f"  {path.name}{note}")
    print("(an archived journal with a server_did can match a "
          "cloud entry. You possibly must remove that entry manually.)")


def cmd_export_token(args: argparse.Namespace) -> int:
    """Run the ``export-token`` command: write the verified token file (HA format).

    It works only if the journal is at stage ``bound`` and verified.

    Args:
        args: Parsed arguments. Uses ``journal``, ``output`` and ``force``.

    Returns:
        Exit code: 0 if the file is written or already the same, else 1.
    """
    journal = BindJournal(args.journal)
    state = journal.load()
    if state is None:
        print(f"no journal at {journal.path}")
        return 1
    if state.stage != "bound" or not state.bound_verified:
        print(
            "journal is not at stage 'bound' (verified). Run setup first. "
            "Setup verifies the binding offline before it reports success."
        )
        return 1
    return _write_token_file(Path(args.output), state.mac, state.token_hex, args.force)


def _write_token_file(out: Path, address: str, token_hex: str, force: bool) -> int:
    new_content = json.dumps({"address": address, "token_hex": token_hex}) + "\n"
    if out.exists() or out.is_symlink():
        if out.is_symlink():
            print(f"the tool does not write through a symlink: {out}")
            return 1
        try:
            existing = out.read_text()
        except OSError:
            existing = None
        if existing == new_content:
            print(f"{out} already has this token. There is nothing to do.")
            return 0
        if not force:
            # never silently replace a user's working token file
            print(f"the tool does not overwrite {out}. The file already exists with "
                  "different content (possibly a working token for a different "
                  "charger). To replace it, run again with --force.")
            return 1
        try:
            old = json.loads(existing or "{}")
        except ValueError:
            old = {}
        old_addr = old.get("address", "?")
        print(f"--force given; the existing file holds address {old_addr}.")
        if not confirm(f"Overwrite the token file for {old_addr}?"):
            print("stopped. The file did not change.")
            return 1
    data = new_content.encode()
    try:
        cloud._secure_write(out, data)
    except cloud.CloudError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out} (mode 0600). The ha-cuk-ble integration can use it.")
    return 0


async def cmd_fetch_token(args: argparse.Namespace) -> int:
    """Run the ``fetch-token`` command: get the token of an already-bound charger.

    It signs in, reads the token from the account device list, and writes
    the token file. It does no bind and no BLE. It does not change the
    account. The login is not saved.

    Args:
        args: Parsed arguments. Uses ``username``, ``region``, ``address``,
            ``output`` and ``force``.

    Returns:
        Exit code: 0 if the token file is written, else 1.
    """
    cloud.assert_safe_env()
    username = args.username or input("Xiaomi account username: ").strip()
    print(f"password for {username} (input hidden):")
    password = getpass.getpass("")
    account = cloud.MiAccount(session=cloud.new_session(), hidden_input=getpass.getpass)
    try:
        session = account.login(username, password)
    finally:
        password = None
        del password
    if session is None:
        print("login failed")
        return 1
    api = cloud.MiCloudApi(account.session, session, region=args.region,
                           skew_seconds=account._skew_seconds)
    devs = await asyncio.to_thread(api.list_devices)
    if args.address:
        want = cloud._mac_candidates(args.address)
        hits = [d for d in devs if cloud.normalize_mac(str(d.get("mac", ""))) in want]
    else:
        hits = [d for d in devs if str(d.get("model", "")).startswith(MODEL_NAME_PREFIX)]
    if not hits:
        print(f"no {'device ' + args.address if args.address else 'CUKTECH charger'} "
              f"on this account in region {args.region}. Try a different --region.")
        return 1
    if len(hits) > 1:
        for i, d in enumerate(hits):
            print(f"  [{i}] {d.get('name')}  {d.get('mac')}  ({d.get('model')})")
        idx = input("select device index: ").strip()
        if not idx.isdigit() or int(idx) >= len(hits):
            print("no device selected")
            return 1
        hits = [hits[int(idx)]]
    dev = hits[0]
    token_hex = str(dev.get("token") or "").strip().lower()
    # Mi Home logs in with exactly this 12-byte value; anything else is a format we haven't seen
    if len(token_hex) != 24 or any(c not in "0123456789abcdef" for c in token_hex):
        print(f"unexpected token format ({len(token_hex)} characters). Report this problem.")
        return 1
    print(f"found {dev.get('name')} {dev.get('mac')} (did {dev.get('did')})")
    return _write_token_file(Path(args.output), str(dev.get("mac")), token_hex, args.force)


# ---------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    """Make the argument parser with all subcommands.

    Returns:
        The parser. Each subcommand sets ``func`` to its ``cmd_*`` handler.
    """
    parser = argparse.ArgumentParser(
        prog="cuktech_pc",
        description=(
            "One-time bind of a CUKTECH AD1204U charger to your Xiaomi "
            "account, with the Xiaomi cloud. You do not need Mi Home. Server "
            "acceptance and the behaviour of unbound hardware are UNTESTED. "
            "Read the README before the first real run."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan", help="scan for AD1204U-family FE95 advertisements (read-only)"
    )
    p_scan.add_argument("--duration", type=float, default=10.0)
    p_scan.set_defaults(func=cmd_scan)

    p_diag = sub.add_parser(
        "diagnose-login",
        help="run ONLY the account login and print a sanitized trace "
             "(no secrets; no scan and no bind)",
    )
    p_diag.add_argument("--username", default="", help="Xiaomi account username")
    p_diag.set_defaults(func=cmd_diagnose_login)

    p_forget = sub.add_parser(
        "forget-login",
        help="remove ONLY the saved Xiaomi login (not the binding "
             "journal, tokens, archives or account entries)",
    )
    p_forget.add_argument(
        "--session-cache", type=Path, default=DEFAULT_SESSION_CACHE,
    )
    p_forget.set_defaults(func=cmd_forget_login)

    p_remove = sub.add_parser(
        "remove-device",
        help="remove ONE device entry from the account (for example, the "
             "entry left by a failed bind); uses the saved login and typed consent",
    )
    p_remove.add_argument("--did", required=True)
    p_remove.add_argument(
        "--session-cache", type=Path, default=DEFAULT_SESSION_CACHE,
    )
    p_remove.set_defaults(func=cmd_remove_device)

    p_setup = sub.add_parser(
        "setup",
        help="run the one-time bind (interactive; consent-gated)",
    )
    p_setup.add_argument("--username", default="", help="Xiaomi account username")
    p_setup.add_argument("--region", default="cn", choices=cloud.SERVERS)
    p_setup.add_argument("--address", default="", help="pre-selected device MAC")
    p_setup.add_argument("--journal", type=Path, default=DEFAULT_JOURNAL)
    p_setup.add_argument(
        "--session-cache", type=Path, default=DEFAULT_SESSION_CACHE,
        help="path of the saved-login cache (the authenticated session, "
             "not the password)",
    )
    p_setup.add_argument("--scan-duration", type=float, default=10.0)
    p_setup.add_argument(
        "--dry-run",
        action="store_true",
        help="offline only: show the resume decision and phase plan",
    )
    p_setup.add_argument("--verbose", action="store_true")
    p_setup.set_defaults(func=cmd_setup)

    p_status = sub.add_parser("status", help="show the journal state (no secrets)")
    p_status.add_argument("--journal", type=Path, default=DEFAULT_JOURNAL)
    p_status.set_defaults(func=cmd_status)

    p_export = sub.add_parser(
        "export-token",
        help="write the verified token to ~/.cuktech_ble.token (HA format)",
    )
    p_export.add_argument("--journal", type=Path, default=DEFAULT_JOURNAL)
    p_export.add_argument("--output", type=Path, default=DEFAULT_TOKEN_OUT)
    p_export.add_argument(
        "--force",
        action="store_true",
        help="let the tool replace an existing DIFFERENT token file (typed "
             "confirmation is still necessary)",
    )
    p_export.set_defaults(func=cmd_export_token)

    p_fetch = sub.add_parser(
        "fetch-token",
        help="token only: sign in and read the token of an already-bound "
             "charger from the account (no bind, no BLE, nothing changed or saved)",
    )
    p_fetch.add_argument("--username", default="", help="Xiaomi account username")
    p_fetch.add_argument("--region", default="cn", choices=cloud.SERVERS)
    p_fetch.add_argument("--address", default="", help="charger MAC (optional)")
    p_fetch.add_argument("--output", type=Path, default=DEFAULT_TOKEN_OUT)
    p_fetch.add_argument("--force", action="store_true",
                         help="let the tool replace an existing DIFFERENT token file")
    p_fetch.set_defaults(func=cmd_fetch_token)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse the arguments and run one command.

    Known errors print one sanitized line to stderr. Other errors print
    only the exception type. No traceback is shown.

    Args:
        argv: Command-line arguments without the program name. If None,
            ``sys.argv[1:]`` is used.

    Returns:
        Exit code of the command: 0 on success, 1 on error, 130 on Ctrl+C.
    """
    import inspect

    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = getattr(args, "verbose", False)
    _configure_logging(verbose=verbose)
    try:
        if inspect.iscoroutinefunction(args.func):
            return asyncio.run(args.func(args))
        return args.func(args)
    except cloud.ProxyRefusedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except cloud.ManualActionRequired as exc:
        # never print the URL with "then re-run" advice (the
        # user's loop); a manual handoff belongs to the normal setup mode,
        # not to a shareable diagnostic output
        print(f"manual action needed: {exc}", file=sys.stderr)
        print("do the confirmation locally in a browser. Then run "
              "setup in NORMAL mode. Do not run diagnose-login again: it "
              "does not continue the session.", file=sys.stderr)
        return 1
    except cloud.UnsafeURLError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except cloud.CloudError as exc:
        print(f"cloud error: {exc}", file=sys.stderr)
        return 1
    except journal_mod.JournalError as exc:
        print(f"journal error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted. The journal is kept. Run setup again to continue.",
              file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        # one sanitized line, never a traceback — login-phase
        # exceptions can otherwise carry the password-hash URL. The
        # exception TYPE is safe to name; nothing else is shown or logged.
        print(f"fatal error ({type(exc).__name__}). The tool shows no details, "
              "to keep credentials safe. Keep the journal and run again. "
              "Report the stage that you reached.",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
