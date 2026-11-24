# cuktech_pc: AD1204U bind and firmware research tools

Python tools for the CUKTECH AD1204U charger (`njcuk.fitting.ad1204`):

- `cuktech_pc.cli` binds a charger that was never bound (CN pid `0x660E` /
  overseas pid `0x8AB9`) to your own Xiaomi account. It uses the legitimate
  cloud-assisted standard-auth v2 flow. Then it exports the token for local
  control with [ha-cuk-ble](https://github.com/zuyan9/ha-cuk-ble) or the
  Android app in [`../app`](../app). You do not need the Mi Home app.
- `cuktech_pc.firmware` downloads the official firmware package for your
  charger and examines it offline. It does not flash the charger.
- Offline firmware research tools: an unpacker, bitmap and command decoders,
  evidence and coverage helpers, and [Ghidra scripts](ghidra/README.md).

> **WARNING: EXPERIMENTAL.**
> - All protocol facts come from the decompiled Mi Home 11.9.521 APK.
> - Offline unit tests cover the flow. The offline test vectors show only
>   that the code is consistent with itself.
> - The bind is not verified end to end against the Xiaomi servers and an
>   unbound charger.
> - Run the tool yourself, at the keyboard. The bind can fail.
> - A failed attempt can leave an allocation on the account. You must remove
>   it manually. The tool does not remove it.

## Setup

You need [uv](https://docs.astral.sh/uv/). Run all commands below from the
`scripts/` directory with `uv run`. On the first run, `uv` installs Python 3.14 and
the exact dependency versions from `uv.lock` into `scripts/.venv`.

The bind CLI needs a Bluetooth adapter. The adapter must be near the unbound
charger. The target platform is Linux/BlueZ. `bleak` also supports macOS and
Windows, but these platforms are not tested.

## Safety model

- Explicit commands only. Nothing runs on import.
- Typed-MAC consent comes before all other access to the charger.
  - The consent gate is after the read-only scan and the guards.
  - The gate is before the connection, before all BLE writes, before the
    ECDH exchange and before the first cloud mutation.
  - The gate needs only the advertisement identity (MAC, pid, smac). If you
    decline, the tool does not touch the charger.
  - Limitation: the account login (a read-only session) occurs before the gate.
- Interrupt-safe bind:
  - After the charger enters the key-exchange state, a cloud failure or an
    unexpected exit before the confirm write sends `0x14` one time. Thus the
    charger does not stay half-bound without a signal. The tool never sends
    `0x13` on material that is not validated.
  - After the tool sends the confirm (`0x13`), it never sends `0x14`. This
    includes the blob/cert upload, the final wait and a journal write after
    the `0x11` from the charger. The app also never sends `0x14` at this
    point. The firmware behavior in this case is not known. The journal
    records an unknown outcome.
- Journal first (crash-safe):
  - The tool saves the pairing token, the beacon key and the cloud material
    at four points. Each save occurs before the next uncertain step.
  - The saves are 0600, atomic and symlink-safe.
  - The tool writes an intent record before each cloud mutation. Thus an
    interrupted call never looks like "cloud never called".
- A resume never restarts without a check. A second run first tries the
  offline token login with the saved token. The results are:
  - *verified*: the bind is complete.
  - *rejected* or *not-registered*: the charger sent the explicit SDK
    wrong-token code or the `e0` ERR_NOT_REGISTERED code. A new start is
    possible only with typed consent, a live unregistered advertisement from
    the same charger, and an archive of the old journal. It is never automatic.
  - *inconclusive*: the charger is unreachable, a timeout occurred, or a
    different auth error occurred. Try again later. The tool does not restart
    or change anything.
- The tool keeps the charger MAC from the journal through a resume. It never
  binds a different charger over an existing journal.
- `status` lists archived journals (identity and stage only). Thus you do not
  forget an old cloud entry.
- The tool never unbinds, deletes or reallocates automatically. For unknown
  or half-done states, it prints manual recovery instructions. Mi Home
  unbinds automatically when the charger rejects the bind. This tool does
  not do that, by design.
- Credentials:
  - The tool reads the password and the 2FA codes with hidden `getpass`
    prompts.
  - Credentials are never in argv, environment variables, logs or error
    messages.
  - A fatal error prints one sanitized line (the exception type name).
  - The tool never shows tracebacks or URLs, because the password hash is
    in a login query string.
  - Session cookies and `ssecurity` stay in memory only.
- Network hardening:
  - Each HTTP call has a connect timeout, a read timeout and a limit on the
    response size.
  - The tool never follows redirects automatically. A 3xx answer to a POST
    (login or cloud mutation) gives a sanitized "ambiguous" error. The tool
    never sends the password hash or the bind mutations again to a different
    hop (redirect target).
  - The email-2FA chain reads its intermediate 302 responses (`Location`,
    `extension-pragma`) itself.
  - Before each request in this chain, the tool checks the URL against an
    allowlist of official hosts (`account.xiaomi.com`, `sts.api.io.mi.com`,
    `{region.}api.io.mi.com`). The URL must use https, the default port and
    no userinfo.
  - If a host is not on the allowlist, the flow stops and tells you to
    continue manually in a browser.
  - The tool refuses proxy environment variables (in all letter cases) and
    `SSLKEYLOGFILE`.
- Captcha and 2FA:
  - The tool saves captcha images next to the journal
    (`~/.cuktech_pc/captcha.png`). You type the code.
  - If the server rejects the code (87001), the tool shows a new image and a
    new prompt. The number of retries has a limit. After the last retry, the
    tool stops and tells you what to do. It never sends a code again without
    a prompt.
  - Email 2FA is fully scripted. The tool reads the code with a hidden prompt.
  - If the account asks for more confirmation, the tool offers a bounded handoff in
    the same session. Open the challenge URL in a browser,
    then push Enter. The CLI then checks this session again.
  - If you complete the challenge in a browser and then run the tool again,
    it does not work. A new run is a new session, and it starts 2FA again.
  - If login still fails, run `diagnose-login` and share its sanitized trace.
    The trace has the phase, HTTP status, JSON key names and numeric codes.
    It has no secrets.
- Identity guards:
  - The FE95 `registered` bit must be clear.
  - The FE95 MAC must match the selected address byte by byte (in either
    byte order) before the tool uploads it as `smac`.
  - The address and the smac (raw or byte-reversed) must not already be on
    the account.
  - If the device list request gives an error, the tool stops (fail-closed).
    It does not treat the error as an empty list.
  - The model string comes only from the live pid mapping. It is never free
    text.
- Clock skew: the tool uses the server `Date` header for the nonce minute
  bucket. If signature errors occur, check NTP.

## Bind usage

Run all commands locally with your own credentials.

WARNING: Never paste credentials or tokens into a chat, an issue tracker or
other channels.

```bash
# 0. login-only diagnostic (if login fails): sanitized trace, no secrets
uv run -m cuktech_pc.cli diagnose-login --username you@example.com

# 1. read-only scan: shows pid, smac, FE95 registered/solicited bits
uv run -m cuktech_pc.cli scan

# 2. offline rehearsal: shows the resume decision + phase plan, touches nothing
uv run -m cuktech_pc.cli setup --dry-run

# 3. the one-time bind (interactive; typed-MAC consent before connecting)
uv run -m cuktech_pc.cli setup --username you@example.com --region cn

# 4. check the journal (no secrets printed)
uv run -m cuktech_pc.cli status

# 5a. charger already bound to an account you can log in to: token only, no bind
uv run -m cuktech_pc.cli fetch-token --username you@example.com --region in

# 5b. export the token for ha-cuk-ble (~/.cuktech_ble.token)
uv run -m cuktech_pc.cli export-token
```

To see all commands (also `forget-login` and `remove-device`), run
`uv run -m cuktech_pc.cli --help`.

`export-token` does not overwrite an existing token file that is different.
To replace the file, run the command again with `--force` and type the
confirmation.

After step 5, all control is local. The integration or the Android app uses
the token offline.

WARNING: After step 5, do not factory-reset the charger. Do not delete the
charger from the account. Each of these actions destroys the binding that
the token needs.

The Android app accepts the token as 24 hex characters. Read the 0600 token
file locally (`cat ~/.cuktech_ble.token`) and type the token on the phone.

## Recovery (manual, by design)

`setup` prints instructions for the current stage if a problem occurs.
The short procedure:

1. Run `setup` again. It first tries the offline login with the saved token.
   If the charger committed the bind, the procedure is complete and the
   cloud is not used.
   - An *inconclusive* check (charger off, too far or busy) never restarts
     anything. Correct the conditions and run `setup` again.
2. WARNING: Do not reset the charger after an unclear result. Keep the
   journal and check `status` first.
   - If a new start is necessary, factory-reset the charger.
   - Remove the account entry that blocks the account-device guard, if one
     exists.
   - Run `setup` again and give consent to a new bind. The tool archives the
     old journal. It does not delete it.
3. The journal file (`~/.cuktech_pc/journal.json`, 0600) keeps all derived
   secrets. Keep it private. If its permissions become wider, the tool does
   not load it until you set them back with `chmod 600`.

## Firmware download and offline research

This repository does not include firmware images. Download the official
package for your own charger with `cuktech_pc.firmware`. The tool saves the
cloud session in `~/.cuktech_pc/firmware-session.json` (mode 0600) on Linux and
macOS, and with DPAPI on Windows. For the full workflow from download to
decompilation, see the [firmware how-to](../docs/firmware-howto.md).

```bash
uv run -m cuktech_pc.firmware login --address AA:BB:CC:DD:EE:FF --region cn
uv run -m cuktech_pc.firmware fetch            # verifies MD5 and the ECDSA signature
uv run -m cuktech_pc.firmware fetch --legacy   # raw image; works also if the charger is not on the account
uv run -m cuktech_pc.firmware inspect PATH/TO/IMAGE.bin
uv run -m cuktech_pc.firmware forget-login
```

Downloads go to `../artifacts/firmware/`. This is a local output directory
that git ignores. To use a different directory, use `fetch --output DIR`.
File names look like `njcuk.fitting.ad1204-2.1.2_0073-signed.bin`. For the
protocol sources, see [firmware research](../docs/firmware-research.md).

Offline tools (they do not use an account, the network or Bluetooth):

```bash
# unpack: startup decompression, font glyphs, RGB565 images, remaining slices
uv run -m cuktech_pc.firmware_unpack ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin \
    --output ../artifacts/firmware/unpacked-0073 --verify --assets --split-unclassified

# describe an AF07 command frame (does not construct or send a write)
uv run -m cuktech_pc.firmware_commands "fe dc ba 01 f1 00 01 08 03 03 0f 0f"

# disassemble 4 Thumb instructions at an address (base 0x403000)
uv run --with capstone python tools/thumb_disasm.py FILE 4203b4 4

# extract JavaScript modules from the Mi Home charger plugin's RAM bundle
uv run -m cuktech_pc.ram_bundle PATH/TO/main.bundle --output NEW_DIRECTORY
```

Output directories must be new.

- The unpacker option `--region OFFSET:SIZE:NAME` extracts one more slice
  that you select.
- Open `index.html` in the output to see galleries and metadata.
- Unclassified chunks can contain code or data. Their generated names do not
  mean that a filesystem was recovered.
- `cuktech_pc.firmware_blob_inventory` compares the remaining ranges from the
  unpacker with Ghidra function bodies.

More information:
[extractor guide](../docs/firmware-extractor.md),
[analysis log](../docs/firmware-analysis-log.md),
[protocol/command follow-up](../docs/firmware/protocol-command-blob-followup.md),
[Ghidra reproduction](ghidra/README.md).

[`analyze-mihome.ps1`](analyze-mihome.ps1) decompiles a Mi Home APK that you
supply. It uses a local JADX/JDK that you already have, and writes to a new
output directory. It does not install or run the APK. See the
[APK analysis record](../docs/firmware/mihome-cn-apk-analysis.md).

## Tests (offline: no account, no network, no Bluetooth)

```bash
uv run -m unittest discover -s tests -t .
uv run -m unittest discover -s tests_firmware -t .
```

`tests/` runs with a built-in IO guard (`tests/__init__.py`):

- Sockets are blocked. An outbound connection or a DNS lookup makes the suite fail.
- `bleak` and `dbus` imports are refused.
- All scratch I/O stays in `scripts/.test-scratch`.

No test needs root, hardware or vendor files. No test is skipped.

## Provenance and licensing

- `crypto.py`, `fe95.py`, and the BLE channel/parcel machinery in
  `blebind.py` are adapted from
  [ha-cuk-ble](https://github.com/zuyan9/ha-cuk-ble) (Apache-2.0). The file
  headers give the exact origins and changes.
- The cloud login and RC4 envelope in `cloud.py` adapt
  [PiotrMachowski/Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
  (MIT) through ha-cuk-ble. The 2FA continuation also uses patterns from
  [al-one/hass-xiaomi-miot](https://github.com/al-one/hass-xiaomi-miot)
  (Apache-2.0).
- The protocol facts come from the decompiled Mi Home APK. This repository
  does not include vendor code, an APK or a firmware image.
