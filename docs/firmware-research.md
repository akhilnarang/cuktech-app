# AD1204U firmware and additional controls

Related records:

- The [firmware analysis log](firmware-analysis-log.md) records each stage of
  the later work: the Ghidra analysis, the custom startup decompressor, the
  extraction of individual fonts and icons, the resolved protocol bits and the
  command map.
- The [Chinese Mi Home APK analysis](firmware/mihome-cn-apk-analysis.md)
  records an official host build from a separate source, its static
  decompilation, the regional charger catalog entries and more plugin and
  firmware lookup formats.

Date: 2026-10-13. Scope: the China model `njcuk.fitting.ad1204`
(CUKTECH AD1204U / 10 Ultra, product ID `26126` / `0x660e`). No firmware was
installed. No charger settings were changed.

## Firmware from Xiaomi

An authenticated query to the China server for the charger on the account
returned `2.1.2_0073`. This was the version offered to this account at that
time. It does not prove the installed version. It does not show all available
beta releases.

| Package | Size | MD5 from Xiaomi, verified locally | SHA-256 computed locally |
|---|---:|---|---|
| Signed OTA | 496,995 bytes | `0bd090bce659c906f3d933f55cc3027c` | `1724b63e797af6a76e43d61931e2361b537e653946a130d0441ca0ef9d5ed65a` |
| Legacy raw image | 495,656 bytes | `c62a0cca0422986c4c15056a0e962691` | `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1` |

Xiaomi CDN links that were seen. The files are hosted by Xiaomi; this repository does not include them.
On 2026-11-22 both links return HTTP 403. Xiaomi now serves only 2.1.2_0079 (see [the 0079 diff](firmware/diff-0079.md)):

- [Signed OTA package](https://iot-ota-cdn.io.mi.com/miio_fw/signed_0bd090bce659c906f3d933f55cc3027c_upd_njcuk.fitting.ad1204.bin)
- [Legacy raw image](https://iot-ota-cdn.io.mi.com/miio_fw/c62a0cca0422986c4c15056a0e962691_upd_njcuk.fitting.ad1204.bin)

The signed package starts with the full raw image, byte for byte. It adds
1,339 bytes of tag, certificates and signature. Keep this trailer for a
future DFU implementation. The raw image is only for inspection.

Downloads and analysis outputs are in `artifacts/firmware/`. Git ignores the
contents of this directory. The first downloads end in `-0.bin` (signed) and
`-1.bin` (raw). The reusable utility uses `-signed.bin` and `-raw.bin`.

## Cloud fetch format

The Bluetooth token authenticates local Bluetooth control. It is not a Xiaomi
cloud session. It does not authorize firmware metadata requests.

The modern BLE metadata API, from the Xiaomi SDK documentation:

```text
POST https://api.io.mi.com/app/v2/device/latest_ver
plaintext data: {"did":"<charger DID from this account's device list>"}
```

If the charger is no longer on the account, the server refuses the DID-based
request. The legacy lookup by model was also seen to work:

```text
POST https://api.io.mi.com/app/home/latest_version
plaintext data: {"model":"njcuk.fitting.ad1204"}
```

Request details:

- For other regions, the base is `https://<region>.api.io.mi.com/app`. China
  uses no prefix.
- API authentication uses the `userId`, `serviceToken` and
  `yetAnotherServiceToken` cookies.
- The JSON above is encrypted and signed into the Xiaomi RC4 form envelope. It
  is not sent as a plain JSON body.
- The existing `cloud.py` / Android `MiEnvelope.kt` make the nonce, the signed
  nonce, `rc4_hash__`, the encrypted `data` and the `signature` fields.
- You do not need a bind or update command to read metadata.

Response shape that was seen, without package-specific values:

```json
{
  "code": 0,
  "result": {
    "version": "2.1.2_0073",
    "url": "https://iot-ota-cdn.io.mi.com/miio_fw/<package>.bin",
    "safe_url": "https://iot-ota-cdn.io.mi.com/miio_fw/<package>.bin",
    "md5": "<32 hex characters>",
    "changeLog": "<release notes>",
    "force": false,
    "rec": false
  }
}
```

The downloader uses a separate HTTPS session without cookies for the CDN.

- It validates each redirect.
- It limits the image to 8 MiB.
- It verifies the metadata MD5 before it accepts the image.

An MD5 match checks that the download is consistent. The authenticated
metadata and the HTTPS connection show where it comes from.

## Reproduce without repeated logins on Windows

From the repository root, with the project virtual environment:

```powershell
cd scripts
# Already saved locally during this investigation; prints presence only.
uv run -m cuktech_pc.firmware status
uv run -m cuktech_pc.firmware fetch
uv run -m cuktech_pc.firmware fetch --legacy
uv run -m cuktech_pc.firmware inspect ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin

# Offline package/CDN regression tests, portable to Windows.
uv run -m unittest tests_firmware.test_firmware

# Only when Xiaomi expires the saved session. Password and email/SMS codes
# are hidden prompts; do not put passwords in command arguments.
uv run -m cuktech_pc.firmware login --region cn --address AA:BB:CC:DD:EE:FF

# Keep the encrypted charger token while discarding cloud credentials.
uv run -m cuktech_pc.firmware forget-login
```

- The commands after `cd scripts` work without a change to `PYTHONPATH`.
- This Windows utility needs `requests`, `rich` and `cryptography`.
- `capstone` is optional, for disassembly.
- You do not need Bluetooth dependencies to download firmware.
- The Linux binding CLI has more dependencies and a separate cache.

Private desktop state is in `scripts/.private/xiaomi-session.dpapi`. Git
ignores this file.

- It contains the validated session, selected account cookies and the charger
  token.
- It is encrypted with Windows DPAPI for the signed-in Windows user.
- Its directory has an ACL for the user only.
- Passwords, verification codes and challenge URLs are not saved.
- A separate process decrypted the saved session and used it to list the
  charger without a new login.
- Xiaomi can still expire or revoke the session.
- If the cloud session expires, the Bluetooth token of the charger stays
  valid. A reset or a new bind of the charger can make the token invalid.

## Image layout and signature inspection

The raw image contains ARM Thumb code and readable strings.

- The initial stack is `0x20047458`.
- The reset vector is `0x00403059`.
- The `R2SF` marker is at file offset `0x28`.
- The analysis uses the image base `0x00403000`.
- The addresses below apply only to this exact `2.1.2_0073` image.
- A FreeRTOS build-path string names `ARM_CM4F`.

The signed-package tag starts at offset `0x79028` (495,656):

| Field | Observed value |
|---|---|
| Magic, 16 bytes | `000000004d49ef54464f544182562647` |
| Tag size, little-endian u16 | 70 |
| Product ID, little-endian u16 | 26126 (`0x660e`) |
| Firmware size, little-endian u32 | 495,656 |
| Certificate block size, little-endian u16 | 1,198 |
| Flags | 0 |
| Remaining signature | 71 bytes, DER ECDSA |

Tag TLVs include the new version (`type=1`, `02 01 02 49 00`), the model
(`type=4`, ASCII), the signing type (`type=3`, value 1) and the product ID
(`type=5`, u32). The certificates come after the tag. The signature comes
after the certificates.

Signature chain:

- The packaged server certificate signs the developer certificate.
- The developer key verifies the ECDSA/SHA-256 signature over the image and the tag.
- Both checks passed with Python `cryptography`.
- This does not give an independent root of trust. The packaged server
  certificate is not verified against a Xiaomi root certificate from a
  separate source.
- The footer also contains a CRC field. Its exact calculation is not verified.
  Do not assume that it is a standalone `zlib.crc32(tag)`.

## Additional settings and misleading fields

The public Xiaomi MIOT specification version 2 lists 21 charger properties on
service 2. The firmware property getter is at `0x00405914`. The setter is at
`0x00405a98`. The setter wrapper is at `0x0041d41c`.

| Property | Meaning and evidence | App behavior |
|---|---|---|
| `2.5` | Scenes 1–4: AI, Apple, Single, Balance. The spec misspells the last label `Banlance`. | Existing scene picker retained. |
| `2.6` | Timeout: 5=1 min, 1=5 min, 2=10 min, 3=30 min, 4=always on. | Corrected in 0.6.5 against original lookup and unchanged MIOT enum path. |
| `2.7` | Protocol-control byte; handler `0x00404d2c`. Follow-up analysis maps bit 1 to global C1/C2 miPPS and bit 2 to global C1/C2 UFCS; bit 0 remains unresolved. | No raw write UI; full mapping and limits are in the stage log. |
| `2.8` | Countdown-setting byte is advertised writable, but this build dispatches writes to the unsupported branch. | Omitted. |
| `2.9`–`2.12` | C1/C2/C3/A shutdown timers, uint16 minutes. Handler `0x00414618` stores `minutes*60-1`; zero clears the timer. | Added optional timer read and per-port timer editing. |
| `2.13` | Display language: 0=English, 1=Chinese. | Added language choices. |
| `2.14` | `enter`, advertised write-only values 1–5, dispatches directly to success without an operation in this build. | Omitted; not a discovered hidden-mode switch. |
| `2.15` | USB-A always on. | Existing control retained. |
| `2.16` | Port-enable mask, bits 0–3=C1/C2/C3/A; handler `0x00404c10` applies port changes. | Added per-port switches, preserving the other bits. |
| `2.17`, `2.18` | Read-only negotiated protocol/capability information. | Existing telemetry retained. |
| `2.19`, `2.20` | Idle screen-off and orientation lock. | Existing controls retained. |
| `2.21` | Handler `0x00404dd0`: C1 bits 0–3 and C2 bits 8–11 enable PD/PPS/UFCS/miPPS; C3 bits 16–17 and A bits 24–25 enable UFCS/SCP. | Static mapping documented in the stage log; no new protocol-toggle UI or hardware validation. |

The outer setter wrapper writes "success" into the status after it calls the
inner setter. Thus a successful write ACK alone does not prove that a setting
changed. The app now reads the setting back before it reports success. On a
mismatch, it shows the value that the charger returned. The app ignores
unsupported read statuses. It does not show them as valid settings.

The original bulk-read request, which is tested on hardware, did not change.
Timer reads use a separate request, because untested properties in the
default batch could disturb normal telemetry. The new timer controls and other changes are
compiled and regression tested. They are not tested on hardware.

## Mode and temperature leads

Strings in this image include:

| File offset | String / lead | What it establishes |
|---|---|---|
| `0x0d4d0` | `BEAST MODE` | Follow-up Ghidra analysis identifies its renderer at `0x0041044c` and UI page-state selection in `0x0041113c`; no additional BLE scene value was established. |
| `0x72c1a` | `AI Temperature Control` | A thermal-control UI label exists. |
| `0x71e20` | User-defined per-port power allocation log | Internal allocation logic exists; a remote configuration API was not established. |
| `0x06a80` and later | Protocol auto-test state/logs | An internal compatibility-test state machine exists. |
| `0x05e47`, `0x05e80` | Shell temperature and temperature-mode logs | Internal temperature processing exists. |

These are analysis leads. They are not new unlocked controls. They are not
evidence of a way around the power limit. The public MIOT map has no
temperature property. Upstream research also reports that an authenticated
sweep after property 21 found no temperature property. That sweep was done on
upstream hardware, not on this charger. Private GATT paths and later firmware
are open questions.

**2026-10-14 update:**

- The public MIOT getter has no temperature property. But the vendor AF08
  status reply carries a cached converted NTC byte.
- A manual experimental app query now reads this status.
- AF07 requests stop normal MIOT cache updates until a disconnect. Thus the app
  connects again after the query.
- The exact frames, code addresses, protocol labels and remaining hardware
  checks are in [the telemetry findings](firmware/findings-telemetry.md).

## Firmware installation boundary

App 0.7.0 can do these tasks without Mi Home:

- check if firmware is available for the account
- download, verify and export a package
- import a signed file offline
- install the file directly

The experimental installer needs a bound China AD1204 that runs 0073. It
verifies the pinned signing chain and matches the flash-commit indices. After
the reconnect, it reads the running version. Hardware flashing and recovery
are not verified. See [implementation and limits](firmware/in-app-flasher.md).

The archived Xiaomi SDK defines OTA control UUID `0x0017`, OTA data `0x0018`,
and 512-byte firmware fragments with reliable transfer framing.

WARNING: SDK command 2 has the name "read size", but it starts and resets a
DFU transfer. Command 4 authenticates the staged image and enables the switch
to it. These are not safe read-only discovery operations.

The SDK service file also gates its DFU handler with authentication and build
options. A copy of the generic SDK protocol does not prove compatibility with
this standard-auth charger. A future native updater needs these items:

- a GATT capture from this charger
- validated transfer framing
- signature handling
- recovery after an interruption
- a version check after the reboot

The later analysis of this firmware confirms the `0x0017/0x0018` registration
and the authenticated dispatch. Its control parser can select 512-byte or
2,048-byte fragments from the link parameters. The stage log has these static
findings, the full command table and the signature path. They are not a live
OTA compatibility test or a recovery test.

The 2026-10-15 [native transfer trace](firmware/ota-transfer-framing.md)
matches these items against this receiver: both indexed layers, control
notifications, resume with a CRC check, and the activation delay that waits
for a disconnect.

- The [validation/recovery review](firmware/ota-validation-recovery.md) also
  finds MD5 checks of the local file. It keeps retries separate from rollback.
- The final completion check of the native UI looks for the same MAC again.
  It does not read the running version again.
- These are offline findings. Independent bootloader/ROM recovery and the
  behavior during a live interruption are not verified.

## Login reliability changes

The Android cloud client retries an idempotent read one time after a dropped
connection or a 502/503/504 response.

- This includes the device-list and firmware metadata POSTs.
- The client can retry a DNS, connect or no-route failure before the request
  reaches the server.
- The client does not automatically send ambiguous password, verification-code
  or bind POST failures again.
- The client does not retry TLS failures.
- The error text tells DNS, timeout and secure-connection failures apart. It
  does not print URLs, cookies or password hashes.

The app encrypts validated Android sessions with Android Keystore and uses them
again for firmware checks.

- To use the session again for setup, the app also checks a hashed username
  and the region. It validates the cache with a device-list request.
- Temporary network errors keep the cache. A confirmed HTTP 401 starts a new sign-in.
- "Forget cloud login" keeps the Bluetooth token. "Forget charger" deletes both.

The BLE engine also waits for the `RCV_OK` of the outgoing request before it
runs response callbacks. Thus an early response cannot make the next readback
overwrite a flow-control wait that is still active. Tests cover matching
readback and ignored-setting ACKs.

No original login-failure trace from the phone of the user was available. Thus
these are targeted resilience fixes. They do not claim to find all causes of
intermittent login failures.

Navigation now scopes the ViewModel of each screen to its back-stack entry.
Thus when you go back from firmware or setup, the temporary login prompts and
state of the screen are cleared. The encrypted credential store is kept.

## Sources and validation

The [extractor guide](firmware-extractor.md) describes the offline extraction.
One command separates the package components, expands the startup blocks,
exports font and color PNGs and keeps the remaining bytes as optional chunks
with source addresses. The [controller/asset follow-up](firmware/controller-and-assets-followup.md)
records the verified color codec, the controller metadata writes and the open
sensor and configuration questions.

- [Xiaomi SDK firmware APIs](https://github.com/MiEcosystem/miot-plugin-sdk/blob/master/miot-sdk/service/smarthome.js): `getLatestVersion`, `getLatestVersionV2`.
- [Xiaomi BLE OTA overview](https://github.com/MiEcosystem/miot-plugin-sdk/blob/master/%E8%93%9D%E7%89%99OTA%E6%AD%A5%E9%AA%A4.md).
- [Public model instances](https://miot-spec.org/miot-spec-v2/instances?status=all).
- [Exact v2 model specification](https://miot-spec.org/miot-spec-v2/instance?type=urn:miot-spec-v2:device:fitting:0000A0D1:njcuk-ad1204:2).
- [Archived Xiaomi DFU implementation](https://github.com/scooterhacking/mijia_ble_libs/tree/master/gatt_dfu), especially `mible_dfu_main.c`, `mible_dfu_auth.c`.
- [Archived Xiaomi service UUIDs and gates](https://github.com/scooterhacking/mijia_ble_libs/blob/master/mijia_profiles/mi_service_server.c).
- [Upstream CUKTECH property research](https://github.com/zuyan9/ha-cuk-ble/blob/master/docs/properties.md).
- [Android Navigation 3 ViewModel scoping](https://developer.android.com/guide/navigation/navigation-3/save-state).

Validation done:

- live authenticated metadata lookup
- MD5 of both CDN packages
- exact comparison of the raw prefix
- package TLV parsing
- developer certificate and image-signature checks
- encrypted desktop-cache roundtrip, and use in a separate process
- Android build, 14 Android regression tests, eight portable firmware-package
  tests, and lint

Bluetooth control and OTA were not tested on the charger.

> NOTE: Paths under `artifacts/` are local files that git ignores. They are
> downloaded vendor packages and outputs that the tools in `scripts/` make
> again. They are not part of this repository. The documents record hashes so
> that you can reproduce the results.
