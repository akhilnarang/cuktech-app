# Chinese Mi Home APK analysis

> **Provenance and scope.** This document is interoperability research on publicly
> distributed software. Its purpose is to let independent software talk to a
> charger that the reader owns. It records only the facts necessary for that
> purpose: request formats, identifiers, offsets, hashes and observed behaviour.
> This repository does not redistribute vendor source code, decompiled code, APKs,
> plugin packages, firmware or other vendor binaries.

Update: the [official charger plugin](mihome-charger-plugin.md) is now downloaded
with the native request format. It is plugin version 60 / package ID 1896060, with
150 extracted JS modules. The failed lookups below come from the first analysis of
the host APK. Stage 20 solved the acquisition.

## Scope and artifact identity

On 2026-10-15, the Chinese-store Mi Home APK was downloaded and decompiled as a new
evidence source for the AD1204U investigation. The inspection is static. The APK
was not installed or run, and no charger command was sent.

The [official Chinese Xiaomi store listing](https://r.app.xiaomi.com/details?id=com.xiaomi.smarthome)
was the source of the APK. This repository does not link to or include the APK.

Measured identity:

| Field | Value |
| --- | --- |
| Package | `com.xiaomi.smarthome` |
| Manifest versionName | `11.7.709` |
| Manifest versionCode | `110717091` |
| APK bytes | `244510121` |
| APK SHA-256 | `73335d3c17dff3e73097db7e2f86a373b7eb2c67611dc82749883ab2da3f0b6e` |
| Signing certificate SHA-256 | `237ada9aca86c5d0b0a411af5d3a899545969705f3b9e36f8d8508f4dfbd444d` |
| ZIP members | `12642` |
| Uncompressed member bytes | `532753176` |
| Root DEX files | `14` |

Android SDK 36.0.0 `apksigner verify --verbose --print-certs` accepts APK signature
schemes v2 and v3, with one signer. This confirms the signature integrity and the
certificate fingerprint. The certificate was not compared with older certificates.
All ZIP member CRC checks pass. The package and version values come from the
decoded manifest. They do not come from a download filename or a search result.

The ignored directory `artifacts/mihome-cn-20261015/` keeps these items:

- The acquisition URL and receipt.
- The APK and its ZIP inventory.
- The signature report.
- Selected original assets.
- The decompiler output.

Git does not include the vendor APK, source, resources or downloaded tools. This
download does not need account cookies or tokens.

## Bundled catalog: exact charger and region distinction

`assets/device_config/plugin_config_cn-zh_cn`, JSON pointer
`/result/devices/list/8575`, includes `njcuk.fitting.ad1204`:

- `pd_id=26126` (`0x660e`), `pid=6`, `bt_bind_style=2`, `resolve_type=3`.
- `localizations=["zh_cn","en"]`, `min_app_version=60160`.
- The name identifies the CUKTECH 10 Ultra charger.

This catalog member is 16,559,920 bytes, SHA-256
`3c560e1102a209d2b8bcfde66c68f1acc1e9d7ca9e227a71e3e6c923eaafbd1c`.
Here `pd_id` is the product identifier. `pid=6` is a different catalog field. Do
not use it in place of the BLE product ID.

The bundled `de-en`, `ru-ru` and `sg-en` catalogs contain the overseas model
`njcuk.fitting.1204e`, `pd_id=35513` (`0x8ab9`), with the same language pair. This
is direct evidence of separate regional model entries. It does not prove which
account or region owns a specific charger. It also does not prove that firmware and
plugins are interchangeable.

The bundled `builtinPluginMap.json` has no `njcuk` entry. The limited byte search
finds the exact model in the device catalog. It does not find a charger
implementation. The model catalog is not the downloaded device plugin. It does not
show the protocol enum or the temperature UI.

## Shipped SDK: additional firmware metadata routes

Module 10065, `miot-sdk/service/smarthome.js`, confirms the existing methods
`getLatestVersion(model)` → `/home/latest_version` (byte `0x617f7`) and
`getLatestVersionV2(did)` → `/v2/device/latest_ver` (byte `0x61991`). It also
has two lookup methods that give more data:

| Function / starting byte | Endpoint | Android body fields |
| --- | --- | --- |
| `_getFirmwareOriginalUpdateInfo`, `0x61b34` | `/v2/device/multi_check_device_version` | `app_level`, `platform:"android"`, `check_reqs:[{did,plugin_level}]` |
| `_getFirmwareOriginalUpdateInfoV2`, `0x621b0` | `/v2/device/check_device_version_v2` | `app_level`, `platform:"android"`, `did`, `plugin_level` |

Here `app_level` is the string form of the Android host `appVersionCode`, with
fallback to `appVersion` / `systemInfo.sysVersion`. `plugin_level` is the string
form of `MIOTPackage.version`. These inputs are different from the host
`api_version` of the plugin retrieval. The first method returns `res.list[0]`. The
V2 method keeps the response as `data`. The charger is not one of the three camera
models that have a hardcoded plugin-version exception.

The generic `FirmwareUpgradeAuto.js` consumer (module 11124, `fetchUpgradeInfo`
near `0x26527a`) recognizes:

- Firmware and MCU changelogs.
- OTA status, progress and failure details.
- Optional `accessory[]` updates.

This proves that the host can show these responses. It does **not** show an AD1204
controller-update package. The SDK bundle does not contain the literal
`njcuk.fitting.ad1204`. Its generic BLE startup path still calls
`getLatestVersionV2` for device types 6/16. No firmware update was started. None of
the new lookups has returned a charger-specific result.

## Decompilation

The APK was decompiled locally with the official
[JADX 1.5.6 CLI](https://github.com/skylot/jadx/releases/tag/v1.5.6), using
`scripts/analyze-mihome.ps1` on a copy of the APK that you get yourself. The
decompiled output stays local in the git-ignored `artifacts/` directory. It is
reconstructed code, not the original source, and some methods failed to decompile.

## Remaining questions

- The host decompilation is complete, with some failed methods.
- The [device plugin](mihome-charger-plugin.md) was examined separately.
- Next step: examine the device plugin for its real MIOT property labels and its
  firmware update UI. Keep the generic host SDK capabilities separate from device
  support.
- The host catalog and the generic SDK alone do not show a new active
  miPPS/UFCS/SCP/VOOC enum name, a hidden setting or a thermal-control command.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository. The hashes are recorded for reproducibility.
