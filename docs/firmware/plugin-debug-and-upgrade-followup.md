# Official plugin debug screen and firmware handoff

## Evidence boundary

Static analysis on 2026-10-15 of the official AD1204 plugin ZIP, SHA-256
`9f1198fb6a096715ae03e3f92afca7cde4fde1b68adfa5ba6f4ed5df61692fe2`.
The cloud metadata gives plugin ID `1028581`, version `60` and package ID
`1896060`. `project.json` gives the application version as `1.1.10`. These are
different identifiers. Do not mix them.

The original `android/main.bundle` is 925,870 bytes, SHA-256
`c8d56c24bfc16ebe5eb802d8ac460ae908c1a81a0c4313bc43768f9b16792d04`.
The references below are line numbers in the extracted modules in the ignored
directory `artifacts/mihome-cn-20261015/plugin-fetch/javascript/modules/`.
These are direct static observations. No JavaScript, charger commands, account
changes or firmware update were run.

## Developer screen: real gate, limited controls

In `module-10370.js` (`MHSetting`), line 75 sets `showDebugItem` from
`isDeveloperAccount(accountID)`. In `module-10016.js`, lines 304–305 implement
this as a check against an embedded allowlist of four accounts. This document
does not give the identifiers, because they are not necessary. Settings lines
390–422 add the developer row. The row opens `DebugInfo` only if the flag is
true and BLE is connected. `module-10007.js` line 83 registers the route.

Thus the developer screen is available only to some accounts. The checked
settings/main-page code for `keyPressTs` and `receMsgDelta` controls the pacing
of property-write responses. It does not give a known tap sequence that enables this
screen.

`module-10385.js` implements these controls:

| Method / lines | Actual effect |
| --- | --- |
| constructor, 61–112 | Displays host/plugin/device versions, subscription results, screen layout and region/language information. |
| `getDeviceSpecInfo`, 168–198 | Reads the cloud device spec through `Service.spec.getSpecString` and logs property/event descriptions. This does not discover extra firmware properties. |
| `changeShowBleConnectingTimeValue`, 454–462 | Toggles a local `Host.storage` preference for plugin connection-time diagnostics. |
| `deleteAuthValue`, 466–522 | Nulls the plugin's `DEVICE_DATA_KEYS` in local storage and through `batchSetDeviceDatas`; then disconnects BLE and exits. This is not evidence of charger unbinding or firmware factory reset. |
| `getTimes` / `deleteTimes`, 525–572 | Loads cloud timer scenes and can remove those scenes. This is not an arbitrary charger command interface. |
| border-width dialog, 375–418 | Changes the plugin UI border width for layout debugging. |
| legal-document rows, 317–336 | Previews bundled agreement/privacy HTML. |

The **device log** switch does not send anything in this shipped code. Its callbacks at lines 300–304 call
`setDeivceLogFUn`, but the body of that method at line 581 is empty.
`getDeviceLogFun` at lines 576–578 only sets a local `retry` argument. This
shipped code does not send a UART or log-enable command. The row is visible,
but do not describe it as working charger logging.

## The host does the firmware update

`module-10010.js` line 2363 calls `Service.smarthome.getLatestVersionV2(did)`.
Lines 2367 and after keep the offered version. The same module reads the
current BLE version with `bleDevice.getVersion(true)` at line 2426. These
handlers do not have a new firmware download API.

`MHSetting` lines 475–516 send an available update to the custom `Upgrade`
warning screen if two conditions are true:

- `showDot2` is true.
- `isChargerWoring()` reports active charging.

That function, at lines 565–590, checks port status `1` and the C3 combined
status `0x11`. In other cases, the plugin opens the host page
`Host.ui.openBleCommonDeviceUpgradePage({auth_type: 4})` directly.

In `module-10451.js` (`Upgrade`), lines 137–143 show that the OK button of the
warning screen also opens the same host page with `auth_type: 4`. The plugin
does not write firmware and does not have a local-image picker. This static
value is a host integration parameter. It is not a recovered flashing protocol.

`module-10007.js` lines 133–138 set up automatic BLE update checks with
`enable:true`, `redPoint:true`, `alertDialog:false`, `authType:5`. This is
different from `auth_type:4` on the explicit page. The API fields and values are
different, and they do not show how the native host interprets them.

## Brand names and remaining gaps

The English localization in `module-10055.js` lines 31/50 calls the internal
scene `sceneMode_Apple` **Hybrid / Hybrid Mode**. The Chinese `module-10058.js`
lines 31/50 call it the digital-ecosystem scene. The Apple variable name, the
example device combinations and the `scene_icon_apple` asset describe a power
allocation scene. They do not detect a phone brand.

A limited case-insensitive search of all extracted plugin modules looked for Samsung,
Huawei, Xiaomi, OPPO, vivo, brand and vendor. It found no other
phone-classification path. This result does not replace or disprove the
separate controller/firmware classification findings. It does not cover native
host code or future plugin versions.

## Native OTA authentication

The native authentication meanings were traced in the same Chinese Mi Home
11.7.709 APK. Java references are relative to
`artifacts/mihome-cn-20261015/analysis-8g/decompiled/sources/`. These are JADX
reconstructions. There was no observation of a live upgrade.

The SDK wrapper `sdk.bundle` lines 4869–4871 sends
`openBleCommonDeviceUpgradePage(params)` to
`MIOTHost.openBleOtaDeviceUpgradePage(params)`. The native route is:

1. `com/xiaomi/smarthome/framework/plugin/rn/nativemodule/MIOTHostModuleCore.java`
   lines 237–253: reads `auth_type` and sends it to the UI provider.
2. `com/xiaomi/smarthome/framework/api/provider/core/RnUIProviderImpl.java`
   lines 325–326: calls `goBleOtaDeviceUpdateActivity`.
3. `com/xiaomi/smarthome/framework/plugin/mpk/PluginActivityHostApiImpl.java`
   lines 311–321: goes to `BleOTAUpgradeActivity` and keeps the integer as
   `arg_auth_type`.
4. `com/xiaomi/smarthome/framework/update/ui/BleOTAUpgradeActivity.java`
   lines 330–366: reads the integer and stores it in the OTA presenter.
5. `_m_j/r1c.java` lines 427–433: uses an existing connection again, or sends
   the stored integer to `_m_j/eu0.java`, `OooO0OO`, lines 42–67.

The last OTA-specific dispatch is explicit:

| Integer | Actual `XmBluetoothManager` call |
| --- | --- |
| 0 | `secureConnect` |
| 1 | `securityChipConnect` |
| 2 | `securityChipSharedDeviceConnect` |
| 3 | `connect` |
| 4 | `bleStandardAuthConnect` |
| 5 | `bleMeshConnect` |
| 6 | `pskConnect` |

Thus the explicit page request of the plugin selects standard authentication at
this dispatch. If the value 5 of the automatic check gets to the same dispatch,
it selects mesh. This does not show which connection the app really used. An
existing connection can be used again.

There is also a catalog override. `BleOTAUpgradeActivity.java` lines 347–348
change the requested value to 6 when `PluginDeviceInfo.Oooo0oO == 2`.
`_m_j/dk9.java` line 214 and `_m_j/la3.java` line 474 export that field as
`bt_is_secure`. It is **not** the different field `bt_bind_style`.

The bundled China catalog has SHA-256
`3c560e1102a209d2b8bcfde66c68f1acc1e9d7ca9e227a71e3e6c923eaafbd1c`.
Its entry `/result/devices/list/8575` for `njcuk.fitting.ad1204` has
`bt_is_secure:0` and `bt_bind_style:2`. Thus that bundled entry does not cause
the PSK override. A runtime replacement of the catalog was not observed. Do not
use numeric definitions from the `BleBindBaseActivity` enum. That enum uses a
different numbering scheme.

Open items:

1. The live charger/host update framing and recovery.
2. Update packages for each controller.
3. Temperature or UART commands outside the routes shown in this plugin.

No update or authentication operation was done.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
