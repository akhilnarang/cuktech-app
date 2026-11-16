# Native OTA validation and recovery boundaries

## Target and method

Offline inspection on 2026-10-15 of Chinese Mi Home `11.7.709`, package
`com.xiaomi.smarthome`, APK SHA-256
`73335d3c17dff3e73097db7e2f86a373b7eb2c67611dc82749883ab2da3f0b6e`.
The official AD1204 plugin hands off to this native OTA page. The
authentication routing is in [the plugin follow-up](plugin-debug-and-upgrade-followup.md).

The references below are paths and lines relative to the kept JADX source tree
`artifacts/mihome-cn-20261015/analysis-8g/decompiled/sources/`.
These are static observations of host code. They are not observed AD1204
behavior. There was no account request, BLE connection, download, update,
cancellation or simulated device operation.

## Preflight and package checks

In `com/xiaomi/smarthome/framework/update/ui/BleOTAUpgradeActivity.java`,
`OooOO0o` (lines 207–218) checks the Bluetooth availability function
`up8.OooO0Oo()` of the host. Then it starts this chain: connect → read the
current version → get remote metadata.

- `_m_j/zt0.java:18–21` reads the current version through
  `getBleMeshFirmwareVersion`.
- `_m_j/yt0.java:18–35` rejects a failed read as `OTAException(-200)`. It stores
  a successful result in the device/presenter.

The helper name alone does not mean that the charger uses mesh authentication.

`_m_j/bod.java:408–412` requests metadata through
`XmPluginHostApi.getBleMeshFirmwareUpdateInfo(model,did,...)`.
`com/xiaomi/smarthome/framework/plugin/mpk/PluginHostApiImpl.java:2072–2096`
implements that request with `/v2/device/latest_ver` and `{did}`.
`_m_j/jd1.java:301–318` keeps non-null metadata and any MCU subrecord. Null
metadata becomes code 1, which is the "latest version" condition of the host.
`BleOTAUpgradeActivity.OooOOO0`, lines 220–231, compares the offered and current
versions through `ia8.OooO0o`. The explicit test-URL route skips this
comparison.

The primary download path is:

`kt0.subscribe` → `PluginHostApiImpl.downloadFirmware` → `sl0.OooO00o` →
`pl0.onSuccess` → `z60.run` → `nl0.onResponse` → `jt0.onResponse`.

| Check | Exact evidence and boundary |
| --- | --- |
| Cancelled presenter | `_m_j/kt0.java:18–28` rejects when the destroy/cancel flag is set. |
| Metadata or explicit test URL | `kt0.java:26–43` requires metadata or the existing test-URL path and rejects an empty selected URL with `-303`. The normal path uses metadata `safeUrl`. |
| Download callback success | `_m_j/jt0.java:28–42` requires callback code 0 and a nonempty local path; failure becomes `-301`. |
| Primary-file checksum | `jt0.java:29–56` chooses metadata `md5` (or the separate test MD5) and compares it with the callback's checksum string. Non-null empty/mismatching expected MD5 becomes `-302`; a null expected MD5 bypasses this comparison. |
| Local-file presence | `_m_j/mt0.java:74–79` calls `kze.OooOOOO(path)` before starting the transfer; a false result throws "upgrade file not exist". The exact helper semantics are not expanded here. |
| Optional MCU checksum | `_m_j/pt0.java:25–40` rejects failed/empty-path downloads as `-606`; when expected MCU MD5 is nonempty, inequality becomes `-607`. `_m_j/ot0.java:25–34` additionally checks that the MCU file exists. |

The first Java output for the full APK has a failure stub for `z60.run`. A
targeted JADX simple-mode view recovered the related branch. Only
`classes13.dex` was extracted from the verified APK, to
`artifacts/mihome-cn-20261015/ota-validation-20261015/classes13.dex`:
10,387,868 bytes, SHA-256
`f102f462e1d01e52726eadc3faa86738a3f4946ceadf2718c58f6fa950896860`.
The command used the JADX 1.5.6 JAR and JDK 21, with
`--single-class _m_j.z60 --decompilation-mode simple --no-res --config none`
and one worker. The exit code was 0. No DEX code was run.

The file `z60-simple/sources/_m_j/z60.java` lines 369–388 show the
discriminator-3 callback. On code 0, the callback does these steps:

1. It puts the local `path` into a bundle.
2. It checks that the path is not empty and is an existing regular file.
3. It calls `ia8.OooOOO0(File)` and returns its string as `md5`.

A nonzero status gives a null bundle. The normal source `ia8.java:252–270`
implements that helper. It reads the file in 4,096-byte blocks into
`MessageDigest` and returns 32-character lowercase hex with zero padding.
`cm6.java:391–404` decodes hex `4d4435` to the algorithm name **MD5**. Thus the
callback calculates the checksum from the local file. It does not copy it from
the remote metadata. File or hash failures return an empty string. Then the
usual nonempty expected MD5 rejects it.

The targeted view contains labeled branches and is not original source that
can compile. This local callback branch is readable. Other failed or unclear
branches in this merged synthetic class were not interpreted.

This analysis found no certificate-chain check, no ECDSA signature check and no
signed-package parser in these limited presenter/download handlers. This is not
a claim about the full APK. It does not mean that the charger accepts unsigned firmware. Also,
`framework/update/OTAException.java` labels `-506` as "switch firmware invalid
sign". A host error name alone does not prove the validation flow of the
charger.

## Three different retries

1. **Download callback retry:** `_m_j/e56.java:25–43` retries if the callback
   code is not zero or the returned local path is empty. It stops when its
   shared counter is 2. `kt0.java:32` sets that counter to 1 for the primary
   file, so there are two attempts in total. The optional MCU path
   (`qt0.java:24–26`) does not reset the counter. It usually starts at the
   initial field value 0, so there are three attempts in total. A later MD5
   rejection in `jt0`/`pt0` is not part of this retry wrapper.
2. **Post-transfer discovery retry:** `_m_j/mt0.java:54–68` sets a default count
   of 4. If `timeout > 32`, the count is the integer `metadata.timeout / 8`. It
   retries a `bu0` scan. `_m_j/bu0.java:21–22` starts a 5,000 ms scan. The
   function in `framework/update/OooO00o.java:16–22` retries only
   `BleUpgradePresenter$DeviceNoFoundException`. The counter limits the number
   of extra scan attempts. `_m_j/li.java:47–50` waits 3 seconds between retries.
3. **UI retry:** the `BleOTAUpgradeActivity` fields at lines 86–87 install
   separate retry listeners. `_m_j/yp0.java:15–17` repeats the preflight.
   `_m_j/zp0.java:21–35` starts the upgrade pipeline again. This alone does not
   prove that the transfer continues from a stored byte offset.

[The correlated transfer trace](ota-transfer-framing.md) describes the packet
retries and resume indices of the transfer layer. Do not describe the scan
retry of the presenter as one of these:

- A second transmission of the image.
- A resume of a partly programmed image.
- A restoration of an old image.

## Completion: acknowledgement, then rediscovery

`_m_j/zp0.java:35` runs these stages in sequence: the native update, a
disconnect stage, a 5-second delay and the discovery stage.
`_m_j/cu0.java:53–65` changes transfer callback code 0 into a successful
pipeline value. Errors become `OTAException(code)`. Its progress callback, lines
25–48, shows "installing" at 100%. That display alone does not verify the
running firmware.

`_m_j/xid.java:289–301` disconnects an existing connection before it sends the
next successful stage value. Then the discovery callback
`framework/update/OooO0O0.java:25–59` does these steps:

1. It compares the Bluetooth MAC of the target with a scan result.
2. It reports the **offered metadata version** to the cloud through
   `n3.Oooo0o0`.
3. It stops the scan and completes the observable.

This completion callback does **not** read the running version. It does not
compare the version with the offered image, and it does not check a hash of the
running image. Then `_m_j/au0.java:34–54` resets the presenter stage and calls
`onSuccess` of the activity. That sets `OTA_SUCCESS` at
`BleOTAUpgradeActivity.java:433–435`.

Thus the last scan of this host flow shows only one thing: after a successful
transfer callback, the host found a matching MAC again. It does not prove that
the new application started. It also cannot tell a successful activation from
a fallback to an older image. A future updater must do a new authenticated
version read after it connects again. Only then can it report success with a
confirmed version.

## Cancellation and recovery

`BleOTAUpgradeActivity.onBackPressed`, lines 269–286, shows a confirmation
dialog when the presenter stage is not zero. On destruction (lines 399–424), the
activity does these steps:

- It sets the cancellation flag of the presenter.
- For stage 2, it calls `cancelBleMeshUpgrade(mac)` and disconnects.
- For stage 1 with metadata, it calls `cancelDownloadBleFirmware(selectedUrl)`.
- It can disconnect a connection that it owns. It clears the local
  `KEY.IS_OTA` flag.

`PluginHostApiImpl.cancelDownloadBleFirmware`, lines 1107–1121, removes the
active downloader for the URL from the map and cancels its network request.
`kt0` and `du0` check the cancellation flag before they start their
download/transfer stage. The optional MCU callback `nt0.java:31–52` also
ignores callbacks after cancellation. These are host cleanup actions. They do
not show an abort acknowledgement from the charger, a transactional rollback or
a recovery guarantee after power loss. This analysis does not fully cover the
behavior of scan disposal/cancellation or of all lower-level transfer
callbacks.

In this path, `KEY.IS_OTA` is a boolean activity/operation marker.
`zp0.java:27` sets it, and destruction clears it. This analysis found no stored
image digest, transfer offset, active bank or rollback record in these presenter
handlers. Lower
transport or charger mechanisms can possibly implement resume or recovery.
Those need separate evidence.

Some progress values are estimates. `nt0.java:67–68` sets the progress to 40
and starts a timer on a specific intermediate MCU result. `_m_j/oO0OOo0o.java`
lines 205–214 increase it one time per second, up to 60. Do not use these UI
numbers as exact offsets of the received image.

## Kept file identities

These source-file hashes connect the quoted reconstructions to this analysis.
The vendor source files are ignored artifacts. They are not repository content.

| Relative source | SHA-256 |
| --- | --- |
| `_m_j/eu0.java` | `726c6b202f056cde6b95f7def908e9fedd4dd39d0c217f0dd6ea0f11c5562f97` |
| `_m_j/zp0.java` | `b56c6e70271c88cec019ad09893396b79a97fe2f8ac6fee418e488bc83e9a404` |
| `_m_j/jt0.java` | `12f929b917179d12a7c64348d7ed5c0378409abff1b2e8f236ceb78b14ee4d2e` |
| `_m_j/e56.java` | `cb7ff15454a31a6487cf361e59330f8fed3bbe8a9ce76949ffd80e0fd6fccd49` |
| `_m_j/mt0.java` | `cb8d1fe76501a54095687705a656db54353854619f2d68b9c3e095f2ba53c526` |
| `framework/update/OooO0O0.java` under `com/xiaomi/smarthome/` | `77b49fa219e51ae346dad906f4cbee38b62ae18ecfe243855d428cdeb6e85d41` |
| `framework/update/ui/BleOTAUpgradeActivity.java` under `com/xiaomi/smarthome/` | `67ba6f8d49458ae50646f88027cc4040498106bf0e5ed860fd66ac523b43d91f` |
| `_m_j/z60.java` (failed method stub) | `878dea909ebe3ef141ad9e96d13b7211ae6c8fd069ab1dfb26e0bd16a69e646d` |
| Targeted `z60-simple/sources/_m_j/z60.java` | `9e843dc619a19c818b49c362947b8eddf827995e88fca4e48d6c652f850df1e2` |
| `_m_j/ia8.java` (file-MD5 helper) | `3209162fbea829789464a2f72ca3d4196ad2153cf1b8b1575cb497f10c81a466` |

The [transfer trace](ota-transfer-framing.md) connects these host checks with
the [firmware receiver and activation parser](ota-firmware-receiver-followup.md).
Open items:

1. Prove the restart, resume and interruption behavior on hardware before an
   app updater is implemented.
2. Find an independent ROM/boot recovery.
3. Verify the installed version after reboot.

This document claims no OTA safety or recovery guarantee from the host UI alone.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
