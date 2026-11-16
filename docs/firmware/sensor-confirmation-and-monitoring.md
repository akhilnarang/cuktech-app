# Sensor confirmation and thermal monitoring: 0073

2026-10-14. Scope: implementation and stronger checks of `0x24` and of other
values. Thermal monitoring and status have the highest priority.
Raw SHA-256: `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
This document adds Android monitoring and static/emulated evidence. Not tested
on a charger. It does not establish the physical calibration.

## Factory calibration and the MCU byte

| Original-code path | Established behavior |
|---|---|
| `0x41478c -> 0x201344` | Loads a 192-byte factory record; checks magic `0x54465043` (`CPFT`), length `0xba`, and a 16-bit stored checksum against ROM routine `0x10a6f6`. The ROM algorithm is outside this OTA. |
| `0x4146ec -> 0x41236c` | Record word `+0xb0` becomes direct reference `0x2000c27c` when record byte `+0x13` is zero or flags at `+8` have bit `0x80`. |
| `0x4146ec -> 0x41234c` | Copies ADC calibration block `+0x14..+0x9b` to context `+0x3c..+0xc3` when byte `+0x13` is zero or flags have bit 0. Record `+0x98` supplies context `+0xc0`, the fallback reference. |
| `0x412248` | Writes default reference 1394 only if calibration-present byte `+0xc4` is zero. |
| `0x41216c(0, sample)` | Uses the direct reference unless sentinel `0x1fffffff`, then context `+0xc0`. The image's initial direct reference is the sentinel. |

For load base `0x403000`, the copied loader has three different addresses:

- Runtime address `0x201344`.
- Original file offset `0x74824`.
- Original flash address `0x477824`.

A separate check found that its 108 code/literal bytes are the same as the
original flash bytes. The charger does not return its factory record,
reference or ADC sample. The 25 reference term, the 1.824 scaling and the RC/RF
comparisons at -20/60/70 make the temperature interpretation stronger. There
is no channel definition that gives the unit.

The vendor reply keeps only eight bits of the result.
`VerifyAdcConversion.java --aliases-only` runs eight scaled inputs on the
direct path and on the fallback path, with synthetic reference 1394:

| Synthetic scaled inputs | Original full signed result | Returned byte |
|---|---:|---|
| 393, 396 | 292 | `0x24` |
| 1350, 1352 | 36 | `0x24` |
| 2310, 2312 | -220 | `0x24` |
| 3266, 3269 | -476 | `0x24` |

All 16 fixtures agree, over 18,548 original instruction steps. A separate
Python script checks each result and each low byte. The emulation does not
include hardware acquisition or ROM. The documented instance-local fixed-Thumb
workaround is kept. The expected model does not replace the original
arithmetic.

These are synthetic inputs, not physical temperature observations. The reported
NTC values 40/41 make 36 a plausible value. They cannot restore the lost bits.
The app shows **“MCU temperature candidate: 36 · 0x24 · units unconfirmed”**.
A signed-byte interpretation also cannot restore the full result or a calibrated
Celsius value.

## Check of the reported values again

The [frames from the user](diagnostics-sample-0073.json) are kept separate from
instrumented measurements. The original code confirms these roles:

| Value | Firmware-confirmed role | Remaining boundary |
|---|---|---|
| NTC2 40 | Converted, filtered shell input `0x2000ceb0`, through `0x415670 / 0x41503c` | Estimated Celsius; physical calibration/location and cache age unverified |
| NTC1 41 | Converted, filtered protection input `0x2000ce7d` | Sensor value, not the protection-state flag |
| AC 1836 mV | Channel-4 ADC engineering value, logged `vac_vol:%d mv`, through `0x4220fc -> 0x411bec` | Sensed proxy, not direct mains voltage |
| Rail 2 | Cached commanded 22 V setting, setter `0x414ac0`, getter `0x414b48` | Not electrical feedback |
| PFC 1 | High control setting; `0x414b5c` stores byte/drives GPIO mask `0x20000`, getter `0x414b54` | Not independently measured PFC state |
| Global 0 | Clear GPIO-derived variant flag, `0x41e5c4` | Not account/server region |
| Default + unbound 0 | False conjunction, `0x40488c` | Does not independently prove binding or identify an account |
| Holiday 0 | Cosmetic startup-artwork setting clear | Persistence/appearance need on-device checks |
| Caps `04 / 07 / 60 / 60` | 55 / 70 / 22.5 / 22.5 W base allocations, translator `0x4092e0`, wrapper `0x4093a2` | Internal 550/700/225 tenths W; not measured output or guaranteed simultaneous totals |
| Revision `0073` | Local constant, `0x4058bc` | Not a secondary-controller version |
| CRC `3b8d` | Boot-record image CRC, `0x405834 -> ROM 0x10c3ae` | Not bootloader version; ROM implementation unavailable |
| SC2021 `0120` | Cached software-version word, logged `[SC2021]Software Version:V%04X` | No inferred dotted/BCD format |
| HUSB `0104 / 4a7f` | Two words from command `80`, reader `0x414e9c` | Roles/format unresolved; caller ignores read failure |
| C1 `07·1b`, native C2 `08·3c` | Corroborated C1/C2 PD Fixed/PPS labels with power hints | Different cache times remain possible; not synchronized contract measurements |

The NTC LUT `0x424f98` maps to units 63..124. The LUT `0x425016` maps to
24..69. The mode changes at about 66/65. In the second LUT, synthetic ADC bins
464..482 give 40, and bins 445..463 give 41. These are arithmetic bins, not raw
samples from a charger. Filters, mode changes, zeros at startup and validity
flags that are not returned make it impossible to calculate back from the
reported caches. Zero means "not available". It does not mean 0 degrees.

## “AI Temperature Control” is a status page

The English table `0x2000c3c8`, index 0, points to `0x475c1a`. The renderer
`0x4105b4` requests that title at `0x410738..0x410740`. The dispatcher
`0x411174` selects it for main-widget page 4. The short-button helper `0x406560`
selects page 4 from pages 2/3, and then goes to overall screen 9. The renderer
uses the thermal stage and the thermometer graphic, which has separate
processing. This path does not show a threshold editor.

In the checked routes, legacy MIOT 2.7 bit 0 is only storage and readback. The
setter `0x404d2c` stores config `0x2000c9ea` bit 7. If only that bit changes,
`TST change_mask,#6` at `0x404d98` skips both protocol callbacks. No supported
thermal threshold write was found. Computed paths and ROM paths are not included
in this result.

## App 0.6.4

- **Read sensors** uses the single sensor request and the reconnect cleanup that
  the app already had. **Read all** keeps the bounded batch. This version adds
  no automatic sampling and no new charger commands.
- Typed readings show these values:
  - NTC estimates.
  - Rail/PFC settings.
  - An unsigned MCU candidate with raw hex.

  The app labels unknown enums and unavailable values clearly.
- Each reply gets its own receive timestamp, with the time offset, and a
  monotonic receive age. The age-display timer runs only when the screen is
  visible. A later version or artwork reply cannot make an older sensor reply
  look new. The receive time does not show the age of the firmware cache.
- The last twelve sensor replies make an in-memory history for the app session.
  If a batch is not complete, the previous thermal snapshot keeps its original
  time. Copied diagnostics contain timestamps, raw frames, MIOT stale state and
  history. They do not contain credentials or a charger address.
- The app shows the thermal stage, active budget and protection state as
  **not reported**. The app explains the firmware budget stages. It does not
  guess the current stage, a protection override or a threshold editor.

`:app:testDebugUnitTest :app:assembleDebug` was successful: **34 tests
passed**, with zero failures, errors or skips. The tests cover these items:

- The exact three reported frames.
- Unsigned MCU bytes.
- Unavailable NTCs.
- Unknown rail/PFC enums.
- Independent monotonic receive ages.

Not installed on a phone and not tested on a charger.

APK: `cuktech-local-0.6.4-experimental-debug.apk` (local build, not distributed), 12,955,014 bytes,
SHA-256 `ee9385e5f0d8696a96679147a18b73d2bcc8b187c561a505bf148281cf3fa9ca`.

## Evidence and remaining checks

[AuditSensorCalibration.java](../../scripts/ghidra/AuditSensorCalibration.java)
keeps 30 exact functions and 294 instruction records. Each instruction byte and
table byte agrees with the raw image in a separate check. A separate check also
compares the copied loader with offset `0x74824`. The decompiler warnings about
the missing ROM are kept. For disputed initializer and control paths, the
original Thumb code is the reference. The read-only processing discards
annotations.

Local `artifacts/firmware/sensor-calibration-followup-20261014/`:
analysis `2d427c5f513929db4442bd0b647f80e90e8228f2813f216895218959b8dbdba8`;
functions `cbab8d071a6c1b50a6746a2877decaa4e435f03ba8acd91e87956355e160bfd9`;
instructions `d7cecf3753da0f369333253cd3a6a1f482dedeb136b737b862117aab26e1979d`.

Alias emulation `artifacts/firmware/adc-24-alias-verification-20261014/`:
summary `8d725edb7f254715736407df4624b62690d24aba9a56a53d7a18f37e8edcaf7a`;
cases `21dd82f26fbb3f1cc2b588eb12db3fa5842afee46876bd54bced49437238a239`.

Open items:

1. A physical NTC comparison.
2. Cache freshness after errors and at startup.
3. Confirmed read routes for the full MCU result, the reference and the
   thermal/protection state.
4. Validation of monitoring, reconnect and history on a phone.

Unresolved units, version roles and protocols need matching ROM, SDK or
controller evidence.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
