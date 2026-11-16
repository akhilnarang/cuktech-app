# Protocol labels and vendor temperature status: 2026-10-14

Target: AD1204U / njcuk.fitting.ad1204, firmware 2.1.2_0073, raw SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
App baseline: version 0.5.5-experimental.
This document adds app version 0.5.6-experimental. The firmware observations
below are static. The new diagnostic is not tested on a charger.

## Per-port protocol display

The app treats byte 1 of properties 2.1–2.4 as an assigned power-cap code. This
is correct. Do not use this byte to identify PD/PPS. The protocol words are
different properties:

- 2.17: high16 = C1, low16 = C2.
- 2.18: high16 = C3, low16 = A.

In each half, the high byte is the protocol code and the low byte is the
related detail byte. The app shows both raw bytes below the readable label.

| Port / code | New display | Evidence and limit |
|---|---|---|
| C1/C2, 07 | PD Fixed | Upstream SINK240 fixed-contract tests; source below |
| C1/C2, 08 | PD PPS | Upstream SINK240 PPS-band tests; source below |
| C1/C2, 09 | miPPS (unverified) | Firmware 0x406364 treats protocol 9 as Xiaomi even without a matching VID; precise miPPS attribution remains inferred |
| C3, 07 | PD | SC2021 base-info routine 0x4152dc forces native code 0x0e on its PD-load flag; translator 0x408fd0 maps it to 07. This does not distinguish fixed PD from PPS on C3 |
| 00 | Protocol not reported | Zero value |
| Other codes | Protocol not identified | Preserved without guessed names |

The native SC2021 translation uses two byte tables at 0x408fe8 and 0x408ff8.
The native codes are a separate namespace: native 08 becomes exposed 03, and
native 0e becomes exposed 07. Thus do not apply a C1/C2 enum directly to the
native SC2021 values. The MIOT update routine at 0x4043ac packs the exposed
records. Sometimes it changes C1/C2 `07 0f` to `01 0f`. The app does not give a
name to that 01 value.

Manufacturer documents confirm that HUSB362 supports PD/PPS and several legacy
protocols. The public brief does not give the CUKTECH command-83 enum. These
public chip features do not show which protocols this charger negotiated with a
specific phone.

Primary sources:
- [Upstream measured property map, PDO-cap halves](https://github.com/zuyan9/ha-cuk-ble/blob/master/docs/properties.md).
  Its older byte-1 protocol guesses do not agree with our firmware power-cap
  trace. Only its independent 2.17/2.18 fixed/PPS measurements support these
  labels.
- [Hynetek HUSB362 brief Rev.1.2](https://www.hynetek.com/uploadfiles/site/219/news/2e70a98f-c05d-4c51-ba5d-1b582d828d15.pdf).

## A vendor BLE status reply contains a temperature

This corrects an earlier statement that the vendor status replies have no
temperature. The identified MIOT getter at 0x405914 still has no temperature
property. But AF00 / AF07 / AF08 gives a different status path.

1. The NTC acquisition 0x415670 reads 17 bytes from SC2021 I2C address 0x42,
   register 0x10. It checks the CRC through 0x4146bc and processes two ADC
   readings.
2. The conversion 0x41503c selects the lookup table 0x424f98 or 0x425016 from
   the NTC current mode. The output offsets are 63 / 24. A filter limits each
   change of the second converted value to 5 or less per update. Instruction
   0x415836 stores the value in RAM byte 0x2000ceb0. These are firmware
   temperature units, interpreted as degrees Celsius. The physical sensor
   location and the accuracy are not verified. This is an internal sensor
   value. It is not the phone temperature.
3. The vendor command handler 0x41fdc4 sends `f1 / group 1 / status 2` to
   0x41c910. Instruction 0x41c928 reads the same RAM byte and stores it at
   payload offset 4 (0x41c92a). The handler sends a 14-byte status payload
   through 0x414288.
4. The encoder at 0x414288 adds the three bytes `fe dc ba` at the start and
   `ef` at the end. The temperature frame is 18 bytes and fits in an MTU-23
   notification.

Status request on AF07 (8 bytes):
```
fe dc ba 01 f1 00 01 02
```
Expected AF08 status reply (18 bytes):
```
fe dc ba 01 f1 02 0a TT <9 other status bytes> ef
```
`TT`, at absolute frame offset 7, is the cached converted NTC byte.
The parser needs the exact length, envelope, response selector, length marker
and terminator. The app reports values outside the mapped range 24..124 as
unavailable. This includes zero at startup. If there is no reply, or the layout
is different, the app reports a failure.

The larger `f1 / group 2` status at 0x41c888 also reads this byte (0x41c8c6).
The byte is at payload offset 10 / frame offset 13. But this frame is 24 bytes,
which is more than the default 20-byte notification payload. Thus the app uses
the shorter mapped status.

## Side effect of the query, and how the app handles it

The common entry of AF07 calls 0x4050d0(0) at 0x41fde2. This sets
`0x2000c9ba=1` and clears the pending MIOT notification mask. While that flag
is set, the MIOT update routine 0x4043ac returns early. Thus a vendor status
query can stop updates of the usual port telemetry cache. The disconnect
handler 0x4165d4 clears that flag at 0x416608.

The app has a **manual experimental temperature read**. It is available after
the usual token login, and only for installed version 2.1.2_0073. The read does
these steps:

1. It subscribes to AF08.
2. It sends only the fixed status request.
3. It accepts only the mapped response.
4. It disconnects and connects again, so that the usual Xiaomi telemetry starts
   again.

If the response times out after the request, the app also disconnects. If the
AF08 characteristic is not present, the read fails and the app sends no query.
The controls are locked while the diagnostic runs. Its timer is separate from
the encrypted session timers, and teardown cancels it. The app has no periodic
temperature polling and no generic factory-command interface.

For these two UUIDs, the Android characteristic lookup searches only AF00.
Writes use the write type that the characteristic supports, through the
serialized GATT queue of the app. The app labels the last requested temperature
as experimental. It does not show it as a value that updates continuously.

## Kept evidence and next checks

App validation: `:app:testDebugUnitTest :app:assembleDebug` was successful. All
20 unit checks passed. Six new checks cover these items:

- Decoding of port halves.
- Ambiguous labels.
- Malformed status frames.
- Unavailable services.
- Teardown after a timeout.
- Locked controls during the query.

The debug APK is version 0.5.6-experimental, version code 19. This validation
does not use the charger and does not prove the physical temperature accuracy.

Local-only pseudocode: `artifacts/firmware/telemetry-followup-20261014/telemetry.c`.
It was made with the installed Ghidra, a copy of the project,
`-readOnly -noanalysis` and `DecompileAt.java`. The original bytes and the
project did not change. A separate check of the raw Thumb code confirmed the
status byte, the packet prefix and the instructions for the disable/reset flag.
There are no live hardware measurements.

Open items:
- Capture AF08 from this charger. Confirm the framing, the Celsius
  interpretation, the sensor location and the reconnection after a query.
- Compare the temperature with the display of the charger. Check invalid values
  and values at startup.
- Capture C1/C2 code 09 with a known Xiaomi miPPS device and cable to confirm
  its name.
- Decode UFCS and legacy protocol codes with controller documentation or a
  meter. Do not infer a protocol from voltage, power, scene, brand or
  enabled-protocol bits.
- If a more exact C3 PPS/proprietary-mode attribution is necessary, recover the
  full secondary controller firmware and command definitions.

## Live readings, 2026-10-14 (user-reported, app 0.6.0)

The user-reported notes below are older than the
[protocol-label audit](protocol-label-audit.md). That audit replaces their
confidence claims:

- 9 is a strong miPPS candidate. It is not independently confirmed.
- `01·0f` does not uniquely prove PD or a 5 V contract.

No original protocol-meter trace comes with these notes. The watt caps for 7/8
have separate controlled upstream sweep evidence. The notes alone do not prove
the exact PDO/APDO pairs.

| Device | Port | 2.17 half | V · A | Reading |
|---|---|---|---|---|
| iPhone | C1 | `07·1b` | 9.1 V · 1.6 A | PD Fixed, 27 W = 9 V × 3 A |
| Galaxy Tab S9 | C2 | `08·21` | 9.3 V · 1.4 A | PD PPS, 33 W = 11 V × 3 A APDO |
| Samsung (2nd session) | C2 | `08·3c` | 18.0 V · 1.8 A | PD PPS, 60 W = 20 V × 3 A |
| Samsung (1st session) | C2 | `07·xx` | — | PD Fixed; Samsung moved to PPS after reconnect |
| Xiaomi tablet alone | C2 | `09·xx` | 5.1 V · 1.8 A | miPPS (agrees with the reading; not proven in firmware) |
| Xiaomi tablet + iPhone on C1 | C2 | `01·0f` | 8.5 V · ~0 A | firmware remap of native `07 0f` (0x4043ac), probably PD 15 W = 5 V × 3 A. The remap condition does not match the `0x03030f0f` mask (see findings-phone.md); not resolved |

- The code meanings 07 = PD fixed, 08 = PD PPS and 09 = miPPS agree with all these readings.
- In all five samples, the detail byte is the PDO power of the contract in watts. The app adds it
  to C1/C2 PD codes ("PD Fixed · 27 W"). INFERRED from samples, not from firmware.
- Vendor status 6 is a cached snapshot. Its native protocol fields can be older than the live
  MIOT 2.17 value.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
