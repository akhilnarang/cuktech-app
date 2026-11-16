# App 0.6.6: official protocol labels and tentative miPPS alias

## Behavior

Version `0.6.6-experimental`, code 29, uses the active renderer table
from the [signed official charger plugin v60](mihome-charger-plugin.md).
The protocol words come from MIOT 2.17/2.18. The allocation, current and voltage bytes
are separate. The app names come from the vendor table, with the exceptions
below. Each nonzero active-port protocol line also shows its raw pair.

| Exposed byte | C1/C2 label | C3 label | USB-A label |
| --- | --- | --- | --- |
| 00 | Protocol not reported; card omits line | Same | Same |
| 01 | 5V | 5V | 5V |
| 02 | 5V | 5V | 5V / QC (unresolved) |
| 03 | QC | QC | QC |
| 04 | AFC | AFC | AFC |
| 05 | FCP | FCP | FCP |
| 06 | SCP | SCP | SCP |
| 07 | PD Fixed | PD | PD |
| 08 | PD PPS | PPS | PPS |
| 09 | miPPS (likely) | PPS | PPS |
| 0a | UFCS | UFCS | UFCS |
| Other bytes | Unknown; card retains raw code | Same | Same |

These are the protocol names that the charger reports. They are not separate
observations of USB wire negotiation. They also do not mean that each code can occur on
each port. The vendor name `5V` does not replace the voltage measurement, which the
charger reports separately.

The `getC1C2ProtocolStr()` function of the official plugin shows 09 as PPS. The app
keeps miPPS for C1/C2 because three sources support it: the Xiaomi classification in the
firmware, PPS-like consumers, and observations with Xiaomi devices. Thus the app shows
"miPPS (likely)" as a tentative alias. The separate `vendorLabel` field is set to PPS.
This change of words is not new proof of negotiation. The copied diagnostics include both
names and the raw `09·xx`.

The official shared renderer calls USB-A 02 "5V". Earlier upstream experiments called it QC.
The app shows this conflict. It does not treat one of the two names as confirmed. The app
does not invent a QC version or a proprietary VOOC/FlashCharge variant. Unknown and future
bytes have no name.

`cap N W` is still limited to C1/C2 codes 07/08 with a nonzero detail byte.
The detail of code 09, the UFCS detail and the SC2021 detail do not become watt caps.
The SC2021 native codes from the AF diagnostics stay in their own namespace.
This table describes the exposed MIOT protocol bytes.

The scene that had the name Apple now shows as "Hybrid (Apple)". Its wire value and
profile do not change. The vendor English localization calls this internal
`sceneMode_Apple` "Hybrid / Hybrid Mode" and gives use cases for Apple products. It is not
a live reading of the device brand. It is not a new allocation mode.

## Implementation and verification

- `PortProtocol` keeps both the app label and the literal official-plugin label.
- Controller cards show the raw pairs next to the mapped names. Unknown names also
  show the raw pair. The unreported/idle behavior does not change.
- The copied diagnostics and the feature guide explain the tentative alias and the
  USB-A conflict. The existing native controller snapshots use the shared decoder.
- The existing fixed/PPS and transport-cache tests stay. New mixed-protocol word
  fixtures check the high and low halves, unknown detail bytes without invented caps,
  and the QC/AFC/FCP/SCP names. A real MIOT response-parser/cache fixture checks that
  09/0a, C3 PD and the USB-A 02 conflict get to the same decoder.

Stage 21 of the [analysis log](../firmware-analysis-log.md) records the app compilation,
the unit-test totals and the APK identity. `testDebugUnitTest` and `assembleDebug` succeed.
All 38 Android unit tests pass, with zero failures, errors or skips. The APK manifest
confirms versionCode 29 / 0.6.6-experimental.

APK: `cuktech-local-0.6.6-experimental-debug.apk` (local build, not distributed), 12833264 bytes.
SHA-256: `598ffa82b66722fc02375d5d82f216e071914226dc9e06edc12a417cd4dbed2b`.

This version adds no new BLE read or write operation, OTA implementation, temperature
threshold or charger control. The APK is a local build. It was not installed on the phone
that was identified earlier as the wrong phone. No live charging-protocol test was done.

## Further plugin findings

The [debug and upgrade follow-up](plugin-debug-and-upgrade-followup.md) records
the account-gated developer screen, the empty device-log callbacks, the plugin-storage
cleanup and the native OTA handoff. These handlers do not give new hidden charger
controls or a working UART log command. The native updater details and the
protocol-negotiation and temperature calibration are separate research tasks.
