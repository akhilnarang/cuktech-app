# Official plugin feature and write-path audit

Date: 2026-10-16. Target: plugin 1028581/version 60/package 1896060,
project 1.1.10, and charger firmware `2.1.2_0073`.

The vendor plugin has defects in its write paths. Its saved preferences and the
controller state can be different. This audit found no extra charging mode,
temperature command, VOOC switch or power override in the inspected plugin. These are static
findings. There was no plugin execution, BLE command, cloud request or flash.
App 0.7.0 does not change.

## Evidence and scope

The [extraction record](mihome-charger-plugin.md) describes the signed RAM
bundle, SHA-256 `c8d56c24bfc16ebe5eb802d8ac460ae908c1a81a0c4313bc43768f9b16792d04`.
The source references below are lines in the extracted
`javascript/modules/module-NNNNN.js` files under
`artifacts/mihome-cn-20261015/plugin-fetch/`. All populated modules were listed
and searched. The routed pages and request helpers were read in detail. This is
not execution coverage. It is not an audit of the full native Mi Home SDK.

These findings come directly from the extracted plugin source.

Firmware addresses use the raw-image base `0x00403000`, image SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
Canonical `artifacts/firmware/ghidra-final/functions.jsonl` SHA-256:
`eb3415d1a9b8f19f5709bf9c79306244b2674266947724a01e417790e12c9822`.
The original Thumb instructions were also checked for these items:

- The legacy setter.
- The per-port UFCS branches.
- The configuration packer.
- The global UFCS helper.

## The reset step can fail before UFCS is restored

`MHSetting`, module 10370, extends React.Component. Its reset path is:

1. `doSettingResetAction` (1004–1035) sends SIID 2 / AIID 1. When the promise
   resolves, it schedules the protocol refresh after one second
   (981–1000,1029). That callback does not check an action result code.
2. `getSwitchParam(false)` (1039–1046) returns 3. The plugin writes this value
   to legacy 2.7, type 1 (1127–1132).
3. On parsed success, line 1167 calls `turnOnAllProtocolSwitch`. Its batch
   is meant to contain 2.7 = 7 and a screen timeout. But the array construction calls
   `this._getScreenOffMode(displayScreenMode)` at line 1070, before the send.

In the shipped source, this class has no `_getScreenOffMode` method. That
method is in the separate ScreenSettingPage (10448:170). Thus the usual
execution throws an exception before the restore batch gets to the writer.
The shared helper catches callback exceptions (10232:487–496), but it does not
send that batch. The error branches also call `this.setProtocolStatus`, which
does not exist in this class (10370:1084,1144). The real method is in
DischargeProtocol (10391:123).

This is a defect in the source code. It was not reproduced, and there is no
claim that a charger stayed disabled. This trace does not include runtime host
patches, connection failures or later controller initialization.

### Firmware effect: two different state sources

The write of 3 clears legacy UFCS bit 2. The original receiver paths are:

| Path | Address | Effect |
| --- | --- | --- |
| Legacy 2.7 setter | `0x00404d2c` | Updates byte `0x2000c9ea`; a bit 1/2 change invokes both global miPPS/UFCS helpers |
| Global miPPS helper | `0x004096d8` | Changes inverted disable bit 0 in both C1/C2 desired-controller structures |
| Global UFCS helper | `0x00409ee4` | Changes inverted disable bit 2 in both C1/C2 desired-controller structures |
| Controller reconciliation | `0x0040a5f4` | Compares controller readback to desired bytes, then can write them through `0x00414f90` |
| Per-port 2.21 packer | `0x004046f8` | Builds mask from saved bytes `0x2000c9e0/e2/e4/e6`, not live controller state |
| Cache update/get | `0x004043ac` / `0x00405914` | Stores that mask at `0x2000eba0`, then returns it for PIID 21 |

Thus a legacy write can change the desired controller UFCS state, but not the
saved per-port UFCS preference. The per-port setter at `0x00404dd0` calls its
UFCS helper only if the saved bit changes (C1 `0x00404e2e–0x00404e4c`, C2
`0x00404edc–0x00404f00`). If you write the same mask again, this does not prove
that the controller UFCS state is restored.

This proves that there are different state sources and direct side effects of
the calls. It does not show how long the difference stays after scene changes,
cable events or a reboot. It also does not show what a sink negotiates. The
JavaScript calls legacy bit 0 SCP. Its physical consumer is not known.

## Batch replies can hide a failed timer write

The shared setter (10232:461–478) pairs each response with each request. Two
requests and two replies give four entries, and some pairs do not match. The
checker rejects mismatched IDs when both are present (342–353). The read helper
pairs by array position (401–416).

The timer page sends 2.8 (enabled-port mask, u8) and 2.9–2.12 (selected port
minutes, u16) in one batch (10433:626–641). Its callback checks only result 0
(675–691). Thus a success there does not confirm the duration write. The
rollback function only writes a log (643–647). If you enable an empty timer,
the default is 120 minutes (612–624).

Firmware 0073 has no supported PIID 8 setter. The real timer setter at
`0x00414618` handles 9–12. Nonzero minutes become `minutes * 60 - 1`. Zero means
off. The [settings review](status-and-settings-followup.md) also shows that the
outer ACK can replace an internal failure with a success. Thus this does not
predict that PIID 8 always returns an error to the plugin. CUKTECH App uses separate writes and
readback. Keep them separate.

## Protocol writes affect other ports and have activation conditions

Each modern toggle builds all four groups again (10433:1217–1230). Both C1/C2
groups always include `0x08`, the firmware miPPS preference. Thus a change of
only C3/A can request C1/C2 miPPS enabled, if those saved bits were cleared.
This is a cross-port side effect, which is wider than the forced bit found
first. The serializer also discards bits that are not in its UI model.
CUKTECH App keeps unrelated and reserved bits.

The vendor strings (10055:129–130, 10058:129–130) give two useful conditions:

- PPS depends on PD. When PD is off, the page hides PPS
  (10433:1346–1351,1363–1368). The serializer keeps the saved PPS preference.
  That bit alone does not prove that PPS can negotiate.
- After a C3/USB-A protocol change, you must disconnect and connect the cable
  again. The controls show this hint at 10433:1375,1380,1389,1394. This is
  vendor guidance, not an observed renegotiation result.

The modern-page gate uses a strict raw string comparison (10016:254–263)
against `2.1.2_0040` (10013:82). The exact value 0040 and empty versions select
the legacy UI. This does not prove that a property is absent. The legacy
handlers implement SCP/miPPS/UFCS indices 0/1/2 (10391:99–171,278–308). They
show only UFCS (311–364).

## Charts and fault names do not add telemetry

The charts have 60 local slots (10013:110). They update each second
(10010:2490–2497,2530–2577) from a cached power value. That value is calculated
from the 0.1 V/0.1 A port fields (2927–2962). This is not a persistent history,
not watt-hours and not proof of 60 new measurements. The plugin parses and logs
the low protocol bytes (2964–3000). The high bytes give the protocol labels.
This adds no confirmed measurement in addition to the firmware fields that are
already traced.

The generic `FAULT_CODE` export (10232:50–65) includes temperature/AC/DC/PV
names. A limited literal-reference search found no consumer in these modules. The
main-page fault counters are set and reset (10010:143–144,3194–3195), but no
update or render path was found. `fault_charge_protect` occurs only at its
definition (10013:83). These are unused scaffolding. They do not expose thermal
faults.

The cloud timer helpers (10232:500–628) also have no known external callers in
these modules. The debug scene list/delete (10385:525–572) does not show a
working path to create a scheduler.

## Inventory of device calls

| Module | Functionality identified |
| --- | --- |
| 10007 root | BLE/cloud subscriptions, navigation, host OTA configuration |
| 10010 MainPage | SIID 2 reads/subscriptions; scene 2.5, enter 2.14, keep-on 2.15 |
| 10370 MHSetting | Language 2.13, reset 2/1, legacy 2.7 follow-up |
| 10391 DischargeProtocol | Legacy protocol 2.7 |
| 10394 scene page | Scene 2.5 |
| 10433 PortCtlPage | Timers 2.8–12, port enable 2.16, protocol mask 2.21 |
| 10448 ScreenSettingPage | Screen 2.6, idle-off 2.19, direction lock 2.20 |
| 10232 helpers | Shared spec get/set wrappers; unused fault/timer scaffolding |

The map (10013:28–67) covers SIID 1 information PIIDs 1–4, SIID 2 charger PIIDs
1–21 and reset AIID 1. No other device-specific SIID or action, arbitrary RPC
or custom AF08 writer was found. The raw characteristic callback is empty
(10010:597–599). The UUID constants 0100/0101/0102 (10232:121–123) have no
known consumer. The host SDK dependency 10074 is not in the device bundle. This
negative result does not cover the native SDK or dynamic behavior.

## Remaining checks

1. Compare the legacy and per-port state with the real controller settings and
   cable events. This shows how long the difference stays. This report did no
   toggle.
2. Compare the native host spec serialization with the JS callbacks. This shows
   the real response order and failure behavior.
3. Give priority to secondary-controller images and bus transactions, to find
   unknown negotiation behavior. Extracted blobs alone do not prove a supported
   protocol.
4. These items are not resolved: temperature calibration and freshness, the
   consumer of legacy bit 0, ROM recovery and an independent proof of active
   miPPS. No thermal threshold command and no signing bypass for modified
   firmware were found.

The tests and the build of the unchanged app were not run again. Vendor
sources, generated analysis, firmware images and credentials are not in Git.

## Selected source hashes

| Module | SHA-256 |
| --- | --- |
| 10010 | `04ed0a9ae205aac37771d16a3561c4bf24ff0880e1e452f246976db5c21c0894` |
| 10013 | `40fe857767a2ea63fb69bdf52b4652e58998914b00ed12f41bfe03a46017483c` |
| 10016 | `2879461df3ae3a4aa2873b1100e578ef2f5e994cf5e518b34ae55c102ef310a3` |
| 10232 | `248f74b85ad921d199db96c4e4ad5ec6f705f80dac19ad9ef2dcfeb93ff49766` |
| 10370 | `fcd015a16e8934aa2318e31afcaf5916ccae271cc0685290ee721e4af51bb759` |
| 10391 | `3fae0eb9f9ee8c10ca3d70a8b0d8e8f6b6abfca86a8bc9bd9b3bac5eec4458b4` |
| 10433 | `057db56321d7dc0eb3399550bcc129949ab13c96044d37601884697b0d1b34b4` |
| 10448 | `dfa86dbab8795869badd59c7149137a3a84da58bdc69ac3ebed9295057dbb450` |

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
