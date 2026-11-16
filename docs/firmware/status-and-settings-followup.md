# Port status, fault presentation and stored settings: 0073

Date: 2026-10-15, stage 17. Scope:

- The consumers of protection and error status.
- The paths that report data from the extra controller sensor candidate.
- The fields and migrations of the app records.

Raw image SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.

All findings below come from offline static analysis or from emulation of
original instructions with a stated scope. There were no charger requests,
setting writes, fault injection, account access, app installation or flashing.

The analysis used the existing read-only Ghidra project and the original bytes.
Separate audits of status/overlay and of storage were compared against the raw
instructions before the conclusions were written.

## Confirmed app defect: screen timeout was off by one

The old UI sent values 4/0/1/2/3 for the labels 1 minute / 5 minutes / 10 minutes /
30 minutes / Always on. The firmware lookup is **one-based**:

| Raw MIOT 2.6 value | Seconds | Correct label | Previous app label |
|---:|---:|---|---|
| 1 | 300 | 5 min | 10 min |
| 2 | 600 | 10 min | 30 min |
| 3 | 1800 | 30 min | Always on |
| 4 | 0 | Always on | 1 min |
| 5 | 60 | 1 min | Rejected by old app validation |

Value 0 is outside the supported enum. For value 0 the lookup falls back to zero
seconds. Do not send 0 as the 5-minute option.

Original helper `0x40476c..0x40477c` computes `uint8(value - 1)`, accepts indices
0..4 and reads the u16 table at `0x424f70`. The exact table bytes are
`2c01 5802 0807 0000 3c00`. The separate vendor handler `0x41ca6c` also checks
`((value - 1) & 255) < 5`.

The MIOT setter at `0x405a98` (PIID-6 arm `0x405b10`) passes the payload byte
unchanged into `0x404fe8(4, value)`. The stores at `0x40501c..0x405028` keep the
raw enum and its computed seconds. Cache update `0x404588..0x40459c` and getter
arm `0x4059a2..0x4059b0` keep the enum. There is no MIOT-specific zero-based
conversion. Timer `0x404ab0` schedules nonzero seconds multiplied by 1000.
Callback `0x4142ec` checks the seconds field.

The physical Keep Screen On toggle of the charger at `0x405f90..0x405fbd` switches
between 1 and 4. Thus it selects **5 minutes ↔ Always on**. The earlier display
report said one minute / ten minutes. That was incorrect, and the report is now
corrected. Scene mode does not have this timeout defect. The app already converts
UI indices to firmware values 1..4 and back.

**App 0.6.5-experimental, code 28:**

- Shared `ScreenTimeout` options give explicit wire values and labels to the picker.
- Controller validation accepts only 1..5.
- Two new unit checks cover the original seconds table and all five real encrypted
  outgoing requests. The tests decrypt each request, check the MIOT PIID/value,
  and then check the matching readback.
- The app rejects the invalid values 0 and 6 and does not write them.
- The existing regression tests for ignored-setting readback are still present.
- All 36 Android tests pass, and the debug build succeeds.

The app does not migrate or write the setting automatically. It shows the current
raw charger value with its corrected meaning.

APK: `cuktech-local-0.6.5-experimental-debug.apk` (local build, not distributed), 12,833,264 bytes,
SHA-256 `2b4d785d686cf38b0a4c7b93cbfbb8bcd7594d5136eefc039dcc64046c5d67b4`.
The appearance on a phone and the physical timeout timing are not verified.

## Fault presentation does not supply individual fault names

UI updater `0x4065c8` tests the native u16 status at telemetry-record +4 with
mask `0x01fc` (`0x406662`). If a masked bit is set, the updater selects widget
state 2 and gives zero voltage and current. If no masked bit is set, native status
bit 11 sets the widget state. Activity is a separate bit-0 test.

Recovered setter `0x41020c..0x410237` is tail-called by wrapper `0x41f8e8`. It
writes widget byte +0x39. If the state changes to a nonzero value, it calls
`0x40fe08` with zero V/I arguments. Renderer `0x40c154` shows these states:

| Widget state | Text in the checked renderer |
|---|---|
| 0 with nonzero cap | Normal V/I/power fields |
| 1 | `-- V`, `-- A`, `--` power |
| 2 or 3 | `00.0 V`, `00.0 A`, `0` power |

The literal words at `0x40c740/744/748/74c/7bc/7c0` and their overlapping
little-endian copies give the placeholders. These branches have no separate
OVP/OCP/OTP label.

Native status bit 5 also enters a special-status mask. Code at
`0x4068b6..0x406918` changes widget state 2 to 3 after >800 timer units, and 3 to
2 after >400. **Both states draw the same placeholders here.** This alternation
does not prove a visible blink. The duration of the timer units is not known.

SC2021 source bits 0/1/2/3 still map to native status bits 7/6/5/2. Their UI
behaviour falls into these groups:

- All of them enter the generic error presentation.
- Mapped bit 5 also causes the timed state alternation.
- Mask `0x84` selects a recovery subset.

These groups do not give individual electrical fault names.

## Native status cannot be used directly as a Bluetooth warning mask

Periodic MIOT packer `0x4043ac` usually sends the low status byte. But if the
status of the fifth internal record `0x2000ec3c` has bit 0 set, **C3 uses the
voltage and current of that record, and the output status is forced to `0x11`**.
The C3 allocation byte still comes from the ordinary C3 record. The
initialization packer `0x414554` packs the low status byte of each ordinary
record directly.

Results:

- The app cannot use native error mask `0x1fc` as `MIOT_status & 0xfc`. The forced
  C3 bit 4 would cause a false warning.
- The native u16 has bits that the low byte does not send.
- Configuration handling at `0x41542a..0x41546a` can replace **all of the native
  status of a disabled SC port with `0x800`**. The earlier low protection flags
  are then lost. Enabled branches clear bit 11. Zero exported error bits do not
  prove that the port is healthy.
- The app copies the raw MIOT words and status. It does not add guessed
  OVP/OCP/OTP names, and it does not report a fault-free condition.

The original-code verification covers every possible low native status byte with
the alternate C3 path inactive and active. Example synthetic input: C1 status
0x80 stays 0x80. C3 status 0x80 becomes 0x11 when the alternate record is active.
This verification goes from memory to packet. No physical fault was captured.

## Recovery has an indexing quirk

Function `0x408f30` scans the native records with status mask `0x84`. For C3/A it
calls the existing configuration setter. For C1/C2 it calls `0x408f6c`. The raw
instructions of that helper at `0x408f74..0x408f84` compute telemetry index
`port | 2` and check `0x84` again. Thus the C1/C2 inputs examine the C3/A records
before the helper sets a HUSB configuration bit. The literal at `0x408fac` is the
same telemetry base `0x2000ec18`.

Do not describe this as a reliable per-port error-clear routine. Do not offer it
as an app recovery action. The later HUSB poll `0x40a718` clears that
configuration bit when its own received status no longer has `0x84`. The physical
behaviour was not observed. It is not known if the cross-port condition is
intentional.

## Extra controller sensor candidate: narrower output boundary

The earlier HUSB lookup/cache candidate is still valid. A 68-entry LUT gives
57..124. The result is averaged into record byte 6, and getter `0x405d10` returns
the maximum. The recovered caller of that getter still discards r0 before it calls
`0x417d60`. The incoming references to the two cache bytes and to the getter are
now recorded.

The periodic packer was run with all 256 values of byte 6. Its output depends only
on the mapped V/I/status/cap fields. The initialization packer and the AF
1/2/6/combined packers were checked statically again. No checked response returns
this extra value, a thermal stage or the full MCU result. The generic MCU-info path
still ends in the existing stub.

This result covers only these output paths. It does not prove that computed
aliases, other ROM services or unwritten handlers are absent. The units are not
known, and no new Celsius field is added.

## Stored-record fields and migration

The app IDs, Mi IDs and NV tags are the same as in the
[previous stage](controller-and-assets-followup.md). The offsets below are inside
each record. They are not physical flash addresses. No live device record was read.
"Reserved/unmapped" means that the checked literal and consumer paths do not show
a meaning. It does not mean that it is safe to change those bytes.

| App record | Offset | Established field |
|---|---:|---|
| 1, 12 bytes, `0x2000c9e8` | 0 | Settings schema marker; compiled default 3 |
| | 1 | Physical-menu Bluetooth switch |
| | 2 | Legacy protocol flags; bit 7's useful charging consumer unresolved, bits 6/5 follow existing miPPS/UFCS enable routes |
| | 3 | Unresolved/reserved |
| | 4 | Scene enum 1..4 |
| | 5 | Timeout enum 1..5 |
| | 6 | Display language |
| | 7 | Physical display orientation, 0..3 |
| | 8 | Screen off while idle |
| | 9 | Orientation lock |
| | 10..11 | Unresolved/reserved |
| 3, 8 bytes, `0x2000c9e0` | 0, 2 | C1/C2 slots: bits 7 PD, 6 PPS, 5 UFCS, 4 miPPS enable controls |
| | 4, 6 | C3/A slots: bits 7 UFCS, 6 SCP enable controls |
| | Odd bytes / other bits | No additional setting meaning established |
| 4, 10 bytes, `0x2000eb72` | 0 | Initializer writes marker 2 |
| | 2..3 | Initializer's stored revision, 0x0073 in this build |
| | 4 | Holiday startup-artwork flag |
| | Other bytes | Unresolved; no extra charging mode established |
| 2, 8 bytes, `0x2000eb67` | 0 | Reset/restoration marker |
| | 1 | Saved AC selector; restoration gated by ROM `0x105e8c` |
| | 2..7 | Unresolved |

The enable-bit names do not confirm provisional active-protocol labels such as
miPPS as a captured negotiated contract. No brightness field was found.

Initializer `0x404954` has two different migration branches.

- Schema 2:
  1. It resets record 3 to the compiled defaults.
  2. It copies legacy bit 5 into both C1/C2 UFCS bits.
  3. It writes record-1 offsets 8/9 as LE word 1.
  4. It changes the schema to 3 and queues save action 4.
- Schema 1: it clears the language byte. That branch does not itself change the
  schema and does not itself save explicitly.

ROM read statuses 6 and 8 restore the defaults. Status 8 first deletes the record.
The default record 1 is `0301e0000101000001000000`. It includes scene 1 and
timeout 1 (five minutes).

Function `0x416168` keeps the physical orientation through `0x404fe8(6, value)`.
It uses LCD command 0x36 with MADCTL bytes that depend on the orientation. This is
orientation persistence. It is not a hidden charging option.

If record 4 reads successfully, the firmware skips initialization. The checked
paths have no updater or validator for its stored revision. **Do not use that
stored revision to identify the current firmware after an OTA.** Use the existing
firmware-version query of the app.

## Reproduction, evidence and remaining questions

[AuditStatusAndSettings.java](../../scripts/ghidra/AuditStatusAndSettings.java)
recovers the widget setter, the physical timeout toggle and the timer callback. It
keeps 43 exact functions / 1,589 original instruction records, typed references
and tables. All exported flash instruction and table bytes match the raw image.
The compiled-default table matches the expanded startup SRAM. Read-only project
processing discards analyst annotations. The earlier 42-of-43 export is kept
separately. The final `status-settings-20261015-complete/` output recovers its
missing timer callback.

[VerifyStatusAndTimeout.java](../../scripts/ghidra/VerifyStatusAndTimeout.java)
verifies 1,280 cases / 214,528 original steps:

- 256 timeout input bytes, including every invalid-byte fallback.
- 512 isolated SC mapping fixtures: all byte-mask values on each port plus all
  16×16 low-nibble pairs, kept initial status bits and 16-byte guards around the
  synthetic record buffer.
- 512 periodic-packer fixtures: every native status byte with alternate C3
  inactive and active, and different values of candidate byte 6.

Python recomputed all expected results separately. All 299 distinct executed
instruction records match the raw image. The final fixtures set the registers and
condition flags explicitly. An earlier run gave the same results but had
uninitialized CY/OV warnings. That run is kept separately from the initialized
verification.

The fixed-Thumb callback workaround changes only the Ghidra emulator instance. The
original p-code and the firmware bytes do not change. This emulator run excludes:
SC reconfiguration and the disabled overwrite, UI and timers, the boot packer, ROM
and peripheral operations. For these, the evidence is static only.

Local identities:

- `status-settings-20261015-complete/functions.jsonl`:
  `7c752ee682e7e79ad908e3335a084c00fd0890bf666d55a4ca6243c659166b0d`.
- Its `instructions.jsonl`:
  `01bc14aefb01b26907160f85a8b9a8fa6b8ac5185d74e7e395e3e69688b93c85`.
- Its `analysis.json`:
  `8d910db05fd06726f9aa39281ec8260b207b227e638cd2a7022fbe68135c4043`.
- `status-timeout-verification-20261015-initialized/verification.json`:
  `2b9af900e44305efc3516d9966d4646f8325ffbbcbc5a4c66f8937b4a5edab0c`.
- Stage-17 coverage report:
  `f3a9db86dc62e9a989429ab6830585077db2df6957aeceb52976178c48332f1c`.

| Original question | Result | Still unresolved |
|---|---|---|
| Can fault bits be named? | Generic native error UI, timed-state group and recovery subset traced; unsafe packed-status interpretation prevented | Individual electrical fault names, intentional recovery indexing and live presentation |
| Can extra sensors be read? | Periodic packer verified; initialization/known diagnostic outputs checked; candidate stays internal in these routes | Units, computed/ROM paths and a legitimate additional read route |
| What do stored fields mean? | Main field map, enum/migration/orientation paths retained; timeout bug fixed | Reserved fields, complete ROM storage layout and live preservation |
| Any additional secret mode? | No new charging unlock established in these paths | Missing controller firmware/ROM and hardware-dependent behavior |

The coverage now keeps 239 focused entries. Of these, 218 come from the unchanged
1,145-entry canonical inventory and 21 are outside it. 927 entries are not
selected. The coverage has 5,530 byte-checked instruction addresses / 14,672
unique flash bytes. These numbers measure the kept evidence. They do not measure
an understanding of the whole device. These findings do not justify physical fault
injection, unsafe override controls or arbitrary memory writes.
