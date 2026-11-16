# Thermal pipeline and diagnostic capture: 0073

2026-10-14. Target raw SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
This document uses three sources: replies reported by the user, static checks
of the original bytes and limited offline emulation. None of them is a
calibrated physical measurement.

## What the three reported replies show

The [credential-free capture record](diagnostics-sample-0073.json) keeps the
three full frames and their origin. They agree with the mapped 21-byte version
layout and the 18-byte sensor/controller layouts. The user did not supply these
items: an original BLE trace, timestamps for each field, the app version, the
negotiated MTU or the reconnect result. The capture date is not known. The
record gives the date when the frames were received.

| Source | Decoded value | Interpretation boundary |
|---|---|---|
| Version selector 1 | Revision `0073`, image CRC `3b8d`, SC2021 `0120`, both HUSB pairs `0104 / 4a7f` | CRC is not a bootloader version; HUSB word roles remain unresolved |
| Sensor selector 2 | NTC2 40, NTC1 41, ADC result low byte `24` = 36, AC proxy 1836 mV | NTC Celsius interpretation remains experimental; proxy is not mains volts; ADC byte is not promoted to Celsius |
| Sensor selector 2 | Rail state 2 (22 V), PFC 1, default/unbound 0, hardware-global 0, Holiday 0 | Commanded/control state; default/unbound false does not identify account binding |
| Controller selector 6 | Caps `04 / 07 / 60 / 60`; C1 `07·1b`, C2 `08·3c`, C3/A zero | Allocation, protocol and measured output are different quantities |
| Protocol mask | `0x03030f0f` | **All twelve mapped enables already set**; no additional mapped protocol can be enabled by setting these bits |

With the corroborated C1/C2 labels, the native pair of C1 agrees with PD Fixed,
and the native pair of C2 agrees with PD PPS. The low detail values 27/60 are
controller power hints. They are not the reported instantaneous output
calculations of 13.65/14.45 W. The description "Apple and tablet" does not
give the exact model, charging technology or controller VID of either device.

## Why normal C2 `01·0f` is different from native `08·3c`

The mapped packer has **no `08·3c -> 01·0f` normalization**. Its conditional C1/C2
remap at `0x4044e8..0x40450c` needs native `07·0f` and bit 7 of the port byte at
`0x2000c9e0`/`0x2000c9e2` clear (written by `0x404dd0` from 2.21 bit 0 or bit 8). In other cases, native `08·3c` does not change.

The two paths can have different update times:

1. Accepted AF requests call `0x4050d0(0)` from `0x41fde0..0x41fde2`. This
   clears the pending MIOT notifications at `0x2000c9bc` and sets the freeze
   byte `0x2000c9ba=1`.
2. While the freeze is set, the packer `0x4043ac` returns immediately. The MIOT
   getter `0x405914` continues to return the old packed voltage/current/status
   words at `0x2000eb80 + port*4` and the C1/C2 pairs at `0x2000eba4`. More
   property reads cannot update those words during the freeze.
3. The scheduler `0x409728` runs the controller polling on its own cycle. It
   checks elapsed time >=21 and moves its reference forward by 20 timer units.
   The physical duration of these units is not known.
4. The active-port worker `0x40a718` reads HUSB command `82`, then `83` through
   `0x414dac`. Successful reads go to the native protocol cache
   `0x2000c998 + port*6` through `0x405e5c`. This path has no vendor freeze
   check.
5. Selector 6 copies that native cache. Its SC2021 logging call `0x415060`
   does not refresh HUSB command 83. If bus reads fail, the cache can be old.
6. Disconnect event branch 1 in `0x4165d4` clears the freeze at `0x416608`.

Thus the user report agrees with older packed MIOT values and a native PPS
cache that updated later. The report alone cannot prove the exact sequence or
the negotiation event. Its 8.5 V reading is not synchronized proof of the
native PPS contract. Packing starts again only after a reconnect. The app
already reconnects after its bounded vendor batch.

## Load-corrected shell input

The raw NTC2 byte that AF08 returns is at `0x2000ceb0`. The function `0x4090a4`
first updates a separate load-state byte at `0x2000ceb1`. Its last block at
`0x409292` applies this correction when the **AC-derived selector**
`0x2000ceb2` is zero:

| Updated load state | Correction to raw NTC2 |
|---:|---:|
| 4 or 7 | -10 |
| 5 | -3 |
| 6 | -7 |
| Other states, or nonzero AC selector | 0 |

The return at `0x4092b2` narrows and sign-extends the value to a signed byte.
These are observed firmware units. Do not apply them as offsets to a physical
thermometer. The earlier load classifier depends on the power/protocol state
and the hardware flag. The reported 55/70 W allocations do **not** show its
current load state. The mapped AF08 replies do not contain the state or the AC
selector.

The original TBB `0x4092a0`, table `0x4092a4`, has the entries `02 04 06 02`.
Thus states 4 and 7 have the same -10 target. The repaired decompilation does
not show the shared state-7 case. The original table and instructions are the
reference.

## Four thermal stages and a separate budget

The code `0x408c7c..0x408e43` was merged into another function before. It is a
separate evaluator, which the tail branch of the scheduler calls. It keeps
these values:

- The derived shell input at `0x2000ceb4`.
- The thermal stage 0..3 at `0x2000ceb6`.
- A transition counter at `0x2000cec8`.

The signed-byte upper/lower threshold pairs are:

| AC selector | Hardware-global flag | Stage 0 | Stage 1 | Stage 2 | Stage 3 |
|---|---|---|---|---|---|
| 0 | Nonzero | 73 / -128 | 87 / 70 | 110 / 75 | 127 / 75 |
| 0 | Zero | 80 / -128 | 92 / 75 | 112 / 85 | 127 / 75 |
| Nonzero | Nonzero | 80 / -128 | 96 / 75 | 112 / 85 | 127 / 75 |
| Nonzero | Zero | 80 / -128 | 97 / 75 | 112 / 85 | 127 / 75 |

The tables `0x473e8c` and `0x473e7c` each hold two eight-byte rows. If the
hardware flag is zero, the second row is used. The AC selector comes from the
separate AC-sense path. The hardware-global flag comes from GPIO. The Xiaomi
cloud region and legacy MIOT 2.7 bit 0 are not these selectors.

The stage logic is:

1. If `temperature > upper` (strict), it requests the next stage, in the range
   0..3.
2. If `temperature < lower`, it requests the previous stage.
3. Conditions that qualify increase the counter. Stable conditions decrease it.
4. At 201, the stage changes and the counter resets.

**The initializer `0x4093cc` sets the counter to 200.** In this evaluator, a
change of direction does not reset the counter. Thus this is not a proved delay
of 201 consecutive samples or of a fixed number of seconds. One-unit input
changes also use a 30-call countdown. Larger changes update immediately.

The budget getter `0x4092c0` uses an index into the u16 tables `0x473e68` /
`0x473e70`. Both are `[1200,1200,900,0]`. The units are internal tenths of
watts. The evidence for the units:

1. The shared-register helper `0x4053ac` multiplies a controller power-detail
   byte by 10.
2. The caller `0x409c1c` passes it to `0x409d08`, which stores the per-port
   hint.
3. The allocator `0x4084c8` adds the hints and subtracts them from the thermal
   budget. Then it calls `0x406e30`.

Internally, the budgets are **120 / 120 / 90 / 0 W**. They do not promise a
delivered output, and they are not a separately reported fault. The mapped
status replies do not return the current stage. These traced routes have no
override, and no protection was changed.

## The screen uses a temperature graphic value

The evaluator also interpolates a graphic input against the anchors
`[25,65,75,79]` at `0x473e78`. The publisher `0x406aa4` does these steps:

1. It clamps this input to 25..79 and stores it at `0x2000c937`.
2. It stores the stage at `0x2000c938`.
3. It sets UI dirty bit `0x400`.

The UI updater `0x4065c8` calls `0x41f894`, which writes the main widget offsets
`+0x3b/+0x3c`. The renderer `0x410a28` maps the value to a position on the
thermometer graphic. **This is not a numeric Celsius report.** Keep these three
values separate: the AF08 raw NTC2, the corrected thermal input and the screen
graphic input.

## Reserved bits and remaining protocol work

The kept bit 1 in HUSB PowerMode has a real error-clear function. `0x408f6c`
tests status `&0x84`, sets that bit and calls the reconciler `0x40a5f4`. The
worker `0x40a718` clears it after the status bits clear. It is not an extra
protocol enable. The kept bits 5..7 have no name.

Legacy MIOT 2.7 bit 0 has storage and readback. The limited canonical
literal-pointer/decompiler search found no meaningful consumer. The app does
not show either unknown bit as a toggle.

The protocol negotiation is in the separate HUSB362/SC2021 controllers, which
are not available. If you enable all mapped bits, this does not do these
things:

- Add VOOC/VFCP support.
- Identify unknown active enums.
- Change the advertised contracts.
- Remove the allocation or thermal limits.

Useful next evidence: matching controller firmware or specifications, ROM/SDK
evidence and more on-device captures.

## Reproduce and extend

New scripts: [AuditThermalAndCache.java](../../scripts/ghidra/AuditThermalAndCache.java),
[VerifyAdcConversion.java](../../scripts/ghidra/VerifyAdcConversion.java),
[VerifyThermalCorrection.java](../../scripts/ghidra/VerifyThermalCorrection.java).
Each script checks the hash of the exact raw image and needs a new output
directory. Use the read-only Ghidra project, `-readOnly -noanalysis`, and
`-scriptPath` set to `scripts/ghidra`. The audit adds annotations only to the
in-memory analysis copy. The read-only processing discards those annotations.

Final local audit: `artifacts/firmware/thermal-cache-followup-20261014-complete/`.
It has 25 exact functions from 25 requests and 708 instruction records. In a
separate check, all instruction bytes and kept table bytes agree with the
original image.
Analysis SHA-256 `5d38ca48396a73bf3d523114d029c0a7c2f9818bd2c805f32b9c09632b323dff`;
functions `58174c46547bd775508a9748548cbd16aa2539bd44bcd070e19f65d7c96ee6c1`;
instructions `ea3f258bb99dddd8985ef786533961e645fa123aca68cf0781b0300ea102aefd`.

The final correction block agreed with 5,120 fixtures over 34,304 instruction
steps. The fixtures cover each raw NTC2 byte, states 0..8 and 255, and AC
selector 0/1. This verifies the final signed-byte correction, including state
7 and byte wrap. It does not emulate the earlier load-state classifier. A
separate Python script checked each output and each fixture combination. The
original 36-byte code/table window agreed with the raw image. Local output:
`artifacts/firmware/thermal-correction-verification-20261014-fixed-thumb/`.
Summary SHA-256 `de792f20b047398ab59e599e9ba5403cf98988654be82c80706038ad36887391`;
cases `fb846ec9d2843eea86e40e2c51b9e2097e717aa30f62dbec55b19165829e06bd`.

The ADC emulation runs the original arithmetic helpers for 498 synthetic
sample/reference fixtures, without acquisition. The ARM handler of Ghidra
12.1.4 throws an exception on Thumb calls and table branches when it tries a
context change during execution. The verification scripts replace only that
handler **inside each emulator instance**. The replacement does these things:

- It asserts Thumb mode.
- It aligns an odd PC.
- It keeps the Thumb context.

The original instruction p-code, the arithmetic and the firmware bytes do not
change. The workaround rejects any change to ARM mode. It uses a private API
that can change between versions, and the outputs record it. The installed
Ghidra and its project files are not patched. See the
[ADC record](adc-diagnostic-followup.md) for the exact arithmetic, the
byte-wrap cases and the remaining physical limits.

Open items:

- Observation of the real load state and thermal stage.
- All transitions of the correction state.
- Physical calibration.
- Behavior when the controller bus fails or the data is old.
- Other fault overlays.
- The NV record dictionary.
- The DFU callback producers.
- The missing ROM and controller images.

These findings do not complete the full firmware audit. The app code and its
0.6.3 build did not change. Uncertain ADC units and the stage/load state, which
the charger does not return, did not become new controls.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
