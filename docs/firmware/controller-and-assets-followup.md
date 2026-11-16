# Controller paths, stored records and color assets: 0073

The later [secondary-controller follow-up](secondary-controller-followup.md)
maps the SC limit producer. It verifies the failed-write cache behavior against
the original instructions. It also explains the wire and analyzer address
notation and gives fewer blob candidates.

2026-10-15, stage 16. Offline analysis of raw SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`,
495,656 bytes, flash base `0x403000`. The existing reconstructed startup memory
and Ghidra project were used again, with format-specific Python decoders. These
exports give no hardware observations.

## Recovered color images

The file interval `[0x4c7aa, 0x5cf08)` was not explained before. It is exactly
the union of 21 color-image streams / 67,422 bytes. There is no gap or overlap
between those streams. This closes that candidate blob. It does not show that
all other intervals are known. It also does not show that no controller image
exists in a different location.

Aligned 12-byte descriptors contain little-endian `u16 width, height, depth,
RLE-marker; u32 source-pointer`. The measured depth is 16. The original opaque
renderer `0x40e30c` reads RGB565 words. Marker zero means literal pixels.
Otherwise, a matching high byte starts a repeat. Its low byte is the count, and
the next word is the color. An encoded count of zero repeats 256 pixels, because
the original uint8 remaining count wraps. This field is not an animation-frame
count.

[firmware_bitmaps.py](../../scripts/cuktech_pc/firmware_bitmaps.py) decodes this
profile. It exports the encoded, RGB565 and PNG forms, the hashes, the
descriptors and a gallery. The integrated
[unpacker](../../scripts/cuktech_pc/firmware_unpack.py) also exports these
items:

- startup blocks;
- 51 font descriptors / 911 alpha glyphs;
- package components;
- the remaining exact binary slices;
- a source map.

See [usage](../firmware-extractor.md).

[VerifyColorBitmaps.java](../../scripts/ghidra/VerifyColorBitmaps.java) executes
the original renderer and the pure framebuffer-address helper against synthetic
SRAM. All 21 original descriptors and the raw, mixed and zero-count fixtures
agree: 24 cases, 1,317,250 instruction steps, both 16-byte guards intact. The
117 distinct executed instruction records agree with the original image bytes.
The instance-local fixed-Thumb workaround for Ghidra 12.1.4 is the same
documented callback adaptation as in the ADC/thermal verifiers. It does not
change the firmware or the p-code. Execution stops before the outer `POP PC` at
`0x40e32a`, after the drawing is complete. There is no LCD, peripheral, ROM or
full-device execution. The PNGs use standard opaque RGB565 expansion. They do
not include caller-specific transparency or clipping.

Local evidence:

- `artifacts/firmware/color-bitmaps-0073-20261015/manifest.json`, SHA-256
  `7edff3c5be21dc6e8eacdfab3790dc714365b14d2230ece00e8302b3280b6086`.
- `artifacts/firmware/color-bitmaps-verification-20261015/verification.json`,
  SHA-256 `ce497eb6a7c97283274d5a3166fbfcc5ea2b732d40b49a598009d41157b46939`.
  The fixture results and the original instruction records are in the same
  directory.
- `artifacts/firmware/extracted-0073-20261015/index.html`: combined extraction.
  All output hashes and the complete source reconstruction were checked
  independently.
- `artifacts/firmware/extracted-and-decompiled-0073-20261015/`: an independent
  second run of the full extraction and Ghidra workflow. `analysis/decompiled.c`
  contains 1,145 approximate function records. The original startup decoder
  again agreed on 44,744 expanded bytes / 286,474 steps, with the guards intact.

## Thermal labels are recovered graphics

The UI renderer `0x4105b4` selects descriptors through the literal pointers
`0x4107ec..0x41081c`. Then it calls the RGB565 renderer through vtable slot +4.
Initialized SRAM links the renderer object `0x2000c5e8` to vtable `0x47397c`.
The second Thumb entry of this vtable is `0x40e30d`. The language and the
orientation select alternative art.

| Widget stage byte +0x3b | Recovered English art | Recovered Chinese art | Example descriptors |
|---|---|---|---|
| 0 | Excellent | 低温运行 | `0x473f6c`, `0x473f78`, `0x473f60` |
| 1 | High Performance | 高效输出 | `0x47404c`, `0x474058`, `0x474040` |
| 2 | Power limitation | 安全控温 | `0x473f08`, `0x473f14`, `0x473efc` |

Thermometers, lightning and other charging symbols are also recovered. For
other stage values, this renderer returns. This pass infers no stage-3 graphic. These
are the labels of the existing thermal-status page. They are not additional
selectable power modes, protocol enables or an unlocked Beast mode. The thermal
budgets found before stay `[120, 120, 90, 0] W`. No live stage was measured.

## HUSB362: the update-like write is host metadata

The checksummed write routine `0x403f7c` has two known direct call sites.
`0x414f52` sends command 0x85 / four bytes, and `0x414fa0` sends command
0x81 / four bytes. The wrappers `0x414f44` and `0x414f90` log the app-version
and the power-mode operations. These mapped write routes contain no bulk or
chunk updater. This negative result does not cover computed callers, ROM or
separate controller images.

The only known direct caller of `0x414f44` is `0x40a718`, at `0x40a880`. For
port 0 under its one-shot flags, it sends four bytes at `0x2000cf28 + 6`. The
initializer `0x4093cc` fills these bytes with the main MCU revision
(`0x4058bc`) and the boot-record image CRC (`0x405834`). On success, it logs
**Set App Version OK**. With the values reported before, the bytes would be
`73 00 8d 3b`. This is an inference from the fields. It is not a captured
packet. It is a host revision/CRC handoff. It is not a controller-firmware
upload command.

The mapped reads through wrapper `0x405194` / body `0x403ef0` are commands
0x80/81/82/83 with 6/4/16/5 data bytes and a checksum. Their version and status
responses are not an embedded HUSB firmware image.

## Another internal controller value, with no new app temperature

The u16 at offset 6 of HUSB status 0x82 goes through `0x414c70` and the binary
search `0x414c08`. Its 68-entry descending LUT at `0x425074` maps to signed
results 57..124. `0x40a718` gives this value as the fifth argument of `0x405d88`.
`0x405bd8` averages the sums at `0x2000c95c + port*4` into byte 6 of eight-byte
records that start at `0x2000ec18`. Thus the C1/C2 values are at
`0x2000ec1e` / `0x2000ec26`.

Getter `0x405d10` returns the signed maximum of those two bytes. Its known
caller `0x4090a4` calls it at `0x4090aa`. Then it immediately calls `0x417d60`
at `0x4090ae` and does not keep r0. Thus this call does not show that the thermal
policy uses the value. The ordinary MIOT packer `0x4043ac` does not include byte
6. The mapped AF 1/2/6 and combined replies do not return it. The value is
possibly a controller temperature. The units are not confirmed, and there is no
known BLE read path. The app has no guessed C1/C2 Celsius fields.

## SC2021: multiplexed reads, configuration and protection sources

At bus address 0x42, both mapped 17-byte reads use register 0x10. The low bits
of register 0x21 select the view. `0x4152dc` does these steps at intervals:

1. It switches to the NTC/version view through `0x415a78(1, currentMode, 0)`.
2. It waits for at least 101 timer units.
3. It reads through `0x415670`.
4. It restores the normal view.

The timer units were not calibrated. The byte-15 checksum covers bytes 0..14.
Byte 16 is outside that checked range. The routine refuses a zero checksum and a
checksum that does not agree.

| View | Returned source fields |
|---|---|
| Normal polling | C3/A status bytes 0/1; big-endian V/I pairs at 2..5 and 6..9; native protocols 10/11; protection masks 12/13 |
| NTC/version | Big-endian software version at 8..9; NTC ADC words at 10..11 and 12..13 |

The write funnel `0x415b3c -> 0x40410c` writes a register/value with a limited
number of retries. The separated function `0x41631c` combines the limit nibbles
`((arg0 << 4) | (arg1 & 0x0f)) & 0xff` and writes register 0x0e. It logs the
limit mode and an optional readback. The other mapped configuration uses these
registers:

- 0x0c/0x0d for the per-port UFCS/SCP settings;
- 0x20 for the multi/port state;
- 0x21 for the view and the NTC-current mode.

These writes are not firmware payloads.

If C3 protection mask bit 7 is set and the cached configuration is available,
`0x4152dc` applies registers 20, 0e, 21, 0d, 0c again through the stored write
function pointer. This is configuration recovery. It is not a reflash.

`0x4154fc..0x41557f` translates the low four bits of the source masks:

| Source mask bit | Output port status bit |
|---|---|
| 0 | 7 / 0x80 |
| 1 | 6 / 0x40 |
| 2 | 5 / 0x20 |
| 3 | 2 / 0x04 |

The helpers `0x405534` / `0x4055ce` update the C3/A status and the SC aggregate
flags. MIOT keeps the low status byte, so these generic raw bits can get to
ordinary telemetry. Their individual OVP/OCP/OTP names are not known. A zero
value does not prove that all protection channels are healthy. There is no
observed physical fault and no new named alert.

## Stored configuration: separate app IDs, Mi IDs, NV tags and queued actions

The wrappers `0x41c84c / 0x41c854 / 0x41c860` delete, read and write app record
IDs after they add 0x50. The backend translates Mi IDs to NVDS tags
`(MiID - 0x70) & 0xff`. ROM does the storage operations. A tag is not a
physical flash address. The field meanings are only partly known.

| App ID | Mi ID | NV tag | Bytes | Established record purpose / initializer |
|---|---|---|---:|---|
| 1 | 0x51 | 0xe1 | 12 | Main settings/schema; `0x404954`, buffer `0x2000c9e8` |
| 2 | 0x52 | 0xe2 | 8 | Reboot/AC-selector restoration; `0x4049fc`, buffer `0x2000eb67` |
| 3 | 0x53 | 0xe3 | 8 | Port/protocol settings; `0x404918`, buffer `0x2000c9e0` |
| 4 | 0x54 | 0xe4 | 10 | Revision/Holiday state; `0x4048d4`, buffer `0x2000eb72` |

No live NV content and no account or binding secrets were read. The compiled
default bytes at initialized SRAM `0x20001768` contain record 3 and then record
1: `f000f000c000c000` / `0301e0000101000001000000`. These are firmware defaults.
They are not the current values of a charger. Record 1 has migration branches.
No general record editor or restore procedure is known.

The queue worker `0x4217e0` was not identified before. It contains a five-way
measured TBB at `0x421866` / table `0x42186a`. `0x404380(4)` queues action 4.
It does not refer to NV record 4. Action 4 calls `0x404a5c`, which writes record
1 / 12 bytes and record 3 / eight bytes. This closes the ADC Assistant save
queue path from `0x404c08`. The Holiday writer of record 4 is a separate
operation.

## The diagnostic dispatch side effect applies to more than known selectors

The recovered handler `0x41fdc4..0x41fe9d` checks a minimum length and the
`fe dc ba` prefix. Then it calls `0x4050d0(0)` before it checks the
opcode, group or selector. Thus an unknown selector in a valid envelope can also
freeze MIOT packing. The handler does not fully check the length for each selector.
The existing app builders use measured frames and reconnect cleanup. There was
no hardware fuzzing, and there is no new UI for selected queries. The nine-way
TBB of F1 group 1 is now kept. Group 2 combined status and the group 4 mutations
stay as documented. No new BLE route to the thermal stage, the full MCU ADC
result or the HUSB candidate value is known. The generic MCU-info stub is not
evidence of such a response.

## Kept evidence and remaining work

[AuditControllerPaths.java](../../scripts/ghidra/AuditControllerPaths.java)
repairs six measured function boundaries and two TBB tables in a read-only
project. Then it exports 53 exact functions / 2,053 original instruction
records. All instructions and exported tables agree with the raw image. The
decompiler warnings and the merged external helpers stay visible. The original
instructions give the arguments, the discarded return and the frame order
above. The changes to the Ghidra project are discarded.

Local `controller-paths-20261015/` identities:

- `functions.jsonl`: `1dfc938979d60b5ddad5bb4c56a8866aebd439ca3f1ae83ed202c8cb4b68378b`.
- `instructions.jsonl`: `557f051f12b557b10dae3194fc05a158507a52d721538a3a6d5a26b8806c03ce`.
- `analysis.json`: `c0bd3cfd15c1d2cfae66f13ec81c1c44abd5163f66880fc35c3212dee2a424bc`.

Updated [coverage ledger](coverage-ledger.md): 216 focused entries. 198 are
from the unchanged 1,145-entry canonical inventory, and 18 are outside it. 947
entries are not selected. The byte check covers 4,332 instruction addresses /
11,436 unique flash bytes. These are counts of kept selections and bytes. They
are not a percentage of the firmware that is understood. All 44 offline
firmware-tool tests pass. App 0.6.4 does not change.

| Question | Result | Remaining boundary |
|---|---|---|
| What is in the 67 KB gap? | Answered: 21 RGB565 assets, verified against original renderer | Other unclassified data, alternate transparency/composition |
| Can we extract naturally? | Implemented and run: common package/startup/font/color/chunk command | New formats require their own parsers; generated names are not original filenames |
| Is HUSB 0x85 an updater? | Mapped path is four-byte host revision/CRC metadata | No controller firmware dump or complete ROM/computed-call closure |
| Are other temperatures internal? | Candidate per-controller lookup/cache mapped | Units and an actual BLE-return route unresolved |
| What do SC protection bits mean? | Four source/output bit relations retained statically | Per-bit fault names and live behavior unresolved |
| What does queued save action 4 write? | Answered: app records 1 and 3 | Complete record dictionary and ROM flash layout unresolved |
| Any new secret/Beast/protocol unlock? | None established in these routes | Existing experimental labels and hardware checks stay qualified |

The next useful targets are the remaining raw-status consumers and overlays,
the unmapped configuration fields and migrations, and the real controller and
ROM definitions. Live cache and fault behavior and physical calibration need
on-device observations. No charger commands, credentials, resets, setting
changes, thermal overrides or firmware writes were used.

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
