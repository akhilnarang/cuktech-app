# Firmware coverage ledger: AD1204U 0073

Snapshot: 2026-10-16, stage 30. Stage 30 adds verification of the manager and
startup gate and of thermal transitions to the earlier allocation evidence.
This ledger measures the kept evidence. It also records what is necessary to
close each investigation. It does not measure the percentage of the charger that
is understood. Mask ROM is not in the mapped image of the main OTA. No separate
power-controller firmware has been recovered. Static decompilation does not prove
execution.

## Measured evidence

| Measurement | Result | Meaning / limit |
|---|---:|---|
| Raw image | 495,656 bytes | Exact SHA-256 below; independently reopened for this count |
| Discovered canonical function entries | 1,145 | Ghidra inventory, including helpers and imperfect boundaries |
| Entries with pseudocode | 1,145 | Automated decompilation; warnings/merged bodies can still exist |
| Unique entries in fifteen focused exports | 270 | Deduplicated retained selection, **not a human-review count** |
| Focused entries also in the canonical inventory | 245 | Retained selections, not a measure of understanding |
| Revised entries outside that inventory | 25 | Includes repaired startup/controller/configuration and UI helper boundaries |
| Inventory entries absent from these focused exports | 900 | Generated backlog; not proof they were never read in older research |
| Unique byte-checked instruction addresses | 9,685 | Exact original bytes matched; disassembly/semantics are separate checks |
| Unique flash bytes in those instruction records | 25,226 | Overlapping exports counted once; not a whole-image code percentage |
| Calls into `0x00100000..0x001fffff` | 190 distinct target addresses | Candidate ROM region outside OTA; not a ROM function inventory |
| Startup LZ verification | 44,744 bytes matched | Original decompressor emulated for 286,474 instructions, guards intact |
| OPPO/vivo classifier verification | 1,536 synthetic cases matched | 71,168 original instruction steps; both ports / all protocol bytes / OPPO, vivo and zero IDs; does not prove protocol support |
| ADC arithmetic verification | 498 synthetic cases matched | 568,066 original instruction steps; acquisition/physical calibration excluded; instance-local fixed-Thumb emulator workaround recorded |
| Exact 0x24 alias verification | 16 synthetic cases matched | 18,548 original instruction steps; 292/36/-220/-476 all return 0x24, reference 1394 with direct/fallback paths; not physical temperature observations |
| Final thermal correction verification | 5,120 synthetic cases matched | 34,304 original instruction steps; all raw bytes / states 0..8 and 255 / AC selector 0/1; earlier load-state classification excluded |
| RGB565 renderer verification | 24 cases matched | 21 original assets plus three edge cases; 1,317,250 original steps, guards intact; no LCD/ROM/peripherals |
| Status/timeout verification | 1,280 synthetic cases matched | 214,528 original steps; timeout LUT, isolated SC mapping, periodic MIOT packing; UI/ROM/peripherals and surrounding SC driver excluded |
| C1/C2 protocol-enable initializer | 8,192 synthetic cases matched | 212,992 original steps; all boolean enable combinations / original disable bytes / both ports and named-log argument order; negotiation/bus/logger excluded |
| SC2021 write/cache verification | 5,394 synthetic cases matched | 155,243 original steps; 96 byte-matched executed instructions; physical bus/protection replay excluded |
| SC2021 protocol/protection gate | 4,744 synthetic cases matched | 329,500 original steps; 162 executed records; assumes CRC acceptance, stops before register-20 overwrite |
| HUSB polling fields/order | 48 synthetic cases matched | 3,666 original steps; 104 executed records; external calls explicitly stubbed, no transport/memcpy/peripheral execution |
| HUSB settling/reduction | 560 synthetic fixtures matched | 20,906 original steps; 209 executed records; original state/power/cache helpers; no full worker or sequential hardware timeline |
| HUSB control-byte reconciliation | 108 synthetic fixtures matched | 3,582 original steps; 59 executed records; exact write arguments/desired context; external bus/reset bodies excluded |
| Allocation dispatcher/scenes | 1,058 synthetic fixtures checked | 324,790 original steps; 1,877 executed records; 226 independent expected rows plus route/clamp/disable/guard checks; manager/bus/ACK excluded |
| Persistent allocation load class | 1,218 synthetic fixtures matched | 101,009 original steps; 245 executed records; original classifier and companion, scripted current/peak/brand inputs and exact memcmp; scheduler/history production excluded |
| C2 startup callback | 69 synthetic calls matched | 2,235 original steps; 39 executed records; context/state/timestamp checked before scripted reconciliation, including cap0 and retained-context calls |
| Allocation manager | 288 synthetic calls matched | 94,603 original steps; 467 executed records; original elapsed/budget/callback bodies, seven original-allocator projections, all other allocation rows scripted; no physical ACK |
| Thermal stage/dirty | 1,659 synthetic calls matched | 82,987 original steps; 187 executed records; signed thresholds/countdown/counter/stage/dirty and retained-state cycle; corrected input/publisher scripted, graphic lacks independent numeric oracle |
| Historical exact-function misses in the focused exports | 4 distinct requests | `0x406528`, `0x4220fc`, `0x41fdc4`, `0x40868c`; latter is an internal block retained as instructions; older misses remain historical |

The focused exports overlap very much. Their raw counts are 82, 39, 43, 17,
20, 25, 30, 53, 43, 28, 15, 22, 19, 22 and 14. The sum of these counts is too
high for the selection. The stage-11 gap export has 18 requests, 17 exact
functions and 265 instruction records. All its exported instruction bytes agree
with the original image. The earlier 258 display records are part of the later
356-record display export.

Stage 12 repaired the factory renderer that a vtable/tail wrapper calls. It also
repaired its eight-way switch and four draw helpers. The new export contains 20
exact functions and 518 original instruction records. All sixteen SC2021
translation rows and eight switch targets agree with the original table bytes.
The canonical auto-export stays as the same baseline. The five recovered
entries are counted separately, so the denominator does not change.

Stage 14 repairs the thermal evaluator/publisher and the cache-freeze helper.
It keeps 25 exact functions and 708 instruction records that agree byte for
byte. It verifies the thermal threshold/budget tables and the correction-switch
tables. The ADC emulator adds 488 distinct executed instruction addresses. Their
original bytes agree and are in the manifest. The separate 36-byte window of the
correction emulator is verified, but it is not counted as an additional
instruction export. Earlier ledger counts stay as historical snapshots in the
analysis log.

Stage 15 keeps 30 exact sensor/calibration functions and 294 instruction records
that agree byte for byte. The copied factory loader at runtime 0x201344 is
checked separately against file offset 0x74824 / flash 0x477824. Its window is
not added to this flash-instruction count. The NTC lookup and cap-switch tables
agree. The 16 additional alias fixtures are separate from the original 498-case
export. These offline checks give no physical sensor or cache validation count.

The vendor entry miss in the optional gap export belongs to that project copy.
Earlier vendor evidence stays valid in its own scope. The protocol export has no
identity sidecar. The manifest assigns it to this image, and the report shows
that this is different from a checked sidecar hash.

Stage 16 keeps 53 exact controller/configuration/UI functions and 2,053
instruction records that agree byte for byte. The color-renderer emulator adds
117 distinct executed records. Overlaps with the focused export are counted one
time. The 21 color streams fill exactly the earlier 67,422-byte asset gap. A
unified extraction exports all identified formats and the remaining source
chunks. Its source accounting is separate from these instruction counts.

Stage 17 keeps 43 exact status/settings functions / 1,589 instruction records.
The initialized timeout/status emulator adds 299 executed records. Overlaps are
counted one time. The byte tables, the default SRAM and the independent Python
fixture results were checked separately. Native error masks and exported MIOT
status are different domains. App 0.6.5 fixes the confirmed timeout bug.

Stage 18 keeps 28 exact protocol/command functions / 633 instruction records
and 26 executed initializer records. Overlaps are counted one time. The kept
evidence now includes the named-log argument order, the big-endian AF protocol
writes and the action callback behavior. The separate blob inventory assigns
113,990 of 167,942 unclassified source bytes to automated function bodies. This
is not verified-code coverage. It does not prove that the other bytes contain
controller firmware.

Earlier user-reported readings and the later
[three-frame report](diagnostics-sample-0073.json) are reported device
observations. They are kept separate from hardware checks. There was no charger
request, app installation, reset, UART operation or firmware flash for this
ledger.

Stage 29 keeps 22 allocation functions and 2,396 byte-matched instruction
records. Older exports already selected these functions, so the unique entry
count stays at 267. The repaired scene bodies and shared-helper execution add
much instruction evidence. The allocation and load-class verifiers add 1,877 and
245 executed records. Overlaps are counted one time. Together they check 2,276
synthetic cases / 425,799 original steps. The external helper, manager,
scheduler and hardware limits are stated. See
[allocation policy](allocation-policy.md) for the independent expected-row
coverage and the corrected connection-order claim.

Stage 30 keeps 14 transition functions / 572 static instruction records. It
also keeps 39/467/187 executed records from the C2 callback, manager and thermal
verifiers. All agree with the original bytes. The three verifiers have a total
of 2,016 cases / 179,825 steps. Older selections already contained most of these
instructions. Stage 30 adds behavioral checks. It does not claim that all kept
code is new. The manager-base literal inventory agrees with all 38 exact raw
occurrences. This search does not prove that the list of computed or general
writers is complete. See [allocation transitions](allocation-transitions.md) for
the injected-state, scripted-helper and continuous scheduler/bus limits.

## Subsystem closure checklist

| Subsystem | Evidence already retained | Still needed before declaring it checked |
|---|---|---|
| Package, startup and assets | Signed/raw relationship, scatter map, startup and color-renderer comparisons, 911 glyphs / 21 color images, exact source reconstruction | Ambiguous descriptors/padding, transparency/composition and additional formats/startup paths; a full filesystem was not established |
| MIOT properties/settings | Recovered getter/setter dispatch, ACK limitations, port/protocol/timer/display paths | Unsupported/malformed cases, remaining computed dispatch and hardware setting behavior |
| Protocol labels | Complete producer/packer trace, SC2021 translation tables, named enable-bit routes, controlled external 7/8 measurements | Exact names for 9 and other native enums; distinguish controller report from negotiated contracts |
| Sensors/protection | Earlier NTC/ADC/thermal evidence plus native error UI, SC mapping, disabled overwrite and C3 packed-status replacement | Individual fault names, physical calibration, additional read route, actual stage/load-state and full transition/fault combinations |
| Display/buttons | Normal UI, ADC Assistant, artwork, Beast renderer, all eight factory LCD pages and callback registration | Other error overlays, indirect writers, physical activation/appearance and timing |
| Power policy | Scene/rail/PFC consumers, normal scene rows, selected AI/classifier boundaries, manager trigger/gate/callback ordering and thermal dirty/recovery cycle | Remaining lower-tier AI classes, insertion timestamp edge cases, continuous scheduler/worker/bus integration, physical timer scale/ACK/recovery and secondary-controller behavior |
| BLE/authentication/beacons | Ordinary login, vendor paths, SDK beacon encoder, missing-producer searches | State-2 producer, computed callback registrations, live access and actual beacon producer/payloads |
| Storage/reset | App records 1..4 field/enum map, schema migration, orientation/Holiday paths, queued save action 4 writes records 1 and 3 | Reserved fields, complete record dictionary, ROM flash layout and preservation/restore proof |
| DFU | Control/data/parser/verification/worker paths and optional callback guards | Optional callback producers, lifetime behavior, boot-ROM checks and recovery validation |
| Manufacturing UART/debug | Binary parser, commands, UART init and mode entry | Pad/voltage identification, safe physical evidence, protections and verified backup/restore |
| ROM/power controllers | Calls/bus formats, cached candidate and protection values, fixed host-metadata write and SC configuration recovery | Matching ROM/SDK and HUSB362/SC2021 images or full command definitions; no secondary image recovered |

For each remaining entry, do these steps:

1. Follow its inputs, each branch and state transition, the side effects, the
   callers and callees, and the indirect registrations.
2. If the decompiler signatures or boundaries do not agree, keep the exact
   instructions.
3. Give each claim a clear status: static, inferred or hardware.

A subsystem is closed when each checklist item has evidence or a stated
external limit. Pseudocode for its functions is not sufficient. Closure of the
whole device needs the missing components.

The next offline priorities are the remaining protocol enum consumers, other
fault overlays, storage/reset records and callback registrations. Items that
need hardware stay in the list. More scans of the same OTA cannot supply the
missing ROM or controller images.

## Reproduce the count

Inputs: [coverage-inputs-0073.json](coverage-inputs-0073.json).
Tool: [firmware_coverage.py](../../scripts/cuktech_pc/firmware_coverage.py).
Run these commands from `scripts`. The kept local exports must be available.

```powershell
uv run -m cuktech_pc.firmware_coverage ../docs/firmware/coverage-inputs-0073.json --output ../artifacts/firmware/my-coverage-report.json
uv run -m unittest tests_firmware.test_coverage tests_firmware.test_evidence -v
```

The output file must be new. The tool does these steps:

1. It reads and checks the identity of the raw image and the analysis.
2. It hashes each input.
3. It counts entries and overlapping instruction bytes one time.
4. It keeps the missing requests and exports the backlog of unselected entries.

The tool stops if the identity does not agree, or if instruction bytes are
incorrect or outside the image. It does not calculate semantic or hardware
completion counts. Git ignores the generated evidence and the vendor binaries.

Snapshot identities:

- Stage-30 focused functions: `c53f1764df83499d563c2e0364b84cb1a2ac5dbf11b9a6e92e32619a7510a01b`.
- Stage-30 report: `artifacts/firmware/coverage-stage30-20261016.json`, SHA-256 `6a91277be5ecf6144c2c47ecdb83ad791007967932d3e2a25a56703383c09b3e`.
- Stage-29 focused functions: `c77b7a69b80349c53ddf433de5d2270492d3c1bad31c783966926e52b6086172`.
- Stage-29 report: `artifacts/firmware/coverage-stage29-20261016.json`, SHA-256 `347e5c3307ac37f7fc5351ef57327d56bd317e482c6d8a718bd202ef35431969`.
- Stage-28 focused functions: `4aeb27f8c5824d7eaf35e9ebc850ee8522a852d83adef74af09aef08e40b92c8`.
- Stage-28 report: `artifacts/firmware/coverage-stage28-20261016.json`, generated from the updated input manifest.
- Stage-27 focused functions: `0e2129a24d2636f93cbbdf385f7ac2dd28330080ee4f0a74b2d96b63c94465f2`.
- Stage-27 report: `artifacts/firmware/coverage-stage27-20261016-complete.json`, generated from the updated input manifest.
- Stage-26 focused functions: `158b8394367faf2a46c0ad1c0a698bcbbfd67108ce1233ae65f74b9db41e889b`.
- Stage-26 report: `artifacts/firmware/coverage-stage26-20261016.json`, generated from the updated input manifest.
- Raw image: `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
- Canonical functions export: `eb3415d1a9b8f19f5709bf9c79306244b2674266947724a01e417790e12c9822`.
- Stage-11 focused functions: `2c96cab204318abda88f3c3b6da15f6a7b3741130bc0c8a591b3e5d26397a25b`.
- Stage-12 focused functions: `6b845a1f3c567f2d02b5f381fe35d246ca7b7d5fcd4d7b751f128cfdbbcba7f3`.
- Local stage-12 report: `7fedaeb5f520f89c958c13806088bc3e5ed0e69f7154f8056eb11fc3851a8ea2`.
- Stage-14 focused functions: `58174c46547bd775508a9748548cbd16aa2539bd44bcd070e19f65d7c96ee6c1`.
- Local stage-14 report: `e9b9d527c8d1d4fb41046d8ac0aba775edcf19ec59f5cfcd7d5bff2aa578aa99`.
- Stage-15 focused functions: `cbab8d071a6c1b50a6746a2877decaa4e435f03ba8acd91e87956355e160bfd9`.
- Local stage-15 report: `b86a420e5b425b3e6feb0cec6b6e2c813aee58707d6a1f79c131fff479e035b9`.
- Stage-16 focused functions: `1dfc938979d60b5ddad5bb4c56a8866aebd439ca3f1ae83ed202c8cb4b68378b`.
- Local stage-16 report: `bca8b08678a2e34911b974b82303fb54defad8e9acefa0c68a8ed4c76871db96`.
- Stage-17 focused functions: `7c752ee682e7e79ad908e3335a084c00fd0890bf666d55a4ca6243c659166b0d`.
- Local stage-17 report: `f3a9db86dc62e9a989429ab6830585077db2df6957aeceb52976178c48332f1c`.
- Stage-18 focused functions: `a637093ce73026b8cd6bd9d3a4423abffe112006387b8c15aea121c3c825ff53`.
- Local stage-18 report: `14e70c5ec55d51b5bd59622d8afdeab375fd241eb9613c5a4376950e79f9444b`.

Related follow-ups: [protocol labels](protocol-label-audit.md),
[allocation policy](allocation-policy.md),
[allocation transitions](allocation-transitions.md),
[protocol settling/control byte](protocol-settling-and-control.md),
[controller field consumers](controller-field-consumers.md),
[secondary controller cache/bus](secondary-controller-followup.md),
[controller paths and color assets](controller-and-assets-followup.md),
[status and stored settings](status-and-settings-followup.md),
[protocol/command/blob confirmation](protocol-command-blob-followup.md),
[ADC diagnostic](adc-diagnostic-followup.md),
[thermal and capture follow-up](thermal-capture-followup.md),
[sensor confirmation and monitoring](sensor-confirmation-and-monitoring.md),
[factory screens](diagnostic-screens-followup.md),
[DFU/authentication](dfu-auth-followup.md).

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
