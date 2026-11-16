# AD1204 0073: staged reverse-engineering record

Date: 2026-10-13. Target: the downloaded China-model
`njcuk.fitting.ad1204`, version `2.1.2_0073`. This log records static evidence
in stages. All firmware inspection is static. Stage 11 records later app
readings from the user as a separate source. No request was sent to the
charger in that stage. The firmware is not patched or flashed.

## Stage 1: Identify the artifact and choose the loader

Status: complete. The signed OTA package is 496,995 bytes. Its first 495,656
bytes are the same as the legacy raw image. The raw SHA-256 is
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.

The first words contain stack `0x20047458`, reset `0x00403059` (Thumb), and
the load address `0x00403000` at file offset `0x24`. `R2SF` occurs at `0x28`.
The header is not a standard ELF/PE header. Most code is readable Cortex/Thumb
code. The full image is not encrypted. This does not classify every data region.

The analysis below uses Ghidra 12.1.4 with its raw-binary loader.

Ghidra import: `BinaryLoader`, `ARM:LE:32:Cortex`, base `0x00403000`.
The scripts that reproduce the analysis are in `scripts/ghidra/`. Initial outputs:
`artifacts/firmware/ghidra-analysis/{analysis.json,functions.jsonl,decompiled.c,strings.jsonl,headless.log}`.
The first analysis found 1,039 function records. This is an automatic
count. It does not prove the true number of vendor functions.

## Stage 2: Recover startup copy and compression regions

Status: complete. The result was checked independently against the original
instructions. The startup routine at `0x00403090` reads 16-byte records
between the pointers at `0x004030b8` and `0x004030bc`. These pointers point
to `0x004030e0..0x00403130`. Each record contains source, destination,
output size, and handler.

| Index | File offset | Runtime destination | Output size | Meaning |
|---|---:|---:|---:|---|
| 0 | `0x734e0` | `0x00200000` | `0x140` / 320 | Copy, including vector/pointer data |
| 1 | `0x73620` | `0x00200140` | `0x1270` / 4,720 | Copied executable code |
| 2 | `0x74890` | `0x002013b0` | `0x374` / 884 | Copied executable/startup code |
| 3 | `0x74c08` | `0x20001730` | `0xaec8` / 44,744 | Custom startup LZ expansion |
| 4 | No file bytes | `0x2000c5f8` | `0x3ae74` / 241,268 | Zero-fill/BSS |

Copy handler: `0x004030c0`. Zero-fill handler: `0x004030d0`.
Decompressor: `0x00403b40`. Its token rules, transcribed from Thumb:

- The low two bits of the token give the literal count plus one. Zero takes the next byte.
- The high nibble of the token gives the match length minus two. Zero takes the next byte.
  A result of zero means no match.
- Bits 2–3 give the high distance bits. The value three takes a separate high byte.
- Back references copy forward. They can overlap their own output.
- The output size in the startup table stops decoding.

The Python translation reads 17,434 bytes, ends at file offset
`0x79022`, and writes exactly 44,744 bytes. Six zero bytes follow before the
signing tag at `0x79028`. Expanded SHA-256:
`bcc38ad1cf76d34fe5a5b7ba91b25ab048655a3418f0fee159fb84bbfbb9299b`.

`scripts/cuktech_pc/firmware_unpack.py` extracts these components with
source offsets, runtime destinations, sizes, and hashes. Before automatic
extraction, the script checks the measured startup layout and handler
prefixes. It reports other R2SF layouts as unrecognized. It does not guess.

The Ghidra SRAM model was split. It initializes only the measured
expanded range. BSS stays uninitialized in the static model. The three
copy regions are mapped at their runtime destinations. The new analysis
gave 1,139 function records. Reset continuation `0x002013bc` now resolves
to peripheral initialization and the application startup sequence.

## Stage 3: Correct decompiler dispatch errors

Status: complete for the listed tables. Automatic switch recovery gave
invalid paths through data and unrelated functions. The raw Thumb table
entries were decoded and given to Ghidra as explicit switch overrides:

| Switch instruction | Table | Entries | Purpose |
|---|---|---:|---|
| `0x0040e85c` | `0x0040e860`, byte entries | 4 | Packed character decoding |
| `0x0041b3fe` | `0x0041b402`, halfword entries | 8 | DFU worker states 2–9 |
| `0x0041cd68` | `0x0041cd6c`, byte entries | 7 | UART group 1 commands `0x35..0x3b` |
| `0x0041cd9e` | `0x0041cda2`, byte entries | 7 | UART group 1 commands `0x17..0x1d` |
| `0x0041789c` | `0x004178a0`, byte entries | 5 | Simple-profile write dispatch |

`RepairChargerDispatch.java` applies these analyst annotations in a repeatable way.
The corrected outputs are in `artifacts/firmware/ghidra-final/`, with 1,145
function records. These include compiler helpers and possible false positives.
The pseudocode still contains warnings and ROM calls that are not modeled.
The scripts add function names. These names are analyst labels. They are not
recovered source symbols.

The Ghidra project is
`artifacts/firmware/ghidra-project/AD1204_0073.gpr`.
The memory-block list in `analysis.json` records the actual load locations.
The generic Ghidra `image_base` metadata is zero. Do not use it as the
flash load address for this raw-loader project.

## Stage 4: Map authenticated charger controls

Status: complete for the identified MIOT callbacks. Getter `0x00405914`,
setter `0x00405a98`, get wrapper `0x0041d3c8`, set wrapper `0x0041d41c`.
The property wrappers send requests to charger service `siid=2`. The getter
default is `0xfffff05f`. The getter has no cases above property 21. This
callback has no temperature property. Other transport paths are separate questions.

| Properties | Static behavior |
|---|---|
| `2.1..2.4` | Read four packed port words; read clears corresponding notification-pending bits |
| `2.5` | Read/set scene; firmware's allocation logic handles the four known scenes |
| `2.6` | Read/set screen timeout |
| `2.7` | Read/set legacy protocol byte; only low three bits applied to configuration |
| `2.8` | Read countdown-setting byte; setter falls into unsupported default |
| `2.9..2.12` | Read/set per-port shutdown timers; uint16 minutes, zero cancels |
| `2.13` | Read/set display language |
| `2.14` | Setter returns success with no operation; getter unsupported |
| `2.15` | Read/set USB-A keep-on behavior; handler `0x004145c8` uses `0x383f` (14,399) timer ticks |
| `2.16` | Read/set C1/C2/C3/A enable mask, low bits 0..3 |
| `2.17..2.18` | Read packed protocol/capability words |
| `2.19..2.20` | Read/set idle screen-off and orientation-lock settings |
| `2.21` | Read/set per-port protocol-enable bit groups |

When a value is present, the setter wrapper writes zero over the inner
status. Thus an ACK does not prove that a setting changed. A readback is
necessary. The experimental app already does this readback.

### Newly resolved protocol map

Setter `0x00404dd0`. Driver initialization `0x00409e84` logs the argument
names `miPPsEnable`, `ufcsEnable`, `ppsEnable`, `pdEnable`. Small helpers that
share registers confuse some decompiler signatures. Thus the bit routing was
also checked against the Thumb instructions and the initializer.

| Port | PD | PPS | UFCS | Xiaomi miPPS | SCP |
|---|---:|---:|---:|---:|---:|
| C1 | 0 | 1 | 2 | 3 | — |
| C2 | 8 | 9 | 10 | 11 | — |
| C3 | — | — | 16 | — | 17 |
| USB-A | — | — | 24 | — | 25 |

The numbers are bit positions in `2.21`. A one enables the named protocol in the
configuration path. The driver register disable bits are inverted. C3/A use
`0x004158e8`. Its log names UFCS and SCP. No separate PD/PPS controls for
C3/A are known. The reserved bits are not more controls.

Legacy `2.7`, setter `0x00404d2c`: bit 1 controls miPPS on both C1/C2 through
`0x004096d8`. Bit 2 controls UFCS on both through `0x00409ee4`. Bit 0 is stored
and causes configuration updates. Its full meaning is not known.
The legacy/global controls and the per-port controls can interact. Hardware
readback and protocol negotiation are not tested.

### Reset action

Action callback `0x0041d368` recognizes `aiid=1`. This matches
`reset-setting` in the downloaded specification. The action restores
settings and port configuration, clears timers, and requests notifications.
This action changes the charger state. It is not a discovery request.
No action was sent to the charger.

## Stage 5: Trace OTA, authentication, and diagnostic transports

Status: partly complete. The firmware itself contains these DFU functions.
They are not only in an archived SDK:

- DFU control parser `0x0041ae44`
- data entry `0x0041b13c`
- worker `0x0041b3f0`
- flash fragment write/readback `0x0041b274`
- application event callback `0x00412898`.

Control request framing is `uint16_le command`, `uint8 payload_length`,
then exactly that many bytes. The parser requires total length `3+length`.

| Command | Observed parser behavior |
|---|---|
| 1 | Queues a 5-byte response and initializes/query state |
| 2 | Selects fragment size `0x200` or `0x800` from a link parameter, invokes the preparation callback, and enters transfer state on success |
| 3 | Loads resume state; optional branch recomputes rolling CRC over staged bytes; returns last fragment index and CRC |
| 4 | Requires 4 payload bytes, deletes stored resume record, stores the switch-delay value, and enters image verification |
| 5 | Enters an optional callback-driven state only when both related callbacks exist |
| 6 | Requires 4 payload bytes and an optional callback pair; selects another callback-driven state |
| 7 | Requires 1 payload byte; invokes event 1 and may select the CRC-recompute resume mode |

The meanings of commands 5/6 are not known. Compiled generic support does not
prove that the application configured those callbacks. Command 2 changes the
DFU state. It is not a safe read-only capability query.

BLE dispatcher `0x00417928` routes OTA control/data only when auth state
getter `0x00417bc8` equals 1. Its application callbacks at two other handles
accept states 1 or 2.

Registration trace: initializer `0x00419f50` builds service `0xfe95` and
nine characteristic descriptors at runtime. It then gives them to builder
`0x0041bc64`. The builder writes `0x2800` / `0x2803` attributes. It adds
`0x2902` descriptors for notification/indication characteristics.
Thus the UUID list below is confirmed in this image, separately from
the archived SDK. The ROM stack allocates the numeric runtime ATT handles.
They are not fixed values in the file.

| Characteristic UUID | Property byte | Declared maximum length | Initial routing interpretation |
|---|---:|---:|---|
| `0x0004` | `0x02` | 20 | Read-only information/version characteristic |
| `0x0005` | `0x12` | 4 | Read + notify information/control characteristic |
| `0x0010` | `0x14` | 4 | Login/registration event-control path |
| `0x0019` | `0x14` | 244 | Login/registration reliable-transfer path |
| `0x0017` | `0x18` | 20 | OTA control, write + notify |
| `0x0018` | `0x14` | 244 | OTA reliable data, write-without-response + notify |
| `0x001a` | `0x14` | 244 | Application reliable-transfer path |
| `0x001b` | `0x14` | 244 | Second application reliable-transfer path |
| `0x001c` | `0x14` | 20 | Information/control callback path |

The UUIDs, property bytes, and declared lengths are read directly from the
initializer. Registration callback `0x00413484` copies the allocated handle of
each characteristic into the structure that dispatcher `0x00417928` uses:

- `0x0010` at structure offset 8
- `0x0019` at 10
- OTA `0x0017/0x0018` at 12/14
- application `0x001a/0x001b` at 16/18
- `0x001c` at 22.

Initializer `0x0042165c` registers application DFU event callback `0x00412898`
and the MIOT get/set/action callbacks. Thus the UUID-to-dispatch route is
confirmed in static analysis. This initialization code does not replace
a live GATT inventory of a running charger.

Worker state 3 verifies the package material and signatures. State 4 schedules
the switch. State 5 cleans up and sends cancel event 8. The worker uses parser
`0x0041ab10`, SHA helper `0x004195a8`, and signature wrapper `0x00419534` /
`0x0041c768`. Flash staging includes address `0x7f000` in `0x0041c4c0`. It
does a readback, CRC checks, and a ROM boot-record operation before restart.
The full physical flash layout and a recovery procedure are not known.

CRC routine `0x0041fea4` uses reflected polynomial `0xedb88320`. It complements
the seed and the result. This identifies the CRC family of the rolling transfer.
It does not identify the coverage of the signing-tag checksum. Simple
`zlib.crc32` calculations over the tag only, the raw image, and the raw image
plus tag do not equal the stored tag value `0x54a7664b`.

### UART diagnostic parser

Receive entry `0x0041d1d8` checks for first byte `0x4f` (`O`). It then dispatches
through `0x0041d1a0`. The group byte is at offset 1. The command is at offset 2.
Group 1 uses the two measured tables above. Group 2 includes a flash-read path
(`0x36`) and short configuration read replies (`0x3a`, `0x3b`).

| Group 1 command | Established code behavior |
|---|---|
| `0x17` | Sets a calibration channel from a uint16 at frame offset 6; starts calibration machinery |
| `0x18` | Clears the calibration-running flag when payload byte equals 1 |
| `0x1b` | Calls a diagnostic control with a boolean from frame offset 5 |
| `0x1d` | Logs `sleep current ctrl en`; configures pins/power/sleep test paths |
| `0x35` | Calls a ROM flash operation with frame parameters when offset 13 equals 2 |
| `0x36` | Calls the ROM flash-write path with address/length/data from the frame |
| `0x39` | Handles signed frequency-offset adjustment |
| `0x3a` | Applies/returns a one-byte RF trim/control value |
| `0x3b` | Stores/reads a six-byte persistent parameter record |

The other entries in the two tables go to the default return. These
paths exist in code. The physical UART pins, baud rate, production gating, and
access from BLE are not verified. They are not commands for the app.

### Information/control callback completion

The application registers `0x004216c0` as the `0x001c` callback. Direct Thumb
inspection shows only these immediate responses:

- Command 0 returns the single byte `03`.
- Command 3 returns seven ASCII bytes `HS6621C`.
- Command 8 returns a 62-byte repeated `123456789/` test string. The outer
  dispatcher pages it with the request offset.
- Other callback commands return status 2.

The outer dispatcher handles command 1 through an asynchronous MCU-info path
(`0x00419dec(0xa6)` / `0x0041c128`). No temperature response and no secret
charging mode were found in the immediate callback.

### Compiled DFU trust anchor

The DFU worker pointer at `0x0041b6d8` resolves to a 64-byte P-256 public
point at `0x00424f20` (file `0x21f20`). This point verifies the packaged
server certificate. The server key verifies the developer certificate. The
developer key verifies the image plus signing tag. This internal chain check
is stronger than a check of the two packaged certificates only. It does not
prove a vendor root of trust from a separate source.
The unpacker applies this embedded-root annotation only to the exact measured
raw-image SHA-256. With `--verify`, it exports the point as `embedded-dfu-root.sec1`.

## Stage 6: Recover display assets

Status: complete for the measured font/icon format. Font lookup at `0x0040e5a6`
uses a sorted table. The draw call at `0x0040e8f0` reads the height from the
font descriptor. It reads the width and pixel pointer from the glyph entry.
It then calls RLE renderer `0x0040e5e0`.

Measured descriptor: three uint32 words `{height,count,glyph_table_address}`.
Measured glyph entry: `{packed_utf8_identifier,width,alpha_rle_address}`.
Pixels are repeated `{alpha_byte,run_length_byte}` pairs. The dimensions
give the output length. Thus a guessed next-pointer boundary is not necessary.

A scan of aligned descriptor candidates, with a check of every glyph, recovers
51 descriptors and 911 glyphs/icons. Every accepted table is sorted.
Every identifier decodes as packed UTF-8. Every RLE stream gives exactly
`width*height` pixels. The descriptor identities are inferred. The unpacker
makes the filenames and grouping. They are not recovered vendor filenames.

`artifacts/firmware/unpacked-0073-complete/` contains 1,839 files, including
911 `.rle` blobs and 911 grayscale PNG alpha masks. `fonts.json` records
each descriptor, entry, source offset, dimensions, and pixel hash.
`assets.html` is a local gallery that you can browse. Sample previews show
a circular animation element and a legible `Holiday Version` graphic.
That graphic does not show a separate hidden mode.

`0x0041044c` draws `BEAST MODE`. UI page state 1 in `0x0041113c` selects it.
That page-state number is not evidence of a new MIOT scene.
The labels `AI Temperature Control`, `ADC Assistant`, and `Continue Test` are
present. Thermal processing and the protocol auto-test state machine have
code references. These labels do not prove more remote APIs.

## Stage 7: Validation and remaining work

Status: complete for offline checks. Current portable checks: 23 tests pass (8 existing package
tests plus 15 unpacker tests). The new checks cover these items:

- overlapping/extended LZ matches
- bounds
- malformed RLE
- exact PNG pixels/CRC
- complete compressed streams
- extraction hashes
- refusal to overwrite existing output
- region traversal.

The checks for signed-component recombination and malformed signing boundaries also pass.

The first emulation of the original instructions completed the decoding loop.
It then stopped with a Ghidra `EmulatorHelper` context-state error in `POP {...,pc}` at `0x00403b9c`.
The verification script now stops before that return epilogue, after the output
is complete. Results:

- 286,474 original Thumb instructions were emulated.
- All 44,744 output bytes are the same as the Python result.
- 17,434 source bytes were read.
- The output guards before and after the buffer are unchanged.

The result is in `ghidra-final/decoder-verification.json`. This is offline
instruction evidence for this one function. It is not evidence of execution
on the charger.

The server certificate, developer certificate, and image signature of the
actual package pass against the compiled public point in the firmware and the
packaged keys. See the description above. Root trust from a separate source
is not verified. All raw-image outputs and original hashes are kept. No standard
zlib/gzip stream was admitted in this image. The custom startup LZ and the glyph
RLE are decoded separately.

The complete `scripts/ghidra/analyze-firmware.ps1` runner was run with
a new output directory, `artifacts/firmware/reproduced-0073`. It imported the
unchanged payload, rebuilt the memory map, and applied the dispatch annotations.
It exported 1,145 function records and repeated the instruction comparison
with success. If a script exception occurs, the final artifact/hash checks fail,
even if Ghidra exits with zero.

This log records the command maps and the unknowns. The decoder comparison and
the GATT route map are complete for their stated scope.
This image alone does not confirm these items:

- physical charger validation
- private temperatures
- full asset/screen layouts
- all boot ROM routines
- optional DFU callbacks
- complete firmware recovery.

Primary Ghidra usage reference:
[Headless Analyzer README](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).
Earlier download/authentication research: [firmware research](firmware-research.md).

## Stage 9: Review newer phone/controller work and trace temperature status

Date: 2026-10-14. Review of the current app/source baseline.
Newer reports in `docs/firmware/` add these topics to the original analysis:
phone identity, scene allocation, manufacturing UART, binding/OTA verdicts and factory
BLE paths. The app already corrects port-info byte 1 to an assigned power cap.
It shows the raw protocol bytes from properties 2.17/2.18.

This stage adds readable PD Fixed/PPS labels and keeps unknown raw values.
It traces a cached NTC byte into the vendor AF08 status reply. The AF07 handler
also pauses MIOT cache updates. Thus, after a manual temperature query, the app
disconnects and connects again. The exact frames, source addresses, query side effect,
app behavior and remaining hardware checks are in
[the telemetry follow-up](firmware/findings-telemetry.md). These are static
findings and app code. They are not a successful live temperature reading.

## Stage 10: Expand status decoding, display workflows and app controls

Date: 2026-10-14. Both NTC caches are traced into AF08 status. This includes the
first protection-input sensor, which the first temperature decoder missed.
Five bounded status replies are mapped byte by byte in
[vendor-status-map.md](firmware/vendor-status-map.md) and its JSON companion.
Version replies have a different header and need a larger MTU. These values are
kept separate from voltage/current measurements and fault flags:

- raw controller protocol namespaces
- rail/PFC state
- hardware-global flag
- ADC proxy.

[Display/button tracing](firmware/display-and-hidden-features.md) identifies
the ADC Assistant workflow, the confirm/cancel/continue screens, the charging-advice
animation, and a persistent Holiday boot-graphic selector. Its value-0/1 setter
and returned flag are mapped. No effect on charging power is traced. The normal
button pin-mux index 36 and the manufacturing index 4 use different ROM families.
Equal low-word masks do not prove a factory shortcut with a button press at startup.
The Ghidra exports for this stage were checked against the original raw bytes.

[Beacon tracing](firmware/beacons-and-passive-telemetry.md) finds the
generic encoder and a separate sixteen-byte key. It finds no active charger
object producer and no temperature/brand/power object IDs. Standard token login
auth state 1 is identified. The producer of accepted state 2 is not known.
[Recovery boundaries](firmware-boundaries-and-recovery.md) give the limits of the physical
debug assumptions and of the same-boot DFU cached-verdict candidate. The signed
package was downloaded before. Older statements that no package was available are
no longer correct. ROM and complete recovery are not verified.

App 0.5.7-experimental adds these functions:

- a bounded sensor/controller/version query batch
- two sensor rows
- diagnostics without credentials, for copy
- mapped per-port protocol switches
- the cosmetic boot-artwork setter.

During vendor queries, the app marks ordinary telemetry as stale. It then
connects again to clear the MIOT pause flag in the firmware.
Artwork writes check the returned flag. Protocol writes read back the complete
setting and keep unrecognized bits. The app skips larger version queries at the
default MTU. The device-feature guide separates on-device workflows from
mapped remote controls.

Validation: the Android unit checks and the debug build pass. 27 checks, zero failures.
The new checks cover both NTC fields, version-header exceptions, MTU-dependent query
sequence, unsigned masks/reserved bits, narrow artwork requests, failed flag
readback and refusal of interleaved requests. The full
[capability inventory and pending matrix](charger-capabilities.md) records what
is complete offline and what needs evidence from the charger. No requests were
sent to the charger. No hardware changes. No firmware writes.

## Stage 11: Measure coverage, review app changes, audit label evidence

Date: 2026-10-14. Review of app changes for
protocol-property caching, controller UI and user-reported Xiaomi/Apple/Samsung
readings. The cache/UI changes are kept. A new regression check parses
a charger response before it checks the labels and the writable protocol mask.
The port-card cap decoder now uses separate C1/C2 and C3/A namespaces.
The earlier display helper did this, but the ordinary decoder did not.

The original upstream controlled SINK240 experiment and the manufacturer
HUSB362 material were checked again. External sources corroborate PD Fixed/PPS
codes 7/8 and the use of their detail as a watt cap. Chip support alone does
not define the CUKTECH enum. The new user-reported notes are useful observations.
They do not prove miPPS or exact PDO/APDO pairs by themselves. No protocol meter
was available. Thus the confirmation comes from the firmware only. App 0.6.2:

- restores the label miPPS (unverified)
- marks C3 PD as unverified
- leaves `01·0f` without a name
- shows `cap N W` only for supported C1/C2 7/8.

The app still calculates output watts from voltage/current.
See [protocol-label audit](firmware/protocol-label-audit.md) for each decision.

The new hash-guarded `AuditCoverageGaps.java` ran with the installed Ghidra on a
read-only copy of the existing project. Eighteen requested entries gave seventeen
exact functions. `0x41fdc4` is an explicit missing entry in that copy. The 265
kept instruction records match the unchanged raw image.
The findings are in these files:

- [ADC diagnostic](firmware/adc-diagnostic-followup.md): byte 8 is the low byte
  of a calibrated temperature-style conversion. RC/RF compensation uses it.
  The shared-register helper arguments and constants are traced. The app shows
  it as a raw value. The physical source, units, validity and exact emulation are not known.
- [Factory screens](firmware/diagnostic-screens-followup.md): screen IDs are
  hex `0x80..0x87`. Controller status and an unknown ROM callback can select
  `0x80`. A short release cycles to `0x87`, then `0x81`. The content of each page,
  the callback activation and other fault overlays are not known.
- [DFU/authentication](firmware/dfu-auth-followup.md): optional controls 5/6
  require callback pairs in BSS table `0x2000eb04`. The guards and worker slots
  are recovered. The callback producers/semantics and the auth-state-2 producer are not known.

The [coverage ledger](firmware/coverage-ledger.md) and an offline tool
separate automated discovery, kept selection and byte comparison.
Canonical inventory: 1,145 entries with pseudocode. Four focused exports:
139 unique entries, 137 present in that inventory (about 12% selected), two
revised boundaries outside it and 1,008 unselected inventory entries. This number
does not measure how much of the firmware is understood. Across overlapping exports, 621
unique instruction addresses / 1,658 unique flash bytes match the raw image.
Candidate call targets in the ROM region are counted separately from code in the OTA.
The closure criteria for each subsystem keep the ROM/controller/hardware limits.

Validation: 29 Android unit checks pass and `:app:assembleDebug` succeeds.
13 offline coverage/evidence checks pass. APK 0.6.2-experimental (code 25):
`cuktech-local-0.6.2-experimental-debug.apk` (local build, not distributed), 12,816,880 bytes,
SHA-256 `0f1a8883546afaa3b55d959135cf2283a43e74fc3297069e33fe938d4ef440c5`.
No charger requests, login, phone installation, flash/reset or hardware
UART action. Firmware, APKs, generated exports and credentials
are not in Git.

## Stage 12: Confirm C3 PD and recover factory LCD diagnostics

Date: 2026-10-14. Primary evidence: the firmware and
the existing Ghidra project copy. No charger request, login, reset, flash,
UART action or app installation.

C3 coarse PD category: the firmware link is now explicit. SC2021
polling `0x4152dc` tests status bit 2 and selects the `C3 PD Load` log at
`0x4153c8`. It sets a cached flag to 1. The branch at `0x415494..0x415498`
uses that flag to select native code `0x0e`. `0x41549c` stores the code.
Translator `0x408fd0` maps it to exposed 7. The app C3 label becomes PD. It is
not resolved if C3 is fixed PD or PPS. This direct trace replaces the C3 uncertainty
of stage 11. The association of miPPS with 9 is a strong inference. The names of
active UFCS/SCP are not known. Their configuration-switch names are explicit.

All sixteen SC2021 translation rows are kept in
[machine-readable form](firmware/sc2021-protocol-translation.json). Unknown
names are null. The original bytes prove that the protocol table is `0x408ff8` and the detail
table is `0x408fe8`. Several native codes map to one exposed code. The
out-of-range fallback is also recorded. Nine functions with 27 numeric
references into the protocol cache were reviewed, with some base/pointer consumers.
This index is bounded. It does not resolve every computed access.

Factory screens `0x80..0x87` are LCD tests. They are not more power modes.
Constructor `0x40cd8c` and vtable `0x473860` lead to draw wrapper `0x40cd64`.
It does a tail branch to renderer `0x40cb84`, which the earlier exports did not have. Its eight-way TBB was
rebuilt from the original table bytes. The pages are:

1. version/CRC/identifier
2. eight colour bars
3. solid red
4. green
5. blue
6. white
7. 32 grayscale strips
8. black.

Initializer `0x4093cc` gives callback `0x4164a9` to ROM
`0x11296c(0x0f,callback)`. This closes the earlier registration gap. The physical
trigger is not known. Full traces: [factory LCD findings](firmware/diagnostic-screens-followup.md).

The first word on the version screen is local revision 0x73. Its `C 0X...` word is
the image CRC from MBR lookup `0x405834`. It is not a secondary firmware
version. Its three joined words come from the address. The original copy
instructions repeat address byte 5 and omit byte 2. Thus the printed identifier
is not a canonical MAC. No live address is published or copied into app reports.

Output activity uses status bit 0. Firmware UI `0x4065c8` tests this bit
separately from other status/protection bits. The app no longer treats any
nonzero byte as active output. Regression cases cover `0x80`, `0x04`,
`0x11`, `0x81`. The app does not show inactive output as proof that no device is connected.
The diagnostic copy now includes each raw MIOT port word and status byte.
Unknown flag meanings stay raw. The feature guide describes the factory LCD checks.

`AuditProtocolAndFactory.java` ran on a read-only project copy and
discarded its annotations. Final local export:
`artifacts/firmware/protocol-factory-followup-20261014-verified/`, twenty exact
functions and 518 instruction records. All records match the original firmware
bytes. All sixteen translation rows and eight switch targets were checked
directly against the original tables. Decompilation still warns about absent ROM
`0x10452a`. For disputed shared-register signatures and boundaries, the original
instructions are the evidence. Not executed on hardware.

The [coverage ledger](firmware/coverage-ledger.md) is updated: 152 unique focused
entries, 145 present in the unchanged 1,145-entry canonical inventory, seven
recovered/revised entries outside it, 1,000 unselected inventory entries.
Deduplicated instruction checks cover 1,139 addresses / 3,090 flash bytes.
These numbers count selected evidence. They do not measure firmware completion.

Validation: app 0.6.3-experimental (code 26). Thirty Android unit checks pass,
the debug build succeeds, and thirteen offline coverage/evidence checks pass.
APK `cuktech-local-0.6.3-experimental-debug.apk` (local build, not distributed), 12,933,428 bytes,
SHA-256 `781169d22f98ef1edf9ede8994acc2a21f5584478e682ee87de6dcfb89b913ee`.
Firmware, APKs, generated exports and credentials are not in Git.

## Stage 13: Check OPPO/vivo recognition and VOOC possibility

Date: 2026-10-14. Question: are OPPO/vivo and VOOC-style protocols also
present? Inputs: the raw image, the verified startup expansion, the canonical
exports and a read-only copy of the Ghidra project.

OPPO/vivo brand recognition is confirmed. It does not depend on the protocol
byte. `0x406364` matches controller-reported ID `0x22d9` to class 4 and
`0x183d` to class 5. The name table and the popup renderer resolve these to
OPPO/vivo plus `Charging` and a cable-current label. The mapped callers of the
classifier are the UI loop and a load-policy classifier. The load-policy
classifier has an Apple case. Its selected body has no protocol-selection
branch for OPPO/vivo.

The new `VerifyBrandClassifier.java` emulated the original instructions for
1,536 synthetic cases: C1/C2, every protocol byte 0..255, and OPPO/vivo/zero
IDs. Results:

- OPPO returned class 4 in every case.
- vivo returned class 5 in every case.
- Zero ID returned Xiaomi class 1 only for protocol 9. In all other cases it returned zero.

All results matched over 71,168 instruction steps. The emulator stops before
the selected BX LR. It executes no ROM/peripheral/negotiation code. It does not
validate actual phones. Its 160-byte code/literal window matches the original raw
image. The output records were checked for all expected combinations.

Hynetek's [HUSB362 announcement](https://en.hynetek.com/2602.html)
lists a configurable VOOC chip capability. This is a real lead.
It does not prove the programmed controller configuration of CUKTECH or an active enum.
Primary OPPO/vivo material separates their branded charging technologies
from PD/PPS. [CTTL](https://gma.caict.ac.cn/en/plat/cttl-t/major-mobile-phone-manufactures-in-China-fully-support-ufcs-fast-charging)
also lists UFCS products from both brands. Thus an OPPO/vivo charging popup
does not prove VOOC/FlashCharge.

UTF-8/UTF-16LE searches across the raw image and the expanded startup block find
none of these strings: VOOC/SuperVOOC/SVOOC, FlashCharge/VFC/VFCP, SFCP/MTK/PE, or Chinese
flash-charge phrases. These items were checked again:

- the C1/C2 initializer with the named miPPS/UFCS/PPS/PD disable bits
- the four-byte power-mode write
- the C3/A UFCS/SCP setters.

No explicit VOOC/VFCP toggle or returned-enum definition was found in this scope.
Missing strings and kept/reserved bits do not prove an absence. They also do
not prove a hidden protocol. The app labels do not change, because target
support is still not known. No new app build or app test run was necessary.

Detailed evidence, limits and source attribution:
[OPPO/vivo/VOOC audit](firmware/oppo-vivo-vooc-audit.md).
Local verification directory:
`artifacts/firmware/brand-classifier-verification-20261014-verified/`.
Summary SHA-256 `b44c99ebf688db0e59c288f11dcd9238844d827da69aa52d48a14bd7127c693b`;
case-record SHA-256 `db5d9780c9b49da544069e76449b46f035824f7a3392231ea291a7a8565faac3`.
The evidence-selection counts do not change from the stage-12 baseline. This
stage adds bounded instruction emulation. It does not give a new firmware percentage.
No hardware request, installation, login, reset or flash.

## Stage 14: User-supplied readings, independent cache timing and deeper thermal policy

Date: 2026-10-14. Inputs: the same raw image and the read-only
project. A diagnostic report from the user gives normal MIOT readings and three complete AF08 frames.
The [capture record without credentials](firmware/diagnostics-sample-0073.json)
records the provenance, the exact frames and the missing timing/MTU/app-version evidence.
Selectors 1/2/6 agree with the existing 21/18/18-byte layouts. This does not
validate physical sensor accuracy or reconnect behavior.

All mapped protocol enables are already on. The reported `0x03030f0f` sets all
twelve known bits. Native C2 `08·3c` supports the existing PD PPS label at its
cache time. Normal C2 `01·0f` is not a known normalization of that pair.
Two chains were followed separately: the freeze/helper/packer/getter chain and
the HUSB poll/reader/cache chain. Vendor queries freeze the packed MIOT voltage/current/
status/protocol words. Controller polling can continue to update the native pairs.
Thus the report can contain values from different cache times. It does not prove an exact
order or a synchronized contract. Failed bus reads can leave native values
stale. A disconnect clears the freeze. The app already does this.

A separate thermal evaluator was recovered. When the AC-derived selector is zero,
its load-corrected shell input subtracts 10/3/7/10 in updated load states 4/5/6/7.
Four thermal stages use upper/lower tables that depend on the variant and AC.
Their internal budgets are 120/120/90/0 W. A transition counter changes stages at 201.
Startup sets it to 200, and stable samples decrement it. Thus it is not
201 consecutive samples. It is also not a proved fixed-time delay. The mapped
AF08 frames do not return the stage/load state. The 55/70 W caps do not show it.

The screen thermometer uses a separate interpolated graphic input, clamped to
25..79. It is not a numeric Celsius display of raw NTC2. Explicit boundaries
and the original bytes resolve the shared-register and merged-function
decompilation problems. The state-7 correction shares the state-4 TBB target.
The decompiler omits that shared case. Thus the original code and the emulation
are the evidence for it. HUSB PowerMode bit 1 is an error-clear handshake. It is
not one more protocol bit. Bits 5..7 and legacy MIOT 2.7 bit 0 have no known useful
control meaning.

The new [AuditThermalAndCache.java](../scripts/ghidra/AuditThermalAndCache.java)
exports 25 exact functions and 708 instruction records. Every kept
instruction/table byte matches the raw image. The read-only project
processing discards the annotations. Local directory:
`artifacts/firmware/thermal-cache-followup-20261014-complete/`.

The new [VerifyAdcConversion.java](../scripts/ghidra/VerifyAdcConversion.java)
executes the original calibration arithmetic for 498 synthetic fixtures over
568,066 instruction steps. The fixtures include fallback/direct calibration, rounding
boundaries and negative/large results. Python reproduces all
results and byte checks. The reported `0x24` equals 36 and fits the internal-temperature
candidate. The charger does not return the actual sample/calibration. Negative/full-width
results alias into positive bytes. Thus no third Celsius label is added.

The new [VerifyThermalCorrection.java](../scripts/ghidra/VerifyThermalCorrection.java)
executes the final correction block for 5,120 synthetic cases over 34,304 steps:
all raw bytes, updated load states 0..8/255, AC selector 0/1. Every result matches
the separate model, including state 7 and the signed-byte wrap. Earlier load
classification, sensing and actual thermal transitions are not included.

The ARM mode callback of Ghidra 12.1.4 failed on calls/table branches. Both scripts
use a documented fixed-Thumb workaround, local to the instance:

1. Assert Thumb.
2. Align the PC.
3. Keep the existing Thumb context.

The original instruction p-code/arithmetic and the firmware bytes do not change.
The workaround uses a private emulator API and rejects ARM transitions.
The installed Ghidra and the project files are not patched. Failed first
exports are kept separate from the verification directories that succeeded.

The [coverage ledger](firmware/coverage-ledger.md) is updated: 165 unique focused
entries, 155 of the unchanged 1,145 canonical entries, ten recovered/revised
entries outside the inventory, 990 unselected entries. The byte checks cover
2,297 instruction addresses / 6,126 unique flash bytes. These numbers count kept
evidence. They do not measure how much of the firmware is understood. Local stage-14
report SHA-256 `e9b9d527c8d1d4fb41046d8ac0aba775edcf19ec59f5cfcd7d5bff2aa578aa99`.

Detailed paths, tables, identities and open questions:
[thermal/capture follow-up](firmware/thermal-capture-followup.md),
[ADC follow-up](firmware/adc-diagnostic-followup.md). Thirteen offline research
checks pass. App 0.6.3 and its APK do not change. No device command, login, app
installation, setting write, reset or flash. This stage does not claim an extra
protocol toggle, a protection override, a Beast-mode entry or a custom-flash route.

## Stage 15: Confirm field roles, trace factory calibration, implement monitoring

Date: 2026-10-14. Scope: thermal code and stronger confirmation.
Thermal monitoring and status come first. Inputs: the exact image, the
rebuilt startup regions and the read-only Ghidra project. No device commands,
calibration writes, login, installation, reset or firmware flash.

`0x24` is decimal 36. It is not proof of 36°C. The provenance of the factory
calibration is now mapped:

- checked 192-byte CPFT record
- direct reference +0xb0
- ADC block/default fallback reference
- initial sentinel
- default 1394.

The charger does not return the actual reference/sample. In 16 more
original-arithmetic fixtures, full values 292/36/-220/-476 all send 0x24
(18,548 instruction steps). Python reproduces every result. These synthetic
results do not mean that such physical temperatures occurred. The app shows
the MCU candidate as unsigned decimal/hex. Its units are not confirmed.

Other values have stronger role evidence:

- The original cap translator/wrapper confirms the 55/70/22.5 W allocation codes.
- Rail 2 and PFC 1 are commanded/control settings. They are not electrical feedback.
- The NTC LUTs, the conversion/filter and the protection consumers confirm an
  input role similar to degrees. They do not confirm calibrated physical Celsius.
- SC2021 word 0120 is logged as the software version. The roles of HUSB 0104/4a7f are not known.
- The Global/default/unbound/Holiday meanings stay separate.
- The reported native C2 supports the existing PPS label, with the cache-time limit described before.

The title AI Temperature Control belongs to main-widget page 4, which the UI can reach.
This page shows the thermal stage/thermometer status. No path to edit
thresholds was found there. If legacy MIOT 2.7 bit 0 changes alone, it does not call the
protocol callbacks. The checked routes have no useful thermal consumer for it.

The new [AuditSensorCalibration.java](../scripts/ghidra/AuditSensorCalibration.java)
keeps 30 exact functions / 294 instruction records. All match the raw bytes.
Copied loader runtime 0x201344 maps to file offset 0x74824 / flash 0x477824.
108 code/literal bytes match. The decompiler warnings about missing ROM stay
explicit. The original Thumb code is the evidence for those initializer/GPIO paths.
The read-only project processing discards the annotations.

App 0.6.4-experimental, code 27, adds these items:

- a thermal snapshot UI
- both NTC estimates
- the MCU candidate
- rail/PFC settings
- receive timestamps and monotonic ages
- a history of the latest 12 sensor replies.

Read sensors uses the existing single query.
Read all keeps the bounded batch. The reconnect cleanup stays. Later version or
artwork replies cannot change the receive time of an earlier sensor reply. The
age-display timer runs only while the screen is visible. If a new batch is
incomplete, the previous thermal snapshot keeps its own time. The copied
diagnostics add per-reply times/history and stale status. They do not include
credentials or the device address. The app does not report the thermal
stage/budget/protection state. It has no automatic shutoff, no guessed stage
and no protection-limit editor.

Build/test: `:app:testDebugUnitTest :app:assembleDebug` succeeds. 34 tests,
zero failures/errors/skips. New regressions cover the exact reported frames, unsigned
MCU bytes, unavailable NTCs, unknown enums and independent monotonic ages.
Thirteen offline research-tool checks pass. New APK:
`cuktech-local-0.6.4-experimental-debug.apk` (local build, not distributed), 12,955,014 bytes,
SHA-256 `ee9385e5f0d8696a96679147a18b73d2bcc8b187c561a505bf148281cf3fa9ca`.
Operation on a phone and physical calibration are not verified.

[Coverage ledger](firmware/coverage-ledger.md): 184 unique focused entries,
171 in the unchanged 1,145 canonical inventory, 13 recovered/revised outside, 974 unselected;
2,572 byte-matched instruction addresses / 6,872 unique flash bytes. These
numbers count selection and byte checks. They do not measure firmware completion.
Local stage-15 report SHA-256
`b86a420e5b425b3e6feb0cec6b6e2c813aee58707d6a1f79c131fff479e035b9`.

Detailed evidence/identities/open checks:
[sensor confirmation and monitoring](firmware/sensor-confirmation-and-monitoring.md).

## Stage 16: Decode color assets, trace controller writes and unify extraction

Date: 2026-10-15. Scope: the controller, diagnostic and configuration
follow-up, and a common unpacker that exports the individual blobs and
pictures. Inputs: the existing raw-image identity and the rebuilt startup
memory. Analysis tool: Ghidra.

21 RGB565 images fill the full 67,422-byte gap at file offsets
`[0x4c7aa, 0x5cf08)`. The measured descriptor is width/height/depth/RLE-marker/
source pointer. The original renderer proves that a repeat count of zero means 256.
It does not mean zero or an animation count. A new Python color decoder exports source blobs,
RGB565 and PNG previews. Emulation of the original renderer matches all 21 actual
assets plus three edge cases: 24 cases / 1,317,250 original instruction steps.
Both guards are unchanged. All 117 executed instruction addresses match
the raw image. The emulation uses synthetic SRAM only. It does not include the LCD,
clipping, transparency, ROM or peripherals.

Recovered thermal graphics: Excellent / 低温运行, High Performance / 高效输出,
Power limitation / 安全控温. Renderer `0x4105b4` selects these for stages 0/1/2,
with language/orientation variants. Other stages return. These are status labels.
They are not new selectable protocols and not a Beast unlock.

Controller leads, narrowed:

- The four bytes of HUSB 0x85 come from the main revision and the boot-record CRC.
- 0x81 is a fixed-size configuration. No chunk/bulk updater was found in the mapped writers.
- SC2021 register 0x10 has normal and NTC/version views. 0x21 selects the view.
- The separated function 0x41631c writes packed limit nibbles to 0x0e.
- A protection path applies five cached configuration registers again. It does not write controller firmware.
- Four raw protection bits map into ordinary status bits. The names of the individual faults are not known.
- One more HUSB lookup/cache value is similar to a temperature. The recovered
  caller discards the return value of its maximum getter. No checked BLE
  response returns those bytes.

The app has no guessed temperature or protection name.

Storage and diagnostic details:

- App records 1..4 map to Mi IDs 0x51..54 and NVDS tags 0xe1..e4. The measured
  lengths are 12/8/8/10. These tags are not flash offsets.
- The queue worker shows that action 4 flushes app records 1 and 3. Action 4
  is not record 4.
- AF dispatch freezes MIOT after the envelope prefix check, before opcode/selector
  recognition. Thus the side effect also occurs for unknown selectors in a valid envelope.

The existing bounded app frames and the reconnect cleanup stay correct.
No hardware fuzzing and no arbitrary-query UI were added.

The new `AuditControllerPaths.java` keeps 53 exact functions / 2,053
instruction records that match the raw bytes. It also keeps typed incoming
references and checked tables. Six boundaries and two measured TBBs are
annotated in a read-only project. The changes are discarded. Detailed
identities, raw locations and the open checklist:
[controller and color assets](firmware/controller-and-assets-followup.md).

One extraction command now covers all identified formats:

- signed components
- copy/LZ startup blocks
- raw font descriptors/tables
- 911 glyph PNGs
- 21 color PNGs and metadata
- source-map JSON
- optional exact unclassified chunks.

The real signed image gave 2,061 files and 31 unclassified slices
(167,942 bytes, including code/data). All output hashes were checked. All
495,656 main-image bytes were rebuilt from the exported source slices/chunks,
without the full-image copy. The package/developer/image checks and the match
to the embedded root of the image pass. A check against an external trusted
root was not done.

The complete PowerShell extraction/Ghidra workflow was run again into a new local
directory. Results: 1,145 function records with pseudocode, and the original startup decoder
matches for 44,744 output bytes / 286,474 steps, with the guards unchanged. The
missing-ROM and approximate-decompilation warnings stay visible. The existing
canonical coverage inputs do not change. The new run is a reproduction. It is
not a new denominator for semantic review. [Extractor usage](firmware-extractor.md).

All 44 offline firmware-tool tests pass. The new checks cover color-codec edge cases,
valid PNG output, overlapping source-map unions, admission of unknown images and a
complete synthetic asset/chunk reconstruction. App 0.6.4 and its APK do not change.
No account login, charger query, installation, setting write, reset or flash.

[Coverage ledger](firmware/coverage-ledger.md): 216 focused entries, 198 in the
unchanged 1,145-entry canonical inventory, 18 outside, 947 unselected;
4,332 byte-checked instruction addresses / 11,436 unique flash bytes.
Local stage-16 report SHA-256
`bca8b08678a2e34911b974b82303fb54defad8e9acefa0c68a8ed4c76871db96`.
These numbers count kept evidence. They do not measure how much of the firmware is understood.

## Stage 17: Confirm status presentation and fix the screen-timeout enum

Date: 2026-10-15. Scope: the protection/error screen, more controller sensors
and the stored settings. Separate status and storage audits were compared with
the raw Thumb code and the existing read-only Ghidra project. No charger
command, setting write, fault injection, account access, installation, reset
or flash.

A real app defect was found and fixed. The original timeout helper `0x40476c`
subtracts one from the raw enum. It then reads `[300,600,1800,0,60]` seconds at
`0x424f70`. The MIOT setter/cache/getter keep that enum unchanged. The
separate vendor validator accepts 1..5. The correct raw values are:

| Raw value | Screen timeout |
|---|---|
| 1 | 5 min |
| 2 | 10 min |
| 3 | 30 min |
| 4 | Always on |
| 5 | 1 min |

The old picker sent 0..4. Thus it selected different durations. The old
controller also rejected 5. The physical Keep Screen On toggle changes 1↔4
(five minutes↔Always on). This corrects the earlier report. The scene values
were checked separately. The existing 1..4 conversion in the app is correct.

App 0.6.5-experimental, code 28: one shared list of timeout options gives the
labels and the wire values. Controller validation accepts only the supported
entries. The app does not migrate or write the setting automatically. On read,
the current raw device value gets its correct label. All 36 Android tests pass
and the debug APK build succeeds. The new checks send all five actual encrypted
requests, decrypt PIID/value, verify the readback and reject unsupported values
without a write. The APK is 12,833,264 bytes, SHA-256
`2b4d785d686cf38b0a4c7b93cbfbb8bcd7594d5136eefc039dcc64046c5d67b4`,
at `cuktech-local-0.6.5-experimental-debug.apk` (local build, not distributed).
Operation on a phone and the physical timing are not verified.

Native error bits have a generic UI. They have no individual names. `0x4065c8` tests
native mask 0x1fc and selects state 2/zero V/I. Renderer `0x40c154` shows state 1
as dashes and states 2/3 as `00.0 V`, `00.0 A`, `0` power. Status bit 5 is part
of a timed state 2/3 alternation after >800/>400 timer units. The render
branches are identical. Thus they do not prove visible blinking. The 0x84 recovery subset is traced.
The C1/C2 helper checks record index `port|2` again. This is a cross-port quirk.
Its intent and live behavior are not known. No per-bit OVP/OCP/OTP name is known.

WARNING: Do not apply the native error mask to Bluetooth status. Periodic MIOT packing
can borrow measurements from the fifth record for C3 and force status 0x11. The
initialization packer uses ordinary low status bytes. The SC disabled handling can
replace the full native status with 0x800 and drop the low protection flags. A simple
warning mask gives false C3 alerts. Zero bits do not prove health.
The raw diagnostic words stay. No guessed fault label is added.

Stored settings now have a field/migration map:

- Record1 holds schema, Bluetooth, legacy protocol flags, scene, timeout,
  language, orientation, idle-off and orientation lock.
- Record3 contains four protocol slots. Their second bytes and other bits are not known.
- Record2 has the restoration marker/AC selector.
- Record4 contains marker/revision/Holiday state. No revision updater was
  recovered for a successful stored read.

Do not use the stored revision to identify the current firmware after an OTA.
Schema2 resets the protocol defaults, copies the UFCS bits, sets the idle-off/lock
defaults, changes the schema and queues a save. The language clear of schema1
is a separate branch. The reserved fields give no more charging unlock.

The extra HUSB candidate stays internal in the checked output routes. The recovered
caller discards its getter return. Initialization and the known AF replies
do not return it. With all values of the candidate byte, periodic packing still
uses the mapped V/I/status/cap fields. No unit claim or new sensor query was added.

The new `AuditStatusAndSettings.java` keeps 43 exact functions / 1,589 original
instruction records, with checked tables/default SRAM and references. The new
`VerifyStatusAndTimeout.java` matches 1,280 synthetic cases / 214,528 original
instruction steps: all timeout bytes, 512 SC mapping fixtures and 512 periodic
packer fixtures. Python reproduces every result and byte-matches
all 299 executed instruction records. The final fixtures initialize the condition flags.
An earlier run that matched with CY/OV warnings is kept separately. The emulator
does not include the UI/timers, the surrounding SC driver, the ROM or the
hardware. The existing 44 offline firmware-tool checks pass.

Detailed fields, raw locations, verification identities and open checklist:
[status and settings follow-up](firmware/status-and-settings-followup.md).
[Coverage ledger](firmware/coverage-ledger.md): 239 focused entries, 218 of the
unchanged 1,145-entry inventory, 21 outside, 927 unselected; 5,530 byte-checked
instruction addresses / 14,672 unique flash bytes. These numbers count evidence.
They do not measure firmware completion. Local stage-17 report SHA-256
`f3a9db86dc62e9a989429ab6830585077db2df6957aeceb52976178c48332f1c`.

## Stage 18: Verify protocol controls, command formats and remaining source blobs

Date: 2026-10-15. Scope: more command/blob/enable-control analysis and
stronger confirmation of miPPS and other protocols. Inputs: the measured
raw/expanded memory and the read-only Ghidra project. No charger
request, setting change, app installation, cloud login, fault injection, reset
or flash. App 0.6.5 and its APK do not change.

The C1/C2 named switches now have verification from the original code. The
argument order of initializer `0x409e84` is `(port, miPPS, UFCS, PD, PPS)`.
The controller disable bits are 0/2/3/4. The logger prints PPS before
PD because it reverses the two stack arguments. The argument order of the
reconciler log and the separate ADC Assistant PPS OFF branch agree: PPS sets bit4, PD sets bit3.
The existing MIOT/app PD/PPS names are correct. An old note with an inferred
initializer argument order was corrected.

`VerifyProtocolSwitches.java` executes the original initializer and the
argument setup of the named log up to the boundary before the logger. Both
ports × all 256 original disable bytes × all 16 boolean enable combinations =
8,192 cases / 212,992 original steps.
Every result/log argument, reserved bit and other context byte matches. Python
checks all cases and all 26 executed instruction records. No
logger/bus/ROM/negotiation code is executed. This straight-line block does not
need the fixed-Thumb callback workaround. This result confirms the control
names. It does not confirm the name of the active protocol byte.

The active names stay qualified:

- The primary upstream fixed/PPS experiment still supports C1/C2 07/08.
- The firmware still links C3 to PD explicitly.
- Returned 09 still has Xiaomi/PPS-like consumers. No explicit miPPS enum definition is known.
- USB-A 02 QC and 04 QC2/SCP observations are more external leads. They are not universal enum names.
- The manufacturer HUSB362/SC2021A pages give the controller capabilities. They
  do not give the returned enum map of CUKTECH.

A controlled on-device procedure for miPPS enabled/disabled/restored is documented.
It was not run. No new speculative app labels were added.

Command details:

- The four-byte protocol mask of AF selector 8 is big endian. The typed u32 of
  MIOT is little endian.
- Selector 7 takes four separate nonzero/zero port booleans.
- Both selectors return fixed success markers without readback.
- The action callback sets result 0 before it checks the AIID. An unknown AIID
  returns success and does nothing. The callback only logs the application SIID.
- Its registration and the generic parser callback path are kept.
- The measured group 1 dispatcher has nine selectors. No extra selector or charging unlock is known.

In command 81, byte 2 HPower follows rail selector == 2. Its reconciler compares only
bytes 0/1/3 before it decides to write the full four-byte payload. This internal
behavior does not show a new remote override or a definite bug.

The new `firmware_commands` CLI describes the exact known frames offline. It keeps the
validators, byte order, twelve named enable bits, reserved bits and ACK limits.
It does not build or send writes. The new `firmware_blob_inventory` checks the
raw/extraction/analysis identities. It overlays unknown source intervals with the
canonical function bodies: 31 chunks / 167,942 bytes, 113,990 in automated bodies,
53,952 outside. ELF/PNG/ZIP-local-header scans return zero. Automated bodies can
include data. Absent signatures do not exclude headerless/encoded controller
images. No new secondary image was recovered. This source accounting is
separate from semantic review and instruction coverage.

`AuditProtocolAndCommands.java` keeps 28 exact functions / 633 original
instruction records, checked tables/log strings and callback paths. Six shared
helpers get measured boundaries. All original bytes match. The decompiler
missing-ROM warnings stay explicit. The read-only annotations are discarded.
All 51 offline firmware-tool tests pass. These include new strict-frame endian/
validation/namespace cases and interval/body accounting checks.

Detailed identities, primary-source links and open checklist:
[protocol/command/blob follow-up](firmware/protocol-command-blob-followup.md).
[Coverage ledger](firmware/coverage-ledger.md): 254 focused entries, 233 of the
unchanged 1,145 canonical entries, 21 outside, 912 unselected; 6,163 byte-checked
instruction addresses / 16,420 unique flash bytes. These numbers count kept
evidence. They do not measure how much of the firmware is understood. Local stage-18 report SHA-256
`14e70c5ec55d51b5bd59622d8afdeab375fd241eb9613c5a4376950e79f9444b`.

## Stage 19: official Chinese Mi Home APK and plugin retrieval paths (2026-10-15)

The evidence source changes from the 0073 firmware tables to the
official Chinese-store Mi Home host APK. The Xiaomi store/CDN gives manifest
version 11.7.709 / 110717091, 244,510,121 bytes, SHA-256
`73335d3c17dff3e73097db7e2f86a373b7eb2c67611dc82749883ab2da3f0b6e`.
Android SDK apksigner accepts the v2/v3 signatures. All archived-member CRCs pass.
The APK is not installed or executed. No charger operation or binding change.

The official JADX 1.5.6 CLI does the decompilation. Its downloaded
release ZIP matches the published SHA-256. A run limited to 4 GiB of memory was
interrupted and is kept. The 8 GiB / four-worker run finishes in about 3.5 minutes.
It gives 55,500 Java files plus the decoded resources/manifest. It reports exit
3, 498 errors / 826 warnings in 175 nodes. It does not parse an opaque 65,160-byte
embedded DEX asset with a nonstandard header. Thus the recovery is not complete and not error-free.
`scripts/analyze-mihome.ps1` keeps the output/receipt and shows the failure.

The bundled Chinese catalog lists `njcuk.fitting.ad1204`, product
26126 / `0x660e`. The inspected overseas catalogs list `njcuk.fitting.1204e`,
35513 / `0x8ab9`. The built-in plugin map has no njcuk entry. The catalog
is not the separate charger plugin. It does not define a charging-protocol enum.

The plaintext SDK code in the APK shows the plugin metadata request. The
native host builder separately supplies API level 10117, the selected region,
backup metadata and a real spelling difference: SDK `packageType`, native
`package_type`. Both are documented. The analysis does not assume that the server treats them the same.
One saved-session metadata lookup in the SDK format fails with `CloudError`. No official
device-plugin metadata/package is retrieved. Session expiry is not inferred.
The field names of the response parser are useful. Its Java has reconstruction
warnings. Thus the exact fallback control flow needs a DEX-level check.

More firmware lookup formats are recovered:
`/v2/device/multi_check_device_version` and
`/v2/device/check_device_version_v2`, including host/plugin version inputs.
The generic host UI can show MCU/accessory updates. No AD1204 controller
package or new flash path is known. The generic host capabilities give no
protocol/thermal label, hidden setting or app change.

Detailed artifact identities, SDK offsets, native references, request formats,
reproduction commands and open gaps:
[Chinese Mi Home APK analysis](firmware/mihome-cn-apk-analysis.md).
The vendor APK, decompiled files and tools stay in ignored artifacts. The
documentation and the wrapper can go on the existing research branch. Firmware
instruction coverage and app 0.6.5/APK do not change. Unrelated test suites were not run again.

## Stage 20: official AD1204 plugin downloaded and unpacked (2026-10-15)

The recovered native `/v2/plugin/fetch_plugin` body succeeds with the existing
authorized CN session (`code=0`). It returns plugin ID 1028581 / version 60 /
package ID 1896060. An earlier short note called the package ID a
version. That was wrong. Response SDK version 10116 and project SDK API 10110 are recorded as
separate fields. No new login, binding, charger command or update.

The returned Xiaomi CDN ZIP is downloaded without account cookies: 4,664,265
bytes, SHA-256 `9f1198fb6a096715ae03e3f92afca7cde4fde1b68adfa5ba6f4ed5df61692fe2`.
Its measured MD5 matches the filename. All ZIP member CRCs pass. The extraction
checks paths/aliases/symlinks/size. The success of the native format does not
show why the earlier SDK-format lookup of stage 19 failed.

The actual signature sequence of the host verifier is recovered: ECDSA-SHA256 over
`SHA256(raw project.json) || SHA256(bundle prefix)`. For this package the prefix
contains the full 925,870-byte main bundle. The two certificate signatures and the
code signature verify against the exact SPKI in the root of the official host APK.
The root uses a nonstandard algorithm encoding. The strict Python X.509 parser
rejects it. Thus a bounded SPKI extraction is necessary. No check against a
separate external root and no full certificate-policy/revocation check was done.
The drawables are not in that signature sequence. The first hypothesis (main
bundle only, first certificate only) fails.

`main.bundle` is a Metro indexed RAM bundle. It is not encrypted JS. The new offline
`cuktech_pc.ram_bundle` recovers 150 modules from 10,452 sparse table slots.
It exports the original ranges and readable JS. It rebuilds every
input byte from the exported slices. Three tests pass for holes, exact
aliases, reconstruction and malformed ranges/text. No JavaScript is executed.

New official label evidence: the active MainPage renderer maps these codes:

| Code | Label |
|---|---|
| 1/2 | 5V |
| 3 | QC |
| 4 | AFC |
| 5 | FCP |
| 6 | SCP |
| 7 | PD |
| 8/9 | PPS |
| 10 | UFCS |

Its inputs come from the protocol bytes of MIOT 2.17/2.18. All four port views
call it. This confirms what the official plugin shows. It does not prove
physical negotiation. It does not prove that every code is valid on every
port/firmware. It does not name active 09 as miPPS. The earlier external
USB-A 02/QC observation conflicts with the 02/5V label of the shared plugin.
This conflict is not resolved. The app labels do not change in this stage.

The per-port PIID21 control code confirms the PD/PPS/UFCS and UFCS/SCP bit names.
It forces C1/C2 bit3 on. Legacy PIID7 has named SCP/miPPS/UFCS switches. The navigation
includes DebugInfo and firmware pages. The route names do not show a hidden
command or a flasher. A bounded text search finds no sensor-temperature
UI. Generic temp fault constants do not prove readings.

All 151 extracted JS files parse with zero failures. The automated semantic
coverage is partial. Each UI fact
is kept with its actual module/source location. This is a first review of the
plugin. It is not a complete semantic audit. Full details, source URL, successful request,
signature limits, reproduction and open work:
[official charger plugin](firmware/mihome-charger-plugin.md).

## Stage 21: app 0.6.6 protocol names and native updater trace (2026-10-15)

App 0.6.6-experimental, code 29, uses the active-protocol display table of
the official plugin. The QC/AFC/FCP/SCP/UFCS names and the vendor 5V/PPS names
are available for mapped exposed bytes. The C1/C2 fixed PD and PPS refinements stay.
Watt caps are still only for codes 07/08. Unknown values stay raw.
Each nonzero protocol line on an active port now shows its code/detail pair.
Before, these pairs were in the diagnostics, but not always on the port cards.

The app keeps miPPS as the label for code 09. Thus C1/C2 show
miPPS (likely). The separate `vendorLabel` keeps the official
PPS name in the copied diagnostics. This alias is tentative. It is
not a new proof of enum-to-miPPS and not a physical negotiation observation. C3/A 09
keep the literal vendor PPS name. USB-A 02 shows 5V / QC (unresolved),
because the vendor UI and the upstream experiments disagree. The app adds no
inferred QC version, no VOOC/FlashCharge name and no new watt meaning.

The app shows the Apple scene as Hybrid (Apple). This follows a check of the official
English localization and the suite examples. Its wire value/profile does not change.
The feature guide and the copied diagnostics explain the label sources and limits.

The first detailed review of the debug page shows these functions: an account
allowlist gate, plugin-local/cloud-storage cleanup and cloud timer-scene helpers.
The rendered device-log callbacks are empty. No UART enable command is known.
No extra brand classifier and no temperature reading were found in this plugin.

The explicit update handler gives `auth_type:4` through the native host to
`BleOTAUpgradeActivity`. The OTA connection dispatcher selects
`bleStandardAuthConnect`. In the same dispatch, value 5 selects mesh and 6
selects PSK. The activity can override the value when catalog `bt_is_secure=2`.
The bundled AD1204 entry has `bt_is_secure=0`, separate from bt_bind_style=2.
An existing connection can skip the reconnect. The runtime catalog and live OTA
behavior were not observed. This gives a useful native entry path. It is not a
working custom flasher. Full method/line references and namespaces:
[debug/updater follow-up](firmware/plugin-debug-and-upgrade-followup.md).

`:app:testDebugUnitTest :app:assembleDebug` succeeds. All 38 Android tests
pass with zero failures/errors/skips. Mixed-protocol packed-word fixtures
keep the high/low halves and raw details, with no invented caps. A parsed MIOT
response/cache fixture covers tentative miPPS, UFCS, C3 PD and the USB-A ambiguity.
The APK manifest confirms the new version. Saved APK:
`cuktech-local-0.6.6-experimental-debug.apk` (local build, not distributed), 12,833,264 bytes,
SHA-256 `598ffa82b66722fc02375d5d82f216e071914226dc9e06edc12a417cd4dbed2b`.
No phone installation, charger command or firmware write. The vendor
artifacts, account material and generated outputs are not in Git.
Mapping/behavior details: [app label evidence](firmware/app-protocol-labels-0066.md).

## Stage 22: native OTA framing, resume and recovery boundaries (2026-10-15)

The native updater route of the official plugin was followed through the downloaded
Mi Home 11.7.709 host into its DFU manager and reliable channel. It was then compared
with the 2.1.2_0073 receiver of this charger. Results:

- The FE95/0017 control requests and the enveloped responses match.
- 0018 carries reliable messages, split into GATT pieces.
- The one-based piece index starts again in each message. The separate logical
  firmware index increases across the image.
- Reliable ACK 0 confirms the assembly. The host waits for 0017 event-kind 2/status 0
  before it continues.
- The receiver code queues that event after the flash commit and the CRC readback succeed.

The Java for the full APK had fragment branches that disagree. Targeted JADX and
exact baksmali disassembly of the verified classes13.dex resolve both the full
and the short final fragments. The output contains a two-byte index followed by the
unchanged bytes of the selected file. There is no final padding and no wrapper stripping.
The optional added CRC of the reliable channel is disabled for this OTA manager.
The device flash CRC, the prefix resume CRC and the signature checks are separate.

Receiver command 2 selects 512-byte file fragments if the negotiated reliable
payload is below 19 bytes. Otherwise it selects 2,048. The default payload is 18. The local cap is 242.
This is a protocol parameter exchange. It is not only the result of the Android
MTU request. The signed package needs 971 or 243 logical fragments.
These numbers are offline calculations. They are not observed negotiated values.

Resume compares the returned index/CRC with the prefix of the selected file. On a
mismatch, it starts from index 1. An offline comparison of the actual 256-entry
table of the host with Python zlib passes all 1,214
prefix checkpoints for the signed package at the two fragment sizes.
The whole-file CRC32 is `9f0ab94b`. This verifies the arithmetic. It does not verify a live resume.

The native downloader calculates the MD5 from the actual local file. A targeted
simple-mode recovery resolves its callback, which failed before. These retries
are separate: download retry, resend of missing pieces, UI retry and discovery
retry after the transfer. After the success callback for the primary image, the
host discovers the matching Bluetooth MAC again. It reports the offered version.
That completion callback does not read the running version again. A timer
generates part of the displayed progress.

Receiver command 4 carries delay 1. The receiver then does these steps:

1. Copy and delete its saved progress record.
2. Verify the staged image.
3. Wait for the disconnect to clear the switch gate.
4. Wait one second.
5. Prepare and read back the boot record.
6. Restart.

ROM/bootloader activation, rollback and power-loss recovery are not in this
image. The optional MCU commands/UI are not a proven controller update route.
Two weak points in the host parser are recorded and are not copied into the app:

- The guard on the length of the index/CRC response is not sufficient.
- In the inspected advance path, the host does not compare the index of the
  fragment event with the pending index.

Detailed packet fields, source hashes, DEX offsets and limits:
[transfer trace](firmware/ota-transfer-framing.md),
[receiver correlation](firmware/ota-firmware-receiver-followup.md), and
[validation/recovery review](firmware/ota-validation-recovery.md).
No cloud request, BLE connection, firmware write or app change.
App 0.6.6 and its existing APK do not change. Unrelated app tests were not
run again. The vendor artifacts and the generated decompilation are not in Git.

## Stage 23: resolve the optional DFU resume-integrity option (2026-10-16)

The exact receiver branch in command 7 (`0x0041ae44`) sets an internal flag
only when the single option byte has `(option & 3) == 1`. This flag changes
the response path of the next command 3. The charger does not use the CRC of
the saved record. It reads the saved byte count from the staging flash and calculates CRC32 again
before it returns the resume state. Command 1 clears the flag. In the inspected
path, command 3 does not clear it. Thus command 7 requests a new integrity
calculation over the flash prefix. It does not enable a charging protocol or Beast mode.

The command changes state:

- Command 3 enters the DFU transfer state.
- Command 4 deletes the saved progress record.
- Command 7 can call an optional application callback.

The traced native Mi Home sender does not use command 7
in its normal sequence. Original Thumb offsets:

- command-7 option mask/store `0x0041aeb4–0x0041aec4`
- command-1 clear `0x0041aef6`
- command-3 flag branch/read/CRC loop `0x0041af8a–0x0041afd6`.

These effects come from static analysis. No command was sent. Detailed offsets
and callback limits are in the
[DFU auth/callback follow-up](firmware/dfu-auth-followup.md), linked from the
[transfer trace](firmware/ota-transfer-framing.md).

## Stage 24: implement the in-app signed-firmware installer (2026-10-16)

0.7.0-experimental, code 30, adds direct installation in CUKTECH App,
without Mi Home. Account downloads stay. Import of a signed file adds an offline
route. Packages stay stored after the app closes.
Before DFU, the updater checks the actual China PID, the registered flag, the
saved-token proof and the current 0073 version. The updater then does these checks:

- It pins the root public point of the original firmware.
- It verifies both certificate signatures and the image/tag signature.
- It binds model/product/version.
- It rejects unsigned, modified and oversize packages.

The app answers the A4 management offer with an 18-byte payload limit.
The next type-1 20-byte probe confirms this profile. This selects 512-byte file
fragments, independently of the Android MTU. Commands 1/2/3 and the reliable frames follow
the matched sender/receiver trace. The data ACK and the matching flash-commit event are
both necessary. Invalid ranges, lengths, pending indices and too many retries stop the transfer.
Characteristic writes now have an optional callback for actual completion. Thus
the updater never treats a queued write as a delivered write.

Signature verification/activation command 4 follows all committed fragments.
The disconnect lets the receiver clear its switch gate. A new token login
and version reads then verify the result. Reconnect retries never flash again.
For a reinstall of the same version, the app reports this limit: equal versions
do not prove that the running image changed. Back navigation is blocked during
the installation. The existing foreground service, a bounded partial wake lock
and a kept ViewModel support the operation. Physical interruption, rollback and
ROM recovery are not verified. Modified unsigned firmware is not enabled.

All 50 Android unit tests pass, with zero failures/errors/skips. The debug assembly
and the APK v2 signature verification succeed. The scripted checks include negotiation,
mutual auth, missing packets, rejected commit indices, resume, truncated frames
and completion timeouts. The actual kept signed package passes the pinned-root
verification/import of the app. If bytes are changed and the metadata MD5 is
calculated again, signature verification still fails. No phone installation or
charger operation. A new CDN download returned 403. The lookup with the saved PC
session failed with CloudError. The package verified before is available for offline import.

APK `cuktech-local-0.7.0-experimental-debug.apk` (local build, not distributed): 12,985,163 bytes,
SHA-256 `b5ecd1936c3d390f1f2af252fb57910e5fe9a413b2c5779d046d870ae40bb6cd`.
[Installer guide, package identity and plugin findings](firmware/in-app-flasher.md).

## Stage 25: audit plugin write paths against controller state (2026-10-16)

The routed pages and shared wrappers of the official plugin have a broken reset
follow-up. It writes legacy 2.7 = 3. It then calls a method that is not in
MHSetting, before it can send the intended 2.7 = 7 batch. Two retry
branches also call a method on the wrong class. This comes from static source
analysis. The fault was not executed or reproduced on a charger.

The firmware traces legacy miPPS/UFCS writes into the desired controller
structures of both C1 and C2. MIOT 2.21 is packed from separate saved preferences.
Its setter calls the UFCS helpers only when a saved bit changes. Thus a readback
or rewrite of an unchanged mask does not show the actual enable state of the
controller. It is not verified how long a disagreement lasts across scenes,
cable events or reboot.

Other plugin findings:

- The shared JS setter combines all request/response pairs. It does not match IDs.
- The timer UI checks only result zero of its mask/duration batch.
- The modern protocol toggles write all port groups again. They force both C1/C2
  miPPS preference bits on, also when the user changes C3/A.
- The vendor UI confirms that PPS depends on PD. It tells the user to replug for C3/A.
- The charts show 60 local cached samples.
- The generic fault/cloud timer code has no known active consumer in the bounded plugin.

The [detailed audit](firmware/plugin-feature-audit-20261016.md) records source lines,
hashes, original firmware addresses, the device-call inventory and the open
native-host/secondary-controller/hardware checks. No extra device endpoint,
thermal threshold write or power override is known. App 0.7.0
does not change. No unrelated build/tests and no hardware/cloud operations.

## Stage 26: verify secondary-controller write/cache behaviour (2026-10-16)

The SC2021 limit helper stores its desired register 0x0e byte, also after all
write attempts fail or the readback does not match. Its equality check then stops an
identical retry. C3/A protocol writes also cache before the ACK. Thus a failed first
request can be followed by success/no-I2C on an identical request. The
three-attempt retry limit and these paths pass 5,394 original-instruction fixtures /
155,243 steps. All 96 executed records match the raw bytes.
External bus/logger/delay calls have scripted returns. No hardware failure and no
full-device emulation is claimed. The first Ghidra ARM callback failure is
kept separately. The completed run uses the existing fixed-Thumb adapter.

The C3/A callback of the allocator selects opaque packed limit values from both cap
codes, including a separate 0xa0 case. The original cap conversion maps 0xa0 to
7.5 W. App 0.7.1-experimental / code 31 adds that label for C3/A. It keeps
the raw code and the C1/C2 namespace separate. All 51 Android tests and the debug
build pass. The APK v2 signature verifies with the existing signer. No installation
or charger command. The APK is 12,882,444 bytes, SHA-256
`ace527b5b12f702c4f864ef1aa09c6338f792d46874a178ccffa473800c12e54`.

The bus routines send 8-bit address bytes:

- C1/C2 0x92/94 are seven-bit 0x49/4a.
- SC2021 0x42 is 0x21.

The HUSB checksum and GPIO-mask paths are kept. They do not identify board pads
or physical voltage levels. No secondary image was recovered. Two 256-byte
candidates are the same as generated AES/SHA constants. A reproducible data
audit explains the remaining host gaps. It does not treat automated function
boundaries as proof of an image.

The [detailed findings, evidence and open work](firmware/secondary-controller-followup.md)
include the limit producer table, the protection replay boundary, the verified fixtures,
the bus map and the metadata reports. All 56 offline firmware-tool tests pass.
The updated ledger keeps 258 focused entries and 6,461 byte-checked instruction
addresses / 17,184 unique flash bytes. These numbers do not measure how much of the firmware is understood.

## Stage 27: trace remaining controller fields into policy (2026-10-16)

Three firmware logs name the HUSB status word at payload offset 10 `mDestVoltage`.
It feeds these checks:

- high-power eligibility (>5500 with the hardware-global flag set)
- reduction-state comparisons near 9200
- PFC policy (>12999)
- an existing auto-test (>18999).

It is separate from the measured voltage. The name does
not decode a PDO/APDO. It is not a calibrated measurement. Words 8/12/14 are not
known. HUSB configuration byte 3 is named `mUFCSCtrl`, default 0x3c. Its
encoding is not known. The cable-popup byte comes from stage 13. It is now mapped
explicitly to command-0x83 byte 4. Byte 5 is the checksum.

The HUSB worker copies 18 bytes after a 16-data-plus-checksum response. Thus it
keeps one stack byte from outside the response. A required protocol read after this
copy can fail before the downstream telemetry updates. 48 original-worker
fixtures / 3,666 steps verify the copy argument, the threshold/callback order
and the early return, with scripted helpers. The memcpy and transport bodies are not included.

SC normal replies require both protocol bytes <=15 before the code parses protection,
replays the configuration or updates the protocol/protection caches. V/I/activity
are already stored at that point. The six-byte cache getter always returns success.
Thus callers can use old protocol state together with newer V/I. 4,744 parser
fixtures / 329,500 original steps verify the gate, the status mapping and the replay
arguments. They stop before the register-20 overwrite. CRC acceptance is assumed.
This does not mean that the electrical protections of the controller are disabled.

The [detailed consumers and byte map](firmware/controller-field-consumers.md) keep
the unknown CRC-covered/unchecked SC bytes, the version-word omission, source addresses,
verification summaries and boundaries. All 1,568 static and 162/104 executed
instruction records match the original bytes. App 0.7.1 does not change.
No charger/cloud operation, firmware write or new APK. The ledger now
keeps 264 focused entries, 7,206 checked instruction addresses and 19,146 unique
flash bytes. These numbers count evidence. They do not measure semantic completion.

## Stage 28: verify settling/power snapshots and narrow control writers (2026-10-16)

The only recovered host writers for the desired `mUFCSCtrl` byte set
C1/C2 to 0x3c. The reviewed enable helpers change a different byte. No MIOT/AF tuning
route is known. 108 original-reconciler fixtures / 3,582 steps confirm these rules:

- A byte-3 mismatch requests a four-byte desired-profile write.
- A mismatch in byte 2 only does not request a write.
- A nonzero host state requests a settling reset.

The bus/reset bodies are stubs. The electrical encoding and the computed/ROM
writers are not known.

560 original settling/power fixtures / 20,906 steps show these results:

- State 2 detects a change in the full record. State 1 checks only the enum.
- The same u16 counter handles zero detection and nonzero settling. Its history
  changes how many zero samples request state 0.
- The power helper reads the previous cached packet before the current one is committed.
- The reduction mapping keeps the prior class for enum 6 and for values >10.

The state numbers/classes are not new charging protocols. The sample thresholds
are not converted to milliseconds. The boundary fixtures are not a captured
sequential hardware timeline.

Startup sets the copied SC tail to zero. No producer or field consumer is known.
Both checked report callers use only the first two protocol bytes of the getter.
The true reporting callback at 0x409f38 was split from an unrelated canonical
entry in the read-only export. The zero-fill/snapshot helper instructions are
also kept. All 608 static and 59/209 executed records match the original bytes.

The [detailed evidence, assumptions and open work](firmware/protocol-settling-and-control.md)
keep the first fixture-state mistake, now corrected, separate from the successful
results. The ledger keeps 267 focused entries and 7,506 checked instruction
addresses / 19,918 unique flash bytes. These numbers do not measure how much of the firmware is understood.
No hardware/cloud operation or app change. App 0.7.1 and its APK stay as they are.

## Stage 29: allocation policy and persistent load classes (2026-10-16)

These parts of the manager are traced: the hint subtraction, the RAW/scene gate,
all twelve scene entries, the disabled-port handling and the final AC-dependent
clamp. The clamp also maps 120->100 W once. Selectors 1 and 2 both bypass that
clamp, but they take different scene branches. The normal Apple/Single/Balance
rows are kept for all 15 occupied masks. Lower-tier Balance is not fully fixed:
its three-port AC-low branch checks reduction class1/hint>=30 W and the timestamp order.

AI uses separate reduction and persistent load classes plus the destination voltage.
It does not use the measured voltage. These are the AI rules found:

- For two-C normal AI, the high predicate is reduction1/hint>=65 W or native8/destination>=19 V.
- If neither port is high, the later recognition timestamp wins.
- If both ports are high, the earlier one wins.
- Nonzero load classes select a 22.5/100 or 22.5/120 W split.

A concrete synthetic case gives the reported 55/70 W pair. Runtime inputs are
missing. Thus the capture cannot be linked to this case.
The Apple exception of the classifier is reduction8. It is not native8/PPS.
The first low-load classification can require a measured rolling peak <2 W at the
existing telemetry scale. The old phone-policy notes are corrected and linked.

1,058 allocation fixtures / 324,790 original steps check routing, clamp,
enable masks and stores/guards, with 226 expected rows transcribed separately.
1,218 classifier/companion fixtures / 101,009 steps compare complete contexts.
All 2,396 static and 1,877/245 executed records match the original bytes.
The [detailed policy and JSON evidence](firmware/allocation-policy.md) keep the
tables, hashes, scripted helper limits, corrected fixture assumptions and partial
attempts separate from the completed evidence. These items are open: scheduler
timelines, the other lower-tier AI class combinations, timestamp edge cases and
controller acceptance. No hardware/cloud operation or app change.

The updated ledger keeps the same 267 unique focused entries, now with
9,618 checked instruction addresses / 25,064 unique flash bytes. These numbers
count kept evidence. They do not measure how much of the firmware is understood.

## Stage 30: C2 startup gate and thermal allocation transitions (2026-10-16)

The C2 gate records the startup order:

1. The first C1 cap dispatch (also cap0) starts a timer.
2. elapsed>=1500 releases the gate.
3. A nonzero C2 dispatch records state3 before reconciliation.

Its success log is a timer label. It does not prove a controller ACK.
In the bounded set of recovered writers, only initialization arms the gate again.
No disconnect or error re-arm is known. The wrap arithmetic of the original
elapsed helper loses one count compared with modulo subtraction. All 38 exact
manager-base literals are kept with the available references. Computed/general
writers are not excluded.

The full trigger chain of the manager is kept and tested. Thermal changes
set the dirty flag for heating and for cooling, also for stage0↔1 with the same budget. The scheduler
runs the manager before the tail thermal evaluation. Thus the next eligible
run uses the dirty flag of a new stage. Stage3 sets the desired caps to zero but
does not update the prior remaining-budget cache. In the traced host path, the
recovery requests 900/1200 again without a user reset. This does not prove a
physical restart/ACK.

These emulation runs pass:

- 69 callback calls / 2,235 original steps
- 288 manager calls / 94,603 steps
- 1,659 thermal calls / 82,987 steps.

The manager checks full synthetic contexts, timer boundaries, all reallocation
triggers and six calls with kept RAM. Seven stage projections execute the original
allocator/Apple scenes. Other rows use scripted allocation output. A separate
thermal cycle keeps the prior state and gives `0→1→2→3→2→1→0`. It models the
dirty-flag use between calls explicitly. It does not execute the manager/scheduler
inside that cycle. All 572 static and 39/467/187 executed instruction records
match the raw image.

The [detailed findings and evidence](firmware/allocation-transitions.md) separate
desired-state stores, scripted reconciler returns 0/1 and injected thermal inputs
from actual bus failures or measured charging. No app changes, charger/cloud
operation, firmware write or protection override. The updated ledger
keeps 270 focused entries, 9,685 checked instruction addresses and 25,226 unique
flash bytes. These numbers do not measure semantic completion.

> NOTE: Paths under `artifacts/` are local files that git ignores
> (downloaded vendor packages and outputs that the tools in `scripts/` make again).
> They are not part of this repository. The hashes are recorded so that you can reproduce the results.
