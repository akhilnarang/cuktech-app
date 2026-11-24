# Reproduce the AD1204 0073 analysis

This workflow does these steps:

1. It imports the raw Cortex/Thumb image for static analysis.
2. It reconstructs the startup memory.
3. It corrects the measured switch tables.
4. It exports pseudocode.
5. It compares the Python LZ decoder with the original decompressor in the
   Ghidra emulator.

The workflow never connects to the charger and never flashes it.

This repository does not include the firmware image. Download the image for
your own charger with `uv run -m cuktech_pc.firmware fetch` (see the
[scripts README](../README.md)). The scripts check the measured 0073 image hash.

The scripts were tested with Ghidra 12.1.4, a full JDK 21 and Python 3.

- The unpacker uses the standard library. `--verify` also needs `cryptography`.
- `analyze-firmware.sh` (Linux/macOS) and `analyze-firmware.ps1` (Windows) run
  the same steps. The shell script was tested with Ghidra 12.2 on Linux, not yet on macOS.
- The paths below are examples. Use your own paths.

From the repository root (Linux/macOS):

```bash
scripts/ghidra/analyze-firmware.sh artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin \
    artifacts/firmware/reproduced-0073 /path/to/ghidra --assets --split-unclassified --verify
```

From the repository root (Windows, PowerShell):

```powershell
scripts/ghidra/analyze-firmware.ps1 `
  -Image artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin `
  -OutputDirectory artifacts/firmware/reproduced-0073 `
  -GhidraHome C:/path/to/ghidra `
  -JavaHome C:/path/to/jdk-21 `
  -Python scripts/.venv/Scripts/python.exe `
  -Assets -SplitUnclassified -VerifySignature
```

The output directory must be new. It contains:

- `unpacked/manifest.json`: package components, startup segments, source and
  runtime addresses, hashes, entropy windows and the verification scope.
- `unpacked/index.html`: the extraction index. If you use `-Assets`,
  `assets.html` shows alpha glyphs and `assets/color/index.html` shows color PNGs.
- `unpacked/source-map.json`: admitted source intervals and remaining ranges.
  `-SplitUnclassified` also saves these ranges as exact binary chunks.
- `project/AD1204_0073.gpr`: open this project in the Ghidra GUI after the run.
- `analysis/functions.jsonl`: function bodies, pseudocode, calls and data references.
- `analysis/decompiled.c`: decompiler output that you can search. It is **not original or compilable source**.
- `analysis/decoder-verification.json`: comparison with the original instructions, and guards.

Script roles:

- `PrepareChargerFirmware.java` supplies the initial Thumb entries.
- `ReconstructChargerMemory.java` maps the measured startup copy and expanded regions.
- `RepairChargerDispatch.java` supplies byte-verified jump destinations.
- `ExportChargerFirmware.java` exports the observations.
- `VerifyStartupDecoder.java` emulates only the memory-to-memory decompressor.

The emulator stops at `0x00403b9c`, before the return epilogue, because this
Ghidra release gives a context-state error in the ARM mode-switch userop of that
return. At the stop, all decompressed output is already complete. This check
does not emulate the charger, the boot ROM, the peripherals or the OTA update
process.

For current findings, exact addresses, completed stages and open unknowns, see
the [firmware analysis log](../../docs/firmware-analysis-log.md).

## Focused audits and verifiers

### Protocol and commands

`AuditProtocolAndCommands.java` keeps 28 exact functions and 633 original
instruction records. It also keeps protocol-log formats, AF byte order and ACK
paths, and action registration and validation. Run it on the read-only project
copy with a new output directory.

`VerifyProtocolSwitches.java` takes a new output directory. It runs only the
original initializer, up to the argument preparation for the named log.

- It covers both ports, all initial bytes and all boolean enable combinations:
  8,192 cases and 212,992 steps.
- Its 26 executed instruction records match the raw image.
- It stops before the logger. It does not run the controller bus, the ROM or
  the negotiation.
- This straight-line check does not need the emulator callback workaround.

For the corrected argument order and the open question about the active miPPS
enum, see [protocol/command/blob findings](../../docs/firmware/protocol-command-blob-followup.md).

### Status and settings

`AuditStatusAndSettings.java` keeps 43 exact functions and 1,589 original
instruction records. It also keeps timeout and property tables, native-to-packed
status paths, configuration migration and error UI evidence. It recovers the
missing widget setter, the physical timeout-toggle helper and the timer
callback. Run it on the existing project copy with `-readOnly -noanalysis` and
a new absolute output directory.

`VerifyStatusAndTimeout.java` takes a new output directory. It checks 1,280
synthetic cases and 214,528 original instruction steps:

- all timeout bytes
- the SC protection-bit translation
- the periodic MIOT C3 replacement path

Registers and condition flags are initialized. The script keeps 299 executed
instruction records. It uses the documented fixed-Thumb emulator callback
workaround. It does not include the ROM, peripherals, UI, timers or the
controller driver before and after the isolated mapping block.

See [status/settings evidence](../../docs/firmware/status-and-settings-followup.md).
That document also describes the timeout fix in app 0.6.5. It also tells why
the native error masks cannot be Bluetooth fault labels.

### Python-only extraction

The [extractor guide](../../docs/firmware-extractor.md) also gives a
Python-only command. On the 0073 image, the full workflow gives these results:

- 2,061 extraction files
- 911 glyphs
- 21 color bitmaps
- 1,145 function records
- a match with the original instructions for all 44,744 startup bytes

The automatic inventory keeps its decompiler warnings. It does not include all
of the later focused boundary repairs.

### Color bitmaps

`VerifyColorBitmaps.java` takes a standalone `firmware_bitmaps` manifest and a
new verification directory.

- It compares all exported RGB565 words with the original opaque renderer. It
  uses synthetic SRAM.
- It adds fixtures for literal, mixed and zero-count runs.
- All 24 cases matched over 1,317,250 instruction steps. The guards stayed intact.
- It uses the same documented fixed-Thumb emulator workaround as the ADC verifiers.
- It does not run the LCD, clipping, color-key transparency, the ROM or peripherals.

To make a standalone manifest from the raw image
(`uv run -m cuktech_pc.firmware fetch --legacy`), run this from `scripts/`
with the venv active:

```bash
uv run -m cuktech_pc.firmware_bitmaps ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-raw.bin ../artifacts/firmware/color-bitmaps
```

### Controller paths

`AuditControllerPaths.java` repairs the measured controller, lookup, queue and
AF-handler entries, and two switch tables. Then it keeps 53 exact functions,
2,053 original instruction records, tables and typed incoming references. Run
it on the project copy with `-readOnly -noanalysis` and a new output directory.
The [controller/asset follow-up](../../docs/firmware/controller-and-assets-followup.md)
keeps these items separate: static findings, inferred roles, verification
against the original renderer, and the remaining controller, ROM and hardware
boundaries.

### UI, protocol tables and display features

- `RepairChargerUi.java` separates the measured UI wrappers and repairs the
  screen dispatch tables.
- `RepairDeviceProtocolDispatch.java` repairs the measured protocol-test and
  scene tables.
- Both scripts refuse a raw image with a different hash.
- `AuditDisplayFeatures.java` exports selected exact functions and original
  instruction bytes. It shows missing entries explicitly.

Run these scripts on a separate project copy with `-readOnly -noanalysis`.
Select a new output location. The [capability inventory](../../docs/charger-capabilities.md)
links their findings and the app and status maps. You can query ordinary
exports with the [offline evidence CLI](../../docs/firmware-evidence-cli.md).

### Coverage gaps

`AuditCoverageGaps.java` keeps the selected ADC, optional DFU and
factory-screen functions and instructions. It does not replace them with the
functions that contain them. It has the same image-hash guard and needs a new
output directory. The [coverage ledger](../../docs/firmware/coverage-ledger.md)
describes the reproducible counts, the byte checks and the remaining closure
criteria for each subsystem.

### Factory screen and SC2021 tables

`AuditProtocolAndFactory.java` recovers the factory LCD vtable target, the
bounded draw functions and the eight-way switch. It exports selected controller
protocol consumers and the exact SC2021 translation tables. Use a separate
read-only project copy and a new output directory. This annotation does not
patch the firmware or run the charger.

### Brand classifier

`VerifyBrandClassifier.java` emulates only the original brand classifier. It
uses synthetic OPPO, vivo and zero-ID records on C1/C2 for all protocol bytes.
A new output directory holds all 1,536 fixture results, the exact code-window
bytes and identity, and the explicit return and hardware boundaries. See the
[brand/protocol audit](../../docs/firmware/oppo-vivo-vooc-audit.md).

### Allocation

- `AuditAllocation.java` repairs the allocation-dispatch, scene-count and
  final-clamp switches. It keeps 22 functions, the original instructions and
  the startup and flash rows.
- `VerifyAllocation.java` runs the original allocator and scenes with
  synthetic caches. It checks routing, clamp, enable and guard behavior, and
  independent fixed, AI and Balance rows.
- `VerifyAllocationLoadClass.java` checks the original persistent-load
  classifier and the immediate revocation helper separately.

All three scripts need the measured raw SHA and a new output directory. Use the
reconstructed project with `-readOnly -noanalysis`. The helpers use caller
registers and condition flags. Thus ordinary C decompilation alone is not
sufficient. See the [allocation evidence and boundaries](../../docs/firmware/allocation-policy.md).

### Allocation transitions

`AuditAllocationTransitions.java` separates the manager, the dispatcher, the
USB-C callback, the elapsed helper, the scheduler and the thermal evaluator. It
keeps the original instructions and the literal references to the manager base.

`VerifyC2StartupGate.java`, `VerifyAllocationManager.java` and
`VerifyThermalStageDirty.java` check startup order, recalculation triggers and
signed thermal stage and dirty transitions. Use the same reconstructed project,
hash guard, new output directories and `-readOnly -noanalysis` workflow.

The [transition report](../../docs/firmware/allocation-transitions.md) keeps
these items separate: scripted helper results, injected stages and
retained-context sequences. It also lists the missing evidence for the
continuous scheduler, bus and hardware.

## Script index

Scripts marked *read-only* only print or export. The other scripts do one of
these things:

- They add analyst annotations to a project copy. Run them with `-readOnly`,
  so that nothing is saved.
- They emulate original instructions on synthetic inputs.

No script touches a charger.

| Script | Purpose |
| --- | --- |
| `analyze-firmware.sh` | End-to-end Linux/macOS driver: the same steps as `analyze-firmware.ps1` |
| `analyze-firmware.ps1` | End-to-end Windows driver: unpack, import, reconstruct, repair, export and verify the 0073 image |
| `PrepareChargerFirmware.java` | Pre-script: seed initial Thumb entries for the raw 0073 image (BinaryLoader at `0x00403000`) |
| `ReconstructChargerMemory.java` | Map measured startup copy/expand regions from the unpacker's `manifest.json` |
| `RepairChargerDispatch.java` | Supply byte-verified TBB/TBH switch destinations |
| `RepairChargerUi.java` | Correct measured UI function boundaries and screen switch tables |
| `RepairDeviceProtocolDispatch.java` | Repair protocol-test/scene switch destinations and export focused evidence |
| `ExportChargerFirmware.java` | Export function records, references and decompiler output |
| `SeedCortexM.java` | Generic raw Cortex-M pre-analysis: seed functions from the vector table |
| `AuditAllocation.java` | Allocation dispatch, scene-count and final-clamp evidence |
| `AuditAllocationTransitions.java` | Allocation manager, startup gate and thermal handoff evidence |
| `AuditControllerFields.java` | Packet-field consumers, pointer aliases and named policy strings |
| `AuditControllerPaths.java` | Controller writes, cached fields, NV action dispatch and RGB565 UI paths |
| `AuditControlSettling.java` | Host protocol-settling and control-byte boundaries |
| `AuditCoverageGaps.java` | Selected ADC, optional DFU and factory-screen evidence |
| `AuditDisplayFeatures.java` | Display/button feature functions and original instruction bytes |
| `AuditProtocolAndCommands.java` | Protocol-enable naming/arguments and AF/action command validation |
| `AuditProtocolAndFactory.java` | Factory LCD renderer and protocol-code / SC2021 translation tables |
| `AuditSecondaryControllers.java` | Secondary controller and bus follow-up at exact entries |
| `AuditSensorCalibration.java` | Sensor meanings, factory calibration provenance and thermal status UI |
| `AuditStatusAndSettings.java` | Native vs packed status and stored setting enum paths |
| `AuditThermalAndCache.java` | Thermal/display derivation and MIOT/native cache evidence |
| `VerifyStartupDecoder.java` | Compare the Python LZ decoder with the original decompressor |
| `VerifyAdcConversion.java` | Emulate the original channel-zero ADC conversion (not acquisition) |
| `VerifyAllocation.java` | Emulate the original allocator and scenes with synthetic caches |
| `VerifyAllocationLoadClass.java` | Emulate the AI load classifier and immediate revocation helper |
| `VerifyAllocationManager.java` | Emulate the allocation manager, elapsed helper and desired-cap callbacks |
| `VerifyBrandClassifier.java` | Emulate the brand classifier with synthetic OPPO/vivo/zero-ID records |
| `VerifyC2StartupGate.java` | Emulate the allocation dispatcher and USB-C startup callback |
| `VerifyColorBitmaps.java` | Compare `firmware_bitmaps` output with the original RGB565 renderer |
| `VerifyHusbControlByte.java` | Emulate the HUSB configuration reconciler |
| `VerifyHusbSettling.java` | Emulate the HUSB settling block and state/power helpers |
| `VerifyHusbStatusFields.java` | Emulate the HUSB362 poll worker |
| `VerifyProtocolSwitches.java` | Emulate the HUSB switch initializer up to its named log |
| `VerifyScLimitCache.java` | Emulate SC2021 limit/cache and retry control flow |
| `VerifyScStatusGate.java` | Emulate the SC2021 normal-packet enum gate and protection consumers |
| `VerifyStatusAndTimeout.java` | Emulate the timeout LUT, SC protection mapping and periodic MIOT packer |
| `VerifyThermalCorrection.java` | Emulate the thermal corrector's final switch |
| `VerifyThermalStageDirty.java` | Emulate thermal stage hysteresis and the allocation dirty flag |
| `BindInfo.java` | Read-only: nearest function and its callers for each address |
| `DecompileAt.java` | Read-only: decompile functions at addresses plus their callees |
| `DumpByStrings.java` | Read-only: decompile functions referencing matching strings, with callers/callees |
| `EcdsaListing.java` | Read-only: disassemble the functions containing each address |
| `EcdsaXrefs.java` | Read-only: find literal-pool words equal to a value and their code refs |
| `OtaListing.java` | Read-only: disassemble a Thumb address range |
| `OtaRefs.java` | Read-only: references to addresses and instructions using given scalars |
| `StateListing.java` | Read-only: disassemble a range and list references to given addresses |
