# Documentation index

These are reverse-engineering notes for the CUKTECH 10 Ultra (AD1204U) charger,
Xiaomi model `njcuk.fitting.ad1204`. This is unofficial interoperability
research. It is not affiliated with or endorsed by CUKTECH or Xiaomi. The notes
cover these subjects:

- the Bluetooth LE protocol of the charger
- binding and authentication
- the firmware structure
- the OTA/DFU path
- on-device features and telemetry

The analysed firmware is 2.1.2_0073 for the OnMicro OM6621Px (Cortex-M4) BLE
SoC. The raw image SHA-256 is
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
If a document does not say differently, the findings come from static analysis
of that image (Ghidra and bounded instruction emulation). They are not
hardware measurements.

This repository does not include vendor binaries. It does not include firmware
images, APKs, plugin packages or decompiled output. Paths under `artifacts/`
are local files that git ignores. These are downloaded vendor packages and
outputs that the tools in [`scripts/`](../scripts/) make again. The documents
record hashes, so that you can reproduce the results with the same inputs.

## Overview

- [Capability inventory](charger-capabilities.md): the functions of the charger, the functions that the app implements, and the items that need a hardware check.
- [Staged analysis log](firmware-analysis-log.md): a record of each analysis stage and its evidence, in time order.
- [Analysis boundaries and recovery](firmware-boundaries-and-recovery.md): the limits of static analysis, and the conditions to meet before a write or a recovery attempt.
- [Coverage ledger](firmware/coverage-ledger.md): the measured, reproducible coverage of the firmware by focused exports. It is not a percentage of "understanding".
- [Coverage inputs (JSON)](firmware/coverage-inputs-0073.json): input manifest for the coverage tool.

## Protocol & BLE

- [Unauthenticated BLE surface](firmware/findings-unauth.md): the AF00/AF07 factory channel and the settings that it can change without login.
- [Vendor status replies](firmware/vendor-status-map.md): byte-level map of AF07/AF08 status replies; [JSON companion](firmware/vendor-status-map.json).
- [Protocol, command formats and blobs](firmware/protocol-command-blob-followup.md): command byte orders, protocol-enable switches and remaining source blobs.
- [Protocol label audit](firmware/protocol-label-audit.md): the evidence threshold for each per-port protocol label.
- [App protocol labels (0.6.6)](firmware/app-protocol-labels-0066.md): mapping of official plugin protocol names into the app, with the tentative miPPS alias.
- [OPPO/vivo/VOOC audit](firmware/oppo-vivo-vooc-audit.md): the brand classifier, and if proprietary fast-charge protocols exist.
- [SC2021 protocol translation (JSON)](firmware/sc2021-protocol-translation.json): translator table for secondary-controller protocol codes.

## Binding & auth

- [Firmware download and additional controls](firmware-research.md): Xiaomi firmware metadata APIs, saved-session reuse, and extra MIOT controls.
- [Bind signature checks](firmware/findings-bind.md): standard-auth register flow and its ECDSA checks chained to the Mijia root.
- [DFU callbacks and auth boundary](firmware/dfu-auth-followup.md): optional DFU controls 5/6 and the unresolved auth-state-2 producer.
- [FE95 beacons and passive telemetry](firmware/beacons-and-passive-telemetry.md): beacon encoder, bind-key requirement and session-state bytes.

## Firmware structure

- [Firmware extractor](firmware-extractor.md): offline unpacker for startup data, fonts, color images and remaining slices.
- [Evidence lookup CLI](firmware-evidence-cli.md): query functions, strings and references in local Ghidra exports.
- [Controller paths, records and color assets](firmware/controller-and-assets-followup.md): controller writes, stored NV records and RGB565 asset decoding.
- [Controller field consumers](firmware/controller-field-consumers.md): how secondary-controller fields go into the policy and the UI; [fields JSON](firmware/controller-fields-0073.json), [verification JSON](firmware/controller-fields-verification-0073.json).
- [Secondary controllers](firmware/secondary-controller-followup.md): HUSB362/SC2021 cache failures, retries and remaining images; [verification JSON](firmware/secondary-controller-verification-0073.json), [data audit JSON](firmware/secondary-data-audit-0073.json).
- [Protocol settling and UFCS control byte](firmware/protocol-settling-and-control.md): settling counters, cached power snapshots and control-byte writers; [verification JSON](firmware/control-settling-verification-0073.json).
- [Allocation policy](firmware/allocation-policy.md): per-scene power allocation and persistent load classes; [JSON](firmware/allocation-policy-0073.json).
- [Allocation transitions](firmware/allocation-transitions.md): allocation manager, C2 startup gate and thermal recovery; [JSON](firmware/allocation-transitions-0073.json).
- [Device identification and power policy](firmware/findings-phone.md): PD chips, phone-brand detection and early scene-policy notes. The allocation documents replace part of this document.

## OTA / DFU

- [OTA transport and image integrity](firmware/findings-ota.md): FE95 DFU service, CRC checks, R2SF header and early function landmarks.
- [Signed-DFU ECDSA verification](firmware/findings-ecdsa.md): signature chain, pinned root key and the cached-verdict weakness.
- [DFU verify state byte](firmware/findings-state.md): the cached verify verdict, and why the boot rejects an unsigned image.
- [OTA transfer framing](firmware/ota-transfer-framing.md): Mi Home's native DFU manager framing compared with the receiver.
- [OTA receiver correlation](firmware/ota-firmware-receiver-followup.md): receiver-side handling of the official transfer.
- [OTA validation and recovery](firmware/ota-validation-recovery.md): host-side validation, resume and recovery boundaries.
- [In-app signed-firmware installer](firmware/in-app-flasher.md): how the app installs official signed firmware, and the risk of a bricked charger.

## Display / UI features

- [Display, buttons and extra features](firmware/display-and-hidden-features.md): ADC Assistant, Holiday artwork, button paths and other on-device workflows.
- [BEAST MODE](firmware/findings-beast.md): the unreachable, display-only BEAST MODE page.
- [Factory LCD tests](firmware/diagnostic-screens-followup.md): factory diagnostic screens and version display.
- [Status and stored settings](firmware/status-and-settings-followup.md): port status, fault presentation, screen-timeout enum and stored settings.

## Telemetry & protocols

- [Protocol labels and vendor temperature](firmware/findings-telemetry.md): per-port protocol display and the AF08 temperature byte.
- [ADC diagnostic](firmware/adc-diagnostic-followup.md): the calibrated temperature-style ADC byte and its arithmetic.
- [Thermal pipeline and capture](firmware/thermal-capture-followup.md): the thermal correction and state pipeline, compared with a diagnostic report from a user.
- [Sensor confirmation and monitoring](firmware/sensor-confirmation-and-monitoring.md): factory calibration record, NTC tables and app thermal monitoring.
- [Diagnostics sample (JSON)](firmware/diagnostics-sample-0073.json): an app diagnostic report from a user, with three AF08 frames and no credentials.

## Official app and plugin

- [Chinese Mi Home APK analysis](firmware/mihome-cn-apk-analysis.md): firmware/plugin metadata requests recovered from the host app.
- [Official charger plugin](firmware/mihome-charger-plugin.md): plugin acquisition, signature verification and first findings.
- [Plugin debug screen and firmware handoff](firmware/plugin-debug-and-upgrade-followup.md): account-gated debug page and native OTA handoff.
- [Plugin feature and write-path audit](firmware/plugin-feature-audit-20261016.md): plugin setters compared against controller state.

## Hardware

- [SWD reflash feasibility](firmware/findings-hw.md): desk research on OM6621Px programming and debug protection.
- [UART factory mode](firmware/findings-uart.md): mp-mode UART behind a GPIO4 boot strap. You cannot get access to it over BLE.

## Tools

The Python tools are in [`scripts/cuktech_pc/`](../scripts/cuktech_pc/). The
Ghidra scripts are in [`scripts/ghidra/`](../scripts/ghidra/README.md). For usage, see [firmware-extractor.md](firmware-extractor.md),
[firmware-evidence-cli.md](firmware-evidence-cli.md),
[firmware-research.md](firmware-research.md) and the
[coverage ledger](firmware/coverage-ledger.md).
