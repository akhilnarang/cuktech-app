# Remaining controller fields and their policy consumers

The [stage-28 follow-up](protocol-settling-and-control.md) verifies the settling
and power-cache consumers. It also narrows the `mUFCSCtrl` writers. It traces the
SC copied tail to startup zero-fill and to caller bytes that the callers ignore.

Date: 2026-10-16, stage 27. Firmware `2.1.2_0073`, raw
SHA-256 `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`,
load base `0x00403000`. This document covers the remaining controller fields. It
traces bus replies into host caches, policy and UI. No physical bus, BLE or cloud
request, setting write or firmware update was sent.

The new findings are:

- The named destination-voltage field and its policy thresholds.
- The extra HUSB cache byte that is outside the response.
- The coupling between SC protocol validation and SC protection validation.
- The named `mUFCSCtrl` byte. Its meaning is not known.

Stage 13 already documented the cable popup and brand behaviour. This document
collects that information. It is not a new discovery or a protocol identification.

The [machine-readable field map](controller-fields-0073.json) covers all bytes of
the mapped HUSB 0x80–0x83 replies and both SC register-0x10 views. It is a bus
layout. It is **not a Bluetooth response layout**. It marks unknown fields as unknown.

## HUSB command 0x82: three unknown words, one policy voltage, one extra byte

Reader `0x414c80` requests 16 data bytes (`0x414c8c`). Checked transport
`0x403ef0` also stores a checksum at response offset 16 (`0x403f52`). Poller
`0x40a718` copies 18 bytes at `0x40a73c–0x40a748` to
`0x2000cf80 + port * 0x12`.

| Response byte(s) | Host interpretation / consumer | Evidence boundary |
| --- | --- | --- |
| 0–1 LE | Measured output-voltage value → `0x405d88` | Distinct from destination word |
| 2–3 LE | Measured output-current value → `0x405d88` | Ordinary telemetry pipeline |
| 4–5 LE | Native status word | Activity, recovery, factory-display and UI consumers below |
| 6–7 LE | Raw input to internal sensor LUT `0x414c70` | Existing temperature-like candidate; no added Celsius label or BLE route |
| 8–9 LE | Unresolved word | Read, checksum-covered, copied and checksum-error logged; no checked policy consumer |
| 10–11 LE | `mDestVoltage` | Explicit firmware name and policy uses below |
| 12–13 LE | Unresolved word | Same unresolved-consumer boundary as offset 8 |
| 14–15 LE | Unresolved word | Same unresolved-consumer boundary as offset 8 |
| 16 | Checksum | Integrity byte, not a measurement |
| 17 in host cache | Stack byte outside the received response | Copied by host; no checked field consumer identified |

Do not call the unknown words padding. Do not give them temperature or PDO
meanings. Their bytes are part of the checked response, and they appear in
diagnostic logging.

The eighteenth cached byte is different. The reader never sets it from the
controller. The copy stays inside the allocated local array, but it includes a
stack byte from outside the response. No checked Bluetooth packer sends that byte.

The reference search finds five functions that read this raw-cache interval:
`0x406b78`, `0x406db4`, `0x4087b0`, `0x409784`, `0x40a718`. Function `0x40a57c`
gets the status as an argument. Thirty-one aligned raw literals point to the
common base `0x2000cf28`. The base uses and the annotated field reads are listed
separately. This search does not cover computed aliases, missing ROM or code that
was not found.

### Destination voltage is not measured output voltage

Three original strings identify the word. The name does not come from a guess
based on its values:

- `0x406da8 → 0x4752af`: ADC/power-setting log with `mDestVoltage`.
- `0x408c50 → 0x475224`: large-power policy log with both `mDestVoltage` and `Voltage`.
- `0x409b04 → 0x475279`: existing automatic-test log with `mDestVoltage`.

| Consumer | Exact comparison / behaviour |
| --- | --- |
| High-power eligibility, `0x40a754–0x40a764` | Hardware-global flag nonzero: unsigned destination word >5500 becomes the argument to named `UsbIfaceSetHighPower` helper `0x409dd8` |
| Reduction classifier, `0x406b78` and `0x406db4` | Uses <=9200 / >=9201 with prior reduction state, power/current getters, protocol/class and other-port occupancy |
| PFC decision, `0x408a00–0x408a0c` | In the hardware-global branch, C1/C2 destination >12999 contributes to large-power requirement; C3/A use a separate measured-voltage branch |
| Existing automatic test, `0x409a36–0x409a46` | Protocol 8 plus destination >18999, or an alternative power threshold, selects its test state/delay |

The reduction comparison is not a standalone thermal limit or voltage limit. No
new user-settable threshold was found. The number scale is consistent with mV. The source
name does not decode a PDO/APDO, and it does not measure voltage by itself.

Getter `0x417d60` reads `0x2000eb7d`. This is the
[hardware-derived isGlobalVersion flag](vendor-status-map.md) from an earlier trace.
When the flag is zero, the worker uses activity for its high-power callback. The
earlier selector-2 report from the user had this flag clear. Do not apply the 5500
rule to that charger from this trace. Do not confuse the flag with the account
region or the server region.

### Native status bits: names only where consumers establish them

- Bit 0 gates the command-0x83 read (`0x40a7d0–0x40a7e8`). It drives aggregate
  activity through `0x40a57c`, and it reaches ordinary telemetry.
- Bits 2 and 7 (mask `0x84`) are part of the existing recovery subset. If they
  are absent, the firmware clears temporary HUSB control bit 1 and reconciles the
  settings (`0x40a808–0x40a818`). The earlier cross-port recovery-index quirk
  is still present.
- Bit 9 (`0x0200`) starts a factory-version display path. It is not an identified
  electrical fault. While UI-mode getter `0x417ba4()` equals 2, its counter
  increments. From count 5 it requests the version display and mode `0x80`
  (`0x40a772–0x40a7c4`).

The generic UI error mask `0x01fc` and disabled-state bit 11 from the earlier
trace do not give individual OVP/OCP/OTP names. These native u16 flags are
different from the ordinary MIOT low status byte.

### A later protocol-read failure also blocks telemetry publication

The original worker first copies the successful 0x82 response. Then, if the
active status requires 0x83 and that read fails, branch `0x40a7e8 → 0x40a858`
returns. The return occurs before the telemetry accumulator and the protocol-cache
updater. Thus the raw controller cache can be new while the downstream telemetry
is old.

With hardware-global flag 1, the destination-based callback occurs before this
failure. With flag 0, the activity-based callback occurs after it, so the firmware
skips it. This is host ordering. No failed read was seen on a charger.

## Other HUSB fields: cable byte, version omission and opaque UFCS control

Command 0x83 has five data bytes plus a checksum. Its cached six-byte record
at `0x2000c998 + port*6` is:

| Byte(s) | Confirmed consumer |
| --- | --- |
| 0 | Native protocol, reporting and settling logic |
| 1 | Power-detail hint, PFC/rail policy, MIOT detail |
| 2–3 LE | Controller-reported vendor ID → `0x406364` brand classifier |
| 4 | UI cable-current value → `0x406792` / `0x406a74` / `0x41f77c` |
| 5 | Checksum; included in cached comparisons, not a sixth data field |

The byte-4 path stores widget `0x2000cd14 + 0x3b`. Renderer `0x40d700` formats
it as `%dA Cable` for recognized brand classes. This shows how the firmware UI
interprets the byte. It does not decode an e-marker, a cable identity or a
physical current rating. The [stage-13 brand audit](oppo-vivo-vooc-audit.md)
already traced that popup. The popup is not evidence of VOOC or of another active
protocol. The mapped MIOT/AF status replies do not export this cable byte or the
vendor-ID word.

Command 0x80 returns three LE words plus a checksum. AF selector 1 reads into
buffers `0x2000c60e` and `0x2000c616`. Function `0x41cae4` copies only words 1
and 2 into its response (`0x41cb20/0x41cb2e`). It omits word 0. The policy meaning
of word 0 is not known. The exact identity of the two displayed version words is
also not known. None of these words is a confirmed bootloader-version field.

Literal `0x40a6e0 → 0x4757e7` logs command 0x81 byte 3 as `mUFCSCtrl`. Loads
`0x40a654/0x40a656` supply the desired value and the read value. At
`0x40a696–0x40a6a0`, a mismatch starts reconciliation. The desired C1/C2 bytes
are set to 0x3c at `0x409442/0x409444`. The encoding and the physical effect are
not known. **The value 60 is not confirmed as watts, amps or temperature.**

This byte is separate from the named UFCS enable bit in byte 1. Byte 2 is the
HPower field from the earlier trace, which comes from the AC selector. A mismatch
of byte 2 alone does not start a write. These internal bytes do not show a new
remote control.

## SC2021: validation couples protocol and protection consumers

Normal register-0x10 response bytes 10 and 11 must both be <=15
(`0x415410–0x41541e`). An invalid byte takes the error/log path and rejoins at
`0x41542a`. It skips all of these:

- Protocol cache updates at `0x2000ce90/91`.
- Protection cache updates at `0x2000ce92/93` and low-nibble status mapping.
- The configuration replay that protection bit 7 starts.

The C3/A voltage, current and activity stores occur before this check. Thus the
native protocol and protection caches can stay old while those values update.
The register-0x20 disabled-status handling that follows can still overwrite the
status. The isolated verifier stops before that stage.

**This finding is about host parsing, reporting and replay. It does not show that
the electrical protections of the controller are disabled.** No real out-of-range
packet was captured.

Getter `0x4158d8–0x4158e4` copies six bytes from `0x2000ce90` and always returns 1.
Thus the checked callers at `0x409f82/0x409fd8` cannot use their voltage fallback
for a getter failure through this getter. A success return does not show that the
data is new. No producer was found for the last two copied bytes
`0x2000ce94/95`. The normal parser writes only the first four. The later
follow-up traces the startup zero-fill. It also confirms that the checked
reporting callers ignore all four nonprotocol bytes that the getter copies.

### Unexplained SC bytes and view selection

The normal view and the NTC/version view both read 17 bytes. CRC helper
`0x4146bc` uses initial value 0xa5 and MSB-first polynomial 0x31. It covers bytes
0–14. The caller compares byte 15 and also rejects a zero CRC. Byte 16 is outside
that integrity check. The normal raw buffer starts at `0x2000ce96`.

| View / remaining field | Checked interpretation |
| --- | --- |
| Normal status byte 0 | Bit 0 activity; bit 2 drives C3 PD-load latch; other bits unnamed |
| Normal status byte 1 | Bit 0 activity; other bits unnamed |
| Normal byte 14 | CRC input only in mapped consumers; no added telemetry meaning |
| Either view byte 16 | No checked field consumer; not CRC-protected; not called padding |
| NTC/version bytes 0–7 and 14 | CRC-covered, no mapped field consumers |
| NTC/version bytes 8–13 | Existing BE software-version and two NTC ADC words |

Register 0x21 selects the response view and the measurement-current range. The
known view/current values are 0x08/09/0c/0d. The low two bits select the normal or
NTC view. The existing conversion routine switches its logged range between
20 µA and 100 µA. These are sensor settings. They are not extra charging protocols.

The setter at `0x415a78` caches the desired view and range before it tries the
bus write. After a failed write, the same request without force can return success
and not write. If the write is acknowledged but the readback does not match, the
function replaces the cached register with the readback and then returns failure.
This static result adds to the [earlier cache review](secondary-controller-followup.md).

## Verification, retained evidence and remaining work

[VerifyScStatusGate.java](../../scripts/ghidra/VerifyScStatusGate.java) passes
4,744 fixtures / 329,500 original steps. The fixtures include:

- Valid protocol pairs and the invalid values 16 and 255.
- Each protection-byte value on each port.
- Both PD-load states.
- Checked replay arguments.

The original protection helper bodies execute. The entry assumes that the CRC is
accepted and that both ports are active. The logger, delay and bus bodies are
stubs. Execution stops before register-0x20 handling. All 162 distinct executed
instruction records match the original bytes.

[VerifyHusbStatusFields.java](../../scripts/ghidra/VerifyHusbStatusFields.java)
passes 48 fixtures / 3,666 original steps. The fixtures cover both ports,
destination values 5499/5500/5501 independently of measured voltage, both mode
values, activity, and 0x83 success and failure. The script checks callback order
and arguments, the 18-byte raw cache, controlled stack poison and context guards.

External helpers, including memcpy and the bus and checksum bodies, have explicit
stubs. The copied-byte test uses the original 18-byte argument with an exact
bytecopy stub. Thus the script does not independently emulate memcpy or the physical transport.
All 104 executed records match the raw bytes.

Both scripts use the instance-local fixed-Thumb Ghidra workaround from earlier
stages. They do not change the firmware or the p-code. The
[verification metadata](controller-fields-verification-0073.json) keeps the
assumptions, stubs and paths that were not executed. There was no full-controller
emulation, calibration, negotiation or physical failure test.

[AuditControllerFields.java](../../scripts/ghidra/AuditControllerFields.java)
keeps 22 exact functions / 1,568 byte-matched instruction records, named
strings and annotated RAM references. The read-only project changes were discarded.

| Local artifact under `artifacts/firmware/` | SHA-256 |
| --- | --- |
| `controller-fields-audit-20261016-complete/functions.jsonl` | `0e2129a24d2636f93cbbdf385f7ac2dd28330080ee4f0a74b2d96b63c94465f2` |
| Its `instructions.jsonl` | `8f00f8618ad71b493deee1e5337288d63406a0f67353983c1397ff8278be2168` |
| Its `analysis.json` | `f052e9e4951135911098d6d97f6d263b830e028a258445b0b7f013e41a4a53e2` |
| `sc-status-gate-verification-20261016/verification.json` | `24d77c282ff6ba1d2a18a43033c1e2b9bce80d0b9cae17098157ed9449fea827` |
| `husb-status-fields-verification-20261016/verification.json` | `edb723e1eb5a33d1f8851ffae0ee8cdef9b7f589fd4f1fb451c2d63ed857a950` |

To repeat the results:

1. Run the three scripts against the reconstructed project with `-readOnly
   -noanalysis`, as in the [previous stage](secondary-controller-followup.md).
2. Use new output directories.
3. Check the result metadata and the Ghidra log.

| Investigation question | Result | Remaining boundary |
| --- | --- | --- |
| Which unexplained HUSB words affect policy? | Destination word named and thresholds mapped | Words 8/12/14, UFCS-control encoding and independent units remain unresolved |
| What are the cable and version bytes? | Existing cable display linked to byte 4; AF version omission identified | Controller-side acquisition/e-marker/word identities unavailable |
| Can caches claim success while containing older fields? | Original-instruction proof for the two specified paths | Physical frequency, later recovery and captured timing remain unknown |
| Do remaining SC bytes reveal new settings/sensors? | No new meaning for CRC-only/unchecked bytes; view/range roles separated | Matching controller definitions or passive capture required |

The app version stays at 0.7.1. This stage adds no new BLE field, active-protocol
label, control or APK. Unrelated app builds and tests were not run again. Vendor
decompilation and generated execution logs are not in Git.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository. The hashes are recorded for reproducibility.
