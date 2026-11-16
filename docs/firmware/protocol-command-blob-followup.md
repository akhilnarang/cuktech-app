# Protocol confirmation, command formats and remaining blobs: 0073

2026-10-15, stage 18. Scope: more work on commands, blobs and controls. The
priority is the confirmation of miPPS and of other protocol values. Raw SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
The existing raw and expanded memory and the read-only Ghidra project were used
again. There was no new cloud login, charger request, protocol change or
hardware experiment.

## Protocol decisions

| Protocol/value | What is established | What is still missing |
|---|---|---|
| C1/C2 PD Fixed, returned 07 | Original reporting path plus independently recorded fixed-PDO sweep | No new local contract measurement |
| C1/C2 PPS, returned 08 | Original policy/reporting path plus independently recorded PPS-band sweep | No new local contract measurement |
| C3 PD, exposed 07/native 0e | Explicit PD-load log → flag → forced enum → translator | Fixed/PPS subdivision |
| miPPS enable | Named control, inverted controller bit and MIOT mapping verified against original instructions | Actual supported sink/cable behavior on this unit |
| C1/C2 returned 09 | Xiaomi fallback in classifier, PPS-like policy grouping and user-reported Xiaomi sessions | An explicit enum-name definition or controlled switch/session correlation; remains miPPS candidate |
| UFCS/SCP enables | Named register/configuration controls and MIOT mapping | Universal active-code association for returned native/exposed values |
| USB-A exposed 02 | External experiment reports it with QC | Exact QC generation and a universal enum binding; retain as a research candidate |
| USB-A exposed 04 | External experiment reports a QC2/SCP ambiguity | Unique active protocol name |
| OPPO/vivo/VOOC | Brand classifier and chip capabilities are separate evidence | A target-specific active VOOC/FlashCharge association |

The [controlled experiment](https://github.com/zuyan9/ha-cuk-ble/blob/master/docs/properties.md#pdo-cap-halves-piid-0x11--0x12)
of the original author reports 07 for the fixed contracts and 08 for both tested
PPS bands. It also records USB-A 02/04 observations. Original firmware evidence
replaces its guesses for port-info byte 1 and its timeout enum. Do not copy its
full table as authoritative. User reports that use the 09 label of this app do
not prove that label independently. The app has no new active-protocol names
that are not confirmed.

The [HUSB362 brief](https://www.hynetek.com/uploadfiles/site/219/news/2e70a98f-c05d-4c51-ba5d-1b582d828d15.pdf)
from the manufacturer confirms programmable PD/PPS and legacy-protocol
capability. It contains no CUKTECH command-83 enum definition. The
[SC2021A product description](https://www.southchip.com/en/product/SC2021A)
from Southchip describes its MCU/PD/dual-DPDM controller. It does not define the
returned protocol-byte values of this firmware. These sources do not give the
active miPPS/UFCS/SCP/VOOC labels for this charger. The capabilities of other
Southchip variants are not evidence about the controller build in this charger.

## Named enable controls: stronger verification

| C1/C2 control | MIOT 2.21 C1 bit | C2 bit | HUSB command 81 byte-1 disable bit |
|---|---:|---:|---:|
| PD | 0 | 8 | 3 |
| PPS | 1 | 9 | 4 |
| UFCS | 2 | 10 | 2 |
| miPPS | 3 | 11 | 0 |

The MIOT bits are enables. The controller bits are inverted disables. Mask 0xe2
keeps the other controller bits. C3/A keep their separate UFCS/SCP controls.
Their enable names do not name all the native enums that the SC2021 returns.

Three paths agree on PD/PPS:

1. Initializer `0x409e84` maps its real arguments
   `(port, miPPS, UFCS, PD, PPS)` to bits 0/2/3/4. The log format at `0x475117`
   prints miPPS/UFCS/PPS/PD. The `STRD r6,r3,[sp]` at `0x409ec6` supplies the
   fifth input before the fourth, to agree with that format.
2. Reconciler `0x40a636..0x40a64f` extracts bit 4 and then bit 3 into the first
   and second stacked arguments of its PPS/PD log. Helper `0x4054fe` only puts
   the port into r1. Read the stack arguments in AAPCS order. The printed order
   is not the source-argument order of the initializer.
3. The named PPS OFF branch `0x409826` of ADC Assistant clears through
   `0x405382`, adds 0x10 at `0x40982c` and stores through `0x40540e`. Log literal
   `0x409af8 → 0x4753d5` says PPS OFF. UFCS OFF adds 0x04.

The PD/PPS switch labels of the app were already correct. An older internal
note listed the initializer arguments as miPPS/UFCS/PPS/PD. That note is
corrected. The returned active enum is a different field. This control-bit
proof alone does not give it.

[VerifyProtocolSwitches.java](../../scripts/ghidra/VerifyProtocolSwitches.java)
executes the original initializer block through argument preparation. It stops
before the logger call at 0x409ece. It checks both ports, all 256 original
disable bytes and all 16 boolean enable combinations: 8,192 cases / 212,992
original instruction steps. All expected disable bytes, named-log arguments,
reserved bits and other context bytes agree. Python calculates each result
again independently. All 26 executed instruction records agree with the original
bytes. Only the stack layout of the skipped prologue is supplied. There is no
logger, bus, ROM, controller negotiation or hardware execution. This
straight-line block does not need the ARM callback workaround.

## Another HUSB field is an internal reconciliation detail

`0x408ecc` fills command-81 byte 2 from the boolean `AC selector == 2`. The log
calls it HPower. Before the four-byte write, `0x40a5f4` compares response bytes
0, 1 and 3. It does not compare byte 2. If only byte 2 is different, that
routine does not send. The value can go with a later write that another field
causes. In the checked routes, no new remote override sets it. This is not
evidence of a selectable high-power unlock or of a confirmed firmware bug.

## Vendor protocol writes use a different byte order from MIOT

F1 group 1 selector 8 loads four request bytes. Then `0x4223a8` combines them
big endian at `0x4223d0..0x4223da` and calls `0x404dd0` at `0x4223dc`. Thus
payload bytes `03 03 0f 0f` mean mask 0x03030f0f. MIOT 2.21 uses its normal
typed little-endian u32. If you reverse those four AF bytes, the write addresses
different controls and reserved bits.

Selector 7 takes four independent bytes and changes each to `!=0`. Then it calls
the port setter in C1/C2/C3/A order through Thumb literal `0x4223a4 → 0x409609`.
Its payload is not a u32 port mask.

Both handlers return fixed success markers. They do not read the state back:

| Setter | Fixed AF08 response |
|---|---|
| Ports, selector 7 | `fe dc ba 01 f1 07 01 01 ef` |
| Protocols, selector 8 | `fe dc ba 01 f1 08 01 01 ef` |

These responses do not prove an accepted configuration or a renegotiated
protocol. The common AF entry also pauses MIOT packing before it identifies a
selector. Thus reconnect before you treat ordinary telemetry as current. The app
continues to use its existing authenticated setters and readback.

The [offline frame describer](../../scripts/cuktech_pc/firmware_commands.py)
does these steps:

1. It accepts the exact measured F1 shapes.
2. It reports the endianness, the validators and the ACK limitations.
3. It decodes the twelve named enable bits and keeps the unknown bits in its
   report.
4. It identifies Holiday queries and Holiday writes.

It never builds or sends writes. Run it from `scripts`:

```powershell
uv run -m cuktech_pc.firmware_commands "fe dc ba 01 f1 00 01 08 03 03 0f 0f"
```

The `mutation` field tells if the known setting writer can run. If a request with
`mutation=false` is delivered, it also pauses the telemetry. This tool does not
classify commands as safe for hardware.

## Action callback and dispatcher closure

Registration `0x42165c` supplies the action callback literal
`0x4216ac = 0x41d369` through `0x41ba00` to RAM `0x2000d220`. The generic parser
`0x41be70` uses the slot. The application callback `0x41d368` logs SIID/AIID and
first writes result zero. Then it checks only the AIID. AIID 1 goes to the
existing reset-settings implementation. Other AIIDs return success and do
nothing. This callback has no SIID check of its own. Upstream authentication and parsing
are a separate limit. A success response does not show that another action
exists.

The measured AF group-1 TBB has exactly nine entries, selectors 1..9. This
dispatcher has no other group-1 selector. The other existing groups, the
manufacturing UART and the missing ROM are separate surfaces. ROM
`0x1129a0(0x0f)` has no known name. No speculative selector or action was sent.

## Remaining blobs are not all separate images

The [blob inventory](../../scripts/cuktech_pc/firmware_blob_inventory.py)
compares the unclassified source ranges of the extractor with the unchanged
canonical Ghidra function-body address sets. For the measured image:

| Measurement | Result |
|---|---:|
| Unclassified extracted intervals | 31 |
| Their source bytes | 167,942 |
| Bytes inside canonical function bodies | 113,990 |
| Bytes outside those bodies | 53,952 |
| Intervals with function-body overlap | 2 |
| Full-raw ELF / PNG / ZIP-local-header signatures | 0 / 0 / 0 |

The largest interval starts at file 0x130 and contains the main executable
region. The function-body overlap is automated evidence. Function bodies can
contain data or incorrect boundaries. The bytes outside the bodies can contain
literals, strings, tables and code that was not identified. The ASCII and
pointer counts are only candidates. No signatures does not exclude a
headerless, compressed, encrypted or other-architecture image. No new
secondary-controller image was found.

To repeat the inventory, run this command from `scripts` with a new report
path:

```powershell
uv run -m cuktech_pc.firmware_blob_inventory ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-1.bin ../artifacts/firmware/extracted-0073-20261015 ../artifacts/firmware/ghidra-final --output ../artifacts/firmware/my-blob-inventory.json
```

## Kept evidence and next confirmation step

[AuditProtocolAndCommands.java](../../scripts/ghidra/AuditProtocolAndCommands.java)
keeps 28 exact functions / 633 original instruction records. It also keeps the
named-log bytes, the translation and dispatch tables and the callback
registrations. Six small shared functions get measured boundaries. All
instruction and table bytes agree with the raw image. The decompiler warnings
about missing ROM stay visible. The original instructions give the argument
order. The read-only project changes are discarded.

Local identities:

- `protocol-switch-verification-20261015/verification.json`:
  `3aaee982b9a3d83a4d6e2645cdfae1f3af9e261d9e6e7f2149c1cf6d88aec465`.
- `protocol-command-audit-20261015/functions.jsonl`:
  `a637093ce73026b8cd6bd9d3a4423abffe112006387b8c15aea121c3c825ff53`.
- Its `instructions.jsonl`:
  `25609a2901c1d71c1f33fd9a4073a1642e6eeae9eda8b1cb4db7ba9ebf45ff21`.
- Its `analysis.json`:
  `e80d85592c9dcf413a1d9d9cdac362ce1319db87ffc9467c1e2f72a128ac816b`.
- `blob-inventory-0073-20261015-stage18.json`:
  `8582149f4c7d3ceb2045abeb2dc70f46287f26af93183e77027694decc2aecf8`.
- Stage-18 coverage report:
  `14e70c5ec55d51b5bd59622d8afdeab375fd241eb9613c5a4376950e79f9444b`.

All 51 offline firmware-tool tests pass. App 0.6.5 and its APK do not change.
The coverage keeps 254 focused entries: 233 of the unchanged 1,145 canonical
entries and 21 outside them. 912 entries are not selected. 6,163 instruction
addresses / 16,420 unique flash bytes agree with the original image. These are
evidence counts. They are not a percentage of the firmware that is understood.

A controlled on-device test can help to name the active value 09 without a
protocol meter. This test was not done.

CAUTION: Change only the miPPS bit. Keep all other bits unchanged.

1. Use one Xiaomi device, one cable and one port.
2. Save the original mask.
3. Enable the miPPS switch. Then disable it. Then restore it.
4. After each change, confirm the readback of the setter.
5. Wait for a stable renegotiation.
6. Reconnect. Then save new native and ordinary protocol records, each with its
   own time.
7. Do the sequence again. This separates the switch effects from cache and
   attachment changes.

If 09 always disappears and comes back with the switch, this is a strong causal
link to the named control. It does not decode USB wire packets or exact PDO/APDO
contracts. A matching HUSB/SC controller definition or image is the best fully
offline route to the enum names.

Command widths, byte order, ACK interpretation, enable-bit names and source
accounting are now closed. These items are still open: active miPPS, the
remaining UFCS/SCP/QC enum names, matching controller firmware, reserved
fields, ROM definitions and physical behavior.

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
