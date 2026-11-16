# Protocol label audit: 0073, 2026-10-14

The [stage-27 controller-field map](controller-field-consumers.md) shows that
the six-byte HUSB protocol cache has five data bytes and a checksum. Byte 4 is
the source of the cable-current popup. Byte 5 is integrity data. That map also
traces paths with mixed freshness. It does not change the active-protocol
labels.

**Current app state:** the [0.6.6 labels](app-protocol-labels-0066.md) do these
things:

- They use the named modes of the official plugin.
- They keep C1/C2 09 as a tentative **miPPS (likely)** alias.
- They keep the literal vendor PPS in diagnostics.
- They show the USB-A 02 disagreement.

The earlier firmware-only label decisions below are historical. There is no
new USB negotiation trace.

**2026-10-15 update:** the [official plugin version 60](mihome-charger-plugin.md)
gives a live UI mapping for MIOT 2.17/2.18: 3 QC, 4 AFC, 5 FCP, 6 SCP, 7 PD,
8/9 PPS, 10 UFCS. Codes 1/2 show 5V. This is vendor-display evidence in addition
to the firmware work below. The plugin does not call code 9 miPPS. The USB-A 02
disagreement with the upstream experiments stays. A shared renderer table
alone does not change the app labels. The earlier decisions below are
historical.

Target raw SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
Reviewed app changes: the property-cache fix, the controller UI changes and
the user-reported device readings. No protocol meter was available, so the
confirmation comes from the firmware. No charger session was started.

## Keep three different quantities separate

1. MIOT 2.1–2.4 byte 1 is a **software allocation code**. It is not a protocol
   enum. The value goes into the telemetry record through `0x405d88`.
   `0x4043ac` packs that byte together with deciamps and decivolts. The C1/C2
   allocation table is at `0x4093a2`. SC2021 has a separate namespace.
2. In MIOT 2.17/2.18, the high byte of each half is an **exposed protocol
   code**. The low byte is related controller detail. These are not the native
   SC2021 enum.
3. The output watts come from the reported voltage and current. If you read the
   protocol detail as a cap, it does not give the instantaneous draw. It also
   does not give a PDO/APDO voltage/current pair.

Stage 12 also checks the status/activity interpretation. The firmware UI
`0x4065c8` tests status bit 0 for active output. It uses mask `0x1fc`
separately for protection/state handling. The app uses bit 0, not "any
nonzero status byte". Thus `0x11` is active, but status-only `0x80` or `0x04`
is not active. The names of the other flags are not known, and the app keeps
them raw. An inactive output does not prove that no cable or device is
connected.

## Label decisions

| Value / scope | Evidence | Decision |
|---|---|---|
| C1/C2 `07` | Controlled upstream fixed-PDO sweep; user-reported iPhone/Samsung notes; identical HUSB362 reply/record path on both ports | Keep PD Fixed; externally corroborated mapping, not a new local meter test |
| C1/C2 `08` | Controlled upstream PPS-band sweep; user-reported Galaxy notes; firmware groups 8 with the PPS-like branch in `0x4087b0` | Keep PD PPS with the same scope limit |
| C1/C2 `09` | `0x406364` assigns Xiaomi when protocol 9 is present even without matching VID; `0x4087b0` groups 9 with 8 when its detail exceeds 15; named miPPS enable path exists; user reports Xiaomi phone and tablet | Strong miPPS candidate; retain **miPPS (unverified)** because the enum-to-name association is not explicit |
| C1/C2 `01·0f` | `0x4043ac` conditionally changes native `07·0f` into this exposed pair | Keep unnamed: the forward remap does not prove every exposed `01·0f` came from native 7, and does not establish a 5 V contract |
| C3 `07` | Stage 12 follows the explicitly logged C3 PD-load flag in `0x4152dc` to forced native `0e`; translator `0x408fd0` maps `0e` to exposed 7 | **PD**, firmware-reported category; no fixed/PPS distinction or new runtime test |
| Other active enums | Complete SC2021 translation tables recovered, but no explicit names for their native states | Keep raw; do not label them QC/AFC/FCP/SCP/UFCS from numeric resemblance |
| Protocol-enable switches | `0x409e84` takes miPPS, UFCS, PD, PPS arguments; its log deliberately prints PPS before PD; `0x40a5f4` names corresponding disable flags; `0x4158e8` names UFCS/SCP | Names are supported for **configuration switches**, not proof of an active session |

The primary experiment reports fixed-voltage sweeps and PPS-band sweeps. It
assigns codes 7/8 and matches the detail to watt caps. This supports the cap
units for those two codes. It does not give the names of other enums. Its
protocol guesses for port byte 1 do not agree with the firmware allocation
trace, so this document does not use them.
See [the original recorded experiments](https://github.com/zuyan9/ha-cuk-ble/blob/master/docs/properties.md).

Hynetek lists PD/PPS and legacy capabilities for HUSB362. This public document
does not define the CUKTECH command-83 enum and does not prove an active
contract:
[manufacturer HUSB362 description](https://en.hynetek.com/2603.html).

## Firmware trace of the detail byte

1. `0x414dac` reads HUSB362 command `0x83`.
2. `0x40a718` copies the returned six-byte record through `0x405e5c` into the
   per-port protocol cache at `0x2000c998 + port*6`.
3. `0x4043ac` keeps record byte 1 in MIOT 2.17.
4. `0x4087b0` starts its detail pointer at `0x2000c998+1` and moves forward by
   six bytes. It adds the values without scaling and logs the sum as
   `ProtocolPower` at `0x4751df` / `0x475224`.
5. The PFC/rail policy uses this sum together with the output power, which has
   a separate calculation.

This supports a controller power hint. The exact PDO/APDO meaning still comes
from controlled external measurements.

The app shows `cap N W` only for C1/C2 7/8. It keeps the detail raw for 9, for
1, for SC2021 values and for all other enums. A reported 15 W cap cannot
explain an 8.5 V observation without a synchronized native/exposed capture.
Check cached values, load transitions and remapping. Do not invent a contract.

## Stage 12: C3 PD confirmed in the reporting code

`0x4153c2` tests bit 2 of the first SC2021 status byte. On a PD-load
transition, `0x4153c8` selects the literal **C3 PD Load**, and `0x4153d2` sets
the cached flag to 1. At `0x415494..0x415498`, that flag selects native code
`0x0e`, and `0x41549c` stores it. The earlier label audit did not have this
explicit protocol-specific association.

The translator `0x408fd0` stores table `0x408ff8` in record byte 0 (protocol)
and table `0x408fe8` in byte 1 (detail). Do not reverse these roles. Thus
native 14 becomes exposed 7 with detail 30. The direct log/flag/code trace
supports the general C3 PD label. This table alone does not give the units of
the detail. It also does not show if the contract is fixed PD or PPS.

[sc2021-protocol-translation.json](sc2021-protocol-translation.json) keeps all
sixteen rows and the out-of-range fallback. Some native states become the same
exposed state. Thus an exposed code cannot give one unique native state. For
example, exposed 1 has five native sources and exposed 3 has four. For native
>=16, the fallback is exposed 1/detail 10. This is one more reason to keep
those codes unnamed.

The selected consumers show that native 13/15 skip a C3 advice animation
(`0x40a2a4`). That branch contains no SCP/UFCS names. The UFCS/SCP register
setters name their control arguments. They set disable bits `0x80`/`0x10` and
keep the other bits. They do not name the returned protocol enums. Code 9 is
still a Xiaomi/PPS-like candidate. It is not an explicit miPPS enum
definition. These negative results apply only to the selected reporting,
policy, classifier, auto-test and control consumers.

The exact instruction records and focused functions are kept locally in
`protocol-factory-followup-20261014-verified`. The script checks the image
hash. No active UFCS/SCP names were added from a guess of the usual numeric
order.

The canonical export has nine functions with 27 direct numeric references to the
cache range `0x2000c998..0x2000c9af`: `0x4043ac`, `0x405e5c`, `0x406364`,
`0x4065c8`, `0x4087b0`, `0x409784`, `0x409c1c`, `0x40a718`, `0x41c9b4`. They
cover packing, updates, classification, UI, rail policy, auto-test, connection
state, controller polling and vendor status. Their selected bodies have no
more explicit names for returned enums. This index does not include all
computed or base-plus-offset accesses, or indirect callers. Thus it cannot
prove that the names are absent from the full image.

## Evidence that can confirm the remaining names from firmware

The [OPPO/vivo/VOOC audit](oppo-vivo-vooc-audit.md) adds a classifier sweep
with the original instructions and research of primary chip sources. OPPO/vivo
brand labels do not show VOOC/VFCP. The configurable VOOC capability of HUSB362
does not name an active AD1204U enum. The app label decisions do not change.

These items can confirm the names:

- An explicit enum definition, a protocol-name lookup or a controller build
  that matches the firmware that makes the status. The main OTA contains
  callers and returned records. It does not contain the HUSB362/SC2021
  negotiation state machines.
- A protocol-specific branch that connects the returned enum to an explicitly
  named protocol, not only to a brand or a voltage.
- The related secondary-controller image or a matching command definition.

Until then, these items are not sufficient to prove which protocol was
negotiated:

- General chip support.
- A named enable bit.
- The charging of a Xiaomi phone.
- An enabled protocol mask.

The app keeps the raw records, so that future evidence can make the labels
better without data loss.

## Validation

The stage 18 [protocol/command confirmation](protocol-command-blob-followup.md)
checks all 8,192 C1/C2 initializer combinations against the original
instructions. This includes the AAPCS log argument order: miPPS/UFCS/PD/PPS
disable bits 0/2/3/4. The named PPS OFF branch sets bit 4 separately. The
switch labels are correct. The returned 09 name is still a candidate. The
extra USB-A QC observations are research leads, not universal enum
definitions. That document also gives a controlled procedure for an on-device
miPPS A/B/restoration capture.

The property-cache correction keeps 2.7, 2.17, 2.18 and 2.21. Before the
correction, the app discarded these parsed properties. A regression check
sends a parsed charger response through the controller cache. The UI changes
stay. The protocol tests keep the raw halves, keep the controller namespaces
separate, and show clearly which labels and cap interpretations are not
supported.
