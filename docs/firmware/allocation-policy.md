# Allocation policy: AD1204 0073

Date: 2026-10-16. Raw image SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
This document follows the allocation decisions of the host MCU. The
original-instruction fixtures use synthetic RAM. They are not charger measurements,
and they do not prove that the controllers accept the result. The missing
HUSB362/SC2021 firmware still controls negotiation.

The later [manager/thermal transition document](allocation-transitions.md)
verifies the startup C2 gate, the allocation trigger chain and the thermal
dirty/recovery path. It narrows the manager and scheduler limits that this earlier
document records. Physical controller acceptance is still not verified.

## Corrections to the earlier description

AI has a persistent **load class** and a separate **reduction class** that comes
from the protocol. They are separate bytes. Normal AI can give a classified
low-load C port 22.5 W and reserve 100/120 W for the other C port. The earlier
description said that all phone-like ports get 45/55 W. That was wrong.

The 9.2 V and 19 V comparisons use the **destination-voltage word** of the
controller. They do not use the measured port voltage. Several older references to
protocol 1/5/8 refer to reduction classes. For example, the Apple exception of the
classifier tests the Apple VID plus **reduction class 8**. It does not test native
protocol 8/PPS. Balance also has dynamic reduction-class branches in its two
lower-budget variants.

The AC selector is not simply a boolean. The scene branches compare it with **exactly 1**.
The final clamp tests **zero against nonzero**. Thus selectors 1 and 2 can give
different caps, although both skip the final clamp. The AC selector is separate
from the hardware flag that comes from GPIO.

## Inputs and decision order

| Input | Runtime location | Meaning / limit |
|---|---|---|
| Manager context | `2000cea8` | Count `+0b`, AC selector `+0a`, scene `+1b`, previous remaining budget `+24` |
| Port host state | `2000cf22 + port` | Nonzero contributes to manager active count and summed power hints; classifier requires state 2 |
| Power hint | `2000cf58 + 4*port`, u16 | Internal 0.1 W units; differs from instantaneous output |
| Reduction class | `2000cf5a + 4*port` | State retained/mapped by the [settling updater](protocol-settling-and-control.md) |
| Persistent load class | `2000cf18 + port` | C1/C2 only in the classifier; scene logic can also write it |
| Native protocol | `2000c998 + 6*port` | Separate enum; native 8 participates in AI's 19 V rule |
| Destination voltage | `2000cf8a + 18*port`, u16 | HUSB word 10; not measured output voltage |
| C1/C2 insertion timestamps | `2000cf6c / 2000cf70` | Used by `409078`; not manager-context `+44/+48` |
| Packed activity | `2000ec1c + 8*port`, bit 0 | Allocator uses this to determine idle-port reserve requirements |

Manager `4084c8` adds the hints of the ports that have a nonzero host state. Getter
`4092c0` returns the thermal-stage budget: **1200 / 1200 / 900 / 0** internal
units. For a nonzero budget it calls `406e30(output, portMode, budget-sum, budget)`.
For a zero budget it calls `409dc8`, which sets all four cap bytes to zero. See the
[thermal trace](thermal-capture-followup.md) for the threshold, counter and sensor
limits. The allocation does not divide the watts in proportion.

The allocator starts with the current cap bytes. It uses the selected startup row
to find the largest requested cap of the idle ports. The reconstructed startup rows
at `2000c2b6` and `2000c2bb` are both `0b 0b 80 70 60`. Only four entries are used
here. The port enable/disable handling changes the second row.

The allocator selects a scene table if one of these conditions is true:

- The remaining budget is smaller than the largest idle-port requirement.
- The internal power hints of C1 and C2 are both nonzero.
- The old or current disabled-port mask is nonzero, and the active count is nonzero.

If no condition is true, the RAW path keeps the current caps for active ports. It
restores the caps of the selected row for idle ports. Thus the scene name alone
does not set the result. Activity, host state and power hints come from different
caches. They can disagree during transitions. The fixture masks make them agree.

When a scene is necessary, the **total budget** selects its tier. The remaining
budget does not:

| Tier condition | AI | Apple / Hybrid | Single / Extreme | Balance |
|---|---|---|---|---|
| Budget >900 | `407104` | `4079d0` | `408180` | `407d1c` |
| Budget <=900, hardware flag nonzero, AC selector zero | `407508` | `407af8` | `408298` | `407e70` |
| Other budget <=900 cases | `407750` | `407bf4` | `4083a0` | `407fbc` |

Then port mode 1 sets disabled ports to zero. If the AC selector is zero, a final
pass adjusts the C-port cap codes:

| Input code / cap | Result |
|---|---|
| `04` / 55 W | `03` / 45 W only when hardware flag is zero |
| `06` / 65 W | `05` / 60 W only when hardware flag is zero |
| `07` / 70 W | `06` / 65 W |
| `09` or `0a` / 90 or 100 W | `08` / 80 W |
| `0b` / 120 W | `0a` / 100 W |

The pass runs **once**. Thus `0b -> 0a` stops at 100 W. SC codes such as `60`,
`80` and `a0` are not C-port code values. No generic watt slider or
additional app tuning command was found in these paths.

After allocation, the manager can force C2 to zero while its C1-startup gate at
context `+7` is 0 or 1. It sends only the changed C1/C2/C3 caps, but it always
calls the USB-A callback. See the
[SC shared-limit producer](secondary-controller-followup.md). These values are the
settings that the host wants. If a bus write fails, the hardware state can be
different. The fixtures below stop before that manager/callback/bus chain.

## Normal AI with both C ports active

This rule applies when exactly two ports (C1 and C2) are active and both load
classes are zero:

```
H(port) = (reductionClass == 1 AND powerHint >= 650)
       OR (nativeProtocol == 8 AND destinationVoltage >= 19000)
```

| H(C1) | H(C2) | C1 / C2 caps |
|---|---|---|
| True | False | 70 / 45 W |
| False | True | 45 / 70 W |
| False | False | Later timestamp gets 70 W, other gets 45 W |
| True | True | Earlier timestamp gets 70 W, other gets 45 W |

The 45 W entry becomes **55 W only for AC selector 1**. For selector 0, the final
clamp above applies after this step. C3 and A both get cap code `60` as reserves.

Helper `409078` compares the sign bit of the timestamp subtraction. The cases with
a missing, equal or wrapped timestamp are separate boundary conditions. They do not
give a guaranteed physical order. Writer `409e34` records the timer when a port
leaves host state 0. It changes zero to 1. State 0 clears the stored timestamp.
"Earlier" and "later" assume that the timer does not wrap between those events.
The order is the order in which recognition starts. It is not a cable trace.

Nonzero load classes have priority in this two-port normal scene:

| First matching condition | C1 / C2 caps | Load-class write |
|---|---|---|
| C1 class >=3 | 22.5 / 100 W | C1 becomes 4 |
| C1 class 1 or 2 | 22.5 / 120 W | C1 becomes 2 |
| C2 class >=3 | 100 / 22.5 W | C2 becomes 4 |
| C2 class 1 or 2 | 120 / 22.5 W | C2 becomes 2 |

These caps are before the clamp. AC selector zero still adjusts 100/120 W after
this step. With three or four active ports, classes >=3 have separate 22.5/70 W
branches. Classes 1 and 2 do not start the same two-port shortcut. The kept
fixture matrix records the baseline masks. It does not claim that these rows
cover every AI state transition.

The reported `04 07 60 60` snapshot can be reproduced with these conditions:

- Normal AI and AC selector 1.
- Both load classes zero.
- H is false for both ports.
- The C1 timestamp is smaller than the C2 timestamp.

An explicit fixture uses C1 hint270/reduction1/native7/destination9000 and C2
hint600/reduction3/native8/destination8500. This is a **possible explanation**
only. The capture from the user does not contain the scene, AC selector, load
classes, destination voltage or insertion timestamps. Thus it cannot identify that
branch with certainty.

## Fixed scenes and a lower-tier exception

The [machine-readable fixture summary](allocation-policy-0073.json) keeps all
15 normal-tier occupied-mask rows for Apple, Single and Balance with AC selector 2.
The caps include idle-port reserves. When exactly C1 and C2 are occupied:

| Scene | AC selector 1 | AC selector 2 |
|---|---|---|
| Apple / Hybrid | 70 / 55 W | 70 / 45 W |
| Single / Extreme | 100 / 22.5 W | 100 / 22.5 W |
| Balance | 60 / 60 W | 55 / 55 W |

The normal Apple profile does not depend on the VID. The lower Balance variants
examine the reduction classes and the power hints.

The AC-low Balance branch with three active ports and both C ports occupied uses
`H = reductionClass==1 AND powerHint>=300`. The same timestamp tie pattern selects
C-port codes `02/01` (33/22.5 W). C3 and A both get `a0` (7.5 W). This is evidence
of host policy. It is not an extra protocol or a mode that the user can select.

## Load classification and remaining limits

Full classifier `406b78` and companion `406db4` keep the persistent class. Before
they classify a port, they require host state 2 and a nonzero hint.

For a class that starts at zero, the main low-load test is reduction class 5, or
class 1 / Apple-with-class-8 with hint <=270. It also checks destination <=9200
and a rolling measured-power peak <20. With the existing telemetry scale, 20 means
2.0 W. It is not a 20 W threshold. If only one device qualifies, it becomes class 1.
If not, the class is 3. A fallback can select class 3 without the peak condition
(class 5, or the other qualifying types with hint<=220 and destination<=9200).
These labels are firmware policy states. They are not brands.

For classes that were already nonzero, the classifier uses current-power threshold
30 (3.0 W with the same scale), the destination voltage, the hint and the class
history. Companion `406db4` processes the first qualifying port on each call. It can
return its update indicator also when it writes the same class value. Normal AI
also writes class 2 and class 4.

The manager runs the full classifier again after the elapsed timer value is >=60000
in a stable AI scene that is not empty. The physical timer scale was not checked.
The isolated fixtures do not include full scheduler timelines, resets or concurrent
cache updates.

## Evidence and reproduction

[AuditAllocation.java](../../scripts/ghidra/AuditAllocation.java) repairs the
measured TBB destinations in a read-only Ghidra project. It keeps 22 exact
functions, the original instructions and the startup/flash table bytes. The
completed export has **2,396 instruction records**. All of them match the raw image.
Local directory: `artifacts/firmware/allocation-audit-20261016-complete/`.

[VerifyAllocation.java](../../scripts/ghidra/VerifyAllocation.java) runs the
original dispatcher, the scene bodies and the shared register/condition-flag
helpers. The logger and delay bodies are stubs. The hardware getter is scripted,
and the timer returns 1. The script checks:

- Output guards.
- The final clamp.
- Disabled-port zeroing.
- The remaining-budget store.
- The expected scene route.
- Selected rows that were transcribed separately.

The completed allocation run checks **1,058 fixtures / 324,790 original steps**.
This includes **226 independent expected rows**:

- 45 normal fixed-scene rows.
- 32 two-C AI power boundaries.
- 24 load-class precedence cases.
- 60 native/reduction/destination combinations.
- 64 AC-low Balance boundaries.
- The reported-pair example.

The other 768 baseline matrix cases and 64 port-enable cases check the
route/clamp/disable/store/guard properties and record the outputs. They are not an
independent reference model of every scene body. The 1,877 distinct executed
instruction records match the original bytes. Local directory:
`artifacts/firmware/allocation-verification-20261016-final/`. Summary SHA-256:
`ad948127f46645f0c5dc64d572218e9c3c0ea48f34aa8ca2d685fa5036d9c5e3`.

[VerifyAllocationLoadClass.java](../../scripts/ghidra/VerifyAllocationLoadClass.java)
separately matches **1,218 fixtures / 101,009 original steps**, with 245 original
instruction records. It tests:

- Both classifier entries.
- The host-state gate and the zero-hint gate.
- The difference between reduction classes and the Apple case.
- The hint, destination, current and peak boundaries.
- The first-port-only behaviour of the companion.

The current power, rolling peak, brand and logging helpers are scripted. memcmp has
exact five-byte semantics. The script compares the complete context plus guards,
and it accepts only the expected load-byte changes. Local directory:
`artifacts/firmware/allocation-load-verification-20261016/`. Summary SHA-256:
`43e1d8b3070798bca10ab5ed8af370bd9582052060e104777f2119b6f4e2fa26`.
The [JSON summary](allocation-policy-0073.json) keeps all input/output-file
digests, normal-scene rows, selected examples and explicit limits.

To repeat the results:

1. Use the reconstructed `AD1204_0073` project / `firmware.bin`, `-readOnly
   -noanalysis`, script path `scripts/ghidra`, and new absolute output directories.
2. Run the audit before the allocation verification in the same headless session.
   This keeps the repaired listing.

The Ghidra 12.1.4 fixed-Thumb callback workaround is local to each emulator. It
does not change firmware bytes or instruction p-code. The results come from Ghidra
analysis of the original bytes.

The first attempt stopped before it completed any fixtures. A merged cap-lookup
function needed an explicit boundary. Also, the synthetic startup enable row used
booleans, which was incorrect. The successful run checks the original startup
bytes before it applies synthetic enable masks. An expanded attempt found a
reversed hand-written timestamp expectation. Another attempt completed its cases
but could not export an unlisted shared helper. The final verifier disassembles
missing executed entries before export. It does not change the original
instructions. The ledger uses only completed exports with successful verification
metadata. The JSON summary identifies earlier partial and replaced outputs.

Not yet known:

- Real runtime snapshots of the scene and state.
- Behaviour with missing, equal or wrapped insertion timestamps.
- Every persistent-class transition across scheduler calls.
- Controller acceptance and renegotiation.
- Electrical behaviour during contention.
- The policy of the secondary controller.

No charger writes, protocol changes, protection overrides, APK installation or
firmware flashing were done.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository. The hashes are recorded for reproducibility.
