# Allocation manager, C2 startup and thermal recovery: 0073

2026-10-16. Raw image SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
This document follows the [allocation decision tables](allocation-policy.md)
into their manager, the desired-cap callbacks and the thermal-stage trigger.
Static original-byte evidence and synthetic instruction execution do not prove
hardware behavior. No charger or cloud operation was done.

## C2 waits for a startup timer

The state byte is `2000cea8+7 = 2000ceaf`. Its timestamp is context `+3c =
2000cee4`. The recovered writers set these states:

| Event | State | Original instructions |
|---|---|---|
| Initialization | 0; timestamp0 | `40943c..40943e` |
| First C1 desired-cap callback while state0 | 1; timestamp=current timer, **including cap0** | `40a976..40a986` |
| Manager sees state1 and elapsed>=1500 | 2 | `40850e..408528` |
| C2 callback receives a nonzero desired cap | 3 from any prior state | `40a98a..40a992` |

In state 0/1, the manager writes zero to its **local desired C2 cap** at
`408682..408686`. This occurs before it dispatches cap changes. Thus, if a C1
callback starts the timer during that dispatch, it cannot enable C2 in the same
manager call. State 2 forces one more allocation. Then a nonzero C2 callback
records state 3. State 2 can stay in these cases:

- C2 stays disabled or zero.
- The desired cap of C2 is already the same as the cached value, so no C2
  callback runs.

The desired-cap store and the state/timestamp changes occur **before** the
reconciler call `40a5f4`. The manager does not use the return value of that
call to release the gate. Its `TYPE_C1_POWER_SET_STATUS_SUCCESS` log is for an
elapsed timer event. It does not prove a controller ACK, a successful PD
contract or measured electrical settling. State 3 means only that the manager
dispatched a nonzero C2 cap.

The limited writer search examined all 38 exact raw literals of the manager base
`2000cea8`, their available references and the recovered original store paths.
For this state, it found only the initializer, timer and callback writers
above. It found no rearm after disconnect or error. The error-clear helper
`408f6c` changes a separate desired configuration bit and calls the reconciler
directly. The search did not exclude computed or general memory writers, or
code outside this OTA. This supports a startup ordering gate. It does not show
a new delay after each cable insertion.

In a synthetic test, state 0 with a C1 cap that already equals its desired
value can stay in state 0, because the callback does not run. This is a limit
of the isolated manager test. It is not evidence that a real startup gets to
that condition or stops there. The usual initialization and the surrounding
scheduler and controller paths are also important.

## Timer units and wrap

The elapsed helper `415d30..415d42` calls the timer source and calculates:

```
now >= start:  now - start
now < start:   now - start - 1       (unsigned 32-bit result)
```

The wrap branch uses `~start`, not `-start`. Thus it gives one count less than
usual modulo subtraction. The gate compares the result of this helper with
1500. Boundary fixtures test source-count differences of 1499/1500/1501 across
the wrap. These are firmware timer units. Their wall-clock duration is not
known.

## What causes a new allocation

The manager `4084c8` counts the ports with a nonzero host state and adds only
their power hints. Its trigger chain `40857a..4085ca` requests an allocation if
one of these conditions is true:

| Condition | Compared input/cache |
|---|---|
| Active count changed | Current nonzero host states versus context `+0b` |
| Summed hint changed | Current sum narrowed to u16 versus `+2c` |
| Port mode changed | Caller argument versus `+17` |
| Disabled-port mask changed | Current enable row versus `+1d` |
| Explicit dirty flag | `+0f != 0` |
| Scene changed | Getter `404784(3)` versus `+1b` |
| C2 startup release pending | `+7 == 2` |
| ADC Assistant state | `+1 == 3` |
| Load-class helper requests work | Return value >=3 |

This trigger chain does not check thermal-stage changes or AC-selector changes
directly. You must also consider their real producers and dirty signals. A
synthetic change of one cached byte alone is not a usual charger event.

The manager selects full AI classification when all these conditions are true:

- The count is nonzero and did not change.
- The cached scene is AI.
- The time since `+30` is >=60000.

In other cases, the companion helper runs. The earlier allocation document
verified their internal class rules.

On reallocation, the manager does these steps:

1. It clears dirty at `408618`.
2. It updates the count, hint, scene and disabled-mask caches.
3. It gets the current budget through `4092c0`.
4. For a nonzero budget, it passes **signed16(budget-sum)** and the total
   budget to the allocator.
5. It clears context `+0` and dispatches the changed caps for C1/C2/C3.

The USB-A callback runs also if its cap did not change. A stable call that does
not go into reallocation does not dispatch that USB-A callback.

The callback processing updates the desired host caps before reconciliation.
With a scripted reconciler return value of 0 or 1, those stores stay updated.
The tests do not include the transport and reconciler bodies. Thus these
values are not observations of physical failures. Controller polling, retries
and blocking inside the bus helpers are not part of the isolated manager test.
There is no proof of a permanent failure, and no guarantee that the loop
continues.

## Thermal changes request allocation, also on recovery

The evaluator `408c7c` stores a new stage at `408d2e`, resets its transition
counter and writes **dirty=1** at `408d34..408d36`. This occurs for heating and
for cooling. It also occurs for stage 0↔1, where the budget stays 1200. The
manager uses the dirty flag and the budget of the new stage:

| Thermal stage | Internal budget | Manager behavior |
|---|---:|---|
| 0 | 1200 | Normal allocator tier when a scene is selected |
| 1 | 1200 | Same budget; dirty still requests reallocation |
| 2 | 900 | Lower-tier scene allocation |
| 3 | 0 | Original helper `409dc8` fills four zero desired-cap bytes |

The zero-budget path does not go through `406e30`. Thus that path does **not
update** the previous remaining-budget cache at `+24`. It is not a measured
power report. Recovery from 3→2 sets dirty again and selects 900. The next
recovery to 1/0 selects 1200. These traced host branches do not need a user
reset. The real controller shutdown and restart, and the start of charging
again, are separate hardware questions.

The scheduler `409728` calls the manager at `409752`, then does other control
work. At `409774`, its tail branch goes to the thermal evaluation. Thus a
transition at that tail requests allocation on the **next eligible scheduler
pass**. The scheduler needs signed `(tick-reference)>=21`. It moves the
reference forward by 20. It does not set the reference to the current tick.
This order does not give a fixed wall-clock interval, IRQ atomicity or an
electrical-response delay.

The thermal transition counter is the same for both directions. Calls that
qualify increase it. Stable calls decrease it. At 201, the stage changes and
the counter resets. The initializer sets it to 200. Thus the first transition
can occur on one qualifying call. It is not always a delay of 201 consecutive
samples. These tests use a scripted corrected signed shell input.
[Sensor calibration and correction](thermal-capture-followup.md) is separate
evidence.

## Verification and reproduction

Scripts:

- [AuditAllocationTransitions.java](../../scripts/ghidra/AuditAllocationTransitions.java)
  keeps the exact manager, callback, timer, thermal and scheduler entries, and
  an inventory of context-pointer literals and references. Read-only
  annotations repair merged function boundaries. They do not patch the
  firmware.
- [VerifyC2StartupGate.java](../../scripts/ghidra/VerifyC2StartupGate.java)
  runs the original dispatcher and C callback. It checks the state, config and
  timestamp before scripted reconciliation results 0/1, and across calls with
  kept context.
- [VerifyAllocationManager.java](../../scripts/ghidra/VerifyAllocationManager.java)
  runs the manager, the elapsed helper, the real budget getter and the cap
  callbacks. Selected stage projections include the original allocator and the
  Apple scenes. Other cases use scripted allocation rows to isolate the caller
  behavior.
- [VerifyThermalStageDirty.java](../../scripts/ghidra/VerifyThermalStageDirty.java)
  runs the thermal stage, counter, countdown and dirty instructions with a
  synthetic corrected input. This includes a heating/cooling cycle with kept
  state. The graphic interpolation runs, but there is no independent numeric
  reference to check it.

Use the reconstructed `AD1204_0073` project / `firmware.bin`, `-readOnly
-noanalysis`, the script path `scripts/ghidra` and new absolute output
directories. The instance-local fixed-Thumb workaround does not change original
firmware bytes or instruction p-code. The analysis used Ghidra on the original
bytes. [The evidence summary](allocation-transitions-0073.json) keeps the
result counts, digests and fixture limits.

Completed local results:

| Export | Checked cases | Original steps | Distinct instruction records |
|---|---:|---:|---:|
| C2 callback | 69 | 2,235 | 39 |
| Allocation manager | 288 | 94,603 | 467 |
| Thermal stage/dirty | 1,659 | 82,987 | 187 |
| Static focused audit | — | — | 572 |

In a separate check, all instruction records agree with the raw-image bytes.
The case counts and step sums agree with the metadata of successful runs. The
three verifiers have a total of 2,016 cases and 179,825 original steps.

The manager test includes six calls with kept RAM:

1. Startup.
2. A wait that is not complete.
3. Release and dispatch of a nonzero C2 cap.
4. Shutdown with zero budget.
5. Recovery with a lower budget.
6. Reallocation with the normal budget and desired caps that did not change.

In that manager sequence, the thermal stages are injected and the allocation
row is scripted. Seven independent stage projections run the original
allocator and the Apple variants.

The separate thermal cycle keeps the previous state. It observes stage events
at calls 1, 202, 403, 604, 805 and 1006: `0→1→2→3→2→1→0`. It clears dirty
between calls to model the consumption by the manager. The manager does not run
inside that cycle. The cycle is a fixture of qualifying calls. It is not a
recording of temperature or time.

The local result directories are `allocation-transitions-audit-20261016`,
`c2-startup-verification-20261016`, `allocation-manager-verification-20261016`
and `thermal-stage-dirty-verification-20261016` under `artifacts/firmware/`.
Their metadata SHA-256 values are, in the same sequence,
`9e3ff634c9d3cf750c9b175b26da51055695b3fdabd2be9e12b9991c9254a876`,
`387f2a3fb6145af1ad9f8d7919013d10e154d39aa961884bd4d0d1f97a7493cb`,
`2b4f0e5f87abc97d93c85278f565e2fb76176d753e6563136270add5971f3565`,
`609746958e0d1b78b29ead53dbcce1d56717fdfd78eeb48957c3ad1f7fb4017c`.

Open items:

- Integration of the scheduler, worker and bus without interruption.
- The real timer frequency.
- All indirect state writers.
- Real hardware ACK, retry and renegotiation.
- Sensor calibration.

These manager and thermal tests do not close the remaining lower-tier AI
combinations and timestamp-selection edges from the earlier document. There is
no new app control, firmware write or protection override.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
