# Display, buttons and extra features: AD1204U 2.1.2_0073

Offline analysis, 2026-10-14. Exact raw-image SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
All addresses below are runtime addresses. No charger command, factory write,
login or firmware installation was done during this audit.

## Summary of findings

- **ADC Assistant is reachable, and it changes the protocol configuration.** It
  tests C1 or C2 with different PD/PPS/UFCS settings. It compares the delivered
  power and lets the user confirm a result. It disconnects and reconnects charging
  during the test. It is not only a brand label or an animation.
- **Continue Test is the prompt to do the same test on C2** after C1 is complete.
- **Holiday Version is a persistent cosmetic option for the boot screen.** Its
  exact rendering and its stored selector are recovered. The vendor-command setter
  is present. No effect on charging power was found on this path.
- **Replace C3 with C1/C2 is a charging-advice animation.** The SC2021 polling path
  arms it when some conditions are true. It is not a new protocol, and it does not
  bypass a power limit.
- The physical button gives three event codes: short release, shorter hold and
  longer hold. The settings screens use them for navigation, toggles, test
  confirmation and a destructive reset action.
- Legacy MIOT 2.7 bit 0 is a stored setting with an unknown meaning. It is separate
  from the power-limit flag that comes from the AC input (see below).

These conclusions come from static code and data. Physical timing, UI appearance
and phone compatibility are not verified on a charger. See the
[Beast findings](findings-beast.md) for the separate Beast-text page, which is
probably not reachable, and for the reachable high-power particle animation.

## Evidence retained and its limits

The analysis used the Ghidra raw-binary loader on the original image.

Local-only outputs:

- `artifacts/firmware/display-followup-20261014/analysis.json`: measured target
  hash, 41 requested entries and 39 exact-address functions recovered.
- `functions.jsonl`: selected decompilation records, with explicit missing-entry
  records at `0x00406528` and `0x004220fc`. The script did not put a containing
  function in place of those entries.
- `instructions.jsonl`: original instruction bytes and listings for the button
  callbacks, queue routing, boot selector, AC flag and other seeds.
- `artifacts/firmware/display-followup-20261014.log`: successful script completion
  and explicit discard of changes to the read-only project copy.
- `artifacts/firmware/protocol-followup-0073/functions.jsonl`: earlier limited
  repairs of the auto-test and scene-allocation switches.
- `artifacts/firmware/display-gpio-followup-20261014/`: extended analysis of the
  button against the manufacturing entry. It has 45 requested entries / 43 exact
  functions and **356 instruction byte ranges**. All ranges match the original raw
  image byte for byte. Ghidra warns that the tail ROM targets `0x00105df0` /
  `0x001044f2` are absent. The raw instructions still give the caller arguments
  and the branches.

[AuditDisplayFeatures.java](../../scripts/ghidra/AuditDisplayFeatures.java) makes
the export. It runs after [RepairChargerUi.java](../../scripts/ghidra/RepairChargerUi.java),
on a separate project copy, with `-readOnly -noanalysis`. The original firmware and
the original project do not change. Capstone also checked the new instruction bytes
against the raw image.

A separate verification matched all **258 exported instruction byte ranges** byte
for byte against the original raw image. It also checked the SHA-256 and all JSONL
record counts. Some old Ghidra function bodies merge tail-branch targets and
shared-register helpers. Thus do not use the pseudocode alone to find a calling
convention or the complete reachability of a feature.

## Physical button event map

Button interrupt/event handler `0x00417da4` calls ROM `0x00104512(0x10)` and tests
the resulting bit-4 level. On the low-level branch, it starts two ROM timers through
`0x0010a522`. On the other branch, it cancels both timers through `0x0010a54c`. It
sends a short-release event only if no hold callback has already marked the press
as consumed.

| UI event | Producer | Condition established in this image |
|---|---|---|
| 1 | `0x00417dfe` → `0x004042d8(1)` | Release with the consumed flag still zero |
| 2 | `0x00413774` → `0x004042d8(2)` | Shorter-hold timer callback; timer argument `1500` |
| 3 | `0x00413738` → `0x004042d8(3)` | Longer-hold timer callback; timer argument `5000` |

The two callback pointers are the literals `0x00413775` / `0x00413739` at
`0x00417e0c` / `0x00417e10` (Thumb bit set). Both callbacks set the consumed flag
at `0x2000c884` before they post their event.

The UI labels call the event-2 operations a **2-second press**. The original ROM
timer argument is `1500`, not `2000`. The timer-unit conversion and the hold
duration that a user feels were not measured. Event 3 uses `5000`. This often
suggests 5 seconds, but it was not timed here.

`0x004042d8` posts queue type 1 with the event byte. Task code at `0x00421852`
reads that byte and calls `0x00406474(1,event)`. That dispatcher selects a handler
from the current screen ID. This traces the physical input producer to the UI
handlers. The short/hold identification does not come only from English strings.

GPIO mask `0x10` is a logical bitmask in the ROM APIs. It does not identify a
package pin, a board pad or a safe electrical connection.

### Button and manufacturing entry: the same mask does not mean the same input

The normal button path and the manufacturing startup check both use mask `0x10`.
But their pin-configuration indices and their ROM GPIO functions are different:

| Path | Pin-mux call | Read API | Other observed APIs |
|---|---|---|---|
| Normal button init `0x00415e10` | `0x0010481c(0x24,0x1c)` (index 36) | `0x00104512(0x10)` | `0x001044fe`, `0x0010444a`, IRQ callback registration `0x001044ec` |
| Manufacturing init `0x0041d03c` | `0x0010481c(4,0x1c)` (index 4) | `0x0010450a(0x10)` | `0x001054d2`, `0x001044f2` |

The exact IRQ chain of the normal button is:

1. Init `0x00415e34` registers Thumb pointer `0x00417c25`.
2. Handler `0x00417c24` tests interrupt bit 4.
3. A one-unit deferred timer runs callback `0x00417da5`.
4. The hold/release handler `0x00417da4` (described above) runs.

The literal callback pointers are at `0x00415e4c` and `0x00417c6c`.

Startup calls the manufacturing routine first and the normal key init later
(`0x002013bc` calls `0x0041cf88` before `0x00415e10`). Its gate reads
`0x0010450a(0x10)` at `0x0041cfca`. It enters `mp mode` only when that read
returns zero.

**Inference:** the normal button uses an extended (high) GPIO bank, logical index
36 (`32+4`). The manufacturing input uses logical index 4 in the lower bank. The
same relative bitmask does not show that a held user button at power-up enters
manufacturing mode. The different mux indices and the paired ROM APIs agree with
two separate logical inputs.

The GPIO ROM definitions, the package mapping and the board wiring are not
available. Thus shared physical wiring is not shown, but it is also not fully
excluded. No startup-button test, strap manipulation or connection to an exposed
board was done or suggested.

The older UART report uses the word "strap" for the startup-level condition. This
does not prove that an accessible board pad exists. Do not replace it with a
confirmed "hold the button while plugging in" procedure.

## Screen IDs and rendering

Byte `+0x38` of the main screen selects the **screen ID**. Its byte `+0x39` selects
a **page inside the main screen**. This is a different namespace. Selection function
`0x0040faec` has measured enter/leave switch tables. The constructors and the draw
vtables at `0x0040abb0` identify the displayed object for each screen.

| Screen ID | Recovered purpose | Rendering / event evidence |
|---|---|---|
| 2 | Main charger pages | Main-page dispatch `0x0041113c`; input `0x004065a8` |
| 5 | Bluetooth setting and connection-status prompts | Object `0x2000cd8c+0x3c`, draw `0x0040e1dc`; input `0x004060c8` |
| 8 | Keep Screen On and USB-A On for 4 Hours | Object `0x2000cc9c+0x3c`, draw `0x004113a4` → `0x004112e0` / `0x00411208`; input `0x00405f0c` |
| 9 | More Settings entry/overview | Object `0x2000cd8c`, draw `0x0040cda4`, state 1; input `0x0040627c` |
| 10 (`0x0a`) | Return-to-main menu entry | Same object/draw, state 2; input `0x004062dc` |
| 11 (`0x0b`) | ADC Assistant: start or insert-C1/C2 prompt | Object `0x2000cb34`, draw `0x0040dc40` → `0x0040da74` / `0x0040d8c0`; input `0x00406044` |
| 12 (`0x0c`) | Identifying Device on C1/C2, reconnection warning | Object `0x2000cb34+0x3c`, draw `0x0040ef9c`; selected by `0x00406044` |
| 13 (`0x0d`) | ADC result, Confirm/Cancel protocol settings | Object `0x2000cbac+0x3c`, draw `0x0040d2e0`; input `0x004061fc` |
| 14 (`0x0e`) | Continue Test on C2 / Exit | Object `0x2000cc24+0x3c`, draw `0x0040c838`; input `0x00406adc` |

The generic widget draw wrapper at vtable offset `+0x18` draws the children. Its
own content renderer is at `+0x10`. Do not treat every `+0x18` entry as the
renderer of the feature. That gives wrong screen identifications.

The English localization IDs come from `0x0040b0b0` and the initialized pointer
table at `0x2000c3c8`. Examples:

- `0x18` ADC Assistant.
- `0x1c` Press 2S to Start.
- `0x1f/0x21` identifying C1/C2.
- `0x23` reconnection warning.
- `0x27/0x28` Confirm/Cancel.
- `0x2b/0x2c` Continue/Exit.
- `0x2d/0x2e` Continue Test C2.

These labels are linked to real renderer calls. They do not come only from string
searches.

## User navigation and settings

The static route from a normal main display is:

1. A short release moves through the main pages to the temperature/control page,
   and then to **More Settings** (screen 9). On the main screen, a longer press
   changes a display-orientation setting with four values. The lock byte can block
   this change.
2. On More Settings, the shorter-hold event opens the Bluetooth page (screen 5).
3. A short release moves through Bluetooth → Keep Screen On → USB-A four-hour
   hold → ADC Assistant → Return to Main → Bluetooth.
4. The shorter-hold event toggles or starts the selected item. On Return to Main,
   it goes back to the ordinary display.

Evidence: `0x0040627c`, `0x004060c8`, `0x00405f0c`, `0x00406044`, `0x004062dc`.
On hardware, the first event can possibly only wake a sleeping screen. The exact
number of clicks is not verified on hardware.

Keep Screen On toggles timeout setting 4 between the values 4 and 1 through
`0x00404fe8`. The corrected mapping is Always on and 5 minutes. Value 4 disables
the timeout timer. The separate idle-screen-off setting still applies. See the
[raw enum confirmation](status-and-settings-followup.md). USB-A uses `0x004145c8`.
Its timer starts at `0x383f` (14399), which agrees with the four-hour UI label.

WARNING: On screen 5, event 3 (the longer hold) resets the configuration and the
binding. It erases configuration records 1 and 3, sets the settings again, calls
the binding-related teardown and then calls ROM reset `0x00105df8` (`0x004060c8`).
Do not try a longer hold on this screen. No such action was done.

## ADC Assistant behavior

On screen 11, the shorter-hold action selects C1 if C1 is active. If not, it
selects C2. If neither port is active, it refreshes the insert-device prompt and
does not start. `0x00409b10(port)` starts the test. It disables C3/A and the other
C port, enables the selected port and enters state 2 of `0x00409784`.

The measured state switch and the shared-register helper instructions show:

| Auto-test state | Work |
|---|---|
| 2 | Clear PD/PPS/UFCS disable bits and request all enabled; wait `30000` timer units |
| 3 | Save all-enabled power/protocol result; choose which further trials are relevant |
| 4 | Disable UFCS, keep other tested protocols enabled; wait `30000` units |
| 5 | Save UFCS-off result; compare with best and proceed to finish |
| 6 | Disable PPS, keep other tested protocols enabled; wait `30000` units |
| 7 | Save PPS-off result; compare with best, then proceed to UFCS-off trial |
| 8 | Select result; re-enable output ports; display result if screen 12 is current |
| 9 | Failure cleanup; restore saved protocol settings; return to Assistant prompt |

Some detected protocol and power conditions skip trials. Thus not every phone gets
all three trials. If the selected port is lost for more than `1999` timer units,
the test fails. The rendered page warns about automatic reconnections. The trial
comparison uses the tracked reported power. If two results are equal, it compares
the observed power. These numbers come from this firmware. They do not guarantee
the maximum possible charging speed of a phone.

Completion helper `0x00409680` enables all four output ports. It does not restore
a saved snapshot of the port-enable state from before the test. The failure branch
calls `0x00404b20` with the saved last-result-port byte. It is not proven that every
failure during a first or new test restores every original setting.

CAUTION: Record the original port and protocol masks before you test on hardware.
No device test was started to examine these cleanup cases.

`0x004061c6` changes screen 12 to 13 and sets up the result controls. On screen 13:

- A shorter hold toggles Confirm/Cancel.
- A short release applies the selected choice through `0x00409ba4`.
- Confirm calls `0x00404b80`. This updates the PD/PPS/UFCS enable bits of the
  selected port and calls the configuration-save path `0x00404c08` →
  `0x00404380(4)`.
- Cancel restores the saved settings through `0x00404b20`.
- A time-out exit from this result screen also calls the cancel path (`0x004069cc`).

Persistence across a restart is not tested on hardware.

After a C1 result, if C2 is active, screen 14 opens. A short release with Continue
selected starts C2 through `0x00409b10(1)`. Exit goes back to the Assistant prompt.
The result page states that its rating is valid for single-port output.

This feature changes the outputs and can save protocol preferences. Do not offer it
as a background read-only diagnostic or as an unverified Bluetooth command. No MIOT
action that starts the Assistant was found.

## Replace C3 with C1/C2 advice

`0x0040a2a4` polls SC2021. After a settling interval of `3000` units, it arms UI
flag `U[4]` (`U=0x2000c92c`) in these cases:

- C3 and A are both active.
- C3 alone meets its controller-protocol and voltage conditions.

For the C3-only case, controller protocol codes 13/15 or a voltage below 5501 skip
the animation. Do not give protocol names to these SC2021 codes without separate
evidence.

UI updater `0x004065c8` reads that flag and calls `0x00406a58`, which selects
screen 7. The constructor of that screen selects object `0x2000cabc`. Renderer
`0x0040ea4c` calls localization IDs 9/10, which are the C3→C1/C2 advice strings.
This is a real advice path for the user. It does not enable a new charging mode.

## Holiday Version selector

Boot-screen renderer `0x0040bcb8` reads object `+0x38`:

- When the value is zero, it draws the ordinary CUKTECH logo branch.
- When the value is one, it draws extra assets. These include the glyph `h`
  (`0x68`, literal at `0x0040be20`) from descriptor `0x0042510c` (`0x0040be1c`).
  The extracted `font-0002210c-glyph-00000068.png` shows **Holiday Version**.

Startup `0x004048d4` loads NV record 4, length 10, into `0x2000eb72`. Byte 4
(`0x2000eb76`) is loaded at `0x0040490a`. The tail-call at `0x00404910` passes it
to `0x0041f888`, which sets boot object `0x2000d1e0+0x38`. The default initializer
sets bytes 4..7 to zero, so the ordinary logo is the default. Getter `0x004047cc`
returns this selector. Setter `0x00405050` stores it and saves record 4. The only
recovered caller of the setter, `0x0041caac`, accepts the values 0/1 and returns
the current selector in a vendor reply.

The setter does not update the existing boot widget immediately. The copy from
storage to the UI occurs at startup. Thus the boot graphic probably changes after
the next reboot (inference; no restart was observed). No normal physical-button
path or MIOT setter for this flag was found. See the vendor command audit for the
exact transport and for its side effect: it stops the telemetry updates. No vendor
write or reboot was sent to test this option.

The exact selector-9 transport was checked separately from the original Thumb code:

```text
AF07 request: fe dc ba 01 f1 00 01 09 VV
AF08 reply:   fe dc ba 01 f1 09 01 HH ef
```

- `VV=00/01` saves the flag.
- `VV=ff` takes the same reply path but skips the writer
  (`CMP r4,#1; BHI 0x0041cac4`). Thus it is a read-only selector query.
- `HH` is the current stored value, at absolute frame offset 7.

The handler at `0x0041fe90` reads the request value at offset 8 and calls
`0x0041caac`. Literal `0x0041cae0` contains reply header `01 f1 09 01`. Helper
`0x00405120` sends exactly 5 payload bytes, so the complete frame has 9 bytes. This
read/write difference applies only to this selector. Do not apply it to other
factory commands. The AF07 common entry still pauses the ordinary MIOT cache updates
until disconnect, also for the read-only query.

## Legacy 2.7 bit 0 and power-limit flags

MIOT 2.7 setter `0x00404d2c` maps input bit 0 to bit 7 of configuration byte
`0x2000c9ea` (base `0x2000c9b8 + 0x32`). Updater `0x004043ac` maps it back into the
read cache, and the settings-save path keeps it. The inspected literal-pointer and
decompiler references show no charging or UI consumer of that bit. Bits 1 and 2
use different, mapped miPPS/UFCS control paths. This search does not prove that
bit 0 is unused everywhere. Computed aliases, ROM consumers and functions that were
not found are gaps.

The allocator flag at `0x2000ceb2` is **not this bit**. Startup routine
`0x00414bc4` tail-branches to `0x004220fc`. That code measures ADC channel 4
through `0x00411bec(4,1,0,100)` and logs `vac_vol`. Instruction `0x00422126` stores
in `0x2000ceb2` whether that ADC result is greater than `0x514` (1300). This is a
selector that comes from the AC input. It is not a Beast mode that can be selected
remotely. NV record 2 can restore the selector under the ROM condition `0x00105e8c`
(`0x004049fc`), which is not known. `0x00404b64` saves it. The ADC threshold is not
1300 V, and it is not a calibrated line-voltage threshold.

## What remains

| Question | State / next evidence |
|---|---|
| Physical short/hold menu behavior | Code route recovered; measure actual duration, wake interception and screen sequence on charger |
| ADC optimum and saved settings | Code recovered; log original 2.21, measured phone/meter output and readback after confirm/cancel/restart |
| ADC enum meanings and timings | Branches measured; controller enum names and ROM timer units still incomplete |
| Holiday vendor command and reboot effect | Setter/storage/render recovered; transport framing in vendor audit; live effect untested |
| Legacy 2.7 bit 0 | Stored/read back; meaningful consumer still unresolved |
| AC-selector calibration and ROM override | ADC branch recovered; physical threshold and ROM `0x00105e8c` unavailable |
| All screen IDs, icon meanings and error pages | Main useful menus mapped; diagnostic IDs `0x80..0x87` and every protection overlay remain incomplete |
| Other firmware versions | Only measured 0073 analyzed; no version bisection with a second image |
| Complete feature reachability | Literal references and selected indirect dispatch mapped; this is not proof against every computed pointer/ROM path |

The full decompilation, the extracted assets and the recovered menus are not a
complete reverse-engineered source tree. The controller firmware, the ROM and the
live behaviour are separate evidence boundaries.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository. The hashes are recorded for reproducibility.
