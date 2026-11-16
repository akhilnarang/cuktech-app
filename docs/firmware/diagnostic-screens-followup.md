# Factory LCD tests and version display: 0073

Offline audit, 2026-10-14. Raw SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
These IDs are hexadecimal `0x80..0x87`. They are not decimal 80–87.

Two known entry paths select `0x80`:

- The HUSB362 polling function `0x40a718` tests status bit `0x0200` in its
  cached status word. If the current screen is 2 and more than four observations
  match, it writes the log `Show Factory Version`. Then it fills the version fields
  through `0x41f8f8` and calls `0x406a30(0x80)`. A controller status starts this
  path. It is not a button shortcut for an ordinary user.
- The callback `0x4164a8` calls ROM `0x1129c4(0x0f)`, checks for screen 2, fills the
  same version fields and selects `0x80`. In stage 12, the initializer `0x4093cc`
  gives the Thumb callback `0x4164a9` to ROM `0x11296c(0x0f, callback)`, with the
  literal at `0x409468`. The physical event is not known. The two ROM routines are
  not in the OTA.

`0x41f8f8` stores five 16-bit fields at `0x2000d106..0x2000d10e`.
In the repaired UI export, `0x40faec` sends high-bit screen IDs to
`0x40fe6c` with subpage `screen - 0x7f`. `0x40fe6c` creates or updates an
overlay widget and keeps the selected subpage. A change to a normal screen
removes the overlay. Thus all these screens use one shared factory/diagnostic
display. They are not eight separately proved charging modes.

The input handler `0x406354` responds only to event 1 (short release).
On `0x80..0x86` it goes to the next screen. On `0x87` it goes back to `0x81`.
It does not go to the main screen. The input dispatcher `0x406474` sends the
high-bit screen IDs to this handler. The exported function body of the handler starts
before the nominal entry. The kept original instruction listing covers
`0x40632a..0x406353`, so that this boundary problem stays visible.

## Stage 12: recovered all eight LCD-test states

The widget constructor `0x40cd8c` is called from `0x40abb0` with the object
`0x2000d0cc`. It sets the vtable to `0x473860`. The redraw slot at `0x473870`
points to the Thumb wrapper `0x40cd65`. The original instruction of this wrapper
tail-branches to `0x40cb84`. This renderer was not an exact function in the canonical
export. The code was recovered through the vtable, not only through existing function
names. Its TBB at `0x40cba4` uses eight bytes at `0x40cba8`.

| Screen | Subpage | Switch target | Content established in code |
|---|---:|---|---|
| `0x80` | 1 | `0x40cbb0` | Version / image CRC / address-derived identifier, via `0x40ca6c` |
| `0x81` | 2 | `0x40cbc2` | Eight colour bars via `0x40ccd4` |
| `0x82` | 3 | `0x40cbce` | Fill RGB `0xff0000` (red) |
| `0x83` | 4 | `0x40cbbc` | Fill RGB `0x00ff00` (green) |
| `0x84` | 5 | `0x40cbd8` | Fill RGB `0x0000ff` (blue) |
| `0x85` | 6 | `0x40cbf0` | Fill RGB `0xffffff` (white) |
| `0x86` | 7 | `0x40cbdc` | 32 grayscale strips via `0x40cc60` |
| `0x87` | 8 | `0x40cbd4` | Fill RGB `0x000000` (black) |

The exact palette of the bars at `0x40cd44` is black, blue, red, green, white,
cyan, yellow, magenta. The grayscale uses `(step*255)/31` for steps 0..31 and
the component scaling helper `0x40ad4c`. These are LCD pixel and colour checks.
The kept renderer paths draw the display. They do not change the charging policy.
The physical orientation, dimensions and appearance were not observed.

### The version page does not show three controller firmware versions

The renderer `0x40ca6c` prints three lines from five 16-bit fields:

- `0X%04x`: the local revision from `0x4058bc`, which returns `0x73`.
- `C 0X%04x`: the image CRC, from the MBR lookup of `0x405834` through ROM
  `0x10c3ae`. It is not a bootloader or SC2021 firmware version.
- `%04x%04x%04x`: three words filled from `0x2000c9d8..0x2000c9dd`.
  They come from the six-byte address helper `0x41b940`. MiBeacon also uses this
  helper for its address field. This document records no device-specific address.

`0x4047d4` has a copy quirk. The original instructions at
`0x404800..0x404820` load bytes 0/1 as a word, then byte 4, byte 5 and byte 3.
Byte 5 is used again in the middle word. For the address bytes
`a0..a5`, the printed words are `a5a4 a3a5 a1a0`. Byte a2 is missing and byte a5
occurs two times. Treat this display as an identifier derived from the address.
It is not a correct MAC string. This result comes from the instructions. No live display
was used to find out if the quirk is intentional.

For subpages >=9, the same renderer draws a number `subpage-9` on a contrasting
background. In the recovered `0x406a30` callsites of the canonical export, no constant
writer selects this range. Computed writes and other error displays were not part
of this search.

No firmware command or button press was sent to open these screens. No named
BLE entry is known. The physical trigger of the callback and the fault overlays
outside this family are still open. They are not related to the state byte of the
separate Beast renderer.

Evidence: stage-11 `coverage-gaps-followup-20261014`, stage-12
`protocol-factory-followup-20261014-verified`, the existing `ghidra-ui-followup`
and the unchanged raw image. The hash-guarded
[AuditProtocolAndFactory.java](../../scripts/ghidra/AuditProtocolAndFactory.java)
rebuilds five bounded entries and the measured TBB on a read-only project
copy. The original bytes do not change. The decompiler inlines several tails and
shows shared-register calls incorrectly. Thus the switch, the colours and the copy
quirk were checked against the original instructions. No claim is made about
execution on hardware or about the ROM implementation.
