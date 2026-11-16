# BEAST MODE: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). The main claims were checked again by decompilation of
0x40fe08 and 0x4065a8. Addresses are runtime addresses.

## Summary
- The page selector `0x41113c` uses byte `+0x39` of the main screen object at `0x2000d110`:
  0 → `0x410030`, 1 → `0x41044c` (BEAST MODE), 2/3 → `0x41083c` (portrait/landscape), 4 → `0x4105b4`
  (verified).
- No code in this build selects page 1. Each writer of the page byte writes 0, 2, 3 or 4. Thus
  BEAST MODE is unused UI in this build. Verified for each writer found. The list of writers is
  probably complete (inferred).
- A similar effect is reachable. On page 0 (total-watts screen), a total output of 71 W or more for
  3 updates starts the same 25-particle animation. It uses a different icon and has no "BEAST MODE"
  text. A total of 59 W or less for 3 updates stops it (verified, `0x40fe08`).
- Both effects only change the display. The power allocator does not read the screen object
  (verified for the traced readers, inferred for all code). There is no hidden power boost.

## Trigger
- Screen object: constructor `0x4111c4` (called at `0x40ac2a` with `r0=0x2000d110`), vtable `0x473a90`,
  draw slot `+0x18` = `0x41113c`.
- The only writer of `+0x39` on this object is the setter `0x40ff6c` (`strb` at `0x40ffbe`). The
  other `strb #0x39` sites are for other objects (`0x405006` config struct `0x2000c9b8`; `0x40bbc8`,
  `0x40bc28`, `0x40c14e`, `0x40de3e`; `0x410220` child widget).
- Setter callers: the screen init `0x410130` sends U[8]. The forwarder `0x41f798` sends U[9]. The UI
  task `0x4065c8` (`0x4067bc`, `0x4067ea`) calls the forwarder if U[8] ≠ U[9]. U is the UI-control
  struct at `0x2000c92c`. U[8] is the current page. U[9] is the requested page.
- Writers of U[9] (all literal refs to `0x2000c92c` and its offsets were scanned):
  - init `0x406404`: word `0x02000202` at U+6 → U[9] = 2.
  - button handler `0x4065a8` (screen id 2): event 1 cycles 0 → 2/3 → 4 → screen 9 (`0x406a30(9)`).
    Event 2 changes setting 6 through `0x41f870`. It writes only 2, 3 or 4.
  - screen-9 handler `0x40627c` event 1: page 0 if `*0x2000cebc != 0`, else 2/3.
  - `0x4062dc`, `0x406448`, `0x406940`, `0x406984`, `0x406a06`: 2 or 3, from the orientation bit
    `*(0x2000ec18+0x24)&1`.
  - setter `0x406550(p)`: the callers send 2 (`0x40946c`, all ports unplugged on page 0) or 2/3
    (`0x405ba0`, orientation flip).
- Button events: queue type 1 → `0x406474(1, code)` at `0x421852`. This function selects on the
  screen id `*(0x2000d110+0x38)` (getter `0x417ba4`). The short-press and long-press mapping is
  inferred.
- No button combination, MIOT property (2.5/2.7/2.14/2.21), af07 command or UART handler gets to U.
  Code that uses U is only in `0x405f00–0x406b74`, `0x40946c`, `0x40a2a4`, `0x4218xx`.

### Reachable high-power animation (`0x40fe08`, through `0x41f7b4` for each port, from `0x4065c8`)
- Per-port power `(mV/100)*(mA/100)` (0.1 W) goes into child `+0x3e` (`0x40c10c`). The sum of the
  five ports goes into `this+0x3e`.
- If `+0x43 == 0` and total/10 ≥ 0x47 (71 W): counter `+0x44` must get to 3, then `+0x43 = 1`.
- If `+0x43 == 1` and total/10 ≤ 0x3b (59 W): the counter must get to 3, then `+0x43 = 0`.
- Page 0 (`0x410030`) draws 25 particles (array `0x200393b8`, stride `0x54`), font char "d"
  (`0x47440e`, font `0x425184`) and "%d.%d W". The tick `0x410548` animates the particles on page 0
  if `+0x43` is set. On page 1 it always animates them. `0x417b00` gives a 100 ms refresh for
  screen 2 if the page is < 2.
- BEAST page `0x41044c`: the same particles, char "c" (`0x474607`), total widget `0x410ff0`, and
  "BEAST MODE" at `0x4104d0`. It has no condition of its own.

## Effect on power
- `0x40ff6c` writes only `+0x39` and the child visibility (`0x40fdf0`, `0x40fe08`). Then it redraws.
- `0x40fe08` writes only UI fields (`+0x3e/+0x43/+0x44`; children `+0x3a/+0x3c/+0x3e`).
- Only UI code reads `+0x43` (`0x40fd3c`, `0x40fd6c`, `0x41003c`, `0x41056e`). The callers of the
  `+0x39` getter `0x417b9c` are `0x405ba0` and `0x40946c` (UI).
- The allocator `0x4087b0` ("UsbIfaceCheckNeedLargePower … UiIFaceMngGetUsbAllPower", `0x47564e`)
  gets the total power from `0x405d38 → 0x405d54`, over the raw port table `0x2000ec18`. It does
  not use the UI object.

## Other pages and screens
- Page 2/3: an extra icon if `+0x42` is set (`0x405b6c` through `0x41f840`, from `0x2000d110+0x74`
  state 2/4).
- Page 4 (`0x4105b4`): two strings and `+0x3b/+0x3c` from U[0xc]/U[0xb] (`0x41f894`). It is
  possibly the temperature mode ("showTempMode %d"). Inferred.
- Screen ids are set through `0x406a30` (U[0]) and read at `0x2000d110+0x38`:
  - 2: main.
  - 3: port-plug animation (`0x406a74`).
  - 7: C3 insert animation (`0x406a58`, armed by `0x40a2a4` U[4]=1, "ANI C3").
  - 5, 8 (`0x405fc0`, `0x406018`), 9, 0xb, 0xd, 0xe: not identified.
- There is no other mode text near file offset `0xd4d0`. Strings not traced: "AI Temperature
  Control" (`0x72c1a`), "ADC Assistant", "Continue Test", "Replace C3 with C1" (`0x475a61`).

## Gaps
- The result "no writer of 1" depends on Ghidra coverage. It also assumes that code gets to U only
  through literals. A computed pointer to `0x2000c935` is possible.
- Other firmware versions can possibly enable page 1 (not checked).
- The physical button code mapping, the meaning of screen 9 and the flag `0x2000cebc` are not
  known. The U[0x1c] copy of the page is not read in `0x405e00–0x406c00`.
