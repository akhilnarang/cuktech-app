# UART factory/diagnostic mode: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). The GPIO4 strap check was verified again by decompilation of
0x41cf88. Addresses are runtime addresses. The RAM boot code is copied from load-2
(0x477890 → 0x2013b0).

The ROM routine names are inferred from how the code calls them: 0x10481c pinmux(pin, func);
0x1054d2 pin_mode(mask, mode); 0x1044f2 gpio_dir; 0x10450a gpio_read(mask);
0x108996 uart_open(base, baud, flow, rx_cb); 0x108bf2 uart_send; 0x10a522 co_timer_set;
0x10b826/0x10b84a nvds_get/put(tag, len, buf);
0x107572/0x107212 sf_read/sf_write(0x51000000, cs, addr, buf, len); 0x106f14 sf_erase.

## Summary
- The 0x4f ('O') protocol runs only in "mp mode" (mass-production test). The charger enters mp
  mode if GPIO4 is low at reset. The first step in the reset continuation is `bl 0x41cf88` at
  0x2013be. 0x41d03c sets GPIO4 as an input with pull-up. If `gpio_read(0x10) == 0`, it opens the
  test UARTs, prints "mp mode" and loops forever (0x41d010). The normal app (MIOT, BLE app, af07)
  does not start (verified 0x41cfc8–0x41d014).
- In normal mode, UART input goes to a one-byte handler on UART0. 0xA5 returns the 6-byte BD
  address. 0xAA remaps the pins.
- No BLE path gets to the 0x4f parser or its handlers. This is true for af07, FE95 and MIOT, with
  or without login (verified, closed call graph below).
- The mp-mode commands have no checksum, no authentication and no bounds checks:
  - flash erase (0x35) and write (0x36) at any address,
  - NVDS BD-address write (0x3b),
  - xtal-trim write (0x3a).
  - Receive also has two unbounded RAM overruns.

## Peripheral & pins
| Mode | UART | Base | TX | RX | Baud | Where |
|---|---|---|---|---|---|---|
| normal | UART0 | 0x40030000 | GPIO5 (func 0xc) | GPIO6 (0xb) | 115200 | 0x201436–0x20146e, rx_cb 0x201551 |
| normal after 0xAA | UART0 | 0x40030000 | GPIO2 | GPIO3 | 115200 | 0x201570–0x20157c |
| normal after 0xAA | UART1 | 0x40040000 | GPIO5 (0x10) | GPIO6 (0xf) | 115200 | 0x20157e–0x20159a, rx_cb 0x2015c5 |
| mp | UART0 (debug log) | 0x40030000 | GPIO4 (0xc) | GPIO7 (0xb) | 115200 | 0x41d104–0x41d12e, no rx_cb |
| mp | UART1 (0x4f protocol) | 0x40040000 | GPIO5 (0x10) | GPIO6 (0xf) | 115200 | 0x41d132–0x41d15a, rx_cb 0x41d279 |

- 115200 = literal 0x1c200, flow control 0 (verified). 8N1 is inferred (ROM default). TX pins get
  pin_mode 1 (push-pull). RX pins get pin_mode 2 (pull-up). Inferred: func codes 0xb/0xc and
  0xf/0x10 are RX/TX.
- printf (0x4239b8) / puts (0x424dcc) → putchar 0x41f7f0 → UART0 (LF → CR LF). The log is on GPIO5
  in normal mode and on GPIO4 in mp mode. At boot, the firmware prints a REBOOT banner and
  "boot reason %d".
- A normal boot also sets GPIO2 to push-pull and GPIO3 to pull-up (0x201454–0x20145e). This is
  probably for the 0xAA remap.

## Enable conditions
- mp mode: the only condition is GPIO4 low when 0x41cf88 reads it at each boot (verified). There
  is no flash flag, NVDS record, timeout or button combination. No other direct pinmux/gpio_read
  of GPIO4 was found (indirect `blx` calls were not fully checked). Thus GPIO4 is probably a
  dedicated strap or test pad (inferred).
- After sleep, the restore callback 0x422312 opens the mp UART again (through 0x41d104). Only
  cmd 0x1d registers this callback.
- The normal UART0 is always opened at boot (rx_cb 0x201550). After sleep, 0x2014f8 case 1 opens
  it again without rx_cb.

## Protocol & commands (mp mode, UART1)
- The byte handler 0x41d278 stores bytes into `0x2000ce28[idx++]` with no upper bound. It starts
  a 5-tick idle timer again → 0x41d1d8 (hex dump, checks `buf[0] == 'O'`) → 0x41d1a0. 0x41d1a0
  copies the data to 0x20031c0c and does not check the length (> 32 B overruns into the TX
  buffer 0x20031c2c).
- Request: `4f <group> <cmd> xx xx <payload…>` (bytes 3–4 are not used, no checksum). Response:
  `4f 03 <cmd> <len u16 le> <data>` on UART1 through 0x41d170.

**Group 1 (handler 0x41cd54)**

| Cmd | Behaviour | Address |
|---|---|---|
| 0x17 | payload +5 = 1 and u16 channel at +6: start RF calibration/carrier timer 0x41cbf8; else stop | 0x41cdaa; stop 0x41cb8c |
| 0x18 | payload +5 = 1: clear running flag | 0x41ce3a |
| 0x1b | RF receive test (toggle via +5 = 1, 0x41d05c): radio IRQ 0x4042fc counts packets starting 0x4f; timer 0x416528 reports count as cmd 0x1c (`rx_sens_per`, capped 100) | 0x41ce26, 0x416528–0x416576 |
| 0x1d | sleep-current test: GPIO4–7 to GPIO (func 0x1c), sleep, restore cb 0x422312 | 0x41ce48–0x41ced0 |
| 0x35 | if +13 == 2: `sf_erase(0x51000000, 0, addr u32@+5, len u32@+9)` (erase INFERRED); no bounds check | 0x41cd74–0x41cd90 |
| 0x36 | `sf_write(0x51000000, 0, addr u32@+5, frame+13, len u32@+9)`; no bounds check (VERIFIED) | 0x41ce0c–0x41ce20 |
| 0x37, 0x38, 0x19, 0x1a, 0x1c | no-op | tables 0x41cd6c / 0x41cda2 |
| 0x39 | step xtal trim (state 0x2000c63c+8) ±1, clamp 0..0x1f, apply, not saved | 0x41cdc2, 0x41cb48 |
| 0x3a | `nvds_put(tag 4, 1, trim)`, apply, reply trim | 0x41cdd8, 0x41ccb4 |
| 0x3b | `nvds_put(tag 1, 6, frame+5)` (BD address, INFERRED), read back, reply 6 B | 0x41cdf2, 0x41cf6c, 0x41cf34 |

**Group 2 (handler 0x41ccdc, read-only)**
- 0x3a: xtal trim (0x41cc84). 0x3b: BD address from NVDS tag 1, fallback RAM 0x2000c4ac (0x41cf34).
- 0x36 flash read: `sf_read(0x51000000, 0, addr u32@+5, 0x20031c2c, len u32@+9)`. The reply length
  is the low 16 bits of len. The read goes into the TX buffer. Then 0x41d170 shifts the buffer onto
  itself by 5, so the data is probably garbled (inferred). A large len overruns RAM.
- Other group-2 commands: no reply. Groups other than 1 and 2 are ignored (0x41d1ae–0x41d1b8).
- Flash write and erase have no bounds. Through SF0 (internal flash) they get to the
  bootloader/MBR, the app, NVDS and the bind records.

**Normal-mode UART0 (rx_cb 0x201550)**
- 0xA5: reads the BD address (NVDS tag 1) and sends it on UART1 (literal 0x2015ac). But UART1 is
  open only after 0xAA (quirk, verified).
- 0xAA: UART0 → GPIO2/3. It opens UART1 on GPIO5/6 at 115200 (rx_cb 0x2015c4 answers only 0xA5).
- Other bytes are logged as `[UART]NTC:%02x`.

## Reachability
- From BLE: not reachable (verified). The call graph is:
  1. Parser 0x41d1a0 ← only 0x41d214 in 0x41d1d8.
  2. 0x41d1d8 ← only the timer callback pointer 0x41d2a8, used by 0x41d278.
  3. 0x41d278 ← registered only by UART init 0x41d104.
  4. 0x41d104 ← only mp mode (0x41cfd2) and the restore callback 0x422312 (registered only in
     cmd 0x1d).

  Only the parser and the handlers themselves call the handlers 0x41cd54, 0x41ccdc, 0x41cf34,
  0x41ccb4, 0x41cc84, 0x41cb48 and 0x41cb8c. Method: raw Thumb BL/B.W scans over flash and the
  three RAM copies, and pointer scans over flash and the expanded .data. The af07 handler
  0x41fdc4 (two levels of callees) calls none of them. In mp mode, the BLE app and MIOT do not
  start.
- Other users of the same ROM primitives (separate paths): sf_write at 0x41c2a6 (DFU area);
  nvds_put at 0x416868 / 0x4168ba.
- This UART is not a sub-MCU link:
  - mp mode only replies to requests (and sends the cmd 0x1c report). It does not poll.
  - The normal UART1 opens only after 0xAA.
  - The sub-chip version and MCU-info paths (af07 `f1 01`, 0x419dec) do not use UART1.
  - The PD chips are on bit-banged I2C. See `findings-phone.md`.
- Physical: GPIO4 low at power-up, and GPIO5 (TX) / GPIO6 (RX), 3.3 V TTL, 115200. The normal-mode
  log is always on GPIO5.

## Risks
- Physical access (GPIO4 strap and GPIO5/6) gives unauthenticated, unbounded flash erase and write.
  It also gives BD-address and xtal-trim rewrites. This is sufficient to brick the charger or
  change it permanently without SWD.
- There are two unbounded RAM overruns in mp-mode receive (0x41d278, 0x41d1aa).
- The normal-mode UART0 RX (GPIO6) is always active. It gives the BD address (0xA5) and remaps
  pins (0xAA). GPIO5 TX gives the debug log.

## Gaps and speculation
- Speculation: GPIO2/3 are possibly the OM6621P SWD pins (no pinout is available; the OM6621E
  uses GPIO0/1). If this is true, 0xAA takes control of them.
- Speculation: GPIO4–7 are bare factory pads under the potting. Access to them probably needs
  depotting. This is the same work as for SWD.
- Not done: the ROM names are not verified against an SDK. 8N1 and the timer tick are not
  confirmed. The IRQ behind 0x4042fc is not known. The indirect `blx` uses of GPIO4 are not
  fully scanned.
