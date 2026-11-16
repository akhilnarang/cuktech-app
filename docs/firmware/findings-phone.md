# Device identification and power policy: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). Addresses are runtime addresses (file offset + 0x403000).

**2026-10-16 correction:** the [allocation-policy follow-up](allocation-policy.md)
replaces the first class/voltage/scene interpretations below. That document:

- Separates the protocol enum, the reduction class and the persistent load class.
- Verifies the normal fixed scene rows and selected AI/lower-tier branches.
- Documents the final clamp that depends on AC.

The old scratch paths are not the source of the new evidence.

## Summary
- The BLE MCU does not negotiate PD/PPS/UFCS/miPPS/SCP. Two "HUSB362" chips control C1/C2. One
  SC2021 controls C3/A. The MCU reads a summary over I2C (protocol, partner VID, cable, V/I). It
  writes back a per-port power cap and protocol-disable bits.
- The brand classifier at 0x406364 (VERIFIED) maps the partner USB VID from the C1/C2 protocol
  record: 1 Xiaomi, 2 Apple, 3 Samsung, 4 OPPO, 5 vivo, 6 Huawei, 7 Honor.
- The traced users of the brand include the "<brand> Charging" / "NA Cable" popup and one AI load-class
  rule. That rule uses the Apple VID plus reduction class 8. It does not use native protocol 8/PPS.
- AI uses power hints, the destination voltage and persistent load classes. Normal Apple, Single
  (logged "Extreme") and Balance use fixed rows. The occupied-port hints and the port count select
  the row. Lower-tier Balance also has reduction-class/power branches. Normal "Apple" allocation
  does not read the VID.
- MIOT does not expose the VID. 2.17/2.18 contain only protocol bytes. Thus the app cannot show
  "detected: iPhone".
- Byte 1 of `PortTelemetry` in the app, labeled "protocol", is the power-cap code. For example,
  0x0b is a 120 W cap. It is not PPS.

## Architecture (VERIFIED unless marked)
### C1/C2 "HUSB362" (`[HUSB362]` log 0x40a920; Hynetek vendor INFERRED)
- Bit-banged I2C: read 0x405194, write 0x403f7c. Bit loops 0x4041b4/0x40414c use ROM GPIO
  0x10452a / 0x10450a, mask 0x1000000 (GPIO24 = SDA, INFERRED).
- 8-bit slave addresses are 0x92 (C1) and 0x94 (C2), from table 0x2000c2b4 (decompressed .data).
  Each frame has an additive checksum ("CheckSum Error").
- Commands:
  - 0x81 PowerMode 4 B (read 0x414d04, write 0x414f90).
  - 0x82 Info 16 B (0x414c80: V, I, status).
  - 0x83 Protocol 5 B + checksum (0x414dac).
  - 0x85 app version write (0x414f44). Version read is 0x414e9c.
- The poll loop 0x40a718 copies Info to 0x2000cf28 + 0x58 + port×0x12.
- 0x83 record (6 B): [0] protocol, [1] ?, [2..3] partner VID, [4] cable amps, [5] ?. The cache is
  at 0x2000c998 + port×6 (written by 0x405e5c). A change sets bit 0x20<<port in 0x2000c8bc. The
  meanings of [1], [4], [5] are INFERRED.
- The PowerMode write 0x40a5f4 uses cfg 0x2000cf28 + port×5: +0x12 cap code, +0x13 protocol-disable
  bits ("Disabled:Mipps/UFCS/PPS/PD"), +0x15 UFCS control.

### C3/A SC2021 (I2C)
- Base info 0x4152dc: `0x404008(0x42, reg 0x10, buf, 0x11)`. It reads 17 B with CRC (0x4146bc):
  C3/A on bits, C3/A V/I big-endian, C3/A protocol bytes (< 0x10; C3 is forced to 0xE on "PD
  Load") and protect flags.
- It writes regs 0x0c, 0x0d, 0x0e, 0x20, 0x21. The UFCS/SCP setter is 0x4158e8. There is no
  VID/identity read.

### Not in this image
PD state machines, PDO/VDM and Discover Identity are in the HUSB362/SC2021 firmware.

## Identification signals

The stage-13 [OPPO/vivo/VOOC follow-up](oppo-vivo-vooc-audit.md) emulates the original classifier
separately. OPPO/vivo IDs keep their brand class for all 256 protocol bytes on C1 and C2. Brand
recognition does not show a VOOC or FlashCharge protocol. That document also describes the chip
capability and the target configuration.

### Partner VID (0x83 record [2..3]) → classifier 0x406364 (VERIFIED), names at 0x40d850
| VIDs | Class |
|---|---|
| 0x2717 | 1 xiaomi |
| 0x05AC | 2 Apple |
| 0x0419, 0x0434, 0x0492, 0x04E8, 0x055D, 0x057A, 0x0839 | 3 Samsung |
| 0x22D9 | 4 OPPO |
| 0x183D | 5 vivo |
| 0x12D1 | 6 HUAWEI |
| 0x339B | 7 HONOR |
| no match and protocol [0] == 9 | 1 xiaomi (9 = miPPS, INFERRED) |
| else | 0 |

There are no comparisons for Google 0x18D1, OnePlus 0x2A70 or vivo 0x2D95. The scan covered all
instruction immediates and the decompressed .data.

### Other signals
- Native protocol bytes: 0x2000c998[port×6 + 0/1]. The byte at 0x2000cf28 + 0x32 + port×4 is a
  reduction class. It is next to the u16 hint at +0x30. See the [settling mapping](protocol-settling-and-control.md).
- Destination voltage is at 0x2000cf28 + 0x62 + port×0x12, with thresholds 9200 and 19000. This is
  HUSB word 10. It is not the measured voltage. See [controller fields](controller-field-consumers.md).
- Cable: 0x40d700 prints record [4] as "%dA Cable" (e-marker source INFERRED).
- The MCU code has no BC1.2 or Apple-divider detection. Port A has only the SC2021 protocol byte.
- Load class 0x406b78 is stored at 0x2000cea8 + 0x70 + port. It is a policy state that depends on
  history. The eligibility check uses the reduction class, the hint, the destination voltage and a
  very low rolling/current measured power. The companion 0x406db4 and the AI scenes also write it.
  See the [verified rules](allocation-policy.md). It does not identify a phone or a laptop. In stable
  AI, a full refresh occurs after elapsed >=60000 timer units.
- Protocol auto-test 0x409784 ("Identifying Device on Port C1/C2…") measures the delivered power
  three times (all on, UFCS off, PPS off) and keeps the best result. 0x409ba4 saves the PD/PPS/UFCS
  enables through 0x404b80 (storage into 2.21 bits INFERRED). This is an empirical test, not an
  identification.

## Classification → power policy
- Power manager 0x4084c8, state 0x2000cea8: +0xb active port count, +0x1b scene (`0x404784(3)`).
- Total budget 0x4092c0, tables 0x473e68/70: 1200/1200/900 (0.1 W) → 120 W, derated 90 W.
- Allocator 0x406e30: row 0 at 0x2000c2b6 holds the per-port max caps `0b 0b 80 70`
  (120/120/45/33 W). If there is no contention, it uses the max caps ("RAW"). If there is
  contention, it uses the scene function for the tier: normal (> 90 W), LIMIT or Ac-Low LIMIT.
- Final clamp when the AC selector 0x2000cea8+0x0a is zero: 7→6, 9/10→8, 11→10. Also 4→3 and 6→5
  when the hardware-global flag 0x2000eb7d is zero. The clamp runs one time.
- C1/C2 cap codes (0x4093a2):

| Code | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 0xa | 0xb |
|---|---|---|---|---|---|---|---|---|---|---|---|
| W | 22.5 | 33 | 45 | 55 | 60 | 65 | 70 | 80 | 90 | 100 | 120 |

- SC2021 cap codes:

| Code | 0x10 | 0x20 | 0x30 | 0x40 | 0x50 | 0x60 | 0x70 | 0x80 | 0x90 |
|---|---|---|---|---|---|---|---|---|---|
| W | 7.5 | 10 | 12 | 15 | 18 | 22.5 | 33 | 45 | 24 |

- The "USER DEFINED" log (0x474e20) is only for port on/off. 0x409608 (PORTCTL; MIOT 2.16 or af07
  `01 07`) changes to mode 1 when the enable mask ≠ 0xF. Disabled ports get cap 0. There is no
  per-port watt setting.

## Scene modes (2.5 → 0x2000cea8+0x1b; dispatch 0x406e30)
| 2.5 | Log | normal / LIMIT / Ac-Low | Inputs |
|---|---|---|---|
| 1 AI | AI | 0x407104 / 0x407750 / 0x407508 | count, power hints, reduction/native enums, destination voltage, load class |
| 2 Apple | Apple | 0x4079d0 / 0x407bf4 / 0x407af8 | occupied-port hints/count + AC selector; no VID/class |
| 3 Single | Extreme | 0x408180 / 0x4083a0 / 0x408298 | busy ports |
| 4 Balance | Balance | 0x407d1c / 0x407fbc / 0x407e70 | occupied-port hints/count; both lower tiers inspect reduction class/power |

- AI high-power condition: reduction class 1 with hint >=65 W, or native enum 8 with destination
  >=19000. With two normal C ports, load classes 1/2 and >=3 select 22.5 W for that port. They keep
  120/100 W for the other port. The class-zero tie policy and the AC-selector differences are
  [verified separately](allocation-policy.md).
- Apple uses fixed splits that prefer two mid-power C ports (0x407ab8: `0a 0a 30 30`,
  `07 0b 80 60`, `07 07 80 30`). If the AC selector is exactly 1, it selects 33 W instead of
  22.5 W and 55 W instead of 45 W in the related branches. The iPhone/iPad target comes only from
  the name. The firmware does not detect the identity.

## Exposed over BLE (getter 0x405914, updater 0x4043ac; VERIFIED)
- 2.1–2.4 (0x2000eb80[0..3]): `(V/100)<<24 | (I/100)<<16 | cap<<8 | status_lo`, from 0x2000ec18 +
  port×8 (+4 status, bit0 discharging; +7 cap code, set in 0x405d88 from cfg+0x12). The observed
  app values 01, 03, 05, 06, 08, 0a, 0b, 30, 60, 70, 80 are all cap codes.
- 2.17: C1 rec[0], C1 rec[1], C2 rec[0], C2 rec[1] (high byte first). For C1 and C2, native `07·0f` is exposed as `01·0f` only when bit 7 of the port byte at `0x2000c9e0`/`0x2000c9e2` is clear. `0x404dd0` copies bit 0 (C1) or bit 8 (C2) of the 2.21 protocol-enable value into that bit, so the static reading is that the remap needs that bit clear. A hardware sample showed `01·0f` while the mask was `0x03030f0f` (both bits set). This conflict is not resolved.
- 2.18: the same for C3 (+0xc/+0xd) and A (+0x12/+0x13).
- No property and no af07 status reply contains the VID or the brand class. Beacons are not fully
  checked.

## Gaps
Later documents close some of the gaps above. There is now focused evidence for these items:

- The separation of the native enum and the reduction enum.
- The packet checksum and cable fields.
- The origin of the SC cache.
- The AC selector and the hardware flag.
- The stored settings.
- The normal scene rows.

For the remaining scope, use the [current coverage ledger](coverage-ledger.md), not the first
scratch inventory. These items are still open: the missing controller firmware, the ROM bodies, the
real runtime allocation transitions and the physical negotiation.
