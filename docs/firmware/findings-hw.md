# Hardware (SWD) reflash feasibility: AD1204U / OM6621Px

Desk research only (2026-10-13). No hardware was touched.

Current limit: physical programming can be investigated with the documented vendor tools for this
chip family. The debug protections and the boot-time checks on this charger are unknown, because
the ROM and a full flash dump are not available. No physical work was done.

## Verified (with sources)
1. SWD read and write: yes. OnMicro has a note about how to flash the 6621x with J-Link/JFlash.
   The tool can program and read the internal flash. It removes write protection automatically.
   It does not support a full-chip erase, because the last sector holds system data. Do not erase
   that sector. Sector erase is supported.
   https://bbs.onmicro.com.cn/m/BLEzhzl/234.html
   - SEGGER added OM662X support to J-Link/Flasher (Apr 2026). The KB lists OM6256/6626/6627/6629
     with the banks OPT 0x400000, MBR 0x401000, User 0x404000. Do not overwrite the factory test
     data.
     https://www.segger.com/news/pr-260422-j-link-flasher-om662x-support/ ,
     https://kb.segger.com/OnMicro_OM6x
   - The OnMicro red-board programmer supports the 6621P series: https://bbs.onmicro.com.cn/m/BLEzhzl/73.html
   - The 6621PW programmer has "xpack" encrypted and non-encrypted modes: https://bbs.onmicro.com.cn/m/BLEzhzl/83.html
   - No pyOCD/OpenOCD pack was found. No documented OM6621 readout-lock or SWD-disable eFuse was
     found. The only SWD-lock setting found is for the OM6681:
     https://bbs.onmicro.com.cn/static/upload/2024/04/15/46304644.pdf
2. Boot check: the OTA header has `R2SF` and a load address. The words at +0x2c and +0x30 are
   0xFFFFFFFF. There is no signature. The Xiaomi ECDSA check runs in the DFU code of the
   application. It does not run at boot.
3. Physical access: in the ChargerLab teardown, the main PCBA is potted on the front and back with
   a grey compound. The MCU and the crystal are on the back. The teardown does not mention test or
   debug pads. Bulk capacitors: 420V 39µF and 3× 420V 18µF.
   https://www.chargerlab.com/teardown-of-cuktech-10-gan-charger-ultra-ad1204u/

## Inferred
- The ROM/bootloader probably checks the header and possibly a CRC. It probably does not check a
  signature. Xpack flash encryption or a vendor lock is possible until somebody reads the chip.
- 0x400000–0x402fff is probably OPT and MBR (boot record, calibration). It is probably not a
  bootloader.
- The bind records (`mible-*`) are in a separate data region. If you erase and rewrite only
  0x403000 to the end of the app, the DID and the keys should stay. A wrong erase range deletes
  them. Xiaomi cannot issue them again.
- On the OM6621E, the SWD pins are also GPIO0/1. You possibly must connect under reset.
- At about 325–375 V, the bulk capacitors store about 5–6.5 J. This energy can kill.

WARNING: Do not connect mains power while wires are attached. Use a 3.3 V bench supply. Before you
touch the board, discharge the capacitors through a resistor and measure the voltage.

## Risks and recovery
- Depotting can tear pads, crack the QFN48 or damage the GaN stage.
- If you erase the calibration or system sectors, the chip can become unusable.
- A bad app image bricks the charger. SWD can recover it if no lock is set.
- Before all other work, read the full 1 MB and keep a copy. This copy is the only way to restore
  the binding.

## Result
It is possible in principle. It is expensive, destructive and dangerous. You need:
1. Full depotting of the back side.
2. A J-Link or an OnMicro programmer, with hand-soldered wires to SWDIO, SWCLK, RST, 3V3 and GND.
   Trace these pins from the QFN pinout.
3. A full read-back before all writes.
4. Writes only to the app sectors.
5. A patched app that keeps the header layout.

After this work, you cannot pot the charger again in the same way. Use it only on the bench.
Do not leave it on mains power without supervision.

Not checked: the 充电头网 teardown photos (for exposed pads), the OM6621P datasheet or reference
manual (not public), and the OnMicro boot/MBR source (no public copy).
