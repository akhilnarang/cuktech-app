# OTA transport and image integrity: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). Scripts: `scripts/ghidra/OtaRefs.java`,
`OtaListing.java`. Nothing was connected or flashed.
V = verified (address given), I = inferred.

## Summary
1. Transports.
   - The only OTA path is Mijia DFU on service FE95 (V, built at 0x419f50): ctrl 0x0017, data
     0x0018, protocol query 0x001C.
   - The GATT write handler 0x417928 rejects ctrl and data writes if the auth byte 0x20031782 is
     not 1 (V). Only a successful Mi login sets it (0x419658). A disconnect clears it. OTA is not
     possible before login (V).
   - 0x41c350 is not an OnMicro OTA hook. It is `mible_record_write`. Record 5 holds the DFU
     progress {crc32, recv_bytes}. It is written through ROM 0x10b128 (`nvds_put`) (V).
   - There are no vendor OTA UUIDs. The only other service is the OnMicro `simple_server` at
     0xAF00 (characteristics AF07/AF08). It is a factory/test channel. It is not used for OTA. It
     has no auth check (V) and probably no BLE security requirement (I). Frames start with
     `FE DC BA`:
     - `F2` with a 12-byte constant (at 0x473e5c) unbinds the charger and reboots.
     - `F1 04 0A 10` reboots.
     - `F1 01 xx` sets port modes and outputs.
2. Integrity.
   - R2SF header: vector table, load 0x403000, magic `R2SF`, chip id 0x6621F100. The size, CRC and
     version slots are 0xFFFFFFFF.
   - CRC32 for each fragment (calculated value against flash readback, 0x41b274). CRC32 over the
     full staged image at 0x7F000 against record 5 (0x41c4c0). These are only transfer checks.
   - Signature: ECDSA-P256 chain (0x41ab10 → 0x419534 → micro-ecc 0x420b32). A missing tag is
     accepted only if the flag 0x2000c4b4 is 0. Its initial value is 0x11 (decompressed RW .data;
     the `aa aa aa aa` tail is the end of the compressed data). Thus an unsigned image gets
     status 6 and is rejected (V).
   - Install: after a pass, MBR entry 0x60 = {0x7F000, size, CRC16} through ROM 0x10c1a0, then
     reboot (V). The bootloader probably checks only that CRC16 (I; no public OM6621 documents
     were found).
3. Mi Home checks the MD5 of the file. It sends the file raw as `[u16 index][fragment]` packets
   (`MeshDfuManager`, UUIDs in `_m_j/gi2`). It adds nothing before or after the file (V).

Open: with the initial flag 0x11, it is not known how the tagless CDN image installs. Possibly
code writes the flag through base+offset addressing, which a literal search does not find.

## 0. Background
- RW `.data` is stored compressed. Scatter table 0x4030e0: load 0x477c08 → RAM 0x20001730, size
  0xaec8, decompressor 0x403b40. The compressed stream ends exactly at file 0x79022. Thus the tail
  is RW init data. It is not a trailer. `cuktech_pc.firmware_unpack` decompresses it. The RAM
  function-pointer tables occur only in the decompressed output.
- 0x41c350 = `mible_record_write(id, buf, len)` → ROM 0x10b128 `nvds_put`. The fragment commit at
  0x41b378 calls it through 0x41c348. 0x41c320 = record_read; 0x41c2dc = record_delete (ROM
  0x10b2b4).
- Other early landmarks: `0x418ce4` / `0x41ab10` PEM/X.509 parsing (mbedTLS-style);
  `0x419008` / `0x419234` / `0x419570` SHA-256 helpers; `0x419658` references
  `mible-login-info` and `0x41e610` `mible-setup-info` (bind records in flash). ROM calls such as
  `0x10b128` and `0x105df8` go to the OM6621 mask ROM (BLE stack/flash).

## 1. Transports
- FE95 characteristics (registered through 0x41bc64 → ROM 0x1155ae): 0x04 (read), 0x05, 0x10
  (auth), 0x19 (standard auth), 0x17 ctrl (write+notify, write-authorized), 0x18 data
  (write-without-response, 244 B, write-authorized), 0x1A/0x1B (MIoT spec), 0x1C
  (protocol/version). Handle table at RAM 0x20031958: ctrl at +0xC, data at +0xE.
- Write-permit 0x417928: ctrl writes need `auth_state() == 1` (0x417bc8 reads 0x20031782). If not,
  they are denied. Data writes are dropped if the state is not 1. Only a login success in
  0x419658 sets the state to 1. A disconnect clears it (0x41f910).
- Ctrl commands (0x41ae44): 1 info; 2 fragment size (0x200, or 0x800 only if an A4 negotiation raised the parcel fragment to 19 bytes or more); 3 last index and running
  CRC32; 4 activate (4-byte delay) → verify; 5/6/7 status/MCU/flags.
- Data path: a fragment `[u16 index][payload]` is written to staging at `fragsize*(index-1)`.
  The CRC32 (0x41fea4, poly 0xEDB88320) of the RAM buffer is compared with the CRC32 of the flash
  readback. The result is stored in record 5.
- AF00 `simple_server`: the second add-service call is at 0x41fcb4. It is registered at stack
  init (0x416e10 → 0x412b74 → 0x412ac0). Writes go as message 0x4c04 to handler 0x41fdc4. This
  handler accepts the `FE DC BA` factory commands above. Attribute table at 0x474180:
  permissions 0x0400, 0x1000, 0x0a00. No security bits are visible. None of its commands change
  staging or the MBR.

## 2. Integrity
- Header: SP 0x20047458, reset 0x403059, +0x24 = 0x403000, +0x28 = `R2SF`, +0x34 = 0x6621F100;
  +0x2C/+0x30/+0x38/+0x3C are 0xFFFFFFFF.
- The version and identity are only in data: "0073" and "njcuk.fitting.ad1204" at
  0x474a46/0x474a4b. The product id 0x660E is in the config struct at RAM 0x2000c49c.
- Verify state machine 0x41b3f0: 0 SUCC, 2 AUTH_FAIL, 6 UNSIGNED. 0x419534 returns 3 OK / 2 fail.
  - The full chain passes → flag 0, status 0, switch.
  - A step fails → flag 1, status 2.
  - No tag or a rejected tag → flag 0 accept, 1 → status 2, other → status 6.
  - Initial flag 0x11.
- Logic quirk (I): after one valid signed verify in the same boot, the charger would accept a
  later unsigned image. This is probably not important, because a valid verify usually switches and
  reboots.
- Switch 0x41c4c0: it reads the staged image at 0x7F000 (it reads each 256 B chunk two times and
  compares them). It compares the CRC32 with record 5. It calculates a CRC16 through ROM 0x10a6f6.
  It writes MBR entry 0x60 through ROM 0x10c1a0 and reads it back with 0x10c09a. It resets
  through ROM 0x105df8. The `[MBR]ADDR/SIZE/CRC:%04X` log at 0x405834 reads the same entry.
- Bootloader (I): probably a CRC16 check against the MBR entry. The charger calculates this value
  itself. Thus only the ECDSA step gives authenticity.

## 3. Mi Home
- `BleUpgradePresenter`: MD5 check → `startBleMeshUpgrade` → `MeshDfuManager`.
- `MeshDfuManager`: reads the file raw. Packets: `[u16 index from 1][fragmentSize bytes]`.
- `gi2` UUIDs: FE95, 0x17, 0x18, 0x1C. A local CRC32 is used for resume. No signature or trailer
  is added.

Not checked: the ROM and bootloader (not in the image), and the meaning of ROM 0x1129a0.
