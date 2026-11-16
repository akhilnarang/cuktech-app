# DFU verify state byte (*0x41b7a4): findings (2026-10-13)

Static analysis only. Image `upd_njcuk.fitting.ad1204.bin` (2.1.2_0073), base
0x403000. Script: `scripts/ghidra/StateListing.java` (listing and refs-to). The RW image was
rebuilt by emulation of the armlink RW decompressor at 0x403b40.

## 0. Correction to the initial notes
- Verify result 2 does not mean success. In the newer Xiaomi lib, the value sent with
  MIBLE_DFU_STATE_VERIFY is a MIBLE_DFU_STATUS_* code: 0 SUCC, 2 ERR_AUTH_FAIL, 6 ERR_UNSIGNED.
  - Source: the public header mijia_ble_libs/gatt_dfu/mible_dfu_main.h (tuya/TuyaOpen-JieLi;
    telink-semi/tc_ble_mesh). It has the same state enum: 0 START, 1 UPGRADE_STATUS, 2 TRANSFER,
    3 VERIFY, 4 SWITCH, ... 8 CANCEL.
  - The dfu_ctx_t layout matches (tag@0, certs@0x200/0x400, server_crt@0x600, dev_crt@0x660,
    sig@0x6c0, sha@0x700). mible_dfu_auth(ctx, init, size) also matches. Verified against
    0x41b700-0x41b704 and the offsets used in 0x41b3f0.
- App callback 0x412898, case 3: it logs "verify result is %d". On 2, it clears the OTA-busy flag
  *0x20031928. FUN_004048b0(2) does nothing (it acts only on 0 and 3).
  - The app does not control the switch. The library controls it through the DFU state
    *0x2000e230 (4 = switch-wait, 5 = cancel). Verified at 0x412898 and 0x4048b0.
- The .c file for this protothread lib version is not public (headers only). Older sync versions
  (bomingfeng TLSR825x, TuanLe2411 Telink mesh) map MI_ERR_INTERNAL -> AUTH_FAIL (2) and all
  other errors -> ERR_UNSIGNED (6). This agrees with the codes above.

## 1. The state byte
- DAT_0041b7a4 = DAT_0041b6dc = 0x2000c4b4 (u8). Only these two literal words point to it. Ghidra
  lists exactly 3 refs, all in FUN_0041b3f0 (verified):
  - 0x41b4e8 strb 1: one of the 3 ECDSA verifies fails (FUN_00419534 returns 2).
  - 0x41b75a strb 0: only after all 3 verifies succeed (step 0x36d returns 3).
  - 0x41b710 ldrb: read only if mible_dfu_auth (0x41ab10) returns non-zero.
- The neighbouring literals do not write it (verified): 0x2000c4ac/c4b0 = 6-byte read at 0x41cf58;
  0x2000c4b2 = u16 1000 read at 0x41aa60/0x41d5f8.
- DFU init (0x41b1d0) and the ctrl commands (0x41ae44) do not change it. It is not persisted.
  Inferred: there are no computed-address writes (only literal and Ghidra refs were checked).
- The initial value is 0x11. This comes from emulation of the compressed RW region (scatter entry
  @0x403110: src 0x477c08 -> 0x20001730, len 0xaec8, decompressor 0x403b40). The length matches
  exactly and the neighbouring values are sane. High confidence. Not observed at runtime.
- Result if mible_dfu_auth fails (verified 0x41b70e-0x41b79a):
  - byte 0 -> status 0 (SUCC), state 4 SWITCH
  - byte 1 -> 2 (AUTH_FAIL), state 5 cancel
  - other (fresh boot, 0x11) -> 6 (UNSIGNED), state 5 cancel
- Thus the byte is the cached verdict of the previous verify in the same boot. No phone flag,
  product config or CRC-only path sets it.

## 2. State machine (FUN_0041b3f0, protothread; pt values are __LINE__ numbers, inferred)
- Ctrl handler 0x41ae44 (verified):
  - cmd 1 -> state 1.
  - cmd 2 (start) -> state 2 (5 if the pre-check fails).
  - cmd 3 (index/resume, CRC32 over the received data) -> state 2.
  - cmd 4 with a 4-byte switch_delay -> state 3. The delay is at 0x20031890.
  - No command checks the current state.
- State 3, pt 0: mible_dfu_auth(ctx 0x2000e2f4, init 0x20031874, recv_bytes=*(0x20047458+8)).
  - If 0, it checks in this sequence: server cert against the root key (0x355), dev cert against
    the server key (0x361), package signature over SHA-256 against the dev key (0x36d). Each check
    uses FUN_00419534 (3 valid / 2 invalid).
  - All pass -> byte=0, status 0, state 4. One fails -> byte=1, status 2, state 5.
  - Then it sends rsp {cmd 4, status} (0x41b3b4) and calls callback(3, {value, 5-byte version}).
    The app value 9 (INVALID_VERSION) overrides the value.
- State 4 (pt 0x39f) (verified): it waits while ctx+0x66 is set. 0x41b7c4 clears this flag on
  disconnect (called from 0x4166b2). Then it counts down switch_delay. At delay 0 it calls
  callback(4) "switch" -> FUN_0041c4c0. This function compares the CRC32 of the staged image at
  flash 0x7f000 with the stored value (0x2000c840[1]). Then it writes the ROM OTA record
  (0x10c1a0) and reboots (0x105df8). 0xFFFFFFFE -> MCU callback; 0xFFFFFFFF -> no switch.
- State 5 -> callback(8) "canceled", state 0.

## 3. Conclusion
- A tagless or unsigned image on a fresh boot gives status 6 (UNSIGNED) and is cancelled.
  Verified (if the initial value is 0x11).
- The cached-verdict weakness is inferred. Each part of the data flow is verified, but it was
  not tested. It applies only after a real Xiaomi-signed package for njcuk.fitting.ad1204 passed
  verification in the same boot.
- A signed package was downloaded later. Its compiled-root, certificate and image chain passed
  offline verification. This replaces the earlier statement that no signed package exists.
- The cached fallback is still only a static candidate. It is not a demonstrated installation or
  recovery route.
- The bootloader (0x400000-0x402fff, not in the OTA) can possibly do more checks. Unknown.

Not checked: computed-address writes to 0x2000c4b4, the bootloader, and if Mi Home ever sends a
signed trailer. The 0x11 start value comes from emulation. It is not a runtime read.
