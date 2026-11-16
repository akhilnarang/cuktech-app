# Signed-DFU ECDSA verification: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). Helper scripts:
`scripts/ghidra/EcdsaXrefs.java`, `EcdsaListing.java`. Reference: the public Mijia BLE SDK sources
(the older `mible_dfu_auth.c` and the newer `mible_dfu_main.c`).

## 1. Where the verification runs

The verification runs in the firmware. It does not run in the ROM. `FUN_0041b3f0` is a
protothread (PT state at ctx +0x4c, PT line numbers 0x355/0x361/0x36d). ctx = 0x2000e2f4.

| Step | Public key | Hash | Signature | Verify call |
|---|---|---|---|---|
| server cert | 0x424f20 (copied at 0x41b47a) | SHA-256(`*(ctx+0x600)`, `*(ctx+0x604)`) | ctx+0x620 | 0x41b61e |
| developer cert | `*(ctx+0x608)` | SHA-256(`*(ctx+0x660)`, `*(ctx+0x664)`) | ctx+0x680 | 0x41b668 |
| firmware | `*(ctx+0x668)` | ctx+0x700 | ctx+0x6c0 | 0x41b4d4 |

All verified.

Call chain (verified):
- `0x419534` = `mi_crypto_ecc_verify`: -1 if an argument is NULL, 3 valid, 2 invalid.
- It calls `0x41c768`, which reverses the byte order of X, Y, hash, r and s. `0x41c768` calls
  `0x420b32(pub, hash, 32, sig, curve = 0x4209f0())` = micro-ecc `uECC_verify`. This function
  rejects r or s if it is zero or ≥ n. It does a Shamir double-scalar multiplication through
  `curve+0xa4` and compares x with r.
- `0x4195a8` = `mbedtls_sha256` through 0x4190f4. It always returns 0.

`0x41ab10` only parses the tag and the certificates. It does not verify.

## 2. Root of trust

At 0x424f20 (file 0x21f20) there are 64 bytes of raw big-endian X||Y. They are immediately
before the DFU tag magic at 0x424f60:

```
bef58b02dae3fff8541aa0448fbac44db7c69a2fa8f0b1b6ff7ad951db6628fa
d7f020ea39a2ee867fdd783fdc2fb086095cc2850413a2802c627dbdc715f4f9
```

- Verified: it is a valid P-256 point.
- Verified: it is the same as the subject key of the Xiaomi "Mijia Root" CA (O=Mijia Root, C=CN,
  valid 2016–2066). Source: `root_cert[]` in `mi_mesh_otp.c` (copy in
  TuanLe2411/Telink_mesh_sdk_VSC). The reference parses a DER root certificate.

Certificate parsing (verified):
1. strstr("-----BEGIN CERTIFICATE-----") finds the PEM certs.
2. `0x418ce4` changes PEM to DER into ctx+0x200 / ctx+0x400.
3. `0x4188c4` parses each cert into a 0x60-byte record (+0 tbs ptr, +4 tbs len, +8 pubkey ptr,
   +0x20 raw r||s). The records are at ctx+0x600 / ctx+0x660.

Extra name check (the meaning is inferred): the name of the developer cert (record +0x18/+0x1c)
must be "cert" (0x474024) or `*(init+0xc)`. If not, `0x41ab10` returns -13.

Firmware hash (verified): `0x4137b0(ctx+0x700, fw_size + tag_size)`. It covers the same data as
the reference. The result of the DER→raw signature conversion (`0x419030`) is checked.

This build does not check certificate dates, key usage or basicConstraints. The reference also
does not check them.

## 3. How results are used

Status codes from the newer SDK `mible_dfu_main.c`: SUCC=0, AUTH_FAIL=2, UNSIGNED=6. The same
value goes to the BLE response and to the app callback `(*0x2000eaf8)(3, …)`.

Results (verified):
- All checks pass → flag `0x2000c4b4 := 0` → status 0, DFU state 4 (switch) (0x41b754, 0x41b71c).
- An ECDSA check fails → flag := 1 → status 2, DFU state 5 (0x41b4e2).
- `0x41ab10` returns non-zero → its return value is ignored. The code tests the flag
  (0x41b70e–0x41b79a): 0 → status 0 and switch; 1 → status 2; other → status 6.

The initial flag value is 0x11. This is verified by emulation of ARMCC `__decompress` at 0x403b40
on the scatter region 0x477c08 → 0x20001730, size 0xaec8 (region table at 0x4030e0). In the output,
55 pointers point to strings that have a NUL before them. The only literal references to the flag
are in `FUN_0041b3f0`.

Results for the charger:
- At boot, an unsigned or tagless image gets status 6 and is rejected. The reference does the same.
- Weakness (the behaviour is verified, the exploitability is inferred): after one image passed
  verification in the current boot, a later image that fails parsing gets SUCC. The probable
  cause is a stale protothread static that the code uses in place of `ret`. This needs a real
  Xiaomi-signed image for this product first.
- Correction to the initial notes: in `0x412898` case 3, value 2 is AUTH_FAIL. The switch comes from DFU
  state 4 → callback(4).

Pre-auth stack VLAs (verified; the impact is inferred): the cert buffer `sp -= align8(cert_size)`
at 0x41ace4–0x41acec and the signature buffer at 0x41adcc get their size from the unauthenticated
tag. This occurs before all signature checks (the reference does the same). strstr runs on a
buffer that has no NUL terminator.

## 4. Comparison with the reference `verify_firmware()`

The chain is the same: root → server cert → developer cert → SHA-256(firmware + tag). Each step
needs `ecc_verify == 3`.
Differences:
- The firmware uses a non-blocking protothread.
- It uses a raw root key. The reference uses a DER cert.
- It has an extra name check on the developer cert.
- On a parse failure, the status comes from the stale flag. In the reference, it comes from the
  return value.

## Not checked
- The curve constants at `DAT_004209f4`.
- What `FUN_00403234` compares.
- If Mi Home adds a signed trailer for this model. Without a trailer, the charger would reject a
  fresh-boot OTA of the CDN image with status 6.
- The stack layout. You need it to know the impact of the VLAs.
