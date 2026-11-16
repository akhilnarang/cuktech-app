# Bind (standard-auth register) signature checks: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). Helper script:
`scripts/ghidra/BindInfo.java`.

## Summary

The register handler is the protothread at 0x41e610. The only path to it is the UPNP write
`15 caps caps2`: 0x417928 → 0x4135f8 → 0x419dec → 0x419658. 0x419658 sends `cmd&0xf0==0x10` to
0x41e610. Verified.

Flow (all verified):
1. The charger receives the P-256 public key of the host (parcel code 3). It does ECDH, then
   HKDF(shared, 16 zero bytes of salt, "mible-setup-info", 64). This gives token, bind_key and
   a_key at 0x20031738/44/54. This agrees with `scripts/cuktech_pc/crypto.py`.
2. It waits for 0x13 (0x14 → 0x12). Then it receives the blob (code 0) and the DER cert (code 7,
   max 512 B).
3. It checks the blob with AES-CCM, with a_key, nonce 10..1b and AAD "devID". A bad tag gives 0x12.
4. Check 1: it verifies the TBS of the cert with ECDSA-P256 against a root key in flash at
   0x47408c (file 0x7108c). The point is on P-256: X=bef58b02…6628fa, Y=d7f020ea…15f4f9.
   The chain has only one level. It does not check validity dates, issuer or signature OID.
5. Check 2: it verifies cloud_sign with ECDSA-P256 over SHA256(did[20] ‖ bind_key[16] ‖ utc_le[4]),
   with the public key of the cert. It does not compare utc to a clock.
6. The DID is fixed to mible record 1. If the record exists and is different, the result is 0x12.
   A factory reset does not delete this record.
7. On success, the charger writes record 0x10 = token ‖ bind_key, installs the beacon key and
   returns 0x11. On a failure, it returns 0x12 and writes nothing.

Can a bind work without the cloud? No.
- No mode, flag, debug path or v1 encrypted-DID-only branch skips a signature check.
- 0x41ea72 is the only code that writes record 0x10.
- You cannot send 0xa1 (delete keys) over BLE. Only the factory-reset event 0x4060c8 starts it.
- Login needs the stored token.
- A replay of a captured cert and signature fails. The reason is that bind_key comes from a new
  ECDH in each session (a new keygen each time is inferred).

Thus a host needs the Xiaomi root private key, or a cert signed by it and the private key of that
cert. The only theoretical route is firmware with a different root key. This needs an unsigned
DFU path.

Not checked: memory safety of the parsers, the meaning of the 0xE1 config bit, the RNG.

## Call path

| Addr | Role | Status |
|---|---|---|
| 0x417928 | GATT write dispatcher; a UPNP write goes to 0x4135f8 | VERIFIED |
| 0x4135f8 | Lets only 0x15, 0x24, 0xa2 and 0xa4 through from BLE. 0x15 also needs bit1 of 0x2000eb60, which 0x413648 sets at service init. 0xa1 cannot be sent over BLE | VERIFIED |
| 0x419658 | Dispatcher: 0x10 group → register 0x41e610; 0x20 group → login; 0xa0–0xa6 admin. 0xa0 loads keys from record 0x10; 0xa1 deletes record 0x10 | VERIFIED |
| 0x4060c8 | Factory-reset event 3: deletes app records 0x51/0x53, queues 0xa1 (deletes record 0x10), deletes record 5 | VERIFIED |

App records are 0x50+n (0x41c84c/54/60). Mible records are 1 = DID, 4 = beacon counter, 5 = DFU,
0x10 = keys.

## Register states (0x41e610)

The state values are protothread line numbers 0x2f0–0x3cd.
- State 0:
  - 0xE1 if the config bit `*(0x2000c494+0xd)&1` and the registered bit `*0x2000eb60&1` are both
    set. Inferred: the config blocks a new bind while the charger is bound.
  - 0xE3 if the charger needs OOB and the host offered no OOB. `caps` (cmd>>8) is ANDed with the
    charger OOB caps at `*(u16*)(0x2000c494+10)`.
- 0x2f0 / 0x2f5 / 0x2fe / 0x302: receive the app public key → 0x2000d53c. Keygen 0x4194d8 →
  0x41c5c0, charger public key at 0x2000e294. ECDH 0x419504 → 0x41c65c (micro-ecc) → shared
  secret at 0x2000eb30. Send the charger public key.
- OOB branch (0x31c–0x333): HMAC confirmation with parcel codes 0xc/0xa/0xd/0xb. Without OOB,
  the salt at 0x2000cfa8 is set to zero.
- HKDF: at 0x41e7dc/0x41955c. The info string is at 0x474078.
- 0x35c: polls the characteristic value through 0x41d49c.
- 0x360 / 0x367: blob → 0x2000e234 (max 0x5c). Cert → 0x2000e00c (max 0x200; length at 0x2000e20c).
- CCM: 0x4194cc → 0x413e28. It returns -0xf on a tag mismatch.
- Cert parse: 0x4188c4 is `mi_crypto_crt_parse_der` (DER only; only DFU uses the PEM parser
  0x418ce4). It is called with `now=NULL`. Outputs: tbs{p,len}, pub (64 B), serial, O, sig[64].
- Hash and verify: SHA-256 at 0x4195a8. The verify chain 0x419534 → 0x41c768 → 0x420b32 is
  micro-ecc `uECC_verify` with range checks and a Shamir ladder. 0x419534 returns 3 (valid) or 2
  (invalid). 2 leads to 0x12. The two verify calls are at 0x41e704 and 0x41ea30.
- DID record: read, compare and write at 0x41ea46–0x41ea54.
- Key record: record 0x10 is written at 0x41ea72. 0x41a6f8(bind_key, 1) sets the beacon key.
  Success raises app event 1. Failure raises event 2.
- Login (0x419658): state 0 returns 0xE0 if the charger is not registered, and 0xE2 (repeat
  login) if `*0x20031782 == 1`. States 0x3f5–0x41f (0x419a4e–0x419b18) do the HMAC exchange with
  a key derived from the stored token, then send 0x21 (ok) or 0x23 (fail). Verified from code.
  The names are inferred.

Not checked: bounds safety in 0x4188c4 and 0x41f14c. Also not checked: if 0x41b378/0x41b0e2 (DFU)
change records 1 or 0x10 (inferred: they do not).
