# Unauthenticated BLE surface: AD1204U fw 2.1.2_0073

Static analysis only (2026-10-13). Nothing was sent to the charger.

Summary: there is one unauthenticated control channel. It is the CUKTECH service `0xaf00`,
characteristic `0xaf07`. It can change settings, switch ports on and off, do a factory reset
(this unbinds the charger) and reboot. No live port power was found on it. All Xiaomi MIOT traffic
needs a login and encryption.

## 1. GATT services and handlers
- `0xaf00` service: no path has authentication (verified). The table is at `0x474180`. It is added
  at `0x41fc58` through `0x412b74`. It is enabled for each connection at `0x416a3c` → `0x412afc`.
  Characteristics: `af07` write, `af08` notify (after a CCCD write), and a `0x2901` descriptor.
- `af07` write path: handler `0x417868` → message `0x4c04` → app handler `0x41fdc4`. This path
  does not call the Mi session/state check (`0x417bc8`, `0x20031782`) (verified).
- Frame format: `fe dc ba <any byte> <op> …`, length > 6. Replies come on `af08` as
  `fe dc ba … ef` (`0x414288`, message `0x4c03`). The upstream unauth scan wrote only `00`/`01` to
  `af07`. Thus it did not use this header.
- Mi service (`0x417928`): UPNP accepts only `15`/`24`/`a2`/`a4`. AVDTP goes to `0x4135e8`. The two
  MIOT characteristics need session state 1 or 2 (verified). One more Mi characteristic
  (offset `+0x16`) has no authentication. Its callback `0x4216c0` returns only fixed data (`03`,
  chip ID `"C126" "66SH"`, a `"123456789…"` test string). It gives no telemetry. One exception: in
  `0x417928`, a write of `01` whose callback fails queues admin op 0xa6 (`mible_mcu_get_info`,
  `0x41c128`), an MCU-info read. No security impact was found.

## 2. Telemetry and settings without login
`af07` with `op=f1` (all verified):

| Command | Function | Effect | Same setter as MIOT property |
|---|---|---|---|
| `01 04 x` | `0x404fe8(3,x)` | sets scene-mode | 2.5 |
| `01 05 x` | `0x404fe8(4,x)` | sets screen-save-time | 2.6 |
| `01 07 a b c d` | `0x409608` | turns ports 0–3 on/off | — |
| `01 08 <u32 big endian>` | `0x404dd0` | sets protocol-ctl-extend | 2.21 |
| `01 09 x` | `0x405050` | values 0/1 select persistent Holiday startup artwork; values >1 skip the writer and return the flag | — |
| `04 xx 0a 10` | ROM `0x105df8` | reboots (byte 7 is ignored) | — |

- Status replies: `f1 02` and `f1 01 01/02/03/06` return the firmware and sub-chip versions, the
  MBR CRC, SC2021 PD-chip registers and setting bytes. `f1 01 02` and `f1 02` also contain a
  cached internal temperature byte. See [telemetry follow-up](findings-telemetry.md).
  Vendor requests also stop MIOT cache updates until disconnection. Inferred: these status
  replies do not contain per-port watts or volts.

Stage 18 confirms that selector 7 changes each separate byte to a boolean.
Selectors 7 and 8 return fixed success markers. They do not echo or read back the value.
The wire byte order of selector 8 is different from the typed little-endian u32 of MIOT.
For the exact raw evidence, the offline frame description and the callback-validation limits,
see [protocol/command follow-up](protocol-command-blob-followup.md).
- `op=f2` with 12 fixed bytes does a factory reset (`00 0a 0c 04 00 42 01 00 03 00 40 00`, at
  `0x473e5c`). The compare is at `0x41fe1a` → `0x4046c6`. It deletes app records 0x51/0x53, sends
  `0xa1` (deletes the Mi keys, record 0x10), deletes record 5 and reboots (verified). No
  application session check was found on the compiled reset/unbind path.
  GATT access on a real charger is not verified.
- FE95 beacons: the encoder is `0x41a4ac`. Objects are always AES-CCM encrypted (frame-control bit
  0x08, AAD `0x11`, 4-byte MIC). The beacon key at `0x2000d7ec` is the bind_key (set at bind,
  `0x41a6f8`). An unbound charger (bit2 of `0x2000eb64` clear) sends no objects (returns 7)
  (verified). Plaintext fields: frame control, product id `0x660e`, MAC, counter.
- Buttons and screen: the long-press reset is local only (`0x4060c8` event 3) (verified).

## 3. MIOT without encryption: none
- The firmware drops MIOT writes if the session state is not 1 or 2 (`0x417928`) (verified).
- Inbound MIOT `0x41ffd4` → `0x41a0d0` returns 1 if there is no session (bit0 of `0x200318e0`
  clear). It checks the AES-CCM tag (`0x412640`, -0xf on mismatch) before `0x41fee4` (verified).
  There is no plaintext or debug branch.

## Gaps
- State values 1 and 2 are not decoded.
- ROM `0x1129a0(0xf)` (`f1 04 xx 0a 11`) is unknown.
- Some status fields are not identified.
