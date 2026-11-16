# Official OTA correlation: AD1204U receiver

Date: 2026-10-15. This document is an offline correlation of the receiver side of
`njcuk.fitting.ad1204`, `2.1.2_0073`. There was no BLE connection, charger request,
network request, flash operation, Ghidra run or database change. The matching
Mi Home sender is documented separately in
[the native transfer trace](ota-transfer-framing.md). That trace follows the native
update route of the official plugin. The runtime selection and compatibility were
not observed. A match with a generic sender class alone does not prove model
selection.

## Evidence identity

| Local artifact | Bytes / SHA-256 |
|---|---|
| `artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-1.bin` | 495,656; `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1` |
| `artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin` | 496,995; `1724b63e797af6a76e43d61931e2361b537e653946a130d0441ca0ef9d5ed65a` |
| `artifacts/firmware/ghidra-final/functions.jsonl` | `eb3415d1a9b8f19f5709bf9c79306244b2674266947724a01e417790e12c9822` |
| `artifacts/firmware/ghidra-final/analysis.json` | `77bb30bdf972e24b2419731f0b18471e29b6e42104c19457bfa295a056645f50` |

The existing local Ghidra exports were used again. Capstone decoded selected parts
from the original bytes separately: packet construction, literal values,
configuration and notification arguments. The signatures that Ghidra infers can
omit shared-register arguments. If they disagree, the raw stores and call arguments
are correct.

## Actual endpoint and authentication gate

Initializer `0x00419f50` builds service `FE95`. Its descriptor writes create:

- OTA control characteristic `0017`, property byte `18` hexadecimal
  (write + notify), maximum length 20.
- Reliable data characteristic `0018`, property byte `14` (write without
  response + notify), maximum length 244.

The descriptor builder is `0x0041bc64`. The characteristics are **0017/0018**. They
are not the legacy 0007/0008 pair. The ROM stack allocates the runtime ATT handle
numbers. Do not hard-code them from the UUIDs.

Dispatcher `0x00417928` takes the allocated control handle from structure
`0x20031958 + 0x0c` and the data handle from `+0x0e`. Both OTA paths require
`0x00417bc8()` to return exactly 1. That getter reads `0x20031782`. The application
reliable channels at offsets `+0x10/+0x12` accept 1 or 2. Do not copy that wider
condition into the OTA gate. A successful login at `0x00419c64` writes 1.
Disconnect helper `0x0041f910` writes 0. No producer of auth state 2 was found in
the inspected literal and reference paths. The fact that the code accepts a value does not
prove that a usable producer exists.

The separate AF00/AF07/AF08 factory/status channel has different framing. It has
no mapped route into this DFU parser. Its reboot and setting commands are not OTA
control packets.

## Three framing layers must remain separate

1. **DFU control request on 0017:** `command:u16le, payload_length:u8,
   payload`. Parser `0x0041ae44` requires the exact total size `3 + length`.
2. **Reliable transport on 0018:** its control messages start with sequence
   zero. Nonzero `u16le` sequence numbers identify the GATT pieces of one
   assembled message. Receive routine `0x0041eeb4` and assembler `0x0041f14c`
   handle this layer.
3. **Logical firmware fragment inside that assembled message:**
   `firmware_fragment_index:u16le, firmware_bytes`. Commit `0x0041b274`
   removes this two-byte index. It writes the bytes at
   `fragment_size * (index - 1)` relative to the staging base.

The GATT piece index and the logical firmware fragment index are independent. Do
not treat each received 0018 value as a complete flash fragment. That skips the
reliable transport, the acknowledgements, the assembly and the retransmission.

### Control notifications include an extra envelope

Queue helper `0x0041b3b4` stores `kind:u8, payload_length:u8, payload`. Worker
instructions `0x0041b444..0x0041b45c` notify the **entire** object with length
`queue[1] + 2`. The notification goes on the control handle at DFU context offset 4.
Thus the two-byte queue envelope is sent on the wire. It is not only local
bookkeeping.

| Event | Complete control notification structure |
|---|---|
| Command 1 response | `01 05 01 00 status 04 00` |
| Command 2 response | `01 05 02 00 status fragment_size:u16le` |
| Command 3 response | `01 09 03 00 status last_firmware_index:u16le rolling_crc32:u32le` |
| Command 4 verification result | `01 03 04 00 status` |
| Firmware fragment result | `02 03 status firmware_index:u16le` |

Here `01/02` are notification kinds. The next byte counts the payload bytes. These
two bytes are not in the matching control request. Fragment result status 0 means
that the observed commit path completed. The code also sends 5 for a commit failure
and 7 for a transport receive failure. These statuses are separate from the
signature verification results and from the reliable transport ACKs.

On 0018, reply helper `0x0041f0ac` builds zero-sequence messages: `00 00 01 code`,
or `00 00 03 code` for the short-message mode. Missing-piece reports add a list of
`u16le` piece indices after `00 00 01 05`.

The observed ordinary receive setup at `0x0041eeb4` accepts a six-byte message
`00 00 00 type count:u16le`. DFU fragment receiver `0x0041b7ec` waits for type
zero. Its ready ACK uses code 1, and its final success ACK uses code 0. These are
static observations of the parser and the constructor. They are not a validated
transmission procedure.

Assembler copy helper `0x0041f120` puts the bytes of a piece, after its two-byte
index, into the assembled buffer at `negotiated_piece_size * (piece_index-1)`.
Reliable initialization `0x0041ed54` sets its global piece size to 18 at the start.
Parameter exchange `0x0041ed80` can change the transport parameters. Do not treat
18 as a fixed current MTU limit. Do not confuse it with the 512/2048-byte logical
firmware fragment size.

## Control effects and resume semantics

| Command | Receiver behavior | Relevant boundary |
|---|---|---|
| 1 | Queues information response, enters state 1, starts worker timer | Changes DFU state; not a passive read of an unrelated characteristic |
| 2 | Selects fragment size 512 or 2048 using reliable-link parameter, invokes optional preparation callback, emits application start event and enters state 2 on success | Prepares a transfer and changes application state |
| 3 | Loads record 5, optionally recomputes CRC over staged bytes, responds with index/CRC, enters state 2 | Resume-state query also enters transfer state |
| 4, payload length 4 | Caches progress, deletes resume record 5, stores switch delay and enters verification state 3 | Destructive to resume metadata; not just a progress query |
| 5 | Requires two optional callback slots and enters state 6 | No configured callback implementation established |
| 6, payload length 4 | Requires another optional callback pair and enters state 8 | Same limit; not proven MCU capability |
| 7, payload length 1 | Calls optional application event 1; when `(option & 3) == 1`, sets a DFU-context flag that makes command 3 recompute the saved prefix CRC from staging flash. Command 1 clears the flag. | Stateful resume-integrity option; no command-7 call found in the traced sender's normal sequence |

The optional slots start in BSS at `0x2000eb04..0x2000eb14`. The parser and the
worker read them through direct references. The inspected exported reference set
has no direct writer that sets or registers them. This means only that no
configuration was found. It does not prove that no writer through a computed
address or ROM exists.

Logical fragment receiver `0x0041b7ec` runs in worker state 2 (and in the shared
state 7). It does these steps:

1. It sets a receive buffer of `fragment_size + 2`.
2. It assembles a type-0 reliable message.
3. It commits through `0x0041b274`.
4. It queues its fragment ACK.

The commit computes CRC32 over the incoming data with the previous seed. It
compares this value with CRC32 over the flash readback. For fragment index 1 it
resets the received count to the length of that fragment. Each later new index adds
its length. The commit saves a sixteen-byte record 5: index at offset 2, CRC32 at
offset 4, received-byte count at offset 8. CRC helper `0x0041fea4` uses the
reflected polynomial `edb88320` with complemented seed and result.

Record helper `0x0041c348` maps a logical record ID to the ROM/NVDS tag
`(id - 0x70) & 0xff`. Thus logical record 5 goes to tag `0x95`. This record holds
the transfer progress. It is not an OnMicro OTA entry point. On command 4,
`0x0041c2d4(5)` first copies the saved received-byte count and CRC into RAM
`0x2000c840`. Then it deletes the progress record. The final switch validation
uses those copies.

## Staging limits recovered from the actual startup data

Connection callback `0x0041668c` builds the 24-byte DFU configuration and calls
`0x0041b1d0`. The source configuration at expanded RAM `0x2000c494` contains:

- Product ID `0x660e`.
- Model and version pointers.
- The staging base at `+0x10 = 0x7f000`.
- The relative size limit at `+0x14 = 0x7c000` (507,904 bytes).

Initializer `0x0041b150` stores these values in the globals `0x2000eb00` and
`0x2000eafc`.

Both existing package lengths are inside the configured relative limit. This does
not prove that either package is safe to install for every firmware, account,
product variant or recovery condition.

Write helper `0x0041b190` checks the relative offset plus the length against the
configured limit. It also requires the absolute end to be below the flash capacity
minus `0x1000`. The flash capacity is found at runtime. The helper erases 4 KiB
sectors through ROM `0x00106e06` and writes through `0x00107212` with peripheral
base `0x51000000`. A ROM device-ID routine gives the flash capacity. The capacity
and protection of the installed chip were not measured. The staging constants alone
do not give a complete physical partition map.

Read helper `0x0041b164` applies the matching relative limit before it calls the
physical read helper `0x0041c1c0`. That helper checks the dynamic capacity and reads
in chunks of up to 256 bytes. The ROM implementations are not available.

## Verification, application callbacks and boot boundary

Worker `0x0041b3f0`, state 3, parses the tag, certificates and signature through
`0x0041ab10`. Then it does three signature verifications with the wrapper
`0x00419534` / `0x0041c768`:

1. Root to server.
2. Server to developer.
3. The image/tag signature.

Literal `0x0041b6d8` selects the compiled P-256 public point at `0x00424f20`. The
real signed artifact was verified offline against this chain, and the chain is
consistent. Public keys cannot sign a replacement image.

The earlier caveat about the cached verdict still applies. Byte `0x2000c4b4` starts
as `0x11`. It changes to zero after full success, or to one after a signature
failure. If the parser fails while the cached value is zero, there is a path to
success. In all other cases the image is rejected. This static path was not shown to
allow custom flashing or a bootloader authentication bypass. See the
[state record](findings-state.md) and the
[recovery boundaries](../firmware-boundaries-and-recovery.md). The old state record
says that no signed package was available. That statement is older than the
verified signed artifact listed above.

Function `0x0042165c` registers application event callback `0x00412898` through
`0x0041ae20`. The events are:

- Event 0 sets OTA busy.
- Event 2 logs the last index.
- Event 3 logs the verification result.
- Event 4 logs the switch.
- Event 8 logs the cancellation and requests a restart through the application helper.

For event 3, the numeric result 2 means authentication failure. It does not mean
success. The library state machine controls the switch path. This logging callback
does not.

State 4 waits while DFU context byte `+0x66` is set. Disconnect callback
`0x0041668c` calls `0x0041b7c4`. If the state already waits for the switch, this
clears the byte. The other non-idle states go to cancellation. The switch delay can
count down. Special values have more branches. None of them is a proven boot
recovery mechanism.

Final helper `0x0041c4c0`:

1. Reads the staged bytes from physical `0x7f000` in chunks of 256 bytes or less.
   It reads each chunk twice and compares the two reads. It tries again if the
   comparison fails.
2. Computes a rolling CRC32 and an additional sixteen-bit value through ROM
   `0x0010a6f6`. It compares the CRC32 with the saved transfer value.
3. Calls ROM `0x0010c1a0(0x60, 0x7f000, size, checksum16)`. It reads the stored
   entry through `0x0010c09a` to verify the address, size and checksum.
4. Requests a restart through ROM `0x00105df8` only after those checks.

This is evidence of staging, transfer integrity and boot-record preparation.
**The supplied image does not contain** these items:

- The ROM checksum algorithm.
- The copy or swap behaviour of the bootloader after the restart.
- Additional signature checks.
- Rollback.
- Power-loss handling and boot-failure recovery.

Earlier documents suggested that the bootloader probably checks only CRC16. That
is a hypothesis. It does not come from recovered code.

## Sender-correlation checklist and remaining recovery evidence

| Check | Receiver evidence | What remains |
|---|---|---|
| Endpoint selection | FE95 / 0017 / 0018 registrations match the plugin → native sender trace | Runtime catalog/connection selection and a live capture |
| Control response parser | Sender/receiver agree on wire kind/length, then command/status | Robust malformed-length handling and hardware observations |
| Packetization | Sender count, ACK, missing-piece resend and both sequence layers match | Real link negotiation, timing and interruption behavior |
| Image bytes | Sender copies selected file unchanged; receiver removes only logical index before storing it | Observe actual selected package and transfer on this unit |
| Resume | Both use indexed prefix CRC and restart from index 1 on mismatch | Test saved checkpoints and power interruption on hardware |
| Validation | Certificate/image chain in application and final CRC/readback | Bootloader/ROM authentication and rollback remain unknown |
| Recovery | No proven independent recovery route | Full flash/ROM dump, calibration/binding backup, protected partitions, restore procedure |

A static match of receiver and sender can answer the offline framing question. It
cannot answer the hardware flashing or recovery questions without the independent
evidence above. No generic factory write surface or flash client was added.

## Correlation with the separately traced native Mi Home sender

The companion sender analysis found these items:

- FE95/0017/0018 in `gw0`.
- The indexed logical fragments of the manager.
- The reliable framing in `wt1` / `z71`.
- The parsing of event-kind 1/2 control notifications.

The receiver evidence above agrees with the reported sender frames. This section
records the checks on the receiver side. The APK identity and the exact sender
source locations are in that companion report. They are not part of the firmware
source hashes listed here.

| Sender behavior reported by the companion pass | Receiver confirmation |
|---|---|
| Setup `00 00 00 00 count:u16le` | `0x0041eeb4` accepts zero sequence, opcode zero, package type zero and count; `0x0041f14c(..., type=0)` awaits it |
| Data `piece_index:u16le + slice(logical_index + file_data)` | `0x0041f120` removes the piece index while assembling; `0x0041b274` then removes the separate logical firmware index |
| ACK 1 starts data, ACK 5 requests missing pieces, ACK 0 completes a reliable message | ACK constructor `0x0041f0ac` and assembler `0x0041f14c` emit these states on 0018 |
| Manager advances the logical image only after event-kind 2/status 0 on 0017 | `0x0041b7ec` invokes flash commit/readback `0x0041b274` only after reliable assembly succeeds, then queues kind 2/status 0; reliable ACK 0 alone does not establish flash commit |
| Resume CRC mismatch restarts the file from its first fragment | `0x0041b274` uses seed zero and resets received count whenever logical firmware index is 1; subsequent new indices extend the stored count |
| Command 4 carries little-endian integer 1 | The four bytes are copied into switch-delay storage; worker state 4 treats values below 60 as seconds and starts a `value * 1000` millisecond timer |

**The 512/2048 decision uses the negotiated reliable payload size. It does not use
the ATT MTU directly.** `0x0041ed38` returns the byte at `0x200318dc` as its second
output. Command 2 tests that byte. Below 19 it selects 512 bytes. Otherwise it
selects 2048. Reliable initialization sets the byte to 18, so the default is 512
bytes.

The `0xa4` parameter exchange in `0x00419658` uses local configuration byte
`0x2000c494 + 0x0e = 244`. It subtracts the two-byte piece index and uses the
result, 242 bytes, as its local cap. `0x0041ed80` negotiates and clamps the peer
and local parameters. A change of the Android ATT MTU alone does not prove that the
reliable parameter byte changed. The sender must complete the matching protocol
exchange. Any further MTU clamp in the sender belongs to the native sender analysis.

For command 4 with delay 1, the one-second countdown waits while context byte
`+0x66` is set. If the state is already the switch state, a disconnect clears the
byte. Thus the observed branch is not "verify, then reboot one second later while
still connected". The sequence is:

1. Verify.
2. Wait for the switch gate.
3. Count down the delay.
4. Check the staging integrity and the boot record again.
5. Request a restart.

This image does not show what the ROM or the bootloader does after the restart.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository. The hashes are recorded for reproducibility.
