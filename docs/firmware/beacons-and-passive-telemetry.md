# FE95 beacons and passive telemetry: AD1204U 2.1.2_0073

Date: 2026-10-14. Offline static analysis only. There was no BLE connection,
packet capture, cloud request, hardware access or charger write.

The firmware contains a generic encrypted MiBeacon object encoder. No
application producer that starts this encoder or fills its object queues was
found. Do not add passive temperature, port-power or phone-brand telemetry to
the capability list only because an encoder exists. The ordinary advertising
path shows identity and binding metadata. The encrypted object IDs and their
charger-specific meanings are not known.

## Evidence identity and scope

Analyzed raw image:

- `njcuk.fitting.ad1204-2.1.2_0073-1.bin`, 495,656 bytes.
- SHA-256: `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
- Flash load address `0x00403000`; Thumb/Cortex code.
- Saved `ghidra-final` export: 1,145 functions and 414 strings.
- Export hashes: `analysis.json`
  `77bb30bdf972e24b2419731f0b18471e29b6e42104c19457bfa295a056645f50`;
  `functions.jsonl`
  `eb3415d1a9b8f19f5709bf9c79306244b2674266947724a01e417790e12c9822`;
  `strings.jsonl`
  `5977d9389c01af6de8e6d2c758af972fddfcb60422033165ee9c505185640bf9`.

The routes below come from these saved Ghidra records and from Capstone
disassembly of the original bytes. Automatic reference recovery does not find
indirect or computed accesses, and it does not find ROM code.

## What the object encoder accepts

Encoder `0x0041a4ac` receives a descriptor. The descriptor contains a four-byte
FE95 header, optional MAC and capability fields, a pointer to object
descriptors, and their count. The object pointer is at descriptor offset
`+0x14`. The count is at `+0x18`.

Each input object uses 16 bytes:

| Offset | Field | Encoding established from the encoder |
|---|---|---|
| `+0` | Object ID | Unsigned 16-bit value |
| `+2` | Payload length | Unsigned byte |
| `+3` | Padding/metadata | Not transmitted as part of the object prefix |
| `+4` | Inline payload | Copied verbatim for the declared length |

The serialized plaintext is:

```text
object_id_le16 | payload_length_u8 | payload_bytes
```

The encoder joins multiple objects one after the other. This is generic
framing. It is not a decoded list of the object IDs of this charger. The encoder
does not map IDs to temperature, voltage or phone brands. The upstream producer
must supply those values. No numeric object ID for temperature, power or brand
is known. Object IDs from other Xiaomi devices are speculation for this
charger.

If the object pointer is null, the encoder clears its object and encryption
flags. If the pointer is not null, the encoder requires bit 2 of `0x2000eb64`.
If that bit is clear, it returns error 7. Then it sets frame-control encryption
bit `0x0008` and object-present bit `0x0040`. This check is for the
key-installed state. It is not a check for a currently authenticated BLE
connection. Basic identity advertising does not require a live login.

## Encryption and counter layout

The literal table of the encoder gives these values:

| Flash literal | Value | Role |
|---|---|---|
| `0x41a6c8` | `0x2000eb64` | Beacon/service state flags |
| `0x41a6cc` | `0x20039391` | Upper three bytes of advertisement counter |
| `0x41a6d0` | `0x2000d7ec` | 16-byte beacon AES key |
| `0x41a6d4` | `0x20039390` | 32-bit advertisement counter |
| `0x41a6d8` | `0x2000d7fc` | 12-byte CCM nonce buffer |

Nonce initialization in `0x41a6f8` sets the first six bytes from the device MAC
through `0x41b940`. It sets the next two bytes from the product ID at config
`+8`. During encoding, the encoder writes the low counter byte to nonce `+8`.
It copies the upper three counter bytes to nonce `+9` and adds those three bytes
to the packet.

```text
nonce = device_mac_6_bytes | product_id_le16 | counter_le32
encrypted suffix = encrypted_objects | counter_upper_3_bytes | MIC_4_bytes
AAD = one byte 0x11
```

The encoder calls AES-CCM through `0x004126a4` with nonce length 12 and tag
length 4. The frame header holds the low counter byte at byte 4. The MAC is
optional in the transmitted header. Thus a receiver must know the MAC of the
selected advertiser, also when that field is not in the header. The header
frame-control and the product ID are not encrypted. Do not trust decrypted
plaintext until the MIC check is successful.

For object pointers that are not null, `0x41a4ac` increments the 32-bit counter.
It saves the counter to record 4 at each 512-counter boundary. Key installation
in resume mode loads that record and adds `0x200`. A new registration resets
the counter. These are static observations of the counter code. They do not come
from a captured live packet sequence.

## Producer routes and the missing application wiring

The saved export contains five calls to `0x41a4ac`:

| Caller | Calls | Role |
|---|---|---|
| `0x41a2ec` | `0x41a3de` | Ordinary identity/capability advertising; null object pointer |
| `0x41a880` | `0x41a93c`, `0x41aa24` | Queue worker, plus a metadata-only fallback |
| `0x41d5a8` | `0x41d6e2`, `0x41d73c` | Periodic object-list worker, plus a metadata-only fallback |

The queue worker `0x41a880` removes 16-byte records from queues `0x20031910`
and `0x2003191c`. Then it gives one record to the encoder. The initializer
`0x41a6f8` makes eight-entry queues. The exported references to each queue are
only initialization and dequeue. No enqueue producer was found.

The periodic worker `0x41d5a8` has these conditions:

1. The enable byte at `0x20031c58` is not zero.
2. `(flags & 6) == 4`.
3. DFU is not active, as checked through `0x41b1bc`.

The worker goes through a circular list with its head at `0x20031c50`. It reads
each object ID from node `+8`. Then it calls a payload callback that it reads
from `0x20047468`. The callback receives an object-ID descriptor and pointers to
the payload and length outputs. A payload length of more than 12 stops that
iteration. The worker removes the header MAC when the payload length is more
than three bytes.

Exact references in the saved export:

- `0x20031c58`: three reads, at `0x41a726`, `0x41a9c8`, `0x41d5aa`; zero writes.
- `0x20047468`: one read, at `0x41d626`; zero writes.
- `0x20031c50/54`: initializer `0x41a72c` makes the list head point to itself.
  The worker reads and goes through the list. No application code that adds a
  node was found.
- The little-endian literals in the raw image agree. Each queue address occurs
  two times. The list head occurs two times. The enable byte occurs three times.
  The callback slot occurs one time. None of these five pointer values occurs
  in the 44,744-byte expanded startup data block.

The zero-fill record of the startup scatter table initializes
`0x2000c5f8..0x2004746b`, inclusive. This range includes the enable byte and the
callback slot. Thus both values start at zero under the decoded startup
routine. The hash of the expanded data block is
`bcc38ad1cf76d34fe5a5b7ba91b25ab048655a3418f0fee159fb84bbfbb9299b`.

Inference: this build keeps generic MiBeacon object support, but no charger
application producer for it is known. Limit: no direct references does not
prove that ROM code, computed-address stores or an unknown function cannot fill
it. A passive advertising capture is necessary. The capture must show if real
chargers send encrypted objects during charging, setting changes, connection,
disconnection or another state.

## What our app can use

The 12-byte saved BLE login token is not the 16-byte beacon key. The bind
derivation makes independent slices: token `[0:12]`, bind key `[12:28]`, and
bind-blob key `[28:44]`. A standard BLE login derives connection session keys
from the token and new random values. These session keys are also different from
the beacon key. The bind-key slice needs the original registration ECDH
material. The token alone cannot give the bind key.

The app `BindCrypto`/`BleChargerBinder` calculates a bind key when it binds a
new charger. It gives this key to the legitimate cloud binding call. This shows
where a future app bind flow could keep the user-authorized key securely. This
does not show that the current saved-token login has the existing key. It also
does not show that a beacon decoder exists in the app. Key retrieval for
existing accounts was not tried. This report contains no real keys or tokens.

Practical capability status:

| Passive feature | Status |
|---|---|
| Product identity (`0x660e` for this image), MAC when included, frame counter, binding metadata | Header format established; existing FE95 parser reads it |
| Encrypted object framing and CCM parameters | Static format established; requires separate 16-byte bind key |
| Actual broadcast temperature / per-port voltage/current/power / phone brand | No activated producer or charger-specific object ID established |
| Read connected telemetry | Separate MIOT/vendor paths; see [vendor status map](vendor-status-map.md) |

## Related authenticated-session state

`0x417bc8` reads the session byte at `0x20031782`. A successful standard
token-login HMAC writes 1 at `0x419c64`. A failure does not write a successful
state. Disconnect cleanup `0x41f910`, called by `0x41668c`, writes 0 at
`0x41f914`. The MIOT GATT gate accepts state 1 or 2. OTA requires state 1. No
direct write of 2 was found, and the meaning of state 2 is not known. Do not
describe state 2 as a bypass or as an alternative login mode.

## Remaining work

1. Capture FE95 service data passively on a phone. At the same time, record the
   charging and connection states. Find out if bit `0x0040` occurs.
2. If encrypted objects occur, get the existing bind key of the device through a
   verified legitimate route. Keep the key in the encrypted storage of the app.
   Validate the MICs and compare the object IDs with connected telemetry.
3. If captures show an active producer that the static references did not find,
   examine computed-address and ROM registration.
4. Trace session state 2 separately. The gate accepts the value, but this does
   not show that the firmware can set it.

To repeat the static lookups, run these commands from `scripts`:

```powershell
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final function 0041a4ac
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final --limit 100 refs 20031c50:20031c58
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final refs 20047468
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final refs 20031782
```

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
