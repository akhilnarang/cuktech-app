# Vendor status replies: AD1204U 2.1.2_0073

Date: 2026-10-14. This document is an offline map of the downloaded
`njcuk.fitting.ad1204` image, raw SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
No request in this document was sent to hardware. The later
[capture from the user](thermal-capture-followup.md) agrees with the mapped
layouts for selectors 1, 2 and 6. Physical calibration and capture timing are not
known.

The addresses refer to the Ghidra raw import and the reconstructed startup regions.
The installed Capstone decoded the raw Thumb instructions separately. This check
covered the stores, header constants, length and callees of each reply.

## Transport and query consequences

Service `AF00`, write characteristic `AF07`, notify characteristic `AF08`.
Application receive handler `0x0041fdc4` checks these conditions:

- Request bytes 0..2 are `fe dc ba`.
- The packet length is greater than six.
- The operation at byte 4 is `f1`.

It then dispatches on byte 6. Group 1 also selects on byte 7. The offsets below
count from the first `fe`, and they start at zero. All integers marked LE are
little endian.

Encoder `0x00414288` builds `fe dc ba + payload + ef`. The payload lengths are
exact at the identified call sites. The version reply is different from the other
replies. It has a three-byte payload selector and no length marker. Do not use one
common length-marker parser for every reply.

**Every accepted vendor request pauses the normal MIOT cache updates.** The common
entry calls `0x004050d0(0)`. This sets `0x2000c9ba=1` and clears pending
notifications. Then `0x004043ac` returns early. A disconnect clears the flag at
`0x00416608`. After a manual query, reconnect before you show ordinary telemetry
as current again. Queries can read internal buses and run an ADC conversion. Thus
they can have hardware side effects.

The selectors in this document do not call the persistent setting writers, port
power setters, reset/unbind, restart or DFU entry. This result applies only to the
recovered local callees. The ROM implementations and live operation are not
verified. An app must send only these exact selector frames. Adjacent selector
values include write operations. Do not offer them as a free command input.

| Read request, complete hex | Reply bytes | Handler | Additional activity |
|---|---:|---|---|
| `fe dc ba 01 f1 00 01 01` | 21 | `0x0041cae4` | Reads both HUSB362 version records; may query boot-record CRC through ROM |
| `fe dc ba 01 f1 00 01 02` | 18 | `0x0041c910` | Runs ADC diagnostic conversion; returns cached sensor/control state |
| `fe dc ba 01 f1 00 01 03` | 9 | `0x0041c988` | Reads binding/configuration state |
| `fe dc ba 01 f1 00 01 06` | 18 | `0x0041c9b4` | Logs three SC2021 register reads; returns cached port state/protocol bytes |
| `fe dc ba 01 f1 00 02 00` | 24 | `0x0041c888` | ADC conversion, boot-record CRC, and cached version/control state |

Group 2 ignores the last selector byte in this handler. The constant eight-byte
request above prevents a short packet.

Firmware 2.1.2_0079 drops AF07 writes shorter than 9 bytes. Thus the app adds a ninth
byte `00` to the read requests above. The 0073 handlers do not read this byte. See
[diff-0079.md](diff-0079.md). AF08 fragmentation is not confirmed on
hardware. A 21-byte value needs an ATT MTU of at least 24. A 24-byte value needs
an MTU of at least 27. The two 18-byte replies fit in the default MTU of 23. Until
the behaviour of the live stack is known, do not assume that the larger replies
arrive complete at the default MTU.

## Short sensor/control status: group 1, selector 2

Exact 18-byte reply:

```text
fe dc ba 01 f1 02 0a T2 AD VL VH R P T1 D G U ef
```

| Frame offset | Width | Observed source/meaning | Interpretation boundary |
|---:|---:|---|---|
| 0..2 | 3 | `fe dc ba` | Envelope |
| 3..6 | 4 | `01 f1 02 0a` | Response selector and ten-byte data marker |
| 7 | 1 | `T2`, RAM `0x2000ceb0` | Filtered second NTC conversion; used as shell-temperature input in thermal code |
| 8 | 1 | `AD`, low byte of `0x00415028()` | ADC diagnostic result; physical units/channel interpretation unresolved |
| 9..10 | 2 | `VL VH`, LE RAM `0x2000ec40` | Cached ADC value logged as `vac_vol:%d mv`; a sensed proxy, not direct mains AC voltage |
| 11 | 1 | `R`, RAM `0x2000eb66` | AC/DC rail state: 0 logs 9 V; 1 logs 16 V; 2 logs 22 V |
| 12 | 1 | `P`, RAM `0x2000eb65` | PFC high-state flag; the code logs `PFC High++` when set |
| 13 | 1 | `T1`, RAM `0x2000ce7d` | Filtered first NTC conversion; used by SC2021 overtemperature protection |
| 14 | 1 | `D`, `0x0040488c()` | True only when binding getter reports unbound **and** the twelve-byte settings record equals defaults |
| 15 | 1 | `G`, `0x00417d60()` / RAM `0x2000eb7d` | Hardware-derived `isGlobalVersion` flag; not cloud account region or AC input range |
| 16 | 1 | `U`, `0x004047cc()` / RAM `0x2000eb76` | Persistent Holiday startup-artwork flag; traced to the boot renderer in the display follow-up |
| 17 | 1 | `ef` | Terminator |

The NTC path at `0x00415670` reads seventeen bytes from SC2021 at address byte
`0x42`, register `0x10`. CRC routine `0x004146bc` uses polynomial `0x31`,
initial value `0xa5`, MSB-first shifting and a final byte truncation. It checks
fifteen data bytes against reply byte 15. Byte 16 is outside that checksum
comparison.

Lookup helper `0x0041503c` converts the two raw NTC values. Its tables start at
`0x00424f98` / `0x00425016`, and the offsets are 63 / 24 for the two
measurement-current modes. Each call changes the filtered value by five
temperature units or less. The table and the thermal labels strongly suggest
Celsius. But the value is not a calibrated measurement of the physical sensor or
surface. A zero at startup means "not available". It does not mean 0 degrees.

The overtemperature path of the first NTC enters protection when the filtered
value is at least 115 for ten qualifying calls. It clears below 100. These are
firmware units and conditions. They are not a recommendation to change limits.
This reply does **not** include the protection-state byte. Do not label a high
temperature or a rail state as a reported fault flag.

Function `0x00415028` delegates to ADC/calibration code `0x00412408(0)`. It
narrows the returned value to eight bits. Function `0x00405420` is called at the
start of this reply. In this build it is an empty function. It is not a refresh
routine.

The [ADC follow-up](adc-diagnostic-followup.md) traces the calibration, the
scaling and the RC/RF consumers. The byte is a candidate for an
internal-temperature-style conversion. It is not a simple raw ADC count. The physical units and validity are
not confirmed, so the app keeps the byte raw. The arithmetic conversion matches 498
original-code emulation fixtures. Negative or out-of-range results can wrap into
positive bytes that look correct. This is arithmetic evidence only. It does not
show a calibrated third sensor. The
[sensor confirmation document](sensor-confirmation-and-monitoring.md) traces the
factory and default references. It verifies that the full values 292/36/-220/-476
all send `0x24`.

The rail and PFC fields are **control settings**. They are not independent
electrical feedback. The app records a timestamp for each received reply. Most of
the packet is cached data. Do not promise that all fields come from one atomic
snapshot.

`isGlobalVersion` comes from `0x0041e5c4`. The log of that function names the flag.
It reads a ROM GPIO function with mask `0x100` and stores the inverted low bit. The
physical pad and the product-variant strap are not mapped. A change of the Xiaomi
account region cannot change this byte, because it comes from the hardware.

## Port/controller status: group 1, selector 6

Exact 18-byte reply:

```text
fe dc ba 01 f1 06 0a C1 C2 C3 A P10 P11 P20 P21 S3 SA ef
```

| Frame offset | Width | Source | Safe app description |
|---:|---:|---|---|
| 7 | 1 | RAM `0x2000cf3a` | C1 assigned power-cap code |
| 8 | 1 | RAM `0x2000cf3f` | C2 assigned power-cap code |
| 9 | 1 | RAM `0x2000ceac` | C3 assigned power-cap code |
| 10 | 1 | RAM `0x2000ceab` | USB-A assigned power-cap code |
| 11..12 | 2 | First two bytes of C1 record at RAM `0x2000c998` | C1 raw native controller protocol/detail pair |
| 13..14 | 2 | First two bytes of C2 record at RAM `0x2000c99e` | C2 raw native controller protocol/detail pair |
| 15 | 1 | `0x00415170()`, SC2021 context offset `0x20` | C3 native SC2021 protocol code |
| 16 | 1 | `0x00415168()`, SC2021 context offset `0x21` | USB-A native SC2021 protocol code |
| 17 | 1 | `ef` | Terminator |

Function `0x004093ac` uses exactly the four allocation pointers at offsets 7..10
to return the current allocation value of each port. C1/C2 power-mode code
`0x0040a5f4` writes these cap codes to controller register `0x81`. The C3/A
allocation path translates its cap code for SC2021. These values are not live
measurements of volts, amperes or watts. Byte zero can have an allocation or
control meaning. Do not use it as an independent "unplugged" indication.

The MIOT packer also uses the C1/C2 protocol records. But the packer can change
`07 0f` to `01 0f`. AF08 gives the raw pair before that change. The C3/A bytes use
the separate SC2021 native namespace. Apply its translation tables at `0x00408fe8` /
`0x00408ff8` before you use a MIOT code label. For example, native `0x0e` becomes
exposed `0x07`. Keep both the native byte and the translated result in diagnostics.

This normalization cannot explain the reported normal C2 `01·0f` and vendor native
`08·3c`. The mapped MIOT packer stops while controller polling can continue. Thus
the values can come from different cache times. The report from the user does not
prove an exact order or bus freshness. See the
[cache trace](thermal-capture-followup.md).

The query calls `0x00415060`. This function reads SC2021 registers `0x0c`, `0x0d`
and `0x0e` and logs the cached close-reason flags. **The firmware does not copy
those register values and close-reason flags into the AF08 payload.** Logs are not
extra remote fields. This reply has no identified per-port fault mask.

## Version reply: group 1, selector 1

The exact reply length is 21 bytes. There is no data-length marker after selector 1.

| Frame offset | Width | Source/meaning |
|---:|---:|---|
| 0..5 | 6 | `fe dc ba 01 f1 01` |
| 6..7 | 2 LE | Local firmware revision `0x004058bc()`, constant `0x0073` in this image |
| 8..9 | 2 LE | Boot-record image CRC from `0x00405834()`, via ROM `0x0010c3ae`; not a bootloader version |
| 10..11 | 2 LE | SC2021 software version, RAM `0x2000174e`; `ffff` may be an uninitialized/unavailable sentinel |
| 12..13 | 2 LE | C1 controller version-record word 1 |
| 14..15 | 2 LE | C1 controller version-record word 2 |
| 16..17 | 2 LE | C2 controller version-record word 1 |
| 18..19 | 2 LE | C2 controller version-record word 2 |
| 20 | 1 | `ef` |

Function `0x00414e9c` reads HUSB362 register/command `0x80`. The read gives six
data bytes plus the controller-bus checksum. For C1 the destination is
`0x2000c60e`. The reply copies four bytes that start at `0x2000c610`, so it drops
the first word. For C2 the read goes into `0x2000c616`, and the copy starts at
`0x2000c618`.

The names and the encoding of the two sent words are not known. They can be boot,
hardware, application or another version. The caller ignores the failure result of
the read helper. Thus a failed bus read can return old cached words. Do not show
zero or all-ones as a valid software version without validation.

This packet does not give a silicon revision or a ROM/bootloader software version.
The static `HS6621C` identity of the main SoC on Xiaomi information UUID `001c`,
command 3, is a different route. It is not one of these version fields. The generic
`001c` command-1 MCU-information path calls stub routines `0x0041c118` (returns
zero) and `0x0041c11c` (returns two for argument zero). Thus this path does not
prove that the firmware discovers a secondary MCU.

## Default/unbound check: group 1, selector 3

Exact nine-byte reply:

```text
fe dc ba 01 f1 03 01 D ef
```

`D` is the same combined condition as short-status offset 14. A false result can
mean a bound device. It can also mean settings that are different from the
twelve-byte defaults. It does not identify a cloud account, and it does not prove
binding by itself.

## Combined status: group 2

Exact 24-byte reply, payload length twenty:

| Frame offset | Width | Meaning |
|---:|---:|---|
| 0..6 | 7 | `fe dc ba 01 f1 00 10` |
| 7..8 | 2 | Fixed bytes `00 05`, purpose not identified |
| 9..10 | 2 LE | Local firmware revision (`0073`) |
| 11..12 | 2 LE | Cached SC2021 software version |
| 13 | 1 | NTC2 / shell-temperature input |
| 14 | 1 | ADC-derived diagnostic byte |
| 15..16 | 2 LE | Cached `vac_vol` ADC proxy, logged millivolts |
| 17 | 1 | AC/DC rail enum |
| 18 | 1 | PFC high-state flag |
| 19..20 | 2 LE | Boot-record image CRC |
| 21..22 | 2 | Fixed bytes `04 05`, purpose not identified |
| 23 | 1 | `ef` |

This reply does not add a second NTC, port voltage or current measurements, a
protection mask or an exact phone identity. The short sensor status plus the
separate version reply are easier to interpret. For this, the app must handle the
MTU and the reconnect behaviour.

## Cosmetic startup-artwork setter, selector 9

The display trace identifies the persistent byte that was "unknown" in earlier
versions of this document. Request `fe dc ba 01 f1 00 01 09 VV` calls `0x0041caac`.

- `VV=00/01` calls `0x00405050`. This updates app-record 4 byte 4 and keeps the
  other bytes.
- Values greater than one skip the writer. The handler only returns the current flag.

Reply: `fe dc ba 01 f1 09 01 HH ef`, exactly nine bytes. `HH` is the returned flag
at frame offset 7. The boot initializer applies this flag to the Holiday graphic
widget. Thus the visible effect needs a reboot after the write.

The app offers only a boolean cosmetic write. It checks the returned flag and then
reconnects. The app does not reboot the charger automatically. Persistence and
appearance are not verified on hardware. See [display tracing](display-and-hidden-features.md)
for the renderer and storage chain.

## What remains to verify

| Pending evidence | What it resolves | Current boundary |
|---|---|---|
| Original BLE traces and remaining selectors 3/combined | Actual transport, MTU behavior and broader reply support | User-supplied complete selector 1/2/6 frames agree with layouts; no original BLE trace |
| Comparison of both NTC bytes with display and external readings | Sensor identity, units, precision, startup validity | Lookup conversion and filtering mapped |
| Physical ADC channel/calibration and live validity | Status byte 8's units and wrap behavior on hardware | Arithmetic-only original-code emulation: 498 matching fixtures; byte truncation aliases results |
| Known controller `0x80` specification or controlled version captures | Names/encoding of the two HUSB362 words | Four bytes returned per controller |
| Controller status/error specification | Decode protocol details and raw allocation values | Native/exposed namespaces separated |
| Manual query followed by disconnect/reconnect | MIOT cache resumes and no settings changed | Disable/reset instruction chain mapped |
| Independent read path for SC2021 close-reason/OTP flags | Real fault diagnostics beyond temperatures | Present internally, absent in mapped AF08 replies |

Related records: [telemetry follow-up](findings-telemetry.md),
[phone/protocol findings](findings-phone.md), [unauthenticated surface](findings-unauth.md).
The machine-readable offsets are in [vendor-status-map.json](vendor-status-map.json).
