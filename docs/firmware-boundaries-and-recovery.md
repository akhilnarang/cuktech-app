# AD1204U 0073: analysis boundaries and recovery requirements

Updated 2026-10-14. Scope: `njcuk.fitting.ad1204`, firmware
`2.1.2_0073`, raw SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.

Sources: local Ghidra exports, and selected raw Thumb instructions decoded
separately with Capstone. No flash write, erase, hardware UART, Bluetooth
request, cloud login or device reset was done.

## An unpacked OTA does not give a recovery route

The image is executable code and data. It is not an encrypted blob. Its
startup decoder, copied code, expanded data and display assets are recovered.
These items are not recovered:

- the ROM
- the complete physical flash
- the separate PD-controller firmware
- the calibration values
- the account-binding storage
- a reproducible vendor toolchain

Ghidra pseudocode is not original compilable source. The number of found
functions does not give a meaningful completion percentage for the firmware.

The current export records calls to 133 distinct targets in `0x0010xxxx`, from
264 distinct function/target pairs. These are bounded export counts. They do
not fully count indirect branches, tail branches, omitted calls and merged
function bodies. The ROM implementations are not in the OTA file.

## UART findings and electrical boundary

Manufacturing branch `0x0041cf88` runs early in the copied reset continuation
`0x002013bc`. The pin-configuration helper `0x0041d03c` does these calls:

1. ROM `0x0010481c` with `(4,0x1c)`
2. ROM `0x001054d2` with `(0x10,2)`
3. a tail branch to ROM `0x001044f2` with `(0x10,0)`

Then the caller checks ROM `0x0010450a(0x10)`. If the result is nonzero, normal
startup continues. If the result is zero, the code starts initialization,
prints `mp mode` and loops in `0x0020016c`.

The GPIO4/input/pull-up interpretation agrees with the other GPIO-style uses
of these routines. But the ROM bodies and the physical pad/package mapping are
not available. The software mask `0x10` is not a confirmed board pad number.
The [UART record](firmware/findings-uart.md) has more inferred pin identities.
Its `3.3 V TTL` statement is not confirmed by this image and not measured on a
board.

WARNING: Confirm the voltage, ground reference, isolation, pin orientation and
real factory entry before you connect anything. Do not connect a grounded USB
serial adapter to an open charger that is connected to mains power. Use only a
qualified isolated bench setup.

Raw instructions complete two diagnostic initialization tails in `0x0041d104`
that Ghidra truncates:

- ROM `0x00108996` receives the peripheral bases `0x40030000` and
  `0x40040000`, the baud argument `0x1c200` (115200) and a third argument of zero.
- The second call installs the Thumb callback `0x0041d279`.

The argument list does not prove eight data bits, parity or stop bits, because
the ROM default implementation is not available.

The receive callback `0x0041d278` adds bytes to a RAM buffer. It starts a
five-tick timer again each time. The timer callback is `0x0041d1d8`.

- The timer callback checks for `4f` (`O`).
- Then `0x0041d1a0` uses frame byte 1 as the command group and byte 2 as the command.
- The reply helper `0x0041d170` sends `4f 03 command length_lo length_hi data`
  through ROM `0x00108bf2` at peripheral `0x40040000`.

This is a binary manufacturing parser. It is not a demonstrated shell. It is not the
AF07 BLE parser.

| Boundary | Established | Remaining |
|---|---|---|
| Group 1 `35` | Calls ROM `0x00106f14` with address/length when frame byte 13 is 2 | Exact erase primitive semantics and alignment |
| Group 1 `36` | Calls ROM write primitive `0x00107212` with physical address, data and length | Flash permissions, write protection, recovery |
| Group 2 `36` | Calls ROM read primitive `0x00107572` and returns length | Buffer overlap/size behavior; no ROM-memory dump route proved |
| RF commands `17/18/1b/39/3a` | Calibration, test, frequency/trim code present | Live behavior and radio calibration preservation |
| Persistent `3b` | Reads/writes six-byte record | Identity semantics and recovery after change |
| BLE reachability | Separate manufacturing parser registration; normal FE95/AF07 paths do not call it in recovered graph | Computed-pointer completeness and actual board behavior |

The receive and dispatch code in the known paths has no visible length limits.
An offline command map is not a safe UART client for general use.

WARNING: Do not send write, erase, calibration or large read requests during
discovery.

## Power controllers and sensors

C1/C2 controller code identifies HUSB362 explicitly. It uses a GPIO/bus
transaction layer that agrees with bit-banged I2C.

- It reads base information with command `82` and protocol records with `83`.
- Version command `80` returns six bytes before the checksum.

C3/USB-A code identifies SC2021. It reads seventeen bytes at address byte
`42`, register `10`.

- The SC2021 CRC helper `0x004146bc` uses the MSB-first polynomial `31` with
  initial value `a5`, on fifteen bytes.
- `0x00415670` interprets two NTC ADC values and converts them through `0x0041503c`.
- Both filtered converted values go into the shorter vendor BLE status reply:
  NTC2 at frame offset 7, NTC1 at frame offset 13. See the complete
  [vendor status map](firmware/vendor-status-map.md).

The known MIOT service-2 callback has no temperature property. But there is a
separate AF08 status route. This corrects earlier general statements that
there is no temperature reading. The temperature units are probably Celsius
(inferred). The sensor placement and calibration are not measured. The SC2021
protection flags and close-reason registers are internal. The mapped AF08
status replies do not send them.

The generic Xiaomi `001c` command-1 MCU-information path calls the local stub
`0x0041c118`, which returns zero. Then it calls `0x0041c11c(0)`, which returns
two. This does not show an implemented transport for second-controller
information. The real HUSB362/SC2021 bus paths are separate and present. This
one OTA does not give their firmware payloads, full command dictionaries or
update procedures.

## OTA signature verification and the cached verdict

The downloaded signed package contains a tag, two certificates and an ECDSA
image signature. Verification is successful against the compiled root public
point, the server key and the developer key. This corrects the older
[state report](firmware/findings-state.md), which says that no signed package
was available. The signed artifact exists and is verified. The public keys do
not give the private signing key.

The application DFU worker has a conditional fallback. Thus it is not correct
to say that all possible OTA acceptance paths verify a signature:

| Condition in `0x0041b3f0` | Write/read | Observed transition |
|---|---|---|
| Final successful signature verification | `0x0041b75a` writes byte zero to `0x2000c4b4` | Verify success, worker state 4 |
| Signature verification failure | `0x0041b4e8` writes byte one | Authentication failure, state 5 |
| Tag/certificate parser returns nonzero | `0x0041b710` reads the same byte | Zero: success/state 4; one: failure status 2/state 5; other: failure status 6/state 5 |

Expanded startup data sets that byte to `11` hexadecimal (17), at
expanded-region offset `0xad84`. Thus after a new startup, the observed
application branch rejects a parser failure.

- The ordinary DFU init `0x0041b1d0` copies only 24 configuration bytes from
  `0x2000c494`. The verdict byte is at configuration base +32. The init does
  not copy or reset it.
- The control parser `0x0041ae44` also does not reset it.
- The exported references to the byte are only the three in the table above.
- Writes to computed addresses and ROM access are not covered by this result.

Sequence:

- Control commands 2/3 start the transfer state. Command 4 starts the verify
  state. The recovered parser does not check the previous worker state.
- State 4 waits while context byte `+0x66` is nonzero. The disconnect handler
  `0x0041b7c4` clears it if the worker is already in state 4.
- The disconnect handler changes the worker state and context. It does not
  change the verdict byte.

Thus an earlier successful signed verification can leave a cached zero during
the same boot. A later parser failure then has a compiled path to success.
This is a candidate from static analysis of the state machine. It is not a
demonstrated custom-firmware installation or a completed exploit. When the
image startup decoder runs again, it restores the measured initial verdict.

The switch helper `0x0041c4c0` does these steps:

1. It reads the staging area at physical address `0x7f000`.
2. It compares the CRC32 with the stored transfer CRC.
3. It records the address, the size and a second checksum that the ROM
   calculates, through ROM `0x0010c1a0`.
4. It checks the stored record through `0x0010c09a`.
5. It requests a restart.

It is not known if the bootloader (not in the image) does more authentication.
The staging flash capacity comes from a ROM/device-ID routine. It is not the
same as the OTA file length.

The optional DFU callback slots at RAM `0x2000eb04..0x2000eb14` start in BSS.
The mapped command and worker functions read them. The exported references
show no direct registration write. The presence of generic optional commands
does not prove that the production application set these callbacks.

## Open questions and next evidence

| Question | Current answer | Evidence needed next | Dependency |
|---|---|---|---|
| All implemented MIOT controls | Getter/setter/action map bounded to service 2 | Hardware readback of each documented setting | Phone/BLE session with a bound device |
| Beast activation and phone brand classification | Separate UI/protocol pass maps the state producers | Controlled device/protocol captures | Known phones/cables/meters |
| Vendor status and two temperatures | Exact 1/2/3/6 and group-2 reply maps | AF08 capture, units, stale-value and reconnect checks | Phone session; negotiated MTU |
| Fault/protection reporting | Internal OTP/close flags present but absent in mapped status replies | Further callback/bus routes or passive logs | ROM/controller specification |
| Controller firmware/versions | HUSB362 `80` and SC2021 version fields mapped | Firmware payloads/specification; word meanings | Independent shipped controller artifacts |
| ADC proxy/calibration | VAC proxy and diagnostic byte reach AF08 | ADC channel/units, gain/reference chain | ROM and exact register conventions |
| Full UI/render recovery | Assets and renderer code recovered | Every page/button transition and screenshots | Runtime UI evidence |
| Factory UART entry | Binary parser, baud argument, GPIO-style gate | Unpowered board identification and isolated measurements | Qualified hardware access |
| Full flash backup | ROM-backed read primitive exists | Complete read-only dump with checksums and verified bounds | Confirmed safe hardware interface |
| Calibration and binding preservation | Persistent records/code exist | Exact partition/record map and backups | Full flash dump |
| Cached-verdict fallback reachability | Piecewise state/data path mapped; boot value 17 | Offline model/original-instruction checks; then controlled verification | No flashing required for offline step |
| Bootloader/ROM checks | Missing from OTA | Read-only ROM/bootloader artifact and security configuration | Hardware dump or matching official SDK |
| Own firmware installation | No proven complete route | Backup, authentication/debug state and tested recovery | All preceding recovery items |
| Git bisect/version comparison | Only this firmware version is analyzed | Another authenticated, hash-bound firmware version | Legitimate matching OTA artifacts |

This report has no hardware flashing client and no recovery procedure. You can
build useful app controls on the known read/settings map. Hardware-level
write, erase and calibration, and custom image installation, are separate
work. This work needs the evidence in the table.
