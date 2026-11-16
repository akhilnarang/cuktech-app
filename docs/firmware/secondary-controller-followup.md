# Secondary controllers: cache failures, allocation policy and remaining images

The later [field-consumer audit](controller-field-consumers.md) maps the
destination-voltage decisions, the remaining reply bytes and the freshness of the
protocol/protection cache. It also verifies the parser and the worker with the
original instructions.

2026-10-16, stage 26. Target `2.1.2_0073`, raw SHA-256
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`,
495,656 bytes, loaded at `0x00403000`. All findings come from static analysis
or from limited emulation of the original instructions with synthetic bus
results. No physical bus, phone, account, charger setting or firmware was
accessed or changed.

The existing reconstructed Ghidra project was opened read-only. The earlier
[controller](controller-and-assets-followup.md) and
[protocol/blob](protocol-command-blob-followup.md) results are prerequisites.

## Confirmed SC2021 cache/ACK limitations

| Path | Original instructions | What it actually establishes |
| --- | --- | --- |
| Register 0x0e limit setter | `0x41631c–0x416374` | Packs two nibbles, skips an equal cached value, and stores the desired byte even after a failed write |
| Register write retries | `0x415b3c–0x415b74` | Tries at most three low-level writes; returns 0 after exhaustion, 1 on success |
| C3/A UFCS/SCP setter | `0x4158e8–0x41595c` | Updates its desired cache before the write; an identical later request returns 1 without another transaction |
| Port enable setter | `0x415244–0x4152a4` | Writes/readbacks register 0x20, optionally writes again on mismatch, then returns 1 without proving ACK success |

The limit setter ignores the return value of the retry helper at
`0x41634c/0x41636e`. For nonzero settings, it reads register 0x0e and logs both
values. It does not compare them to find success. Both branches go to the cache
store at `0x416372`. Thus the setter caches the request also when the readback
does not agree.

For the protocol setter, the test is a synthetic failure and then the same
request. If the first request changes the cache, the results are 0 and then 1.
The bus-helper call counts are 1 and then 0. The stored disable bits are UFCS
bit 7 and SCP bit 4. The other bits do not change. This is host control flow. It
is not an observed controller fault.

Thus success markers and saved configuration readback cannot prove that the
secondary controller applied a setting. A repeat of the same request is not a
verified repair. The [plugin audit](plugin-feature-audit-20261016.md) found a
separate disagreement between the legacy C1/C2 settings and the per-port
preferences. This SC cache issue is a different limit. It does not show that
all setting writes fail.

### Recovery is still possible, but it is not established as an app command

At `0x4154b8–0x4154fa`, C3 protection bit 7 and a nonzero cached register 0x20
start a direct replay of 20, 0e, 21, 0d, 0c through the stored write function
(`0x415634 → 0x415b3d`). The replay does not use the high-level equality checks.
It also ignores the write results. A changed desired limit also starts a new
write attempt. In these paths, no automatic readback reconciliation for an
unchanged 0x0e was found. Protection replay and real bus failures were not
emulated or caused.

## Original-instruction verification

[VerifyScLimitCache.java](../../scripts/ghidra/VerifyScLimitCache.java) ran
5,394 cases / 155,243 original instruction steps:

- 5,358 limit cases: all 16×16 nibble combinations, selected distinct prior
  bytes, successful and failed writes, and readback profiles that agree or do not
  agree.
- Four retry cases: success on attempt 1, 2 or 3, or failure after three
  attempts.
- 32 protocol cases: both ports, all four UFCS/SCP settings and four prior
  bytes. A second, identical request on the same synthetic context follows each
  case.

All expected results and context guards agree. All 96 distinct executed
instruction records agree with the original raw bytes. The external logger,
delay and bus entry points return scripted results to the real LR. Their bodies
and the peripherals do not execute. The original BL executes, and each fixture
stops before the last POP PC.

The first run failed at the first BL because of the ARM emulator
`setISAMode`/STOPPED issue in Ghidra 12.1.4. The successful run uses the known
instance-local fixed-Thumb callback adaptation. This adaptation refuses ARM
transitions and does not change the original instruction p-code or the
firmware. It records 29,124 callbacks. The first partial directory is kept, but
it is not successful evidence.

The [verification summary](secondary-controller-verification-0073.json) records
the scope and the exclusions. Local complete directory:
`artifacts/firmware/sc-limit-cache-verification-20261016-fixed-thumb/`.
Its `verification.json` SHA-256 is
`c343388560859dd4feddce22d52cd9fc6a79271e70912d04ea700b0ebbd24644`;
`executed-instructions.jsonl` SHA-256 is
`341c5bf18b3f74260db6b085a2806baae4ee548250065344f7c10beadb2da201`.

## Shared C3/A allocation policy

Callback `0x40a498` is different from the canonical merged function at
`0x409e64`. On its USB-A path, `0x40a4f8–0x40a544` selects the packed register
0x0e value from the configured allocation codes of C3/A. The priority order is:

| Condition | Register 0x0e request |
| --- | --- |
| Both are 0x30 (12 W + 12 W) | Logs that combination; leaves the prior limit unchanged |
| Either is 0xa0 (7.5 W) | 0x43 |
| A is 0x60 (22.5 W), C3 is 0x80 (45 W) | 0x01 |
| Otherwise either is 0x60 (22.5 W) | 0x21 |
| Otherwise | 0x00 |

The allocator does not suppress unchanged caps for port 3
(`0x40868c–0x4086a4`). Thus this USB-A callback can run also when its cap does
not change. The equality test of the register helper can still stop a bus write.
The electrical meanings and units of the nibbles are not known. The value 0x43
is not 43 W. This table gives no override for a selected power.

The original cap conversion `0x4093a2 → 0x4092e0` maps 0xa0 to 75 deciwatts =
7.5 W (`0x409334–0x40933a`). It has the same watt label as 0x10. But it has a
different policy role in the table above, so decoding must keep the raw code.

App 0.7.1-experimental / code 31 adds the missing C3/A cap label to ordinary
telemetry and to shared vendor diagnostics. C1/C2 do not use that code space.
There is no new write or control. All 51 Android tests pass. The debug build and
the APK v2 signature verification are successful, with the same debug signer as
0.7.0. APK `cuktech-local-0.7.1-experimental-debug.apk` (local build, not
distributed): 12,882,444 bytes, SHA-256
`ace527b5b12f702c4f864ef1aa09c6338f792d46874a178ccffa473800c12e54`.
This APK was not installed on a phone.

## Bus address and checksum details for future passive captures

The original byte writer `0x4041b4` sends eight bits of its argument directly.
The reconstructed initialized table at `0x2000c2b4` starts with 92 94. These
are wire address bytes. They are not seven-bit analyzer addresses:

| Controller | Firmware write byte | Read byte | Seven-bit I2C address |
| --- | --- | --- | --- |
| C1 HUSB362 | 0x92 | 0x93 | 0x49 |
| C2 HUSB362 | 0x94 | 0x95 | 0x4a |
| SC2021 | 0x42 | 0x43 | 0x21 |

The HUSB checked read `0x403ef0` does these steps:

1. It sends the address and the command.
2. It stops, and then starts the read with `address + 1`.
3. It accepts a last byte equal to
   `(2 * write_address + 1 + command + sum(data)) & 255`.

The request/response lengths are 0x80→6, 0x81→4, 0x82→16, 0x83→5 data bytes.
That checksum follows each response. The checked write `0x403f7c` adds
`(write_address + command + sum(data)) & 255`. The known 0x81/0x85 callers send
four data bytes. The 0x85 route is host revision/CRC metadata.

The bit-banged routines use ROM GPIO masks 0x01000000 for the data line and
0x02000000 for the clock line (`0x4041b4`, `0x404298`, `0x4042c4`). These masks
do not identify physical package pins or accessible board pads. The logic level,
the pad mapping and a captured waveform are not known. Ordinary BLE cannot read
any chosen controller register through these bus helpers.

## Secondary-image search: fewer candidates, no image found

The kept signed package contains one raw payload. A 70-byte tag, a 1,198-byte
certificate bundle and a 71-byte DER signature follow it. This package layout
contains no second controller image. The old RGB565 gap stays closed.

[firmware_data_audit.py](../../scripts/cuktech_pc/firmware_data_audit.py)
makes the full AES S-box independently through GF(2^8) inversion and the affine
transform. It makes the SHA-256 K words through exact integer cube roots of
primes. Both agree with these original intervals. The end offsets are
exclusive:

| Raw file interval | Classification / boundary |
| --- | --- |
| 0x2219c–0x2229c | Exact 256-byte SHA-256 constant table; compression consumer 0x418d50, pointer 0x418e7c→0x42519c |
| 0x22390–0x22490 | Exact 256-byte AES S-box; consumer 0x4126e0, pointer 0x41286c→0x425390 |
| 0x21f98–0x22100 | Contains SC/HUSB lookup data; pointers at 0x415058/5c and 0x414c7c, not a fully classified interval |
| 0x254a0–0x271e8 | 7,496-byte candidate has UI pixel/border consumers 0x40b2e0/0x40b958; not every byte is classified |
| 0x71178–0x734e0 | 9,064-byte mixed interval, including 7,324 printable-string-candidate bytes; no upload consumer identified |

The main-code candidate interval `[0x130,0x21f8c)` has 138,844 bytes. If you
remove the canonical function bodies, 24,952 bytes stay in many small parts.
The largest contiguous gap is only 860 bytes. Eleven gaps are 256 bytes or
more. Thus a large separate image fully outside the known host functions is
less probable. Automated boundaries can be incorrect or can contain data. Thus
this result does not exclude embedded, compressed, encrypted or
other-architecture firmware.

The [data audit report](secondary-data-audit-0073.json) keeps the offsets,
digests and gaps. To repeat it, run this command from `scripts` with a new
report file:

```powershell
uv run -m cuktech_pc.firmware_data_audit ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-1.bin ../artifacts/firmware/ghidra-final --output ../artifacts/firmware/my-data-audit.json
```

All 56 offline firmware-tool tests pass. Git does not contain the generated
vendor content. The committed reports contain metadata and synthetic results.

## Kept source audit and open questions

[AuditSecondaryControllers.java](../../scripts/ghidra/AuditSecondaryControllers.java)
repairs the measured boundaries and the 32-entry cap TBB. It exports 15 exact
functions / 551 byte-matched instruction records. One internal-block request at
0x40868c has no exact function entry. It stays a recorded miss, and its
instruction range is kept. The decompiler warnings about missing ROM stay
visible. The read-only project changes were discarded.

To repeat the audit and the verifier on an existing reconstructed project, use
your local paths and two new evidence directories:

```powershell
& C:/path/to/ghidra/support/analyzeHeadless.bat C:/path/to/project AD1204_0073 `
  -process firmware.bin -readOnly -noanalysis -scriptPath D:/path/to/cuktech-app/scripts/ghidra `
  -postScript AuditSecondaryControllers.java D:/path/to/new-controller-audit `
  -postScript VerifyScLimitCache.java D:/path/to/new-cache-verification
```

Use JDK 21 or later, as the installed Ghidra requires. Check the result JSON and
the script error log. Headless Ghidra can exit with zero after script errors.

Local `secondary-controller-audit-20261016-complete/` SHA-256 identities:

- `functions.jsonl`: `158b8394367faf2a46c0ad1c0a698bcbbfd67108ce1233ae65f74b9db41e889b`.
- `instructions.jsonl`: `a87e93887a42b399ccce8c5509d8e2273e98b7966c8cdcf2ea7063034e5608e9`.
- `analysis.json`: `20014eb7da90cb9f4ba173458b8dff6d36334869941c5454f25420316074408f`.

| Question | State after this pass | Next evidence needed |
| --- | --- | --- |
| Does ACK/saved state guarantee applied settings? | Answered: these SC paths can report/cache requests without proving delivery | Passive capture to establish actual failures and recovery timing |
| How does C3/A sharing choose its limit register? | Producer table recovered; units unresolved | Matching controller register definition or measured electrical behaviour |
| Is there a secondary image in the OTA? | None recovered; crypto/UI/string candidates narrowed | Matching separately supplied controller build, ROM definition or hardware acquisition |
| Can bus details be decoded independently? | Address convention, checksums and host commands mapped | Actual passive capture and physical pad/voltage identification |
| Any new VOOC/miPPS enum proof, thermal override or custom controller flasher? | No | Controller-side definitions or independent negotiation evidence |

More string scans of this same OTA cannot supply the missing controller code.
The next useful evidence is a matching controller build or SDK, or a passive
capture. Guessed BLE commands or new labels do not replace this evidence.

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
