# Protocol settling, cached power and the UFCS control byte

2026-10-16, stage 28. Target firmware `2.1.2_0073`, raw
SHA-256 `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`,
base `0x00403000`. This document continues the
[controller-field trace](controller-field-consumers.md). It is offline analysis
only. There was no charger, BLE, cloud, controller bus or firmware operation.
App 0.7.1 does not change.

The result is policy and reporting behavior. It is not a new protocol unlock.
The host does these steps:

1. It checks complete protocol records for changes.
2. It settles with a continuity check that uses only the enum.
3. It uses the cached power before it commits the latest record.

The encoding of `mUFCSCtrl` is not known. No supported tuning route was found.

## `mUFCSCtrl`: a host default with no setting

The desired HUSB command-0x81 byte 3 is at `0x2000cf3d` / `0x2000cf42`.
Initializer `0x4093cc` writes 0x3c to both at `0x409444` / `0x409442`.
The other annotated references are reads in reconciler `0x40a5f4`.
The reviewed protocol helpers change the named enable/disable bits of byte 1.
They do not set byte 3. The existing initializer verification also makes sure
that protocol-bit updates do not change unrelated context bytes.

The limited alias inventory keeps 31 aligned raw literals for the common base
`0x2000cf28`. It keeps two for the C1 profile base `0x2000cf3a` and one for the
C2 base `0x2000cf3f`, with their annotated users. In these routes, no other
producer or MIOT/AF setting for byte 3 was found. This does not exclude
computed aliases, missing ROM or writes in the secondary firmware.

The verification of the original reconciler confirms these actions:

| Scripted input | Host action |
| --- | --- |
| Configuration read fails | No write or settling-reset callback |
| All compared bytes equal | No write |
| Only byte 2 / HPower differs | No write |
| Only byte 3 / mUFCSCtrl differs | Sends all four desired profile bytes |
| Byte 0 or byte 1 differs | Sends all four desired profile bytes |
| A write is requested while internal state is nonzero | Calls the existing settling-reset helper |

The desired profile and context do not change. This is a reconciliation
mechanism. It does not give the encoding of the byte. It is not known if the
value 60 is watts, current, voltage or temperature. No control for this byte was
added to the app. The synthetic test values that are not the default are not supported
settings.

## Host settling uses two different comparisons

The internal state byte is `0x2000cf22 + port`. The shared u16 counter is
`0x2000cf44 + port*2`. The state numbers 0/1/2 are host bookkeeping. They are
not USB charging protocol identifiers. The checked transitions follow
`0x40a81c–0x40a82a` and the out-of-line branches `0x40a89a–0x40a902`:

| Current input / state | Decision |
| --- | --- |
| Native enum 3–6 | Requests state 2 immediately |
| Enum zero | Increments the shared counter; at >=20 requests state 0 |
| Other nonzero enum, state 0 | Enters state 1 |
| Other nonzero enum, state 1 | Increments counter only if enum equals the previously cached enum; otherwise resets it to zero; at >=30 requests state 2 |
| Other nonzero enum, state 2 | Compares all six cached/current bytes; any difference requests state 1 |

The six-byte record contains five controller data bytes and a checksum. A
change of the power detail, the vendor-ID byte or the cable byte can cause an
exit from state 2, also when the enum does not change. But in state 1, more
metadata changes do not reset the counter if the enum does not change. Thus
state 2 does not prove that all metadata was stable for 30 samples.

The metadata fixtures calculate the checksum again after each data byte change.
The fixtures do not claim a physically valid change of only the checksum. The
zero-record fixtures model the zero-initialized local record of the polling
worker, with its inactive path. They are not checked all-zero bus replies.

### The zero/settling counter is shared

The "twenty zero samples" limit is correct only when the counter starts at zero.
A synthetic state-1 fixture that starts at counter 29 goes to state 0 on its
first zero input. The reason is that the same counter is incremented and
compared with 20. Real transitions reset the counter through `0x409c1c`. Failed
bus reads do not execute this block, as the
[previous worker verification](controller-field-consumers.md) shows. Thus the
limit is not a general cable-disconnect duration.

Scheduler `0x409728` starts work only after at least 21 timer units. It adds 20
to its reference and rotates C1/C2/SC work. No sample threshold here is
converted to seconds or milliseconds. The ordinary activity reports and the
nonzero host state of the allocator can show different stages of that transition
for a short time.

## Power policy uses the previous cached record

The small helper `0x4053ac` is not an empty function, although the canonical C
output shows it as empty. Its original instructions use the live r4/r8 registers
of the caller and give:

- r0 = port;
- r1 = 10 × previously cached protocol-detail byte;
- r2 = previously cached native protocol enum.

`0x409c1c` uses that snapshot when it updates power through `0x409d08`. Later,
the worker commits the latest record through `0x405e5c` at `0x40a854`. Thus the
power/protocol snapshot of the transition can be older than the packet that was
read and published. The multiplier describes the internal value of the host. It
does not prove general watt units or PDO/APDO meanings for each enum.

One verified pair of boundary fixtures starts with cached `07·1e` and reads
`03·28`. The immediate state-2 transition still stores internal power 300 and
protocol 7. Then it commits the new packet. A next consistent boundary with
`03·28` cached updates power to 400 and protocol to 3. These are two fixtures
with explicit initial values. They are not a captured hardware timeline of two
polls.

Entry into state 1 from state 0 sets internal power to 100 and keeps the prior
reduction byte. Entry into state 1 from state 2 keeps the prior power and
reduction. State 0 clears power and reduction. It does not have to clear the
protocol byte, which is stored separately. Thus, for diagnostics, keep the UI
protocol, the measured output and the allocation-policy state separate.

## Reduction classes are not charging protocol names

In state 2, `0x409d08` uses table `0x409d7c` with mask 0x7bf:

| Native enum input | Stored reduction class |
| --- | --- |
| 0, 1, 2 | 5 |
| 3, 4, 5 | 4 |
| 6 | **Retains previous class**; table entry is deliberately skipped by mask |
| 7 | 1 |
| 8 | 3 |
| 9 | 2 |
| 10 | 8 |
| >10 | Retains previous class |

The internal power value and the stored enum can change when the reduction
class does not change. The verifier runs the original instructions for all 256
input enums on both ports. This includes synthetic values that were not
observed from a controller. The result confirms that the host treats 8 and 9 differently. It does not
prove that enum 9 is miPPS, and it does not identify a negotiated wire protocol.

The updater at `0x405e5c` also treats state 1 differently. In state 1, a changed
cached record sets a per-port pending byte. In other states, it sets immediate
update flag bits. This is one more limit on report timing. It is not evidence of
a lost update or of a physical charging fault on a charger.

## SC cache tail: bytes set to zero at startup with no known producer

Startup descriptor `0x403120–0x40312f` selects the zero-fill destination
`0x2000c5f8`, size `0x3ae74`, handler `0x4030d0`. That range includes
`0x2000ce94/95`. The normal SC parser writes protocol/protection at `ce90..93`.
No producer for the last two bytes was found.

Getter `0x4158d8` copies all six bytes. But the two checked report callers
(`0x409f82`, `0x409fd8`) use only the first two protocol bytes. They ignore the
copied protection bytes and the tail. The real callback starts at `0x409f38` and
has out-of-line code up to `0x40a160`. Before, Ghidra merged it into the
unrelated canonical entry `0x40a1f0`. The read-only export has the repaired
boundary.

Direct references show only the tail read of the getter at `0x4158da`. The
limited review of raw base literals finds eleven `ce70` pointers and one `ce7d`. It
finds no new tail writer that overlaps. The expanded startup data adds no
pointer into `ce70..95`. These bytes are a copied tail that startup sets to
zero. No producer and no downstream field consumer is known. They are not a
different sensor. This result does not cover computed aliases, missing ROM or
unknown code.

## Verification and reproducibility

[VerifyHusbSettling.java](../../scripts/ghidra/VerifyHusbSettling.java) passes
560 fixtures / 20,906 original instruction steps. Its 209 distinct executed
records agree byte for byte. There are 48 settling/updater boundary fixtures and
512 reduction-enum fixtures. The original state, snapshot, comparison, power and
cache-update helpers execute. Exact equality replaces the six-byte memcmp body.
Explicit stubs replace the loggers, the delay and the insertion timestamp. The
updater runs separately after the transition block, in worker order. The
verifier does not emulate the full worker, the scheduler, the allocator, the
peripherals or a sequential multi-poll timeline.

[VerifyHusbControlByte.java](../../scripts/ghidra/VerifyHusbControlByte.java)
passes 108 fixtures / 3,582 original steps, with 59 byte-matched executed
records. The fixtures cover both ports, three synthetic desired byte values,
six reply profiles and three host states. Stubs replace the bus/checksum,
logger, writer and settling-reset bodies. The verifier checks the complete
written payload and the guarded desired context. A first fixture run used an
incorrect synthetic state address and stopped after nine cases. That run is kept
separately and is not successful evidence. The completed run uses
`0x2000cf22+port`. The real literal/base offset confirms this address.

Both verifiers use the known instance-local fixed-Thumb emulator adaptation.
This adaptation does not change the original instructions or p-code. The
[verification summaries](control-settling-verification-0073.json) keep the
assumptions, synthetic inputs and exclusions. There is no claim of charger
traffic or of physical protocol negotiation.

[AuditControlSettling.java](../../scripts/ghidra/AuditControlSettling.java)
keeps 19 exact functions / 608 byte-matched instruction records. It also keeps
field references, aligned-literal users and original tables. The original
startup and snapshot-helper instructions give their meanings. Incomplete
decompiler signatures are not a source. The read-only project changes were
discarded.

| Local artifact under `artifacts/firmware/` | SHA-256 |
| --- | --- |
| `control-settling-audit-20261016-complete/functions.jsonl` | `4aeb27f8c5824d7eaf35e9ebc850ee8522a852d83adef74af09aef08e40b92c8` |
| Its `instructions.jsonl` | `af021114419caa91806f3b359bb4e3f96a1c35a4be944f06f11d942f53a57ce7` |
| Its `analysis.json` | `9b2bc6bf9b31d0a866e47e1ba3fe0e76072551006c310c7b013ac596a54531f3` |
| `husb-settling-verification-20261016/verification.json` | `2fb59ef96bc971a8b92c85be4a02e0a348fb000b2c60cd3cc6ba470e9e1eb1e5` |
| `husb-control-byte-verification-20261016-corrected/verification.json` | `0c34718fa418246fc14335c1b7163b61624dcf8cfad0bb22baf5354598333a9b` |

To repeat the results, do these steps:

1. Use the previous reconstructed project.
2. Run the three scripts with the `-readOnly -noanalysis` invocation in the
   [controller guide](secondary-controller-followup.md). Use new output
   directories.
3. Check the result metadata and the script-error logs.

| Question | Result | Remaining boundary |
| --- | --- | --- |
| Can mUFCSCtrl be tuned through a recovered host setting? | No route found; default/reconciliation confirmed | Encoding, computed/ROM writes and secondary-controller definition |
| What makes protocol state settle? | Two comparisons and shared counter verified | Real timing and behaviour under actual attachment/metadata changes |
| Can policy use older power than the displayed protocol record? | Previous-cache ordering established | Actual full-device scheduling and observed lag |
| Do SC tail bytes expose more telemetry? | No producer/consumer found; startup zero-fill and ignored caller bytes mapped | Remaining aliases and controller definitions |

There is no new app control, protocol rename or APK. The unrelated app and tool
unit suites were not run again. The validation runs the original firmware
paths, and it checks the field maps, the kept bytes and the documentation links.
Git does not contain the generated firmware evidence or the vendor binaries.

> NOTE: Paths under `artifacts/` refer to local files that git ignores. These
> files are downloaded vendor packages and outputs that the tools in `scripts/`
> make again. They are not part of this repository. The hashes let you
> reproduce the results.
