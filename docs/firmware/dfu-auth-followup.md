# Optional DFU callbacks and authentication boundary: 0073

Offline audit, 2026-10-14. Raw SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.

The control parser `0x41ae44` handles the optional commands 5 and 6 only if the related
callback pairs are nonzero. The literal at `0x41b130` points to `0x2000eb04`. This is a
four-slot callback table. The worker also uses it through the literal `0x41b6d0`.

| Control | Guard | Compiled transition |
|---|---|---|
| 5 | table slots 0 and 1 both nonzero | worker state 6 |
| 6 | table slots 2 and 3 both nonzero; payload length exactly four | worker state 8, copies supplied data |

The worker `0x41b3f0` calls slot 0 from state 6, slot 2 from the callback branch of state 3,
and slot 3 from state 8. The fragment worker `0x41b7ec` uses slot 1. These are the observed
roles. The evidence is not sufficient to call commands 5 and 6 recovery, rollback or a
custom-image installer.

The numeric references in the full export contain reads of these four slots. They contain no
fixed-address writes. The slots are in BSS, which startup sets to zero. This does not prove
that the slots stay null. A callback registration function, memcpy, a computed pointer,
unrecovered code or the ROM can fill them. Which code fills them, and if they are reachable,
is still an open task. Do not assume that an undocumented command works.

The standard token-login trace gets to authentication state 1. MIOT also accepts state 2.
No code that sets state 2 has been found yet in the kept ordinary authentication paths. This
pass does not treat state 2 as an unauthenticated access method. See [beacon/authentication boundaries](beacons-and-passive-telemetry.md).

The cached DFU verdict and the signature/parser paths are static findings. This callback audit
does not show a recoverable custom-firmware route. A valid signed package also does not show
one. Boot-ROM acceptance, storage preservation and restoration are not verified. No OTA control
or flash operation was done.

## Command 7: request a fresh resume CRC

The control handler `0x0041ae44` decodes the one-byte option of command 7. The low two bits
must be `01` (`option & 3 == 1`) to set a DFU-context flag. Then the next command 3 resume
query reads the saved progress record. It calculates the CRC32 again from staging flash, over
the byte count in that record. Then it returns the index and CRC. Without the flag, command 3
uses the stored record value directly.

Command 1 clears the flag. Command 3 does not clear it in the inspected path. Thus the flag
stays set until command 1 or a context reinitialization clears it. Each repeated command 3
request can read staging again. Values with low two bits other than `01` do not request the
new calculation.

Thus command 7 controls a stateful resume-integrity behavior. It is not a charging-mode
toggle, an arbitrary flash writer or a safe telemetry getter. Command 3 also starts the DFU
transfer state. Command 4 later deletes the saved record, as the OTA reports describe. The
generic Mi Home sender trace has no command-7 call in its normal OTA sequence. No command was
sent to the charger.

Evidence: the original Thumb branch/mask/store at `0x0041aeb4–
0x0041aec4`, the command-1 clear at `0x0041aef6`, and the command-3 flag branch
and staging-read CRC loop at `0x0041af8a–0x0041afd6`. The decompiled view of handler
`0x0041ae44` shows the same control flow across commands. This code calculates the saved
prefix CRC again. It does not authenticate the image. It does not prove that the staged bytes
can boot.

Evidence: the parser, worker and fragment-worker records in the hash-guarded
`coverage-gaps-followup-20261014` export, and parser instructions checked against the raw
image. The vendor entry `0x41fdc4` is not an exact function in this project copy. It is
recorded as missing, and its containing function was not used in its place. Earlier vendor
evidence is kept separate.
