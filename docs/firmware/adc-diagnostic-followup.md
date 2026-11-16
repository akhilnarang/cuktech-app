# ADC diagnostic follow-up: 0073

Offline audit, 2026-10-14. Raw image SHA-256:
`65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.

AF08 sensor frame byte 8 is not simply a raw ADC count. The wrapper `0x415028` calls
`0x412408(0)`. That function samples ADC channel argument zero two times through
`0x4122c8(0,0)`. It adds the results, calculates the average and scales it.
Then it calls `0x41216c(0, scaled_sample)`.

In the channel-zero conversion, the calibration reference comes from
`0x2000c27c`. The sentinel `0x1fffffff` selects the default at ADC context
`0x2000d224+0xc0`. The original Thumb instructions load the reference into r4.
The shared-register wrapper `0x40557a` uses r4. The usual decompilation does not
show this parameter. If you read only its pseudocode signature, you lose the
calibration term.

The arithmetic agrees with about
`25 + (calibration_reference - scaled_sample) * 1000 / 2048 / 1.824`.
The firmware uses float/double conversions and integer truncation, so this
expression is only an explanation. An emulation of the original instructions
confirmed the exact rounding sequence below on 498 fixtures. Literals that
were checked:

| Address / source | Interpretation in the arithmetic |
|---|---|
| `0x4124bc..0x4124c3` | double 0.8 used in sample scaling |
| helper `0x40520c` | double 1/2048 multiplier |
| `0x412208..0x41220b` | upper double word for 1000 |
| `0x41220c..0x412213` | double 1.824 |
| `0x412214..0x412217` | upper double word for 25 |

`0x41382c` calls the same conversion during `calib_repair_rc_rf_init`.
`0x41390c` samples it again for RC/RF calibration. This includes hysteresis
around 60/70 and a difference threshold of 31. Thus the value is probably an
internal MCU temperature estimate for oscillator/radio compensation. These
callers do not show the physical ADC source or the calibrated Celsius accuracy.

The vendor store truncates the result to one byte. A negative or full-range
value can wrap. No valid range for this field is proved. The value is separate
from the two SC2021 NTC caches and from the AC-sense ADC proxy. The app keeps
the hexadecimal diagnostic byte. The app does not show it as a third Celsius
sensor.

Evidence: `coverage-gaps-followup-20261014/{functions,instructions}.jsonl`.
[AuditCoverageGaps.java](../../scripts/ghidra/AuditCoverageGaps.java) made
these files from a read-only project copy. The coverage tool compares all kept
instruction bytes with the raw image. Sample acquisition uses hardware. There is
no full ADC acquisition emulation and no device measurement. The arithmetic-only
emulation below adds to this static audit. Open items:

1. The physical channel definition.
2. The full source of the calibration value.
3. The live validity and wrap behavior.

## Verification of the original arithmetic and the reported byte

[VerifyAdcConversion.java](../../scripts/ghidra/VerifyAdcConversion.java)
runs `0x41216c(0, scaled_sample)` and its original software arithmetic helpers.
It gives synthetic calibration words at `0x2000c27c` and the fallback context
word at `0x2000d2e4`. Thus it tests the sentinel path and the direct-reference
path separately. The script does not run the acquisition at `0x412408`.

The fixtures used three references (1394/1200/1600), both paths, sampled inputs
0..4095, rounding boundaries and signed outliers. Result: 498 matching results
over 568,066 instruction steps. This fixture set is not a full proof over all
integer inputs.

The model that agreed with all fixtures does these operations in this sequence:

```text
delta = float32(reference) - float32(scaled_sample)
v = float64(delta) * (1 / 2048)
v = v * 1000
v = v / 1.824
v = v + 25
result = trunc_to_signed_int(float32(v))
vendor_byte = result & 255
```

A separate Python script calculated each fixture again with explicit float32
rounding, and got the same results. All 488 executed instruction addresses and
five code/literal windows are the same as the original image bytes. Execution
stops before the outer POP PC at `0x412200`. No ROM or peripheral code runs.

Ghidra 12.1.4 needs an instance-local fixed-Thumb mode-handler workaround. The
script output and the [thermal/capture follow-up](thermal-capture-followup.md)
record this workaround. The expected model does not replace any original
arithmetic.

| Synthetic reference / scaled sample | Full result | Returned vendor byte |
|---|---:|---|
| 1394 / 1352 | 36 | `24` |
| 1394 / 1394 | 25 | `19` |
| 1394 / 1488 | 0 | `00` |
| 1394 / 1494 | -1 | `ff` |
| 1394 / 4095 | -698 | `46` |

The sensor frame from the user contains `24`, decimal 36. This agrees with the
temperature-style conversion and is near the reported NTC values 40/41. The
frame does not return the real reference and sample. The synthetic 36 case does
not prove that the reporting charger had those inputs. The fixtures show that truncation
changes negative or out-of-range results into bytes that look like valid positive
values. Thus the app keeps the raw `0x24`. A calibrated third Celsius reading is
not confirmed.

Local output: `artifacts/firmware/adc-conversion-verification-20261014-verified/`.
Summary SHA-256 `2743458f8d7f203743f0f36d11e24f9e0c1603e7835ac3f7e24bfc14beb1847f`;
cases `9888d7264fce1a70a13291354aa7fa8e00679d922761018a1432bfc1d7648b2d`;
executed instructions `16c538db737fdf95a395c6298a663df86679d654cef39d536890444e13b1c64c`.

## Factory record and exact `0x24` aliases

The [sensor confirmation document](sensor-confirmation-and-monitoring.md)
traces these items:

- The checksummed 192-byte factory record.
- The direct reference at record `+0xb0`.
- The fallback at `+0x98`.
- The default 1394 when no ADC calibration is loaded.

The charger does not return the real reference and sample.

The `--aliases-only` mode runs 16 more fixtures on the original arithmetic.
With synthetic reference 1394, the full results 292, 36, -220 and -476 all give
`0x24`. A separate Python script gets the same result for each fixture. Thus the
byte has more than one possible meaning. This does not claim that those
physical temperatures occurred. Monitoring shows 36 / `0x24`, units not
confirmed. The byte alone cannot give Celsius or the full signed result.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
