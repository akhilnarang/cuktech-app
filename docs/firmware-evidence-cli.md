# Offline firmware evidence lookup

`cuktech_pc.firmware_evidence` indexes the `analysis.json`, `functions.jsonl`
and `strings.jsonl` files that `ExportChargerFirmware.java` makes. It uses the
Python standard library and reads only local files. It does not run firmware,
use the network, use BLE or flash anything.

Run these commands from `scripts`. If you use a different export, change the
analysis directory.

```powershell
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final identity
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final function 00410130
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final strings "BEAST MODE"
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final refs 2000c934
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final refs 2000c934:2000c93b --type WRITE --type READ
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final neighbors 00410130 --direction both --depth 2
```

## Input rules

- Addresses are hexadecimal, with or without `0x`. Ranges include both endpoints.
- `function` accepts an exact entry address or an exact function name. It does
  not guess which function contains an address inside a function.
- String search uses a literal substring and ignores letter case. It does not
  use regular expressions.
- `refs` matches the exported destination address. It does not expand the
  width of a memory operation and does not interpret pointer arithmetic.
- `--type` is an exact filter for the reference type. You can use it more than
  one time. Examples from the export: `READ`, `WRITE`, `DATA`, `PARAM`,
  `UNCONDITIONAL_CALL`.
- Ghidra `Stack[...]` targets stay visible in the original function references.
  Numeric-address searches and graphs do not include them. The response
  identity gives the number of excluded reference occurrences.

## Response identity

Each JSON response includes these items:

- the analyzed program
- the image SHA-256 that Ghidra reports
- the loaded record counts
- separate SHA-256 hashes of the three export files

With this data, you can tell different analysis runs on the same image apart.
The CLI does not open the image again to verify the input hash that Ghidra reports.

## Output limits

Put the common options before the subcommand:

```powershell
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final --limit 10 --offset 10 refs 2000c934:2000c9ff
uv run -m cuktech_pc.firmware_evidence --analysis ../artifacts/firmware/ghidra-final --limit 10 --text-limit 2000 function 00410130
```

- `--limit` sets the number of records in each result array. The default is
  30. The maximum is 200.
- `--offset` pages `refs` and `strings`.
- Function callers and references show only their first bounded page, with the
  totals. To page all incoming references, use `refs FUNCTION_ENTRY`.
- Each string record includes a maximum of 10 references. To page more, use
  `refs STRING_ADDRESS`.
- `--text-limit` limits the decompiled source and the string values. The
  output gives their original length and tells if they were clipped.
- The `callers` array of the export contains all recorded incoming references
  to the entry point. These can include data pointers. For questions about
  calls only, look at the `type` field or use `neighbors`.

## Neighborhoods

Neighborhoods follow only CALL references in the selected direction.

- They do not include data pointers to functions.
- They report callee addresses that are not resolved.
- They stop at `--depth` (default 1, maximum 8) and `--max-nodes` (default 500).
- The flag for search-budget truncation is separate from the flag for
  output-page truncation.
- A graph edge shows an exported static call reference. It does not show that
  the call runs in a specific mode.

## Limits of the evidence

All results are static analysis evidence. These items can be missing: indirect
calls, inferred structure accesses, ROM implementations, functions that Ghidra
did not find, and undefined data.

NOTE: Zero matching references does not prove that a field is not used.

## Tests

Focused tests (they do not need vendor binaries or generated exports):

```powershell
uv run -m unittest tests_firmware.test_evidence -v
```

> NOTE: Paths under `artifacts/` are local files that git ignores. They are
> downloaded vendor packages and outputs that the tools in `scripts/` make
> again. They are not part of this repository. The documents record hashes so
> that you can reproduce the results.
