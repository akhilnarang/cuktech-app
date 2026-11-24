# How to get and analyse the firmware

This guide shows the full workflow, step by step: download the official
firmware, check it, disassemble it, decompile it and compare two versions. It
is the workflow that made the notes in this directory. Every step is static
analysis. No step connects to the charger or changes it.

Run the commands from `scripts/` with `uv run` (see the
[scripts README](../scripts/README.md)). The commands are for Linux and macOS.
On Windows, use the PowerShell scripts that the step names.

## 1. Download the firmware

You need a Xiaomi account. Xiaomi gives firmware only to a signed-in account,
and only the latest version. Older versions are not available from Xiaomi.
The old CDN links in [firmware-research.md](firmware-research.md) return
HTTP 403.

```bash
cd scripts
uv run -m cuktech_pc.firmware login --address AA:BB:CC:DD:EE:FF --region cn
uv run -m cuktech_pc.firmware fetch            # signed package
uv run -m cuktech_pc.firmware fetch --legacy   # raw image
```

- `login` asks for the password and for a captcha or a 2FA code if Xiaomi asks
  for one. Type them in the terminal. The password is not saved.
- Use the region where the charger is registered. Chargers for the China
  market usually use `cn`.
- The session is saved, so the next `fetch` needs no login:
  - Linux and macOS: `~/.cuktech_pc/firmware-session.json`, mode 0600.
  - Windows: `scripts/.private/xiaomi-session.dpapi`, encrypted with DPAPI.
- `forget-login` deletes the cloud credentials. If Xiaomi expires the session,
  run `login` again.
- Files go to `artifacts/firmware/`, for example
  `njcuk.fitting.ad1204-2.1.2_0079-signed.bin`. Git ignores this directory.
  Do not commit firmware.

If the app removed the charger from the account after the bind, `login` still
saves the session. Then only `fetch --legacy` works, because Xiaomi offers the
raw image by model. The signed package needs the charger on the account.

## 2. Check the file

`fetch` checks Xiaomi's MD5. For the signed package, it also checks the
developer and image signatures against the pinned Mijia root key. To check a
file that you got from a different source:

```bash
sha256sum FILE
uv run -m cuktech_pc.firmware inspect FILE
```

Compare the SHA-256 with the values in
[firmware-research.md](firmware-research.md) (0073) and
[diff-0079.md](firmware/diff-0079.md) (0079). `inspect` verifies the
signatures of a signed package.

The signed package is the raw image plus a trailer of about 1,340 bytes (tag,
certificates and signature). Thus addresses and offsets are the same in both
files.

## 3. Know the image layout

| Item | Value |
|---|---|
| CPU | OnMicro OM6621Px, Arm Cortex-M4, Thumb-2, little-endian |
| Flash load address | `0x403000` |
| File offset | address − `0x403000` |
| Vector table | offset 0: initial SP, then reset vector (`0x403059` in 0073 and 0079) |
| RAM | startup code copies and decompresses data to `0x200000` and `0x20000000`+ |

The image header also contains `0x00403000` at offset `0x24`.

In a disassembler, load the file as raw binary, Arm little-endian Cortex
(Thumb), at base `0x403000`. If you load it at base 0, every address in these
notes is 0x403000 higher than in your tool. For example, the note address
`0x4203B4` is `ROM:0001D3B4` in an IDA database with base 0.

## 4. Disassemble a few instructions

To check one address quickly, use `tools/thumb_disasm.py`. It uses
[capstone](https://www.capstone-engine.org/), which `uv` gets for this run only:

```bash
uv run --with capstone python tools/thumb_disasm.py FILE 4203b4 4
```

On the 0079 image, this shows the start of the AF07 command dispatcher:

```text
0x4203b4  48 88         ldrh r0, [r1, #2]
0x4203b6  09 28         cmp r0, #9
0x4203b8  c0 f0 b4 80   blo.w #0x420524
0x4203bc  10 b5         push {r4, lr}
```

The arguments are the file, the address in hex and the number of
instructions.

## 5. Unpack the image

The unpacker decompresses the startup data, and extracts fonts, color images
and the remaining slices. It writes a manifest and an HTML index.

```bash
uv run -m cuktech_pc.firmware_unpack FILE --output ../artifacts/firmware/unpacked-0079 --assets --verify
```

`--verify` checks the signatures of a signed package. See the
[extractor guide](firmware-extractor.md).

## 6. Decompile with Ghidra

You need Ghidra 12 and a JDK 21 or later.

For 0073, the scripts in `scripts/ghidra/` do the full pipeline: unpack,
import, rebuild the startup memory, repair the dispatch tables, export
pseudocode and verify the decompressor. The output directory must be new.

```bash
ghidra/analyze-firmware.sh FILE ../artifacts/firmware/ghidra-0073 /path/to/ghidra --assets
```

On Windows, use `scripts/ghidra/analyze-firmware.ps1`. The outputs are:

- `project/`: open it in the Ghidra GUI.
- `analysis/functions.jsonl`: every function with body, pseudocode, calls and
  references.
- `analysis/decompiled.c`: all pseudocode in one file. It is not original or
  compilable source.

To search the export, use the [evidence lookup CLI](firmware-evidence-cli.md).
For the focused audit scripts, see the [Ghidra README](../scripts/ghidra/README.md).

The shell script was tested on Linux. The pipeline scripts check the 0073 image hash and use measured 0073
addresses. For a different version, import the file without them:

```bash
/path/to/ghidra/support/analyzeHeadless PROJECT_DIR AD1204_0079 \
    -import FILE -loader BinaryLoader -loader-baseAddr 0x00403000 -processor ARM:LE:32:Cortex
```

Then open the project in the Ghidra GUI. This import does not rebuild the
startup memory, so references to RAM have no data.

## 7. Compare two versions

[diff-0079.md](firmware/diff-0079.md) compares 0079 with 0073. The method:

1. Import both images with the same steps. Export the functions of each.
2. Match the functions between the versions. Code moves, so do not match by
   address. Match by byte sequences that occur only one time in each image,
   then by calls and by similar code.
3. Compare matched functions after you remove branch targets and pointers.
   Put each function in one group: same, moved, changed, new or removed.
4. Read every changed function and record what its behaviour does now.
5. Check each important claim at the byte level with a second, independent
   reader. Tools such as step 4 make this fast.

The match and diff tools for 0079 were made for that one comparison. They are
not in this repository.

## 8. The Mi Home app and plugin

The official app and its charger plugin show how Xiaomi talks to the charger.
The repository does not include them. Get your own copy.

- APK: decompile it with [JADX](https://github.com/skylot/jadx). On Windows,
  `scripts/analyze-mihome.ps1` runs JADX and writes a receipt. See the
  [APK analysis record](firmware/mihome-cn-apk-analysis.md).
- Plugin: extract the JavaScript modules from its RAM bundle with
  `uv run -m cuktech_pc.ram_bundle main.bundle --output NEW_DIR`. See the
  [plugin notes](firmware/mihome-charger-plugin.md).

## 9. Record what you find

Put a new finding in the matching document from the [index](README.md). Name
the firmware version, and the address or capture that shows the finding. Mark
guesses as unresolved.
