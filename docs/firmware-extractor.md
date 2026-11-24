# Extracting AD1204 0073 firmware

The firmware is a plaintext Cortex/Thumb program in a signed Xiaomi OTA
package. Its startup data and graphics use several encodings. It is not a ZIP
archive with the original PNG file names. The extractor decodes the known
formats. It saves the original encoded bytes next to the results.

Run this from `scripts`. Use a new output directory.

```powershell
uv run -m cuktech_pc.firmware_unpack ../artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin --output ../artifacts/firmware/my-extracted-0073 --assets --split-unclassified --verify
```

Then open `index.html` in the output.

- The extractor does not use a cloud login, a Bluetooth connection or hardware.
- Python 3.11+ is sufficient. `--verify` also uses the existing `cryptography`
  dependency.
- For an unsigned or raw image, do not use `--verify`.

| Output | Contents |
|---|---|
| `firmware.bin`, `r2sf-header.bin` | Exact main-image/header slices |
| `xiaomi-tag.bin`, certificates, signature | Exact signed-package components, when present |
| `startup-table.bin`, `load-*.bin` | Startup records, copied SRAM data, compressed and expanded startup blocks; zero-fill regions are described in the manifest |
| `assets.html`, `fonts.json`, `assets/font-*` | Alpha glyph gallery, metadata, raw descriptors/tables, encoded RLE and grayscale PNGs |
| `assets/color/index.html`, `bitmaps.json` | Color gallery and source/decoded hashes |
| `assets/color/bitmap-*` | Raw descriptors, encoded blobs, little-endian RGB565 pixels and opaque RGB PNGs |
| `stream-*.bin`, `stream-*.expanded.bin` | Complete checksummed gzip/zlib streams, if found; none admitted in this image |
| `source-map.json` | Overlapping identified source intervals, source hashes and the complement of their union |
| `unclassified/range-*.bin` | Optional exact remaining slices; can contain executable code, constants, unknown data and padding |
| `strings.json`, `manifest.json` | ASCII candidates, addresses, hashes, startup mapping, signature results and limitations |

## Limits of the extraction

- `--assets` enables the font extraction and the color profile.
- The color extraction works only with the raw-image SHA-256
  `65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1`.
  For a different image, the output says that the color profile is not supported.
- Which descriptors are admitted as fonts is still inferred from sorted packed UTF-8 identifiers and
  valid bounded glyph streams.
- Generated file names show addresses. They are not names from the vendor build system.
- PNG transparency keys, clipping, full screen composition and animations are
  not reconstructed.

## Results on the 0073 image

- The measured signed image gives 2,061 files. These include 51 font
  descriptors, 911 glyphs, 21 color bitmaps and 31 unclassified slices.
- The 21 color streams use exactly the file offsets `[0x4c7aa, 0x5cf08)` /
  67,422 bytes.
- The remaining slices are 167,942 bytes in total. This number is source
  accounting. It is not a measure of code that is not yet examined.
- All 495,656 main-image bytes were reconstructed separately from the exported
  source slices and the remaining chunks. The full `firmware.bin` copy was not
  used in this check. All listed output hashes matched.

The color codec was compared separately with the original renderer at
`0x40e30c`. All 21 real assets and three synthetic edge cases matched over
1,317,250 original instruction steps. Both framebuffer guards stayed intact.
The check does not include the LCD hardware, peripherals, ROM, color-key
transparency or clipping. See [the research record](firmware/controller-and-assets-followup.md).

## Decompiler output

To make decompiler pseudocode and a Ghidra project in the same run, use the
existing workflow from the repository root. On Linux/macOS:

```bash
scripts/ghidra/analyze-firmware.sh artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin \
    artifacts/firmware/my-extracted-and-decompiled-0073 /path/to/ghidra --assets --split-unclassified --verify
```

On Windows:

```powershell
scripts/ghidra/analyze-firmware.ps1 `
  -Image artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin `
  -OutputDirectory artifacts/firmware/my-extracted-and-decompiled-0073 `
  -GhidraHome C:/path/to/ghidra `
  -JavaHome C:/path/to/jdk-21 `
  -Python python `
  -Assets -SplitUnclassified -VerifySignature
```

- The assets are in `unpacked/`.
- `analysis/decompiled.c` and `functions.jsonl` contain pseudocode that you can search.
- `project/AD1204_0073.gpr` is the local project.
- Decompiler output is approximate. It can contain warnings and merged
  functions. It is not original or directly compilable source.
- The focused research scripts keep more measured boundary and switch
  corrections separately.
- Neither workflow rebuilds, signs or flashes firmware.
- The signature check confirms the package chain and its match to the root key
  compiled into this image. It does not authenticate an external trusted root.

Source: [unpacker](../scripts/cuktech_pc/firmware_unpack.py),
[color decoder](../scripts/cuktech_pc/firmware_bitmaps.py),
[Ghidra workflow](../scripts/ghidra/README.md). Vendor binaries, generated PNGs
and decompilation stay local in the ignored `artifacts/firmware/` directory.

The later [secondary-controller audit](firmware/secondary-controller-followup.md)
adds an offline [data-identity check](../scripts/cuktech_pc/firmware_data_audit.py).
AES/SHA tables that it makes separately match 512 bytes that were earlier in
unclassified slices. Its host-function gap report makes the list of candidates
smaller. It does not claim a secondary image. It does not give a format to all
remaining bytes.

> NOTE: Paths under `artifacts/` are local files that git ignores. They are
> downloaded vendor packages and outputs that the tools in `scripts/` make
> again. They are not part of this repository. The documents record hashes so
> that you can reproduce the results.
