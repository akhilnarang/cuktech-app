"""Offline extraction of the measured 0073 RGB565 bitmap descriptor/codec.

The previous alpha-font extractor does not decode these colored images.
Descriptor admission is bounded/inferred; no filesystem, extra charging mode,
controller firmware or animation is implied by an exported bitmap.
Run: ``uv run -m cuktech_pc.firmware_bitmaps SOURCE OUTPUT``.
"""

import argparse
import hashlib
import html
import json
from pathlib import Path
import struct
import sys
import zlib

from .firmware_unpack import KNOWN_AD1204_0073_SHA256, MAX_IMAGE, parse_package

MAX_PIXELS = 320 * 320
MAX_TOTAL_PIXELS = 8 * 1024 * 1024


def decode_rgb565(data: bytes, pixels: int, marker: int) -> tuple[bytes, int]:
    """Return little-endian color words and consumed bytes, before LCD swapping.

    Original uncropped renderer 0x40e30c tests each word's high byte against the
    descriptor marker. A matching word uses its low byte as a repeat count and
    consumes the next word as color. Its uint8 remaining-count behavior makes
    an encoded zero mean 256 pixels. Marker zero disables RLE entirely.

    Args:
        data: The encoded source, from the start of the bitmap.
        pixels: Pixel count (width x height), 1 to ``MAX_PIXELS``.
        marker: The RLE marker byte, 0 to 255. 0 means no RLE.

    Returns:
        A ``(words, consumed)`` tuple. ``words`` has ``pixels * 2`` bytes.
        ``consumed`` is the number of source bytes read.

    Raises:
        ValueError: If a parameter is out of range, the source is truncated,
            or a repeat goes past the pixel count.
    """
    if not 0 < pixels <= MAX_PIXELS or not 0 <= marker <= 255:
        raise ValueError("bitmap dimensions/marker outside measured bounds")
    output = bytearray()
    cursor = 0
    while len(output) < pixels * 2:
        if cursor + 2 > len(data):
            raise ValueError("truncated color word")
        word = data[cursor:cursor + 2]
        cursor += 2
        count = 1
        if marker and word[1] == marker:
            count = word[0] or 256
            if cursor + 2 > len(data):
                raise ValueError("truncated repeat color")
            word = data[cursor:cursor + 2]
            cursor += 2
        if len(output) + count * 2 > pixels * 2:
            raise ValueError("repeat exceeds declared bitmap dimensions")
        output.extend(word * count)
    return bytes(output), cursor


def rgb565_png(words: bytes, width: int, height: int) -> bytes:
    """Encode RGB565 pixels as an opaque 8-bit RGB PNG.

    Args:
        words: Little-endian RGB565 words, ``width * height * 2`` bytes.
        width: Width in pixels, 1 to 320.
        height: Height in pixels, 1 to 320.

    Returns:
        The PNG file bytes.

    Raises:
        ValueError: If the buffer size or dimensions are not valid.
    """
    if len(words) != width * height * 2 or not 0 < width <= 320 or not 0 < height <= 320:
        raise ValueError("RGB565 buffer does not match dimensions")
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        for x in range(width):
            value = struct.unpack_from("<H", words, (y * width + x) * 2)[0]
            r, g, b = value >> 11, value >> 5 & 63, value & 31
            scanlines.extend(((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)))

    def chunk(tag: bytes, content: bytes) -> bytes:
        return struct.pack(">I", len(content)) + tag + content + struct.pack(">I", zlib.crc32(tag + content))

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b"")


def bitmap_assets(payload: bytes, base: int) -> list[dict]:
    """Find bitmap descriptors in a payload and decode each one to check it.

    The function scans every 4-byte aligned offset for a 12-byte descriptor
    (width, height, depth 16, marker, address). It keeps only descriptors
    whose source decodes without error.

    Args:
        payload: The firmware payload without the signed-package tail.
        base: The load address of ``payload[0]``.

    Returns:
        One metadata dict per bitmap, with offsets, sizes, hashes and the
        output file names.

    Raises:
        ValueError: If there are more than 256 bitmaps or more than
            ``MAX_TOTAL_PIXELS`` pixels in total.
    """
    records = []
    total_pixels = 0
    for offset in range(0, len(payload) - 11, 4):
        width, height, depth, marker, address = struct.unpack_from("<HHHHI", payload, offset)
        source = address - base
        if not (0 < width <= 320 and 0 < height <= 320 and depth == 16 and marker <= 255 and 0 <= source < len(payload)):
            continue
        try:
            decoded, consumed = decode_rgb565(payload[source:], width * height, marker)
        except ValueError:
            continue
        total_pixels += width * height
        if len(records) >= 256 or total_pixels > MAX_TOTAL_PIXELS:
            raise ValueError("bitmap extraction budget exceeded")
        stem = f"bitmap-{base + offset:08x}"
        records.append({"descriptor_offset": offset, "descriptor_address": base + offset,
                        "width": width, "height": height, "bits_per_pixel": depth,
                        "rle_marker": marker, "source_offset": source, "source_address": address,
                        "source_size": consumed,
                        "source_sha256": hashlib.sha256(payload[source:source + consumed]).hexdigest(),
                        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                        "encoded_file": stem + ".encoded.bin", "rgb565_file": stem + ".rgb565-le.bin",
                        "preview_file": stem + ".png",
                        "basis": "Inferred descriptor; exact bounded pixel count under original uncropped RGB565 codec. No image name, animation or charging feature inferred."})
    return records


def export_assets(payload: bytes, records: list[dict], write, prefix: str = "") -> str:
    """Export records through the unpacker's provenance-aware writer, or alone.

    Args:
        payload: The firmware payload that ``records`` refer to.
        records: The result of ``bitmap_assets``.
        write: Callable ``write(name, content, offset, basis)`` that stores one
            file.
        prefix: Text added before each file name.

    Returns:
        The HTML text of a preview gallery.

    Raises:
        ValueError: If a record does not match the decoded source.
    """
    gallery = ["<!doctype html><meta charset='utf-8'><title>0073 colored bitmaps</title>",
               "<style>body{background:#202020;color:white;font-family:system-ui}figure{display:inline-block;vertical-align:top;margin:10px}img{display:block;image-rendering:pixelated;background:black}</style>",
               "<h1>0073 RGB565 bitmaps</h1><p>Original pixels decoded offline. IDs are source addresses; names, transparency keys and activation routes are not inferred.</p>"]
    for record in records:
        start, size = record["source_offset"], record["source_size"]
        words, consumed = decode_rgb565(payload[start:start + size], record["width"] * record["height"], record["rle_marker"])
        if consumed != size or hashlib.sha256(words).hexdigest() != record["decoded_sha256"]:
            raise ValueError("bitmap metadata disagrees with decoded source")
        write(prefix + record["encoded_file"], payload[start:start + size], start, "encoded RGB565 bitmap; inferred descriptor, verified codec")
        write(prefix + record["rgb565_file"], words, start, "derived little-endian RGB565 pixels")
        write(prefix + record["preview_file"], rgb565_png(words, record["width"], record["height"]), start, "derived opaque RGB565 PNG preview")
        label = f"0x{record['descriptor_address']:08x} · {record['width']}×{record['height']} · marker {record['rle_marker']}"
        gallery.append(f"<figure><img loading='lazy' src='{record['preview_file']}' alt='{html.escape(label)}'><figcaption>{html.escape(label)}</figcaption></figure>")
    return "\n".join(gallery)


def extract(source: Path, output: Path) -> dict:
    """Extract all bitmaps of the measured 0073 image to a new directory.

    Writes the encoded, RGB565 and PNG files, ``index.html`` and
    ``manifest.json``.

    Args:
        source: The firmware package file.
        output: The output directory. It must not exist.

    Returns:
        The manifest dict.

    Raises:
        ValueError: If the file is too large, is not the measured 0073
            image, the output exists, or a bitmap check fails.
    """
    if source.stat().st_size > MAX_IMAGE:
        raise ValueError("input exceeds image budget")
    data = source.read_bytes()
    package = parse_package(data)
    payload = data[:package["firmware_size"]]
    sha = hashlib.sha256(payload).hexdigest()
    if sha != KNOWN_AD1204_0073_SHA256:
        raise ValueError("bitmap renderer profile is verified only for the measured 0073 image")
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must be new")
    records = bitmap_assets(payload, package["declared_image_base"])
    output.mkdir(parents=True)
    def write(name, content, offset, basis):
        with (output / name).open("xb") as stream:
            stream.write(content)
    (output / "index.html").write_text(export_assets(payload, records, write), encoding="utf-8")
    report = {"sha256": sha, "source_bytes": len(payload), "renderer": "0040e30c",
              "bitmap_count": len(records), "bitmaps": records,
              "limitations": ["Descriptor selection is inferred from layout and bounded codec validity.",
                              "PNG uses opaque standard RGB565; caller-specific color-key transparency and clipping are not applied.",
                              "No hardware, ROM, controller negotiation or firmware update is executed.",
                              "Extracted image bytes are not proof that no embedded controller firmware exists elsewhere."]}
    (output / "manifest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The process exit code: 0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        report = extract(args.source, args.output)
    except (ValueError, OSError) as error:
        print(f"bitmap extraction error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"sha256": report["sha256"], "bitmap_count": report["bitmap_count"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
