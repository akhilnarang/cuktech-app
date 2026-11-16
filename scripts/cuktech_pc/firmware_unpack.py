"""Offline R2SF/Xiaomi OTA unpacker; no account, network, Bluetooth, or flashing.

The observed AD1204 image is plaintext machine code, not an encrypted archive.
Extracts package components, startup copy/LZ regions, optional font/color RLE,
and analyst-selected slices. Inventories strings/entropy and admits only
complete bounded zlib/gzip streams in its generic stream scan. It does
not manufacture a filesystem or claim arbitrary high-entropy bytes are crypto.
Run: ``uv run -m cuktech_pc.firmware_unpack IMAGE --output DIR``.
"""

import argparse
import hashlib
import html
import json
import math
from collections import Counter
from pathlib import Path
import re
import struct
import sys
import zlib

MAGIC = bytes.fromhex("000000004d49ef54464f544182562647")
MAX_IMAGE = 8 * 1024 * 1024
MAX_DECOMPRESSED = 16 * 1024 * 1024
MAX_TOTAL_DECOMPRESSED = 64 * 1024 * 1024
KNOWN_AD1204_0073_SHA256 = "65d96d0f6138a36fc62ce62325d055f934dac40d67bc31720f8182ebf5c80ce1"


def expand_startup_lz(data: bytes, expected_size: int) -> tuple[bytes, int]:
    """Translate the Thumb decompressor at 0x00403b40, including overlap.

    Low two token bits encode literal count + 1 (zero uses the next byte).
    High nibble encodes match count - 2 (zero uses the next byte; zero means
    no match). Bits 2:3 extend the back distance; value 3 takes a high byte.
    Stop at the table's declared output size, not at an invented terminator.

    Args:
        data: The compressed source, from the start of the block.
        expected_size: The declared output size in bytes, 1 to
            ``MAX_DECOMPRESSED``.

    Returns:
        A ``(output, consumed)`` tuple. ``consumed`` is the number of source
        bytes read.

    Raises:
        ValueError: If the size is out of range, the input is truncated, or
            a token is not valid or goes past the declared output.
    """
    if not 0 < expected_size <= MAX_DECOMPRESSED:
        raise ValueError("startup expansion size is outside the budget")
    output = bytearray()
    cursor = 0

    def byte():
        nonlocal cursor
        if cursor >= len(data):
            raise ValueError("truncated startup-compressed block")
        value = data[cursor]
        cursor += 1
        return value

    while len(output) < expected_size:
        token = byte()
        literals = token & 3
        if not literals:
            literals = byte()
        match = token >> 4
        if not match:
            match = byte()
        if not literals:
            raise ValueError("invalid zero startup literal-count encoding")
        literals -= 1
        if cursor + literals > len(data) or len(output) + literals > expected_size:
            raise ValueError("startup literal run exceeds input or declared output")
        output.extend(data[cursor:cursor + literals])
        cursor += literals
        if match:
            distance = byte()
            distance += byte() << 8 if token & 12 == 12 else (token & 12) << 6
            if not 0 < distance <= len(output):
                raise ValueError("startup back-reference points before output")
            if len(output) + match + 2 > expected_size:
                raise ValueError("startup match exceeds declared output")
            for _ in range(match + 2):
                output.append(output[-distance])
        elif not literals:
            raise ValueError("startup token makes no progress")
    return bytes(output), cursor


def scatter_regions(payload: bytes, base: int):
    """Admit the measured AD1204 startup-table profile, not guessed partitions.

    Other layouts return no automatic sections. Exact arbitrary ranges remain
    available with --region. Zero-fill records describe memory, not source bytes.

    Args:
        payload: The firmware payload without the signed-package tail.
        base: The declared image base address.

    Returns:
        A ``(regions, files)`` tuple. ``regions`` has one dict per table
        record. ``files`` has ``(name, content, source_offset, basis)``
        tuples to write. Both lists are empty if the profile does not match.

    Raises:
        ValueError: If a table record in the matched profile has a bad
            extent, overlaps another record, points outside the firmware, or
            has an unknown handler.
    """
    if len(payload) < 0xb48:
        return [], []
    start, end = struct.unpack_from("<II", payload, 0xb8)
    if (start, end) != (base + 0xe0, base + 0x130):
        return [], []
    if payload[0xc0:0xc8] != bytes.fromhex("02e008c8121f08c1") or payload[0xb40:0xb48] != bytes.fromhex("70b58d1810f8014b"):
        return [], []
    regions, files = [], []
    destinations = []
    for index, offset in enumerate(range(0xe0, 0x130, 16)):
        source, destination, size, handler = struct.unpack_from("<IIII", payload, offset)
        if not 0 < size <= MAX_DECOMPRESSED or destination + size > 0x100000000:
            raise ValueError("startup table has invalid destination extent")
        if any(destination < other + length and other < destination + size for other, length in destinations):
            raise ValueError("startup destination regions overlap")
        destinations.append((destination, size))
        row = {"index": index, "table_offset": offset, "source_address": source,
               "destination_address": destination, "expanded_size": size, "handler_address": handler}
        prefix = f"load-{index}-{destination:08x}"
        if handler == base + 0xd0:
            row.update(kind="zero_fill", source_offset=None, source_size=0)
        elif handler in (base + 0xc0, base + 0xb40):
            source_offset = source - base
            if not 0 <= source_offset < len(payload):
                raise ValueError("startup source is outside firmware")
            if handler == base + 0xc0:
                if source_offset + size > len(payload):
                    raise ValueError("startup copy extends outside firmware")
                content = payload[source_offset:source_offset + size]
                name = prefix + "-copy.bin"
                row.update(kind="copy", source_offset=source_offset, source_size=size, file=name, sha256=digest(content))
                files.append((name, content, source_offset, "startup table copy region"))
            else:
                content, used = expand_startup_lz(payload[source_offset:], size)
                encoded_name = prefix + "-compressed.bin"
                expanded_name = prefix + "-expanded.bin"
                row.update(kind="startup_lz", source_offset=source_offset, source_size=used,
                           file=expanded_name, encoded_file=encoded_name, sha256=digest(content))
                files.append((encoded_name, payload[source_offset:source_offset + used], source_offset, "startup decompressor consumed bytes"))
                files.append((expanded_name, content, source_offset, "reconstructed startup SRAM bytes; derived from decompressor"))
        else:
            raise ValueError("unrecognized handler in admitted startup-table profile")
        regions.append(row)
    return regions, files


def digest(data: bytes) -> str:
    """Return the SHA-256 of ``data`` as lowercase hex.

    Args:
        data: The bytes to hash.

    Returns:
        The 64-character hex digest.
    """
    return hashlib.sha256(data).hexdigest()


def decode_alpha_runs(data: bytes, pixels: int) -> tuple[bytes, int]:
    """Decode (alpha, run-length) byte pairs used by the font renderer.

    The renderer at 0x0040e5e0 consumes width * height pixels. No fabricated
    terminator or boundary inferred from the next pointer is used.

    Args:
        data: The RLE source, from the start of the glyph.
        pixels: Pixel count (width x height), 1 to 160 * 255.

    Returns:
        A ``(alpha, consumed)`` tuple. ``alpha`` has one byte per pixel.

    Raises:
        ValueError: If ``pixels`` is out of range, the source is truncated,
            or a run is zero or goes past the pixel count.
    """
    if not 0 < pixels <= 160 * 255:
        raise ValueError("glyph pixel count is outside the measured profile")
    output = bytearray()
    cursor = 0
    while len(output) < pixels:
        if cursor + 2 > len(data):
            raise ValueError("truncated glyph RLE")
        alpha, count = data[cursor:cursor + 2]
        cursor += 2
        if not count or len(output) + count > pixels:
            raise ValueError("glyph run has zero length or exceeds its dimensions")
        output.extend(bytes([alpha]) * count)
    return bytes(output), cursor


def grayscale_png(pixels: bytes, width: int, height: int) -> bytes:
    """Render the recovered alpha mask as a standard grayscale PNG preview.

    Args:
        pixels: One 8-bit value per pixel, row by row.
        width: Width in pixels.
        height: Height in pixels.

    Returns:
        The PNG file bytes.

    Raises:
        ValueError: If ``len(pixels)`` is not ``width * height``.
    """
    if len(pixels) != width * height:
        raise ValueError("PNG dimensions do not match pixels")
    def chunk(kind, value):
        return struct.pack(">I", len(value)) + kind + value + struct.pack(">I", zlib.crc32(kind + value) & 0xffffffff)
    scanlines = b"".join(b"\0" + pixels[row * width:(row + 1) * width] for row in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b""))


def font_assets(payload: bytes, base: int):
    """Find measured font descriptors; validate every glyph before admission.

    Descriptor: uint32 height, count, glyph-table pointer. Glyph: uint32 packed
    UTF-8 identifier, width, RLE pointer. Rendering uses the low bytes of height
    and width; this profile conservatively admits small positive full words.

    Args:
        payload: The firmware payload without the signed-package tail.
        base: The declared image base address.

    Returns:
        One dict per admitted font, with its glyph list.

    Raises:
        ValueError: If there are more than 128 fonts, more than 4096 glyphs
            or more than ``MAX_TOTAL_DECOMPRESSED`` pixels in total.
    """
    fonts, total_pixels, total_glyphs = [], 0, 0
    for offset in range(0, len(payload) - 12, 4):
        height, count, table_address = struct.unpack_from("<III", payload, offset)
        table = table_address - base
        if not (1 <= height <= 160 and 1 <= count <= 1024 and 0 <= table <= len(payload) - 12 * count):
            continue
        glyphs = []
        previous = -1
        for index in range(count):
            identifier, width, pointer = struct.unpack_from("<III", payload, table + index * 12)
            start = pointer - base
            if not (previous < identifier <= 0xffffffff and 1 <= width <= 255 and 0 <= start < len(payload) - 1):
                break
            try:
                text = identifier.to_bytes(max(1, (identifier.bit_length() + 7) // 8), "big").decode("utf-8")
                pixels, used = decode_alpha_runs(payload[start:], width * height)
            except (UnicodeError, ValueError):
                break
            previous = identifier
            stem = f"assets/font-{offset:08x}-glyph-{identifier:08x}"
            glyphs.append({"identifier": identifier, "text": text, "width": width, "height": height,
                           "table_offset": table + index * 12, "source_offset": start, "source_size": used,
                           "rle_file": stem + ".rle", "preview_file": stem + ".png", "pixel_sha256": digest(pixels)})
        else:
            total_glyphs += len(glyphs)
            total_pixels += sum(g["width"] * g["height"] for g in glyphs)
            if len(fonts) >= 128 or total_glyphs > 4096 or total_pixels > MAX_TOTAL_DECOMPRESSED:
                raise ValueError("font extraction budget exceeded")
            fonts.append({"descriptor_offset": offset, "descriptor_address": base + offset,
                          "height": height, "count": count, "table_address": table_address,
                          "basis": "inferred descriptor; every glyph has sorted packed UTF-8 ID and an exact bounded RLE pixel count",
                          "glyphs": glyphs})
    return fonts


def parse_package(data: bytes) -> dict:
    """Parse the R2SF header and the optional Xiaomi signed-package tail.

    Args:
        data: The complete file, 1 KiB to ``MAX_IMAGE`` (8 MiB).

    Returns:
        A dict with the size, SHA-256, vector table, declared image base,
        ``signed`` and ``firmware_size``. A signed package also adds the tag
        fields, TLVs, the stored tag CRC32 and a ``components`` list (tag,
        certificates, signature and each PEM certificate).

    Raises:
        ValueError: If the file is not an R2SF image, or the signing header,
            boundaries or TLVs are not valid.
    """
    if not 1024 <= len(data) <= MAX_IMAGE or data[40:44] != b"R2SF":
        raise ValueError("expected a 1 KiB–8 MiB R2SF firmware image")
    stack, reset = struct.unpack_from("<II", data)
    base = struct.unpack_from("<I", data, 0x24)[0]
    result = {"size": len(data), "sha256": digest(data), "initial_stack": stack,
              "reset_vector": reset, "declared_image_base": base, "signed": False,
              "firmware_size": len(data), "components": []}
    offset = data.rfind(MAGIC)
    if offset < 0:
        return result
    if offset + 28 > len(data):
        raise ValueError("truncated Xiaomi signing header")
    tag_size, pid, fw_size, cert_size, flags, reserved = struct.unpack_from("<HHIHBB", data, offset + 16)
    cert_start, signature_start = offset + tag_size, offset + tag_size + cert_size
    if tag_size < 32 or fw_size != offset or cert_size == 0 or signature_start >= len(data):
        raise ValueError("invalid signing component boundaries")
    fields = []
    seen = set()
    cursor, end = offset + 28, cert_start - 4
    while cursor < end:
        if cursor + 2 > end:
            raise ValueError("truncated TLV header")
        kind, length = data[cursor:cursor + 2]
        if kind in seen or cursor + 2 + length > end:
            raise ValueError("duplicate TLV or value outside signing tag")
        value = data[cursor + 2:cursor + 2 + length]
        fields.append({"type": kind, "offset": cursor, "length": length, "hex": value.hex()})
        seen.add(kind)
        cursor += 2 + length
    result.update(signed=True, firmware_size=fw_size, tag_offset=offset, tag_size=tag_size,
                  product_id=pid, flags=flags, reserved=reserved, tlvs=fields,
                  tag_crc32_stored=struct.unpack_from("<I", data, end)[0],
                  tag_crc32_status="algorithm and coverage not established")
    result["components"] = [
        {"name": "xiaomi-tag.bin", "offset": offset, "size": tag_size},
        {"name": "certificates.pem", "offset": cert_start, "size": cert_size},
        {"name": "image-signature.der", "offset": signature_start, "size": len(data) - signature_start}]
    certs = list(re.finditer(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", data[cert_start:signature_start]))
    for index, cert in enumerate(certs):
        result["components"].append({"name": f"certificate-{index}.pem", "offset": cert_start + cert.start(), "size": cert.end() - cert.start()})
    return result


def entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of ``data``.

    Args:
        data: The bytes to measure.

    Returns:
        Bits per byte, 0.0 to 8.0. Empty data gives 0.0.
    """
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()) if data else 0.0


def compressed_streams(data: bytes):
    """Validate a complete stream; zlib checks its own Adler-32/gzip CRC.

    Header matches alone are discarded. Output, total expansion, and stream
    count are bounded. A carved stream is a candidate resource, not a file name
    recovered from the firmware's build system.

    Args:
        data: The bytes to scan.

    Yields:
        ``(info, expanded)`` tuples. ``info`` has the offset, compressed
        size, format, expanded size and expanded SHA-256.

    Raises:
        ValueError: If there are more than 128 streams or more than
            ``MAX_TOTAL_DECOMPRESSED`` expanded bytes in total.
    """
    total, count = 0, 0
    for match in re.finditer(rb"\x1f\x8b\x08|[\x08\x18\x28\x38\x48\x58\x68\x78].", data, re.DOTALL):
        offset = match.start()
        gzip = data[offset:offset + 3] == b"\x1f\x8b\x08"
        if not gzip and (int.from_bytes(data[offset:offset + 2], "big") % 31 or data[offset + 1] & 0x20):
            continue
        try:
            decoder = zlib.decompressobj(31 if gzip else 15)
            expanded = decoder.decompress(data[offset:], MAX_DECOMPRESSED + 1)
            if not decoder.eof or len(expanded) > MAX_DECOMPRESSED or len(expanded) < 16:
                continue
            size = len(data) - offset - len(decoder.unused_data)
            total += len(expanded)
            count += 1
            if total > MAX_TOTAL_DECOMPRESSED or count > 128:
                raise ValueError("embedded stream expansion budget exceeded")
            yield {"offset": offset, "size": size, "format": "gzip" if gzip else "zlib",
                   "expanded_size": len(expanded), "expanded_sha256": digest(expanded)}, expanded
        except zlib.error:
            continue


def parse_region(value: str, size: int) -> tuple[int, int, str]:
    """Parse one ``--region OFFSET:SIZE:NAME`` value.

    Args:
        value: The region text. OFFSET and SIZE are decimal or ``0x`` hex.
        size: The payload size in bytes.

    Returns:
        The ``(offset, length, name)`` tuple.

    Raises:
        ValueError: If the format or name is not valid, or the region is
            outside the payload.
    """
    try:
        at, length, name = value.split(":", 2)
        offset, length = int(at, 0), int(length, 0)
    except (ValueError, TypeError) as exc:
        raise ValueError("region must be OFFSET:SIZE:NAME (decimal or 0x hex)") from exc
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ValueError("region name must be a short plain filename")
    if offset < 0 or length <= 0 or offset + length > size:
        raise ValueError("region is outside the firmware payload")
    return offset, length, name


def source_map(payload: bytes, base: int, regions: list[dict]) -> dict:
    """Account for admitted source intervals, without inventing file boundaries.

    Overlap is allowed (shared glyphs and metadata views); unclassified ranges
    are the complement of the union, not guessed code/data/crypto partitions.

    Args:
        payload: The firmware payload.
        base: The flash base address of ``payload[0]``.
        regions: Dicts with ``offset``, ``size``, ``kind`` and ``basis``.

    Returns:
        The source-map dict with sorted regions, byte counts, the
        unclassified ranges and limitations.

    Raises:
        ValueError: If a region is empty or outside the payload.
    """
    ordered = sorted(regions, key=lambda row: (row["offset"], row["size"], row["kind"]))
    merged = []
    for row in ordered:
        start, size = row["offset"], row["size"]
        if start < 0 or size <= 0 or start + size > len(payload):
            raise ValueError("source-map interval outside firmware")
        # Keep original, overlapping provenance separately from the union.
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], start + size)
        else:
            merged.append([start, start + size])
    unclassified, cursor = [], 0
    for start, end in merged + [[len(payload), len(payload)]]:
        if cursor < start:
            unclassified.append({"offset": cursor, "address": base + cursor, "size": start - cursor,
                                 "sha256": digest(payload[cursor:start]),
                                 "file": f"unclassified/range-{cursor:08x}-{start:08x}.bin"})
        cursor = end
    return {"firmware_sha256": digest(payload), "firmware_size": len(payload), "flash_base": base,
            "regions": [dict(row, address=base + row["offset"], sha256=digest(payload[row["offset"]:row["offset"] + row["size"]])) for row in ordered],
            "classified_source_bytes": sum(end - start for start, end in merged),
            "unclassified_source_bytes": sum(row["size"] for row in unclassified),
            "unclassified_ranges": unclassified,
            "limitations": "Source accounting, not semantic coverage. Unclassified ranges can contain executable code, constants, metadata and unknown data; their boundaries are generated, not recovered filenames or partitions."}


def unpack(source: Path, destination: Path, regions=(), verify=False, assets=False, split_unclassified=False) -> dict:
    """Extract an R2SF image or signed package to a new directory.

    Writes the payload, header, package components, startup regions,
    selected regions, compressed streams, optional assets, ``source-map.json``,
    ``strings.json``, ``index.html`` and ``manifest.json``. Each written file
    is opened in exclusive mode.

    Args:
        source: The firmware file, 8 MiB maximum.
        destination: The output directory. It must not exist.
        regions: ``OFFSET:SIZE:NAME`` texts for analyst-selected slices.
        verify: If ``True``, verify the developer certificate and image
            signature. On the measured 0073 image, also verify the server
            certificate against the embedded DFU root key.
        assets: If ``True``, extract alpha-font glyphs, and RGB565 bitmaps on
            the measured 0073 image.
        split_unclassified: If ``True``, also write each unclassified range
            as a file.

    Returns:
        The manifest dict.

    Raises:
        ValueError: If the file is too large or not valid, the destination
            exists, a region is not valid, a budget is exceeded, or a
            verification fails.
        ImportError: If ``verify`` is set and ``cryptography`` is not installed.
    """
    if source.stat().st_size > MAX_IMAGE:
        raise ValueError("input exceeds the 8 MiB image limit")
    data = source.read_bytes()
    info = parse_package(data)
    payload = data[:info["firmware_size"]]
    selected = [parse_region(r, len(payload)) for r in regions]
    startup, startup_files = scatter_regions(payload, info["declared_image_base"])
    fonts = font_assets(payload, info["declared_image_base"]) if assets else []
    # Only the exact measured image admits the independently verified color
    # renderer profile. An unfamiliar image retains its unknown bytes.
    bitmaps = []
    color_profile = "not requested"
    if assets:
        color_profile = "unsupported image; color assets not decoded"
        if digest(payload) == KNOWN_AD1204_0073_SHA256:
            from .firmware_bitmaps import bitmap_assets
            bitmaps = bitmap_assets(payload, info["declared_image_base"])
            color_profile = "0073 opaque RGB565 renderer 0x0040e30c"
    embedded_root = None
    # A new directory prevents overwriting source images or unrelated files.
    # All output names are generated here or validated by parse_region.
    if destination.exists() or destination.is_symlink():
        raise ValueError("output directory must be new")
    if verify:
        if not info["signed"]:
            raise ValueError("raw image has no packaged signature to verify")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.exceptions import InvalidSignature
        cert_part, sig_part = info["components"][1:3]
        certs = x509.load_pem_x509_certificates(data[cert_part["offset"]:cert_part["offset"] + cert_part["size"]])
        if len(certs) != 2:
            raise ValueError("expected two packaged certificates")
        server, developer = certs
        try:
            server.public_key().verify(developer.signature, developer.tbs_certificate_bytes, ec.ECDSA(developer.signature_hash_algorithm))
            developer.public_key().verify(data[sig_part["offset"]:], data[:cert_part["offset"]], ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ValueError("packaged developer/image signature verification failed") from exc
        info["signature_verification"] = {"developer_certificate": True, "image_and_tag": True,
                                          "independent_trusted_root": "not verified"}
        if digest(payload) == KNOWN_AD1204_0073_SHA256:
            # The worker at 0x0041b3f0 loads this root pointer for the first
            # certificate verification. Scope this annotation to its exact image.
            root_address = struct.unpack_from("<I", payload, 0x41b6d8 - 0x403000)[0]
            root_offset = root_address - 0x403000
            embedded_root = b"\x04" + payload[root_offset:root_offset + 64]
            root_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), embedded_root)
            try:
                root_key.verify(server.signature, server.tbs_certificate_bytes, ec.ECDSA(server.signature_hash_algorithm))
            except InvalidSignature as exc:
                raise ValueError("server certificate does not match the measured firmware root") from exc
            info["signature_verification"].update(server_certificate_matches_embedded_root=True,
                                                  embedded_root_address=root_address, embedded_root_offset=root_offset)
    destination.mkdir(parents=True, exist_ok=False)
    outputs = []

    def write(name, content, offset=None, basis="exact source slice"):
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        outputs.append({"name": name, "source_offset": offset, "size": len(content), "sha256": digest(content), "basis": basis})

    write("firmware.bin", payload, 0)
    write("r2sf-header.bin", payload[:0x40], 0, "first 64 bytes; observed header/startup boundary")
    if startup:
        write("startup-table.bin", payload[0xe0:0x130], 0xe0, "admitted startup table; raw source records")
    for component in info["components"]:
        start = component["offset"]
        write(component["name"], data[start:start + component["size"]], start)
    if embedded_root is not None:
        write("embedded-dfu-root.sec1", embedded_root, info["signature_verification"]["embedded_root_offset"],
              "uncompressed SEC1 P-256 public point; prefix 04 added to the exact compiled 64-byte point")
    for start, length, name in selected:
        write("region-" + name + ".bin", payload[start:start + length], start, "analyst-selected range; semantics supplied by analyst")
    for name, content, offset, basis in startup_files:
        write(name, content, offset, basis)
    gallery = ["<!doctype html><meta charset='utf-8'><title>Recovered firmware alpha masks</title>",
               "<style>body{background:#181818;color:#eee;font-family:system-ui}figure{display:inline-block;margin:8px;padding:8px;background:#303030}img{display:block;min-width:16px}figcaption{font-size:12px}</style>",
               "<h1>Recovered firmware alpha masks</h1><p>Decoded from font RLE. Filenames and grouping are analyst-generated; UI colors and screen layouts are not recovered here.</p>"]
    for font in fonts:
        at, table = font["descriptor_offset"], font["table_address"] - info["declared_image_base"]
        write(f"assets/font-{at:08x}-descriptor.bin", payload[at:at + 12], at, "inferred font descriptor")
        write(f"assets/font-{at:08x}-table.bin", payload[table:table + font["count"] * 12], table, "inferred glyph table")
        gallery.append(f"<h2>Descriptor 0x{font['descriptor_address']:08x}; height {font['height']}</h2>")
        for glyph in font["glyphs"]:
            start, size = glyph["source_offset"], glyph["source_size"]
            encoded = payload[start:start + size]
            pixels, _ = decode_alpha_runs(encoded, glyph["width"] * glyph["height"])
            write(glyph["rle_file"], encoded, start, "validated glyph alpha RLE; inferred font descriptor")
            write(glyph["preview_file"], grayscale_png(pixels, glyph["width"], glyph["height"]), start, "derived grayscale alpha-mask preview")
            label = html.escape(f"0x{glyph['identifier']:08x} {glyph['text']}", quote=True)
            gallery.append(f"<figure><img loading='lazy' src='{glyph['preview_file']}' alt='{label}'><figcaption>{label}</figcaption></figure>")
    if assets:
        write("fonts.json", json.dumps(fonts, indent=2, ensure_ascii=False).encode("utf-8"), basis="inferred font descriptors and validated glyph metadata")
        write("assets.html", "\n".join(gallery).encode("utf-8"), basis="derived local asset gallery")
        if bitmaps:
            from .firmware_bitmaps import export_assets
            for bitmap in bitmaps:
                at = bitmap["descriptor_offset"]
                write(f"assets/color/bitmap-{bitmap['descriptor_address']:08x}-descriptor.bin", payload[at:at + 12], at, "inferred RGB565 bitmap descriptor")
            color_gallery = export_assets(payload, bitmaps, write, "assets/color/")
            write("assets/color/index.html", color_gallery.encode("utf-8"), basis="derived local color asset gallery")
        write("bitmaps.json", json.dumps({"profile": color_profile, "directory": "assets/color", "bitmaps": bitmaps}, indent=2).encode("utf-8"), basis="inferred color descriptors, source boundaries and decoded hashes")
    streams = []
    for stream, expanded in compressed_streams(payload):
        at = stream["offset"]
        prefix = f"stream-{at:08x}-{stream['format']}"
        write(prefix + ".bin", payload[at:at + stream["size"]], at, "complete checksummed compressed stream")
        write(prefix + ".expanded.bin", expanded, at, "decompressed bytes; not a direct source slice")
        streams.append(stream)
    mapped = [{"offset": 0, "size": 0x40, "kind": "header", "basis": "observed R2SF header boundary"}]
    if startup:
        mapped.append({"offset": 0xe0, "size": 0x50, "kind": "startup_table", "basis": "admitted startup profile"})
    for region in startup:
        if region["source_size"]:
            mapped.append({"offset": region["source_offset"], "size": region["source_size"], "kind": region["kind"], "basis": "startup table / bounded decoder"})
    for font in fonts:
        mapped.extend([{"offset": font["descriptor_offset"], "size": 12, "kind": "font_descriptor", "basis": font["basis"]},
                       {"offset": font["table_address"] - info["declared_image_base"], "size": font["count"] * 12, "kind": "glyph_table", "basis": font["basis"]}])
        mapped.extend({"offset": glyph["source_offset"], "size": glyph["source_size"], "kind": "alpha_rle", "basis": "bounded glyph decoder"} for glyph in font["glyphs"])
    for bitmap in bitmaps:
        mapped.extend([{"offset": bitmap["descriptor_offset"], "size": 12, "kind": "bitmap_descriptor", "basis": bitmap["basis"]},
                       {"offset": bitmap["source_offset"], "size": bitmap["source_size"], "kind": "color_bitmap", "basis": "bounded RGB565 decoder"}])
    mapped.extend({"offset": stream["offset"], "size": stream["size"], "kind": stream["format"], "basis": "complete checksummed compressed stream"} for stream in streams)
    # Analyst-selected slices remain exports, not automatically identified data.
    layout = source_map(payload, info["declared_image_base"], mapped)
    layout["unclassified_files_written"] = split_unclassified
    if split_unclassified:
        for row in layout["unclassified_ranges"]:
            write(row["file"], payload[row["offset"]:row["offset"] + row["size"]], row["offset"], "unclassified source interval; generated boundary, no inferred semantics")
    write("source-map.json", json.dumps(layout, indent=2).encode("utf-8"), basis="overlapping admitted source ranges and their unclassified complement")
    strings = [{"offset": m.start(), "address": info["declared_image_base"] + m.start(), "text": m.group().decode("ascii")}
               for m in re.finditer(rb"[\x20-\x7e]{5,}", payload)]
    write("strings.json", json.dumps(strings, indent=2).encode(), basis="ASCII inventory; includes possible code coincidences")
    windows = [{"offset": at, "size": len(payload[at:at + 4096]), "bits_per_byte": round(entropy(payload[at:at + 4096]), 5)}
               for at in range(0, len(payload), 4096)]
    info.update(source=str(source.resolve()), outputs=outputs, compressed_streams=streams, entropy_windows=windows,
                startup_regions=startup, startup_profile="measured AD1204 startup table" if startup else "not recognized",
                asset_summary={"requested": assets, "font_descriptors": len(fonts), "glyphs": sum(f["count"] for f in fonts), "color_bitmaps": len(bitmaps), "color_profile": color_profile},
                encryption_status="Readable Cortex/Thumb image; no whole-image decryption required. This does not prove every embedded region is plaintext.",
                limitations=["No recovered filesystem, partition table, or complete asset map is implied.",
                             "Entropy alone cannot distinguish encryption, compression, assets, or machine code.",
                             "No repacking, signing, firmware execution, hardware changes, or flashing."])
    index = ["<!doctype html><meta charset='utf-8'><title>Firmware extraction</title>",
             "<style>body{font-family:system-ui;max-width:70em;margin:2em auto;background:#202020;color:#eee}a{color:#8bd}li{margin:.7em}</style>",
             "<h1>Firmware extraction</h1>", f"<p>Firmware SHA-256: <code>{digest(payload)}</code></p><ul>",
             "<li><a href='manifest.json'>Manifest: files, hashes and source offsets</a></li>",
             "<li><a href='source-map.json'>Source map and unclassified ranges</a></li>",
             "<li><a href='strings.json'>ASCII string inventory</a></li>"]
    if assets:
        index.append(f"<li><a href='assets.html'>{len(fonts)} font descriptors / {sum(f['count'] for f in fonts)} alpha glyphs</a></li>")
    if bitmaps:
        index.append(f"<li><a href='assets/color/index.html'>{len(bitmaps)} color bitmaps</a></li>")
    index.append("</ul><p>Generated filenames and inferred descriptor grouping. Unclassified chunks may contain code and data. This is an offline extractor; it does not recreate original source or a filesystem.</p>")
    write("index.html", "\n".join(index).encode("utf-8"), basis="derived extraction index")
    (destination / "manifest.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def main() -> int:
    """Run the command-line entry point and print a summary as JSON.

    Returns:
        The process exit code: 0 on success, 1 on error.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--region", action="append", default=[], help="exact firmware slice OFFSET:SIZE:NAME; repeatable")
    parser.add_argument("--verify", action="store_true", help="check packaged developer/image signatures (requires cryptography)")
    parser.add_argument("--assets", action="store_true", help="extract alpha-font PNGs and, on the verified 0073 image, color RGB565 PNGs")
    parser.add_argument("--split-unclassified", action="store_true", help="also save source intervals outside admitted regions as unnamed binary chunks (can contain code/data)")
    args = parser.parse_args()
    try:
        info = unpack(args.image, args.output, args.region, args.verify, args.assets, args.split_unclassified)
    except (OSError, ValueError, ImportError, zlib.error) as exc:
        print(f"Unpack failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output.resolve()), "signed": info["signed"],
                      "firmware_size": info["firmware_size"], "files": len(info["outputs"]) + 1,
                      "assets": info["asset_summary"],
                      "validated_compressed_streams": len(info["compressed_streams"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
