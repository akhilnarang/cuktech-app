"""Offline Metro indexed-RAM JavaScript extraction; never executes JavaScript.

Format: facebook/metro packages/metro/src/shared/output/RamBundle/as-indexed-file.js.
Offsets refer to the code blob after the header/table, including startup code.
Run: ``uv run -m cuktech_pc.ram_bundle BUNDLE --output DIR``.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

MAGIC = 0xFB0BD1E5
MAX_BYTES = 64 * 1024 * 1024


def parse(blob: bytes) -> dict:
    """Parse and validate a Metro indexed RAM bundle in memory.

    Modules that share one byte range become one section with all their ids.
    Gaps between sections are reported as ``unclassified``.

    Args:
        blob: The complete bundle file, 12 bytes to ``MAX_BYTES`` (64 MiB).

    Returns:
        A report dict with the size, SHA-256, slot counts, the code blob
        offset and a ``sections`` list that covers every byte of ``blob``.

    Raises:
        ValueError: If the size, magic, module table or a range is not
            valid, if sections overlap, or if a JavaScript section is not a
            null-terminated UTF-8 string.
        UnicodeDecodeError: If a JavaScript section is not valid UTF-8.
    """
    if not 12 <= len(blob) <= MAX_BYTES:
        raise ValueError("invalid or excessive indexed RAM bundle size")
    magic, count, startup_size = struct.unpack_from("<III", blob)
    base = 12 + count * 8
    if magic != MAGIC or base > len(blob) or base + startup_size > len(blob):
        raise ValueError("invalid magic, module table or startup range")
    if not startup_size:
        raise ValueError("missing null-terminated startup code")
    groups: dict[tuple[int, int], list[int]] = {}
    populated = 0
    for module_id in range(count):
        offset, size = struct.unpack_from("<II", blob, 12 + module_id * 8)
        if offset == size == 0:
            continue
        if size == 0 or offset < startup_size or base + offset + size > len(blob):
            raise ValueError(f"invalid module range: {module_id}")
        groups.setdefault((base + offset, size), []).append(module_id)
        populated += 1
    sections = [{"kind": "header", "offset": 0, "size": 12},
                {"kind": "table", "offset": 12, "size": count * 8},
                {"kind": "startup", "offset": base, "size": startup_size}]
    for (offset, size), ids in sorted(groups.items()):
        sections.append({"kind": "module", "offset": offset, "size": size,
                         "module_ids": ids})
    for section in sections:
        if section["kind"] in ("startup", "module"):
            part = blob[section["offset"]:section["offset"] + section["size"]]
            if not part.endswith(b"\0") or b"\0" in part[:-1]:
                raise ValueError("JavaScript section is not a null-terminated string")
            part[:-1].decode("utf-8", errors="strict")
    complete = []
    cursor = 0
    for section in sections:
        if section["offset"] < cursor:
            raise ValueError("partially overlapping module sections")
        if section["offset"] > cursor:
            complete.append({"kind": "unclassified", "offset": cursor,
                             "size": section["offset"] - cursor})
        complete.append(section)
        cursor = section["offset"] + section["size"]
    if cursor < len(blob):
        complete.append({"kind": "unclassified", "offset": cursor,
                         "size": len(blob) - cursor})
    return {"format": "metro-indexed-ram-bundle", "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(), "table_slots": count,
            "populated_slots": populated, "unique_module_sections": len(groups),
            "code_blob_offset": base, "startup_bytes": startup_size,
            "sections": complete}


def unpack(source: Path, output: Path) -> dict:
    """Extract every section of a bundle to files and verify the round trip.

    Writes ``sections/*.bin``, ``startup.js``, ``modules/module-<id>.js`` and
    ``manifest.json``. The function then rebuilds the input from the written
    slices and compares the SHA-256.

    Args:
        source: The bundle file.
        output: The output directory. It must not exist.

    Returns:
        The ``parse`` report, with file names, per-section SHA-256,
        ``roundtrip_verified`` and ``limitations`` added.

    Raises:
        ValueError: If the file is larger than ``MAX_BYTES``, if ``parse``
            fails, or if the written slices do not rebuild the input.
        FileExistsError: If ``output`` exists.
    """
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("indexed RAM bundle exceeds size cap")
    blob = source.read_bytes()
    report = parse(blob)  # Validate every range and text section before writing.
    output.mkdir(parents=True, exist_ok=False)
    (output / "sections").mkdir()
    (output / "modules").mkdir()
    for index, section in enumerate(report["sections"]):
        part = blob[section["offset"]:section["offset"] + section["size"]]
        name = f"sections/{index:04d}-{section['kind']}.bin"
        (output / name).write_bytes(part)
        section.update(file=name, sha256=hashlib.sha256(part).hexdigest())
        if section["kind"] in ("startup", "module"):
            js = ("startup.js" if section["kind"] == "startup" else
                  f"modules/module-{section['module_ids'][0]}.js")
            (output / js).write_bytes(part[:-1])
            section["javascript_file"] = js
    # Independently rebuild from exported slices, without a copied input file.
    rebuilt = bytearray()
    for section in report["sections"]:
        part = (output / section["file"]).read_bytes()
        if (len(rebuilt) != section["offset"] or len(part) != section["size"] or
                hashlib.sha256(part).hexdigest() != section["sha256"]):
            raise ValueError("exported section failed verification")
        rebuilt.extend(part)
    if len(rebuilt) != len(blob) or hashlib.sha256(rebuilt).hexdigest() != report["sha256"]:
        raise ValueError("exported slices do not reconstruct the input")
    report["roundtrip_verified"] = True
    report["limitations"] = ["Extracts UTF-8 JavaScript; does not execute it or recover original pre-transpilation source.",
                             "Shared module ranges are retained as aliases, not duplicated physical sections."]
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    """Run the command-line entry point and print the report without the section list."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = unpack(args.bundle, args.output)
    print(json.dumps({k: v for k, v in report.items() if k != "sections"}, indent=2))


if __name__ == "__main__":
    main()
