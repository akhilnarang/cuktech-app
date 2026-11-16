"""Count retained static evidence, not semantic or whole-device completion.

Input paths are relative to the manifest's parent directory. Instruction records
are independently compared with the original flash image; no device is used.
Run: ``uv run -m cuktech_pc.firmware_coverage MANIFEST [--output FILE]``.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .firmware_evidence import address, hex_address


LIMITATIONS = [
    "Function inventory is Ghidra's discovered entries, not a complete ground truth.",
    "Focused exports prove retained selection, not human review or understood behavior.",
    "Instruction comparison proves byte identity, not correct disassembly or execution.",
    "No semantic-review percentage or whole-firmware completion percentage is calculated.",
    "Unselected entries may have been read in older analysis; selected entries may remain unresolved.",
    "Mask ROM, separate controller firmware, computed paths and real-device validation remain outside these counts.",
]


def audit(manifest_path: Path) -> dict:
    """Count the evidence that a coverage manifest lists, and check it.

    The function hashes every input file, checks that all files refer to the
    same image, and compares each instruction record with the image bytes.

    Args:
        manifest_path: The manifest JSON file. Paths in it are relative to
            its directory.

    Returns:
        The coverage report dict. ``semantic_review_count`` and
        ``hardware_validation_count`` are always ``None``.

    Raises:
        ValueError: If a hash does not match, an entry is duplicated, or an
            instruction record is empty, outside the image, different from the
            image or in conflict with another record.
        KeyError: If a required manifest or record field is missing.
    """
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = manifest_path.parent
    inputs = []

    def read(relative):
        path = root / relative
        data = path.read_bytes()
        inputs.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        return data

    def rows(relative):
        return [json.loads(line) for line in read(relative).decode("utf-8").splitlines() if line.strip()]

    image = read(manifest["image"])
    digest = hashlib.sha256(image).hexdigest()
    if digest != manifest["sha256"]:
        raise ValueError("image SHA-256 does not match manifest")
    metadata = json.loads(read(manifest["analysis_metadata"]))
    if metadata["sha256"] != digest:
        raise ValueError("analysis SHA-256 does not match image")
    inventory = {}
    for row in rows(manifest["inventory"]):
        at = address(row["address"])
        if at in inventory:
            raise ValueError("duplicate inventory entry")
        inventory[at] = row
    selected = set()
    focused = []
    for source in manifest["focused"]:
        if source.get("metadata"):
            info = json.loads(read(source["metadata"]))
            if info["sha256"] != digest:
                raise ValueError("focused metadata SHA-256 does not match image")
            identity = "image hash in sidecar matches"
        else:
            identity = "manifest attribution only; no identity sidecar"
        entries = set()
        missing = []
        errors = []
        records = rows(source["functions"])
        for row in records:
            if not row.get("address"):
                missing.append(row)
                continue
            at = address(row["address"])
            if at in entries:
                raise ValueError("duplicate focused entry within one export")
            entries.add(at)
            if row.get("error") or not row.get("decompiled"):
                errors.append(hex_address(at))
        selected.update(entries)
        focused.append({"functions": source["functions"], "identity": identity,
                        "records": len(records), "unique_entries": len(entries),
                        "missing_requests": missing, "decompilation_errors": errors})
    byte_map = {}
    instruction_map = {}
    instruction_sources = []
    base = address(manifest["flash_base"])
    for relative in manifest.get("instructions", []):
        records = rows(relative)
        for row in records:
            at = address(row["address"])
            data = bytes.fromhex(row["bytes"])
            if not data:
                raise ValueError("empty instruction bytes")
            offset = at - base
            if offset < 0 or offset + len(data) > len(image):
                raise ValueError("instruction outside supplied flash image")
            if image[offset:offset + len(data)] != data:
                raise ValueError(f"instruction bytes mismatch at {hex_address(at)}")
            if at in instruction_map and instruction_map[at] != data:
                raise ValueError("conflicting instruction record lengths")
            instruction_map[at] = data
            for n, value in enumerate(data):
                if at + n in byte_map and byte_map[at + n] != value:
                    raise ValueError("conflicting overlapping instruction bytes")
                byte_map[at + n] = value
        instruction_sources.append({"path": relative, "records": len(records)})
    unselected = sorted(set(inventory) - selected)
    rom_calls = set()
    for row in inventory.values():
        for ref in row.get("references", []):
            if "CALL" not in ref.get("type", ""):
                continue
            try:
                target = address(ref["to"])
            except ValueError:
                continue
            if 0x00100000 <= target < 0x00200000:
                rom_calls.add(target)
    return {
        "schema_version": 1, "image_sha256": digest, "image_bytes": len(image),
        "limitations": LIMITATIONS, "inputs": inputs,
        "inventory": {"entries": len(inventory),
                      "with_pseudocode": sum(bool(r.get("decompiled")) for r in inventory.values()),
                      "decompilation_errors": sum(bool(r.get("error")) for r in inventory.values())},
        "focused_sources": focused,
        "focused_unique_entries": len(selected),
        "focused_entries_in_inventory": len(selected & set(inventory)),
        "focused_entries_outside_inventory": [hex_address(a) for a in sorted(selected - set(inventory))],
        "instruction_sources": instruction_sources,
        "byte_checked_instruction_addresses": len(instruction_map),
        "byte_checked_unique_flash_bytes": len(byte_map),
        "direct_rom_call_targets": [hex_address(a) for a in sorted(rom_calls)],
        "unselected_inventory_entries": [
            {"address": hex_address(a), "name": inventory[a].get("name"),
             "body": inventory[a].get("body"), "error": inventory[a].get("error")}
            for a in unselected],
        "semantic_review_count": None, "hardware_validation_count": None,
    }


def main(argv=None):
    """Run the command-line entry point.

    Args:
        argv: Argument list, or ``None`` to use ``sys.argv``.

    Returns:
        The process exit code: 0 on success, 2 on error.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, help="new output file; existing files are refused")
    args = parser.parse_args(argv)
    try:
        result = audit(args.manifest)
        serialized = json.dumps(result, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(serialized)
            print(json.dumps({k: result[k] for k in (
                "image_sha256", "image_bytes", "inventory", "focused_unique_entries",
                "focused_entries_in_inventory", "focused_entries_outside_inventory",
                "byte_checked_instruction_addresses", "byte_checked_unique_flash_bytes")}))
        else:
            print(serialized, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"coverage error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
