"""Read-only, offline lookups in ExportChargerFirmware JSON exports.

No firmware execution, network, Ghidra installation, or third-party package is
required. Address arguments are hexadecimal; ranges include both endpoints.
Run: ``uv run -m cuktech_pc.firmware_evidence --analysis DIR {identity,function,strings,refs,neighbors}``.
"""

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import sys


LIMITATIONS = [
    "Static exported observations only; no runtime or hardware behavior is proved.",
    "Only references present in these exports are indexed. Indirect calls, pointer arithmetic, ROM code, undefined data, and undiscovered functions may be missing.",
    "Incoming references match their exported target address, not the size of a load/store or an inferred structure field.",
    "Ghidra Stack[...] targets remain in function records but are excluded from the numeric-address reference index and call graph.",
    "The export SHA-256 identifies the analyzed image as reported by Ghidra; the image itself is not reopened or independently verified here.",
]


def address(value: str | int) -> int:
    """Parse a hexadecimal address.

    Args:
        value: An int, or hex text with an optional ``0x`` prefix (1 to 16 digits).

    Returns:
        The address as an int, 0 to 2**64 - 1.

    Raises:
        ValueError: If the value is a bool, is not valid hex text, or is
            outside the unsigned 64-bit range.
    """
    if isinstance(value, bool):
        raise ValueError("invalid hexadecimal address")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", value):
        result = int(value, 16)
    else:
        raise ValueError(f"invalid hexadecimal address: {value!r}")
    if not 0 <= result <= 0xffffffffffffffff:
        raise ValueError("address outside unsigned 64-bit range")
    return result


def address_range(value: str) -> tuple[int, int]:
    """Parse ``HEX_ADDRESS`` or an inclusive ``HEX_START:HEX_END`` range.

    Args:
        value: The range text. One address gives a range of one byte.

    Returns:
        The ``(start, end)`` tuple. Both ends are inclusive.

    Raises:
        ValueError: If the text has more than one colon, an address is not
            valid, or the end is before the start.
    """
    parts = value.split(":")
    if len(parts) not in (1, 2):
        raise ValueError("expected HEX_ADDRESS or HEX_START:HEX_END (inclusive)")
    start = address(parts[0])
    end = address(parts[-1])
    if end < start:
        raise ValueError("address range end precedes start")
    return start, end


def hex_address(value: int) -> str:
    """Format an address as at least 8 lowercase hex digits without a prefix.

    Args:
        value: The address.

    Returns:
        The hex text.
    """
    return f"{value:08x}"


def page(rows: list, limit: int, offset: int = 0) -> dict:
    """Return one page of a result list, with counts.

    Args:
        rows: The complete result list.
        limit: The maximum number of items on the page.
        offset: The index of the first item.

    Returns:
        A dict with ``total``, ``offset``, ``limit``, ``returned``,
        ``truncated`` and ``items``.
    """
    return {"total": len(rows), "offset": offset, "limit": limit,
            "returned": len(rows[offset:offset + limit]),
            "truncated": offset > 0 or offset + limit < len(rows),
            "items": rows[offset:offset + limit]}


def clipped(value: str, limit: int) -> dict:
    """Cut text to a maximum length and record if it was cut.

    Args:
        value: The text.
        limit: The maximum number of characters.

    Returns:
        A dict with ``text``, ``characters`` (the original length) and
        ``truncated``.
    """
    return {"text": value[:limit], "characters": len(value), "truncated": len(value) > limit}


class AnalysisIndex:
    """In-memory index of one ExportChargerFirmware export directory.

    The constructor loads ``analysis.json``, ``functions.jsonl`` and
    ``strings.jsonl``, checks every record, and builds a sorted list of
    unique numeric-address references. ``Stack[...]`` targets are only counted.

    Args:
        directory: The directory with the three export files.

    Raises:
        ValueError: If a file is not valid JSON or UTF-8, a record or
            address is not valid, or a function entry is duplicated.
        OSError: If a file cannot be read.

    Attributes:
        directory: The export directory.
        digests: SHA-256 hex digest of each loaded file, by file name.
        metadata: The ``analysis.json`` object.
        functions: The function records.
        strings: The string records.
        by_address: The function records by entry address.
        references: Unique references, sorted by target, source and type.
        stack_reference_count: The number of ``Stack[...]`` references skipped.
    """
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.digests = {}
        self.metadata = self._load("analysis.json")
        if not isinstance(self.metadata, dict):
            raise ValueError("analysis.json must contain an object")
        self.functions = self._load_lines("functions.jsonl")
        self.strings = self._load_lines("strings.jsonl")
        self.by_address = {}
        self.references = []
        self.stack_reference_count = 0
        seen = set()
        for number, function in enumerate(self.functions, 1):
            self._validate_record(function, f"functions.jsonl:{number}")
            at = address(function["address"])
            if at in self.by_address:
                raise ValueError(f"duplicate function entry {hex_address(at)}")
            self.by_address[at] = function
            for ref in function.get("references", []):
                self._add_reference(ref, at, "function.references", seen)
            for ref in function.get("callers", []):
                self._add_reference(ref, None, "function.callers", seen)
        for number, string in enumerate(self.strings, 1):
            self._validate_record(string, f"strings.jsonl:{number}")
            if not isinstance(string.get("value"), str):
                raise ValueError(f"strings.jsonl:{number}: value must be a string")
            for ref in string.get("references", []):
                self._add_reference(ref, None, "string.references", seen)
        self.references.sort(key=lambda r: (address(r["to"]), address(r["from"]), r["type"]))

    def _load(self, name: str):
        data = (self.directory / name).read_bytes()
        self.digests[name] = hashlib.sha256(data).hexdigest()
        try:
            return json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f"{name}: invalid JSON: {exc}") from exc

    def _load_lines(self, name: str) -> list:
        data = (self.directory / name).read_bytes()
        self.digests[name] = hashlib.sha256(data).hexdigest()
        try:
            lines = data.decode("utf-8-sig").splitlines()
        except UnicodeError as exc:
            raise ValueError(f"{name}: invalid UTF-8") from exc
        result = []
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("record must be an object")
            except ValueError as exc:
                raise ValueError(f"{name}:{number}: {exc}") from exc
            result.append(row)
        return result

    @staticmethod
    def _validate_record(record: dict, location: str):
        try:
            address(record["address"])
            for field in ("references", "callers"):
                refs = record.get(field, [])
                if not isinstance(refs, list):
                    raise ValueError(f"{field} must be an array")
                for ref in refs:
                    if not isinstance(ref, dict):
                        raise ValueError("reference must be an object")
                    address(ref["from"])
                    target = ref["to"]
                    if not (isinstance(target, str) and re.fullmatch(r"Stack\[-?0x[0-9a-fA-F]+\]", target)):
                        address(target)
                    if not isinstance(ref.get("type"), str) or not ref["type"]:
                        raise ValueError("reference type must be a nonempty string")
                    if ref.get("function") is not None:
                        address(ref["function"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"{location}: {exc}") from exc

    def _add_reference(self, ref: dict, owner: int | None, source: str, seen: set):
        if isinstance(ref["to"], str) and ref["to"].startswith("Stack["):
            self.stack_reference_count += 1
            return
        owner = address(ref["function"]) if ref.get("function") is not None else owner
        key = (address(ref["from"]), address(ref["to"]), ref["type"], owner)
        if key in seen:
            return
        seen.add(key)
        self.references.append({"from": hex_address(key[0]), "to": hex_address(key[1]),
                                "type": ref["type"],
                                "function": None if owner is None else hex_address(owner),
                                "source": source})

    def identity(self) -> dict:
        """Describe the loaded export and its file hashes.

        Returns:
            A dict with the directory, program, image SHA-256, language, image
            base, record counts, skipped stack references and file digests.
        """
        return {"directory": str(self.directory.resolve()),
                "program": self.metadata.get("program"), "image_sha256": self.metadata.get("sha256"),
                "language": self.metadata.get("language"), "image_base": self.metadata.get("image_base"),
                "loaded_function_count": len(self.functions), "loaded_string_count": len(self.strings),
                "excluded_stack_reference_occurrences": self.stack_reference_count,
                "export_file_sha256": self.digests}

    def function(self, target: str, limit: int, text_limit: int) -> dict:
        """Look up one function by exact entry address or exact name.

        An address must be an entry point. The function does not search for a
        function that contains the address.

        Args:
            target: Hex entry address, or the exact function name.
            limit: The maximum number of callers and references to return.
            text_limit: The maximum number of decompiled characters.

        Returns:
            A dict with the address, name, body, signature, error, clipped
            pseudocode, and pages of callers and references.

        Raises:
            ValueError: If no function matches, or a name matches more than one.
        """
        # Address is an exact entry point, never an assumed containing function.
        try:
            row = self.by_address.get(address(target))
        except ValueError:
            matches = [f for f in self.functions if f.get("name") == target]
            if len(matches) > 1:
                raise ValueError("function name is ambiguous; use an exact entry address") from None
            row = matches[0] if matches else None
        if row is None:
            raise ValueError(f"no exact function entry or name found: {target}")
        return {"address": row["address"], "name": row.get("name"), "body": row.get("body"),
                "signature": row.get("signature"), "error": row.get("error"),
                "decompiled": clipped(row.get("decompiled") or "", text_limit),
                "callers": page(row.get("callers", []), limit),
                "references": page(row.get("references", []), limit)}

    def incoming(self, target: str, types: list[str], limit: int, offset: int) -> dict:
        """List the references to an address or an inclusive address range.

        Args:
            target: ``HEX_ADDRESS`` or ``HEX_START:HEX_END``.
            types: Reference types to keep (case-insensitive). Empty keeps all.
            limit: The page size.
            offset: The index of the first result.

        Returns:
            A dict with the range, the type filter and a page of references.

        Raises:
            ValueError: If ``target`` is not a valid address or range.
        """
        start, end = address_range(target)
        wanted = set(t.upper() for t in types)
        rows = [r for r in self.references if start <= address(r["to"]) <= end
                and (not wanted or r["type"].upper() in wanted)]
        return {"range": [hex_address(start), hex_address(end)], "types": sorted(wanted),
                "references": page(rows, limit, offset)}

    def search_strings(self, query: str, limit: int, offset: int, text_limit: int) -> dict:
        """Find strings that contain a literal substring (case-insensitive).

        Args:
            query: The substring. It must not be empty.
            limit: The page size. Each string also shows up to 10 references.
            offset: The index of the first result.
            text_limit: The maximum number of characters per string.

        Returns:
            A dict with the query, the match rule and a page of strings.

        Raises:
            ValueError: If ``query`` is empty.
        """
        if not query:
            raise ValueError("string search must be nonempty")
        rows = []
        for row in self.strings:
            if query.casefold() in row["value"].casefold():
                rows.append({"address": row["address"], "value": clipped(row["value"], text_limit),
                             "references": page(row.get("references", []), min(limit, 10))})
        return {"query": query, "match": "case-insensitive literal substring",
                "strings": page(rows, limit, offset)}

    def neighborhood(self, target: str, direction: str, depth: int, limit: int, max_nodes: int) -> dict:
        """Walk the call graph from one function, breadth-first.

        Only exported CALL references with a known owner function are edges.

        Args:
            target: Hex entry address of an exported function.
            direction: ``"both"``, ``"callers"`` or ``"callees"``.
            depth: The maximum number of call steps from the root.
            limit: The page size for nodes and edges.
            max_nodes: The maximum number of visited nodes. The walk stops
                adding nodes after this limit and sets ``search_truncated``.

        Returns:
            A dict with the root, settings, a page of nodes (with depth and
            name) and a page of caller/callee edges.

        Raises:
            ValueError: If ``target`` is not an exported function entry.
        """
        root = address(target)
        if root not in self.by_address:
            raise ValueError("neighborhood root must be an exact exported function entry")
        outgoing, incoming = {}, {}
        for ref in self.references:
            if "CALL" not in ref["type"].upper() or ref["function"] is None:
                continue
            caller, callee = address(ref["function"]), address(ref["to"])
            outgoing.setdefault(caller, set()).add(callee)
            incoming.setdefault(callee, set()).add(caller)
        visited = {root: 0}
        queue = deque([root])
        edges = set()
        capped = False
        while queue:
            node = queue.popleft()
            if visited[node] >= depth:
                continue
            adjacent = []
            if direction in ("both", "callees"):
                adjacent.extend((dest, node, dest) for dest in sorted(outgoing.get(node, [])))
            if direction in ("both", "callers"):
                adjacent.extend((src, src, node) for src in sorted(incoming.get(node, [])))
            for neighbor, caller, callee in adjacent:
                if neighbor not in visited:
                    if len(visited) >= max_nodes:
                        capped = True
                        continue
                    visited[neighbor] = visited[node] + 1
                    queue.append(neighbor)
                edges.add((caller, callee))
        nodes = [{"address": hex_address(at), "depth": d,
                  "name": self.by_address.get(at, {}).get("name"), "exported_function": at in self.by_address}
                 for at, d in sorted(visited.items(), key=lambda item: (item[1], item[0]))]
        return {"root": hex_address(root), "direction": direction, "depth": depth,
                "search_node_limit": max_nodes, "search_truncated": capped,
                "nodes": page(nodes, limit),
                "edges": page([{"caller": hex_address(a), "callee": hex_address(b)}
                               for a, b in sorted(edges)], limit),
                "edge_scope": "Exported CALL references only; non-call address references excluded."}


def bounded_int(minimum: int, maximum: int):
    """Make an argparse ``type`` that accepts an int in a closed range.

    Args:
        minimum: The smallest accepted value.
        maximum: The largest accepted value.

    Returns:
        A parser function. It raises ``argparse.ArgumentTypeError`` for a
        value outside the range and ``ValueError`` for text that is not an int.
    """
    def parse(value: str):
        number = int(value)
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"expected {minimum}..{maximum}")
        return number
    return parse


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point and print the result as JSON.

    Args:
        argv: Argument list, or ``None`` to use ``sys.argv``.

    Returns:
        The process exit code: 0 on success, 2 on error.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path, required=True, help="directory containing the three JSON exports")
    parser.add_argument("--limit", type=bounded_int(1, 200), default=30, help="maximum records per result array (default 30)")
    parser.add_argument("--offset", type=bounded_int(0, 10000000), default=0, help="strings/refs result offset")
    parser.add_argument("--text-limit", type=bounded_int(0, 100000), default=12000, help="maximum decompiled/string characters per item")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("identity")
    function = sub.add_parser("function")
    function.add_argument("target", help="exact hexadecimal entry address or exact function name")
    strings = sub.add_parser("strings")
    strings.add_argument("query", help="literal case-insensitive substring")
    refs = sub.add_parser("refs")
    refs.add_argument("target", help="hexadecimal address or inclusive START:END")
    refs.add_argument("--type", action="append", default=[], help="exact exported type; repeat to include multiple types")
    graph = sub.add_parser("neighbors")
    graph.add_argument("target", help="exact hexadecimal function entry address")
    graph.add_argument("--direction", choices=["both", "callers", "callees"], default="both")
    graph.add_argument("--depth", type=bounded_int(0, 8), default=1)
    graph.add_argument("--max-nodes", type=bounded_int(1, 10000), default=500)
    args = parser.parse_args(argv)
    try:
        index = AnalysisIndex(args.analysis)
        if args.command == "identity":
            result = {"metadata": index.metadata}
        elif args.command == "function":
            result = index.function(args.target, args.limit, args.text_limit)
        elif args.command == "strings":
            result = index.search_strings(args.query, args.limit, args.offset, args.text_limit)
        elif args.command == "refs":
            result = index.incoming(args.target, args.type, args.limit, args.offset)
        else:
            result = index.neighborhood(args.target, args.direction, args.depth, args.limit, args.max_nodes)
        print(json.dumps({"analysis": index.identity(), "limitations": LIMITATIONS + index.metadata.get("limitations", []),
                          "result": result}, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"firmware-evidence: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
