"""Overlay extracted unclassified source slices with automated function bodies.

This is source accounting, not code validation or firmware-image discovery.
Only local measured 0073 input/exports are accepted; no target is executed.
Run: ``uv run -m cuktech_pc.firmware_blob_inventory IMAGE EXTRACTION ANALYSIS --output FILE``.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from .firmware_unpack import KNOWN_AD1204_0073_SHA256, MAX_IMAGE


def union_size(intervals: list[tuple[int, int]]) -> int:
    """Calculate the number of bytes that a set of half-open intervals covers.

    Args:
        intervals: ``(start, stop)`` pairs. Overlaps are counted one time.

    Returns:
        The size of the union in bytes.

    Raises:
        ValueError: If a start is negative or a stop is less than its start.
    """
    total, end = 0, -1
    for start, stop in sorted(intervals):
        if start < 0 or stop < start:
            raise ValueError("invalid interval")
        total += max(0, stop - max(start, end))
        end = max(end, stop)
    return total


def body_ranges(body: str, base: int, size: int) -> list[tuple[int, int]]:
    """Get the address ranges of a Ghidra function body as image offsets.

    Args:
        body: The Ghidra body text, with ranges such as ``[0040e30c, 0040e3ff]``.
        base: The flash load address of offset 0.
        size: The image size in bytes. Ranges outside the image are dropped.

    Returns:
        Half-open ``(start, stop)`` offsets. The stop is one past the
        inclusive end address.
    """
    result = []
    for lo, hi in re.findall(r"\[([0-9a-fA-F]{8}),\s*([0-9a-fA-F]{8})\]", body):
        start, stop = int(lo, 16) - base, int(hi, 16) - base + 1
        if 0 <= start < stop <= size:
            result.append((start, stop))
    return result


def inventory(image: Path, extraction: Path, analysis: Path) -> dict:
    """Count the function-body, ASCII and pointer bytes in each unclassified range.

    Args:
        image: The raw 0073 flash image.
        extraction: The directory with ``source-map.json`` from ``firmware_unpack``.
        analysis: The directory with ``analysis.json`` and ``functions.jsonl``.

    Returns:
        The report dict, with per-chunk counts, totals, signature hits and
        limitations.

    Raises:
        ValueError: If the image is too large, the hashes or sizes do not
            match, a range is outside the image or has a wrong digest, or
            ranges overlap.
    """
    if image.stat().st_size > MAX_IMAGE:
        raise ValueError("raw image exceeds budget")
    raw = image.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    layout = json.loads((extraction / 'source-map.json').read_text(encoding='utf-8'))
    metadata = json.loads((analysis / 'analysis.json').read_text(encoding='utf-8'))
    if sha != KNOWN_AD1204_0073_SHA256 or layout['firmware_sha256'] != sha or metadata['sha256'] != sha:
        raise ValueError("image/extraction/analysis identity mismatch")
    if layout['firmware_size'] != len(raw):
        raise ValueError("source-map size mismatch")
    base = layout['flash_base']
    functions_file = analysis / 'functions.jsonl'
    functions = [json.loads(line) for line in functions_file.read_text(encoding='utf-8').splitlines()]
    ranges = [(a,b,row['address']) for row in functions for a,b in body_ranges(row['body'],base,len(raw))]
    result, extents = [], []
    for chunk in layout['unclassified_ranges']:
        start, size = chunk['offset'], chunk['size']
        if start < 0 or size <= 0 or start + size > len(raw):
            raise ValueError("unclassified source outside image")
        stop = start + size
        data = raw[start:stop]
        if hashlib.sha256(data).hexdigest() != chunk['sha256']:
            raise ValueError("unclassified source digest mismatch")
        extents.append((start,stop))
        hits = [(max(start,a),min(stop,b),name) for a,b,name in ranges if a < stop and start < b]
        strings = list(re.finditer(rb'[\x20-\x7e]{5,}',data))
        result.append({"source_offset":start,"source_size":size,"sha256":chunk['sha256'],
                       "canonical_function_body_bytes":union_size([(a,b) for a,b,_ in hits]),
                       "function_entries":sorted({name for _,_,name in hits}),
                       "ascii_candidate_bytes":sum(len(m.group()) for m in strings),
                       "ascii_candidates":len(strings),
                       "flash_pointer_words":sum(base <= int.from_bytes(raw[i:i+4],'little') < base+len(raw)
                                                 for i in range((start+3)&~3,stop-3,4))})
    if union_size(extents) != sum(stop-start for start,stop in extents):
        raise ValueError("unclassified ranges overlap")
    return {"firmware_sha256":sha,"source_map_sha256":hashlib.sha256((extraction/'source-map.json').read_bytes()).hexdigest(),
            "functions_sha256":hashlib.sha256(functions_file.read_bytes()).hexdigest(),
            "unclassified_source_bytes":sum(r['source_size'] for r in result),
            "bytes_in_canonical_function_bodies":sum(r['canonical_function_body_bytes'] for r in result),
            "chunks_with_function_overlap":sum(bool(r['canonical_function_body_bytes']) for r in result),
            "signature_hits":{name:raw.count(sig) for name,sig in {'ELF':b'\x7fELF','PNG':b'\x89PNG\r\n\x1a\n','ZIP_local_header':b'PK\x03\x04'}.items()},
            "chunks":result,
            "limitations":["Automated function bodies can include data or imperfect boundaries; overlap is not verified machine code or semantic coverage.",
                           "ASCII candidates can be code coincidences; pointer-looking words do not prove objects or embedded images.",
                           "Signature absence does not exclude headerless, compressed, encrypted or other-architecture controller firmware.",
                           "No new file boundaries, protocol names, flashing route or device capability is inferred."]}


def main() -> int:
    """Run the command-line entry point and write the report to a new file.

    Returns:
        0 on success. Errors exit with code 2 through ``parser.exit``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('extraction',type=Path)
    parser.add_argument('analysis',type=Path)
    parser.add_argument('--output',type=Path,required=True,help='new report file')
    args = parser.parse_args()
    try:
        report = inventory(args.image,args.extraction,args.analysis)
        with args.output.open('x',encoding='utf-8') as stream:
            json.dump(report,stream,indent=2)
    except (ValueError,OSError,KeyError,TypeError) as error:
        parser.exit(2,f'blob inventory error: {error}\n')
    print(json.dumps({key:report[key] for key in ('unclassified_source_bytes','bytes_in_canonical_function_bodies','chunks_with_function_overlap','signature_hits')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
