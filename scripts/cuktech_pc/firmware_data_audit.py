"""Identify measured 0073 crypto constants and remaining host-code gaps offline.

Generates standard tables independently; does not label every nearby byte or
infer a secondary executable from signatures/automated function boundaries.
Run: ``uv run -m cuktech_pc.firmware_data_audit IMAGE ANALYSIS --output FILE``.
"""

import argparse
import hashlib
import json
from pathlib import Path

from .firmware_blob_inventory import body_ranges
from .firmware_unpack import KNOWN_AD1204_0073_SHA256, MAX_IMAGE


def _multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with the AES polynomial 0x11b."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ (0x11b if a & 0x80 else 0)) & 255
        b >>= 1
    return result


def aes_sbox() -> bytes:
    """Generate the AES S-box from its definition (GF(2^8) inverse and affine map).

    Returns:
        The 256-byte S-box.
    """
    result = []
    for value in range(256):
        inverse = 0
        if value:
            inverse, power, exponent = 1, value, 254
            while exponent:
                if exponent & 1:
                    inverse = _multiply(inverse, power)
                power = _multiply(power, power)
                exponent >>= 1
        transformed = inverse ^ 0x63
        for shift in range(1, 5):
            transformed ^= ((inverse << shift) | (inverse >> (8 - shift))) & 255
        result.append(transformed)
    return bytes(result)


def sha256_constants() -> bytes:
    """Generate the 64 SHA-256 round constants K from the first 64 primes.

    Each word is the first 32 fraction bits of the cube root of a prime. The
    calculation uses only integers, so there is no float rounding.

    Returns:
        64 words of 4 bytes, little-endian (256 bytes), as stored in the image.
    """
    primes = []
    candidate = 2
    while len(primes) < 64:
        if all(candidate % prime for prime in primes if prime * prime <= candidate):
            primes.append(candidate)
        candidate += 1
    words = []
    for prime in primes:
        # Exact integer floor(cuberoot(prime) * 2**32); no float rounding.
        target, lo, hi = prime << 96, 0, 1 << 36
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if mid ** 3 <= target:
                lo = mid
            else:
                hi = mid
        words.append((lo & 0xffffffff).to_bytes(4, 'little'))
    return b''.join(words)


def gaps(start: int, stop: int, covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Find the parts of ``[start, stop)`` that no covered interval includes.

    Args:
        start: The first offset of the area.
        stop: The offset after the last byte of the area.
        covered: Half-open ``(a, b)`` intervals. They can overlap or go
            outside the area.

    Returns:
        Sorted half-open ``(a, b)`` gaps.

    Raises:
        ValueError: If an interval is negative or its end is before its start.
    """
    if start < 0 or stop < start or any(a < 0 or b < a for a, b in covered):
        raise ValueError('invalid interval')
    cursor, result = start, []
    for a, b in sorted(covered):
        a, b = max(start, a), min(stop, b)
        if b <= a:
            continue
        if a > cursor:
            result.append((cursor, a))
        cursor = max(cursor, b)
    if cursor < stop:
        result.append((cursor, stop))
    return result


def audit(image: Path, analysis: Path) -> dict:
    """Check the known crypto tables in the 0073 image and measure host-code gaps.

    The SHA-256 K words at 0x2219c and the AES S-box at 0x22390 must match
    the generated tables. The gap search covers offsets 0x130 to 0x21f8c.

    Args:
        image: The raw 0073 flash image.
        analysis: The directory with ``analysis.json`` and ``functions.jsonl``.

    Returns:
        The report dict with the table matches, gap counts and limitations.

    Raises:
        ValueError: If a file is too large, the hashes do not match, or a
            table differs from the generated table.
    """
    if image.stat().st_size > MAX_IMAGE:
        raise ValueError('image exceeds budget')
    raw = image.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    metadata = json.loads((analysis / 'analysis.json').read_text(encoding='utf-8'))
    if digest != KNOWN_AD1204_0073_SHA256 or metadata['sha256'] != digest:
        raise ValueError('image/analysis identity mismatch')
    source = analysis / 'functions.jsonl'
    if source.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('function export exceeds budget')
    exported = source.read_bytes()
    functions = [json.loads(line) for line in exported.decode('utf-8').splitlines() if line.strip()]
    covered = [span for row in functions for span in body_ranges(row['body'], 0x403000, len(raw))]
    matches = []
    for name, offset, generated in [('SHA-256 K words', 0x2219c, sha256_constants()),
                                    ('AES S-box', 0x22390, aes_sbox())]:
        observed = raw[offset:offset + len(generated)]
        if observed != generated:
            raise ValueError(f'{name} differs from independently generated table')
        matches.append({'name': name, 'offset': offset, 'length': len(generated),
                        'sha256': hashlib.sha256(observed).hexdigest(), 'entire_table_matches': True})
    remaining = gaps(0x130, 0x21f8c, covered)
    return {'firmware_sha256': digest, 'functions_sha256': hashlib.sha256(exported).hexdigest(),
            'constant_tables': matches,
            'host_interval': {'start': 0x130, 'stop_exclusive': 0x21f8c,
                              'outside_body_bytes': sum(b - a for a, b in remaining),
                              'largest_gap': max(b - a for a, b in remaining),
                              'gaps_at_least_256': [{'offset': a, 'size': b - a} for a, b in remaining if b - a >= 256]},
            'limitations': ['Exact generated-table identity classifies only the returned byte ranges.',
                            'Automated function bodies can be incomplete or include data; gaps are not proven executable/image boundaries.',
                            'No secondary controller image, protocol capability or flashing route is established.']}


def main() -> int:
    """Run the command-line entry point and write the report to a new file.

    Returns:
        0 on success. Errors exit with code 2 through ``parser.exit``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('analysis', type=Path)
    parser.add_argument('--output', type=Path, required=True, help='new report file')
    args = parser.parse_args()
    try:
        report = audit(args.image, args.analysis)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f'data audit error: {error}\n')
    print(json.dumps({'matched_table_bytes': sum(row['length'] for row in report['constant_tables']),
                      'largest_host_gap': report['host_interval']['largest_gap']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
