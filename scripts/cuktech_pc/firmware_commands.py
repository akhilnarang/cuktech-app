"""Describe measured 0073 AF07 frames offline; never send or construct writes.

Accepts exact known request shapes, not the firmware's permissive envelope.
Unknown/truncated/extra fields are rejected rather than inferred safe.
Run: ``uv run -m cuktech_pc.firmware_commands HEX_FRAME``.
"""

import argparse
import json

from .firmware_unpack import KNOWN_AD1204_0073_SHA256

PROTOCOL_BITS = {
    "C1": {"PD": 0, "PPS": 1, "UFCS": 2, "miPPS": 3},
    "C2": {"PD": 8, "PPS": 9, "UFCS": 10, "miPPS": 11},
    "C3": {"UFCS": 16, "SCP": 17},
    "A": {"UFCS": 24, "SCP": 25},
}
KNOWN_MASK = sum(1 << bit for port in PROTOCOL_BITS.values() for bit in port.values())
TIMEOUT_SECONDS = {1: 300, 2: 600, 3: 1800, 4: 0, 5: 60}


def describe(frame: bytes) -> dict:
    """Describe one F1 request frame from the static 0073 handler table.

    Args:
        frame: The request, 8 to 12 bytes, that starts with ``fedcba01f100``.

    Returns:
        A dict with the operation name, handler address, ``mutation`` flag
        and the decoded value fields. ``hardware_validated`` is always
        ``False``.

    Raises:
        ValueError: If the frame shape, group, selector or length is not one
            of the measured request shapes.
    """
    if not 8 <= len(frame) <= 12 or frame[:6] != bytes.fromhex("fedcba01f100"):
        raise ValueError("not an exact measured F1 request shape")
    group, selector = frame[6:8]
    result = {"firmware_sha256": KNOWN_AD1204_0073_SHA256, "request_hex": frame.hex(),
              "group": group, "selector": selector, "offline_only": True,
              "hardware_validated": False,
              "common_effect_if_delivered": "Pauses MIOT packing until disconnect; fields may be cached.",
              "scope": "Static handler behavior. This tool does not send data, authorize a write or prove a negotiated charging protocol."}
    if group == 2 and selector == 0 and len(frame) == 8:
        return dict(result, operation="combined status", mutation=False, handler="0041c888")
    if group != 1 or not 1 <= selector <= 9:
        raise ValueError("unmapped group/selector; no command inferred")
    read = {1: ("controller versions", "0041cae4"), 2: ("sensor/control caches", "0041c910"),
            3: ("unbound/default status", "0041c988"), 6: ("controller/protocol caches", "0041c9b4")}
    if selector in read:
        if len(frame) != 8:
            raise ValueError("status request must contain exactly eight bytes")
        name, handler = read[selector]
        return dict(result, operation=name, mutation=False, handler=handler)
    if selector in (4, 5, 9):
        if len(frame) != 9:
            raise ValueError("setting request requires one byte")
        value = frame[8]
        if selector == 4:
            return dict(result, operation="scene setting", handler="0041ca2c", value=value,
                        mutation=1 <= value <= 4, accepted_by_validator=1 <= value <= 4,
                        reply="returns current setting; readback still required", byte_order="u8")
        if selector == 5:
            return dict(result, operation="screen timeout setting", handler="0041ca6c", value=value,
                        mutation=value in TIMEOUT_SECONDS, accepted_by_validator=value in TIMEOUT_SECONDS,
                        seconds=TIMEOUT_SECONDS.get(value),
                        reply="returns current setting; readback still required", byte_order="u8")
        return dict(result, operation="Holiday artwork write" if value <= 1 else "Holiday artwork query",
                    handler="0041caac", value=value, mutation=value <= 1,
                    reply="returns current artwork flag", byte_order="u8")
    if len(frame) != 12:
        raise ValueError("port/protocol request requires exactly four payload bytes")
    if selector == 7:
        return dict(result, operation="port enables", mutation=True, handler="00422338",
                    ports={name: bool(value) for name, value in zip(PROTOCOL_BITS, frame[8:], strict=True)},
                    input_bytes=list(frame[8:]), argument_rule="each nonzero byte enables its port",
                    reply_hex="fedcba01f1070101ef", reply_verifies_setting=False)
    mask = int.from_bytes(frame[8:], "big")
    return dict(result, operation="protocol enable mask", mutation=True, handler="004223a8",
                byte_order="big", mask=mask, mask_hex=f"0x{mask:08x}",
                enabled={name: {protocol: bool(mask & (1 << bit)) for protocol, bit in bits.items()}
                         for name, bits in PROTOCOL_BITS.items()},
                unknown_bits_hex=f"0x{mask & (0xffffffff ^ KNOWN_MASK):08x}",
                reply_hex="fedcba01f1080101ef", reply_verifies_setting=False,
                protocol_note="Enable controls only; not active protocol-code identification. MIOT 2.21 uses its normal little-endian typed value instead.")


def main() -> int:
    """Run the command-line entry point and print the description as JSON.

    Returns:
        0 on success. Errors exit with code 2 through ``parser.exit``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hex_frame", help="measured AF07 request bytes, quoted if spaced")
    args = parser.parse_args()
    try:
        if len(args.hex_frame) > 128:
            raise ValueError("frame text exceeds budget")
        result = describe(bytes.fromhex(args.hex_frame))
    except ValueError as error:
        parser.exit(2, f"command description error: {error}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
