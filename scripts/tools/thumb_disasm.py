"""Disassemble Thumb instructions at an address of an AD1204 image.

Usage: uv run --with capstone python tools/thumb_disasm.py FILE ADDRESS_HEX [COUNT]
"""

import sys

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

BASE = 0x403000  # flash load address of the AD1204 image
path, address, count = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3]) if len(sys.argv) > 3 else 16
with open(path, "rb") as f:
    data = f.read()
offset = address - BASE
for insn in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(data[offset:offset + count * 4], address):
    print(f"{insn.address:#x}  {insn.bytes.hex(' '):<12}  {insn.mnemonic} {insn.op_str}")
    count -= 1
    if not count:
        break
