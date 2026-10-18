"""disasm_focus_cmd.py — 24 日 crash forensics for SetNationalFocusCommand.

The live send AV'd at RVA 0x24c2f0d (exception 0xc0000005) — inside the
"describe/log" helper that day-10 notes identified as the target of the
command's vfn[1]. This script disassembles, offline:

  * both constructors (0x1146E60 / 0x1146EA0) — the authoritative list of
    fields a hand-built blob must reproduce,
  * the crash site (0x24c2e20 .. 0x24c2f60),
  * the command vtable at 0x2996458.

Usage: python research/disasm_focus_cmd.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.win_disasm import disasm, pe                              # noqa: E402

CTOR = 0x1146E60
CTOR_VARIANT = 0x1146EA0
CRASH_SITE = 0x24C2E20
VFT = 0x2996458
POST = 0x2250B00
OPERATOR_NEW = 0x21C9AF0


def dump(tag: str, rva: int, n: int = 0x100) -> None:
    p = pe()
    print(f"\n=== {tag} @ rva {rva:#x} ===")
    for addr, mnem, ops, tgt, raw in disasm(rva, n):
        mark = "  <== CRASH SITE" if addr == 0x24C2F0D else ""
        print(f"  {addr:#010x}: {raw.hex():<24} {mnem} {ops}{tgt}{mark}")


def main() -> int:
    p = pe()
    print(f"image base {p.base:#x}")

    dump("SetNationalFocus ctor", CTOR, 0xC0)
    dump("SetNationalFocus ctor (variant)", CTOR_VARIANT, 0xC0)
    dump("crash site (kind-describe helper)", CRASH_SITE, 0x140)

    print(f"\n=== vtable @ {VFT:#x} (first 0x10 slots) ===")
    for i in range(0x10):
        fn = int.from_bytes(p.read_rva(VFT + i * 8, 8), "little")
        name = ""
        if p.base <= fn < p.base + 0x4000000:
            name = f"-> rva {fn - p.base:#x}"
        print(f"  +{i * 8:#04x}: {fn:#018x} {name}")

    print(f"\n=== around operator new ({OPERATOR_NEW:#x}) / Post ({POST:#x}) ===")
    for addr, mnem, ops, tgt, raw in disasm(OPERATOR_NEW, 0x30):
        print(f"  {addr:#010x}: {mnem} {ops}")
    for addr, mnem, ops, tgt, raw in disasm(POST, 0x60):
        print(f"  {addr:#010x}: {mnem} {ops}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
