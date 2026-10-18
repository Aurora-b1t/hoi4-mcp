"""find_vft_refs.py — who references a vftable RVA, and what do they do?

The 24 日 crash was a misattributed constructor: the note said "SetNationalFocus
ctor = 0x1146E60", but that ctor installs vftable 0x2996070
(.?AVCSetFuelPriorityCommand@@ per RTTI), so the blob we posted had the right
vtable and the wrong field layout — the game AV'd while describing it.

Everything about a command class can be recovered from xrefs to its vftable:
the constructor (lea rax,[rip+vft]; mov [rcx],rax) and the UI call sites (the
same lea followed by `mov ecx,<size>; call operator new`). This tool prints
both, with the surrounding disassembly.

Usage:
  python research/find_vft_refs.py 0x2996458
  python research/find_vft_refs.py 0x2996458 --ctor 0x1146E60
  python research/find_vft_refs.py --list CSetNationalFocusCommand
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.win_disasm import disasm, pe                              # noqa: E402

RTTI = Path(__file__).resolve().parents[1] / "hoi4copilot" / "tables" / "generated" / "rtti.json"


def classes_by_name() -> dict:
    d = json.loads(RTTI.read_text(encoding="utf-8"))
    return {c["name"]: c for c in d["classes"]}


def vft_owner(rva: int) -> list[str]:
    return [n for n, c in classes_by_name().items() if rva in (c.get("vftable_rvas") or [])]


def scan_lea_refs(target_rva: int) -> list[tuple[int, int]]:
    """(rva_of_insn, target) for every RIP-relative lea in .text hitting target."""
    p = pe()
    va, vsize, data = p.section(".text")
    hits = []
    for i in range(len(data) - 7):
        b0 = data[i]
        if b0 not in (0x48, 0x4C, 0x49, 0x4D):
            continue
        if data[i + 1] != 0x8D:
            continue
        modrm = data[i + 2]
        if (modrm & 0xC7) != 0x05:          # mod=00, rm=101 => RIP-relative
            continue
        disp = int.from_bytes(data[i + 3:i + 7], "little", signed=True)
        insn_rva = va + i
        if insn_rva + 7 + disp == target_rva:
            hits.append((insn_rva, insn_rva + 7 + disp))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rva", nargs="?", help="vftable RVA (hex ok)")
    ap.add_argument("--list", help="class name: print its vftables + xrefs")
    ap.add_argument("--span", type=lambda s: int(s, 0), default=0x60,
                    help="bytes of context to disassemble at each hit")
    a = ap.parse_args()

    p = pe()
    if a.list:
        by = classes_by_name()
        cls = by.get(a.list) or by.get(f".?AV{a.list}@@")
        if not cls:
            near = [n for n in by if a.list.lower() in n.lower()][:10]
            print(f"class not found; near: {near}")
            return 2
        print(f"{cls['name']}: vftables "
              f"{[hex(x) for x in cls.get('vftable_rvas') or []]}")
        for vt in cls.get("vftable_rvas") or []:
            for insn, _t in scan_lea_refs(vt):
                print(f"  xref @ {insn:#x}")
        return 0

    target = int(a.rva, 0)
    print(f"vftable {target:#x} owners: {vft_owner(target)}")
    hits = scan_lea_refs(target)
    print(f"{len(hits)} RIP-relative lea xrefs in .text")
    for insn, _t in hits:
        print(f"\n--- xref at {insn:#x} ---")
        for addr, mnem, ops, tgt, raw in disasm(insn - 0x20, a.span + 0x20):
            print(f"  {addr:#010x}: {raw.hex():<20} {mnem} {ops}{tgt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
