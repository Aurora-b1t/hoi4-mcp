"""Call-xref for the ctor hunt: find operator new (size in ecx) and the common
Post callee around command construction sites."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import capstone

from research.win_disasm import pe, disasm, show, func_end

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def call_xrefs(target_rva: int) -> list[int]:
    """All E8 rel32 call sites targeting target_rva (within .text)."""
    p = pe()
    rva0, size, raw = p.text
    out = []
    tgt = target_rva
    i = 0
    n = len(raw) - 5
    while i < n:
        j = raw.find(b"\xe8", i)
        if j < 0 or j >= n:
            break
        rel = struct.unpack_from("<i", raw, j + 1)[0]
        if rva0 + j + 5 + rel == tgt:
            out.append(rva0 + j)
        i = j + 1
    return out


def context(rva: int, before=0x50, after=0x60) -> list[tuple]:
    lo = max(rva - before, pe().text[0])
    return disasm(lo, rva - lo + after)


def show_ctx(rva, before=0x50, after=0x60, mark=True):
    for a, m, o, t, _b in context(rva, before, after):
        flag = "  <<< CALL" if mark and a == rva else ""
        print(f"{a:#x}: {m} {o}{t}{flag}")


if __name__ == "__main__":
    targets = [int(x, 16) for x in sys.argv[1:]] or [0x1146e60, 0x1146ea0]
    for t in targets:
        print(f"===== callers of {t:#x} =====")
        xs = call_xrefs(t)
        print(f"  {len(xs)} call sites")
        for x in xs[:12]:
            print(f"  ---- site {x:#x} (func?) ----")
            show_ctx(x, 0x48, 0x50)
