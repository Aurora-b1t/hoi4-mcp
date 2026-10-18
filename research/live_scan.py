"""Live vftable instance scan for the write/read-layer key singletons."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from hoi4_mcp.process.attach import Game
from hoi4_mcp.process.instances import _readable_regions
from hoi4_mcp.process import win32ext as w

RTTI = json.loads((Path(__file__).resolve().parents[1] / "hoi4_mcp/tables/generated/rtti.json").read_text())
BY_VFT = {}
for c in RTTI["classes"]:
    for r in c["vftable_rvas"]:
        BY_VFT[r] = c["name"]


def vftable_class(p, vft_va: int):
    return BY_VFT.get(vft_va - p.base)


def scan_vftables(p, vft_rvas: list[int]) -> dict[int, list[int]]:
    """Fast big-chunk scan: {rva: [instance addrs]}"""
    targets = sorted({p.base + r: r for r in vft_rvas}.items())
    uniq = np.array([t[0] for t in targets], dtype=np.uint64)
    found = {}
    chunk = 1 << 24
    for mbi in _readable_regions(p):
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(chunk, end - addr)
            try:
                raw = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            m = len(raw) // 8
            if not m:
                addr += n
                continue
            q = np.frombuffer(raw[: m * 8], dtype=np.uint64)
            pos = np.searchsorted(uniq, q)
            pos_c = np.minimum(pos, len(uniq) - 1)
            hit = uniq[pos_c] == q
            for i in np.nonzero(hit)[0].tolist():
                rva = targets[pos_c[i]][1]
                found.setdefault(rva, []).append(addr + i * 8)
            addr += n
    return found


def dump_instance(p, addr, n, label, width=16):
    raw = p.memory.rpm(addr, n)
    print(f"--- {label} @ {addr:#x} ({n:#x} bytes)")
    for i in range(0, len(raw), width):
        line = raw[i:i + width]
        print(f"  +{i:#06x}: {line.hex(' ')}")
    return raw


def main():
    g = Game()
    p = g.proc
    m = p.memory
    base = p.base

    wanted = {}
    for name in (".?AVCInGameIdler@@", ".?AVCGamePlaySettings@@",
                 ".?AVCCurrentGameState@@", ".?AVCCountry@@",
                 ".?AVCGameIdler@@", ".?AVCGameApplication@@"):
        for c in RTTI["classes"]:
            if c["name"] == name:
                wanted[name] = c["vftable_rvas"]
    flat = [r for rs in wanted.values() for r in rs]
    print(f"scanning {len(flat)} vftables of {len(wanted)} classes ...")
    found = scan_vftables(p, flat)
    for name, rvas in wanted.items():
        for r in rvas:
            hits = found.get(r, [])
            if hits:
                print(f"{name}: vftable {r:#x} -> {len(hits)} inst {[hex(a) for a in hits[:6]]}")

    # follow the idler chain
    idlers = []
    for r in wanted.get(".?AVCInGameIdler@@", []):
        idlers += found.get(r, [])
    if idlers:
        idler = idlers[0]
        dump_instance(p, idler, 0x40, "CInGameIdler head")
        for off in (0x520, 0x530, 0x570, 0x620, 0x6C0, 0x780, 0x790, 0x795, 0x7A0):
            try:
                v = m.u64(idler + off)
                b = m.rpm(idler + off, 8)
                print(f"  +{off:#06x}: q={v:#x} raw={b.hex(' ')}")
            except OSError:
                pass
        q1 = m.u64(idler + 0x530)
        if q1:
            v1 = m.u64(q1)
            print(f"  idler+0x530 -> {q1:#x} vftable {v1:#x} (rva {v1 - base:#x}) "
                  f"-> {vftable_class(p, v1)}")
            fn1 = m.u64(v1 + 0x88)
            print(f"    slot17(+0x88) fn rva = {fn1 - base:#x}")

    gs = found.get(wanted.get(".?AVCCurrentGameState@@", [0]) [0], [])
    if gs:
        G = gs[0]
        dump_instance(p, G + 0x310, 0x18, "gamestate +0x310 (countries array?)")
        for off in (0x268, 0x310, 0x328, 0x340, 0x518, 0x51C, 0x520, 0x908):
            try:
                print(f"  gs+{off:#06x}: {m.u64(G + off):#018x}")
            except OSError:
                break


if __name__ == "__main__":
    main()
