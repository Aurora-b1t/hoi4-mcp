"""Live read-only probe: resolve the idler global, GetCommandQueue chain and
the command queue object. Zero writes, zero calls into the game."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.process.attach import Game
from hoi4copilot.process import win32ext as w

RTTI = json.loads((Path(__file__).resolve().parents[1] / "hoi4copilot/tables/generated/rtti.json").read_text())
BY_VFT = {}
for c in RTTI["classes"]:
    for r in c["vftable_rvas"]:
        BY_VFT[r] = c["name"]


def vftable_class(p, vft_va: int) -> str | None:
    return BY_VFT.get(vft_va - p.base)


def main():
    g = Game()
    p = g.proc
    m = p.memory
    base = p.base
    print(f"attached: {p!r}")

    # -- idler global ------------------------------------------------------
    slot = 0x332F260
    idler = m.u64(base + slot)
    print(f"[base+{slot:#x}] (tag-holder global) = {idler:#x}")
    if not idler:
        print("  -> NULL: not inside a session?")
        return
    vft = m.u64(idler)
    print(f"  vftable = {vft:#x} (rva {vft - base:#x}) -> {vftable_class(p, vft)}")
    tag0 = m.u32(idler)
    tag520 = m.u32(idler + 0x520)
    print(f"  [idler+0x000] u32 = {tag0:#x}  [idler+0x520] u32 = {tag520:#x}")

    # -- queue chain -------------------------------------------------------
    q1 = m.u64(idler + 0x530)
    print(f"[idler+0x530] = {q1:#x}")
    if q1:
        v1 = m.u64(q1)
        print(f"  vftable = {v1:#x} (rva {v1 - base:#x}) -> {vftable_class(p, v1)}")
        fn1 = m.u64(v1 + 0x88)
        print(f"  slot17(+0x88) fn = {fn1:#x} (rva {fn1 - base:#x})")

    # -- tag holder fields near +0 / +0x520 --------------------------------
    band = m.rpm(idler, 0x40)
    print("  first 0x40 bytes:", band.hex(" "))

    # -- what else: sample some candidate singletons from prior session ----
    known = {
        "CGameApplication": 0x12D4E2100B0,
        "CGamePlaySettings": 0x12E92E5F5F8,
        "CGameIdler(note: old snapshot)": 0x12EEC5B7108,
    }
    for name, addr in known.items():
        try:
            raw = m.rpm(addr, 8)
            v = struct.unpack("<Q", raw)[0]
            cls = None
            if v:
                vt2 = m.u64(v)
                cls = vftable_class(p, vt2)
            print(f"prior singleton {name} @ {addr:#x}: ptr={v:#x} class={cls}")
        except OSError as e:
            print(f"prior singleton {name} @ {addr:#x}: unreadable ({e})")


if __name__ == "__main__":
    main()
