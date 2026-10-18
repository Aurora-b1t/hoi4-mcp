"""One-off read-only probe v9: does the player country hold a table of
CTechnology pointers (the country's own tech instances)?

Country array @ [G_GAMESTATE+0x310], index == tag (verified: country[1]+0x08 == 1).
Read the player country's first 0x10000 bytes and report every qword that points
at an object whose first qword is the CTechnology vftable -- plus, for vectors,
the {begin,end,cap} triples that look like a tech-pointer table.

Read-only.
"""
from __future__ import annotations

import re
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.inject import tables as T                                # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402
from hoi4_mcp.process.instances import scan_for_vftable_ptr            # noqa: E402

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98)
SPAN = 0x10000


def name_of(m, a: int) -> str | None:
    for off in NAMES_AT:
        va = a + off
        try:
            blob = m.rpm(va, 0x20)
        except OSError:
            continue
        size = int.from_bytes(blob[0x10:0x18], "little")
        cap = int.from_bytes(blob[0x18:0x20], "little")
        if not 0 < size < 64:
            continue
        if cap <= 15 and size <= 15:
            s = blob[:size]
        elif 15 < cap < 0x1000:
            try:
                s = m.rpm(int.from_bytes(blob[0:8], "little"), size)
            except OSError:
                continue
        else:
            continue
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.\- ]*", s):
            return s.decode()
    return None


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base = p.base
    gs = m.u64(base + T.G_GAMESTATE)
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    arr = m.u64(gs + 0x310)
    raw = m.rpm(arr, 512 * 8)
    countries = [int.from_bytes(raw[i * 8:(i + 1) * 8], "little") for i in range(512)]
    me = countries[tag]
    print(f"player tag={tag} country={me:#x}  vft={m.u64(me) - base:#x}")

    t0 = time.time()
    hits = set(scan_for_vftable_ptr(p, [VFT]).get(VFT, []))
    print(f"tech instances: {len(hits)} ({time.time()-t0:.1f}s)")

    blob = m.rpm(me, SPAN)
    tech_ptrs: dict[int, int] = {}
    for off in range(0, SPAN - 8, 8):
        val = int.from_bytes(blob[off:off + 8], "little")
        if val in hits:
            tech_ptrs[off] = val
    print(f"qwords inside the country object that point at a tech instance: {len(tech_ptrs)}")
    for off, val in list(tech_ptrs.items())[:20]:
        print(f"  +{off:#06x} -> {val:#x}  name={name_of(m, val)!r}")

    # vector triplets: begin/end/cap where begin points at an array of tech ptrs
    cands = []
    for off in range(0, SPAN - 0x18, 8):
        begin = int.from_bytes(blob[off:off + 8], "little")
        end = int.from_bytes(blob[off + 8:off + 16], "little")
        cap = int.from_bytes(blob[off + 16:off + 24], "little")
        if not (0x10000 < begin < 1 << 47 and begin <= end <= cap):
            continue
        n = (end - begin) // 8
        if not (40 <= n <= 4000) or (cap - begin) // 8 > 8000:
            continue
        try:
            arr_raw = m.rpm(begin, min(int(end - begin), 0x40))
        except OSError:
            continue
        ptrs = [int.from_bytes(arr_raw[i:i + 8], "little") for i in range(0, len(arr_raw), 8)]
        n_tech = sum(1 for q in ptrs if q in hits)
        if ptrs and n_tech == len(ptrs):
            cands.append((off, begin, n, n_tech))
    print(f"vector-like tables full of tech pointers: {len(cands)}")
    for off, begin, n, n_tech in cands[:6]:
        print(f"  country+{off:#06x} -> table @ {begin:#x} n={n} tech_ptrs={n_tech}")
        try:
            full = m.rpm(begin, min(n, 700) * 8)
        except OSError:
            continue
        names = []
        for i in range(0, len(full), 8):
            a = int.from_bytes(full[i:i + 8], "little")
            nm = name_of(m, a)
            if nm:
                names.append((i // 8, nm))
        print(f"    entries with a readable name: {len(names)} -> {names[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
