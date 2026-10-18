"""One-off read-only probe v13: do the name-bearing CTechnology objects carry the
1-based tech id at +0x38 (the field `0xed5080` indexes the country array with)?

If yes, the resolution chain for CSetResearchCommand is:

    name --(vftable scan + std::string)--> definition object
         --(obj[+0x38])--> id
         country[+0xF60]->CTechnologyStatus[+0x88][id-1] = the country's instance
    => the command's `r8` is the DEFINITION pointer (0xed5080 maps it per country)

Read-only.
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.inject import tables as T                                # noqa: E402
from hoi4copilot.process.attach import Game, find_live_pids               # noqa: E402
from hoi4copilot.process.instances import scan_for_vftable_ptr            # noqa: E402
from hoi4copilot.readstate.techdata import TechDB                         # noqa: E402

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98, 0xb8, 0xd8, 0xf8)


def name_at(m, buf: bytes, page_va: int, va: int) -> str | None:
    rel = va - page_va
    if not (0 <= rel <= PAGE - 0x20):
        return None
    blob = buf[rel:rel + 0x20]
    size = int.from_bytes(blob[0x10:0x18], "little")
    cap = int.from_bytes(blob[0x18:0x20], "little")
    if not 0 < size < 64:
        return None
    if cap <= 15 and size <= 15:
        s = blob[:size]
    elif 15 < cap < 0x1000:
        try:
            s = m.rpm(int.from_bytes(blob[0:8], "little"), size)
        except OSError:
            return None
    else:
        return None
    return s.decode() if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.\- ]*", s) else None


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    known = set(TechDB().db().keys())
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base = p.base
    gs = m.u64(base + T.G_GAMESTATE)
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    arr = m.u64(gs + 0x310)
    countries = [int.from_bytes(m.rpm(arr + i * 8, 8), "little") for i in range(512)]
    mgr = m.u64(countries[tag] + 0xF60)
    table = m.u64(mgr + 0x88)
    count = m.u32(mgr + 0x94)
    elems = {int.from_bytes(m.rpm(table + i * 8, 8), "little"): i + 1
             for i in range(count)}
    print(f"player country array: {len(elems)} instances (id = index+1)")

    hits = scan_for_vftable_ptr(p, [VFT]).get(VFT, [])
    per_page: dict[int, list[int]] = defaultdict(list)
    for a in hits:
        per_page[a & ~(PAGE - 1)].append(a)
    named: dict[int, str] = {}
    for page_va, addrs in per_page.items():
        try:
            buf = m.rpm(page_va, PAGE)
        except OSError:
            continue
        for a in addrs:
            rel = a - page_va
            if rel + 8 > PAGE or int.from_bytes(buf[rel:rel + 8], "little") - base != VFT:
                continue
            for off in NAMES_AT:
                nm = name_at(m, buf, page_va, a + off)
                if nm:
                    named[a] = nm
                    break
    print(f"named objects: {len(named)} (known tech names among them: "
          f"{len([k for k in named.values() if k in known])})")
    print(f"named objects that ARE country instances: "
          f"{len([a for a in named if a in elems])}")

    ids = []
    rows = []
    for a, nm in named.items():
        try:
            blob = m.rpm(a, 0x40)
        except OSError:
            continue
        tid = int.from_bytes(blob[0x38:0x3c], "little")
        ids.append(tid)
        rows.append((tid, nm, a))
    ok = [t for t in ids if 1 <= t <= count]
    print(f"definitions with id in 1..{count}: {len(ok)}/{len(ids)}")
    print("id range:", (min(ids), max(ids)) if ids else None)
    print("sample rows (id, name, addr):")
    for t, nm, a in sorted(rows)[:18]:
        print(f"  id={t:<6d} {nm:36s} {a:#x}")
    c = Counter(t for t in ids if 1 <= t <= count)
    print("duplicate ids:", [kv for kv in c.items() if kv[1] > 1][:6])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
