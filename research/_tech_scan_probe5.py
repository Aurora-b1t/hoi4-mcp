"""One-off read-only probe v5: are the 243k CTechnology instances definition
objects (one per tech) or per-country copies (~549 x 440)?

Method: page-batched RPM over every vftable hit -- one 4 KB read per page, then
extract the object's std::string name from the same buffer. Reading 243k objects
one syscall at a time would take minutes; batching by page takes seconds.

Read-only.
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.process.attach import Game, find_live_pids               # noqa: E402
from hoi4copilot.process.instances import scan_for_vftable_ptr            # noqa: E402
from hoi4copilot.readstate.techdata import TechDB                         # noqa: E402

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38)


def read_name(m, base_buf: bytes, page_va: int, obj_va: int) -> str | None:
    """std::string at the candidate offsets; uses base_buf when it covers it."""
    for off in NAMES_AT:
        va = obj_va + off
        rel = va - page_va
        if not (0 <= rel <= PAGE - 0x20):
            continue
        blob = base_buf[rel:rel + 0x20]
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
    tech_names = set(TechDB().db().keys())
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    t0 = time.time()
    hits = scan_for_vftable_ptr(p, [VFT]).get(VFT, [])
    print(f"scan: {len(hits)} hits in {time.time()-t0:.1f}s")

    per_page: dict[int, list[int]] = defaultdict(list)
    for a in hits:
        per_page[a & ~(PAGE - 1)].append(a)

    names: Counter = Counter()
    addr_of: dict[str, int] = {}
    named = 0
    t1 = time.time()
    for page_va, addrs in per_page.items():
        try:
            buf = m.rpm(page_va, PAGE)
        except OSError:
            continue
        for a in addrs:
            rel = a - page_va
            if rel + 8 > PAGE:
                continue
            if int.from_bytes(buf[rel:rel + 8], "little") - p.base != VFT:
                continue
            nm = read_name(m, buf, page_va, a)
            if nm:
                named += 1
                names[nm] += 1
                addr_of.setdefault(nm, a)
    dt = time.time() - t1
    print(f"page-batched pass: {dt:.1f}s  pages={len(per_page)}  "
          f"named objects={named}  distinct names={len(names)}")
    print("most common names:", names.most_common(12))
    print("names appearing exactly once:", sum(1 for v in names.values() if v == 1))
    hits_join = {k: v for k, v in names.items() if k in tech_names}
    print(f"names that are known TECH names: {len(hits_join)} of {len(names)}")
    print("examples:", list(hits_join.items())[:12])
    for probe in ("light_armor", "artillery_brigade", "heavy_cruiser", "field_guns",
                  "mechanized", "rocket_artillery", "infantry_weapons"):
        if probe in names:
            print(f"  {probe:22s} x{names[probe]:<4d} first={addr_of[probe]:#x}")
    # where do the named objects live? (definitions should cluster)
    addrs = sorted(addr_of.values())
    if addrs:
        print(f"named-object address range: {addrs[0]:#x} .. {addrs[-1]:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
