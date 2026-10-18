"""One-off read-only probe v6: definition vs instance among CTechnology objects.

v5 found 379 objects carrying a readable name and 243k without one. Hypothesis:
the named ones are shared tech *definitions* (~#techs) and the rest are
per-country instances holding a pointer to their definition.

Test: collect named objects, then sample unnamed ones and look for a qword equal
to a named object's address in their first 0x800 bytes. Record the offset
histogram -- a consistent offset is the definition back-pointer field.

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

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98)


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
    if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.\- ]*", s):
        return s.decode()
    return None


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    t0 = time.time()
    hits = scan_for_vftable_ptr(p, [VFT]).get(VFT, [])
    print(f"{len(hits)} hits in {time.time()-t0:.1f}s")

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
            if rel + 8 > PAGE or int.from_bytes(buf[rel:rel + 8], "little") - p.base != VFT:
                continue
            for off in NAMES_AT:
                nm = name_at(m, buf, page_va, a + off)
                if nm:
                    named[a] = nm
                    break
    print(f"named objects: {len(named)}  distinct names: {len(set(named.values()))}")
    namedset = set(named)

    unnamed = [a for a in hits if a not in namedset]
    print(f"unnamed objects: {len(unnamed)}")
    step = max(1, len(unnamed) // 3000)
    sample = unnamed[::step][:3000]
    off_hist: Counter = Counter()
    with_ptr = 0
    for a in sample:
        try:
            blob = m.rpm(a, 0x800)
        except OSError:
            continue
        found_any = False
        for off in range(0, 0x800 - 8, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            if val in namedset:
                off_hist[off] += 1
                found_any = True
        if found_any:
            with_ptr += 1
    print(f"unnamed objects pointing at a NAMED object: {with_ptr}/{len(sample)}")
    print("back-pointer offset histogram:", dict(off_hist.most_common(10)))

    # reverse view: how many unnamed objects point at each named one?
    refs: Counter = Counter()
    for a in unnamed[:20000]:
        try:
            blob = m.rpm(a, 0x800)
        except OSError:
            continue
        for off in range(0, 0x800 - 8, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            if val in namedset:
                refs[val] += 1
                break
    print(f"among {min(20000, len(unnamed))} unnamed objects, "
          f"{len(refs)} distinct named targets referenced")
    print("top referenced definitions:",
          [(named[k], v) for k, v in refs.most_common(8)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
