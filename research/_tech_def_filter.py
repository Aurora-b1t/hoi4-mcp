"""One-off read-only probe v14: find FULLY INITIALISED CTechnology objects.

The 26 日 live probe showed the name-bearing objects are not usable: passing one
to the game's own predicate (0xED8F00) faulted at a virtual call through
`[obj+0x48]` — the object's interface pointer is garbage. A real tech object
should satisfy:

  * first qword = CTechnology vftable (0x2974EE0),
  * +0x38 (id) in 1..552,
  * +0x48 = a readable pointer whose first qword is a code address inside the
    image (i.e. a vtable) -- that is the pointer the predicate calls through.

Page-batched scan + filter, read-only.
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.inject import tables as T                                # noqa: E402
from hoi4copilot.process.attach import Game, find_live_pids               # noqa: E402
from hoi4copilot.process.instances import scan_for_vftable_ptr            # noqa: E402

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98, 0xb8, 0xd8)


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
        print(f"need one live pid, got {live}")
        return 2
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base, size = p.base, p.image_size
    gs = m.u64(base + T.G_GAMESTATE)
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    countries = [int.from_bytes(m.rpm(m.u64(gs + 0x310) + i * 8, 8), "little")
                 for i in range(512)]
    mgr = m.u64(countries[tag] + 0xF60)
    table = m.u64(mgr + 0x88)
    count = m.u32(mgr + 0x94)
    inst_of_id = {i + 1: int.from_bytes(m.rpm(table + i * 8, 8), "little")
                  for i in range(count)}
    print(f"country={countries[tag]:#x} manager={mgr:#x} ids 1..{count}")

    t0 = time.time()
    hits = scan_for_vftable_ptr(p, [VFT]).get(VFT, [])
    per_page: dict[int, list[int]] = defaultdict(list)
    for a in hits:
        per_page[a & ~(PAGE - 1)].append(a)
    print(f"{len(hits)} instances in {time.time()-t0:.1f}s")

    good: list[tuple[int, int, str | None]] = []
    id_ok = 0
    for page_va, addrs in per_page.items():
        try:
            buf = m.rpm(page_va, PAGE)
        except OSError:
            continue
        for a in addrs:
            rel = a - page_va
            if rel + 8 > PAGE or int.from_bytes(buf[rel:rel + 8], "little") - base != VFT:
                continue
            if rel + 0x50 > PAGE:
                continue
            tid = int.from_bytes(buf[rel + 0x38:rel + 0x3c], "little")
            if not 1 <= tid <= count:
                continue
            id_ok += 1
            iface = int.from_bytes(buf[rel + 0x48:rel + 0x50], "little")
            if not 0x10000 < iface < (1 << 47):
                continue
            try:
                code = int.from_bytes(m.rpm(iface, 8), "little")
            except OSError:
                continue
            if not base <= code < base + size:
                continue
            nm = None
            for off in NAMES_AT:
                nm = name_at(m, buf, page_va, a + off)
                if nm:
                    break
            good.append((a, tid, nm))
    print(f"objects with id in range: {id_ok}; with a valid [obj+0x48] vtable: {len(good)}")
    names = Counter(nm for _a, _t, nm in good if nm)
    print(f"  named among them: {sum(names.values())} / distinct {len(names)}")
    print("  examples:")
    for a, tid, nm in good[:12]:
        inst = inst_of_id.get(tid, 0)
        print(f"    {a:#x} id={tid:<4d} instance={inst:#x} name={nm!r}")
    ids = Counter(t for _a, t, _n in good)
    print(f"  distinct ids: {len(ids)}; most duplicated: {ids.most_common(5)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
