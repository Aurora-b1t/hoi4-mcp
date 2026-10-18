"""One-off read-only probe v8: do the name-bearing CTechnology objects belong to
ONE country (the player's)?

If yes, they are the player country's own tech instances -- exactly the objects
CSetResearchCommand's `r8` must point at -- and we have a name -> live pointer
map for free.

Method: read the country array at [G_GAMESTATE+0x310]; for every named tech
object, look for a qword pointing at one of those countries and report which
country index shows up.

Read-only.
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
    return s.decode() if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.\- ]*", s) else None


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base = p.base

    gs = m.u64(base + T.G_GAMESTATE)
    print(f"gamestate={gs:#x} tag={m.u32(gs + T.GS_PLAYER_TAG_OFF)}")
    arr = m.u64(gs + 0x310)
    size = m.u64(gs + 0x318)
    cap = m.u64(gs + 0x320)
    print(f"country array @ {arr:#x} size={size} cap={cap}")
    countries = []
    raw = m.rpm(arr, min(size, 440) * 8)
    for i in range(min(size, 440)):
        c = int.from_bytes(raw[i * 8:(i + 1) * 8], "little")
        if c:
            countries.append(c)
    print(f"non-null countries: {len(countries)}  first={countries[0]:#x} last={countries[-1]:#x}")
    cset = set(countries)

    t0 = time.time()
    hits = scan_for_vftable_ptr(p, [VFT]).get(VFT, [])
    print(f"{len(hits)} tech instances in {time.time()-t0:.1f}s")
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
    print(f"named tech objects: {len(named)}")

    idx_of = {c: i for i, c in enumerate(countries)}
    owner: Counter = Counter()
    examples: list[str] = []
    for a, nm in list(named.items())[:400]:
        try:
            blob = m.rpm(a, 0x700)
        except OSError:
            continue
        for off in range(0, 0x700 - 8, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            if val in cset:
                owner[idx_of[val]] += 1
                if len(examples) < 10:
                    examples.append(f"    {nm!r} @ {a:#x} +{off:#x} -> country[{idx_of[val]}]")
                break
    print("country index referenced by named tech objects:", owner.most_common(10))
    print("examples:")
    print("\n".join(examples))
    if countries:
        for i in (0, 1, 2):
            if i < len(countries):
                head = m.rpm(countries[i], 0x30)
                q = [int.from_bytes(head[j:j + 8], "little") for j in range(0, 0x30, 8)]
                print(f"  country[{i}] @ {countries[i]:#x}: " +
                      " ".join(f"{v:#x}" for v in q))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
