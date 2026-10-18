"""One-off read-only probe v12: lay out the country's 552 CTechnology elements.

v11 established the chain
    tag -> country (+0xF60) -> CTechnologyStatus -> [+0x88] array, [+0x94] count,
    [+0xAC] research slots
and 0xed5080 indexes that array by `tech[+0x38] - 1`.

This probe dumps the first elements verbatim, checks whether they point at one of
the ~380 name-bearing CTechnology objects, and looks for the id/name fields.

Read-only.
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.inject import tables as T                                # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402
from hoi4_mcp.process.instances import scan_for_vftable_ptr            # noqa: E402

VFT = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98, 0xb8, 0xd8)


def name_in_page(m, buf: bytes, page_va: int, va: int) -> str | None:
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
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    arr = m.u64(gs + 0x310)
    countries = [int.from_bytes(m.rpm(arr + i * 8, 8), "little") for i in range(512)]
    mgr = m.u64(countries[tag] + 0xF60)
    table = m.u64(mgr + 0x88)
    count = m.u32(mgr + 0x94)
    print(f"manager={mgr:#x} table={table:#x} count={count}")

    elems = [int.from_bytes(m.rpm(table + i * 8, 8), "little") for i in range(count)]
    print(f"first 6 elements: {[hex(e) for e in elems[:6]]}")
    print("element dwords +0x30..+0x40 for the first 6:")
    for e in elems[:6]:
        blob = m.rpm(e, 0x50)
        print(f"  {e:#x}: " + " ".join(
            f"+{o:#04x}={int.from_bytes(blob[o:o+4],'little'):#x}" for o in (0x30, 0x34, 0x38, 0x3c, 0x40, 0x44)))

    # collect every name-bearing CTechnology object (page-batched, as in v5)
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
                nm = name_in_page(m, buf, page_va, a + off)
                if nm:
                    named[a] = nm
                    break
    print(f"name-bearing CTechnology objects: {len(named)}")
    namedset = set(named)

    # do the country's 552 elements point at named objects (definition links)?
    ptr_hits: Counter = Counter()
    link_examples: list[str] = []
    for i, e in enumerate(elems):
        try:
            blob = m.rpm(e, 0x800)
        except OSError:
            continue
        for off in range(0, 0x800 - 8, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            if val in namedset:
                ptr_hits[off] += 1
                if len(link_examples) < 8:
                    link_examples.append(f"    elem[{i}] {e:#x} +{off:#x} -> {named[val]!r}")
                break
    print("element -> named-object links:", dict(ptr_hits.most_common(6)))
    print("\n".join(link_examples))

    # ... or do the named objects point at the elements (reverse link)?
    elemset = set(elems)
    owned: Counter = Counter()
    for a, nm in list(named.items()):
        try:
            blob = m.rpm(a, 0x800)
        except OSError:
            continue
        for off in range(0, 0x800 - 8, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            if val in elemset:
                owned[off] += 1
                break
    print("named-object -> element links:", dict(owned.most_common(6)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
