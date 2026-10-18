"""One-off read-only probe v2: dissect live CTechnology-shaped objects.

Questions this answers (all with RPM only, no payload):
  1. how many distinct instances are there really (primary vs secondary vftable
     hit is the same object twice),
  2. what is at +0x08 (a per-tech id? a global object id?),
  3. where does a tech's script name live — inline std::string or a pointer,
  4. is there a per-country table of these objects (549 techs x 440 countries).

Usage: python research/_tech_scan_probe2.py [n_dump]
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402
from hoi4_mcp.process.instances import (scan_for_vftable_ptr,          # noqa: E402
                                           _readable_regions)
from hoi4_mcp.readstate.techdata import TechDB                         # noqa: E402

VFT_PRIMARY = 0x2974EE0
VFT_SECOND = 0x2974F30
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,80}")


def main() -> int:
    n_dump = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    live = find_live_pids()
    if len(live) != 1:
        print(f"need exactly one live pid, got {live}")
        return 2
    names = set(TechDB().db().keys())
    print(f"known tech names: {len(names)}")
    g = Game(live[0])
    p = g.proc
    m = p.memory

    t0 = time.time()
    found = scan_for_vftable_ptr(p, [VFT_PRIMARY, VFT_SECOND])
    prim = found.get(VFT_PRIMARY, [])
    sec = found.get(VFT_SECOND, [])
    print(f"scan {time.time()-t0:.1f}s  primary-hits={len(prim)} secondary-hits={len(sec)}")
    secset = set(sec)
    objects = [a for a in prim if a + 0x10 not in secset]
    print(f"objects whose +0x10 is NOT a secondary vftable (real heads): {len(objects)}")
    print(f"primary hits that ARE +0x10 of another hit: {len(prim) - len(objects)}")

    # 2. the +0x08 dword across a sample
    ids = Counter()
    for a in objects[:4000]:
        try:
            ids[int.from_bytes(m.rpm(a + 8, 4), "little")] += 1
        except OSError:
            pass
    vals = sorted(ids)
    print(f"+0x08 sample: {len(ids)} distinct in {len(objects[:4000])} objects; "
          f"min={vals[0]:#x} max={vals[-1]:#x} most={ids.most_common(4)}")
    dense = [v for v in vals if v < 0x400]
    print(f"  values < 0x400: {len(dense)} -> {dense[:20]}")

    # 3. follow pointers inside the objects, classify the pointed-to strings
    name_hits: Counter = Counter()
    ptr_hits: Counter = Counter()
    examples: list[str] = []
    for a in objects[:6000]:
        try:
            head = m.rpm(a, 0x100)
        except OSError:
            continue
        for off in range(0, 0x100, 8):
            val = int.from_bytes(head[off:off + 8], "little")
            if not (0x10000 < val < (1 << 47)):
                continue
            try:
                blob = m.rpm(val, 48)
            except OSError:
                continue
            mt = PRINTABLE.match(blob)
            if not mt:
                continue
            s = mt.group().decode(errors="replace").rstrip()
            ptr_hits[off] += 1
            if s in names:
                name_hits[off] += 1
                if len(examples) < 6:
                    examples.append(f"    {a:#x} +{off:#x} -> {val:#x} = {s!r}")
        # inline std::string at a few candidate offsets
        for off in (0x28, 0x30, 0x38, 0x78):
            size = int.from_bytes(head[off + 0x10:off + 0x18], "little")
            cap = int.from_bytes(head[off + 0x18:off + 0x20], "little")
            if 0 < size < 32 and cap <= 15 and off + size <= 0x100:
                s = head[off:off + size].decode(errors="replace")
                if s in names:
                    name_hits[("inline", off)] += 1
    print("pointer fields that point at printable data:", dict(ptr_hits.most_common(10)))
    print("fields whose target is a KNOWN TECH NAME:", dict(name_hits.most_common(10)))
    print("examples:")
    print("\n".join(examples))

    # 4. dump a few objects in full
    print(f"\n--- dumps (first {n_dump} objects) ---")
    for a in objects[:n_dump]:
        print(f"object {a:#x}:")
        try:
            blob = m.rpm(a, 0x140)
        except OSError:
            continue
        for off in range(0, 0x140, 8):
            val = int.from_bytes(blob[off:off + 8], "little")
            note = ""
            if 0x10000 < val < (1 << 47):
                try:
                    s = m.rpm(val, 40)
                    mt = PRINTABLE.match(s)
                    if mt:
                        note = f"  -> {mt.group().decode(errors='replace')!r}"
                    else:
                        q = int.from_bytes(s[:8], "little")
                        note = f"  -> [{q:#x} ...]"
                except OSError:
                    note = "  -> (unreadable)"
            print(f"  +{off:#04x}: {val:#018x}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
