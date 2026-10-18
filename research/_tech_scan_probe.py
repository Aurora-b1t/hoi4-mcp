"""One-off read-only probe: find live CTechnology objects and their script names.

Why: CSetResearchCommand's ctor takes `r8 = CTechnology*` (the same object the
research panel gets from its row item — see the UI call site at 0x2ABB6B:
`mov rsi, qword ptr [r14]` / `mov edi, dword ptr [r14 + 8]` /
`movzx ebx, byte ptr [r14 + 0xc]`).  To post a research order by *name* we need
name -> live object, exactly like inject/focus_ids.py does for focuses.

Method (mirrors focus_ids.py): scan committed RW memory for pointers to the
CTechnology vftables (rtti.json), then look for a known tech script name inside
each object's first bytes.  Tech names come from common/technologies via
readstate.techdata.TechData (offline data, no game files touched at runtime).

Read-only: RPM only, no APC, no payload, no thread touched.
"""
from __future__ import annotations

import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402
from hoi4_mcp.process.instances import scan_for_vftable_ptr            # noqa: E402

VFT_TECH = [0x2974EE0, 0x2974F30]      # .?AVCTechnology@@ (primary + 2nd)
ASCII = re.compile(rb"[a-z][a-z0-9_]{3,60}")


def tech_names() -> set[str]:
    from hoi4_mcp.readstate.techdata import TechDB
    return set(TechDB().db().keys())


def main() -> int:
    live = find_live_pids()
    print(f"live pids: {live}")
    if len(live) != 1:
        return 2
    names = tech_names()
    print(f"known tech names (common/technologies): {len(names)}")
    g = Game(live[0])
    p = g.proc
    m = p.memory

    t0 = time.time()
    found = scan_for_vftable_ptr(p, VFT_TECH)
    for vft in VFT_TECH:
        print(f"  vftable {vft:#x}: {len(found.get(vft, []))} instances")
    print(f"scan seconds: {time.time()-t0:.1f}")

    objs = sorted(set(found.get(VFT_TECH[0], [])) | set(found.get(VFT_TECH[1], [])))
    shifts: Counter[int] = Counter()
    mapped: dict[str, int] = {}
    samples: list[str] = []
    for a in objs:
        try:
            head = m.rpm(a, 0x100)
        except OSError:
            continue
        # any known tech name in the first 0x100 bytes (window includes the
        # std::string body for the small-string case, or a pointer we resolve
        # below)
        for mt in ASCII.finditer(head):
            s = mt.group().decode()
            if s in names:
                shifts[mt.start()] += 1
                mapped.setdefault(s, a)
                break
        else:
            # fall back: follow a plausible heap pointer and read there
            for off in range(0, 0x100 - 8, 8):
                ptr = int.from_bytes(head[off:off + 8], "little")
                if not (0x10000 < ptr < 1 << 48):
                    continue
                try:
                    blob = m.rpm(ptr, 0x40)
                except OSError:
                    continue
                mt = ASCII.match(blob)
                if mt and mt.group().decode() in names:
                    shifts[("ptr", off)] += 1
                    mapped.setdefault(mt.group().decode(), a)
                    break
        if len(samples) < 8:
            q = [int.from_bytes(head[i:i + 8], "little") for i in (0, 8, 0x10)]
            samples.append(f"    {a:#x}: vft={q[0]-p.base:#x} +8={q[1]:#x} +10={q[2]:#x}")

    print(f"objects with a known tech name: {len(mapped)} of {len(objs)}")
    print("name-offset histogram:", dict(shifts.most_common(12)))
    print("samples (head qwords):")
    print("\n".join(samples))
    for s in ("infantry_weapons", "support_weapons", "industry", "construction1",
              "basic_machine_tools", "electronic_mechanical_engineering"):
        if s in mapped:
            print(f"  {s:34s} -> {mapped[s]:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
