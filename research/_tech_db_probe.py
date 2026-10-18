"""One-off read-only probe v4: reach CTechnology objects through the game's own
technology database / folder objects.

Idea: rather than guessing which of the ~243k CTechnology-vftable instances is
the definition the research command wants, walk the database singleton
(CTechnologyDatabase / CTechnologyFolder / CTechnologyPath) and read out the
container that holds the definitions.

Read-only (RPM).
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402
from hoi4_mcp.process.instances import scan_for_vftable_ptr            # noqa: E402
from hoi4_mcp.readstate.techdata import TechDB                         # noqa: E402

VFT_TECH = 0x2974EE0
DB = {"CTechnologyDatabase": 0x2944150, "CTechnologyFolder": 0x2944108,
      "CTechnologyPath": 0x2944068, "CTechnologySharingGroup": 0x2721740,
      "CTechnologySharing": 0x2721630}
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,80}")


def msvc_string(m, addr: int, maxlen: int = 0x100) -> str | None:
    try:
        blob = m.rpm(addr, 0x20)
    except OSError:
        return None
    size = int.from_bytes(blob[0x10:0x18], "little")
    cap = int.from_bytes(blob[0x18:0x20], "little")
    if not 0 < size < maxlen:
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
    if not re.fullmatch(rb"[ -~]+", s):
        return None
    return s.decode()


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    names = set(TechDB().db().keys())
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    t0 = time.time()
    found = scan_for_vftable_ptr(p, list(DB.values()))
    print(f"scan {time.time()-t0:.1f}s")
    for label, rva in DB.items():
        print(f"  {label:26s} {rva:#x}: {len(found.get(rva, []))} instances")

    for label, rva in DB.items():
        for inst in found.get(rva, [])[:3]:
            print(f"\n===== {label} @ {inst:#x} =====")
            try:
                head = m.rpm(inst, 0x100)
            except OSError:
                continue
            for off in range(0, 0x100, 8):
                val = int.from_bytes(head[off:off + 8], "little")
                note = ""
                if 0x10000 < val < (1 << 47):
                    try:
                        first = int.from_bytes(m.rpm(val, 8), "little")
                        if first - p.base == VFT_TECH:
                            nm = None
                            for so in (0x28, 0x78, 0x18, 0x38, 0x50, 0x98):
                                nm = msvc_string(m, val + so)
                                if nm:
                                    break
                            note = f"  -> TECH OBJECT name={nm!r}"
                        else:
                            s = m.rpm(val, 40)
                            mt = PRINTABLE.match(s)
                            if mt:
                                note = f"  -> {mt.group().decode(errors='replace')!r}"
                            else:
                                note = f"  -> vft_rva={first - p.base:#x}"
                    except OSError:
                        note = "  -> (unreadable)"
                print(f"  +{off:#04x}: {val:#018x}{note}")

            # follow plausible container pointers one level and look for runs of
            # tech objects (a vector of CTechnology* or of inline objects)
            for off in range(0, 0x100, 8):
                val = int.from_bytes(head[off:off + 8], "little")
                if not (0x10000 < val < (1 << 47)):
                    continue
                try:
                    run = m.rpm(val, 0x40)
                except OSError:
                    continue
                techs = []
                for i in range(0, 0x40, 8):
                    cand = int.from_bytes(run[i:i + 8], "little")
                    if not (0x10000 < cand < (1 << 47)):
                        continue
                    try:
                        if int.from_bytes(m.rpm(cand, 8), "little") - p.base == VFT_TECH:
                            techs.append(cand)
                    except OSError:
                        pass
                if techs:
                    print(f"  !! +{off:#04x} -> {val:#x} holds {len(techs)} tech pointers "
                          f"e.g. {[hex(t) for t in techs[:4]]}")
    print(f"\nknown tech names for join: {len(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
