"""One-off read-only probe v3: is vftable 0x2974EE0 really CTechnology's?

If the RTTI JSON lists many classes for the same vftable RVA, /OPT:ICF folded
identical vtables and a vftable-pointer scan is NOT an identity check. Then the
question becomes what the 240k objects actually are, and how to reach a tech
definition by script name.

Read-only (RPM).
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.process.attach import Game, find_live_pids               # noqa: E402
from hoi4copilot.process.instances import scan_for_vftable_ptr            # noqa: E402
from hoi4copilot.readstate.techdata import TechDB                         # noqa: E402

VFT_A = 0x2974EE0
VFT_B = 0x2974F30
RTTI = Path(__file__).resolve().parents[1] / "hoi4copilot/tables/generated/rtti.json"


def owners(rva: int) -> list[str]:
    d = json.loads(RTTI.read_text(encoding="utf-8"))
    out = []
    for c in d["classes"]:
        if rva in [int(x) for x in (c.get("vftable_rvas") or [])]:
            out.append(c["name"])
    return out


def msvc_string(m, addr: int, maxlen: int = 0x200) -> str | None:
    """std::string at addr: {union{sso[16]; ptr}; size; cap}."""
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
    elif 15 < cap < 0x200:
        ptr = int.from_bytes(blob[0:8], "little")
        try:
            s = m.rpm(ptr, size)
        except OSError:
            return None
    else:
        return None
    if not re.fullmatch(rb"[ -~]+", s):
        return None
    return s.decode()


def main() -> int:
    for rva in (VFT_A, VFT_B):
        ow = owners(rva)
        print(f"vftable {rva:#x}: {len(ow)} RTTI classes -> {ow[:12]}")
    live = find_live_pids()
    if len(live) != 1:
        return 2
    names = set(TechDB().db().keys())
    print(f"known tech names: {len(names)}")
    g = Game(live[0])
    p, m = g.proc, g.proc.memory

    t0 = time.time()
    found = scan_for_vftable_ptr(p, [VFT_A, VFT_B])
    hits = found.get(VFT_A, [])
    print(f"scan {time.time()-t0:.1f}s hits(A)={len(hits)} hits(B)={len(found.get(VFT_B, []))}")

    sample = hits[:20000]
    named: Counter = Counter()
    off_hist: Counter = Counter()
    struct_ok = 0
    for a in sample:
        got = None
        for off in (0x28, 0x78, 0x18, 0x38, 0x50):
            s = msvc_string(m, a + off)
            if s:
                got = (off, s)
                break
        if got:
            struct_ok += 1
            off_hist[got[0]] += 1
            named[got[1]] += 1
    print(f"objects with a readable std::string: {struct_ok}/{len(sample)}")
    print("string-offset histogram:", dict(off_hist.most_common(8)))
    print(f"distinct strings: {len(named)}")
    print("top strings:", named.most_common(25))
    tech_hits = {k: v for k, v in named.items() if k in names}
    print(f"strings that ARE known tech names: {len(tech_hits)} -> {list(tech_hits)[:20]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
