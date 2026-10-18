"""Semantic probe: map the 2-level structure of the GER country body +
find where research/techs live at file top-level. One-shot research tool."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, r"D:/hoi4-copilot")

from hoi4copilot.readstate.world_state import (
    walkthrough, find_countries, country_anchors, statement_member_scan,
    scalar_value, NAMES, header_stmts,
)


def depth_members(data, pos, kind, depth, span, open_i, close_i, d0):
    """Yield every member of the body with key resolution and value preview."""
    i = open_i + 1
    out = []
    while i < close_i:
        if int(depth[i]) != d0 + 1:
            i += 1
            continue
        t = int(kind[i])
        if t == 0x0004:
            break
        if t in (0x000F, 0x0017):
            p = int(pos[i])
            ln = data[p + 2] | (data[p + 3] << 8)
            key = data[p + 4:p + 4 + ln].decode("utf-8", "replace")
            if int(kind[i + 1]) == 0x0001:
                vt = int(kind[i + 2])
                if vt == 0x0003:
                    cl = find_matching(kind, i + 2)
                    out.append((key, f"body[{int(pos[i+2]):#x}+{int(pos[cl])-int(pos[i+2]):,}b]"))
                    i = cl + 1
                    continue
                out.append((key, repr(scalar_value(vt, data, pos[i + 2]))))
                i += 3
                continue
            out.append((key, "<no-eq>"))
            i += 1
            continue
        if t == 0x0001:
            out.append(("<anon>", f"prim={scalar_value(int(kind[i+1]), data, pos[i+1])}"))
            i += 2
            continue
        nm = NAMES.get(t, f"T_{t:04X}")
        if int(kind[i + 1]) == 0x0001:
            vt = int(kind[i + 2])
            if vt == 0x0003:
                cl = find_matching(kind, i + 2)
                out.append((nm, f"body[{int(pos[i+2]):#x}+{int(pos[cl])-int(pos[i+2]):,}b]"))
                i = cl + 1
                continue
            out.append((nm, repr(scalar_value(vt, data, pos[i + 2]))))
            i += 3
            continue
        out.append((f"tok{t:#06x}", "<no-eq>"))
        i += 1
    return out


def find_matching(kind, open_i):
    from hoi4copilot.readstate.bin5_scaffold import find_matching as fm
    return fm(kind, open_i)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else (
        r"C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/"
        r"save games/GER_1936_03_31_11.hoi4")
    data = Path(path).read_bytes()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    key_p, open_p, close_p, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    print(f"anchors={len(anchors)}")
    tag_want = sys.argv[2] if len(sys.argv) > 2 else "GER"
    for tag, ti, oi, ck in anchors:
        if tag != tag_want or ck is None:
            continue
        d0 = int(depth[oi])
        print(f"== {tag} body: {int(pos[ck])-int(pos[oi]):,}b depth0={d0}")
        mem = depth_members(data, pos, kind, depth, span, oi, ck, d0)
        print(f"-- {tag} top members ({len(mem)}):")
        for k, v in mem:
            print(f"   {k} = {v}")
        # drill into selected bodies
        for want in ("production", "units", "politics", "focus", "deployment",
                     "reinforcement", "variables", "ai", "history", "fuel_status"):
            i = oi + 1
            while i < ck:
                t = int(kind[i])
                if int(depth[i]) == d0 + 1 and t in (0x000F, 0x0017):
                    p = int(pos[i])
                    ln = data[p + 2] | (data[p + 3] << 8)
                    txt = data[p + 4:p + 4 + ln].decode("utf-8", "replace")
                    if txt == want and int(kind[i + 1]) == 0x0001 and int(kind[i + 2]) == 0x0003:
                        cl = find_matching(kind, i + 2)
                        sub = depth_members(data, pos, kind, depth, span, i + 2, cl, d0 + 1)
                        print(f"-- {tag}.{want} ({len(sub)} members):")
                        for k, v in sub[:60]:
                            print(f"     {k} = {v}")
                        if len(sub) > 60:
                            print(f"     ... ({len(sub)-60} more)")
                        break
                i += 1
        break


if __name__ == "__main__":
    main()
