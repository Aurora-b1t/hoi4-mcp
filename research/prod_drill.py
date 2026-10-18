"""Dump GER's production/deployment/reinforcement body member shapes + the
buildings body of a GER-owned state. Usage: python research/prod_drill.py [save]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4_mcp.saveparse.tokens import load_tokens
from hoi4_mcp.readstate.bin5_scaffold import walkthrough, find_matching
from hoi4_mcp.readstate.country_sem import (Countries, member_list,
                                               run_to_values, dict_of,
                                               markers_of)
from hoi4_mcp.readstate.world_state import scalar_value

NAMES = load_tokens()

def show_body(cn, marker, label, maxsub=12):
    oi, cl = marker[1], marker[2]
    inner = member_list(cn.data, cn.pos, cn.kind, cn.depth, cn.span, oi, cl)
    print(f"  {label}: body[{int(cn.pos[cl])-int(cn.pos[oi]):,}B] n={len(inner)}")
    for k, vk, vi, cl2 in inner[:maxsub]:
        if vk == 'body':
            sub = member_list(cn.data, cn.pos, cn.kind, cn.depth, cn.span, vi, cl2)
            print(f"    {k}: body[{int(cn.pos[cl2])-int(cn.pos[vi]):,}B] n={len(sub)} "
                  f"keys={[x[0] for x in sub[:10]]}")
        elif vk == 'run':
            print(f"    {k}: run={run_to_values(vi, cn.data)[:6]}")
        else:
            print(f"    {k}: prim={scalar_value(int(cn.kind[vi]), cn.data, int(cn.pos[vi]))}")
    if len(inner) > maxsub:
        print(f"    ... +{len(inner)-maxsub} more: {[x[0] for x in inner[maxsub:]][:12]}")

def main(path):
    cn = Countries(path)
    tag = cn.player() or "GER"
    mem = cn.members(tag)
    for key in ("production", "deployment", "reinforcement", "upgrades",
                "naval_headquarter_status"):
        v = mem.get(key)
        if cn.is_body(v):
            show_body(cn, v, key)
        else:
            print(f"  {key}: {v}")
    # a GER state's buildings body (top-level states)
    STATE_TOK = {v: k for k, v in NAMES.items()}.get("states")
    i = 0; n = len(cn.kind)
    while i < n:
        if int(cn.depth[i]) != 0:
            i += 1; continue
        t = int(cn.kind[i])
        if (t == STATE_TOK) and int(cn.kind[i+1]) == 0x0001 \
                and int(cn.kind[i+2]) == 0x0003 \
                and NAMES.get(t) == "states":
            break
        i += 1
    st_open, st_close = i+2, find_matching(cn.kind, i+2)
    shown = 0
    for k, vk, vi, cl in member_list(cn.data, cn.pos, cn.kind, cn.depth,
                                     cn.span, st_open, st_close):
        if vk != 'body':
            continue
        inner = dict_of(cn.entries((('body', vi, cl),)) and
                        member_list(cn.data, cn.pos, cn.kind, cn.depth,
                                    cn.span, vi, cl))
        # owner check via entries
        own = None
        for kk, vk2, vi2, cl2 in member_list(cn.data, cn.pos, cn.kind,
                                             cn.depth, cn.span, vi, cl):
            if kk == 'owner' and vk2 == 'prim':
                own = scalar_value(int(cn.kind[vi2]), cn.data, int(cn.pos[vi2]))
        if own != tag:
            continue
        bl = None
        for kk, vk2, vi2, cl2 in member_list(cn.data, cn.pos, cn.kind,
                                             cn.depth, cn.span, vi, cl):
            if kk == 'buildings' and vk2 == 'body':
                bl = (vi2, cl2)
        if bl is None:
            continue
        print(f"\n== state {scalar_value(int(cn.kind[k_idx]) if False else int(cn.kind[0]), cn.data, 0) if False else k} owner={own} ==")
        oi2, cl2 = bl
        for kk, vk3, vi3, cl3 in member_list(cn.data, cn.pos, cn.kind,
                                             cn.depth, cn.span, oi2, cl2):
            if vk3 == 'body':
                sub = member_list(cn.data, cn.pos, cn.kind, cn.depth,
                                  cn.span, vi3, cl3)
                print(f"  {kk}: body n={len(sub)}: "
                      + " ".join(f"{x[0]}={run_to_values(x[2], cn.data) if x[1]=='run' else '?'}"
                                 if x[1] == 'run' else f"{x[0]}:body"
                                 for x in sub[:8]))
                for x in sub:
                    if x[1] == 'body':
                        s3 = member_list(cn.data, cn.pos, cn.kind, cn.depth,
                                         cn.span, x[2], x[3])
                        print(f"    {x[0]}: " + " ".join(
                            f"{y[0]}={run_to_values(y[2], cn.data)}"
                            if y[1] == 'run' else f"{y[0]}={scalar_value(int(cn.kind[y[2]]), cn.data, int(cn.pos[y[2]]))}"
                            if y[1] == 'prim' else f"{y[0]}:body"
                            for y in s3[:8]))
            elif vk3 == 'run':
                print(f"  {kk}: run={run_to_values(vi3, cn.data)}")
            else:
                print(f"  {kk}: prim={scalar_value(int(cn.kind[vi3]), cn.data, int(cn.pos[vi3]))}")
        shown += 1
        if shown >= 2:
            break

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_16.hoi4"))
    main(p)
