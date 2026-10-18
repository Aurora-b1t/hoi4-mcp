"""Drill into the top-level `states` body of a save: member shape of one state,
with focus on buildings/construction. Usage: python research/states_drill.py [save] [state_id]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4_mcp.saveparse.tokens import load_tokens
from hoi4_mcp.readstate.bin5_scaffold import walkthrough, find_matching
from hoi4_mcp.readstate.country_sem import (member_list, run_to_values,
                                               dict_of, markers_of, prim)

NAMES = load_tokens()
BY_NAME = {v: k for k, v in NAMES.items()}
STATE_TOK = BY_NAME.get("states")

def main(path, want_state=None):
    data = Path(path).read_bytes()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    # find top-level 'states' body (id token or string key)
    i = 0; n = len(kind)
    st_open = st_close = None
    while i < n:
        if int(depth[i]) != 0:
            i += 1; continue
        t = int(kind[i])
        is_key = (t == STATE_TOK) or (t in (0x000F, 0x0017))
        if is_key:
            p = int(pos[i])
            if t in (0x000F, 0x0017):
                ln = data[p+2] | (data[p+3] << 8)
                key = data[p+4:p+4+ln].decode("utf-8", "replace")
            else:
                key = NAMES.get(t)
            if key == "states" and int(kind[i+1]) == 0x0001 and int(kind[i+2]) == 0x0003:
                st_open, st_close = i+2, find_matching(kind, i+2)
                break
        i += 1
    assert st_open is not None, "states body not found"
    print(f"states body: tokens [{st_open},{st_close}] "
          f"bytes {int(pos[st_open]):,}-{int(pos[st_close]):,}")
    # states members: repeated <id> = {...}
    members = member_list(data, pos, kind, depth, span, st_open, st_close)
    print(f"n_members={len(members)} first keys: "
          f"{[m[0] for m in members[:6]]} ... last: {members[-1][0]}")
    # pick one state
    target = None
    for k, vk, vi, cl in members:
        if vk != 'body':
            continue
        if want_state is None or k == want_state:
            target = (k, vi, cl)
            break
    k, vi, cl = target
    print(f"\n== state {k} ==")
    inner = member_list(data, pos, kind, depth, span, vi, cl)
    for kk, vk2, vi2, cl2 in inner:
        if vk2 == 'body':
            sub = member_list(data, pos, kind, depth, span, vi2, cl2)
            keys = [x[0] for x in sub]
            print(f"  {kk}: body[{int(pos[cl2])-int(pos[vi2]):,}B] "
                  f"n={len(sub)} keys={keys[:14]}{'...' if len(keys)>14 else ''}")
        elif vk2 == 'run':
            print(f"  {kk}: run = {run_to_values(vi2, data)[:8]}")
        else:
            val = run_to_values([(vi2,)] if False else [], data)
            # prim: value token index
            from hoi4_mcp.readstate.world_state import scalar_value
            print(f"  {kk}: prim = {scalar_value(int(kind[vi2]), data, int(pos[vi2]))}")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_16.hoi4"))
    main(p, sys.argv[2] if len(sys.argv) > 2 else None)
