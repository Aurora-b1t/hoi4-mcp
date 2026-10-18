"""Aggregate member-name distribution across ALL states; dump one state that
has a construction member, in full. Usage: python research/states_scan.py [save]"""
import sys, time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4_mcp.saveparse.tokens import load_tokens
from hoi4_mcp.readstate.bin5_scaffold import walkthrough, find_matching
from hoi4_mcp.readstate.country_sem import member_list, run_to_values
from hoi4_mcp.readstate.world_state import scalar_value

NAMES = load_tokens()
BY_NAME = {v: k for k, v in NAMES.items()}
STATE_TOK = BY_NAME.get("states")

def key_txt(data, pos, kind, i):
    t = int(kind[i])
    if t in (0x000F, 0x0017):
        p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
        return data[p+4:p+4+ln].decode("utf-8", "replace")
    return NAMES.get(t, f"T_{t:04X}")

def main(path):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    i = 0; n = len(kind)
    st_open = st_close = None
    while i < n:
        if int(depth[i]) != 0:
            i += 1; continue
        t = int(kind[i])
        if (t == STATE_TOK or t in (0x000F, 0x0017)) and \
                int(kind[i+1]) == 0x0001 and int(kind[i+2]) == 0x0003 and \
                key_txt(data, pos, kind, i) == "states":
            st_open, st_close = i+2, find_matching(kind, i+2)
            break
        i += 1
    assert st_open is not None
    members = member_list(data, pos, kind, depth, span, st_open, st_close)
    print(f"states: {len(members)} members, {time.time()-t0:.1f}s")
    dist = Counter()
    n_state = 0
    construction_states = []
    buildings_samples = []
    for k, vk, vi, cl in members:
        if vk != 'body':
            continue
        n_state += 1
        inner = member_list(data, pos, kind, depth, span, vi, cl)
        names = [x[0] for x in inner]
        dist.update(names)
        if 'construction' in names:
            construction_states.append((k, vi, cl))
    print(f"n_states={n_state}")
    for name, cnt in dist.most_common(30):
        print(f"  {name:32s} {cnt:6d}")
    print(f"states WITH construction member: {len(construction_states)}")
    # dump first construction state in full
    if construction_states:
        k, vi, cl = construction_states[0]
        print(f"\n== FULL DUMP state {k} ==")
        for kk, vk2, vi2, cl2 in member_list(data, pos, kind, depth, span, vi, cl):
            if vk2 == 'body':
                sub = member_list(data, pos, kind, depth, span, vi2, cl2)
                print(f"  {kk}: body[{int(pos[cl2])-int(pos[vi2]):,}B] n={len(sub)}")
                for k3, vk3, vi3, cl3 in sub[:20]:
                    if vk3 == 'body':
                        s3 = member_list(data, pos, kind, depth, span, vi3, cl3)
                        print(f"    {k3}: body n={len(s3)} keys={[x[0] for x in s3[:10]]}")
                    elif vk3 == 'run':
                        print(f"    {k3}: run={run_to_values(vi3, data)[:6]}")
                    else:
                        print(f"    {k3}: prim={scalar_value(int(kind[vi3]), data, int(pos[vi3]))}")
            elif vk2 == 'run':
                print(f"  {kk}: run={run_to_values(vi2, data)[:6]}")
            else:
                print(f"  {kk}: prim={scalar_value(int(kind[vi2]), data, int(pos[vi2]))}")
    print(f"done in {time.time()-t0:.1f}s")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_16.hoi4"))
    main(p)
