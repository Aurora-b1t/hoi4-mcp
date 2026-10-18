"""Survey the TOP-LEVEL structure of a .hoi4 save: every top-level member
with its byte span, so we know which global bodies exist besides countries.
Usage: python research/top_survey.py [save.hoi4]"""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4copilot.saveparse.tokens import load_tokens
from hoi4copilot.readstate.bin5_scaffold import walkthrough, find_matching

NAMES = load_tokens()

def key_of(data, pos, kind, i):
    t = int(kind[i])
    if t in (0x000F, 0x0017):
        p = int(pos[i]); ln = data[p + 2] | (data[p + 3] << 8)
        return data[p + 4:p + 4 + ln].decode("utf-8", "replace")
    return NAMES.get(t, f"T_{t:04X}")

def main(path):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    print(f"walkthrough {len(data)/1e6:.1f}MB in {time.time()-t0:.1f}s, "
          f"{len(kind)} tokens")
    # walk top level (depth 0): statements and bodies
    i = 0
    n = len(kind)
    rows = []
    while i < n:
        d = int(depth[i])
        if d != 0:
            i += 1
            continue
        t = int(kind[i])
        if t == 0x0004:
            i += 1
            continue
        # statement head: key [ = value]
        k = key_of(data, pos, kind, i)
        eq = int(kind[i + 1]) if i + 1 < n else 0
        if eq == 0x0001:
            vt = int(kind[i + 2])
            if vt == 0x0003:
                cl = find_matching(kind, i + 2)
                size = int(pos[cl]) - int(pos[i + 2])
                rows.append((k, "body", size, i, cl))
                i = cl + 1
                continue
            rows.append((k, "prim", 0, i, i + 2))
            i += 3
            continue
        rows.append((k, "bare", 0, i, i))
        i += 1
    print(f"{'key':38s} {'kind':5s} {'size':>12s}")
    for k, kk, size, a, b in rows:
        print(f"{k:38s} {kk:5s} {size:12,d}")
    print(f"total {len(rows)} top-level members in {time.time()-t0:.1f}s")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        r"C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/"
        r"save games/GER_1936_03_31_16.hoi4")
    main(p)
