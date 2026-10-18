"""Hunt every occurrence of a given key token in the save with depth + local
context, to find where a concept (construction) really lives.
Usage: python research/tok_hunt.py [save] [keyname...]"""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4_mcp.saveparse.tokens import load_tokens
from hoi4_mcp.readstate.bin5_scaffold import walkthrough

NAMES = load_tokens()
BY_NAME = {v: k for k, v in NAMES.items()}

def key_txt(data, pos, kind, i):
    t = int(kind[i])
    if t in (0x000F, 0x0017):
        p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
        return data[p+4:p+4+ln].decode("utf-8", "replace")
    return NAMES.get(t, f"T_{t:04X}")

def main(path, keynames):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    print(f"walk {time.time()-t0:.1f}s tokens={len(kind)}")
    for keyname in keynames:
        tok = BY_NAME.get(keyname)
        print(f"\n### {keyname}: token {tok:#06x}" if tok is not None
              else f"\n### {keyname}: NOT IN TOKEN TABLE")
        if tok is None:
            continue
        sites = [i for i in range(len(kind)) if int(kind[i]) == tok]
        print(f"  occurrences: {len(sites)}")
        # context: previous key + whether followed by '=' '{'
        from collections import Counter
        ctx = Counter()
        for i in sites:
            prev = key_txt(data, pos, kind, i-1) if i else "?"
            nxt = int(kind[i+1]) if i+1 < len(kind) else 0
            nxt2 = int(kind[i+2]) if i+2 < len(kind) else 0
            shape = ("=body" if nxt == 0x0001 and nxt2 == 0x0003 else
                     "=prim" if nxt == 0x0001 else "bare")
            ctx[(int(depth[i]), shape)] += 1
        for (d, shape), cnt in sorted(ctx.items()):
            print(f"  depth={d:2d} {shape:6s} x{cnt}")
        # sample contexts: show prev-key for depth<=2 sites
        shown = 0
        for i in sites:
            d = int(depth[i])
            if d > 2:
                continue
            prev = key_txt(data, pos, kind, i-1) if i else "?"
            nxt = int(kind[i+1]) if i+1 < len(kind) else 0
            nxt2 = int(kind[i+2]) if i+2 < len(kind) else 0
            shape = ("=body" if nxt == 0x0001 and nxt2 == 0x0003 else
                     "=prim" if nxt == 0x0001 else "bare")
            print(f"    @{int(pos[i]):#x} d={d} after[{prev}] {shape}")
            shown += 1
            if shown >= 25:
                break
    print(f"\ndone {time.time()-t0:.1f}s")

if __name__ == "__main__":
    DEFAULT = (str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_16.hoi4"))
    args = sys.argv[1:]
    if args and Path(args[0]).suffix in (".hoi4", ".bin"):
        p, keys = args[0], args[1:]
    else:
        p, keys = DEFAULT, args
    main(p, keys or ["construction"])
