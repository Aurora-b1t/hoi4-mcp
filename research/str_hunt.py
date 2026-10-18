"""Hunt inline STRING keys (0xF/0x17) by content; cluster by (depth, shape).
Usage: python research/str_hunt.py <text...>"""
import sys, time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4copilot.readstate.bin5_scaffold import walkthrough

def main(path, texts):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    print(f"walk {time.time()-t0:.1f}s tokens={len(kind)}")
    for text in texts:
        b = text.encode("utf-8")
        print(f"\n### '{text}'")
        ctx = Counter()
        samples = []
        hits = 0
        for i in range(len(kind)):
            t = int(kind[i])
            if t not in (0xF, 0x17):
                continue
            p = int(pos[i])
            ln = data[p+2] | (data[p+3] << 8)
            if ln != len(b) or data[p+4:p+4+ln] != b:
                continue
            hits += 1
            nxt = int(kind[i+1]) if i+1 < len(kind) else 0
            nxt2 = int(kind[i+2]) if i+2 < len(kind) else 0
            shape = ("=body" if nxt == 0x0001 and nxt2 == 0x0003 else
                     "=prim" if nxt == 0x0001 else "bare")
            ctx[(int(depth[i]), shape)] += 1
            if len(samples) < 12:
                samples.append((int(pos[i]), int(depth[i]), shape))
        print(f"  hits={hits}")
        for (d, shape), cnt in sorted(ctx.items()):
            print(f"  depth={d:2d} {shape:6s} x{cnt}")
        for s in samples[:12]:
            print(f"    @{s[0]:#x} d={s[1]} {s[2]}")
    print(f"done {time.time()-t0:.1f}s")

if __name__ == "__main__":
    DEFAULT = (r"C:/Users/hongyu_tang/Documents/Paradox Interactive/"
               r"Hearts of Iron IV/save games/GER_1936_03_31_16.hoi4")
    args = sys.argv[1:]
    if args and Path(args[0]).suffix in (".hoi4", ".bin"):
        p, texts = args[0], args[1:]
    else:
        p, texts = DEFAULT, args
    main(p, texts or ["infrastructure"])
