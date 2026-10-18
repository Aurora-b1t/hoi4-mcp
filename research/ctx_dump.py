"""Dump token-level context around specific string-key occurrences: show
neighbouring tokens (key=value groups) so we can see the local structure.
Usage: python research/ctx_dump.py <text> <which=depth:shape> [-all]"""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4copilot.saveparse.tokens import load_tokens
from hoi4copilot.readstate.bin5_scaffold import walkthrough
from hoi4copilot.readstate.world_state import scalar_value

NAMES = load_tokens()

def tok_txt(data, pos, kind, i):
    t = int(kind[i])
    if t in (0x000F, 0x0017):
        p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
        return data[p+4:p+4+ln].decode("utf-8", "replace")
    if t == 0x0003:
        return "{"
    if t == 0x0004:
        return "}"
    if t == 0x0001:
        return "="
    v = scalar_value(t, data, int(pos[i]))
    return NAMES.get(t, f"T_{t:04X}") if v is None else repr(v)

def main(path, text, depth_want, shape_want, n_show=3, ctx=36):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    b = text.encode("utf-8")
    shown = 0
    for i in range(len(kind)):
        t = int(kind[i])
        if t not in (0xF, 0x17):
            continue
        p = int(pos[i])
        ln = data[p+2] | (data[p+3] << 8)
        if ln != len(b) or data[p+4:p+4+ln] != b:
            continue
        nxt = int(kind[i+1]) if i+1 < len(kind) else 0
        nxt2 = int(kind[i+2]) if i+2 < len(kind) else 0
        shape = ("=body" if nxt == 0x0001 and nxt2 == 0x0003 else
                 "=prim" if nxt == 0x0001 else "bare")
        if int(depth[i]) != depth_want or shape != shape_want:
            continue
        lo = max(0, i - ctx); hi = min(len(kind), i + ctx)
        parts = []
        for j in range(lo, hi):
            s = tok_txt(data, pos, kind, j)
            mark = f"[{s}]" if j == i else s
            parts.append(mark)
        print(f"@{p:#x} depth={int(depth[i])}\n  " + "\n  ".join(
            [f"{' '.join(parts[:ctx//2])}",
             f"{' '.join(parts[ctx//2:])}"]))
        shown += 1
        if shown >= n_show:
            break
    print(f"({shown} shown, {time.time()-t0:.1f}s)")

if __name__ == "__main__":
    DEFAULT = (r"C:/Users/hongyu_tang/Documents/Paradox Interactive/"
               r"Hearts of Iron IV/save games/GER_1936_03_31_16.hoi4")
    args = sys.argv[1:]
    if args and Path(args[0]).suffix in (".hoi4", ".bin"):
        p, rest = args[0], args[1:]
    else:
        p, rest = DEFAULT, args
    text = rest[0]
    d, shape = rest[1].split(":")
    main(p, text, int(d), shape)
