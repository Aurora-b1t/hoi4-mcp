"""bin5 research probe: parse a save limit-by-limit, dump structure, find bad spots.

Usage:
  python research/bin5_probe.py <save.hoi4> [--limit N] [--stat]
    --limit N    parse only the first N bytes after the magic (default: all)
    --stat       collect token usage stats and print the top 40
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.saveparse import bin5 as B


def render(v, depth=0, max_items=6):
    if isinstance(v, B.Obj):
        kinds = []
        for it in v.items[:max_items]:
            if isinstance(it, tuple):
                k, _ = it
                kinds.append("anon" if k == B.TOKEN_ANON else hex(k))
            else:
                kinds.append(type(it).__name__ if not isinstance(it, str) else repr(str(it)[:12]))
        more = " …" if len(v.items) > max_items else ""
        return "{" + f"{len(v.items)} items: " + ', '.join(kinds) + more + "}"
    if isinstance(v, tuple) and v and v[0] == "corrupt":
        return f"!corrupt: {v[1]}"
    return repr(v)


def main():
    path = sys.argv[1]
    data = Path(path).read_bytes()
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])

    stats = {}
    count = [0]
    last = [(None, None, None)]

    def on_pair(key, value, off):
        count[0] += 1
        stats[key] = stats.get(key, 0) + 1
        last[0] = (key, value, off)

    try:
        pairs = B.parse(data, limit=limit, on_pair=on_pair)
    except Exception as exc:
        k, v, off = last[0]
        print(f"UNCAUGHT after {count[0]} pairs, last pair key={k!r} off={off:#x}: {exc!r}")
        if off is not None:
            seg = data[off-32:off+64] if isinstance(off, int) else b""
            print("context:", seg.hex(" "))
        return

    print(f"pairs: {count[0]}, consumed {hex(pairs[-1][2] if pairs else 0)} - {hex(len(data))}")
    shown = 0
    for key, value, off in pairs:
        if "--stat" in sys.argv:
            continue
        if key in (0x356Cf,):
            pass
        print(f"{off:#010x} {('<anon>' if key == B.TOKEN_ANON else hex(key)):>10} = {render(value, 0)[:110]}")
        shown += 1
        if shown >= 60:
            print("...(truncated)")
            break
    if "--stat" in sys.argv:
        top = sorted(stats.items(), key=lambda kv: -kv[1])[:40]
        for k, n in top:
            print(f"  {'anon' if k == B.TOKEN_ANON else hex(k)}: {n}")
        print(f"distinct ids: {len(stats)}")


if __name__ == "__main__":
    main()
