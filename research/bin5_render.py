"""Render HOI4bin5 saves into human-readable semantic trees.

Uses tables/generated/tokens.json (extracted from the live exe, see
hoi4copilot.saveparse.tokens). Controls:

  python research/bin5_render.py <save.hoi4> [--depth N] [--maxlines N]
  python research/bin5_render.py <saveA.hoi4> <saveB.hoi4> --diff
      diff the two statement-lists (same campaign, different times) and
      print only changed token ids and values.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.saveparse import bin5 as B
from hoi4copilot.saveparse.tokens import load_tokens


def show_value(v, names, width=90):
    if isinstance(v, B.Obj):
        return f"{{{len(v.items)} items}}"
    s = repr(v)
    return s if len(s) <= width else s[:width - 1] + "…"


def render_pairs(pairs, names, depth_limit=4, max_lines=400, stats_only=False):
    lines = []

    def walk(key, value, path, depth):
        name = "<anon>" if key == B.TOKEN_ANON else (
            names.get(key, f"T_{key:04x}") if isinstance(key, int) else repr(key))
        if isinstance(value, B.Obj):
            if depth < depth_limit:
                lines.append("  " * depth + f"{name} {{")
                out = 0
                for item in value.items:
                    if isinstance(item, tuple) and isinstance(item[0], (int, str)):
                        walk(item[0], item[1], path + [name], depth + 1)
                        out += 1
                    else:
                        # bare member
                        lines.append("  " * (depth + 1) + show_value(item, names, 50))
                    if len(lines) >= max_lines:
                        lines.append("  " * (depth + 1) + "…")
                        raise StopIteration
                lines.append("  " * depth + "}")
            else:
                lines.append("  " * depth + f"{name} {{{len(value.items)} items}}")
        else:
            lines.append("  " * depth + f"{name} = {show_value(value, names, 70)}")
    try:
        for key, value, off in pairs:
            walk(key, value, [], 0)
            if len(lines) >= max_lines:
                lines.append("…")
                break
    except StopIteration:
        pass
    return lines


def flatten_map(pairs):
    """flat map for diff: {(path tuple): value} using statement-level structure.

    Duplicate keys get an ordinal suffix. Collisions acceptable for research.
    """
    out: dict = {}
    counters: dict = {}

    def norm(path, key, value):
        if isinstance(value, B.Obj):
            for item in value.items:
                if isinstance(item, tuple) and isinstance(item[0], (int, str)):
                    norm(path + [key], item[0], item[1])
            return
        keyn = "<anon>" if key == B.TOKEN_ANON else key
        tp = tuple(path) + (keyn,)
        c = counters.get(tp, 0)
        counters[tp] = c + 1
        out[(tp, c)] = value

    def walk(key, value):
        # leaf: primitives recurse into objs
        if isinstance(value, B.Obj):
            for item in value.items:
                if isinstance(item, tuple) and isinstance(item[0], (int, str)):
                    walk(item[0], item[1])
            return
        norm([], key, value)

    for key, value, off in pairs:
        walk(key, value)
    return out


def diff_saves(path_a, path_b, max_lines=200):
    ta, tb = parse_file(path_a), parse_file(path_b)
    fa, fb = flatten_map(ta), flatten_map(tb)
    names = load_tokens()

    def is_nan_change(va, vb):
        return isinstance(va, float) and isinstance(vb, float) and \
            str(va) == str(vb) == "nan"

    changes = []
    for k in set(fa) | set(fb):
        va, vb = fa.get(k, "<ABSENT>"), fb.get(k, "<ABSENT>")
        if va != vb and not is_nan_change(va, vb):
            changes.append((k, va, vb))
    by_key: dict = {}
    for (path, _), va, vb in changes:
        leaf = path[-1] if path else B.TOKEN_ANON
        by_key.setdefault(leaf, []).append((path, va, vb))
    print(f"A: {path_a}")
    print(f"B: {path_b}")
    print(f"flat: A={len(fa)} B={len(fb)} changed={len(changes)} "
          f"({len(by_key)} distinct keys)")
    rows = sorted(by_key.items(), key=lambda kv: -kv[1][0].__len__() if False else -len(kv[1]))
    for leaf, items in rows:
        kn = "<anon>" if leaf == B.TOKEN_ANON else (
            names.get(leaf, f"T_{leaf:04x}") if isinstance(leaf, int) else str(leaf)[:24])
        path0 = items[0][0]
        ctx = ".".join("<anon>" if x == B.TOKEN_ANON else (
            names.get(x, f"T_{x:04x}") if isinstance(x, int) else str(x)[:12])
            for x in path0[-2:])
        print(f"  {kn!s:>34} x{len(items)}   e.g. ctx={ctx}")
        if len(items) and kn != "<anon>":
            for path, va, vb in items[1:3]:
                print(f"      {show_value(va, names, 54)!r} -> {show_value(vb, names, 54)!r}")


def parse_file(path):
    data = Path(path).read_bytes()
    return B.parse(data)


def main():
    args = sys.argv[1:]
    if "--diff" in args:
        i = args.index("--diff")
        diff_saves(args[0], args[1])
        return
    path = args[0]
    depth = 4
    if "--depth" in args:
        depth = int(args[args.index("--depth") + 1])
    maxl = 400
    if "--maxlines" in args:
        maxl = int(args[args.index("--maxlines") + 1])
    data = Path(path).read_bytes()
    pairs = B.parse(data)
    names = load_tokens()
    for line in render_pairs(pairs, names, depth, maxl):
        print(line)


if __name__ == "__main__":
    main()
