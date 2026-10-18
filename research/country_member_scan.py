"""Aggregate member-name distribution across ALL country bodies; list which
countries carry rare keys (candidate homes for the construction queue).
Usage: python research/country_member_scan.py [save]"""
import sys, time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4copilot.saveparse.tokens import load_tokens
from hoi4copilot.readstate.bin5_scaffold import (walkthrough, find_countries,
                                                country_anchors)
from hoi4copilot.readstate.country_sem import member_list

NAMES = load_tokens()

def main(path):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    _, _, _, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    print(f"{len(anchors)} countries, walk {time.time()-t0:.1f}s")
    dist = Counter()
    holders = defaultdict(list)
    for tag, ti, oi, ck in anchors:
        if ck is None:
            continue
        d0 = int(depth[oi])
        for k, vk, vi, cl in member_list(data, pos, kind, depth, span, oi, ck):
            dist[k] += 1
            if dist[k] <= 3:
                holders[k].append(tag)
    print(f"distinct member keys: {len(dist)}  ({time.time()-t0:.1f}s)")
    for name, cnt in dist.most_common():
        print(f"  {name:36s} {cnt:5d}  e.g.{holders[name][:3]}")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else (
        r"C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/"
        r"save games/GER_1936_03_31_16.hoi4")
    main(p)
