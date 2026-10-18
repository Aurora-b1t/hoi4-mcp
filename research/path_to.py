"""Find the member path (country member -> ... ->) whose body span covers a
given byte offset. Usage: python research/path_to.py [save] [byte_offset]"""
import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hoi4copilot.saveparse.tokens import load_tokens
from hoi4copilot.readstate.bin5_scaffold import (walkthrough, find_countries,
                                                country_anchors)
from hoi4copilot.readstate.country_sem import member_list

NAMES = load_tokens()

def main(path, target_byte):
    data = Path(path).read_bytes()
    t0 = time.time()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    _, _, _, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    host = None
    for tag, ti, oi, ck in anchors:
        if ck is None:
            continue
        a, b = int(pos[oi]), int(pos[ck])
        if a <= target_byte <= b:
            host = (tag, oi, ck)
            break
    if host is None:
        print("byte not inside any country body")
        return
    tag, oi, ck = host
    print(f"byte {target_byte:#x} inside country {tag}")
    # recursive descent: find member bodies covering the target
    path_keys = []
    # find top member
    best = None
    for k, vk, vi, cl in member_list(data, pos, kind, depth, span, oi, ck):
        if vk != 'body':
            continue
        a, b = int(pos[vi]), int(pos[cl])
        if a <= target_byte <= b:
            best = (k, vi, cl)
            break
    lvl = 0
    cur = best
    while cur:
        k, vi, cl = cur
        path_keys.append(k)
        inner = member_list(data, pos, kind, depth, span, vi, cl)
        nxt = None
        for k2, vk2, vi2, cl2 in inner:
            if vk2 != 'body':
                continue
            a, b = int(pos[vi2]), int(pos[cl2])
            if a <= target_byte <= b and b - a > 4:
                nxt = (k2, vi2, cl2)
                break
        cur = nxt
    print("  path: " + " -> ".join(path_keys))
    print(f"  ({time.time()-t0:.1f}s)")

if __name__ == "__main__":
    DEFAULT = (r"C:/Users/hongyu_tang/Documents/Paradox Interactive/"
               r"Hearts of Iron IV/save games/GER_1936_03_31_16.hoi4")
    args = sys.argv[1:]
    if args and args[0].startswith("0x"):
        p, off = DEFAULT, int(args[0], 16)
    elif args and Path(args[0]).suffix in (".hoi4", ".bin"):
        p, off = args[0], int(args[1], 16) if len(args) > 1 else 0
    else:
        p, off = DEFAULT, int(args[0], 16) if args else 0x81061b
    main(p, off)
