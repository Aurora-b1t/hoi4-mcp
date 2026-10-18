"""Extract HOI4's compile-time key-token table from the loaded exe image.

Save keys are u16 ids indexing a static table built into the binary. We find
anchor strings ("game_version", "difficulty", ...) inside the image, then the
qword pointers that reference them; the pointer array around them IS the
token table and (pos - table_start)/8 is the id.

Run: python research/token_table.py   (game must be running)
Writes tables/generated/tokens.json
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import re
import struct

import numpy as np

from hoi4_mcp import config
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import Game

ANCHORS = [b"game_version\x00", b"difficulty\x00", b"player_ledger\x00",
           b"date\x00", b"ideology\x00", b"very_easy\x00", b"player\x00"]


def main():
    g = Game()
    p = g.proc
    base = p.base

    img = w.read_process_memory(p.handle, base, p.image_size)
    print(f"image {p.image_size/1e6:.1f} MB read")

    # string anchor VAs
    anchor_vas = {}
    for a in ANCHORS:
        needle = a[:-1]  # without NUL for the \0-terminated check
        for m in re.finditer(re.escape(a), img):
            va = base + m.start()
            name = a[:-1].decode()
            anchor_vas.setdefault(name, []).append(va)
    print("anchor occurrences:", {k: [hex(v) for v in vs] for k, vs in anchor_vas.items()})

    q = np.frombuffer(img[: (len(img) // 8) * 8], dtype=np.uint64)

    # pointers to anchors
    ptr_pos = []
    for name, vas in anchor_vas.items():
        for va in vas:
            hits = np.nonzero(q == np.uint64(va))[0]
            for h in hits.tolist():
                ptr_pos.append((h, name, va))
    ptr_pos.sort()
    print("pointer refs found:", len(ptr_pos), [(hex(base + h*8), n) for h, n, _ in ptr_pos[:12]])

    if not ptr_pos:
        print("no pointers into image strings; trying hash-table scheme")
        return

    # cluster pointers that are adjacent (spacing 8) => array
    positions = [h for h, _, _ in ptr_pos]
    clusters = []
    cur = [positions[0]]
    for x in positions[1:]:
        if x - cur[-1] <= 8:
            cur.append(x)
        else:
            clusters.append(cur)
            cur = [x]
    clusters.append(cur)
    clusters.sort(key=len, reverse=True)
    print("clusters:", [(len(c), hex(base + c[0]*8)) for c in clusters[:6]])

    # take the largest cluster as table; determine array start = first ptr pos
    best = clusters[0]
    start_idx = best[0]
    # dump a wide window around to find array bounds: pointers to ascii strings
    def looks_like_string_ptr(v):
        return v and base <= v < base + p.image_size

    # find array start: walk left from start_idx while qwords are string ptrs
    lo = start_idx
    while lo > 0 and looks_like_string_ptr(int(q[lo-1])):
        lo -= 1
    hi = start_idx
    while hi < len(q) - 1 and looks_like_string_ptr(int(q[hi+1])):
        hi += 1
    print("array bounds idx:", lo, hi, "size:", hi - lo + 1)

    table = {}
    for idx in range(lo, hi + 1):
        va = int(q[idx])
        rva = va - base
        # read the string from the image buffer
        off = rva  # file RVA maps linearly to buffer position only within mapped sections
        end = img.find(b"\x00", off, off + 200)
        if end < 0:
            continue
        raw = img[off:end]
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if s and all(32 <= ord(ch) < 127 or ord(ch) > 0x2E80 for ch in s):
            table[idx - lo] = s

    out = config.TABLES_DIR / "tokens.json"
    out.write_text(json.dumps({"table_start_rva": (base + lo*8) - base, "tokens": table}, indent=0))
    print(f"token table size: {len(table)} -> {out}")
    for k in (0x012A, 0x2E3E, 0x299F, 0x00EE, 0x284A, 0xEDFF, 0x000B, 0x0021):
        print(hex(k), "->", table.get(k, "?"))


if __name__ == "__main__":
    main()
