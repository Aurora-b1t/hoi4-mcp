"""bin5 tokenizer — single-pass walk that records every token position, kind,
and the depth map; decked into a per-country scaffold. Kept lean for speed.

Pitch: one 4-5s python loop over 10M tokens; then numpy reduction to find:
  'countries' at depth0 and country-tag anchors at depth1.
O/C/str site lists recorded as arrays for branch targeting.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "research"))


def walkthrough(data: bytes, start: int):
    """Walk the full file, returning:
        pos:   int32[n_tokens]   token positions
        kind:  uint16[n_tokens]  token kinds (incl. control tokens)
        depth: int32[n_tokens]   depth BEFORE the token (it sits there)
        span:  int32[n_tokens]   token length (bytes consumed)
    """
    N = len(data)
    mv = memoryview(data)
    # lists, with generous presizing
    pos = np.empty(N // 3 + 1024, dtype=np.int64)
    kind = np.empty(N // 3 + 1024, dtype=np.uint16)
    depth = np.empty(N // 3 + 1024, dtype=np.int32)
    span = np.empty(N // 3 + 1024, dtype=np.int32)
    n = 0
    p = start
    d = 0
    while p < N:
        h, l = mv[p], mv[p + 1]
        t = h | (l << 8)
        if t == 3 or t == 4:
            ln = 2
        elif t == 0xF or t == 0x17:
            ln = 4 + (mv[p + 2] | (mv[p + 3] << 8))
        elif t == 0xE:
            ln = 3
        elif t == 0xC or t == 0x14:
            ln = 6
        elif t == 0x167 or t == 0x29C or t == 0x317 or t == 0xD:
            ln = 10
        else:
            ln = 2
        pos[n] = p
        kind[n] = t
        depth[n] = d
        span[n] = ln
        if t == 3:
            d += 1
        elif t == 4:
            d -= 1
        n += 1
        p += ln
    return pos[:n], kind[:n], depth[:n], span[:n]


def find_countries(data: bytes, start: int, pos, kind, depth, span):
    """Locate the top-level 'countries' statement. Returns (key_p, open_p,
    close_p, anchor_indexes, tag_list)."""
    N = len(data)
    # token id 0x2D49 = 'countries'; str-key country tags are QUOTED with = {
    sites = np.nonzero(kind == 0x2D49)[0]
    for i in sites:
        p = int(pos[i])
        # next tokens: '=' then '{'
        j = i + 1
        if j >= len(kind) or kind[j] != 0x0001:
            continue
        j += 1
        if j >= len(kind) or kind[j] != 0x0003:
            continue
        close_i = find_matching(kind, j + 1)
        if close_i is None:
            continue
        # this must be a depth-0 statement:
        if int(depth[i]) != 0:
            continue
        return (p, int(pos[j]), int(pos[close_i]) + int(span[close_i]),
                j + 1, close_i)
    raise ValueError("top-level countries not found")


def find_matching(kind: np.ndarray, open_i: int) -> int | None:
    """Index of the close-brace token closing the OPEN at open_i."""
    d = 1
    i = open_i + 1
    n = len(kind)
    while i < n:
        t = kind[i]
        if t == 0x0003:
            d += 1
        elif t == 0x0004:
            d -= 1
            if d == 0:
                return int(i)
        i += 1
    return None


def country_anchors(data: bytes, pos, kind, depth, span, inner_open_i, close_i):
    """Enumerate country tags: QUOTED tokens at relative depth0 within
    [inner_open_i, close_i) followed by '=' and '{'. Returns [(tag, tok_idx,
    open_idx, close_idx)] with closes pinned by matching."""
    seg = range(inner_open_i, close_i)
    out = []
    pending = []
    # STEP1: find candidates
    for i in seg:
        t = int(kind[i])
        if t not in (0xF, 0x17):
            continue
        d = int(depth[i])
        if d >= int(depth[inner_open_i]) + 1:
            # inside country bodies only after open — check: depth==1 relative
            pass
        rel = d - int(depth[inner_open_i])
        if rel != 0:
            continue
        p = int(pos[i])
        ln2 = data[p + 2] | (data[p + 3] << 8)
        txt = data[p + 4:p + 4 + ln2].decode("utf-8", "replace")
        nxt = int(kind[i + 1])
        nxt2 = int(kind[i + 2])
        if nxt == 0x0001 and nxt2 == 0x0003 and 2 <= len(txt) <= 8:
            out.append((txt, i, i + 2, None))
        # skip the string's payload & its next 2 tokens
        # we'll move through the range sequentially anyway
    # STEP2: compute per-anchor close
    for k, (tag, ti, oi, _ck) in enumerate(out):
        out[k] = (tag, ti, oi, find_matching(kind, oi + 1))
    return out


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_02_25_08.hoi4"))
    data = Path(path).read_bytes()
    t0 = time.time()
    pos, kind, depth, span = walkthrough(data, data.find(b"HOI4bin5*") + 9)
    t1 = time.time()
    key_p, open_p, close_p, inner_open_i, inner_close_i = find_countries(
        data, 9, pos, kind, depth, span)
    t2 = time.time()
    anchors = country_anchors(data, pos, kind, depth, span, inner_open_i, inner_close_i)
    t3 = time.time()
    print(f"walk={t1-t0:.2f}s  countries={key_p:#x} body[{open_p:#x},{close_p:#x})"
          f" {close_p-open_p:,}b  find={t2-t1:.2f}s anchors={t3-t2:.2f}s")
    print(f"country tags: {len(anchors)}: first {[a[0] for a in anchors[:10]]}"
          f"... last {[a[0] for a in anchors[-3:]]}")
    if anchors:
        g = anchors[0]
        ti, oi, ck = g[1], g[2], g[3]
        print(f"GER: tok@{int(pos[ti]):#x} open@{int(pos[oi]):#x}"
              f" close@{int(pos[ck]):#x} size={int(pos[ck])-int(pos[oi]):,}")
