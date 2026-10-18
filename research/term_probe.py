"""bin5 string-terminator discovery + depth simulator.

Phase A (recon): at a W point (string | W' | '=' | '{'), try terminator
variants and simulate depth from W to the next W' anchor; report variant(s)
whose predicted W' offset matches ground truth, and their depth residuals.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, r"D:/hoi4-copilot/")
sys.path.insert(0, r"D:/hoi4-copilot/research")

from bin5_struct import token_len

EQUAL = 0x0001
OPEN = 0x0003
CLOSE = 0x0004
QUOTED = 0x000F
I32 = 0x000C
F32 = 0x000D
BOOL = 0x000E
U32 = 0x0014
UNQUOTED = 0x0017
F64 = 0x0167
U64 = 0x029C
I64 = 0x0317

LEN_TOKENS = (QUOTED, UNQUOTED)


def tl(data, p, term: int) -> int:
    """Token length at p given string terminator variant."""
    t = struct.unpack_from("<H", data, p)[0]
    if t in LEN_TOKENS:
        ln = struct.unpack_from("<H", data, p + 2)[0]
        return 4 + ln + term
    if t in (EQUAL, OPEN, CLOSE):
        return 2
    if t in (I32, U32, F32):
        return 6
    if t in (F64, U64, I64):
        return 10
    if t == BOOL:
        return 3
    return 2


def str_text(data, p) -> str:
    ln = struct.unpack_from("<H", data, p + 2)[0]
    return data[p + 4:p + 4 + ln].decode("utf-8", "replace")


def simulate(data, p0, d0, term: int, limit: int = 40_000):
    """Walk tokens from p0 at depth d0; return (end_p, depth_at_end,
    anchor_hits); anchor = depth==d0 string with = { following."""
    p = p0
    d = d0
    N = len(data)
    anchors = []
    while True:
        if p >= N or p > limit:
            if d != d0:
                return None
            break
        t = struct.unpack_from("<H", data, p)[0]
        if t == OPEN:
            d += 1
            p += 2
            continue
        if t == CLOSE:
            d -= 1
            if d < d0:
                # body end
                return (p, d, anchors)
            p += 2
            continue
        if t in LEN_TOKENS:
            try:
                text = str_text(data, p)
            except Exception:
                return None
            w = p
            p_next = p + tl(data, p, term)
            q = p_next
            if q >= N or struct.unpack_from("<H", data, q)[0] != EQUAL:
                p = p_next
                continue
            q += 2
            if q >= N or struct.unpack_from("<H", data, q)[0] != OPEN:
                # bare string value (e.g. = next token non-brace); skip
                vt = struct.unpack_from("<H", data, q)[0]
                p = q + tl(data, q, term)
                continue
            # anchor found only if back at d0
            if d == d0:
                q += 2
                anchors.append((w, d, text))
                p = q
                continue
            # string attribute at deeper level: just consume whole statement
            p = q + 2  # consumed = and {
            d += 1
            continue
        # other tokens
        p += tl(data, p, term)
    return (p, d, anchors)


COUNTRIES_ANCHOR = 7910706


def phase_a(paths, start_after=COUNTRIES_ANCHOR):
    data = Path(paths[0]).read_bytes()
    N = len(data)
    # W0: the countries open (d0=1 stakeout). W: its first string anchor
    # "GER" (known) at 7910712, open 7910710 (d=1).
    W_open = 7910710
    assert struct.unpack_from("<H", data, W_open)[0] == OPEN
    anchors = []
    p = W_open + 2
    cnt = 0
    while p < N and cnt < 40:
        t = struct.unpack_from("<H", data, p)[0]
        if t == OPEN and struct.unpack_from("<H", data, p)[0] == OPEN:
            anchors.append(p)
            cnt += 1
        p += tl(data, p, 0)
    if not anchors:
        print("no stage-2 anchors; abort")
        return
    W = anchors[0] - 4  # before '=' before '{' before open
    # verify: W = QUOTED "GER"
    assert struct.unpack_from("<H", data, W)[0] == QUOTED, f"W={W:#x}"
    d0 = 1  # inside countries body
    print(f"W      = {W} ({str_text(data, W)!r})")
    print(f"W_open = {W_open}, d0 countries body")
    # W' ground truth by string search
    gt = []
    FIND = b"ENG"
    p = W
    while True:
        p = data.find(FIND, p + 4)
        if p < 0:
            break
        if (p - 4 == 0 or data[p-1] != 0) or True:
            pass
        # must be QUOTED at p-2... we want position of the QUOTED token
        tok = struct.unpack_from("<H", data, p - 2)[0]
        if tok in LEN_TOKENS:
            nxtt = struct.unpack_from("<H", data, p + (4 - 2) + len(FIND) - 4 + 2)[0]
            gt.append(p - 2)
    if not gt:
        print("no ENG quoted token found?!"); return
    W_GT = gt[0]
    print(f"next anchor ground truth: {W_GT:#x} ({W_GT})")
    print("variants:")
    for term in (0, 1, 2):
        res = simulate(data, W_open + 2, d0, term, limit=W_GT + 4_000_000)
        if res is None:
            print(f"  term={term}: no result (unbalanced)")
            continue
        end_p, d_end, a_list = res
        tag = "HIT " if a_list and a_list[0][0] == W_GT else "MISS"
        print(f"  term={term}: anchors={len(a_list)} first={a_list[0] if a_list else None} "
              f"depth_end={d_end} end_p={end_p} {tag}")


if __name__ == "__main__":
    paths = sys.argv[1:] or [r"C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games/GER_1936_02_25_08.hoi4"]
    phase_a(paths)
