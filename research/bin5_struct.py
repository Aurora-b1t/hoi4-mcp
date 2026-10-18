"""Byte-level structural sweep over HOI4bin5 streams.

Unlike the statement-based parser (bin5.parse), this walk is *exact* at the
byte level: every token is either a self-describing atom, an OPEN, a CLOSE,
or an id; payloads (4/8/1-byte prims, u16-length strings) are skipped with
their true lengths. Brace depth is therefore recoverable without resolving
any key/value ambiguity. Errors stay local: a bracket tree is byte-exact and
consumers interpret bodies locally.

We also provide token alignment recovery: given a guess offset, verify that
a u16 token stream + payload skipping lands on a ^EQUAL at the right place;
scan a few byte shifts to find the alignment that yields plausible keys.
"""
from __future__ import annotations

import struct
from typing import Optional

EQUAL = 0x0001
OPEN = 0x0003
CLOSE = 0x0004
I32 = 0x000C
F32 = 0x000D
BOOL = 0x000E
QUOTED = 0x000F
U32 = 0x0014
UNQUOTED = 0x0017
F64 = 0x0167
U64 = 0x029C
I64 = 0x0317

# token id -> payload size (including the 2-byte token itself)
_TOKEN_PAYLOAD = {
    EQUAL: 0, I32: 4, U32: 4, F32: 4, F64: 8, U64: 8, I64: 8, BOOL: 1,
}


class TokenError(Exception):
    pass


def token_len(data: bytes, p: int) -> int:
    """Total length of the token at p (2-byte token + payload), or raise."""
    t = struct.unpack_from("<H", data, p)[0]
    if t in (EQUAL, OPEN, CLOSE):
        return 2
    if t in (I32, U32, F32):
        return 6
    if t in (F64, U64, I64):
        return 10
    if t == BOOL:
        return 3
    if t in (QUOTED, UNQUOTED):
        ln = struct.unpack_from("<H", data, p + 2)[0]
        return 4 + ln
    return 2  # ids


def sweep(data: bytes, start: int, end: int) -> "tuple[list, dict]":
    """Brace-depth pass with exact payload skipping.

    Returns (events, ctx):
      events: list of (depth, off, kind, size); kind in o/c/x(id/equal-tail)
      ctx: {depth_at_end, at_close}

    Consumer rule: within one event list, each entry (off, kind):
      'o' opens a body spanning [off+2, matching-close); 'x' is any
      non-structural token (id/prim payload included atomically).
    """
    events: list = []
    depth = 0
    p = start
    problems = 0
    while p < end:
        off = p
        try:
            ln = token_len(data, p)
        except struct.error:
            break
        t = struct.unpack_from("<H", data, p)[0]
        if t == OPEN:
            events.append((depth, off, "o", ln))
            depth += 1
        elif t == CLOSE:
            depth -= 1
            events.append((depth, off, "c", ln))
        else:
            events.append((depth, off, "x", ln))
        p += ln
        if depth < 0:
            problems += 1
            depth = 0
    ctx = {"depth_end": depth, "overshoots": problems}
    return events, ctx


def depth_report(events) -> dict:
    maxd = 0
    for d, off, kind, ln in events:
        if d > maxd:
            maxd = d
    return {"events": len(events), "max_depth": maxd}


def find_top_statements(data: bytes, start: int, end: int) -> list:
    """Exact (key_off, value_kind, value_off, value_end, key_type) triples for
    depth-0 statements: key may be any token(followed by EQUAL); value slot is
    a prim, an OPEN..CLOSE body, or unknown (id).

    Returns [(key_off, key_token, kind, voff, vend)]: value span for 'body'
    includes braces; for prim = token+payload span."""
    out = []
    events, _ = sweep(data, start, end)
    # index: build open->close pairs stacked inline using the depth dial
    # and walk item-aligned: top-level = depth==0 events; group into
    # (key [x] , '=', value)
    i = 0
    n = len(events)
    while i < n:
        d, off, kind, ln = events[i]
        if d != 0:
            # likely expression junk (depth skew) - skip one event
            i += 1
            continue
        # expect: x(id/key or prim-key) x(EQUAL) then value
        if i + 1 >= n:
            break
        d2, off2, kind2, ln2 = events[i + 1]
        if kind2 != "x":
            out.append((off, -1, kind, off, ln))  # bare, no '='
            i += 1
            continue
        t2 = struct.unpack_from("<H", data, off2)[0]
        if t2 != EQUAL:
            out.append((off, -1, kind, off, ln))
            i += 1
            continue
        if i + 2 >= n:
            break
        _, voff, vkind, vln = events[i + 2]
        if vkind == "o":
            # find matching close: depth at value open is d? events store depth
            # before open; walk to first event with depth == that d and kind c
            vd = events[i + 2][0]
            j = i + 3
            while j < n:
                dj, offj, kj, lnj = events[j]
                if kj := (dj == vd and kind == "c"):
                    break
                j += 1
            vend = (events[j][1] + events[j][3]) if j < n else end
            out.append((off, struct.unpack_from("<H", data, off)[0],
                        "body", voff, vend))
            i = j + 1
        else:
            out.append((off, struct.unpack_from("<H", data, off)[0],
                        "prim", voff, voff + vln))
            i += 3
    return out


def find_alignment(data: bytes, start: int, end: int, max_shift: int = 3) -> int:
    """Try byte shifts; alignment that produces a clean sweep (no negative
    depth overshoot except at very end) wins. Returns best start."""
    best, best_score = start, None
    for shift in range(max_shift):
        try:
            _, ctx = sweep(data, start + shift, end)
        except Exception:
            continue
        score = (ctx["overshoots"], ctx["depth_end"] != 0)
        if best_score is None or score < best_score:
            best, best_score = start + shift, score
    return best
