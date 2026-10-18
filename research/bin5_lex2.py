"""bin5 v2: statement-preserving depth walker with payload-accurate tokenizes.

Mechanism: 'p later' cursor walks token positions. Events go into `log`
with the FULL definition:
  token events include: key tokens (u-key), equal, payloads.

Statement structure: (atom EQUAL value) or lone atom, with atoms = id/prim/str.

Top-level (depth0) / X-level all handled via integer stack: 'state' records
current pending key or not. That allows member-aware tree yields.
"""
from __future__ import annotations

import struct
from typing import Callable, Optional

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

LEN_TOKENS = (QUOTED, UNQUOTED)


from bin5_lex3 import token_len as _lex3_token_len


def token_len(data: bytes, p: int) -> int:
    return _lex3_token_len(data, p)



def read_payload(data, p):
    """Return python value of the PAYLOAD at token p (skipping the token),
    or raise if not a value token."""
    t = struct.unpack_from("<H", data, p)[0]
    if t in (EQUAL, OPEN, CLOSE):
        raise ValueError(f"control token at {p:#x}")
    if t == I32:
        return struct.unpack_from("<i", data, p + 2)[0]
    if t == U32:
        return struct.unpack_from("<I", data, p + 2)[0]
    if t == F32:
        return struct.unpack_from("<f", data, p + 2)[0]
    if t == F64:
        return struct.unpack_from("<d", data, p + 2)[0]
    if t == I64:
        return struct.unpack_from("<q", data, p + 2)[0]
    if t == U64:
        return struct.unpack_from("<Q", data, p + 2)[0]
    if t == BOOL:
        return data[p + 2] != 0
    if t in LEN_TOKENS:
        return str_text(data, p)
    raise ValueError(f"id token at {p:#x}: no payload")


def str_text(data, p):
    ln = struct.unpack_from("<H", data, p + 2)[0]
    return data[p + 4:p + 4 + ln].decode("utf-8", "replace")


class Cursor:
    """Brace-depth + payload-skipping walker with unbounded container-skip."""
    __slots__ = ("data", "p", "N", "log")

    def __init__(self, data: bytes, p: int = 0):
        self.data = data
        self.p = p
        self.N = len(data)
        self.log: list = []

    def step(self) -> int:
        """Consume one token; returns (type, payload-or-None)."""
        d = self.data
        p = self.p
        t = struct.unpack_from("<H", d, p)[0]
        ln = token_len(d, p)
        self.p = p + ln
        return t, ln

    def skip_value(self, d0: Optional[int] = None) -> int:
        """Skip the VALUE at current token position (payload or body).

        returns (end position). depth equilibrium: entering depth is
        assumed 0; matching close returns there."""
        depth = 0
        while self.p < self.N:
            t, ln = self.step()
            if t == OPEN:
                depth += 1
            elif t == CLOSE:
                depth -= 1
                if depth == 0:
                    return self.p
                if depth < 0:
                    return self.p
        return self.p


def walk_bins(data: bytes, start: int, limit_end: int = None):
    """Enumerate statements: (key_p, key_kind, value_p, value_end).

    key_kind: 'id' | 'prim' | 'str' | 'anon' (no key, leading =).
    value_end: for prims = end of payload; for body = past matching close.
    """
    cur = Cursor(data, start)
    end = limit_end if limit_end is not None else cur.N
    out = []
    log = []
    while cur.p < end:
        p0 = cur.p
        t, _ = cur.step()
        kkind = ("id" if t not in (EQUAL, OPEN, CLOSE)
                 and t not in (I32, U32, F32, F64, I64, U64, BOOL)
                 and t not in LEN_TOKENS else
                 ("prim" if t in (I32, U32, F32, F64, I64, U64, BOOL) else
                  ("str" if t in LEN_TOKENS else "ctrl")))
        if kkind == "ctrl" and t != EQUAL:
            log.append(p0)
            continue
        if t == EQUAL:
            # anon key = follows
            if cur.p >= end:
                break
            vp = cur.p
            t2, _ = cur.step()
            if t2 == OPEN:
                ve = cur.skip_value()
            else:
                ve = cur.p
            out.append((None, "anon", vp, ve))
            continue
        # normal key atom
        kp = p0
        if cur.p < end:
            t2, _ = cur.step()
        else:
            break
        if t2 != EQUAL:
            # bare atom; do NOT skip it as-if it were an '='-statement
            # (skip_value would consume a real following value)
            out.append((kp, kkind, None, cur.p))
            continue
        if cur.p >= end:
            break
        vp = cur.p
        t3, _ = cur.step()
        if t3 == OPEN:
            ve = cur.skip_value()
        else:
            ve = cur.p
        out.append((kp, kkind, vp, ve))
    return out, log
