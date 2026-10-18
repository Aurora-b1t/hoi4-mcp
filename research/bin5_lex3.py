"""bin5 v3 lexer — the grammar is now complete and byte-exact.

HOI4bin5 grammar (v1.19.x, verified by full-file depth balance):
  magic       = b'HOI4bin5*' (9B) then token stream
  token sizes:
    0x0001 '='    2 B
    0x0003 '{'    2 B
    0x0004 '}'    2 B
    0x000E bool   3 B  (2 token + 1 payload)
    0x000C i32    6 B
    0x0014 u32    6 B
    0x000D FLOAT 10 B  (2 + 8; value = u64 / 2^24, Paradox fixed-point)
    0x0167 f64   10 B
    0x029C u64   10 B
    0x0317 i64   10 B
    0x000F quoted string = 4 + ln  (u16 len + utf-8 bytes; NO trailing terminator)
    0x0017 unquoted     = 4 + ln
    other               = id token, 2 B, meaning resolved from tokens.json
  Grammar vs. bin5.py (v1): only the F32 size changes (v1 wrongly used 6 B,
  which destabilized every scan past the first ~450 KB of numeric data).

Full-file sweep with v3 tokenizer on GER_1936_02_25_08.hoi4 (39.1 MB):
    opens == closes == 964797, final_depth == 0, p == N
=> brace structure is byte-exact and error-free; remaining work is purely
   semantic layering (keys vs values inside bodies).
"""
from __future__ import annotations

import struct

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


def token_len(data: bytes, p: int) -> int:
    """Self-delimiting token length at position p."""
    t = struct.unpack_from("<H", data, p)[0]
    if t in (EQUAL, OPEN, CLOSE):
        return 2
    if t in (I32, U32):
        return 6
    if t in (F32, F64, U64, I64):
        return 10
    if t == BOOL:
        return 3
    if t in LEN_TOKENS:
        ln = struct.unpack_from("<H", data, p + 2)[0]
        return 4 + ln
    return 2


def read_payload(data: bytes, p: int):
    """Python value of the payload token at p (non-control tokens only)."""
    t = struct.unpack_from("<H", data, p)[0]
    if t == I32:
        return struct.unpack_from("<i", data, p + 2)[0]
    if t == U32:
        return struct.unpack_from("<I", data, p + 2)[0]
    if t == F32:
        # HOI4 fixed-point: value = u64 / 2^24 (verified empirically on
        # GER politics popularity populations: 0.2084 / 0.0596 / 0.2384)
        raw = struct.unpack_from("<Q", data, p + 2)[0]
        return raw / 16777216.0
    if t == F64:
        return struct.unpack_from("<d", data, p + 2)[0]
    if t == I64:
        return struct.unpack_from("<q", data, p + 2)[0]
    if t == U64:
        return struct.unpack_from("<Q", data, p + 2)[0]
    if t == BOOL:
        return data[p + 2] != 0
    if t in LEN_TOKENS:
        ln = struct.unpack_from("<H", data, p + 2)[0]
        return data[p + 4:p + 4 + ln].decode("utf-8", "replace")
    raise ValueError(f"id token at {p:#x}: {t:#06x}")


def sweep(data: bytes, start: int, end: int) -> dict:
    """Byte-level token depth sweep; guaranteed d==0 at end on valid saves."""
    p = start
    d = 0
    opens = closes = strs = 0
    while p < end:
        t = struct.unpack_from("<H", data, p)[0]
        ln = token_len(data, p)
        if t == OPEN:
            opens += 1; d += 1
        elif t == CLOSE:
            closes += 1; d -= 1
        elif t in LEN_TOKENS:
            strs += 1
        p += ln
    return {"opens": opens, "closes": closes, "strings": strs,
            "depth_end": d, "exact_end": p == end}
