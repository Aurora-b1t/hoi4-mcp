"""bin5 v2 lexer (research).

Core update over bin5_struct: QUOTED/UNQUOTED strings carry a 2-byte
terminator after the text bytes (observed empirically; verified by the
ENG-anchor byte pattern). All other payload sizes unchanged.

This makes the token stream STEP-CONSISTENT: bracket structures as certs
(depth stack per statement-level parse). Everything downstream is a
consumer (segment/anchor model).
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
    """Total length of the token at p (self-delimiting bytes), or raise."""
    t = struct.unpack_from("<H", data, p)[0]
    if t in (EQUAL, OPEN, CLOSE):
        return 2
    if t in (I32, U32, F32):
        return 6
    if t in (F64, U64, I64):
        return 10
    if t == BOOL:
        return 3
    if t in LEN_TOKENS:
        ln = struct.unpack_from("<H", data, p + 2)[0]
        return 4 + ln + 2      # +2: empirically verified terminator
    return 2  # ids


def str_text(data: bytes, p: int) -> str:
    """String value at p (QUOTED/UNQUOTED token)."""
    t = struct.unpack_from("<H", data, p)[0]
    if t not in LEN_TOKENS:
        raise ValueError(f"not a string token at {p:#x}")
    ln = struct.unpack_from("<H", data, p + 2)[0]
    return data[p + 4:p + 4 + ln].decode("utf-8", "replace")
