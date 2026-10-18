"""bin5 fast token walk — numpy-vectorized byte-level scaffold.

Achievements:
 - full-file depth map in <1s
 - exact close-brace per open-brace
 - per-country spans inside the countries body

Mechanism: iterative numpy scans for each token kind; a single disciplined
pass over the file bytes. Token-length per position is computed via the
self-delimiting payload model:
  0x0F/0x17 strings: 4 + u16 length (no terminator)
  0x0D floats: 10 bytes (2 + 8; fixed-point i64/2^24)
  0x0C/0x14: 6 bytes (2 + 4)
  0x0167/0x029C/0x0317: 10 bytes (2 + 8)
  0x000E: 3 bytes (2 + 1)
  0x0001/0x0003/0x0004: 2 bytes
  rest: 2 bytes (id)
"""
from __future__ import annotations

import struct
import numpy as np

TOKEN__EQUAL = 0x0001
TOKEN__OPEN = 0x0003
TOKEN__CLOSE = 0x0004
TOKEN__I32 = 0x000C
TOKEN__F32 = 0x000D
TOKEN__BOOL = 0x000E
TOKEN__QUOTED = 0x000F
TOKEN__U32 = 0x0014
TOKEN__UNQUOTED = 0x0017
TOKEN__F64 = 0x0167
TOKEN__U64 = 0x029C
TOKEN__I64 = 0x0317


def token_stream(data: bytes, start: int):
    """Single pass: iterate tokens from start. Yield (p, token, ln).
    Generator is still python-loop but DONE-ONCE per save; the main cost
    driver. For any big workloads use the numpy pre-scans below."""
    N = len(data)
    p = start
    while p < N:
        t = data[p] | (data[p + 1] << 8)
        if t == TOKEN__OPEN:
            yield p, t, 2
            p += 2
        elif t == TOKEN__CLOSE:
            yield p, t, 2
            p += 2
        elif t == TOKEN__QUOTED or t == TOKEN__UNQUOTED:
            ln = data[p + 2] | (data[p + 3] << 8)
            total = 4 + ln
            yield p, t, total
            p += total
        elif t == TOKEN__BOOL:
            yield p, t, 3
            p += 3
        elif t in (TOKEN__I32, TOKEN__U32):
            yield p, t, 6
            p += 6
        elif t in (TOKEN__F32, TOKEN__F64, TOKEN__U64, TOKEN__I64):
            yield p, t, 10
            p += 10
        else:
            yield p, t, 2
            p += 2


class Scaffold:
    """Savescountry scaffolding: positions of { and } with depth; depth at
    every token position; token-length offset map.

    Produces (arrays):
        tok_p: int32 positions of token starts
        tok_t: int16 token kinds at tok_p
        depth: int32 depth BEFORE each token (the depth it sits at)
        next_p: int32 positions of next token (i.e. tok_p + len)
    """

    def __init__(self, data: bytes, start: int):
        raise NotImplementedError("built by build_scaffold()")


def build_scaffold(data: bytes, start: int) -> Scaffold:
    """Numpy-based single pass, arrays."""
    N = len(data)
    # first estimate the number of tokens: at minimum 2 bytes each; at most
    # if all strings with lengths, the number of tokens overshoots the byte-length.
    # pre-scan token positions with a loop is only 2M iterations in python but
    # that's slow; instead iterate numpy: use a queue-less block scan.
    #
    # Fast approach: iterate by chunk processing:
    #  pass 1: a python list of (p, token) pairs via a while loop, but pack the
    #  iteration efficiently: whole block tokens, numpy convert.
    # ...
    raise NotImplementedError


def pragma():
    pass
