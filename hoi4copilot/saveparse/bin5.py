"""HOI4bin5 save parser (Jomini binary, per rakaly/jomini lexer table).

Layout on disk: magic "HOI4bin5*" is 9 bytes (`HOI4bin5` + 0x2A), the token
stream follows. Grammar observed on 1.19.3 vanilla saves:

    document : stmt* EOF                     (no braces at top level)
    stmt     : id EQUAL value
             | EQUAL value                   (leading anonymous key, observed once)
    value    : OPEN body CLOSE
             | prim+                         (vector-ish runs of primitives)
    body     : ( id EQUAL value | id | prim | EQUAL value )*

Token types: 0x0001 '=' 0x0003 '{' 0x0004 '}' 0x000C i32 0x000D f32
0x000E bool 0x000F quoted-string(u16 len) 0x0014 u32 0x0017 unquoted-string
0x0167 f64 0x029C u64 0x0317 i64

id->name resolution is NOT in the file; the name table lives in the running
game process (see research/token_table.py).
"""

from __future__ import annotations

from collections import namedtuple
from typing import Any, Callable, Optional
import struct

MAGIC = b"HOI4bin5*"

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

PRIMS = (I32, U32, F32, F64, U64, I64, BOOL, QUOTED, UNQUOTED)
PRIMSET = frozenset(PRIMS)

TOKEN_ANON = "anon"   # statement key marker for the leading anonymous entry

Obj = namedtuple("Obj", "items")   # brace body: list of items (see module doc)


class ParseError(Exception):
    def __init__(self, at: int, msg: str):
        self.at = at
        super().__init__(f"parse error @{at:#x}: {msg}")


class Reader:
    __slots__ = ("d", "p")

    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def u16(self) -> int:
        v = struct.unpack_from("<H", self.d, self.p)[0]
        self.p += 2
        return v

    def peek_u16(self) -> int:
        return struct.unpack_from("<H", self.d, self.p)[0]

    def lstr(self) -> str:
        ln = self.u16()
        raw = self.d[self.p:self.p + ln]
        self.p += ln
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")

    def prim(self, t: int) -> Any:
        """Read the payload of type token t. r.p must already be PAST the
        type token (caller consumes it, e.g. via u16())."""
        d, p = self.d, self.p
        if t == I32:
            self.p = p = p + 4
            return struct.unpack_from("<i", d, p - 4)[0]
        if t == U32:
            self.p = p = p + 4
            return struct.unpack_from("<I", d, p - 4)[0]
        if t == F32:
            self.p = p = p + 4
            return struct.unpack_from("<f", d, p - 4)[0]
        if t == F64:
            self.p = p = p + 8
            return struct.unpack_from("<d", d, p - 8)[0]
        if t == I64:
            self.p = p = p + 8
            return struct.unpack_from("<q", d, p - 8)[0]
        if t == U64:
            self.p = p = p + 8
            return struct.unpack_from("<Q", d, p - 8)[0]
        if t == BOOL:
            b = d[p]
            self.p = p + 1
            return b != 0
        if t in (QUOTED, UNQUOTED):
            return self.lstr()
        raise ValueError(f"not a primitive token: 0x{t:04X}")


def _value(r: Reader) -> Any:
    """One value slot: a single primitive, or an object body { body* }.

    bin5 assignments carry exactly one primitive value (multi-primitive
    vectors use braces), so the run-of-prims idea is dead: consuming prims
    greedily eats the next numeric-key statement's key."""
    t = r.peek_u16()
    if t == OPEN:
        r.u16()
        items: list = []
        while True:
            t2 = r.peek_u16()
            if t2 == CLOSE:
                r.u16()
                break
            if t2 in PRIMSET:
                r.u16()
                items.append(r.prim(t2))
            elif t2 == EQUAL:
                r.u16()
                items.append((TOKEN_ANON, _value(r)))
            else:  # id
                key = r.u16()
                if r.peek_u16() == EQUAL:
                    r.u16()
                    items.append((key, _value(r)))
                else:
                    items.append(key)  # bare id member
        return Obj(items)
    vals = []
    while True:
        if r.p + 2 > len(r.d):
            break    # prim at the window end: no next token to peek at
        t3 = r.peek_u16()
        if t3 in PRIMSET:
            r.u16()
            vals.append(r.prim(t3))
        else:
            break
    if not vals:
        token = r.u16()
        return ("id", token)
    return vals[0] if len(vals) == 1 else vals


def parse(data: bytes, limit: Optional[int] = None,
          on_pair: Optional[Callable] = None) -> list:
    """Parse into top-level [(id, value, byte_offset)]; id may be TOKEN_ANON,
    an int (registry key), or a scalar (number/string key).

    on_pair(key, value, offset) is called per statement for streaming stats.
    """
    pos = data.find(MAGIC)
    start = pos + len(MAGIC) if pos >= 0 else 0
    r = Reader(data, start)
    end = len(r.d) - 2 if limit is None else limit
    pairs: list = []
    while r.p < end:
        if data.find(MAGIC, r.p, r.p + len(MAGIC)) == r.p:
            r.p += len(MAGIC)
            continue
        off = r.p
        t = r.u16()
        if t == EQUAL:
            key = TOKEN_ANON
        else:
            key = t
            if r.peek_u16() != EQUAL:
                # bare key (no EQUAL): record and resync; the stream does not
                # align on one side, so leave payload bytes untouched
                pairs.append((key, None, off))
                continue
            r.u16()
        try:
            v = _value(r)
        except (ValueError, struct.error, UnicodeDecodeError) as exc:
            pairs.append((key, ("corrupt", f"{exc}"), off))
            break
        pairs.append((key, v, off))
        if on_pair is not None:
            on_pair(key, v, off)
    return pairs


def skip_value(r: Reader) -> None:
    t = r.u16()
    if t in (I32, U32, F32):
        r.p += 4
    elif t in (F64, U64, I64):
        r.p += 8
    elif t == BOOL:
        r.p += 1
    elif t in (QUOTED, UNQUOTED):
        ln = r.u16()
        r.p += ln
    elif t == OPEN:
        depth = 1
        while depth:
            t2 = r.u16()
            if t2 == OPEN:
                depth += 1
            elif t2 == CLOSE:
                depth -= 1
            elif t2 in (I32, U32, F32):
                r.p += 4
            elif t2 in (F64, U64, I64):
                r.p += 8
            elif t2 == BOOL:
                r.p += 1
            elif t2 in (QUOTED, UNQUOTED):
                ln = r.u16()
                r.p += ln
    # ids pass through


def visit(pairs: list, fn: Callable) -> None:
    """Depth-first over (key, value) forest.

    fn(key, value, depth, path) where path is the list of ancestor keys.
    Equivalent of Paradox .txt rendering: '{' bodies flatten naturally.
    """
    stack: list = []

    def rec(key, value, depth):
        if isinstance(value, Obj):
            for item in value.items:
                if isinstance(item, tuple):
                    k, v = item
                else:
                    k, v = None, item
                rec(k, v, depth + 1)
        elif isinstance(value, list):
            for v in value:
                rec(key, v, depth)
        else:
            fn(key, value, depth, stack)

    def walk(key, value, depth):
        stack.append(key)
        try:
            rec(key, value, depth)
        finally:
            stack.pop()

    for key, value, _off in pairs:
        walk(key, value, 0)


def collect_ids(pairs: list) -> dict[int, int]:
    """Count token-key occurrences: {id: count} ('anon' key included)."""
    stats: dict = {}

    def fn(key, value, depth, path):
        stats[key] = stats.get(key, 0) + 1

    visit(pairs, fn)
    return stats
