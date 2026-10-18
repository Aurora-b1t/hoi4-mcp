"""Minimal PNG reader for the 24-bit RGB files written by screenshot.save_png."""

import struct
import zlib

import numpy as np


def read_png(path) -> np.ndarray:
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, w, h, idat = 8, None, None, b""
    while pos < len(data):
        ln = struct.unpack_from(">I", data, pos)[0]
        tag = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if tag == b"IHDR":
            w, h = struct.unpack_from(">II", chunk, 0)[:2]
        elif tag == b"IDAT":
            idat += chunk
        pos += 12 + ln
    raw = zlib.decompress(idat)
    stride = w * 3
    out = np.zeros((h, w, 3), dtype=np.uint8)
    prev = None
    p0 = 0
    for y in range(h):
        f = raw[p0]
        un = np.frombuffer(raw[p0 + 1:p0 + 1 + stride], dtype=np.uint8).astype(np.int32).copy()
        p0 += 1 + stride
        if f == 2 and prev is not None:
            un = (un + prev) & 0xFF
        elif f in (1, 3, 4):
            prev0 = prev if prev is not None else np.zeros(stride, dtype=np.int32)
            for x in range(stride):
                a = un[x - 3] if x >= 3 else 0
                b = int(prev0[x])
                c = int(prev0[x - 3]) if x >= 3 else 0
                if f == 1:
                    un[x] = (un[x] + a) & 0xFF
                elif f == 3:
                    un[x] = (un[x] + (a + b) // 2) & 0xFF
                else:
                    pp = a + b - c
                    pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                    pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    un[x] = (un[x] + pr) & 0xFF
        prev = un
        out[y] = un.reshape(w, 3).astype(np.uint8)
    return out
