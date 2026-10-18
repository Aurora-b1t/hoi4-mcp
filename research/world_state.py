"""HOI4 save-driven World State reader (v1).

Read the FULL game state out of a .hoi4 save, purely offline:
  countries -> per-country: PP / stability / war_support / research slots
  production / resources / focus_tree / characters ...

Built on the verified v3 bin5 grammar (bin5_lex3):
  strings carry NO terminator (4 + ln bytes); F32 = 10B fixed-point (i64/2^24 in
  some fields; 1e5 in others — PASS the scale through the field registry).

Key abstractions:
  Scaffolding: walkthrough() -> pos/kind/depth/span numpy arrays (1 walk).
  country index country_index() -> [(tag, open_idx, close_idx)] inside the
  top-level countries body.

Field extraction: scalar values in fixed-point distributions; the scale
table:
    SCALE_1E5  = raw / 100000.0   (fraction values: stability, PP...)
    SCALE_2P24 = raw / 2**24      (party popularity fractions)
"""

from __future__ import annotations

import sys
import struct
from pathlib import Path

import numpy as np

sys.path.insert(0, r"D:/hoi4-copilot")
sys.path.insert(0, r"D:/hoi4-copilot/research")

try:
    from .saveparse.tokens import load_tokens
    from .saveparse.saveinfo import decode_date, DATE_EPOCH
except ImportError:
    from research.bin5_scaffold import walkthrough, find_countries, find_matching  # noqa
    from research.country_scan import quick_country_index  # noqa
    from hoi4copilot.saveparse.tokens import load_tokens
    from hoi4copilot.saveparse.saveinfo import decode_date, DATE_EPOCH

from research.bin5_scaffold import walkthrough, find_countries, find_matching, country_anchors  # noqa


# scale for raw fixed point values in per-field semantic map
SCALE_1E5 = 100000.0
SCALE_2P24 = float(2 ** 24)


def scalar_value(kind, data, pos, scale=SCALE_1E5):
    """Interpret the VALUE token at index i: (kind, data, pos) tuple.
    Returns a python number; supports the primitive payload tokens."""
    t = int(kind)
    if t == 0x000C:
        return struct.unpack_from("<i", data, int(pos) + 2)[0]
    if t == 0x0014:
        return struct.unpack_from("<I", data, int(pos) + 2)[0]
    if t == 0x000D:
        # HOI4 1.19 fixed point: 8-byte signed i64 in most cases; the save
        # scales are empirical and field-dependent
        raw = struct.unpack_from("<Q", data, int(pos) + 2)[0]
        if raw >= 2 ** 63:
            raw -= 2 ** 64
        return raw / scale
    if t == 0x0167:
        return struct.unpack_from("<d", data, int(pos) + 2)[0]
    if t == 0x029C:
        return struct.unpack_from("<Q", data, int(pos) + 2)[0]
    if t == 0x0317:
        return struct.unpack_from("<q", data, int(pos) + 2)[0]
    if t == 0x000E:
        return data[int(pos) + 2] != 0
    if t in (0x000F, 0x0017):
        ln = struct.unpack_from("<H", data, int(pos) + 2)[0]
        return data[int(pos) + 4:int(pos) + 4 + ln].decode("utf-8", "replace")
    return None


def statement_member_scan(data, pos, kind, depth, span, i0, i1, depth_at_open):
    """Scan members in [i0, i1) into dict: name -> value.
    name: STR name for string-keyed stmts, or token id for id-keyed. Bare
    entries (no '=') are ignored. Value: scalar OR a body span with a 'body'
    marker (returns (depth_close_idx, ) for lazy readouts)."""
    mem = {}
    i = i0
    d_target = depth_at_open + 1
    while i < i1:
        d = int(depth[i])
        if d > d_target:
            i += 1
            continue
        i0_member = i
        t = int(kind[i])
        if d != d_target:
            i += 1
            continue
        if t == 0x0004:
            break
        if t in (0x000F, 0x0017):
            # string key
            p = int(pos[i])
            ln = data[p + 2] | (data[p + 3] << 8)
            txt = data[p + 4:p + 4 + ln].decode("utf-8", "replace")
            if int(kind[i + 1]) == 0x0001:
                vt = int(kind[i + 2])
                if vt == 0x0003:
                    cl = find_matching(kind, i + 2)
                    mem[txt] = ("body", i + 2, cl)
                    i = cl + 1
                else:
                    mem[txt] = ("prim", scalar_value(kind[i + 2], data, pos[i + 2]), i + 2)
                i += 3
                continue
            i += 1
            continue
        if t == 0x0001:   # anon statement
            vt = int(kind[i + 1])
            if vt == 0x0003:
                cl = find_matching(kind, i + 1)
                mem["<anon>"] = ("body", i + 1, cl)
                i = cl + 1
            else:
                mem["<anon>"] = ("prim", scalar_value(kind[i + 1], data, pos[i + 1]), i + 1)
                i += 2
            continue
        # id-key member
        if int(kind[i + 1]) == 0x0001:
            nm_key = t
            nm = f"T_{t:04X}"  # placeholder; consumers pass name map when needed
            vt = int(kind[i + 2])
            if vt == 0x0003:
                cl = find_matching(kind, i + 2)
                mem[nm] = ("body", i + 2, cl)
                i = cl + 1
            else:
                mem[nm] = ("prim", scalar_value(kind[i + 2], data, pos[i + 2]), i + 2)
            i += 3
            continue
        i += 1
    return mem


def world_summary(save_path):
    """Compute the summary structure from a .hoi4 save file."""
    p = Path(save_path)
    data = p.read_bytes()
    start = data.find(b"HOI4bin5*") + 9
    pos, kind, depth, span = walkthrough(data, start)
    key_p, open_p, close_p, inner_open_i, inner_close_i = find_countries(
        data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, inner_open_i, inner_close_i)
    summary = {
        "path": str(p),
        "size": len(data),
        "countries": [],
    }
    for (tag, key_idx, open_idx, close_idx) in anchors:
        if close_idx is None:
            continue
        d0 = int(depth[open_idx])
        members = statement_member_scan(data, pos, kind, depth, span,
                                        open_idx + 1, close_idx, d0)
        cinfo = {
            "tag": tag,
            "open": int(pos[open_idx]),
            "size": int(pos[close_idx]) - int(pos[open_idx]),
            "members": members,
        }
        summary["countries"].append(cinfo)
    return summary


if __name__ == "__main__":
    import json
    path = sys.argv[1] if len(sys.argv) > 1 else (
        r"C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/"
        r"save games/GER_1936_02_25_08.hoi4")
    ws = world_summary(path)
    print(f"save {ws['path']} {ws['size']/1e6:.1f}MB")
    for c in ws["countries"][:60]:
        nm = []
        for key, val in c["members"].items():
            nm.append(key if val[0] == "body" else f"{key}={val[1]}")
        print(f"  {c['tag']:5s} {c['size']:>10,}b: {', '.join(nm[:8])}...")
