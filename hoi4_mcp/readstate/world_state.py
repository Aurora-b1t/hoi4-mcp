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

try:
    from ..saveparse.tokens import load_tokens
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from hoi4_mcp.saveparse.tokens import load_tokens

from .bin5_scaffold import walkthrough, find_countries, find_matching, country_anchors

NAMES = load_tokens()
BY_NAME = {v: k for k, v in NAMES.items()}


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
        # not an IEEE double: 2B token + 8B int64 fixed point, scale 1e6
        # (calibrated: fuel slope = oil*2.2/day across GER saves)
        raw = struct.unpack_from("<q", data, int(pos) + 2)[0]
        return raw / 1e6
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
                    i = cl + 1      # body consumed up to its close; NO +3 here
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
            nm = NAMES.get(t, f"T_{t:04X}")   # resolved through tok registry
            vt = int(kind[i + 2])
            if vt == 0x0003:
                cl = find_matching(kind, i + 2)
                mem[nm] = ("body", i + 2, cl)
                i = cl + 1        # body consumed up to its close; NO +3 here
            else:
                mem[nm] = ("prim", scalar_value(kind[i + 2], data, pos[i + 2]), i + 2)
                i += 3
            continue
        i += 1
    return mem


def world_summary(save_path) -> dict:
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
    # header scalars from the token-walk (fast; equivalent of saveinfo for now)
    from ..saveparse.saveinfo import decode_date
    hdr = header_stmts(data, pos, kind, depth, span)
    for k, v in hdr.get("scalars", {}).items():
        if k == "date":
            try:
                summary["date"] = decode_date(v)
                summary["date_token"] = v
            except Exception:
                summary["date"] = v
        else:
            summary[k] = v
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


def header_stmts(data: bytes, pos, kind, depth, span) -> dict:
    """Top-level statements until the first big body: scalars + header dict."""
    scalars: dict = {}
    i = 0
    n = len(kind)
    open_bodies = 0
    anon_count = 0
    while i < n and open_bodies < 4:
        t = int(kind[i])
        d = int(depth[i])
        if t == 0x0003:
            open_bodies += 1
            if d == 0:
                # inline a body's header-level resolution
                cl = find_matching(kind, i)
                i = cl + 1 if cl is not None else i + 1
                continue
            i += 1
            continue
        if d != 0:
            i += 1
            continue
        if t == 0x0004:
            i += 1
            continue
        if t == 0x0001:
            # anon statement: the first one is the player country tag (header)
            # (e.g. anon = 'GER'); the remaining ones at top-level are rare
            if int(kind[i + 1]) in (0x000F, 0x0017):
                p_tok = int(pos[i + 1])
                ln = data[p_tok + 2] | (data[p_tok + 3] << 8)
                val = data[p_tok + 4:p_tok + 4 + ln].decode("utf-8", "replace")
                if anon_count == 0 and 2 <= len(val) <= 6:
                    scalars["player"] = val
                anon_count += 1
                i += 2
                continue
            v = scalar_value(kind[i + 1], data, pos[i + 1])
            scalars[f"<anon{anon_count}>"] = v
            anon_count += 1
            i += 2
            continue
        if t in (0x000F, 0x0017):
            p_tok = int(pos[i])
            ln = data[p_tok + 2] | (data[p_tok + 3] << 8)
            txt = data[p_tok + 4:p_tok + 4 + ln].decode("utf-8", "replace")
            if int(kind[i + 1]) == 0x0001:
                v = scalar_value(kind[i + 2], data, pos[i + 2])
                scalars[txt] = v
                i += 3
                continue
            i += 1
            continue
        nm = NAMES.get(t, f"T_{t:04X}")
        if int(kind[i + 1]) == 0x0001:
            scalars[nm] = scalar_value(kind[i + 2], data, pos[i + 2])
            i += 3
            continue
        i += 1
    return {"scalars": scalars}


def country_detail(data, pos, kind, depth, span, open_idx, close_idx, tag: str) -> dict:
    """Per-country summary fields: PP / stability / war_support / research
    slots / capital / focus_tree name; pulled straight from the country's
    direct-top members (in the fixed-point scale registry)."""
    d0 = int(depth[open_idx])
    members = statement_member_scan(data, pos, kind, depth, span,
                                    open_idx + 1, close_idx, d0)
    out: dict = {"tag": tag}

    def sval(name, default=None):
        val = members.get(name, None)
        if val and val[0] == "prim":
            return val[1]
        return default

    def body_scan(name):
        val = members.get(name)
        if val and val[0] == "body":
            sub = statement_member_scan(data, pos, kind, depth, span,
                                        val[1] + 1, val[2], d0 + 1)
            return sub
        return {}

    pol = body_scan("politics")
    own_pp = pol.get("political_power")
    out["political_power"] = own_pp[1] if (own_pp and own_pp[0] == "prim") else None
    for k in ("stability", "war_support", "command_power", "research_slot",
              "original_research_slots", "capital", "original_capital",
              "num_ships", "major", "focus_tree", "preferred_tactic",
              "accidents_score", "is_top_ic_country"):
        out[k] = sval(k)
    out["n_members"] = len(members)
    return out


def top_lines(save_path=None, data=None, scaffold=None) -> str:
    """Compact agent-facing report from a save: player, date, top countries
    with their key numbers + resources."""
    import time as _t
    t0 = _t.time()
    if data is None:
        data = Path(save_path).read_bytes()
    start = data.find(b"HOI4bin5*") + 9
    if scaffold is None:
        pos, kind, depth, span = walkthrough(data, start)
    else:
        pos, kind, depth, span = scaffold
    key_p, open_p, close_p, inner_open_i, inner_close_i = find_countries(
        data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, inner_open_i, inner_close_i)
    hdr = header_stmts(data, pos, kind, depth, span).get("scalars", {})
    player_tag = hdr.get("player", "?")
    try:
        from ..saveparse.saveinfo import decode_date
        date_s = decode_date(hdr["date"]) if isinstance(hdr.get("date"), int) else str(hdr.get("date"))
    except Exception:
        date_s = str(hdr.get("date"))

    lines = [f"save-size={len(data) / 1e6:.1f}MB",
             f"player={player_tag}",
             f"date={date_s}",
             f"difficulty={hdr.get('difficulty')}",
             f"version={hdr.get('version')}"]
    details = []
    for (tag, key_idx, open_idx, close_idx) in anchors:
        if close_idx is None:
            continue
        c = country_detail(data, pos, kind, depth, span, open_idx, close_idx, tag)
        details.append(c)
    details.sort(key=lambda c: (0 if c.get("major") else 1,
                                -(c.get("political_power") or 0)))
    for c in details[:40]:
        lines.append(
            f"  {c['tag']:5s} PP={c['political_power']} stab={c['stability']} "
            f"wsup={c['war_support']} slots={c['research_slot']} "
            f"tree={c['focus_tree']}")
    lines.append(f"({len(anchors)} countries scanned, done in "
                 f"{_t.time() - t0:.1f}s)")
    return "\n".join(lines)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_02_25_08.hoi4"))
    ws = world_summary(path)
    print(f"save {ws['path']} {ws['size']/1e6:.1f}MB")
    for c in ws["countries"][:60]:
        nm = []
        for key, val in c["members"].items():
            nm.append(key if val[0] == "body" else f"{key}={val[1]}")
        print(f"  {c['tag']:5s} {c['size']:>10,}b: {', '.join(nm[:8])}...")
