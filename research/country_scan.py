"""Optimized full-file pass: one linear walk producing the statement scaffold.

Countries with anchors within countries body; direct memo for world_state.

Runtime on GER_1936_02_25_08 (39 MB): < 1s with python bytearray loop.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "research"))

from bin5_lex3 import token_len  # noqa: E402
from hoi4_mcp.saveparse.tokens import load_tokens  # noqa: E402

NAMES = load_tokens()


def quick_country_index(path: str, want: set[str] | None = None):
    """Return [(tag, open_brace, close_brace)] for the countries section."""
    data = Path(path).read_bytes()
    N = len(data)
    start = data.find(b"HOI4bin5*") + 9

    # depth-tuned linear walk for 'countries' at depth 0
    p = start
    d = 0
    countries_pos = None
    while p < N:
        t = struct.unpack_from("<H", data, p)[0]
        if t == 0x2D49 and d == 0:
            if (struct.unpack_from("<H", data, p + 2)[0] == 1 and
                    struct.unpack_from("<H", data, p + 4)[0] == 3):
                countries_pos = p
                break
        if t == 3:
            d += 1
        elif t == 4:
            d -= 1
        p += token_len(data, p)

    if countries_pos is None:
        raise ValueError("countries statement not found at top level")

    CB0 = countries_pos + 4
    CB1 = None
    q = CB0 + 2
    dd = 1
    while q < N:
        t = struct.unpack_from("<H", data, q)[0]
        if t == 3:
            dd += 1
        elif t == 4:
            dd -= 1
            if dd == 0:
                CB1 = q
                break
        q += token_len(data, q)

    p = CB0 + 2
    d = 0
    anchors = []
    while p < CB1:
        t = struct.unpack_from("<H", data, p)[0]
        ln = token_len(data, p)
        if t == 3:
            d += 1
        elif t == 4:
            d -= 1
        elif t in (0xF, 0x17) and d == 0:
            ln2 = struct.unpack_from("<H", data, p + 2)[0]
            txt = data[p + 4:p + 4 + ln2].decode("utf-8", "replace")
            nxt = struct.unpack_from("<H", data, p + 4 + ln2)[0]
            nxt2 = struct.unpack_from("<H", data, p + 6 + ln2)[0]
            if nxt == 1 and nxt2 == 3:
                anchors.append([txt, p + 4 + ln2, None])
        p += ln
    for i, (tag, ap, _) in enumerate(anchors):
        dd = 1
        q = ap + 2
        while q < CB1:
            t = struct.unpack_from("<H", data, q)[0]
            if t == 3:
                dd += 1
            elif t == 4:
                dd -= 1
                if dd == 0:
                    anchors[i][2] = q
                    break
            q += token_len(data, q)
    if want is not None:
        anchors = [a for a in anchors if a[0] in want]
    return (countries_pos, CB0, CB1), anchors


def members_of(data: bytes, op: int, cl: int):
    """Country body top-level [depth-1 bearing] members: name->(v0 orNone end)."""
    p = op
    members = {}
    last_key = None
    while p < cl:
        t = struct.unpack_from("<H", data, p)[0]
        ln = token_len(data, p)
        if t == 3 and last_key is not None:
            dd = 1
            q = p + 2
            while q < cl:
                t4 = struct.unpack_from("<H", data, q)[0]
                if t4 == 3:
                    dd += 1
                elif t4 == 4:
                    dd -= 1
                    if dd == 0:
                        break
                q += token_len(data, q)
            keyname = NAMES.get(last_key, f"T_{last_key:04X}")
            members.setdefault(keyname, (p + 2, q))
            last_key = None
            p = q + 2
            continue
        if t == 4:
            p += ln
            continue
        if t == 1:
            p += ln
            continue
        if t in (0xF, 0x17):
            ln2 = struct.unpack_from("<H", data, p + 2)[0]
            nxt = struct.unpack_from("<H", data, p + 4 + ln2)[0]
            if nxt == 1:
                # string-key statement: its value starts at p+4+ln2+2
                txt = data[p + 4:p + 4 + ln2].decode("utf-8", "replace")
                members.setdefault(f'str:{txt}', (p + 4 + ln2 + 2, None))
            p += ln
            continue
        nxt = struct.unpack_from("<H", data, p + 2)[0]
        if nxt == 1:
            last_key = t
        p += ln
    return members


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_02_25_08.hoi4"))
    t0 = time.time()
    span, anchors = quick_country_index(path)
    print(f"walk {time.time()-t0:.2f}s  countries@{span[0]:#x}"
          f" body[{span[1]:#x},{span[2]:#x})")
    print(f"anchors {len(anchors)}; first:", [a[0] for a in anchors[:10]])
    t0 = time.time()
    g_next = [a for a in anchors if a[0] == "GER"][0]
    data = Path(path).read_bytes()
    mem = members_of(data, g_next[1] + 2, g_next[2])
    print(f"GER members {time.time()-t0:.2f}s count={len(mem)}")
    interesting = [k for k in mem if k in NAMES.values() or k.startswith("str:")]
    for k in interesting[:40]:
        print(f"   {k}")
