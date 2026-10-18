"""One-off read-only probe v10: the country's own tech array.

0xed5080 (called by CSetResearchCommand::CanExecute as f(country, tech)) is:

    movsxd r8, dword ptr [rdx + 0x38]   ; id = tech->[+0x38]  (1-based)
    lea    eax, [r8 - 1]
    cmp    eax, dword ptr [rcx + 0x94]  ; country->count
    jge    -> NULL
    mov    rax, qword ptr [rcx + 0x88]  ; country->array
    mov    rax, qword ptr [rax + r8*8 - 8]
    ret

So the object the command wants is an element of [CCountry+0x88], indexed by its
own id at +0x38. Dump that array for the player country and identify what the
elements really are (vftable RVA, id field, name).

Read-only.
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.inject import tables as T                                # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402

NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98, 0xb8, 0xd8)


def name_of(m, a: int) -> str | None:
    for off in NAMES_AT:
        try:
            blob = m.rpm(a + off, 0x20)
        except OSError:
            continue
        size = int.from_bytes(blob[0x10:0x18], "little")
        cap = int.from_bytes(blob[0x18:0x20], "little")
        if not 0 < size < 64:
            continue
        if cap <= 15 and size <= 15:
            s = blob[:size]
        elif 15 < cap < 0x1000:
            try:
                s = m.rpm(int.from_bytes(blob[0:8], "little"), size)
            except OSError:
                continue
        else:
            continue
        if re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.\- ]*", s):
            return s.decode()
    return None


def main() -> int:
    live = find_live_pids()
    if len(live) != 1:
        return 2
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base = p.base
    gs = m.u64(base + T.G_GAMESTATE)
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    arr = m.u64(gs + 0x310)
    countries = [int.from_bytes(m.rpm(arr + i * 8, 8), "little") for i in range(512)]
    me = countries[tag]
    print(f"player tag={tag} country={me:#x}")

    head = m.rpm(me, 0x100)
    for off in (0x88, 0x90, 0x94, 0x98, 0x9c):
        print(f"  country+{off:#04x}: {int.from_bytes(head[off:off+8],'little'):#x}")
    table = int.from_bytes(head[0x88:0x90], "little")
    count = int.from_bytes(head[0x94:0x98], "little")
    print(f"tech table @ {table:#x} count={count}")

    raw = m.rpm(table, min(count, 1200) * 8)
    vfts: Counter = Counter()
    ids: list[int] = []
    named: list[tuple[int, int, str]] = []
    for i in range(0, len(raw), 8):
        a = int.from_bytes(raw[i:i + 8], "little")
        n = i // 8
        if not a:
            continue
        try:
            vft = m.u64(a) - base
            obj = m.rpm(a, 0x40)
        except OSError:
            continue
        vfts[vft] += 1
        tid = int.from_bytes(obj[0x38:0x3c], "little")
        ids.append(tid)
        nm = name_of(m, a)
        if nm and len(named) < 25:
            named.append((n, tid, nm))
    print("element vftable RVAs:", {hex(k): v for k, v in vfts.most_common(6)})
    print(f"ids read: {len(ids)} min={min(ids) if ids else None} max={max(ids) if ids else None}")
    print("first 20 ids:", ids[:20])
    print("named elements (index, id, name):", named)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
