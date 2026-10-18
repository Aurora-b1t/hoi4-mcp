"""One-off read-only probe v11: country+0xF60 -> technology manager -> tech array.

Chain (all decoded from the game's own code):

    CSetResearchCommand::CanExecute:
        rcx = &tag; call 0xbb48f0        ; -> some object
        call 0x6cfcb0                    ; = `mov rax,[rcx+0xF60]` -> tech manager
        rdi = manager
        slot  = cmd[+0x38]; must be <  [manager+0xAC]      (research slot count)
        tag   = cmd[+0x28]; must be > 0
        call 0xed8f00(manager, tech, 0)  ; CanResearch

    0xed5080(manager, tech):
        id = tech[+0x38] (1-based); bounds-check id-1 against [manager+0x94]
        return [manager+0x88][id-1]

So name -> object can go through the manager's own array: every element is the
country's tech instance, and its id is at +0x38.

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
from hoi4_mcp.readstate.techdata import TechDB                         # noqa: E402

NAMES_AT = (0x28, 0x78, 0x18, 0x50, 0x98, 0xb8, 0xd8, 0x38, 0x40, 0x48)


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
    known = set(TechDB().db().keys())
    g = Game(live[0])
    p, m = g.proc, g.proc.memory
    base = p.base
    gs = m.u64(base + T.G_GAMESTATE)
    tag = m.u32(gs + T.GS_PLAYER_TAG_OFF)
    arr = m.u64(gs + 0x310)
    countries = [int.from_bytes(m.rpm(arr + i * 8, 8), "little") for i in range(512)]
    me = countries[tag]
    mgr = m.u64(me + 0xF60)
    print(f"tag={tag} country={me:#x} vft={m.u64(me)-base:#x} tech_manager={mgr:#x}")
    if not mgr:
        print("manager pointer is NULL")
        return 1
    print(f"manager vft={m.u64(mgr)-base:#x}")
    head = m.rpm(mgr, 0xB0)
    table = int.from_bytes(head[0x88:0x90], "little")
    count = int.from_bytes(head[0x94:0x98], "little")
    slots = int.from_bytes(head[0xAC:0xB0], "little")
    print(f"table @ {table:#x} count={count} research_slots={slots}")

    raw = m.rpm(table, min(count, 2000) * 8)
    vfts: Counter = Counter()
    ids: list[int] = []
    named: list[tuple[int, int, str]] = []
    by_name: dict[str, int] = {}
    for i in range(0, len(raw), 8):
        a = int.from_bytes(raw[i:i + 8], "little")
        n = i // 8
        if not a:
            continue
        try:
            vft = m.u64(a) - base
            tid = m.u32(a + 0x38)
        except OSError:
            continue
        vfts[vft] += 1
        ids.append(tid)
        nm = name_of(m, a)
        if nm:
            by_name.setdefault(nm, a)
            if len(named) < 20:
                named.append((n, tid, nm))
    print("element vftables:", {hex(k): v for k, v in vfts.most_common(5)})
    print(f"ids: n={len(ids)} min={min(ids) if ids else None} max={max(ids) if ids else None} "
          f"unique={len(set(ids))}")
    print(f"elements with a readable name: {len(by_name)}")
    print("sample (index, id, name):", named)
    print(f"names that are known tech names: {len([k for k in by_name if k in known])}")
    for probe in ("infantry_weapons", "light_armor", "artillery_brigade", "field_guns"):
        if probe in by_name:
            print(f"  {probe:20s} id={m.u32(by_name[probe]+0x38)} @ {by_name[probe]:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
