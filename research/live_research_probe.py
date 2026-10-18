"""live_research_probe.py — ask the GAME whether a candidate CTechnology* is a
valid SetResearch target (26 日). Read-only with respect to game state.

Background (research/NOTES.md 26 日): CSetResearchCommand's ctor takes a live
`CTechnology*` (r8), and CanExecute (its vtable +0x48 = 0x1166BC0) validates it
like this:

    manager = [country + 0xF60]                 ; CTechnologyStatus (vft 0x2974FA0)
    slot    = cmd[+0x38], 0 <= slot < manager[+0xAC]     ; research slot count
    tag     = cmd[+0x28] > 0
    0xED8F00(manager, tech, 0) == 1             ; the predicate, starts with
                                                ;   0xED5080(manager, tech)
    0xED5080(manager, tech) = manager[+0x88][tech[+0x38] - 1]   ; id at +0x38

So the missing piece for posting a research order is "which live object carries
the right id". This script delivers ONE VM payload that calls the game's own
accessors for a handful of candidate pointers and prints what the game answers.
Nothing is posted; the only game-thread work is these read-only calls.

Usage:
  python research/live_research_probe.py [--pid N] [--no-save]
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot import config, safety                                   # noqa: E402
from hoi4copilot.inject import script as S                               # noqa: E402
from hoi4copilot.inject import tables as T                               # noqa: E402
from hoi4copilot.inject.commands import CommandLayer                     # noqa: E402
from hoi4copilot.process.attach import Game, find_live_pids              # noqa: E402
from hoi4copilot.process.instances import scan_for_vftable_ptr           # noqa: E402

VFT_TECH = 0x2974EE0
PAGE = 0x1000
NAMES_AT = (0x28, 0x78, 0x18, 0x38, 0x50, 0x98, 0xb8, 0xd8)
FN_TECH_INSTANCE = 0xED5080          # (manager, tech) -> country instance | NULL
FN_CAN_RESEARCH = 0xED8F00           # (manager, tech, 0) -> bool
SAVE_DIR = config.DOCS_ROOT / "save games"
_SSRE = re.compile(rb"[A-Za-z][A-Za-z0-9_.\- ]*")


def name_at(m, buf: bytes, page_va: int, va: int) -> str | None:
    rel = va - page_va
    if not (0 <= rel <= PAGE - 0x20):
        return None
    blob = buf[rel:rel + 0x20]
    size = int.from_bytes(blob[0x10:0x18], "little")
    cap = int.from_bytes(blob[0x18:0x20], "little")
    if not 0 < size < 64:
        return None
    if cap <= 15 and size <= 15:
        s = blob[:size]
    elif 15 < cap < 0x1000:
        try:
            s = m.rpm(int.from_bytes(blob[0:8], "little"), size)
        except OSError:
            return None
    else:
        return None
    mt = _SSRE.fullmatch(s)
    return mt.group().decode() if mt else None


def named_objects(p, m) -> dict[str, int]:
    """{name: address} for CTechnology objects carrying a readable std::string."""
    hits = scan_for_vftable_ptr(p, [VFT_TECH]).get(VFT_TECH, [])
    per_page: dict[int, list[int]] = defaultdict(list)
    for a in hits:
        per_page[a & ~(PAGE - 1)].append(a)
    out: dict[str, int] = {}
    for page_va, addrs in per_page.items():
        try:
            buf = m.rpm(page_va, PAGE)
        except OSError:
            continue
        for a in addrs:
            rel = a - page_va
            if rel + 8 > PAGE or int.from_bytes(buf[rel:rel + 8], "little") - p.base != VFT_TECH:
                continue
            for off in NAMES_AT:
                nm = name_at(m, buf, page_va, a + off)
                if nm:
                    out.setdefault(nm, a)
                    break
    return out


def avail_techs() -> set[str]:
    """Techs the newest save says the player can research right now."""
    path = max(SAVE_DIR.glob("*.hoi4"), key=lambda q: q.stat().st_mtime, default=None)
    if path is None:
        return set()
    from hoi4copilot.readstate.country_sem import Countries, country_sections
    cn = Countries(path)
    tag = cn.player() or cn.tags()[0]
    f = country_sections(cn, tag, ["research"]).get(tag, {}).get("research", {})
    print(f"  save {path.name}: {len(f.get('avail') or [])} researchable techs")
    return {row["tech"] for row in (f.get("avail") or []) if row.get("tech")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--no-save", action="store_true",
                    help="skip the save-side avail list (saves ~20s)")
    a = ap.parse_args()

    live = find_live_pids()
    pid = a.pid or (live[0] if len(live) == 1 else None)
    if pid is None:
        print(f"REFUSING: need exactly one live hoi4.exe, found {live}")
        return 2
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda q: q.stat().st_mtime, default=None)
    rep = safety.guard(pid=pid, save_path=newest)
    print(f"guard: {rep.as_line()}")
    if rep.verdict == "multiplayer" and not config.ALLOW_MP:
        print("REFUSING: multiplayer evidence; the write layer is SP-only")
        return 3
    if config.READ_ONLY:
        print("REFUSING: HOI4_READ_ONLY=1")
        return 3

    game = Game(pid)
    p, m = game.proc, game.proc.memory
    base = p.base
    layer = CommandLayer(game)
    print(f"pid={pid} gamestate={layer.gamestate:#x} tag={layer.player_tag} "
          f"paused={layer.is_paused()} gate={layer.queue_gate_open()}")

    # --- the chain, straight from the game's own CanExecute -------------------
    tag = layer.player_tag
    countries = [int.from_bytes(m.rpm(m.u64(layer.gamestate + 0x310) + i * 8, 8), "little")
                 for i in range(512)]
    country = countries[tag]
    manager = m.u64(country + 0xF60)
    table = m.u64(manager + 0x88)
    count = m.u32(manager + 0x94)
    slots = m.u32(manager + 0xAC)
    print(f"country={country:#x} manager={manager:#x} "
          f"(vft={m.u64(manager) - base:#x}, want 0x2974FA0)\n"
          f"  tech table={table:#x} count={count} research_slots={slots}")

    elems = [int.from_bytes(m.rpm(table + i * 8, 8), "little") for i in range(count)]

    # --- candidates -----------------------------------------------------------
    cands: list[tuple[str, int]] = []
    if elems:
        cands.append(("array[0] (id field)", elems[0]))
    nonzero = [(i, e) for i, e in enumerate(elems) if 1 <= m.u32(e + 0x38) <= count]
    print(f"  array elements with an id in 1..{count}: {len(nonzero)}"
          + (f" e.g. {[(i, hex(e)) for i, e in nonzero[:4]]}" if nonzero else ""))
    for i, e in nonzero[:2]:
        cands.append((f"array[{i}] (id set)", e))

    print("scanning CTechnology instances for readable names ...")
    t0 = time.time()
    named = named_objects(p, m)
    print(f"  {len(named)} name-bearing objects in {time.time()-t0:.1f}s")
    avail: set[str] = set() if a.no_save else avail_techs()
    named_avail = [n for n in named if n in avail]
    print(f"  of those, names the save calls researchable NOW: {len(named_avail)} "
          f"-> {named_avail[:6]}")
    for nm in named_avail[:3]:
        cands.append((f"named {nm!r} (avail)", named[nm]))
    for nm in [n for n in named if n not in avail][:2]:
        cands.append((f"named {nm!r}", named[nm]))

    # --- one payload, one delivery -------------------------------------------
    print(f"\ndelivering ONE VM payload with {len(cands)} candidates "
          f"({len(cands) * 2} game calls) ...")
    print(f"shield: {layer.script.install_shield().get('installed')}")
    sc = S.Script(allow_calls={(base, base + p.image_size)})
    ops: list[tuple[int, int]] = []
    for label, cand in cands:
        i = sc.call(base + FN_TECH_INSTANCE, manager, cand)
        j = sc.call(base + FN_CAN_RESEARCH, manager, cand, 0)
        ops.append((i, j))
    t0 = time.time()
    r = layer.script.run(sc)
    dt = (time.time() - t0) * 1000
    print(f"  done={r.get('done')} status={r.get('status')} tid={r.get('tid')} "
          f"kind={r.get('kind')} latency={dt:.0f}ms intact={r.get('job_intact')} "
          f"fault_rip={r.get('fault_rip'):#x} dead={r.get('dead', False)}")

    print(f"\n{'candidate':34s} {'addr':>14s} {'id':>5s} {'instance':>14s} can_research")
    for (label, cand), (i, j) in zip(cands, ops):
        inst = r["results"][i] if r.get("results") else 0
        can = r["results"][j] if r.get("results") else 0
        try:
            tid = m.u32(cand + 0x38)
        except OSError:
            tid = -1
        print(f"{label:34s} {cand:#14x} {tid:5d} {inst:#14x} {bool(can)}")

    time.sleep(0.4)
    print(f"\npost-check: paused={layer.is_paused()} alive={p.is_alive()} "
          f"channel={layer.script.status()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
