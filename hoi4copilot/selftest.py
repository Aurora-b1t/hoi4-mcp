"""CLI self-tests: `attach` verifies process layer; `rtti-probe` checks for MSVC RTTI in the exe."""

from __future__ import annotations

import argparse
import logging
import os
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("selftest")

from . import config  # noqa: E402


def cmd_attach(_args) -> int:
    from .process.attach import Game

    g = Game()
    p = g.proc
    ver_ok = g.check_version()
    print(p)
    print(f"version match with pinned tables: {ver_ok}")
    # smoke: read the PE header at module base
    mz = p.memory.rpm(p.base, 2)
    print(f"MZ header present: {mz[:2] == b'MZ'}")
    return 0 if (ver_ok and mz[:2] == b"MZ") else 1


def cmd_rtti_probe(_args) -> int:
    """Scan hoi4.exe on disk for MSVC RTTI type descriptors (".?AV...").

    This is the Phase 1 go/no-go gate: if the Windows build ships without RTTI
    we must fall back to string/vtable-guided discovery.
    """
    from . import config
    exe = config.find_install_dir() / config.EXE_NAME
    data = exe.read_bytes()
    idx = 0
    classes: list[str] = []
    while True:
        idx = data.find(b".?A", idx)
        if idx < 0:
            break
        end = data.find(b"\x00", idx, idx + 300)
        if end > 0:
            name = data[idx:end]
            if all(32 <= b < 127 for b in name):
                classes.append(name.decode())
        idx += 1
    print(f"examined {len(data)/1e6:.1f} MB exe -> {len(classes)} candidate type descriptors")
    prefixes = {}
    for name in classes:
        key = name[:40]
        prefixes[key] = prefixes.get(key, 0) + 1
    interesting = [k for k in prefixes if any(s in k for s in
                   (".?AVCCommandQueue", ".?AVCGame", ".?AVCPlayer", ".?AVCHoi", ".?AVCObject",
                    ".?AVPlayer", ".?AVCCountry", ".?AVCFront", ".?AVCArmy", ".?AVCDecision",
                    ".?AVCFocus", ".?AVCLaw", ".?AVCTech"))]
    print("\n".join(f"{n:5d}  {c}" for c, n in sorted(prefixes.items(), key=lambda kv: -kv[1])[:60]))
    print("interesting:")
    for c in interesting:
        print("  ", c, "->", [n for n in classes if n[:40] == c][:6])
    return 0


def cmd_rtti_scan(_args) -> int:
    """Full MSVC RTTI pass -> tables/generated/rtti.json + summary of key classes."""
    from . import config
    from .rtti.msvc import scan_exe

    exe = config.find_install_dir() / config.EXE_NAME
    db = scan_exe(exe)
    out = config.TABLES_DIR / "rtti.json"
    db.dump(out)
    print(f"classes: {len(db.by_name)}  -> {out}")
    for pat in (r"CommandQueue", r"Command$", r"Queue", r"^\.\?AVCGame", r"^\.\?AVCCountry@@",
                r"^\.\?AVCArmy", r"^\.\?AVCFront", r"^\.\?AVCDecision", r"^\.\?AVCTechnology@@",
                r"CGameState", r"CPlayer", r"^\.\?AVCFormationBoss", r"HANDLE|CHandle"):
        hits = db.search(pat)
        print(f"\n[{pat}] {len(hits)}")
        for info in hits[:25]:
            vt = [hex(v) for v in info.vftable_rvas[:4]]
            print(f"  rva td={info.td_rva:#x} vt={vt} {info.name}")
    return 0


def cmd_classes(_args) -> int:
    """Print vftables for curated key classes from the RTTI database."""
    from .rtti import catalog as cat
    from .rtti.msvc import RttiDatabase

    db = RttiDatabase.load(config.TABLES_DIR / "rtti.json")
    found = {}
    for key, patterns in cat.KEY_CLASSES.items():
        hits = []
        for pat in patterns:
            for info in db.search(pat):
                hits.append(info)
        hits = sorted({h.name: h for h in hits}.values(), key=lambda i: i.name)
        for info in hits:
            for vt in info.vftable_rvas:
                found.setdefault(key, []).append((info.name, vt))
    for key in sorted(found):
        for name, vt in found[key]:
            print(f"{key:16s} vt=0x{vt:X}  {name}")
    print(f"\ntotal classes with vtables in curated set: {sum(len(v) for v in found.values())}")
    return 0


def cmd_instances(_args) -> int:
    """Attach to a running game and count live instances of key classes."""
    from .process.attach import Game
    from .process import instances

    from .rtti.msvc import RttiDatabase

    db = RttiDatabase.load(config.TABLES_DIR / "rtti.json")
    patterns = {
        "game_state": [r"^\.\?AVCGameState@@"],
        "country": [r"^\.\?AVCCountry@@"],
        "state": [r"^\.\?AVCState@@"],
        "province": [r"^\.\?AVCProvince@@"],
        "army": [r"^\.\?AVCArmy@@"],
        "army_group": [r"^\.\?AVCArmyGroup@@"],
        "front": [r"^\.\?AVCFront@@"],
        "focus_tree": [r"^\.\?AVCNationalFocusTree@@"],
        "focus_progress": [r"^\.\?AVCNationalFocusProgress@@"],
        "idea": [r"^\.\?AVCIdea@@"],
        "production_line": [r"^\.\?AVCProductionLine@@"],
        "war": [r"^\.\?AVCWar@@"],
        "faction": [r"^\.\?AVCFaction@@"],
        "player": [r"^\.\?AVCPlayer@@"],
        "air_wing": [r"^\.\?AVCAirWing@@"],
        "ship": [r"^\.\?AVCShip@@"],
        "unit_leader": [r"^\.\?AVCArmyLeader@@"],
    }
    rvas = {}
    for key, pats in patterns.items():
        rvas[key] = []
        for pat in pats:
            rvas[key] += [v for info in db.search(pat) for v in info.vftable_rvas]
    g = Game()
    print(g.proc)
    counts = instances.count_watch(g.proc, rvas)
    for key in sorted(counts):
        print(f"{key:16s} {counts[key]}")
    return 0


def cmd_token_scan(_args) -> int:
    """Extract the save-key token registry from the running game image and
    write tables/generated/tokens.json. Needs hoi4.exe running (the table
    lives in a runtime-committed hole of the image, not on disk)."""
    from .saveparse.tokens import build_tokens_file
    tb = build_tokens_file()
    print(f"tokens: {len(tb)}")
    for k in (27, 0xEE, 0x289A, 0x299F):
        print(f"  {k:#06x} = {tb.get(k, '?')}")
    return 0


def cmd_save_info(args) -> int:
    """Decode save header(s): player/ideology/difficulty/date. Offline."""
    from pathlib import Path
    from .saveparse.saveinfo import read_header
    rc = 0
    for p in args.paths:
        try:
            h = read_header(Path(p), limit=16384)
            print(h.summary())
        except Exception as exc:
            print(f"{p}: {exc}")
            rc = 1
    return rc


def cmd_country_detail(args) -> int:
    """Per-country semantic detail from a save, offline: pol/research/prod/
    construction/res/units/diplo/decisions/focus/fuel/mp/chars."""
    from pathlib import Path
    from .readstate.country_sem import (
        Countries, country_sections, format_sections)
    rc = 0
    try:
        cn = Countries(Path(args.path))
        tags = list(args.tags) if args.tags else []
        if not tags:
            tags = [cn.player()] if cn.player() else cn.tags()[:1]
        for tag in tags:
            sec = country_sections(cn, tag, None)
            print(format_sections(tag, sec.get(tag, {})))
    except Exception as exc:
        print(f"{args.path}: {exc}")
        rc = 1
    return rc


def cmd_guard(_args) -> int:
    """Print the session-safety guard bundle (game.log marker / TCP sockets /
    newest-save multiplayer token). Offline + live, no writes."""
    from . import safety
    from .process.attach import Game
    pid = None
    try:
        pid = Game().proc.pid
    except Exception:
        pass
    rep = safety.guard(pid=pid, save_path=_newest_save())
    print(rep.as_line())
    for r in rep.reasons:
        print(f"  reason: {r}")
    return 0 if rep.verdict in ("singleplayer", "unknown") else 1


def _newest_save() -> str | None:
    sg = config.DOCS_ROOT / "save games"
    try:
        cands = sorted(sg.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime)
        return str(cands[0]) if cands else None
    except Exception:
        return None


def cmd_replay_check(args) -> int:
    """Validate a recording file and print the replay schedule (no clicks)."""
    import json as _json
    from pathlib import Path
    p = Path(args.path)
    steps = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            s = _json.loads(line)
            if "meta" not in s:
                steps.append(s)
    total_wait = sum(min(30.0, s.get("dt", 0) / 1000.0) for s in steps)
    print(f"{p.name}: {len(steps)} steps, scheduled wait {total_wait:.1f}s @speed1")
    for i, s in enumerate(steps):
        kind = s.get("kind")
        extra = ""
        if kind == "click":
            extra = f"= click ({s.get('x')},{s.get('y')}) hold={s.get('hold')}"
        elif kind == "right_click":
            extra = f"= right ({s.get('x')},{s.get('y')})"
        elif kind == "wheel":
            extra = f"= wheel {s.get('delta')}"
        elif kind == "key":
            extra = f"= key vk={s.get('vk')}"
        elif kind == "note":
            extra = f"= note {s.get('note')!r}"
        print(f"  [{i:02d}] dt={s.get('dt', 0):>6d}ms {kind}{extra}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="hoi4-selftest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("attach").set_defaults(func=cmd_attach)
    sub.add_parser("rtti-probe").set_defaults(func=cmd_rtti_probe)
    sub.add_parser("rtti-scan").set_defaults(func=cmd_rtti_scan)
    sub.add_parser("classes").set_defaults(func=cmd_classes)
    sub.add_parser("instances").set_defaults(func=cmd_instances)
    sub.add_parser("token-scan").set_defaults(func=cmd_token_scan)
    ssi = sub.add_parser("save-info")
    ssi.add_argument("paths", nargs="+")
    ssi.set_defaults(func=cmd_save_info)
    scd = sub.add_parser("country-detail")
    scd.add_argument("path")
    scd.add_argument("tags", nargs="*")
    scd.set_defaults(func=cmd_country_detail)
    sub.add_parser("guard").set_defaults(func=cmd_guard)
    rck = sub.add_parser("replay-check")
    rck.add_argument("path")
    rck.set_defaults(func=cmd_replay_check)
    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except Exception:
        log.exception("selftest failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
