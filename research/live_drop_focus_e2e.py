"""live_drop_focus_e2e.py — DropCurrentNationalFocusCommand through the ctor-faithful
APC channel (25 日).

The spec (tables.py, verified by specverify):
    ctor(this, rdx=&tag):  mov eax,[rdx]; mov [rcx+0x28],eax      (size 0x30)
so the command is built by the GAME's own constructor from ONE argument: a
pointer to the int32 player tag (the UI passes gamestate+0x520).

Sequence:
  1. guard + attach, print the player tag / queue gate / paused bit,
  2. read the current focus state out of the newest save (ground truth before),
  3. `post` through one special user APC: new -> ctor(&tag) -> Post(queue, cmd),
  4. report posted / job_intact / latency,
  5. optionally write a fresh save (--save) and re-parse it.

Usage:
  python research/live_drop_focus_e2e.py            # post + report
  python research/live_drop_focus_e2e.py --save     # also save and re-parse
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp import config, safety                                   # noqa: E402
from hoi4_mcp.inject import tables as T                               # noqa: E402
from hoi4_mcp.inject.commands import CommandLayer                     # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids              # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"


def focus_state_from_latest() -> dict:
    """The newest save, and — when the newest is a temp-rename pair — also the
    file the game actually settled on (it writes `<name>_temp.hoi4` first)."""
    path = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    if path is None:
        return {}
    from hoi4_mcp.readstate.country_sem import Countries, country_sections
    cn = Countries(path)
    tag = cn.player() or cn.tags()[0]
    sec = country_sections(cn, tag, ["focus"]).get(tag, {})
    f = sec.get("focus", {})
    return {"save": path.name, "tag": tag, "current": f.get("current"),
            "remaining_days": f.get("remaining_days"),
            "progress": f.get("progress"), "n_completed": f.get("n_completed")}


def focus_state_in(name: str) -> dict:
    path = SAVE_DIR / name
    if not path.exists():
        return {"save": name, "error": "missing"}
    from hoi4_mcp.readstate.country_sem import Countries, country_sections
    cn = Countries(path)
    tag = cn.player() or cn.tags()[0]
    f = country_sections(cn, tag, ["focus"]).get(tag, {}).get("focus", {})
    return {"save": name, "tag": tag, "current": f.get("current"),
            "remaining_days": f.get("remaining_days"),
            "progress": f.get("progress"), "n_completed": f.get("n_completed")}


def save_via_ui() -> str:
    from hoi4_mcp.ui.session import SessionDriver
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    if newest is not None:
        backup = SAVE_DIR / f"_backup_{newest.stem}_pre_drop.hoi4"
        if not backup.exists():
            import shutil
            shutil.copy2(newest, backup)
            print(f"  (backed up {newest.name} -> {backup.name})")
    d = SessionDriver(Game())
    before = {p.name: p.stat().st_mtime for p in SAVE_DIR.glob("*.hoi4")}
    d.open_menu()
    time.sleep(0.5)
    d.input.click(0.502, 0.30)           # 保存游戏 (same row mcp_server.hoi4_save uses)
    time.sleep(1.5)
    d.input.click(0.560, 0.813)          # 保存 (prefilled GER_<date> filename)
    confirmed = False
    for i in range(30):
        time.sleep(2.0)
        after = {p.name: p.stat().st_mtime for p in SAVE_DIR.glob("*.hoi4")}
        new = [k for k, v in after.items() if before.get(k) != v]
        if new:
            time.sleep(3.0)
            return new[0]
        if not confirmed and i >= 2:
            d.input.click(0.569, 0.666)  # 覆盖确认 OK
            confirmed = True
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save", action="store_true")
    ap.add_argument("--pid", type=int, default=None)
    a = ap.parse_args()

    live = find_live_pids()
    pid = a.pid or (live[0] if len(live) == 1 else None)
    if pid is None:
        print(f"REFUSING: need exactly one live hoi4.exe, found {live}")
        return 2
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    rep = safety.guard(pid=pid, save_path=newest)
    print(f"guard: {rep.as_line()}")
    if rep.verdict == "multiplayer" and not config.ALLOW_MP:
        print("REFUSING: multiplayer evidence")
        return 3
    if config.READ_ONLY:
        print("REFUSING: HOI4_READ_ONLY=1")
        return 3

    print(f"save-side before: {json.dumps(focus_state_from_latest(), ensure_ascii=False)}")

    game = Game(pid)
    layer = CommandLayer(game)
    tag_addr = layer.gamestate + T.GS_PLAYER_TAG_OFF
    print(f"gamestate={layer.gamestate:#x} queue={layer.queue:#x} "
          f"gate_open={layer.queue_gate_open()} paused={layer.is_paused()}")
    print(f"&tag = {tag_addr:#x}  tag value = {layer.player_tag} "
          f"(the UI passes this very address)")
    if not layer.player_tag:
        print("REFUSING: player tag reads 0 — the ctor would build a bogus command")
        return 4

    res = layer.drop_focus_ctor()
    print(f"post (ctor path): {json.dumps(res, ensure_ascii=False, default=str)}")
    if res.get("dead"):
        print("  THE GAME IS GONE — see research/NOTES.md")
        return 6
    if res.get("job_intact") is False:
        print("  WARNING: job_intact=False — treat this send as untrusted")
    if not res.get("posted"):
        print("  posted=False: the game refused (CanExecute: no focus running?) "
              "or the delivery never ran — not automatically a channel failure")

    time.sleep(1.5)
    if a.save:
        name = save_via_ui()
        print(f"saved: {name!r}")
        if name:
            time.sleep(1.0)
            # the dialog writes <name>_temp.hoi4 first and then renames over
            # <name>; both are evidence, so report whichever exists
            for cand in (name, name.replace("_temp", "")):
                st = focus_state_in(cand)
                if "error" not in st:
                    print(f"save-side after ({cand}): "
                          f"{json.dumps(st, ensure_ascii=False)}")

    print(f"channel stats: {layer.script.status()}")
    print("alive:", game.proc.is_alive())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
