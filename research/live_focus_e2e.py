"""live_focus_e2e.py — SetNationalFocus through the APC channel, with live and
save-side evidence (24 日, the Phase I main dish).

Sequence (all player-equivalent, CanExecute stays in charge):

  1. guard + attach; find the player country's current focus state in the
     NEWEST save (ground truth before),
  2. resolve the numeric focus id from the LIVE CNationalFocus instances and
     dump the target focus object's neighbourhood (before),
  3. `CSession::Post(SetNationalFocusCommand{tag, focus_id, mode})` through the
     APC channel — one special user APC,
  4. dump the same neighbourhood again (after) and diff it: the write layer's
     effect on live memory, without saving,
  5. optionally (--save) drive the in-game menu to write a fresh save, so the
     offline parser can confirm `focus.current` flipped.

Usage:
  python research/live_focus_e2e.py --focus GER_accelerate_the_rearmament_program
  python research/live_focus_e2e.py --focus GER_autarky_efforts --mode 1 --save
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot import config, safety                                   # noqa: E402
from hoi4copilot.inject import tables as T                               # noqa: E402
from hoi4copilot.inject.commands import CommandLayer                     # noqa: E402
from hoi4copilot.inject.focus_ids import _string_field                   # noqa: E402
from hoi4copilot.process import win32ext as w                            # noqa: E402
from hoi4copilot.process.attach import (AttachedProcess, Game,             # noqa: E402
                                        find_live_pids)
from hoi4copilot.process.instances import scan_for_vftable_ptr           # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"
DUMP = 0x120


def focus_objects(proc) -> dict[int, tuple[int, str]]:
    """{id: (object address, name)} from live CNationalFocus instances."""
    m = proc.memory
    out: dict[int, tuple[int, str]] = {}
    for a in scan_for_vftable_ptr(proc, [T.FOCUS_VFT]).get(T.FOCUS_VFT, []):
        try:
            head = m.rpm(a, 0x40)
        except OSError:
            continue
        fid = int.from_bytes(head[8:12], "little")
        name = _string_field(m, a + 0x18) or _string_field(m, a + 0x38)
        if name:
            out[fid] = (a, name)
    return out


def before_after(proc, addr: int) -> list[tuple[int, int, int]]:
    raw = proc.memory.rpm(addr - 0x40, DUMP)
    return [(i, raw[i], raw[i]) for i in range(DUMP)]


def diff_dump(a: bytes, b: bytes) -> list[str]:
    out = []
    for i in range(0, min(len(a), len(b)), 8):
        if a[i:i + 8] != b[i:i + 8]:
            out.append(f"  +{i:#04x}: {a[i:i+8].hex()} -> {b[i:i+8].hex()} "
                       f"({int.from_bytes(a[i:i+8],'little'):#x} -> "
                       f"{int.from_bytes(b[i:i+8],'little'):#x})")
    return out


def focus_state_from_latest() -> dict:
    path = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    if path is None:
        return {}
    from hoi4copilot.readstate.country_sem import Countries, country_sections
    cn = Countries(path)
    tag = cn.player() or cn.tags()[0]
    sec = country_sections(cn, tag, ["focus"]).get(tag, {})
    f = sec.get("focus", {})
    return {"save": path.name, "tag": tag, "current": f.get("current"),
            "banked_days": f.get("banked_days"), "progress": f.get("progress"),
            "n_completed": f.get("n_completed")}


def save_via_ui() -> str:
    """The hoi4_save() chain: menu -> 保存 -> confirm (player-equivalent).

    The dialog prefills `GER_<game date>`, which for this session is the very
    file we are reading, so the game raises an overwrite confirmation: the
    current newest GER save is copied aside first ("_backup_..._pre_focus.hoi4")
    and the confirmation is clicked if it appears.
    """
    from hoi4copilot.ui.session import SessionDriver
    from hoi4copilot.process.attach import Game
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    if newest is not None:
        backup = SAVE_DIR / f"_backup_{newest.stem}_pre_focus.hoi4"
        if not backup.exists():
            import shutil
            shutil.copy2(newest, backup)
            print(f"  (backed up {newest.name} -> {backup.name})")
    d = SessionDriver(Game())
    before = {p.name: p.stat().st_mtime for p in SAVE_DIR.glob("*.hoi4")}
    d.open_menu()
    time.sleep(0.5)
    d.input.click(0.502, 0.30)
    time.sleep(1.5)
    d.input.click(0.560, 0.813)
    confirmed = False
    for i in range(30):
        time.sleep(2.0)
        after = {p.name: p.stat().st_mtime for p in SAVE_DIR.glob("*.hoi4")}
        new = [k for k, v in after.items() if before.get(k) != v]
        if new:
            time.sleep(2.5)
            return new[0]
        if not confirmed and i >= 2:
            d.input.click(0.570, 0.678)      # 覆盖确认框 OK
            confirmed = True
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--focus", default="GER_accelerate_the_rearmament_program")
    ap.add_argument("--save", action="store_true", help="also write a save and re-parse")
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

    p = AttachedProcess(pid)
    print(f"attached pid={pid} base={p.base:#x} version={p.version()!r}")
    print(f"save-side before: {json.dumps(focus_state_from_latest(), ensure_ascii=False)}")

    print("scanning live CNationalFocus instances (~20s) ...")
    objs = focus_objects(p)
    print(f"  {len(objs)} focus objects")
    hit = [(fid, addr, nm) for fid, (addr, nm) in objs.items() if nm == a.focus]
    if not hit:
        near = [nm for _, nm in objs.values() if a.focus.lower() in nm.lower()][:8]
        print(f"  focus {a.focus!r} not found live; near: {near}")
        return 4
    fid, faddr, fname = hit[0]
    print(f"  {fname} -> id {fid} @ {faddr:#x}")

    p.detach()
    game = Game(pid)
    p = game.proc
    layer = CommandLayer(game)
    print(f"queue={layer.queue:#x} gate_open={layer.queue_gate_open()} "
          f"player_tag={layer.player_tag} paused={layer.is_paused()}")
    print(f"tag address the UI passes: {layer.gamestate + T.GS_PLAYER_TAG_OFF:#x} "
          f"(= gamestate+{T.GS_PLAYER_TAG_OFF:#x})")

    snap0 = p.memory.rpm(faddr - 0x40, DUMP)

    t0 = time.time()
    res = layer.post_focus_ctor(faddr)
    print(f"post (ctor path): {json.dumps(res, ensure_ascii=False, default=str)} "
          f"({(time.time() - t0) * 1000:.0f}ms wall)")
    if res.get("dead"):
        print("  THE GAME IS GONE — see the crash forensics in research/NOTES.md")
        return 6
    if not res.get("posted"):
        print("  posted=False — the game refused the command (CanExecute said no) "
              "or the delivery never ran; not necessarily a channel failure")
        return 5
    if res.get("job_intact") is False:
        print("  WARNING: job_intact=False — treat this send as untrusted")

    time.sleep(1.5)
    snap1 = p.memory.rpm(faddr - 0x40, DUMP)
    changes = diff_dump(snap0, snap1)
    print(f"focus object diff around {faddr:#x} (relative to {faddr - 0x40:#x}):")
    print("\n".join(changes) if changes else "  (no change in this window)")

    # second view: the same object read again after another second, to separate
    # "the game set a flag" from "the game is ticking it"
    time.sleep(1.0)
    snap2 = p.memory.rpm(faddr - 0x40, DUMP)
    changes2 = diff_dump(snap1, snap2)
    print("second diff (1s later):")
    print("\n".join(changes2) if changes2 else "  (stable)")

    if a.save:
        name = save_via_ui()
        print(f"saved: {name!r}")
        if name:
            time.sleep(1.0)
            print(f"save-side after: {json.dumps(focus_state_from_latest(), ensure_ascii=False)}")

    print(f"channel stats: {layer.script.status()}")
    print("alive:", p.is_alive())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
