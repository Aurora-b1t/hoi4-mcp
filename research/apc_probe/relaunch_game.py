"""Relaunch hoi4.exe and bring back the save session (23 日, after the APC
command-payload crash killed the previous process).

The process died from OUR bug, not from a game fault: the private stack of the
first channel version was too small, the game's own operator new frames ran
down into the job, and the payload re-read it as garbage (AV at offset 0 —
`call 0`). Layout + payload are fixed and stand-in verified; this script gets
the session back so the fixed channel can be tested for real.

Steps (each one screenshots, so a wrong coordinate is caught before the next):
  1  start hoi4.exe (skips the launcher), wait for the window
  2  main menu  -> 单人游戏
  3  landing screen -> newest save row
  4  -> 开始 (start)
  5  wait for the session, report the date panel

Usage: python research/apc_probe/relaunch_game.py --until 4
"""
from __future__ import annotations

import argparse
import ctypes
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4_mcp.tools import screenshot as S          # noqa: E402
from hoi4_mcp.tools.input import Input              # noqa: E402
from hoi4_mcp import config                         # noqa: E402

SHOTS = Path(__file__).resolve().parents[2] / "shots"
_u32 = ctypes.WinDLL("user32", use_last_error=True)


def find_pid(timeout: float = 120.0) -> int | None:
    """Newest USABLE instance: a crashed hoi4.exe can linger for hours as a
    one-thread zombie that still answers by name (23 日), so require a real
    session's thread count."""
    import psutil
    t0 = time.time()
    while time.time() - t0 < timeout:
        cands = []
        for p in psutil.process_iter(["name", "create_time"]):
            try:
                if (p.info["name"] or "").lower() == "hoi4.exe" and p.num_threads() >= 8:
                    cands.append((p.info["create_time"], p.pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if cands:
            return max(cands)[1]
        time.sleep(1.0)
    return None


def shot(pid: int, tag: str) -> Path:
    arr = S.capture_smart(pid)
    out = SHOTS / f"day23_relaunch_{tag}.png"
    if arr is not None:
        S.save_png(arr, out)
        print(f"  shot -> {out.name} {arr.shape}")
    else:
        print("  shot FAILED (client off-screen?)")
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--until", type=int, default=4)
    ap.add_argument("--install", default=str(config.find_install_dir()))
    args = ap.parse_args()

    # clean slate: the crashed process can linger as a one-thread zombie
    subprocess.run(["taskkill", "/F", "/IM", "hoi4.exe"], capture_output=True)
    time.sleep(2.0)

    exe = Path(args.install) / "hoi4.exe" if args.install else None
    if exe is None or not exe.exists():
        raise SystemExit(f"hoi4.exe not found (--install {args.install!r})")
    print(f"starting {exe}")
    subprocess.Popen([str(exe)], cwd=str(exe.parent))

    pid = find_pid()
    if not pid:
        raise SystemExit("hoi4.exe did not start")
    print(f"pid={pid}, waiting for the main menu (60s)")
    time.sleep(60)
    try:
        hwnd = S.find_hoi4_hwnd(pid)
        print("onscreen:", S.ensure_onscreen(hwnd))
    except Exception as e:
        print("window note:", e)
        hwnd = S.find_hoi4_hwnd(pid)
    S.focus_window(hwnd)
    time.sleep(1.0)
    inp = Input(hwnd)
    shot(pid, "1_menu")

    if args.until >= 2:
        print("click 单人游戏 (0.498, 0.196)")
        inp.click(0.498, 0.196)
        time.sleep(3.0)
        shot(pid, "2_sp_menu")

    if args.until >= 3:
        # the single-player landing screen is a SUBMENU (继续游戏 / 开始游戏 /
        # 载入游戏 / 游戏教程 / 返回), not the save list: 继续游戏 is avoided on
        # purpose (NOTES 15 日 CTD case), so go through 载入游戏.
        print("click 载入游戏 (0.498, 0.387)")
        inp.click(0.498, 0.387)
        time.sleep(4.0)
        shot(pid, "3_load_dialog")
        print("click newest save row (0.140, 0.3625)")
        inp.click(0.140, 0.3625)
        time.sleep(2.0)
        shot(pid, "3b_row_selected")

    if args.until >= 4:
        # measured 23 日 on 1920x1200: the green 开始 button spans x 1310..1560,
        # and the documented 0.851 also lands inside the clickable bar
        print("click 开始 (0.851, 0.946)")
        inp.click(0.851, 0.946)
        print("waiting 60s for the session to load")
        time.sleep(60)
        shot(pid, "4_ingame")

    print("done")


if __name__ == "__main__":
    main()
