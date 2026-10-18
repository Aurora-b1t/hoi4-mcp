"""live_speed_e2e.py — speed commands through the CTOR path, with pips evidence.

Why this is its own check: the 24 日 spec audit showed DecreaseGameSpeedCommand
is 0x48 bytes (not 0x40) because its constructor builds a std::string member at
+0x28. Going through the real ctor is now the only sanctioned way to build it, so
this script exercises

    operator new(0x48) -> CDecreaseGameSpeedCommand::ctor -> Post

on the live game and captures the speed-pip strip before/after, so the effect is
verifiable by eye (the 23 日 acceptance criterion) rather than by claim.

Usage: python research/live_speed_e2e.py [--steps 1] [--pid N]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp import config, safety                                   # noqa: E402
from hoi4_mcp.inject.commands import CommandLayer                     # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids              # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"
SHOTS = Path(__file__).resolve().parents[1] / "shots"
# the speed pips sit just below the date panel in the top-right corner
CROP = (0.70, 0.005, 0.94, 0.078)


def capture(tag: str):
    from PIL import Image
    from hoi4_mcp.ui.session import SessionDriver
    from research.speed_pips import band, classify
    d = SessionDriver(Game())
    arr = d.shot()
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = int(CROP[0] * w), int(CROP[1] * h), int(CROP[2] * w), int(CROP[3] * h)
    sub = arr[y0:y1, x0:x1]
    img = Image.fromarray(sub)
    img = img.resize((img.width * 2, img.height * 2), Image.NEAREST)
    out = SHOTS / f"day24_speed_{tag}.png"
    img.save(out)
    pips = classify(band(arr))
    print(f"  shot: {out} ({sub.shape[1]}x{sub.shape[0]} px crop, 2x)")
    print(f"  pips: {pips}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", type=int, default=1)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--direction", choices=("up", "down"), default="up")
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

    game = Game(pid)
    p = game.proc
    layer = CommandLayer(game)
    print(f"pid={pid} paused={layer.is_paused()} queue_gate={layer.queue_gate_open()}")
    print(f"shield: {layer.script.install_shield()}")

    print("capturing BEFORE ...")
    capture(f"{a.direction}_before")
    delta = a.steps if a.direction == "up" else -a.steps
    t0 = time.time()
    res = layer.speed_step_apc(delta)
    print(f"speed_step_apc({delta}) via {res['via']} in {(time.time() - t0) * 1000:.0f}ms")
    for r in res["results"]:
        print("   ", r)
    time.sleep(1.2)
    print("capturing AFTER ...")
    capture(f"{a.direction}_after")
    print("alive:", p.is_alive())
    print("compare the two PNGs: the pip block must move by one")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
