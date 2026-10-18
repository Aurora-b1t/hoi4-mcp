"""LIVE acceptance test for the APC command channel (23 日).

Posts CIncreaseGameSpeedCommand through the new in-process APC channel and
verifies the effect twice: (a) the command's own evidence (operator new
returned a heap object, Post returned non-zero, the payload ran on a game
thread), and (b) the HUD speed indicator, cropped before/after.

Speed is the same acceptance action 21 日 used for the graft protocol, so the
two channels are directly comparable. The speed is stepped back afterwards.

Usage: python research/apc_probe/apc_post_test.py [--delta 2] [--no-restore]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4copilot.inject.apc import SHELLCODE                      # noqa: E402
from hoi4copilot.inject.commands import CommandLayer              # noqa: E402
from hoi4copilot.process.attach import Game                       # noqa: E402
from hoi4copilot.tools import screenshot as S                     # noqa: E402
from hoi4copilot import safety                                    # noqa: E402

SHOTS = Path(__file__).resolve().parents[2] / "shots"


def hud_crop(pid: int, tag: str) -> Path:
    arr = S.capture_smart(pid)
    out = SHOTS / f"day23_speed_{tag}.png"
    if arr is not None:
        S.save_png(arr[0:80, 1380:1800], out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--delta", type=int, default=2)
    ap.add_argument("--no-restore", action="store_true")
    ap.add_argument("--pid", type=int, default=None)
    args = ap.parse_args()

    print("shellcode (%d bytes):" % len(SHELLCODE))
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(SHELLCODE, 0):
        print(f"   +{i.address:04x}: {i.mnemonic} {i.op_str}")

    g = Game(args.pid)
    rep = safety.guard(pid=g.proc.pid)
    print(f"\npid={g.proc.pid} guard={rep.verdict} ({rep.as_line()})")
    if rep.verdict == "multiplayer":
        raise SystemExit("refusing: multiplayer evidence present")

    layer = CommandLayer(g)
    print(f"queue={layer.queue:#x} player_tag={layer.player_tag} "
          f"paused={layer.is_paused()} gate_open={layer.queue_gate_open()}")

    before = hud_crop(g.proc.pid, "before")
    print(f"hud before -> {before.name}")

    print(f"\n== post IncreaseGameSpeed x{args.delta} via special APC ==")
    for i in range(args.delta):
        t0 = time.time()
        res = layer.send_apc("IncreaseGameSpeed")
        print(f"  [{i}] {res}  (wall {time.time()-t0:.2f}s)")
        print(f"      alive={g.is_alive()} paused={layer.is_paused()}")
        if not g.is_alive():
            print("  !! process died — stopping here")
            break

    time.sleep(0.8)
    after = hud_crop(g.proc.pid, "after")
    print(f"hud after  -> {after.name}")
    print(f"paused after speed change: {layer.is_paused()} (unchanged expected)")
    print("apc stats:", layer.apc.status())

    if not args.no_restore:
        print(f"\n== restore: DecreaseGameSpeed x{args.delta} ==")
        for i in range(args.delta):
            print(f"  [{i}] {layer.send_apc('DecreaseGameSpeed')}")
        time.sleep(0.5)
        print(f"paused now: {layer.is_paused()}")
        print("apc stats:", layer.apc.status())

    print("\ngame alive:", g.is_alive())
    print("compare the two crops for the speed pips.")


if __name__ == "__main__":
    main()


