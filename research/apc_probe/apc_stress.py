"""Live stress test for the APC command channel: N sends in a row.

This is the check the retired graft protocol could never pass ("one command per
session"): the channel creates no thread and suspends none, so consecutive
sends should simply work. Alternates Increase/Decrease so the game's speed ends
where it started.

Usage: python research/apc_probe/apc_stress.py [--sends 6] [--pid N] [--graft]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4_mcp.inject.commands import CommandLayer     # noqa: E402
from hoi4_mcp.process.attach import Game              # noqa: E402
from hoi4_mcp import safety                           # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sends", type=int, default=6)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--graft", action="store_true",
                    help="use the retired freeze/graft protocol instead")
    args = ap.parse_args()

    g = Game(args.pid)
    rep = safety.guard(pid=g.proc.pid)
    print(f"pid={g.proc.pid} guard={rep.verdict}")
    if rep.verdict == "multiplayer":
        raise SystemExit("refusing: multiplayer evidence present")

    L = CommandLayer(g)
    print(f"queue={L.queue:#x} tag={L.player_tag} paused={L.is_paused()} "
          f"gate={L.queue_gate_open()}")

    ok = 0
    for i in range(args.sends):
        name = "IncreaseGameSpeed" if i % 2 == 0 else "DecreaseGameSpeed"
        t0 = time.time()
        try:
            r = (L.send_fused(name) if args.graft else L.send_apc(name))
        except Exception as e:
            print(f"[{i}] EXC {type(e).__name__}: {e}")
            break
        alive = g.is_alive()
        print(f"[{i}] {name:22s} posted={r.get('posted')} "
              f"cmd={r.get('cmd')} lat={r.get('latency_ms')}ms "
              f"kind={r.get('thread_kind')} intact={r.get('job_intact')} "
              f"wall={time.time()-t0:.2f}s alive={alive}")
        if not alive:
            print("!! process died")
            break
        if r.get("posted"):
            ok += 1
    print(f"\n{ok}/{args.sends} posted; stats={L.apc.status() if not args.graft else L.rc.stats()}")
    print("paused:", L.is_paused(), "alive:", g.is_alive())


if __name__ == "__main__":
    main()
