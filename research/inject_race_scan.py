"""Racy-scan picker battery (22 日 stability track, step 1 of 「先 racy 扫描后定点冻结」).

Validates the new no-suspension discriminator in inject/call.py against a
game-like victim BEFORE any live game touch (the established pre-game
protocol):

  victim = python process: main thread in a hot user-code loop + N sleeper
  threads circling kernel waits — the same mix as the paused game
  (main/idle + render threads hot, workers parked; 21 日 live sampling).

Battery:
  P  probes-only : probe_targets() classification (works LIVE too — it never
                   suspends anything; against the game pass --probes-only --live)
  T  tick-cycle  : repeated hijack calls (GetTickCount) xN — stresses the
                   2nd+ send scenario that crashed the game on 21 日
  L  legacy-demo : (opt-in) legacy full-scan under freeze against a sleeper
                   victim — expected to kill it, re-baselines 21 日 惨案 3.

Usage:
  python research/inject_race_scan.py                # P + T on a fresh victim
  python research/inject_race_scan.py --sends 30
  python research/inject_race_scan.py --probes-only --live   # game, read-only
  python research/inject_race_scan.py --legacy-demo          # disposable victim
"""
from __future__ import annotations

import argparse
import ctypes
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import AttachedProcess
from hoi4copilot.inject.call import RemoteCaller, CallError

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

FN_TICK = int(k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"GetTickCount"))

# game-like victim: 1 hot main + sleepers on kernel waits
VICTIM_SRC = r"""
import threading, sys
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8
stop = threading.Event()
def sleeper():
    while not stop.is_set():
        time.sleep(0.05)
import time
for _ in range(N):
    threading.Thread(target=sleeper, daemon=True).start()
x = 0
while not stop.is_set():
    x ^= 1
"""

SLEEP_VICTIM_SRC = r"""
import time, threading
stop = threading.Event()
def sleeper():
    while not stop.is_set():
        time.sleep(0.05)
threading.Thread(target=sleeper, daemon=True).start()
time.sleep(3600)   # main parked in a kernel wait, like a game system thread
"""


def spawn_victim(src: str, sleepers: int = 8) -> subprocess.Popen:
    argv = [sys.executable, "-c", src, str(sleepers)] if src is VICTIM_SRC \
        else [sys.executable, "-c", src]
    p = subprocess.Popen(argv)
    time.sleep(1.5)     # let threads spin up into steady state
    return p


def alive(pid: int) -> bool:
    try:
        import psutil
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except Exception:
        return False


def probes_only(rc: RemoteCaller, rounds: int = 8) -> dict:
    """Probe classification statistics — never suspends; safe on live game."""
    main_tid = rc._threads()[0]
    hist: dict[str, int] = {}
    per_tid: dict[int, int] = {}
    for i in range(rounds):
        short = rc.probe_targets()
        hist[f"n={len(short)}"] = hist.get(f"n={len(short)}", 0) + 1
        for tid in short:
            per_tid[tid] = per_tid.get(tid, 0) + 1
            hist["main" if tid == main_tid else "worker"] = \
                hist.get("main" if tid == main_tid else "worker", 0) + 1
    return {"main_tid": main_tid, "rounds": rounds, "hist": hist,
            "per_tid": {str(k): v for k, v in sorted(per_tid.items())}}


def tick_cycle(rc: RemoteCaller, sends: int = 20) -> tuple[list[int], list[str]]:
    """Repeated single-shot hijack calls; returns (tick values, notes)."""
    ticks, notes = [], []
    for i in range(sends):
        try:
            v = rc.call(FN_TICK, (), what=f"tick#{i}")
        except CallError as e:
            notes.append(f"send#{i}: {e}")
            break
        ticks.append(v)
    return ticks, notes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sends", type=int, default=20)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--probes-only", action="store_true")
    ap.add_argument("--live", action="store_true",
                    help="attach the running hoi4.exe instead of a victim "
                         "(probes-only is read-only-safe; sends NOT allowed)")
    ap.add_argument("--legacy-demo", action="store_true",
                    help="opt-in: legacy full-scan picker on a sleeper victim "
                         "(expected crash — re-baselines 21日 惨案 3)")
    args = ap.parse_args()

    if args.live:
        if not args.probes_only:
            print("LIVE sends are not part of this battery (one-injection "
                  "budget is reserved for a separate deliberate step).")
            return
        from hoi4copilot.process.attach import Game
        game = Game()
        proc = game.proc
        print(f"LIVE probes against hoi4.exe pid={proc.pid} (read-only, "
              "no suspension)")
    else:
        victim_src = SLEEP_VICTIM_SRC if args.legacy_demo else VICTIM_SRC
        vic = spawn_victim(victim_src, 8)
        proc = AttachedProcess(vic.pid)
        print(f"victim pid={vic.pid} src={'sleeper' if args.legacy_demo else 'hot+sleepers'}")

    rc = RemoteCaller(proc, timeout=6.0, attempts=10,
                      allow_module_patterns=("python",), mode="hijack")
    if args.legacy_demo:
        rc.legacy_fallback = True
        rc.attempts = 20

    print("\n== P: probe classification ==")
    stat = probes_only(rc, args.rounds)
    print(f"main_tid={stat['main_tid']} rounds={stat['rounds']}")
    print(f"hist={stat['hist']}")
    print(f"per_tid={stat['per_tid']}")
    if not args.legacy_demo:
        main_hits = stat["per_tid"].get(str(stat["main_tid"]), 0)
        worker_hits = sum(v for k, v in stat["per_tid"].items()
                          if k != str(stat["main_tid"]))
        ok = main_hits >= args.rounds * 0.4 and worker_hits <= 1
        print(f"classifier verdict: {'GREEN' if ok else 'CHECK'} "
              f"(main {main_hits}/{args.rounds}, workers {worker_hits})")

    if args.probes_only:
        print("\nprobes-only done (no suspension, no set-context anywhere).")
        return

    print("\n== T: repeated hijack tick-cycle ==")
    ticks, notes = tick_cycle(rc, args.sends)
    mono = all(b >= a for a, b in zip(ticks, ticks[1:]))
    print(f"ticks received: {len(ticks)}/{args.sends} monotonic={mono}")
    for n in notes:
        print("  note:", n)

    if args.legacy_demo:
        time.sleep(0.5)
        print(f"\nlegacy-demo result: victim alive={alive(vic.pid)} "
              f"(expected False — re-baselines 惨案 3)")
        if alive(vic.pid):
            vic.kill()
        print("rc.stats:", rc.stats())
        return

    time.sleep(0.5)
    ok_victim = alive(vic.pid)
    print(f"\nvictim alive after cycle: {ok_victim}")
    print("rc.stats:", rc.stats())
    verdict = "GREEN" if (ok_victim and mono and len(ticks) >= args.sends) else "FAIL"
    print(f"\nRACY-PICKER BATTERY: {verdict}")
    if not ok_victim and vic.poll() is None:
        vic.kill()
    sys.exit(0 if verdict == "GREEN" else 1)


if __name__ == "__main__":
    main()
