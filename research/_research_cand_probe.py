"""One-off live probe: validate specific CTechnology candidates through the game's
own accessors (read-only w.r.t. game state).

    r1 = 0xED5080(manager, cand)        -> the country's instance for that id | NULL
    r2 = 0xED8F00(manager, cand, 0)     -> the CanResearch predicate CanExecute uses

One candidate per delivery is *not* needed (a fault aborts the VM, so candidates
after a faulting one do not run) — order therefore matters: put the risky ones
last. The faulting op is decoded from job.S_FAULT_R13.

Usage: python research/_research_cand_probe.py 0x... 0x... [--pid N]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot import config, safety                                   # noqa: E402
from hoi4copilot.inject import script as S                               # noqa: E402
from hoi4copilot.inject.commands import CommandLayer                     # noqa: E402
from hoi4copilot.process.attach import Game, find_live_pids              # noqa: E402

FN_MAP, FN_CAN = 0xED5080, 0xED8F00
SAVE_DIR = config.DOCS_ROOT / "save games"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("addrs", nargs="+")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--map-only", action="store_true",
                    help="call only 0xED5080 (id -> instance); skip the predicate")
    a = ap.parse_args()
    cands = [int(x, 16) for x in a.addrs]

    live = find_live_pids()
    pid = a.pid or (live[0] if len(live) == 1 else None)
    if pid is None:
        return 2
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda q: q.stat().st_mtime, default=None)
    print(f"guard: {safety.guard(pid=pid, save_path=newest).as_line()}")
    if config.READ_ONLY:
        return 3

    game = Game(pid)
    p, m = game.proc, game.proc.memory
    layer = CommandLayer(game)
    gs = layer.gamestate
    tag = layer.player_tag
    countries = [int.from_bytes(m.rpm(m.u64(gs + 0x310) + i * 8, 8), "little")
                 for i in range(512)]
    mgr = m.u64(countries[tag] + 0xF60)
    print(f"manager={mgr:#x} paused={layer.is_paused()} shield={layer.script.install_shield().get('installed')}")

    sc = S.Script(allow_calls={(p.base, p.base + p.image_size)})
    pairs = []
    for c in cands:
        i = int(sc.call(p.base + FN_MAP, mgr, c))
        j = None if a.map_only else int(sc.call(p.base + FN_CAN, mgr, c, 0))
        pairs.append((i, j))
    t0 = time.time()
    r = layer.script.run(sc)
    print(f"delivery: done={r.get('done')} status={r.get('status')} "
          f"latency={(time.time()-t0)*1000:.0f}ms intact={r.get('job_intact')} "
          f"fault_rip={r.get('fault_rip'):#x} fault_code={r.get('fault_code'):#x} "
          f"dead={r.get('dead', False)}")
    page = r.get("page") or 0
    fr13 = r.get("fault_r13") or 0
    if fr13 and page:
        idx = (fr13 - (page + S.D_OPS)) // S.OP_SIZE
        which = "map" if (a.map_only or idx % 2 == 0) else "can_research"
        who = cands[idx // (1 if a.map_only else 2)]
        print(f"  fault happened in op {idx} ({which} for {who:#x}) "
              f"-> later candidates did not run")
    res = r.get("results") or []
    for n, (c, (i, j)) in enumerate(zip(cands, pairs)):
        inst = res[i] if i < len(res) else None
        can = None if j is None else (res[j] if j < len(res) else None)
        tid = None
        iface = None
        try:
            tid = m.u32(c + 0x38)
            iface = m.u64(c + 0x48)
        except OSError:
            pass
        print(f"  [{n}] {c:#x} id={tid:<6d} [+0x48]={iface:#x} "
              f"instance={inst if inst is None else hex(inst)} "
              f"can_research={can if can is None else bool(can)}")
    time.sleep(0.4)
    print(f"post-check: paused={layer.is_paused()} alive={p.is_alive()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
