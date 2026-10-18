"""live_vm_probe.py — first live run of the write-v3.1 VM payload (24 日).

Read-only with respect to game state: it installs the payload + crash shield in
our own arena, then

  1. reads live game memory THROUGH the VM (idler paused byte, gamestate
     vftable pointer) and cross-checks against plain RPM,
  2. calls a game function from a game thread (operator new) as the general
     "call anything" proof,
  3. deliberately faults inside the arena (read from an unmapped page) and
     requires the process to survive — the shield's live acceptance test,
  4. re-reads the paused byte afterwards: the game must still be answering.

Every step prints the job block (status / tid / latency / job_intact /
fault_rip) so the evidence is in the transcript, not in a claim.

Usage: python research/live_vm_probe.py [--pid N] [--no-fault]
"""
from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp import config, safety                                  # noqa: E402
from hoi4_mcp.inject import script as S                              # noqa: E402
from hoi4_mcp.inject import tables as T                              # noqa: E402
from hoi4_mcp.process import win32ext as w                           # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess, find_live_pids  # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"


def show(tag: str, r: dict) -> None:
    print(f"  {tag:26s} done={r.get('done')} status={r.get('status')} "
          f"tid={r.get('tid')} kind={r.get('kind')} "
          f"lat={'' if r.get('latency') is None else round(r['latency'] * 1000)}ms "
          f"intact={r.get('job_intact')} fault_rip={r.get('fault_rip'):#x} "
          f"fault_code={r.get('fault_code'):#x} dead={r.get('dead', False)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--no-fault", action="store_true")
    a = ap.parse_args()

    live = find_live_pids()
    pid = a.pid or (live[0] if len(live) == 1 else None)
    if pid is None:
        print(f"REFUSING: need exactly one live hoi4.exe, found {live}")
        return 2

    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    rep = safety.guard(pid=pid, save_path=newest)
    print(f"guard: {rep.as_line()}  (save={newest.name if newest else None})")
    if rep.verdict == "multiplayer" and not config.ALLOW_MP:
        print("REFUSING: multiplayer evidence; the write layer is SP-only")
        return 3
    if config.READ_ONLY:
        print("REFUSING: HOI4_READ_ONLY=1")
        return 3

    p = AttachedProcess(pid)
    m = p.memory
    print(f"attached pid={pid} base={p.base:#x} version={p.version()!r}")

    ch = S.ScriptChannel(p, timeout=4.0)
    res = ch.install_shield()
    print(f"shield: installed={res.get('installed')} handler={res.get('handler')} "
          f"handle={res.get('handle')}")
    show("install-shield", res["result"])
    print(f"arena: code={ch.code:#x} data={ch.data:#x} payload={len(S.PAYLOAD)}B")

    # ---- 1. read live game memory through the VM ----------------------------
    idler = m.u64(p.base + T.G_IDLER)
    paused_addr = idler + T.IDLER_PAUSED_OFF
    direct = m.u8(paused_addr)
    sc = S.Script()
    j = len(sc.ops)
    sc.read(paused_addr, 8)
    sc.read(p.base + T.G_GAMESTATE, 8)
    r = ch.run(sc)
    show("read idler/gamestate", r)
    got_paused = r["local"].get(j, b"\xff" * 8)[0]
    got_gs = struct.unpack("<Q", r["local"].get(j + 1, b"\0" * 8))[0]
    gs_expected = m.u64(p.base + T.G_GAMESTATE)
    print(f"    paused byte: rpm={direct} vm={got_paused} "
          f"{'MATCH' if direct == got_paused else 'MISMATCH'}")
    print(f"    gamestate ptr: rpm={gs_expected:#x} vm={got_gs:#x} "
          f"{'MATCH' if gs_expected == got_gs else 'MISMATCH'}")
    print(f"    gamestate vft rva: {m.u64(gs_expected) - p.base:#x} "
          f"(table says {T.VFT_GAMESTATE:#x})")

    # ---- 2. call a game function from a game thread -------------------------
    sc = S.Script(allow_calls={(p.base, p.base + p.image_size)})
    k = sc.call(p.base + T.FN_OPERATOR_NEW, 0x38)
    r = ch.run(sc)
    show("call operator new(0x38)", r)
    heap = r["results"][k] if r.get("results") else 0
    print(f"    returned heap pointer: {heap:#x} (leaks 0x38 bytes by design)")
    if heap:
        try:
            back = m.rpm(heap, 8)
            print(f"    first 8 bytes at that pointer: {back.hex()} (readable)")
        except OSError as exc:
            print(f"    pointer not readable: {exc}")

    # ---- 3. the shield's live acceptance test -------------------------------
    if not a.no_fault:
        sc = S.Script()
        sc.read(0x10, 8)                      # unmapped page: the VM faults
        r = ch.run(sc)
        show("deliberate fault", r)
        in_arena = ch.code <= r["fault_rip"] < ch.code + S.CODE_ARENA_SIZE
        print(f"    fault inside our arena: {in_arena}; "
              f"process alive: {p.is_alive()}")

    # ---- 4. the game must still answer --------------------------------------
    time.sleep(0.3)
    try:
        after = m.u8(paused_addr)
        gs_after = m.u64(p.base + T.G_GAMESTATE)
        print(f"post-check: paused byte={after} (was {direct}) "
              f"gamestate={gs_after:#x} (was {gs_expected:#x}) alive={p.is_alive()}")
    except OSError as exc:
        print(f"post-check FAILED: {exc}")
        return 1

    print(f"channel stats: {ch.status()}")
    print("LIVE VM PROBE:", "GREEN" if p.is_alive() and after == direct else "CHECK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
