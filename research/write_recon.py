"""write_recon.py — READ-ONLY reconnaissance of the inject/write layer.

Answers, in one shot and without touching game state:
  * which hoi4.exe instances exist (live vs dying),
  * the identity chain the write layer insists on (gamestate / gameapp / queue /
    idler vftable RVAs vs inject/tables.py),
  * player tag, queue gate byte, live paused byte (idler+0x6C1),
  * mitigation-policy decode (by SDK bit order), thread inventory by kind,
  * which command classes the pinned table can build today.

Usage:
  python research/write_recon.py            # attach to the single live hoi4.exe
  python research/write_recon.py --pid 1234
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.inject import tables as T                      # noqa: E402
from hoi4_mcp.process import win32ext as w                    # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess, find_pids, find_live_pids  # noqa: E402

SS_BITS = ["EnableUserShadowStack", "AuditUserShadowStack", "SetContextIpValidation",
           "AuditSetContextIpValidation", "UserShadowStackStrictMode",
           "BlockNonCetBinaries", "BlockNonCetBinariesNonEhcont",
           "AuditBlockNonCetBinaries", "CetDynamicApisOutOfProcOnly",
           "SetContextIpValidationRelaxedMode"]


def decode_ss(flags: int) -> str:
    on = [n for i, n in enumerate(SS_BITS) if flags & (1 << i)]
    return f"{flags:#x} -> {on or 'none'}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    a = ap.parse_args()

    raw, live = find_pids(), find_live_pids()
    print(f"hoi4.exe by name : {raw}")
    print(f"hoi4.exe live    : {live}  (>= {8} threads; a dying crash remnant "
          f"sits at 1-2 threads)")

    if a.pid:
        pid = a.pid
    elif len(live) == 1:
        pid = live[0]
    else:
        print("REFUSING: need exactly one live hoi4.exe")
        return 2
    p = AttachedProcess(pid)
    m = p.memory
    print(f"attached pid={p.pid} base={p.base:#x} size={p.image_size:#x} "
          f"version={p.version()!r} (table {T.GAME_VERSION})")

    ss = w.get_mitigation_policy(p.handle, 15, 4) or 0
    print(f"shadow-stack policy (4B): {decode_ss(ss)}")
    print(f"  dynamic_code={w.get_mitigation_policy(p.handle, 2, 4)} "
          f"cfg={w.get_mitigation_policy(p.handle, 7, 4)} "
          f"block_non_cet={w.get_mitigation_policy(p.handle, 5, 4)}")

    # identity chain, exactly as CommandLayer._resolve() does it
    def expect(slot: int, vft: int, name: str) -> int | None:
        ptr = m.u64(p.base + slot)
        if not ptr:
            print(f"  {name:16s} slot {slot:#x} = NULL (not in a session?)")
            return None
        got = m.u64(ptr) - p.base
        ok = "OK " if got == vft else "STALE"
        print(f"  {name:16s} ptr={ptr:#x} vft_rva={got:#x} expect={vft:#x} {ok}")
        return ptr if got == vft else None

    print("identity chain:")
    gs = expect(T.G_GAMESTATE, T.VFT_GAMESTATE, "gamestate")
    ga = expect(T.G_GAMEAPP, T.VFT_GAMEAPP, "gameapplication")
    idler = expect(T.G_IDLER, T.VFT_IDLER, "ingame-idler")
    if ga:
        q = m.u64(ga + T.GAMEAPP_QUEUE_OFF)
        qv = m.u64(q) - p.base if q else 0
        print(f"  {'queue':16s} ptr={q:#x} vft_rva={qv:#x} expect={T.VFT_QUEUE:#x} "
              f"{'OK ' if qv == T.VFT_QUEUE else 'STALE'}")
        if q:
            print(f"  queue gate byte  [queue+{T.QUEUE_IS_HOST_OFF:#x}] = "
                  f"{m.u8(q + T.QUEUE_IS_HOST_OFF)} (1 = Post enqueues locally)")
            print(f"  sender stamp     [queue+{T.QUEUE_SENDER_OFF:#x}] = "
                  f"{m.u32(q + T.QUEUE_SENDER_OFF)}")
    if gs:
        print(f"  player tag       [gamestate+{T.GS_PLAYER_TAG_OFF:#x}] = "
              f"{m.u32(gs + T.GS_PLAYER_TAG_OFF)}")
    if idler:
        print(f"  paused byte      [idler+{T.IDLER_PAUSED_OFF:#x}] = "
              f"{m.u8(idler + T.IDLER_PAUSED_OFF)}  "
              f"mirror[+{T.IDLER_PAUSED_MIRROR:#x}] = "
              f"{m.u8(idler + T.IDLER_PAUSED_MIRROR)}")

    tids = w.list_thread_ids(p.pid)
    print(f"threads: {len(tids)}")

    print("command classes in tables.COMMANDS:")
    for name, spec in sorted(T.COMMANDS.items()):
        fields = ", ".join(f"{f[2]}@{f[0]:#x}" for f in spec["fields"]) or "-"
        print(f"  {name:20s} vt={spec['vt']:#x} size={spec['size']:#x} fields: {fields}")

    p.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
