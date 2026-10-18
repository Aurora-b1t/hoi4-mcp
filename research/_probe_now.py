"""One-off read-only probe of the running game: session identity chain, queue
gate, paused bit, player tag, plus the newest save + its focus section.

Zero writes, zero calls into the game (no APC, no payload). Safe to run while
the user is playing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp import config, safety                                    # noqa: E402
from hoi4_mcp.process.attach import Game, find_live_pids               # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"


def main() -> int:
    live = find_live_pids()
    print(f"live hoi4 pids: {live}")
    if len(live) != 1:
        return 2
    pid = live[0]
    newest = max(SAVE_DIR.glob("*.hoi4"), key=lambda p: p.stat().st_mtime, default=None)
    print(f"newest save: {newest.name if newest else None} "
          f"(mtime {newest.stat().st_mtime:.0f})" if newest else "no saves")
    try:
        print("guard:", safety.guard(pid=pid, save_path=newest).as_line())
    except Exception as exc:                                        # noqa: BLE001
        print("guard failed:", exc)

    g = Game(pid)
    p = g.proc
    m = p.memory
    print(f"proc: pid={p.pid} base={p.base:#x} image_size={p.image_size:#x}")
    from hoi4_mcp.inject import tables as T
    for name, slot, vft in (("gamestate", T.G_GAMESTATE, T.VFT_GAMESTATE),
                            ("idler", T.G_IDLER, T.VFT_IDLER),
                            ("gameapp", T.G_GAMEAPP, T.VFT_GAMEAPP)):
        ptr = m.u64(p.base + slot)
        got = m.u64(ptr) - p.base if ptr else None
        print(f"  {name:9s} slot={slot:#x} -> {ptr:#x} "
              f"vft_rva={got if got is None else hex(got)} "
              f"expected={vft:#x} match={got == vft}")
    try:
        from hoi4_mcp.inject.commands import CommandLayer
        layer = CommandLayer(g)
        print(f"layer: gamestate={layer.gamestate:#x} queue={layer.queue:#x} "
              f"gate_open={layer.queue_gate_open()} paused={layer.is_paused()} "
              f"tag={layer.player_tag} &tag={layer.gamestate + T.GS_PLAYER_TAG_OFF:#x}")
    except Exception as exc:                                        # noqa: BLE001
        print("layer resolve failed:", exc)

    if newest is not None:
        from hoi4_mcp.readstate.country_sem import Countries, country_sections
        cn = Countries(newest)
        tag = cn.player() or cn.tags()[0]
        f = country_sections(cn, tag, ["focus"]).get(tag, {}).get("focus", {})
        print(f"save focus[{tag}]: " + json.dumps(
            {"current": f.get("current"), "remaining_days": f.get("remaining_days"),
             "banked_days": f.get("banked_days"), "n_completed": f.get("n_completed"),
             "n_available": len(f.get("available") or [])}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
