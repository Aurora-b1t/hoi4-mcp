"""E2E closed loop for the inject write layer: CIncrease/DecreaseGameSpeedCommand.

Safety posture: game paused (verified), SP guard enforced, single-shot calls
(two remote calls per command, no loop injection), every step re-verified,
speed restored to the starting value at the end.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process.attach import Game
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.ui.session import SessionDriver
from hoi4_mcp.inject.guard import write_refusal
from hoi4_mcp.inject.commands import CommandLayer
from hoi4_mcp.inject import tables as T


def snap_bands(p, addrs) -> dict[int, bytes]:
    out = {}
    for label, addr, n in addrs:
        out[label] = p.memory.rpm(addr, n)
    return out


def diff_bands(a: dict, b: dict, base_map: dict) -> list[str]:
    out = []
    for label in a:
        if a[label] != b[label]:
            ra = a[label]
            rb = b[label]
            for i in range(min(len(ra), len(rb))):
                if ra[i] != rb[i]:
                    out.append(f"{label}+{i:#x}: {ra[i]:#04x} -> {rb[i]:#04x} "
                               f"(abs {hex(base_map[label] + i)})")
    return out


def main():
    refusal = write_refusal(None)
    if refusal:
        print(refusal)
        return

    g = Game()
    p = g.proc
    print(f"attached {p!r}")

    d = SessionDriver(g)
    icon0 = d.icon_state()
    print(f"ground truth before: icon={icon0}")
    if icon0 != "paused":
        print("NOT PAUSED — aborting inject test (discipline: paused only)")
        return
    shot0 = d.save_shot(Path.home() / ".hoi4_mcp" / "shots", "inject_before")
    print("before shot:", shot0)

    layer = CommandLayer(g)
    layer.rc.attempts = 40
    layer.rc.rearm_delay = 0.008
    print(f"gamestate={layer.gamestate:#x} tag={layer.player_tag} "
          f"queue={layer.queue:#x} gate_open={layer.queue_gate_open()} "
          f"idler={layer.idler:#x} paused_byte={layer.is_paused()}")

    # memory bands to diff (locate the speed field as a bonus): the idler band
    # around the Linux-equivalent pause/speed neighbourhood.
    idler = layer.idler
    band_defs = [("idler", idler + 0x600, 0x200)]
    before = snap_bands(p, band_defs)

    print("\n== injecting IncreaseGameSpeed x2 (fused: one freeze per send) ==")
    r1 = layer.send_fused("IncreaseGameSpeed")
    print("  post #1:", r1)
    time.sleep(0.6)
    r2 = layer.send_fused("IncreaseGameSpeed")
    print("  post #2:", r2)
    time.sleep(1.0)

    icon1 = d.icon_state()
    shot1 = d.save_shot(Path.home() / ".hoi4_mcp" / "shots", "inject_after_up")
    after = snap_bands(p, band_defs)
    diffs = diff_bands(before, after, {lbl: a for (lbl, a, _n) in band_defs})
    print(f"after: icon={icon1} shot={shot1}")
    print("memory diffs:")
    for x in diffs[:40]:
        print("  ", x)
    print(f"  ({len(diffs)} changed bytes total in the sampled bands)")
    print("caller stats:", layer.rc.stats())

    print("\n== reverting: DecreaseGameSpeed x2 (fused) ==")
    r3 = layer.send_fused("DecreaseGameSpeed")
    print("  post #3:", r3)
    time.sleep(0.6)
    r4 = layer.send_fused("DecreaseGameSpeed")
    print("  post #4:", r4)
    time.sleep(1.0)
    icon2 = d.icon_state()
    shot2 = d.save_shot(Path.home() / ".hoi4_mcp" / "shots", "inject_after_down")
    restored = snap_bands(p, band_defs)
    diffs2 = diff_bands(before, restored, {lbl: a for (lbl, a, _n) in band_defs})
    print(f"final: icon={icon2} shot={shot2}")
    print(f"revert residual diffs: {len(diffs2)}")
    for x in diffs2[:20]:
        print("  ", x)


if __name__ == "__main__":
    main()
