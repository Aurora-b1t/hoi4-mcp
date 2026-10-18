"""Controlled clock walk: floor speed to 1, unpause ~90 s, track packed-date cells.

Sweeps RW memory for u64 values near the dominant packed date (0x029C77F8
band) while paused, unpauses, sweeps again, and reports which cells moved and
by how much (the per-hour stride). Screenshots at each checkpoint document the
displayed date for cross-checking.
"""

import sys
import time
import json
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np

from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process import instances as inst
from hoi4_mcp.process.attach import Game
from hoi4_mcp.tools import screenshot as shot
from hoi4_mcp.tools.input import Input

SHOTS = Path(__file__).parent / "shots"
V0 = 0x029C77F8          # dominant packed value while paused at 13:00 Jan 21
BAND_LO = V0 - 0x8000
BAND_HI = V0 + 0x10000
SAMPLE_DATA = Path(__file__).parent / "clock_walk.json"


def sweep_cells(p) -> dict[int, int]:
    """addr -> u64 for cells whose value falls in the date band."""
    out = {}
    n_scanned = 0
    for mbi in inst._readable_regions(p):
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(1 << 22, end - addr)
            try:
                raw = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            n_scanned += n
            m = len(raw) // 8
            q = np.frombuffer(raw[: m * 8], dtype=np.uint64)
            mask = (q >= BAND_LO) & (q <= BAND_HI)
            idx = np.nonzero(mask)[0]
            for i in idx.tolist():
                out[addr + i * 8] = int(q[i])
            addr += n
    print(f"  scanned {n_scanned/1e9:.2f} GB -> {len(out)} cells in band")
    return out


def take_shot(tag, p):
    arr = shot.capture_smart(p.pid)
    shot.save_png(arr, SHOTS / f"{tag}.png")
    return tag


def main():
    g = Game()
    p = g.proc
    hwnd = shot.find_hoi4_hwnd(p.pid)
    shot.focus_window(hwnd)
    inp = Input(hwnd)

    CLIP = (0.68, 0.04, 0.758, 0.059), (0.775, 0.059)  # panel origin; slow btn; pause btn

    # A. floor the speed: press '-' (0xBD) 8 times, keyed on the game window
    take_shot("cw_pre", p)
    for _ in range(8):
        inp.key(0xBD)  # VK_OEM_MINUS
        time.sleep(0.15)
    take_shot("cw_speed1", p)

    # B. baseline sweep while paused
    print("sweep A (paused)...")
    a = sweep_cells(p)
    base = {ad: v for ad, v in a.items() if v == V0}
    print(f"  cells == V0: {len(base)}")
    take_shot("cw_t0", p)

    # C. unpause and let the game run
    inp.key(0x20)  # space
    time.sleep(95.0)

    # D. sweep while running
    print("sweep B (running)...")
    b = sweep_cells(p)
    take_shot("cw_t1", p)

    # E. pause again to restore state
    inp.key(0x20)
    time.sleep(2.0)
    take_shot("cw_t2", p)

    moved = []
    for ad, v1 in base.items():
        v2 = b.get(ad)
        if v2 is not None and v2 != v1:
            moved.append((ad, v1, v2, v2 - v1))
    moved.sort(key=lambda t: -abs(t[3]))
    summary = {
        "V0": V0,
        "band_size_a": len(a),
        "cells_V0": len(base),
        "moved_count": len(moved),
        "delta_hist": {},
        "moved_top": [(hex(ad), hex(v1), hex(v2), v2 - v1) for ad, v1, v2, d in moved[:60]],
    }
    from collections import Counter
    dh = Counter(t[3] for t in moved)
    summary["delta_hist"] = {str(k): v for k, v in dh.most_common(20)}
    print("delta histogram:", dict(dh.most_common(20)))
    SAMPLE_DATA.write_text(json.dumps(summary, indent=1))
    print("saved", SAMPLE_DATA)


if __name__ == "__main__":
    main()
