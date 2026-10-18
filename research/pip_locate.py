"""pip_locate.py — find the speed-pip strip in a live screenshot (ASCII map).

Prints a coarse character map of the top-right area so the pip row can be
located in client coordinates:

    G  green-ish      R  red-ish      .  dark      o  grey/bright

Usage: python research/pip_locate.py [x0 y0 x1 y1]
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def char_for(px) -> str:
    r, g, b = (int(v) for v in px)
    lum = (r + g + b) / 3
    if lum < 55:
        return "."
    if g > r + 12 and g > b + 12:
        return "G"
    if r > g + 25:
        return "R"
    if b > r + 15 and b > g + 15:
        return "B"
    return "o"


def main() -> int:
    from hoi4copilot.process.attach import Game
    from hoi4copilot.ui.session import SessionDriver
    arr = SessionDriver(Game()).shot()
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = (0.68, 0.005, 0.95, 0.13)
    if len(sys.argv) > 4:
        x0, y0, x1, y1 = (float(v) for v in sys.argv[1:5])
    sub = arr[int(y0 * h):int(y1 * h):2, int(x0 * w):int(x1 * w):2]
    print(f"client {w}x{h}; region x {x0}-{x1} y {y0}-{y1} "
          f"(rows step {2/h:.4f}, cols step {2/w:.4f})")
    for row in sub:
        print("".join(char_for(px) for px in row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
