"""speed_pips.py — read the HOI4 speed-pip strip as data instead of by eye.

The pips live just below the date panel. Each of the five slots is classified by
its dominant colour:

    green  = a speed step that is available/selected
    bright = the currently selected speed
    red    = the top step when the game is at its ceiling? (observed 24 日)
    dark   = empty

Usage:
  python research/speed_pips.py                 # classify now
  python research/speed_pips.py --before FILE --after FILE
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BAND = (0.775, 0.043, 0.865, 0.056)      # x0, y0, x1, y1 (client normalised)
SLOTS = 5


def grab() -> np.ndarray:
    from hoi4_mcp.process.attach import Game
    from hoi4_mcp.ui.session import SessionDriver
    return SessionDriver(Game()).shot()


def band(arr: np.ndarray) -> np.ndarray:
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = (int(BAND[0] * w), int(BAND[1] * h),
                      int(BAND[2] * w), int(BAND[3] * h))
    return arr[y0:y1, x0:x1]


def classify(sub: np.ndarray) -> list[str]:
    """Split the band into five slots and name each slot's dominant colour."""
    h, w = sub.shape[:2]
    out = []
    for i in range(SLOTS):
        col = sub[:, int(i * w / SLOTS):int((i + 1) * w / SLOTS)]
        px = col.reshape(-1, 3).astype(int)
        r, g, b = px[:, 0].mean(), px[:, 1].mean(), px[:, 2].mean()
        lum = (r + g + b) / 3
        if lum < 55:
            out.append(f"dark({lum:.0f})")
        elif g > r + 12 and g > b + 12:
            out.append(f"green({r:.0f},{g:.0f},{b:.0f})")
        elif r > g + 25:
            out.append(f"red({r:.0f},{g:.0f},{b:.0f})")
        elif b > r + 15 and b > g + 15:
            out.append(f"blue({r:.0f},{g:.0f},{b:.0f})")
        else:
            out.append(f"grey({r:.0f},{g:.0f},{b:.0f})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", type=Path)
    ap.add_argument("--after", type=Path)
    a = ap.parse_args()
    if a.before and a.after:
        from PIL import Image
        for tag, p in (("before", a.before), ("after", a.after)):
            arr = np.asarray(Image.open(p).convert("RGB"))
            print(f"{tag:6s} {p.name}: {classify(band(arr))}")
        return 0
    arr = grab()
    print(f"pips now: {classify(band(arr))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
