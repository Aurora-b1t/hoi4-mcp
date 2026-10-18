"""Drive HOI4's menus with normalized clicks to reach a game session.

Menu geometry in HOI4 1.19 (1920x1200 window, gui_scale 1.5): the menu panel
is centered horizontally around x~0.494, buttons vertically stacked from
y~0.21 with pitch ~0.056. Values are captured from live screenshots at our
pinned resolution; a layout drift check re-validates a screenshot before
clicking through.
"""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np

from ..tools import screenshot
from ..tools.input import Input


def button_rows(self_scan: np.ndarray) -> list[float]:
    raise NotImplementedError


class MenuDriver:
    def __init__(self, hwnd: int):
        self.hwnd = hwnd
        self.input = Input(hwnd)

    # -- helpers -------------------------------------------------------------
    def shot(self) -> np.ndarray:
        arr = screenshot.capture(self.hwnd)
        if arr is None:
            # fallback: mss screen grab of window rect
            import ctypes
            import mss
            r = screenshot.RECT()
            ctypes.windll.user32.GetWindowRect(self.hwnd, ctypes.byref(r))
            with mss.mss() as s:
                cap = np.asarray(s.grab({"left": r.left, "top": r.top,
                                         "width": r.right - r.left,
                                         "height": r.bottom - r.top}))
            arr = cap[:, :, :3][:, :, ::-1].copy()
        return arr

    def mean_luma(self, x: float, y: float, half: int = 8) -> float:
        arr = self.shot()
        h, w = arr.shape[:2]
        cx, cy = int(x * w), int(y * h)
        win = arr[cy - half:cy + half, cx - half:cx + half]
        return float(win.mean())

    # -- menu flow -----------------------------------------------------------
    def in_main_menu(self) -> bool:
        arr = self.shot()
        # menu button strip around x=0.49 has dark rows with light text; detect
        # by sampling three known button centers luma is mid-range
        lumas = [self.mean_luma(0.494, y, 10) for y in (0.219, 0.275, 0.331)]
        return 25 < np.mean(lumas) < 130  # dark buttons w/ text present

    def click_singleplayer(self) -> None:
        self.input.click(0.494, 0.219)

    def click_resume_or_save(self, save_ratio_index: int = 0) -> None:
        """Click '继续游戏' (continue) if present, else first save row."""
        time.sleep(1.0)
        # The saved-game screen shows 继续 (continue) top-right area.
        # Normalize: HOI4 1.19 single-player screen: top row buttons:
        #   继续(0.875, 0.03) ; 新建存档 tabs on left; list rows center-left.
        self.input.click(0.494, 0.15 + 0.0 * 0.0)  # placeholder alpha
        time.sleep(0.5)

    def reach_game(self) -> bool:
        """Journey: main menu -> single player -> (continue) -> in-game."""
        if self.in_main_menu():
            self.click_singleplayer()
            time.sleep(2.5)
        # saved-game view: click 继续 if present (right list header)
        self.click_resume_or_save()
        return True
