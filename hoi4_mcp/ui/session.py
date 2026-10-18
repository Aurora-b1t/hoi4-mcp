"""In-session vehicle: click-equivalent controls over the running HOI4 client.

Coordinates are client-normalized (0..1) captured at this pinned resolution
(windowed 1295x837 logical / 1942x1256 physical, DPI 150%). The date panel:
speed-down (0.758, 0.059), pause/resume (0.775, 0.059), speed-up (0.898, 0.059).
"""

from __future__ import annotations

import time
from pathlib import Path

from ..process.attach import Game
from ..tools import screenshot as shot
from ..tools.input import Input

# date-panel geometry (normalized CLIENT coords; re-calibrated 16日 after the
# click-mapping was switched from window-rect to client-rect: the y values
# moved from 0.059 to 0.024, x unchanged)
BTN_SPEED_DOWN = (0.759, 0.024)
BTN_PAUSE = (0.776, 0.024)
BTN_SPEED_UP = (0.897, 0.024)
MENU_ICON = (0.978, 0.024)      # hamburger menu, top-right (client-frame)
MENU_CLOSE = (0.502, 0.660)     # 主菜单自带的『关闭』按钮 (外点关不掉它)
OUTSIDE_CLICK = (0.030, 0.900)  # 大西洋深水区: 关"外点可关"面板, 不会选师

# load-save flow (18日 live re-calibrated on the in-session 载入对话框:
# full-screen modal, list x≈0.385-0.625, 6 rows fully visible)
MENU_LOAD = (0.502, 0.257)      # 游戏内 ☰ 菜单的『载入』行
MAINMENU_SINGLE = (0.498, 0.196)  # 主菜单: 单人游戏
MAINMENU_LOAD = (0.498, 0.387)    # 主菜单: 载入游戏
LOAD_ROW0 = (0.45, 0.382)       # 列表首行中心 (17日表的 0.115,0.393 系误测)
LOAD_ROW_PITCH = 0.066
LOAD_START = (0.567, 0.810)     # 『载入游戏』按钮 (与存档框『保存』同位)
LOAD_BACK = (0.449, 0.810)      # 『返回』
LOAD_MAX_ROWS = 6               # 不做滚动; 更老的档让玩家/agent 手动滚


class SessionDriver:
    def __init__(self, game: Game | None = None):
        self.game = game or Game()
        self.pid = self.game.proc.pid
        self.hwnd = shot.find_hoi4_hwnd(self.pid)
        if not self.hwnd:
            raise RuntimeError("hoi4 window not found")
        moved = shot.ensure_onscreen(self.hwnd)
        if moved != "onscreen":
            self._moved_note = moved  # evidence for the operator
        self.input = Input(self.hwnd)

    # -- primitives -----------------------------------------------------------
    def shot(self, path: Path | None = None):
        if path is not None:
            return shot.capture_smart(self.pid), path
        return shot.capture_smart(self.pid)

    def save_shot(self, dir_: Path, tag: str) -> Path:
        arr = shot.capture_smart(self.pid)
        p = dir_ / f"{tag}.png"
        shot.save_png(arr, p)
        return p

    def click(self, n, dy=0.0, focus: bool = False) -> None:
        """One player-equivalent click. `focus=True` first raises the game
        window: SendInput goes to whatever is in the foreground, and Windows
        swallows the click that activates a background window — the 24 日 save
        chain failed exactly that way (its first click never reached the menu)."""
        if focus:
            shot.focus_window(self.hwnd)
        x, y = n
        self.input.click(x, y + dy)
        time.sleep(0.8)

    # -- state ---------------------------------------------------------------
    DATE_REGION = (0.787, 0.010, 0.885, 0.036)  # digits only (stops above the
    # flashing alert-icon row at y>=0.036 that never stops animating)
    ICON_CENTER = (0.773, 0.022)   # ‖/▶ state glyph (right of speed-down btn)

    def _icon_patch(self) -> "np.ndarray | None":
        import numpy as np
        arr = shot.capture_smart(self.pid)
        if arr is None:
            return None
        h, w = arr.shape[:2]
        cx, cy = self.ICON_CENTER
        px, py = int(cx * w), int(cy * h)
        p = arr[py - 14:py + 14, px - 20:px + 20].astype(np.int16)
        return p

    def icon_state(self) -> str | None:
        """Classify the pause/resume GLYPH: ‖ (paused) vs ▶ (running).

        The date-panel digits strip gets occupied by transient animated
        banners (observed 19 日: a striped toast slides behind the clock and
        animates even while PAUSED), so pixel-diff voting over the panel is
        unreliable as a primary detector. The state glyph is static per
        state and cleanly separable: column profile of bright pixels shows
        TWO separated bars (‖) vs ONE contiguous tapering wedge (▶).
        Returns 'paused' | 'running' | None (undecidable crop/layout).
        """
        import numpy as np
        p1 = self._icon_patch()
        time.sleep(0.6)
        p2 = self._icon_patch()
        votes = []
        for p in (p1, p2):
            if p is None or p.size == 0:
                return None
            luma = p.mean(axis=2)
            thr = luma > luma.mean() + 12
            cols = thr.sum(axis=0)
            # drop left neighbor-button decoration (identical across states)
            cols = cols[12:]
            runs, cur = [], 0
            for c in cols:
                if c > 0:
                    cur += 1
                else:
                    if cur:
                        runs.append((cur, len(runs)))
                    cur = 0
            if cur:
                runs.append((cur, len(runs)))
            runs = [(w, i) for (w, i) in runs if w >= 3]  # bar/wedge length >=3
            if len(runs) == 2 and all(r[0] <= 6 for r in runs):
                votes.append("paused")       # two short bar islands (‖)
            elif len(runs) == 1 and runs[0][0] >= 9:
                votes.append("running")      # one long tapered wedge (▶)
            else:
                votes.append(None)
        clean = [v for v in votes if v is not None]   # one transient may hide
        if clean and clean.count(clean[0]) == len(clean):
            return clean[0]                  # every decidable capture agrees
        return None

    def is_running(self, verbose: bool = False):
        """Game running? Primary: state glyph classifier; the clock-strip
        pixel vote is supporting evidence only — banner animations
        repeatedly fooled the vote (17-19 日 实证)."""
        st = self.icon_state()
        if verbose:
            verd = {"paused": "paused", "running": "running",
                    None: "unknown"}[st]
            return f"{verd} (icon={st or 'undecidable'}; {self.cast_timevote()})"
        return {"paused": False, "running": True, None: None}[st]

    def cast_timevote(self) -> str:
        """Legacy clock-strip vote, kept as evidence text (not authoritative)."""
        import numpy as np

        def region():
            arr = shot.capture_smart(self.pid)
            h, w = arr.shape[:2]
            x0, y0, x1, y1 = self.DATE_REGION
            return arr[int(y0 * h):int(y1 * h), int(x0 * w):int(x1 * w)].astype(np.int16)

        frames = []
        for _ in range(6):
            frames.append(region())
            time.sleep(0.9)
        diffs = [float(np.abs(b - a).mean())
                 for a, b in zip(frames[:-1], frames[1:]) if a.shape == b.shape]
        moved = sum(d > 2.0 for d in diffs)
        return ("votes=[" + " ".join(f"{d:.2f}" for d in diffs) + "] "
                f"moved={moved} of {len(diffs)}")

    def state(self) -> str:
        r = self.is_running()
        return "running" if r else ("paused" if r is False else "unknown")

    def cast_diffs(self) -> str:
        """Human-readable evidence string: icon classification + strip vote."""
        icon = self.icon_state()
        return f"icon={icon or 'undecidable'}; {self.cast_timevote()}"

    # -- controls ---------------------------------------------------------------
    def pause_toggle(self) -> None:
        self.click(BTN_PAUSE)

    def floor_speed(self) -> None:
        """Click speed-down 8x: guarantees lowest speed regardless of current."""
        for _ in range(8):
            self.click(BTN_SPEED_DOWN)

    def set_speed(self, n: int) -> None:
        """Set game speed 1..5 by flooring then boosting."""
        self.floor_speed()
        for _ in range(max(0, min(4, n - 1))):
            self.click(BTN_SPEED_UP)

    # -- menu -----------------------------------------------------------------
    def open_menu(self) -> None:
        self.click(MENU_ICON, focus=True)

    def menu_change_score(self) -> float:
        """Mean-abs pixel change over the main-menu modal area between two
        captures — big when the menu was open and got closed by a click."""
        import numpy as np
        arr1 = shot.capture_smart(self.pid)
        self.click(MENU_CLOSE)
        arr2 = shot.capture_smart(self.pid)
        if arr1 is None or arr2 is None:
            return -1.0
        h = min(arr1.shape[0], arr2.shape[0])
        w = min(arr1.shape[1], arr2.shape[1])
        r = np.abs(arr1[:h, :w].astype(np.int16) - arr2[:h, :w].astype(np.int16))
        area = r[int(0.24 * h):int(0.76 * h), int(0.38 * w):int(0.62 * w)]
        return round(float(area.mean()), 2)

    def menu_close(self) -> str:
        self.click(MENU_CLOSE)
        score = self.menu_change_score()
        return f"menu_close: post-click re-diff={score} (>6 means it changed again -> still/again open)"

    def click_outside(self, xy=None) -> None:
        """Click a safely-empty map spot — closes OUTSIDE-closable modals
        (e.g. 紧张度世界紧张度面板), does NOT close the main menu."""
        self.click(xy or OUTSIDE_CLICK)

    # -- load save -------------------------------------------------------------
    @staticmethod
    def _area_diff(arr1, arr2, x0, y0, x1, y1) -> float:
        import numpy as np
        if arr1 is None or arr2 is None:
            return -1.0
        h = min(arr1.shape[0], arr2.shape[0])
        w = min(arr1.shape[1], arr2.shape[1])
        r = np.abs(arr1[:h, :w].astype(np.int16) -
                   arr2[:h, :w].astype(np.int16))
        a = r[int(y0 * h):int(y1 * h), int(x0 * w):int(x1 * w)]
        return round(float(a.mean()), 2)

    def open_menu_verified(self) -> bool:
        """Click ☰ and verify a menu modal actually opened via pixel diff of
        the modal region; False means we're likely at the MAIN menu (no ☰)."""
        arr1 = shot.capture_smart(self.pid)
        self.click(MENU_ICON)
        arr2 = shot.capture_smart(self.pid)
        return self._area_diff(arr1, arr2, 0.38, 0.20, 0.62, 0.72) > 6

    def load_save(self, row: int, confirm: bool = True,
                  wait_s: float = 30.0) -> dict:
        """Navigate to the load dialog and pick save list row `row` (0-based;
        list assumed newest-first). confirm=False stops after selecting the
        row so the caller can verify the highlighted row + detail pane
        screenshot first. Returns evidence screenshot paths at each step."""
        out = {"steps": [], "row": row}
        if not 0 <= row < LOAD_MAX_ROWS:
            out["error"] = (f"row {row} outside visible list "
                            f"(0..{LOAD_MAX_ROWS - 1}); no scrolling — load a "
                            f"more recent save or click the list manually")
            return out
        opened = self.open_menu_verified()
        out["steps"].append(f"menu_open={opened}")
        if opened:
            self.click(MENU_LOAD)           # 游戏内菜单: 载入
            out["steps"].append("menu→载入")
        else:
            self.click(MAINMENU_SINGLE)     # 主菜单: 单人游戏 → 载入游戏
            time.sleep(1.5)
            self.click(MAINMENU_LOAD)
            out["steps"].append("mainmenu→单人→载入")
        time.sleep(1.5)
        out["dialog"] = self._ev_shot("load_dialog")
        y = LOAD_ROW0[1] + LOAD_ROW_PITCH * row
        self.input.click(LOAD_ROW0[0], y)
        time.sleep(1.0)
        out["selected"] = self._ev_shot("load_selected")
        if not confirm:
            out["note"] = ("selection only; check 'selected' shows the right "
                           "save, then call again with confirm=true")
            return out
        self.input.click(*LOAD_START)
        # loading screen → session; give it time to settle before evidence
        deadline = time.time() + wait_s
        while time.time() < deadline:
            time.sleep(3.0)
        out["after_load"] = self._ev_shot("after_load")
        out["steps"].append(f"开始 clicked; waited {wait_s:.0f}s")
        return out

    def _ev_shot(self, tag: str) -> str | None:
        arr = shot.capture_smart(self.pid)
        if arr is None:
            return None
        d = Path.home() / ".hoi4_mcp" / "shots"
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{tag}_{int(time.time() * 1000) % 10**10}.png"
        shot.save_png(arr, p)
        return str(p)
