"""SendInput-based mouse/keyboard control (real input, player-equivalent).

The game reads raw input, so PostMessage clicks are ignored; we send real
input events. Coordinates are window-relative (0..1) and mapped onto the
virtual desktop's absolute space for SendInput.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time

from . import screenshot as _shot

_u32 = ctypes.windll.user32

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_ABSOLUTE = 0x8000

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
                ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]


class INPUTUNION(ctypes.Union):
    _anonymous_ = ("mi", "ki")
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", INPUTUNION)]


_u32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]


def _game_window_rect(hwnd: int) -> tuple[int, int, int, int]:
    """CLIENT rect in absolute screen coords.

    Captures are client-based (PrintWindow PW_CLIENTONLY / client-rect mss),
    so clicks must be normalized against the SAME frame; otherwise every
    coordinate carries the title-bar/border offset."""
    r = _shot.RECT()
    if not _u32.GetClientRect(hwnd, ctypes.byref(r)):
        return 0, 0, 0, 0
    pt = wt.POINT(0, 0)
    _u32.ClientToScreen(hwnd, ctypes.byref(pt))
    return (pt.x, pt.y, pt.x + (r.right - r.left), pt.y + (r.bottom - r.top))


class Input:
    """Mouse+keyboard driver bound to the game's window rect."""

    def __init__(self, hwnd: int):
        self.hwnd = hwnd

    def _abs(self, x: float, y: float) -> tuple[int, int]:
        """Window-relative (0..1) -> SendInput absolute desktop coords."""
        l, t, r, b = _game_window_rect(self.hwnd)
        px = l + min(max(x, 0.0), 1.0) * (r - l)
        py = t + min(max(y, 0.0), 1.0) * (b - t)
        vx = _u32.GetSystemMetrics(SM_XVIRTUALSCREEN)
        vy = _u32.GetSystemMetrics(SM_YVIRTUALSCREEN)
        vw = _u32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
        vh = _u32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
        nx = int(round((px - vx) / max(1, vw) * 65535))
        ny = int(round((py - vy) / max(1, vh) * 65535))
        return nx, ny

    def _send_mouse(self, flags: int, x: float | None = None, y: float | None = None,
                    wheel: int = 0) -> None:
        inp = INPUT()
        inp.type = INPUT_MOUSE
        mi = inp.u.mi
        mi.dwFlags = flags
        if wheel:
            mi.mouseData = wheel & 0xFFFFFFFF
        if x is not None and y is not None:
            mi.dx, mi.dy = self._abs(x, y)
            mi.dwFlags |= MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE
        _u32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))

    # -- mouse ---------------------------------------------------------------
    def move(self, x: float, y: float) -> None:
        self._send_mouse(MOUSEEVENTF_MOVE, x, y)

    def click(self, x: float, y: float, hold: float = 0.03) -> None:
        self.move(x, y)
        time.sleep(0.06)
        self._send_mouse(MOUSEEVENTF_LEFTDOWN)
        time.sleep(hold)
        self._send_mouse(MOUSEEVENTF_LEFTUP)

    def right_click(self, x: float, y: float, hold: float = 0.03) -> None:
        self.move(x, y)
        time.sleep(0.06)
        self._send_mouse(MOUSEEVENTF_RIGHTDOWN)
        time.sleep(hold)
        self._send_mouse(MOUSEEVENTF_RIGHTUP)

    def drag(self, x0: float, y0: float, x1: float, y1: float, steps: int = 12) -> None:
        self.move(x0, y0)
        time.sleep(0.05)
        self._send_mouse(MOUSEEVENTF_LEFTDOWN)
        time.sleep(0.05)
        for i in range(1, steps + 1):
            self.move(x0 + (x1 - x0) * i / steps, y0 + (y1 - y0) * i / steps)
            time.sleep(0.012)
        time.sleep(0.05)
        self._send_mouse(MOUSEEVENTF_LEFTUP)

    def wheel(self, x: float, y: float, delta: int) -> None:
        self.move(x, y)
        time.sleep(0.03)
        self._send_mouse(MOUSEEVENTF_WHEEL, x, y, wheel=delta)

    # -- keyboard ------------------------------------------------------------
    def key(self, vk: int, hold: float = 0.03) -> None:
        down = INPUT(); down.type = INPUT_KEYBOARD
        down.u.ki.wVk = vk
        up = INPUT(); up.type = INPUT_KEYBOARD
        up.u.ki.wVk = vk
        up.u.ki.dwFlags = 2  # KEYEVENTF_KEYUP
        _u32.SendInput(1, ctypes.byref(down), ctypes.sizeof(INPUT))
        time.sleep(hold)
        _u32.SendInput(1, ctypes.byref(up), ctypes.sizeof(INPUT))
