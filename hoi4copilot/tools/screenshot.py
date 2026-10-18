"""Focus-steal-free screenshots of the HOI4 window via PrintWindow (GDI).

Works for most D3D games when the target window is interactive; returns a
(BGR) ndarray or writes a PNG for template-building/vision tools.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time
from pathlib import Path

import numpy as np

_g32 = ctypes.WinDLL("user32", use_last_error=True)

# Align this process with physical pixels: without DPI awareness GetWindowRect
# returns scaled/logical coords on scaled displays and the mss fallback grabs a
# REGION SHIFTED off the window (observed: foreign windows bleeding into grabs).
try:
    _g32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2, Win10+
except AttributeError:
    ctypes.windll.user32.SetProcessDPIAware()

PW_CLIENTONLY = 0x1
PW_RENDERFULLCONTENT = 0x2  # captures DWM-flipped content (works on D3D games)


class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


_g32.PrintWindow.argtypes = [wt.HWND, ctypes.c_void_p, ctypes.c_uint]
_g32.GetClientRect.argtypes = [wt.HWND, ctypes.POINTER(RECT)]
_g32.SetForegroundWindow.argtypes = [wt.HWND]
_g32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
_g32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_int, ctypes.c_uint]
_g32.IsWindowVisible.argtypes = [wt.HWND]
_g32.IsWindowVisible.restype = ctypes.c_long
SW_RESTORE = 9


def focus_window(hwnd: int) -> None:
    """Bring the game window to the front so clicks/screenshots hit the game."""
    if _g32.IsIconic(hwnd):
        _g32.ShowWindow(hwnd, SW_RESTORE)
        time.sleep(0.2)
    ok = _g32.SetForegroundWindow(hwnd)
    if not ok:
        # ALT-key nudge fallback for strict foreground lock
        _g32.keybd_event(0x12, 0, 0, 0)      # ALT down
        _g32.SetForegroundWindow(hwnd)
        _g32.keybd_event(0x12, 0, 2, 0)      # ALT up
    time.sleep(0.35)


def find_hoi4_hwnd(pid: int) -> int:
    """Return the top-level window HWND belonging to pid (argest area)."""
    results: list = []

    @ctypes.WINFUNCTYPE(ctypes.c_int, wt.HWND, wt.LPARAM)
    def cb(hwnd, _lparam):
        pid_word = ctypes.c_ulong()
        _g32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_word))
        if pid_word.value == pid and _g32.IsWindowVisible(hwnd):
            results.append(hwnd)
        return 1

    _g32.EnumWindows(cb, 0)
    if not results:
        return 0
    # pick largest
    best, best_area = 0, -1
    for hwnd in results:
        r = RECT()
        _g32.GetWindowRect(hwnd, ctypes.byref(r))
        area = (r.right - r.left) * (r.bottom - r.top)
        if area > best_area:
            best, best_area = hwnd, area
    return best


def ensure_onscreen(hwnd: int) -> str:
    """Reposition the window (size/SCROLL unchanged) so it fully sits inside
    the virtual desktop. OS-level window management, no game state touched:
    with part of the client off-screen the mss screen grab shows black there
    and clicks in that zone land on no monitor — both coordinate systems
    (capture and input) silently break. Returns a short action note."""
    wx, wy, wcx, wcy = 0, 0, 0, 0
    wr = RECT()
    if not _g32.GetWindowRect(hwnd, ctypes.byref(wr)):
        return "no-rect"
    u32 = ctypes.windll.user32
    vs_l, vs_t = u32.GetSystemMetrics(76), u32.GetSystemMetrics(77)
    vs_r = vs_l + u32.GetSystemMetrics(78)
    vs_b = vs_t + u32.GetSystemMetrics(79)
    over_r = max(0, wr.right - vs_r)
    over_b = max(0, wr.bottom - vs_b)
    over_l = max(0, vs_l - wr.left)
    over_t = max(0, vs_t - wr.top)
    if not (over_r or over_b or over_l or over_t):
        return "onscreen"
    nx = wr.left - over_r + over_l
    ny = wr.top - over_b + over_t
    SWP_NOSIZE, SWP_NOZORDER, SWP_NOACTIVATE = 0x1, 0x4, 0x10
    u32.SetWindowPos(hwnd, 0, nx, ny, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE)
    time.sleep(0.3)
    return (f"moved ({wr.left},{wr.top})->({nx},{ny}) "
            f"over_r={over_r} over_b={over_b}")


def capture(hwnd: int) -> np.ndarray | None:
    """Capture client area of hwnd -> np.uint8 BGR (h, w, 3) or None."""
    r = RECT()
    if not _g32.GetClientRect(hwnd, ctypes.byref(r)):
        return None
    w, h = r.right - r.left, r.bottom - r.top
    if w <= 0 or h <= 0:
        return None
    hdc_window = _g32.GetWindowDC(hwnd)
    if not hdc_window:
        return None
    from ctypes import wintypes as wt2
    g32 = ctypes.windll.gdi32
    hdc_mem = g32.CreateCompatibleDC(hdc_window)
    hbm = g32.CreateCompatibleBitmap(hdc_window, w, h)
    g32.SelectObject(hdc_mem, hbm)
    ok = _g32.PrintWindow(hwnd, hdc_mem, PW_CLIENTONLY | PW_RENDERFULLCONTENT)
    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
                    ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
                    ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
                    ("biSizeImage", ctypes.c_uint32)]
    class BITMAPINFO(ctypes.Structure):
        _fields_ = [("bmiHeader", BITMAPINFOHEADER)]
    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h  # top-down
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 24
    bmi.bmiHeader.biCompression = 0
    buf = (ctypes.c_char * (w * h * 3))()
    got = g32.GetDIBits(hdc_mem, hbm, 0, h, buf, ctypes.byref(bmi), 0)
    if got == 0 and not ok:
        return None
    arr = np.frombuffer(buf, dtype=np.uint8).reshape(h, w, 3)[:, :, ::-1].copy()
    g32.DeleteObject(hbm)
    g32.DeleteDC(hdc_mem)
    _g32.ReleaseDC(hwnd, hdc_window)
    return arr


def capture_pid(pid: int):
    hwnd = find_hoi4_hwnd(pid)
    if not hwnd:
        return None
    return capture(hwnd)


def capture_smart(pid: int) -> np.ndarray | None:
    """PrintWindow first; on blank output fall back to mss screen grab of the window rect."""
    hwnd = find_hoi4_hwnd(pid)
    if not hwnd:
        return None
    arr = capture(hwnd)
    if arr is not None and arr.size and arr.mean() > 1.0 and arr.std() > 1.0:
        return arr
    # fallback grab must match the capture/click frame: CLIENT rect on screen
    r = RECT()
    _g32.GetClientRect(hwnd, ctypes.byref(r))
    pt = wt.POINT(0, 0)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
    grab = RECT()
    grab.left = pt.x
    grab.top = pt.y
    grab.right = pt.x + (r.right - r.left)
    grab.bottom = pt.y + (r.bottom - r.top)
    with _topmost(hwnd):
        cap = _mss_grab(grab)
    return cap


def _mss_grab(r: RECT) -> np.ndarray | None:
    import mss
    with mss.mss() as s:
        cap = np.asarray(s.grab({"left": r.left, "top": r.top,
                                 "width": r.right - r.left,
                                 "height": r.bottom - r.top}))
    return cap[:, :, :3][:, :, ::-1].copy()


class _topmost:
    """Temporarily raise the window above all others WITHOUT stealing focus.

    PrintWindow renders black for the game's D3D swapchain, so screen grabbing
    is the only working capture; other windows covering the game rect would
    pollute it, so we lift the game first. SWP_NOACTIVATE keeps keyboard focus
    untouched.
    """

    HWND_TOPMOST = -1
    HWND_NOTOPMOST = -2
    SWP_NOMOVE = 0x2
    SWP_NOSIZE = 0x1
    SWP_NOACTIVATE = 0x10

    def __init__(self, hwnd: int):
        self.hwnd = hwnd

    def __enter__(self):
        _g32.SetWindowPos(self.hwnd, self.HWND_TOPMOST, 0, 0, 0, 0,
                          self.SWP_NOMOVE | self.SWP_NOSIZE | self.SWP_NOACTIVATE)
        time.sleep(0.25)  # let DWM recompose
        return self

    def __exit__(self, *exc):
        _g32.SetWindowPos(self.hwnd, self.HWND_NOTOPMOST, 0, 0, 0, 0,
                          self.SWP_NOMOVE | self.SWP_NOSIZE | self.SWP_NOACTIVATE)
        return False


def save_png(arr: np.ndarray, path: Path) -> None:
    """Minimal PNG writer (RGB, 8-bit) without extra dependencies."""
    import struct
    import zlib

    h, w, _ = arr.shape
    rgb = arr[:, :, ::-1]
    raw = b"".join(b"\x00" + rgb[y].tobytes() for y in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def load_png(path: Path) -> np.ndarray | None:
    """Reader for PNGs this module (or equivalents) wrote: 8-bit truecolor,
    one IDAT zlib stream of per-row BGR scanlines — the save_png layout.
    Returns RGB ndarray or None on anything it cannot parse."""
    import struct
    import zlib

    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    w = h = None
    idat = b""
    while pos + 8 <= len(data):
        ln = struct.unpack_from(">I", data, pos)[0]
        tag = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + ln]
        if tag == b"IHDR":
            w, h, depth, ctype = struct.unpack_from(">IIBB", chunk, 0)
            if depth != 8 or ctype != 2:
                return None
        elif tag == b"IDAT":
            idat += chunk
        elif tag == b"IEND":
            break
        pos += 12 + ln
    if not w or not h or not idat:
        return None
    raw = zlib.decompress(idat)
    stride = w * 3 + 1
    rows = [raw[y * stride + 1:(y + 1) * stride] for y in range(h)]
    arr = np.frombuffer(b"".join(rows), dtype=np.uint8).reshape(h, w, 3)
    # file scanlines are BGR (save_png flips RGB->BGR on the way out);
    # flip back so the return matches capture()'s RGB convention
    return arr[:, :, ::-1].copy()
