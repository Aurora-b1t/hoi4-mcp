"""Session-safety guard: single-player enforcement evidence (19 日).

Three independent evidence sources for "is this a multiplayer session";
the write layer locks on any hard MP evidence (conservative by design):

1. `logs/game.log` tail — the game itself prints
   ``[[ Launching MULTIPLAYER-game ]]`` vs ``[[ Launching SINGLEPLAYER-game ]]``
   on every session start (frontend.cpp). Live, authoritative, nearly free.
2. Open TCP sockets owned by the hoi4.exe PID — an MP session holds live
   peer/server connections; the SP sessions observed so far hold zero.
   Reported as evidence only (no lock by itself: exotic SP-side telemetry
   could keep a socket).
3. Save token `multiplayer` (id 0x3E74) — MP saves carry a truthy key;
   every local SP save so far (33/33, v1.18–v1.19.3) lacks it entirely.

Useful side discovery that motivated this module: the game writes
CCommandQueue per-channel logs (`posted/sent/received/executed_commands.log`)
in the same logs dir — breadcrumbs for the future Post-injection work.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .saveparse import bin5

T_MULTIPLAYER = 0x3E74

SP_MARK = "Launching SINGLEPLAYER-game"
MP_MARK = "Launching MULTIPLAYER-game"


@dataclass
class GuardReport:
    log_launch: str | None = None      # "singleplayer" | "multiplayer" | None
    log_tail_ts: str | None = None     # [hh:mm:ss] of the Launching line
    tcp_open: int | None = None        # sockets owned by the game PID
    save_flag: bool | None = None      # multiplayer token truthy in a save
    save_name: str | None = None
    verdict: str = "unknown"           # "singleplayer" | "multiplayer" | "unknown"
    reasons: list[str] = field(default_factory=list)

    def as_line(self) -> str:
        bits = [f"log={self.log_launch}", f"tcp_open={self.tcp_open}",
                f"save_flag={self.save_flag}", f"verdict={self.verdict}"]
        return " ".join(bits)


def log_launch_marker() -> tuple[str | None, str | None]:
    """Scan the tail of game.log for the most recent Launching marker."""
    path = config.DOCS_ROOT / "logs" / "game.log"
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 131072))
            tail = f.read().decode("utf-8", "replace")
    except OSError:
        return None, None
    mp, sp = tail.rfind(MP_MARK), tail.rfind(SP_MARK)
    idx = max(mp, sp)
    if idx < 0:
        return None, None
    ts = None
    # the line starts with "[hh:mm:ss]"; walk back to it
    line_start = tail.rfind("\n", 0, idx) + 1
    line = tail[line_start:tail.find("\n", line_start) if
                tail.find("\n", line_start) > 0 else len(tail)]
    if line.startswith("[") and "]" in line:
        ts = line[1:line.index("]")]
    return ("multiplayer" if mp > sp else "singleplayer"), ts


def tcp_open_for_pid(pid: int) -> int:
    """Count TCP connections owned by `pid` (GetExtendedTcpTable, no shell)."""
    u32 = ctypes.windll.iphlpapi
    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    MIB_TCPROW_OWNER_PID_FIELDS = (
        ("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD), ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    )

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = MIB_TCPROW_OWNER_PID_FIELDS

    class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
        _fields_ = [("dwNumEntries", wt.DWORD),
                    ("table", MIB_TCPROW_OWNER_PID * 0)]

    size = wt.DWORD(0)
    u32.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0)
    if size.value == 0:
        return 0
    buf = (ctypes.c_byte * size.value)()
    if u32.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                               TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return -1  # call failed: report sentinel rather than "no sockets"
    tab = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    n = tab.dwNumEntries
    rows = ctypes.cast(ctypes.byref(buf, 4),  # skip dwNumEntries header
                       ctypes.POINTER(MIB_TCPROW_OWNER_PID * max(n, 1))).contents
    count = 0
    for i in range(n):
        if rows[i].dwOwningPid == pid:
            state = rows[i].dwState
            # count established/listening-ish states (skip TIME_WAIT 4/CLOSE 11)
            if state not in (4, 11):
                count += 1
    return count


def save_mp_flag(path: str | Path, deep: bool = False) -> bool | None:
    """True if a truthy `multiplayer` key serializes in the save.

    Byte-scan for (T id, EQUAL) pairs, then validate by parsing a window; a
    padded false value or an unrelated payload hit is therefore noise-proof.
    deep=False keeps the scan to the first 2 MiB (MP keys sit in the header
    region in Jomini saves); deep=True scans the whole file (~13 s pass).
    """
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if deep:
        data = data
    else:
        data = data[:2 * 1024 * 1024]
    pat = struct.pack("<HH", T_MULTIPLAYER, bin5.EQUAL)
    idx = data.find(pat)
    while idx >= 0:
        try:
            r = bin5.Reader(data, idx)
            key = r.u16()          # T_MULTIPLAYER
            r.u16()                # EQUAL
            val = bin5._value(r)
            if val is True:
                return True
            if val is False or val == ("id", 0):  # malformed-but-there
                return False
        except Exception:
            pass  # window parse failure -> keep scanning at idx+1
        idx = data.find(pat, idx + 1)
    return False


def guard(pid: int | None = None, save_path: str | Path | None = None) -> GuardReport:
    """Gather the evidence bundle; hard-MP evidence wins, else unknown."""
    rep = GuardReport()
    rep.log_launch, rep.log_tail_ts = log_launch_marker()
    rep.tcp_open = tcp_open_for_pid(pid) if pid else None
    if save_path is not None:
        rep.save_name = Path(save_path).name
        rep.save_flag = save_mp_flag(save_path)
    if rep.log_launch == "multiplayer" or rep.save_flag is True:
        rep.verdict = "multiplayer"
    elif rep.log_launch == "singleplayer" and (rep.save_flag is False
                                               or rep.save_flag is None):
        rep.verdict = "singleplayer"
    reasons = []
    if rep.log_launch == "multiplayer":
        reasons.append(f"game.log: {MP_MARK} @ {rep.log_tail_ts}")
    if rep.save_flag is True:
        reasons.append(f"save {rep.save_name}: multiplayer=yes")
    rep.reasons = reasons
    return rep
