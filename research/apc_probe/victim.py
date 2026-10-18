"""Disposable victim for the day-23 write-primitive matrix.

Two threads with the two properties that matter for injection:
  * main      — heartbeats a JSON state file (liveness / APC-completion counter)
  * alertable — parked in WaitForSingleObjectEx(..., TRUE) = a REAL alertable
                wait (the classic QueueUserAPC delivery point)
  * busy      — hot pure-user-code loop, never alertable (the SetThreadContext
                graft case; also the target for QueueUserAPC2 special APCs)

A CANARY ctypes field gives a known data address to prove that plain
WriteProcessMemory still works (baseline) and to host a "did code run" flag
without touching anything the victim needs.

Usage: python victim.py <state_dir>
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import time

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateEventW.restype = ctypes.c_void_p
_k32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
_k32.WaitForSingleObjectEx.restype = ctypes.c_uint32
_k32.WaitForSingleObjectEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int]
_k32.GetCurrentThreadId.restype = ctypes.c_uint32

WAIT_IO_COMPLETION = 0xC0   # 192: an APC ran during our alertable wait
WAIT_TIMEOUT = 0x102

CANARY = ctypes.c_uint64(0x1111111111111111)

S = {
    "pid": os.getpid(),
    "ppid": os.getppid(),
    "tids": {},
    "alertable_waits": 0,
    "apc_completions": 0,
    "busy": 0,
    "canary_addr": ctypes.addressof(CANARY),
    "alive": True,
}
_EVT = _k32.CreateEventW(None, 0, 0, None)


def _alertable() -> None:
    S["tids"]["alertable"] = _k32.GetCurrentThreadId()
    while S["alive"]:
        rc = _k32.WaitForSingleObjectEx(ctypes.c_void_p(_EVT), 100, 1)
        if rc == WAIT_IO_COMPLETION:
            S["apc_completions"] += 1
        elif rc == WAIT_TIMEOUT:
            S["alertable_waits"] += 1


def _busy() -> None:
    S["tids"]["busy"] = _k32.GetCurrentThreadId()
    x = 0
    while S["alive"]:
        x += 1
        S["busy"] = x


def main() -> None:
    state_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(state_dir, exist_ok=True)
    threading.Thread(target=_alertable, daemon=True).start()
    threading.Thread(target=_busy, daemon=True).start()
    S["tids"]["main"] = _k32.GetCurrentThreadId()
    path = os.path.join(state_dir, f"{os.getpid()}.json")
    while True:
        S["ticks"] = S.get("ticks", 0) + 1
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(S, f)
        os.replace(tmp, path)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
