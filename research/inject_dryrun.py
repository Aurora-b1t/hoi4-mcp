"""Dry-run the hijack protocol on a harmless local python victim.

Remote-calls kernel32!GetTickCount / GetCurrentProcessId in a spawned python
process; any crash here costs nothing. Validates: arena, shellcode, suspend-
all, main-thread hijack, done-flag poll, context restore, resume.
"""
from __future__ import annotations

import ctypes
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import AttachedProcess
from hoi4_mcp.inject.call import RemoteCaller

# main thread must be frozen in USER code (hijacking a kernel-wait thread is
# unsafe — see inject/call.py); a busy loop guarantees that.
VICTIM_SRC = "while True:\n    pass\n"


def main():
    victim = subprocess.Popen([sys.executable, "-c", VICTIM_SRC])
    time.sleep(1.0)
    print(f"victim pid={victim.pid}")
    try:
        proc = AttachedProcess(victim.pid)
        print(f"attached: base={proc.base:#x} size={proc.image_size:#x}")

        # kernel32 base is shared per-boot across processes; resolve locally.
        # NOTE: restype must be c_void_p — the default c_int truncates 64-bit
        # module handles (the exact bug that fed the first dry run a garbage
        # function address).
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetModuleHandleW.restype = ctypes.c_void_p
        k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        k32.GetProcAddress.restype = ctypes.c_void_p
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        base_k32 = k32.GetModuleHandleW("kernel32.dll")
        print(f"kernel32 base = {base_k32:#x}")

        rc = RemoteCaller(proc, timeout=8.0,
                          allow_module_patterns=("python3",))
        for name, expect in (("GetTickCount", None), ("GetCurrentProcessId", victim.pid)):
            addr = k32.GetProcAddress(base_k32, name.encode())
            if not addr:
                print(f"  {name}: resolve failed")
                continue
            t0 = time.time()
            r = rc.call(int(addr), (), what=name)
            print(f"  {name}() = {r:#x} ({r}) in {time.time()-t0:.2f}s")
            if expect is not None:
                assert r == expect, f"{name} returned {r}, expected {expect}"
        # two GetTickCount calls must increase (thread really ran twice)
        a = rc.call(int(k32.GetProcAddress(base_k32, b"GetTickCount")), ())
        time.sleep(0.05)
        b = rc.call(int(k32.GetProcAddress(base_k32, b"GetTickCount")), ())
        print(f"  tick a={a} b={b} increasing={b >= a}")
        print("caller stats:", rc.stats())

        alive = victim.poll() is None
        print(f"victim still alive: {alive}")
        assert alive, "victim died during dry run!"
        print("DRY RUN OK")
    finally:
        victim.kill()


if __name__ == "__main__":
    main()
