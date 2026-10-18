"""Instrumented dry-run: find WHERE the hijacked thread crashes.

Runs the remote call against a victim, then (on death) reads the newest WER
Application event for the victim image -> faulting module / exception code.
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import AttachedProcess
from hoi4_mcp.inject.call import RemoteCaller

VICTIM_SRC = "import time\nwhile True:\n    time.sleep(0.05)\n"

PS_EVENT = (
    "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName="
    "'Application Error'; StartTime=(Get-Date).AddMinutes(-3)} -MaxEvents 3 "
    "-ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated; $_.Message }"
)


def k32_resolved(name: str) -> int:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    base = k32.GetModuleHandleW("kernel32.dll")
    addr = k32.GetProcAddress(base, name.encode())
    return int(addr)


def main():
    victim = subprocess.Popen([sys.executable, "-c", VICTIM_SRC])
    time.sleep(1.0)
    print(f"victim pid={victim.pid}")
    try:
        proc = AttachedProcess(victim.pid)
        rc = RemoteCaller(proc, timeout=4.0)
        addr = k32_resolved("GetTickCount")
        print(f"GetTickCount @ {addr:#x}")
        try:
            r = rc.call(addr, (), what="GetTickCount")
            print(f"OK: GetTickCount() = {r:#x} ({r})")
        except Exception as e:
            print(f"CALLED FAILED: {e}")
        time.sleep(0.5)
        alive = victim.poll() is None
        print(f"victim alive: {alive}")
        if not alive:
            print(f"victim exit code: {victim.returncode}")
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", PS_EVENT],
                capture_output=True, text=True, timeout=30).stdout
            print("---- WER events ----")
            print(out[:3000])
    finally:
        victim.kill()


if __name__ == "__main__":
    main()
