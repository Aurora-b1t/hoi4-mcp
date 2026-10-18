"""Bisect the remote-call failure: CreateRemoteThread variants vs hijack.

t1: fresh thread calling GetTickCount directly (no shellcode)
t2: fresh thread running our shellcode (with RtlExitUserThread tail)
  -> isolates shellcode/param encoding from the hijack/restore step
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

VICTIM_SRC = "import time\nwhile True:\n    time.sleep(0.05)\n"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

K32BASE = k32.GetModuleHandleW("kernel32.dll")
NTDBLBASE = k32.GetModuleHandleW("ntdll.dll")
FN_TICK = int(k32.GetProcAddress(K32BASE, b"GetTickCount"))
FN_EXIT = int(k32.GetProcAddress(NTDBLBASE, b"RtlExitUserThread"))
FN_CRT = int(k32.GetProcAddress(K32BASE, b"CreateRemoteThread"))
FN_WFSO = int(k32.GetProcAddress(K32BASE, b"WaitForSingleObject"))
FN_GECT = int(k32.GetProcAddress(K32BASE, b"GetExitCodeThread"))

SHELLCODE_EXIT = bytes.fromhex(
    "4989CB" "4883EC28" "4D8BD3" "498B4300" "498B4B08" "FFD0"
    "49894228" "4CC7423001000000" "4883C428" "41FF6238"  # jmp [r10+0x38]
    "CCCC")


def remote_thread_run(proc, start_rva_addr: int, param: int):
    h, tid = w.create_remote_thread(proc.handle, start_rva_addr, param)
    k32b = FN_WFSO
    code = w._k32.WaitForSingleObject(h, 5000)
    exitc = ctypes.c_uint32(0)
    w._k32.GetExitCodeThread(h, ctypes.byref(exitc))
    w._k32.CloseHandle(h)
    return exitc.value


def main():
    victim = subprocess.Popen([sys.executable, "-c", VICTIM_SRC])
    time.sleep(1.0)
    print(f"victim pid={victim.pid}")
    tests = []
    try:
        proc = AttachedProcess(victim.pid)
        print(f"attached base={proc.base:#x}")

        # t1: fresh thread -> GetTickCount directly
        code = remote_thread_run(proc, FN_TICK, 0)
        tests.append(("t1 fresh-thread GetTickCount", code, proc))
        print(f"t1: exit_code={code:#x} ({code}) sane={0 < code < 2**31}")

        # t2: fresh thread -> our shellcode with param
        arena = w.virtual_alloc_ex(proc.handle, 0x4000, 0x40)
        w.write_process_memory(proc.handle, arena, SHELLCODE_EXIT.ljust(0x100, b"\xcc"))
        param = arena + 0x200
        # layout: [0]=func [8..0x20]=args [0x28]=result [0x30]=done [0x38]=exit_fn
        blob = struct.pack("<5Q", FN_TICK, 0, 0, 0, 0)
        blob += struct.pack("<QQQ", 0, 0, FN_EXIT)
        w.write_process_memory(proc.handle, param, blob)
        code2 = remote_thread_run(proc, arena, param)
        # read result from the param block
        res = int.from_bytes(w.read_process_memory(proc.handle, param + 0x28, 8), "little")
        done = int.from_bytes(w.read_process_memory(proc.handle, param + 0x30, 8), "little")
        print(f"t2: exit_code={code2:#x} result={res} done={done}")
        tests.append(("t2 fresh-thread shellcode", res, proc))

        alive = victim.poll() is None
        print(f"victim alive after t1/t2: {alive}")
    finally:
        victim.kill()


if __name__ == "__main__":
    main()
