"""Hijack-layer bisect: which retarget op (RIP only / +RCX / +RSP) kills the
victim. Fresh victim per variant; evidence = thread RIP samples + param state."""
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
from hoi4_mcp.inject.call import SHELLCODE, Context, _OFF, CONTEXT_AMD64, STACK_TOP

VICTIM_SRC = "import time\nwhile True:\n    time.sleep(0.05)\n"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
K32BASE = k32.GetModuleHandleW("kernel32.dll")
FN_TICK = int(k32.GetProcAddress(K32BASE, b"GetTickCount"))

k32.GetThreadContext.restype = ctypes.c_bool
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.SetThreadContext.restype = ctypes.c_bool
k32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


def run_variant(name: str, set_rcx: bool, set_rsp: bool):
    victim = subprocess.Popen([sys.executable, "-c", VICTIM_SRC])
    time.sleep(1.0)
    print(f"--- {name} (victim {victim.pid}) ---")
    try:
        proc = AttachedProcess(victim.pid)
        arena = w.virtual_alloc_ex(proc.handle, 0x4000, 0x40)
        w.write_process_memory(proc.handle, arena, SHELLCODE)
        param = arena + 0x200
        w.write_process_memory(proc.handle, param, struct.pack("<5Q", FN_TICK, 0, 0, 0, 0))
        tids = w.list_thread_ids(victim.pid)
        prev = {}
        for tid in tids:
            h = w.open_thread(tid)
            prev[tid] = w.suspend_thread(h)
            w._k32.CloseHandle(h)
        target = tids[0]
        th = w.open_thread(target)
        saved = Context()
        struct.pack_into("<I", saved.buf, _OFF["ContextFlags"], CONTEXT_AMD64)
        ok = k32.GetThreadContext(th, ctypes.addressof(saved.buf))
        print(f"  getctx ok={ok} saved RIP={saved.get('Rip'):#x} RSP={saved.get('Rsp'):#x} "
              f"RCX={saved.get('Rcx'):#x}")
        ctx = Context()
        ctypes.memmove(ctx.buf, saved.buf, 1232)
        struct.pack_into("<I", ctx.buf, _OFF["ContextFlags"], CONTEXT_AMD64)
        ctx.set("Rip", arena)
        ctx.set("Rcx", param if set_rcx else saved.get("Rcx"))
        ctx.set("Rsp", (arena + STACK_TOP) if set_rsp else saved.get("Rsp"))
        ok2 = k32.SetThreadContext(th, ctypes.addressof(ctx.buf))
        print(f"  setctx ok={ok2} -> RIP={ctx.get('Rip'):#x} RCX={ctx.get('Rcx'):#x} "
              f"RSP={ctx.get('Rsp'):#x}")
        w.resume_thread(th)
        # sample RIP while it runs
        rips = []
        probe = Context()
        for _ in range(25):
            struct.pack_into("<I", probe.buf, _OFF["ContextFlags"], CONTEXT_AMD64)
            if k32.GetThreadContext(th, ctypes.addressof(probe.buf)):
                rips.append((probe.get("Rip"), probe.get("Rsp")))
            time.sleep(0.004)
        done = None
        try:
            done = int.from_bytes(w.read_process_memory(proc.handle, param + 0x30, 8), "little")
        except OSError:
            pass
        alive = victim.poll() is None
        print("  samples:", [(hex(r - arena) if arena <= r < arena + 0x4000 else hex(r),
                              hex(s)) for r, s in rips[:8]])
        print(f"  done={done} alive={alive}")
        w.suspend_thread(th)
        k32.SetThreadContext(th, ctypes.addressof(saved.buf))
        w.resume_thread(th)
        w._k32.CloseHandle(th)
        print(f"  restored; alive={victim.poll() is None}")
    finally:
        victim.kill()


def main():
    run_variant("H1 RIP only", set_rcx=False, set_rsp=False)
    run_variant("H2 RIP+RCX (own stack)", set_rcx=True, set_rsp=False)
    run_variant("H3 RIP+RCX+arenaRSP", set_rcx=True, set_rsp=True)


if __name__ == "__main__":
    main()
