"""Cave-protocol battery (22 日 stability track, step 2).

The 22 日 finding: system-wide SetContextIpValidation arrived with the
10-14 KB security updates (effective after today's boot; before it, the
21 日 live closed loop worked). It neuters:
  a) CreateRemoteThread into non-image RWX (fail-fast 0xC0000409),
  b) SetThreadContext RIP-grafts into non-image RWX (RIP visibly 0x0).
Grafted RIPs to REAL image code still execute (kernel32!GetTickCount
graft ran and returned in RAX). The 21 日 repeat-send crash and today's
victim deaths converge on the SECOND SetThreadContext (restore) after a
grafted run.

Protocol change (this file): ONE SetThreadContext per cycle, and no
restore call at all. The grafted code lives in a code cave INSIDE a real
loaded image (patched via WPM/CoW); job data + private stack live in a
private RWX arena (data pages — never jumped to, so not IP-validated).
The cave runs the job, then restores 15 GP registers + rsp from the
context block and JMPs back to the original RIP:

  freeze -> racy shortlist -> graft (RIP=cave, RCX=B, RSP=W, one SetContext)
  -> cave calls func, stores result/done -> restores regs/rsp from B ->
  jmp original RIP; our side polls done; thaw. Target thread continues
  its original code exactly, from inside itself.

Battery on a game-like python victim (hot main + sleepers):
  1. cave discovery (zero run in python312.dll code pages) + WPM patch
  2. repeated cave-graft cycles (GetTickCount; monotonic; victim alive)

Usage: python research/cave_bisect.py [--cycles N] [--rounds R]
"""
from __future__ import annotations

import argparse
import ctypes
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4_mcp.process.attach import AttachedProcess
from hoi4_mcp.inject.call import RemoteCaller, Context
from hoi4_mcp.process import win32ext as w

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
FN_TICK = int(k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"GetTickCount"))

HOT = ("import time, threading\n"
       "for i in range(8):\n"
       "    threading.Thread(target=lambda: [time.sleep(0.05) for _ in iter(int,1)]).start()\n"
       "x = 0\n"
       "while True:\n"
       "    x ^= 1\n")

# --- B block layout (arena data) — mirrors CAVE below; keep in sync! ---------
#   +0x00 func | +0x08 a1 | +0x10 a2 | +0x18 a3 | +0x20 a4
#   +0x28 result | +0x30 done | +0x38 orig RIP | +0x40 orig RSP
#   +0x48 rax  +0x50 rcx  +0x58 rdx  +0x60 rbx  +0x68 rsi  +0x70 rdi
#   +0x78 rbp  +0x80 r8   +0x88 r9   +0x90 r10  +0x98 r11  +0xA0 r12
#   +0xA8 r13  +0xB0 r14  +0xB8 r15
B_SIZE = 0xD0
RESULT_OFF = 0x28
DONE_OFF = 0x30
RIP_OFF = 0x38
RSP_OFF = 0x40
GP_ORDER = ["Rax", "Rcx", "Rdx", "Rbx", "Rsi", "Rdi", "Rbp", "R8", "R9",
            "R10", "R11", "R12", "R13", "R14", "R15"]
GP_OFF = 0x48
STACK_OFF = 0x1000          # private stack top of arenas at B_base+STACK_OFF
STACK_TOP = 0x2FF8          # rsp%16 == 8 (shellcode entry expectation)
ARENA_SIZE = 0x4000

# CAVE (self-restoring entry; ONE SetContext per cycle)
CAVE = bytes.fromhex(
    "53"                      # push rbx
    "55"                      # push rbp
    "56"                      # push rsi
    "57"                      # push rdi
    "4154"                    # push r12
    "4155"                    # push r13
    "4156"                    # push r14
    "4157"                    # push r15          ; 8 pushes = 0x40
    "4883EC30"                # sub rsp, 0x30     ; shadow+pad
    "4889CB"                  # mov rbx, rcx      ; rbx = B (callee-saved)
    "488B03"                  # mov rax, [rbx]    ; func
    "488B4B08"                # mov rcx, [rbx+0x08]
    "488B5310"                # mov rdx, [rbx+0x10]
    "4C8B4318"                # mov r8,  [rbx+0x18]
    "4C8B4B20"                # mov r9,  [rbx+0x20]
    "FFD0"                    # call rax
    "48894328"                # mov [rbx+0x28], rax   ; result
    "48C7433001000000"        # mov qword [rbx+0x30], 1 ; done
    "4883C430"                # add rsp, 0x30
    "415F"                    # pop r15
    "415E"                    # pop r14
    "415D"                    # pop r13
    "415C"                    # pop r12
    "5F"                      # pop rdi
    "5E"                      # pop rsi
    "5D"                      # pop rbp        ; rbx STILL = B (never popped!)
    # register wholesale restore from B via rbx (order matters: rbx last)
    "488B4348"                # mov rax, [rbx+0x48]
    "488B4B50"                # mov rcx, [rbx+0x50]
    "488B5358"                # mov rdx, [rbx+0x58]
    "488B7368"                # mov rsi, [rbx+0x68]
    "488B7B70"                # mov rdi, [rbx+0x70]
    "488B6B78"                # mov rbp, [rbx+0x78]
    "4C8B4380"                # mov r8,  [rbx+0x80]
    "4C8B4B88"                # mov r9,  [rbx+0x88]
    "4C8B5390"                # mov r10, [rbx+0x90]
    "4C8B5B98"                # mov r11, [rbx+0x98]
    "4C8B63A0"                # mov r12, [rbx+0xA0]
    "4C8B6BA8"                # mov r13, [rbx+0xA8]
    "4C8B73B0"                # mov r14, [rbx+0xB0]
    "4C8B7BB8"                # mov r15, [rbx+0xB8]
    "488B6340"                # mov rsp, [rbx+0x40]  ; orig rsp
    "488B5B60"                # mov rbx, [rbx+0x60]  ; orig rbx (LAST)
    "FFE2"                    # jmp r10              ; back to original RIP
)


def find_cave(pid: int, dllname: str, need: int = 0x200):
    """First >=`need`-byte zero run inside an executable region of a module."""
    p = AttachedProcess(pid)
    for name, base, size in w.enumerate_modules(p.handle):
        if dllname in name:
            dll_base, dll_size = base, size
            break
    else:
        return None
    a = dll_base
    while a < dll_base + dll_size:
        mbi = w.virtual_query(p.handle, a)
        if mbi is None:
            break
        prot = mbi.Protect & 0xFF
        if mbi.State == 0x1000 and prot in (0x10, 0x20, 0x40):
            sz = min(mbi.RegionSize, dll_base + dll_size - a)
            try:
                data = w.read_process_memory(p.handle, a, sz)
            except OSError:
                a += mbi.RegionSize
                continue
            run = 0
            start = None
            for i, b in enumerate(data):
                if b == 0:
                    if run == 0:
                        start = i
                    run += 1
                    if run == need:
                        return a + start
                else:
                    run = 0
            a += mbi.RegionSize
        else:
            a += mbi.RegionSize
    return None


class CaveChannel:
    """One cave + arena pair; repeated graft cycles through it."""

    def __init__(self, proc):
        self.p = proc
        self.h = proc.handle
        self.m = proc.memory
        self.cave = None
        self.arena = None

    def arm(self, dllname="python312.dll"):
        self.cave = find_cave(self.p.pid, dllname, need=len(CAVE) + 16)
        if not self.cave:
            raise RuntimeError("no code cave found in " + dllname)
        self._cave_backup = w.read_process_memory(self.h, self.cave, len(CAVE))
        w.write_process_memory(self.h, self.cave, CAVE)
        back = w.read_process_memory(self.h, self.cave, len(CAVE))
        if back != CAVE:
            raise RuntimeError("cave patch failed (readback differs)")
        self.arena = w.virtual_alloc_ex(self.h, ARENA_SIZE, 0x40)
        return self.cave, self.arena

    def job(self, func: int, args=(0, 0, 0, 0)) -> int:
        """Rewrite B + zero done flag; returns B address."""
        b = self.arena           # B at arena+0; stack at arena+0x1000
        blob = struct.pack("<5Q", func, *[int(a) for a in args])
        blob += struct.pack("<2Q", 0, 0)              # result, done
        w.write_process_memory(self.h, b, blob)
        return b

    def graft(self, rc: RemoteCaller, b: int) -> tuple[int | None, str | None]:
        """One freeze→graft→poll→(self-restore inside target) cycle."""
        short = rc.probe_targets()
        tids = rc._threads()
        prev = rc._suspend_all(tids)
        rc._suspended_now = {t for t, was in prev.items() if was == 0}
        target = th = None
        res, err = None, None
        try:
            target = rc._pick_from_shortlist(short)
            if target is None:
                return None, "rearm (nothing shortlisted; harmless)"
            th = w.open_thread(target)
            saved = Context(); saved.flags()
            if not k32.GetThreadContext(th, ctypes.c_void_p(ctypes.addressof(saved.buf))):
                return None, "GetContext failed"
            # stash orig RIP/RSP/GPs into B for the cave's self-restore
            frame = struct.pack("<2Q", saved.get("Rip"), saved.get("Rsp"))
            frame += struct.pack("<15Q", *[saved.get(n) for n in GP_ORDER])
            w.write_process_memory(self.h, b + RIP_OFF, frame)
            ctx = Context()
            ctypes.memmove(ctx.buf, saved.buf, 1232); ctx.flags()
            ctx.set("Rip", self.cave)
            ctx.set("Rcx", b)
            ctx.set("Rsp", b + STACK_OFF + STACK_TOP)
            if not k32.SetThreadContext(th, ctypes.c_void_p(ctypes.addressof(ctx.buf))):
                err = f"graft SetContext failed err={ctypes.get_last_error()}"
                return None, err
            w.resume_thread(th)
            deadline = time.time() + rc.timeout
            while time.time() < deadline:
                try:
                    done = int.from_bytes(self.m.rpm(b + DONE_OFF, 8), "little")
                except OSError:
                    err = "victim died mid-poll"
                    return None, err
                if done:
                    break
                time.sleep(0.002)
            if not done:
                err = f"timeout (target={target})"
                return None, err
            res = int.from_bytes(self.m.rpm(b + RESULT_OFF, 8), "little")
            return res, err
        finally:
            if th is not None:
                k32.CloseHandle(th)
            rc._resume_frozen(prev, skip=target)

    def disarm(self):
        """Restore the cave bytes (image-cave hygiene)."""
        if self.cave and self._cave_backup:
            try:
                w.write_process_memory(self.h, self.cave, self._cave_backup)
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cycles", type=int, default=8)
    ap.add_argument("--dll", default="python312.dll")
    args = ap.parse_args()

    vic = subprocess.Popen([sys.executable, "-c", HOT])
    time.sleep(1.5)
    p = AttachedProcess(vic.pid)
    rc = RemoteCaller(p, timeout=4.0, attempts=6,
                      allow_module_patterns=("python",), mode="hijack")

    ch = CaveChannel(p)
    cave, arena = ch.arm(args.dll)
    print(f"victim pid={vic.pid} cave={cave:#x} arena={arena:#x}")

    ticks = []
    for n in range(args.cycles):
        b = ch.job(FN_TICK)
        res, err = ch.graft(rc, b)
        alive = vic.pid in (__import__("psutil").pids())
        print(f"cycle#{n}: {'tick=' + str(res) if res is not None else 'N/A'} "
              f"err={err!r} alive={alive}")
        if res is None:
            break
        ticks.append(res)
    if len(ticks) > 1:
        print("monotonic:", all(y >= x for x, y in zip(ticks, ticks[1:])))
    ch.disarm()
    print("FINAL victim alive:", vic.pid in __import__("psutil").pids())
    try:
        vic.kill()
    except Exception:
        pass
    ec = 0 if len(ticks) == args.cycles and vic.pid in __import__("psutil").pids() else 1
    sys.exit(ec)


if __name__ == "__main__":
    main()
