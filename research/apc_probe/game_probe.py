"""LIVE game probe: can we execute code inside hoi4.exe today, without suspending
a single thread?

Stage 1 (default): queue a special user APC (QueueUserAPC2 +
QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC) at an existing game thread. The payload
writes only into OUR OWN VirtualAllocEx'd arena (TID + magic + done) and
returns. It touches no game state, suspends nothing, and is idempotent — if it
fires later it just rewrites the same words.

Stage 2: same channel, but the payload CALLS a function from the game thread's
own context — kernel32!GetTickCount (harness dry run) or hoi4!operator new
(the TLS/reentrancy test). Leaks one 0x38-byte allocation in the latter case.

Why this exists: the 22 日 verdict ("SetContextIpValidation kills every
cross-process graft") was built on a bit-misread.
GetProcessMitigationPolicy(UserShadowStack) = 0x100 is bit 8 =
CetDynamicApisOutOfProcOnly, NOT bit 2 = SetContextIpValidation (SDK
10.0.22000 winnt.h + phnt bindings agree). This script tests the live process
instead of inferring from victims.

Job layout (job-relative offsets ARE arena-absolute: the job sits at arena+0):
    +0x00 func   +0x08 a1   +0x10 a2   +0x18 a3   +0x20 a4
    +0x28 result +0x30 done +0x38 stack_top +0x40 saved_rsp +0x48 tid
Shellcode at arena+0x400; private stack top arena+0x2FF0 (RSP%16==0).

Usage:
  python research/apc_probe/game_probe.py --stage 1
  python research/apc_probe/game_probe.py --stage 2 --func new
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4_mcp.process import win32ext as w                      # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess             # noqa: E402
from hoi4_mcp.inject import tables as T                         # noqa: E402

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.QueueUserAPC.restype = wt.DWORD
_k32.QueueUserAPC.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t]
# restype/argtypes MUST be declared: the default c_int restype truncates a
# 64-bit function address to 32 bits (this bug made the probe jump to NULL).
_k32.GetModuleHandleW.restype = ctypes.c_void_p
_k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
HAVE_APC2 = hasattr(_k32, "QueueUserAPC2")
if HAVE_APC2:
    _k32.QueueUserAPC2.restype = wt.BOOL
    _k32.QueueUserAPC2.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t, ctypes.c_int]
SPECIAL = 1

JOB_OFF = 0x000
SC_OFF = 0x400
RESULT_OFF = 0x028
DONE_OFF = 0x030
STACK_PTR_OFF = 0x038
SAVED_RSP_OFF = 0x040
TID_OFF = 0x048
JOB_SIZE = 0x50
STACK_TOP = 0x2FF0          # %16 == 0
ARENA_SIZE = 0x4000
PAGE_EXECUTE_READWRITE = 0x40

MAGIC = 0x5A5A112233445566

# --- stage 1: touch nothing but our own arena -------------------------------
SC_TOUCH = bytes.fromhex(
    "53"                          # push rbx
    "4889CB"                      # mov rbx, rcx          ; job
    "65488B042548000000"          # mov rax, gs:[0x48]    ; TEB->ClientId.UniqueThread
    "48898348000000"              # mov [rbx+0x48], rax   ; tid
    "48B86655443322115A5A"        # mov rax, MAGIC
    "48898328000000"              # mov [rbx+0x28], rax   ; result
    "48C7833000000001000000"      # mov qword [rbx+0x30], 1
    "5B"                          # pop rbx
    "C3"                          # ret
)

# --- stage 2: call func(a1..a4) on the game thread's own context ------------
# RSP is swapped to a private stack (16-aligned) so the interrupted thread's
# stack is never grown; the caller's RSP is stashed at job+0x40 and restored
# before returning to the APC dispatcher.
SC_CALL = bytes.fromhex(
    "53"                          # push rbx
    "4889CB"                      # mov rbx, rcx          ; job
    "65488B042548000000"          # mov rax, gs:[0x48]
    "48898348000000"              # mov [rbx+0x48], rax   ; tid
    "48896340"                    # mov [rbx+0x40], rsp   ; save caller rsp
    "488B6338"                    # mov rsp, [rbx+0x38]   ; private stack (aligned)
    "4883EC20"                    # sub rsp, 0x20         ; shadow space
    "488B03"                      # mov rax, [rbx]        ; func
    "488B4B08"                    # mov rcx, [rbx+0x08]
    "488B5310"                    # mov rdx, [rbx+0x10]
    "4C8B4318"                    # mov r8,  [rbx+0x18]
    "4C8B4B20"                    # mov r9,  [rbx+0x20]
    "FFD0"                        # call rax
    "48894328"                    # mov [rbx+0x28], rax   ; result
    "48C7433001000000"            # mov qword [rbx+0x30], 1
    "488B6340"                    # mov rsp, [rbx+0x40]   ; back to caller rsp
    "5B"                          # pop rbx
    "C3"                          # ret
)


def disasm(b: bytes) -> str:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return "\n    ".join(f"+{i.address:04x}: {i.mnemonic} {i.op_str}"
                         for i in md.disasm(b, 0))


SS_BITS = ["EnableUserShadowStack", "AuditUserShadowStack",
           "SetContextIpValidation", "AuditSetContextIpValidation",
           "UserShadowStackStrictMode", "BlockNonCetBinaries",
           "BlockNonCetBinariesNonEhcont", "AuditBlockNonCetBinaries",
           "CetDynamicApisOutOfProcOnly", "SetContextIpValidationRelaxedMode"]


def decode_ss(flags: int) -> str:
    on = [n for i, n in enumerate(SS_BITS) if flags & (1 << i)]
    return f"{flags:#x} -> {on or 'none'}"


def find_pid() -> int:
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq hoi4.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    pids = [int(line.split('","')[1]) for line in out.splitlines() if line.startswith('"')]
    if len(pids) != 1:
        raise SystemExit(f"expected exactly one hoi4.exe, got {pids}")
    return pids[0]


def build_job(arena: int, func: int, args=(0, 0, 0, 0)) -> bytes:
    job = struct.pack("<5Q", func, *[int(a) for a in args])
    job += struct.pack("<QQ", 0, 0)                          # result, done
    job += struct.pack("<Q", arena + STACK_TOP)              # +0x38 stack top
    job += struct.pack("<QQ", 0, 0)                          # +0x40 saved rsp, +0x48 tid
    assert len(job) == JOB_SIZE, len(job)
    return job


class Probe:
    def __init__(self, pid: int | None = None):
        self.p = AttachedProcess(pid or find_pid())
        self.h = self.p.handle
        self.m = self.p.memory
        self.arena = w.virtual_alloc_ex(self.h, ARENA_SIZE, PAGE_EXECUTE_READWRITE)
        print(f"attached pid={self.p.pid} base={self.p.base:#x} arena={self.arena:#x}")
        print(f"shadow-stack policy: {decode_ss(w.get_mitigation_policy(self.h, 15, 4) or 0)}")
        print(f"dynamic_code={w.get_mitigation_policy(self.h, 2, 4)} "
              f"cfg={w.get_mitigation_policy(self.h, 7, 4)}")

    def paused(self):
        try:
            idler = struct.unpack("<Q", self.m.rpm(self.p.base + T.G_IDLER, 8))[0]
            return self.m.rpm(idler + T.IDLER_PAUSED_OFF, 1)[0]
        except OSError:
            return None

    def fire(self, tid: int, classic: bool = False):
        try:
            h = w.open_thread(tid)
        except OSError as e:
            return False, f"OpenThread failed: {e}"
        try:
            if classic:
                rc = _k32.QueueUserAPC(ctypes.c_void_p(self.arena + SC_OFF), h,
                                       self.arena + JOB_OFF)
                return bool(rc), f"QueueUserAPC rc={rc}"
            ok = _k32.QueueUserAPC2(ctypes.c_void_p(self.arena + SC_OFF), h,
                                    self.arena + JOB_OFF, SPECIAL)
            return bool(ok), f"QueueUserAPC2(SPECIAL) ok={bool(ok)}"
        finally:
            w._k32.CloseHandle(h)

    def poll(self, timeout: float = 3.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                done = struct.unpack("<Q", self.m.rpm(self.arena + DONE_OFF, 8))[0]
                if done:
                    tid = struct.unpack("<Q", self.m.rpm(self.arena + TID_OFF, 8))[0]
                    res = struct.unpack("<Q", self.m.rpm(self.arena + RESULT_OFF, 8))[0]
                    return done, tid, res, time.time() - t0
            except OSError as e:
                print("  readback failed:", e)
                return -1, 0, 0, time.time() - t0
            time.sleep(0.005)
        return 0, 0, 0, time.time() - t0

    def threads_main_first(self):
        out = []
        for tid in w.list_thread_ids(self.p.pid):
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                created = w.get_thread_times(h)[0]
            except OSError:
                continue
            finally:
                w._k32.CloseHandle(h)
            out.append((tid, created))
        out.sort(key=lambda t: t[1])
        return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", type=int, default=1)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--classic", action="store_true",
                    help="plain alertable QueueUserAPC instead of the special APC")
    ap.add_argument("--main-first", action="store_true", default=False)
    ap.add_argument("--workers", type=int, default=6,
                    help="how many worker threads to try before the main thread")
    ap.add_argument("--func", choices=("tick", "new"), default="tick",
                    help="stage-2 callee: kernel32!GetTickCount (victim dry run) "
                         "or hoi4!operator new (the TLS/reentrancy test)")
    args = ap.parse_args()

    pr = Probe(args.pid)
    tl = pr.threads_main_first()
    main_tid = tl[0][0]
    print(f"{len(tl)} threads; main(candidate, earliest-created)={main_tid}")

    if args.stage == 1:
        sc = SC_TOUCH
        job = b"\0" * JOB_SIZE
        print("stage1: write-only payload (no game state touched)")
    else:
        sc = SC_CALL
        if args.func == "new":
            fn_va = pr.p.base + T.FN_OPERATOR_NEW
            call_args = (0x38, 0, 0, 0)
            print(f"stage2: hoi4!operator new @ {fn_va:#x} (TLS/reentrancy test)")
        else:
            fn_va = int(_k32.GetProcAddress(_k32.GetModuleHandleW("kernel32.dll"),
                                            b"GetTickCount"))
            call_args = (0, 0, 0, 0)
            print(f"stage2: kernel32!GetTickCount @ {fn_va:#x} (harness dry run)")
        job = build_job(pr.arena, fn_va, call_args)
    w.write_process_memory(pr.h, pr.arena + JOB_OFF, job)
    w.write_process_memory(pr.h, pr.arena + SC_OFF, sc)
    back_job = pr.m.rpm(pr.arena + JOB_OFF, len(job))
    back_sc = pr.m.rpm(pr.arena + SC_OFF, len(sc))
    print(f"readback: job_ok={back_job == job} sc_ok={back_sc == sc} "
          f"stack_top={struct.unpack('<Q', back_job[STACK_PTR_OFF:STACK_PTR_OFF+8])[0]:#x} "
          f"func={struct.unpack('<Q', back_job[:8])[0]:#x}")
    if back_sc != sc:
        print("  MISMATCH sc:", back_sc.hex())
    print("shellcode:\n    " + disasm(sc))

    paused_before = pr.paused()
    print(f"paused byte before: {paused_before}")

    workers = [(t, c) for t, c in tl if t != main_tid]
    order = ([(main_tid, 0.0)] if args.main_first
             else workers[: args.workers] + [(main_tid, 0.0)])

    hit = None
    for tid, _c in order:
        w.write_process_memory(pr.h, pr.arena + DONE_OFF, b"\0" * 8)
        ok, note = pr.fire(tid, classic=args.classic)
        if not ok:
            print(f"  tid={tid}: {note}")
            continue
        done, ran_tid, res, dt = pr.poll(3.0)
        print(f"  tid={tid}: {note} -> done={done} ran_on={ran_tid} "
              f"result={res:#x} dt={dt*1000:.0f}ms")
        if done:
            hit = (tid, ran_tid, res, dt)
            break

    print()
    if hit:
        print(f"IN-PROCESS EXECUTION CONFIRMED: queued at tid={hit[0]}, "
              f"executed on tid={hit[1]}, result={hit[2]:#x} ({hit[3]*1000:.0f}ms)")
        if args.stage == 2 and args.func == "new":
            print("  => game-side call from a game thread's own context: "
                  + ("OK (heap ptr returned)" if hit[2] else "returned NULL"))
    else:
        print("no APC delivery observed in the window (queued, not lost)")

    print(f"paused byte after: {pr.paused()} (before {paused_before})")
    print(f"threads now: {len(w.list_thread_ids(pr.p.pid))}")
    print("game process alive:", pr.p.is_alive())
    print("NOTE: the arena stays mapped on purpose — a pending APC must never jump "
          "into freed memory. 16 KB, harmless.")


if __name__ == "__main__":
    main()
