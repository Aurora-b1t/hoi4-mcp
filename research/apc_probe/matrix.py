"""Cross-process execution-primitive matrix (day-23 re-research of the write layer).

Why: the 22 日 verdict said the 2026-10-14 Windows security update killed the
SetThreadContext graft, and the fix would be "self-launch the game with
PROCESS_CREATION_MITIGATION_POLICY". That verdict rests on ONE primitive
(graft). This battery re-baselines it and probes the alternatives that never
touch SetThreadContext:

  queue_apc        QueueUserAPC  -> same-process APCs are the classic trigger
  queue_apc2       QueueUserAPC2 special APC (runs even when NOT alertable)
  crt_private      CreateRemoteThread into our own RWX arena  (22 日: dies)
  crt_loadlib      CreateRemoteThread = LoadLibraryW          (22 日: "in-image
                   start is fine" => this is the DLL-injection door)
  graft            the old suspend + SetThreadContext hijack   (control)
  wpm_canary       plain WriteProcessMemory data write         (baseline)

Every test spawns a FRESH victim: a fatal primitive must not poison the next
one. Nothing here touches the game; the live game probe is a separate script.

Usage:
  python research/apc_probe/matrix.py                 # all tests
  python research/apc_probe/matrix.py queue_apc queue_apc2
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4_mcp.process import win32ext as w                      # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess             # noqa: E402
from hoi4_mcp.inject.call import RemoteCaller, CallError        # noqa: E402

HERE = Path(__file__).resolve().parent
VICTIM = HERE / "victim.py"

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.QueueUserAPC.restype = wt.DWORD
_k32.QueueUserAPC.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t]
_k32.CreateRemoteThread.restype = wt.HANDLE
_k32.CreateRemoteThread.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                                    ctypes.POINTER(wt.DWORD)]
_k32.GetModuleHandleW.restype = ctypes.c_void_p
_k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_k32.GetTickCount.restype = wt.DWORD

HAVE_APC2 = hasattr(_k32, "QueueUserAPC2")
if HAVE_APC2:
    _k32.QueueUserAPC2.restype = wt.BOOL
    _k32.QueueUserAPC2.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t, ctypes.c_int]

QUEUE_USER_APC_FLAGS_NONE = 0
QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1

# --- arena layout (mirrors inject/call.py so the same shellcode plugs in) ----
SC_OFF = 0x0000
PARAM_OFF = 0x0200
RESULT_OFF = 0x0228
DONE_OFF = 0x0230
TID_OFF = 0x0238
STACK_BASE = 0x1000
STACK_TOP = 0x2FF8
ARENA_SIZE = 0x4000

# APC/CRT-safe payload: records the executing TID + a magic value, then RETURNS
# cleanly (no spin) so the APC dispatcher can resume the interrupted thread and
# a CreateRemoteThread newcomer can exit through BaseThreadInitThunk.
#   mov rax, gs:[0x48]          ; TEB->ClientId.UniqueThread
#   mov [rcx+0x238], rax
#   mov rax, 0x1122334455667788
#   mov [rcx+0x228], rax
#   mov qword [rcx+0x230], 1
#   ret
SC_PROBE = bytes.fromhex(
    "65488B042548000000"
    "48898138020000"
    "48B88877665544332211"
    "48898128020000"
    "48C7813002000001000000"
    "C3"
)
MAGIC = 0x1122334455667788
PAGE_EXECUTE_READWRITE = 0x40


def disasm(b: bytes) -> str:
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return " | ".join(f"{i.mnemonic} {i.op_str}" for i in md.disasm(b, 0))
    except Exception as e:      # pragma: no cover
        return f"<capstone unavailable: {e}>"


class Victim:
    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.p = subprocess.Popen([sys.executable, str(VICTIM), state_dir],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pid = self.p.pid
        self.state_path = os.path.join(state_dir, f"{self.pid}.json")
        self.proc = None
        self.arena = 0
        self.dead_note = ""
        for _ in range(50):
            if os.path.exists(self.state_path):
                try:
                    st = self.state()
                    if "busy" in st.get("tids", {}):
                        break
                except Exception:
                    pass
            time.sleep(0.1)
        time.sleep(0.4)
        try:
            self.proc = AttachedProcess(self.pid)
        except Exception as e:
            self.dead_note = f"attach failed: {e}"

    def state(self) -> dict:
        with open(self.state_path) as f:
            return json.load(f)

    def alive(self) -> bool:
        return self.p.poll() is None

    def exit_code(self):
        return self.p.poll()

    def rpm(self, addr: int, size: int) -> bytes:
        return self.proc.memory.rpm(addr, size)

    def alloc(self) -> int:
        if not self.arena:
            self.arena = w.virtual_alloc_ex(self.proc.handle, ARENA_SIZE,
                                            PAGE_EXECUTE_READWRITE)
            w.write_process_memory(self.proc.handle, self.arena, SC_PROBE)
        return self.arena

    def poll_done(self, timeout: float = 2.0):
        """(done, tid, result, elapsed) — reads only our own arena."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            if not self.alive():
                return None, None, None, time.time() - t0
            try:
                done = struct.unpack("<Q", self.rpm(self.arena + DONE_OFF, 8))[0]
                tid = struct.unpack("<Q", self.rpm(self.arena + TID_OFF, 8))[0]
                res = struct.unpack("<Q", self.rpm(self.arena + RESULT_OFF, 8))[0]
            except OSError:
                return None, None, None, time.time() - t0
            if done:
                return done, tid, res, time.time() - t0
            time.sleep(0.005)
        return 0, None, None, time.time() - t0

    def cleanup(self):
        try:
            if self.proc:
                self.proc.detach()
        except Exception:
            pass
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait(timeout=5)


# --- primitives -------------------------------------------------------------
def _thread_handle(v: Victim, tid: int):
    return w.open_thread(tid)


def queue_apc(v: Victim, tid: int, special: bool = False) -> tuple[bool, str]:
    h = _thread_handle(v, tid)
    try:
        if special:
            if not HAVE_APC2:
                return False, "QueueUserAPC2 not exported on this build"
            ok = _k32.QueueUserAPC2(ctypes.c_void_p(v.alloc()),
                                    h, v.alloc(),
                                    QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)
            return bool(ok), f"QueueUserAPC2(SPECIAL) -> ok={bool(ok)} err={ctypes.get_last_error()}"
        r = _k32.QueueUserAPC(ctypes.c_void_p(v.alloc()), h, v.alloc())
        return bool(r), f"QueueUserAPC -> rc={r} err={ctypes.get_last_error()}"
    finally:
        w._k32.CloseHandle(h)


def crt(v: Victim, start: int, param: int) -> tuple[bool, str, int]:
    tid = wt.DWORD(0)
    ctypes.set_last_error(0)
    h = _k32.CreateRemoteThread(v.proc.handle, None, 0, ctypes.c_void_p(start),
                                ctypes.c_void_p(param), 0, ctypes.byref(tid))
    if not h:
        return False, f"CreateRemoteThread -> err={ctypes.get_last_error()}", 0
    w._k32.CloseHandle(h)
    return True, "created", tid.value


def graft(v: Victim, fn_va: int) -> tuple[bool, str]:
    """The 21 日 protocol A: racy shortlist -> freeze all -> SetThreadContext."""
    rc = RemoteCaller(v.proc, timeout=3.0, attempts=6,
                      allow_module_patterns=("python",), mode="hijack")
    try:
        tick = rc.call(fn_va, (), what="GetTickCount")
        return True, f"tick={tick} stats={rc.stats()}"
    except CallError as e:
        return False, f"CallError: {e}"
    finally:
        try:
            rc.close()
        except Exception:
            pass


# --- tests ------------------------------------------------------------------
def t_wpm_canary(v: Victim) -> str:
    addr = v.state()["canary_addr"]
    before = struct.unpack("<Q", v.rpm(addr, 8))[0]
    w.write_process_memory(v.proc.handle, addr, struct.pack("<Q", 0xDEADBEEFCAFEF00D))
    after = struct.unpack("<Q", v.rpm(addr, 8))[0]
    return f"canary {before:#x} -> {after:#x} (WriteProcessMemory baseline)"


def t_queue_apc_alertable(v: Victim) -> str:
    tid = v.state()["tids"]["alertable"]
    ok, note = queue_apc(v, tid)
    done, rtid, res, dt = v.poll_done(3.0)
    apcs = v.state().get("apc_completions") if v.alive() else None
    return (f"{note}; target={tid} done={done} ran_on={rtid} magic_ok="
            f"{res == MAGIC} dt={dt*1000:.0f}ms victim_apc_completions={apcs}")


def t_queue_apc_busy(v: Victim) -> str:
    tid = v.state()["tids"]["busy"]
    ok, note = queue_apc(v, tid)
    done, rtid, res, dt = v.poll_done(1.5)
    return (f"{note}; target={tid} (NOT alertable) done={done} ran_on={rtid} "
            f"dt={dt*1000:.0f}ms  [expect done=0: no alertable wait]")


def t_queue_apc2_special_busy(v: Victim) -> str:
    tid = v.state()["tids"]["busy"]
    ok, note = queue_apc(v, tid, special=True)
    done, rtid, res, dt = v.poll_done(3.0)
    return (f"{note}; target={tid} (busy) done={done} ran_on={rtid} "
            f"magic_ok={res == MAGIC} dt={dt*1000:.0f}ms")


def t_queue_apc2_special_alertable(v: Victim) -> str:
    tid = v.state()["tids"]["alertable"]
    ok, note = queue_apc(v, tid, special=True)
    done, rtid, res, dt = v.poll_done(3.0)
    return (f"{note}; target={tid} (alertable) done={done} ran_on={rtid} "
            f"magic_ok={res == MAGIC} dt={dt*1000:.0f}ms")


def t_crt_private(v: Victim) -> str:
    arena = v.alloc()
    ok, note, tid = crt(v, arena + SC_OFF, arena)
    done, rtid, res, dt = v.poll_done(2.0)
    time.sleep(0.3)
    return (f"{note} tid={tid}; done={done} ran_on={rtid} victim_alive={v.alive()} "
            f"exit={v.exit_code()} dt={dt*1000:.0f}ms")


def t_crt_loadlib(v: Victim) -> str:
    cands = [r"C:\Windows\System32\msimg32.dll", r"C:\Windows\System32\wer.dll",
             r"C:\Windows\System32\dbghelp.dll"]
    loaded = {Path(n).name.lower() for n, _b, _s in w.enumerate_modules(v.proc.handle)}
    target = next((c for c in cands if Path(c).name.lower() not in loaded), None)
    if not target:
        return "no unloaded candidate dll"
    buf = (target + "\0").encode("utf-16-le")
    remote = w.virtual_alloc_ex(v.proc.handle, len(buf) + 2, w.PAGE_READWRITE)
    w.write_process_memory(v.proc.handle, remote, buf)
    loadlib = int(_k32.GetProcAddress(_k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW"))
    ok, note, tid = crt(v, loadlib, remote)
    time.sleep(1.0)
    after = {Path(n).name.lower() for n, _b, _s in w.enumerate_modules(v.proc.handle)} \
        if v.alive() else set()
    return (f"target={target} {note} tid={tid}; loaded_now="
            f"{Path(target).name.lower() in after} victim_alive={v.alive()}")


def t_graft(v: Victim) -> str:
    tick_fn = int(_k32.GetProcAddress(_k32.GetModuleHandleW("kernel32.dll"), b"GetTickCount"))
    ok, note = graft(v, tick_fn)
    time.sleep(0.3)
    return f"{note}; victim_alive={v.alive()} exit={v.exit_code()}"


TESTS = {
    "wpm_canary": t_wpm_canary,
    "queue_apc_alertable": t_queue_apc_alertable,
    "queue_apc_busy": t_queue_apc_busy,
    "queue_apc2_special_busy": t_queue_apc2_special_busy,
    "queue_apc2_special_alertable": t_queue_apc2_special_alertable,
    "crt_private": t_crt_private,
    "crt_loadlib": t_crt_loadlib,
    "graft": t_graft,
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("tests", nargs="*", default=None)
    ap.add_argument("--keep", action="store_true", help="do not delete state dir")
    args = ap.parse_args()
    names = args.tests or list(TESTS)

    print("shellcode:", SC_PROBE.hex())
    print("disasm   :", disasm(SC_PROBE))
    print(f"QueueUserAPC2 available: {HAVE_APC2}")
    print(f"python {sys.version.split()[0]}\n")

    results = {}
    for name in names:
        fn = TESTS.get(name)
        if not fn:
            print(f"?? unknown test {name}")
            continue
        sd = tempfile.mkdtemp(prefix=f"apcprobe_{name}_")
        v = Victim(sd)
        if v.dead_note:
            print(f"[{name}] victim setup problem: {v.dead_note}")
            results[name] = "SETUP-FAIL"
            continue
        try:
            out = fn(v)
        except Exception as e:
            out = f"EXC {type(e).__name__}: {e}"
        alive = v.alive()
        results[name] = "alive" if alive else f"DEAD(exit={v.exit_code()})"
        print(f"[{name}] {out}")
        print(f"[{name}] victim: {'ALIVE' if alive else 'DEAD exit=' + str(v.exit_code())}")
        print()
        v.cleanup()
        if not args.keep:
            try:
                import shutil
                shutil.rmtree(sd, ignore_errors=True)
            except Exception:
                pass

    print("=== summary ===")
    for k, val in results.items():
        print(f"  {k:32s} victim={val}")


if __name__ == "__main__":
    main()
