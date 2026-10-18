"""APC payload variant battery — isolates WHERE the call-payload dies.

Stage-1 (marker-only) payloads deliver in ~16 ms; the stage-2 (call) payload
produced no done-flag at all. Two hypotheses: (a) never delivered, (b)
delivered and crashed before writing the flag.

Every variant therefore writes a PROGRESS MARKER at job+0x30 as its very first
act, so "delivered" is observable independently of the call. One fresh victim,
one arena per variant, liveness checked between variants.

Usage: python research/apc_probe/apc_debug.py
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4copilot.process import win32ext as w                      # noqa: E402
from hoi4copilot.process.attach import AttachedProcess             # noqa: E402

HERE = Path(__file__).resolve().parent
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.QueueUserAPC2.restype = wt.BOOL
_k32.QueueUserAPC2.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t, ctypes.c_int]
_k32.GetModuleHandleW.restype = ctypes.c_void_p
_k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
TICK = int(_k32.GetProcAddress(_k32.GetModuleHandleW("kernel32.dll"), b"GetTickCount"))

JOB = 0x000
SC = 0x400
STACK_TOP = 0x2FF0
ARENA = 0x4000
MARK = 0x30
RESULT = 0x28
TIDOFF = 0x38
SAVED_RSP = 0x48
STACK_PTR = 0x40

# every variant: marker first, then the behaviour under test
HEAD = ("53"                    # push rbx
        "4889CB"                # mov rbx, rcx
        "48C78330000000")       # mov qword [rbx+0x30], imm32  (filled per variant)
TAIL_RET = "5B" "C3"            # pop rbx; ret
GP_ARGS = ("488B03" "488B4B08" "488B5310" "4C8B4318" "4C8B4B20")  # rax,rcx,rdx,r8,r9

VARIANTS = {
    # marker only — the known-good control
    "mark": HEAD + "AAAAAAAA" + "65488B042548000000" + "48898338000000" + TAIL_RET,
    # marker + private-stack switch, marker after the switch, restore, marker
    "switch_mark": (HEAD + "BBBBBBBB"
                    + "48896340"            # mov [rbx+0x40], rsp
                    + "488B6338"            # mov rsp, [rbx+0x38]
                    + "48C78350000000EEEEEEEE"   # post-switch marker @0x50
                    + "488B6340"            # mov rsp, [rbx+0x40]
                    + "48C78358000000FFFFFFFF"   # post-restore marker @0x58
                    + TAIL_RET),
    # marker + call on the INTERRUPTED thread's own stack
    "call_own": (HEAD + "CCCCCCCC"
                 + "4883EC28"        # sub rsp, 0x28   (entry rsp%16==8 -> 0)
                 + GP_ARGS + "FFD0"  # call rax
                 + "48894328"        # mov [rbx+0x28], rax
                 + "48C7433001000000"
                 + "4883C428"        # add rsp, 0x28
                 + TAIL_RET),
    # marker + call on the private stack, corrected offsets (+0x38 top, +0x40 rsp)
    "call_priv2": (HEAD + "DDDDDDDD"
                   + "48896340"                 # mov [rbx+0x40], rsp
                   + "488B6338"                 # mov rsp, [rbx+0x38]
                   + "48C7835000000011111111"   # marker: switched
                   + "4883EC20"
                   + GP_ARGS + "FFD0"
                   + "48894328"
                   + "48C7433001000000"
                   + "488B6340"
                   + "48C7835800000022222222"   # marker: restored
                   + TAIL_RET),
    # EXACT copy of game_probe.SC_CALL (tid store first, no extra markers)
    "call_gp": ("53" "4889CB"
                "65488B042548000000"     # mov rax, gs:[0x48]
                "48898348000000"         # mov [rbx+0x48], rax   ; tid
                "48896340"               # mov [rbx+0x40], rsp
                "488B6338"               # mov rsp, [rbx+0x38]
                "4883EC20"
                + GP_ARGS + "FFD0"
                + "48894328"
                + "48C7433001000000"
                + "488B6340"
                + TAIL_RET),
}


def disasm(b: bytes) -> str:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return " | ".join(f"{i.mnemonic} {i.op_str}" for i in md.disasm(b, 0))


def main() -> None:
    sd = tempfile.mkdtemp(prefix="apcdbg_")
    vic = subprocess.Popen([sys.executable, str(HERE / "victim.py"), sd],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = Path(sd) / f"{vic.pid}.json"
    for _ in range(60):
        if state.exists():
            break
        time.sleep(0.1)
    time.sleep(0.6)
    st = __import__("json").loads(state.read_text())
    target = st["tids"]["main"]
    print(f"victim pid={vic.pid} main_tid={target} tids={st['tids']}")

    p = AttachedProcess(vic.pid)
    for name, hexsc in VARIANTS.items():
        sc = bytes.fromhex(hexsc)
        print(f"\n=== {name} ({len(sc)} bytes) ===")
        print("   ", disasm(sc))
        arena = w.virtual_alloc_ex(p.handle, ARENA, 0x40)
        job = struct.pack("<5Q", TICK, 0, 0, 0, 0)
        job += struct.pack("<QQ", 0, 0)
        job += struct.pack("<Q", arena + STACK_TOP)
        job += struct.pack("<Q", 0)
        w.write_process_memory(p.handle, arena + JOB, job)
        w.write_process_memory(p.handle, arena + SC, sc)
        h = w.open_thread(target)
        ok = _k32.QueueUserAPC2(ctypes.c_void_p(arena + SC), h, arena + JOB, 1)
        w._k32.CloseHandle(h)
        mark = 0
        t0 = time.time()
        while time.time() - t0 < 2.0:
            try:
                mark = struct.unpack("<Q", p.memory.rpm(arena + MARK, 8))[0]
                if mark:
                    break
            except OSError as e:
                mark = -1
                print("    readback failed:", e)
                break
            time.sleep(0.005)
        try:
            res = struct.unpack("<Q", p.memory.rpm(arena + RESULT, 8))[0]
            tid = struct.unpack("<Q", p.memory.rpm(arena + TIDOFF, 8))[0]
            m50 = struct.unpack("<Q", p.memory.rpm(arena + 0x50, 8))[0]
            m58 = struct.unpack("<Q", p.memory.rpm(arena + 0x58, 8))[0]
        except OSError:
            res = tid = m50 = m58 = -1
        extra = f" m50={m50:#x} m58={m58:#x}" if (m50 or m58) else ""
        alive = vic.poll() is None
        print(f"    queued={bool(ok)} marker={mark:#x} result={res:#x} ran_on={tid} "
              f"dt={(time.time()-t0)*1000:.0f}ms{extra} victim_alive={alive}"
              f"{'' if alive else ' exit=' + str(vic.poll())}")
        if not alive:
            break

    if vic.poll() is None:
        vic.kill()
    print("\ndone.")


if __name__ == "__main__":
    main()
