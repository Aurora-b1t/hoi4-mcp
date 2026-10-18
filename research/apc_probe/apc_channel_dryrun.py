"""Dry run for the FULL APC command payload (operator new + blob copy + Post)
against a stand-in process — the pre-game protocol the 23 日 first live send
skipped, which cost a game process.

The stand-in provides two fake callees in its own RWX page:
  fake_new(size)            -> records size, returns a pool pointer
  fake_post(queue, cmd, f)  -> records its three arguments, returns 1

so every observable of the payload is verifiable without a game:
  claim flag, executing TID, blob copied to the returned "command" pointer,
  and the exact (queue, cmd, force) Post would receive.

Usage: python research/apc_probe/apc_channel_dryrun.py [--rounds 3]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4_mcp.inject.apc import (ApcChannel, SHELLCODE, JOB_SIZE, J_CLAIM,   # noqa: E402
                                    J_TID, J_DONE, J_CMD, J_POSTED, J_NEW, J_POST,
                                    J_QUEUE, J_SIZE, J_BLOB, J_NQWORD, J_STACK)
from hoi4_mcp.process import win32ext as w                                   # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess                          # noqa: E402

HERE = Path(__file__).resolve().parent
FAKE_BASE = 0x000
FAKE_POST = 0x100
META = 0x200
POOL = 0x300
FAKES_SIZE = 0x1000
PAGE_EXECUTE_READWRITE = 0x40

MAGIC_QUEUE = 0x1122334455667788
BLOB = bytes(range(0x38))


def fake_new(arena: int, deep: int = 0) -> bytes:
    """Returns a pool pointer; with deep>0 it also eats `deep` bytes of the
    private stack and dirties them — the game's real operator new + Post use
    real stack, and the first live send died in a way that smells like the
    callee walking over the job/blob that sit below the stack top."""
    body = bytes.fromhex("48B8") + struct.pack("<Q", arena + META)     # mov rax, meta
    body += bytes.fromhex("488908")                                    # mov [rax], rcx (size)
    if deep:
        words = deep // 8
        body += (bytes.fromhex("4881EC") + struct.pack("<I", deep)     # sub rsp, deep
                 + bytes.fromhex("4889E7")                             # mov rdi, rsp
                 + bytes.fromhex("48B84343434343434343")               # mov rax, 0x43...
                 + bytes.fromhex("48B9") + struct.pack("<Q", words)    # mov rcx, n words
                 + bytes.fromhex("F348AB")                             # rep stosq  (trash it all)
                 + bytes.fromhex("4881C4") + struct.pack("<I", deep))  # add rsp, deep
    return (body
            + bytes.fromhex("48B8") + struct.pack("<Q", arena + POOL)   # mov rax, pool
            + bytes.fromhex("C3"))


def fake_post(arena: int) -> bytes:
    return (bytes.fromhex("48B8") + struct.pack("<Q", arena + META)
            + bytes.fromhex("48894808")       # mov [rax+8], rcx  (queue)
            + bytes.fromhex("48895010")       # mov [rax+0x10], rdx (cmd)
            + bytes.fromhex("4C894018")       # mov [rax+0x18], r8 (force)
            + bytes.fromhex("48C74020ADDE0000")   # mov qword [rax+0x20], 0xDEAD
            + bytes.fromhex("B801000000")     # mov eax, 1
            + bytes.fromhex("C3"))


def disasm(b: bytes) -> str:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return " | ".join(f"{i.mnemonic} {i.op_str}" for i in md.disasm(b, 0))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--deep-stack", type=int, default=0,
                    help="bytes of stack the fake callee eats (tests whether the "
                         "private stack can reach the job/blob below it)")
    args = ap.parse_args()

    print(f"payload shellcode ({len(SHELLCODE)} bytes):")
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i in md.disasm(SHELLCODE, 0):
        print(f"   +{i.address:04x}: {i.mnemonic} {i.op_str}")

    sd = tempfile.mkdtemp(prefix="apcch_")
    vic = subprocess.Popen([sys.executable, str(HERE / "victim.py"), sd],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = Path(sd) / f"{vic.pid}.json"
    for _ in range(80):
        if state.exists():
            break
        time.sleep(0.1)
    time.sleep(0.6)
    st = json.loads(state.read_text())
    print(f"\nvictim pid={vic.pid} tids={st['tids']}")

    p = AttachedProcess(vic.pid)
    fakes = w.virtual_alloc_ex(p.handle, FAKES_SIZE, PAGE_EXECUTE_READWRITE)
    fn_new, fn_post = fakes + FAKE_BASE, fakes + FAKE_POST
    w.write_process_memory(p.handle, fakes + FAKE_BASE, fake_new(fakes, args.deep_stack))
    w.write_process_memory(p.handle, fakes + FAKE_POST, fake_post(fakes))
    print(f"fakes at {fakes:#x} (deep_stack={args.deep_stack})")
    print("  fake_new :", disasm(fake_new(fakes, args.deep_stack)))
    print("  fake_post:", disasm(fake_post(fakes)))

    ch = ApcChannel(p, timeout=3.0, per_thread_wait=0.4)
    ok_all = True
    for r in range(args.rounds):
        w.write_process_memory(p.handle, fakes + META, b"\0" * 0x40)
        w.write_process_memory(p.handle, fakes + POOL, b"\xcc" * 0x100)
        res = ch.run(fn_new, fn_post, MAGIC_QUEUE, len(BLOB), BLOB)
        time.sleep(0.05)
        meta = p.memory.rpm(fakes + META, 0x28)
        size_req, q_arg, cmd_arg, force_arg, magic = struct.unpack("<QQQQQ", meta)
        pool = p.memory.rpm(fakes + POOL, len(BLOB))
        raw = p.memory.rpm(res["slot"], JOB_SIZE)
        q = struct.unpack("<%dQ" % (JOB_SIZE // 8), raw)
        blob_src = res["slot"] + 0x100
        job_intact = (q[0] == fn_new and q[2] == fn_post and q[3] == MAGIC_QUEUE
                      and q[4] == len(BLOB) and q[5] == blob_src
                      and q[6] == (len(BLOB) + 7) // 8)
        checks = {
            "done": res.get("done") == 1,
            "claim": res.get("claim") == 1,
            "tid_valid": res.get("tid") not in (None, 0),
            "job_intact": job_intact,
            "size_arg": size_req == len(BLOB),
            "queue_arg": q_arg == MAGIC_QUEUE,
            "cmd_arg_is_pool": cmd_arg == fakes + POOL,
            "force_arg_zero": force_arg == 0,
            "post_returned": res.get("posted") == 1,
            "blob_copied": pool == BLOB,
            "victim_alive": vic.poll() is None,
        }
        bad = [k for k, v in checks.items() if not v]
        ok_all &= not bad
        print(f"\nround {r}: raw={ {k: (hex(v) if isinstance(v, int) else v) for k, v in res.items() if k != 'slot'} }")
        print(f"  meta: size={size_req:#x} queue={q_arg:#x} cmd={cmd_arg:#x} "
              f"force={force_arg:#x} magic={magic:#x}")
        print(f"  checks: " + ", ".join(f"{k}={'ok' if v else 'FAIL'}" for k, v in checks.items()))
        if bad:
            print(f"  FAILED: {bad}")
            print(f"  pool[:16]={pool[:16].hex()} expected={BLOB[:16].hex()}")
            # raw job dump for offset forensics
            raw = p.memory.rpm(res["slot"], JOB_SIZE)
            q = struct.unpack("<%dQ" % (JOB_SIZE // 8), raw)
            names = ["new", "claim", "post", "queue", "size", "blob", "nq", "stack",
                     "saved_rsp", "tid", "done", "cmd", "posted", "spare"]
            for i, (n, v) in enumerate(zip(names, q)):
                print(f"    job[{i:2d}] +{i*8:#04x} {n:10s} = {v:#018x}")
            break
        if not checks["victim_alive"]:
            break
    print(f"\nchannel stats: {ch.status()}")
    print("DRY RUN:", "GREEN" if ok_all else "FAIL")
    if vic.poll() is None:
        vic.kill()
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
