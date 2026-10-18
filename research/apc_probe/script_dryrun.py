"""script_dryrun.py — stand-in validation for the write-v3.1 VM payload.

The 23 日 rule is non-negotiable: a new payload runs green on a stand-in BEFORE
it ever touches the game. This harness spawns a disposable victim, builds fake
callees and fake data in the victim's own RWX page, and drives the VM through
every op and every failure mode it is supposed to survive:

  call-args   rcx/rdx/r8/r9 arrive exactly, RAX comes back
  read        target -> our data page (and back out through RPM)
  write       our data page -> target
  write_raw   sizes 1/2/4/8
  memset      fill a target range
  bad-op      status=1, victim alive
  deep-stack  a callee that eats 24 KB of the private stack cannot hurt the job
  overflow    a deliberate 32 KB callee DOES hit the job -> job_intact=False
  fault       a bad READ address faults inside the arena -> shield recovers
  null-call   `call 0` with the payload in flight -> shield recovers (the exact
              23 日 killer, now survivable)
  claim       one job queued at several threads runs exactly once

Two phases: phase A proves the fault scenarios really do kill a host with no
shield installed; phase B installs the shield and requires the victim to live.

Usage: python research/apc_probe/script_dryrun.py [--skip-phase-a]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import keystone                                                              # noqa: E402
from hoi4_mcp.inject import script as S                                   # noqa: E402
from hoi4_mcp.process import win32ext as w                                # noqa: E402
from hoi4_mcp.process.attach import AttachedProcess                       # noqa: E402

HERE = Path(__file__).resolve().parent
PAGE_EXECUTE_READWRITE = 0x40

FAKE_REC = 0x000
FAKE_INC = 0x200
FAKE_NULL = 0x300
FAKE_NEW = 0x380
FAKE_CTOR = 0x400
FAKE_POST = 0x500
FAKE_AV = 0x580
FAKE_REC8 = 0x600
FAKE_PTR = 0x700
FAKE_CTOR8 = 0x780
META = 0x800
SCRATCH = 0x900
POOL = 0xA00
FAKES_SIZE = 0x1000
PTR_TARGET = 0xB00          # holds a pointer VALUE the callee dereferences
PTR_VALUE = 0xDEADBEEFCAFEF00D

MAGIC = 0xFEEDFACE12345678
ARGS = (0x1111222233334444, 0x5555666677778888, 0x9999AAAABBBBCCCC, 0xDDDDEEEEFFFF0000)

_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def asm(src: str) -> bytes:
    code, _ = _KS.asm(src)
    return bytes(code)


def fake_rec(base: int, deep: int = 0) -> bytes:
    src = f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x00], rcx
    mov qword ptr [rax + 0x08], rdx
    mov qword ptr [rax + 0x10], r8
    mov qword ptr [rax + 0x18], r9
    mov qword ptr [rax + 0x28], 0x1234      // proof this code really ran
    """
    if deep:
        src += f"""
    sub rsp, {deep}
    mov rdi, rsp
    movabs rax, 0x4343434343434343
    mov rcx, {deep // 8}
    cld
    rep stosq
    add rsp, {deep}
        """
    src += f"""
    movabs rax, {MAGIC:#x}
    ret
    """
    return asm(src)


def fake_inc(base: int) -> bytes:
    return asm(f"""
    movabs rax, {base + META:#x}
    inc qword ptr [rax + 0x30]
    mov rax, qword ptr [rax + 0x30]
    ret
    """)


def fake_null() -> bytes:
    return asm("""
    xor eax, eax
    call rax
    ret
    """)


def fake_new(base: int) -> bytes:
    """operator new: records the requested size, returns the pool pointer."""
    return asm(f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x00], rcx
    movabs rax, {base + POOL:#x}
    ret
    """)


def fake_ctor(base: int, eat: int = 0) -> bytes:
    """ctor(this, a1, a2, a3): records rcx/rdx/r8/r9, returns this.

    `this` is parked in rbx because the deep-stack branch runs `rep stosq`,
    which walks rcx down to zero (a test-harness bug that looked like a payload
    bug on the first run: the object pointer came back as 0).
    """
    src = f"""
    push rbx
    mov rbx, rcx
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x08], rcx
    mov qword ptr [rax + 0x10], rdx
    mov qword ptr [rax + 0x18], r8
    mov qword ptr [rax + 0x20], r9
    """
    if eat:
        src += f"""
    sub rsp, {eat}
    mov rdi, rsp
    movabs rax, 0x4343434343434343
    mov rcx, {eat // 8}
    cld
    rep stosq
    add rsp, {eat}
        """
    src += """
    mov rax, rbx
    pop rbx
    ret
    """
    return asm(src)


def fake_ctor8(base: int) -> bytes:
    """ctor(this, a1, a2, a3, stack): records the 5th argument off the stack.

    Frame layout: the payload calls the ctor with the 5th argument at
    [rsp+0x28] (its own frame: +0x20 plus the pushed return address); after this
    function's `push rbx` the same slot is [rsp+0x30].
    """
    return asm(f"""
    push rbx
    mov rbx, rcx
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x08], rcx
    mov qword ptr [rax + 0x10], rdx
    mov qword ptr [rax + 0x18], r8
    mov qword ptr [rax + 0x20], r9
    mov r10, qword ptr [rsp + 0x30]
    mov qword ptr [rax + 0x28], r10
    mov rax, rbx
    pop rbx
    ret
    """)


def fake_post(base: int) -> bytes:
    """Mirrors the REAL Post ABI: Post(queue, cmd, force) = rcx, rdx, r8.

    The first version of this fake assumed rcx=obj (the VM's call_this order),
    so the harness happily validated a wrong calling convention — and the live
    game died inside Post. A fake is only as good as the ABI it mirrors.
    """
    return asm(f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x28], rcx
    mov qword ptr [rax + 0x30], rdx
    mov qword ptr [rax + 0x38], r8
    mov eax, 1
    ret
    """)


def fake_av(base: int) -> bytes:
    """A callee that takes an access violation (the crash class the in-call
    shield rule exists for).

    NB: `mov byte ptr [0x20], 1` assembles RIP-relative (keystone turned it into
    `[rip+0x19]`, i.e. a harmless write inside our own page) — write through a
    register instead.
    """
    return asm("""
    movabs rax, 0x20
    mov byte ptr [rax], 1
    ret
    """)


ARGS8 = (0x1111222233334444, 0x5555666677778888, 0x9999AAAABBBBCCCC,
         0xDDDDEEEEFFFF0000, 0x0102030405060708, 0xA1A2A3A4A5A6A7A8,
         0xB1B2B3B4B5B6B7B8, 0xC1C2C3C4C5C6C7C8)


def fake_rec8(base: int) -> bytes:
    """An 8-argument callee shape (4 registers + 4 stack slots).

    It records the four register arguments and the four stack slots. Nothing
    stages stack arguments any more, so those slots must read as zero — i.e. the
    payload neither drops a register argument nor invents a stack one.
    """
    slots = [f"[rsp + {0x28 + 8 * i:#x}]" for i in range(4)]
    saves = "\n".join(
        f"mov r10, {s}\n    mov qword ptr [rax + {0x40 + 8 * i:#x}], r10"
        for i, s in enumerate(slots))
    return asm(f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x00], rcx
    mov qword ptr [rax + 0x08], rdx
    mov qword ptr [rax + 0x10], r8
    mov qword ptr [rax + 0x18], r9
    movabs rax, {base + META:#x}
{saves}
    movabs rax, {MAGIC:#x}
    ret
    """)


def fake_ptr_probe(base: int, value: int) -> bytes:
    """A callee whose 5th argument (stack) must be a POINTER: it records both the
    pointer it was handed and the value it finds behind it."""
    return asm(f"""
    movabs rax, {base + META:#x}
    mov r10, qword ptr [rsp + 0x28]
    mov qword ptr [rax + 0x00], r10
    mov r10, qword ptr [r10]
    mov qword ptr [rax + 0x08], r10
    movabs rax, {MAGIC:#x}
    ret
    """)


class Victim:
    def __init__(self, label: str):
        self.dir = tempfile.mkdtemp(prefix=f"dryrun_{label}_")
        self.proc = subprocess.Popen([sys.executable, str(HERE / "victim.py"), self.dir],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state = Path(self.dir) / f"{self.proc.pid}.json"
        for _ in range(80):
            if state.exists():
                break
            time.sleep(0.1)
        time.sleep(0.6)
        # the victim writes this file itself; on Windows the handle can still be
        # held for a moment after the path appears (shared-mode retry)
        for _ in range(40):
            try:
                self.state = json.loads(state.read_text())
                break
            except (PermissionError, json.JSONDecodeError):
                time.sleep(0.1)
        else:
            raise RuntimeError(f"victim {self.proc.pid} never published {state}")
        self.p = AttachedProcess(self.proc.pid)
        self.fakes = w.virtual_alloc_ex(self.p.handle, FAKES_SIZE, PAGE_EXECUTE_READWRITE)
        w.write_process_memory(self.p.handle, self.fakes + FAKE_REC, fake_rec(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_INC, fake_inc(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_NULL, fake_null())
        w.write_process_memory(self.p.handle, self.fakes + FAKE_NEW, fake_new(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_CTOR, fake_ctor(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_POST, fake_post(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_AV, fake_av(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_REC8, fake_rec8(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_PTR,
                               fake_ptr_probe(self.fakes, PTR_VALUE))
        w.write_process_memory(self.p.handle, self.fakes + FAKE_CTOR8,
                               fake_ctor8(self.fakes))
        w.write_process_memory(self.p.handle, self.fakes + SCRATCH, b"\xcc" * 0x100)
        w.write_process_memory(self.p.handle, self.fakes + PTR_TARGET,
                               struct.pack("<Q", PTR_VALUE))

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def meta(self, n: int = 0x40) -> bytes:
        return self.p.memory.rpm(self.fakes + META, n)

    def scratch(self, n: int = 0x40) -> bytes:
        return self.p.memory.rpm(self.fakes + SCRATCH, n)

    def poke(self, off: int, data: bytes) -> None:
        w.write_process_memory(self.p.handle, self.fakes + off, data)

    def kill(self) -> None:
        if self.alive:
            self.proc.kill()


class Runner:
    def __init__(self, victim: Victim, shield: bool):
        self.v = victim
        self.ch = S.ScriptChannel(victim.p, timeout=3.0)
        self.shield = shield
        if shield:
            self.install = self.ch.install_shield()
        self.results: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, bool(ok), detail))
        print(f"  [{'ok ' if ok else 'FAIL'}] {name:22s} {detail}")
        return bool(ok)

    # -- scenarios -------------------------------------------------------------
    def sc_call_args(self) -> None:
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.call(self.v.fakes + FAKE_REC, *ARGS)
        r = self.ch.run(sc)
        meta = self.v.meta()
        got = struct.unpack("<4Q", meta[:0x20])
        self.check("call-args", r["done"] and r["status"] == 0 and r["results"][i] == MAGIC
                   and got == ARGS and struct.unpack_from("<Q", meta, 0x28)[0] == 0x1234,
                   f"done={r['done']} status={r['status']} rax={r['results'][i]:#x} "
                   f"args={'match' if got == ARGS else got}")

    def sc_read(self) -> None:
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        sc.call(self.v.fakes + FAKE_REC, *ARGS)
        j = len(sc.ops)
        sc.read(self.v.fakes + META, 0x20)
        r = self.ch.run(sc)
        self.check("read", r["local"].get(j) == self.v.meta(0x20) and r["status"] == 0,
                   f"{r['local'].get(j, b'')[:8].hex()} == victim meta")

    def sc_write(self) -> None:
        sc = S.Script()
        payload = bytes(range(16))
        sc.write(self.v.fakes + SCRATCH + 0x20, payload)
        r = self.ch.run(sc)
        back = self.v.scratch(0x40)[0x20:0x30]
        self.check("write", back == payload and r["status"] == 0,
                   f"target[{0x20:#x}:] = {back.hex()}")

    def sc_write_raw(self) -> None:
        sc = S.Script()
        for i, (size, value) in enumerate(((1, 0xAB), (2, 0xBEEF), (4, 0xDEADBEEF),
                                           (8, 0x0123456789ABCDEF))):
            sc.write_raw(self.v.fakes + SCRATCH + i * 8, value, size)
        r = self.ch.run(sc)
        b = self.v.scratch(0x40)
        expect = (b"\xab" + b"\xcc" * 7 + b"\xef\xbe" + b"\xcc" * 6
                  + struct.pack("<I", 0xDEADBEEF) + b"\xcc" * 4
                  + struct.pack("<Q", 0x0123456789ABCDEF))
        self.check("write_raw 1/2/4/8", b[:0x20] == expect and r["status"] == 0,
                   b[:0x20].hex())

    def sc_memset(self) -> None:
        sc = S.Script()
        sc.memset(self.v.fakes + SCRATCH + 0x40, 0x5A, 32)
        r = self.ch.run(sc)
        b = self.v.scratch(0x80)[0x40:0x60]
        self.check("memset", b == b"\x5a" * 32 and r["status"] == 0, b[:8].hex())

    def sc_bad_op(self) -> None:
        sc = S.Script()
        sc.ops.append(S.Op(5, 1, 2, 3))
        r = self.ch.run(sc)
        self.check("bad-op status", r["done"] == 1 and r["status"] == 1 and self.v.alive,
                   f"status={r['status']} alive={self.v.alive}")

    def sc_alloc_ctor(self) -> None:
        """The ctor-faithful path (24 日): new -> real ctor -> Post(obj, ...),
        all in ONE delivery, with the object carried between the ops.

        The fake Post mirrors the real ABI (rcx=queue, rdx=cmd, r8=force), so
        this also pins the *register slot* of the object: slot 1 = rdx."""
        self.v.poke(META, b"\0" * 0x40)
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.alloc_ctor(self.v.fakes + FAKE_NEW, self.v.fakes + FAKE_CTOR, 0x38,
                          0xAAAA, 0xBBBB, 0xCCCC)
        j = sc.call_obj(self.v.fakes + FAKE_POST, 1, 0x1122334455667788, 0)
        r = self.ch.run(sc)
        q = struct.unpack("<8Q", self.v.meta())
        size, obj_in, a1, a2, a3, post_rcx, post_rdx, post_r8 = q
        obj = r["results"][i]
        checks = {
            "size": size == 0x38,
            "obj_from_new": obj == self.v.fakes + POOL,
            "ctor_this": obj_in == obj,
            "ctor_args": (a1, a2, a3) == (0xAAAA, 0xBBBB, 0xCCCC),
            "post_rcx_is_queue": post_rcx == 0x1122334455667788,
            "post_rdx_is_obj": post_rdx == obj,
            "post_r8_is_force": post_r8 == 0,
            "post_ret": r["results"][j] == 1,
            "status": r["status"] == 0,
        }
        bad = [k for k, v in checks.items() if not v]
        self.check("alloc_ctor -> call_obj", not bad,
                   f"obj={obj:#x} " + ", ".join(f"{k}={'ok' if v else 'FAIL'}"
                                                for k, v in checks.items()))

    def sc_call_args8(self) -> None:
        """The retired 4+ argument path must be REFUSED, not silently truncated
        (24 日's trap: the payload ignored everything past r9)."""
        self.v.poke(META + 0x80, b"\0" * 0x20)   # clear the recorded stack slots
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        try:
            sc.call(self.v.fakes + FAKE_REC8, *ARGS8)
            refused = False
        except S.ScriptError:
            refused = True
        # four arguments still work, and an 8-argument callee must see the first
        # four in registers and zero on the stack
        sc4 = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc4.call(self.v.fakes + FAKE_REC8, *ARGS8[:4])
        r = self.ch.run(sc4)
        meta = self.v.meta(0x80)
        regs = struct.unpack_from("<4Q", meta, 0x00)
        stack = struct.unpack_from("<4Q", meta, 0x40)
        ok = (refused and r["done"] and r["status"] == 0
              and r["results"][i] == MAGIC and regs == ARGS8[:4]
              and stack == (0, 0, 0, 0))
        self.check("5+ args refused / 4 in registers", ok,
                   f"refused={refused} regs={'ok' if regs == ARGS8[:4] else regs} "
                   f"stack={stack}")
    def sc_stack_pointer_arg(self) -> None:
        """A read_ptr value used as a REGISTER argument is the address of our
        local copy — the `&value` shape a ctor like SetResearch's wants (the
        game writes through it). The read must run BEFORE the consumer."""
        self.v.poke(META, b"\0" * 0x20)
        target = self.v.fakes + PTR_TARGET
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        ref = sc.read_ptr(target)
        i = sc.call(self.v.fakes + FAKE_CTOR8, ref, 2, 3, 4)
        r = self.ch.run(sc)
        _r9, got_rcx, got_rdx, got_r8, _a5 = struct.unpack("<5Q", self.v.meta(0x28))
        local = r["local"].get(ref.op)
        want = S.BUF_BASE + (r.get("page") or 0)
        ok = (r["done"] and r["status"] == 0 and got_rcx == want
              and local == struct.pack("<Q", PTR_VALUE))
        self.check("read_ptr -> &local buffer", ok,
                   f"callee rcx={got_rcx:#x} (want {want:#x}) "
                   f"read_ptr local={local.hex() if local else None} "
                   f"rdx={got_rdx:#x}")

    def sc_ctor_stack_args(self) -> None:
        """The ctor path with all four of its arguments: this + rdx/r8/r9, in the
        game's own constructor, with the object carried to call_obj."""
        self.v.poke(META, b"\0" * 0x60)
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.alloc_ctor(self.v.fakes + FAKE_NEW, self.v.fakes + FAKE_CTOR8, 0x38,
                          0xAAAA, 0xBBBB, 0xCCCC)
        r = self.ch.run(sc)
        q = struct.unpack("<8Q", self.v.meta())
        size, obj_in, a1, a2, a3, a4 = q[:6]
        obj = r["results"][i]
        ok = (r["status"] == 0 and obj == self.v.fakes + POOL and obj_in == obj
              and (size, a1, a2, a3) == (0x38, 0xAAAA, 0xBBBB, 0xCCCC)
              and a4 == 0)
        self.check("ctor 3 args + this", ok,
                   f"size={size:#x} this={'ok' if obj_in == obj else hex(obj_in)} "
                   f"rdx/r8/r9={(a1, a2, a3)} r9_extra={a4:#x}")

    def sc_fault_in_callee(self) -> None:
        """A callee that AVs while `g_in_call` is set must be taken over by the
        shield: the fault RIP is in the FAKES page (not our arena), so only the
        in-call rule can save the host — this is the 24 日 live crash, offline."""
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        sc.call(self.v.fakes + FAKE_AV)
        r = self.ch.run(sc)
        in_fakes = self.v.fakes <= r["fault_rip"] < self.v.fakes + FAKES_SIZE
        self.check("fault inside callee", r["done"] == 1 and r["status"] == 2
                   and in_fakes and self.v.alive,
                   f"rip={r['fault_rip']:#x} (fakes {self.v.fakes:#x}) "
                   f"code={r['fault_code']:#x} alive={self.v.alive}")

    def sc_alloc_ctor_deep(self, eat: int = 0x6000) -> None:
        """A constructor deeper than the old 3.8 KB stack: 23 日's collision."""
        w.write_process_memory(self.v.p.handle, self.v.fakes + FAKE_CTOR,
                               fake_ctor(self.v.fakes, eat))
        self.v.poke(META, b"\0" * 0x40)
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.alloc_ctor(self.v.fakes + FAKE_NEW, self.v.fakes + FAKE_CTOR, 0x38,
                          1, 2, 3)
        r = self.ch.run(sc)
        # `status` and `job_intact` are themselves job fields: once the callee
        # walks over the job they are garbage, so the *result* is the evidence
        ok = r["results"][i] == self.v.fakes + POOL if r.get("results") else False
        self.check(f"ctor stack {eat // 1024}KB", ok,
                   f"obj={r['results'][i] if r.get('results') else None} "
                   f"intact={r.get('job_intact')} status={r.get('status')}")
        w.write_process_memory(self.v.p.handle, self.v.fakes + FAKE_CTOR,
                               fake_ctor(self.v.fakes))

    def sc_claim(self) -> None:
        self.v.poke(META + 0x30, b"\0" * 8)
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.call(self.v.fakes + FAKE_INC)
        r = self.ch.run(sc)
        counter = struct.unpack_from("<Q", self.v.meta(), 0x30)[0]
        self.check("claim single-use", r["results"][i] == 1 and counter == 1,
                   f"counter={counter} (queued at up to 7 threads)")

    def sc_deep_stack(self, deep: int = 0x6000, expect_job_intact: bool = True) -> None:
        w.write_process_memory(self.v.p.handle, self.v.fakes + FAKE_REC, fake_rec(self.v.fakes, deep))
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        i = sc.call(self.v.fakes + FAKE_REC, *ARGS)
        r = self.ch.run(sc)
        rax = r["results"][i] if r.get("results") else None
        # a callee that walks over the job also destroys the status/done fields,
        # so the callee's own return value is the evidence that matters
        ok = rax == MAGIC
        self.check(f"stack {deep // 1024}KB", ok,
                   f"rax={rax if rax is None else hex(rax)} "
                   f"job_intact={r.get('job_intact')}")
        w.write_process_memory(self.v.p.handle, self.v.fakes + FAKE_REC, fake_rec(self.v.fakes))

    def sc_fault_read(self) -> None:
        sc = S.Script()
        sc.read(0x10, 8)                      # unmapped low page -> VM's rep movsb faults
        r = self.ch.run(sc)
        in_arena = self.ch.code <= r["fault_rip"] < self.ch.code + S.CODE_ARENA_SIZE
        self.check("fault-in-arena", r["done"] == 1 and r["status"] == 2 and in_arena
                   and self.v.alive,
                   f"status={r['status']} rip={r['fault_rip']:#x} "
                   f"code={r['fault_code']:#x} alive={self.v.alive}")

    def sc_null_call(self) -> None:
        sc = S.Script(allow_calls={(0, 1)})
        sc.call(0)
        r = self.ch.run(sc)
        self.check("null-call shielded", r["done"] == 1 and r["status"] == 2 and self.v.alive,
                   f"status={r['status']} rip={r['fault_rip']:#x} alive={self.v.alive}")

    def sc_null_call_via_fake(self) -> None:
        """The 23 日 shape: our call returns into a callee that calls null."""
        sc = S.Script(allow_calls={(self.v.fakes, self.v.fakes + FAKES_SIZE)})
        sc.call(self.v.fakes + FAKE_NULL)
        r = self.ch.run(sc)
        self.check("null-in-callee", r["done"] == 1 and r["status"] == 2 and self.v.alive,
                   f"status={r['status']} rip={r['fault_rip']:#x} alive={self.v.alive}")


def phase_a() -> bool:
    print("\n== phase A: no shield, the fault scenarios must be lethal ==")
    v = Victim("noshield")
    print(f"victim pid={v.proc.pid} fakes={v.fakes:#x}")
    try:
        r = Runner(v, shield=False)
        try:
            r.sc_null_call_via_fake()
        except OSError as exc:
            print(f"  (the channel noticed the victim vanishing: {exc})")
        time.sleep(0.5)
        dead = not v.alive
        print(f"  [{'ok ' if dead else 'FAIL'}] victim died without the shield "
              f"(exit={v.proc.poll()})")
        return dead
    finally:
        v.kill()


def phase_b(skip_a: bool) -> int:
    print("\n== phase B: shield installed, every op and every fault must survive ==")
    v = Victim("shield")
    print(f"victim pid={v.proc.pid} fakes={v.fakes:#x}")
    scenarios = ("sc_call_args", "sc_call_args8", "sc_stack_pointer_arg",
                 "sc_ctor_stack_args", "sc_read", "sc_write", "sc_write_raw",
                 "sc_memset", "sc_bad_op", "sc_claim", "sc_alloc_ctor",
                 "sc_fault_in_callee", "sc_fault_read",
                 "sc_null_call", "sc_null_call_via_fake")
    try:
        r = Runner(v, shield=True)
        print(f"  shield: {r.install}")
        for name in scenarios:
            try:
                getattr(r, name)()
            except OSError as exc:
                r.check(name, False, f"target vanished: {exc}")
                break
        alive = v.alive
        print(f"  [{'ok ' if alive else 'FAIL'}] victim alive at the end of phase B")
        print(f"\nchannel stats: {r.ch.status()}")
        bad = [n for n, ok, _ in r.results if not ok] + ([] if alive else ["alive"])
        print("DRY RUN (phase B):", "GREEN" if not bad else f"FAIL {bad}")
        return 0 if not bad else 1
    finally:
        v.kill()


def phase_c() -> int:
    """The stack-flood scenarios get a FRESH victim each: walking 24-32 KB over
    the private stack also walks over the slot's job, so the arena is spent
    afterwards and any later send would look dead (that is the scenario's
    point, not a bug — but it cannot share a process with the others)."""
    print("\n== phase C: private-stack floods (one fresh victim each) ==")
    bad = []
    # the private stack has STACK_TOP - JOB_SIZE of headroom: 12 KB stays clear
    # of the job, 24 KB does not
    for deep, expect_intact in ((0x3000, True), (0x6000, False)):
        v = Victim(f"flood{deep // 1024}")
        try:
            r = Runner(v, shield=True)
            r.sc_deep_stack(deep=deep, expect_job_intact=expect_intact)
            alive = v.alive
            print(f"  [{'ok ' if alive else 'FAIL'}] victim alive after the "
                  f"{deep // 1024}KB callee")
            bad += [n for n, ok, _ in r.results if not ok] + \
                   ([] if alive else [f"alive-{deep}"])
        finally:
            v.kill()
    # the same flood through the ctor path
    v = Victim("floodctor")
    try:
        r = Runner(v, shield=True)
        r.sc_alloc_ctor_deep(eat=0x3000)
        alive = v.alive
        print(f"  [{'ok ' if alive else 'FAIL'}] victim alive after a 12KB ctor")
        bad += [n for n, ok, _ in r.results if not ok] + ([] if alive else ["alive-ctor"])
    finally:
        v.kill()
    print("DRY RUN (phase C):", "GREEN" if not bad else f"FAIL {bad}")
    return 0 if not bad else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-phase-a", action="store_true")
    ap.add_argument("--skip-phase-c", action="store_true")
    a = ap.parse_args()
    a_ok = True if a.skip_phase_a else phase_a()
    b = phase_b(a.skip_phase_a)
    c = 0 if a.skip_phase_c else phase_c()
    return 0 if (a_ok and b == 0 and c == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
