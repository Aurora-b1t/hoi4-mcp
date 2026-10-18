"""script.py — write v3.1: a micro-VM payload for the APC channel.

Why this exists
---------------
`apc.py` ships a *fixed* payload: operator new -> copy blob -> Post. That is
exactly one shape of write (post one player command). Everything else the write
layer will ever need — calling a command constructor, calling a getter to read a
game object from the game's own thread, patching two fields of a live struct
between two calls, copying a struct out to inspect it — needs a payload that can
run a *sequence* of memory operations on a game thread.

This module assembles that payload (keystone) and drives it:

    op 0  END
    op 1  CALL(func, a0=target, a1=0, a2/a3/a4/a5 = rcx/rdx/r8/r9)
          -> RAX stored in the op's result slot. Four register arguments is the
             whole budget: the stack-argument path was removed on 25 日 (it never
             worked inside the VM — see Script._stack_block / `STACK_ARGS` note).
    op 2  WRITE_RAW(addr, value, size) -> size in {1,2,4,8}
    op 3  READ(dst_local, src_target, size)   target -> our data page
    op 4  WRITE(dst_target, src_local, size)  our data page -> target
    op 6  MEMSET(dst_target, byte, size)
    op 7  ALLOC_CTOR(new, ctor, size, a1, a2, a3)
          -> obj = new(size); ctor(obj, a1, a2, a3); obj kept for op 8
    op 8  CALL_OBJ(func, slot, a1, a2, a3, len)
          -> func(*args) with the op-7 object substituted into register
             argument `slot` (0=rcx, 1=rdx, 2=r8, 3=r9); `len` is the number of
             register arguments given (1..4) and the first `len-1` of them come
             from a1/a2/a3

Register arguments are passed straight through; there is no stack-argument
path (25 日): a command whose constructor reads a fifth argument from the
caller's stack cannot go through ALLOC_CTOR — post it with the blob path
instead, which writes every field explicitly (see `SetResearch`, 26 日).

Ops 7/8 exist because of the 24 日 crash: a hand-built blob reproduced the
command's *vtable* but not its *field layout* (the note's ctor belonged to a
different class), and the game AV'd while describing the command. Calling the
real constructor is the only ctor-faithful way to build an object.

`slot` exists because of the 24 日 *second* crash: Post's signature is
Post(queue, cmd, force), i.e. the object belongs in rdx — an earlier
"call_this" that always put it in rcx handed Post the queue as the command and
killed the game inside Post.

Layout (three allocations, each with one job):
  * code arena  : shellcode + one private-stack slot per send (stride 0x8000)
  * data arena  : one 8 KB page per send: header + ops + local buffers
  * the job sits at the bottom of its slot and is claimed with one atomic xchg

Safety carried over from apc.py and hardened:
  * the payload NEVER re-reads the job after the first call — job inputs are
    prefetched into callee-saved registers (23 日: a callee walked over the job
    and turned the send into `call 0`),
  * the op list lives in a *separate* allocation from the private stack, so a
    deep callee cannot walk over the program it is executing,
  * CALL targets are checked against a whitelist (game image / explicit modules)
    before anything is written into the target process,
  * one atomic claim per job: duplicate deliveries are no-ops,
  * `job_intact` readback of the INPUT fields, exactly like apc.py.

The 0x8000 slot gives 31.7 KB of private stack (vs 15.6 KB) because the VM may
call arbitrary game functions whose frames are deeper than operator new.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import struct
import time

try:
    import keystone
except ImportError:  # pragma: no cover - keystone is a hard dependency now
    keystone = None

from ..process import win32ext as w

log = logging.getLogger(__name__)

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.QueueUserAPC.restype = wt.DWORD
_k32.QueueUserAPC.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t]
HAVE_APC2 = hasattr(_k32, "QueueUserAPC2")
if HAVE_APC2:
    _k32.QueueUserAPC2.restype = wt.BOOL
    _k32.QueueUserAPC2.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t, ctypes.c_int]
QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1

# --- code arena --------------------------------------------------------------
SC_OFF = 0x0000             # the VM shellcode
JOB_BASE = 0x1000           # first job slot (job at slot+0, stack above it)
SLOT_STRIDE = 0x8000        # 32 KB per send: job + private stack
STACK_TOP = 0x4000          # runs DOWN from here (RSP % 16 == 0); the headroom
                            # above it absorbs the gaps of a real call chain
CODE_ARENA_SIZE = 0x200000  # 2 MB -> 255 slots, never freed

# --- data arena (ops + local buffers, one 16 KB page per send) ---------------
# Page map:  hdr 0x0000 | ops 0x0040..0x1040 | stack blocks 0x1000..0x1400
#            | local buffers 0x1400..0x4000
# (a run-time Ref needs no region of its own: it resolves to the producer's own
# result field, which lives inside the op record)
DATA_PAGE = 0x4000
DATA_ARENA_SIZE = 0x100000  # 1 MB -> 64 sends
MAX_OPS = 64
STACK_BASE = 0x1000         # stack-argument blocks (up to 8 qwords per call)
MAX_STACK_BLOCKS = 64
BUF_BASE = 0x1400           # local buffers, after the static area
BUF_END = DATA_PAGE         # buffers must end before the page end (base..end)

#: set on a *stack* operand that holds the address of a value we own: the payload
#: dereferences it once, so the callee receives the pointer itself (read_ptr) or
#: the address of a local copy (the `&tag` shape a command ctor wants).
DEREF_FLAG = 1 << 63

D_MAGIC = 0x00
D_NOPS = 0x08
D_STATUS = 0x10             # written by the payload: 0 ok, 1 bad op, 2 faulted
D_FAULT_RIP = 0x18
D_FAULT_OP = 0x20
D_OPS = 0x40
MAGIC = 0x5343524950543031  # "SCRPT01"

OP_SIZE = 0x40
OP_CODE, OP_A0, OP_A1, OP_A2, OP_A3, OP_A4, OP_RES, OP_A5 = (
    0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38)

OP_END, OP_CALL, OP_WRITE_RAW, OP_READ, OP_WRITE, OP_MEMSET, OP_ALLOC_CTOR, \
    OP_CALL_OBJ = 0, 1, 2, 3, 4, 6, 7, 8

# --- job layout (job-relative) ----------------------------------------------
S_DATA = 0x00               # data page VA (script pointer)
S_CLAIM = 0x08              # atomic single-use claim
S_STACK = 0x10              # private stack top
S_SAVED_RSP = 0x18          # payload output
S_TID = 0x20                # payload output
S_DONE = 0x28               # payload output
S_STATUS = 0x30             # payload output: 0 ok, 1 bad op, 2 faulted
S_NOPS_DONE = 0x38          # payload output
S_FAULT_RIP = 0x40          # payload output (shield)
S_FAULT_CODE = 0x48         # payload output (shield)
S_LAST_RAX = 0x50           # payload output
S_FAULT_R13 = 0x58          # payload output (shield): VM op pointer at fault
S_JOB_SIZE = 0x60

INPUT_FIELDS = (S_DATA, S_STACK)

PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04

_ASM = r"""
vm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbx, rcx                      // job
    mov rax, 1
    xchg qword ptr [rbx + 8], rax     // atomic single-use claim
    test rax, rax
    jnz epilogue
    mov rax, qword ptr gs:[0x48]      // TEB->ClientId.UniqueThread
    mov qword ptr [rbx + 0x20], rax
    mov qword ptr [rip + g_cur_job], rbx
    mov r12, qword ptr [rbx + 0x00]   // data page (never touched by the stack)
    mov qword ptr [rbx + 0x30], 0     // status = ok
    mov qword ptr [rbx + 0x38], 0     // ops done
    mov qword ptr [rbx + 0x50], 0     // last rax
    mov qword ptr [rbx + 0x18], rsp   // save caller rsp
    mov rsp, qword ptr [rbx + 0x10]   // private stack
    sub rsp, 0x200                    // shadow room + the 8 stack-argument slots
    lea r13, [r12 + 0x40]             // first op
    mov r14, qword ptr [r12 + 0x08]   // op count
loop:
    test r14, r14
    jz done
    mov rax, qword ptr [r13 + 0x00]
    cmp rax, 0
    je done
    cmp rax, 1
    je op_call
    cmp rax, 2
    je op_write_raw
    cmp rax, 3
    je op_read
    cmp rax, 4
    je op_write
    cmp rax, 6
    je op_memset
    cmp rax, 7
    je op_alloc_ctor
    cmp rax, 8
    je op_call_obj
    mov qword ptr [rbx + 0x30], 1     // unknown op -> status 1
    jmp done
op_call:
    // op-1 layout: a0 = target, a1 unused, a2..a5 = rcx/rdx/r8/r9
    // (op records are [code, a0, a1, a2, a3, a4, RESULT, a5], so r9 reads a5)
    // rcx is parked in rbp: the payload restores it right before the call, and
    // rbp is callee-saved, so nothing we call can disturb it.
    mov rbp, qword ptr [r13 + 0x18]   // a2, parked: rbp is callee-saved
    mov rcx, qword ptr [r13 + 0x18]
    mov rdx, qword ptr [r13 + 0x20]
    mov r8,  qword ptr [r13 + 0x28]
    mov r9,  qword ptr [r13 + 0x38]
call_args_ready:
    mov rcx, rbp                      // a2 (in case anything above clobbered it)
    mov rax, qword ptr [r13 + 0x08]   // function pointer (op a0)
    mov qword ptr [rip + g_in_call], 1
    call rax
    mov qword ptr [rip + g_in_call], 0
    mov qword ptr [r13 + 0x30], rax
    mov qword ptr [rbx + 0x50], rax
    jmp next
op_write_raw:
    mov rdi, qword ptr [r13 + 0x08]
    mov rax, qword ptr [r13 + 0x10]
    mov rcx, qword ptr [r13 + 0x18]
    cmp rcx, 8
    je wr8
    cmp rcx, 4
    je wr4
    cmp rcx, 2
    je wr2
    mov byte ptr [rdi], al
    jmp next
wr2:
    mov word ptr [rdi], ax
    jmp next
wr4:
    mov dword ptr [rdi], eax
    jmp next
wr8:
    mov qword ptr [rdi], rax
    jmp next
op_read:
    mov rdi, qword ptr [r13 + 0x08]   // local dst
    mov rsi, qword ptr [r13 + 0x10]   // target src
    mov rcx, qword ptr [r13 + 0x18]
    cld
    rep movsb
    jmp next
op_write:
    mov rdi, qword ptr [r13 + 0x08]   // target dst
    mov rsi, qword ptr [r13 + 0x10]   // local src
    mov rcx, qword ptr [r13 + 0x18]
    cld
    rep movsb
    jmp next
op_memset:
    mov rdi, qword ptr [r13 + 0x08]
    mov rax, qword ptr [r13 + 0x10]
    mov rcx, qword ptr [r13 + 0x18]
    cld
    rep stosb
    jmp next
op_alloc_ctor:
    // op-7 layout: a0 = operator new, a1 = ctor, a2..a4 = rdx/r8/r9,
    // a5 = object size << 40
    mov r10, qword ptr [r13 + 0x08]   // operator new
    mov rcx, qword ptr [r13 + 0x38]
    shr rcx, 40                       // object size (top 24 bits of a5)
    mov qword ptr [rip + g_in_call], 1
    call r10
    mov qword ptr [rip + g_in_call], 0
    mov qword ptr [rip + g_last_obj], rax
    mov qword ptr [rbx + 0x50], rax
    test rax, rax
    jz ac_done
    mov rcx, rax                      // this
    mov rdx, qword ptr [r13 + 0x18]   // a2
    mov r8,  qword ptr [r13 + 0x20]   // a3
    mov r9,  qword ptr [r13 + 0x28]   // a4
    mov rax, qword ptr [r13 + 0x10]   // a1 = ctor
    mov qword ptr [rip + g_in_call], 1
    call rax
    mov qword ptr [rip + g_in_call], 0
ac_done:
    mov qword ptr [r13 + 0x30], rax
    jmp next
op_call_obj:
    // func(s0, s1, s2, s3) with the op-7 object substituted into the register
    // named by `slot` (the operand also carries 16 * explicit-argument count)
    mov r10, qword ptr [r13 + 0x10]   // slot + 16 * count
    mov rax, r10
    and rax, 15
    shr r10, 4
    cmp rax, 1
    jne co_s2
    mov r10, 1
    jmp co_slot
co_s2:
    cmp rax, 2
    jne co_s3
    mov r10, 2
    jmp co_slot
co_s3:
    cmp rax, 3
    jne co_s0
    mov r10, 3
    jmp co_slot
co_s0:
    xor eax, eax
co_slot:
    mov rcx, qword ptr [r13 + 0x18]
    mov rdx, qword ptr [r13 + 0x20]
    mov r8,  qword ptr [r13 + 0x28]
    mov r9,  qword ptr [r13 + 0x30]
    mov r11, qword ptr [rip + g_last_obj]
    test rax, rax
    jnz co_1
    mov rcx, r11
    jmp co_go
co_1:
    cmp rax, 1
    jne co_2
    mov rdx, r11
    jmp co_go
co_2:
    cmp rax, 2
    jne co_3
    mov r8, r11
    jmp co_go
co_3:
    mov r9, r11
co_go:
    mov rax, qword ptr [r13 + 0x08]
    mov qword ptr [rip + g_in_call], 1
    call rax
    mov qword ptr [rip + g_in_call], 0
    mov qword ptr [r13 + 0x30], rax
    mov qword ptr [rbx + 0x50], rax
    jmp next
next:
    add r13, 0x40
    dec r14
    inc qword ptr [rbx + 0x38]
    jmp loop
done:
    mov qword ptr [rip + g_cur_job], 0
    mov qword ptr [rbx + 0x28], 1     // done
    mov rsp, qword ptr [rbx + 0x18]   // restore caller rsp
epilogue:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

// ---- crash shield -----------------------------------------------------------
// A vectored exception handler installed by install_shield(). It only takes
// over faults that happen inside OUR arena (a bug in the VM itself: a bad copy
// size, a wild op target), or, when g_guard_null is set, a wild jump to the
// null page while a payload is in flight (the killer on 23-rd was `call 0`).
// Everything else returns EXCEPTION_CONTINUE_SEARCH, i.e. the game keeps its
// own exception semantics. On takeover it rewrites the faulting CONTEXT so the
// thread lands on `recover` with the job in rbx and the caller's rsp restored,
// then returns EXCEPTION_CONTINUE_EXECUTION: the process never dies.
handler:
    mov rdx, qword ptr [rcx + 0x00]   // ExceptionRecord
    mov r8,  qword ptr [rcx + 0x08]   // ContextRecord
    mov rax, qword ptr [rdx + 0x10]   // ExceptionAddress
    mov r9,  qword ptr [rip + g_cur_job]
    test r9, r9
    jz search
    mov r10, qword ptr [rip + g_arena_lo]
    cmp rax, r10
    jb try_null
    mov r11, qword ptr [rip + g_arena_hi]
    cmp rax, r11
    jb take_over
try_null:
    cmp qword ptr [rip + g_guard_null], 0
    je try_in_call
    cmp rax, 0x10000
    jb take_over
try_in_call:
    // a hard fault inside a function the payload itself called (the second
    // crash on the 24th: Post with the arguments in the wrong registers). Only
    // access violations and illegal instructions are taken over; C++
    // exceptions and everything else keep the game's own semantics.
    cmp qword ptr [rip + g_in_call], 0
    je search
    mov r10d, dword ptr [rdx + 0x00]  // exception code
    cmp r10d, 0xC0000005
    je take_over
    cmp r10d, 0xC000001D
    je take_over
take_over:
    mov r10, qword ptr [rdx + 0x00]   // exception code
    mov qword ptr [r9 + 0x40], rax    // fault rip
    mov qword ptr [r9 + 0x48], r10    // exception code
    mov r10, qword ptr [r8 + 0xe0]    // ContextRecord->R13 = op pointer
    mov qword ptr [r9 + 0x58], r10
    mov r10, qword ptr [r9 + 0x18]    // saved caller rsp
    mov qword ptr [r8 + 0x98], r10    // CONTEXT.Rsp
    mov qword ptr [r8 + 0x90], r9     // CONTEXT.Rbx = job
    mov r10, qword ptr [rip + g_recover]
    mov qword ptr [r8 + 0xf8], r10    // CONTEXT.Rip
    mov eax, -1                       // EXCEPTION_CONTINUE_EXECUTION
    ret
search:
    xor eax, eax                      // EXCEPTION_CONTINUE_SEARCH
    ret

// entered through the rewritten CONTEXT: rbx = job, rsp = caller rsp
recover:
    mov qword ptr [rbx + 0x30], 2     // status = faulted
    mov qword ptr [rbx + 0x28], 1     // done
    mov qword ptr [rip + g_cur_job], 0
    mov rsp, qword ptr [rbx + 0x18]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.align 16
g_arena_lo:
    .quad 0
g_arena_hi:
    .quad 0
g_cur_job:
    .quad 0
g_last_obj:
    .quad 0
g_in_call:
    .quad 0
g_recover:
    .quad 0
g_guard_null:
    .quad 1
"""


_LABELS = ("vm", "handler", "recover", "g_arena_lo", "g_arena_hi",
           "g_cur_job", "g_last_obj", "g_in_call", "g_recover", "g_guard_null")


def assemble(source: str = _ASM) -> tuple[bytes, dict[str, int]]:
    """Assemble the payload; return (code, {label: offset}).

    keystone 0.9.2's python binding has no symbol-table accessor (`sym_resolver`
    is an input hook and defaults to None), so the label offsets are recovered
    by appending a `movabs rax, <label>` probe per label and reading the
    immediates back out of the tail. The probe is not part of the shipped code.
    """
    if keystone is None:
        raise RuntimeError("keystone-engine is required to assemble the VM payload")
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    probe = "\n".join(f"movabs rax, {name}" for name in _LABELS)
    try:
        code, _count = ks.asm(source + "\n" + probe)
    except keystone.KsError as exc:  # pragma: no cover - assembler syntax drift
        raise RuntimeError(f"keystone refused the VM payload: {exc}") from exc
    if not code:
        raise RuntimeError("keystone produced an empty payload")
    code = bytes(code)
    probe_len = 10 * len(_LABELS)
    payload, tail = code[:-probe_len], code[-probe_len:]
    syms = {}
    for i, name in enumerate(_LABELS):
        chunk = tail[i * 10:(i + 1) * 10]
        if chunk[:2] != b"\x48\xb8":
            raise RuntimeError(f"probe for {name} is not a movabs ({chunk.hex()})")
        syms[name] = struct.unpack_from("<Q", chunk, 2)[0]
    return payload, syms


PAYLOAD, SYM = assemble()
ENTRY_VM = SYM["vm"]
G_OFF = {k: SYM[k] for k in SYM if k.startswith("g_")}

# Structural self-checks: the shellcode is the security-critical artifact, so
# every property the design depends on is asserted at import time (the 23 日
# coding bug — `mov rcx, r14` encoded as `mov rcx, r13` — was found by exactly
# this kind of assertion after it had already been in a live payload).
import capstone  # noqa: E402

_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_MD.detail = True
_INSN = list(_MD.disasm(PAYLOAD, 0))


def _mnemonics() -> list[str]:
    return [f"{i.mnemonic} {i.op_str}" for i in _INSN]


def _insn_between(lo: int, hi: int) -> list:
    return [i for i in _INSN if lo <= i.address < hi]


_TEXT = "\n".join(_mnemonics())
_VM_BODY = "\n".join(m for i in _INSN if SYM["vm"] <= i.address < SYM["handler"]
                     for m in [f"{i.mnemonic} {i.op_str}"])

assert "xchg qword ptr [rbx + 8], rax" in _VM_BODY, "the atomic claim moved"
assert len([m for m in _VM_BODY.splitlines() if " call " in f" {m} "]) == 4, \
    "the VM calls out exactly four times: op-1 dispatch, op-7 new + ctor, op-8"
assert "rep movsb" in _VM_BODY and "rep stosb" in _VM_BODY, "copy ops moved"
assert "gs:[0x48]" in _VM_BODY, "the TID probe moved"
assert len(_insn_between(SYM["handler"], SYM["recover"])) > 10, "the shield handler shrank"
assert len(_insn_between(SYM["recover"], SYM["g_arena_lo"])) > 5, "the recovery stub shrank"
def _last_real(lo: int, hi: int):
    """Last non-padding instruction in [lo, hi): `.align` fills with nops."""
    real = [i for i in _insn_between(lo, hi) if not i.mnemonic.startswith("nop")]
    if not real:
        raise AssertionError(f"no instructions between {lo:#x} and {hi:#x}")
    return real[-1]


assert _last_real(SYM["vm"], SYM["handler"]).mnemonic == "ret", "VM epilogue moved"
assert _last_real(SYM["handler"], SYM["recover"]).mnemonic == "ret", \
    "the shield handler must end in ret"
assert _last_real(SYM["recover"], SYM["g_arena_lo"]).mnemonic == "ret", \
    "the recovery stub must end in ret"
assert SYM["vm"] == 0, "the VM entry must be the payload start"
assert SYM["g_cur_job"] + 8 <= SYM["g_guard_null"] + 8, "globals moved"
assert SYM["g_guard_null"] + 8 <= JOB_BASE, \
    "payload ran past its reserved page (%#x)" % (SYM["g_guard_null"] + 8)


class ScriptError(RuntimeError):
    pass


class Ref:
    """A value that only exists at run time: what a CALL produced (its RAX) or a
    local buffer holding a pointer read out of the game (see Script.read_ptr).

    A Ref may be used as an argument of a LATER op; it is resolved to that op's
    result slot / the buffer's address when the script is packed, which is also
    why a Ref used as a *stack* argument is dereferenced once by the payload:
    the argument slot then holds the pointer itself, not our local copy of it.
    """

    __slots__ = ("op", "addr")

    def __init__(self, op: int, addr: int | None = None):
        self.op = op                      # index of the producing op
        self.addr = addr                  # data-page offset, when it holds data

    def crack(self) -> int:
        """The placeholder operand: ref id in the top 32 bits, offset in the low."""
        return (self.op << 32) | ((self.addr or 0) & 0xFFFFFFFF)

    def __index__(self) -> int:
        return self.op

    def __repr__(self) -> str:            # pragma: no cover - debugging aid
        return f"Ref(op={self.op}, addr={self.addr:#x})" if self.addr is not None \
            else f"Ref(op={self.op})"


def _is_ref(v) -> bool:
    return isinstance(v, Ref)


def _operand(v):
    return v if isinstance(v, Ref) else int(v)


class Op:
    """One VM instruction. Use Script's helpers rather than building these.

    Local-buffer operands are stored as *page offsets* and relocated to
    absolute addresses when the data page is allocated (Op.pack(page)): the
    page VA does not exist while the caller is still building the script.
    """

    __slots__ = ("code", "a0", "a1", "a2", "a3", "a4", "a5")

    def __init__(self, code: int, a0=0, a1=0, a2=0, a3=0, a4=0, a5=0):
        self.code = int(code)
        # operands are integers except for a run-time Ref, which stays symbolic
        # until ScriptChannel._resolve_refs assigns it a slot
        self.a0, self.a1, self.a2, self.a3, self.a4, self.a5 = (
            _operand(a0), _operand(a1), _operand(a2), _operand(a3),
            _operand(a4), _operand(a5))

    def pack(self, page: int = 0) -> bytes:
        a0, a1, a5 = self.a0, self.a1, self.a5
        if self.code == OP_READ:
            a0 += page          # local dst
        elif self.code == OP_WRITE:
            a1 += page          # local src
        elif self.code == OP_CALL:
            # a1 = block offset (low 32) | count (high 32): only the offset is
            # relocated, and the add must not carry into the count field
            a1 = (a1 & ~0xFFFFFFFF) | ((a1 + page) & 0xFFFFFFFF)
        elif self.code == OP_ALLOC_CTOR:
            a5 = (a5 & ~0xFFFFFFFF) | (((a5 & 0xFFFFFFFF) + page) & 0xFFFFFFFF)
        # records are OP_SIZE (0x40) apart: code + a0..a4 + result + a5
        return struct.pack("<8Q", self.code, a0, a1, self.a2, self.a3, self.a4,
                           0, a5)


class Buffer:
    """A local buffer inside the script's data page (target -> us, us -> target)."""

    __slots__ = ("offset", "size")

    def __init__(self, offset: int, size: int):
        self.offset, self.size = offset, size


class Script:
    """Builder for one VM delivery. Ops are validated when the script runs."""

    def __init__(self, *, allow_calls: set[tuple[int, int]] | None = None):
        self.ops: list[Op] = []
        self.buffers: dict[int, bytes] = {}   # data-page offset -> bytes to stage
        self.stack_blocks: dict[int, list] = {}   # op index -> stack arguments
        self.alloc_sizes: dict[int, int] = {}     # op index -> operator new size
        self._buf = BUF_BASE
        self._stack = STACK_BASE
        self._allow = allow_calls
        self.call_targets: list[int] = []
        self._resolved = False                    # a Script may be sent once

    # -- op builders -----------------------------------------------------------
    def call(self, func: int, *args) -> Ref:
        """Call func(a1..a4) on the game thread; returns a Ref to its result.

        Four register arguments (rcx/rdx/r8/r9) — the Windows x64 ABI's whole
        register budget. Every command in the table fits: the object goes in
        rcx (or through call_obj), so a 4-argument command like
        CDropCurrentNationalFocusCommand is already at the limit.

        Stack arguments (5+) are NOT available: the payload's copy into the
        callee's home space was never made reliable (see `STACK_ARGS_SUPPORTED`)
        and no command in scope needs them.

        Calls are refused unless an explicit call whitelist was supplied: a
        wrong target does not fail loudly, it jumps.
        """
        regs, stack = self._pack_args(args, 4, "call")
        self._check_call(func, "call")
        # op-1 layout: a0=target, a1=0 (no stack block), a2..a5 = rcx/rdx/r8/r9
        self.ops.append(Op(OP_CALL, func, 0, *regs))
        return Ref(len(self.ops) - 1)

    def write_raw(self, addr: int, value: int, size: int = 8) -> None:
        if size not in (1, 2, 4, 8):
            raise ScriptError("write_raw size must be 1/2/4/8")
        self.ops.append(Op(OP_WRITE_RAW, addr, value, size))

    def read(self, addr: int, size: int) -> Buffer:
        buf = self._claim_buffer(size)
        self.ops.append(Op(OP_READ, buf.offset, addr, size))
        return buf

    def read_ptr(self, addr: int) -> Ref:
        """Read a pointer (qword) out of the game at run time.

        The value is dereferenced again by the payload when it is used as a
        *stack* argument, so `sc.call(ctor, tag_addr, sc.read_ptr(ptr_addr))`
        passes the pointer itself — the shape SetResearch and friends need
        (their ctor takes an object pointer, and the offset only exists live).
        """
        buf = self._claim_buffer(8)
        self.ops.append(Op(OP_READ, buf.offset, addr, 8))
        return Ref(len(self.ops) - 1, buf.offset)

    def write(self, addr: int, data: bytes) -> Buffer:
        """Stage `data` in the script's data page and copy it to `addr` at run
        time (so the bytes travel with the delivery, not through a second WPM)."""
        buf = self._claim_buffer(len(data))
        self.buffers[buf.offset] = bytes(data)
        self.ops.append(Op(OP_WRITE, addr, buf.offset, len(data)))
        return buf

    def memset(self, addr: int, value: int, size: int) -> None:
        self.ops.append(Op(OP_MEMSET, addr, value & 0xFF, size))

    # -- ctor-faithful object construction -------------------------------------
    def alloc_ctor(self, new: int, ctor: int, size: int, *args) -> int:
        """operator new(size), then ctor(obj, args...). The object stays
        available to call_obj() (op 8). This is the ONLY sanctioned way to
        build a game object: a hand-built blob reproduces nothing but the
        fields someone remembered to copy (24 日: a game died of exactly that).

        `size` is kept in Python only (Script.alloc_sizes): the op record has no
        seventh field to carry it, and the payload does not need it — the ctor
        path is `new` then `ctor`, and the ctor is what decides the layout.
        """
        if len(args) > 3:
            raise ScriptError(f"the ctor path takes at most 3 arguments "
                              f"(rdx/r8/r9; got {len(args)})")
        # the ctor is ctor(this, rdx, r8, r9): rcx is `this`
        regs = list(args) + [0] * (3 - len(args))
        self._check_call(new, "operator new")
        self._check_call(ctor, "constructor")
        # op 7 layout: a0=new, a1=ctor, a2/a3/a4=rdx/r8/r9, a5 = size << 40
        self.alloc_sizes[len(self.ops)] = int(size)
        if size >= (1 << 24):
            raise ScriptError(f"operator new size {size:#x} does not fit the "
                              f"24-bit field the record shares with the opcode")
        self.ops.append(Op(OP_ALLOC_CTOR, new, ctor, *regs, int(size) << 40))
        return len(self.ops) - 1

    def call_obj(self, func: int, slot: int, *args) -> int:
        """func(*args) with the op-7 object substituted into register argument
        `slot` (0=rcx, 1=rdx, 2=r8, 3=r9); missing arguments are zero.

        At most three explicit arguments: the fourth op-8 operand is the
        receiving register itself, so a 4+ argument call needs op 1 (call) with
        the object supplied as a value instead.

        Post is `Post(queue, cmd, force)` = rcx=queue, rdx=obj, r8=0, so the
        object belongs in slot 1 — the 24 日 second crash was an earlier version
        that always used rcx and handed Post the queue as the command.
        """
        if not 0 <= slot <= 3:
            raise ScriptError("slot must be 0..3 (rcx/rdx/r8/r9)")
        if len(args) > 3:
            raise ScriptError(f"call_obj takes at most 3 explicit arguments "
                              f"(got {len(args)})")
        regs, stack = self._pack_args(args, 3, "call_obj")
        self._check_call(func, "call_obj")
        packed = list(regs) + [0] * (4 - len(regs))
        # op 8 layout: a0=func, a1=slot+16*count, a2..a5=rcx/rdx/r8/r9, and
        # a5's qword is the receiving register, not an argument, so the ABI
        # forces this call to keep at most 3 explicit arguments (use op 1 for
        # anything wider).
        self.ops.append(Op(OP_CALL_OBJ, func, slot + 16 * len(args), *packed[:4]))
        return len(self.ops) - 1

    # -- argument packing ------------------------------------------------------
    def _pack_args(self, args, max_total: int, what: str):
        """Pad the register argument list. Refs stay symbolic: Op.__init__ keeps
        them (int() would bake in the placeholder crack and lose the value)."""
        if len(args) > max_total:
            raise ScriptError(f"{what} takes at most {max_total} register "
                              f"arguments (got {len(args)}); the VM has no "
                              f"stack-argument path")
        return list(args) + [0] * max(0, 4 - len(args)), []

    def _stack_block(self, values: list) -> int:
        """RETIRED: the stack-argument path.

        The payload's copy into a callee's home space was never made reliable
        (the copy itself works in stand-alone shellcode; inside the VM the
        second store faults the thread). No command in scope needs 5+ arguments
        — the largest ones here use four registers — so the API refuses them
        instead of pretending. Kept as a tripwire for anyone who tries.
        """
        raise ScriptError("the VM has no stack-argument path: a call takes at "
                          "most 4 register arguments (rcx/rdx/r8/r9)")

    def _push(self, op: Op) -> Ref:
        self.ops.append(op)
        return Ref(len(self.ops) - 1)

    def _refs_in(self, i: int) -> list[Ref]:
        """Every symbolic operand of op i (record operands + its stack block)."""
        op = self.ops[i]
        found = [getattr(op, f) for f in ("a0", "a1", "a2", "a3", "a4", "a5")
                 if _is_ref(getattr(op, f))]
        return found + [v for v in self.stack_blocks.get(i, ()) if _is_ref(v)]

    def _check_call(self, func: int, what: str) -> None:
        if self._allow is None:
            raise ScriptError(f"no call whitelist: pass allow_calls={{(lo, hi), ...}} "
                              f"to Script() to permit {what}")
        if not any(lo <= func < hi for lo, hi in self._allow):
            raise ScriptError(f"{what} target {func:#x} is outside the allowed modules "
                              f"{[f'{lo:#x}-{hi:#x}' for lo, hi in self._allow]}")
        self.call_targets.append(func)

    # -- helpers ---------------------------------------------------------------
    def _claim_buffer(self, size: int) -> Buffer:
        if size <= 0 or size > 0x800:
            raise ScriptError("local buffers are 1..0x800 bytes")
        off = (self._buf + 7) & ~7
        if off + size > BUF_END:
            raise ScriptError(f"script data page exhausted (need {size:#x} at {off:#x})")
        self._buf = off + size
        # buffers are written by the caller through write_buffer() before the run
        return Buffer(off, size)


class ScriptChannel:
    """Code arena + data arena + one job per send, delivered by special user APC."""

    def __init__(self, proc, timeout: float = 3.0, per_thread_wait: float = 0.35,
                 max_threads: int = 6, probe_window: float = 0.04):
        self.p = proc
        self.h = proc.handle
        self.m = proc.memory
        self.timeout = timeout
        self.per_thread_wait = per_thread_wait
        self.max_threads = max_threads
        self.probe_window = probe_window
        self.code: int | None = None
        self.data: int | None = None
        self._slot = 0
        self._page = 0
        self.shield_installed = False
        self.stats = {"sends": 0, "attempts": 0, "deliveries": 0,
                      "last_ran_on": None, "last_latency": None, "last_kind": None}

    # -- arenas ----------------------------------------------------------------
    def _ensure_arenas(self) -> None:
        if self.code is None:
            self.code = w.virtual_alloc_ex(self.h, CODE_ARENA_SIZE, PAGE_EXECUTE_READWRITE)
            w.write_process_memory(self.h, self.code + SC_OFF, PAYLOAD)
            if self.m.rpm(self.code + SC_OFF, len(PAYLOAD)) != PAYLOAD:
                raise ScriptError("VM payload readback mismatch in target arena")
            self._patch_globals()
            log.info("script code arena at %#x", self.code)
        if self.data is None:
            self.data = w.virtual_alloc_ex(self.h, DATA_ARENA_SIZE, PAGE_READWRITE)
            log.info("script data arena at %#x", self.data)

    def _patch_globals(self, guard_null: int = 1) -> None:
        """Point the payload's data labels at this arena's real addresses."""
        vals = {
            "g_arena_lo": self.code,
            "g_arena_hi": self.code + CODE_ARENA_SIZE,
            "g_cur_job": 0,
            "g_recover": self.code + SYM["recover"],
            "g_guard_null": guard_null,
        }
        for name, value in vals.items():
            w.write_process_memory(self.h, self.code + G_OFF[name], struct.pack("<Q", value))

    # -- crash shield ----------------------------------------------------------
    def install_shield(self) -> dict:
        """Install the vectored exception handler in the target (idempotent per
        process). AddVectoredExceptionHandler is resolved through the target's
        own kernel32 mapping, so no assumption about ASLR is needed."""
        self._ensure_arenas()
        if self.shield_installed:
            return {"installed": True, "already": True}
        fn = self._resolve_export("kernel32.dll", b"AddVectoredExceptionHandler")
        handler = self.code + SYM["handler"]
        script = Script(allow_calls={(fn, fn + 1)})
        script.call(fn, 1, handler)
        res = self.run(script)
        if not res.get("done"):
            raise ScriptError(f"shield install did not run: {res}")
        handle = res["results"][0]
        if not handle:
            raise ScriptError("AddVectoredExceptionHandler returned NULL")
        self.shield_installed = True
        self._patch_globals()
        log.info("crash shield installed in target (%#x, handle %#x)", handler, handle)
        return {"installed": True, "handler": hex(handler), "handle": hex(handle),
                "result": res}

    def _resolve_export(self, module: str, name: bytes) -> int:
        """Address of an export inside the TARGET process: its own module base
        plus the offset of the same export in ours (same DLL, same boot)."""
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetModuleHandleW.restype = ctypes.c_void_p
        k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        k32.GetProcAddress.restype = ctypes.c_void_p
        k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        ours = k32.GetModuleHandleW(module)
        if not ours:
            raise ScriptError(f"{module} is not loaded in this process")
        fn = k32.GetProcAddress(ctypes.c_void_p(ours), name)
        if not fn:
            raise ScriptError(f"{module}!{name.decode()} not found")
        for mod_name, base, _size in w.enumerate_modules(self.h):
            if mod_name.lower().endswith(module.lower()):
                return base + (fn - ours)
        raise ScriptError(f"{module} is not loaded in the target process")

    def _next_slot(self) -> int:
        self._ensure_arenas()
        n = (CODE_ARENA_SIZE - JOB_BASE) // SLOT_STRIDE
        if self._slot >= n - 1:
            raise ScriptError("script code arena exhausted; restart the session")
        slot = self.code + JOB_BASE + self._slot * SLOT_STRIDE
        self._slot += 1
        return slot

    def _next_page(self) -> int:
        self._ensure_arenas()
        n = DATA_ARENA_SIZE // DATA_PAGE
        if self._page >= n - 1:
            raise ScriptError("script data arena exhausted; restart the session")
        page = self.data + self._page * DATA_PAGE
        self._page += 1
        return page

    def close(self) -> None:
        self.code = None
        self.data = None

    # -- thread selection (same policy as apc.py) -------------------------------
    def _threads(self) -> list[int]:
        tids = w.list_thread_ids(self.p.pid)
        created = {}
        for tid in tids:
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                created[tid] = w.get_thread_times(h)[0]
            except OSError:
                pass
            finally:
                w._k32.CloseHandle(h)
        if len(created) > 1:
            tids.sort(key=lambda t: created.get(t, float("inf")))
        return tids

    def _classify(self, tids: list[int]):
        def sample():
            out = {}
            for tid in tids:
                try:
                    h = w.open_thread(tid)
                except OSError:
                    continue
                try:
                    out[tid] = w.get_thread_times(h)[3]
                except OSError:
                    pass
                finally:
                    w._k32.CloseHandle(h)
            return out

        t0 = sample()
        time.sleep(self.probe_window)
        t1 = sample()
        parked, hot = [], []
        for tid, u0 in t0.items():
            u1 = t1.get(tid)
            if u1 is None:
                continue
            (hot if u1 > u0 else parked).append(tid)
        return parked, hot, (tids[0] if tids else None)

    def _queue(self, entry: int, tid: int, param: int) -> bool:
        try:
            h = w.open_thread(tid)
        except OSError:
            return False
        try:
            if HAVE_APC2:
                ok = _k32.QueueUserAPC2(ctypes.c_void_p(entry), h, param,
                                        QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)
                return bool(ok)
            return bool(_k32.QueueUserAPC(ctypes.c_void_p(entry), h, param))
        finally:
            w._k32.CloseHandle(h)

    # -- run -------------------------------------------------------------------
    def run(self, script: Script, threads: list[int] | None = None) -> dict:
        if not script.ops:
            raise ScriptError("empty script")
        if len(script.ops) > MAX_OPS:
            raise ScriptError(f"at most {MAX_OPS} ops per delivery (got {len(script.ops)})")
        self._ensure_arenas()
        page = self._next_page()
        slot = self._next_slot()
        raw_ops, blocks = self._resolve_refs(script, page)

        # data page: header + ops + local buffers, all staged BEFORE the job is
        # written and the APC is queued (the payload must never see a half-built
        # program: the atomic claim is the only synchronization point we need).
        header = struct.pack("<4Q", MAGIC, len(script.ops), 0, 0)
        w.write_process_memory(self.h, page, header)
        w.write_process_memory(self.h, page + D_OPS, raw_ops)
        for off, vals in blocks.items():
            w.write_process_memory(self.h, page + off,
                                   struct.pack("<%dQ" % len(vals), *vals))
        for off, blob in script.buffers.items():
            w.write_process_memory(self.h, page + off, blob)

        job = struct.pack("<12Q", page, 0, slot + STACK_TOP, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        assert len(job) == S_JOB_SIZE
        w.write_process_memory(self.h, slot, job)
        if self.m.rpm(slot, S_JOB_SIZE) != job:
            raise ScriptError(f"job writeback mismatch at {slot:#x}")

        self.stats["sends"] += 1
        tids = threads or self._threads()
        parked, hot, main = self._classify(tids)
        wave1 = [(t, "parked") for t in parked if t != main][:4]
        wave2 = ([(main, "main")] if main else []) + \
                [(t, "hot") for t in hot if t != main][:3] + \
                [(t, "parked") for t in parked if t != main][4:self.max_threads]

        deadline = time.time() + self.timeout
        claimed_at = None
        for wave, window in ((wave1, 1.2), (wave2, max(0.5, deadline - time.time()))):
            for tid, kind in wave:
                self.stats["attempts"] += 1
                if self._queue(self.code + SC_OFF, tid, slot) and claimed_at is None:
                    claimed_at = (tid, kind, time.time())
            wend = min(deadline, time.time() + window)
            while time.time() < wend:
                st = self._read_job(slot)
                if st is None:
                    return self._dead_result(slot, page)
                if st["done"]:
                    self.stats["deliveries"] += 1
                    st["latency"] = time.time() - (claimed_at[2] if claimed_at else time.time())
                    self.stats["last_ran_on"] = st["tid"]
                    self.stats["last_latency"] = st["latency"]
                    self.stats["last_kind"] = claimed_at[1] if claimed_at else None
                    return self._finish(st, slot, page, script, job,
                                        claimed_at[1] if claimed_at else None)
                if st["claim"] and claimed_at is None:
                    claimed_at = (tid, kind, time.time())
                time.sleep(0.003)
        st = self._read_job(slot)
        if st is None:
            return self._dead_result(slot, page)
        out = self._finish(st, slot, page, script, job, claimed_at[1] if claimed_at else None)
        out["timeout"] = True
        return out

    # -- run-time references ---------------------------------------------------
    def _resolve_refs(self, script: Script, page: int) -> tuple[bytes, dict[int, list[int]]]:
        """Turn run-time Refs (a CALL's RAX, read_ptr's value) into operands.

        Refs are symbolic while the script is being built — the data page does
        not exist yet. Resolution enforces causality: a Ref may only be consumed
        by a *later* op, because the payload reads the slot before running a
        consumer and a backwards reference would read a slot that is still zero.

        A Ref that carries an `addr` lives in a local buffer the producing op
        already fills (read_ptr), so it is used as-is — as a register argument
        that is the `&value` shape (SetResearch's `&tag`). Any other Ref
        resolves to the producer's own result field (`[op + OP_RES]`, the qword
        the payload stores RAX into): the op record itself is the storage, so no
        operand has to be spent on it and a call may still use all four register
        arguments.
        """
        fields = ("a0", "a1", "a2", "a3", "a4", "a5")

        # Resolution rewrites operands in place (the page VA does not exist while
        # a script is being built), so it may run exactly ONCE per Script: a
        # second pass would add the page offset again and silently shift every
        # argument (this cost an afternoon of "the payload loads the wrong
        # operand" debugging — the payload was innocent, the test harness called
        # the resolver twice).
        if script._resolved:
            raise ScriptError("this Script was already resolved: build a new one "
                              "(operands hold absolute addresses now)")
        script._resolved = True

        def resolve(r: Ref) -> int:
            if r.addr is not None:
                # a local buffer read_ptr fills: the operand is its ABSOLUTE
                # address (the buffer offset is page-relative like every other
                # local operand)
                return page + r.addr
            op = script.ops[r.op]
            if op.code == OP_ALLOC_CTOR:
                raise ScriptError(
                    "an op-7 (alloc_ctor) result cannot be consumed as a value: "
                    "the object is only reachable through call_obj()")
            if op.code not in (OP_CALL, OP_CALL_OBJ):
                raise ScriptError(f"op {r.op} (opcode {op.code}) produces no value")
            return page + r.op * OP_SIZE + OP_RES

        # pass 1: causality (a backwards reference would read a zero slot)
        for i in range(len(script.ops)):
            for r in script._refs_in(i):
                if r.op >= i and r.addr is None:
                    raise ScriptError(
                        f"op {i} uses a value produced by op {r.op}: Refs must "
                        f"point at an earlier CALL / read_ptr")

        # pass 2: rewrite every operand (blocks are gone: no stack arguments).
        # Causality is enforced here as well, so a Script whose ops were moved
        # around after the builder ran cannot smuggle a forward reference in.
        for i in range(len(script.ops)):
            op = script.ops[i]
            for f in fields:
                v = getattr(op, f)
                if _is_ref(v):
                    if v.op >= i:
                        raise ScriptError(
                            f"op {i} references op {v.op}, which has not run yet")
                    setattr(op, f, resolve(v))
        return b"".join(op.pack(page) for op in script.ops), {}
    def _read_job(self, slot: int) -> dict | None:
        """None when the target is gone (RPM fails): the caller must not turn a
        dead process into a traceback — a crashed target is a *result*."""
        try:
            raw = self.m.rpm(slot, S_JOB_SIZE)
        except OSError:
            return None
        q = struct.unpack("<%dQ" % (S_JOB_SIZE // 8), raw)
        return {"claim": q[S_CLAIM // 8], "tid": q[S_TID // 8], "done": q[S_DONE // 8],
                "status": q[S_STATUS // 8], "n_ops": q[S_NOPS_DONE // 8],
                "fault_rip": q[S_FAULT_RIP // 8], "fault_code": q[S_FAULT_CODE // 8],
                "fault_r13": q[S_FAULT_R13 // 8], "last_rax": q[S_LAST_RAX // 8],
                "saved_rsp": q[S_SAVED_RSP // 8]}

    @staticmethod
    def _dead_result(slot: int, page: int, job: bytes | None = None) -> dict:
        return {"done": 0, "dead": True, "status": None, "claim": 0, "tid": None,
                "fault_rip": 0, "fault_code": 0, "fault_r13": 0, "last_rax": 0,
                "results": [], "local": {}, "slot": slot, "page": page,
                "job_intact": False, "kind": None, "latency": None}

    def job_intact(self, slot: int, expect: bytes) -> bool:
        inputs = (S_DATA, S_STACK)
        try:
            back = self.m.rpm(slot, S_JOB_SIZE)
        except OSError:
            return False
        return all(back[o:o + 8] == expect[o:o + 8] for o in inputs)

    def _finish(self, st: dict, slot: int, page: int, script: Script,
                job: bytes, kind: str | None) -> dict:
        results = []
        local = {}
        try:
            if st["done"]:
                raw = self.m.rpm(page + D_OPS, OP_SIZE * len(script.ops))
                for i in range(len(script.ops)):
                    results.append(struct.unpack_from("<Q", raw, i * OP_SIZE + OP_RES)[0])
            # read the local buffers back for READ() ops
            for i, op in enumerate(script.ops):
                if op.code == OP_READ:
                    local[i] = self.m.rpm(page + op.a0, op.a2)
        except OSError:
            return self._dead_result(slot, page)
        return {**st, "results": results, "local": local, "slot": slot, "page": page,
                "kind": kind, "job_intact": self.job_intact(slot, job),
                "in_flight": bool(st["claim"]) and not st["done"]}

    def status(self) -> dict:
        return {"code_arena": hex(self.code) if self.code else None,
                "data_arena": hex(self.data) if self.data else None,
                "slots_used": self._slot, "pages_used": self._page,
                "shield_installed": self.shield_installed,
                "have_apc2": HAVE_APC2, "payload_bytes": len(PAYLOAD), **self.stats}


def disasm(code: bytes | None = None) -> str:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return "\n".join(f"+{i.address:04x}: {i.mnemonic} {i.op_str}"
                     for i in md.disasm(code if code is not None else PAYLOAD, 0))
