"""apc.py — in-process command channel via a special user APC (23 日).

This replaces the 21 日 "suspend every thread + SetThreadContext graft"
protocol, which was retired on a misdiagnosis: the mitigation dword
GetProcessMitigationPolicy(UserShadowStack) = 0x100 that NOTES 22 日 read as
"SetContextIpValidation ON" is bit 8 = CetDynamicApisOutOfProcOnly; the
SetContextIpValidation bit is bit 2 (SDK 10.0.22000 winnt.h, confirmed against
phnt bindings). The live process was re-probed on 23 日: graft, CreateRemoteThread
into our own RWX page, CreateRemoteThread=LoadLibraryW and QueueUserAPC2 all
work.

Why the APC is the better channel:

  * no thread is ever suspended (the 21 日 "2nd send kills the game" failure
    lived in the suspend/graft/restore window),
  * no thread is created (a newcomer has none of the game's thread-local
    state, which is why game-side calls AV'd from a CreateRemoteThread),
  * the payload runs ON A GAME THREAD, in that thread's own TLS context; the
    kernel delivers it at a user-mode transition and the APC dispatcher
    restores the interrupted context with NtContinue, so the thread resumes
    exactly where it was,
  * QueueUserAPC2 + QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC does not need the
    target to sit in an alertable wait.

Safety rules kept from the v2 charter:
  * only disassembly-verified addresses (inject/tables.py) are called,
  * the job is single-use: an atomic claim flag makes a duplicate delivery a
    no-op, so queueing the same job at several threads can never post twice,
  * the arena is never freed (a pending APC must not jump into freed memory),
  * force=0: the game's own CanExecute runs exactly as it does for a click.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import struct
import time

from ..process import win32ext as w

log = logging.getLogger(__name__)

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.QueueUserAPC.restype = wt.DWORD
_k32.QueueUserAPC.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t]
HAVE_APC2 = hasattr(_k32, "QueueUserAPC2")
if HAVE_APC2:
    _k32.QueueUserAPC2.restype = wt.BOOL
    _k32.QueueUserAPC2.argtypes = [ctypes.c_void_p, wt.HANDLE, ctypes.c_size_t, ctypes.c_int]

QUEUE_USER_APC_FLAGS_NONE = 0
QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1

# --- arena layout -----------------------------------------------------------
# ONE slot per queued job, and the private stack must never reach the job or
# the blob: on 23 日 the first live send died with an access violation at
# offset 0 because a 4 KB slot stack let the real operator new/Post frames run
# down into the job, which the payload then re-read as garbage (verified on a
# stand-in: a fake callee that eats 6 KB trashes the job and kills the host).
SC_OFF = 0x0000             # shared shellcode
JOB_BASE = 0x1000           # first job slot
SLOT_STRIDE = 0x4000        # job + blob + ~15.6 KB private stack
BLOB_OFF = 0x0100           # blob staging inside a slot
STACK_TOP = 0x3FF0          # private stack top inside a slot (RSP % 16 == 0)
ARENA_SIZE = 0x100000       # 1 MB, never freed (63 slots)

# --- job layout (job-relative == arena-absolute for reads) ------------------
J_NEW = 0x00                # operator new VA
J_CLAIM = 0x08              # atomic single-use claim (xchg)
J_POST = 0x10               # Post VA
J_QUEUE = 0x18              # CSession*
J_SIZE = 0x20               # command object size
J_BLOB = 0x28               # blob source (in-slot)
J_NQWORD = 0x30             # blob length in qwords
J_STACK = 0x38              # private stack top
J_SAVED_RSP = 0x40
J_TID = 0x48                # thread the payload actually ran on
J_DONE = 0x50
J_CMD = 0x58                # command object returned by operator new
J_POSTED = 0x60             # Post() return value
JOB_SIZE = 0x70

PAGE_EXECUTE_READWRITE = 0x40

# The payload: claim -> new(size) -> copy blob -> Post(queue, cmd, 0) -> done,
# then restore RSP and return to the APC dispatcher. It only ever touches its
# own slot; the interrupted thread's registers are restored by ntdll
# (NtContinue), so nothing else needs saving.
_MAIN = bytes.fromhex(
    "65488B042548000000"        # mov rax, gs:[0x48]    ; TEB->ClientId.UniqueThread
    "48898348000000"            # mov [rbx+0x48], rax
    # cache post/queue/blob/count in callee-saved registers BEFORE the first
    # call: the payload must not re-read its job after calling into the game
    # (23 日: an undersized private stack let the game's own frames overwrite
    # the job, and the re-read turned the send into `call 0`).
    "4C8B6B10"                  # mov r13, [rbx+0x10]   ; Post
    "4C8B7318"                  # mov r14, [rbx+0x18]   ; queue
    "4C8B7B28"                  # mov r15, [rbx+0x28]   ; blob
    "488B6B30"                  # mov rbp, [rbx+0x30]   ; n qwords
    "48896340"                  # mov [rbx+0x40], rsp   ; save caller rsp
    "488B6338"                  # mov rsp, [rbx+0x38]   ; private stack
    "4883EC20"                  # sub rsp, 0x20         ; shadow space
    "488B4B20"                  # mov rcx, [rbx+0x20]   ; size
    "FF5300"                    # call qword [rbx+0x00] ; operator new
    "4989C4"                    # mov r12, rax          ; cmd
    "4C896358"                  # mov [rbx+0x58], r12
    "4C89FE"                    # mov rsi, r15          ; blob
    "4C89E7"                    # mov rdi, r12
    "4889E9"                    # mov rcx, rbp          ; n qwords
    "FC"                        # cld
    "F348A5"                    # rep movsq
    "4C89F1"                    # mov rcx, r14          ; queue
    "4C89E2"                    # mov rdx, r12          ; cmd
    "4531C0"                    # xor r8d, r8d          ; force = 0 (CanExecute runs)
    "41FFD5"                    # call r13              ; Post
    "48894360"                  # mov [rbx+0x60], rax
    "48C7435001000000"          # mov qword [rbx+0x50], 1
    "488B6340"                  # mov rsp, [rbx+0x40]
)

_PREFIX = bytes.fromhex(
    "53"                        # push rbx
    "4154"                      # push r12
    "4155"                      # push r13
    "4156"                      # push r14
    "4157"                      # push r15
    "55"                        # push rbp
    "4889CB"                    # mov rbx, rcx          ; job
    "48C7C001000000"            # mov rax, 1
    "48874308"                  # xchg [rbx+0x08], rax  ; claim (atomic)
    "4885C0"                    # test rax, rax
)
_EPILOGUE = bytes.fromhex(
    "5D"                        # pop rbp
    "415F"                      # pop r15
    "415E"                      # pop r14
    "415D"                      # pop r13
    "415C"                      # pop r12
    "5B"                        # pop rbx
    "C3"                        # ret
)
_JNZ = bytes([0x75, len(_MAIN)])   # jnz epilogue: someone else already ran it
SHELLCODE = _PREFIX + _JNZ + _MAIN + _EPILOGUE

# the jump is raw bytes; verify it lands on the epilogue (a future edit must
# not silently corrupt the control flow).
assert 0 < len(_MAIN) < 128, "jnz is rel8 — payload grew past 127 bytes"
assert SHELLCODE[len(_PREFIX)] == 0x75, "jnz opcode moved"
assert SHELLCODE[len(_PREFIX) + 1] == len(_MAIN), "jnz displacement out of sync"
assert SHELLCODE[len(_PREFIX) + 2 + len(_MAIN):] == _EPILOGUE, "epilogue moved"


class ApcError(RuntimeError):
    pass


class ApcChannel:
    """One RWX arena per target process; every send() is one queued APC."""

    def __init__(self, proc, timeout: float = 3.0, per_thread_wait: float = 0.35,
                 max_threads: int = 6, probe_window: float = 0.04):
        self.p = proc
        self.h = proc.handle
        self.m = proc.memory
        self.timeout = timeout
        self.per_thread_wait = per_thread_wait
        self.max_threads = max_threads
        self.probe_window = probe_window
        self.arena: int | None = None
        self._slot = 0
        self.stats = {"sends": 0, "attempts": 0, "deliveries": 0,
                      "last_ran_on": None, "last_latency": None,
                      "last_kind": None}

    # -- arena ---------------------------------------------------------------
    def _ensure_arena(self) -> int:
        if self.arena:
            return self.arena
        self.arena = w.virtual_alloc_ex(self.h, ARENA_SIZE, PAGE_EXECUTE_READWRITE)
        w.write_process_memory(self.h, self.arena + SC_OFF, SHELLCODE)
        back = self.m.rpm(self.arena + SC_OFF, len(SHELLCODE))
        if back != SHELLCODE:
            raise ApcError("shellcode readback mismatch in target arena")
        log.info("apc arena at %#x", self.arena)
        return self.arena

    def _next_slot(self) -> int:
        """Slots are bump-allocated and never reused: an APC queued for an
        earlier job may still be pending, and it must find its slot intact."""
        self._ensure_arena()
        n_slots = (ARENA_SIZE - JOB_BASE) // SLOT_STRIDE
        if self._slot >= n_slots - 1:
            raise ApcError("APC arena exhausted; restart the session")
        slot = self.arena + JOB_BASE + self._slot * SLOT_STRIDE
        self._slot += 1
        return slot

    def close(self) -> None:
        """Never frees the arena on purpose (see module docstring); detaches."""
        self.arena = None

    # -- thread selection ------------------------------------------------------
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

    def _classify(self, tids: list[int]) -> tuple[list[int], list[int], int | None]:
        """(parked, hot, main). Parked = user time did not move across the
        probe window: the thread is sitting in a wait, so an APC delivered at
        its return-to-user runs with no lock held by that thread — the safest
        possible point to call the game's allocator and the command queue."""
        def sample() -> dict[int, float]:
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

    # -- fire ------------------------------------------------------------------
    def _queue(self, slot: int, tid: int) -> bool:
        try:
            h = w.open_thread(tid)
        except OSError:
            return False
        try:
            if HAVE_APC2:
                ok = _k32.QueueUserAPC2(ctypes.c_void_p(self.arena + SC_OFF), h,
                                        slot, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)
                return bool(ok)
            return bool(_k32.QueueUserAPC(ctypes.c_void_p(self.arena + SC_OFF), h, slot))
        finally:
            w._k32.CloseHandle(h)

    def _read_job(self, slot: int) -> dict:
        raw = self.m.rpm(slot, JOB_SIZE)
        q = struct.unpack("<%dQ" % (JOB_SIZE // 8), raw)
        return {"claim": q[J_CLAIM // 8], "tid": q[J_TID // 8],
                "done": q[J_DONE // 8], "cmd": q[J_CMD // 8],
                "posted": q[J_POSTED // 8], "_q": q}

    def job_intact(self, slot: int, expect: bytes) -> bool:
        """The payload re-reads its job BEFORE the first call (post/queue/blob/
        count are cached in callee-saved registers for exactly this reason), so
        a callee that walks over the job can no longer turn a send into a
        random call. This tripwire compares only the INPUT fields the sender
        wrote — the tid/saved-rsp/cmd/posted slots are payload OUTPUT and are
        supposed to change."""
        inputs = (J_NEW, J_POST, J_QUEUE, J_SIZE, J_BLOB, J_NQWORD, J_STACK)
        try:
            back = self.m.rpm(slot, JOB_SIZE)
        except OSError:
            return False
        return all(back[o:o + 8] == expect[o:o + 8] for o in inputs)

    def run(self, new_va: int, post_va: int, queue: int, cmd_size: int,
            blob: bytes, threads: list[int] | None = None) -> dict:
        """Queue one single-use job and wait for a game thread to run it."""
        slot = self._next_slot()
        n_qwords = (cmd_size + 7) // 8
        blob_src = slot + BLOB_OFF
        job = struct.pack("<9Q", new_va, 0, post_va, queue, cmd_size,
                          blob_src, n_qwords, slot + STACK_TOP, 0)
        job += struct.pack("<5Q", 0, 0, 0, 0, 0)
        assert len(job) == JOB_SIZE
        w.write_process_memory(self.h, blob_src, blob.ljust(n_qwords * 8, b"\0"))
        w.write_process_memory(self.h, slot, job)
        back = self.m.rpm(slot, JOB_SIZE)
        if back != job:
            raise ApcError(f"job writeback mismatch at {slot:#x} "
                           f"({sum(a != b for a, b in zip(back, job))} bytes differ)")

        self.stats["sends"] += 1
        tids = self._threads()
        parked, hot, main = self._classify(tids)
        # Delivery latency is the target thread's wait interval, so queue the
        # job at a small batch of PARKED threads at once (clean delivery point:
        # no lock held) and let the atomic claim pick the winner. Extra
        # deliveries are no-ops by construction. Only if nothing claims within
        # `first_wave` do we touch the main/hot threads, which can be
        # interrupted mid-frame.
        wave1 = [(t, "parked") for t in parked if t != main][:4]
        wave2 = ([(main, "main")] if main else []) + \
                [(t, "hot") for t in hot if t != main][:3] + \
                [(t, "parked") for t in parked if t != main][4:self.max_threads]

        deadline = time.time() + self.timeout
        claimed_at = None
        for wave, window in ((wave1, 1.2), (wave2, max(0.5, deadline - time.time()))):
            for tid, kind in wave:
                self.stats["attempts"] += 1
                if self._queue(slot, tid):
                    if claimed_at is None:
                        claimed_at = (tid, kind, time.time())
            wend = min(deadline, time.time() + window)
            while time.time() < wend:
                st = self._read_job(slot)
                if st["done"]:
                    self.stats["deliveries"] += 1
                    lat = time.time() - (claimed_at[2] if claimed_at else time.time())
                    self.stats["last_ran_on"] = st["tid"] or (claimed_at[0] if claimed_at else None)
                    self.stats["last_latency"] = lat
                    self.stats["last_kind"] = claimed_at[1] if claimed_at else None
                    kind = claimed_at[1] if claimed_at else None
                    queued_at = claimed_at[0] if claimed_at else None
                    st.pop("_q", None)
                    return {**st, "claimed": True, "queued_at": queued_at,
                            "kind": kind, "latency": lat,
                            "slot": slot, "job_intact": self.job_intact(slot, job)}
                if st["claim"] and claimed_at is None:
                    claimed_at = (tid, kind, time.time())
                time.sleep(0.003)
        st = self._read_job(slot)
        st.pop("_q", None)
        in_flight = bool(st["claim"]) and not st["done"]
        return {**st, "claimed": bool(st["claim"]), "queued_at": claimed_at[0] if claimed_at else None,
                "kind": claimed_at[1] if claimed_at else None, "latency": None,
                "slot": slot, "job_intact": self.job_intact(slot, job),
                "in_flight": in_flight, "timeout": True}

    def status(self) -> dict:
        return {"arena": hex(self.arena) if self.arena else None,
                "slots_used": self._slot, "have_apc2": HAVE_APC2, **self.stats}
