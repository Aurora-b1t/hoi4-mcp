"""Remote call primitive: run a function inside the game process.

Protocol (single-shot; NEVER inside a loop — see inject/__init__.py):
  1. VirtualAllocEx an RWX arena once (shellcode + param + private stack).
  2. RACY SCAN (no suspension): two GetThreadTimes snapshots ~50ms apart;
     threads whose user time grew are genuinely executing. For those, two
     rip samples (4ms apart) must both sit in a legal image AND differ —
     a thread parked in a kernel wait re-plays a constant trap-frame user
     RIP, which GetThreadContext cannot tell apart from real user-mode
     execution. Time growth + rip motion divides the two (22 日).
  3. Suspend ALL game threads (atomic snapshot; the game is paused anyway),
     then verify the shortlisted thread's rip is STILL in a legal image and
     graft it: saved CONTEXT onto the stack, RIP=shellcode, RCX=param,
     RSP=private stack.
  4. Resume ONLY that thread; it calls func(args), stores the result and the
     done-flag, then spins. Other threads stay frozen.
  5. Poll the done-flag; suspend the thread, restore the saved CONTEXT,
     resume everything.

The expensive per-thread probing now happens BEFORE the freeze window
(21 日 crash study: the frozen-window had 118 GetThreadContext calls and
picked blind; grafting a kernel-waiting thread and restore races across 118
suspended threads are the leading crash hypotheses for the "2nd send dies"
failure. The racy shortlist keeps the freeze window short and the graft
deterministic). Main thread comes first in every ordering: it is the queue
owner and the path player clicks take (the Linux reference hijacks main).

TLS note: the main-thread hijack keeps TLS state intact (gs:[0x58] slot
array is populated by the loader; a CreateRemoteThread newcomer gets fresh
TLS and game functions reading TLS slots would run with wrong thread-local
state). On timeout we restore the original context and resume everything:
the caller thread continues exactly where it was, and any lock it held is
released — a recoverable, clean abort (the remote thread keeps spinning
harmlessly).
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import struct
import time

from ..process import win32ext as w

log = logging.getLogger(__name__)

# exit-tail variant for fresh-thread calls: after storing result/done, jump
# through [param+0x38] (= ntdll!RtlExitUserThread resolved by the caller) so
# the injected thread terminates cleanly instead of spinning forever.
SHELLCODE_EXIT = bytes.fromhex(
    "53"                # push rbx
    "4883EC20"          # sub rsp, 0x20           ; shadow space; rsp%16==0
    "4889CB"            # mov rbx, rcx            ; param -> rbx
    "488B03"            # mov rax, [rbx]          ; func
    "488B4B08"          # mov rcx, [rbx+0x08]     ; arg1
    "488B5310"          # mov rdx, [rbx+0x10]     ; arg2
    "4C8B4318"          # mov r8,  [rbx+0x18]     ; arg3
    "4C8B4B20"          # mov r9,  [rbx+0x20]     ; arg4
    "FFD0"              # call rax
    "48894328"          # mov [rbx+0x28], rax     ; result
    "48C7433001000000"  # mov qword [rbx+0x30], 1 ; done
    "4883C420"          # add rsp, 0x20
    "FF6338"            # jmp qword [rbx+0x38]    ; exit_fn BEFORE popping rbx
                        #  (the earlier pop made this read garbage and AV'd)
    "9999"              # never reached; padding
)

# arena layout
SC_OFF = 0x0000          # shellcode
PARAM_OFF = 0x0200       # job: {func, a1..a4, result, done[, exit_fn]}
RESULT_OFF = 0x0228
DONE_OFF = 0x0230
EXITFN_OFF = 0x0238
BLOB_OFF = 0x0280        # fused-job blob payload staging area
STACK_BASE = 0x1000      # private stack 0x1000..0x3000 (rsp grows down)
STACK_TOP = 0x2FF8       # % 16 == 8 (shellcode expects entry rsp%16==8)
ARENA_SIZE = 0x4000

# fused build+post: ONE freeze cycle constructs the command (operator new),
# copies the pre-built qword-rounded blob and posts it. The entire send is a
# single suspension window, never an injection loop.
#
# fused job layout (PARAM_OFF): operator_new(+0x00) | post(+0x08) |
# queue(+0x10) | cmd_size(+0x18) | blob_src(+0x20) | out cmd(+0x28) |
# out post(+0x30) | done(+0x38) | n_qwords(+0x40)
SHELLCODE_FUSED = bytes.fromhex(
    "53" "56" "57" "4154" "4155"  # push rbx,rsi,rdi,r12,r13; rsp ≡ 0 mod 16
    "4883EC20"                    # sub rsp, 0x20          ; shadow space
    "4889CB"                      # mov rbx, rcx           ; job (callee-saved:
                                  #  must survive operator new across call 1)
    "488B4B18"                    # mov rcx, [rbx+0x18]    ; cmd_size
    "FF13"                        # call [rbx]             ; operator new
    "4989C4"                      # mov r12, rax           ; cmd
    "4889C7"                      # mov rdi, rax
    "488B7320"                    # mov rsi, [rbx+0x20]    ; blob source
    "488B4B40"                    # mov rcx, [rbx+0x40]    ; n qwords
    "F348A5"                      # rep movsq
    "488B4B10"                    # mov rcx, [rbx+0x10]    ; queue
    "4C89E2"                      # mov rdx, r12           ; cmd
    "4531C0"                      # xor r8, r8             ; force = 0
    "FF5308"                      # call [rbx+0x08]        ; Post(queue, cmd, 0)
    "48894330"                    # mov [rbx+0x30], rax    ; post result
    "4C896328"                    # mov [rbx+0x28], r12    ; cmd ptr
    "48C7433801000000"            # mov qword [rbx+0x38], 1; done
    "EBFE"                        # jmp $                  ; spin (restored)
)

# param lives in RBX (callee-saved): r10/r11 are VOLATILE per the Windows ABI
# and are free to be clobbered by the callee — holding state across `call`
# there is a real bug (it AVs once any callee touches r10). rbx is preserved.
SHELLCODE = bytes.fromhex(
    "53"                # push rbx                ; save callee-saved
    "4883EC20"          # sub rsp, 0x20           ; shadow space; rsp%16==0
    "4889CB"            # mov rbx, rcx            ; param -> rbx
    "488B03"            # mov rax, [rbx]          ; func
    "488B4B08"          # mov rcx, [rbx+0x08]     ; arg1
    "488B5310"          # mov rdx, [rbx+0x10]     ; arg2
    "4C8B4318"          # mov r8,  [rbx+0x18]     ; arg3
    "4C8B4B20"          # mov r9,  [rbx+0x20]     ; arg4
    "FFD0"              # call rax
    "48894328"          # mov [rbx+0x28], rax     ; result
    "48C7433001000000"  # mov qword [rbx+0x30], 1 ; done
    "4883C420"          # add rsp, 0x20
    "5B"                # pop rbx
    "EBFE"              # jmp $                   ; spin (context gets restored)
    "CCCC"              # padding
)

# CONTEXT (x64) — full record, 1232 bytes, 16-aligned buffer
CONTEXT_AMD64 = 0x10000B
_OFF = {"ContextFlags": 0x30, "Rax": 0x78, "Rcx": 0x80, "Rdx": 0x88,
        "Rbx": 0x90, "Rsp": 0x98, "Rbp": 0xA0, "Rsi": 0xA8, "Rdi": 0xB0,
        "R8": 0xB8, "R9": 0xC0, "R10": 0xC8, "R11": 0xD0, "R12": 0xD8,
        "R13": 0xE0, "R14": 0xE8, "R15": 0xF0, "Rip": 0xF8}


class Context:
    """Minimal x64 CONTEXT wrapper over a 1232-byte record."""

    def __init__(self):
        self.buf = (ctypes.c_byte * 1232)()
        self._base = ctypes.addressof(self.buf)
        self._align()

    def _align(self):
        if self._base % 16:
            raise RuntimeError("CONTEXT buffer must be 16-byte aligned")

    def get(self, name):
        off = _OFF[name]
        return struct.unpack_from("<Q", self.buf, off)[0]

    def set(self, name, value):
        off = _OFF[name]
        struct.pack_into("<Q", self.buf, off, value)

    def flags(self, value=CONTEXT_AMD64):
        struct.pack_into("<I", self.buf, _OFF["ContextFlags"], value)


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.GetThreadContext.restype = BOOLT = wt.BOOL
_k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
_k32.SetThreadContext.restype = BOOLT
_k32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.c_void_p]
_k32.GetExitCodeThread.restype = BOOLT
_k32.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
_k32.VirtualAllocEx.restype = ctypes.c_void_p
_k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
_k32.VirtualProtectEx.restype = BOOLT
_k32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD)]
_k32.WaitForSingleObject.restype = wt.DWORD
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

PAGE_EXECUTE_READWRITE = 0x40


class CallError(RuntimeError):
    pass


class RemoteCaller:
    """One arena per process; every call() is a suspend-hijack-restore cycle."""

    def __init__(self, proc, timeout: float = 5.0, attempts: int = 8,
                 rearm_delay: float = 0.01,
                 allow_module_patterns: tuple[str, ...] = (),
                 mode: str = "newthread",
                 probe_window: float = 0.05,
                 legacy_fallback: bool = False):
        self.p = proc
        self.m = proc.memory
        self.timeout = timeout
        self.attempts = attempts          # freeze re-arms before giving up
        self.rearm_delay = rearm_delay
        self.allow_module_patterns = allow_module_patterns
        self.mode = mode
        self.probe_window = probe_window  # GetThreadTimes delta window (no suspension)
        # 21 日未决 (同会话 2+ 发概率性崩) 的对策第一发: 关掉冻结窗内的全量
        # 盲扫, 只在 racy 短名单里定点摘取。legacy_fallback=True 才恢复旧行为。
        self.legacy_fallback = legacy_fallback
        self._arena: int | None = None
        self._calls = 0
        self._ranges: list[tuple[int, int]] | None = None
        self._suspended_now: set[int] = set()
        self.stats_probes = 0
        self.stats_shortlist_hits = 0
        self.stats_freezes = 0

    # -- arena ----------------------------------------------------------------
    def _alloc(self) -> int:
        if self._arena:
            return self._arena
        addr = w.virtual_alloc_ex(self.p.handle, ARENA_SIZE, PAGE_EXECUTE_READWRITE)
        w.write_process_memory(self.p.handle, addr, SHELLCODE)
        self._arena = addr
        return addr

    def close(self):
        if self._arena:
            try:
                w.virtual_free_ex(self.p.handle, self._arena)
            except OSError:
                pass
            self._arena = None

    # -- thread helpers ---------------------------------------------------------
    def _threads(self) -> list[int]:
        """Game thread ids, MAIN THREAD FIRST (earliest creation time,
        from GetThreadTimes — no third-party dependency)."""
        tids = w.list_thread_ids(self.p.pid)
        created: dict[int, float] = {}
        for tid in tids:
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                c, _e, _k, _u = w.get_thread_times(h)
                created[tid] = c
            except OSError:
                pass
            finally:
                w._k32.CloseHandle(h)
        if created and len(created) > 1:
            tids.sort(key=lambda t: created.get(t, float("inf")))
        return tids

    @staticmethod
    def _suspend_all(tids: list[int]) -> dict[int, int]:
        """Returns {tid: previous_suspend_count}; only count==0 threads are
        ours to resume (an already-suspended thread keeps its own owner)."""
        prev = {}
        for tid in tids:
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                prev[tid] = w.suspend_thread(h)
            finally:
                w._k32.CloseHandle(h)
        return prev

    @staticmethod
    def _resume_frozen(prev: dict[int, int], skip: int | None = None) -> None:
        for tid, was in prev.items():
            if was != 0 or tid == skip:
                continue
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                w.resume_thread(h)
            finally:
                w._k32.CloseHandle(h)

    def _legal_ranges(self) -> list[tuple[int, int]]:
        """RIP ranges that mean 'frozen in user code': the game image plus any
        extra modules allowed by pattern (dry runs run in python3*.dll, which
        is safe ONLY because their hosts never wait — research tooling only)."""
        if self._ranges is None:
            p = self.p
            rs = [(p.base, p.base + p.image_size)]
            for name, base, size in w.enumerate_modules(p.handle):
                if any(pat in name for pat in self.allow_module_patterns):
                    rs.append((base, base + size))
            self._ranges = rs
        return self._ranges

    def _in_image(self, rip: int) -> bool:
        return any(lo <= rip < hi for lo, hi in self._legal_ranges())

    # -- racy probing (NO suspension) -------------------------------------------
    def _user_times(self) -> dict[int, float]:
        """{tid: user-mode seconds} — accumulates for genuinely running
        threads, stays flat for parked ones (GetThreadTimes is documented
        to work on running threads)."""
        out: dict[int, float] = {}
        for tid in self._threads():
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                u = w.get_thread_times(h)[3]
                out[tid] = u
            except OSError:
                pass
            finally:
                w._k32.CloseHandle(h)
        return out

    @staticmethod
    def _sample_rip(handle: int) -> int | None:
        ctx = Context()
        ctx.flags()
        if not _k32.GetThreadContext(handle, ctypes.addressof(ctx.buf)):
            return None
        return ctx.get("Rip")

    def probe_targets(self, rip_iv: float = 0.004) -> list[int]:
        """Racy shortlist of threads GENUINELY executing user code — no
        suspension anywhere in this method.

        Both gates required:
          a) user time grew across probe_window (kernel-blessed evidence the
             thread runs; a kernel-waiting thread does not accumulate user
             time);
          b) two rip samples rip_iv apart, ALL in a legal image and DISTINCT
             (motion evidence). A thread parked in a kernel wait re-plays a
             constant trap-frame rip, which GetThreadContext cannot tell apart
             from real user-mode execution on its own (21 日 惨案 3).

        Failure modes are benign: a false-negative just costs one re-arm; the
        final authority is the frozen rip re-verification under suspension.
        Ordering: main thread first (queue owner, player-click path).
        """
        t0 = self._user_times()
        time.sleep(self.probe_window)
        t1 = self._user_times()
        self.stats_probes += 1
        out: list[int] = []
        for tid in self._threads():
            a, b = t0.get(tid), t1.get(tid)
            if a is None or b is None or b <= a:
                continue                    # parked in a wait, new, or gone
            try:
                h = w.open_thread(tid)
            except OSError:
                continue
            try:
                r1 = self._sample_rip(h)
                time.sleep(rip_iv)
                r2 = self._sample_rip(h)
            except OSError:
                continue
            finally:
                w._k32.CloseHandle(h)
            if r1 is None or r2 is None:
                continue
            if r1 == r2 or not (self._in_image(r1) and self._in_image(r2)):
                continue                    # identical rip == parked/spinning
            out.append(tid)
        return out

    def _frozen_rip(self, tid: int) -> int | None:
        """rip of a SUSPENDED thread (authoritative check under freeze)."""
        try:
            h = w.open_thread(tid)
        except OSError:
            return None
        try:
            return self._sample_rip(h)
        finally:
            w._k32.CloseHandle(h)

    # -- freeze/graft/restore ----------------------------------------------------
    def _pick_from_shortlist(self, shortlist: list[int]) -> int | None:
        """Under an active suspension snapshot: first shortlisted thread whose
        rip is STILL in a legal image (it moved or parked between the racy
        scan and the freeze — then re-arm instead of grafting blind)."""
        for tid in shortlist:
            if tid not in self._suspended_now:
                continue
            rip = self._frozen_rip(tid)
            if rip is not None and self._in_image(rip):
                return tid
        return None

    def _pick_target(self, tids: list[int]) -> int:
        """LEGACY full scan under freeze: first thread NOT suspended whose rip
        is inside a legal image. ⚠ Cannot distinguish genuine user-mode rip
        from a kernel-wait trap-frame rip (21 日 惨案 3); kept behind
        legacy_fallback=True for availability study only."""
        for tid in tids:
            rip = self._frozen_rip(tid)
            if rip is not None and self._in_image(rip):
                return tid
        raise CallError("no thread frozen inside a legal image (all threads "
                        "sit in kernel waits at this instant)")

    def _attempt_one(self, arena: int, param: int, shellcode: bytes,
                     done_off: int, result_offs: tuple[int, ...],
                     what: str, shortlist: list[int]) -> tuple[int, ...] | None:
        """One freeze→graft→poll→restore cycle against `shellcode` with job at
        `param`. Returns the readback values or None (no legal target → re-arm)."""
        tids = self._threads()
        prev = self._suspend_all(tids)
        self._suspended_now = {tid for tid, was in prev.items() if was == 0}
        self.stats_freezes += 1
        target = None
        th = None
        try:
            # 22 日: 定点摘取 — racy 短名单在冻结后逐一复核可用性,
            # 失败即 re-arm, 绝不盲摘; legacy 全量扫仅在显式 fallback 时启用。
            target = self._pick_from_shortlist(shortlist) if shortlist else None
            if target is not None:
                self.stats_shortlist_hits += 1
            if target is None:
                if self.legacy_fallback:
                    target = self._pick_target(tids)
                else:
                    return None                 # re-arm: nothing grafted
            th = w.open_thread(target)
            saved = Context()
            saved.flags()
            if not _k32.GetThreadContext(th, ctypes.addressof(saved.buf)):
                raise ctypes.WinError(ctypes.get_last_error())
            ctx = Context()
            ctypes.memmove(ctx.buf, saved.buf, 1232)
            ctx.flags()
            ctx.set("Rip", arena + SC_OFF)
            ctx.set("Rcx", param)
            ctx.set("Rsp", arena + STACK_TOP)
            if not _k32.SetThreadContext(th, ctypes.addressof(ctx.buf)):
                raise ctypes.WinError(ctypes.get_last_error())
            w.resume_thread(th)

            deadline = time.time() + self.timeout
            done = 0
            rips = []
            while time.time() < deadline:
                try:
                    done = int.from_bytes(self.m.rpm(arena + done_off, 8), "little")
                except OSError:
                    break                       # process died mid-call
                if done:
                    break
                if len(rips) < 6:
                    probe = Context()
                    probe.flags()
                    if _k32.GetThreadContext(th, ctypes.addressof(probe.buf)):
                        rips.append(probe.get("Rip"))
                time.sleep(0.002)

            w.suspend_thread(th)
            if not _k32.SetThreadContext(th, ctypes.addressof(saved.buf)):
                raise ctypes.WinError(ctypes.get_last_error())
            while w.resume_thread(th) > 0:
                pass                            # drain any extra suspend count
            w._k32.CloseHandle(th)
            th = None
            self._calls += 1
            readbacks = [int.from_bytes(self.m.rpm(arena + o, 8), "little")
                         for o in result_offs]
            if not done:
                raise CallError(
                    f"remote call did not finish ({what}); original context "
                    "restored, threads resumed. target=" + hex(target) +
                    " rips=" + " ".join(hex(r) for r in rips))
            return tuple(readbacks)
        finally:
            if th is not None:
                try:
                    w._k32.CloseHandle(th)
                except OSError:
                    pass
            self._suspended_now = set()
            self._resume_frozen(prev, skip=target)

    def _run_hijacked(self, shellcode: bytes, job_blob: bytes, done_off: int,
                      result_offs: tuple[int, ...], what: str) -> tuple[int, ...]:
        """Write shellcode+job (pre-freeze), then per attempt: racy shortlist →
        freeze → targeted graft → poll → restore. Everything expensive happens
        OUTSIDE the freeze window; re-arms cost nothing but a re-probe."""
        arena = self._alloc()
        param = arena + PARAM_OFF
        w.write_process_memory(self.p.handle, arena + SC_OFF, shellcode)
        w.write_process_memory(self.p.handle, param, job_blob)
        last_err: Exception | None = None
        for _attempt in range(self.attempts):
            shortlist = self.probe_targets()
            try:
                r = self._attempt_one(arena, param, shellcode, done_off,
                                      result_offs, what, shortlist)
                if r is not None:
                    return r
            except OSError as e:
                last_err = e                    # process died mid-call
                break
            time.sleep(self.rearm_delay)
        if last_err:
            raise CallError(f"process died during hijacked call "
                            f"({what or 'job'})") from last_err
        raise CallError(f"no genuinely-running user-code thread shortlisted in "
                        f"{self.attempts} racy probes (freeze cycles with no "
                        f"graft are harmless); nothing hijacked ({what or 'job'})")

        # -- the call ---------------------------------------------------------------
    def call(self, func_va: int, args=(), what: str = "") -> int:
        """Run func(args...) in the game process once. ≤4 register args.

        mode="hijack": freeze-graft-poll-restore cycle (needs a thread frozen
        in user code; unreliable in a paused game — kept for research).
        mode="newthread": CreateRemoteThread with a self-exiting shellcode.
        Default; TLS-sensitive paths inside Post are disabled in SP sessions,
        and command EXECUTION happens later on the game's own main thread."""
        if len(args) > 4:
            raise CallError("remote call supports at most 4 register args "
                            "(stack args unimplemented on purpose)")
        if self.mode == "newthread":
            return self._call_newthread(func_va, args, what)
        return self._call_hijack(func_va, args, what)

    def _call_newthread(self, func_va: int, args, what: str) -> int:
        arena = self._alloc()
        param = arena + PARAM_OFF
        exit_fn = self._exit_fn()
        blob = struct.pack("<5Q", func_va, *([int(a) for a in args] + [0] * (4 - len(args))))
        blob += struct.pack("<QQ", 0, 0)          # result, done
        blob += struct.pack("<Q", exit_fn)
        w.write_process_memory(self.p.handle, param, blob)
        w.write_process_memory(self.p.handle, arena + SC_OFF, SHELLCODE_EXIT)
        h, tid = w.create_remote_thread(self.p.handle, arena + SC_OFF, param)
        try:
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    done = int.from_bytes(self.m.rpm(arena + DONE_OFF, 8), "little")
                except OSError:
                    raise CallError(f"process died during remote call "
                                    f"({what or hex(func_va)})")
                if done:
                    break
                time.sleep(0.002)
            result = int.from_bytes(self.m.rpm(arena + RESULT_OFF, 8), "little")
            self._calls += 1
            if not done:
                raise CallError(f"remote thread did not finish within "
                                f"{self.timeout}s ({what or hex(func_va)}); "
                                "result armed but untrusted")
            return result
        finally:
            w._k32.CloseHandle(h)
            # free the param slot for the next call (optional; next call rewrites)
            self._exit_fn_seen = True

    def _exit_fn(self) -> int:
        """ntdll!RtlExitUserThread, resolved once (system-dll base is shared)."""
        if not getattr(self, "_exitfn_addr", None):
            import ctypes
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.GetModuleHandleW.restype = ctypes.c_void_p
            k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            k32.GetProcAddress.restype = ctypes.c_void_p
            k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            ntd = k32.GetModuleHandleW("ntdll.dll")
            addr = k32.GetProcAddress(ntd, b"RtlExitUserThread")
            if not addr:
                raise CallError("cannot resolve ntdll!RtlExitUserThread")
            self._exitfn_addr = int(addr)
        return self._exitfn_addr

    def _call_hijack(self, func_va: int, args, what: str) -> int:
        arena = self._alloc()
        param = arena + PARAM_OFF
        blob = struct.pack("<5Q", func_va, *([int(a) for a in args] + [0] * (4 - len(args))))
        blob += struct.pack("<QQ", 0, 0)      # result, done
        (result,) = self._run_hijacked(SHELLCODE, blob, DONE_OFF,
                                       (RESULT_OFF,), what or hex(func_va))
        return result

    def hijack_fused(self, new_va: int, post_va: int, queue: int,
                     blob: bytes, size: int, what: str) -> tuple[int, int]:
        """ONE freeze window: operator new + copy the pre-built blob + Post.
        Returns (cmd_ptr, posted)."""
        arena = self._alloc()
        n_qwords = (size + 7) // 8
        w.write_process_memory(self.p.handle, arena + BLOB_OFF,
                               blob.ljust(n_qwords * 8, b"\0"))
        # job layout — MUST match SHELLCODE_FUSED:
        #   +0x00 new | +0x08 post | +0x10 queue | +0x18 size | +0x20 blob_src
        #   | +0x28 cmd (out) | +0x30 posted (out) | +0x38 done | +0x40 n_qwords
        job = struct.pack("<9Q", new_va, post_va, queue, size, arena + BLOB_OFF,
                          0, 0, 0, n_qwords)
        done_off = PARAM_OFF + 0x38
        result_offs = (PARAM_OFF + 0x28, PARAM_OFF + 0x30)
        cmd, posted = self._run_hijacked(
            SHELLCODE_FUSED, job, done_off, result_offs, what or "fused build&post")
        return cmd, posted

    def stats(self) -> dict:
        return {"arena": hex(self._arena) if self._arena else None,
                "calls": self._calls,
                "probes": self.stats_probes,
                "shortlist_hits": self.stats_shortlist_hits,
                "freezes": self.stats_freezes,
                "legacy_fallback": self.legacy_fallback}
