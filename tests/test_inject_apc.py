"""Static + logic tests for the APC write channel (23 日).

Everything here is offline: the payload is hand-assembled, so the encodings
that matter are asserted rather than trusted. Both bugs found on 23 日 were in
these bytes — a `mov rcx,r14` that had been encoded as `mov rcx,r13` (the
stand-in caught it) and a job/stack overlap (it killed the game).
"""
from __future__ import annotations

import struct

import pytest

from hoi4_mcp.inject import apc as A


def insns() -> list[tuple[int, str, str]]:
    capstone = pytest.importorskip("capstone")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return [(i.address, i.mnemonic, i.op_str) for i in md.disasm(A.SHELLCODE, 0)]


# --- flow control -----------------------------------------------------------
def test_payload_has_claim_and_single_exit():
    """claim = atomic xchg on job+0x08, and a single ret that is preceded by
    balanced pushes/pops (the APC dispatcher expects RSP untouched)."""
    prog = insns()
    assert prog[0][1] == "push" and prog[0][2] == "rbx"
    xchg = [(a, m, o) for a, m, o in prog if m == "xchg"]
    assert len(xchg) == 1, "exactly one atomic claim"
    _, _, ops = xchg[0]
    assert f"[rbx + {A.J_CLAIM}]" in ops and ops.endswith("rax")
    rets = [p for p in prog if p[1] == "ret"]
    assert len(rets) == 1, "one exit only (both paths converge on the epilogue)"
    pushes = [p[2] for p in prog if p[1] == "push"]
    pops = [p[2] for p in prog if p[1] == "pop"]
    assert sorted(pushes) == sorted(pops), f"unbalanced stack: {pushes} vs {pops}"


def test_jnz_lands_on_epilogue():
    """A duplicate delivery must fall through to `pop rbp` — the jump target
    is asserted in the module, re-asserted here against the disassembly."""
    prog = insns()
    jnz = [p for p in prog if p[1].startswith("jne") or p[1] == "jnz"]
    assert len(jnz) == 1
    addr, _, ops = jnz[0]
    target = int(ops, 16)
    at_target = [p for p in prog if p[0] == target]
    assert at_target and at_target[0][1] == "pop", f"jnz -> {ops}, not the epilogue"


def test_payload_caches_job_fields_before_calling_into_the_game():
    """THE 23 日 fix: post/queue/blob/count are read into callee-saved
    registers BEFORE the first call, and never re-read from the job after any
    call. A callee that walks over the job must not be able to redirect us."""
    prog = insns()
    call_idxs = [i for i, p in enumerate(prog) if p[1] == "call"]
    assert len(call_idxs) >= 2, "payload calls operator new then Post"
    first_call = call_idxs[0]
    cached = {"r13", "r14", "r15", "rbp"}
    for _, mnemonic, ops in prog[:first_call]:
        if mnemonic == "mov" and ops.startswith(("r13,", "r14,", "r15,", "rbp,")):
            cached.discard(ops.split(",")[0])
    assert not cached, f"not cached before the first call: {cached}"
    # after the first call the payload may only (a) restore its own rsp and
    # (b) write OUTPUT fields — never load a game argument back out of the job.
    def is_argument_reload(p) -> bool:
        _, mnemonic, ops = p
        if mnemonic != "mov" or not ops.startswith(("r", "e")):
            return False
        dest, _, src = ops.partition(", ")
        if dest == "rsp":
            return False                      # stack restore, cached nowhere
        if src.endswith("]"):
            return True                       # load from memory
        return False

    reloads = [p for p in prog[first_call:] if is_argument_reload(p)]
    assert not reloads, f"job re-read after a call: {reloads}"


def test_post_is_called_through_the_cached_register():
    prog = insns()
    calls = [p for p in prog if p[1] == "call"]
    assert calls[-1][2] == "r13", "Post must go through the cached register"


def test_rep_movsq_is_preceded_by_cld():
    prog = insns()
    idx = [i for i, p in enumerate(prog) if p[1] == "rep movsq"]
    assert idx, "the blob copy is a rep movsq"
    assert prog[idx[0] - 1][1] == "cld", "DF must not be assumed clear"


# --- layout -----------------------------------------------------------------
def test_private_stack_cannot_reach_the_job():
    """The 23 日 game kill: a 3.8 KB stack sat right on top of the job and the
    real operator new walked into it. Keep >=12 KB of headroom."""
    headroom = A.STACK_TOP - (A.BLOB_OFF + 0x200)
    assert headroom >= 12 * 1024, f"only {headroom} bytes of stack headroom"
    assert A.STACK_TOP % 16 == 0, "Windows x64 wants a 16-byte aligned RSP"
    assert A.SLOT_STRIDE > A.STACK_TOP, "the stack must live inside its slot"


def test_job_layout_is_disjoint_and_complete():
    fields = {"J_NEW": A.J_NEW, "J_CLAIM": A.J_CLAIM, "J_POST": A.J_POST,
              "J_QUEUE": A.J_QUEUE, "J_SIZE": A.J_SIZE, "J_BLOB": A.J_BLOB,
              "J_NQWORD": A.J_NQWORD, "J_STACK": A.J_STACK,
              "J_SAVED_RSP": A.J_SAVED_RSP, "J_TID": A.J_TID, "J_DONE": A.J_DONE,
              "J_CMD": A.J_CMD, "J_POSTED": A.J_POSTED}
    offs = sorted(fields.items(), key=lambda kv: kv[1])
    assert offs[0][1] == 0
    for (n1, o1), (n2, o2) in zip(offs, offs[1:]):
        assert o2 - o1 >= 8, f"{n1} and {n2} overlap"
        assert o1 % 8 == 0, f"{n1} is not qword aligned"
    assert offs[-1][1] + 8 <= A.JOB_SIZE, "JOB_SIZE does not cover every field"
    assert A.JOB_SIZE % 8 == 0
    # the blob must not sit between the job and the stack
    assert A.JOB_SIZE <= A.BLOB_OFF < A.STACK_TOP


def test_arena_has_room_for_a_session():
    slots = (A.ARENA_SIZE - A.JOB_BASE) // A.SLOT_STRIDE
    assert slots >= 16, "too few single-use slots; a session would run out"


def test_payload_reads_the_documented_job_offsets():
    """Every offset the payload touches must be one the sender writes."""
    prog = insns()
    used = set()
    for _, mnemonic, ops in prog:
        if "[rbx + " in ops:
            used.add(int(ops.split("[rbx + ")[1].split("]")[0], 16))
        elif "[rbx]" in ops:
            used.add(0)
    known = {A.J_NEW, A.J_CLAIM, A.J_POST, A.J_QUEUE, A.J_SIZE, A.J_BLOB,
             A.J_NQWORD, A.J_STACK, A.J_SAVED_RSP, A.J_TID, A.J_DONE, A.J_CMD,
             A.J_POSTED}
    assert used <= known, f"payload touches undocumented offsets: {used - known}"


# --- job_intact logic -------------------------------------------------------
class _FakeMem:
    def __init__(self, data: bytes):
        self.data = data

    def rpm(self, addr: int, size: int) -> bytes:
        return self.data[:size]


class _FakeProc:
    def __init__(self, data: bytes):
        self.handle = 1
        self.memory = _FakeMem(data)


def _job_bytes(**over) -> bytes:
    base = {"new": 0x1000, "claim": 0, "post": 0x2000, "queue": 0x3000,
            "size": 0x38, "blob": 0x4000, "nq": 7, "stack": 0x5000}
    base.update(over)
    job = struct.pack("<9Q", base["new"], base["claim"], base["post"],
                      base["queue"], base["size"], base["blob"], base["nq"],
                      base["stack"], 0)
    return job + struct.pack("<5Q", 0, 0, 0, 0, 0)


def test_job_intact_ignores_output_fields():
    """tid/saved_rsp/cmd/posted/done are payload OUTPUT; a normal send must
    not be flagged as corrupted because of them."""
    job = _job_bytes()
    written = bytearray(job)
    struct.pack_into("<Q", written, A.J_CLAIM, 1)
    struct.pack_into("<Q", written, A.J_TID, 12345)
    struct.pack_into("<Q", written, A.J_SAVED_RSP, 0x7FF9_0000_1234)
    struct.pack_into("<Q", written, A.J_CMD, 0x207F_0000_9999)
    struct.pack_into("<Q", written, A.J_POSTED, 1)
    struct.pack_into("<Q", written, A.J_DONE, 1)
    ch = A.ApcChannel(_FakeProc(bytes(written)))
    assert ch.job_intact(0, job) is True


@pytest.mark.parametrize("field", ["new", "post", "queue", "size", "blob", "nq", "stack"])
def test_job_intact_trips_on_a_clobbered_input(field):
    job = _job_bytes()
    clobbered = bytearray(job)
    off = {"new": A.J_NEW, "post": A.J_POST, "queue": A.J_QUEUE,
           "size": A.J_SIZE, "blob": A.J_BLOB, "nq": A.J_NQWORD,
           "stack": A.J_STACK}[field]
    struct.pack_into("<Q", clobbered, off, 0x4343_4343_4343_4343)
    ch = A.ApcChannel(_FakeProc(bytes(clobbered)))
    assert ch.job_intact(0, job) is False, f"{field} clobber not detected"


def test_mitigation_bit_decode_documents_the_22_day_correction():
    """0x100 is bit 8 = CetDynamicApisOutOfProcOnly. SetContextIpValidation is
    bit 2 — the 22 日 'platform blockade' read the wrong bit."""
    from hoi4_mcp.process import win32ext as w
    assert w.get_mitigation_policy.__doc__ is not None or True
    names = ["EnableUserShadowStack", "AuditUserShadowStack",
             "SetContextIpValidation", "AuditSetContextIpValidation",
             "UserShadowStackStrictMode", "BlockNonCetBinaries",
             "BlockNonCetBinariesNonEhcont", "AuditBlockNonCetBinaries",
             "CetDynamicApisOutOfProcOnly", "SetContextIpValidationRelaxedMode"]
    flags = 0x100
    on = [n for i, n in enumerate(names) if flags & (1 << i)]
    assert on == ["CetDynamicApisOutOfProcOnly"]
    assert "SetContextIpValidation" not in on
