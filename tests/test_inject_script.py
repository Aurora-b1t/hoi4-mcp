"""Static + logic tests for the write-v3.1 VM payload (24 日).

The payload is machine-generated (keystone) but hand-written, so the properties
that keep it safe are asserted against the disassembly rather than trusted:

  * one atomic claim, one exit, balanced pushes/pops,
  * the op list lives outside the private stack's reach (separate allocation),
  * the shield handler's CONTEXT offsets are the ones winnt.h defines,
  * op records are OP_SIZE apart (the 24 日 bug: 7-qword records in a 0x40
    stride made every op after the first read garbage),
  * CALL targets are whitelisted before anything reaches the target process.

The stand-in integration (every op + every fault mode) lives in
research/apc_probe/script_dryrun.py; it needs subprocesses, so it is not part
of the fast suite.
"""
from __future__ import annotations

import struct

import pytest

from hoi4copilot.inject import script as S


def insns() -> list[tuple[int, str, str]]:
    capstone = pytest.importorskip("capstone")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return [(i.address, i.mnemonic, i.op_str) for i in md.disasm(S.PAYLOAD, 0)]


def body() -> list[tuple[int, str, str]]:
    return [i for i in insns() if S.SYM["vm"] <= i[0] < S.SYM["handler"]]


# --- payload structure -------------------------------------------------------
def test_payload_layout_is_reserved_and_ordered():
    assert S.SYM["vm"] == 0
    assert S.SYM["vm"] < S.SYM["handler"] < S.SYM["recover"] < S.SYM["g_arena_lo"]
    assert S.SYM["g_guard_null"] + 8 <= S.JOB_BASE, "payload overlaps the job area"
    assert S.SYM["g_recover"] > S.SYM["recover"], "the stub must exist before it is referenced"


def test_vm_has_one_claim_one_call_one_exit():
    prog = body()
    assert prog[0][1] == "push" and prog[0][2] == "rbx"
    xchg = [p for p in prog if p[1] == "xchg"]
    assert len(xchg) == 1, "exactly one atomic claim"
    assert f"[rbx + {S.S_CLAIM}]" in xchg[0][2]
    calls = [p for p in prog if p[1] == "call"]
    assert len(calls) == 4, ("four call sites: op-1 dispatch, op-7 operator new, "
                             "op-7 constructor, op-8 call_this")
    assert all(p[2] in ("rax", "r10") for p in calls), \
        "every call goes through a register (r10 = operator new, read before ctor)"
    rets = [p for p in prog if p[1] == "ret"]
    assert len(rets) == 1, "one return path"
    pushes = sorted(p[2] for p in prog if p[1] == "push")
    pops = sorted(p[2] for p in prog if p[1] == "pop")
    assert pushes == pops, f"unbalanced stack: {pushes} vs {pops}"


def test_alloc_ctor_keeps_the_object_for_call_obj():
    """op 7 must remember the object in a global (g_last_obj) and build the
    ctor call as rcx=obj, rdx/r8/r9 = a2/a3/a4; op 8 must read that global and
    substitute it into the requested register slot."""
    prog = body()
    text = "\n".join(f"{m} {o}" for _a, m, o in prog)
    assert "qword ptr [rip + " in text
    assert any(m == "mov" and o == "rcx, rax" for _a, m, o in prog), \
        "op 7 must pass the new object in rcx"
    assert any(m == "mov" and o.startswith("r11, qword ptr [rip") for _a, m, o in prog), \
        "op 8 must take the object from g_last_obj"
    for reg in ("rcx, r11", "rdx, r11", "r8, r11", "r9, r11"):
        assert any(m == "mov" and o == reg for _a, m, o in prog), \
            f"slot substitution into {reg} missing"
    assert any(m == "shr" and o.startswith("rcx, ") for _a, m, o in prog), \
        "op 7 must decode the object size from a5"


def test_call_uses_four_register_arguments_and_no_stack_block():
    """op 1 passes rcx/rdx/r8/r9 straight from a2..a5; stack arguments are not a
    supported path (the API refuses a 5th argument), so the payload must not
    contain any stack-copy machinery."""
    prog = body()
    text = "\n".join(f"{m} {o}" for _a, m, o in prog)
    for off in (S.OP_A2, S.OP_A3, S.OP_A4, S.OP_A5):
        assert any(m == "mov" and f"[r13 + {off:#x}]" in o for _a, m, o in prog), \
            f"op 1 must read a register argument at op+{off:#x}"
    assert "rep movsq" not in text, "the retired stack-copy path is back"
    assert any(m == "mov" and o == "rcx, rbp" for _a, m, o in prog), \
        "rcx is parked in rbp across the op and restored at the call"
    assert text.count("qword ptr [rip +") >= 2, \
        "the in-call guard must wrap the call"


def test_calls_are_wrapped_by_the_in_call_flag():
    """The shield's third rule keys on g_in_call: every call out of the VM must
    set it and clear it again, so a hard fault inside a callee we invoked can be
    told apart from the game's own faults (24 日: Post with a bad argument)."""
    prog = body()
    seq = [(m, o) for _a, m, o in prog]
    calls = [i for i, (m, o) in enumerate(seq) if m == "call"]
    assert len(calls) == 4
    for idx in calls:
        before = seq[max(0, idx - 3):idx]
        after = seq[idx + 1:idx + 4]
        assert any("g_in_call" not in o and "[rip + " in o and "1" in o for _m, o in before), \
            f"call at index {idx} is not preceded by g_in_call = 1: {before}"
        assert any("[rip + " in o and ", 0" in o for _m, o in after), \
            f"call at index {idx} is not followed by g_in_call = 0: {after}"


def test_call_obj_slot_is_bounded():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    with pytest.raises(S.ScriptError):
        sc.call_obj(0x140050000, 4)
    with pytest.raises(S.ScriptError):
        sc.call_obj(0x140050000, 0, 1, 2, 3, 4)


def test_program_pointer_comes_from_the_job_not_the_stack():
    """The op list is a separate allocation: the payload loads it from the job
    (S_DATA) and walks it in r13 — nothing about the program lives on the
    private stack, so a deep callee cannot rewrite the program it is running."""
    prog = body()
    assert any(m == "mov" and o == "r12, qword ptr [rbx]" for _, m, o in prog), \
        "the data-page pointer must come from the job"
    assert any(m == "lea" and o == "r13, [r12 + 0x40]" for _, m, o in prog), \
        "the op cursor must derive from the data page"
    assert any(m == "mov" and o == "r14, qword ptr [r12 + 8]" for _, m, o in prog), \
        "the op count must come from the data page header"
    # the private stack is only ever switched once, and restored once
    stack_sets = [o for _, m, o in prog if m == "mov" and o.startswith("rsp, qword ptr [rbx")]
    assert len(stack_sets) == 2, f"one switch, one restore: {stack_sets}"
    assert not any("[rsp" in o for _, m, o in prog if m == "mov"), \
        "the VM must not keep state on its private stack between ops"


def test_copy_ops_use_rep_movs_and_stos():
    text = "\n".join(f"{m} {o}" for _, m, o in body())
    assert "rep movsb" in text and "rep stosb" in text
    assert text.count("cld") == 3, "every string op clears DF first"


def test_write_raw_covers_1_2_4_8():
    text = "\n".join(f"{m} {o}" for _, m, o in body())
    for want in ("mov byte ptr [rdi], al", "mov word ptr [rdi], ax",
                 "mov dword ptr [rdi], eax", "mov qword ptr [rdi], rax"):
        assert want in text, f"{want} missing from WRITE_RAW"


def test_op_records_are_op_size_apart():
    """The 24 日 bug: Op.pack emitted 7 qwords into a 0x40 stride, so the second
    op of any multi-op script was decoded from the middle of the first."""
    op = S.Op(S.OP_CALL, 0x1000, 1, 2, 3, 4)
    assert len(op.pack()) == S.OP_SIZE
    assert S.OP_RES + 8 <= S.OP_SIZE
    two = struct.unpack("<16Q", op.pack() + op.pack())
    assert two[8] == S.OP_CALL, "the second record must start at +0x40"


# --- op encoding -------------------------------------------------------------
def test_local_buffers_are_relocated_at_pack_time():
    page = 0x7FF000000000
    read = S.Op(S.OP_READ, 0x1100, 0x1234, 0x20)
    write = S.Op(S.OP_WRITE, 0x2000, 0x1110, 0x10)
    raw = S.Op(S.OP_WRITE_RAW, 0x2000, 0xFF, 1)
    assert struct.unpack_from("<Q", read.pack(page), S.OP_A0)[0] == 0x1100 + page
    assert struct.unpack_from("<Q", read.pack(page), S.OP_A1)[0] == 0x1234
    assert struct.unpack_from("<Q", write.pack(page), S.OP_A1)[0] == 0x1110 + page
    assert struct.unpack_from("<Q", write.pack(page), S.OP_A0)[0] == 0x2000
    assert struct.unpack_from("<Q", raw.pack(page), S.OP_A0)[0] == 0x2000, \
        "raw ops are absolute and must never be relocated"


def test_script_builder_allocates_distinct_buffers():
    sc = S.Script()
    a = sc.read(0x1000, 0x20)
    b = sc.write(0x2000, b"x" * 8)
    assert a.offset != b.offset
    assert sc.buffers[b.offset] == b"x" * 8
    assert [op.code for op in sc.ops] == [S.OP_READ, S.OP_WRITE]


def test_buffer_and_op_limits():
    sc = S.Script()
    with pytest.raises(S.ScriptError):
        sc.read(0x1000, 0x1000)                      # > 0x800
    with pytest.raises(S.ScriptError):
        sc.write_raw(0x1000, 1, 3)                   # only 1/2/4/8
    with pytest.raises(S.ScriptError):
        for _ in range(30):
            sc.read(0x1000, 0x800)                   # exceeds the page


def test_call_targets_are_whitelisted_before_anything_is_written():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    sc.call(0x140050000, 1, 2, 3, 4)
    assert sc.call_targets == [0x140050000]
    with pytest.raises(S.ScriptError):
        sc.call(0x7FF000000000)
    with pytest.raises(S.ScriptError):
        S.Script().call(0x140050000)                 # no whitelist => refuse all


def test_too_many_args_refused():
    """The VM has no stack-argument path, so a 5th argument is refused up front
    instead of being silently dropped (24 日's trap: the payload ignored it)."""
    sc = S.Script(allow_calls={(0x1000, 0x2000)})
    with pytest.raises(S.ScriptError):
        sc.call(0x1000, 1, 2, 3, 4, 5)
    with pytest.raises(S.ScriptError):
        sc.alloc_ctor(0x1000, 0x1100, 0x40, 1, 2, 3, 4)
    with pytest.raises(S.ScriptError):
        sc.call_obj(0x1000, 1, 1, 2, 3, 4)


# --- operand layout + run-time references ------------------------------------
def test_call_maps_arguments_to_the_abi_registers():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    sc.call(0x140050000, 1, 2, 3, 4)
    op = sc.ops[0]
    assert (op.a0, op.a1) == (0x140050000, 0), "a1 is unused (no stack block)"
    assert (op.a2, op.a3, op.a4, op.a5) == (1, 2, 3, 4)
    sc.call(0x140050000, 1, 2)
    assert (sc.ops[1].a2, sc.ops[1].a3, sc.ops[1].a4, sc.ops[1].a5) == (1, 2, 0, 0)


def test_alloc_ctor_packs_the_object_size_into_a5():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    i = sc.alloc_ctor(0x140060000, 0x140070000, 0x38, 0xAAAA, 0xBBBB, 0xCCCC)
    op = sc.ops[i]
    assert (op.a0, op.a1, op.a2, op.a3, op.a4) == (0x140060000, 0x140070000,
                                                   0xAAAA, 0xBBBB, 0xCCCC)
    assert op.a5 >> 40 == 0x38, "size in the top 24 bits"
    assert sc.alloc_sizes[i] == 0x38
    sc.alloc_ctor(0x140060000, 0x140070000, 0x48, 1)
    assert sc.ops[-1].a5 >> 40 == 0x48
    assert (sc.ops[-1].a2, sc.ops[-1].a3, sc.ops[-1].a4) == (1, 0, 0)


def test_call_obj_encodes_slot_and_argument_count_in_one_operand():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    i = sc.call_obj(0x140080000, 1, 0xAA, 0)
    op = sc.ops[i]
    assert op.a1 == 1 + 16 * 2, "slot 1 with two explicit arguments"
    assert (op.a2, op.a3, op.a4, op.a5) == (0xAA, 0, 0, 0)
    i = sc.call_obj(0x140080000, 0)
    assert sc.ops[i].a1 == 0, "slot 0, no explicit arguments beyond the object"


def test_refs_resolve_to_the_producers_result_field_and_enforce_causality():
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    producer = sc.call(0x140050000, 1)
    sc.call(0x140050001, producer, 2)
    raw, blocks = S.ScriptChannel._resolve_refs(_Stub(), sc, 0x1000000000)
    slot = 0x1000000000 + 0 * S.OP_SIZE + S.OP_RES
    assert raw[S.OP_SIZE + S.OP_A2:S.OP_SIZE + S.OP_A2 + 8] == \
        struct.pack("<Q", slot), "the consumer passes the producer's result field"
    assert blocks == {}
    # a Ref used before it exists must be refused, not read as zero
    bad = S.Script(allow_calls={(0x140000000, 0x140100000)})
    r = bad.call(0x140050000, 1)
    bad.ops.insert(0, S.Op(S.OP_CALL, 0x140050000, 0, *([r] + [0] * 3)))
    with pytest.raises(S.ScriptError):
        S.ScriptChannel._resolve_refs(_Stub(), bad, 0x1000000000)
    # ... and a Script may only be resolved once
    with pytest.raises(S.ScriptError):
        S.ScriptChannel._resolve_refs(_Stub(), sc, 0x1000000000)


class _Stub:
    """ScriptChannel._resolve_refs without a process (the page VA is supplied)."""
    _resolve_refs = S.ScriptChannel._resolve_refs


def test_read_ptr_hands_over_the_buffer_address():
    """A read_ptr Ref IS the local buffer, so its operand is that buffer's
    ABSOLUTE address — the `&value` shape a ctor like SetResearch's wants."""
    sc = S.Script(allow_calls={(0x140000000, 0x140100000)})
    ref = sc.read_ptr(0x1400A0000)
    assert ref.addr == S.BUF_BASE, "the value lives in a local buffer"
    assert sc.ops[ref.op].code == S.OP_READ
    sc.call(0x140050000, ref)
    page = 0x10000000000
    raw, _blocks = S.ScriptChannel._resolve_refs(_Stub(), sc, page)
    q = struct.unpack_from("<8Q", raw, S.OP_SIZE)
    assert q[S.OP_A2 // 8] == page + S.BUF_BASE, \
        "the consumer passes the buffer's absolute address"


# --- shield ------------------------------------------------------------------
def test_shield_handler_checks_membership_and_returns_search_by_default():
    """The handler must bail out with EXCEPTION_CONTINUE_SEARCH (0) when no
    payload is in flight, and rewrite CONTEXT only in the takeover path."""
    prog = [i for i in insns() if S.SYM["handler"] <= i[0] < S.SYM["recover"]]
    text = [(a, m, o) for a, m, o in prog]
    joined = "\n".join(f"{m} {o}" for _, m, o in text)
    assert f"[rip + " in joined and "g_cur_job" not in joined  # resolved to rip-relative
    # the "search" path is `xor eax,eax; ret`; the takeover path sets eax = -1
    assert any(m == "xor" and o == "eax, eax" for _, m, o in text)
    assert any(m == "mov" and o == "eax, 0xffffffff" for _, m, o in text)
    last = [t for t in text if not t[1].startswith("nop")][-1]
    assert last[1] == "ret"


def test_shield_context_offsets_match_winnt():
    """CONTEXT for AMD64: Rbx 0x90, Rsp 0x98, Rip 0xf8, R13 0xe0. A wrong
    offset here would silently corrupt a thread's registers instead of
    recovering it."""
    code = S.PAYLOAD[S.SYM["handler"]:S.SYM["recover"]]
    assert struct.pack("<I", 0x90) in code and b"\x90" in code
    text = "\n".join(f"{m} {o}" for _, m, o in
                     [(0, i.mnemonic, i.op_str) for i in
                      __import__("capstone").Cs(__import__("capstone").CS_ARCH_X86,
                                                __import__("capstone").CS_MODE_64)
                      .disasm(code, S.SYM["handler"])])
    for off in ("0x90", "0x98", "0xf8", "0xe0"):
        assert f"[r8 + {off}]" in text, f"CONTEXT.{off} write missing: {text}"
    for off in ("0x40", "0x48", "0x58"):
        assert f"[r9 + {off}]" in text, f"job fault record {off} missing"


def test_recover_stub_marks_fault_and_restores_rsp():
    prog = [(i.mnemonic, i.op_str) for i in
            __import__("capstone").Cs(__import__("capstone").CS_ARCH_X86,
                                      __import__("capstone").CS_MODE_64)
            .disasm(S.PAYLOAD[S.SYM["recover"]:S.SYM["g_arena_lo"]], S.SYM["recover"])]
    text = "\n".join(f"{m} {o}" for m, o in prog)
    assert f"qword ptr [rbx + {S.S_STATUS:#x}], 2".replace("0x30", "0x30") in text
    assert f"[rbx + {S.S_DONE:#x}], 1" in text
    assert f"rsp, qword ptr [rbx + {S.S_SAVED_RSP:#x}]" in text


# --- job layout --------------------------------------------------------------
def test_job_layout_fits_and_inputs_are_inside():
    assert S.S_JOB_SIZE == 0x60 and S.S_JOB_SIZE % 8 == 0
    for off in S.INPUT_FIELDS:
        assert off + 8 <= S.S_JOB_SIZE
    outs = (S.S_TID, S.S_DONE, S.S_STATUS, S.S_NOPS_DONE, S.S_FAULT_RIP,
            S.S_FAULT_CODE, S.S_LAST_RAX, S.S_FAULT_R13, S.S_SAVED_RSP)
    assert not (set(outs) & set(S.INPUT_FIELDS)), "outputs must not be compared by job_intact"


def test_slots_leave_enough_stack_below_the_job():
    """The 23 日 killer was a private stack that reached the job. The VM slot is
    0x8000 with the stack top well above the job, i.e. tens of KB of headroom."""
    assert S.SLOT_STRIDE == 0x8000
    assert S.STACK_TOP <= 0x7FF0
    assert S.STACK_TOP - S.S_JOB_SIZE >= 0x3000
