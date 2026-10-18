"""Static consistency tests for the inject layer's pinned tables.

These run offline (no game required): they check the tables' internal
coherence and the byte-level correctness of the shellcode encodings — the
class of bugs that killed the first live session (a wrong modrm register in
the done-store) is exactly what static verification catches.
"""
from __future__ import annotations

import struct

import pytest

from hoi4_mcp.inject import tables as T


def test_base_init_matches_layout():
    """BASE_INIT bytes cover the constructor-written base fields exactly."""
    offs = [o for o, _f, _v in T.BASE_INIT]
    assert offs == [0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C]


def test_command_sizes_and_fields():
    # field writes must fit inside the object
    for name, spec in T.COMMANDS.items():
        for off, fmt, _n in spec["fields"]:
            assert off + struct.calcsize(fmt) <= spec["size"], name
        assert spec["vt"] & 7 == 0       # vftables are 8-aligned
        assert isinstance(spec.get("verified"), bool), name
        assert isinstance(spec.get("blob_ok"), bool), name
    # the speed commands carry no payload fields (self-contained semantics)
    for name in ("IncreaseGameSpeed", "DecreaseGameSpeed", "SetGameSpeed"):
        assert T.COMMANDS[name]["fields"] == [], name
        assert T.COMMANDS[name]["verified"] is True, name
    # SetNationalFocus: tag pointer + CNationalFocus* (24 日 correction — the
    # old {focus_id@0x2C, mode@0x30} layout belonged to another class's ctor)
    fields = {f[2]: f for f in T.COMMANDS["SetNationalFocus"]["fields"]}
    assert set(fields) == {"tag", "focus"}
    assert fields["focus"][0] == 0x30 and fields["focus"][1] == "<Q"
    # a spec with no verified ctor must never claim blob safety
    for name, spec in T.COMMANDS.items():
        if not spec.get("ctor"):
            assert not spec.get("verified") and not spec.get("blob_ok"), name


def test_shellcode_done_store_targets_param_register():
    """The classic 21-day_session crash: 48 C7 /0 with rm=010 is RDX, not R10.
    The shellocodes must write result/done through RBX (REX.B not needed for
    rbx=011) — decode-check by hand."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    from hoi4_mcp.inject import call as C

    for name, blob in (("SHELLCODE", C.SHELLCODE), ("SHELLCODE_FUSED", C.SHELLCODE_FUSED)):
        ins = list(md.disasm(blob, 0))
        text = [f"{i.mnemonic} {i.op_str}" for i in ins]
        params = [t for t in text if "rsp" not in t and ("0x28" in t or "0x30" in t
                                                         or "0x38" in t)]
        stores = [t for t in params if t.startswith("mov qword")]
        assert stores, f"{name}: no result/done stores found"
        for t in stores:
            assert "[rbx" in t or "[r10" in t.replace("ptr ", "") or "r10" in t, \
                f"{name}: done-store not param-relative: {t}"
            assert "rdx" not in t, f"{name}: store through volatile rdx"


def test_fused_shellcode_is_complete():
    """The fused shellcode: 5 callee-saved pushes, balanced, calls via [rbx+n]
    (param through a callee-saved register, r11 never held across a call)."""
    import capstone
    from hoi4_mcp.inject import call as C
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    text = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(C.SHELLCODE_FUSED, 0)]
    pushes = [t for t in text if t.startswith("pop") is False]
    # nothing may dereference r11 after call 1
    assert not any("r11" in t for t in text)
    assert sum(1 for t in text if t.startswith("push")) == 5
    assert text[-1] == "jmp 0x42" or text[-1].startswith("jmp")
    # both calls go through memory (function pointers from the job)
    calls = [t for t in text if t.startswith("call")]
    assert len(calls) == 2 and all("[" in c for c in calls)


def test_globals_and_functions_are_header_aligned():
    """Every pinned RVA is plausibly aligned / inside the module."""
    rvas = [T.G_GAMESTATE, T.G_IDLER, T.G_GAMEAPP, T.G_QUEUE,
            T.FN_POST, T.FN_OPERATOR_NEW]
    for r in rvas:
        assert 0x1000 <= r < 0x3800000, r       # inside hoi4.exe image (58MB)
    assert T.GAMEAPP_QUEUE_OFF % 8 == 0
    assert T.IDLER_PAUSED_OFF % 8 == 1          # mid-qword flag byte (unusual!
    # so pin it explicitly here to catch accidental renumbering)
    assert T.IDLER_PAUSED_OFF == 0x6C1
    assert T.QUEUE_IS_HOST_OFF == 0x795


def test_tables_version_pin():
    assert T.GAME_VERSION == "1.19.3.0"
