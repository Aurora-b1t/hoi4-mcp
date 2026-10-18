"""Offline verification of the command specs against the installed binary.

The 24 日 crash was a *spec* bug, not a channel bug: the SetNationalFocus entry
in tables.py carried a constructor that belongs to CSetFuelPriorityCommand, so
the hand-built blob had the right vtable and the wrong fields, and the game AV'd
while describing the command (RVA 0x24c2f0d). `specverify` rebuilds both facts
from the binary and these tests keep the table honest:

  * the vftable must belong to the command's RTTI class,
  * the recorded ctor must install that very vftable,
  * the object size must cover every field the ctor writes,
  * `blob_ok` may only be True when the blob's fields cover the ctor's writes,
  * an unverified spec must be refused by the writer.

Skipped when the game is not installed (CI / other machines).
"""
from __future__ import annotations

import pytest

from hoi4copilot.inject import tables as T
from hoi4copilot.inject import specverify as SV


@pytest.fixture(scope="module")
def reports():
    try:
        SV.Image.get()
    except Exception as exc:                      # noqa: BLE001 - install missing
        pytest.skip(f"hoi4.exe not available: {exc}")
    return SV.verify_all()


@pytest.mark.parametrize("name", sorted(T.COMMANDS))
def test_spec_matches_the_binary(name, reports):
    rep = reports[name]
    assert rep.ok, f"{name}: " + "; ".join(rep.problems)


@pytest.mark.parametrize("name", sorted(T.COMMANDS))
def test_blob_ok_implies_field_coverage(name, reports):
    spec = T.COMMANDS[name]
    coverage = [n for n in reports[name].notes if n.startswith("field coverage complete")]
    if spec.get("blob_ok"):
        assert coverage, f"{name}: blob_ok=True but the ctor writes unknown fields"
    if spec.get("verified"):
        assert spec.get("ctor"), f"{name}: verified without a ctor RVA"


def test_setnationalfocus_layout_is_the_corrected_one():
    """Pin the correction: +0x28 = tag (int32), +0x30 = focus object pointer,
    and no field at +0x2C (the ctor never writes it)."""
    spec = T.COMMANDS["SetNationalFocus"]
    assert [f[0] for f in spec["fields"]] == [0x28, 0x30]
    assert spec["size"] == 0x38 and spec["ctor"] == 0x01146F70
    writes = SV.Image.get().ctor_writes(spec["ctor"])
    assert 0x30 in writes and "0x2c" not in {hex(o) for o in writes}


def test_unverified_specs_are_refused_by_the_writer():
    """The guard that would have prevented the 24 日 crash: never post a spec
    whose layout was not verified against the ctor."""
    from hoi4copilot.inject.commands import CommandLayer, CallError

    class _Fake:
        pass

    with pytest.raises(CallError):
        CommandLayer.send_apc(_Fake(), "PauseGame")
    with pytest.raises(CallError):
        CommandLayer.send_apc(_Fake(), "DecreaseGameSpeed")   # blob path disabled


def test_post_argument_order_from_the_binary(reports):
    """Machine-check the ABI that killed the game on 24 日 (second crash):

        Post(queue, cmd, force)  ->  rcx=queue, rdx=cmd, r8=force

    Evidence straight out of Post's prologue: the gate byte is read from
    [rcx + QUEUE_IS_HOST_OFF] (rcx is the queue), the virtual gate predicates go
    through `mov rax,[rdx]` (rdx is the command object) and `test r8b,r8b` is the
    force flag. The VM must therefore place the object in slot 1 (rdx).
    """
    img = SV.Image.get()
    text = [f"{i.mnemonic} {i.op_str}" for i in img.insns(T.FN_POST, 0x40)]
    joined = "\n".join(text)
    assert f"byte ptr [rcx + {T.QUEUE_IS_HOST_OFF:#x}]" in joined, \
        "Post no longer gates on the queue at [rcx+0x795] — argument order changed?"
    assert "rax, qword ptr [rdx]" in joined and "call qword ptr [rax + 0x80]" in joined, \
        "Post no longer treats rdx as the command object"
    assert "r8b, r8b" in joined, "Post no longer takes the force flag in r8"

    from hoi4copilot.inject.script import Script
    sc = Script(allow_calls={(0, 1 << 64)})
    sc.call_obj(T.FN_POST, 1, 0xAA, 0)
    op = sc.ops[-1]
    assert op.a1 & 15 == 1, "the command object belongs in slot 1 (rdx)"
    assert op.a1 >> 4 == 2, "the slot operand also carries the argument count"
