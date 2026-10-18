"""specverify.py — offline verification of the command specs in tables.py.

24 日: `SetNationalFocus`'s spec carried a *misattributed* constructor. The
object we posted had the correct vtable and the wrong field layout, the game
accepted it into the queue, and then AV'd while describing it (RVA 0x24c2f0d) —
process gone. Nothing in the pipeline could have caught that, because the spec
was never checked against the binary.

This module is that check, and it runs offline (no game, just the PE):

  1. the vftable RVA must belong to the command's RTTI class,
  2. the constructor entry in the spec must actually install that vftable
     (`lea reg,[rip+vft]` + `mov [rcx],reg`),
  3. the object size must appear as the `mov ecx,<size>` immediate at a call
     site of the constructor (the UI's own `operator new` site),

Every failure is reported as a problem string; `tests/test_inject_specs.py`
runs this over the whole table.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from . import tables as T

RTTI_JSON = Path(__file__).resolve().parent.parent / "tables" / "generated" / "rtti.json"


@dataclass
class SpecReport:
    name: str
    ok: bool = True
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, why: str) -> None:
        self.ok = False
        self.problems.append(why)

    def note(self, why: str) -> None:
        self.notes.append(why)


class Image:
    """Minimal read/disasm wrapper around hoi4.exe (lazy, cached)."""

    _inst = None

    def __init__(self) -> None:
        import pefile
        self.pe = pefile.PE(str(config.find_install_dir() / config.EXE_NAME), fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase

    @classmethod
    def get(cls) -> "Image":
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def read_rva(self, rva: int, n: int) -> bytes:
        return self.pe.get_data(rva, n)

    def u32(self, rva: int) -> int:
        return int.from_bytes(self.read_rva(rva, 4), "little")

    def u64(self, rva: int) -> int:
        return int.from_bytes(self.read_rva(rva, 8), "little")

    def insns(self, rva: int, n: int = 0x60):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        return list(md.disasm(self.read_rva(rva, n), rva))

    def lea_targets(self, rva: int, n: int = 0x60) -> list[int]:
        """RIP-relative `lea reg,[rip+disp32]` targets inside [rva, rva+n).

        Byte-level on purpose: capstone's operand details need `detail = True`
        and the encoding here is fixed (REX.W + 8D + modrm mod=00 rm=101).
        """
        raw = self.read_rva(rva, n)
        out = []
        for i in range(len(raw) - 7):
            if raw[i] not in (0x48, 0x4C, 0x49, 0x4D) or raw[i + 1] != 0x8D:
                continue
            if (raw[i + 2] & 0xC7) != 0x05:
                continue
            disp = int.from_bytes(raw[i + 3:i + 7], "little", signed=True)
            out.append(rva + i + 7 + disp)
        return out

    def call_xrefs(self, target_rva: int, scan: int | None = None) -> list[int]:
        """E8 rel32 call sites in .text targeting target_rva."""
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0") == b".text":
                rva0, raw = s.VirtualAddress, self.pe.get_data(s.VirtualAddress,
                                                               s.Misc_VirtualSize)
                break
        else:
            return []
        out, i = [], 0
        while True:
            j = raw.find(b"\xe8", i)
            if j < 0 or j + 5 > len(raw):
                break
            rel = int.from_bytes(raw[j + 1:j + 5], "little", signed=True)
            if rva0 + j + 5 + rel == target_rva:
                out.append(rva0 + j)
            i = j + 1
        return out

    def ctor_writes(self, ctor_rva: int, limit: int = 0x80) -> dict[int, str]:
        """{offset: description} for every `mov [reg+off], src` the ctor makes,
        stopping at its first ret.

        This is the crash-class check: a field the constructor initialises and
        the spec does not know about is a field the game will dereference in a
        hand-built blob and find zero.
        """
        out: dict[int, str] = {}
        for i in self.insns(ctor_rva, limit):
            if i.mnemonic == "ret":
                break
            if i.mnemonic != "mov" or " ptr [" not in i.op_str:
                continue
            dst, _, src = i.op_str.partition(", ")
            if "rip" in dst:
                continue
            for reg in ("rcx", "rbx", "rdi", "rsi", "rdx", "r8"):
                if not dst.startswith(f"{'qword' if 'qword' in dst else 'dword' if 'dword' in dst else 'word' if 'word' in dst else 'byte'} ptr [{reg}"):
                    continue
                tail = dst.split("[", 1)[1].split("]", 1)[0]
                parts = tail.split("+")
                off = 0
                if len(parts) > 1:
                    try:
                        off = int(parts[1].strip(), 16)
                    except ValueError:
                        continue
                elif parts[0].strip() != reg:
                    continue
                out[off] = f"{dst}, {src}"
        return out


def rtti_vftables() -> dict[str, list[int]]:
    d = json.loads(RTTI_JSON.read_text(encoding="utf-8"))
    return {c["name"]: [int(x) for x in (c.get("vftable_rvas") or [])] for c in d["classes"]}


def class_names_for(name: str) -> list[str]:
    """The RTTI name is usually C<Name>Command, but CPauseGame is not."""
    return [f".?AVC{name}Command@@", f".?AVC{name}@@", f".?AV{name}@@"]


def verify(name: str, spec: dict, *, img: Image | None = None,
           rtti: dict[str, list[int]] | None = None) -> SpecReport:
    rep = SpecReport(name)
    img = img or Image.get()
    rtti = rtti if rtti is not None else rtti_vftables()

    owners = [cn for cn in class_names_for(name) if spec["vt"] in rtti.get(cn, [])]
    if not owners:
        others = [cn for cn, v in rtti.items() if spec["vt"] in v][:4]
        rep.fail(f"vftable {spec['vt']:#x} does not belong to {name} "
                 f"(RTTI owners: {others or 'none'})")
    else:
        rep.note(f"vftable {spec['vt']:#x} = {owners[0]}")

    ctor = spec.get("ctor")
    if ctor is None:
        if spec.get("verified"):
            rep.fail("verified=True but no constructor RVA is recorded")
        else:
            rep.note("no ctor recorded (spec is not postable)")
        return rep

    targets = img.lea_targets(ctor, 0x50)
    if spec["vt"] not in targets:
        rep.fail(f"ctor {ctor:#x} never loads vftable {spec['vt']:#x} "
                 f"(lea targets: {[hex(t) for t in targets[:4]]})")
    if not any(i.mnemonic == "mov" and i.op_str.startswith("qword ptr [rcx],")
               for i in img.insns(ctor, 0x50)):
        rep.fail(f"ctor {ctor:#x} does not install a vftable into [rcx]")

    # every field the ctor initialises must be known to the spec (BASE_INIT
    # covers the command base); an uncovered offset is a field a hand-built
    # blob would leave zero — the 24 日 crash class.
    base_offsets = {off for off, _fmt, _val in T.BASE_INIT}
    field_offsets = {f[0] for f in spec.get("fields") or []}
    covered = base_offsets | field_offsets
    writes = img.ctor_writes(ctor)
    uncovered = {off: how for off, how in writes.items()
                 if off not in covered and off != 0}
    if uncovered:
        detail = ", ".join(f"+{off:#x} ({how})" for off, how in sorted(uncovered.items()))
        if spec.get("blob_ok"):
            rep.fail("blob_ok=True but the ctor writes fields a hand-built blob "
                     f"would leave zero: {detail}")
        else:
            rep.note(f"blob path disabled on purpose (blob_ok=False): ctor writes {detail}")
    else:
        if not spec.get("blob_ok"):
            rep.note("field coverage complete — blob_ok=False is conservative, not required")
        rep.note(f"field coverage complete ({len(writes)} writes, "
                 f"{len(field_offsets)} spec fields)")

    # the object must be big enough for every field the ctor writes: a size
    # smaller than the last write is a heap overflow waiting for the ctor path
    widths = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
    min_size = 0
    for off, how in writes.items():
        w = next((v for k, v in widths.items() if how.startswith(k)), 1)
        min_size = max(min_size, off + w)
    if spec["size"] < min_size:
        rep.fail(f"size {spec['size']:#x} is smaller than the ctor's last write "
                 f"(needs >= {min_size:#x}) — the ctor would overflow the object")
    else:
        rep.note(f"size {spec['size']:#x} covers the ctor's writes (>= {min_size:#x})")

    # object size at the ctor's call sites (the UI's operator new immediate)
    sizes = []
    for site in img.call_xrefs(ctor):
        for i in img.insns(max(site - 0x30, 0), 0x30):
            if i.mnemonic == "mov" and i.op_str.startswith("ecx, 0x"):
                sizes.append(int(i.op_str.split("0x")[1], 16))
    if sizes and spec["size"] not in sizes:
        rep.fail(f"size {spec['size']:#x} not among the ctor call-site "
                 f"allocations {[hex(s) for s in sorted(set(sizes))]}")
    elif sizes:
        rep.note(f"size {spec['size']:#x} confirmed at the ctor's call site")
    else:
        rep.note("no direct call site found (ctor may be called indirectly)")

    if not spec.get("verified"):
        rep.note("verified=False: the write layer refuses to post this spec")
    return rep


def verify_all() -> dict[str, SpecReport]:
    img = Image.get()
    rtti = rtti_vftables()
    return {n: verify(n, s, img=img, rtti=rtti) for n, s in T.COMMANDS.items()}


if __name__ == "__main__":
    for name, rep in verify_all().items():
        flag = "OK   " if rep.ok else "FAIL "
        print(f"{flag}{name}: verified={T.COMMANDS[name].get('verified')}")
        for p in rep.problems:
            print(f"        problem: {p}")
        for n in rep.notes:
            print(f"        note:    {n}")
