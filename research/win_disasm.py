"""Static disassembly helpers for the Windows PE (hoi4.exe 1.19.3.0).

Purpose: recover the Windows-side equivalents of the reference (Linux) tables:
  - command ctors (which arg lands at which field offset)
  - operator new / Post (the common callees around ctor sites)
  - idler global (static data slot) + GetCommandQueue vtable slot

MSVC x64 calling convention: rcx=this, rdx=arg1, r8=arg2, r9=arg3.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import capstone
import pefile

from hoi4copilot import config

_BIN = config.find_install_dir() / config.EXE_NAME


class PE:
    def __init__(self):
        self.pe = pefile.PE(str(_BIN), fast_load=True)
        self.data = bytes(self.pe.__data__)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = self.section(".text")
        self.sections = {s.Name.rstrip(b"\0").decode(): (s.VirtualAddress, s.Misc_VirtualSize)
                         for s in self.pe.sections}

    def section(self, name):
        for s in self.pe.sections:
            if s.Name.rstrip(b"\0").decode() == name:
                return s.VirtualAddress, s.Misc_VirtualSize, self.data[s.PointerToRawData: s.PointerToRawData + s.SizeOfRawData]
        raise KeyError(name)

    def read_rva(self, rva, n):
        off = self.pe.get_offset_from_rva(rva)
        return self.data[off: off + n]

    def va(self, rva):
        return self.base + rva

    def rva_of_va(self, va):
        return va - self.base


_pe: PE | None = None


def pe() -> PE:
    global _pe
    if _pe is None:
        _pe = PE()
    return _pe


MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


def disasm(rva, n=400, stop_ret=False):
    p = pe()
    code = p.read_rva(rva, n)
    out = []
    for ins in MD.disasm(code, rva):
        tgt = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            tgt = f"  -> {int(ins.op_str, 16):#x}"
        out.append((ins.address, ins.mnemonic, ins.op_str, tgt, ins.bytes))
        if stop_ret and ins.mnemonic == "ret":
            break
    return out


def show(rva, n=400, stop_ret=False):
    for a, m, o, t, _b in disasm(rva, n, stop_ret):
        print(f"{a:#x}: {m} {o}{t}")


# ---------------------------------------------------------------- xref scan
_LEA_OPCODES = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}  # 48 8D <modrm>


def lea_xrefs_to(target_va: int) -> list[int]:
    """RIP-relative lea r64, [rip+disp32] whose target == target_va."""
    p = pe()
    rva0, size, raw = p.text
    out = []
    n = len(raw) - 7
    i = 0
    tgt = target_va - p.base
    while i < n:
        j = raw.find(b"\x48\x8D", i)
        if j < 0 or j >= n:
            break
        if raw[j + 2] in _LEA_OPCODES and j + 3 + 4 <= len(raw):
            disp = struct.unpack_from("<i", raw, j + 3)[0]
            insn_end = j + 7
            if rva0 + insn_end + disp == tgt:
                out.append(rva0 + j)
            i = j + 3
        else:
            i = j + 1
    return out


def find_func_start(rva: int, max_back: int = 0x2000) -> int | None:
    """Walk back to the nearest function start: previous ret/jmp short block
    followed by int3 padding (MSVC emits 0xCC fill between functions)."""
    p = pe()
    rva0 = p.text[0]
    if rva < rva0:
        return None
    lo = max(rva - max_back, rva0)
    raw = p.read_rva(lo, rva - lo)
    # find last run of >=4 CC bytes before rva
    pos = len(raw)
    best = None
    idx = len(raw) - 1
    while idx >= 0:
        if raw[idx] == 0xCC:
            end = idx
            while idx >= 0 and raw[idx] == 0xCC:
                idx -= 1
            run = end - idx
            if run >= 4:
                # function starts right after the padding
                best = lo + idx + 1
                break
        else:
            idx -= 1
    if best is None:
        return None
    return best


def func_end(start: int, max_len: int = 0x4000) -> int:
    p = pe()
    raw = p.read_rva(start, max_len)
    # stop at >=4 CC bytes after at least one ret
    seen_ret = False
    i = 0
    md = MD
    for ins in md.disasm(raw, start):
        if ins.mnemonic == "ret":
            seen_ret = True
        run = raw[ins.address - start: ins.address - start + 4]
        if seen_ret and run == b"\xcc" * 4:
            return ins.address + 1
        if ins.size == 0:
            break
        i = ins.address - start
        if i + 16 > len(raw):
            break
    return start + max_len


# ------------------------------------------------------------- ctor parsing
THIS_REGS = {"rcx"}
ARGREG = {"rdx": 1, "edx": 1, "dl": 1, "r8": 2, "r8d": 2, "r8b": 2,
          "r9": 3, "r9d": 3, "r9b": 3}
SIZE_OF = {"qword": 8, "dword": 4, "word": 2, "byte": 1}
FMT = {8: "<q", 4: "<i", 2: "<h", 1: "<B"}


def parse_ctor(rva: int, end: int | None = None) -> dict:
    """Parse the parameterised ctor: which arg lands at which field offset.

    Returns {offset: {"size": n, "arg": k, "kind": str}} where kind in
    value|ptr|int|bool|handle|deref|fieldN.
    """
    p = pe()
    if end is None:
        end = func_end(rva)
    this = set(THIS_REGS)
    argof = dict(ARGREG)
    derived = {}
    fieldptr = {}
    out = []
    vftarget = None
    nargs = 0
    size = None  # operator new size if ctor is wrapped
    for a, m, o, _t, _b in disasm(rva, end - rva):
        # register copy:  mov rX, rY
        if m == "mov":
            parts = [s.strip() for s in o.split(",", 1)]
            if len(parts) == 2:
                dst, src = parts
                if src in this:
                    this.add(dst)
                    continue
                if src in argof:
                    argof[dst] = argof[src]
                    nargs = max(nargs, argof[src])
                    continue
                # lea rX, [this+off]  -> pointer to a field (capstone prints "lea rX,[rcx+0x28]")
                # handled below by lea branch
        if m == "lea":
            # lea r64, [this+off]
            import re
            mm = re.match(r"(\w+), \[(\w+)\+(0x[0-9a-f]+)\]", o)
            if mm and mm.group(2) in this:
                fieldptr[mm.group(1)] = int(mm.group(3), 16)
                continue
        # mov rX, [arg+off]  (value derived from an argument)
        if m in ("mov", "movzx", "movsx") and "," in o:
            import re
            mm = re.match(r"(\w+), (?:(qword|dword|word|byte) ptr )?\[(\w+)(?:\+(0x[0-9a-f]+))?\]", o)
            if mm and mm.group(3) in argof:
                ai = argof[mm.group(3)]
                off = int(mm.group(4), 16) if mm.group(4) else 0
                kind = "handle" if off == 0x08 else ("deref" if off == 0 else "field%#x" % off)
                derived[mm.group(1)] = (ai, kind, SIZE_OF.get(mm.group(2) or "qword", 8))
                continue
        # stores
        if m == "mov" and "," in o:
            import re
            mm = re.match(r"(?:(qword|dword|word|byte) ptr )?\[(\w+)\], (\w+)$", o)
            if mm and mm.group(2) in this:
                _emit(out, 0, SIZE_OF.get(mm.group(1) or "qword", 8), mm.group(3), argof, derived)
                continue
            mm = re.match(r"(?:(qword|dword|word|byte) ptr )?\[(\w+)(?:\+(0x[0-9a-f]+))?\], (\w+)$", o)
            if mm and mm.group(2) in this:
                off = int(mm.group(3), 16) if mm.group(3) else 0
                _emit(out, off, SIZE_OF.get(mm.group(1) or "qword", 8), mm.group(4), argof, derived)
                continue
            mm = re.match(r"(?:(qword|dword|word|byte) ptr )?\[(\w+)\], (\w+)$", o)
            if mm and mm.group(2) in fieldptr:
                _emit(out, fieldptr[mm.group(2)], SIZE_OF.get(mm.group(1) or "qword", 8),
                      mm.group(3), argof, derived)
                continue
    seen, res = set(), []
    for off, sz, ai, kind in out:
        if off in seen or not (0x08 <= off < 0x400):
            continue
        seen.add(off)
        res.append({"offset": off, "size": sz, "arg": ai, "kind": kind})
    res.sort(key=lambda x: x["offset"])
    return {"ctor": rva, "end": end, "args": nargs, "fields": res, "vftarget": vftarget}


def _emit(out, off, sz, src, argof, derived):
    if src in argof:
        out.append((off, sz, argof[src], "ptr" if sz == 8 else ("bool" if sz == 1 else "int")))
    elif src in derived:
        ai, kind, dsz = derived[src]
        out.append((off, sz, ai, kind))


def find_ctors(class_name: str, verbose=True):
    """Find functions that store the class vftable into [rcx] (= ctor/dtor sites)."""
    import json
    db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
    vt = None
    for c in db["classes"]:
        if c["name"] == class_name:
            vt = c["vftable_rvas"][0]
            break
    if vt is None:
        raise KeyError(class_name)
    sites = lea_xrefs_to(pe().va(vt))
    out = []
    for s in sites:
        start = find_func_start(s)
        if start is None:
            continue
        end = func_end(start)
        # the vftable-store must be near the top (first ~0x60 bytes) for a ctor
        rel = s - start
        out.append({"site": s, "func": start, "end": end, "rel": rel})
    if verbose:
        print(f"{class_name}: vftable {vt:#x}, xrefs {len(sites)}")
        for x in out:
            print(f"  func {x['func']:#x}..{x['end']:#x} site_rel={x['rel']:#x}")
    return out, vt


if __name__ == "__main__":
    cls = sys.argv[1] if len(sys.argv) > 1 else ".?AVCSetNationalFocusCommand@@"
    xs, vt = find_ctors(cls)
    for x in xs:
        print(f"---- func {x['func']:#x} ----")
        show(x["func"], min(0x120, x["end"] - x["func"]))
