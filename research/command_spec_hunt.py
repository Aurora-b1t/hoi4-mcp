"""command_spec_hunt.py — verify/derive a command's spec from the binary alone.

24 日 lesson: `inject/tables.py` carried a *misattributed* constructor for
SetNationalFocus (the note's 0x1146E60 belongs to CSetFuelPriorityCommand), so
a hand-built blob had the right vtable and the wrong field layout. The game did
not reject it — it AV'd while describing the command (RVA 0x24c2f0d).

This tool rebuilds a spec from the only authoritative sources:

  1. the vftable RVA from MSVC RTTI (tables/generated/rtti.json),
  2. every `lea reg,[rip+vft]` xref in .text — the constructors and factories,
  3. the field writes inside those constructors (`mov [rcx+off], src`),
  4. the `mov ecx,<size>; call operator new` site next to the ctor call, which
     pins the object size,
  5. (optionally) the UI call site's argument setup, to name each field.

Usage:
  python research/command_spec_hunt.py                    # all of tables.COMMANDS
  python research/command_spec_hunt.py SetNationalFocus --ctx 0x60
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.inject import tables as T                              # noqa: E402
from research.win_disasm import disasm, pe                              # noqa: E402
from research.find_vft_refs import scan_lea_refs, vft_owner             # noqa: E402
from research.win_callers import call_xrefs                             # noqa: E402

NEW = T.FN_OPERATOR_NEW


def ctor_of(vft_rva: int) -> list[int]:
    """lea xrefs that install the vftable into [rcx]/[rax] a few bytes later."""
    out = []
    for insn, _t in scan_lea_refs(vft_rva):
        insns = disasm(insn, 0x28)
        if any(m == "mov" and o.startswith("qword ptr [rc") and o.endswith("rax")
               for _a, m, o, _t2, _b in insns[:6]):
            out.append(insn)
    return out


def field_writes(ctor_rva: int, span: int = 0x100) -> list[str]:
    """`mov [rcx+off], src` / `mov dword ptr [rcx+off], imm` inside the ctor."""
    out = []
    for _a, m, o, _t, raw in disasm(ctor_rva, span):
        if m != "mov" or not o.startswith(("qword ptr [rcx", "dword ptr [rcx",
                                           "word ptr [rcx", "byte ptr [rcx")):
            continue
        if o.endswith("rax") and "lea" not in o:
            pass
        out.append(f"{o}  [{raw.hex()}]")
        if o.startswith("qword ptr [rcx], rax") and len(out) > 1:
            pass
    return out


def new_sites(near: int, window: int = 0x60) -> list[str]:
    """`mov ecx,<size>` immediately before a call to operator new near `near`."""
    out = []
    for _a, m, o, _t, raw in disasm(max(near - window, 0), window * 2):
        if m == "mov" and o.startswith("ecx, 0x"):
            out.append(o)
    return out


def ctor_entry(lea_rva: int, back: int = 0x40) -> int | None:
    """Walk back over the instruction stream to the function entry (the byte
    after a run of int3 padding). The lea site is the vftable store; the entry
    is what send_ctor_apc() must call."""
    p = pe()
    for k in range(1, back):
        if p.read_rva(lea_rva - k, 1) == b"\xcc":
            return lea_rva - k + 1
    return None


def arg_usage(ctor_rva: int, span: int = 0x80) -> dict[str, list[str]]:
    """How the constructor consumes its register arguments.

    MSVC x64: rcx=this, rdx=arg1, r8=arg2, r9=arg3. The interesting shapes are
      * `mov eax, [rdx]`   -> arg1 is a POINTER to an int (the UI's &tag)
      * `mov [rcx+off], r8` -> arg2 is stored verbatim (a handle/pointer)
      * `test r8, r8`      -> arg2 may be NULL (optional)
    """
    out: dict[str, list[str]] = {"rdx": [], "r8": [], "r9": [], "stores": []}
    for _a, m, o, _t, _raw in disasm(ctor_rva, span):
        if m == "ret":
            break
        if m in ("mov", "movzx", "movsx", "lea"):
            for reg in ("rdx", "r8", "r9"):
                if f", qword ptr [{reg}]" in o or f", dword ptr [{reg}]" in o \
                        or f", word ptr [{reg}]" in o or f", byte ptr [{reg}]" in o:
                    out[reg].append(f"{o}   (deref: pointer to value)")
                elif o.startswith(f"[rcx +") and o.endswith(reg):
                    out["stores"].append(f"{o}   ({reg} stored verbatim)")
        elif m == "test" and o in ("r8, r8", "rdx, rdx", "r9, r9"):
            out[o.split(",")[0]].append(f"test {o}   (optional / may be NULL)")
    return {k: v for k, v in out.items() if v}


REF_TABLE = (Path(__file__).resolve().parents[1] / "research" / "clausewitz_ref"
             / "calling" / "tables" / "commands.txt")


def ref_entry(class_name: str) -> str | None:
    """The reference (Linux) table's row for the same class, for cross-checking
    field *kinds* (addresses are platform-specific; structure is not)."""
    short = class_name.replace(".?AV", "").replace("@@", "")
    try:
        for line in REF_TABLE.read_text(encoding="utf-8").splitlines():
            if line.startswith(short + " "):
                return line.rstrip()
    except OSError:
        return None
    return None


def full_hunt(tag: str, ctx: int = 0, dump: bool = False) -> dict:
    """One command class: RTTI -> vftable -> ctor entry -> size -> arg usage.

    `tag` may be a bare command name (SetResearch), a class name
    (CSetResearchCommand) or a full RTTI name (.?AVCSetResearchCommand@@).
    """
    d = json.loads((Path(__file__).resolve().parents[1] / "hoi4copilot" / "tables"
                    / "generated" / "rtti.json").read_text(encoding="utf-8"))
    classes = {c["name"]: c for c in d["classes"]}
    if tag.startswith(".?AV"):
        candidates = [tag]
    else:
        base = tag[1:] if tag.startswith("C") and tag[1:2].isupper() else tag
        candidates = [f".?AVC{base}Command@@", f".?AVC{base}@@", f".?AV{base}@@",
                      f".?AVC{tag}Command@@", f".?AV{tag}@@"]
    name = next((c for c in candidates if c in classes), candidates[0])
    cls = classes.get(name)
    if not cls:
        near = [n for n in classes if tag.lower() in n.lower()][:8]
        return {"class": name, "error": "not in RTTI", "near": near}
    rep: dict = {"class": name, "ref_table": ref_entry(name)}
    for vft in [int(x) for x in (cls.get("vftable_rvas") or [])]:
        rep["vftable"] = hex(vft)
        leas = scan_lea_refs(vft)
        rep["vft_xrefs"] = [hex(x) for x, _t in leas]
        ctors = []
        for lea, _t in leas:
            entry = ctor_entry(lea)
            if entry is None:
                continue
            ins = disasm(entry, 0x60)
            if not any(m == "mov" and o.startswith("qword ptr [rcx],") for _a, m, o, _t2, _b in ins):
                continue
            ctors.append(entry)
            key = f"ctor@{entry:#x}"
            rep[key] = {
                "writes": [f"+{off:#x} {how}" for off, how in
                           sorted(Image_writes(entry).items())],
                "args": arg_usage(entry),
                "sizes_at_call_sites": sorted({s for x in call_xrefs(entry)
                                               for s in new_sites(x, 0x40)}),
                "callers": [hex(x) for x in call_xrefs(entry)[:6]],
            }
            if ctx:
                for x in call_xrefs(entry)[:2]:
                    rep[f"callctx@{x:#x}"] = [
                        f"{a:#x}: {m} {o}" for a, m, o, _t3, _b
                        in disasm(max(x - ctx, 0), ctx + 0x30)]
        rep["ctors"] = [hex(c) for c in ctors]
        if dump:
            for c in ctors[:1]:
                rep[f"body@{c:#x}"] = [f"{a:#x}: {b.hex():<20} {m} {o}"
                                       for a, m, o, _t4, b in disasm(c, 0x80)]
    return rep


def Image_writes(ctor_rva: int) -> dict[int, str]:
    """ctor writes as {offset: 'kind src'} (offset 0 = the vftable store)."""
    out: dict[int, str] = {}
    for _a, m, o, _t, _b in disasm(ctor_rva, 0x80):
        if m == "ret":
            break
        if m != "mov" or " ptr [" not in o:
            continue
        dst, _, src = o.partition(", ")
        if not dst.startswith(("qword", "dword", "word", "byte")):
            continue
        tail = dst.split("[", 1)[1].split("]", 1)[0]
        reg, _, offs = tail.partition(" + ")
        if reg.strip() not in ("rcx", "rbx"):
            continue
        off = int(offs, 16) if offs else 0
        out[off] = f"{dst.split(' ptr')[0]} <- {src}"
    return out


def hunt(tag: str, spec: dict | None, vft: int | None = None, ctx: int = 0) -> dict:
    """Return a report for one command class."""
    name = tag if tag.startswith(".?AV") else f".?AVC{tag}Command@@"
    d = json.loads((Path(__file__).resolve().parents[1] / "hoi4copilot" / "tables"
                    / "generated" / "rtti.json").read_text(encoding="utf-8"))
    classes = {c["name"]: c for c in d["classes"]}
    cls = classes.get(name)
    if not cls:
        near = [n for n in classes if tag.lower() in n.lower()][:8]
        return {"class": name, "error": "not in RTTI", "near": near}
    vfts = [int(x) for x in (cls.get("vftable_rvas") or [])]
    if vft is not None:
        vfts = [vft]
    rep = {"class": name, "rtti_vftables": [hex(v) for v in vfts],
           "table_vt": hex(spec["vt"]) if spec else None,
           "table_size": hex(spec["size"]) if spec else None,
           "vft_matches_table": bool(spec and vfts and spec["vt"] in vfts)}
    for v in vfts:
        ctors = ctor_of(v)
        rep[f"ctors@{v:#x}"] = [hex(c) for c in ctors]
        for c in ctors[:2]:
            rep[f"fields@{c:#x}"] = field_writes(c)
            sizes = [s for s in new_sites(c) ] if ctx else []
            if sizes:
                rep[f"sizes_near@{c:#x}"] = sizes
            callers = call_xrefs(c)[:6]
            rep[f"callers@{c:#x}"] = [hex(x) for x in callers]
            if ctx:
                for x in callers[:2]:
                    body = [f"{a:#x}: {m} {o}" for a, m, o, _t, _b
                            in disasm(max(x - ctx, 0), ctx + 0x30)]
                    rep[f"callctx@{x:#x}"] = body
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name", nargs="?", help="command name (SetNationalFocus) or full RTTI name")
    ap.add_argument("--ctx", type=lambda s: int(s, 0), default=0,
                    help="bytes of caller context to disassemble at each call site")
    ap.add_argument("--vft", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--full", action="store_true",
                    help="per-class report: ctor, size, argument usage")
    ap.add_argument("--body", action="store_true", help="also dump the ctor body")
    a = ap.parse_args()

    if a.name:
        if a.full:
            print(json.dumps(full_hunt(a.name, a.ctx, a.body), indent=2,
                             ensure_ascii=False))
            return 0
        spec = T.COMMANDS.get(a.name)
        rep = hunt(a.name, spec, a.vft, a.ctx)
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0

    for nm, spec in sorted(T.COMMANDS.items()):
        rep = hunt(nm, spec)
        verdict = "OK" if rep.get("vft_matches_table") else "MISMATCH"
        print(f"\n===== {nm}: table vt={spec['vt']:#x} size={spec['size']:#x} "
              f"-> {verdict} =====")
        print(f"  rtti vftables: {rep.get('rtti_vftables')}")
        for k, v in rep.items():
            if k.startswith("ctors@"):
                print(f"  {k}: {v}")
            elif k.startswith("fields@"):
                for line in v:
                    print(f"    {k} {line}")
            elif k.startswith("sizes_near@"):
                print(f"  {k}: {v}")
            elif k.startswith("callers@"):
                print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
