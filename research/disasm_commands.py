"""Disassembly research: locate the player command queue / Post mechanism.

Plan: find a Command subclass's vftable-adjacent data. Commands likely carry
their own construction metadata; the queue posts via a known exported
sequence. We decompile around CSetNationalFocusCommand vtable[0] (dtor) and
vtable[1..] to find calls into a queue object.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import struct

import capstone
import pefile

from hoi4copilot import config
from hoi4copilot.process import instances as inst
from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import Game

_exe_bytes = None


def exe():
    global _exe_bytes
    if _exe_bytes is None:
        install = config.find_install_dir()
        _exe_bytes = (install / config.EXE_NAME).read_bytes()
    return _exe_bytes


def pe():
    pe_ = pefile.PE(None)  # cannot parse from mem; use file
    return pe_


def find_class_vftable_file(class_name: str):
    """Static: vftable RVA from rtti.json plus function RVAs from it."""
    db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
    for c in db["classes"]:
        if c["name"] == class_name:
            return c["vftable_rvas"]
    return []


def read_func_bytes_file(rva: int, n: int = 256):
    data = exe()
    import pefile
    pe_ = pefile.PE(str(config.find_install_dir() / config.EXE_NAME), fast_load=True)
    off = pe_.get_offset_from_rva(rva)
    return data[off:off + n], rva


def disasm_around_vtable(class_name: str, n_funcs: int = 6):
    vfs = find_class_vftable_file(class_name)
    if not vfs:
        print("no vftable for", class_name)
        return
    vft = vfs[0]
    data, _ = read_func_bytes_file(vft, 8 * (n_funcs + 1))
    fns = struct.unpack_from("<%dQ" % (n_funcs + 0), data, 0)
    print(class_name, "vftable rva", hex(vft))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for i, fn in enumerate(fns[1:1 + n_funcs]):
        # fn is VA; convert to RVA using image base guess
        import pefile
        pe_ = pefile.PE(str(config.find_install_dir() / config.EXE_NAME), fast_load=True)
        base = pe_.OPTIONAL_HEADER.ImageBase
        rva = fn - base
        code, _ = read_func_bytes_file(rva, 128)
        print(f"--- vfn[{i}] rva={rva:#x}")
        for ins in md.disasm(code, rva):
            print(f"    {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
            if ins.mnemonic in ("ret", "jmp") and ins.op_str.startswith("0x"):
                break
        _ = base


if __name__ == "__main__":
    disasm_around_vtable(".?AVCSetNationalFocusCommand@@")
