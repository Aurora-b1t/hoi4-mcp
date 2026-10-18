"""Chase the command dispatch target: dump 0x24c2e20 and who it calls."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import struct

import capstone
import pefile

from hoi4copilot import config

pe_ = pefile.PE(str(config.find_install_dir() / config.EXE_NAME), fast_load=True)
data = bytes(pe_.__data__)
IMG_BASE = pe_.OPTIONAL_HEADER.ImageBase


def read_rva(rva, n):
    off = pe_.get_offset_from_rva(rva)
    return data[off:off+n]


def disasm(rva, n=200, stop_ret=True):
    code = read_rva(rva, n)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    out = []
    for ins in md.disasm(code, rva):
        tgt = ""
        if ins.mnemonic in ("call", "jmp") and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            tgt = f"  -> rva {t:#x}"
        out.append(f"{ins.address:#x}: {ins.mnemonic} {ins.op_str}{tgt}")
        if stop_ret and ins.mnemonic == "ret":
            break
    return out


if __name__ == "__main__":
    for rva in (0x24c2e20,):
        print(f"==== {rva:#x} ====")
        for line in disasm(rva, 400, stop_ret=False):
            print(line)
