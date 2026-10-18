"""One-off: read a vftable's MSVC RTTI identity straight out of hoi4.exe.

Layout (x64): vftable[-1] -> CompleteObjectLocator
  COL: +0x00 signature(1) +0x04 offset +0x08 cdOffset
       +0x0C pTypeDescriptor (image-relative RVA on x64)
  TypeDescriptor: +0x00 vftable +0x08 spare +0x10 char name[] (".?AV...@@")

Control cases included so a failure of the tooling itself is visible.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.win_disasm import pe                                         # noqa: E402

CASES = {
    "CTechnology (rtti.json)": 0x2974EE0,
    "CTechnology 2nd": 0x2974F30,
    "CNationalFocus": 0x02739C08,
    "CSetResearchCommand": 0x2994F40,
    "CCurrentGameState": 0x02721158,
    "CSession": 0x02B3E9D8,
    "CTechnologyDatabase": 0x2944150,
}


def rtti_name(P, vft_rva: int) -> str:
    col_ptr = int.from_bytes(P.read_rva(vft_rva - 8, 8), "little")
    col_rva = col_ptr - P.base
    if not (0 < col_rva < 0x3300000):
        return f"<bad COL ptr {col_ptr:#x}>"
    col = P.read_rva(col_rva, 0x14)
    sig = int.from_bytes(col[0:4], "little")
    off = int.from_bytes(col[4:8], "little")
    cd = int.from_bytes(col[8:12], "little")
    td_rva = int.from_bytes(col[12:16], "little")
    if not (0 < td_rva < 0x3300000):
        return f"<sig={sig:#x} off={off} cd={cd} bad TD {td_rva:#x}>"
    td = P.read_rva(td_rva, 0x40)
    raw = td[0x10:]
    name = raw.split(b"\0", 1)[0].decode(errors="replace")
    return f"{name}  (sig={sig:#x} off={off} cd={cd} td={td_rva:#x})"


def main() -> int:
    P = pe()
    for label, rva in CASES.items():
        print(f"{label:26s} vft={rva:#09x} -> {rtti_name(P, rva)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
