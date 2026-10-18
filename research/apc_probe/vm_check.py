"""vm_check.py — assemble the v3.1 VM payload, disassemble it, and report the
structural properties the payload's safety depends on.

Usage: python research/apc_probe/vm_check.py [--dump]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main() -> int:
    dump = "--dump" in sys.argv
    # import the source pieces without triggering the module-level asserts
    import keystone
    import capstone

    src = (Path(__file__).resolve().parents[2] / "hoi4copilot" / "inject" /
           "script.py").read_text(encoding="utf-8")
    start = src.index('_ASM = r"""') + len('_ASM = r"""')
    end = src.index('"""', start)
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    code, _ = ks.asm(src[start:end])
    code = bytes(code)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines = [f"+{i.address:04x}: {i.mnemonic} {i.op_str}".rstrip()
             for i in md.disasm(code, 0)]
    print(f"{len(code)} bytes, {len(lines)} instructions")
    if dump:
        print("\n".join(lines))
    else:
        for l in lines:
            if any(k in l for k in ("gs:", " call ", "xchg", "ret", "rep ")):
                print("  ", l)
    print("checks:")
    print("  xchg claim      :", any("xchg" in l for l in lines))
    print("  four call sites :", sum(1 for l in lines if " call " in l) == 4)
    print("  rep movsb/stosb :", any("rep movsb" in l for l in lines),
          any("rep stosb" in l for l in lines))
    print("  TID probe (gs:) :", any("gs:" in l for l in lines))
    print("  ends in ret     :", lines[-1].endswith("ret"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
