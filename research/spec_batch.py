"""spec_batch.py — derive Windows specs for a list of command classes at once.

For each class: RTTI vftable -> ctor entry -> field writes -> object size at the
UI's `mov ecx,size; call operator new` site -> argument usage; plus the reference
(Linux) table's row for the same class as a structural cross-check.

Prints one compact line per class (and a JSON blob with --json).

Usage:
  python research/spec_batch.py                       # the default target list
  python research/spec_batch.py CSetResearchCommand CAddConstructionCommand
  python research/spec_batch.py --json > research/out_spec_batch.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from research.command_spec_hunt import full_hunt                        # noqa: E402

DEFAULT = [
    "CSetResearchCommand",
    "CDropCurrentNationalFocusCommand",
    "CBypassNationalFocusCommand",
    "CSelectDecisionCommand",
    "CSelectEventOptionCommand",
    "CAddConstructionCommand",
    "CRemoveAllConstructionCommand",
    "CAddProductionLineFactoriesCommand",
    "CSetProductionLineAmountCommand",
    "CAddIdeaCommand",
]


def compact(name: str, rep: dict) -> str:
    if "error" in rep:
        return f"{name:42s} NOT FOUND ({rep.get('near')})"
    ctors = rep.get("ctors") or []
    if not ctors:
        return f"{name:42s} vft={rep.get('vftable')} no ctor found"
    c = ctors[0]
    info = rep[f"ctor@{c}"]
    sizes = info["sizes_at_call_sites"]
    args = info["args"]
    argbits = []
    for reg in ("rdx", "r8", "r9"):
        for line in args.get(reg, []):
            kind = "deref" if "deref" in line else ("opt" if "test" in line else "?")
            argbits.append(f"{reg}:{kind}")
    writes = [w for w in info["writes"] if not w.startswith("+0x0 ")]
    return (f"{name:42s} vft={rep['vftable']:>10s} ctor={c} "
            f"size={','.join(sizes) or '?':>10s} "
            f"args=[{', '.join(argbits)}] writes={len(writes)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    names = a.names or DEFAULT
    out = {}
    for n in names:
        rep = full_hunt(n)
        out[n] = rep
        print(compact(n, rep))
        ref = rep.get("ref_table")
        if ref:
            m = re.search(r"(\d+)\s+(\S+)\s*$", ref)
            print(f"{'':42s} ref(Linux): args={m.group(1) if m else '?'} "
                  f"fields={m.group(2) if m else '?'}")
    if a.json:
        print(json.dumps(out, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
