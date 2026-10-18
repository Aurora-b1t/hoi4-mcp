"""One-off: look up RTTI classes by regex in tables/generated/rtti.json.

Usage: python research/_rtti_lookup.py 'CTechnology$' 'CEvent$' ...
Prints `name  [vftable_rvas]` for classes that have at least one vftable.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RTTI = Path(__file__).resolve().parents[1] / "hoi4_mcp" / "tables" / "generated" / "rtti.json"


def main() -> int:
    pats = [re.compile(p) for p in sys.argv[1:]] or [re.compile("Tech")]
    d = json.loads(RTTI.read_text(encoding="utf-8"))
    n = 0
    for c in d["classes"]:
        if not (c.get("vftable_rvas")):
            continue
        if any(p.search(c["name"]) for p in pats):
            print(f"{c['name']:60s} {[hex(int(x)) for x in c['vftable_rvas']]}")
            n += 1
    print(f"-- {n} classes with vftables matched", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
