"""tool_ascii.py — strip non-ASCII characters from the VM payload's comments.

keystone's python binding encodes the source as ASCII, so a stray CJK character
in a `//` comment makes the payload refuse to assemble. Run after editing
hoi4_mcp/inject/script.py's _ASM block.
"""
from __future__ import annotations

import re
from pathlib import Path

P = Path(__file__).resolve().parents[1] / "hoi4_mcp" / "inject" / "script.py"


def main() -> int:
    s = P.read_text(encoding="utf-8")
    start = s.index('_ASM = r"""')
    end = s.index('"""', start + len('_ASM = r"""'))
    block = s[start:end]
    new = re.sub(r"//[^\n]*", lambda m: re.sub(r"[^\x00-\x7f]", "", m.group(0)), block)
    P.write_text(s[:start] + new + s[end:], encoding="utf-8")
    bad = [ln for ln in new.splitlines() if any(ord(c) > 127 for c in ln)]
    print(f"non-ASCII lines left in _ASM: {len(bad)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
