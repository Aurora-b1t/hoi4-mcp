"""tool_labels.py — report duplicate labels in the VM payload source."""
from __future__ import annotations

import collections
import re
from pathlib import Path

P = Path(__file__).resolve().parents[1] / "hoi4copilot" / "inject" / "script.py"


def main() -> int:
    s = P.read_text(encoding="utf-8")
    start = s.index('_ASM = r"""')
    end = s.index('"""', start + 10)
    block = s[start:end]
    labels = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*):", block)
    dup = [k for k, v in collections.Counter(labels).items() if v > 1]
    print("labels:", len(labels))
    print("duplicates:", dup)
    for name in dup:
        lines = [i + 1 for i, ln in enumerate(block.splitlines())
                 if ln.strip() == f"{name}:"]
        print(f"  {name}: {lines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
