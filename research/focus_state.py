"""focus_state.py — print one country's focus section out of a save, offline.

Used as the ground-truth half of the write-layer E2E: inject a
SetNationalFocus through the APC channel, then read a fresh save and compare
`current` / `completed` / banked progress against what was there before.

Usage:
  python research/focus_state.py                # newest .hoi4, player country
  python research/focus_state.py GER_1936_09_19_06.hoi4
  python research/focus_state.py latest GER --json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot import config                                          # noqa: E402

SAVE_DIR = config.DOCS_ROOT / "save games"


def resolve(name: str) -> Path:
    if name in ("latest", ""):
        cands = sorted(SAVE_DIR.glob("*.hoi4"), key=lambda p: -p.stat().st_mtime)
        if not cands:
            raise SystemExit("no saves found")
        return cands[0]
    p = SAVE_DIR / name
    if not p.is_file():
        raise SystemExit(f"no such save: {p}")
    return p


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    path = resolve(args[0] if args else "latest")
    tag = (args[1] if len(args) > 1 else "").upper()
    print(f"save: {path.name}  (mtime {path.stat().st_mtime:.0f})", file=sys.stderr)

    from hoi4copilot.readstate.country_sem import (
        Countries, country_sections, format_sections)
    cn = Countries(path)
    tag = tag or cn.player() or cn.tags()[0]
    sec = country_sections(cn, tag, ["focus"])
    inner = sec.get(tag, sec)
    if as_json:
        print(json.dumps(inner, indent=2, ensure_ascii=False, default=str))
    else:
        print(format_sections(tag, inner))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
