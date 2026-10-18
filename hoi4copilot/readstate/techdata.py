"""Technology definition database from the game's common/technologies/*.txt.

Gives per-tech research_cost (game design units) + start_year + categories +
the leads_to prerequisite graph. Paired with the save's research_points/
points_factor this yields:
  invested_research_days = points / points_factor      (exact; save-side)
  total days needs the live UI (days-remaining) to calibrate the base
  days-per-cost constant — offline estimates use base_days_per_cost=110
  (empirical: EME cost1.0 93.5d@1.16, MG08 113日 UI 对表, NOTES.md 17日).
available(done, busy, year, factor_free) derives the researchable-now list:
save techs are keyed by their exact tier name (GER 1936: infantry_weapons and
infantry_weapons1 as separate entries), so done = the key set directly.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

if sys.platform == "win32":
    _CANDIDATES = (
        os.environ.get("HOI4_INSTALL", ""),
        r"D:\Steam\steamapps\common\Hearts of Iron IV",
        r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV",
        r"D:\SteamLibrary\steamapps\common\Hearts of Iron IV",
    )
else:
    _CANDIDATES = (os.environ.get("HOI4_INSTALL", ""),)


def install_dir() -> Path | None:
    for c in _CANDIDATES:
        p = Path(c) if c else None
        if p and (p / "common" / "technologies").is_dir():
            return p
    return None


_TECH_RE = re.compile(r"^\t([\w]+) = \{(.*?)^\t\}", re.S | re.M)
_COST_RE = re.compile(r"^\s*research_cost = ([\d.]+)", re.M)
_YEAR_RE = re.compile(r"^\s*start_year = (\d{4})", re.M)
_CAT_RE = re.compile(r"^\s*categories = \{([^}]*)\}", re.S)
_LEADS_RE = re.compile(r"leads_to_tech = ([\w]+)")
_SPTECH_RE = re.compile(r"^\s*is_special_project_tech = yes", re.M)
_SPPROJ_RE = re.compile(r"is_special_project_completed = [\w:]+")
_ALLOW_RE = re.compile(r"^\t\tallow = \{(.*?)^\t\t\}", re.S | re.M)
_ALWAYS_NO_RE = re.compile(r"always = no")
_TAG_RE = re.compile(r"\b(?:original_)?tag\s*=\s*([A-Z0-9]{3})")


def parse_tech_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    out = {}
    for m in _TECH_RE.finditer(text):
        name, body = m.group(1), m.group(2)
        cost = _COST_RE.search(body)
        year = _YEAR_RE.search(body)
        cats = _CAT_RE.search(body)
        allow = _ALLOW_RE.search(body)
        allow_body = allow.group(1) if allow else ""
        out[name] = {
            "cost": float(cost.group(1)) if cost else None,
            "start_year": int(year.group(1)) if year else None,
            "categories": cats.group(1).split() if cats else [],
            "leads_to": _LEADS_RE.findall(body),
            # special-project techs (Götterdämmerung) have NO leads_to parent:
            # they unlock via the special projects system, so a plain
            # prereq-graph model must never call them "available"
            "sp_gated": bool(_SPTECH_RE.search(body)) or
                        bool(_SPPROJ_RE.search(body)),
            # allow-gate: hidden techs (always = no, e.g. national-spirit
            # placeholders) and country-tag-restricted techs
            "hidden": bool(_ALWAYS_NO_RE.search(allow_body)),
            "allow_tags": sorted(set(_TAG_RE.findall(allow_body))),
        }
    return out


class TechDB:
    """Lazy-loaded tech definitions; None fields when the game dir is absent."""

    def __init__(self):
        self._db: dict | None = None
        self._parents: dict[str, list[str]] | None = None

    def db(self) -> dict:
        if self._db is None:
            self._db = {}
            root = install_dir()
            if root:
                tdir = root / "common" / "technologies"
                for f in sorted(tdir.glob("*.txt")):
                    try:
                        self._db.update(parse_tech_file(f))
                    except Exception:
                        continue
        return self._db

    def parents(self) -> dict[str, list[str]]:
        """tech -> [prereq techs] (reverse of the leads_to graph). A tech is
        researchable only when every parent is done; parents([]) = tree roots."""
        if self._parents is None:
            rev: dict[str, list[str]] = {}
            for tech, row in self.db().items():
                for child in row.get("leads_to", ()):
                    rev.setdefault(child, []).append(tech)
            self._parents = rev
        return self._parents

    def available(self, done, busy=(), year=None, factor_free=None,
                  tag=None, limit: int = 0) -> list[dict]:
        """Techs researchable right now: every leads_to parent done, not
        already done or in progress, NOT special-project gated (those unlock
        via the special projects system, not the research tree), NOT hidden
        (allow = { always = no }) and NOT tag-restricted away from `tag`.
        Sorted by ahead-of-time (0 first), then newest start_year, then
        cheap cost. est_days uses the cost*110/factor model calibrated
        against the live UI (NOTES.md 17日); pass factor_free = an empty
        slot's points_factor (pure country bonus, no ahead-of-time penalty
        baked in) for the best estimate."""
        year = int(year) if year else None
        rows = []
        for name, row in self.db().items():
            if name in done or name in busy:
                continue
            if row.get("sp_gated") or row.get("hidden"):
                continue
            at = row.get("allow_tags")
            if at and (not tag or tag not in at):
                continue
            if any(p not in done for p in self.parents().get(name, ())):
                continue
            sy = row.get("start_year")
            ahead = max(0, sy - year) if (year and sy) else 0
            r = {"tech": name, "cost": row.get("cost"), "start_year": sy}
            if ahead:
                r["ahead_y"] = ahead
            cost = row.get("cost")
            if factor_free and cost and not ahead:
                r["est_days"] = round(cost * 110 / factor_free, 1)
            rows.append(r)
        rows.sort(key=lambda r: (r.get("ahead_y", 0),
                                 -(r.get("start_year") or 0),
                                 r.get("cost") or 99.0))
        return rows[:limit] if limit else rows

    def get(self, tech: str) -> dict | None:
        row = self.db().get(tech)
        if row is None:
            return None
        return dict(row)

    def enrich_progress(self, tech: str, points, points_factor=None) -> dict:
        """Attach cost/start_year + invested days to an in-progress entry."""
        row = self.get(tech) or {}
        out = {"tech": tech, "points": points}
        if row.get("cost") is not None:
            out["cost_units"] = row["cost"]
        if row.get("start_year") is not None:
            out["start_year"] = row["start_year"]
        if isinstance(points, (int, float)) and \
                isinstance(points_factor, (int, float)) and points_factor:
            out["invested_days"] = round(points / points_factor, 2)
        return out
