"""National focus definition database from the game's common/national_focus/.

Mirrors techdata.TechDB for the focus tree (NOTES.md 20日): the save's
`focus.completed` member serializes as REPEATED `completed = <focus-id>`
strings (verified: SOV 5 / ITA 7 / ENG 4 entries in GER_1936_09_19_06), and
the country member `focus_tree` is the selected tree's id string
("german_focus", ...). With the completed set + prereq graph this derives
the research.avail-style "pickable now" list.

Semantics (Paradox script):
  prerequisite = { focus = A focus = B }   -- OR block
  prerequisite = { focus = C }             -- further blocks are ANDed
  mutually_exclusive = { focus = X }       -- completed X locks this forever
  available = { <triggers> }               -- cannot be evaluated offline ->
                                              'gated' flag (verify in UI)
  bypass = { <triggers> }                  -- auto-complete conditions

Duration (both defines-anchored, NOTES.md 20日):
  NFocus.FOCUS_POINT_DAYS = 7            -> duration_days = cost * 7
  NFocus.MAX_SAVED_FOCUS_PROGRESS = 10   -> while no focus is selected,
     progress banks up to 10 DAYS and is applied instantly on the next pick.
  save `progress` raw /1e5 = DAYS accrued (integral across 7 countries),
  = banked days + days into the current focus. GER four_year_plan (cost 5
  -> 35d) read 10.0 at pick time (91 idle days -> 10-day bank) and 10.0
  banked again after completing during an unattended run — both exact.
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
        if p and (p / "common" / "national_focus").is_dir():
            return p
    return None


# Focus blocks nest at varying depth (joint/branch bodies run `focus = {`
# two tabs deep), and joint-branch files put `joint_focus` at column 0, so
# fixed-indent regexes would miss both -> brace-balanced scan.
_FOCUS_OPEN_RE = re.compile(r"\n\t+focus = \{")
_ID_RE = re.compile(r"^\s*id = (\S+)", re.M)
_COST_RE = re.compile(r"^\s*cost = ([\d.]+)", re.M)
_PREREQ_RE = re.compile(r"prerequisite = \{([^{}]*)\}", re.S)
_MUTEX_RE = re.compile(r"mutually_exclusive = \{([^{}]*)\}", re.S)
_FOCUS_IN_BLOCK_RE = re.compile(r"focus = (\S+)")
_TREE_ID_RE = re.compile(r"^\s*id = (\S+)", re.M)


def _block_end(text: str, open_pos: int) -> int:
    """Index of the '}' matching the '{' at open_pos (exclusive end)."""
    depth = 0
    for i in range(open_pos, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text)


def _nonempty_block(body: str, key: str) -> bool:
    """True if `<key> = { ... }` exists AND carries non-whitespace content."""
    m = re.search(rf"^\s*{key} = \{{", body, re.M)
    if not m:
        return False
    return bool(body[m.end():_block_end(body, m.end() - 1)].strip())


def _tree_country_tags(tree_body: str) -> list[str]:
    """Tags the tree claims via its country-selection block: any
    tag/original_tag = XXX inside the `country = {...}` member."""
    m = re.search(r"^\s*country = \{", tree_body, re.M)
    if not m:
        return []
    blk = tree_body[m.end():_block_end(tree_body, m.end() - 1)]
    return sorted(set(re.findall(r"(?:original_)?tag = ([A-Z0-9]{3})", blk)))


def parse_focus_file(path: Path) -> tuple[dict, dict]:
    """One tree file -> (focuses {id: row}, trees {tree_id: {tags, file}}).

    Focus ids are globally unique across trees (the save completes by id),
    so duplicate ids across variant trees keep the first occurrence."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    focuses: dict = {}
    trees: dict = {}

    def scan_focuses(segment: str, tree_id: str) -> None:
        # `\n\t+focus = {`: m.end()-1 is the '{', m.end() the body start
        for m in _FOCUS_OPEN_RE.finditer(segment):
            body = segment[m.end():_block_end(segment, m.end() - 1)]
            idm = _ID_RE.search(body)
            if not idm or idm.group(1) in focuses:
                continue
            prereq_blocks = [
                _FOCUS_IN_BLOCK_RE.findall(blk)
                for blk in _PREREQ_RE.findall(body)
            ]
            mx = _MUTEX_RE.search(body)
            costm = _COST_RE.search(body)
            focuses[idm.group(1)] = {
                "tree": tree_id,
                "file": path.name,
                "cost": float(costm.group(1)) if costm else None,
                "prereq_blocks": prereq_blocks,
                "mutex": _FOCUS_IN_BLOCK_RE.findall(mx.group(1)) if mx else [],
                "gated": _nonempty_block(body, "available"),
                "bypass": _nonempty_block(body, "bypass"),
            }

    # named trees: focus_tree = { id = X ... } (usually one per file; the
    # block sits at column 0 in the shipped files)
    tree_spans = []
    for m in re.finditer(r"(?:^|\n)focus_tree = \{", text):
        end = _block_end(text, m.end() - 1)
        body = text[m.end():end]
        idm = _TREE_ID_RE.search(body)
        tid = idm.group(1) if idm else path.stem
        trees[tid] = {"tags": _tree_country_tags(body), "file": path.name}
        tree_spans.append((m.end(), end))
        scan_focuses(body, tid)
    # joint-branch files keep their focuses outside any focus_tree block;
    # attribute them to a pseudo-tree named after the file
    leftover = []
    last = 0
    for start, end in tree_spans:
        leftover.append(text[last:start])
        last = end
    leftover.append(text[last:])
    rest = "\n".join(leftover)
    if _FOCUS_OPEN_RE.search(rest):
        scan_focuses(rest, path.stem)
    return focuses, trees


class FocusDB:
    """Lazy focus-definition registry over the whole vanilla tree set."""

    def __init__(self):
        self._db: dict | None = None
        self._trees: dict | None = None

    def _load(self) -> None:
        if self._db is not None:
            return
        self._db, self._trees = {}, {}
        root = install_dir()
        if root:
            fdir = root / "common" / "national_focus"
            for f in sorted(fdir.glob("*.txt")):
                try:
                    fo, tr = parse_focus_file(f)
                    self._db.update(fo)
                    self._trees.update(tr)
                except Exception:
                    continue

    def db(self) -> dict:
        self._load()
        return self._db

    def trees(self) -> dict:
        self._load()
        return self._trees

    def get(self, focus: str) -> dict | None:
        row = self.db().get(focus)
        return dict(row) if row else None

    def days(self, focus: str) -> float | None:
        """Duration in game days: cost * FOCUS_POINT_DAYS(=7)."""
        row = self.get(focus)
        if row and row.get("cost") is not None:
            return row["cost"] * 7.0
        return None

    def _tree_allowed(self, tree_id: str, tag: str | None,
                      used_trees: dict | None) -> bool:
        """Is this tree selectable by `tag`?

        used_trees = {tree_id: set(tags)} built by the CALLER from the save
        itself (every country's `focus_tree` member names its active tree,
        so the save is the authoritative tree->tags map — file-side country
        blocks are unreliable: e.g. norway.txt gates its selection behind a
        `NOR_AAT = yes` DLC flag with no tag at all)."""
        if tree_id in ("generic_focus", "generic"):
            return True
        if used_trees is None:
            return True   # no map available: don't filter (caller opts in)
        tags = used_trees.get(tree_id)
        if tags is None:
            return False  # nobody in this game runs this tree
        return not tags or (tag is not None and tag in tags)

    def available(self, completed, current=None, tag: str | None = None,
                  used_trees: dict | None = None, banked: float | None = None,
                  limit: int = 0) -> list[dict]:
        """Focuses pickable right now given the completed set.

        A focus qualifies when every `prerequisite` OR-block contains at
        least one completed focus (zero blocks = tree root), it is not
        completed/running, none of its mutually_exclusive targets are
        completed, and its tree is selectable by this country: the generic
        tree, any tree some save country runs with this tag (used_trees),
        or — for non-root focuses — any tree reached through prereq
        adjacency (shared DLC branches chain off national trees that way).
        Roots of other countries' trees never appear.

        used_trees: {tree_id: set-of-tags} from the save's per-country
        `focus_tree` members; without it no tree filtering happens.

        Rows carry `gated=True` when the definition has a non-empty
        `available = {...}` trigger (evaluate in the UI before relying).
        est_days = duration minus instantly-applied banked days (pass
        `banked` = the save's progress days when NO focus is running)."""
        self._load()
        done = set(completed)
        rows = []
        for fid, row in self._db.items():
            if fid in done or fid == current:
                continue
            if any(mx in done for mx in row["mutex"]):
                continue
            blocks = row["prereq_blocks"]
            root = not blocks
            if not root and any(
                    not any(p in done for p in blk) for blk in blocks):
                continue
            if root and not self._tree_allowed(row["tree"], tag, used_trees):
                continue
            cost = row.get("cost")
            r = {"focus": fid, "cost": cost, "tree": row["tree"]}
            if blocks:
                r["prereqs"] = sorted({p for blk in blocks for p in blk
                                       if p in done})
            if row["gated"]:
                r["gated"] = True
            if row["bypass"]:
                r["bypass"] = True
            if cost:
                duration = cost * 7.0
                base = max(0.0, duration - banked) if banked else duration
                r["est_days"] = round(base, 1)
            rows.append(r)
        rows.sort(key=lambda r: (r.get("gated", False),
                                 r.get("cost") or 99.0,
                                 r.get("focus", "")))
        return rows[:limit] if limit else rows
