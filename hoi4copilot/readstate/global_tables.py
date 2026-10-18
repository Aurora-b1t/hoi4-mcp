"""Global (non-country) bodies of a save: equipment frames, division templates,
per-country custom variant names.

Verified joins (GER_1936_03_31_16, NOTES.md 17日):
  production line/stockpile id {serial, type} -> top-level `equipments` frame
  of the SAME (serial, type) -> frame key = equipment archetype
  (e.g. 1326/70 -> infantry_equipment_1).
  division.division_template_id {serial} -> top-level `division_templates`
  item with name="Infanterie-Division", country="GER".
  Custom (designer) variant display names live in the country's
  production.scheduled_equipment_variants as repeated <archetype> bodies with
  name/upgrades/modules (no id — matched by archetype for display hints).
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from ..saveparse.tokens import load_tokens
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from hoi4copilot.saveparse.tokens import load_tokens

from .bin5_scaffold import find_matching
from .country_sem import Countries, dict_of, markers_of

NAMES = load_tokens()


def find_top_body(cn: Countries, name: str):
    """Locate a top-level `<name> = {` body -> (open_idx, close_idx) or None."""
    data, pos, kind, depth = cn.data, cn.pos, cn.kind, cn.depth
    i, n = 0, len(kind)
    while i < n:
        if int(depth[i]) != 0:
            i += 1
            continue
        t = int(kind[i])
        if t in (0x0001, 0x0003, 0x0004):
            i += 1
            continue
        if t in (0x000F, 0x0017):
            p = int(pos[i])
            ln = data[p + 2] | (data[p + 3] << 8)
            key = data[p + 4:p + 4 + ln].decode("utf-8", "replace")
        else:
            key = NAMES.get(t)
        if key == name and int(kind[i + 1]) == 0x0001 \
                and int(kind[i + 2]) == 0x0003:
            return i + 2, find_matching(kind, i + 2)
        i += 1
    return None


class GlobalTables:
    """One-pass global lookups over a save (built lazily from a Countries)."""

    def __init__(self, cn: Countries):
        self.cn = cn
        self._frames: dict | None = None      # (serial, type) -> archetype
        self._templates: dict | None = None   # serial -> {name, country, key}
        self._sched: dict | None = None       # tag -> {archetype: [names]}
        self._chars: dict | None = None       # id -> {name, country, roles}

    # ------------------------------------------------------------- frames
    def frames(self) -> dict:
        if self._frames is None:
            self._frames = {}
            body = find_top_body(self.cn, "equipments")
            if body:
                for k, vk, vi, cl in self._members(body):
                    iv = self._item_id((vi, cl))
                    if iv is not None:
                        self._frames[iv] = k
        return self._frames

    def archetype(self, marker) -> str | None:
        """id body marker {T_000B=serial, type=N} -> archetype name."""
        inner = dict_of(self.cn.entries(marker))
        serial, ty = inner.get("T_000B"), inner.get("type")
        return self.frames().get((serial, ty))

    def archetype_of(self, v) -> str | None:
        """member value (body marker or list of them) -> first archetype."""
        for m in markers_of(v):
            a = self.archetype(m)
            if a:
                return a
        return None

    # ---------------------------------------------------------- templates
    def templates(self) -> dict:
        if self._templates is None:
            self._templates = {}
            body = find_top_body(self.cn, "division_templates")
            if body:
                for k, vk, vi, cl in self._members(body):
                    sub = dict_of(self.cn.entries(("body", vi, cl)))
                    iv = self._item_id((vi, cl))
                    if iv is None:
                        continue
                    serial = iv[0] if isinstance(iv, tuple) else iv
                    self._templates[serial] = {
                        "name": sub.get("name"),
                        "country": sub.get("country"),
                    }
        return self._templates

    def template_name(self, serial) -> str | None:
        t = self.templates().get(serial)
        return t.get("name") if t else None

    # ------------------------------------------------- custom variant names
    def scheduled_variants(self, tag: str) -> dict:
        """tag -> {archetype: [custom variant names]} from that country's
        production.scheduled_equipment_variants."""
        if self._sched is None:
            self._sched = {}
        if tag in self._sched:
            return self._sched[tag]
        out: dict[str, list] = {}
        mem = self.cn.members(tag)
        prod = mem.get("production")
        if self.cn.is_body(prod):
            es = dict_of(self.cn.entries(prod))
            for m in markers_of(es.get("scheduled_equipment_variants")):
                for arch, v in self.cn.entries(m):
                    for mm in markers_of(v):
                        name = dict_of(self.cn.entries(mm)).get("name")
                        if isinstance(name, str):
                            out.setdefault(arch, []).append(name)
        self._sched[tag] = out
        return out

    # ---------------------------------------------------------- characters
    def characters(self) -> dict:
        """character id -> {name, country, roles} from the top-level
        character_manager (historical + dynamic). Names verified vs
        GER roster (NOTES.md 17日)."""
        if self._chars is None:
            self._chars = {}
            body = find_top_body(self.cn, "character_manager")
            if body:
                from .country_sem import member_list
                o, c = body
                for k, vk, vi, cl in member_list(
                        self.cn.data, self.cn.pos, self.cn.kind,
                        self.cn.depth, self.cn.span, o, c):
                    if k not in ("historical", "dynamic") or \
                            not (isinstance(vk, str)):
                        continue
                    for kk, vk2, vi2, cl2 in self._members((vi, cl)):
                        if kk != "character":
                            continue
                        sub = dict_of(self.cn.entries(("body", vi2, cl2)))
                        iv = sub.get("T_000B")
                        if not self.cn.is_body(iv):
                            continue
                        cid = dict_of(self.cn.entries(iv)).get("T_000B")
                        roles = [rk for rk in ("country_leaders",
                                               "field_marshal",
                                               "corps_commander",
                                               "advisors", "scientists")
                                 if rk in sub]
                        self._chars[cid] = {
                            "name": sub.get("name"),
                            "country": sub.get("country"),
                            "roles": roles,
                        }
        return self._chars

    # ------------------------------------------------------------ helpers
    def _members(self, body_pair):
        o, c = body_pair
        from .country_sem import member_list
        return member_list(self.cn.data, self.cn.pos, self.cn.kind,
                           self.cn.depth, self.cn.span, o, c)

    def _item_id(self, span):
        vi, cl = span
        sub = dict_of(self.cn.entries(("body", vi, cl)))
        iv = sub.get("T_000B")
        if self.cn.is_body(iv):
            inner = dict_of(self.cn.entries(iv))
            return inner.get("T_000B"), inner.get("type")
        return None
