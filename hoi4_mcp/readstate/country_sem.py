"""Country-level semantic readers over a bin5 save (readstate v2).

Every field below is byte-verified against GER/ITA/CHI saves of 1.19.3.0 and
the running game's UI (research/NOTES.md 16日).

Sections map to game panels:
  pol        PP / stability / war_support / command_power / elections /
             parties (popularity % = raw/1e5) / ideas (laws & spirits)
  research   done techs {level, date} + in-progress {points} + slot count
             + avail (researchable-now from the leads_to prereq graph)
  prod       military/naval lines + equipment stockpile + cic_bank
  construction  build queue = production.general_lines (present only when
             non-empty; cost == common/buildings base_cost)
  res        resources produced/imported/exported/to_export
  units      divisions (id, template, location, organisation, strength,
             experience, dig_in, manpower) + fleet/ship counts
  diplo      active_relations (attitude + opinion per country)
  decisions  active timed/targeted decisions (decision/target/days)
  focus      tree + current/progress(days)/paused + COMPLETED list +
             available (research.avail-style pickable-now derivation:
             prereq graph from common/national_focus, duration cost*7,
             banked days applied; readstate/focusdata.py)
  fuel       fuel / max_fuel (fixed point /1e6) + gain fields
  mp         manpower ratio (conscription %) + division manpower sum
  chars      leader/advisors/unit_leaders/scientists (joined to names)
  theatres   command chain: theatre -> division handles + fronts

Calibration: 0x000C/0x0014/0x029C/0x0317 exact ints; 0x000D int64 /1e5
(PP/stab/progress/percentage); 0x0167 int64 /1e6 (fuel, efficiencies).

Save techs are keyed by their exact tier name (infantry_weapons AND
infantry_weapons1 are separate entries; level>1 seen only as mod repeat
grants), so `done` = the entry-key set directly. Army display names ("1.
Armee") are not serialized — CONFIRMED again on GER_1936_09_19_06 (20日):
no army-grouping bodies exist anywhere in the save; theatres carry
division handles directly. The closest thing to army identity is the
per-division `division_name.name_order` ordinal, which units now expose
as a reconstructed name ("<order>. <template>").
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from ..saveparse.tokens import load_tokens
    from ..saveparse import saveinfo
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from hoi4_mcp.saveparse.tokens import load_tokens
    from hoi4_mcp.saveparse import saveinfo

from .world_state import (
    scalar_value, walkthrough, find_countries, find_matching,
    statement_member_scan)
from .bin5_scaffold import country_anchors

NAMES = load_tokens()
BY_NAME = {v: k for k, v in NAMES.items()}

EPOCH_TOKEN = 60759359   # == 1936-01-01 00:00 (saveinfo)


def decode_hdate(tok):
    """Save date token -> game-hours since 1936-01-01 00:00 (or raw)."""
    if isinstance(tok, int) and tok > 40000000:
        return tok - EPOCH_TOKEN
    return tok if isinstance(tok, int) else None


# ------------------------------------------------------------------ engine
# member_list record: (key, vkind, payload, close_i)
#   vkind='prim'  payload = value-token idx
#   vkind='body'  payload = open-tok idx, close_i = close-tok idx
#   vkind='run'   payload = [(tok, pos)|('txt', s)]: consecutive bare tokens

def member_list(data, pos, kind, depth, span, open_i, close_i=None):
    if close_i is None:
        close_i = find_matching(kind, open_i)
    dt = int(depth[open_i]) + 1
    out, run = [], []
    i = open_i + 1
    while i < close_i:
        d = int(depth[i])
        if d != dt:
            i += 1
            continue
        t = int(kind[i])
        if t == 0x0004:
            break
        if t in (0x000F, 0x0017):
            p = int(pos[i])
            ln = data[p + 2] | (data[p + 3] << 8)
            key = data[p + 4:p + 4 + ln].decode("utf-8", "replace")
        else:
            key = NAMES.get(t, f"T_{t:04X}")
        eq = int(kind[i + 1]) if i + 1 < len(kind) else 0
        if eq != 0x0001:
            if t in (0x000C, 0x000D, 0x0014, 0x0167, 0x029C, 0x0317, 0x000E):
                run.append((t, int(pos[i])))
            else:  # bare id/string token: idea lists etc.
                run.append(('txt', key))
            i += 1
            continue
        if run:
            out.append(("<run>", "run", run, None))
            run = []
        vt = int(kind[i + 2])
        if vt == 0x0003:
            cl = find_matching(kind, i + 2)
            out.append((key, "body", i + 2, cl))
            i = cl + 1
            continue
        out.append((key, "prim", i + 2, None))
        i += 3
    if run:
        out.append(("<run>", "run", run, None))
    return out


def run_to_values(run_items, data):
    vals = []
    for it in run_items:
        if isinstance(it, tuple) and it and it[0] in ('txt', 'str'):
            vals.append(it[1])
        else:
            vals.append(scalar_value(int(it[0]), data, int(it[1])))
    return vals


class Countries:
    """One-pass scaffold; per-country top members cached. All record shapes:
    statement_member_scan dict:  key -> ('prim', val, idx) | ('body', oi, cl)
    entries list:                [(key, value) ...] repeated keys preserved."""

    def __init__(self, path, data=None):
        self.path = Path(path)
        self.data = data if data is not None else self.path.read_bytes()
        d = self.data
        self.pos, self.kind, self.depth, self.span = walkthrough(
            d, d.find(b"HOI4bin5*") + 9)
        _, _, _, io_i, ic_i = find_countries(
            d, 9, self.pos, self.kind, self.depth, self.span)
        self.anchors = country_anchors(d, self.pos, self.kind, self.depth,
                                       self.span, io_i, ic_i)
        self.by_tag = {a[0]: (a[2], a[3]) for a in self.anchors}
        self._members: dict[str, dict] = {}
        self._gt = None
        try:
            self.header = saveinfo.read_header(self.path, limit=16384)
        except Exception as exc:
            self.header = {"error": str(exc)}

    def tables(self):
        """GlobalTables over this save (lazy; joins ids -> archetype/name)."""
        if self._gt is None:
            from .global_tables import GlobalTables
            self._gt = GlobalTables(self)
        return self._gt

    def tree_usage(self) -> dict:
        """{tree_id: set(tags)} from every country's `focus_tree` member —
        the authoritative tree->tags map (file-side country blocks are
        unreliable: some gate selection behind DLC flags with no tag).
        numpy scan: T_focus_tree(0x33b8) + EQUAL + string, mapped to the
        enclosing country anchor by token index."""
        if getattr(self, "_tree_usage", None) is not None:
            return self._tree_usage
        import numpy as np
        import bisect
        t_ft = BY_NAME.get('focus_tree', 0x33B8)
        idxs = np.where(self.kind == t_ft)[0]
        anchor_starts = sorted((int(self.pos[a[2]]), a[0])
                               for a in self.anchors if a[2] is not None)
        starts = [s for s, _ in anchor_starts]
        usage: dict = {}
        for i in idxs:
            if i + 2 >= len(self.kind) or \
                    int(self.kind[i + 1]) != 0x0001:
                continue
            vt = int(self.kind[i + 2])
            if vt not in (0x000F, 0x0017):
                continue
            p = int(self.pos[i + 2])
            ln = self.data[p + 2] | (self.data[p + 3] << 8)
            tree = self.data[p + 4:p + 4 + ln].decode("utf-8", "replace")
            k = bisect.bisect_right(starts, int(self.pos[i])) - 1
            tag = anchor_starts[k][1] if k >= 0 else None
            if tag:
                usage.setdefault(tree, set()).add(tag)
        self._tree_usage = usage
        return usage

    def tags(self):
        return sorted(self.by_tag)

    def player(self):
        h = self.header
        try:
            f = getattr(h, "player", None)
            return f() if callable(f) else f
        except Exception:
            return None

    def date_s(self):
        try:
            return self.header.summary()
        except Exception:
            return ""

    def members(self, tag: str) -> dict:
        if tag not in self._members:
            pair = self.by_tag.get(tag)
            if pair is None:
                self._members[tag] = {}
            else:
                oi, ck = pair
                d0 = int(self.depth[oi])
                self._members[tag] = statement_member_scan(
                    self.data, self.pos, self.kind, self.depth, self.span,
                    oi + 1, ck, d0)
        return self._members[tag]

    def entries(self, marker) -> list:
        """('body',oi,cl) marker -> ordered [(key, value)] resolved members."""
        if not self.is_body(marker):
            return []
        out = []
        for rec in member_list(self.data, self.pos, self.kind, self.depth,
                               self.span, marker[1], marker[2]):
            key, vk, vi, cl = rec
            if vk == 'body':
                out.append((key, ('body', vi, cl)))
            elif vk == 'run':
                out.append((key, run_to_values(vi, self.data)))
            else:  # 'prim': vi = value-token index; scalar_value wants bytes
                out.append((key, scalar_value(int(self.kind[vi]),
                                              self.data, int(self.pos[vi]))))
        return out

    @staticmethod
    def is_body(v) -> bool:
        return isinstance(v, tuple) and v and v[0] == 'body'

    def one(self, marker, name):
        if not self.is_body(marker):
            return None
        for k, v in self.entries(marker):
            if k == name:
                return v
        return None

    def id_of(self, marker, key='T_000B'):
        """Numeric id from a signature member. Two shapes:
        <name> = <prim> and <name> = { T_000B: id, type: X }."""
        v = self.one(marker, key) if self.is_body(marker) else marker
        if self.is_body(v):
            s = self.one(v, 'T_000B')
            return s if isinstance(s, (int, float, str)) else None
        return v if isinstance(v, (int, float, str)) else None


# ------------------------------------------------------------- small utils

def markers_of(v) -> list:
    """Member value = one body marker or REPEATED (list of them) -> list."""
    if isinstance(v, tuple) and v and v[0] == 'body':
        return [v]
    if isinstance(v, list):
        return [m for m in v if isinstance(m, tuple) and m and m[0] == 'body']
    return []


def dict_of(es: list) -> dict:
    """entries list -> dict; repeated keys -> list; '<run>' -> '<list>'."""
    d: dict = {}
    for k, v in es:
        if k == "<run>":
            d.setdefault("<list>", []).extend(
                v if isinstance(v, list) else [v])
            continue
        if k in d:
            if not isinstance(d[k], list):
                d[k] = [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def prim(v):
    """Pull a scalar out of the member-dict shape ('prim', val, idx), or pass
    plain scalars through; bodies/other -> None."""
    if isinstance(v, tuple) and len(v) == 3 and v[0] == 'prim':
        return v[1]
    if isinstance(v, (int, float, str, bool)):
        return v
    return None


def scalars_of(es: list) -> dict:
    """entries -> dict for plain scalar members only (skips bodies)."""
    out = {}
    for k, v in es:
        if isinstance(v, tuple):  # body marker
            continue
        if isinstance(v, list):
            out[k] = v
            continue
        out[k] = v
    return out


def one_or_val(x):
    if isinstance(x, dict) and 'T_000B' in x:
        return x.get('T_000B').get('T_000B') if isinstance(
            x.get('T_000B'), dict) else x.get('T_000B')
    return x


# ---------------------------------------------------------- section readers

def sec_politics(cn: Countries, mem: dict) -> dict:
    out = {k: prim(mem.get(k)) for k in
           ('stability', 'war_support', 'command_power')}
    pol = mem.get('politics')
    out["political_power"] = None
    out["parties"] = []
    out["ideas"] = []
    if not cn.is_body(pol):
        return out
    pmap = dict_of(cn.entries(pol))
    out["political_power"] = pmap.get('political_power') \
        if isinstance(pmap.get('political_power'), (int, float, str)) \
        else None
    out["ruling_party"] = prim(pmap.get('ruling_party'))
    out["elections_allowed"] = prim(pmap.get('elections_allowed'))
    out["last_election_h"] = decode_hdate(prim(pmap.get('last_election')))
    for marker in markers_of(pmap.get('parties')):
        for k, v in cn.entries(marker):
            if isinstance(v, tuple) and v and v[0] == 'body':
                out["parties"].append({"id": k,
                                       "popularity%": _first_val(cn, v,
                                                                 'popularity')})
    ib = pmap.get('ideas')
    ideas: list = []
    for marker in markers_of(ib):
        for k, v in cn.entries(marker):
            if isinstance(v, list):
                ideas.extend(x for x in v if isinstance(x, str))
            elif isinstance(v, str):
                ideas.append(k)
    out["ideas"] = ideas
    return out


def _first_val(cn, marker, name):
    if not cn.is_body(marker):
        return None
    for k, v in cn.entries(marker):
        if k == name:
            return v
    return None


def sec_research(cn: Countries, mem: dict) -> dict:
    from .techdata import TechDB
    out = {k: prim(mem.get(k)) for k in
           ('research_slot', 'original_research_slots')}
    out.update({"done": [], "in_progress": [], "slots": [], "avail": []})
    tec = mem.get('technology')
    if not cn.is_body(tec):
        return out
    tm = dict_of(cn.entries(tec))
    # per-slot speed factor (country bonus + ahead-of-time penalty baked in);
    # the max is the best proxy for the pure country bonus (an EMPTY slot's
    # factor carries no ahead-of-time penalty)
    factor: dict = {}
    for marker in markers_of(tm.get('slots')):
        for k, v in cn.entries(marker):
            if not (isinstance(v, tuple) and v and v[0] == 'body'):
                continue
            inner = dict_of(cn.entries(v))
            if isinstance(inner.get('points_factor'), (int, float)):
                factor[k] = inner['points_factor']
    factor_free = max(factor.values(), default=None)
    db = TechDB()
    for marker in markers_of(tm.get('technologies')):
        done, prog = [], []
        for k, v in cn.entries(marker):
            if not (isinstance(v, tuple) and v and v[0] == 'body'):
                continue
            inner = dict_of(cn.entries(v))
            lv = inner.get('level')
            rp = inner.get('research_points')
            dt = inner.get('date')
            if lv is not None:
                done.append({"tech": k, "level": lv,
                             "date_h": decode_hdate(
                                 dt if isinstance(dt, (int, float))
                                 else None)})
            elif rp is not None:
                prog.append(db.enrich_progress(k, rp, factor.get(k)))
        out["done"] += done
        out["in_progress"] += prog
    for marker in markers_of(tm.get('slots')):
        for k, v in cn.entries(marker):
            if k == '<run>':
                continue
            if isinstance(v, tuple) and v and v[0] == 'body':
                inner = dict_of(cn.entries(v))
                row = {"slot": k}
                row.update({kk: vv for kk, vv in inner.items()
                            if isinstance(vv, (int, float, str, bool)) and
                            not str(kk).startswith('T_')})
                out["slots"].append(row)
            else:
                out["slots"].append({"slot": k})
    # researchable-now derivation (leads_to prereq graph vs done techs)
    year = None
    try:
        ds = cn.header.date_str()
        year = int(str(ds).split("-")[0])
    except Exception:
        year = None
    try:
        out["avail"] = db.available(
            {d["tech"] for d in out["done"]},
            busy={d["tech"] for d in out["in_progress"]},
            year=year, factor_free=factor_free,
            tag=cn._cur_tag or cn.player())
    except Exception as exc:
        out["avail"] = [{"error": f"{exc.__class__.__name__}: {exc}"}]
    return out


def _line_row(cn: Countries, marker, gt=None) -> dict:
    """One production line: each repeated <military_lines|naval_lines> body
    IS the line; fields sit directly on it."""
    ln = dict_of(cn.entries(marker))
    arch = gt.archetype_of(ln.get('equipment_variant_index')) if gt else None
    return {
        "id": _line_id(cn, ln),
        "variant_id": _line_variant(cn, ln),
        "archetype": arch,
        "produced": ln.get('produced'),
        "factories": ln.get('active_factories', ln.get('queued_factories')),
        "requested": ln.get('requested_factories'),
        "priority": ln.get('priority'),
        "amount": ln.get('amount'),
        "speed": ln.get('speed'),
        "cost": ln.get('cost'),
    }


def _line_id(cn: Countries, ln: dict):
    for k, v in ln.items():
        if not k.startswith('T_'):
            continue
        if isinstance(v, tuple) and v and v[0] == 'body':
            return cn.id_of(v)
        if isinstance(v, list):
            for m in v:
                if isinstance(m, tuple) and m and m[0] == 'body':
                    return cn.id_of(m)
    return None


def _line_variant(cn: Countries, ln: dict):
    v = ln.get('equipment_variant_index')
    if isinstance(v, tuple) and v[0] == 'body':
        return cn.id_of(v)
    if isinstance(v, list):
        for m in v:
            if isinstance(m, tuple) and m[0] == 'body':
                return cn.id_of(m)
    return None


def sec_production(cn: Countries, mem: dict) -> dict:
    gt = cn.tables()
    out = {"num_ships": prim(mem.get('num_ships'))}
    pr = mem.get('production')
    if not cn.is_body(pr):
        return out
    pm = dict_of(cn.entries(pr))
    out["military_lines"] = []
    out["naval_lines"] = []
    for key, label in (("military_lines", "military_lines"),
                       ("naval_lines", "naval_lines")):
        for marker in markers_of(pm.get(key)):
            out[label].append(_line_row(cn, marker, gt))
    stock = []
    for marker in markers_of(pm.get('equipments')):
        for k, v in cn.entries(marker):
            if not (isinstance(v, tuple) and v and v[0] == 'body'):
                continue
            inner = dict_of(cn.entries(v))
            vid = inner.get('equipment_variant_index',
                            inner.get('equipment_variant', inner.get('id')))
            var = None
            arch = None
            for tk, tv in inner.items():
                if tk.startswith('T_') and isinstance(tv, tuple) and                         tv and tv[0] == 'body':
                    var = cn.id_of(tv)
                    if gt:
                        arch = gt.archetype(tv)
                    break
            if arch is None and gt:
                arch = gt.archetype_of(vid) if cn.is_body(vid) else None
            stock.append({"variant": var, "archetype": arch,
                          "amount": inner.get('amount')})
    out["stockpile"] = stock
    for marker in markers_of(pm.get('cic_bank')):
        out["cic_bank"] = prim(cn.one(marker, 'value'))
    custom = gt.scheduled_variants(getattr(cn, "_cur_tag", None) or "")
    if custom:
        out["custom_variants"] = {k: ", ".join(v) for k, v in custom.items()}
    return out


def sec_construction(cn: Countries, mem: dict) -> dict:
    """Construction queue = production.general_lines (repeated `building`
    items). Present in the save ONLY when the queue is non-empty. Schema
    verified vs ENG AI queue (GER 1936-03-31): cost == common/buildings
    base_cost; started items carry produced/active_factories/speed."""
    out = {"queue": []}
    pr = mem.get('production')
    if not cn.is_body(pr):
        return out
    pm = dict_of(cn.entries(pr))
    for gl in markers_of(pm.get('general_lines')):
        for k, v in cn.entries(gl):
            for m in markers_of(v):
                d = dict_of(cn.entries(m))
                b = d.get('building')
                bd = dict_of(cn.entries(b)) if cn.is_body(b) else {}
                iv = d.get('T_000B')
                idd = dict_of(cn.entries(iv)) if cn.is_body(iv) else {}
                prog = d.get('produced')
                cost = d.get('cost')
                frac = None
                if isinstance(prog, (int, float)) and \
                        isinstance(cost, (int, float)) and cost:
                    frac = round(prog / cost, 3)
                out["queue"].append({
                    "serial": idd.get('T_000B'),
                    "building": bd.get('template'),
                    "state": bd.get('location'),
                    "produced": prog,
                    "cost": cost,
                    "progress": frac,
                    "factories": d.get('active_factories'),
                    "speed_per_day": d.get('speed'),
                    "amount": d.get('amount'),
                    "priority": d.get('priority'),
                    "created_h": decode_hdate(d.get('created_date')),
                    "allied_build": d.get('allied_build'),
                    "started": prog is not None,
                })
    return out


def sec_resources(cn: Countries, mem: dict) -> dict:
    r = mem.get('resources')
    if not cn.is_body(r):
        return {}
    rm = dict_of(cn.entries(r))
    out = {}
    for k in ("produced", "imported", "exported", "to_export", "base_export"):
        vals = {}
        for marker in markers_of(rm.get(k)):
            for name, val in cn.entries(marker):
                if isinstance(val, (int, float)) and \
                        not str(name).startswith('T_'):
                    vals[name] = val
        if vals:
            out[k] = vals
    return out


def sec_units(cn: Countries, mem: dict) -> dict:
    gt = cn.tables()
    out = {"num_ships": prim(mem.get('num_ships'))}
    u = mem.get('units')
    divs, n_fleets, n_task_forces = [], 0, 0
    if cn.is_body(u):
        for k, v in cn.entries(u):
            if not (isinstance(v, tuple) and v and v[0] == 'body'):
                continue
            if k == 'fleet':
                n_fleets += 1
                f1 = dict_of(cn.entries(v))
                for tf in markers_of(f1.get('task_force')):
                    n_task_forces += 1
                continue
            if k != 'division':
                continue
            dv_marker = v
            dv = dict_of(cn.entries(dv_marker))
            mp_val = None
            for marker in markers_of(dv.get('army_manpower')):
                amv = cn.one(marker, 'army_manpower_value')
                if cn.is_body(amv):
                    vv = cn.one(amv, 'value')
                    if cn.is_body(vv):
                        mp_val = cn.one(vv, 'value')
            tpl_id = cn.id_of(dv_marker, 'division_template_id')
            tpl_name = gt.template_name(tpl_id) if gt else None
            # division_name = {type, name_order}: per-template ordinal
            # (1st/2nd/... division raised off that template). Display name
            # = "<ordinal>. <template>" for the standard scheme — verified
            # vs GER 1936 ("1. Panzer-Division" etc.); brigade-size units
            # carry no order.
            dn = dv.get('division_name')
            dnm = dict_of(cn.entries(dn)) if cn.is_body(dn) else {}
            order = dnm.get('name_order')
            name = f"{order}. {tpl_name}" if \
                (isinstance(order, (int, float)) and tpl_name) else tpl_name
            divs.append({
                "id": cn.id_of(dv_marker),
                "template_id": tpl_id,
                "template": tpl_name,
                "name_order": order,
                "name": name,
                "location": dv.get('location'),
                "organisation": dv.get('organisation'),
                "strength": dv.get('strength'),
                "experience": dv.get('experience'),
                "dig_in": dv.get('dig_in'),
                "manpower": mp_val,
            })
    out.update({"n_divisions": len(divs), "divisions": divs,
                "n_fleets": n_fleets, "n_task_forces": n_task_forces})
    return out


def sec_diplomacy(cn: Countries, mem: dict) -> dict:
    dd = mem.get('diplomacy')
    if not cn.is_body(dd):
        return {}
    dm = dict_of(cn.entries(dd))
    rows = []
    for marker in markers_of(dm.get('active_relations')):
        for k, v in cn.entries(marker):
            if not (isinstance(v, tuple) and v and v[0] == 'body'):
                continue
            inner = dict_of(cn.entries(v))
            rows.append({"c": k, "attitude": prim(inner.get('attitude')),
                         "opinion": prim(inner.get('cached_sum'))})
    return {"active_relations": rows}


def sec_decisions(cn: Countries, mem: dict) -> dict:
    ds = mem.get('decision_status')
    if not cn.is_body(ds):
        return {}
    dm = dict_of(cn.entries(ds))
    out = {"timed": [], "targeted": []}

    def rows(key):
        res = []
        for marker in markers_of(dm.get(key)):
            inner = dict_of(cn.entries(marker))
            dec = inner.get('decision')
            if dec is not None:
                # flat record: <key> = { decision, target, days }
                res.append({"decision": prim(dec),
                            "target": one_or_val(inner.get('target')),
                            "days": inner.get('days')})
            else:  # container of repeated per-decision bodies
                for k, v in cn.entries(marker):
                    if not (isinstance(v, tuple) and v and v[0] == 'body'):
                        continue
                    d2 = dict_of(cn.entries(v))
                    res.append({"decision": prim(d2.get('decision')),
                                "target": one_or_val(d2.get('target')),
                                "days": d2.get('days')})
        return res
    out["timed"] = rows('active_timed_decision')
    out["targeted"] = rows('active_targeted_decision')
    return out


def sec_focus(cn: Countries, mem: dict) -> dict:
    """Focus state + research.avail-style 'pickable now' derivation.

    Save schema (NOTES.md 20日, byte-verified GER/SOV/ITA/ENG/FRA/POL/JAP):
      focus = { completed = <id>  (REPEATED key, one per completed focus,
                                 in completion order)
                progress = <F32 raw/1e5 = DAYS: banked days while no focus
                            runs (cap MAX_SAVED_FOCUS_PROGRESS=10), else
                            days into the current focus>
                current = <id> (absent when none) paused = <bool> }
    Duration = cost * 7 (defines NFocus.FOCUS_POINT_DAYS)."""
    f = mem.get('focus')
    if not cn.is_body(f):
        return {}
    fm = dict_of(cn.entries(f))
    completed = [v for k, v in cn.entries(f)
                 if k == 'completed' and isinstance(v, str)]
    out = {"current": fm.get('current'), "progress": fm.get('progress'),
           "paused": fm.get('paused'),
           "tree": prim(mem.get('focus_tree')),
           "completed": completed}
    out["n_completed"] = len(completed)
    prog = fm.get('progress')
    banked = prog if out["current"] is None else None
    if banked is not None:
        out["banked_days"] = banked
    if out["current"] is not None:
        try:
            from .focusdata import FocusDB
            dur = FocusDB().days(out["current"])
            if dur is not None and isinstance(prog, (int, float)):
                out["duration_days"] = dur
                out["remaining_days"] = round(max(0.0, dur - prog), 1)
        except Exception:
            pass
    try:
        from .focusdata import FocusDB
        out["available"] = FocusDB().available(
            completed, current=out["current"], tag=cn._cur_tag,
            used_trees=cn.tree_usage(), banked=banked)
    except Exception as exc:
        out["available"] = [{"error": f"{exc.__class__.__name__}: {exc}"}]
    return out


def sec_fuel(cn: Countries, mem: dict) -> dict:
    f = mem.get('fuel_status')
    if not cn.is_body(f):
        return {}
    fm = dict_of(cn.entries(f))
    keep = ("fuel", "max_fuel", "fuel_gain", "fuel_cost",
            "fuel_gain_per_oil", "fuel_gain_from_states", "remaining_hours")
    return {k: fm[k] for k in keep if k in fm}


def sec_mp(cn: Countries, mem: dict) -> dict:
    out = {}
    mp = mem.get('manpower')
    if cn.is_body(mp):
        out["ratio"] = cn.one(mp, 'ratio')
    total = 0
    u = mem.get('units')
    if cn.is_body(u):
        for k, v in cn.entries(u):
            if k != 'division' or not (isinstance(v, tuple) and v[0] == 'body'):
                continue
            dv = dict_of(cn.entries(v))
            for marker in markers_of(dv.get('army_manpower')):
                amv = cn.one(marker, 'army_manpower_value')
                if cn.is_body(amv):
                    vv = cn.one(amv, 'value')
                    if cn.is_body(vv):
                        val = cn.one(vv, 'value')
                        if isinstance(val, (int, float)):
                            total += val
    out["divisions_manpower"] = total
    return out


def sec_chars(cn: Countries, mem: dict) -> dict:
    """Country roster from `characters` character_status items, joined with
    names from the global character_manager."""
    gt = cn.tables()
    all_chars = gt.characters()
    out = {"leader": None, "advisors": [], "unit_leaders": [],
           "scientists": []}
    ch = mem.get('characters')
    if not cn.is_body(ch):
        return out
    for k, v in cn.entries(ch):
        if k != 'character_status' or not cn.is_body(v):
            continue
        d = dict_of(cn.entries(v))
        iv = d.get('character')
        cid = None
        if cn.is_body(iv):
            cid = dict_of(cn.entries(iv)).get('T_000B')
        info = all_chars.get(cid, {})
        row = {"id": cid, "name": info.get("name")}
        # several characters carry country_leader=True (ideological
        # succession pool); body order puts the CURRENT leader first
        # (live-verified: GER shows Hitler, 17日)
        if d.get('country_leader') and out["leader"] is None:
            out["leader"] = row["name"] or row
        if d.get('advisor'):
            out["advisors"].append(row["name"] or row)
        if d.get('unit_leader'):
            out["unit_leaders"].append(row["name"] or row)
        if d.get('scientist'):
            out["scientists"].append(row["name"] or row)
    return out


def _flatten(cn: Countries, v) -> list:
    """A value that may be a scalar / body-of-run / run -> list of scalars."""
    if isinstance(v, (int, float, str)) or v is None:
        return [v] if v is not None else []
    if cn.is_body(v):
        out = []
        for _k, vv in cn.entries(v):
            if isinstance(vv, list):
                out.extend(x for x in vv if isinstance(x, (int, float)))
            elif isinstance(vv, (int, float, str)):
                out.append(vv)
        return out
    if isinstance(v, list):
        return [x for x in v if isinstance(x, (int, float))]
    return []


def sec_theatres(cn: Countries, mem: dict) -> dict:
    """Army command chain: theatres.theatre entries. Byte-verified on
    GER_1936_03_31_16 (NOTES.md 18日): theatre = {id{serial,type=67},
    area(states-run), unit xN ({serial,type=51} handles whose serials match
    the division ids in `units`), front xN ({serial,type=66}, area, provinces,
    enemies)}. Army display names ("1. Armee") are NOT serialized."""
    out = {"theatres": []}
    th = mem.get('theatres')
    if not cn.is_body(th):
        return out
    tm = dict_of(cn.entries(th))
    for t in markers_of(tm.get('theatre')):
        tid = cn.id_of(t)
        area: list = []
        units, fronts = [], []
        for k, v in cn.entries(t):
            if k == 'unit' and cn.is_body(v):
                units.append(cn.id_of(v))
            elif k == 'front' and cn.is_body(v):
                fd = dict_of(cn.entries(v))
                fronts.append({
                    "id": cn.id_of(v),
                    "area": fd.get('area'),
                    "provinces": _flatten(cn, fd.get('provinces')),
                    "enemies": _flatten(cn, fd.get('enemies')),
                })
            elif k == 'area':
                area = _flatten(cn, v)
        out["theatres"].append({"id": tid, "area_states": area,
                                "units": units, "fronts": fronts})
    return out


# ------------------------------------------------------------------- API

SECTIONS = {
    "pol": sec_politics,
    "research": sec_research,
    "prod": sec_production,
    "construction": sec_construction,
    "res": sec_resources,
    "units": sec_units,
    "diplo": sec_diplomacy,
    "decisions": sec_decisions,
    "focus": sec_focus,
    "fuel": sec_fuel,
    "mp": sec_mp,
    "chars": sec_chars,
    "theatres": sec_theatres,
}


def country_head(cn: Countries) -> str:
    head = f"save={cn.path.name} "
    try:
        h = cn.header.summary()
        head += " | ".join(h.split()[:4])
    except Exception:
        pass
    return head


def country_sections(path_or_cn, tags=None, names=None) -> dict:
    """Bundle sections for tags (list or single str; None = player/registry).
    names=None -> the full curated section set."""
    cn = path_or_cn if isinstance(path_or_cn, Countries) else Countries(
        path_or_cn)
    if tags is None:
        player = cn.player()
        date_s = ""
        try:
            date_s = cn.header.date_str()
        except Exception:
            pass
        return {"player": player, "date": date_s, "n_countries":
                len(cn.tags())}
    if isinstance(tags, str):
        tags = [tags]
    want = list(names or SECTIONS.keys())
    out = {}
    for tag in tags:
        mem = cn.members(tag)
        if not mem:
            out[tag] = {"error": f"no such country in save: {tag}"}
            continue
        cn._cur_tag = tag
        sec = {}
        for s in want:
            fn = SECTIONS.get(s)
            if fn is None:
                sec[s] = {"error": "unknown section"}
                continue
            try:
                sec[s] = fn(cn, mem)
            except Exception as exc:
                sec[s] = {"error": f"{exc.__class__.__name__}: {exc}"}
        out[tag] = sec
    return out


def format_sections(tag: str, sec: dict, max_rows: int = 14) -> str:
    """Compact agent-readable text for one country's sections."""
    out = [f"== {tag} =="]
    for name, data in sec.items():
        if isinstance(data, dict) and "error" in data:
            out.append(f"{name}: ERROR {data['error']}")
            continue
        scal = " ".join(
            f"{k}={v}" for k, v in data.items()
            if isinstance(v, (int, float, str, bool)) or v is None)
        out.append(f"{name}: {scal}".rstrip())
        for k, v in data.items():
            if isinstance(v, dict) and v and k != "error":
                out.append(f"  {k}: " + " ".join(
                    f"{kk}={vv}" for kk, vv in v.items()
                    if isinstance(vv, (int, float, str))))
        for k, v in data.items():
            if not (isinstance(v, list) and v):
                continue
            shown = v[:max_rows]
            if k == "divisions":
                txt = " | ".join(
                    f"id={d.get('id')} "
                    f"{d.get('name') or d.get('template') or d.get('template_id')} "
                    f"@{d.get('location')} org={d.get('organisation')} "
                    f"str={d.get('strength')} xp={d.get('experience')}"
                    for d in shown if isinstance(d, dict))
            elif k == "parties":
                txt = " ".join(f"{d.get('id')}:{d.get('popularity%')}"
                               for d in shown if isinstance(d, dict))
            elif k == "done":
                txt = ",".join(str(d.get('tech')) for d in shown)
            elif k == "in_progress":
                txt = " | ".join(
                    f"{d.get('tech')}(cost{d.get('cost_units','?')} "
                    f"yr{d.get('start_year','?')}) {d.get('points')}pts "
                    f"~{d.get('invested_days','?')}d"
                    for d in shown if isinstance(d, dict))
            elif k == "avail":
                txt = " | ".join(
                    f"{d.get('tech')}(cost{d.get('cost','?')} "
                    f"yr{d.get('start_year','?')}"
                    + (f" +{d['ahead_y']}y ahead" if d.get('ahead_y') else "")
                    + (f" ~{d['est_days']}d" if d.get('est_days') else "") + ")"
                    for d in shown if isinstance(d, dict))
            elif k == "available" and v and isinstance(v[0], dict) \
                    and "focus" in (v[0] or {}):
                txt = " | ".join(
                    f"{d.get('focus')}(cost{d.get('cost','?')}"
                    + (f" prereq={'+'.join(d['prereqs'])}" if d.get('prereqs') else "")
                    + (" GATED" if d.get('gated') else "")
                    + (f" ~{d['est_days']}d" if d.get('est_days') is not None
                       else "") + ")"
                    for d in shown if isinstance(d, dict))
            elif k == "theatres":
                txt = " | ".join(
                    f"theatre{d.get('id')} area={len(d.get('area_states') or [])}states "
                    f"divs={(d.get('units') or [])[:8]}"
                    + ("…" if len(d.get('units') or []) > 8 else "")
                    + f" fronts={len(d.get('fronts') or [])}"
                    for d in shown if isinstance(d, dict))
            elif k in ("military_lines", "naval_lines"):
                txt = " | ".join(
                    f"{d.get('archetype') or d.get('variant_id')} "
                    f"fac={d.get('factories')} req={d.get('requested')} "
                    f"prod={d.get('produced')}"
                    for d in shown if isinstance(d, dict))
            elif k == "queue":
                txt = " | ".join(
                    f"{d.get('building')}@s{d.get('state')} "
                    f"{d.get('progress') if d.get('progress') is not None else 'queued'}"
                    f"{' fac=' + str(d.get('factories')) if d.get('factories') is not None else ''}"
                    for d in shown if isinstance(d, dict))
            elif k == "stockpile":
                txt = " ".join(
                    f"{d.get('archetype') or d.get('variant')}x{d.get('amount')}"
                    for d in shown if isinstance(d, dict))
            elif k == "active_relations":
                txt = " ".join(f"{d.get('c')}:{d.get('attitude')}"
                               f"({d.get('opinion')})" for d in shown
                               if isinstance(d, dict))
            elif k == "ideas":
                txt = ",".join(str(x) for x in shown)
            elif k in ("timed", "targeted"):
                txt = " | ".join(
                    f"{d.get('decision')}@{d.get('target')} d={d.get('days')}"
                    for d in shown if isinstance(d, dict))
            elif k == "slots":
                txt = str(shown)
            elif k in ("advisors", "unit_leaders", "scientists"):
                txt = ", ".join(str(x) for x in shown)
            else:
                txt = str(shown)
            if txt:
                ell = f" (+{len(v)-max_rows} more)" if len(v) > max_rows else ""
                out.append(f"  {k}[{len(v)}]: {txt}{ell}")
    return "\n".join(out)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else (
        str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_11.hoi4"))
    tags = [a for a in sys.argv[2:] if a.isupper()]
    cn = Countries(path)
    if not tags:
        tags = [cn.player()] if cn.player() else cn.tags()[:1]
    for tag in tags:
        sec = country_sections(cn, tag, None)
        print(format_sections(tag, sec.get(tag, {})))
