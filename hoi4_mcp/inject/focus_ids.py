"""Live CNationalFocus numeric-id ↔ script-name mapping (read-only).

SetNationalFocusCommand takes the numeric focus id (int32); the UI passes
[focus_obj+0x08]. This module builds that mapping straight from the live
game database: scan heap objects by their CNationalFocus vftable
(tables.FOCUS_VFT), then per instance read

  +0x08 int32  focus id (unique per object; 10668 distinct on 1.19.3.0)
  +0x18 std::string focus script name (MSVC layout: union{sso[16]; ptr},
               size at +0x10, cap at +0x18 — cap<=15 ⇒ sso bytes inline)
  (+0x38 is a second copy of the same string, used as a fallback)

Verified asset anchors (22 日, session GER 1936-09-19 paused):
  GER_the_four_year_plan -> 58138, GER_autarky_efforts -> 58139,
  GER_accelerate_the_rearmament_program -> 58147,
  GER_remilitarize_the_rhineland -> 58224, industrial_effort -> 58086.
The save's completed-focus list joins 1:1 into this map.

Cost: one vftable scan over committed RW memory (~20-25s), afterwards
pure per-instance reads (<1s). Map is rebuilt per session call is fine;
ids are stable for a given build+tree-load, so cache freely.
"""
from __future__ import annotations

import re
import time

from ..process.instances import scan_for_vftable_ptr
from . import tables as T

VFT_FOCUS = T.FOCUS_VFT         # primary vftable (multi-inheritance: +0x10 dup)
_SSORE = re.compile(rb"[a-zA-Z][a-zA-Z0-9_\-. ]{2,60}")


def _string_field(m, addr: int) -> str | None:
    """MSVC std::string at addr: {union{sso[16]; char* p}; size_t size;
    size_t cap}. cap<=15 and size<=15 => inline; cap>15 => heap pointer."""
    try:
        blob = m.rpm(addr, 0x20)
    except OSError:
        return None
    size = int.from_bytes(blob[0x10:0x18], "little")
    cap = int.from_bytes(blob[0x18:0x20], "little")
    if not 0 < size < 200:
        return None
    if cap <= 15 and size <= 15:
        s = blob[:size]
    else:
        ptr = int.from_bytes(blob[0:8], "little")
        try:
            s = m.rpm(ptr, size)
        except OSError:
            return None
    mt = _SSORE.match(s)
    return mt.group().decode() if mt else None


def scan_focus_ids(proc) -> dict:
    """Build {int focus_id: str script_name} from live memory. Read-only."""
    return {fid: nm for fid, (_addr, nm) in scan_focus_ids_objects(proc).items()}


def scan_focus_ids_objects(proc) -> dict:
    """{int focus_id: (object address, str script_name)}.

    The address matters: SetNationalFocusCommand stores a POINTER to the focus
    object (+0x30), not its numeric id — that was the 24 日 correction.
    """
    m = proc.memory
    found = scan_for_vftable_ptr(proc, [VFT_FOCUS])
    out: dict[int, tuple[int, str]] = {}
    for a in found.get(VFT_FOCUS, []):
        try:
            head = m.rpm(a, 0x40)
        except OSError:
            continue
        fid = int.from_bytes(head[8:12], "little")
        name = _string_field(m, a + 0x18) or _string_field(m, a + 0x38)
        if name:
            out[fid] = (a, name)
    return out


def scan_focus_ids_rich(proc) -> dict:
    """Same scan with diagnostics: counts + unnamed leftovers."""
    t0 = time.time()
    m = proc.memory
    found = scan_for_vftable_ptr(proc, [VFT_FOCUS])
    insts = found.get(VFT_FOCUS, [])
    out: dict[int, str] = {}
    plain: list[int] = []
    for a in insts:
        try:
            head = m.rpm(a, 0x40)
        except OSError:
            continue
        fid = int.from_bytes(head[8:12], "little")
        name = _string_field(m, a + 0x18) or _string_field(m, a + 0x38)
        if name:
            out[fid] = name
        else:
            plain.append(fid)
    by_pref: dict[str, int] = {}
    for n in out.values():
        pref = n.split("_", 1)[0]
        by_pref[pref] = by_pref.get(pref, 0) + 1
    return {"seconds": round(time.time() - t0, 1),
            "instances": len(insts),
            "mapped": len(out),
            "unnamed": plain[:40],
            "tree_prefixes": dict(sorted(by_pref.items(), key=lambda kv: -kv[1])),
            "by_id": {str(k): v for k, v in sorted(out.items())}}
