"""Runtime instance discovery: find live objects by their vftable pointer.

Objects with polymorphic RTTI carry a pointer to their class vftable as the
first qword. Scanning committed RW memory for that pointer yields the live
instances (armies, countries, focus trees ...). This works without any prior
knowledge of singletons.
"""

from __future__ import annotations

import logging
import numpy as np

from .attach import Game
from . import win32ext as w

log = logging.getLogger(__name__)


def _readable_regions(proc):
    """Committed RW regions worth scanning (any heap-like type)."""
    p = proc
    for mbi in w.iter_regions(p.handle):
        protect = mbi.Protect & 0xFF   # high bits (TARGETS_INVALID etc.) don't matter
        if not mbi.State & w.MEM_COMMIT:
            continue
        if protect not in (0x04, 0x08):  # PAGE_READWRITE, PAGE_WRITECOPY
            continue
        if mbi.RegionSize < 64:
            continue
        yield mbi


def scan_for_vftable_ptr(proc: "AttachedProcess", vftable_rvas: list[int], min_count: int = 1) -> dict[int, list[int]]:
    """Find memory addresses whose first qword equals VA(vftable).

    Returns {vftable_rva: sorted instance addresses}. Scans PAGE_READWRITE
    regions; image regions hold static data and rarely contain heap objects
    mid-field, so keep the walk cheap there by skipping them.
    """
    p = proc
    va_targets = {p.base + rva: rva for rva in vftable_rvas}
    found: dict[int, list[int]] = {}
    chunk = 1 << 20  # 1 MB: tolerate flaky partial regions; game threads poke memory live
    for mbi in _readable_regions(p):
        start = mbi.BaseAddress
        end = start + mbi.RegionSize
        addr = start
        while addr < end:
            size = min(chunk, end - addr)
            try:
                raw = w.read_process_memory(p.handle, addr, size)
            except OSError:
                # partial/uncommitted page or racing region - skip to next chunk
                addr += size
                continue
            n = len(raw) // 8
            if n >= 1:
                q = np.frombuffer(raw[: n * 8], dtype=np.uint64)
                for target, tvftable in va_targets.items():
                    hits = np.nonzero(q == np.uint64(target))[0]
                    for hval in hits.tolist():
                        found.setdefault(tvftable, []).append(addr + hval * 8)
            addr += size
    for k in found:
        found[k] = sorted(found[k])
    return found


def count_watch(proc, key_vftable_rvas: dict[str, list[int]]) -> dict[str, int]:
    """Cheap version of instance scan returning counts only, per catalog key."""
    p = proc
    all_rvas = [rva for rvas in key_vftable_rvas.values() for rva in rvas]
    res = scan_for_vftable_ptr(p, all_rvas)
    counts = {}
    for key, rvas in key_vftable_rvas.items():
        counts[key] = sum(len(res.get(rva, [])) for rva in rvas)
    return counts
