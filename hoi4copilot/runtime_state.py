"""Runtime game-state readers driven by RTTI instance scans.

game_date(): locate live CGameDate objects (vftables 0x27183a8 / 0x27183d8
at v1.19.3.0), read packed u64 at +8; == the save-side date token (see
saveparse.saveinfo), so decode_date() applies directly.

Object layout (x64):
    +0x00  void* vftable            (CGameDate; two variants observed)
    +0x08  u64    packed date       (== saveinfo DATE_EPOCH + hours)
    +0x10  void* other vftable

Scan is full RW memory (~30-60s); cache the resulting addresses and re-read
instantly afterwards. All copies agree while paused; while running they can
differ by a tick, so report max or median.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

from .process.attach import Game
from .process.instances import _readable_regions
from .process import win32ext as w
from .rtti.msvc import RttiDatabase
from . import config
from .saveparse.saveinfo import decode_date, DATE_EPOCH

log = logging.getLogger(__name__)

CGD_CLASS = r"^\.\?AVCGameDate@@"


def cgame_date_vftables(db: RttiDatabase | None = None) -> list[int]:
    db = db or RttiDatabase.load(config.TABLES_DIR / "rtti.json")
    rvas: list[int] = []
    for info in db.search(CGD_CLASS):
        rvas.extend(info.vftable_rvas)
    return rvas


def find_game_dates(g: Game) -> list[tuple[int, int]]:
    """Scan RW memory for live CGameDate instances.

    Live objects are 24-byte { vftable, packed_u64, vftable_2 }; plain
    scheduled-date blobs and image statics don't have the second vftable and
    are rejected. Returns [(addr, packed_u64)].
    """
    p = g.proc
    vts = cgame_date_vftables()
    va_set = {p.base + rva for rva in vts}
    if not va_set:
        return []
    uniq = np.array(sorted(va_set), dtype=np.uint64)
    out: list[tuple[int, int]] = []
    chunk = 1 << 24
    for mbi in _readable_regions(p):
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(chunk, end - addr)
            try:
                raw = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            m = len(raw) // 8
            if not m:
                addr += n
                continue
            q = np.frombuffer(raw[: m * 8], dtype=np.uint64)
            pos = np.searchsorted(uniq, q)
            pos_c = np.minimum(pos, len(uniq) - 1)
            hit = uniq[pos_c] == q
            for i in np.nonzero(hit)[0].tolist():
                if i + 2 >= m:
                    continue
                packed = int(q[i + 1])
                if int(q[i + 2]) not in va_set:
                    continue
                out.append((addr + i * 8, packed))
            addr += n
    return out


def read_date(g: Game, cached_addrs: list[int] | None = None) -> dict:
    """Current game date from live CGameDate objects.

    Temporal filter: values within a sane campaign window around the head
    cluster; the game keeps ALL live copies in sync while paused, so report
    the modal value and spread.
    """
    if cached_addrs:
        samples = []
        p = g.proc
        for a in cached_addrs:
            try:
                raw = w.read_process_memory(p.handle, a + 8, 8)
                samples.append(int.from_bytes(raw, "little"))
            except OSError:
                continue
        addrs = cached_addrs
    else:
        found = find_game_dates(g)
        found = [(a, v) for a, v in found
                 if DATE_EPOCH - 24 * 400 < v < DATE_EPOCH + 24 * 366 * 400]
        addrs = [a for a, _ in found]
        samples = [v for _, v in found]
    if not samples:
        return {"error": "no CGameDate instance found"}
    from collections import Counter
    clusters = []
    for v, c in Counter(samples).items():
        label = decode_date(v)
        if "raw" in label:
            continue          # ignore out-of-epoch garbage
        clusters.append((label, c))
    clusters.sort(key=lambda x: -x[1])
    return {
        "count": len(samples),
        "clusters": clusters[:12],
        "note": ("live date is a small in-sync cluster; static defaults and "
                 "scheduled dates dominate the list — cross-check with the "
                 "date-panel screenshot or a fresh save"),
    }
