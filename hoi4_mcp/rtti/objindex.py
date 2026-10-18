"""Batch object index: one memory pass enumerates live instances for ALL
tracked classes, with periodic refresh.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import numpy as np

from ..process import win32ext as w
from ..process.instances import _readable_regions

log = logging.getLogger(__name__)

CHUNK = 1 << 24  # 16 MB


@dataclass
class ObjIndex:
    """addr lists per catalog key; addresses point at the object start."""

    addrs: dict[str, list[int]] = field(default_factory=dict)
    built_at: float = 0.0
    scanned_bytes: int = 0
    seconds: float = 0.0

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.addrs.items()}

    def for_key(self, key: str) -> list[int]:
        return self.addrs.get(key, [])


def scan_index(proc, targets: dict[str, list[int]], chunk: int = CHUNK) -> ObjIndex:
    """One pass over RW memory; targets maps key -> list of vftable RVAs."""
    t0 = time.perf_counter()
    uniq_va = sorted({proc.base + rva for rvas in targets.values() for rva in rvas})
    va_to_keys: dict[int, set[str]] = {va: set() for va in uniq_va}
    for key, rvas in targets.items():
        for rva in rvas:
            va_to_keys[proc.base + rva].add(key)
    uniq_np = np.array(uniq_va, dtype=np.uint64)
    found: dict[str, list[int]] = {k: [] for k in targets}
    total = 0
    for mbi in _readable_regions(proc):
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(chunk, end - addr)
            try:
                raw = w.read_process_memory(proc.handle, addr, n)
            except OSError:
                addr += n
                continue
            total += len(raw)
            m = len(raw) // 8
            if m and len(uniq_np):
                q = np.frombuffer(raw[: m * 8], dtype=np.uint64)
                pos = np.searchsorted(uniq_np, q)
                pos_c = np.minimum(pos, len(uniq_np) - 1)
                hit = uniq_np[pos_c] == q
                idxs = np.nonzero(hit)[0]
                for i in idxs.tolist():
                    va = int(q[i])
                    for key in va_to_keys[va]:
                        found[key].append(addr + i * 8)
            addr += n
    for k in found:
        found[k] = sorted(set(found[k]))
    out = ObjIndex(addrs=found, built_at=time.time(), scanned_bytes=total,
                   seconds=time.perf_counter() - t0)
    log.info("objindex: %s in %.1fs (%.1f GB)", out.counts(), out.seconds, total / 1e9)
    return out
