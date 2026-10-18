"""Semantic anchoring research tools (runnable one-off diagnostics)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import re
from collections import Counter

import numpy as np

from hoi4_mcp import config
from hoi4_mcp.process import instances as inst
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import Game


def load_db():
    db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
    vt_all = {}
    for c in db["classes"]:
        for v in c["vftable_rvas"]:
            vt_all[v] = c["name"]
    return db, vt_all


def vftable_rvas_of(db, name_pat):
    rx = re.compile(name_pat)
    out = []
    for c in db["classes"]:
        if rx.match(c["name"]):
            out.extend(c["vftable_rvas"])
    return out


class Probe:
    def __init__(self):
        self.db, self.vt_all = load_db()
        self.g = Game()
        self.p = self.g.proc
        self.base = self.p.base

    def instances(self, pat, unique=True):
        res = inst.scan_for_vftable_ptr(self.p, vftable_rvas_of(self.db, pat))
        out = []
        for rva, addrs in res.items():
            out.extend(addrs)
        return sorted(set(out)) if unique else sorted(out)

    def single(self, pat):
        addrs = self.instances(pat)
        return addrs[0] if len(addrs) == 1 else None

    def dump_annotated(self, root, nq=140, title=""):
        out = [f"--- {title} @ {root:#x} ---"]
        for i in range(nq):
            a = root + i * 8
            try:
                q = self.p.memory.u64(a)
            except OSError:
                break
            note = ""
            if q and (q - self.base) in self.vt_all:
                note = f" <- {self.vt_all[q - self.base]}"
            elif q and self.base < q < self.base + self.p.image_size:
                note = " <- binary"
            else:
                mbi = w.virtual_query(self.p.handle, q) if q else None
                if mbi is not None and mbi.State & w.MEM_COMMIT and (mbi.Protect & 0xFF) in (0x04, 0x08):
                    note = " [heap]"
            out.append(f"  +{i*8:#06x}: 0x{q:016X}{note}")
        return "\n".join(out)

    def whom_holds(self, value: int, max_back: int = 65536, sample: int = 120):
        """Scan memory for qword==value; return (hits, owner class counter)."""
        hits = []
        for mbi in inst._readable_regions(self.p):
            addr = mbi.BaseAddress
            end = addr + mbi.RegionSize
            while addr < end:
                n = min(1 << 22, end - addr)
                try:
                    raw = w.read_process_memory(self.p.handle, addr, n)
                except OSError:
                    addr += n
                    continue
                q = np.frombuffer(raw[:(len(raw) // 8) * 8], dtype=np.uint64)
                m = np.nonzero(q == np.uint64(value))[0]
                for h in m.tolist()[:40]:
                    hits.append(addr + h * 8)
                addr += n
        owner = Counter()
        for H in hits[:sample]:
            for back in range(0, max_back, 8):
                a = H - back
                try:
                    v = self.p.memory.u64(a)
                except OSError:
                    break
                rva = v - self.base
                if rva in self.vt_all:
                    owner[(self.vt_all[rva], back)] += 1
                    break
        return hits, owner
