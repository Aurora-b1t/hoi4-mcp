"""Streaming full-memory diff to find live clock tickers.

Sweep -> wait (game running) -> sweep; record u32/qword cells whose value
changed by a small amount (1..4). Then a second pair of sweeps while PAUSED
to verify freeze. Cheap: streams pages, keeps only changed cell dict.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import time
from collections import defaultdict

import numpy as np

from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import Game
from probe import load_db


def sweep_u32(p):
    """Walk RW regions; return dict addr->u32 for cells whose bytes look 'current'."""
    out = {}
    for mbi in w.iter_regions(p.handle):
        if not (mbi.State & w.MEM_COMMIT) or (mbi.Protect & 0xFF) not in (0x04, 0x08):
            continue
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(1 << 22, end - addr)
            try:
                raw = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            m = len(raw) // 4
            u = np.frombuffer(raw[:m*4], dtype=np.uint32)
            # skip indexes of uninteresting pages by cheap prefilter: only keep values plausibly date-ish
            # date encodings end up ~0x029C7xxx; keep also small ints (for hour fields)
            mask = ((u >= 0x029C7000) & (u <= 0x029D0000)) | (u < 0x1000)
            idx = np.nonzero(mask)[0]
            for i in idx.tolist():
                out[addr + i*4] = int(u[i])
            addr += n
    return out


def main():
    db, vt_all = load_db()
    g = Game()
    p = g.proc
    print("pid", p.pid)

    print("sweep A (running)...")
    a = sweep_u32(p)
    print("cells:", len(a))
    time.sleep(12)
    print("sweep B (running)...")
    b = sweep_u32(p)
    print("cells:", len(b))

    pairs = 0
    tickers = []
    for addr, val in a.items():
        nv = b.get(addr)
        if nv is None:
            continue
        d = nv - val
        if d in (1, 2, 3, -1, -2, -3):
            pairs += 1
            tickers.append((addr, val, nv, d))
    print("small-delta changed cells:", pairs)
    seen = defaultdict(int)
    from collections import Counter
    region_stat = Counter()
    for addr, val, nv, d in tickers:
        mbi = w.virtual_query(p.handle, addr)
        key = (hex(mbi.BaseAddress) if mbi else "?", hex(mbi.Protect) if mbi else "?")
        region_stat[key] += 1
    for k, n in region_stat.most_common(10):
        print(k, n)
    (Path(__file__).parent / "tickers.json").write_text(
        __import__("json").dumps([(hex(ad), va, nv, d) for ad, va, nv, d in tickers]))


if __name__ == "__main__":
    main()
