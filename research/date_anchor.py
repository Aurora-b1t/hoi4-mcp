"""Find the packed date encoding among CGameDate instance copies.

Game is paused at 1936.01.01.12. Every CGameDate copy of the current date
should carry the same payload -> the dominant next-qword value across 1.4M
instances is the packed encoding. After advancing the clock by one in-game
hour the encoding must shift 12->13 at a stable offset.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from collections import Counter

import numpy as np

from probe import load_db
from hoi4copilot.process import instances as inst
from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import Game

OFFS = [8, 16, 24, 32]


def collect(db, vt_all, p, offsets=OFFS, max_instances=400000):
    gs = [c for c in db["classes"] if c["name"] == ".?AVCGameDate@@"][0]
    res = inst.scan_for_vftable_ptr(p, gs["vftable_rvas"])
    inst_addrs = [a for rva in gs["vftable_rvas"] for a in res.get(rva, [])][:max_instances]
    print("CGameDate instances:", len(inst_addrs))
    counters = {o: Counter() for o in offsets}
    addrs = np.array(sorted(inst_addrs), dtype=np.uint64)
    # batched reads: instances may be scattered; read each 8*(max offset/8)+8 bytes
    span = max(offsets) + 8
    CHUNK = 256
    for i in range(0, len(addrs), CHUNK):
        batch = addrs[i:i + CHUNK]
        for a in batch.tolist():
            try:
                raw = w.read_process_memory(p.handle, a, span)
            except OSError:
                continue
            for o in offsets:
                if o + 8 <= len(raw):
                    v = int.from_bytes(raw[o:o + 8], "little", signed=False)
                    counters[o][v] += 1
    return counters, inst_addrs


def main():
    db, vt_all = load_db()
    g = Game()
    p = g.proc
    counters, addrs = collect(db, vt_all, p)
    for o, c in counters.items():
        print(f"--- offset +{o}: top7 of {sum(c.values())}")
        for v, n in c.most_common(7):
            print(f"    0x{v:016X} x{n}")


if __name__ == "__main__":
    main()
