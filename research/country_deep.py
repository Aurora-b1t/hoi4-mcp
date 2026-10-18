"""Hop through CCountry pointer fields hunting the 'GER' tag (player country)."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np

from hoi4_mcp import config
from hoi4_mcp.process import instances as inst
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import Game

OUT = Path(__file__).parent
DEPTH_BAND = 0x4000
SCAN_SPAN = 0x800  # pointer-field band to walk inside CCountry


def main():
    db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
    vt = {v: c["name"] for c in db["classes"] for v in c["vftable_rvas"]}
    cc = [c for c in db["classes"] if c["name"] == ".?AVCCountry@@"][0]
    g = Game()
    p = g.proc
    base = p.base

    d = json.loads((OUT / "country_anchor.json").read_text())
    addrs = sorted(int(a, 16) for a in d["addrs"])

    # pick the contiguous block (stride 5904): find longest consecutive run
    runs, cur = [], [addrs[0]]
    for a, b in zip(addrs, addrs[1:]):
        if b - a in (5904, 17712):
            cur.append(b)
        else:
            runs.append(cur)
            cur = [b]
    runs.append(cur)
    block = max(runs, key=len)
    print("longest contiguous block:", len(block), hex(block[0]), "->", hex(block[-1]))

    hits = {}
    checked = 0
    for i, a in enumerate(block[:12] + [block[len(block) // 2], block[-1]]):
        try:
            raw = w.read_process_memory(p.handle, a, SCAN_SPAN)
        except OSError:
            continue
        q = np.frombuffer(raw, dtype=np.uint64)
        for j in range(len(q)):
            v = int(q[j])
            if not v or base < v < base + p.image_size:
                continue
            mbi = w.virtual_query(p.handle, v) if v else None
            if mbi is None or not mbi.State & w.MEM_COMMIT or (mbi.Protect & 0xFF) not in (0x04, 0x08):
                continue
            checked += 1
            try:
                tgt = w.read_process_memory(p.handle, v, DEPTH_BAND)
            except OSError:
                continue
            for pat_name, pat in (("ascii", b"GER\x00"), ("u16", b"G\x00E\x00R\x00")):
                jj = tgt.find(pat)
                while jj >= 0:
                    hits.setdefault(f"{hex(a)}+{hex(j*8)}->{hex(v)}", []).append((pat_name, hex(jj)))
                    jj = tgt.find(pat, jj + 1)
    print("pointer fields walked:", checked)
    for k, v in hits.items():
        print("HIT", k, v[:4])
    (OUT / "country_deep.json").write_text(json.dumps(hits, indent=1))

    # dump annotated band of the first CCountry in the block for manual review
    a0 = block[0]
    lines = []
    for i in range(SCAN_SPAN // 8):
        off = i * 8
        try:
            qv = int.from_bytes(w.read_process_memory(p.handle, a0 + off, 8), "little")
        except OSError:
            break
        note = ""
        if qv and qv - base in vt:
            note = f" <- {vt[qv - base]}"
        elif qv and base < qv < base + p.image_size:
            note = " [bin]"
        else:
            mbi = w.virtual_query(p.handle, qv) if qv else None
            if mbi is not None and mbi.State & w.MEM_COMMIT and (mbi.Protect & 0xFF) in (0x04, 0x08):
                note = " [heap]"
        lines.append(f"+{off:#06x}: 0x{qv:016X}{note}")
    (OUT / "country0_dump.txt").write_text("\n".join(lines))
    print("dumped band of", hex(a0))


if __name__ == "__main__":
    main()
