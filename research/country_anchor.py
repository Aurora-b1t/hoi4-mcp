"""CCountry array + player-country (GER) anchor.

Scans live CCountry instances, reports the address layout (contiguity, stride),
then looks for the 3-letter tag 'GER' inside each country's memory band to
find the player's country object. Dumps an annotated band of the player
country for field-offset hunting.
"""

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
BAND = 0x2000  # bytes to inspect around each country instance


def main():
    db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
    vt = {v: c["name"] for c in db["classes"] for v in c["vftable_rvas"]}
    cc = [c for c in db["classes"] if c["name"] == ".?AVCCountry@@"][0]
    g = Game()
    p = g.proc
    base = p.base
    res = inst.scan_for_vftable_ptr(p, cc["vftable_rvas"])
    addrs = sorted({a for r in cc["vftable_rvas"] for a in res.get(r, [])})
    print("CCountry instances:", len(addrs))
    diffs = [b - a for a, b in zip(addrs, addrs[1:])]
    from collections import Counter
    print("stride histogram:", Counter(diffs).most_common(8))

    # find GER band per instance
    ger_addrs, tag_hits = [], {}
    for i, a in enumerate(addrs):
        # scan [a - 0x40, a + BAND) for 'GER' å word (padded? tags are u8[3]+nul or u16?)
        try:
            raw = w.read_process_memory(p.handle, a, BAND)
        except OSError:
            continue
        for pat_name, pat in (("ascii", b"GER\x00"), ("u16le", b"G\x00E\x00R\x00")):
            j = raw.find(pat)
            if j >= 0:
                tag_hits.setdefault(pat_name, []).append((hex(a), hex(j)))
    for k, v in tag_hits.items():
        print(f"tag pattern {k}: {len(v)} countries, first: {v[:3]}")

    out = {"instance_count": len(addrs), "addrs": [hex(a) for a in addrs],
           "strides": Counter(diffs).most_common(10), "tag_hits": tag_hits}
    (OUT / "country_anchor.json").write_text(json.dumps(out, indent=1))

    if tag_hits.get("ascii"):
        a0 = int(tag_hits["ascii"][0][0], 16)
        probe = probe.Probe() if False else None
        # annotated dump of player country
        lines = []
        for i in range(BAND // 8):
            off = i * 8
            try:
                q = int.from_bytes(w.read_process_memory(p.handle, a0 + off, 8), "little")
            except OSError:
                break
            note = ""
            if q and q - base in vt:
                note = f" <- {vt[q - base]}"
            elif q and base < q < base + p.image_size:
                note = " [bin]"
            else:
                mbi = w.virtual_query(p.handle, q) if q else None
                if mbi is not None and mbi.State & w.MEM_COMMIT and (mbi.Protect & 0xFF) in (0x04, 0x08):
                    note = " [heap]"
            tiny = f" ({q})" if q < 10**8 else ""
            lines.append(f"+{off:#06x}: 0x{q:016X}{note}{tiny}")
        (OUT / "country_ger_dump.txt").write_text("\n".join(lines))
        print("dumped", len(lines), "qwords of player country @", hex(a0))


if __name__ == "__main__":
    main()
