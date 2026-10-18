"""Live-clock hunt v2: with the save-side date encoding solved, the runtime
date is a KNOWN 32-bit value (epoch 60759359 + hours since 1936-01-01).

Probe: search all committed memory for the expected token (u32 + parts of a
u64, little endian) and report hits; after we resume the game for N hours the
targets move by a known +delta. Save the hit list for corroborating which
address is the live clock.

Run: python research/clock_anchor2.py [expected_token]
     (default derives from GER_1936_02_25_16.hoi4 = 1936-02-25 16:00)
"""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from hoi4_mcp.process.attach import Game
from hoi4_mcp.process.instances import _readable_regions
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.saveparse.saveinfo import read_header, decode_date

SG = Path.home() / "Documents/Paradox Interactive/Hearts of Iron IV/save games"


def main():
    token = None
    if len(sys.argv) > 1:
        token = int(sys.argv[1])
    else:
        h = read_header(SG / "GER_1936_02_25_16.hoi4", limit=16384)
        token = h.date_token()
        print("save header date:", decode_date(token))
    print("target token:", token, hex(token))

    g = Game()
    p = g.proc
    hits = []
    chunk = 1 << 20
    regions = list(_readable_regions(p))
    print(f"regions: {len(regions)}")
    for mbi in regions:
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(chunk, end - addr)
            try:
                buf = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            # u32 match
            m = len(buf) // 4
            if m:
                u32 = np.frombuffer(buf[: m * 4], dtype=np.uint32)
                for idx in np.nonzero(u32 == np.uint32(token))[0].tolist():
                    va = addr + idx * 4
                    # capture neighborhood
                    lo = max(0, idx * 4 - 8)
                    hi = min(len(buf), idx * 4 + 8)
                    hits.append((va, buf[lo:hi]))
            addr += n
    print(f"u32=={token}: {len(hits)} hits")
    bydelta: dict[int, int] = {}
    for va, ctx in hits:
        val = struct.unpack_from("<Q", ctx, 8)[0] if len(ctx) >= 16 else 0
        bydelta[val - token] = bydelta.get(val - token, 0) + 1
    print("next-qword - token distribution:",
          sorted(bydelta.items(), key=lambda kv: -kv[1])[:8])
    for va, ctx in hits[:24]:
        print(f"  {va:#x} {ctx.hex(' ')}")


if __name__ == "__main__":
    main()
