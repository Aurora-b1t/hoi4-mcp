"""One-shot diagnostics for runtime instance discovery.

Checks, in order of suspicion:
 1. Does the loaded exe image (runtime) match the on-disk one (RVA-derived)?
 2. Does any memory region contain the vftable VA of CGameState?
 3. Scan single region that contains CGameState vftable bytes copy (.rdata starts
    before heap). Then scan RW regions for pointers & what those pointers hold.
"""

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from hoi4copilot import config
from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import Game

db = json.loads((config.TABLES_DIR / "rtti.json").read_text())
gs = [c for c in db["classes"] if c["name"] == ".?AVCGameState@@"][0]
vft_rva = gs["vftable_rvas"][0]
print("CGameState vftable RVA on disk table:", hex(vft_rva))

g = Game()
p = g.proc
print(g.proc)
vft_va = p.base + vft_rva
print("runtime vftable VA:", hex(vft_va))

# 1. verify the on-disk vftable contents still match in the loaded image
disk = open(p.install_dir / config.EXE_NAME, "rb").read()
import pefile

pe = pefile.PE(str(p.install_dir / config.EXE_NAME), fast_load=True)
foff = pe.get_offset_from_rva(vft_rva)
disk_fn = struct.unpack_from("<Q", disk, foff)[0]
rt_fn = p.memory.u64(vft_va)
print(f"disk vftable[0]=0x{disk_fn:X}  runtime=0x{rt_fn:X}  delta=0x{rt_fn - disk_fn:X} (expect rebase delta = {hex(p.base - 0x140000000)})")

# 2. what does the re-based VM address of the vftable look like in RW memory?
# scan a big sample region for the VA value
targets = {vft_va}
hits = 0
scanned = 0
for mbi in w.iter_regions(p.handle):
    if not (mbi.State & w.MEM_COMMIT) or mbi.Protect != w.PAGE_READWRITE:
        continue
    if mbi.RegionSize > 3 << 30:
        continue
    addr = mbi.BaseAddress
    size = mbi.RegionSize
    try:
        while addr < mbi.BaseAddress + size:
            n = min(1 << 22, mbi.BaseAddress + size - addr)
            raw = w.read_process_memory(p.handle, addr, n)
            scanned += n
            q = np.frombuffer(raw[: (len(raw) // 8) * 8], dtype=np.uint64)
            m = np.nonzero(q == np.uint64(vft_va))[0]
            for h in m.tolist():
                inst = addr + h * 8
                print(f"HIT vftable-ptr instance @ 0x{inst:X}")
                hits += 1
                if hits > 20:
                    raise KeyboardInterrupt
            addr += n
    except KeyboardInterrupt:
        break
    except OSError:
        continue
print(f"scanned {scanned/1e6:.0f} MB, hits={hits}")
