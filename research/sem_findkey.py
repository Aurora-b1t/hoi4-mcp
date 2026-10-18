"""Find where a given key sits in the save's token stream (depth/context)."""
import sys
from pathlib import Path
sys.path.insert(0, r"D:/hoi4-copilot")
import numpy as np
from hoi4copilot.saveparse.tokens import load_tokens
from hoi4copilot.readstate.world_state import walkthrough
from hoi4copilot.readstate.bin5_scaffold import find_matching

NAMES = {v: k for k, v in load_tokens().items()}  # name -> id
path = sys.argv[1] if len(sys.argv) > 1 and Path(sys.argv[1]).is_file() else \
    r'C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games/GER_1936_03_31_11.hoi4'
keys = [a for a in sys.argv[1:] if a != path]
data = Path(path).read_bytes()
pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*') + 9)

for key in keys:
    tid = NAMES.get(key)
    if tid is None:
        print(f'{key}: not in token registry'); continue
    sites = np.nonzero(kind == tid)[0]
    print(f'{key}: id={tid:#06x} sites={len(sites)}')
    pat = {}
    for i in sites[:20000]:
        follow = int(kind[i+1]) if i+1 < len(kind) else -1
        if follow == 0x0001 and int(kind[i+2]) == 0x0003:
            cl = find_matching(kind, i+2)
            lbl = f'body depth={int(depth[i])} size={int(pos[cl])-int(pos[i]):,}b parentsig={key}'
        elif follow == 0x0001:
            lbl = f'scalar depth={int(depth[i])}'
        else:
            lbl = f'no-eq depth={int(depth[i])}'
        pat[lbl] = pat.get(lbl, 0) + 1
    for k, v in sorted(pat.items()):
        print(f'   {k} x{v}')
