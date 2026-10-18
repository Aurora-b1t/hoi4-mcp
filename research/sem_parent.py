"""Parent-chain probe: for the first site of a key, print enclosing body keys."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from hoi4_mcp.saveparse.tokens import load_tokens
from hoi4_mcp.readstate.world_state import walkthrough
from hoi4_mcp.readstate.bin5_scaffold import find_matching

NAME2ID = {v: k for k, v in load_tokens().items()}
ID2NAME = {v: k for k, v in NAME2ID.items()}
path = sys.argv[1] if len(sys.argv) > 1 and Path(sys.argv[1]).is_file() else \
    str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_11.hoi4")
keys = [a for a in sys.argv[1:] if a != path]
data = Path(path).read_bytes()
pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*') + 9)
n = len(kind)

def key_at(i):
    t = int(kind[i])
    if t in (0xF, 0x17):
        p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
        return data[p+4:p+4+ln].decode('utf-8', 'replace')
    return ID2NAME.get(t, f'T_{t:04X}')

for key in keys:
    tid = NAME2ID[key]
    sites = np.nonzero(kind == tid)[0]
    if not len(sites):
        print(f'{key}: none'); continue
    i = int(sites[0])
    # walk back: find enclosing OPEN braces by depth
    chain = []
    d = int(depth[i])
    j = i - 1
    while j >= 0 and len(chain) < 12:
        if int(kind[j]) == 0x0003 and int(depth[j]) < d:
            # it's an open at shallower depth; get its key: token j-1 or j-2
            k1 = int(kind[j-1])
            if k1 == 0x0001:
                chain.append(f'{key_at(j-2)!r}@{int(pos[j]):#x}')
                d = int(depth[j]); j -= 1; continue
            if k1 in (0xF, 0x17):
                chain.append(f'{key_at(j-1)!r}@{int(pos[j]):#x}')
                d = int(depth[j]); j -= 1; continue
            chain.append(f'ils@{int(pos[j]):#x}')
            d = int(depth[j]); j -= 1; continue
        j -= 1
    chain.reverse()
    print(f'{key} x{len(sites)} firstsite@{int(pos[i]):#x} depth={int(depth[i])}')
    for c in chain[::-1][:8]:
        print('   ^', c)
