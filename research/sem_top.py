"""Top-level (depth0) member scan of a bin5 save. Research one-shot."""
import sys
from pathlib import Path
sys.path.insert(0, r"D:/hoi4-copilot")
from hoi4copilot.readstate.world_state import walkthrough, NAMES, scalar_value
from hoi4copilot.readstate.bin5_scaffold import find_matching

data = Path(sys.argv[1] if len(sys.argv) > 1 else
    r'C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games/GER_1936_03_31_11.hoi4').read_bytes()
pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*')+9)
n = len(kind)
print('top-level (depth0) members of the file:')
i = 0
while i < n:
    t = int(kind[i]); d = int(depth[i])
    if d == 0 and t not in (0x0003, 0x0004):
        if t in (0xF, 0x17):
            p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
            txt = data[p+4:p+4+ln].decode('utf-8', 'replace')
            if int(kind[i+1]) == 0x0001:
                vt = int(kind[i+2])
                if vt == 0x0003:
                    cl = find_matching(kind, i+2)
                    print(f'  {txt} = body[{cl-i+1} tok, {int(pos[cl])-int(pos[i]):,}b]')
                    i = cl + 1; continue
                print(f'  {txt} = {scalar_value(vt, data, pos[i+2])!r}')
                i += 3; continue
            print(f'  {txt} (no-eq)'); i += 1; continue
        nm = NAMES.get(t, f'T_{t:04X}')
        if int(kind[i+1]) == 0x0001:
            vt = int(kind[i+2])
            if vt == 0x0003:
                cl = find_matching(kind, i+2)
                print(f'  {nm} = body[{cl-i+1} tok, {int(pos[cl])-int(pos[i]):,}b]')
                i = cl + 1; continue
            print(f'  {nm} = {scalar_value(vt, data, pos[i+2])!r}')
            i += 3; continue
        print(f'  {nm} (no-eq)'); i += 1; continue
    i += 1
