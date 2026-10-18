"""Dump any country body member 2-4 levels deep. Usage:
   python sem_dump.py <save|GER_1936_03_31_11> GER production [technology resources units diplomacy politics manpower fuel_status flags decision_status]
"""
import sys
from pathlib import Path
sys.path.insert(0, r"D:/hoi4-copilot")
from hoi4copilot.readstate.world_state import (
    walkthrough, find_countries, country_anchors, statement_member_scan,
    NAMES, scalar_value)
from hoi4copilot.readstate.bin5_scaffold import find_matching

SG = r'C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games'

def load(path):
    if Path(path).is_file():
        p = Path(path)
    else:
        sg = Path(SG)
        p = sg / path if (sg / path).is_file() else None
    if p is None or not p.is_file():
        print(f'no save: {path}'); sys.exit(1)
    return p.read_bytes(), p.name

def rec_body(data, pos, kind, depth, span, open_i, ind='   ', maxdepth=3, max_items=30):
    close_i = find_matching(kind, open_i)
    d_t = int(depth[open_i]) + 1
    cnt = 0
    out = []
    i = open_i + 1
    while i < close_i:
        if int(depth[i]) != d_t:
            i += 1; continue
        t = int(kind[i])
        if t == 0x0004: break
        if t in (0xF, 0x17):
            p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
            txt = data[p+4:p+4+ln].decode('utf-8', 'replace')
        else:
            txt = NAMES.get(t, f'T_{t:04X}')
        if int(kind[i+1]) == 0x0001:
            vt = int(kind[i+2])
            if vt == 0x0003:
                cl = find_matching(kind, i+2)
                sz = int(pos[cl]) - int(pos[i+2])
                cnt += 1
                if cnt > max_items:
                    out.append(f'{ind}... more ({i} tok idx {int(pos[i]):#x})')
                    i = cl + 1; continue
                out.append(f'{ind}{txt} = body[{sz:,}b] @ {int(pos[i+2]):#x}')
                if sz < 100000 and maxdepth > 0:
                    sub = rec_body(data, pos, kind, depth, span, i+2, ind + '   ',
                                   maxdepth - 1, max_items)
                    out.extend('   ' + s if not s.startswith('   ') else s for s in sub)
                i = cl + 1; continue
            out.append(f'{ind}{txt} = {scalar_value(vt, data, pos[i+2])!r}')
            i += 3; continue
        out.append(f'{ind}{txt} (no-eq)')
        i += 1
    return out

def main():
    args = sys.argv[1:]
    if not args:
        args = ['GER_1936_03_31_11.hoi4', 'GER', 'production']
    data, name = load(args[0])
    tag = args[1] if len(args) > 1 else 'GER'
    bodies = args[2:] or ['production']
    pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*')+9)
    k_p, o_p, c_p, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    for tg, ti, oi, ck in anchors:
        if tg != tag or ck is None:
            continue
        d0 = int(depth[oi])
        m = statement_member_scan(data, pos, kind, depth, span, oi+1, ck, d0)
        for bn in bodies:
            b = m.get(bn)
            if not (b and b[0] == 'body'):
                print(f'=== {tag}.{bn}: MISSING (type={b and b[0]})')
                continue
            sz = int(pos[b[2]]) - int(pos[b[1]])
            print(f'=== {tag}.{bn} [{sz:,}b] ===')
            for line in rec_body(data, pos, kind, depth, span, b[1], maxdepth=4):
                print(line)
        return
    print(f'anchor {tag} not found')

if __name__ == '__main__':
    main()
