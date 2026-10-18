"""Generic drill: path like production.military_lines into a country body."""
import sys
from pathlib import Path
sys.path.insert(0, r"D:/hoi4-copilot")
from hoi4copilot.readstate.world_state import (
    walkthrough, find_countries, country_anchors, statement_member_scan,
    NAMES, scalar_value)
from hoi4copilot.readstate.bin5_scaffold import find_matching

SAVE = r'C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games/GER_1936_03_31_11.hoi4'

def hexof(idx, n=14):
    p = int(pos[idx]); return ' '.join(f'{b:02x}' for b in data[p:p+n])

def tree(open_i, maxd=4, ind='   ', max_items=18, kind_of=None):
    cl = find_matching(kind, open_i)
    dt = int(depth[open_i]) + 1
    out, c = [], 0
    i = open_i + 1
    while i < cl:
        if int(depth[i]) != dt:
            i += 1; continue
        t = int(kind[i])
        if t == 0x0004: break
        if t in (0xF, 0x17):
            p = int(pos[i]); ln = data[p+2] | (data[p+3] << 8)
            k = data[p+4:p+4+ln].decode('utf-8', 'replace')
        else:
            k = NAMES.get(t, f'T_{t:04X}')
        if int(kind[i+1]) == 0x0001:
            vt = int(kind[i+2])
            if vt == 0x0003:
                c2 = find_matching(kind, i+2)
                sz = int(pos[c2]) - int(pos[i+2])
                c += 1
                if c <= max_items:
                    ki = f' [hex@{int(pos[i]):#x}]' if kind_of else ''
                    out.append(f'{ind}{k} = body[{sz:,}b]{ki}')
                    if sz < 30000 and maxd > 0:
                        sub = tree(i+2, maxd-1, ind+'   ')
                        out.extend('   '+s for s in sub)
                elif c == max_items + 1:
                    out.append(f'{ind}... x{c}+')
                i = c2 + 1; continue
            if c < max_items:
                v = scalar_value(vt, data, pos[i+2])
                ki = f' {hexof(i)}' if kind_of else ''
                out.append(f'{ind}{k} = {v!r}{ki}')
            i += 3; continue
        if c < max_items:
            out.append(f'{ind}{k} (no-eq){""}')
        i += 1
    return out

def main():
    global data, pos, kind, depth, span
    path = sys.argv[1] if Path(sys.argv[1]).is_file() else SAVE
    tag = 'GER'
    pths = []
    for a in sys.argv[1:]:
        if Path(a).is_file():
            path = a
        elif a.isupper():
            tag = a
        else:
            pths.append(a)
    data = Path(path).read_bytes()
    pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*')+9)
    k_p, o_p, c_p, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    for tg, ti, oi, ck in anchors:
        if tg != tag or ck is None:
            continue
        d0 = int(depth[oi])
        m = statement_member_scan(data, pos, kind, depth, span, oi+1, ck, d0)
        for pth in pths or ['production']:
            cur = m; cur_body_i = oi; ok = True
            parts = pth.split('.')
            for pi, key in enumerate(parts):
                b = cur.get(key)
                if not (b and b[0] == 'body'):
                    print(f'=== {tag}.{pth}: {"MISSING" if b is None else b[0]} at part {key}')
                    ok = False; break
                d_t = d0 + pi + 1
                cur = statement_member_scan(data, pos, kind, depth, span, b[1]+1, b[2], d_t)
                cur_body_i = b[1]
            if ok:
                print(f'=== {tag}.{pth} ===')
                for line in tree(cur_body_i, kind_of='hex' in sys.argv):
                    print(line)
        return
    print(f'no anchor {tag}')

if __name__ == '__main__':
    main()
