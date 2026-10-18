"""Correct off-by-one probe: politics / decision_status / focus / theatres /
flags sample / fuel hex / construction search inside states."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import struct
from hoi4_mcp.readstate.world_state import (
    walkthrough, find_countries, country_anchors, statement_member_scan,
    NAMES, scalar_value)
from hoi4_mcp.readstate.bin5_scaffold import find_matching

SAVE = str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_03_31_11.hoi4")
argv = [a for a in sys.argv[1:] if Path(a).is_file()]
data = Path(argv[0] if argv else SAVE).read_bytes()
pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*')+9)
k_p, o_p, c_p, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)

def tree(open_i, maxd=4, ind='   ', max_items=16, max_sz=60000):
    cl = find_matching(kind, open_i)
    dt = int(depth[open_i]) + 1
    out, c = [], 0
    i = open_i + 1
    while i < cl:
        if int(depth[i]) != dt: i += 1; continue
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
                    out.append(f'{ind}{k} = body[{sz:,}b]')
                    if sz < max_sz and maxd > 0:
                        out.extend('   '+s for s in tree(i+2, maxd-1, ind+'   ', max_items, max_sz))
                elif c == max_items+1: out.append(f'{ind}... x{c}+')
                i = c2 + 1; continue
            if c < max_items:
                out.append(f'{ind}{k} = {scalar_value(vt, data, pos[i+2])!r}')
            i += 3; continue
        if c < max_items: out.append(f'{ind}{k} (no-eq)')
        i += 1
    if c > max_items: out.append(f'{ind}... x{c-max_items} more')
    return out

tag = 'GER'
for tg, ti, oi, ck in anchors:
    if tg == tag and ck:
        break
d0 = int(depth[oi])
m = statement_member_scan(data, pos, kind, depth, span, oi+1, ck, d0)
for bn, maxd in (('politics', 4), ('decision_status', 4), ('focus', 4),
                 ('theatres', 3), ('flags', 2), ('fuel_status', 1), ('manpower', 2)):
    b = m.get(bn)
    if not (b and b[0] == 'body'):
        print(f'=== {bn}: missing'); continue
    print(f'=== {tag}.{bn} ===')
    for line in tree(b[1], maxd=maxd, max_items=14):
        print(line)

# fuel raw tokens
fb = m['fuel_status'][1]
i = fb + 1
print('--- fuel_status raw tokens:')
print(key if (key := hex(int(kind[i]))) else '')
for j, label in ((i, 'fuel'), (i+3, 'max_fuel')):
    p = int(pos[j]); t = int(kind[j])
    print(f'  {label}: tok={t:#06x} hex={data[p:p+10].hex()}')

# active research: technologies entries with date > now
now = 60761506
tec = m['technology'][1]
sub = statement_member_scan(data, pos, kind, depth, span, tec+1, find_matching(kind, tec), int(depth[tec]))
tch = sub['technologies'][1]
ents = statement_member_scan(data, pos, kind, depth, span, tch+1, find_matching(kind, tch), int(depth[tch]))
print(f'--- technologies: {len(ents)} entries')
for k, v in ents.items():
    if v[0] != 'body': continue
    inner = statement_member_scan(data, pos, kind, depth, span, v[1]+1, v[2], int(depth[v[1]]))
    rp = inner.get('research_points'); de = inner.get('date')
    if rp and de and (rp[1] or 0) > 0 and de[1] != 60759371:
        print(f'  {k}: rp={rp[1]} date={de[1]} deadline={de[1]-now}h')
