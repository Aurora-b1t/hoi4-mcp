"""Fuel scale calibration: raw int64s of fuel/max_fuel across countries+saves."""
import sys, struct
from pathlib import Path
sys.path.insert(0, r"D:/hoi4-copilot")
from hoi4copilot.readstate.world_state import walkthrough, find_countries, country_anchors, statement_member_scan
from hoi4copilot.readstate.bin5_scaffold import find_matching
from hoi4copilot.saveparse.saveinfo import decode_date

SG = Path(r'C:/Users/hongyu_tang/Documents/Paradox Interactive/Hearts of Iron IV/save games')
for name in sys.argv[1:] or []:
    pass
files = [a for a in sys.argv[1:] if (SG / a).is_file()] or \
    sorted({p.name for p in SG.glob('GER_1936_*.hoi4')}) + sorted({p.name for p in SG.glob('ITA_1936_*.hoi4')})
rows = []
for fn in files:
    data = (SG / fn).read_bytes()
    pos, kind, depth, span = walkthrough(data, data.find(b'HOI4bin5*')+9)
    k_p, o_p, c_p, io_i, ic_i = find_countries(data, 9, pos, kind, depth, span)
    anchors = country_anchors(data, pos, kind, depth, span, io_i, ic_i)
    for tg, ti, oi, ck in anchors:
        if tg not in ('GER', 'ITA', 'SOV', 'JPN', 'JAP', 'ENG', 'FRA', 'USA', 'POL', 'TUR', 'SRI', 'CHI', 'PRC', 'AST') or ck is None:
            continue
        d0 = int(depth[oi])
        m = statement_member_scan(data, pos, kind, depth, span, oi+1, ck, d0)
        fs = m.get('fuel_status')
        if not (fs and fs[0] == 'body'): continue
        # read first two 0x0167 (+fuel_gain 0x000D 3rd)
        i = fs[1] + 1
        vals = {}
        for nm in ('fuel', 'max_fuel', 'fuel_gain', 'fuel_gain_per_oil'):
            t = int(kind[i]); tok = int(kind[i+2])
            pv = int(pos[i+2])
            raw = struct.unpack_from('<q', data, pv+2)[0]
            vals[nm] = (tok, raw)
            i += 3
        rows.append((fn, tg, vals))
        break   # first matching country per save
for fn, tg, vals in rows:
    tokf, rf = vals['fuel']; tokm, rm = vals['max_fuel']
    _, rg = vals['fuel_gain']; _, rpo = vals['fuel_gain_per_oil']
    hdr = decode_from = None
    try:
        from hoi4copilot.saveparse.saveinfo import read_header
        hdr = read_header(SG / fn, limit=16384).date
    except Exception:
        hdr = '?'
    print(f'{fn[:28]:28s} {tg} fuel_raw={rf:>14,} max_raw={rm:>14,} gain_raw={rg:>10,} per_oil={rpo:>12,} scale_guess_fuel={rf/1e6:>10.2f} raw/1e5={rf/1e5:>12.1f} date={hdr}')
