import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import re
from hoi4_mcp import config
from hoi4_mcp.rtti.msvc import RttiDatabase

db = RttiDatabase.load(config.TABLES_DIR / "rtti.json")
print("db size:", len(db.by_name))
for name in [".?AVCCountry@@", ".?AVCGameState@@", ".?AVCProvince@@"]:
    print("has", name, name in db.by_name)
pats = [r"^\.?AVCCountry@@", r"^\.?AVCProvince@@"]
for p in pats:
    rx = re.compile(p)
    m = [i for i in db.by_name.values() if rx.match(i.name)]
    print(p, "->", [(i.name, i.vftable_rvas) for i in m])
