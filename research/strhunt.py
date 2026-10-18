"""Search back through token offsets: for a given site in the file, we want
the QUOTED-token position q such that text spans [q+4, q+4+ln) and matches s,
with any trailing bytes afterwards.
"""
import sys, struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def find_string_tokens(data: bytes, s: bytes, start=0, limit_hits=200):
    hits = []
    p = data.find(s, start)
    while p >= 0 and len(hits) < limit_hits:
        # look back: could be QUOTED (0xf) or UNQUOTED (0x17) with proper len field
        for back in (2, 3, 4):
            q = p - back
            if q < 0:
                continue
            t = struct.unpack_from("<H", data, q)[0]
            if t in (0xF, 0x17):
                ln = struct.unpack_from("<H", data, q+2)[0]
                if q + 4 + ln == p + len(s):
                    hits.append((q, t, ln))
                    break
        p = data.find(s, p + 1)
    return hits


def report(s: bytes, path=str(Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV" / "save games" / "GER_1936_02_25_08.hoi4")):
    data = Path(path).read_bytes()
    print(f"-- {s!r} --")
    hits = find_string_tokens(data, s)
    print(f"  {len(hits)} string-token sites")
    ts = {}
    for q, t, ln in hits[:150]:
        nxt = struct.unpack_from("<H", data, q+4+ln)[0]
        after = data[q+4+ln:q+4+ln+6].hex()
        ts[after[:4]] = ts.get(after[:4], 0) + 1
    for k, c in sorted(ts.items(), key=lambda kv: -kv[1])[:8]:
        print(f"  after-string 2B {k}: x{c}")
    # show first 12 raw:
    for q, t, ln in hits[:12]:
        nxt = data[q+4+ln:q+4+ln+4].hex()
        print(f"  q={q:#x} ln={ln} after={nxt}")


if __name__ == "__main__":
    for v in (b"NOR_trotsky_in_norway", b"GER", b"BIG_naval", b"urban Opposition".replace(b" ", b"_")):
        report(v)
