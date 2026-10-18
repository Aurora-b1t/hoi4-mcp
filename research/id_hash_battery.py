"""Token-id hash battery: test the hypothesis that save token ids are
truncated hashes of the key name, across every hash family we can think of.

We have solid anchor pairs from GER_1936_02_25_08 header:
  0x299F ~ difficulty-ish (value 'very_easy')
  0x2E3E ~ ideology-ish  (value 'fascism')
  0x00EE ~ version-ish   (value 'Operation Postern v1.19.3.0.c01a (5632)')
  0x284A ~ mystery u32   (value 60760687)
theory: id == H(name) & 0xFFFF (or >> shifts).

If ANY scheme matches >=2 anchors, the whole table collapses to a vocab
hash: we can decode every key from the game script corpus.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def fnv1a32(d, h=0x811C9DC5):
    for b in d:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1_32(d):
    h = 0x811C9DC5
    for b in d:
        h = ((h * 0x01000193) ^ b) & 0xFFFFFFFF
    return h


def djb2(d, seed=5381):
    h = seed
    for b in d:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h


def djb2lc(d, seed=5381):  # lowercased
    return djb2(bytes(c if 65 > c or c > 90 else c + 32 for c in d), seed)


def djb2x33(d, seed=0):
    h = seed
    for b in d:
        h = (h * 31 + b) & 0xFFFFFFFF
    return h


def sdbm(d):
    h = 0
    for b in d:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def llvm_hash(d):  # llvm "StringMap" style (DJB-seeded 0? close enough)
    h = 0
    for b in d:
        h = (h * 32 + b) & 0xFFFFFFFF
    return h


def crc16_ccaatt(variants):
    import zlib
    out = {}
    for name, v in variants.items():
        out[name] = v
    return out


FAMILIES = {}


def register(name, fn, truncate=(lambda h: h & 0xFFFF,)):
    trs = {"&0xFFFF": truncate[0]}
    FAMILIES[(name, "lo16")] = lambda d, f=fn, t=truncate[0]: t(f(d))
    FAMILIES[(name, "hi16")] = lambda d, f=fn: (f(d) >> 16) & 0xFFFF


for fname, f in [("fnv1a", fnv1a32), ("fnv1", fnv1_32), ("djb2", djb2),
                 ("djb2lc", djb2lc), ("djb2x33", djb2x33), ("sdbm", sdbm),
                 ("llvm", llvm_hash)]:
    register(fname, f)

# also seed variants for djb2: seeds 0,5381,0xFFFF...
for seed in (0, 0xFFFF, 0xFFFFFFFF):
    FAMILIES[(f"djb2s{seed:#x}", "lo16")] = lambda d, s=seed: djb2(d, seed=s) & 0xFFFF
    FAMILIES[(f"djb2s{seed:#x}", "hi16")] = lambda d, s=seed: (djb2(d, seed=s) >> 16) & 0xFFFF

# crc16s
import zlib

def c16_ccitt_false(d):
    crc = 0xFFFF
    for b in d:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc

def c16_xmodem(d):
    import binascii
    return binascii.crc_hqx(d, 0)

def c16_hqx_xff(d):
    import binascii
    return binascii.crc_hqx(d, 0xFFFF)

FAMILIES[("crc_ccitt", "raw16")] = c16_ccitt_false
FAMILIES[("crc_xmodem", "raw16")] = c16_xmodem
FAMILIES[("crc_hqx_xff", "raw16")] = c16_hqx_xff

# also: maybe COIEEL (cpp init?) nothing. add adler+sum variants
FAMILIES[("adler16", "raw16")] = lambda d: zlib.adler32(d, 0) & 0xFFFF
FAMILIES[("sum16", "raw16")] = lambda d: sum(d) & 0xFFFF

# Paradox Hash (community "dex hash" from paradox game converters): 
# h = 13 (seed 0) or similar; test both classic:
def pdx_hash(d, seed=0):
    h = seed
    for b in d:
        h = (h * 32 + b + 1) & 0xFFFFFFFF
    return h

for seed in (0, 1, 13, 5381):
    FAMILIES[(f"pdx{seed}", "lo16")] = lambda d, s=seed: pdx_hash(d, s) & 0xFFFF
    FAMILIES[(f"pdx{seed}", "hi16")] = lambda d, s=seed: (pdx_hash(d, s) >> 16) & 0xFFFF


ANCHORS = {
    "very_easy's key": 0x299F,
    "ideology-ish": 0x2E3E,
    "version-ish": 0x00EE,
    "tag-ish (0x289A)": 0x289A,
    "second-place tag (10394)": 10394,
}
NAMES = {
    "very_easy's key": ["difficulty", "game_difficulty", "diff", "save_difficulty"],
    "ideology-ish": ["ideology", "player_ideology", "politics"],
    "version-ish": ["game_version", "save_game_version", "version", "mod_name",
                    "save_version", "mod_version"],
    "tag-ish (0x289A)": ["tag", "country_tag", "TAG", "country"],
    "second-place tag (10394)": ["tag", "country_tag", "TAG"],
}


def main():
    for anchor, ids in [(aname, aid) for aname, aid in ANCHORS.items()]:
        pass
    # collect hits: which family maps some candidate name for an anchor to its id
    matches = []
    for famname, f in sorted(FAMILIES.items()):
        for anchor, aid in ANCHORS.items():
            for name in NAMES[anchor]:
                for dotted in (name,):
                    if f(dotted.encode()) == aid:
                        matches.append((famname, anchor, dotted, hex(aid)))
    for m in matches:
        print("MATCH", m)
    if not matches:
        print("no matches across", len(FAMILIES), "families;")
        # also print full hashes of candidates for manual eyeballing
        for fname, f in [("fnv1a", fnv1a32), ("fnv1", fnv1_32), ("djb2", djb2),
                         ("djb2x33", djb2x33), ("sdbm", sdbm)]:
            for nm in ["tag", "difficulty", "ideology", "game_version", "player"]:
                print(f"  {fname}({nm!r}) = {f(nm.encode()):#010x} lo={f(nm.encode()) & 0xFFFF:#06x} "
                      f"hi={f(nm.encode()) >> 16:#06x}")


if __name__ == "__main__":
    main()
