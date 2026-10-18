"""Heap battery: find the save-key identity structure in the RUNNING game.

For a handful of (key id, canonical value string) pairs taken from the GER
save header, scan ALL committed memory for occurrences of the string and
report any u16 in a +-72 byte window that equals the paired id (or that
appears suspiciously often across strings, to reveal an id slot offset).

Pairs:
  0x00EE  'Operation Postern v1.19.3.0.c01a (5632)'   (game version)
  0x299F  'very_easy'                                  (difficulty value)
  0x2E3E  'fascism'
  0x29C9  'MTG_second_london_conference'               (decision? name-first obj)
  27      'WTT_current_china_leader'                   (trigger name)
  0x2B5E  'very_easy'                                  (second place usage)
"""
import sys
import struct
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hoi4copilot.process.attach import Game
from hoi4copilot.process.instances import _readable_regions
from hoi4copilot.process import win32ext as w

PAIRS = [
    (0x00EE, b"Operation Postern v1.19.3.0.c01a (5632)"),
    (0x299F, b"very_easy"),
    (0x2E3E, b"fascism"),
    (0x29C9, b"MTG_second_london_conference"),
    (27,     b"WTT_current_china_leader"),
    (0x2B5E, b"very_easy"),
    (0x289A, b"tag"),
]


def scan():
    g = Game()
    p = g.proc
    hit_ctx: dict = defaultdict(lambda: defaultdict(list))  # (key,needle) -> {delta: [va]}
    processed = 0
    chunk = 1 << 20
    needles = [(key, bytes(needle)) for key, needle in PAIRS]
    regions = list(_readable_regions(p))
    for mbi in regions:
        addr = mbi.BaseAddress
        end = addr + mbi.RegionSize
        while addr < end:
            n = min(chunk, end - addr)
            try:
                buf = w.read_process_memory(p.handle, addr, n)
            except OSError:
                addr += n
                continue
            processed += len(buf)
            for key, needle in needles:
                start = buf.find(needle)
                while start >= 0:
                    va = addr + start
                    lo = max(0, start - 72)
                    hi = min(len(buf), start + len(needle) + 72)
                    win = buf[lo:hi]
                    keyk = (key, needle[:26].decode("utf-8", "replace"))
                    for off in range(0, len(win) - 1):
                        u = win[off] | (win[off + 1] << 8)
                        if u == key:
                            hit_ctx[keyk][lo + off - start].append(va)
                    start = buf.find(needle, start + 1)
            addr += n
    print(f"scanned {processed/1e9:.2f} GB committed across {len(regions)} regions")
    for keyk, deltas in sorted(hit_ctx.items(), key=lambda kv: kv[0][0]):
        print(keyk[0], repr(keyk[1]))
        items = sorted(deltas.items())
        print("   ", {m: len(v) for m, v in items})
        big = sorted(items, key=lambda kv: -len(kv[1]))[:2]
        for m, vas in big:
            print(f"    delta={m} n={len(vas)} e.g. {', '.join(hex(v) for v in vas[:4])}")


if __name__ == "__main__":
    scan()
