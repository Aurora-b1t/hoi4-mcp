"""Locate the save-key token registry inside the running hoi4.exe image.

Theory (from id distribution): save key ids are sparse indexes in 0..~0x4D59,
assigned once per key (append across versions). The registry likely lives as
static data: an array of pointers to C strings, where the array index or a
parallel field is the id.

Probe: 
  A) find qwords IN THE IMAGE that point into the image (string pointers),
     cluster consecutive ones (candidate pointer arrays)
  B) for each cluster, test whether the anchor ids land on plausible strings
     (0x00EE -> a version-looking string, 0x289A -> "tag", ...) 
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from hoi4copilot.process.attach import Game
from hoi4copilot.process import win32ext as w

ANCHORS = {
    0x00EE: "version-like",
    0x299F: "difficulty-like",
    0x2E3E: "ideology-like",
    0x289A: "tag (id 10394)",
}
SPACING = 8


def cstr(img, off, maxn=96):
    end = img.find(b'\x00', off, off + maxn)
    if end < 0:
        end = off + maxn
    raw = img[off:end]
    if not raw or any(c < 9 for c in raw):
        return None
    try:
        s = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if len(s) >= 2 else None


def main():
    g = Game()
    p = g.proc
    base, size = p.base, p.image_size
    img = w.read_process_memory(p.handle, base, size)
    print(f"image {size / 1e6:.1f} MB @ {base:#x}")

    q = np.frombuffer(img[: (len(img) // 8) * 8], dtype=np.uint64)
    lo = np.uint64(base)
    hi = np.uint64(base + size)
    into_idx = np.nonzero((q >= lo) & (q < hi))[0]
    print(f"image->image pointer qwords: {len(into_idx)}")

    strings = []          # cluster of ptr array idxs
    starts = []
    for i in into_idx.tolist():
        if not starts or i - starts[-1][-1] > 2:
            starts.append([i])
        else:
            starts[-1].append(i)
    clusters = [(c[0], len(c)) for c in starts]
    big = [c for c in clusters if c[1] >= 16]
    big.sort(key=lambda c: -c[1])
    print(f"strings-ptr clusters >= 16: {len(big)}, in 512+ : {sum(1 for c in big if c[1] >= 512)}")
    for start, n in big[:12]:
        print(f"  cluster idx {start:#x} n={n}")

    # For each big cluster: dump strings at positions near the anchor ids,
    # scaled per-cluster? Two possible indexings: absolute id == pos, or 
    # pos == id - base_of_cluster. Try pos==anchor_id and pos==anchor_id-base.
    print("\n--- anchor position checks (absolute id == pointer-array position) ---")
    for start, n in big[:30]:
        end = start + n
        hits = []
        for aid in ANCHORS:
            if start <= aid < end:
                va = int(q[aid])
                rva = va - base
                s = cstr(img, rva)
                if s:
                    hits.append((hex(aid), s))
        if hits:
            print(f"cluster@{start:#x} n={n}: {hits}")

    print("\n--- base-relative check: pos == anchor_id - cluster_start_id k ---")
    # different guess: id = pos + k for some constant k; detect k by matching 
    # "tag"-pointer position (aid 10394): k = pos('tag' string) - 10394
    tag_addrs = []
    for m in np.frombuffer(img, np.uint8).itershape() if False else []:
        pass
    # find the addresses of key strings first
    raw = img
    want = {
        b"tag\x00": "tag",
        b"very_easy\x00": "very_easy",
        b"fascism\x00": "fascism",
        b"Operation Postern": None,
        b"difficulty\x00": "difficulty",
    }
    addrs = {}
    for needle, key in want.items():
        idx = raw.find(needle)
        while idx >= 0:
            addrs.setdefault(key, []).append(base + idx)
            idx = raw.find(needle, idx + 1)
    for k, v in addrs.items():
        print(f"  string {'k' if False else k!r}: {[hex(x) for x in v[:6]]}")
    qnp = q
    for key, vas in addrs.items():
        for va in vas:
            hits = np.nonzero(qnp == np.uint64(va))[0].tolist()
            if not hits:
                continue
            for i in hits:
                # which cluster?
                for start, n in big[:120]:
                    if start <= i < start + n:
                        delta = i - 10394
                        print(f"  ptr-to-{key!r} at array idx {i:#x} in cluster@{start:#x}(n={n}) "
                              f"k = idx-10394 = {delta}  (if delta==0 this is a direct id table)")
                        break


if __name__ == "__main__":
    main()
