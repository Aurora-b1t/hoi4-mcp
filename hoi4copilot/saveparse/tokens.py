"""Extract the hoI4 save-key token registry from hoi4.exe (static image data).

The 1.19.3 binary contains a 72-byte-stride node array whose records read:
    +0x00  u64  sentinel/empty-string sso ptr (value irrelevant)
    +0x08  u64  id         (~0..0x6000, sparse over keyspace; gaps skip ids)
    +0x10  ptr  -> pointer to the inline name bytes (may wrap past node end)
    +0x18  u32  21         (record type marker)
    +0x1c  u32  len+1      (name length + 1)
    +0x30  char name[len]  (inline, NUL-terminated)

The array runs contiguous with stride 0x48; consecutive sentinel qwords are
the fingerprint (sentinel RVA observed 0x9c5170 @ v1.19.3.0 checksum 5632 --
computed from ImageBase to stay relocation-safe).

Usage:
  python -m hoi4copilot.saveparse.tokens          # from exe on disk
  python research/... can pass --image-runtime later if needed
Writes tables/generated/tokens.json: {"image_base":..., "magic_offsets":...,
"tokens": {"<id decimal>": "name"}} to keep ids as JSON-int-decimal keys.
"""
from __future__ import annotations

import json
from collections import Counter
import struct
from pathlib import Path

from .. import config

RECORD_STRIDE = 0x48
ID_SLOT = 0x08
LEN_SLOT = 0x1C
NAME_SLOT = 0x30
TYPE_U32 = 21


def _find_sentinel_rva(pe_image_base: int) -> int:
    """The sentinel qword value differs on disk (ImageBase-relative).
    We don't know a priori which rdata qword it is; instead we detect the
    array directly by its id+len grid fingerprint, so no sentinel needed.
    Falls back to detecting via TYPE_U32/len field runs."""
    return 0


def extract_from_image(img: bytes, image_base: int,
                       heap_get=None) -> dict[int, str]:
    """Scan an image buffer for the token node array.

    heap_get(va, size) -> bytes reads outside-image strings (long names are
    heap-allocated at runtime); when absent those records are skipped.

    Robust scheme: find the sentinel value (an rdata/empty-string pointer
    that repeats with exact stride 0x48 across a long chain), walk the chain,
    and read each record: id@+0x08, len+=1@+0x1C, inline name@+0x30.
    Fallback: grid-fingerprint scan if no long chain is found.
    """
    import numpy as np

    n = len(img)
    q64 = np.frombuffer(img[: (n // 8) * 8], dtype=np.uint64)
    step = RECORD_STRIDE // 8
    # find values whose q64[i + step] == q64[i] often (sentinel chains)
    same = q64[:-step] == q64[step:]
    idxs_same = np.nonzero(same)[0]
    vals, counts = np.unique(q64[idxs_same], return_counts=True)
    # keep candidates: pointer-ish values, frequent
    mask = (vals > 0x10000) & (counts >= 50)
    cands = vals[mask]
    counts = counts[mask]
    if not len(cands):
        print("no sentinel candidate found")
        return {}
    order = np.argsort(-counts)
    best_value = int(cands[order[0]])
    best_len = 0
    for v in cands[order].tolist():
        idxs = np.nonzero(q64 == np.uint64(v))[0]
        idxs = np.sort(idxs[np.nonzero(q64[np.minimum(idxs + step, len(q64) - 1)] == np.uint64(v))])
        if not len(idxs):
            continue
        d = np.diff(idxs)
        breaks = np.nonzero(d != step)[0]
        seg = 0
        pos = 0
        for b in breaks.tolist():
            seg = max(seg, b - pos + 1)
            pos = b + 1
        seg = max(seg, len(idxs) - pos)
        if seg > best_len:
            best_len = seg
            best_value = v
    print(f"sentinel chain: value={best_value:#x} len={best_len}")
    table: dict[int, str] = {}
    if best_value is not None:
        idxs = np.nonzero(q64 == np.uint64(best_value))[0]
        idxs = np.sort(idxs[np.nonzero(q64[np.minimum(idxs + step, len(q64) - 1)] == np.uint64(best_value))])
        for i in idxs.tolist():
            off = i * 8
            if off + RECORD_STRIDE > n:
                continue
            q_id = struct.unpack_from("<Q", img, off + ID_SLOT)[0]
            ln = struct.unpack_from("<I", img, off + LEN_SLOT)[0]
            if not (0 < q_id < 0x10000 and 1 <= ln <= 64):
                continue
            strptr = struct.unpack_from("<Q", img, off + 0x10)[0]
            rva = strptr - image_base
            if rva == off + NAME_SLOT:      # inline copy
                raw = img[off + NAME_SLOT: off + NAME_SLOT + ln]
            elif 0 < rva < n:               # pointer elsewhere in image
                raw = img[rva: rva + ln]
            elif heap_get is not None:      # long name: heap-allocated string
                raw = heap_get(strptr, min(ln, 128))
            else:
                continue
            nm = raw.split(b"\x00")[0]
            if len(nm) == ln - 1:
                table[q_id] = nm.decode("latin-1", "replace")
        return table
    # fallback grid scan
    off = 0
    while off + RECORD_STRIDE < n:
        q_id = struct.unpack_from("<Q", img, off + ID_SLOT)[0]
        ln = struct.unpack_from("<I", img, off + LEN_SLOT)[0]
        ty = struct.unpack_from("<I", img, off + 0x18)[0]
        if 0 < q_id < 0x10000 and 1 <= ln <= 60 and ty == TYPE_U32:
            raw = img[off + NAME_SLOT: off + NAME_SLOT + ln]
            nm = raw.split(b"\x00")[0]
            if len(nm) == ln - 1:
                table[q_id] = nm.decode("latin-1", "replace")
        off += 8
    return table


def exe_buffer() -> tuple[bytes, int]:
    """Read the RUNNING game's image (or fall back to the on-disk exe mapped
    to VAs). NOTE: the token array lives in an uncommitted-by-section hole of
    the image that only exists in the live process (RVA ~0x33b8000,
    v1.19.3.0), so disk extraction alone cannot find it; runtime read is the
    production path, disk is only used when the game is not running."""
    import pefile
    import os

    try:
        from ..process.attach import Game
        g = Game()
        p = g.proc
        from ..process import win32ext as w
        img = w.read_process_memory(p.handle, p.base, p.image_size)
        return img, p.base
    except Exception:
        pass

    exe = config.find_install_dir() / config.EXE_NAME
    pe = pefile.PE(str(exe), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    raw = bytes(pe.__data__)
    buf = bytearray(size)
    try:
        buf[:min(size, 0x400)] = raw[:min(size, 0x400)]
    except Exception:
        pass
    for s in pe.sections:
        va = s.VirtualAddress
        rd = s.PointerToRawData
        take = min(s.Misc_VirtualSize, s.SizeOfRawData)
        if take <= 0 or rd + take > len(raw) or va + take > size:
            continue
        buf[va: va + take] = raw[rd: rd + take]
    return bytes(buf), image_base


def build_tokens_file(out: Path | None = None) -> dict[int, str]:
    heap_get = None
    img, image_base = None, 0x140000000
    try:
        from ..process.attach import Game
        g = Game()
        p = g.proc
        from ..process import win32ext as w
        img = w.read_process_memory(p.handle, p.base, p.image_size)

        def heap_get(va: int, size: int) -> bytes:
            return w.read_process_memory(p.handle, va, size)
    except Exception:
        pass
    if img is None:
        img, image_base = exe_buffer()
    table = extract_from_image(img, image_base, heap_get=heap_get)
    out = out or (config.TABLES_DIR / "tokens.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "exe": config.EXE_NAME,
        "image_base": image_base,
        "count": len(table),
        "tokens": {str(k): v for k, v in sorted(table.items())},
    }
    out.write_text(json.dumps(payload, indent=0, ensure_ascii=False))
    return table


def load_tokens(path: Path | None = None) -> dict[int, str]:
    path = path or (config.TABLES_DIR / "tokens.json")
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return {int(k): v for k, v in d["tokens"].items()}


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(prog="hoi4-tokens")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    tb = build_tokens_file(Path(a.out) if a.out else None)
    print(f"tokens: {len(tb)}")
    for k in (27, 0xEE, 0x289A, 0x299F):
        print(f"  {k:#06x} = {tb.get(k, '?')}")
