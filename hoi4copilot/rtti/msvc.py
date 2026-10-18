"""MSVC x64 RTTI scanner for hoi4.exe.

The shipped exe keeps /GR runtime type information, giving the full class
inventory: name -> TypeDescriptor RVA -> CompleteObjectLocator RVA ->
vftable RVAs. Output addresses are RVAs so static-file and runtime scans
share one address space (runtime: VA = image_base + RVA).

Layouts (x64):
  TypeDescriptor { void* vftable; void* spare; char name[]; }   // name at td+16
  CompleteObjectLocator64  *6 DWORDs* {
      signature==1; offset; cdOffset; typeDescriptorOffset;  // image-relative
      classDescriptorOffset; selfOffset == locator's own RVA; }
  vftable at rva V: qword[V-8] == image_base + COL RVA (full VA, relocated),
  followed by >=1 function-pointer VAs inside the image.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pefile

log = logging.getLogger(__name__)

_NAME_RE = re.compile(rb".\?A[A-Za-z0-9_?$:./@\-' ]{1,300}@\x00")

MAX_NAME = 300


@dataclass
class TypeInfo:
    name: str
    td_rva: int
    col_rvas: list
    vftable_rvas: list


class RttiDatabase:
    def __init__(self, infos: list, image_base: int):
        self.by_name = {i.name: i for i in infos}
        self.by_td = {i.td_rva: i for i in infos}
        self.by_vftable: dict = {}
        for info in infos:
            for v in info.vftable_rvas:
                self.by_vftable[v] = info
        self.image_base = image_base

    def search(self, pattern: str) -> list:
        rx = re.compile(pattern, re.I)
        return [i for i in self.by_name.values() if rx.search(i.name)]

    def name_at_td(self, td_rva: int):
        return self.by_td.get(td_rva)

    def dump(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "image_base": self.image_base,
            "classes": [{"name": i.name, "td_rva": i.td_rva, "col_rvas": i.col_rvas,
                         "vftable_rvas": i.vftable_rvas} for i in self.by_name.values()],
        }
        path.write_text(json.dumps(payload, indent=1))

    @classmethod
    def load(cls, path: Path) -> "RttiDatabase":
        d = json.loads(path.read_text())
        infos = [TypeInfo(i["name"], i["td_rva"], i["col_rvas"], i["vftable_rvas"])
                 for i in d["classes"]]
        return cls(infos, d["image_base"])


def _sections(pe: pefile.PE):
    for s in pe.sections:
        raw = s.get_data()
        if not raw:
            continue
        yield s.VirtualAddress, raw


def scan_exe(exe_path: Path) -> RttiDatabase:
    pe = pefile.PE(str(exe_path), fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    data = bytes(pe.__data__)

    # ---------- 1. type descriptors (name -> td rva) ----------
    infos: dict = {}
    for m in _NAME_RE.finditer(data):
        name_bytes = m.group(0)
        if not name_bytes.startswith(b".?A"):
            continue
        td_rva = pe.get_rva_from_offset(m.start() - 16)
        if not (0 < td_rva < size_of_image):
            continue
        try:
            vf_va = pe.get_qword_at_rva(td_rva)
        except Exception:
            continue
        if vf_va is None or not (image_base <= vf_va < image_base + size_of_image):
            continue
        name = name_bytes[:-1].decode("ascii", errors="replace")
        if td_rva not in infos:
            infos[td_rva] = TypeInfo(name=name, td_rva=td_rva, col_rvas=[], vftable_rvas=[])

    known_td = set(infos)

    # ---------- 2. COLs across data sections ----------
    col_of: dict = {}   # col_rva -> td_rva
    for sec_rva, raw in _sections(pe):
        if sec_rva >= image_base:
            continue  # impossible, safety
        n32 = len(raw) // 4
        if n32 == 0:
            continue
        u32 = np.frombuffer(raw[: n32 * 4], dtype=np.uint32)
        cands = np.nonzero(u32 == 1)[0]
        if len(cands) == 0:
            continue
        cl = cands.tolist()
        for idx in cl:
            if idx + 5 >= n32:
                continue
            col_rva = sec_rva + idx * 4
            offset_field = int(u32[idx + 1])
            if offset_field & 0xFFFF0000:
                continue
            td_off = int(u32[idx + 3])
            cd_off = int(u32[idx + 4])
            self_off = int(u32[idx + 5])
            if self_off != col_rva:
                continue
            if not (0 < td_off < size_of_image and 0 < cd_off < size_of_image):
                continue
            if td_off not in known_td:
                continue
            col_of[col_rva] = td_off
            infos[td_off].col_rvas.append(col_rva)

    # ---------- 3. vftables: qword COL-VA stored just before function pointers ----------
    va_targets = {image_base + rva: rva for rva in col_of}
    for sec_rva, raw in _sections(pe):
        nq = len(raw) // 8
        if nq < 5:
            continue
        q = np.frombuffer(raw[: nq * 8], dtype=np.uint64)
        lo = np.uint64(image_base)
        hi = np.uint64(image_base + size_of_image)
        within = np.nonzero((q >= lo) & (q < hi))[0]
        for idx in within.tolist():
            if idx + 3 >= nq:
                continue
            val = int(q[idx])
            col_rva = va_targets.get(val)
            if col_rva is None:
                continue
            vft_rva = sec_rva + idx * 8 + 8
            ok = True
            for k in (idx + 1, idx + 2, idx + 3):
                f = int(q[k])
                if not (image_base < f < image_base + size_of_image) or f % 4:
                    ok = False
                    break
            if ok:
                infos[col_of[col_rva]].vftable_rvas.append(vft_rva)

    infos_list = [infos[r] for r in sorted(infos)]
    nvt = sum(len(i.vftable_rvas) for i in infos_list)
    log.info("RTTI scan: %d classes, %d COLs, %d vftables", len(infos_list), len(col_of), nvt)
    return RttiDatabase(infos_list, image_base)
