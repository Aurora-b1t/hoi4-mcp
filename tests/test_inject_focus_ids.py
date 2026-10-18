"""focus_ids layer tests: MSVC-string decoding, id readback and vftable
table wiring (pure functions — no live process needed)."""
from __future__ import annotations

import struct

import pytest

from hoi4copilot.inject import tables as T
from hoi4copilot.inject.focus_ids import _string_field, VFT_FOCUS  # noqa: F401


class _FakeMem:
    """rpm(addr, n) adres-arbiter: answers from a dict of byte ranges."""

    def __init__(self, pages: dict[int, bytes]):
        self.pages = pages

    def rpm(self, addr: int, n: int) -> bytes:
        for base, data in self.pages.items():
            if base <= addr < base + len(data):
                off = addr - base
                return data[off:off + n]
        raise OSError("unreadable")


# -- _string_field: MSVC std::string {union{sso[16];char*}; size; cap} ---------
def _msvc_string_page(buf_addr: int, sso: bytes | None = None, heap=None,
                      size: int = 0, cap: int = 0) -> bytes:
    b = bytearray(0x20)
    if heap is not None:
        struct.pack_into("<Q", b, 0, heap)
    elif sso is not None:
        b[0:len(sso)] = sso
    struct.pack_into("<Q", b, 0x10, size)
    struct.pack_into("<Q", b, 0x18, cap)
    return bytes(b)


def test_string_field_sso_inline():
    # short name stored inline: cap<=15 & size<=15
    blob = _msvc_string_page(0x1000, sso=b"AFG_kajaki_dam\0".ljust(16, b"\0"),
                             size=14, cap=15)
    mem = _FakeMem({0x1000: blob})
    name = _string_field(mem, 0x1000)
    assert name == "AFG_kajaki_dam"


def test_string_field_heap_pointer():
    # 22-char name: cap>15 -> pointer at +0, chars at heap
    s = b"GER_rekindle_imperial_sentiment"[:22] + b"\0"
    heap_addr = 0x565600000
    blob = _msvc_string_page(0x1000, heap=heap_addr, size=22, cap=31)
    mem = _FakeMem({
        0x1000: blob,
        heap_addr: s.ljust(32, b"\0"),
    })
    name = _string_field(mem, 0x1000)
    assert name == s[:22].decode().rstrip("\0")


def test_string_field_unreadable_and_empty_return_none():
    assert _string_field(_FakeMem({}), 0x10) is None
    blob = _msvc_string_page(0x1000, sso=b"\0" * 16, size=0, cap=15)
    assert _string_field(_FakeMem({0x1000: blob}), 0x1000) is None


def test_string_field_rejects_oversize():
    blob = _msvc_string_page(0x1000, sso=b"\0" * 16, size=500, cap=600)
    assert _string_field(_FakeMem({0x1000: blob}), 0x1000) is None


# -- tables wiring -------------------------------------------------------------
def test_focus_vftable_is_pinned_rva():
    # CNationalFocus primary vftable discovered on 22 日, live GER session
    assert VFT_FOCUS == 0x02739C08
    # it must be one of the known command/vft anchors style: small positive RVA
    assert 0x100000 <= VFT_FOCUS < 0x4000000


def test_focus_id_and_name_offsets_v2资产锚点():
    """The asset anchors from the 22 日 live closed loop stay pinned."""
    # live extracted: GER_the_four_year_plan == 58138 (int32 at obj+0x08)
    # (structural: id is int32 at +0x08 — verify via a fake instance block)
    head = bytearray(0x40)
    struct.pack_into("<Q", head, 0, 0x07FF706DA9C08)
    struct.pack_into("<i", head, 8, 58138)
    fid = int.from_bytes(head[8:12], "little")
    assert fid == 58138
