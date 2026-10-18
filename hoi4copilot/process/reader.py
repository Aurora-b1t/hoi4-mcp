"""Typed memory reads over an attached process."""

from __future__ import annotations

import struct

from . import win32ext as w


class ProcessMemory:
    def __init__(self, handle: w.HANDLE):
        self._h = handle

    # -- raw -----------------------------------------------------------------
    def rpm(self, address: int, size: int) -> bytes:
        return w.read_process_memory(self._h, address, size)

    def rpm_checked(self, address: int, size: int, what: str = "") -> bytes:
        try:
            return self.rpm(address, size)
        except OSError:
            raise MemoryReadError(address, size, what)

    # -- scalars -------------------------------------------------------------
    def u8(self, a: int) -> int: return self.rpm(a, 1)[0]
    def u16(self, a: int) -> int: return struct.unpack("<H", self.rpm(a, 2))[0]
    def u32(self, a: int) -> int: return struct.unpack("<I", self.rpm(a, 4))[0]
    def i32(self, a: int) -> int: return struct.unpack("<i", self.rpm(a, 4))[0]
    def u64(self, a: int) -> int: return struct.unpack("<Q", self.rpm(a, 8))[0]
    def i64(self, a: int) -> int: return struct.unpack("<q", self.rpm(a, 8))[0]
    def f32(self, a: int) -> float: return struct.unpack("<f", self.rpm(a, 4))[0]
    def f64(self, a: int) -> float: return struct.unpack("<d", self.rpm(a, 8))[0]

    def ptr(self, a: int) -> int:
        """Read a pointer-sized value that may be NULL."""
        return self.u64(a)

    def ptr_checked(self, a: int, what: str = "") -> int:
        try:
            return self.u64(a)
        except OSError:
            raise MemoryReadError(a, 8, what)

    # -- strings -------------------------------------------------------------
    def cstr(self, a: int, max_len: int = 256) -> str:
        raw = self.rpm(a, max_len)
        raw = raw.split(b"\0", 1)[0]
        return raw.decode("utf-8", errors="replace")

    def u16str(self, a: int, max_chars: int = 128) -> str:
        raw = self.rpm(a, max_chars * 2)
        end = 0
        for i in range(0, len(raw), 2):
            if raw[i:i + 2] == b"\0\0":
                end = i
                break
        else:
            end = len(raw) - len(raw) % 2
        return raw[:end].decode("utf-16-le", errors="replace")

    # -- regions -------------------------------------------------------------
    def regions(self):
        return w.iter_regions(self._h)


class MemoryReadError(Exception):
    def __init__(self, address: int, size: int, what: str = ""):
        self.address = address
        self.size = size
        self.what = what
        super().__init__(f"failed memory read @ 0x{address:X} size={size} {what}")
