"""Thin ctypes bindings for the Win32 process APIs we need.

Windows x64 only; the game is a 64-bit process and we are a 64-bit python.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from ctypes.wintypes import BOOL, DWORD, HANDLE, HMODULE, LPVOID, LPCVOID, ULONG

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---- process access ----
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_ALL_ACCESS = 0x1FFFFF

THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040
THREAD_SET_CONTEXT = 0x0010
THREAD_GET_CONTEXT = 0x0008

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_IMAGE = 0x1000000

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", ctypes.c_uint32),
        ("_pad1", ctypes.c_uint32),
        ("RegionSize", ctypes.c_uint64),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    ]


_k32.OpenProcess.restype = HANDLE
_k32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
_k32.ReadProcessMemory.restype = BOOL
_k32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, ctypes.c_size_t, ct := ctypes.POINTER(ctypes.c_size_t)]
_k32.WriteProcessMemory.restype = BOOL
_k32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
_k32.VirtualQueryEx.restype = ctypes.c_size_t
_k32.VirtualQueryEx.argtypes = [HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
_k32.VirtualAllocEx.restype = ctypes.c_void_p
_k32.VirtualAllocEx.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_size_t, DWORD, DWORD]
_k32.VirtualFreeEx.restype = BOOL
_k32.VirtualFreeEx.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_size_t, DWORD]
_k32.VirtualProtectEx.restype = BOOL
_k32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD, ctypes.POINTER(DWORD)]
_k32.CreateRemoteThread.restype = HANDLE
_k32.CreateRemoteThread.argtypes = [
    HANDLE, ctypes.c_void_p, ctypes.c_size_t, LPVOID, LPVOID, DWORD, ctypes.POINTER(DWORD)]
_k32.SuspendThread.restype = DWORD
_k32.ResumeThread.restype = DWORD
_k32.SuspendThread.argtypes = [HANDLE]
_k32.ResumeThread.argtypes = [HANDLE]
_k32.OpenThread.restype = HANDLE
_k32.OpenThread.argtypes = [DWORD, BOOL, DWORD]
_k32.WaitForSingleObject.restype = DWORD
_k32.WaitForSingleObject.argtypes = [HANDLE, DWORD]
_k32.CreateToolhelp32Snapshot.restype = HANDLE
_k32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
_k32.Thread32First.restype = BOOL
_k32.Thread32First.argtypes = [HANDLE, LPVOID]
_k32.Thread32Next.restype = BOOL
_k32.Thread32Next.argtypes = [HANDLE, LPVOID]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", DWORD),
    ]


TH32CS_SNAPTHREAD = 0x4
LIST_MODULES_ALL = 0x03


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", DWORD), ("EntryPoint", LPVOID)]


# EnumProcessModulesEx lives in psapi (kernel32 forwards it as K32* since Win7)
_psapi = ctypes.WinDLL("psapi", use_last_error=True)
_k32.EnumProcessModulesEx = _psapi.EnumProcessModulesEx
_k32.EnumProcessModulesEx.restype = BOOL
_k32.EnumProcessModulesEx.argtypes = [HANDLE, ctypes.POINTER(HMODULE), DWORD, ctypes.POINTER(DWORD), DWORD]

_psapi.GetModuleFileNameExW.restype = DWORD
_psapi.GetModuleFileNameExW.argtypes = [HANDLE, HMODULE, ctypes.c_wchar_p, DWORD]
_psapi.GetModuleBaseNameW.restype = DWORD
_psapi.GetModuleBaseNameW.argtypes = [HANDLE, HMODULE, ctypes.c_wchar_p, DWORD]
_psapi.GetModuleInformation.restype = BOOL
_psapi.GetModuleInformation.argtypes = [HANDLE, HMODULE, ctypes.POINTER(MODULEINFO), DWORD]


def open_process(pid: int, access: int = PROCESS_ALL_ACCESS) -> HANDLE:
    h = _k32.OpenProcess(access, False, pid)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return HANDLE(h)


def read_process_memory(handle: HANDLE, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not _k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.raw[: got.value]


def write_process_memory(handle: HANDLE, address: int, data: bytes) -> None:
    wrote = ctypes.c_size_t(0)
    if not _k32.WriteProcessMemory(handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(wrote)):
        raise ctypes.WinError(ctypes.get_last_error())


def virtual_query(handle: HANDLE, address: int) -> MEMORY_BASIC_INFORMATION | None:
    mbi = MEMORY_BASIC_INFORMATION()
    r = _k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if r == 0:
        return None
    return mbi


def iter_regions(handle: HANDLE, start: int = 0x10000, end: int = 0x7FFFFFFFFFFF):
    """Yield MEMORY_BASIC_INFORMATION for committed regions from low to high."""
    addr = start
    while addr < end:
        mbi = virtual_query(handle, addr)
        if mbi is None:
            return
        if mbi.State & MEM_COMMIT:
            yield mbi
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:  # guard against bad region info
            return
        addr = nxt


def enumerate_modules(handle: HANDLE):
    """Return (name_lower -> (base, size)) for all loaded modules."""
    needed = DWORD(0)
    size = 4096
    while True:
        buf = (HMODULE * (size // 8))()
        if not _k32.EnumProcessModulesEx(handle, buf, size, ctypes.byref(needed), LIST_MODULES_ALL):
            raise ctypes.WinError(ctypes.get_last_error())
        if needed.value <= size:
            break
        size = needed.value
    mods = []
    for i in range(needed.value // ctypes.sizeof(HMODULE)):
        hm = HMODULE(buf[i])
        name = ctypes.create_unicode_buffer(512)
        _psapi.GetModuleFileNameExW(handle, hm, name, 512)
        base = ctypes.create_string_buffer(ctypes.sizeof(MODULEINFO))
        info = MODULEINFO()
        _psapi.GetModuleInformation(handle, hm, ctypes.byref(info), ctypes.sizeof(info))
        mods.append((name.value.lower(), info.lpBaseOfDll or 0, info.SizeOfImage))
    return mods


def open_thread(tid: int, access: int = THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION
                | THREAD_SET_CONTEXT | THREAD_GET_CONTEXT) -> HANDLE:
    h = _k32.OpenThread(access, False, tid)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return HANDLE(h)


_k32.GetThreadTimes.restype = BOOL
_k32.GetThreadTimes.argtypes = [HANDLE, ctypes.POINTER(ctypes.c_uint64),
                                ctypes.POINTER(ctypes.c_uint64),
                                ctypes.POINTER(ctypes.c_uint64),
                                ctypes.POINTER(ctypes.c_uint64)]


def get_thread_times(handle: HANDLE) -> tuple[float, float, float, float]:
    """(create_s, exit_s, kernel_s, user_s) — FILETIME 100ns units.
    Works on RUNNING threads; user/kernel time accumulation is the
    kernel-blessed signal that a thread actually executes."""
    ct = ctypes.c_uint64(0)   # creation
    et = ctypes.c_uint64(0)   # exit
    kt = ctypes.c_uint64(0)   # kernel
    ut = ctypes.c_uint64(0)   # user
    if not _k32.GetThreadTimes(handle, ctypes.byref(ct), ctypes.byref(et),
                               ctypes.byref(kt), ctypes.byref(ut)):
        raise ctypes.WinError(ctypes.get_last_error())
    return ct.value * 1e-7, et.value * 1e-7, kt.value * 1e-7, ut.value * 1e-7


def suspend_thread(handle: HANDLE) -> int:
    return _k32.SuspendThread(handle)


def resume_thread(handle: HANDLE) -> int:
    return _k32.ResumeThread(handle)


def list_thread_ids(pid: int) -> list[int]:
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        out = []
        ok = _k32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                out.append(te.th32ThreadID)
            ok = _k32.Thread32Next(snap, ctypes.byref(te))
        return out
    finally:
        _k32.CloseHandle(snap)


def create_remote_thread(handle: HANDLE, start_routine: int, param: int, suspended: bool = False):
    tid = DWORD(0)
    flags = 0x4 if suspended else 0  # CREATE_SUSPENDED
    h = _k32.CreateRemoteThread(
        handle, None, 0, ctypes.c_void_p(start_routine), ctypes.c_void_p(param),
        flags, ctypes.byref(tid))
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return HANDLE(h), tid.value


def virtual_alloc_ex(handle: HANDLE, size: int, protect: int = PAGE_READWRITE, reserve: bool = False) -> int:
    p = _k32.VirtualAllocEx(
        handle, None, size,
        (MEM_RESERVE | MEM_COMMIT) if reserve else MEM_COMMIT, protect)
    if not p:
        raise ctypes.WinError(ctypes.get_last_error())
    return p


def virtual_free_ex(handle: HANDLE, addr: int, size: int = 0):
    if not _k32.VirtualFreeEx(handle, ctypes.c_void_p(addr), size, 0x8000):
        raise ctypes.WinError(ctypes.get_last_error())


def virtual_protect_ex(handle: HANDLE, addr: int, size: int, protect: int) -> int:
    old = DWORD(0)
    if not _k32.VirtualProtectEx(handle, ctypes.c_void_p(addr), size, protect,
                                 ctypes.byref(old)):
        raise ctypes.WinError(ctypes.get_last_error())
    return old.value


# ---- mitigation-policy introspection (READ-ONLY; no thread touched) ---------
_k32.GetProcessMitigationPolicy.restype = BOOL
_k32.GetProcessMitigationPolicy.argtypes = [HANDLE, ctypes.c_int, LPVOID, ctypes.c_size_t]

PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = 15
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = 2
PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = 7


def get_mitigation_policy(handle: HANDLE, policy: int, size: int = 8) -> int | None:
    buf = ctypes.create_string_buffer(size)
    if not _k32.GetProcessMitigationPolicy(handle, policy, buf, size):
        err = ctypes.get_last_error()
        if err:      # policy not supported on this build => None
            return None
    return int.from_bytes(buf.raw[:size], "little")


def mitigation_report(handle: HANDLE) -> dict:
    """Shadow-stack / dynamic-code / CFG raw policy dwords for one process.
    Relevant to the inject layer: SetContextIpValidation (shadow-stack
    bit) neuters SetThreadContext RIP-grafts; dynamic-code policy neuters
    RWX allocs. Read-only: works on any live process."""
    out = {}
    for name, pol, size in [("shadow_stack", PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY, 8),
                            ("dynamic_code", PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, 4),
                            ("cfg", PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, 4)]:
        out[name] = get_mitigation_policy(handle, pol, size)
    return out
