"""ABI check for the write-v3.1 VM (clean harness: no manual resolution)."""
from __future__ import annotations
import struct, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import keystone
from hoi4copilot.inject import script as S
from hoi4copilot.process import win32ext as w
from hoi4copilot.process.attach import AttachedProcess

PAGE_EXECUTE_READWRITE = 0x40
FAKE, META, PTRCALLEE, PTRCELL = 0x000, 0x600, 0x800, 0x900
FAKES_SIZE = 0x1000
MAGIC = 0xFEEDFACE12345678
ARGS6 = (0xA1A1A1A1A1A1A1A1, 0xB2B2B2B2B2B2B2B2, 0xC3C3C3C3C3C3C3C3,
         0xD4D4D4D4D4D4D4D4, 0xE5E5E5E5E5E5E5E5, 0xF6F6F6F6F6F6F6F6)
TARGET_VALUE = 0xDEADBEEFCAFEF00D
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def asm(src):
    code, _ = _KS.asm(src)
    return bytes(code)


def callee6(base):
    """6 args: 4 registers + 2 stack."""
    return asm(f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x00], rcx
    mov qword ptr [rax + 0x08], rdx
    mov qword ptr [rax + 0x10], r8
    mov qword ptr [rax + 0x18], r9
    mov r10, qword ptr [rsp + 0x28]
    mov qword ptr [rax + 0x20], r10
    mov r10, qword ptr [rsp + 0x30]
    mov qword ptr [rax + 0x28], r10
    movabs rax, {MAGIC:#x}
    ret
    """)


def ptr_callee(base):
    """The 6th argument (stack) must be a POINTER: record it and its referent."""
    return asm(f"""
    movabs rax, {base + META:#x}
    mov r10, qword ptr [rsp + 0x30]
    mov qword ptr [rax + 0x00], r10
    mov r10, qword ptr [r10]
    mov qword ptr [rax + 0x08], r10
    movabs rax, {MAGIC:#x}
    ret
    """)


d = tempfile.mkdtemp(prefix="abi_")
proc = subprocess.Popen([sys.executable, str(HERE / "victim.py"), d],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
state = Path(d) / f"{proc.pid}.json"
for _ in range(80):
    if state.exists():
        break
    time.sleep(0.1)
time.sleep(0.6)
p = AttachedProcess(proc.pid)
fakes = w.virtual_alloc_ex(p.handle, FAKES_SIZE, PAGE_EXECUTE_READWRITE)
w.write_process_memory(p.handle, fakes + FAKE, callee6(fakes))
w.write_process_memory(p.handle, fakes + PTRCALLEE, ptr_callee(fakes))
w.write_process_memory(p.handle, fakes + PTRCELL, struct.pack("<Q", TARGET_VALUE))
w.write_process_memory(p.handle, fakes + META, b"\0" * 0x40)

ch = S.ScriptChannel(p, timeout=3.0)
fails = []

sc = S.Script(allow_calls={(fakes, fakes + FAKES_SIZE)})
sc.call(fakes + FAKE, *ARGS6)
job = ch._ensure_arenas()
r = ch.run(sc)
got = struct.unpack("<6Q", p.memory.rpm(fakes + META, 0x30))
ok = got == ARGS6 and r["status"] == 0
print("8-arg ABI (4 reg + 2 stack):", "GREEN" if ok else f"RED {[hex(x) for x in got]}")
print("   victim alive:", proc.poll() is None, " record:",
      [hex(x) for x in struct.unpack("<8Q", p.memory.rpm(r["page"] + 0x40, 0x40))])
fails += [] if ok else ["8-arg"]

p.memory.rpm(fakes + META, 8)
w.write_process_memory(p.handle, fakes + META, b"\0" * 0x40)
sc2 = S.Script(allow_calls={(fakes, fakes + FAKES_SIZE)})
ref = sc2.read_ptr(fakes + PTRCELL)
sc2.call(fakes + PTRCALLEE, 1, 2, 3, 4, 5, ref)
r = ch.run(sc2)
gotptr, gotval = struct.unpack("<2Q", p.memory.rpm(fakes + META, 0x10))
ok = gotptr == TARGET_VALUE and gotval == TARGET_VALUE and r["status"] == 0
print("read_ptr deref into a stack arg:", "GREEN" if ok else
      f"RED ptr={gotptr:#x} val={gotval:#x} want={TARGET_VALUE:#x}")
fails += [] if ok else ["ptr"]

try:
    ch.run(sc2)
    print("second send: NOT refused  <-- BAD")
    fails.append("resend")
except S.ScriptError as exc:
    print("re-send refused:", exc)

print("ABI SUITE:", "GREEN" if not fails else f"RED {fails}")
proc.kill()
