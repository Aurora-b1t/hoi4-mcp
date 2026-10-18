"""Isolated check: does a read_ptr Ref arrive as the buffer address in rcx?"""
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
FAKE, META, PTRCELL = 0x000, 0x600, 0x900
MAGIC = 0xFEEDFACE12345678
TARGET_VALUE = 0xDEADBEEFCAFEF00D
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


def asm(src):
    code, _ = _KS.asm(src)
    return bytes(code)


def callee(base):
    return asm(f"""
    movabs rax, {base + META:#x}
    mov qword ptr [rax + 0x00], rcx
    mov qword ptr [rax + 0x08], rdx
    mov qword ptr [rax + 0x10], r8
    mov qword ptr [rax + 0x18], r9
    movabs rax, {MAGIC:#x}
    ret
    """)


d = tempfile.mkdtemp(prefix="rp_")
proc = subprocess.Popen([sys.executable, str(HERE / "victim.py"), d],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
state = Path(d) / f"{proc.pid}.json"
for _ in range(80):
    if state.exists():
        break
    time.sleep(0.1)
time.sleep(0.6)
p = AttachedProcess(proc.pid)
fakes = w.virtual_alloc_ex(p.handle, 0x1000, PAGE_EXECUTE_READWRITE)
w.write_process_memory(p.handle, fakes + FAKE, callee(fakes))
w.write_process_memory(p.handle, fakes + PTRCELL, struct.pack("<Q", TARGET_VALUE))

ch = S.ScriptChannel(p, timeout=3.0)
sc = S.Script(allow_calls={(fakes, fakes + 0x1000)})
ref = sc.read_ptr(fakes + PTRCELL)
i = sc.call(fakes + FAKE, ref, 2, 3, 4)
print("ops:", [(o.code, hex(o.a0), hex(o.a1), o.a2 if isinstance(o.a2, int) else o.a2,
                o.a3, o.a4, o.a5) for o in sc.ops])
r = ch.run(sc)
got = struct.unpack("<4Q", p.memory.rpm(fakes + META, 0x20))
print("page =", hex(r["page"]), " expecting rcx =", hex(r["page"] + S.BUF_BASE))
print("callee: rcx=%#x rdx=%#x r8=%#x r9=%#x" % got)
print("read_ptr local:", r["local"].get(ref.op, b"").hex())
proc.kill()
