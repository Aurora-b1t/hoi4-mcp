"""Differential check of op 1 (register + stack arguments) against a victim."""
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
FAKE_REC, META = 0x000, 0x600
MAGIC = 0xFEEDFACE12345678
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
SENT = (0xA1A1A1A1A1A1A1A1, 0xB2B2B2B2B2B2B2B2, 0xC3C3C3C3C3C3C3C3,
        0xD4D4D4D4D4D4D4D4, 0xE5E5E5E5E5E5E5E5, 0xF6F6F6F6F6F6F6F6)
NAMES = {v: f"arg{i + 1}" for i, v in enumerate(SENT)}


def asm(src):
    code, _ = _KS.asm(src)
    return bytes(code)


def fake_rec(base):
    """Records 4 register arguments and the two stack arguments."""
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


d = tempfile.mkdtemp(prefix="dbg5_")
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
w.write_process_memory(p.handle, fakes + FAKE_REC, fake_rec(fakes))

ch = S.ScriptChannel(p, timeout=3.0)
sc = S.Script(allow_calls={(fakes, fakes + 0x1000)})
sc.call(fakes + FAKE_REC, *SENT)
r = ch.run(sc)
print("done:", r["done"], "status:", r["status"], "job_intact:", r["job_intact"])
got = struct.unpack("<6Q", p.memory.rpm(fakes + META, 0x30))
probe = struct.unpack("<5Q", p.memory.rpm(r["slot"] + 0x100, 0x28))
print("call-site probe: rcx=%s rdx=%s r8=%s r9=%s r13=%s" % tuple(
    NAMES.get(v, hex(v)) for v in probe))
probe2 = struct.unpack("<2Q", p.memory.rpm(r["slot"] + 0x130, 0x10))
print("raw a1 =", hex(probe2[0]), " raw count(r10) =", hex(probe2[1]))
probe3 = struct.unpack("<1Q", p.memory.rpm(r["slot"] + 0x140, 8))[0]
print("[r13+0x18] =", NAMES.get(probe3, hex(probe3)), " (should be a2)")
print("   page =", hex(r["page"]), " page+0x40 =", hex(r["page"] + 0x40))
rec = struct.unpack("<8Q", p.memory.rpm(r["page"] + S.D_OPS, 0x40))
want = SENT
labels = ("rcx", "rdx", "r8", "r9", "stack[0]", "stack[1]")
ok = True
for lab, g, wv in zip(labels, got, want):
    good = g == wv
    ok &= good
    print(f"  {lab:9s} {'ok ' if good else 'BAD'} {NAMES.get(g, hex(g))}")
print("OP-1 8-ARG ABI:", "GREEN" if ok else "RED")
# the same Script must refuse a second send
try:
    ch.run(sc)
    print("second send: NOT refused  <-- BAD")
except S.ScriptError as exc:
    print("second send refused:", exc)
proc.kill()
