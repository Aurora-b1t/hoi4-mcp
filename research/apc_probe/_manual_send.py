"""Run the page staging manually, verify bytes, then dispatch by hand."""
from __future__ import annotations
import struct, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import capstone
import keystone
from hoi4_mcp.inject import script as S
from hoi4_mcp.process import win32ext as w
from hoi4_mcp.process.attach import AttachedProcess

PAGE_EXECUTE_READWRITE = 0x40
FAKE_REC, META = 0x000, 0x600
MAGIC = 0xFEEDFACE12345678
_KS = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
A1, A2, A3, A4, A5, A6 = (0xA1A1A1A1A1A1A1A1, 0xB2B2B2B2B2B2B2B2,
                          0xC3C3C3C3C3C3C3C3, 0xD4D4D4D4D4D4D4D4,
                          0xE5E5E5E5E5E5E5E5, 0xF6F6F6F6F6F6F6F6)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def asm(src):
    code, _ = _KS.asm(src)
    return bytes(code)


def fake(base):
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


d = tempfile.mkdtemp(prefix="man_")
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
w.write_process_memory(p.handle, fakes + FAKE_REC, fake(fakes))
ch = S.ScriptChannel(p, timeout=3.0)
sc = S.Script(allow_calls={(fakes, fakes + 0x1000)})
sc.call(fakes + FAKE_REC, A1, A2, A3, A4, A5, A6)
page = ch._next_page()
slot = ch._next_slot()
raw_ops, blocks = ch._resolve_refs(sc, page)
w.write_process_memory(ch.h, page, struct.pack("<4Q", S.MAGIC, len(sc.ops), 0, 0))
w.write_process_memory(ch.h, page + S.D_OPS, raw_ops)
for off, vals in blocks.items():
    w.write_process_memory(ch.h, page + off, struct.pack("<%dQ" % len(vals), *vals))
print("page", hex(page), "slot", hex(slot))
print("record bytes:", p.memory.rpm(page + S.D_OPS, 0x40).hex())
print("python ops  :", [hex(x) for x in (sc.ops[0].code, sc.ops[0].a0, sc.ops[0].a1,
                                          sc.ops[0].a2, sc.ops[0].a3, sc.ops[0].a4,
                                          sc.ops[0].a5)])
print("blocks:", blocks)
live = p.memory.rpm(ch.code + 0xd1, 0x40)
print("op_call bytes live:", live.hex())
print("op_call bytes src :", S.PAYLOAD[0xd1:0xd1 + 0x40].hex())
for ins in md.disasm(live, ch.code + 0xd1):
    print(f"  {ins.address - ch.code:04x}: {ins.mnemonic} {ins.op_str}")
proc.kill()
