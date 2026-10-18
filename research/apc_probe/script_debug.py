"""script_debug.py — one op at a time against a stand-in, with full forensics.

Prints, per op: the op record as the payload sees it, the job result
(status / fault_rip / fault_code / last_rax), and the target bytes afterwards.

Usage: python research/apc_probe/script_debug.py
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from hoi4copilot.inject import script as S                        # noqa: E402
from hoi4copilot.process import win32ext as w                     # noqa: E402
from hoi4copilot.process.attach import AttachedProcess            # noqa: E402

HERE = Path(__file__).resolve().parent
PAGE_EXECUTE_READWRITE = 0x40
SCRATCH = 0x400
FAKES_SIZE = 0x1000


def show(tag: str, ch, r: dict, target: int, n: int = 0x20) -> None:
    print(f"\n--- {tag} ---")
    print(f"  job: done={r.get('done')} claim={r.get('claim')} status={r.get('status')} "
          f"n_ops={r.get('n_ops')} last_rax={r.get('last_rax'):#x} "
          f"fault_rip={r.get('fault_rip'):#x} fault_code={r.get('fault_code'):#x} "
          f"job_intact={r.get('job_intact')} dead={r.get('dead', False)}")
    try:
        ops = ch.m.rpm(r["page"] + S.D_OPS, 0x40 * 4)
        for k in range(4):
            rec = struct.unpack_from("<7Q", ops, k * 0x40)
            if rec[0] == 0 and k:
                break
            print(f"  op{k}: code={rec[0]} a0={rec[1]:#x} a1={rec[2]:#x} a2={rec[3]:#x} "
                  f"a3={rec[4]:#x} a4={rec[5]:#x} res={rec[6]:#x}")
        print(f"  target: {ch.m.rpm(target, n).hex()}")
    except OSError as exc:
        print("  readback failed:", exc)


def main() -> int:
    sd = tempfile.mkdtemp(prefix="dbg_")
    vic = subprocess.Popen([sys.executable, str(HERE / "victim.py"), sd],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = Path(sd) / f"{vic.pid}.json"
    for _ in range(80):
        if state.exists():
            break
        time.sleep(0.1)
    time.sleep(0.5)
    json.loads(state.read_text())
    p = AttachedProcess(vic.pid)
    fakes = w.virtual_alloc_ex(p.handle, FAKES_SIZE, PAGE_EXECUTE_READWRITE)
    w.write_process_memory(p.handle, fakes, b"\xcc" * FAKES_SIZE)
    print(f"victim pid={vic.pid} fakes={fakes:#x} scratch={fakes + SCRATCH:#x}")

    ch = S.ScriptChannel(p, timeout=3.0)
    ch.install_shield()

    blob = bytes(range(16))

    sc = S.Script()
    sc.write_raw(fakes + SCRATCH, 0xBEEF, 2)
    r = ch.run(sc)
    show("WRITE_RAW size=2 @ +0", ch, r, fakes + SCRATCH, 8)

    sc = S.Script()
    sc.write_raw(fakes + SCRATCH + 0x10, 0xDEADBEEF, 4)
    r = ch.run(sc)
    show("WRITE_RAW size=4 @ +0x10", ch, r, fakes + SCRATCH, 0x20)

    sc = S.Script()
    sc.write_raw(fakes + SCRATCH + 0x20, 0x0123456789ABCDEF, 8)
    r = ch.run(sc)
    show("WRITE_RAW size=8 @ +0x20", ch, r, fakes + SCRATCH, 0x30)

    sc = S.Script()
    sc.write(fakes + SCRATCH + 0x40, blob)
    r = ch.run(sc)
    show("WRITE(memcpy) 16B @ +0x40", ch, r, fakes + SCRATCH + 0x38, 0x30)

    sc = S.Script()
    sc.memset(fakes + SCRATCH + 0x80, 0x5A, 16)
    r = ch.run(sc)
    show("MEMSET 16B @ +0x80", ch, r, fakes + SCRATCH + 0x78, 0x28)

    sc = S.Script()
    j = len(sc.ops)
    sc.read(fakes + SCRATCH, 0x10)
    r = ch.run(sc)
    show("READ 16B from +0", ch, r, fakes + SCRATCH, 0x10)
    print("  local buffers:", {k: v.hex() for k, v in r.get("local", {}).items()}, "op", j)

    sc = S.Script()
    for i, (size, value) in enumerate(((1, 0xAB), (2, 0xBEEF), (4, 0xDEADBEEF),
                                       (8, 0x0123456789ABCDEF))):
        sc.write_raw(fakes + SCRATCH + 0x100 + i * 8, value, size)
    r = ch.run(sc)
    show("WRITE_RAW x4 (one script)", ch, r, fakes + SCRATCH + 0x100, 0x20)

    vic.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
