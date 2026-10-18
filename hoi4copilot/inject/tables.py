"""Pinned offset/command tables for HOI4 1.19.3.0 (Windows, hoi4.exe 55.8MB).

All RVAs are relative to the hoi4.exe module base. Recovered by static
disassembly (research/win_disasm.py, research/win_callers.py) on 21 日, the
first session of the v2 inject track. Everything here was confirmed from the
game's own UI code paths:

  queue = [G_GAMEAPP + 0x380]                       (CSession*)
  Post(queue, cmd, force) = FN_POST                 (UI tail-calls it)
  cmd   = FN_OPERATOR_NEW(size)                     (UI calls it before ctor)
  blob  = vptr + BASE_INIT + fields                 (ctor output, rebuilt)

Command vtable layout (Windows): +0x60/+0x80 are the Post-gate predicates
(mostly `xor al,al; ret` stubs), +0x58/+0xB8 logging/describe, +0x00 the
scalar-deleting dtor (called by Post's refuse path with edx=1).
Version drift => every field here may be invalid; gate on version.
"""

from __future__ import annotations

GAME_VERSION = "1.19.3.0"

# --- static globals (image slots holding live singleton pointers) -----------
G_GAMESTATE = 0x0332F260        # CCurrentGameState*  (player tag @ +0x520)
G_GAMESTATE_ALT = 0x0333DA08    # second reference to the same pointer
G_IDLER = 0x0332F698            # CInGameIdler*
G_IDLER_ALT = 0x0332F6A0
G_GAMEAPP = 0x03452450          # CGameApplication*
G_QUEUE = 0x03451DA8            # CSession* (the command queue holder)

# --- functions ---------------------------------------------------------------
FN_POST = 0x02250B00            # Post(CSession* queue, CCommand* cmd, u8 force)
FN_OPERATOR_NEW = 0x021C9AF0    # operator new(size_t)  (UI allocation site)

# --- live object chains ------------------------------------------------------
GAMEAPP_QUEUE_OFF = 0x380       # queue = [CGameApplication + 0x380]
GS_PLAYER_TAG_OFF = 0x520       # int32 tag used by ctor calls (1 = GER)
IDLER_PAUSED_OFF = 0x6C1        # u8 1 = paused (Linux IDLER_PAUSED same; live-verified 21 日)
IDLER_PAUSED_MIRROR = 0x6C2     # u8 copy (0x6C3 on Linux; drifts per platform)
QUEUE_IS_HOST_OFF = 0x795       # u8 1 = Post enqueues locally (SP host)
QUEUE_SENDER_OFF = 0xA4         # u32 stamped into cmd+0xC by the enqueue path
CMD_QUEUE_CONTAINER_OFF = 0x58  # [CSession+0x58] -> command list container
FOCUS_VFT = 0x02739C08          # CNationalFocus primary vftable (RVA)

# vftable RVAs for identity checks (refuse to operate if these don't match)
VFT_GAMESTATE = 0x02721158      # .?AVCCurrentGameState@@
VFT_IDLER = 0x02968FF0          # .?AVCInGameIdler@@ primary vftable
VFT_GAMEAPP = 0x027182E0        # .?AVCGameApplication@@
VFT_QUEUE = 0x02B3E9D8          # .?AVCSession@@

# --- command base initialisation (what every ctor writes; MSVC x64) ---------
# [+0x00]=vptr  [+0x08]=0(u8)  [+0x0C]=-1(i32)  [+0x10]=0(i32)
# [+0x14]=0xFFFF0000 (u16+u16 pair)  [+0x18]=0(u16)  [+0x1C]=0(qword)
BASE_INIT = [
    (0x08, "<B", 0),
    (0x0C, "<i", -1),
    (0x10, "<i", 0),
    (0x14, "<I", 0xFFFF0000),
    (0x18, "<H", 0),
    (0x1C, "<Q", 0),
]

# --- command specs (name -> dict) --------------------------------------------
# fields: [(offset, struct fmt, semantic name)]  — sizes verified from ctor
# writes and UI `operator new` immediates.
#
# `verified` is a *safety* flag: True only when the spec was re-derived from the
# binary (RTTI vftable + the ctor that installs it + the UI's operator new size)
# with research/command_spec_hunt.py AND, for the layout, the ctor's own field
# writes. 24 日 cost a game process to learn why: a spec whose ctor had been
# misattributed (0x1146E60 is CSetFuelPriorityCommand's ctor) produced a blob
# with the right vtable and the wrong fields, and the game AV'd while describing
# the command. The write layer refuses unverified specs.
#
# `ctor` is the *function entry* (not the lea site) that installs the vftable;
# send_ctor_apc() calls it so the object is built by the game, not by us.
COMMANDS = {
    "IncreaseGameSpeed": dict(
        vt=0x02977040, size=0x28, fields=[], ctor=0x0F05820, verified=True,
        blob_ok=True),
    "DecreaseGameSpeed": dict(
        # 24 日 correction: the ctor initialises a std::string member at +0x28
        # (movups zero @+0x28, size @+0x38, cap=0xf @+0x40), so the object is
        # 0x48 — the old 0x40 came from a misread UI site. Use the ctor path:
        # a blob cannot reproduce that member.
        vt=0x02977108, size=0x48, fields=[], ctor=0x0F05750, verified=True,
        blob_ok=False),
    "SetGameSpeed": dict(
        # object is 0x30 (0x28 was wrong: the ctor writes a dword at +0x28).
        # EMPTY object: the speed value travels via a pending-setter call, not
        # in the command body. Prefer Increase/Decrease for inject.
        vt=0x029771D0, size=0x30, fields=[], ctor=0x0F05850, verified=True,
        blob_ok=False),
    "SetNationalFocus": dict(
        vt=0x02996458, size=0x38, ctor=0x01146F70, verified=True, blob_ok=True,
        # ctor(rcx=this, rdx=&tag(int32), r8=CNationalFocus*):
        #   mov eax,[rdx]; mov [rcx+0x28],eax ; mov [rcx+0x30],r8
        # +0x2C is never written by the ctor (not a field); the UI passes
        # gamestate+0x520 as &tag, so no local staging is needed.
        fields=[(0x28, "<i", "tag"),
                (0x30, "<Q", "focus")],   # focus = pointer to the focus object
        note="the 21 日 layout (focus_id@0x2C, mode@0x30) belonged to a "
             "different class's ctor and killed the game on 24 日"),
    "PauseGame": dict(
        # class is CPauseGame (RTTI .?AVCPauseGame@@, same vftable); its ctor
        # has NOT been recovered yet, so the old flag_a/flag_b guess is gone.
        vt=0x0296A560, size=0x50, fields=[], ctor=None, verified=False,
        blob_ok=False,
        note="spec unverified: use the UI pause button until the ctor is found"),
    "DropCurrentNationalFocus": dict(
        # 25 日: research/command_spec_hunt.py --full
        #   ctor(this, rdx=&tag): mov eax,[rdx]; mov [rcx+0x28],eax
        # (the same shape as SetNationalFocus: the tag travels as a *pointer to*
        # the int32, which is why a live call passes gamestate+0x520).
        # size 0x30 is the UI's own `mov ecx,0x30; call operator new` immediate.
        vt=0x02996520, size=0x30, ctor=0x01144800, verified=True, blob_ok=True,
        fields=[(0x28, "<i", "tag")],
        note="one argument: the tag (via &tag). Drops whatever focus is current — "
             "the game itself refuses when nothing is selected (Post returns 0)"),
    "SetResearch": dict(
        # 26 日: research/command_spec_hunt.py CSetResearchCommand --full
        #   ctor(this, rdx=&tag, r8=CTechnology*, r9d=slot, [rsp+0x20]=bool):
        #     mov eax,[rdx]                 ; tag VALUE (the append is &tag)
        #     mov [rcx+0x28],eax
        #     movzx eax, byte ptr [rsp+0x28] ; 5th argument, from the STACK
        #     mov [rcx+0x3c],al
        #     mov [rcx+0x30],r8             ; tech object pointer
        #     mov [rcx+0x38],r9d            ; research slot index (0-based)
        # UI call sites: 0x2ABB6B ({tech,slot,flag} array replay path) and
        # 0x13DB4AD (AI planner) — both stage the bool at [rsp+0x20].
        # The 5th argument is why this one posts through the BLOB path: the VM
        # payload has no stack-argument path (25 日, 血案 4), while the blob can
        # write +0x3C explicitly.  specverify: all ten ctor writes covered.
        vt=0x02994F40, size=0x40, ctor=0x011479C0, verified=True, blob_ok=True,
        fields=[(0x28, "<i", "tag"), (0x30, "<Q", "tech"),
                (0x38, "<i", "slot"), (0x3c, "<B", "flag")],
        note="CanExecute (vtable+0x48) decodes as: slot >= 0 and slot < "
             "tech_manager[+0xAC] (research slot count), tag > 0, then "
             "0xED8F00(manager, tech, 0) == 1. `tech` must be a live "
             "CTechnology-shaped object carrying a 1-based id at +0x38; the "
             "manager cache is country[+0xF60] -> CTechnologyStatus, whose "
             "[+0x88] array (count at [+0x94]) is indexed by id-1. Resolving a "
             "name -> object is still open (see research/NOTES.md 26 日)."),
    "BypassNationalFocus": dict(
        # 25 日: research/command_spec_hunt.py --full
        #   ctor(this, rdx=&tag, r8=CNationalFocus*):
        #     mov eax,[rdx]; mov [rcx+0x28],eax ; mov [rcx+0x30],r8
        # 参考表 (Linux) 同一行: args=2 fields=0x24:deref,0x28:ptr —— 逐条对上
        # (偏移 +4/+8 是本平台与 Linux 的已知位移)。
        # size 0x38 = UI `mov ecx,0x38` 立即数。
        vt=0x029965E8, size=0x38, ctor=0x01143AD0, verified=True, blob_ok=True,
        fields=[(0x28, "<i", "tag"), (0x30, "<Q", "focus")],
        note="two arguments: &tag and the CNationalFocus* to bypass. The focus "
             "object must be resolved live (hoi4_focus_ids / live scan), which is "
             "what the read_ptr op is for"),
}

#: every field of the command base that a ctor writes, with the value the
#: hand-built blob puts there (see BASE_INIT) — kept next to COMMANDS so both
#: the writer and the verifier read the same source of truth.
BLOB_SAFE_FLAG = "blob_ok"


def va(base: int, rva: int) -> int:
    return base + rva
