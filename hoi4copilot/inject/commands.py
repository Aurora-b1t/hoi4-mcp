"""Player-command layer over the injected remote call: the same path a mouse
click takes (build CCommand -> CSession queue -> Post). Every send() is
exactly TWO remote calls (operator new + Post) plus one memory write of the
pre-built object; three sends in a row are three separate suspend-resume
cycles, never a loop inside one frozen window.

Object blobs replicate the ctor output byte-for-byte (BASE_INIT + fields +
zero padding), so no constructor call is needed.
"""
from __future__ import annotations

import struct

from ..process.attach import Game
from . import tables as T
from .call import RemoteCaller, CallError


class CommandLayer:
    def __init__(self, game: Game, timeout: float = 10.0):
        self.g = game
        self.p = game.proc
        self.m = self.p.memory
        self.rc = RemoteCaller(self.p, timeout=timeout)
        self._apc = None
        self._vm = None
        self._resolve()

    # -- identity-checked object resolution -----------------------------------
    def _resolve(self) -> None:
        base = self.p.base

        def expect(slot_rva: int, vft_rva: int, name: str) -> int:
            ptr = self.m.u64(base + slot_rva)
            if not ptr:
                raise CallError(f"{name}: global slot {slot_rva:#x} is NULL "
                                "(not inside a session?)")
            vft = self.m.u64(ptr)
            if vft - base != vft_rva:
                raise CallError(f"{name}: vftable rva {vft - base:#x} != "
                                f"expected {vft_rva:#x} — offset table is "
                                "stale for this game build; refusing to inject")
            return ptr

        self.gamestate = expect(T.G_GAMESTATE, T.VFT_GAMESTATE, "gamestate")
        self.gameapp = expect(T.G_GAMEAPP, T.VFT_GAMEAPP, "gameapplication")
        self.queue = self.m.u64(self.gameapp + T.GAMEAPP_QUEUE_OFF)
        if not self.queue:
            raise CallError("command queue is NULL (CGameApplication+0x380)")
        vft = self.m.u64(self.queue)
        if vft - base != T.VFT_QUEUE:
            raise CallError(f"queue object: vftable rva {vft - base:#x} != "
                            f"{T.VFT_QUEUE:#x} — refusing to inject")
        self.player_tag = self.m.u32(self.gamestate + T.GS_PLAYER_TAG_OFF)
        # idler paused byte lives on the idler instance, resolved lazily
        self._idler: int | None = None

    @property
    def idler(self) -> int | None:
        if self._idler is None:
            base = self.p.base
            ptr = self.m.u64(base + T.G_IDLER)
            if ptr and self.m.u64(ptr) - base == T.VFT_IDLER:
                self._idler = ptr
        return self._idler

    def is_paused(self) -> bool | None:
        if not self.idler:
            return None
        return bool(self.m.u8(self.idler + T.IDLER_PAUSED_OFF))

    def queue_gate_open(self) -> bool:
        """queue+0x795 != 0 => Post(force=0) enqueues locally (like a click)."""
        return self.m.u8(self.queue + T.QUEUE_IS_HOST_OFF) != 0

    def send_fused(self, name: str, **fields) -> dict:
        """The whole send (operator new + blob + Post) inside ONE freeze window
        on a real game thread — the TLS-correct channel, never an injection
        loop. Retired as the product path on 23 日 (it suspends every thread);
        kept for the research fallback."""
        spec = T.COMMANDS[name]
        blob = self.build_blob(spec, fields)
        cmd, posted = self.rc.hijack_fused(
            self.p.base + T.FN_OPERATOR_NEW, self.p.base + T.FN_POST,
            self.queue, blob, spec["size"], name)
        return {"command": name, "cmd": hex(cmd), "posted": bool(posted)}

    # -- APC channel (23 日): the product path --------------------------------
    @property
    def apc(self):
        if self._apc is None:
            from .apc import ApcChannel
            self._apc = ApcChannel(self.p)
        return self._apc

    @property
    def script(self):
        """write v3.1: the micro-VM channel (remote calls, raw writes, and
        ctor-faithful object construction)."""
        if self._vm is None:
            from .script import ScriptChannel
            self._vm = ScriptChannel(self.p)
        return self._vm

    def send_apc(self, name: str, **fields) -> dict:
        """Post a command from an EXISTING game thread via a special user APC
        (QueueUserAPC2): no thread is suspended and none is created, so the
        payload runs in that thread's own TLS context and the game's queue sees
        exactly what a mouse click produces. Queue slot is single-use (atomic
        claim), arena persists for the life of the process.

        Refuses specs whose blob layout cannot reproduce the ctor's writes
        (24 日: an unverified layout killed a game process). Use
        send_ctor_apc() for those."""
        spec = T.COMMANDS[name]
        if not spec.get("verified") or not spec.get("blob_ok"):
            raise CallError(
                f"{name}: the hand-built blob path is disabled for this command "
                f"(verified={spec.get('verified')}, blob_ok={spec.get('blob_ok')}) — "
                f"the ctor writes fields the blob cannot reproduce. Use "
                f"send_ctor_apc() / hoi4_inject_post, or re-verify with "
                f"research/command_spec_hunt.py + hoi4copilot.inject.specverify.")
        blob = self.build_blob(spec, fields)
        r = self.apc.run(self.p.base + T.FN_OPERATOR_NEW, self.p.base + T.FN_POST,
                         self.queue, spec["size"], blob)
        out = {"command": name, "via": "apc",
               "posted": bool(r.get("posted")),
               "cmd": hex(r["cmd"]) if r.get("cmd") else None,
               "ran_on": r.get("tid"), "thread_kind": r.get("kind"),
               "latency_ms": round(r["latency"] * 1000) if r.get("latency") else None,
               "job_intact": r.get("job_intact")}
        if r.get("job_intact") is False:
            out["warning"] = ("the job block changed while the payload ran: the "
                              "callee walked over its own job (stack collision) "
                              "— treat this send's outcome as untrusted")
        if not r.get("done"):
            out["timeout"] = True
            out["note"] = ("job queued but no game thread reached it inside the "
                           "window; it is still pending (single-use claim makes "
                           "a late delivery harmless)")
        return out

    # -- write v3.1: ctor-faithful posting (24 日) -----------------------------
    def send_ctor_apc(self, name: str, *args, force: int = 0) -> dict:
        """Build the command the way the GAME builds it: one APC delivery runs
        `operator new(size)` -> the real constructor -> `Post(queue, obj, force)`.

        Why this replaced hand-built blobs: a blob can reproduce the vtable and
        still get the fields wrong (24 日, SetNationalFocus: the layout in the
        table belonged to another class, and the game AV'd while describing the
        command). The constructor is the only authority on the layout, and it
        also runs whatever bookkeeping the class does.
        """
        spec = T.COMMANDS[name]
        if not spec.get("ctor"):
            raise CallError(f"{name}: no verified constructor RVA in tables.py; "
                            "find it with research/command_spec_hunt.py first")
        from .script import Script
        sc = Script(allow_calls={(self.p.base, self.p.base + self.p.image_size)})
        sc.alloc_ctor(self.p.base + T.FN_OPERATOR_NEW, self.p.base + spec["ctor"],
                      spec["size"], *args)
        # Post(queue, cmd, force): the object goes in rdx (slot 1) — an earlier
        # version put it in rcx and killed the game inside Post (24 日).
        sc.call_obj(self.p.base + T.FN_POST, 1, self.queue, force)
        r = self.script.run(sc)
        out = {"command": name, "via": "ctor-apc",
               "posted": bool(r["results"][1]) if len(r.get("results") or []) > 1 else None,
               "cmd": hex(r["results"][0]) if r.get("results") else None,
               "ran_on": r.get("tid"), "thread_kind": r.get("kind"),
               "latency_ms": round(r["latency"] * 1000) if r.get("latency") else None,
               "status": r.get("status"), "job_intact": r.get("job_intact"),
               "ctor": hex(self.p.base + spec["ctor"])}
        if r.get("status") == 2:
            out["fault"] = (f"the payload faulted (rip={r.get('fault_rip'):#x}, "
                            f"code={r.get('fault_code'):#x}) and the crash shield "
                            f"recovered the thread")
        if r.get("dead"):
            out["dead"] = True
        if not r.get("done"):
            out["timeout"] = True
        return out

    def speed_step_apc(self, delta: int) -> dict:
        """Speed step through the ctor path: new + the game's own constructor +
        Post, one APC per step (the ctor path is the default now — it is the
        only one that cannot get the field layout wrong)."""
        kind = "IncreaseGameSpeed" if delta > 0 else "DecreaseGameSpeed"
        return {"steps": abs(delta), "via": "ctor-apc",
                "results": [self.send_ctor_apc(kind) for _ in range(abs(delta))]}

    def speed_step_blob(self, delta: int) -> dict:
        """Legacy blob path (IncreaseGameSpeed only — its ctor's writes are
        fully covered by BASE_INIT)."""
        kind = "IncreaseGameSpeed" if delta > 0 else "DecreaseGameSpeed"
        return {"steps": abs(delta), "via": "apc",
                "results": [self.send_apc(kind) for _ in range(abs(delta))]}

    def post_focus_apc(self, focus_id: int, tag: int | None = None,
                       mode: int = 0) -> dict:
        """RETIRED path (kept for the record): hand-built SetNationalFocus blob
        with focus_id@0x2C / mode@0x30. 24 日 proved that layout belongs to a
        different class — it AV'd the game. Use post_focus_ctor() instead."""
        raise CallError("post_focus_apc is retired: the 0x2C/0x30 layout was a "
                        "misattributed ctor and killed the game on 24 日; use "
                        "post_focus_ctor(focus_obj)")

    def post_focus_ctor(self, focus_obj: int, tag_addr: int | None = None,
                        force: int = 0) -> dict:
        """SetNationalFocus the game's way: ctor(this, &tag, CNationalFocus*).

        `focus_obj` is the live CNationalFocus instance address (inject/
        focus_ids.py returns ids; the scan also yields the object addresses).
        `tag_addr` defaults to gamestate+0x520 — the very address the UI's own
        call site passes as &tag.
        """
        if tag_addr is None:
            tag_addr = self.gamestate + T.GS_PLAYER_TAG_OFF
        return self.send_ctor_apc("SetNationalFocus", tag_addr, focus_obj,
                                  force=force)

    def drop_focus_ctor(self, tag_addr: int | None = None, force: int = 0) -> dict:
        """DropCurrentNationalFocusCommand the game's way (25 日 spec): its ctor is
        `ctor(this, rdx=&tag)` — one argument, the same &tag shape the focus
        picker uses. The game refuses (Post returns 0) when no focus is running,
        which is CanExecute speaking, not a channel failure.
        """
        if tag_addr is None:
            tag_addr = self.gamestate + T.GS_PLAYER_TAG_OFF
        return self.send_ctor_apc("DropCurrentNationalFocus", tag_addr, force=force)

    def post_research(self, tech_obj: int, slot: int, *, tag: int | None = None,
                      flag: int = 0, force: int = 0) -> dict:
        """SetResearch (26 日 spec) — queued through the blob path on purpose.

        The ctor takes a FIFTH argument (a bool the game stages at [rsp+0x20],
        stored at +0x3C) and the VM payload deliberately has no stack-argument
        path (25 日 "血案 4"), so the ctor path could only pass garbage there.
        The blob reproduces all ten of the ctor's writes -- specverify reports
        full field coverage -- including that bool, which is written explicitly.

        `tech_obj` is a LIVE CTechnology-shaped object (the caller resolves it;
        the game reads its 1-based id at +0x38 and looks up the country's own
        instance through tech_manager[+0x88][id-1]).  `slot` is the 0-based
        research slot; CanExecute rejects slot >= research-slot count.
        """
        if tag is None:
            tag = self.player_tag
        return self.send_apc("SetResearch", tag=tag, tech=tech_obj, slot=slot,
                             flag=flag)

    def bypass_focus_ctor(self, focus_obj: int, tag_addr: int | None = None,
                          force: int = 0) -> dict:
        """BypassNationalFocusCommand the game's way (25 日 spec):
        `ctor(this, rdx=&tag, r8=CNationalFocus*)` — the same two live arguments
        SetNationalFocus takes, so `hoi4_focus_ids()`/the live instance scan
        supplies `focus_obj`.
        """
        if tag_addr is None:
            tag_addr = self.gamestate + T.GS_PLAYER_TAG_OFF
        return self.send_ctor_apc("BypassNationalFocus", tag_addr, focus_obj,
                                  force=force)

    def speed_step_fused(self, delta: int) -> dict:
        name_kind = "IncreaseGameSpeed" if delta > 0 else "DecreaseGameSpeed"
        out = []
        for _ in range(abs(delta)):
            out.append(self.send_fused(name_kind))
        return {"steps": abs(delta), "results": out}

    # -- command build/post ---------------------------------------------------
    def alloc(self, size: int) -> int:
        return self.rc.call(self.p.base + T.FN_OPERATOR_NEW, (size,),
                            what="operator new")

    def build_blob(self, spec: dict, fields: dict) -> bytes:
        size = spec["size"]
        blob = bytearray(size)                       # zero padding everywhere
        struct.pack_into("<Q", blob, 0, self.p.base + spec["vt"])
        for off, fmt, val in T.BASE_INIT:
            struct.pack_into(fmt, blob, off, val)
        known = {f[2]: f for f in spec["fields"]}
        for k, v in fields.items():
            if k not in known:
                raise KeyError(f"unknown field {k!r}; valid: {sorted(known)}")
            off, fmt, _ = known[k]
            struct.pack_into(fmt, blob, off, int(v))
        return bytes(blob)

    def post(self, cmd_ptr: int, force: int = 0) -> bool:
        r = self.rc.call(self.p.base + T.FN_POST, (self.queue, cmd_ptr, force),
                         what="CSession Post")
        return bool(r & 0xFF)

    def send(self, name: str, force: int = 0, **fields) -> dict:
        spec = T.COMMANDS[name]
        ptr = self.alloc(spec["size"])
        if not ptr:
            raise CallError("operator new returned NULL")
        blob = self.build_blob(spec, fields)
        from ..process import win32ext as w32
        w32.write_process_memory(self.p.handle, ptr, blob)
        ok = self.post(ptr, force)
        return {"command": name, "ptr": hex(ptr), "posted": ok,
                "size": spec["size"], "queue": hex(self.queue)}

    def speed_step(self, delta: int) -> dict:
        """Speed change via the self-contained +/- commands (0..4 internal)."""
        name = "IncreaseGameSpeed" if delta > 0 else "DecreaseGameSpeed"
        out = []
        for _ in range(abs(delta)):
            out.append(self.send(name))
        return {"steps": abs(delta), "results": out}
