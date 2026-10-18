"""MCP server exposing the hoi4-mcp tool surface.

Read tools observe the live game process/state; action tools act through the
in-game UI (player-equivalent input: real clicks on the running client). The
injection-based command path (CCommandQueue::Post) stays a gated enhancement;
every tool here is safe against game-legal checks by construction.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import numpy as np

from mcp.server.mcpserver import MCPServer

from . import SUPPORTED_VERSION, config
from .process.attach import Game
from .tools import screenshot as _shot
from .ui.session import SessionDriver
from . import safety

# mean RGB channel delta above which hoi4_replay refuses to run (the
# current screen state no longer matches the recording's start frame)
REPLAY_DIFF_LIMIT = 8.0

mcp = MCPServer("hoi4", instructions=(
    "Hearts of Iron IV MCP server (hoi4-mcp). Observe via screenshots/state, decide, then act "
    "through the player-equivalent UI controls. Keep the game PAUSED while "
    "reading to snapshot a stable state. All coordinates are client-normalized "
    "(0..1)."
))

_game: Game | None = None
_game_lock = threading.Lock()


def resolve_game() -> Game:
    global _game
    with _game_lock:
        if _game is None or not _game.is_alive():
            _game = Game()
        g = _game
    return g


def resolve_driver() -> SessionDriver:
    return SessionDriver(resolve_game())


# ---------------------------------------------------------- write-layer guard
def _write_refusal() -> str | None:
    """Common gate for every action tool: read_only barrier + MP covenant.

    Hard MP evidence (game.log '[[ Launching MULTIPLAYER-game ]]' still the
    most recent session start, or a save asserting multiplayer=yes) refuses
    writes. HOI4_READ_ONLY=1 / HOI4_ALLOW_MP=1 are env switches evaluated at
    server startup (enforced again and again here, so a plain config mistake
    cannot make the tools quietly permissive)."""
    if config.READ_ONLY:
        return ("refused: read_only barrier (HOI4_READ_ONLY=1). Observation "
                "tools stay available; restart the server without the flag "
                "to re-enable actions.")
    rep = safety.guard(pid=_game.proc.pid if _game else None,
                       save_path=_latest_save_path())
    if rep.verdict == "multiplayer" and not config.ALLOW_MP:
        return ("refused: multiplayer session detected "
                f"({'; '.join(rep.reasons) or rep.as_line()}). This toolset is "
                "single-player by covenant — see README. HOI4_ALLOW_MP=1 is "
                "the developer override.")
    return None


def _latest_save_path() -> Path | None:
    try:
        cands = sorted(SAVE_SG.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime)
        return cands[0] if cands else None
    except Exception:
        return None



SHOTS_DIR = config._PROJECT_ROOT / "shots"


def _save_shot(arr, tag: str) -> str:
    SHOTS_DIR.mkdir(exist_ok=True)
    path = SHOTS_DIR / f"{tag}_{int(time.time() * 1000) % 10**10}.png"
    _shot.save_png(arr, path)
    return str(path)


def _crop(arr, x0: float, y0: float, x1: float, y1: float):
    h, w = arr.shape[:2]
    return arr[int(y0 * h):int(y1 * h), int(x0 * w):int(x1 * w)]


def _err(exc: Exception) -> str:
    return f"error: {exc.__class__.__name__}: {exc}"


# ---------------------------------------------------------------- basic info
@mcp.tool()
def hoi4_game_info() -> str:
    """Process info, install/version, and whether tables match the running game."""
    try:
        p = resolve_game().proc
    except Exception as exc:
        return _err(exc)
    ok = p.version() == SUPPORTED_VERSION
    guard = safety.guard(pid=p.pid, save_path=_latest_save_path())
    return (
        f"pid={p.pid} base=0x{p.base:X} image=0x{p.image_size:X} "
        f"version={p.version()} tables_pinned={SUPPORTED_VERSION} compatible={ok} "
        f"install={p.install_dir}\n"
        f"guard: {guard.as_line()}"
        + (f" reasons: {'; '.join(guard.reasons)}" if guard.reasons else "")
        + f"\nbarriers: read_only={config.READ_ONLY} allow_mp={config.ALLOW_MP}"
    )


@mcp.tool()
def hoi4_instances() -> str:
    """Live RTTI instance counts (country/army/front/...). Costly: a full memory scan (~1-3 min)."""
    try:
        from .process import instances as inst
        from .rtti.msvc import RttiDatabase

        db = RttiDatabase.load(config.TABLES_DIR / "rtti.json")
        wanted = {
            ".?AVCCountry@@": "country",
            ".?AVCNationalFocusTree@@": "focus_tree",
            ".?AVCNationalFocusProgress@@": "focus_progress",
            ".?AVCIdea@@": "idea",
            ".?AVCState@@": "state",
            ".?AVCProvince@@": "province",
            ".?AVCArmy@@": "army",
            ".?AVCAirWing@@": "air_wing",
            ".?AVCShip@@": "ship",
            ".?AVCFront@@": "front",
            ".?AVCWar@@": "war",
            ".?AVCFaction@@": "faction",
            ".?AVCArmyLeader@@": "unit_leader",
        }
        rvas = {}
        for name, key in wanted.items():
            info = db.by_name.get(name)
            if info is not None:
                rvas[key] = list(info.vftable_rvas)
        counts = inst.count_watch(resolve_game().proc, rvas)
        return " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    except Exception as exc:
        return _err(exc)


# ---------------------------------------------------------------- read (visual)
@mcp.tool()
def hoi4_hud(kind: str = "full") -> str:
    """Capture the game window (kind: full | topbar | date | small) and return PNG path(s)."""
    try:
        d = resolve_driver()
        from hoi4_mcp.tools import screenshot as shot
        arr = shot.capture_smart(d.pid)
        if arr is None:
            return "error: capture failed"
        out = [_save_shot(arr, "full")]
        if kind in ("topbar", "date", "all"):
            out.append(_save_shot(_crop(arr, 0.0, 0.03, 1.0, 0.125), "topbar"))
        if kind in ("date", "all"):
            out.append(_save_shot(_crop(arr, 0.60, 0.03, 1.0, 0.12), "date"))
        if kind in ("small", "all"):
            out.append(_save_shot(arr[::2, ::2], "small"))
        return "paths: " + " | ".join(out)
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_state() -> str:
    """Running/paused (via ticking pixel check over the date panel) + date-panel crop path."""
    try:
        d = resolve_driver()
        from hoi4_mcp.tools import screenshot as shot
        state = d.state()
        arr = shot.capture_smart(d.pid)
        crop = _crop(arr, 0.60, 0.03, 1.0, 0.12)
        return f"state={state} datepanel={_save_shot(crop, 'date')}"
    except Exception as exc:
        return _err(exc)


# ---------------------------------------------------------------- actions (UI)
@mcp.tool()
def hoi4_pause_toggle() -> str:
    """Click the pause/resume button, then verify with the tick detector."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        d.pause_toggle()
        return f"toggled; state={d.state()}"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_set_speed(n: int) -> str:
    """Best-effort set game speed 1..5 via speed buttons (floor then boost)."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        d.set_speed(n)
        return f"set_speed({n}) sent; verify pacing from date panel across ticks"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_click(x: float, y: float) -> str:
    """Send one real click at client-normalized (x, y) onto the game window (player-equivalent)."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        d.input.click(x, y)
        from hoi4_mcp.tools import screenshot as shot
        arr = shot.capture_smart(d.pid)
        return f"clicked ({x:.3f},{y:.3f}); shot={_save_shot(arr, 'after_click')}"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_save() -> str:
    """Save the game through the in-game menu (prefilled date-named save); returns the new .hoi4 file."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        sg = Path.home() / "Documents/Paradox Interactive/Hearts of Iron IV/save games"
        before = {p.name: p.stat().st_mtime for p in sg.glob("*.hoi4")}
        d.open_menu()
        time.sleep(0.5)
        d.input.click(0.502, 0.30)    # 保存游戏 (menu rows; client-frame)
        time.sleep(1.5)
        d.input.click(0.560, 0.813)   # 保存 (prefilled GER_<date> filename)
        for _ in range(30):
            time.sleep(2.0)
            after = {p.name: p.stat().st_mtime for p in sg.glob("*.hoi4")}
            new = [k for k, v in after.items() if before.get(k) != v]
            if new:
                size_kb = (sg / new[0]).stat().st_size // 1024
                time.sleep(3.0)  # let the dialog close and file finalize
                return f"saved {new[0]} ({size_kb} KB)"
        return "error: no new save file appeared; inspect shots for the dialog state"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_load(save_name: str = "latest", confirm: bool = True) -> str:
    """Load a save through the game UI (player-equivalent clicks).
    save_name: 'latest' (newest .hoi4 by mtime) or an exact file name; the
    load-dialog list is sorted newest-first (verified == hoi4_saves order),
    row = its index. confirm=false stops right after selecting the row — the
    'selected' screenshot then shows the highlighted row AND its hover detail
    (filename/date/多人游戏=否) so you can verify before committing.
    WARNING: loading DISCARDS the current session — hoi4_save() first if the
    live state matters. If the highlighted row is not the intended save,
    abort via 返回 (0.449, 0.810) and pick the row manually with hoi4_click.
    After loading, verify 'after_load': the date panel must show the save's
    date (also returned as 'expected')."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        from .saveparse.saveinfo import read_header
        d = resolve_driver()
        cands = sorted(SAVE_SG.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime)
        names = [p.name for p in cands]
        if save_name == "latest":
            idx = 0
            target = cands[0] if cands else None
        elif save_name in names:
            idx = names.index(save_name)
            target = SAVE_SG / save_name
        else:
            return (f"error: no save named {save_name}; newest first: "
                    + ", ".join(names[:12])
                    + (" ..." if len(names) > 12 else ""))
        if idx >= SessionDriver.LOAD_MAX_ROWS:
            return (f"error: {save_name} is list row {idx} (beyond the "
                    f"visible {SessionDriver.LOAD_MAX_ROWS} rows, no "
                    f"scrolling implemented); the game is likely already ON "
                    f"a newer session anyway")
        res = d.load_save(idx, confirm=confirm)
        if target is not None:
            try:
                h = read_header(target, limit=16384)
                res["expected"] = h.summary()
            except Exception:
                pass
        if confirm and "error" not in res:
            res["note"] = ("verify 'after_load': the date panel should show "
                           "the loaded save's date; hoi4_state() to confirm")
        return "\n".join(f"{k}: {v}" for k, v in res.items())
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_saves(filter: str = "") -> str:
    """List save games with decoded headers (player/ideology/difficulty/date).
    Offline read of the save directory; no game interaction."""
    try:
        from .saveparse.saveinfo import read_header
        sg = Path.home() / "Documents/Paradox Interactive/Hearts of Iron IV/save games"
        rows = []
        for p in sorted(sg.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime):
            if filter and filter.lower() not in p.name.lower():
                continue
            try:
                h = read_header(p, limit=16384)
                rows.append(h.summary())
            except Exception as exc:
                rows.append(f"{p.name}: unreadable ({exc})")
        return "\n".join(rows) if rows else "no saves"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_date() -> str:
    """Read game date from live CGameDate objects in memory (full RW scan,
    ~25s). Returns decoded date clusters; the live one is a small in-sync
    family — cross-check with the date-panel screenshot when ambiguous."""
    try:
        from .runtime_state import read_date
        res = read_date(resolve_game())
        if "error" in res:
            return res["error"]
        rows = ", ".join(f"{lbl} x{c}" for lbl, c in res["clusters"])
        return f"CGameDate clusters (n={res['count']}): {rows}\n{res['note']}"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_dismiss(kind: str = "outside") -> str:
    """Dismiss overlay UI after popups/events are handled. kind='menu' closes
    the MAIN menu via its own 关闭 button (outside click does NOT close it);
    kind='outside' clicks an empty-ocean spot, which closes outside-closable
    modals (e.g. the world tension panel). Both return evidence screenshot
    paths so you can verify with your own eyes."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        if kind == "menu":
            res = d.menu_close()
        elif kind == "outside":
            d.click_outside()
            res = "outside-click sent"
        else:
            return f"error: unknown kind {kind} (menu|outside)"
        from hoi4_mcp.tools import screenshot as shot
        arr = shot.capture_smart(d.pid)
        return f"{res}; shot={_save_shot(arr, 'after_dismiss')}"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_hover(x: float, y: float) -> str:
    """Move the mouse to client-normalized (x, y) WITHOUT clicking and return
    an evidence screenshot. Tooltips key off hover — e.g. manpower (0.300,
    0.024) read 可征召% + 兵役法, stability icon (0.155, 0.024) read the
    base/修正 breakdown, industry (0.353, 0.024) read 军民工厂占用 — so
    hover-then-read is how top-bar numbers get decomposed like a real
    player does. Input goes through the write-layer guard like clicks."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        d = resolve_driver()
        d.input.move(x, y)
        time.sleep(1.0)   # let the tooltip element animate in
        from hoi4_mcp.tools import screenshot as shot
        arr = shot.capture_smart(d.pid)
        return f"hover ({x:.3f},{y:.3f}); shot={_save_shot(arr, 'after_hover')}"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_popup(recall: int = 0) -> str:
    """Evidence kit for the surprise-auto-pause case (an event popup is the
    usual cause: HOI4 pauses the game and drops a modal over the UI). There
    is NO universal close/option coordinate — event boxes vary in size and
    stack their option buttons, so this tool only returns the reading
    material; you then choose the option yourself with hoi4_click at
    coordinates you read off the screenshot, and re-check icon/state after.
    recall=N (0..8) returns the N most recent evidence shots instead of
    capturing again — cheap when a popup just moved between two renders and
    you want to compare frames already on disk. Fresh captures when 0.
    Returns: icon classification + full frame + date crop + left-bottom crop
    (typical event-box zone) paths."""
    try:
        d = resolve_driver()
        if recall:
            rec_files = sorted(SHOTS_DIR.glob("*.png"),
                               key=lambda p: -p.stat().st_mtime)[:min(recall, 8)]
            if not rec_files:
                return "error: no shots saved yet (recall needs prior captures)"
            icon = d.icon_state()
            return (f"icon={icon or 'undecidable'} (recall mode, no fresh "
                    f"capture)\nlast shots newest-first: "
                    + " | ".join(str(p) for p in rec_files))
        from hoi4_mcp.tools import screenshot as shot
        arr = shot.capture_smart(d.pid)
        if arr is None:
            return "error: capture failed"
        icon = d.icon_state()
        full = _save_shot(arr, "popup_full")
        date = _save_shot(_crop(arr, 0.60, 0.005, 1.0, 0.055), "popup_date")
        box = _save_shot(_crop(arr, 0.05, 0.30, 0.60, 0.97), "popup_bbox")
        hint = ("treat as EVENT POPUP: read popup_full, then click your chosen "
                "option via hoi4_click; popups pause the game themselves — "
                "after handling, verify with hoi4_popup() again or hoi4_state()")
        return (f"icon={icon or 'undecidable'}\nfull={full}\ndate={date}\n"
                f"box={box}\n{hint}")
    except Exception as exc:
        return _err(exc)


REC_STATE: dict = {"recorder": None}


@mcp.tool()
def hoi4_record(action: str = "status") -> str:
    """Click-sequence recorder. action='start' begins logging every mouse/
    keyboard event the driver emits to a JSONL file (plus a start-frame
    screenshot saved next to it, used by hoi4_replay to verify the layout
    still matches before clicking anything); 'stop' flushes and returns the
    file path; 'status' reports whether a recording is live.
    Replay it later with hoi4_replay to reproduce a hand-debugged click
    chain (e.g. the exact menu walk to a panel) one-to-one."""
    try:
        if action == "start":
            failed = _write_refusal()
            if failed:
                return failed
            if REC_STATE["recorder"] is None:
                d = resolve_driver()
                from hoi4_mcp.tools import screenshot as shot
                from .ui.recorder import Recorder, RECORDING_DIR, attach_input
                rec = Recorder()
                REC_STATE["recorder"] = rec
                REC_STATE["input"] = d.input
                attach_input(d.input, rec)
                path = RECORDING_DIR / f"rec_{time.strftime('%Y%m%d_%H%M%S')}.jsonl"
                # start-frame evidence for the replay-time pre-check
                start_png = None
                try:
                    arr = shot.capture_smart(d.pid)
                    if arr is not None:
                        sp = path.with_name(path.stem + "_start.png")
                        shot.save_png(arr, sp)
                        start_png = str(sp)
                except Exception:
                    pass
                rec.start(path=path, meta=(dict(start_frame=str(start_png))
                                           if start_png else None))
                return (f"recording started -> {path} "
                        f"(start frame: {start_png or 'none'})")
            return "error: already recording"
        if action == "stop":
            rec = REC_STATE["recorder"]
            if rec is None:
                return "not recording"
            summary = rec.stop()
            REC_STATE["recorder"] = None
            return f"recording stopped: {summary['steps']} steps -> {summary['path']}"
        if action == "status":
            rec = REC_STATE["recorder"]
            return (f"recording, {len(rec.steps) - 1} steps so far, "
                    f"file {rec.path}") if rec else "not recording"
        return f"error: unknown action {action!r} (start|stop|status)"
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_replay(path: str, speed: float = 1.0, force: bool = False) -> str:
    """Replay a recorded click sequence (JSONL from hoi4_record) through the
    live game input, waiting the original deltas divided by `speed`.
    BEFORE any click, the current frame is diffed against the recording's
    start-frame screenshot (written by hoi4_record start): a mean channel
    delta > REPLAY_DIFF_LIMIT refuses the replay (wrong screen state is the
    no.1 way a dumb replay ends up clicking the wrong thing) unless
    force=True. The recipe stays layout-sensitive: same panels open/paused
    as when recorded; always verify the returned final evidence shot."""
    refused = _write_refusal()
    if refused:
        return refused
    try:
        import json as _json
        from pathlib import Path as _P
        from hoi4_mcp.tools import screenshot as shot
        p = _P(path)
        if not p.is_file():
            return f"error: no recording at {path}"
        meta = {}
        with p.open("r", encoding="utf-8") as f:
            first = f.readline()
            try:
                meta = _json.loads(first).get("meta", {})
            except Exception:
                meta = {}
        start_frame = meta.get("start_frame")
        check = None
        if start_frame and not force:
            base = shot.load_png(_P(start_frame))
            cur = shot.capture_smart(resolve_driver().pid)
            if base is None or cur is None:
                check = ("error: start-frame evidence unreadable "
                         f"({start_frame}); pass force=True to replay anyway")
            else:
                h = min(base.shape[0], cur.shape[0])
                w = min(base.shape[1], cur.shape[1])
                diff = float(np.abs(
                    base[:h, :w].astype(np.int16)
                    - cur[:h, :w].astype(np.int16)).mean())
                if diff > REPLAY_DIFF_LIMIT:
                    now = _P(str(_P(start_frame).with_suffix("")) +
                             "_now.png")
                    if cur is not None:
                        shot.save_png(cur, now)
                    return (f"refused: screen state changed since recording "
                            f"(frame diff {diff:.2f} > {REPLAY_DIFF_LIMIT}); "
                            f"now={now} ref={start_frame}. Set the same "
                            f"panels/pause state as during recording, or "
                            f"force=true if the mismatch is cosmetic.")
                check = f"start-frame diff {diff:.2f} <= {REPLAY_DIFF_LIMIT} ok"
        d = resolve_driver()
        from .ui.recorder import Recorder
        res = Recorder.replay(path, d, speed=speed)
        if check:
            res["start_check"] = check
        arr = shot.capture_smart(d.pid)
        res["final_shot"] = _save_shot(arr, "after_replay") if arr is not None else None
        return "\n".join(f"{k}: {v}" for k, v in res.items())
    except Exception as exc:
        return _err(exc)


SAVE_SG = Path.home() / "Documents/Paradox Interactive/Hearts of Iron IV/save games"


def _parse_save_summary(path: Path) -> str:
    from .readstate.world_state import top_lines
    return top_lines(str(path))


def _resolve_save_path(save_name: str) -> Path | None:
    cands = sorted(SAVE_SG.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime)
    if save_name == "latest":
        return cands[0] if cands else None
    p = SAVE_SG / save_name
    if p.is_file():
        return p
    return None


@mcp.tool()
def hoi4_country_detail(save_name: str = "latest", tag: str = "",
                        sections: str = "") -> str:
    """Per-country semantic detail parsed offline from a save (zero intrusion).
    Sections (space-less comma/empty=all): pol (PP/stability/war support/
    parties/ideas-laws) | research (done techs + in-progress + slots + avail:
    researchable-now techs from the leads_to prereq graph, cost/start_year/
    est days) | prod (production lines with equipment archetype names +
    stockpile + custom variants) | construction (build queue: building/state/
    progress/factories; empty if nothing queued) | res (resource production) |
    units (divisions with NAMES reconstructed from template + name_order) |
    diplo (attitudes+opinions) | decisions | focus (tree + completed list +
    available: pickable-now focuses from the national_focus prereq graph,
    duration cost*7 days, banked days applied; GATED rows have an
    unevaluated trigger — verify in UI) | fuel | mp (manpower, ratio/1e5 =
    effective recruitable %) | chars (leader/advisors/generals by name; ~1min
    first time) | theatres (command chain: division ids per theatre + fronts).
    save_name='latest' picks the newest .hoi4 (pair with hoi4_save() to read
    the LIVE game); tag defaults to the player country."""
    try:
        from .readstate.country_sem import (
            Countries, SECTIONS, country_sections, format_sections)
        path = _resolve_save_path(save_name)
        if path is None:
            return f"error: no save named {save_name} in {SAVE_SG}"
        cn = Countries(path)
        want_tag = tag.strip().upper()
        if not want_tag:
            want_tag = cn.player() or cn.tags()[0]
        if sections:
            want_secs = [s.strip() for s in sections.replace(",", " ").split()
                         if s.strip()]
        else:
            want_secs = list(SECTIONS.keys())
        sec = country_sections(cn, want_tag, want_secs)
        inner = sec.get(want_tag, sec)
        if "error" in inner:
            return inner["error"]
        return format_sections(want_tag, inner)
    except Exception as exc:
        return _err(exc)


@mcp.tool()
def hoi4_world_state(save_name: str = "latest") -> str:
    """Full offline world-state summary from a save: player/date/version +
    per-country digest (PP/stability/war_support/research slots/focus tree).
    save_name: 'latest' picks the newest .hoi4 in the save dir, or an exact
    file name. To analyze the LIVE game, pair this with hoi4_save() first
    (the fresh save is then 'latest'). Pure offline parsing, zero intrusion."""
    try:
        if save_name == "latest":
            cands = sorted(SAVE_SG.glob("*.hoi4"), key=lambda q: -q.stat().st_mtime)
            if not cands:
                return "error: no save files"
            path = cands[0]
        else:
            path = SAVE_SG / save_name
            if not path.exists():
                return f"error: no save named {save_name} in {SAVE_SG}"
        return _parse_save_summary(path)
    except Exception as exc:
        return _err(exc)


# ------------------------------------------------- v2 inject layer (Phase I)
_inject_layer = None


def _resolve_inject_layer():
    global _inject_layer
    from .inject.commands import CommandLayer
    if _inject_layer is None or (_game and _inject_layer.p.pid != _game.proc.pid):
        layer = CommandLayer(_game if _game else resolve_game())
        layer.rc.attempts = 60          # paused game rarely freezes a user-code
        layer.rc.rearm_delay = 0.006    # thread; re-arm until one is caught
        _inject_layer = layer
    return _inject_layer


@mcp.tool()
def hoi4_inject_status() -> str:
    """v2 inject-layer status: identity checks of the resolved CSession /
    CInGameIdler / CCurrentGameState, the Post gate byte, the live paused byte
    (no UI, no save read), and the APC channel state. Read-only memory probes
    plus the mitigation-policy decode."""
    try:
        layer = _resolve_inject_layer()
    except Exception as exc:
        return _err(exc)
    from .process import win32ext as _w
    ss = _w.get_mitigation_policy(layer.p.handle, 15, 4) or 0
    bits = [n for i, n in enumerate(
        ["EnableUserShadowStack", "AuditUserShadowStack", "SetContextIpValidation",
         "AuditSetContextIpValidation", "UserShadowStackStrictMode",
         "BlockNonCetBinaries", "BlockNonCetBinariesNonEhcont",
         "AuditBlockNonCetBinaries", "CetDynamicApisOutOfProcOnly",
         "SetContextIpValidationRelaxedMode"]) if ss & (1 << i)]
    return (
        f"gamestate={layer.gamestate:#x} tag={layer.player_tag}\n"
        f"queue={layer.queue:#x} gate_open={layer.queue_gate_open()}\n"
        f"idler={layer.idler:#x} paused={layer.is_paused()}\n"
        f"shadow-stack policy={ss:#x} -> {bits or 'none'}\n"
        f"apc channel (v3.0 blob): {layer.apc.status()}\n"
        f"vm channel (v3.1 ctor): {layer.script.status()}\n"
        "channels: v3.0 = one special user APC per send, payload = operator new "
        "+ blob copy + Post; v3.1 = the micro-VM payload (remote call / raw "
        "write / ctor-faithful object construction) with a vectored-exception "
        "crash shield installed in the target. No thread is suspended and none "
        "is created, so the payload runs in the game thread's own TLS context "
        "and Post goes through the player's own queue with CanExecute intact. "
        "Verify actions with hoi4_hud afterwards.\n"
        "24 日: posting a command whose field layout was never verified against "
        "the game's own constructor AV'd the process (RVA 0x24c2f0d). The write "
        "layer now refuses unverified specs and builds objects with the real "
        "ctor — see research/NOTES.md."
    )


@mcp.tool()
def hoi4_inject_post(command: str = "", focus: str = "", focus_id: int = 0) -> str:
    """v3.1: post ONE player command built by the GAME'S OWN CONSTRUCTOR (24 日).

    channel = one special user APC that runs `operator new(size)` -> the real
    ctor -> `Post(queue, obj, force=0)` on an existing game thread; no thread is
    suspended and none is created.

    command = a name from inject/tables.py COMMANDS whose spec is ctor-verified:
      IncreaseGameSpeed | DecreaseGameSpeed | SetGameSpeed      (no arguments)
      SetNationalFocus | BypassNationalFocus                    (focus / focus_id)
      DropCurrentNationalFocus                                  (tag only)
    (PauseGame is refused: its constructor has not been recovered yet, so the
    write layer will not guess its layout. SetResearch is spec-verified but its
    CTechnology* argument cannot be resolved by name yet — see NOTES 26 日.)

    SetNationalFocus takes either focus (a name such as
    GER_accelerate_the_rearmament_program, resolved against the live
    CNationalFocus instances) or focus_id (numeric). The command carries a
    POINTER to the focus object — there is no numeric-id field and no mode field
    (that was the 21 日 misreading that killed a game process on 24 日).

    Verification is the caller's job: posted=True only means the queue took the
    object; the game then executes it (or frees it) on its own thread."""
    ref = _write_refusal()
    if ref:
        return ref
    try:
        from .inject import tables as _T
        layer = _resolve_inject_layer()
    except Exception as exc:
        return _err(exc)
    if not command:
        return ("error: command required; one of " +
                ", ".join(f"{n}{'' if s.get('verified') else ' (unverified)'}"
                          for n, s in sorted(_T.COMMANDS.items())))
    if command not in _T.COMMANDS:
        return f"error: unknown command {command!r}; known: {sorted(_T.COMMANDS)}"

    args: list[int] = []
    tag_addr = layer.gamestate + _T.GS_PLAYER_TAG_OFF
    if command == "SetResearch":
        return ("error: SetResearch is spec-verified but not wired into this tool "
                "yet: its ctor takes a live CTechnology* (id at +0x38) and the "
                "name -> object resolution is still open — see research/NOTES.md "
                "26 日; use CommandLayer.post_research(tech_obj, slot) with a "
                "resolved pointer")
    if command in ("SetNationalFocus", "BypassNationalFocus"):
        from .inject.focus_ids import scan_focus_ids_objects
        try:
            objs = scan_focus_ids_objects(layer.p)
        except Exception as exc:
            return _err(exc)
        if not focus_id and focus:
            hit = [(fid, addr) for fid, (addr, nm) in objs.items()
                   if nm.lower() == focus.lower()]
            if not hit:
                near = [nm for _f, (_a, nm) in list(objs.items())[:400]
                        if focus.lower() in nm.lower()][:8]
                return (f"error: focus {focus!r} not in the live focus map"
                        + (f"; near matches: {near}" if near else ""))
            focus_id, faddr = hit[0]
        else:
            hit = [(fid, addr) for fid, (addr, nm) in objs.items() if fid == focus_id]
            if not hit:
                return f"error: focus_id {focus_id} not found in the live focus map"
            faddr = hit[0][1]
        # the UI's own call site passes &tag = gamestate+0x520 and the focus object
        args = [tag_addr, faddr] + ([0] if command == "SetNationalFocus" else [])
    elif command == "DropCurrentNationalFocus":
        # ctor(this, rdx=&tag): one argument, the same &tag the focus picker uses
        args = [tag_addr]
    elif command in ("IncreaseGameSpeed", "DecreaseGameSpeed", "SetGameSpeed"):
        args = []                      # argument-less: nothing travels in the body
    try:
        res = layer.send_ctor_apc(command, *args)
    except Exception as exc:
        return _err(exc)
    return (f"{res}\nverify with hoi4_hud / hoi4_country_detail('latest')")


@mcp.tool()
def hoi4_focus_ids(prefix: str = "") -> str:
    """READ-ONLY: numeric focus ids for SetNationalFocusCommand, built live
    from CNationalFocus instances (id @ +0x08, MSVC-string name @ +0x18).
    Optional prefix filter (e.g. GER_). ~1 vftable scan (~25s) per call
    without a cache; the mapping is stable for the running session.
    Join pairs with hoi4_country_detail(...,'focus') name strings."""
    try:
        from .inject.focus_ids import scan_focus_ids
        game = _game if _game else resolve_game()
        mapping = scan_focus_ids(game.proc)
    except Exception as exc:
        return _err(exc)
    if prefix:
        pref = prefix.lower()
        mapping = {k: v for k, v in mapping.items() if v.lower().startswith(pref)}
    if not mapping:
        return ("no CNationalFocus instances resolved — is the game in a "
                "session? (main menu has no focus database)")
    lines = [f"{len(mapping)} focus ids reconstructed live"]
    shown = 0
    for k in sorted(mapping):
        v = mapping[k]
        if shown < 40 or (prefix and shown < 400):
            lines.append(f"  {v} = {k}")
            shown += 1
    if len(mapping) > shown:
        lines.append(f"  ... ({len(mapping) - shown} more; pass prefix= to narrow)")
    return "\n".join(lines)


@mcp.tool()
def hoi4_inject_speed(delta: int = 1) -> str:
    """Post CIncreaseGameSpeedCommand / CDecreaseGameSpeedCommand through the
    player-command queue via the APC channel (23 日) — the same queue a speed
    button click uses, CanExecute intact. delta in {-2,-1,1,2}.
    Verify with hoi4_hud('date'): the executed command shows as changed speed
    pips. Each step is one special user APC; the game is never suspended and no
    thread is created, so consecutive steps are cheap (the 21 日 'one command
    per session' rule belonged to the retired graft protocol)."""
    ref = _write_refusal()
    if ref:
        return ref
    if delta not in (-2, -1, 1, 2):
        return "error: delta must be one of -2/-1/1/2"
    try:
        layer = _resolve_inject_layer()
    except Exception as exc:
        return _err(exc)
    name = "IncreaseGameSpeed" if delta > 0 else "DecreaseGameSpeed"
    out = []
    for _ in range(abs(delta)):
        try:
            out.append(layer.send_apc(name))
        except Exception as exc:
            out.append(_err(exc))
            break
        time.sleep(0.25)   # adjacent APCs are independent; no freeze window
    note = ("speed pips in hoi4_hud('date') prove execution; posted=True means "
            "enqueued (the queue later executes or frees the object). "
            "job_intact=False would mean a callee walked over its own job — "
            "treat that send as untrusted.")
    return "\n".join(str(o) for o in out) + f"\n{name} steps={abs(delta)}\n{note}"


def main() -> None:
    mcp.run()
