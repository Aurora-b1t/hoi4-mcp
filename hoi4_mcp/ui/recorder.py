"""Session recording / replay (19 日): click-sequence observer + player.

Records every Input-level mouse/keyboard event with wall-clock deltas into a
JSONL file; replays the same sequence against a live game window. Purpose:
(1) reproducible UI flows — the agent can save a hand-debugged click chain
and replay it later instead of re-deriving coordinates each time;
(2) evidence — a recording of "how the state was reached" from actions.

Replay is deliberately dumb: same normalized coordinates + original inter-step
delay / speed. It never re-decides anything, so the recipe dies when the game
UI layout changes — check the final evidence screenshot every time.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

RECORDING_DIR = Path.home() / ".hoi4_mcp" / "recordings"


class Recorder:
    """Hooks into an Input instance; records click/right_click/wheel/key."""

    def __init__(self):
        self.steps: list[dict] = []
        self.path: Path | None = None
        self.t0: float | None = None
        self._running = False
        self._last_t: float | None = None

    def start(self, path: Path | None = None, meta: dict | None = None) -> Path:
        RECORDING_DIR.mkdir(parents=True, exist_ok=True)
        self.path = path or (RECORDING_DIR /
                             f"rec_{time.strftime('%Y%m%d_%H%M%S')}.jsonl")
        head = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "game": "hoi4"}
        if meta:
            head.update(meta)
        self.steps = [{"t": 0, "meta": head}]
        self._running = True
        self._last_t = time.time()
        return self.path

    def annotate(self, note: str) -> None:
        """Insert a marker step (no input event); replay shows it, then skips."""
        if self._running:
            self.steps.append({"dt": self._dt_ms(), "kind": "note", "note": note})

    def _dt_ms(self) -> int:
        now = time.time()
        dt = int((now - self._last_t) * 1000) if self._last_t else 0
        self._last_t = now
        return dt

    def record(self, kind: str, **kwargs) -> None:
        if not self._running:
            return
        step = {"dt": self._dt_ms(), "kind": kind, **kwargs}
        self.steps.append(step)

    def stop(self) -> dict:
        self._running = False
        summary = {"path": str(self.path), "steps": len(self.steps) - 1}
        if self.path and self.steps:
            with self.path.open("w", encoding="utf-8") as f:
                for s in self.steps:
                    f.write(json.dumps(s, ensure_ascii=False) + "\n")
        return summary

    # -- replay ---------------------------------------------------------------
    @staticmethod
    def replay(path: str | Path, driver, speed: float = 1.0,
               max_wait_s: float = 30.0) -> dict:
        """Replay a recording file through `driver.input` (a live SessionDriver's
        Input). Waits dt/speed between events (capped at max_wait_s each).
        Read-only mode check + MP guard live at the MCP layer, not here."""
        steps: list[dict] = []
        with Path(path).open("r", encoding="utf-8") as f:
            for line in f:
                s = json.loads(line)
                if "meta" not in s:
                    steps.append(s)
        n = len(steps)
        waits = [min(max_wait_s, s.get("dt", 0) / 1000.0 / max(speed, 0.1))
                 for s in steps]
        t0 = time.time()
        executed = 0
        for i, s in enumerate(steps):
            if waits[i] > 0.05:
                time.sleep(waits[i])
            kind = s.get("kind")
            inp = driver.input
            try:
                if kind == "click":
                    inp.click(s["x"], s["y"], hold=s.get("hold", 0.03))
                elif kind == "right_click":
                    inp.right_click(s["x"], s["y"])
                elif kind == "wheel":
                    inp.wheel(s["x"], s["y"], s.get("delta", -120))
                elif kind == "key":
                    inp.key(s["vk"])
                elif kind == "note":
                    pass
                else:
                    return {"error": f"unknown step kind {kind!r} at {i}",
                            "executed": executed}
                executed += 1
            except KeyError as exc:
                return {"error": f"step {i} missing field {exc}",
                        "executed": executed}
        return {"replayed": executed, "total_steps": n,
                "path": str(path), "speed": speed,
                "elapsed_s": round(time.time() - t0, 1)}


def attach_input(input_obj, recorder: Recorder) -> None:
    """Wrap Input click/right_click/wheel/key so every event lands in the log.
    Idempotent: the un-wrapped originals are stored once on the instance, so
    repeated attaches never stack wrappers (which would double-log)."""
    if not hasattr(input_obj, "_rec_orig"):
        input_obj._rec_orig = {
            "click": input_obj.click,
            "right_click": input_obj.right_click,
            "wheel": input_obj.wheel,
            "key": input_obj.key,
        }
    orig = input_obj._rec_orig

    def click(x, y, hold=0.03):
        orig["click"](x, y, hold)
        recorder.record("click", x=round(x, 5), y=round(y, 5), hold=hold)

    def right_click(x, y, hold=0.03):
        orig["right_click"](x, y, hold)
        recorder.record("right_click", x=round(x, 5), y=round(y, 5))

    def wheel(x, y, delta):
        orig["wheel"](x, y, delta)
        recorder.record("wheel", x=round(x, 5), y=round(y, 5), delta=delta)

    def key(vk, hold=0.03):
        orig["key"](vk, hold)
        recorder.record("key", vk=vk)

    input_obj.click = click
    input_obj.right_click = right_click
    input_obj.wheel = wheel
    input_obj.key = key
    input_obj._recorder_bound = recorder
