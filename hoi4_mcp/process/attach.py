"""Attach/disconnect logic for a running hoi4.exe."""

from __future__ import annotations

import logging
import pathlib
import threading
from typing import Callable, Optional

import psutil

from .. import config, __version__  # noqa: F401
from .. import SUPPORTED_VERSION
from . import win32ext as w
from .reader import ProcessMemory

log = logging.getLogger(__name__)


def find_pids(exe_name: str = config.EXE_NAME) -> list[int]:
    pids = []
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() == exe_name.lower():
                pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


# A crashed hoi4.exe can sit in "terminating" for a long time with a single
# surviving thread: TerminateProcess fails with ACCESS_DENIED, the window is
# gone, and nothing can attach to it — but it still answers tasklist/psutil by
# name (23 日: it made every later "expected exactly one hoi4.exe" check fail).
MIN_LIVE_THREADS = 8


def find_live_pids(exe_name: str = config.EXE_NAME) -> list[int]:
    """PIDs that look like a usable process: a real session has >100 threads,
    a dying one has one or two."""
    out = []
    for proc in psutil.process_iter(["name"]):
        try:
            if not proc.info["name"] or proc.info["name"].lower() != exe_name.lower():
                continue
            if proc.num_threads() >= MIN_LIVE_THREADS:
                out.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


class AttachedProcess:
    """Handle + module info for one hoi4.exe instance."""

    def __init__(self, pid: int):
        self.pid = pid
        proc = psutil.Process(pid)
        self.exe_path = pathlib.Path(proc.exe())
        self.cmdline = proc.cmdline()
        self.install_dir = self.exe_path.parent

        self.handle: w.HANDLE = None
        self.memory: ProcessMemory = None
        self.base: int = 0
        self.image_size: int = 0
        self._attach()

    # -- lifetime ------------------------------------------------------------
    def _attach(self) -> None:
        self.handle = w.open_process(self.pid)
        self.memory = ProcessMemory(self.handle)
        mods = w.enumerate_modules(self.handle)
        exe_lower = self.exe_path.name.lower()
        for name, base, size in mods:
            if name.endswith(exe_lower):
                self.base = base
                self.image_size = size
        if not self.base:
            raise RuntimeError(f"hoi4.exe module base not found among {len(mods)} modules")

    def is_alive(self) -> bool:
        try:
            return psutil.pid_exists(self.pid) and psutil.Process(self.pid).status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            return False

    def version(self) -> str:
        try:
            return config.install_version(self.install_dir)
        except Exception:
            return "unknown"

    def detach(self) -> None:
        if self.handle:
            w._k32.CloseHandle(self.handle)
            self.handle = None

    def __repr__(self):
        return (f"<AttachedProcess pid={self.pid} base=0x{self.base:X} size=0x{self.image_size:X} "
                f"version={self.version()!r}>")


class Game:
    """Single entry point for the read layer; auto-reconnects if the game restarts."""

    def __init__(self, pid: Optional[int] = None):
        self._lock = threading.RLock()
        self._proc: Optional[AttachedProcess] = None
        self._watcher: Optional[threading.Thread] = None
        if pid:
            self.proc = AttachedProcess(pid)
        elif len(pids := find_live_pids()) == 1:
            self.proc = AttachedProcess(pids[0])
        else:
            raise RuntimeError(f"expected exactly one usable hoi4.exe, found "
                               f"{pids or 'none'} (raw: {find_pids()})")

    @property
    def proc(self) -> AttachedProcess:
        return self._proc

    @proc.setter
    def proc(self, value: AttachedProcess) -> None:
        self._proc = value

    def ensure(self) -> AttachedProcess:
        with self._lock:
            if self._proc is None:
                self._attach()
            return self._proc

    def _attach(self) -> None:
        pids = find_pids()
        if not pids:
            raise RuntimeError("hoi4.exe is not running")
        if len(pids) > 1:
            raise RuntimeError(f"multiple hoi4.exe instances: {pids}")
        self._proc = AttachedProcess(pids[0])
        log.info("attached: %s", self._proc)

    def check_version(self) -> bool:
        """True when the running game matches the pinned offset-table version."""
        v = self.ensure().version()
        return v == SUPPORTED_VERSION

    def drop(self, reason: str) -> None:
        if self._proc:
            log.warning("dropping attachment (%s)", reason)
            self._proc.detach()
        self._proc = None

    def is_alive(self) -> bool:
        p = self._proc
        return p is not None and p.is_alive()

    def start_watcher(self, on_dead: Optional[Callable[["Game"], None]] = None) -> None:
        def run():
            while True:
                if self._proc and not self._proc.is_alive():
                    self.drop("process exited")
                    if on_dead:
                        try:
                            on_dead(self)
                        except Exception:
                            log.exception("dead-watch callback failed")
                threading.Event().wait(5.0)

        t = threading.Thread(target=run, name="hoi4-watch", daemon=True)
        t.start()
        self._watcher = t
