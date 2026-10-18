"""Shared fixtures: locate local saves / game install; skip when absent."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

SAVE_DIR = (Path.home() / "Documents" / "Paradox Interactive"
            / "Hearts of Iron IV" / "save games")


def newest_saves(n: int = 3) -> list[Path]:
    if not SAVE_DIR.is_dir():
        return []
    return sorted(SAVE_DIR.glob("*.hoi4"), key=lambda p: -p.stat().st_mtime)[:n]


def any_save_of(tag_prefix: str) -> Path | None:
    for p in newest_saves(20):
        if p.name.startswith(tag_prefix):
            return p
    return None


@pytest.fixture(scope="session")
def ger_save() -> Path:
    """Newest GER save (player-country regression body); skips the module
    when the machine has no local saves (CI / other machines)."""
    p = newest_saves(20)
    ger = [q for q in p if q.name.startswith(("GER_", "autosave"))]
    if not ger:
        pytest.skip("no local GER saves present")
    return ger[0]


@pytest.fixture(scope="session")
def game_install() -> Path:
    from hoi4copilot.readstate import techdata
    root = techdata.install_dir()
    if root is None:
        root = os.environ.get("HOI4_INSTALL")
    if not root:
        pytest.skip("HOI4 install dir not found")
    return Path(root)
