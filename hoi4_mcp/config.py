"""Static configuration: game install paths, product versions, build outputs."""

from __future__ import annotations

import json
import os
from pathlib import Path

EXE_NAME = "hoi4.exe"

DEFAULT_INSTALL_CANDIDATES = [
    r"D:\Steam\steamapps\common\Hearts of Iron IV",
    r"C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV",
    r"C:\Program Files\Steam\steamapps\common\Hearts of Iron IV",
]

DOCS_ROOT = Path(os.environ.get("HOI4_DOCS", Path.home() / "Documents" / "Paradox Interactive" / "Hearts of Iron IV"))

# Safety switches (evaluated at import; the MCP server is a fresh process, so
# env vars set before `hoi4-server` starts are the intended entry point).
# READ_ONLY: refuse every write tool (screen footage/menu parking only).
# ALLOW_MP:  explicit override so a developer can test the write layer inside
#            a multiplayer session; the project covenant is single-player only.
READ_ONLY = os.environ.get("HOI4_READ_ONLY", "0") == "1"
ALLOW_MP = os.environ.get("HOI4_ALLOW_MP", "0") == "1"

PACKAGE_ROOT = Path(__file__).resolve().parent
TABLES_DIR = PACKAGE_ROOT / "tables" / "generated"

_PROJECT_ROOT = PACKAGE_ROOT.parent


def find_install_dir() -> Path:
    """Locate the HOI4 install dir (env override first, then known locations)."""
    env = os.environ.get("HOI4_INSTALL")
    if env:
        p = Path(env)
        if (p / EXE_NAME).is_file():
            return p

    candidates_file = _PROJECT_ROOT / "hoi4_mcp_install.json"
    if candidates_file.is_file():
        p = Path(json.loads(candidates_file.read_text())["install_dir"])
        if (p / EXE_NAME).is_file():
            return p

    for cand in DEFAULT_INSTALL_CANDIDATES:
        p = Path(cand)
        if (p / EXE_NAME).is_file():
            return p

    raise FileNotFoundError(
        "HOI4 install not found. Set HOI4_INSTALL or write "
        f"{candidates_file}: {{\"install_dir\": \"D:/Steam/.../Hearts of Iron IV\"}}"
    )


def install_version(install_dir: Path) -> str:
    """Read the raw game version, e.g. 1.19.3.0, from launcher-settings.json."""
    data = json.loads((install_dir / "launcher-settings.json").read_text(encoding="utf-8"))
    return data.get("rawVersion", "unknown")
