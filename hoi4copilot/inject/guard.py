"""Write-channel guard for the inject layer (same policy as the UI write
tools' _write_refusal in mcp_server, self-contained so both channels stay
locked together): HOI4_READ_ONLY=1 refuses everything; hard multiplayer
evidence refuses unless HOI4_ALLOW_MP=1."""
from __future__ import annotations

from .. import config
from .. import safety


def write_refusal(pid: int | None) -> str | None:
    """Return a refusal reason string, or None when the write may proceed."""
    if config.READ_ONLY:
        return ("refused: read_only barrier (HOI4_READ_ONLY=1). Command "
                "injection is a write channel and stays locked.")
    rep = safety.guard(pid=pid)
    if rep.verdict == "multiplayer" and not config.ALLOW_MP:
        return ("refused: multiplayer session detected "
                f"({'; '.join(rep.reasons) or rep.as_line()}). This toolset "
                "is single-player by covenant — see README. HOI4_ALLOW_MP=1 "
                "is the developer override.")
    return None
