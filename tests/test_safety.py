"""safety.py: multiplayer-token scan + verdict logic on synthetic evidence."""

from __future__ import annotations

import struct

import pytest

from hoi4copilot import safety
from hoi4copilot.saveparse import bin5


def _bin5_blob(*pairs: bytes) -> bytes:
    return b"HOI4bin5\x2A" + b"".join(pairs)


def _kv(token: int, value: bytes) -> bytes:
    return struct.pack("<HH", token, bin5.EQUAL) + value


def _str(text: str) -> bytes:
    raw = text.encode()
    return struct.pack("<HH", 0x000F, len(raw)) + raw


def _bool(v: bool) -> bytes:
    return struct.pack("<HH", 0x000E, 1 if v else 0)


def test_mp_flag_true(tmp_path):
    p = tmp_path / "mp.hoi4"
    p.write_bytes(_bin5_blob(_kv(0x299F, _str("very_easy")),
                             _kv(safety.T_MULTIPLAYER, _bool(True))))
    assert safety.save_mp_flag(p) is True


def test_mp_flag_false_and_absent(tmp_path):
    p = tmp_path / "sp.hoi4"
    p.write_bytes(_bin5_blob(_kv(0x299F, _str("very_easy")),
                             _kv(safety.T_MULTIPLAYER, _bool(False))))
    assert safety.save_mp_flag(p) is False
    q = tmp_path / "none.hoi4"
    q.write_bytes(_bin5_blob(_kv(0x299F, _str("very_easy"))))
    assert safety.save_mp_flag(q) is False


def _raw_str(raw: bytes) -> bytes:
    return struct.pack("<HH", 0x000F, len(raw)) + raw


def test_mp_flag_noise_immune(tmp_path):
    # a multiplayer-shaped byte pair inside an unrelated string payload
    # (followed by a garbage value token) must not parse as a key
    p = tmp_path / "noise.hoi4"
    noise_inside = struct.pack("<HH", safety.T_MULTIPLAYER, bin5.EQUAL) + b"\xff\xff"
    p.write_bytes(_bin5_blob(_kv(0x299F, _raw_str(noise_inside))))
    assert safety.save_mp_flag(p) is False


def test_guard_verdicts(monkeypatch, tmp_path):
    monkeypatch.setattr(safety, "tcp_open_for_pid", lambda pid: 0)
    log = tmp_path / "logs"
    log.mkdir()
    monkeypatch.setattr(safety.config, "DOCS_ROOT", tmp_path)

    # log says singleplayer + SP save -> singleplayer
    sp_save = tmp_path / "sp.hoi4"
    sp_save.write_bytes(_bin5_blob(_kv(safety.T_MULTIPLAYER, _bool(False))))
    monkeypatch.setattr(safety, "log_launch_marker",
                        lambda: ("singleplayer", "11:44:14"))
    rep = safety.guard(save_path=sp_save)
    assert rep.verdict == "singleplayer"

    # log says multiplayer -> locked regardless of save
    monkeypatch.setattr(safety, "log_launch_marker",
                        lambda: ("multiplayer", "12:00:00"))
    rep = safety.guard(save_path=sp_save)
    assert rep.verdict == "multiplayer"
    assert rep.reasons

    # truthy save token wins on its own nodes
    mp_save = tmp_path / "mp.hoi4"
    mp_save.write_bytes(_bin5_blob(_kv(safety.T_MULTIPLAYER, _bool(True))))
    monkeypatch.setattr(safety, "log_launch_marker", lambda: (None, None))
    rep = safety.guard(save_path=mp_save)
    assert rep.verdict == "multiplayer"


def test_real_sp_save_not_flagged(ger_save):
    flag = safety.save_mp_flag(ger_save, deep=True)
    assert flag is not True, f"SP save {ger_save.name} flags multiplayer"
