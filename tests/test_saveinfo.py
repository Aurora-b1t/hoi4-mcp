"""saveinfo: header decode + the hours-since-1936 date encoding."""

from __future__ import annotations

import pytest

from hoi4_mcp.saveparse.saveinfo import decode_date, encode_date


def test_date_roundtrip():
    assert encode_date(1936, 1, 1, 0) == 60759359   # the EPOCH constant
    assert decode_date(encode_date(1936, 1, 1, 0)) == "1936-01-01 00"
    for y, m, d, h in ((1936, 1, 1, 12), (1936, 9, 19, 6), (1937, 3, 2, 8)):
        assert decode_date(encode_date(y, m, d, h)) == f"{y:04d}-{m:02d}-{d:02d} {h:02d}"


def test_no_leap_year_calendar():
    # HOI4 counts 365-day years: 1937-01-01 is exactly 8760h after epoch
    assert encode_date(1937, 1, 1) - 60759359 == 8760


def test_real_save_headers(ger_save):
    from hoi4_mcp.saveparse.saveinfo import read_header
    h = read_header(ger_save, limit=16384)
    s = h.summary()
    assert "player=GER" in s or ger_save.name.startswith("autosave")
    assert "date=" in s
