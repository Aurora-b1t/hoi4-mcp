"""bin5 lexer balance + country_sem semantics on a real local save."""

from __future__ import annotations

import pytest

from hoi4_mcp.readstate.country_sem import (
    Countries, country_sections, format_sections)


@pytest.fixture(scope="module")
def cn(ger_save):
    return Countries(ger_save)


def test_bin5_full_file_balance(cn):
    pos, kind, depth, span = cn.pos, cn.kind, cn.depth, cn.span
    n_open = int((kind == 0x0003).sum())
    n_close = int((kind == 0x0004).sum())
    assert n_open == n_close
    assert int(depth[-1]) == 0          # final depth back at root


def test_country_volume(cn):
    assert len(cn.tags()) >= 400        # 1.19.3 world: ~440 countries


def test_ger_politics(cn, ger_save):
    tag = "GER" if "GER" in cn.by_tag else cn.tags()[0]
    cn._cur_tag = tag
    sec = country_sections(cn, tag, ["pol"])
    if "error" in sec.get(tag, {}):
        pytest.fail(f"pol section errored: {sec[tag]['error']}")
    pol = sec[tag]["pol"]
    if tag == "GER":
        # the demo campaign is fascist; UI cross-checks from 16-19 日
        assert isinstance(pol["political_power"], (int, float))
        assert 0 <= pol["stability"] <= 100
    parties = pol["parties"]
    assert parties, "parties list empty"
    total = sum(p["popularity%"] for p in parties)
    assert 99.9 < total < 100.1, f"popularity sums to {total}"


def test_focus_section_schema(cn):
    tag = "GER" if "GER" in cn.by_tag else cn.tags()[0]
    cn._cur_tag = tag
    sec = country_sections(cn, tag, ["focus"])
    if "error" in sec.get(tag, {}):
        pytest.fail(f"focus section errored: {sec[tag]['error']}")
    foc = sec[tag]["focus"]
    assert isinstance(foc["completed"], list)
    assert all(isinstance(x, str) for x in foc["completed"])
    assert foc["tree"], "no active tree id"
    av = foc["available"]
    assert isinstance(av, list)
    for row in av:
        assert "focus" in row


def test_units_names(cn):
    tag = "GER" if "GER" in cn.by_tag else cn.tags()[0]
    cn._cur_tag = tag
    sec = country_sections(cn, tag, ["units"])
    if "error" in sec.get(tag, {}):
        pytest.fail(f"units section errored: {sec[tag]['error']}")
    divs = sec[tag]["units"]["divisions"]
    assert divs, "no divisions in save"
    named = [d for d in divs if d.get("name")]
    assert named, "no division carried a reconstructed name"


def test_format_rendering(cn):
    tag = "GER" if "GER" in cn.by_tag else cn.tags()[0]
    cn._cur_tag = tag
    sec = country_sections(cn, tag, ["focus"])
    txt = format_sections(tag, sec.get(tag, {}))
    assert "== " in txt and "available[" in txt
