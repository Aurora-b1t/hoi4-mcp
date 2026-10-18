"""TechDB from the game's common/technologies + prereq-graph derivations."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def tdb(game_install):
    from hoi4_mcp.readstate.techdata import TechDB
    return TechDB()


def test_db_has_core_techs(tdb):
    d = tdb.db()
    assert "infantry_weapons" in d
    assert d["infantry_weapons"]["leads_to"], "leads_to graph empty"


def test_parents_graph(tdb):
    parents = tdb.parents()
    assert "infantry_weapons" in parents.get("infantry_weapons1", [])


def test_available_filters_roots_by_done(tdb):
    rows = tdb.available(set(), year=1936)      # empty done: only roots
    for r in rows:
        assert not parents_unmet(tdb, r["tech"], set())
    # done infantry_weapons -> infantry_weapons1 becomes available
    rows2 = tdb.available({"infantry_weapons"}, year=1936)
    ids = {r["tech"] for r in rows2}
    assert "infantry_weapons1" in ids
    assert "infantry_weapons" not in ids


def parents_unmet(tdb, tech, done) -> set:
    return {p for p in tdb.parents().get(tech, ()) if p not in done}


def test_sp_and_hidden_gated_out(tdb):
    rows = tdb.available(set(), year=1936)
    for r in rows:
        row = tdb.get(r["tech"])
        assert not row["sp_gated"]
        assert not row["hidden"]
