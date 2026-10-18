"""FocusDB: national_focus parsing + availability derivation (20日 work)."""

from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def fdb(game_install):
    from hoi4_mcp.readstate.focusdata import FocusDB
    return FocusDB()


def test_focus_volume(fdb):
    d = fdb.db()
    assert len(d) > 9000, f"suspiciously few focuses parsed ({len(d)})"
    assert len(fdb.trees()) >= 50


def test_four_year_plan_row(fdb):
    row = fdb.get("GER_the_four_year_plan")
    assert row is not None
    assert row["tree"] == "german_focus"
    assert row["cost"] == 5.0
    assert row["mutex"] == ["GER_prioritize_economic_growth"]
    assert row["prereq_blocks"] == []


def test_prereq_graph(fdb):
    row = fdb.get("GER_autarky_efforts")
    assert row and ["GER_the_four_year_plan"] in row["prereq_blocks"]
    # multi-focus prerequisite blocks serialize as OR semantics
    or_blocks = [r for r in fdb.db().values()
                 for blk in r["prereq_blocks"] if len(blk) > 1]
    assert or_blocks, "expected OR prerequisite blocks somewhere"


def test_available_filtering(fdb):
    done = {"GER_the_four_year_plan"}
    used = {"german_focus": {"GER"}, "generic_focus": set()}
    rows = fdb.available(done, tag="GER", used_trees=used)
    ids = {r["focus"] for r in rows}
    # immediate GER successors show with their satisfied prereqs
    assert "GER_autarky_efforts" in ids
    row = next(r for r in rows if r["focus"] == "GER_autarky_efforts")
    assert row["prereqs"] == ["GER_the_four_year_plan"]
    # other countries' tree roots never leak in
    nor = [i for i in ids if i.startswith(("NOR_", "SOV_", "FRA_"))]
    assert not nor, f"foreign tree roots leaked: {nor[:5]}"


def test_est_days_banked(fdb):
    done = {"GER_the_four_year_plan"}
    used = {"german_focus": {"GER"}, "generic_focus": set()}
    rows = fdb.available(done, tag="GER", used_trees=used, banked=10.0)
    by_id = {r["focus"]: r for r in rows}
    # cost 5 -> 35 days minus 10 banked = 25; cost 10 -> 60
    assert by_id["GER_autarky_efforts"]["est_days"] == 25.0
    assert by_id["army_effort"]["est_days"] == 60.0


def test_mutually_exclusive_blocks(fdb):
    used = {"german_focus": {"GER"}, "generic_focus": set()}
    done = {"GER_the_four_year_plan", "GER_prioritize_economic_growth"}
    ids = {r["focus"] for r in
           fdb.available(done, tag="GER", used_trees=used)}
    # prioritize_economic_growth completed -> its mutex stays hidden anyway
    # (not completed), but the four_year_plan side must not reappear either
    assert "GER_the_four_year_plan" not in ids
