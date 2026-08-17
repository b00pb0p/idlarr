#!/usr/bin/env python3
"""Tests for tools/demo-seed.py.

It is a contributor tool, not shipped code, but it duplicates one thing that
must not drift: the password hash format. If app.hash_password() changes and
the seeder does not, the demo boots with credentials nobody can log in with —
and the person hitting that is someone trying to contribute a screenshot.

Run:  .venv/bin/python -m pytest test_demo_seed.py -q
"""

import importlib.util
import os
import re
import sqlite3
import tempfile
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-demo-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "demo_seed", Path(__file__).resolve().parent.parent / "tools" / "demo-seed.py")
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)


@pytest.fixture
def seeded(tmp_path):
    demo.main(tmp_path)
    return tmp_path


def test_the_seeded_password_actually_works(seeded):
    """The drift guard. A hash format change in app.py must fail here, not
    hand someone a demo they cannot sign into."""
    conn = sqlite3.connect(seeded / "data" / "idlarr.db")
    stored = dict(conn.execute("SELECT k, v FROM state").fetchall())
    conn.close()
    assert app.verify_password(demo.DEMO_PASSWORD, stored["auth_hash"])
    assert not app.verify_password("wrong-password", stored["auth_hash"])
    assert stored["auth_user"] == demo.DEMO_USER
    assert stored["auth_method"] == "forms"


def test_the_demo_boots_without_the_no_signin_banner(seeded, monkeypatch):
    monkeypatch.setattr(app, "DB_PATH", seeded / "data" / "idlarr.db")
    monkeypatch.setattr(app, "CONFIG_PATH", seeded / "config" / "trackers.yml")
    app._cfg_cache["data"] = None
    assert app.auth_method() == "forms"
    assert app.userscript_version_peek() != "not served yet"
    app._cfg_cache["data"] = None


def test_every_state_on_the_ladder_is_represented(seeded, monkeypatch):
    """A screenshot of twelve green rows shows nothing. The point of the demo
    data is that one row sits on each rung."""
    monkeypatch.setattr(app, "DB_PATH", seeded / "data" / "idlarr.db")
    monkeypatch.setattr(app, "CONFIG_PATH", seeded / "config" / "trackers.yml")
    app._cfg_cache["data"] = None
    states = {r["state"] for r in app.statuses()}
    # Derived from RANK, not a written-out list. The hardcoded set omitted
    # `snoozed` and passed anyway, so the fixture claimed every rung while
    # missing one; adding a tenth state would have gone the same way.
    assert states == set(app.RANK), \
        f"the demo never shows: {sorted(set(app.RANK) - states)}"
    app._cfg_cache["data"] = None


def test_the_snooze_date_is_computed_not_hardcoded(seeded):
    """A literal date in demo-trackers.yml would rot: the demo would show
    `snoozed` for a while and then quietly stop, which is exactly the drift
    that made a reused demo database show four empty rungs."""
    import datetime
    raw = (seeded / "config" / "trackers.yml").read_text()
    assert "__SNOOZE__" not in raw, "the placeholder was never substituted"
    m = re.search(r'snooze_until:\s*"(\d{4}-\d{2}-\d{2})"', raw)
    assert m, "no snoozed tracker in the demo config"
    assert datetime.date.fromisoformat(m.group(1)) > datetime.date.today(), \
        "the demo ships a snooze date that has already passed"


def test_the_demo_config_names_no_real_tracker(seeded):
    """It exists so nobody publishes their own membership list."""
    cfg = yaml.safe_load((seeded / "config" / "trackers.yml").read_text())
    hosts = [t.get("url", "") for t in cfg["trackers"]]
    assert all(".example/" in u for u in hosts), hosts
    assert len(cfg["trackers"]) == 12
