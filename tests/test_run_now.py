#!/usr/bin/env python3
"""Running the daily check by hand, and the extraction that made it possible.

run_daily_check() came out of the `while True` in scheduler() so it could have
a second caller. The risk in that move is the scheduler quietly losing its
call, which no other test would notice, so that is pinned here too.

Run:  .venv/bin/python -m pytest tests/test_run_now.py -q
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-runnow-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    monkeypatch.setattr(app, "BACKUP_DIR", tmp_path / "backups")
    app._cfg_cache["data"] = None
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
    yield path
    app._cfg_cache["data"] = None


@pytest.fixture
def client(cfg):
    return TestClient(app.app)


@pytest.fixture
def quiet(monkeypatch):
    """No real pushes. notify() is covered by its own tests."""
    sent = []

    async def fake(rows):
        sent.append(rows)
    monkeypatch.setattr(app, "notify", fake)
    return sent


# --------------------------------------------------------- what it records

def test_it_counts_as_todays_run(cfg, quiet):
    """Deliberate. The manual run really did evaluate the day, so letting the
    scheduled one fire again would mean two rounds of pushes for one day."""
    today = datetime.now(app.local_tz()).date().isoformat()
    asyncio.run(app.run_daily_check(today, by_hand=True))
    assert app.get_state("last_check") == today


def test_the_panel_stops_promising_a_run_today(cfg, quiet):
    """The user-visible half of the line above: after Run now, the next-run
    line must flip to tomorrow, or it promises a run that will not happen."""
    today = datetime.now(app.local_tz()).date().isoformat()
    assert app.next_check()[0] != f"runs tomorrow at {app.load_config()['check_hour']:02d}:00"
    asyncio.run(app.run_daily_check(today, by_hand=True))
    text, overdue = app.next_check()
    assert text.startswith("runs tomorrow") and not overdue


def test_a_hand_run_is_labelled_and_a_scheduled_one_is_not(cfg, quiet):
    """Same distinction as auth_source on a tracker row: a run someone asked
    for is different evidence from one that happened on its own."""
    asyncio.run(app.run_daily_check("2026-08-06", by_hand=True))
    assert "by hand" in app.read_activity("check")["detail"]

    asyncio.run(app.run_daily_check("2026-08-07"))
    assert "by hand" not in app.read_activity("check")["detail"]


def test_a_failed_backup_does_not_stop_the_alert(cfg, quiet, monkeypatch):
    """The invariant that made backup_db() run first and inside a try. It moved
    functions in this change, which is exactly when an invariant gets dropped.
    """
    def boom(today):
        raise OSError("disk full")
    monkeypatch.setattr(app, "backup_db", boom)

    asyncio.run(app.run_daily_check("2026-08-06", by_hand=True))
    assert app.read_activity("backup")["ok"] is False
    assert len(quiet) == 1, "the alert did not run after a backup failure"
    assert app.get_state("last_check") == "2026-08-06"


# ------------------------------------------------------------- the endpoint

def test_the_endpoint_runs_it(client, quiet):
    r = client.post("/api/check")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert len(quiet) == 1


def test_it_needs_the_ui_login_when_one_is_set(client, quiet):
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    assert client.post("/api/check").status_code == 401
    assert not quiet, "it ran anyway"


def test_the_read_only_key_cannot_trigger_it(client, quiet):
    """It writes: a snapshot, last_check, and real pushes to your phone."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    r = client.post("/api/check", headers={"X-Api-Key": app.api_key()})
    assert r.status_code == 401
    assert not quiet


def test_a_second_run_while_one_is_going_is_refused(cfg):
    """A double-click, or a click landing on the check hour. Without the lock
    each one backs up, evaluates and sends the day's alerts again.

    Driven in one event loop against the endpoint directly. An earlier version
    raced two TestClient calls in threads, and TestClient runs each request in
    its OWN loop, so the first had already finished by the time the second
    went out: it asserted the lock while never actually holding it.
    """
    from fastapi import HTTPException

    async def drive():
        async with app.check_lock:                  # a run is in progress
            try:
                # Bounded on purpose. Without the guard, api_check() does not
                # return an error, it WAITS on the lock the test is holding, so
                # an unbounded await here hangs the suite instead of failing it.
                await asyncio.wait_for(app.api_check(), timeout=2)
            except HTTPException as exc:
                return exc.status_code
            except asyncio.TimeoutError:
                return "blocked on the lock instead of refusing"
            return "ran a second check"

    assert asyncio.run(drive()) == 409


# ----------------------------------------------- the extraction did not orphan

def test_the_scheduler_still_calls_it(cfg, monkeypatch):
    """The whole risk of pulling this out of the `while True`. Every test above
    calls run_daily_check() directly, so the scheduler could stop calling it
    and they would all stay green while the service silently never checked.
    """
    calls = []

    async def fake(today, by_hand=False):
        calls.append((today, by_hand))
    monkeypatch.setattr(app, "run_daily_check", fake)

    class Stop(Exception):
        pass

    async def stop_after_one_tick(_):
        raise Stop
    monkeypatch.setattr(app.asyncio, "sleep", stop_after_one_tick)

    cfgd = dict(app.load_config())
    cfgd["check_hour"] = 0                      # always past the hour
    monkeypatch.setattr(app, "load_config", lambda: cfgd)
    app.set_state("last_check", "2000-01-01")   # and not yet run today

    with pytest.raises(Stop):
        asyncio.run(app.scheduler())

    assert len(calls) == 1, "the scheduler no longer runs the daily check"
    assert calls[0][1] is False, "a scheduled run must not be labelled by hand"


def test_the_scheduler_yields_to_a_manual_run(cfg, monkeypatch):
    """Both take the same lock. If the scheduler ignored it, a click landing on
    the check hour would send the day's alerts twice."""
    calls = []

    async def fake(today, by_hand=False):
        calls.append(today)
    monkeypatch.setattr(app, "run_daily_check", fake)

    class Stop(Exception):
        pass

    async def stop_after_one_tick(_):
        raise Stop
    monkeypatch.setattr(app.asyncio, "sleep", stop_after_one_tick)

    cfgd = dict(app.load_config())
    cfgd["check_hour"] = 0
    monkeypatch.setattr(app, "load_config", lambda: cfgd)
    app.set_state("last_check", "2000-01-01")

    async def drive():
        async with app.check_lock:              # pretend a manual run is going
            try:
                # Bounded for the same reason as the test above: a scheduler
                # that ignores the lock does not run a second check, it WAITS
                # on one, so an unbounded await hangs rather than fails.
                await asyncio.wait_for(app.scheduler(), timeout=2)
            except Stop:
                return "skipped the tick"
            except asyncio.TimeoutError:
                return "blocked on the lock"
            return "returned unexpectedly"

    assert asyncio.run(drive()) == "skipped the tick"
    assert calls == [], "the scheduler ran a check while one was in progress"


# ---------------------------------------------------------------- the panel

def test_the_button_reaches_the_panel(cfg):
    """Pins the call site. The endpoint passing its own tests proves nothing if
    nothing on the page posts to it."""
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert 'id="ckrun"' in html
    assert "/api/check" in app.PAGE
