#!/usr/bin/env python3
"""Tests for the recent-activity block.

The daily check, the backup, the alert and the heartbeat all run unattended,
and each can fail leaving no trace on screen — a failed backup and a successful
one look identical from the dashboard. This records each outcome so "did last
night work?" does not require a shell.

Run:  .venv/bin/python -m pytest tests/test_activity.py -q
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-act-")
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
    app._cfg_cache["data"] = None
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
        conn.execute("DELETE FROM events")
    yield path
    app._cfg_cache["data"] = None


def test_round_trip(cfg):
    app.note_activity("backup", True, "idlarr-2026-08-04.db (24 KB)")
    a = app.read_activity("backup")
    assert a["ok"] is True
    assert a["detail"] == "idlarr-2026-08-04.db (24 KB)"
    assert len(a["at"]) == 16          # YYYY-MM-DD HH:MM


def test_unset_reads_as_none(cfg):
    assert app.read_activity("backup") is None


def test_corrupt_row_does_not_crash_the_page(cfg):
    """A bad state row must not take the settings panel down — that would turn
    a cosmetic problem into an outage."""
    app.set_state("act_backup", "{not json")
    assert app.read_activity("backup") is None


def test_a_failed_alert_is_recorded_as_failed(cfg, monkeypatch):
    """The case that matters. A refused push previously left nothing on screen
    and the dashboard looked identical to a healthy night."""
    monkeypatch.setattr(app, "NOTIFY_URLS", ["json://localhost/"])
    monkeypatch.setattr(app, "dispatch", lambda t, b, p: (False, "403 forbidden"))
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts='2020-01-01T00:00:00+00:00'")
    asyncio.run(app.notify(app.statuses()))
    a = app.read_activity("alert")
    assert a["ok"] is False
    assert "403 forbidden" in a["detail"]


def test_nothing_due_still_counts_as_a_successful_run(cfg, monkeypatch):
    """A quiet night is a healthy night, not a missing one. Recording it is
    what makes 'never' meaningful for an install that has been up for days."""
    monkeypatch.setattr(app, "NOTIFY_URLS", ["json://localhost/"])
    asyncio.run(app.notify(app.statuses()))
    a = app.read_activity("alert")
    assert a["ok"] is True and a["detail"] == "nothing due"


def test_a_failed_heartbeat_is_recorded(cfg, monkeypatch):
    monkeypatch.setattr(app, "dispatch", lambda t, b, p: (False, "refused"))
    now = datetime(2026, 8, 4, 12, 0, tzinfo=ZoneInfo("America/Chicago"))
    asyncio.run(app.maybe_alive_push({"alive_push_days": 7, "check_hour": 9}, now))
    a = app.read_activity("heartbeat")
    assert a["ok"] is False and "refused" in a["detail"]


def test_the_panel_shows_never_before_anything_has_run(cfg, monkeypatch):
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
    page = TestClient(app.app).get("/").text
    assert "Daily check" in page and "Nightly backup" in page
    # The activity row must not reuse the settings row's label, or the panel
    # shows two "Still-alive push" rows meaning different things.
    assert "Last heartbeat" in page
    assert page.count("Still-alive push") == 1
    assert page.count(">never<") >= 4


def test_the_panel_shows_outcomes_once_recorded(cfg, monkeypatch):
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
    app.note_activity("backup", False, "disk full")
    page = TestClient(app.app).get("/").text
    assert "disk full" in page
    assert 'class="val off"' in page       # rendered as a failure, not a fact


def test_detail_is_escaped(cfg, monkeypatch):
    """Failure text comes from exceptions and provider responses, which are not
    ours to trust."""
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
    app.note_activity("backup", False, '<img src=x onerror=alert(1)>')
    page = TestClient(app.app).get("/").text
    assert "<img src=x" not in page
    assert "&lt;img src=x" in page
