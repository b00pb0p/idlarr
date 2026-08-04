#!/usr/bin/env python3
"""Tests for snooze, the per-tracker alert threshold, and config download.

Snooze exists because trackers have vacation modes and accounts get parked, and
the only tool for that was `immune: true` — which is PERMANENT. Forgetting to
undo it silently stops watching an account you still care about, which is the
failure this whole service exists to prevent. A snooze expires by itself.

Run:  .venv/bin/python -m pytest tests/test_snooze.py -q
"""

import os
import shutil
import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-snooze-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"
NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    app._cfg_cache["data"] = None
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM state")
    yield path
    app._cfg_cache["data"] = None


def tracker(**over):
    base = {"id": "alpha", "name": "Alpha", "inactivity_days": 30,
            "alert_at_pct": 0.65, "immune": False, "immune_reason": "",
            "snooze_until": "", "url": "", "notes": "", "verified": False}
    base.update(over)
    return base


# --------------------------------------------------------------- the ladder

def test_a_future_snooze_suppresses_alerts(cfg):
    """An expired tracker would normally be `urgent`. Snoozed, it must not
    alert at all — that is the entire point."""
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts=? WHERE tracker_id='alpha'",
                     ((NOW - timedelta(days=40)).isoformat(),))
    soon = (date(2026, 8, 4) + timedelta(days=14)).isoformat()
    out = app.evaluate(tracker(snooze_until=soon), now=NOW)
    assert out["state"] == "snoozed"
    assert out["priority"] is None
    assert soon in out["reason"]


def test_the_countdown_is_still_visible_while_snoozed(cfg):
    """Suppressing the alert must not hide the numbers — you still need to know
    when the account actually expires while deciding whether to extend."""
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts=? WHERE tracker_id='alpha'",
                     ((NOW - timedelta(days=10)).isoformat(),))
    soon = (date(2026, 8, 4) + timedelta(days=5)).isoformat()
    out = app.evaluate(tracker(snooze_until=soon), now=NOW)
    assert out["days_since"] == 10
    assert out["days_left"] == 20


def test_a_past_snooze_is_ignored(cfg):
    """It must expire BY ITSELF. A snooze that outlived its date and kept
    suppressing would be exactly the silent failure `immune` risks."""
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts=? WHERE tracker_id='alpha'",
                     ((NOW - timedelta(days=40)).isoformat(),))
    past = (date(2026, 8, 4) - timedelta(days=1)).isoformat()
    out = app.evaluate(tracker(snooze_until=past), now=NOW)
    assert out["state"] == "expired"
    assert out["priority"] == "urgent"


def test_snoozing_today_still_counts(cfg):
    app.record("alpha", "auth")
    out = app.evaluate(tracker(snooze_until="2026-08-04"), now=NOW)
    assert out["state"] == "snoozed"


def test_immune_still_outranks_snooze(cfg):
    out = app.evaluate(tracker(immune=True, snooze_until="2026-12-01"), now=NOW)
    assert out["state"] == "immune"


def test_a_malformed_date_does_not_suppress(cfg):
    """A typo must fail SAFE — keep alerting rather than silently muting."""
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts=? WHERE tracker_id='alpha'",
                     ((NOW - timedelta(days=40)).isoformat(),))
    out = app.evaluate(tracker(snooze_until="next tuesday"), now=NOW)
    assert out["state"] == "expired"


def test_snoozed_rows_are_excluded_from_the_alert(cfg):
    rows = [app.evaluate(tracker(snooze_until="2026-12-01"), now=NOW)]
    assert app.build_notification(rows) is None


# --------------------------------------------------------------- the API

@pytest.fixture
def client(cfg):
    return TestClient(app.app)


def test_api_sets_and_clears_a_snooze(client, cfg):
    until = (date.today() + timedelta(days=14)).isoformat()
    r = client.post("/api/limit/alpha", json={"snooze_until": until})
    assert r.status_code == 200 and r.json()["snooze_until"] == until
    assert yaml.safe_load(cfg.read_text())["trackers"][0]["snooze_until"] == until
    r = client.post("/api/limit/alpha", json={"snooze_until": ""})
    assert r.json()["snooze_until"] == ""


@pytest.mark.parametrize("bad", ["not-a-date", "2026-13-01", "04/08/2026"])
def test_api_rejects_a_bad_snooze_date(client, bad):
    assert client.post("/api/limit/alpha",
                       json={"snooze_until": bad}).status_code == 400


def test_api_refuses_a_snooze_longer_than_a_year(client):
    """Past a year you want `immune`, which says so on the row instead of
    hiding a countdown behind a date nobody will revisit."""
    far = (date.today() + timedelta(days=400)).isoformat()
    assert client.post("/api/limit/alpha",
                       json={"snooze_until": far}).status_code == 400


def test_snooze_survives_in_config_with_comments(client, cfg):
    until = (date.today() + timedelta(days=7)).isoformat()
    client.post("/api/limit/alpha", json={"snooze_until": until})
    assert "FAIL-SAFE PLACEHOLDER" in cfg.read_text()


# ----------------------------------------------- per-tracker alert threshold

def test_per_tracker_threshold_is_written(client, cfg):
    r = client.post("/api/limit/alpha", json={"alert_at_pct": 0.5})
    assert r.status_code == 200
    assert yaml.safe_load(cfg.read_text())["trackers"][0]["alert_at_pct"] == 0.5


@pytest.mark.parametrize("bad", [0.1, 1.5, "half"])
def test_per_tracker_threshold_is_range_checked(client, bad):
    assert client.post("/api/limit/alpha",
                       json={"alert_at_pct": bad}).status_code == 400


def test_lowering_the_threshold_makes_due_reachable(cfg):
    """The documented reason this exists: on a 30-day limit, `due` at 0.65
    never fires before `warn` does. Lowering it per-tracker fixes that without
    making a 365-day tracker nag for months."""
    app.record("alpha", "auth")
    with app.db() as conn:
        conn.execute("UPDATE events SET ts=? WHERE tracker_id='alpha'",
                     ((NOW - timedelta(days=13)).isoformat(),))
    assert app.evaluate(tracker(inactivity_days=30, alert_at_pct=0.65),
                        now=NOW)["state"] == "ok"
    assert app.evaluate(tracker(inactivity_days=30, alert_at_pct=0.4),
                        now=NOW)["state"] == "due"


# --------------------------------------------------------------- download

def test_config_download_is_byte_identical(client, cfg):
    r = client.get("/api/config")
    assert r.status_code == 200
    assert r.text == cfg.read_text()
    assert "FAIL-SAFE PLACEHOLDER" in r.text
    assert "attachment" in r.headers["content-disposition"]


def test_config_download_needs_auth_when_configured(client):
    """It contains your full tracker list — the thing the README says not to
    publish."""
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    assert client.get("/api/config").status_code == 401
