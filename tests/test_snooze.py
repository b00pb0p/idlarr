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


# --------------------------------------------------------- config restore
#
# Replacing trackers.yml is the most destructive operation here: it overwrites
# the source of truth for every countdown. It validates hard and backs up first.

def test_restore_replaces_and_backs_up(client, cfg):
    new_cfg = ("defaults:\n  inactivity_days: 30\n  timezone: UTC\n"
               "  check_hour: 9\n\ntrackers:\n  - id: solo\n    name: Solo\n"
               "    url: https://solo.example/\n    inactivity_days: 60\n")
    r = client.post("/api/config", json={"yaml": new_cfg})
    assert r.status_code == 200
    body = r.json()
    assert body["before"] == 7 and body["after"] == 1
    assert [t["id"] for t in yaml.safe_load(cfg.read_text())["trackers"]] == ["solo"]
    # the previous file must still exist, or a bad restore is unrecoverable
    backups = list(cfg.parent.glob(f"{cfg.name}.*.bak"))
    assert len(backups) == 1
    assert len(yaml.safe_load(backups[0].read_text())["trackers"]) == 7


@pytest.mark.parametrize("bad,why", [
    ("not: [valid", "unparseable YAML"),
    ("- just\n- a\n- list\n", "top level is not a mapping"),
    ("trackers: 5\n", "trackers is not a list"),
    ("trackers:\n  - name: no id\n", "tracker without an id"),
    ("trackers:\n  - id: 'Bad Id!'\n", "unusable id"),
    ("trackers:\n  - id: dup\n  - id: dup\n", "duplicate ids"),
    ("trackers:\n  - id: a\n    inactivity_days: 0\n", "limit out of range"),
    ("trackers:\n  - id: a\n    inactivity_days: soon\n", "limit not a number"),
    ("defaults:\n  timezone: Not/AZone\ntrackers: []\n", "bad timezone"),
    ("", "empty"),
])
def test_restore_refuses_bad_input(client, cfg, bad, why):
    before = cfg.read_text()
    assert client.post("/api/config", json={"yaml": bad}).status_code == 400, why
    assert cfg.read_text() == before, f"wrote anyway: {why}"


def test_restore_keeps_events_so_history_survives(client, cfg):
    """Removed trackers keep their events, so restoring an older config
    restores its history rather than silently restarting those countdowns."""
    app.record("alpha", "auth")
    client.post("/api/config", json={
        "yaml": "trackers:\n  - id: solo\n    name: Solo\n"})
    with app.db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE tracker_id='alpha'").fetchone()["c"]
    assert n == 1


def test_restore_needs_auth_when_configured(client, cfg):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    before = cfg.read_text()
    assert client.post("/api/config",
                       json={"yaml": "trackers: []\n"}).status_code == 401
    assert cfg.read_text() == before
