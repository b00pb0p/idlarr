#!/usr/bin/env python3
"""Tests for the still-alive heartbeat and the defaults writeback.

The heartbeat exists because nothing else watches the watchdog: if the
container dies, the daily check and the nightly backup both stop and neither
absence is visible. Silence reads exactly like "nothing is due" — which is the
one thing this service must never be ambiguous about.

Run:  .venv/bin/python -m pytest tests/test_alive.py -q
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-alive-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"
TZ = ZoneInfo("America/Chicago")


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


@pytest.fixture
def sent(monkeypatch):
    """Capture dispatch() calls instead of sending."""
    calls = []
    monkeypatch.setattr(app, "dispatch",
                        lambda t, b, p: (calls.append((t, b, p)), (True, ""))[1])
    return calls


def run(cfg_dict, now):
    return asyncio.run(app.maybe_alive_push(cfg_dict, now))


NOON = datetime(2026, 8, 4, 12, 0, tzinfo=TZ)


# ------------------------------------------------------------- heartbeat

def test_disabled_by_default(cfg, sent):
    """Opt-in. An extra weekly push is a real cost for anyone who does not
    want it, and unrequested notifications are how people learn to ignore
    the ones that matter."""
    assert app.load_config()["alive_push_days"] == 0
    assert run({"alive_push_days": 0, "check_hour": 9}, NOON) is False
    assert sent == []


def test_sends_when_enabled_and_never_sent_before(cfg, sent):
    assert run({"alive_push_days": 7, "check_hour": 9}, NOON) is True
    assert len(sent) == 1
    title, body, prio = sent[0]
    assert "still alive" in title.lower()
    assert "Watching" in body


def test_does_not_send_again_within_the_interval(cfg, sent):
    run({"alive_push_days": 7, "check_hour": 9}, NOON)
    assert run({"alive_push_days": 7, "check_hour": 9},
               NOON + timedelta(days=6)) is False
    assert len(sent) == 1


def test_sends_again_once_the_interval_has_passed(cfg, sent):
    run({"alive_push_days": 7, "check_hour": 9}, NOON)
    assert run({"alive_push_days": 7, "check_hour": 9},
               NOON + timedelta(days=7)) is True
    assert len(sent) == 2


def test_waits_for_check_hour(cfg, sent):
    """Sharing the daily check's hour keeps all scheduled noise together
    rather than arriving at whatever time the container happened to boot."""
    early = NOON.replace(hour=3)
    assert run({"alive_push_days": 7, "check_hour": 9}, early) is False
    assert sent == []


def test_a_failed_send_is_not_recorded_as_sent(cfg, monkeypatch):
    """Recording a failure as sent would suppress the next heartbeat too —
    turning one lost push into a silent week, which is the exact failure this
    feature exists to detect."""
    monkeypatch.setattr(app, "dispatch", lambda t, b, p: (False, "refused"))
    assert run({"alive_push_days": 7, "check_hour": 9}, NOON) is False
    assert not app.get_state("last_alive_push")


def test_body_names_the_closest_tracker(cfg, sent):
    app.record("alpha", "auth")
    run({"alive_push_days": 7, "check_hour": 9}, NOON)
    assert "Closest:" in sent[0][1]


def test_unparseable_timestamp_is_treated_as_never_sent(cfg, sent):
    """A corrupt state row must not silence the heartbeat forever."""
    app.set_state("last_alive_push", "not-a-date")
    assert run({"alive_push_days": 7, "check_hour": 9}, NOON) is True


# ------------------------------------------------------- defaults writeback

def test_sets_a_default(cfg):
    app.save_default_field("check_hour", 6)
    assert yaml.safe_load(cfg.read_text())["defaults"]["check_hour"] == 6


def test_defaults_edit_keeps_comments_and_trackers(cfg):
    before = len(yaml.safe_load(cfg.read_text())["trackers"])
    app.save_default_field("timezone", "Europe/Berlin")
    text = cfg.read_text()
    assert "FAIL-SAFE PLACEHOLDER" in text
    assert len(yaml.safe_load(text)["trackers"]) == before


def test_a_missing_key_is_inserted(cfg):
    """alive_push_days is not in existing configs, so setting it must add the
    line rather than silently doing nothing."""
    assert "alive_push_days" not in cfg.read_text()
    app.save_default_field("alive_push_days", 7)
    assert yaml.safe_load(cfg.read_text())["defaults"]["alive_push_days"] == 7
    app._cfg_cache["data"] = None
    assert app.load_config()["alive_push_days"] == 7


def test_unknown_keys_are_refused(cfg):
    """The allow-list stops a typo or a hostile payload writing arbitrary YAML
    into the defaults block."""
    with pytest.raises(KeyError):
        app.save_default_field("trackers", "nonsense")
    with pytest.raises(KeyError):
        app.save_default_field("../../etc/passwd", 1)


# ------------------------------------------------------------- the endpoint

@pytest.fixture
def client(cfg):
    from fastapi.testclient import TestClient
    return TestClient(app.app)


def test_settings_endpoint_writes_all_four(client, cfg):
    r = client.post("/api/settings", json={"timezone": "Europe/Berlin",
                                           "check_hour": 6,
                                           "alert_at_pct": 0.5,
                                           "alive_push_days": 7})
    assert r.status_code == 200
    doc = yaml.safe_load(cfg.read_text())["defaults"]
    assert doc["timezone"] == "Europe/Berlin"
    assert doc["check_hour"] == 6
    assert doc["alert_at_pct"] == 0.5
    assert doc["alive_push_days"] == 7


@pytest.mark.parametrize("payload", [
    {"timezone": "Not/AZone"},
    {"check_hour": 24}, {"check_hour": -1}, {"check_hour": "noon"},
    {"alert_at_pct": 0.2}, {"alert_at_pct": 1.5}, {"alert_at_pct": "half"},
    {"alive_push_days": -1}, {"alive_push_days": 500},
    {},
])
def test_settings_endpoint_validates(client, payload):
    """These drive day counting and alert timing. A bad value is not a crash —
    it is a countdown that reads plausibly and fires at the wrong time."""
    assert client.post("/api/settings", json=payload).status_code == 400


def test_a_rejected_value_writes_nothing(client, cfg):
    before = cfg.read_text()
    client.post("/api/settings", json={"check_hour": 99})
    assert cfg.read_text() == before


def test_settings_need_auth_when_configured(client, cfg):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    assert client.post("/api/settings", json={"check_hour": 6}).status_code == 401
