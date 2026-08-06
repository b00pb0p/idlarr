#!/usr/bin/env python3
"""Tests for evaluate() — the state ladder.

CLAUDE.md: "There is no test file; add one if you touch evaluate()." This is
that file, written when window_days was renamed to inactivity_days.

Run:  .venv/bin/python -m pytest test_evaluate.py -q
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Point the module at throwaway paths BEFORE importing it — app.py reads these
# at import time.
_tmp = tempfile.mkdtemp(prefix="idlarr-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")

import app  # noqa: E402

NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def fresh_db():
    """Each test gets an empty events table."""
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM state")
    yield


def tracker(**over):
    """A tracker dict shaped like load_config() produces."""
    base = {
        "id": "testsite",
        "name": "TestSite",
        "inactivity_days": 30,
        "alert_at_pct": 0.65,
        "verified": False,
        "immune": False,
        "immune_reason": "",
        "notes": "",
        "url": "",
    }
    return {**base, **over}


def seen(kind, days_ago, tracker_id="testsite"):
    """Insert an event at a fixed offset from NOW."""
    ts = (NOW - timedelta(days=days_ago)).isoformat()
    with app.db() as conn:
        conn.execute(
            "INSERT INTO events (tracker_id, kind, ts, source) VALUES (?,?,?,?)",
            (tracker_id, kind, ts, "test"),
        )


# ------------------------------------------------------------------ the ladder

def test_unknown_when_no_auth_ever():
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "unknown"
    assert out["priority"] is None
    assert out["days_left"] is None


def test_unknown_even_when_visits_exist():
    """A visit alone must never start the countdown."""
    seen("visit", 1)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "unknown"


def test_ok_when_fresh():
    seen("auth", 1)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "ok"
    assert out["priority"] is None
    assert out["days_left"] == 29


def test_due_at_alert_pct():
    """60 * 0.65 = 39, and 39 days left (21) is still clear of the 14d warn rung."""
    seen("auth", 39)
    out = app.evaluate(tracker(inactivity_days=60), NOW)
    assert out["state"] == "due"
    assert out["priority"] == "default"


def test_ok_just_below_alert_pct():
    seen("auth", 38)
    out = app.evaluate(tracker(inactivity_days=60), NOW)
    assert out["state"] == "ok"


def test_warn_at_14_days_left():
    seen("auth", 16)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "warn"
    assert out["priority"] == "high"
    assert out["days_left"] == 14


def test_critical_at_5_days_left():
    seen("auth", 25)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "critical"
    assert out["priority"] == "urgent"
    assert out["days_left"] == 5


def test_expired_at_zero():
    seen("auth", 30)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "expired"
    assert out["priority"] == "urgent"
    assert out["days_left"] == 0


def test_expired_past_zero():
    seen("auth", 40)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "expired"
    assert "10d ago" in out["reason"]


# ------------------------------------------------------------- session death

def test_session_beats_ok():
    """Recent visit + much older auth = dead cookie, regardless of days_left."""
    seen("auth", 10)
    seen("visit", 1)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "session"
    assert out["priority"] == "high"


def test_session_beats_expired():
    """stale_session is checked first — it's the more actionable diagnosis."""
    seen("auth", 60)
    seen("visit", 1)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "session"


def test_no_session_when_auth_is_recent():
    """Visited and authed on the same day is the healthy case."""
    seen("auth", 1)
    seen("visit", 1)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "ok"


def test_no_session_when_visit_is_stale():
    """Both old = you haven't been there, not a broken cookie."""
    seen("auth", 20)
    seen("visit", 10)
    out = app.evaluate(tracker(), NOW)
    assert out["state"] != "session"
    assert out["state"] == "warn"      # 30 - 20 = 10 days left


# ------------------------------------------------- inactivity_days is honored

def test_longer_limit_delays_escalation():
    """The renamed key must actually drive the maths."""
    seen("auth", 40)
    assert app.evaluate(tracker(inactivity_days=30), NOW)["state"] == "expired"
    assert app.evaluate(tracker(inactivity_days=90), NOW)["state"] == "ok"


def test_alert_pct_scales_with_limit():
    seen("auth", 40)
    out = app.evaluate(tracker(inactivity_days=60), NOW)
    assert out["state"] == "due"          # 60 * 0.65 = 39, and 40 >= 39
    assert out["days_left"] == 20


def test_events_are_scoped_per_tracker():
    """One tracker's auth must not satisfy another's countdown."""
    seen("auth", 1, tracker_id="othersite")
    out = app.evaluate(tracker(), NOW)
    assert out["state"] == "unknown"


# --------------------------------------------------- 'due' reachability

# The percentage rung is checked AFTER the absolute 14d/5d rungs, so 'due' only
# fires when some whole number of days satisfies both d >= 0.65*W and W - d > 14.
# In integers that first happens at W = 43. At the shipped placeholder of 30
# every tracker skips 'due' entirely and goes silent -> warn/high. This is
# recorded, not endorsed; see CLAUDE.md open item 7.

def test_due_is_unreachable_at_the_placeholder_limit():
    for days_since in range(0, 31):
        with app.db() as conn:
            conn.execute("DELETE FROM events")
        seen("auth", days_since)
        assert app.evaluate(tracker(inactivity_days=30), NOW)["state"] != "due"


def test_due_becomes_reachable_at_43():
    def reachable(W):
        for days_since in range(0, W + 1):
            with app.db() as conn:
                conn.execute("DELETE FROM events")
            seen("auth", days_since)
            if app.evaluate(tracker(inactivity_days=W), NOW)["state"] == "due":
                return True
        return False

    assert not reachable(42)
    assert reachable(43)


# ------------------------------------------------------------------- immunity

def test_immune_outranks_expired():
    """If pruning cannot touch the account, no countdown is meaningful."""
    seen("auth", 400)
    out = app.evaluate(tracker(immune=True), NOW)
    assert out["state"] == "immune"
    assert out["priority"] is None


def test_immune_outranks_session():
    seen("auth", 60)
    seen("visit", 0)
    assert app.evaluate(tracker(immune=True), NOW)["state"] == "immune"


def test_immune_with_no_events_is_still_immune():
    """Never 'unknown' — immunity does not depend on having bootstrapped."""
    out = app.evaluate(tracker(immune=True), NOW)
    assert out["state"] == "immune"
    assert out["days_since"] is None


def test_immune_still_reports_days_idle():
    seen("auth", 42)
    out = app.evaluate(tracker(immune=True), NOW)
    assert out["days_since"] == 42
    assert out["days_left"] is None      # a deadline would be a lie


def test_immune_reason_becomes_the_displayed_reason():
    out = app.evaluate(tracker(immune=True, immune_reason="Elite user class"), NOW)
    assert out["reason"] == "Elite user class"


def test_immune_without_reason_gets_a_default():
    assert app.evaluate(tracker(immune=True), NOW)["reason"]


def test_immune_never_notifies():
    """The whole point: an immune tracker must never reach the ntfy batch."""
    seen("auth", 400)
    rows = [app.evaluate(tracker(immune=True), NOW)]
    assert [r for r in rows if r["priority"]] == []


def test_clearing_immunity_restores_the_countdown():
    seen("auth", 400)
    assert app.evaluate(tracker(immune=False), NOW)["state"] == "expired"


# ------------------------------------------------------ calendar-day counting

def seen_at(kind, when, tracker_id="testsite"):
    with app.db() as conn:
        conn.execute(
            "INSERT INTO events (tracker_id, kind, ts, source) VALUES (?,?,?,?)",
            (tracker_id, kind, when.isoformat(), "test"))


def test_yesterday_evening_counts_as_one_day():
    """(now - auth).days would say 0 here — 18 hours is not a whole 24h period.

    That is how the row said 'today' while the drawer showed yesterday's date,
    and it also delayed every alert by up to a day.
    """
    seen_at("auth", NOW - timedelta(hours=18))
    out = app.evaluate(tracker(), NOW)
    assert (NOW - (NOW - timedelta(hours=18))).days == 0      # the old behavior
    assert out["days_since"] == 1                              # the new one
    assert out["days_left"] == 29


def test_one_minute_past_midnight_counts_as_a_day():
    tz = app.local_tz()
    local_now = NOW.astimezone(tz)
    midnight = local_now.replace(hour=0, minute=1, second=0, microsecond=0)
    seen_at("auth", midnight - timedelta(minutes=2))           # 23:59 yesterday
    out = app.evaluate(tracker(), midnight)
    assert out["days_since"] == 1


def test_same_day_earlier_is_still_zero():
    seen_at("auth", NOW - timedelta(hours=2))
    assert app.evaluate(tracker(), NOW)["days_since"] == 0


def test_elapsed_days_never_undercounts():
    """Sweep a day of offsets: calendar counting must always be >= the old
    24h-period count, never below it. Below would mean alerting later."""
    for hours in range(0, 49):
        earlier = NOW - timedelta(hours=hours)
        assert app.elapsed_days(NOW, earlier) >= (NOW - earlier).days


# --------------------------------------------------------- server-side dedupe

def ping(tracker_id, kind):
    """Replicate /ping's dedupe decision without the HTTP layer."""
    last, _ = app.last_event(tracker_id, kind)
    if last is not None and (NOW - last) < timedelta(hours=app.DEDUPE_HOURS):
        return False
    return True


def test_first_ping_records():
    assert ping("testsite", "auth") is True


def test_second_ping_within_window_is_deduped():
    seen("auth", 0)
    assert ping("testsite", "auth") is False


def test_ping_after_window_records_again():
    seen("auth", 1)      # 24h ago, window is 12h
    assert ping("testsite", "auth") is True


def test_dedupe_is_per_kind():
    """A recent visit must not suppress an auth."""
    seen("visit", 0)
    assert ping("testsite", "auth") is True


def test_dedupe_is_per_tracker():
    seen("auth", 0, tracker_id="othersite")
    assert ping("testsite", "auth") is True


def test_unmark_reopens_the_window_immediately():
    """The bug this replaced: deleting an event left the client believing it
    had reported, so the tracker went silent. Server-side dedupe self-heals."""
    seen("auth", 0)
    assert ping("testsite", "auth") is False
    app.drop_last_auth("testsite")
    assert ping("testsite", "auth") is True


# ---------------------------------------------------------------- backup

@pytest.fixture
def backup_dir(tmp_path, monkeypatch):
    d = tmp_path / "backups"
    monkeypatch.setattr(app, "BACKUP_DIR", d)
    monkeypatch.setattr(app, "backup_keep", lambda: 14)
    return d


def test_backup_writes_a_readable_copy(backup_dir):
    import sqlite3
    seen("auth", 3)
    dest = app.backup_db("2026-07-28")
    assert dest.exists() and dest.stat().st_size > 0
    rows = sqlite3.connect(dest).execute(
        "SELECT tracker_id, kind FROM events").fetchall()
    assert ("testsite", "auth") in rows      # a real snapshot, not an empty file


def test_backup_is_idempotent_for_one_day(backup_dir):
    seen("auth", 1)
    first = app.backup_db("2026-07-28")
    stamp = first.stat().st_mtime_ns
    again = app.backup_db("2026-07-28")
    assert again == first and again.stat().st_mtime_ns == stamp


def test_backup_prunes_to_the_retention_limit(backup_dir, monkeypatch):
    monkeypatch.setattr(app, "backup_keep", lambda: 3)
    seen("auth", 1)
    for day in range(1, 8):
        app.backup_db(f"2026-07-{day:02d}")
    kept = sorted(p.name for p in backup_dir.glob("idlarr-*.db"))
    assert len(kept) == 3
    assert kept == ["idlarr-2026-07-05.db", "idlarr-2026-07-06.db",
                    "idlarr-2026-07-07.db"]        # newest kept, oldest dropped


def test_backup_can_be_disabled(backup_dir, monkeypatch):
    monkeypatch.setattr(app, "backup_keep", lambda: 0)
    assert app.backup_db("2026-07-28") is None
    assert not backup_dir.exists()


def test_backup_leaves_no_tmp_file(backup_dir):
    seen("auth", 1)
    app.backup_db("2026-07-28")
    assert not list(backup_dir.glob("*.tmp"))


# ----------------------------------------------------------- fail-closed auth

def test_require_token_rejects_when_token_unset(monkeypatch):
    """The old code returned early here, silently disabling authentication."""
    monkeypatch.setattr(app, "TOKEN", "")
    with pytest.raises(app.HTTPException) as e:
        app.require_token("Bearer anything")
    assert e.value.status_code == 500


def test_require_token_rejects_a_wrong_token(monkeypatch):
    monkeypatch.setattr(app, "TOKEN", "correct")
    with pytest.raises(app.HTTPException) as e:
        app.require_token("Bearer wrong")
    assert e.value.status_code == 401


def test_require_token_rejects_a_missing_header(monkeypatch):
    monkeypatch.setattr(app, "TOKEN", "correct")
    with pytest.raises(app.HTTPException):
        app.require_token(None)


def test_require_token_accepts_the_right_token(monkeypatch):
    monkeypatch.setattr(app, "TOKEN", "correct")
    app.require_token("Bearer correct")          # must not raise


# ---------------------------------------------------- apprise fan-out

def test_apprise_severity_mapping():
    """Priorities must reach Apprise as its own severity names, so a phone
    shows an urgent alert differently from a routine one."""
    assert app.apprise_type("urgent") == "failure"
    assert app.apprise_type("high") == "warning"
    assert app.apprise_type("default") == "info"


def test_apprise_type_is_total():
    """Every priority the ladder can produce must map to something."""
    for p in ("default", "high", "urgent"):
        assert app.apprise_type(p) in ("info", "warning", "failure")
    assert app.apprise_type(None) == "info"        # never raises
    assert app.apprise_type("nonsense") == "info"


def test_notify_urls_parses_a_comma_list(monkeypatch):
    import importlib
    monkeypatch.setenv("IDLARR_NOTIFY_URLS",
                       " pover://user@token , discord://id/tok ,, tgram://bot/chat ")
    parsed = [u.strip() for u in os.environ["IDLARR_NOTIFY_URLS"].split(",") if u.strip()]
    assert parsed == ["pover://user@token", "discord://id/tok", "tgram://bot/chat"]


# ------------------------------------------------------------ notification

def row(**over):
    base = {"name": "TestSite", "reason": "3d left.", "priority": "high", "state": "warn"}
    return {**base, **over}


def test_no_payload_when_nothing_actionable():
    assert app.build_notification([row(priority=None)]) is None


def test_payload_is_json_serializable_with_non_ascii():
    """The bug this replaced: an em dash in a header crashed every push with
    UnicodeEncodeError, which looked identical to a quiet day."""
    import json
    p = app.build_notification([row(name="Alpha", reason="1d left — log in today.")])
    json.dumps(p)                       # would raise if not serializable
    assert "—" in p["title"]
    assert p["title"].encode("utf-8")    # body is UTF-8, not ASCII headers


def test_free_text_immune_reason_does_not_break_it():
    import json
    p = app.build_notification([row(name="Ünicode", reason="café — 50% off ✓")])
    json.dumps(p)
    assert "café" in p["body"]


def test_priority_is_carried_through_by_name():
    """Apprise maps the name to each service's own severity at send time."""
    assert app.build_notification([row(priority="urgent")])["priority"] == "urgent"
    assert app.build_notification([row(priority="high")])["priority"] == "high"
    assert app.build_notification([row(priority="default")])["priority"] == "default"


def test_worst_priority_wins():
    p = app.build_notification([row(priority="default"), row(priority="urgent"),
                                row(priority="high")])
    assert p["priority"] == "urgent"


def test_single_item_title_names_the_tracker():
    p = app.build_notification([row(name="Alpha", reason="2d left.")])
    assert p["title"].startswith("Alpha")


def test_many_items_batch_into_one_message():
    """23 separate pushes is how the user starts ignoring them."""
    rows = [row(name=f"T{i}") for i in range(23)]
    p = app.build_notification(rows)
    assert p["title"] == "23 trackers need a login"
    assert p["body"].count("\n") == 22


def test_status_url_is_in_the_body_not_a_click_action(monkeypatch):
    """Every service renders a URL in text; only some support tap targets."""
    monkeypatch.setattr(app, "status_url", lambda: "https://box.example/")
    p = app.build_notification([row()])
    assert p["body"].endswith("https://box.example/")

    monkeypatch.setattr(app, "status_url", lambda: "")
    assert "http" not in app.build_notification([row()])["body"]


# ------------------------------------------------------------------- ordering

def test_statuses_sorts_worst_first():
    order = {"expired": 0, "session": 1, "critical": 2, "warn": 3,
             "due": 4, "unknown": 5, "ok": 6, "snoozed": 7, "immune": 8}
    assert sorted(order, key=order.get)[0] == "expired"
    assert sorted(order, key=order.get)[-1] == "immune"


def test_every_state_has_a_sort_rank_and_label():
    """A state missing from either dict is a KeyError at render time."""
    states = {"expired", "session", "critical", "warn", "due", "unknown", "ok",
              "snoozed", "immune"}
    assert states <= set(app.LABELS), f"unlabeled: {states - set(app.LABELS)}"
    assert states == set(app.RANK), f"unranked: {states ^ set(app.RANK)}"

    # The page has its OWN LABEL and RANK maps in JavaScript. They are a
    # separate copy, and a state missing from them renders "undefined" or sorts
    # to the wrong end — invisible in the Python tests above.
    import re
    js_label = set(re.findall(r"(\w+):'", re.search(r"const LABEL=\{(.*?)\};",
                                                    app.PAGE, re.S).group(1)))
    js_rank = set(re.findall(r"(\w+):\d", re.search(r"const RANK=\{(.*?)\}",
                                                    app.PAGE).group(1)))
    assert states <= js_label, f"missing from the page's LABEL: {states - js_label}"
    assert states == js_rank, f"page RANK disagrees: {states ^ js_rank}"


def test_state_names_are_valid_css_identifiers():
    """The page sets --c:var(--<state>), so a state with a space or an
    underscore mismatch would render every row the default color."""
    for s in app.RANK:
        assert s.replace("-", "").isalnum(), s


# -------------------------------------------------------- real config sanity

def test_shipped_config_uses_inactivity_days():
    """Guards against a half-finished rename in trackers.yml."""
    cfg = app.load_config()
    assert len(cfg["trackers"]) == 7
    for t in cfg["trackers"]:
        assert "inactivity_days" in t, f"{t['id']} missing inactivity_days"
        assert "window_days" not in t, f"{t['id']} still has window_days"


def test_missing_limit_falls_back_short_not_long(tmp_path, monkeypatch):
    """A tracker with no inactivity_days anywhere must get the fail-safe 30.

    Falling back to 90 would be invisible: eight trackers are legitimately set
    to 90, so a silently-defaulted one would look deliberate.
    """
    cfg = tmp_path / "t.yml"
    cfg.write_text("defaults:\n  alert_at_pct: 0.65\ntrackers:\n  - id: nolimit\n    name: NoLimit\n")
    monkeypatch.setattr(app, "CONFIG_PATH", cfg)
    app._cfg_cache["data"] = None
    try:
        t = app.load_config()["trackers"][0]
        assert t["inactivity_days"] == 30, "fallback must err short"
    finally:
        app._cfg_cache["data"] = None
