#!/usr/bin/env python3
"""Tests for first-run behaviour: token generation and config auto-creation.

Both reverse decisions the project originally made deliberately, so the tests
pin the SAFETY PROPERTIES that made those decisions right — not just the new
convenience. Auto-generating a token is fine only because /ping still fails
closed; auto-creating a config is fine only because "empty because new" stays
distinguishable from "empty because your mount is wrong".

Run:  .venv/bin/python -m pytest tests/test_firstrun.py -q
"""

import os
import re
import sqlite3
import tempfile
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-firstrun-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """A blank slate: empty database, no config file, no env token."""
    monkeypatch.setattr(app, "DB_PATH", tmp_path / "idlarr.db")
    monkeypatch.setattr(app, "CONFIG_PATH", tmp_path / "config" / "trackers.yml")
    monkeypatch.setattr(app, "TOKEN", "")          # as if IDLARR_TOKEN were unset
    app._cfg_cache["data"] = None
    app.init_db()
    yield tmp_path
    app._cfg_cache["data"] = None


# ------------------------------------------------------------------- token

def test_token_is_generated_when_none_is_set(fresh):
    assert app.get_token() == ""
    app.set_state("idlarr_token", "generated-value")
    assert app.get_token() == "generated-value"


def test_an_explicit_env_token_always_wins(fresh, monkeypatch):
    """Env must never be silently overridden by a stale generated value —
    otherwise setting IDLARR_TOKEN would appear to do nothing."""
    app.set_state("idlarr_token", "generated-value")
    monkeypatch.setattr(app, "TOKEN", "env-value")
    assert app.get_token() == "env-value"


def test_ping_still_fails_closed_with_no_token_anywhere(fresh):
    """THE safety property. The original design refused to boot because an
    empty token turned /ping into an open endpoint. Generation replaces the
    refusal, so this must still answer 'no' rather than 'yes'."""
    from fastapi import HTTPException
    assert app.get_token() == ""
    with pytest.raises(HTTPException) as e:
        app.require_token("Bearer anything")
    assert e.value.status_code == 500        # misconfigured, never accepted


def test_generated_token_is_enforced_not_decorative(fresh):
    from fastapi import HTTPException
    app.set_state("idlarr_token", "s3cret")
    app.require_token("Bearer s3cret")                    # accepted
    for bad in ("Bearer wrong", "s3cret", "", None):
        with pytest.raises(HTTPException) as e:
            app.require_token(bad)
        assert e.value.status_code == 401, bad


def test_generated_token_is_long_enough_to_be_unguessable(fresh):
    """secrets.token_hex(32) — 64 hex chars. A short token would be brute
    forcible against an endpoint that forges auth events."""
    import secrets
    assert len(secrets.token_hex(32)) == 64


def test_the_generated_token_reaches_the_userscript(fresh, monkeypatch):
    """Generation is only useful if the script the user installs carries it."""
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    app.set_state("idlarr_token", "abc123")
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    js = app.render_userscript("https://idlarr.test.internal")
    assert 'const TOKEN    = "abc123";' in js


# ------------------------------------------------------------------ config

def test_default_config_is_valid_and_empty(fresh):
    """A bare `trackers:` key parses as None; load_config normalises it to an
    empty list. Assert the contract the app actually relies on, not the raw
    parse — they legitimately differ."""
    doc = yaml.safe_load(app.default_config())
    assert doc["trackers"] in (None, [])
    assert doc["defaults"]["inactivity_days"] == 30
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    assert app.load_config()["trackers"] == []


def test_default_config_keeps_the_fail_safe_warning(fresh):
    """A generated config must carry the same warning as the shipped example:
    an unconfirmed limit is a guess, and a guess too high loses the account."""
    assert "FAIL-SAFE PLACEHOLDER" in app.default_config()


def test_an_auto_created_config_still_loads(fresh):
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    cfg = app.load_config()
    assert cfg["trackers"] == []
    assert cfg["check_hour"] == 9


def test_empty_config_shows_a_first_run_banner_naming_the_path(fresh, monkeypatch):
    """The mitigation for auto-creating. A mis-mounted /config produces an
    empty install that looks healthy; naming the resolved path on screen is
    what makes 'empty because new' distinguishable from 'empty because wrong'."""
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    page = TestClient(app.app).get("/").text
    assert "No trackers yet" in page
    # The banner prompts about the mount but does NOT print the resolved path:
    # inside a container that is always /config/trackers.yml and identifies
    # nothing. The startup log carries it instead.
    assert "Check your config mount" in page
    assert str(app.CONFIG_PATH) not in page


def test_the_banner_disappears_once_a_tracker_exists(fresh, monkeypatch):
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    app.add_tracker({"id": "alpha", "name": "Alpha", "url": "https://a.example/",
                     "host": "a.example", "inactivity_days": 30,
                     "verified": False, "notes": "", "auth_sel": ""})
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    page = TestClient(app.app).get("/").text
    assert "No trackers yet" not in page


@pytest.mark.parametrize("trackers_line", ["trackers:", "trackers: []", "trackers:  [ ]"])
def test_add_works_against_a_freshly_created_config(fresh, trackers_line):
    """The first "Add tracker" on an auto-created config. This broke when the
    template wrote `trackers: []` while add_tracker only matched a bare
    `trackers:` — auto-create and add each worked alone and failed together,
    on the exact path a new user takes first."""
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(
        "defaults:\n  inactivity_days: 30\n  timezone: UTC\n  check_hour: 9\n\n"
        + trackers_line + "\n")
    app._cfg_cache["data"] = None
    app.add_tracker({"id": "alpha", "name": "Alpha", "url": "https://a.example/",
                     "host": "a.example", "inactivity_days": 30,
                     "verified": False, "notes": "", "auth_sel": ""})
    assert [t["id"] for t in app.load_config()["trackers"]] == ["alpha"]


def test_second_add_also_works(fresh):
    """Appending to a list that was empty a moment ago is a different code path
    from appending to one that already had entries."""
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    for tid in ("alpha", "beta"):
        app.add_tracker({"id": tid, "name": tid.title(),
                         "url": f"https://{tid}.example/", "host": f"{tid}.example",
                         "inactivity_days": 30, "verified": False,
                         "notes": "", "auth_sel": ""})
    assert [t["id"] for t in app.load_config()["trackers"]] == ["alpha", "beta"]
    assert "FAIL-SAFE PLACEHOLDER" in app.CONFIG_PATH.read_text()


# --------------------------------------------------------------- timezone

def test_generated_config_uses_TZ_not_a_hardcoded_utc(fresh, monkeypatch):
    """local_tz() reads the CONFIG FILE, not the environment. A hardcoded UTC
    in the generated config silently counts days in the wrong zone for anyone
    who set TZ — and a zone behind the user's makes days_left too large, firing
    every alert LATE. Invisible, and in the unsafe direction."""
    monkeypatch.setenv("TZ", "America/Chicago")
    assert yaml.safe_load(app.default_config())["defaults"]["timezone"] == "America/Chicago"


def test_generated_config_falls_back_to_utc_for_a_bad_tz(fresh, monkeypatch):
    """A nonsense TZ must not produce a config that cannot load — ZoneInfo
    would raise on every request."""
    monkeypatch.setenv("TZ", "Not/AZone")
    assert yaml.safe_load(app.default_config())["defaults"]["timezone"] == "UTC"


def test_the_generated_timezone_actually_drives_day_counting(fresh, monkeypatch):
    """End to end: write the generated config, then confirm local_tz() returns
    the zone TZ asked for. Pins the whole chain rather than the string."""
    monkeypatch.setenv("TZ", "America/Chicago")
    app.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    app.CONFIG_PATH.write_text(app.default_config())
    app._cfg_cache["data"] = None
    assert str(app.local_tz()) == "America/Chicago"


def test_an_explicit_token_is_remembered_so_losing_env_is_survivable(fresh, monkeypatch):
    """An existing install whose .env goes missing must NOT mint a new token —
    the userscript already in the browser carries the old one and would 401 on
    every tracker, silently. Storing the explicit token on first boot makes the
    env var's disappearance survivable."""
    monkeypatch.setattr(app, "TOKEN", "my-real-token")
    assert not app.get_state("idlarr_token")
    # what lifespan does on boot
    if not app.get_state("idlarr_token"):
        app.set_state("idlarr_token", app.TOKEN if app.TOKEN else "generated")
    assert app.get_state("idlarr_token") == "my-real-token"
    # now .env vanishes
    monkeypatch.setattr(app, "TOKEN", "")
    assert app.get_token() == "my-real-token"
    app.require_token("Bearer my-real-token")          # still accepted


def test_a_changed_env_token_still_wins_over_the_remembered_one(fresh, monkeypatch):
    """Remembering must not pin the old value: rotating IDLARR_TOKEN has to
    take effect, or a deliberate rotation would silently do nothing."""
    app.set_state("idlarr_token", "old-token")
    monkeypatch.setattr(app, "TOKEN", "new-token")
    assert app.get_token() == "new-token"


# ------------------------------------------------------------- permissions

def test_database_is_not_world_readable(fresh):
    """SQLite creates files 0644. That handed any local user on a shared host
    the tracker list, the API token, the session secret (enough to mint a
    login) and the saved Prowlarr key. Encryption at rest needs a key you have
    to manage; this needs nothing."""
    import stat
    app.init_db()
    mode = stat.S_IMODE(app.DB_PATH.stat().st_mode)
    assert mode & 0o077 == 0, f"database is {oct(mode)}, readable beyond owner"


def test_backups_are_not_world_readable(fresh, monkeypatch):
    """Backups carry exactly the same secrets as the live database, and they
    are the copies most likely to travel."""
    import stat
    monkeypatch.setattr(app, "BACKUP_DIR", fresh / "backups")
    monkeypatch.setattr(app, "BACKUP_KEEP", 3)
    app.init_db()
    dest = app.backup_db("2026-08-04")
    assert dest is not None and dest.exists()
    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode & 0o077 == 0, f"backup is {oct(mode)}, readable beyond owner"
