#!/usr/bin/env python3
"""Tests for add_tracker() / remove_tracker() — appending to and deleting from
trackers.yml.

Same stakes as test_config_write.py: this writes the user's source of truth,
and the comments in that file are load-bearing. The checks that matter most are
the ones about BLAST RADIUS — an append that quietly reformatted or dropped a
sibling entry would look fine and stay invisible until the day that sibling's
limit mattered.

Run:  .venv/bin/python -m pytest test_config_add.py -q
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-addtest-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"

NEW = {"id": "newone", "name": "New One", "url": "https://new.example/",
       "host": "new.example", "inactivity_days": 45, "verified": False,
       "notes": "Gazelle. Added by test.", "auth_sel": ""}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    app._cfg_cache["data"] = None
    yield path
    app._cfg_cache["data"] = None


def doc(path):
    return yaml.safe_load(path.read_text())


def ids(path):
    return [t["id"] for t in doc(path)["trackers"]]


# ------------------------------------------------------------------- adding

def test_appends_the_entry(cfg):
    app.add_tracker(dict(NEW))
    assert ids(cfg)[-1] == "newone"
    added = doc(cfg)["trackers"][-1]
    assert added["name"] == "New One"
    assert added["inactivity_days"] == 45
    assert added["url"] == "https://new.example/"


def test_defaults_are_fail_safe(cfg):
    """Unverified, and short. A limit nobody has read off the tracker's rules
    page is a guess, and a guess that is too HIGH loses the account."""
    app.add_tracker({**NEW, "inactivity_days": 30})
    added = doc(cfg)["trackers"][-1]
    assert added["verified"] is False
    assert added["inactivity_days"] == 30


def test_comments_survive(cfg):
    before = cfg.read_text()
    app.add_tracker(dict(NEW))
    after = cfg.read_text()
    for line in before.splitlines():
        if line.lstrip().startswith("#"):
            assert line in after, f"comment lost: {line!r}"


def test_the_fail_safe_warning_block_survives(cfg):
    """The loudest comment in the file. If any writeback can erase this one,
    the file's own warning about placeholder limits disappears silently."""
    app.add_tracker(dict(NEW))
    assert "EVERY inactivity_days BELOW IS A FAIL-SAFE PLACEHOLDER" in cfg.read_text()


def test_existing_entries_are_untouched_byte_for_byte(cfg):
    """The blast-radius check. Everything before the append must be identical."""
    before = cfg.read_text()
    app.add_tracker(dict(NEW))
    after = cfg.read_text()
    assert after.startswith(before.rstrip("\n"))


def test_only_the_new_lines_are_added(cfg):
    before = cfg.read_text().splitlines()
    app.add_tracker(dict(NEW))
    after = cfg.read_text().splitlines()
    assert after[:len(before)] == before or after[:len(before) - 1] == before[:-1]
    assert len(after) - len(before) <= 8


def test_optional_fields_are_omitted_not_blank(cfg):
    """An empty auth_sel must not be written: the userscript treats a present
    selector as authoritative, so "" would match nothing and that tracker would
    never record an auth event."""
    app.add_tracker({**NEW, "auth_sel": "", "notes": ""})
    text = cfg.read_text()
    assert "auth_sel:" not in text.split("- id: newone")[1]
    assert "notes:" not in text.split("- id: newone")[1]


def test_auth_sel_is_written_when_given(cfg):
    app.add_tracker({**NEW, "auth_sel": 'a[href*="/x?key="]'})
    assert doc(cfg)["trackers"][-1]["auth_sel"] == 'a[href*="/x?key="]'


def test_quotes_in_values_survive(cfg):
    app.add_tracker({**NEW, "name": 'The "Quoted" One',
                     "notes": 'Custom. Uses a: colon, and "quotes".'})
    added = doc(cfg)["trackers"][-1]
    assert added["name"] == 'The "Quoted" One'
    assert added["notes"] == 'Custom. Uses a: colon, and "quotes".'


def test_duplicate_id_is_refused(cfg):
    with pytest.raises(ValueError, match="already in the config"):
        app.add_tracker({**NEW, "id": "alpha"})
    assert ids(cfg).count("alpha") == 1


def test_no_tmp_file_is_left_behind(cfg):
    app.add_tracker(dict(NEW))
    assert not list(cfg.parent.glob("*.tmp"))


def test_cache_is_invalidated(cfg):
    app.load_config()                       # warm it
    app.add_tracker(dict(NEW))
    assert "newone" in {t["id"] for t in app.load_config()["trackers"]}


def test_the_new_tracker_reaches_the_userscript(cfg, monkeypatch):
    """The whole point of the two features together: adding a tracker changes
    the generated script, so the browser picks it up on the next update check."""
    app.init_db()                        # the version counter lives in `state`
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    app.add_tracker(dict(NEW))
    js = app.render_userscript("https://idlarr.test.internal")
    assert "// @match        *://*.new.example/*" in js
    assert '{ host: "new.example", id: "newone" }' in js


# ------------------------------------------------------------------ removing

def test_removes_the_entry(cfg):
    app.remove_tracker("gamma")
    assert "gamma" not in ids(cfg)
    assert len(ids(cfg)) == 6


@pytest.mark.parametrize("victim", ["alpha", "delta", "omega"])
def test_removal_leaves_siblings_identical(cfg, victim):
    """First, middle and last entries — the edges are where a range calculation
    goes wrong."""
    before = {t["id"]: t for t in doc(cfg)["trackers"] if t["id"] != victim}
    app.remove_tracker(victim)
    after = {t["id"]: t for t in doc(cfg)["trackers"]}
    assert after == before


def test_removal_keeps_comments(cfg):
    app.remove_tracker("gamma")
    assert "EVERY inactivity_days BELOW IS A FAIL-SAFE PLACEHOLDER" in cfg.read_text()


def test_removal_does_not_leave_growing_gaps(cfg):
    app.remove_tracker("gamma")
    app.remove_tracker("delta")
    assert "\n\n\n" not in cfg.read_text()


def test_removing_an_unknown_id_raises(cfg):
    with pytest.raises(KeyError):
        app.remove_tracker("nosuchtracker")


def test_remove_then_add_round_trips(cfg):
    original = doc(cfg)["trackers"]
    target = next(t for t in original if t["id"] == "epsilon")
    app.remove_tracker("epsilon")
    app.add_tracker({**target, "host": app.host_from_url(target["url"])})
    back = next(t for t in doc(cfg)["trackers"] if t["id"] == "epsilon")
    for key in ("name", "url", "inactivity_days", "verified", "notes"):
        assert back.get(key) == target.get(key), key


def test_events_survive_removal(cfg):
    """Deliberate. `events` is append-only apart from drop_last_auth(), and
    keeping them means re-adding an id restores its history instead of silently
    restarting the countdown — the exact failure this service prevents."""
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM events")
    app.record("gamma", "auth")
    app.remove_tracker("gamma")
    with app.db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM events WHERE tracker_id='gamma'").fetchone()["c"]
    assert n == 1


# ------------------------------------------------------------------ the API

@pytest.fixture
def client(cfg):
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
    return TestClient(app.app)


def test_api_creates(client, cfg):
    r = client.post("/api/tracker", json={"name": "New One",
                                          "url": "https://new.example/"})
    assert r.status_code == 200
    assert r.json()["id"] == "newone"
    assert doc(cfg)["trackers"][-1]["host"] == "new.example"


def test_api_derives_id_and_host(client, cfg):
    client.post("/api/tracker", json={"name": "Some Tracker!",
                                      "url": "https://www.some-tracker.example/x"})
    added = doc(cfg)["trackers"][-1]
    assert added["id"] == "sometracker"
    assert added["host"] == "some-tracker.example"      # www. stripped


def test_api_defaults_to_thirty_unverified(client, cfg):
    client.post("/api/tracker", json={"name": "Bare", "url": "https://bare.example/"})
    added = doc(cfg)["trackers"][-1]
    assert added["inactivity_days"] == 30
    assert added["verified"] is False


@pytest.mark.parametrize("payload,code", [
    ({"name": "", "url": "https://x.example/"}, 400),
    ({"name": "x" * 81, "url": "https://x.example/"}, 400),
    ({"name": "Ok", "url": "ftp://x.example/"}, 400),
    ({"name": "Ok", "url": "https://x.example/", "inactivity_days": 0}, 400),
    ({"name": "Ok", "url": "https://x.example/", "inactivity_days": 4000}, 400),
    ({"name": "Ok", "url": "https://x.example/", "inactivity_days": "soon"}, 400),
    ({"name": "!!!", "url": "https://x.example/"}, 400),          # unusable id
    ({"name": "Alpha Tracker", "id": "alpha"}, 409),              # duplicate
])
def test_api_validates(client, payload, code):
    assert client.post("/api/tracker", json=payload).status_code == code


def test_api_deletes(client, cfg):
    r = client.delete("/api/tracker/gamma")
    assert r.status_code == 200 and r.json()["removed"] == "gamma"
    assert "gamma" not in ids(cfg)


def test_api_delete_unknown_is_404(client):
    assert client.delete("/api/tracker/nosuch").status_code == 404


def test_api_needs_auth_when_configured(client, cfg):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    assert client.post("/api/tracker", json={"name": "X",
                                             "url": "https://x.example/"}).status_code == 401
    assert client.delete("/api/tracker/gamma").status_code == 401
    assert "gamma" in ids(cfg)


# --------------------------------------------------------- empty-list edge cases

def test_add_to_inline_empty_list(tmp_path, monkeypatch):
    """The auto-generated config uses `trackers: []`. add_tracker must handle
    this — it's what every fresh zero-config install starts with."""
    path = tmp_path / "trackers.yml"
    path.write_text(
        "defaults:\n"
        "  inactivity_days: 30\n"
        "  alert_at_pct: 0.65\n"
        "  timezone: UTC\n"
        "  check_hour: 9\n\n"
        "trackers: []\n"
    )
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    app._cfg_cache["data"] = None

    app.add_tracker(dict(NEW))
    result = doc(path)
    assert len(result["trackers"]) == 1
    assert result["trackers"][0]["id"] == "newone"
    assert result["trackers"][0]["inactivity_days"] == 45
    app._cfg_cache["data"] = None


def test_add_to_bare_empty_key(tmp_path, monkeypatch):
    """The other empty-list form: `trackers:` with nothing after it."""
    path = tmp_path / "trackers.yml"
    path.write_text(
        "defaults:\n"
        "  inactivity_days: 30\n\n"
        "trackers:\n"
    )
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    app._cfg_cache["data"] = None

    app.add_tracker(dict(NEW))
    result = doc(path)
    assert len(result["trackers"]) == 1
    assert result["trackers"][0]["id"] == "newone"
    app._cfg_cache["data"] = None
