#!/usr/bin/env python3
"""The read-only API key.

The whole point of a separate key is that it CANNOT write. `IDLARR_TOKEN` posts
events to /ping, so anything holding it can forge an auth event and silently
reset a countdown, which is the failure this service exists to prevent. Most of
what follows is therefore about what the key is refused, not what it allows.

Run:  .venv/bin/python -m pytest tests/test_apikey.py -q
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-apikey-test-")
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


@pytest.fixture
def client(cfg):
    return TestClient(app.app)


@pytest.fixture
def key(cfg):
    return app.api_key()


# ----------------------------------------------------------------- the key

def test_a_key_is_generated_on_first_read(cfg):
    """Like the arrs mint theirs. Nothing to configure, and an upgrade does not
    have to be told to go and create one."""
    assert not app.get_state("api_key")
    k = app.api_key()
    assert len(k) == 64
    assert app.get_state("api_key") == k
    assert app.api_key() == k, "a second read must not mint a different key"


def test_the_key_is_not_the_ping_token(cfg, monkeypatch):
    """IDLARR_TOKEN writes events. If these were ever the same value, handing a
    dashboard read access would hand it the ability to forge an auth event."""
    monkeypatch.setattr(app, "TOKEN", "the-ping-token")
    assert app.api_key() != app.get_token()


# ------------------------------------------------------------- what it opens

@pytest.mark.parametrize("path", ["/api/summary", "/api/status", "/api/history/alpha"])
def test_the_key_opens_the_read_endpoints(client, key, path):
    assert client.get(path, headers={"X-Api-Key": key}).status_code == 200
    assert client.get(path, params={"apikey": key}).status_code == 200


@pytest.mark.parametrize("path", ["/api/summary", "/api/status"])
def test_a_wrong_key_is_refused(client, key, path):
    """With auth OFF these routes pass a session check anyway, so the refusal
    has to come from the key comparison itself, not from require_ui."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    assert client.get(path, headers={"X-Api-Key": "no"}).status_code == 401
    assert client.get(path).status_code == 401


def test_the_error_says_which_secret_to_send(client):
    """The commonest mistake is reaching for IDLARR_TOKEN, because it is the
    only key most people know they have."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    detail = client.get("/api/summary", headers={"X-Api-Key": "no"}).json()["detail"]
    assert "X-Api-Key" in detail and "apikey" in detail
    assert "IDLARR_TOKEN" in detail


# ------------------------------------------------- what it must never open

WRITES = [
    ("post", "/api/mark/alpha"), ("post", "/api/unmark/alpha"),
    ("post", "/api/limit/alpha"), ("post", "/api/tracker"),
    ("delete", "/api/tracker/alpha"), ("post", "/api/settings"),
    ("post", "/api/import"), ("post", "/api/config"),
    ("post", "/api/auth"), ("post", "/api/apikey"),
    ("post", "/api/check"),
]


@pytest.mark.parametrize("verb,path", WRITES)
def test_the_key_cannot_write(client, key, verb, path):
    """The reason this key exists at all. A leaked dashboard key marking a
    tracker seen would leave the page reading `ok` while the account ages out.

    Checked with a sign-in configured, so passing would mean the key really did
    authorise the write rather than auth simply being off."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    kw = {"headers": {"X-Api-Key": key}}
    if verb != "delete":                    # httpx DELETE takes no body
        kw["json"] = {}
    r = getattr(client, verb)(path, **kw)
    # 401 exactly. NOT "401 or 303": 303 is /api/mark's own SUCCESS response,
    # so accepting it would have let this pass on a genuinely broken guard.
    assert r.status_code == 401, \
        f"{verb.upper()} {path} returned {r.status_code} for a read-only key"


def test_the_key_cannot_rotate_itself(client, key):
    """Rotation is behind the UI login on purpose: a leaked key must not be
    able to lock you out of noticing it leaked."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    before = app.api_key()
    client.post("/api/apikey", headers={"X-Api-Key": key})
    assert app.api_key() == before


# ---------------------------------------------------------------- rotation

def test_regenerating_invalidates_the_old_key(client, key):
    assert client.get("/api/summary", headers={"X-Api-Key": key}).status_code == 200
    new = client.post("/api/apikey").json()["api_key"]
    assert new != key
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    assert client.get("/api/summary", headers={"X-Api-Key": key}).status_code == 401
    assert client.get("/api/summary", headers={"X-Api-Key": new}).status_code == 200


# ----------------------------------------------------------- the contract

def test_summary_has_the_documented_shape(client, key):
    """This is the surface other people build against. /api/status changes with
    the page; this must not, so its keys are pinned here by name."""
    d = client.get("/api/summary", headers={"X-Api-Key": key}).json()
    for field in ("trackers", "counts", "needs_attention", "worst",
                  "soonest_deadline", "last_check", "version"):
        assert field in d, f"missing documented field: {field}"
    assert d["trackers"] == 7
    assert set(d["counts"]) == set(app.RANK), "counts must carry every state"
    assert sum(d["counts"].values()) == d["trackers"]


def test_summary_survives_an_empty_config(client, cfg, monkeypatch):
    """First run. `worst` and `soonest_deadline` have nothing to point at, and
    a widget parsing this must get null rather than a 500."""
    cfg.write_text("trackers:\n")
    app._cfg_cache["data"] = None
    d = client.get("/api/summary", headers={"X-Api-Key": app.api_key()}).json()
    assert d["trackers"] == 0
    assert d["worst"] is None and d["soonest_deadline"] is None
    assert d["needs_attention"] == 0


def test_summary_ignores_immune_and_snoozed_for_the_deadline(client, key, cfg):
    """A tracker that cannot expire has no deadline to be soonest. Counting one
    would have a dashboard reporting a countdown that never fires."""
    import yaml
    data = yaml.safe_load(cfg.read_text())
    for t in data["trackers"]:
        t["immune"] = True
    cfg.write_text(yaml.safe_dump(data))
    app._cfg_cache["data"] = None
    d = client.get("/api/summary", headers={"X-Api-Key": key}).json()
    assert d["soonest_deadline"] is None


# ------------------------------------------------------------------- timing

def test_the_key_comparison_is_constant_time():
    """`==` short-circuits on the first wrong byte, which is a timing oracle
    for a secret that is sent on every dashboard refresh. Mirrors the same
    guard on the /ping token; no behavioral test can see the difference, so
    this asserts the code path."""
    import inspect
    src = inspect.getsource(app.require_api_key)
    assert "compare_digest" in src
    assert "sent == " not in src and "== api_key()" not in src


def test_the_key_is_never_logged():
    """It rides in a query string for widgets that cannot set headers, so it
    already lands in access logs. Nothing here should put it anywhere else."""
    import inspect
    for fn in (app.require_api_key, app.api_key, app.regenerate_api_key):
        src = inspect.getsource(fn)
        for line in src.split("\n"):
            if "print(" in line:
                assert "api_key()" not in line and "{k}" not in line, line.strip()
