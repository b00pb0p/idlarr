#!/usr/bin/env python3
"""Tests for the Prowlarr / Jackett import.

Two things matter here beyond "does it parse the JSON". First, that nothing is
written without an explicit apply — an API key pointed at the wrong instance
should cost you a list on screen, not seven entries in your config. Second,
that an imported limit is never treated as fact: neither tool knows a tracker's
inactivity policy, so everything must land at 30 days and unverified, exactly
like a hand-added entry.

Run:  .venv/bin/python -m pytest test_import.py -q
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-imp-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"

PROWLARR = [
    {"name": "Real One", "protocol": "torrent", "privacy": "private",
     "indexerUrls": ["https://real.example/"]},
    {"name": "Cardigann One", "protocol": "torrent", "privacy": "private",
     "indexerUrls": [], "fields": [{"name": "baseUrl", "value": "https://carr.example/"}]},
    {"name": "Semi One", "protocol": "torrent", "privacy": "semiPrivate",
     "indexerUrls": ["https://semi.example/"]},
    {"name": "Public One", "protocol": "torrent", "privacy": "public",
     "indexerUrls": ["https://pub.example/"]},
    {"name": "Usenet One", "protocol": "usenet", "privacy": "private",
     "indexerUrls": ["https://nzb.example/"]},
    {"name": "Alpha Tracker", "protocol": "torrent", "privacy": "private",
     "indexerUrls": ["https://alpha.example/"]},          # already configured
]

JACKETT = [
    {"id": "realone", "name": "Real One", "type": "private",
     "site_link": "https://real.example/", "configured": True},
    {"id": "pub", "name": "Public One", "type": "public",
     "site_link": "https://pub.example/", "configured": True},
    {"id": "unconf", "name": "Unconfigured One", "type": "private",
     "site_link": "https://unconf.example/", "configured": False},
]


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
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
def prowlarr(monkeypatch):
    monkeypatch.setattr(app, "_fetch_json", lambda url, headers: PROWLARR)


@pytest.fixture
def jackett(monkeypatch):
    monkeypatch.setattr(app, "_fetch_json", lambda url, headers: JACKETT)


def ids(path):
    return [t["id"] for t in yaml.safe_load(path.read_text())["trackers"]]


BODY = {"source": "prowlarr", "url": "http://prowlarr.example:9696", "api_key": "k"}


# ------------------------------------------------------------- normalising

def test_prowlarr_keeps_private_torrent_indexers(prowlarr):
    names = [i["name"] for i in app.prowlarr_indexers("http://x", "k")]
    assert "Real One" in names
    assert "Semi One" in names            # semi-private still prunes for inactivity
    assert "Public One" not in names      # no account to lose
    assert "Usenet One" not in names      # not a tracker


def test_prowlarr_reads_cardigann_base_url(prowlarr):
    """Most Prowlarr indexers are Cardigann definitions, which carry the address
    in `fields` rather than in indexerUrls."""
    got = {i["name"]: i["url"] for i in app.prowlarr_indexers("http://x", "k")}
    assert got["Cardigann One"] == "https://carr.example/"


def test_jackett_skips_public_and_unconfigured(jackett):
    names = [i["name"] for i in app.jackett_indexers("http://x", "k")]
    assert names == ["Real One"]


# ------------------------------------------------------------- preview

def test_preview_writes_nothing(client, cfg, prowlarr):
    before = cfg.read_text()
    r = client.post("/api/import", json=BODY)
    assert r.status_code == 200
    assert cfg.read_text() == before


def test_preview_marks_what_would_be_skipped(client, prowlarr):
    got = {c["id"]: c["skip"] for c in client.post("/api/import", json=BODY).json()["candidates"]}
    assert got["realone"] == ""
    assert got["alphatracker"] == "already configured"     # matched on host


def test_existing_host_under_a_new_name_is_not_re_added(client, cfg, prowlarr):
    """Prowlarr calls it "Alpha Tracker"; the config calls it "alpha". Same
    host. Adding it again would split one account's history across two rows and
    leave both countdowns wrong."""
    client.post("/api/import", json={**BODY, "apply": True})
    assert len([i for i in ids(cfg) if i in ("alpha", "alphatracker")]) == 1


# ------------------------------------------------------------- apply

def test_apply_adds_the_new_ones(client, cfg, prowlarr):
    r = client.post("/api/import", json={**BODY, "apply": True})
    assert r.status_code == 200
    body = r.json()
    assert set(body["added"]) == {"realone", "cardigannone", "semione"}
    assert not body["failed"]
    for tid in body["added"]:
        assert tid in ids(cfg)


def test_imported_limits_are_never_treated_as_fact(client, cfg, prowlarr):
    """Neither tool knows an inactivity policy. A limit that arrives looking
    authoritative and is too high is precisely what loses an account."""
    client.post("/api/import", json={**BODY, "apply": True})
    added = [t for t in yaml.safe_load(cfg.read_text())["trackers"]
             if t["id"] in ("realone", "cardigannone", "semione")]
    assert len(added) == 3
    for t in added:
        assert t["inactivity_days"] == 30
        assert t["verified"] is False


def test_apply_preserves_comments(client, cfg, prowlarr):
    client.post("/api/import", json={**BODY, "apply": True})
    assert "EVERY inactivity_days BELOW IS A FAIL-SAFE PLACEHOLDER" in cfg.read_text()


def test_apply_is_idempotent(client, cfg, prowlarr):
    client.post("/api/import", json={**BODY, "apply": True})
    first = ids(cfg)
    second = client.post("/api/import", json={**BODY, "apply": True})
    assert second.json()["added"] == []
    assert ids(cfg) == first


def test_jackett_apply(client, cfg, jackett):
    r = client.post("/api/import", json={**BODY, "source": "jackett", "apply": True})
    assert r.json()["added"] == ["realone"]
    assert "realone" in ids(cfg)


def test_imported_trackers_reach_the_userscript(client, cfg, prowlarr, monkeypatch):
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    client.post("/api/import", json={**BODY, "apply": True})
    js = app.render_userscript("https://idlarr.test.internal")
    assert '{ host: "real.example", id: "realone" }' in js


# ------------------------------------------------------------- failures

@pytest.mark.parametrize("body,code", [
    ({**BODY, "source": "sonarr"}, 400),
    ({**BODY, "url": "prowlarr.example"}, 400),
    ({**BODY, "api_key": ""}, 400),
])
def test_validation(client, body, code):
    assert client.post("/api/import", json=body).status_code == code


def test_unreachable_host_is_reported_not_swallowed(client, monkeypatch):
    def boom(url, headers):
        raise ValueError("could not reach http://prowlarr.example:9696/api/v1/indexer: refused")
    monkeypatch.setattr(app, "_fetch_json", boom)
    r = client.post("/api/import", json=BODY)
    assert r.status_code == 502
    assert "could not reach" in r.json()["detail"]


def test_bad_key_says_so(client, monkeypatch):
    def boom(url, headers):
        raise ValueError("http://x/api/v1/indexer returned 401 — check the API key")
    monkeypatch.setattr(app, "_fetch_json", boom)
    assert "check the API key" in client.post("/api/import", json=BODY).json()["detail"]


def test_needs_auth_when_configured(client, cfg, prowlarr):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    assert client.post("/api/import", json={**BODY, "apply": True}).status_code == 401
    assert "realone" not in ids(cfg)


# --------------------------------------------------- API hosts and subdomains
#
# Prowlarr returns some indexers by their API host rather than their site —
# BroadcasTheNet comes back as api.broadcasthe.net, for example. An exact-host
# dedupe treats that as a tracker you do not have and imports a duplicate: one
# account across two rows, both countdowns wrong, and the new row matching a
# host no browser session exists on, so it sits at `unknown` forever and reads
# as broken detection. Found against a real Prowlarr, not by reasoning.

@pytest.mark.parametrize("a,b,want", [
    ("api.broadcasthe.net", "broadcasthe.net", True),
    ("broadcasthe.net", "api.broadcasthe.net", True),
    ("tracker.example.com", "example.com", True),
    ("example.com", "example.com", True),
    ("EXAMPLE.com", "example.COM", True),
    ("broadcasthe.net", "broadcasthe.org", False),
    ("notbroadcasthe.net", "broadcasthe.net", False),   # suffix without a dot
    ("", "broadcasthe.net", False),
    ("broadcasthe.net", "", False),
])
def test_same_site(a, b, want):
    assert app.same_site(a, b) is want


@pytest.mark.parametrize("url,host,want_url,want_host", [
    ("https://api.broadcasthe.net/", "api.broadcasthe.net",
     "https://broadcasthe.net/", "broadcasthe.net"),
    ("https://alpha.example/", "alpha.example",
     "https://alpha.example/", "alpha.example"),
    ("https://api.example.com/path", "api.example.com",
     "https://example.com/path", "example.com"),
])
def test_api_hosts_become_browsable(url, host, want_url, want_host):
    assert app.browsable(url, host) == (want_url, want_host)


API_HOST = [{"name": "BroadcasTheNet", "protocol": "torrent", "privacy": "private",
             "indexerUrls": ["https://api.broadcasthe.net/"]}]


@pytest.fixture
def apihost(monkeypatch):
    monkeypatch.setattr(app, "_fetch_json", lambda url, headers: API_HOST)


def test_api_host_is_recognised_as_already_configured(client, cfg, apihost):
    """A configured `broadcasthe.net` and Prowlarr's `api.broadcasthe.net`
    are one tracker, not two."""
    app.add_tracker({"id": "btn", "name": "BroadcasTheNet",
                     "url": "https://broadcasthe.net/", "host": "broadcasthe.net",
                     "inactivity_days": 30, "verified": False,
                     "notes": "", "auth_sel": ""})
    c = client.post("/api/import", json=BODY).json()["candidates"]
    assert [x["skip"] for x in c] == ["already configured"]


def test_api_host_is_not_imported_twice(client, cfg, apihost):
    app.add_tracker({"id": "btn", "name": "BroadcasTheNet",
                     "url": "https://broadcasthe.net/", "host": "broadcasthe.net",
                     "inactivity_days": 30, "verified": False,
                     "notes": "", "auth_sel": ""})
    assert client.post("/api/import", json={**BODY, "apply": True}).json()["added"] == []
    assert ids(cfg).count("btn") == 1
    assert "broadcasthenet" not in ids(cfg)


def test_a_genuinely_new_api_host_imports_as_the_site(client, cfg, apihost):
    """Nothing configured yet, so it IS new — but it must land as the site, not
    as the API host. A row matching api.* never sees a browser session."""
    client.post("/api/import", json={**BODY, "apply": True})
    added = [t for t in yaml.safe_load(cfg.read_text())["trackers"]
             if t["id"] == "broadcasthenet"][0]
    assert added["host"] == "broadcasthe.net"
    assert added["url"] == "https://broadcasthe.net/"


def test_the_generated_match_is_for_the_site_not_the_api(client, cfg, apihost, monkeypatch):
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
    client.post("/api/import", json={**BODY, "apply": True})
    js = app.render_userscript("https://idlarr.test.internal")
    assert "// @match        *://*.broadcasthe.net/*" in js
    assert "api.broadcasthe.net" not in js


SUBDOMAIN = [{"name": "Alpha Tracker", "protocol": "torrent", "privacy": "private",
              "indexerUrls": ["https://www2.alpha.example/"]}]


def test_a_non_api_subdomain_is_still_the_same_tracker(client, cfg, monkeypatch):
    """`api.` is normalised away before comparison, so it does not exercise the
    subdomain rule on its own. This does: the config holds alpha.example and
    Prowlarr offers www2.alpha.example. Exact-host matching imports a duplicate.
    """
    monkeypatch.setattr(app, "_fetch_json", lambda url, headers: SUBDOMAIN)
    c = client.post("/api/import", json=BODY).json()["candidates"]
    assert [x["skip"] for x in c] == ["already configured"]
    assert client.post("/api/import", json={**BODY, "apply": True}).json()["added"] == []
    assert "alphatracker" not in ids(cfg)


# --------------------------------------------------- remembering the connection

def test_a_working_connection_is_remembered(client, cfg, prowlarr):
    """A container recreate should not send you back to Prowlarr for the key."""
    client.post("/api/import", json=BODY)
    assert app.get_state("import_source") == "prowlarr"
    assert app.get_state("import_url") == BODY["url"]
    assert app.get_state("import_key") == "k"


def test_a_failed_connection_is_not_remembered(client, cfg, monkeypatch):
    """Saving a key that did not work means the blank-to-reuse path silently
    replays a bad credential forever."""
    monkeypatch.setattr(app, "_fetch_json",
                        lambda u, h: (_ for _ in ()).throw(ValueError("refused")))
    assert client.post("/api/import", json=BODY).status_code == 502
    assert not app.get_state("import_key")


def test_blank_key_reuses_the_saved_one(client, cfg, prowlarr):
    client.post("/api/import", json=BODY)
    r = client.post("/api/import", json={**BODY, "api_key": ""})
    assert r.status_code == 200
    assert r.json()["candidates"]


def test_blank_key_is_not_reused_for_a_different_instance(client, cfg, prowlarr):
    """Sending one service's key to another host would be a credential leak."""
    client.post("/api/import", json=BODY)
    r = client.post("/api/import", json={**BODY, "url": "http://other.example:9696",
                                         "api_key": ""})
    assert r.status_code == 400
    r = client.post("/api/import", json={**BODY, "source": "jackett", "api_key": ""})
    assert r.status_code == 400


def test_forget_clears_it(client, cfg, prowlarr):
    client.post("/api/import", json=BODY)
    assert client.post("/api/import", json={"forget": True}).json() == {"forgotten": True}
    for k in ("import_source", "import_url", "import_key"):
        assert not app.get_state(k)


def test_the_key_is_never_sent_back_to_the_browser(client, cfg, prowlarr):
    # A distinctive key: BODY's is one letter, which appears all over the page
    # and would make this assertion pass or fail for unrelated reasons.
    secret = "tk_zq7wvx4n8m2playbook"
    client.post("/api/import", json={**BODY, "api_key": secret})
    page = client.get("/").text
    assert secret not in page
    assert "saved &mdash; leave blank to reuse" in page
    assert BODY["url"] in page          # the URL is fine to show
