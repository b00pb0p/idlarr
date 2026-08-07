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
import re
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
    # Prowlarr does not reliably set `privacy` on usenet indexers. Requiring an
    # explicit "private" there drops the sites the import exists to find.
    {"name": "Usenet Two", "protocol": "usenet",
     "indexerUrls": ["https://nzb2.example/"]},
    {"name": "Usenet Public", "protocol": "usenet", "privacy": "public",
     "indexerUrls": ["https://openzb.example/"]},
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


# ------------------------------------------------------------- normalizing

def test_prowlarr_keeps_private_indexers_of_both_protocols(prowlarr):
    """Usenet accounts lapse for inactivity exactly like tracker accounts, and
    Prowlarr holds both. This used to drop everything non-torrent, so an OMG or
    NZBs.in account was invisible to a tool that exists to watch for that."""
    got = {i["name"]: i.get("protocol") for i in app.prowlarr_indexers("http://x", "k")}
    assert got.get("Real One") == "torrent"
    assert got.get("Semi One") == "torrent"   # semi-private still prunes
    assert got.get("Usenet One") == "usenet"
    assert "Public One" not in got            # no account to lose
    assert "Usenet Public" not in got         # an explicit public stays out


def test_usenet_without_a_privacy_field_is_kept(prowlarr):
    """The defensive half. Prowlarr does not always populate `privacy` for
    usenet, and requiring it would drop those silently, which is the failure
    this change is fixing rather than one to reintroduce."""
    names = [i["name"] for i in app.prowlarr_indexers("http://x", "k")]
    assert "Usenet Two" in names


def test_jackett_declares_torrent(jackett):
    """Jackett has no usenet concept. Saying so explicitly keeps the protocol
    filter from having to guess."""
    assert {i["protocol"] for i in app.jackett_indexers("http://x", "k")} == {"torrent"}


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
    assert set(body["added"]) == {"realone", "cardigannone", "semione",
                                  "usenetone", "usenettwo"}
    assert not body["failed"]
    for tid in body["added"]:
        assert tid in ids(cfg)


def test_imported_limits_are_never_treated_as_fact(client, cfg, prowlarr):
    """Neither tool knows an inactivity policy. A limit that arrives looking
    authoritative and is too high is precisely what loses an account."""
    client.post("/api/import", json={**BODY, "apply": True})
    # Usenet included: neither tool knows a usenet retention policy either, and
    # OMG's is nothing like a tracker's, so it must not arrive looking checked.
    added = [t for t in yaml.safe_load(cfg.read_text())["trackers"]
             if t["id"] in ("realone", "cardigannone", "semione",
                            "usenetone", "usenettwo")]
    assert len(added) == 5
    for t in added:
        assert t["inactivity_days"] == 30
        assert t["verified"] is False


def test_protocols_filter_narrows_the_import(client, cfg, prowlarr):
    """The panel offers a checkbox per protocol. Preview and apply must honor
    it identically, or you confirm one list and get another."""
    r = client.post("/api/import", json={**BODY, "protocols": ["torrent"]})
    got = {c["id"] for c in r.json()["candidates"]}
    assert "realone" in got
    assert not {"usenetone", "usenettwo"} & got

    r = client.post("/api/import", json={**BODY, "protocols": ["usenet"]})
    got = {c["id"] for c in r.json()["candidates"]}
    assert got == {"usenetone", "usenettwo"}


def test_omitting_protocols_takes_both(client, cfg, prowlarr):
    """A scripted caller that predates the checkboxes must get the WIDER set.
    Defaulting to torrent-only would silently reinstate the old bug."""
    got = {c["id"] for c in client.post("/api/import", json=BODY).json()["candidates"]}
    assert {"realone", "usenetone"} <= got


def test_selecting_no_protocol_is_refused(client, cfg, prowlarr):
    """Silently importing nothing looks identical to a broken connection."""
    r = client.post("/api/import", json={**BODY, "protocols": []})
    assert r.status_code == 400
    assert "torrent" in r.json()["detail"]


def test_candidates_report_their_protocol(client, cfg, prowlarr):
    """The preview shows it per row, so you can see what you are about to add
    rather than trusting the checkbox."""
    got = {c["id"]: c["protocol"] for c in
           client.post("/api/import", json=BODY).json()["candidates"]}
    assert got["realone"] == "torrent"
    assert got["usenetone"] == "usenet"


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
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
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


def test_api_host_is_recognized_as_already_configured(client, cfg, apihost):
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
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
    client.post("/api/import", json={**BODY, "apply": True})
    js = app.render_userscript("https://idlarr.test.internal")
    assert "// @match        *://*.broadcasthe.net/*" in js
    assert "api.broadcasthe.net" not in js


SUBDOMAIN = [{"name": "Alpha Tracker", "protocol": "torrent", "privacy": "private",
              "indexerUrls": ["https://www2.alpha.example/"]}]


def test_a_non_api_subdomain_is_still_the_same_tracker(client, cfg, monkeypatch):
    """`api.` is normalized away before comparison, so it does not exercise the
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


def test_saving_with_remember_off_clears_the_key(client, cfg, prowlarr):
    """Replaces the Forget button, which did the same job with a second
    control. Two controls for one outcome is how one of them ends up stale.

    It clears the KEY only. The source and URL are not secrets and keeping
    them means the form is still filled in next time.
    """
    client.post("/api/import", json=BODY)
    assert app.get_state("import_key")

    r = client.post("/api/import", json={"set_remember": False})
    assert r.json() == {"ok": True, "remembered": False, "removed": True}
    assert not app.get_state("import_key")
    assert app.get_state("import_url"), "the URL was cleared too"


def test_the_key_is_never_sent_back_to_the_browser(client, cfg, prowlarr):
    # A distinctive key: BODY's is one letter, which appears all over the page
    # and would make this assertion pass or fail for unrelated reasons.
    secret = "tk_zq7wvx4n8m2playbook"
    client.post("/api/import", json={**BODY, "api_key": secret})
    page = client.get("/").text
    assert secret not in page
    assert "saved &mdash; leave blank to reuse" in page
    assert BODY["url"] in page          # the URL is fine to show


def test_import_failures_are_logged_not_only_returned(client, cfg, monkeypatch, capsys):
    """The person who hits the error is rarely the person reading the logs.
    Returning the reason only to the browser leaves nothing to diagnose from."""
    monkeypatch.setattr(app, "_fetch_json",
                        lambda u, h: (_ for _ in ()).throw(ValueError("connection refused")))
    assert client.post("/api/import", json=BODY).status_code == 502
    assert "connection refused" in capsys.readouterr().out


def test_a_write_failure_is_reported_per_tracker_not_as_a_500(client, cfg, prowlarr, monkeypatch):
    """A read-only or wrongly-owned /config is the likeliest difference between
    two installs. Uncaught it became a bare 500 that named nothing."""
    def refuse(entry):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(app, "add_tracker", refuse)
    r = client.post("/api/import", json={**BODY, "apply": True})
    assert r.status_code == 200
    body = r.json()
    assert body["added"] == []
    assert len(body["failed"]) == 5
    assert "cannot write" in body["failed"][0]["error"]


def test_write_failures_are_logged(client, cfg, prowlarr, monkeypatch, capsys):
    monkeypatch.setattr(app, "add_tracker",
                        lambda e: (_ for _ in ()).throw(ValueError("refusing write")))
    client.post("/api/import", json={**BODY, "apply": True})
    out = capsys.readouterr().out
    assert "0 added, 5 failed" in out and "refusing write" in out


# ---------------------------------------------------------------- SSRF surface

@pytest.mark.parametrize("scheme", [
    "file:///etc/passwd",
    "gopher://internal:70/",
    "ftp://internal/secret",
    "http-x://weird",
    "//no-scheme.example",
])
def test_import_rejects_non_http_schemes(client, scheme):
    """The import fetches a user-supplied URL server-side. Allowing file:// would
    turn it into a local-file read, and other schemes widen the SSRF surface.
    Only http(s) is accepted, and the check must run BEFORE any fetch."""
    r = client.post("/api/import", json={"source": "prowlarr", "url": scheme,
                                         "api_key": "k"})
    assert r.status_code == 400


def test_import_does_not_fetch_before_validating_scheme(client, monkeypatch):
    """Prove nothing is fetched for a bad scheme — the guard is before the wire,
    not after."""
    called = []
    monkeypatch.setattr(app, "_fetch_json", lambda u, h: called.append(u) or [])
    client.post("/api/import", json={"source": "prowlarr",
                                     "url": "file:///etc/passwd", "api_key": "k"})
    assert called == [], "fetched a file:// URL before rejecting it"


# ------------------------------------------- not remembering the API key

def _fake_fetch(monkeypatch):
    """A source that answers, so the remember branch is actually reached.

    Patched at _fetch_json like the fixtures above, rather than at
    prowlarr_indexers: the first version stubbed the parser and returned raw
    API shapes, which the caller then indexed for keys the parser is what adds.
    """
    monkeypatch.setattr(app, "_fetch_json", lambda url, headers: PROWLARR)


def test_the_key_is_saved_by_default(client, cfg, monkeypatch):
    """Unchanged behavior, pinned. An upgrade must not quietly stop
    remembering a connection that worked yesterday."""
    _fake_fetch(monkeypatch)
    r = client.post("/api/import", json={"source": "prowlarr",
                                         "url": "http://prowlarr.local",
                                         "api_key": "SECRETKEY"})
    assert r.status_code == 200
    assert app.get_state("import_key") == "SECRETKEY"


def test_unticking_remember_never_writes_the_key(client, cfg, monkeypatch):
    """The import runs when a human clicks Preview, with the form open, so this
    credential is the one thing in `state` that need not be there at all."""
    _fake_fetch(monkeypatch)
    r = client.post("/api/import", json={"source": "prowlarr",
                                         "url": "http://prowlarr.local",
                                         "api_key": "SECRETKEY",
                                         "remember": False})
    assert r.status_code == 200
    assert not app.get_state("import_key")
    # The source and URL are not secrets and stay, so the form is still filled
    # in next time and only the key has to be retyped.
    assert app.get_state("import_url") == "http://prowlarr.local"


def test_an_import_never_destroys_a_stored_key(client, cfg, monkeypatch):
    """An earlier version cleared it here as well, so unticking the box and
    pressing Preview silently destroyed a saved credential. Removing one is
    Save's job and only Save's: a destructive action needs its own click, or
    there is no moment at which you could change your mind.
    """
    _fake_fetch(monkeypatch)
    client.post("/api/import", json={"source": "prowlarr",
                                     "url": "http://prowlarr.local",
                                     "api_key": "OLDKEY"})
    assert app.get_state("import_key") == "OLDKEY"

    client.post("/api/import", json={"source": "prowlarr",
                                     "url": "http://prowlarr.local",
                                     "api_key": "NEWKEY", "remember": False})
    assert app.get_state("import_key") == "OLDKEY", \
        "a preview destroyed the stored key"


def test_the_box_survives_a_reload(client, cfg, monkeypatch):
    """Derived from "is a key saved" instead, a fresh install and one you had
    just cleared would render identically while meaning opposite things."""
    _fake_fetch(monkeypatch)
    def box(html):
        return re.search(r'<input type="checkbox" id="imrem"[^>]*>', html).group(0)

    assert "checked" in box(app.settings_sheet("none", 7, 7, "/x.js")), \
        "a fresh install must default to remembering"
    client.post("/api/import", json={"set_remember": False})
    assert "checked" not in box(app.settings_sheet("none", 7, 7, "/x.js"))
    client.post("/api/import", json={"set_remember": True})
    assert "checked" in box(app.settings_sheet("none", 7, 7, "/x.js"))


def test_the_forget_row_is_gone(cfg):
    """Its whole job is now the remember box plus Save."""
    html = app.settings_sheet("none", 7, 7, "/x.js")
    assert 'id="imforget"' not in html and "Saved connection" not in html


def test_save_reaches_the_panel_and_posts_the_flag(cfg):
    html = app.settings_sheet("none", 7, 7, "/x.js")
    assert 'id="imsave"' in html
    assert "set_remember:on" in app.PAGE, "Save never sends the flag"


def test_an_absent_flag_still_remembers(client, cfg, monkeypatch):
    """A scripted caller written before this existed sends no `remember`. It
    must keep the behavior it was written against rather than silently losing
    its saved key on the next run."""
    _fake_fetch(monkeypatch)
    client.post("/api/import", json={"source": "prowlarr",
                                     "url": "http://prowlarr.local",
                                     "api_key": "SCRIPTKEY"})
    assert app.get_state("import_key") == "SCRIPTKEY"


def test_a_failed_fetch_saves_nothing_either_way(client, cfg, monkeypatch):
    """The existing rule, still holding with the new branch in place: a key
    that failed must not be replayed by blank-means-reuse."""
    def boom(url, headers):
        raise ValueError("connection refused")
    monkeypatch.setattr(app, "_fetch_json", boom)
    for remember in (True, False):
        client.post("/api/import", json={"source": "prowlarr",
                                         "url": "http://prowlarr.local",
                                         "api_key": "BADKEY",
                                         "remember": remember})
        assert not app.get_state("import_key")


def test_the_checkbox_reaches_the_panel_and_the_payload(cfg):
    """Pins the call site. The flag working server-side proves nothing if the
    form never sends it, and the box would silently do nothing."""
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert 'id="imrem"' in html, "no remember checkbox on the import form"
    assert 'checked' in re.search(r'<input type="checkbox" id="imrem"[^>]*>',
                                  html).group(0), "it must default to on"
    assert "remember:document.getElementById('imrem').checked" in app.PAGE, \
        "the payload never carries the flag"


def test_a_read_timeout_reports_instead_of_a_500(client, cfg, monkeypatch):
    """IMPORT_TIMEOUT exists to stop a hung Prowlarr hanging the request, so
    this fires by design rather than rarely. urlopen raises TimeoutError
    directly instead of wrapping it in URLError, and TimeoutError is an OSError
    sibling, so nothing in _fetch_json caught it: it escaped that function and
    then escaped the caller's `except ValueError` as well. The result was a 500
    traceback in place of the message written for this exact case.

    Found 2026-08-06 while adding the remember flag.
    """
    import urllib.request

    def hang(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr(urllib.request, "urlopen", hang)

    r = client.post("/api/import", json={"source": "prowlarr",
                                         "url": "http://prowlarr.local",
                                         "api_key": "K"})
    assert r.status_code == 502, f"got {r.status_code}, not a reported failure"
    assert "did not answer" in r.json()["detail"]
    assert not app.get_state("import_key"), "a timed-out key was remembered"


def test_the_checkbox_labels_are_capitalized(cfg):
    """Sentence case on every control label, asked for 2026-08-06. Pinned
    because nothing else would notice one drifting back: a lowercase label
    renders perfectly and reads as a typo only to whoever asked for it.
    """
    html = app.settings_sheet("none", 7, 7, "/x.js")
    for cid in ("imrem", "impt", "impu"):
        m = re.search(rf'<input type="checkbox" id="{cid}"[^>]*>\s*([A-Za-z])', html)
        assert m, f"no label text after the {cid} checkbox"
        assert m.group(1).isupper(), \
            f"the {cid} label starts lowercase ({m.group(1)!r})"


def test_all_three_checkboxes_share_one_row(cfg):
    """They are one set of options, not three scattered decisions. Remember
    lived beside the key field for a while and read as a fourth thing."""
    html = app.settings_sheet("none", 7, 7, "/x.js")
    row = re.search(r'<div class="improt">.*?</div>', html, re.S)
    assert row, "no protocol row"
    for cid in ("impt", "impu", "imrem", "imsave"):
        assert f'id="{cid}"' in row.group(0), f"{cid} is not on that row"


def test_save_matches_the_save_in_general_and_sign_in(cfg):
    """Same class and same width. Matching the class alone was not enough
    twice over: first this was a secondary button, then it was a primary one
    sized by its text while the others filled the control column.

    Every button in the panel is now one width, `--btn`, so there is nothing
    left for this one to differ on. Reported twice, 2026-08-06 and 08-07.
    """
    html = app.settings_sheet("none", 7, 7, "/x.js")
    assert '<button class="lk pri" id="imsave">' in html, \
        "Save is not the primary button the other panes use"
    assert ".sheet .lk{width:var(--btn)" in app.PAGE, \
        "settings controls are not on one shared width"
    rule = re.search(r"\.improt button\{([^}]*)\}", app.PAGE)
    assert rule and "width" not in rule.group(1), \
        "Save is being sized separately from the other buttons again"


def test_the_checkbox_row_wraps_before_it_overflows(cfg):
    """Three checkboxes plus a 200px button do not fit on one line at phone
    width. Without wrapping they overflow the pane instead of stacking."""
    css = app.PAGE
    rule = re.search(r"\.improt\{([^}]*)\}", css)
    assert rule and "flex-wrap:wrap" in rule.group(1), \
        "the row will overflow rather than wrap"


def test_save_sits_on_the_pane_edge(cfg):
    """Its right edge has to land where the full-width key field above ends.
    Everything here is width:100% under box-sizing:border-box, so margin-left:
    auto on the button is the whole mechanism."""
    rule = re.search(r"\.improt button\{([^}]*)\}", app.PAGE)
    assert rule, "no rule for the button on that row"
    assert "margin-left:auto" in rule.group(1), \
        "Save will sit next to the checkboxes instead of on the pane edge"


def test_the_jackett_note_left_the_row(cfg):
    """It used margin-left:auto to hold the right end, which is Save's edge
    now. Two things claiming one edge means each moves whenever the other
    appears."""
    html = app.settings_sheet("none", 7, 7, "/x.js")
    row = re.search(r'<div class="improt">.*?</div>', html, re.S).group(0)
    assert 'id="impnote"' not in row, "the note is back on Save's row"
    assert 'class="impnote" id="impnote" hidden' in html, "the note is gone entirely"
    assert ".impnote[hidden]{display:none}" in app.PAGE, \
        "it will show permanently, as a fact about the panel rather than a reason"


def test_save_says_whether_a_key_was_actually_removed(client, cfg, prowlarr):
    """"Saved key removed" when there was never one to remove is the same
    shape as the notification test that reported success without sending: a
    confirmation describing something that did not happen. The server knows
    which it was, so it reports it rather than leaving the page to guess.
    """
    # Nothing stored yet.
    r = client.post("/api/import", json={"set_remember": False})
    assert r.json() == {"ok": True, "remembered": False, "removed": False}

    # Now store one, then remove it.
    client.post("/api/import", json=BODY)
    assert app.get_state("import_key")
    r = client.post("/api/import", json={"set_remember": False})
    assert r.json()["removed"] is True
    assert not app.get_state("import_key")

    # And again, with nothing left.
    assert client.post("/api/import", json={"set_remember": False}).json()["removed"] is False


def test_the_page_reports_all_three_outcomes(cfg):
    """Ticked, unticked-and-removed, unticked-and-nothing-there. A single
    message for the last two would state a removal that did not occur."""
    script = app.PAGE
    for phrase in ("the key from your next import will be stored",
                   "saved key removed",
                   "nothing to remove; no key was stored"):
        assert phrase in script, f"the page never says {phrase!r}"
    assert "d.removed" in script, \
        "the page ignores what the server reported and guesses"
