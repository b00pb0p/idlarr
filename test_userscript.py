#!/usr/bin/env python3
"""Tests for the generated userscript.

The point of generating it is that the four hand-edits it replaces all failed
QUIETLY — a mismatched id 404s, a missing @connect is eaten by tracker CSP, a
stale token 401s, and none of those announce themselves on the status page. So
these tests are mostly about the negative: no placeholder survives, every id
matches the config /ping validates against, and drift between app.py and the
template raises rather than shipping a broken script.

Run:  .venv/bin/python -m pytest test_userscript.py -q
"""

import os
import re
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-us-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

BASE = "https://idlarr.test.internal"


@pytest.fixture(autouse=True)
def fresh():
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
    yield


@pytest.fixture
def js():
    return app.render_userscript(BASE)


# ------------------------------------------------------------- host_from_url

@pytest.mark.parametrize("url,want", [
    ("https://alpha.example/", "alpha.example"),
    ("https://www.empornium.sx", "empornium.sx"),
    ("http://beta.example/index.php", "beta.example"),
    ("https://a.b.c.example/browse?x=1", "a.b.c.example"),
    ("https://tracker.example:8443/", "tracker.example"),
    ("https://user:pw@tracker.example/", "tracker.example"),
    ("https://WWW.Shouty.EXAMPLE/", "shouty.example"),
    ("", ""),
])
def test_host_from_url(url, want):
    assert app.host_from_url(url) == want


def test_www_is_stripped_so_one_entry_covers_both():
    """The script matches on `hostname.includes(host)`, so keeping `www.` would
    silently fail on the apex domain — a tracker that records nothing while
    looking correctly configured."""
    assert app.host_from_url("https://www.x.example/") == "x.example"


# ------------------------------------------------------------- rendering

@pytest.mark.parametrize("placeholder", [
    "PUT_IDLARR_TOKEN_HERE",          # would 401 every ping
    "idlarr.example.ts.net",          # would point @connect/ENDPOINT at nothing
])
def test_no_placeholder_survives(js, placeholder):
    """Any of these reaching a browser installs cleanly and reports nowhere."""
    assert placeholder not in js


def test_endpoint_and_token_come_from_config(js):
    assert f'const ENDPOINT = "{BASE}/ping";' in js
    assert f'const TOKEN    = "{app.TOKEN}";' in js


def test_connect_names_the_endpoint_host(js):
    """Wrong or missing, and tracker CSP kills every request — the single
    hardest failure to diagnose from the browser side."""
    assert "// @connect      idlarr.test.internal" in js


def test_update_urls_point_back_at_the_service(js):
    """Without these, adding a tracker means reinstalling by hand."""
    assert f"// @updateURL   {BASE}/idlarr.user.js?token={app.TOKEN}" in js
    assert f"// @downloadURL {BASE}/idlarr.user.js?token={app.TOKEN}" in js


def test_one_match_line_per_tracker(js):
    hosts = {t["host"] for t in app.load_config()["trackers"] if t.get("host")}
    found = set(re.findall(r"^// @match\s+\*://\*\.(\S+)/\*$", js, re.M))
    assert found == hosts


def test_site_ids_match_the_config_exactly(js):
    """THE structural guarantee. A SITES id that is not in trackers.yml makes
    /ping answer 404 forever, and the status page just shows a tracker that
    never records — indistinguishable from a broken heuristic."""
    known = {t["id"] for t in app.load_config()["trackers"] if t.get("host")}
    emitted = set(re.findall(r'\{ host: "[^"]+", id: "([^"]+)"', js))
    assert emitted == known


def test_auth_sel_is_emitted_only_where_configured(js):
    cfg = {t["id"]: t for t in app.load_config()["trackers"]}
    assert 'id: "zeta", authSel: "a[href*=\\"/torrent?key=\\"]"' in js
    assert cfg["zeta"]["auth_sel"]
    # A tracker without one must not get an empty authSel: the script treats a
    # present selector as authoritative, so "" would never match and that
    # tracker would never record an auth event.
    assert 'id: "alpha", authSel' not in js


def test_trackers_without_a_host_are_left_out(monkeypatch):
    cfg = app.load_config()
    trimmed = {**cfg, "trackers": [{**t, "host": "" if t["id"] == "alpha" else t["host"]}
                                   for t in cfg["trackers"]]}
    monkeypatch.setattr(app, "load_config", lambda: trimmed)
    out = app.render_userscript(BASE)
    assert 'id: "alpha"' not in out
    assert 'id: "beta"' in out


def test_output_is_valid_javascript(js):
    esprima = pytest.importorskip("esprima")
    esprima.parseScript(js)


def test_metadata_block_is_intact(js):
    assert js.startswith("// ==UserScript==")
    assert "// ==/UserScript==" in js
    assert js.index("// ==UserScript==") < js.index("// ==/UserScript==")


# ------------------------------------------------------------- versioning

def test_version_only_moves_when_content_changes():
    """Violentmonkey compares versions as ordered values, so this counter must
    increase — and must NOT increase on an unchanged refetch, or every update
    check reinstalls."""
    first = app.userscript_version("payload-a")
    assert app.userscript_version("payload-a") == first
    second = app.userscript_version("payload-b")
    assert second != first
    assert int(second.rsplit(".", 1)[1]) > int(first.rsplit(".", 1)[1])


def test_rendered_version_is_in_the_metadata(js):
    assert re.search(r"^// @version\s+\d+\.\d+\.\d+$", js, re.M)


# ------------------------------------------------------------- drift guard

@pytest.mark.parametrize("drop,label", [
    (r"(?m)^  const TOKEN    = .*$", "token"),
    (r"(?m)^  const ENDPOINT = .*$", "endpoint"),
    (r"(?ms)  const SITES = \[.*?\n  \];", "sites array"),
    (r"(?m)^// @connect .*$", "connect line"),
])
def test_drift_between_template_and_renderer_raises(monkeypatch, tmp_path, drop, label):
    """If someone renames one of these lines in idlarr.user.js, the renderer
    must fail loudly. Silently serving a script with the placeholder still in
    it would 401 every ping and look exactly like a broken tracker."""
    mangled = re.sub(drop, "", app.USERSCRIPT_PATH.read_text(encoding="utf-8"), count=1)
    path = tmp_path / "idlarr.user.js"
    path.write_text(mangled, encoding="utf-8")
    monkeypatch.setattr(app, "USERSCRIPT_PATH", path)
    with pytest.raises(RuntimeError, match=label):
        app.render_userscript(BASE)


def test_missing_template_raises_something_readable(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "USERSCRIPT_PATH", tmp_path / "nope.user.js")
    with pytest.raises(RuntimeError, match="cannot read the userscript template"):
        app.render_userscript(BASE)


# ------------------------------------------------------------- the route

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(app, "STATUS_URL", BASE)
    return TestClient(app.app)


def test_route_is_open_when_no_login_is_configured(client):
    """Deliberate, and it is not a widening: with auth off /api/mark already
    lets a stranger reset a countdown, which is strictly worse than holding the
    token. Pinned as a test so nobody "fixes" it into an inconsistency."""
    assert app.auth_method() == "none"
    assert client.get("/idlarr.user.js").status_code == 200


def test_route_needs_the_token_or_a_session_once_auth_is_on(client):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    client.cookies.clear()
    assert client.get("/idlarr.user.js").status_code == 401
    assert client.get("/idlarr.user.js?token=wrong").status_code == 401
    r = client.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert r.status_code == 200
    assert "PUT_IDLARR_TOKEN_HERE" not in r.text


def test_route_accepts_a_ui_session(client):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    assert client.get("/idlarr.user.js").status_code == 200
    client.cookies.clear()
    assert client.get("/idlarr.user.js").status_code == 401


def test_route_serves_javascript(client):
    r = client.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert r.headers["content-type"].startswith("text/javascript")


def test_route_explains_a_missing_status_url(monkeypatch):
    """Serving a script whose ENDPOINT is empty would install fine and report
    nowhere. Refuse, and say what to set."""
    monkeypatch.setattr(app, "STATUS_URL", "")
    c = TestClient(app.app)
    r = c.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert r.status_code == 500
    assert "STATUS_URL" in r.json()["detail"]
