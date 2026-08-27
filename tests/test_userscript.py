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
    ("https://www.some-tracker.net", "some-tracker.net"),
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
    monkeypatch.setattr(app, "status_url", lambda: BASE)
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
    monkeypatch.setattr(app, "status_url", lambda: "")
    c = TestClient(app.app)
    r = c.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert r.status_code == 500
    assert "status page URL" in r.json()["detail"]


# ------------------------------------------------------------- packaging

def test_every_dockerfile_copy_is_allowed_by_dockerignore():
    """.dockerignore is deny-all plus an allow-list, so adding a COPY without a
    matching exception fails the build with "not found" for a file that plainly
    exists — six minutes into a multi-arch job, having already burned the arm64
    emulation. Its own comment warns about this; a comment is not a guard.
    """
    root = Path(__file__).resolve().parent.parent
    ignore = (root / ".dockerignore").read_text().splitlines()
    if not any(ln.strip() == "*" for ln in ignore):
        pytest.skip(".dockerignore is not deny-all; this check does not apply")
    allowed = {ln.strip()[1:] for ln in ignore if ln.strip().startswith("!")}

    for line in (root / "Dockerfile").read_text().splitlines():
        if not line.strip().upper().startswith("COPY "):
            continue
        parts = line.split()[1:]
        for src in parts[:-1]:                      # last token is the destination
            if src.startswith("--"):
                continue
            assert src in allowed, (
                f"Dockerfile copies {src!r} but .dockerignore does not allow it — "
                f"add '!{src}' or the build fails with 'not found'")


# ------------------------------------------- the veto that cried wolf

def _isauthed_source():
    """The isAuthed body from the shipped template."""
    src = (Path(__file__).parent.parent / "idlarr.user.js").read_text()
    return re.search(r"function isAuthed\(\) \{(.*?)\n  \}", src, re.S).group(1)


def test_one_password_field_vetoes_but_two_do_not():
    """A login form has exactly one password field; a change-password form has
    two or more, and only a signed-in user sees one.

    Reported 2026-08-17: mma-tracker.org/my.php carries `chpassword` and
    `passagain` beside an unmistakable Logout link. Vetoing on ANY visible
    password field made that page record a visit and no auth, which is the
    dead-cookie signature, so the row flipped to `logged out`. That is a HIGH
    priority alert, so the conservative direction was not free.
    """
    body = _isauthed_source()
    assert "visiblePasswordFields().length === 1" in body, \
        "the veto is not keyed on the field count, so a profile page still vetoes"
    assert "visiblePasswordField()" not in body, "the old any-field veto is back"


def test_the_veto_still_covers_the_per_site_selector():
    """authSel replaces the positive signal, never the guard. A login page that
    happened to contain the selector would reset a countdown, which is the
    worst failure this project has."""
    body = _isauthed_source()
    veto = body.index("visiblePasswordFields().length === 1")
    sel = body.index("site.authSel")
    assert veto < sel, "authSel is now checked before the veto, so it can bypass it"


def test_the_debug_helper_reports_the_count_not_a_boolean():
    """One field vetoes and two do not, so a bare true/false cannot explain the
    verdict it produced, which is the whole job of that helper."""
    src = (Path(__file__).parent.parent / "idlarr.user.js").read_text()
    assert "visiblePasswordFields: visiblePasswordFields().length" in src


def test_editing_the_template_marks_installed_scripts_stale(tmp_path, monkeypatch):
    """The version counter only moves when the payload hash changes, and the
    payload used to be the base URL, the @match block and SITES: the template
    itself was not in it.

    So editing the detection heuristic changed nothing the digest could see.
    The rev never moved, @version never changed, no script manager ever
    updated, and the stale banner never fired. A detection fix would reach the
    server and not one browser. Found 2026-08-17 shipping exactly such a fix.
    """
    tpl = tmp_path / "idlarr.user.js"
    tpl.write_text((Path(__file__).parent.parent / "idlarr.user.js").read_text())
    monkeypatch.setattr(app, "USERSCRIPT_PATH", tpl)

    before = app._userscript_payload("https://idlarr.example")[2]
    tpl.write_text(tpl.read_text().replace(
        "if (visiblePasswordFields().length === 1) return false;",
        "if (visiblePasswordFields().length > 99) return false;", 1))
    after = app._userscript_payload("https://idlarr.example")[2]

    assert before != after, \
        "a change to the detection heuristic does not move the payload hash"


def test_the_version_counter_moves_when_the_template_changes(tmp_path, monkeypatch):
    """Behavioral half: the @version a script manager compares must increase,
    or it will not offer the update."""
    tpl = tmp_path / "idlarr.user.js"
    tpl.write_text((Path(__file__).parent.parent / "idlarr.user.js").read_text())
    monkeypatch.setattr(app, "USERSCRIPT_PATH", tpl)
    app.set_state("userscript_hash", "")
    app.set_state("userscript_rev", "0")

    v1 = app.userscript_version(app._userscript_payload("https://idlarr.example")[2])
    v2 = app.userscript_version(app._userscript_payload("https://idlarr.example")[2])
    assert v1 == v2, "refetching an unchanged script must not bump the version"

    tpl.write_text(tpl.read_text().replace("const COOLDOWN", "const COOLDOWN2", 1))
    v3 = app.userscript_version(app._userscript_payload("https://idlarr.example")[2])
    assert v3 != v1, "editing the template did not produce a new version"
    assert int(v3.rsplit(".", 1)[1]) > int(v1.rsplit(".", 1)[1]), \
        "the version must INCREASE; managers compare them as ordered values"


def test_an_unreadable_template_does_not_take_the_page_down(tmp_path, monkeypatch):
    """The staleness check runs on every page render. render_userscript() is
    the one that must fail loudly on a missing template; this must not."""
    monkeypatch.setattr(app, "USERSCRIPT_PATH", tmp_path / "gone.js")
    app._userscript_payload("https://idlarr.example")
