#!/usr/bin/env python3
"""Reporting a declined auth.

The password veto cannot tell a one-field change-password form from a login
form, so it declines both. Declining a login page is the point; declining a
profile page is the residual gap, and it was SILENT: the row looked exactly
like a tracker you had never opened. Finding which of your sites had such a
page meant visiting the profile page of every one of them.

Run:  .venv/bin/python -m pytest tests/test_veto_report.py -q
"""

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-veto-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"
AUTH = {"Authorization": "Bearer test-token"}


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


def veto(client, tid="alpha", path="/my.php"):
    return client.post("/ping", headers=AUTH,
                       json={"tracker": tid, "kind": "veto", "path": path})


# --------------------------------------------------------------- recording

def test_a_veto_is_recorded(client, cfg):
    assert veto(client).status_code == 200
    d = app.veto_for("alpha")
    assert d and d["path"] == "/my.php" and d["at"]


def test_a_veto_is_not_an_event(client, cfg):
    """`events` is append-only history of what the ACCOUNT did. This is the
    script saying it declined to judge a page, which is about DETECTION. Filed
    as an event it would be indistinguishable from a visit, and a visit is
    exactly what manufactures a false `logged out`."""
    veto(client)
    with app.db() as conn:
        n = conn.execute("SELECT count(*) FROM events").fetchone()[0]
    assert n == 0, "a veto was written into the events table"


def test_a_veto_never_moves_a_countdown(client, cfg):
    """The failure this project exists to prevent is a countdown that resets
    without a real login."""
    before = {r["id"]: r["days_since"] for r in app.statuses()}
    veto(client)
    assert {r["id"]: r["days_since"] for r in app.statuses()} == before


def test_the_latest_one_wins(client, cfg):
    veto(client, path="/my.php")
    veto(client, path="/usercp.php")
    assert app.veto_for("alpha")["path"] == "/usercp.php"


def test_an_unknown_tracker_is_shrugged_off_not_404(client, cfg):
    """A removed tracker keeps pinging until the script updates. For auth and
    visit that 404 teaches the client to back off; for a diagnostic there is
    nothing to back off from and nothing to report."""
    r = client.post("/ping", headers=AUTH,
                    json={"tracker": "ghost", "kind": "veto", "path": "/my.php"})
    assert r.status_code == 200
    assert not app.veto_for("ghost")


def test_it_still_needs_the_token(client, cfg):
    r = client.post("/ping", json={"tracker": "alpha", "kind": "veto"})
    assert r.status_code in (401, 403)
    assert not app.veto_for("alpha")


def test_an_unknown_kind_is_still_refused(client, cfg):
    r = client.post("/ping", headers=AUTH, json={"tracker": "alpha", "kind": "nonsense"})
    assert r.status_code == 400


def test_a_corrupt_record_reads_as_none(client, cfg):
    """It is JSON in a text column. Unreadable must mean `no veto`, not a 500
    on every page render."""
    app.set_state("veto_alpha", "{not json")
    assert app.veto_for("alpha") is None
    assert client.get("/").status_code == 200


# ------------------------------------------------------------- the row

def test_the_row_says_so(client, cfg):
    """The whole point: visible across every tracker at once, rather than
    opening the profile page of each one to find out."""
    assert 'class="veto"' not in client.get("/").text
    veto(client, path="/my.php")
    page = client.get("/").text
    row = re.search(r'<tr class="row" id="t-alpha".*?</tr>', page, re.S).group(0)
    assert 'class="veto"' in row, "the row does not show the declined detection"
    assert "/my.php" in row, "the tooltip does not name the page"


def test_only_the_reporting_tracker_is_marked(client, cfg):
    veto(client, tid="alpha")
    page = client.get("/").text
    beta = re.search(r'<tr class="row" id="t-beta".*?</tr>', page, re.S)
    assert beta and 'class="veto"' not in beta.group(0)


def test_the_marker_is_styled_and_distinct_from_the_note(client, cfg):
    """Same size and position as the note marker, but coloured: one is
    something you wrote, the other is something to act on. Two identical
    glyphs meaning different things is worse than neither."""
    assert "td.nm .veto{" in app.PAGE
    assert re.search(r"td\.nm \.veto\{[^}]*color:var\(--warn\)", app.PAGE), \
        "the marker has no colour, so it reads as another note"


def test_the_tooltip_is_escaped(client, cfg):
    """The path comes off a tracker page, so it is untrusted text going into
    an attribute."""
    veto(client, path='/x" onmouseover="alert(1)')
    page = client.get("/").text
    assert 'onmouseover="alert(1)' not in page
    assert "&quot;" in page or "&#34;" in page


# --------------------------------------------------------- the userscript

def _js():
    return (Path(__file__).parent.parent / "idlarr.user.js").read_text()


def test_the_script_reports_only_when_a_logout_was_found():
    """A page with no logout control is a different problem, and one this
    already warns about: it needs an authSel. Reporting both as the same thing
    would bury the one that is actionable."""
    src = _js()
    # Located by index rather than a braced regex: the block contains template
    # literals, and `${site.id}` closes a brace the regex would stop at.
    guard = src.find("visiblePasswordFields().length === 1 && findLogout()")
    assert guard != -1, "the veto report is not gated on a logout control"
    call = src.find("send('veto'", guard)
    assert call != -1, "no veto is sent inside that guard"
    # And nothing between them re-opens the gate.
    assert "findLogout" not in src[guard + 60:call], \
        "something else sits between the guard and the report"

    # The other ending must stay separate: no logout control at all needs an
    # authSel, and reporting both the same way buries the actionable one.
    assert "set authSel for this site" in src


def test_the_script_sends_the_path():
    assert re.search(r"send\('veto',\s*\{\s*path:", _js()), \
        "the report does not say WHICH page was declined"


def test_the_veto_has_its_own_cooldown_key():
    """send() keys the cooldown on `idl_<id>_<kind>`, so a veto cannot starve
    a visit or an auth of its own window, and cannot spam on a busy page."""
    src = _js()
    assert "const key = `idl_${site.id}_${kind}`" in src


# ------------------------------------------------------------- the loop

def _set_url(cfg, tid, url):
    import yaml
    d = yaml.safe_load(cfg.read_text())
    for t in d["trackers"]:
        if t["id"] == tid:
            t["url"] = url
    cfg.write_text(yaml.safe_dump(d))
    app._cfg_cache["data"] = None


def test_it_says_so_when_the_tracker_url_is_the_declined_page(client, cfg):
    """The loop. If the configured URL IS the page being declined, the link on
    that row leads somewhere that can never record an auth: every visit from
    the dashboard adds a visit and no auth, which is the dead-cookie
    signature, so the row cries `logged out` forever and the countdown never
    resets. "Visit another page" is useless advice when the dashboard is what
    sent you there. Pointed out 2026-08-27.
    """
    _set_url(cfg, "alpha", "https://alpha.example/my.php")
    veto(client, path="/my.php")
    row = re.search(r'<tr class="row" id="t-alpha".*?</tr>',
                    client.get("/").text, re.S).group(0)
    assert "own URL points at that page" in row, \
        "the row does not say the dashboard link is the problem"
    assert "veto loop" in row, "the loop variant is not marked"


def test_a_different_page_gets_the_ordinary_advice(client, cfg):
    """Declined on a page you happened to open is not a loop: the dashboard
    link still works, so the advice is simply to use it."""
    _set_url(cfg, "alpha", "https://alpha.example/browse.php")
    veto(client, path="/my.php")
    row = re.search(r'<tr class="row" id="t-alpha".*?</tr>',
                    client.get("/").text, re.S).group(0)
    assert "records auth normally" in row
    assert "own URL points at that page" not in row
    assert "veto loop" not in row


def test_the_comparison_ignores_the_query_string(client, cfg):
    """A configured URL often carries one; the reported path never does."""
    _set_url(cfg, "alpha", "https://alpha.example/my.php?tab=security")
    veto(client, path="/my.php")
    row = re.search(r'<tr class="row" id="t-alpha".*?</tr>',
                    client.get("/").text, re.S).group(0)
    assert "own URL points at that page" in row


def test_a_tracker_with_no_url_is_never_a_loop(client, cfg):
    """There is no link to be wrong."""
    _set_url(cfg, "alpha", "")
    veto(client, path="/my.php")
    row = re.search(r'<tr class="row" id="t-alpha".*?</tr>',
                    client.get("/").text, re.S).group(0)
    assert "veto loop" not in row


def test_the_loop_variant_is_visually_distinct(client, cfg):
    """It is the one with something to do about it."""
    assert re.search(r"td\.nm \.veto\.loop\{[^}]*color:", app.PAGE), \
        "the loop variant looks identical to the ordinary one"
