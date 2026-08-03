#!/usr/bin/env python3
"""Tests for the rendered status page.

Nothing tested the page's own contract before this, and it has a sharp edge:
PAGE is a template filled by str.replace, so a renamed placeholder ships a page
with `__STATUS__` printed on it rather than failing anywhere. These assert the
substitutions happened, the settings panel is wired to elements that exist, and
the status line says what it should.

Run:  .venv/bin/python -m pytest test_page.py -q
"""

import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-page-test-")
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
    monkeypatch.setattr(app, "STATUS_URL", "https://idlarr.test.internal")
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
def page(client):
    return client.get("/").text


def test_no_placeholder_reaches_the_browser(page):
    """PAGE is filled by str.replace, so a renamed placeholder does not raise —
    it prints `__STATUS__` on the page and looks like a rendering glitch."""
    leftover = re.findall(r"__[A-Z_]+__", page)
    assert not leftover, f"unsubstituted: {leftover}"


def test_settings_panel_is_present_with_every_section(page):
    for section in ("general", "signin", "script", "import", "notify", "about"):
        assert f'id="s-{section}"' in page
        assert f'data-s="{section}"' in page


@pytest.mark.parametrize("element", [
    "sheet", "sx", "gear", "addtrk",                       # panel and header
    "amm", "amc", "amu", "amp", "amsave", "ame",           # sign-in form
    "ims", "imu", "imk", "imlist", "impreview", "imapply",  # import form
    "ntest", "nte", "cpjs", "tm", "tmn", "tmsave",         # test, copy, add
])
def test_every_element_the_script_reaches_for_exists(page, element):
    """The page's JS is one IIFE. A getElementById that returns null throws and
    kills every handler after it, including the ones that were fine."""
    assert f'id="{element}"' in page


def test_status_line_reports_the_real_counts(page, cfg):
    line = re.search(r'<div class="statusline">(.*?)</div>', page, re.S).group(1)
    assert "<b>7</b> trackers" in line
    assert 'sign-in <b class="bad">off</b>' in line


def test_status_line_shows_the_userscript_version_once_served(client, page):
    assert "not served yet" in page
    client.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert "userscript <b>1.1.1</b>" in client.get("/").text


def test_rendering_the_page_never_bumps_the_userscript_version(client):
    """Painting the dashboard must not invalidate the script already installed
    in someone's browser. The counter belongs to the generator alone."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")
    before = app.get_state("userscript_rev")
    for _ in range(3):
        client.get("/")
    assert app.get_state("userscript_rev") == before


def test_install_link_is_absent_without_status_url(client, monkeypatch):
    """A link that 500s is worse than no link. Say what to set instead."""
    monkeypatch.setattr(app, "STATUS_URL", "")
    page = client.get("/").text
    assert "idlarr.user.js?token=" not in page
    assert "STATUS_URL" in page


def test_signed_in_page_offers_sign_out(client):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    page = client.get("/").text
    assert 'id="amout"' in page
    assert 'sign-in <b class="ok">forms</b>' in page
    assert "No sign-in configured" not in page


def test_banner_button_targets_the_signin_section(page):
    """It should land on the section that fixes the problem, not merely open
    the panel and leave you hunting."""
    assert "js-authcfg" in page
    assert "openSheet('signin')" in page


# ---------------------------------------------------------------- test-notify

def test_test_notify_takes_a_session_or_the_token(client, monkeypatch):
    """It is a button in Settings now, and a fetch from the page sends a cookie,
    never a bearer header. The token path stays for scripts and the docs."""
    monkeypatch.setattr(app, "NOTIFY_URLS", ["json://localhost/"])
    monkeypatch.setattr(app, "dispatch", lambda *a: (True, ""))
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    assert client.post("/api/test-notify").status_code == 200      # session
    client.cookies.clear()
    assert client.post("/api/test-notify").status_code == 401
    r = client.post("/api/test-notify",
                    headers={"Authorization": f"Bearer {app.TOKEN}"})
    assert r.status_code == 200


def test_test_notify_sends_even_when_nothing_is_due(client, monkeypatch):
    """THE bug. It used to run the daily check, which sends nothing when
    nothing is due — so on a healthy install the test silently succeeded
    without notifying, and could not tell working alerts from broken ones."""
    sent = []
    monkeypatch.setattr(app, "NOTIFY_URLS", ["json://localhost/"])
    monkeypatch.setattr(app, "dispatch",
                        lambda title, body, prio: (sent.append((title, body)), (True, ""))[1])
    assert app.build_notification(app.statuses()) is None      # nothing due
    assert client.post("/api/test-notify").status_code == 200
    assert len(sent) == 1
    assert "Test from Idlarr" in sent[0][1]


def test_test_notify_reports_why_a_send_failed(client, monkeypatch):
    """Apprise signals refusal by returning False and logging the reason. Not
    surfacing it makes a bad token look identical to a delivered message."""
    monkeypatch.setattr(app, "NOTIFY_URLS", ["json://localhost/"])
    monkeypatch.setattr(app, "dispatch", lambda *a: (False, "403 forbidden"))
    r = client.post("/api/test-notify")
    assert r.status_code == 502
    assert "403 forbidden" in r.json()["detail"]


def test_test_notify_says_so_when_nothing_is_configured(client, monkeypatch):
    monkeypatch.setattr(app, "NOTIFY_URLS", [])
    r = client.post("/api/test-notify")
    assert r.status_code == 400
    assert "IDLARR_NOTIFY_URLS" in r.json()["detail"]


# ---------------------------------------------------------------- structure
#
# Both of these exist because app.py was once silently duplicated — two PAGE
# constants and two /login registrations — and the whole suite stayed green.
# The page rendered with correct markup and no stylesheet, which reads as a
# broken layout rather than as broken code.

@pytest.mark.parametrize("selector", [
    ".statusline{", ".sheet{", ".sheet .win{", ".sheet nav{", ".sheet .row{",
    ".sheet .row .ctl2{", ".hbtn{", ".gear{", ".xclose{", ".imlist{",
    ".banner{", ".modal{", ".legend{",
])
def test_layout_classes_have_rules(page, selector):
    """The markup is emitted from Python and the CSS lives in PAGE. Nothing
    couples them, so shipping one without the other is a silent failure: every
    element is present and correct, and the page looks wrecked."""
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    assert selector in css, f"markup uses {selector} but no rule defines it"


def test_no_route_is_registered_twice():
    """A duplicated block of app.py re-registers routes rather than raising.
    FastAPI takes the first match, so the second copy is dead code that still
    imports, still passes tests, and quietly diverges."""
    seen = {}
    for route in app.app.routes:
        if not hasattr(route, "methods"):
            continue
        key = (route.path, tuple(sorted(route.methods)))
        seen[key] = seen.get(key, 0) + 1
    assert not [k for k, n in seen.items() if n > 1]


def test_the_two_page_templates_stay_distinct():
    """LOGIN_PAGE is defined before PAGE and both end with the same
    `</style></head><body>`. Any edit that searches for that string finds the
    login page's copy first — which is exactly how the duplication happened."""
    assert app.PAGE.count("</style></head><body>") == 1
    assert app.LOGIN_PAGE.count("</style></head><body>") == 1
    assert app.PAGE is not app.LOGIN_PAGE
