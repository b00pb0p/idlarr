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
    "setTz", "setHour", "setPct", "setAlive", "setSave", "setErr",  # general
    "cfgUp", "cfgFile",                                    # config restore
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


def test_signin_form_defaults_to_forms_when_nothing_is_configured(page):
    """Pre-selecting the CURRENT method means "None" is selected on a fresh
    install, so filling in credentials and pressing Save posts method=none and
    silently changes nothing — on the one control that exists to stop the
    dashboard being open."""
    sel = re.search(r'<select id="amm">(.*?)</select>', page, re.S).group(1)
    assert '<option value="forms" selected>' in sel
    assert '<option value="none" selected>' not in sel


def test_signin_form_keeps_the_configured_method_selected(client):
    client.post("/api/auth", json={"method": "basic", "username": "jared",
                                   "password": "correct-horse"})
    sel = re.search(r'<select id="amm">(.*?)</select>',
                    client.get("/").text, re.S).group(1)
    assert '<option value="basic" selected>' in sel


# ---------------------------------------------------------------- version

def test_version_is_not_hardcoded_in_the_source():
    """It was, and it drifted on the very next release: v1.1.1 shipped
    reporting 1.1.0, so a container that had updated correctly told its owner
    it hadn't. It comes from the build now."""
    src = (Path(__file__).resolve().parent.parent / "app.py").read_text()
    assert 'IDLARR_VERSION = os.environ.get("IDLARR_VERSION"' in src
    assert not re.search(r'^IDLARR_VERSION = "[\d.]+"', src, re.M)


def test_the_build_chain_passes_the_version_through():
    """Three files have to agree — app.py reads the variable, the Dockerfile
    declares and exports it, and publish.yml supplies it. Breaking any one
    leaves the About panel reporting `dev` on a real release."""
    root = Path(__file__).resolve().parent.parent
    dockerfile = (root / "Dockerfile").read_text()
    assert "ARG IDLARR_VERSION" in dockerfile
    assert "ENV IDLARR_VERSION=${IDLARR_VERSION}" in dockerfile

    publish = (root / ".github" / "workflows" / "publish.yml").read_text()
    builds = publish.count("uses: docker/build-push-action@v6")
    passes = publish.count("build-args: IDLARR_VERSION=")
    assert builds == passes, f"{builds} build steps but {passes} pass the version"


def test_about_panel_reports_the_running_version(page, monkeypatch):
    assert f'<span class="val">{app.IDLARR_VERSION}</span>' in page


# ---------------------------------------------------------------- XSS surface
#
# The drawer builds its HTML by string concatenation in the browser, so any
# user-controlled string field interpolated without hesc() is an injection.
# immune_reason shipped exactly this way — reflected raw into value="..." while
# notes beside it was escaped — so a reason like `x" onmouseover="alert(1)`
# broke out of the attribute. These guards make the next such field fail here.

# Fields a user can set to arbitrary text (via /api/limit, /api/tracker, the
# import, or a hand-edited trackers.yml). Each must be escaped wherever the
# client-side JS drops it into markup.
USER_TEXT_FIELDS = ["immune_reason", "notes", "name", "url", "software"]


@pytest.mark.parametrize("field", USER_TEXT_FIELDS)
def test_user_text_is_escaped_before_it_reaches_markup(page, field):
    """Every string-concatenation interpolation of a user-text field must go
    through hesc(). A raw `'+d.notes` OR `'+(d.notes` fails; `'+hesc(d.notes`
    passes. The earlier version of this test missed the `'+(d.` form and passed
    vacuously on the very bug it was meant to catch — hence the explicit
    optional `(` and the `# noqa` allowlist for non-HTML uses below."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    # A `+` (string concat), optional whitespace, optional `(` or `hesc(`,
    # then the field. If the wrapper isn't hesc(, it's raw interpolation.
    hits = 0
    for m in re.finditer(r"\+\s*(hesc\(\s*|\(\s*)?[de]\.%s\b"
                         % re.escape(field), script):
        wrapper = (m.group(1) or "")
        assert wrapper.startswith("hesc"), (
            f"d.{field} interpolated without hesc() near "
            f"...{script[max(0,m.start()-30):m.start()+40]!r}")
        hits += 1


def test_immune_reason_specifically_is_escaped(page):
    """The one that shipped. Pin it by name so a regression is unmistakable."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert "hesc(d.immune_reason" in script
    assert re.search(r"value=\"'\+d\.immune_reason", script) is None


def test_no_css_selector_is_defined_twice_in_the_base_stylesheet():
    """Two `.imlist{...}` blocks drifted apart in the base stylesheet — one
    orphaned when Import moved out of a modal — and the cascade resolved the
    conflict non-obviously. Duplicate base-level selectors are almost always
    that: a leftover. Overrides inside @media are legitimate and excluded."""
    css = re.search(r"<style>(.*?)</style>", app.PAGE, re.S).group(1)
    # Drop @media blocks (balanced-brace scan) so intentional overrides don't trip it.
    base, depth, i = [], 0, 0
    while i < len(css):
        if css.startswith("@media", i):
            # skip to the matching close brace of this @media
            j = css.index("{", i); d = 1; j += 1
            while d and j < len(css):
                d += css[j] == "{"; d -= css[j] == "}"; j += 1
            i = j; continue
        base.append(css[i]); i += 1
    base_css = "".join(base)
    selectors = re.findall(r"(?:^|})\s*([^{}@]+?)\s*\{", base_css)
    seen = {}
    for sel in selectors:
        sel = " ".join(sel.split())          # normalise whitespace
        seen[sel] = seen.get(sel, 0) + 1
    dupes = {s: n for s, n in seen.items() if n > 1}
    assert not dupes, f"selectors defined more than once in the base stylesheet: {dupes}"


# ---------------------------------------------------------------- the drawer
#
# The drawer is built client-side, so its controls never appear in the served
# HTML — only in the script that renders them. These assert the script still
# creates every control its own handlers query, which is the failure the
# element-id test above cannot see.

@pytest.mark.parametrize("cls", [
    "lim", "pct", "snz", "snzclr", "nts", "rsn",   # inputs
    "chk", "imm", "seen", "undo", "del",           # buttons
    "a2", "msg", "sched", "hist",                  # structure
])
def test_drawer_builds_every_control_its_handlers_query(page, cls):
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert f"class=\"{cls}" in script or f"'{cls}" in script or f'.{cls}' in script, cls


def test_drawer_alert_threshold_is_a_percent_select_not_a_decimal(page):
    """It shipped as a raw 0.65 text input while the global setting was already
    a percent dropdown — the same control asking for two different units."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert "pctOpts" in script
    assert "'%</option>'" in script or "+'%</option>'" in script
    assert 'inputmode="decimal"' not in script


def test_dead_drawer_styles_are_gone(page):
    """.ctl/.field/.note/.reason were orphaned by the drawer redesign. A
    duplicated .imlist block drifted this exact way before."""
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    for sel in ("  .ctl{", "  .field{", "  .note{", "  .reason{", "  .ctl2r{"):
        assert sel not in css, f"dead rule still present: {sel.strip()}"


def test_healthz_reports_the_build_version(client, monkeypatch):
    """CI reads the version from here rather than scraping the About panel.
    Grepping HTML coupled the build check to markup, so a layout change could
    fail the release for no real reason — and the failure could not say why."""
    monkeypatch.setattr(app, "IDLARR_VERSION", "1.2.3")
    body = client.get("/healthz").json()
    assert body["version"] == "1.2.3"
    assert body["ok"] is True
    assert "trackers" in body


def test_healthz_version_matches_what_the_about_panel_shows(client):
    """Two surfaces, one value. If they can disagree, one of them is lying."""
    shown = client.get("/healthz").json()["version"]
    page = client.get("/").text
    assert f'<span class="val">{shown}</span>' in page
