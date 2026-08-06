#!/usr/bin/env python3
"""Tests for the rendered status page.

Nothing tested the page's own contract before this, and it has a sharp edge:
PAGE is a template filled by str.replace, so a renamed placeholder ships a page
with `__LEGEND__` printed on it rather than failing anywhere. These assert the
substitutions happened, the settings panel is wired to elements that exist, and
the table's columns agree across the four places that state them.

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
    monkeypatch.setattr(app, "status_url", lambda: "https://idlarr.test.internal")
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
    "impt", "impu", "impul", "impnote",                    # import protocols
    "ntest", "nte", "cpjs", "tm", "tmn", "tmsave", "tmimp",  # test, copy, add
    "setTz", "setHour", "setPct", "setAlive", "setSave", "setErr",  # general
    "cfgUp", "cfgFile",                                    # config restore
])
def test_every_element_the_script_reaches_for_exists(page, element):
    """The page's JS is one IIFE. A getElementById that returns null throws and
    kills every handler after it, including the ones that were fine."""
    assert f'id="{element}"' in page


def test_legend_reports_the_tracker_total(page, cfg):
    """The total moved off the status line into the first legend cell. It is
    the one number there that is not a state, so it is easy to drop when the
    strip is regenerated."""
    tot = re.search(r'<div class="tot"><b>(\d+)</b><span>([^<]+)</span>', page)
    assert tot, "no total cell in the legend"
    assert tot.group(1) == "7", tot.group(1)
    assert tot.group(2) == "trackers"


def test_about_shows_the_userscript_version_once_served(client, page):
    """Also moved off the status line. Before the script has ever been served
    it must say so rather than show a version nobody can install."""
    assert "not served yet" in page
    client.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert "1.1.1" in re.search(r'id="s-about".*?</section>',
                                client.get("/").text, re.S).group(0)


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
    monkeypatch.setattr(app, "status_url", lambda: "")
    page = client.get("/").text
    assert "idlarr.user.js?token=" not in page
    # It should say where to fix it, and that is Settings now, not .env.
    assert "status page URL" in page


def test_signed_in_page_offers_sign_out(client):
    client.post("/api/auth", json={"method": "forms", "username": "jared",
                                   "password": "correct-horse"})
    page = client.get("/").text
    assert 'id="amout"' in page
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
    ".sheet{", ".sheet .win{", ".sheet nav{", ".sheet .row{",
    ".sheet .row .ctl2{", ".hbtn{", ".gear{", ".xclose{", ".imlist{", ".addbtn{",
    ".banner{", ".modal{", ".legend{",
    # added with the vitals layout: the header trace, the elapsed meta line,
    # the software/chip strip under the name, the unit under the countdown,
    # the legend's total cell and the footer's label rows
    ".pulse{", ".elm{", "td.nm .m2{", "td.n small{", ".legend .tot{", ".foot .fr{",
])
def test_layout_classes_have_rules(page, selector):
    """The markup is emitted from Python and the CSS lives in PAGE. Nothing
    couples them, so shipping one without the other is a silent failure: every
    element is present and correct, and the page looks wrecked.

    Checked against the BASE stylesheet, not the whole thing: `.pulse{` also
    appears as `@media(...){.pulse{display:none}}`, so searching the raw CSS
    passed even with the real rule deleted — the guard proved nothing for
    every class that happens to carry a mobile override."""
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    base = _base_stylesheet(css)
    assert selector in base, f"markup uses {selector} but no base rule defines it"


def test_table_column_count_agrees_everywhere(page):
    """The `--cols` grid template, <thead>, every body row and the drawer's
    colspan are four separate statements of one number. Add or drop a column
    and three of them still render — the header labels just stop sitting over
    their data, or the drawer stops spanning the row. Nothing couples them.

    `--cols` is the layout authority since the table stopped being a table:
    rows are grid cards so a row and its drawer can butt together."""
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    tracks = re.search(r"--cols:([^;}]+)", css).group(1).split()
    n = len(tracks)
    heads = len(re.findall(r"<th\b", page))
    spans = {int(x) for x in re.findall(r'colspan="(\d+)"', page)}
    rows = re.findall(r'<tr class="row".*?</tr>', page, re.S)
    assert rows, "fixture rendered no rows, so this guard proves nothing"
    cells = {len(re.findall(r"<td\b", r)) for r in rows}

    assert heads == n, f"--cols has {n} tracks {tracks} but {heads} <th>"
    assert cells == {n}, f"{n} columns but rows have {cells} <td>"
    assert spans == {n}, f"{n} columns but colspan is {spans}"


def test_import_offers_both_protocols_checked(page):
    """Usenet accounts lapse for inactivity too, and the import used to drop
    them. Both boxes must default to CHECKED: shipping usenet unticked would
    reproduce the old behavior for anyone who does not notice the control."""
    css = _base_stylesheet(re.search(r"<style>(.*?)</style>", page, re.S).group(1))
    assert ".improt{" in css, "checkboxes have no styling"
    for eid in ('id="impt"', 'id="impu"'):
        m = re.search(r'<input type="checkbox" ' + eid + r'([^>]*)>', page)
        assert m, f"{eid} missing"
        assert "checked" in m.group(1), f"{eid} does not default to checked"
    script = re.search(r"<style>(.*?)</style>", page, re.S).group(1) and \
        re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert "protocols:" in script, "the selection is never sent to the endpoint"
    # Jackett has no usenet, so the box is disabled when it is the source. A
    # disabled box must not contribute to the payload whatever its checked
    # state, or picking Jackett would ask for a protocol it cannot serve.
    assert "imsync" in script, "the usenet box never reacts to the source"
    assert "!p[0].disabled" in script, "a disabled protocol box is still sent"
    assert re.search(r'<em id="impnote" hidden>', page), \
        "the Jackett note must start hidden; it only applies to one source"


def test_add_tracker_offers_the_import_route(page):
    """The two ways to add a tracker live in different places, with nothing
    linking them: this dialog, and Import inside Settings. A new user finds one
    and never learns the other exists. The prompt must actually open the Import
    section, not merely the settings panel."""
    assert 'id="tmimp"' in page
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    m = re.search(r"tmimp'\)\.addEventListener\('click',\(\)=>\{(.*?)\}\)", script, re.S)
    assert m, "the import prompt has no click handler"
    assert "openSheet('import')" in m.group(1), \
        f"prompt does not open the Import section: {m.group(1).strip()}"


def test_page_renders_once_a_browser_has_reported_a_version(client, cfg):
    """The stale-script banner reads `js_url`, and it was first written ABOVE
    the line that defines it. Every test still passed, because the guard is
    `if stale and js_url` and `stale` is None until some browser has actually
    pinged, so the NameError was short-circuited away. The page 500'd only on a
    real install, the moment the first ping arrived.

    So: render the page in BOTH states, not just the quiet one."""
    assert client.get("/").status_code == 200          # nothing has reported

    app.set_state("script_seen", "1.1.1")              # a browser reports in
    app.set_state("userscript_rev", "4")               # and the server moved on
    r = client.get("/")
    assert r.status_code == 200, "page 500s once a version has been reported"
    assert 'id="stale"' in r.text, "no warning that the installed script is behind"
    assert "1.1.1" in r.text and "1.1.4" in r.text


def test_ping_without_a_version_still_works(client, cfg):
    """Backwards compatibility both ways. A script installed before versions
    were reported sends no `v`, and must not be rejected, and must not wipe a
    version some other browser already reported."""
    app.set_state("script_seen", "1.1.5")
    r = client.post("/ping", json={"tracker": "alpha", "kind": "visit"},
                    headers={"Authorization": f"Bearer {app.TOKEN}"})
    assert r.status_code == 200
    assert app.get_state("script_seen") == "1.1.5"


def test_a_removed_tracker_gets_a_useful_404(client, cfg):
    """The browser keeps its @match until the next update check, so a tracker
    you removed still pings. "add it to trackers.yml" was exactly wrong advice
    for that case."""
    r = client.post("/ping", json={"tracker": "deleted-one", "kind": "auth"},
                    headers={"Authorization": f"Bearer {app.TOKEN}"})
    assert r.status_code == 404
    d = r.json()["detail"]
    assert "removed" in d and "typo" in d
    assert "add it to trackers.yml" not in d


def test_the_userscript_backs_off_on_a_4xx(client):
    """The cooldown is written only on success, so failures retry next page
    load. That is right for a timeout and wrong for a 404: a removed tracker
    would POST and fail on EVERY page load of that site until the script
    updates. 5xx must still retry."""
    js = (Path(__file__).resolve().parent.parent / "idlarr.user.js").read_text()
    assert "res.status >= 400 && res.status < 500" in js, \
        "no 4xx back-off; a removed tracker will hammer /ping"
    # the success path must still be the only one that counts as recorded
    assert js.count("GM_setValue(key, Date.now())") == 2


def test_an_import_marks_the_script_stale_with_no_fetch(client, cfg):
    """The version counter is LAZY: `userscript_rev` moves only inside
    render_userscript(), which runs when the script is fetched. Comparing revs
    alone therefore reported "up to date" for the entire window between an
    import and the browser's next update check, which is precisely when you
    need telling. Reported from the field after a usenet import.

    Nothing here fetches the script after the change, on purpose."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")     # a version now exists
    app.set_state("script_seen", app.userscript_version_peek())
    assert 'id="stale"' not in client.get("/").text, "should be current"

    r = client.post("/api/tracker", json={
        "id": "nzbsin", "name": "NZBs.in", "url": "https://nzbs.in/",
        "inactivity_days": 30})
    assert r.status_code == 200, r.text

    body = client.get("/").text
    assert 'id="stale"' in body, \
        "an import left the browser's script uncovered and said nothing"
    assert "tracker list has changed" in body


def test_removing_a_tracker_marks_the_script_stale_too(client, cfg):
    """Removal is the same lazy-counter problem as an import, from the other
    direction: the browser keeps the removed site in its @match until it
    updates, so it carries on pinging a tracker that no longer exists. The page
    has to say the script is behind for that to ever resolve.

    Nothing re-fetches the script here either."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")
    app.set_state("script_seen", app.userscript_version_peek())
    assert 'id="stale"' not in client.get("/").text

    victim = app.load_config()["trackers"][0]["id"]
    assert client.delete(f"/api/tracker/{victim}").status_code == 200

    body = client.get("/").text
    assert 'id="stale"' in body, "a removal left the script matching a dead site"
    assert "tracker list has changed" in body


def test_no_stale_warning_before_a_script_has_been_generated(client, cfg):
    """Nothing can be behind a script that does not exist. A first-run install
    must not be told to reinstall what it has not got."""
    assert (app.get_state("userscript_rev", "0") or "0") == "0"
    assert 'id="stale"' not in client.get("/").text


def test_no_stale_warning_while_the_script_matches_the_config(client, cfg):
    """Serving the script records the hash of what it contains. Until the
    config moves past that, there is nothing to warn about, even though no
    browser has reported a version."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")
    assert 'id="stale"' not in client.get("/").text


def test_the_dismiss_key_changes_when_the_config_changes(client, cfg):
    """Dismissing the banner stores its key so it stays hidden. If that key did
    not move when the config moved, dismissing after adding one tracker would
    hide the warning for every tracker you added afterwards, silently. Keyed on
    the config hash for exactly that reason."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")

    def key_after(tid):
        client.post("/api/tracker", json={
            "id": tid, "name": tid, "url": f"https://{tid}.example/",
            "inactivity_days": 30})
        m = re.search(r'id="stale" data-v="([^"]+)"', client.get("/").text)
        assert m, f"no banner after adding {tid}"
        return m.group(1)

    first, second = key_after("one"), key_after("two")
    assert first != second, \
        "dismissing the first warning would have hidden the second"


def test_stale_warning_without_any_reported_version(client, cfg):
    """THE upgrade case, reported from the field on 1.6.0.

    A userscript installed before version reporting existed sends no version,
    so `script_seen` is empty. Requiring it made the warning useless exactly
    when it was first needed: adding a tracker warned nobody, because the only
    way to start reporting a version is to install the new script, which is the
    very thing the banner exists to prompt.

    The earlier test here asserted the opposite and passed, because it set up
    the precondition the real upgrade does not have."""
    client.get(f"/idlarr.user.js?token={app.TOKEN}")      # a script exists
    assert not app.get_state("script_seen"), "nobody has reported a version"

    r = client.post("/api/tracker", json={
        "id": "test1", "name": "Test 1", "url": "https://test1.example/",
        "inactivity_days": 30})
    assert r.status_code == 200, r.text

    body = client.get("/").text
    assert 'id="stale"' in body, \
        "added a tracker with an unreported script version and said nothing"
    assert "tracker list has changed" in body


def test_ping_records_the_reported_script_version(client, cfg):
    """This is what makes the comparison possible at all."""
    client.post("/ping", json={"tracker": "alpha", "kind": "auth", "v": "1.1.9"},
                headers={"Authorization": f"Bearer {app.TOKEN}"})
    assert app.get_state("script_seen") == "1.1.9"


def test_timezone_is_a_picker_not_free_text(page):
    """Free text meant a typo was only caught on Save, and nobody remembers
    whether it is America/Sao_Paulo or America/Sao Paulo. The configured zone
    must always be an option even if this build's tzdata does not list it —
    otherwise opening Settings silently reselects the first zone and Save
    changes every countdown."""
    sel = re.search(r'<select id="setTz">(.*?)</select>', page, re.S)
    assert sel, "timezone is not a <select>"
    body = sel.group(1)
    assert "<optgroup" in body, "a flat list of ~500 zones is a scroll, not a choice"
    assert '<option value="UTC"' in body
    cur = app.load_config()["timezone"]
    assert re.search(rf'<option value="{re.escape(cur)}" selected>', body), \
        f"configured zone {cur} is not the selected option"


def test_closing_settings_discards_unsaved_edits(page):
    """The panel is rendered once, server-side; closing it only removed a CSS
    class. An abandoned edit stayed in the DOM, so reopening showed it as the
    saved config — and the next Save posted it. Reported from a live install
    after clearing the timezone field and closing without saving."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    close = re.search(r"const closeSheet=\(\)=>\{(.*?)\};", script)
    assert close, "closeSheet not found in its expected form"
    assert "resetFields" in close.group(1), \
        "closing only hides the panel; unsaved edits survive into the next open"
    assert "defaultValue" in script and "defaultSelected" in script
    # ...and a save must move the defaults forward, or closing after saving
    # would revert the very change that was just written. Assert the CALL, not
    # the declaration — matching bare "keepAsSaved" passed with the call
    # deleted, because the function itself was still defined.
    assert "keepAsSaved(document.getElementById('s-general'))" in script, \
        "general save does not update the defaults; closing would undo it"


def test_a_note_shows_a_marker_on_the_row(client, cfg):
    """Only the FIRST word of notes reaches the row, as the software line, so a
    note that does not begin with a known software name changed nothing visible
    and read as not having saved."""
    with_notes = [t for t in app.load_config()["trackers"]
                  if (t.get("notes") or "").strip()]
    assert with_notes, "fixture has no notes, so this proves nothing"
    assert client.get("/").text.count('class="note"') == len(with_notes)

    tid = with_notes[0]["id"]
    client.post(f"/api/limit/{tid}", json={"notes": ""})
    assert client.get("/").text.count('class="note"') == len(with_notes) - 1, \
        "clearing a note left its marker behind"

    # The reported case: a note that is not a software name at all.
    client.post(f"/api/limit/{tid}", json={"notes": "lost this one once already"})
    body = client.get("/").text
    assert body.count('class="note"') == len(with_notes)
    assert 'title="lost this one once already"' in body


def test_the_note_marker_is_not_the_hand_marker(page):
    """The pencil already means "last auth was marked by hand". Two identical
    glyphs meaning different things is worse than having neither."""
    m = re.search(r'<span class="note"[^>]*>(.*?)</span>', page, re.S)
    assert m, "no note marker rendered"
    assert "&#9998;" not in m.group(1), "the note marker reuses the hand pencil"
    assert "<svg" in m.group(1)


def test_note_text_is_escaped_into_the_marker_title(client, cfg):
    """It is user text going into an attribute. The drawer's XSS guard covers
    the client-built markup; this one is server-rendered and needs its own."""
    tid = app.load_config()["trackers"][0]["id"]
    client.post(f"/api/limit/{tid}", json={"notes": 'x" onmouseover="alert(1)'})
    body = client.get("/").text
    assert 'onmouseover="alert(1)' not in body
    assert "&quot;" in body or "&#34;" in body


def test_paint_keeps_the_software_line_and_marker_in_step(page):
    """Both are derived from `notes`, and editing notes in the drawer repaints
    the row. paint() was not touching the software line at all, despite a
    comment at the notes handler saying it did, so changing the software word
    left the old one on the row until a reload."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    paint = re.search(r"function paint\(tr,d\)\{(.*?)\n \}", script, re.S)
    assert paint, "paint() not found"
    body = paint.group(1)
    assert "d.software" in body, "paint never updates the software line"
    assert "'.note'" in body or '".note"' in body, "paint never updates the marker"


def test_add_tracker_dialog_forgets_what_you_typed(page):
    """Same shape as the settings panel: rendered once, and closing it only
    removed a CSS class. Reported after adding a tracker, removing it, then
    reopening the dialog to find every field still filled in.

    Two causes, both needed. closeTrk() has to restore the fields, AND the
    inputs have to opt out of form restoration: a successful add ends in
    location.reload(), and browsers repopulate inputs across a reload unless
    told not to. Fixing only the close handler leaves the reload path."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    close = re.search(r"const closeTrk=\(\)=>\{(.*?)\};", script)
    assert close, "closeTrk not found in its expected form"
    assert "resetFields" in close.group(1), \
        "closing the dialog leaves what you typed in the DOM"

    for eid in ("tmn", "tmu", "tmi", "tmd", "tmo"):
        m = re.search(r'<input id="' + eid + r'"([^>]*)>', page)
        assert m, eid
        assert 'autocomplete="off"' in m.group(1), \
            f"{eid} will be repopulated by the browser after location.reload()"


def test_one_reset_helper_serves_every_panel(page):
    """There were two panels of the same shape and only one got fixed. The
    helper takes a root now, so the next one cannot be forgotten by being
    written against a different container."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    assert "const resetFields=root=>" in script
    assert "resetFields(sheet)" in script and "resetFields(tm)" in script


def test_settings_label_bold_does_not_leak_into_help_text(page):
    """`.sheet .row .lbl b` matched any <b> inside the row's help text too, so
    an emphasised phrase became a block-level 14.5px heading mid-sentence and
    split the sentence across three lines. Two rows already did this. The rule
    must stay a DIRECT-child selector."""
    css = _base_stylesheet(re.search(r"<style>(.*?)</style>", page, re.S).group(1))
    assert ".sheet .row .lbl>b{" in css, \
        "label bold must be `.lbl>b`, or <b> in help text renders as a heading"
    assert re.search(r"\.sheet \.row \.lbl b\{", css) is None, \
        "descendant form is back; <b> in help text will break the layout again"


@pytest.mark.parametrize("method,shown", [("none", False), ("forms", True),
                                          ("basic", False)])
def test_signout_appears_only_where_it_works(client, method, shown):
    """Under HTTP Basic the browser re-sends the Authorization header on every
    request, so dropping the session cookie does not sign you out — the next
    request is authenticated again. Neither sign-out control may appear there,
    and there is nothing to sign out of when auth is off.

    Both are checked together: they are rendered in different places (the
    header and the Sign-in panel) from separate conditions, so one can be
    tightened while the other keeps offering a button that does nothing."""
    if method != "none":
        client.post("/api/auth", json={"method": method, "username": "jared",
                                       "password": "correct-horse"})
    body = client.get("/", auth=("jared", "correct-horse")).text
    for el in ('id="hout"', 'id="amout"'):
        assert (el in body) is shown, \
            f"method={method}: {el} should{'' if shown else ' not'} be present"
    if shown:
        script = re.search(r"<script>(.*?)</script>", body, re.S).group(1)
        for h in ("'hout'", "'amout'"):
            assert h in script, f"{h} rendered but no handler wired to it"


def test_every_row_cell_the_script_repaints_exists(page):
    """`paint()` rewrites a row in place after an edit. It queried `td.seen`
    and `td.lim`, which the five-column layout removed — so the first one
    returned null, threw, and killed the rest of the repaint. The row kept its
    old countdown and the console showed
    "can't access property textContent, tr.querySelector(...) is null".

    Nothing coupled the script's selectors to the cells the server renders;
    the element-id test above only covers ids, and these are classes."""
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    wanted = set(re.findall(r"querySelector\('(td\.\w+|\.\w+)'\)", script))
    row = re.search(r'<tr class="row".*?</tr>', page, re.S)
    assert row, "fixture rendered no rows, so this guard proves nothing"
    have = {f"td.{c}" for c in re.findall(r'<td class="(\w+)', row.group(0))}
    have |= {f".{c}" for c in re.findall(r'class="([\w-]+)', row.group(0))}
    missing = {w for w in wanted if w in {f"td.{x}" for x in
               ("s", "nm", "st", "n", "el", "sw", "seen", "lim")} } - have
    assert not missing, f"paint() queries cells the row no longer has: {missing}"


def test_the_two_unit_label_maps_agree(page):
    """The unit under each countdown ("days left", "days over", "exempt") is
    stated twice: LABELS in Python renders it, LABEL in the page's JS rewrites
    it after an edit. They had already drifted on `immune` — and neither was
    reachable, because the row builder carried a third, inline copy of the
    rule. Compare VALUES; comparing key sets is what let the drift through."""
    js = dict(re.findall(r"(\w+):'([^']*)'",
                         re.search(r"const LABEL=\{(.*?)\};", page, re.S).group(1)))
    assert js == app.LABELS, (
        f"python-only {set(app.LABELS.items()) - set(js.items())}, "
        f"js-only {set(js.items()) - set(app.LABELS.items())}")


def test_the_drawer_does_not_inherit_the_row_nowrap(page):
    """`td{white-space:nowrap}` exists so a long tracker name ellipsizes in its
    own cell. The drawer is a <td> too, so it inherited nowrap — and its prose
    (the empty-schedule and empty-history messages are whole sentences) ran out
    of its pane and printed across the one beside it.

    Only reproducible above 760px: the mobile block already sets
    td{white-space:normal}, so a phone-width check would have passed."""
    css = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    rule = re.search(r"\n  tr\.drawer td\{(.*?)\}", _base_stylesheet(css), re.S)
    assert rule, "no base tr.drawer td rule"
    assert "white-space:normal" in " ".join(rule.group(1).split()), \
        "drawer inherits td{white-space:nowrap}; its prose will overrun the next pane"


def test_every_sort_option_resolves_to_a_header(page):
    """The mobile <select> sorts by clicking the matching (hidden) <th>. An
    option whose column no longer exists silently does nothing — the list just
    fails to reorder, which reads as a broken table rather than dead markup."""
    sel = re.search(r'<select id="msf".*?</select>', page, re.S).group(0)
    options = set(re.findall(r'<option value="(\w+)">', sel))
    headers = set(re.findall(r'<th data-k="(\w+)"', page))
    assert options, "no sort options rendered"
    assert options <= headers, f"sort options with no <th>: {options - headers}"


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
    # Match the action WITHOUT its version. Counting `@v6` made this fail the
    # moment Dependabot proposed `@v7`: builds dropped to 0 while passes stayed
    # at 2, so a routine bump looked like a broken release chain. The invariant
    # is "every build step passes the version", not "the action is at v6".
    builds = len(re.findall(r"uses:\s*docker/build-push-action@", publish))
    passes = publish.count("build-args: IDLARR_VERSION=")
    assert builds, "no docker build steps found; did the action get renamed?"
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


def _base_stylesheet(css: str) -> str:
    """`css` with every @media block removed, by balanced-brace scan. Rules
    inside a media query are overrides: they neither count as a duplicate
    definition nor as the base definition of a class."""
    base, i = [], 0
    while i < len(css):
        if css.startswith("@media", i):
            j = css.index("{", i); d = 1; j += 1
            while d and j < len(css):
                d += css[j] == "{"; d -= css[j] == "}"; j += 1
            i = j; continue
        base.append(css[i]); i += 1
    return "".join(base)


def test_no_css_selector_is_defined_twice_in_the_base_stylesheet():
    """Two `.imlist{...}` blocks drifted apart in the base stylesheet — one
    orphaned when Import moved out of a modal — and the cascade resolved the
    conflict non-obviously. Duplicate base-level selectors are almost always
    that: a leftover. Overrides inside @media are legitimate and excluded."""
    css = re.search(r"<style>(.*?)</style>", app.PAGE, re.S).group(1)
    selectors = re.findall(r"(?:^|})\s*([^{}@]+?)\s*\{", _base_stylesheet(css))
    seen = {}
    for sel in selectors:
        sel = " ".join(sel.split())          # normalize whitespace
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
