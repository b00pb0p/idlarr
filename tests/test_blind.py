#!/usr/bin/env python3
"""A tracker the script cannot read, and the one question that fixes it.

Some sites keep no sign-out control in the page at all: single-page apps
usually render it only once a menu is opened. The script then has nothing to
judge by, records visits and never a login, and the dashboard called that
`logged out`. That was false, the user signed in again, nothing changed, and
the only way out was finding a CSS selector in a browser console and editing
trackers.yml by hand. Reported on milkie.cc 2026-10-02.

Run:  .venv/bin/python -m pytest tests/test_blind.py -q
"""

import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-blind-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"
AUTH = {"Authorization": "Bearer test-token"}
SEL = "button.profile-button"


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


def ping(client, kind, tid="alpha", **extra):
    return client.post("/ping", headers=AUTH,
                       json={"tracker": tid, "kind": kind, **extra})


def blind(client, tid="alpha", cand=(SEL,), path="/browse"):
    return ping(client, "blind", tid, path=path, cand=list(cand))


def event(tid, kind, days_ago, source="userscript"):
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    with app.db() as conn:
        conn.execute("INSERT INTO events (tracker_id, kind, ts, source) VALUES (?,?,?,?)",
                     (tid, kind, ts, source))


def row(tid="alpha"):
    return next(r for r in app.statuses() if r["id"] == tid)


def events(tid="alpha", kind="auth"):
    with app.db() as conn:
        return conn.execute("SELECT ts, source FROM events WHERE tracker_id=? AND kind=? "
                            "ORDER BY ts", (tid, kind)).fetchall()


def entry(cfg, tid="alpha"):
    return next(t for t in yaml.safe_load(cfg.read_text())["trackers"] if t["id"] == tid)


# ----------------------------------------------------------------- the report

def test_it_is_recorded_with_what_the_script_found(client, cfg):
    assert blind(client).status_code == 200
    b = app.blind_for("alpha")
    assert b["path"] == "/browse" and b["cand"] == [SEL]
    assert datetime.fromisoformat(b["iso"]).tzinfo is not None, \
        "the time is not comparable with an event timestamp"


def test_it_is_not_an_event(client, cfg):
    """`events` is what the ACCOUNT did. Filing this as a visit would
    manufacture the very state it exists to explain."""
    blind(client)
    with app.db() as conn:
        assert conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"] == 0


def test_it_needs_the_token(client, cfg):
    r = client.post("/ping", json={"tracker": "alpha", "kind": "blind"})
    assert r.status_code == 401
    assert app.blind_for("alpha") is None


def test_an_unknown_tracker_is_shrugged_off(client, cfg):
    r = blind(client, tid="nope")
    assert r.status_code == 200 and "ignored" in r.json()
    assert app.blind_for("nope") is None


def test_candidates_are_filtered_not_trusted(client, cfg):
    """They come off a tracker page. Anything that is on every page would
    record a login on every page, so it never becomes a suggestion."""
    blind(client, cand=["body", "*", 7, "", SEL, SEL, "x" * 300,
                        "a.one", "a.two", "a.three"])
    assert app.blind_for("alpha")["cand"] == [SEL, "a.one", "a.two"]


def test_a_corrupt_record_reads_as_none(client, cfg):
    app.set_state("blind_alpha", "{not json")
    assert app.blind_for("alpha") is None
    assert client.get("/").status_code == 200


# -------------------------------------------------------------- what clears it

def test_a_login_form_clears_it(client, cfg):
    """A visible login form is a real signed-out page, so the script CAN tell
    and a standing question would be wrong."""
    blind(client)
    ping(client, "blind", login=True)
    assert app.blind_for("alpha") is None


def test_an_observed_login_clears_it_even_when_deduped(client, cfg):
    ping(client, "auth")
    blind(client)
    r = ping(client, "auth")
    assert r.json()["deduped"] is True, "this is not exercising the dedupe path"
    assert app.blind_for("alpha") is None


def test_a_manual_mark_does_not_clear_it(client, cfg):
    """Being told you logged in is not the script being able to see it."""
    blind(client)
    client.post("/api/mark/alpha", follow_redirects=False)
    assert app.blind_for("alpha") is not None


def test_a_visit_does_not_clear_it(client, cfg):
    blind(client)
    ping(client, "visit")
    assert app.blind_for("alpha") is not None


def test_a_script_one_reply_behind_is_corrected_not_believed(client, cfg):
    """A script that has not learned the selector yet still reports. Storing
    that would put an answered question back on the row."""
    app.save_tracker_fields("alpha", auth_sel=SEL)
    r = blind(client)
    assert app.blind_for("alpha") is None
    assert r.json()["authSel"] == SEL, "the reply is what teaches the script"
    # And the mirror image: still using a selector the server has cleared.
    app.save_tracker_fields("alpha", auth_sel="")
    r = ping(client, "blind", path="/x", sel=SEL)
    assert app.blind_for("alpha") is None and r.json()["authSel"] == ""


# ------------------------------------------ a selector that matched nothing

def miss(client, cfg, sel=SEL):
    app.save_tracker_fields("alpha", auth_sel=sel)
    return ping(client, "blind", path="/browse", sel=sel)


def test_a_selector_that_matched_nothing_is_recorded(client, cfg):
    """The silent failure the docs named as the reason for having no field:
    a wrong selector, and a tracker that never records again."""
    miss(client, cfg)
    b = app.blind_for("alpha")
    assert b["sel"] == SEL and b["cand"] == [], \
        "with a selector set the question is whether IT is right"
    event("alpha", "auth", 20); event("alpha", "visit", 0)
    assert row()["label"] == app.CANT_TELL and row()["blind"]["sel"] == SEL


def test_candidates_sent_alongside_a_selector_are_dropped(client, cfg):
    app.save_tracker_fields("alpha", auth_sel=SEL)
    ping(client, "blind", path="/x", sel=SEL, cand=["a.other"])
    assert app.blind_for("alpha")["cand"] == []


def test_yes_on_a_miss_clears_the_selector_and_counts_the_visit(client, cfg):
    """"I was signed in and it did not see me" means the selector is wrong.
    Cleared rather than replaced: the next visit reports what is on the page
    now, and the question returns with something to offer."""
    miss(client, cfg)
    r = client.post("/api/blind/alpha", json={"answer": "yes"})
    assert r.status_code == 200, r.text
    assert not entry(cfg).get("auth_sel") and r.json()["auth_sel"] == ""
    got = events()
    assert len(got) == 1 and got[0]["source"] == "manual"
    assert app.blind_for("alpha") is None


def test_no_on_a_miss_keeps_the_selector(client, cfg):
    miss(client, cfg)
    client.post("/api/blind/alpha", json={"answer": "no"})
    assert entry(cfg)["auth_sel"] == SEL and events() == []


def test_a_record_never_outlives_the_selector_it_was_about(client, cfg):
    """Changing the selector by any route settles the old question. Shown
    after that, "your element was not on the page" would be about an element
    the tracker no longer has."""
    miss(client, cfg)
    client.post("/api/limit/alpha", json={"auth_sel": "a.new"})
    assert app.blind_for("alpha") is None
    miss(client, cfg, "a.new")
    client.post("/api/limit/alpha", json={"auth_sel": ""})
    assert app.blind_for("alpha") is None
    # And if one is somehow left behind, evaluate() refuses to show it.
    app.set_state("blind_alpha", json.dumps(
        {"path": "/", "at": "x", "iso": "", "cand": [], "sel": "a.gone"}))
    assert row()["blind"] is None
    assert 'class="blind"' not in re.search(
        r'<tr class="row" id="t-alpha".*?</tr>', client.get("/").text, re.S).group(0)


def test_the_drawer_escapes_the_selector_too(client, cfg):
    js = _script(client)
    assert "hesc(bl.sel)" in js
    assert not re.search(r"\+\s*bl\.sel\s*(\+|;)", js)


def test_the_marker_says_which_ending_it_was(client, cfg):
    miss(client, cfg)
    page = client.get("/").text
    assert "nothing matching the element set for this tracker" in page
    client.post("/api/limit/alpha", json={"auth_sel": ""})
    blind(client)
    assert "no sign-out control" in client.get("/").text


# ------------------------------------------------- the reply carries a selector

@pytest.mark.parametrize("kind,extra", [
    ("visit", {}), ("auth", {}), ("veto", {"path": "/x"}),
    ("blind", {"path": "/x", "cand": []}), ("blind", {"login": True}),
])
def test_every_reply_carries_the_selector(client, cfg, kind, extra):
    """ALWAYS present, empty when there is none. The script caches it, so
    "absent" has to keep meaning "an older server", never "cleared"."""
    assert ping(client, kind, **extra).json()["authSel"] == ""
    app.save_tracker_fields("alpha", auth_sel=SEL)
    assert ping(client, kind, **extra).json()["authSel"] == SEL


def test_a_deduped_reply_carries_it_too(client, cfg):
    """The dedupe return is the common case within 12 hours. Dropping the
    selector there would make "takes effect on your next visit" untrue for
    most of a day."""
    app.save_tracker_fields("alpha", auth_sel=SEL)
    ping(client, "visit")
    r = ping(client, "visit").json()
    assert r["deduped"] is True and r["authSel"] == SEL


# ------------------------------------------------------------ what the row says

def test_logged_out_becomes_cant_tell(client, cfg):
    event("alpha", "auth", 20)
    event("alpha", "visit", 0)
    assert row()["state"] == "session" and row()["label"] == "logged out"
    blind(client)
    r = row()
    assert r["state"] == "session", "the state KEY must not change"
    assert r["label"] == app.CANT_TELL
    assert "can't tell" in r["reason"] and "dead" not in r["reason"]


def test_the_label_only_moves_for_that_one_state(client, cfg):
    """A tracker with a recent login is `ok` whatever the script could or
    could not see on some page."""
    event("alpha", "auth", 1)
    blind(client)
    assert row()["label"] == "ok"
    assert row()["blind"] is not None, "the question is still asked"


def test_the_push_says_cant_tell_not_logged_out(client, cfg):
    event("alpha", "auth", 20)
    event("alpha", "visit", 0)
    blind(client)
    note = app.build_notification(app.statuses())
    assert "can't tell" in note["body"] and "cookie is dead" not in note["body"]


def test_the_marker_is_on_the_row_and_escaped(client, cfg):
    blind(client, path='/x" onmouseover="alert(1)')
    page = client.get("/").text
    r = re.search(r'<tr class="row" id="t-alpha".*?</tr>', page, re.S).group(0)
    assert 'class="blind"' in r
    assert 'onmouseover="alert(1)' not in r
    beta = re.search(r'<tr class="row" id="t-beta".*?</tr>', page, re.S).group(0)
    assert 'class="blind"' not in beta, "the marker leaked onto another tracker"


def test_the_row_cell_shows_the_label(client, cfg):
    event("alpha", "auth", 20)
    event("alpha", "visit", 0)
    blind(client)
    r = re.search(r'<tr class="row" id="t-alpha".*?</tr>', client.get("/").text, re.S).group(0)
    assert re.search(r'<td class="st">can&#x27;t tell</td>', r), r[-400:]


# ----------------------------------------------------------------- the answer

def test_yes_adopts_the_element(client, cfg):
    blind(client)
    r = client.post("/api/blind/alpha", json={"answer": "yes"})
    assert r.status_code == 200, r.text
    assert entry(cfg)["auth_sel"] == SEL
    assert r.json()["auth_sel"] == SEL and r.json()["blind"] is None
    assert app.blind_for("alpha") is None


def test_yes_counts_that_visit_as_a_login_at_the_time_of_the_visit(client, cfg):
    """Stamped with the moment of the ANSWER, the countdown would start late
    by however long the question sat unanswered. Late is the unsafe direction."""
    seen = datetime.now(timezone.utc) - timedelta(days=5)
    app.set_state("blind_alpha", json.dumps(
        {"path": "/browse", "at": "x", "iso": seen.isoformat(), "cand": [SEL]}))
    client.post("/api/blind/alpha", json={"answer": "yes"})
    got = events()
    assert len(got) == 1 and got[0]["source"] == "manual", \
        "it is asserted, not observed, and must say so"
    assert abs(datetime.fromisoformat(got[0]["ts"]) - seen) < timedelta(seconds=1)
    assert row()["days_since"] == 5


@pytest.mark.parametrize("iso", ["", "garbage", "2026-10-02T12:00:00",
                                 (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()])
def test_an_untrustworthy_time_adopts_the_element_without_a_login(client, cfg, iso):
    """Unreadable, naive or in the future: not a time to build a countdown on."""
    app.set_state("blind_alpha", json.dumps({"path": "/", "at": "x", "iso": iso, "cand": [SEL]}))
    assert client.post("/api/blind/alpha", json={"answer": "yes"}).status_code == 200
    assert entry(cfg)["auth_sel"] == SEL
    assert events() == []


def test_yes_never_moves_a_login_backwards(client, cfg):
    event("alpha", "auth", 1)
    seen = datetime.now(timezone.utc) - timedelta(days=5)
    app.set_state("blind_alpha", json.dumps(
        {"path": "/", "at": "x", "iso": seen.isoformat(), "cand": [SEL]}))
    client.post("/api/blind/alpha", json={"answer": "yes"})
    assert len(events()) == 1 and row()["days_since"] == 1


def test_no_changes_nothing_but_the_question(client, cfg):
    """Being signed out says nothing about whether the element is a good one."""
    blind(client)
    r = client.post("/api/blind/alpha", json={"answer": "no"})
    assert r.status_code == 200
    assert not entry(cfg).get("auth_sel")
    assert events() == [] and app.blind_for("alpha") is None


def test_yes_only_takes_what_the_script_reported(client, cfg):
    """This endpoint adopts a suggestion. Free text goes through /api/limit,
    where it is validated as one."""
    blind(client)
    r = client.post("/api/blind/alpha", json={"answer": "yes", "selector": "a.evil"})
    assert r.status_code == 400
    assert not entry(cfg).get("auth_sel") and app.blind_for("alpha") is not None


def test_yes_with_nothing_found_is_refused(client, cfg):
    blind(client, cand=[])
    assert client.post("/api/blind/alpha", json={"answer": "yes"}).status_code == 400


def test_the_refusals(client, cfg):
    assert client.post("/api/blind/alpha", json={"answer": "yes"}).status_code == 409
    assert client.post("/api/blind/nope", json={"answer": "yes"}).status_code == 404
    blind(client)
    assert client.post("/api/blind/alpha", json={"answer": "maybe"}).status_code == 400


# ------------------------------------------------------ setting one by hand

def test_the_drawer_can_set_and_clear_one(client, cfg):
    before = {t["id"]: t for t in yaml.safe_load(cfg.read_text())["trackers"]}
    r = client.post("/api/limit/alpha", json={"auth_sel": SEL})
    assert r.status_code == 200 and r.json()["auth_sel"] == SEL
    assert entry(cfg)["auth_sel"] == SEL
    r = client.post("/api/limit/alpha", json={"auth_sel": ""})
    assert r.status_code == 200 and r.json()["auth_sel"] == ""
    assert not entry(cfg).get("auth_sel")
    after = {t["id"]: t for t in yaml.safe_load(cfg.read_text())["trackers"]}
    for tid in before:
        if tid != "alpha":
            assert after[tid] == before[tid], f"{tid} changed"


@pytest.mark.parametrize("bad", ["body", "*", "DIV", "a\nb", "x" * 201])
def test_a_selector_that_is_certainly_wrong_is_refused(client, cfg, bad):
    r = client.post("/api/limit/alpha", json={"auth_sel": bad})
    assert r.status_code == 400, r.text
    assert not entry(cfg).get("auth_sel")


def test_setting_one_by_hand_answers_the_question(client, cfg):
    blind(client)
    client.post("/api/limit/alpha", json={"auth_sel": SEL})
    assert app.blind_for("alpha") is None


def test_a_selector_survives_as_yaml(client, cfg):
    """Quotes, brackets and a colon: everything YAML would otherwise read."""
    sel = 'a[href*="/torrent?key="]:not(.x)'
    assert client.post("/api/limit/alpha", json={"auth_sel": sel}).status_code == 200
    assert entry(cfg)["auth_sel"] == sel


# ------------------------------------------------------- nothing to reinstall

def test_a_selector_change_does_not_ask_for_a_reinstall(client, cfg):
    """The script learns its selector from the ping reply. If the digest moved
    too, the "userscript is behind" banner would appear one click after the
    dashboard said there was nothing to reinstall."""
    before = app._userscript_payload("https://x.test")[2]
    app.save_tracker_fields("alpha", auth_sel=SEL)
    matches, sites, after, _ = app._userscript_payload("https://x.test")
    assert after == before, "a selector change moved the version digest"
    assert f"authSel: {json.dumps(SEL)}" in sites, \
        "it must still be baked in, as the bootstrap for a fresh install"


def test_adding_a_tracker_still_moves_the_digest(client, cfg):
    """The exclusion is the selector alone, not the site list."""
    before = app._userscript_payload("https://x.test")[2]
    d = yaml.safe_load(cfg.read_text())
    d["trackers"].append({"id": "zeta", "name": "Zeta", "url": "https://zeta.example/",
                          "host": "zeta.example", "inactivity_days": 30})
    cfg.write_text(yaml.safe_dump(d)); app._cfg_cache["data"] = None
    assert app._userscript_payload("https://x.test")[2] != before


# ------------------------------------------------------------------ the page

def _script(client):
    return "\n".join(re.findall(r"<script>(.*?)</script>", client.get("/").text, re.S))


def test_the_drawer_escapes_what_came_off_the_tracker(client, cfg):
    js = _script(client)
    ask = js[js.index("const ask="):js.index("el.innerHTML='<td colspan")]
    # Each value is concatenated ONLY inside hesc(). `(pick ? ... : ...)` is a
    # condition, not an interpolation, so the bare form is matched by what
    # follows it: a `+` or the end of a concatenation.
    for raw in (r"d\.name", r"bl\.at(\|\|'')?", r"pick"):
        bare = re.search(r"\+\s*%s\s*(\+|;)" % raw, ask)
        assert not bare, f"interpolated raw: {ask[bare.start():bare.start()+50]}"
    for wrapped in ("hesc(d.name)", "hesc(bl.at||'')", "hesc(pick)"):
        assert wrapped in ask, f"{wrapped} is missing from the question"


def test_the_question_does_not_borrow_another_elements_class(client, cfg):
    """Every class the question's markup uses must be styled ONLY under
    `.ask`. Its key line was first given `class="q"`, which is the
    `unconfirmed` badge, and rendered as an uppercase outlined pill. Found by
    looking at it on a real instance; no test could see it, since the markup
    and the CSS were each correct on their own.
    """
    page = client.get("/").text
    js = _script(client)
    ask = js[js.index("const ask="):js.index("el.innerHTML='<td colspan")]
    css = re.sub(r"/\*.*?\*/", "", re.search(r"<style>(.*?)</style>", page, re.S).group(1), flags=re.S)
    used = set(re.findall(r'class="([\w -]+)"', ask))
    names = {c for group in used for c in group.split()} - {"ask", "lk", "pri", "byes", "bno"}
    assert names, "the question's classes were not found; the regex needs updating"
    for name in names:
        for sel in re.findall(r"(?:^|\})\s*([^{}]*\.%s\b[^{}]*)\{" % re.escape(name), css):
            for part in sel.split(","):
                # Only an UNSCOPED rule can reach in here. `.sheet .sub` needs
                # a `.sheet` ancestor the drawer does not have; a bare `.q`
                # needs nothing, which is exactly how it got in.
                first = re.split(r"[\s>+~]+", part.strip())[0]
                if re.search(r"\.%s\b" % re.escape(name), first):
                    assert ".ask" in part, \
                        f"`.{name}` is styled outside the question by `{part.strip()}`"


def test_the_page_takes_its_label_from_the_server(client, cfg):
    """One rule, computed in evaluate(). A second copy in the page script is
    how the state ordering and the unit labels each drifted."""
    js = _script(client)
    assert "d.label||SLBL[d.state]" in js
    assert "can't tell" not in js and "can\\'t tell" not in js, \
        "the page script has its own copy of the label"


def test_answering_removes_the_marker_without_a_reload(client, cfg):
    js = _script(client)
    paint = js[js.index("function paint("):js.index("function drawer(")]
    assert re.search(r"querySelector\('td\.nm \.blind'\).*?!d\.blind\)\w+\.remove\(\)", paint, re.S)


# ------------------------------------------------------------- the userscript

def _js():
    return (Path(__file__).parent.parent / "idlarr.user.js").read_text()


def test_the_script_never_adopts_a_candidate_itself():
    """It may only SUGGEST. A wrong guess records logins that never happened,
    and only the person who was there knows whether they were signed in."""
    src = _js()
    assert "site.authSel = " in src
    for m in re.finditer(r"site\.authSel\s*=\s*([^;]+);", src):
        assert m.group(1).strip() in ("cachedSel", "sel"), \
            f"authSel is assigned from something other than the server: {m.group(0)}"
    fn = src[src.index("function signedInCandidates()"):src.index("// ------------------------------------------------------------- scheduling")]
    assert "site.authSel" not in fn and "send(" not in fn


def test_it_reports_only_with_nothing_to_go_on():
    src = _js()
    gate = src.index("if (fields === 0) {")
    assert 0 < src.index("'blind', site.authSel", gate) - gate < 160
    login = src.index("send('blind', { login: true }")
    assert login < gate and "return;" in src[login:gate], \
        "a login form falls through and is also reported as can't-tell"


def test_a_bad_selector_cannot_throw_inside_the_observer():
    src = _js()
    fn = src[src.index("function selMatches("):src.index("function selMatches(") + 200]
    assert "try" in fn and "catch" in fn
    authed = src[src.index("function isAuthed()"):src.index("function send(")]
    assert "document.querySelector(site.authSel)" not in authed
    assert "selMatches(site.authSel)" in authed


def test_the_reply_is_where_the_selector_comes_from():
    src = _js()
    onload = src[src.index("onload: res =>"):src.index("onerror:")]
    assert "applySel(body.authSel)" in onload
    apply = src[src.index("function applySel("):src.index("function selMatches(")]
    assert "typeof sel !== 'string'" in apply, \
        "a reply with no selector (an older server) would wipe the cached one"


# ------------------------------------------- the finder, run for real (QuickJS)

DOM = r"""
const els = [];
function E(tag, cls, o){ o = o || {};
  const e = {tagName: tag.toUpperCase(), id: o.id || '', classList: cls ? cls.split(' ') : [],
             textContent: o.text || '', offsetWidth: o.hidden ? 0 : 10, offsetHeight: o.hidden ? 0 : 10,
             getClientRects(){ return o.hidden ? [] : [1]; }};
  els.push(e); return e; }
const CSS = { escape: s => s };
const document = { querySelectorAll(sel){
  if (sel === '[class],[id]') return els.filter(e => e.id || e.classList.length);
  let m = /^([a-z0-9-]*)\.([\w-]+)$/i.exec(sel);
  if (m) return els.filter(e => (!m[1] || e.tagName.toLowerCase() === m[1]) && e.classList.includes(m[2]));
  m = /^#([\w-]+)$/.exec(sel);
  if (m) return els.filter(e => e.id === m[1]);
  throw new Error('unsupported selector ' + sel); } };
function isVisible(el){ return !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length)); }
function selMatches(sel){ try { return document.querySelectorAll(sel).length; } catch (_) { return 0; } }
"""


def _finder():
    if os.environ.get("CI"):
        import quickjs          # a skip in CI would be a pass that ran nothing
    else:
        quickjs = pytest.importorskip("quickjs")
    src = _js()
    block = src[src.index("  const FRAMEWORK ="):
                src.index("  // ------------------------------------------------------------- scheduling")]
    ctx = quickjs.Context()
    ctx.eval(DOM + block)
    return ctx


def _run(build):
    ctx = _finder()
    ctx.eval(build)
    return json.loads(ctx.eval("JSON.stringify(signedInCandidates())"))


def test_it_finds_what_a_person_found_on_milkie():
    """The exact element from the report, among the Angular Material classes
    that were on it."""
    got = _run("""
      E('button', 'mat-focus-indicator profile-button mat-icon-button mat-button-base');
      E('mat-toolbar', 'mat-toolbar mat-primary');
      for (let i = 0; i < 30; i++) E('tor-torrent-release', 'ng-star-inserted');
    """)
    assert got == ["button.profile-button"]


def test_framework_and_generated_names_are_never_offered():
    got = _run("""
      E('div', 'mat-user-menu'); E('div', 'css-1q2w3e4-user'); E('div', 'user-8f3a2c1');
      E('div', 'MuiAvatar-root'); E('span', 'ng-user');
    """)
    assert got == []


def test_a_signed_out_page_offers_nothing():
    """`account` and `user` show up on a logged-out header too, attached to
    the very controls that say so."""
    got = _run("""
      E('a', 'user-login'); E('a', 'account-register'); E('div', 'guest-user');
      E('a', 'account-link', {text: 'Sign in'}); E('button', 'user-menu', {text: 'Log in / Register'});
    """)
    assert got == []


def test_a_column_of_other_people_is_not_about_you():
    got = _run("for (let i = 0; i < 25; i++) E('td', 'user-name');")
    assert got == []


def test_hidden_elements_are_skipped_and_the_best_comes_first():
    got = _run("""
      E('div', 'avatar', {hidden: true});
      E('div', 'bonus-points'); E('a', 'logoutLink'); E('span', 'user_ratio');
      E('div', '', {id: 'profile'});
    """)
    assert got[0] == "a.logoutLink"
    assert "div.avatar" not in got and len(got) == 3
