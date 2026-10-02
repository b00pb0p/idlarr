#!/usr/bin/env python3
"""The userscript, actually run.

Everything else about the script is checked by reading its source. That is
not enough for the one promise that cannot be seen in a diff: a selector
confirmed on the dashboard takes effect on the next page load, with nothing
to reinstall. This boots the real file in QuickJS against a stub page and a
stub server and watches what it sends.

Run:  .venv/bin/python -m pytest tests/test_userscript_runtime.py -q
"""

import json
import os
from pathlib import Path

import pytest

try:
    import quickjs
except ImportError:                                    # pragma: no cover
    # Skipping is right on a laptop without the engine and WRONG in CI, where
    # a skipped file is a green run that executed none of the script.
    if os.environ.get("CI"):
        raise
    quickjs = pytest.importorskip("quickjs")

SRC = (Path(__file__).parent.parent / "idlarr.user.js").read_text()

HARNESS = r"""
var store = STORE, sent = [], pending = [], timers = [], logs = [];
var els = [];
function E(tag, cls, o){ o = o || {};
  var e = {tagName: tag.toUpperCase(), id: o.id || '', type: o.type || '',
           classList: cls ? cls.split(' ') : [], textContent: o.text || '',
           offsetWidth: o.hidden ? 0 : 10, offsetHeight: o.hidden ? 0 : 10,
           outerHTML: '<' + tag + '>', attributes: [],
           getAttribute: function(){ return null; },
           getClientRects: function(){ return o.hidden ? [] : [1]; }};
  els.push(e); return e; }
function q(sel){
  if (sel.indexOf('[[') !== -1) throw new Error('bad selector');
  // gamma's baked selector in the template, matched by a marker class.
  if (sel.indexOf('/torrent?key=') !== -1)
    return els.filter(function(e){ return e.classList.indexOf('keylink') !== -1; });
  if (sel === '[class],[id]') return els.filter(function(e){ return e.id || e.classList.length; });
  if (sel === 'input[type="password"]') return els.filter(function(e){ return e.type === 'password'; });
  if (sel === 'a, button, [role="button"]')
    return els.filter(function(e){ return e.tagName === 'A' || e.tagName === 'BUTTON'; });
  var m = /^([a-z0-9-]*)\.([\w-]+)$/i.exec(sel);
  if (m) return els.filter(function(e){
    return (!m[1] || e.tagName.toLowerCase() === m[1]) && e.classList.indexOf(m[2]) !== -1; });
  return [];
}
var document = { documentElement: {},
  querySelectorAll: q, querySelector: function(s){ var r = q(s); return r.length ? r[0] : null; } };
var CSS = { escape: function(s){ return s; } };
var location = { hostname: HOST, pathname: '/browse' };
var history = { pushState: function(){}, replaceState: function(){} };
var window = { addEventListener: function(){} };
var unsafeWindow = {};
var console = { log: function(m){ logs.push(m); }, warn: function(m){ logs.push(m); } };
function MutationObserver(cb){ this.observe = function(){}; this.disconnect = function(){}; }
function requestAnimationFrame(f){ f(); }
function setTimeout(f){ timers.push(f); return timers.length; }
function clearTimeout(){}
var GM_info = { script: { version: '1.1.9' } };
function GM_getValue(k, d){ return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : d; }
function GM_setValue(k, v){ store[k] = v; }
function GM_xmlhttpRequest(o){
  var body = JSON.parse(o.data); sent.push(body);
  pending.push(function(){ o.onload({ status: 200, responseText: JSON.stringify(REPLY(body)) }); });
}
function flush(){ while (pending.length) pending.shift()(); }
function timeout(){ var t = timers; timers = []; t.forEach(function(f){ f(); }); flush(); }
function kinds(){ return sent.map(function(b){ return b.kind; }); }
"""


def boot(page, host="alpha.example", store=None, reply="{ok: true}"):
    """Run the script once, as one page load. Returns the context."""
    ctx = quickjs.Context()
    ctx.eval("var STORE = %s; var HOST = %s; var REPLY = function(body){ return %s; };"
             % (json.dumps(store or {}), json.dumps(host), reply))
    ctx.eval(HARNESS)
    ctx.eval(page)
    ctx.eval(SRC)
    ctx.eval("flush()")
    return ctx


def get(ctx, expr):
    return json.loads(ctx.eval("JSON.stringify(%s)" % expr))


MILKIE = "E('button', 'mat-focus-indicator profile-button mat-icon-button');"
SEL = "button.profile-button"


def test_a_site_it_cannot_read_is_reported_with_what_it_found():
    """No sign-out control, no password field, no selector: nothing to judge
    by. It says so, and offers the element a person would have picked."""
    ctx = boot(MILKIE, reply="{ok: true, authSel: ''}")
    assert get(ctx, "kinds()") == ["visit"], "it recorded a login it could not see"
    ctx.eval("timeout()")
    assert get(ctx, "kinds()") == ["visit", "blind"]
    report = get(ctx, "sent[1]")
    assert report["cand"] == [SEL] and report["path"] == "/browse"


def test_the_reply_delivers_a_selector_and_it_works_at_once():
    """THE promise. The server answers the visit ping with a selector; the
    script must record the login on this same page load, not after an update."""
    ctx = boot(MILKIE, reply="{ok: true, authSel: 'button.profile-button'}")
    assert get(ctx, "kinds()") == ["visit", "auth"]
    assert get(ctx, "store")["idl_alpha_sel"] == SEL, "it was not kept for the next load"
    ctx.eval("timeout()")
    assert "blind" not in get(ctx, "kinds()"), "it asked a question it had just answered"


def test_the_next_page_load_needs_no_reply_at_all():
    """Cached, so detection works at boot even while both pings are inside
    their cooldown and nothing is sent that could carry a reply."""
    ctx = boot(MILKIE, store={"idl_alpha_sel": SEL}, reply="{ok: true}")
    assert get(ctx, "kinds()") == ["visit", "auth"]


def test_a_cleared_selector_is_forgotten():
    """An empty string from the server is an answer, not an absence."""
    ctx = boot(MILKIE, store={"idl_alpha_sel": SEL}, reply="{ok: true, authSel: ''}")
    assert get(ctx, "store")["idl_alpha_sel"] == ""
    # Only the selector is carried over. The first load also wrote its ping
    # cooldowns, and with those the second would send nothing at all, which
    # would pass this for the wrong reason.
    ctx2 = boot(MILKIE, store={"idl_alpha_sel": get(ctx, "store")["idl_alpha_sel"]},
                reply="{ok: true, authSel: ''}")
    assert get(ctx2, "kinds()") == ["visit"], "a cleared selector still records logins"


def test_an_older_server_does_not_wipe_the_cache():
    """A reply with no `authSel` key is a server that predates it."""
    ctx = boot(MILKIE, store={"idl_alpha_sel": SEL}, reply="{ok: true}")
    assert get(ctx, "store")["idl_alpha_sel"] == SEL


def test_an_empty_cache_entry_overrides_the_baked_selector():
    """gamma ships with a baked `authSel` in the template. Once the server has
    said there is none, the baked one must not come back."""
    page = "E('a', 'keylink');"       # what the baked selector matches
    baked = boot(page, host="gamma.example", reply="{ok: true}")
    assert get(baked, "kinds()") == ["visit", "auth"], \
        "precondition: the baked selector is not matching, so this proves nothing"
    ctx = boot(page, host="gamma.example",
               store={"idl_gamma_sel": ""}, reply="{ok: true, authSel: ''}")
    assert get(ctx, "kinds()") == ["visit"]


def test_a_login_form_is_reported_as_one_and_never_as_a_login():
    """The guard outranks the selector: an element that also shows on the
    login page must not reset a countdown there."""
    page = MILKIE + "E('input', '', {type: 'password'});"
    ctx = boot(page, store={"idl_alpha_sel": SEL}, reply="{ok: true, authSel: 'button.profile-button'}")
    assert get(ctx, "kinds()") == ["visit"], "a login was recorded on a login page"
    ctx.eval("timeout()")
    assert get(ctx, "sent[sent.length - 1]").get("login") is True
    assert "cand" not in get(ctx, "sent[sent.length - 1]")


def test_a_selector_that_does_not_parse_cannot_break_the_page():
    ctx = boot(MILKIE, store={"idl_alpha_sel": "a[[broken"}, reply="{ok: true}")
    assert get(ctx, "kinds()") == ["visit"]
    ctx.eval("timeout()")      # and the watch still ends without throwing


def test_a_selector_that_matched_nothing_says_which_one():
    """Signed out, or the selector is wrong: typed by hand, or broken by a
    redesign. A wrong one used to be silent, the tracker just never recorded
    again, and that was the reason the docs gave for having no field for it.

    It names the selector it used so the server can tell a real miss from a
    script that is one reply behind, and it offers NO candidates: with a
    selector set the question is whether that one is right, not which to use.
    """
    ctx = boot("E('div', 'user-menu');", store={"idl_alpha_sel": SEL},
               reply="{ok: true, authSel: 'button.profile-button'}")
    ctx.eval("timeout()")
    assert get(ctx, "kinds()") == ["visit", "blind"]
    report = get(ctx, "sent[1]")
    assert report["sel"] == SEL and "cand" not in report


def test_a_signup_page_is_not_reported_at_all():
    """Two password fields and no sign-out control is a registration form.
    Nobody is being asked whether they were signed in on that."""
    ctx = boot("E('input','',{type:'password'}); E('input','',{type:'password'});",
               reply="{ok: true, authSel: ''}")
    ctx.eval("timeout()")
    assert get(ctx, "kinds()") == ["visit"]
