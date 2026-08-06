#!/usr/bin/env python3
"""Notification destinations managed from the panel.

Two sources feed one list and neither replaces the other: IDLARR_NOTIFY_URLS,
which lives in .env and therefore never reaches a backup, and destinations
added in Settings, which live in the database and therefore do. That choice is
the point of most of what follows.

Run:  .venv/bin/python -m pytest tests/test_notify_dests.py -q
"""

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-nd-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

FIXTURE = Path(__file__).parent / "tests_fixture.yml"
GOOD = "discord://123456789012345678/AbCdEfGhToken"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    monkeypatch.setattr(app, "NOTIFY_ENV", [])
    app._cfg_cache["data"] = None
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
    yield path
    app._cfg_cache["data"] = None


@pytest.fixture
def client(cfg):
    return TestClient(app.app)


def add(client, url=GOOD, name=""):
    return client.post("/api/notify", json={"url": url, "name": name})


# ------------------------------------------------------------ adding

def test_a_url_is_checked_before_it_is_saved(client):
    """Left until send time, a typo shows up as a missed alert on the night
    something was actually due, which is the failure this service exists to
    prevent."""
    assert add(client).status_code == 200
    assert add(client, "notascheme").status_code == 400
    assert add(client, "bogusproto://a/b").status_code == 400


def test_the_error_never_echoes_the_url(client):
    """It carries a credential. The same reason dispatch() logs a scheme rather
    than the URL it rejected."""
    secret = "bogusproto://SUPERSECRETTOKEN"
    body = add(client, secret).json()["detail"]
    assert "SUPERSECRETTOKEN" not in body
    assert "bogusproto" in body, "it should still say which scheme it refused"


def test_the_same_destination_is_not_added_twice(client):
    assert add(client).status_code == 200
    assert add(client).status_code == 400


# ------------------------------------------------- the two sources

def test_env_and_panel_both_send(client, monkeypatch):
    """They ADD to one list rather than competing for one value, which is why
    there is no precedence rule here to get wrong."""
    monkeypatch.setattr(app, "NOTIFY_ENV", ["json://envhost/path"])
    add(client)
    urls = app.notify_urls()
    assert "json://envhost/path" in urls and GOOD in urls


def test_the_same_url_in_both_places_sends_once(client, monkeypatch):
    """A doubled push reads as a bug in the alerting rather than as a
    duplicated config line."""
    monkeypatch.setattr(app, "NOTIFY_ENV", [GOOD])
    add(client)
    assert app.notify_urls().count(GOOD) == 1


def test_the_env_var_is_never_copied_into_the_database(client, monkeypatch):
    """The whole point of keeping it in .env is that .env is not in /data, so
    those credentials never reach a backup. Seeding it into `state` would
    defeat exactly that, silently."""
    monkeypatch.setattr(app, "NOTIFY_ENV", ["json://envhost/path"])
    # Driven through TestClient's CONTEXT MANAGER, which is what runs lifespan.
    # An earlier version called client.get("/") and asserted the same thing;
    # that never executes startup, so it would have passed with seeding put
    # back exactly where it originally was.
    with TestClient(app.app):
        pass
    assert app.notify_dests() == [], "startup copied the env var into the database"
    raw = app.get_state("notify_dests", "") or ""
    assert "envhost" not in raw


def test_a_disabled_destination_stops_receiving(client):
    """Disable exists because Remove cannot be undone from the page: the URL is
    never rendered back, so there is nothing left to retype from."""
    dest_id = add(client).json()["id"]
    assert GOOD in app.notify_urls()
    client.post(f"/api/notify/{dest_id}", json={"enabled": False})
    assert GOOD not in app.notify_urls()
    client.post(f"/api/notify/{dest_id}", json={"enabled": True})
    assert GOOD in app.notify_urls()


# ------------------------------------------------------------ editing

def test_a_blank_url_keeps_the_stored_one(client):
    """Same rule the import key uses. Without it you could not rename or mute a
    destination without retyping a credential the page will not show you."""
    dest_id = add(client, name="old").json()["id"]
    r = client.post(f"/api/notify/{dest_id}", json={"name": "new"})
    assert r.status_code == 200
    d = app.notify_dests()[0]
    assert d["name"] == "new" and d["url"] == GOOD


def test_editing_validates_a_replacement_url(client):
    dest_id = add(client).json()["id"]
    assert client.post(f"/api/notify/{dest_id}",
                       json={"url": "notascheme"}).status_code == 400
    assert app.notify_dests()[0]["url"] == GOOD, "a bad edit overwrote a good URL"


def test_removing_one_twice_is_a_404_not_a_silent_success(client):
    dest_id = add(client).json()["id"]
    assert client.delete(f"/api/notify/{dest_id}").status_code == 200
    assert client.delete(f"/api/notify/{dest_id}").status_code == 404


def test_an_unknown_id_is_refused(client):
    assert client.post("/api/notify/nope", json={"name": "x"}).status_code == 404
    assert client.post("/api/notify/nope/test").status_code == 404


# --------------------------------------------------------- not leaking

def test_a_stored_url_never_reaches_the_page(client, monkeypatch):
    """With sign-in off the page is open to anything that can reach the port,
    and one Discord URL is enough to post into someone's channel."""
    monkeypatch.setattr(app, "NOTIFY_ENV", ["json://envsecret/path"])
    add(client, "discord://999888777666555444/DBSECRETTOKEN")
    html = client.get("/").text
    assert "DBSECRETTOKEN" not in html
    assert "envsecret" not in html
    assert "999888777666555444" not in html


def test_the_mask_reveals_nothing_of_the_url(client):
    """It showed the last four characters first, the way a card number does.
    For ntfy the topic IS the secret, so four characters of a short topic is a
    lot of it. A truncated hash tells two destinations apart just as well."""
    for url in ("ntfy://mytopic", "discord://1/SECRET", GOOD):
        masked = app.mask_url(url)
        body = url.split("://", 1)[1]
        for n in range(3, len(body) + 1):
            assert body[-n:] not in masked, f"{masked} leaks the tail of {url}"
        assert masked.startswith(url.split("://")[0] + "://")


def test_two_destinations_are_still_told_apart(client):
    """The mask has to disambiguate or the list is useless with two of the same
    provider."""
    assert app.mask_url("discord://1/AAA") != app.mask_url("discord://1/BBB")


# ------------------------------------------------------------ sending

def test_one_destination_is_tested_on_its_own(client, monkeypatch):
    """Apprise returns one boolean for the whole batch, so with three
    configured a refusal from any of them reads as "notifications are broken"
    and names none of them."""
    seen = []
    monkeypatch.setattr(app, "dispatch_to",
                        lambda urls, *a: (seen.append(urls), (True, ""))[1])
    monkeypatch.setattr(app, "NOTIFY_ENV", ["json://other/path"])
    dest_id = add(client).json()["id"]
    assert client.post(f"/api/notify/{dest_id}/test").status_code == 200
    assert seen == [[GOOD]], f"tested {seen} instead of just the chosen one"


def test_a_refusal_reports_the_providers_reason(client, monkeypatch):
    monkeypatch.setattr(app, "dispatch_to", lambda *a: (False, "error=404"))
    dest_id = add(client).json()["id"]
    r = client.post(f"/api/notify/{dest_id}/test")
    assert r.status_code == 502 and "error=404" in r.json()["detail"]


def test_a_corrupt_blob_does_not_take_alerting_down(client):
    """It is JSON in a text column. Unreadable must read as "none configured",
    which the page announces loudly, rather than a 500 on every request."""
    app.set_state("notify_dests", "{not json")
    assert app.notify_dests() == []
    assert client.get("/").status_code == 200


# ------------------------------------------------------------- the page

def test_the_panel_wires_every_endpoint_it_offers(cfg):
    """Pins the call sites. Endpoints passing their own tests prove nothing if
    nothing on the page posts to them."""
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert 'id="ndadd"' in html and 'id="ndurl"' in html
    for frag in ("'/api/notify'", "/api/notify/", "'DELETE'", "data-act"):
        assert frag in app.PAGE, f"the script never uses {frag}"


def test_the_list_says_which_entries_came_from_env(cfg, monkeypatch):
    """Showing only the editable ones would make the list lie about what will
    actually receive an alert."""
    monkeypatch.setattr(app, "NOTIFY_ENV", ["json://envhost/path"])
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert "from .env" in html


def test_the_backup_tradeoff_is_stated_where_you_add_one(cfg):
    """Someone pasting a credential into a web form deserves to be told where
    it lands, at the moment they do it, not only in the README."""
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert "backup" in html and "IDLARR_NOTIFY_URLS" in html


def test_the_add_form_is_one_full_width_row(cfg):
    """Both fields sat in the 200px control column, which cannot show an
    Apprise URL, and the name was pushed onto a row of its own with the whole
    left half empty. Reported 2026-08-06.

    The rule that keeps it fixed is that `.ndform` is a direct child of the
    row rather than of `.ctl2`: anything inside `.ctl2` is capped at 200px no
    matter what width it asks for.
    """
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    form = re.search(r'<div class="ndform">.*?</div>', html, re.S)
    assert form, "no full-width add form"
    assert 'id="ndurl"' in form.group(0) and 'id="ndname"' in form.group(0), \
        "the URL and name fields are not on the same row"
    assert 'class="ctl2"><input id="ndurl"' not in html, \
        "the URL field is back in the 200px control column"

    # Assert against the RULE BODY, not the whole stylesheet. The first version
    # checked `"width:100%" in css`, which any other rule in the page satisfies,
    # so narrowing .ndform back to `display:flex` alone kept it green.
    css = app.PAGE
    rule = re.search(r"\.ndform\{([^}]*)\}", css)
    assert rule, "no .ndform rule"
    assert "display:flex" in rule.group(1)
    assert "width:100%" in rule.group(1), \
        "the form will only be as wide as its contents"

    # And the URL field has to be the one that grows, or it renders at the same
    # width as the name field.
    assert re.search(r'<input id="ndurl"[^>]*class="f2"', html), \
        "the URL field does not carry the growing class"
    assert re.search(r"\.ndform \.f2\{[^}]*flex:2", css), \
        ".f2 has no flex rule, so the class on the URL field does nothing"

    assert ".sheet .row.wide>.lbl{flex:1 0 100%}" in css, \
        "the help text will sit beside the form instead of above it"
