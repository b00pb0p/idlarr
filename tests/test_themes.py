#!/usr/bin/env python3
"""The theme selector.

A theme is only a set of CSS custom properties, so the thing that can silently
break is not the switching, it is a colour somewhere that never became a
variable: it stays put while everything around it changes, and nothing fails.
Most of what follows is about that.

Run:  .venv/bin/python -m pytest tests/test_themes.py -q
"""

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-theme-test-")
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
    app._cfg_cache["data"] = None
    app.init_db()
    yield path
    app._cfg_cache["data"] = None


@pytest.fixture
def client(cfg):
    return TestClient(app.app)


def page_css(html):
    return "".join(re.findall(r"<style>(.*?)</style>", html, re.S))


# ------------------------------------------------- the palettes themselves

def test_every_theme_defines_every_variable():
    """A missing key does not fail, it renders that one colour as nothing:
    black text on a black background, or an invisible state. The default is
    the reference because it is the one that is always complete."""
    ref = set(app.THEMES[app.DEFAULT_THEME])
    for key, palette in app.THEMES.items():
        missing = ref - set(palette)
        assert not missing, f"theme {key!r} is missing: {sorted(missing)}"


def test_the_default_is_a_real_theme():
    assert app.DEFAULT_THEME in app.THEMES
    assert set(app.THEME_KEYS) == set(app.THEMES), \
        "THEME_KEYS and THEMES disagree, so the dropdown and the validator differ"


def test_every_state_colour_is_distinct_within_a_theme():
    """Nine states have to read apart at a glance; telling them apart IS the
    product. Two sharing a value is a theme that looks fine and lies."""
    states = ("ok", "due", "warn", "critical", "expired",
              "immune", "session", "unknown", "snoozed")
    for key, palette in app.THEMES.items():
        seen = {}
        for s in states:
            seen.setdefault(palette[s].lower(), []).append(s)
        clashes = {v: n for v, n in seen.items() if len(n) > 1}
        assert not clashes, f"theme {key!r} reuses a colour: {clashes}"


def test_meta_keys_never_reach_the_stylesheet():
    """`label` and `hint` are for the dropdown. Emitted as properties they
    would write `--label:Slate` into :root, which is harmless and wrong."""
    for key in app.THEMES:
        css = app.theme_css(key)
        assert "--label" not in css and "--hint" not in css


# ------------------------------------------------------------- rendering

def test_the_palette_is_rendered_server_side(client, cfg):
    """Applied by script instead, every load would paint the default first and
    flash to the real theme."""
    html = client.get("/").text
    assert "__THEME__" not in html, "the placeholder was never substituted"
    root = re.search(r":root\{(.*?)\}", page_css(html), re.S).group(1)
    assert app.THEMES[app.DEFAULT_THEME]["bg"] in root


@pytest.mark.parametrize("key", list(app.THEMES))
def test_each_theme_reaches_the_page(client, cfg, key):
    app.save_default_field("theme", key)
    root = re.search(r":root\{(.*?)\}", page_css(client.get("/").text), re.S).group(1)
    assert app.THEMES[key]["bg"] in root, f"{key} did not reach :root"


def test_the_theme_survives_load_config(cfg):
    """load_config() returns an EXPLICIT dict, so a key written into defaults
    that is not listed there does not exist downstream. Saving the theme wrote
    trackers.yml correctly and changed nothing on screen until it was added.
    """
    app.save_default_field("theme", "paper")
    assert app.load_config().get("theme") == "paper", \
        "the theme is written to the config but never read back out of it"
    assert app.theme() == "paper"


def test_an_unknown_theme_falls_back(cfg):
    """A hand-edited config, or a downgrade after a theme is removed. Serving
    a :root with nothing in it is not a crash, it is an unreadable page whose
    only fix is editing YAML."""
    cfg.write_text(cfg.read_text().replace("defaults:", "defaults:\n  theme: nonsense", 1))
    app._cfg_cache["data"] = None
    assert app.theme() == app.DEFAULT_THEME
    assert app.THEMES[app.DEFAULT_THEME]["bg"] in app.theme_css()


def test_the_login_page_is_themed_too(client, cfg):
    """It is the first thing a themed install shows, and it has its own
    stylesheet, so it is easy to leave behind."""
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    app.save_default_field("theme", "paper")
    html = client.get("/login").text
    assert "__THEME__" not in html, "the login page keeps the placeholder"
    assert app.THEMES["paper"]["bg"] in html
    app.set_state("auth_method", "")
    app.set_state("auth_hash", "")


# --------------------------------------------------- nothing left behind

def test_no_colour_outside_the_palette(cfg):
    """The one failure mode that is silent. A colour written literally in a
    rule stays put while every other colour changes, and nothing errors.

    #000 is allowed: the four uses are mask-image gradients on the ECG, where
    it means opacity rather than colour.
    """
    for name in ("PAGE", "LOGIN_PAGE"):
        css = page_css(getattr(app, name))
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        css = re.sub(r":root\{.*?\}", "", css, flags=re.S)
        found = [c for c in re.findall(r"(#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\))", css)
                 if c not in ("#000",)]
        assert not found, f"{name} has colours a theme cannot reach: {sorted(set(found))}"


def test_every_variable_used_is_defined_by_every_theme(cfg):
    """The other direction: a rule may not reference a variable no palette
    supplies, or that property silently resolves to nothing."""
    supplied = set(app.THEMES[app.DEFAULT_THEME]) - set(app._THEME_META)
    for name in ("PAGE", "LOGIN_PAGE"):
        css = page_css(getattr(app, name))
        used = set(re.findall(r"var\(--([a-z0-9]+)\)", css))
        root = re.search(r":root\{(.*?)\}", css, re.S).group(1)
        local = set(re.findall(r"--([a-z0-9]+)\s*:", root))
        # single-letter names are set inline per element, not by the theme
        undefined = {u for u in used - supplied - local if len(u) > 2}
        assert not undefined, f"{name} uses undefined variables: {sorted(undefined)}"


# ------------------------------------------------------------- the panel

def test_the_selector_offers_every_theme(cfg):
    html = app.settings_sheet("none", 7, 7, "/x.js")
    sel = re.search(r'<select id="setTheme">(.*?)</select>', html, re.S)
    assert sel, "no theme selector"
    for key in app.THEME_KEYS:
        assert f'value="{key}"' in sel.group(1), f"{key} is not offered"
    assert sel.group(1).count("selected") == 1, "exactly one option must be selected"


def test_the_selector_shows_the_saved_theme(cfg):
    app.save_default_field("theme", "contrast")
    html = app.settings_sheet("none", 7, 7, "/x.js")
    sel = re.search(r'<select id="setTheme">(.*?)</select>', html, re.S).group(1)
    assert re.search(r'value="contrast" selected', sel), \
        "the dropdown does not reflect what is saved"


def test_save_posts_the_theme(cfg):
    assert "theme:document.getElementById('setTheme').value" in app.PAGE, \
        "Save never sends the theme"


def test_the_preview_has_every_palette_to_paint_with(cfg, client):
    """Picking from the dropdown repaints without a round trip, so the page
    needs them all, not just the active one."""
    html = client.get("/").text
    assert "__THEMEDATA__" not in html, "the palette data was never substituted"
    blob = re.search(r"const THEMES=(\{.*?\});", html, re.S).group(1)
    data = json.loads(blob)
    assert set(data) == set(app.THEMES)
    assert "label" not in data[app.DEFAULT_THEME], "meta keys leaked into the page"


# ----------------------------------------------------------- the endpoint

def test_an_unknown_theme_is_refused_by_the_endpoint(client, cfg):
    """Allow-listing the KEY is not enough; the VALUE has to be checked, or a
    typo writes a config that renders an unreadable page."""
    r = client.post("/api/settings", json={"theme": "phosphor"})
    assert r.status_code == 400
    assert "phosphor" in r.json()["detail"]
    assert app.load_config().get("theme") != "phosphor"


def test_the_endpoint_accepts_a_real_one(client, cfg):
    assert client.post("/api/settings", json={"theme": "nocturne"}).status_code == 200
    assert app.theme() == "nocturne"


def test_the_read_only_key_cannot_change_the_theme(client, cfg):
    app.set_state("auth_method", "forms")
    app.set_state("auth_hash", app.hash_password("x" * 10))
    r = client.post("/api/settings", json={"theme": "paper"},
                    headers={"X-Api-Key": app.api_key()})
    assert r.status_code == 401
    app.set_state("auth_method", "")
    app.set_state("auth_hash", "")


def test_the_dropdown_shows_names_only(cfg):
    """Asked for 2026-08-10. The descriptions made every option a sentence in a
    narrow control, and the live preview already answers what each one looks
    like better than any wording could.
    """
    html = app.settings_sheet("none", 7, 7, "/x.js")
    sel = re.search(r'<select id="setTheme">(.*?)</select>', html, re.S).group(1)
    for opt in re.findall(r'<option[^>]*>(.*?)</option>', sel):
        assert opt in {t["label"] for t in app.THEMES.values()}, \
            f"option carries more than a name: {opt!r}"


def test_no_dead_description_is_left_in_the_table(cfg):
    """Nothing renders it any more. A field kept `just in case` is data that
    drifts from the thing it claims to describe with nothing to catch it."""
    for key, palette in app.THEMES.items():
        assert "hint" not in palette, f"{key} still carries an unused hint"


def test_stripping_meta_cannot_eat_palette_keys(cfg):
    """`_THEME_META` guards against emitting --label as a property. With one
    entry left it is a frozenset on purpose: written `("label")` it would be a
    STRING, and `k not in "label"` matches any substring, so --l, --a and --b
    would vanish from every palette with nothing failing.
    """
    assert not isinstance(app._THEME_META, str), \
        "_THEME_META is a string; substring matching will eat palette keys"
    css = app.theme_css(app.DEFAULT_THEME)
    for key in app.THEMES[app.DEFAULT_THEME]:
        if key == "label":
            continue
        assert f"--{key}:" in css, f"{key} was stripped from the palette"
