#!/usr/bin/env python3
"""Tests for save_tracker_fields() — the trackers.yml writeback.

This is the only code in the project that writes to the user's source of truth,
and trackers.yml is full of load-bearing comments (the fail-safe warning, the
per-tracker notes about seeding / user class / vacation mode). A yaml.safe_dump
round-trip would silently delete all of it, so these tests assert on the exact
bytes, not just on the parsed result.

Run:  .venv/bin/python -m pytest test_config_write.py -q
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

_tmp = tempfile.mkdtemp(prefix="idlarr-cfgtest-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")

import app  # noqa: E402

# A committed fixture, not the user's live config: the real trackers.yml is
# gitignored, and tests must not depend on which trackers anyone runs.
FIXTURE = Path(__file__).parent / "tests_fixture.yml"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """A throwaway copy of the fixture config, wired into the module."""
    path = tmp_path / "trackers.yml"
    shutil.copy(FIXTURE, path)
    monkeypatch.setattr(app, "CONFIG_PATH", path)
    app._cfg_cache["data"] = None
    yield path
    app._cfg_cache["data"] = None


def entry(path, tracker_id):
    data = yaml.safe_load(path.read_text())
    return next(t for t in data["trackers"] if t["id"] == tracker_id)


# ------------------------------------------------------------ the happy path

def test_sets_inactivity_days(cfg):
    app.save_tracker_fields("beta", inactivity_days=120)
    assert entry(cfg, "beta")["inactivity_days"] == 120


def test_sets_verified(cfg):
    app.save_tracker_fields("beta", verified=True)
    assert entry(cfg, "beta")["verified"] is True


def test_sets_both(cfg):
    app.save_tracker_fields("beta", inactivity_days=90, verified=True)
    e = entry(cfg, "beta")
    assert (e["inactivity_days"], e["verified"]) == (90, True)


def test_verified_can_go_back_to_false(cfg):
    app.save_tracker_fields("beta", verified=True)
    app.save_tracker_fields("beta", verified=False)
    assert entry(cfg, "beta")["verified"] is False


def test_noop_when_both_none(cfg):
    before = cfg.read_text()
    app.save_tracker_fields("beta")
    assert cfg.read_text() == before


# ------------------------------------------------- comments must survive

def test_header_warning_block_survives(cfg):
    app.save_tracker_fields("beta", inactivity_days=120, verified=True)
    text = cfg.read_text()
    assert "A FAIL-SAFE PLACEHOLDER, NOT A FACT" in text
    assert "whether seeding announces reset the clock" in text
    assert "vacation/hiatus mode" in text


def test_per_tracker_notes_survive(cfg):
    app.save_tracker_fields("gamma", inactivity_days=45)
    text = cfg.read_text()
    assert "Already lost this one once." in text
    assert "Has vacation mode - use it." in text
    assert "Confirm the domain periodically." in text


def test_only_the_intended_line_changes(cfg):
    before = cfg.read_text().splitlines()
    app.save_tracker_fields("beta", inactivity_days=120)
    after = cfg.read_text().splitlines()
    assert len(before) == len(after)
    diff = [(b, a) for b, a in zip(before, after) if b != a]
    assert len(diff) == 1
    assert diff[0][0].strip() == "inactivity_days: 30"
    assert diff[0][1].strip() == "inactivity_days: 120"


def test_indentation_is_preserved(cfg):
    app.save_tracker_fields("beta", inactivity_days=120)
    line = next(l for l in cfg.read_text().splitlines()
                if l.strip() == "inactivity_days: 120")
    assert line.startswith("    ")      # 4 spaces, matching sibling keys


# ------------------------------------------------------ blast radius

def test_other_trackers_untouched(cfg):
    before = {t["id"]: dict(t) for t in yaml.safe_load(cfg.read_text())["trackers"]}
    app.save_tracker_fields("beta", inactivity_days=120, verified=True)
    after = {t["id"]: dict(t) for t in yaml.safe_load(cfg.read_text())["trackers"]}
    assert set(before) == set(after)
    for tid in before:
        if tid != "beta":
            assert before[tid] == after[tid], f"{tid} changed"


def test_defaults_block_untouched(cfg):
    app.save_tracker_fields("beta", inactivity_days=120)
    data = yaml.safe_load(cfg.read_text())
    assert data["defaults"]["inactivity_days"] == 30
    assert data["defaults"]["alert_at_pct"] == 0.65
    assert data["defaults"]["timezone"] == "America/Chicago"


def test_tracker_count_is_stable(cfg):
    app.save_tracker_fields("beta", inactivity_days=120)
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7


def test_first_and_last_entries_are_writable(cfg):
    """Block-bounds maths is most likely to be wrong at the edges."""
    app.save_tracker_fields("alpha", inactivity_days=11)       # first
    app.save_tracker_fields("omega", inactivity_days=99)    # last
    assert entry(cfg, "alpha")["inactivity_days"] == 11
    assert entry(cfg, "omega")["inactivity_days"] == 99
    assert entry(cfg, "epsilon")["inactivity_days"] == 30


# --------------------------------------------------------------- immunity

def test_sets_immune(cfg):
    app.save_tracker_fields("delta", immune=True)
    assert entry(cfg, "delta")["immune"] is True


def test_immune_key_is_inserted_when_absent(cfg):
    """No shipped entry has an immune: line, so this is always an insert.

    Asserts on parsed entries, not raw text — the file's header comments
    document the field, and matching those was a false failure once already.
    """
    shipped = yaml.safe_load(cfg.read_text())["trackers"]
    assert all("immune" not in t for t in shipped)
    app.save_tracker_fields("delta", immune=True)
    assert entry(cfg, "delta")["immune"] is True
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7


def test_immune_reason_round_trips(cfg):
    app.save_tracker_fields("delta", immune=True, immune_reason="Elite user class")
    assert entry(cfg, "delta")["immune_reason"] == "Elite user class"


def test_immune_reason_survives_quotes_and_colons(cfg):
    """The reason is free text from a form; YAML must not choke on it."""
    nasty = 'donated: "gold" tier #1 — 50% off, back\\slash'
    app.save_tracker_fields("delta", immune_reason=nasty)
    assert entry(cfg, "delta")["immune_reason"] == nasty
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7


def test_immune_reason_with_newline_does_not_break_the_file(cfg):
    app.save_tracker_fields("delta", immune_reason="line one\nline two")
    assert entry(cfg, "delta")["immune_reason"] == "line one\nline two"
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7
    assert "A FAIL-SAFE PLACEHOLDER, NOT A FACT" in cfg.read_text()


def test_immunity_can_be_cleared(cfg):
    app.save_tracker_fields("delta", immune=True, immune_reason="vacation mode")
    app.save_tracker_fields("delta", immune=False)
    e = entry(cfg, "delta")
    assert e["immune"] is False
    assert e["immune_reason"] == "vacation mode"   # kept, so re-enabling is cheap


def test_immune_does_not_disturb_neighbors(cfg):
    before = {t["id"]: dict(t) for t in yaml.safe_load(cfg.read_text())["trackers"]}
    app.save_tracker_fields("delta", immune=True, immune_reason="Elite")
    after = {t["id"]: dict(t) for t in yaml.safe_load(cfg.read_text())["trackers"]}
    for tid in before:
        if tid != "delta":
            assert before[tid] == after[tid], f"{tid} changed"


# --------------------------------------------------------------- refusals

def test_unknown_tracker_raises(cfg):
    before = cfg.read_text()
    with pytest.raises(KeyError):
        app.save_tracker_fields("does-not-exist", inactivity_days=60)
    assert cfg.read_text() == before


def test_commented_block_is_not_matched(cfg):
    """A commented-out entry must never be treated as a real one."""
    cfg.write_text(cfg.read_text() + (
        "\n"
        "  # - id: ghost\n"
        "  #   name: Ghost\n"
        "  #   inactivity_days: 30\n"
        "  #   verified: false\n"
    ))
    app._cfg_cache["data"] = None
    with pytest.raises(KeyError):
        app.save_tracker_fields("ghost", inactivity_days=60)
    assert "#   inactivity_days: 30" in cfg.read_text()


def test_no_tmp_file_left_behind(cfg):
    app.save_tracker_fields("beta", inactivity_days=120)
    assert not list(cfg.parent.glob("*.tmp"))


def test_missing_key_is_inserted(cfg):
    """A tracker with no inactivity_days line still gets one."""
    # Strip the key from one entry by line, rather than matching a literal
    # block — the fixture's exact text is not something tests should encode.
    lines = cfg.read_text().splitlines(keepends=True)
    start, end, _ = app._block_bounds(lines, "zeta")
    kept = [l for i, l in enumerate(lines)
            if not (start <= i < end and l.strip().startswith("inactivity_days:"))]
    cfg.write_text("".join(kept))
    app._cfg_cache["data"] = None
    assert "inactivity_days" not in yaml.safe_load(cfg.read_text())["trackers"][5]

    app.save_tracker_fields("zeta", inactivity_days=75)
    assert entry(cfg, "zeta")["inactivity_days"] == 75
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7


# ------------------------------------------------- reload after write

def test_load_config_sees_the_change(cfg):
    """The in-process cache must not serve a stale limit after a write."""
    assert next(t for t in app.load_config()["trackers"]
                if t["id"] == "beta")["inactivity_days"] == 30
    app.save_tracker_fields("beta", inactivity_days=120)
    assert next(t for t in app.load_config()["trackers"]
                if t["id"] == "beta")["inactivity_days"] == 120


def test_repeated_writes_accumulate(cfg):
    for n in (40, 50, 60):
        app.save_tracker_fields("beta", inactivity_days=n)
    assert entry(cfg, "beta")["inactivity_days"] == 60
    assert len(yaml.safe_load(cfg.read_text())["trackers"]) == 7
    assert "A FAIL-SAFE PLACEHOLDER, NOT A FACT" in cfg.read_text()


# ------------------------------------------------------------------- notes
#
# Notes were write-once until 2026-08-03: settable when adding a tracker from
# the page and unreachable afterwards. Since `software` is derived from the
# first word of notes, that also meant a wrong software column was permanent
# without hand-editing the file.

def test_sets_notes(cfg):
    app.save_tracker_fields("beta", notes="UNIT3D. Vacation mode available.")
    assert entry(cfg, "beta")["notes"] == "UNIT3D. Vacation mode available."


def test_notes_edit_keeps_comments(cfg):
    app.save_tracker_fields("beta", notes="Custom")
    assert "EVERY inactivity_days BELOW IS A FAIL-SAFE PLACEHOLDER" in cfg.read_text()


def test_notes_edit_leaves_siblings_alone(cfg):
    before = {t["id"]: t for t in yaml.safe_load(cfg.read_text())["trackers"]
              if t["id"] != "beta"}
    app.save_tracker_fields("beta", notes="TBDev")
    after = {t["id"]: t for t in yaml.safe_load(cfg.read_text())["trackers"]
             if t["id"] != "beta"}
    assert after == before


def test_editing_notes_re_derives_software(cfg):
    """The software column is the first word of notes. Editing one must move
    the other, or the row keeps showing software the notes no longer claim."""
    app._cfg_cache["data"] = None
    assert {t["id"]: t["software"] for t in app.load_config()["trackers"]}["beta"] == "Gazelle"
    app.save_tracker_fields("beta", notes="UNIT3D. Moved off Gazelle.")
    assert {t["id"]: t["software"] for t in app.load_config()["trackers"]}["beta"] == "UNIT3D"


def test_notes_with_awkward_characters_survive(cfg):
    tricky = 'Custom. Uses a: colon, "quotes", and a # hash.'
    app.save_tracker_fields("beta", notes=tricky)
    assert entry(cfg, "beta")["notes"] == tricky


def test_notes_can_be_cleared(cfg):
    app.save_tracker_fields("beta", notes="")
    assert entry(cfg, "beta")["notes"] == ""


def test_notes_alone_is_enough_to_write(cfg):
    """Every other field is None here; the early-return guard must not swallow
    a notes-only update."""
    app.save_tracker_fields("beta", notes="Changed")
    assert entry(cfg, "beta")["notes"] == "Changed"
