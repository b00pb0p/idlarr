#!/usr/bin/env python3
"""The panel's "next run" line, and its agreement with the scheduler.

next_check() restates the gate inside scheduler(). Two copies of one condition
is the shape of most bugs in this project, so the important test here is not
that the text is pretty, it is that the prediction and the gate agree across
every hour of the day.

Run:  .venv/bin/python -m pytest tests/test_next_check.py -q
"""

import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-nextcheck-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402


@pytest.fixture(autouse=True)
def clean():
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
    yield


def at(monkeypatch, hour, check_hour=9, last_check=None, day=6):
    """Freeze the clock and the config, the way the scheduler sees them."""
    cfg = dict(app.load_config())
    cfg["check_hour"] = check_hour
    monkeypatch.setattr(app, "load_config", lambda: cfg)

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 8, day, hour, 30, tzinfo=tz)

    monkeypatch.setattr(app, "datetime", Frozen)
    if last_check:
        app.set_state("last_check", last_check)


def scheduler_would_run(hour, check_hour, last_check, today="2026-08-06"):
    """The gate from scheduler(), restated once here so the sweep below has
    something independent to compare against."""
    return hour >= check_hour and last_check != today


# ------------------------------------------------------- the reported case

def test_moving_the_hour_after_the_day_already_ran(monkeypatch):
    """The field report, 2026-08-06. check_hour was moved to 23:00 during a day
    whose check had already run at 09:00, so nothing ran that evening. That is
    correct, and the panel gave no way to tell it from a stalled scheduler."""
    at(monkeypatch, hour=14, check_hour=23, last_check="2026-08-06")
    text, overdue = app.next_check()
    assert text == "next tomorrow 23:00"
    assert not overdue


def test_the_morning_after_that(monkeypatch):
    """Next day, before 23:00. Still waiting, and it should say for how long
    rather than leaving yesterday's timestamp to be interpreted."""
    at(monkeypatch, hour=8, check_hour=23, last_check="2026-08-05")
    assert app.next_check() == ("next today 23:00", False)


def test_the_hour_has_passed_and_the_day_has_not_run(monkeypatch):
    """The loop wakes every 10 minutes, so this is a narrow window. Anything
    still reading this on a reload is stuck rather than waiting, which is why
    it carries a flag the panel can color."""
    at(monkeypatch, hour=23, check_hour=23, last_check="2026-08-05")
    assert app.next_check() == ("due now", True)


# ------------------------------------------------------------- edge cases

def test_a_first_run_that_has_never_checked(monkeypatch):
    """`last_check` is empty. It must read as scheduled, not as overdue since
    the beginning of time, and the row beside it already says "never"."""
    at(monkeypatch, hour=8, check_hour=9, last_check=None)
    assert app.next_check() == ("next today 09:00", False)


def test_midnight_check_hour(monkeypatch):
    """check_hour 0 makes `hour >= 0` true at every hour, so the date is the
    only thing holding it back. Off-by-one here would claim a run had been
    missed every single day."""
    at(monkeypatch, hour=3, check_hour=0, last_check="2026-08-06")
    assert app.next_check() == ("next tomorrow 00:00", False)
    at(monkeypatch, hour=3, check_hour=0, last_check="2026-08-05")
    assert app.next_check() == ("due now", True)


def test_exactly_on_the_hour(monkeypatch):
    """The gate is `>=`, not `>`. A `>` here would push every check an hour
    late, in the direction that makes alerts arrive late."""
    at(monkeypatch, hour=9, check_hour=9, last_check="2026-08-05")
    assert app.next_check() == ("due now", True)


# ------------------------------------------------- the seam that matters

@pytest.mark.parametrize("check_hour", [0, 9, 23])
@pytest.mark.parametrize("ran_today", [True, False])
def test_the_prediction_agrees_with_the_gate_at_every_hour(
        monkeypatch, check_hour, ran_today):
    """The whole point. next_check() is a second copy of scheduler()'s
    condition; nothing else couples them. "due now" must mean exactly "the
    scheduler would fire on its next tick", at all 24 hours, for both states
    of the day.
    """
    last = "2026-08-06" if ran_today else "2026-08-05"
    for hour in range(24):
        at(monkeypatch, hour=hour, check_hour=check_hour, last_check=last)
        _, overdue = app.next_check()
        expected = scheduler_would_run(hour, check_hour, last)
        assert overdue == expected, (
            f"hour={hour} check_hour={check_hour} last_check={last}: "
            f"predictor says overdue={overdue}, gate says {expected}")


# ------------------------------------------------------------ the panel

def test_the_line_reaches_the_panel(monkeypatch):
    """Pins the CALL. next_check() passing its own tests proves nothing if the
    settings panel never asks for it."""
    at(monkeypatch, hour=8, check_hour=23, last_check="2026-08-05")
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert "next today 23:00" in html


def test_the_line_shows_before_anything_has_ever_run(monkeypatch):
    """First run. The activity row renders "never" through a different branch,
    and the first version of this dropped the next-run line on that path, which
    is the one install where "is this even scheduled?" is the actual question.
    """
    at(monkeypatch, hour=8, check_hour=9, last_check=None)
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert "never" in html and "next today 09:00" in html


def test_overdue_is_styled_and_the_rule_exists(monkeypatch):
    """A class with no rule behind it is invisible, so the one state worth
    noticing would look identical to the ones that are fine."""
    at(monkeypatch, hour=23, check_hour=9, last_check="2026-08-05")
    html = app.settings_sheet("none", 7, 7, "/idlarr.user.js")
    assert re.search(r'class="act-d due"', html)
    assert ".act-d.due{" in app.PAGE
