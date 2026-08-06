#!/usr/bin/env python3
"""Backups must not be world-readable, including ones already on disk.

A snapshot carries the whole `state` table: `session_secret` (mint a login),
`idlarr_token` (forge an auth event via /ping) and `import_key`. Read access to
one is strictly stronger than holding the read-only API key.

Run:  .venv/bin/python -m pytest tests/test_backup_modes.py -q
"""

import os
import stat
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="idlarr-backupmode-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def backups(tmp_path, monkeypatch):
    d = tmp_path / "backups"
    d.mkdir()
    monkeypatch.setattr(app, "BACKUP_DIR", d)
    return d


def test_a_fresh_backup_is_own_only(tmp_path, monkeypatch, backups):
    """The 2026-08-04 behavior, pinned so the retrofit cannot be mistaken for
    it. This one covers the file being written."""
    db = tmp_path / "src.db"
    monkeypatch.setattr(app, "DB_PATH", db)
    app.init_db()
    dest = app.backup_db("2026-08-06")
    assert dest is not None and mode(dest) == 0o600


def test_older_backups_are_retrofitted(backups):
    """The bug this exists for. `_own_only()` was added to backup_db() where it
    applies to the file being WRITTEN, so every install that upgraded kept a
    directory of 0644 snapshots and nothing ever said so.

    Reproduces the reference deployment on 2026-08-06 exactly: eight old
    snapshots at 0644 and the newest already at 0600.
    """
    old = []
    for day in range(28, 32):
        p = backups / f"idlarr-2026-07-{day}.db"
        p.write_bytes(b"x")
        os.chmod(p, 0o644)
        old.append(p)
    recent = backups / "idlarr-2026-08-05.db"
    recent.write_bytes(b"x")
    os.chmod(recent, 0o600)

    assert any(mode(p) & 0o077 for p in old), "precondition: some are readable"
    app.secure_existing_backups()

    for p in old + [recent]:
        assert mode(p) == 0o600, f"{p.name} left at {oct(mode(p))}"


def test_the_sweep_runs_even_when_backups_are_switched_off(backups, monkeypatch):
    """`backup_keep: 0` makes backup_db() return before it touches anything.
    Turning backups off does not delete the ones already written, so a sweep
    living inside backup_db() would never reach them. This is why it is called
    from startup instead."""
    monkeypatch.setattr(app, "backup_keep", lambda: 0)
    p = backups / "idlarr-2026-07-01.db"
    p.write_bytes(b"x")
    os.chmod(p, 0o644)
    app.secure_existing_backups()
    assert mode(p) == 0o600


def test_the_sweep_runs_when_todays_snapshot_already_exists(tmp_path, monkeypatch, backups):
    """backup_db() returns early on `if dest.exists()`. That is the state after
    any restart later the same day, which is exactly when someone reboots into
    a new version."""
    db = tmp_path / "src.db"
    monkeypatch.setattr(app, "DB_PATH", db)
    app.init_db()
    today = "2026-08-06"
    (backups / f"idlarr-{today}.db").write_bytes(b"x")
    os.chmod(backups / f"idlarr-{today}.db", 0o644)

    assert app.backup_db(today) is not None
    assert mode(backups / f"idlarr-{today}.db") == 0o644, \
        "precondition: backup_db returned early and fixed nothing"

    app.secure_existing_backups()
    assert mode(backups / f"idlarr-{today}.db") == 0o600


def test_a_missing_backup_dir_is_not_an_error(tmp_path, monkeypatch):
    """First run, or backups never enabled. Startup must not die here."""
    monkeypatch.setattr(app, "BACKUP_DIR", tmp_path / "nope")
    app.secure_existing_backups()


def test_it_does_not_claim_a_fix_the_filesystem_refused(backups, monkeypatch, capsys):
    """`_own_only()` swallows OSError, because fuse and shfs ignore chmod. If
    the mode is not read back, this reports success on a filesystem where
    nothing changed, and the operator is told a hole is closed when it is not.
    """
    monkeypatch.setattr(app, "_own_only", lambda p: None)     # chmod does nothing
    p = backups / "idlarr-2026-07-01.db"
    p.write_bytes(b"x")
    os.chmod(p, 0o644)

    app.secure_existing_backups()
    out = capsys.readouterr().out
    assert "restricted" not in out, "claimed a fix that did not happen"
    assert "WARNING" in out and "ignored chmod" in out


def test_startup_actually_runs_the_sweep(tmp_path, monkeypatch, backups):
    """Pins the CALL, not the definition.

    Every test above invokes secure_existing_backups() directly, so deleting
    the one line in lifespan() that calls it leaves all of them green while
    shipping the original bug untouched. Mutation-checked: removing that line
    turns this red and nothing else.

    Driven through TestClient's context manager, which is what runs lifespan.
    """
    from fastapi.testclient import TestClient

    p = backups / "idlarr-2026-07-01.db"
    p.write_bytes(b"x")
    os.chmod(p, 0o644)

    monkeypatch.setattr(app, "DB_PATH", tmp_path / "startup.db")
    with TestClient(app.app):
        pass

    assert mode(p) == 0o600, "startup did not sweep existing backups"
