#!/usr/bin/env python3
"""
Idlarr — passive inactivity watchdog for private trackers.

Generates ZERO traffic to any tracker. A userscript reports when you were
last seen logged in; this service nags you before the inactivity limit is reached.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import stat as statmod
import threading
import time
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
import zoneinfo
from zoneinfo import ZoneInfo

import yaml
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

# ---------------------------------------------------------------- config

DB_PATH = Path(os.environ.get("IDLARR_DB", "/data/idlarr.db"))
CONFIG_PATH = Path(os.environ.get("IDLARR_CONFIG", "/config/trackers.yml"))
TOKEN = os.environ.get("IDLARR_TOKEN", "")
_ENV_STATUS_URL = os.environ.get("STATUS_URL", "").strip()
STATUS_URL = _ENV_STATUS_URL      # startup default, before the config loads


def status_url() -> str:
    """Public URL of the status page: appended to alerts, and the endpoint the
    generated userscript reports to.

    Config is authoritative; STATUS_URL seeds it once, same as TZ and
    backup_keep. Getting this wrong points the script's @connect at the wrong
    host and tracker CSP silently kills every ping, so being able to fix it
    from the panel — rather than by editing compose and recreating the
    container — matters more here than for most settings.
    """
    try:
        return str(load_config().get("status_url", "") or "")
    except Exception:
        return _ENV_STATUS_URL

# Every notification goes through Apprise -- ntfy included, via ntfy:// or
# ntfys://. One code path, ~100 services, nothing bespoke to maintain. See
# https://github.com/caronc/apprise/wiki for each service's URL scheme.
# These strings carry credentials, so they are never printed.
# Destinations come from TWO places and both stay supported: this variable, and
# the list managed in Settings. They ADD to one list rather than competing for
# one value, so there is no precedence rule to get wrong -- which is what made
# the old dual-source `backup_keep` design bad, not the fact of two sources.
#
# The reason to keep this one is privacy, not compatibility. A destination
# added in the panel lives in the database, so it lives in every backup. Anyone
# who would rather no credential ever touched the database keeps using this,
# and .env is not in /data.
NOTIFY_ENV = [u.strip() for u in os.environ.get("IDLARR_NOTIFY_URLS", "").split(",") if u.strip()]

# One event per kind per tracker per this window. Server-side on purpose — see
# the note in /ping. Must be >= the userscript's client-side cooldown.
DEDUPE_HOURS = int(os.environ.get("IDLARR_DEDUPE_HOURS", 12))

# Daily snapshot of the events database, taken as part of the daily check.
# Set IDLARR_BACKUP_KEEP=0 to turn it off.
BACKUP_DIR = Path(os.environ.get("IDLARR_BACKUP_DIR", "/data/backups"))
_ENV_BACKUP_KEEP = os.environ.get("IDLARR_BACKUP_KEEP", "").strip()
BACKUP_KEEP = int(_ENV_BACKUP_KEEP or 14)   # startup default, before config loads


def backup_keep() -> int:
    """How many snapshots to retain. Config only.

    IDLARR_BACKUP_KEEP SEEDS this on first run and is then ignored — the same
    shape as TZ seeding the generated config. Two live sources for one integer
    meant a precedence rule, a read-only mode and a note explaining which one
    won; one source needs none of that.
    """
    try:
        return int(load_config().get("backup_keep", 14))
    except Exception:
        return 14

# Set IDLARR_RESET_AUTH=1 to clear the UI login on the next boot. Without an
# escape hatch a forgotten password bricks the dashboard permanently — the
# credentials live in the database, so there is no config file to hand-edit
# the way you would with an *arr's config.xml.
RESET_AUTH = os.environ.get("IDLARR_RESET_AUTH", "").strip().lower() in ("1", "true", "yes")

# Injected at image build time from the git tag (see the Dockerfile and
# publish.yml). Hand-maintaining this drifted immediately: v1.1.1 shipped
# reporting 1.1.0, so a correctly-updated container told its owner it had not
# updated. "dev" is honest when running from source.
IDLARR_VERSION = os.environ.get("IDLARR_VERSION", "dev")

KNOWN_SOFTWARE = {"gazelle": "Gazelle", "unit3d": "UNIT3D", "tbdev": "TBDev",
                  "custom": "Custom"}

def default_config() -> str:
    """The config written on first run when none exists.

    The timezone comes from the TZ environment variable, NOT a hardcoded UTC.
    local_tz() reads this file, not the environment, so hardcoding UTC here
    would silently count days in the wrong zone for anyone who set TZ in
    compose — and counting in a zone behind the user's makes days_left too
    large, which fires every alert LATE. That is the unsafe direction, and it
    is invisible: nothing looks wrong, the countdown is just quietly generous.

    Carries the same fail-safe warning as trackers.example.yml, so a generated
    config still shouts that 30d is a placeholder rather than a fact.
    """
    tz = (os.environ.get("TZ") or "UTC").strip() or "UTC"
    try:
        ZoneInfo(tz)
    except Exception:
        print(f"[startup] TZ={tz!r} is not a known timezone: using UTC in the "
              f"generated config. Fix `timezone:` in trackers.yml, or day "
              f"counting will be off for you.")
        tz = "UTC"
    return f"""# Idlarr config. Hot-reloaded: no container restart needed.
#
# Add trackers from the status page (+ Add tracker), import them from Prowlarr
# or Jackett, or write them here by hand. See docs/trackers.md.
#
# ############################################################################
# # EVERY inactivity_days IS A FAIL-SAFE PLACEHOLDER UNTIL YOU CONFIRM IT.   #
# # 30d is short enough to nag before almost any real limit is hit. Raise    #
# # each one as you read that tracker's own rules page, then set verified.   #
# ############################################################################

defaults:
  inactivity_days: 30
  alert_at_pct: 0.65
  timezone: {tz}
  check_hour: 9
  backup_keep: 14

trackers:
"""


_cfg_cache = {"mtime": 0.0, "data": None}


def host_from_url(url: str) -> str:
    """Bare hostname from a config `url`, minus any leading www.

    The userscript matches `location.hostname.includes(host)`, so dropping
    `www.` is what makes one entry cover both the apex and the subdomain. A
    tracker whose login sits on a different domain from its browse pages needs
    an explicit `host:` in the config instead.
    """
    if not url:
        return ""
    host = re.sub(r"^[a-z]+://", "", url.strip(), flags=re.I).split("/")[0]
    host = host.split("@")[-1].split(":")[0]          # strip credentials, port
    return re.sub(r"^www\.", "", host, flags=re.I).lower()


def load_config() -> dict:
    """Reload trackers.yml on change so edits don't need a container restart."""
    mtime = CONFIG_PATH.stat().st_mtime
    if _cfg_cache["data"] is None or mtime != _cfg_cache["mtime"]:
        with CONFIG_PATH.open() as fh:
            raw = yaml.safe_load(fh) or {}
        defaults = raw.get("defaults", {}) or {}
        trackers = []
        for t in raw.get("trackers", []) or []:
            merged = {**defaults, **t}
            # 30, never 90. This only fires if BOTH the entry and the defaults
            # block omit the key, which should never happen — but the value it
            # falls back to has to err short. A tracker that silently got 90
            # would be indistinguishable from the eight trackers legitimately
            # set to 90, so the mistake would never be visible; and if its real
            # policy were 30, the account would be pruned around day 30 while
            # the first alert waited until day 76.
            merged.setdefault("inactivity_days", 30)
            merged.setdefault("alert_at_pct", 0.65)
            merged.setdefault("name", merged["id"])
            merged.setdefault("notes", "")
            merged.setdefault("url", "")
            merged.setdefault("verified", False)   # has the limit been confirmed?
            # Donation, a high user class, or a permanent exemption can put an
            # account outside inactivity pruning entirely. Such a tracker keeps
            # its row (and its link, and the reason) but never alerts.
            merged.setdefault("immune", False)
            merged.setdefault("immune_reason", "")
            # ISO date. Suppresses alerts until it passes, then evaluation
            # returns to normal on its own — the point of a snooze over
            # `immune` is that forgetting to undo it is not a silent failure.
            merged.setdefault("snooze_until", "")
            # The status page shows tracker software as its own column. It has
            # always lived as the first word of `notes` ("Gazelle. Already lost
            # once."), so derive it rather than making the user restate it. An
            # explicit `software:` key wins if one is ever added.
            if not merged.get("software"):
                first = re.split(r"[.\s]", (merged.get("notes") or "").strip(), maxsplit=1)[0]
                merged["software"] = KNOWN_SOFTWARE.get(first.lower(), "")
            # `host` drives the generated userscript's @match lines and its
            # SITES entry. Derived from `url` so nobody restates the domain,
            # with an explicit `host:` override for the odd site whose login
            # lives on a different domain from its browse pages.
            if not merged.get("host"):
                merged["host"] = host_from_url(merged.get("url", ""))
            # Escape hatch for a site the logout heuristic cannot read at all
            # (an SPA that renders its menu only on click). Any selector that
            # exists ONLY when authenticated.
            merged.setdefault("auth_sel", "")
            trackers.append(merged)
        _cfg_cache.update(
            mtime=mtime,
            data={
                "trackers": trackers,
                "timezone": defaults.get("timezone", "UTC"),
                "check_hour": int(defaults.get("check_hour", 9)),
                # 0 disables. Nothing watches the watchdog otherwise: if this
                # container dies, the output is silence, which is
                # indistinguishable from "nothing is due".
                "alive_push_days": int(defaults.get("alive_push_days", 0)),
                "alert_at_pct": float(defaults.get("alert_at_pct", 0.65)),
                "backup_keep": int(defaults.get("backup_keep", 14)),
                "status_url": str(defaults.get("status_url", "") or ""),
            },
        )
    return _cfg_cache["data"]


def local_tz() -> ZoneInfo:
    return ZoneInfo(load_config()["timezone"])


# ------------------------------------------------------- config writeback

_write_lock = threading.Lock()

_ID_RE = re.compile(r"^(\s*)-\s+id:\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*$")


def _block_bounds(lines: list[str], tracker_id: str) -> tuple[int, int, str]:
    """Locate one tracker's line range in trackers.yml.

    Returns (start, end, indent) where start is the '- id:' line and end is
    exclusive. Comment lines are skipped when matching so the commented-out
    example blocks the file has carried in the past can never be hit.
    """
    start = indent = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        m = _ID_RE.match(line)
        if m and m.group(2) == tracker_id:
            start, indent = i, m.group(1)
            break
    if start is None:
        raise KeyError(f"no '- id: {tracker_id}' block in {CONFIG_PATH}")

    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.lstrip().startswith("#") or not line.strip():
            continue
        # next list item at the same indent, or any shallower key, ends the block
        stripped = len(line) - len(line.lstrip())
        if _ID_RE.match(line) or stripped <= len(indent):
            end = i
            break
    return start, end, indent


def save_tracker_fields(tracker_id: str, inactivity_days: int | None = None,
                        verified: bool | None = None, immune: bool | None = None,
                        immune_reason: str | None = None,
                        notes: str | None = None,
                        snooze_until: str | None = None,
                        alert_at_pct: float | None = None) -> None:
    """Rewrite one tracker's inactivity_days / verified in trackers.yml.

    A surgical line edit, NOT a yaml.safe_dump round-trip. The comments in
    trackers.yml are load-bearing — the fail-safe warning block and the
    per-tracker notes about seeding/user class/vacation mode are the whole
    point of item 1 — and dumping would erase every one of them.

    Writes atomically via os.replace, and refuses to install a file that
    doesn't parse or that changes the tracker count.
    """
    if all(v is None for v in (inactivity_days, verified, immune, immune_reason,
                               notes, snooze_until, alert_at_pct)):
        return

    with _write_lock:
        original = CONFIG_PATH.read_text()
        lines = original.splitlines(keepends=True)
        start, end, indent = _block_bounds(lines, tracker_id)
        field_indent = indent + "  "

        def upsert(key: str, value: str) -> None:
            nonlocal end
            pat = re.compile(rf"^(\s*){re.escape(key)}:\s*.*$")
            for i in range(start + 1, end):
                if lines[i].lstrip().startswith("#"):
                    continue
                m = pat.match(lines[i])
                if m:
                    lines[i] = f"{m.group(1)}{key}: {value}\n"
                    return
            # absent — insert directly under the id line
            lines.insert(start + 1, f"{field_indent}{key}: {value}\n")
            end += 1

        if inactivity_days is not None:
            upsert("inactivity_days", str(int(inactivity_days)))
        if verified is not None:
            upsert("verified", "true" if verified else "false")
        if immune is not None:
            upsert("immune", "true" if immune else "false")
        if alert_at_pct is not None:
            upsert("alert_at_pct", str(float(alert_at_pct)))
        if snooze_until is not None:
            upsert("snooze_until", json.dumps(str(snooze_until)))
        if notes is not None:
            # Also re-derives the software column, since that is the first word
            # of notes unless an explicit `software:` key overrides it.
            upsert("notes", json.dumps(str(notes)))
        if immune_reason is not None:
            # json.dumps produces a double-quoted scalar that is valid YAML and
            # escapes quotes/backslashes/newlines. The re-parse check below is
            # what actually guarantees it survived.
            upsert("immune_reason", json.dumps(str(immune_reason)))

        candidate = "".join(lines)

        # Validate before touching the real file. A corrupt trackers.yml means
        # the service refuses to start (FileNotFoundError's sibling), and the
        # user finds out via a missed alert.
        before = yaml.safe_load(original) or {}
        after = yaml.safe_load(candidate) or {}
        n_before = len(before.get("trackers") or [])
        n_after = len(after.get("trackers") or [])
        if n_after != n_before:
            raise ValueError(f"refusing write: tracker count {n_before} -> {n_after}")
        entry = next((t for t in after["trackers"] if t.get("id") == tracker_id), None)
        if entry is None:
            raise ValueError(f"refusing write: '{tracker_id}' vanished from config")
        if inactivity_days is not None and entry.get("inactivity_days") != int(inactivity_days):
            raise ValueError("refusing write: inactivity_days did not take")
        if verified is not None and bool(entry.get("verified")) != bool(verified):
            raise ValueError("refusing write: verified did not take")
        if immune is not None and bool(entry.get("immune")) != bool(immune):
            raise ValueError("refusing write: immune did not take")
        if immune_reason is not None and entry.get("immune_reason", "") != str(immune_reason):
            raise ValueError("refusing write: immune_reason did not take")
        if notes is not None and entry.get("notes", "") != str(notes):
            raise ValueError("refusing write: notes did not take")
        if snooze_until is not None and str(entry.get("snooze_until", "")) != str(snooze_until):
            raise ValueError("refusing write: snooze_until did not take")
        if alert_at_pct is not None and float(entry.get("alert_at_pct", -1)) != float(alert_at_pct):
            raise ValueError("refusing write: alert_at_pct did not take")

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(candidate)
        os.replace(tmp, CONFIG_PATH)

    # Force a reload rather than trusting mtime granularity on fuse/shfs mounts.
    _cfg_cache["data"] = None


ID_OK = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")


def slugify(name: str) -> str:
    """A tracker id from a display name. Must satisfy ID_OK or the caller
    should reject it — the id ends up in the userscript's SITES array, in DOM
    element ids, and in every /ping, so it stays boring on purpose."""
    slug = re.sub(r"[^a-z0-9]+", "", (name or "").strip().lower())
    return slug[:40]


def _entry_block(entry: dict, indent: str) -> list[str]:
    """Render one tracker as YAML lines. json.dumps gives a double-quoted
    scalar that is valid YAML and escapes quotes and backslashes; the re-parse
    check in the callers is what actually proves it survived."""
    field = indent + "  "
    out = [f"{indent}- id: {entry['id']}\n",
           f"{field}name: {json.dumps(entry['name'])}\n",
           f"{field}url: {json.dumps(entry.get('url', ''))}\n"]
    if entry.get("host"):
        out.append(f"{field}host: {json.dumps(entry['host'])}\n")
    out.append(f"{field}inactivity_days: {int(entry['inactivity_days'])}\n")
    out.append(f"{field}verified: {'true' if entry.get('verified') else 'false'}\n")
    if entry.get("notes"):
        out.append(f"{field}notes: {json.dumps(entry['notes'])}\n")
    if entry.get("auth_sel"):
        out.append(f"{field}auth_sel: {json.dumps(entry['auth_sel'])}\n")
    return out


def _others(doc: dict, skip: str) -> dict:
    """Every tracker except one, keyed by id: for blast-radius checks."""
    return {t.get("id"): t for t in (doc.get("trackers") or []) if t.get("id") != skip}


def save_default_field(key: str, value) -> None:
    """Rewrite one key in the `defaults:` block of trackers.yml.

    Same surgical-line-edit discipline as save_tracker_fields: never a yaml
    dump, because the comments in that file are load-bearing. Validates the
    result parses, that the key took, and that the TRACKER LIST is untouched —
    a defaults edit that silently dropped an entry would be invisible until
    that tracker's limit mattered.
    """
    allowed = {"timezone", "check_hour", "alert_at_pct", "inactivity_days",
               "alive_push_days", "backup_keep", "status_url"}
    if key not in allowed:
        raise KeyError(f"not a settable default: {key}")

    with _write_lock:
        original = CONFIG_PATH.read_text()
        lines = original.splitlines(keepends=True)

        start = next((i for i, ln in enumerate(lines)
                      if re.match(r"^defaults:\s*$", ln)), None)
        if start is None:
            raise ValueError("no `defaults:` block in the config")
        end = len(lines)
        for i in range(start + 1, len(lines)):
            ln = lines[i]
            if ln.strip() and not ln.startswith((" ", "\t")) and not ln.lstrip().startswith("#"):
                end = i
                break

        rendered = json.dumps(value) if isinstance(value, str) else str(value)
        pat = re.compile(rf"^(\s+){re.escape(key)}:\s*.*$")
        for i in range(start + 1, end):
            if lines[i].lstrip().startswith("#"):
                continue
            m = pat.match(lines[i])
            if m:
                lines[i] = f"{m.group(1)}{key}: {rendered}\n"
                break
        else:
            lines.insert(start + 1, f"  {key}: {rendered}\n")

        candidate = "".join(lines)
        before = yaml.safe_load(original) or {}
        after = yaml.safe_load(candidate) or {}
        if (after.get("defaults") or {}).get(key) != value:
            raise ValueError(f"refusing write: {key} did not take")
        if (before.get("trackers") or []) != (after.get("trackers") or []):
            raise ValueError("refusing write: it changed the tracker list")

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(candidate)
        os.replace(tmp, CONFIG_PATH)

    _cfg_cache["data"] = None


def add_tracker(entry: dict) -> None:
    """Append a tracker to trackers.yml, comments intact.

    Same discipline as save_tracker_fields: a line edit, never a yaml dump,
    validated before os.replace. The extra check here is BLAST RADIUS — every
    other entry must come back byte-for-byte identical after parsing. An append
    that quietly reformatted a sibling would be invisible until the day that
    sibling's limit mattered.
    """
    tid = entry["id"]
    with _write_lock:
        original = CONFIG_PATH.read_text()
        lines = original.splitlines(keepends=True)
        before = yaml.safe_load(original) or {}
        existing = [t.get("id") for t in (before.get("trackers") or [])]
        if tid in existing:
            raise ValueError(f"'{tid}' is already in the config")

        if existing:
            _, end, indent = _block_bounds(lines, existing[-1])
        else:
            # An empty list: insert directly under the `trackers:` key.
            # Accept `trackers:` and `trackers: []`. An inline empty list has
            # to be rewritten to a bare key first — appending a block under
            # `trackers: []` produces invalid YAML, which is how the very first
            # "Add tracker" on an auto-created config used to fail.
            end = None
            for i, ln in enumerate(lines):
                m = re.match(r"^trackers:\s*(\[\s*\])?\s*$", ln)
                if m:
                    if m.group(1):
                        lines[i] = "trackers:\n"
                    end = i + 1
                    break
            if end is None:
                raise ValueError("no `trackers:` key in the config to append to")
            indent = "  "

        block = _entry_block(entry, indent)
        # Keep the blank-line rhythm the file already uses, without stacking
        # blank lines when the previous entry already ended with one.
        if end > 0 and lines[end - 1].strip():
            block.insert(0, "\n")
        lines[end:end] = block
        candidate = "".join(lines)

        after = yaml.safe_load(candidate) or {}
        n_before, n_after = len(existing), len(after.get("trackers") or [])
        if n_after != n_before + 1:
            raise ValueError(f"refusing write: tracker count {n_before} -> {n_after}")
        fresh = next((t for t in after["trackers"] if t.get("id") == tid), None)
        if fresh is None:
            raise ValueError(f"refusing write: '{tid}' is not in the result")
        if fresh.get("name") != entry["name"]:
            raise ValueError("refusing write: name did not survive the round-trip")
        if int(fresh.get("inactivity_days", -1)) != int(entry["inactivity_days"]):
            raise ValueError("refusing write: inactivity_days did not take")
        if _others(after, tid) != _others(before, tid):
            raise ValueError("refusing write: it changed another tracker")

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(candidate)
        os.replace(tmp, CONFIG_PATH)

    _cfg_cache["data"] = None


def remove_tracker(tracker_id: str) -> None:
    """Delete one tracker's block from trackers.yml.

    Its EVENTS are deliberately left in the database. `events` is append-only
    apart from drop_last_auth(), and keeping them means re-adding the same id
    restores its history rather than silently starting the countdown over —
    which is the failure mode this whole service exists to prevent.
    """
    with _write_lock:
        original = CONFIG_PATH.read_text()
        lines = original.splitlines(keepends=True)
        before = yaml.safe_load(original) or {}
        start, end, _ = _block_bounds(lines, tracker_id)
        # Absorb one preceding blank line so removals don't leave a growing
        # gap where trackers used to be.
        if start > 0 and not lines[start - 1].strip():
            start -= 1
        del lines[start:end]
        candidate = "".join(lines)

        after = yaml.safe_load(candidate) or {}
        n_before = len(before.get("trackers") or [])
        n_after = len(after.get("trackers") or [])
        if n_after != n_before - 1:
            raise ValueError(f"refusing write: tracker count {n_before} -> {n_after}")
        if any(t.get("id") == tracker_id for t in (after.get("trackers") or [])):
            raise ValueError(f"refusing write: '{tracker_id}' is still there")
        if _others(after, tracker_id) != _others(before, tracker_id):
            raise ValueError("refusing write: it changed another tracker")

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(candidate)
        os.replace(tmp, CONFIG_PATH)

    _cfg_cache["data"] = None


# ---------------------------------------------------------------- storage

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _own_only(path: Path) -> None:
    """chmod 0600. SQLite creates files 0644 by default, so the database and
    every backup were world-readable — on a shared host that hands any local
    user the full tracker list, the API token, the session secret (with which
    they can mint a login) and the saved Prowlarr key. Cheap to close, and it
    needs no key management, unlike encrypting at rest."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass          # best effort: some filesystems (fuse/shfs) ignore modes


def secure_existing_backups() -> None:
    """Retrofit 0600 onto snapshots written before that was enforced.

    `_own_only()` was added to `backup_db()` on 2026-08-04, where it applies to
    the file being written and nothing else. So every install that UPGRADED
    kept a directory of 0644 snapshots, each carrying `session_secret` and
    `idlarr_token`, readable by any local user. Retention ages them out, but
    that is up to `backup_keep` days of exposure that nothing anywhere reports.
    Found on the reference deployment 2026-08-06: the database was 0600 and
    eight of nine backups beside it were 0644.

    At STARTUP, not inside backup_db(): that returns early when the day's
    snapshot already exists, and early again when backups are switched off,
    so a sweep placed there would skip the restart right after an upgrade,
    which is the one case this exists for.

    The mode is read back afterwards rather than assumed. `_own_only()` is
    best-effort and swallows the failure, so on a filesystem that ignores modes
    this would otherwise report a fix that did not happen.
    """
    try:
        found = sorted(BACKUP_DIR.glob("idlarr-*.db"))
    except OSError:
        return

    fixed, stubborn = 0, 0
    for path in found:
        try:
            if not statmod.S_IMODE(path.stat().st_mode) & 0o077:
                continue
            _own_only(path)
            if statmod.S_IMODE(path.stat().st_mode) & 0o077:
                stubborn += 1
            else:
                fixed += 1
        except OSError:
            continue

    if fixed:
        print(f"[backup] restricted {fixed} older snapshot(s) to 0600")
    if stubborn:
        print(f"[startup] WARNING: {stubborn} backup(s) under {BACKUP_DIR} stay "
              f"group/world-readable; the filesystem ignored chmod. They hold "
              f"the session secret and the ping token. Move /data to a path "
              f"that honors file modes.")


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                tracker_id TEXT NOT NULL,
                kind       TEXT NOT NULL,      -- 'auth' | 'visit'
                ts         TEXT NOT NULL,      -- ISO8601 UTC
                source     TEXT DEFAULT ''     -- 'userscript' | 'manual'
            );
            CREATE INDEX IF NOT EXISTS idx_events_lookup
                ON events (tracker_id, kind, ts DESC);
            CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
            """
        )
    _own_only(DB_PATH)


def record(tracker_id: str, kind: str, source: str = "userscript") -> None:
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO events (tracker_id, kind, ts, source) VALUES (?,?,?,?)",
            (tracker_id, kind, now, source),
        )


def last_event(tracker_id: str, kind: str) -> tuple[datetime | None, str]:
    """Most recent event of a kind, as (when, source). Source matters: a
    'manual' auth is you asserting you logged in, which is worth far less
    evidence than the userscript observing it."""
    with db() as conn:
        row = conn.execute(
            "SELECT ts, source FROM events WHERE tracker_id=? AND kind=? "
            "ORDER BY ts DESC LIMIT 1",
            (tracker_id, kind),
        ).fetchone()
    if not row:
        return None, ""
    return datetime.fromisoformat(row["ts"]), (row["source"] or "")


def last_seen(tracker_id: str, kind: str):
    return last_event(tracker_id, kind)[0]


def drop_last_auth(tracker_id: str) -> dict | None:
    """Delete the most recent auth event. The events table is otherwise
    append-only; this is the single exception, and it exists because a
    mistaken 'seen' click (or a stale cached page fooling the heuristic)
    silently resets a countdown, which is exactly the failure this project
    is meant to prevent. Returns the removed row, or None."""
    with db() as conn:
        row = conn.execute(
            "SELECT id, ts, source FROM events WHERE tracker_id=? AND kind='auth' "
            "ORDER BY ts DESC LIMIT 1",
            (tracker_id,),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM events WHERE id=?", (row["id"],))
    return {"ts": row["ts"], "source": row["source"] or ""}


def notify_dests() -> list[dict]:
    """Every configured destination: [{id, name, url, enabled}, ...].

    Stored as JSON in `state` rather than its own table: it is a short list
    edited whole, and a table would need a migration for no gain.

    These are credentials, so they are in the database in plaintext, which puts
    them in every nightly backup. That is deliberate and documented rather than
    hidden: an Apprise URL has to be SENT to the provider, so it cannot be
    hashed, and encrypting it with a key the container reads unattended is
    obfuscation. It is also what the *arrs do with their own notification
    settings. See the backup note in the README.
    """
    try:
        out = json.loads(get_state("notify_dests", "") or "[]")
        return out if isinstance(out, list) else []
    except (ValueError, TypeError):
        # A corrupt blob must not take alerting down silently; an empty list
        # reads as "nothing configured", which the page announces loudly.
        print("[notify] destinations are unreadable, treating as none")
        return []


def save_notify_dests(dests: list[dict]) -> None:
    set_state("notify_dests", json.dumps(dests))


def notify_urls() -> list[str]:
    """Every destination that will actually receive: env first, then the panel.

    Deduplicated, because the same URL configured in both places would
    otherwise send twice, and a doubled push looks like a bug in the alerting
    rather than a duplicated config line.
    """
    out, seen = [], set()
    for url in NOTIFY_ENV + [d["url"] for d in notify_dests()
                             if d.get("enabled", True) and d.get("url")]:
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def scheme_name(url: str) -> str:
    """`discord://x/y` -> `Discord`. A fallback label when none was typed, so
    an unnamed row still says what it is rather than showing a bare mask."""
    raw = url.split("://", 1)[0] if "://" in url else "unknown"
    return {"ntfy": "ntfy", "ntfys": "ntfy"}.get(raw, raw.capitalize())


def mask_url(url: str) -> str:
    """`discord://... a3f1`. Scheme, plus a fingerprint that is not the URL.

    The tail of the real URL was the obvious thing to show, the way a card
    number shows its last four, and it is wrong here: for ntfy the topic IS the
    secret, and four characters of a short topic is a lot of it. The name field
    already tells two destinations apart, so the tail bought nothing and leaked
    something. A truncated hash disambiguates just as well and reveals none of
    the input.

    Same rule as `import_key`, which reaches the page only as a boolean. It
    matters more here because with sign-in off the page is open to anything
    that can reach the port, and one of these is enough to post into someone
    else's Discord channel.
    """
    scheme = url.split("://", 1)[0] if "://" in url else "?"
    return f"{scheme}://\u2026 {hashlib.sha256(url.encode()).hexdigest()[:4]}"


def note_activity(job: str, ok: bool, detail: str) -> None:
    """Record the outcome of an unattended job so the page can show it.

    The daily check, the backup, the alert and the heartbeat all run while
    nobody is watching, and each can fail in a way that leaves no trace on
    screen — a failed backup and a successful one look identical from the
    dashboard. `docker logs` has the detail, but needing a shell to answer
    "did last night work?" is the same gap that made the notification test
    useless when it silently sent nothing.
    """
    stamp = datetime.now(local_tz()).strftime("%Y-%m-%d %H:%M")
    set_state(f"act_{job}", json.dumps({"at": stamp, "ok": ok, "detail": detail}))


def read_activity(job: str) -> dict | None:
    raw = get_state(f"act_{job}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def get_state(k: str, default=None):
    with db() as conn:
        row = conn.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
    return row["v"] if row else default


def set_state(k: str, v: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO state (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, v),
        )


# ---------------------------------------------------------------- auth
#
# Modeled on the *arr apps rather than on an environment variable: a username
# and password configured IN THE APP, hashed at rest, changeable without
# touching compose or recreating the container. It rides on the `state` table,
# so it is covered by the nightly backup for free.
#
# IDLARR_TOKEN stays exactly what it was — the API key the userscript sends to
# /ping. It is read at boot from .env, so letting the UI rotate it would
# silently desync the two halves and 401 every ping. One credential for
# machines, one for humans, same split the *arrs use.
#
# This is OPTIONAL. With nothing configured the service behaves as 1.0 did.
# But "off" is a state we announce, never a silence: startup says so and the
# page carries a banner until you either set a password or dismiss it. Every
# serious bug in this project's history was invisible, and an open dashboard is
# not an obvious one — anyone who can reach the port can POST /api/mark and
# reset a countdown, which is precisely the failure this service exists to
# prevent, and the dashboard would read `ok` the whole time.

PBKDF2_ROUNDS = 600_000     # OWASP guidance for PBKDF2-HMAC-SHA256, 2023 onward
SESSION_DAYS = 30
LOCKOUT_AFTER = 5           # consecutive failures from one address...
LOCKOUT_SECONDS = 300       # ...costs this long a timeout
SESSION_COOKIE = "idlarr_session"

# ip -> [consecutive_failures, blocked_until_epoch]. In memory on purpose: a
# restart clearing it is fine, since the point is to make online guessing slow,
# not to keep a permanent ban list.
_login_fails: dict[str, list] = {}


def hash_password(pw: str) -> str:
    """Django-format PBKDF2. stdlib only: no new dependency for this."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ROUNDS)
    return (f"pbkdf2_sha256${PBKDF2_ROUNDS}$"
            f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}")


def verify_password(pw: str, encoded: str) -> bool:
    try:
        algo, rounds, salt_b64, hash_b64 = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                                 base64.b64decode(salt_b64), int(rounds))
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except (ValueError, TypeError, AttributeError):
        # A malformed hash means "no", never "yes".
        return False


def session_secret() -> bytes:
    """Stored, not derived from IDLARR_TOKEN. Two reasons: rotating the API
    token should not sign every browser out, and rotating THIS row is what
    makes 'sign out everywhere' a single write."""
    s = get_state("session_secret")
    if not s:
        s = secrets.token_hex(32)
        set_state("session_secret", s)
    return s.encode()


def make_session(user: str) -> str:
    payload = json.dumps({"u": user, "exp": int(time.time()) + SESSION_DAYS * 86400})
    raw = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig = hmac.new(session_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def read_session(cookie: str | None) -> str | None:
    """Returns the username, or None for anything not currently valid."""
    if not cookie or "." not in cookie:
        return None
    raw, _, sig = cookie.rpartition(".")
    expected = hmac.new(session_secret(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if int(data.get("exp", 0)) < time.time():
            return None
        return str(data.get("u")) or None
    except (ValueError, TypeError):
        return None


def auth_method() -> str:
    """'none' | 'forms' | 'basic'.

    A method recorded with no credentials behind it reads as OFF rather than as
    a locked door nobody holds the key to — otherwise a half-finished setup, or
    an IDLARR_RESET_AUTH boot, would leave the dashboard permanently 401.
    """
    m = get_state("auth_method", "none")
    return m if (m in ("forms", "basic") and get_state("auth_hash")) else "none"


def check_login(user: str, pw: str) -> bool:
    want_user = get_state("auth_user", "") or ""
    want_hash = get_state("auth_hash", "") or ""
    if not want_hash:
        return False
    # Evaluate both halves unconditionally so a wrong username and a wrong
    # password cost the same time and cannot be told apart from outside.
    ok_user = hmac.compare_digest(user.encode(), want_user.encode())
    ok_pass = verify_password(pw, want_hash)
    return ok_user and ok_pass


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def lockout_left(ip: str) -> int:
    """Seconds still to serve, 0 if not locked out."""
    rec = _login_fails.get(ip)
    return max(0, int(rec[1] - time.time())) if rec else 0


def note_login_failure(ip: str) -> None:
    rec = _login_fails.setdefault(ip, [0, 0.0])
    rec[0] += 1
    if rec[0] >= LOCKOUT_AFTER:
        rec[0] = 0
        rec[1] = time.time() + LOCKOUT_SECONDS


def authed(request: Request) -> bool:
    """True when the caller may use the UI and its API.

    Basic credentials are accepted under BOTH methods. The setting decides how
    an unauthenticated caller is challenged — a login page or the browser's own
    dialog — not which credentials are valid. That keeps curl and scripts
    working under `forms` without a login round-trip.
    """
    if auth_method() == "none":
        return True
    if read_session(request.cookies.get(SESSION_COOKIE)):
        return True
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        ip = client_ip(request)
        if lockout_left(ip):
            return False
        try:
            user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        if check_login(user, pw):
            _login_fails.pop(ip, None)
            return True
        note_login_failure(ip)
    return False


def api_key() -> str:
    """The read-only key, generated on first read like the *arrs mint theirs.

    Deliberately NOT `IDLARR_TOKEN`. That one writes events to /ping, so
    anything holding it can forge an auth event and silently reset a countdown,
    which is the exact failure this service exists to prevent. It is also baked
    into the generated userscript, making it the most-copied secret here.
    """
    k = get_state("api_key")
    if not k:
        k = secrets.token_hex(32)
        set_state("api_key", k)
    return k


def require_api_key(request: Request) -> None:
    """Read-only access for dashboards and monitors.

    Accepts `X-Api-Key` (the arr convention) or `?apikey=` (Jackett's, and what
    most dashboard widgets send). A valid key satisfies the route on its own,
    so a widget needs no session; a browser session still works, so the page
    itself keeps using these endpoints unchanged.

    Permanently GET only. This dependency is never attached to a route that
    writes, so a leaked dashboard key cannot mark a tracker seen.
    """
    sent = request.headers.get("x-api-key") or request.query_params.get("apikey") or ""
    if sent and hmac.compare_digest(sent, api_key()):
        return
    if authed(request):
        return
    # Say which header, because the most common failure is sending the wrong
    # secret: IDLARR_TOKEN looks interchangeable and is not.
    raise HTTPException(401, "read access needs a session or the read-only API "
                             "key, as X-Api-Key or ?apikey=. This is not "
                             "IDLARR_TOKEN.")


def require_ui(request: Request) -> None:
    """Route dependency. Passes straight through when auth is off."""
    if authed(request):
        return
    if auth_method() == "basic":
        raise HTTPException(401, "authentication required",
                            headers={"WWW-Authenticate": 'Basic realm="Idlarr"'})
    raise HTTPException(401, "authentication required")


def set_session_cookie(resp: Response, request: Request, user: str) -> None:
    # `secure` only when the request actually arrived over HTTPS. Setting it
    # unconditionally would break every plain-HTTP LAN install in the most
    # confusing way possible: the login succeeds, the browser silently drops
    # the cookie, and you land back on the login page with no error anywhere.
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    resp.set_cookie(SESSION_COOKIE, make_session(user), path="/",
                    max_age=SESSION_DAYS * 86400, httponly=True,
                    samesite="lax", secure=(proto == "https"))


# ---------------------------------------------------------------- logic

def elapsed_days(later: datetime, earlier: datetime) -> int:
    """Whole calendar days between two instants, in the configured timezone.

    NOT (later - earlier).days. That counts elapsed 24-hour periods, so an auth
    at 15:09 yesterday still reads as 0 days ago at 09:14 today — the row said
    "today" while the drawer's history said yesterday's date, which is how this
    was spotted. Worse than the cosmetic mismatch: under-counting elapsed days
    makes days_left larger, so every alert fires up to a day LATE. Calendar days
    round the other way, which is the safe direction here.
    """
    tz = local_tz()
    return (later.astimezone(tz).date() - earlier.astimezone(tz).date()).days


def evaluate(tracker: dict, now: datetime | None = None) -> dict:
    """Compute one tracker's status. Pure-ish: reads DB, decides nothing else."""
    now = now or datetime.now(timezone.utc)
    inactivity_days = int(tracker["inactivity_days"])
    auth, auth_source = last_event(tracker["id"], "auth")
    visit = last_seen(tracker["id"], "visit")

    out = {
        **tracker,
        "last_auth": auth,
        "last_visit": visit,
        "auth_source": auth_source,
        "days_since": None,
        "days_left": None,
        "state": "unknown",
        "priority": None,
        "reason": "",
    }

    # Immunity outranks everything, including expired: if pruning cannot touch
    # the account, no countdown is meaningful and no alert should ever fire.
    if tracker.get("immune"):
        if auth is not None:
            out["days_since"] = elapsed_days(now, auth)
        out.update(state="immune", priority=None,
                   reason=tracker.get("immune_reason") or "Exempt from inactivity pruning.")
        return out

    # Snoozed: vacation mode is on, or the account is parked. Alerts are
    # suppressed but the COUNTDOWN IS STILL SHOWN — you still want to know when
    # the account actually expires while deciding whether to extend. Unlike
    # `immune` this expires by itself, so forgetting to undo it cannot silently
    # stop watching an account you still care about.
    snooze = str(tracker.get("snooze_until") or "").strip()
    if snooze:
        try:
            until = date.fromisoformat(snooze)
        except ValueError:
            until = None
        if until and until >= now.astimezone(local_tz()).date():
            if auth is not None:
                out["days_since"] = elapsed_days(now, auth)
                out["days_left"] = inactivity_days - out["days_since"]
            out.update(state="snoozed", priority=None,
                       reason=f"Snoozed until {until.isoformat()}.")
            return out

    # Visited recently but not authenticated => session died. Independent of the limit.
    stale_session = (
        visit is not None
        and elapsed_days(now, visit) <= 3
        and (auth is None or elapsed_days(visit, auth) >= 3)
    )

    if auth is None:
        out["state"] = "unknown"
        out["reason"] = "No login ever recorded. Log in once to initialize, or mark it seen."
        return out

    days_since = elapsed_days(now, auth)
    days_left = inactivity_days - days_since
    out.update(days_since=days_since, days_left=days_left)

    alert_after = inactivity_days * float(tracker["alert_at_pct"])

    if stale_session:
        out.update(state="session", priority="high",
                   reason="Visited recently while logged out: session cookie is dead.")
    elif days_left <= 0:
        out.update(state="expired", priority="urgent",
                   reason=f"Inactivity limit passed {abs(days_left)}d ago. May already be disabled.")
    elif days_left <= 5:
        out.update(state="critical", priority="urgent",
                   reason=f"{days_left}d left. Log in today.")
    elif days_left <= 14:
        out.update(state="warn", priority="high", reason=f"{days_left}d left.")
    elif days_since >= alert_after:
        out.update(state="due", priority="default", reason=f"{days_left}d left.")
    else:
        out.update(state="ok", reason=f"{days_left}d left.")
    return out


def statuses(now: datetime | None = None) -> list[dict]:
    """Worst first. Uses the module-level RANK rather than a local copy: this
    had its own duplicate ordering dict, so adding a state updated the page and
    silently left server-side sorting behind — and a KeyError here takes the
    whole status page down."""
    rows = [evaluate(t, now) for t in load_config()["trackers"]]
    return sorted(rows, key=lambda r: (RANK[r["state"]],
                                       r["days_left"] if r["days_left"] is not None else 9999))


def build_notification(rows: list[dict]) -> dict | None:
    """Build the alert, or None if nothing is actionable.

    Provider-neutral: title, body and a priority name. Apprise turns that into
    whatever each service wants. Split out from sending so it can be tested
    without a network, and because getting it wrong is silent -- a malformed
    push looks exactly like a quiet day.
    """
    actionable = [r for r in rows if r["priority"]]
    if not actionable:
        return None

    worst = max(actionable, key=lambda r: ["default", "high", "urgent"].index(r["priority"]))
    body = "\n".join(f"{r['name']}: {r['reason']}" for r in actionable)
    # The link goes in the BODY, not a provider-specific click action: every
    # service renders a URL, but only some support a tap target.
    base = status_url()
    if base:
        body += f"\n\n{base}"

    return {
        "title": (f"{actionable[0]['name']} -- {actionable[0]['reason']}"
                  if len(actionable) == 1
                  else f"{len(actionable)} trackers need a login"),
        "body": body,
        "priority": worst["priority"],
    }


# Apprise NotifyType names. Kept as plain strings so the mapping is testable
# without the library installed, and resolved only at send time.
APPRISE_TYPE = {"default": "info", "high": "warning", "urgent": "failure"}


def apprise_type(priority: str) -> str:
    return APPRISE_TYPE.get(priority, "info")


def dispatch(title: str, body: str, priority: str) -> tuple[bool, str]:
    """Send to every enabled destination."""
    return dispatch_to(notify_urls(), title, body, priority)


def dispatch_to(urls: list[str], title: str, body: str,
                priority: str) -> tuple[bool, str]:
    """Send one message through Apprise. Returns (ok, reason).

    The reason matters: Apprise reports a refused push by returning False and
    logging why, so without capturing its log a bad token or a topic the server
    will not accept is indistinguishable from a successful send.

    Takes the URL list rather than reading it, so ONE destination can be tested
    on its own. Apprise returns a single boolean for the whole batch, so with
    three configured a refusal from any one of them reads as "notifications are
    broken" and names none of them.
    """
    try:
        import apprise
    except ImportError:
        return False, "apprise is not installed"

    seen: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                seen.append(record.getMessage())

    handler, logger = _Capture(), logging.getLogger("apprise")
    logger.addHandler(handler)
    try:
        ap = apprise.Apprise()
        for url in urls:
            if not ap.add(url):
                # Never print the URL itself: these contain credentials.
                seen.append(f"rejected a URL (scheme '{url.split('://')[0]}')")
        if not len(ap):
            return False, "no usable notification URLs"
        ok = bool(ap.notify(title=title, body=body,
                            notify_type=apprise_type(priority)))
    finally:
        logger.removeHandler(handler)
    return ok, ("" if ok else (seen[-1] if seen else "the provider refused it"))


async def maybe_alive_push(cfg: dict, now_local: datetime) -> bool:
    """Send a low-priority "still alive" push every `alive_push_days`.

    Nothing else watches the watchdog. If this container dies, the daily check
    and the nightly backup both stop and NEITHER absence is visible anywhere —
    silence reads exactly like "nothing is due". A heartbeat inverts that: once
    you expect one weekly, silence becomes a signal.

    Returns True if a push was sent. Deliberately runs after the daily check,
    so a day with a real alert does not also get a redundant heartbeat.

    The hour guard is "not BEFORE check_hour", not "at check_hour". Enabling
    this after the check hour therefore sends one on the next tick rather than
    waiting a day — which is worth keeping: an unproven notification path that
    stays silent for a week is exactly what this feature exists to prevent.
    Every subsequent push lands in the check-hour window.
    """
    every = int(cfg.get("alive_push_days", 0))
    if every <= 0 or now_local.hour < int(cfg.get("check_hour", 9)):
        return False

    last = get_state("last_alive_push", "") or ""
    if last:
        try:
            when = datetime.fromisoformat(last)
            if when.tzinfo is None:
                when = when.replace(tzinfo=now_local.tzinfo)
            if elapsed_days(now_local, when) < every:
                return False
        except ValueError:
            pass          # unparseable -> treat as never sent

    rows = statuses()
    worst = min((r for r in rows if r["days_left"] is not None),
                key=lambda r: r["days_left"], default=None)
    body = (f"Idlarr is running. Watching {len(rows)} tracker(s).\n"
            + (f"Closest: {worst['name']}, {worst['days_left']}d left."
               if worst else "No countdowns running yet."))
    ok, why = await asyncio.to_thread(dispatch, "Idlarr still alive", body, "default")
    print(f"[alive] {'sent' if ok else 'FAILED'}" + ("" if ok else f": {why}"))
    note_activity("heartbeat", ok, "sent" if ok else f"refused: {why}")
    if ok:
        set_state("last_alive_push", now_local.isoformat())
    return ok


async def notify(rows: list[dict]) -> None:
    payload = build_notification(rows)
    if payload is None:
        print("[notify] nothing due")
        note_activity("alert", True, "nothing due")
        return
    if not notify_urls():
        print("[notify] no destinations configured -- alert not sent")
        note_activity("alert", False, "no destinations configured")
        return
    try:
        # Apprise is synchronous; a slow provider must not stall the scheduler.
        ok, reason = await asyncio.to_thread(
            dispatch, payload["title"], payload["body"], payload["priority"])
        n = payload["body"].count("\n") + 1
        print(f"[notify] {'sent' if ok else 'FAILED'} ({n} line(s))"
              + ("" if ok else f": {reason}"))
        note_activity("alert", ok,
                      f"{n} tracker(s)" if ok else f"refused: {reason}")
    except Exception as exc:
        print(f"[notify] FAILED: {exc}")
        note_activity("alert", False, str(exc))


def backup_db(today: str) -> Path | None:
    """Snapshot the database to BACKUP_DIR/idlarr-YYYY-MM-DD.db.

    Uses SQLite's online backup API, so it is safe to run while the service is
    writing — no need to stop, lock, or copy the file underneath ourselves.
    Writes to a .tmp first and renames, so a crash mid-backup cannot leave a
    truncated file that looks like a good snapshot.

    This exists because the events table is the ONLY record of when each
    account was last seen. Losing it does not risk an account, but it resets
    every countdown to `unknown` until each tracker is re-bootstrapped.
    """
    keep = backup_keep()
    if keep <= 0:
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dest = BACKUP_DIR / f"idlarr-{today}.db"
    if dest.exists():
        return dest

    tmp = dest.with_suffix(".db.tmp")
    try:
        with sqlite3.connect(DB_PATH) as src, sqlite3.connect(tmp) as dst:
            src.backup(dst)
        _own_only(tmp)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()

    # ISO dates sort lexicographically, so oldest-first is just sorted().
    stale = sorted(BACKUP_DIR.glob("idlarr-*.db"))[:-keep]
    for old in stale:
        old.unlink()
    if stale:
        print(f"[backup] pruned {len(stale)} old snapshot(s)")
    return dest


def next_check() -> tuple[str, bool]:
    """When the daily check will next run, as (text, overdue).

    This RESTATES the gate in scheduler() below, which is why it lives against
    it rather than beside the page code that calls it. If that condition ever
    changes, this is the other copy, and `test_scheduler.py` compares the two
    across a sweep rather than trusting them to stay in step.

    It exists because the panel showed only what had already happened. Moving
    `check_hour` to 23:00 during a day whose check had already run at 09:00
    correctly produced no run that evening, and the panel gave no way to tell
    that from a stalled scheduler. Reported from the field 2026-08-06.

    `overdue` is the case worth having a flag for: the hour has passed, the day
    has not been checked, and the loop wakes every 10 minutes, so anything
    still saying this on a reload is genuinely stuck rather than merely waiting.
    """
    cfg = load_config()
    hour = int(cfg["check_hour"])
    now = datetime.now(local_tz())
    if get_state("last_check") == now.date().isoformat():
        return f"runs tomorrow at {hour:02d}:00", False
    if now.hour >= hour:
        return "due now", True
    return f"runs today at {hour:02d}:00", False


# Held for the duration of a check so the scheduler and a Run now cannot both
# run one: a click landing on the check hour would otherwise send the day's
# alerts twice. It guards genuine OVERLAP, not two clicks in a row — a check
# finishes in milliseconds, so sequential clicks simply both run. The button
# disabling itself and the page reloading on success is what covers that.
check_lock = asyncio.Lock()


async def run_daily_check(today: str, by_hand: bool = False) -> dict:
    """One daily pass: back up, evaluate every tracker, send whatever is due.

    Extracted from the `while True` in scheduler() for the same reason
    maybe_alive_push() was — an inline block inside a loop cannot be tested,
    and this one now has a second caller in POST /api/check.

    `last_check` is set here, by BOTH callers on purpose. A manual run really
    did evaluate the day, so letting the scheduled one fire again later would
    mean two rounds of pushes for one day. The panel says so, since "I ran it
    at noon so tonight is handled" is not something to have to infer.

    The backup runs before the alert and its failure is caught, because the
    alert is the point of the service and a full disk must not silence it.
    """
    print(f"[check] running for {today}" + (" (by hand)" if by_hand else ""))
    try:
        dest = backup_db(today)
        if dest:
            kb = dest.stat().st_size // 1024
            print(f"[backup] {dest} ({dest.stat().st_size} bytes)")
            note_activity("backup", True, f"{dest.name} ({kb} KB)")
        else:
            note_activity("backup", True, "disabled")
    except Exception as exc:
        print(f"[backup] FAILED: {exc}")
        note_activity("backup", False, str(exc))
    await notify(statuses())
    set_state("last_check", today)
    n = len(load_config()["trackers"])
    # Same distinction as auth_source on a tracker row: a run someone asked for
    # is different evidence from one that happened on its own, and a panel that
    # conflates them hides which.
    note_activity("check", True, f"{n} tracker(s)" + (", by hand" if by_hand else ""))
    return {"trackers": n}


async def scheduler() -> None:
    """Wake often, act once per local day. Survives restarts without drift."""
    while True:
        try:
            cfg = load_config()
            now_local = datetime.now(local_tz())
            today = now_local.date().isoformat()
            if now_local.hour >= cfg["check_hour"] and get_state("last_check") != today:
                if check_lock.locked():
                    print("[check] a manual run is in progress, skipping this tick")
                else:
                    async with check_lock:
                        await run_daily_check(today)

            # ---- still-alive heartbeat -------------------------------------
            # Its whole job is to make silence meaningful: if these stop
            # arriving, the container is down.
            await maybe_alive_push(cfg, now_local)

        except Exception as exc:
            print(f"[check] error: {exc}")
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The next two are what a first-time user actually hits. Both used to
    # surface as a raw traceback in a restart loop, which says nothing about
    # the fix. They still refuse to start on purpose: auto-creating either one
    # would turn a mis-mounted volume into a silently empty install that looks
    # like it is working.
    try:
        init_db()
    except sqlite3.OperationalError as exc:
        uid = os.getuid()
        raise RuntimeError(
            f"Cannot open the database at {DB_PATH}: {exc}\n"
            f"  The container runs as UID {uid}, and the directory you mounted at\n"
            f"  /data must be writable by it. From your compose directory:\n"
            f"      mkdir -p data && chown -R {uid} data\n"
            f"  If /data looks empty when it should not be, the mount is pointing\n"
            f"  somewhere other than you think."
        ) from exc

    # AFTER init_db(): this reads the destination list out of `state`, and on a
    # first boot that table does not exist until init_db() has run. Placed
    # above it, a fresh install died with "no such table: state" before ever
    # reaching the handler that explains a mis-mounted /data.
    # IDLARR_NOTIFY_URLS is deliberately NOT copied into the database. Someone
    # setting it is quite likely doing so to keep credentials out of /data, and
    # seeding would defeat exactly that.
    if not notify_urls():
        # Not fatal -- the status page still works -- but a watchdog that
        # cannot reach you is the exact failure this project exists to avoid,
        # and silence is indistinguishable from "nothing is due".
        print("[startup] WARNING: no notification destinations. Alerts will go "
              "nowhere. Add one in Settings, Notifications, or set "
              "IDLARR_NOTIFY_URLS.")

    secure_existing_backups()

    # A first boot with no IDLARR_TOKEN mints one and stores it, the way the
    # *arrs generate an API key. The original design refused to start instead,
    # because an EMPTY token once turned /ping into an open endpoint. That
    # failure is still closed — but by guaranteeing a token exists rather than
    # by refusing to run. get_token() reads env first, so setting IDLARR_TOKEN
    # still wins and nothing is silently overridden.
    if not get_state("idlarr_token"):
        if TOKEN:
            # Remember an explicitly-set token. Without this, an install whose
            # .env later goes missing generates a BRAND NEW token, and the
            # userscript already deployed in the browser starts 401ing on every
            # tracker — silently, which is the failure this service prevents.
            # Storing it means the env var disappearing is survivable.
            set_state("idlarr_token", TOKEN)
        else:
            set_state("idlarr_token", secrets.token_hex(32))
            print("[startup] No IDLARR_TOKEN set: generated one and saved it "
                  "to the database. Install the userscript from the status page "
                  "and it will carry the right token automatically.")

    # Belt and braces: if a token still cannot be obtained, refuse to start.
    # An open /ping is invisible; a container that will not boot is not.
    if not get_token():
        raise RuntimeError(
            "IDLARR_TOKEN is not set and could not be generated: refusing to "
            "start. An empty token would disable authentication entirely and "
            "/ping would accept anything. Set IDLARR_TOKEN in .env, or check "
            f"that {DB_PATH} is writable."
        )

    # Migrate IDLARR_BACKUP_KEEP into the config once, so an install that set
    # it keeps its retention. Only when the key is ABSENT — otherwise editing it
    # in the panel would be undone on every restart.
    if _ENV_BACKUP_KEEP:
        try:
            raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            if "backup_keep" not in (raw.get("defaults") or {}):
                save_default_field("backup_keep", int(_ENV_BACKUP_KEEP))
                print(f"[startup] Moved IDLARR_BACKUP_KEEP={_ENV_BACKUP_KEEP} into "
                      f"trackers.yml. It is editable in Settings now; the "
                      f"environment variable is no longer read and can be removed.")
        except (OSError, ValueError, KeyError) as exc:
            print(f"[startup] could not migrate IDLARR_BACKUP_KEEP: {exc}")

    if _ENV_STATUS_URL:
        try:
            raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}
            if "status_url" not in (raw.get("defaults") or {}):
                save_default_field("status_url", _ENV_STATUS_URL.rstrip("/"))
                print(f"[startup] Moved STATUS_URL into trackers.yml. It is "
                      f"editable in Settings now; the environment variable is "
                      f"no longer read and can be removed.")
        except (OSError, ValueError, KeyError) as exc:
            print(f"[startup] could not migrate STATUS_URL: {exc}")

    if RESET_AUTH:
        # Clearing session_secret as well is the point: a password reset that
        # left existing cookies valid would not lock out whoever you are
        # resetting because of.
        for key in ("auth_method", "auth_user", "auth_hash", "session_secret"):
            set_state(key, "")
        print("[startup] IDLARR_RESET_AUTH is set, UI authentication has been "
              "cleared and every existing session invalidated. Remove the "
              "variable, restart, then set a new login from the status page.")

    # Auto-create the config on first run. The original design refused,
    # because auto-creating turns a MIS-MOUNTED volume into a silently empty
    # install that looks like it is working. That risk is real and has not gone
    # away — but it was decided when hand-editing the file was the only way to
    # add a tracker, so an empty config was simply useless. Add and Import make
    # an empty config the legitimate first-run state.
    #
    # The mitigation is to make "empty because new" impossible to confuse with
    # "empty because your mount is wrong": we say the resolved path out loud,
    # every time, and the page carries a first-run banner while it is empty.
    if not CONFIG_PATH.exists():
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_PATH.write_text(default_config())
        except OSError as exc:
            raise RuntimeError(
                f"No tracker config at {CONFIG_PATH}, and it could not be "
                f"created: {exc}\n"
                f"  The container runs as UID {os.getuid()}; the directory you\n"
                f"  mounted at /config must be writable by it:\n"
                f"      mkdir -p config && chown -R {os.getuid()} config"
            ) from exc
        print(f"[startup] No config found: created an empty one at "
              f"{CONFIG_PATH}. If you expected trackers here, /config is "
              f"mounted somewhere other than you think.")
    try:
        cfg = load_config()
    except Exception as exc:
        raise RuntimeError(
            f"Could not read {CONFIG_PATH}: {exc}\n"
            f"  Check it is valid YAML and readable by UID {os.getuid()}."
        ) from exc
    print(f"[startup] {len(cfg['trackers'])} tracker(s) loaded, timezone {cfg['timezone']}")

    # Say it out loud. Optional does not mean quiet: an unauthenticated status
    # page looks identical to an authenticated one until somebody uses it.
    if auth_method() == "none":
        print("[startup] UI authentication is OFF. Anyone who can reach this "
              "port can read your tracker list, reset a countdown via "
              "/api/mark, and rewrite limits via /api/limit. Set a login from "
              "the status page, or keep the service on a trusted network.")
    else:
        print(f"[startup] UI authentication: {auth_method()} "
              f"(user {get_state('auth_user', '')!r})")

    task = asyncio.create_task(scheduler())
    yield
    task.cancel()


app = FastAPI(title="Idlarr", lifespan=lifespan)


def get_token() -> str:
    """The API token the userscript sends to /ping.

    Precedence: IDLARR_TOKEN from the environment (module-level TOKEN, which
    tests also monkeypatch) first, then the one generated into `state` on first
    boot. Env wins so an explicit setting is never silently overridden by a
    stale generated value.
    """
    return TOKEN or (get_state("idlarr_token", "") or "")


def require_token(auth: str | None) -> None:
    """Fails CLOSED. An earlier version returned early when TOKEN was empty,
    which meant a missing or misspelled env var silently turned /ping into an
    open endpoint — and looked identical to working. `lifespan` refuses to
    start without a token, so this branch should be unreachable; it exists so
    that if it ever is reached, the answer is 'no' rather than 'yes'."""
    token = get_token()
    if not token:
        raise HTTPException(status_code=500,
                            detail="server misconfigured: IDLARR_TOKEN is not set")
    # Constant-time. `!=` short-circuits on the first wrong byte, which is a
    # timing oracle for the one token that gates forging auth events — the core
    # threat this service exists to prevent. The userscript route already used
    # compare_digest; this makes /ping match it.
    if not hmac.compare_digest(auth or "", f"Bearer {token}"):
        raise HTTPException(status_code=401, detail="bad token")


# ---------------------------------------------------------------- routes

@app.post("/ping")
async def ping(payload: dict = Body(...), authorization: str | None = Header(default=None)):
    require_token(authorization)
    tid = str(payload.get("tracker", "")).strip().lower()
    kind = payload.get("kind", "auth")
    if kind not in ("auth", "visit"):
        raise HTTPException(400, "kind must be auth|visit")
    # The script reports which version it is running. Adding or importing a
    # tracker bumps the served version, and until the browser picks that up the
    # new site has no @match, so it never pings and sits at `unknown` looking
    # like broken detection. Recording this is what lets the page say so.
    seen = str(payload.get("v", "")).strip()[:32]
    if seen:
        set_state("script_seen", seen)
        set_state("script_seen_at", datetime.now(local_tz()).strftime("%Y-%m-%d %H:%M"))

    known = {t["id"] for t in load_config()["trackers"]}
    if tid not in known:
        # Reached by a REMOVED tracker as well as a typo: the browser's script
        # keeps its @match until the next update check. Name both, because
        # "add it to trackers.yml" is wrong advice for the removal case.
        raise HTTPException(
            404, f"unknown tracker '{tid}': removed from your config, or a "
                 f"typo. Nothing was recorded.")

    # Dedupe HERE, not in the browser. The userscript used to hold a 12h
    # cooldown in GM storage, which meant /api/unmark could delete an event the
    # client still believed it had reported — and that tracker went silent for
    # up to 12 hours with no indication. The database is the only thing that
    # knows what actually exists, so it owns the window. The client keeps a
    # short cooldown purely to avoid request spam while browsing.
    last, _ = last_event(tid, kind)
    if last is not None and (datetime.now(timezone.utc) - last) < timedelta(hours=DEDUPE_HOURS):
        return {"ok": True, "tracker": tid, "kind": kind, "deduped": True}

    record(tid, kind)
    return {"ok": True, "tracker": tid, "kind": kind, "deduped": False}


@app.post("/api/mark/{tracker_id}", dependencies=[Depends(require_ui)])
async def mark(tracker_id: str):
    """Bootstrap helper: assert you just logged in. Don't rely on this daily.

    Open when no login is configured, which is the 1.0 behavior. Worth
    knowing what that means before leaving it that way: a stranger POSTing here
    resets a countdown, after which the dashboard reads `ok` while the account
    ages out. That is the whole failure this service prevents, so on a shared
    network — university, shared housing — set a login.
    """
    known = {t["id"] for t in load_config()["trackers"]}
    if tracker_id not in known:
        raise HTTPException(404, "unknown tracker")
    record(tracker_id, "auth", source="manual")
    return Response(status_code=303, headers={"Location": "/"})


def clean(r: dict) -> dict:
    return {
        "id": r["id"], "name": r["name"], "state": r["state"],
        "days_since": r["days_since"], "days_left": r["days_left"],
        "inactivity_days": r["inactivity_days"], "verified": bool(r["verified"]),
        "immune": bool(r.get("immune")), "immune_reason": r.get("immune_reason", ""),
        "snooze_until": str(r.get("snooze_until") or ""),
        "reason": r["reason"], "auth_source": r.get("auth_source", ""),
        "software": r.get("software", ""), "url": r.get("url", ""),
        "notes": r.get("notes", ""), "alert_at_pct": float(r.get("alert_at_pct", 0.65)),
        "last_auth": r["last_auth"].isoformat() if r["last_auth"] else None,
        "last_visit": r["last_visit"].isoformat() if r["last_visit"] else None,
    }


@app.get("/api/status", dependencies=[Depends(require_api_key)])
async def api_status():
    return [clean(r) for r in statuses()]


@app.post("/api/limit/{tracker_id}", dependencies=[Depends(require_ui)])
async def set_limit(tracker_id: str, payload: dict = Body(...)):
    """Set inactivity_days and/or verified for one tracker, from the status page.

    Behind the UI login when one is configured. This one WRITES to
    trackers.yml, so with auth off the exposure costs config, not just a
    countdown reset. See Gotchas.
    """
    known = {t["id"] for t in load_config()["trackers"]}
    if tracker_id not in known:
        raise HTTPException(404, "unknown tracker")

    days = payload.get("inactivity_days")
    verified = payload.get("verified")
    immune = payload.get("immune")
    immune_reason = payload.get("immune_reason")
    notes = payload.get("notes")
    if notes is not None:
        notes = str(notes).strip()[:500]

    snooze = payload.get("snooze_until")
    if snooze is not None:
        snooze = str(snooze).strip()
        if snooze:
            try:
                until = date.fromisoformat(snooze)
            except ValueError:
                raise HTTPException(400, "snooze_until must be a date, YYYY-MM-DD")
            # A year is already far beyond any vacation mode. Longer than that
            # you want `immune`, which says so on the row instead of hiding a
            # countdown behind a date nobody will revisit.
            if until > date.today() + timedelta(days=365):
                raise HTTPException(400, "snooze cannot exceed a year: use immune instead")
            snooze = until.isoformat()

    if immune is not None:
        immune = bool(immune)
    if immune_reason is not None:
        immune_reason = str(immune_reason).strip()[:200]

    if days is not None:
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise HTTPException(400, "inactivity_days must be a whole number")
        if not 1 <= days <= 3650:
            raise HTTPException(400, "inactivity_days must be between 1 and 3650")
    if verified is not None:
        verified = bool(verified)
    pct = payload.get("alert_at_pct")
    if pct is not None:
        try:
            pct = float(pct)
        except (TypeError, ValueError):
            raise HTTPException(400, "alert_at_pct must be a number")
        if not 0.4 <= pct <= 0.95:
            raise HTTPException(400, "alert_at_pct must be between 0.4 and 0.95")

    if all(v is None for v in (days, verified, immune, immune_reason, notes,
                               snooze, pct)):
        raise HTTPException(400, "nothing to update")

    try:
        save_tracker_fields(tracker_id, days, verified, immune, immune_reason,
                            notes, snooze, pct)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")

    row = next(r for r in statuses() if r["id"] == tracker_id)
    return clean(row)


@app.get("/api/config", dependencies=[Depends(require_ui)])
async def download_config():
    """Download trackers.yml as it is on disk.

    Byte-for-byte, comments included — the per-tracker notes about seeding,
    user class and vacation mode are the part worth keeping, and a yaml dump
    would drop every one of them.
    """
    try:
        body = CONFIG_PATH.read_text()
    except OSError as exc:
        raise HTTPException(500, f"cannot read {CONFIG_PATH}: {exc}")
    stamp = datetime.now(local_tz()).strftime("%Y-%m-%d")
    return Response(
        body, media_type="text/yaml; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="trackers-{stamp}.yml"'})


@app.post("/api/config", dependencies=[Depends(require_ui)])
async def upload_config(payload: dict = Body(...)):
    """Replace trackers.yml wholesale, after validating it and backing up what
    is there now.

    This is the most destructive operation in the service: it overwrites the
    source of truth for every countdown. So it validates hard and refuses on
    anything it does not understand, rather than writing a file that parses but
    means something different.

    Removed trackers keep their events — `events` is append-only apart from
    drop_last_auth() — so restoring an older config restores its history rather
    than silently restarting those countdowns.
    """
    body = payload.get("yaml")
    if not isinstance(body, str) or not body.strip():
        raise HTTPException(400, "no config content")
    if len(body) > 1_000_000:
        raise HTTPException(400, "config is implausibly large")

    try:
        doc = yaml.safe_load(body)
    except yaml.YAMLError as exc:
        raise HTTPException(400, f"not valid YAML: {exc}")
    if not isinstance(doc, dict):
        raise HTTPException(400, "top level must be a mapping with a `trackers:` key")

    trackers = doc.get("trackers")
    if trackers is None:
        trackers = []
    if not isinstance(trackers, list):
        raise HTTPException(400, "`trackers:` must be a list")

    seen = set()
    for i, t in enumerate(trackers):
        if not isinstance(t, dict):
            raise HTTPException(400, f"tracker #{i + 1} is not a mapping")
        tid = str(t.get("id", "")).strip().lower()
        if not ID_OK.match(tid):
            raise HTTPException(400, f"tracker #{i + 1} has an unusable id: {tid!r}")
        if tid in seen:
            raise HTTPException(400, f"duplicate tracker id: {tid!r}")
        seen.add(tid)
        days = t.get("inactivity_days", (doc.get("defaults") or {}).get("inactivity_days", 30))
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{tid}: inactivity_days must be a whole number")
        if not 1 <= days <= 3650:
            raise HTTPException(400, f"{tid}: inactivity_days must be 1-3650")

    tz = (doc.get("defaults") or {}).get("timezone")
    if tz is not None:
        try:
            ZoneInfo(str(tz))
        except Exception:
            raise HTTPException(400, f"defaults.timezone: '{tz}' is not a known timezone")

    before = len(load_config()["trackers"])
    stamp = datetime.now(local_tz()).strftime("%Y%m%d-%H%M%S")
    backup = CONFIG_PATH.with_name(f"{CONFIG_PATH.name}.{stamp}.bak")
    try:
        with _write_lock:
            if CONFIG_PATH.exists():
                backup.write_text(CONFIG_PATH.read_text())
            tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
            tmp.write_text(body)
            os.replace(tmp, CONFIG_PATH)
        _cfg_cache["data"] = None
        after = len(load_config()["trackers"])
    except OSError as exc:
        raise HTTPException(500, f"cannot write {CONFIG_PATH}: {exc}")

    print(f"[config] replaced: {before} -> {after} tracker(s), "
          f"previous saved as {backup.name}")
    return {"before": before, "after": after, "backup": backup.name}


@app.post("/api/settings", dependencies=[Depends(require_ui)])
async def update_settings(payload: dict = Body(...)):
    """Edit the `defaults:` block from the settings panel.

    Each value is range-checked here rather than trusted: these drive day
    counting and alert timing, and a bad one is not a crash — it is a countdown
    that reads plausibly and fires at the wrong time.
    """
    changed = {}

    tz = payload.get("timezone")
    if tz is not None:
        try:
            ZoneInfo(str(tz))
        except Exception:
            raise HTTPException(400, f"'{tz}' is not a known timezone")
        changed["timezone"] = str(tz)

    hour = payload.get("check_hour")
    if hour is not None:
        try:
            hour = int(hour)
        except (TypeError, ValueError):
            raise HTTPException(400, "check_hour must be a whole number")
        if not 0 <= hour <= 23:
            raise HTTPException(400, "check_hour must be between 0 and 23")
        changed["check_hour"] = hour

    pct = payload.get("alert_at_pct")
    if pct is not None:
        try:
            pct = float(pct)
        except (TypeError, ValueError):
            raise HTTPException(400, "alert_at_pct must be a number")
        # Below 0.4 a 365-day tracker starts nagging 219 days early; above 0.95
        # `due` never fires before `warn` does. Both make the rung useless.
        if not 0.4 <= pct <= 0.95:
            raise HTTPException(400, "alert_at_pct must be between 0.4 and 0.95")
        changed["alert_at_pct"] = pct

    alive = payload.get("alive_push_days")
    if alive is not None:
        try:
            alive = int(alive)
        except (TypeError, ValueError):
            raise HTTPException(400, "alive_push_days must be a whole number")
        if not 0 <= alive <= 90:
            raise HTTPException(400, "alive_push_days must be between 0 and 90")
        changed["alive_push_days"] = alive

    keep = payload.get("backup_keep")
    if keep is not None:
        try:
            keep = int(keep)
        except (TypeError, ValueError):
            raise HTTPException(400, "backup_keep must be a whole number")
        if not 0 <= keep <= 365:
            raise HTTPException(400, "backup_keep must be between 0 and 365")
        changed["backup_keep"] = keep

    surl = payload.get("status_url")
    if surl is not None:
        surl = str(surl).strip()
        if surl and not re.match(r"^https?://", surl, re.I):
            raise HTTPException(400, "status_url must start with http:// or https://")
        changed["status_url"] = surl.rstrip("/")

    if not changed:
        raise HTTPException(400, "nothing to update")
    try:
        for key, value in changed.items():
            save_default_field(key, value)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")
    except OSError as exc:
        raise HTTPException(500, f"cannot write {CONFIG_PATH}: {exc}")

    cfg = load_config()
    return {k: cfg.get(k) for k in
            ("timezone", "check_hour", "alert_at_pct", "alive_push_days",
             "backup_keep", "status_url")}


@app.post("/api/tracker", dependencies=[Depends(require_ui)])
async def create_tracker(payload: dict = Body(...)):
    """Add a tracker from the status page.

    `inactivity_days` defaults to 30 and `verified` to false on purpose, the
    same fail-safe the shipped config shouts about: a limit you have not read
    off the tracker's own rules page is a guess, and a guess that is too HIGH
    is the one that loses the account.
    """
    name = str(payload.get("name", "")).strip()
    if not 1 <= len(name) <= 80:
        raise HTTPException(400, "name must be 1-80 characters")

    tid = str(payload.get("id", "")).strip().lower() or slugify(name)
    if not tid:
        # A name of nothing but punctuation slugifies to "". Saying "'' is not
        # a valid id" tells the user nothing about what to do next.
        raise HTTPException(
            400, f"could not derive an id from '{name}': enter one explicitly")
    if not ID_OK.match(tid):
        raise HTTPException(
            400, "id must be lowercase letters, digits, - or _ (max 40), "
                 f"'{tid}' is not usable as one")
    if tid in {t["id"] for t in load_config()["trackers"]}:
        raise HTTPException(409, f"'{tid}' already exists")

    url = str(payload.get("url", "")).strip()
    if url and not re.match(r"^https?://", url, re.I):
        raise HTTPException(400, "url must start with http:// or https://")

    days = payload.get("inactivity_days", 30)
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise HTTPException(400, "inactivity_days must be a whole number")
    if not 1 <= days <= 3650:
        raise HTTPException(400, "inactivity_days must be between 1 and 3650")

    host = str(payload.get("host", "")).strip().lower() or host_from_url(url)
    entry = {
        "id": tid, "name": name, "url": url, "host": host,
        "inactivity_days": days, "verified": bool(payload.get("verified")),
        "notes": str(payload.get("notes", "")).strip()[:500],
        "auth_sel": str(payload.get("auth_sel", "")).strip()[:200],
    }
    try:
        add_tracker(entry)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")

    row = next(r for r in statuses() if r["id"] == tid)
    return clean(row)


# --- importing from Prowlarr / Jackett ------------------------------------
#
# These talk to YOUR indexer manager, never to a tracker. The no-tracker-traffic
# rule is about requests that could get an account banned; Prowlarr on your own
# box is not one of those, and it already holds the exact list you would
# otherwise retype.
#
# What it imports is IDENTITY only — name and URL. Never inactivity_days:
# neither tool knows a tracker's inactivity policy, and a limit that arrives
# looking authoritative but is too high is the failure this project exists to
# prevent. Everything lands at 30 days, unverified, like any hand-added entry.

IMPORT_TIMEOUT = 10
PRIVATE = {"private", "semiprivate", "semi-private"}


def _worth_watching(item: dict, protocol: str) -> bool:
    """A public tracker needs no account, so there is nothing to keep alive.

    Usenet inverts the test rather than sharing it. Every usenet indexer worth
    watching sits behind an account, and Prowlarr does not reliably populate
    `privacy` for them, so requiring an explicit "private" there drops exactly
    the sites this import is meant to find, silently. Anything not explicitly
    public counts.
    """
    p = str(item.get("privacy", "")).lower().replace("_", "")
    return p != "public" if protocol == "usenet" else p in PRIVATE


def same_site(a: str, b: str) -> bool:
    """True when two hosts belong to the same tracker.

    Exact comparison is not enough. Prowlarr returns some indexers by their
    API host rather than their site — BroadcasTheNet as `api.broadcasthe.net`,
    for example — so a configured `broadcasthe.net` looks like a different
    tracker and gets imported again.
    That splits one account's history across two rows and leaves BOTH
    countdowns wrong, which is the failure this service exists to prevent.

    A subdomain relation in either direction is the same site here: the
    userscript matches `*.domain`, which already covers both.
    """
    if not a or not b:
        return False
    a, b = a.lower().strip("."), b.lower().strip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def browsable(url: str, host: str) -> tuple[str, str]:
    """Rewrite an API host to the site you would actually log in on.

    An `api.` host is not somewhere a browser session exists, so a row pointing
    at one would never record an auth event and its link would go nowhere
    useful — it would sit at `unknown` forever and read as broken detection.
    """
    if host.startswith("api."):
        return re.sub(r"(//)api\.", r"\1", url, count=1), host[4:]
    return url, host


def _fetch_json(url: str, headers: dict) -> list:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=IMPORT_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = ": check the API key" if exc.code in (401, 403) else ""
        raise ValueError(f"{url.split('?')[0]} returned {exc.code}{hint}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"could not reach {url.split('?')[0]}: {exc.reason}") from exc
    except TimeoutError as exc:
        # A READ timeout, which urlopen raises directly rather than wrapping in
        # URLError, and TimeoutError is an OSError sibling so nothing above
        # catches it. It escaped this function and then escaped the caller's
        # `except ValueError` too, so a Prowlarr that accepts the connection and
        # then never answers produced a 500 traceback instead of the message
        # written for exactly this case. IMPORT_TIMEOUT exists to make this
        # happen, so it is not a rare path.
        raise ValueError(f"{url.split('?')[0]} did not answer within "
                         f"{IMPORT_TIMEOUT}s") from exc
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{url.split('?')[0]} did not return JSON: {exc}") from exc


def prowlarr_indexers(base: str, api_key: str) -> list[dict]:
    data = _fetch_json(f"{base.rstrip('/')}/api/v1/indexer", {"X-Api-Key": api_key})
    out = []
    for item in data if isinstance(data, list) else []:
        # Usenet accounts lapse for inactivity the same way tracker accounts do,
        # and Prowlarr holds both. This used to drop everything non-torrent.
        protocol = str(item.get("protocol", "torrent")).lower()
        if protocol not in ("torrent", "usenet"):
            continue
        if not _worth_watching(item, protocol):
            continue
        urls = item.get("indexerUrls") or []
        url = urls[0] if urls else ""
        if not url:
            # Cardigann-defined indexers carry the address in `fields` instead.
            for field in item.get("fields") or []:
                if field.get("name") == "baseUrl" and field.get("value"):
                    url = str(field["value"])
                    break
        out.append({"name": str(item.get("name", "")).strip(), "url": url,
                    "protocol": protocol})
    return out


def jackett_indexers(base: str, api_key: str) -> list[dict]:
    data = _fetch_json(
        f"{base.rstrip('/')}/api/v2.0/indexers?configured=true&apikey={api_key}", {})
    out = []
    for item in data if isinstance(data, list) else []:
        if not item.get("configured", True):
            continue
        if str(item.get("type", "")).lower().replace("_", "") not in PRIVATE:
            continue
        # Jackett is torrent-only; it has no usenet concept to report.
        out.append({"name": str(item.get("name", "")).strip(),
                    "url": str(item.get("site_link", "")).strip(),
                    "protocol": "torrent"})
    return out


@app.post("/api/import", dependencies=[Depends(require_ui)])
async def import_indexers(payload: dict = Body(...)):
    """Preview or apply an import from Prowlarr or Jackett.

    Defaults to a PREVIEW. Writing seven trackers into someone's config on a
    button press, when the API key might point at the wrong instance, is not a
    thing to do without showing the list first.

    A working connection is remembered in the `state` table so a container
    recreate does not send you back to Prowlarr for the key again. It is stored
    in plaintext, on the same disk as everything else this service knows — see
    the Import section of the docs, and the Forget button beside it.
    """
    # Save on the import form applies the remember box on its own, without
    # running an import. Unticking the box does nothing until this is pressed:
    # a checkbox that destroys a stored credential the instant it is clicked
    # gives you no chance to change your mind, and no way to see what it did.
    if "set_remember" in payload:
        keep = bool(payload["set_remember"])
        set_state("import_remember", "1" if keep else "0")
        if not keep and get_state("import_key"):
            set_state("import_key", "")
            print("[import] forgot the saved API key at your request")
        return {"ok": True, "remembered": keep}

    source = str(payload.get("source", "")).strip().lower()
    if source not in ("prowlarr", "jackett"):
        raise HTTPException(400, "source must be prowlarr or jackett")
    base = str(payload.get("url", "")).strip()
    if not re.match(r"^https?://", base, re.I):
        raise HTTPException(400, "url must start with http:// or https://")

    # Absent means True, so a scripted caller written before this existed keeps
    # the behavior it was written against rather than silently losing its key.
    remember = bool(payload.get("remember", True))
    api_key = str(payload.get("api_key", "")).strip()
    if not api_key:
        # Blank means "reuse what is saved", but only for the same instance —
        # silently sending one service's key to another would be a leak.
        if (get_state("import_source", "") == source
                and get_state("import_url", "") == base):
            api_key = get_state("import_key", "") or ""
    if not api_key:
        raise HTTPException(400, "an API key is required")

    # Which protocols to take. Absent means both, so a scripted call or an
    # older client gets the wider set rather than silently the narrower one.
    raw = payload.get("protocols")
    wanted = ({"torrent", "usenet"} if raw is None
              else {str(p).lower() for p in raw} & {"torrent", "usenet"})
    if not wanted:
        raise HTTPException(400, "select torrent, usenet, or both")

    fetch = prowlarr_indexers if source == "prowlarr" else jackett_indexers
    try:
        found = await asyncio.to_thread(fetch, base, api_key)
    except ValueError as exc:
        # Log it as well as returning it. Only the browser saw this before, so
        # "the import failed" left nothing in the logs to look at — and the
        # person reporting it is rarely the person reading them.
        print(f"[import] {source} FAILED: {exc}")
        raise HTTPException(502, str(exc))

    # Only remember a connection that actually answered. Saving a key that
    # failed would make the blank-means-reuse path replay a bad credential.
    set_state("import_source", source)
    set_state("import_url", base)
    # The KEY is opt-out, unlike the source and the URL, which are not secrets.
    # Nothing here runs unattended: an import happens when a human clicks
    # Preview, with the form already open, so this credential is the one thing
    # in `state` that does not have to be there at all. Unlike a notification
    # URL, which fires at 23:00 with nobody watching, this can simply be
    # retyped. Default on, so an upgrade behaves exactly as it did.
    set_state("import_remember", "1" if remember else "0")
    if remember:
        set_state("import_key", api_key)

    known_ids = {t["id"] for t in load_config()["trackers"]}
    known_hosts = {t["host"] for t in load_config()["trackers"] if t.get("host")}

    candidates, seen = [], set()
    for item in found:
        if not item["name"]:
            continue
        if item.get("protocol", "torrent") not in wanted:
            continue
        tid = slugify(item["name"])
        url, host = browsable(item["url"], host_from_url(item["url"]))
        if not tid or tid in seen:
            continue
        seen.add(tid)
        # Match on host as well as id, and by SITE rather than exact string:
        # the same tracker under a different display name, or stored by its API
        # host, would otherwise be added twice and split its history.
        known = tid in known_ids or any(same_site(host, k) for k in known_hosts)
        why = "already configured" if known else "" if host else "no usable URL"
        candidates.append({"id": tid, "name": item["name"], "url": url,
                           "host": host, "skip": why,
                           "protocol": item.get("protocol", "torrent")})

    if not payload.get("apply"):
        return {"source": source, "found": len(found), "candidates": candidates}

    added, failed = [], []
    for c in candidates:
        if c["skip"]:
            continue
        try:
            add_tracker({"id": c["id"], "name": c["name"], "url": c["url"],
                         "host": c["host"], "inactivity_days": 30,
                         "verified": False, "notes": "", "auth_sel": ""})
            added.append(c["id"])
        except (KeyError, ValueError) as exc:
            failed.append({"id": c["id"], "error": str(exc)})
        except OSError as exc:
            # Read-only or wrongly-owned /config. Uncaught this became a bare
            # 500, which says nothing about the mount that caused it.
            failed.append({"id": c["id"],
                           "error": f"cannot write {CONFIG_PATH}: {exc}"})
    if failed:
        print(f"[import] {len(added)} added, {len(failed)} failed: "
              + "; ".join(f"{f['id']}: {f['error']}" for f in failed))
    return {"source": source, "added": added, "failed": failed,
            "skipped": [c["id"] for c in candidates if c["skip"]]}


@app.delete("/api/tracker/{tracker_id}", dependencies=[Depends(require_ui)])
async def delete_tracker(tracker_id: str):
    """Remove a tracker. Its auth history stays in the database: see
    remove_tracker() for why."""
    if tracker_id not in {t["id"] for t in load_config()["trackers"]}:
        raise HTTPException(404, "unknown tracker")
    try:
        remove_tracker(tracker_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")
    return {"removed": tracker_id, "trackers": len(load_config()["trackers"])}


@app.post("/api/unmark/{tracker_id}", dependencies=[Depends(require_ui)])
async def unmark(tracker_id: str):
    """Undo the most recent auth event: a misclicked 'seen', or an auth the
    heuristic recorded wrongly (e.g. a cached logged-in page while the site
    was actually down). Same posture as /api/mark."""
    known = {t["id"] for t in load_config()["trackers"]}
    if tracker_id not in known:
        raise HTTPException(404, "unknown tracker")
    removed = drop_last_auth(tracker_id)
    row = next(r for r in statuses() if r["id"] == tracker_id)
    return {"removed": removed, "row": clean(row)}


@app.get("/api/history/{tracker_id}", dependencies=[Depends(require_api_key)])
async def history(tracker_id: str, limit: int = 5):
    """Recent auth events for one tracker, newest first.

    Fetched when a row is expanded rather than bundled into /api/status —
    23 trackers x 5 events is a lot of payload nobody has asked to see yet.
    """
    known = {t["id"] for t in load_config()["trackers"]}
    if tracker_id not in known:
        raise HTTPException(404, "unknown tracker")
    with db() as conn:
        rows = conn.execute(
            "SELECT ts, source FROM events WHERE tracker_id=? AND kind='auth' "
            "ORDER BY ts DESC LIMIT ?",
            (tracker_id, max(1, min(int(limit), 25))),
        ).fetchall()
    # Emit the LOCAL calendar date, not the raw UTC timestamp. Slicing the ISO
    # string client-side gave the UTC date, which disagreed with the row's
    # "today"/"Nd ago" for anything logged in the evening.
    tz = local_tz()
    out = []
    for r in rows:
        when = datetime.fromisoformat(r["ts"]).astimezone(tz)
        out.append({"ts": r["ts"], "date": when.strftime("%Y-%m-%d"),
                    "time": when.strftime("%H:%M"), "source": r["source"] or ""})
    return out


@app.get("/api/summary", dependencies=[Depends(require_api_key)])
async def api_summary():
    """The documented, stable shape for dashboards and monitors.

    /api/status exists too and returns every field of every tracker, but its
    shape has changed repeatedly while the page was being built. Anything
    external should read THIS: it is a small, deliberate contract, and the
    point of it is that renaming a field on the status page cannot silently
    break somebody's widget.
    """
    rows = statuses()
    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    # Worst first is already the sort order, so the head of the list is the
    # tracker that needs attention soonest. `None` when there are no trackers.
    worst = rows[0] if rows else None
    # The soonest real deadline, ignoring anything that cannot expire.
    live = [r for r in rows
            if not r["immune"] and r["days_left"] is not None
            and r["state"] != "snoozed"]
    soonest = min(live, key=lambda r: r["days_left"]) if live else None

    return {
        "trackers": len(rows),
        "counts": {s: counts.get(s, 0) for s in RANK},
        "needs_attention": sum(counts.get(s, 0) for s in
                               ("expired", "critical", "warn", "due", "session")),
        "worst": None if worst is None else {
            "id": worst["id"], "name": worst["name"], "state": worst["state"],
            "days_left": worst["days_left"],
        },
        "soonest_deadline": None if soonest is None else {
            "id": soonest["id"], "name": soonest["name"],
            "days_left": soonest["days_left"],
        },
        "last_check": get_state("last_check", "") or None,
        "version": IDLARR_VERSION,
    }


@app.get("/healthz")
async def healthz():
    """Stays open on purpose. Open item 1 wants an uptime monitor pointed here,
    and a monitor that needs credentials is a monitor that will not get set up.
    It discloses a tracker count and nothing else."""
    return {"ok": True, "version": IDLARR_VERSION,
            "trackers": len(load_config()["trackers"])}


# ---------------------------------------------------------------- userscript
#
# Installing used to mean four careful hand-edits: the @match block, @connect,
# ENDPOINT/TOKEN, and the SITES array. Every one of them is something this
# service already knows, and each fails QUIETLY when wrong — a mismatched id
# 404s, a missing @connect is killed by tracker CSP, a wrong token 401s. So
# generate the script from the same config /ping validates against, and the
# whole class stops existing.
#
# The template is the committed idlarr.user.js read at runtime, NOT a second
# copy embedded here. Two copies of the detection heuristic would drift, and
# the heuristic is the part that took four sites and a debug helper to get
# right. Every substitution below is checked, so renaming one of these lines
# fails loudly instead of shipping a script with PUT_IDLARR_TOKEN_HERE in it.

USERSCRIPT_PATH = Path(os.environ.get(
    "IDLARR_USERSCRIPT", str(Path(__file__).resolve().parent / "idlarr.user.js")))
USERSCRIPT_BASE_VERSION = "1.1"


def _userscript_payload(base: str) -> tuple[str, str, str, int]:
    """The @match block, the SITES array, the key those hash into, and the count.

    Factored out so that "what the script would contain right now" has ONE
    definition. The staleness check needs it too, and two copies of this would
    drift the first time a field was added to SITES.
    """
    # A tracker with no host cannot be matched, so it is left out entirely
    # rather than emitted as a broken entry. The route reports the count.
    trackers = [t for t in load_config()["trackers"] if t.get("host")]
    matches = "\n".join(f"// @match        *://*.{t['host']}/*" for t in trackers)
    sites = "\n".join(
        "    {{ host: {}, id: {}{} }},".format(
            json.dumps(t["host"]), json.dumps(t["id"]),
            f", authSel: {json.dumps(t['auth_sel'])}" if t.get("auth_sel") else "")
        for t in trackers)
    return matches, sites, "\n".join([base, matches, sites]), len(trackers)


def userscript_version(payload: str) -> str:
    """A version that only moves when the generated content actually changes.

    Violentmonkey decides whether to update by comparing versions as ORDERED
    values, so a content hash cannot be the version — it would not increase.
    Keep a counter in `state` and bump it only when the hash changes: adding a
    tracker always triggers an update, and refetching an unchanged script
    never does.
    """
    digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
    if get_state("userscript_hash") != digest:
        set_state("userscript_rev", str(int(get_state("userscript_rev", "0") or 0) + 1))
        set_state("userscript_hash", digest)
    return f"{USERSCRIPT_BASE_VERSION}.{get_state('userscript_rev', '1')}"


def userscript_stale() -> tuple[str, str, str] | None:
    """(installed, why, dismiss_key) when the browser's script is behind.

    Three ways it can be behind, and the third is the one that matters on an
    upgrade:

      1. a browser reported a rev lower than the last one served, or
      2. the config has moved past the script that was last generated, so
         whatever anyone holds cannot cover it.

    The second does NOT require anyone to have reported a version. It used to,
    and that made the whole warning useless exactly when it was first needed:
    a script installed before version reporting existed sends no version, so
    `script_seen` is empty, so adding a tracker warned nobody. The feature could
    not help until you had already done the thing it exists to remind you about.

    Returns None when no script has ever been generated: nothing can be behind
    a thing that does not exist, and a first-run install must not be told to
    reinstall what it has not got.
    """
    rev = get_state("userscript_rev", "0") or "0"
    if rev == "0":
        return None

    installed = get_state("script_seen", "") or ""

    changed, digest = False, ""
    base = status_url()
    if base:
        # Same payload the generator hashes, from the same helper, so this
        # cannot disagree with what a fetch would produce.
        _, _, payload, _ = _userscript_payload(base.rstrip("/"))
        digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
        changed = get_state("userscript_hash", "") != digest

    behind = False
    if installed:
        try:
            behind = int(installed.rsplit(".", 1)[-1]) < int(rev)
        except ValueError:
            installed = ""     # unparseable: unknown, rather than a wrong claim

    if not (behind or changed):
        return None
    why = ("your tracker list has changed since it was generated" if changed
           else f"{USERSCRIPT_BASE_VERSION}.{rev} is being served")
    # Keyed on the CONFIG when the config is what moved, so dismissing after
    # adding one tracker does not stay dismissed after adding the next.
    return installed, why, (digest if changed else rev)


def userscript_version_peek() -> str:
    """What the last render produced, read-only.

    Deliberately does NOT bump the counter: painting the status page must never
    invalidate the script already installed in someone's browser.
    """
    rev = get_state("userscript_rev", "0") or "0"
    return f"{USERSCRIPT_BASE_VERSION}.{rev}" if rev != "0" else "not served yet"


def render_userscript(base_url: str) -> str:
    """Fill the committed template from live config. Raises on anything unfilled."""
    try:
        src = USERSCRIPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read the userscript template at "
                           f"{USERSCRIPT_PATH}: {exc}") from exc

    base = base_url.rstrip("/")
    connect_host = host_from_url(base)
    matches, sites, payload, n_trackers = _userscript_payload(base)

    version = userscript_version(payload)

    # @updateURL/@downloadURL point back here, so adding a tracker on the
    # status page reaches the browser on Violentmonkey's next update check
    # instead of needing a reinstall. The token has to ride in the URL: that
    # fetch carries no session cookie.
    script_url = f"{base}/idlarr.user.js?token={get_token()}"
    meta_extra = (f"// @updateURL   {script_url}\n"
                  f"// @downloadURL {script_url}\n"
                  f"// @connect      {connect_host}")

    rules = [
        ("match block", r"(?m)^// @match .*(?:\n// @match .*)*",
         matches or "// @match        *://idlarr.invalid/*"),
        ("connect line", r"(?m)^// @connect .*", meta_extra),
        ("version line", r"(?m)^// @version .*", f"// @version      {version}"),
        ("endpoint", r"(?m)^  const ENDPOINT = .*$",
         f"  const ENDPOINT = {json.dumps(base + '/ping')};"),
        ("token", r"(?m)^  const TOKEN    = .*$",
         f"  const TOKEN    = {json.dumps(get_token())};"),
        ("sites array", r"  const SITES = \[.*?\n  \];",
         "  const SITES = [\n" + sites + "\n  ];"),
    ]
    out = src
    for label, pattern, repl in rules:
        out, n = re.subn(pattern, lambda _m, r=repl: r, out,
                         count=1, flags=re.S if label == "sites array" else 0)
        if n != 1:
            raise RuntimeError(
                f"userscript template no longer contains the {label}, "
                f"idlarr.user.js and render_userscript() have drifted apart")

    # Cosmetic, and deliberately NOT drift-checked: these only make the served
    # file honest about being generated. A wording change in the template
    # should not take the endpoint down.
    out = out.replace(
        "// ---- one @match per tracker; add both here and in SITES below ----",
        "// ---- @match lines, generated from trackers.yml ----", 1)
    # No timestamp in here on purpose: it would make every download differ,
    # and the whole point of the version counter is that an unchanged script
    # stays byte-identical.
    banner = (
        "\n// ---------------------------------------------------------------\n"
        f"// GENERATED by Idlarr from trackers.yml, {n_trackers} tracker(s).\n"
        "// Do not edit: the next auto-update overwrites this file. Add or\n"
        "// change trackers on the status page instead, and the browser picks\n"
        "// it up on Violentmonkey's next update check.\n"
        "// ---------------------------------------------------------------")
    return out.replace("// ==/UserScript==", "// ==/UserScript==" + banner, 1)


@app.get("/idlarr.user.js")
async def userscript(request: Request, token: str = ""):
    """Serve the userscript, generated from live config.

    Reachable with either the API token in the query string or a UI session.
    The token has to be accepted because Violentmonkey's update check sends no
    cookies; and the served script necessarily CONTAINS the token, so this is
    not a widening — with no login configured, /api/mark already grants a
    stranger strictly more than the token does.
    """
    if not (hmac.compare_digest(token, get_token()) or authed(request)):
        raise HTTPException(401, "pass ?token=<IDLARR_TOKEN> or sign in first")
    if not status_url():
        raise HTTPException(
            500,
            "No status page URL is set, so the generated script would have "
            "no endpoint to report to. Set it in Settings -> General to the "
            "URL you reach this page on.")
    try:
        body = render_userscript(status_url())
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))
    return Response(body, media_type="text/javascript; charset=utf-8")


# ---------------------------------------------------------------- auth routes

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Idlarr - Sign in</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,800&family=Martian+Mono:wght@400;500&family=Familjen+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
<style>
 :root{--bg:#0a0e0d;--head:#0f1614;--line:#1d2a26;--line2:#284039;--fg:#eaf6f2;
   --dim:#93aaa4;--accent:#2fe6a6;--bad:#ff6b5e;
   --disp:'Bricolage Grotesque',system-ui,sans-serif;
   --mono:'Martian Mono',ui-monospace,monospace;
   --body:'Familjen Grotesk',system-ui,sans-serif}
 *{box-sizing:border-box}
 /* The centring and the glow go on BODY ONLY. Applied to `html` as well, html
    became a flex container, which made body a flex ITEM -- so body shrank to
    the width of the form and painted its own copy of the gradient inside that
    narrow box. It showed as a lighter vertical band down the middle of the
    page, the exact width of the sign-in card. */
 html{height:100%}
 body{margin:0;min-height:100%;background:var(--bg);color:var(--fg);
   font-family:var(--body);font-size:14px;display:flex;
   -webkit-font-smoothing:antialiased;
   background-image:radial-gradient(90% 60% at 50% 0%,rgba(47,230,166,.07),transparent 60%);
   align-items:center;justify-content:center}
 form{background:var(--head);border:1px solid var(--line2);border-radius:14px;
   padding:28px;width:320px}
 h1{font-family:var(--disp);font-size:23px;font-weight:800;letter-spacing:-.03em;
   margin:0 0 22px}
 h1 b{color:var(--accent);font-weight:800}
 /* Body face, like every other uppercase label in the app. Mono is for
    numerals and machine data. */
 label{display:block;font-family:var(--body);font-weight:600;color:var(--dim);font-size:11px;
   letter-spacing:.13em;text-transform:uppercase;margin:0 0 6px}
 input{width:100%;background:var(--bg);border:1px solid var(--line2);border-radius:8px;
   color:var(--fg);padding:9px 11px;font-family:var(--mono);font-weight:500;
   font-size:12.5px;margin-bottom:14px}
 input:focus{outline:none;border-color:var(--accent)}
 /* Same metrics as the status page's + Add tracker button. */
 button{width:100%;height:40px;background:var(--accent);border:0;border-radius:8px;
   color:#04120d;font-family:var(--mono);font-weight:600;font-size:10px;
   letter-spacing:.11em;text-transform:uppercase;cursor:pointer;transition:filter .15s}
 button:hover{filter:brightness(1.12)}
 .err{color:var(--bad);font-size:12px;min-height:16px;margin:10px 0 0;text-align:center}
</style></head><body>
<form id="f" autocomplete="on">
  <h1>idl<b>a</b>rr</h1>
  <label for="u">username</label><input id="u" name="username" autocomplete="username" autofocus>
  <label for="p">password</label>
  <input id="p" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
  <p class="err" id="e"></p>
</form>
<script>
document.getElementById('f').addEventListener('submit',async ev=>{
  ev.preventDefault();
  const e=document.getElementById('e'); e.textContent='';
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('u').value,
                         password:document.getElementById('p').value})});
  const d=await r.json().catch(()=>({}));
  if(r.ok){location.href='/';} else {e.textContent=d.detail||'sign in failed';}
});
</script></body></html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if auth_method() == "none" or authed(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(LOGIN_PAGE)


@app.post("/login")
async def login(request: Request, payload: dict = Body(...)):
    ip = client_ip(request)
    left = lockout_left(ip)
    if left:
        # 429, not 401: the answer here is "not yet", and a client that cannot
        # tell those apart will happily keep guessing.
        raise HTTPException(429, f"too many attempts, try again in {left}s")
    if auth_method() == "none":
        raise HTTPException(400, "no login is configured")

    user = str(payload.get("username", ""))
    pw = str(payload.get("password", ""))
    if not check_login(user, pw):
        note_login_failure(ip)
        raise HTTPException(401, "wrong username or password")

    _login_fails.pop(ip, None)
    resp = Response(content=json.dumps({"ok": True}), media_type="application/json")
    set_session_cookie(resp, request, user)
    return resp


@app.post("/logout")
async def logout():
    resp = Response(content=json.dumps({"ok": True}), media_type="application/json")
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/auth", dependencies=[Depends(require_ui)])
async def auth_status():
    """Never returns the hash, and there is no endpoint that does."""
    return {"method": auth_method(), "user": get_state("auth_user", "") or ""}


@app.post("/api/auth", dependencies=[Depends(require_ui)])
async def auth_configure(request: Request, payload: dict = Body(...)):
    """Set, change, or remove the UI login.

    While nothing is configured this is open — the same first-run window an
    *arr has, and the reason to do setup before putting the box on a shared
    network. Once configured, changing anything needs the current password, so
    a borrowed session alone cannot lock you out of your own dashboard.
    """
    method = str(payload.get("method", "")).strip().lower()
    if method not in ("none", "forms", "basic"):
        raise HTTPException(400, "method must be none, forms, or basic")

    already = bool(get_state("auth_hash"))
    if already and not check_login(get_state("auth_user", "") or "",
                                   str(payload.get("current_password", ""))):
        raise HTTPException(403, "current password is wrong")

    if method == "none":
        for key in ("auth_method", "auth_user", "auth_hash"):
            set_state(key, "")
        # Rotate so sessions minted under the old password die with it.
        set_state("session_secret", secrets.token_hex(32))
        return {"method": "none", "user": ""}

    user = str(payload.get("username", "")).strip()
    pw = str(payload.get("password", ""))
    if not 1 <= len(user) <= 64:
        raise HTTPException(400, "username must be 1-64 characters")
    if ":" in user:
        # HTTP Basic splits on the first colon, so a colon in the username
        # would authenticate under `forms` and fail under `basic`.
        raise HTTPException(400, "username cannot contain a colon")
    if len(pw) < 8:
        raise HTTPException(400, "password must be at least 8 characters")

    set_state("auth_user", user)
    set_state("auth_hash", hash_password(pw))
    set_state("auth_method", method)
    # Changing credentials signs every other device out. The caller gets a
    # fresh cookie in the same response so they are not signed out by their
    # own password change.
    set_state("session_secret", secrets.token_hex(32))
    resp = Response(content=json.dumps({"method": method, "user": user}),
                    media_type="application/json")
    set_session_cookie(resp, request, user)
    return resp


@app.post("/api/apikey", dependencies=[Depends(require_ui)])
async def regenerate_api_key():
    """Mint a new read-only key. Behind require_ui, never the key itself: a
    leaked key must not be able to rotate itself and lock you out of noticing.
    The old value stops working the moment this returns."""
    k = secrets.token_hex(32)
    set_state("api_key", k)
    print("[api] read-only API key regenerated")
    return {"api_key": k}


@app.post("/api/check", dependencies=[Depends(require_ui)])
async def api_check():
    """Run the daily check now, rather than waiting for check_hour.

    Two cases this answers. A check hour moved later in a day whose check has
    already run does not fire again that day, which is correct and looks like a
    stalled scheduler. And a container down across a late check hour skips the
    day entirely: the gate is `hour >= check_hour`, so at 00:10 with check_hour
    23 it will not catch up until 23:00 tomorrow.

    It really does run the check, alerts included. A button that evaluated but
    did not send would repeat the mistake /api/test-notify was built to fix.
    """
    if check_lock.locked():
        raise HTTPException(409, "a check is already running")
    async with check_lock:
        today = datetime.now(local_tz()).date().isoformat()
        result = await run_daily_check(today, by_hand=True)
    return {"ok": True, **result, "ran_at": read_activity("check") or {}}


def _valid_apprise(url: str) -> str:
    """Return an error string, or "" if Apprise will take it.

    Checked at ADD time. Left until send time, a typo shows up as a missed
    alert on the night something was actually due, which is the failure this
    whole service exists to prevent.
    """
    if "://" not in url:
        return "that does not look like an Apprise URL (no scheme)"
    try:
        import apprise
    except ImportError:
        return ""          # cannot validate; let the send report it instead
    try:
        if not apprise.Apprise().add(url):
            # Never echo the URL: it carries a credential.
            return (f"Apprise did not accept a '{url.split('://')[0]}://' URL. "
                    f"Check the scheme and the fields after it.")
    except Exception as exc:
        return f"Apprise could not parse it: {exc}"
    return ""


@app.post("/api/notify", dependencies=[Depends(require_ui)])
async def add_notify_dest(payload: dict = Body(...)):
    url = str(payload.get("url", "")).strip()
    name = str(payload.get("name", "")).strip()[:40]
    if not url:
        raise HTTPException(400, "an Apprise URL is required")
    bad = _valid_apprise(url)
    if bad:
        raise HTTPException(400, bad)
    dests = notify_dests()
    if any(d.get("url") == url for d in dests):
        raise HTTPException(400, "that destination is already configured")
    dests.append({"id": secrets.token_hex(4), "name": name, "url": url,
                  "enabled": True})
    save_notify_dests(dests)
    print(f"[notify] added a {url.split('://')[0]} destination")
    return {"ok": True, "id": dests[-1]["id"]}


@app.post("/api/notify/{dest_id}", dependencies=[Depends(require_ui)])
async def edit_notify_dest(dest_id: str, payload: dict = Body(...)):
    """A BLANK url means keep the stored one, the same rule the import key
    uses. The page never renders a URL back, so without this you could not
    rename a destination or mute it without retyping a credential you cannot
    read."""
    dests = notify_dests()
    for d in dests:
        if d.get("id") != dest_id:
            continue
        if "name" in payload:
            d["name"] = str(payload["name"]).strip()[:40]
        if "enabled" in payload:
            d["enabled"] = bool(payload["enabled"])
        url = str(payload.get("url", "")).strip()
        if url:
            bad = _valid_apprise(url)
            if bad:
                raise HTTPException(400, bad)
            d["url"] = url
        save_notify_dests(dests)
        return {"ok": True}
    raise HTTPException(404, "no such destination")


@app.delete("/api/notify/{dest_id}", dependencies=[Depends(require_ui)])
async def remove_notify_dest(dest_id: str):
    dests = notify_dests()
    kept = [d for d in dests if d.get("id") != dest_id]
    if len(kept) == len(dests):
        raise HTTPException(404, "no such destination")
    save_notify_dests(kept)
    print("[notify] removed a destination")
    return {"ok": True}


@app.post("/api/notify/{dest_id}/test", dependencies=[Depends(require_ui)])
async def test_one_notify_dest(dest_id: str):
    """Sends through ONE destination, so a failure names the one that failed.

    The all-at-once test cannot: Apprise reports a single boolean for the whole
    batch, so with three destinations configured a refusal from any one of them
    reads as "notifications are broken".
    """
    for d in notify_dests():
        if d.get("id") == dest_id:
            ok, reason = await asyncio.to_thread(
                dispatch_to, [d["url"]],
                "Idlarr test", "If you can read this, this destination works.",
                "default")
            if not ok:
                raise HTTPException(502, f"not accepted: {reason}")
            return {"ok": True}
    raise HTTPException(404, "no such destination")


@app.post("/api/test-notify")
async def test_notify(request: Request,
                      authorization: str | None = Header(default=None)):
    """Send a real test message. Bearer token OR a UI session.

    It used to run the daily check, which sends NOTHING when nothing is due —
    so on a healthy install the test quietly succeeded without notifying, and
    could not tell "your alerts work" from "your alerts are broken". A test
    that passes when the thing under test never ran is worse than no test.
    This always sends, and returns the provider's own reason for a refusal
    instead of swallowing it.
    """
    tok = get_token()
    if not (tok and hmac.compare_digest(authorization or "", f"Bearer {tok}")) \
            and not authed(request):
        raise HTTPException(401, "bad token")
    if not notify_urls():
        raise HTTPException(400, "no notification destinations are configured, so "
                                 "alerts have nowhere to go. Add one below, or "
                                 "set IDLARR_NOTIFY_URLS in .env.")

    when = datetime.now(local_tz()).strftime("%d %b %Y %H:%M %Z")
    body = (f"Test from Idlarr at {when}.\n"
            f"Watching {len(load_config()['trackers'])} tracker(s). "
            f"If you can read this, alerts will reach you.")
    ok, reason = await asyncio.to_thread(dispatch, "Idlarr test", body, "default")
    if not ok:
        print(f"[notify] test FAILED: {reason}")
        raise HTTPException(502, f"not accepted: {reason}")
    print("[notify] test sent")
    return {"ok": True, "destinations": len(notify_urls())}


# ---------------------------------------------------------------- view

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Idlarr - Account Activity Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Martian+Mono:wght@400;500;600;700&family=Familjen+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e0d;--head:#0f1614;--drawer:#131d1a;--line:#1d2a26;--line2:#284039;
    --fg:#eaf6f2;--dim:#93aaa4;--dim2:#c2d5d0;
    --ok:#2fe6a6;--due:#ffe066;--warn:#ffab45;--critical:#ff6b5e;--expired:#ff4d7d;
    --immune:#8f9bd6;--session:#4fd3ff;--unknown:#4b5f5a;--accent:#2fe6a6;
    --snoozed:#b58be0;
    --sig:#2fe6a6;--sigdim:#1c6d54;
    /* Three faces, three jobs: names carry weight, numbers stay tabular, and
       everything else has to read at 9px. Mixing them was the point. */
    --disp:'Bricolage Grotesque',system-ui,sans-serif;
    --mono:'Martian Mono',ui-monospace,monospace;
    --body:'Familjen Grotesk',system-ui,sans-serif;
  }
  *{box-sizing:border-box}
  /* The glow belongs to ONE element. On html and body both it was painted
     twice, at double the intended opacity. */
  html{background:var(--bg)}
  body{margin:0;background:var(--bg);color:var(--fg);
    font-family:var(--body);font-size:14px;-webkit-font-smoothing:antialiased;
    -moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility;
    background-image:radial-gradient(120% 80% at 50% -10%,rgba(47,230,166,.06),transparent 60%);
    background-attachment:fixed}
  .wrap{max-width:1160px;margin:0 auto;padding:28px 26px 90px}
  /* One column template drives the header labels and every row, at every
     width. Two layout models (table on desktop, grid on mobile) is what let
     the two drift apart. */
  :root{--cols:14px 232px 92px 104px 1fr}

  /* Every band on the page is separated the same way: 22px, a hairline,
     22px. Header / counts / table / footer. */
  .bar{display:flex;align-items:center;gap:20px;padding-bottom:22px;
    border-bottom:1px solid var(--line);flex-wrap:wrap}
  /* line-height:1 keeps a 36px wordmark inside the 38px button row, so the
     header does not grow. Without it the line box is ~43px and everything
     shifts down. */
  h1{font-family:var(--disp);font-size:36px;font-weight:800;letter-spacing:-.03em;
    margin:0;line-height:1}
  h1 b{color:var(--sig);font-weight:800}
  /* Decorative. Generated in JS: jittered, but with no distinctive feature
     anywhere, because a landmark is what lets the eye spot the loop. */
  /* Owns the whole middle of the header now that the clock is gone. The fade
     is tightened to 4%: across a much wider strip an 8% ramp ate a visible
     chunk of trace at each end. */
  .pulse{flex:1;min-width:120px;height:38px;position:relative;overflow:hidden;
    -webkit-mask-image:linear-gradient(90deg,transparent,#000 4%,#000 96%,transparent);
    mask-image:linear-gradient(90deg,transparent,#000 4%,#000 96%,transparent)}
  /* 600%, not 200%: one tile is three screen-widths of trace, so the loop
     runs 18 beats before it repeats while only ~6 are on screen at once.
     translateX(-50%) is still exactly one tile. */
  .pulse svg{position:absolute;left:0;top:0;height:38px;width:600%;animation:slide 18s linear infinite}
  @keyframes slide{to{transform:translateX(-50%)}}
  @media(prefers-reduced-motion:reduce){.pulse svg{animation:none}}
  @media(max-width:760px){.pulse{display:none}}

  .legend{display:grid;grid-template-columns:repeat(10,1fr);gap:1px;margin:22px 0 0;
    background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .legend div{min-width:0;padding:13px 14px;background:var(--head)}
  .legend .tot{--c:var(--fg);background:var(--drawer)}
  /* A healthy install is nine zeros and one number. At full strength a red 0
     under EXPIRED reads as an alarm; dimmed, color only appears where
     something actually is in that state. */
  .legend .zero{opacity:.34}
  .legend b{display:block;font-family:var(--mono);font-size:22px;font-weight:700;
    color:var(--c);line-height:1;font-variant-numeric:tabular-nums}
  /* Labels take the body face; Martian Mono keeps the numerals. Its slab
     uppercase at .14em turned NOTIFICATIONS and LOGGED OUT into letter
     soup — the same reason the state column moved off it. */
  .legend span{font-family:var(--body);font-size:11px;letter-spacing:.13em;
    text-transform:uppercase;color:var(--dim);display:block;margin-top:7px;font-weight:600}

  /* Not a table layout. Rows are cards on a shared grid, so a row and its
     drawer can butt together — border-spacing would have forced a gap between
     every row pair, including a row and its own drawer. */
  table,thead,tbody{display:block;width:100%}
  table{margin-top:22px;padding-top:22px;border-top:1px solid var(--line)}
  thead tr,tbody tr.row{display:grid;grid-template-columns:var(--cols);gap:18px;
    align-items:center}
  thead tr{padding:0 18px 9px;align-items:end}
  thead th{font-family:var(--body);font-size:11px;letter-spacing:.15em;text-transform:uppercase;
    color:var(--dim);text-align:center;padding:0;font-weight:600;
    cursor:pointer;user-select:none;white-space:nowrap;min-width:0}
  thead th:hover{color:var(--fg)}
  /* `elapsed` is centered over its BAR, which starts 45px in, not over the
     whole column — otherwise it sits noticeably left of what it names. */
  thead th.mid{padding-left:45px}
  thead th::after{content:'';display:inline-block;width:0;height:0;margin-left:6px;
    vertical-align:2px;border-left:3.5px solid transparent;border-right:3.5px solid transparent;
    opacity:.3;border-bottom:4px solid currentColor}
  thead th[data-dir="desc"]::after{border-bottom:0;border-top:4px solid currentColor;opacity:1}
  thead th[data-dir="asc"]::after{opacity:1}
  thead th.nos{cursor:default} thead th.nos::after{display:none}

  tbody tr.row{cursor:pointer;background:var(--head);border:1px solid var(--line);
    border-radius:12px;padding:14px 18px;margin-bottom:7px;transition:border-color .2s}
  tbody tr.row:hover{border-color:var(--line2)}
  tbody tr.row.open{border-color:var(--line2);border-bottom-color:transparent;
    border-radius:12px 12px 0 0;margin-bottom:0}
  tbody tr.row.flash{animation:fl .9s ease}
  @keyframes fl{0%,100%{background:var(--head)}18%{background:rgba(47,230,166,.11)}}
  td{padding:0;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  td.s::after{content:'';display:block;width:8px;height:8px;border-radius:50%;
    background:var(--c);box-shadow:0 0 12px var(--c)}
  td.nm{line-height:1.2}
  td.nm a{font-family:var(--disp);font-weight:700;font-size:16.5px;letter-spacing:-.012em;
    color:var(--fg);text-decoration:none;border-bottom:1px solid transparent}
  td.nm a:hover{color:var(--c);border-bottom-color:var(--c)}
  td.nm .t{font-family:var(--disp);font-weight:700;font-size:16.5px;letter-spacing:-.012em;
    display:block;overflow:hidden;text-overflow:ellipsis}
  td.nm i{font-style:normal;color:var(--dim);font-size:11px;margin-left:7px;font-weight:400}
  td.nm .note{display:inline-block;margin-left:7px;color:var(--dim);vertical-align:1px;
    cursor:help}
  td.nm .note:hover{color:var(--dim2)}
  td.nm .note svg{display:block}
  /* Stacked, not inline: the badge beside the software read as a second word
     of it, and a long software name pushed the badge out of the column. */
  td.nm .m2{display:flex;flex-direction:column;align-items:flex-start;gap:4px;
    margin-top:3px;min-width:0}
  .sw{font-family:var(--body);color:var(--dim);font-size:11px;letter-spacing:.1em;
    text-transform:uppercase;font-weight:600}
  td.st{font-family:var(--body);font-size:12.5px;letter-spacing:.13em;text-transform:uppercase;
    color:var(--c);font-weight:700;white-space:normal;line-height:1.25}
  td.n{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;
    font-size:27px;font-weight:700;color:var(--c);line-height:1}
  td.n small{display:block;font-size:10.5px;font-weight:500;color:var(--dim2);
    letter-spacing:.06em;margin-top:5px}
  /* Pushed off the countdown by the same gap that sits on its other side, so
     the number reads as its own object rather than a label on the bar. */
  td.el{padding-left:45px;position:relative;height:30px}
  .meter{position:absolute;left:45px;right:0;bottom:0;height:4px;background:var(--line);
    border-radius:2px;overflow:hidden}
  .meter i{position:absolute;inset:0 auto 0 0;width:var(--p);background:var(--c);
    border-radius:2px;opacity:.85}
  .meter.none{opacity:.22}
  .elm{position:absolute;top:0;right:0;font-family:var(--mono);font-weight:500;
    font-size:10px;color:var(--dim)}
  .q{font-family:var(--body);font-weight:600;font-size:9.5px;letter-spacing:.1em;color:var(--accent);
    border:1px solid var(--sigdim);border-radius:20px;padding:2px 7px;font-weight:500;
    text-transform:uppercase;white-space:nowrap}

  tr.drawer{display:block;margin-bottom:7px}
  /* white-space MUST be reset here. `td{white-space:nowrap}` above exists so a
     long tracker name ellipsizes in its cell — but the drawer is a <td> too,
     so it inherited nowrap and its prose (the empty-schedule and empty-history
     messages are full sentences) ran out of its pane and across the next one.
     Invisible below 760px, where the mobile block already sets normal. */
  tr.drawer td{display:block;padding:0;background:var(--drawer);
    white-space:normal;text-overflow:clip;
    border:1px solid var(--line2);border-top:1px solid var(--line);
    border-radius:0 0 12px 12px}
  .d{display:grid;grid-template-columns:minmax(0,340px) 1fr 1fr;gap:0}
  .d>div{padding:20px 22px;border-right:1px solid var(--line);min-width:0;
    overflow-wrap:anywhere}
  .d>div:last-child{border-right:0}
  @media(max-width:940px){.d{grid-template-columns:1fr}
    .d>div{border-right:0;border-bottom:1px solid var(--line)}
    .d>div:last-child{border-bottom:0}}
  .dh{font-family:var(--body);font-size:11px;letter-spacing:.15em;text-transform:uppercase;
    color:var(--dim);font-weight:600;margin-bottom:16px}
  button{font-family:var(--mono);font-size:9.5px;font-weight:500;letter-spacing:.09em;
    text-transform:uppercase;background:transparent;color:var(--dim2);
    border:1px solid var(--line2);border-radius:7px;padding:8px 12px;cursor:pointer;transition:.15s}
  button:hover{color:var(--fg);border-color:var(--dim)}
  button:disabled{opacity:.35;cursor:not-allowed}
  button.on{color:var(--accent);border-color:var(--accent);background:rgba(224,85,63,.09)}
  button.arm{color:var(--expired);border-color:var(--expired);background:rgba(165,44,78,.14)}
  button.danger:hover{color:var(--expired);border-color:var(--expired)}
  .msg{font-size:10px;color:var(--dim);min-height:14px;margin-top:9px;letter-spacing:.03em}
  .msg.bad{color:var(--critical)} .msg.good{color:var(--ok)} .msg.warn{color:var(--due)}
  /* Controls are sized to their CONTENT and share a left edge. Stretching
     each one to the column width put a three-digit day count in a 200px box. */
  .a2 .r{display:flex;align-items:center;gap:10px;padding:8px 0;
    border-bottom:1px solid var(--line)}
  .a2 .r:last-child{border-bottom:0}
  .a2 label{width:88px;flex:none;color:var(--dim2);font-family:var(--body);
    font-size:13px;font-weight:500}
  /* Controls pin to the right edge and share it; the hint floats left so a
     three-digit day count and a date picker still line up. */
  .a2 .c{flex:1;min-width:0;display:flex;align-items:center;justify-content:flex-end;gap:6px}
  .a2 .c input,.a2 .c select{background:var(--bg);border:1px solid var(--line2);
    border-radius:7px;color:var(--fg);padding:6px 9px;font-family:var(--mono);
    font-weight:500;font-size:12.5px}
  .a2 .c input:focus,.a2 .c select:focus{outline:none;border-color:var(--sig)}
  .a2 .c input:disabled{opacity:.4;cursor:not-allowed}
  .a2 .w-num{width:76px;text-align:right}
  select.w-num{text-align:left}
  .a2 .w-date{width:142px}
  .a2 .w-grow{flex:1;min-width:0}
  .a2 .c em{font-style:normal;color:var(--dim);font-size:10px;white-space:nowrap;
    order:-1;margin-right:auto;overflow:hidden;text-overflow:ellipsis}
  .a2 .c em b{font-weight:400;color:var(--dim2)}
  .a2 .lk.mini{padding:5px 8px;font-size:8px}
  @media(max-width:940px){
    .a2 label{width:66px}
    /* Space is dearer than the hint on a phone. */
    .a2 .c em{display:none}
  }
  .sched,.hist{font-family:var(--mono);font-size:11px}
  .sched div,.hist div{display:flex;align-items:baseline;gap:14px;padding:6px 0;
    border-bottom:1px solid var(--line)}
  .sched div:last-child,.hist div:last-child{border-bottom:0}
  /* 72px, not 58: CRITICAL measured ~55px in Martian Mono at .14em and sat
     hard against the date. Labels are the body face here like everywhere
     else — this rule and .hist em were missed in that sweep. */
  .sched b{font-family:var(--body);font-size:10.5px;letter-spacing:.12em;
    text-transform:uppercase;font-weight:600;color:var(--k);width:72px;flex:none}
  .sched span,.hist span{color:var(--dim2)}
  .sched em,.hist em{font-style:normal;margin-left:auto;color:var(--dim)}
  .sched .past{opacity:.4}
  .hist em{font-family:var(--body);font-size:10.5px;letter-spacing:.12em;
    text-transform:uppercase;font-weight:600}
  .hist em.hand{color:var(--accent)}

  /* Was one dim 10px paragraph with middots doing the work of punctuation, so
     five separate facts read as one run-on sentence. Each is its own line with
     its trigger in a fixed-width label column. */
  /* 15px, not 22: the last row carries a 7px bottom margin of its own, so
     22 here would sit the rule 29px below it and break the rhythm. */
  .foot{margin-top:15px;padding-top:22px;border-top:1px solid var(--line);
    color:var(--dim2);font-size:12.5px;line-height:1.55}
  .foot .fr{display:flex;gap:14px;padding:3px 0}
  .foot .fr em{flex:none;width:126px;font-style:normal;font-family:var(--body);
    font-weight:600;font-size:11px;letter-spacing:.13em;text-transform:uppercase;
    color:var(--dim);padding-top:2px}
  .foot b{color:var(--sig);font-weight:500}
  @media(max-width:760px){.foot .fr{display:block}
    .foot .fr em{display:block;width:auto;margin-bottom:1px}}
  .empty{color:var(--dim);padding:50px 0;text-align:center;letter-spacing:.12em;text-transform:uppercase}

  /* Mobile sort control — the <thead> is hidden below, so this drives the same
     handlers by clicking the (still present) header cells programmatically. */
  .msort{display:none;gap:6px;align-items:center}
  .msort select,.msort button{font-family:var(--mono);font-size:9.5px;font-weight:500;
    letter-spacing:.09em;text-transform:uppercase;background:var(--bg);color:var(--dim2);
    border:1px solid var(--line2);border-radius:7px;padding:8px 10px}
  .msort select{-webkit-appearance:none;appearance:none;padding-right:22px;
    background-image:linear-gradient(45deg,transparent 50%,var(--dim) 50%),
      linear-gradient(135deg,var(--dim) 50%,transparent 50%);
    background-position:calc(100% - 13px) 12px,calc(100% - 9px) 12px;
    background-size:4px 4px,4px 4px;background-repeat:no-repeat}

  /* ------------------------------------------------------------- mobile
     table-layout:fixed plus px column widths sums wider than a phone, which
     collapses the name column to nothing and overlaps the headers. Below this
     breakpoint the table stops behaving like a table and each row becomes a
     small card laid out on its own grid. */
  @media(max-width:760px){
    .wrap{padding:16px 12px 50px}
    .bar{gap:10px}
    h1{font-size:26px}
    .msort{display:flex;margin-left:auto}
    .legend{display:grid;grid-template-columns:repeat(5,1fr);border-bottom:0}
    .legend div{border-bottom:1px solid var(--line);min-width:0;padding:7px 9px}
    .legend div:nth-child(5n){border-right:0}
    .legend b{font-size:15px}
    .legend span{font-size:8px;letter-spacing:.1em}

    /* Same card, fewer tracks: the columns sum wider than a phone, so the
       countdown moves beside the name and the trace spans the full width. */
    thead{display:none}
    tbody tr.row{grid-template-columns:1fr auto;
      grid-template-areas:"nm n" "st n" "el el";
      gap:4px 12px;align-items:baseline;padding:12px 14px 11px 14px;
      border-left:3px solid var(--c);border-radius:10px}
    tbody tr.row.open{border-radius:10px 10px 0 0}
    td{white-space:normal}
    td.s{display:none}
    td.nm{grid-area:nm}
    td.nm a,td.nm .t{font-size:15.5px}
    td.st{grid-area:st;font-size:11px}
    td.n{grid-area:n;font-size:29px;align-self:center}
    td.el{grid-area:el;margin-top:10px;padding-left:0}
    .meter{left:0}
    .d{grid-template-columns:1fr}
    tr.drawer td{border-radius:0 0 10px 10px}
      .foot{font-size:9.5px}
  }
  /* Rounded like every other container, and readable: 12px was smaller than
     the body text it interrupts. The color is stated rather than inherited,
     so the message cannot pick one up from whatever encloses it. */
  .banner{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:16px 0 0;
    padding:13px 16px;border:1px solid var(--critical);background:#251619;
    border-radius:12px;font-size:13.5px;line-height:1.5;color:var(--fg)}
  .banner b{color:var(--critical);letter-spacing:.04em}
  /* Amber, not red. An out-of-date script is a thing to fix today, not a
     security hole, and using the same color for both teaches you to ignore it. */
  .banner.warn{border-color:var(--warn);background:#241d10}
  .banner.warn b{color:var(--warn)}
  .banner .sp{margin-left:auto;display:flex;gap:7px}
  /* Used on BOTH <button> and <a>. A bare button{} rule elsewhere sets
     uppercase/9px/bold, which anchors never inherit — so every .lk must state
     its own metrics or the two render as different controls side by side.
     inline-flex + line-height is what makes their heights match. */
  .lk{display:inline-flex;align-items:center;justify-content:center;
    box-sizing:border-box;background:var(--bg);border:1px solid var(--line2);
    border-radius:7px;color:var(--dim2);font-family:var(--mono);font-size:9.5px;
    font-weight:500;letter-spacing:.09em;text-transform:uppercase;
    line-height:1;padding:8px 12px;cursor:pointer;text-decoration:none;
    white-space:nowrap;transition:.15s}
  .lk:hover{border-color:var(--sigdim);color:var(--fg)}
  .lk:disabled{opacity:.35;cursor:not-allowed}
  .lk.pri{background:var(--sig);border-color:var(--sig);color:#04120d;font-weight:600}
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;
    align-items:center;justify-content:center;z-index:30}
  .modal.on{display:flex}
  .modal .box{background:var(--head);border:1px solid var(--line2);border-radius:14px;
    padding:24px 26px;width:430px;max-width:92vw;box-shadow:0 24px 60px rgba(0,0,0,.55)}
  .modal h3{margin:0 0 8px;font-family:var(--disp);font-weight:700;font-size:19px;
    letter-spacing:-.01em;text-transform:none}
  .modal .hint{color:var(--dim2);font-size:12.5px;margin:0 0 8px;line-height:1.5}
  .modal .hint b{color:var(--warn);font-weight:600}
  .modal label{display:block;color:var(--dim);font-family:var(--body);font-weight:600;
    font-size:11px;letter-spacing:.13em;text-transform:uppercase;margin:14px 0 6px}
  .modal input,.modal select{width:100%;background:var(--bg);border:1px solid var(--line2);
    border-radius:8px;color:var(--fg);padding:9px 11px;font-family:var(--mono);
    font-weight:500;font-size:12.5px}
  .modal input::placeholder{color:#5c716c}
  .modal input:focus,.modal select:focus{outline:none;border-color:var(--sig)}
  .modal .rowb{display:flex;gap:8px;margin-top:22px;padding-top:18px;
    border-top:1px solid var(--line)}
  /* Buttons size to their content now, so the import prompt can hold the left
     of the row. flex:1 stretched two words across half the dialog each. */
  .modal .rowb button{padding:9px 14px;font-family:var(--mono);font-weight:500;
    font-size:9.5px;letter-spacing:.09em;text-transform:uppercase;cursor:pointer}
  .modal .rowb .alt{margin-right:auto;font-size:12px;color:var(--dim);
    align-self:center;line-height:1.35}
  .modal .rowb .alt a{color:var(--sig);cursor:pointer;text-decoration:none;
    border-bottom:1px solid var(--sigdim);white-space:nowrap}
  .modal .rowb .alt a:hover{border-bottom-color:var(--sig)}
  .modal .e{color:var(--critical);font-size:11.5px;min-height:15px;margin:7px 0 0}
  .modal .box.wide{width:410px}
  .modal .rowb button:disabled{opacity:.4;cursor:default}

  .hbtn{display:flex;gap:9px;align-items:center}
  /* Creating a tracker is a list action, so it rides the header next to the
     list — not two clicks deep under the cog. Filled, because it is the one
     thing a new install has to do. */
  .addbtn{background:var(--sig);color:#04120d;border:0;border-radius:8px;
    font-family:var(--mono);font-weight:600;font-size:10px;letter-spacing:.11em;
    text-transform:uppercase;cursor:pointer;white-space:nowrap;transition:filter .15s;
    /* height, not padding: the cog is a fixed 38px square, and matching two
       controls by eye through padding drifts the moment the font metrics do. */
    height:38px;padding:0 16px;display:inline-flex;align-items:center}
  .addbtn:hover{filter:brightness(1.12)}
  .gear{width:38px;height:38px;padding:0;border-radius:8px;background:var(--head);
    border:1px solid var(--line2);color:var(--dim2);cursor:pointer;font-size:17px;
    line-height:1;display:grid;place-items:center;
    transition:color .15s,border-color .15s,transform .3s}
  .gear:hover{color:var(--sig);border-color:var(--sigdim);transform:rotate(40deg)}
  /* Same 38px square as the cog. Stroked icon rather than a glyph, because no
     unicode logout character sits on the same optical weight as the others. */
  .signout{width:38px;height:38px;padding:0;border-radius:8px;background:var(--head);
    border:1px solid var(--line2);color:var(--dim2);cursor:pointer;
    display:grid;place-items:center;transition:color .15s,border-color .15s}
  .signout:hover{color:var(--sig);border-color:var(--sigdim)}
  .signout svg{display:block;transition:transform .18s}
  .signout:hover svg{transform:translateX(2px)}

  .sheet{position:fixed;inset:0;background:rgba(0,0,0,.66);display:none;z-index:40;
    align-items:center;justify-content:center}
  .sheet.on{display:flex}
  /* Grid, not flex, so the close button can span the full width above BOTH
     the nav and the pane without wrapping them in another element. Source
     order is close / nav / pane, so auto-placement puts nav and pane in row 2
     on their own. */
  /* 14px, the same as `.modal .box` and the login form, which carry an
     identical background and border. overflow:hidden is load-bearing here and
     not just tidiness: nav and the close bar paint their own backgrounds right
     into the corners, so without it they square off the radius. */
  .sheet .win{background:var(--head);border:1px solid var(--line2);position:relative;
    border-radius:14px;
    width:min(790px,94vw);height:min(584px,88vh);overflow:hidden;
    display:grid;grid-template-columns:180px 1fr;grid-template-rows:auto 1fr}
  .sheet nav{width:180px;border-right:1px solid var(--line);background:var(--bg);
    padding:14px 0;flex:none}
  .sheet nav button{display:block;width:100%;text-align:left;background:none;
    border:0;border-left:2px solid transparent;color:var(--dim);font-family:var(--body);
    font-weight:600;font-size:12px;letter-spacing:.13em;text-transform:uppercase;
    padding:12px 20px;cursor:pointer}
  .sheet nav button:hover{color:var(--fg)}
  .sheet nav button.on{color:var(--fg);background:var(--head)}
  .sheet .pane{flex:1;overflow:auto;padding:20px 22px}
  .sheet .pane section{display:none}
  .sheet .pane section.on{display:block}
  /* Section titles are names, not labels: uppercase micro-tracking made
     "General" read as a form field rather than the heading above one. */
  .sheet h4{margin:0 0 6px;font-family:var(--disp);font-weight:700;font-size:19px;
    letter-spacing:-.01em;text-transform:none}
  .sheet .sub{color:var(--dim2);font-size:13px;margin:0 0 20px;line-height:1.55}
  /* Command chips in help text: kept whole (never break mid-token) and set off
     from prose, so when one wraps to its own line it reads as a called-out
     command rather than a stray fragment. */
  .sheet code,.sheet .sub code,.sheet .lbl code,.banner code{font-family:var(--mono);
    font-size:.92em;background:var(--bg);border:1px solid var(--line2);
    border-radius:3px;padding:1px 5px;white-space:nowrap;color:var(--fg)}
  .sheet .row{display:flex;align-items:center;gap:14px;padding:12px 0;
    border-bottom:1px solid var(--line)}
  .sheet .row:last-child{border-bottom:0}
  .sheet .row .lbl{flex:1;min-width:0}
  /* DIRECT child only. As `.lbl b` it also matched any <b> inside the help
     text below the label, turning an emphasised phrase into a second
     block-level 14.5px heading mid-sentence — so "…<b>nothing due</b> means…"
     rendered as three broken lines. The Install row's "<b>status page URL</b>"
     had the same fault. */
  .sheet .row .lbl>b{display:block;font-weight:600;font-size:14.5px;color:var(--fg)}
  .sheet .row .lbl span b{color:var(--dim2);font-weight:600}
  .sheet .row .lbl span{color:var(--dim);font-size:12.5px;line-height:1.5;
    display:block;margin-top:2px}
  .sheet .row .val{font-family:var(--mono);font-weight:500;font-size:12.5px;color:var(--dim2)}
  .sheet .row .val.on{color:var(--ok)}
  .sheet .row .val.off{color:var(--critical)}
  .sheet input,.sheet select{background:var(--bg);border:1px solid var(--line2);
    border-radius:8px;color:var(--fg);padding:8px 11px;font-family:var(--mono);
    font-weight:500;font-size:12.5px}
  .sheet input:focus,.sheet select:focus{outline:none;border-color:var(--sig)}
  /* ONE fixed control column. Every control shares a left and right edge;
     letting each size itself staggered them down the panel. */
  .sheet .row .ctl2{width:200px;flex:none;display:flex;justify-content:flex-end;
    gap:6px;align-items:center}
  .sheet .row .ctl2>input,.sheet .row .ctl2>select{width:100%}
  .sheet .row .ctl2>.val{white-space:normal;text-align:right}
  /* Recent activity: timestamp above, outcome beneath, both right-aligned in
     the same fixed column as every other control. */
  .sheet .row .ctl2{flex-wrap:wrap}
  .sheet .act-d{width:100%;text-align:right;font-style:normal;color:var(--dim);
    font-size:10.5px;margin-top:2px}
  .sheet .act-d.due{color:var(--due)}
  .sheet .row .ctl2>button{flex:1}
  /* Destination rows span the pane rather than sitting in the 200px control
     column: a name, a masked URL and three buttons do not fit there, and the
     URL is the part you need room to read. */
  .ndlist{margin:0 0 16px;border-top:1px solid var(--line)}
  .nd{display:flex;align-items:center;gap:9px;padding:10px 0;
    border-bottom:1px solid var(--line)}
  .nd-n{font-family:var(--body);font-weight:600;font-size:13px;color:var(--fg);
    flex:none;min-width:88px}
  .nd-u{font-family:var(--mono);font-size:10.5px;color:var(--dim);
    flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .nd .lk{flex:none;padding:6px 10px}
  .nd.off .nd-n,.nd.off .nd-u{opacity:.45}
  .nd-src{font-family:var(--body);font-size:10.5px;letter-spacing:.1em;
    text-transform:uppercase;color:var(--dim);flex:none}
  /* A row whose control spans the pane instead of sitting in the 200px
     column. An Apprise URL does not fit in 200px, and splitting the form
     across two rows left the entire left half of one of them empty. */
  .sheet .row.wide{flex-wrap:wrap}
  .sheet .row.wide>.lbl{flex:1 0 100%}
  .ndform{display:flex;gap:9px;align-items:center;width:100%;margin-top:11px}
  .ndform input{min-width:0}
  .ndform .f2{flex:2}
  .ndform .f1{flex:1}
  .ndform button{flex:none}
  /* The key field shares its cell with the reveal button, so it may not take
     the full width the way every other input in this column does. */
  .sheet .row .ctl2>.keyf{width:auto;flex:1;min-width:0}
  .sheet .row .ctl2>.ico{flex:none;padding:8px 9px}
  .ico .i-hide{display:none}
  .ico.on .i-show{display:none}
  .ico.on .i-hide{display:inline}
  .sheet .stack{margin:0 0 14px}
  .sheet .stack input,.sheet .stack select{width:100%;margin-bottom:9px}
  .sheet .e{color:var(--critical);font-size:12px;min-height:16px;margin:9px 0 0}
  .sheet .e.good{color:var(--ok)}
  /* Its own bar rather than floating in the corner. Absolutely positioned it
     sat over the pane, so it landed on whatever control happened to be at the
     top right and got harder to pick out the further you scrolled. The phone
     layout already did this; it turned out to be the better answer at every
     width. */
  .xclose{grid-column:1/-1;display:flex;justify-content:flex-end;align-items:center;
    background:var(--head);border:0;border-bottom:1px solid var(--line);
    color:var(--dim);font-size:19px;cursor:pointer;line-height:1;
    padding:8px 15px;z-index:2}
  /* border-color is pinned, not inherited. The generic `button:hover` sets it
     on every button, and .xclose has no outline, only a bottom border acting
     as this bar's divider — so hovering lit that divider up and it read as a
     stray bracket under the bar. */
  .xclose:hover{color:var(--fg);border-color:var(--line)}
  /* scrollbar-gutter reserves the track so content never sits under it; the
     row's right padding is the fallback for engines without it. 10px was not
     enough — desktop scrollbars run 15-17px, so "already configured" was still
     clipped. */
  .imlist{max-height:170px;overflow:auto;margin:2px 0 6px;scrollbar-gutter:stable}
  .imlist:empty{display:none}
  /* A grid, not a flex row. Flexed, each cell sized to its own text, so
     TORRENT and USENET being different widths pushed the status column left
     and right per row and nothing lined up. */
  .imlist .r{display:grid;grid-template-columns:minmax(0,1fr) 62px 106px;gap:10px;
    align-items:baseline;padding:5px 6px 5px 0;
    border-bottom:1px solid var(--line);font-size:12px}
  .imlist .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .imlist .sk{color:var(--dim);font-size:10px;white-space:nowrap;text-align:right}
  .imlist .new{color:var(--ok);font-size:10px;white-space:nowrap;text-align:right}
  .imlist .pr{color:var(--dim);font-size:9.5px;letter-spacing:.09em;
    text-transform:uppercase;white-space:nowrap;font-family:var(--mono)}
  .improt{display:flex;align-items:center;gap:16px;margin:2px 0 8px;font-size:12px;
    color:var(--dim2)}
  .improt label{display:flex;align-items:center;gap:6px;cursor:pointer;
    flex:none;white-space:nowrap}
  .improt input{width:14px;height:14px;accent-color:var(--sig);cursor:pointer;
    padding:0;margin:0}
  /* Save owns the right edge of this row, and margin-left:auto is what puts
     it there. Everything in the pane is width:100% under box-sizing:border-box,
     so that edge is the same one the key field above ends on. */
  .improt button{margin-left:auto;flex:none}
  .impnote{color:var(--dim);font-size:11px;line-height:1.4;margin:0 0 10px;
    font-family:var(--body)}
  .impnote[hidden]{display:none}
  /* Inherits every label and input rule from .improt, so it is the same
     control at the same left edge. Only the Save button is extra. */
  .improt label.off{opacity:.4;cursor:not-allowed}
  .improt label.off input{cursor:not-allowed}
  @media(max-width:760px){
    .sheet .win{grid-template-columns:1fr;grid-template-rows:auto auto 1fr;
      height:92vh}
    /* Eight tabs don't fit at phone width, so the nav scrolls sideways here.
       The × already sits in its own bar at every width, so nothing shares that
       row and the tabs scroll freely underneath. */
    .xclose{padding:9px 13px;font-size:20px}
    .sheet nav{width:100%;display:flex;overflow-x:auto;padding:0;
      border-right:0;border-bottom:1px solid var(--line)}
    .sheet nav button{border-left:0;border-bottom:2px solid transparent;
      white-space:nowrap;padding:12px 13px;width:auto}
    .sheet nav button.on{border-left:0;border-bottom-color:var(--accent)}
    .sheet .row{flex-wrap:wrap}
    .sheet .row .ctl2{width:100%;justify-content:flex-start}
    .banner .sp{margin-left:0;width:100%}
    .addbtn{height:34px;padding:0 12px;font-size:9px}
    .gear{width:34px;height:34px;font-size:15px}
  }
</style></head><body><div class="wrap">

<div class="bar"><h1>idl<b>a</b>rr</h1>
  <div class="pulse" id="pulse"></div>
  <div class="msort"><select id="msf" aria-label="sort by">
    <option value="st">state</option><option value="nm">tracker</option>
    <option value="left">left</option><option value="el">elapsed</option>
  </select><button id="msd" aria-label="reverse sort">&#8645;</button></div>
  <div class="hbtn"><button class="addbtn" id="addtrk">+ Add tracker</button><button class="gear" id="gear" title="settings" aria-label="settings">&#9881;</button>__SIGNOUT__</div></div>
__BANNER__
<div class="legend">__LEGEND__</div>

<table>
<thead><tr><th class="nos"></th>
<th data-k="nm" data-t="s">tracker</th>
<th data-k="st" data-t="n">state</th>
<th data-k="left" data-t="n">left</th>
<th data-k="el" data-t="n" class="mid">elapsed</th></tr></thead>
<tbody>__ROWS__</tbody></table>

<div class="foot">
  <div class="fr"><em>Click a row</em>for controls, the alert schedule and auth history</div>
  <div class="fr"><em>Click a name</em>to open that tracker in a new tab</div>
  <div class="fr"><em>Click a heading</em>to sort by it</div>
  <div class="fr"><em>&#9998;</em>last auth was marked by hand, not observed by the userscript</div>
  <div class="fr"><em>Countdowns</em>run on <b>auth</b> events only &mdash; a visit while logged
    out does not reset one. No request is ever made to a tracker.</div>
</div>
</div>

__SHEET__

<div class="modal" id="tm"><div class="box">
  <h3>Add tracker</h3>
  <p class="hint">The limit starts at 30 days and stays <b>unconfirmed</b> until
  you read that tracker's own rules page. A limit set too high is the one that
  loses the account, so this errs short on purpose.</p>
  <label for="tmn">name</label>
  <input id="tmn" autocomplete="off" placeholder="Alpha Tracker">
  <label for="tmu">url</label>
  <input id="tmu" autocomplete="off" placeholder="https://alpha.example/">
  <label for="tmi">id &mdash; ping and script id</label>
  <input id="tmi" autocomplete="off" placeholder="derived from the name">
  <label for="tmd">inactivity limit, in days</label>
  <input id="tmd" type="text" inputmode="numeric" autocomplete="off" value="30">
  <label for="tmo">notes</label>
  <input id="tmo" autocomplete="off" placeholder="Gazelle. Seeding counts.">
  <div class="rowb">
    <span class="alt">Have Prowlarr/Jackett? <a id="tmimp">Import</a></span>
    <button class="lk" id="tmcancel">Cancel</button>
    <button class="lk pri" id="tmsave">Add</button></div>
  <p class="e" id="tme"></p>
</div></div>


<script>
(function(){
 const CURRENT_METHOD='__AUTHMETHOD__';
 const tb=document.querySelector('tbody');
 // Mirrors LABELS in app.py; a test asserts the two agree by value.
 const LABEL={ok:'days left',due:'days left',warn:'days left',critical:'days left',
   expired:'days over',session:'re-auth',immune:'exempt',unknown:'no data',
   snoozed:'days left'};
 const RANK={expired:0,session:1,critical:2,warn:3,due:4,unknown:5,ok:6,snoozed:7,immune:8};
 // Display names, where they differ from the state key. Mirrors STATE_LABEL
 // in app.py; a test asserts the two agree.
 const SLBL={session:'logged out'};

 const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify(b||{})}).then(async r=>{const d=await r.json().catch(()=>({}));
   if(!r.ok)throw new Error(d.detail||('HTTP '+r.status));return d;});

 const ago=d=>d===null||d===undefined?'never':(d===0?'today':d+'d ago');
 const fmt=n=>{const d=new Date();d.setHours(0,0,0,0);d.setDate(d.getDate()+n);
   return d.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});};

 // Only what the row cannot show: when each rung fires, and the evidence behind it.
 function schedule(d){
   if(d.immune)return '<div><span>Exempt &mdash; no alert will ever fire.</span></div>';
   if(d.days_left===null)
     return '<div><span>No auth recorded, so there is no baseline to schedule from.</span></div>';
   const L=d.inactivity_days,left=d.days_left,since=d.days_since,pctv=d.alert_at_pct;
   const rungs=[['due',Math.ceil(pctv*L)-since,'--due'],['warn',left-14,'--warn'],
                ['critical',left-5,'--critical'],['expired',left,'--expired']];
   let out='',seen=new Set();
   for(const [name,inDays,c] of rungs){
     // 'due' is checked after the absolute rungs, so on a short limit it can
     // never fire. Say that instead of printing a date that will not happen.
     if(name==='due'&&inDays>left-14){
       out+='<div class="past"><b style="--k:var('+c+')">due</b>'
          +'<span>never fires at this limit</span></div>';continue;}
     if(seen.has(inDays))continue; seen.add(inDays);
     const past=inDays<=0;
     out+='<div class="'+(past?'past':'')+'"><b style="--k:var('+c+')">'+name+'</b>'
        +'<span>'+fmt(inDays)+'</span><em>'+(past?'passed':'in '+inDays+'d')+'</em></div>';
   }
   return out;
 }

 function paint(tr,d){
   tr.style.setProperty('--c','var(--'+d.state+')');
   tr.dataset.st=RANK[d.state]; tr.dataset.state=d.state;
   tr.dataset.left=d.days_left===null?'':d.days_left;
   tr.dataset.lim=d.inactivity_days; tr.dataset.seen=d.days_since===null?'':d.days_since;
   tr.dataset.immune=d.immune?'1':''; tr.dataset.verified=d.verified?'1':'';
   tr.dataset.reason=d.immune_reason||'';
   tr.dataset.el=d.days_since===null?'0':
     Math.min(100,Math.max(0,d.days_since/Math.max(d.inactivity_days,1)*100)).toFixed(2);
   tr.querySelector('td.st').textContent=d.immune&&d.immune_reason?d.immune_reason
     :(SLBL[d.state]||d.state);
   // The countdown carries its unit as a child, so textContent= would wipe it.
   // `td.seen` and `td.lim` are gone -- last auth and the limit share the
   // elapsed cell's meta line now.
   const big=(d.immune||d.days_left===null)?'\\u2014':Math.abs(d.days_left);
   tr.querySelector('td.n').innerHTML=big+'<small>'+(LABEL[d.state]||'')+'</small>';
   tr.querySelector('.elm').textContent=ago(d.days_since)+' \\u00b7 '+d.inactivity_days+'d';
   const p=d.days_since===null?0:Math.min(100,Math.max(3,(1-d.days_left/d.inactivity_days)*100));
   tr.querySelector('.meter i').style.setProperty('--p',(d.immune?0:p).toFixed(0)+'%');
   tr.querySelector('.meter').classList.toggle('none',!!d.immune);
   const q=tr.querySelector('.q');
   if(q)q.style.display=(d.verified||d.immune)?'none':'';
   // Both of these are derived from `notes`, and editing notes in the drawer
   // calls paint(). The software line was NOT being updated despite a comment
   // at the notes handler saying it was, so changing "UNIT3D..." to
   // "Gazelle..." left the old value on the row until a reload.
   const sw=tr.querySelector('.sw'); if(sw)sw.textContent=d.software||'';
   const nm=tr.querySelector('td.nm'), had=nm.querySelector('.note');
   const has=!!(d.notes||'').trim();
   if(has&&!had){
     const el=document.createElement('span');
     el.className='note';
     el.innerHTML='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" '+
       'stroke="currentColor" stroke-width="2.4" stroke-linecap="round" '+
       'aria-hidden="true"><path d="M5 7h14M5 12h14M5 17h9"/></svg>';
     nm.insertBefore(el, nm.querySelector('.m2'));
   }
   if(had&&!has)had.remove();
   const mark=nm.querySelector('.note');
   if(mark)mark.title=d.notes||'';
   tr.classList.remove('flash');void tr.offsetWidth;tr.classList.add('flash');
 }

 function drawer(tr){
   const d=JSON.parse(tr.dataset.row), imm=!!d.immune;
   const el=document.createElement('tr'); el.className='drawer';
   // Labeled rows: label + a control sized to its content, sharing a left
   // edge. Previously every control filled the column width, so a three-digit
   // day count sat in a 200px box beside a date picker.
   const pctOpts=(sel)=>{let o='';
     for(let v=40;v<100;v+=5)o+='<option value="'+(v/100).toFixed(2)+'"'
       +(Math.abs(sel-v/100)<0.001?' selected':'')+'>'+v+'%</option>';
     return o;};
   el.innerHTML='<td colspan="5"><div class="d" style="--c:var(--'+d.state+')">'
    +'<div><div class="dh">controls</div><div class="a2">'
    +'<div class="r"><label>Limit</label><div class="c">'
    +'<input class="lim w-num" type="text" inputmode="numeric" value="'
    +d.inactivity_days+'"'+(imm?' disabled':'')+'><em>days</em></div></div>'
    +'<div class="r"><label>Alert at</label><div class="c">'
    +'<select class="pct w-num">'+pctOpts(d.alert_at_pct||0.65)+'</select>'
    +'<em>of the limit before <b>due</b> fires</em></div></div>'
    +'<div class="r"><label>Snooze</label><div class="c">'
    +'<input class="snz w-date" type="date" value="'+hesc(d.snooze_until||'')+'">'
    +'<button class="lk mini snzclr"'+(d.snooze_until?'':' style="display:none"')
    +'>Clear</button></div></div>'
    +'<div class="r"><label>Notes</label><div class="c">'
    +'<input class="nts w-grow" value="'+hesc(d.notes||'')
    +'" placeholder="first word sets the software column"></div></div>'
    +'<div class="r"><label>State</label><div class="c">'
    +'<button class="lk chk'+(d.verified?' pri':'')+'"'+(imm?' disabled':'')+'>'
    +(d.verified?'✓ Confirmed':'Confirm')+'</button>'
    +'<button class="lk imm'+(imm?' pri':'')+'">'+(imm?'● Immune':'Immune')+'</button>'
    +'</div></div>'
    +(imm?'<div class="r"><label>Reason</label><div class="c">'
      +'<input class="rsn w-grow" value="'+hesc(d.immune_reason||'')
      +'" placeholder="why immune? e.g. donated, elite class"></div></div>':'')
    +'<div class="r"><label>Actions</label><div class="c">'
    +'<button class="lk seen">Seen</button>'
    +'<button class="lk undo">Undo</button>'
    +'<button class="lk del">Remove</button></div></div>'
    +'</div><div class="msg"></div></div>'
    +'<div><div class="dh">alert schedule</div><div class="sched">'+schedule(d)+'</div></div>'
    +'<div><div class="dh">auth history</div><div class="hist">'
    +'<div><span>loading…</span></div></div></div></div></td>';
   tr.after(el); tr.classList.add('open');

   const msg=(t,c)=>{const m=el.querySelector('.msg');m.textContent=t;
     m.className='msg '+(c||'');if(c==='good')setTimeout(()=>{if(m.textContent===t)m.textContent='';},4000);};
   const refresh=row=>{tr.dataset.row=JSON.stringify(row);paint(tr,row);
     el.querySelector('.sched').innerHTML=schedule(row);};

   fetch('/api/history/'+d.id).then(r=>r.json()).then(rows=>{
     el.querySelector('.hist').innerHTML=rows.length?rows.map(e=>
       '<div><span>'+e.date+'</span><span style="opacity:.6">'+e.time+'</span>'
       +'<em class="'+(e.source==='manual'?'hand':'')+'">'
       +(e.source==='manual'?'by hand':(e.source||'unknown'))+'</em></div>').join('')
       : '<div><span>No auth event has ever been recorded.</span></div>';
   }).catch(()=>{el.querySelector('.hist').innerHTML='<div><span>history unavailable</span></div>';});

   const lim=el.querySelector('.lim');
   if(lim){let orig=lim.value;
     const commit=()=>{const v=parseInt(lim.value,10);
       if(!Number.isFinite(v)||v<1||v>3650){msg('limit must be 1-3650 days','bad');lim.value=orig;return;}
       if(String(v)===orig)return;
       post('/api/limit/'+d.id,{inactivity_days:v}).then(r=>{orig=String(r.inactivity_days);
         refresh(r);msg(r.verified?'saved':'saved, still unconfirmed','warn');})
        .catch(e=>{msg(e.message,'bad');lim.value=orig;});};
     lim.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();lim.blur();}
       if(e.key==='Escape'){lim.value=orig;lim.blur();}});
     lim.addEventListener('blur',commit);}

   el.querySelector('.chk').addEventListener('click',function(){
     if(this.disabled)return;
     post('/api/limit/'+d.id,{verified:!this.classList.contains('on')}).then(r=>{
       refresh(r);this.classList.toggle('on',r.verified);
       this.innerHTML=r.verified?'\\u2713 confirmed':'confirm';
       msg(r.verified?'confirmed':'confirmation cleared','good');}).catch(e=>msg(e.message,'bad'));});

   el.querySelector('.imm').addEventListener('click',function(){
     const next=!this.classList.contains('on');
     post('/api/limit/'+d.id,{immune:next}).then(r=>{refresh(r);
       el.remove();tr.classList.remove('open');drawer(tr);
       msg(next?'immune, it will never alert':'immunity cleared','good');})
      .catch(e=>msg(e.message,'bad'));});

   const rsn=el.querySelector('.rsn');
   if(rsn){let last=rsn.value;
     const save=()=>{if(rsn.value===last)return;
       post('/api/limit/'+d.id,{immune_reason:rsn.value}).then(r=>{last=r.immune_reason;
         refresh(r);msg('reason saved','good');}).catch(e=>{msg(e.message,'bad');rsn.value=last;});};
     rsn.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();rsn.blur();}});
     rsn.addEventListener('blur',save);}

   const snz=el.querySelector('.snz');
   if(snz){let last=snz.value;
     const save=()=>{if(snz.value===last)return;
       post('/api/limit/'+d.id,{snooze_until:snz.value}).then(r=>{last=r.snooze_until||'';
         refresh(r);paint(tr,r);
         msg(r.snooze_until?('snoozed until '+r.snooze_until+', no alerts until then')
                           :'snooze cleared','good');
       }).catch(e=>{msg(e.message,'bad');snz.value=last;});};
     snz.addEventListener('change',()=>{save();
       const c=el.querySelector('.snzclr');
       if(c)c.style.display=snz.value?'':'none';});
     const clr=el.querySelector('.snzclr');
     if(clr)clr.addEventListener('click',()=>{
       // An empty date input does not read as "not snoozed", so clearing is
       // an explicit action rather than something you have to discover.
       snz.value='';clr.style.display='none';save();});}

   const pct=el.querySelector('.pct');
   if(pct){let last=pct.value;
     pct.addEventListener('change',()=>{
       post('/api/limit/'+d.id,{alert_at_pct:pct.value}).then(r=>{
         last=String(r.alert_at_pct);refresh(r);paint(tr,r);
         msg('alert threshold saved','good');
       }).catch(e=>{msg(e.message,'bad');pct.value=last;});});}

   const nts=el.querySelector('.nts');
   if(nts){let last=nts.value;
     const save=()=>{if(nts.value===last)return;
       post('/api/limit/'+d.id,{notes:nts.value}).then(r=>{last=r.notes;
         // The software column is derived from notes, so repaint the row too.
         refresh(r);paint(tr,r);msg('notes saved','good');})
        .catch(e=>{msg(e.message,'bad');nts.value=last;});};
     nts.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();nts.blur();}});
     nts.addEventListener('blur',save);}

   // Two-step: one stray click here silently resets a countdown.
   const seenBtn=el.querySelector('.seen');let armed=false,t=null;
   seenBtn.addEventListener('click',()=>{
     if(!armed){armed=true;seenBtn.classList.add('arm');seenBtn.textContent='confirm?';
       msg('records a manual auth, only if you really just logged in','warn');
       t=setTimeout(()=>{armed=false;seenBtn.classList.remove('arm');
         seenBtn.textContent='seen';msg('');},4000);return;}
     clearTimeout(t);armed=false;seenBtn.classList.remove('arm');seenBtn.textContent='seen';
     post('/api/mark/'+d.id).then(()=>fetch('/api/status').then(r=>r.json())).then(rows=>{
       const row=rows.find(x=>x.id===d.id);refresh(row);
       el.remove();tr.classList.remove('open');drawer(tr);}).catch(e=>msg(e.message,'bad'));});

   el.querySelector('.undo').addEventListener('click',()=>{
     post('/api/unmark/'+d.id).then(res=>{
       if(!res.removed){msg('no auth event to undo','bad');return;}
       refresh(res.row);el.remove();tr.classList.remove('open');drawer(tr);
     }).catch(e=>msg(e.message,'bad'));});

   // Two-click confirm rather than a browser dialog: this edits trackers.yml,
   // and a misclick here deletes a tracker you are relying on. Disarms itself
   // after 5s so a forgotten armed button cannot be triggered later.
   const del=el.querySelector('.del');
   del.addEventListener('click',()=>{
     if(del.dataset.armed!=='1'){
       del.dataset.armed='1'; del.textContent='confirm remove';
       msg('removes it from trackers.yml, auth history is kept','warn');
       setTimeout(()=>{if(del.dataset.armed==='1'){
         del.dataset.armed=''; del.textContent='remove'; msg('');}},5000);
       return;}
     fetch('/api/tracker/'+d.id,{method:'DELETE'}).then(async r=>{
       const j=await r.json().catch(()=>({}));
       if(!r.ok)throw new Error(j.detail||('failed ('+r.status+')'));
       location.reload();
     }).catch(e=>msg(e.message,'bad'));});
 }

 tb.addEventListener('click',e=>{
   if(e.target.closest('a')||e.target.closest('.d'))return;
   const tr=e.target.closest('tr.row'); if(!tr)return;
   const nx=tr.nextElementSibling;
   if(nx&&nx.classList.contains('drawer')){nx.remove();tr.classList.remove('open');return;}
   drawer(tr);
 });

 document.querySelectorAll('th[data-k]').forEach(th=>{
   th.addEventListener('click',()=>{
     const k=th.dataset.k,num=th.dataset.t==='n';
     const dir=th.dataset.dir==='asc'?'desc':'asc';
     document.querySelectorAll('th[data-k]').forEach(o=>o.removeAttribute('data-dir'));
     th.dataset.dir=dir;
     tb.querySelectorAll('tr.drawer').forEach(x=>{
       x.previousElementSibling.classList.remove('open');x.remove();});
     [...tb.querySelectorAll('tr.row')].sort((a,b)=>{
       let x=a.dataset[k],y=b.dataset[k];
       if(num){ // blanks last always: "no data" must never outrank something expiring
         const nx=x===''?null:+x,ny=y===''?null:+y;
         if(nx===null&&ny===null)return 0;
         if(nx===null)return 1;
         if(ny===null)return -1;
         return dir==='asc'?nx-ny:ny-nx;}
       return dir==='asc'?x.localeCompare(y):y.localeCompare(x);
     }).forEach(r=>tb.appendChild(r));
   });
 });

 // The header row is display:none on mobile but still in the DOM, so the
 // select just drives the same sort handlers rather than duplicating them.
 const msf=document.getElementById('msf'),msd=document.getElementById('msd');
 const th4=k=>document.querySelector('th[data-k="'+k+'"]');
 if(msf){
   msf.addEventListener('change',()=>{const t=th4(msf.value);
     if(t){t.removeAttribute('data-dir');t.click();}});
   msd.addEventListener('click',()=>{const t=th4(msf.value);if(t)t.click();});
 }

 // ---- header trace ----------------------------------------------------
 // Purely decorative. Two tiles side by side, scrolled by exactly one tile, so
 // the loop point is the join between them.
 //
 // The tiles MUST stay sibling <path>s carrying their own transform
 // attribute. They were briefly a nested <g transform=...> while a drift
 // animation ran on `.pulse g` -- a CSS animation's transform overrides a
 // transform presentation attribute, so the copy's translate() was destroyed,
 // it stacked on the original, and the right half of the strip was blank. Do
 // not animate a transform on anything wrapping these paths.
 //
 // RR intervals are jittered and then normalized to sum to exactly W, so the
 // first beat of the next tile lands one ordinary interval after the last beat
 // of this one; the seam is just another beat gap. Amplitude, P and T vary per
 // beat -- a metronome reads as a graphic, not a monitor.
 (function(){
   const host=document.getElementById('pulse'); if(!host)return;
   const MID=19,H=38,W=2160,N=18;      // 18 beats/tile, ~6 on screen at a time
   let s=1337; const rnd=()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff};
   // Baseline drift, BAKED INTO THE PATH rather than animated on the group.
   // As a CSS translateY on <g> it moved the whole trace rigidly, which reads
   // as a bounce. Here it undulates along the trace and scrolls with it. Three
   // whole cycles per tile, so both ends sit on MID at matching slope and the
   // seam stays invisible.
   const b=(px)=>MID+2.2*Math.sin(2*Math.PI*3*px/W);
   const rr=[]; for(let i=0;i<N;i++)rr.push(1+(rnd()-0.5)*0.44);
   const k=W/rr.reduce((a,b2)=>a+b2,0);
   let d='M0 '+MID,x=0;
   const to=(nx,ny)=>{d+=' L'+nx.toFixed(1)+' '+ny.toFixed(1)};
   for(let i=0;i<N;i++){
     const start=x, span=rr[i]*k;
     // A slow envelope over the tile, plus jitter: beats come in taller and
     // shorter runs the way breathing modulates a real trace, instead of every
     // peak landing at one of two heights.
     // Floor 5, not 8.5: the troughs were barely shorter than the peaks. The
     // ceiling is capped too — at the old spread the tallest R overshot the
     // top of the viewBox by 1.6px and had its tip clipped flat.
     const amp=5+8*(0.5+0.5*Math.sin(2*Math.PI*2*i/N))+rnd()*2.2;
     const tw=3.8+rnd()*4, pw=2.8+rnd()*2.4;
     x+=10;to(x,b(x));
     d+=' q 7 -'+pw.toFixed(1)+' 15 0'; x+=15;                      // P
     x+=6;to(x,b(x)); x+=3;to(x,b(x)+2.5+rnd());                    // Q
     x+=4;to(x,b(x)-amp);                                           // R
     x+=4;to(x,b(x)+amp*0.45); x+=5;to(x,b(x)); x+=8;to(x,b(x));    // S
     d+=' q 10 -'+tw.toFixed(1)+' 21 0'; x+=21;                     // T
     x=start+span; to(x,b(x));                                      // diastole
   }
   to(W,MID);
   const p=t=>'<path d="'+d+'"'+t+' fill="none" stroke="var(--sig)" '+
             'stroke-width="1.4" stroke-linejoin="round" opacity=".85"/>';
   host.innerHTML='<svg viewBox="0 0 '+(W*2)+' '+H+'" preserveAspectRatio="none" aria-hidden="true">'+
     '<g>'+p('')+p(' transform="translate('+W+',0)"')+'</g></svg>';
 })();

 // ---- sign-in ---------------------------------------------------------
 // The banner is dismissable but NOT sticky-dismissed across a password
 // change: it is keyed on the current method, so turning auth off again
 // brings the warning back rather than staying hidden from an earlier click.
 const ban=document.getElementById('ban');
 if(ban){
   if(localStorage.getItem('idl_authban')==='none')ban.style.display='none';
   const bx=document.getElementById('banx');
   if(bx)bx.addEventListener('click',()=>{
     localStorage.setItem('idl_authban','none');ban.style.display='none';});
 }

 // Same trick for the stale-script warning, keyed on the SERVED version:
 // dismissing 1.1.7 must not hide 1.1.8. A dismissal that outlives the thing
 // it dismissed is how you stop being told about the next one.
 const st=document.getElementById('stale');
 if(st){
   const sv=st.dataset.v||'';
   if(localStorage.getItem('idl_staleban')===sv)st.style.display='none';
   const sx=document.getElementById('stalex');
   if(sx)sx.addEventListener('click',()=>{
     localStorage.setItem('idl_staleban',sv);st.style.display='none';});
 }

 // ---- settings sheet ---------------------------------------------------
 const sheet=document.getElementById('sheet');
 const ame=document.getElementById('ame');
 const amm=document.getElementById('amm'),amc=document.getElementById('amc');
 const openSheet=to=>{sheet.classList.add('on');
   const nb=to&&sheet.querySelector('nav button[data-s="'+to+'"]'); if(nb)nb.click();
   const f=sheet.querySelector('section.on input,section.on select'); if(f)f.focus();};
 // The panel is rendered ONCE, server-side. Closing it only hid it, so an
 // abandoned edit stayed in the DOM: reopening showed the edited value as if
 // it were the saved config, and the next Save posted it. Closing discards.
 const eachField=(root,fn)=>root.querySelectorAll('input,select').forEach(fn);
 // Takes a root, because the settings sheet is not the only panel rendered
 // once and merely hidden on close. The add-tracker dialog is the same shape,
 // and fixing only the sheet left its twin next door still remembering.
 const resetFields=root=>eachField(root,el=>{
   if(el.type==='checkbox'||el.type==='radio')el.checked=el.defaultChecked;
   else if(el.tagName==='SELECT')
     Array.from(el.options).forEach(o=>{o.selected=o.defaultSelected;});
   else el.value=el.defaultValue;});
 // After a save the DOM holds the new truth but the markup defaults still hold
 // the old one, so without this the next close would revert what you just saved.
 const keepAsSaved=root=>eachField(root,el=>{
   if(el.type==='checkbox'||el.type==='radio')el.defaultChecked=el.checked;
   else if(el.tagName==='SELECT')
     Array.from(el.options).forEach(o=>{o.defaultSelected=o.selected;});
   else el.defaultValue=el.value;});
 const closeSheet=()=>{sheet.classList.remove('on');resetFields(sheet);};
 document.getElementById('gear').addEventListener('click',()=>openSheet());
 document.getElementById('sx').addEventListener('click',closeSheet);
 sheet.addEventListener('click',e=>{if(e.target===sheet)closeSheet();});
 sheet.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>{
   sheet.querySelectorAll('nav button').forEach(x=>x.classList.remove('on'));
   sheet.querySelectorAll('.pane section').forEach(x=>x.classList.remove('on'));
   b.classList.add('on');
   document.getElementById('s-'+b.dataset.s).classList.add('on');}));
 // The banner lands you on the right section, not merely inside the panel.
 document.querySelectorAll('.js-authcfg').forEach(b=>
   b.addEventListener('click',()=>openSheet('signin')));
 if(amm)amm.addEventListener('change',()=>{
   amc.style.display=amm.value==='none'?'none':'';});

 // ---- sign out ---------------------------------------------------------
 // Two entry points, one behavior: the header icon and the button in
 // Settings -> Sign-in.
 ['amout','hout'].forEach(id=>{const b=document.getElementById(id);
   if(b)b.addEventListener('click',()=>fetch('/logout',{method:'POST'})
     .then(()=>location.href='/login'));});

 // ---- add tracker ------------------------------------------------------
 const tm=document.getElementById('tm'),tme=document.getElementById('tme');
 const tmn=document.getElementById('tmn'),tmi=document.getElementById('tmi');
 // Mirrors slugify() on the server, so what you see is what gets saved.
 // Filled in as you type the name, but only until you edit it yourself —
 // after that the field is yours and typing the name no longer overwrites it.
 // Clearing it hands the job back to the server, which derives the same value.
 const slug=s=>s.toLowerCase().replace(/[^a-z0-9]+/g,'').slice(0,40);
 tmi.addEventListener('input',()=>{tmi.dataset.dirty=tmi.value?'1':'';});
 tmn.addEventListener('input',()=>{
   if(tmi.dataset.dirty!=='1')tmi.value=slug(tmn.value);});
 const closeTrk=()=>{tm.classList.remove('on');resetFields(tm);tmi.dataset.dirty='';};
 document.getElementById('addtrk').addEventListener('click',()=>{
   tme.textContent='';tmi.dataset.dirty='';tm.classList.add('on');tmn.focus();});
 document.getElementById('tmcancel').addEventListener('click',closeTrk);
 // The two ways to add a tracker sat in different places with nothing linking
 // them: this dialog, and Import inside Settings. Offer the other from here.
 document.getElementById('tmimp').addEventListener('click',()=>{
   closeTrk(); openSheet('import');});
 tm.addEventListener('click',e=>{if(e.target===tm)closeTrk();});
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeTrk();});
 document.getElementById('tmsave').addEventListener('click',async()=>{
   tme.textContent='';
   const r=await fetch('/api/tracker',{method:'POST',
     headers:{'Content-Type':'application/json'},
     body:JSON.stringify({name:tmn.value,url:document.getElementById('tmu').value,
       id:tmi.value,inactivity_days:document.getElementById('tmd').value,
       notes:document.getElementById('tmo').value})});
   const d=await r.json().catch(()=>({}));
   if(!r.ok){tme.textContent=d.detail||('failed ('+r.status+')');return;}
   location.reload();
 });

 // ---- import from Prowlarr / Jackett -----------------------------------
 // Names come from an external service, so they are escaped rather than
 // concatenated into innerHTML raw.
 const hesc=s=>String(s==null?'':s).replace(/[&<>"']/g,
   c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const ime=document.getElementById('ime');
 const imlist=document.getElementById('imlist'),imapply=document.getElementById('imapply');
 // Jackett has no usenet indexers, so the box would be a control that does
 // nothing. Disable it and say why, rather than letting a preview come back
 // empty and look like a broken connection.
 const ims=document.getElementById('ims'),impu=document.getElementById('impu');
 const impul=document.getElementById('impul'),impnote=document.getElementById('impnote');
 const imsync=()=>{const jack=ims.value==='jackett';
   impu.disabled=jack; impul.classList.toggle('off',jack);
   impnote.hidden=!jack;};
 ims.addEventListener('change',imsync); imsync();

 const imbody=()=>({source:document.getElementById('ims').value,
   url:document.getElementById('imu').value,
   api_key:document.getElementById('imk').value,
   remember:document.getElementById('imrem').checked,
   protocols:[['impt','torrent'],['impu','usenet']]
     .map(p=>[document.getElementById(p[0]),p[1]])
     .filter(p=>p[0].checked&&!p[0].disabled).map(p=>p[1])});

 const impost=extra=>fetch('/api/import',{method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify(Object.assign(imbody(),extra||{}))});

 // Preview first, always. An API key pointed at the wrong instance should cost
 // a list on screen, not a rewritten config.
 document.getElementById('impreview').addEventListener('click',async()=>{
   ime.textContent='';
   imlist.innerHTML='<div class="r"><span class="nm">checking\\u2026</span></div>';
   imapply.disabled=true;
   const r=await impost(); const d=await r.json().catch(()=>({}));
   if(!r.ok){imlist.innerHTML='';ime.textContent=d.detail||('failed ('+r.status+')');return;}
   const c=d.candidates||[], fresh=c.filter(x=>!x.skip).length;
   imlist.innerHTML=c.length?c.map(x=>'<div class="r"><span class="nm">'+hesc(x.name)
     +'</span><span class="pr">'+hesc(x.protocol||'')+'</span>'
     +(x.skip?'<span class="sk">'+hesc(x.skip)+'</span>'
             :'<span class="new">will add</span>')+'</div>').join('')
     :'<div class="r"><span class="nm">nothing private found for that selection</span></div>';
   imapply.disabled=fresh===0;
   imapply.textContent=fresh?('Import '+fresh):'Import';
 });

 // Applies the remember box on its own. Unticking it does nothing until this
 // is pressed: a checkbox that destroys a stored credential the moment it is
 // clicked leaves no chance to change your mind and says nothing about what
 // it did.
 const imsave=document.getElementById('imsave');
 if(imsave)imsave.addEventListener('click',async()=>{
   const on=document.getElementById('imrem').checked;
   imsave.disabled=true; ime.className='e'; ime.textContent='saving\u2026';
   try{
     const r=await fetch('/api/import',{method:'POST',
       headers:{'Content-Type':'application/json'},
       body:JSON.stringify({set_remember:on})});
     if(!r.ok){const d=await r.json().catch(()=>({}));
               ime.textContent=d.detail||('failed ('+r.status+')');
               imsave.disabled=false;return;}
     ime.className='e good';
     ime.textContent=on?'the key from your next import will be stored'
                       :'saved key removed';
     imsave.disabled=false;
   }catch(e){ime.textContent='failed: '+e.message;imsave.disabled=false;}
 });

 imapply.addEventListener('click',async()=>{
   ime.textContent='';ime.className='e';imapply.disabled=true;
   const r=await impost({apply:true}); const d=await r.json().catch(()=>({}));
   if(!r.ok){ime.textContent=d.detail||('failed ('+r.status+')');imapply.disabled=false;return;}
   // The response says what happened per tracker. Reloading regardless made a
   // total failure look exactly like success: the page came back with nothing
   // added and no reason given anywhere.
   const added=(d.added||[]).length, failed=d.failed||[];
   if(failed.length){
     ime.textContent=added+' added, '+failed.length+' failed: '
       +failed.map(f=>hesc(f.id)+': '+hesc(f.error)).join('; ');
     imapply.disabled=false;return;}
   if(!added){
     ime.textContent='nothing added: every tracker found is already configured';
     imapply.disabled=false;return;}
   location.reload();
 });

 // ---- notification destinations ---------------------------------------
 // Delegated from the list, so rows added after load are wired without a
 // second registration path that could drift from this one.
 const nde=document.getElementById('nde');
 const ndsay=(m,good)=>{if(nde){nde.className=good?'e good':'e';nde.textContent=m;}};
 const ndlist=document.querySelector('.ndlist');
 if(ndlist)ndlist.addEventListener('click',async(ev)=>{
   const b=ev.target.closest('button[data-act]'); if(!b)return;
   const row=b.closest('.nd'), id=row&&row.dataset.id; if(!id)return;
   const act=b.dataset.act, was=b.textContent;
   b.disabled=true; ndsay('');
   try{
     let r;
     if(act==='del'){
       // Two-step. A removed destination cannot be undone from the page: the
       // URL is never rendered back, so there is nothing left to retype from.
       if(b.dataset.arm!=='1'){
         b.dataset.arm='1';b.classList.add('arm');b.textContent='Confirm';
         b.disabled=false;return;
       }
       r=await fetch('/api/notify/'+encodeURIComponent(id),{method:'DELETE'});
     }else if(act==='toggle'){
       r=await fetch('/api/notify/'+encodeURIComponent(id),{method:'POST',
         headers:{'Content-Type':'application/json'},
         body:JSON.stringify({enabled:was!=='On'})});
     }else{
       b.textContent='Sending\u2026';
       r=await fetch('/api/notify/'+encodeURIComponent(id)+'/test',{method:'POST'});
     }
     const d=await r.json().catch(()=>({}));
     if(!r.ok){b.textContent=was;b.disabled=false;
              b.dataset.arm='';b.classList.remove('arm');
              ndsay(d.detail||('failed ('+r.status+')'));return;}
     if(act==='test'){b.textContent='Sent';b.disabled=false;
                      setTimeout(()=>b.textContent=was,1800);
                      ndsay('sent, check that destination',true);return;}
     location.reload();
   }catch(e){b.textContent=was;b.disabled=false;ndsay('failed: '+e.message);}
 });

 const ndadd=document.getElementById('ndadd');
 if(ndadd)ndadd.addEventListener('click',async()=>{
   const url=document.getElementById('ndurl').value.trim();
   if(!url){ndsay('paste an Apprise URL first');return;}
   ndadd.disabled=true;ndsay('checking\u2026');
   try{
     const r=await fetch('/api/notify',{method:'POST',
       headers:{'Content-Type':'application/json'},
       body:JSON.stringify({url:url,name:document.getElementById('ndname').value})});
     const d=await r.json().catch(()=>({}));
     if(!r.ok){ndadd.disabled=false;ndsay(d.detail||('failed ('+r.status+')'));return;}
     location.reload();
   }catch(e){ndadd.disabled=false;ndsay('failed: '+e.message);}
 });

 const ntest=document.getElementById('ntest'),nte=document.getElementById('nte');
 if(ntest)ntest.addEventListener('click',async()=>{
   nte.className='e';nte.textContent='sending\u2026';ntest.disabled=true;
   const r=await fetch('/api/test-notify',{method:'POST'});
   const d=await r.json().catch(()=>({}));
   ntest.disabled=false;
   if(r.ok){nte.className='e good';nte.textContent='sent, check your device';}
   else{nte.textContent=d.detail||('failed ('+r.status+')');}
 });

 // ---- run the daily check now -----------------------------------------
 // Reloads on success rather than patching the four activity rows and the
 // next-run line by hand. paint() drifting from the cells the server renders
 // is a bug this project has already shipped once; there is nothing to gain
 // by growing a second copy of that markup here.
 const ckrun=document.getElementById('ckrun'),cke=document.getElementById('cke');
 if(ckrun)ckrun.addEventListener('click',async()=>{
   cke.className='e';cke.textContent='running\u2026';ckrun.disabled=true;
   try{
     const r=await fetch('/api/check',{method:'POST'});
     const d=await r.json().catch(()=>({}));
     if(r.ok){cke.className='e good';cke.textContent='done, reloading\u2026';
              location.reload();return;}
     cke.textContent=d.detail||('failed ('+r.status+')');
   }catch(e){cke.textContent='failed: '+e.message;}
   ckrun.disabled=false;
 });

 // ---- restore a config ------------------------------------------------
 const cfgUp=document.getElementById('cfgUp'),cfgFile=document.getElementById('cfgFile');
 if(cfgUp){
   cfgUp.addEventListener('click',()=>cfgFile.click());
   cfgFile.addEventListener('change',async()=>{
     const f=cfgFile.files[0]; if(!f)return;
     const err=document.getElementById('setErr');
     err.className='e';err.textContent='reading '+f.name+'\u2026';
     const text=await f.text();
     const r=await fetch('/api/config',{method:'POST',
       headers:{'Content-Type':'application/json'},body:JSON.stringify({yaml:text})});
     const d=await r.json().catch(()=>({}));
     cfgFile.value='';
     if(!r.ok){err.textContent=d.detail||('failed ('+r.status+')');return;}
     err.className='e good';
     err.textContent=d.before+' \u2192 '+d.after+' trackers; previous saved as '+d.backup;
     setTimeout(()=>location.reload(),1200);
   });
 }

 // ---- general settings -------------------------------------------------
 const setSave=document.getElementById('setSave'),setErr=document.getElementById('setErr');
 if(setSave)setSave.addEventListener('click',async()=>{
   setErr.className='e';setErr.textContent='saving\u2026';setSave.disabled=true;
   const r=await fetch('/api/settings',{method:'POST',
     headers:{'Content-Type':'application/json'},
     body:JSON.stringify({timezone:document.getElementById('setTz').value,
       check_hour:document.getElementById('setHour').value,
       alert_at_pct:document.getElementById('setPct').value,
       alive_push_days:document.getElementById('setAlive').value,
       backup_keep:document.getElementById('setKeep').value,
       status_url:document.getElementById('setUrl').value})});
   const d=await r.json().catch(()=>({}));
   setSave.disabled=false;
   if(!r.ok){setErr.textContent=d.detail||('failed ('+r.status+')');return;}
   setErr.className='e good';setErr.textContent='Saved';
   keepAsSaved(document.getElementById('s-general'));
   setTimeout(()=>{if(setErr.textContent==='Saved')setErr.textContent='';},3000);
   // Timezone and the alert threshold change day counting, so the rows behind
   // the panel are now stale. Repaint them in place rather than reloading:
   // a reload closes the panel, which makes changing two settings in a row
   // needlessly tedious.
   try{
     const rows=await (await fetch('/api/status')).json();
     rows.forEach(row=>{const tr=document.getElementById('t-'+row.id);
       if(tr){tr.dataset.row=JSON.stringify(row);paint(tr,row);}});
   }catch(e){/* the panel still saved; the table just repaints on next load */}
 });

 // ---- read-only API key ------------------------------------------------
 const apik=document.getElementById('apik'), apie=document.getElementById('apie');
 // ---- reveal the key --------------------------------------------------
 // type=password is shoulder-surfing cover, not secrecy: the value is in the
 // page source either way, because Copy has to be able to read it. What it
 // stops is the key sitting on screen during a screen-share or a screenshot.
 const apieye=document.getElementById('apieye'), apik0=document.getElementById('apik');
 if(apieye&&apik0)apieye.addEventListener('click',()=>{
   const show=apik0.type==='password';
   apik0.type=show?'text':'password';
   apieye.classList.toggle('on',show);
   apieye.title=apieye.ariaLabel=show?'hide the key':'show the key';
 });

 const apicopy=document.getElementById('apicopy'), apinew=document.getElementById('apinew');
 if(apicopy)apicopy.addEventListener('click',()=>{
   const done=()=>{const o=apicopy.textContent;
     apicopy.textContent='Copied';setTimeout(()=>apicopy.textContent=o,1600);};
   if(navigator.clipboard)navigator.clipboard.writeText(apik.value).then(done,()=>{});
   else{apik.select();document.execCommand('copy');done();}});
 if(apinew)apinew.addEventListener('click',async()=>{
   // Two-step. Regenerating silently breaks every widget already using it, and
   // there is no undo: the old value is gone the moment the server writes.
   if(apinew.dataset.arm!=='1'){
     apinew.dataset.arm='1'; apinew.classList.add('arm');
     apinew.textContent='Confirm';
     apie.className='e warn';
     apie.textContent='This breaks anything already using the current key.';
     setTimeout(()=>{if(apinew.dataset.arm==='1'){apinew.dataset.arm='';
       apinew.classList.remove('arm');apinew.textContent='Regenerate';
       apie.textContent='';apie.className='e';}},6000);
     return;}
   apinew.dataset.arm=''; apinew.classList.remove('arm');
   apinew.textContent='Regenerate'; apie.className='e'; apie.textContent='';
   try{const d=await post('/api/apikey');
     apik.value=d.api_key; apie.className='e good'; apie.textContent='New key generated';
     // Keep it as the value a close would restore to, or reopening Settings
     // would show the previous key as though nothing had changed.
     apik.defaultValue=d.api_key;
     setTimeout(()=>{if(apie.textContent==='New key generated')apie.textContent='';},4000);}
   catch(e){apie.className='e bad';apie.textContent=e.message;}});

 const cpjs=document.getElementById('cpjs');
 if(cpjs)cpjs.addEventListener('click',()=>{
   const u=cpjs.dataset.u, done=()=>{const o=cpjs.textContent;
     cpjs.textContent='Copied';setTimeout(()=>cpjs.textContent=o,1600);};
   // clipboard API needs a secure context; plenty of these run on plain http
   // over a LAN or tailnet, so fall back rather than failing silently.
   if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(u).then(done);}
   else{const t=document.createElement('textarea');t.value=u;document.body.appendChild(t);
     t.select();try{document.execCommand('copy');done();}finally{t.remove();}}
 });

 document.getElementById('amsave').addEventListener('click',async()=>{
   ame.textContent='';
   const body={method:amm.value,
     username:document.getElementById('amu').value,
     password:document.getElementById('amp').value,
     current_password:document.getElementById('amx').value};
   const r=await fetch('/api/auth',{method:'POST',
     headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
   const d=await r.json().catch(()=>({}));
   if(!r.ok){ame.textContent=d.detail||('failed ('+r.status+')');return;}
   // The method changed, so the dismissed-banner memory is stale.
   localStorage.removeItem('idl_authban');
   location.reload();
 });
})();
</script></body></html>"""

# The unit printed under each countdown. Mirrored by LABEL in the page's JS,
# which repaints that cell after an edit; a test asserts the two agree by
# VALUE, not just by key -- they had drifted on `immune` while both sat unused.
LABELS = {"ok": "days left", "due": "days left", "warn": "days left",
          "critical": "days left", "expired": "days over", "session": "re-auth",
          "unknown": "no data", "immune": "exempt", "snoozed": "days left"}
RANK = {"expired": 0, "session": 1, "critical": 2, "warn": 3, "due": 4,
        "unknown": 5, "ok": 6, "snoozed": 7, "immune": 8}

# What a state is CALLED on screen, where that differs from what it is called
# in the code. `session` is the one that needed it: the state means the
# userscript saw a visit but no authenticated session — your login cookie
# died — and "session" named the mechanism rather than the problem. The key
# stays `session` everywhere else, so RANK, --session, /api/status and every
# test keep working. Mirrored by SLBL in the page's JS; agreement is tested.
STATE_LABEL = {"session": "logged out"}


def _pct(r: dict) -> float:
    if r["days_left"] is None or r["days_since"] is None:
        return 0.0
    return min(max(r["days_since"] / max(r["inactivity_days"], 1), 0), 1) * 100


def _ago(d) -> str:
    return "never" if d is None else ("today" if d == 0 else f"{d}d ago")


def esc(s) -> str:
    return html_escape(str(s), quote=True)


def _row(label: str, hint: str, control: str) -> str:
    """One settings row: label and help on the left, control in the fixed-width
    column on the right. Every control shares that column — letting each size
    itself is what staggered them down the panel."""
    sub = f"<span>{hint}</span>" if hint else ""
    return (f'<div class="row"><div class="lbl"><b>{label}</b>{sub}</div>'
            f'<div class="ctl2">{control}</div></div>')


def _tz_options(current: str) -> str:
    """Every zone this Python knows, grouped by region.

    Free text was wrong twice over: a typo is only caught on Save (the endpoint
    does validate), and nobody remembers whether it is America/Sao_Paulo or
    America/Sao Paulo. Grouped because a flat list of ~500 is a scroll, not a
    choice.

    `current` is always present even if this build's tzdata does not know it, 
    otherwise opening Settings on a config written elsewhere would silently
    reselect the first zone in the list and change every countdown on Save.
    """
    try:
        zones = sorted(z for z in zoneinfo.available_timezones() if "/" in z)
    except Exception:                       # no tzdata: still offer UTC
        zones = []
    if current and current != "UTC" and current not in zones:
        zones = sorted(zones + [current])
    sel = lambda z: " selected" if z == current else ""
    out = [f'<option value="UTC"{sel("UTC")}>UTC</option>']
    region = None
    for z in zones:
        r = z.split("/", 1)[0]
        if r != region:
            if region is not None:
                out.append("</optgroup>")
            out.append(f'<optgroup label="{esc(r)}">')
            region = r
        out.append(f'<option value="{esc(z)}"{sel(z)}>{esc(z)}</option>')
    if region is not None:
        out.append("</optgroup>")
    return "".join(out)


def _act_row(label: str, job: str, sub: str = "",
             extra: tuple[str, bool] | None = None) -> str:
    """One line of the recent-activity block: when it last ran and how it went.

    "never" is meaningful rather than missing: a backup that has never run on
    an install that is days old is exactly the kind of quiet failure the
    dashboard could not previously show.

    `sub` matters more than it looks. Every row here is a timestamp with no
    context, and three of the four carry the SAME timestamp because they happen
    inside one another — which reads as a bug until something says otherwise.
    """
    a = read_activity(job)
    # The next-run line shows even when nothing has ever run. On a fresh
    # install "never" is the whole story otherwise, and "never" plus a date is
    # what tells you the thing is scheduled rather than broken.
    nxt = ""
    if extra:
        text, overdue = extra
        nxt = f'<em class="act-d{" due" if overdue else ""}">{esc(text)}</em>'
    if not a:
        return _row(label, sub, f'<span class="val">never</span>{nxt}')
    cls = "on" if a.get("ok") else "off"
    detail = esc(a.get("detail", ""))
    return _row(label, sub,
                f'<span class="val {cls}">{esc(a.get("at", ""))}</span>'
                f'<em class="act-d">{detail}</em>{nxt}')


EYE_ICON = ('<svg class="i-show" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>')

EYEOFF_ICON = ('<svg class="i-hide" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.9 17.9A10.1 10.1 0 0 1 12 20c-7 0-11-8-11-8a18.5 18.5 0 0 1 5.1-5.9M9.9 4.2A9.1 9.1 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2m-6.7-1.1a3 3 0 1 1-4.2-4.2"/><line x1="1" y1="1" x2="23" y2="23"/></svg>')


def settings_sheet(method: str, n_trk: int, n_hosts: int, js_url: str,
                   script_ver: str = "", last_check: str = "") -> str:
    """The settings panel. Rendered here rather than in PAGE because most of it
    is live state, and because the sections that carry forms need the current
    values to be correct on first paint."""
    cfg = load_config()
    user = get_state("auth_user", "") or ""
    last = get_state("last_check", "") or "not yet"
    try:
        db_kb = f"{DB_PATH.stat().st_size // 1024} KB"
    except OSError:
        db_kb = "unknown"

    # --- general: editable, written back to the defaults block in
    #     trackers.yml. Range-checked server-side in /api/settings — these
    #     drive day counting and alert timing, so a bad value is not a crash,
    #     it is a countdown that reads plausibly and fires at the wrong time.
    alive = int(cfg.get("alive_push_days", 0))
    alive_opts = "".join(
        f'<option value="{v}"{" selected" if alive == v else ""}>{label}</option>'
        for v, label in ((0, "Off"), (1, "Daily"), (7, "Weekly"), (30, "Monthly")))

    # Hours are shown in both notations rather than behind a 12/24 preference:
    # one setting to serve one number is not worth the surface, and a reader
    # who thinks in either format gets an unambiguous answer.
    hour_now = int(cfg["check_hour"])
    hour_opts = "".join(
        f'<option value="{h}"{" selected" if hour_now == h else ""}>'
        f'{h:02d}:00 &nbsp;&middot;&nbsp; {(h % 12) or 12} {"am" if h < 12 else "pm"}'
        f'</option>' for h in range(24))

    # Percent, not a bare fraction. 0.65 asks the reader to convert; "65%" does
    # not. The stored value stays a float, so nothing downstream changes.
    pct_now = float(cfg.get("alert_at_pct", 0.65))
    pct_opts = "".join(
        f'<option value="{v/100:.2f}"{" selected" if abs(pct_now - v/100) < 0.001 else ""}>'
        f'{v}%</option>' for v in range(40, 100, 5))
    general = (
        _row("Timezone", "All day counting is calendar days in this zone.",
             f'<select id="setTz">{_tz_options(cfg["timezone"])}</select>')
        + _row("Daily check hour",
               "When the check runs and alerts batch into one push.",
               f'<select id="setHour">{hour_opts}</select>')
        + _row("Alert threshold",
               "How much of a tracker's limit may pass before <em>due</em> "
               "fires. Lower means earlier nagging on long limits.",
               f'<select id="setPct">{pct_opts}</select>')
        + _row("Still-alive push",
               "Nothing else watches the watchdog. If this container dies the "
               "daily check stops and silence looks exactly like nothing being "
               "due. The first one arrives shortly after you switch this on, so "
               "you know it works; after that they land with the daily check.",
               f'<select id="setAlive">{alive_opts}</select>')
        + _row("", "", '<button class="lk pri" id="setSave">Save</button>')
        + '<p class="e" id="setErr"></p>'
        # "Nightly backup" was wrong — it runs inside the daily check, not at
        # night — and "Last alert" implied one had been sent when the row
        # records only that the step ran.
        + _row("Status page URL",
               "The address you reach this page on. The generated userscript "
               "reports here, and alerts link to it. Wrong, and tracker CSP "
               "blocks every ping.",
               f'<input id="setUrl" class="w-grow" value="{esc(status_url())}" '
               f'placeholder="https://idlarr.example.ts.net">')
        + _row("Backup retention",
               "Kept in /data/backups, one per day. 0 disables them.",
               f'<input id="setKeep" class="w-num" value="{backup_keep()}">'
               f'<em class="act-d" style="width:auto;margin:0">days</em>')
        + '<p class="sub" style="margin:15px 0 0">Written to '
          '<code>trackers.yml</code>, which is hot-reloaded, only a timezone '
          'change needs a restart to affect an already-running check.</p>')

    # Split out of General 2026-08-06: that pane had grown to hold a form, a
    # read-only activity log and two file actions, which are three different
    # questions. Everything the Save button posts stays together in General;
    # what moved here is what the service DID and the files behind it.
    system = (
        _act_row("Daily check", "check",
                 "Runs at the check hour. The two below happen inside it, "
                 "which is why they share its timestamp.",
                 extra=next_check())
        + _act_row("Database backup", "backup",
                   "Taken at the start of the check, before any alert, so a "
                   "failed backup can never stop one.")
        + _act_row("Notification", "alert",
                   "Only sends when something is due. <b>nothing due</b> means "
                   "it ran and there was nothing to tell you.")
        + _act_row("Heartbeat", "heartbeat",
                   "Separate from the check: a low-priority push so that "
                   "silence from Idlarr means the container is down.")
        + _row("Run the check now",
               "Backs up, evaluates every countdown and sends anything due, "
               "exactly as the scheduled run does. Use it after a restart that "
               "spanned the check hour. It counts as today's run, so the "
               "scheduled one will not fire again today. It does not send a "
               "heartbeat.",
               '<button class="lk" id="ckrun">Run now</button>')
        + '<p class="e" id="cke"></p>'
        + _row("Your config",
               "Download <code>trackers.yml</code> exactly as it is on disk, "
               "comments and all. Restoring replaces it: the current file is "
               "saved alongside as a <code>.bak</code> first.",
               '<a class="lk" href="/api/config" download>Download</a>'
               '<button class="lk" id="cfgUp">Restore\u2026</button>'
               '<input type="file" id="cfgFile" accept=".yml,.yaml,text/yaml" '
               'style="display:none">'))

    # --- sign-in: the form that used to be its own modal. Same element ids, so
    #     the handlers did not have to change.
    # Default the dropdown to Forms when nothing is configured. Selecting the
    # CURRENT method means "None" is pre-selected on a fresh install, so
    # filling in a username and password and pressing Save posts method=none —
    # the server clears an already-empty sign-in, the page reloads, and nothing
    # has changed. A silent no-op on the one control whose whole job is to stop
    # the dashboard being open.
    shown = method if method != "none" else "forms"
    sel = lambda v, t: f'<option value="{v}"{" selected" if shown == v else ""}>{t}</option>'
    signin = (
        _row("Status",
             "Anyone who can reach this page can reset a countdown or rewrite "
             "your limits." if method == "none" else
             "The page and every write endpoint require this.",
             f'<span class="val off">not configured</span>' if method == "none"
             else f'<span class="val on">{esc(user)} &middot; {esc(method)}</span>')
        + _row("Method", "Forms shows a login page; Basic uses the browser prompt.",
               f'<select id="amm">{sel("forms", "Forms")}{sel("basic", "Basic")}'
               f'{sel("none", "None")}</select>')
        + f'<div id="amc">'
          f'{_row("Username", "", f"""<input id="amu" value="{esc(user)}" autocomplete="username">""")}'
          f'{_row("Password", "8 characters minimum.", """<input id="amp" type="password" autocomplete="new-password">""")}'
          f'</div>'
        + (_row("Current password", "Required to change or remove a sign-in.",
                '<input id="amx" type="password" autocomplete="current-password">')
           if method != "none" else '<input id="amx" type="hidden">')
        + _row("", "Changing this signs every other browser out. Forgotten it? "
                   "Restart once with this set, then remove it: "
                   "<code>IDLARR_RESET_AUTH=1</code>",
               # Forms only, same reason as the header icon: HTTP Basic
               # re-sends its credentials on every request, so signing out
               # cannot work and the button would do nothing visible.
               ('<button class="lk" id="amout">Sign out</button>' if method == "forms" else "")
               + '<button class="lk pri" id="amsave">Save</button>')
        + '<p class="e" id="ame"></p>')

    script = (
        _row("Covers", "One @match and one SITES entry per tracker with a host.",
             f'<span class="val on">{n_hosts} tracker'
             f'{"" if n_hosts == 1 else "s"}</span>')
        + _row("Endpoint", "Where the script reports. From the status page URL.",
               f'<span class="val">{esc(host_from_url(status_url())) or "not set"}</span>')
        + (_row("Install", "Any userscript manager (Violentmonkey, Tampermonkey, "
                           "Greasemonkey) installs from this link.",
                f'<a class="lk pri" href="{esc(js_url)}">Install</a>'
                f'<button class="lk" id="cpjs" data-u="{esc(js_url)}">Copy URL</button>')
           if js_url else
           _row("Install", "Set the <b>status page URL</b> above, without it the "
                           "generated script would have nowhere to report.",
                '<span class="val off">unavailable</span>')))

    # A working connection is remembered so a container recreate does not send
    # you back to Prowlarr for the key. The key itself is never sent back to
    # the browser — the field shows that one is saved, and blank means reuse it.
    src, iurl = get_state("import_source", "") or "prowlarr", get_state("import_url", "") or ""
    saved_key = bool(get_state("import_key"))
    # Stored, so the box still reads as you left it after a reload. Derived
    # from "is a key saved" instead, a fresh install and one you had just
    # cleared would render identically while meaning opposite things.
    remember_on = get_state("import_remember", "1") != "0"
    opt = lambda v, t: f'<option value="{v}"{" selected" if src == v else ""}>{t}</option>'
    imp = (
        '<div class="stack">'
        f'<select id="ims">{opt("prowlarr", "Prowlarr")}{opt("jackett", "Jackett")}</select>'
        f'<input id="imu" placeholder="http://prowlarr.local:9696" value="{esc(iurl)}">'
        f'<input id="imk" type="password" autocomplete="off" placeholder="'
        f'{"saved &mdash; leave blank to reuse" if saved_key else "API key"}">'
        '</div>'
        # Two boxes, not one per site. The decision is which KIND of account to
        # watch; per-indexer ticking would be twenty controls answering a
        # question already answered. Both on, because excluding usenet by
        # default is the behavior this is fixing.
        '<div class="improt">'
        '<label><input type="checkbox" id="impt" checked> Torrent</label>'
        '<label id="impul"><input type="checkbox" id="impu" checked> Usenet</label>'
        # All three boxes share one left edge: they are one set of options, not
        # three scattered decisions. Save carries `lk pri` like the Save in
        # General and Sign-in, and margin-left:auto puts its right edge on the
        # pane edge, which is exactly where the full-width key field above ends.
        f'<label><input type="checkbox" id="imrem"'
        f'{" checked" if remember_on else ""}> Remember this key</label>'
        '<button class="lk pri" id="imsave">Save</button>'
        '</div>'
        # Below the row rather than in it. It used margin-left:auto to sit at
        # the right end, which is now Save's edge, and two things claiming one
        # edge means each moves whenever the other appears.
        # Only shown once it applies. Sitting there permanently, it read as a
        # fact about the panel rather than an explanation of a disabled box.
        '<p class="impnote" id="impnote" hidden>Jackett indexes torrents only, '
        'so there is no usenet to fetch. Switch the source to Prowlarr for '
        'that.</p>'
        '<div class="imlist" id="imlist"></div>'
        + _row("", "Preview first. Nothing is written until you confirm.",
               '<button class="lk" id="impreview">Preview</button>'
               '<button class="lk pri" id="imapply" disabled>Import</button>')
        # The Saved connection row and its Forget button are gone: unticking
        # `Remember this key` and pressing Save does the same thing, and two
        # controls for one outcome is how one of them ends up stale.
        + '<p class="e" id="ime"></p>')

    # Destinations are listed, not hidden behind a count. The count alone could
    # not tell you WHICH one was failing, and with the URL masked there is
    # nothing sensitive about showing that a Discord destination exists.
    rows = []
    for d in notify_dests():
        off = not d.get("enabled", True)
        rows.append(
            f'<div class="nd{" off" if off else ""}" data-id="{esc(d["id"])}">'
            f'<span class="nd-n">{esc(d.get("name") or scheme_name(d["url"]))}</span>'
            f'<span class="nd-u">{esc(mask_url(d["url"]))}</span>'
            f'<button class="lk" data-act="toggle">{"Off" if off else "On"}</button>'
            f'<button class="lk" data-act="test">Test</button>'
            f'<button class="lk" data-act="del">Remove</button></div>')
    # Env-sourced ones are shown so the list is not a lie about what will
    # receive, but they are not editable here: they belong to .env.
    for url in NOTIFY_ENV:
        rows.append(
            '<div class="nd env">'
            f'<span class="nd-n">{esc(scheme_name(url))}</span>'
            f'<span class="nd-u">{esc(mask_url(url))}</span>'
            '<span class="nd-src">from .env</span></div>')

    notify = (
        _row("Destinations",
             "Where alerts go. Each one is an Apprise URL, so anything Apprise "
             "supports works: ntfy, Discord, Telegram, Pushover, Gotify, email.",
             f'<span class="val {"on" if notify_urls() else "off"}">'
             f'{len(notify_urls())} destination'
             f'{"" if len(notify_urls()) == 1 else "s"}</span>')
        + (f'<div class="ndlist">{"".join(rows)}</div>' if rows else
           '<p class="sub" style="margin:0 0 14px">Nothing configured, so '
           'alerts have nowhere to go.</p>')
        # One row, not two. The fields sat in the 200px control column, which is
        # far too narrow for an Apprise URL, and the name ended up stranded on
        # a row of its own with the whole left half empty.
        + ('<div class="row wide"><div class="lbl"><b>Add one</b><span>'
           'Paste an Apprise URL, for example '
           '<code>discord://webhook_id/webhook_token</code> or '
           '<code>ntfy://your-topic</code>. A name is optional and is only a '
           'label. It is checked with Apprise before it is saved.'
           '</span></div>'
           '<div class="ndform">'
           '<input id="ndurl" class="f2" placeholder="scheme://..." '
           'autocomplete="off" spellcheck="false">'
           '<input id="ndname" class="f1" placeholder="name (optional)" '
           'autocomplete="off">'
           '<button class="lk pri" id="ndadd">Add</button></div></div>')
        + '<p class="e" id="nde"></p>'
        + _row("Send a test",
               "Goes to every destination at once. Test a single one from its "
               "own row above, which is the only way to learn WHICH is failing.",
               '<button class="lk" id="ntest">Send test</button>')
        + '<p class="e" id="nte"></p>'
        + '<p class="sub" style="margin:15px 0 0">A destination added here is '
          'stored in the database, so it is in every nightly backup. To keep '
          'credentials out of <code>/data</code> entirely, list them in '
          '<code>IDLARR_NOTIFY_URLS</code> in <code>.env</code> instead: both '
          'sources are used, and neither replaces the other. Saved URLs are '
          'never shown again, only their scheme.</p>')

    about = (
        _row("Version", "", f'<span class="val">{IDLARR_VERSION}</span>')
        + _row("Trackers", "", f'<span class="val">{n_trk}</span>')
        # Both moved off the status line under the table, which was four
        # unrelated facts in a row nobody read. They are reference values, and
        # reference values belong in About.
        + _row("Userscript", "Version served to Violentmonkey. Bumps when you "
               "add or remove a tracker.",
               f'<span class="val">{esc(script_ver)}</span>')
        + _row("Last check", "The daily pass that evaluates every countdown "
               "and sends the batched alert.",
               f'<span class="val">{esc(last_check)}</span>')
        + _row("Database", "Backed up once a day, inside the check.", f'<span class="val">{db_kb}</span>')
        + _row("Uptime check",
               "/healthz needs no credentials, so a monitor can reach it.",
               '<a class="lk" href="/healthz" target="_blank" rel="noreferrer">/healthz</a>')
        + '<p class="sub" style="margin:15px 0 0">Idlarr never contacts a tracker. '
          'A userscript already running in your browser reports when you were '
          'seen logged in; the service does the rest.</p>')

    # The key is SHOWN, unlike auth_hash and unlike import_key. It has to be
    # copied into a widget's config, so hiding it would just mean a Reveal
    # button that everyone clicks. What it can do is bounded instead: reads
    # only, and it cannot rotate itself.
    api = (
        _row("Read-only key",
             "For dashboards and monitors. Send it as <code>X-Api-Key</code> or "
             "<code>?apikey=</code>. It cannot change anything.",
             f'<input id="apik" type="password" readonly autocomplete="off" '
             f'class="keyf" value="{esc(api_key())}">'
             '<button class="lk ico" id="apieye" title="show the key" '
             'aria-label="show the key">' + EYE_ICON + EYEOFF_ICON + '</button>')
        + _row("", "Regenerate if it leaks. The old key stops working "
                   "immediately and anything using it will need the new one.",
               '<button class="lk" id="apicopy">Copy</button>'
               '<button class="lk" id="apinew">Regenerate</button>')
        + _row("Endpoint", "The stable one. <code>/api/status</code> exists but "
                           "its shape follows the page, so it can change.",
               '<span class="val">/api/summary</span>')
        + '<p class="e" id="apie"></p>')

    sections = [
        ("general", "General", "Everything that applies to the whole install.", general),
        ("signin", "Sign-in", "Stored hashed in the database, not in a file.", signin),
        ("script", "Userscript", "Generated from your tracker list. Nothing to fill "
         "in, and it updates itself when you add a tracker.", script),
        ("import", "Import", "Reads your own Prowlarr or Jackett, never a tracker. "
         "Limits are not imported, because neither tool knows them, so "
         "everything arrives at 30 days, unconfirmed.", imp),
        ("notify", "Notifications", "Every alert goes through Apprise.", notify),
        ("api", "API", "A read-only key so other services can read your "
         "status. It can never write, so a leaked key cannot reset a "
         "countdown.", api),
        ("system", "System", "What the unattended jobs did, and the files "
         "behind them.", system),
        ("about", "About", "", about),
    ]
    nav = "".join(
        f'<button{" class=\"on\"" if i == 0 else ""} data-s="{k}">{t}</button>'
        for i, (k, t, _, _) in enumerate(sections))
    panes = "".join(
        f'<section{" class=\"on\"" if i == 0 else ""} id="s-{k}"><h4>{t}</h4>'
        f'{f"<p class=\"sub\">{sub}</p>" if sub else ""}{body}</section>'
        for i, (k, t, sub, body) in enumerate(sections))
    return (f'<div class="sheet" id="sheet"><div class="win">'
            f'<button class="xclose" id="sx" aria-label="close">&times;</button>'
            f'<nav>{nav}</nav><div class="pane">{panes}</div></div></div>')


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not authed(request):
        if auth_method() == "basic":
            raise HTTPException(401, "authentication required",
                                headers={"WWW-Authenticate": 'Basic realm="Idlarr"'})
        return RedirectResponse("/login", status_code=303)

    rows = statuses()
    payloads = [clean(r) for r in rows]

    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    # The total leads the strip: it is the one number that is not a state, so
    # it gets the neutral color and its own divider.
    legend = (f'<div class="tot"><b>{len(rows)}</b><span>trackers</span></div>'
              + "".join(
                  f'<div class="{"zero" if not counts.get(s) else ""}" '
                  f'style="--c:var(--{s})"><b>{counts.get(s, 0)}</b>'
                  f'<span>{STATE_LABEL.get(s, s)}</span></div>'
                  for s in ("expired", "session", "critical", "warn", "due",
                            "unknown", "ok", "snoozed", "immune")))

    body = []
    for r, p in zip(rows, payloads):
        s = r["state"]
        big = ", " if (r["immune"] or r["days_left"] is None) else str(abs(r["days_left"]))
        # The unit is not decoration: "4" under a red dot is ambiguous until it
        # says whether those are days remaining or days already overdue.
        unit = LABELS[s]
        name = (f'<a href="{esc(r["url"])}" target="_blank" rel="noreferrer">{esc(r["name"])}</a>'
                if r["url"] else f'<span class="t">{esc(r["name"])}</span>')
        hand = ' <i title="last auth was marked by hand">&#9998;</i>' if r.get("auth_source") == "manual" else ""
        # Only the FIRST word of notes reaches the row, as the software line, so
        # a note like "lost this once already" changed nothing visible and read
        # as not having saved. This says one exists without putting free text on
        # a fixed-width row; the note itself is the tooltip and the drawer.
        # Deliberately NOT the pencil: that already means "marked by hand", and
        # two identical glyphs meaning different things is worse than neither.
        note = (f'<span class="note" title="{esc(r["notes"])}">'
                '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" '
                'stroke="currentColor" stroke-width="2.4" stroke-linecap="round" '
                'aria-hidden="true"><path d="M5 7h14M5 12h14M5 17h9"/></svg></span>'
                if (r.get("notes") or "").strip() else "")
        q = ("" if (r["verified"] or r["immune"]) else
             '<span class="q" title="limit is a placeholder, not researched">unconfirmed</span>')
        state_txt = (r["immune_reason"] if (r["immune"] and r["immune_reason"])
                     else STATE_LABEL.get(s, s))
        body.append(
            f'<tr class="row" id="t-{esc(r["id"])}" data-nm="{esc(r["name"])}" '
            f'data-sw="{esc(r["software"])}" data-st="{RANK[s]}" data-state="{s}" '
            f'data-seen="{"" if r["days_since"] is None else r["days_since"]}" '
            f'data-left="{"" if r["days_left"] is None else r["days_left"]}" '
            f'data-lim="{r["inactivity_days"]}" '
            f'data-el="{_pct(r):.2f}" '
            f"data-row='{json.dumps(p).replace(chr(39), '&#39;')}' "
            f'style="--c:var(--{s})">'
            f'<td class="s"></td>'
            f'<td class="nm">{name}{hand}{note}'
            f'<span class="m2"><span class="sw">{esc(r["software"])}</span>{q}</span></td>'
            f'<td class="st">{esc(state_txt)}</td>'
            f'<td class="n">{big}<small>{unit}</small></td>'
            f'<td class="el">'
            f'<div class="elm">{_ago(r["days_since"])} &middot; {r["inactivity_days"]}d</div>'
            f'<div class="meter{"" if not (r["immune"] or r["state"] == "snoozed") else " none"}">'
            f'<i style="--p:{0 if r["immune"] else max(3, _pct(r)):.0f}%"></i></div></td></tr>')

    method = auth_method()
    if method == "none":
        # Named consequences, not "consider enabling authentication". The two
        # verbs are the ones that actually cost you something.
        banner = (
            '<div class="banner" id="ban"><b>No sign-in configured.</b> '
            'Anyone who can reach this page can reset a countdown or rewrite '
            'your limits.<span class="sp">'
            '<button class="lk pri js-authcfg">Set one up</button>'
            '<button class="lk" id="banx">Dismiss</button></span></div>')
    else:
        banner = ""

    # An empty config is now the legitimate first-run state, so it must be
    # impossible to confuse with a mis-mounted /config that merely LOOKS new.
    # Name the resolved path on screen, the same way startup names it in the log.
    if not rows:
        # Deliberately does NOT print the resolved path. In a container it is
        # always /config/trackers.yml, so it identifies nothing — the failure
        # is which HOST directory is bound there, which the service cannot see.
        # The startup log carries the resolved path for the cases where it does
        # discriminate (running from source with a custom IDLARR_CONFIG).
        banner += (
            '<div class="banner" id="firstrun"><b>No trackers yet.</b> '
            'Use <b>+ Add tracker</b>, or <b>Import</b> from Prowlarr or '
            'Jackett. Expecting some already? Check your config mount.</div>')

    # The status line is read-only. Actions live in the header and the
    # settings panel now — mixing the two in fixed-width cells is what made the
    # old footer overflow.
    n_hosts = sum(1 for t in load_config()["trackers"] if t.get("host"))
    n_trk = len(load_config()["trackers"])
    _su = status_url()
    js_url = (f"{_su.rstrip('/')}/idlarr.user.js?token={get_token()}" if _su else "")

    # A stale userscript is a SILENT failure and the most expensive kind here:
    # a tracker added after the browser's copy has no @match, so it never pings,
    # sits at `unknown` forever and reads as broken detection rather than as an
    # out-of-date script. Violentmonkey does pick it up on its own via
    # @updateURL, but on its own schedule, so say both.
    stale = userscript_stale()
    if stale and js_url:
        installed, why, dkey = stale
        # Stated as an adjacent fact, not a cause. A tracker that has never
        # reported is what a stale script looks like, but it is also what a
        # broken selector or a site you have not visited looks like, and this
        # cannot tell them apart.
        n_new = sum(1 for r in rows if r["days_since"] is None)
        covers = (f" {n_new} tracker{'' if n_new == 1 else 's'} "
                  f"{'has' if n_new == 1 else 'have'} never reported."
                  if n_new else "")
        banner += (
            f'<div class="banner warn" id="stale" data-v="{esc(dkey)}">'
            '<b>Your userscript is out of date.</b> '
            # The installed version is only known once a browser has reported
            # one. Say nothing about it rather than printing an empty string.
            + (f'The browser has {esc(installed)} and {esc(why)}.'
               if installed else f'{esc(why[0].upper() + why[1:])}.')
            + f'{covers} '
            'Your script manager picks this up on its own next update check, '
            'if automatic updates are switched on.'
            '<span class="sp">'
            f'<a class="lk pri" href="{esc(js_url)}">Update now</a>'
            '<button class="lk" id="stalex">Dismiss</button></span></div>')


    script_ver = userscript_version_peek() if js_url else "not served: no status URL"
    last_check = get_state("last_check", "") or "not yet"

    # Forms only. Under HTTP Basic the browser re-sends the Authorization
    # header on every request, so dropping the session cookie does not sign you
    # out — the next request is authenticated again. A button that visibly does
    # nothing is worse than no button.
    signout = ('<button class="signout" id="hout" title="sign out" aria-label="sign out">'
               '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" '
               'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
               'stroke-linejoin="round" aria-hidden="true">'
               '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
               '<polyline points="16 17 21 12 16 7"/>'
               '<line x1="21" y1="12" x2="9" y2="12"/></svg></button>'
               if method == "forms" else "")

    sheet = settings_sheet(method, n_trk, n_hosts, js_url, script_ver, last_check)

    return (PAGE
            .replace("__ROWS__", "".join(body) or
                     '<tr><td colspan="5"><div class="empty">no trackers configured</div></td></tr>')
            .replace("__LEGEND__", legend)
            .replace("__BANNER__", banner)
            .replace("__SIGNOUT__", signout)
            .replace("__SHEET__", sheet)
            .replace("__AUTHMETHOD__", method))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
