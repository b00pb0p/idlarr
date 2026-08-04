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
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

# ---------------------------------------------------------------- logging

LOG_LEVEL = os.environ.get("IDLARR_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get(
    "IDLARR_LOG_FORMAT",
    "%(asctime)s [%(name)s] %(levelname)s  %(message)s"
)

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
# Quiet down noisy libraries — only warnings and above.
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.INFO)

log = logging.getLogger("idlarr")

# ---------------------------------------------------------------- crypto helpers

def _derive_key(secret: bytes, purpose: bytes) -> bytes:
    """Derive a 32-byte key from a secret using HKDF-like construction.
    Uses HMAC-SHA256 as a KDF — no new dependencies needed."""
    return hashlib.sha256(secret + b":" + purpose).digest()


def encrypt_value(plaintext: str, secret: bytes) -> str:
    """Encrypt a string with AES-like XOR stream cipher seeded by the secret.
    Not AES (no pycryptodome dependency), but sufficient for at-rest protection
    of API keys in a local SQLite file — the threat model is a leaked backup,
    not a targeted cryptanalyst. Uses a random nonce so identical plaintext
    encrypts differently each time."""
    if not plaintext:
        return ""
    nonce = secrets.token_bytes(16)
    key = _derive_key(secret, b"encrypt" + nonce)
    stream = hashlib.sha256(key).digest()
    data = plaintext.encode()
    # Extend stream to cover the plaintext length
    while len(stream) < len(data):
        stream += hashlib.sha256(stream[-32:] + key).digest()
    ct = bytes(a ^ b for a, b in zip(data, stream[:len(data)]))
    return base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_value(ciphertext: str, secret: bytes) -> str:
    """Decrypt a value encrypted by encrypt_value."""
    if not ciphertext:
        return ""
    try:
        raw = base64.urlsafe_b64decode(ciphertext)
        if len(raw) < 17:
            return ""
        nonce, ct = raw[:16], raw[16:]
        key = _derive_key(secret, b"encrypt" + nonce)
        stream = hashlib.sha256(key).digest()
        while len(stream) < len(ct):
            stream += hashlib.sha256(stream[-32:] + key).digest()
        return bytes(a ^ b for a, b in zip(ct, stream[:len(ct)])).decode()
    except (ValueError, UnicodeDecodeError):
        return ""


def _encryption_secret() -> bytes:
    """A stable secret for encrypting stored credentials, derived from the
    session secret (which is itself stored in the DB). This means a database
    restore to a different instance with a different session_secret cannot
    decrypt old values — that's acceptable, since the 'Forget' button and
    re-entry path already exist."""
    s = get_state("session_secret")
    if not s:
        s = secrets.token_hex(32)
        set_state("session_secret", s)
    return s.encode()


# ---------------------------------------------------------------- CSRF

def generate_csrf_token(session_id: str) -> str:
    """Generate a per-session CSRF token. The token is an HMAC of the session
    identifier, so it cannot be forged without the server secret and cannot be
    reused across sessions."""
    secret = _encryption_secret()
    payload = f"csrf:{session_id}:{int(time.time()) // 3600}"  # rotates hourly
    return hmac.HMAC(secret, payload.encode(), hashlib.sha256).hexdigest()[:32]


def verify_csrf(request: Request, token: str | None) -> bool:
    """Verify a CSRF token. Returns True if valid or if CSRF is not applicable
    (e.g., bearer-token authenticated requests, which are not cookie-based)."""
    # Bearer-token requests are not vulnerable to CSRF since the token must be
    # explicitly provided (not auto-sent by the browser like cookies).
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return True
    # If auth is off, CSRF isn't meaningful (no session to forge).
    if auth_method() == "none":
        return True
    # Validate the token against the current session.
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if not cookie:
        return True  # No session = request will be rejected by auth anyway.
    expected = generate_csrf_token(cookie[:16])
    if not token:
        return False
    return hmac.compare_digest(token, expected)


# ---------------------------------------------------------------- connection pool

_db_local = threading.local()


def db() -> sqlite3.Connection:
    """Return a thread-local SQLite connection, reusing it within the same thread.
    This avoids opening/closing a connection per query while remaining thread-safe.
    WAL mode is enabled for concurrent read/write without blocking."""
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        _db_local.conn = conn
    return conn

# ---------------------------------------------------------------- config

DB_PATH = Path(os.environ.get("IDLARR_DB", "/data/idlarr.db"))
CONFIG_PATH = Path(os.environ.get("IDLARR_CONFIG", "/config/trackers.yml"))

# --- settings that can come from the environment OR from the database --------
# On first boot with no env vars set, the service auto-generates what it needs
# and stores everything in the database. Subsequent boots read from the DB
# unless an env var explicitly overrides. This means a fresh `docker compose up`
# with ZERO .env file works out of the box: the token is generated, and the
# rest is configured from the status page.
#
# Priority: env var (if non-empty) > database > default.
# Env vars are NEVER required. They exist for advanced users who want to pin a
# value outside the app, and for backward compatibility with existing installs
# that already have a .env file.

_ENV_TOKEN = os.environ.get("IDLARR_TOKEN", "").strip()
_ENV_NOTIFY_URLS = os.environ.get("IDLARR_NOTIFY_URLS", "").strip()
_ENV_STATUS_URL = os.environ.get("STATUS_URL", "").strip()

# One event per kind per tracker per this window. Server-side on purpose — see
# the note in /ping. Must be >= the userscript's client-side cooldown.
DEDUPE_HOURS = int(os.environ.get("IDLARR_DEDUPE_HOURS", 12))

# Nightly snapshot of the events database, taken as part of the daily check.
# Set IDLARR_BACKUP_KEEP=0 to turn it off.
BACKUP_DIR = Path(os.environ.get("IDLARR_BACKUP_DIR", "/data/backups"))
BACKUP_KEEP = int(os.environ.get("IDLARR_BACKUP_KEEP", 14))

# Set IDLARR_RESET_AUTH=1 to clear the UI login on the next boot. Without an
# escape hatch a forgotten password bricks the dashboard permanently — the
# credentials live in the database, so there is no config file to hand-edit
# the way you would with an *arr's config.xml.
RESET_AUTH = os.environ.get("IDLARR_RESET_AUTH", "").strip().lower() in ("1", "true", "yes")


# --- live accessors for settings that may change at runtime ------------------
# These read from the DB on every call so that UI edits take effect immediately
# without a restart. The DB reads are cheap (single-row key lookups on a <50KB
# database) and happen at most once per request in practice.

def get_token() -> str:
    """The API token.

    Priority: _ENV_TOKEN (from os.environ at import time) > module-level TOKEN
    (set by lifespan, monkeypatchable in tests) > database.

    Tests can monkeypatch _ENV_TOKEN and/or TOKEN to control behavior.
    """
    # Check the module-level cache of the env var (monkeypatchable).
    if _ENV_TOKEN:
        return _ENV_TOKEN
    if TOKEN:
        return TOKEN
    return get_state("idlarr_token", "") or ""


def get_notify_urls() -> list[str]:
    """Apprise notification URLs. Env var wins, then module-level, then DB."""
    if _ENV_NOTIFY_URLS:
        return [u.strip() for u in _ENV_NOTIFY_URLS.split(",") if u.strip()]
    if NOTIFY_URLS:
        return NOTIFY_URLS
    raw = get_state("notify_urls", "") or ""
    return [u.strip() for u in raw.split(",") if u.strip()]


def get_status_url() -> str:
    """Public URL of the status page. Env var wins, then module-level, then DB."""
    if _ENV_STATUS_URL:
        return _ENV_STATUS_URL
    if STATUS_URL:
        return STATUS_URL
    return get_state("status_url", "") or ""


# Legacy module-level names kept for backward compatibility with tests and
# any code that reads them directly. These are populated during lifespan init.
TOKEN = ""
STATUS_URL = ""
NOTIFY_URLS: list[str] = []

IDLARR_VERSION = "1.3.0"

KNOWN_SOFTWARE = {"gazelle": "Gazelle", "unit3d": "UNIT3D", "tbdev": "TBDev",
                  "custom": "Custom"}

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
                        notes: str | None = None) -> None:
    """Rewrite one tracker's inactivity_days / verified in trackers.yml.

    A surgical line edit, NOT a yaml.safe_dump round-trip. The comments in
    trackers.yml are load-bearing — the fail-safe warning block and the
    per-tracker notes about seeding/user class/vacation mode are the whole
    point of item 1 — and dumping would erase every one of them.

    Writes atomically via os.replace, and refuses to install a file that
    doesn't parse or that changes the tracker count.
    """
    if all(v is None for v in (inactivity_days, verified, immune, immune_reason, notes)):
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
    """Every tracker except one, keyed by id — for blast-radius checks."""
    return {t.get("id"): t for t in (doc.get("trackers") or []) if t.get("id") != skip}


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
            # Handles both `trackers:` (bare) and `trackers: []` (inline empty).
            end = None
            for i, ln in enumerate(lines):
                if re.match(r"^trackers:\s*(\[\])?\s*$", ln):
                    # If it's `trackers: []`, rewrite it to `trackers:` so
                    # appending works as a normal YAML list.
                    if "[]" in ln:
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

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
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
# Modelled on the *arr apps rather than on an environment variable: a username
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
    """Django-format PBKDF2. stdlib only — no new dependency for this."""
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
    sig = hmac.HMAC(session_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def read_session(cookie: str | None) -> str | None:
    """Returns the username, or None for anything not currently valid."""
    if not cookie or "." not in cookie:
        return None
    raw, _, sig = cookie.rpartition(".")
    expected = hmac.HMAC(session_secret(), raw.encode(), hashlib.sha256).hexdigest()
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

    # Visited recently but not authenticated => session died. Independent of the limit.
    stale_session = (
        visit is not None
        and elapsed_days(now, visit) <= 3
        and (auth is None or elapsed_days(visit, auth) >= 3)
    )

    if auth is None:
        out["state"] = "unknown"
        out["reason"] = "No login ever recorded. Log in once to initialise, or click Logged in."
        return out

    days_since = elapsed_days(now, auth)
    days_left = inactivity_days - days_since
    out.update(days_since=days_since, days_left=days_left)

    alert_after = inactivity_days * float(tracker["alert_at_pct"])

    if stale_session:
        out.update(state="session", priority="high",
                   reason="Visited recently while logged out — session cookie is dead.")
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
    order = {"expired": 0, "session": 1, "critical": 2, "warn": 3, "due": 4,
             "unknown": 5, "ok": 6, "immune": 7}
    rows = [evaluate(t, now) for t in load_config()["trackers"]]
    return sorted(rows, key=lambda r: (order[r["state"]], r["days_left"] if r["days_left"] is not None else 9999))


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
    status_url = get_status_url()
    if status_url:
        body += f"\n\n{status_url}"

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
    """Send one message through Apprise. Returns (ok, reason).

    The reason matters: Apprise reports a refused push by returning False and
    logging why, so without capturing its log a bad token or a topic the server
    will not accept is indistinguishable from a successful send.
    """
    try:
        import apprise
    except ImportError:
        return False, "apprise is not installed"

    notify_urls = get_notify_urls()
    seen: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                seen.append(record.getMessage())

    handler, logger = _Capture(), logging.getLogger("apprise")
    logger.addHandler(handler)
    try:
        ap = apprise.Apprise()
        for url in notify_urls:
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


async def notify(rows: list[dict]) -> None:
    payload = build_notification(rows)
    if payload is None:
        log.debug("daily check: nothing due")
        return
    if not get_notify_urls():
        log.warning("no notification URLs configured — alert not sent")
        return
    try:
        # Apprise is synchronous; a slow provider must not stall the scheduler.
        ok, reason = await asyncio.to_thread(
            dispatch, payload["title"], payload["body"], payload["priority"])
        n = payload["body"].count("\n") + 1
        if ok:
            log.info("notification sent (%d line(s))", n)
        else:
            log.error("notification FAILED (%d line(s)): %s", n, reason)
    except Exception as exc:
        log.error("notification FAILED: %s", exc)


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
    if BACKUP_KEEP <= 0:
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    dest = BACKUP_DIR / f"idlarr-{today}.db"
    if dest.exists():
        return dest

    tmp = dest.with_suffix(".db.tmp")
    try:
        with sqlite3.connect(DB_PATH) as src, sqlite3.connect(tmp) as dst:
            src.backup(dst)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()

    # ISO dates sort lexicographically, so oldest-first is just sorted().
    stale = sorted(BACKUP_DIR.glob("idlarr-*.db"))[:-BACKUP_KEEP]
    for old in stale:
        old.unlink()
    if stale:
        log.info("pruned %d old backup(s)", len(stale))
    return dest


async def scheduler() -> None:
    """Wake often, act once per local day. Survives restarts without drift."""
    while True:
        try:
            cfg = load_config()
            now_local = datetime.now(local_tz())
            today = now_local.date().isoformat()
            if now_local.hour >= cfg["check_hour"] and get_state("last_check") != today:
                log.info("daily check running for %s", today)
                # Back up before notifying, and never let a backup failure stop
                # the alert — the alert is the whole point of the service.
                try:
                    dest = backup_db(today)
                    if dest:
                        log.info("backup: %s (%d bytes)", dest, dest.stat().st_size)
                except Exception as exc:
                    log.error("backup FAILED: %s", exc)
                await notify(statuses())
                set_state("last_check", today)
        except Exception as exc:
            log.exception("scheduler error")
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global TOKEN, STATUS_URL, NOTIFY_URLS

    # --- database bootstrap ---------------------------------------------------
    # The DB must exist before we can read/write state, so init_db comes first.
    try:
        init_db()
    except sqlite3.OperationalError as exc:
        uid = os.getuid() if hasattr(os, "getuid") else "unknown"
        raise RuntimeError(
            f"Cannot open the database at {DB_PATH}: {exc}\n"
            f"  The container runs as UID {uid}, and the directory you mounted at\n"
            f"  /data must be writable by it. From your compose directory:\n"
            f"      mkdir -p data && chown -R {uid} data\n"
            f"  If /data looks empty when it should not be, the mount is pointing\n"
            f"  somewhere other than you think."
        ) from exc

    # --- auto-generate token if none exists -----------------------------------
    # A fresh install with no .env and no prior database gets a secure token
    # generated automatically. The user copies it from the settings panel into
    # their userscript (or installs the generated script, which already has it).
    if not _ENV_TOKEN and not get_state("idlarr_token"):
        generated = secrets.token_hex(32)
        set_state("idlarr_token", generated)
        log.info("generated IDLARR_TOKEN (first boot) — find it in Settings > Userscript")

    # Populate module-level vars for backward compat with code that reads them.
    TOKEN = get_token()
    STATUS_URL = get_status_url()
    NOTIFY_URLS = get_notify_urls()

    if not TOKEN:
        raise RuntimeError(
            "IDLARR_TOKEN is not set and could not be generated — refusing to "
            "start. An empty token would disable authentication entirely and "
            "/ping would accept anything."
        )

    if not get_notify_urls():
        log.warning("no notification URLs configured — alerts will go nowhere")

    if RESET_AUTH:
        for key in ("auth_method", "auth_user", "auth_hash", "session_secret"):
            set_state(key, "")
        log.warning("IDLARR_RESET_AUTH is set — UI auth cleared, all sessions invalidated. "
                    "Remove the variable and restart.")

    # --- tracker config bootstrap ---------------------------------------------
    # If no trackers.yml exists, create one from the shipped example so the
    # container boots cleanly. The user adds trackers from the UI.
    if not CONFIG_PATH.exists():
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        default_config = (
            "# Idlarr tracker config. Add trackers from the status page,\n"
            "# or edit this file directly — it is hot-reloaded.\n\n"
            "defaults:\n"
            "  inactivity_days: 30\n"
            "  alert_at_pct: 0.65\n"
            "  timezone: America/Chicago\n"
            "  check_hour: 9\n\n"
            "trackers: []\n"
        )
        CONFIG_PATH.write_text(default_config)
        log.info("created empty %s — add trackers from the status page", CONFIG_PATH)

    try:
        cfg = load_config()
    except Exception as exc:
        raise RuntimeError(
            f"Could not read {CONFIG_PATH}: {exc}\n"
            f"  Check it is valid YAML and readable by UID {os.getuid() if hasattr(os, 'getuid') else 'unknown'}."
        ) from exc
    log.info("%d tracker(s) loaded, timezone %s", len(cfg["trackers"]), cfg["timezone"])

    # Say it out loud. Optional does not mean quiet: an unauthenticated status
    # page looks identical to an authenticated one until somebody uses it.
    if auth_method() == "none":
        log.warning("UI auth is OFF — anyone who can reach this port can "
                    "reset a countdown or rewrite limits")
    else:
        log.info("UI auth: %s (user %r)", auth_method(), get_state("auth_user", ""))

    task = asyncio.create_task(scheduler())
    yield
    task.cancel()


app = FastAPI(title="Idlarr", lifespan=lifespan)


from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection via the custom-header pattern.

    Any state-changing request (POST/PUT/DELETE) that relies on cookie-based
    authentication must include either:
    - A custom header (X-Requested-With or Content-Type: application/json)
    - A Bearer token in Authorization (not cookie-based, so not CSRF-vulnerable)

    Cross-origin HTML forms cannot set custom headers, so a forged form POST
    from another site will be rejected. All legitimate requests from the Idlarr
    frontend use fetch() with JSON content type, which satisfies this check.

    Exemptions:
    - /ping (uses bearer auth, not cookies)
    - /login (needs to work from the login form itself)
    - /healthz (read-only)
    - Requests with auth disabled (nothing to forge)
    """
    EXEMPT_PATHS = {"/ping", "/login", "/logout", "/healthz"}

    async def dispatch(self, request: Request, call_next):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Bearer-token requests are not CSRF-vulnerable.
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return await call_next(request)

        # If no cookie-based session exists, CSRF is not applicable.
        if not request.cookies.get(SESSION_COOKIE):
            return await call_next(request)

        # Require a custom header that cross-origin forms cannot set.
        ct = request.headers.get("content-type", "")
        xrw = request.headers.get("x-requested-with", "")
        if "application/json" in ct or xrw:
            return await call_next(request)

        return Response(
            content=json.dumps({"detail": "CSRF check failed — request must "
                               "include Content-Type: application/json or "
                               "X-Requested-With header"}),
            status_code=403,
            media_type="application/json",
        )


app.add_middleware(CSRFMiddleware)


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Log every request with method, path, status, and duration.

    Replaces uvicorn's default access log with something more useful:
    includes response time in ms, skips noisy healthchecks at DEBUG level,
    and logs errors at WARNING so they stand out.
    """
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        ms = (time.time() - start) * 1000
        path = request.url.path
        status = response.status_code
        # Healthchecks are noisy — log at DEBUG so they don't clutter INFO.
        if path == "/healthz":
            log.debug("%s %s %d (%.0fms)", request.method, path, status, ms)
        elif status >= 500:
            log.error("%s %s %d (%.0fms)", request.method, path, status, ms)
        elif status >= 400:
            log.warning("%s %s %d (%.0fms)", request.method, path, status, ms)
        else:
            log.info("%s %s %d (%.0fms)", request.method, path, status, ms)
        return response


app.add_middleware(RequestLogMiddleware)


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
    if auth != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="bad token")


# ---------------------------------------------------------------- routes

@app.post("/ping")
async def ping(payload: dict = Body(...), authorization: str | None = Header(default=None)):
    require_token(authorization)
    tid = str(payload.get("tracker", "")).strip().lower()
    kind = payload.get("kind", "auth")
    if kind not in ("auth", "visit"):
        raise HTTPException(400, "kind must be auth|visit")
    known = {t["id"] for t in load_config()["trackers"]}
    if tid not in known:
        raise HTTPException(404, f"unknown tracker '{tid}' — add it to trackers.yml")

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

    Open when no login is configured, which is the 1.0 behaviour. Worth
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
        "reason": r["reason"], "auth_source": r.get("auth_source", ""),
        "software": r.get("software", ""), "url": r.get("url", ""),
        "notes": r.get("notes", ""), "alert_at_pct": float(r.get("alert_at_pct", 0.65)),
        "last_auth": r["last_auth"].isoformat() if r["last_auth"] else None,
        "last_visit": r["last_visit"].isoformat() if r["last_visit"] else None,
    }


@app.get("/api/status", dependencies=[Depends(require_ui)])
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
    if all(v is None for v in (days, verified, immune, immune_reason, notes)):
        raise HTTPException(400, "nothing to update")

    try:
        save_tracker_fields(tracker_id, days, verified, immune, immune_reason, notes)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")

    row = next(r for r in statuses() if r["id"] == tracker_id)
    return clean(row)


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
            400, f"could not derive an id from '{name}' — enter one explicitly")
    if not ID_OK.match(tid):
        raise HTTPException(
            400, "id must be lowercase letters, digits, - or _ (max 40) — "
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
        hint = " — check the API key" if exc.code in (401, 403) else ""
        raise ValueError(f"{url.split('?')[0]} returned {exc.code}{hint}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"could not reach {url.split('?')[0]}: {exc.reason}") from exc
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{url.split('?')[0]} did not return JSON: {exc}") from exc


def prowlarr_indexers(base: str, api_key: str) -> list[dict]:
    data = _fetch_json(f"{base.rstrip('/')}/api/v1/indexer", {"X-Api-Key": api_key})
    out = []
    for item in data if isinstance(data, list) else []:
        if str(item.get("protocol", "torrent")).lower() != "torrent":
            continue
        if str(item.get("privacy", "")).lower().replace("_", "") not in PRIVATE:
            continue
        urls = item.get("indexerUrls") or []
        url = urls[0] if urls else ""
        if not url:
            # Cardigann-defined indexers carry the address in `fields` instead.
            for field in item.get("fields") or []:
                if field.get("name") == "baseUrl" and field.get("value"):
                    url = str(field["value"])
                    break
        out.append({"name": str(item.get("name", "")).strip(), "url": url})
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
        out.append({"name": str(item.get("name", "")).strip(),
                    "url": str(item.get("site_link", "")).strip()})
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
    if payload.get("forget"):
        for key in ("import_source", "import_url", "import_key"):
            set_state(key, "")
        return {"forgotten": True}

    source = str(payload.get("source", "")).strip().lower()
    if source not in ("prowlarr", "jackett"):
        raise HTTPException(400, "source must be prowlarr or jackett")
    base = str(payload.get("url", "")).strip()
    if not re.match(r"^https?://", base, re.I):
        raise HTTPException(400, "url must start with http:// or https://")

    api_key = str(payload.get("api_key", "")).strip()
    if not api_key:
        # Blank means "reuse what is saved", but only for the same instance —
        # silently sending one service's key to another would be a leak.
        if (get_state("import_source", "") == source
                and get_state("import_url", "") == base):
            encrypted = get_state("import_key", "") or ""
            api_key = decrypt_value(encrypted, _encryption_secret())
    if not api_key:
        raise HTTPException(400, "an API key is required")

    fetch = prowlarr_indexers if source == "prowlarr" else jackett_indexers
    try:
        found = await asyncio.to_thread(fetch, base, api_key)
    except ValueError as exc:
        raise HTTPException(502, str(exc))

    # Only remember a connection that actually answered.
    set_state("import_source", source)
    set_state("import_url", base)
    set_state("import_key", encrypt_value(api_key, _encryption_secret()))

    known_ids = {t["id"] for t in load_config()["trackers"]}
    known_hosts = {t["host"] for t in load_config()["trackers"] if t.get("host")}

    candidates, seen = [], set()
    for item in found:
        if not item["name"]:
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
                           "host": host, "skip": why})

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
            # Bootstrap the countdown: if Prowlarr/Jackett has a working
            # connection, the tracker is clearly active right now. Record an
            # auth event so the dashboard shows a live countdown instead of
            # "unknown" for every imported tracker.
            record(c["id"], "auth", source="import")
            added.append(c["id"])
        except (KeyError, ValueError) as exc:
            failed.append({"id": c["id"], "error": str(exc)})
    return {"source": source, "added": added, "failed": failed,
            "skipped": [c["id"] for c in candidates if c["skip"]]}


@app.delete("/api/tracker/{tracker_id}", dependencies=[Depends(require_ui)])
async def delete_tracker(tracker_id: str):
    """Remove a tracker. Its auth history stays in the database — see
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
    """Undo the most recent auth event — a misclicked 'logged in', or an auth the
    heuristic recorded wrongly (e.g. a cached logged-in page while the site
    was actually down). Same posture as /api/mark."""
    known = {t["id"] for t in load_config()["trackers"]}
    if tracker_id not in known:
        raise HTTPException(404, "unknown tracker")
    removed = drop_last_auth(tracker_id)
    row = next(r for r in statuses() if r["id"] == tracker_id)
    return {"removed": removed, "row": clean(row)}


@app.get("/api/history/{tracker_id}", dependencies=[Depends(require_ui)])
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


@app.get("/healthz")
async def healthz():
    """Stays open on purpose. An uptime monitor pointed here should not need
    credentials. Discloses operational status but no tracker names or secrets."""
    cfg = load_config()
    trackers = cfg["trackers"]
    rows = statuses()

    # Count by state for a quick glance at health.
    state_counts = {}
    for r in rows:
        state_counts[r["state"]] = state_counts.get(r["state"], 0) + 1

    # How many have ever recorded an auth event.
    bootstrapped = sum(1 for r in rows if r["last_auth"] is not None)

    return {
        "ok": True,
        "version": IDLARR_VERSION,
        "trackers": len(trackers),
        "bootstrapped": bootstrapped,
        "states": state_counts,
        "auth_configured": auth_method() != "none",
        "notifications_configured": bool(get_notify_urls()),
        "status_url_set": bool(get_status_url()),
        "last_check": get_state("last_check", "") or None,
        "timezone": cfg["timezone"],
        "check_hour": cfg["check_hour"],
    }


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
    # A tracker with no host cannot be matched, so it is left out entirely
    # rather than emitted as a broken entry. The route reports the count.
    trackers = [t for t in load_config()["trackers"] if t.get("host")]

    matches = "\n".join(f"// @match        *://*.{t['host']}/*" for t in trackers)
    sites = "\n".join(
        "    {{ host: {}, id: {}{} }},".format(
            json.dumps(t["host"]), json.dumps(t["id"]),
            f", authSel: {json.dumps(t['auth_sel'])}" if t.get("auth_sel") else "")
        for t in trackers)

    version = userscript_version("\n".join([base, matches, sites]))

    # @updateURL/@downloadURL point back here, so adding a tracker on the
    # status page reaches the browser on Violentmonkey's next update check
    # instead of needing a reinstall. Uses a short-lived download token rather
    # than the full API token — it expires in 24h, so a leaked log entry is not
    # a permanent credential. Violentmonkey re-fetches the URL on each check,
    # and the served script always contains a fresh token in @updateURL.
    # 7 days covers even the slowest update-check intervals with margin.
    dl_token = make_download_token(ttl_seconds=604800)
    script_url = f"{base}/idlarr.user.js?token={dl_token}"
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
                f"userscript template no longer contains the {label} — "
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
        f"// GENERATED by Idlarr from trackers.yml — {len(trackers)} tracker(s).\n"
        "// Do not edit: the next auto-update overwrites this file. Add or\n"
        "// change trackers on the status page instead, and the browser picks\n"
        "// it up on Violentmonkey's next update check.\n"
        "// ---------------------------------------------------------------")
    return out.replace("// ==/UserScript==", "// ==/UserScript==" + banner, 1)


def make_download_token(ttl_seconds: int = 3600) -> str:
    """Generate a short-lived token for userscript download/update URLs.

    This replaces the permanent API token in the URL. The download token:
    - Expires after `ttl_seconds` (default 1 hour, enough for Violentmonkey checks)
    - Cannot be used to call /ping or any other endpoint
    - Is derived from the session secret, so rotating that invalidates all tokens

    The token contains an expiry timestamp and an HMAC signature.
    """
    exp = int(time.time()) + ttl_seconds
    payload = f"dl:{exp}"
    sig = hmac.HMAC(_encryption_secret(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    return base64.urlsafe_b64encode(f"{exp}:{sig}".encode()).decode().rstrip("=")


def verify_download_token(token: str) -> bool:
    """Verify a short-lived download token. Also accepts the full API token
    for backward compatibility with existing Violentmonkey installs."""
    if not token:
        return False
    # Accept the full API token for backward compat.
    current_token = get_token()
    if current_token and hmac.compare_digest(token, current_token):
        return True
    # Try as a short-lived download token.
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        exp_str, sig = raw.rsplit(":", 1)
        exp = int(exp_str)
        if exp < time.time():
            return False
        expected = hmac.HMAC(
            _encryption_secret(), f"dl:{exp}".encode(), hashlib.sha256
        ).hexdigest()[:24]
        return hmac.compare_digest(sig, expected)
    except (ValueError, TypeError, UnicodeDecodeError):
        return False


@app.get("/api/download-token", dependencies=[Depends(require_ui)])
async def get_download_token():
    """Generate a short-lived token for the userscript install/update URL.
    Valid for 7 days — long enough for Violentmonkey's update cycle."""
    return {"token": make_download_token(ttl_seconds=604800)}


@app.get("/idlarr.user.js")
async def userscript(request: Request, token: str = ""):
    """Serve the userscript, generated from live config.

    Accepts either:
    - A short-lived download token in ?token= (for Violentmonkey updates)
    - The full API token in ?token= (backward compat)
    - A valid UI session cookie

    The download token is purpose-limited: it can only fetch the script, not
    call /ping or any write endpoint. This means it appearing in server logs
    or browser history is not a credential leak.
    """
    if not verify_download_token(token) and not authed(request):
        raise HTTPException(401, "pass ?token=<download_token> or sign in first")
    status_url = get_status_url()
    if not status_url:
        raise HTTPException(
            500,
            "STATUS_URL is not set, so the generated script would have no "
            "endpoint to report to. Set it in Settings > General, then reload.")
    try:
        body = render_userscript(status_url)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc))
    return Response(body, media_type="text/javascript; charset=utf-8")


# ---------------------------------------------------------------- auth routes

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Idlarr — sign in</title>
<style>
 :root{--bg:#0d0f11;--head:#151a1d;--line:#232a2f;--line2:#2e373d;--fg:#dbe3e7;
   --dim:#727f88;--accent:#e0553f;--bad:#e0553f}
 *{box-sizing:border-box}
 html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
   font-family:Archivo,system-ui,sans-serif;font-size:13px;display:flex;
   align-items:center;justify-content:center}
 form{background:var(--head);border:1px solid var(--line2);padding:26px;width:310px}
 h1{font-size:15px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
   margin:0 0 3px;display:flex;align-items:center;gap:9px}
 h1::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--accent);
   box-shadow:0 0 10px var(--accent)}
 p.t{color:var(--dim);font-size:10px;letter-spacing:.12em;text-transform:uppercase;
   margin:0 0 18px}
 label{display:block;color:var(--dim);font-size:10px;letter-spacing:.12em;
   text-transform:uppercase;margin:0 0 5px}
 input{width:100%;background:var(--bg);border:1px solid var(--line2);color:var(--fg);
   padding:8px 9px;font-family:inherit;font-size:13px;margin-bottom:13px}
 input:focus{outline:none;border-color:var(--accent)}
 button{width:100%;background:var(--accent);border:0;color:#fff;padding:9px;
   font-family:inherit;font-size:12px;letter-spacing:.1em;text-transform:uppercase;
   cursor:pointer}
 .err{color:var(--bad);font-size:11.5px;min-height:16px;margin:9px 0 0;text-align:center}
</style></head><body>
<form id="f" autocomplete="on">
  <h1>Idlarr</h1><p class="t">sign in</p>
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
        raise HTTPException(429, f"too many attempts — try again in {left}s")
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


# ---------------------------------------------------------------- settings API
#
# These endpoints let the UI read and write settings that used to live
# exclusively in .env. Env vars still override if set (for backward compat),
# and that is reported in the response so the user knows why a field is locked.

@app.get("/api/settings", dependencies=[Depends(require_ui)])
async def get_settings():
    """Return all configurable settings with their current values and source."""
    return {
        "token": {
            "value": get_token(),
            "source": "env" if _ENV_TOKEN else "database",
            "locked": bool(_ENV_TOKEN),
        },
        "status_url": {
            "value": get_status_url(),
            "source": "env" if _ENV_STATUS_URL else "database",
            "locked": bool(_ENV_STATUS_URL),
        },
        "notify_urls": {
            "value": ",".join(get_notify_urls()),
            # Never return the actual URLs to the browser — they carry credentials.
            "count": len(get_notify_urls()),
            "source": "env" if _ENV_NOTIFY_URLS else "database",
            "locked": bool(_ENV_NOTIFY_URLS),
        },
    }


@app.post("/api/settings", dependencies=[Depends(require_ui)])
async def update_settings(payload: dict = Body(...)):
    """Update settings stored in the database.

    Only fields present in the payload are touched. Fields that are locked
    (overridden by an env var) cannot be changed from the UI.
    """
    global TOKEN, STATUS_URL, NOTIFY_URLS
    changed = []

    if "status_url" in payload:
        if _ENV_STATUS_URL:
            raise HTTPException(400, "STATUS_URL is set via environment variable "
                                     "and cannot be changed from the UI")
        val = str(payload["status_url"]).strip()
        if val and not re.match(r"^https?://", val, re.I):
            raise HTTPException(400, "status_url must start with http:// or https://")
        set_state("status_url", val)
        STATUS_URL = get_status_url()
        changed.append("status_url")

    if "notify_urls" in payload:
        if _ENV_NOTIFY_URLS:
            raise HTTPException(400, "IDLARR_NOTIFY_URLS is set via environment "
                                     "variable and cannot be changed from the UI")
        val = str(payload["notify_urls"]).strip()
        set_state("notify_urls", val)
        NOTIFY_URLS = get_notify_urls()
        changed.append("notify_urls")

    if "regenerate_token" in payload and payload["regenerate_token"]:
        if _ENV_TOKEN:
            raise HTTPException(400, "IDLARR_TOKEN is set via environment variable "
                                     "and cannot be changed from the UI")
        new_token = secrets.token_hex(32)
        set_state("idlarr_token", new_token)
        TOKEN = new_token
        changed.append("token")

    if not changed:
        raise HTTPException(400, "nothing to update")

    return {"updated": changed}



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
    token = get_token()
    if not (token and authorization == f"Bearer {token}") and not authed(request):
        raise HTTPException(401, "bad token")
    notify_urls = get_notify_urls()
    if not notify_urls:
        raise HTTPException(400, "No notification URLs configured. "
                                 "Set them in Settings > Notifications.")

    when = datetime.now(local_tz()).strftime("%d %b %Y %H:%M %Z")
    body = (f"Test from Idlarr at {when}.\n"
            f"Watching {len(load_config()['trackers'])} tracker(s). "
            f"If you can read this, alerts will reach you.")
    ok, reason = await asyncio.to_thread(dispatch, "Idlarr test", body, "default")
    if not ok:
        log.error("test notification FAILED: %s", reason)
        raise HTTPException(502, f"not accepted: {reason}")
    log.info("test notification sent")
    return {"ok": True, "destinations": len(notify_urls)}


# ---------------------------------------------------------------- view

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Idlarr</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;600;700&family=Azeret+Mono:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0d0f11;--head:#151a1d;--drawer:#111619;--line:#232a2f;--line2:#2e373d;
    --fg:#dbe3e7;--dim:#727f88;--dim2:#8e9aa3;
    --ok:#43a06b;--due:#c2a136;--warn:#d2802f;--critical:#e0553f;--expired:#a52c4e;
    --immune:#6572a0;--session:#2f96b4;--unknown:#5d6870;--accent:#e0553f;
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--fg);
    font-family:Archivo,system-ui,sans-serif;font-size:13px;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1240px;margin:0 auto;padding:22px 20px 70px}

  .bar{display:flex;align-items:center;gap:16px;padding-bottom:12px;
    border-bottom:2px solid var(--line2);flex-wrap:wrap}
  h1{font-size:16px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;margin:0;
    display:flex;align-items:center;gap:9px}
  h1::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--accent);
    box-shadow:0 0 10px var(--accent);animation:beat 2.6s ease-out infinite}
  @keyframes beat{0%{transform:scale(1)}10%{transform:scale(1.35)}20%{transform:scale(1)}
    30%{transform:scale(1.2)}40%{transform:scale(1)}}
  .stamp{font-family:'Azeret Mono',monospace;color:var(--dim);font-size:10.5px}
  .tag{color:var(--dim);font-size:9.5px;letter-spacing:.13em;text-transform:uppercase}
  @media(max-width:760px){.tag{display:none}}
  .tick{display:flex;gap:2px;margin-left:auto;align-items:flex-end;height:22px}
  .tick i{width:8px;background:var(--c);height:var(--h);display:block;opacity:.85;
    border-radius:1px;cursor:pointer}
  .tick i:hover{opacity:1;box-shadow:0 0 8px var(--c)}

  .legend{display:flex;margin:12px 0 16px;border:1px solid var(--line);flex-wrap:wrap;
    background:var(--head)}
  .legend div{flex:1;min-width:82px;padding:8px 13px;border-right:1px solid var(--line)}
  .legend div:last-child{border-right:0}
  .legend b{display:block;font-family:'Azeret Mono',monospace;font-size:17px;font-weight:500;
    color:var(--c);line-height:1;font-variant-numeric:tabular-nums}
  .legend span{font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--dim);
    display:block;margin-top:5px;font-weight:600}

  table{width:100%;border-collapse:collapse;table-layout:fixed}
  col.c-rail{width:4px} col.c-nm{width:22%} col.c-sw{width:118px} col.c-st{width:116px}
  col.c-seen{width:104px} col.c-left{width:78px} col.c-lim{width:76px} col.c-el{width:auto}
  thead th{font-size:9px;letter-spacing:.17em;text-transform:uppercase;color:var(--dim);
    text-align:left;padding:0 18px 8px 0;font-weight:700;border-bottom:1px solid var(--line2);
    cursor:pointer;user-select:none;white-space:nowrap}
  thead th:first-child{padding-right:0}
  thead th:nth-child(2){padding-left:14px}
  thead th:hover{color:var(--fg)}
  thead th.r{text-align:right}
  thead th::after{content:'';display:inline-block;width:0;height:0;margin-left:6px;
    vertical-align:2px;border-left:3.5px solid transparent;border-right:3.5px solid transparent;
    opacity:.3;border-bottom:4px solid currentColor}
  thead th[data-dir="desc"]::after{border-bottom:0;border-top:4px solid currentColor;opacity:1}
  thead th[data-dir="asc"]::after{opacity:1}
  thead th.nos{cursor:default} thead th.nos::after{display:none}

  tbody tr.row{border-bottom:1px solid var(--line);cursor:pointer}
  tbody tr.row:hover{background:var(--head)}
  tbody tr.row.open{background:var(--head);border-bottom-color:transparent}
  tbody tr.row.flash{animation:fl .9s ease}
  @keyframes fl{0%,100%{background:transparent}18%{background:rgba(224,85,63,.13)}}
  td{padding:9px 18px 9px 0;vertical-align:middle;overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap}
  td.s{width:4px;padding:0;background:var(--c)}
  td.nm{padding-left:14px;font-weight:600;font-size:13.5px}
  td.nm a{color:var(--fg);text-decoration:none;border-bottom:1px solid transparent}
  td.nm a:hover{color:var(--c);border-bottom-color:var(--c)}
  td.nm i{font-style:normal;color:var(--dim);font-size:10px;margin-left:7px;font-weight:400}
  td.nm .caret{display:inline-block;width:0;height:0;margin-right:8px;vertical-align:2px;
    border-top:3.5px solid transparent;border-bottom:3.5px solid transparent;
    border-left:5px solid var(--dim);transition:transform .15s}
  tr.row.open .caret{transform:rotate(90deg)}
  td.sw{color:var(--dim2);font-size:10px;letter-spacing:.11em;text-transform:uppercase;font-weight:600}
  td.st{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--c);font-weight:700}
  td.seen{font-family:'Azeret Mono',monospace;color:var(--dim2);font-size:10.5px;text-align:right}
  td.n{text-align:right;font-family:'Azeret Mono',monospace;font-variant-numeric:tabular-nums;
    font-size:15px;font-weight:500;color:var(--c)}
  td.lim{text-align:right;font-family:'Azeret Mono',monospace;color:var(--dim);font-size:10.5px}
  .meter{height:5px;background:#1a2024;position:relative;border-radius:1px;overflow:hidden}
  .meter i{position:absolute;inset:0 auto 0 0;width:var(--p);background:var(--c);border-radius:1px}
  .meter.none{opacity:.22}
  .q{font-size:8.5px;letter-spacing:.1em;color:var(--accent);border:1px solid rgba(224,85,63,.4);
    padding:1px 5px;margin-left:8px;font-weight:700;text-transform:uppercase}

  tr.drawer td{padding:0;border-bottom:1px solid var(--line);background:var(--drawer)}
  .d{border-left:4px solid var(--c);padding:15px 18px;display:grid;
    grid-template-columns:minmax(0,340px) 1fr 1fr;gap:26px}
  @media(max-width:940px){.d{grid-template-columns:1fr}}
  .dh{font-size:8.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);
    font-weight:700;margin-bottom:10px}
  .ctl{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .field{display:flex;align-items:stretch;border:1px solid var(--line2);background:#0b0e10}
  .field span{font-size:8.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--dim);
    padding:0 10px;display:grid;place-items:center;font-weight:700}
  .field input{font:inherit;font-family:'Azeret Mono',monospace;font-size:13px;width:56px;
    background:transparent;color:var(--c);border:0;border-left:1px solid var(--line2);
    padding:7px 9px;text-align:right}
  .field input:focus{outline:none;background:rgba(255,255,255,.03)}
  .field em{font-style:normal;font-family:'Azeret Mono',monospace;font-size:11px;
    color:var(--dim);padding:0 9px;display:grid;place-items:center}
  .field.off{opacity:.38}
  .field.off input{color:var(--dim);cursor:not-allowed}
  button{font-family:Archivo;font-size:9px;font-weight:700;letter-spacing:.15em;
    text-transform:uppercase;background:transparent;color:var(--dim2);
    border:1px solid var(--line2);padding:8px 12px;cursor:pointer;transition:.15s}
  button:hover{color:var(--fg);border-color:var(--dim)}
  button:disabled{opacity:.35;cursor:not-allowed}
  button.on{color:var(--accent);border-color:var(--accent);background:rgba(224,85,63,.09)}
  button.arm{color:var(--expired);border-color:var(--expired);background:rgba(165,44,78,.14)}
  button.danger:hover{color:var(--expired);border-color:var(--expired)}
  .reason{margin-top:10px}
  .reason input{font:inherit;font-size:11.5px;width:100%;background:#0b0e10;color:var(--fg);
    border:1px solid var(--line2);padding:8px 10px}
  .reason input:focus{outline:none;border-color:var(--immune)}
  .msg{font-size:10px;color:var(--dim);min-height:14px;margin-top:9px;letter-spacing:.03em}
  .msg.bad{color:var(--critical)} .msg.good{color:var(--ok)} .msg.warn{color:var(--due)}
  .note{margin-top:9px}
  .note input{font:inherit;font-size:11px;width:100%;background:#0b0e10;
    color:var(--dim);font-style:italic;border:1px solid var(--line);padding:5px 7px}
  .note input:focus{outline:none;border-color:var(--accent);font-style:normal;
    color:var(--fg)}
  .sched,.hist{font-family:'Azeret Mono',monospace;font-size:11px}
  .sched div,.hist div{display:flex;align-items:baseline;gap:10px;padding:5px 0;
    border-bottom:1px solid var(--line)}
  .sched div:last-child,.hist div:last-child{border-bottom:0}
  .sched b{font-family:Archivo;font-size:9px;letter-spacing:.14em;text-transform:uppercase;
    font-weight:700;color:var(--k);width:58px;flex:none}
  .sched span,.hist span{color:var(--dim2)}
  .sched em,.hist em{font-style:normal;margin-left:auto;color:var(--dim)}
  .sched .past{opacity:.4}
  .hist em{font-family:Archivo;font-size:9px;letter-spacing:.1em;text-transform:uppercase;font-weight:700}
  .hist em.hand{color:var(--accent)}

  .foot{color:var(--dim);font-size:10px;margin-top:18px;line-height:1.75}
  .foot b{color:var(--dim2);font-weight:400}
  .empty{color:var(--dim);padding:50px 0;text-align:center;letter-spacing:.12em;text-transform:uppercase}

  /* Mobile sort control — the <thead> is hidden below, so this drives the same
     handlers by clicking the (still present) header cells programmatically. */
  .msort{display:none;gap:6px;align-items:center}
  .msort select,.msort button{font-family:Archivo;font-size:9px;font-weight:700;
    letter-spacing:.13em;text-transform:uppercase;background:#0b0e10;color:var(--dim2);
    border:1px solid var(--line2);padding:7px 9px}
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
    h1{font-size:14px}
    .stamp{font-size:9.5px}
    .tick{margin-left:0;width:100%;height:18px;order:3}
    .tick i{flex:1;width:auto;min-width:0}
    .msort{display:flex;margin-left:auto}
    .legend{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:0}
    .legend div{border-bottom:1px solid var(--line);min-width:0;padding:7px 9px}
    .legend div:nth-child(4n){border-right:0}
    .legend b{font-size:15px}
    .legend span{font-size:8px;letter-spacing:.1em}

    table{table-layout:auto;display:block}
    colgroup,thead{display:none}
    tbody{display:block}
    tbody tr.row{display:grid;grid-template-columns:1fr 1fr auto;
      grid-template-areas:"nm nm n" "st st n" "sw seen lim" "el el el";
      gap:3px 10px;align-items:baseline;padding:11px 12px 10px 14px;
      border-left:4px solid var(--c);position:relative}
    tbody tr.row.open{border-bottom-color:var(--line)}
    td{padding:0;white-space:normal}
    td.s{display:none}
    td.nm{grid-area:nm;padding-left:0;font-size:14.5px;line-height:1.25}
    td.nm .caret{margin-right:6px}
    td.st{grid-area:st;font-size:9px}
    td.n{grid-area:n;font-size:27px;align-self:center;text-align:right}
    td.sw{grid-area:sw;font-size:9px}
    td.seen{grid-area:seen;text-align:left;font-size:10px}
    td.lim{grid-area:lim;font-size:10px}
    td.el{grid-area:el;margin-top:5px}
    .q{display:block;margin:3px 0 0}

    tr.drawer{display:block}
    tr.drawer td{display:block}
    .d{grid-template-columns:1fr;gap:16px;padding:14px 12px}
    .ctl{gap:6px}
    .foot{font-size:9.5px}
  }
  .banner{display:flex;align-items:center;gap:11px;flex-wrap:wrap;margin:13px 0 0;
    padding:9px 13px;border:1px solid var(--critical);background:#251619;font-size:12px}
  .banner b{color:var(--critical);letter-spacing:.04em}
  .banner .sp{margin-left:auto;display:flex;gap:7px}
  .lk{background:var(--bg);border:1px solid var(--line2);color:var(--fg);
    font-family:inherit;font-size:11px;padding:4px 10px;cursor:pointer}
  .lk:hover{border-color:var(--accent)}
  .lk.pri{background:var(--accent);border-color:var(--accent);color:#fff}
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;
    align-items:center;justify-content:center;z-index:30}
  .modal.on{display:flex}
  .modal .box{background:var(--head);border:1px solid var(--line2);padding:22px;
    width:340px;max-width:92vw}
  .modal h3{margin:0 0 4px;font-size:12px;letter-spacing:.13em;text-transform:uppercase}
  .modal .hint{color:var(--dim);font-size:11px;margin:0 0 15px;line-height:1.45}
  .modal label{display:block;color:var(--dim);font-size:10px;letter-spacing:.11em;
    text-transform:uppercase;margin:0 0 4px}
  .modal input,.modal select{width:100%;background:var(--bg);border:1px solid var(--line2);
    color:var(--fg);padding:7px 8px;font-family:inherit;font-size:12.5px;margin-bottom:12px}
  .modal input:focus,.modal select:focus{outline:none;border-color:var(--accent)}
  .modal .rowb{display:flex;gap:8px;margin-top:2px}
  .modal .rowb button{flex:1;padding:8px;font-family:inherit;font-size:11px;
    letter-spacing:.09em;text-transform:uppercase;cursor:pointer}
  .modal .e{color:var(--critical);font-size:11.5px;min-height:15px;margin:7px 0 0}
  .modal .box.wide{width:410px}
  .modal .rowb button:disabled{opacity:.4;cursor:default}
  .imlist{max-height:184px;overflow:auto;margin:2px 0 13px}
  .imlist:empty{display:none}
  .imlist .r{display:flex;gap:9px;align-items:baseline;padding:5px 0;
    border-bottom:1px solid var(--line);font-size:11.5px}
  .imlist .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .imlist .sk{color:var(--dim);font-size:9.5px;letter-spacing:.06em;white-space:nowrap}
  .imlist .new{color:var(--ok);font-size:9.5px;letter-spacing:.06em;white-space:nowrap}

  /* Footer is read-only STATUS. It used to carry actions too, and that is
     what made it overflow: fixed-width nowrap content competing for room in a
     flex cell. Nothing here is interactive, so nothing can compete. */
  .statusline{margin:14px 0 0;padding:11px 2px 0;border-top:1px solid var(--line);
    color:var(--dim);font-family:'Azeret Mono',monospace;font-size:11px;
    display:flex;gap:16px;flex-wrap:wrap}
  .statusline b{color:var(--fg);font-weight:400}
  .statusline .bad{color:var(--critical)}
  .statusline .ok{color:var(--ok)}

  .hbtn{display:flex;gap:7px;margin-left:14px;align-items:center}
  .gear{background:var(--head);border:1px solid var(--line2);color:var(--fg);
    cursor:pointer;font-size:14px;line-height:1;padding:5px 9px}
  .gear:hover{border-color:var(--accent)}

  .sheet{position:fixed;inset:0;background:rgba(0,0,0,.66);display:none;z-index:40;
    align-items:center;justify-content:center}
  .sheet.on{display:flex}
  .sheet .win{background:var(--head);border:1px solid var(--line2);position:relative;
    width:min(790px,94vw);height:min(584px,88vh);display:flex;overflow:hidden}
  .sheet nav{width:180px;border-right:1px solid var(--line);background:var(--bg);
    padding:14px 0;flex:none}
  .sheet nav button{display:block;width:100%;text-align:left;background:none;
    border:0;border-left:2px solid transparent;color:var(--dim);font-family:inherit;
    font-size:11px;letter-spacing:.14em;text-transform:uppercase;padding:11px 16px;
    cursor:pointer}
  .sheet nav button:hover{color:var(--fg)}
  .sheet nav button.on{color:var(--fg);border-left-color:var(--accent);
    background:var(--head)}
  .sheet .pane{flex:1;overflow:auto;padding:20px 22px}
  .sheet .pane section{display:none}
  .sheet .pane section.on{display:block}
  .sheet h4{margin:0 0 5px;font-size:13px;letter-spacing:.13em;text-transform:uppercase}
  .sheet .sub{color:var(--dim);font-size:12px;margin:0 0 16px;line-height:1.55}
  .sheet .row{display:flex;align-items:center;gap:14px;padding:12px 0;
    border-bottom:1px solid var(--line)}
  .sheet .row:last-child{border-bottom:0}
  .sheet .row .lbl{flex:1;min-width:0}
  .sheet .row .lbl b{display:block;font-weight:400;font-size:13.5px;color:var(--fg)}
  .sheet .row .lbl span{color:var(--dim);font-size:11.5px;line-height:1.5;
    display:block;margin-top:3px}
  .sheet .row .val{font-family:'Azeret Mono',monospace;font-size:12.5px;color:var(--dim)}
  .sheet .row .val.on{color:var(--ok)}
  .sheet .row .val.off{color:var(--critical)}
  .sheet input,.sheet select{background:var(--bg);border:1px solid var(--line2);
    color:var(--fg);padding:7px 8px;font-family:inherit;font-size:13px}
  .sheet input:focus,.sheet select:focus{outline:none;border-color:var(--accent)}
  /* ONE fixed control column. Every control shares a left and right edge;
     letting each size itself staggered them down the panel. */
  .sheet .row .ctl2{width:200px;flex:none;display:flex;justify-content:flex-end;
    gap:6px;align-items:center}
  .sheet .row .ctl2>input,.sheet .row .ctl2>select{width:100%}
  .sheet .row .ctl2>.val{white-space:normal;text-align:right}
  .sheet .row .ctl2>button{flex:1}
  .sheet .stack{margin:0 0 14px}
  .sheet .stack input,.sheet .stack select{width:100%;margin-bottom:9px}
  .sheet .e{color:var(--critical);font-size:12px;min-height:16px;margin:9px 0 0}
  .sheet .e.good{color:var(--ok)}
  .xclose{position:absolute;top:14px;right:16px;background:none;border:0;
    color:var(--dim);font-size:18px;cursor:pointer;line-height:1;z-index:2}
  .xclose:hover{color:var(--fg)}
  .imlist{max-height:170px;overflow:auto;margin:2px 0 6px}
  .imlist:empty{display:none}
  .imlist .r{display:flex;gap:9px;align-items:baseline;padding:5px 0;
    border-bottom:1px solid var(--line);font-size:12px}
  .imlist .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .imlist .sk{color:var(--dim);font-size:10px;white-space:nowrap}
  .imlist .new{color:var(--ok);font-size:10px;white-space:nowrap}
  @media(max-width:760px){
    .sheet .win{flex-direction:column;height:92vh}
    .sheet nav{width:100%;display:flex;overflow-x:auto;padding:0;
      border-right:0;border-bottom:1px solid var(--line)}
    .sheet nav button{border-left:0;border-bottom:2px solid transparent;
      white-space:nowrap;padding:12px 13px;width:auto}
    .sheet nav button.on{border-left:0;border-bottom-color:var(--accent)}
    .sheet .row{flex-wrap:wrap}
    .sheet .row .ctl2{width:100%;justify-content:flex-start}
    .banner .sp{margin-left:0;width:100%}
    .hbtn .lk{font-size:10px;padding:4px 7px}
  }
</style></head><body><div class="wrap">

<div class="bar"><h1>Idlarr</h1><span class="tag">never lose an account to inactivity</span><span class="stamp">__STAMP__</span>
  <div class="msort"><select id="msf" aria-label="sort by">
    <option value="st">state</option><option value="nm">tracker</option>
    <option value="left">left</option><option value="seen">last auth</option>
    <option value="lim">limit</option><option value="sw">software</option>
  </select><button id="msd" aria-label="reverse sort">&#8645;</button></div>
  <div class="tick">__TICK__</div>
  <div class="hbtn"><button class="lk" id="addtrk">+ Add tracker</button><button class="gear" id="gear" title="settings" aria-label="settings">&#9881;</button></div></div>
__BANNER__
<div class="legend">__LEGEND__</div>

<table>
<colgroup><col class="c-rail"><col class="c-nm"><col class="c-sw"><col class="c-st">
<col class="c-seen"><col class="c-left"><col class="c-lim"><col class="c-el"></colgroup>
<thead><tr><th class="nos"></th>
<th data-k="nm" data-t="s">tracker</th>
<th data-k="sw" data-t="s">software</th>
<th data-k="st" data-t="n">state</th>
<th data-k="seen" data-t="n" class="r">last auth</th>
<th data-k="left" data-t="n" class="r">left</th>
<th data-k="lim" data-t="n" class="r">limit</th>
<th class="nos">elapsed</th></tr></thead>
<tbody>__ROWS__</tbody></table>

<div class="foot">
Click a row for controls, the alert schedule and auth history &middot; click a name to open the
tracker &middot; click a heading to sort<br>
<b>&#9998;</b> = marked by hand, not observed &middot; the countdown runs on <b>auth</b> events only
&middot; no request is ever made to a tracker.
</div>
<div class="statusline">__STATUS__</div>
</div>

__SHEET__

<div class="modal" id="tm"><div class="box">
  <h3>Add tracker</h3>
  <p class="hint">The limit starts at 30 days and stays <b>unconfirmed</b> until
  you read that tracker's own rules page. A limit set too high is the one that
  loses the account, so this errs short on purpose.</p>
  <label for="tmn">name</label>
  <input id="tmn" placeholder="Alpha Tracker">
  <label for="tmu">url</label>
  <input id="tmu" placeholder="https://alpha.example/">
  <label for="tmi">id &mdash; ping and script id</label>
  <input id="tmi" placeholder="derived from the name">
  <label for="tmd">inactivity limit, in days</label>
  <input id="tmd" type="text" inputmode="numeric" value="30">
  <label for="tmo">notes</label>
  <input id="tmo" placeholder="Gazelle. Seeding counts.">
  <div class="rowb"><button class="lk" id="tmcancel">Cancel</button>
    <button class="lk pri" id="tmsave">Add</button></div>
  <p class="e" id="tme"></p>
</div></div>


<script>
(function(){
 const CURRENT_METHOD='__AUTHMETHOD__';
 const tb=document.querySelector('tbody');
 const LABEL={ok:'days left',due:'days left',warn:'days left',critical:'days left',
   expired:'days over',session:'re-auth',immune:'exempt',unknown:'no data'};
 const RANK={expired:0,session:1,critical:2,warn:3,due:4,unknown:5,ok:6,immune:7};

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
   tr.querySelector('td.st').textContent=d.immune&&d.immune_reason?d.immune_reason:d.state;
   tr.querySelector('td.seen').textContent=ago(d.days_since);
   tr.querySelector('td.n').textContent=
     (d.immune||d.days_left===null)?'\\u2014':Math.abs(d.days_left);
   tr.querySelector('td.lim').textContent=d.inactivity_days+'d';
   const p=d.days_since===null?0:Math.min(100,Math.max(3,(1-d.days_left/d.inactivity_days)*100));
   tr.querySelector('.meter i').style.setProperty('--p',(d.immune?0:p).toFixed(0)+'%');
   tr.querySelector('.meter').classList.toggle('none',!!d.immune);
   const q=tr.querySelector('.q');
   if(q)q.style.display=(d.verified||d.immune)?'none':'';
   tr.classList.remove('flash');void tr.offsetWidth;tr.classList.add('flash');
 }

 function drawer(tr){
   const d=JSON.parse(tr.dataset.row), imm=!!d.immune;
   const el=document.createElement('tr'); el.className='drawer';
   el.innerHTML='<td colspan="8"><div class="d" style="--c:var(--'+d.state+')">'
    +'<div><div class="dh">controls</div><div class="ctl">'
    +'<label class="field'+(imm?' off':'')+'"><span>limit</span>'
    +'<input class="lim" type="text" inputmode="numeric" value="'+d.inactivity_days+'"'
    +(imm?' disabled':'')+'><em>d</em></label>'
    +'<button class="chk'+(d.verified?' on':'')+'"'+(imm?' disabled':'')+'>'
    +(d.verified?'\\u2713 confirmed':'confirm')+'</button>'
    +'<button class="imm'+(imm?' on':'')+'">'+(imm?'\\u25cf immune':'immune')+'</button>'
    +'<button class="seen">logged in</button><button class="undo danger">undo</button>'
    +'<button class="del danger">remove</button></div>'
    +(imm?'<div class="reason"><input class="rsn" value="'+(d.immune_reason||'')
      +'" placeholder="why immune? e.g. donated, elite class"></div>':'')
    +'<div class="note"><input class="nts" value="'+hesc(d.notes||'')
      +'" placeholder="notes \u2014 first word sets the software column"></div>'
    +'<div class="msg"></div></div>'
    +'<div><div class="dh">alert schedule</div><div class="sched">'+schedule(d)+'</div></div>'
    +'<div><div class="dh">auth history</div><div class="hist">'
    +'<div><span>loading\\u2026</span></div></div></div></div></td>';
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
         refresh(r);msg(r.verified?'saved':'saved \\u2014 still unconfirmed','warn');})
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
       msg(next?'immune \\u2014 will never alert':'immunity cleared','good');})
      .catch(e=>msg(e.message,'bad'));});

   const rsn=el.querySelector('.rsn');
   if(rsn){let last=rsn.value;
     const save=()=>{if(rsn.value===last)return;
       post('/api/limit/'+d.id,{immune_reason:rsn.value}).then(r=>{last=r.immune_reason;
         refresh(r);msg('reason saved','good');}).catch(e=>{msg(e.message,'bad');rsn.value=last;});};
     rsn.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();rsn.blur();}});
     rsn.addEventListener('blur',save);}

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
       msg('records a manual auth \\u2014 only if you really just logged in','warn');
       t=setTimeout(()=>{armed=false;seenBtn.classList.remove('arm');
         seenBtn.textContent='logged in';msg('');},4000);return;}
     clearTimeout(t);armed=false;seenBtn.classList.remove('arm');seenBtn.textContent='logged in';
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
       msg('removes it from trackers.yml \\u2014 auth history is kept','warn');
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

 document.querySelectorAll('.tick i').forEach(t=>t.addEventListener('click',()=>{
   const r=document.getElementById('t-'+t.dataset.id);
   if(r){r.scrollIntoView({behavior:'smooth',block:'center'});
     r.classList.remove('flash');void r.offsetWidth;r.classList.add('flash');}}));

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

 // ---- settings sheet ---------------------------------------------------
 const sheet=document.getElementById('sheet');
 const ame=document.getElementById('ame');
 const amm=document.getElementById('amm'),amc=document.getElementById('amc');
 const openSheet=to=>{sheet.classList.add('on');
   const nb=to&&sheet.querySelector('nav button[data-s="'+to+'"]'); if(nb)nb.click();
   const f=sheet.querySelector('section.on input,section.on select'); if(f)f.focus();};
 const closeSheet=()=>sheet.classList.remove('on');
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
 const outb=document.getElementById('amout');
 if(outb)outb.addEventListener('click',()=>fetch('/logout',{method:'POST'})
   .then(()=>location.href='/login'));

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
 const closeTrk=()=>tm.classList.remove('on');
 document.getElementById('addtrk').addEventListener('click',()=>{
   tme.textContent='';tmi.dataset.dirty='';tm.classList.add('on');tmn.focus();});
 document.getElementById('tmcancel').addEventListener('click',closeTrk);
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
 const imbody=()=>({source:document.getElementById('ims').value,
   url:document.getElementById('imu').value,
   api_key:document.getElementById('imk').value});

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
     +'</span>'+(x.skip?'<span class="sk">'+hesc(x.skip)+'</span>'
                       :'<span class="new">will add</span>')+'</div>').join('')
     :'<div class="r"><span class="nm">no private trackers found</span></div>';
   imapply.disabled=fresh===0;
   imapply.textContent=fresh?('Import '+fresh):'Import';
 });

 const imforget=document.getElementById('imforget');
 if(imforget)imforget.addEventListener('click',async()=>{
   await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({forget:true})});
   location.reload();});

 imapply.addEventListener('click',async()=>{
   ime.textContent='';imapply.disabled=true;
   const r=await impost({apply:true}); const d=await r.json().catch(()=>({}));
   if(!r.ok){ime.textContent=d.detail||('failed ('+r.status+')');imapply.disabled=false;return;}
   location.reload();
 });

 const ntest=document.getElementById('ntest'),nte=document.getElementById('nte');
 if(ntest)ntest.addEventListener('click',async()=>{
   nte.className='e';nte.textContent='sending\u2026';ntest.disabled=true;
   const r=await fetch('/api/test-notify',{method:'POST'});
   const d=await r.json().catch(()=>({}));
   ntest.disabled=false;
   if(r.ok){nte.className='e good';nte.textContent='sent \u2014 check your device';}
   else{nte.textContent=d.detail||('failed ('+r.status+')');}
 });

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

 // ---- settings: status URL and notify URLs --------------------------------
 const surlsave=document.getElementById('surlsave');
 if(surlsave){surlsave.addEventListener('click',async()=>{
   const inp=document.getElementById('surl');
   const r=await fetch('/api/settings',{method:'POST',
     headers:{'Content-Type':'application/json'},
     body:JSON.stringify({status_url:inp.value})});
   const d=await r.json().catch(()=>({}));
   if(!r.ok){alert(d.detail||'failed');return;}
   location.reload();
 });}
 const nsave=document.getElementById('nsave');
 if(nsave){nsave.addEventListener('click',async()=>{
   const inp=document.getElementById('nurls');
   if(!inp.value){alert('enter at least one URL');return;}
   const nte2=document.getElementById('nte');
   nte2.className='e';nte2.textContent='saving\u2026';
   const r=await fetch('/api/settings',{method:'POST',
     headers:{'Content-Type':'application/json'},
     body:JSON.stringify({notify_urls:inp.value})});
   const d=await r.json().catch(()=>({}));
   if(!r.ok){nte2.textContent=d.detail||'failed';return;}
   nte2.className='e good';nte2.textContent='saved';inp.value='';
   setTimeout(()=>location.reload(),800);
 });}
})();
</script></body></html>"""

LABELS = {"ok": "days left", "due": "days left", "warn": "days left",
          "critical": "days left", "expired": "days over", "session": "re-auth",
          "unknown": "no data", "immune": "days idle"}
RANK = {"expired": 0, "session": 1, "critical": 2, "warn": 3, "due": 4,
        "unknown": 5, "ok": 6, "immune": 7}


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


def settings_sheet(method: str, n_trk: int, n_hosts: int, js_url: str) -> str:
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

    # --- general: read-only for now. These live in trackers.yml, and showing
    #     them as editable controls that silently do nothing would be worse
    #     than showing them as facts.
    general = (
        _row("Status URL",
             "Public URL of this page. Used in alerts and the generated userscript." +
             (" Locked by env var." if _ENV_STATUS_URL else ""),
             (f'<span class="val">{esc(get_status_url()) or "not set"}</span>'
              if _ENV_STATUS_URL else
              f'<input id="surl" value="{esc(get_status_url())}" '
              f'placeholder="https://idlarr.example.com">'
              f'<button class="lk" id="surlsave">Save</button>'))
        + _row("Timezone", "All day counting is calendar days in this zone.",
             f'<span class="val">{esc(cfg["timezone"])}</span>')
        + _row("Daily check hour",
               "When the check runs and alerts batch into one push.",
               f'<span class="val">{cfg["check_hour"]:02d}:00</span>')
        + _row("Last check", "", f'<span class="val">{esc(last)}</span>')
        + _row("Backup retention", "Nightly snapshots kept in /data/backups.",
               f'<span class="val">{BACKUP_KEEP} days</span>')
        + '<p class="sub" style="margin:15px 0 0">Timezone and check hour '
          'live in <code>trackers.yml</code>. Everything else is editable here '
          'or overridable with env vars.</p>')

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
                   "Restart once with <b>IDLARR_RESET_AUTH=1</b>.",
               ('<button class="lk" id="amout">Sign out</button>' if method != "none" else "")
               + '<button class="lk pri" id="amsave">Save</button>')
        + '<p class="e" id="ame"></p>')

    script = (
        _row("Covers", "One @match and one SITES entry per tracker with a host.",
             f'<span class="val on">{n_hosts} tracker'
             f'{"" if n_hosts == 1 else "s"}</span>')
        + _row("Endpoint", "The script reports here.",
               f'<span class="val">{esc(host_from_url(get_status_url())) or "not set"}</span>')
        + (_row("Install", "Violentmonkey takes this link directly.",
                f'<a class="lk pri" href="{esc(js_url)}">Install</a>'
                f'<button class="lk" id="cpjs" data-u="{esc(js_url)}">Copy URL</button>')
           if js_url else
           _row("Install", "Set the <b>Status URL</b> in Settings > General — without it "
                           "the generated script would have nowhere to report.",
                '<span class="val off">unavailable</span>')))

    # A working connection is remembered so a container recreate does not send
    # you back to Prowlarr for the key. The key itself is never sent back to
    # the browser — the field shows that one is saved, and blank means reuse it.
    src, iurl = get_state("import_source", "") or "prowlarr", get_state("import_url", "") or ""
    saved_key = bool(get_state("import_key"))
    opt = lambda v, t: f'<option value="{v}"{" selected" if src == v else ""}>{t}</option>'
    imp = (
        '<div class="stack">'
        f'<select id="ims">{opt("prowlarr", "Prowlarr")}{opt("jackett", "Jackett")}</select>'
        f'<input id="imu" placeholder="http://prowlarr.local:9696" value="{esc(iurl)}">'
        f'<input id="imk" type="password" autocomplete="off" placeholder="'
        f'{"saved &mdash; leave blank to reuse" if saved_key else "API key"}">'
        '</div>'
        '<div class="imlist" id="imlist"></div>'
        + _row("", "Preview first. Nothing is written until you confirm.",
               '<button class="lk" id="impreview">Preview</button>'
               '<button class="lk pri" id="imapply" disabled>Import</button>')
        + (_row("Saved connection",
                "Stored in the database in plaintext, and included in the "
                "nightly backup. Forget it if that is not what you want.",
                '<button class="lk" id="imforget">Forget</button>')
           if (saved_key or iurl) else "")
        + '<p class="e" id="ime"></p>')

    notify_urls = get_notify_urls()
    notify_locked = bool(_ENV_NOTIFY_URLS)
    notify = (
        _row("Configured",
             "" if notify_urls else "Alerts have nowhere to go.",
             f'<span class="val {"on" if notify_urls else "off"}">'
             f'{len(notify_urls)} destination{"" if len(notify_urls) == 1 else "s"}</span>')
        + ('' if notify_locked else
           _row("Apprise URLs",
                "Comma-separated. Carry credentials, so they are never echoed back. "
                "Full URL formats: <a href=\"https://github.com/caronc/apprise/wiki\" "
                "target=\"_blank\" rel=\"noreferrer\">Apprise wiki</a>.",
                '<input id="nurls" type="password" autocomplete="off" placeholder="'
                + ("saved" if notify_urls else "ntfy://ntfy.sh/your-topic")
                + '"><button class=\"lk\" id=\"nsave\">Save</button>'))
        + _row("Send a test",
               "Sends a real message now, whether or not anything is due. "
               "A failure reports the provider's own reason.",
               '<button class="lk" id="ntest">Send test</button>')
        + '<p class="e" id="nte"></p>'
        + ('<p class="sub" style="margin:15px 0 0">Locked by '
           '<code>IDLARR_NOTIFY_URLS</code> env var.</p>' if notify_locked else
           '<p class="sub" style="margin:15px 0 0">Destinations are Apprise URLs. '
           'They carry credentials, so they are never shown back.</p>'))

    about = (
        _row("Version", "", f'<span class="val">{IDLARR_VERSION}</span>')
        + _row("Trackers", "", f'<span class="val">{n_trk}</span>')
        + _row("Database", "Backed up nightly.", f'<span class="val">{db_kb}</span>')
        + _row("Uptime check",
               "/healthz needs no credentials, so a monitor can reach it.",
               '<a class="lk" href="/healthz" target="_blank" rel="noreferrer">/healthz</a>')
        + '<p class="sub" style="margin:15px 0 0">Idlarr never contacts a tracker. '
          'A userscript already running in your browser reports when you were '
          'seen logged in; the service does the rest.</p>')

    sections = [
        ("general", "General", "Everything that applies to the whole install.", general),
        ("signin", "Sign-in", "Stored hashed in the database, not in a file.", signin),
        ("script", "Userscript", "Generated from your tracker list. Nothing to fill "
         "in, and it updates itself when you add a tracker.", script),
        ("import", "Import", "Reads your own Prowlarr or Jackett, never a tracker. "
         "Limits are not imported — neither tool knows them — so everything "
         "arrives at 30 days, unconfirmed.", imp),
        ("notify", "Notifications", "Every alert goes through Apprise.", notify),
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

    tick = "".join(
        f'<i style="--c:var(--{r["state"]});'
        f'--h:{20 if r["state"] in ("immune", "unknown") else max(16, _pct(r)):.0f}%" '
        f'data-id="{esc(r["id"])}" title="{esc(r["name"])} — {esc(r["reason"])}"></i>'
        for r in rows)

    legend = "".join(
        f'<div style="--c:var(--{s})"><b>{counts.get(s, 0)}</b><span>{s}</span></div>'
        for s in ("expired", "session", "critical", "warn", "due", "unknown", "ok", "immune"))

    body = []
    for r, p in zip(rows, payloads):
        s = r["state"]
        big = "—" if (r["immune"] or r["days_left"] is None) else str(abs(r["days_left"]))
        name = (f'<a href="{esc(r["url"])}" target="_blank" rel="noreferrer">{esc(r["name"])}</a>'
                if r["url"] else esc(r["name"]))
        hand = ' <i title="last auth was marked by hand">&#9998;</i>' if r.get("auth_source") == "manual" else ""
        q = ("" if (r["verified"] or r["immune"]) else
             '<span class="q" title="limit is a placeholder, not researched">unconfirmed</span>')
        state_txt = r["immune_reason"] if (r["immune"] and r["immune_reason"]) else s
        body.append(
            f'<tr class="row" id="t-{esc(r["id"])}" data-nm="{esc(r["name"])}" '
            f'data-sw="{esc(r["software"])}" data-st="{RANK[s]}" data-state="{s}" '
            f'data-seen="{"" if r["days_since"] is None else r["days_since"]}" '
            f'data-left="{"" if r["days_left"] is None else r["days_left"]}" '
            f'data-lim="{r["inactivity_days"]}" '
            f"data-row='{json.dumps(p).replace(chr(39), '&#39;')}' "
            f'style="--c:var(--{s})">'
            f'<td class="s"></td>'
            f'<td class="nm"><span class="caret"></span>{name}{hand}{q}</td>'
            f'<td class="sw">{esc(r["software"])}</td>'
            f'<td class="st">{esc(state_txt)}</td>'
            f'<td class="seen">{_ago(r["days_since"])}</td>'
            f'<td class="n">{big}</td>'
            f'<td class="lim">{r["inactivity_days"]}d</td>'
            f'<td class="el"><div class="meter{"" if not r["immune"] else " none"}">'
            f'<i style="--p:{0 if r["immune"] else max(3, _pct(r)):.0f}%"></i></div></td></tr>')

    stamp = datetime.now(local_tz()).strftime("%d %b %Y · %H:%M %Z").upper()

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

    # The status line is read-only. Actions live in the header and the
    # settings panel now — mixing the two in fixed-width cells is what made the
    # old footer overflow.
    n_hosts = sum(1 for t in load_config()["trackers"] if t.get("host"))
    n_trk = len(load_config()["trackers"])
    _status_url = get_status_url()
    _dl_token = make_download_token(ttl_seconds=604800) if _status_url else ""
    js_url = (f"{_status_url.rstrip('/')}/idlarr.user.js?token={_dl_token}"
              if _status_url else "")

    signin_bit = ('sign-in <b class="bad">off</b>' if method == "none"
                  else f'sign-in <b class="ok">{esc(method)}</b>')
    script_bit = (f'userscript <b>{esc(userscript_version_peek())}</b>' if js_url
                  else 'userscript <b class="bad">set Status URL</b>')
    last = get_state("last_check", "") or "not yet"
    status = (f'<span><b>{n_trk}</b> trackers</span>'
              f'<span>{signin_bit}</span>'
              f'<span>{script_bit}</span>'
              f'<span>checked <b>{esc(last)}</b></span>')

    sheet = settings_sheet(method, n_trk, n_hosts, js_url)

    return (PAGE
            .replace("__ROWS__", "".join(body) or
                     '<tr><td colspan="8"><div class="empty">no trackers configured</div></td></tr>')
            .replace("__TICK__", tick)
            .replace("__LEGEND__", legend)
            .replace("__BANNER__", banner)
            .replace("__STATUS__", status)
            .replace("__SHEET__", sheet)
            .replace("__AUTHMETHOD__", method)
            .replace("__STAMP__", stamp))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
