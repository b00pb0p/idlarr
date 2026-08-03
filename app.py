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

# ---------------------------------------------------------------- config

DB_PATH = Path(os.environ.get("IDLARR_DB", "/data/idlarr.db"))
CONFIG_PATH = Path(os.environ.get("IDLARR_CONFIG", "/config/trackers.yml"))
TOKEN = os.environ.get("IDLARR_TOKEN", "")
STATUS_URL = os.environ.get("STATUS_URL", "")  # appended to alerts so you can tap through

# Every notification goes through Apprise -- ntfy included, via ntfy:// or
# ntfys://. One code path, ~100 services, nothing bespoke to maintain. See
# https://github.com/caronc/apprise/wiki for each service's URL scheme.
# These strings carry credentials, so they are never printed.
NOTIFY_URLS = [u.strip() for u in os.environ.get("IDLARR_NOTIFY_URLS", "").split(",") if u.strip()]

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

KNOWN_SOFTWARE = {"gazelle": "Gazelle", "unit3d": "UNIT3D", "tbdev": "TBDev",
                  "custom": "Custom"}

_cfg_cache = {"mtime": 0.0, "data": None}


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
                        immune_reason: str | None = None) -> None:
    """Rewrite one tracker's inactivity_days / verified in trackers.yml.

    A surgical line edit, NOT a yaml.safe_dump round-trip. The comments in
    trackers.yml are load-bearing — the fail-safe warning block and the
    per-tracker notes about seeding/user class/vacation mode are the whole
    point of item 1 — and dumping would erase every one of them.

    Writes atomically via os.replace, and refuses to install a file that
    doesn't parse or that changes the tracker count.
    """
    if all(v is None for v in (inactivity_days, verified, immune, immune_reason)):
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

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(candidate)
        os.replace(tmp, CONFIG_PATH)

    # Force a reload rather than trusting mtime granularity on fuse/shfs mounts.
    _cfg_cache["data"] = None


# ---------------------------------------------------------------- storage

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


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
        out["reason"] = "No login ever recorded. Log in once to initialise, or mark it seen."
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
    if STATUS_URL:
        body += f"\n\n{STATUS_URL}"

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


async def notify(rows: list[dict]) -> None:
    payload = build_notification(rows)
    if payload is None:
        print("[notify] nothing due")
        return
    if not NOTIFY_URLS:
        print("[notify] IDLARR_NOTIFY_URLS is empty -- alert not sent")
        return

    try:
        import apprise
    except ImportError:
        print("[notify] apprise is not installed (pip install apprise)")
        return

    def _send() -> bool:
        ap = apprise.Apprise()
        for url in NOTIFY_URLS:
            if not ap.add(url):
                # Never print the URL itself: these contain credentials.
                print(f"[notify] apprise rejected a URL (scheme '{url.split('://')[0]}')")
        if not len(ap):
            print("[notify] no usable notification URLs")
            return False
        return ap.notify(title=payload["title"], body=payload["body"],
                         notify_type=apprise_type(payload["priority"]))

    try:
        # Apprise is synchronous; a slow provider must not stall the scheduler.
        ok = await asyncio.to_thread(_send)
        n = payload["body"].count("\n") + 1
        print(f"[notify] {'sent' if ok else 'FAILED'} to {len(NOTIFY_URLS)} target(s), {n} item(s)")
    except Exception as exc:   # never let a push failure kill the loop
        print(f"[notify] FAILED: {exc}")


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
        print(f"[backup] pruned {len(stale)} old snapshot(s)")
    return dest


async def scheduler() -> None:
    """Wake often, act once per local day. Survives restarts without drift."""
    while True:
        try:
            cfg = load_config()
            now_local = datetime.now(local_tz())
            today = now_local.date().isoformat()
            if now_local.hour >= cfg["check_hour"] and get_state("last_check") != today:
                print(f"[check] running for {today}")
                # Back up before notifying, and never let a backup failure stop
                # the alert — the alert is the whole point of the service.
                try:
                    dest = backup_db(today)
                    if dest:
                        print(f"[backup] {dest} ({dest.stat().st_size} bytes)")
                except Exception as exc:
                    print(f"[backup] FAILED: {exc}")
                await notify(statuses())
                set_state("last_check", today)
        except Exception as exc:
            print(f"[check] error: {exc}")
        await asyncio.sleep(600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Refuse to start rather than run without authentication. A container that
    # will not boot is impossible to miss; an open /ping is invisible until
    # something writes to your database that you did not send.
    if not TOKEN:
        raise RuntimeError(
            "IDLARR_TOKEN is not set — refusing to start. An empty token would "
            "disable authentication entirely and /ping would accept anything. "
            "Generate one with `openssl rand -hex 32`, put it in .env, and use "
            "the same value for TOKEN in the userscript."
        )
    if not NOTIFY_URLS:
        # Not fatal -- the status page still works -- but a watchdog that
        # cannot reach you is the exact failure this project exists to avoid,
        # and silence is indistinguishable from "nothing is due".
        print("[startup] WARNING: IDLARR_NOTIFY_URLS is empty. "
              "Alerts will go nowhere. See .env.example.")
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

    if RESET_AUTH:
        # Clearing session_secret as well is the point: a password reset that
        # left existing cookies valid would not lock out whoever you are
        # resetting because of.
        for key in ("auth_method", "auth_user", "auth_hash", "session_secret"):
            set_state(key, "")
        print("[startup] IDLARR_RESET_AUTH is set — UI authentication has been "
              "cleared and every existing session invalidated. Remove the "
              "variable, restart, then set a new login from the status page.")

    if not CONFIG_PATH.exists():
        raise RuntimeError(
            f"No tracker config at {CONFIG_PATH}.\n"
            f"  Copy the example into the directory you mounted at /config:\n"
            f"      cp trackers.example.yml config/trackers.yml\n"
            f"  If you did create it, /config is mounted somewhere else."
        )
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


def require_token(auth: str | None) -> None:
    """Fails CLOSED. An earlier version returned early when TOKEN was empty,
    which meant a missing or misspelled env var silently turned /ping into an
    open endpoint — and looked identical to working. `lifespan` refuses to
    start without a token, so this branch should be unreachable; it exists so
    that if it ever is reached, the answer is 'no' rather than 'yes'."""
    if not TOKEN:
        raise HTTPException(status_code=500,
                            detail="server misconfigured: IDLARR_TOKEN is not set")
    if auth != f"Bearer {TOKEN}":
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
    if all(v is None for v in (days, verified, immune, immune_reason)):
        raise HTTPException(400, "nothing to update")

    try:
        save_tracker_fields(tracker_id, days, verified, immune, immune_reason)
    except (KeyError, ValueError) as exc:
        raise HTTPException(500, f"config write refused: {exc}")

    row = next(r for r in statuses() if r["id"] == tracker_id)
    return clean(row)


@app.post("/api/unmark/{tracker_id}", dependencies=[Depends(require_ui)])
async def unmark(tracker_id: str):
    """Undo the most recent auth event — a misclicked 'seen', or an auth the
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
    """Stays open on purpose. Open item 1 wants an uptime monitor pointed here,
    and a monitor that needs credentials is a monitor that will not get set up.
    It discloses a tracker count and nothing else."""
    return {"ok": True, "trackers": len(load_config()["trackers"])}


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


@app.post("/api/test-notify")
async def test_notify(authorization: str | None = Header(default=None)):
    require_token(authorization)
    await notify(statuses())
    return {"ok": True}


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
  .note{margin-top:9px;font-size:10.5px;color:var(--dim);font-style:italic}
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
</style></head><body><div class="wrap">

<div class="bar"><h1>Idlarr</h1><span class="tag">never lose an account to inactivity</span><span class="stamp">__STAMP__</span>
  <div class="msort"><select id="msf" aria-label="sort by">
    <option value="st">state</option><option value="nm">tracker</option>
    <option value="left">left</option><option value="seen">last auth</option>
    <option value="lim">limit</option><option value="sw">software</option>
  </select><button id="msd" aria-label="reverse sort">&#8645;</button></div>
  <div class="tick">__TICK__</div></div>
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
&middot; no request is ever made to a tracker.<br>__AUTHFOOT__
</div>
</div>

<div class="modal" id="am"><div class="box">
  <h3>Sign-in</h3>
  <p class="hint">Stored hashed in the database, not in a file. Changing it signs
  every other browser out. Forgotten it? Restart with <b>IDLARR_RESET_AUTH=1</b>.</p>
  <label for="amm">method</label>
  <select id="amm">
    <option value="forms">Forms &mdash; login page</option>
    <option value="basic">Basic &mdash; browser prompt</option>
    <option value="none">None &mdash; no sign-in</option>
  </select>
  <div id="amc">
    <label for="amu">username</label><input id="amu" autocomplete="username">
    <label for="amp">password</label>
    <input id="amp" type="password" autocomplete="new-password" placeholder="8 characters minimum">
  </div>
  <div id="amcur" style="display:none">
    <label for="amx">current password</label>
    <input id="amx" type="password" autocomplete="current-password">
  </div>
  <div class="rowb"><button class="lk" id="amcancel">Cancel</button>
    <button class="lk pri" id="amsave">Save</button></div>
  <p class="e" id="ame"></p>
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
    +'<button class="seen">seen</button><button class="undo danger">undo</button></div>'
    +(imm?'<div class="reason"><input class="rsn" value="'+(d.immune_reason||'')
      +'" placeholder="why immune? e.g. donated, elite class"></div>':'')
    +(!imm&&d.notes?'<div class="note">'+d.notes+'</div>':'')
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

   // Two-step: one stray click here silently resets a countdown.
   const seenBtn=el.querySelector('.seen');let armed=false,t=null;
   seenBtn.addEventListener('click',()=>{
     if(!armed){armed=true;seenBtn.classList.add('arm');seenBtn.textContent='confirm?';
       msg('records a manual auth \\u2014 only if you really just logged in','warn');
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

 const am=document.getElementById('am'),ame=document.getElementById('ame');
 const amm=document.getElementById('amm'),amc=document.getElementById('amc');
 const amcur=document.getElementById('amcur');
 const openAuth=()=>{ame.textContent='';am.classList.add('on');
   amcur.style.display=CURRENT_METHOD==='none'?'none':'';
   amm.value=CURRENT_METHOD==='none'?'forms':CURRENT_METHOD;
   amc.style.display=amm.value==='none'?'none':'';
   (amm.value==='none'?amm:document.getElementById('amu')).focus();};
 const closeAuth=()=>am.classList.remove('on');
 amm.addEventListener('change',()=>{amc.style.display=amm.value==='none'?'none':'';});
 document.getElementById('amcancel').addEventListener('click',closeAuth);
 am.addEventListener('click',e=>{if(e.target===am)closeAuth();});
 document.addEventListener('keydown',e=>{if(e.key==='Escape')closeAuth();});
 document.querySelectorAll('.js-authcfg').forEach(b=>b.addEventListener('click',openAuth));

 const outb=document.getElementById('out');
 if(outb)outb.addEventListener('click',()=>fetch('/logout',{method:'POST'})
   .then(()=>location.href='/login'));

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
        authfoot = ('Sign-in <b>off</b> &middot; '
                    '<button class="lk js-authcfg">configure</button>')
    else:
        banner = ""
        authfoot = (f'Signed in as <b>{esc(get_state("auth_user", "") or "")}</b> '
                    f'({esc(method)}) &middot; '
                    f'<button class="lk js-authcfg">change</button> '
                    f'<button class="lk" id="out">sign out</button>')

    return (PAGE
            .replace("__ROWS__", "".join(body) or
                     '<tr><td colspan="8"><div class="empty">no trackers configured</div></td></tr>')
            .replace("__TICK__", tick)
            .replace("__LEGEND__", legend)
            .replace("__BANNER__", banner)
            .replace("__AUTHFOOT__", authfoot)
            .replace("__AUTHMETHOD__", method)
            .replace("__STAMP__", stamp))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
