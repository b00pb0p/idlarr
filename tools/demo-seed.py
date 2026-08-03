#!/usr/bin/env python3
"""Build a demo instance for screenshots.

The README asks contributors to screenshot a demo instance rather than their own
— the status page lists every tracker you are a member of, which is not
something to publish. This makes that demo look like a real install instead of
twelve rows of `unknown`: twelve fictional trackers, every state on the ladder
represented, and enough auth history that an expanded drawer has something in
it.

    python3 tools/demo-seed.py /tmp/idlarr-demo    # chowns to 1001 for you
    docker run --rm -p 8090:8080 \
      -v /tmp/idlarr-demo/data:/data -v /tmp/idlarr-demo/config:/config \
      -e IDLARR_TOKEN=demo -e IDLARR_NOTIFY_URLS=ntfy://ntfy.sh/idlarr-demo \
      -e STATUS_URL=http://localhost:8090 -e TZ=America/Chicago \
      ghcr.io/b00pb0p/idlarr:latest

Then open http://localhost:8090, expand a row, and capture.

Run it live rather than saving the HTML: the drawer fetches its auth history
from /api/history, which cannot work from a file:// page.
"""

import os
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (id, days since last auth, days since last visit, source) -> intended state.
# The ladder is in CLAUDE.md; these numbers are chosen to land one row on each
# rung so a screenshot shows the whole range rather than a wall of green.
PLAN = [
    ("nebula",     34,  34, "userscript"),   # expired  — 30d limit, 4 over
    ("ironclad",   57,  57, "userscript"),   # critical — 60d limit, 3 left
    ("redshift",   80,  80, "userscript"),   # warn     — 90d limit, 10 left
    ("papertrail", 240, 240, "userscript"),  # due      — 365d limit, past 65%
    ("vinylvault", 20,   1, "userscript"),   # session  — fresh visit, stale auth
    ("cinephile",  10,  10, "manual"),       # ok, and marked by hand
    ("lossless",    3,   3, "userscript"),   # ok
    ("retroroms",   6,   6, "userscript"),   # ok
    ("animeattic",  7,   7, "userscript"),   # immune
    ("comixcrypt", 40,  40, "userscript"),   # immune
    # docuwatch and sportsball are left with no events, so they read `unknown`
]


def main(target: Path) -> None:
    data, config = target / "data", target / "config"
    data.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "demo-trackers.yml", config / "trackers.yml")

    db = data / "idlarr.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            tracker_id TEXT NOT NULL,
            kind       TEXT NOT NULL,
            ts         TEXT NOT NULL,
            source     TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_lookup
            ON events (tracker_id, kind, ts DESC);
        CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT);
    """)
    now = datetime.now(timezone.utc)
    for tid, auth_d, visit_d, source in PLAN:
        # Three auth events apiece so an expanded drawer has a history to show.
        for offset in (auth_d, auth_d + 14, auth_d + 30):
            conn.execute("INSERT INTO events (tracker_id,kind,ts,source) VALUES (?,?,?,?)",
                         (tid, "auth", (now - timedelta(days=offset)).isoformat(), source))
        conn.execute("INSERT INTO events (tracker_id,kind,ts,source) VALUES (?,?,?,?)",
                     (tid, "visit", (now - timedelta(days=visit_d)).isoformat(), "userscript"))
    conn.commit()
    conn.close()

    # The container runs as UID 1001 and cannot write a root-owned mount. This
    # is the single most common first-run failure, so do it here rather than
    # leaving it as a step to miss.
    owned = True
    for path in (target, data, config, db, config / "trackers.yml"):
        try:
            os.chown(path, 1001, -1)
        except (OSError, AttributeError):
            owned = False
    if not owned:
        print(f"NOTE: could not chown to 1001. Before starting the container:\n"
              f"    chown -R 1001 {target}\n"
              f"Without it startup fails with 'unable to open database file'.\n")

    print(f"demo instance in {target}")
    print(f"  config/trackers.yml  12 fictional trackers")
    print(f"  data/idlarr.db       {len(PLAN)} seeded, 2 left as `unknown`")
    print("\nSet a sign-in from the page before capturing, or the red "
          "'no sign-in configured' banner dominates the shot.")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/idlarr-demo"))
