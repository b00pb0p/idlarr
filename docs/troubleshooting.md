# Troubleshooting

What to do when a tracker stops recording, and how to restore from a backup.

Run `__idlarr()` in the browser console on that site. It reports the script's own
view of the page: whether it considers you authenticated, which detection path
ran, the logout element it matched, whether a visible password field vetoed it,
and any logout-shaped elements it rejected:

```js
__idlarr()
```

That object answers nearly every "why isn't this working" question without a
round of guessing. Common outcomes:

| What you see | What it means |
|---|---|
| `logoutFound: false`, `candidates` non-empty | the heuristic missed a convention. Widen it, or set `auth_sel` |
| `candidates: []` | no logout control in the DOM at all (common in single-page apps). Point `auth_sel` at something else that only exists when logged in |
| `isAuthed: true` but nothing recorded | check the lines above it; a debounce or a `401` will say so |
| `visiblePasswordField: true` | you're on a login page, or a change-password form |
| `__idlarr` is not defined | the script isn't running here at all. See below |

**If a tracker you just added does nothing**, the browser's copy of the script is
probably older than your config. **The status page now says so itself**: once any
tracker reports in, the script tells the service which version it is running, and
an amber banner appears when that is behind what is being served, with an
**Update now** link. If you see no banner, the installed version is current and
the problem is elsewhere. It updates on your manager's own schedule, not
the moment you add a tracker. Force an update from your manager's dashboard
(in Violentmonkey, the
script's ⋮ menu, *Check for updates*), or reinstall from Settings → Userscript.
Compare the `@version` in the installed script against the one the service is
serving; if they differ, that's the whole answer.


# The daily check has not run

**Settings → System** tells you directly. The **Daily check** row carries the
timestamp of the last run and, beneath it, when the next one is due: `runs today
at 23:00`, `runs tomorrow at 23:00`, or `due now`.

Three things look identical from a stale timestamp alone, and the next-run line
is what separates them.

**It already ran today, and you moved the check hour later.** The scheduler is
keyed on a *date*, not a time: a day it has already checked is finished, so
moving `check_hour` from 09:00 to 23:00 at lunchtime produces no second run that
evening. The new hour takes effect tomorrow. The row reads `runs tomorrow at
23:00` and nothing is wrong.

**The container was down across the check hour.** The gate is `hour >=
check_hour`, so the catch-up window is the rest of the day. At 09:00 that leaves
fifteen hours and a container that missed nine o'clock still checks when it comes
back. At 23:00 it leaves one, and a restart spanning midnight skips that day
outright: at 00:10 the hour test fails and nothing runs until 23:00 tomorrow.
Press **Run now** to cover the gap.

**The scheduler is genuinely stuck.** The row reads `due now` and keeps reading
it. The loop wakes every ten minutes, so that state should be almost impossible
to catch; still seeing it after a reload means the loop is not running. Check
`docker logs` for a traceback and restart the container.

A useful cross-check: the **Daily check** row shows the tracker count *at the
time it ran*. If that number disagrees with what the page shows now, nothing has
run since you last added or imported a tracker.

## Running one by hand

**Settings → System → Run now** does the real thing: it takes the backup,
evaluates every countdown and sends whatever is due. It is not a dry run, and it
is not the notification test, which only proves the delivery path works.

It counts as that day's run, so the scheduled one will not fire again today, and
the row records that it was run by hand. It does not send a heartbeat.

# Restoring a backup

Snapshots land in `/data/backups/` as `idlarr-YYYY-MM-DD.db`, written during
the daily check (at your `check_hour`, not overnight) via SQLite's online
backup API. Restoring one is a file
copy:

```bash
docker compose stop
cp data/backups/idlarr-2026-08-03.db data/idlarr.db
chown 1001 data/idlarr.db
docker compose start
```

`cp` creates the copy with your umask rather than the source's mode, so the
restored file may land world-readable. Startup tightens it back to `0600`, but
`chmod 600 data/idlarr.db` before starting closes the window.

Startup logs the tracker count; the page should show your countdowns as of that
snapshot. **Verified against a real deployment**: 23 trackers with every state
and last-auth date intact.

Two things to expect. A restored snapshot **re-runs that day's check and
re-sends its alert**, because the backup is written just before the "already
checked today" marker, so restoring on a day something was due gives you a
duplicate push. And a restore rolls back to the last daily snapshot, so auth
events recorded since then are gone; the countdowns will read older than
reality until the userscript reports again.

Practising this on a second container first (separate port, separate `data/`
and `config/`) costs nothing and is how the behavior above was found. Never
point a test instance at your live `config/`: the status page **writes** to
`trackers.yml`.

