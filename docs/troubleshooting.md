# Troubleshooting

What to do when a tracker stops recording, and how to restore from a backup.

Run `__idlarr()` in the browser console on that site. It reports the script's own
view of the page — whether it considers you authenticated, which detection path
ran, the logout element it matched, whether a visible password field vetoed it,
and any logout-shaped elements it rejected:

```js
__idlarr()
```

That object answers nearly every "why isn't this working" question without a
round of guessing. Common outcomes:

| What you see | What it means |
|---|---|
| `logoutFound: false`, `candidates` non-empty | the heuristic missed a convention — widen it, or set `auth_sel` |
| `candidates: []` | no logout control in the DOM at all (common in single-page apps) — point `auth_sel` at something else that only exists when logged in |
| `isAuthed: true` but nothing recorded | check the lines above it; a debounce or a `401` will say so |
| `visiblePasswordField: true` | you're on a login page, or a change-password form |
| `__idlarr` is not defined | the script isn't running here at all — see below |

**If a tracker you just added does nothing**, the browser's copy of the script is
probably older than your config. It updates on your manager's own schedule, not
the moment you add a tracker. Force an update from your manager's dashboard — in Violentmonkey, the
script's ⋮ menu, *Check for updates* — or reinstall from Settings → Userscript.
Compare the `@version` in the installed script against the one the service is
serving; if they differ, that's the whole answer.


# Restoring a backup

Snapshots land in `/data/backups/` as `idlarr-YYYY-MM-DD.db`, written nightly
during the daily check via SQLite's online backup API. Restoring one is a file
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
snapshot. **Verified against a real deployment** — 23 trackers with every state
and last-auth date intact.

Two things to expect. A restored snapshot **re-runs that day's check and
re-sends its alert**, because the backup is written just before the "already
checked today" marker — so restoring on a day something was due gives you a
duplicate push. And a restore rolls back to the last nightly snapshot, so auth
events recorded since then are gone; the countdowns will read older than
reality until the userscript reports again.

Practising this on a second container first — separate port, separate `data/`
and `config/` — costs nothing and is how the behaviour above was found. Never
point a test instance at your live `config/`: the status page **writes** to
`trackers.yml`.

