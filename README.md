# Idlarr

**Never lose an account to inactivity again.**

[![tests](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml/badge.svg)](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml)

Let me preface this by being clear about something; this is stupid. Idlarr was created
to automate and fix a problem I had ONCE in 15+ years. It's more than likely unnecessary,
definitely overkill, but it's 2026 and we all have tokens to burn. Now that's out of the
way....

Private trackers prune accounts that go idle. Idlarr watches how long it has been
since you actually logged in to each one, and pushes a notification before the
clock runs out.

**It never contacts a tracker.** A userscript already running in your browser
reports when you were seen logged in; the service does the rest. There is nothing
for a tracker to detect and nothing to ban you for.

<!-- Replace with your own screenshot; see "Screenshot" below before you do. -->
![The Idlarr status page](docs/screenshot.png)

## Why not just automate the logins?

That was the first thought, and it was scrapped. Plenty of trackers ban automated
logins, and a ban is permanently worse than the inactivity disable it would have
prevented. Idlarr is deliberately passive: it observes a page you were going to
load anyway and never issues a request of its own. If a feature seems to need
one, it doesn't.

## Requirements

- Docker and Docker Compose
- A browser with [Violentmonkey](https://violentmonkey.github.io/),
  [Tampermonkey](https://www.tampermonkey.net/) or
  [Greasemonkey](https://www.greasespot.net/)
- Somewhere to host it. It has its own optional sign-in; behind Tailscale or a VPN is still the belt-and-braces answer
- Somewhere to send notifications: [ntfy](https://ntfy.sh), [Pushover](https://pushover.net/),
  [Pushbullet](https://www.pushbullet.com/), [Discord](https://discord.com/), [Telegram](https://telegram.org/),
  or anything else [Apprise](https://github.com/caronc/apprise) supports

FastAPI + SQLite in one container. No Postgres, no build step, one DB file.

## How it works

0. You install the userscript in one click from the status page. It is
   generated from your tracker list, so there is nothing to fill in, and it
   updates itself when you add a tracker.
1. You visit a tracker in your normal browser.
2. The userscript checks whether you're authenticated and POSTs `{tracker, kind}`
   to the service. Two event kinds:
   - `visit`: fires on every page load
   - `auth`: fires only when you're actually logged in
3. Daily, the service compares `last auth` against that tracker's inactivity limit
   and pushes an escalating alert if you're getting close.

Tracking both kinds is what separates *"my session died"* from *"I haven't been
there in two months"* from *"the userscript broke."*

## Quickstart

Five minutes if nothing surprises you. The full walkthrough, covering every environment
variable, a different UID, building from source and worked config examples, is in
**[docs/setup.md](docs/setup.md)**.

**1. Directories.** The `chown` matters: the container runs as UID 1001 and
cannot create these itself. If Docker creates them they come out root-owned and
startup fails with `unable to open database file`.

```bash
mkdir -p idlarr/data idlarr/config && cd idlarr
chown -R 1001 data config
curl -fsSLO https://raw.githubusercontent.com/b00pb0p/idlarr/main/.env.example
cp .env.example .env
```

There is no config to copy. An empty `trackers.yml` is created on first boot,
and you add trackers from the page.

**2. Settings.** Only one thing is worth setting before you start:
`IDLARR_NOTIFY_URLS`, an [Apprise](https://github.com/caronc/apprise) URL,
`ntfy://ntfy.sh/your-topic`, `pover://USER@TOKEN`, `discord://ID/TOKEN`, and
~100 more. Without it the service runs and warns, but nothing can reach you.

Set `STATUS_URL` to the address you'll reach the page on. The userscript is
generated from it. It seeds the config on first run; afterwards you change it
in **Settings → General** rather than here.

`IDLARR_TOKEN` is optional. One is generated on first boot and the userscript
you install already carries it. Set it only to pin a specific value.

**3. Deploy.** A prebuilt multi-arch image is published to GHCR:

```yaml
services:
  idlarr:
    image: ghcr.io/b00pb0p/idlarr:latest
    container_name: idlarr
    restart: unless-stopped
    ports:
      - "8099:8080"
    volumes:
      - ./data:/data
      - ./config:/config
    env_file: .env
```

```bash
docker compose up -d
```

`latest` follows releases, `1.2` pins a minor, `edge` tracks `main`.

**4. Userscript.** Install a userscript manager
([Violentmonkey](https://violentmonkey.github.io/),
[Tampermonkey](https://www.tampermonkey.net/) or
[Greasemonkey](https://www.greasespot.net/)),
open the status page, and click **Install** in the Userscript section of
settings. The script is generated from your tracker list, with nothing to fill in, and
and it updates itself when you add a tracker.

**5. Bootstrap.** Everything starts at `no data`. Visit each tracker while
logged in, or open a row and click **seen** to assert it by hand.

Then add your real trackers from the page, or import them from Prowlarr or
Jackett. See **[docs/trackers.md](docs/trackers.md)**.

## Signing in

Optional, and off until you set it up. Configure it from the status page:
there is no password in `.env`, and nothing to edit in a file. The credentials
are stored **hashed** (PBKDF2-HMAC-SHA256) in the database, so they ride along
in the daily backup and change without recreating the container.

| Method | What a stranger sees |
|---|---|
| **None** | The dashboard. Also `POST /api/mark`, which resets a countdown. |
| **Forms** | A login page. |
| **Basic** | The browser's own credentials prompt. |

Under **Forms**, HTTP Basic credentials are still accepted on the API, so curl
and scripts work without a login round-trip. The setting decides how you are
*challenged*, not which credentials are valid.

### Do I need it?

Behind Tailscale, a VPN, or an authenticating reverse proxy: no, and the
default costs you nothing. On a shared network such as university halls,
shared housing or an office: yes. The risk is not that someone reads your
tracker list, though they can. It is that `POST /api/mark/{id}` needs no
credentials with auth off, and one call silently resets a countdown. Your
dashboard then reads `ok`
while the account ages out, which is the precise failure this whole service
exists to prevent.

The status page says so in a banner until you either set a login or dismiss it,
and the startup log names the three things an open instance exposes. Optional
should not mean easy to forget.

### If you forget the password

There is no config file to hand-edit, so there is an env var instead:

```bash
IDLARR_RESET_AUTH=1
```

Start once. The login is cleared and every existing session is invalidated,
then **remove the variable and restart again**, or the next boot clears it
right back.

### What it does not cover

`/healthz` stays open so an uptime monitor needs no credentials. `/ping` keeps
using `IDLARR_TOKEN`, which is unchanged: one credential for the userscript,
one for you, the same split the *arr apps use. And the login is only as strong
as the transport. Over plain HTTP on an untrusted network, use a VPN or put
TLS in front of it.

## The status page

One card per account, worst first: **tracker · state · left · elapsed**, with
the software under each name, and last auth and the limit on the elapsed line.
Click **tracker**, **state**, **left** or **elapsed** to sort by it, elapsed
being how much of that tracker's window has burned. Blanks always sort last, so
a tracker with no data can never outrank one that's expiring.

Click a **name** to open that tracker in a new tab. Click anywhere else on the
row to expand a drawer with three panels:

- **controls**: limit, alert threshold, snooze, notes, `confirm`, `immune`
  (with a reason field), `seen`, `undo`, `remove`
- **alert schedule**: the exact date each rung fires, or why it won't
- **auth history**: recent auth events, and whether each was observed or asserted

**Add tracker**, the settings gear and, when sign-in uses Forms, a **sign-out**
icon sit top right. Everything configurable lives behind the gear, in eight
sections. Closing the panel discards anything you have not saved.

| | |
|---|---|
| **General** | timezone, check hour, alert threshold, still-alive push, status page URL, backup retention |
| **Sign-in** | method, credentials, and sign out when the method is Forms |
| **Userscript** | coverage, endpoint, **Install** and **Copy URL** |
| **Import** | Prowlarr or Jackett, torrent and usenet |
| **Notifications** | add, name, mute, test and remove destinations, and a **Send test** for all |
| **API** | the read-only key, masked behind an eye, with **Copy** and **Regenerate** |
| **System** | what the daily check, backup, alert and heartbeat last did, when the check runs next, a **Run now** button, and config download and restore |
| **About** | version, tracker count, userscript version, last check, database size, `/healthz` |

General holds exactly what the **Save** button writes. Anything read-only, and
the two file actions, live in **System**.

The tracker total leads the count strip at the top, beside the per-state counts.
The userscript version and the date of the last daily check live in **About**;
sign-in state is announced by the red banner and the **Sign-in** panel rather
than repeated in a footer.

On a phone each card re-grids to fit: the countdown moves beside the name and
the elapsed bar spans the full width. The settings nav becomes a scrolling
tab strip.

Limits written here go straight into `trackers.yml`, comments intact,
hot-reloaded, no restart. `seen` is two-step on purpose.

## Managing trackers

**Add** from the header, or **Import** from your own Prowlarr or Jackett in the
settings panel. Remove one by opening its row. Everything lands at **30 days,
unconfirmed**, because a limit nobody has read off the tracker's own rules page
is a guess, and a guess that is too high is the one that loses the account.

Imports cover **torrent and usenet**, both ticked by default. Prowlarr holds
both, and a usenet account lapses for inactivity the same way a tracker account
does. Jackett is torrent-only.

Imports never carry a limit: neither Prowlarr nor Jackett knows an inactivity
policy, and a wrong number arriving with the authority of an import is worse
than no number.

Full detail on importing, editing `trackers.yml` by hand, `host` overrides and
the `auth_sel` escape hatch for sites the auth heuristic cannot read is in
**[docs/trackers.md](docs/trackers.md)**.

## Alert escalation

Relative to each tracker's inactivity limit:

| Remaining | State | Priority | Reaches you as |
|---|---|---|---|
| immune | immune | none | never alerts |
| snoozed (date in future) | snoozed | none | never alerts, expires by itself |
| > 35% | ok | none | silent |
| ≤ 35% (or past `alert_at_pct`) | due | `default` | *info* |
| ≤ 14 days | warn | `high` | *warning* |
| ≤ 5 days | critical | `urgent` | *failure* |
| past the limit | expired | `urgent` | *failure* |
| visited while logged out | session, shown as **logged out** | `high` | *warning* |
| no auth event ever recorded | unknown | none | silent |

The right-hand column is the Apprise severity, which each service renders in its
own way: a color in Discord, a priority level in Pushover, a tag in ntfy.

`unknown` is the state every tracker starts in, and it stays there until the
userscript reports an authenticated visit. It is silent on purpose: there is no
baseline to count from, so there is nothing to be late for. A tracker stuck on
`unknown` after you have visited it means the script is not reporting, which
[Troubleshooting](docs/troubleshooting.md) covers.

## Still-alive push

The check runs once per local day, at `check_hour`. **Settings → System** shows
when it last ran and when it runs next, and **Run now** runs one immediately:
back up, evaluate every countdown, send anything due. Use it after a restart
that spanned the check hour, since a missed window is not retried until the
same hour tomorrow.

Nothing else watches the watchdog. If this container dies, the daily check and
the backup it takes both stop, and **silence is exactly what a healthy quiet
day looks like**. You would not find out until an account was gone.

Turn on a heartbeat in *Settings → General → Still-alive push*: daily, weekly or
monthly. It sends one low-priority message, *"Idlarr is running. Watching
23 trackers. Closest: Anthelion, 4 days left."* Once you expect one every
Monday, its absence means something.

Off by default. Unrequested notifications are how people learn to ignore the
ones that matter. It runs after the daily check and only when nothing was due,
so a day with a real alert never also gets a heartbeat, and a failed send is not
recorded as sent. Otherwise one lost push would silence the next one too.

The alternative, if you already run monitoring: point an uptime monitor at
`/healthz`, which needs no credentials for exactly this reason.

Alerts batch into **one message per day**, not one per tracker. A dozen separate
pushes is how someone starts ignoring them. It repeats daily while anything is
actionable. One 3am push is how accounts get lost.

## Notifications

Everything goes through [Apprise](https://github.com/caronc/apprise), which
speaks around a hundred services, **including ntfy**. One setting, one code
path, nothing bespoke to maintain.

```bash
IDLARR_NOTIFY_URLS=ntfys://ntfy.example.com/my-topic?token=tk_xxx
```

Comma-separate for several destinations:

```bash
IDLARR_NOTIFY_URLS=pover://USER_KEY@APP_TOKEN,discord://WEBHOOK_ID/WEBHOOK_TOKEN
```

| Service | URL format |
|---|---|
| [ntfy.sh](https://ntfy.sh) | `ntfy://ntfy.sh/your-topic` |
| self-hosted ntfy | `ntfys://ntfy.example.com/your-topic?token=tk_xxx` |
| [Pushover](https://pushover.net/) | `pover://USER_KEY@APP_TOKEN` |
| [Pushbullet](https://www.pushbullet.com/) | `pbul://ACCESS_TOKEN` |
| [Discord](https://discord.com/) | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| [Telegram](https://telegram.org/) | `tgram://BOT_TOKEN/CHAT_ID` |
| [Signal](https://signal.org/) | `signal://HOST:PORT/FROM/TO` (needs signal-cli-rest-api) |
| [Slack](https://slack.com/) | `slack://TOKEN_A/TOKEN_B/TOKEN_C/#channel` |
| [Matrix](https://matrix.org/) | `matrix://USER:PASS@HOST/#room` |
| [Gotify](https://gotify.net/) | `gotify://HOST/TOKEN` |
| Email | `mailto://user:pass@gmail.com` |

The [Apprise wiki](https://github.com/caronc/apprise/wiki) has the rest.

Alert priority maps to Apprise's own severity, so an expiring account looks
different on your phone from a routine nudge: `default` becomes *info*, `high`
becomes *warning*, `urgent` becomes *failure*.

The status page URL, if set, is appended to the message body rather than used as a
provider-specific click action. Every service renders a URL, only some support
a tap target.

**With `IDLARR_NOTIFY_URLS` empty, nothing can reach you.** Compose refuses to
start without it, and the service warns if it ends up empty anyway.

**These URLs contain credentials.** Keep them in `.env`, which is gitignored.

## Endpoints

There is a **read-only API key** for dashboards, uptime checks and scripts.
It reads and can never write, so a key sitting in a widget's config cannot
reset a countdown. Find it in *Settings, API*, and read
**[docs/api.md](docs/api.md)** for what it opens and what it refuses.

Point anything external at **`/api/summary`**. It is the stable shape.
`/api/status` returns every field of every tracker and follows the page, so it
changes.

<details>
<summary>Full route list</summary>

| Route | Purpose |
|---|---|
| `GET /` | Status page |
| `GET /api/summary` | Counts, worst tracker, next deadline. **The stable shape for other services** |
| `GET /api/status` | Same data as the page, as JSON. Shape follows the page |
| `POST /ping` | Userscript ingest (bearer auth) |
| `POST /api/mark/{id}` | Manual "I just logged in" |
| `POST /api/unmark/{id}` | Remove the most recent auth event |
| `POST /api/limit/{id}` | Set `inactivity_days` / `verified` / `immune` / `snooze_until` / `alert_at_pct` / `notes`, writes trackers.yml |
| `GET /api/history/{id}` | Recent auth events, newest first (drawer) |
| `GET /idlarr.user.js` | The userscript, generated from live config. `?token=` or a session |
| `POST /api/tracker` | Add a tracker, appends to trackers.yml |
| `DELETE /api/tracker/{id}` | Remove one. Auth history is kept |
| `POST /api/import` | Preview (default) or apply a Prowlarr/Jackett import |
| `GET /api/config` | Download `trackers.yml` as it is on disk |
| `POST /api/config` | Replace `trackers.yml`. Validates first, backs up what was there |
| `POST /api/settings` | Edit the `defaults:` block: timezone, check hour, thresholds |
| `GET`/`POST /api/auth` | Read or change the UI login |
| `POST /login` · `POST /logout` | Session in, session out |
| `POST /api/check` | Run the daily check now: back up, evaluate, send anything due |
| `POST /api/apikey` | Regenerate the read-only key. UI login only, never the key itself |
| `POST /api/test-notify` | Send a test notification. Bearer token or a session |
| `GET /healthz` | Health check, **always open**, so an uptime monitor needs no credentials |

Everything above `/api/test-notify` sits behind the UI login **when one is
configured**; with none set they are open, which is the 1.0 behavior. The three
read endpoints (`/api/summary`, `/api/status`, `/api/history/{id}`) also accept
the read-only key, as `X-Api-Key` or `?apikey=`. No write endpoint does. `/ping`
always uses the bearer token, never the login. The userscript posts to it
cross-origin from tracker pages, where cookies do not apply.

</details>

## Things that will bite you

- **With no sign-in set, the write endpoints are open.** `/api/mark`,
  `/api/unmark`, `/api/limit`, `/api/tracker` and `/api/import` all skip auth
  until you configure one, and three of those rewrite `trackers.yml`. The
  dangerous one is `/api/mark`: it resets a countdown, so the page then reads
  `ok` while the account ages out. Set a login, keep it behind Tailscale or a
  VPN, or both.
- **The `seen` button is a bootstrap tool, not a workflow.** The week you tap it
  out of habit without logging in is the week this stops working. It's two-step
  in the UI for that reason, and every row shows whether its last auth was
  *seen by userscript* or *marked by hand*. If a mark was wrong (site was down,
  page came from cache), `undo` removes it.
- **Auth detection is a heuristic**: a `logout` link present, no password field.
  Works on Gazelle/UNIT3D and most PHP trackers. If a site redesigns, it silently
  stops recording `auth`, so you'll get alerts you don't deserve. That's the safe
  failure direction, but check the console (`[idlarr]` logs) before assuming
  the tracker is at fault. Use `auth_sel` to override per-site.
- **`trackers.yml` hot-reloads.** Edit it live; no restart.
- **The database is backed up once a day**, at the start of the daily check
  rather than overnight, to `/data/backups/idlarr-YYYY-MM-DD.db`. 14 days by
  default, set in **Settings → General**. What it last did is in
  **Settings → System**. It is the only record of when each
  account was last seen. Losing it risks no account, but resets every countdown
  to `no data` until you re-visit all of them. See
  [Restoring a backup](docs/troubleshooting.md#restoring-a-backup); it has been tested, and there is one
  surprise in it.
- **Your tracker list can be downloaded and restored** from *Settings →
  System*. The download is the file as it is on disk, comments included.
  Restoring **replaces** it. The current file is saved beside it as
  `trackers.yml.<timestamp>.bak` first, and anything that does not validate is
  refused before a single byte is written. Removed trackers keep their auth
  history, so restoring an older config resumes those countdowns rather than
  restarting them.
- **A backup contains every secret the service holds**: your tracker list, the
  API token, the session secret, the read-only API key, a saved Prowlarr key,
  and any notification destination added in Settings.  Destinations listed in
  `IDLARR_NOTIFY_URLS` are **not** among them: `.env` is not in `/data`, which
  is the reason that route is still supported. The database and its backups are written `0600` so other local users
  cannot read them, and snapshots written before that was enforced are
  restricted on startup, so an upgrade does not leave old ones readable. That
  only protects them *on the box*. If you sync `/data` anywhere (an appdata
  backup plugin, rsync, cloud storage), encrypt it at that layer. Idlarr does
  not encrypt them itself: the key would have to live somewhere it could read
  unattended, and a backup you cannot decrypt is not a backup.
- **The clock is `last auth`, not `last visit`.** Passing by while logged out
  doesn't count, and it shouldn't.

## When something isn't working

Run `__idlarr()` in the browser console on the tracker that won't record. It
reports the script's own view of the page and answers nearly every "why isn't
this working" question without guessing.

Diagnosis table, the stale-script case, why the daily check may not have run,
and how to restore from a backup:
**[docs/troubleshooting.md](docs/troubleshooting.md)**.

The read-only API, what it can and cannot do, and recipes for Uptime Kuma and
dashboard widgets: **[docs/api.md](docs/api.md)**.

## Screenshot

If you contribute one, **screenshot a demo instance, not your own**. The status
page lists every tracker you're a member of, and that is not something to publish.

`tools/demo-seed.py` builds one that looks like a real install: twelve
fictional trackers, every state on the ladder represented, and enough auth
history that an expanded drawer has something in it:

```bash
python3 tools/demo-seed.py /tmp/idlarr-demo    # chowns to 1001 for you
docker run --rm -p 8090:8080 \
  -v /tmp/idlarr-demo/data:/data -v /tmp/idlarr-demo/config:/config \
  -e IDLARR_TOKEN=demo -e IDLARR_NOTIFY_URLS=ntfy://ntfy.sh/idlarr-demo \
  -e STATUS_URL=http://localhost:8090 -e TZ=America/Chicago \
  ghcr.io/b00pb0p/idlarr:edge
```

**`:edge`, not `:latest`.** `latest` follows releases, so it will not show
anything merged since the last tag, so you would be photographing an older app
than the one you are documenting.

No `python3` on the host, common on NAS distributions? Run the seeder inside
the image, which has one. `--user 0` is needed so it can write the mount and
chown it afterwards:

```bash
docker run --rm --user 0 -v "$PWD/tools:/tools" -v /tmp/idlarr-demo:/demo \
  ghcr.io/b00pb0p/idlarr:edge python /tools/demo-seed.py /demo
```

Seed **before** starting the container. Docker creates a missing bind-mount
source as an empty root-owned directory, so starting first gets you
`No tracker config at /config/trackers.yml` and a database it cannot write.

It boots screenshot-ready, with a sign-in already configured, so there is no red
banner. Log in with **`demo` / `demo-password`**.

Set `STATUS_URL` to the address you will actually browse. `localhost` is right
only if you are on the machine running it; from anywhere else the Install link
points at your own computer.

Run it rather than saving the HTML: the drawer fetches its history from
`/api/history`, which cannot work from a `file://` page, and an expanded drawer
is the part of the page a table of rows does not show.

## Contributing

Issues and pull requests welcome. `pytest` runs on every push; please keep it
green and add a test for behavior changes. Most of the suite exists because
something silently did the wrong thing once.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
```

## A note on scope

Idlarr reminds you to log in. That's all it does. It doesn't automate logins,
touch your ratio, seed, download, or interact with a tracker in any way. It only
reads a page your browser already loaded. Respect the rules of the sites you're a
member of; this tool won't help you break them.

## License

MIT, see [LICENSE](LICENSE).
