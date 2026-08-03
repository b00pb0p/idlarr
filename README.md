# Idlarr

**Never lose an account to inactivity again.**

[![tests](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml/badge.svg)](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml)

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
- A browser with [Violentmonkey](https://violentmonkey.github.io/) or Tampermonkey
- Somewhere to host it. It has its own optional sign-in; behind Tailscale or a VPN is still the belt-and-braces answer
- Somewhere to send notifications — [ntfy](https://ntfy.sh), Pushover, Discord, Telegram, or anything else [Apprise](https://github.com/caronc/apprise) supports

FastAPI + SQLite in one container. No Postgres, no build step, one DB file.

## How it works

0. You install the userscript in one click from the status page. It is
   generated from your tracker list, so there is nothing to fill in, and it
   updates itself when you add a tracker.
1. You visit a tracker in your normal browser.
2. The userscript checks whether you're authenticated and POSTs `{tracker, kind}`
   to the service. Two event kinds:
   - `visit` — fires on every page load
   - `auth` — fires only when you're actually logged in
3. Daily, the service compares `last auth` against that tracker's inactivity limit
   and pushes an escalating alert if you're getting close.

Tracking both kinds is what separates *"my session died"* from *"I haven't been
there in two months"* from *"the userscript broke."*

## Setup

**1. Create a directory and fetch the templates** — there's no need to clone
the repo; the image is prebuilt:

```bash
mkdir -p idlarr/data idlarr/config && cd idlarr
chown -R 1001 data config

BASE=https://raw.githubusercontent.com/b00pb0p/idlarr/main
curl -fsSLO $BASE/trackers.example.yml
curl -fsSLO $BASE/.env.example
```

The `chown` matters: the container runs as a non-root user and cannot create
those directories itself. If Docker creates them, they come out root-owned and
startup fails with `unable to open database file`. The image runs as UID 1001;
for a different one you must build from source (see `PUID` below).

*(Cloned the repo instead? You already have both — skip the `curl`s.)*

There is no userscript to download: the service generates it from your config
and serves it from the status page.

**2. Config** — copy the example and edit it:

```bash
cp trackers.example.yml config/trackers.yml
```

One entry per tracker:

```yaml
defaults:
  inactivity_days: 30
  alert_at_pct: 0.65
  timezone: America/Chicago
  check_hour: 9

trackers:
  - id: alpha
    name: Alpha Tracker
    url: https://alpha.example/
    inactivity_days: 30
    verified: false
    notes: "Gazelle"

  - id: beta
    name: Beta Tracker
    url: https://beta.example/browse.php
    inactivity_days: 90
    verified: true
    notes: "UNIT3D. Donated, may be exempt - check."
```

`url` should point at a page that requires a login — the status page links to
it, and it's where you'll land to reset the clock. `notes` beginning with the
tracker software (`Gazelle`, `UNIT3D`, `TBDev`, `Custom`) fills in the software
column for free. `check_hour` is when the daily check runs, in `timezone`.

> **Those numbers are fail-safe placeholders, not research.** Nobody outside a
> tracker reliably knows its current inactivity policy, and a limit guessed too
> long costs you the account — the exact failure this tool exists to prevent.
> 30 days nags you early enough for almost any real policy. Read each tracker's
> own rules page, correct the number, then flip `verified: true`.

The status page marks unverified rows and counts them in the header, so what
you still haven't checked stays visible.

While you're in each rules page, note three things that can make an entry
unnecessary: whether **seeding announces** reset the clock, whether your **user
class** is exempt, and whether the site has a **vacation mode**.

**3. Secrets and settings** — copy `.env.example` to `.env` and fill it in:

```bash
cp .env.example .env
openssl rand -hex 32          # -> IDLARR_TOKEN
```

| Variable | Required | Default | What it does |
|---|---|---|---|
| `IDLARR_TOKEN` | **yes** | — | Shared secret for `/ping`. The service **refuses to start** without it. Baked into the generated userscript automatically. |
| `IDLARR_NOTIFY_URLS` | **yes** | — | Comma-separated [Apprise](https://github.com/caronc/apprise) URLs — ntfy, Pushover, Discord, Telegram, Signal and ~100 more. Compose aborts if unset. |
| `STATUS_URL` | no | *(empty)* | Public URL of the status page. Appended to every alert so you can tap through. |
| `TZ` | no | `UTC` | Drives the daily check and **all day counting** — set it to your own zone or countdowns can be a day out. |
| `PUID` | build only | `1001` | **Build argument, not a runtime variable.** The published image always runs as 1001; `chown` your `data/` and `config/` to match. To use a different UID you must build from source: `docker compose build --build-arg PUID=1000`. |
| `IDLARR_RESET_AUTH` | no | *(unset)* | Set to `1` to clear the UI login on the next boot — the only way back in from a forgotten password. **Remove it afterwards**, or every boot clears it again. |
| `IDLARR_BACKUP_KEEP` | no | `14` | Dated database snapshots to retain. `0` disables backups. |
| `IDLARR_BACKUP_DIR` | no | `/data/backups` | Where those snapshots go. |
| `IDLARR_DEDUPE_HOURS` | no | `12` | One event per tracker per kind per this window. Must be ≥ the userscript's `COOLDOWN`. |

`IDLARR_DB` and `IDLARR_CONFIG` are set in the image and only need changing if
you run it outside Docker.

**4. Deploy**

A prebuilt multi-arch image is published to GHCR, so there's nothing to build:

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

Tags: `latest` follows releases, `1.2` and `1.2.3` pin to a version, `edge`
tracks `main`. Pin to a major.minor if you'd rather not be
upgraded into breaking changes.

Building from source instead — for anyone modifying it:

```bash
docker compose up -d --build
```

**Set a sign-in, or keep the page private.** With no login configured, the
write endpoints are open and one of them rewrites your config — a stranger can
reset a countdown, after which the dashboard reads `ok` while the account ages
out. Set one from the footer (see [Signing in](#signing-in)), keep it behind
Tailscale or a VPN, or both. Do not expose it unauthenticated.

`/ping` itself is token-protected, and the service **refuses to start** without
`IDLARR_TOKEN` — an empty token would disable authentication entirely, which is
indistinguishable from working until something writes to your database.

**5. Userscript** — install [Violentmonkey](https://violentmonkey.github.io/),
then open the status page and click **Install** in the footer.

That link serves a script generated from your live `trackers.yml`: every
`@match`, the `@connect` host, the endpoint and the token are already filled in,
and the `SITES` ids come from the same config `/ping` validates against, so they
cannot disagree. There is nothing to edit.

It also carries `@updateURL`, so **adding a tracker later reaches the browser on
its own** — Violentmonkey picks it up on the next update check, no reinstall.

The link needs `STATUS_URL` set (step 3); without it the generated script would
have nowhere to report and the route says so rather than serving one. If you'd
rather install by hand — no status page access, or you want to read it first —
the URL is:

```
https://idlarr.example.ts.net/idlarr.user.js?token=YOUR_IDLARR_TOKEN
```

The committed `idlarr.user.js` in the repo is the **template** that route fills
in. You can still edit it by hand and paste it in; see
[Adding or removing a tracker](#adding-or-removing-a-tracker).

**6. Bootstrap** — everything starts at `no data`. Visit each tracker while
logged in, or use `seen` on the status page.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Status page |
| `GET /api/status` | Same data as JSON |
| `POST /ping` | Userscript ingest (bearer auth) |
| `POST /api/mark/{id}` | Manual "I just logged in" |
| `POST /api/unmark/{id}` | Remove the most recent auth event |
| `POST /api/limit/{id}` | Set `inactivity_days` / `verified` / `immune`, writes trackers.yml |
| `GET /api/history/{id}` | Recent auth events, newest first (drawer) |
| `GET /idlarr.user.js` | The userscript, generated from live config. `?token=` or a session |
| `POST /api/tracker` | Add a tracker, appends to trackers.yml |
| `DELETE /api/tracker/{id}` | Remove one. Auth history is kept |
| `POST /api/import` | Preview (default) or apply a Prowlarr/Jackett import |
| `GET`/`POST /api/auth` | Read or change the UI login |
| `POST /login` · `POST /logout` | Session in, session out |
| `POST /api/test-notify` | Fire the check immediately (bearer auth) |
| `GET /healthz` | Health check — **always open**, so an uptime monitor needs no credentials |

Everything above `/api/test-notify` sits behind the UI login **when one is
configured**; with none set they are open, which is the 1.0 behaviour. `/ping`
always uses the bearer token, never the login — the userscript posts to it
cross-origin from tracker pages, where cookies do not apply.

## Signing in

Optional, and off until you set it up. Configure it from the status page —
there is no password in `.env`, and nothing to edit in a file. The credentials
are stored **hashed** (PBKDF2-HMAC-SHA256) in the database, so they ride along
in the nightly backup and change without recreating the container.

| Method | What a stranger sees |
|---|---|
| **None** | The dashboard. Also `POST /api/mark`, which resets a countdown. |
| **Forms** | A login page. |
| **Basic** | The browser's own credentials prompt. |

Under **Forms**, HTTP Basic credentials are still accepted on the API, so curl
and scripts work without a login round-trip. The setting decides how you are
*challenged*, not which credentials are valid.

### Do I need it?

Behind Tailscale, a VPN, or an authenticating reverse proxy — no, and the
default costs you nothing. On a shared network — university halls, shared
housing, an office — yes. The risk is not that someone reads your tracker list,
though they can. It is that `POST /api/mark/{id}` needs no credentials with auth
off, and one call silently resets a countdown. Your dashboard then reads `ok`
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

Start once — the login is cleared and every existing session is invalidated —
then **remove the variable and restart again**, or the next boot clears it
right back.

### What it does not cover

`/healthz` stays open so an uptime monitor needs no credentials. `/ping` keeps
using `IDLARR_TOKEN`, which is unchanged: one credential for the userscript,
one for you, the same split the *arr apps use. And the login is only as strong
as the transport — over plain HTTP on an untrusted network, use a VPN or put
TLS in front of it.

## Notifications

Everything goes through [Apprise](https://github.com/caronc/apprise), which
speaks around a hundred services — **including ntfy**. One setting, one code
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
| ntfy.sh | `ntfy://ntfy.sh/your-topic` |
| self-hosted ntfy | `ntfys://ntfy.example.com/your-topic?token=tk_xxx` |
| Pushover | `pover://USER_KEY@APP_TOKEN` |
| Pushbullet | `pbul://ACCESS_TOKEN` |
| Discord | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Signal | `signal://HOST:PORT/FROM/TO` (needs signal-cli-rest-api) |
| Slack | `slack://TOKEN_A/TOKEN_B/TOKEN_C/#channel` |
| Matrix | `matrix://USER:PASS@HOST/#room` |
| Gotify | `gotify://HOST/TOKEN` |
| Email | `mailto://user:pass@gmail.com` |

The [Apprise wiki](https://github.com/caronc/apprise/wiki) has the rest.

Alert priority maps to Apprise's own severity, so an expiring account looks
different on your phone from a routine nudge: `default` becomes *info*, `high`
becomes *warning*, `urgent` becomes *failure*.

`STATUS_URL`, if set, is appended to the message body rather than used as a
provider-specific click action — every service renders a URL, only some support
a tap target.

**With `IDLARR_NOTIFY_URLS` empty, nothing can reach you.** Compose refuses to
start without it, and the service warns if it ends up empty anyway.

**These URLs contain credentials.** Keep them in `.env`, which is gitignored.

## The status page

A sortable table: **tracker · software · state · last auth · left · limit ·
elapsed**, worst first by default. Click any heading to sort; blanks always sort
last, so a tracker with no data can never outrank one that's expiring.

Click a **name** to open that tracker in a new tab. Click anywhere else on the
row to expand a drawer with three panels:

- **controls** — limit, `confirm`, `immune` (with a reason field), `seen`,
  `undo`, `remove`
- **alert schedule** — the exact date each rung fires, or why it won't
- **auth history** — recent auth events, and whether each was observed or asserted

**Add tracker** and the settings gear sit top right. Everything configurable
lives behind the gear, in six sections:

| | |
|---|---|
| **General** | timezone, check hour, last check, backup retention |
| **Sign-in** | method, credentials, sign out |
| **Userscript** | coverage, endpoint, **Install** and **Copy URL** |
| **Import** | Prowlarr or Jackett |
| **Notifications** | destination count, and a **Send test** button |
| **About** | version, database size, `/healthz` |

The footer is a read-only status line — tracker count, sign-in state, userscript
version, last check. Nothing there is clickable, which is deliberate: an earlier
version mixed status and actions in fixed-width cells and the content overflowed
the moment a label got long.

On a phone the table stops being a table — each row becomes a labelled grid —
and the settings nav becomes a scrolling tab strip.

Limits written here go straight into `trackers.yml`, comments intact,
hot-reloaded, no restart. `seen` is two-step on purpose.

## Adding or removing a tracker

**From the status page.** Footer, *Trackers* cell, **Add**. Name and URL are
enough — the id is derived from the name and the host from the URL, both
editable. The entry is appended to `trackers.yml` with its comments intact, and
the generated userscript changes with it, so the browser picks up the new
`@match` on Violentmonkey's next update check.

To remove one, open its row and click **remove**, then confirm. Its **auth
history stays in the database** on purpose: re-adding the same id restores the
countdown rather than silently restarting it, which is the failure this whole
service exists to prevent.

New trackers always start at **30 days, unconfirmed**. That is not laziness — a
limit nobody has read off the tracker's own rules page is a guess, and a guess
that is too high is the one that loses the account. Raise it and tick *confirm*
once you have checked.

### Importing from Prowlarr or Jackett

Footer, **Import**. Point it at your own Prowlarr or Jackett with an API key and
it lists the private indexers it found, marking which are new. Nothing is
written until you click Import — an API key aimed at the wrong instance should
cost you a list on screen, not a rewritten config.

| | URL | API key |
|---|---|---|
| Prowlarr | `http://prowlarr.local:9696` | Settings → General → API Key |
| Jackett | `http://jackett.local:9117` | top of the Jackett dashboard |

Public indexers and usenet are skipped — there is no account to lose. Trackers
already in your config are skipped too, matched on **host** as well as id, so a
tracker Prowlarr names differently is not added twice.

**Limits are never imported.** Neither tool knows a tracker's inactivity policy,
so everything arrives at 30 days and unconfirmed like any other new entry. A
limit that showed up looking authoritative and was wrong in the high direction
would be worse than no limit at all.

This talks to your indexer manager, never to a tracker. The no-tracker-traffic
rule is about requests that could get an account banned; Prowlarr on your own
box is not one of those.

### By hand

`trackers.yml` is still the source of truth and is hot-reloaded, so editing it
directly works and needs no restart:

```yaml
  - id: animebytes
    name: AnimeBytes
    url: https://animebytes.tv/
    inactivity_days: 30
    verified: false
    notes: "Gazelle"
```

`url` should point at a page that requires a login — the status page links to
it, and it's where you'll land to reset the clock. `notes` starting with the
tracker software (`Gazelle`, `UNIT3D`, `TBDev`, `Custom`) fills the software
column for free.

`host` is derived from `url` minus any leading `www.`, and drives the generated
userscript's `@match` line. Set it explicitly only when the domain you log in on
differs from the one you want the row to link to:

```yaml
    host: animebytes.tv
```

There is no second file to keep in sync any more. The `@match` lines and the
`SITES` array are generated from these entries, so an id can no longer drift
between the two and produce a silent `404 unknown tracker`.

### A site the heuristic can't read

Single-page apps often keep no logout control in the DOM until you open a user
menu, which passive detection can't do. Set `auth_sel` on that tracker to
anything that only exists when you're authenticated — a per-account download
link, an upload button, your username:

```yaml
  - id: example
    name: Example
    url: https://example.cc/browse
    auth_sel: 'a[href*="/torrent?key="]'
```

It goes straight into the generated userscript's `SITES` entry as `authSel`.

A passkey in a download URL is stronger evidence than a logout link, since it
cannot be rendered for an anonymous visitor. Note that such links usually only
appear on torrent-listing pages — point that tracker's `url` at its browse page.

**Removing** a tracker is the reverse: delete both entries and reinstall. Its
recorded events stay in the database, so re-adding the same `id` later resumes
the old countdown rather than starting fresh.

## Immune trackers

Some accounts can't be pruned at all: you donated, your user class is exempt, or
the site has a standing exemption. Hit `immune` on that row and it moves to its
own section — no countdown, no alerts ever, and it leaves the unconfirmed-limits
denominator, so `1/21` means 21 trackers still actually need a number.

A reason field appears when you toggle it on. Fill it in. In six months you will
not remember whether it was the donation or the user class, and if the site
changes its policy that's the only thing that tells you what to re-check.

Immunity outranks every other state, including `expired` — an immune tracker that
hasn't been touched in 200 days is still fine, and saying otherwise would train
you to ignore the alerts that matter.

## Alert escalation

Relative to each tracker's inactivity limit:

| Remaining | State | Priority | Reaches you as |
|---|---|---|---|
| immune | immune | — | never alerts |
| > 35% | ok | — | silent |
| ≤ 35% (or past `alert_at_pct`) | due | `default` | *info* |
| ≤ 14 days | warn | `high` | *warning* |
| ≤ 5 days | critical | `urgent` | *failure* |
| past the limit | expired | `urgent` | *failure* |
| visited while logged out | session | `high` | *warning* |

The right-hand column is the Apprise severity, which each service renders in its
own way — a colour in Discord, a priority level in Pushover, a tag in ntfy.

Alerts batch into **one message per day**, not one per tracker. A dozen separate
pushes is how someone starts ignoring them. It repeats daily while anything is
actionable — one 3am push is how accounts get lost.

## When a tracker won't record

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
probably older than your config. It updates on Violentmonkey's own schedule, not
the moment you add a tracker. Force it from Violentmonkey's dashboard — the
script's ⋮ menu, *Check for updates* — or reinstall from the status page footer.
Compare the `@version` in the installed script against the one the service is
serving; if they differ, that's the whole answer.

## Screenshot

If you contribute one, **screenshot a demo instance, not your own**. The status
page lists every tracker you're a member of, and that is not something to publish.
Point a throwaway container at `trackers.example.yml` and shoot that.

## Restoring a backup

Snapshots land in `/data/backups/` as `idlarr-YYYY-MM-DD.db`, written nightly
during the daily check via SQLite's online backup API. Restoring one is a file
copy:

```bash
docker compose stop
cp data/backups/idlarr-2026-08-03.db data/idlarr.db
chown 1001 data/idlarr.db
docker compose start
```

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
  *seen by userscript* or *marked by hand*. If a mark was wrong — site was down,
  page came from cache — `undo` removes it.
- **Auth detection is a heuristic**: a `logout` link present, no password field.
  Works on Gazelle/UNIT3D and most PHP trackers. If a site redesigns, it silently
  stops recording `auth` — you'll get alerts you don't deserve. That's the safe
  failure direction, but check the console (`[idlarr]` logs) before assuming
  the tracker is at fault. Use `auth_sel` to override per-site.
- **`trackers.yml` hot-reloads.** Edit it live; no restart.
- **The database is backed up nightly** to `/data/backups/idlarr-YYYY-MM-DD.db`,
  14 days by default (`IDLARR_BACKUP_KEEP`). It is the only record of when each
  account was last seen — losing it risks no account, but resets every countdown
  to `no data` until you re-visit all of them. See
  [Restoring a backup](#restoring-a-backup); it has been tested, and there is one
  surprise in it.
- **The clock is `last auth`, not `last visit`.** Passing by while logged out
  doesn't count, and it shouldn't.

## Contributing

Issues and pull requests welcome. `pytest` runs on every push; please keep it
green and add a test for behaviour changes — most of the suite exists because
something silently did the wrong thing once.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
```

## A note on scope

Idlarr reminds you to log in. That's all it does. It doesn't automate logins,
touch your ratio, seed, download, or interact with a tracker in any way — it only
reads a page your browser already loaded. Respect the rules of the sites you're a
member of; this tool won't help you break them.

## License

MIT — see [LICENSE](LICENSE).
