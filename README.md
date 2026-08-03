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
- Somewhere private to host it — Tailscale, a VPN, or reverse-proxy auth
- Somewhere to send notifications — [ntfy](https://ntfy.sh), Pushover, Discord, Telegram, or anything else [Apprise](https://github.com/caronc/apprise) supports

FastAPI + SQLite in one container. No Postgres, no build step, one DB file.

## How it works

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
curl -fsSLO $BASE/idlarr.user.js
```

The `chown` matters: the container runs as a non-root user and cannot create
those directories itself. If Docker creates them, they come out root-owned and
startup fails with `unable to open database file`. The image runs as UID 1001;
for a different one you must build from source (see `PUID` below).

*(Cloned the repo instead? You already have all three — skip the `curl`s.)*

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
| `IDLARR_TOKEN` | **yes** | — | Shared secret for `/ping`. The service **refuses to start** without it. Must byte-match `TOKEN` in the userscript. |
| `IDLARR_NOTIFY_URLS` | **yes** | — | Comma-separated [Apprise](https://github.com/caronc/apprise) URLs — ntfy, Pushover, Discord, Telegram, Signal and ~100 more. Compose aborts if unset. |
| `STATUS_URL` | no | *(empty)* | Public URL of the status page. Appended to every alert so you can tap through. |
| `TZ` | no | `UTC` | Drives the daily check and **all day counting** — set it to your own zone or countdowns can be a day out. |
| `PUID` | build only | `1001` | **Build argument, not a runtime variable.** The published image always runs as 1001; `chown` your `data/` and `config/` to match. To use a different UID you must build from source: `docker compose build --build-arg PUID=1000`. |
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

**Keep the status page private.** Three write endpoints are unauthenticated by
design, and one of them rewrites your config — see *Things that will bite you*.
Put it behind Tailscale, a VPN, or reverse-proxy auth. Do not expose it.

`/ping` itself is token-protected, and the service **refuses to start** without
`IDLARR_TOKEN` — an empty token would disable authentication entirely, which is
indistinguishable from working until something writes to your database.

**5. Userscript** — open `idlarr.user.js` (downloaded in step 1), paste it into
a new Violentmonkey script, and edit four things.

The metadata block — one `@match` per tracker, and `@connect` set to your
endpoint as a **bare hostname**, no scheme or path:

```javascript
// @match        *://*.alpha.example/*
// @match        *://*.beta.example/*
//
// @connect      idlarr.example.ts.net
```

`@connect` is required: trackers set a strict CSP, which is why this uses
`GM_xmlhttpRequest` rather than `fetch`.

The settings — full URL **including `/ping`**, and the token byte-matching
`IDLARR_TOKEN` from your `.env`:

```javascript
  const ENDPOINT = 'https://idlarr.example.ts.net/ping';
  const TOKEN    = 'the-same-64-char-string-as-IDLARR_TOKEN';
```

And one `SITES` entry per tracker, with **ids matching `trackers.yml`**:

```javascript
  const SITES = [
    { host: 'alpha.example', id: 'alpha' },
    { host: 'beta.example', id: 'beta' },
  ];
```

`host` is the bare domain, matched as a substring of `location.hostname`, so it
covers `www.` and any other subdomain. If an id here doesn't match one in
`trackers.yml`, `/ping` returns `404 unknown tracker` and the browser console
says so.

**6. Bootstrap** — everything starts at `no data`. Visit each tracker while
logged in, or use `seen` on the status page.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Status page |
| `GET /api/status` | Same data as JSON |
| `POST /ping` | Userscript ingest (bearer auth) |
| `POST /api/mark/{id}` | Manual "I just logged in" — **unauthenticated**, see below |
| `POST /api/unmark/{id}` | Remove the most recent auth event — **unauthenticated** |
| `POST /api/limit/{id}` | Set `inactivity_days` / `verified` / `immune`, writes trackers.yml — **unauthenticated** |
| `GET /api/history/{id}` | Recent auth events, newest first (drawer) |
| `POST /api/test-notify` | Fire the check immediately (bearer auth) |
| `GET /healthz` | Health check |

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

- **controls** — limit, `confirm`, `immune` (with a reason field), `seen`, `undo`
- **alert schedule** — the exact date each rung fires, or why it won't
- **auth history** — recent auth events, and whether each was observed or asserted

Limits written here go straight into `trackers.yml`, comments intact,
hot-reloaded, no restart. `seen` is two-step on purpose.

## Adding or removing a tracker

Two files, and the **`id` must be identical in both**. If they drift, `/ping`
returns `404 unknown tracker` and the userscript logs it to the console.

Say you're adding AnimeBytes (Gazelle) and Blutopia (UNIT3D).

**`config/trackers.yml`** — append two entries:

```yaml
  - id: animebytes
    name: AnimeBytes
    url: https://animebytes.tv/
    inactivity_days: 30
    verified: false
    notes: "Gazelle"

  - id: blutopia
    name: Blutopia
    url: https://blutopia.cc/
    inactivity_days: 30
    verified: false
    notes: "UNIT3D"
```

`url` should point at a page that requires a login — the status page links to it,
and it's where you'll land to reset the clock. `notes` starting with the tracker
software (`Gazelle`, `UNIT3D`, `TBDev`, `Custom`) populates the software column
for free. Leave `inactivity_days: 30` and `verified: false` until you've read the
site's own rules page.

**`idlarr.user.js`** — one `@match` line in the metadata block:

```javascript
// @match        *://*.animebytes.tv/*
// @match        *://*.blutopia.cc/*
```

and one `SITES` entry each, with the **same ids**:

```javascript
  const SITES = [
    { host: 'animebytes.tv', id: 'animebytes' },
    { host: 'blutopia.cc', id: 'blutopia' },
  ];
```

`host` is the bare domain, no scheme and no path — it's matched as a substring of
`location.hostname`, so it covers `www.` and any other subdomain. The `@match`
pattern `*://*.domain/*` covers the apex domain too.

Reinstall the script, then visit each site logged in. You want:

```
[idlarr] animebytes active on animebytes.tv
[idlarr] animebytes auth recorded
```

If the second line doesn't appear, run `__idlarr()` — see
[When a tracker won't record](#when-a-tracker-wont-record).

### A site the heuristic can't read

Single-page apps often keep no logout control in the DOM until you open a user
menu, which passive detection can't do. Point `authSel` at anything that only
exists when you're authenticated — a per-account download link, an upload button,
your username:

```javascript
    { host: 'example.cc', id: 'example', authSel: 'a[href*="/torrent?key="]' },
```

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
| `logoutFound: false`, `candidates` non-empty | the heuristic missed a convention — widen it, or set `authSel` |
| `candidates: []` | no logout control in the DOM at all (common in single-page apps) — point `authSel` at something else that only exists when logged in |
| `isAuthed: true` but nothing recorded | check the lines above it; a debounce or a `401` will say so |
| `visiblePasswordField: true` | you're on a login page, or a change-password form |

## Screenshot

If you contribute one, **screenshot a demo instance, not your own**. The status
page lists every tracker you're a member of, and that is not something to publish.
Point a throwaway container at `trackers.example.yml` and shoot that.

## Things that will bite you

- **The write endpoints have no auth.** `/api/mark`, `/api/unmark` and `/api/limit`
  are all unauthenticated, and `/api/limit` writes to `trackers.yml`. Keep the
  status page behind Tailscale or Caddy auth. Don't expose it raw.
- **The `seen` button is a bootstrap tool, not a workflow.** The week you tap it
  out of habit without logging in is the week this stops working. It's two-step
  in the UI for that reason, and every row shows whether its last auth was
  *seen by userscript* or *marked by hand*. If a mark was wrong — site was down,
  page came from cache — `undo` removes it.
- **Auth detection is a heuristic**: a `logout` link present, no password field.
  Works on Gazelle/UNIT3D and most PHP trackers. If a site redesigns, it silently
  stops recording `auth` — you'll get alerts you don't deserve. That's the safe
  failure direction, but check the console (`[idlarr]` logs) before assuming
  the tracker is at fault. Use `authSel` to override per-site.
- **`trackers.yml` hot-reloads.** Edit it live; no restart.
- **The database is backed up nightly** to `/data/backups/idlarr-YYYY-MM-DD.db`,
  14 days by default (`IDLARR_BACKUP_KEEP`). It is the only record of when each
  account was last seen — losing it risks no account, but resets every countdown
  to `no data` until you re-visit all of them. To restore, stop the container,
  copy a snapshot over `/data/idlarr.db`, start it again.
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
