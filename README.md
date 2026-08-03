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

## Quickstart

Five minutes if nothing surprises you. The full walkthrough — every environment
variable, a different UID, building from source, worked config examples — is in
**[docs/setup.md](docs/setup.md)**.

**1. Directories and templates.** The `chown` matters: the container runs as
UID 1001 and cannot create these itself. If Docker creates them they come out
root-owned and startup fails with `unable to open database file`.

```bash
mkdir -p idlarr/data idlarr/config && cd idlarr
chown -R 1001 data config
BASE=https://raw.githubusercontent.com/b00pb0p/idlarr/main
curl -fsSLO $BASE/trackers.example.yml
curl -fsSLO $BASE/.env.example
cp trackers.example.yml config/trackers.yml
```

**2. Secrets.** Copy `.env.example` to `.env` and set two things: a token, and
where alerts go.

```bash
cp .env.example .env
openssl rand -hex 32          # -> IDLARR_TOKEN
```

`IDLARR_NOTIFY_URLS` is an [Apprise](https://github.com/caronc/apprise) URL —
`ntfy://ntfy.sh/your-topic`, `pover://USER@TOKEN`, `discord://ID/TOKEN`, and
~100 more. Set `STATUS_URL` to the address you'll reach the page on; the
userscript is generated from it.

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

**4. Userscript.** Install [Violentmonkey](https://violentmonkey.github.io/),
open the status page, and click **Install** in the Userscript section of
settings. The script is generated from your tracker list — nothing to fill in —
and it updates itself when you add a tracker.

**5. Bootstrap.** Everything starts at `no data`. Visit each tracker while
logged in, or open a row and click **seen** to assert it by hand.

Then add your real trackers from the page, or import them from Prowlarr or
Jackett — see **[docs/trackers.md](docs/trackers.md)**.

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

## The status page

A sortable table: **tracker · software · state · last auth · left · limit ·
elapsed**, worst first by default. Click any heading to sort; blanks always sort
last, so a tracker with no data can never outrank one that's expiring.

Click a **name** to open that tracker in a new tab. Click anywhere else on the
row to expand a drawer with three panels:

- **controls** — limit, `confirm`, `immune` (with a reason field), notes,
  `seen`, `undo`, `remove`
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

## Managing trackers

**Add** from the header, or **Import** from your own Prowlarr or Jackett in the
settings panel. Remove one by opening its row. Everything lands at **30 days,
unconfirmed**, because a limit nobody has read off the tracker's own rules page
is a guess — and a guess that is too high is the one that loses the account.

Imports never carry a limit: neither Prowlarr nor Jackett knows a tracker's
inactivity policy, and a wrong number arriving with the authority of an import
is worse than no number.

Full detail — importing, editing `trackers.yml` by hand, `host` overrides, and
the `auth_sel` escape hatch for sites the auth heuristic cannot read — is in
**[docs/trackers.md](docs/trackers.md)**.

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

## Endpoints

<details>
<summary>Full route list</summary>

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
| `POST /api/test-notify` | Send a test notification. Bearer token or a session |
| `GET /healthz` | Health check — **always open**, so an uptime monitor needs no credentials |

Everything above `/api/test-notify` sits behind the UI login **when one is
configured**; with none set they are open, which is the 1.0 behaviour. `/ping`
always uses the bearer token, never the login — the userscript posts to it
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
  [Restoring a backup](docs/troubleshooting.md#restoring-a-backup); it has been tested, and there is one
  surprise in it.
- **The clock is `last auth`, not `last visit`.** Passing by while logged out
  doesn't count, and it shouldn't.

## When something isn't working

Run `__idlarr()` in the browser console on the tracker that won't record. It
reports the script's own view of the page and answers nearly every "why isn't
this working" question without guessing.

Diagnosis table, the stale-script case, and how to restore from a backup:
**[docs/troubleshooting.md](docs/troubleshooting.md)**.

## Screenshot

If you contribute one, **screenshot a demo instance, not your own**. The status
page lists every tracker you're a member of, and that is not something to publish.

`tools/demo-seed.py` builds one that looks like a real install — twelve
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
anything merged since the last tag — you would be photographing an older app
than the one you are documenting.

No `python3` on the host — common on NAS distributions? Run the seeder inside
the image, which has one. `--user 0` is needed so it can write the mount and
chown it afterwards:

```bash
docker run --rm --user 0 -v "$PWD/tools:/tools" -v /tmp/idlarr-demo:/demo \
  ghcr.io/b00pb0p/idlarr:edge python /tools/demo-seed.py /demo
```

Seed **before** starting the container. Docker creates a missing bind-mount
source as an empty root-owned directory, so starting first gets you
`No tracker config at /config/trackers.yml` and a database it cannot write.

It boots screenshot-ready — a sign-in already configured so there is no red
banner, and a userscript version in the status line. Log in with
**`demo` / `demo-password`**.

Set `STATUS_URL` to the address you will actually browse. `localhost` is right
only if you are on the machine running it; from anywhere else the Install link
points at your own computer.

Run it rather than saving the HTML: the drawer fetches its history from
`/api/history`, which cannot work from a `file://` page — and an expanded drawer
is the part of the page a table of rows does not show.

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
