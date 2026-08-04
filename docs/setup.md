# Setup

The full walkthrough. [The README](../README.md#quickstart) has a short version
that covers the common case; come here for the parts it skips — every
environment variable, running as a different UID, building from source, and
worked examples of the config and the userscript.

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
out. Set one from the settings panel (see [Signing in](../README.md#signing-in)), keep it behind
Tailscale or a VPN, or both. Do not expose it unauthenticated.

`/ping` itself is token-protected, and the service **refuses to start** without
`IDLARR_TOKEN` — an empty token would disable authentication entirely, which is
indistinguishable from working until something writes to your database.

**5. Userscript** — install a userscript manager ([Violentmonkey](https://violentmonkey.github.io/), Tampermonkey, or Greasemonkey),
then open the status page, click the settings gear, and click **Install** in the
Userscript section.

That link serves a script generated from your live `trackers.yml`: every
`@match`, the `@connect` host, the endpoint and the token are already filled in,
and the `SITES` ids come from the same config `/ping` validates against, so they
cannot disagree. There is nothing to edit.

It also carries `@updateURL`, so **adding a tracker later reaches the browser on
its own** — your manager picks it up on its next update check, no reinstall.

The link needs `STATUS_URL` set (step 3); without it the generated script would
have nowhere to report and the route says so rather than serving one. If you'd
rather install by hand — no status page access, or you want to read it first —
the URL is:

```
https://idlarr.example.ts.net/idlarr.user.js?token=YOUR_IDLARR_TOKEN
```

The committed `idlarr.user.js` in the repo is the **template** that route fills
in. You can still edit it by hand and paste it in; see
[Managing trackers](trackers.md).

**6. Bootstrap** — everything starts at `no data`. Visit each tracker while
logged in, or use `seen` on the status page.

