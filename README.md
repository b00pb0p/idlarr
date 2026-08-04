# Idlarr

**Never lose an account to inactivity again.**

[![tests](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml/badge.svg)](https://github.com/b00pb0p/idlarr/actions/workflows/tests.yml)

Private trackers prune accounts that go idle. Idlarr watches how long it has been
since you actually logged in to each one, and pushes a notification before the
clock runs out.

**It never contacts a tracker.** A userscript already running in your browser
reports when you were seen logged in; the service does the rest. There is nothing
for a tracker to detect and nothing to ban you for.

![The Idlarr status page](docs/screenshot.png)

## Why not just automate the logins?

That was the first thought, and it was scrapped. Plenty of trackers ban automated
logins, and a ban is permanently worse than the inactivity disable it would have
prevented. Idlarr is deliberately passive: it observes a page you were going to
load anyway and never issues a request of its own. If a feature seems to need
one, it doesn't.

## Requirements

- Docker (that's it)
- A browser with [Violentmonkey](https://violentmonkey.github.io/) or Tampermonkey
- Somewhere to host it — behind Tailscale or a VPN is the belt-and-braces answer
- Somewhere to send notifications — [ntfy](https://ntfy.sh), Pushover, Discord,
  Telegram, or anything else [Apprise](https://github.com/caronc/apprise) supports

FastAPI + SQLite in one container. No Postgres, no build step, one DB file.

## Deployment

### docker run (one command, zero config files)

```bash
mkdir -p idlarr/data idlarr/config && sudo chown -R 1001 idlarr
docker run -d \
  --name idlarr \
  --restart unless-stopped \
  -p 8099:8080 \
  -v ./idlarr/data:/data \
  -v ./idlarr/config:/config \
  -e TZ=America/Chicago \
  ghcr.io/b00pb0p/idlarr:latest
```

That's it. Open `http://localhost:8099` and configure everything from the UI.

### docker compose (recommended)

Create a `docker-compose.yml`:

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
    environment:
      TZ: America/Chicago
```

Then:

```bash
mkdir -p data config && sudo chown -R 1001 data config
docker compose up -d
```

Open `http://localhost:8099`. No `.env` file needed.

### What happens on first boot

1. A secure API token is auto-generated and stored in the database
2. An empty `trackers.yml` is created in `/config`
3. The status page opens with a setup guide

Everything else — notification URLs, the public status URL, UI login — is
configured from the Settings panel (gear icon, top right).

### Image tags

| Tag | What it tracks |
|---|---|
| `latest` | Stable releases |
| `1.3` | A specific minor (recommended) |
| `edge` | `main` branch — unreleased work |

### Environment variables (all optional)

| Variable | Default | Purpose |
|---|---|---|
| `TZ` | `UTC` | Timezone for daily checks and day counting |
| `IDLARR_TOKEN` | auto-generated | API token shared with the userscript |
| `IDLARR_NOTIFY_URLS` | — | Comma-separated Apprise URLs |
| `STATUS_URL` | — | Public URL of the status page |
| `IDLARR_RESET_AUTH` | — | Set to `1` to clear a forgotten password |
| `IDLARR_BACKUP_KEEP` | `14` | Days of nightly DB snapshots to keep |

Env vars **override** values stored in the database. If set, the corresponding
UI field shows as read-only. Omit them entirely to manage everything from the UI.

### Building from source

```bash
git clone https://github.com/b00pb0p/idlarr.git && cd idlarr
docker compose up -d --build
```

To use a different UID (e.g. to match your NAS user):

```bash
docker compose build --build-arg PUID=1000
docker compose up -d
```

## How it works

0. You install the userscript in one click from the status page. It is
   generated from your tracker list — nothing to fill in — and it updates
   itself when you add a tracker.
1. You visit a tracker in your normal browser.
2. The userscript checks whether you're authenticated and POSTs `{tracker, kind}`
   to the service. Two event kinds:
   - `visit` — fires on every page load
   - `auth` — fires only when you're actually logged in
3. Daily, the service compares `last auth` against that tracker's inactivity limit
   and pushes an escalating alert if you're getting close.

Tracking both kinds is what separates *"my session died"* from *"I haven't been
there in two months"* from *"the userscript broke."*

## First-time setup

After deploying, open the status page and:

1. **Set a login** — Click the gear icon > Sign-in. Without one, anyone who can
   reach the port can reset a countdown.
2. **Set the Status URL** — Gear > General. This is the public URL you reach the
   page on (e.g. `https://idlarr.yourdomain.com`). The userscript is generated
   from it.
3. **Set notifications** — Gear > Notifications. Paste one or more Apprise URLs.
   Use **Send test** to verify.
4. **Add trackers** — Click "+ Add tracker" or use Import (Prowlarr/Jackett).
5. **Install the userscript** — Gear > Userscript > Install. One click.
6. **Bootstrap** — Visit each tracker while logged in, or click **seen** per row.

## Signing in

Optional, and off until you set it up. Configure it from the status page —
there is no password in `.env`, and nothing to edit in a file. The credentials
are stored **hashed** (PBKDF2-HMAC-SHA256) in the database.

| Method | What a stranger sees |
|---|---|
| **None** | The dashboard. Also `POST /api/mark`, which resets a countdown. |
| **Forms** | A login page. |
| **Basic** | The browser's own credentials prompt. |

### Do I need it?

Behind Tailscale or a VPN — no. On a shared network — yes. The risk is that
`POST /api/mark/{id}` silently resets a countdown, and your dashboard reads `ok`
while the account ages out.

### If you forget the password

```bash
docker exec idlarr sh -c 'IDLARR_RESET_AUTH=1 exec uvicorn app:app --host 0.0.0.0 --port 8080'
# Or: add IDLARR_RESET_AUTH=1 to environment, restart once, then remove it.
```

## Alert escalation

| Remaining | State | Apprise severity |
|---|---|---|
| immune | immune | never alerts |
| > 35% left | ok | silent |
| ≤ 35% (or past `alert_at_pct`) | due | info |
| ≤ 14 days | warn | warning |
| ≤ 5 days | critical | failure |
| past the limit | expired | failure |
| visited while logged out | session | warning |

Alerts batch into **one message per day**. Repeats daily while anything is
actionable.

## Notifications

Everything goes through [Apprise](https://github.com/caronc/apprise) (~100
services supported). Configure from Settings > Notifications in the UI, or pin
via the `IDLARR_NOTIFY_URLS` env var.

| Service | URL format |
|---|---|
| ntfy.sh | `ntfy://ntfy.sh/your-topic` |
| self-hosted ntfy | `ntfys://ntfy.example.com/your-topic?token=tk_xxx` |
| Pushover | `pover://USER_KEY@APP_TOKEN` |
| Discord | `discord://WEBHOOK_ID/WEBHOOK_TOKEN` |
| Telegram | `tgram://BOT_TOKEN/CHAT_ID` |
| Gotify | `gotify://HOST/TOKEN` |

The [Apprise wiki](https://github.com/caronc/apprise/wiki) has the full list.

## Security

- **CSRF protection** — All state-changing requests require a JSON content type
  or custom header, which cross-origin forms cannot provide.
- **Encrypted credentials at rest** — Prowlarr/Jackett API keys stored in the
  database are encrypted, not plaintext.
- **Short-lived download tokens** — The userscript install/update URL uses a
  token that expires in 24 hours. A leaked server log or browser history entry
  cannot be used to access the API.
- **Rate-limited login** — 5 failures from one IP locks it out for 5 minutes.
- **Hashed passwords** — PBKDF2-HMAC-SHA256, 600k rounds.
- **WAL-mode SQLite** — Concurrent reads don't block writes.
- **Non-root container** — Runs as UID 1001.

## Managing trackers

**Add** from the header, or **Import** from your own Prowlarr or Jackett in the
settings panel. Remove one by opening its row.

Everything lands at **30 days, unconfirmed** — a limit nobody has confirmed from
the tracker's own rules page is a guess, and a guess that is too high loses the
account.

Full detail in **[docs/trackers.md](docs/trackers.md)**.

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
| `POST /api/limit/{id}` | Set inactivity_days / verified / immune |
| `GET /api/history/{id}` | Recent auth events (drawer) |
| `GET /idlarr.user.js` | Generated userscript (download token or session) |
| `GET /api/download-token` | Short-lived token for userscript URL |
| `GET /api/settings` | Current config values and sources |
| `POST /api/settings` | Update status_url, notify_urls, regenerate token |
| `POST /api/tracker` | Add a tracker |
| `DELETE /api/tracker/{id}` | Remove one (auth history kept) |
| `POST /api/import` | Preview/apply Prowlarr/Jackett import |
| `GET`/`POST /api/auth` | Read or change the UI login |
| `POST /login` / `POST /logout` | Session in/out |
| `POST /api/test-notify` | Send a test notification |
| `GET /healthz` | Health check (always open) |

</details>

## Things that will bite you

- **With no sign-in set, the write endpoints are open.** Set a login, keep it
  behind Tailscale or a VPN, or both.
- **The `seen` button is a bootstrap tool, not a workflow.** It's two-step for
  that reason.
- **Auth detection is a heuristic.** If a site redesigns, it silently stops
  recording. Run `__idlarr()` in the browser console to diagnose.
- **`trackers.yml` hot-reloads.** No restart needed.
- **The database is backed up nightly** to `/data/backups/`. It is the only
  record of when each account was last seen.

## When something isn't working

Run `__idlarr()` in the browser console on the tracker that won't record.
Full diagnosis: **[docs/troubleshooting.md](docs/troubleshooting.md)**.

## Screenshot

If you contribute one, **screenshot a demo instance, not your own**:

```bash
python3 tools/demo-seed.py /tmp/idlarr-demo
docker run --rm -p 8090:8080 \
  -v /tmp/idlarr-demo/data:/data -v /tmp/idlarr-demo/config:/config \
  -e TZ=America/Chicago -e STATUS_URL=http://localhost:8090 \
  ghcr.io/b00pb0p/idlarr:edge
```

Log in with **`demo` / `demo-password`**.

## Contributing

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
