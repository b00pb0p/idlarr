# The read-only API

Idlarr can hand out a **read-only key** so other services can see your tracker
status without being able to change it. It is meant for dashboard widgets,
uptime checks and small scripts.

The key is in **Settings, API**. One is generated the first time you look, so
there is nothing to create. It is masked until you click the eye beside it, so
opening Settings during a screen-share does not hand it over. **Copy** works
whether it is showing or not.

## What it can and cannot do

It reads. That is the whole of it.

| | |
|---|---|
| Read your status, counts and auth history | yes |
| Mark a tracker as seen | **no** |
| Change a limit, add or remove a tracker | **no** |
| Change settings, sign-in, or notifications | **no** |
| Generate a new key | **no** |

The restriction is the point. Marking a tracker seen resets its countdown, and
a countdown reset by mistake is the exact failure this service exists to
prevent: the page reads `ok` while the account quietly ages out. A key that
sits in a dashboard config file, on a machine you may not control, must not be
able to do that.

Regenerating is also refused. A leaked key must not be able to rotate itself
and lock you out of noticing.

### With sign-in switched off

If you have not configured a login, **every read endpoint is open to anything
that can reach the port**, key or no key. That is the 1.0 posture and it has not
changed: the status page itself is open too. The key still matters, because it
is what lets a widget keep working once you *do* set a login, and because the
write endpoints are refused with a key even then.

On a shared network, set a login. `POST /api/mark/{id}` is open without one, and
one call to it resets a countdown.

> **This is not `IDLARR_TOKEN`.** That one is for the userscript, it writes
> events, and anything holding it can forge a login. Do not put it in a
> dashboard. If you send it here you will get a 401 telling you so.

## Sending the key

Either of these, whichever your tool supports:

```bash
curl -H "X-Api-Key: YOUR_KEY" https://idlarr.example/api/summary
curl "https://idlarr.example/api/summary?apikey=YOUR_KEY"
```

`X-Api-Key` is the convention the arr apps use. `?apikey=` is Jackett's, and
what most dashboard widgets send.

Prefer the header when you have the choice. A key in a query string ends up in
web server access logs and browser history; a header does not.

A browser session works too, which is why the status page itself uses these
endpoints without a key.

## Endpoints

### `GET /api/summary`

**Use this one.** It is small, it is deliberate, and its shape will not change
underneath you.

```json
{
  "trackers": 23,
  "counts": {
    "expired": 0, "session": 0, "critical": 1, "warn": 2, "due": 0,
    "unknown": 1, "ok": 15, "snoozed": 0, "immune": 4
  },
  "needs_attention": 3,
  "worst": { "id": "anthelion", "name": "Anthelion", "state": "critical", "days_left": 4 },
  "soonest_deadline": { "id": "anthelion", "name": "Anthelion", "days_left": 4 },
  "last_check": "2026-08-06",
  "version": "1.7.1"
}
```

| Field | Meaning |
|---|---|
| `trackers` | how many you are watching, including immune ones |
| `counts` | every state, always all nine keys, so a chart never has holes |
| `needs_attention` | expired, critical, warn, due and logged out, added up |
| `worst` | the tracker at the top of the page, or `null` if you have none |
| `soonest_deadline` | the nearest real deadline, or `null` |
| `last_check` | date of the last daily check, or `null` if none has run |
| `version` | the running Idlarr version |

`worst` and `soonest_deadline` are usually the same tracker but not always.
`worst` is the most serious *state*; `soonest_deadline` is the smallest number
of days left. A tracker showing `logged out` outranks one with fewer days
remaining, because a dead session cookie is not fixed by waiting.

Immune and snoozed trackers are **excluded** from `soonest_deadline`. Neither
can expire, so reporting one as the next deadline would show a countdown that
never fires.

Both are `null` on a fresh install with no trackers. Handle that.

### `GET /api/status`

Every field of every tracker. Useful for building something specific, but its
shape follows the status page and has changed several times. If you parse it,
expect to revisit that when Idlarr changes.

### `GET /api/history/{id}`

Recent auth events for one tracker, with the date and whether each was observed
by the userscript or entered by hand.

### `GET /healthz`

No key needed, by design, so an uptime monitor works without credentials.
Returns `{"ok": true, "version": ..., "trackers": N}`.

## Recipes

All four assume `YOUR_KEY` from *Settings, API* and your own hostname.

### A dashboard tile

The commonest use. Homepage's `customapi` widget, which Glance, Dashy and most
others mirror closely enough to adapt:

```yaml
- Idlarr:
    icon: mdi-account-clock
    href: https://idlarr.example
    widget:
      type: customapi
      url: https://idlarr.example/api/summary
      refreshInterval: 3600000        # hourly is plenty, this changes daily
      headers:
        X-Api-Key: YOUR_KEY
      mappings:
        - field: needs_attention
          label: Attention
        - field:
            counts: expired
          label: Expired
        - field:
            soonest_deadline: days_left
          label: Next
          format: number
```

`counts` always carries all nine states, so a tile mapping states to colors
never hits a missing key and shows a blank. `soonest_deadline` **can** be
`null`, on a fresh install or when every tracker is immune, so pick a widget
that tolerates that or map `needs_attention` alone.

### Uptime Kuma, red when something needs you

An **HTTP(s) - Keyword** monitor:

| | |
|---|---|
| URL | `https://idlarr.example/api/summary` |
| Keyword | `"needs_attention":0` |
| Invert Keyword | **on** |
| Headers | `{ "X-Api-Key": "YOUR_KEY" }` |
| Heartbeat Interval | 3600 |

Inverted, so the monitor is up while the count is zero and goes down the moment
anything is expired, critical, warn, due or logged out. Worth having even
though Idlarr pushes its own alerts: this one fails through a different service,
so a broken ntfy token does not take both out at once.

### Noticing the daily check stopped

`last_check` is the date the scheduler last ran. If it is behind today, alerts
are not being evaluated at all, and nothing else reports that. `/healthz` is
green the whole time, because the web server is fine; it is the loop behind it
that is not.

```bash
#!/bin/sh
# Exits 1 if Idlarr has not run its daily check today. Cron it after check_hour.
json=$(curl -sf --max-time 10 -H "X-Api-Key: $KEY" \
         https://idlarr.example/api/summary) || {
  echo "idlarr unreachable"
  exit 1
}
last=$(echo "$json" | jq -r '.last_check // "never"')
[ "$last" = "$(date +%F)" ] || {
  echo "idlarr last checked: $last"
  exit 1
}
```

Keep the unreachable case separate, as above. Folding it in reports a service
that is down as one whose scheduler has stalled, and those want different
fixes. Note `jq -r` prints a JSON `null` as the four characters `null`, so the
`// "never"` is doing real work: without it the fallback never fires.

Run it on a box in the same timezone as Idlarr's `timezone` setting, or compare
against that zone explicitly. `last_check` is a local date, so an hour of
disagreement either side of midnight reads as a day behind.

`never` means no check has ever completed, which on an install more than a day
old means the scheduler has not come up since the container did.

### In your shell prompt or MOTD

You open a terminal more often than you open a dashboard.

```bash
# ~/.bashrc
idlarr() {
  curl -sf --max-time 2 -H "X-Api-Key: $IDLARR_KEY" \
    https://idlarr.example/api/summary \
  | jq -r 'if .needs_attention == 0
           then "idlarr: all \(.trackers) ok"
           else "idlarr: \(.needs_attention) need attention, worst \(.worst.name) (\(.worst.state))"
           end'
}
idlarr
```

`--max-time 2` matters if you call it on every shell start. Without it, a box
that is down or unreachable hangs your prompt instead of printing nothing.

## If it stops working

A `401` means the key was wrong, missing, or you sent `IDLARR_TOKEN` instead.
The error text says which. Check Settings, API for the current value, and
remember that regenerating breaks everything using the old one immediately.
