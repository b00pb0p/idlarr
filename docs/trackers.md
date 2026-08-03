# Managing trackers

Adding, removing and importing them, plus the escape hatch for a site the auth
heuristic cannot read. All of this happens after you are running — see
[Setup](setup.md) to get there.

**From the status page.** **+ Add tracker**, top right. Name and URL are
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

## Importing from Prowlarr or Jackett

Settings gear → **Import**. Point it at your own Prowlarr or Jackett with an API key and
it lists the private indexers it found, marking which are new. Nothing is
written until you click Import — an API key aimed at the wrong instance should
cost you a list on screen, not a rewritten config.

| | URL | API key |
|---|---|---|
| Prowlarr | `http://prowlarr.local:9696` | Settings → General → API Key |
| Jackett | `http://jackett.local:9117` | top of the Jackett dashboard |

Public indexers and usenet are skipped — there is no account to lose. Trackers
already in your config are skipped too, matched on **site** as well as id, so a
tracker Prowlarr names differently is not added twice.

Matching is by site rather than by exact hostname, and API hosts are rewritten
to the site you actually log in on. Prowlarr stores BroadcasTheNet as
`api.broadcasthe.net`; that is one tracker with `broadcasthe.net`, not two. It
matters more than it sounds: a duplicate splits one account's history across two
rows and leaves **both** countdowns wrong, and a row matching an API host never
sees a browser session, so it would sit at `unknown` forever looking like broken
detection.

**Limits are never imported.** Neither tool knows a tracker's inactivity policy,
so everything arrives at 30 days and unconfirmed like any other new entry. A
limit that showed up looking authoritative and was wrong in the high direction
would be worse than no limit at all.

This talks to your indexer manager, never to a tracker. The no-tracker-traffic
rule is about requests that could get an account banned; Prowlarr on your own
box is not one of those.

## By hand

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

## A site the heuristic can't read

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


# Immune trackers

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

