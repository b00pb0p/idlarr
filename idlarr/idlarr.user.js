// ==UserScript==
// @name         Idlarr
// @namespace    idlarr
// @version      1.0.0
// @description  Never lose an account to inactivity again. Reports "I was logged in" to a self-hosted watchdog; sends nothing to the tracker.
// @author       you
// @run-at       document-idle
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        unsafeWindow
//
// ---- one @match per tracker; add both here and in SITES below ----
// NOTE: '*.domain/*' covers the apex domain and all subdomains.
// @match        *://*.alpha.example/*
// @match        *://*.beta.example/*
// @match        *://*.gamma.example/*
//
// ---- must match your IDLARR endpoint host (CSP bypass needs this) ----
// @connect      idlarr.example.ts.net
// ==/UserScript==

(function () {
  'use strict';

  // ------------------------------------------------------------- settings
  const ENDPOINT = 'https://idlarr.example.ts.net/ping';
  // Must be byte-identical to IDLARR_TOKEN in docker-compose.yml, or every
  // ping comes back 401 and the console fills with [idlarr] 401 lines.
  const TOKEN    = 'PUT_IDLARR_TOKEN_HERE';
  // Short on purpose. The REAL one-per-12h dedupe now lives on the server,
  // because only the database knows what actually exists. A long client-side
  // cooldown meant /api/unmark could delete an event the browser still believed
  // it had reported, silencing that tracker for up to 12 hours with no
  // indication anywhere. This 5 minutes only stops request spam while browsing;
  // any drift now self-heals within one cooldown.
  const COOLDOWN = 5 * 60 * 1000;

  // hostname substring -> { id, authSel? }
  // `id` MUST equal the id in trackers.yml.
  // `authSel` overrides detection for sites the generic heuristic gets wrong.
  const SITES = [
    { host: 'alpha.example', id: 'alpha' },
    { host: 'beta.example', id: 'beta' },
    // Some sites keep no logout control in the DOM (single-page apps often
    // render it only once a user menu is opened). Point authSel at any element
    // that exists ONLY when authenticated — a passkey link, an upload button.
    { host: 'gamma.example', id: 'gamma', authSel: 'a[href*="/torrent?key="]' },
    // add one entry per tracker; `id` must match trackers.yml
  ];

  // ------------------------------------------------------------- detection
  const site = SITES.find(s => location.hostname.includes(s.host));
  if (!site) return;

  // A logout affordance, by URL or by label. Three conventions seen in the wild:
  //   Gazelle / TBDev   <a href="logout.php?auth=...">
  //   UNIT3D            <form method="POST" action=".../logout">
  //   some custom PHP   <form action="/lout.php"><button>Log out</button>
  // That last one defeats both naive checks: 'lout.php' does not contain the
  // substring 'logout', and the label has a space in it. Hence two rules.
  const LOGOUT_ATTR = [
    'a[href*="logout" i]', 'a[href*="lout.php" i]', 'a[href*="signout" i]',
    'form[action*="logout" i]', 'form[action*="lout.php" i]', 'form[action*="signout" i]',
    'button[formaction*="logout" i]', 'button[formaction*="lout.php" i]',
  ].join(',');

  // Anchored and whole-string: matches a control LABELLED "log out", never a
  // paragraph that merely mentions logging out.
  const LOGOUT_TEXT = /^(log|sign)\s*-?\s*out$/i;

  function findLogout() {
    const byAttr = document.querySelector(LOGOUT_ATTR);
    if (byAttr) return byAttr;
    for (const el of document.querySelectorAll('a, button, [role="button"]')) {
      if (LOGOUT_TEXT.test((el.textContent || '').trim())) return el;
    }
    return null;
  }

  // Rendered, not merely present. SPAs routinely keep a login form mounted and
  // hidden; vetoing on those would reject a page that is plainly authenticated.
  // A real login page always has a VISIBLE password field, so this keeps the
  // guard's purpose while dropping its false positives.
  function isVisible(el) {
    return !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length));
  }

  function visiblePasswordField() {
    for (const el of document.querySelectorAll('input[type="password"]')) {
      if (isVisible(el)) return el;
    }
    return null;
  }

  function isAuthed() {
    // The password veto applies to authSel too, not just the generic path.
    // authSel replaces the positive signal, never this veto — otherwise a login
    // page that happened to contain the selector would reset a countdown, which
    // is the worst failure this project has. The remaining cost is a false
    // NEGATIVE on a logged-in change-password page; that is the safe direction,
    // and the next page load corrects it.
    if (visiblePasswordField()) return false;
    if (site.authSel) return !!document.querySelector(site.authSel);
    return !!findLogout();
  }

  function send(kind) {
    const key = `idl_${site.id}_${kind}`;
    const last = Number(GM_getValue(key, 0));
    if (Date.now() - last < COOLDOWN) {
      // Log it. A silent debounce is indistinguishable from a broken script,
      // and that ambiguity costs real time when diagnosing a quiet tracker.
      const mins = ((COOLDOWN - (Date.now() - last)) / 60000).toFixed(1);
      console.log(`[idlarr] ${site.id} ${kind} debounced locally, ${mins}m left`);
      return false;
    }

    GM_xmlhttpRequest({
      method: 'POST',
      url: ENDPOINT,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TOKEN}`,
      },
      data: JSON.stringify({ tracker: site.id, kind }),
      timeout: 10000,
      onload: res => {
        if (res.status >= 200 && res.status < 300) {
          GM_setValue(key, Date.now());
          let deduped = false;
          try { deduped = !!JSON.parse(res.responseText).deduped; } catch (_) {}
          console.log(`[idlarr] ${site.id} ${kind} ` +
                      (deduped ? 'already on record (server dedupe)' : 'recorded'));
        } else {
          console.warn(`[idlarr] ${res.status}: ${res.responseText}`);
        }
      },
      onerror: () => console.warn('[idlarr] endpoint unreachable'),
      ontimeout: () => console.warn('[idlarr] endpoint timeout'),
    });
    return true;
  }

  // ------------------------------------------------------------- scheduling
  //
  // Checking auth exactly once at document-idle is not enough. Trackers built
  // on UNIT3D v8 hydrate the navbar with Alpine/Livewire AFTER idle, so the
  // logout form genuinely is not in the DOM when a single synchronous check
  // runs — a manual console probe finds it, the script never does. Sites using
  // Turbo/PJAX have the mirror problem: logging in navigates client-side, so no
  // document load ever happens again.
  //
  // So: check immediately, then watch the DOM for a bounded window, and re-check
  // on client-side navigation. All of this is local DOM observation — still ZERO
  // requests to any tracker, which is the one constraint that must never bend.

  const WATCH_MS = 10000;   // give late-hydrating frameworks time to render
  let authSent = false;

  // 'visit' is a per-page-load fact, so it is sent once per load (and once per
  // SPA navigation) — NOT from checkAuth(). Calling it on every observer tick
  // spams the console on any page that mutates continuously.
  function checkAuth() {
    if (authSent) return true;
    if (!isAuthed()) return false;
    // Either dispatched or knowingly debounced — both mean "handled", and both
    // log. Never mark it handled without saying which.
    send('auth');
    authSent = true;
    return true;
  }

  function watchForAuth() {
    if (authSent) return;
    let queued = false;
    const obs = new MutationObserver(() => {
      // Busy pages fire thousands of mutations; coalesce to one check per frame.
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => {
        queued = false;
        if (checkAuth()) stop();
      });
    });
    obs.observe(document.documentElement, { childList: true, subtree: true });
    const timer = setTimeout(() => {
      stop();
      if (!authSent) {
        console.warn(`[idlarr] ${site.id}: no logout affordance after ` +
                     `${WATCH_MS / 1000}s — set authSel for this site`);
      }
    }, WATCH_MS);
    function stop() { obs.disconnect(); clearTimeout(timer); }
  }

  // Client-side navigation (Turbo, Livewire, plain pushState) never re-runs a
  // userscript, so hook it explicitly.
  function onSpaNav() {
    if (authSent) return;
    send('visit');
    if (!checkAuth()) watchForAuth();
  }
  for (const fn of ['pushState', 'replaceState']) {
    const orig = history[fn];
    history[fn] = function () { const r = orig.apply(this, arguments); onSpaNav(); return r; };
  }
  window.addEventListener('popstate', onSpaNav);

  // Always announce, so "did the script run?" is answerable even when both
  // event kinds are inside their 12h debounce and nothing is sent.
  // ------------------------------------------------------------- diagnostics
  //
  // Every site that has failed so far failed differently — a masked debounce,
  // an unmatched URL convention, an SPA with no logout control. Each round cost
  // a paste-a-console-one-liner exchange. This reports the script's own view of
  // the page instead, so diagnosing tracker N+1 is one call.
  function report() {
    const found = findLogout();
    return {
      site: site.id,
      host: location.hostname,
      isAuthed: isAuthed(),
      authAlreadyHandled: authSent,
      authSel: site.authSel || '(generic heuristic)',
      authSelMatches: site.authSel ? document.querySelectorAll(site.authSel).length : null,
      logoutFound: !!found,
      logoutHTML: found ? found.outerHTML.slice(0, 180) : null,
      visiblePasswordField: !!visiblePasswordField(),
      // Anything logout-shaped, whether or not the heuristic accepted it —
      // this is what to send when detection fails.
      candidates: [...document.querySelectorAll('a, button, form, input[type=submit]')]
        .filter(e => /log\s*-?\s*out|sign\s*-?\s*out|\blout\b/i.test(
          (e.textContent || '') + ' ' + (e.getAttribute('href') || '') + ' ' +
          (e.getAttribute('action') || '') + ' ' + (e.value || '')))
        .slice(0, 6).map(e => e.outerHTML.slice(0, 180)),
    };
  }
  try { unsafeWindow.__idlarr = report; } catch (_) { /* sandboxed; ignore */ }

  console.log(`[idlarr] ${site.id} active on ${location.hostname}` +
              ` — run __idlarr() for detection detail`);
  send('visit');
  if (!checkAuth()) {
    // Say which branch we took, so "nothing happened" is never ambiguous.
    console.log(`[idlarr] ${site.id} not authed at idle — watching ${WATCH_MS / 1000}s`);
    watchForAuth();
  }
})();
