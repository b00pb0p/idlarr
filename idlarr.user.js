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

  // The selector comes from the SERVER, in the reply to every ping, and is
  // cached here. The copy baked into SITES above is only the bootstrap for a
  // fresh install. That is what lets a selector confirmed on the dashboard take
  // effect on the next page load with nothing to reinstall. An empty string is
  // a real answer ("there is none") and overrides the baked value; only a
  // value that was never stored leaves the baked one alone.
  const SEL_KEY = `idl_${site.id}_sel`;
  const cachedSel = GM_getValue(SEL_KEY, null);
  if (typeof cachedSel === 'string') site.authSel = cachedSel;

  function applySel(sel) {
    if (typeof sel !== 'string') return;      // an older server: keep what we have
    if (GM_getValue(SEL_KEY, null) !== sel) GM_setValue(SEL_KEY, sel);
    if ((site.authSel || '') === sel) return;
    site.authSel = sel;
    console.log(`[idlarr] ${site.id} now detects sign-in by ` +
                (sel ? `"${sel}"` : 'the generic heuristic'));
    // The element is usually on the page already, since this reply arrives
    // after load. If it is not, the watcher still running will see it.
    checkAuth();
  }

  // A selector that does not parse must read as "no match", never throw: this
  // is called from a MutationObserver, and an exception there fires on every
  // mutation of the page.
  function selMatches(sel) {
    try { return document.querySelectorAll(sel).length; } catch (_) { return 0; }
  }

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

  // Anchored and whole-string: matches a control LABELED "log out", never a
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

  function visiblePasswordFields() {
    return [...document.querySelectorAll('input[type="password"]')].filter(isVisible);
  }

  function isAuthed() {
    // A login form has exactly ONE password field. A change-password form has
    // two or more, and only a signed-in user is ever shown one. That count is
    // the whole discriminator: it keeps the veto's real purpose, which is that
    // an auth must never be recorded on a login page, while dropping the false
    // negative on a profile page.
    //
    // Reported 2026-08-17. mma-tracker.org/my.php carries `chpassword` and
    // `passagain` in its profile form, beside an unmistakable Logout link. The
    // old rule vetoed on any visible password field, so a page the user was
    // plainly signed in to recorded a visit and no auth — which is exactly the
    // dead-cookie signature, and flipped the row to `logged out`. That is a
    // HIGH priority alert, so the safe direction was not free: it cried wolf
    // about the one state that means something specific.
    //
    // The veto still applies to authSel as well as the generic path. authSel
    // replaces the positive signal, never this guard, or a login page that
    // happened to contain the selector would reset a countdown.
    if (visiblePasswordFields().length === 1) return false;
    if (site.authSel) return selMatches(site.authSel) > 0;
    return !!findLogout();
  }

  function send(kind, extra) {
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
      // The installed version rides along so the service can tell you when
      // your copy is behind. Adding a tracker bumps the served version, and
      // a stale script simply never reports the new site: it sits at
      // `unknown` forever and reads as broken detection.
      data: JSON.stringify({ tracker: site.id, kind, v: GM_info.script.version,
                             ...(extra || {}) }),
      timeout: 10000,
      onload: res => {
        if (res.status >= 200 && res.status < 300) {
          GM_setValue(key, Date.now());
          let deduped = false, body = null;
          try { body = JSON.parse(res.responseText); } catch (_) {}
          if (body) { deduped = !!body.deduped; applySel(body.authSel); }
          console.log(`[idlarr] ${site.id} ${kind} ` +
                      (deduped ? 'already on record (server dedupe)' : 'recorded'));
        } else {
          // Back off on a 4xx. The cooldown is normally written only on
          // success, so a transient failure retries on the next page load --
          // but a 4xx is not transient. A tracker you REMOVED from Idlarr is
          // still in this script's @match until the next update check, so
          // without this it POSTs and 404s on every single page load of that
          // site. 5xx and network errors still retry immediately.
          if (res.status >= 400 && res.status < 500) GM_setValue(key, Date.now());
          console.warn(`[idlarr] ${res.status}: ${res.responseText}`);
        }
      },
      onerror: () => console.warn('[idlarr] endpoint unreachable'),
      ontimeout: () => console.warn('[idlarr] endpoint timeout'),
    });
    return true;
  }

  // ------------------------------------------------------- signed-in candidates
  //
  // For a site with no sign-out control in the DOM at all (single-page apps
  // usually render it only once a menu is opened). The script cannot tell
  // signed-in from signed-out there, so it looks for something a member would
  // have and lets the dashboard ASK. It never adopts one of these itself: a
  // wrong guess records logins that did not happen.
  //
  // Only names a person wrote count. Framework and generated class names
  // (mat-icon-button, css-1x2y3z) change between builds and say nothing.
  const FRAMEWORK = /^(mat|mdc|cdk|ng|v|el|ant|chakra|css|sc|jsx|tw|fa|fas|far|ti|bi|icon|svg|is|has|js)[-_]|^Mui[A-Z]/;
  const GENERATED = /\d{3,}|[-_](?=[a-z0-9]*\d)[a-z0-9]{5,}$/i;
  const SIGNED_OUT = /(^|-)(log-?in|sign-?in|sign-?up|register|guest|anon(ymous)?|forgot|reset|recover)(-|$)/;
  const SIGNED_OUT_TEXT = /log\s*in|sign\s*in|sign\s*up|register|create\s+an?\s+account/i;
  const MEMBER = [
    [/(^|-)(log|sign)-?out(-|$)/, 5],
    [/(^|-)(profile|avatar|username)(-|$)/, 4],
    [/(^|-)(user|account|member)(-|$)/, 3],
    [/(^|-)(inbox|notifications?|ratio|bonus|invites?)(-|$)/, 2],
  ];

  function signedInCandidates() {
    const found = new Map();
    for (const el of document.querySelectorAll('[class],[id]')) {
      const names = [];
      if (el.id) names.push(['#', el.id]);
      for (const c of el.classList || []) names.push(['.', c]);
      const tag = el.tagName.toLowerCase();
      for (const [sigil, name] of names) {
        if (name.length > 60 || FRAMEWORK.test(name) || GENERATED.test(name)) continue;
        // profileButton, profile_button and profile-button are one name.
        const norm = name.replace(/([a-z0-9])([A-Z])/g, '$1-$2')
                         .replace(/_/g, '-').toLowerCase();
        if (SIGNED_OUT.test(norm)) continue;
        const hit = MEMBER.find(([re]) => re.test(norm));
        if (!hit) continue;
        const sel = (sigil === '#' ? '' : tag) + sigil + CSS.escape(name);
        if (sel.length > 120 || found.has(sel)) continue;
        const n = selMatches(sel);
        // More than a few matches is a list of other people (a `user` cell on
        // every row of a torrent table), not something about YOU.
        if (n < 1 || n > 3 || !isVisible(el)) continue;
        if (SIGNED_OUT_TEXT.test((el.textContent || '').slice(0, 200))) continue;
        found.set(sel, hit[1] + (n === 1 ? 1 : 0) +
                       (tag === 'button' || tag === 'a' ? 1 : 0));
      }
    }
    return [...found.entries()].sort((a, b) => b[1] - a[1])
                               .slice(0, 3).map(e => e[0]);
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
      if (authSent) return;
      // Two very different endings, and they used to look identical in the
      // console. No logout control at all means detection needs an authSel.
      // A logout control that WAS found, beside a single password field, means
      // the veto declined a page you are plainly signed in to — the residual
      // gap left by counting fields, since one field cannot be told apart from
      // a login form. Report that one: silence here is indistinguishable from
      // a page you never opened, and finding these by hand means visiting the
      // profile page of every tracker you have.
      if (visiblePasswordFields().length === 1 && findLogout()) {
        console.warn(`[idlarr] ${site.id}: auth declined on ${location.pathname}` +
                     ` — a logout control is present but so is one password` +
                     ` field, which is indistinguishable from a login form`);
        send('veto', { path: location.pathname.slice(0, 120) });
        return;
      }
      const fields = visiblePasswordFields().length;
      if (fields === 1) {
        // A login form: you really are signed out. Say so, because a standing
        // "can't tell" on the dashboard would now be wrong. It CAN tell.
        console.log(`[idlarr] ${site.id}: login form on ${location.pathname}`);
        send('blind', { login: true });
        return;
      }
      console.warn(`[idlarr] ${site.id}: no logout affordance after ` +
                   `${WATCH_MS / 1000}s`);
      // No sign-out control, no password field, and no selector to go by: the
      // script has nothing to judge with. This used to end in the console line
      // above and nowhere else, so the dashboard called it "logged out", which
      // was false, and the only fix was hand-editing a config file. Report it,
      // with whatever on this page looks like it belongs to a member, so the
      // dashboard can ask one question instead.
      //
      // WITH a selector the report says which one matched nothing, and offers
      // no candidates. Either this is a signed-out page or the selector is
      // wrong, and a wrong one (typed by hand, or broken by a redesign) used
      // to be completely silent: the tracker simply never recorded again.
      if (fields === 0) {
        const path = location.pathname.slice(0, 120);
        send('blind', site.authSel ? { path, sel: site.authSel }
                                   : { path, cand: signedInCandidates() });
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
      authSelMatches: site.authSel ? selMatches(site.authSel) : null,
      // What the script would offer the dashboard if it could not tell.
      signedInCandidates: signedInCandidates(),
      logoutFound: !!found,
      logoutHTML: found ? found.outerHTML.slice(0, 180) : null,
      // The COUNT, not a boolean: one field vetoes, two or more do not, so a
      // bare true/false cannot explain the verdict it produced.
      visiblePasswordFields: visiblePasswordFields().length,
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
