#!/usr/bin/env python3
"""Tests for the optional UI login.

The thing these are really guarding is the same failure the project keeps
hitting: auth that LOOKS enabled while accepting everything. `require_token`
once returned early on an empty token and /healthz stayed green throughout.
So several tests below assert the negative — that a half-configured login
reads as off, that a rotated secret really does invalidate a cookie, that a
password change cannot be made by a borrowed session alone.

Run:  .venv/bin/python -m pytest test_auth.py -q
"""

import base64
import json
import os
import tempfile
import time
from pathlib import Path

import pytest

# Same trick as test_evaluate.py: app.py reads these at import time.
_tmp = tempfile.mkdtemp(prefix="idlarr-auth-test-")
os.environ["IDLARR_DB"] = str(Path(_tmp) / "test.db")
os.environ["IDLARR_CONFIG"] = str(Path(__file__).parent / "tests_fixture.yml")
os.environ.setdefault("IDLARR_TOKEN", "test-token")

import app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

PW = "correct-horse"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    """Empty state, and PBKDF2 turned down so the suite stays fast.

    600k rounds is right in production and would add ~0.4s to every single
    test here. verify_password reads the round count back out of the stored
    string, so lowering it cannot mask a mismatch.
    """
    app.init_db()
    with app.db() as conn:
        conn.execute("DELETE FROM state")
        conn.execute("DELETE FROM events")
    app._login_fails.clear()
    monkeypatch.setattr(app, "PBKDF2_ROUNDS", 1000)
    yield


@pytest.fixture
def client():
    # No context manager on purpose: that would run lifespan and start the
    # scheduler task, which these tests have no use for.
    return TestClient(app.app)


def configure(client, method="forms", user="jared", pw=PW, current=None):
    return client.post("/api/auth", json={
        "method": method, "username": user, "password": pw,
        "current_password": current or "",
    })


# ------------------------------------------------------------- hashing

def test_password_round_trip():
    enc = app.hash_password(PW)
    assert app.verify_password(PW, enc)
    assert not app.verify_password(PW + "x", enc)
    assert not app.verify_password("", enc)


def test_hash_is_salted():
    """Two hashes of the same password must differ, or the stored value leaks
    'these two accounts share a password' — and here it would leak it across
    reconfigurations of the same account."""
    assert app.hash_password(PW) != app.hash_password(PW)


def test_hash_stores_no_plaintext():
    enc = app.hash_password(PW)
    assert PW not in enc
    assert enc.startswith("pbkdf2_sha256$")


@pytest.mark.parametrize("bad", ["", "garbage", "pbkdf2_sha256$notanint$a$b",
                                 "md5$1$a$b", "a$b$c"])
def test_malformed_hash_is_never_accepted(bad):
    """A corrupt or truncated hash must answer 'no'. An exception escaping here
    would 500, and a bare `except: pass` upstream would turn that into 'yes'."""
    assert app.verify_password(PW, bad) is False


# ------------------------------------------------------------- sessions

def test_session_round_trip():
    tok = app.make_session("jared")
    assert app.read_session(tok) == "jared"


@pytest.mark.parametrize("mangle", [
    lambda t: t[:-1] + ("a" if t[-1] != "a" else "b"),   # tampered signature
    lambda t: t.split(".")[0],                            # signature removed
    lambda t: "." + t.split(".")[1],                      # payload removed
    lambda t: "",
])
def test_tampered_session_rejected(mangle):
    assert app.read_session(mangle(app.make_session("jared"))) is None


def test_forged_payload_rejected():
    """Re-signing needs the secret; swapping the payload alone must not work."""
    raw = base64.urlsafe_b64encode(
        json.dumps({"u": "attacker", "exp": int(time.time()) + 999}).encode()
    ).decode().rstrip("=")
    good = app.make_session("jared")
    assert app.read_session(raw + "." + good.rpartition(".")[2]) is None


def test_expired_session_rejected(monkeypatch):
    monkeypatch.setattr(app, "SESSION_DAYS", -1)
    assert app.read_session(app.make_session("jared")) is None


def test_rotating_the_secret_invalidates_sessions():
    tok = app.make_session("jared")
    assert app.read_session(tok) == "jared"
    app.set_state("session_secret", "")          # forces a fresh one
    assert app.read_session(tok) is None


# ------------------------------------------------------------- method state

def test_method_defaults_to_none():
    assert app.auth_method() == "none"


def test_method_without_credentials_reads_as_off():
    """A recorded method with no hash behind it must be OFF, not a locked door
    nobody holds the key to — otherwise a half-finished setup or a reset would
    leave the dashboard permanently 401 with no way back in."""
    app.set_state("auth_method", "forms")
    assert app.auth_method() == "none"


# ------------------------------------------------------------- lockout

def test_lockout_after_repeated_failures(client):
    configure(client)
    for _ in range(app.LOCKOUT_AFTER):
        assert client.post("/login", json={"username": "jared",
                                           "password": "wrong"}).status_code == 401
    # Even the RIGHT password is refused now: this is a timeout, not a check.
    r = client.post("/login", json={"username": "jared", "password": PW})
    assert r.status_code == 429


def test_successful_login_clears_the_counter(client):
    configure(client)
    for _ in range(app.LOCKOUT_AFTER - 1):
        client.post("/login", json={"username": "jared", "password": "wrong"})
    assert client.post("/login", json={"username": "jared",
                                       "password": PW}).status_code == 200
    for _ in range(app.LOCKOUT_AFTER - 1):
        assert client.post("/login", json={"username": "jared",
                                           "password": "wrong"}).status_code == 401


# ------------------------------------------------------------- enforcement

def test_everything_open_when_auth_is_off(client):
    assert client.get("/").status_code == 200
    assert client.get("/api/status").status_code == 200
    assert client.post("/api/mark/alpha").status_code in (200, 303)


def test_banner_shown_only_when_auth_is_off(client):
    page = client.get("/").text
    assert "No sign-in configured" in page                       # the banner
    assert 'sign-in <b class="bad">off</b>' in page              # the status line
    assert '<span class="val off">not configured</span>' in page  # the settings panel
    configure(client)
    page = client.get("/", auth=("jared", PW)).text
    assert "No sign-in configured" not in page
    assert 'sign-in <b class="ok">forms</b>' in page
    assert '<span class="val on">jared' in page


PROTECTED = ["/api/status", "/api/history/alpha", "/api/auth"]


@pytest.mark.parametrize("path", PROTECTED)
def test_protected_paths_401_without_credentials(client, path):
    configure(client)
    client.cookies.clear()
    assert client.get(path).status_code == 401


def test_write_endpoints_401_without_credentials(client):
    """The one that actually costs something: a stranger POSTing /api/mark
    resets a countdown, after which the page reads `ok` while the account ages
    out — the exact failure this service exists to prevent."""
    configure(client)
    client.cookies.clear()
    assert client.post("/api/mark/alpha").status_code == 401
    assert client.post("/api/unmark/alpha").status_code == 401
    assert client.post("/api/limit/alpha",
                       json={"inactivity_days": 90}).status_code == 401


def test_healthz_stays_open(client):
    """Open item 1 wants an uptime monitor here. A monitor needing credentials
    is a monitor that does not get set up."""
    configure(client)
    client.cookies.clear()
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_ping_still_uses_the_bearer_token(client):
    """The userscript posts cross-origin from tracker pages, where cookies do
    not apply. If the UI login ever starts gating /ping, every tracker goes
    silent and the dashboard gives no hint why."""
    configure(client)
    client.cookies.clear()
    assert client.post("/ping", json={"tracker": "alpha"}).status_code == 401
    r = client.post("/ping", json={"tracker": "alpha"},
                    headers={"Authorization": f"Bearer {app.TOKEN}"})
    assert r.status_code == 200


def test_forms_redirects_to_login(client):
    configure(client, method="forms")
    client.cookies.clear()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_basic_challenges_with_a_header(client):
    configure(client, method="basic")
    client.cookies.clear()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Basic realm="Idlarr"'


def test_basic_credentials_work_under_forms(client):
    """The method decides how you are CHALLENGED, not which credentials are
    valid — so curl and scripts keep working without a login round-trip."""
    configure(client, method="forms")
    client.cookies.clear()
    assert client.get("/api/status", auth=("jared", PW)).status_code == 200
    assert client.get("/api/status", auth=("jared", "wrong")).status_code == 401


def test_login_sets_a_working_session(client):
    configure(client, method="forms")
    client.cookies.clear()
    assert client.post("/login", json={"username": "jared",
                                       "password": "wrong"}).status_code == 401
    r = client.post("/login", json={"username": "jared", "password": PW})
    assert r.status_code == 200
    assert app.SESSION_COOKIE in r.cookies
    assert client.get("/api/status").status_code == 200


def test_session_cookie_is_httponly_and_not_secure_over_plain_http(client):
    """`secure` on a plain-HTTP LAN install breaks login in the most confusing
    way there is: the browser accepts it, silently drops the cookie, and you
    bounce back to the login page with no error anywhere."""
    configure(client, method="forms")
    client.cookies.clear()
    r = client.post("/login", json={"username": "jared", "password": PW})
    setc = r.headers["set-cookie"].lower()
    assert "httponly" in setc
    assert "samesite=lax" in setc
    assert "secure" not in setc


def test_logout_clears_the_cookie(client):
    configure(client, method="forms")
    client.post("/login", json={"username": "jared", "password": PW})
    assert client.get("/api/status").status_code == 200
    client.post("/logout")
    assert client.get("/api/status").status_code == 401


# ------------------------------------------------------------- configuring

def test_first_setup_is_open_then_closes(client):
    assert client.get("/api/auth").status_code == 200      # nothing configured
    assert configure(client).status_code == 200
    client.cookies.clear()
    assert client.get("/api/auth").status_code == 401


def test_changing_requires_the_current_password(client):
    """A borrowed session alone must not be enough to lock the owner out of
    their own dashboard."""
    configure(client)
    assert configure(client, pw="brand-new-one").status_code == 403
    assert configure(client, pw="brand-new-one", current="nope").status_code == 403
    assert configure(client, pw="brand-new-one", current=PW).status_code == 200
    client.cookies.clear()
    assert client.get("/api/status", auth=("jared", "brand-new-one")).status_code == 200


def test_disabling_requires_the_current_password(client):
    configure(client)
    assert client.post("/api/auth", json={"method": "none"}).status_code == 403
    assert client.post("/api/auth", json={"method": "none",
                                          "current_password": PW}).status_code == 200
    client.cookies.clear()
    assert client.get("/api/status").status_code == 200


def test_password_change_invalidates_other_sessions(client):
    configure(client)
    stale = client.cookies.get(app.SESSION_COOKIE)
    configure(client, pw="brand-new-one", current=PW)
    assert app.read_session(stale) is None


def test_password_change_keeps_the_caller_signed_in(client):
    """Signing yourself out by changing your own password is a bad enough
    surprise to be worth a test."""
    configure(client)
    r = configure(client, pw="brand-new-one", current=PW)
    assert app.SESSION_COOKIE in r.cookies
    assert client.get("/api/status").status_code == 200


@pytest.mark.parametrize("payload,why", [
    ({"method": "forms", "username": "jared", "password": "short1"}, "too short"),
    ({"method": "forms", "username": "", "password": PW}, "empty username"),
    ({"method": "forms", "username": "a" * 65, "password": PW}, "username too long"),
    ({"method": "forms", "username": "a:b", "password": PW}, "colon in username"),
    ({"method": "sso", "username": "jared", "password": PW}, "unknown method"),
])
def test_configuration_is_validated(client, payload, why):
    assert client.post("/api/auth", json=payload).status_code == 400, why


def test_colon_username_is_refused_because_basic_splits_on_it(client):
    """It would authenticate under forms and fail under basic — a setting
    change would then look like a broken password."""
    assert configure(client, user="a:b").status_code == 400


def test_auth_status_never_returns_the_hash(client):
    configure(client)
    body = client.get("/api/auth").text
    assert "hash" not in body.lower()
    assert PW not in body
    assert set(client.get("/api/auth").json()) == {"method", "user"}


def test_reset_clears_everything():
    """IDLARR_RESET_AUTH is the only way back in from a forgotten password,
    since the credentials live in the database and not in a file you can edit.
    Clearing session_secret matters too: a reset that left existing cookies
    valid would not lock out whoever you are resetting because of."""
    app.set_state("auth_user", "jared")
    app.set_state("auth_hash", app.hash_password(PW))
    app.set_state("auth_method", "forms")
    stale = app.make_session("jared")

    for key in ("auth_method", "auth_user", "auth_hash", "session_secret"):
        app.set_state(key, "")

    assert app.auth_method() == "none"
    assert app.read_session(stale) is None


# ---------------------------------------------------------------- token timing

def test_ping_token_uses_constant_time_comparison(monkeypatch):
    """`!=` short-circuits on the first wrong byte, a timing oracle for the
    token that gates forging auth events. Assert the code path uses
    hmac.compare_digest rather than a plain string compare."""
    import inspect
    src = inspect.getsource(app.require_token)
    assert "compare_digest" in src
    assert "auth != " not in src and "!= f\"Bearer" not in src


def test_ping_token_still_enforces_after_the_timing_fix(monkeypatch):
    """Constant-time must not mean lax. Every wrong form is still rejected."""
    monkeypatch.setattr(app, "TOKEN", "right-token")
    from fastapi import HTTPException
    def code(auth):
        try:
            app.require_token(auth); return 200
        except HTTPException as e:
            return e.status_code
    assert code("Bearer right-token") == 200
    for bad in ("Bearer wrong-token", "right-token", "Bearer ", "", None, "bearer right-token"):
        assert code(bad) == 401, bad
