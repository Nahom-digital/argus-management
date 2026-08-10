"""The login path: what gets recorded, what gets blocked, what a blocker is told.

Every table in this area already had a writer and a reader before this suite
existed. What was missing was anything calling them, so the Logs tab sat empty
and a blocked address was never actually stopped. These tests assert the wiring,
which is the part that was absent.
"""
import pytest

import DB
import panel
import web_guard
from fastapi.testclient import TestClient

IP = "203.0.113.77"
OTHER_IP = "203.0.113.78"
WRONG = "definitely-not-the-password"


@pytest.fixture
def client(conn):
    """A client whose peer address is one this suite owns, so counting rows by
    address cannot pick up anything else on the machine."""
    cur = conn.cursor()
    cur.execute("DELETE FROM web_login_log WHERE ip LIKE '203.0.113.%'")
    cur.execute("DELETE FROM web_login_block WHERE ip LIKE '203.0.113.%'")
    cur.execute("DELETE FROM web_fp_block WHERE last_ip LIKE '203.0.113.%'")
    conn.commit()
    cur.close()
    # The ingress gate only lets loopback or Cloudflare through, so the peer is
    # loopback and the address under test arrives in the forwarded header the
    # same way it would from nginx.
    with TestClient(panel.app, client=("127.0.0.1", 51020)) as c:
        yield c
    cur = conn.cursor()
    cur.execute("DELETE FROM web_login_log WHERE ip LIKE '203.0.113.%'")
    cur.execute("DELETE FROM web_login_block WHERE ip LIKE '203.0.113.%'")
    cur.execute("DELETE FROM web_fp_block WHERE last_ip LIKE '203.0.113.%'")
    conn.commit()
    cur.close()


def _attempt(client, ip=IP, username="admin", password=WRONG, device="HarnessBrowser/1.0"):
    return client.post("/api/login",
                       json={"username": username, "password": password},
                       headers={"x-forwarded-for": ip, "user-agent": device})


def _rows(conn, ip=IP):
    cur = conn.cursor()
    cur.execute("""SELECT username, success, fp_hash, fingerprint, details, ip
                   FROM web_login_log WHERE ip = %s ORDER BY id""", (ip,))
    out = cur.fetchall()
    cur.close()
    return out


def _block(conn, ip=IP):
    cur = conn.cursor()
    cur.execute("SELECT fail_count, blocked_until FROM web_login_block WHERE ip = %s", (ip,))
    row = cur.fetchone()
    cur.close()
    return row


# ------------------------------------------------------------------ recording
def test_a_failed_login_is_recorded(client, conn):
    assert _attempt(client).status_code == 401
    rows = _rows(conn)
    assert len(rows) == 1
    assert rows[0][1] is False, "the row must be marked as a failure"
    assert rows[0][5] == IP, "the forwarded address must be what is stored"


def test_the_device_is_recorded_so_the_operator_knows_which_machine_tried(client, conn):
    _attempt(client, device="Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0.0.0 Safari/537.36")
    _, _, fp_hash, fingerprint, _, _ = _rows(conn)[0]
    assert fp_hash, "a failed attempt with no device recorded cannot be blocked by device"
    assert fingerprint and "Chrome" in fingerprint, fingerprint


def test_two_different_browsers_are_two_different_devices(client, conn):
    _attempt(client, device="Mozilla/5.0 Chrome/141.0.0.0")
    _attempt(client, device="Mozilla/5.0 Firefox/130.0")
    hashes = {row[2] for row in _rows(conn)}
    assert len(hashes) == 2, "one fingerprint for two browsers would block bystanders"


def test_the_attempted_password_is_never_stored(client, conn):
    """A mistyped password is usually the real one, one character off. Storing it
    turns the log into a plaintext password store readable by anyone holding the
    Logs grant."""
    _attempt(client, password="Sup3rSecret!ButMistyped")
    cur = conn.cursor()
    cur.execute("SELECT tried_password FROM web_login_log WHERE ip = %s", (IP,))
    stored = [r[0] for r in cur.fetchall()]
    cur.close()
    assert all(not s for s in stored), f"a password was written to the log: {stored}"


def test_the_reader_does_not_hand_out_a_password_column(conn):
    """Old rows written before that changed may still hold one, so not selecting
    it is the thing that keeps it out of the interface."""
    page = DB.get_web_login_logs(1, 5)
    for row in page["logs"]:
        assert "tried_password" not in row, row.keys()


def test_a_failure_counts_against_the_address(client, conn):
    _attempt(client)
    _attempt(client)
    fail_count, blocked_until = _block(conn)
    assert fail_count == 2
    assert blocked_until is None, "two failures is not yet a block"


# -------------------------------------------------------------------- blocking
def test_five_failures_blocks_the_address_and_the_device(client, conn):
    for _ in range(web_guard.FAIL_LIMIT):
        _attempt(client)
    fail_count, blocked_until = _block(conn)
    assert fail_count == web_guard.FAIL_LIMIT
    assert blocked_until is not None, "five failures must block the address"

    cur = conn.cursor()
    cur.execute("SELECT fail_count, blocked_until FROM web_fp_block WHERE last_ip = %s", (IP,))
    device_row = cur.fetchone()
    cur.close()
    assert device_row and device_row[1] is not None, \
        "five failures must block the device as well, or moving IP defeats it"


def test_the_device_block_follows_the_machine_to_a_new_address(client, conn):
    """The whole point of fingerprinting: an attacker who changes address but
    keeps the same browser is still the same attacker."""
    for _ in range(web_guard.FAIL_LIMIT):
        _attempt(client, ip=IP, device="AttackTool/9.9")
    # The device is whatever the server actually recorded for those attempts. A
    # fingerprint rebuilt here from a made up request would hash the headers this
    # test thought to set rather than the ones the client really sent, and would
    # pass or fail for reasons that have nothing to do with the block.
    device = _rows(conn)[-1][2]
    assert device, "the attempts recorded no device, so there is nothing to follow"
    allowed, _fails, _until = DB.check_web_login_allowed(OTHER_IP, device)
    assert allowed is False, "a fresh address with the blocked device must be refused"


def test_a_blocked_caller_is_only_told_the_credentials_are_wrong(client, conn):
    for _ in range(web_guard.FAIL_LIMIT):
        _attempt(client)
    r = _attempt(client)
    assert r.status_code == 401
    body = r.json()
    assert body["error"] == "Invalid username or password."
    text = str(body).lower()
    for leak in ("block", "locked", "too many", "attempt", "wait", "until", "hour"):
        assert leak not in text, f"the response reveals the lockout: {body}"


def test_a_correct_password_from_a_blocked_address_still_fails(client, conn, monkeypatch):
    """Otherwise the lockout is decoration: the whole point is that the guess
    which would have worked does not get a chance."""
    right = "the-right-one"
    # An oracle that accepts one password and refuses the rest. Patching it to
    # accept everything would have made the five attempts below succeed, so
    # nothing would be blocked and the test would prove nothing.
    monkeypatch.setattr(DB, "verify_admin", lambda u, p: p == right)
    for _ in range(web_guard.FAIL_LIMIT):
        _attempt(client)
    r = _attempt(client, password=right)
    assert r.status_code == 401
    assert "session" not in r.cookies


def test_an_attempt_from_a_blocked_source_is_still_recorded(client, conn):
    """The caller learns nothing, but the operator has to be able to see that
    something is still knocking."""
    for _ in range(web_guard.FAIL_LIMIT):
        _attempt(client)
    before = len(_rows(conn))
    _attempt(client)
    rows = _rows(conn)
    assert len(rows) == before + 1
    assert "blocked" in (rows[-1][4] or "").lower(), rows[-1][4]


def test_a_private_address_is_blocked_exactly_like_a_public_one(client, conn):
    """The machine on the desk next to the server is not more trustworthy than
    the internet."""
    private = "10.0.0.42"
    cur = conn.cursor()
    cur.execute("DELETE FROM web_login_log WHERE ip = %s", (private,))
    cur.execute("DELETE FROM web_login_block WHERE ip = %s", (private,))
    conn.commit()
    cur.close()
    try:
        assert web_guard.is_private(private)
        for _ in range(web_guard.FAIL_LIMIT):
            _attempt(client, ip=private)
        allowed, _f, until = DB.check_web_login_allowed(private, "")
        assert allowed is False and until is not None
    finally:
        cur = conn.cursor()
        cur.execute("DELETE FROM web_login_log WHERE ip = %s", (private,))
        cur.execute("DELETE FROM web_login_block WHERE ip = %s", (private,))
        cur.execute("DELETE FROM web_fp_block WHERE last_ip = %s", (private,))
        conn.commit()
        cur.close()


def test_expiry_is_decided_by_the_database_not_by_python(conn):
    """The rows are written with CURRENT_TIMESTAMP into a column with no time
    zone. Comparing them against datetime.utcnow() was wrong by the server's
    offset, so a 24 hour block released after 21 in GMT+3."""
    ip = "203.0.113.99"
    cur = conn.cursor()
    cur.execute("DELETE FROM web_login_block WHERE ip = %s", (ip,))
    # A block that expired one minute ago must read as expired, and one that
    # expires in a minute must read as active, whatever the server's offset is.
    cur.execute("""INSERT INTO web_login_block (ip, fail_count, first_fail, last_fail, blocked_until)
                   VALUES (%s, 9, now(), now(), now() - INTERVAL '1 minute')""", (ip,))
    conn.commit()
    cur.close()
    try:
        allowed, _f, _u = DB.check_web_login_allowed(ip, "")
        assert allowed is True, "an expired block must not still refuse"

        cur = conn.cursor()
        cur.execute("""INSERT INTO web_login_block (ip, fail_count, first_fail, last_fail, blocked_until)
                       VALUES (%s, 9, now(), now(), now() + INTERVAL '1 minute')
                       ON CONFLICT (ip) DO UPDATE SET blocked_until = EXCLUDED.blocked_until""", (ip,))
        conn.commit()
        cur.close()
        allowed, _f, _u = DB.check_web_login_allowed(ip, "")
        assert allowed is False, "a block one minute from expiry must still refuse"
    finally:
        cur = conn.cursor()
        cur.execute("DELETE FROM web_login_block WHERE ip = %s", (ip,))
        conn.commit()
        cur.close()


# ------------------------------------------------------------------- successes
def test_a_successful_login_clears_the_count_and_opens_a_session(client, conn, monkeypatch):
    right = "the-right-one"
    monkeypatch.setattr(DB, "verify_admin", lambda u, p: p == right)
    _attempt(client, password=WRONG)          # one failure on record
    assert _block(conn)[0] == 1, "there is no count for the success to clear"
    r = _attempt(client, username="admin", password=right)
    assert r.status_code == 200
    assert _block(conn) is None, "a success must clear the failure count"

    rows = _rows(conn)
    assert rows[-1][1] is True

    cur = conn.cursor()
    cur.execute("""SELECT username, status FROM web_session_log
                   WHERE ip = %s ORDER BY login_at DESC LIMIT 1""", (IP,))
    session = cur.fetchone()
    cur.execute("DELETE FROM web_session_log WHERE ip = %s", (IP,))
    conn.commit()
    cur.close()
    assert session, "sessions was an empty table because nothing ever wrote to it"
    assert session[1] == "active"


# -------------------------------------------------------------- fingerprinting
class _FakeRequest:
    def __init__(self, ua="", lang="en-US,en;q=0.9"):
        self.headers = {"user-agent": ua, "accept-language": lang}


def test_a_fingerprint_is_stable_for_the_same_headers():
    a, _ = web_guard.fingerprint(_FakeRequest("Chrome/141"))
    b, _ = web_guard.fingerprint(_FakeRequest("Chrome/141"))
    assert a == b


def test_a_fingerprint_changes_when_the_device_does():
    a, _ = web_guard.fingerprint(_FakeRequest("Chrome/141"))
    b, _ = web_guard.fingerprint(_FakeRequest("Chrome/142"))
    c, _ = web_guard.fingerprint(_FakeRequest("Chrome/141", lang="de-DE"))
    assert len({a, b, c}) == 3


def test_a_request_with_no_headers_at_all_still_fingerprints():
    fp, summary = web_guard.fingerprint(_FakeRequest(""))
    assert fp and summary == "no user agent"


def test_the_device_summary_is_readable():
    cases = {
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141.0.0.0 Safari/537.36":
            ("Chrome 141", "Linux"),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0": ("Firefox 130", "Windows"),
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1": ("Safari", "iPhone"),
        "curl/8.5.0": ("curl 8", ""),
    }
    for ua, (browser, platform) in cases.items():
        summary = web_guard.describe({"user-agent": ua, "accept-language": "en-US"})
        assert browser in summary, (ua, summary)
        if platform:
            assert platform in summary, (ua, summary)


def test_an_unknown_range_falls_back_instead_of_failing():
    """The range arrives from a query string, so it is caller-controlled."""
    for hostile in ("", "nonsense", "1 day'; DROP TABLE ssh_log; --", None):
        label, interval = web_guard.range_interval(hostile)
        assert interval in {v[1] for v in web_guard.RANGES.values()}, interval
        assert label


def test_every_range_the_ui_offers_is_one_the_server_knows():
    import re
    with open("panel.py", encoding="utf-8") as fh:
        markup = fh.read()
    offered = set(re.findall(r'name="sec-range" value="([\w]+)"', markup))
    assert offered, "the scanner found no range control to check"
    assert offered <= set(web_guard.RANGES), offered - set(web_guard.RANGES)


def test_a_hostile_interval_cannot_reach_the_summary_sql():
    """An INTERVAL literal cannot be bound as a parameter, so it is spliced into
    the statement. The reader has to refuse anything that is not an interval."""
    hostile = ["1 day'; DROP TABLE ssh_log; --", "1 day) OR 1=1 --", "", None,
               "9999999 days", "1 day; SELECT 1"]
    for bad in hostile:
        summary = DB.get_login_summary(bad)
        assert set(summary) == {"ssh_success", "ssh_failed", "web_success",
                                "web_failed", "active_sessions", "blocked_ips",
                                "blocked_devices"}, summary
    # The table the injection attempt named is still there.
    assert DB.get_login_summary("1 day")["ssh_success"] >= 0


def test_every_interval_web_guard_offers_is_one_the_reader_accepts():
    for _label, interval in web_guard.RANGES.values():
        assert DB._INTERVAL_SHAPE.match(interval), interval
