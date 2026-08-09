"""Firewall records and the SSH auto-block decision.

The decision logic is tested against the real database. Actually pushing rules
into iptables or ufw needs root and mutates the host, so those calls are
exercised only through their validation and their recorded outcome, never by
asserting that a rule landed.
"""
import uuid

import pytest

import firewall

# Every row this module writes carries this tag, so cleanup is exact and a
# second run cannot collide with the first on ssh_log's event_hash index.
TAG = "pytest-fw-" + uuid.uuid4().hex[:8]


@pytest.fixture
def clean(conn):
    firewall.ensure_tables(conn, force=True)
    cur = conn.cursor()
    cur.execute("DELETE FROM fw_block WHERE ip LIKE '203.0.113.%' OR ip LIKE '198.51.100.%'")
    cur.execute("DELETE FROM fw_rule WHERE port BETWEEN 39000 AND 39100")
    cur.execute("DELETE FROM ssh_log WHERE event_hash LIKE 'pytest-fw-%'")
    conn.commit()
    cur.close()
    yield conn
    cur = conn.cursor()
    cur.execute("DELETE FROM fw_block WHERE ip LIKE '203.0.113.%' OR ip LIKE '198.51.100.%'")
    cur.execute("DELETE FROM fw_rule WHERE port BETWEEN 39000 AND 39100")
    cur.execute("DELETE FROM ssh_log WHERE event_hash LIKE 'pytest-fw-%'")
    cur.execute("DELETE FROM fw_block WHERE ip = '127.0.0.1'")
    conn.commit()
    cur.close()


def _log_ssh(conn, ip, event, count=1, minutes_ago=1):
    cur = conn.cursor()
    for i in range(count):
        cur.execute(
            """INSERT INTO ssh_log (event_hash, ts, event_type, ip, username)
               VALUES (%s, now() - make_interval(mins => %s), %s, %s, 'root')""",
            (f"{TAG}-{ip}-{event}-{i}-{minutes_ago}", minutes_ago, event, ip),
        )
    conn.commit()
    cur.close()


def test_a_block_is_recorded_even_when_the_firewall_cannot_apply_it(clean):
    ip = "203.0.113.10"
    firewall.block_ip(clean, ip, reason="testing", source="manual", created_by="admin")
    rows = [b for b in firewall.list_blocks(clean) if b["ip"] == ip]
    assert len(rows) == 1
    assert rows[0]["reason"] == "testing"
    assert firewall.is_blocked(clean, ip)


def test_blocking_twice_updates_rather_than_duplicating(clean):
    ip = "203.0.113.11"
    firewall.block_ip(clean, ip, reason="first", source="manual")
    firewall.block_ip(clean, ip, reason="second", source="ssh-auto")
    rows = [b for b in firewall.list_blocks(clean) if b["ip"] == ip]
    assert len(rows) == 1
    assert rows[0]["reason"] == "second"
    assert rows[0]["source"] == "ssh-auto"


def test_unblocking_removes_the_record(clean):
    ip = "203.0.113.12"
    firewall.block_ip(clean, ip)
    firewall.unblock_ip(clean, ip)
    assert not firewall.is_blocked(clean, ip)


def test_a_bad_address_is_refused(clean):
    for bad in ("", "not-an-ip", "999.1.1.1", "1.1.1.1; rm -rf /", "$(whoami)"):
        with pytest.raises(ValueError):
            firewall.block_ip(clean, bad)


def test_five_failures_makes_an_offender(clean):
    ip = "203.0.113.20"
    _log_ssh(clean, ip, "FAILED", count=5)
    assert ip in [o["ip"] for o in firewall.ssh_offenders(clean)]


def test_four_failures_is_not_enough(clean):
    ip = "203.0.113.21"
    _log_ssh(clean, ip, "FAILED", count=4)
    assert ip not in [o["ip"] for o in firewall.ssh_offenders(clean)]


def test_an_eventual_success_means_it_was_a_person_not_an_attacker(clean):
    ip = "203.0.113.22"
    _log_ssh(clean, ip, "FAILED", count=6)
    _log_ssh(clean, ip, "ACCEPTED", count=1)
    assert ip not in [o["ip"] for o in firewall.ssh_offenders(clean)], \
        "a source that authenticated must not be auto-blocked"


def test_failures_outside_the_window_are_forgiven(clean):
    ip = "203.0.113.23"
    _log_ssh(clean, ip, "FAILED", count=9, minutes_ago=600)
    assert ip not in [o["ip"] for o in firewall.ssh_offenders(clean)]


def test_loopback_is_never_auto_blocked(clean):
    _log_ssh(clean, "127.0.0.1", "FAILED", count=20)
    offenders = [o["ip"] for o in firewall.ssh_offenders(clean)]
    assert "127.0.0.1" not in offenders, \
        "auto-blocking loopback would lock the operator out of their own box"


def test_enforcing_blocks_the_offender_once(clean):
    ip = "203.0.113.24"
    _log_ssh(clean, ip, "FAILED", count=7)
    first = firewall.enforce_ssh_autoblock(clean)
    assert ip in [b["ip"] for b in first]
    assert firewall.is_blocked(clean, ip)
    # A second pass must not report it again, or the activity log fills up.
    second = firewall.enforce_ssh_autoblock(clean)
    assert ip not in [b["ip"] for b in second]


def test_port_rules_validate_before_touching_the_host(clean):
    for port, proto, direction in [(0, "tcp", "in"), (70000, "tcp", "in"),
                                   (39001, "sctp", "in"), (39001, "tcp", "sideways")]:
        with pytest.raises(ValueError):
            firewall.set_rule(clean, port, proto, direction, True)


def test_a_port_rule_round_trips(clean):
    firewall.set_rule(clean, 39002, "tcp", "in", True, note="test rule")
    rows = [r for r in firewall.list_rules(clean) if r["port"] == 39002]
    assert len(rows) == 1
    assert rows[0]["enabled"] is True and rows[0]["note"] == "test rule"

    firewall.set_rule(clean, 39002, "tcp", "in", False)
    rows = [r for r in firewall.list_rules(clean) if r["port"] == 39002]
    assert rows[0]["enabled"] is False
    assert rows[0]["note"] == "test rule", "an empty note must not wipe the old one"

    firewall.delete_rule(clean, 39002, "tcp", "in")
    assert not [r for r in firewall.list_rules(clean) if r["port"] == 39002]


def test_the_same_port_can_differ_by_direction(clean):
    firewall.set_rule(clean, 39003, "tcp", "in", True)
    firewall.set_rule(clean, 39003, "tcp", "out", False)
    rows = {r["direction"]: r for r in firewall.list_rules(clean) if r["port"] == 39003}
    assert rows["in"]["enabled"] is True
    assert rows["out"]["enabled"] is False


def test_a_proxy_port_is_marked_automatic(clean):
    firewall.allow_proxy_port(clean, 39004, "example.test", created_by="admin")
    row = next(r for r in firewall.list_rules(clean) if r["port"] == 39004)
    assert row["auto"] is True
    assert "example.test" in row["note"]


def test_status_reports_which_backend_would_be_used():
    st = firewall.status()
    assert set(st) == {"backend", "ufw_installed", "ufw_active", "iptables"}
    assert st["backend"] in (None, "ufw", "iptables", "nft")
