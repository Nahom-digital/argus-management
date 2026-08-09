# Host firewall control: blocking single addresses, and allowing ports in and
# out. Presented in the panel as "Firewall Settings" rather than as ufw, because
# the backend is whichever of ufw, nftables or iptables the box actually has.
#
# Mirrors the shape of the other helper modules here: its own SCHEMA tuple,
# plain functions that take an already-open connection, no pool of its own.
import ipaddress
import re
import shutil
import subprocess

MANAGED_COMMENT = "argus-management"

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS fw_block (
        id          SERIAL PRIMARY KEY,
        ip          VARCHAR(64) UNIQUE NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        source      VARCHAR(32) NOT NULL DEFAULT 'manual',
        applied     BOOLEAN NOT NULL DEFAULT FALSE,
        detail      TEXT NOT NULL DEFAULT '',
        created_by  VARCHAR(100) NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX IF NOT EXISTS idx_fw_block_ip ON fw_block(ip)",
    """CREATE TABLE IF NOT EXISTS fw_rule (
        id          SERIAL PRIMARY KEY,
        port        INTEGER NOT NULL,
        protocol    VARCHAR(8) NOT NULL DEFAULT 'tcp',
        direction   VARCHAR(8) NOT NULL DEFAULT 'in',
        enabled     BOOLEAN NOT NULL DEFAULT TRUE,
        note        TEXT NOT NULL DEFAULT '',
        auto        BOOLEAN NOT NULL DEFAULT FALSE,
        created_by  VARCHAR(100) NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (port, protocol, direction)
    )""",
)

PROTOCOLS = ("tcp", "udp")
DIRECTIONS = ("in", "out")

_schema_ready = False


def ensure_tables(conn, force=False):
    global _schema_ready
    if _schema_ready and not force:
        return
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    cur.close()
    _schema_ready = True


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------
def _have(binary):
    return shutil.which(binary) is not None


def backend():
    """Which tool will be used. ufw is preferred when it is actually enabled,
    because writing iptables rules underneath an active ufw is how you end up
    with rules that vanish on the next reload."""
    if _have("ufw") and ufw_active():
        return "ufw"
    if _have("iptables"):
        return "iptables"
    if _have("nft"):
        return "nft"
    return None


def ufw_active():
    if not _have("ufw"):
        return False
    r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    return r.returncode == 0 and "Status: active" in r.stdout


def status():
    return {"backend": backend(), "ufw_installed": _have("ufw"),
            "ufw_active": ufw_active(), "iptables": _have("iptables")}


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:400]


# ---------------------------------------------------------------------------
# Blocking single addresses
# ---------------------------------------------------------------------------
def apply_block(ip):
    """Drop all traffic from one address. Idempotent. Returns (ok, detail)."""
    if not valid_ip(ip):
        return False, "not an IP address"
    kind = backend()
    if kind is None:
        return False, "no firewall tool available on this host"

    if kind == "ufw":
        # ufw refuses duplicates itself, so a repeat is harmless.
        return _run(["ufw", "insert", "1", "deny", "from", ip, "comment", MANAGED_COMMENT])

    family = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
    if kind == "nft" and not _have(family):
        return _run(["nft", "add", "rule", "inet", "filter", "input",
                     "ip", "saddr", ip, "drop"])
    check = subprocess.run(
        [family, "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
    if check.returncode == 0:
        return True, "already blocked"
    return _run([family, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])


def remove_block(ip):
    if not valid_ip(ip):
        return False, "not an IP address"
    kind = backend()
    if kind is None:
        return False, "no firewall tool available on this host"
    if kind == "ufw":
        return _run(["ufw", "delete", "deny", "from", ip])
    family = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
    ok, detail = _run([family, "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if not ok and "No chain/target/match" in detail:
        return True, "was not blocked"
    return ok, detail


def block_ip(conn, ip, reason="", source="manual", created_by=""):
    """Record the block and push it to the firewall. The record is written
    either way, so a host without a firewall tool still shows the operator's
    intent and can be reconciled later."""
    ensure_tables(conn)
    if not valid_ip(ip):
        raise ValueError("that is not an IP address")
    ok, detail = apply_block(ip)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO fw_block (ip, reason, source, applied, detail, created_by)
           VALUES (%s, %s, %s, %s, %s, %s)
           ON CONFLICT (ip) DO UPDATE SET
             reason = EXCLUDED.reason, source = EXCLUDED.source,
             applied = EXCLUDED.applied, detail = EXCLUDED.detail""",
        (ip, reason, source, ok, detail, created_by),
    )
    conn.commit()
    cur.close()
    return ok, detail


def unblock_ip(conn, ip):
    ensure_tables(conn)
    ok, detail = remove_block(ip)
    cur = conn.cursor()
    cur.execute("DELETE FROM fw_block WHERE ip = %s", (ip,))
    conn.commit()
    cur.close()
    return ok, detail


def is_blocked(conn, ip):
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM fw_block WHERE ip = %s", (ip,))
    found = cur.fetchone() is not None
    cur.close()
    return found


def list_blocks(conn):
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT ip, reason, source, applied, detail, created_by, created_at
           FROM fw_block ORDER BY created_at DESC"""
    )
    rows = cur.fetchall()
    cur.close()
    return [{"ip": r[0], "reason": r[1], "source": r[2], "applied": r[3],
             "detail": r[4], "created_by": r[5],
             "created_at": r[6].isoformat() if r[6] else None} for r in rows]


# ---------------------------------------------------------------------------
# Port rules
# ---------------------------------------------------------------------------
def _rule_problem(port, protocol, direction):
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return "Port must be a number between 1 and 65535."
    if protocol not in PROTOCOLS:
        return "Protocol must be tcp or udp."
    if direction not in DIRECTIONS:
        return "Direction must be in or out."
    return ""


def apply_rule(port, protocol, direction, enabled):
    """Allow or stop allowing one port. Returns (ok, detail)."""
    problem = _rule_problem(port, protocol, direction)
    if problem:
        return False, problem
    kind = backend()
    if kind is None:
        return False, "no firewall tool available on this host"

    if kind == "ufw":
        verb = "allow" if enabled else "delete"
        target = f"{port}/{protocol}"
        if direction == "out":
            cmd = (["ufw", "allow", "out", target] if enabled
                   else ["ufw", "delete", "allow", "out", target])
        else:
            cmd = ["ufw", "allow", target] if enabled else ["ufw", "delete", "allow", target]
        ok, detail = _run(cmd)
        if not ok and not enabled and "Could not delete" in detail:
            return True, "rule was not present"
        return ok, detail

    chain = "INPUT" if direction == "in" else "OUTPUT"
    flag = "--dport" if direction == "in" else "--dport"
    rule = ["-p", protocol, flag, str(port), "-j", "ACCEPT"]
    if enabled:
        if subprocess.run(["iptables", "-C", chain] + rule,
                          capture_output=True).returncode == 0:
            return True, "already allowed"
        return _run(["iptables", "-I", chain, "1"] + rule)
    ok, detail = _run(["iptables", "-D", chain] + rule)
    if not ok and "No chain/target/match" in detail:
        return True, "rule was not present"
    return ok, detail


def set_rule(conn, port, protocol="tcp", direction="in", enabled=True,
             note="", auto=False, created_by=""):
    ensure_tables(conn)
    problem = _rule_problem(port, protocol, direction)
    if problem:
        raise ValueError(problem)
    ok, detail = apply_rule(port, protocol, direction, enabled)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO fw_rule (port, protocol, direction, enabled, note, auto, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT (port, protocol, direction) DO UPDATE SET
             enabled = EXCLUDED.enabled,
             note = CASE WHEN EXCLUDED.note = '' THEN fw_rule.note ELSE EXCLUDED.note END,
             auto = fw_rule.auto OR EXCLUDED.auto""",
        (port, protocol, direction, bool(enabled), note, bool(auto), created_by),
    )
    conn.commit()
    cur.close()
    return ok, detail


def delete_rule(conn, port, protocol, direction):
    ensure_tables(conn)
    apply_rule(port, protocol, direction, False)
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM fw_rule WHERE port = %s AND protocol = %s AND direction = %s",
        (port, protocol, direction),
    )
    conn.commit()
    cur.close()
    return True


def list_rules(conn):
    ensure_tables(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT port, protocol, direction, enabled, note, auto, created_by, created_at
           FROM fw_rule ORDER BY direction, port, protocol"""
    )
    rows = cur.fetchall()
    cur.close()
    return [{"port": r[0], "protocol": r[1], "direction": r[2], "enabled": r[3],
             "note": r[4], "auto": r[5], "created_by": r[6],
             "created_at": r[7].isoformat() if r[7] else None} for r in rows]


def allow_proxy_port(conn, port, domain, created_by=""):
    """Called when a proxy host is created, so its port is reachable without
    the operator having to remember a second step. Marked auto so the interface
    can show why the rule exists."""
    try:
        return set_rule(conn, int(port), "tcp", "in", True,
                        note=f"opened for {domain}", auto=True, created_by=created_by)
    except (ValueError, TypeError) as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Automatic blocking after repeated SSH failures
# ---------------------------------------------------------------------------
SSH_FAIL_LIMIT = 5
SSH_FAIL_WINDOW_MINUTES = 60

# Addresses that must never be auto-blocked, however they behave. Locking the
# operator out of their own box because a script mistyped a password five times
# is worse than the attack being defended against.
NEVER_BLOCK = ("127.0.0.1", "::1")


def _is_local(ip):
    if ip in NEVER_BLOCK:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True          # unparseable, so not something to act on
    return addr.is_loopback or addr.is_link_local


def ssh_offenders(conn, limit=SSH_FAIL_LIMIT, minutes=SSH_FAIL_WINDOW_MINUTES):
    """Addresses with at least `limit` failed SSH attempts in the window and no
    success in it. A source that eventually authenticated is a person getting
    their password wrong, not an attacker."""
    cur = conn.cursor()
    cur.execute(
        """SELECT ip,
                  COUNT(*) FILTER (WHERE event_type = 'FAILED')  AS failures,
                  COUNT(*) FILTER (WHERE event_type = 'ACCEPTED') AS successes,
                  MAX(ts) AS last_seen
             FROM ssh_log
            WHERE ip IS NOT NULL
              AND ts >= now() - make_interval(mins => %s)
            GROUP BY ip
           HAVING COUNT(*) FILTER (WHERE event_type = 'FAILED') >= %s
              AND COUNT(*) FILTER (WHERE event_type = 'ACCEPTED') = 0
            ORDER BY failures DESC""",
        (minutes, limit),
    )
    rows = cur.fetchall()
    cur.close()
    return [{"ip": r[0], "failures": r[1], "successes": r[2],
             "last_seen": r[3].isoformat() if r[3] else None}
            for r in rows if not _is_local(r[0])]


def enforce_ssh_autoblock(conn, limit=SSH_FAIL_LIMIT, minutes=SSH_FAIL_WINDOW_MINUTES):
    """Block every address over the threshold that is not blocked already.
    Returns the list of addresses newly blocked."""
    ensure_tables(conn)
    blocked = []
    for offender in ssh_offenders(conn, limit, minutes):
        if is_blocked(conn, offender["ip"]):
            continue
        ok, detail = block_ip(
            conn, offender["ip"],
            reason=f"{offender['failures']} failed SSH attempts in {minutes} minutes",
            source="ssh-auto",
        )
        blocked.append({"ip": offender["ip"], "failures": offender["failures"],
                        "applied": ok, "detail": detail})
    return blocked
