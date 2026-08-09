# Staff accounts the primary admin can create: their own login, and a
# permission set (terminal, database, logs, disk) narrower than the admin's.
# Mirrors recovery.py's shape: its own SCHEMA tuple, plain functions that
# take an already-open connection, no pool of its own.
import collections
import hmac
import json
import re
import subprocess

import recovery

TERMINAL_NONE = "none"
TERMINAL_LIMITED = "limited"
TERMINAL_ROOT = "root"
TERMINAL_LEVELS = (TERMINAL_NONE, TERMINAL_LIMITED, TERMINAL_ROOT)

DISK_NONE = "none"
DISK_OWN = "own"
DISK_FULL = "full"
DISK_SCOPES = (DISK_NONE, DISK_OWN, DISK_FULL)

# ---------------------------------------------------------------------------
# The grant registry.
#
# This tuple is the only place a permission is defined. It drives storage
# defaults, payload validation, what resolve_permissions() hands the request
# path, and the form the admin fills in. Generating the form from the same
# definition the enforcement reads is what makes it impossible to ship a
# checkbox no endpoint honours, or an endpoint no checkbox exposes.
#
# Adding a permission means adding a line here and one check at its endpoint.
# ---------------------------------------------------------------------------
Grant = collections.namedtuple("Grant", "key kind choices default group label help")

PERMISSIONS = (
    Grant("terminal", "choice", TERMINAL_LEVELS, TERMINAL_NONE, "terminal",
          "Terminal access",
          "None, a locked-down shell as their own system user, or full root."),

    Grant("disk_scope", "choice", DISK_SCOPES, DISK_NONE, "disk",
          "Files they can reach",
          "Nothing, only their own home directory, or the whole filesystem."),
    Grant("disk_download", "bool", None, False, "disk",
          "Download files", "Copy files off the server."),
    Grant("disk_delete", "bool", None, False, "disk",
          "Delete files", "Remove files permanently. There is no undo."),

    Grant("db_read", "bool", None, False, "database",
          "Read tables", "Browse the rows in this panel's tables."),
    Grant("db_write", "bool", None, False, "database",
          "Change rows", "Insert, edit and delete rows, and add columns."),
    Grant("db_log", "bool", None, False, "database",
          "View change log", "See who changed which row, and when."),

    Grant("net_detail", "bool", None, False, "network",
          "Network detail", "Open the active connection list in the Server section."),
    Grant("net_proxy", "bool", None, False, "network",
          "Manage proxy hosts", "Create and edit reverse proxy hosts."),

    Grant("cpumem_detail", "bool", None, False, "compute",
          "CPU and memory detail",
          "Open the top-process lists behind the CPU and memory meters."),

    Grant("svc_status", "bool", None, False, "services",
          "See service status", "List services and read whether they are running."),
    Grant("svc_restart", "bool", None, False, "services",
          "Start and restart", "Bring a service back up."),
    Grant("svc_stop", "bool", None, False, "services",
          "Stop services", "Take a running service down."),

    Grant("logs_access", "bool", None, False, "logs",
          "Logs section", "Open the Logs tab and everything that reads from it."),
)

GRANT_KEYS = frozenset(g.key for g in PERMISSIONS)
_BY_KEY = {g.key: g for g in PERMISSIONS}
CHOICE_KEYS = frozenset(g.key for g in PERMISSIONS if g.kind == "choice")

GROUP_ORDER = ("terminal", "disk", "database", "network", "compute", "services", "logs")
GROUP_LABELS = {
    "terminal": "Terminal", "disk": "Disk", "database": "Database",
    "network": "Network", "compute": "CPU and memory", "services": "Services",
    "logs": "Logs",
}

_TRUTHY = ("1", "true", "yes", "on")


def normalize_grants(raw):
    """Exactly one entry per registry key and nothing else.

    Anything unrecognized, mistyped or out of range collapses to that grant's
    default, so a hostile payload can only ever ask for less than it sent.
    Callers must run every inbound grant dict through this before storing it.
    """
    if not isinstance(raw, dict):
        raw = {}
    out = {}
    for g in PERMISSIONS:
        value = raw.get(g.key, g.default)
        if g.kind == "choice":
            out[g.key] = value if value in g.choices else g.default
        elif isinstance(value, str):
            out[g.key] = value.strip().lower() in _TRUTHY
        else:
            out[g.key] = bool(value)
    return out


def all_grants(enabled=True):
    """Every grant at its widest setting, used for the admin identity so a
    newly added permission is never accidentally withheld from the admin."""
    out = {}
    for g in PERMISSIONS:
        if g.kind == "choice":
            out[g.key] = g.choices[-1] if enabled else g.default
        else:
            out[g.key] = bool(enabled)
    return out


def describe_grants():
    """The registry as JSON for the admin form. Ordered by group so the form
    renders in a stable, meaningful sequence."""
    order = {name: i for i, name in enumerate(GROUP_ORDER)}
    # Stable sort, so registry order survives inside each group. That keeps
    # disk_scope ahead of the download and delete switches it governs.
    ordered = sorted(PERMISSIONS, key=lambda g: order.get(g.group, 99))
    return [
        {
            "key": g.key, "kind": g.kind,
            "choices": list(g.choices) if g.choices else None,
            "default": g.default, "group": g.group,
            "label": g.label, "help": g.help,
        }
        for g in ordered
    ]


def grant_groups():
    """Group identifiers with their display labels, in render order."""
    return [{"key": k, "label": GROUP_LABELS[k]} for k in GROUP_ORDER]

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS panel_user (
        id               SERIAL PRIMARY KEY,
        username         VARCHAR(100) UNIQUE NOT NULL,
        password_hash    TEXT NOT NULL,
        terminal_access  VARCHAR(16) NOT NULL DEFAULT 'none',
        os_username      VARCHAR(64),
        database_access  BOOLEAN NOT NULL DEFAULT FALSE,
        logs_access      BOOLEAN NOT NULL DEFAULT FALSE,
        disk_access      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_by       VARCHAR(100) NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS idx_panel_user_username ON panel_user(username)",
)


def ensure_table(conn):
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    cur.close()


def _os_username_for(username):
    safe = re.sub(r"[^a-z0-9]", "", username.lower())[:20] or "user"
    return f"argus_{safe}"[:32]


def os_account_exists(os_username):
    return subprocess.run(["id", os_username], capture_output=True).returncode == 0


def provision_os_account(os_username):
    """Create a login-locked OS account used only as a privilege-drop target
    for restricted terminal sessions: no password, no SSH key, reachable
    only by this process setuid-ing into it after already being root."""
    if os_account_exists(os_username):
        return True, ""
    r = subprocess.run(
        ["useradd", "-m", "-s", "/bin/bash", os_username],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False, r.stderr.strip()
    return True, ""


def deprovision_os_account(os_username):
    if not os_username or not os_account_exists(os_username):
        return
    subprocess.run(["userdel", "-r", os_username], capture_output=True, text=True)


def create_user(conn, username, password, terminal_access, database_access,
                 logs_access, disk_access, created_by):
    ensure_table(conn)
    username = (username or "").strip()
    if terminal_access not in TERMINAL_LEVELS:
        terminal_access = TERMINAL_NONE

    os_username = None
    if terminal_access == TERMINAL_LIMITED:
        os_username = _os_username_for(username)
        ok, err = provision_os_account(os_username)
        if not ok:
            raise RuntimeError(f"could not create system account: {err}")

    cur = conn.cursor()
    cur.execute(
        """INSERT INTO panel_user
           (username, password_hash, terminal_access, os_username,
            database_access, logs_access, disk_access, created_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (username, recovery.hash_password(password), terminal_access, os_username,
         bool(database_access), bool(logs_access), bool(disk_access), created_by),
    )
    conn.commit()
    cur.close()
    return os_username


def list_users(conn):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT username, terminal_access, os_username, database_access,
                  logs_access, disk_access, created_at, created_by
           FROM panel_user ORDER BY created_at ASC"""
    )
    rows = cur.fetchall()
    cur.close()
    return [
        {
            "username": r[0], "terminal_access": r[1], "os_username": r[2],
            "database_access": r[3], "logs_access": r[4], "disk_access": r[5],
            "created_at": r[6].isoformat() if r[6] else None, "created_by": r[7],
        }
        for r in rows
    ]


def get_user(conn, username):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT username, password_hash, terminal_access, os_username,
                  database_access, logs_access, disk_access
           FROM panel_user WHERE username = %s""",
        (username,),
    )
    row = cur.fetchone()
    cur.close()
    if not row:
        return None
    return {
        "username": row[0], "password_hash": row[1], "terminal_access": row[2],
        "os_username": row[3], "database_access": row[4], "logs_access": row[5],
        "disk_access": row[6],
    }


def verify_login(conn, username, password):
    user = get_user(conn, username)
    if not user:
        return None
    if not hmac.compare_digest(recovery.hash_password(password), user["password_hash"]):
        return None
    return user


def update_permissions(conn, username, terminal_access=None, database_access=None,
                        logs_access=None, disk_access=None):
    user = get_user(conn, username)
    if not user:
        return False

    fields, params = [], []
    if terminal_access is not None and terminal_access in TERMINAL_LEVELS:
        fields.append("terminal_access = %s")
        params.append(terminal_access)
        if terminal_access == TERMINAL_LIMITED and not user["os_username"]:
            os_username = _os_username_for(username)
            ok, err = provision_os_account(os_username)
            if not ok:
                raise RuntimeError(f"could not create system account: {err}")
            fields.append("os_username = %s")
            params.append(os_username)
    if database_access is not None:
        fields.append("database_access = %s")
        params.append(bool(database_access))
    if logs_access is not None:
        fields.append("logs_access = %s")
        params.append(bool(logs_access))
    if disk_access is not None:
        fields.append("disk_access = %s")
        params.append(bool(disk_access))

    if not fields:
        return True
    params.append(username)
    cur = conn.cursor()
    cur.execute(f"UPDATE panel_user SET {', '.join(fields)} WHERE username = %s", params)
    conn.commit()
    cur.close()
    return True


def delete_user(conn, username):
    user = get_user(conn, username)
    if not user:
        return False
    cur = conn.cursor()
    cur.execute("DELETE FROM panel_user WHERE username = %s", (username,))
    conn.commit()
    cur.close()
    if user["os_username"]:
        deprovision_os_account(user["os_username"])
    return True


def resolve_permissions(conn, username):
    """The single source of truth for what a signed-in identity may do.
    The primary admin account is always full-access; a panel_user row
    carries its own narrower grants; anything else gets nothing."""
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM admin WHERE username = %s", (username,))
    is_admin = cur.fetchone() is not None
    cur.close()
    if is_admin:
        return {
            "role": "admin", "terminal_access": TERMINAL_ROOT, "os_username": None,
            "database_write": True, "database_access": True,
            "logs_access": True, "disk_access": True,
        }

    user = get_user(conn, username)
    if not user:
        return {
            "role": "none", "terminal_access": TERMINAL_NONE, "os_username": None,
            "database_write": False, "database_access": False,
            "logs_access": False, "disk_access": False,
        }
    return {
        "role": "staff",
        "terminal_access": user["terminal_access"],
        "os_username": user["os_username"],
        "database_write": False,
        "database_access": bool(user["database_access"]),
        "logs_access": bool(user["logs_access"]),
        "disk_access": bool(user["disk_access"]),
    }
