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
        elif isinstance(value, bool):
            out[g.key] = value
        elif isinstance(value, str):
            out[g.key] = value.strip().lower() in _TRUTHY
        elif isinstance(value, (int, float)):
            out[g.key] = value != 0
        else:
            # A dict or a list arriving where a boolean belongs is malformed,
            # not permission. Python would call a non-empty one truthy, so it
            # collapses to the default instead of being trusted.
            out[g.key] = bool(g.default)
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
    # Permission model v2. The four legacy grant columns above are left in
    # place and are no longer read. Rows created from here on leave them at
    # their defaults, so rolling the code back removes access rather than
    # granting it by accident.
    "ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS grants JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS auth_epoch INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE panel_user ADD COLUMN IF NOT EXISTS full_name VARCHAR(120)",
)

# A row written before v2 has an empty grants object. New rows always store a
# full normalized set, so an empty object is an unambiguous "not migrated yet".
_BACKFILL_SENTINEL = "SELECT username, terminal_access, database_access, logs_access, " \
                     "disk_access FROM panel_user WHERE grants = '{}'::jsonb"


def _backfill_legacy_grants(conn):
    """Translate pre-v2 rows into the registry, once.

    Deliberately conservative: disk_access became browse plus download, never
    delete, and database_access became read, never write. Nobody gains a
    destructive permission from a migration they did not ask for.
    """
    cur = conn.cursor()
    cur.execute(_BACKFILL_SENTINEL)
    rows = cur.fetchall()
    for username, terminal_access, database_access, logs_access, disk_access in rows:
        grants = normalize_grants({
            "terminal": terminal_access,
            "db_read": bool(database_access),
            "logs_access": bool(logs_access),
            "disk_scope": DISK_FULL if disk_access else DISK_NONE,
            "disk_download": bool(disk_access),
            "disk_delete": False,
        })
        cur.execute("UPDATE panel_user SET grants = %s WHERE username = %s",
                    (json.dumps(grants), username))
    if rows:
        conn.commit()
    cur.close()
    return len(rows)


_schema_ready = False


def ensure_table(conn, force=False):
    """Idempotent, and after the first call in a process it is free.

    get_user() calls this on every lookup, so without the guard every
    permission check would replay eight DDL statements and a backfill scan.
    """
    global _schema_ready
    if _schema_ready and not force:
        return
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    cur.close()
    _backfill_legacy_grants(conn)
    _schema_ready = True


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


def is_admin_username(conn, username):
    """Whether this name belongs to the primary admin account.

    resolve_permissions() checks the admin table first and returns every grant
    for a match. So a staff row sharing that name would be resolved as the
    admin, which is why creation refuses it and verify_login refuses it.
    """
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM admin WHERE username = %s", (username,))
    found = cur.fetchone() is not None
    cur.close()
    return found


def needs_os_account(grants):
    """A real system account is required both for a locked-down shell and for
    a home directory to sandbox file access into."""
    return grants.get("terminal") == TERMINAL_LIMITED or grants.get("disk_scope") == DISK_OWN


def create_user(conn, username, password, grants, created_by):
    ensure_table(conn)
    username = (username or "").strip()
    if is_admin_username(conn, username):
        raise ValueError("that name belongs to the admin account, pick another")
    grants = normalize_grants(grants)

    os_username = None
    if needs_os_account(grants):
        os_username = _os_username_for(username)
        ok, err = provision_os_account(os_username)
        if not ok:
            raise RuntimeError(f"could not create system account: {err}")

    cur = conn.cursor()
    cur.execute(
        """INSERT INTO panel_user
           (username, password_hash, os_username, grants, created_by)
           VALUES (%s, %s, %s, %s, %s)""",
        (username, recovery.hash_password(password), os_username,
         json.dumps(grants), created_by),
    )
    conn.commit()
    cur.close()
    return os_username


def list_users(conn):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT username, os_username, grants, full_name, auth_epoch,
                  created_at, created_by
           FROM panel_user ORDER BY created_at ASC"""
    )
    rows = cur.fetchall()
    cur.close()
    return [
        {
            "username": r[0], "os_username": r[1],
            "grants": normalize_grants(r[2]), "full_name": r[3] or "",
            "auth_epoch": r[4],
            "created_at": r[5].isoformat() if r[5] else None, "created_by": r[6],
        }
        for r in rows
    ]


def get_user(conn, username):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT username, password_hash, os_username, grants, full_name,
                  auth_epoch
           FROM panel_user WHERE username = %s""",
        (username,),
    )
    row = cur.fetchone()
    cur.close()
    if not row:
        return None
    return {
        "username": row[0], "password_hash": row[1], "os_username": row[2],
        "grants": normalize_grants(row[3]), "full_name": row[4] or "",
        "auth_epoch": row[5],
    }


# Comparing against this when the account does not exist keeps a miss and a
# wrong password costing the same work, so response time does not disclose
# which usernames are real.
_ABSENT_HASH = recovery.hash_password("\x00 no such account \x00")


def verify_login(conn, username, password):
    candidate = recovery.hash_password(password)
    # Closes the escalation even for a row created before create_user started
    # refusing the name: a staff row called "admin" would otherwise sign in
    # here and then resolve to full admin permissions.
    if is_admin_username(conn, username):
        hmac.compare_digest(candidate, _ABSENT_HASH)
        return None
    user = get_user(conn, username)
    if not user:
        hmac.compare_digest(candidate, _ABSENT_HASH)
        return None
    if not hmac.compare_digest(candidate, user["password_hash"]):
        return None
    return user


def auth_epoch_for(conn, username):
    """The session generation for one identity. A token minted before the
    current value is stale and must be rejected."""
    cur = conn.cursor()
    cur.execute("SELECT auth_epoch FROM panel_user WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    return int(row[0]) if row else 0


def _is_narrowing(old, new):
    """True when the new grant set takes anything away. Widening a grant set
    is safe for a live session; taking something away is not, so only the
    narrowing case forces a re-login."""
    for g in PERMISSIONS:
        before, after = old.get(g.key), new.get(g.key)
        if g.kind == "choice":
            if g.choices.index(after) < g.choices.index(before):
                return True
        elif before and not after:
            return True
    return False


def update_user(conn, username, grants=None, password=None, full_name=None):
    """Edit a staff account in one place: their grants, their password, their
    display name, or any combination. Grants are replaced wholesale rather
    than merged, so the form the admin submits is exactly what is stored and
    an unchecked box always means revoked."""
    user = get_user(conn, username)
    if not user:
        return False

    fields, params = [], []
    revoke_sessions = False

    if grants is not None:
        new_grants = normalize_grants(grants)
        if _is_narrowing(user["grants"], new_grants):
            revoke_sessions = True
        if needs_os_account(new_grants) and not user["os_username"]:
            os_username = _os_username_for(username)
            ok, err = provision_os_account(os_username)
            if not ok:
                raise RuntimeError(f"could not create system account: {err}")
            fields.append("os_username = %s")
            params.append(os_username)
        fields.append("grants = %s")
        params.append(json.dumps(new_grants))

    if password is not None:
        fields.append("password_hash = %s")
        params.append(recovery.hash_password(password))
        revoke_sessions = True

    if full_name is not None:
        fields.append("full_name = %s")
        params.append(full_name.strip()[:120])

    if not fields:
        return True
    if revoke_sessions:
        fields.append("auth_epoch = auth_epoch + 1")

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

    Every grant key sits at the top level of the returned dict, so a request
    handler asks perms["db_write"] and never has to know how it was stored.
    The primary admin is always every grant at its widest, computed from the
    registry rather than written out, so adding a permission can never
    accidentally withhold it from the admin.
    """
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM admin WHERE username = %s", (username,))
    is_admin = cur.fetchone() is not None
    cur.close()
    if is_admin:
        out = {"role": "admin", "username": username, "os_username": None,
               "full_name": "", "auth_epoch": 0}
        out.update(all_grants(True))
        return out

    user = get_user(conn, username)
    if not user:
        out = {"role": "none", "username": username, "os_username": None,
               "full_name": "", "auth_epoch": 0}
        out.update(all_grants(False))
        return out

    out = {"role": "staff", "username": user["username"],
           "os_username": user["os_username"], "full_name": user["full_name"],
           "auth_epoch": user["auth_epoch"]}
    out.update(user["grants"])
    return out


def no_permissions(username=""):
    """What an unauthenticated request resolves to. Kept here so the deny-all
    shape is derived from the registry too, never hand-maintained."""
    out = {"role": "none", "username": username, "os_username": None,
           "full_name": "", "auth_epoch": 0}
    out.update(all_grants(False))
    return out
