import os
import re
import logging
import json
import uuid
import secrets
import string
import hashlib
import asyncio
import functools
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import psycopg2
from psycopg2 import sql, pool as _pgpool

STARTUP_MESSAGE = "Mock Database connection established."

# --- .env loader (no third-party dependency) ---
# Secrets live in the .env file next to this module, not in source. Real
# environment variables, if already set, win, so containers/systemd can still
# override without editing the file.
def _load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception as e:
        logging.warning(f".env load failed: {e}")

_load_dotenv()
DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "elink"),
    "user": os.environ.get("DB_USER", "elink"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "host": os.environ.get("DB_HOST", "127.0.0.1"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}

_POOL_MIN = 2

_POOL_MAX = 32          # < Postgres max_connections (100); headroom for >1 worker

_CONN_POOL = None

_POOL_LOCK = threading.Lock()

def _get_pool():
    global _CONN_POOL
    if _CONN_POOL is None:
        with _POOL_LOCK:
            if _CONN_POOL is None:   # double-checked: build exactly one pool under concurrency
                _CONN_POOL = _pgpool.ThreadedConnectionPool(_POOL_MIN, _POOL_MAX, **DB_CONFIG)
    return _CONN_POOL

def init_pool():
    """Warm the pool eagerly at startup so the first request never pays the
    connect+auth latency and the lazy-init race can never happen under load."""
    _get_pool()

def close_pool():
    """Close every pooled connection on graceful shutdown."""
    global _CONN_POOL
    with _POOL_LOCK:
        if _CONN_POOL is not None:
            try:
                _CONN_POOL.closeall()
            finally:
                _CONN_POOL = None

def get_connection():
    conn = _get_pool().getconn()
    conn.autocommit = True
    return conn

def release_connection(conn):
    try:
        _get_pool().putconn(conn)
    except Exception:
        pass

_DB_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="db")

async def run(fn, *args, **kwargs):
    """Offload a synchronous DB call off the event loop:
        user = await DB.run(DB.get_user, tid)
    Keeps the exact semantics of calling fn(*args, **kwargs) directly."""
    loop = asyncio.get_running_loop()
    call = fn if not kwargs else functools.partial(fn, **kwargs)
    return await loop.run_in_executor(_DB_EXECUTOR, call, *args)

def _hash_pw(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"botcontrol", 260000).hex()

def ensure_admin_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM admin")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO admin (username, password_hash) VALUES (%s, %s)",
            ("admin", _hash_pw("admin"))
        )
        conn.commit()
    # Ensure response column exists on start_users
    cur.execute("ALTER TABLE IF EXISTS start_users ADD COLUMN IF NOT EXISTS response TEXT DEFAULT ''")
    conn.commit()
    cur.close()
    release_connection(conn)

def verify_admin(username: str, password: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM admin WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    return row is not None and row[0] == _hash_pw(password)

def update_admin_credentials(new_username: str, new_password: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE admin SET username = %s, password_hash = %s",
        (new_username, _hash_pw(new_password))
    )
    updated = cur.rowcount > 0
    conn.commit()
    cur.close()
    release_connection(conn)
    return updated

def get_table_list():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
    tables = [row[0] for row in cur.fetchall()]
    cur.close()
    release_connection(conn)
    return tables

def get_table_count(table_name: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
    count = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return count

def get_table_page(table_name: str, page: int, rows_per_page: int = 10):
    offset = (page - 1) * rows_per_page
    conn = get_connection()
    cur = conn.cursor()
    # ORDER BY 1: first column is the serial PK in every table ('orders' uses order_id, not id)
    query = sql.SQL("SELECT * FROM {} ORDER BY 1 DESC LIMIT %s OFFSET %s").format(sql.Identifier(table_name))
    cur.execute(query, (rows_per_page, offset))
    rows = cur.fetchall()
    col_names = [desc[0] for desc in cur.description]
    cur.close()
    release_connection(conn)
    return {"columns": col_names, "rows": rows}

def _p2p_trace(action, data):
    logging.info(f"__TRACE__{json.dumps({'src': 'DB.py', 'dest': 'bot.py', 'action': action, 'data': data}, default=str)}")

def _rows_to_dicts(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def admin_log(admin_username, action_type, target_tid=None, ip_address=None, notes=""):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO admin_action (admin_username, action_type, target_tid, ip_address, notes) VALUES (%s, %s, %s, %s, %s)",
        (admin_username, action_type, str(target_tid) if target_tid else None, ip_address, notes)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Audit Log", {"admin": admin_username, "action": action_type, "tid": str(target_tid), "notes": notes})

def get_audit_log(page=1, limit=100):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM admin_action ORDER BY id DESC LIMIT %s OFFSET %s", (limit, (page - 1) * limit))
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def get_setting(key, default=None):
    """Generic system_settings reader (key/value). Used for runtime bot config
    (bot_token, base_webhook_url, webhook_secret) so credential changes persist
    across restarts WITHOUT rewriting source files."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM system_settings WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    return row[0] if row else default

def set_setting(key, value):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO system_settings (key, value) VALUES (%s, %s)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP""",
        (key, str(value))
    )
    conn.commit()
    cur.close()
    release_connection(conn)

import string
def ensure_security_log_tables():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ssh_log (
            id SERIAL PRIMARY KEY,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            event_type VARCHAR(32) NOT NULL,
            ip TEXT,
            username TEXT,
            fingerprint TEXT,
            session_pid INTEGER,
            port INTEGER,
            auth_method VARCHAR(20),
            details TEXT
        )
    """)
    # event_hash lets us persist live journald events without duplicating rows
    # across repeated polls (journald is volatile and rotates; this table is not).
    cur.execute("ALTER TABLE IF EXISTS ssh_log ADD COLUMN IF NOT EXISTS event_hash TEXT")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_log_hash ON ssh_log(event_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ssh_log_ts ON ssh_log(ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ssh_log_ip ON ssh_log(ip)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS web_login_log (
            id SERIAL PRIMARY KEY,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip TEXT NOT NULL,
            username TEXT,
            success BOOLEAN NOT NULL,
            user_agent TEXT,
            tried_password TEXT,
            details TEXT
        )
    """)
    cur.execute("ALTER TABLE IF EXISTS web_login_log ADD COLUMN IF NOT EXISTS tried_password TEXT")
    # Rich device fingerprint captured by the login page (browser, version, screen
    # resolution, timezone, device clock, platform, languages, canvas hash, ...).
    cur.execute("ALTER TABLE IF EXISTS web_login_log ADD COLUMN IF NOT EXISTS fp_hash TEXT")
    cur.execute("ALTER TABLE IF EXISTS web_login_log ADD COLUMN IF NOT EXISTS fingerprint TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wll_ts ON web_login_log(ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wll_ip ON web_login_log(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wll_fp ON web_login_log(fp_hash)")
    # Device-level brute-force block list: keyed on the browser/device fingerprint
    # so a blocked attacker can't simply hop to a new IP on the same machine.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS web_fp_block (
            fp_hash TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL DEFAULT 0,
            first_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP,
            last_ip TEXT,
            sample TEXT,
            note TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS web_login_block (
            ip TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL DEFAULT 0,
            first_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP,
            note TEXT
        )
    """)
    cur.execute("ALTER TABLE IF EXISTS web_login_block ADD COLUMN IF NOT EXISTS note TEXT")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS web_session_log (
            id SERIAL PRIMARY KEY,
            session_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            ip TEXT NOT NULL,
            user_agent TEXT,
            login_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            logout_at TIMESTAMP,
            status VARCHAR(16) NOT NULL DEFAULT 'active'
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wsl_session ON web_session_log(session_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wsl_login  ON web_session_log(login_at DESC)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS http_access_log (
            id BIGSERIAL PRIMARY KEY,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip TEXT NOT NULL,
            method VARCHAR(10) NOT NULL,
            path TEXT NOT NULL,
            query TEXT,
            status_code INTEGER NOT NULL,
            duration_ms INTEGER,
            user_agent TEXT,
            referer TEXT,
            authed_user TEXT
        )
    """)
    # Captured response so the operator can click a row and see what the server
    # actually sent back (textual responses only; size-capped, see log_http_request).
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_body TEXT")
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS content_type TEXT")
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_size INTEGER")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_ts   ON http_access_log(ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_ip   ON http_access_log(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_path ON http_access_log(path)")
    conn.commit()
    cur.close()
    release_connection(conn)

_HAL_BODY_CAP = 200_000   # max chars of response body stored per request

def log_http_request(ip: str, method: str, path: str, query: str,
                     status_code: int, duration_ms: int,
                     user_agent: str, referer: str, authed_user: str,
                     response_body: str = None, content_type: str = None,
                     response_size: int = None):
    body = response_body
    if body is not None and len(body) > _HAL_BODY_CAP:
        body = body[:_HAL_BODY_CAP] + f"\n\n… [truncated, {response_size or len(response_body)} bytes total]"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO http_access_log
               (ip, method, path, query, status_code, duration_ms, user_agent, referer,
                authed_user, response_body, content_type, response_size)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (ip, method, path, query or None, status_code, duration_ms,
         user_agent or None, referer or None, authed_user or None,
         body, content_type or None, response_size)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def get_http_access_entry(entry_id: int):
    """Full single access-log row, including the captured response body."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, ts, ip, method, path, query, status_code, duration_ms,
                  user_agent, referer, authed_user, response_body, content_type, response_size
           FROM http_access_log WHERE id = %s""", (entry_id,))
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows[0] if rows else None

def get_http_access_logs(page: int = 1, limit: int = 100,
                         ip_filter: str = "", path_filter: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    where, params = [], []
    if ip_filter:
        where.append("ip ILIKE %s"); params.append(f"%{ip_filter}%")
    if path_filter:
        where.append("path ILIKE %s"); params.append(f"%{path_filter}%")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    cur.execute(
        f"""SELECT id, ts, ip, method, path, query, status_code, duration_ms,
                   user_agent, referer, authed_user, content_type, response_size
            FROM http_access_log {clause}
            ORDER BY id DESC LIMIT %s OFFSET %s""",
        params + [limit, (page - 1) * limit]
    )
    rows = _rows_to_dicts(cur)
    cur.execute(f"SELECT COUNT(*) FROM http_access_log {clause}", params)
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ip) FROM http_access_log")
    unique_ips = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return {"logs": rows, "total": total, "unique_ips": unique_ips}

def get_ip_profile(ip: str):
    """Everything known about a single IP, cross-referenced across every log:
    HTTP access, web-panel logins, active/expired sessions, SSH events and the
    block list. Powers the security dashboard's "click an IP" drill-down so the
    operator sees, in one place, every section the address turned up in."""
    ip = (ip or "").strip()
    conn = get_connection()
    cur = conn.cursor()
    out = {"ip": ip, "summary": {}, "http": {}, "web_logins": {},
           "sessions": [], "ssh": {}, "block": None}
    try:
        # --- HTTP access log ---
        cur.execute(
            """SELECT id, ts, method, path, query, status_code, duration_ms,
                      user_agent, referer, authed_user
               FROM http_access_log WHERE ip = %s ORDER BY id DESC LIMIT 200""",
            (ip,))
        http_rows = _rows_to_dicts(cur)
        cur.execute(
            """SELECT COUNT(*), MIN(ts), MAX(ts),
                      COUNT(DISTINCT path), COUNT(DISTINCT authed_user)
               FROM http_access_log WHERE ip = %s""", (ip,))
        hc = cur.fetchone()
        cur.execute(
            """SELECT path, COUNT(*) c FROM http_access_log WHERE ip = %s
               GROUP BY path ORDER BY c DESC LIMIT 15""", (ip,))
        top_paths = [{"path": r[0], "count": r[1]} for r in cur.fetchall()]
        cur.execute(
            """SELECT DISTINCT authed_user FROM http_access_log
               WHERE ip = %s AND authed_user IS NOT NULL AND authed_user <> ''""",
            (ip,))
        http_users = [r[0] for r in cur.fetchall()]
        out["http"] = {"total": hc[0], "first": str(hc[1]) if hc[1] else None,
                       "last": str(hc[2]) if hc[2] else None,
                       "distinct_paths": hc[3], "distinct_users": hc[4],
                       "top_paths": top_paths, "users": http_users,
                       "recent": http_rows}

        # --- Web-panel login attempts ---
        cur.execute(
            """SELECT id, ts, username, success, user_agent, tried_password, details
               FROM web_login_log WHERE ip = %s ORDER BY id DESC LIMIT 100""",
            (ip,))
        wl_rows = _rows_to_dicts(cur)
        cur.execute(
            """SELECT COUNT(*), COUNT(*) FILTER (WHERE success),
                      COUNT(*) FILTER (WHERE NOT success)
               FROM web_login_log WHERE ip = %s""", (ip,))
        wc = cur.fetchone()
        cur.execute(
            """SELECT DISTINCT username FROM web_login_log
               WHERE ip = %s AND username IS NOT NULL AND username <> ''""", (ip,))
        wl_users = [r[0] for r in cur.fetchall()]
        out["web_logins"] = {"total": wc[0], "success": wc[1], "failed": wc[2],
                             "usernames": wl_users, "recent": wl_rows}

        # --- Web sessions ---
        cur.execute(
            """SELECT session_id, username, user_agent, login_at, expires_at,
                      logout_at, status
               FROM web_session_log WHERE ip = %s ORDER BY login_at DESC LIMIT 100""",
            (ip,))
        out["sessions"] = _rows_to_dicts(cur)

        # --- SSH events (best-effort: table may be empty if only journald is used) ---
        try:
            cur.execute(
                """SELECT id, ts, event_type, username, fingerprint, port,
                          auth_method, details
                   FROM ssh_log WHERE ip = %s ORDER BY id DESC LIMIT 100""", (ip,))
            ssh_rows = _rows_to_dicts(cur)
            cur.execute(
                """SELECT COUNT(*),
                          COUNT(*) FILTER (WHERE event_type = 'ACCEPTED'),
                          COUNT(*) FILTER (WHERE event_type = 'FAILED')
                   FROM ssh_log WHERE ip = %s""", (ip,))
            sc = cur.fetchone()
            out["ssh"] = {"total": sc[0], "accepted": sc[1], "failed": sc[2],
                          "recent": ssh_rows}
        except Exception:
            conn.rollback()
            out["ssh"] = {"total": 0, "accepted": 0, "failed": 0, "recent": []}

        # --- Block list ---
        cur.execute(
            """SELECT ip, fail_count, first_fail, last_fail, blocked_until, note
               FROM web_login_block WHERE ip = %s""", (ip,))
        brow = _rows_to_dicts(cur)
        out["block"] = brow[0] if brow else None

        out["summary"] = {
            "http_requests": out["http"]["total"],
            "web_login_attempts": out["web_logins"]["total"],
            "web_login_failed": out["web_logins"]["failed"],
            "sessions": len(out["sessions"]),
            "ssh_events": out["ssh"]["total"],
            "blocked": bool(out["block"] and out["block"].get("blocked_until")),
            "usernames": sorted(set(wl_users + http_users)),
        }
    finally:
        cur.close()
        release_connection(conn)
    return out

def log_session_created(session_id: str, username: str, ip: str, user_agent: str, expires_at):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO web_session_log (session_id, username, ip, user_agent, expires_at)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (session_id) DO NOTHING""",
        (session_id, username, ip, user_agent, expires_at)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def log_session_ended(session_id: str, reason: str = "logout"):
    if not session_id:
        return
    conn = get_connection()
    cur = conn.cursor()
    status = "logged_out" if reason == "logout" else "expired"
    cur.execute(
        """UPDATE web_session_log
           SET logout_at = CURRENT_TIMESTAMP, status = %s
           WHERE session_id = %s AND status = 'active'""",
        (status, session_id)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def expire_old_sessions():
    """Mark sessions whose expires_at has passed as expired."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE web_session_log
           SET status = 'expired'
           WHERE status = 'active' AND expires_at < CURRENT_TIMESTAMP"""
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def get_web_sessions(limit: int = 100):
    conn = get_connection()
    cur = conn.cursor()
    expire_old_sessions()
    cur.execute(
        """SELECT id, session_id, username, ip, user_agent,
                  login_at, expires_at, logout_at, status
           FROM web_session_log
           ORDER BY login_at DESC LIMIT %s""",
        (limit,)
    )
    rows = _rows_to_dicts(cur)
    cur.execute("SELECT COUNT(*) FROM web_session_log WHERE status = 'active'")
    active = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM web_session_log")
    total = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return {"sessions": rows, "active": active, "total": total}

def log_web_login(ip: str, username: str, success: bool, user_agent: str,
                  tried_password: str = "", details: str = "",
                  fp_hash: str = "", fingerprint: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO web_login_log
               (ip, username, success, user_agent, tried_password, details, fp_hash, fingerprint)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (ip, username, success, user_agent,
         tried_password if not success else "", details,
         fp_hash or None, fingerprint or None)
    )
    if not success:
        cur.execute("""
            INSERT INTO web_login_block (ip, fail_count, first_fail, last_fail)
            VALUES (%s, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (ip) DO UPDATE
              SET fail_count  = web_login_block.fail_count + 1,
                  last_fail   = CURRENT_TIMESTAMP,
                  blocked_until = CASE
                      WHEN web_login_block.fail_count + 1 >= 5
                      THEN CURRENT_TIMESTAMP + INTERVAL '24 hours'
                      ELSE web_login_block.blocked_until
                  END
        """, (ip,))
        # Device-fingerprint block: same machine, even from a fresh IP, gets
        # locked out after 5 failures. The 'sample' keeps a human-readable hint.
        if fp_hash:
            sample = (fingerprint or user_agent or "")[:500]
            cur.execute("""
                INSERT INTO web_fp_block (fp_hash, fail_count, first_fail, last_fail, last_ip, sample)
                VALUES (%s, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s)
                ON CONFLICT (fp_hash) DO UPDATE
                  SET fail_count = web_fp_block.fail_count + 1,
                      last_fail  = CURRENT_TIMESTAMP,
                      last_ip    = EXCLUDED.last_ip,
                      sample     = EXCLUDED.sample,
                      blocked_until = CASE
                          WHEN web_fp_block.fail_count + 1 >= 5
                          THEN CURRENT_TIMESTAMP + INTERVAL '24 hours'
                          ELSE web_fp_block.blocked_until
                      END
            """, (fp_hash, ip, sample))
    else:
        cur.execute("DELETE FROM web_login_block WHERE ip = %s", (ip,))
        if fp_hash:
            cur.execute("DELETE FROM web_fp_block WHERE fp_hash = %s", (fp_hash,))
    conn.commit()
    cur.close()
    release_connection(conn)

def check_web_login_allowed(ip: str, fp_hash: str = ""):
    """Returns (allowed: bool, fail_count: int, blocked_until: datetime|None).

    Blocks if EITHER the source IP or the device fingerprint has been blocked,
    so an attacker can't dodge the lockout just by switching IP on one machine.
    Expired blocks are cleaned up lazily."""
    import datetime
    conn = get_connection()
    cur = conn.cursor()
    try:
        # --- Device-fingerprint block takes precedence (harder to evade) ---
        if fp_hash:
            cur.execute(
                "SELECT fail_count, blocked_until FROM web_fp_block WHERE fp_hash = %s",
                (fp_hash,))
            frow = cur.fetchone()
            if frow and frow[1] is not None:
                if datetime.datetime.utcnow() < frow[1]:
                    return False, frow[0], frow[1]
                cur.execute("DELETE FROM web_fp_block WHERE fp_hash = %s", (fp_hash,))
                conn.commit()

        cur.execute(
            "SELECT fail_count, blocked_until FROM web_login_block WHERE ip = %s",
            (ip,))
        row = cur.fetchone()
        if not row:
            return True, 0, None
        fail_count, blocked_until = row
        if blocked_until is not None:
            if datetime.datetime.utcnow() < blocked_until:
                return False, fail_count, blocked_until
            cur.execute("DELETE FROM web_login_block WHERE ip = %s", (ip,))
            conn.commit()
        return True, fail_count, None
    finally:
        cur.close()
        release_connection(conn)

def get_web_login_logs(page=1, limit=50):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ts, ip, username, success, user_agent, tried_password, details, fp_hash, fingerprint FROM web_login_log ORDER BY id DESC LIMIT %s OFFSET %s",
        (limit, (page - 1) * limit)
    )
    rows = _rows_to_dicts(cur)
    cur.execute("SELECT COUNT(*) FROM web_login_log")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM web_login_log WHERE success = TRUE")
    success_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM web_login_log WHERE success = FALSE")
    fail_count = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return {"logs": rows, "total": total, "success": success_count, "failed": fail_count}

def get_web_blocked_ips():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT ip, fail_count, first_fail, last_fail, blocked_until, note FROM web_login_block ORDER BY last_fail DESC"
    )
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def block_web_ip(ip: str, hours: int = 24 * 365, note: str = "Manually blocked"):
    """Manually insert an IP into the block list. Default duration: 1 year."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO web_login_block (ip, fail_count, first_fail, last_fail, blocked_until, note)
        VALUES (%s, 5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + %s * INTERVAL '1 hour', %s)
        ON CONFLICT (ip) DO UPDATE
          SET fail_count    = GREATEST(web_login_block.fail_count, 5),
              last_fail     = CURRENT_TIMESTAMP,
              blocked_until = CURRENT_TIMESTAMP + %s * INTERVAL '1 hour',
              note          = EXCLUDED.note
    """, (ip, hours, note, hours))
    conn.commit()
    cur.close()
    release_connection(conn)

def unblock_web_ip(ip: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM web_login_block WHERE ip = %s", (ip,))
    cur.execute("DELETE FROM web_fp_block WHERE last_ip = %s", (ip,))
    conn.commit()
    cur.close()
    release_connection(conn)

def get_fp_blocked():
    """Devices locked out by fingerprint (independent of their current IP)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT fp_hash, fail_count, first_fail, last_fail, blocked_until, last_ip, sample, note
           FROM web_fp_block ORDER BY last_fail DESC""")
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def unblock_fp(fp_hash: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM web_fp_block WHERE fp_hash = %s", (fp_hash,))
    conn.commit()
    cur.close()
    release_connection(conn)

def persist_ssh_events(events: list) -> int:
    """Insert parsed journald SSH events into ssh_log, de-duplicated by content
    hash. Returns the number of NEW rows written."""
    if not events:
        return 0
    import hashlib as _hl
    conn = get_connection()
    cur = conn.cursor()
    written = 0
    for e in events:
        raw = "|".join(str(e.get(k) or "") for k in
                       ("ts", "event", "ip", "user", "port", "method", "fingerprint", "pid"))
        eh = _hl.sha256(raw.encode()).hexdigest()
        cur.execute("""
            INSERT INTO ssh_log
                (event_hash, ts, event_type, ip, username, fingerprint, session_pid, port, auth_method, details)
            VALUES (%s, COALESCE(%s::timestamptz, CURRENT_TIMESTAMP), %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_hash) DO NOTHING
        """, (
            eh, e.get("ts"), (e.get("event") or "UNKNOWN")[:32], e.get("ip"),
            e.get("user"), e.get("fingerprint"), e.get("pid"), e.get("port"),
            (e.get("method") or None), None,
        ))
        written += cur.rowcount
    conn.commit()
    cur.close()
    release_connection(conn)
    return written

def get_persisted_ssh(limit: int = 4000, since: str = None) -> list:
    """Read stored SSH events back as the same dict shape the live parser emits."""
    conn = get_connection()
    cur = conn.cursor()
    clause, params = "", []
    if since:
        clause = "WHERE ts >= %s::timestamptz"
        params.append(since)
    cur.execute(f"""
        SELECT to_char(ts, 'YYYY-MM-DD"T"HH24:MI:SSOF') AS ts, event_type, ip,
               username, port, auth_method, fingerprint, session_pid
        FROM ssh_log {clause}
        ORDER BY ts DESC LIMIT %s
    """, params + [limit])
    rows = cur.fetchall()
    cur.close()
    release_connection(conn)
    out = []
    for r in rows:
        out.append({"ts": r[0], "event": r[1], "ip": r[2], "user": r[3],
                    "port": r[4], "method": r[5], "fingerprint": r[6], "pid": r[7]})
    return out

def get_ssh_attacker_detail(ip: str):
    """For a blocked/attacking SSH IP: every username they tried, auth methods,
    any key fingerprints presented, and counts. NOTE: sshd never records the
    actual password typed, so that field is genuinely unavailable for SSH."""
    ip = (ip or "").strip()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT username, COUNT(*) c FROM ssh_log
        WHERE ip = %s AND username IS NOT NULL AND username <> ''
        GROUP BY username ORDER BY c DESC LIMIT 100""", (ip,))
    users = [{"username": r[0], "attempts": r[1]} for r in cur.fetchall()]
    cur.execute("""
        SELECT DISTINCT fingerprint FROM ssh_log
        WHERE ip = %s AND fingerprint IS NOT NULL AND fingerprint <> ''""", (ip,))
    fps = [r[0] for r in cur.fetchall()]
    cur.execute("""
        SELECT event_type, COUNT(*) FROM ssh_log WHERE ip = %s GROUP BY event_type""", (ip,))
    by_event = {r[0]: r[1] for r in cur.fetchall()}
    cur.execute("""
        SELECT DISTINCT auth_method FROM ssh_log
        WHERE ip = %s AND auth_method IS NOT NULL AND auth_method <> ''""", (ip,))
    methods = [r[0] for r in cur.fetchall()]
    cur.close()
    release_connection(conn)
    return {"ip": ip, "usernames_tried": users, "key_fingerprints": fps,
            "auth_methods": methods, "events_by_type": by_event,
            "password_note": "SSH passwords are never recorded by sshd and cannot be captured."}

_CLEARABLE = {
    "access":    "http_access_log",
    "web_logins": "web_login_log",
    "sessions":  "web_session_log",
    "ssh":       "ssh_log",
    "blocked":   "web_login_block",
    "fp_blocked": "web_fp_block",
}

def get_security_log_counts() -> dict:
    """Total stored-row count for every security log section, for the UI."""
    conn = get_connection()
    cur = conn.cursor()
    out = {}
    for key, table in _CLEARABLE.items():
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            out[key] = cur.fetchone()[0]
        except Exception:
            conn.rollback()
            out[key] = 0
    cur.close()
    release_connection(conn)
    return out

def clear_security_log(kind: str) -> int:
    """Manually wipe one security-log section. Explicit operator action only:
    nothing here is ever deleted automatically. Returns rows removed."""
    table = _CLEARABLE.get(kind)
    if not table:
        raise ValueError(f"unknown log section: {kind}")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table}")
    n = cur.fetchone()[0]
    cur.execute(f"DELETE FROM {table}")
    conn.commit()
    cur.close()
    release_connection(conn)
    return n

import datetime as _dt
import secrets as _secrets
