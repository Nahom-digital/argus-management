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
# environment variables, if already set, win — so containers/systemd can still
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

# Credentials are read from the environment (populated from .env above). The DB
# password is never hardcoded here; if it is missing the app fails loudly rather
# than silently using a default. Non-secret connection details keep safe defaults.
DB_CONFIG = {
    "dbname": os.environ.get("DB_NAME", "elink"),
    "user": os.environ.get("DB_USER", "elink"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "host": os.environ.get("DB_HOST", "127.0.0.1"),
    "port": int(os.environ.get("DB_PORT", "5432")),
}
if not DB_CONFIG["password"]:
    logging.warning("DB_PASSWORD is not set — create a .env file (see .env.example) "
                    "or export DB_PASSWORD. Database connections will fail until then.")

# --- Connection Pool (thread-safe) ---
# Reuse connections instead of opening a fresh TCP+auth handshake on every
# query. ThreadedConnectionPool is safe to share across the event-loop thread
# AND the DB worker threads used by DB.run(): every function acquires and
# releases its connection within one synchronous block, never holding one
# across an await, so at most one connection is live per thread at any instant.
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

# --- Async offload ---
# Run a blocking psycopg2 function in a dedicated thread pool so the asyncio
# event loop is NEVER blocked on Postgres I/O. SQL and transaction logic are
# unchanged — only WHERE the call runs changes. Worker count is bounded below
# _POOL_MAX so we can never request more live connections than the pool hands
# out (each offloaded call holds at most one connection at a time).
_DB_EXECUTOR = ThreadPoolExecutor(max_workers=16, thread_name_prefix="db")

async def run(fn, *args, **kwargs):
    """Offload a synchronous DB call off the event loop:
        user = await DB.run(DB.get_user, tid)
    Keeps the exact semantics of calling fn(*args, **kwargs) directly."""
    loop = asyncio.get_running_loop()
    call = fn if not kwargs else functools.partial(fn, **kwargs)
    return await loop.run_in_executor(_DB_EXECUTOR, call, *args)

# --- Admin Auth ---
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

def is_this_a_new_user(user_id: int) -> bool:
    trace_in = {
        "src": "bot.py", "dest": "DB.py",
        "action": "ACTION: Query User Registration",
        "data": {"tid": user_id}
    }
    logging.info(f"__TRACE__{json.dumps(trace_in)}")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM login_users WHERE tid = %s", (str(user_id),))
    exists = cur.fetchone() is not None
    cur.close()
    release_connection(conn)

    is_new = not exists
    trace_out = {
        "src": "DB.py", "dest": "bot.py",
        "action": "Return User Status",
        "data": {"is_registered": exists}
    }
    logging.info(f"__TRACE__{json.dumps(trace_out)}")
    return is_new

def register_user(tid: int, name: str, realn: str, username: str, usertype: int):
    trace_in = {
        "src": "bot.py", "dest": "DB.py",
        "action": "Register New User",
        "data": {"tid": tid, "name": name, "realn": realn, "username": username, "usertype": usertype}
    }
    logging.info(f"__TRACE__{json.dumps(trace_in)}")
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO login_users (tid, name, realn, username, usertype) VALUES (%s, %s, %s, %s, %s)",
        (str(tid), name, realn, username, usertype)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

    # A brand-new account must never inherit verification. If this TID was deleted
    # and re-created, an old APPROVED/PENDING verification row could linger (older
    # deletions didn't clear it) and make the fresh account read as verified — so
    # we wipe any stale verification rows for this TID on registration. Done in its
    # own transaction so it can never affect the account insert above.
    try:
        ensure_verification_request_table()
        vconn = get_connection()
        vcur = vconn.cursor()
        vcur.execute("DELETE FROM verification_requests WHERE tid = %s", (str(tid),))
        vconn.commit()
        vcur.close()
        release_connection(vconn)
    except Exception as e:
        logging.error(f"register_user verification cleanup failed for {tid}: {e}")
    
    trace_out = {
        "src": "DB.py", "dest": "bot.py",
        "action": "User Registered",
        "data": {"status": "SUCCESS", "tid": tid}
    }
    logging.info(f"__TRACE__{json.dumps(trace_out)}")

def get_user(tid):
    trace_in = {
        "src": "bot.py", "dest": "DB.py",
        "action": "Query User Account",
        "data": {"tid": str(tid)}
    }
    logging.info(f"__TRACE__{json.dumps(trace_in)}")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT tid, name, realn, username, usertype, created_at FROM login_users WHERE tid = %s",
        (str(tid),)
    )
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    if not row:
        return None

    user = {"tid": row[0], "name": row[1], "realn": row[2], "username": row[3], "usertype": row[4], "created_at": row[5]}
    trace_out = {
        "src": "DB.py", "dest": "bot.py",
        "action": "Return User Account",
        "data": {"tid": user["tid"], "name": user["name"], "realn": user["realn"]}
    }
    logging.info(f"__TRACE__{json.dumps(trace_out)}")
    return user

def update_user_realname(tid, realn):
    """Correct a user's real name (used by the /verify name-change step so the
    account name matches the submitted ID). login_users supports UPDATE for the
    app role even though it can't ALTER the table."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE login_users SET realn = %s WHERE tid = %s", (realn, str(tid)))
    conn.commit()
    cur.close()
    release_connection(conn)

def log_start_user(update_id: str, tid: str, name: str, username: str, login: bool, text: str, response: str = ""):
    trace_in = {
        "src": "log.py", "dest": "DB.py",
        "action": "Log Start User",
        "data": {"update_id": update_id, "tid": tid, "name": name, "username": username, "login": login, "text": text, "response": response}
    }
    logging.info(f"__TRACE__{json.dumps(trace_in)}")

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO start_users (update_id, tid, name, username, login, your_column_name, response) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (str(update_id), str(tid), name, username, login, text, response)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    
    trace_out = {
        "src": "DB.py", "dest": "log.py",
        "action": "Start User Logged",
        "data": {"status": "SUCCESS"}
    }
    logging.info(f"__TRACE__{json.dumps(trace_out)}")

# --- Bot conversation history (from the start_users interaction log) ---
def get_bot_conversation_users(search: str = ""):
    """One row per user who has ever talked to the bot, built from the start_users
    log: their tid, latest known name/username, how many exchanges we have, and a
    preview of their most recent message. Ordered most-recent-activity first
    (start_users has no timestamp, so the SERIAL id is the chronological key).
    Optional `search` filters by tid / name / username (case-insensitive)."""
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        params = []
        where = ""
        if search:
            where = """WHERE tid ILIKE %s OR name ILIKE %s OR username ILIKE %s"""
            like = f"%{search}%"
            params = [like, like, like]
        cur.execute(
            f"""SELECT s.tid,
                       (SELECT name     FROM start_users WHERE tid = s.tid AND name     <> '' ORDER BY id DESC LIMIT 1) AS name,
                       (SELECT username FROM start_users WHERE tid = s.tid AND username <> '' ORDER BY id DESC LIMIT 1) AS username,
                       COUNT(*)        AS exchanges,
                       MAX(s.id)       AS last_id,
                       (SELECT your_column_name FROM start_users WHERE tid = s.tid ORDER BY id DESC LIMIT 1) AS last_text,
                       BOOL_OR(s.login) AS ever_logged_in
                FROM start_users s
                {where}
                GROUP BY s.tid
                ORDER BY last_id DESC""",
            params
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_bot_conversation_users failed: {e}")
    cur.close()
    release_connection(conn)
    return rows

def get_bot_conversation(tid):
    """Full bot conversation for one user, oldest first: each row is one exchange
    (the user's text in `your_column_name` and the bot's `response`). The SERIAL
    id gives chronological order since start_users carries no timestamp."""
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        cur.execute(
            """SELECT id, update_id, tid, name, username, login,
                      your_column_name AS text, response
               FROM start_users WHERE tid = %s ORDER BY id ASC""",
            (str(tid),)
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_bot_conversation failed: {e}")
    cur.close()
    release_connection(conn)
    return rows

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

# =====================================================================
# --- P2P Trading: Ads, Orders, Messaging, Balance Locking ---
# =====================================================================
P2P_ACTIVE_STATUSES = ("ACTIVE", "PAID", "ADMIN_REVIEW")

def _p2p_trace(action, data):
    logging.info(f"__TRACE__{json.dumps({'src': 'DB.py', 'dest': 'bot.py', 'action': action, 'data': data}, default=str)}")

def _rows_to_dicts(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]

def _row_to_dict(cur):
    row = cur.fetchone()
    if not row:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))

def _parse_ad(ad):
    if ad:
        ad["methods"] = json.loads(ad["payment_methods"] or "[]")
        ad["accounts"] = json.loads(ad["payment_accounts"] or "{}")
        # Network info lives in the ad_networks side table; default here so every
        # ad dict carries the keys even if the caller doesn't attach them.
        ad.setdefault("networks", [])
        ad.setdefault("network", None)
    return ad

def ensure_p2p_tables():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ads (
            id SERIAL PRIMARY KEY,
            merchant_tid TEXT NOT NULL,
            merchant_name TEXT NOT NULL,
            ad_type VARCHAR(4) NOT NULL,
            min_amount NUMERIC(30, 8) NOT NULL,
            max_amount NUMERIC(30, 8) NOT NULL,
            price_per_usdt NUMERIC(12, 2) NOT NULL,
            payment_methods TEXT NOT NULL,
            payment_accounts TEXT NOT NULL,
            payment_time_minutes INTEGER NOT NULL,
            total_trades INTEGER NOT NULL DEFAULT 0,
            success_rate NUMERIC(6, 2) NOT NULL DEFAULT 100,
            last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id SERIAL PRIMARY KEY,
            ad_id INTEGER NOT NULL,
            seller_tid TEXT NOT NULL,
            seller_rname TEXT NOT NULL,
            buyer_tid TEXT NOT NULL,
            buyer_rname TEXT NOT NULL,
            usdt_amount NUMERIC(30, 8) NOT NULL,
            fiat_amount NUMERIC(30, 2) NOT NULL,
            payment_method TEXT NOT NULL,
            payment_account_number TEXT NOT NULL,
            order_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
            buyer_paid BOOLEAN NOT NULL DEFAULT FALSE,
            seller_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
            admin_requested BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS p2p_message (
            id SERIAL PRIMARY KEY,
            order_id INTEGER NOT NULL,
            sender_tid TEXT NOT NULL,
            sender_role VARCHAR(10) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Per-ad USDT networks (SELL: one row; BUY: one row per accepted network).
    # Kept in its own table so it works even though `ads` is owned by `postgres`
    # and the app role cannot ALTER it.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ad_networks (
            id SERIAL PRIMARY KEY,
            ad_id INTEGER NOT NULL,
            network VARCHAR(16) NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ad_networks_ad ON ad_networks (ad_id)")
    # balance may not exist yet on a fresh install (Crypto.py also creates it)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS balance (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            token VARCHAR(16) NOT NULL DEFAULT 'USDT',
            amount NUMERIC(30, 8) NOT NULL DEFAULT 0,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (tid, token)
        )
    """)
    # Run each additive ALTER independently. The app DB role may lack ownership
    # of some legacy tables (they can be owned by `postgres`), in which case the
    # ALTER raises InsufficientPrivilege. Previously the first such failure
    # aborted the whole migration, leaving later statements unrun. Isolating each
    # statement lets every grantable change apply and surfaces the un-grantable
    # ones as warnings instead of a hard failure. (Per-ad networks deliberately
    # avoid ALTERing the postgres-owned `ads` table — see ad_networks above.)
    _migrations = [
        ("balance", "ALTER TABLE balance ADD COLUMN IF NOT EXISTS locked NUMERIC(30, 8) NOT NULL DEFAULT 0"),
        ("login_users", "ALTER TABLE IF EXISTS login_users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP"),
        # Persist the Telegram file_id of any image traded in the chat so the
        # Management thread (Orders + Requested Admin) can render it. NOTE:
        # p2p_message is postgres-owned, not app-owned, so this ALTER raises
        # InsufficientPrivilege when run as the app user (elink) and is skipped
        # below. The column must be added once as the table owner/superuser:
        #   sudo -u postgres psql -d elink \
        #     -c "ALTER TABLE p2p_message ADD COLUMN IF NOT EXISTS file_id TEXT;"
        # Kept here so the no-op is harmless and a failure still can't abort startup.
        ("p2p_message", "ALTER TABLE p2p_message ADD COLUMN IF NOT EXISTS file_id TEXT"),
    ]
    for table, stmt in _migrations:
        try:
            cur.execute(stmt)
        except Exception as e:
            conn.rollback()
            logging.warning(
                f"ensure_p2p_tables: skipped migration on '{table}' ({e}). "
                f"If this column is required, add it as the table owner/superuser."
            )
    conn.commit()
    cur.close()
    release_connection(conn)

def touch_last_seen(tid):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE login_users SET last_seen = CURRENT_TIMESTAMP WHERE tid = %s", (str(tid),))
    cur.execute("UPDATE ads SET last_seen = CURRENT_TIMESTAMP WHERE merchant_tid = %s", (str(tid),))
    conn.commit()
    cur.close()
    release_connection(conn)

# --- Balance locking ---
def get_available_balance(tid, token="USDT"):
    """Returns (amount, locked). Available to spend = amount - locked."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT amount, locked FROM balance WHERE tid = %s AND token = %s", (str(tid), token))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    if not row:
        return Decimal("0"), Decimal("0")
    return row[0], row[1]

def lock_balance(tid, amount, token="USDT") -> bool:
    """Locks `amount` of the user's balance. Fails if available balance is short."""
    amount = Decimal(str(amount))
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE balance SET locked = locked + %s, updated_at = CURRENT_TIMESTAMP
           WHERE tid = %s AND token = %s AND amount - locked >= %s""",
        (amount, str(tid), token, amount)
    )
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    release_connection(conn)
    if ok:
        _p2p_trace("Balance Locked", {"tid": str(tid), "amount": str(amount)})
    return ok

def unlock_balance(tid, amount, token="USDT", conn=None):
    """Release locked funds. If `conn` is provided the caller owns the
    transaction (finalize_order threads one connection through the whole order
    settlement); we then neither commit nor release it."""
    amount = Decimal(str(amount))
    owned = conn is None
    if owned:
        conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE balance SET locked = GREATEST(locked - %s, 0), updated_at = CURRENT_TIMESTAMP
           WHERE tid = %s AND token = %s""",
        (amount, str(tid), token)
    )
    if owned:
        conn.commit()
        cur.close()
        release_connection(conn)
    else:
        cur.close()
    _p2p_trace("Balance Unlocked", {"tid": str(tid), "amount": str(amount)})

def transfer_locked(from_tid, to_tid, amount, token="USDT", admin_override=False, conn=None) -> bool:
    """Moves `amount` from the sender's LOCKED balance to the receiver, atomically.
    Frozen wallets and global freeze block transfers unless an admin overrides
    (admin dispute resolution must still be able to move escrow).

    If `conn` is provided the caller owns the transaction (finalize_order makes
    the whole order settlement atomic by threading one connection through the
    transfer, the ad adjustment and the order-status change); in that mode the
    freeze/suspension guard is the caller's responsibility and we neither commit
    nor release the connection. Returns False (without rolling back) if the
    sender's locked balance no longer covers the amount, so the caller can abort."""
    owned = conn is None
    if owned and not admin_override:
        try:
            if is_global_freeze():
                return False
            flags = get_user_flags(from_tid)
            if flags and (flags["wallet_frozen"] or flags["status"] == "SUSPENDED"):
                return False
        except Exception:
            return False  # fail closed
    amount = Decimal(str(amount))
    if owned:
        conn = get_connection()
        conn.autocommit = False
    cur = conn.cursor()
    try:
        cur.execute(
            """UPDATE balance SET amount = amount - %s, locked = locked - %s, updated_at = CURRENT_TIMESTAMP
               WHERE tid = %s AND token = %s AND amount >= %s AND locked >= %s""",
            (amount, amount, str(from_tid), token, amount, amount)
        )
        if cur.rowcount == 0:
            if owned:
                conn.rollback()
            cur.close()
            return False
        cur.execute(
            """INSERT INTO balance (tid, token, amount) VALUES (%s, %s, %s)
               ON CONFLICT (tid, token) DO UPDATE SET
                   amount = balance.amount + EXCLUDED.amount,
                   updated_at = CURRENT_TIMESTAMP""",
            (str(to_tid), token, amount)
        )
        # keep the legacy user_wallet column in sync for the dashboard
        cur.execute("UPDATE user_wallet SET usdt_balance = usdt_balance - %s WHERE tid = %s", (amount, str(from_tid)))
        cur.execute("UPDATE user_wallet SET usdt_balance = usdt_balance + %s WHERE tid = %s", (amount, str(to_tid)))
        if owned:
            conn.commit()
    except Exception:
        if owned:
            conn.rollback()
        raise
    finally:
        if owned:
            conn.autocommit = True
            cur.close()
            release_connection(conn)
        elif not cur.closed:
            cur.close()
    _p2p_trace("P2P Transfer", {"from": str(from_tid), "to": str(to_tid), "amount": str(amount)})
    return True

# --- Ads ---
# Per-ad USDT networks live in their own `ad_networks` table (created/owned by the
# app DB role) instead of columns on `ads`, because `ads` is owned by `postgres`
# and the app role cannot ALTER it. SELL ads store a single network; BUY ads store
# the list of networks the merchant accepts. On read, _attach_ad_networks() turns
# the side-table rows back into ad["network"] (SELL) and ad["networks"] (BUY list).
def _write_ad_networks(cur, ad_id, network, networks):
    """Replace the network rows for an ad. `network` (single, SELL) and `networks`
    (list, BUY) are merged into a de-duplicated ordered list of rows."""
    cur.execute("DELETE FROM ad_networks WHERE ad_id = %s", (ad_id,))
    nets = []
    for n in ([network] if network else []) + list(networks or []):
        if n and n not in nets:
            nets.append(n)
    for n in nets:
        cur.execute("INSERT INTO ad_networks (ad_id, network) VALUES (%s, %s)", (ad_id, n))

def _load_ad_networks_map(cur, ad_ids):
    """Batch-load {ad_id: [networks]} for the given ad ids (preserves insert order)."""
    if not ad_ids:
        return {}
    cur.execute(
        "SELECT ad_id, network FROM ad_networks WHERE ad_id = ANY(%s) ORDER BY id",
        (list(ad_ids),)
    )
    out: dict = {}
    for aid, net in cur.fetchall():
        out.setdefault(aid, []).append(net)
    return out

def _attach_ad_networks(ad, net_list):
    """Populate ad['networks'] (full list) and ad['network'] (single, SELL only)
    from a list of networks loaded from ad_networks."""
    if not ad:
        return ad
    net_list = net_list or []
    ad["networks"] = list(net_list)
    ad["network"] = net_list[0] if (ad.get("ad_type") == "SELL" and net_list) else None
    return ad

def create_ad(merchant_tid, merchant_name, ad_type, min_amount, max_amount,
              price, methods, accounts, payment_time_minutes, network=None,
              networks=None) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO ads (merchant_tid, merchant_name, ad_type, min_amount, max_amount,
                            price_per_usdt, payment_methods, payment_accounts, payment_time_minutes)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (str(merchant_tid), merchant_name, ad_type, min_amount, max_amount,
         price, json.dumps(methods), json.dumps(accounts), payment_time_minutes)
    )
    ad_id = cur.fetchone()[0]
    _write_ad_networks(cur, ad_id, network, networks)
    conn.commit()
    cur.close()
    release_connection(conn)
    # Every ad needs a public handle (MID) in the listing. Merchants are minted one
    # on promotion, but verified NON-merchants can now post small ads too, so make
    # sure the poster has a MID (no-op if they already do). Best-effort: a MID hiccup
    # must never fail ad creation.
    try:
        get_or_create_merchant_id(merchant_tid)
    except Exception as e:
        logging.warning(f"create_ad MID ensure failed for {merchant_tid}: {e}")
    _p2p_trace("Ad Created", {"ad_id": ad_id, "merchant_tid": str(merchant_tid), "type": ad_type,
                              "min": str(min_amount), "max": str(max_amount), "price": str(price),
                              "network": network, "networks": networks or []})
    return ad_id

def update_ad(ad_id, min_amount, max_amount, price, methods, accounts, payment_time_minutes,
              network=None, networks=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE ads SET min_amount=%s, max_amount=%s, price_per_usdt=%s,
                          payment_methods=%s, payment_accounts=%s, payment_time_minutes=%s
           WHERE id = %s""",
        (min_amount, max_amount, price, json.dumps(methods), json.dumps(accounts),
         payment_time_minutes, ad_id)
    )
    _write_ad_networks(cur, ad_id, network, networks)
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Ad Updated", {"ad_id": ad_id, "network": network, "networks": networks or []})

def get_ad(ad_id):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ads WHERE id = %s", (ad_id,))
        ad = _row_to_dict(cur)
        if ad:
            cur.execute(
                """SELECT DISTINCT network FROM transaction
                   WHERE tid = %s AND token = 'USDT' AND amount > 0
                     AND network NOT IN ('INTERNAL')""",
                (ad["merchant_tid"],)
            )
            ad["deposit_networks"] = sorted(r[0] for r in cur.fetchall())
            _attach_ad_networks(ad, _load_ad_networks_map(cur, [ad["id"]]).get(ad["id"]))
        cur.close()
    finally:
        release_connection(conn)
    # MID lookup uses its own connection AFTER releasing this one, so it can never
    # leak this connection or poison its transaction if the MID store has an issue.
    if ad:
        ad["merchant_id"] = get_merchant_id(ad["merchant_tid"])
        ad["merchant_username"] = get_usernames_map([ad["merchant_tid"]]).get(ad["merchant_tid"], "")
        ad["merchant_has_avatar"] = has_user_avatar(ad["merchant_tid"])
    return _parse_ad(ad)

def get_merchant_ads(tid):
    conn = get_connection()
    cur = conn.cursor()
    # GHOST ads (paused because their network is closed) are still the merchant's
    # ads — show them in /my_ads so the owner knows they'll reopen.
    cur.execute("SELECT * FROM ads WHERE merchant_tid = %s AND status IN ('ACTIVE', 'GHOST') ORDER BY id DESC", (str(tid),))
    ads = _rows_to_dicts(cur)
    if ads:
        net_map = _load_ad_networks_map(cur, [a["id"] for a in ads])
        for a in ads:
            _attach_ad_networks(a, net_map.get(a["id"]))
    cur.close()
    release_connection(conn)
    return [_parse_ad(a) for a in ads]

def get_merchant_ad_by_type(tid, ad_type):
    """The merchant's single active ad of a given side (BUY/SELL), or None.
    Used to enforce one active ad per side."""
    conn = get_connection()
    cur = conn.cursor()
    # A GHOST ad still occupies the one-per-side slot (it will reopen), so it
    # counts here too — the merchant can't post a second ad of the same side.
    cur.execute(
        "SELECT * FROM ads WHERE merchant_tid = %s AND ad_type = %s AND status IN ('ACTIVE', 'GHOST') "
        "ORDER BY id DESC LIMIT 1",
        (str(tid), ad_type)
    )
    ad = _row_to_dict(cur)
    if ad:
        _attach_ad_networks(ad, _load_ad_networks_map(cur, [ad["id"]]).get(ad["id"]))
    cur.close()
    release_connection(conn)
    return _parse_ad(ad)

def count_merchant_ads_by_type(tid, ad_type) -> int:
    """How many active (or GHOST) ads of a side the merchant has. Enforces the
    per-side limits (BUY: 1, SELL: 3)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM ads WHERE merchant_tid = %s AND ad_type = %s "
        "AND status IN ('ACTIVE', 'GHOST')",
        (str(tid), ad_type)
    )
    n = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return int(n or 0)

def merchant_sell_ad_networks(tid, exclude_ad_id=None):
    """The set of networks already used by the merchant's active (or GHOST) SELL ads.
    Each SELL ad must be on a distinct network, so a new/edited ad's network must not
    be in this set. `exclude_ad_id` drops the ad being edited (so keeping its own
    network isn't treated as a clash)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT DISTINCT an.network
             FROM ads a JOIN ad_networks an ON an.ad_id = a.id
            WHERE a.merchant_tid = %s AND a.ad_type = 'SELL'
              AND a.status IN ('ACTIVE', 'GHOST')
              AND (%s IS NULL OR a.id <> %s)""",
        (str(tid), exclude_ad_id, exclude_ad_id)
    )
    nets = {r[0] for r in cur.fetchall()}
    cur.close()
    release_connection(conn)
    return nets

def merchant_has_active_ad(tid) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM ads WHERE merchant_tid = %s AND status IN ('ACTIVE', 'GHOST') LIMIT 1", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def merchant_has_fund_locking_ad(tid) -> bool:
    """True only when the merchant has an ad that escrow-locks their USDT, i.e. a
    SELL ad. A BUY ad ("I Buy USDT") locks nothing — the merchant pays fiat and
    receives USDT — so it must NOT block withdrawal. GHOST counts (it reopens and
    still holds the locked funds)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM ads WHERE merchant_tid = %s AND ad_type = 'SELL' "
        "AND status IN ('ACTIVE', 'GHOST') LIMIT 1",
        (str(tid),),
    )
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def browse_ads(ad_type, viewer_tid=""):
    """ACTIVE ads of a type. SELL ads: cheapest first; BUY ads: highest price first.
    Reputation (success_rate) breaks ties. Each ad includes the merchant's deposit
    networks so the listing can show which blockchain the USDT lives on.

    The viewer's OWN ad is intentionally included (a merchant who is the only one
    on a side would otherwise get an empty list). Self-trading is blocked later at
    the Process step; `is_own` is flagged here so the UI can mark it."""
    order_clause = "price_per_usdt ASC" if ad_type == "SELL" else "price_per_usdt DESC"
    conn = get_connection()
    try:
        cur = conn.cursor()
        # The viewer's OWN ad is always pinned to the very top (so a merchant
        # immediately sees their own listing), then the normal price / reputation
        # ordering for everyone else.
        cur.execute(
            f"""SELECT * FROM ads WHERE ad_type = %s AND status = 'ACTIVE'
                ORDER BY (merchant_tid = %s) DESC, {order_clause}, success_rate DESC, total_trades DESC""",
            (ad_type, str(viewer_tid))
        )
        ads = _rows_to_dicts(cur)
        if ads:
            merchant_tids = list({a["merchant_tid"] for a in ads})
            cur.execute(
                """SELECT tid, network FROM transaction
                   WHERE tid = ANY(%s::text[]) AND token = 'USDT' AND amount > 0
                     AND network NOT IN ('INTERNAL')
                   GROUP BY tid, network""",
                (merchant_tids,)
            )
            net_map: dict = {}
            for tid_val, net in cur.fetchall():
                net_map.setdefault(tid_val, set()).add(net)
            for a in ads:
                a["deposit_networks"] = sorted(net_map.get(a["merchant_tid"], set()))
            ad_net_map = _load_ad_networks_map(cur, [a["id"] for a in ads])
            for a in ads:
                _attach_ad_networks(a, ad_net_map.get(a["id"]))
        cur.close()
    finally:
        release_connection(conn)
    # MID lookup runs on its own connection AFTER releasing the one above, and is
    # fail-safe ({} on any error), so the listing can never hang or leak on it.
    merchant_tids = list({a["merchant_tid"] for a in ads}) if ads else []
    mid_map = get_merchant_ids_map(merchant_tids) if ads else {}
    uname_map = get_usernames_map(merchant_tids) if ads else {}
    avatar_tids = get_avatar_tids(merchant_tids) if ads else set()
    for a in ads:
        a["is_own"] = (a["merchant_tid"] == str(viewer_tid))
        a["merchant_id"] = mid_map.get(a["merchant_tid"])
        a["merchant_username"] = uname_map.get(a["merchant_tid"], "")
        a["merchant_has_avatar"] = a["merchant_tid"] in avatar_tids
    return [_parse_ad(a) for a in ads]

def cancel_ad(ad_id, status="CANCELLED"):
    """Cancels an ad; unlocks the merchant funds backing a SELL ad. A GHOST ad
    (paused for a closed network) can also be cancelled — its SELL lock is still
    in place, so it must be released here too."""
    ad = get_ad(ad_id)
    if not ad or ad["status"] not in ("ACTIVE", "GHOST"):
        return None
    if ad["ad_type"] == "SELL":
        unlock_balance(ad["merchant_tid"], ad["max_amount"])
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE ads SET status = %s WHERE id = %s", (status, ad_id))
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Ad Cancelled", {"ad_id": ad_id, "status": status})
    return ad

def get_all_ads():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ads ORDER BY id DESC")
    ads = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return ads

# --- Merchant statistics ---
def merchant_stats(merchant_tid):
    """Total terminal trades and success rate for a merchant.
    A trade that went through admin review does not count as successful."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT COUNT(*) FILTER (WHERE o.order_status = 'COMPLETED' AND NOT o.admin_requested),
                  COUNT(*)
           FROM orders o JOIN ads a ON a.id = o.ad_id
           WHERE a.merchant_tid = %s AND o.order_status IN ('COMPLETED', 'CANCELLED', 'CLOSED')""",
        (str(merchant_tid),)
    )
    ok, total = cur.fetchone()
    cur.close()
    release_connection(conn)
    rate = round(ok / total * 100, 2) if total else Decimal("100")
    return {"total_trades": total, "success_rate": rate}

def refresh_ad_stats(merchant_tid):
    stats = merchant_stats(merchant_tid)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE ads SET total_trades = %s, success_rate = %s WHERE merchant_tid = %s",
                (stats["total_trades"], stats["success_rate"], str(merchant_tid)))
    conn.commit()
    cur.close()
    release_connection(conn)

# --- Orders ---
# Order ids are random 9-digit numbers (not sequential) so they can't be guessed
# or enumerated. Kept as integers so every int() cast and the {order_id:int} API
# route keep working unchanged — only the values are random.
def _random_order_id(cur) -> int:
    for _ in range(50):
        oid = secrets.randbelow(900_000_000) + 100_000_000   # 100000000 .. 999999999
        cur.execute("SELECT 1 FROM orders WHERE order_id = %s", (oid,))
        if not cur.fetchone():
            return oid
    raise RuntimeError("could not allocate a unique order_id")

def create_order(ad_id, seller_tid, seller_rname, buyer_tid, buyer_rname,
                 usdt_amount, fiat_amount, payment_method, payment_account_number) -> int:
    conn = get_connection()
    try:
        cur = conn.cursor()
        order_id = _random_order_id(cur)
        cur.execute(
            """INSERT INTO orders (order_id, ad_id, seller_tid, seller_rname, buyer_tid, buyer_rname,
                                   usdt_amount, fiat_amount, payment_method, payment_account_number)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (order_id, ad_id, str(seller_tid), seller_rname, str(buyer_tid), buyer_rname,
             usdt_amount, fiat_amount, payment_method, payment_account_number)
        )
        conn.commit()
        cur.close()
    except Exception:
        conn.rollback()
        raise
    finally:
        release_connection(conn)
    _p2p_trace("Order Created", {"order_id": order_id, "ad_id": ad_id,
                                 "seller": str(seller_tid), "buyer": str(buyer_tid),
                                 "usdt": str(usdt_amount), "fiat": str(fiat_amount)})
    return order_id

def migrate_order_ids_to_random():
    """One-time: replace the old sequential order ids (< 100000000) with random
    ones, cascading the new id into p2p_message.order_id and
    transaction.related_order_id so message threads and ledger links stay intact.
    Idempotent — new orders already get random ids in the 9-digit range, so a
    second run finds nothing to migrate. Never raises (logged on failure)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT order_id FROM orders WHERE order_id < 100000000")
        old_ids = [r[0] for r in cur.fetchall()]
        for old in old_ids:
            new = _random_order_id(cur)
            cur.execute("UPDATE orders SET order_id = %s WHERE order_id = %s", (new, old))
            cur.execute("UPDATE p2p_message SET order_id = %s WHERE order_id = %s", (new, old))
            cur.execute('UPDATE "transaction" SET related_order_id = %s WHERE related_order_id = %s', (new, old))
        conn.commit()
        cur.close()
        if old_ids:
            logging.info(f"migrate_order_ids_to_random: migrated {len(old_ids)} order id(s).")
    except Exception as e:
        conn.rollback()
        logging.error(f"migrate_order_ids_to_random failed (left as-is): {e}")
    finally:
        release_connection(conn)

def get_order(order_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
    order = _row_to_dict(cur)
    cur.close()
    release_connection(conn)
    return order

def get_active_order(tid):
    """The user's current active trade (as buyer or seller), or None."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM orders WHERE (seller_tid = %s OR buyer_tid = %s)
           AND order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW')
           ORDER BY created_at DESC, order_id DESC LIMIT 1""",
        (str(tid), str(tid))
    )
    order = _row_to_dict(cur)
    cur.close()
    release_connection(conn)
    return order

def get_order_history(tid, limit=10):
    """The user's most recent orders (as buyer or seller), newest first.
    Powers /order_history so users and merchants can review past trades and
    see whether each one COMPLETED or was CANCELLED."""
    tid = str(tid)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM orders WHERE seller_tid = %s OR buyer_tid = %s
           ORDER BY created_at DESC, order_id DESC LIMIT %s""",
        (tid, tid, int(limit))
    )
    orders = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return orders

def order_set_paid(order_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE orders SET buyer_paid = TRUE,
               order_status = CASE WHEN order_status = 'ACTIVE' THEN 'PAID' ELSE order_status END
           WHERE order_id = %s AND order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW')""",
        (order_id,)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Order Marked Paid", {"order_id": order_id})

def order_request_admin(order_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE orders SET admin_requested = TRUE, order_status = 'ADMIN_REVIEW'
           WHERE order_id = %s AND order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW')""",
        (order_id,)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Admin Review Requested", {"order_id": order_id})

def finalize_order(order_id, outcome, seller_confirmed=False, admin_override=False):
    """Terminal transition for an order.
    COMPLETED: moves escrowed USDT seller -> buyer, shrinks SELL-ad max automatically.
    CANCELLED / CLOSED: returns escrow (unlocks seller funds for BUY-ad orders).
    Returns the updated order dict, or None if the order wasn't active."""
    order = get_order(order_id)
    if not order or order["order_status"] not in P2P_ACTIVE_STATUSES:
        return None
    ad = get_ad(order["ad_id"])
    amount = order["usdt_amount"]

    # COMPLETED transfers honor the same freeze/suspension guard transfer_locked
    # used to apply — checked up-front so the whole settlement can be one txn.
    if outcome == "COMPLETED" and not admin_override:
        try:
            if is_global_freeze():
                return None
            flags = get_user_flags(order["seller_tid"])
            if flags and (flags["wallet_frozen"] or flags["status"] == "SUSPENDED"):
                return None
        except Exception:
            return None  # fail closed

    # ONE atomic transaction: the balance move, the SELL-ad stock adjustment and
    # the order-status change all commit together (or roll back together), so a
    # crash can never leave escrow moved while the order is still ACTIVE — the
    # only financial-consistency hole in the previous multi-commit version.
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        if outcome == "COMPLETED":
            if not transfer_locked(order["seller_tid"], order["buyer_tid"], amount,
                                   admin_override=admin_override, conn=conn):
                conn.rollback()
                return None
            # Move real fund ownership seller->buyer and log the P2P internal
            # transaction (its real network + custody location). Wrapped in a
            # SAVEPOINT: this tracking is best-effort and must NEVER roll back the
            # escrow settlement itself, even if the audit insert fails.
            try:
                cur.execute("SAVEPOINT p2p_track")
                moved = fund_ledger_transfer(order["seller_tid"], order["buyer_tid"], amount, conn)
                logged = Decimal("0")
                for m in moved:
                    log_internal_txn(cur, f"P2P-{order_id}", "P2P",
                                     order["seller_tid"], order["buyer_tid"], m["amount"],
                                     network=m["network"], custody_address=m["custody_address"],
                                     related_order_id=order_id)
                    logged += m["amount"]
                if logged < amount:
                    # ledger under-covers the escrow that moved: still log the
                    # remainder so the internal history matches the balance move.
                    log_internal_txn(cur, f"P2P-{order_id}", "P2P",
                                     order["seller_tid"], order["buyer_tid"], amount - logged,
                                     related_order_id=order_id)
                cur.execute("RELEASE SAVEPOINT p2p_track")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT p2p_track")
                logging.warning(f"finalize_order #{order_id}: P2P tracking failed (settlement kept): {e}")
            if ad and ad["ad_type"] == "SELL":
                # ad maximum follows the merchant's remaining locked stock
                new_max = ad["max_amount"] - amount
                if new_max <= 0 or new_max < ad["min_amount"]:
                    cur.execute("UPDATE ads SET max_amount = %s, status = 'CLOSED' WHERE id = %s",
                                (max(new_max, 0), ad["id"]))
                    if new_max > 0:
                        unlock_balance(ad["merchant_tid"], new_max, conn=conn)
                else:
                    cur.execute("UPDATE ads SET max_amount = %s WHERE id = %s", (new_max, ad["id"]))
        else:
            # no transfer: release the order's escrow lock back to the seller
            if ad and ad["ad_type"] == "BUY":
                unlock_balance(order["seller_tid"], amount, conn=conn)

        cur.execute(
            """UPDATE orders SET order_status = %s, seller_confirmed = %s,
                   completed_at = CASE WHEN %s = 'COMPLETED' THEN CURRENT_TIMESTAMP ELSE completed_at END
               WHERE order_id = %s""",
            (outcome, seller_confirmed, outcome, order_id)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)
    if ad:
        refresh_ad_stats(ad["merchant_tid"])
    _p2p_trace("Order Finalized", {"order_id": order_id, "outcome": outcome, "usdt": str(amount)})
    return get_order(order_id)

# --- Order messaging ---
def add_p2p_message(order_id, sender_tid, sender_role, text, file_id=None):
    conn = get_connection()
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO p2p_message (order_id, sender_tid, sender_role, message, file_id) VALUES (%s, %s, %s, %s, %s)",
                (order_id, str(sender_tid), sender_role, text, file_id)
            )
        except Exception:
            # Older DBs may not have the file_id column yet — fall back so a chat
            # message is never lost just because the image-thread migration hasn't run.
            conn.rollback()
            cur.execute(
                "INSERT INTO p2p_message (order_id, sender_tid, sender_role, message) VALUES (%s, %s, %s, %s)",
                (order_id, str(sender_tid), sender_role, text)
            )
        conn.commit()
        cur.close()
    except Exception:
        conn.rollback()
        raise
    finally:
        release_connection(conn)
    _p2p_trace("P2P Message", {"order_id": order_id, "role": sender_role})

def get_p2p_messages(order_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM p2p_message WHERE order_id = %s ORDER BY id ASC", (order_id,))
    msgs = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return msgs

def get_message_threads():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT o.order_id, o.seller_rname, o.buyer_rname, o.order_status,
                  COUNT(m.id) AS message_count, MAX(m.created_at) AS last_message
           FROM orders o JOIN p2p_message m ON m.order_id = o.order_id
           GROUP BY o.order_id, o.seller_rname, o.buyer_rname, o.order_status
           ORDER BY last_message DESC"""
    )
    threads = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return threads

def ensure_contact_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contact_messages (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            realn TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            direction VARCHAR(4) NOT NULL DEFAULT 'IN',
            message TEXT NOT NULL,
            is_read BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS contact_sessions (
            tid TEXT PRIMARY KEY,
            entered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("ALTER TABLE contact_messages ADD COLUMN IF NOT EXISTS file_id TEXT")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_contact_tid ON contact_messages (tid)")
    conn.commit()
    cur.close()
    release_connection(conn)

def enter_contact_session(tid):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO contact_sessions (tid) VALUES (%s) ON CONFLICT (tid) DO UPDATE SET entered_at = CURRENT_TIMESTAMP",
        (str(tid),)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def exit_contact_session(tid):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM contact_sessions WHERE tid = %s", (str(tid),))
    conn.commit()
    cur.close()
    release_connection(conn)

def is_in_contact_session(tid):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM contact_sessions WHERE tid = %s", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def add_contact_message(tid, realn, username, message, direction='IN', file_id=None):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO contact_messages (tid, realn, username, direction, message, file_id) VALUES (%s, %s, %s, %s, %s, %s)",
        (str(tid), realn or '', username or '', direction, message, file_id)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def get_contact_threads():
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT m.tid,
               MAX(m.realn) AS realn,
               MAX(m.username) AS username,
               COUNT(*) FILTER (WHERE m.direction = 'IN' AND m.is_read = FALSE) AS unread,
               COUNT(*) AS total,
               MAX(m.created_at) AS last_time,
               (SELECT message FROM contact_messages m2
                WHERE m2.tid = m.tid ORDER BY id DESC LIMIT 1) AS last_message,
               (SELECT file_id FROM contact_messages m2
                WHERE m2.tid = m.tid ORDER BY id DESC LIMIT 1) AS last_file_id,
               CASE WHEN cs.tid IS NOT NULL THEN TRUE ELSE FALSE END AS is_active
        FROM contact_messages m
        LEFT JOIN contact_sessions cs ON cs.tid = m.tid
        GROUP BY m.tid, cs.tid
        ORDER BY MAX(m.created_at) DESC
    """)
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def get_contact_conversation(tid):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM contact_messages WHERE tid = %s ORDER BY id ASC", (str(tid),))
    msgs = _rows_to_dicts(cur)
    cur.execute("SELECT 1 FROM contact_sessions WHERE tid = %s", (str(tid),))
    is_active = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return {"messages": msgs, "is_active": is_active}

def mark_contact_read(tid):
    ensure_contact_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE contact_messages SET is_read = TRUE WHERE tid = %s AND direction = 'IN'",
        (str(tid),)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

# =====================================================================
# --- Become-Merchant requests ---
# A user applies for Merchant status through the /become_merchant wizard;
# admins approve/reject from Management → Merchant Requests.
# =====================================================================
def ensure_merchant_request_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS merchant_requests (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            rname TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            intention VARCHAR(8) NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            experience BOOLEAN NOT NULL DEFAULT FALSE,
            message TEXT NOT NULL DEFAULT '',
            status VARCHAR(10) NOT NULL DEFAULT 'PENDING',
            reason TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            decided_at TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_merchant_req_status ON merchant_requests (status)")
    conn.commit()
    cur.close()
    release_connection(conn)

def has_pending_merchant_request(tid):
    ensure_merchant_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM merchant_requests WHERE tid = %s AND status = 'PENDING'", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def create_merchant_request(tid, rname, username, intention, phone, experience, message):
    ensure_merchant_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO merchant_requests (tid, rname, username, intention, phone, experience, message)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (str(tid), rname or '', username or '', intention, phone or '', bool(experience), message or '')
    )
    req_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    release_connection(conn)
    return req_id

def list_merchant_requests(status="PENDING"):
    ensure_merchant_request_table()
    conn = get_connection()
    cur = conn.cursor()
    if status:
        cur.execute("SELECT * FROM merchant_requests WHERE status = %s ORDER BY id DESC", (status,))
    else:
        cur.execute("SELECT * FROM merchant_requests ORDER BY id DESC")
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def get_merchant_request(req_id):
    ensure_merchant_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM merchant_requests WHERE id = %s", (int(req_id),))
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows[0] if rows else None

def decide_merchant_request(req_id, status, reason=""):
    """Mark a PENDING request APPROVED or REJECTED. Returns the updated row,
    or None if it was missing or already decided (so the caller can't double-apply)."""
    ensure_merchant_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE merchant_requests
              SET status = %s, reason = %s, decided_at = CURRENT_TIMESTAMP
            WHERE id = %s AND status = 'PENDING'
        RETURNING *""",
        (status, reason or '', int(req_id))
    )
    rows = _rows_to_dicts(cur)
    conn.commit()
    cur.close()
    release_connection(conn)
    return rows[0] if rows else None

# =====================================================================
# --- Account verification (KYC) ---
# A user submits ID photos (front + back) through the /verify wizard; admins
# approve/reject from Management → Verify Requests. (The selfie_file_id column
# is retained for older records but no longer collected.) "Verified" = the user has
# at least one APPROVED verification request. Kept in its own app-owned table
# (login_users is postgres-owned and can't be ALTERed by the app role).
# =====================================================================
def ensure_verification_request_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS verification_requests (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            rname TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL DEFAULT '',
            id_front_file_id TEXT NOT NULL DEFAULT '',
            id_back_file_id TEXT NOT NULL DEFAULT '',
            selfie_file_id TEXT NOT NULL DEFAULT '',
            status VARCHAR(10) NOT NULL DEFAULT 'PENDING',
            reason TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            decided_at TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_verification_req_status ON verification_requests (status)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_verification_req_tid ON verification_requests (tid)")
    conn.commit()
    cur.close()
    release_connection(conn)

def is_user_verified(tid):
    """True if the user has at least one APPROVED verification request."""
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM verification_requests WHERE tid = %s AND status = 'APPROVED' LIMIT 1", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def has_pending_verification(tid):
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM verification_requests WHERE tid = %s AND status = 'PENDING'", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def create_verification_request(tid, rname, username, id_front, id_back, selfie):
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO verification_requests
               (tid, rname, username, id_front_file_id, id_back_file_id, selfie_file_id)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
        (str(tid), rname or '', username or '', id_front or '', id_back or '', selfie or '')
    )
    req_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    release_connection(conn)
    return req_id

def list_verification_requests(status="PENDING"):
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    if status:
        cur.execute("SELECT * FROM verification_requests WHERE status = %s ORDER BY id DESC", (status,))
    else:
        cur.execute("SELECT * FROM verification_requests ORDER BY id DESC")
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def get_verification_request(req_id):
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM verification_requests WHERE id = %s", (int(req_id),))
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows[0] if rows else None

def decide_verification_request(req_id, status, reason=""):
    """Mark a PENDING verification APPROVED or REJECTED. Returns the updated row,
    or None if it was missing or already decided (so the caller can't double-apply)."""
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE verification_requests
              SET status = %s, reason = %s, decided_at = CURRENT_TIMESTAMP
            WHERE id = %s AND status = 'PENDING'
        RETURNING *""",
        (status, reason or '', int(req_id))
    )
    rows = _rows_to_dicts(cur)
    conn.commit()
    cur.close()
    release_connection(conn)
    return rows[0] if rows else None

def admin_verify_user(tid, rname=''):
    """Manually mark a user verified from the admin user panel. If they have a
    PENDING request, approve the most recent one (keeping the images they
    submitted). Otherwise insert a fresh APPROVED record with no images (the UI
    shows 'No Image'). Append-only — never deletes or rewrites prior rows."""
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE verification_requests
              SET status = 'APPROVED', decided_at = CURRENT_TIMESTAMP
            WHERE id = (SELECT id FROM verification_requests
                         WHERE tid = %s AND status = 'PENDING'
                         ORDER BY id DESC LIMIT 1)
        RETURNING id""",
        (str(tid),)
    )
    if cur.fetchone() is None:
        cur.execute(
            """INSERT INTO verification_requests (tid, rname, status, decided_at)
               VALUES (%s, %s, 'APPROVED', CURRENT_TIMESTAMP)""",
            (str(tid), rname or '')
        )
    conn.commit()
    cur.close()
    release_connection(conn)

def admin_unverify_user(tid):
    """Revoke a user's verification without losing history: flip every APPROVED
    row to REVOKED so is_user_verified() returns False while the records (and
    their images) are preserved. Returns the number of rows revoked."""
    ensure_verification_request_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE verification_requests
              SET status = 'REVOKED', decided_at = CURRENT_TIMESTAMP
            WHERE tid = %s AND status = 'APPROVED'""",
        (str(tid),)
    )
    n = cur.rowcount
    conn.commit()
    cur.close()
    release_connection(conn)
    return n

def get_mgmt_counts():
    conn = get_connection()
    cur = conn.cursor()

    def _safe_count(sql):
        try:
            cur.execute(sql)
            return int(cur.fetchone()[0])
        except Exception:
            return 0

    contact_unread = _safe_count("SELECT COUNT(*) FROM contact_messages WHERE is_read = FALSE AND direction = 'IN'")
    review_pending = _safe_count("SELECT COUNT(*) FROM orders WHERE order_status = 'ADMIN_REVIEW'")
    wd_review      = _safe_count("SELECT COUNT(*) FROM withdraw WHERE status = 'PENDING' AND review_reason IS NOT NULL")
    merchant_pending = _safe_count("SELECT COUNT(*) FROM merchant_requests WHERE status = 'PENDING'")
    verify_pending = _safe_count("SELECT COUNT(*) FROM verification_requests WHERE status = 'PENDING'")
    cur.close()
    release_connection(conn)
    return {
        "contact_unread":   contact_unread,
        "review_pending":   review_pending,
        "wd_review":        wd_review,
        "merchant_pending": merchant_pending,
        "verify_pending":   verify_pending,
        "total":            contact_unread + review_pending + wd_review + merchant_pending + verify_pending,
    }

def get_admin_review_orders():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE order_status = 'ADMIN_REVIEW' ORDER BY created_at DESC, order_id DESC")
    orders = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return orders

def get_all_orders():
    """Every order plus its chat message count — powers the admin Orders overview.
    In-flight trades (ACTIVE / PAID / ADMIN_REVIEW) are listed first, then the
    most recent finalized ones, so active trading orders are always on top."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT o.*, COALESCE(m.cnt, 0) AS message_count
           FROM orders o
           LEFT JOIN (SELECT order_id, COUNT(*) AS cnt FROM p2p_message GROUP BY order_id) m
             ON m.order_id = o.order_id
           ORDER BY
             CASE WHEN o.order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW') THEN 0 ELSE 1 END,
             o.created_at DESC, o.order_id DESC"""
    )
    orders = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return orders


# =====================================================================
# --- Management: user control, wallet control, security, audit ---
# (kept separate from the P2P section above: user management and wallet
#  operations are isolated concerns; both write to the immutable audit log)
# =====================================================================
WITHDRAW_STATUSES = ("PENDING", "PROCESSING", "COMPLETED", "FAILED", "CANCELLED")
_WD_TRANSITIONS = {
    "PENDING": {"PROCESSING", "COMPLETED", "FAILED", "CANCELLED"},
    "PROCESSING": {"COMPLETED", "FAILED", "CANCELLED"},
}

def ensure_mgmt_tables():
    conn = get_connection()
    cur = conn.cursor()
    # account + wallet control flags live on login_users (TID is the only key)
    cur.execute("ALTER TABLE IF EXISTS login_users ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'")
    cur.execute("ALTER TABLE IF EXISTS login_users ADD COLUMN IF NOT EXISTS wallet_frozen BOOLEAN NOT NULL DEFAULT FALSE")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS deleted_users (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            username TEXT,
            realn TEXT,
            role INTEGER,
            wallet_addresses TEXT,
            derivation_index INTEGER,
            registration_date TIMESTAMP,
            account_status VARCHAR(16),
            wallet_status VARCHAR(16),
            trade_stats TEXT,
            balance_info TEXT,
            full_snapshot TEXT,
            deleted_by TEXT NOT NULL,
            deleted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_action (
            id SERIAL PRIMARY KEY,
            admin_username TEXT NOT NULL,
            action_type VARCHAR(40) NOT NULL,
            target_tid TEXT,
            ip_address TEXT,
            notes TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # audit records are immutable: a DB trigger rejects UPDATE and DELETE
    cur.execute("""
        CREATE OR REPLACE FUNCTION admin_action_immutable() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'admin_action audit records are immutable';
        END;
        $$ LANGUAGE plpgsql
    """)
    cur.execute("DROP TRIGGER IF EXISTS admin_action_protect ON admin_action")
    cur.execute("""
        CREATE TRIGGER admin_action_protect BEFORE UPDATE OR DELETE ON admin_action
        FOR EACH ROW EXECUTE FUNCTION admin_action_immutable()
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key VARCHAR(40) PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # withdrawal queue metadata: type, fees, broadcast hash, auto-processing flags
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS withdraw_type VARCHAR(12) NOT NULL DEFAULT 'ONCHAIN'")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS fee_network NUMERIC(30, 8) NOT NULL DEFAULT 0")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS fee_platform NUMERIC(30, 8) NOT NULL DEFAULT 0")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS final_amount NUMERIC(30, 8)")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS tx_hash TEXT")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS auto BOOLEAN NOT NULL DEFAULT FALSE")
    cur.execute("ALTER TABLE IF EXISTS withdraw ADD COLUMN IF NOT EXISTS review_reason TEXT")
    # platform earnings ledger (withdrawal fees, future revenue sources)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS profit (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            transaction_id INTEGER,
            source VARCHAR(40) NOT NULL,
            amount NUMERIC(30, 8) NOT NULL,
            related_withdraw_id INTEGER,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # indexed queries for scale — each wrapped individually because tables like
    # withdraw and transaction are created by crypto_engine.py and may not exist yet
    for idx in (
        "CREATE INDEX IF NOT EXISTS idx_profit_time ON profit (created_at)",
        "CREATE INDEX IF NOT EXISTS idx_profit_source ON profit (source)",
        "CREATE INDEX IF NOT EXISTS idx_withdraw_created ON withdraw (created_at)",
        "CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders (seller_tid)",
        "CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders (buyer_tid)",
        "CREATE INDEX IF NOT EXISTS idx_orders_status ON orders (order_status)",
        "CREATE INDEX IF NOT EXISTS idx_ads_merchant ON ads (merchant_tid)",
        "CREATE INDEX IF NOT EXISTS idx_ads_status ON ads (status)",
        "CREATE INDEX IF NOT EXISTS idx_withdraw_tid ON withdraw (tid)",
        "CREATE INDEX IF NOT EXISTS idx_withdraw_status ON withdraw (status)",
        "CREATE INDEX IF NOT EXISTS idx_p2p_message_order ON p2p_message (order_id)",
        "CREATE INDEX IF NOT EXISTS idx_admin_action_time ON admin_action (created_at)",
        "CREATE INDEX IF NOT EXISTS idx_transaction_tid ON transaction (tid)",
    ):
        try:
            cur.execute(idx)
        except Exception:
            pass  # table not created yet by crypto_engine.py — index will be added on next restart
    conn.commit()
    cur.close()
    release_connection(conn)
    ensure_contact_table()
    ensure_response_table()

# --- Audit log (append-only) ---
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

# --- User control ---
def get_user_flags(tid):
    """One-query account gate: returns {'status', 'wallet_frozen', 'usertype'} or None if unregistered."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, wallet_frozen, usertype FROM login_users WHERE tid = %s", (str(tid),))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    if not row:
        return None
    return {"status": row[0], "wallet_frozen": row[1], "usertype": row[2]}

def set_user_status(tid, status):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE login_users SET status = %s WHERE tid = %s", (status, str(tid)))
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    release_connection(conn)
    return ok

def set_user_role(tid, usertype):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE login_users SET usertype = %s WHERE tid = %s", (int(usertype), str(tid)))
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    release_connection(conn)
    if ok:
        # A Merchant ID (MID) is the merchant's public identity in /ads — it is
        # minted on promotion and revoked the moment they drop back to a normal
        # user, so only current merchants ever carry one.
        if int(usertype) == 2:
            get_or_create_merchant_id(tid)
        else:
            revoke_merchant_id(tid)
    return ok

# =====================================================================
# --- Merchant IDs (MID) — a merchant's public handle, shown in /ads
# instead of their real name. Lives in its own table so the postgres-owned
# user table never needs an ALTER, and so "revoke" is a simple row delete.
# =====================================================================
_MID_READY = False

# MIDs are random (e.g. MID-7QF3K9ZP), not sequential, so they reveal nothing
# about how many merchants exist or their order. Length 12 ("MID-" + 8 chars)
# never matches the old "MID-#####" sequential form, which lets us detect and
# replace any leftover sequential ids exactly once.
def _random_mid(cur) -> str:
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(50):
        mid = "MID-" + "".join(secrets.choice(alphabet) for _ in range(8))
        cur.execute("SELECT 1 FROM merchant_ids WHERE mid = %s", (mid,))
        if not cur.fetchone():
            return mid
    raise RuntimeError("could not allocate a unique MID")

def ensure_merchant_id_table():
    global _MID_READY
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS merchant_ids (
                seq SERIAL,
                tid TEXT PRIMARY KEY,
                mid TEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Make sure every current merchant has a row (covers merchants promoted
        # before this feature existed).
        cur.execute("""INSERT INTO merchant_ids (tid)
                       SELECT tid FROM login_users WHERE usertype = 2
                       ON CONFLICT (tid) DO NOTHING""")
        # Assign a random MID to any row missing one OR still on the old
        # sequential "MID-#####" format (one-time replacement).
        cur.execute("SELECT tid FROM merchant_ids WHERE mid IS NULL OR mid = '' OR mid ~ '^MID-[0-9]{5}$'")
        for (mtid,) in cur.fetchall():
            cur.execute("UPDATE merchant_ids SET mid = %s WHERE tid = %s", (_random_mid(cur), mtid))
        conn.commit()
        cur.close()
        _MID_READY = True
    except Exception:
        conn.rollback()
        raise
    finally:
        release_connection(conn)

def _ensure_mid():
    if not _MID_READY:
        ensure_merchant_id_table()

def get_or_create_merchant_id(tid):
    """Return the merchant's MID, minting a fresh random one if absent.
    Never raises — returns None if the MID store is unavailable."""
    try:
        _ensure_mid()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT mid FROM merchant_ids WHERE tid = %s", (str(tid),))
            row = cur.fetchone()
            if row and row[0]:
                mid = row[0]
            else:
                mid = _random_mid(cur)
                cur.execute(
                    "INSERT INTO merchant_ids (tid, mid) VALUES (%s, %s) "
                    "ON CONFLICT (tid) DO UPDATE SET mid = EXCLUDED.mid",
                    (str(tid), mid))
            conn.commit()
            cur.close()
            return mid
        except Exception:
            conn.rollback()
            raise
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_or_create_merchant_id failed for {tid}: {e}")
        return None

def get_merchant_id(tid):
    """Read-only: the merchant's MID, or None (also None on any error, so callers
    can safely fall back to the TID without risking the request)."""
    try:
        _ensure_mid()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT mid FROM merchant_ids WHERE tid = %s", (str(tid),))
            row = cur.fetchone()
            cur.close()
            return row[0] if row else None
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_merchant_id failed for {tid}: {e}")
        return None

def get_merchant_ids_map(tids):
    """{tid: mid} for the given tids — one query, for the /ads listing. Returns
    {} on any error so the listing still renders (falling back to TIDs)."""
    if not tids:
        return {}
    try:
        _ensure_mid()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT tid, mid FROM merchant_ids WHERE tid = ANY(%s::text[])", ([str(t) for t in tids],))
            out = {r[0]: r[1] for r in cur.fetchall()}
            cur.close()
            return out
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_merchant_ids_map failed: {e}")
        return {}

def get_usernames_map(tids):
    """{tid: username} for the given tids — one query, for the /ads listing so each
    ad can show the merchant's public username (and build their avatar initial).
    Returns {} on any error so the listing still renders."""
    if not tids:
        return {}
    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT tid, username FROM login_users WHERE tid = ANY(%s::text[])",
                        ([str(t) for t in tids],))
            out = {r[0]: (r[1] or "") for r in cur.fetchall()}
            cur.close()
            return out
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_usernames_map failed: {e}")
        return {}

def get_tid_by_mid(mid):
    """Reverse lookup tid <- MID (MIDs are the public merchant handle shown in the
    market). Returns the tid string or None. Never raises — None on any error so a
    bad/unknown MID just yields 'no avatar'."""
    if not mid:
        return None
    try:
        _ensure_mid()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT tid FROM merchant_ids WHERE mid = %s", (str(mid),))
            row = cur.fetchone()
            cur.close()
            return row[0] if row else None
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_tid_by_mid failed: {e}")
        return None

# =====================================================================
# --- User profile pictures (avatars) ---
# A user may upload one profile photo through the Mini App (Account screen). It is
# shown on their own account, on their ad cards in the market, and to the other
# party inside an active order. Stored in its own app-owned table (login_users is
# postgres-owned and can't be ALTERed by the app role). Images are validated and
# RE-ENCODED to JPEG by the web layer before they ever reach here, so what we store
# is always a clean raster image — never SVG/HTML (the XSS guard lives there).
# =====================================================================
def ensure_user_avatar_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_avatars (
            tid TEXT PRIMARY KEY,
            image BYTEA NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'image/jpeg',
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    release_connection(conn)

def set_user_avatar(tid, image_bytes, content_type='image/jpeg'):
    """Insert or replace a user's avatar (one row per tid)."""
    ensure_user_avatar_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO user_avatars (tid, image, content_type, updated_at)
               VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
           ON CONFLICT (tid) DO UPDATE
               SET image = EXCLUDED.image,
                   content_type = EXCLUDED.content_type,
                   updated_at = CURRENT_TIMESTAMP""",
        (str(tid), psycopg2.Binary(image_bytes), content_type or 'image/jpeg')
    )
    conn.commit()
    cur.close()
    release_connection(conn)

def get_user_avatar(tid):
    """(image_bytes, content_type) for the user's avatar, or None if they have none."""
    ensure_user_avatar_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT image, content_type FROM user_avatars WHERE tid = %s", (str(tid),))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    if not row:
        return None
    img = row[0]
    if isinstance(img, memoryview):
        img = img.tobytes()
    return (bytes(img), row[1] or 'image/jpeg')

def delete_user_avatar(tid):
    """Remove the user's avatar (revert to the initial-letter placeholder)."""
    ensure_user_avatar_table()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM user_avatars WHERE tid = %s", (str(tid),))
    conn.commit()
    cur.close()
    release_connection(conn)

def get_avatar_tids(tids):
    """Set of tids (from the given list) that have an avatar — one query for the
    ads listing so each card knows whether to show a photo. set() on any error."""
    if not tids:
        return set()
    try:
        ensure_user_avatar_table()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT tid FROM user_avatars WHERE tid = ANY(%s::text[])",
                        ([str(t) for t in tids],))
            out = {r[0] for r in cur.fetchall()}
            cur.close()
            return out
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"get_avatar_tids failed: {e}")
        return set()

def has_user_avatar(tid):
    """True when the user has uploaded an avatar. Never raises (False on error)."""
    return str(tid) in get_avatar_tids([tid])

def revoke_merchant_id(tid):
    """Drop the MID when a merchant becomes a normal user again. Never raises."""
    try:
        _ensure_mid()
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM merchant_ids WHERE tid = %s", (str(tid),))
            conn.commit()
            cur.close()
        except Exception:
            conn.rollback()
            raise
        finally:
            release_connection(conn)
    except Exception as e:
        logging.warning(f"revoke_merchant_id failed for {tid}: {e}")

# --- Wallet control (separate from account control) ---
def set_wallet_frozen(tid, frozen: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE login_users SET wallet_frozen = %s WHERE tid = %s", (bool(frozen), str(tid)))
    ok = cur.rowcount > 0
    conn.commit()
    cur.close()
    release_connection(conn)
    return ok

def is_global_freeze() -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM system_settings WHERE key = 'global_freeze'")
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    return bool(row and row[0] == "1")

def set_global_freeze(enabled: bool):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO system_settings (key, value) VALUES ('global_freeze', %s)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP""",
        ("1" if enabled else "0",)
    )
    conn.commit()
    cur.close()
    release_connection(conn)

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

# =====================================================================
# --- Per-network on/off switch (emergency control) ---
# Lets an admin disable a specific network for deposits and/or withdrawals
# (e.g. when that chain's gas reserve runs dry) and show users a custom message
# instead of the normal flow. State lives in network_status.
# =====================================================================
NETWORK_CODES = ["BSC", "ETH", "POLYGON", "TRON", "TON"]
_NET_STATUS_READY = False

def ensure_network_status_table():
    global _NET_STATUS_READY
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS network_status (
            network VARCHAR(16) PRIMARY KEY,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            scope VARCHAR(16) NOT NULL DEFAULT 'BOTH',
            message TEXT,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    for code in NETWORK_CODES:
        cur.execute(
            "INSERT INTO network_status (network, active) VALUES (%s, TRUE) ON CONFLICT (network) DO NOTHING",
            (code,))
    conn.commit()
    cur.close()
    release_connection(conn)
    _NET_STATUS_READY = True

def _ensure_net_status():
    # Self-heal: create + seed on first use, so this works even if the startup
    # table-setup block was aborted before reaching it.
    if not _NET_STATUS_READY:
        ensure_network_status_table()

def get_network_status_all():
    _ensure_net_status()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT network, active, scope, message, updated_at FROM network_status ORDER BY network")
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def set_network_status(network, active, scope="BOTH", message=None):
    _ensure_net_status()
    network = (network or "").upper()
    scope = (scope or "BOTH").upper()
    if scope not in ("BOTH", "DEPOSIT", "WITHDRAW"):
        scope = "BOTH"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO network_status (network, active, scope, message, updated_at)
           VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
           ON CONFLICT (network) DO UPDATE SET
               active = EXCLUDED.active, scope = EXCLUDED.scope,
               message = EXCLUDED.message, updated_at = CURRENT_TIMESTAMP""",
        (network, bool(active), scope, (message or None)))
    conn.commit()
    cur.close()
    release_connection(conn)

def get_network_status_map():
    """{network: {'active': bool, 'scope': str, 'message': str|None}} — one query,
    for building the deposit/withdraw/wallet views without per-network round-trips."""
    _ensure_net_status()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT network, active, scope, message FROM network_status")
    out = {r[0]: {"active": bool(r[1]), "scope": (r[2] or "BOTH"), "message": r[3]}
           for r in cur.fetchall()}
    cur.close()
    release_connection(conn)
    return out

def network_action_allowed(network, action):
    """Is `action` ('DEPOSIT' | 'WITHDRAW') currently allowed on `network`?
    Returns (ok: bool, message: str|None). Blocked only when the network is
    inactive AND its disable-scope covers this action (BOTH or the matching one).
    The message is the admin's custom note to show the user, or None."""
    _ensure_net_status()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT active, scope, message FROM network_status WHERE network = %s",
                ((network or "").upper(),))
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    if not row or row[0]:
        return True, None                      # unknown or active -> allowed
    scope = (row[1] or "BOTH").upper()
    if scope == "BOTH" or scope == (action or "").upper():
        return False, (row[2] or None)
    return True, None

def closed_networks_for_ads():
    """Set of network codes the admin has turned off. A closed network cannot
    host new ads and any active ad using it is ghosted. We treat *inactive* as
    closed regardless of the deposit/withdraw scope — a network that is off for
    trading shouldn't accept new trades on any side."""
    return {n for n, s in get_network_status_map().items() if not s["active"]}

def set_ad_status(ad_id, status):
    """Flip an ad's status without touching the SELL fund lock (used to ghost /
    un-ghost ads when a network closes/opens — the lock must persist so the ad
    can resume instantly)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE ads SET status = %s WHERE id = %s", (status, ad_id))
    conn.commit()
    cur.close()
    release_connection(conn)

def reconcile_ads_for_networks():
    """Bring every ad in line with the current network on/off state, called
    whenever an admin toggles a network:
      • an ACTIVE ad that uses a now-closed network  -> GHOST (hidden from /ads,
        owner keeps it in /my_ads, SELL lock untouched);
      • a GHOST ad whose networks are ALL open again -> ACTIVE.
    Returns {'ghosted': [...], 'restored': [...]} of {id, merchant_tid, ad_type}
    so the caller can notify each owner."""
    _ensure_net_status()
    closed = closed_networks_for_ads()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, merchant_tid, ad_type, status FROM ads WHERE status IN ('ACTIVE', 'GHOST')")
    ads = cur.fetchall()
    net_map = _load_ad_networks_map(cur, [a[0] for a in ads])
    ghosted, restored = [], []
    for ad_id, mtid, ad_type, status in ads:
        nets = [n for n in (net_map.get(ad_id) or []) if n]
        has_closed = any(n in closed for n in nets)
        if status == "ACTIVE" and has_closed:
            cur.execute("UPDATE ads SET status = 'GHOST' WHERE id = %s", (ad_id,))
            ghosted.append({"id": ad_id, "merchant_tid": mtid, "ad_type": ad_type})
        elif status == "GHOST" and nets and not has_closed:
            cur.execute("UPDATE ads SET status = 'ACTIVE' WHERE id = %s", (ad_id,))
            restored.append({"id": ad_id, "merchant_tid": mtid, "ad_type": ad_type})
    conn.commit()
    cur.close()
    release_connection(conn)
    if ghosted or restored:
        _p2p_trace("Ads Reconciled", {"ghosted": [a["id"] for a in ghosted],
                                      "restored": [a["id"] for a in restored]})
    return {"ghosted": ghosted, "restored": restored}

def withdraw_allowed(tid):
    """Every withdrawal security gate in one place. Returns (ok, reason);
    reason in: UNKNOWN_USER, SUSPENDED, FROZEN, GLOBAL_FREEZE, PENDING_WITHDRAWAL, ACTIVE_ORDER."""
    flags = get_user_flags(tid)
    if not flags:
        return False, "UNKNOWN_USER"
    if flags["status"] == "SUSPENDED":
        return False, "SUSPENDED"
    if flags["wallet_frozen"]:
        return False, "FROZEN"
    if is_global_freeze():
        return False, "GLOBAL_FREEZE"
    if has_pending_withdrawal(tid):
        return False, "PENDING_WITHDRAWAL"
    if get_active_order(tid):
        return False, "ACTIVE_ORDER"
    return True, ""

# --- Withdrawal queue ---
def has_pending_withdrawal(tid) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM withdraw WHERE tid = %s AND status IN ('PENDING', 'PROCESSING') LIMIT 1", (str(tid),))
    found = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return found

def list_withdrawals(status=None, page=1, limit=25):
    conn = get_connection()
    cur = conn.cursor()
    if status:
        cur.execute("SELECT COUNT(*) FROM withdraw WHERE status = %s", (status,))
        total = cur.fetchone()[0]
        cur.execute("SELECT * FROM withdraw WHERE status = %s ORDER BY id DESC LIMIT %s OFFSET %s",
                    (status, limit, (page - 1) * limit))
    else:
        cur.execute("SELECT COUNT(*) FROM withdraw")
        total = cur.fetchone()[0]
        cur.execute("SELECT * FROM withdraw ORDER BY id DESC LIMIT %s OFFSET %s", (limit, (page - 1) * limit))
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows, total

def set_withdrawal_status(withdraw_id, new_status, tx_hash=None):
    """Queue transition with a row lock (race-proof). FAILED/CANCELLED refund the
    user's balance automatically (error recovery). COMPLETED records the platform
    fee in the profit ledger. Returns the row or None."""
    if new_status not in WITHDRAW_STATUSES:
        return None
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM withdraw WHERE id = %s FOR UPDATE", (withdraw_id,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return None
        cols = [d[0] for d in cur.description]
        wd = dict(zip(cols, row))
        if new_status not in _WD_TRANSITIONS.get(wd["status"], set()):
            conn.rollback()
            return None
        cur.execute("UPDATE withdraw SET status = %s, tx_hash = COALESCE(%s, tx_hash) WHERE id = %s",
                    (new_status, tx_hash, withdraw_id))
        if new_status in ("FAILED", "CANCELLED"):
            # automatic recovery: the FULL gross that was debited (amount + fees,
            # since fees are charged on top of the withdrawal) returns to the
            # user's spendable balance.
            refund = (Decimal(str(wd["amount"]))
                      + Decimal(str(wd.get("fee_network") or 0))
                      + Decimal(str(wd.get("fee_platform") or 0)))
            cur.execute(
                """INSERT INTO balance (tid, token, amount) VALUES (%s, %s, %s)
                   ON CONFLICT (tid, token) DO UPDATE SET
                       amount = balance.amount + EXCLUDED.amount,
                       updated_at = CURRENT_TIMESTAMP""",
                (wd["tid"], wd["token"], refund)
            )
            cur.execute("UPDATE user_wallet SET usdt_balance = usdt_balance + %s WHERE tid = %s",
                        (refund, wd["tid"]))
        if new_status == "COMPLETED":
            # Both fees become realized profit on completion: the 1% platform fee
            # (WITHDRAW_FEE) plus the flat network fee (WITHDRAW_NETWORK_FEE). Both
            # are charged in USDT and retained in custody — the native gas the
            # network fee offsets is paid separately from the master wallet — so
            # the full fee is platform revenue.
            if wd.get("fee_platform") and Decimal(str(wd["fee_platform"])) > 0:
                cur.execute(
                    "INSERT INTO profit (tid, source, amount, related_withdraw_id) VALUES (%s, 'WITHDRAW_FEE', %s, %s)",
                    (wd["tid"], wd["fee_platform"], withdraw_id)
                )
            if wd.get("fee_network") and Decimal(str(wd["fee_network"])) > 0:
                cur.execute(
                    "INSERT INTO profit (tid, source, amount, related_withdraw_id) VALUES (%s, 'WITHDRAW_NETWORK_FEE', %s, %s)",
                    (wd["tid"], wd["fee_network"], withdraw_id)
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)
    _p2p_trace("Withdrawal Status", {"id": withdraw_id, "from": wd["status"], "to": new_status,
                                     "tid": wd["tid"], "amount": str(wd["amount"])})
    wd["status"] = new_status
    if tx_hash:
        wd["tx_hash"] = tx_hash
    return wd

# --- User directory / profile ---
def search_users(q="", page=1, limit=15):
    """Search by TID, username, real name, or any wallet address."""
    where, params = "", []
    if q:
        like = f"%{q}%"
        where = """WHERE l.tid ILIKE %s OR l.username ILIKE %s OR l.realn ILIKE %s
                   OR uw.evm_address ILIKE %s OR uw.tron_address ILIKE %s OR uw.ton_address ILIKE %s"""
        params = [like] * 6
    base = f"""FROM login_users l
               LEFT JOIN user_wallet uw ON uw.tid = l.tid
               LEFT JOIN balance b ON b.tid = l.tid AND b.token = 'USDT' {where}"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) {base}", params)
    total = cur.fetchone()[0]
    cur.execute(
        f"""SELECT l.tid, l.username, l.realn, l.usertype, l.status, l.wallet_frozen,
                   l.created_at, l.last_seen, COALESCE(b.amount, 0) AS amount,
                   COALESCE(b.locked, 0) AS locked,
                   EXISTS(SELECT 1 FROM verification_requests v
                          WHERE v.tid = l.tid AND v.status = 'APPROVED') AS verified
            {base} ORDER BY l.id DESC LIMIT %s OFFSET %s""",
        params + [limit, (page - 1) * limit]
    )
    users = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return users, total

def get_user_profile(tid):
    tid = str(tid)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""SELECT tid, name, realn, username, usertype, status, wallet_frozen,
                          created_at, last_seen FROM login_users WHERE tid = %s""", (tid,))
    user = _row_to_dict(cur)
    if not user:
        cur.close()
        release_connection(conn)
        return None
    cur.execute("SELECT EXISTS(SELECT 1 FROM verification_requests WHERE tid = %s AND status = 'APPROVED')", (tid,))
    user["verified"] = bool(cur.fetchone()[0])
    cur.execute("""SELECT id, status, reason, id_front_file_id, id_back_file_id,
                          selfie_file_id, created_at
                   FROM verification_requests WHERE tid = %s ORDER BY id DESC""", (tid,))
    user["verifications"] = _rows_to_dicts(cur)
    cur.execute("SELECT amount, locked FROM balance WHERE tid = %s AND token = 'USDT'", (tid,))
    bal = cur.fetchone() or (Decimal("0"), Decimal("0"))
    cur.execute("SELECT evm_address, tron_address, ton_address, derivation_index FROM user_wallet WHERE tid = %s", (tid,))
    w = cur.fetchone()
    cur.execute("""SELECT id, ad_type, min_amount, max_amount, price_per_usdt, status
                   FROM ads WHERE merchant_tid = %s AND status = 'ACTIVE' ORDER BY id DESC""", (tid,))
    open_ads = _rows_to_dicts(cur)
    cur.execute("""SELECT order_id, seller_rname, buyer_rname, usdt_amount, fiat_amount, order_status
                   FROM orders WHERE (seller_tid = %s OR buyer_tid = %s)
                   AND order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW') ORDER BY created_at DESC, order_id DESC""", (tid, tid))
    open_orders = _rows_to_dicts(cur)
    cur.execute("""SELECT COUNT(*) FROM orders WHERE (seller_tid = %s OR buyer_tid = %s)
                   AND order_status = 'COMPLETED'""", (tid, tid))
    completed = cur.fetchone()[0]
    cur.execute("SELECT status, COUNT(*) FROM withdraw WHERE tid = %s GROUP BY status", (tid,))
    wd_counts = dict(cur.fetchall())
    cur.close()
    release_connection(conn)
    user.update({
        "balance": bal[0], "locked": bal[1],
        "wallets": {"EVM": w[0], "TRON": w[1], "TON": w[2], "derivation_index": w[3]} if w else None,
        "open_ads": open_ads, "open_orders": open_orders,
        "completed_trades": completed, "withdrawal_counts": wd_counts,
    })
    return user

# --- Atomic account deletion ---
def delete_user_atomic(tid, deleted_by):
    """Snapshots everything about a user into deleted_users, then removes all of
    their rows from the active tables — in ONE transaction. Any failure rolls
    back completely. Refuses while the user has an active order (counterparty
    escrow would be orphaned). Returns (ok, reason)."""
    tid = str(tid)
    if get_active_order(tid):
        return False, "User has an active order. Resolve it first (Requested Admin or /order)."
    # Ensure the verification table exists BEFORE the delete transaction, so the
    # verification_requests cleanup inside it can run unconditionally without a
    # missing-table error poisoning the whole transaction.
    ensure_verification_request_table()
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM login_users WHERE tid = %s FOR UPDATE", (tid,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, "User not found."
        cols = [d[0] for d in cur.description]
        user = dict(zip(cols, row))

        def grab(sql_text, params):
            cur.execute(sql_text, params)
            c = [d[0] for d in cur.description]
            return [dict(zip(c, r)) for r in cur.fetchall()]

        wallets = grab("SELECT * FROM user_wallet WHERE tid = %s", (tid,))
        balances = grab("SELECT * FROM balance WHERE tid = %s", (tid,))
        ads_rows = grab("SELECT * FROM ads WHERE merchant_tid = %s", (tid,))
        orders_rows = grab("SELECT * FROM orders WHERE seller_tid = %s OR buyer_tid = %s", (tid, tid))
        withdraws = grab("SELECT * FROM withdraw WHERE tid = %s", (tid,))
        txs = grab('SELECT * FROM "transaction" WHERE tid = %s', (tid,))
        cur.execute("""SELECT COUNT(*) FILTER (WHERE order_status = 'COMPLETED'), COUNT(*)
                       FROM orders WHERE seller_tid = %s OR buyer_tid = %s""", (tid, tid))
        ok_n, total_n = cur.fetchone()

        snapshot = json.dumps({
            "login_user": user, "user_wallet": wallets, "balance": balances,
            "ads": ads_rows, "orders": orders_rows, "withdraw": withdraws,
            "transactions": txs,
        }, default=str)
        wallet_addresses = json.dumps(
            {"EVM": wallets[0]["evm_address"], "TRON": wallets[0]["tron_address"],
             "TON": wallets[0]["ton_address"]} if wallets else {})

        cur.execute(
            """INSERT INTO deleted_users (tid, username, realn, role, wallet_addresses,
                   derivation_index, registration_date, account_status, wallet_status,
                   trade_stats, balance_info, full_snapshot, deleted_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (tid, user.get("username"), user.get("realn"), user.get("usertype"),
             wallet_addresses,
             wallets[0]["derivation_index"] if wallets else None,
             user.get("created_at"), user.get("status", "ACTIVE"),
             "FROZEN" if user.get("wallet_frozen") else "ACTIVE",
             json.dumps({"completed_trades": ok_n, "total_trades": total_n}),
             json.dumps(balances, default=str), snapshot, str(deleted_by))
        )
        # remove every related record (children first, login_users last for the FK)
        cur.execute("""DELETE FROM p2p_message WHERE sender_tid = %s
                       OR order_id IN (SELECT order_id FROM orders WHERE seller_tid = %s OR buyer_tid = %s)""",
                    (tid, tid, tid))
        cur.execute("DELETE FROM orders WHERE seller_tid = %s OR buyer_tid = %s", (tid, tid))
        cur.execute("DELETE FROM ads WHERE merchant_tid = %s", (tid,))
        cur.execute("DELETE FROM withdraw WHERE tid = %s", (tid,))
        cur.execute('DELETE FROM "transaction" WHERE tid = %s', (tid,))
        cur.execute("DELETE FROM balance WHERE tid = %s", (tid,))
        cur.execute("DELETE FROM user_wallet WHERE tid = %s", (tid,))
        # Verification rows must go too, or a re-created account on the same TID
        # would inherit the old APPROVED status and read as already verified.
        # (The table is ensured before this transaction starts, so this is safe.)
        cur.execute("DELETE FROM verification_requests WHERE tid = %s", (tid,))
        cur.execute("DELETE FROM start_users WHERE tid = %s", (tid,))
        cur.execute("DELETE FROM login_users WHERE tid = %s", (tid,))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"delete_user_atomic({tid}) rolled back: {e}")
        return False, f"Deletion failed and was rolled back: {e}"
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)
    _p2p_trace("User Deleted", {"tid": tid, "by": str(deleted_by)})
    return True, ""

def get_security_stats():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*),
                          COUNT(*) FILTER (WHERE status = 'SUSPENDED'),
                          COUNT(*) FILTER (WHERE wallet_frozen)
                   FROM login_users""")
    total, suspended, frozen = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM withdraw WHERE status IN ('PENDING', 'PROCESSING')")
    pending_wd = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM orders WHERE order_status IN ('ACTIVE', 'PAID', 'ADMIN_REVIEW')")
    active_orders = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return {"total_users": total, "suspended_users": suspended, "frozen_wallets": frozen,
            "pending_withdrawals": pending_wd, "active_orders": active_orders,
            "global_freeze": is_global_freeze()}


# =====================================================================
# --- Withdrawal automation: daily limit, auto queue, approval ---
# =====================================================================
DAILY_WITHDRAW_LIMIT = Decimal("500")   # USDT per rolling 24h; above this -> security review

def get_daily_withdrawn(tid):
    """Total ONCHAIN USDT the user requested in the last 24h (failed/cancelled excluded)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT COALESCE(SUM(amount), 0) FROM withdraw
           WHERE tid = %s AND withdraw_type = 'ONCHAIN'
             AND status NOT IN ('FAILED', 'CANCELLED')
             AND created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'""",
        (str(tid),)
    )
    total = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    return total

def withdrawal_requires_review(tid, amount) -> bool:
    """True when this request pushes the user's rolling-24h total above the limit."""
    return get_daily_withdrawn(tid) + Decimal(str(amount)) > DAILY_WITHDRAW_LIMIT

def get_auto_pending_withdrawals(limit=5):
    """Rows the automatic processor should broadcast now."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT * FROM withdraw
           WHERE status = 'PENDING' AND auto = TRUE AND review_reason IS NULL
             AND withdraw_type = 'ONCHAIN'
           ORDER BY id ASC LIMIT %s""",
        (limit,)
    )
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def get_recent_onchain_withdrawals(limit=15):
    """Recent on-chain withdrawals — what the gas reserve is actually being spent
    on. Powers the Gas panel's 'where the gas is going' list."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, tid, network, amount, final_amount, status, wallet_address,
                  review_reason, created_at
           FROM withdraw
           WHERE withdraw_type = 'ONCHAIN'
           ORDER BY id DESC LIMIT %s""",
        (limit,)
    )
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows

def approve_withdrawal(withdraw_id):
    """Admin approval of a review-flagged withdrawal: clears the flag and hands the
    row to the automatic processor. Returns the row or None."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE withdraw SET review_reason = NULL, auto = TRUE
           WHERE id = %s AND status = 'PENDING' RETURNING *""",
        (withdraw_id,)
    )
    wd = _row_to_dict(cur)
    conn.commit()
    cur.close()
    release_connection(conn)
    if wd:
        _p2p_trace("Withdrawal Approved", {"id": withdraw_id, "tid": wd["tid"], "amount": str(wd["amount"])})
    return wd

def flag_withdraw_review(withdraw_id, reason):
    """Auto-processing failed: push the row back to PENDING with the failure reason
    so an admin can retry (approve) or cancel (auto-refund). Funds stay debited."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE withdraw SET status = 'PENDING', auto = FALSE, review_reason = %s WHERE id = %s",
        (str(reason)[:500], withdraw_id)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Withdrawal Flagged For Review", {"id": withdraw_id, "reason": str(reason)[:120]})


def record_withdraw_broadcast(withdraw_id, tx_hash):
    """Append a broadcast tx hash to a withdrawal AS SOON AS each leg is sent, so a
    crash or failure midway through a multi-leg send leaves a durable on-row trace.
    auto_process_withdraw refuses to re-broadcast any row that already carries a
    hash, which is what prevents a double-spend when an admin retries a row whose
    first leg already left custody."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """UPDATE withdraw
           SET tx_hash = CASE WHEN tx_hash IS NULL OR tx_hash = ''
                              THEN %s ELSE tx_hash || ',' || %s END
           WHERE id = %s""",
        (str(tx_hash), str(tx_hash), withdraw_id)
    )
    conn.commit()
    cur.close()
    release_connection(conn)


# =====================================================================
# --- Profit ledger (platform earnings) ---
# =====================================================================
def record_profit(tid, source, amount, related_withdraw_id=None, transaction_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO profit (tid, source, amount, related_withdraw_id, transaction_id)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (str(tid), source, Decimal(str(amount)), related_withdraw_id, transaction_id)
    )
    pid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    release_connection(conn)
    _p2p_trace("Profit Recorded", {"id": pid, "tid": str(tid), "source": source, "amount": str(amount)})
    return pid

def get_profit_stats():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""SELECT COALESCE(SUM(amount), 0),
                          COALESCE(SUM(amount) FILTER (WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'), 0),
                          COALESCE(SUM(amount) FILTER (WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '30 days'), 0)
                   FROM profit""")
    total, daily, monthly = cur.fetchone()
    cur.execute("SELECT source, COALESCE(SUM(amount), 0), COUNT(*) FROM profit GROUP BY source ORDER BY 2 DESC")
    by_source = {r[0]: {"amount": r[1], "count": r[2]} for r in cur.fetchall()}
    cur.close()
    release_connection(conn)
    wf = by_source.get("WITHDRAW_FEE", {"amount": Decimal("0"), "count": 0})
    wnf = by_source.get("WITHDRAW_NETWORK_FEE", {"amount": Decimal("0"), "count": 0})
    return {"total": total, "daily": daily, "monthly": monthly, "by_source": by_source,
            "withdraw_fee_income": Decimal(str(wf["amount"])) + Decimal(str(wnf["amount"]))}

def list_profits(page=1, limit=50):
    """Profit records joined to the withdrawal that produced each one, so the admin
    can see WHO it came from, HOW MUCH they withdrew, on WHICH network the fee was
    retained (where it sits in custody), and the destination + tx of that send."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM profit")
    total = cur.fetchone()[0]
    cur.execute(
        """SELECT p.id, p.tid, p.source, p.amount, p.related_withdraw_id,
                  p.transaction_id, p.created_at,
                  lu.username AS username, lu.realn AS realn,
                  w.amount AS w_amount, w.network AS w_network,
                  w.wallet_address AS w_to,
                  w.fee_network AS w_fee_network, w.fee_platform AS w_fee_platform,
                  w.tx_hash AS w_tx
           FROM profit p
           LEFT JOIN login_users lu ON lu.tid = p.tid
           LEFT JOIN withdraw w ON w.id = p.related_withdraw_id
           ORDER BY p.id DESC LIMIT %s OFFSET %s""",
        (limit, (page - 1) * limit)
    )
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    return rows, total


# =====================================================================
# --- System balance & holdings (admin System Balance section) ---
# =====================================================================
def get_system_balance():
    """Total client funds the platform currently owes (the authoritative ledger)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""SELECT COALESCE(SUM(amount), 0), COALESCE(SUM(locked), 0),
                          COUNT(*) FILTER (WHERE amount > 0)
                   FROM balance WHERE token = 'USDT'""")
    total, locked, holders = cur.fetchone()
    cur.close()
    release_connection(conn)
    return {"total": total, "locked": locked, "available": total - locked, "holders": holders}

def get_user_network_balance(tid, network):
    """Net USDT balance for a user on a specific network: deposits minus withdrawals.
    Used to validate that the user has enough on-chain balance on the chosen network."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT GREATEST(
               (SELECT COALESCE(SUM(amount), 0) FROM transaction
                WHERE tid = %s AND network = %s AND token = 'USDT'
                  AND amount > 0 AND status = 'CONFIRMED')
               -
               (SELECT COALESCE(SUM(amount), 0) FROM withdraw
                WHERE tid = %s AND network = %s AND token = 'USDT'
                  AND status NOT IN ('REJECTED', 'CANCELLED')),
               0
           )""",
        (str(tid), network, str(tid), network)
    )
    result = cur.fetchone()[0]
    cur.close()
    release_connection(conn)
    from decimal import Decimal
    return Decimal(str(result or 0))


def get_user_balance_by_network(tid):
    """Net USDT balance per network for a user (deposits minus withdrawals, floored at 0).
    Returns {network: Decimal} for all networks where the user has ever deposited."""
    conn = get_connection()
    cur = conn.cursor()
    from decimal import Decimal
    try:
        cur.execute(
            """SELECT
                   t.network,
                   GREATEST(
                       COALESCE(t.total_in, 0) - COALESCE(w.total_out, 0),
                       0
                   ) AS net_amount
               FROM (
                   SELECT network, SUM(amount) AS total_in
                   FROM transaction
                   WHERE tid = %s AND token = 'USDT' AND amount > 0
                     AND status = 'CONFIRMED' AND network NOT IN ('INTERNAL')
                   GROUP BY network
               ) t
               LEFT JOIN (
                   SELECT network, SUM(amount) AS total_out
                   FROM withdraw
                   WHERE tid = %s AND token = 'USDT'
                     AND status NOT IN ('REJECTED', 'CANCELLED')
                   GROUP BY network
               ) w ON w.network = t.network
               ORDER BY t.network""",
            (str(tid), str(tid))
        )
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    release_connection(conn)
    return {row[0]: Decimal(str(row[1] or 0)) for row in rows}


def get_user_deposit_networks(tid):
    """Returns the distinct on-chain networks this user has deposited USDT from,
    ordered by most recent deposit. Used to hint users toward the right withdrawal
    network and to inform admin emergency-transfer network selection."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT DISTINCT network FROM transaction
           WHERE tid = %s AND token = 'USDT' AND amount > 0
             AND network NOT IN ('INTERNAL')
           ORDER BY network""",
        (str(tid),)
    )
    rows = cur.fetchall()
    cur.close()
    release_connection(conn)
    return [r[0] for r in rows]


def get_balance_holders():
    """Every user holding a positive USDT ledger balance, with their deposit addresses
    and the on-chain networks where they originally deposited (for admin emergency transfer)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT l.tid, l.username, l.realn, b.amount, b.locked,
                  uw.evm_address, uw.tron_address, uw.ton_address, uw.derivation_index
           FROM balance b
           JOIN login_users l ON l.tid = b.tid
           LEFT JOIN user_wallet uw ON uw.tid = b.tid
           WHERE b.token = 'USDT' AND b.amount > 0
           ORDER BY b.amount DESC"""
    )
    rows = _rows_to_dicts(cur)
    # Attach deposit-network info for each holder in one extra query
    if rows:
        tids = [r["tid"] for r in rows]
        placeholders = ",".join(["%s"] * len(tids))
        cur.execute(
            f"""SELECT tid, network FROM transaction
                WHERE tid = ANY(ARRAY[{placeholders}]::text[])
                  AND token = 'USDT' AND amount > 0
                  AND network NOT IN ('INTERNAL')""",
            tids
        )
        net_map: dict[str, set] = {}
        for tid_val, net in cur.fetchall():
            net_map.setdefault(tid_val, set()).add(net)
        for r in rows:
            r["deposit_networks"] = sorted(net_map.get(r["tid"], set()))
    cur.close()
    release_connection(conn)
    for r in rows:
        r["available"] = r["amount"] - r["locked"]
        r.setdefault("deposit_networks", [])
    return rows


# =====================================================================
# --- Fund Ledger (real custody tracking: network + address + owner) ---
# =====================================================================

def ensure_fund_ledger_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS fund_ledger (
            id SERIAL PRIMARY KEY,
            tid TEXT NOT NULL,
            network VARCHAR(16) NOT NULL,
            custody_address TEXT NOT NULL,
            custody_index INTEGER NOT NULL,
            amount NUMERIC(30,8) NOT NULL CHECK (amount > 0),
            source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_fl_tid ON fund_ledger(tid, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_fl_addr ON fund_ledger(custody_address, network)")
    # Dedicated audit log of internal fund movements (TID->TID transfers and P2P
    # settlements). It mirrors each move's real on-chain location (network +
    # custody address) and current owner, so the transaction history can show
    # where the funds actually sit and the withdrawal engine stays consistent.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS internal_transaction (
            id SERIAL PRIMARY KEY,
            ref TEXT,
            method VARCHAR(12) NOT NULL,
            from_tid TEXT NOT NULL,
            to_tid TEXT NOT NULL,
            amount NUMERIC(30, 8) NOT NULL,
            token VARCHAR(16) NOT NULL DEFAULT 'USDT',
            network VARCHAR(16),
            custody_address TEXT,
            related_order_id INTEGER,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_itx_from ON internal_transaction(from_tid, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_itx_to ON internal_transaction(to_tid, created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_itx_method ON internal_transaction(method)")
    conn.commit()
    cur.close()
    release_connection(conn)


def log_internal_txn(cur, ref, method, from_tid, to_tid, amount, token="USDT",
                     network=None, custody_address=None, related_order_id=None):
    """Append one row to the internal_transaction audit log using the CALLER'S
    cursor, so it commits inside the caller's transaction. `method` is 'INTERNAL'
    (a TID->TID transfer / "internal withdraw") or 'P2P' (an order settlement).
    network/custody_address record the real on-chain location the moved funds
    sit at; on-chain transactions never call this (their method stays blank)."""
    cur.execute(
        """INSERT INTO internal_transaction
               (ref, method, from_tid, to_tid, amount, token, network,
                custody_address, related_order_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (ref, method, str(from_tid), str(to_tid), Decimal(str(amount)), token,
         network, custody_address, related_order_id)
    )


def _custody_index_for_address(address, cur):
    """Look up the derivation_index for a platform custody address. Returns 0 for master."""
    cur.execute(
        """SELECT derivation_index FROM user_wallet
           WHERE evm_address = %s OR tron_address = %s OR ton_address = %s LIMIT 1""",
        (address, address, address)
    )
    row = cur.fetchone()
    return row[0] if row else 0


def fund_ledger_credit(tid, network, custody_address, custody_index, amount,
                       source=None, conn=None):
    """Record that `tid` now owns `amount` USDT on `network` sitting at `custody_address`.
    Called on every confirmed deposit. `conn` allows callers to fold this into their txn."""
    owned = conn is None
    if owned:
        conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO fund_ledger
                   (tid, network, custody_address, custody_index, amount, source)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (str(tid), network, custody_address, custody_index,
             Decimal(str(amount)), source)
        )
        if owned:
            conn.commit()
    finally:
        cur.close()
        if owned:
            release_connection(conn)


def fund_ledger_transfer(from_tid, to_tid, amount, conn, network=None):
    """Transfer ownership of `amount` USDT FIFO. With `network` given, only that
    network's custody is moved (the sender chose which network to send from); with
    None it moves FIFO across all networks (the legacy P2P-release behaviour).
    Caller MUST own the transaction (no commit here). Returns the chunks moved as
    [{"network", "custody_address", "amount"}] so the caller can log each move's
    real on-chain location in internal_transaction."""
    from_tid, to_tid = str(from_tid), str(to_tid)
    remaining = Decimal(str(amount))
    moved = []
    cur = conn.cursor()
    if network:
        cur.execute(
            """SELECT id, network, custody_address, custody_index, amount
               FROM fund_ledger WHERE tid = %s AND network = %s
               ORDER BY created_at ASC FOR UPDATE""",
            (from_tid, network)
        )
    else:
        cur.execute(
            """SELECT id, network, custody_address, custody_index, amount
               FROM fund_ledger WHERE tid = %s ORDER BY created_at ASC FOR UPDATE""",
            (from_tid,)
        )
    rows = cur.fetchall()
    for row_id, network, custody_address, custody_index, row_amount in rows:
        if remaining <= 0:
            break
        row_amount = Decimal(str(row_amount))
        take = min(row_amount, remaining)
        if take == row_amount:
            cur.execute("UPDATE fund_ledger SET tid = %s WHERE id = %s", (to_tid, row_id))
        else:
            cur.execute("UPDATE fund_ledger SET amount = amount - %s WHERE id = %s",
                        (take, row_id))
            cur.execute(
                """INSERT INTO fund_ledger
                       (tid, network, custody_address, custody_index, amount, source)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (to_tid, network, custody_address, custody_index, take,
                 f"INTERNAL-FROM:{from_tid}")
            )
        moved.append({"network": network, "custody_address": custody_address, "amount": take})
        remaining -= take
    cur.close()
    return moved


def fund_ledger_consume(tid, network, amount, conn=None):
    """Reduce/delete FIFO fund_ledger entries after a successful on-chain withdrawal."""
    owned = conn is None
    if owned:
        conn = get_connection()
        conn.autocommit = False
    cur = conn.cursor()
    try:
        remaining = Decimal(str(amount))
        cur.execute(
            """SELECT id, amount FROM fund_ledger
               WHERE tid = %s AND network = %s ORDER BY created_at ASC FOR UPDATE""",
            (str(tid), network)
        )
        for row_id, row_amount in cur.fetchall():
            if remaining <= 0:
                break
            row_amount = Decimal(str(row_amount))
            if row_amount <= remaining:
                cur.execute("DELETE FROM fund_ledger WHERE id = %s", (row_id,))
                remaining -= row_amount
            else:
                cur.execute("UPDATE fund_ledger SET amount = amount - %s WHERE id = %s",
                            (remaining, row_id))
                remaining = Decimal("0")
        if owned:
            conn.commit()
    except Exception:
        if owned:
            conn.rollback()
        raise
    finally:
        cur.close()
        if owned:
            conn.autocommit = True
            release_connection(conn)


def fund_ledger_plan(tid, network, amount):
    """Which custody addresses to pull from for this user's on-chain withdrawal.
    Returns (plan, shortfall): plan = [{id, address, index, amount}] or (None, shortfall)."""
    amount = Decimal(str(amount))
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, custody_address, custody_index, amount
           FROM fund_ledger WHERE tid = %s AND network = %s ORDER BY created_at ASC""",
        (str(tid), network)
    )
    rows = cur.fetchall()
    cur.close()
    release_connection(conn)
    plan, remaining = [], amount
    for row_id, address, index, row_amount in rows:
        if remaining <= 0:
            break
        row_amount = Decimal(str(row_amount))
        take = min(row_amount, remaining)
        plan.append({"id": row_id, "address": address, "index": index, "amount": take})
        remaining -= take
    if remaining > 0:
        return None, remaining
    return plan, Decimal("0")


def fund_ledger_balance_by_network(tid):
    """Live {network: Decimal} breakdown for a user — the authoritative source for /balance."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """SELECT network, SUM(amount) FROM fund_ledger
               WHERE tid = %s GROUP BY network ORDER BY network""",
            (str(tid),)
        )
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    release_connection(conn)
    return {r[0]: Decimal(str(r[1])) for r in rows if r[1]}


def fund_ledger_available_by_network(tid):
    """Per-network USDT the user can actually act on right now: their fund_ledger
    holdings minus any in-flight (PENDING/PROCESSING) on-chain withdrawal on that
    network. This is the authoritative source for the /balance breakdown and the
    per-network withdrawal check — it stays consistent with the balance table,
    which is debited the moment a withdrawal is requested. The raw fund_ledger
    rows are left untouched until COMPLETED so the auto-processor can still read
    the exact custody addresses to sign from."""
    conn = get_connection()
    cur = conn.cursor()
    out = {}
    try:
        cur.execute(
            """SELECT network, SUM(amount) FROM fund_ledger
               WHERE tid = %s GROUP BY network""", (str(tid),))
        for net, amt in cur.fetchall():
            out[net] = Decimal(str(amt or 0))
        cur.execute(
            """SELECT network, COALESCE(SUM(amount), 0) FROM withdraw
               WHERE tid = %s AND withdraw_type = 'ONCHAIN'
                 AND status IN ('PENDING', 'PROCESSING')
               GROUP BY network""", (str(tid),))
        for net, amt in cur.fetchall():
            out[net] = out.get(net, Decimal("0")) - Decimal(str(amt or 0))
    except Exception:
        pass
    cur.close()
    release_connection(conn)
    return {n: v for n, v in out.items() if v > 0}


# =====================================================================
# --- Admin Internal Edit / balance ↔ custody reconciliation ---
# Tools for the "Internal Edit" management section. Three layers must agree:
#   • balance        — spendable ledger, what the platform OWES the user
#   • fund_ledger    — per-network CUSTODY: where that USDT physically sits
#   • on-chain       — the real USDT (scanned live by crypto_engine)
# Deleting an account can wipe its `balance` row while leaving its custody rows,
# so the two drift (the reported bug: balance 0 but funds still on-chain). These
# helpers re-sync them safely:
#   • a CREDIT raises balance, backed FIRST by the user's existing custody
#     surplus (no new custody rows — the funds are already theirs), then by any
#     remaining UN-credited on-chain funds (new fund_ledger rows). It can never
#     make total balance exceed total on-chain — the solvency cap the admin set.
#   • a DEBIT lowers balance and consumes matching custody.
# Every mutation is ONE transaction across all three layers, and NOTHING is ever
# sent to the user.
# =====================================================================

def fund_ledger_attribution_by_network():
    """Global per-network custody total currently recorded in fund_ledger — how
    much of the real on-chain USDT is already attributed to users on each network
    (per-network solvency is measured against this: custody must stay ≤ on-chain)."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT network, COALESCE(SUM(amount), 0) FROM fund_ledger GROUP BY network")
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    release_connection(conn)
    return {r[0]: Decimal(str(r[1] or 0)) for r in rows}


def fund_ledger_attribution_by_address(network):
    """{custody_address: Decimal} already credited per address on `network`. Lets
    the reconcile tool compute each address's UN-credited on-chain remainder
    (real on-chain balance at that address minus this)."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """SELECT custody_address, COALESCE(SUM(amount), 0) FROM fund_ledger
               WHERE network = %s GROUP BY custody_address""",
            (network,))
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    release_connection(conn)
    return {r[0]: Decimal(str(r[1] or 0)) for r in rows}


def backfill_withdraw_fee_profit():
    """Idempotent DB fix: ensure every COMPLETED on-chain withdrawal has its NETWORK
    fee recorded as profit. Older completions only logged the 1% platform fee, so
    the network-fee revenue was missing from the profit ledger — this inserts a
    'WITHDRAW_NETWORK_FEE' profit row for each completed withdrawal that lacks one.
    Safe to run repeatedly. Returns {added, amount}."""
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    added, amount = 0, Decimal("0")
    try:
        cur.execute(
            """SELECT w.id, w.tid, w.fee_network
               FROM withdraw w
               WHERE w.withdraw_type = 'ONCHAIN' AND w.status = 'COMPLETED'
                 AND COALESCE(w.fee_network, 0) > 0
                 AND NOT EXISTS (
                     SELECT 1 FROM profit p
                     WHERE p.related_withdraw_id = w.id AND p.source = 'WITHDRAW_NETWORK_FEE')"""
        )
        for wid, tid, fee_net in cur.fetchall():
            fee_net = Decimal(str(fee_net))
            cur.execute(
                "INSERT INTO profit (tid, source, amount, related_withdraw_id) VALUES (%s, 'WITHDRAW_NETWORK_FEE', %s, %s)",
                (str(tid), fee_net, wid)
            )
            added += 1
            amount += fee_net
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)
    return {"added": added, "amount": amount}


def withdraw_fee_revenue():
    """Returns (total, {tid: Decimal}) of the USDT withdrawal fees (network +
    platform) retained in custody from COMPLETED on-chain withdrawals.

    The fee is charged ON TOP of the amount and is NEVER broadcast — only `amount`
    leaves custody — so the fee USDT accumulates as on-chain surplus over the
    balance ledger. That surplus is the platform's fee revenue, NOT a user's
    recoverable orphan: Internal Edit subtracts it so the admin can never credit
    profit back to a user by mistake. Attributed to the withdrawing user, whose
    own custody address physically holds the leftover fee."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """SELECT tid, COALESCE(SUM(COALESCE(fee_network, 0) + COALESCE(fee_platform, 0)), 0)
               FROM withdraw
               WHERE withdraw_type = 'ONCHAIN' AND status = 'COMPLETED'
               GROUP BY tid"""
        )
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    release_connection(conn)
    by_tid = {str(r[0]): Decimal(str(r[1] or 0)) for r in rows}
    total = sum(by_tid.values(), Decimal("0"))
    return total, by_tid


def get_reconcile_users():
    """Every user that has EITHER a balance row OR custody in fund_ledger, with
    both figures side by side so the admin can see and fix drift. `gap` =
    custody − balance: when positive (e.g. a deleted/recreated account) it is the
    amount that can be recovered straight from custody the user already owns.
    Ordered by largest recoverable gap first."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """SELECT u.tid,
                  COALESCE(b.amount, 0) AS balance,
                  COALESCE(b.locked, 0) AS locked,
                  COALESCE(f.custody, 0) AS custody,
                  lu.username, lu.realn
           FROM (SELECT tid FROM balance WHERE token = 'USDT'
                 UNION SELECT tid FROM fund_ledger) u
           LEFT JOIN balance b ON b.tid = u.tid AND b.token = 'USDT'
           LEFT JOIN (SELECT tid, SUM(amount) AS custody FROM fund_ledger GROUP BY tid) f
                  ON f.tid = u.tid
           LEFT JOIN login_users lu ON lu.tid = u.tid
           ORDER BY GREATEST(COALESCE(f.custody, 0) - COALESCE(b.amount, 0), 0) DESC,
                    COALESCE(b.amount, 0) DESC"""
    )
    rows = _rows_to_dicts(cur)
    cur.close()
    release_connection(conn)
    for r in rows:
        r["balance"] = Decimal(str(r["balance"] or 0))
        r["locked"] = Decimal(str(r["locked"] or 0))
        r["custody"] = Decimal(str(r["custody"] or 0))
        r["gap"] = max(r["custody"] - r["balance"], Decimal("0"))
    return rows


def admin_reconcile_credit(tid, amount, onchain_plan=None, source="ADMIN_RECONCILE"):
    """Increase user `tid`'s spendable balance by `amount`, keeping balance ≤ custody
    so the recovered funds stay withdrawable. Backed, in ONE transaction, by:
      1) the user's existing custody SURPLUS (fund_ledger already records funds the
         balance table lost — the deleted/recreated-account case): this just raises
         balance, with no new custody rows; then
      2) any remainder from `onchain_plan` = [{network, address, index, amount}],
         real on-chain funds NOT yet in fund_ledger that the CALLER has verified —
         inserted as new fund_ledger rows so they become withdrawable custody.
    Refuses (rolls back) if surplus + plan can't cover `amount`. The legacy
    user_wallet.usdt_balance mirror is kept in sync. No user notification.
    Returns (True, new_balance) or (False, reason)."""
    amount = Decimal(str(amount))
    if amount <= 0:
        return False, "AMOUNT_INVALID"
    onchain_plan = onchain_plan or []
    EPS = Decimal("0.00000001")
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        cur.execute("SELECT COALESCE(SUM(amount), 0) FROM fund_ledger WHERE tid = %s", (str(tid),))
        custody = Decimal(str(cur.fetchone()[0]))
        cur.execute("SELECT COALESCE(amount, 0) FROM balance WHERE tid = %s AND token = 'USDT'", (str(tid),))
        row = cur.fetchone()
        bal = Decimal(str(row[0])) if row else Decimal("0")
        surplus = max(custody - bal, Decimal("0"))
        plan_total = sum((Decimal(str(p["amount"])) for p in onchain_plan), Decimal("0"))
        if surplus + plan_total + EPS < amount:
            conn.rollback()
            return False, "INSUFFICIENT_BACKING"
        # Add new custody rows only for the part beyond the existing surplus.
        need_from_plan = max(amount - surplus, Decimal("0"))
        added = Decimal("0")
        for p in onchain_plan:
            if added >= need_from_plan:
                break
            take = min(Decimal(str(p["amount"])), need_from_plan - added)
            if take <= 0:
                continue
            cur.execute(
                """INSERT INTO fund_ledger
                       (tid, network, custody_address, custody_index, amount, source)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (str(tid), p["network"], p["address"], int(p["index"]), take, source))
            added += take
        cur.execute(
            """INSERT INTO balance (tid, token, amount) VALUES (%s, 'USDT', %s)
               ON CONFLICT (tid, token) DO UPDATE SET
                   amount = balance.amount + EXCLUDED.amount,
                   updated_at = CURRENT_TIMESTAMP""",
            (str(tid), amount))
        cur.execute(
            "UPDATE user_wallet SET usdt_balance = COALESCE(usdt_balance, 0) + %s WHERE tid = %s",
            (amount, str(tid)))
        cur.execute("SELECT amount FROM balance WHERE tid = %s AND token = 'USDT'", (str(tid),))
        new_bal = Decimal(str(cur.fetchone()[0]))
        conn.commit()
        return True, new_bal
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)


def admin_reconcile_debit(tid, amount):
    """Lower user `tid`'s spendable balance by `amount` and consume matching custody
    FIFO across their networks, in ONE transaction. Refuses (rolls back) when the
    user's SPENDABLE balance (amount − locked) is short, so funds locked in a live
    trade are never touched. Custody is consumed up to what the user holds (if the
    account was over-credited beyond its custody, the leftover simply isn't
    consumed). Returns (True, new_balance) or (False, reason). No user notification."""
    amount = Decimal(str(amount))
    if amount <= 0:
        return False, "AMOUNT_INVALID"
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        # Spendable-balance check (locked funds stay protected). The WHERE guard
        # makes the debit atomic — rowcount 0 means not enough free balance.
        cur.execute(
            """UPDATE balance SET amount = amount - %s, updated_at = CURRENT_TIMESTAMP
               WHERE tid = %s AND token = 'USDT' AND amount - locked >= %s""",
            (amount, str(tid), amount))
        if cur.rowcount == 0:
            conn.rollback()
            return False, "INSUFFICIENT_SPENDABLE"
        # Consume custody FIFO across the user's networks (largest holding first),
        # up to what they actually hold.
        cur.execute(
            """SELECT network, SUM(amount) FROM fund_ledger WHERE tid = %s
               GROUP BY network ORDER BY SUM(amount) DESC""", (str(tid),))
        remaining = amount
        for net, amt in cur.fetchall():
            if remaining <= 0:
                break
            take = min(Decimal(str(amt)), remaining)
            fund_ledger_consume(str(tid), net, take, conn=conn)  # folds into this txn
            remaining -= take
        cur.execute(
            "UPDATE user_wallet SET usdt_balance = GREATEST(COALESCE(usdt_balance, 0) - %s, 0) WHERE tid = %s",
            (amount, str(tid)))
        cur.execute("SELECT amount FROM balance WHERE tid = %s AND token = 'USDT'", (str(tid),))
        new_bal = Decimal(str(cur.fetchone()[0]))
        conn.commit()
        return True, new_bal
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)


def backfill_fund_ledger():
    """One-time migration: seed fund_ledger from confirmed on-chain deposits
    for users who deposited before fund_ledger existed. Safe to run repeatedly —
    skips users already present in the ledger."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT DISTINCT tid FROM fund_ledger")
        already = {r[0] for r in cur.fetchall()}
        cur.execute(
            """SELECT tid, network, wallet_address, SUM(amount) AS total
               FROM transaction
               WHERE status = 'CONFIRMED' AND amount > 0
                 AND network NOT IN ('INTERNAL')
                 AND token = 'USDT'
               GROUP BY tid, network, wallet_address"""
        )
        rows = cur.fetchall()
        inserted = 0
        for tid, network, wallet_address, total in rows:
            if str(tid) in already:
                continue
            idx = _custody_index_for_address(wallet_address, cur)
            cur.execute(
                """INSERT INTO fund_ledger
                       (tid, network, custody_address, custody_index, amount, source)
                   VALUES (%s, %s, %s, %s, %s, 'BACKFILL')""",
                (str(tid), network, wallet_address, idx, Decimal(str(total)))
            )
            inserted += 1
        conn.commit()
        if inserted:
            import logging
            logging.info(f"fund_ledger backfill: {inserted} entries created")
    except Exception as e:
        conn.rollback()
        import logging
        logging.warning(f"fund_ledger backfill failed: {e}")
    finally:
        cur.close()
        release_connection(conn)


# =====================================================================
# --- Internal transfers (0-fee, TID-to-TID, ledger only) ---
# =====================================================================
def internal_transfer(from_tid, to_tid, amount, network=None):
    """Moves available (unlocked) USDT between two registered users with no fee.
    With `network` given, the funds are pulled from that network's custody (the
    sender picks which network to send from, mirroring on-chain withdrawal) and the
    sender must hold enough there; with None it moves FIFO across all networks.
    Returns (ok, reason); reason in: GLOBAL_FREEZE, SENDER_BLOCKED,
    RECEIVER_UNAVAILABLE, INSUFFICIENT, INSUFFICIENT_NETWORK."""
    from_tid, to_tid = str(from_tid), str(to_tid)
    amount = Decimal(str(amount))
    if amount <= 0:
        return False, "INSUFFICIENT"
    try:
        if is_global_freeze():
            return False, "GLOBAL_FREEZE"
        sf = get_user_flags(from_tid)
        if not sf or sf["status"] == "SUSPENDED" or sf["wallet_frozen"]:
            return False, "SENDER_BLOCKED"
        rf = get_user_flags(to_tid)
        if not rf or rf["status"] == "SUSPENDED":
            return False, "RECEIVER_UNAVAILABLE"
        # When a network is chosen, the custody on THAT network must fully back the
        # amount (same per-network rule as an on-chain withdrawal), so the ledger
        # move below can never under-cover the balance move.
        if network is not None:
            net_avail = fund_ledger_available_by_network(from_tid).get(network, Decimal("0"))
            if net_avail < amount:
                return False, "INSUFFICIENT_NETWORK"
    except Exception:
        return False, "SENDER_BLOCKED"  # fail closed
    ref = uuid.uuid4().hex[:20]
    conn = get_connection()
    conn.autocommit = False
    cur = conn.cursor()
    try:
        cur.execute(
            """UPDATE balance SET amount = amount - %s, updated_at = CURRENT_TIMESTAMP
               WHERE tid = %s AND token = 'USDT' AND amount - locked >= %s""",
            (amount, from_tid, amount)
        )
        if cur.rowcount == 0:
            conn.rollback()
            return False, "INSUFFICIENT"
        cur.execute(
            """INSERT INTO balance (tid, token, amount) VALUES (%s, 'USDT', %s)
               ON CONFLICT (tid, token) DO UPDATE SET
                   amount = balance.amount + EXCLUDED.amount,
                   updated_at = CURRENT_TIMESTAMP""",
            (to_tid, amount)
        )
        # transfer history (network INTERNAL, one row per leg)
        cur.execute(
            """INSERT INTO transaction (tid, network, wallet_address, transaction_hash, amount, token, status)
               VALUES (%s, 'INTERNAL', %s, %s, %s, 'USDT', 'CONFIRMED')""",
            (from_tid, to_tid, f"INT-{ref}-OUT", -amount)
        )
        cur.execute(
            """INSERT INTO transaction (tid, network, wallet_address, transaction_hash, amount, token, status)
               VALUES (%s, 'INTERNAL', %s, %s, %s, 'USDT', 'CONFIRMED')""",
            (to_tid, from_tid, f"INT-{ref}-IN", amount)
        )
        # keep the legacy user_wallet column in sync for the dashboard
        cur.execute("UPDATE user_wallet SET usdt_balance = usdt_balance - %s WHERE tid = %s", (amount, from_tid))
        cur.execute("UPDATE user_wallet SET usdt_balance = usdt_balance + %s WHERE tid = %s", (amount, to_tid))
        # transfer real fund ownership so the recipient's /balance shows the correct
        # network. Same transaction as the balance move, so the two can never
        # drift apart: either both commit or both roll back. The guard swallows a
        # non-DB glitch (lets the transfer proceed untracked); a real DB error
        # poisons the txn and the outer handler rolls the whole transfer back.
        # Move real fund ownership and log the internal transaction (its real
        # network + custody location). SAVEPOINT-guarded so this best-effort
        # tracking can never roll back the actual balance move.
        try:
            cur.execute("SAVEPOINT fl_track")
            moved = fund_ledger_transfer(from_tid, to_tid, amount, conn, network=network)
            logged = Decimal("0")
            for m in moved:
                log_internal_txn(cur, ref, "INTERNAL", from_tid, to_tid, m["amount"],
                                 network=m["network"], custody_address=m["custody_address"])
                logged += m["amount"]
            if logged < amount:
                # ledger under-covers the balance moved: still log the remainder so
                # the internal transaction history matches the balance move.
                log_internal_txn(cur, ref, "INTERNAL", from_tid, to_tid, amount - logged)
            cur.execute("RELEASE SAVEPOINT fl_track")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT fl_track")
            logging.warning(f"internal_transfer {from_tid}->{to_tid}: tracking failed (transfer kept): {e}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.autocommit = True
        cur.close()
        release_connection(conn)
    _p2p_trace("Internal Transfer", {"from": from_tid, "to": to_tid, "amount": str(amount), "ref": ref})
    return True, ""


def get_pool_holdings():
    """Per-owner custody pool for the dashboard 'Pool' section: who owns how much
    USDT, on which network, sitting at which custody wallet — straight from
    fund_ledger, the authoritative real-ownership map.

    Distinguishes two different people: the OWNER OF THE FUNDS (fl.tid — who the
    USDT belongs to, which changes on internal/P2P transfers) and the REAL OWNER
    OF THE WALLET (the user whose deposit address `custody_address` actually is —
    resolved via user_wallet). After a transfer these differ: the funds sit in
    the original depositor's custody wallet while belonging to someone else."""
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        cur.execute(
            """SELECT fl.tid, l.username, l.realn, fl.network, fl.custody_address,
                      SUM(fl.amount) AS amount,
                      wo.tid AS wallet_owner_tid,
                      wl.username AS wallet_owner_username,
                      wl.realn AS wallet_owner_realn
               FROM fund_ledger fl
               LEFT JOIN login_users l ON l.tid = fl.tid
               LEFT JOIN user_wallet wo
                      ON wo.evm_address  = fl.custody_address
                      OR wo.tron_address = fl.custody_address
                      OR wo.ton_address  = fl.custody_address
               LEFT JOIN login_users wl ON wl.tid = wo.tid
               GROUP BY fl.tid, l.username, l.realn, fl.network, fl.custody_address,
                        wo.tid, wl.username, wl.realn
               HAVING SUM(fl.amount) > 0
               ORDER BY fl.tid, fl.network"""
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_pool_holdings failed: {e}")
    cur.close()
    release_connection(conn)
    return rows


def list_onchain_log(page=1, limit=25):
    """On-chain activity log for the dashboard: real-chain deposits (from
    `transaction`, excluding INTERNAL legs) UNION on-chain withdrawals (from
    `withdraw`), tagged DEPOSIT / WITHDRAW. Newest first. Returns (rows, total)."""
    offset = (page - 1) * limit
    conn = get_connection()
    cur = conn.cursor()
    rows, total = [], 0
    try:
        cur.execute(
            """SELECT (SELECT COUNT(*) FROM transaction WHERE network NOT IN ('INTERNAL'))
                    + (SELECT COUNT(*) FROM withdraw)"""
        )
        total = cur.fetchone()[0]
        cur.execute(
            """SELECT direction, tid, network, address, amount, status, tx_hash,
                      created_at, wid FROM (
                   SELECT 'DEPOSIT' AS direction, tid, network, wallet_address AS address,
                          amount, status, transaction_hash AS tx_hash, created_at,
                          NULL::int AS wid
                   FROM transaction WHERE network NOT IN ('INTERNAL')
                   UNION ALL
                   SELECT 'WITHDRAW' AS direction, tid, network, wallet_address AS address,
                          amount, status, tx_hash, created_at, id AS wid
                   FROM withdraw
               ) combined
               ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset)
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"list_onchain_log failed: {e}")
    cur.close()
    release_connection(conn)
    return rows, total


def list_all_transactions(page=1, limit=25):
    """Unified transaction history for the dashboard 'Transactions' section:
    on-chain rows from `transaction` (method blank) UNION internal transfers and
    P2P settlements from `internal_transaction` (method INTERNAL / P2P). Newest
    first, paginated. Returns (rows, total)."""
    offset = (page - 1) * limit
    conn = get_connection()
    cur = conn.cursor()
    rows, total = [], 0
    try:
        cur.execute(
            """SELECT (SELECT COUNT(*) FROM transaction WHERE network NOT IN ('INTERNAL'))
                    + (SELECT COUNT(*) FROM internal_transaction)"""
        )
        total = cur.fetchone()[0]
        cur.execute(
            """SELECT source, method, from_tid, to_tid, network, address, amount,
                      token, status, created_at, ref, order_id FROM (
                   SELECT 'ONCHAIN' AS source, '' AS method, NULL::text AS from_tid,
                          tid AS to_tid, network, wallet_address AS address, amount,
                          token, status, created_at, transaction_hash AS ref,
                          NULL::int AS order_id
                   FROM transaction WHERE network NOT IN ('INTERNAL')
                   UNION ALL
                   SELECT 'INTERNAL' AS source, method, from_tid, to_tid, network,
                          custody_address AS address, amount, token,
                          'CONFIRMED' AS status, created_at, ref,
                          related_order_id AS order_id
                   FROM internal_transaction
               ) combined
               ORDER BY created_at DESC LIMIT %s OFFSET %s""",
            (limit, offset)
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"list_all_transactions failed: {e}")
    cur.close()
    release_connection(conn)
    return rows, total


def get_user_transaction_history(tid, limit=50):
    """A single user's OWN transaction history — deposits, withdrawals and internal
    transfers — newest first. SECURITY: every leg is filtered by `tid = %s`, so a
    caller can only ever see their own movements; never pass a TID derived from
    untrusted input. Sources:
      • DEPOSIT  — on-chain credits from `transaction` (network <> 'INTERNAL').
      • INTERNAL — TID->TID transfers from `transaction` (network = 'INTERNAL'),
                   one signed leg per user: amount < 0 means sent, > 0 received.
                   `wallet_address` holds the counterparty TID.
      • WITHDRAW — on-chain withdrawals from `withdraw` (always outgoing); shows
                   the amount sent on-chain (`final_amount`) and the destination.
    Amounts are returned as positive absolute values with an explicit `direction`."""
    tid = str(tid)
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        cur.execute(
            """SELECT kind, direction, amount, network, token, status,
                      counterparty, ref, created_at FROM (
                   SELECT 'DEPOSIT' AS kind, 'IN' AS direction, amount,
                          network, token, status, '' AS counterparty,
                          transaction_hash AS ref, created_at
                   FROM transaction
                   WHERE tid = %s AND network <> 'INTERNAL' AND amount > 0
                   UNION ALL
                   SELECT 'INTERNAL' AS kind,
                          CASE WHEN amount < 0 THEN 'OUT' ELSE 'IN' END AS direction,
                          ABS(amount) AS amount,
                          'INTERNAL' AS network, token, status,
                          wallet_address AS counterparty,
                          transaction_hash AS ref, created_at
                   FROM transaction
                   WHERE tid = %s AND network = 'INTERNAL'
                   UNION ALL
                   SELECT 'WITHDRAW' AS kind, 'OUT' AS direction,
                          COALESCE(final_amount, amount) AS amount,
                          network, token, status,
                          wallet_address AS counterparty,
                          COALESCE(tx_hash, '') AS ref, created_at
                   FROM withdraw
                   WHERE tid = %s
               ) h
               ORDER BY created_at DESC LIMIT %s""",
            (tid, tid, tid, limit)
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_user_transaction_history failed for {tid}: {e}")
    cur.close()
    release_connection(conn)
    return rows


# =====================================================================
# --- Command Response Registry (admin-editable bot replies) ---
# Every user-facing reply the bot can send is registered here with a
# stable key, the command/button that triggers it, the user state it
# applies to, and a default template. Admins edit the live text from
# Management -> Command Response; bot.py reads it through get_response().
# Placeholders in {curly_braces} are filled in by the bot at send time.
# =====================================================================
import string

# Each entry: key, command (group label), trigger (command/button/system),
# state (user-state label), label (human description), placeholders, default.
RESPONSE_DEFAULTS = [
    # ---- /start ----
    {"key": "start_new", "command": "/start", "trigger": "command", "state": "New (unregistered)",
     "label": "Welcome message for a brand-new user", "placeholders": ["first_name"],
     "default": "Welcome, {first_name}!\nThis bot helps you conduct secure P2P USDT cryptocurrency trades between buyers and sellers.\nTo get started, tap 🚀 Getting Started → 🆕 Create Account on the menu below.\n\nHappy trading! 🚀💰"},
    {"key": "start_returning", "command": "/start", "trigger": "command", "state": "Registered",
     "label": "Welcome-back message for a returning user", "placeholders": ["first_name"],
     "default": "Hello, {first_name}!\nWelcome back.\nYour account has already been created and is ready to use.\nUse the menu buttons below to get around.\n\nHappy trading! 🚀💰"},

    # ---- shared ----
    {"key": "not_registered", "command": "General", "trigger": "system", "state": "Unregistered",
     "label": "Shown when an unregistered user runs any command that needs an account", "placeholders": ["first_name"],
     "default": "Hello {first_name},\n\nYou are not registered yet. Tap 🚀 Getting Started → 🆕 Create Account on the menu below to get started."},
    {"key": "unknown_command", "command": "General", "trigger": "system", "state": "Any",
     "label": "Fallback reply for unrecognised text or commands", "placeholders": [],
     "default": "Please use the menu buttons below to get around."},
    {"key": "suspended", "command": "General", "trigger": "system", "state": "Suspended",
     "label": "Shown to a suspended account on any message or button press", "placeholders": [],
     "default": "Your account is suspended. Please contact support."},
    {"key": "network_unknown", "command": "General", "trigger": "button", "state": "Any",
     "label": "Popup when an unknown network button is pressed", "placeholders": [],
     "default": "Unknown network."},
    {"key": "cancel_prefix", "command": "General", "trigger": "system", "state": "Any",
     "label": "Prefix prepended to any prompt that can be aborted with /cancel", "placeholders": [],
     "default": "/cancel to stop"},
    {"key": "ads_cancel_hint", "command": "/ads", "trigger": "system", "state": "Registered",
     "label": "Footer hint under the ad-browse control message", "placeholders": [],
     "default": "/cancel to exit"},
    {"key": "withdraw_net_balance_suffix", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Per-network balance line appended to the on-chain withdraw amount prompt", "placeholders": ["network_short", "balance"],
     "default": "\n\nYour USDT ({network_short}) balance: {balance} USDT"},
    {"key": "withdraw_net_balance_btn", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Network button label in the on-chain withdraw network picker", "placeholders": ["label", "balance"],
     "default": "{label} | Balance: {balance} USDT"},
    {"key": "order_network_hint", "command": "/order", "trigger": "system", "state": "Buyer on completion",
     "label": "Withdraw hint appended when an order completes (buyer has known networks)", "placeholders": ["nets"],
     "default": "\n\n💡 Your balance is on: {nets} — tap 💰 Wallet & Funds → ⬆️ Withdraw to send on-chain."},
    {"key": "order_network_hint_generic", "command": "/order", "trigger": "system", "state": "Buyer on completion",
     "label": "Withdraw hint appended when an order completes (no known networks)", "placeholders": [],
     "default": "\n\n💡 Tap 💰 Wallet & Funds → ⬆️ Withdraw to send your USDT on-chain."},
    {"key": "cancel_done", "command": "General", "trigger": "command", "state": "Any",
     "label": "/cancel — an active session was cleared", "placeholders": [],
     "default": "✅ Done. Your current request was cancelled.\n\nUse the menu buttons below to begin again."},
    {"key": "cancel_nothing", "command": "General", "trigger": "command", "state": "Any",
     "label": "/cancel — nothing was in progress", "placeholders": [],
     "default": "There is nothing to cancel.\n\nUse the menu buttons below to begin."},
    {"key": "chat_cleared", "command": "General", "trigger": "command", "state": "Any",
     "label": "/clear — recent chat messages were deleted", "placeholders": ["count"],
     "default": "🧹 Chat cleared.\n\nUse the menu buttons below to begin again."},

    # ---- /create_account ----
    {"key": "create_account_exists", "command": "/create_account", "trigger": "command", "state": "Registered",
     "label": "User tries to create an account they already have", "placeholders": ["first_name"],
     "default": "Dear {first_name}, your account is already created. Use the menu buttons below to see what you can do."},
    {"key": "create_account_ask_name", "command": "/create_account", "trigger": "command", "state": "New",
     "label": "Prompt asking for the user's first name", "placeholders": [],
     "default": "Your First Name"},
    {"key": "create_account_ask_lastname", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Shown after first name is accepted; asks for last name", "placeholders": [],
     "default": "Before Creating Your Account...\n\nYour Last Name"},
    {"key": "realname_invalid", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Name validation failed (letters A-Z only, at least 4 letters)", "placeholders": [],
     "default": "Please input a valid name using only A-Z letters with at least 4 letters."},
    {"key": "create_account_ask_username", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Shown after last name is accepted; asks for a public username", "placeholders": [],
     "default": "Almost done! Choose a public username (4–20 letters, numbers or _).\n\nThis is shown to other traders on your ads — it must be DIFFERENT from your Telegram @username."},
    {"key": "username_invalid", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Username failed the format rules", "placeholders": [],
     "default": "Please choose a valid username: 4–20 characters, only letters, numbers or underscore (_)."},
    {"key": "username_same_as_telegram", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "User picked a username equal to their Telegram @username", "placeholders": [],
     "default": "That is your Telegram username — your public username must be DIFFERENT. Please pick another one."},
    {"key": "account_creating", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Acknowledgement while the account is being created", "placeholders": [],
     "default": "Creating Your Account..."},
    {"key": "account_created", "command": "/create_account", "trigger": "system", "state": "New",
     "label": "Account creation success message", "placeholders": ["real_name"],
     "default": "Account created successfully, {real_name}!\nYour USDT deposit wallets are ready — tap 💰 Wallet & Funds → 👛 Wallet on the menu below.\nUse the menu buttons below to get around."},

    # ---- /list ----
    {"key": "list_registered", "command": "/list", "trigger": "command", "state": "Registered",
     "label": "The full command list shown to registered users", "placeholders": [],
     "default": "📋 Menu Guide\n\nUse the buttons at the bottom of the chat:\n\n🚀 Getting Started — create & verify your account, view your info\n💰 Wallet & Funds — wallets, balance, deposit, withdraw\n🤝 P2P Trading — browse ads, your orders, post ads, become a merchant\n🛠️ Support & More — contact support, clear chat, cancel\n\nTap a category, pick an option, and use ⬅️ Back to return.\n\nHappy trading! 🚀💰"},

    # ---- /account ----
    {"key": "account_info", "command": "/account", "trigger": "command", "state": "Registered",
     "label": "Account information screen", "placeholders": ["name", "username_display", "realn", "created", "tid", "usertype_display"],
     "default": "👤 Your Account\n\nTelegram Name: {name}\nTelegram Username: {username_display}\nReal Name: {realn}\nAccount Created: {created}\nTID: {tid}\nAccount Type: {usertype_display}"},

    # ---- /wallet ----
    {"key": "wallet_header", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "Header above the deposit-wallet list", "placeholders": [],
     "default": "💳 Your USDT Deposit Wallets"},
    {"key": "wallet_bnb", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "BNB Smart Chain (BEP20) deposit address card — same address as ETH/POL", "placeholders": ["evm"],
     "default": "🟡 BNB Smart Chain (BEP20)\n\nYour Deposit Address:\n`{evm}`"},
    {"key": "wallet_eth", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "Ethereum (ERC20) deposit address card — same address as BNB/POL", "placeholders": ["evm"],
     "default": "🔵 Ethereum (ERC20)\n\nYour Deposit Address:\n`{evm}`"},
    {"key": "wallet_pol", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "Polygon (POL) deposit address card — same address as BNB/ETH", "placeholders": ["evm"],
     "default": "🟣 Polygon (POL)\n\nYour Deposit Address:\n`{evm}`"},
    {"key": "wallet_tron", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "TRON deposit address card", "placeholders": ["tron"],
     "default": "🔴 TRON (TRC20)\n\nYour Deposit Address:\n`{tron}`"},
    {"key": "wallet_ton", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "TON deposit address card", "placeholders": ["ton"],
     "default": "💎 TON\n\nYour Deposit Address:\n`{ton}`"},
    {"key": "wallet_internal", "command": "/wallet", "trigger": "command", "state": "Registered",
     "label": "Internal account number (TID) card shown last — used for 0-fee internal transfers", "placeholders": ["tid"],
     "default": "🏦 Internal Account Number (TID)\n`{tid}`\n\nShare this number to receive 0-fee internal transfers from other users. It is also the TID asked for when you withdraw internally."},
    {"key": "qr_hint", "command": "/wallet", "trigger": "system", "state": "Registered",
     "label": "Tappable /qr command appended to each wallet/deposit address card", "placeholders": ["cmd"],
     "default": "\n\n📷 Tap for a scannable QR image: {cmd}"},
    {"key": "qr_caption", "command": "/wallet", "trigger": "system", "state": "QR image sent",
     "label": "Caption under the QR code image", "placeholders": ["label", "address"],
     "default": "📷 {label}\n\nScan to send USDT to your address:\n`{address}`\n\n⚠️ Only send USDT, and only on the correct network."},
    {"key": "qr_choose_first", "command": "/wallet", "trigger": "system", "state": "No QR context",
     "label": "Shown when /qr is sent with no network (no wallet chosen)", "placeholders": [],
     "default": "Please first choose your wallet via 💰 Wallet & Funds → 👛 Wallet, then tap the QR link under the network you want."},
    {"key": "qr_failed", "command": "/wallet", "trigger": "system", "state": "QR generation failed",
     "label": "Fallback when the QR image could not be generated", "placeholders": ["address"],
     "default": "Couldn't generate the QR image right now. Your address is:\n`{address}`"},

    # ---- /balance ----
    {"key": "balance_info", "command": "/balance", "trigger": "command", "state": "Registered",
     "label": "Balance display (per-network breakdown)", "placeholders": ["net_lines", "total", "available_line"],
     "default": "💰 Your USDT Balance\n\n{net_lines}\n\nTotal: {total} USDT{available_line}"},
    {"key": "balance_net_line", "command": "/balance", "trigger": "system", "state": "Registered",
     "label": "One per-network balance row in the balance view (label carries its own emoji)", "placeholders": ["network_label", "amount"],
     "default": "{network_label}: {amount}"},
    {"key": "balance_available_line", "command": "/balance", "trigger": "system", "state": "Registered",
     "label": "Extra line in the balance view when some funds are locked", "placeholders": ["available"],
     "default": "\nAvailable: {available} USDT"},

    # ---- /deposit ----
    {"key": "deposit_prompt", "command": "/deposit", "trigger": "command", "state": "Registered",
     "label": "Network selection prompt", "placeholders": [],
     "default": "Select the network you want to deposit USDT from:"},
    {"key": "deposit_address", "command": "/deposit", "trigger": "button", "state": "Registered",
     "label": "Deposit address shown after picking a network", "placeholders": ["label", "address", "fee_usd", "fee_pct"],
     "default": "{label}\n\nYour Deposit Address:\n`{address}`\n\nNetwork Fee: {fee_usd} ({fee_pct} on a ~$100 deposit)\n\nSend only USDT to this address. Your balance will be credited automatically after confirmation."},
    {"key": "deposit_confirm_time", "command": "/deposit", "trigger": "button", "state": "Registered",
     "label": "Estimated confirmation time shown under the deposit address", "placeholders": ["label", "confirms", "time"],
     "default": "⏱ Confirmation time on {label}: {time}.\n\nYour deposit is credited after {confirms} block confirmation(s) — you'll get a message automatically the moment it lands."},
    {"key": "network_disabled_default", "command": "/deposit", "trigger": "system", "state": "Network disabled",
     "label": "Fallback shown when a disabled network is picked and no custom message is set", "placeholders": ["label"],
     "default": "⚠️ {label} is temporarily unavailable. Please choose another network or try again later."},
    {"key": "no_active_networks", "command": "/deposit", "trigger": "system", "state": "All disabled",
     "label": "Shown when no networks are available to select", "placeholders": [],
     "default": "⚠️ All networks are temporarily unavailable. Please try again shortly."},
    {"key": "network_disabled_tag", "command": "/balance", "trigger": "system", "state": "Network disabled",
     "label": "Tag appended inline to a disabled network's line in /balance", "placeholders": [],
     "default": " ⚠️ DISACTIVATED Network"},
    {"key": "wallet_net_disabled", "command": "/wallet", "trigger": "system", "state": "Network disabled",
     "label": "Per-network warning appended to a single /wallet address card when that one network is disabled", "placeholders": ["network"],
     "default": "\n\n⚠️ Do NOT send USDT to ({network}) network right now — it's De-activated for now! Use the others."},

    # ---- /withdraw ----
    {"key": "withdraw_frozen", "command": "/withdraw", "trigger": "system", "state": "Wallet frozen",
     "label": "Withdrawal blocked because the wallet is frozen", "placeholders": [],
     "default": "Your wallet is currently frozen. This may be due to an active P2P trade or an administrative review. If you believe this is an error, please contact support."},
    {"key": "withdraw_global_freeze", "command": "/withdraw", "trigger": "system", "state": "Global freeze",
     "label": "Withdrawal blocked by the global emergency freeze", "placeholders": [],
     "default": "Withdrawals are temporarily unavailable. Please try again later."},
    {"key": "withdraw_pending", "command": "/withdraw", "trigger": "system", "state": "Has pending withdrawal",
     "label": "User already has a withdrawal in progress", "placeholders": [],
     "default": "You already have a withdrawal in progress. Please wait for it to finish before requesting another."},
    {"key": "withdraw_active_order", "command": "/withdraw", "trigger": "system", "state": "Has active trade",
     "label": "Withdrawal blocked while a P2P trade is active", "placeholders": [],
     "default": "Your funds are protected while you have an active P2P trade. Please finish your trade first — tap 🤝 P2P Trading → 📦 My Order to continue."},
    {"key": "withdraw_block_generic", "command": "/withdraw", "trigger": "system", "state": "Blocked (other)",
     "label": "Generic withdrawal-blocked fallback", "placeholders": [],
     "default": "Withdrawals are not available for your account right now. Please contact support."},
    {"key": "withdraw_throttle", "command": "/withdraw", "trigger": "system", "state": "Any",
     "label": "Too many withdrawal requests in a short time", "placeholders": [],
     "default": "Please wait a few seconds before requesting another withdrawal."},
    {"key": "withdraw_has_active_ad", "command": "/withdraw", "trigger": "system", "state": "Merchant with ad",
     "label": "Merchant must remove their Sell ad before withdrawing (My Ads is opened below)", "placeholders": [],
     "default": "📌 You have an active Sell ad that locks your USDT. Please remove it first.\n\nYour Sell ad(s) are shown below — tap 🗑 Cancel Ad to remove one, then try withdrawing again."},
    {"key": "withdraw_type_prompt", "command": "/withdraw", "trigger": "command", "state": "Registered",
     "label": "Choose Internal (0 fee) or On-Chain withdrawal", "placeholders": [],
     "default": "How would you like to withdraw your USDT?\n\n💸 Internal Transfer — instant, 0 fees, sent to another user by TID.\n🌐 On-Chain Transfer — sent to an external wallet (network fee + 1% platform fee)."},
    {"key": "withdraw_prompt_network", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Network selection prompt for on-chain withdrawal", "placeholders": [],
     "default": "Select the network you want to withdraw USDT to:"},
    {"key": "withdraw_int_ask_tid", "command": "/withdraw", "trigger": "button", "state": "Internal transfer",
     "label": "Ask for the recipient's TID", "placeholders": [],
     "default": "💸 Internal Transfer (0 Fee)\n\nPlease send the recipient's TID (every user can find their own TID at the bottom of 💰 Wallet & Funds → 👛 Wallet):"},
    {"key": "withdraw_int_tid_invalid", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Recipient TID is not numeric", "placeholders": [],
     "default": "That doesn't look like a valid TID. A TID contains numbers only — please send the recipient's TID:"},
    {"key": "withdraw_int_not_found", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "No account exists for that TID", "placeholders": ["tid"],
     "default": "No account was found with TID {tid}. Please check the TID and send it again:"},
    {"key": "withdraw_int_self", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "User tried to transfer to themselves", "placeholders": [],
     "default": "You cannot transfer to your own account. Please send another user's TID:"},
    {"key": "withdraw_int_ask_amount", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Ask how much to send internally", "placeholders": ["name", "tid"],
     "default": "Sending to: {name} (TID {tid})\n\nHow much USDT do you want to send?"},
    {"key": "withdraw_int_prompt_network", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Ask which network to send the internal transfer from", "placeholders": ["name", "tid"],
     "default": "Sending to: {name} (TID {tid})\n\nWhich network do you want to send the USDT from?"},
    {"key": "withdraw_int_ask_amount_net", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Ask internal amount after a network is chosen", "placeholders": ["name", "tid", "label", "balance"],
     "default": "Sending to: {name} (TID {tid})\nFrom: {label} ({balance} USDT available)\n\nHow much USDT do you want to send? (minimum 1 USDT)"},
    {"key": "withdraw_int_min", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Internal transfer below the 1 USDT minimum", "placeholders": [],
     "default": "The minimum internal transfer is 1 USDT. Please enter a higher amount:"},
    {"key": "withdraw_max_btn", "command": "/withdraw", "trigger": "button", "state": "Internal transfer",
     "label": "MAX amount button on the amount step", "placeholders": ["max"],
     "default": "⬆️ MAX ({max} USDT)"},
    {"key": "withdraw_int_net_insufficient", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Not enough USDT on the chosen network", "placeholders": ["label", "balance"],
     "default": "You only have {balance} USDT on {label}. Enter a smaller amount or send /cancel and choose another network:"},
    {"key": "withdraw_int_no_funds", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "No per-network balance to send internally", "placeholders": [],
     "default": "You don't have any USDT on a network to send right now."},
    {"key": "withdraw_int_confirm_net", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Internal transfer confirmation (with network)", "placeholders": ["name", "tid", "amount", "label"],
     "default": "🧾 Please confirm your internal transfer:\n\nRecipient: {name}\nTID: {tid}\nFrom network: {label}\nAmount: {amount} USDT\nFee: 0 USDT (internal transfers are free)\n\nPress Send to confirm or Cancel to abort."},
    {"key": "withdraw_int_confirm", "command": "/withdraw", "trigger": "system", "state": "Internal transfer",
     "label": "Internal transfer confirmation screen", "placeholders": ["name", "tid", "amount"],
     "default": "🧾 Please confirm your internal transfer:\n\nRecipient: {name}\nTID: {tid}\nAmount: {amount} USDT\nFee: 0 USDT (internal transfers are free)\n\nPress Send to confirm or Cancel to abort."},
    {"key": "withdraw_int_done", "command": "/withdraw", "trigger": "button", "state": "Internal transfer",
     "label": "Internal transfer completed (sender)", "placeholders": ["amount", "name", "tid"],
     "default": "✅ Transfer complete!\n{amount} USDT was sent to {name} (TID {tid}) with 0 fees.\nTap 💰 Wallet & Funds → 💵 Balance to check your balance."},
    {"key": "withdraw_int_received", "command": "/withdraw", "trigger": "system", "state": "Internal transfer (recipient)",
     "label": "Internal transfer received notification", "placeholders": ["amount", "name", "tid"],
     "default": "💰 You received {amount} USDT from {name} (TID {tid}) via internal transfer.\nTap 💰 Wallet & Funds → 💵 Balance to check your balance."},
    {"key": "withdraw_int_failed", "command": "/withdraw", "trigger": "button", "state": "Internal transfer",
     "label": "Internal transfer failed at execution", "placeholders": [],
     "default": "❌ The internal transfer could not be completed: your available balance changed or the recipient is unavailable. Please tap 💰 Wallet & Funds → ⬆️ Withdraw to try again."},
    {"key": "withdraw_ask_address", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Prompt for the destination wallet address", "placeholders": ["label"],
     "default": "{label}\n\nPlease send the destination wallet address you want to withdraw your USDT to:"},
    {"key": "withdraw_invalid_address", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Destination address failed network format check", "placeholders": ["label"],
     "default": "That is not a valid {label} address.\nPlease send a wallet address that matches the selected network:"},
    {"key": "withdraw_ask_amount", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Prompt for the withdrawal amount", "placeholders": ["min", "max"],
     "default": "How much USDT do you want to withdraw?\n(Min {min} — Max {max} USDT)"},
    {"key": "withdraw_amount_invalid", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Withdrawal amount is not a valid number", "placeholders": [],
     "default": "Please send a valid number for the amount (e.g. 25.50):"},
    {"key": "withdraw_amount_low", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Withdrawal amount below the minimum", "placeholders": ["min"],
     "default": "Amount too low. Minimum withdrawal: {min} USDT"},
    {"key": "withdraw_amount_high", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Withdrawal amount above the maximum", "placeholders": ["max"],
     "default": "Amount too high. Maximum withdrawal: {max} USDT"},
    {"key": "withdraw_locked", "command": "/withdraw", "trigger": "system", "state": "Has locked funds",
     "label": "Part of the balance is locked in a trade/ad", "placeholders": ["total", "locked", "available"],
     "default": "🔒 Part of your balance is locked in an active P2P trade or ad and cannot be withdrawn.\n\nTotal balance: {total} USDT\nLocked: {locked} USDT\nAvailable: {available} USDT\n\nPlease send a smaller amount, or use the menu buttons below to start again."},
    {"key": "withdraw_insufficient", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Not enough available balance to withdraw", "placeholders": ["available", "amount"],
     "default": "❌ Insufficient balance.\n\nAvailable balance: {available} USDT\nRequested: {amount} USDT\n\nPlease send a smaller amount, or use the menu buttons below to start again."},
    {"key": "withdraw_insufficient_fee", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Balance can't cover the amount plus its fee", "placeholders": ["amount", "fee_total", "total_debit", "available", "max"],
     "default": "❌ Insufficient balance.\n\nThe full {amount} USDT is sent on-chain — the {fee_total} USDT fee is taken from your balance on top of that, so you need {total_debit} USDT to withdraw this.\n\nAvailable balance: {available} USDT\n\nYou need the amount of the fee to withdraw this, so please choose a smaller amount. The most you can withdraw right now is {max} USDT."},
    {"key": "withdraw_amount_fees", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Withdrawal amount does not cover the fees", "placeholders": ["fee_total"],
     "default": "The amount must be greater than the total fees ({fee_total} USDT). Please send a larger amount:"},
    {"key": "withdraw_confirm_fees", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Final confirmation with full fee breakdown", "placeholders": ["label", "address", "amount", "fee_network", "fee_platform", "fee_total", "total_debit", "final"],
     "default": "🧾 Please confirm your withdrawal:\n\nNetwork: {label}\nTo Wallet: `{address}`\nYou will receive: {amount} USDT\n\nNetwork Fee: {fee_network} USDT\nPlatform Fee (1%): {fee_platform} USDT\nTotal Fees: {fee_total} USDT\n\nTotal deducted from your balance: {total_debit} USDT\n\nPress Send to confirm or Cancel to abort."},
    {"key": "withdraw_expired", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Confirm pressed but the request expired", "placeholders": [],
     "default": "This withdraw request has expired. Please tap 💰 Wallet & Funds → ⬆️ Withdraw to start again."},
    {"key": "withdraw_cancelled", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "User cancelled the withdrawal", "placeholders": [],
     "default": "Your withdrawal request has been canceled. Please use the menu buttons below to continue."},
    {"key": "withdraw_failed", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Withdrawal failed at the final debit step", "placeholders": [],
     "default": "❌ Withdrawal failed: your available balance no longer covers this amount, or your wallet status changed.\nPlease check 💰 Wallet & Funds → 💵 Balance and tap ⬆️ Withdraw to try again."},
    {"key": "withdraw_submitted_auto", "command": "/withdraw", "trigger": "button", "state": "Registered",
     "label": "Withdrawal accepted — automatic processing", "placeholders": ["label", "address", "amount", "final"],
     "default": "✅ Your withdraw request has been submitted!\n\nNetwork: {label}\nTo Wallet: `{address}`\nYou will receive: {amount} USDT\n(The network + platform fee was charged to your balance on top of this.)\n\nIt is being processed automatically — you will get a message as soon as the funds are sent."},
    {"key": "withdraw_review_notice", "command": "/withdraw", "trigger": "button", "state": "Over daily limit",
     "label": "Withdrawal needs security review (over 500 USDT in 24h)", "placeholders": [],
     "default": "Your daily withdrawal limit is 500 USDT. Requests exceeding this amount require security review and support inspection. Please wait until approval is completed. Thank you for your patience."},
    {"key": "withdraw_approved_notify", "command": "/withdraw", "trigger": "system", "state": "After admin approval",
     "label": "Sent when an admin approves a reviewed withdrawal", "placeholders": ["id"],
     "default": "✅ Your withdrawal #{id} passed the security review and was approved. It is now being processed automatically — you will get a message as soon as the funds are sent."},
    {"key": "withdraw_complete_notify", "command": "/withdraw", "trigger": "system", "state": "On completion",
     "label": "Sent when the funds have actually been broadcast on-chain", "placeholders": ["id", "final", "address", "label", "tx_hash"],
     "default": "✅ Withdrawal #{id} complete!\n\n{final} USDT was sent to:\n`{address}`\nNetwork: {label}\nTransaction: {tx_hash}\n\nThank you for trading with us!"},
    {"key": "deposit_received", "command": "/deposit", "trigger": "system", "state": "On deposit detection",
     "label": "Sent automatically when a deposit is detected and credited", "placeholders": ["amount", "label"],
     "default": "💰 Deposit received!\n\n{amount} USDT arrived via {label} and has been credited to your balance.\nTap 💰 Wallet & Funds → 💵 Balance to check it."},

    # ---- /post_ad ----
    {"key": "not_merchant", "command": "/post_ad", "trigger": "system", "state": "Normal user",
     "label": "Non-merchant tried a merchant-only command", "placeholders": [],
     "default": "You are not a Merchant. You can only buy or sell through merchants."},
    {"key": "postad_need_merchant", "command": "/post_ad", "trigger": "system", "state": "Verified non-merchant",
     "label": "Verified non-merchant tried to post an ad above the non-merchant limit", "placeholders": ["limit"],
     "default": "⭐ Ads above {limit} USDT are for Merchants only.\n\nTo create an ad this large you have to become a Merchant. Do you want to apply now?"},
    {"key": "postad_ask_type", "command": "/post_ad", "trigger": "command", "state": "Merchant",
     "label": "Ask whether to create a Buy or Sell ad", "placeholders": [],
     "default": "What type of ad do you want to create?"},
    {"key": "postad_wizard_expired", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Ad wizard state expired", "placeholders": [],
     "default": "This wizard has expired. Tap 🤝 P2P Trading → 📝 Post Ad to start again."},
    {"key": "postad_ask_min", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask for the minimum ad amount", "placeholders": [],
     "default": "Please enter the minimum amount (USDT, at least 5):"},
    {"key": "postad_min_invalid", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Minimum amount is not a valid number", "placeholders": [],
     "default": "Please send a valid number for the minimum amount:"},
    {"key": "postad_min_positive", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Minimum amount must be at least the floor", "placeholders": ["min"],
     "default": "The minimum amount must be at least {min} USDT. Please try again:"},
    {"key": "postad_ask_max", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask for the maximum ad amount", "placeholders": [],
     "default": "Please enter the maximum amount (USDT):"},
    {"key": "postad_max_invalid", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Maximum amount is not a valid number", "placeholders": [],
     "default": "Please send a valid number for the maximum amount:"},
    {"key": "postad_max_lt_min", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Maximum is smaller than the minimum", "placeholders": ["min"],
     "default": "The maximum must be at least the minimum ({min} USDT). Please try again:"},
    {"key": "postad_sell_over_balance", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Sell ad max exceeds the merchant's available balance", "placeholders": ["available"],
     "default": "Merchant cannot create a Sell ad larger than their available balance.\n\nYour available balance: {available} USDT"},
    {"key": "postad_sell_over_network", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Sell ad max exceeds the balance on the chosen network", "placeholders": ["network_short", "available"],
     "default": "Your sell ad is backed by the USDT on the network you chose. You only have {available} USDT on {network_short}.\n\nEnter a smaller maximum, or /cancel and pick another network."},
    {"key": "postad_no_network_balance", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "No single network holds enough USDT to back a sell ad", "placeholders": [],
     "default": "You don't hold at least 5 USDT on any single network, so you can't post a sell ad yet. Deposit or move funds onto one network first."},
    {"key": "postad_sell_limit", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Merchant reached the 3 sell-ad limit", "placeholders": [],
     "default": "You already have 3 active sell ads (the maximum). Manage them from 🗂 My Ads."},
    {"key": "postad_network_dup", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Chosen network already used by another sell ad", "placeholders": ["network_short"],
     "default": "You already have a sell ad on {network_short}. Each sell ad must use a different network — pick another one."},
    {"key": "postad_select_methods", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask the merchant to pick payment methods", "placeholders": [],
     "default": "Select the payment methods you accept:"},
    {"key": "postad_pm_need_one", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Merchant pressed Done without choosing a method", "placeholders": [],
     "default": "Please select a payment method first."},
    {"key": "postad_pm_added", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Confirmation popup that a method was added", "placeholders": ["choice"],
     "default": "{choice} added ✅"},
    {"key": "postad_ask_account", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask for the account number of a payment method", "placeholders": ["method"],
     "default": "Please send your {method} account number."},
    {"key": "postad_account_too_short", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Account number has 8 or fewer digits", "placeholders": [],
     "default": "That account number is too short — it must have more than 8 digits. Please send a valid account number."},
    {"key": "postad_ask_price", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask for the price per 1 USDT", "placeholders": [],
     "default": "Please enter 1 USDT price."},
    {"key": "postad_price_invalid", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Price is not a valid number", "placeholders": [],
     "default": "Please send a valid number for the price:"},
    {"key": "postad_price_range", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Price out of the allowed range", "placeholders": [],
     "default": "Please enter a price between 0.01 and 300.00."},
    {"key": "postad_ask_paytime", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask for the payment-time window in minutes", "placeholders": [],
     "default": "Please enter the payment time in minutes (5–30):"},
    {"key": "postad_paytime_invalid", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Payment time is not a whole number", "placeholders": [],
     "default": "Please send a whole number of minutes (5–30):"},
    {"key": "postad_paytime_range", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Payment time out of the allowed range", "placeholders": [],
     "default": "Payment time must be between 5 and 30 minutes. Please try again:"},
    {"key": "postad_lock_failed", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Could not lock the merchant's funds for the Sell ad", "placeholders": [],
     "default": "❌ Could not lock funds — your available balance changed. Please tap 🤝 P2P Trading → 📝 Post Ad again."},
    {"key": "postad_created_head", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Header line when a new ad is created", "placeholders": ["ad_type", "id"],
     "default": "✅ Your {ad_type} ad #{id} has been created!"},
    {"key": "postad_updated_head", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Header line when an ad is updated", "placeholders": ["id"],
     "default": "✅ Your ad #{id} has been updated!"},
    {"key": "postad_ask_network", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask the merchant which network their USDT is stored on (SELL ads only)", "placeholders": [],
     "default": "Which network is your USDT stored on?\n\nSelect the network that matches where your USDT balance came from:"},
    {"key": "postad_network_selected", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Confirmation shown after the merchant picks a network for their SELL ad", "placeholders": ["network_short"],
     "default": "USDT ({network_short}) selected."},
    {"key": "postad_ask_networks", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ask which USDT networks a BUY ad accepts (multi-select)", "placeholders": [],
     "default": "Which USDT networks do you accept?\n\nSelect one or more, then press Done."},
    {"key": "postad_net_added", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "A network was added to the multi-select", "placeholders": ["choice"],
     "default": "Added {choice}."},
    {"key": "postad_net_need_one", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Done pressed with no network selected", "placeholders": [],
     "default": "Please select at least one network first."},
    {"key": "postad_network_closed", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Chosen network is temporarily closed by an admin", "placeholders": ["network_short"],
     "default": "🚫 The USDT ({network_short}) network is temporarily closed. Please wait until it is open again to post an ad on it."},
    {"key": "postad_all_networks_closed", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Every network is currently closed", "placeholders": [],
     "default": "🚫 All networks are temporarily closed right now. Please try again later."},
    {"key": "postad_create_failed", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ad could not be created/updated due to an internal error", "placeholders": [],
     "default": "❌ Could not save your ad — something went wrong. Please tap 🤝 P2P Trading → 📝 Post Ad again."},
    {"key": "postad_already_type", "command": "/post_ad", "trigger": "button", "state": "Merchant",
     "label": "Merchant already has an active ad of the chosen side (1 BUY + 1 SELL max)", "placeholders": ["ad_type"],
     "default": "You already have an active {ad_type} ad. You can edit it, or delete it and create a new one."},
    {"key": "postad_result_body", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Ad summary body after create/update", "placeholders": ["head", "ad_type", "min", "max", "price", "fiat", "methods", "minutes", "network_line"],
     "default": "{head}\n\nType: {ad_type}\n{network_line}Min: {min} USDT\nMax: {max} USDT\nPrice: {price} {fiat} / USDT\nPayment Methods: {methods}\nPayment Time: {minutes} minutes\n\nTap 🤝 P2P Trading → 🗂 My Ads to manage your ads."},

    # ---- /my_ads ----
    {"key": "myads_none", "command": "/my_ads", "trigger": "command", "state": "Merchant",
     "label": "Merchant has no active ads", "placeholders": [],
     "default": "You have no active ads. Tap 🤝 P2P Trading → 📝 Post Ad to create one."},
    {"key": "myads_item", "command": "/my_ads", "trigger": "command", "state": "Merchant",
     "label": "One ad card in the merchant's ad list", "placeholders": ["id", "ad_type", "min", "max", "price", "fiat", "methods", "minutes"],
     "default": "📢 Ad #{id} — {ad_type}\n\nMin: {min} USDT\nMax: {max} USDT\nPrice: {price} {fiat} / USDT\nPayment Methods: {methods}\nPayment Time: {minutes} minutes"},
    {"key": "myads_ghost_note", "command": "/my_ads", "trigger": "command", "state": "Merchant",
     "label": "Banner shown above a ghosted (network-closed) ad in /my_ads", "placeholders": [],
     "default": "⏸ Temporarily disactivated — its network is closed. It will open automatically when the network is back.\n\n"},
    {"key": "ad_ghosted_notify", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Tells the owner their ad was paused because its network closed", "placeholders": ["id"],
     "default": "⏸ Your ad #{id} has been temporarily disactivated because its network was closed. You can still see it in 🤝 P2P Trading → 🗂 My Ads — it will open soon, once the network is back."},
    {"key": "ad_restored_notify", "command": "/post_ad", "trigger": "system", "state": "Merchant",
     "label": "Tells the owner their ad is active again after the network reopened", "placeholders": ["id"],
     "default": "✅ Your ad #{id} is active again — its network has reopened."},
    {"key": "myad_not_yours", "command": "/my_ads", "trigger": "button", "state": "Merchant",
     "label": "Acting on an ad that isn't the merchant's", "placeholders": [],
     "default": "This ad is not yours."},
    {"key": "myad_already_removed", "command": "/my_ads", "trigger": "button", "state": "Merchant",
     "label": "Cancelling an already-removed ad", "placeholders": [],
     "default": "This ad is already removed."},
    {"key": "myad_cancelled", "command": "/my_ads", "trigger": "button", "state": "Merchant",
     "label": "Ad cancelled confirmation", "placeholders": ["id"],
     "default": "🗑 Ad #{id} has been cancelled."},
    {"key": "myad_edit_inactive", "command": "/my_ads", "trigger": "button", "state": "Merchant",
     "label": "Editing an ad that is no longer active", "placeholders": [],
     "default": "This ad is no longer active."},
    {"key": "myad_edit_intro", "command": "/my_ads", "trigger": "button", "state": "Merchant",
     "label": "Intro line when starting to edit an ad", "placeholders": ["id", "ad_type"],
     "default": "✏️ Editing ad #{id} ({ad_type}).\n\nPlease enter the minimum amount (USDT):"},

    # ---- /ads ----
    {"key": "ads_ask_side", "command": "/ads", "trigger": "command", "state": "Registered",
     "label": "Ask whether the user wants to Buy or Sell", "placeholders": [],
     "default": "Do you want to Buy or Sell USDT?"},
    {"key": "ads_none", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "No ads available to browse", "placeholders": [],
     "default": "No ads available right now. Please check back later."},
    {"key": "browse_ad_sell_text", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Ad card for a SELL ad (merchant selling USDT) — single 'Asset ON' network", "placeholders": ["side_label", "merchant_id", "price", "fiat", "min", "max", "methods", "minutes", "total_trades", "success_rate", "last_seen", "network_line"],
     "default": "{side_label}\n\n🆔 Merchant: {merchant_id}\n💰 Price: {price} {fiat} / USDT\n📉 Min Amount: {min} USDT\n📈 Max Amount: {max} USDT\n💳 Payment Methods: {methods}\n⏱ Payment Time: {minutes} minutes\n🔗 Asset ON: {network_line}\n📊 Total Trades: {total_trades}\n⭐ Success Rate: {success_rate}%\n🕐 Last Seen: {last_seen}"},
    {"key": "browse_ad_buy_text", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Ad card for a BUY ad (merchant buying USDT) — 'Accepted USDT Network' list", "placeholders": ["side_label", "merchant_id", "price", "fiat", "min", "max", "methods", "minutes", "total_trades", "success_rate", "last_seen", "network_line"],
     "default": "{side_label}\n\n🆔 Merchant: {merchant_id}\n💰 Price: {price} {fiat} / USDT\n📉 Min Amount: {min} USDT\n📈 Max Amount: {max} USDT\n💳 Payment Methods: {methods}\n⏱ Payment Time: {minutes} minutes\n✅ Accepted USDT Network:\n🔗 {network_line}\n📊 Total Trades: {total_trades}\n⭐ Success Rate: {success_rate}%\n🕐 Last Seen: {last_seen}"},
    {"key": "ads_nav_first", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Already at the first ad", "placeholders": [],
     "default": "This is the first ad."},
    {"key": "ads_nav_last", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "No more ads to show", "placeholders": [],
     "default": "No more ads."},
    {"key": "ads_browse_use", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Navigation pressed without a browse session", "placeholders": [],
     "default": "Tap 🤝 P2P Trading → 📢 Browse Ads to start browsing."},
    {"key": "ads_ad_unavailable", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "The selected ad is no longer available", "placeholders": [],
     "default": "This ad is no longer available."},
    {"key": "ads_own_ad", "command": "/ads", "trigger": "button", "state": "Merchant",
     "label": "Merchant tried to trade against their own ad", "placeholders": [],
     "default": "This is your own ad — you can't trade against yourself. Tap 🤝 P2P Trading → 🗂 My Ads to manage it."},
    {"key": "ads_own_ad_tag", "command": "/ads", "trigger": "button", "state": "Merchant",
     "label": "Banner prefixed to the merchant's own ad in the browse list", "placeholders": [],
     "default": "⭐ This is your ad\n\n"},
    {"key": "ads_finish_active", "command": "/ads", "trigger": "button", "state": "Has active trade",
     "label": "User must finish their current trade first", "placeholders": [],
     "default": "Please finish your active trade first. Tap 🤝 P2P Trading → 📦 My Order to continue."},
    {"key": "ads_merchant_busy", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "The merchant is currently in another trade", "placeholders": [],
     "default": "This merchant is currently in an active trade. Please try again later."},
    {"key": "ads_summary_total", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Summary when all ads fit in one batch (≤10)", "placeholders": ["total"],
     "default": "Total Ads: {total}."},
    {"key": "ads_summary_more", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Summary when there are more ads beyond the current batch", "placeholders": ["remaining"],
     "default": "There are {remaining} more ads. Please use the buttons below to browse them."},
    {"key": "ads_ask_amount", "command": "/ads", "trigger": "button", "state": "Registered",
     "label": "Ask how much USDT to buy/sell", "placeholders": ["verb", "min", "max"],
     "default": "How much USDT do you want to {verb}?\n(Min {min} — Max {max} USDT)"},

    # ---- order creation ----
    {"key": "ordc_ad_gone", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Ad disappeared mid-order", "placeholders": [],
     "default": "This ad is no longer available. Tap 🤝 P2P Trading → 📢 Browse Ads to browse again."},
    {"key": "ordc_amount_invalid", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Order amount is not a valid number", "placeholders": [],
     "default": "Please send a valid number for the amount:"},
    {"key": "ordc_amount_low", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Order amount below the ad minimum", "placeholders": ["min"],
     "default": "Amount too low. Minimum allowed: {min} USDT"},
    {"key": "ordc_amount_high", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Order amount above the ad maximum", "placeholders": ["max"],
     "default": "Amount too high. Maximum allowed: {max} USDT"},
    {"key": "ordc_insufficient", "command": "Order creation", "trigger": "system", "state": "Selling user",
     "label": "Seller lacks the balance to sell that amount", "placeholders": ["available", "amount"],
     "default": "❌ Insufficient balance.\n\nYour available balance: {available} USDT\nRequested: {amount} USDT"},
    {"key": "ordc_confirm", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Order amount/price confirmation", "placeholders": ["amount", "price", "fiat", "fiat_cur", "verb"],
     "default": "💱 {amount} USDT × {price} = {fiat} {fiat_cur}\nYou will {verb} {fiat} {fiat_cur}.\n\nPress Process to continue."},
    {"key": "ordc_expired", "command": "Order creation", "trigger": "button", "state": "Registered",
     "label": "Order-creation request expired", "placeholders": [],
     "default": "This request has expired. Tap 🤝 P2P Trading → 📢 Browse Ads to start again."},
    {"key": "ordc_select_method", "command": "Order creation", "trigger": "button", "state": "Registered",
     "label": "Ask which payment method to use", "placeholders": [],
     "default": "Select a payment method:"},
    {"key": "ordc_invalid_method", "command": "Order creation", "trigger": "button", "state": "Registered",
     "label": "Chosen payment method is not valid for the ad", "placeholders": [],
     "default": "Invalid payment method."},
    {"key": "ordc_ask_network", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Ask the user to pick the USDT network for the trade", "placeholders": [],
     "default": "Select the USDT network for this trade:"},
    {"key": "ordc_network_unsupported", "command": "Order creation", "trigger": "button", "state": "Registered",
     "label": "User picked a network the ad/merchant does not support", "placeholders": [],
     "default": "Merchant does not accept this network. Please choose another."},
    {"key": "ordc_network_no_balance", "command": "Order creation", "trigger": "button", "state": "Selling user",
     "label": "User selling has no balance on the chosen network", "placeholders": ["network_short"],
     "default": "You have no USDT balance on {network_short}. Please choose a network where you hold funds."},
    {"key": "ordc_ask_account", "command": "Order creation", "trigger": "system", "state": "Selling user",
     "label": "Ask the seller for their receiving account number", "placeholders": ["method"],
     "default": "Please send your {method} account number."},
    {"key": "ordc_account_too_short", "command": "Order creation", "trigger": "system", "state": "Selling user",
     "label": "Account number has 8 or fewer digits", "placeholders": [],
     "default": "That account number is too short — it must have more than 8 digits. Please send a valid account number."},
    {"key": "ordc_insufficient_changed", "command": "Order creation", "trigger": "system", "state": "Selling user",
     "label": "Balance changed before the order could be locked", "placeholders": [],
     "default": "❌ Insufficient balance — your balance changed. Tap 🤝 P2P Trading → 📢 Browse Ads to start again."},
    {"key": "order_created", "command": "Order creation", "trigger": "system", "state": "Registered",
     "label": "Order created successfully", "placeholders": ["order_id"],
     "default": "✅ Order #{order_id} created!\nTap 🤝 P2P Trading → 📦 My Order to view and continue your trade."},
    {"key": "order_merchant_notify", "command": "Order creation", "trigger": "system", "state": "Merchant (other party)",
     "label": "Notification to the merchant about a new order", "placeholders": ["merchant_name"],
     "default": "Dear {merchant_name}, you have a new order. Please tap 🤝 P2P Trading → 📦 My Order to continue."},
    {"key": "ordc_back_use_ads", "command": "Order creation", "trigger": "button", "state": "Registered",
     "label": "Back pressed with no browse session", "placeholders": [],
     "default": "Tap 🤝 P2P Trading → 📢 Browse Ads to browse ads."},

    # ---- /order ----
    {"key": "order_lock_message", "command": "/order", "trigger": "system", "state": "Has active trade",
     "label": "Shown when any command/menu/text is blocked during an active order (order reopened below)", "placeholders": [],
     "default": "Please finish your active order first."},
    {"key": "order_none", "command": "/order", "trigger": "command", "state": "Registered",
     "label": "User has no active order", "placeholders": [],
     "default": "You have no active order. Tap 🤝 P2P Trading → 📢 Browse Ads to start trading."},
    {"key": "order_text", "command": "/order", "trigger": "command", "state": "Has active trade",
     "label": "The active-trade order screen", "placeholders": ["order_id", "merchant_name", "buyer_rname", "seller_rname", "usdt_amount", "fiat_amount", "fiat", "payment_method", "payment_account_number", "order_status", "role_line"],
     "default": "🧾 Order #{order_id}\n\n{role_line}\n\nMerchant Name: {merchant_name}\nBuyer Name: {buyer_rname}\nSeller Name: {seller_rname}\nUSDT Amount: {usdt_amount} USDT\nFiat Amount: {fiat_amount} {fiat}\nPayment Method: {payment_method}\nAccount Number: {payment_account_number}\nStatus: {order_status}\n\nTap 💬 Message below to chat with the other trader."},
    {"key": "order_role_receive", "command": "/order", "trigger": "system", "state": "Has active trade",
     "label": "Role line shown to the trader who will RECEIVE USDT on this order", "placeholders": ["amount"],
     "default": "⬇️ You will RECEIVE {amount} USDT on this order."},
    {"key": "order_role_send", "command": "/order", "trigger": "system", "state": "Has active trade",
     "label": "Role line shown to the trader who will SEND USDT on this order", "placeholders": ["amount"],
     "default": "⬆️ You will SEND {amount} USDT on this order."},
    {"key": "order_inactive", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Order is no longer active", "placeholders": [],
     "default": "This order is no longer active."},
    {"key": "order_not_part", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "User is not a party to this order", "placeholders": [],
     "default": "You are not part of this order."},
    {"key": "order_only_buyer_paid", "command": "/order", "trigger": "button", "state": "Seller",
     "label": "Only the buyer can press I Have Paid", "placeholders": [],
     "default": "Only the buyer can press I Have Paid."},
    {"key": "order_already_paid", "command": "/order", "trigger": "button", "state": "Buyer",
     "label": "Order already marked paid", "placeholders": [],
     "default": "Already marked as paid."},
    {"key": "order_paid_done", "command": "/order", "trigger": "button", "state": "Buyer",
     "label": "Buyer marked the order as paid", "placeholders": ["order_id"],
     "default": "💵 Order #{order_id} marked as Paid. Waiting for the seller to release funds."},
    {"key": "order_paid_notify", "command": "/order", "trigger": "system", "state": "Seller (other party)",
     "label": "Notify seller that buyer marked paid", "placeholders": ["order_id"],
     "default": "💵 Order #{order_id}: the buyer marked the payment as done. Please verify you received the money, then press Release Fund."},
    {"key": "order_only_seller_release", "command": "/order", "trigger": "button", "state": "Buyer",
     "label": "Only the seller can release funds", "placeholders": [],
     "default": "Only the seller can release funds."},
    {"key": "order_wait_payment", "command": "/order", "trigger": "button", "state": "Seller",
     "label": "Seller tried to release before payment", "placeholders": [],
     "default": "Please wait for payment confirmation first."},
    {"key": "order_complete_fail", "command": "/order", "trigger": "button", "state": "Seller",
     "label": "Order could not be completed", "placeholders": [],
     "default": "Could not complete the order. Please contact an admin."},
    {"key": "order_completed_seller", "command": "/order", "trigger": "button", "state": "Seller",
     "label": "Completion message shown to the seller", "placeholders": ["order_id", "amount"],
     "default": "✅ Order #{order_id} completed! {amount} USDT transferred to the buyer."},
    {"key": "order_completed_buyer", "command": "/order", "trigger": "system", "state": "Buyer (other party)",
     "label": "Completion message sent to the buyer", "placeholders": ["order_id", "amount", "network_hint"],
     "default": "✅ Order #{order_id} completed! {amount} USDT has been credited to your balance.{network_hint}"},
    {"key": "order_cancel_paid_block", "command": "/order", "trigger": "button", "state": "Seller",
     "label": "Cannot cancel after buyer marked paid", "placeholders": [],
     "default": "The buyer already marked as paid — please use Request Admin instead."},
    {"key": "order_cancelled", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Order cancelled confirmation", "placeholders": ["order_id"],
     "default": "❌ Order #{order_id} has been cancelled."},
    {"key": "order_cancel_sent", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Cancel request sent, awaiting the other trader's agreement", "placeholders": ["order_id"],
     "default": "🕊 Cancel request sent for order #{order_id}. The order will only be cancelled if the other trader agrees."},
    {"key": "order_cancel_ask", "command": "/order", "trigger": "system", "state": "Other party",
     "label": "Ask the other trader to agree to a cancellation", "placeholders": ["order_id"],
     "default": "⚠️ The other trader wants to cancel order #{order_id}. Are you OK with that?"},
    {"key": "order_cancel_self", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Requester tried to answer their own cancel request", "placeholders": [],
     "default": "You started this cancel request — the other trader has to respond."},
    {"key": "order_cancel_expired", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Cancel request no longer active", "placeholders": [],
     "default": "This cancel request is no longer active."},
    {"key": "order_cancel_agreed_notify", "command": "/order", "trigger": "system", "state": "Requester",
     "label": "Notify the requester that the other trader agreed to cancel", "placeholders": ["order_id"],
     "default": "✅ The other trader agreed. Order #{order_id} has been cancelled."},
    {"key": "order_cancel_declined_self", "command": "/order", "trigger": "button", "state": "Other party",
     "label": "Confirmation shown to the trader who declined the cancellation", "placeholders": ["order_id"],
     "default": "Order #{order_id} stays active — you declined the cancellation."},
    {"key": "order_cancel_declined_notify", "command": "/order", "trigger": "system", "state": "Requester",
     "label": "Notify the requester that their cancellation was declined", "placeholders": ["order_id"],
     "default": "🚫 The other trader declined to cancel order #{order_id}. The trade is still active — press 🛡 Request Admin if you need help."},
    {"key": "order_admin_requested", "command": "/order", "trigger": "button", "state": "Registered",
     "label": "Admin review requested confirmation", "placeholders": ["order_id"],
     "default": "🛡 Admin review requested for order #{order_id}. An admin will review it shortly."},
    {"key": "order_admin_notify", "command": "/order", "trigger": "system", "state": "Other party",
     "label": "Notify the other trader that admin review was requested", "placeholders": ["order_id"],
     "default": "🛡 Admin review was requested for order #{order_id}."},

    # ---- /message (persistent in-trade relay chat) ----
    {"key": "message_no_trade", "command": "/message", "trigger": "command", "state": "Registered",
     "label": "No active trade to message in", "placeholders": [],
     "default": "You have no active trade."},
    {"key": "message_enter_sender", "command": "/message", "trigger": "command", "state": "Has active trade",
     "label": "Shown to the user when they open the trade chat", "placeholders": [],
     "default": "💬 You are now in the active trade messaging system. Anything you send (text, image) will be seen by the other trader.\n\nUse /cancel to exit."},
    {"key": "message_enter_receiver", "command": "/message", "trigger": "system", "state": "Other party",
     "label": "Notifies the other trader that a chat was opened", "placeholders": [],
     "default": "💬 The other trader opened the chat. Tap 🤝 P2P Trading → 💬 Message Trader to reply."},
    {"key": "message_already_in", "command": "/message", "trigger": "command", "state": "In trade chat",
     "label": "Shown when the user runs /message but is already in trade chat", "placeholders": [],
     "default": "You are already in the trade chat. Just type your message. Use /cancel to exit."},
    {"key": "message_relay", "command": "/message", "trigger": "system", "state": "Other party",
     "label": "How a relayed message is shown to the other trader", "placeholders": ["sender", "text"],
     "default": "{sender} - {text}\n\nTap 🤝 P2P Trading → 💬 Message Trader to reply. Use /cancel to exit."},
    {"key": "message_sent", "command": "/message", "trigger": "system", "state": "In trade chat",
     "label": "Acknowledgement after the user sends a chat message", "placeholders": [],
     "default": "✅ Your message is sent. Use /cancel to exit or continue chatting."},
    {"key": "message_relay_failed", "command": "/message", "trigger": "system", "state": "In trade chat",
     "label": "Shown when the message could not be delivered to the other trader", "placeholders": [],
     "default": "⚠️ Couldn't deliver your message to the other trader right now. Please try again in a moment."},
    {"key": "message_media_blocked", "command": "/message", "trigger": "system", "state": "In trade chat",
     "label": "Shown when the user sends an unsupported attachment in trade chat", "placeholders": [],
     "default": "Only text and images can be sent in the trade chat."},
    {"key": "trade_chat_exited", "command": "/cancel", "trigger": "command", "state": "In trade chat",
     "label": "Sent when the user uses /cancel to exit the trade chat", "placeholders": [],
     "default": "You have exited the trade chat. Tap 🤝 P2P Trading → 💬 Message Trader to reopen it during your trade."},

    # ---- /order_history ----
    {"key": "orderhist_none", "command": "/order_history", "trigger": "command", "state": "Registered",
     "label": "User has no past orders", "placeholders": [],
     "default": "You have no past orders yet. Tap 🤝 P2P Trading → 📢 Browse Ads to start trading."},
    {"key": "orderhist_header", "command": "/order_history", "trigger": "command", "state": "Registered",
     "label": "Heading shown above the order history list", "placeholders": ["count"],
     "default": "🧾 Your Order History (last {count}):"},
    {"key": "orderhist_item", "command": "/order_history", "trigger": "command", "state": "Registered",
     "label": "One order line in the history list", "placeholders": ["order_id", "role", "counterparty", "usdt_amount", "fiat_amount", "fiat", "status", "date"],
     "default": "🧾 Order #{order_id}\nRole: {role}\nCounterparty: {counterparty}\nAmount: {usdt_amount} USDT ({fiat_amount} {fiat})\nStatus: {status}\nDate: {date}"},

    # ---- /transaction_history ----
    {"key": "txhist_none", "command": "/transaction_history", "trigger": "command", "state": "Registered",
     "label": "User has no transactions yet", "placeholders": [],
     "default": "You have no transactions yet. Your deposits, withdrawals and internal transfers will appear here."},
    {"key": "txhist_header", "command": "/transaction_history", "trigger": "command", "state": "Registered",
     "label": "Heading shown above the transaction history list", "placeholders": ["count"],
     "default": "🧾 Your Transaction History (last {count}):"},
    {"key": "txhist_item", "command": "/transaction_history", "trigger": "command", "state": "Registered",
     "label": "One transaction line in the history list", "placeholders": ["icon", "title", "sign", "amount", "token", "detail", "status", "date"],
     "default": "{icon} {title}\nAmount: {sign}{amount} {token}\n{detail}Status: {status}\nDate: {date}"},

    # ---- /contact ----
    {"key": "contact_ask_message", "command": "/contact", "trigger": "command", "state": "Any",
     "label": "Prompt shown to start the support message wizard", "placeholders": [],
     "default": "Please Send your Message to support Team:"},
    {"key": "contact_session_started", "command": "/contact", "trigger": "system", "state": "Any",
     "label": "Sent after the user's first support message — confirms active chat session started", "placeholders": [],
     "default": "Your message has been sent!\n\nYou are now in an active support chat — any message you send here will reach us directly.\n\nUse /cancel to exit the chat."},
    {"key": "chat_message_received", "command": "/contact", "trigger": "system", "state": "In active chat",
     "label": "Acknowledgement for each message the user sends while in active support chat", "placeholders": [],
     "default": "Message received. Use /cancel to exit the chat."},
    {"key": "chat_exited", "command": "/cancel", "trigger": "command", "state": "In active chat",
     "label": "Sent when the user uses /cancel to exit the active support chat", "placeholders": [],
     "default": "You have exited the support chat. If you need help again, tap 🛠️ Support & More → 🛠 Contact Support."},
    {"key": "contact_command_blocked", "command": "Any", "trigger": "system", "state": "In active chat",
     "label": "Shown when a user tries to use a /command while in active support chat", "placeholders": [],
     "default": "You cannot use commands while in a support chat.\n\nPlease exit first using /cancel if needed."},
    {"key": "chat_menu_blocked", "command": "Any", "trigger": "system", "state": "In a chat room",
     "label": "Shown when a user taps a menu button while in a support or trade chat", "placeholders": [],
     "default": "💬 You're in a chat right now. Please leave it first by sending /cancel, then you can use the menu."},

    # ---- /become_merchant ----
    {"key": "become_merchant_already", "command": "/become_merchant", "trigger": "command", "state": "Merchant",
     "label": "User is already a merchant", "placeholders": [],
     "default": "✅ You are already a Merchant! Tap 🤝 P2P Trading → 📝 Post Ad to create your first ad."},
    {"key": "bm_intro", "command": "/become_merchant", "trigger": "command", "state": "Registered",
     "label": "Step 1 — intro + intention question (BUY/SELL/BOTH buttons)", "placeholders": ["rname"],
     "default": "🏪 {rname}, you would like to become a Merchant on this platform.\n\nCan you please tell us your intention — what would you like to do here?"},
    {"key": "bm_pending_exists", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Shown when the user already has a pending merchant request", "placeholders": [],
     "default": "⏳ You already have a Merchant request under review. Please wait for our team to respond."},
    {"key": "bm_ask_phone", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Step 2 — ask for the phone number the Telegram account was created on", "placeholders": [],
     "default": "📱 Could you please provide a phone number — the one your Telegram account was created on?\n\n(Numbers only.)"},
    {"key": "bm_phone_invalid", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Phone number validation failed (non-digits entered)", "placeholders": [],
     "default": "⚠️ Please enter numbers only — no letters or symbols. Try again."},
    {"key": "bm_ask_experience", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Step 3 — ask whether the user has merchant experience elsewhere (Yes/No buttons)", "placeholders": [],
     "default": "💼 Do you have experience being a Merchant on other platforms?"},
    {"key": "bm_ask_message", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Step 4 — ask for an optional message", "placeholders": [],
     "default": "✍️ If you have any message for us, please write it now.\n\nIf you don't, just send \"Yes\"."},
    {"key": "bm_review", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Step 5 — summary of collected data before submission (Send/Cancel buttons)",
     "placeholders": ["rname", "intention", "phone", "experience", "message"],
     "default": "📋 Please review your Merchant request:\n\n👤 Name: {rname}\n🎯 Intention: {intention}\n📱 Phone: {phone}\n💼 Experience: {experience}\n✍️ Message: {message}\n\nSend this request to our team?"},
    {"key": "bm_submitted", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Confirmation after the request is sent", "placeholders": [],
     "default": "✅ Your Merchant request has been submitted. Our team will review it and get back to you soon."},
    {"key": "bm_cancelled", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Shown when the user cancels the request", "placeholders": [],
     "default": "❌ Your Merchant request has been cancelled."},
    {"key": "bm_expired", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Shown when a wizard button is pressed but the session has expired", "placeholders": [],
     "default": "This Merchant application has expired. Please start again via 🤝 P2P Trading → ⭐ Become Merchant."},
    {"key": "bm_approved", "command": "/become_merchant", "trigger": "system", "state": "Merchant",
     "label": "Sent to the user when an admin approves their request", "placeholders": ["rname"],
     "default": "🎉 Dear {rname}, your Merchant request has been approved!\n\nPlease tap 🤝 P2P Trading → 📝 Post Ad to start your first AD."},
    {"key": "bm_rejected", "command": "/become_merchant", "trigger": "system", "state": "Registered",
     "label": "Sent to the user when an admin rejects their request", "placeholders": ["rname", "reason"],
     "default": "😔 Sorry {rname}, your Merchant request has been rejected for these reasons:\n\n{reason}"},

    # ---- /verify (account verification / KYC) ----
    {"key": "verify_required", "command": "/verify", "trigger": "system", "state": "Unverified",
     "label": "Gate shown when an unverified user tries a restricted action (trade / withdraw / become merchant)", "placeholders": ["action"],
     "default": "🔒 To {action}, you must verify your account first.\n\nPlease verify via 🚀 Getting Started → ✅ Verify."},
    {"key": "verify_required_amount", "command": "/verify", "trigger": "system", "state": "Unverified",
     "label": "Gate shown when an unverified user tries to {action} for more than the unverified limit", "placeholders": ["action", "limit"],
     "default": "🔒 Unverified accounts can {action} up to {limit} USDT at a time.\n\nFor bigger amounts, please verify your account via 🚀 Getting Started → ✅ Verify."},
    {"key": "verify_already", "command": "/verify", "trigger": "command", "state": "Verified",
     "label": "Shown when an already-verified user runs /verify", "placeholders": [],
     "default": "✅ Your account is already verified. You can use all features."},
    {"key": "verify_pending_exists", "command": "/verify", "trigger": "command", "state": "Registered",
     "label": "Shown when the user already has a pending verification request", "placeholders": [],
     "default": "⏳ Your verification is already under review. Please wait for our team to respond."},
    {"key": "verify_ask_front", "command": "/verify", "trigger": "command", "state": "Registered",
     "label": "Step 1 — ask for the front side of the ID", "placeholders": [],
     "default": "🪪 Account Verification — Step 1 of 2\n\nPlease send a clear photo of the FRONT side of your ID.\n\n⚠️ Make sure it is not blurry and has no glare/reflection, or it will not be accepted."},
    {"key": "verify_ask_back", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Step 2 — ask for the back side of the ID", "placeholders": [],
     "default": "🪪 Step 2 of 2\n\nNow send a clear photo of the BACK side of your ID.\n\n⚠️ No blur and no glare/reflection, please."},
    {"key": "verify_confirm_name", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Final step — confirm the account name matches the ID (Done / Change name buttons)", "placeholders": ["rname"],
     "default": "Is your account name *{rname}* the same as the name on the ID you provided?\n\nIf yes, press ✅ Done & Submit.\nIf not, press ✏️ Change name to correct it before submitting."},
    {"key": "verify_ask_firstname", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Change-name sub-step — ask for the first name", "placeholders": [],
     "default": "Please send your FIRST name, exactly as it appears on your ID."},
    {"key": "verify_ask_lastname", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Change-name sub-step — ask for the last name", "placeholders": [],
     "default": "Now send your LAST name, exactly as it appears on your ID."},
    {"key": "verify_submitted", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Confirmation after the verification request is submitted", "placeholders": [],
     "default": "✅ Your verification request has been submitted. Our team will review it and get back to you soon."},
    {"key": "verify_expired", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Shown when a verify wizard button is pressed but the session has expired", "placeholders": [],
     "default": "This verification session has expired. Please start again via 🚀 Getting Started → ✅ Verify."},
    {"key": "verify_need_photo", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Shown when text/other is sent where a photo is expected", "placeholders": [],
     "default": "📷 Please send a photo for this step (not text)."},
    {"key": "verify_unsupported_file", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Shown when a non-image file (document/video/sticker/etc.) is sent during an ID photo step", "placeholders": [],
     "default": "⚠️ Unsupported file. Please send a normal image (photo) for this step, or use /cancel to stop the verification."},
    {"key": "verify_approved", "command": "/verify", "trigger": "system", "state": "Verified",
     "label": "Sent to the user when an admin approves verification", "placeholders": ["rname"],
     "default": "🎉 Dear {rname}, your account has been verified! You can now perform all actions — trading, withdrawals and merchant applications."},
    {"key": "verify_rejected", "command": "/verify", "trigger": "system", "state": "Registered",
     "label": "Sent to the user when an admin rejects verification", "placeholders": ["rname", "reason"],
     "default": "😔 Sorry {rname}, your verification was rejected because of:\n\n{reason}\n\nPlease submit again via 🚀 Getting Started → ✅ Verify."},

    # ---- withdrawal network balance checks ----
    {"key": "withdraw_network_mismatch", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "Shown when user withdraws on a network they haven't deposited to", "placeholders": ["chosen", "deposited"],
     "default": "⚠️ You have no USDT deposits on {chosen}.\n\nYour deposits are on: {deposited}\n\nYou can only withdraw the amount you have on the selected network. Please choose one of your deposit networks."},
    {"key": "withdraw_insufficient_network", "command": "/withdraw", "trigger": "system", "state": "Registered",
     "label": "User requested more USDT than their on-chain balance on this network", "placeholders": ["network", "requested", "available", "other_nets"],
     "default": "❌ Insufficient USDT ({network_short}) balance.\n\nYour balance on {network}: {available} USDT\nRequested: {requested} USDT\n\n{other_nets}Tap 💰 Wallet & Funds → ⬆️ Withdraw again to select a different network."},

    # ---- inline button menu (header text above the submenu buttons) ----
    # The command list is now rendered as tappable inline buttons, so these texts
    # are just the menu header shown above the buttons. Tapping a button runs the
    # matching command. Each submenu has a Back button to return to the home menu.
    {"key": "menu_home", "command": "Menu", "trigger": "button", "state": "Any",
     "label": "Header shown for the home menu (the 4 family buttons)", "placeholders": [],
     "default": "📋 Main Menu\n\nPick a category:"},
    {"key": "menu_family_start", "command": "Menu", "trigger": "button", "state": "Any",
     "label": "Header shown when the 'Getting Started' box is tapped", "placeholders": [],
     "default": "🚀 Getting Started\n\nChoose an option below:"},
    {"key": "menu_family_wallet", "command": "Menu", "trigger": "button", "state": "Any",
     "label": "Header shown when the 'Wallet & Funds' box is tapped", "placeholders": [],
     "default": "💰 Wallet & Funds\n\nChoose an option below:"},
    {"key": "menu_family_trading", "command": "Menu", "trigger": "button", "state": "Any",
     "label": "Header shown when the 'P2P Trading' box is tapped", "placeholders": [],
     "default": "🤝 P2P Trading\n\nChoose an option below:"},
    {"key": "menu_family_support", "command": "Menu", "trigger": "button", "state": "Any",
     "label": "Header shown when the 'Support & More' box is tapped", "placeholders": [],
     "default": "🛠️ Support & More\n\nChoose an option below:"},

    # ---- session guard (stray command / family-box tap mid-wizard) ----
    {"key": "session_guard", "command": "General", "trigger": "system", "state": "In a flow",
     "label": "Shown when a user sends a command or taps a menu box while a flow is waiting for input", "placeholders": ["action", "expected"],
     "default": "⏳ You're still {action}.\n\nPlease send {expected} to continue — or use /cancel to exit first."},
]

_RESPONSE_INDEX = {e["key"]: e for e in RESPONSE_DEFAULTS}
_RESPONSE_CACHE = None  # key -> live template text (loaded from DB on first use)

# Responses introduced for / specific to the button-menu system. The dashboard's
# Command Response section exposes an Old/New switch; "New" shows exactly these so
# the admin can tune the menu wording without hunting through the old command
# replies (which stay where they are). Add a key here to surface it under "New".
MENU_RESPONSE_KEYS = {
    "menu_home",
    "menu_family_start", "menu_family_wallet",
    "menu_family_trading", "menu_family_support",
    "list_registered",      # the 📖 Menu Guide
    "unknown_command",      # "use the menu buttons below" nudge
    "chat_menu_blocked",    # tapped a menu button while in a chat room
    "wallet_internal",      # internal account number (TID) card
    "order_role_receive", "order_role_send",  # receive/send USDT role line
}


class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _safe_format(text, kw):
    """Format a template, leaving any unknown {placeholder} untouched and never raising."""
    try:
        return string.Formatter().vformat(text, (), _SafeDict(**{k: str(v) for k, v in kw.items()}))
    except Exception:
        return text


def ensure_response_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS command_response (
            key VARCHAR(64) PRIMARY KEY,
            template TEXT NOT NULL,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # seed any keys that don't have a row yet; never overwrite an admin edit
    for e in RESPONSE_DEFAULTS:
        cur.execute(
            "INSERT INTO command_response (key, template) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
            (e["key"], e["default"])
        )
    # One-off migration: the trade-chat relay line used to be hardcoded
    # "Trader - {text}". Move any row still on that exact old default to the new
    # name-aware template so the recipient sees the sender's real name. Rows an
    # admin has customised (anything other than the old default) are left alone.
    cur.execute(
        "UPDATE command_response SET template = %s WHERE key = 'message_relay' AND template = %s",
        (_RESPONSE_INDEX["message_relay"]["default"],
         "Trader - {text}\n\nUse /message to reply. Use /cancel to exit.")
    )
    # One-off migration: the /balance + /wallet displays were redesigned (clean
    # emoji-per-network rows, a short inline DISACTIVATED tag, and per-network
    # /wallet warnings). Move rows still on a known old default to the new one;
    # anything an admin has since customised is left untouched.
    _redesign_migrations = [
        # The ad minimum is now 5 USDT (was "greater than 0") to match the webview.
        ("postad_min_positive", [
            "The minimum amount must be greater than 0. Please try again:",
        ]),
        ("postad_ask_min", [
            "Please enter the minimum amount (USDT):",
        ]),
        # Verification no longer asks for a selfie-with-ID — front + back only,
        # so the step counters drop from "of 3" to "of 2".
        ("verify_ask_front", [
            "🪪 Account Verification — Step 1 of 3\n\nPlease send a clear photo of the FRONT side of your ID.\n\n⚠️ Make sure it is not blurry and has no glare/reflection, or it will not be accepted.",
        ]),
        ("verify_ask_back", [
            "🪪 Step 2 of 3\n\nNow send a clear photo of the BACK side of your ID.\n\n⚠️ No blur and no glare/reflection, please.",
        ]),
        ("balance_info", [
            "💰 Your USDT Balance\n\nBy Network:\n{net_lines}\n\nTotal: {total} USDT{available_line}",
        ]),
        ("balance_net_line", [
            "  USDT ({network_short}): {amount}",
        ]),
        ("network_disabled_tag", [
            "  ⚠️ DISACTIVATED — Don't send money to this network!",
            "  ⚠️ DISACTIVATED — Don't send money to this network! ({networks})",
        ]),
        # The family boxes used to reply with a text list of /commands; they now
        # open an inline button submenu, so the text is just a header. Move rows
        # still on the old command-list default to the new header.
        ("menu_family_start", [
            "🚀 Getting Started\n\n/start — Welcome / restart the bot\n/create_account — Register your account\n/verify — Verify your account (KYC)\n/account — View your account information",
        ]),
        ("menu_family_wallet", [
            "💰 Wallet & Funds\n\n/wallet — Your USDT deposit wallets\n/balance — Your current USDT balance\n/deposit — Deposit USDT (select a network)\n/withdraw — Withdraw USDT (internal or on-chain)",
        ]),
        ("menu_family_trading", [
            "🤝 P2P Trading\n\n/ads — Browse merchant Buy/Sell ads\n/order — View your active trade\n/order_history — View your past orders\n/message — Message the other trader during a trade\n/post_ad — Create an ad (merchants only)\n/my_ads — Manage your ads (merchants only)\n/become_merchant — Apply to become a Merchant",
        ]),
        ("menu_family_support", [
            "🛠️ Support & More\n\n/contact — Contact support\n/list — View the full command list\n/cancel — Cancel whatever you're currently doing\n/clear — Clear the recent chat messages",
        ]),
        # The bot moved from typed commands to the bottom button menu, so the
        # onboarding / exit texts no longer tell users to send /commands. Move
        # rows still on the old command-pointing default to the new menu wording.
        ("start_new", [
            "Welcome, {first_name}!\nThis bot helps you conduct secure P2P USDT cryptocurrency trades between buyers and sellers.\nTo get started, create your account by sending:\n/create_account\n\nHappy trading! 🚀💰",
        ]),
        ("start_returning", [
            "Hello, {first_name}!\nWelcome back.\nYour account has already been created and is ready to use.\nSend /list to view all available commands and features.\n\nHappy trading! 🚀💰",
        ]),
        ("not_registered", [
            "Hello {first_name},\n\nYou are not registered yet. Please send /create_account first to create your account and get started.",
        ]),
        ("unknown_command", [
            "Unknown command. Please use /start to continue.",
        ]),
        ("cancel_done", [
            "✅ Done. Your current request was cancelled.\n\nStart with /list to begin again.",
        ]),
        ("cancel_nothing", [
            "There is nothing to cancel.\n\nStart with /list to begin.",
        ]),
        ("chat_cleared", [
            "🧹 Chat cleared.\n\nStart with /list to begin again.",
        ]),
        ("create_account_exists", [
            "Dear {first_name}, your account is already created. Please send /list to see what you can do.",
        ]),
        ("account_created", [
            "Account created successfully, {real_name}!\nYour USDT deposit wallets are ready — send /wallet to view them.\nUse /start to see options.",
        ]),
        ("list_registered", [
            "📋 Available Commands:\n\n/start — Show welcome message\n/list — View this command list\n/create_account — Register your account\n/account — View your account information\n/wallet — View your USDT deposit wallets\n/balance — View your current USDT balance\n/verify — Verify your account (required to trade, withdraw or become a merchant)\n/deposit — Deposit USDT (select a network)\n/withdraw — Withdraw USDT to an external wallet\n/ads — Browse merchant Buy/Sell ads\n/post_ad — Create an ad (merchants only)\n/my_ads — Manage your ads (merchants only)\n/order — View your active trade\n/order_history — View your past orders\n/message — Message the other trader during a trade\n/become_merchant — Apply to become a Merchant\n/contact — Contact support\n/cancel — Cancel whatever you're currently doing\n/clear — Clear the recent chat messages\n\nHappy trading! 🚀💰",
        ]),
        ("order_network_hint", [
            "\n\n💡 Your balance is on: {nets} — use /withdraw to send on-chain.",
        ]),
        ("order_network_hint_generic", [
            "\n\n💡 Use /withdraw to send your USDT on-chain.",
        ]),
        ("qr_choose_first", [
            "Please first choose your wallet using /wallet, then tap the QR link under the network you want.",
        ]),
        ("withdraw_active_order", [
            "Your funds are protected while you have an active P2P trade. Please finish your trade first — use /order to continue.",
        ]),
        ("withdraw_int_ask_tid", [
            "💸 Internal Transfer (0 Fee)\n\nPlease send the recipient's TID (every user can see their own TID with /account):",
        ]),
        ("withdraw_int_done", [
            "✅ Transfer complete!\n{amount} USDT was sent to {name} (TID {tid}) with 0 fees.\nUse /balance to check your balance.",
        ]),
        ("withdraw_int_received", [
            "💰 You received {amount} USDT from {name} (TID {tid}) via internal transfer.\nUse /balance to check your balance.",
        ]),
        ("withdraw_int_failed", [
            "❌ The internal transfer could not be completed: your available balance changed or the recipient is unavailable. Please use /withdraw to try again.",
        ]),
        ("withdraw_locked", [
            "🔒 Part of your balance is locked in an active P2P trade or ad and cannot be withdrawn.\n\nTotal balance: {total} USDT\nLocked: {locked} USDT\nAvailable: {available} USDT\n\nPlease send a smaller amount, or /list to start again.",
        ]),
        ("withdraw_insufficient", [
            "❌ Insufficient balance.\n\nAvailable balance: {available} USDT\nRequested: {amount} USDT\n\nPlease send a smaller amount, or /list to start again.",
        ]),
        ("withdraw_expired", [
            "This withdraw request has expired. Please use /withdraw to start again.",
        ]),
        ("withdraw_cancelled", [
            "Your withdrawal request has been canceled. Please send /list to continue.",
        ]),
        ("withdraw_failed", [
            "❌ Withdrawal failed: your available balance no longer covers this amount, or your wallet status changed.\nPlease check /balance and use /withdraw to try again.",
        ]),
        ("withdraw_has_active_ad", [
            "You have an active ad. Please remove it first.",
        ]),
        ("deposit_received", [
            "💰 Deposit received!\n\n{amount} USDT arrived via {label} and has been credited to your balance.\nUse /balance to check it.",
        ]),
        ("postad_wizard_expired", [
            "This wizard has expired. Use /post_ad to start again.",
        ]),
        ("postad_lock_failed", [
            "❌ Could not lock funds — your available balance changed. Please /post_ad again.",
        ]),
        ("postad_create_failed", [
            "❌ Could not save your ad — something went wrong. Please /post_ad again.",
        ]),
        ("postad_result_body", [
            "{head}\n\nType: {ad_type}\n{network_line}Min: {min} USDT\nMax: {max} USDT\nPrice: {price} {fiat} / USDT\nPayment Methods: {methods}\nPayment Time: {minutes} minutes\n\nUse /my_ads to manage your ads.",
        ]),
        ("myads_none", [
            "You have no active ads. Use /post_ad to create one.",
        ]),
        ("ad_ghosted_notify", [
            "⏸ Your ad #{id} has been temporarily disactivated because its network was closed. You can still see it in /my_ads — it will open soon, once the network is back.",
        ]),
        ("ads_browse_use", [
            "Use /ads to start browsing.",
        ]),
        ("ads_own_ad", [
            "This is your own ad — you can't trade against yourself. Use /my_ads to manage it.",
        ]),
        ("ads_finish_active", [
            "Please finish your active trade first. Use /order to continue.",
        ]),
        ("ordc_ad_gone", [
            "This ad is no longer available. Use /ads to browse again.",
        ]),
        ("ordc_expired", [
            "This request has expired. Use /ads to start again.",
        ]),
        ("ordc_insufficient_changed", [
            "❌ Insufficient balance — your balance changed. Use /ads to start again.",
        ]),
        ("order_created", [
            "✅ Order #{order_id} created!\nUse /order to view and continue your trade.",
        ]),
        ("order_merchant_notify", [
            "Dear {merchant_name}, you have a new order. Please use /order to continue.",
        ]),
        ("ordc_back_use_ads", [
            "Use /ads to browse ads.",
        ]),
        ("order_lock_message", [
            "Please finish your active trade first. Use /order to continue.",
        ]),
        ("order_none", [
            "You have no active order. Use /ads to start trading.",
        ]),
        ("order_text", [
            "🧾 Order #{order_id}\n\nMerchant Name: {merchant_name}\nBuyer Name: {buyer_rname}\nSeller Name: {seller_rname}\nUSDT Amount: {usdt_amount} USDT\nFiat Amount: {fiat_amount} {fiat}\nPayment Method: {payment_method}\nAccount Number: {payment_account_number}\nStatus: {order_status}\n\nUse /message to chat with the other trader.",
        ]),
        ("message_enter_receiver", [
            "💬 The other trader opened the chat. Use /message to reply.",
        ]),
        ("message_relay", [
            "{sender} - {text}\n\nUse /message to reply. Use /cancel to exit.",
        ]),
        ("trade_chat_exited", [
            "You have exited the trade chat. Use /message to reopen it during your trade.",
        ]),
        ("orderhist_none", [
            "You have no past orders yet. Use /ads to start trading.",
        ]),
        ("chat_exited", [
            "You have exited the support chat. If you need help again, use /contact.",
        ]),
        ("become_merchant_already", [
            "✅ You are already a Merchant! Use /post_ad to create your first ad.",
        ]),
        ("bm_expired", [
            "This Merchant application has expired. Please start again with /become_merchant.",
        ]),
        ("bm_approved", [
            "🎉 Dear {rname}, your Merchant request has been approved!\n\nPlease use /post_ad to start your first AD.",
        ]),
        ("verify_required", [
            "🔒 To {action}, you must verify your account first.\n\nPlease verify your account using /verify.",
        ]),
        ("verify_expired", [
            "This verification session has expired. Please start again with /verify.",
        ]),
        ("verify_rejected", [
            "😔 Sorry {rname}, your verification was rejected because of:\n\n{reason}\n\nPlease submit again using /verify.",
        ]),
        ("withdraw_insufficient_network", [
            "❌ Insufficient USDT ({network_short}) balance.\n\nYour balance on {network}: {available} USDT\nRequested: {requested} USDT\n\n{other_nets}Use /withdraw again to select a different network.",
        ]),
    ]
    for key, old_templates in _redesign_migrations:
        for old in old_templates:
            cur.execute(
                "UPDATE command_response SET template = %s WHERE key = %s AND template = %s",
                (_RESPONSE_INDEX[key]["default"], key, old)
            )
    # --- Menu-era refresh + cleanup (automatic, idempotent) ----------------
    # The bot is now menu-driven, but rows seeded before that redesign can still
    # carry pre-menu wording that tells users to type /commands that no longer
    # work. Walk every stored row once:
    #   * a row whose key is no longer in the registry is a retired response —
    #     delete it so the Management → Command Response section never lists a
    #     reply the bot can't send;
    #   * a row whose template still mentions a retired command (anything but
    #     /cancel and /qr*) is stale pre-menu text — reset it to the current
    #     menu-based default.
    # Clean rows — including genuine admin edits that reference no retired
    # command — are left exactly as they are. The whole pass is safe to re-run on
    # every startup, so the section always reflects what the bot actually replies.
    cur.execute("SELECT key, template FROM command_response")
    for k, t in cur.fetchall():
        meta = _RESPONSE_INDEX.get(k)
        if meta is None:
            cur.execute("DELETE FROM command_response WHERE key = %s", (k,))
        elif t and _RETIRED_CMD_RE.search(t):
            cur.execute("UPDATE command_response SET template = %s WHERE key = %s",
                        (meta["default"], k))
    conn.commit()
    cur.close()
    release_connection(conn)
    global _RESPONSE_CACHE
    _RESPONSE_CACHE = None  # force reload on next access


def _load_response_cache():
    global _RESPONSE_CACHE
    if _RESPONSE_CACHE is not None:
        return _RESPONSE_CACHE
    cache = {}
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT key, template FROM command_response")
        for k, t in cur.fetchall():
            cache[k] = t
        cur.close()
        release_connection(conn)
    except Exception:
        pass  # table missing / DB down -> fall back to registry defaults
    _RESPONSE_CACHE = cache
    return cache


# The bot is menu-driven: the ONLY slash-commands a user may ever see are /cancel
# and the /qr* address commands. Every other command reference is scrubbed from
# responses at render time — a hard guarantee that holds no matter what is stored
# in command_response (a stale row that predates the menu, an admin edit, etc.),
# so we never depend on a migration having run. The leading (^|[\s(]) anchor means
# only a real "/command" mention is matched, never a path inside a URL.
_RETIRED_CMD_RE = re.compile(r"(^|[\s(])/(?!cancel\b)(?!qr)[A-Za-z][A-Za-z0-9_]*\b", re.M)


def _scrub_retired_commands(text):
    """Replace any retired slash-command reference (anything but /cancel and /qr*)
    with a pointer to the menu, so a user can never see a command they can't use."""
    if not text or "/" not in text:
        return text
    return _RETIRED_CMD_RE.sub(lambda m: m.group(1) + "the menu below", text)


def get_response(key, **kw):
    """Returns the live (admin-editable) response text for a key, formatted with kw.
    Falls back to the registry default if the DB has no override. Retired commands
    are scrubbed from the template (before formatting, so user-supplied values are
    never altered)."""
    cache = _load_response_cache()
    text = cache.get(key)
    if text is None:
        meta = _RESPONSE_INDEX.get(key)
        text = meta["default"] if meta else ""
    text = _scrub_retired_commands(text)
    if kw:
        text = _safe_format(text, kw)
    return text


def get_all_responses():
    """Returns the full catalogue grouped by command, with current text + default."""
    cache = _load_response_cache()
    groups = []
    by_cmd = {}
    for e in RESPONSE_DEFAULTS:
        cmd = e["command"]
        if cmd not in by_cmd:
            by_cmd[cmd] = {"command": cmd, "items": []}
            groups.append(by_cmd[cmd])
        cur_text = cache.get(e["key"], e["default"])
        by_cmd[cmd]["items"].append({
            "key": e["key"], "label": e["label"], "trigger": e["trigger"],
            "state": e["state"], "placeholders": e["placeholders"],
            "text": cur_text, "default": e["default"],
            "modified": cur_text != e["default"],
            "new": e["key"] in MENU_RESPONSE_KEYS,  # drives the Old/New switch
        })
    return groups


def update_response(key, template):
    if key not in _RESPONSE_INDEX:
        return False
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO command_response (key, template, updated_at)
           VALUES (%s, %s, CURRENT_TIMESTAMP)
           ON CONFLICT (key) DO UPDATE SET template = EXCLUDED.template, updated_at = CURRENT_TIMESTAMP""",
        (key, template)
    )
    conn.commit()
    cur.close()
    release_connection(conn)
    global _RESPONSE_CACHE
    if _RESPONSE_CACHE is not None:
        _RESPONSE_CACHE[key] = template
    _p2p_trace("Response Edited", {"key": key})
    return True


def reset_response(key):
    meta = _RESPONSE_INDEX.get(key)
    if not meta:
        return False
    return update_response(key, meta["default"])


# ---------------------------------------------------------------------------
# Security logging — SSH events + web login attempts
# ---------------------------------------------------------------------------

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
    # actually sent back (textual responses only; size-capped — see log_http_request).
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_body TEXT")
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS content_type TEXT")
    cur.execute("ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_size INTEGER")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_ts   ON http_access_log(ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_ip   ON http_access_log(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hal_path ON http_access_log(path)")
    conn.commit()
    cur.close()
    release_connection(conn)


# ---------------------------------------------------------------------------
# Web App (Mini App) action log — the "Bot Webview Conversation"
# ---------------------------------------------------------------------------
# Every meaningful thing a person does inside the web app (open, navigate, view an
# ad, place/pay/release/cancel an order, deposit, withdraw, hit the verify/create
# gate, …) is POSTed back from the browser and recorded here, keyed by the
# authenticated Telegram id. Both real account holders AND guests (people who open
# the app from Telegram but have no account yet) are captured, so the dashboard can
# replay exactly what each visitor did in the app.
def ensure_webview_log_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS webview_logs (
            id BIGSERIAL PRIMARY KEY,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            tid TEXT NOT NULL,
            name TEXT DEFAULT '',
            username TEXT DEFAULT '',
            registered BOOLEAN NOT NULL DEFAULT FALSE,
            verified BOOLEAN NOT NULL DEFAULT FALSE,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            user_agent TEXT DEFAULT '',
            platform TEXT DEFAULT ''
        )
    """)
    # Idempotent column adds so an already-created table picks up the detail fields.
    cur.execute("ALTER TABLE IF EXISTS webview_logs ADD COLUMN IF NOT EXISTS ip TEXT DEFAULT ''")
    cur.execute("ALTER TABLE IF EXISTS webview_logs ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT ''")
    cur.execute("ALTER TABLE IF EXISTS webview_logs ADD COLUMN IF NOT EXISTS platform TEXT DEFAULT ''")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wvl_tid ON webview_logs(tid)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wvl_ts  ON webview_logs(ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_wvl_ip  ON webview_logs(ip)")
    conn.commit()
    cur.close()
    release_connection(conn)


_WVL_DETAIL_CAP = 4000   # max chars of free-form detail stored per action

def log_webview_action(tid, name, username, registered, verified, action,
                       detail="", ip="", user_agent="", platform=""):
    """Record one web-app action. Best-effort — never raises into the request path."""
    if detail and len(detail) > _WVL_DETAIL_CAP:
        detail = detail[:_WVL_DETAIL_CAP] + " …[truncated]"
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO webview_logs
                   (tid, name, username, registered, verified, action, detail, ip, user_agent, platform)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (str(tid), (name or "")[:120], (username or "")[:120],
             bool(registered), bool(verified), str(action)[:200], detail or "",
             (ip or "")[:64], (user_agent or "")[:400], (platform or "")[:64])
        )
        conn.commit()
    except Exception as e:
        # Roll back so a failed insert never returns a poisoned (aborted-txn)
        # connection to the pool, which would break the next query on it.
        try:
            conn.rollback()
        except Exception:
            pass
        logging.warning(f"log_webview_action failed: {e}")
    cur.close()
    release_connection(conn)


def get_webview_users(search: str = ""):
    """One row per tid that has any web-app activity: latest known name/username,
    how many actions we have, the most recent action + its time, and whether they
    were ever a registered user (vs. a guest). Most-recent-activity first.
    Optional case-insensitive `search` over tid / name / username."""
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        params = []
        where = ""
        if search:
            where = "WHERE tid ILIKE %s OR name ILIKE %s OR username ILIKE %s"
            like = f"%{search}%"
            params = [like, like, like]
        cur.execute(
            f"""SELECT w.tid,
                       (SELECT name     FROM webview_logs WHERE tid = w.tid AND name     <> '' ORDER BY id DESC LIMIT 1) AS name,
                       (SELECT username FROM webview_logs WHERE tid = w.tid AND username <> '' ORDER BY id DESC LIMIT 1) AS username,
                       COUNT(*)              AS actions,
                       MAX(w.id)             AS last_id,
                       (SELECT action FROM webview_logs WHERE tid = w.tid ORDER BY id DESC LIMIT 1) AS last_action,
                       (SELECT ip     FROM webview_logs WHERE tid = w.tid AND ip <> '' ORDER BY id DESC LIMIT 1) AS last_ip,
                       MAX(w.ts)             AS last_ts,
                       BOOL_OR(w.registered) AS ever_registered
                FROM webview_logs w
                {where}
                GROUP BY w.tid
                ORDER BY last_id DESC""",
            params
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_webview_users failed: {e}")
    cur.close()
    release_connection(conn)
    return rows


def get_webview_conversation(tid):
    """Full web-app action log for one tid, oldest first (SERIAL id is the
    chronological key alongside the ts)."""
    conn = get_connection()
    cur = conn.cursor()
    rows = []
    try:
        cur.execute(
            """SELECT id, ts, tid, name, username, registered, verified, action, detail,
                      ip, user_agent, platform
               FROM webview_logs WHERE tid = %s ORDER BY id ASC""",
            (str(tid),)
        )
        rows = _rows_to_dicts(cur)
    except Exception as e:
        logging.warning(f"get_webview_conversation failed: {e}")
    cur.close()
    release_connection(conn)
    return rows


_HAL_BODY_CAP = 200_000   # max chars of response body stored per request

def log_http_request(ip: str, method: str, path: str, query: str,
                     status_code: int, duration_ms: int,
                     user_agent: str, referer: str, authed_user: str,
                     response_body: str = None, content_type: str = None,
                     response_size: int = None):
    body = response_body
    if body is not None and len(body) > _HAL_BODY_CAP:
        body = body[:_HAL_BODY_CAP] + f"\n\n… [truncated — {response_size or len(response_body)} bytes total]"
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


# --- Device-fingerprint block list (web admin login) ---
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


# --- SSH event persistence ---
# journald is volatile (it rotates and is wiped on some hosts), so the live
# parser alone loses history. We persist every parsed event into ssh_log keyed
# by a content hash, then the dashboard can union live + stored events.
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


# --- Totals + manual log clearing (no auto-deletion) ---
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
    """Manually wipe one security-log section. Explicit operator action only —
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


# ===========================================================================
# Database-section gate: a SECOND factor in front of the raw DB browser.
# Separate password + Telegram 2FA, its own short-lived session, and an
# IP-only ban (no device fingerprint) after repeated failures.
# ===========================================================================
import datetime as _dt
import secrets as _secrets

_GATE_MAX_FAILS   = 5          # failed code entries before the IP is banned
_GATE_BAN_HOURS   = 24         # how long a banned IP stays out
_GATE_CODE_TTL    = 300        # 2FA code lifetime, seconds (5 min)
_GATE_MAX_CODES   = 5          # max code requests/resends per IP per window
_GATE_CODE_WINDOW = 900        # resend-count window, seconds (15 min)


def ensure_db_gate_tables():
    conn = get_connection()
    cur = conn.cursor()
    # single-row config (id is always 1)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS db_gate_config (
            id INTEGER PRIMARY KEY DEFAULT 1,
            password_hash TEXT NOT NULL,
            telegram_id TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT db_gate_config_singleton CHECK (id = 1)
        )
    """)
    # 2FA codes — table literally named "2fa" (quoted everywhere it's used).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS "2fa" (
            id SERIAL PRIMARY KEY,
            code TEXT NOT NULL,
            telegram_id TEXT,
            ip TEXT,
            purpose VARCHAR(32) NOT NULL DEFAULT 'db_gate',
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN NOT NULL DEFAULT FALSE
        )
    """)
    cur.execute('CREATE INDEX IF NOT EXISTS idx_2fa_lookup ON "2fa"(purpose, used, expires_at)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_2fa_ip ON "2fa"(ip, created_at)')
    # IP-only ban list for the gate (deliberately NOT fingerprint-based)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS db_gate_block (
            ip TEXT PRIMARY KEY,
            fail_count INTEGER NOT NULL DEFAULT 0,
            first_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_fail TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_until TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    release_connection(conn)


def is_db_gate_configured() -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM db_gate_config WHERE id = 1")
    out = cur.fetchone() is not None
    cur.close()
    release_connection(conn)
    return out


def get_db_gate_telegram_id() -> str:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT telegram_id FROM db_gate_config WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    return row[0] if row else ""


def set_db_gate_config(password: str, telegram_id: str):
    """Create or replace the gate password + 2FA Telegram id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO db_gate_config (id, password_hash, telegram_id)
        VALUES (1, %s, %s)
        ON CONFLICT (id) DO UPDATE
          SET password_hash = EXCLUDED.password_hash,
              telegram_id   = EXCLUDED.telegram_id,
              updated_at    = CURRENT_TIMESTAMP
    """, (_hash_pw(password), str(telegram_id).strip()))
    conn.commit()
    cur.close()
    release_connection(conn)


def verify_db_gate_password(password: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM db_gate_config WHERE id = 1")
    row = cur.fetchone()
    cur.close()
    release_connection(conn)
    return bool(row) and row[0] == _hash_pw(password)


def update_db_gate_config(new_password: str = None, new_telegram_id: str = None) -> bool:
    """Change the gate password and/or 2FA Telegram id in place — only the fields
    actually supplied are touched. Returns False if the gate row doesn't exist
    (not yet configured) or nothing was supplied. Callers MUST have already
    verified the current password + an unlocked gate session."""
    sets, params = [], []
    if new_password:
        sets.append("password_hash = %s")
        params.append(_hash_pw(new_password))
    if new_telegram_id is not None and str(new_telegram_id).strip():
        sets.append("telegram_id = %s")
        params.append(str(new_telegram_id).strip())
    if not sets:
        return False
    sets.append("updated_at = CURRENT_TIMESTAMP")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"UPDATE db_gate_config SET {', '.join(sets)} WHERE id = 1", params)
    updated = cur.rowcount
    conn.commit()
    cur.close()
    release_connection(conn)
    return updated > 0


def db_gate_check_allowed(ip: str):
    """(allowed, fail_count, blocked_until) — IP-based only."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT fail_count, blocked_until FROM db_gate_block WHERE ip = %s", (ip,))
        row = cur.fetchone()
        if not row:
            return True, 0, None
        fail_count, blocked_until = row
        if blocked_until is not None:
            if _dt.datetime.utcnow() < blocked_until:
                return False, fail_count, blocked_until
            cur.execute("DELETE FROM db_gate_block WHERE ip = %s", (ip,))
            conn.commit()
            return True, 0, None
        return True, fail_count, None
    finally:
        cur.close()
        release_connection(conn)


def create_2fa_code(ip: str, purpose: str = "db_gate"):
    """Generate a fresh 6-digit code, invalidate prior unused ones, store it.
    Returns (code, telegram_id, error). error is set when the resend cap is hit
    or the gate isn't configured."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT telegram_id FROM db_gate_config WHERE id = 1")
        cfg = cur.fetchone()
        if not cfg:
            return None, None, "not_configured"
        telegram_id = cfg[0]
        # resend throttle: max N codes per IP per window
        cur.execute(
            'SELECT COUNT(*) FROM "2fa" WHERE ip = %s AND purpose = %s '
            "AND created_at > CURRENT_TIMESTAMP - %s * INTERVAL '1 second'",
            (ip, purpose, _GATE_CODE_WINDOW))
        if cur.fetchone()[0] >= _GATE_MAX_CODES:
            return None, telegram_id, "too_many_codes"
        # one live code at a time: retire previous unused codes for this purpose
        cur.execute('UPDATE "2fa" SET used = TRUE WHERE purpose = %s AND used = FALSE', (purpose,))
        code = f"{_secrets.randbelow(1000000):06d}"
        cur.execute(
            'INSERT INTO "2fa" (code, telegram_id, ip, purpose, expires_at) '
            "VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP + %s * INTERVAL '1 second')",
            (code, telegram_id, ip, purpose, _GATE_CODE_TTL))
        conn.commit()
        return code, telegram_id, None
    finally:
        cur.close()
        release_connection(conn)


def verify_2fa_code(code: str, purpose: str = "db_gate") -> bool:
    """True if a matching, unused, unexpired code exists; consumes it on match."""
    code = (code or "").strip()
    if not code:
        return False
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            'SELECT id FROM "2fa" WHERE purpose = %s AND used = FALSE '
            "AND expires_at > CURRENT_TIMESTAMP AND code = %s "
            "ORDER BY id DESC LIMIT 1", (purpose, code))
        row = cur.fetchone()
        if not row:
            return False
        cur.execute('UPDATE "2fa" SET used = TRUE WHERE id = %s', (row[0],))
        conn.commit()
        return True
    finally:
        cur.close()
        release_connection(conn)


def db_gate_record_fail(ip: str):
    """Count a failed code entry; ban the IP once it reaches the limit.
    Returns (banned: bool, fail_count: int, blocked_until)."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO db_gate_block (ip, fail_count, first_fail, last_fail)
            VALUES (%s, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (ip) DO UPDATE
              SET fail_count = db_gate_block.fail_count + 1,
                  last_fail  = CURRENT_TIMESTAMP,
                  blocked_until = CASE
                      WHEN db_gate_block.fail_count + 1 >= %s
                      THEN CURRENT_TIMESTAMP + %s * INTERVAL '1 hour'
                      ELSE db_gate_block.blocked_until END
            RETURNING fail_count, blocked_until
        """, (ip, _GATE_MAX_FAILS, _GATE_BAN_HOURS))
        fail_count, blocked_until = cur.fetchone()
        conn.commit()
        banned = blocked_until is not None and _dt.datetime.utcnow() < blocked_until
        return banned, fail_count, blocked_until
    finally:
        cur.close()
        release_connection(conn)


def db_gate_reset(ip: str):
    """Clear the fail/ban record for an IP after a successful unlock."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM db_gate_block WHERE ip = %s", (ip,))
    conn.commit()
    cur.close()
    release_connection(conn)
