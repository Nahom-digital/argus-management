#!/usr/bin/env python3
# Management.py, standalone Server Management panel (systemd service: management).
#
# A self-contained FastAPI control panel that runs ALONGSIDE (and independently of)
# Main.py, reusing the existing infrastructure of the MainApp box:
#
#   * System.py   -> live server telemetry, PTY terminal, process/connection views
#   * DB.py       -> the elink Postgres pool + credentials (.env) and the shared
#                    `admin` table, so login uses the SAME username/password as Main.py
#   * .session_secret -> the SAME HMAC key, so the session cookie format is identical
#   * vendor/fonts + vendor/xterm + the Main.py CSS design system (static_mgmt/) so
#                    the Server / Terminal / Logs UI looks & behaves exactly like Main.py
#
# It adds: a structured `management_log` table, systemd service control, and a Logs
# view that captures SSH activity AND every action/data movement done by any user
# (logins, service control, terminal commands, security actions, HTTP access).
#
# Separate Desktop and Mobile shells are served (own chrome each) over one shared
# component set + JS, so the mobile experience mirrors the desktop one.
#
# Security model mirrors Main.py: public edge listener behind Cloudflare, a
# Cloudflare-only ingress gate, signed session-cookie gating on every route.
# NOTHING related to WELINKP2P / the trading bot is referenced here.

import os
import re
import datetime
import time
import json
import html
import hmac
import base64
import hashlib
import secrets
import asyncio
import logging
import subprocess
import tempfile
import ipaddress
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

import DB
import System
import recovery
import panel_users
import ssh_vault
import vault
import cloudflare_tunnel
import firewall
import mail
import mailcow
import identity
import telegram_bot
import branding
import provision
import web_guard
import nginx_proxy
from psycopg2 import sql as pg_sql

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_PROJECT_DIR, "static_mgmt")

# Public path this panel is published under. MainApp owns the domain root
# (webview, webhook, bot admin), so nginx routes only <MGMT_BASE>/… here and
# strips the prefix before proxying, the routes below stay mounted at "/".
# Everything the browser is *told* to fetch (assets, API calls, redirects,
# websocket) must carry the prefix back, which is what this constant is for.
# Set MGMT_BASE="" to serve at the domain root again (must match nginx).
MGMT_BASE = os.environ.get("MGMT_BASE", "/management").rstrip("/")
_COOKIE_PATH = MGMT_BASE + "/"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [management] %(levelname)s %(message)s")

# What host/port uvicorn actually bound (filled in __main__), so the Config tab
# can show "currently serving on …" and flag a pending restart.
SERVER_RUNTIME = {"host": None, "port": None}

# ---------------------------------------------------------------------------
# Session token, the same scheme Main.py uses, signed with the SAME secret.
# ---------------------------------------------------------------------------
def _load_jwt_secret() -> str:
    path = os.path.join(_PROJECT_DIR, ".session_secret")
    if os.path.exists(path):
        with open(path) as f:
            s = f.read().strip()
        if s:
            return s
    s = os.urandom(32).hex()
    with open(path, "w") as f:
        f.write(s)
    return s

_JWT_SECRET = _load_jwt_secret()

# --- session invalidation epoch --------------------------------------------- #
# Sessions are stateless signed tokens, so there is no server-side record to
# delete when a password changes. Instead every token records the auth epoch it
# was minted under; bumping the stored epoch retires every token in circulation
# at once. That is what makes "reset the password" actually evict an intruder.
_EPOCH_CACHE = {"value": None, "read_at": 0.0}
_EPOCH_TTL = 15.0          # seconds; bounds the per-request settings lookup

def _auth_epoch() -> int:
    now = time.time()
    if _EPOCH_CACHE["value"] is None or now - _EPOCH_CACHE["read_at"] > _EPOCH_TTL:
        try:
            _EPOCH_CACHE["value"] = int(DB.get_setting("auth_epoch", "0") or 0)
        except Exception:
            # A database blip must not sign everybody out mid-session.
            if _EPOCH_CACHE["value"] is None:
                _EPOCH_CACHE["value"] = 0
        _EPOCH_CACHE["read_at"] = now
    return _EPOCH_CACHE["value"]

def _bump_auth_epoch() -> int:
    nxt = _auth_epoch() + 1
    DB.set_setting("auth_epoch", nxt)
    _EPOCH_CACHE["value"], _EPOCH_CACHE["read_at"] = nxt, time.time()
    return nxt

# The epoch above is global: bumping it signs out everybody, which is right for
# the admin changing their own password and wrong for the admin resetting one
# staff member's. So each staff row carries its own epoch too, and a token is
# valid only while both still match. Cached briefly because it is read on every
# single request; _forget_user_epoch() makes a reset take effect immediately
# for the path that performed it.
_USER_EPOCH_CACHE = {}
_USER_EPOCH_TTL = 10.0

def _user_epoch(username: str) -> int:
    if not username:
        return 0
    now = time.time()
    hit = _USER_EPOCH_CACHE.get(username)
    if hit and now - hit[1] <= _USER_EPOCH_TTL:
        return hit[0]
    try:
        conn = DB.get_connection()
        try:
            value = panel_users.auth_epoch_for(conn, username)
        finally:
            DB.release_connection(conn)
    except Exception:
        # A database blip must not sign anybody out mid-session. Reuse the last
        # known value, and only fall back to 0 if we have never read one.
        return hit[0] if hit else 0
    _USER_EPOCH_CACHE[username] = (value, now)
    return value

def _forget_user_epoch(username: str) -> None:
    _USER_EPOCH_CACHE.pop(username, None)

# How long a signed session cookie is good for. Stated once so the cookie, the
# token claim and the row in the sessions log cannot disagree about when a
# session ends.
SESSION_TTL = 86400

def _create_session_token(username: str = "admin", sid: str = None) -> str:
    if sid is None:
        sid = secrets.token_hex(16)
    payload = json.dumps({"exp": int(time.time()) + SESSION_TTL,
                          "username": username, "sid": sid,
                          "ae": _auth_epoch(), "ue": _user_epoch(username)}).encode()
    sig = hmac.new(_JWT_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(payload).decode() + "." + sig

def _get_token_data(token: str):
    try:
        b64, sig = token.split(".", 1)
        b64 += "=" * (-len(b64) % 4)
        payload = base64.urlsafe_b64decode(b64)
        expected = hmac.new(_JWT_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(payload)
        if data.get("exp", 0) <= int(time.time()):
            return None
        # Tokens minted before the current epoch were revoked by a password change.
        if int(data.get("ae", 0)) != _auth_epoch():
            return None
        # And tokens minted before this identity's own epoch were revoked by an
        # admin resetting that one account, without disturbing anybody else.
        if int(data.get("ue", 0)) != _user_epoch(data.get("username", "")):
            return None
        return data
    except Exception:
        return None

def _authed(request: Request) -> bool:
    return _get_token_data(request.cookies.get("session", "")) is not None

def _admin_name(request: Request) -> str:
    data = _get_token_data(request.cookies.get("session", ""))
    return (data or {}).get("username", "") if data else ""

# ---------------------------------------------------------------------------
# Cloudflare-only ingress gate (mirrors Main.py).  Source: cloudflare.com/ips/
# ---------------------------------------------------------------------------
_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)
_CLOUDFLARE_NETS = tuple(ipaddress.ip_network(c) for c in _CLOUDFLARE_CIDRS)
_LOCAL_NETS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
_CF_GATE_ON = True

def _is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CLOUDFLARE_NETS)

def _is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _LOCAL_NETS)

def _ingress_allowed(ip: str) -> bool:
    if not _CF_GATE_ON:
        return True
    return _is_local_ip(ip) or _is_cloudflare_ip(ip)

def _hop_ip(request: Request) -> str:
    """Who connected to our edge, as the ingress gate has to judge it.

    nginx fronts this panel on loopback, so the socket peer is 127.0.0.1 and the
    peer nginx itself saw is in X-Real-IP, trustworthy only because it arrived
    over loopback. This is the value the Cloudflare gate rules on, so nothing
    softer than X-Real-IP belongs here. X-Forwarded-For in particular is a list
    any caller may prepend to, and honouring it here would let a stranger name
    their own hop and talk their way past the gate.
    """
    peer = request.client.host if request.client else ""
    if _is_local_ip(peer):
        real = request.headers.get("x-real-ip", "").strip()
        if real:
            return real
    return peer

def _client_ip(request: Request) -> str:
    """The visitor, for logging and for login blocking.

    Behind Cloudflare the hop is an edge address and the visitor is named in
    CF-Connecting-IP. Behind a plain proxy the hop is already the visitor.
    X-Forwarded-For is the last resort and is read only from a local hop,
    because getting this wrong is no longer cosmetic: with login blocking wired
    up, a deployment whose proxy sends nothing else would file every visitor
    under 127.0.0.1 and let one stranger's five failures lock everybody out.
    Only the leftmost entry is taken.
    """
    hop = _hop_ip(request)
    if _is_cloudflare_ip(hop):
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return cf
    if _is_local_ip(hop):
        first = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if first:
            return first
    return hop

def _client_ip_ws(websocket: WebSocket) -> str:
    try:
        peer = websocket.client.host if websocket.client else "?"
        if _is_local_ip(peer):
            real = (websocket.headers.get("cf-connecting-ip", "")
                    or websocket.headers.get("x-real-ip", "")).strip()
            if real:
                return real
        return peer
    except Exception:
        return "?"

def _is_https(request: Request) -> bool:
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"

class _CloudflareOnly(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not _ingress_allowed(_hop_ip(request)):
            return Response(status_code=403)
        return await call_next(request)

class _BasePathStrip:
    """Accept <MGMT_BASE>/… as well as /… .

    Every route below is registered at a bare path because nginx strips the
    public prefix before proxying. Reached directly, no proxy, or a proxy that
    forwards the prefix intact, the browser asks for "<MGMT_BASE>/login" and
    "<MGMT_BASE>/static/dash.css", which 404 and leave the page unstyled. Taking
    a leading MGMT_BASE off the path here makes both shapes route identically,
    so the panel is no longer dependent on someone else rewriting URLs for it.

    Plain ASGI rather than BaseHTTPMiddleware so the terminal's websocket
    handshake gets the same treatment as HTTP requests.
    """

    def __init__(self, app, base=""):
        self.app = app
        self.base = (base or "").rstrip("/")

    async def __call__(self, scope, receive, send):
        if self.base and scope.get("type") in ("http", "websocket"):
            path = scope.get("path", "")
            if path == self.base or path.startswith(self.base + "/"):
                scope = dict(scope)
                scope["path"] = path[len(self.base):] or "/"
                raw = scope.get("raw_path")
                if raw:
                    # raw_path carries the query string in some servers; only
                    # the prefix comes off, the rest is left untouched.
                    prefix = self.base.encode()
                    if raw.startswith(prefix):
                        scope["raw_path"] = raw[len(prefix):] or b"/"
        await self.app(scope, receive, send)

# Paths that would drown the access log without telling anyone anything: the
# stylesheet, the fonts, the terminal bundle. A request for a font is not an
# event worth a row, and one page load makes a dozen of them.
_ACCESS_LOG_SKIP = ("/static/", "/assets/", "/favicon")

def _record_access(ip, method, path, query, status, duration_ms, ua, referer, user):
    """One row in the access log.

    The response body is deliberately not captured. Storing it would put every
    answer this panel ever gave, including admin-only ones, in a table any
    account with the Logs grant can read, and would grow without bound. The
    entry viewer already says "no response body captured" when there is none.
    """
    try:
        DB.log_http_request(ip, method, path, query, status, duration_ms,
                            ua[:400], (referer or "")[:400], user or None)
    except Exception as e:
        logging.warning(f"access log write failed: {e}")

class _AccessLog(BaseHTTPMiddleware):
    """Records every request that got past the ingress gate.

    The table and its reader already existed; nothing ever wrote to it, so the
    Access Log section of the Logs tab had been permanently empty. Logging must
    never change the outcome of a request, so every failure here is swallowed.
    """
    async def dispatch(self, request, call_next):
        started = time.monotonic()
        response = await call_next(request)
        path = request.url.path
        if any(path.startswith(skip) for skip in _ACCESS_LOG_SKIP):
            return response
        duration = int((time.monotonic() - started) * 1000)
        try:
            user = _admin_name(request) if _authed(request) else ""
        except Exception:
            user = ""
        asyncio.create_task(DB.run(
            _record_access, _client_ip(request), request.method, path,
            request.url.query, response.status_code, duration,
            request.headers.get("user-agent", ""),
            request.headers.get("referer", ""), user))
        return response

class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        h["X-Frame-Options"] = "DENY"
        # A route that already set its own policy wanted a stricter one than the
        # page policy below, and this used to overwrite it. Uploaded pictures are
        # served with default-src 'none', which the app policy would have widened
        # back to script-src 'self' 'unsafe-inline' on the way out.
        if "content-security-policy" not in h:
            h["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self'; connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
            )
        if _is_https(request):
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

# ---------------------------------------------------------------------------
# management_log, structured event/audit table owned by this panel.
# ---------------------------------------------------------------------------
LOG_LEVELS = ("INFO", "WARN", "ERROR", "ACTION")
LOG_CATEGORIES = ("AUTH", "SERVICE", "TERMINAL", "SYSTEM", "SECURITY")

def ensure_management_log():
    conn = DB.get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS management_log (
            id        BIGSERIAL PRIMARY KEY,
            ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
            level     VARCHAR(10)  NOT NULL DEFAULT 'INFO',
            category  VARCHAR(32)  NOT NULL DEFAULT 'SYSTEM',
            actor     VARCHAR(100) NOT NULL DEFAULT '',
            ip        VARCHAR(64)  NOT NULL DEFAULT '',
            action    VARCHAR(200) NOT NULL DEFAULT '',
            target    VARCHAR(200) NOT NULL DEFAULT '',
            detail    TEXT         NOT NULL DEFAULT '',
            status    VARCHAR(20)  NOT NULL DEFAULT 'ok'
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_mgmt_log_ts ON management_log (ts DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_mgmt_log_cat ON management_log (category)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_mgmt_log_level ON management_log (level)")
    conn.commit()
    cur.close()
    DB.release_connection(conn)

def write_log(level, category, action, actor="", ip="", target="", detail="", status="ok"):
    try:
        conn = DB.get_connection()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO management_log (level, category, actor, ip, action, target, detail, status)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (str(level)[:10], str(category)[:32], str(actor)[:100], str(ip)[:64],
             str(action)[:200], str(target)[:200], str(detail)[:8000], str(status)[:20]))
        conn.commit()
        cur.close()
        DB.release_connection(conn)
    except Exception as e:
        logging.warning(f"management_log write failed: {e}")

def query_logs(level="", category="", q="", limit=200):
    conn = DB.get_connection()
    cur = conn.cursor()
    where, params = [], []
    if level and level.upper() in LOG_LEVELS:
        where.append("level = %s"); params.append(level.upper())
    if category and category.upper() in LOG_CATEGORIES:
        where.append("category = %s"); params.append(category.upper())
    if q:
        where.append("(action ILIKE %s OR detail ILIKE %s OR target ILIKE %s OR actor ILIKE %s)")
        like = f"%{q}%"; params += [like, like, like, like]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    limit = max(1, min(int(limit or 200), 1000))
    cur.execute(
        f"""SELECT id, ts, level, category, actor, ip, action, target, detail, status
            FROM management_log {clause} ORDER BY ts DESC, id DESC LIMIT {limit}""", params)
    rows = cur.fetchall()
    cur.close()
    DB.release_connection(conn)
    return [{
        "id": r[0], "ts": r[1].strftime("%Y-%m-%d %H:%M:%S") if r[1] else "",
        "level": r[2], "category": r[3], "actor": r[4], "ip": r[5],
        "action": r[6], "target": r[7], "detail": r[8], "status": r[9],
    } for r in rows]

def log_counts():
    conn = DB.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT level, COUNT(*) FROM management_log GROUP BY level")
    by_level = {lvl: 0 for lvl in LOG_LEVELS}
    for lvl, n in cur.fetchall():
        by_level[lvl] = n
    cur.execute("SELECT COUNT(*) FROM management_log")
    total = cur.fetchone()[0]
    cur.close()
    DB.release_connection(conn)
    return {"total": total, "by_level": by_level}

# ---------------------------------------------------------------------------
# systemd service control.
# ---------------------------------------------------------------------------
_SVC_NAME_RE = re.compile(r"^[A-Za-z0-9@._\-]+$")
_SVC_ACTIONS = {"start", "stop", "restart", "enable", "disable"}

def _norm_service(name: str) -> str:
    name = (name or "").strip()
    if not _SVC_NAME_RE.fullmatch(name):
        return ""
    if not name.endswith(".service"):
        name += ".service"
    return name

def list_services():
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all",
             "--no-legend", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=20)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "services": []}
    services = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
        desc = parts[4] if len(parts) > 4 else ""
        services.append({
            "name": unit, "short": unit[:-8] if unit.endswith(".service") else unit,
            "load": load, "active": active, "sub": sub, "description": desc,
        })
    services.sort(key=lambda s: (s["active"] != "active", s["name"].lower()))
    return {"services": services}

def service_detail(name: str):
    unit = _norm_service(name)
    if not unit:
        return {"error": "invalid service name"}
    def _run(args):
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=15).stdout.strip()
        except Exception:
            return ""
    try:
        status = subprocess.run(["systemctl", "status", unit, "--no-pager", "-n", "40"],
                                capture_output=True, text=True, timeout=15).stdout
    except Exception as e:
        status = f"{type(e).__name__}: {e}"
    return {"name": unit, "active": _run(["systemctl", "is-active", unit]),
            "enabled": _run(["systemctl", "is-enabled", unit]), "status": status}

def control_service(name: str, action: str):
    unit = _norm_service(name)
    if not unit:
        return False, "invalid service name"
    if action not in _SVC_ACTIONS:
        return False, "invalid action"
    try:
        proc = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return True, (proc.stdout or proc.stderr or "ok").strip()
        return False, (proc.stderr or proc.stdout or "failed").strip()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

# ---------------------------------------------------------------------------
# SSH journald parser (ported from Main.py). Persists to the shared ssh_log
# table so history survives journald rotation; merges stored + live events.
# ---------------------------------------------------------------------------
_ACCEPTED_RE   = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
_FAILED_RE     = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
_INVALID_RE    = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
_DISCONNECT_RE = re.compile(r"Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
_CLOSED_RE     = re.compile(r"Connection closed by (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>[\d.a-fA-F:]+) port (?P<port>\d+)")
_SESSION_RE    = re.compile(r"session (?P<state>opened|closed) for user (?P<user>\S+)")
_FINGERPRINT_RE = re.compile(r"(?P<ip>[\d.a-fA-F:]+).*?key (?P<type>[\w-]+) (?P<fp>SHA256:\S+)")
_TIMEOUT_RE    = re.compile(r"Timeout before authentication.*?from (?P<ip>[\d.a-fA-F:]+)")

def _autoblock_ssh_offenders():
    """Block addresses that have failed SSH too many times, right after fresh
    events land. Runs on the log-reading path rather than on a timer, so it has
    no background loop to keep alive, and it never raises: failing to block is
    not a reason to fail the log view the operator is looking at."""
    try:
        conn = DB.get_connection()
        try:
            newly = firewall.enforce_ssh_autoblock(conn)
        finally:
            DB.release_connection(conn)
        for entry in newly:
            write_log(
                "WARN", "SECURITY", "Auto-blocked SSH attacker", actor="system",
                target=entry["ip"],
                detail=(f"{entry['failures']} failed attempts within "
                        f"{firewall.SSH_FAIL_WINDOW_MINUTES} minutes; "
                        f"firewall: {entry['detail'] or 'applied'}"),
                status="ok" if entry["applied"] else "failed",
            )
    except Exception as e:
        logging.error(f"SSH auto-block failed: {e}")


def _parse_ssh_journal(since: str = None, limit: int = 500) -> dict:
    cmd = ["journalctl", "-u", "ssh", "--no-pager", "-o", "short-iso", "--reverse"]
    if since:
        cmd += ["--since", since]
    cmd += ["-n", str(min(limit * 4, 4000))]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode(errors="replace")
    except Exception:
        out = ""
    events, sessions_current = [], {}
    for line in out.splitlines():
        parts = line.split(" ", 3)
        if len(parts) < 4:
            continue
        ts_raw, _host, proc_msg = parts[0], parts[1], parts[3]
        pid_m = re.search(r"\[(\d+)\]", parts[2])
        pid = int(pid_m.group(1)) if pid_m else None
        msg = proc_msg
        ev = {"ts": ts_raw, "pid": pid, "ip": None, "user": None,
              "port": None, "event": None, "method": None, "fingerprint": None}
        m = _ACCEPTED_RE.search(msg)
        if m:
            ev.update(event="ACCEPTED", ip=m.group("ip"), user=m.group("user"),
                      port=int(m.group("port")), method=m.group("method")); events.append(ev); continue
        m = _FAILED_RE.search(msg)
        if m:
            ev.update(event="FAILED", ip=m.group("ip"), user=m.group("user"),
                      port=int(m.group("port")), method=m.group("method")); events.append(ev); continue
        m = _INVALID_RE.search(msg)
        if m:
            ev.update(event="INVALID_USER", ip=m.group("ip"), user=m.group("user"),
                      port=int(m.group("port"))); events.append(ev); continue
        m = _FINGERPRINT_RE.search(msg)
        if m:
            ev.update(event="FINGERPRINT", ip=m.group("ip"),
                      fingerprint=f"{m.group('type')} {m.group('fp')}"); events.append(ev); continue
        m = _SESSION_RE.search(msg)
        if m:
            state = m.group("state")
            ev.update(event="SESSION_" + state.upper(), user=m.group("user"))
            if state == "opened" and pid:
                sessions_current[pid] = ev
            elif state == "closed" and pid:
                sessions_current.pop(pid, None)
            events.append(ev); continue
        m = _DISCONNECT_RE.search(msg) or _CLOSED_RE.search(msg)
        if m:
            ev.update(event="DISCONNECTED", ip=m.group("ip"), user=m.group("user"),
                      port=int(m.group("port"))); events.append(ev); continue
        m = _TIMEOUT_RE.search(msg)
        if m:
            ev.update(event="TIMEOUT", ip=m.group("ip")); events.append(ev)
    try:
        DB.persist_ssh_events(events)
        _autoblock_ssh_offenders()
        stored = DB.get_persisted_ssh(limit=max(limit * 4, 4000))
        seen, merged = set(), []
        for e in events + stored:
            key = (e.get("ts"), e.get("event"), e.get("ip"), e.get("user"),
                   e.get("port"), e.get("fingerprint"), e.get("pid"))
            if key in seen:
                continue
            seen.add(key); merged.append(e)
        merged.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)
        events = merged
    except Exception as _e:
        logging.error(f"SSH persist/merge failed: {_e}")
    accepted = [e for e in events if e["event"] == "ACCEPTED"]
    failed = [e for e in events if e["event"] == "FAILED"]
    fingerprints = [e for e in events if e["event"] == "FINGERPRINT"]
    current = _get_current_ssh_sessions()
    ip_stats = {}
    for e in events:
        ip = e.get("ip")
        if not ip:
            continue
        s = ip_stats.setdefault(ip, {"ip": ip, "attempts": 0, "success": 0, "last_seen": e["ts"]})
        s["attempts"] += 1
        if e["event"] == "ACCEPTED":
            s["success"] += 1
        if e["ts"] > s["last_seen"]:
            s["last_seen"] = e["ts"]
    return {
        "events": events[:limit], "accepted": accepted, "failed": failed,
        "fingerprints": fingerprints, "current_sessions": current,
        "ip_stats": sorted(ip_stats.values(), key=lambda x: x["attempts"], reverse=True)[:30],
        "summary": {
            "total_events": len(events), "accepted_count": len(accepted),
            "failed_count": len(failed), "unique_ips": len(ip_stats),
            "attacker_ips": len([v for v in ip_stats.values() if v["success"] == 0]),
        },
    }

def _get_current_ssh_sessions() -> list:
    sessions = []
    try:
        out = subprocess.check_output(["ss", "-tnp"], stderr=subprocess.DEVNULL, timeout=5).decode(errors="replace")
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state, laddr, raddr = parts[0], parts[3], parts[4]
            if ":22" not in laddr or state != "ESTAB":
                continue
            proc_info = parts[5] if len(parts) > 5 else ""
            pid_m = re.search(r"pid=(\d+)", proc_info)
            proc_m = re.search(r'"([^"]+)"', proc_info)
            sessions.append({"local": laddr, "remote": raddr,
                             "pid": pid_m.group(1) if pid_m else None,
                             "process": proc_m.group(1) if proc_m else "sshd"})
    except Exception:
        pass
    return sessions

# ---------------------------------------------------------------------------
# Management bind config, kept in its OWN system_settings keys so it never
# clashes with Main.py's server_host/server_port.
# ---------------------------------------------------------------------------
def get_mgmt_config():
    host = DB.get_setting("management_host", "0.0.0.0") or "0.0.0.0"
    raw = DB.get_setting("management_port", "80")
    try:
        port = int(raw)
    except (TypeError, ValueError):
        port = 80
    return host, port

def mgmt_config_view():
    host, port = get_mgmt_config()
    return {"host": host, "port": port, "default_host": "0.0.0.0", "default_port": 80,
            "public_host": getattr(System, "PUBLIC_HOST", ""),
            "running_host": SERVER_RUNTIME["host"], "running_port": SERVER_RUNTIME["port"],
            "scheme": "http"}

def set_mgmt_config(host, port):
    host = (host or "").strip()
    if not host or not System._valid_host(host):
        raise ValueError(f"Invalid host: {host}")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number")
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    DB.set_setting("management_host", host)
    DB.set_setting("management_port", port)
    return host, port

# ===========================================================================
# Front-end, reuses Main.py's CSS design system + icon sprite from static_mgmt.
# ===========================================================================
def _read_static(name: str) -> str:
    try:
        with open(os.path.join(_STATIC_DIR, name), encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logging.error(f"static read {name} failed: {e}")
        return ""

_ICON_SPRITE = _read_static("sprite.html")

_NAV = [("server", "Server", "ic-server"), ("config", "Config", "ic-settings"),
        ("terminal", "Terminal", "ic-monitor"), ("mail", "Mail", "ic-mail"),
        ("logs", "Logs", "ic-shield-alert")]

def _visible_nav(perms: dict):
    """Which top-level tabs this identity gets. Config is always present,
    because every signed-in person has an account page to look at; what it
    contains is decided by _config_cards()."""
    out = []
    for k, label, ic in _NAV:
        if k == "terminal" and perms.get("terminal", "none") == "none":
            continue
        if k == "logs" and not perms.get("logs_access"):
            continue
        out.append((k, label, ic))
    return out

def _config_cards(perms: dict):
    """Which Config sub-pages this identity may open, in display order.

    One card per grant, which is the whole point: a staff member granted only
    Cloudflare tunnels opens Config and finds Cloudflare Tunnel, not somebody
    else's idea of where tunnels live. Proxy, Cloudflare and the firewall used to
    share the proxy page, so two of the three grants led to an empty Config.

    Staff always get their own account card. The admin gets everything.
    """
    if perms.get("role") == "admin":
        return ["users", "server", "service", "database", "proxy", "tunnel",
                "firewall", "telegram"]
    cards = ["account"]
    for grant, key in (("svc_status", "service"), ("db_read", "database"),
                       ("net_proxy", "proxy"), ("tunnel_manage", "tunnel"),
                       ("firewall_manage", "firewall"),
                       ("telegram_manage", "telegram")):
        if perms.get(grant):
            cards.append(key)
    return cards

_CONFIG_CARD_META = {
    "account":  ("My Account", "ic-users",
                 "Your username, what you are allowed to do, and your password."),
    "users":    ("User Management", "ic-users",
                 "Create staff accounts, edit what they may do, and reset their passwords."),
    "server":   ("Server Configuration", "ic-server",
                 "Where this panel listens, and SSH access to the box."),
    "service":  ("Service", "ic-sliders-horizontal",
                 "Start, stop and inspect systemd services."),
    "database": ("Database", "ic-database",
                 "Browse and edit the tables this panel uses."),
    "proxy":    ("Proxy", "ic-globe",
                 "Reverse proxy hosts served by nginx."),
    "tunnel":   ("Cloudflare Tunnel", "ic-cloud",
                 "Publish a name on the internet without opening a port."),
    "firewall": ("Firewall", "ic-shield-alert",
                 "Which ports this server accepts, and which addresses are blocked."),
    "telegram": ("Telegram Bot", "ic-send",
                 "Run this panel from a chat, and decide who is allowed to."),
}

_CONFIG_BACK = (
    '<button class="db-action-btn config-back" onclick="configBack()">'
    '<svg class="ic"><use href="#ic-chevron-left"/></svg>Back</button>'
)

def _config_sub_users():
    return f"""
  <div class="config-sub" data-cfgsub="users" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">User Management</div>
    <div class="cfg-card">
      <div class="device-title">Staff accounts</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">Accounts you create for people who should not have the full admin login.</div>
      <div id="user-list"><div class="empty-state">Loading&hellip;</div></div>
    </div>
    <div class="cfg-card cfg-card-wide" style="margin-top:18px;" id="nu-card">
      <div class="device-title" id="nu-card-title">Add a user</div>
      <div class="settings-subtitle" id="nu-card-sub" style="margin:6px 0 16px;">Every permission below is off until you grant it.</div>
      <div class="field-group" id="nu-username-group"><label class="field-label" for="nu-username">Username</label>
        <div class="field-hint">Letters, digits, dot, dash and underscore. It cannot be changed afterwards.</div>
        <input class="field-input" id="nu-username" type="text" autocomplete="off" spellcheck="false"></div>
      <div class="field-group"><label class="field-label" for="nu-password">Password</label>
        <div class="field-hint" id="nu-password-hint">At least 8 characters, and not only digits.</div>
        <input class="field-input" id="nu-password" type="password" autocomplete="new-password"></div>
      <div id="nu-grants" class="grant-form"><div class="empty-state">Loading permissions&hellip;</div></div>
      <div class="nu-actions">
        <button class="save-btn" id="nu-submit" onclick="submitPanelUser()">Create User</button>
        <button class="db-action-btn" id="nu-cancel" onclick="resetUserForm()" hidden>Cancel</button>
      </div>
      <div class="save-feedback" id="nu-feedback"></div>
    </div>
  </div>"""

def _config_sub_account(perms: dict):
    """What a staff member sees under Config: their own account, nothing else.
    The grant list is rendered read-only from the same registry the admin's
    form is built from, so the two can never describe different things."""
    return f"""
  <div class="config-sub" data-cfgsub="account" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">My Account</div>
    <div class="cfg-card">
      <div class="device-title">Who you are</div>
      <dl class="acct-facts">
        <dt>Username</dt><dd id="acct-username">{html.escape(perms.get("username") or "")}</dd>
        <dt>Role</dt><dd id="acct-role">Staff account</dd>
      </dl>
    </div>
    <div class="cfg-card cfg-card-wide" style="margin-top:18px;">
      <div class="device-title">What you are allowed to do</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">Only an admin can change these. Ask one in person if you need more.</div>
      <div id="acct-grants" class="grant-form grant-form-readonly"><div class="empty-state">Loading&hellip;</div></div>
    </div>
  </div>"""

def _config_sub_server():
    return f"""
  <div class="config-sub" data-cfgsub="server" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">Server Configuration</div>
    <div class="cfg-card">
      <div class="device-title">Management Launch Configuration</div>
      <div class="settings-subtitle" style="margin:6px 0 18px;">Host and port this panel binds (HTTP). Applies on next restart of the <code>management</code> service.</div>
      <div class="field-group"><label class="field-label" for="cfg-host">Host</label>
        <div class="field-hint">Use <code>0.0.0.0</code> for every interface.</div>
        <input class="field-input" id="cfg-host" type="text" placeholder="0.0.0.0" spellcheck="false" autocomplete="off">
        <div class="host-chips" id="host-chips"></div></div>
      <div class="field-group"><label class="field-label" for="cfg-port">Port</label>
        <div class="field-hint">Standard HTTP is <code>80</code>.</div>
        <input class="field-input" id="cfg-port" type="number" min="1" max="65535" placeholder="80" autocomplete="off"></div>
      <button class="save-btn" id="cfg-save-btn" onclick="saveServerConfig()">Save Configuration</button>
      <div class="save-feedback" id="cfg-feedback"></div>
      <div class="cfg-running" id="cfg-running"></div>
    </div>
    <div class="cfg-card" style="margin-top:18px;">
      <div class="device-title">SSH access</div>
      <div class="settings-subtitle" style="margin:6px 0 16px;">The SSH daemon, a keypair for signing in as root, and whether password login is allowed at all.
        <svg class="ic" style="color:var(--danger)"><use href="#ic-triangle-alert"/></svg> If SSH is your only way in, keep another route before disabling anything here.</div>
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
        <span class="cfg-running" id="ssh-state">Checking&hellip;</span>
        <button class="save-btn" id="ssh-toggle-btn" onclick="toggleSsh()" disabled>&hellip;</button></div>
      <div class="save-feedback" id="ssh-feedback"></div>

      <div id="ssh-key-block" style="margin-top:18px;">
        <div class="cfg-running" id="ssh-key-state">Checking for a key&hellip;</div>
        <button class="save-btn" id="ssh-genkey-btn" onclick="generateSshKey()" hidden>Generate SSH key</button>
        <div id="ssh-key-details" hidden>
          <div class="field-group"><label class="field-label">Public key</label>
            <textarea class="field-input" id="ssh-pubkey" rows="3" readonly spellcheck="false"></textarea></div>
          <button class="db-action-btn" onclick="downloadSshPrivateKey()"><svg class="ic"><use href="#ic-download"/></svg>Download private key</button>
          <div class="settings-subtitle" id="ssh-fingerprint" style="margin-top:8px;"></div>
        </div>
        <div class="save-feedback" id="ssh-key-feedback"></div>
      </div>

      <div class="field-group" style="margin-top:18px;"><label class="field-label" for="ssh-password">Root password (reference only)</label>
        <div class="field-hint">Stored encrypted for your own records. Saving it here does not change any account's real password on this server.</div>
        <input class="field-input" id="ssh-password" type="password" autocomplete="off"></div>
      <button class="save-btn" id="ssh-password-save" onclick="saveSshPassword()">Save</button>
      <div class="save-feedback" id="ssh-password-feedback"></div>

      <div class="field-group" style="margin-top:18px;">
        <label class="perm-check"><input type="checkbox" id="ssh-allow-password" onchange="toggleSshPasswordLogin()">Allow password login (uncheck for key-only)</label>
      </div>
      <div class="save-feedback" id="ssh-login-mode-feedback"></div>
    </div>
  </div>"""

def _config_sub_service():
    return f"""
  <div class="config-sub" data-cfgsub="service" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">Systemd services</div>
    <div style="display:flex;gap:8px;margin-bottom:12px;align-items:center;">
      <input id="svc-search" class="field-input" style="max-width:240px;" placeholder="filter services&hellip;">
      <button class="db-action-btn" onclick="loadServices()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button></div>
    <div id="svc-list"><div class="empty-state">Loading&hellip;</div></div>
  </div>"""

def _config_sub_database(perms: dict):
    write = perms.get("role") == "admin"
    hint = "" if write else '<span class="cfg-running">read only</span>'
    return f"""
  <div class="config-sub" data-cfgsub="database" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">Database</div>
    <div style="display:flex;gap:8px;margin-bottom:12px;align-items:center;flex-wrap:wrap;">
      <select class="field-input" id="db-table-sel" style="max-width:240px;" onchange="loadDbTable()"><option value="">Pick a table&hellip;</option></select>
      <button class="db-action-btn" onclick="loadDbTables()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
      {hint}
    </div>
    <div id="db-table-view"><div class="empty-state">Pick a table to browse it.</div></div>
  </div>"""

def _px_toggle(field, label, help_text, on=False):
    """A behaviour switch. These read as physical on/off because they change
    how traffic is handled, not what the host is."""
    return f"""
        <label class="px-toggle-row">
          <span class="grant-copy">
            <span class="grant-label">{label}</span>
            <span class="grant-help">{help_text}</span>
          </span>
          <span class="px-switch">
            <input type="checkbox" data-px="{field}"{" checked" if on else ""}>
            <span class="px-switch-track"><span class="px-switch-knob"></span></span>
          </span>
        </label>"""

def _px_check(field, label, help_text):
    return f"""
        <label class="px-check-row">
          <input type="checkbox" data-px="{field}">
          <span class="grant-copy">
            <span class="grant-label">{label}</span>
            <span class="grant-help">{help_text}</span>
          </span>
        </label>"""

def _config_sub_proxy(perms):
    listen_segs = "".join(
        f'<label class="grant-seg"><input type="radio" name="px-listen" '
        f'value="{value}"{" checked" if value == "https" else ""}>{label}</label>'
        for value, label in (("http", "HTTP"), ("https", "HTTPS"),
                             ("tcp", "TCP"), ("udp", "UDP")))
    forward_segs = "".join(
        f'<label class="grant-seg"><input type="radio" name="px-forward-scheme" '
        f'value="{value}"{" checked" if value == "http" else ""}>{label}</label>'
        for value, label in (("http", "HTTP"), ("https", "HTTPS")))

    return f"""
  <div class="config-sub" data-cfgsub="proxy" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">Proxy</div>

    <div class="cfg-card cfg-card-wide">
      <div class="px-card-head">
        <div>
          <div class="device-title">Reverse proxy hosts</div>
          <div class="settings-subtitle" style="margin-top:6px;">Every server block nginx loads. Hosts added here can be edited; hand-written ones are left alone.</div>
        </div>
        <button class="save-btn" id="px-new" type="button" onclick="openProxyForm(null)">Add proxy host</button>
      </div>
      <div id="proxy-list" style="margin-top:16px;"><div class="empty-state">Loading&hellip;</div></div>
    </div>

    <div class="cfg-card cfg-card-wide" id="px-form-card" style="margin-top:18px;" hidden>
      <div class="px-card-head">
        <div class="device-title" id="px-form-title">Add a proxy host</div>
        <button class="db-action-btn" onclick="closeProxyForm()">Cancel</button>
      </div>

      <div class="grant-group" style="margin-top:16px;">
        <div class="grant-legend">Incoming</div>
        <div class="px-row px-row-domain">
          <div class="px-field">
            <label class="field-label" for="px-listen-group">Scheme</label>
            <div class="grant-seg-group" id="px-listen-group">{listen_segs}</div>
          </div>
          <div class="px-field px-field-grow">
            <label class="field-label" for="px-domain">Domain name</label>
            <input class="field-input" id="px-domain" type="text" placeholder="app.example.com"
                   spellcheck="false" autocomplete="off">
          </div>
        </div>
        <div class="px-row" id="px-listen-port-row">
          <div class="px-field">
            <label class="field-label" for="px-listen-port">Listen port</label>
            <div class="field-hint">The port on this server the host answers on. Empty means the scheme default.</div>
            <input class="field-input" id="px-listen-port" type="number" min="1" max="65535"
                   placeholder="15432" inputmode="numeric" autocomplete="off">
          </div>
        </div>
        <div class="px-stream-note" id="px-stream-note" hidden></div>
      </div>

      <div class="grant-group">
        <div class="grant-legend">Forward to</div>
        <div class="px-row">
          <div class="px-field" id="px-forward-scheme-field">
            <label class="field-label" for="px-forward-scheme-group">Scheme</label>
            <div class="grant-seg-group" id="px-forward-scheme-group">{forward_segs}</div>
          </div>
          <div class="px-field px-field-grow">
            <label class="field-label" for="px-forward-host">Hostname or IP</label>
            <input class="field-input" id="px-forward-host" type="text" placeholder="127.0.0.1"
                   spellcheck="false" autocomplete="off">
          </div>
          <div class="px-field px-field-port">
            <label class="field-label" for="px-forward-port">Port</label>
            <input class="field-input" id="px-forward-port" type="number" min="1" max="65535"
                   placeholder="8080" inputmode="numeric" autocomplete="off">
          </div>
        </div>
      </div>

      <div class="grant-group" id="px-tls-group" hidden>
        <div class="grant-legend">HTTPS</div>
        <div class="px-check-grid">
          {_px_check("force_ssl", "Force SSL", "Send anyone arriving on HTTP to HTTPS instead.")}
          {_px_check("http2", "HTTP/2 support", "Fewer round trips for browsers that speak it.")}
          {_px_check("hsts", "HSTS enabled", "Tells browsers never to use plain HTTP for this name again.")}
          {_px_check("hsts_subdomains", "HSTS subdomains", "Extends that promise to every name under it. Only with HSTS on.")}
        </div>
      </div>

      <div class="grant-group" id="px-behaviour-group">
        <div class="grant-legend">Behaviour</div>
        {_px_toggle("cache_assets", "Cache assets",
                    "Let browsers keep images, fonts, CSS and JS for 30 days.")}
        {_px_toggle("block_exploits", "Block common exploits",
                    "Reject requests carrying the usual injection and traversal probes.")}
        {_px_toggle("websockets", "Websockets support",
                    "Pass the upgrade through so live connections stay open.", on=True)}
      </div>

      <div class="grant-group" id="px-locations-group">
        <div class="grant-legend">Custom locations</div>
        <div class="settings-subtitle" style="margin:0 0 12px;">
          Optional. Send a path under this domain somewhere else, for example
          /api to a different port. Leave empty to forward everything to one place.
        </div>
        <div id="px-locations"></div>
        <button class="db-action-btn" id="px-add-location" onclick="addProxyLocation()">
          <svg class="ic"><use href="#ic-plus"/></svg> Add a location
        </button>
      </div>

      <div class="px-form-actions">
        <button class="save-btn" id="px-save" onclick="saveProxyHost()">Save host</button>
        <div class="save-feedback" id="px-feedback"></div>
      </div>
    </div>
  </div>"""

def _config_sub_tunnel(perms):
    """Cloudflare Tunnel, on its own page.

    It is a sequence, not a set of independent switches: there is nothing to
    create until an account is connected, nothing to forward until a tunnel
    exists, and nothing to run until something is forwarded. The steps are
    numbered because the order carries that information, and each one stays
    closed until the step before it is satisfied.
    """
    return """
  <div class="config-sub" data-cfgsub="tunnel" hidden>
    """ + _CONFIG_BACK + """
    <div class="mgmt-h2">Cloudflare Tunnel</div>
    <div class="cfg-card cfg-card-wide" id="cf-card">
      <div class="px-card-head">
        <div class="settings-subtitle">
          Publish a name on the internet without opening a port. Cloudflare
          answers HTTPS at its edge and the tunnel hands the request to a port
          on this machine over plain HTTP, so the port stays closed.
        </div>
        <span class="cf-version" id="cf-version"></span>
      </div>

      <div class="cf-missing" id="cf-missing" hidden></div>

      <ol class="cf-steps" id="cf-steps">
        <li class="cf-step" id="cf-step-account">
          <div class="cf-step-head">
            <span class="cf-step-n">1</span>
            <span class="cf-step-title">Connect a Cloudflare account</span>
            <span class="cf-state" id="cf-account-state">checking</span>
          </div>
          <div class="cf-step-body">
            <div id="cf-account-idle">
              <div class="field-hint" style="margin-bottom:10px;">
                Opening the link signs this server in to your account. It only
                has to be done once.
              </div>
              <button class="save-btn" id="cf-login" onclick="tunnelLogin()">Create the link</button>
            </div>
            <div id="cf-link-row" hidden>
              <div class="cf-link-note"><span class="cf-pulse"></span>Waiting for you to finish in the browser</div>
              <div class="cf-link-box">
                <a class="cf-link" id="cf-link" href="#" target="_blank" rel="noopener noreferrer"></a>
                <button class="db-action-btn" onclick="tunnelCopyLink()">Copy link</button>
              </div>
            </div>
            <div id="cf-account-done" hidden>
              <div class="field-hint" style="margin-bottom:10px;">
                This server can manage the tunnels on your account.
              </div>
              <button class="db-action-btn cf-danger" onclick="tunnelDisconnect()">Disconnect account</button>
            </div>
            <div class="save-feedback" id="cf-account-feedback"></div>
          </div>
        </li>

        <li class="cf-step" id="cf-step-tunnel">
          <div class="cf-step-head">
            <span class="cf-step-n">2</span>
            <span class="cf-step-title">Create a tunnel</span>
            <span class="cf-state" id="cf-tunnel-state">waiting</span>
          </div>
          <div class="cf-step-body">
            <div id="cf-tunnel-list"></div>
            <div class="cf-add-row">
              <input class="field-input" id="cf-tunnel-name" type="text" maxlength="62"
                     placeholder="Tunnel name, for example home-server" autocomplete="off"
                     spellcheck="false">
              <button class="save-btn" id="cf-tunnel-create" onclick="tunnelCreate()">Create tunnel</button>
            </div>
            <div class="save-feedback" id="cf-tunnel-feedback"></div>
          </div>
        </li>

        <li class="cf-step" id="cf-step-forward">
          <div class="cf-step-head">
            <span class="cf-step-n">3</span>
            <span class="cf-step-title">Forward a hostname to a local port</span>
            <span class="cf-state" id="cf-route-state">waiting</span>
          </div>
          <div class="cf-step-body">
            <div id="cf-route-list"></div>
            <div class="cf-route-form">
              <div class="cf-field">
                <label class="field-label" for="cf-hostname">Public hostname</label>
                <input class="field-input" id="cf-hostname" type="text" maxlength="253"
                       placeholder="app.example.com" autocomplete="off" spellcheck="false">
              </div>
              <div class="cf-field">
                <label class="field-label" for="cf-local-host">Local address</label>
                <input class="field-input" id="cf-local-host" type="text" maxlength="255"
                       value="127.0.0.1" autocomplete="off" spellcheck="false">
              </div>
              <div class="cf-field cf-field-port">
                <label class="field-label" for="cf-local-port">Local port</label>
                <input class="field-input" id="cf-local-port" type="number" min="1" max="65535"
                       placeholder="8080" inputmode="numeric" autocomplete="off">
              </div>
              <button class="save-btn" id="cf-route-add" onclick="tunnelAddRoute()">Add forward</button>
            </div>
            <div class="field-hint">
              The DNS record is created at Cloudflare for you. The local side is
              plain HTTP, so the service does not need a certificate of its own.
            </div>
            <div class="save-feedback" id="cf-route-feedback"></div>
          </div>
        </li>

        <li class="cf-step" id="cf-step-run">
          <div class="cf-step-head">
            <span class="cf-step-n">4</span>
            <span class="cf-step-title">Keep the tunnel running</span>
            <span class="cf-state" id="cf-service-state">waiting</span>
          </div>
          <div class="cf-step-body">
            <div class="field-hint" style="margin-bottom:10px;" id="cf-service-note">
              Installed as a service, the tunnel comes back by itself after a reboot.
            </div>
            <div class="cf-btn-row">
              <button class="save-btn" id="cf-svc-install" onclick="tunnelService('install')">Install and start</button>
              <button class="db-action-btn" id="cf-svc-restart" onclick="tunnelService('restart')">Restart</button>
              <button class="db-action-btn" id="cf-svc-stop" onclick="tunnelService('stop')">Stop</button>
              <button class="db-action-btn cf-danger" id="cf-svc-remove" onclick="tunnelService('uninstall')">Remove service</button>
            </div>
            <div class="save-feedback" id="cf-service-feedback"></div>
          </div>
        </li>
      </ol>
    </div>
  </div>"""

def _config_sub_firewall(perms):
    """The firewall, on its own page. A proxy host opens its own inbound port as
    it is saved, so this is where that shows up as well as where a port is opened
    by hand."""
    return """
  <div class="config-sub" data-cfgsub="firewall" hidden>
    """ + _CONFIG_BACK + """
    <div class="mgmt-h2">Firewall</div>
    <div class="cfg-card cfg-card-wide">
      <div class="device-title">Firewall settings</div>
      <div class="settings-subtitle" style="margin:6px 0 4px;">
        Which ports this server accepts and which it may reach out on. A proxy
        host opens its own inbound port here automatically.
      </div>
      <div id="px-fw-status" class="px-fw-status"></div>
      <div class="px-fw-add">
        <select class="field-input px-fw-dir" id="px-fw-direction" aria-label="Direction">
          <option value="in">Inbound</option>
          <option value="out">Outbound</option>
        </select>
        <select class="field-input px-fw-proto" id="px-fw-protocol" aria-label="Protocol">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <input class="field-input px-fw-port" id="px-fw-port" type="number" min="1" max="65535"
               placeholder="Port" inputmode="numeric" autocomplete="off">
        <input class="field-input px-fw-note" id="px-fw-note" type="text"
               placeholder="What is it for" maxlength="120" autocomplete="off">
        <button class="save-btn" id="px-fw-add" onclick="addFirewallRule()">Add rule</button>
      </div>
      <div class="save-feedback" id="px-fw-feedback"></div>
      <div class="px-fw-cols">
        <div>
          <div class="px-fw-legend">Inbound</div>
          <div id="px-fw-in"><div class="empty-state">Loading&hellip;</div></div>
        </div>
        <div>
          <div class="px-fw-legend">Outbound</div>
          <div id="px-fw-out"><div class="empty-state">Loading&hellip;</div></div>
        </div>
      </div>
      <div class="px-fw-legend" style="margin-top:20px;">Blocked addresses</div>
      <div id="px-fw-blocks"><div class="empty-state">Loading&hellip;</div></div>
    </div>
  </div>"""

def _config_sub_telegram(perms):
    """The bot, on its own page: the token, the endpoint Telegram delivers to,
    who is allowed to use it, and the conversation log every allow decision is
    made from."""
    return """
  <div class="config-sub" data-cfgsub="telegram" hidden>
    """ + _CONFIG_BACK + """
    <div class="mgmt-h2">Telegram Bot</div>

    <div class="cfg-card cfg-card-wide">
      <div class="device-title">Bot connection</div>
      <div class="settings-subtitle" style="margin:6px 0 16px;">
        BotFather gives you a token. Paste it here with the domain this panel is
        already reachable on, and Telegram is told to deliver every message to
        <code>/bot</code> on that domain. Nothing new is opened on the firewall.
      </div>
      <div class="field-group"><label class="field-label" for="tg-token">Bot token</label>
        <div class="field-hint" id="tg-token-hint">Stored encrypted at rest and never shown again after saving.</div>
        <input class="field-input" id="tg-token" type="password" autocomplete="off" spellcheck="false"
               placeholder="123456789:AA..."></div>
      <div class="field-group"><label class="field-label" for="tg-domain">Domain</label>
        <div class="field-hint">The name you already use to reach this panel, without <code>https://</code>.</div>
        <input class="field-input" id="tg-domain" type="text" autocomplete="off" spellcheck="false"
               placeholder="panel.example.com"></div>
      <div class="field-group"><label class="field-label" for="tg-notify">Notification email</label>
        <div class="field-hint">Where the bot reports what it did: strangers writing in, access granted, commands run. Leave empty for no email.</div>
        <input class="field-input" id="tg-notify" type="text" autocomplete="off" spellcheck="false"
               placeholder="you@example.com"></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <button class="save-btn" id="tg-save" onclick="saveTelegram()">Save</button>
        <button class="save-btn" id="tg-connect" onclick="connectTelegram()">Connect the bot</button>
        <button class="db-action-btn" id="tg-disconnect" onclick="disconnectTelegram()">Disconnect</button>
        <button class="db-action-btn" onclick="loadTelegram()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
      </div>
      <div class="save-feedback" id="tg-feedback"></div>
      <div class="cfg-running" id="tg-state" style="margin-top:12px;">Loading&hellip;</div>
    </div>

    <div class="cfg-card cfg-card-wide" style="margin-top:18px;">
      <div class="device-title">Who may use the bot</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">
        An admin gets everything this panel can do. A user gets exactly what
        their panel account is allowed, and nothing more.
      </div>
      <div id="tg-users"><div class="empty-state">Loading&hellip;</div></div>
      <div class="px-fw-add" style="margin-top:14px;">
        <input class="field-input" id="tg-add-id" type="text" inputmode="numeric"
               placeholder="Telegram ID" autocomplete="off">
        <select class="field-input" id="tg-add-role" aria-label="Role">
          <option value="user">User</option>
          <option value="admin">Admin</option>
          <option value="blocked">Blocked</option>
        </select>
        <input class="field-input" id="tg-add-user" type="text"
               placeholder="Panel account (users only)" autocomplete="off">
        <button class="save-btn" onclick="allowTelegramId()">Allow</button>
      </div>
      <div class="save-feedback" id="tg-users-feedback"></div>
    </div>

    <div class="cfg-card cfg-card-wide" style="margin-top:18px;">
      <div class="device-title">Conversation log</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">
        Every message the bot has received, whoever sent it. This is where an
        unknown Telegram ID becomes an allowed one.
      </div>
      <div id="tg-pending"></div>
      <div class="px-fw-legend" style="margin-top:16px;">All messages</div>
      <div id="tg-log"><div class="empty-state">Loading&hellip;</div></div>
      <div style="margin-top:12px;">
        <button class="db-action-btn" onclick="clearTelegramLog()"><svg class="ic"><use href="#ic-trash-2"/></svg>Clear the log</button>
      </div>
    </div>
  </div>"""

_CONFIG_SUB_BUILDERS = {
    "account": _config_sub_account,
    "users": lambda perms: _config_sub_users(),
    "server": lambda perms: _config_sub_server(),
    "service": lambda perms: _config_sub_service(),
    "database": lambda perms: _config_sub_database(perms),
    "proxy": lambda perms: _config_sub_proxy(perms),
    "tunnel": lambda perms: _config_sub_tunnel(perms),
    "firewall": lambda perms: _config_sub_firewall(perms),
    "telegram": lambda perms: _config_sub_telegram(perms),
}

def _config_pane_html(perms: dict) -> str:
    allowed = _config_cards(perms)
    cards = "".join(
        f'<button class="config-card" data-cfgnav="{key}" onclick="configOpen(\'{key}\')">'
        f'<svg class="ic"><use href="#{_CONFIG_CARD_META[key][1]}"/></svg>'
        f'<div class="config-card-title">{_CONFIG_CARD_META[key][0]}</div>'
        f'<div class="config-card-desc">{_CONFIG_CARD_META[key][2]}</div>'
        f'</button>'
        for key in allowed
    )
    subs = "".join(_CONFIG_SUB_BUILDERS[key](perms) for key in allowed)
    return f"""
  <div class="pane" data-pane="config"><div class="pane-scroll">
    <div id="config-menu" class="config-menu">{cards}</div>
    {subs}
  </div></div>"""

def _crest():
    return ('<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/>'
            '<rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/>'
            '<line x1="6" x2="6.01" y1="18" y2="18"/></svg>')

# The four panes are identical across shells (same IDs); only the chrome differs.
_PANES_TEMPLATE = """
<div class="mgmt-main">
  <!-- SERVER -->
  <div class="pane" data-pane="server"><div class="pane-scroll"><div class="server-inner">
    <div class="srv-grid">
      <div class="metric-card metric-clickable" onclick="openServerDetail('cpu')" title="Top processes by CPU">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-cpu"/></svg>CPU</span><span class="metric-now" id="m-cpu-now">0%</span></div>
        <canvas class="metric-chart" id="chart-cpu" height="70"></canvas>
        <div class="metric-foot" id="m-cpu-foot">-</div>
        <div class="core-bars" id="core-bars"></div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('mem')" title="Top processes by memory">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-memory-stick"/></svg>Memory</span><span class="metric-now" id="m-ram-now">0%</span></div>
        <canvas class="metric-chart" id="chart-ram" height="70"></canvas>
        <div class="metric-foot" id="m-ram-foot">-</div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('net')" title="Active connections">
        <div class="metric-head net-head"><span class="metric-title"><svg class="ic"><use href="#ic-wifi"/></svg>Network</span><span class="metric-now net-now" id="m-net-now"><span>&darr;0B/s</span><span>&uarr;0B/s</span></span></div>
        <canvas class="metric-chart" id="chart-net" height="70"></canvas>
        <div class="metric-foot" id="m-net-foot">-</div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('disk')" title="Browse, upload and download files">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-hard-drive"/></svg>Disk</span><span class="metric-now" id="m-disk-now">0%</span></div>
        <div class="disk-bar"><div class="disk-fill" id="disk-fill"></div></div>
        <div class="metric-foot" id="m-disk-foot">-</div>
        <div class="metric-head" style="margin-top:14px;"><span class="metric-title">Load avg</span><span class="metric-now" id="m-load-now">0.00</span></div>
        <div class="metric-foot" id="m-load-foot">1m / 5m / 15m</div>
      </div>
    </div>
    <div class="device-card">
      <div class="device-card-head">
        <div class="device-card-heading">
          <div class="device-title">Device &amp; OS</div>
          <div class="device-sub">Hardware, network and runtime at a glance.</div>
        </div>
        <span class="device-live" title="Refreshes every 15 seconds"><span class="status-dot on"></span>Live hardware</span>
      </div>
      <div class="device-grid" id="device-grid"><div class="empty-state">Loading device info&hellip;</div></div>
    </div>
  </div></div></div>

  {config_pane}

  <!-- TERMINAL -->
  <div class="pane" data-pane="terminal"><div class="pane-scroll">
    <div class="term-tabs" id="term-tabs">
      <button class="term-addbtn" id="term-add" title="Open another terminal" onclick="termAddTab()">+</button></div>
    <div class="term-stack" id="term-stack"></div>
  </div></div>

  <!-- LOGS -->
  <!-- MAIL. Two audiences in one pane: an admin who may still have to set the
       whole thing up, and everybody else, who either has an address or does not.
       Which of those you are decides what is on the page, so the shell here is
       almost empty and the interface is built from the overview call. -->
  <div class="pane" data-pane="mail"><div class="pane-scroll">
    <div id="mail-main" hidden>
      <div class="mail-bar">
        <div class="mail-folders">
          <button class="log-cat-tab active" data-mailfolder="inbox" onclick="mailFolder('inbox')">
            <svg class="ic"><use href="#ic-inbox"/></svg>Inbox<span class="mail-count" id="mail-inbox-count"></span>
          </button>
          <button class="log-cat-tab" data-mailfolder="sent" onclick="mailFolder('sent')">
            <svg class="ic"><use href="#ic-send"/></svg>Sent
          </button>
        </div>
        <select class="field-input mail-box-pick" id="mail-box" aria-label="Mailbox"
                onchange="loadMailMessages()"></select>
        <button class="save-btn" id="mail-compose-btn" onclick="mailCompose()">
          <svg class="ic"><use href="#ic-send"/></svg>Write
        </button>
        <button class="db-action-btn" id="mail-sync-btn" onclick="mailSync()" hidden>
          <svg class="ic"><use href="#ic-refresh-cw"/></svg>Collect mail
        </button>
        <button class="db-action-btn" id="mail-settings-btn" onclick="mailToggleSettings()"
                aria-expanded="false" aria-controls="mail-setup" hidden>
          <svg class="ic"><use href="#ic-settings"/></svg>Mail settings
        </button>
      </div>

      <div class="cfg-card cfg-card-wide" id="mail-compose-card" hidden>
        <div class="px-card-head">
          <div class="device-title">New message</div>
          <button class="db-action-btn" onclick="mailCloseCompose()">Cancel</button>
        </div>
        <div class="mail-from" id="mail-from-row"></div>
        <div class="grant-group" style="margin-top:14px;">
          <div class="grant-legend">Where is it going</div>
          <div class="field-hint" style="margin:0 0 10px;">
            Internal mail is delivered inside this system and never reaches the
            relay. External mail is handed to the relay and leaves the building.
          </div>
          <div class="grant-seg-group" id="mail-route-group">
            <label class="grant-seg"><input type="radio" name="mail-route" value="internal" checked>Internal</label>
            <label class="grant-seg"><input type="radio" name="mail-route" value="external">External</label>
          </div>
        </div>
        <div class="field-group" style="margin-top:16px;">
          <label class="field-label" for="mail-to">To</label>
          <input class="field-input" id="mail-to" type="email" maxlength="320"
                 placeholder="somebody@example.com" autocomplete="off" spellcheck="false">
          <div class="field-hint" id="mail-to-hint"></div>
        </div>
        <div class="field-group">
          <label class="field-label" for="mail-subject">Subject</label>
          <input class="field-input" id="mail-subject" type="text" maxlength="300" autocomplete="off">
        </div>
        <div class="field-group">
          <label class="field-label" for="mail-body">Message</label>
          <textarea class="field-input mail-body-input" id="mail-body" rows="9" maxlength="100000"></textarea>
        </div>
        <div class="px-form-actions">
          <button class="save-btn" id="mail-send" onclick="mailSend()">Send</button>
          <div class="save-feedback" id="mail-send-feedback"></div>
        </div>
      </div>

      <div class="mail-split">
        <div class="mail-list" id="mail-list"><div class="empty-state">Loading&hellip;</div></div>
        <div class="mail-read" id="mail-read">
          <div class="mail-read-nothing">
            <svg class="ic"><use href="#ic-mail"/></svg>
            <b>Nothing open</b>
            Pick a message on the left and it opens here. Unread ones carry a red dot.
          </div>
        </div>
      </div>
    </div>

    <!-- The setup sits below the mail, not above it. Until a domain exists it is
         the only thing on the page, because there is nothing else to show. Once
         mail is running it is reference material, and the button in the bar
         brings it back. -->
    <div id="mail-setup"></div>
  </div></div>

  <div class="pane" data-pane="logs"><div class="pane-scroll">
    <!-- Four numbers, one question each. The old set mixed "total events" with
         "unique IPs" and "active sessions", which answered nothing you would
         actually ask. Every tile here is scoped by the range control beside it,
         so the numbers move when you change the window. -->
    <div class="sec-range-row">
      <div class="sec-range-label">Showing</div>
      <div class="grant-seg-group" id="sec-range-group">
        <label class="grant-seg"><input type="radio" name="sec-range" value="today" checked>Today</label>
        <label class="grant-seg"><input type="radio" name="sec-range" value="3days">Last 3 days</label>
        <label class="grant-seg"><input type="radio" name="sec-range" value="week">Last week</label>
        <label class="grant-seg"><input type="radio" name="sec-range" value="month">Last month</label>
      </div>
      <button class="db-action-btn" style="margin-left:auto;" onclick="loadSecurityLogs()">
        <svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
    </div>
    <div class="srv-grid" id="sec-ssh-cards" style="margin-bottom:18px;">
      <div class="metric-card"><div class="metric-head"><span class="metric-title">SSH logins</span><span class="metric-now" style="color:var(--success)" id="sec-ssh-ok">&hellip;</span></div><div class="metric-foot" id="sec-ssh-ok-foot">successful, over SSH</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">SSH failures</span><span class="metric-now" style="color:var(--danger)" id="sec-ssh-bad">&hellip;</span></div><div class="metric-foot" id="sec-ssh-bad-foot">rejected SSH attempts</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Panel logins</span><span class="metric-now" style="color:var(--success)" id="sec-web-ok">&hellip;</span></div><div class="metric-foot" id="sec-web-ok-foot">successful, in this panel</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Panel failures</span><span class="metric-now" style="color:var(--danger)" id="sec-web-bad">&hellip;</span></div><div class="metric-foot" id="sec-web-bad-foot">wrong username or password</div></div>
    </div>
    <div class="log-cat-tabs">
      <button class="log-cat-tab" data-logcat="ssh" onclick="showLogCategory('ssh')">SSH Log</button>
      <button class="log-cat-tab" data-logcat="web" onclick="showLogCategory('web')">Web Log</button>
      <button class="log-cat-tab active" data-logcat="server" onclick="showLogCategory('server')">Server Activity</button>
    </div>
    <div class="sec-cat-group" data-logcat="ssh" hidden>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center;">
        <button class="db-action-btn sec-section-btn" data-sec="ssh-sessions" onclick="showSecSection('ssh-sessions')">Active Sessions</button>
        <button class="db-action-btn sec-section-btn" data-sec="ssh-events" onclick="showSecSection('ssh-events')">All Events</button>
        <button class="db-action-btn sec-section-btn" data-sec="ssh-accepted" onclick="showSecSection('ssh-accepted')">Successful Logins</button>
        <button class="db-action-btn sec-section-btn" data-sec="ssh-fingerprints" onclick="showSecSection('ssh-fingerprints')">Key Fingerprints</button>
        <button class="db-action-btn sec-section-btn" data-sec="ssh-top-ips" onclick="showSecSection('ssh-top-ips')">Top IPs</button>
      </div>
    </div>
    <div class="sec-cat-group" data-logcat="web" hidden>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center;">
        <button class="db-action-btn sec-section-btn" data-sec="access-log" onclick="showSecSection('access-log')">Access Log</button>
        <button class="db-action-btn sec-section-btn" data-sec="web-sessions" onclick="showSecSection('web-sessions')">Sessions</button>
        <button class="db-action-btn sec-section-btn" data-sec="web-logs" onclick="showSecSection('web-logs')">Login Logs</button>
        <button class="db-action-btn sec-section-btn" data-sec="web-blocked" onclick="showSecSection('web-blocked')">Blocked IPs</button>
        <button class="db-action-btn sec-section-btn" data-sec="fp-blocked" onclick="showSecSection('fp-blocked')">Blocked Devices</button>
      </div>
    </div>
    <div class="sec-cat-group" data-logcat="server">
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center;">
        <button class="db-action-btn sec-section-btn active" data-sec="panel-actions" onclick="showSecSection('panel-actions')">Panel Actions</button>
      </div>
    </div>
    <div id="sec-content"><div class="empty-state">Loading security logs&hellip;</div></div>
  </div></div>

  {account_pane}
</div>

<div id="srv-detail-overlay" onclick="if(event.target===this)closeServerDetail()">
  <div id="srv-detail-modal">
    <div id="srv-detail-head"><span id="srv-detail-title">Detail</span>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end;">
        <button class="db-action-btn" id="srv-upload-btn" onclick="pickUploadFile()" hidden><svg class="ic"><use href="#ic-upload"/></svg>Upload</button>
        <input type="file" id="fb-upload-input" hidden multiple onchange="uploadFile(this)">
        <button class="db-action-btn" onclick="refreshServerDetail()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
        <button class="db-action-btn" onclick="closeServerDetail()"><svg class="ic"><use href="#ic-x"/></svg>Close</button></div></div>
    <div id="srv-detail-body"></div>
  </div>
</div>

<div id="upload-overlay" aria-hidden="true">
  <div id="upload-modal" role="dialog" aria-modal="true" aria-labelledby="upload-title">
    <div id="upload-head">
      <div id="upload-head-copy">
        <div id="upload-title">Uploads</div>
        <div id="upload-sub">Preparing&hellip;</div>
      </div>
      <button class="db-action-btn" id="upload-close-btn" onclick="closeUploadPanel()"><svg class="ic"><use href="#ic-x"/></svg>Close</button>
    </div>
    <div id="upload-overall" data-state="active">
      <div class="upload-meter" id="upload-overall-meter" role="progressbar" aria-label="Overall upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
        <div id="upload-overall-bar"></div>
      </div>
      <div id="upload-overall-text">0 of 0 uploaded</div>
    </div>
    <div id="upload-list"></div>
    <div id="upload-foot"><span id="upload-foot-note">Keep this panel open while files upload. Closing it asks before stopping the queue.</span></div>
  </div>
</div>

<div id="upload-stop-overlay" class="app-modal-overlay" aria-hidden="true">
  <div class="app-modal" role="alertdialog" aria-modal="true" aria-labelledby="upload-stop-title">
    <div class="app-modal-title" id="upload-stop-title">Stop uploading?</div>
    <div class="app-modal-msg" id="upload-stop-msg">Some files are still uploading.</div>
    <div class="app-modal-btns">
      <button class="app-modal-btn" onclick="resolveUploadStop(false)">Keep uploading</button>
      <button class="app-modal-btn danger" onclick="resolveUploadStop(true)">Yes, stop upload</button>
    </div>
  </div>
</div>
"""

def _account_pane_html(perms: dict) -> str:
    """Reached from the picture in the top bar rather than the nav, because it is
    a rare errand, not one of the places you work.

    What is on it depends on who you are, and one card is the reason this is a
    function instead of a constant: recovery codes belong to the admin alone, so
    a staff member is not shown a card they cannot use. They are told where to go
    instead, which is a person, not a page.
    """
    is_admin = perms.get("role") == "admin"

    recovery_card = """
    <div class="cfg-card" style="margin-top:18px;">
      <div class="device-title">Recovery codes</div>
      <div class="settings-subtitle" style="margin:6px 0 16px;">Single-use codes that reset this password from the login page when you cannot sign in.
        <svg class="ic" style="color:var(--danger)"><use href="#ic-triangle-alert"/></svg> Anyone holding a code can take over the panel.</div>
      <div class="cfg-running" id="acct-codes-state">Checking&hellip;</div>
      <div class="field-group" style="margin-top:16px;"><label class="field-label" for="acct-regen-pw">Current password</label>
        <div class="field-hint">Required, because issuing new codes retires every existing one.</div>
        <input class="field-input" id="acct-regen-pw" type="password" autocomplete="current-password"></div>
      <button class="save-btn" id="acct-regen" onclick="regenerateRecoveryCodes()">Generate New Codes</button>
      <div class="save-feedback" id="acct-regen-feedback"></div>
      <div id="acct-codes-out" hidden></div>
    </div>""" if is_admin else """
    <div class="mail-empty-note" style="margin-top:18px;">
      <b>There are no recovery codes for staff accounts.</b><br>
      If you cannot sign in, ask an administrator to reset your password. They do
      it in person, which is a stronger check than a code in a file, and it means
      nothing exists that could sign in as you if it were found.
    </div>"""

    return f"""
  <div class="pane" data-pane="account"><div class="pane-scroll">
    <div class="cfg-card acct-id-card">
      <div class="acct-id-head">
        <span class="acct-face acct-face-lg" id="acct-face">
          <img id="acct-face-img" alt="" hidden><span id="acct-face-txt">&hellip;</span>
        </span>
        <div class="acct-id-copy">
          <div class="acct-id-name" id="acct-id-name">&hellip;</div>
          <div class="acct-id-sub"><span id="acct-id-user"></span>
            <span class="acct-role-chip" id="acct-id-role"></span></div>
        </div>
      </div>
      <div class="acct-id-body">
        <div class="field-group">
          <label class="field-label" for="acct-fullname">Full name</label>
          <div class="field-hint" id="acct-name-hint">Shown in the top bar, and on every
            message you send.</div>
          <input class="field-input" id="acct-fullname" type="text" maxlength="120"
                 autocomplete="name" placeholder="Your name as it should appear">
        </div>
        <div class="px-form-actions">
          <button class="save-btn" onclick="saveFullName()">Save name</button>
          <div class="save-feedback" id="acct-name-feedback"></div>
        </div>
        <div class="acct-pic">
          <div class="field-label">Picture</div>
          <div class="field-hint" id="acct-pic-hint">PNG or SVG. It is rebuilt from the
            parts we recognise before it is stored, so nothing else in the file survives.</div>
          <div class="cf-btn-row" style="margin-top:10px;">
            <label class="db-action-btn acct-upload">
              <svg class="ic"><use href="#ic-upload"/></svg>Choose a picture
              <input type="file" id="acct-pic-input" accept="image/png,image/svg+xml"
                     onchange="uploadAvatar(this)" hidden>
            </label>
            <button class="db-action-btn" id="acct-pic-clear" onclick="removeAvatar()" hidden>Remove</button>
          </div>
          <div class="save-feedback" id="acct-pic-feedback"></div>
          <div class="field-hint" id="acct-bimi" hidden></div>
        </div>
      </div>
    </div>

    <div class="cfg-card" style="margin-top:18px;">
      <div class="device-title">Password</div>
      <div class="settings-subtitle" style="margin:6px 0 18px;">Changing it signs out every other browser currently using this account.</div>
      <div class="field-group"><label class="field-label" for="acct-cur">Current password</label>
        <input class="field-input" id="acct-cur" type="password" autocomplete="current-password"></div>
      <div class="field-group"><label class="field-label" for="acct-new">New password</label>
        <div class="field-hint">At least 8 characters, and not only digits.</div>
        <input class="field-input" id="acct-new" type="password" autocomplete="new-password"></div>
      <div class="field-group"><label class="field-label" for="acct-new2">Confirm new password</label>
        <input class="field-input" id="acct-new2" type="password" autocomplete="new-password"></div>
      <button class="save-btn" id="acct-save" onclick="changePassword()">Change Password</button>
      <div class="save-feedback" id="acct-feedback"></div>
    </div>
    {recovery_card}
  </div></div>"""

def _nav_badge(key):
    """Mail is the one tab where something can be waiting for you, so it is the
    one tab that carries a count. Empty until the count arrives, and hidden at
    zero rather than showing a nought."""
    if key != "mail":
        return ""
    return '<span class="nav-badge" id="mail-badge" hidden>0</span>'

def _mobile_tabbar(nav):
    items = "".join(
        f'<button class="mtab" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg>'
        f'<span>{label}</span>'
        + ('<span class="nav-badge nav-badge-m" id="mail-badge-m" hidden>0</span>'
           if k == "mail" else "")
        + '</button>'
        for k, label, ic in nav)
    return f'<nav class="mobile-tabbar" style="grid-template-columns:repeat({len(nav)},1fr);">{items}</nav>'

def _topbar(mobile: bool, user: str, nav, me: dict, role: str):
    tabs = "".join(
        f'<button class="tab-btn" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg>'
        f'{label}{_nav_badge(k)}</button>'
        for k, label, ic in nav)
    safe_user = html.escape(user or "", quote=True)
    shown = html.escape(me.get("full_name") or user or "", quote=True)
    role_label = "Administrator" if role == "admin" else "Staff"
    # The picture is an <img>, never inlined markup, whatever kind of file it is.
    # An SVG in an <img> cannot run script or fetch anything; the same SVG pasted
    # into this page could do both.
    if me.get("has_avatar"):
        src = f'{MGMT_BASE}/api/account/avatar/{safe_user}?v={html.escape(me.get("avatar_hash", "")[:16])}'
        face = f'<img src="{src}" alt="" width="30" height="30">'
    else:
        face = f'<span>{html.escape(me.get("initials") or "?")}</span>'
    right = (
        '<button class="theme-btn" onclick="toggleTheme()" title="Toggle dark mode"><svg class="ic"><use href="#ic-moon" id="theme-ic"/></svg></button>'
        # The username was inert text; it is now the way into account settings,
        # which is where people already look for it.
        f'<button class="acct-btn" data-nav="account" onclick="switchSection(\'account\')" '
        f'title="Account settings for {safe_user}" aria-label="Account settings for {safe_user}">'
        f'<span class="acct-face" id="topbar-face">{face}</span>'
        f'<span class="acct-copy"><span class="acct-name" id="topbar-name">{shown}</span>'
        f'<span class="acct-role">{role_label}</span></span></button>'
        f'<a href="{MGMT_BASE}/logout" class="db-action-btn"><svg class="ic"><use href="#ic-log-out"/></svg>Logout</a>'
    )
    return (
        '<div class="mgmt-top">'
        f'<div class="mgmt-brand"><span class="mgmt-crest">{_crest()}</span>Management</div>'
        f'<div class="mgmt-tabs">{tabs}</div>'
        f'<div class="mgmt-right">{right}</div>'
        '</div>'
    )

def _dashboard_html(mobile: bool, user: str, perms: dict, me: dict = None) -> str:
    shell = "mgmt-mobile" if mobile else "mgmt-desktop"
    nav = _visible_nav(perms)
    # No identity passed means nobody looked it up: fall back to the account name
    # and its initials rather than making the caller supply a dict it does not have.
    me = me or {"full_name": perms.get("full_name") or "", "has_avatar": False,
                "initials": identity.initials(perms.get("full_name"), user)}
    panes = (_PANES_TEMPLATE
             .replace("{config_pane}", _config_pane_html(perms))
             .replace("{account_pane}", _account_pane_html(perms)))
    # The whole resolved grant set goes to the client so the interface can hide
    # controls nobody can use. This is a convenience for the person looking at
    # the page and never a security boundary: every one of these is enforced
    # again server-side, and the browser copy is assumed to be tampered with.
    client_perms = {"role": perms.get("role"), "username": perms.get("username", ""),
                    "fullName": perms.get("full_name", "")}
    client_perms.update({k: perms.get(k) for k in panel_users.GRANT_KEYS})
    perms_json = json.dumps(client_perms)
    return (
        "<!DOCTYPE html><html lang=\"en\"><head>"
        "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        f"<title>Management</title>"
        f"<link rel=\"icon\" href=\"{MGMT_BASE}/favicon.ico\">"
        f"<link rel=\"stylesheet\" href=\"{MGMT_BASE}/static/dash.css\">"
        f"<script>window.MGMT_BASE={json.dumps(MGMT_BASE)};window.MGMT_PERMS={perms_json};</script></head>"
        f"<body class=\"mgmt {shell}\">{_ICON_SPRITE}"
        f"{_topbar(mobile, user, nav, me, perms.get('role', ''))}{panes}{_mobile_tabbar(nav)}"
        f"<script src=\"{MGMT_BASE}/static/management.js\"></script></body></html>"
    )

def _is_mobile(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return any(t in ua for t in ("mobi", "android", "iphone", "ipod", "windows phone"))

# Login page, warm palette via the shared stylesheet, same /api/login flow.
# __BASE__ is substituted with MGMT_BASE by _login_html().
_LOGIN_HTML = r"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Management</title><link rel="icon" href="__BASE__/favicon.ico">
<link rel="stylesheet" href="__BASE__/static/dash.css">
<style>
  body.login { display:flex; align-items:center; justify-content:center; min-height:100dvh; padding:24px;
    background:radial-gradient(120% 120% at 50% 0%, var(--bg1,#ede0c8) 0%, var(--bg2,#d8c19c) 100%); }
  .box { width:100%; max-width:384px; padding:44px 40px 38px; background:var(--card); border:1px solid var(--gray-200);
    border-radius:18px; box-shadow:0 2px 4px rgba(58,42,22,.06), 0 30px 70px -20px rgba(58,42,22,.30); }
  .crest { width:54px; height:54px; margin:0 auto 20px; display:flex; align-items:center; justify-content:center;
    border-radius:15px; background:var(--accent); color:#fbf2e2; }
  [data-theme="dark"] .crest { color:#20160c; } .crest svg { width:26px; height:26px; }
  .brand { font-family:var(--display); font-size:27px; font-weight:700; letter-spacing:1px; text-align:center; color:var(--black); }
  .sub { font-size:12px; color:var(--gray-400); text-align:center; letter-spacing:2.4px; text-transform:uppercase;
    margin:7px 0 30px; font-family:var(--display); font-weight:500; }
  .fg { margin-bottom:16px; } .fl { display:block; font-size:10px; font-weight:700; letter-spacing:.7px;
    text-transform:uppercase; color:var(--gray-600); margin-bottom:6px; font-family:var(--display); }
  .fi { width:100%; padding:11px 13px; border:1px solid var(--gray-200); border-radius:10px; font-family:var(--mono);
    font-size:13px; color:var(--black); background:var(--white); }
  .fi:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px var(--ring); }
  .btn2 { width:100%; margin-top:10px; padding:12px; background:var(--accent); color:#fbf2e2; border:none;
    border-radius:10px; font-size:14px; font-family:var(--display); font-weight:700; cursor:pointer; }
  [data-theme="dark"] .btn2 { color:#20160c; } .btn2:disabled { opacity:.55; cursor:not-allowed; }
  .err { margin-top:16px; font-size:12px; color:var(--danger); text-align:center; min-height:16px; }
  .okmsg { margin-top:16px; font-size:12.5px; line-height:1.55; color:var(--success); text-align:center; }
  /* The two views live in one card: signing in and recovering are the same
     task at different levels of trouble, so the card stays put and its
     contents change rather than throwing up a second surface. */
  [hidden] { display:none !important; }
  .view { animation:viewin .18s cubic-bezier(.22,1,.36,1) both; }
  @keyframes viewin { from { opacity:0; transform:translateY(5px); } to { opacity:1; transform:none; } }
  @media (prefers-reduced-motion:reduce) { .view { animation:none; } }
  .viewhead { font-family:var(--display); font-size:15px; font-weight:700; color:var(--black);
    text-align:center; margin-bottom:7px; }
  .note { font-size:11.5px; line-height:1.6; color:var(--gray-500); text-align:center; margin:0 0 22px; }
  .alt { margin-top:17px; text-align:center; }
  .linkbtn { background:none; border:none; padding:5px 7px; font-family:inherit; font-size:12px;
    color:var(--gray-500); cursor:pointer; border-radius:7px; text-decoration:underline;
    text-underline-offset:3px; text-decoration-color:var(--gray-300);
    transition:color .15s, text-decoration-color .15s; }
  .linkbtn:hover { color:var(--accent); text-decoration-color:var(--accent); }
  .linkbtn:focus-visible { outline:none; box-shadow:0 0 0 3px var(--ring); color:var(--accent); }
  .fi.code { letter-spacing:.2em; text-align:center; font-size:15px; }
  .fi.code::placeholder { letter-spacing:.12em; color:var(--gray-300); }
</style></head><body class="login">
<div class="box">
  <div class="crest"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="10" width="18" height="12" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/><circle cx="12" cy="16" r="1"/></svg></div>
  <div class="brand">Management</div><div class="sub">Authorized access only</div>

  <div class="view" id="signin-view">
    <form id="lf">
      <div class="fg"><label class="fl" for="u">Username</label><input class="fi" id="u" type="text" autofocus autocomplete="username" spellcheck="false"></div>
      <div class="fg"><label class="fl" for="p">Password</label><input class="fi" id="p" type="password" autocomplete="current-password"></div>
      <button class="btn2" type="submit" id="sbtn">Sign in</button>
      <div class="err" id="err" role="alert" aria-live="polite"></div>
    </form>
    <div class="alt"><button class="linkbtn" type="button" id="to-recover">Forgot your password?</button></div>
  </div>

  <div class="view" id="recover-view" hidden>
    <div class="viewhead">Recover account</div>
    <p class="note">Enter one of the single-use codes from your <code>.recovery</code> file. Each code works once.</p>
    <form id="rf">
      <div class="fg"><label class="fl" for="ru">Username</label><input class="fi" id="ru" type="text" autocomplete="username" spellcheck="false"></div>
      <div class="fg"><label class="fl" for="rc">Recovery code</label>
        <input class="fi code" id="rc" type="text" inputmode="numeric" autocomplete="one-time-code"
               placeholder="0000 0000 0000" maxlength="14" spellcheck="false"></div>
      <div class="fg"><label class="fl" for="rp">New password</label><input class="fi" id="rp" type="password" autocomplete="new-password"></div>
      <div class="fg"><label class="fl" for="rp2">Confirm new password</label><input class="fi" id="rp2" type="password" autocomplete="new-password"></div>
      <button class="btn2" type="submit" id="rbtn">Reset password</button>
      <div class="err" id="rerr" role="alert" aria-live="polite"></div>
      <div class="okmsg" id="rok" hidden></div>
    </form>
    <div class="alt"><button class="linkbtn" type="button" id="to-signin">Back to sign in</button></div>
  </div>
</div>
<script>
  if(localStorage.getItem('theme')==='dark') document.documentElement.setAttribute('data-theme','dark');
  const $=function(id){ return document.getElementById(id); };

  /* --- view swapping ---------------------------------------------------- */
  function showView(which){
    const signin=which==='signin';
    $('signin-view').hidden=!signin; $('recover-view').hidden=signin;
    /* re-trigger the entrance so the swap reads as a change, not a jump */
    const v=signin?$('signin-view'):$('recover-view');
    v.classList.remove('view'); void v.offsetWidth; v.classList.add('view');
    (signin?$('u'):$('ru')).focus();
  }
  $('to-recover').addEventListener('click', function(){
    $('ru').value=$('u').value.trim(); showView('recover');
  });
  $('to-signin').addEventListener('click', function(){ showView('signin'); });
  document.addEventListener('keydown', function(e){
    if(e.key==='Escape' && !$('recover-view').hidden) showView('signin');
  });

  /* --- recovery code field: digits only, grouped in fours ---------------- */
  $('rc').addEventListener('input', function(){
    const digits=this.value.replace(/\D/g,'').slice(0,12);
    this.value=digits.replace(/(.{4})(?=.)/g,'$1 ');
  });

  /* --- sign in ----------------------------------------------------------- */
  $('lf').addEventListener('submit', async function(e){
    e.preventDefault(); const b=$('sbtn'), er=$('err'); b.disabled=true; er.textContent='';
    try{ const res=await fetch('__BASE__/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:$('u').value.trim(),password:$('p').value})});
      const d=await res.json(); if(d.status==='ok'){ location.href='__BASE__/'; } else { er.textContent=d.error||'Invalid username or password.'; b.disabled=false; }
    }catch(_){ er.textContent='Network error, please try again.'; b.disabled=false; }
  });

  /* --- recover ----------------------------------------------------------- */
  $('rf').addEventListener('submit', async function(e){
    e.preventDefault();
    const b=$('rbtn'), er=$('rerr'), okEl=$('rok');
    er.textContent=''; okEl.hidden=true;
    const user=$('ru').value.trim(), code=$('rc').value.replace(/\D/g,''), pw=$('rp').value;
    if(code.length!==12){ er.textContent='A recovery code is 12 digits.'; $('rc').focus(); return; }
    if(pw!==$('rp2').value){ er.textContent='The two passwords do not match.'; $('rp2').focus(); return; }
    b.disabled=true; b.textContent='Resetting…';
    try{
      const res=await fetch('__BASE__/api/recover',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({username:user,code:code,new_password:pw})});
      const d=await res.json();
      if(d.status==='ok'){
        okEl.textContent='Password reset. '+d.remaining+' recovery code'+(d.remaining===1?'':'s')+' left. Signing you in…';
        okEl.hidden=false; $('rf').querySelectorAll('input').forEach(function(i){ i.disabled=true; });
        setTimeout(function(){ $('u').value=user; showView('signin'); $('p').focus(); }, 2200);
      } else {
        er.textContent=d.error||'Could not reset the password.';
        b.disabled=false; b.textContent='Reset password';
      }
    }catch(_){ er.textContent='Network error, please try again.'; b.disabled=false; b.textContent='Reset password'; }
  });
</script></body></html>"""

def _login_html() -> str:
    return _LOGIN_HTML.replace("__BASE__", MGMT_BASE)

def _ensure_feature_tables():
    """Tables for features that arrived after the first release.

    A panel upgraded in place would otherwise serve the page and not have the
    tables behind it. Every statement is IF NOT EXISTS, so this costs one round
    trip at boot and nothing after that.
    """
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        for statement in (cloudflare_tunnel.SCHEMA + mail.SCHEMA
                          + identity.SCHEMA + telegram_bot.SCHEMA):
            cur.execute(statement)
        cur.close()
    finally:
        DB.release_connection(conn)

# ===========================================================================
# FastAPI app
# ===========================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        DB.init_pool()
    except Exception as e:
        logging.warning(f"DB pool warm failed: {e}")
    try:
        ensure_management_log()
    except Exception as e:
        logging.error(f"ensure_management_log failed: {e}")
    try:
        _ensure_feature_tables()
    except Exception as e:
        logging.error(f"feature tables failed: {e}")
    write_log("INFO", "SYSTEM", "Management panel started", actor="system", detail=f"pid={os.getpid()}")
    yield
    write_log("INFO", "SYSTEM", "Management panel stopped", actor="system")

app = FastAPI(title="Management", lifespan=lifespan)
# Added first => innermost, so it sees the path after the prefix is stripped and
# only requests the ingress gate already let through.
app.add_middleware(_AccessLog)
app.add_middleware(_SecurityHeaders)
app.add_middleware(_CloudflareOnly)
# Added last => outermost, so the prefix is gone before anything else looks at
# the path. A no-op when MGMT_BASE is "" (the reverse-proxied deployment).
app.add_middleware(_BasePathStrip, base=MGMT_BASE)

def _need_auth():
    return JSONResponse(status_code=401, content={"error": "Unauthorized"})

# ---- static assets / fonts / xterm (not session-gated) ----
_FONT_DIR = os.path.join(_PROJECT_DIR, "vendor", "fonts")
_FONT_FILES = {"notoserif.woff2": "font/woff2", "oxanium.woff2": "font/woff2"}
_XTERM_DIR = os.path.join(_PROJECT_DIR, "vendor", "xterm")
_XTERM_FILES = {"xterm.js": "application/javascript", "xterm.css": "text/css", "addon-fit.js": "application/javascript"}
_STATIC_FILES = {"dash.css": "text/css", "management.js": "application/javascript"}

@app.get("/static/{fname}")
async def serve_static(fname: str):
    ctype = _STATIC_FILES.get(fname)
    path = os.path.join(_STATIC_DIR, fname)
    if not ctype or not os.path.isfile(path):
        return JSONResponse(status_code=404, content={"error": "not found"})
    # no-cache, not no-store: a store-and-revalidate policy means every change
    # to the app's own js or css is picked up on the next visit, instead of a
    # cached copy from before a release silently pairing with new markup and
    # killing buttons. Without a Cache-Control at all, browsers heuristically
    # cache FileResponse assets for a slice of their file age, which can be
    # hours, and that stale js was once the entire panel's frontend.
    return FileResponse(path, media_type=ctype,
                        headers={"Cache-Control": "no-cache"})

@app.get("/assets/fonts/{fname}")
async def serve_font(fname: str):
    ctype = _FONT_FILES.get(fname)
    path = os.path.join(_FONT_DIR, fname)
    if not ctype or not os.path.isfile(path):
        return JSONResponse(status_code=404, content={"error": "not found"})
    return FileResponse(path, media_type=ctype)

@app.get("/assets/xterm/{fname}")
async def serve_xterm(fname: str):
    ctype = _XTERM_FILES.get(fname)
    path = os.path.join(_XTERM_DIR, fname)
    if not ctype or not os.path.isfile(path):
        return JSONResponse(status_code=404, content={"error": "not found"})
    return FileResponse(path, media_type=ctype)

# ---- auth ----
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _authed(request):
        return RedirectResponse(url=f"{MGMT_BASE}/", status_code=302)
    return HTMLResponse(content=_login_html())

_WRONG_CREDENTIALS = "Invalid username or password."

@app.post("/api/login")
async def do_login(request: Request):
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    fp_hash, device = web_guard.fingerprint(request)
    private = web_guard.is_private(ip)
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    # A blocked address or device gets the same answer as a wrong password.
    # Saying "you are blocked" would confirm the lockout exists, reveal how long
    # it lasts, and tell the caller that a different address gets further. The
    # attempt is still recorded, so the operator sees it even though the caller
    # learns nothing. A private address is blocked exactly like a public one.
    allowed, prior_fails, blocked_until = await DB.run(
        DB.check_web_login_allowed, ip, fp_hash)
    if not allowed:
        await DB.run(DB.log_web_login, ip, username, False, ua,
                     f"refused, already blocked until {blocked_until}",
                     fp_hash, device)
        write_log("WARN", "AUTH", "Login attempt from a blocked source",
                  actor=username or "?", ip=ip,
                  detail=f"{device}; {'private' if private else 'public'} address; "
                         f"blocked until {blocked_until}",
                  status="denied")
        return JSONResponse(status_code=401, content={"error": _WRONG_CREDENTIALS})

    try:
        ok = await DB.run(DB.verify_admin, username, password)
        if not ok:
            ok = await DB.run(_verify_staff_login, username, password)
    except Exception as e:
        logging.error(f"verify_admin failed: {e}")
        ok = False

    if not ok:
        await DB.run(DB.log_web_login, ip, username, False, ua,
                     "wrong username or password", fp_hash, device)
        fails = prior_fails + 1
        now_blocked = fails >= web_guard.FAIL_LIMIT
        write_log("WARN", "AUTH", "Failed login", actor=username or "?", ip=ip,
                  detail=(f"{device}; attempt {fails} of {web_guard.FAIL_LIMIT}"
                          + (f"; address and device blocked for "
                             f"{web_guard.BLOCK_HOURS}h" if now_blocked else "")),
                  status="denied")
        return JSONResponse(status_code=401, content={"error": _WRONG_CREDENTIALS})

    sid = secrets.token_hex(16)
    token = _create_session_token(username, sid=sid)
    await DB.run(DB.log_web_login, ip, username, True, ua, "", fp_hash, device)
    await DB.run(_record_session, sid, username, ip, ua)
    write_log("ACTION", "AUTH", "Login success", actor=username, ip=ip,
              detail=device)
    resp = JSONResponse(content={"status": "ok"})
    # Path-scoped to MGMT_BASE: MainApp serves its own "session" cookie on the
    # same domain now, so an unscoped cookie here would clobber that one.
    resp.set_cookie("session", token, httponly=True, max_age=SESSION_TTL, samesite="lax",
                    secure=_is_https(request), path=_COOKIE_PATH)
    return resp

def _record_session(sid, username, ip, ua):
    """Sessions has been an empty table since it was built, because nothing ever
    called the writer. A failure here must not cost the user their login."""
    try:
        expires = datetime.datetime.now() + datetime.timedelta(seconds=SESSION_TTL)
        DB.log_session_created(sid, username, ip, ua[:400], expires)
    except Exception as e:
        logging.warning(f"session log write failed: {e}")

def _end_session(sid, reason="logout"):
    try:
        DB.log_session_ended(sid, reason)
    except Exception as e:
        logging.warning(f"session log close failed: {e}")

@app.get("/logout")
async def logout(request: Request):
    if _authed(request):
        data = _get_token_data(request)
        write_log("ACTION", "AUTH", "Logout", actor=_admin_name(request), ip=_client_ip(request))
        if data and data.get("sid"):
            await DB.run(_end_session, data["sid"], "logout")
    resp = RedirectResponse(url=f"{MGMT_BASE}/login", status_code=302)
    resp.delete_cookie("session", path=_COOKIE_PATH)
    return resp

# ===========================================================================
# Account: change your own password, and single-use recovery codes
# ===========================================================================
async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}

def _set_admin_password(username: str, password: str) -> int:
    conn = DB.get_connection()          # autocommit
    try:
        cur = conn.cursor()
        cur.execute("UPDATE admin SET password_hash = %s WHERE username = %s",
                    (recovery.hash_password(password), username))
        changed = cur.rowcount
        cur.close()
        return changed
    finally:
        DB.release_connection(conn)

@app.get("/api/account/recovery-status")
async def api_recovery_status(request: Request):
    if not _authed(request):
        return _need_auth()
    # Recovery codes exist so the one irreplaceable account cannot be locked
    # out. A staff account is replaceable: the admin resets its password in
    # person, which is a stronger check than a code sitting in a text file.
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    username = _admin_name(request)

    def work():
        conn = DB.get_connection()
        try:
            recovery.ensure_table(conn)
            unused, total = recovery.remaining(conn, username)
            return unused, total, recovery.generated_at(conn, username)
        finally:
            DB.release_connection(conn)

    try:
        unused, total, made = await DB.run(work)
    except Exception as e:
        logging.error(f"recovery-status failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not read recovery codes."})
    return JSONResponse({"username": username, "unused": unused, "total": total,
                         "generated_at": made.isoformat() if made else None})

def _verify_own_password(username, password):
    """The current password, checked against whichever table this account is in.

    This used to ask the admin table and nothing else, so a staff member had a
    password form on their account page that could never succeed: their own
    password was compared against a row that does not exist.
    """
    conn = DB.get_connection()
    try:
        if panel_users.is_admin_username(conn, username):
            return "admin", DB.verify_admin(username, password)
        return "staff", bool(panel_users.verify_login(conn, username, password))
    finally:
        DB.release_connection(conn)

def _set_own_password(role, username, password):
    if role == "admin":
        return _set_admin_password(username, password)
    conn = DB.get_connection()
    try:
        return 1 if panel_users.update_user(conn, username, password=password) else 0
    finally:
        DB.release_connection(conn)

@app.post("/api/account/password")
async def api_account_password(request: Request):
    if not _authed(request):
        return _need_auth()
    username, ip = _admin_name(request), _client_ip(request)
    body = await _json_body(request)
    current = body.get("current_password") or ""
    new = body.get("new_password") or ""

    role, ok = await DB.run(_verify_own_password, username, current)
    if not ok:
        write_log("WARN", "AUTH", "Password change refused", actor=username, ip=ip,
                  detail="current password did not match", status="denied")
        return JSONResponse(status_code=403,
                            content={"error": "Your current password is not correct."})

    problem = recovery.password_problem(new, username)
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})
    if new == current:
        return JSONResponse(status_code=400,
                            content={"error": "The new password must be different from the current one."})

    try:
        if not await DB.run(_set_own_password, role, username, new):
            return JSONResponse(status_code=500, content={"error": "Could not update the password."})
        if role == "admin":
            # The global epoch signs out everybody, which is what the admin
            # changing their own password should do. A staff member changing
            # theirs must not, so their row's own epoch is bumped instead, which
            # update_user already did.
            await DB.run(_bump_auth_epoch)
        else:
            _forget_user_epoch(username)
    except Exception as e:
        logging.error(f"password change failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not update the password."})

    write_log("ACTION", "AUTH", "Password changed", actor=username, ip=ip,
              detail="every other session was signed out")
    # The epoch bump just invalidated this browser's cookie too, hand it a new
    # one so the person who made the change is not signed out by their own action.
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie("session", _create_session_token(username), httponly=True,
                    max_age=SESSION_TTL, samesite="lax", secure=_is_https(request),
                    path=_COOKIE_PATH)
    return resp

@app.post("/api/account/recovery-codes")
async def api_account_recovery_codes(request: Request):
    """Mint a new set. Re-authenticates first: this is a credential-issuing action."""
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    username, ip = _admin_name(request), _client_ip(request)
    body = await _json_body(request)

    if not await DB.run(DB.verify_admin, username, body.get("current_password") or ""):
        write_log("WARN", "SECURITY", "Recovery code regeneration refused", actor=username,
                  ip=ip, detail="current password did not match", status="denied")
        return JSONResponse(status_code=403,
                            content={"error": "Your current password is not correct."})

    codes = recovery.generate_codes()

    def work():
        conn = DB.get_connection()
        try:
            recovery.ensure_table(conn)
            recovery.replace_codes(conn, username, codes)
        finally:
            DB.release_connection(conn)

    try:
        await DB.run(work)
    except Exception as e:
        logging.error(f"recovery code regeneration failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not store the new codes."})

    path, file_error = None, None
    try:
        path = recovery.write_recovery_file(_PROJECT_DIR, username, codes)
    except OSError as e:
        file_error = str(e)
        logging.warning(f".recovery file not written: {e}")

    write_log("ACTION", "SECURITY", "Recovery codes regenerated", actor=username, ip=ip,
              detail=f"{len(codes)} new codes; all previous codes invalidated")
    return JSONResponse({"status": "ok", "path": path, "file_error": file_error,
                         "codes": [recovery.format_code(c) for c in codes]})

# ===========================================================================
# Identity: the name and the picture that go in front of a person
# ===========================================================================
def _identity_work(fn, *args):
    """Own connection, no commit here: the pool hands out autocommit
    connections, so the module's own conn.commit() calls are the no-ops they
    look like and a commit at this level would be one too."""
    conn = DB.get_connection()
    try:
        return fn(conn, *args)
    finally:
        DB.release_connection(conn)

def _identity_overview(username, role):
    conn = DB.get_connection()
    try:
        me = identity.get(conn, username)
        me["role"] = role
        me["role_label"] = "Administrator" if role == "admin" else "Staff account"
        # Recovery codes are the admin's alone, so the page must be told that
        # rather than guessing from the role name.
        me["has_recovery"] = role == "admin"
        me["max_upload_kb"] = identity.MAX_UPLOAD // 1024
        kind, data, _digest = identity.avatar(conn, username)
        me["bimi"] = ("" if not kind else identity.bimi_problem(kind, data or b""))
        me["mail_domain"] = (mail.config(conn) or {}).get("domain", "")
        return me
    finally:
        DB.release_connection(conn)

@app.get("/api/account/identity")
async def api_identity_get(request: Request):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username = _admin_name(request)
    try:
        return JSONResponse(await DB.run(_identity_overview, username, perms.get("role")))
    except Exception as e:
        logging.error(f"identity read failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not read your account."})

@app.post("/api/account/name")
async def api_identity_name(request: Request):
    """Your own display name. Nobody sets anybody else's here: an admin editing
    a staff member does it through the staff form, which writes the same row."""
    if not _authed(request):
        return _need_auth()
    username = _admin_name(request)
    body = await _json_body(request)
    problem = identity.name_problem(body.get("full_name"))
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})
    try:
        ok, name = await DB.run(_identity_work, identity.set_full_name,
                                username, body.get("full_name"))
    except Exception as e:
        logging.error(f"name change failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not save that name."})
    if not ok:
        return JSONResponse(status_code=400, content={"error": name})
    write_log("ACTION", "SETTINGS", "Display name changed", actor=username,
              ip=_client_ip(request), detail=f"now shown as {name}")
    return {"status": "ok", "full_name": name}

@app.post("/api/account/avatar")
async def api_identity_avatar_set(request: Request):
    """The picture, posted as the raw file rather than a multipart form.

    One less parser in the request path, and it makes no difference to what is
    trusted: the bytes decide what the file is, never the content type the
    browser attached and never the name it came with.
    """
    if not _authed(request):
        return _need_auth()
    username = _admin_name(request)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > identity.MAX_UPLOAD:
        return JSONResponse(status_code=413, content={
            "error": f"Use a file under {identity.MAX_UPLOAD // 1024} KB."})
    raw = await request.body()
    if len(raw) > identity.MAX_UPLOAD:
        return JSONResponse(status_code=413, content={
            "error": f"Use a file under {identity.MAX_UPLOAD // 1024} KB."})
    try:
        ok, detail = await DB.run(_identity_work, identity.set_avatar, username, raw)
    except Exception as e:
        logging.error(f"avatar upload failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not store that picture."})
    if not ok:
        write_log("WARN", "SETTINGS", "Picture refused", actor=username,
                  ip=_client_ip(request), detail=detail, status="denied")
        return JSONResponse(status_code=400, content={"error": detail})
    write_log("ACTION", "SETTINGS", "Picture changed", actor=username,
              ip=_client_ip(request), detail=f"{detail}, {len(raw)} bytes uploaded")
    return {"status": "ok", "kind": detail}

@app.delete("/api/account/avatar")
async def api_identity_avatar_clear(request: Request):
    if not _authed(request):
        return _need_auth()
    username = _admin_name(request)
    try:
        await DB.run(_identity_work, identity.clear_avatar, username)
    except Exception as e:
        logging.error(f"avatar removal failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not remove it."})
    write_log("ACTION", "SETTINGS", "Picture removed", actor=username, ip=_client_ip(request))
    return {"status": "ok"}

def _avatar_response(kind, data, digest, request):
    """An avatar served so that it cannot become a document.

    An SVG rendered in an <img> already cannot run script, and the panel only
    ever renders them that way. This is the second lock: opened directly in a
    tab, the CSP leaves it nothing it is allowed to do, and nosniff stops the
    browser deciding the bytes are really HTML.
    """
    if request.headers.get("if-none-match") == f'"{digest}"':
        return Response(status_code=304)
    return Response(content=data, media_type=identity.MIME[kind], headers={
        "Cache-Control": "private, max-age=0, must-revalidate",
        "ETag": f'"{digest}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
        "Content-Disposition": f'inline; filename="avatar.{kind}"',
    })

@app.get("/api/account/avatar/{username}")
async def api_identity_avatar_get(request: Request, username: str):
    """Anybody signed in may see anybody's picture: it appears beside their name
    on every message they send, so hiding it from colleagues would be theatre."""
    if not _authed(request):
        return _need_auth()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", username or ""):
        return JSONResponse(status_code=400, content={"error": "Bad name."})
    try:
        kind, data, digest = await DB.run(_identity_work, identity.avatar, username)
    except Exception as e:
        logging.error(f"avatar read failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not read it."})
    if not kind:
        return JSONResponse(status_code=404, content={"error": "No picture."})
    return _avatar_response(kind, data, digest, request)

def _bimi_logo(username):
    conn = DB.get_connection()
    try:
        # Only an address on the configured mail domain gets a published logo:
        # BIMI exists to be fetched by strangers, so it is offered for exactly
        # the accounts that send mail and no others.
        if not mail.boxes(conn, owner=username):
            return None, "", ""
        kind, data, digest = identity.avatar(conn, username)
        if not kind or identity.bimi_problem(kind, data or b""):
            return None, "", ""
        return identity.bimi_svg(data, identity.display_name(conn, username)), digest, "svg"
    finally:
        DB.release_connection(conn)

@app.get("/bimi/{username}.svg")
async def api_bimi_logo(request: Request, username: str):
    """Deliberately open, because a receiving mail server fetches this with no
    session and no way to get one. It is one sanitized SVG per account that
    already publishes an address, and nothing else is reachable from here."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", username or ""):
        return JSONResponse(status_code=400, content={"error": "Bad name."})
    try:
        data, digest, _kind = await DB.run(_bimi_logo, username)
    except Exception as e:
        logging.error(f"bimi read failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not read it."})
    if not data:
        return JSONResponse(status_code=404, content={"error": "No logo published."})
    return Response(content=data, media_type="image/svg+xml", headers={
        "Cache-Control": "public, max-age=3600",
        "ETag": f'"{digest}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    })

# ===========================================================================
# The mark in the tab: the Argus Recon icon, shipped with the panel
# ===========================================================================
@app.get("/favicon.ico")
async def api_favicon(request: Request):
    """No session needed. A browser asks for this before it has one, and it is
    the panel's own badge, not anybody's data."""
    kind, data, digest = branding.get()
    if request.headers.get("if-none-match") == f'"{digest}"':
        return Response(status_code=304)
    return Response(content=data, media_type=identity.MIME[kind], headers={
        "Cache-Control": "public, max-age=86400",
        "ETag": f'"{digest}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    })

# --- unauthenticated recovery ----------------------------------------------- #
# The only route that changes a password without a session, so it is throttled
# per-IP and globally. The code space is 10^12 with five live codes, so guessing
# is already hopeless; this exists to make a sustained attempt loud and cheap to
# survive rather than to be the only thing standing in the way.
_RECOVER_WINDOW = 900          # 15 minutes
_RECOVER_MAX_PER_IP = 5
_RECOVER_MAX_GLOBAL = 20
_recover_fails = {}            # ip -> [monotonic timestamps]

def _recover_prune(now):
    for addr in list(_recover_fails):
        kept = [t for t in _recover_fails[addr] if now - t < _RECOVER_WINDOW]
        if kept:
            _recover_fails[addr] = kept
        else:
            _recover_fails.pop(addr, None)

def _recover_blocked(ip: str) -> bool:
    now = time.time()
    _recover_prune(now)
    if len(_recover_fails.get(ip, ())) >= _RECOVER_MAX_PER_IP:
        return True
    return sum(len(v) for v in _recover_fails.values()) >= _RECOVER_MAX_GLOBAL

def _recover_note_fail(ip: str):
    _recover_fails.setdefault(ip, []).append(time.time())

@app.post("/api/recover")
async def api_recover(request: Request):
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    body = await _json_body(request)
    username = (body.get("username") or "").strip()
    code = recovery.normalize_code(body.get("code") or "")
    new = body.get("new_password") or ""

    if _recover_blocked(ip):
        write_log("WARN", "SECURITY", "Account recovery rate-limited",
                  actor=username or "?", ip=ip, detail=f"ua={ua[:120]}", status="denied")
        return JSONResponse(status_code=429,
                            content={"error": "Too many attempts. Wait 15 minutes and try again."})

    problem = recovery.password_problem(new, username)
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})

    def work():
        conn = DB.get_connection()
        try:
            recovery.ensure_table(conn)
            if not _admin_exists_conn(conn, username):
                recovery.burn_time()        # same cost as a wrong code
                return False, 0
            if not recovery.consume_code(conn, username, code, ip):
                return False, 0
            cur = conn.cursor()
            cur.execute("UPDATE admin SET password_hash = %s WHERE username = %s",
                        (recovery.hash_password(new), username))
            cur.close()
            unused, _total = recovery.remaining(conn, username)
            return True, unused
        finally:
            DB.release_connection(conn)

    try:
        accepted, left = await DB.run(work)
    except Exception as e:
        logging.error(f"recovery failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Recovery is unavailable right now."})

    if not accepted:
        _recover_note_fail(ip)
        write_log("WARN", "SECURITY", "Recovery code rejected", actor=username or "?",
                  ip=ip, detail=f"ua={ua[:120]}", status="denied")
        # One message for every failure mode: no account enumeration.
        return JSONResponse(status_code=403,
                            content={"error": "That username and recovery code do not match."})

    try:
        await DB.run(_bump_auth_epoch)      # evict anyone already signed in
    except Exception as e:
        logging.error(f"epoch bump after recovery failed: {e}")

    write_log("ACTION", "SECURITY", "Password reset with a recovery code", actor=username,
              ip=ip, detail=f"{left} code(s) remaining; all sessions signed out")
    return JSONResponse({"status": "ok", "remaining": left})

def _admin_exists_conn(conn, username: str) -> bool:
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM admin WHERE username = %s", (username,))
        return cur.fetchone() is not None
    finally:
        cur.close()

# ---- staff accounts (panel_user) and permission resolution ----
def _verify_staff_login(username: str, password: str) -> bool:
    conn = DB.get_connection()
    try:
        return panel_users.verify_login(conn, username, password) is not None
    finally:
        DB.release_connection(conn)

def _resolve_permissions(username: str) -> dict:
    conn = DB.get_connection()
    try:
        return panel_users.resolve_permissions(conn, username)
    finally:
        DB.release_connection(conn)

async def _current_permissions(request: Request) -> dict:
    username = _admin_name(request)
    if not username:
        return panel_users.no_permissions()
    return await DB.run(_resolve_permissions, username)

async def _require(request: Request, check):
    """check(perms) -> bool. Returns (perms, None) if allowed, or
    (None, JSONResponse 403) if not. Always call _authed() first."""
    perms = await _current_permissions(request)
    if not check(perms):
        return None, JSONResponse(status_code=403, content={"error": "Not permitted."})
    return perms, None

def _is_admin(perms):
    return perms.get("role") == "admin"

def _grant(key):
    """A _require check for one named grant from the registry.

    The admin resolves to every grant at its widest, so there is deliberately
    no "or is admin" escape hatch here. One grant, one check, and the form the
    admin sees is generated from the same registry these keys come from.
    """
    return lambda p: bool(p.get(key))

def _can_browse(perms):
    return perms.get("disk_scope", "none") != "none"

def _disk_root(perms):
    """The prefix every requested path must resolve inside, or None when the
    caller may see the whole filesystem.

    A staff member scoped to their own files but with no system account has
    nothing legitimate to browse, so they get a path that cannot exist rather
    than an accidental view of /.
    """
    if perms.get("disk_scope") != panel_users.DISK_OWN:
        return None
    os_username = perms.get("os_username")
    return f"/home/{os_username}" if os_username else "/nonexistent-no-home"

# ---- dashboard ----
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _authed(request):
        return RedirectResponse(url=f"{MGMT_BASE}/login", status_code=302)
    perms = await _current_permissions(request)
    username = _admin_name(request) or "admin"
    try:
        me = await DB.run(_identity_work, identity.get, username)
    except Exception as e:
        logging.warning(f"identity read failed, falling back to the account name: {e}")
        me = None
    return HTMLResponse(content=_dashboard_html(_is_mobile(request), username, perms, me))

# ---- server status (System.py) ----
@app.get("/api/system/static")
async def api_static(request: Request):
    if not _authed(request):
        return _need_auth()
    try:
        return System.static_info()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/stats")
async def api_stats(request: Request):
    if not _authed(request):
        return _need_auth()
    try:
        return System.live_stats()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/processes")
async def api_processes(request: Request, by: str = "cpu"):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("cpumem_detail"))
    if denied:
        return denied
    try:
        return await DB.run(System.top_processes, "mem" if by == "mem" else "cpu")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/connections")
async def api_connections(request: Request, established: int = 0):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_detail"))
    if denied:
        return denied
    try:
        return await DB.run(System.net_connections, established_only=bool(established))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/files")
async def api_files(request: Request, path: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _can_browse)
    if denied:
        return denied
    root = _disk_root(perms)
    if root and not os.path.isdir(root):
        # Scoped to their own files, with no directory to scope to. Saying so is
        # better than the browser reporting that a path is not a directory.
        return {"error": "There is no home directory for this account on this "
                         "server yet, so there is nothing to browse.",
                "path": "", "parent": None, "entries": []}
    try:
        return await DB.run(System.list_dir, path or None, root)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/download")
async def api_download(request: Request, path: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, lambda p: _can_browse(p) and p.get("disk_download"))
    if denied:
        return denied
    full, reason = System.resolve_download(path, root=_disk_root(perms))
    if reason == "not_found":
        return JSONResponse(status_code=404, content={"error": "not found"})
    if reason == "blocked":
        return JSONResponse(status_code=403, content={"error": "download blocked"})
    write_log("ACTION", "SYSTEM", "File download", actor=_admin_name(request),
              ip=_client_ip(request), target=full[:200])
    return FileResponse(full, filename=os.path.basename(full), media_type="application/octet-stream")

@app.delete("/api/system/delete")
async def api_delete_file(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, lambda p: _can_browse(p) and p.get("disk_delete"))
    if denied:
        return denied
    body = await _json_body(request)
    path = body.get("path") or ""
    ok, reason = await DB.run(System.delete_file, path, _disk_root(perms))
    if not ok:
        code = 404 if reason == "not_found" else 400 if reason == "is_directory" else 403 if reason == "blocked" else 500
        return JSONResponse(status_code=code, content={"error": reason or "delete failed"})
    write_log("ACTION", "SYSTEM", "File deleted", actor=_admin_name(request),
              ip=_client_ip(request), target=path[:200])
    return {"status": "ok"}

_UPLOAD_ERRORS = {
    "blocked": "Uploads are not allowed in that folder.",
    "not_a_directory": "That is not a folder.",
    "bad_name": "That file name is not allowed.",
    "name_too_long": "That file name is too long.",
    "exists": "A file with that name already exists in this folder.",
    "no_owner": "The system account for this folder no longer exists.",
}

def _upload_limit_text():
    limit = System.MAX_UPLOAD_BYTES
    if limit and limit % (1024 ** 3) == 0:
        return f"{limit // (1024 ** 3)} GB"
    return f"{max(1, limit // (1024 ** 2))} MB"

@app.post("/api/system/upload")
async def api_upload_file(request: Request, path: str = "", name: str = ""):
    """Stream one file from the browser into the folder being browsed.

    The name and folder arrive as query parameters and the file is the raw
    request body, the same shape the avatar upload uses, so no multipart parser
    sits in the request path. Nothing is written under the real name until the
    whole body has arrived, and an existing name is never replaced.
    """
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(
        request, lambda p: _can_browse(p) and p.get("disk_upload"))
    if denied:
        return denied
    root = _disk_root(perms)
    directory, dest, reason = System.resolve_upload(
        path, name, root, staff=perms.get("role") != "admin")
    if reason:
        code = 409 if reason == "exists" else 403 if reason == "blocked" else 400
        return JSONResponse(status_code=code, content={
            "error": _UPLOAD_ERRORS.get(reason, "Upload refused.")})

    limit = System.MAX_UPLOAD_BYTES
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return JSONResponse(status_code=413, content={
            "error": f"Use a file under {_upload_limit_text()}."})

    try:
        fd, temp_path = tempfile.mkstemp(prefix=".argus-upload-", dir=directory)
    except OSError as e:
        logging.error(f"could not create an upload staging file: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not save the upload."})

    total = 0
    too_large = False
    try:
        with os.fdopen(fd, "wb") as out:
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > limit:
                    too_large = True
                    break
                out.write(chunk)
        if too_large:
            return JSONResponse(status_code=413, content={
                "error": f"Use a file under {_upload_limit_text()}."})
        owner = (perms.get("os_username")
                 if perms.get("disk_scope") == panel_users.DISK_OWN else None)
        ok, detail = await DB.run(System.finish_upload, temp_path, dest, owner)
        if not ok:
            code = 409 if detail == "exists" else 403 if detail == "blocked" else 500
            return JSONResponse(status_code=code, content={
                "error": _UPLOAD_ERRORS.get(detail, "Could not save the upload.")})
    except Exception as e:
        logging.error(f"upload failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not save the upload."})
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
    write_log("ACTION", "SYSTEM", "File uploaded", actor=_admin_name(request),
              ip=_client_ip(request), target=dest[:200], detail=f"{total} bytes")
    return {"status": "ok", "name": name, "path": dest, "size": total}

# ---- management bind config ----
@app.get("/api/system/config")
async def api_config_get(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    return mgmt_config_view()

@app.post("/api/system/config")
async def api_config_set(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    try:
        host, port = await DB.run(set_mgmt_config, body.get("host"), body.get("port"))
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    needs_restart = (host != SERVER_RUNTIME["host"] or port != SERVER_RUNTIME["port"])
    write_log("ACTION", "SYSTEM", "Saved launch config", actor=_admin_name(request),
              ip=_client_ip(request), target=f"{host}:{port}")
    return {"status": "ok", "host": host, "port": port, "needs_restart": needs_restart}

# ---- services ----
@app.get("/api/services")
async def api_services(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("svc_status"))
    if denied:
        return denied
    return await DB.run(list_services)

@app.get("/api/services/{name}")
async def api_service_detail(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("svc_status"))
    if denied:
        return denied
    return await DB.run(service_detail, name)

# Bringing a service up and taking one down are separately granted: a staff
# member who may restart a wedged service is not automatically trusted to stop
# it. Anything not in this map is refused before it reaches systemctl.
_SERVICE_ACTION_GRANT = {
    "start": "svc_restart", "restart": "svc_restart", "reload": "svc_restart",
    "stop": "svc_stop",
}

@app.post("/api/services/{name}/{action}")
async def api_service_action(request: Request, name: str, action: str):
    if not _authed(request):
        return _need_auth()
    needed = _SERVICE_ACTION_GRANT.get(action)
    if not needed:
        return JSONResponse(status_code=400, content={"error": "Unsupported action."})
    perms, denied = await _require(request, _grant(needed))
    if denied:
        return denied
    ok, message = await DB.run(control_service, name, action)
    write_log("ACTION" if ok else "ERROR", "SERVICE", f"{action} service",
              actor=_admin_name(request), ip=_client_ip(request), target=name,
              detail=message[:1000], status="ok" if ok else "failed")
    return {"ok": ok, "message": message}

# ---- Config: SSH access settings (admin only) ----
def _ssh_status_data():
    conn = DB.get_connection()
    try:
        rec = ssh_vault.get_record(conn)
    finally:
        DB.release_connection(conn)
    return {
        "sshd_running": ssh_vault.sshd_running(),
        "key_exists": ssh_vault.key_files_exist(),
        "public_key": (rec or {}).get("public_key", ""),
        "fingerprint": (rec or {}).get("fingerprint", ""),
        "password_saved": bool((rec or {}).get("password")),
        "allow_password_login": ssh_vault.password_login_allowed(),
        "generated_at": (rec or {}).get("generated_at"),
    }

@app.get("/api/config/ssh/status")
async def api_ssh_status(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    return await DB.run(_ssh_status_data)

def _ssh_generate(password):
    ssh_vault.ensure_sshd_running()
    public_key, private_key, fingerprint, report = ssh_vault.generate_keypair()
    conn = DB.get_connection()
    try:
        allow = ssh_vault.password_login_allowed()
        ssh_vault.save_record(conn, public_key, private_key, password, fingerprint, allow)
    finally:
        DB.release_connection(conn)
    # The report travels to the browser. Generating a key that was never
    # installed or never tried used to look identical to one that works.
    return {"public_key": public_key, "fingerprint": fingerprint,
            "installed": report["installed"], "verified": report["verified"],
            "verify_detail": report["verify_detail"],
            "steps": report["steps"], "problems": report["problems"]}

@app.post("/api/config/ssh/generate")
async def api_ssh_generate(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    try:
        result = await DB.run(_ssh_generate, body.get("password") or "")
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    write_log("ACTION", "SECURITY", "Generated SSH keypair", actor=_admin_name(request), ip=_client_ip(request))
    return {"status": "ok", **result}

def _ssh_save_password(password):
    conn = DB.get_connection()
    try:
        ssh_vault.ensure_table(conn)
        rec = ssh_vault.get_record(conn)
        if rec is None:
            return False
        ssh_vault.update_password(conn, password)
        return True
    finally:
        DB.release_connection(conn)

@app.post("/api/config/ssh/password")
async def api_ssh_password(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    saved = await DB.run(_ssh_save_password, body.get("password") or "")
    if not saved:
        return JSONResponse(status_code=400, content={"error": "Generate a key first."})
    write_log("ACTION", "SECURITY", "Saved SSH reference password", actor=_admin_name(request), ip=_client_ip(request))
    return {"status": "ok"}

def _ssh_set_login_mode(allow):
    ok, message = ssh_vault.set_password_login(allow)
    if ok:
        conn = DB.get_connection()
        try:
            rec = ssh_vault.get_record(conn)
            if rec is not None:
                cur = conn.cursor()
                cur.execute("UPDATE ssh SET allow_password_login = %s, updated_at = CURRENT_TIMESTAMP", (allow,))
                conn.commit()
                cur.close()
        finally:
            DB.release_connection(conn)
    return ok, message

@app.post("/api/config/ssh/login-mode")
async def api_ssh_login_mode(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    allow = bool(body.get("allow_password_login"))
    ok, message = await DB.run(_ssh_set_login_mode, allow)
    write_log("ACTION" if ok else "ERROR", "SECURITY", "SSH login mode",
              actor=_admin_name(request), ip=_client_ip(request),
              detail=("password allowed" if allow else "key only") + ": " + message,
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=500, content={"error": message})
    return {"status": "ok", "message": message}

def _ssh_private_key():
    conn = DB.get_connection()
    try:
        rec = ssh_vault.get_record(conn)
    finally:
        DB.release_connection(conn)
    return (rec or {}).get("private_key", "")

@app.get("/api/config/ssh/private-key")
async def api_ssh_private_key(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    key = await DB.run(_ssh_private_key)
    if not key:
        return JSONResponse(status_code=404, content={"error": "No key generated yet."})
    write_log("ACTION", "SECURITY", "Downloaded SSH private key", actor=_admin_name(request), ip=_client_ip(request))
    return Response(content=key, media_type="application/x-pem-file",
                     headers={"Content-Disposition": "attachment; filename=id_ed25519"})

# ---- Config: User Management (admin only) ----
# Usernames end up in a derived system account name and in every audit row, so
# they are restricted to characters that are unambiguous in both places.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

def _list_panel_users():
    conn = DB.get_connection()
    try:
        return panel_users.list_users(conn)
    finally:
        DB.release_connection(conn)

@app.get("/api/config/users")
async def api_users_list(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    return {"users": await DB.run(_list_panel_users)}

@app.get("/api/config/grants")
async def api_grants_registry(request: Request):
    """The grant registry, so the admin form is generated from the same
    definition the enforcement reads. Any signed-in user may read it: it is a
    description of the permission vocabulary, not of anybody's permissions."""
    if not _authed(request):
        return _need_auth()
    return {"groups": panel_users.grant_groups(), "grants": panel_users.describe_grants()}

def _create_panel_user(username, password, grants, created_by):
    conn = DB.get_connection()
    try:
        return panel_users.create_user(conn, username, password, grants, created_by)
    finally:
        DB.release_connection(conn)

def _grant_summary(grants):
    """A short, readable record of a grant set for the audit trail."""
    on = [k for k in panel_users.GRANT_KEYS
          if k not in panel_users.CHOICE_KEYS and grants.get(k)]
    choices = [f"{k}={grants.get(k)}" for k in sorted(panel_users.CHOICE_KEYS)]
    return ", ".join(choices + sorted(on)) or "no grants"

@app.post("/api/config/users")
async def api_users_create(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or len(username) > 100:
        return JSONResponse(status_code=400, content={"error": "Enter a username."})
    if not _USERNAME_RE.match(username):
        return JSONResponse(status_code=400, content={
            "error": "Usernames may use letters, digits, dot, dash and underscore only."})
    problem = recovery.password_problem(password, username)
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})
    # normalize_grants is the only thing that decides what a grant payload
    # means, so an unknown or malformed key can only ever narrow the request.
    grants = panel_users.normalize_grants(body.get("grants"))
    try:
        os_username = await DB.run(_create_panel_user, username, password, grants,
                                    _admin_name(request))
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    except Exception as e:
        msg = "That username is already taken." if "unique" in str(e).lower() else "Could not create the user."
        return JSONResponse(status_code=400, content={"error": msg})
    write_log("ACTION", "SECURITY", "Created panel user", actor=_admin_name(request),
              ip=_client_ip(request), target=username, detail=_grant_summary(grants))
    return {"status": "ok", "os_username": os_username}

def _update_panel_user(username, **fields):
    conn = DB.get_connection()
    try:
        ok = panel_users.update_user(conn, username, **fields)
        # A name the admin sets here is the same name the person sees on their own
        # account page and the same one that goes on their mail, so it is written
        # to the identity row too rather than left to disagree with it.
        if ok and fields.get("full_name") and not identity.name_problem(fields["full_name"]):
            identity.set_full_name(conn, username, fields["full_name"])
        return ok
    finally:
        DB.release_connection(conn)

@app.post("/api/config/users/{username}")
async def api_users_update(request: Request, username: str):
    """Edit one staff account: their grants, their password, their display
    name. Username is deliberately not editable, the system account and the
    whole audit trail are keyed on it."""
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    fields, notes = {}, []

    if "grants" in body:
        fields["grants"] = panel_users.normalize_grants(body.get("grants"))
        notes.append(_grant_summary(fields["grants"]))
    if body.get("password"):
        problem = recovery.password_problem(body["password"], username)
        if problem:
            return JSONResponse(status_code=400, content={"error": problem})
        fields["password"] = body["password"]
        notes.append("password reset")
    if "full_name" in body:
        fields["full_name"] = str(body.get("full_name") or "")
        notes.append("name changed")

    if not fields:
        return JSONResponse(status_code=400, content={"error": "Nothing to change."})
    try:
        ok = await DB.run(_update_panel_user, username, **fields)
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    if not ok:
        return JSONResponse(status_code=404, content={"error": "No such user."})
    # Drop the cached epoch so a reset or a narrowed grant set takes hold on the
    # target's very next request rather than up to ten seconds later.
    _forget_user_epoch(username)
    write_log("ACTION", "SECURITY", "Updated panel user", actor=_admin_name(request),
              ip=_client_ip(request), target=username, detail="; ".join(notes))
    return {"status": "ok"}

def _delete_panel_user(username):
    conn = DB.get_connection()
    try:
        return panel_users.delete_user(conn, username)
    finally:
        DB.release_connection(conn)

@app.delete("/api/config/users/{username}")
async def api_users_delete(request: Request, username: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    ok = await DB.run(_delete_panel_user, username)
    if not ok:
        return JSONResponse(status_code=404, content={"error": "No such user."})
    write_log("ACTION", "SECURITY", "Deleted panel user", actor=_admin_name(request),
              ip=_client_ip(request), target=username)
    return {"status": "ok"}

# ---- Config: Database viewer/editor (panel's own tables only) ----
_DB_SCHEMA_TABLES = ("admin", "admin_recovery_code", "system_settings",
                      "management_log", "admin_action", "ssh_log", "web_login_log",
                      "web_fp_block", "web_login_block", "web_session_log",
                      "http_access_log", "ssh", "panel_user")
_DB_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]{0,58}$")
_DB_COLUMN_TYPES = ("TEXT", "INTEGER", "BIGINT", "BOOLEAN", "TIMESTAMPTZ", "NUMERIC", "DATE")

def _db_tables_present():
    return [t for t in _DB_SCHEMA_TABLES if t in set(DB.get_table_list())]

@app.get("/api/config/db/tables")
async def api_db_tables(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_read"))
    if denied:
        return denied
    return {"tables": await DB.run(_db_tables_present), "write": perms.get("role") == "admin"}

def _db_table_page(name, page):
    data = DB.get_table_page(name, page, rows_per_page=25)
    data["total"] = DB.get_table_count(name)
    return data

@app.get("/api/config/db/table/{name}")
async def api_db_table(request: Request, name: str, page: int = 1):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_read"))
    if denied:
        return denied
    if name not in _DB_SCHEMA_TABLES:
        return JSONResponse(status_code=404, content={"error": "No such table."})
    try:
        data = await DB.run(_db_table_page, name, max(1, page))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    data["page"] = max(1, page)
    return data

def _db_insert_row(name, values):
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cols = [c for c in values.keys() if _DB_IDENT_RE.match(c)]
        query = pg_sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            pg_sql.Identifier(name),
            pg_sql.SQL(", ").join(pg_sql.Identifier(c) for c in cols),
            pg_sql.SQL(", ").join(pg_sql.Placeholder() for _ in cols),
        )
        cur.execute(query, [values[c] for c in cols])
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)

def _db_update_row(name, pk_column, pk_value, values):
    if not _DB_IDENT_RE.match(pk_column):
        raise ValueError("bad primary key column")
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cols = [c for c in values.keys() if _DB_IDENT_RE.match(c)]
        assignments = pg_sql.SQL(", ").join(
            pg_sql.SQL("{} = {}").format(pg_sql.Identifier(c), pg_sql.Placeholder()) for c in cols
        )
        query = pg_sql.SQL("UPDATE {} SET {} WHERE {} = %s").format(
            pg_sql.Identifier(name), assignments, pg_sql.Identifier(pk_column)
        )
        cur.execute(query, [values[c] for c in cols] + [pk_value])
        changed = cur.rowcount
        conn.commit()
        cur.close()
        return changed
    finally:
        DB.release_connection(conn)

def _db_delete_row(name, pk_column, pk_value):
    if not _DB_IDENT_RE.match(pk_column):
        raise ValueError("bad primary key column")
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        query = pg_sql.SQL("DELETE FROM {} WHERE {} = %s").format(
            pg_sql.Identifier(name), pg_sql.Identifier(pk_column)
        )
        cur.execute(query, (pk_value,))
        changed = cur.rowcount
        conn.commit()
        cur.close()
        return changed
    finally:
        DB.release_connection(conn)

def _db_add_column(name, col_name, col_type):
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        query = pg_sql.SQL("ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} " + col_type).format(
            pg_sql.Identifier(name), pg_sql.Identifier(col_name)
        )
        cur.execute(query)
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)

@app.post("/api/config/db/table/{name}/row")
async def api_db_row_insert(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_write"))
    if denied:
        return denied
    if name not in _DB_SCHEMA_TABLES:
        return JSONResponse(status_code=404, content={"error": "No such table."})
    body = await _json_body(request)
    values = body.get("values") or {}
    try:
        await DB.run(_db_insert_row, name, values)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)[:300]})
    write_log("ACTION", "SECURITY", "Inserted database row", actor=_admin_name(request),
              ip=_client_ip(request), target=name)
    return {"status": "ok"}

@app.put("/api/config/db/table/{name}/row")
async def api_db_row_update(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_write"))
    if denied:
        return denied
    if name not in _DB_SCHEMA_TABLES:
        return JSONResponse(status_code=404, content={"error": "No such table."})
    body = await _json_body(request)
    pk_column, pk_value = body.get("pk_column"), body.get("pk_value")
    values = body.get("values") or {}
    if not pk_column or pk_value is None:
        return JSONResponse(status_code=400, content={"error": "Missing primary key."})
    try:
        changed = await DB.run(_db_update_row, name, pk_column, pk_value, values)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)[:300]})
    write_log("ACTION", "SECURITY", "Updated database row", actor=_admin_name(request),
              ip=_client_ip(request), target=f"{name}:{pk_value}")
    return {"status": "ok", "changed": changed}

@app.delete("/api/config/db/table/{name}/row")
async def api_db_row_delete(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_write"))
    if denied:
        return denied
    if name not in _DB_SCHEMA_TABLES:
        return JSONResponse(status_code=404, content={"error": "No such table."})
    body = await _json_body(request)
    pk_column, pk_value = body.get("pk_column"), body.get("pk_value")
    if not pk_column or pk_value is None:
        return JSONResponse(status_code=400, content={"error": "Missing primary key."})
    try:
        changed = await DB.run(_db_delete_row, name, pk_column, pk_value)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)[:300]})
    write_log("ACTION", "SECURITY", "Deleted database row", actor=_admin_name(request),
              ip=_client_ip(request), target=f"{name}:{pk_value}")
    return {"status": "ok", "changed": changed}

@app.post("/api/config/db/table/{name}/column")
async def api_db_add_column(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("db_write"))
    if denied:
        return denied
    if name not in _DB_SCHEMA_TABLES:
        return JSONResponse(status_code=404, content={"error": "No such table."})
    body = await _json_body(request)
    col_name = (body.get("name") or "").strip().lower()
    col_type = (body.get("type") or "").strip().upper()
    if not _DB_IDENT_RE.match(col_name):
        return JSONResponse(status_code=400, content={"error": "Bad column name."})
    if col_type not in _DB_COLUMN_TYPES:
        return JSONResponse(status_code=400, content={"error": "Unsupported column type."})
    try:
        await DB.run(_db_add_column, name, col_name, col_type)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)[:300]})
    write_log("ACTION", "SECURITY", "Added database column", actor=_admin_name(request),
              ip=_client_ip(request), target=f"{name}.{col_name}", detail=col_type)
    return {"status": "ok"}

# ---- Config: Proxy (nginx reverse proxy hosts) ----
def _proxy_spec_from_body(body):
    """Only the fields the renderer knows about, so a caller cannot smuggle
    extra keys into a stored spec."""
    spec = {
        "domain": body.get("domain"),
        "listen_scheme": body.get("listen_scheme"),
        "listen_port": body.get("listen_port"),
        "forward_scheme": body.get("forward_scheme"),
        "forward_host": body.get("forward_host"),
        "forward_port": body.get("forward_port"),
        "cert_path": body.get("cert_path"),
        "cert_key_path": body.get("cert_key_path"),
        "locations": [],
    }
    for flag in nginx_proxy.TLS_FLAGS + nginx_proxy.BEHAVIOUR_FLAGS:
        spec[flag] = bool(body.get(flag))
    for loc in (body.get("locations") or [])[:40]:
        if not isinstance(loc, dict):
            continue
        entry = {
            "path": loc.get("path"),
            "forward_scheme": loc.get("forward_scheme"),
            "forward_host": loc.get("forward_host"),
            "forward_port": loc.get("forward_port"),
        }
        for flag in nginx_proxy.BEHAVIOUR_FLAGS:
            entry[flag] = bool(loc.get(flag))
        spec["locations"].append(entry)
    return spec

def _proxy_port_for_firewall(spec):
    """The port the outside world connects to, which is the one the firewall
    has to let in. A web host honours its listen port when one was set, and
    a certless HTTPS host is served as plain HTTP, so it listens on 80."""
    scheme = spec.get("listen_scheme")
    if scheme in ("tcp", "udp"):
        return int(spec.get("listen_port") or 0)
    port = 80
    if scheme == "https":
        cert = (spec.get("cert_path") or "").strip()
        key = (spec.get("cert_key_path") or "").strip()
        if cert and key:
            port = 443
    try:
        custom = int(spec.get("listen_port"))
    except (TypeError, ValueError):
        custom = 0
    return custom if 1 <= custom <= 65535 else port

@app.get("/api/config/proxy/hosts")
async def api_proxy_list(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    return {"installed": nginx_proxy.nginx_installed(),
            "stream_supported": nginx_proxy.stream_supported(),
            "stream_problem": nginx_proxy.stream_problem(),
            "hosts": await DB.run(nginx_proxy.list_hosts)}

@app.post("/api/config/proxy/hosts")
async def api_proxy_create(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    spec = _proxy_spec_from_body(await _json_body(request))
    try:
        result = await DB.run(nginx_proxy.create_host, spec)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    stored = result["spec"]
    opened = await _open_proxy_port(request, stored)
    write_log("ACTION", "SYSTEM", "Created proxy host", actor=_admin_name(request),
              ip=_client_ip(request), target=stored["domain"],
              detail=f"{stored['listen_scheme']} to {stored['forward_scheme']}://"
                     f"{stored['forward_host']}:{stored['forward_port']}")
    return {"status": "ok", "file": result["file"], "firewall": opened}

@app.put("/api/config/proxy/hosts/{filename}")
async def api_proxy_update(request: Request, filename: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    spec = _proxy_spec_from_body(await _json_body(request))
    try:
        result = await DB.run(nginx_proxy.update_host, filename, spec)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    stored = result["spec"]
    opened = await _open_proxy_port(request, stored)
    write_log("ACTION", "SYSTEM", "Edited proxy host", actor=_admin_name(request),
              ip=_client_ip(request), target=stored["domain"],
              detail=f"{stored['listen_scheme']} to {stored['forward_scheme']}://"
                     f"{stored['forward_host']}:{stored['forward_port']}")
    return {"status": "ok", "file": result["file"], "firewall": opened}

@app.delete("/api/config/proxy/hosts/{filename}")
async def api_proxy_delete(request: Request, filename: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    try:
        await DB.run(nginx_proxy.delete_host, filename)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    write_log("ACTION", "SYSTEM", "Removed proxy host", actor=_admin_name(request),
              ip=_client_ip(request), target=filename)
    return {"status": "ok"}

async def _open_proxy_port(request, spec):
    """A proxy host nobody can reach is not a working proxy host, so the port
    goes on the allow list as the host is saved. A firewall that will not take
    the rule must not undo the host that was already written."""
    port = _proxy_port_for_firewall(spec)
    if not port:
        return {"port": 0, "opened": False}
    actor = _admin_name(request)

    def work():
        conn = DB.get_connection()
        try:
            return firewall.allow_proxy_port(conn, port, spec["domain"],
                                             created_by=actor)
        finally:
            DB.release_connection(conn)

    try:
        applied, detail = await DB.run(work)
    except Exception as e:
        return {"port": port, "opened": False, "error": str(e)}
    return {"port": port, "opened": True, "enforced": bool(applied),
            "detail": detail}

# ---- structured panel logs ----
@app.get("/api/logs")
async def api_logs(request: Request, level: str = "", category: str = "", q: str = "", limit: int = 200):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return {"logs": await DB.run(query_logs, level, category, q, limit)}

@app.get("/api/logs/counts")
async def api_logs_counts(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return await DB.run(log_counts)

# ---- SSH / security logs (shared elink tables, via DB.py) ----
@app.get("/api/system/ssh-logs")
async def api_ssh_logs(request: Request, since: str = "", limit: int = 200):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    try:
        return await DB.run(_parse_ssh_journal, since or None, limit)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/ssh-sessions")
async def api_ssh_sessions(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return {"sessions": await DB.run(_get_current_ssh_sessions)}

@app.get("/api/system/web-login-logs")
async def api_web_login_logs(request: Request, page: int = 1, limit: int = 50):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return await DB.run(DB.get_web_login_logs, page, limit)

@app.get("/api/system/web-blocked-ips")
async def api_web_blocked_ips(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return {"blocked": await DB.run(DB.get_web_blocked_ips)}

@app.post("/api/system/web-unblock")
async def api_web_unblock(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse(status_code=400, content={"error": "ip required"})
    await DB.run(DB.unblock_web_ip, ip)
    write_log("ACTION", "SECURITY", "Unblock web IP", actor=_admin_name(request), ip=_client_ip(request), target=ip)
    return {"status": "unblocked", "ip": ip}

@app.post("/api/system/web-block")
async def api_web_block(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    hours = int(body.get("hours") or 8760)
    note = (body.get("note") or "Manually blocked").strip()
    if not ip:
        return JSONResponse(status_code=400, content={"error": "ip required"})
    await DB.run(DB.block_web_ip, ip, hours, note)
    write_log("ACTION", "SECURITY", "Block web IP", actor=_admin_name(request),
              ip=_client_ip(request), target=ip, detail=f"{hours}h, {note}")
    return {"status": "blocked", "ip": ip, "hours": hours}

@app.get("/api/system/access-log")
async def api_access_log(request: Request, page: int = 1, limit: int = 100, ip: str = "", path: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return await DB.run(DB.get_http_access_logs, page, min(limit, 500), ip, path)

@app.get("/api/system/access-log-entry")
async def api_access_log_entry(request: Request, id: int):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    entry = await DB.run(DB.get_http_access_entry, id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Entry not found"})
    return entry

@app.get("/api/system/web-sessions")
async def api_web_sessions(request: Request, limit: int = 100):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return await DB.run(DB.get_web_sessions, limit)

@app.get("/api/system/ip-profile")
async def api_ip_profile(request: Request, ip: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    if not (ip or "").strip():
        return JSONResponse(status_code=400, content={"error": "ip required"})
    return await DB.run(DB.get_ip_profile, ip.strip())

@app.get("/api/system/log-counts")
async def api_security_log_counts(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return await DB.run(DB.get_security_log_counts)

@app.get("/api/system/security-summary")
async def api_security_summary(request: Request, range: str = ""):
    """The four numbers at the top of the Logs tab, over a chosen window.

    The window is resolved through web_guard's fixed table rather than passed
    through, so a query string never reaches SQL and an unknown value falls back
    instead of failing.
    """
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    label, interval = web_guard.range_interval(range)
    counts = await DB.run(DB.get_login_summary, interval)
    counts["range"] = range if range in web_guard.RANGES else web_guard.DEFAULT_RANGE
    counts["range_label"] = label
    counts["ranges"] = [{"key": k, "label": v[0]} for k, v in web_guard.RANGES.items()]
    return counts

@app.post("/api/system/clear-log")
async def api_clear_log(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    kind = (body.get("kind") or "").strip()
    try:
        removed = await DB.run(DB.clear_security_log, kind)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    write_log("ACTION", "SECURITY", "Clear security log", actor=_admin_name(request),
              ip=_client_ip(request), target=kind, detail=f"{removed} rows")
    return {"status": "cleared", "kind": kind, "removed": removed}

@app.get("/api/system/fp-blocked")
async def api_fp_blocked(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    return {"blocked": await DB.run(DB.get_fp_blocked)}

@app.post("/api/system/fp-unblock")
async def api_fp_unblock(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    fp_hash = (body.get("fp_hash") or "").strip()
    if not fp_hash:
        return JSONResponse(status_code=400, content={"error": "fp_hash required"})
    await DB.run(DB.unblock_fp, fp_hash)
    write_log("ACTION", "SECURITY", "Unblock device", actor=_admin_name(request), ip=_client_ip(request), target=fp_hash)
    return {"status": "unblocked", "fp_hash": fp_hash}

@app.get("/api/system/ssh-attacker")
async def api_ssh_attacker(request: Request, ip: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("logs_access"))
    if denied:
        return denied
    if not (ip or "").strip():
        return JSONResponse(status_code=400, content={"error": "ip required"})
    return await DB.run(DB.get_ssh_attacker_detail, ip.strip())

@app.post("/api/system/ssh-block")
async def api_ssh_block(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not firewall.valid_ip(ip):
        return JSONResponse(status_code=400, content={"error": "valid ip required"})

    def work():
        conn = DB.get_connection()
        try:
            return firewall.block_ip(conn, ip, reason=(body.get("reason") or "Blocked from the SSH log"),
                                      source="manual", created_by=_admin_name(request))
        finally:
            DB.release_connection(conn)

    try:
        enforced, detail = await DB.run(work)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    write_log("ACTION" if enforced else "WARN", "SECURITY", "Block SSH IP (firewall)",
              actor=_admin_name(request), ip=_client_ip(request), target=ip,
              detail=detail, status="ok" if enforced else "failed")
    return {"status": "blocked" if enforced else "recorded", "ip": ip,
            "firewall_enforced": enforced, "detail": detail}

@app.post("/api/system/ssh-unblock")
async def api_ssh_unblock(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    ip = (body.get("ip") or "").strip()
    if not firewall.valid_ip(ip):
        return JSONResponse(status_code=400, content={"error": "valid ip required"})

    def work():
        conn = DB.get_connection()
        try:
            return firewall.unblock_ip(conn, ip)
        finally:
            DB.release_connection(conn)

    ok, detail = await DB.run(work)
    write_log("ACTION", "SECURITY", "Unblock IP (firewall)", actor=_admin_name(request),
              ip=_client_ip(request), target=ip, detail=detail)
    return {"status": "ok", "removed": ok, "detail": detail}

# ---- Firewall settings ----
def _firewall_state():
    conn = DB.get_connection()
    try:
        return {"status": firewall.status(),
                "blocks": firewall.list_blocks(conn),
                "rules": firewall.list_rules(conn),
                "ssh_limit": firewall.SSH_FAIL_LIMIT,
                "ssh_window_minutes": firewall.SSH_FAIL_WINDOW_MINUTES,
                "offenders": firewall.ssh_offenders(conn)}
    finally:
        DB.release_connection(conn)

@app.get("/api/config/firewall")
async def api_firewall_get(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("firewall_manage"))
    if denied:
        return denied
    return await DB.run(_firewall_state)

@app.post("/api/config/firewall/rule")
async def api_firewall_rule(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("firewall_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    try:
        port = int(body.get("port"))
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "Enter a port number."})
    protocol = (body.get("protocol") or "tcp").lower()
    direction = (body.get("direction") or "in").lower()
    enabled = bool(body.get("enabled", True))

    def work():
        conn = DB.get_connection()
        try:
            return firewall.set_rule(conn, port, protocol, direction, enabled,
                                      note=(body.get("note") or ""),
                                      created_by=_admin_name(request))
        finally:
            DB.release_connection(conn)

    try:
        ok, detail = await DB.run(work)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    write_log("ACTION" if ok else "WARN", "SECURITY",
              f"Firewall {'allow' if enabled else 'remove'} {port}/{protocol} {direction}",
              actor=_admin_name(request), ip=_client_ip(request),
              detail=detail, status="ok" if ok else "failed")
    return {"status": "ok", "applied": ok, "detail": detail}

@app.delete("/api/config/firewall/rule")
async def api_firewall_rule_delete(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("firewall_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    try:
        port = int(body.get("port"))
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "Enter a port number."})
    protocol = (body.get("protocol") or "tcp").lower()
    direction = (body.get("direction") or "in").lower()

    def work():
        conn = DB.get_connection()
        try:
            return firewall.delete_rule(conn, port, protocol, direction)
        finally:
            DB.release_connection(conn)

    await DB.run(work)
    write_log("ACTION", "SECURITY", f"Firewall rule removed {port}/{protocol} {direction}",
              actor=_admin_name(request), ip=_client_ip(request))
    return {"status": "ok"}

@app.post("/api/config/firewall/block")
async def api_firewall_block(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("firewall_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    ip = (body.get("ip") or "").strip()
    if not firewall.valid_ip(ip):
        return JSONResponse(status_code=400, content={"error": "Enter an IP address."})

    def work():
        conn = DB.get_connection()
        try:
            return firewall.block_ip(conn, ip, reason=(body.get("reason") or "Blocked by hand"),
                                      source="manual", created_by=_admin_name(request))
        finally:
            DB.release_connection(conn)

    ok, detail = await DB.run(work)
    write_log("ACTION" if ok else "WARN", "SECURITY", "Firewall block", actor=_admin_name(request),
              ip=_client_ip(request), target=ip, detail=detail, status="ok" if ok else "failed")
    return {"status": "ok", "applied": ok, "detail": detail}

# ---- Config: Cloudflare Tunnel ----
# Cloudflare terminates HTTPS at its edge and cloudflared collects it from here
# over plain HTTP, so a hostname can be published without opening a port at all.
# Every one of these runs in a worker with its own connection, the way the
# firewall endpoints do, because they all shell out to cloudflared.
def _tunnel_work(fn, *args, **kwargs):
    """Run one cloudflare_tunnel call in a worker with its own connection.
    Pooled connections are autocommit, so there is nothing to commit here."""
    def work():
        conn = DB.get_connection()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            DB.release_connection(conn)
    return work

@app.get("/api/config/tunnel")
async def api_tunnel_get(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    return await DB.run(_tunnel_work(cloudflare_tunnel.overview))

@app.post("/api/config/tunnel/login")
async def api_tunnel_login(request: Request):
    """Hand back the link that connects a Cloudflare account.

    cloudflared waits for the browser itself, so this returns as soon as the link
    exists and the page polls until the account shows up.
    """
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    state = await DB.run(cloudflare_tunnel.login_start)
    write_log("ACTION", "NETWORK", "Cloudflare account login started",
              actor=_admin_name(request), ip=_client_ip(request),
              detail=state.get("state", ""), status="ok" if state.get("url") else "pending")
    return state

@app.get("/api/config/tunnel/login")
async def api_tunnel_login_state(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    return await DB.run(cloudflare_tunnel.login_state)

@app.post("/api/config/tunnel/disconnect")
async def api_tunnel_disconnect(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    try:
        removed = await DB.run(cloudflare_tunnel.disconnect)
    except OSError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    write_log("ACTION", "NETWORK", "Cloudflare account disconnected",
              actor=_admin_name(request), ip=_client_ip(request),
              detail=", ".join(removed))
    return {"status": "ok", "removed": removed}

@app.post("/api/config/tunnel/create")
async def api_tunnel_create(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    name = (body.get("name") or "").strip().lower()
    actor = _admin_name(request)
    problem = cloudflare_tunnel.name_problem(name)
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})

    ok, message = await DB.run(_tunnel_work(cloudflare_tunnel.create_tunnel, name, actor))
    if ok:
        await DB.run(_tunnel_work(_tunnel_activate_if_first, name))
    write_log("ACTION" if ok else "WARN", "NETWORK", "Cloudflare tunnel created",
              actor=actor, ip=_client_ip(request), target=name,
              detail=message[:400], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

def _tunnel_activate_if_first(conn, name):
    """The first tunnel becomes the one the service runs, because a panel with
    one tunnel and nothing selected would just be a question with one answer."""
    if not cloudflare_tunnel.active_tunnel(conn):
        cloudflare_tunnel.set_active(conn, name)
    return True

@app.delete("/api/config/tunnel/{name}")
async def api_tunnel_delete(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    name = (name or "").strip().lower()
    if cloudflare_tunnel.name_problem(name):
        return JSONResponse(status_code=400, content={"error": "That is not a tunnel name."})
    ok, message = await DB.run(_tunnel_work(cloudflare_tunnel.delete_tunnel, name))
    write_log("ACTION" if ok else "WARN", "NETWORK", "Cloudflare tunnel deleted",
              actor=_admin_name(request), ip=_client_ip(request), target=name,
              detail=message[:400], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/config/tunnel/active")
async def api_tunnel_active(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    name = (body.get("name") or "").strip().lower()
    ok, message = await DB.run(_tunnel_work(cloudflare_tunnel.set_active, name))
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    write_log("ACTION", "NETWORK", "Cloudflare tunnel selected to run",
              actor=_admin_name(request), ip=_client_ip(request), target=name)
    return {"status": "ok", "active": name}

@app.post("/api/config/tunnel/route")
async def api_tunnel_route(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    tunnel = (body.get("tunnel") or "").strip().lower()
    hostname = (body.get("hostname") or "").strip().lower()
    local_host = (body.get("local_host") or "127.0.0.1").strip().lower()
    local_port = body.get("local_port")
    problem = (cloudflare_tunnel.name_problem(tunnel)
               or cloudflare_tunnel.route_problem(hostname, local_host, local_port))
    if problem:
        return JSONResponse(status_code=400, content={"error": problem})

    actor = _admin_name(request)
    ok, message = await DB.run(_tunnel_work(
        cloudflare_tunnel.add_route, tunnel, hostname, local_host, local_port, actor))
    write_log("ACTION" if ok else "WARN", "NETWORK", "Cloudflare tunnel forward",
              actor=actor, ip=_client_ip(request), target=hostname,
              detail=f"{local_host}:{local_port} through {tunnel}; {message}"[:400],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.delete("/api/config/tunnel/route/{hostname}")
async def api_tunnel_route_delete(request: Request, hostname: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    ok, message = await DB.run(_tunnel_work(cloudflare_tunnel.remove_route, hostname))
    write_log("ACTION" if ok else "WARN", "NETWORK", "Cloudflare tunnel forward removed",
              actor=_admin_name(request), ip=_client_ip(request), target=hostname,
              detail=message[:400], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/config/tunnel/service")
async def api_tunnel_service(request: Request):
    """Install, start, stop, restart or remove the service that runs the tunnel."""
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("tunnel_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    action = (body.get("action") or "").strip().lower()
    if action == "install":
        ok, message = await DB.run(_tunnel_work(cloudflare_tunnel.install_service))
    elif action == "uninstall":
        ok, message = await DB.run(cloudflare_tunnel.uninstall_service)
    elif action in ("start", "stop", "restart"):
        ok, message = await DB.run(cloudflare_tunnel.service_action, action)
    else:
        return JSONResponse(status_code=400,
                            content={"error": "That is not something the tunnel can be asked to do."})
    write_log("ACTION" if ok else "WARN", "NETWORK", f"Cloudflare tunnel {action}",
              actor=_admin_name(request), ip=_client_ip(request),
              target=cloudflare_tunnel.SERVICE_NAME, detail=message[:400],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

# ---- Mail ----
# Mail is not gated on a grant: everybody with an account gets the tab, and what
# they see is decided by which mailboxes are theirs. The admin is the only one who
# can configure anything or hand an address out, so those endpoints check for the
# admin and the rest filter by ownership. visible_boxes is the single place that
# decision is made, and every read passes its result through as the box filter,
# so there is no path that reads a mailbox somebody does not own.
def _mail_work(fn, *args, **kwargs):
    def work():
        conn = DB.get_connection()
        try:
            mail.ensure_schema(conn)
            return fn(conn, *args, **kwargs)
        finally:
            DB.release_connection(conn)
    return work

def _mail_identity(perms):
    return perms.get("username") or "", perms.get("role") == "admin"

def _mail_faces(conn):
    """Which addresses on this system have a face, and what to write when they
    do not.

    Built once per overview rather than per message: a mailbox belongs to a panel
    account, that account may have a picture, and a message from that address
    should show it. Mail from outside has no account and so gets initials, which
    is the honest answer, not a missing image.
    """
    people = identity.everyone(conn)
    out = {}
    for box in mail.boxes(conn):
        owner = box["owner"]
        who = people.get(owner, {}) if owner else {}
        name = box["full_name"] or who.get("full_name") or box["local_part"]
        out[box["address"]] = {
            "name": name,
            "initials": identity.initials(name, box["local_part"]),
            "avatar": (f"{MGMT_BASE}/api/account/avatar/{owner}"
                       f"?v={who.get('avatar_hash', '')[:16]}") if who.get("has_avatar") else "",
        }
    return out

def _public_origin(request: Request) -> str:
    """The address this panel is being looked at from, or "" if it is a local one.

    Used only to suggest a DNS value to the admin reading the page, never to
    fetch anything and never in a redirect, which is what makes it safe to read
    the Host header here: the worst a forged one can do is print the wrong
    suggestion back to the person who forged it.
    """
    host = (request.headers.get("host") or "").strip()
    if not host or not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?", host):
        return ""
    name = host.split(":")[0].lower()
    if name in ("localhost", "127.0.0.1", "::1") or name.endswith(".local"):
        return ""
    scheme = "https" if _is_https(request) else "http"
    return f"{scheme}://{host}"

def _bimi_state(conn, username, domain, public_origin=""):
    """Whether this account's picture can be published as its mail logo, and the
    DNS value that would do it.

    Kept honest on purpose: BIMI wants a square SVG, most pictures are neither,
    and a record pointing at a logo a receiver cannot draw is worse than not
    publishing one. So the reason is reported rather than the record.
    """
    url = f"{public_origin}{MGMT_BASE}/bimi/{username}.svg" if public_origin else ""
    kind, data, _digest = identity.avatar(conn, username)
    if not kind:
        return {"ready": False, "problem": "This account has no picture yet.",
                "url": url, "record": ""}
    problem = identity.bimi_problem(kind, data or b"")
    if problem:
        return {"ready": False, "problem": problem, "url": url, "record": ""}
    if not domain:
        return {"ready": False, "problem": "Set the mail domain first.",
                "url": url, "record": ""}
    if not url:
        return {"ready": False, "problem": ("A logo has to be fetched over HTTPS from "
                                            "outside, so the panel needs a public "
                                            "address before it can publish one."),
                "url": "", "record": ""}
    return {"ready": True, "problem": "", "url": url,
            "record": identity.bimi_record(url)}

def _mail_overview(conn, username, is_admin, public_origin=""):
    cfg = mail.config(conn)
    mine = mail.visible_boxes(conn, username, is_admin)
    out = {
        "configured": cfg["configured"],
        "domain": cfg["domain"],
        "is_admin": is_admin,
        "username": username,
        "boxes": mine,
        "unread": mail.unread_count(conn, [b["id"] for b in mine]),
        "outbound_ready": cfg["outbound_ready"],
        "faces": _mail_faces(conn),
        "me": identity.get(conn, username),
    }
    if is_admin:
        out["config"] = cfg
        out["all_boxes"] = mail.boxes(conn)
        out["inbound"] = mailcow.status(conn, cfg["domain"])
        out["bimi"] = _bimi_state(conn, username, cfg["domain"], public_origin)
        out["dns"] = mailcow.dns_help(cfg["domain"], out["bimi"]["record"])
        out["staff"] = [u["username"] for u in panel_users.list_users(conn)]
    return out

@app.get("/api/mail/overview")
async def api_mail_overview(request: Request):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)
    return await DB.run(_mail_work(_mail_overview, username, is_admin,
                                   _public_origin(request)))

@app.get("/api/mail/unread")
async def api_mail_unread(request: Request):
    """Just the number behind the tab, so the badge does not cost a full read."""
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        return {"unread": mail.unread_count(conn, [b["id"] for b in mine]),
                "boxes": len(mine)}
    return await DB.run(_mail_work(work))

@app.get("/api/mail/messages")
async def api_mail_messages(request: Request, folder: str = "inbox",
                            box: str = "", page: int = 1):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        ids = [b["id"] for b in mine]
        if box:
            # A box filter can only ever narrow what the caller may already read.
            ids = [b["id"] for b in mine if b["address"] == box.strip().lower()]
        return mail.messages(conn, ids, folder=folder, page=page)
    return await DB.run(_mail_work(work))

@app.post("/api/mail/read")
async def api_mail_read(request: Request):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)
    body = await _json_body(request)
    try:
        message_id = int(body.get("id"))
    except (TypeError, ValueError):
        return JSONResponse(status_code=400, content={"error": "Which message?"})
    read = bool(body.get("read", True))

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        return mail.mark_read(conn, message_id, [b["id"] for b in mine], read)
    if not await DB.run(_mail_work(work)):
        return JSONResponse(status_code=404, content={"error": "No such message."})
    return {"status": "ok"}

@app.delete("/api/mail/message/{message_id}")
async def api_mail_delete(request: Request, message_id: int):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        return mail.delete_message(conn, message_id, [b["id"] for b in mine])
    if not await DB.run(_mail_work(work)):
        return JSONResponse(status_code=404, content={"error": "No such message."})
    return {"status": "ok"}

@app.post("/api/mail/send")
async def api_mail_send(request: Request):
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)
    body = await _json_body(request)
    from_address = (body.get("from") or "").strip().lower()
    route = (body.get("route") or "").strip().lower()

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        if from_address not in {b["address"] for b in mine}:
            return False, "That is not one of your addresses.", ""
        # A named address speaks for itself: mail from sales@ says "Sales Desk",
        # not the name of whoever happens to be holding it. An address with no
        # name of its own borrows the name of the person sending from it.
        display = (next((b["full_name"] for b in mine
                         if b["address"] == from_address), "")
                   or identity.display_name(conn, username))
        return mail.send(conn, from_address, body.get("to") or "",
                         body.get("subject") or "", body.get("body") or "",
                         route, actor=username, from_name=display)

    ok, message, used = await DB.run(_mail_work(work))
    write_log("ACTION" if ok else "WARN", "MAIL", "Mail sent", actor=username,
              ip=_client_ip(request), target=(body.get("to") or "")[:200],
              detail=f"{used or route}: {message}"[:400],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message, "route": used}

# ---- Mail configuration and mailboxes, admin only ----
@app.post("/api/mail/domain")
async def api_mail_domain(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    domain = (body.get("domain") or "").strip().lower()
    actor = _admin_name(request)
    ok, message = await DB.run(_mail_work(mail.set_domain, domain, actor))
    write_log("ACTION" if ok else "WARN", "MAIL", "Mail domain set", actor=actor,
              ip=_client_ip(request), target=domain, detail=message[:300],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/mail/relay")
async def api_mail_relay(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    actor = _admin_name(request)
    ok, message = await DB.run(_mail_work(
        mail.set_relay, body.get("host") or "", body.get("port") or mail.DEFAULT_RELAY_PORT,
        body.get("user") or "", body.get("password") or "",
        bool(body.get("starttls", True)), body.get("from") or "", actor))
    write_log("ACTION" if ok else "WARN", "MAIL", "Outbound relay configured",
              actor=actor, ip=_client_ip(request),
              target=(body.get("host") or "")[:200], detail=message[:300],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/mail/relay/check")
async def api_mail_relay_check(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    ok, detail = await DB.run(_mail_work(mail.check_relay))
    write_log("ACTION" if ok else "WARN", "MAIL", "Relay check", actor=_admin_name(request),
              ip=_client_ip(request), detail=detail[:300], status="ok" if ok else "failed")
    return {"status": "ok" if ok else "failed", "ok": ok, "detail": detail}

@app.post("/api/mail/box")
async def api_mail_box_create(request: Request):
    """Create an address under the configured domain, and create it at mailcow too
    when mailcow is reachable, so the same address exists in both places."""
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    local_part = (body.get("local_part") or "").strip().lower()
    owner = (body.get("owner") or "").strip()
    full_name = body.get("full_name") or ""
    actor = _admin_name(request)

    def work(conn):
        cfg = mail.config(conn)
        if not cfg["domain"]:
            return False, "Configure the mail domain first.", ""
        secret = secrets.token_urlsafe(18)
        server_side, note = False, ""
        if mailcow.api_ready(conn):
            made, detail = mailcow.add_mailbox(conn, local_part, cfg["domain"],
                                               secret, full_name)
            server_side = bool(made)
            if not made:
                note = f" mailcow would not create it: {detail}"
        ok, message, _box_id = mail.create_box(conn, local_part, owner, full_name,
                                               actor, secret=secret,
                                               server_side=server_side)
        return ok, message + note, ("server" if server_side else "panel")

    ok, message, where = await DB.run(_mail_work(work))
    write_log("ACTION" if ok else "WARN", "MAIL", "Mailbox created", actor=actor,
              ip=_client_ip(request), target=local_part[:100],
              detail=f"{where}; owner={owner or 'admin'}; {message}"[:400],
              status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message, "where": where}

@app.post("/api/mail/box/assign")
async def api_mail_box_assign(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    address = (body.get("address") or "").strip().lower()
    owner = (body.get("owner") or "").strip()

    def work(conn):
        if owner and not panel_users.get_user(conn, owner):
            return False, f"There is no account called {owner}."
        return mail.assign_box(conn, address, owner)

    ok, message = await DB.run(_mail_work(work))
    write_log("ACTION" if ok else "WARN", "MAIL", "Mailbox assigned",
              actor=_admin_name(request), ip=_client_ip(request), target=address,
              detail=message[:300], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/mail/box/name")
async def api_mail_box_name(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    ok, message = await DB.run(_mail_work(
        mail.set_box_name, (body.get("address") or "").strip().lower(),
        body.get("full_name") or ""))
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.delete("/api/mail/box/{address}")
async def api_mail_box_delete(request: Request, address: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    address = (address or "").strip().lower()

    def work(conn):
        if mailcow.api_ready(conn):
            mailcow.delete_mailbox(conn, address)
        return mail.delete_box(conn, address)

    ok, message = await DB.run(_mail_work(work))
    write_log("ACTION" if ok else "WARN", "MAIL", "Mailbox deleted",
              actor=_admin_name(request), ip=_client_ip(request), target=address,
              detail=message[:300], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/mail/inbound/prepare")
async def api_mail_inbound_prepare(request: Request):
    """Set up mailcow for the domain, and open the one port mail arrives on.

    Port 25 is opened here rather than left to the operator because a mail server
    nothing can reach is not a mail server, and this is the moment the intent is
    unambiguous.
    """
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    domain = (body.get("domain") or "").strip().lower()
    actor = _admin_name(request)

    def work(conn):
        ok, message = mail.set_domain(conn, domain, actor)
        if not ok:
            return False, message, {}
        started, note = mailcow.prepare(domain)
        opened, detail = firewall.set_rule(
            conn, mailcow.SMTP_PORT, "tcp", "in", True,
            note="inbound mail", auto=True, created_by=actor)
        return started, f"{message} {note}", {"port_opened": bool(opened),
                                              "port_detail": detail}

    try:
        ok, message, extra = await DB.run(_mail_work(work))
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    write_log("ACTION" if ok else "WARN", "MAIL", "Inbound mail prepared",
              actor=actor, ip=_client_ip(request), target=domain,
              detail=message[:400], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message, **extra}

@app.post("/api/mail/inbound/{action}")
async def api_mail_inbound_action(request: Request, action: str):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    if action == "start":
        domain = await DB.run(_mail_work(lambda c: mail.config(c).get("domain", "")))
        ok, message = mailcow.start_stack(domain)
    elif action == "stop":
        ok, message = mailcow.stop_stack()
    elif action == "key":
        body = await _json_body(request)
        ok, message = await DB.run(_mail_work(mail.set_mailcow_key,
                                              body.get("key") or "",
                                              _admin_name(request)))
    else:
        return JSONResponse(status_code=400,
                            content={"error": "That is not something inbound mail can be asked to do."})
    write_log("ACTION" if ok else "WARN", "MAIL", f"Inbound mail {action}",
              actor=_admin_name(request), ip=_client_ip(request),
              detail=message[:300], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message}

@app.post("/api/system/install")
async def api_system_install(request: Request):
    """Install a missing system component the panel knows how to install.

    The body names a component, never a package: the name is looked up in
    provision.COMPONENTS and only that entry's own fixed package list is handed
    to the package manager, so nothing from a request reaches a command line.
    """
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    body = await _json_body(request)
    raw = body.get("components") or ([body["component"]] if body.get("component") else [])
    wanted = [c for c in raw if isinstance(c, str) and c in provision.COMPONENTS]
    if not wanted:
        return JSONResponse(status_code=400,
                            content={"error": "That is not something the panel can install."})
    started, message = provision.install_async(wanted)
    write_log("ACTION" if started else "WARN", "SYSTEM", "Install missing packages",
              actor=_admin_name(request), ip=_client_ip(request),
              target=",".join(wanted), detail=message[:300],
              status="ok" if started else "busy")
    if not started:
        return JSONResponse(status_code=409, content={"error": message})
    return {"status": "ok", "message": message}

@app.get("/api/system/install")
async def api_system_install_state(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    state = provision.job_state()
    state["missing"] = provision.missing()
    state["can_install"] = provision.escalation() is not None
    return state

@app.get("/api/mail/inbound-job")
async def api_mail_inbound_job(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _is_admin)
    if denied:
        return denied
    return mailcow.job_state()

@app.post("/api/mail/sync")
async def api_mail_sync(request: Request):
    """Collect what has arrived at a mailbox on the mail server into the panel."""
    if not _authed(request):
        return _need_auth()
    perms = await _current_permissions(request)
    username, is_admin = _mail_identity(perms)
    body = await _json_body(request)
    address = (body.get("address") or "").strip().lower()

    def work(conn):
        mine = mail.visible_boxes(conn, username, is_admin)
        if address not in {b["address"] for b in mine}:
            return False, "That is not one of your addresses.", 0
        return mailcow.sync_box(conn, address)

    ok, message, added = await DB.run(_mail_work(work))
    if not ok:
        return JSONResponse(status_code=400, content={"error": message})
    return {"status": "ok", "message": message, "added": added}

@app.get("/api/system/ssh-status")
async def api_ssh_status(request: Request):
    if not _authed(request):
        return _need_auth()
    try:
        active = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True).stdout.strip()
        enabled = subprocess.run(["systemctl", "is-enabled", "ssh"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        return JSONResponse(status_code=503, content={"error": "systemctl not available"})
    return {"active": active == "active", "state": active or "unknown", "enabled": enabled or "unknown"}

@app.post("/api/system/ssh-toggle")
async def api_ssh_toggle(request: Request):
    if not _authed(request):
        return _need_auth()
    body = await request.json()
    enable = bool(body.get("enable"))
    cmds = ([["systemctl", "enable", "ssh"], ["systemctl", "start", "ssh"]] if enable
            else [["systemctl", "stop", "ssh"], ["systemctl", "disable", "ssh"]])
    errors = []
    try:
        for c in cmds:
            r = subprocess.run(c, capture_output=True, text=True)
            if r.returncode != 0:
                msg = (r.stderr or r.stdout or "").strip()
                if msg:
                    errors.append(msg)
        active = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        return JSONResponse(status_code=503, content={"error": "systemctl not available"})
    ok = (active == "active") if enable else (active != "active")
    write_log("ACTION" if ok else "ERROR", "SERVICE", "SSH " + ("enable" if enable else "disable"),
              actor=_admin_name(request), ip=_client_ip(request), target="ssh.service",
              detail=("ok" if ok else "FAILED: " + "; ".join(errors))[:300], status="ok" if ok else "failed")
    if not ok:
        return JSONResponse(status_code=500, content={"error": "SSH toggle failed: " + ("; ".join(errors) or "unknown")})
    return {"status": "ok", "active": active == "active", "enable": enable}

# ---- terminal: PTY WebSocket (ported from Main.py) ----
_TERMS = {}
_TERM_BUF_MAX = 256 * 1024

# ---------------------------------------------------------------------------
# Telegram bot.
#
# One public endpoint and a handful of admin ones. The public endpoint is the
# only route in this file that answers without a session, so it authenticates
# the caller a different way: Telegram is told a secret when the webhook is
# installed, sends it back on every delivery, and a POST arriving without it is
# dropped before the body is even read as an update.
# ---------------------------------------------------------------------------
def _tg_work(fn, *args, **kwargs):
    def work():
        conn = DB.get_connection()
        try:
            return fn(conn, *args, **kwargs)
        finally:
            DB.release_connection(conn)
    return work

@app.get("/api/config/telegram")
async def api_telegram_get(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    return await DB.run(_tg_work(telegram_bot.status))

@app.post("/api/config/telegram")
async def api_telegram_set(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    actor = _admin_name(request)
    ok, detail = await DB.run(_tg_work(
        telegram_bot.set_config,
        bot_token=body.get("token", ""),
        domain=body.get("domain"),
        notify_email=body.get("notify_email"),
        actor=actor))
    write_log("ACTION" if ok else "WARN", "NETWORK", "Telegram bot settings saved",
              actor=actor, ip=_client_ip(request), detail=detail,
              status="ok" if ok else "failed")
    return JSONResponse(status_code=200 if ok else 400,
                        content={"ok": ok, "detail": detail})

@app.post("/api/config/telegram/connect")
async def api_telegram_connect(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    actor = _admin_name(request)
    ok, detail = await DB.run(_tg_work(telegram_bot.install_webhook, actor=actor))
    write_log("ACTION" if ok else "ERROR", "NETWORK", "Telegram webhook installed",
              actor=actor, ip=_client_ip(request), detail=detail,
              status="ok" if ok else "failed")
    return JSONResponse(status_code=200 if ok else 400,
                        content={"ok": ok, "detail": detail})

@app.post("/api/config/telegram/disconnect")
async def api_telegram_disconnect(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    actor = _admin_name(request)
    ok, detail = await DB.run(_tg_work(telegram_bot.remove_webhook, actor=actor))
    write_log("ACTION", "NETWORK", "Telegram webhook removed", actor=actor,
              ip=_client_ip(request), detail=detail,
              status="ok" if ok else "failed")
    return JSONResponse(status_code=200 if ok else 400,
                        content={"ok": ok, "detail": detail})

@app.post("/api/config/telegram/allow")
async def api_telegram_allow(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    actor = _admin_name(request)
    ok, detail = await DB.run(_tg_work(
        telegram_bot.allow, body.get("telegram_id"),
        (body.get("role") or telegram_bot.ROLE_USER),
        body.get("panel_user", ""), actor))
    write_log("ACTION" if ok else "WARN", "SECURITY", "Telegram access changed",
              actor=actor, ip=_client_ip(request),
              target=str(body.get("telegram_id", "")), detail=detail,
              status="ok" if ok else "failed")
    return JSONResponse(status_code=200 if ok else 400,
                        content={"ok": ok, "detail": detail})

@app.post("/api/config/telegram/revoke")
async def api_telegram_revoke(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    body = await _json_body(request)
    actor = _admin_name(request)
    ok, detail = await DB.run(_tg_work(telegram_bot.revoke,
                                       body.get("telegram_id"), actor))
    write_log("ACTION" if ok else "WARN", "SECURITY", "Telegram access revoked",
              actor=actor, ip=_client_ip(request),
              target=str(body.get("telegram_id", "")), detail=detail,
              status="ok" if ok else "failed")
    return JSONResponse(status_code=200 if ok else 400,
                        content={"ok": ok, "detail": detail})

@app.get("/api/config/telegram/log")
async def api_telegram_log(request: Request, limit: int = 200, telegram_id: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    who = telegram_id if telegram_id.strip().lstrip("-").isdigit() else None
    rows = await DB.run(_tg_work(telegram_bot.recent, limit, who))
    return {"log": rows}

@app.post("/api/config/telegram/log/clear")
async def api_telegram_log_clear(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("telegram_manage"))
    if denied:
        return denied
    ok, detail = await DB.run(_tg_work(telegram_bot.clear_log))
    write_log("ACTION", "NETWORK", "Telegram conversation log cleared",
              actor=_admin_name(request), ip=_client_ip(request))
    return {"ok": ok, "detail": detail}

@app.post("/bot")
async def telegram_webhook(request: Request):
    """Where Telegram delivers. Public by necessity, guarded by the secret it
    was given when the webhook was installed.

    It always answers 200 once the secret checks out. Telegram retries anything
    else, so a command that raised would otherwise be replayed forever.
    """
    def gate():
        conn = DB.get_connection()
        try:
            return telegram_bot.enabled(conn), telegram_bot.webhook_secret(conn)
        finally:
            DB.release_connection(conn)

    on, secret = await DB.run(gate)
    if not on or not secret:
        return JSONResponse(status_code=404, content={"error": "not found"})
    sent = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not hmac.compare_digest(sent, secret):
        write_log("WARN", "SECURITY", "Telegram webhook called without the secret",
                  actor="unknown", ip=_client_ip(request), status="blocked")
        return JSONResponse(status_code=403, content={"error": "forbidden"})
    try:
        update = await request.json()
    except Exception:
        return {"ok": True}

    ip = _client_ip(request)

    def audit(person, perms, text):
        write_log("ACTION", "SYSTEM", "Telegram command",
                  actor=f"tg:{person['telegram_id']}", ip=ip,
                  target=perms.get("username", ""), detail=(text or "")[:200])

    try:
        await DB.run(_tg_work(telegram_bot.handle_update, update, audit))
    except Exception as e:
        logging.error(f"telegram update failed: {e}")
    return {"ok": True}

def _safe_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

class _ManagedTerm:
    def __init__(self, sid, persist, rows, cols, owner="", run_as=None, jail=False):
        self.sid = sid
        self.persist = bool(persist)
        self.owner = owner
        self.run_as = run_as
        self.sess = System.PtySession(run_as=run_as, jail=jail)
        self.sess.spawn(rows=rows, cols=cols)
        self.rows, self.cols = rows, cols
        self.buffer = bytearray()
        self.subscribers = set()
        self.dead = False
        self.created = time.time()
        self.loop = asyncio.get_running_loop()
        self._start_reader()

    def _start_reader(self):
        def _on_readable():
            try:
                data = os.read(self.sess.fd, 65536)
            except OSError:
                data = b""
            if not data:
                self.dead = True
                try:
                    self.loop.remove_reader(self.sess.fd)
                except Exception:
                    pass
                for q in list(self.subscribers):
                    q.put_nowait(None)
                return
            overflow = len(self.buffer) + len(data) - _TERM_BUF_MAX
            if overflow > 0:
                del self.buffer[:overflow]
            self.buffer += data
            for q in list(self.subscribers):
                q.put_nowait(data)
        try:
            self.loop.add_reader(self.sess.fd, _on_readable)
        except Exception as e:
            logging.error(f"terminal reader add failed: {e}")
            self.dead = True

    def write(self, data):
        self.sess.write(data)

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.sess.set_winsize(rows, cols)

    def close(self):
        self.dead = True
        try:
            self.loop.remove_reader(self.sess.fd)
        except Exception:
            pass
        try:
            self.sess.close()
        except Exception:
            pass

def _term_close(sid):
    mt = _TERMS.pop(sid, None)
    if mt:
        mt.close()

@app.get("/api/system/terminals")
async def list_terminals(request: Request):
    if not _authed(request):
        return _need_auth()
    return {"sessions": [
        {"id": sid, "persist": mt.persist, "alive": not mt.dead,
         "rows": mt.rows, "cols": mt.cols, "created": int(mt.created)}
        for sid, mt in _TERMS.items()]}

@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    if _CF_GATE_ON:
        peer = websocket.client.host if websocket.client else ""
        if not _ingress_allowed(peer):
            await websocket.close(code=1008)
            return
    token_data = _get_token_data(websocket.cookies.get("session", ""))
    if token_data is None:
        await websocket.close(code=1008)
        return
    username = token_data.get("username", "")
    perms = await DB.run(_resolve_permissions, username)
    terminal_access = perms.get("terminal", "none")
    if terminal_access == panel_users.TERMINAL_NONE:
        await websocket.close(code=1008)
        return
    limited = terminal_access == panel_users.TERMINAL_LIMITED
    run_as = perms.get("os_username") if limited else None
    is_admin = perms.get("role") == "admin"
    if limited and not System.jail_available():
        # A limited terminal is meant to be confined to its own home directory.
        # Install what does that rather than quietly handing out a shell that can
        # read the whole machine; this session still starts inside their home
        # with a cd that refuses to leave it, and the next one is contained.
        provision.install_async(["jail"])

    await websocket.accept()
    qp = websocket.query_params
    sid = (qp.get("sid") or "").strip()[:64]
    persist = (qp.get("persist") or "") in ("1", "true", "yes", "on")
    rows = _safe_int(qp.get("rows"), 24)
    cols = _safe_int(qp.get("cols"), 80)
    mt = _TERMS.get(sid) if sid else None
    if mt is not None and mt.dead:
        _term_close(sid)
        mt = None
    if mt is not None and not is_admin and mt.owner != username:
        # A restricted user cannot attach to someone else's terminal by
        # guessing/reusing a session id, so start a fresh one instead.
        sid = secrets.token_hex(8)
        mt = None
    if mt is None:
        if not sid:
            sid = secrets.token_hex(8)
        try:
            mt = _ManagedTerm(sid, persist, rows, cols, owner=username,
                              run_as=run_as, jail=limited)
        except Exception as e:
            logging.error(f"terminal spawn failed: {e}")
            await websocket.close(code=1011)
            return
        _TERMS[sid] = mt
    else:
        mt.persist = persist
    try:
        await websocket.send_text(json.dumps({"sid": sid, "persist": mt.persist}))
    except Exception:
        pass
    q: asyncio.Queue = asyncio.Queue()
    mt.subscribers.add(q)
    if mt.buffer:
        try:
            await websocket.send_bytes(bytes(mt.buffer))
        except Exception:
            pass

    async def pump_out():
        while True:
            data = await q.get()
            if data is None:
                try:
                    await websocket.send_bytes(b"\r\n\x1b[90m[session ended]\x1b[0m\r\n")
                except Exception:
                    pass
                return
            try:
                await websocket.send_bytes(data)
            except Exception:
                return

    out_task = asyncio.create_task(pump_out())
    try:
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            b = msg.get("bytes")
            if b is not None:
                mt.write(b)
                continue
            t = msg.get("text")
            if not t:
                continue
            try:
                ctrl = json.loads(t)
            except Exception:
                mt.write(t)
                continue
            if not isinstance(ctrl, dict):
                continue
            if "resize" in ctrl:
                try:
                    r, c = ctrl["resize"]
                    mt.resize(int(r), int(c))
                except Exception:
                    pass
            if "persist" in ctrl:
                mt.persist = bool(ctrl["persist"])
            if ctrl.get("kill"):
                _term_close(sid)
                break
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logging.error(f"terminal_ws closed: {type(e).__name__}: {e}")
    finally:
        mt.subscribers.discard(q)
        out_task.cancel()
        kept = mt.persist and not mt.dead
        if not kept and not mt.subscribers:
            _term_close(sid)
        write_log("ACTION", "TERMINAL", "PTY session " + ("detached (kept alive)" if kept else "ended"),
                  actor="terminal", ip=_client_ip_ws(websocket), target=f"sid={sid}")

@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "management"}

# ===========================================================================
if __name__ == "__main__":
    try:
        HOST, PORT = get_mgmt_config()
    except Exception:
        HOST, PORT = "0.0.0.0", 80
    SERVER_RUNTIME["host"], SERVER_RUNTIME["port"] = HOST, PORT
    FALLBACK_PORT = 4042
    # proxy_headers=False on purpose: see _hop_ip. Uvicorn would otherwise take
    # X-Forwarded-For as the socket peer, which is the visitor's address behind a
    # tunnel, and the ingress gate would refuse every forwarded request.
    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="info",
                    proxy_headers=False)
    except (PermissionError, OSError) as e:
        logging.error(f"Bind {HOST}:{PORT} failed ({e}); falling back to :{FALLBACK_PORT}")
        SERVER_RUNTIME["port"] = FALLBACK_PORT
        uvicorn.run(app, host=HOST, port=FALLBACK_PORT, log_level="info",
                    proxy_headers=False)
