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
import firewall
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

def _create_session_token(username: str = "admin", sid: str = None) -> str:
    if sid is None:
        sid = secrets.token_hex(16)
    payload = json.dumps({"exp": int(time.time()) + 86400,
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
    """Who actually connected to our public edge. nginx fronts this panel on
    loopback, so the socket peer is 127.0.0.1 and the real peer nginx saw is in
    X-Real-IP, trustworthy only because it arrived over loopback."""
    peer = request.client.host if request.client else ""
    if _is_local_ip(peer):
        real = request.headers.get("x-real-ip", "").strip()
        if real:
            return real
    return peer

def _client_ip(request: Request) -> str:
    hop = _hop_ip(request)
    if _is_cloudflare_ip(hop):
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return cf
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

class _SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        h["X-Frame-Options"] = "DENY"
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
        ("terminal", "Terminal", "ic-monitor"), ("logs", "Logs", "ic-shield-alert")]

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

    Staff always get their own account card, and then only the cards their
    grants unlock. The admin gets everything.
    """
    if perms.get("role") == "admin":
        return ["users", "server", "service", "database", "proxy"]
    cards = ["account"]
    if perms.get("svc_status"):
        cards.append("service")
    if perms.get("db_read"):
        cards.append("database")
    if perms.get("net_proxy"):
        cards.append("proxy")
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

def _config_sub_proxy():
    return f"""
  <div class="config-sub" data-cfgsub="proxy" hidden>
    {_CONFIG_BACK}
    <div class="mgmt-h2">Proxy</div>
    <div class="cfg-card">
      <div class="device-title">Reverse proxy hosts</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">Detected and managed nginx server blocks.</div>
      <div id="proxy-list"><div class="empty-state">Loading&hellip;</div></div>
    </div>
    <div class="cfg-card" style="margin-top:18px;">
      <div class="device-title">Add a proxy host</div>
      <div class="field-group"><label class="field-label" for="px-domain">Domain</label>
        <input class="field-input" id="px-domain" type="text" placeholder="example.com" spellcheck="false" autocomplete="off"></div>
      <div class="field-group"><label class="field-label" for="px-target">Target</label>
        <div class="field-hint">Where nginx forwards requests, for example 127.0.0.1:8080</div>
        <input class="field-input" id="px-target" type="text" placeholder="127.0.0.1:8080" spellcheck="false" autocomplete="off"></div>
      <div class="field-group"><label class="perm-check"><input type="checkbox" id="px-ws" checked>Support WebSockets</label></div>
      <button class="save-btn" id="px-create" onclick="createProxyHost()">Add Host</button>
      <div class="save-feedback" id="px-feedback"></div>
    </div>
  </div>"""

_CONFIG_SUB_BUILDERS = {
    "account": _config_sub_account,
    "users": lambda perms: _config_sub_users(),
    "server": lambda perms: _config_sub_server(),
    "service": lambda perms: _config_sub_service(),
    "database": lambda perms: _config_sub_database(perms),
    "proxy": lambda perms: _config_sub_proxy(),
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
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-wifi"/></svg>Network</span><span class="metric-now" id="m-net-now">&darr;0 &uarr;0</span></div>
        <canvas class="metric-chart" id="chart-net" height="70"></canvas>
        <div class="metric-foot" id="m-net-foot">-</div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('disk')" title="Browse & download files">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-hard-drive"/></svg>Disk</span><span class="metric-now" id="m-disk-now">0%</span></div>
        <div class="disk-bar"><div class="disk-fill" id="disk-fill"></div></div>
        <div class="metric-foot" id="m-disk-foot">-</div>
        <div class="metric-head" style="margin-top:14px;"><span class="metric-title">Load avg</span><span class="metric-now" id="m-load-now">0.00</span></div>
        <div class="metric-foot" id="m-load-foot">1m / 5m / 15m</div>
      </div>
    </div>
    <div class="device-card">
      <div class="device-title">Device &amp; OS</div>
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
  <div class="pane" data-pane="logs"><div class="pane-scroll">
    <div class="srv-grid" id="sec-ssh-cards" style="margin-bottom:18px;">
      <div class="metric-card"><div class="metric-head"><span class="metric-title">SSH Total Events</span><span class="metric-now" id="sec-total">&hellip;</span></div><div class="metric-foot" id="sec-unique-ips">unique IPs: &hellip;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Successful Logins</span><span class="metric-now" style="color:#27ae60" id="sec-accepted">&hellip;</span></div><div class="metric-foot" id="sec-sessions">active sessions: &hellip;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Failed Attempts</span><span class="metric-now" style="color:#e74c3c" id="sec-failed">&hellip;</span></div><div class="metric-foot" id="sec-attackers">attacker IPs: &hellip;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Web Login Attempts</span><span class="metric-now" id="sec-web-total">&hellip;</span></div><div class="metric-foot" id="sec-web-fail">failed: &hellip;</div></div>
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
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center;">
      <button class="db-action-btn" onclick="loadSecurityLogs()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
      <select id="sec-since-sel" onchange="loadSecurityLogs()" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);">
        <option value="">Last 200 events</option><option value="today">Today</option><option value="yesterday">Yesterday</option><option value="7 days ago">Last 7 days</option></select>
    </div>
    <div id="sec-content"><div class="empty-state">Loading security logs&hellip;</div></div>
  </div></div>

  <!-- ACCOUNT, reached from the username in the top bar rather than the nav,
       because it is a rare errand, not one of the four places you work. -->
  <div class="pane" data-pane="account"><div class="pane-scroll">
    <div class="cfg-card">
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
    </div>
  </div></div>
</div>

<div id="srv-detail-overlay" onclick="if(event.target===this)closeServerDetail()">
  <div id="srv-detail-modal">
    <div id="srv-detail-head"><span id="srv-detail-title">Detail</span>
      <div style="display:flex;gap:8px;align-items:center;">
        <button class="db-action-btn" onclick="refreshServerDetail()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
        <button class="db-action-btn" onclick="closeServerDetail()"><svg class="ic"><use href="#ic-x"/></svg>Close</button></div></div>
    <div id="srv-detail-body"></div>
  </div>
</div>
"""

def _mobile_tabbar(nav):
    items = "".join(
        f'<button class="mtab" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg><span>{label}</span></button>'
        for k, label, ic in nav)
    return f'<nav class="mobile-tabbar" style="grid-template-columns:repeat({len(nav)},1fr);">{items}</nav>'

def _topbar(mobile: bool, user: str, nav):
    tabs = "".join(
        f'<button class="tab-btn" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg>{label}</button>'
        for k, label, ic in nav)
    safe_user = html.escape(user or "", quote=True)
    right = (
        '<button class="theme-btn" onclick="toggleTheme()" title="Toggle dark mode"><svg class="ic"><use href="#ic-moon" id="theme-ic"/></svg></button>'
        # The username was inert text; it is now the way into account settings,
        # which is where people already look for it.
        f'<button class="db-action-btn acct-btn" data-nav="account" onclick="switchSection(\'account\')" '
        f'title="Account settings for {safe_user}" aria-label="Account settings for {safe_user}">'
        f'<svg class="ic"><use href="#ic-lock-keyhole"/></svg>'
        f'<span class="acct-name">{safe_user}</span></button>'
        f'<a href="{MGMT_BASE}/logout" class="db-action-btn"><svg class="ic"><use href="#ic-log-out"/></svg>Logout</a>'
    )
    return (
        '<div class="mgmt-top">'
        f'<div class="mgmt-brand"><span class="mgmt-crest">{_crest()}</span>Management</div>'
        f'<div class="mgmt-tabs">{tabs}</div>'
        f'<div class="mgmt-right">{right}</div>'
        '</div>'
    )

def _dashboard_html(mobile: bool, user: str, perms: dict) -> str:
    shell = "mgmt-mobile" if mobile else "mgmt-desktop"
    nav = _visible_nav(perms)
    panes = _PANES_TEMPLATE.replace("{config_pane}", _config_pane_html(perms))
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
        f"<title>Management</title><link rel=\"stylesheet\" href=\"{MGMT_BASE}/static/dash.css\">"
        f"<script>window.MGMT_BASE={json.dumps(MGMT_BASE)};window.MGMT_PERMS={perms_json};</script></head>"
        f"<body class=\"mgmt {shell}\">{_ICON_SPRITE}"
        f"{_topbar(mobile, user, nav)}{panes}{_mobile_tabbar(nav)}"
        f"<script src=\"{MGMT_BASE}/static/management.js\"></script></body></html>"
    )

def _is_mobile(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return any(t in ua for t in ("mobi", "android", "iphone", "ipod", "windows phone"))

# Login page, warm palette via the shared stylesheet, same /api/login flow.
# __BASE__ is substituted with MGMT_BASE by _login_html().
_LOGIN_HTML = r"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Management</title><link rel="stylesheet" href="__BASE__/static/dash.css">
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
    write_log("INFO", "SYSTEM", "Management panel started", actor="system", detail=f"pid={os.getpid()}")
    yield
    write_log("INFO", "SYSTEM", "Management panel stopped", actor="system")

app = FastAPI(title="Management", lifespan=lifespan)
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
    return FileResponse(path, media_type=ctype)

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

@app.post("/api/login")
async def do_login(request: Request):
    ip = _client_ip(request)
    ua = request.headers.get("user-agent", "")
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    try:
        ok = await DB.run(DB.verify_admin, username, password)
        if not ok:
            ok = await DB.run(_verify_staff_login, username, password)
    except Exception as e:
        logging.error(f"verify_admin failed: {e}")
        ok = False
    if not ok:
        write_log("WARN", "AUTH", "Failed login", actor=username or "?", ip=ip,
                  detail=f"ua={ua[:120]}", status="denied")
        return JSONResponse(status_code=401, content={"error": "Invalid username or password."})
    sid = secrets.token_hex(16)
    token = _create_session_token(username, sid=sid)
    write_log("ACTION", "AUTH", "Login success", actor=username, ip=ip, detail=f"ua={ua[:120]}")
    resp = JSONResponse(content={"status": "ok"})
    # Path-scoped to MGMT_BASE: MainApp serves its own "session" cookie on the
    # same domain now, so an unscoped cookie here would clobber that one.
    resp.set_cookie("session", token, httponly=True, max_age=86400, samesite="lax",
                    secure=_is_https(request), path=_COOKIE_PATH)
    return resp

@app.get("/logout")
async def logout(request: Request):
    if _authed(request):
        write_log("ACTION", "AUTH", "Logout", actor=_admin_name(request), ip=_client_ip(request))
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

@app.post("/api/account/password")
async def api_account_password(request: Request):
    if not _authed(request):
        return _need_auth()
    username, ip = _admin_name(request), _client_ip(request)
    body = await _json_body(request)
    current = body.get("current_password") or ""
    new = body.get("new_password") or ""

    if not await DB.run(DB.verify_admin, username, current):
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
        if not await DB.run(_set_admin_password, username, new):
            return JSONResponse(status_code=500, content={"error": "Could not update the password."})
        await DB.run(_bump_auth_epoch)
    except Exception as e:
        logging.error(f"password change failed: {e}")
        return JSONResponse(status_code=500, content={"error": "Could not update the password."})

    write_log("ACTION", "AUTH", "Password changed", actor=username, ip=ip,
              detail="every other session was signed out")
    # The epoch bump just invalidated this browser's cookie too, hand it a new
    # one so the person who made the change is not signed out by their own action.
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie("session", _create_session_token(username), httponly=True,
                    max_age=86400, samesite="lax", secure=_is_https(request),
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
    return HTMLResponse(content=_dashboard_html(_is_mobile(request), _admin_name(request) or "admin", perms))

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
async def api_connections(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_detail"))
    if denied:
        return denied
    try:
        return await DB.run(System.net_connections)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/files")
async def api_files(request: Request, path: str = ""):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _can_browse)
    if denied:
        return denied
    try:
        return await DB.run(System.list_dir, path or None, _disk_root(perms))
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
        return panel_users.update_user(conn, username, **fields)
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

# ---- Config: Proxy (nginx reverse proxy hosts, admin only) ----
@app.get("/api/config/proxy/hosts")
async def api_proxy_list(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    return {"installed": nginx_proxy.nginx_installed(),
            "hosts": await DB.run(nginx_proxy.list_hosts)}

@app.post("/api/config/proxy/hosts")
async def api_proxy_create(request: Request):
    if not _authed(request):
        return _need_auth()
    perms, denied = await _require(request, _grant("net_proxy"))
    if denied:
        return denied
    body = await _json_body(request)
    domain = (body.get("domain") or "").strip()
    target = (body.get("target") or "").strip()
    websockets = bool(body.get("websockets"))
    try:
        await DB.run(nginx_proxy.create_host, domain, target, websockets)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except RuntimeError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    write_log("ACTION", "SYSTEM", "Created proxy host", actor=_admin_name(request),
              ip=_client_ip(request), target=domain, detail=f"-> {target}")
    return {"status": "ok"}

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

def _safe_int(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

class _ManagedTerm:
    def __init__(self, sid, persist, rows, cols, owner="", run_as=None):
        self.sid = sid
        self.persist = bool(persist)
        self.owner = owner
        self.run_as = run_as
        self.sess = System.PtySession(run_as=run_as)
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
    run_as = perms.get("os_username") if terminal_access == panel_users.TERMINAL_LIMITED else None
    is_admin = perms.get("role") == "admin"

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
        # guessing/reusing a session id -- start a fresh one instead.
        sid = secrets.token_hex(8)
        mt = None
    if mt is None:
        if not sid:
            sid = secrets.token_hex(8)
        try:
            mt = _ManagedTerm(sid, persist, rows, cols, owner=username, run_as=run_as)
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
    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="info")
    except (PermissionError, OSError) as e:
        logging.error(f"Bind {HOST}:{PORT} failed ({e}); falling back to :{FALLBACK_PORT}")
        SERVER_RUNTIME["port"] = FALLBACK_PORT
        uvicorn.run(app, host=HOST, port=FALLBACK_PORT, log_level="info")
