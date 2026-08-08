#!/usr/bin/env python3
# Management.py — standalone Server Management panel (systemd service: management).
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

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_PROJECT_DIR, "static_mgmt")

# Public path this panel is published under. MainApp owns the domain root
# (webview, webhook, bot admin), so nginx routes only <MGMT_BASE>/… here and
# strips the prefix before proxying — the routes below stay mounted at "/".
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
# Session token — the same scheme Main.py uses, signed with the SAME secret.
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

def _create_session_token(username: str = "admin", sid: str = None) -> str:
    if sid is None:
        sid = secrets.token_hex(16)
    payload = json.dumps({"exp": int(time.time()) + 86400,
                          "username": username, "sid": sid}).encode()
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
        return data if data.get("exp", 0) > int(time.time()) else None
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
    X-Real-IP — trustworthy only because it arrived over loopback."""
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
    public prefix before proxying. Reached directly — no proxy, or a proxy that
    forwards the prefix intact — the browser asks for "<MGMT_BASE>/login" and
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
# management_log — structured event/audit table owned by this panel.
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
# Management bind config — kept in its OWN system_settings keys so it never
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
# Front-end — reuses Main.py's CSS design system + icon sprite from static_mgmt.
# ===========================================================================
def _read_static(name: str) -> str:
    try:
        with open(os.path.join(_STATIC_DIR, name), encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logging.error(f"static read {name} failed: {e}")
        return ""

_ICON_SPRITE = _read_static("sprite.html")

_NAV = [("server", "Server", "ic-server"), ("services", "Services", "ic-sliders-horizontal"),
        ("terminal", "Terminal", "ic-monitor"), ("logs", "Logs", "ic-shield-alert")]

def _crest():
    return ('<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/>'
            '<rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/>'
            '<line x1="6" x2="6.01" y1="18" y2="18"/></svg>')

# The four panes are identical across shells (same IDs); only the chrome differs.
_PANES = """
<div class="mgmt-main">
  <!-- SERVER -->
  <div class="pane" data-pane="server"><div class="pane-scroll"><div class="server-inner">
    <div class="srv-grid">
      <div class="metric-card metric-clickable" onclick="openServerDetail('cpu')" title="Top processes by CPU">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-cpu"/></svg>CPU</span><span class="metric-now" id="m-cpu-now">0%</span></div>
        <canvas class="metric-chart" id="chart-cpu" height="70"></canvas>
        <div class="metric-foot" id="m-cpu-foot">&mdash;</div>
        <div class="core-bars" id="core-bars"></div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('mem')" title="Top processes by memory">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-memory-stick"/></svg>Memory</span><span class="metric-now" id="m-ram-now">0%</span></div>
        <canvas class="metric-chart" id="chart-ram" height="70"></canvas>
        <div class="metric-foot" id="m-ram-foot">&mdash;</div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('net')" title="Active connections">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-wifi"/></svg>Network</span><span class="metric-now" id="m-net-now">&darr;0 &uarr;0</span></div>
        <canvas class="metric-chart" id="chart-net" height="70"></canvas>
        <div class="metric-foot" id="m-net-foot">&mdash;</div>
      </div>
      <div class="metric-card metric-clickable" onclick="openServerDetail('disk')" title="Browse & download files">
        <div class="metric-head"><span class="metric-title"><svg class="ic"><use href="#ic-hard-drive"/></svg>Disk</span><span class="metric-now" id="m-disk-now">0%</span></div>
        <div class="disk-bar"><div class="disk-fill" id="disk-fill"></div></div>
        <div class="metric-foot" id="m-disk-foot">&mdash;</div>
        <div class="metric-head" style="margin-top:14px;"><span class="metric-title">Load avg</span><span class="metric-now" id="m-load-now">0.00</span></div>
        <div class="metric-foot" id="m-load-foot">1m / 5m / 15m</div>
      </div>
    </div>
    <div class="device-card">
      <div class="device-title">Device &amp; OS</div>
      <div class="device-grid" id="device-grid"><div class="empty-state">Loading device info&hellip;</div></div>
    </div>
    <div class="cfg-card" style="margin-top:18px;">
      <div class="device-title">Management Launch Configuration</div>
      <div class="settings-subtitle" style="margin:6px 0 18px;">Host &amp; port this panel binds (HTTP). Independent of Main.py. Applies on next restart of the <code>management</code> service.</div>
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
      <div class="device-title">SSH</div>
      <div class="settings-subtitle" style="margin:6px 0 16px;">Turn the server's SSH daemon on or off.
        <svg class="ic" style="color:var(--danger)"><use href="#ic-triangle-alert"/></svg> If SSH is your only way in, keep another route before disabling.</div>
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
        <span class="cfg-running" id="ssh-state">Checking&hellip;</span>
        <button class="save-btn" id="ssh-toggle-btn" onclick="toggleSsh()" disabled>&hellip;</button></div>
      <div class="save-feedback" id="ssh-feedback"></div>
    </div>
  </div></div></div>

  <!-- SERVICES -->
  <div class="pane" data-pane="services"><div class="pane-scroll">
    <div class="mgmt-h2">Systemd services</div>
    <div style="display:flex;gap:8px;margin-bottom:12px;align-items:center;">
      <input id="svc-search" class="field-input" style="max-width:240px;" placeholder="filter services&hellip;">
      <button class="db-action-btn" onclick="loadServices()"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button></div>
    <div id="svc-list"><div class="empty-state">Loading&hellip;</div></div>
  </div></div>

  <!-- TERMINAL -->
  <div class="pane" data-pane="terminal"><div class="pane-scroll">
    <div class="term-tabs" id="term-tabs">
      <button class="term-addbtn" id="term-add" title="Open another terminal" onclick="termAddTab()">+</button></div>
    <div class="term-stack" id="term-stack"></div>
  </div></div>

  <!-- LOGS -->
  <div class="pane" data-pane="logs"><div class="pane-scroll">
    <div class="srv-grid" id="sec-ssh-cards" style="margin-bottom:18px;">
      <div class="metric-card"><div class="metric-head"><span class="metric-title">SSH Total Events</span><span class="metric-now" id="sec-total">&mdash;</span></div><div class="metric-foot" id="sec-unique-ips">unique IPs: &mdash;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Successful Logins</span><span class="metric-now" style="color:#27ae60" id="sec-accepted">&mdash;</span></div><div class="metric-foot" id="sec-sessions">active sessions: &mdash;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Failed Attempts</span><span class="metric-now" style="color:#e74c3c" id="sec-failed">&mdash;</span></div><div class="metric-foot" id="sec-attackers">attacker IPs: &mdash;</div></div>
      <div class="metric-card"><div class="metric-head"><span class="metric-title">Web Login Attempts</span><span class="metric-now" id="sec-web-total">&mdash;</span></div><div class="metric-foot" id="sec-web-fail">failed: &mdash;</div></div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center;">
      <div style="font-weight:700;font-size:13px;">Section:</div>
      <button class="db-action-btn sec-section-btn active" data-sec="panel-actions" onclick="showSecSection('panel-actions')">Panel Actions</button>
      <button class="db-action-btn sec-section-btn" data-sec="ssh-sessions" onclick="showSecSection('ssh-sessions')">Active SSH Sessions</button>
      <button class="db-action-btn sec-section-btn" data-sec="ssh-events" onclick="showSecSection('ssh-events')">All SSH Events</button>
      <button class="db-action-btn sec-section-btn" data-sec="ssh-accepted" onclick="showSecSection('ssh-accepted')">Successful Logins</button>
      <button class="db-action-btn sec-section-btn" data-sec="ssh-fingerprints" onclick="showSecSection('ssh-fingerprints')">Key Fingerprints</button>
      <button class="db-action-btn sec-section-btn" data-sec="ssh-top-ips" onclick="showSecSection('ssh-top-ips')">Top IPs</button>
      <button class="db-action-btn sec-section-btn" data-sec="access-log" onclick="showSecSection('access-log')">Access Log</button>
      <button class="db-action-btn sec-section-btn" data-sec="web-sessions" onclick="showSecSection('web-sessions')">Sessions</button>
      <button class="db-action-btn sec-section-btn" data-sec="web-logs" onclick="showSecSection('web-logs')">Web Login Logs</button>
      <button class="db-action-btn sec-section-btn" data-sec="web-blocked" onclick="showSecSection('web-blocked')">Blocked IPs</button>
      <button class="db-action-btn sec-section-btn" data-sec="fp-blocked" onclick="showSecSection('fp-blocked')">Blocked Devices</button>
      <button class="db-action-btn" onclick="loadSecurityLogs()" style="margin-left:auto;"><svg class="ic"><use href="#ic-refresh-cw"/></svg>Refresh</button>
      <select id="sec-since-sel" onchange="loadSecurityLogs()" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);">
        <option value="">Last 200 events</option><option value="today">Today</option><option value="yesterday">Yesterday</option><option value="7 days ago">Last 7 days</option></select>
    </div>
    <div id="sec-content"><div class="empty-state">Loading security logs&hellip;</div></div>
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

def _mobile_tabbar():
    items = "".join(
        f'<button class="mtab" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg><span>{label}</span></button>'
        for k, label, ic in _NAV)
    return f'<nav class="mobile-tabbar" style="grid-template-columns:repeat({len(_NAV)},1fr);">{items}</nav>'

def _topbar(mobile: bool, user: str):
    tabs = "".join(
        f'<button class="tab-btn" data-nav="{k}"><svg class="ic"><use href="#{ic}"/></svg>{label}</button>'
        for k, label, ic in _NAV)
    right = (
        '<button class="theme-btn" onclick="toggleTheme()" title="Toggle dark mode"><svg class="ic"><use href="#ic-moon" id="theme-ic"/></svg></button>'
        f'<span class="muted" style="font-size:12px;color:var(--gray-500);">{user}</span>'
        f'<a href="{MGMT_BASE}/logout" class="db-action-btn"><svg class="ic"><use href="#ic-log-out"/></svg>Logout</a>'
    )
    return (
        '<div class="mgmt-top">'
        f'<div class="mgmt-brand"><span class="mgmt-crest">{_crest()}</span>Management</div>'
        f'<div class="mgmt-tabs">{tabs}</div>'
        f'<div class="mgmt-right">{right}</div>'
        '</div>'
    )

def _dashboard_html(mobile: bool, user: str) -> str:
    shell = "mgmt-mobile" if mobile else "mgmt-desktop"
    return (
        "<!DOCTYPE html><html lang=\"en\"><head>"
        "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        f"<title>Management</title><link rel=\"stylesheet\" href=\"{MGMT_BASE}/static/dash.css\">"
        f"<script>window.MGMT_BASE={json.dumps(MGMT_BASE)};</script></head>"
        f"<body class=\"mgmt {shell}\">{_ICON_SPRITE}"
        f"{_topbar(mobile, user)}{_PANES}{_mobile_tabbar()}"
        f"<script src=\"{MGMT_BASE}/static/management.js\"></script></body></html>"
    )

def _is_mobile(request: Request) -> bool:
    ua = request.headers.get("user-agent", "").lower()
    return any(t in ua for t in ("mobi", "android", "iphone", "ipod", "windows phone"))

# Login page — warm palette via the shared stylesheet, same /api/login flow.
# __BASE__ is substituted with MGMT_BASE by _login_html().
_LOGIN_HTML = """<!DOCTYPE html><html lang="en"><head>
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
</style></head><body class="login">
<div class="box">
  <div class="crest"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="10" width="18" height="12" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/><circle cx="12" cy="16" r="1"/></svg></div>
  <div class="brand">Management</div><div class="sub">Authorized access only</div>
  <form id="lf">
    <div class="fg"><label class="fl" for="u">Username</label><input class="fi" id="u" type="text" autofocus autocomplete="username" spellcheck="false"></div>
    <div class="fg"><label class="fl" for="p">Password</label><input class="fi" id="p" type="password" autocomplete="current-password"></div>
    <button class="btn2" type="submit" id="sbtn">Sign in</button><div class="err" id="err"></div>
  </form>
</div>
<script>
  if(localStorage.getItem('theme')==='dark') document.documentElement.setAttribute('data-theme','dark');
  document.getElementById('lf').addEventListener('submit', async function(e){
    e.preventDefault(); const b=document.getElementById('sbtn'), er=document.getElementById('err'); b.disabled=true; er.textContent='';
    try{ const res=await fetch('__BASE__/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:document.getElementById('u').value.trim(),password:document.getElementById('p').value})});
      const d=await res.json(); if(d.status==='ok'){ location.href='__BASE__/'; } else { er.textContent=d.error||'Invalid username or password.'; b.disabled=false; }
    }catch(_){ er.textContent='Network error — please try again.'; b.disabled=false; }
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

# ---- dashboard ----
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not _authed(request):
        return RedirectResponse(url=f"{MGMT_BASE}/login", status_code=302)
    return HTMLResponse(content=_dashboard_html(_is_mobile(request), _admin_name(request) or "admin"))

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
    try:
        return await DB.run(System.top_processes, "mem" if by == "mem" else "cpu")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/connections")
async def api_connections(request: Request):
    if not _authed(request):
        return _need_auth()
    try:
        return await DB.run(System.net_connections)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/files")
async def api_files(request: Request, path: str = "/"):
    if not _authed(request):
        return _need_auth()
    try:
        return await DB.run(System.list_dir, path)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/download")
async def api_download(request: Request, path: str = ""):
    if not _authed(request):
        return _need_auth()
    full, reason = System.resolve_download(path)
    if reason == "not_found":
        return JSONResponse(status_code=404, content={"error": "not found"})
    if reason == "blocked":
        return JSONResponse(status_code=403, content={"error": "download blocked"})
    write_log("ACTION", "SYSTEM", "File download", actor=_admin_name(request),
              ip=_client_ip(request), target=full[:200])
    return FileResponse(full, filename=os.path.basename(full), media_type="application/octet-stream")

# ---- management bind config ----
@app.get("/api/system/config")
async def api_config_get(request: Request):
    if not _authed(request):
        return _need_auth()
    return mgmt_config_view()

@app.post("/api/system/config")
async def api_config_set(request: Request):
    if not _authed(request):
        return _need_auth()
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
    return await DB.run(list_services)

@app.get("/api/services/{name}")
async def api_service_detail(request: Request, name: str):
    if not _authed(request):
        return _need_auth()
    return await DB.run(service_detail, name)

@app.post("/api/services/{name}/{action}")
async def api_service_action(request: Request, name: str, action: str):
    if not _authed(request):
        return _need_auth()
    ok, message = await DB.run(control_service, name, action)
    write_log("ACTION" if ok else "ERROR", "SERVICE", f"{action} service",
              actor=_admin_name(request), ip=_client_ip(request), target=name,
              detail=message[:1000], status="ok" if ok else "failed")
    return {"ok": ok, "message": message}

# ---- structured panel logs ----
@app.get("/api/logs")
async def api_logs(request: Request, level: str = "", category: str = "", q: str = "", limit: int = 200):
    if not _authed(request):
        return _need_auth()
    return {"logs": await DB.run(query_logs, level, category, q, limit)}

@app.get("/api/logs/counts")
async def api_logs_counts(request: Request):
    if not _authed(request):
        return _need_auth()
    return await DB.run(log_counts)

# ---- SSH / security logs (shared elink tables, via DB.py) ----
@app.get("/api/system/ssh-logs")
async def api_ssh_logs(request: Request, since: str = "", limit: int = 200):
    if not _authed(request):
        return _need_auth()
    try:
        return await DB.run(_parse_ssh_journal, since or None, limit)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/api/system/ssh-sessions")
async def api_ssh_sessions(request: Request):
    if not _authed(request):
        return _need_auth()
    return {"sessions": await DB.run(_get_current_ssh_sessions)}

@app.get("/api/system/web-login-logs")
async def api_web_login_logs(request: Request, page: int = 1, limit: int = 50):
    if not _authed(request):
        return _need_auth()
    return await DB.run(DB.get_web_login_logs, page, limit)

@app.get("/api/system/web-blocked-ips")
async def api_web_blocked_ips(request: Request):
    if not _authed(request):
        return _need_auth()
    return {"blocked": await DB.run(DB.get_web_blocked_ips)}

@app.post("/api/system/web-unblock")
async def api_web_unblock(request: Request):
    if not _authed(request):
        return _need_auth()
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
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    hours = int(body.get("hours") or 8760)
    note = (body.get("note") or "Manually blocked").strip()
    if not ip:
        return JSONResponse(status_code=400, content={"error": "ip required"})
    await DB.run(DB.block_web_ip, ip, hours, note)
    write_log("ACTION", "SECURITY", "Block web IP", actor=_admin_name(request),
              ip=_client_ip(request), target=ip, detail=f"{hours}h — {note}")
    return {"status": "blocked", "ip": ip, "hours": hours}

@app.get("/api/system/access-log")
async def api_access_log(request: Request, page: int = 1, limit: int = 100, ip: str = "", path: str = ""):
    if not _authed(request):
        return _need_auth()
    return await DB.run(DB.get_http_access_logs, page, min(limit, 500), ip, path)

@app.get("/api/system/access-log-entry")
async def api_access_log_entry(request: Request, id: int):
    if not _authed(request):
        return _need_auth()
    entry = await DB.run(DB.get_http_access_entry, id)
    if not entry:
        return JSONResponse(status_code=404, content={"error": "Entry not found"})
    return entry

@app.get("/api/system/web-sessions")
async def api_web_sessions(request: Request, limit: int = 100):
    if not _authed(request):
        return _need_auth()
    return await DB.run(DB.get_web_sessions, limit)

@app.get("/api/system/ip-profile")
async def api_ip_profile(request: Request, ip: str = ""):
    if not _authed(request):
        return _need_auth()
    if not (ip or "").strip():
        return JSONResponse(status_code=400, content={"error": "ip required"})
    return await DB.run(DB.get_ip_profile, ip.strip())

@app.get("/api/system/log-counts")
async def api_security_log_counts(request: Request):
    if not _authed(request):
        return _need_auth()
    return await DB.run(DB.get_security_log_counts)

@app.post("/api/system/clear-log")
async def api_clear_log(request: Request):
    if not _authed(request):
        return _need_auth()
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
    return {"blocked": await DB.run(DB.get_fp_blocked)}

@app.post("/api/system/fp-unblock")
async def api_fp_unblock(request: Request):
    if not _authed(request):
        return _need_auth()
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
    if not (ip or "").strip():
        return JSONResponse(status_code=400, content={"error": "ip required"})
    return await DB.run(DB.get_ssh_attacker_detail, ip.strip())

@app.post("/api/system/ssh-block")
async def api_ssh_block(request: Request):
    if not _authed(request):
        return _need_auth()
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip or not re.match(r"^[0-9a-fA-F:.]+$", ip):
        return JSONResponse(status_code=400, content={"error": "valid ip required"})
    enforced, detail = False, ""
    try:
        check = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if check.returncode != 0:
            add = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
            enforced = add.returncode == 0
            detail = (add.stderr or "").strip()
        else:
            enforced, detail = True, "rule already present"
    except FileNotFoundError:
        detail = "iptables not available on this host"
    except Exception as e:
        detail = str(e)
    write_log("ACTION" if enforced else "WARN", "SECURITY", "Block SSH IP (firewall)",
              actor=_admin_name(request), ip=_client_ip(request), target=ip,
              detail=detail, status="ok" if enforced else "failed")
    return {"status": "blocked" if enforced else "recorded", "ip": ip,
            "firewall_enforced": enforced, "detail": detail}

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
    def __init__(self, sid, persist, rows, cols):
        self.sid = sid
        self.persist = bool(persist)
        self.sess = System.PtySession()
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
    if _get_token_data(websocket.cookies.get("session", "")) is None:
        await websocket.close(code=1008)
        return
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
    if mt is None:
        if not sid:
            sid = secrets.token_hex(8)
        try:
            mt = _ManagedTerm(sid, persist, rows, cols)
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
