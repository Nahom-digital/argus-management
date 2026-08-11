# Telegram bot control: run this panel from a chat.
#
# Telegram delivers updates to one HTTPS endpoint, so the bot is wired up by
# pointing setWebhook at <your domain>/bot and letting the same nginx and
# Cloudflare front door that serves the panel carry the traffic. Nothing new is
# opened on the firewall.
#
# Two things make it safe to expose a chat to a server:
#
#   1. Telegram sends a secret token header on every delivery, generated here
#      and never shown after it is set. A POST without it is dropped.
#   2. No chat can do anything until an admin allows its numeric Telegram ID.
#      Every message from a stranger is written to the conversation log with the
#      ID attached, which is where the admin picks it up and allows it.
#
# An allowed chat is either an admin (everything the panel can do) or a normal
# user bound to a panel account, in which case the exact same grant registry
# that gates the web interface gates the chat. There is deliberately no separate
# permission model here: /help is generated from what the grants resolve to, so
# the bot cannot offer a command the account is not allowed to run.
#
# Mirrors the shape of the other helper modules: its own SCHEMA tuple, plain
# functions taking an already-open connection, no pool of its own.
import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import mail
import panel_users
import System

API_ROOT = "https://api.telegram.org"

# system_settings keys. Runtime configuration, so changing the token never means
# editing a file or restarting the service.
S_TOKEN = "tg_bot_token"
S_DOMAIN = "tg_domain"
S_SECRET = "tg_webhook_secret"
S_ENABLED = "tg_enabled"
S_NOTIFY = "tg_notify_email"
S_HOOK_AT = "tg_webhook_at"
S_HOOK_URL = "tg_webhook_url"

WEBHOOK_PATH = "/bot"

ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_BLOCKED = "blocked"
ROLES = (ROLE_ADMIN, ROLE_USER, ROLE_BLOCKED)

LOG_LIMIT = 200
MSG_LIMIT = 3800          # Telegram caps a message at 4096 characters
SHELL_TIMEOUT = 45

_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS tg_user (
        id           SERIAL PRIMARY KEY,
        telegram_id  BIGINT UNIQUE NOT NULL,
        tg_username  VARCHAR(64) NOT NULL DEFAULT '',
        display_name VARCHAR(160) NOT NULL DEFAULT '',
        role         VARCHAR(16) NOT NULL DEFAULT 'user',
        panel_user   VARCHAR(100) NOT NULL DEFAULT '',
        chat_id      BIGINT NOT NULL DEFAULT 0,
        allowed_by   VARCHAR(100) NOT NULL DEFAULT '',
        allowed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen    TIMESTAMPTZ
    )""",
    """CREATE TABLE IF NOT EXISTS tg_log (
        id           SERIAL PRIMARY KEY,
        ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
        telegram_id  BIGINT NOT NULL DEFAULT 0,
        tg_username  VARCHAR(64) NOT NULL DEFAULT '',
        display_name VARCHAR(160) NOT NULL DEFAULT '',
        chat_id      BIGINT NOT NULL DEFAULT 0,
        direction    VARCHAR(4) NOT NULL DEFAULT 'in',
        text         TEXT NOT NULL DEFAULT '',
        allowed      BOOLEAN NOT NULL DEFAULT FALSE,
        detail       VARCHAR(200) NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS idx_tg_log_ts ON tg_log(id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_tg_log_who ON tg_log(telegram_id)",
)


# ------------------------------------------------------------------ settings
def _get(conn, key, default=""):
    cur = conn.cursor()
    cur.execute("SELECT value FROM system_settings WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()
    return row[0] if row and row[0] is not None else default


def _put(conn, key, value):
    cur = conn.cursor()
    cur.execute("""INSERT INTO system_settings (key, value) VALUES (%s, %s)
                   ON CONFLICT (key) DO UPDATE
                   SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP""",
                (key, str(value)))
    cur.close()


def token(conn):
    """The bot token itself. Stays inside this module."""
    return _get(conn, S_TOKEN, "")


def webhook_secret(conn):
    return _get(conn, S_SECRET, "")


def enabled(conn):
    return _get(conn, S_ENABLED, "0") == "1"


def config(conn):
    """What the interface may see: whether a token is set, never the token."""
    tok = token(conn)
    domain = _get(conn, S_DOMAIN, "")
    return {
        "token_set": bool(tok),
        "token_hint": ("…" + tok[-4:]) if len(tok) > 6 else "",
        "domain": domain,
        "enabled": enabled(conn),
        "notify_email": _get(conn, S_NOTIFY, ""),
        "webhook_url": _get(conn, S_HOOK_URL, ""),
        "webhook_at": str(_get(conn, S_HOOK_AT, ""))[:19],
        "secret_set": bool(webhook_secret(conn)),
        "suggested_url": (f"https://{domain}{WEBHOOK_PATH}" if domain else ""),
    }


def set_config(conn, bot_token=None, domain=None, notify_email=None, actor=""):
    """Store what the operator typed. An empty token means "leave it alone", so
    the field can stay blank on a page that never shows the stored value."""
    if bot_token:
        bot_token = bot_token.strip()
        if not _TOKEN_RE.match(bot_token):
            return False, ("That does not look like a bot token. BotFather hands "
                           "you digits, a colon, then a long random string.")
        _put(conn, S_TOKEN, bot_token)
    if domain is not None:
        domain = domain.strip().lower().rstrip("/")
        domain = re.sub(r"^https?://", "", domain).split("/")[0]
        if domain and not _DOMAIN_RE.match(domain):
            return False, "That is not a domain name this bot can be reached on."
        _put(conn, S_DOMAIN, domain)
    if notify_email is not None:
        notify_email = notify_email.strip().lower()
        if notify_email and mail.address_problem(notify_email):
            return False, mail.address_problem(notify_email)
        _put(conn, S_NOTIFY, notify_email)
    return True, "Saved."


# ------------------------------------------------------------- telegram calls
def call(conn_token, method, payload=None, timeout=20):
    """One Bot API call. Returns (ok, result_or_reason).

    Telegram answers with its own ok/description envelope even on an HTTP error,
    so the description is dug out and returned as the reason rather than raising
    something the page cannot show.
    """
    if not conn_token:
        return False, "No bot token is set yet."
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        f"{API_ROOT}/bot{conn_token}/{method}", data=data,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode() or "{}")
        except Exception:
            return False, f"Telegram answered HTTP {e.code}."
        return False, body.get("description") or f"Telegram answered HTTP {e.code}."
    except urllib.error.URLError as e:
        return False, f"Telegram could not be reached: {e.reason}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    if not body.get("ok"):
        return False, body.get("description") or "Telegram refused the call."
    return True, body.get("result")


def send_message(conn, chat_id, text, quiet=False):
    """Reply into a chat, splitting anything Telegram would refuse to carry."""
    tok = token(conn)
    if not tok or not chat_id:
        return False
    ok = True
    for chunk in _chunks(text):
        good, _ = call(tok, "sendMessage", {
            "chat_id": chat_id, "text": chunk,
            "parse_mode": "HTML", "disable_notification": bool(quiet),
        })
        ok = ok and good
    return ok


def _chunks(text):
    text = text or ""
    while len(text) > MSG_LIMIT:
        cut = text.rfind("\n", 0, MSG_LIMIT)
        if cut < MSG_LIMIT // 2:
            cut = MSG_LIMIT
        yield text[:cut]
        text = text[cut:]
    yield text or "."


def identity(conn):
    """getMe, so the operator can see the token belongs to the bot they meant."""
    tok = token(conn)
    if not tok:
        return {"ok": False, "detail": "No bot token is set yet."}
    ok, res = call(tok, "getMe")
    if not ok:
        return {"ok": False, "detail": res}
    return {"ok": True, "username": res.get("username", ""),
            "name": res.get("first_name", ""), "id": res.get("id", 0)}


def webhook_info(conn):
    tok = token(conn)
    if not tok:
        return {"ok": False, "detail": "No bot token is set yet."}
    ok, res = call(tok, "getWebhookInfo")
    if not ok:
        return {"ok": False, "detail": res}
    return {"ok": True, "url": res.get("url", ""),
            "pending": res.get("pending_update_count", 0),
            "last_error": res.get("last_error_message", ""),
            "ip": res.get("ip_address", "")}


def install_webhook(conn, actor=""):
    """Point Telegram at <domain>/bot and turn the bot on.

    The secret token is minted here and handed to Telegram in the same call, so
    the value on our side and the value Telegram will send back can never drift
    apart.
    """
    tok = token(conn)
    if not tok:
        return False, "Set the bot token first."
    domain = _get(conn, S_DOMAIN, "")
    if not domain:
        return False, "Set the domain this panel is reachable on first."
    url = f"https://{domain}{WEBHOOK_PATH}"
    secret = secrets.token_urlsafe(32).replace("-", "_")[:60]
    ok, res = call(tok, "setWebhook", {
        "url": url, "secret_token": secret, "max_connections": 20,
        "allowed_updates": ["message", "edited_message", "callback_query"],
        "drop_pending_updates": True,
    })
    if not ok:
        return False, res
    _put(conn, S_SECRET, secret)
    _put(conn, S_HOOK_URL, url)
    _put(conn, S_ENABLED, "1")
    _put(conn, S_HOOK_AT, time.strftime("%Y-%m-%d %H:%M:%S"))
    notify(conn, "Telegram bot connected",
           f"The bot now receives updates at {url}.\nConnected by {actor or 'an admin'}.")
    return True, f"Telegram will deliver updates to {url}."


def remove_webhook(conn, actor=""):
    tok = token(conn)
    if not tok:
        return False, "No bot token is set yet."
    ok, res = call(tok, "deleteWebhook", {"drop_pending_updates": True})
    if not ok:
        return False, res
    _put(conn, S_ENABLED, "0")
    _put(conn, S_HOOK_URL, "")
    _put(conn, S_SECRET, "")
    return True, "The bot no longer receives anything."


def status(conn):
    """Everything the Telegram card shows in one round trip."""
    out = config(conn)
    out["identity"] = identity(conn) if out["token_set"] else {"ok": False, "detail": ""}
    out["webhook"] = webhook_info(conn) if out["token_set"] else {"ok": False, "detail": ""}
    out["users"] = users(conn)
    out["log"] = recent(conn)
    out["pending"] = pending(conn)
    return out


# ---------------------------------------------------------------- the roster
def _row_user(row):
    return {"telegram_id": row[0], "tg_username": row[1], "display_name": row[2],
            "role": row[3], "panel_user": row[4], "chat_id": row[5],
            "allowed_by": row[6], "allowed_at": str(row[7] or "")[:19],
            "last_seen": str(row[8] or "")[:19]}


_USER_COLS = ("telegram_id, tg_username, display_name, role, panel_user, "
              "chat_id, allowed_by, allowed_at, last_seen")


def users(conn):
    cur = conn.cursor()
    cur.execute(f"SELECT {_USER_COLS} FROM tg_user ORDER BY role, telegram_id")
    rows = [_row_user(r) for r in cur.fetchall()]
    cur.close()
    return rows


def find(conn, telegram_id):
    cur = conn.cursor()
    cur.execute(f"SELECT {_USER_COLS} FROM tg_user WHERE telegram_id = %s",
                (int(telegram_id),))
    row = cur.fetchone()
    cur.close()
    return _row_user(row) if row else None


def allow(conn, telegram_id, role=ROLE_USER, panel_user="", actor=""):
    """Let one Telegram ID in, at one role.

    The ID is taken from the conversation log, which is the only place a
    stranger's ID is ever written down, so allowing somebody is a deliberate act
    against a message they actually sent.
    """
    try:
        telegram_id = int(str(telegram_id).strip())
    except (TypeError, ValueError):
        return False, "A Telegram ID is a number."
    if role not in ROLES:
        return False, "Role must be admin, user or blocked."
    panel_user = (panel_user or "").strip()[:100]
    seen = _last_seen_identity(conn, telegram_id)
    cur = conn.cursor()
    cur.execute("""INSERT INTO tg_user (telegram_id, tg_username, display_name,
                                        role, panel_user, chat_id, allowed_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (telegram_id) DO UPDATE
                   SET role = EXCLUDED.role,
                       panel_user = EXCLUDED.panel_user,
                       allowed_by = EXCLUDED.allowed_by,
                       allowed_at = now(),
                       tg_username = CASE WHEN EXCLUDED.tg_username <> ''
                                          THEN EXCLUDED.tg_username
                                          ELSE tg_user.tg_username END,
                       display_name = CASE WHEN EXCLUDED.display_name <> ''
                                           THEN EXCLUDED.display_name
                                           ELSE tg_user.display_name END""",
                (telegram_id, seen.get("tg_username", ""), seen.get("display_name", ""),
                 role, panel_user, seen.get("chat_id", 0), actor))
    cur.close()
    word = {ROLE_ADMIN: "full admin access", ROLE_USER: "user access",
            ROLE_BLOCKED: "no access at all"}[role]
    notify(conn, f"Telegram access changed for {telegram_id}",
           f"{actor or 'An admin'} gave Telegram ID {telegram_id} {word}"
           + (f", bound to the panel account {panel_user}." if panel_user else "."))
    if role != ROLE_BLOCKED and seen.get("chat_id"):
        send_message(conn, seen["chat_id"],
                     "You have been allowed to use this bot. Send /help to see "
                     "what you can do.")
    return True, f"Telegram ID {telegram_id} now has {word}."


def revoke(conn, telegram_id, actor=""):
    cur = conn.cursor()
    cur.execute("DELETE FROM tg_user WHERE telegram_id = %s", (int(telegram_id),))
    gone = cur.rowcount
    cur.close()
    if not gone:
        return False, "That ID was not on the list."
    notify(conn, f"Telegram access removed for {telegram_id}",
           f"{actor or 'An admin'} removed Telegram ID {telegram_id} from the bot.")
    return True, f"Telegram ID {telegram_id} can no longer use the bot."


def _last_seen_identity(conn, telegram_id):
    cur = conn.cursor()
    cur.execute("""SELECT tg_username, display_name, chat_id FROM tg_log
                   WHERE telegram_id = %s ORDER BY id DESC LIMIT 1""",
                (int(telegram_id),))
    row = cur.fetchone()
    cur.close()
    if not row:
        return {}
    return {"tg_username": row[0] or "", "display_name": row[1] or "",
            "chat_id": row[2] or 0}


# ------------------------------------------------------- the conversation log
def record(conn, direction, telegram_id, text, tg_username="", display_name="",
           chat_id=0, allowed=False, detail=""):
    cur = conn.cursor()
    cur.execute("""INSERT INTO tg_log (telegram_id, tg_username, display_name,
                                       chat_id, direction, text, allowed, detail)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (int(telegram_id or 0), (tg_username or "")[:64],
                 (display_name or "")[:160], int(chat_id or 0), direction,
                 (text or "")[:4000], bool(allowed), (detail or "")[:200]))
    cur.close()


def recent(conn, limit=LOG_LIMIT, telegram_id=None):
    """Every message this bot has seen, newest first. This is the log the admin
    reads to find out who is knocking, and the ID they allow from."""
    limit = max(1, min(int(limit or LOG_LIMIT), 1000))
    cur = conn.cursor()
    if telegram_id:
        cur.execute("""SELECT id, ts, telegram_id, tg_username, display_name,
                              chat_id, direction, text, allowed, detail
                       FROM tg_log WHERE telegram_id = %s
                       ORDER BY id DESC LIMIT %s""", (int(telegram_id), limit))
    else:
        cur.execute("""SELECT id, ts, telegram_id, tg_username, display_name,
                              chat_id, direction, text, allowed, detail
                       FROM tg_log ORDER BY id DESC LIMIT %s""", (limit,))
    rows = [{"id": r[0], "ts": str(r[1] or "")[:19], "telegram_id": r[2],
             "tg_username": r[3], "display_name": r[4], "chat_id": r[5],
             "direction": r[6], "text": r[7], "allowed": r[8], "detail": r[9]}
            for r in cur.fetchall()]
    cur.close()
    return rows


def pending(conn):
    """IDs that have written to the bot and are on nobody's list yet."""
    cur = conn.cursor()
    cur.execute("""SELECT l.telegram_id, MAX(l.tg_username), MAX(l.display_name),
                          MAX(l.chat_id), COUNT(*), MAX(l.ts)
                   FROM tg_log l
                   LEFT JOIN tg_user u ON u.telegram_id = l.telegram_id
                   WHERE u.id IS NULL AND l.direction = 'in' AND l.telegram_id <> 0
                   GROUP BY l.telegram_id ORDER BY MAX(l.ts) DESC LIMIT 50""")
    rows = [{"telegram_id": r[0], "tg_username": r[1] or "",
             "display_name": r[2] or "", "chat_id": r[3] or 0,
             "messages": r[4], "last_seen": str(r[5] or "")[:19]}
            for r in cur.fetchall()]
    cur.close()
    return rows


def clear_log(conn):
    cur = conn.cursor()
    cur.execute("DELETE FROM tg_log")
    cur.close()
    return True, "Conversation log cleared."


# ------------------------------------------------------------- notifications
def notify(conn, subject, body):
    """Send one email about something the bot did.

    Best effort on purpose: a mail relay that is down must never stop a command
    from running or an admin from allowing somebody.
    """
    try:
        to_addr = _get(conn, S_NOTIFY, "")
        if not to_addr:
            return False
        boxes = mail.boxes(conn)
        if not boxes:
            return False
        sender = boxes[0]["address"]
        route = "internal" if any(b["address"] == to_addr for b in boxes) else "external"
        ok, _detail, _route = mail.send(conn, sender, to_addr, f"[Argus bot] {subject}",
                                        body, route, actor="telegram-bot")
        return ok
    except Exception:
        return False


# ------------------------------------------------------------- permissions
def _permissions(conn, person):
    """What this chat may do, in exactly the terms the web panel uses.

    An admin resolves to every grant at its widest, the same object the web
    session for the primary admin gets. A normal user bound to a panel account
    resolves through that account, so revoking a grant in User Management
    revokes it in the chat at the same moment. A normal user bound to nothing
    gets no grants at all, which leaves them the identity commands and nothing
    else.
    """
    if person["role"] == ROLE_ADMIN:
        perms = dict(panel_users.all_grants(True))
        perms.update({"role": "admin", "username": person.get("panel_user") or "admin",
                      "os_username": None})
        return perms
    if person.get("panel_user"):
        try:
            return panel_users.resolve_permissions(conn, person["panel_user"])
        except Exception:
            pass
    perms = panel_users.no_permissions()
    perms = dict(perms)
    perms["username"] = person.get("panel_user") or f"tg:{person['telegram_id']}"
    return perms


def _is_admin(perms):
    return perms.get("role") == "admin"


# ------------------------------------------------------------- the commands
#
# One row per command: the word, who may run it, the one-line help, and the
# handler. The help text is filtered through the same check that runs the
# command, so /help can never advertise something the caller would be refused.
def _allowed_always(perms):
    return True


def _needs(key):
    return lambda perms: bool(perms.get(key))


def _needs_terminal(perms):
    return perms.get("terminal", panel_users.TERMINAL_NONE) != panel_users.TERMINAL_NONE


COMMANDS = []


def command(word, check, usage, help_text):
    def wrap(fn):
        COMMANDS.append({"word": word, "check": check, "usage": usage,
                         "help": help_text, "fn": fn})
        return fn
    return wrap


class _Ctx:
    """Everything a handler is allowed to know about the message it answers."""

    def __init__(self, conn, person, perms, chat_id, args, raw):
        self.conn = conn
        self.person = person
        self.perms = perms
        self.chat_id = chat_id
        self.args = args
        self.raw = raw


def _esc(text):
    return (str(text or "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _pre(text):
    text = (text or "").strip() or "(no output)"
    return f"<pre>{_esc(text[:MSG_LIMIT - 100])}</pre>"


@command("/start", _allowed_always, "/start", "Say hello and show who you are.")
def _cmd_start(ctx):
    return (f"<b>Argus management</b>\nYou are signed in as "
            f"<b>{_esc(ctx.perms.get('username'))}</b> "
            f"({'admin' if _is_admin(ctx.perms) else 'user'}).\n"
            "Send /help for everything you can do here.")


@command("/help", _allowed_always, "/help", "List every command you may run.")
def _cmd_help(ctx):
    lines = ["<b>What you can do here</b>"]
    for spec in COMMANDS:
        if spec["check"](ctx.perms):
            lines.append(f"<code>{_esc(spec['usage'])}</code>\n   {_esc(spec['help'])}")
    hidden = [s for s in COMMANDS if not s["check"](ctx.perms)]
    if hidden:
        lines.append(f"\n{len(hidden)} more command(s) exist that your account is "
                     "not allowed to run. An admin can widen your permissions in "
                     "the panel under User Management.")
    return "\n".join(lines)


@command("/id", _allowed_always, "/id", "Show your Telegram ID and this chat's ID.")
def _cmd_id(ctx):
    return (f"Your Telegram ID is <code>{ctx.person['telegram_id']}</code>\n"
            f"This chat is <code>{ctx.chat_id}</code>")


@command("/whoami", _allowed_always, "/whoami",
         "Show your role and every permission you hold.")
def _cmd_whoami(ctx):
    perms = ctx.perms
    lines = [f"<b>{_esc(perms.get('username'))}</b>",
             f"Role: {'admin' if _is_admin(perms) else 'user'}",
             f"Telegram ID: <code>{ctx.person['telegram_id']}</code>",
             f"Panel account: {_esc(ctx.person.get('panel_user') or 'not linked')}",
             "", "<b>Permissions</b>"]
    for g in panel_users.PERMISSIONS:
        value = perms.get(g.key)
        if g.kind == "choice":
            lines.append(f"{_esc(g.label)}: {_esc(value)}")
        else:
            lines.append(f"{'yes' if value else 'no'}  {_esc(g.label)}")
    return "\n".join(lines)


@command("/status", _needs("cpumem_detail"), "/status",
         "CPU, memory, disk and uptime for this server.")
def _cmd_status(ctx):
    s = System.live_stats()
    st = System.static_info()
    ram = s.get("ram") or {}
    disk = s.get("disk") or {}
    load = s.get("load") or {}
    up = int(s.get("uptime_seconds") or st.get("uptime_seconds") or 0)
    return ("<b>Server</b>\n"
            f"Host: {_esc(st.get('hostname', ''))}\n"
            f"System: {_esc(st.get('os_full') or st.get('distro', ''))}\n"
            f"CPU: {s.get('cpu_percent', 0)}%\n"
            f"Memory: {ram.get('percent', 0)}% of {_esc(ram.get('total_h', ''))}\n"
            f"Disk: {disk.get('percent', 0)}% of {_esc(disk.get('total_h', ''))}\n"
            f"Load: {load.get('1', 0)} {load.get('5', 0)} {load.get('15', 0)}\n"
            f"Uptime: {up // 86400}d {(up % 86400) // 3600}h {(up % 3600) // 60}m")


@command("/services", _needs("svc_status"), "/services [filter]",
         "List systemd services and whether they are running.")
def _cmd_services(ctx):
    import panel
    needle = (ctx.args[0].lower() if ctx.args else "")
    rows = (panel.list_services() or {}).get("services", [])
    if needle:
        rows = [r for r in rows if needle in r.get("name", "").lower()]
    if not rows:
        return "No service matched."
    rows = rows[:60]
    out = [f"{'up  ' if r.get('active') == 'active' else 'down'} {_esc(r.get('name'))}"
           for r in rows]
    return "<b>Services</b>\n" + "\n".join(out)


@command("/service", _needs("svc_status"), "/service <name> <status|start|restart|stop>",
         "Inspect or control one service. Starting and stopping need their own permission.")
def _cmd_service(ctx):
    import panel
    if len(ctx.args) < 1:
        return "Usage: /service &lt;name&gt; &lt;status|start|restart|stop&gt;"
    name = ctx.args[0]
    action = (ctx.args[1] if len(ctx.args) > 1 else "status").lower()
    if action == "status":
        d = panel.service_detail(name)
        return (f"<b>{_esc(name)}</b>\n{_esc(d.get('active', ''))} / "
                f"{_esc(d.get('sub', ''))}\n{_pre(d.get('status', ''))}")
    if action in ("start", "restart") and not ctx.perms.get("svc_restart"):
        return "You are not allowed to start services."
    if action == "stop" and not ctx.perms.get("svc_stop"):
        return "You are not allowed to stop services."
    if action not in ("start", "restart", "stop"):
        return "Action must be status, start, restart or stop."
    ok, detail = panel.control_service(name, action)
    return f"{'Done' if ok else 'Refused'}: {_esc(detail or action)}"


@command("/logs", _needs("logs_access"), "/logs [count]",
         "The most recent management log entries.")
def _cmd_logs(ctx):
    import panel
    try:
        count = min(int(ctx.args[0]), 50) if ctx.args else 15
    except ValueError:
        count = 15
    rows = panel.query_logs(limit=count)
    if not rows:
        return "The log is empty."
    out = []
    for r in rows[:count]:
        out.append(f"{str(r.get('ts', ''))[:19]}  {_esc(r.get('level'))}  "
                   f"{_esc(r.get('action'))}  {_esc(r.get('actor') or '')}")
    return "<b>Management log</b>\n" + _pre("\n".join(out))


@command("/sh", _needs_terminal, "/sh <command>",
         "Run a shell command. Root accounts run as root, limited accounts run as their own system user.")
def _cmd_sh(ctx):
    cmd = ctx.raw.strip()
    if not cmd:
        return "Usage: /sh &lt;command&gt;"
    level = ctx.perms.get("terminal")
    who = ctx.perms.get("username")
    if level == panel_users.TERMINAL_ROOT:
        res = System.run_command(cmd, timeout=SHELL_TIMEOUT)
        out = (res.get("stdout", "") + res.get("stderr", ""))
        rc = res.get("returncode", 0)
    else:
        os_user = ctx.perms.get("os_username") or ""
        if not os_user:
            return ("Your account has a limited shell but no system user to run "
                    "it as. An admin has to create one first.")
        try:
            proc = subprocess.run(["su", "-", os_user, "-c", cmd],
                                  capture_output=True, text=True,
                                  timeout=SHELL_TIMEOUT)
            out = proc.stdout + proc.stderr
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            out, rc = f"Timed out after {SHELL_TIMEOUT}s\n", 124
        except Exception as e:
            out, rc = f"{type(e).__name__}: {e}\n", 1
    notify(ctx.conn, "Command run from Telegram",
           f"{who} ({ctx.person['telegram_id']}) ran:\n\n{cmd}\n\n"
           f"exit {rc}\n\n{out[:2000]}")
    return f"exit {rc}\n{_pre(out)}"


@command("/mail", _needs("logs_access"), "/mail <to> | <subject> | <body>",
         "Send an email from this server's first mailbox.")
def _cmd_mail(ctx):
    parts = [p.strip() for p in ctx.raw.split("|")]
    if len(parts) < 3 or not all(parts[:3]):
        return "Usage: /mail someone@example.com | Subject | Message body"
    to_addr, subject, body = parts[0], parts[1], "|".join(parts[2:])
    boxes = mail.boxes(ctx.conn)
    if not boxes:
        return "There is no mailbox on this system to send from yet."
    sender = boxes[0]["address"]
    route = "internal" if any(b["address"] == to_addr for b in boxes) else "external"
    ok, detail, _r = mail.send(ctx.conn, sender, to_addr, subject, body, route,
                               actor=ctx.perms.get("username", ""))
    return _esc(detail)


@command("/notify", _is_admin, "/notify <email|off>",
         "Where the bot emails what it did. Off stops the emails.")
def _cmd_notify(ctx):
    if not ctx.args:
        current = _get(ctx.conn, S_NOTIFY, "")
        return f"Notifications go to <code>{_esc(current)}</code>" if current \
            else "No notification address is set."
    value = "" if ctx.args[0].lower() in ("off", "none", "-") else ctx.args[0]
    ok, detail = set_config(ctx.conn, notify_email=value)
    if not ok:
        return _esc(detail)
    return f"Notifications now go to {_esc(value)}" if value \
        else "Notification emails are off."


@command("/conv", _is_admin, "/conv [count]",
         "The bot's conversation log: every message it has received, with the sender's ID.")
def _cmd_conv(ctx):
    try:
        count = min(int(ctx.args[0]), 60) if ctx.args else 20
    except ValueError:
        count = 20
    rows = recent(ctx.conn, limit=count)
    if not rows:
        return "Nothing in the conversation log yet."
    out = []
    for r in rows:
        arrow = "in " if r["direction"] == "in" else "out"
        who = r["tg_username"] or r["display_name"] or str(r["telegram_id"])
        mark = "" if r["allowed"] else " (not allowed)"
        out.append(f"{r['ts']}  {arrow}  {who} [{r['telegram_id']}]{mark}\n"
                   f"    {(r['text'] or '')[:160]}")
    return "<b>Conversation log</b>\n" + _pre("\n".join(out))


@command("/pending", _is_admin, "/pending",
         "Telegram IDs that have written in and are not allowed yet.")
def _cmd_pending(ctx):
    rows = pending(ctx.conn)
    if not rows:
        return "Nobody is waiting."
    out = ["<b>Waiting for a decision</b>"]
    for r in rows:
        name = r["tg_username"] or r["display_name"] or "unnamed"
        out.append(f"<code>{r['telegram_id']}</code>  {_esc(name)}  "
                   f"{r['messages']} message(s), last {r['last_seen']}")
    out.append("\nAllow one with <code>/allow &lt;id&gt; admin</code> or "
               "<code>/allow &lt;id&gt; user &lt;panel account&gt;</code>.")
    return "\n".join(out)


@command("/users", _is_admin, "/users", "Everyone who may use this bot.")
def _cmd_users(ctx):
    rows = users(ctx.conn)
    if not rows:
        return "Nobody has been allowed yet. Try /pending."
    out = ["<b>Bot users</b>"]
    for r in rows:
        name = r["tg_username"] or r["display_name"] or "unnamed"
        bound = f" as {r['panel_user']}" if r["panel_user"] else ""
        out.append(f"<code>{r['telegram_id']}</code>  {_esc(name)}  "
                   f"{r['role']}{_esc(bound)}")
    return "\n".join(out)


@command("/allow", _is_admin, "/allow <id> [admin|user] [panel account]",
         "Let a Telegram ID in. An admin gets everything; a user gets what their panel account allows.")
def _cmd_allow(ctx):
    if not ctx.args:
        return "Usage: /allow &lt;telegram id&gt; [admin|user] [panel account]"
    role = ctx.args[1].lower() if len(ctx.args) > 1 else ROLE_USER
    panel_user = ctx.args[2] if len(ctx.args) > 2 else ""
    ok, detail = allow(ctx.conn, ctx.args[0], role, panel_user,
                       actor=ctx.perms.get("username", ""))
    return _esc(detail)


@command("/block", _is_admin, "/block <id>", "Refuse a Telegram ID from now on.")
def _cmd_block(ctx):
    if not ctx.args:
        return "Usage: /block &lt;telegram id&gt;"
    ok, detail = allow(ctx.conn, ctx.args[0], ROLE_BLOCKED,
                       actor=ctx.perms.get("username", ""))
    return _esc(detail)


@command("/revoke", _is_admin, "/revoke <id>",
         "Remove a Telegram ID from the bot completely.")
def _cmd_revoke(ctx):
    if not ctx.args:
        return "Usage: /revoke &lt;telegram id&gt;"
    ok, detail = revoke(ctx.conn, ctx.args[0], actor=ctx.perms.get("username", ""))
    return _esc(detail)


_BY_WORD = None


def _lookup(word):
    global _BY_WORD
    if _BY_WORD is None:
        _BY_WORD = {c["word"]: c for c in COMMANDS}
    return _BY_WORD.get(word)


# ---------------------------------------------------------------- the webhook
def handle_update(conn, update, actor_log=None):
    """One Telegram update, start to finish.

    Everything is logged before anything is decided, because the log is what the
    admin reads to find the ID of somebody who should be let in. A stranger is
    told their own ID and nothing else about this server.
    """
    message = (update.get("message") or update.get("edited_message")
               or (update.get("callback_query") or {}).get("message") or {})
    frm = (update.get("message") or update.get("edited_message")
           or update.get("callback_query") or {}).get("from") or {}
    chat_id = (message.get("chat") or {}).get("id") or frm.get("id") or 0
    telegram_id = frm.get("id") or 0
    text = (message.get("text") or update.get("callback_query", {}).get("data") or "").strip()
    tg_username = frm.get("username") or ""
    display_name = " ".join(x for x in (frm.get("first_name"), frm.get("last_name")) if x)

    person = find(conn, telegram_id) if telegram_id else None
    allowed = bool(person and person["role"] != ROLE_BLOCKED)

    record(conn, "in", telegram_id, text, tg_username, display_name, chat_id,
           allowed, detail=(person["role"] if person else "unknown"))

    if telegram_id:
        cur = conn.cursor()
        cur.execute("UPDATE tg_user SET last_seen = now(), chat_id = %s "
                    "WHERE telegram_id = %s", (chat_id, telegram_id))
        cur.close()

    if not allowed:
        _greet_stranger(conn, person, telegram_id, chat_id, tg_username,
                        display_name, text)
        return {"ok": True, "handled": "not allowed"}

    perms = _permissions(conn, person)
    reply = _dispatch(conn, person, perms, chat_id, text)
    record(conn, "out", telegram_id, reply, tg_username, display_name, chat_id,
           True, detail="reply")
    send_message(conn, chat_id, reply)
    if actor_log:
        try:
            actor_log(person, perms, text)
        except Exception:
            pass
    return {"ok": True, "handled": text.split(" ")[0][:32]}


def _dispatch(conn, person, perms, chat_id, text):
    if not text:
        return "Send /help to see what you can do."
    word, _, rest = text.partition(" ")
    word = word.split("@")[0].lower()          # /help@mybot in a group
    if not word.startswith("/"):
        return ("That is not a command. Send /help to see everything you can "
                "do here.")
    spec = _lookup(word)
    if not spec:
        return f"{_esc(word)} is not a command here. Send /help."
    if not spec["check"](perms):
        return ("Your account is not allowed to run that. Send /help to see what "
                "you can do, or ask an admin to widen your permissions.")
    ctx = _Ctx(conn, person, perms, chat_id, rest.split(), rest)
    try:
        return spec["fn"](ctx)
    except Exception as e:
        return f"That failed: {_esc(type(e).__name__)}: {_esc(e)}"


def _greet_stranger(conn, person, telegram_id, chat_id, tg_username,
                    display_name, text):
    """What somebody who is not on the list is told, and what that costs them.

    They get their own ID so they can pass it to an admin, and nothing else. The
    admin gets one email the first time a given ID writes in, so a stranger
    hammering the bot cannot turn the notification address into a mailbomb.
    """
    if person and person["role"] == ROLE_BLOCKED:
        return
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) FROM tg_log
                   WHERE telegram_id = %s AND direction = 'in'""", (telegram_id,))
    seen_before = (cur.fetchone() or [0])[0]
    cur.close()
    reply = ("This bot is locked to approved accounts.\n\n"
             f"Your Telegram ID is <code>{telegram_id}</code>\n\n"
             "Give that number to an admin. It is already in this panel's "
             "conversation log, so they can allow it from there.")
    record(conn, "out", telegram_id, reply, tg_username, display_name, chat_id,
           False, detail="stranger")
    send_message(conn, chat_id, reply)
    if seen_before <= 1:
        name = tg_username or display_name or "somebody unnamed"
        notify(conn, "Unknown Telegram account messaged the bot",
               f"{name} (Telegram ID {telegram_id}) wrote to the bot:\n\n"
               f"{(text or '')[:500]}\n\n"
               "They have no access. Allow them in the panel under Config, "
               "Telegram Bot, or from the chat with:\n"
               f"  /allow {telegram_id} user\n"
               f"  /allow {telegram_id} admin")
