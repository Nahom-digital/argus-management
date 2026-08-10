# Mail for the panel: the mailboxes, the messages, and the two ways a message
# can leave. Internal mail is delivered by writing a row and never touches the
# relay; external mail goes out through the SMTP relay the admin configured.
# Both are recorded, and which of the two happened is part of the record, since
# "did that leave the building" is the first question anybody asks.
#
# Mirrors the shape of the other helper modules here: its own SCHEMA tuple, plain
# functions that take an already-open connection, no pool of its own.
import re
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

import vault

# A local part per RFC 5321 in the shape people actually use, plus the domain
# rules the panel already applies to proxy hostnames.
_LOCAL_RE = re.compile(r"^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$")
_DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ADDRESS_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")

SUBJECT_MAX = 300
BODY_MAX = 100_000
ROUTES = ("internal", "external")
DEFAULT_RELAY_PORT = 587

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS mail_config (
        id                  SERIAL PRIMARY KEY,
        domain              VARCHAR(253) NOT NULL DEFAULT '',
        relay_host          VARCHAR(255) NOT NULL DEFAULT '',
        relay_port          INTEGER NOT NULL DEFAULT 587,
        relay_user          VARCHAR(255) NOT NULL DEFAULT '',
        relay_secret        TEXT NOT NULL DEFAULT '',
        relay_starttls      BOOLEAN NOT NULL DEFAULT TRUE,
        relay_from          VARCHAR(320) NOT NULL DEFAULT '',
        relay_checked_at    TIMESTAMPTZ,
        relay_check_detail  TEXT NOT NULL DEFAULT '',
        mailcow_api_key     TEXT NOT NULL DEFAULT '',
        updated_by          VARCHAR(100) NOT NULL DEFAULT '',
        updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS mail_box (
        id           SERIAL PRIMARY KEY,
        address      VARCHAR(320) UNIQUE NOT NULL,
        local_part   VARCHAR(64) NOT NULL,
        owner        VARCHAR(100) NOT NULL DEFAULT '',
        full_name    VARCHAR(160) NOT NULL DEFAULT '',
        secret       TEXT NOT NULL DEFAULT '',
        server_side  BOOLEAN NOT NULL DEFAULT FALSE,
        created_by   VARCHAR(100) NOT NULL DEFAULT '',
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS mail_message (
        id           BIGSERIAL PRIMARY KEY,
        box_id       INTEGER NOT NULL REFERENCES mail_box(id) ON DELETE CASCADE,
        direction    VARCHAR(8)  NOT NULL,
        route        VARCHAR(8)  NOT NULL,
        from_addr    VARCHAR(320) NOT NULL DEFAULT '',
        from_name    VARCHAR(160) NOT NULL DEFAULT '',
        to_addr      VARCHAR(320) NOT NULL DEFAULT '',
        subject      TEXT NOT NULL DEFAULT '',
        body         TEXT NOT NULL DEFAULT '',
        unread       BOOLEAN NOT NULL DEFAULT TRUE,
        status       VARCHAR(16) NOT NULL DEFAULT 'delivered',
        detail       TEXT NOT NULL DEFAULT '',
        remote_uid   VARCHAR(120) NOT NULL DEFAULT '',
        ts           TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX IF NOT EXISTS idx_mail_msg_box ON mail_message(box_id, ts DESC)",
    "CREATE INDEX IF NOT EXISTS idx_mail_msg_unread ON mail_message(box_id) WHERE unread",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_msg_uid "
    "ON mail_message(box_id, remote_uid) WHERE remote_uid <> ''",
)


def ensure_schema(conn):
    cur = conn.cursor()
    for statement in SCHEMA:
        cur.execute(statement)
    cur.close()


# ----------------------------------------------------------------- validation
def domain_problem(domain):
    domain = (domain or "").strip().lower()
    if not domain:
        return "A domain is required."
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        return f"{domain} is not a domain name."
    return ""


def local_part_problem(local):
    local = (local or "").strip().lower()
    if not local:
        return "An address is required."
    if not _LOCAL_RE.match(local):
        return ("An address may hold lowercase letters, digits, dots, plus signs, "
                "hyphens and underscores, and must start and end with a letter "
                "or digit.")
    return ""


def address_problem(address):
    address = (address or "").strip()
    if not address:
        return "A recipient is required."
    if len(address) > 320 or not _ADDRESS_RE.match(address):
        return f"{address} is not an email address."
    return ""


def _one_line(value, limit):
    """Anything that reaches a header has to be one line.

    A newline in a subject or an address is how a second header, or a second
    recipient, gets added to somebody else's message. EmailMessage would refuse
    some of these later; they are removed here so no path can carry one.
    """
    text = re.sub(r"[\r\n\t]+", " ", str(value or "")).strip()
    return text[:limit]


# --------------------------------------------------------------------- config
_CONFIG_COLUMNS = ("domain", "relay_host", "relay_port", "relay_user",
                   "relay_starttls", "relay_from", "relay_checked_at",
                   "relay_check_detail")


def config(conn):
    """The mail settings, without the secrets.

    The relay password and the mailcow API key never leave this module. What the
    interface needs is whether they are set, not what they are.
    """
    cur = conn.cursor()
    cur.execute(f"""SELECT {', '.join(_CONFIG_COLUMNS)},
                           relay_secret <> '' AS relay_secret_set,
                           mailcow_api_key <> '' AS mailcow_key_set
                    FROM mail_config ORDER BY id LIMIT 1""")
    row = cur.fetchone()
    cur.close()
    if not row:
        return {"domain": "", "relay_host": "", "relay_port": DEFAULT_RELAY_PORT,
                "relay_user": "", "relay_starttls": True, "relay_from": "",
                "relay_checked_at": "", "relay_check_detail": "",
                "relay_secret_set": False, "mailcow_key_set": False,
                "outbound_ready": False, "configured": False}
    out = dict(zip(_CONFIG_COLUMNS, row[:len(_CONFIG_COLUMNS)]))
    out["relay_checked_at"] = str(out["relay_checked_at"] or "")[:19]
    out["relay_secret_set"] = bool(row[-2])
    out["mailcow_key_set"] = bool(row[-1])
    out["outbound_ready"] = bool(out["relay_host"])
    out["configured"] = bool(out["domain"])
    return out


def _ensure_row(conn):
    cur = conn.cursor()
    cur.execute("SELECT id FROM mail_config ORDER BY id LIMIT 1")
    row = cur.fetchone()
    if row:
        cur.close()
        return row[0]
    cur.execute("INSERT INTO mail_config (domain) VALUES ('') RETURNING id")
    new_id = cur.fetchone()[0]
    cur.close()
    return new_id


def set_domain(conn, domain, actor=""):
    """The one domain every address on this system lives under.

    Asked once, when inbound mail is configured, and kept: changing it later
    would orphan every address already handed out, so it is refused while
    mailboxes exist.
    """
    problem = domain_problem(domain)
    if problem:
        return False, problem
    domain = domain.strip().lower()
    current = config(conn)
    if current["domain"] and current["domain"] != domain and count_boxes(conn):
        return False, (f"This system already sends as {current['domain']} and has "
                       "mailboxes under it. Delete those first if the domain "
                       "really has to change.")
    row_id = _ensure_row(conn)
    cur = conn.cursor()
    cur.execute("""UPDATE mail_config
                   SET domain = %s, updated_by = %s, updated_at = now()
                   WHERE id = %s""", (domain, actor[:100], row_id))
    cur.close()
    return True, f"Mail is configured for {domain}."


def set_relay(conn, host, port, user, password, starttls=True, from_addr="", actor=""):
    """Where external mail is handed off. The password is encrypted at rest and
    is never read back out to the interface."""
    host = _one_line(host, 255).lower()
    if not host:
        return False, "A relay host is required."
    if not _DOMAIN_RE.match(host) and not re.match(r"^[\d.:a-f]+$", host):
        return False, f"{host} is not a host name or an address."
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False, "The relay port has to be a number."
    if not 1 <= port <= 65535:
        return False, "The relay port has to be between 1 and 65535."
    user = _one_line(user, 255)
    from_addr = _one_line(from_addr, 320)
    if from_addr and address_problem(from_addr):
        return False, address_problem(from_addr)

    row_id = _ensure_row(conn)
    cur = conn.cursor()
    if password:
        cur.execute("""UPDATE mail_config
                       SET relay_host = %s, relay_port = %s, relay_user = %s,
                           relay_secret = %s, relay_starttls = %s, relay_from = %s,
                           updated_by = %s, updated_at = now()
                       WHERE id = %s""",
                    (host, port, user, vault.encrypt(password), bool(starttls),
                     from_addr, actor[:100], row_id))
    else:
        # An edit that leaves the password field empty is an edit to the other
        # settings, not a request to forget the password.
        cur.execute("""UPDATE mail_config
                       SET relay_host = %s, relay_port = %s, relay_user = %s,
                           relay_starttls = %s, relay_from = %s,
                           updated_by = %s, updated_at = now()
                       WHERE id = %s""",
                    (host, port, user, bool(starttls), from_addr,
                     actor[:100], row_id))
    cur.close()
    return True, f"External mail will be handed to {host}:{port}."


def _relay_secret(conn):
    cur = conn.cursor()
    cur.execute("SELECT relay_secret FROM mail_config ORDER BY id LIMIT 1")
    row = cur.fetchone()
    cur.close()
    return vault.decrypt(row[0]) if row and row[0] else ""


def set_mailcow_key(conn, key, actor=""):
    row_id = _ensure_row(conn)
    cur = conn.cursor()
    cur.execute("""UPDATE mail_config SET mailcow_api_key = %s, updated_by = %s,
                          updated_at = now() WHERE id = %s""",
                (vault.encrypt(_one_line(key, 200)), actor[:100], row_id))
    cur.close()
    return True, "The mailcow API key is stored."


def mailcow_key(conn):
    cur = conn.cursor()
    cur.execute("SELECT mailcow_api_key FROM mail_config ORDER BY id LIMIT 1")
    row = cur.fetchone()
    cur.close()
    return vault.decrypt(row[0]) if row and row[0] else ""


# ------------------------------------------------------------------ mailboxes
def count_boxes(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM mail_box")
    total = cur.fetchone()[0]
    cur.close()
    return total


def boxes(conn, owner=None):
    """Every mailbox, or only the ones belonging to one panel account."""
    cur = conn.cursor()
    if owner is None:
        cur.execute("""SELECT b.id, b.address, b.local_part, b.owner, b.full_name,
                              b.server_side, b.created_by, b.created_at,
                              (SELECT COUNT(*) FROM mail_message m
                                WHERE m.box_id = b.id AND m.unread
                                  AND m.direction = 'in')
                       FROM mail_box b ORDER BY b.address""")
    else:
        cur.execute("""SELECT b.id, b.address, b.local_part, b.owner, b.full_name,
                              b.server_side, b.created_by, b.created_at,
                              (SELECT COUNT(*) FROM mail_message m
                                WHERE m.box_id = b.id AND m.unread
                                  AND m.direction = 'in')
                       FROM mail_box b WHERE b.owner = %s ORDER BY b.address""",
                    (owner,))
    rows = [{"id": r[0], "address": r[1], "local_part": r[2], "owner": r[3],
             "full_name": r[4], "server_side": r[5], "created_by": r[6],
             "created_at": str(r[7])[:19], "unread": r[8]}
            for r in cur.fetchall()]
    cur.close()
    return rows


def create_box(conn, local_part, owner="", full_name="", actor="", secret="",
               server_side=False):
    """Add an address under the configured domain and hand it to somebody.

    owner is a panel username, or "" for an address only the admin can read.
    """
    cfg = config(conn)
    if not cfg["domain"]:
        return False, "Configure the mail domain first.", None
    problem = local_part_problem(local_part)
    if problem:
        return False, problem, None
    local_part = local_part.strip().lower()
    address = f"{local_part}@{cfg['domain']}"
    cur = conn.cursor()
    cur.execute("SELECT id FROM mail_box WHERE address = %s", (address,))
    if cur.fetchone():
        cur.close()
        return False, f"{address} already exists.", None
    cur.execute("""INSERT INTO mail_box (address, local_part, owner, full_name,
                                         secret, server_side, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (address, local_part, (owner or "")[:100],
                 _one_line(full_name, 160), vault.encrypt(secret) if secret else "",
                 bool(server_side), actor[:100]))
    box_id = cur.fetchone()[0]
    cur.close()
    return True, f"{address} created.", box_id


def assign_box(conn, address, owner):
    cur = conn.cursor()
    cur.execute("UPDATE mail_box SET owner = %s WHERE address = %s RETURNING id",
                ((owner or "")[:100], (address or "").strip().lower()))
    row = cur.fetchone()
    cur.close()
    if not row:
        return False, "There is no such address."
    return True, (f"{address} now belongs to {owner}" if owner
                  else f"{address} is now an admin-only address")


def set_box_name(conn, address, full_name):
    cur = conn.cursor()
    cur.execute("UPDATE mail_box SET full_name = %s WHERE address = %s RETURNING id",
                (_one_line(full_name, 160), (address or "").strip().lower()))
    row = cur.fetchone()
    cur.close()
    return (True, "Saved.") if row else (False, "There is no such address.")


def delete_box(conn, address):
    cur = conn.cursor()
    cur.execute("DELETE FROM mail_box WHERE address = %s RETURNING id",
                ((address or "").strip().lower(),))
    row = cur.fetchone()
    cur.close()
    return (True, f"{address} deleted.") if row else (False, "There is no such address.")


def box_secret(conn, address):
    cur = conn.cursor()
    cur.execute("SELECT secret FROM mail_box WHERE address = %s",
                ((address or "").strip().lower(),))
    row = cur.fetchone()
    cur.close()
    return vault.decrypt(row[0]) if row and row[0] else ""


def visible_boxes(conn, username, is_admin):
    """What this account may read. The admin sees every mailbox; everybody else
    sees only their own, and this is the only place that decision is made."""
    return boxes(conn) if is_admin else boxes(conn, owner=username)


def _box_by_address(conn, address):
    cur = conn.cursor()
    cur.execute("""SELECT id, address, owner, full_name FROM mail_box
                   WHERE address = %s""", ((address or "").strip().lower(),))
    row = cur.fetchone()
    cur.close()
    if not row:
        return None
    return {"id": row[0], "address": row[1], "owner": row[2], "full_name": row[3]}


# ------------------------------------------------------------------- messages
def messages(conn, box_ids, folder="inbox", page=1, limit=50):
    """One page of a folder, for the boxes the caller is allowed to read.

    box_ids comes from visible_boxes, so an empty list can only ever return
    nothing. That is what keeps one account out of another account's mail.
    """
    if not box_ids:
        return {"messages": [], "total": 0, "page": 1, "pages": 1}
    direction = "out" if folder == "sent" else "in"
    limit = max(1, min(int(limit or 50), 200))
    page = max(1, int(page or 1))
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) FROM mail_message
                   WHERE box_id = ANY(%s) AND direction = %s""",
                (list(box_ids), direction))
    total = cur.fetchone()[0]
    cur.execute("""SELECT m.id, m.box_id, b.address, m.direction, m.route,
                          m.from_addr, m.from_name, m.to_addr, m.subject, m.body,
                          m.unread, m.status, m.detail, m.ts
                   FROM mail_message m JOIN mail_box b ON b.id = m.box_id
                   WHERE m.box_id = ANY(%s) AND m.direction = %s
                   ORDER BY m.id DESC LIMIT %s OFFSET %s""",
                (list(box_ids), direction, limit, (page - 1) * limit))
    rows = [{"id": r[0], "box_id": r[1], "box": r[2], "direction": r[3],
             "route": r[4], "from_addr": r[5], "from_name": r[6], "to_addr": r[7],
             "subject": r[8], "body": r[9], "unread": r[10], "status": r[11],
             "detail": r[12], "ts": str(r[13])[:19]}
            for r in cur.fetchall()]
    cur.close()
    pages = max(1, (total + limit - 1) // limit)
    return {"messages": rows, "total": total, "page": page, "pages": pages}


def unread_count(conn, box_ids):
    if not box_ids:
        return 0
    cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) FROM mail_message
                   WHERE box_id = ANY(%s) AND direction = 'in' AND unread""",
                (list(box_ids),))
    total = cur.fetchone()[0]
    cur.close()
    return total


def mark_read(conn, message_id, box_ids, read=True):
    if not box_ids:
        return False
    cur = conn.cursor()
    cur.execute("""UPDATE mail_message SET unread = %s
                   WHERE id = %s AND box_id = ANY(%s) RETURNING id""",
                (not read, int(message_id), list(box_ids)))
    row = cur.fetchone()
    cur.close()
    return bool(row)


def delete_message(conn, message_id, box_ids):
    if not box_ids:
        return False
    cur = conn.cursor()
    cur.execute("DELETE FROM mail_message WHERE id = %s AND box_id = ANY(%s) RETURNING id",
                (int(message_id), list(box_ids)))
    row = cur.fetchone()
    cur.close()
    return bool(row)


def _record(conn, box_id, direction, route, from_addr, from_name, to_addr,
            subject, body, status, detail="", unread=True, remote_uid=""):
    cur = conn.cursor()
    cur.execute("""INSERT INTO mail_message
                     (box_id, direction, route, from_addr, from_name, to_addr,
                      subject, body, unread, status, detail, remote_uid)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (box_id, direction, route, from_addr, from_name, to_addr,
                 subject, body, unread, status, detail[:2000], remote_uid))
    new_id = cur.fetchone()[0]
    cur.close()
    return new_id


def deliver_inbound(conn, box_id, from_addr, from_name, to_addr, subject, body,
                    route="external", remote_uid=""):
    """A message arriving from outside, or from another mailbox here."""
    return _record(conn, box_id, "in", route, _one_line(from_addr, 320),
                   _one_line(from_name, 160), _one_line(to_addr, 320),
                   _one_line(subject, SUBJECT_MAX), (body or "")[:BODY_MAX],
                   "delivered", unread=True, remote_uid=remote_uid[:120])


# ---------------------------------------------------------------------- send
def send(conn, from_address, to_addr, subject, body, route, actor="",
         from_name=""):
    """Send one message, either internally or out through the relay.

    Internal means exactly that: the recipient is a mailbox on this system, the
    message is delivered by writing a row, and the relay is never opened. It is
    refused rather than silently upgraded if the recipient is not local, because
    a message the sender believed never left the building must not leave it.

    Returns (ok, message, route_used).
    """
    if route not in ROUTES:
        return False, "Choose whether this goes internally or externally.", ""
    sender = _box_by_address(conn, from_address)
    if not sender:
        return False, "That is not one of your addresses.", ""
    problem = address_problem(to_addr)
    if problem:
        return False, problem, ""
    to_addr = _one_line(to_addr, 320).lower()
    subject = _one_line(subject, SUBJECT_MAX)
    body = (body or "")[:BODY_MAX]
    display = _one_line(from_name or sender["full_name"] or "", 160)
    recipient = _box_by_address(conn, to_addr)

    if route == "internal":
        if not recipient:
            return False, (f"{to_addr} is not a mailbox on this system, so it "
                           "cannot be delivered internally. Send it externally "
                           "instead."), ""
        deliver_inbound(conn, recipient["id"], sender["address"], display,
                        to_addr, subject, body, route="internal")
        _record(conn, sender["id"], "out", "internal", sender["address"], display,
                to_addr, subject, body, "sent", detail="delivered on this system",
                unread=False)
        return True, f"Delivered to {to_addr} without leaving this system.", "internal"

    cfg = config(conn)
    if not cfg["relay_host"]:
        return False, ("External mail has no relay configured yet, so it cannot "
                       "be sent. An admin can set one up under Outbound mail."), ""
    ok, detail = _relay_send(conn, cfg, sender["address"], display, to_addr,
                             subject, body)
    _record(conn, sender["id"], "out", "external", sender["address"], display,
            to_addr, subject, body, "sent" if ok else "failed", detail=detail,
            unread=False)
    if not ok:
        return False, f"The relay would not take it: {detail}", "external"
    return True, f"Handed to {cfg['relay_host']} for delivery to {to_addr}.", "external"


def build_message(from_addr, from_name, to_addr, subject, body, envelope_from=""):
    """The message itself. EmailMessage does the header encoding, which is what
    keeps a display name with a comma or a non-ASCII letter from breaking the
    From line."""
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    if envelope_from and envelope_from != from_addr:
        msg["Sender"] = envelope_from
    msg.set_content(body or "")
    return msg


def _relay_send(conn, cfg, from_addr, from_name, to_addr, subject, body):
    """(ok, detail). Every failure is reported rather than raised: a message that
    could not go out still has to be recorded as one that was tried."""
    password = _relay_secret(conn)
    envelope = cfg.get("relay_from") or from_addr
    msg = build_message(from_addr, from_name, to_addr, subject, body, envelope)
    try:
        with smtplib.SMTP(cfg["relay_host"], int(cfg["relay_port"]), timeout=30) as smtp:
            smtp.ehlo()
            if cfg.get("relay_starttls", True):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if cfg.get("relay_user"):
                smtp.login(cfg["relay_user"], password)
            smtp.send_message(msg, from_addr=envelope, to_addrs=[to_addr])
        return True, f"accepted by {cfg['relay_host']}"
    except smtplib.SMTPAuthenticationError:
        return False, "the relay refused the username and password"
    except smtplib.SMTPRecipientsRefused:
        return False, f"the relay refused {to_addr}"
    except smtplib.SMTPException as e:
        return False, f"{type(e).__name__}: {e}"[:300]
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as e:
        return False, f"{type(e).__name__}: {e}"[:300]


def check_relay(conn):
    """Open the relay, start TLS, sign in, and hang up without sending anything.
    Saved on the config row so the page can say when it last worked."""
    cfg = config(conn)
    if not cfg["relay_host"]:
        return False, "No relay is configured."
    password = _relay_secret(conn)
    ok, detail = True, ""
    try:
        with smtplib.SMTP(cfg["relay_host"], int(cfg["relay_port"]), timeout=20) as smtp:
            smtp.ehlo()
            if cfg.get("relay_starttls", True):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if cfg.get("relay_user"):
                smtp.login(cfg["relay_user"], password)
            detail = "connected, TLS started, signed in" if cfg.get("relay_user") \
                else "connected and TLS started"
    except smtplib.SMTPAuthenticationError:
        ok, detail = False, "the relay refused the username and password"
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"[:300]

    row_id = _ensure_row(conn)
    cur = conn.cursor()
    cur.execute("""UPDATE mail_config SET relay_checked_at = now(),
                          relay_check_detail = %s WHERE id = %s""",
                (("ok: " if ok else "failed: ") + detail, row_id))
    cur.close()
    return ok, detail


def parse_address(raw):
    """(display name, address) from a From header, both one line."""
    name, addr = parseaddr(raw or "")
    return _one_line(name, 160), _one_line(addr, 320).lower()
