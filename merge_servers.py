# Linking one Argus panel to another.
#
# Each installation owns one random "private key" generated on first start and
# kept encrypted in merge_serverkey. To manage another panel, an admin adds its
# host and that panel's key. The first call introduces this panel (a handshake)
# carrying this panel's own key as link_key; the receiving panel records a
# request together with that key, and nothing is served until its admin allows
# it. Every later data call carries a short-lived JWT signed with this panel's
# own key, in an Authorization header and in the argus_merge cookie. Only the
# handshake and the status poll are signed with the receiving panel's key, so an
# unbound peer can still introduce itself. That is deliberately separate from
# the browser session in panel.py.
#
# No database or network work happens at import time. management.py imports
# every top-level module, so all of it lives inside functions.
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import DB
import vault
import argus_version

# Scopes a linked panel may be asked for. Terminal is never part of a staff
# account's remote access: only the admin holds it.
SCOPES = ("overview", "cpu", "memory", "network", "disk", "terminal")
ADMIN_SCOPES = list(SCOPES)
_USER_SCOPES = ("cpu", "memory", "network", "disk")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS merge_serverkey (
        key_id       VARCHAR(64) PRIMARY KEY,
        server_uid   VARCHAR(64),
        role         VARCHAR(16) NOT NULL DEFAULT 'remote',
        label        VARCHAR(200) NOT NULL DEFAULT '',
        key_cipher   TEXT NOT NULL,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        rotated_at   TIMESTAMPTZ
    )""",
    "CREATE INDEX IF NOT EXISTS idx_merge_key_uid ON merge_serverkey(server_uid)",
    """CREATE TABLE IF NOT EXISTS merge_server (
        id              VARCHAR(64) PRIMARY KEY,
        name            VARCHAR(120) NOT NULL DEFAULT '',
        host            TEXT NOT NULL,
        port            INTEGER NOT NULL DEFAULT 80,
        scheme          VARCHAR(8) NOT NULL DEFAULT 'http',
        base_path       VARCHAR(200) NOT NULL DEFAULT '',
        key_id          VARCHAR(64) NOT NULL,
        link_key_cipher TEXT NOT NULL DEFAULT '',
        server_uid      VARCHAR(64),
        remote_hostname TEXT NOT NULL DEFAULT '',
        remote_version  VARCHAR(64) NOT NULL DEFAULT '',
        status          VARCHAR(20) NOT NULL DEFAULT 'pending',
        approved        BOOLEAN NOT NULL DEFAULT FALSE,
        last_error      TEXT NOT NULL DEFAULT '',
        last_seen       TIMESTAMPTZ,
        position        INTEGER NOT NULL DEFAULT 0,
        created_by      VARCHAR(100) NOT NULL DEFAULT '',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX IF NOT EXISTS idx_merge_server_pos ON merge_server(position)",
    "CREATE INDEX IF NOT EXISTS idx_merge_server_uid ON merge_server(server_uid)",
    """CREATE TABLE IF NOT EXISTS merge_request (
        server_uid     VARCHAR(64) PRIMARY KEY,
        hostname       TEXT NOT NULL DEFAULT '',
        host           TEXT NOT NULL DEFAULT '',
        remote_version VARCHAR(64) NOT NULL DEFAULT '',
        status         VARCHAR(16) NOT NULL DEFAULT 'pending',
        requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
        decided_at   TIMESTAMPTZ,
        decided_by   VARCHAR(100) NOT NULL DEFAULT '',
        note         TEXT NOT NULL DEFAULT '',
        peer_key_cipher TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS idx_merge_request_status ON merge_request(status)",
    """CREATE TABLE IF NOT EXISTS merge_user_access (
        username    VARCHAR(100) NOT NULL,
        server_id   VARCHAR(64) NOT NULL,
        permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
        position    INTEGER NOT NULL DEFAULT 0,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (username, server_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_merge_access_user ON merge_user_access(username, position)",
)

SCHEMA_UPGRADES = (
    "ALTER TABLE IF EXISTS merge_server ADD COLUMN IF NOT EXISTS "
    "remote_version VARCHAR(64) NOT NULL DEFAULT ''",
    "ALTER TABLE IF EXISTS merge_server ADD COLUMN IF NOT EXISTS "
    "link_key_cipher TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE IF EXISTS merge_request ADD COLUMN IF NOT EXISTS "
    "remote_version VARCHAR(64) NOT NULL DEFAULT ''",
    "ALTER TABLE IF EXISTS merge_request ADD COLUMN IF NOT EXISTS "
    "peer_key_cipher TEXT NOT NULL DEFAULT ''",
)

_schema_ready = False


def ensure_schema(conn=None, force=False):
    """Create the merge tables. Idempotent, and cached after the first call."""
    global _schema_ready
    if _schema_ready and not force:
        return
    own = conn is None
    if own:
        conn = DB.get_connection()
    try:
        cur = conn.cursor()
        for statement in SCHEMA:
            cur.execute(statement)
        for statement in SCHEMA_UPGRADES:
            cur.execute(statement)
        conn.commit()
        cur.close()
        _schema_ready = True
    finally:
        if own:
            DB.release_connection(conn)


def panel_version():
    return argus_version.version()


def version_state(remote_version):
    """Compare a panel's reported version with this installation's version.

    A missing version is not treated as a mismatch because a panel running an
    older release cannot report one. It is surfaced separately so the interface
    can still tell the admin that a comparison was impossible.
    """
    local = panel_version()
    remote = str(remote_version or "").strip()
    return {
        "local_version": local,
        "remote_version": remote,
        "version_mismatch": bool(remote) and remote != local,
        "version_unknown": not bool(remote),
    }


def _local_label():
    try:
        name = socket.getfqdn() or socket.gethostname()
    except Exception:
        name = "argus-management"
    return (name or "argus-management")[:200]


def _new_key():
    return secrets.token_urlsafe(48)


def local_label():
    return _local_label()


def ensure_local_identity():
    """Return this installation's identity, generating its key on first start.

    The row is one, fixed key_id of "local". INSERT ... ON CONFLICT keeps two
    workers starting at the same moment from minting two different identities.
    """
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT server_uid, label, key_cipher FROM merge_serverkey "
            "WHERE key_id = 'local'")
        row = cur.fetchone()
        if row:
            uid, label, cipher = row
            if not vault.decrypt(cipher):
                # The vault key was rotated or the row predates this vault. A
                # key nobody can read is worse than a new one, and links on the
                # other side will say why they stopped working. Peers already
                # bound to the old key stay bound and must be re-approved.
                cipher = vault.encrypt(_new_key())
                cur.execute(
                    "UPDATE merge_serverkey SET key_cipher=%s, rotated_at=now() "
                    "WHERE key_id='local'", (cipher,))
                conn.commit()
            cur.close()
            return {"server_uid": uid, "key_id": "local", "label": label,
                    "key": vault.decrypt(cipher)}
        uid = uuid.uuid4().hex
        key = _new_key()
        label = _local_label()
        cur.execute(
            """INSERT INTO merge_serverkey (key_id, server_uid, role, label, key_cipher)
               VALUES ('local', %s, 'local', %s, %s)
               ON CONFLICT (key_id) DO NOTHING""",
            (uid, label, vault.encrypt(key)))
        conn.commit()
        cur.execute(
            "SELECT server_uid, label, key_cipher FROM merge_serverkey "
            "WHERE key_id = 'local'")
        uid, label, cipher = cur.fetchone()
        cur.close()
        return {"server_uid": uid, "key_id": "local", "label": label,
                "key": vault.decrypt(cipher)}
    finally:
        DB.release_connection(conn)


def local_key():
    return ensure_local_identity()["key"]


def rotate_local_key():
    """Mint a new local key. Existing linked panels must be given the new key;
    calls they make with the old one stop verifying immediately.

    A link that is already bound keeps the key it presented. Rotating the local
    key does not rebind it: the peer must be removed and re-approved from both
    sides. There is deliberately no automatic re-bind, because accepting a new
    key on presentation is exactly how a peer could steal another peer's link.
    """
    ident = ensure_local_identity()
    key = _new_key()
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE merge_serverkey SET key_cipher=%s, rotated_at=now() "
            "WHERE key_id='local'", (vault.encrypt(key),))
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)
    return {"server_uid": ident["server_uid"], "label": ident["label"], "key": key}


# ---------------------------------------------------------------------------
# Linked-server records
# ---------------------------------------------------------------------------
def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_token(key, claims, ttl=120):
    """An HS256 JWT. The header is present so any JWT reader recognises it;
    the signature is what this app trusts."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = dict(claims)
    now = int(time.time())
    payload.setdefault("iat", now)
    payload.setdefault("exp", now + int(ttl))
    payload.setdefault("jti", secrets.token_hex(8))
    body = _b64e(json.dumps(header, separators=(",", ":")).encode()) + "." + \
           _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + _b64e(sig)


def verify_token(token, key):
    """The payload, or None for anything malformed, mis-signed or expired."""
    try:
        head, payload, sig = token.split(".", 2)
        body = head + "." + payload
        expected = hmac.new(key.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64d(sig), expected):
            return None
        data = json.loads(_b64d(payload))
        if int(data.get("exp", 0)) <= int(time.time()):
            return None
        if not data.get("iss"):
            return None
        return data
    except Exception:
        return None


def _token_from_request(request):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    # A cookie as well as the header, so a request carrying either works. This
    # cookie name is distinct from the browser session cookie on purpose.
    return request.cookies.get("argus_merge", "")


# A token is accepted once. The pair lives only in this process, bounded, and
# is purged as its TTL passes; a restart forgetting it is harmless.
def _new_lock():
    # Imported here so the module's import block stays as it is.
    import threading
    return threading.Lock()


_replay_lock = _new_lock()
_replay_seen = {}
_REPLAY_LIMIT = 4096


def _remember_jti(issuer, jti, exp):
    """True when this (iss, jti) pair was already used inside its lifetime."""
    if not jti:
        return False
    now = int(time.time())
    key = (str(issuer), str(jti))
    with _replay_lock:
        for old in [k for k, until in _replay_seen.items() if until <= now]:
            _replay_seen.pop(old, None)
        until = _replay_seen.get(key)
        if until and until > now:
            return True
        _replay_seen[key] = int(exp or (now + 120))
        while len(_replay_seen) > _REPLAY_LIMIT:
            _replay_seen.pop(min(_replay_seen, key=_replay_seen.get), None)
    return False


def _reset_replay_cache():
    """Drop every consumed (iss, jti) pair. Used by tests."""
    with _replay_lock:
        _replay_seen.clear()


def _unverified_claims(token):
    """The payload of a token with its signature still unchecked."""
    try:
        payload = token.split(".", 2)[1]
        data = json.loads(_b64d(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _ws_token(websocket):
    tok = (websocket.query_params.get("token") or "").strip()
    if tok:
        return tok
    auth = websocket.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return websocket.cookies.get("argus_merge", "")


def request_status(server_uid):
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT status FROM merge_request WHERE server_uid=%s",
                    (server_uid,))
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    finally:
        DB.release_connection(conn)


def request_record(server_uid):
    """The decision and the bound key for one peer.

    peer_key is decrypted here and used only to verify that peer's tokens. It is
    never returned to a route handler's caller and never logged.
    """
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            "SELECT status, peer_key_cipher FROM merge_request WHERE server_uid=%s",
            (server_uid,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return {"status": None, "has_peer_key": False, "peer_key": ""}
        key = vault.decrypt(row[1] or "")
        return {"status": row[0], "has_peer_key": bool(key), "peer_key": key}
    finally:
        DB.release_connection(conn)


_UID_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


class PeerKeyConflict(Exception):
    """A peer presented a different link key than the one already bound."""


def _checked_server_uid(server_uid):
    uid = server_uid if isinstance(server_uid, str) else ""
    if not 8 <= len(uid) <= 64:
        raise ValueError("A server id must be 8 to 64 characters.")
    if not set(uid) <= _UID_ALLOWED:
        raise ValueError(
            "A server id may only contain letters, numbers, _ and -.")
    return uid


def record_request(server_uid, hostname, host, note="", remote_version="",
                   link_key=None):
    """Record an incoming handshake and bind the key it presented.

    An already-allowed panel stays allowed and a denied one stays denied until
    the local admin changes it. The first non-empty link_key wins: a later
    handshake for the same uid may repeat that key but can never replace it, so
    one peer cannot inherit another peer's approval by announcing a new key.
    """
    server_uid = _checked_server_uid(server_uid)
    link_key = link_key or ""
    if link_key:
        if not 16 <= len(link_key) <= 200 or \
                any(ord(ch) < 32 or ord(ch) == 127 for ch in link_key):
            raise ValueError("The link key is not valid.")
    new_cipher = vault.encrypt(link_key) if link_key else ""
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        # If the vault key rotated, the stored cipher may no longer decrypt.
        # Treat that as an unbound link and clear it with a compare-and-set on
        # the exact ciphertext, so a concurrent handshake is not overwritten.
        cur.execute(
            "SELECT peer_key_cipher FROM merge_request WHERE server_uid=%s",
            (server_uid,))
        found = cur.fetchone()
        if found and found[0] and not vault.decrypt(found[0]):
            cur.execute(
                "UPDATE merge_request SET peer_key_cipher='' "
                "WHERE server_uid=%s AND peer_key_cipher=%s",
                (server_uid, found[0]))
        # One statement, so concurrent handshakes cannot interleave between a
        # read and a write. The existing key (if any) always wins; an empty one
        # is filled by the key this handshake presented. A link that was
        # allowed or denied before per-peer keys is moved back to pending so an
        # admin re-approves the key instead of inheriting the old decision.
        cur.execute(
            """INSERT INTO merge_request
                   (server_uid, hostname, host, note, remote_version,
                    peer_key_cipher)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (server_uid) DO UPDATE
                 SET peer_key_cipher = CASE
                         WHEN merge_request.peer_key_cipher = ''
                         THEN EXCLUDED.peer_key_cipher
                         ELSE merge_request.peer_key_cipher END,
                     status = CASE
                         WHEN merge_request.peer_key_cipher = ''
                              AND EXCLUDED.peer_key_cipher <> ''
                              AND merge_request.status = 'allowed'
                         THEN 'pending'
                         ELSE merge_request.status END
               RETURNING status, peer_key_cipher""",
            (server_uid, (hostname or "")[:300], (host or "")[:300],
             (note or "")[:1000], (remote_version or "")[:64], new_cipher))
        status, stored_cipher = cur.fetchone()
        stored_key = vault.decrypt(stored_cipher or "")
        if link_key and stored_key and stored_key != link_key:
            # The update kept the original key and did not touch the status, so
            # nothing changed. Refuse the handshake instead of letting one peer
            # replace another's binding.
            raise PeerKeyConflict(
                "That server is already linked with a different key.")
        # Only a handshake that matched (or newly bound) gets to refresh the
        # request metadata, so a mismatched caller cannot rewrite the record.
        cur.execute(
            """UPDATE merge_request
               SET hostname=%s, host=%s, remote_version=%s, last_seen=now()
               WHERE server_uid=%s""",
            ((hostname or "")[:300], (host or "")[:300],
             (remote_version or "")[:64], server_uid))
        conn.commit()
        cur.close()
        return status
    finally:
        DB.release_connection(conn)


def verify_incoming(token, purpose="api", allow_pending=False,
                    require_request=True, ident=None):
    """Check a token from another panel and report what it may do.

    A peer allowed on this panel is bound to the key it presented in its first
    handshake, and only that key may sign its data calls. The handshake and the
    status poll are the only purposes that may still arrive signed with this
    panel's own key, because that is how an unbound peer introduces itself.
    Every other purpose requires a bound peer key.

    Returns (claims, error) where error carries the HTTP status, the message
    and an optional machine code ("link_key_required").
    """
    ident = ident or ensure_local_identity()
    hinted = _unverified_claims(token or "")
    issuer = hinted.get("iss")
    # Only a bounded lookup key is taken from the unverified payload; nothing is
    # trusted until the signature is checked below.
    if not isinstance(issuer, str) or not 1 <= len(issuer) <= 64 or \
            not set(issuer) <= _UID_ALLOWED:
        return None, {"status": 401, "error": "Invalid server token."}
    record = request_record(issuer)
    peer_key = record.get("peer_key") or ""
    local_key = ident.get("key") or ""
    keys = [peer_key] if peer_key else []
    if purpose in ("handshake", "status") or not peer_key:
        # Bootstrap purposes must also keep working after the peer is bound: a
        # linked panel always signs those with the receiving panel's key.
        if local_key and local_key not in keys:
            keys.append(local_key)
    data = None
    for key in keys:
        data = verify_token(token, key)
        if data:
            break
    if not data:
        return None, {"status": 401, "error": "Invalid server token."}
    if data.get("aud") and data.get("aud") != ident.get("server_uid"):
        return None, {"status": 401, "error": "Invalid server token."}
    if data.get("purpose") != purpose:
        return None, {"status": 401, "error": "Invalid server token."}
    # The audience is this panel's uid. The first handshake cannot know it yet
    # (the add flow has not stored the peer uid), so allow an empty aud only for
    # handshake; every later call must name this panel.
    aud = data.get("aud")
    if purpose == "handshake":
        if aud and aud != ident.get("server_uid"):
            return None, {"status": 401, "error": "Invalid server token."}
    elif not aud or aud != ident.get("server_uid"):
        return None, {"status": 401, "error": "Invalid server token."}
    if not peer_key and purpose not in ("handshake", "status"):
        # Never accept a data call that only proves possession of this panel's
        # own key: any peer holding it could then act as any other peer.
        return None, {"status": 401, "error": "That server has not bound a link key yet.",
                      "code": "link_key_required"}
    status = record.get("status")
    if status is None:
        if require_request:
            return None, {"status": 401,
                          "error": "This server has not requested access."}
    elif status != "allowed" and not allow_pending:
        return None, {"status": 401, "error": "This server is not allowed yet."}
    if _remember_jti(data.get("iss"), data.get("jti"), data.get("exp")):
        return None, {"status": 401, "error": "This server token was already used."}
    return data, None


def list_requests():
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            """SELECT server_uid, hostname, host, remote_version, status,
                      requested_at, last_seen, decided_at, decided_by, note
               FROM merge_request
               ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END,
                        last_seen DESC, requested_at DESC""")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        cur.close()
        for row in rows:
            row.update(version_state(row.get("remote_version")))
            for k in ("requested_at", "last_seen", "decided_at"):
                if row.get(k):
                    row[k] = row[k].isoformat()
        return rows
    finally:
        DB.release_connection(conn)


def decide_request(server_uid, allow, actor):
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        status = "allowed" if allow else "denied"
        cur.execute(
            """UPDATE merge_request
               SET status=%s, decided_at=now(), decided_by=%s,
                   last_seen=now()
               WHERE server_uid=%s""",
            (status, actor or "", server_uid))
        changed = cur.rowcount
        conn.commit()
        cur.close()
        # Only the incoming request changes. An outgoing link to the same panel
        # is a separate direction with its own approval on the other side; this
        # must never make this panel show that server before it allowed us.
        return bool(changed)
    finally:
        DB.release_connection(conn)


# ---------------------------------------------------------------------------
# Local records of remote panels
# ---------------------------------------------------------------------------
def normalize_target(host, port=None, base_path=""):
    """Turn what an admin typed into (scheme, host, port, base_path).

    host may be a bare name/IP or a complete URL. A complete URL wins over the
    separate port/path fields, which is what people expect when they paste one.
    A bare host with no port, or port 443, is treated as HTTPS; use :80 or a
    full http:// URL for a plain-HTTP panel.
    """
    host = (host or "").strip()
    if not host:
        raise ValueError("Enter the server host.")
    if "://" in host:
        parts = urllib.parse.urlsplit(host)
        if not parts.hostname:
            raise ValueError("That host is not valid.")
        scheme = (parts.scheme or "http").lower()
        if scheme not in ("http", "https"):
            raise ValueError("Only http and https are supported.")
        port = parts.port or (443 if scheme == "https" else 80)
        path = parts.path or ""
    else:
        # A bare host has no scheme to read. Decide afterwards from the port:
        # 443 (or no port at all) is HTTPS, everything else plain HTTP.
        scheme = None
        # A bare IPv6 literal (::1) is indistinguishable from host:port at a
        # glance, so bracket it before urlsplit and let it fail cleanly if it is
        # not an address.
        raw = host
        try:
            if raw.count(":") > 1 and not raw.startswith("["):
                ipaddress.ip_address(raw)
                raw = "[" + raw + "]"
        except ValueError:
            pass
        parts = urllib.parse.urlsplit("//" + raw)
        if not parts.hostname:
            raise ValueError("That host is not valid.")
        if parts.port:
            port = parts.port
        path = parts.path or ""
    if port in (None, ""):
        port = 443 if scheme in (None, "https") else 80
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if scheme is None:
        scheme = "https" if port == 443 else "http"
    # A path typed into a complete URL wins over the separate panel-path field,
    # matching the "paste a URL" behaviour described above.
    path = (path or base_path or "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/")
    if path == "/":
        path = ""
    if len(path) > 200:
        raise ValueError("The panel path must be 200 characters or fewer.")
    name = parts.hostname or ""
    if not name:
        raise ValueError("That host is not valid.")
    return {"scheme": scheme, "host": name, "port": port, "base_path": path}


def create_server(name, host, port, base_path, key, created_by=""):
    """Store a remote panel and its key. The call is not made here; the caller
    runs handshake() afterwards so a slow or dead host cannot hold a request."""
    target = normalize_target(host, port, base_path)
    key = (key or "").strip()
    if len(key) < 16:
        raise ValueError("The private key is too short. Paste the key shown on the other panel.")
    if len(key) > 200 or any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
        raise ValueError("The private key is not valid. Paste the key shown on the other panel.")
    ensure_local_identity()
    server_id = uuid.uuid4().hex
    key_id = uuid.uuid4().hex
    link_key = _new_key()
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        conn.autocommit = False
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO merge_serverkey (key_id, role, label, key_cipher)
                   VALUES (%s, 'remote', %s, %s)""",
                (key_id, (name or target["host"])[:200], vault.encrypt(key)))
            cur.execute(
                """INSERT INTO merge_server
                       (id, name, host, port, scheme, base_path, key_id,
                        link_key_cipher, status, position, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending',
                           COALESCE((SELECT MAX(position)+1 FROM merge_server), 0), %s)""",
                (server_id, (name or target["host"])[:120], target["host"],
                 target["port"], target["scheme"], target["base_path"], key_id,
                 vault.encrypt(link_key), created_by or ""))
            conn.commit()
            cur.close()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.autocommit = True
    finally:
        DB.release_connection(conn)
    return server_id


def _key_for_server(row):
    """The remote panel's key, whether the row came from get_server(include_key)
    or the usual key-free form used by route handlers."""
    key = row.get("key")
    if key:
        return key
    cipher = row.get("key_cipher")
    if not cipher and row.get("id"):
        conn = DB.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT k.key_cipher FROM merge_server m
                   JOIN merge_serverkey k ON k.key_id = m.key_id
                   WHERE m.id=%s""", (row["id"],))
            found = cur.fetchone()
            cur.close()
            cipher = found[0] if found else None
        finally:
            DB.release_connection(conn)
    if not cipher:
        raise ValueError("The key for that linked server is missing.")
    key = vault.decrypt(cipher)
    if not key:
        raise ValueError("The key for that linked server cannot be read. Replace it.")
    return key


def _link_key_for_server(row):
    """The key this panel signs DATA calls with for one linked peer.

    New links get a key generated for that relationship only, so a different
    peer that holds this panel's bootstrap key cannot mint a token claiming to
    be this panel. Links created before that column existed fall back to the
    local identity key, which keeps them working until they are re-added.
    """
    key = row.get("link_key")
    if key:
        return key
    cipher = row.get("link_key_cipher")
    if not cipher and row.get("id"):
        conn = DB.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT link_key_cipher FROM merge_server WHERE id=%s",
                (row["id"],))
            found = cur.fetchone()
            cur.close()
            cipher = found[0] if found else None
        finally:
            DB.release_connection(conn)
    key = vault.decrypt(cipher or "")
    if key:
        return key
    return ensure_local_identity()["key"]


def list_servers(include_pending=True):
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        clause = "" if include_pending else "WHERE m.approved = TRUE"
        cur.execute(
            f"""SELECT m.id, m.name, m.host, m.port, m.scheme, m.base_path,
                       m.key_id, m.server_uid, m.remote_hostname, m.remote_version,
                       m.status, m.approved, m.last_error, m.last_seen, m.position,
                       m.created_by, m.created_at, k.key_cipher
                FROM merge_server m
                JOIN merge_serverkey k ON k.key_id = m.key_id
                {clause}
                ORDER BY m.position ASC, m.created_at ASC""")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        cur.close()
        for row in rows:
            row.pop("key_cipher", None)
            row.update(version_state(row.get("remote_version")))
            if row.get("last_seen"):
                row["last_seen"] = row["last_seen"].isoformat()
            if row.get("created_at"):
                row["created_at"] = row["created_at"].isoformat()
        return rows
    finally:
        DB.release_connection(conn)


def get_server(server_id, include_key=False):
    if not server_id:
        return None
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            """SELECT m.id, m.name, m.host, m.port, m.scheme, m.base_path,
                      m.key_id, m.link_key_cipher, m.server_uid,
                      m.remote_hostname, m.remote_version,
                      m.status, m.approved, m.last_error, m.last_seen, m.position,
                      m.created_by, m.created_at, k.key_cipher
               FROM merge_server m
               JOIN merge_serverkey k ON k.key_id = m.key_id
               WHERE m.id = %s""", (server_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return None
        cols = [d[0] for d in cur.description]
        out = dict(zip(cols, row))
        if include_key:
            out["key"] = vault.decrypt(out["key_cipher"])
            out["link_key"] = vault.decrypt(out.get("link_key_cipher") or "")
        out.pop("key_cipher", None)
        out.pop("link_key_cipher", None)
        out.update(version_state(out.get("remote_version")))
        cur.close()
        return out
    finally:
        DB.release_connection(conn)


def update_server(server_id, **fields):
    allowed = {"name", "host", "port", "scheme", "base_path", "server_uid",
               "remote_hostname", "remote_version", "status", "approved",
               "last_error"}
    parts, params = [], []
    for k, v in fields.items():
        if k in allowed:
            parts.append(f"{k} = %s")
            params.append(v)
    if not parts:
        return
    params.append(server_id)
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE merge_server SET {', '.join(parts)} WHERE id=%s", params)
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)


def update_server_by_uid(server_uid, **fields):
    """Remote approval arrives keyed by the remote's uid, not our local id."""
    allowed = {"status", "approved", "last_error", "last_seen"}
    parts, params = [], []
    for k, v in fields.items():
        if k in allowed:
            parts.append(f"{k} = %s")
            params.append(v)
    if not parts:
        return
    params.append(server_uid)
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(f"UPDATE merge_server SET {', '.join(parts)} WHERE server_uid=%s", params)
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)


def replace_server_key(server_id, key):
    """Replace the stored key for one linked panel and force a fresh handshake."""
    key = (key or "").strip()
    if len(key) < 16:
        raise ValueError("The private key is too short. Paste the key shown on the other panel.")
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT key_id FROM merge_server WHERE id=%s", (server_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return False
        cur.execute(
            "UPDATE merge_serverkey SET key_cipher=%s, rotated_at=now() "
            "WHERE key_id=%s", (vault.encrypt(key), row[0]))
        cur.execute(
            """UPDATE merge_server
               SET server_uid='', remote_hostname='', status='pending',
                   approved=FALSE, last_error=''
               WHERE id=%s""", (server_id,))
        conn.commit()
        cur.close()
        return True
    finally:
        DB.release_connection(conn)


def delete_server(server_id):
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        conn.autocommit = False
        try:
            cur = conn.cursor()
            cur.execute("SELECT key_id FROM merge_server WHERE id=%s", (server_id,))
            row = cur.fetchone()
            if not row:
                cur.close()
                conn.rollback()
                return False
            cur.execute("DELETE FROM merge_server WHERE id=%s", (server_id,))
            cur.execute("DELETE FROM merge_serverkey WHERE key_id=%s", (row[0],))
            cur.execute("DELETE FROM merge_user_access WHERE server_id=%s", (server_id,))
            conn.commit()
            cur.close()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.autocommit = True
    finally:
        DB.release_connection(conn)


def reorder_servers(ids):
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        for pos, sid in enumerate([i for i in (ids or []) if i]):
            cur.execute("UPDATE merge_server SET position=%s WHERE id=%s", (pos, sid))
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)


# ---------------------------------------------------------------------------
# Per-user visibility
# ---------------------------------------------------------------------------
def normalize_access(raw):
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    for key in _USER_SCOPES:
        value = raw.get(key, False)
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value != 0
        elif isinstance(value, str):
            out[key] = value.strip().lower() in ("1", "true", "yes", "on")
        else:
            out[key] = False
    return out


def set_user_access(username, entries):
    """Replace one account's server list wholesale. entries is an ordered list
    of {server_id, permissions}; unknown servers are dropped. An entry with no
    metric scopes is still meaningful: it grants the hardware overview only."""
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute("SELECT id FROM merge_server")
        valid = {r[0] for r in cur.fetchall()}
        cur.execute("DELETE FROM merge_user_access WHERE username=%s", (username,))
        seen = set()
        pos = 0
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            sid = str(entry.get("server_id") or "")
            if sid not in valid or sid in seen:
                continue
            perms = normalize_access(entry.get("permissions", entry))
            seen.add(sid)
            cur.execute(
                """INSERT INTO merge_user_access
                       (username, server_id, permissions, position)
                   VALUES (%s, %s, %s, %s)""",
                (username, sid, json.dumps(perms), pos))
            pos += 1
        conn.commit()
        cur.close()
        return True
    finally:
        DB.release_connection(conn)


def get_user_access(username):
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        cur.execute(
            """SELECT a.server_id, a.permissions, a.position,
                      m.name, m.remote_hostname, m.status, m.approved
               FROM merge_user_access a
               JOIN merge_server m ON m.id = a.server_id
               WHERE a.username=%s
               ORDER BY a.position ASC, m.position ASC""", (username,))
        rows = cur.fetchall()
        cur.close()
        return [
            {"server_id": r[0], "permissions": normalize_access(r[1]),
             "position": r[2], "name": r[3], "hostname": r[4],
             "status": r[5], "approved": r[6]}
            for r in rows
        ]
    finally:
        DB.release_connection(conn)


def user_scopes(username):
    return {row["server_id"]: row["permissions"]
            for row in get_user_access(username)}


def delete_user_access(username):
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM merge_user_access WHERE username=%s", (username,))
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)


def servers_for_user(username, role):
    """Server-page list. Admin sees every approved panel; staff see only the
    panels an admin explicitly listed for them."""
    servers = [s for s in list_servers() if s.get("approved")]
    if role == "admin":
        for s in servers:
            s["scopes"] = {k: True for k in _USER_SCOPES}
            s["terminal"] = True
        return servers
    access = {row["server_id"]: row for row in get_user_access(username)}
    out = []
    for s in servers:
        hit = access.get(s["id"])
        if not hit:
            continue
        s = dict(s)
        s["scopes"] = hit["permissions"]
        s["position"] = hit["position"]
        s["terminal"] = False
        out.append(s)
    out.sort(key=lambda x: (x.get("position", 0), x.get("created_at") or ""))
    return out


def access_for_user(username, role, server):
    """(has the server, metric scopes). An access row with no scopes is valid:
    it grants the always-visible hardware overview and nothing else."""
    if role == "admin":
        return True, list(ADMIN_SCOPES)
    perms = user_scopes(username).get(server["id"])
    if perms is None:
        return False, []
    return True, [k for k in _USER_SCOPES if perms.get(k)]


def scopes_for(username, role, server):
    return access_for_user(username, role, server)[1]


# ---------------------------------------------------------------------------
# HTTP / websocket calls to the other panel
# ---------------------------------------------------------------------------
def server_url(server, path=""):
    if not path.startswith("/"):
        path = "/" + path
    host = str(server["host"])
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    base = f"{server['scheme']}://{host}:{int(server['port'])}"
    return base + (server.get("base_path") or "") + path


def server_ws_url(server, path=""):
    url = server_url(server, path)
    if url.startswith("https://"):
        url = "wss://" + url[8:]
    elif url.startswith("http://"):
        url = "ws://" + url[7:]
    return url


def make_server_token(server, subject="server", role="admin", scopes=None,
                      purpose="api", ttl=120, bootstrap=False):
    """A short-lived token for one call to a linked panel.

    bootstrap is only for the two calls that an unbound peer makes: the
    handshake and the status poll. They are signed with the receiving panel's
    key because that is the only key both sides already know. Every data call
    is signed with the key generated for this one link, which the receiver
    bound at handshake time, so holding another peer's key never grants data
    access.
    """
    ident = ensure_local_identity()
    claims = {
        "iss": ident["server_uid"],
        "aud": server.get("server_uid") or "",
        "sub": subject or "server",
        "role": role or "staff",
        "scopes": list(scopes or []),
        "purpose": purpose,
        "host": ident.get("label") or _local_label(),
        "hostname": _local_label(),
        "version": panel_version(),
    }
    key = _key_for_server(server) if bootstrap else _link_key_for_server(server)
    return sign_token(key, claims, ttl=ttl)


def _needs_link_key(data):
    """True for the 401 that means the other side has not bound our key yet."""
    return isinstance(data, dict) and data.get("code") == "link_key_required"


def _open_request(url, token, method="GET", body=None, timeout=10,
                  content_type="application/json"):
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Cookie", "argus_merge=" + token)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "argus-management-merge")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", content_type)
    req.data = data
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def http_call(server, path, token, method="GET", body=None, timeout=10):
    """(status_code, parsed_json_or_None, error_text). Never raises."""
    url = server_url(server, path)
    try:
        with _open_request(url, token, method=method, body=body, timeout=timeout) as resp:
            limit = 5_000_000
            raw = resp.read(limit + 1)
            if len(raw) > limit:
                message = "The remote response is too large to read."
                return 502, {"error": message}, message
            try:
                data = json.loads(raw) if raw else None
            except Exception:
                data = None
            if not isinstance(data, dict):
                if 200 <= resp.status < 300:
                    # A 2xx with an empty, short or non-object body is not a
                    # success: the caller would otherwise act on partial or
                    # missing data as if the peer had answered.
                    message = "The remote panel returned an invalid response."
                    return 502, {"error": message}, message
                return resp.status, {"raw": raw.decode("utf-8", "replace")}, ""
            return resp.status, data, ""
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(1_000_000)
            try:
                data = json.loads(raw or b"{}")
            except Exception:
                data = {"error": raw.decode("utf-8", "replace")[:500]}
        except Exception:
            data = {"error": f"HTTP {e.code}"}
        return e.code, data, str(data.get("error") or f"HTTP {e.code}")
    except Exception as e:
        return 0, None, f"{type(e).__name__}: {e}"


def handshake(server_id, timeout=8):
    """Introduce this panel to the remote one, or refresh a known link.

    Returns a dict that is safe to hand back to the browser. The local record is
    updated with the remote uid, hostname and status. The body carries this
    panel's own key as link_key so the receiver can bind it to this uid; that is
    the only moment the key crosses the wire.
    """
    server = get_server(server_id, include_key=True)
    if not server:
        return {"ok": False, "error": "That server is no longer listed."}
    link_key = _link_key_for_server(server)
    token = make_server_token(server, scopes=["handshake"], purpose="handshake",
                              bootstrap=True)
    code, data, err = http_call(
        server, "/api/merge/handshake", token, method="POST",
        body={"hostname": _local_label(), "host": _local_label(),
              "link_key": link_key}, timeout=timeout)
    if code == 0:
        update_server(server_id, status="down", last_error=err[:500])
        return {"ok": False, "status": "down", "error": err}
    if code != 200 or not isinstance(data, dict):
        msg = (data or {}).get("error") or err or f"HTTP {code}"
        if code in (401, 403):
            update_server(server_id, status="denied", approved=False,
                          last_error=str(msg)[:500])
            return {"ok": False, "status": "denied", "error": msg}
        if code == 409:
            # This panel already has a different key bound for us. It is not a
            # network failure, so do not present it as one.
            update_server(server_id, status="pending", approved=False,
                          last_error=str(msg)[:500])
            return {"ok": False, "status": "key_mismatch", "error": msg}
        update_server(server_id, status="down", last_error=str(msg)[:500])
        return {"ok": False, "status": "down", "error": msg}
    status = data.get("status") or "pending"
    approved = status == "allowed"
    remote_version = str(data.get("version") or "")[:64]
    update_server(
        server_id,
        server_uid=data.get("server_uid") or server.get("server_uid") or "",
        remote_hostname=(data.get("hostname") or "")[:300],
        remote_version=remote_version,
        status="connected" if approved else status,
        approved=approved,
        last_error="")
    conn = DB.get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE merge_serverkey SET server_uid=%s WHERE key_id=%s",
            (data.get("server_uid") or "", server["key_id"]))
        conn.commit()
        cur.close()
    finally:
        DB.release_connection(conn)
    result = {"ok": True, "status": "connected" if approved else status,
              "server_uid": data.get("server_uid"),
              "hostname": data.get("hostname") or "",
              "version": panel_version(),
              "remote_version": remote_version}
    result.update(version_state(remote_version))
    return result


def refresh_status(server_id, timeout=5, repaired=False):
    started = time.monotonic()

    def remaining():
        """Keep the whole check, including a key repair, inside its budget."""
        return max(0.05, timeout - (time.monotonic() - started))

    server = get_server(server_id, include_key=True)
    if not server or not server.get("server_uid"):
        return {"ok": False, "status": server.get("status") if server else "gone",
                "error": "No handshake has completed yet."}
    token = make_server_token(server, scopes=["status"], purpose="status",
                              bootstrap=True)
    code, data, err = http_call(server, "/api/merge/status", token,
                                timeout=remaining())
    if code == 0:
        update_server(server_id, status="down", last_error=err[:500])
        return {"ok": False, "status": "down", "error": err}
    if code != 200 or not isinstance(data, dict):
        msg = (data or {}).get("error") or err or f"HTTP {code}"
        if code in (401, 403):
            update_server(server_id, status="denied", approved=False,
                          last_error=str(msg)[:500])
            return {"ok": False, "status": "denied", "error": msg}
        update_server(server_id, status="down", last_error=str(msg)[:500])
        return {"ok": False, "status": "down", "error": msg}
    if data.get("link_key_required") and not repaired:
        # An allowed link from before per-peer keys: the other side has no key
        # bound for this panel. Its handshake is idempotent and binds the key;
        # poll once more so the caller sees the repaired state. Both steps share
        # the original timeout budget.
        handshake(server_id, timeout=remaining())
        return refresh_status(server_id, timeout=remaining(), repaired=True)
    status = data.get("status") or "pending"
    approved = status == "allowed"
    remote_version = str(data.get("version") or "")[:64]
    fields = {"status": "connected" if approved else status,
              "approved": approved, "last_error": "",
              "remote_version": remote_version}
    if data.get("hostname"):
        fields["remote_hostname"] = str(data["hostname"])[:300]
    update_server(server_id, **fields)
    result = {"ok": True, "status": "connected" if approved else status,
              "server_uid": server.get("server_uid"),
              "hostname": data.get("hostname") or "",
              "version": panel_version(),
              "remote_version": remote_version}
    result.update(version_state(remote_version))
    return result


def prune_requests(uid_prefix=""):
    """Drop stale handshakes, then keep only the newest 200 pending ones.

    uid_prefix is for tests: it limits the delete to rows whose uid starts
    with that string so a test never removes another suite's pending request
    from the shared database. Production calls this with no prefix.
    """
    conn = DB.get_connection()
    try:
        ensure_schema(conn)
        cur = conn.cursor()
        clause, params = "", []
        if uid_prefix:
            clause = " AND left(server_uid, %s) = %s"
            params = [len(uid_prefix), uid_prefix]
        cur.execute(
            """DELETE FROM merge_request
               WHERE status IN ('pending', 'denied')
                 AND (requested_at < now() - interval '30 days'
                      OR last_seen < now() - interval '30 days')""" + clause,
            params)
        removed = cur.rowcount
        cur.execute(
            """DELETE FROM merge_request
               WHERE status = 'pending'
                 AND server_uid NOT IN (
                     SELECT server_uid FROM merge_request
                     WHERE status = 'pending'
                     ORDER BY last_seen DESC, requested_at DESC, server_uid
                     LIMIT 200)""" + clause,
            params)
        removed += cur.rowcount
        conn.commit()
        cur.close()
        return removed
    finally:
        DB.release_connection(conn)


def refresh_all_status(timeout=4):
    """Best-effort background sweep. One dead panel never blocks the others."""
    from concurrent.futures import ThreadPoolExecutor, wait

    try:
        prune_requests()
    except Exception:
        pass

    servers = [s for s in list_servers() if s.get("server_uid")]
    out = {}
    if not servers:
        return out

    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        budget = 4.0
    budget = max(0.0, budget)
    deadline = time.monotonic() + budget
    workers = max(1, min(8, len(servers)))
    executor = ThreadPoolExecutor(max_workers=workers,
                                  thread_name_prefix="merge-status")

    def check(server_id):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"ok": False, "status": "down",
                    "error": "Status check timed out."}
        return refresh_status(server_id, timeout=min(budget, remaining))

    futures = {}
    try:
        for server in servers:
            futures[executor.submit(check, server["id"])] = server
        done, _ = wait(list(futures),
                        timeout=max(0.0, deadline - time.monotonic()))
        for future, server in futures.items():
            if future in done:
                try:
                    out[server["id"]] = future.result()
                except Exception as e:
                    message = f"{type(e).__name__}: {e}"
                    try:
                        update_server(server["id"], status="down",
                                      last_error=message[:500])
                    except Exception:
                        pass
                    out[server["id"]] = {"ok": False, "status": "down",
                                         "error": message}
            else:
                # Do not persist "down" for work that was cancelled before it
                # started: the peer was never contacted, and a busy sweep with
                # more servers than workers would flap healthy links. A check
                # that is still running writes its own result when it finishes.
                future.cancel()
                out[server["id"]] = {"ok": False, "status": "down",
                                     "error": "Status check timed out."}
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return out


def call_for_user(server, username, role, path, method="GET", body=None,
                  required=None, timeout=10):
    """Make one request as this signed-in person, with exactly the scopes the
    local permission model allows. The remote side re-checks the signature and
    the scope claims, so a tampered local page cannot widen them."""
    scopes = scopes_for(username, role, server)
    if required and required not in scopes:
        return 403, {"error": "Not permitted for this server."}, "scope"
    token = make_server_token(server, subject=username, role=role,
                              scopes=scopes, purpose="api")
    code, data, err = http_call(server, path, token, method=method, body=body,
                                timeout=timeout)
    if code == 401 and _needs_link_key(data):
        # An allowed link from before per-peer keys. One handshake binds this
        # panel's key on the other side and the call is retried once with a
        # token signed by it.
        handshake(server["id"])
        token = make_server_token(server, subject=username, role=role,
                                  scopes=scopes, purpose="api")
        code, data, err = http_call(server, path, token, method=method,
                                    body=body, timeout=timeout)
    if code == 0:
        update_server(server["id"], status="down", last_error=err[:500])
    elif code == 401:
        # The key no longer matches, or the remote admin withdrew the approval.
        update_server(server["id"], status="denied", approved=False,
                      last_error=(err or "access denied")[:500])
    elif code == 200:
        update_server(server["id"], status="connected", approved=True,
                      last_error="")
    # A 403 is a normal refusal of one operation (a protected file, an upload
    # name that exists) and must not tear down the whole link.
    return code, data, err


# ---------------------------------------------------------------------------
# Streaming file transfer
# ---------------------------------------------------------------------------
def open_download(server, username, role, path, timeout=30):
    """Open a remote file for streaming. Returns (response, error)."""
    scopes = scopes_for(username, role, server)
    if "disk" not in scopes:
        return None, "Not permitted for this server."
    url = server_url(server, "/api/merge/download?" +
                     urllib.parse.urlencode({"path": path}))
    for attempt in (0, 1):
        token = make_server_token(server, subject=username, role=role,
                                  scopes=scopes, purpose="api")
        try:
            resp = _open_request(url, token, timeout=timeout)
            update_server(server["id"], status="connected", approved=True,
                          last_error="")
            return resp, ""
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read(2000) or b"{}")
                message = body.get("error") or f"HTTP {e.code}"
            except Exception:
                body = {}
                message = f"HTTP {e.code}"
            if e.code == 401 and _needs_link_key(body) and attempt == 0:
                handshake(server["id"])
                continue
            if e.code == 401:
                update_server(server["id"], status="denied", approved=False,
                              last_error=str(message)[:500])
            return None, message
        except Exception as e:
            message = f"{type(e).__name__}: {e}"
            update_server(server["id"], status="down", last_error=message[:500])
            return None, message
    return None, "That server needs its link key refreshed."


def upload_file(server, username, role, folder, name, fileobj, size,
                timeout=3600):
    """Stream a staged local upload to the remote panel with Content-Length."""
    scopes = scopes_for(username, role, server)
    if "disk" not in scopes:
        return 403, {"error": "Not permitted for this server."}
    parts = urllib.parse.urlsplit(server_url(server, "/api/merge/upload"))
    path = parts.path + "?" + urllib.parse.urlencode({"path": folder or "",
                                                      "name": name})
    for attempt in (0, 1):
        token = make_server_token(server, subject=username, role=role,
                                  scopes=scopes, purpose="api")
        if attempt:
            try:
                fileobj.seek(0)
            except Exception:
                return 0, {"error": "The upload could not be restarted."}
        conn = None
        try:
            if parts.scheme == "https":
                conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                                   timeout=timeout,
                                                   context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                                  timeout=timeout)
            conn.putrequest("POST", path)
            conn.putheader("Authorization", "Bearer " + token)
            conn.putheader("Cookie", "argus_merge=" + token)
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(int(size)))
            conn.endheaders()
            sent = 0
            while True:
                chunk = fileobj.read(1024 * 1024)
                if not chunk:
                    break
                conn.send(chunk)
                sent += len(chunk)
            resp = conn.getresponse()
            raw = resp.read(2_000_000)
            try:
                data = json.loads(raw or b"{}")
            except Exception:
                data = {"error": raw.decode("utf-8", "replace")[:500]}
            if resp.status == 200:
                update_server(server["id"], status="connected", approved=True,
                              last_error="")
            elif resp.status == 401:
                if _needs_link_key(data) and attempt == 0:
                    handshake(server["id"])
                    continue
                update_server(server["id"], status="denied", approved=False,
                              last_error=str(data.get("error") or "access denied")[:500])
            return resp.status, data
        except Exception as e:
            message = f"{type(e).__name__}: {e}"
            try:
                update_server(server["id"], status="down", last_error=message[:500])
            except Exception:
                pass
            return 0, {"error": message}
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    return 0, {"error": "That server needs its link key refreshed."}
