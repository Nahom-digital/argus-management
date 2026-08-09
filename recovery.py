#!/usr/bin/env python3
# recovery.py — admin password hashing and single-use account recovery codes.
#
# Shared deliberately by management.py (the setup wizard / CLI) and panel.py
# (the running web panel) so the hash format and the code format can never
# drift apart between the thing that writes codes and the thing that checks
# them. Every function takes an open psycopg2 connection rather than opening
# its own, because the two callers get their connections from different places
# (the wizard connects directly, the panel borrows from DB.py's pool).

import os
import hmac
import stat
import hashlib
import secrets
from datetime import datetime

# The panel's own admin password hash. This MUST stay byte-identical to
# DB._hash_pw() or logins stop verifying — same algorithm, same static salt,
# same iteration count.
_PW_SALT = b"botcontrol"
_PW_ITERATIONS = 260_000

# Recovery codes are only 12 digits (~40 bits), so they get a per-code random
# salt and a slow KDF: if the database ever leaks, the codes must not fall to
# an offline sweep of the 10^12 space.
_CODE_ITERATIONS = 200_000
_CODE_SALT_BYTES = 16

CODE_COUNT = 5
CODE_DIGITS = 12

RECOVERY_FILENAME = ".recovery"

# Passwords this rejects outright regardless of length.
_COMMON_PASSWORDS = {
    "password", "password1", "admin123", "12345678", "123456789", "1234567890",
    "qwertyui", "letmein1", "adminadmin", "changeme", "management",
}


# --------------------------------------------------------------------------- #
# password hashing / policy
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), _PW_SALT, _PW_ITERATIONS).hex()


def password_problem(password: str, username: str = "") -> str:
    """Return a human-readable reason the password is unacceptable, else ""."""
    if len(password) < 8:
        return "Use at least 8 characters."
    if len(password) > 200:
        return "That password is unreasonably long."
    if password.lower() in _COMMON_PASSWORDS:
        return "That password is too common — pick another."
    if username and password.lower() == username.lower():
        return "The password cannot be the same as the username."
    if password.isdigit():
        return "Use more than just digits."
    return ""


# --------------------------------------------------------------------------- #
# recovery code generation / hashing
# --------------------------------------------------------------------------- #
def generate_codes(count: int = CODE_COUNT, digits: int = CODE_DIGITS):
    """`count` cryptographically random codes of exactly `digits` digits."""
    span = 10 ** digits
    return [str(secrets.randbelow(span)).zfill(digits) for _ in range(count)]


def normalize_code(raw: str) -> str:
    """Keep only digits, so spaced/dashed input pasted from .recovery works."""
    return "".join(ch for ch in str(raw or "") if ch.isdigit())


def format_code(code: str) -> str:
    """1234 5678 9012 — grouped for reading, never for storage."""
    code = normalize_code(code)
    return " ".join(code[i:i + 4] for i in range(0, len(code), 4))


def hash_code(code: str, salt: bytes = None) -> str:
    salt = salt or secrets.token_bytes(_CODE_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", normalize_code(code).encode(), salt, _CODE_ITERATIONS)
    return f"pbkdf2${_CODE_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_code(code: str, stored: str) -> bool:
    """Constant-time check of a candidate code against one stored hash."""
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", normalize_code(code).encode(),
            bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except Exception:
        return False


def burn_time():
    """Spend the same work as verify_code() on a miss.

    Called when the username does not exist, so a wrong username and a wrong
    code cost the same wall-clock time and the endpoint cannot be used to
    enumerate accounts.
    """
    hashlib.pbkdf2_hmac("sha256", b"\x00" * 12,
                        b"\x00" * _CODE_SALT_BYTES, _CODE_ITERATIONS)


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #
SCHEMA = (
    """CREATE TABLE IF NOT EXISTS admin_recovery_code (
           id         SERIAL PRIMARY KEY,
           username   TEXT NOT NULL,
           code_hash  TEXT NOT NULL,
           created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
           used_at    TIMESTAMP,
           used_ip    TEXT
       )""",
    "CREATE INDEX IF NOT EXISTS idx_arc_user ON admin_recovery_code (username, used_at)",
)


def ensure_table(conn):
    cur = conn.cursor()
    try:
        for stmt in SCHEMA:
            cur.execute(stmt)
        if not getattr(conn, "autocommit", False):
            conn.commit()
    finally:
        cur.close()


def replace_codes(conn, username: str, codes):
    """Swap in a fresh set, retiring every previous code for that user."""
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM admin_recovery_code WHERE username = %s", (username,))
        for code in codes:
            cur.execute(
                "INSERT INTO admin_recovery_code (username, code_hash) VALUES (%s, %s)",
                (username, hash_code(code)))
        if not getattr(conn, "autocommit", False):
            conn.commit()
    finally:
        cur.close()


def remaining(conn, username: str):
    """(unused, total) for this user."""
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT count(*) FILTER (WHERE used_at IS NULL), count(*) "
            "FROM admin_recovery_code WHERE username = %s", (username,))
        row = cur.fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)
    finally:
        cur.close()


def generated_at(conn, username: str):
    cur = conn.cursor()
    try:
        cur.execute("SELECT max(created_at) FROM admin_recovery_code "
                    "WHERE username = %s", (username,))
        row = cur.fetchone()
        return row[0] if row and row[0] else None
    finally:
        cur.close()


def consume_code(conn, username: str, code: str, ip: str = "") -> bool:
    """Spend one unused code. True only if it matched and was marked used.

    Every unused row is evaluated even after a hit, so the time taken does not
    reveal which slot matched. The UPDATE is guarded on `used_at IS NULL` so
    two concurrent requests cannot spend the same code twice.
    """
    digits = normalize_code(code)
    if len(digits) != CODE_DIGITS:
        burn_time()
        return False

    cur = conn.cursor()
    try:
        cur.execute("SELECT id, code_hash FROM admin_recovery_code "
                    "WHERE username = %s AND used_at IS NULL ORDER BY id",
                    (username,))
        rows = cur.fetchall()
        if not rows:
            burn_time()
            return False

        matched_id = None
        for row_id, code_hash in rows:
            if verify_code(digits, code_hash) and matched_id is None:
                matched_id = row_id
        if matched_id is None:
            return False

        cur.execute(
            "UPDATE admin_recovery_code SET used_at = CURRENT_TIMESTAMP, used_ip = %s "
            "WHERE id = %s AND used_at IS NULL", (ip or None, matched_id))
        spent = cur.rowcount == 1
        if not getattr(conn, "autocommit", False):
            conn.commit()
        return spent
    finally:
        cur.close()


# --------------------------------------------------------------------------- #
# the .recovery file
# --------------------------------------------------------------------------- #
def recovery_path(project_dir: str) -> str:
    return os.path.join(project_dir, RECOVERY_FILENAME)


def write_recovery_file(project_dir: str, username: str, codes) -> str:
    """Write the only plaintext copy of the codes, readable by its owner alone."""
    path = recovery_path(project_dir)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = [
        "ARGUS MANAGEMENT — ACCOUNT RECOVERY CODES",
        "=" * 48,
        "",
        f"Account : {username}",
        f"Created : {stamp}",
        "",
        "Each code unlocks ONE password reset from the panel's login page",
        '(the "Recover account" link) and stops working the moment it is used.',
        "",
        "Keep this file somewhere safe and offline. Anyone holding a code can",
        "take over the panel. Regenerating codes invalidates every code below.",
        "",
    ]
    body += [f"  {i}.  {format_code(code)}" for i, code in enumerate(codes, 1)]
    body += ["", "=" * 48, ""]

    # Create private from the outset — never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(body))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 0600 even if it pre-existed
    return path
