# SSH access settings for this box: keypair generation, root-login toggle,
# and encrypted storage of the private key + a reference password. Mirrors
# recovery.py's shape (its own SCHEMA tuple, its own ensure/read/write
# functions, no third-party state) so management.py and panel.py can both
# import it without either owning the table definition.
import os
import re
import stat
import subprocess

import vault

KEY_BASENAME = "id_ed25519"
SSHD_CONFIG_PATHS = ("/etc/ssh/sshd_config", "/etc/sshd_config")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS ssh (
        id SERIAL PRIMARY KEY,
        public_key TEXT,
        private_key_encrypted TEXT,
        password_encrypted TEXT,
        key_fingerprint TEXT,
        allow_password_login BOOLEAN NOT NULL DEFAULT TRUE,
        generated_at TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )""",
)


def ensure_table(conn):
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    conn.commit()
    cur.close()


def _project_dir():
    return os.path.dirname(os.path.abspath(__file__))


def key_paths():
    base = _project_dir()
    return os.path.join(base, KEY_BASENAME), os.path.join(base, KEY_BASENAME + ".pub")


def key_files_exist():
    priv, pub = key_paths()
    return os.path.exists(priv) and os.path.exists(pub)


def sshd_running():
    rc = subprocess.run(["systemctl", "is-active", "--quiet", "ssh"]).returncode
    if rc == 0:
        return True
    rc = subprocess.run(["systemctl", "is-active", "--quiet", "sshd"]).returncode
    return rc == 0


def ensure_sshd_running():
    """Best-effort start of the SSH daemon; never raises."""
    for unit in ("ssh", "sshd"):
        r = subprocess.run(["systemctl", "start", unit], capture_output=True, text=True)
        if r.returncode == 0:
            subprocess.run(["systemctl", "enable", unit], capture_output=True, text=True)
            return True
    return sshd_running()


def _find_sshd_config():
    for p in SSHD_CONFIG_PATHS:
        if os.path.exists(p):
            return p
    return None


def password_login_allowed():
    path = _find_sshd_config()
    if not path:
        return True
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return True
    m = re.search(r'(?im)^\s*PasswordAuthentication\s+(yes|no)\s*$', text)
    if not m:
        return True
    return m.group(1).lower() == "yes"


def set_password_login(allowed: bool):
    """Set PasswordAuthentication yes/no in sshd_config and reload sshd.
    Returns (ok, message)."""
    path = _find_sshd_config()
    if not path:
        return False, "sshd_config not found"
    value = "yes" if allowed else "no"
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        return False, str(e)

    found = False
    out = []
    for line in lines:
        if re.match(r'(?i)^\s*#?\s*PasswordAuthentication\s+', line):
            out.append(f"PasswordAuthentication {value}\n")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"\nPasswordAuthentication {value}\n")

    try:
        with open(path, "w") as f:
            f.writelines(out)
    except OSError as e:
        return False, str(e)

    for unit in ("ssh", "sshd"):
        r = subprocess.run(["systemctl", "reload", unit], capture_output=True, text=True)
        if r.returncode == 0:
            return True, f"PasswordAuthentication set to {value}"
    r = subprocess.run(["systemctl", "restart", "ssh"], capture_output=True, text=True)
    if r.returncode == 0:
        return True, f"PasswordAuthentication set to {value}"
    return True, f"PasswordAuthentication set to {value} (reload the SSH service manually to apply)"


def generate_keypair():
    """Generate a new ed25519 keypair in the project directory, add the
    public key to root's authorized_keys, and return (public_key, private_key,
    fingerprint). Raises RuntimeError on failure."""
    priv, pub = key_paths()
    if os.path.exists(priv):
        os.remove(priv)
    if os.path.exists(pub):
        os.remove(pub)

    r = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", priv, "-N", "", "-C", "argus-management"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "ssh-keygen failed")

    os.chmod(priv, stat.S_IRUSR | stat.S_IWUSR)
    with open(priv) as f:
        private_key = f.read()
    with open(pub) as f:
        public_key = f.read().strip()

    fp = subprocess.run(["ssh-keygen", "-lf", pub], capture_output=True, text=True, timeout=10)
    fingerprint = fp.stdout.strip() if fp.returncode == 0 else ""

    _authorize_root_key(public_key)
    return public_key, private_key, fingerprint


def _authorize_root_key(public_key):
    """Best-effort: append the new public key to root's authorized_keys so
    the generated key can actually be used to sign in. Never raises."""
    try:
        auth_dir = "/root/.ssh"
        auth_file = os.path.join(auth_dir, "authorized_keys")
        os.makedirs(auth_dir, exist_ok=True, mode=0o700)
        existing = ""
        if os.path.exists(auth_file):
            with open(auth_file) as f:
                existing = f.read()
        if public_key not in existing:
            with open(auth_file, "a") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(public_key + "\n")
        os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def save_record(conn, public_key, private_key, password, fingerprint, allow_password_login):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute("DELETE FROM ssh")
    cur.execute(
        """INSERT INTO ssh
           (public_key, private_key_encrypted, password_encrypted,
            key_fingerprint, allow_password_login, generated_at, updated_at)
           VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)""",
        (public_key, vault.encrypt(private_key), vault.encrypt(password or ""),
         fingerprint, allow_password_login),
    )
    conn.commit()
    cur.close()


def update_password(conn, password):
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        "UPDATE ssh SET password_encrypted = %s, updated_at = CURRENT_TIMESTAMP",
        (vault.encrypt(password or ""),),
    )
    conn.commit()
    cur.close()


def get_record(conn):
    """Returns a dict with decrypted private_key/password, or None if no
    record exists yet."""
    ensure_table(conn)
    cur = conn.cursor()
    cur.execute(
        """SELECT public_key, private_key_encrypted, password_encrypted,
                  key_fingerprint, allow_password_login, generated_at
           FROM ssh ORDER BY id DESC LIMIT 1"""
    )
    row = cur.fetchone()
    cur.close()
    if not row:
        return None
    public_key, priv_enc, pw_enc, fingerprint, allow_pw, generated_at = row
    return {
        "public_key": public_key,
        "private_key": vault.decrypt(priv_enc) if priv_enc else "",
        "password": vault.decrypt(pw_enc) if pw_enc else "",
        "fingerprint": fingerprint,
        "allow_password_login": allow_pw,
        "generated_at": generated_at.isoformat() if generated_at else None,
    }
