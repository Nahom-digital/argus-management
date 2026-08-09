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
    """Generate a new ed25519 keypair, install the public half so it can
    actually be used, and confirm that it authenticates.

    Returns (public_key, private_key, fingerprint, report) where report
    describes what was installed and whether a real login succeeded. Raises
    RuntimeError only if the key could not be generated at all: an install or
    verification problem is reported rather than thrown, because the key itself
    is still valid and downloadable.
    """
    priv, pub = key_paths()
    for path in (priv, pub):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError as e:
                # Usually a key left behind by a run under a different account.
                # Say so, rather than surfacing a bare PermissionError.
                raise RuntimeError(
                    f"could not replace the existing key at {path}: {e}. "
                    "Remove it by hand, or run the panel as the account that owns it."
                ) from e

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

    report = install_public_key(public_key)
    return public_key, private_key, fingerprint, report


def _target_home(username="root"):
    try:
        import pwd
        entry = pwd.getpwnam(username)
        return entry.pw_dir, entry.pw_uid, entry.pw_gid
    except (ImportError, KeyError):
        return ("/root" if username == "root" else f"/home/{username}"), 0, 0


def install_public_key(public_key, username="root"):
    """Put the public key where sshd will actually read it.

    Reports what happened instead of swallowing it. The previous version caught
    OSError and passed, so a panel running without the privileges to write
    /root/.ssh told the operator the key was ready when nothing had been
    installed.

    sshd's StrictModes refuses an authorized_keys file, or a .ssh directory,
    that is group or world writable, so the modes are set explicitly rather
    than left to makedirs and the umask.
    """
    steps, problems = [], []
    home, uid, gid = _target_home(username)
    auth_dir = os.path.join(home, ".ssh")
    auth_file = os.path.join(auth_dir, "authorized_keys")

    try:
        if not os.path.isdir(auth_dir):
            os.makedirs(auth_dir, exist_ok=True)
            steps.append(f"created {auth_dir}")
        # Applied whether or not we created it: an existing directory with
        # loose modes is exactly the case StrictModes rejects.
        os.chmod(auth_dir, stat.S_IRWXU)

        existing = ""
        if os.path.exists(auth_file):
            with open(auth_file) as f:
                existing = f.read()

        if public_key.split()[1] in existing:
            steps.append("key was already authorized")
        else:
            with open(auth_file, "a") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(public_key + "\n")
            steps.append(f"appended the key to {auth_file}")

        os.chmod(auth_file, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.chown(auth_dir, uid, gid)
            os.chown(auth_file, uid, gid)
        except (OSError, AttributeError) as e:
            problems.append(f"could not set ownership to {username}: {e}")
    except OSError as e:
        problems.append(f"could not write {auth_file}: {e}")
        return {"installed": False, "steps": steps, "problems": problems,
                "verified": False, "verify_detail": "not attempted"}

    ok, detail = ensure_key_login_possible(username)
    if not ok:
        problems.append(detail)
    elif detail:
        steps.append(detail)

    verified, verify_detail = verify_key_login(username)
    return {"installed": True, "steps": steps, "problems": problems,
            "verified": verified, "verify_detail": verify_detail}


def _sshd_setting(text, name):
    m = re.search(rf'(?im)^\s*{name}\s+(\S+)\s*$', text)
    return m.group(1).lower() if m else None


def _set_sshd_setting(path, name, value):
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        return False, str(e)
    out, found = [], False
    for line in lines:
        if re.match(rf'(?i)^\s*#?\s*{name}\s+', line):
            out.append(f"{name} {value}\n")
            found = True
        else:
            out.append(line)
    if not found:
        out.append(f"\n{name} {value}\n")
    try:
        with open(path, "w") as f:
            f.writelines(out)
    except OSError as e:
        return False, str(e)
    return True, ""


def ensure_key_login_possible(username="root"):
    """Make sure sshd will accept a key for this account.

    Installing a key into /root/.ssh/authorized_keys achieves nothing while
    PermitRootLogin is no, which is a common hardened default and the usual
    reason a freshly generated key appears not to work. Only that specific case
    is changed, and only to prohibit-password, which permits the key while
    still refusing a root password.
    """
    path = _find_sshd_config()
    if not path:
        return True, ""
    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        return False, f"could not read {path}: {e}"

    notes = []
    if _sshd_setting(text, "PubkeyAuthentication") == "no":
        ok, err = _set_sshd_setting(path, "PubkeyAuthentication", "yes")
        if not ok:
            return False, f"PubkeyAuthentication is off and could not be changed: {err}"
        notes.append("turned PubkeyAuthentication on")

    if username == "root":
        current = _sshd_setting(text, "PermitRootLogin")
        if current == "no":
            ok, err = _set_sshd_setting(path, "PermitRootLogin", "prohibit-password")
            if not ok:
                return False, f"PermitRootLogin is no and could not be changed: {err}"
            notes.append("set PermitRootLogin to prohibit-password so the key is accepted")

    if notes:
        reloaded = False
        for unit in ("ssh", "sshd"):
            if subprocess.run(["systemctl", "reload", unit],
                              capture_output=True).returncode == 0:
                reloaded = True
                break
        if not reloaded:
            notes.append("reload the SSH service to apply")
    return True, ", ".join(notes)


def verify_key_login(username="root"):
    """Actually use the key. Returns (ok, detail).

    A generated key that was never tried is a guess. This connects to the local
    sshd with the key and nothing else: BatchMode refuses to fall back to a
    password prompt, so success means the key itself worked.
    """
    priv, _ = key_paths()
    if not os.path.exists(priv):
        return False, "no private key on disk"
    if not sshd_running():
        return False, "the SSH service is not running, so the key could not be tested"
    r = subprocess.run(
        ["ssh", "-i", priv, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=6",
         "-o", "PreferredAuthentications=publickey", "-o", "IdentitiesOnly=yes",
         f"{username}@127.0.0.1", "true"],
        capture_output=True, text=True, timeout=25,
    )
    if r.returncode == 0:
        return True, f"signed in to {username}@127.0.0.1 with the key"
    return False, (r.stderr.strip().splitlines() or ["ssh failed"])[-1][:300]


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
