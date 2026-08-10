# Inbound mail: the mailcow stack that actually receives from the internet, and
# the two ways this panel talks to it (its API to create mailboxes, IMAP to pull
# the mail into the database).
#
# Sending is a different problem and lives in mail.py. This module is only about
# the server that listens on port 25, because that is the part that cannot be
# faked: a relay lets you send, but nothing arrives until something is listening.
import imaplib
import os
import re
import socket
import subprocess
import threading
import time
from email import message_from_bytes
from email.header import decode_header, make_header

import mail
import provision

INSTALL_DIR = "/opt/mailcow-dockerized"
CONF_PATH = os.path.join(INSTALL_DIR, "mailcow.conf")
REPO = "https://github.com/mailcow/mailcow-dockerized.git"
SMTP_PORT = 25
IMAP_PORT = 993
API_TIMEOUT = 30
HTTP_PORT = "8081"
HTTPS_PORT = "8443"

_state = {"action": "", "started": 0.0, "done": True, "ok": True,
          "output": "", "error": "", "admin_password": ""}
# What the panel has already worked out about this mailcow, so the page can
# show real values (the API key it minted, the DKIM record mailcow generated,
# this server's public address) instead of telling the operator to go and
# find them. Filled in the background, read on every poll.
_setup = {"api_key": "", "dkim": "", "public_ip": "", "domain_added": False,
          "busy": False, "error": ""}
_lock = threading.Lock()


# ------------------------------------------------------------------ the host
def _run(args, timeout=120, cwd=None, env=None):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              cwd=cwd, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} did not finish within {timeout}s."
    except OSError as e:
        return 126, str(e)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def docker_state():
    """(ok, reason). A docker binary is not the same as a running daemon, and
    mailcow needs the daemon."""
    from shutil import which
    if not which("docker"):
        return False, "Docker is not installed on this server."
    rc, out = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if rc != 0:
        return False, ("Docker is installed but its daemon is not reachable: "
                       + out.strip().splitlines()[-1][:200] if out.strip()
                       else "Docker is installed but its daemon is not running.")
    return True, out.strip()[:40]


def compose_cmd():
    """mailcow ships a compose file, and compose comes in two spellings."""
    from shutil import which
    if which("docker"):
        rc, _ = _run(["docker", "compose", "version"], timeout=30)
        if rc == 0:
            return ["docker", "compose"]
    if which("docker-compose"):
        return ["docker-compose"]
    return None


def installed():
    return os.path.isfile(CONF_PATH)


def cloned():
    return os.path.isdir(os.path.join(INSTALL_DIR, ".git"))


def conf_value(name):
    if not installed():
        return ""
    try:
        with open(CONF_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith(name + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        return ""
    return ""


def conf_set(name, value):
    """Write a setting into mailcow.conf, replacing the line if it is there.

    The panel forces a few of mailcow's settings (the web ports, so they do
    not collide with the panel's own). Passing them as environment to compose
    works for one `up`, but mailcow's own scripts read the file, so the file
    is what has to agree.
    """
    if not installed():
        return False
    try:
        with open(CONF_PATH, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        out, found = [], False
        for line in lines:
            if line.startswith(name + "="):
                if not found:
                    out.append(f"{name}={value}\n")
                    found = True
                continue                      # drop any duplicate later lines
            out.append(line)
        if not found:
            if out and not out[-1].endswith("\n"):
                out.append("\n")
            out.append(f"{name}={value}\n")
        with open(CONF_PATH, "w", encoding="utf-8") as fh:
            fh.writelines(out)
        return True
    except OSError:
        return False


def hostname():
    return conf_value("MAILCOW_HOSTNAME")


def containers():
    """(running, total). Nothing else in the panel should have to know that this
    is docker underneath, so it comes back as two numbers."""
    cmd = compose_cmd()
    if not cmd or not installed():
        return 0, 0
    rc, out = _run(cmd + ["ps", "--format", "{{.State}}"], timeout=60, cwd=INSTALL_DIR)
    if rc != 0:
        return 0, 0
    states = [line.strip().lower() for line in out.splitlines() if line.strip()]
    return sum(1 for s in states if s.startswith("running")), len(states)


def port_listening(port=SMTP_PORT, host="127.0.0.1"):
    """Is anything actually accepting on the port. The one check that says
    whether mail could arrive, rather than whether it was configured to."""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def status(conn=None, domain=""):
    docker_ok, docker_note = docker_state()
    running, total = containers()
    out = {
        "docker": docker_ok,
        "docker_note": docker_note,
        "compose": compose_cmd() is not None,
        "cloned": cloned(),
        "installed": installed(),
        "install_dir": INSTALL_DIR,
        "hostname": hostname(),
        "containers_running": running,
        "containers_total": total,
        "smtp_listening": port_listening(SMTP_PORT),
        "http_port": HTTP_PORT,
        "https_port": HTTPS_PORT,
        "admin_username": "admin",
        "admin_password": conf_value("MAILCOW_PASS") or _state.get("admin_password", ""),
        "busy": not _state["done"],
        "action": _state["action"],
        "last_error": _state["error"],
        "last_output": _state["output"][-1500:],
    }
    out["ready"] = out["installed"] and out["smtp_listening"]
    # What the panel would have to install before mailcow can run, so the page
    # can offer to do it rather than print a package name at the operator.
    out["needs"] = [c for c in ("docker", "compose") if not provision.present(c)]
    out["can_install"] = bool(out["needs"]) and provision.escalation() is not None
    out["install"] = provision.job_state()
    problems = []
    if out["needs"]:
        labels = " and ".join(provision.COMPONENTS[c]["label"] for c in out["needs"])
        problems.append(
            f"{labels} is not installed yet, and mailcow needs it. The panel can "
            "install it for you." if out["can_install"] else
            f"{labels} is not installed, and this panel cannot install it: it is "
            "not running as root and sudo would ask for a password.")
    elif not docker_ok:
        problems.append(docker_note)
    if docker_ok and out["compose"] and not out["installed"]:
        problems.append("mailcow has not been set up on this server yet.")
    if out["installed"] and not out["smtp_listening"]:
        problems.append("mailcow is set up but nothing is listening on port 25, "
                        "so mail cannot arrive yet.")
    out["problems"] = problems
    # Everything the operator would otherwise have to go and find: the login,
    # the API key the panel minted for itself, and whether the domain is
    # actually registered inside mailcow.
    out["api_key"] = _setup.get("api_key", "") or (mail.mailcow_key(conn) if conn else "")
    out["domain_added"] = bool(_setup.get("domain_added"))
    out["dkim_ready"] = bool(_setup.get("dkim"))
    out["public_ip"] = _setup.get("public_ip", "")
    out["setup_busy"] = bool(_setup.get("busy"))
    if out["installed"] and running > 0:
        # The ports the panel forces have to be in the file too, not only in
        # the environment of one `compose up`: mailcow's own scripts read the
        # file, and a file that still says 80 is a collision waiting to happen.
        if conf_value("HTTP_PORT") != HTTP_PORT:
            conf_set("HTTP_PORT", HTTP_PORT)
        if conf_value("HTTPS_PORT") != HTTPS_PORT:
            conf_set("HTTPS_PORT", HTTPS_PORT)
        # If the stack is running but we do not know the admin password yet
        # (install predates the panel), set one now so the page can show it.
        _ensure_admin_password()
        out["admin_password"] = _state.get("admin_password", "") or conf_value("MAILCOW_PASS")
        # And work out the rest (API key, the domain inside mailcow, DKIM,
        # this server's address) in the background, so the next poll has it.
        provision_async(domain)
        out["api_key"] = _setup.get("api_key", "") or out["api_key"]
        out["setup_busy"] = bool(_setup.get("busy"))
    return out


# --------------------------------------------------------- setting it up
def _background(action, fn):
    """Run one long job and let the page poll for it.

    Cloning mailcow and pulling its images take minutes, which is far too long
    for a request to sit open, so this follows the same shape as the Cloudflare
    login: start it, report progress, poll.
    """
    with _lock:
        if not _state["done"]:
            return False, f"Already busy with {_state['action']}."
        _state.update({"action": action, "started": time.time(), "done": False,
                       "ok": True, "output": "", "error": ""})

    def work():
        try:
            ok, output = fn()
        except Exception as e:                       # pragma: no cover, defensive
            ok, output = False, f"{type(e).__name__}: {e}"
        with _lock:
            _state.update({"done": True, "ok": ok, "output": output[-4000:],
                           "error": "" if ok else output.strip()[-400:]})

    threading.Thread(target=work, daemon=True).start()
    return True, f"{action} started."


def _mysql(sql):
    """(ok, output) for one statement against mailcow's own database.

    The root password lives in mailcow.conf, and the statement is passed as
    a single argument to the mysql client, so no shell parses it.
    """
    cmd, dbroot = compose_cmd(), conf_value("DBROOT")
    if not cmd or not dbroot:
        return False, ""
    rc, out = _run(cmd + ["exec", "-T", "mysql-mailcow", "mysql", "-u", "root",
                          f"-p{dbroot}", "mailcow", "-N", "-B", "-e", sql],
                   timeout=120, cwd=INSTALL_DIR)
    return rc == 0, out


def public_ip():
    """This server's address as the rest of the world sees it.

    It is what the A record has to contain, and it cannot be read off a local
    interface: behind NAT the local address is not the one mail will arrive
    at. So it is asked of something outside, with the answer cached.
    """
    if _setup.get("public_ip"):
        return _setup["public_ip"]
    import requests
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com",
                "https://ifconfig.me/ip"):
        try:
            text = requests.get(url, timeout=8).text.strip()
        except Exception:
            continue
        # Anything that is not four numbers is an error page, not an address.
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text):
            with _lock:
                _setup["public_ip"] = text
            return text
    return ""


def _ensure_api_key(conn):
    """Give the panel an API key for mailcow, creating one if there is none.

    mailcow's own UI can mint these, but requiring a trip through that UI is
    exactly the manual step this panel exists to remove. The key is written
    straight into mailcow's api table and stored here, so every later call
    (adding the domain, generating DKIM, creating mailboxes) just works.
    """
    existing = mail.mailcow_key(conn)
    if existing:
        return existing
    ok, out = _mysql("SELECT api_key FROM api WHERE access='rw' AND active=1 LIMIT 1;")
    key = out.strip().splitlines()[-1].strip() if ok and out.strip() else ""
    if not key:
        import secrets
        # mailcow's own keys are this shape, and its UI validates the format.
        key = "-".join("".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                               for _ in range(6)) for _ in range(5))
        # skip_ip_check, because the panel reaches mailcow over the loopback
        # and the source address it presents is the docker bridge, not a
        # stable value worth pinning an allow-list to.
        ok, _out = _mysql(
            "INSERT INTO api (api_key, allow_from, skip_ip_check, access, active) "
            f"VALUES ('{key}', '', 1, 'rw', 1);")
        if not ok:
            return ""
    try:
        mail.set_mailcow_key(conn, key, "panel")
        conn.commit()
    except Exception:
        conn.rollback()
        return ""
    return key


def _ensure_domain(conn, domain, key):
    """Make sure mailcow knows the domain, so mail for it is accepted."""
    ok, out = _mysql(f"SELECT domain FROM domain WHERE domain='{domain}';")
    if ok and domain in out:
        return True
    made, _detail = _api(conn, "POST", "/add/domain", {
        "domain": domain, "active": "1", "aliases": "20", "mailboxes": "50",
        "maxquota": "3072", "quota": "20480", "restart_sogo": "1",
    }, key=key)
    return bool(made)


def _ensure_dkim(conn, domain, key):
    """The DKIM record's real value, generating the key pair if needed.

    Until this exists the DNS table can only say "the key mailcow generates",
    which is not something anybody can paste into a DNS panel.
    """
    got, body = _api(conn, "GET", f"/get/dkim/{domain}", key=key)
    txt = body.get("dkim_txt", "") if got and isinstance(body, dict) else ""
    if txt:
        return txt
    _api(conn, "POST", "/add/dkim", {
        "domains": domain, "dkim_selector": "dkim", "key_size": "2048",
    }, key=key)
    got, body = _api(conn, "GET", f"/get/dkim/{domain}", key=key)
    if got and isinstance(body, dict):
        return body.get("dkim_txt", "")
    return ""


def _provision(conn, domain):
    """Everything mailcow needs before it is usable, done once, in order.

    Each step is skipped when it is already true, so this is safe to call on
    every poll: it converges rather than repeating work.
    """
    domain = (domain or "").strip().lower()
    if not domain or not installed():
        return
    running, _total = containers()
    if running == 0:
        return
    key = _ensure_api_key(conn)
    if not key:
        return
    with _lock:
        _setup["api_key"] = key
    if not _ensure_domain(conn, domain, key):
        return
    with _lock:
        _setup["domain_added"] = True
    txt = _ensure_dkim(conn, domain, key)
    if txt:
        with _lock:
            _setup["dkim"] = txt


def provision_async(domain):
    """Run _provision off the request thread.

    Generating a 2048-bit DKIM key and waiting on mailcow's API takes longer
    than a page load should, and the page polls anyway, so the values appear
    on the next tick rather than holding this one open. It takes its own
    connection from the pool because it outlives the request that started it.
    """
    if _setup.get("busy") or not (domain or "").strip():
        return
    # Nothing left to work out: don't take a connection to discover that.
    if _setup.get("api_key") and _setup.get("dkim") and _setup.get("public_ip"):
        return
    with _lock:
        _setup["busy"] = True

    def work():
        import DB
        conn = None
        try:
            conn = DB.get_connection()
            public_ip()
            _provision(conn, domain)
        except Exception as e:                       # pragma: no cover, defensive
            with _lock:
                _setup["error"] = f"{type(e).__name__}: {e}"[:200]
        finally:
            if conn is not None:
                DB.release_connection(conn)
            with _lock:
                _setup["busy"] = False

    threading.Thread(target=work, daemon=True).start()


def _set_admin_password(pw):
    """Push a new admin password into the running mailcow database.

    The password is hashed the way mailcow itself hashes it (PHP
    password_hash, bcrypt) by running PHP inside the same php-fpm container,
    then written into the admin table via the mysql container.  This is the
    same result mailcow's own admin UI produces, without needing any
    interactive prompt.
    """
    cmd = compose_cmd()
    if not cmd:
        return False
    # token_urlsafe output is only [A-Za-z0-9_-], safe to embed in PHP code.
    rc, out = _run(cmd + ["exec", "-T", "php-fpm-mailcow", "php", "-r",
                          f"echo password_hash('{pw}', PASSWORD_DEFAULT);"],
                   timeout=60, cwd=INSTALL_DIR)
    if rc != 0 or not out.strip():
        return False
    hashed = out.strip().splitlines()[-1].strip()
    if not hashed.startswith("$2"):
        return False
    dbroot = conf_value("DBROOT")
    if not dbroot:
        return False
    # The hash contains $ characters, which is fine: args go straight to the
    # process, no shell is involved.
    sql = f"UPDATE admin SET password='{hashed}' WHERE username='admin';"
    rc, _out = _run(cmd + ["exec", "-T", "mysql-mailcow", "mysql", "-u", "root",
                           f"-p{dbroot}", "mailcow", "-e", sql],
                    timeout=120, cwd=INSTALL_DIR)
    return rc == 0


def _persist_admin_password(pw):
    """Remember the password across panel restarts.

    It is appended to mailcow.conf, the file conf_value() already reads.
    mailcow does not use this key itself, but the panel does, and this is
    the one durable file the panel already reads for everything else.
    """
    try:
        with open(CONF_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"\nMAILCOW_PASS={pw}\n")
    except OSError:
        pass


def _ensure_admin_password():
    """Make sure the admin password is known so status() can show it.

    For fresh installs it was set during prepare() and written to
    mailcow.conf.  For installs that predate the panel, or when the conf
    has gone missing, generate one and push it into the running mailcow
    database.
    """
    # Already have it in memory from a recent prepare() or a previous reset.
    if _state.get("admin_password"):
        return
    # Read from the conf file (set during prepare, or persisted later).
    pw = conf_value("MAILCOW_PASS")
    if pw:
        with _lock:
            _state["admin_password"] = pw
        return
    # The stack must be running for the in-container reset to work.
    running, _ = containers()
    if running == 0:
        return
    # Don't hammer docker exec on every status poll if it failed before.
    if _state.get("_pw_attempted"):
        return
    with _lock:
        _state["_pw_attempted"] = True
    # Existing install with no stored password: generate one and push it
    # into mailcow via its own database.
    import secrets
    pw = secrets.token_urlsafe(12)
    if _set_admin_password(pw):
        with _lock:
            _state["admin_password"] = pw
            _state["_pw_attempted"] = False  # allow retry on next start if needed
        _persist_admin_password(pw)


def job_state():
    with _lock:
        return {"action": _state["action"], "busy": not _state["done"],
                "ok": _state["ok"], "error": _state["error"],
                "output": _state["output"][-1500:],
                "seconds": int(time.time() - _state["started"]) if _state["started"] else 0,
                "http_port": HTTP_PORT,
                "https_port": HTTPS_PORT,
                "admin_username": "admin",
                "admin_password": _state.get("admin_password", "") or conf_value("MAILCOW_PASS"),
                }


def prepare(domain, timezone="UTC"):
    """Clone mailcow and write its config for this domain.

    The mail host is mail.<domain>, which is the convention mailcow's own docs
    use and what the DNS records people are told to create point at.
    """
    problem = mail.domain_problem(domain)
    if problem:
        return False, problem
    host = f"mail.{domain.strip().lower()}"

    def work():
        # Docker and Compose are installed here rather than demanded up front:
        # setting mail up is the moment the operator has said they want this, and
        # a missing package is something the panel can fix on its own.
        ready, detail = provision.ensure_all(["docker", "compose"])
        if not ready:
            return False, detail
        ok, note = docker_state()
        if not ok:
            return False, note
        if not cloned():
            os.makedirs(os.path.dirname(INSTALL_DIR), exist_ok=True)
            rc, out = _run(["git", "clone", "--depth", "1", REPO, INSTALL_DIR],
                           timeout=900)
            if rc != 0:
                return False, f"could not clone mailcow: {out.strip()[-400:]}"
        if not installed():
            env = dict(os.environ, MAILCOW_HOSTNAME=host, MAILCOW_TZ=timezone,
                       MAILCOW_BRANCH="master",
                       HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT)
            rc, out = _run(["./generate_config.sh"], timeout=300,
                           cwd=INSTALL_DIR, env=env)
            if rc != 0 or not installed():
                return False, f"generate_config.sh failed: {out.strip()[-400:]}"
        # generate_config.sh writes 80/443 whatever the environment said, so
        # the ports the panel forces are written over it here, in the file
        # mailcow's own scripts read.
        conf_set("HTTP_PORT", HTTP_PORT)
        conf_set("HTTPS_PORT", HTTPS_PORT)
        return True, f"mailcow is set up for {host}. Start the containers next."

    return _background("preparing mailcow", work)


def start_stack(domain=""):
    if not installed():
        return False, "mailcow is not set up yet."

    def work():
        ready, detail = provision.ensure_all(["docker", "compose"])
        if not ready:
            return False, detail
        cmd = compose_cmd()
        if not cmd:
            return False, "Docker Compose is still not usable on this server."
        # Written before the stack comes up, so the containers bind where the
        # panel says rather than fighting it for 80 and 443.
        conf_set("HTTP_PORT", HTTP_PORT)
        conf_set("HTTPS_PORT", HTTPS_PORT)
        # The first start pulls several gigabytes of images, which is why this is
        # a background job with a very long ceiling rather than a request.
        rc, out = _run(cmd + ["pull"], timeout=5400, cwd=INSTALL_DIR)
        if rc != 0:
            return False, f"could not pull the mailcow images: {out.strip()[-400:]}"
        rc, out = _run(cmd + ["up", "-d"], timeout=3600, cwd=INSTALL_DIR,
                       env=dict(os.environ, HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT))
        if rc != 0:
            return False, f"the mailcow stack would not start: {out.strip()[-400:]}"
        # Make sure we can show the admin password on the page.  For fresh
        # installs it was set during prepare().  For existing installs, or if
        # the conf somehow lost it, generate one and push it into mailcow.
        with _lock:
            _state.pop("_pw_attempted", None)  # fresh start, fresh attempt
        _ensure_admin_password()
        # mailcow needs a moment after `up` before its API answers, and the
        # rest of setup goes through that API.
        for _ in range(20):
            if port_listening(int(HTTPS_PORT)):
                break
            time.sleep(3)
        provision_async(domain)
        return True, "the mailcow stack is up"

    return _background("starting mailcow", work)


def stop_stack():
    cmd = compose_cmd()
    if not cmd:
        return False, "Docker Compose is missing."
    if not installed():
        return False, "mailcow is not set up yet."

    def work():
        rc, out = _run(cmd + ["down"], timeout=900, cwd=INSTALL_DIR)
        return (rc == 0), ("the mailcow stack is down" if rc == 0
                           else f"could not stop it: {out.strip()[-400:]}")

    return _background("stopping mailcow", work)


# ------------------------------------------------------------------- its API
def _api_base():
    """mailcow's API, over the loopback rather than its public name.

    The public name is exactly what does not resolve yet: the A record the
    panel is asking the operator to create is the thing being set up. So the
    call goes to 127.0.0.1 on the HTTPS port the panel forces, and carries
    the hostname in the Host header, which is what mailcow's nginx routes on.
    """
    return f"https://127.0.0.1:{HTTPS_PORT}/api/v1"


def api_ready(conn):
    return bool(installed()) and bool(mail.mailcow_key(conn))


def _api(conn, method, path, payload=None, key=""):
    """(ok, parsed-or-text). mailcow answers 200 with a body saying "danger" when
    it refuses, so the body has to be read rather than just the status."""
    import requests
    base = _api_base()
    key = key or mail.mailcow_key(conn)
    if not key:
        return False, "No mailcow API key is stored."
    url = base + path
    headers = {"X-API-Key": key, "Content-Type": "application/json"}
    host = hostname()
    if host:
        headers["Host"] = host
    # The certificate is issued for the mail hostname, and this connection is
    # to 127.0.0.1, so it can never validate. Verifying is not what makes a
    # loopback call safe; not leaving the machine is.
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    try:
        response = requests.request(method, url, json=payload,
                                    timeout=API_TIMEOUT, headers=headers,
                                    verify=False)
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:300]
    if response.status_code >= 400:
        return False, f"mailcow answered {response.status_code}"
    try:
        body = response.json()
    except ValueError:
        return False, response.text[:300]
    problems = _api_problems(body)
    if problems:
        return False, "; ".join(problems)[:400]
    return True, body


def _api_problems(body):
    """mailcow reports refusals inside a 200. Each entry carries a type, and
    anything that is not success is a refusal worth showing."""
    entries = body if isinstance(body, list) else [body]
    problems = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type", "")).lower()
        if kind and kind not in ("success", "info"):
            message = entry.get("msg") or entry.get("message") or kind
            problems.append(str(message)[:200])
    return problems


def add_domain(conn, domain):
    return _api(conn, "POST", "/add/domain", {
        "domain": domain, "active": "1", "aliases": "20", "mailboxes": "50",
        "maxquota": "3072", "quota": "20480", "restart_sogo": "1",
    })


def add_mailbox(conn, local_part, domain, password, name=""):
    return _api(conn, "POST", "/add/mailbox", {
        "local_part": local_part, "domain": domain, "name": name or local_part,
        "password": password, "password2": password,
        "quota": "3072", "active": "1", "force_pw_update": "0",
    })


def delete_mailbox(conn, address):
    return _api(conn, "POST", "/delete/mailbox", [address])


# -------------------------------------------------------------- pulling mail
def _decoded(value):
    try:
        return str(make_header(decode_header(value or "")))
    except (UnicodeDecodeError, LookupError, ValueError):
        return value or ""


def _plain_body(message):
    """The readable part of a message. HTML-only mail is kept as its markup and
    the interface renders it as text, because rendering somebody else's HTML in
    the panel is how a mail becomes a script."""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace")
                except (AttributeError, LookupError):
                    continue
        for part in message.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace")
                except (AttributeError, LookupError):
                    continue
        return ""
    try:
        return message.get_payload(decode=True).decode(
            message.get_content_charset() or "utf-8", "replace")
    except (AttributeError, LookupError):
        return str(message.get_payload())[:mail.BODY_MAX]


def sync_box(conn, address, host="", limit=50):
    """Pull a mailbox's newest messages into the database.

    The panel stores every message, so an address only has to be reachable once
    for its mail to stay readable here. Messages already stored are recognised by
    their IMAP UID, so a second sync adds nothing twice.
    """
    address = (address or "").strip().lower()
    box = mail._box_by_address(conn, address)
    if not box:
        return False, "There is no such mailbox.", 0
    password = mail.box_secret(conn, address)
    if not password:
        return False, ("This mailbox has no stored password, so its mail cannot "
                       "be collected. Recreate it from this panel."), 0
    host = host or hostname()
    if not host:
        return False, "mailcow has no hostname configured yet.", 0

    try:
        import ssl
        context = ssl._create_unverified_context()
        client = imaplib.IMAP4_SSL(host, IMAP_PORT, ssl_context=context)
    except Exception as e:
        return False, f"could not reach {host}: {type(e).__name__}", 0
    added = 0
    try:
        client.login(address, password)
        client.select("INBOX")
        typ, data = client.uid("search", None, "ALL")
        if typ != "OK":
            return False, "the mailbox would not answer a search", 0
        uids = (data[0] or b"").split()[-limit:]
        for raw_uid in uids:
            uid = raw_uid.decode()
            typ, fetched = client.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not fetched or not isinstance(fetched[0], tuple):
                continue
            message = message_from_bytes(fetched[0][1])
            from_name, from_addr = mail.parse_address(message.get("From", ""))
            try:
                mail.deliver_inbound(
                    conn, box["id"], from_addr, from_name,
                    _decoded(message.get("To", address)),
                    _decoded(message.get("Subject", "")),
                    _plain_body(message), route="external", remote_uid=uid)
                added += 1
            except Exception:
                # A duplicate UID is the normal case on a second sync, and the
                # unique index is what makes it cheap to detect.
                conn.rollback()
    except imaplib.IMAP4.error as e:
        return False, f"IMAP refused: {e}"[:200], added
    finally:
        try:
            client.logout()
        except Exception:
            pass
    return True, f"{added} new message(s) collected", added


DNS_RECORDS = (
    ("A", "mail.<domain>", "<ip>",
     "so the world can find the mail host"),
    ("MX", "<domain>", "mail.<domain>",
     "so mail for the domain is delivered here, priority 10"),
    ("TXT", "<domain>", "v=spf1 mx ~all",
     "so receivers accept mail this server sends"),
    ("TXT", "dkim._domainkey.<domain>", "<dkim>",
     "so receivers can verify it was really you"),
    ("TXT", "_dmarc.<domain>", "v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>",
     "so receivers know what to do with forgeries"),
)


def dns_help(domain, bimi_record=""):
    """What has to exist in DNS before any of this works. Shown rather than
    hidden, because a mail server with no MX record fails silently.

    Every value is the value: the A record carries this server's real address
    and the DKIM row carries the key mailcow actually generated, because a
    table saying "the key mailcow generates" is not something anyone can
    paste into a DNS panel. A row whose value is not known yet says so in
    `pending`, and the page can show it as waiting rather than as an answer.

    The BIMI row only appears once there is a logo to point at, since a record
    naming a picture that does not exist is worse than no record at all.
    """
    domain = (domain or "<domain>").strip().lower()
    ip = _setup.get("public_ip", "")
    dkim = _setup.get("dkim", "")
    rows = []
    for kind, name, value, why in DNS_RECORDS:
        pending = ""
        if "<ip>" in value and not ip:
            pending = "working out this server's public address"
        if "<dkim>" in value and not dkim:
            pending = "mailcow is still generating the key"
        rows.append({
            "type": kind,
            "name": name.replace("<domain>", domain),
            "value": (value.replace("<domain>", domain)
                           .replace("<ip>", ip or "")
                           .replace("<dkim>", dkim or "")),
            "why": why,
            "pending": pending,
        })
    if bimi_record:
        rows.append({
            "type": "TXT", "name": f"default._bimi.{domain}", "value": bimi_record,
            "why": ("so receivers can show your logo beside your mail. The URL has "
                    "to be reachable over HTTPS from outside"),
            "pending": "",
        })
    return rows
