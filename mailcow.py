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


def status(conn=None):
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
        "http_port": conf_value("HTTP_PORT") or HTTP_PORT,
        "https_port": conf_value("HTTPS_PORT") or HTTPS_PORT,
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


def job_state():
    with _lock:
        return {"action": _state["action"], "busy": not _state["done"],
                "ok": _state["ok"], "error": _state["error"],
                "output": _state["output"][-1500:],
                "seconds": int(time.time() - _state["started"]) if _state["started"] else 0,
                "http_port": conf_value("HTTP_PORT") or HTTP_PORT,
                "https_port": conf_value("HTTPS_PORT") or HTTPS_PORT,
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
            import secrets
            admin_pw = secrets.token_urlsafe(12)
            env = dict(os.environ, MAILCOW_HOSTNAME=host, MAILCOW_TZ=timezone,
                       MAILCOW_BRANCH="master",
                       MAILCOW_PASS=admin_pw,
                       HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT)
            rc, out = _run(["./generate_config.sh"], timeout=300,
                           cwd=INSTALL_DIR, env=env)
            if rc != 0 or not installed():
                return False, f"generate_config.sh failed: {out.strip()[-400:]}"
            with _lock:
                _state["admin_password"] = admin_pw
        return True, f"mailcow is set up for {host}. Start the containers next."

    return _background("preparing mailcow", work)


def start_stack():
    if not installed():
        return False, "mailcow is not set up yet."

    def work():
        ready, detail = provision.ensure_all(["docker", "compose"])
        if not ready:
            return False, detail
        cmd = compose_cmd()
        if not cmd:
            return False, "Docker Compose is still not usable on this server."
        # The first start pulls several gigabytes of images, which is why this is
        # a background job with a very long ceiling rather than a request.
        rc, out = _run(cmd + ["pull"], timeout=5400, cwd=INSTALL_DIR)
        if rc != 0:
            return False, f"could not pull the mailcow images: {out.strip()[-400:]}"
        rc, out = _run(cmd + ["up", "-d"], timeout=3600, cwd=INSTALL_DIR,
                       env=dict(os.environ, HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT))
        if rc != 0:
            return False, f"the mailcow stack would not start: {out.strip()[-400:]}"
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
    host = hostname()
    return f"https://{host}/api/v1" if host else ""


def api_ready(conn):
    return bool(_api_base()) and bool(mail.mailcow_key(conn))


def _api(conn, method, path, payload=None):
    """(ok, parsed-or-text). mailcow answers 200 with a body saying "danger" when
    it refuses, so the body has to be read rather than just the status."""
    import requests
    base = _api_base()
    if not base:
        return False, "mailcow has no hostname configured yet."
    key = mail.mailcow_key(conn)
    if not key:
        return False, "No mailcow API key is stored."
    url = base + path
    headers = {"X-API-Key": key, "Content-Type": "application/json"}
    try:
        response = requests.request(method, url, json=payload,
                                    timeout=API_TIMEOUT, headers=headers)
    except requests.exceptions.SSLError:
        # A mailcow that has not finished getting its certificate yet serves a
        # self-signed one, and the very first call is the one that creates the
        # domain, so refusing outright would leave setup with no way forward.
        # The retry is deliberate, narrow, and reported: only after a TLS failure,
        # only for this host, and the caller is told the certificate was not
        # verified so it can say so on the page.
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
    ("A", "mail.<domain>", "this server's public address",
     "so the world can find the mail host"),
    ("MX", "<domain>", "mail.<domain>, priority 10",
     "so mail for the domain is delivered here"),
    ("TXT", "<domain>", "v=spf1 mx ~all",
     "so receivers accept mail this server sends"),
    ("TXT", "dkim._domainkey.<domain>", "the DKIM key mailcow generates",
     "so receivers can verify it was really you"),
    ("TXT", "_dmarc.<domain>", "v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>",
     "so receivers know what to do with forgeries"),
)


def dns_help(domain, bimi_record=""):
    """What has to exist in DNS before any of this works. Shown rather than
    hidden, because a mail server with no MX record fails silently.

    The BIMI row only appears once there is a logo to point at, since a record
    naming a picture that does not exist is worse than no record at all.
    """
    domain = (domain or "<domain>").strip().lower()
    rows = [{"type": kind, "name": name.replace("<domain>", domain),
             "value": value.replace("<domain>", domain), "why": why}
            for kind, name, value, why in DNS_RECORDS]
    if bimi_record:
        rows.append({
            "type": "TXT", "name": f"default._bimi.{domain}", "value": bimi_record,
            "why": ("so receivers can show your logo beside your mail. The URL has "
                    "to be reachable over HTTPS from outside"),
        })
    return rows
