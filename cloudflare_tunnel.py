# Cloudflare Tunnel control: connect a Cloudflare account, create a tunnel, and
# point a public hostname at a port on this machine. Cloudflare terminates HTTPS
# at its edge and cloudflared reaches the local service over plain HTTP, so the
# port being forwarded never has to be open to the internet at all.
#
# Mirrors the shape of the other helper modules here: its own SCHEMA tuple, plain
# functions that take an already-open connection, no pool of its own. Everything
# that shells out reports the reason it failed rather than raising, because the
# panel has to be able to show the operator what Cloudflare said.
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time

CONFIG_DIR = "/etc/cloudflared"
CERT_PATH = os.path.join(CONFIG_DIR, "cert.pem")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.yml")
SERVICE_NAME = "argus-tunnel"
UNIT_PATH = f"/etc/systemd/system/{SERVICE_NAME}.service"
ACTIVE_SETTING = "cf_active_tunnel"

# cloudflared prints the login URL on stdout and then waits for the browser to
# come back. This is the line worth showing the operator.
_URL_RE = re.compile(r"https://\S*dash\.cloudflare\.com/\S+")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,61}$")
_HOSTNAME_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_LOCAL_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,253}[a-z0-9])?$")

LOGIN_TIMEOUT = 900        # cloudflared is left waiting this long for the browser

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS cf_tunnel (
        id          SERIAL PRIMARY KEY,
        name        VARCHAR(120) UNIQUE NOT NULL,
        tunnel_id   VARCHAR(64) NOT NULL DEFAULT '',
        cred_file   TEXT NOT NULL DEFAULT '',
        created_by  VARCHAR(100) NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS cf_route (
        id          SERIAL PRIMARY KEY,
        tunnel      VARCHAR(120) NOT NULL,
        hostname    VARCHAR(253) UNIQUE NOT NULL,
        local_host  VARCHAR(255) NOT NULL DEFAULT '127.0.0.1',
        local_port  INTEGER NOT NULL,
        dns_ok      BOOLEAN NOT NULL DEFAULT FALSE,
        detail      TEXT NOT NULL DEFAULT '',
        created_by  VARCHAR(100) NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX IF NOT EXISTS idx_cf_route_tunnel ON cf_route(tunnel)",
)


# --------------------------------------------------------------- the binary
def binary():
    return shutil.which("cloudflared") or ""


def installed():
    return bool(binary())


def version():
    if not installed():
        return ""
    rc, out = _run(["--version"], timeout=10)
    return out.strip().splitlines()[0] if rc == 0 and out.strip() else ""


def _env():
    """cloudflared keeps its account certificate next to the config by default,
    which is the invoking user's home directory. The panel is not always the same
    user twice, so the location is stated explicitly instead.

    HOME is pinned as well. `tunnel login` is the one subcommand that ignores
    TUNNEL_ORIGIN_CERT and writes into its own config directory under HOME, so
    the panel has to know which directory that will be to go and collect the
    certificate afterwards. See _adopt_cert().
    """
    env = dict(os.environ)
    env["TUNNEL_ORIGIN_CERT"] = CERT_PATH
    env["HOME"] = _login_home()
    return env


def _login_home():
    """The HOME cloudflared will write its login certificate under."""
    home = os.environ.get("HOME") or ""
    if home and os.path.isdir(home):
        return home
    return "/root" if os.path.isdir("/root") else "/tmp"


def _run(args, timeout=60):
    """(returncode, combined output). A missing binary is a returncode, not an
    exception, so every caller can report it the same way."""
    if not installed():
        return 127, "cloudflared is not installed on this server."
    try:
        proc = subprocess.run([binary(), "--no-autoupdate"] + list(args),
                              capture_output=True, text=True, timeout=timeout,
                              env=_env())
    except subprocess.TimeoutExpired:
        return 124, f"cloudflared did not answer within {timeout}s."
    except OSError as e:
        return 126, str(e)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def ensure_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)


# ------------------------------------------------------------------- account
def _cert_is_real(path):
    """A certificate file that is actually a certificate. cloudflared writes a
    PEM bundle here; anything else is a half-finished or stray file."""
    try:
        if os.path.getsize(path) < 64:
            return False
        with open(path, "rb") as fh:
            return b"-----BEGIN" in fh.read(4096)
    except OSError:
        return False


# Where `cloudflared tunnel login` may have left the certificate. It writes into
# its own config directory and ignores TUNNEL_ORIGIN_CERT, so this is not the
# path the rest of the module uses, and the file has to be collected.
def _login_cert_candidates():
    homes = [_login_home(), "/root", os.path.expanduser("~")]
    seen, out = set(), []
    for home in homes:
        path = os.path.join(home, ".cloudflared", "cert.pem")
        if path not in seen and path != CERT_PATH:
            seen.add(path)
            out.append(path)
    return out


def _adopt_cert():
    """Move a certificate cloudflared wrote elsewhere into the panel's own path.

    This is the difference between a login that worked and a login the panel
    could not see: the browser flow completes, cloudflared writes
    ~/.cloudflared/cert.pem and exits happily, and every later command is told
    to read /etc/cloudflared/cert.pem instead. Collect it, and the tunnel
    commands that do honour TUNNEL_ORIGIN_CERT all line up again.

    Returns True when a certificate is in place afterwards.
    """
    if _cert_is_real(CERT_PATH):
        return True
    for path in _login_cert_candidates():
        if not _cert_is_real(path):
            continue
        try:
            ensure_dir()
            # O_NOFOLLOW: read the file cloudflared wrote, never wherever a
            # symlink in its place points. A private key is not something to
            # copy through an indirection nobody checked.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with os.fdopen(fd, "rb") as src:
                    data = src.read(1024 * 1024)
            except Exception:
                os.close(fd)
                continue
            # A unique temporary name, so two requests arriving together cannot
            # interleave into one half-written file and then publish it.
            tmp = f"{CERT_PATH}.{os.getpid()}.{threading.get_ident()}.new"
            with open(tmp, "wb") as dst:
                dst.write(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, CERT_PATH)
        except OSError:
            continue
        return True
    return False


def logged_in():
    """True when this server can manage the account's tunnels.

    Adopting here rather than in the caller means every path that asks the
    question (the status endpoint, the poll the browser runs, the tunnel
    commands themselves) picks up a fresh login without being told to look.
    """
    return _adopt_cert()


_login = {"url": "", "started": 0.0, "output": "", "done": False, "error": ""}
_login_lock = threading.Lock()

# cloudflared exits the moment the browser comes back, and writes the
# certificate just before it does. Give the file a few seconds to appear rather
# than calling a successful login a failure by half a second.
_CERT_WAIT = 15


def _login_reader(proc):
    """Read cloudflared's output until the login URL shows up, then keep reading
    until it exits. The process exits by itself once the browser has come back,
    so its exit is what "connected" means."""
    lines = []
    try:
        for line in proc.stdout:
            lines.append(line)
            match = _URL_RE.search(line)
            if match:
                with _login_lock:
                    _login["url"] = match.group(0)
        proc.wait(timeout=5)
    except Exception as e:                       # pragma: no cover, defensive
        with _login_lock:
            _login["error"] = str(e)
    finally:
        deadline = time.time() + _CERT_WAIT
        connected = logged_in()
        while not connected and time.time() < deadline:
            time.sleep(0.5)
            connected = logged_in()
        with _login_lock:
            _login["output"] = "".join(lines)[-4000:]
            _login["done"] = True
            if not connected and not _login["error"]:
                _login["error"] = _login_failure(_login["output"])


def _login_failure(output):
    """Say what actually went wrong, in the words cloudflared used.

    The old message blamed the operator for closing the browser too early, which
    was usually not what happened, and left nothing to act on.
    """
    tail = ""
    for line in reversed([ln.strip() for ln in output.splitlines() if ln.strip()]):
        low = line.lower()
        if "http" in low and "dash.cloudflare.com" in low:
            continue
        if any(word in low for word in ("error", "failed", "denied", "timeout",
                                        "unable", "cannot", "refused")):
            tail = line[:300]
            break
    if tail:
        return f"cloudflared could not finish signing in: {tail}"
    return ("cloudflared finished without leaving a certificate this server can "
            "read. If you did authorize a domain, open the link again; if it "
            f"keeps happening, check that {CONFIG_DIR} is writable.")


def login_start():
    """Begin connecting a Cloudflare account and hand back the link to open.

    cloudflared waits for the browser itself, so this returns as soon as the
    link is known and the waiting happens in the background. Calling it again
    while a link is still live returns the same link rather than a second one.
    """
    if logged_in():
        return {"state": "connected", "url": "", "cert": CERT_PATH}
    if not installed():
        return {"state": "missing", "url": "",
                "error": "cloudflared is not installed on this server."}
    with _login_lock:
        live = (_login["url"] and not _login["done"]
                and time.time() - _login["started"] < LOGIN_TIMEOUT)
        if live:
            return {"state": "waiting", "url": _login["url"]}
    try:
        ensure_dir()
    except OSError as e:
        return {"state": "error", "url": "",
                "error": f"cannot write to {CONFIG_DIR}: {e}"}

    with _login_lock:
        _login.update({"url": "", "started": time.time(), "output": "",
                       "done": False, "error": ""})
    try:
        proc = subprocess.Popen(
            [binary(), "--no-autoupdate", "tunnel", "login"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=_env(), start_new_session=True)
    except OSError as e:
        with _login_lock:
            _login.update({"done": True, "error": str(e)})
        return {"state": "error", "url": "", "error": str(e)}

    threading.Thread(target=_login_reader, args=(proc,), daemon=True).start()
    deadline = time.time() + 20
    while time.time() < deadline:
        with _login_lock:
            if _login["url"]:
                return {"state": "waiting", "url": _login["url"]}
            if _login["done"]:
                return {"state": "error", "url": "",
                        "error": _login["error"] or _login["output"][-400:]}
        time.sleep(0.2)
    return {"state": "error", "url": "",
            "error": "cloudflared did not print a login link."}


def login_state():
    if logged_in():
        return {"state": "connected", "url": "", "cert": CERT_PATH}
    with _login_lock:
        if _login["url"] and not _login["done"]:
            waited = int(time.time() - _login["started"])
            if waited < LOGIN_TIMEOUT:
                return {"state": "waiting", "url": _login["url"], "waited": waited}
            return {"state": "idle", "url": "",
                    "error": "The link expired before it was opened."}
        if _login["error"]:
            return {"state": "error", "url": "", "error": _login["error"]}
    return {"state": "idle", "url": ""}


def disconnect():
    """Forget the account certificate. Tunnels themselves stay in Cloudflare;
    this machine simply loses the right to manage them until it logs in again.

    The copy cloudflared wrote under HOME goes too, or the next status check
    would adopt it straight back and Disconnect would appear to do nothing.
    """
    removed = []
    for path in [CERT_PATH] + _login_cert_candidates():
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                continue
            removed.append(path)
    with _login_lock:
        _login.update({"url": "", "started": 0.0, "output": "", "done": False,
                       "error": ""})
    return removed


# ------------------------------------------------------------------- tunnels
def cred_path(name):
    return os.path.join(CONFIG_DIR, f"{name}.json")


def _json_rows(out):
    """(rows, problem). cloudflared mixes log lines in with its JSON, and prints
    a bare `null` rather than an empty list when the account has no tunnels at
    all, which is the ordinary state of a new account and not an error."""
    text = out.strip()
    if not text:
        return [], ""
    if "[" in text and "]" in text:
        try:
            rows = json.loads(text[text.index("["):text.rindex("]") + 1])
        except (ValueError, json.JSONDecodeError):
            return [], "cloudflared answered something that was not a tunnel list."
        return (rows if isinstance(rows, list) else []), ""
    for line in text.splitlines():
        if line.strip() == "null":
            return [], ""
    return [], "cloudflared answered something that was not a tunnel list."


def list_remote():
    """The tunnels Cloudflare knows about, or a reason it could not be asked."""
    if not logged_in():
        return [], "No Cloudflare account is connected yet."
    rc, out = _run(["tunnel", "list", "--output", "json"], timeout=45)
    if rc != 0:
        return [], out.strip()[-400:] or "cloudflared could not list tunnels."
    rows, problem = _json_rows(out)
    if problem:
        return [], problem
    out_rows = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        out_rows.append({
            "id": str(row.get("id") or ""),
            "name": str(row.get("name") or ""),
            "created_at": str(row.get("created_at") or "")[:19],
            "connections": len(row.get("connections") or []),
        })
    return out_rows, ""


def name_problem(name):
    if not name:
        return "A tunnel needs a name."
    if not _NAME_RE.match(name):
        return ("A tunnel name may only hold lowercase letters, digits and "
                "hyphens, and must start with a letter or digit.")
    return ""


def create_tunnel(conn, name, actor=""):
    """Create the tunnel at Cloudflare and remember it here.

    The credentials file is written next to the config rather than into a home
    directory, so the service that runs the tunnel can find it whoever it runs
    as. Returns (ok, message).
    """
    problem = name_problem(name)
    if problem:
        return False, problem
    if not logged_in():
        return False, "Connect a Cloudflare account first."
    ensure_dir()
    rc, out = _run(["tunnel", "create", "--credentials-file", cred_path(name), name],
                   timeout=60)
    if rc != 0:
        return False, out.strip()[-400:] or "cloudflared refused to create the tunnel."

    tunnel_id = ""
    match = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", out)
    if match:
        tunnel_id = match.group(1)
    cur = conn.cursor()
    cur.execute("""INSERT INTO cf_tunnel (name, tunnel_id, cred_file, created_by)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (name) DO UPDATE
                     SET tunnel_id = EXCLUDED.tunnel_id,
                         cred_file = EXCLUDED.cred_file""",
                (name, tunnel_id, cred_path(name), actor[:100]))
    cur.close()
    return True, f"Tunnel {name} created."


def delete_tunnel(conn, name):
    """Remove the tunnel from Cloudflare and every route pointing through it."""
    if name_problem(name):
        return False, "That is not a tunnel name."
    if not logged_in():
        return False, "Connect a Cloudflare account first."
    rc, out = _run(["tunnel", "delete", "--credentials-file", cred_path(name), name],
                   timeout=60)
    # A tunnel already gone from Cloudflare must still be cleared from here, or
    # the panel would keep showing something nobody can act on.
    gone = rc == 0 or "not found" in out.lower()
    cur = conn.cursor()
    cur.execute("DELETE FROM cf_route WHERE tunnel = %s", (name,))
    cur.execute("DELETE FROM cf_tunnel WHERE name = %s", (name,))
    cur.close()
    if os.path.exists(cred_path(name)):
        try:
            os.remove(cred_path(name))
        except OSError:
            pass
    if not gone:
        return False, out.strip()[-400:] or "cloudflared refused to delete the tunnel."
    return True, f"Tunnel {name} deleted."


def known_tunnels(conn):
    cur = conn.cursor()
    cur.execute("""SELECT name, tunnel_id, cred_file, created_by, created_at
                   FROM cf_tunnel ORDER BY name""")
    rows = [{"name": r[0], "tunnel_id": r[1], "cred_file": r[2],
             "created_by": r[3], "created_at": str(r[4])[:19]}
            for r in cur.fetchall()]
    cur.close()
    return rows


# -------------------------------------------------------------------- routes
def route_problem(hostname, local_host, local_port):
    problems = []
    host = (hostname or "").strip().lower()
    if not host:
        problems.append("A public hostname is required.")
    elif not _HOSTNAME_RE.match(host):
        problems.append(f"{hostname} is not a hostname Cloudflare can route.")
    target = (local_host or "").strip().lower()
    if not target:
        problems.append("A local address is required.")
    elif not _is_ip(target) and not _LOCAL_HOST_RE.match(target):
        problems.append(f"{local_host} is not an address or a hostname.")
    try:
        port = int(local_port)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        problems.append("The local port has to be between 1 and 65535.")
    return " ".join(problems)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def routes(conn, tunnel=""):
    cur = conn.cursor()
    if tunnel:
        cur.execute("""SELECT tunnel, hostname, local_host, local_port, dns_ok, detail,
                              created_by, created_at
                       FROM cf_route WHERE tunnel = %s ORDER BY hostname""", (tunnel,))
    else:
        cur.execute("""SELECT tunnel, hostname, local_host, local_port, dns_ok, detail,
                              created_by, created_at
                       FROM cf_route ORDER BY tunnel, hostname""")
    rows = [{"tunnel": r[0], "hostname": r[1], "local_host": r[2], "local_port": r[3],
             "dns_ok": r[4], "detail": r[5], "created_by": r[6],
             "created_at": str(r[7])[:19]}
            for r in cur.fetchall()]
    cur.close()
    return rows


def add_route(conn, tunnel, hostname, local_host, local_port, actor=""):
    """Point a public hostname through a tunnel at a local port.

    Two things have to happen: the hostname needs a DNS record at Cloudflare
    pointing at this tunnel, and the tunnel's own config needs an ingress rule
    saying where to deliver it. Returns (ok, message).
    """
    if name_problem(tunnel):
        return False, "That is not a tunnel name."
    problem = route_problem(hostname, local_host, local_port)
    if problem:
        return False, problem
    hostname = hostname.strip().lower()
    local_host = local_host.strip().lower()
    local_port = int(local_port)

    rc, out = _run(["tunnel", "route", "dns", "--overwrite-dns", tunnel, hostname],
                   timeout=60)
    dns_ok = rc == 0
    detail = "" if dns_ok else out.strip()[-300:]

    cur = conn.cursor()
    cur.execute("""INSERT INTO cf_route (tunnel, hostname, local_host, local_port,
                                         dns_ok, detail, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (hostname) DO UPDATE
                     SET tunnel = EXCLUDED.tunnel,
                         local_host = EXCLUDED.local_host,
                         local_port = EXCLUDED.local_port,
                         dns_ok = EXCLUDED.dns_ok,
                         detail = EXCLUDED.detail""",
                (tunnel, hostname, local_host, local_port, dns_ok, detail, actor[:100]))
    cur.close()

    written, write_note = write_config(conn, tunnel)
    if not dns_ok:
        return False, ("The forward is saved and the tunnel will serve it, but "
                       f"the DNS record could not be created: {detail}")
    if not written:
        return False, f"The DNS record is in place, but {write_note}"
    return True, f"{hostname} now reaches {local_host}:{local_port} through {tunnel}."


def remove_route(conn, hostname):
    hostname = (hostname or "").strip().lower()
    cur = conn.cursor()
    cur.execute("SELECT tunnel FROM cf_route WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    cur.execute("DELETE FROM cf_route WHERE hostname = %s", (hostname,))
    cur.close()
    if not row:
        return False, "There is no forward for that hostname."
    write_config(conn, row[0])
    return True, f"{hostname} no longer forwards anywhere."


# -------------------------------------------------------------- config + unit
def active_tunnel(conn):
    cur = conn.cursor()
    cur.execute("SELECT value FROM system_settings WHERE key = %s", (ACTIVE_SETTING,))
    row = cur.fetchone()
    cur.close()
    return (row[0] if row else "") or ""


def set_active(conn, name):
    if name and name_problem(name):
        return False, "That is not a tunnel name."
    cur = conn.cursor()
    cur.execute("""INSERT INTO system_settings (key, value) VALUES (%s, %s)
                   ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value""",
                (ACTIVE_SETTING, name))
    cur.close()
    return True, name


def render_config(tunnel, cred_file, route_rows):
    """The cloudflared config file for one tunnel.

    Hostnames, addresses and ports are all validated before they get here, so
    every value is a plain YAML scalar with nothing to quote. The catch-all at
    the end is what keeps cloudflared from serving a hostname nobody configured.
    """
    lines = [
        "# Written by Argus Management. Edits here are replaced when a forward",
        "# is added or removed in the panel.",
        f"tunnel: {tunnel}",
        f"credentials-file: {cred_file}",
        "no-autoupdate: true",
        "ingress:",
    ]
    for row in route_rows:
        lines.append(f"  - hostname: {row['hostname']}")
        lines.append(f"    service: http://{row['local_host']}:{row['local_port']}")
    lines.append("  - service: http_status:404")
    return "\n".join(lines) + "\n"


def write_config(conn, tunnel=""):
    """(ok, note). Renders the config for the tunnel and, if the service is
    already running, asks it to pick the file up."""
    tunnel = tunnel or active_tunnel(conn)
    if not tunnel:
        return False, "no tunnel is selected to run."
    rows = routes(conn, tunnel)
    cred = cred_path(tunnel)
    if not os.path.isfile(cred):
        return False, (f"the credentials file for {tunnel} is missing, so the "
                       "tunnel cannot be started from this machine.")
    try:
        ensure_dir()
        tmp = CONFIG_PATH + ".new"
        with open(tmp, "w") as fh:
            fh.write(render_config(tunnel, cred, rows))
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG_PATH)
    except OSError as e:
        return False, f"the config file could not be written: {e}"
    if service_state().get("active"):
        _systemctl("restart")
    return True, ""


UNIT_TEMPLATE = """[Unit]
Description=Cloudflare Tunnel, managed by Argus Management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} --no-autoupdate --config {config} tunnel run
Restart=on-failure
RestartSec=5s
TimeoutStartSec=0
Environment=TUNNEL_ORIGIN_CERT={cert}

[Install]
WantedBy=multi-user.target
"""


def _systemctl(*args, timeout=30):
    """systemctl, always aimed at our own unit. daemon-reload is the one verb
    that takes no unit name, so it is spelled out separately."""
    if args == ("daemon-reload",):
        cmd = ["systemctl", "daemon-reload"]
    else:
        cmd = ["systemctl"] + list(args) + [f"{SERVICE_NAME}.service"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return 1, str(e)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def install_service(conn):
    """Write the unit that runs the tunnel and start it. Named argus-tunnel so it
    never collides with a cloudflared service the operator installed by hand."""
    if not installed():
        return False, "cloudflared is not installed on this server."
    tunnel = active_tunnel(conn)
    if not tunnel:
        return False, "Choose which tunnel should run first."
    ok, note = write_config(conn, tunnel)
    if not ok:
        return False, note
    try:
        with open(UNIT_PATH, "w") as fh:
            fh.write(UNIT_TEMPLATE.format(binary=binary(), config=CONFIG_PATH,
                                          cert=CERT_PATH))
    except OSError as e:
        return False, f"the service file could not be written: {e}"
    _systemctl("daemon-reload")
    rc, out = _systemctl("enable", "--now")
    if rc != 0:
        return False, out.strip()[-400:] or "systemd refused to start the tunnel."
    return True, f"{tunnel} is running as {SERVICE_NAME}.service."


def service_action(action):
    if action not in ("start", "stop", "restart"):
        return False, "That is not something the tunnel service can be asked to do."
    rc, out = _systemctl(action)
    if rc != 0:
        return False, out.strip()[-400:] or f"systemd refused to {action} the tunnel."
    return True, f"Tunnel {action}ed."


def uninstall_service():
    if not os.path.exists(UNIT_PATH):
        return True, "The tunnel service was not installed."
    _systemctl("disable", "--now")
    try:
        os.remove(UNIT_PATH)
    except OSError as e:
        return False, str(e)
    _systemctl("daemon-reload")
    return True, "The tunnel service was removed."


def service_state():
    """What systemd says about our unit, in the shape the panel displays."""
    out = {"installed": os.path.exists(UNIT_PATH), "active": False,
           "state": "not installed", "enabled": False}
    if not out["installed"]:
        return out
    rc, text = _systemctl("is-active", timeout=15)
    state = (text or "").strip().splitlines()[0] if text.strip() else "unknown"
    out["state"] = state
    out["active"] = state == "active"
    rc, text = _systemctl("is-enabled", timeout=15)
    out["enabled"] = (text or "").strip().startswith("enabled")
    return out


def overview(conn):
    """Everything the Cloudflare card needs in one answer, so the interface does
    not have to guess which step the operator is on."""
    remote, remote_error = list_remote()
    return {
        "installed": installed(),
        "version": version(),
        "logged_in": logged_in(),
        "login": login_state(),
        "config_dir": CONFIG_DIR,
        "tunnels": known_tunnels(conn),
        "remote": remote,
        "remote_error": remote_error,
        "active": active_tunnel(conn),
        "routes": routes(conn),
        "service": service_state(),
    }
