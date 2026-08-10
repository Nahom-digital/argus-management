#!/usr/bin/env python3
# management.py, the one-command front door for the Argus Management panel.
#
#   python3 management.py             interactive setup wizard, then run
#   python3 management.py --service   install + start the systemd service, then exit
#   python3 management.py --serve     run in the foreground from deploy.json (systemd calls this)
#   python3 management.py --status    show the service / config status
#   python3 management.py --setup     force the wizard even without a TTY
#
# This file is deliberately self-sufficient: it needs nothing but a stock
# Python 3 interpreter. It installs its own Python dependencies (working around
# Debian/Kali's PEP-668 "externally-managed-environment" refusal, falling back
# to a private virtualenv when the system refuses outright), makes sure a
# PostgreSQL server is installed and running, finds a privileged way into that
# server even when the configured role does not exist yet, then provisions the
# database, the schema, and the panel's admin account.
#
# The FastAPI app itself lives in panel.py; this file is only the deployment
# front door so the whole thing ships as one easy-to-run app.

import os
import re
import sys
import glob
import json
import time
import stat
import errno
import shutil
import socket
import getpass
import hashlib
import platform
import secrets
import tempfile
import subprocess

# Standard library only, so importing these before the dependency bootstrap is safe.
import recovery
import ssh_vault
import panel_users
import cloudflare_tunnel
import firewall
import mail

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "deploy.json")
ENV_PATH = os.path.join(HERE, ".env")
VENV_DIR = os.path.join(HERE, ".venv")
SERVICE_NAME = "argus-management"
UNIT_PATH = f"/etc/systemd/system/{SERVICE_NAME}.service"

CONNECT_TIMEOUT = 5          # seconds for a single PostgreSQL connection attempt
SEP = "\x1f"                 # ASCII unit separator, psql field delimiter

DEFAULTS = {
    "db_host": "127.0.0.1",
    "db_port": 5432,
    "db_user": "argus",
    "db_password": "",
    "db_name": "argus",
    "host": "127.0.0.1",
    "port": 8080,
    "base_path": "",         # "" -> served at the domain root (e.g. a subdomain)
}


# --------------------------------------------------------------------------- #
# terminal helpers
# --------------------------------------------------------------------------- #
_TTY = sys.stdout.isatty()

def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _TTY else str(text)

def banner():
    print()
    print(_c("  ARGUS · Management panel, deployment setup", "1;36"))
    print(_c("  " + "─" * 46, "2;36"))

def head(text):
    print("\n" + _c("── " + text + " " + "─" * max(3, 58 - len(text)), "1;36"))

def ok(text):
    print(_c("  ✓ ", "1;32") + str(text))

def warn(text):
    print(_c("  ! ", "1;33") + str(text))

def err(text):
    print(_c("  ✗ ", "1;31") + str(text))

def info(text):
    print(_c("    " + str(text), "2;37"))

def step(text):
    print(_c("  · ", "1;34") + str(text))

def ask(prompt, default=None):
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        val = input(_c("  » ", "1;35") + prompt + suffix + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        err("setup cancelled")
        sys.exit(130)
    return val or (default if default is not None else "")

def ask_secret(prompt, allow_empty=False):
    while True:
        try:
            val = getpass.getpass(_c("  » ", "1;35") + prompt + ": ")
        except (EOFError, KeyboardInterrupt):
            print()
            err("setup cancelled")
            sys.exit(130)
        if val or allow_empty:
            return val
        warn("a value is required")

def ask_yes(prompt, default=False):
    d = "Y/n" if default else "y/N"
    while True:
        val = ask(f"{prompt} ({d})", "").lower()
        if not val:
            return default
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        warn("please answer y or n")


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
def run(cmd, timeout=600, cwd=None, env=None, capture=True, stdin_input=None):
    """Run a command, never raising. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            input=stdin_input,
            timeout=timeout,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"
    except Exception as e:                                   # pragma: no cover
        return 1, "", str(e)

def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0

def have_sudo():
    return shutil.which("sudo") is not None

def sudo_prefix():
    """Command prefix that escalates to root, or [] when we already are root."""
    if is_root():
        return []
    if have_sudo():
        return ["sudo"]
    return []

def can_escalate():
    return is_root() or have_sudo()

def sudo_is_cached():
    """True when sudo runs without prompting (root, NOPASSWD, or cached ticket)."""
    if is_root():
        return True
    if not have_sudo():
        return False
    rc, _, _ = run(["sudo", "-n", "true"], timeout=10)
    return rc == 0

def prime_sudo(reason):
    """Ask for the sudo password once, up front, so later steps don't stall."""
    if sudo_is_cached():
        return True
    if not have_sudo() or not sys.stdin.isatty():
        return False
    info(f"sudo is needed to {reason}")
    rc, _, _ = run(["sudo", "-v"], timeout=120, capture=False)
    return rc == 0


# --------------------------------------------------------------------------- #
# 1. Python dependency bootstrap
# --------------------------------------------------------------------------- #
# The panel needs a handful of third-party packages. Rather than making the
# operator fight `pip install -r requirements.txt` on a distro that refuses to
# touch the system site-packages, we install them ourselves and escalate through
# progressively more forceful strategies until one sticks.

# import name -> (pip specs, distro package names)
DEPENDENCIES = (
    ("psycopg2",   ("psycopg2-binary",), ("python3-psycopg2",)),
    ("fastapi",    ("fastapi",),         ("python3-fastapi",)),
    ("starlette",  ("starlette",),       ("python3-starlette",)),
    ("uvicorn",    ("uvicorn",),         ("python3-uvicorn",)),
    ("websockets", ("websockets",),      ("python3-websockets",)),  # in-browser terminal
    ("cryptography", ("cryptography",),  ("python3-cryptography",)),  # SSH vault encryption
)

def _importable(module):
    import importlib.util
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False

def _refresh_import_paths():
    """Make freshly installed packages visible to the running interpreter."""
    import importlib
    import site
    try:
        user_site = site.getusersitepackages()
        if user_site and os.path.isdir(user_site) and user_site not in sys.path:
            sys.path.insert(0, user_site)
    except Exception:
        pass
    importlib.invalidate_caches()

def _missing_dependencies():
    return [dep for dep in DEPENDENCIES if not _importable(dep[0])]

def _ensure_pip():
    rc, _, _ = run([sys.executable, "-m", "pip", "--version"], timeout=60)
    if rc == 0:
        return True
    step("pip is missing, bootstrapping it with ensurepip")
    run([sys.executable, "-m", "ensurepip", "--upgrade"], timeout=300)
    rc, _, _ = run([sys.executable, "-m", "pip", "--version"], timeout=60)
    if rc == 0:
        return True
    # Debian splits pip into its own package.
    if shutil.which("apt-get") and can_escalate():
        run(sudo_prefix() + ["apt-get", "install", "-y", "python3-pip"], timeout=900)
        rc, _, _ = run([sys.executable, "-m", "pip", "--version"], timeout=60)
    return rc == 0

# Ordered from least to most invasive. `--break-system-packages` is what gets
# past PEP-668 on Debian/Kali/Ubuntu; older pips don't know the flag, which is
# why the plain attempts come first and failures are simply stepped over.
PIP_STRATEGIES = (
    ("pip",                                     []),
    ("pip --user",                              ["--user"]),
    ("pip --break-system-packages",             ["--break-system-packages"]),
    ("pip --user --break-system-packages",      ["--user", "--break-system-packages"]),
)

def _pip_install(specs, extra_flags, python=None):
    cmd = [python or sys.executable, "-m", "pip", "install",
           "--disable-pip-version-check", "--no-input"] + list(extra_flags) + list(specs)
    return run(cmd, timeout=1800)

def _apt_install(packages):
    if not shutil.which("apt-get") or not can_escalate():
        return False
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(sudo_prefix() + ["apt-get", "update", "-qq"], timeout=900, env=env)
    rc, _, _ = run(sudo_prefix() + ["apt-get", "install", "-y"] + list(packages),
                   timeout=1800, env=env)
    return rc == 0

def _venv_python():
    candidate = os.path.join(VENV_DIR, "bin", "python")
    if os.path.exists(candidate):
        return candidate
    candidate = os.path.join(VENV_DIR, "Scripts", "python.exe")   # Windows
    if os.path.exists(candidate):
        return candidate
    return None

def _running_inside_venv():
    py = _venv_python()
    return bool(py) and os.path.realpath(sys.executable) == os.path.realpath(py)

def _create_venv():
    """Build .venv next to this script. Returns the interpreter path or None."""
    py = _venv_python()
    if py:
        return py
    step("creating a private virtualenv (.venv) for the panel's dependencies")
    # --system-site-packages so anything already installed system-wide is reused
    # instead of being downloaded again.
    rc, _, stderr = run([sys.executable, "-m", "venv", "--system-site-packages", VENV_DIR],
                        timeout=900)
    if rc != 0:
        # Debian ships `venv` without ensurepip until python3-venv is installed.
        if "ensurepip" in stderr or "python3-venv" in stderr or rc == 1:
            info("virtualenv support is missing, installing it from the distro")
            ver = f"python{sys.version_info.major}.{sys.version_info.minor}-venv"
            _apt_install([ver]) or _apt_install(["python3-venv"])
            shutil.rmtree(VENV_DIR, ignore_errors=True)
            rc, _, stderr = run([sys.executable, "-m", "venv", "--system-site-packages", VENV_DIR],
                                timeout=900)
    if rc != 0 and shutil.which("virtualenv"):
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        rc, _, stderr = run(["virtualenv", VENV_DIR], timeout=900)
    if rc != 0:
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        err(f"could not create a virtualenv: {stderr.strip()[:200]}")
        return None
    return _venv_python()

def _reexec(python):
    """Restart this script under a different interpreter, once."""
    env = dict(os.environ, ARGUS_BOOTSTRAPPED="1")
    argv = [python, os.path.abspath(__file__)] + sys.argv[1:]
    ok(f"restarting under {python}")
    sys.stdout.flush()
    os.execve(python, argv, env)

def ensure_python_deps():
    """Guarantee every runtime dependency is importable. May re-exec the process."""
    head("Runtime dependencies")

    missing = _missing_dependencies()
    if not missing:
        ok("all Python dependencies are present")
        return

    # If a venv already exists and the system interpreter is short of packages,
    # the venv is almost certainly where they live, go there first.
    venv_py = _venv_python()
    if venv_py and not _running_inside_venv() and os.environ.get("ARGUS_BOOTSTRAPPED") != "1":
        _reexec(venv_py)

    names = ", ".join(m[0] for m in missing)
    step(f"missing: {names}")
    step("installing them now, no manual pip step required")

    if _ensure_pip():
        specs = [spec for dep in missing for spec in dep[1][:1]]
        for label, flags in PIP_STRATEGIES:
            rc, _, stderr = _pip_install(specs, flags)
            _refresh_import_paths()
            if not _missing_dependencies():
                ok(f"installed via {label}")
                return
            if rc != 0:
                reason = "externally-managed environment" if "externally-managed" in stderr \
                    else (stderr.strip().splitlines() or [""])[-1][:120]
                info(f"{label} did not work ({reason}), trying the next approach")
    else:
        warn("pip is unavailable in this interpreter")

    # Distro packages: works on Debian-likes even when pip is locked down.
    missing = _missing_dependencies()
    if missing:
        distro_pkgs = [pkg for dep in missing for pkg in dep[2]]
        if distro_pkgs and shutil.which("apt-get"):
            step("falling back to distro packages (apt)")
            if _apt_install(distro_pkgs):
                _refresh_import_paths()
                if not _missing_dependencies():
                    ok("installed via apt")
                    return

    # Last resort, and the one that works everywhere: our own virtualenv.
    missing = _missing_dependencies()
    if missing:
        if os.environ.get("ARGUS_BOOTSTRAPPED") == "1":
            err("dependencies are still missing after bootstrapping: "
                + ", ".join(m[0] for m in missing))
            info("install them manually, then re-run:  python3 management.py")
            sys.exit(1)
        step("the system refuses to install packages, using a private virtualenv instead")
        py = _create_venv()
        if not py:
            err("could not build a virtualenv; cannot continue")
            sys.exit(1)
        specs = [spec for dep in missing for spec in dep[1][:1]]
        rc, _, stderr = _pip_install(specs, [], python=py)
        if rc != 0:
            err(f"installing into the virtualenv failed: {stderr.strip()[:300]}")
            sys.exit(1)
        ok("dependencies installed into .venv")
        _reexec(py)

    ok("all Python dependencies are present")


def python_for_service():
    """The interpreter systemd should launch, the venv's, when we built one."""
    return _venv_python() or sys.executable


# --------------------------------------------------------------------------- #
# 2. PostgreSQL presence
# --------------------------------------------------------------------------- #
PSQL_SEARCH_GLOBS = (
    "/usr/lib/postgresql/*/bin/psql",       # Debian / Ubuntu / Kali
    "/usr/pgsql-*/bin/psql",                # RHEL / Fedora
    "/opt/homebrew/opt/postgresql*/bin/psql",
    "/usr/local/opt/postgresql*/bin/psql",
)

def find_psql():
    found = shutil.which("psql")
    if found:
        return found
    import glob
    for pattern in PSQL_SEARCH_GLOBS:
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]      # highest version
    return None

def find_pg_binary(name):
    found = shutil.which(name)
    if found:
        return found
    import glob
    for pattern in PSQL_SEARCH_GLOBS:
        for match in sorted(glob.glob(pattern.replace("psql", name))):
            return match
    return None

def port_is_open(host, port, timeout=2.0):
    """True when something accepts TCP connections there."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False

def socket_dir_has_server(port):
    """True when a PostgreSQL unix socket for `port` exists locally."""
    for directory in ("/var/run/postgresql", "/run/postgresql", "/tmp"):
        if os.path.exists(os.path.join(directory, f".s.PGSQL.{port}")):
            return directory
    return None

def postgres_is_up(host, port):
    if host.startswith("/"):
        return os.path.exists(os.path.join(host, f".s.PGSQL.{port}"))
    return port_is_open(host, port) or bool(socket_dir_has_server(port))

def detect_package_manager():
    for mgr in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk", "brew"):
        if shutil.which(mgr):
            return mgr
    return None

PG_PACKAGES = {
    "apt-get": ["postgresql", "postgresql-contrib"],
    "dnf":     ["postgresql-server", "postgresql-contrib"],
    "yum":     ["postgresql-server", "postgresql-contrib"],
    "pacman":  ["postgresql"],
    "zypper":  ["postgresql-server"],
    "apk":     ["postgresql", "postgresql-contrib"],
    "brew":    ["postgresql"],
}

NGINX_PACKAGES = {
    "apt-get": ["nginx"], "dnf": ["nginx"], "yum": ["nginx"],
    "pacman":  ["nginx"], "zypper": ["nginx"], "apk": ["nginx"], "brew": ["nginx"],
}

def nginx_installed():
    return shutil.which("nginx") is not None

def install_nginx():
    """Install nginx, needed for the panel's reverse proxy manager. Never
    fatal: the panel works without it, that feature is just unavailable."""
    if nginx_installed():
        return True
    mgr = detect_package_manager()
    if not mgr:
        warn("no supported package manager found, install nginx manually if you want the proxy manager")
        return False
    packages = NGINX_PACKAGES[mgr]
    step(f"installing nginx with {mgr}: {' '.join(packages)}")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if mgr == "brew":
        rc, _, stderr = run(["brew", "install"] + packages, timeout=1800)
    elif mgr == "apt-get":
        run(sudo_prefix() + ["apt-get", "update", "-qq"], timeout=900, env=env)
        rc, _, stderr = run(sudo_prefix() + ["apt-get", "install", "-y"] + packages, timeout=1800, env=env)
    elif mgr in ("dnf", "yum"):
        rc, _, stderr = run(sudo_prefix() + [mgr, "install", "-y"] + packages, timeout=1800)
    elif mgr == "pacman":
        rc, _, stderr = run(sudo_prefix() + ["pacman", "-Sy", "--noconfirm"] + packages, timeout=1800)
    elif mgr == "zypper":
        rc, _, stderr = run(sudo_prefix() + ["zypper", "--non-interactive", "install"] + packages, timeout=1800)
    else:
        rc, _, stderr = run(sudo_prefix() + ["apk", "add"] + packages, timeout=1800)
    if rc != 0:
        warn(f"nginx install failed, so the proxy manager stays unavailable: "
             f"{stderr.strip()[:300]}")
        return False
    run(sudo_prefix() + ["systemctl", "enable", "nginx"], timeout=60)
    run(sudo_prefix() + ["systemctl", "start", "nginx"], timeout=60)
    ok("nginx installed")
    return True

STREAM_MODULE_PACKAGES = {
    "apt-get": ["libnginx-mod-stream"],
    "dnf": ["nginx-mod-stream"], "yum": ["nginx-mod-stream"],
}
STREAM_DIR = "/etc/nginx/stream.d"
STREAM_INCLUDE = f"stream {{\n    include {STREAM_DIR}/*.conf;\n}}\n"

def _nginx_has_stream():
    """Whether nginx would understand a stream {} block right now."""
    rc, out, errout = run(["nginx", "-V"], timeout=30)
    build = (out or "") + (errout or "")
    if "--with-stream=dynamic" in build:
        for name in glob.glob("/etc/nginx/modules-enabled/*.conf"):
            try:
                with open(name) as fh:
                    body = fh.read()
            except OSError:
                continue
            if "load_module" in body and "stream_module" in body:
                return True
        return False
    return "--with-stream" in build

def ensure_nginx_stream():
    """Make TCP and UDP proxy hosts possible.

    Two separate things are needed and neither is the default on Debian: the
    stream module has to be loaded, and nginx.conf needs a stream {} block that
    includes somewhere for the panel to write. Without both, a TCP host is an
    unknown directive and nginx refuses to start, so the panel refuses to write
    one until this has run. Never fatal: HTTP and HTTPS hosts work regardless.
    """
    if not nginx_installed():
        return False
    mgr = detect_package_manager()
    if not _nginx_has_stream():
        packages = STREAM_MODULE_PACKAGES.get(mgr)
        if not packages:
            info("nginx has no stream module, so TCP and UDP proxy hosts stay unavailable")
            return False
        step(f"installing the nginx stream module: {' '.join(packages)}")
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        if mgr == "apt-get":
            run(sudo_prefix() + ["apt-get", "update", "-qq"], timeout=900, env=env)
            rc, _, stderr = run(sudo_prefix() + ["apt-get", "install", "-y"] + packages,
                                timeout=1800, env=env)
        else:
            rc, _, stderr = run(sudo_prefix() + [mgr, "install", "-y"] + packages, timeout=1800)
        if rc != 0 or not _nginx_has_stream():
            warn("the nginx stream module could not be installed, so TCP and UDP "
                 "proxy hosts stay unavailable")
            return False
        ok("nginx stream module installed")

    if not os.path.isdir(STREAM_DIR):
        rc, _, _ = run(sudo_prefix() + ["mkdir", "-p", STREAM_DIR], timeout=30)
        if rc != 0:
            warn(f"could not create {STREAM_DIR}, so TCP and UDP hosts stay unavailable")
            return False

    conf = "/etc/nginx/nginx.conf"
    try:
        with open(conf) as fh:
            current = fh.read()
    except OSError as e:
        warn(f"could not read {conf}: {e}")
        return False
    if STREAM_DIR in current:
        ok("nginx is ready for TCP and UDP proxy hosts")
        return True

    step(f"adding a stream block to {conf} so {STREAM_DIR} is loaded")
    backup = conf + ".argus-backup"
    run(sudo_prefix() + ["cp", conf, backup], timeout=30)
    updated = current.rstrip("\n") + "\n\n# added by argus-management, for TCP and UDP proxy hosts\n" + STREAM_INCLUDE
    if not _write_root_file(conf, updated):
        warn(f"could not write {conf}, so TCP and UDP hosts stay unavailable")
        return False
    rc, _, stderr = run(sudo_prefix() + ["nginx", "-t"], timeout=60)
    if rc != 0:
        warn(f"nginx rejected the stream block, putting {conf} back: {stderr.strip()[:200]}")
        run(sudo_prefix() + ["cp", backup, conf], timeout=30)
        return False
    run(sudo_prefix() + ["systemctl", "reload", "nginx"], timeout=60)
    ok("nginx is ready for TCP and UDP proxy hosts")
    return True

def _write_root_file(path, text):
    """Write a file that belongs to root. Goes through a temporary file so a
    failed copy leaves the original untouched rather than half written."""
    fd, tmp = tempfile.mkstemp(prefix="argus-nginx-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        rc, _, _ = run(sudo_prefix() + ["cp", tmp, path], timeout=30)
        return rc == 0
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

CLOUDFLARED_ARCH = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "armv7l": "arm", "armv6l": "arm", "i386": "386", "i686": "386",
}
CLOUDFLARED_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"
CLOUDFLARED_BIN = "/usr/local/bin/cloudflared"

def cloudflared_installed():
    return shutil.which("cloudflared") is not None

def _download(url, dest):
    """Fetch a file with whichever downloader the box has."""
    if shutil.which("curl"):
        rc, _, stderr = run(["curl", "-fsSL", "-o", dest, url], timeout=900)
    elif shutil.which("wget"):
        rc, _, stderr = run(["wget", "-q", "-O", dest, url], timeout=900)
    else:
        return False, "neither curl nor wget is installed"
    if rc != 0 or not os.path.exists(dest) or os.path.getsize(dest) < 1024:
        return False, (stderr or "").strip()[:200] or "the download produced nothing"
    return True, ""

def install_cloudflared():
    """Install cloudflared, which is what makes the Cloudflare Tunnel page work.

    Cloudflare does not ship it in the distro repositories, so this takes the
    release package for this architecture, and falls back to the bare binary when
    dpkg is not the way software arrives on this machine. Never fatal: the panel
    works without it and only that one page goes unavailable.
    """
    if cloudflared_installed():
        ok(f"cloudflared present: {shutil.which('cloudflared')}")
        return True
    machine = platform.machine().lower()
    arch = CLOUDFLARED_ARCH.get(machine)
    if not arch:
        warn(f"no cloudflared build for {machine or 'this architecture'}, so the "
             "Cloudflare Tunnel page stays unavailable")
        return False
    if detect_package_manager() == "brew":
        step("installing cloudflared with brew")
        rc, _, stderr = run(["brew", "install", "cloudflared"], timeout=1800)
        if rc == 0:
            ok("cloudflared installed")
            return True
        warn(f"brew could not install cloudflared: {stderr.strip()[:200]}")
        return False

    tmpdir = tempfile.mkdtemp(prefix="argus-cloudflared-")
    try:
        if shutil.which("dpkg"):
            deb = os.path.join(tmpdir, "cloudflared.deb")
            step(f"downloading cloudflared for {arch}")
            got, why = _download(f"{CLOUDFLARED_BASE}/cloudflared-linux-{arch}.deb", deb)
            if got:
                rc, _, stderr = run(sudo_prefix() + ["dpkg", "-i", deb], timeout=600)
                if rc == 0 and cloudflared_installed():
                    ok("cloudflared installed")
                    return True
                warn(f"the cloudflared package would not install: {stderr.strip()[:200]}")
            else:
                warn(f"could not download the cloudflared package: {why}")

        binary = os.path.join(tmpdir, "cloudflared")
        step(f"downloading the cloudflared binary for {arch}")
        got, why = _download(f"{CLOUDFLARED_BASE}/cloudflared-linux-{arch}", binary)
        if not got:
            warn(f"could not download cloudflared: {why}, so the Cloudflare "
                 "Tunnel page stays unavailable")
            return False
        os.chmod(binary, 0o755)
        rc, _, stderr = run(sudo_prefix() + ["cp", binary, CLOUDFLARED_BIN], timeout=120)
        if rc != 0:
            warn(f"could not put cloudflared in {CLOUDFLARED_BIN}: {stderr.strip()[:200]}")
            return False
        run(sudo_prefix() + ["chmod", "755", CLOUDFLARED_BIN], timeout=60)
        if not cloudflared_installed():
            warn(f"cloudflared was copied to {CLOUDFLARED_BIN} but is not on PATH")
            return False
        ok("cloudflared installed")
        return True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

DOCKER_PACKAGES = {
    "apt-get": ["docker.io", "docker-compose-v2"],
    "dnf": ["docker", "docker-compose"], "yum": ["docker", "docker-compose"],
    "pacman": ["docker", "docker-compose"], "zypper": ["docker", "docker-compose"],
    "apk": ["docker", "docker-compose"], "brew": ["docker"],
}

def _compose_present():
    if shutil.which("docker"):
        rc, _, _ = run(["docker", "compose", "version"], timeout=60)
        if rc == 0:
            return True
    return shutil.which("docker-compose") is not None

def install_mail_prerequisites():
    """Make inbound mail possible: mailcow needs Docker and Compose.

    The mailcow stack itself is several gigabytes and needs a domain and DNS
    before it is worth pulling, so it is set up from the Mail tab where the admin
    types the domain. What is installed here is the part that has to exist before
    that button can do anything. Never fatal: without it only inbound mail is
    unavailable, and outbound still works through a relay.
    """
    have_docker = shutil.which("docker") is not None
    if have_docker and _compose_present():
        ok("Docker and Compose present, mailcow can be set up from the Mail tab")
        return True
    mgr = detect_package_manager()
    packages = DOCKER_PACKAGES.get(mgr)
    if not packages:
        warn("no supported package manager found, so install Docker by hand if "
             "you want to receive mail on this server")
        return False
    step(f"installing Docker and Compose with {mgr}: {' '.join(packages)}")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if mgr == "apt-get":
        run(sudo_prefix() + ["apt-get", "update", "-qq"], timeout=900, env=env)
        rc, _, stderr = run(sudo_prefix() + ["apt-get", "install", "-y"] + packages,
                            timeout=1800, env=env)
    elif mgr == "brew":
        rc, _, stderr = run(["brew", "install"] + packages, timeout=1800)
    elif mgr == "pacman":
        rc, _, stderr = run(sudo_prefix() + ["pacman", "-Sy", "--noconfirm"] + packages,
                            timeout=1800)
    elif mgr == "zypper":
        rc, _, stderr = run(sudo_prefix() + ["zypper", "--non-interactive", "install"] + packages,
                            timeout=1800)
    elif mgr == "apk":
        rc, _, stderr = run(sudo_prefix() + ["apk", "add"] + packages, timeout=1800)
    else:
        rc, _, stderr = run(sudo_prefix() + [mgr, "install", "-y"] + packages, timeout=1800)
    if rc != 0:
        warn("Docker could not be installed, so receiving mail stays unavailable: "
             + stderr.strip()[:200])
        return False
    run(sudo_prefix() + ["systemctl", "enable", "docker"], timeout=60)
    run(sudo_prefix() + ["systemctl", "start", "docker"], timeout=120)
    if not _compose_present():
        warn("Docker is installed but Compose is not, so mailcow cannot be "
             "started. Install docker-compose-plugin and run this again.")
        return False
    ok("Docker and Compose installed, mailcow can be set up from the Mail tab")
    return True

def install_postgres():
    """Install a PostgreSQL server with whatever package manager is present."""
    mgr = detect_package_manager()
    if not mgr:
        err("no supported package manager found, install PostgreSQL manually")
        return False
    packages = PG_PACKAGES[mgr]
    step(f"installing PostgreSQL with {mgr}: {' '.join(packages)}")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    if mgr == "brew":
        rc, _, stderr = run(["brew", "install"] + packages, timeout=3600)
    elif mgr == "apt-get":
        run(sudo_prefix() + ["apt-get", "update", "-qq"], timeout=900, env=env)
        rc, _, stderr = run(sudo_prefix() + ["apt-get", "install", "-y"] + packages,
                            timeout=3600, env=env)
    elif mgr in ("dnf", "yum"):
        rc, _, stderr = run(sudo_prefix() + [mgr, "install", "-y"] + packages, timeout=3600)
    elif mgr == "pacman":
        rc, _, stderr = run(sudo_prefix() + ["pacman", "-Sy", "--noconfirm"] + packages,
                            timeout=3600)
    elif mgr == "zypper":
        rc, _, stderr = run(sudo_prefix() + ["zypper", "--non-interactive", "install"] + packages,
                            timeout=3600)
    else:  # apk
        rc, _, stderr = run(sudo_prefix() + ["apk", "add"] + packages, timeout=3600)

    if rc != 0:
        err(f"PostgreSQL install failed: {stderr.strip()[:300]}")
        return False
    ok("PostgreSQL installed")
    return True

def initialize_cluster():
    """Create the data directory on distros that don't do it during install."""
    setup = shutil.which("postgresql-setup")
    if setup:
        run(sudo_prefix() + [setup, "--initdb"], timeout=900)
        return
    initdb = find_pg_binary("initdb")
    data_dir = "/var/lib/postgres/data"      # Arch layout
    if not initdb or not os.path.isdir(os.path.dirname(data_dir)):
        return
    try:
        already_initialised = bool(os.listdir(data_dir))
    except OSError:
        already_initialised = False          # missing dir, initdb will create it
    if not already_initialised:
        run(sudo_prefix() + ["-u", "postgres", initdb, "-D", data_dir], timeout=900)

def start_postgres(port):
    """Bring the server up with whatever init system this host uses."""
    if shutil.which("systemctl"):
        for unit in ("postgresql", f"postgresql@{_debian_cluster_unit()}", "postgresql.service"):
            if not unit or unit.endswith("@"):
                continue
            run(sudo_prefix() + ["systemctl", "enable", unit], timeout=120)
            rc, _, _ = run(sudo_prefix() + ["systemctl", "start", unit], timeout=180)
            if rc == 0:
                time.sleep(2)
                if postgres_is_up("127.0.0.1", port):
                    return True
    if shutil.which("service"):
        run(sudo_prefix() + ["service", "postgresql", "start"], timeout=180)
        time.sleep(2)
        if postgres_is_up("127.0.0.1", port):
            return True
    if shutil.which("pg_ctlcluster"):
        import glob
        for conf in sorted(glob.glob("/etc/postgresql/*/main")):
            version = conf.split("/")[3]
            run(sudo_prefix() + ["pg_ctlcluster", version, "main", "start"], timeout=180)
        time.sleep(2)
        if postgres_is_up("127.0.0.1", port):
            return True
    if shutil.which("brew"):
        run(["brew", "services", "start", "postgresql"], timeout=180)
        time.sleep(3)
        return postgres_is_up("127.0.0.1", port)
    return False

def _debian_cluster_unit():
    import glob
    for conf in sorted(glob.glob("/etc/postgresql/*/main")):
        parts = conf.split("/")
        return f"{parts[3]}-main"
    return ""

def ensure_postgres(host, port):
    """Make sure a PostgreSQL server is installed and accepting connections."""
    if postgres_is_up(host, port):
        ok(f"PostgreSQL is running on {host}:{port}")
        return True

    if host not in ("127.0.0.1", "localhost", "::1") and not host.startswith("/"):
        err(f"cannot reach PostgreSQL at {host}:{port}")
        info("that is a remote host, start it there, or point the wizard somewhere else")
        return False

    server_installed = bool(find_pg_binary("postgres") or find_pg_binary("initdb")
                            or os.path.isdir("/etc/postgresql"))
    if not server_installed:
        warn("PostgreSQL is not installed on this machine")
        if not ask_yes("Install PostgreSQL now?", True):
            err("PostgreSQL is required, cannot continue")
            return False
        if not can_escalate():
            err("installing packages needs root (install sudo, or re-run as root)")
            return False
        prime_sudo("install PostgreSQL")
        if not install_postgres():
            return False
        initialize_cluster()
    else:
        warn("PostgreSQL is installed but not accepting connections, starting it")

    if not can_escalate():
        err("starting the database needs root (install sudo, or re-run as root)")
        return False
    prime_sudo("start the PostgreSQL service")
    if start_postgres(port):
        ok(f"PostgreSQL is running on {host}:{port}")
        return True

    err(f"PostgreSQL still is not reachable on {host}:{port}")
    info("check the server log, then re-run this wizard")
    return False


# --------------------------------------------------------------------------- #
# 3. A privileged way into the server
# --------------------------------------------------------------------------- #
# The old wizard gave up the moment psycopg2 could not authenticate with the
# credentials typed at the prompt, which is exactly the state a fresh server is
# in, because the role does not exist yet. Instead we try every channel a real
# operator would try, in order, and keep the first that works.

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$")

def valid_ident(name):
    """Accept only plain identifiers, keeps names out of SQL injection range."""
    return bool(name) and bool(_IDENT_RE.match(name))

def qident(name):
    return '"' + str(name).replace('"', '""') + '"'

def qlit(value):
    return "'" + str(value).replace("'", "''") + "'"


class SQLChannel:
    """Something that can run SQL against the server with real privilege."""
    label = "?"
    privileged = False

    def query(self, sql, db=None):
        raise NotImplementedError

    def execute(self, sql, db=None):
        raise NotImplementedError

    def probe(self):
        """Confirm the channel works and record whether it can create things."""
        rows = self.query("SELECT current_user, "
                          "(SELECT rolsuper OR rolcreatedb FROM pg_roles "
                          " WHERE rolname = current_user)")
        self.privileged = bool(rows and str(rows[0][1]).lower() in ("true", "t", "1"))
        return str(rows[0][0]) if rows else ""


class Psycopg2Channel(SQLChannel):
    def __init__(self, host, port, user, password, maintenance_db="postgres"):
        self.host, self.port = host, int(port)
        self.user, self.password = user, password
        self.maintenance_db = maintenance_db
        where = host if host.startswith("/") else f"{host}:{port}"
        self.label = f"psycopg2 as {user}@{where}"

    def _connect(self, db=None):
        import psycopg2
        conn = psycopg2.connect(
            dbname=db or self.maintenance_db, user=self.user,
            password=self.password, host=self.host, port=self.port,
            connect_timeout=CONNECT_TIMEOUT,
        )
        conn.autocommit = True      # CREATE DATABASE cannot run inside a transaction
        return conn

    def query(self, sql, db=None):
        conn = self._connect(db)
        try:
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall() if cur.description else []
            cur.close()
            return [list(r) for r in rows]
        finally:
            conn.close()

    def execute(self, sql, db=None):
        conn = self._connect(db)
        try:
            cur = conn.cursor()
            cur.execute(sql)
            cur.close()
        finally:
            conn.close()


class PsqlChannel(SQLChannel):
    """Shell out to psql, the route that works when TCP auth does not.

    On Debian-likes the postgres superuser is reachable only as the `postgres`
    OS user over the local socket (peer authentication), so `sudo -u postgres
    psql` is the canonical bootstrap path and psycopg2 simply cannot get there.
    """

    def __init__(self, psql, port, user="postgres", host=None, sudo_user=None,
                 maintenance_db="postgres"):
        self.psql, self.port = psql, int(port)
        self.user, self.host = user, host
        self.sudo_user = sudo_user
        self.maintenance_db = maintenance_db
        via = f"sudo -u {sudo_user} " if sudo_user else ""
        self.label = f"{via}psql as {user}"

    def _full_cmd(self, sql, db=None):
        cmd = []
        if self.sudo_user:
            # -n so a missing sudo ticket fails immediately instead of blocking
            # the wizard on a hidden password prompt.
            cmd += ["sudo", "-n", "-u", self.sudo_user]
        cmd += [self.psql, "-X", "-q", "-A", "-t", "-F", SEP,
                "-v", "ON_ERROR_STOP=1"]
        if self.host:
            cmd += ["-h", self.host]
        cmd += ["-p", str(self.port), "-U", self.user, "-d", db or self.maintenance_db,
                "-c", sql]
        return cmd

    def _run(self, sql, db=None):
        env = dict(os.environ, PGCONNECT_TIMEOUT=str(CONNECT_TIMEOUT))
        env.pop("PGPASSWORD", None)
        # cwd=/ so psql as another user never trips over an unreadable directory
        rc, stdout, stderr = run(self._full_cmd(sql, db), timeout=120, cwd="/", env=env)
        if rc != 0:
            raise RuntimeError((stderr or stdout).strip()[:400] or f"psql exited {rc}")
        return stdout

    def query(self, sql, db=None):
        out = self._run(sql, db)
        rows = []
        for line in out.splitlines():
            if line == "":
                continue
            rows.append(line.split(SEP))
        return rows

    def execute(self, sql, db=None):
        self._run(sql, db)


def _candidate_channels(cfg):
    """Every plausible way in, cheapest and most likely first."""
    host, port = cfg["db_host"], cfg["db_port"]
    user, password = cfg["db_user"], cfg["db_password"]
    os_user = getpass.getuser()
    psql = find_psql()

    # Only probe a local socket directory that genuinely has a server on it,
    # otherwise every extra candidate costs a full connect timeout.
    hosts = [host]
    sock_dir = socket_dir_has_server(port)
    if sock_dir and sock_dir not in hosts:
        hosts.append(sock_dir)

    seen = set()
    channels = []

    def add(channel):
        if channel.label not in seen:
            seen.add(channel.label)
            channels.append(channel)

    # 1. exactly what the operator configured
    if user:
        add(Psycopg2Channel(host, port, user, password))
    # 2. the superuser over the local socket, trust/peer auth on a fresh cluster
    for h in hosts:
        for u in (user, "postgres", os_user):
            if not u:
                continue
            add(Psycopg2Channel(h, port, u, ""))
            if password:
                add(Psycopg2Channel(h, port, u, password))
    # 3. psql as the postgres OS user (the Debian bootstrap path).
    #    Only when sudo will not stop to ask for a password, discovery must
    #    never block. obtain_admin_channel() primes sudo and retries if needed.
    if psql:
        if sudo_is_cached():
            add(PsqlChannel(psql, port, "postgres", sudo_user="postgres"))
        add(PsqlChannel(psql, port, "postgres"))
        add(PsqlChannel(psql, port, os_user))
    return channels

def discover_admin_channel(cfg, quiet=False):
    """Find a channel that can inspect the server; prefer one that can create."""
    best = None
    for channel in _candidate_channels(cfg):
        try:
            who = channel.probe()
        except Exception:
            continue
        if channel.privileged:
            if not quiet:
                ok(f"connected as {_c(who, '1;37')} via {channel.label}")
            return channel
        if best is None:
            best = (channel, who)
    if best:
        channel, who = best
        if not quiet:
            ok(f"connected as {_c(who, '1;37')} via {channel.label}")
            warn(f"'{who}' cannot create databases or roles, "
                 "you can still pick an existing database")
        return channel
    return None

def obtain_admin_channel(cfg):
    """Get a privileged channel, asking for superuser credentials if needed."""
    head("Connecting to PostgreSQL")
    step("looking for a way in …")
    channel = discover_admin_channel(cfg)
    if channel:
        return channel

    warn("none of the automatic connection methods worked")
    info("that usually means the server only accepts password logins")
    if have_sudo() and not sudo_is_cached() and sys.stdin.isatty():
        info("trying again with sudo, you may be asked for your password")
        if prime_sudo("reach PostgreSQL as the 'postgres' system user"):
            channel = discover_admin_channel(cfg)
            if channel:
                return channel

    for attempt in range(3):
        info("enter a PostgreSQL account that may create databases "
             "(usually 'postgres')")
        su_user = ask("PostgreSQL superuser", "postgres")
        su_pass = ask_secret(f"Password for {su_user} (blank if none)", allow_empty=True)
        probe = Psycopg2Channel(cfg["db_host"], cfg["db_port"], su_user, su_pass)
        try:
            who = probe.probe()
            ok(f"connected as {_c(who, '1;37')} via {probe.label}")
            return probe
        except Exception as e:
            err(f"could not connect: {_short_pg_error(e)}")
            if attempt < 2 and not ask_yes("Try different credentials?", True):
                break
    return None

def _short_pg_error(exc):
    text = str(exc).strip().replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    return text[:200] or exc.__class__.__name__


# --------------------------------------------------------------------------- #
# 4. Database inventory and provisioning
# --------------------------------------------------------------------------- #
SYSTEM_DATABASES = {"postgres", "template0", "template1"}

def list_databases(channel):
    rows = channel.query(
        "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname")
    return [r[0] for r in rows]

def count_tables(channel, dbname):
    try:
        rows = channel.query(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema = 'public'", db=dbname)
        return int(rows[0][0]) if rows else 0
    except Exception:
        return -1        # not readable by this channel

def database_exists(channel, name):
    rows = channel.query(f"SELECT 1 FROM pg_database WHERE datname = {qlit(name)}")
    return bool(rows)

def role_exists(channel, name):
    rows = channel.query(f"SELECT 1 FROM pg_roles WHERE rolname = {qlit(name)}")
    return bool(rows)

def ensure_role(channel, name, password):
    """Create the login role, or reset its password if it is already there."""
    if role_exists(channel, name):
        channel.execute(f"ALTER ROLE {qident(name)} WITH LOGIN PASSWORD {qlit(password)}")
        ok(f"role '{name}' updated")
    else:
        channel.execute(
            f"CREATE ROLE {qident(name)} WITH LOGIN PASSWORD {qlit(password)}")
        ok(f"role '{name}' created")

def create_database(channel, name, owner):
    if database_exists(channel, name):
        warn(f"database '{name}' already exists, reusing it")
    else:
        channel.execute(f"CREATE DATABASE {qident(name)} OWNER {qident(owner)}")
        ok(f"database '{name}' created")

def grant_database_access(channel, dbname, role):
    """Give the app role everything it needs inside its own database."""
    statements = [
        (f"GRANT ALL PRIVILEGES ON DATABASE {qident(dbname)} TO {qident(role)}", None),
        (f"GRANT ALL ON SCHEMA public TO {qident(role)}", dbname),
        (f"ALTER SCHEMA public OWNER TO {qident(role)}", dbname),
        (f"GRANT ALL ON ALL TABLES IN SCHEMA public TO {qident(role)}", dbname),
        (f"GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {qident(role)}", dbname),
    ]
    for sql, db in statements:
        try:
            channel.execute(sql, db=db)
        except Exception:
            pass        # best effort, the owner already has most of these

def generate_password(length=24):
    alphabet = ("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
                "-_=+.:")     # no quotes, no '#', safe in .env and in SQL literals
    return "".join(secrets.choice(alphabet) for _ in range(length))

def ask_identifier(prompt, default=""):
    while True:
        value = ask(prompt, default)
        if valid_ident(value):
            return value
        warn("use letters, digits and underscores; must start with a letter")

def ask_new_password(subject):
    """Prompt for a password, offering to generate a strong one."""
    while True:
        pw = ask_secret(f"{subject} (blank = generate a strong one)", allow_empty=True)
        if not pw:
            pw = generate_password()
            ok("generated a strong password (saved to .env)")
            return pw
        if len(pw) < 8:
            warn("please use at least 8 characters")
            continue
        again = ask_secret("Repeat the password", allow_empty=True)
        if again != pw:
            warn("the passwords did not match, try again")
            continue
        return pw

def choose_database(channel, cfg):
    """Show what is on the server and let the operator pick or create."""
    head("Choose the database to use")
    try:
        databases = list_databases(channel)
    except Exception as e:
        err(f"could not list databases: {_short_pg_error(e)}")
        databases = []

    usable = [d for d in databases if d not in SYSTEM_DATABASES]

    if not usable:
        warn("there are no application databases on this server yet")
        info("the server is running, it simply has nothing but its own system "
             "databases on it")
        print()
        info("a new database will be created for the panel, with the tables it needs")
        return create_database_flow(channel, cfg)

    print(f"  Found {_c(len(usable), '1;37')} database(s) on this server:\n")
    for i, name in enumerate(usable, 1):
        tables = count_tables(channel, name)
        if tables < 0:
            note = "  (no read access)"
        elif tables == 0:
            note = "  (empty)"
        else:
            note = f"  ({tables} tables)"
        marker = _c("  ← currently configured", "1;32") if name == cfg["db_name"] else ""
        print(f"    {_c(str(i), '1;37')}. {name}{_c(note, '2;37')}{marker}")
    print(f"    {_c('n', '1;37')}. create a NEW database for the panel")
    print()

    while True:
        choice = ask("Select a database by number, or 'n' to create one", "n").lower()
        if choice == "n":
            return create_database_flow(channel, cfg)
        if choice.isdigit() and 1 <= int(choice) <= len(usable):
            return use_existing_database_flow(channel, cfg, usable[int(choice) - 1])
        warn(f"enter a number between 1 and {len(usable)}, or 'n'")


def create_database_flow(channel, cfg):
    head("Create a new database")
    if not channel.privileged:
        err("the connected account is not allowed to create databases or roles")
        info("re-run the wizard and supply a superuser (usually 'postgres')")
        sys.exit(1)

    name = ask_identifier("Database name", cfg["db_name"] or "argus")
    role = ask_identifier("Database user (owner) to create", name)
    password = ask_new_password(f"Password for database user '{role}'")

    step(f"creating role '{role}' …")
    ensure_role(channel, role, password)
    step(f"creating database '{name}' …")
    create_database(channel, name, role)
    grant_database_access(channel, name, role)

    cfg["db_name"], cfg["db_user"], cfg["db_password"] = name, role, password
    return cfg


def use_existing_database_flow(channel, cfg, name):
    head(f"Using existing database '{name}'")
    info("the panel needs a login role with access to this database")
    role = ask_identifier("Database user the panel should connect as",
                          cfg["db_user"] or name)

    exists = False
    try:
        exists = role_exists(channel, role)
    except Exception:
        pass

    if exists:
        info(f"role '{role}' already exists")
        if cfg["db_password"] and not ask_yes(f"Set a new password for '{role}'?", False):
            password = cfg["db_password"]
        else:
            password = ask_new_password(f"Password for '{role}'")
            if channel.privileged:
                ensure_role(channel, role, password)
            else:
                warn("cannot change the password, not a privileged account")
    else:
        if not channel.privileged:
            err(f"role '{role}' does not exist and this account cannot create it")
            sys.exit(1)
        password = ask_new_password(f"Password for new database user '{role}'")
        ensure_role(channel, role, password)

    if channel.privileged:
        grant_database_access(channel, name, role)

    cfg["db_name"], cfg["db_user"], cfg["db_password"] = name, role, password
    return cfg


# --------------------------------------------------------------------------- #
# 5. Schema, the tables this panel actually runs on
# --------------------------------------------------------------------------- #
# Mirrors what DB.py and panel.py expect at runtime. Everything is IF NOT EXISTS
# so running the wizard again over a live database is safe.

SCHEMA = (
    ("admin accounts", (
        """CREATE TABLE IF NOT EXISTS admin (
               id            SERIAL PRIMARY KEY,
               username      VARCHAR(100) UNIQUE NOT NULL,
               password_hash TEXT NOT NULL
           )""",
    )),
    ("account recovery codes", recovery.SCHEMA),
    ("system settings", (
        """CREATE TABLE IF NOT EXISTS system_settings (
               key        VARCHAR(40) PRIMARY KEY,
               value      TEXT NOT NULL,
               updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
    )),
    ("panel event log", (
        """CREATE TABLE IF NOT EXISTS management_log (
               id       BIGSERIAL PRIMARY KEY,
               ts       TIMESTAMPTZ  NOT NULL DEFAULT now(),
               level    VARCHAR(10)  NOT NULL DEFAULT 'INFO',
               category VARCHAR(32)  NOT NULL DEFAULT 'SYSTEM',
               actor    VARCHAR(100) NOT NULL DEFAULT '',
               ip       VARCHAR(64)  NOT NULL DEFAULT '',
               action   VARCHAR(200) NOT NULL DEFAULT '',
               target   VARCHAR(200) NOT NULL DEFAULT '',
               detail   TEXT         NOT NULL DEFAULT '',
               status   VARCHAR(20)  NOT NULL DEFAULT 'ok'
           )""",
        "CREATE INDEX IF NOT EXISTS idx_mgmt_log_ts    ON management_log (ts DESC)",
        "CREATE INDEX IF NOT EXISTS idx_mgmt_log_cat   ON management_log (category)",
        "CREATE INDEX IF NOT EXISTS idx_mgmt_log_level ON management_log (level)",
    )),
    ("admin audit trail", (
        """CREATE TABLE IF NOT EXISTS admin_action (
               id             SERIAL PRIMARY KEY,
               admin_username TEXT NOT NULL,
               action_type    VARCHAR(40) NOT NULL,
               target_tid     TEXT,
               ip_address     TEXT,
               notes          TEXT,
               created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
           )""",
        "CREATE INDEX IF NOT EXISTS idx_admin_action_time ON admin_action (created_at)",
    )),
    ("SSH access log", (
        """CREATE TABLE IF NOT EXISTS ssh_log (
               id          SERIAL PRIMARY KEY,
               ts          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               event_type  VARCHAR(32) NOT NULL,
               ip          TEXT,
               username    TEXT,
               fingerprint TEXT,
               session_pid INTEGER,
               port        INTEGER,
               auth_method VARCHAR(20),
               details     TEXT,
               event_hash  TEXT
           )""",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_ssh_log_hash ON ssh_log (event_hash)",
        "CREATE INDEX IF NOT EXISTS idx_ssh_log_ts ON ssh_log (ts DESC)",
        "CREATE INDEX IF NOT EXISTS idx_ssh_log_ip ON ssh_log (ip)",
    )),
    ("web login log", (
        """CREATE TABLE IF NOT EXISTS web_login_log (
               id             SERIAL PRIMARY KEY,
               ts             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               ip             TEXT NOT NULL,
               username       TEXT,
               success        BOOLEAN NOT NULL,
               user_agent     TEXT,
               tried_password TEXT,
               details        TEXT,
               fp_hash        TEXT,
               fingerprint    TEXT
           )""",
        "CREATE INDEX IF NOT EXISTS idx_wll_ts ON web_login_log (ts DESC)",
        "CREATE INDEX IF NOT EXISTS idx_wll_ip ON web_login_log (ip)",
        "CREATE INDEX IF NOT EXISTS idx_wll_fp ON web_login_log (fp_hash)",
    )),
    ("brute-force blocks", (
        """CREATE TABLE IF NOT EXISTS web_fp_block (
               fp_hash       TEXT PRIMARY KEY,
               fail_count    INTEGER NOT NULL DEFAULT 0,
               first_fail    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               last_fail     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               blocked_until TIMESTAMP,
               last_ip       TEXT,
               sample        TEXT,
               note          TEXT
           )""",
        """CREATE TABLE IF NOT EXISTS web_login_block (
               ip            TEXT PRIMARY KEY,
               fail_count    INTEGER NOT NULL DEFAULT 0,
               first_fail    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               last_fail     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               blocked_until TIMESTAMP,
               note          TEXT
           )""",
    )),
    ("panel sessions", (
        """CREATE TABLE IF NOT EXISTS web_session_log (
               id         SERIAL PRIMARY KEY,
               session_id TEXT UNIQUE NOT NULL,
               username   TEXT NOT NULL,
               ip         TEXT NOT NULL,
               user_agent TEXT,
               login_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               expires_at TIMESTAMP NOT NULL,
               logout_at  TIMESTAMP,
               status     VARCHAR(16) NOT NULL DEFAULT 'active'
           )""",
        "CREATE INDEX IF NOT EXISTS idx_wsl_session ON web_session_log (session_id)",
        "CREATE INDEX IF NOT EXISTS idx_wsl_login   ON web_session_log (login_at DESC)",
    )),
    ("HTTP access log", (
        """CREATE TABLE IF NOT EXISTS http_access_log (
               id            BIGSERIAL PRIMARY KEY,
               ts            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
               ip            TEXT NOT NULL,
               method        VARCHAR(10) NOT NULL,
               path          TEXT NOT NULL,
               query         TEXT,
               status_code   INTEGER NOT NULL,
               duration_ms   INTEGER,
               user_agent    TEXT,
               referer       TEXT,
               authed_user   TEXT,
               response_body TEXT,
               content_type  TEXT,
               response_size INTEGER
           )""",
        "CREATE INDEX IF NOT EXISTS idx_hal_ts   ON http_access_log (ts DESC)",
        "CREATE INDEX IF NOT EXISTS idx_hal_ip   ON http_access_log (ip)",
        "CREATE INDEX IF NOT EXISTS idx_hal_path ON http_access_log (path)",
    )),
    ("SSH access settings", ssh_vault.SCHEMA),
    ("panel staff accounts", panel_users.SCHEMA),
    ("firewall blocks and port rules", firewall.SCHEMA),
    ("Cloudflare tunnels and their forwards", cloudflare_tunnel.SCHEMA),
    ("mailboxes, messages and mail settings", mail.SCHEMA),
)

# Columns added to tables that may predate this version of the schema. Each is
# individually idempotent, so an upgrade over an existing database is safe.
SCHEMA_UPGRADES = (
    "ALTER TABLE IF EXISTS ssh_log         ADD COLUMN IF NOT EXISTS event_hash TEXT",
    "ALTER TABLE IF EXISTS web_login_log   ADD COLUMN IF NOT EXISTS tried_password TEXT",
    "ALTER TABLE IF EXISTS web_login_log   ADD COLUMN IF NOT EXISTS fp_hash TEXT",
    "ALTER TABLE IF EXISTS web_login_log   ADD COLUMN IF NOT EXISTS fingerprint TEXT",
    "ALTER TABLE IF EXISTS web_login_block ADD COLUMN IF NOT EXISTS note TEXT",
    "ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_body TEXT",
    "ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS content_type TEXT",
    "ALTER TABLE IF EXISTS http_access_log ADD COLUMN IF NOT EXISTS response_size INTEGER",
)

SCHEMA_TABLES = ("admin", "admin_recovery_code", "system_settings",
                 "management_log", "admin_action", "ssh_log", "web_login_log",
                 "web_fp_block", "web_login_block", "web_session_log",
                 "http_access_log", "ssh", "panel_user",
                 "fw_block", "fw_rule", "cf_tunnel", "cf_route",
                 "mail_config", "mail_box", "mail_message")


def app_connection(cfg):
    """A psycopg2 connection using the panel's own credentials."""
    import psycopg2
    conn = psycopg2.connect(
        dbname=cfg["db_name"], user=cfg["db_user"], password=cfg["db_password"],
        host=cfg["db_host"], port=int(cfg["db_port"]), connect_timeout=CONNECT_TIMEOUT,
    )
    conn.autocommit = True
    return conn

def verify_app_connection(cfg):
    """(True, '') when the panel's own credentials work end to end."""
    try:
        conn = app_connection(cfg)
        conn.close()
        return True, ""
    except Exception as e:
        return False, _short_pg_error(e)

def apply_schema(cfg, channel=None):
    """Create every table the panel needs, reporting each group as it lands."""
    head("Building the panel's table structure")

    try:
        conn = app_connection(cfg)
        runner = ("app", conn)
    except Exception as e:
        if channel is None:
            err(f"cannot reach the database to create tables: {_short_pg_error(e)}")
            return False
        info("using the privileged connection to build the schema")
        runner = ("channel", channel)

    failures = []

    def execute(sql):
        if runner[0] == "app":
            cur = runner[1].cursor()
            try:
                cur.execute(sql)
            finally:
                cur.close()
        else:
            runner[1].execute(sql, db=cfg["db_name"])

    try:
        for label, statements in SCHEMA:
            try:
                for sql in statements:
                    execute(sql)
                ok(f"{label}")
            except Exception as e:
                failures.append((label, _short_pg_error(e)))
                err(f"{label}: {_short_pg_error(e)}")
        for sql in SCHEMA_UPGRADES:
            try:
                execute(sql)
            except Exception:
                pass        # column already present, or table owned elsewhere
    finally:
        if runner[0] == "app":
            runner[1].close()

    if failures:
        err(f"{len(failures)} schema step(s) failed")
        return False

    created = verify_schema(cfg, channel)
    ok(f"{len(created)}/{len(SCHEMA_TABLES)} tables present in "
       f"'{cfg['db_name']}': {', '.join(created)}")
    return len(created) == len(SCHEMA_TABLES)

def verify_schema(cfg, channel=None):
    """Return the schema tables that actually exist in the target database."""
    sql = ("SELECT table_name FROM information_schema.tables "
           "WHERE table_schema = 'public' ORDER BY table_name")
    try:
        conn = app_connection(cfg)
        try:
            cur = conn.cursor()
            cur.execute(sql)
            present = {r[0] for r in cur.fetchall()}
            cur.close()
        finally:
            conn.close()
    except Exception:
        if channel is None:
            return []
        try:
            present = {r[0] for r in channel.query(sql, db=cfg["db_name"])}
        except Exception:
            return []
    return [t for t in SCHEMA_TABLES if t in present]


# --------------------------------------------------------------------------- #
# 6. pg_hba repair, only when the panel's own login is refused
# --------------------------------------------------------------------------- #
def repair_pg_hba(channel, cfg):
    """Prepend a rule allowing the panel's role to log in over loopback TCP.

    Only reached when the role exists with the right password but the host-based
    auth rules still reject it. First matching line wins in pg_hba.conf, so the
    new rules go in ahead of everything else.
    """
    try:
        rows = channel.query("SHOW hba_file")
        hba = rows[0][0]
    except Exception as e:
        warn(f"could not locate pg_hba.conf: {_short_pg_error(e)}")
        return False

    rule_v4 = f"host    {cfg['db_name']}    {cfg['db_user']}    127.0.0.1/32    scram-sha-256"
    rule_v6 = f"host    {cfg['db_name']}    {cfg['db_user']}    ::1/128         scram-sha-256"
    marker = "# --- added by Argus management.py ---"

    step(f"adding a login rule to {hba}")
    if not can_escalate():
        warn("editing pg_hba.conf needs root, skipping")
        return False
    prime_sudo("edit pg_hba.conf")

    rc, current, _ = run(sudo_prefix() + ["cat", hba], timeout=60)
    if rc != 0:
        warn("could not read pg_hba.conf")
        return False
    if rule_v4 in current:
        info("the rule is already there")
        return True

    lines = current.splitlines()
    insert_at = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.split()[0] in ("local", "host", "hostssl", "hostnossl"):
            insert_at = i
            break
    updated = lines[:insert_at] + [marker, rule_v4, rule_v6, ""] + lines[insert_at:]

    run(sudo_prefix() + ["cp", hba, hba + ".argus.bak"], timeout=60)
    rc, _, stderr = run(sudo_prefix() + ["tee", hba], timeout=60,
                        stdin_input="\n".join(updated) + "\n")
    if rc != 0:
        warn(f"could not write pg_hba.conf: {stderr.strip()[:200]}")
        return False
    try:
        channel.execute("SELECT pg_reload_conf()")
    except Exception:
        run(sudo_prefix() + ["systemctl", "reload", "postgresql"], timeout=120)
    ok(f"pg_hba.conf updated (backup at {hba}.argus.bak)")
    time.sleep(1)
    return True


def ensure_app_login(cfg, channel):
    """Guarantee the panel's own credentials can actually reach the database."""
    working, reason = verify_app_connection(cfg)
    if working:
        ok(f"the panel can log in as '{cfg['db_user']}' to '{cfg['db_name']}'")
        return True

    warn(f"the panel could not log in yet: {reason}")
    if channel and channel.privileged and "authentication" in reason.lower():
        if repair_pg_hba(channel, cfg):
            working, reason = verify_app_connection(cfg)
            if working:
                ok("login works after fixing pg_hba.conf")
                return True

    # A password mismatch on a pre-existing role is the other common cause.
    if channel and channel.privileged:
        step("resetting the role's password to what we just configured")
        try:
            ensure_role(channel, cfg["db_user"], cfg["db_password"])
            working, reason = verify_app_connection(cfg)
            if working:
                ok("login works after resetting the password")
                return True
        except Exception as e:
            warn(f"password reset failed: {_short_pg_error(e)}")

    err(f"the panel still cannot log in: {reason}")
    return False


# --------------------------------------------------------------------------- #
# 7. Panel admin account
# --------------------------------------------------------------------------- #
def _hash_pw(password):
    """Must stay byte-identical to DB._hash_pw or logins will not verify."""
    return recovery.hash_password(password)

def existing_admins(cfg):
    try:
        conn = app_connection(cfg)
        try:
            cur = conn.cursor()
            cur.execute("SELECT username, password_hash FROM admin ORDER BY id")
            rows = cur.fetchall()
            cur.close()
            return [(r[0], r[1]) for r in rows]
        finally:
            conn.close()
    except Exception:
        return []

def setup_admin_account(cfg):
    """Create (or reset) the account used to log into the panel's web UI."""
    head("Panel administrator account")
    current = existing_admins(cfg)
    if current:
        info(f"existing panel admin(s): {', '.join(u for u, _ in current)}")
        if not ask_yes("Create or reset an administrator account now?", True):
            return True
    else:
        info("this is the username and password you will use to sign in to the panel")

    username = ask_identifier("Admin username", "admin")
    while True:
        password = ask_secret("Admin password")
        problem = recovery.password_problem(password, username)
        if problem:
            warn(problem.lower().rstrip("."))
            continue
        if ask_secret("Repeat the admin password") != password:
            warn("the passwords did not match, try again")
            continue
        break

    try:
        conn = app_connection(cfg)
        try:
            cur = conn.cursor()
            cur.execute(
                """INSERT INTO admin (username, password_hash) VALUES (%s, %s)
                   ON CONFLICT (username)
                   DO UPDATE SET password_hash = EXCLUDED.password_hash""",
                (username, _hash_pw(password)))
            # A leftover admin/admin from a previous bootstrap is a live hole.
            weak = _hash_pw("admin")
            cur.execute(
                "DELETE FROM admin WHERE username = 'admin' "
                "AND password_hash = %s AND username <> %s", (weak, username))
            removed = cur.rowcount
            cur.close()
        finally:
            conn.close()
    except Exception as e:
        err(f"could not save the admin account: {_short_pg_error(e)}")
        return False

    ok(f"admin account '{username}' is ready")
    if removed:
        ok("removed the insecure default 'admin'/'admin' account")

    issue_recovery_codes(cfg, username)
    return True


def issue_recovery_codes(cfg, username, announce=True):
    """Mint a fresh set of single-use codes and write them to .recovery."""
    try:
        conn = app_connection(cfg)
        try:
            recovery.ensure_table(conn)
            codes = recovery.generate_codes()
            recovery.replace_codes(conn, username, codes)
        finally:
            conn.close()
        path = recovery.write_recovery_file(HERE, username, codes)
    except Exception as e:
        err(f"could not create recovery codes: {_short_pg_error(e)}")
        return None

    if announce:
        head("Account recovery codes")
        info("if you ever forget the password, these get you back in, one use each")
        for i, code in enumerate(codes, 1):
            print(f"    {_c(str(i) + '.', '2;37')}  {_c(recovery.format_code(code), '1;37')}")
        print()
        ok(f"saved to {path} (owner-only, 0600)")
        info(f"only the hashes are stored in the database, {recovery.RECOVERY_FILENAME}")
        info("is the sole plaintext copy, so keep it somewhere safe and offline")
        warn("anyone holding a code can take over the panel")
    return codes


# --------------------------------------------------------------------------- #
# 8. Config persistence
# --------------------------------------------------------------------------- #
def _env_file_value(key, default=""):
    if not os.path.exists(ENV_PATH):
        return default
    try:
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except Exception:
        pass
    return default

def load_config():
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                cfg.update(json.load(f))
        except Exception as e:
            warn(f"could not read deploy.json: {e}")
    if not cfg.get("db_password"):
        cfg["db_password"] = os.environ.get("DB_PASSWORD",
                                            _env_file_value("DB_PASSWORD", ""))
    cfg["db_port"] = int(cfg.get("db_port") or 5432)
    cfg["port"] = int(cfg.get("port") or 8080)
    return cfg

def save_config(cfg):
    """deploy.json keeps the non-secret choices; .env keeps the DB password."""
    public = {k: v for k, v in cfg.items() if k != "db_password"}
    with open(CONFIG_PATH, "w") as f:
        json.dump(public, f, indent=2)
        f.write("\n")
    write_env(cfg)
    os.chmod(CONFIG_PATH, 0o644)

def write_env(cfg):
    lines = [
        "# Written by management.py, keep out of version control.",
        f"DB_NAME={cfg['db_name']}",
        f"DB_USER={cfg['db_user']}",
        f"DB_PASSWORD={cfg['db_password']}",
        f"DB_HOST={cfg['db_host']}",
        f"DB_PORT={cfg['db_port']}",
        "",
    ]
    with open(ENV_PATH, "w") as f:
        f.write("\n".join(lines))
    os.chmod(ENV_PATH, stat.S_IRUSR | stat.S_IWUSR)      # 0600


# --------------------------------------------------------------------------- #
# 9. Network binding
# --------------------------------------------------------------------------- #
def port_available(host, port):
    """True when we could bind here ourselves."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, int(port)))
        return True
    except OSError:
        return False

def choose_binding(cfg):
    head("Where should the panel listen?")
    info("127.0.0.1 keeps the panel private behind nginx; "
         "0.0.0.0 exposes it on every interface")
    cfg["host"] = ask("Bind host", cfg["host"])

    while True:
        raw = ask("Port to serve on", cfg["port"])
        try:
            port = int(raw)
        except ValueError:
            warn("a port must be a number")
            continue
        if not 1 <= port <= 65535:
            warn("a port must be between 1 and 65535")
            continue
        if port < 1024 and not is_root():
            warn(f"port {port} needs root; the service can use it but a "
                 "foreground run cannot")
        if not port_available(cfg["host"], port):
            # Our own service holding the port is fine, we restart it later.
            if service_is_active():
                info(f"port {port} is currently held by {SERVICE_NAME} "
                     "(it will be restarted)")
                cfg["port"] = port
                break
            warn(f"port {port} is already in use by something else")
            if not ask_yes("Use it anyway?", False):
                continue
        cfg["port"] = port
        break

    # A sub-path is only correct when a reverse proxy mounts the panel under one.
    # Setting it for a plain local install makes the browser ask for
    # "<base>/static/dash.css", which this app does not serve at the root, the
    # page then loads unstyled. Say so plainly instead of just showing a default.
    print()
    info("URL base path, leave this EMPTY unless a reverse proxy mounts the")
    info("panel under a sub-path of a bigger site (e.g. example.com/management).")
    info("For a normal or local install, empty is what you want.")
    while True:
        base = ask("URL base path (press Enter for none)", cfg["base_path"]).strip()
        if not base or base == "/":
            cfg["base_path"] = ""
            break
        if not base.startswith("/"):
            base = "/" + base
        base = base.rstrip("/")
        shown = "127.0.0.1" if cfg["host"] in ("0.0.0.0", "::") else cfg["host"]
        warn(f"the panel will only answer on http://{shown}:{cfg['port']}{base}/")
        info(f"plain http://{shown}:{cfg['port']}/ will redirect there")
        if ask_yes(f"Keep the base path '{base}'?", False):
            cfg["base_path"] = base
            break
        info("cleared, leaving the base path empty")
        cfg["base_path"] = ""
        break
    return cfg


# --------------------------------------------------------------------------- #
# 10. systemd service
# --------------------------------------------------------------------------- #
def systemd_available():
    return shutil.which("systemctl") is not None and os.path.isdir("/run/systemd/system")

def service_is_active():
    if not shutil.which("systemctl"):
        return False
    rc, out, _ = run(["systemctl", "is-active", SERVICE_NAME], timeout=30)
    return out.strip() == "active"

def build_unit(cfg):
    python = python_for_service()
    return f"""[Unit]
Description=Argus Management, Server Management Panel (FastAPI)
Documentation=https://github.com/Nahom-digital/argus-management
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={HERE}
ExecStart={python} {os.path.join(HERE, 'management.py')} --serve
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

def write_unit(cfg):
    unit = build_unit(cfg)
    try:
        with open(UNIT_PATH, "w") as f:
            f.write(unit)
        return True
    except (PermissionError, OSError) as e:
        if e.errno not in (errno.EACCES, errno.EPERM):
            err(f"could not write {UNIT_PATH}: {e}")
            return False

    if not can_escalate():
        err(f"writing {UNIT_PATH} needs root (install sudo, or re-run as root)")
        return False
    prime_sudo("install the systemd service")
    rc, _, stderr = run(sudo_prefix() + ["tee", UNIT_PATH], timeout=60, stdin_input=unit)
    if rc != 0:
        detail = stderr.strip().splitlines()
        if any("password" in line or "terminal is required" in line for line in detail):
            err("installing a system service needs root, and sudo could not ask "
                "for your password here")
            info("re-run it yourself with:")
            print(_c("      sudo python3 management.py --service", "1;37"))
        else:
            err(f"could not write {UNIT_PATH}: {(detail or [''])[-1][:200]}")
        return False
    return True

def install_service(cfg, start=True):
    """Install, enable and (optionally) start the systemd unit."""
    head("Installing the background service")

    if not systemd_available():
        err("systemd is not available on this host")
        info("run the panel in the foreground instead:  python3 management.py --serve")
        return False

    if not write_unit(cfg):
        return False
    ok(f"wrote {UNIT_PATH}")

    run(sudo_prefix() + ["systemctl", "daemon-reload"], timeout=120)
    rc, _, stderr = run(sudo_prefix() + ["systemctl", "enable", SERVICE_NAME], timeout=120)
    if rc != 0:
        warn(f"could not enable the service: {stderr.strip()[:200]}")
    else:
        ok(f"{SERVICE_NAME} will start automatically on boot")

    if not start:
        return True

    step("starting the service …")
    rc, _, stderr = run(sudo_prefix() + ["systemctl", "restart", SERVICE_NAME], timeout=180)
    if rc != 0:
        err(f"could not start the service: {stderr.strip()[:200]}")
        info(f"look at the log:  journalctl -u {SERVICE_NAME} -n 50 --no-pager")
        return False

    # Confirm it is genuinely up rather than crash-looping.
    host, port = cfg["host"], int(cfg["port"])
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    for _ in range(20):
        time.sleep(0.5)
        if service_is_active() and port_is_open(probe_host, port, timeout=1):
            ok(f"{SERVICE_NAME} is active and listening")
            return True
    if service_is_active():
        warn(f"{SERVICE_NAME} is active but nothing is listening on port {port} yet")
        info(f"check the log:  journalctl -u {SERVICE_NAME} -n 50 --no-pager")
        return True

    err(f"{SERVICE_NAME} failed to stay running")
    rc, out, _ = run(["journalctl", "-u", SERVICE_NAME, "-n", "20", "--no-pager"], timeout=60)
    if out.strip():
        print(out.strip())
    return False

def announce_service(cfg):
    base = cfg.get("base_path", "") or "/"
    host = cfg["host"]
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print()
    print(_c(f"  ► Your management panel is running on port {cfg['port']}", "1;32"))
    print(_c(f"    http://{shown}:{cfg['port']}{base}", "1;37"))
    print()
    info("it runs in the background and starts again on boot")
    info(f"status:   systemctl status {SERVICE_NAME}")
    info(f"restart:  systemctl restart {SERVICE_NAME}")
    info(f"stop:     systemctl stop {SERVICE_NAME}")
    info(f"logs:     journalctl -u {SERVICE_NAME} -f")
    print()


# --------------------------------------------------------------------------- #
# 11. --upgrade: pull the latest code from GitHub and restart
# --------------------------------------------------------------------------- #
def git(*args, timeout=600):
    return run(["git", "-C", HERE] + list(args), timeout=timeout)

def is_git_checkout():
    rc, out, _ = git("rev-parse", "--is-inside-work-tree", timeout=60)
    return rc == 0 and out.strip() == "true"

def restart_service(cfg):
    """Restart the systemd unit and confirm it comes back listening."""
    if not systemd_available() or not os.path.exists(UNIT_PATH):
        warn(f"{SERVICE_NAME} is not installed as a service, nothing to restart")
        info("run it in the foreground with:  python3 management.py --serve")
        info("or install the service with:    python3 management.py --service")
        return False

    # The unit embeds the interpreter path; regenerate it if that has drifted
    # (e.g. the upgrade introduced a .venv that did not exist before).
    try:
        with open(UNIT_PATH) as f:
            if f.read() != build_unit(cfg):
                step("service definition changed, rewriting the unit")
                if write_unit(cfg):
                    run(sudo_prefix() + ["systemctl", "daemon-reload"], timeout=120)
    except OSError:
        pass

    step("restarting the service …")
    rc, _, stderr = run(sudo_prefix() + ["systemctl", "restart", SERVICE_NAME], timeout=180)
    if rc != 0:
        lines = stderr.strip().splitlines()
        if any("password" in ln or "terminal is required" in ln for ln in lines):
            err("restarting the service needs root, and sudo could not ask for "
                "your password here")
            info("the code is already updated, finish it with:")
            print(_c(f"      sudo systemctl restart {SERVICE_NAME}", "1;37"))
        else:
            err(f"could not restart {SERVICE_NAME}: {(lines or [''])[-1][:200]}")
            info(f"check the log:  journalctl -u {SERVICE_NAME} -n 50 --no-pager")
        return False

    host, port = cfg["host"], int(cfg["port"])
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    for _ in range(20):
        time.sleep(0.5)
        if service_is_active() and port_is_open(probe_host, port, timeout=1):
            ok(f"{SERVICE_NAME} is back up on port {port}")
            return True
    err(f"{SERVICE_NAME} did not come back on port {port}")
    info(f"check the log:  journalctl -u {SERVICE_NAME} -n 50 --no-pager")
    return False

def upgrade_mode():
    """`--upgrade`: git pull the latest code, refresh deps/schema, restart."""
    banner()
    head("Upgrading from GitHub")

    if not shutil.which("git"):
        err("git is not installed, cannot pull updates")
        return 1
    if not is_git_checkout():
        err(f"{HERE} is not a git checkout, so there is nothing to pull")
        info("this install was copied rather than cloned; re-clone it with:")
        info("  git clone https://github.com/Nahom-digital/argus-management.git")
        return 1

    rc, branch, _ = git("rev-parse", "--abbrev-ref", "HEAD", timeout=60)
    branch = branch.strip() or "main"
    rc, origin, _ = git("remote", "get-url", "origin", timeout=60)
    if rc != 0:
        err("this checkout has no 'origin' remote to pull from")
        return 1
    info(f"repository: {origin.strip()}")
    info(f"branch:     {branch}")

    # Never throw away work that is only on this machine.
    rc, dirty, _ = git("status", "--porcelain", timeout=120)
    tracked = [ln for ln in dirty.splitlines() if ln and not ln.startswith("??")]
    if tracked:
        err("there are uncommitted changes to tracked files:")
        for line in tracked[:10]:
            info("  " + line)
        info("commit or stash them, then run --upgrade again")
        return 1

    step("fetching from origin …")
    rc, _, stderr = git("fetch", "--prune", "origin")
    if rc != 0:
        err(f"git fetch failed: {stderr.strip()[:200]}")
        return 1

    rc, log, _ = git("log", "--oneline", f"HEAD..origin/{branch}", timeout=120)
    incoming = [ln for ln in log.splitlines() if ln.strip()]

    if not incoming:
        ok("already up to date, no new commits on origin")
        updated = False
    else:
        print(f"  {_c(len(incoming), '1;37')} new commit(s) to apply:")
        for line in incoming[:15]:
            info("  " + line)
        if len(incoming) > 15:
            info(f"  … and {len(incoming) - 15} more")
        step("pulling …")
        rc, _, stderr = git("pull", "--ff-only", "origin", branch)
        if rc != 0:
            err(f"fast-forward pull failed: {stderr.strip()[:200]}")
            info("your branch has diverged from origin; reconcile it by hand")
            return 1
        rc, after, _ = git("rev-parse", "--short", "HEAD", timeout=60)
        ok(f"code updated to {after.strip()}")
        updated = True

    # A new revision may have added dependencies or tables.
    if _missing_dependencies():
        ensure_python_deps()
    else:
        ok("dependencies already satisfied")

    # A new revision may also need more of the host than the last one did. This
    # is idempotent, so running it on every upgrade costs nothing when it is
    # already in place.
    if nginx_installed():
        ensure_nginx_stream()
    install_cloudflared()
    install_mail_prerequisites()

    cfg = load_config()
    if os.path.exists(CONFIG_PATH):
        working, reason = verify_app_connection(cfg)
        if working:
            missing_tables = [t for t in SCHEMA_TABLES
                              if t not in verify_schema(cfg)]
            if missing_tables:
                step(f"applying {len(missing_tables)} new table(s)")
                apply_schema(cfg)
            else:
                ok("database schema already up to date")
        else:
            warn(f"skipping the schema check, database unreachable: {reason}")
    else:
        warn("no deploy.json yet, run the setup wizard before serving")
        return 1

    head("Restarting")
    if not restart_service(cfg):
        return 1
    announce_service(cfg)
    return 0


# --------------------------------------------------------------------------- #
# 12. Run the panel
# --------------------------------------------------------------------------- #
def serve(cfg):
    """Run the FastAPI panel in this process (blocks until stopped)."""
    # Credentials must be in the environment BEFORE DB.py / panel.py import,
    # because DB.py reads DB_CONFIG at import time.
    os.environ["DB_NAME"] = str(cfg["db_name"])
    os.environ["DB_USER"] = str(cfg["db_user"])
    os.environ["DB_PASSWORD"] = str(cfg["db_password"])
    os.environ["DB_HOST"] = str(cfg["db_host"])
    os.environ["DB_PORT"] = str(cfg["db_port"])
    os.environ["MGMT_BASE"] = str(cfg.get("base_path", ""))

    # Service starts should heal themselves rather than crash on a missing import.
    if _missing_dependencies():
        ensure_python_deps()

    working, reason = verify_app_connection(cfg)
    if not working:
        err(f"database connection failed: {reason}")
        info("re-run the setup wizard to fix it:  python3 management.py")
        sys.exit(1)

    import uvicorn
    import panel                      # the FastAPI app

    host, port = cfg["host"], int(cfg["port"])
    if hasattr(panel, "SERVER_RUNTIME"):
        panel.SERVER_RUNTIME["host"], panel.SERVER_RUNTIME["port"] = host, port

    # keep the panel's own Config tab in sync with what we actually bound
    try:
        import DB
        DB.set_setting("management_host", host)
        DB.set_setting("management_port", port)
    except Exception:
        pass

    base = cfg.get("base_path", "") or "/"
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(_c(f"\n  ► Management panel is running on http://{shown}:{port}{base}", "1;32"))
    print(_c(f"    (bound to {host}:{port})\n", "2;37"))
    # uvicorn logs to stderr; flush ours first so the two stay in order when
    # stdout is a pipe or the journal rather than a terminal.
    sys.stdout.flush()
    uvicorn.run(panel.app, host=host, port=port, log_level="info")


def show_status():
    banner()
    cfg = load_config()
    head("Configuration")
    if os.path.exists(CONFIG_PATH):
        ok(f"deploy.json: {CONFIG_PATH}")
    else:
        warn("deploy.json does not exist, run the wizard first")
    info(f"database:  {cfg['db_user']}@{cfg['db_host']}:{cfg['db_port']}/{cfg['db_name']}")
    info(f"binding:   {cfg['host']}:{cfg['port']}{cfg.get('base_path') or ''}")
    info(f"python:    {python_for_service()}")

    head("Dependencies")
    missing = _missing_dependencies()
    if missing:
        warn("missing: " + ", ".join(m[0] for m in missing))
    else:
        ok("all Python dependencies present")

    head("Database")
    if not postgres_is_up(cfg["db_host"], cfg["db_port"]):
        err(f"no PostgreSQL server on {cfg['db_host']}:{cfg['db_port']}")
    else:
        working, reason = verify_app_connection(cfg)
        if working:
            ok(f"connected to '{cfg['db_name']}'")
            present = verify_schema(cfg)
            missing_tables = [t for t in SCHEMA_TABLES if t not in present]
            if missing_tables:
                warn(f"missing tables: {', '.join(missing_tables)}")
            else:
                ok(f"all {len(SCHEMA_TABLES)} panel tables present")
            admins = existing_admins(cfg)
            if admins:
                ok(f"admin account(s): {', '.join(u for u, _ in admins)}")
                try:
                    conn = app_connection(cfg)
                    try:
                        for username, _ in admins:
                            unused, total = recovery.remaining(conn, username)
                            if total == 0:
                                warn(f"'{username}' has no recovery codes, "
                                     "run:  python3 management.py --recovery-codes")
                            elif unused == 0:
                                warn(f"'{username}' has used all {total} recovery codes")
                            else:
                                ok(f"recovery codes for '{username}': "
                                   f"{unused} of {total} unused")
                    finally:
                        conn.close()
                except Exception:
                    pass
            else:
                warn("no admin account configured")
        else:
            err(f"cannot connect: {reason}")

    head("Service")
    if not systemd_available():
        info("systemd is not available on this host")
    elif not os.path.exists(UNIT_PATH):
        info(f"{SERVICE_NAME} is not installed, "
             "run:  python3 management.py --service")
    else:
        rc, out, _ = run(["systemctl", "is-active", SERVICE_NAME], timeout=30)
        state = out.strip() or "unknown"
        (ok if state == "active" else warn)(f"{SERVICE_NAME}: {state}")
    print()


def recovery_codes_mode():
    """`--recovery-codes`: mint a fresh set, retiring whatever came before."""
    banner()
    if not os.path.exists(CONFIG_PATH):
        err("no deploy.json yet, run the setup wizard first")
        info("  python3 management.py")
        return 1
    cfg = load_config()
    if _missing_dependencies():
        ensure_python_deps()

    working, reason = verify_app_connection(cfg)
    if not working:
        err(f"database connection failed: {reason}")
        return 1

    admins = existing_admins(cfg)
    if not admins:
        err("there is no panel admin account yet, run the wizard first")
        return 1

    if len(admins) == 1:
        username = admins[0][0]
    else:
        info("accounts: " + ", ".join(u for u, _ in admins))
        username = ask("Which account", admins[0][0])
        if username not in [u for u, _ in admins]:
            err(f"no such account: {username}")
            return 1

    warn(f"this retires every existing recovery code for '{username}'")
    if not ask_yes("Generate a new set now?", True):
        info("nothing changed")
        return 0

    return 0 if issue_recovery_codes(cfg, username) else 1


# --------------------------------------------------------------------------- #
# 13. The wizard
# --------------------------------------------------------------------------- #
def wizard():
    banner()
    cfg = load_config()

    # --- 1. dependencies (may re-exec into .venv and never return) ---------- #
    ensure_python_deps()

    # --- 2. the database server -------------------------------------------- #
    head("PostgreSQL server")
    cfg["db_host"] = ask("PostgreSQL host", cfg["db_host"])
    while True:
        try:
            cfg["db_port"] = int(ask("PostgreSQL port", cfg["db_port"]))
            break
        except ValueError:
            warn("a port must be a number")
    if not ensure_postgres(cfg["db_host"], cfg["db_port"]):
        sys.exit(1)
    if install_nginx():   # best-effort, only the Proxy page in Config needs it
        ensure_nginx_stream()
    install_cloudflared()  # best-effort too, for the Cloudflare Tunnel card
    install_mail_prerequisites()   # Docker and Compose, for receiving mail

    # --- 3. a privileged connection ---------------------------------------- #
    channel = obtain_admin_channel(cfg)
    if channel is None:
        err("could not get into PostgreSQL with any method")
        info("check that the server accepts connections, then re-run the wizard")
        sys.exit(1)

    # --- 4. pick or build the database ------------------------------------- #
    cfg = choose_database(channel, cfg)

    # --- 5. make sure the panel itself can log in -------------------------- #
    head("Verifying the panel's database login")
    if not ensure_app_login(cfg, channel):
        info("fix the PostgreSQL authentication rules, then re-run the wizard")
        sys.exit(1)

    # --- 6. tables ---------------------------------------------------------- #
    if not apply_schema(cfg, channel):
        err("the schema is incomplete, the panel would not run correctly")
        sys.exit(1)

    # --- 7. the admin account ---------------------------------------------- #
    if not setup_admin_account(cfg):
        sys.exit(1)

    # --- 8. binding --------------------------------------------------------- #
    cfg = choose_binding(cfg)

    save_config(cfg)
    ok(f"saved {os.path.basename(CONFIG_PATH)} and .env")

    # --- 9. service or foreground ------------------------------------------ #
    head("Run as a background service?")
    info("as a service the panel keeps running after you close this terminal, "
         "and starts again on boot")
    if ask_yes("Install and run the panel as a service now?", True):
        if install_service(cfg, start=True):
            announce_service(cfg)
            sys.exit(0)
        err("the service could not be installed")
        if not ask_yes("Run in the foreground instead?", True):
            sys.exit(1)

    print()
    warn("running in the FOREGROUND, this terminal now owns the panel")
    info("if you exit here (Ctrl+C) or close this terminal, the panel stops too")
    info("to run it as a background service instead, run:")
    print(_c("      python3 management.py --service", "1;37"))
    sys.stdout.flush()
    serve(cfg)


def service_mode():
    """`--service`: install + start the service from an existing config, then exit."""
    banner()
    if not os.path.exists(CONFIG_PATH):
        err("no deploy.json yet, run the setup wizard first")
        info("  python3 management.py")
        sys.exit(1)
    cfg = load_config()
    ensure_python_deps()

    working, reason = verify_app_connection(cfg)
    if not working:
        err(f"database connection failed: {reason}")
        info("re-run the setup wizard:  python3 management.py")
        sys.exit(1)
    ok(f"database '{cfg['db_name']}' reachable")

    if install_service(cfg, start=True):
        announce_service(cfg)
        sys.exit(0)
    sys.exit(1)


USAGE = """
  Argus Management, deployment front door

    python3 management.py             run the setup wizard, then start the panel
    python3 management.py --service   install + start the systemd service, then exit
    python3 management.py --upgrade   git pull the latest code, then restart the service
    python3 management.py --serve     run in the foreground from deploy.json
    python3 management.py --status    show configuration / database / service status
    python3 management.py --recovery-codes
                                      mint a new set of single-use recovery codes
    python3 management.py --setup     force the wizard even without a TTY
    python3 management.py --help      this message
"""

def main():
    args = set(sys.argv[1:])

    if args & {"-h", "--help", "help"}:
        print(USAGE)
        return
    if "--status" in args:
        show_status()
        return
    if "--recovery-codes" in args:
        sys.exit(recovery_codes_mode())
    if "--upgrade" in args:
        sys.exit(upgrade_mode())
    if "--service" in args:
        service_mode()
        return
    if "--serve" in args:
        serve(load_config())
        return
    if "--setup" in args or sys.stdin.isatty():
        wizard()
        return
    # non-interactive with no flag: behave like the service
    serve(load_config())


if __name__ == "__main__":
    main()
