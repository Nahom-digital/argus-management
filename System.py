# System.py, Server management engine for the MainApp dashboard.
#
# Supplies the "Server" section of the Main.py control panel:
#   * static device / OS information (hostname, kernel, CPU model, RAM, boot time…)
#   * hardware sensors and network identity (CPU temperature, fans, battery, IPs)
#   * live telemetry (CPU %, per-core, RAM, swap, disk, network in/out bandwidth)
#   * a root terminal (shell command execution with a persistent working dir)
#   * the FastAPI launch configuration (host / port) persisted in system_settings
#
# Loader contract (see mainapp-architecture): Main.py auto-imports every top-level
# .py file as a module, so this file MUST NOT do DB or network work at import time.
# Heavy deps (psutil) and DB are imported lazily inside the functions.

import os
import sys
import time
import shlex
import platform
import shutil
import subprocess
import logging
from datetime import datetime

# --- Server launch defaults ---------------------------------------------------
# nginx owns :80 and reverse-proxies to us, so the app binds loopback only:
# nothing but nginx can reach it, and the origin port is never exposed.
# The LIVE values live in system_settings (server_host / server_port) and are
# editable from the dashboard Configuration tab, so these literals are only the
# first-run fallback. Public host of the production box is kept here as a
# convenience option for the UI.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 55
PUBLIC_HOST = "207.180.29.181"

# Fallback port used only if binding the configured port fails at startup (e.g.
# port 80 without root on a dev box), keeps the dashboard reachable regardless.
FALLBACK_PORT = 4041

_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Network bandwidth sampling ----------------------------------------------
# psutil only gives cumulative byte counters; we turn them into a live rate by
# remembering the previous sample and dividing the delta by the elapsed time.
_net_last = {"t": None, "sent": 0, "recv": 0}

# --- Terminal state -----------------------------------------------------------
# A web terminal needs a working directory that survives between commands so
# `cd` behaves like a real shell. Plain `cd` commands are resolved in-process;
# everything else runs in this directory.
_term_cwd = _PROJECT_DIR


def _human_bytes(n):
    """Format a byte count as a compact human string (e.g. 15.6 GB)."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024.0
    return f"{n:.1f} EB"


def static_info():
    """Slow-changing device + OS facts. Cheap enough to call on demand."""
    import psutil

    uname = platform.uname()
    boot = psutil.boot_time()
    try:
        freq = psutil.cpu_freq()
        max_mhz = round(freq.max) if freq and freq.max else None
    except Exception:
        max_mhz = None

    vm = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("/")
        disk_total = disk.total
    except Exception:
        disk_total = 0

    temp = cpu_temp()
    fans, fan_not_reported = fan_speeds()
    batt = battery()
    priv = private_ip() or {}

    # Best-effort human-readable CPU model name.
    cpu_model = uname.processor or platform.processor() or ""
    if not cpu_model and os.path.exists("/proc/cpuinfo"):
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        except Exception:
            pass

    return {
        "hostname": uname.node,
        "os": f"{uname.system} {uname.release}",
        "os_full": platform.platform(),
        "distro": _distro_name(),
        "kernel": uname.version,
        "arch": uname.machine,
        "cpu_model": cpu_model or "Unknown CPU",
        "cpu_cores_physical": psutil.cpu_count(logical=False) or 0,
        "cpu_cores_logical": psutil.cpu_count(logical=True) or 0,
        "cpu_max_mhz": max_mhz,
        "cpu_temp_c": round(temp["c"], 1) if temp else None,
        "cpu_temp_label": temp["label"] if temp else "",
        "ram_total": vm.total,
        "ram_total_h": _human_bytes(vm.total),
        "disk_total": disk_total,
        "disk_total_h": _human_bytes(disk_total),
        "fans": fans,
        "fan_not_reported": fan_not_reported,
        "battery": batt,
        "private_ip": priv.get("ip", ""),
        "private_ip_iface": priv.get("iface", ""),
        "public_ip": public_ip(),
        "python": platform.python_version(),
        "boot_time": datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M:%S"),
        "uptime_seconds": int(time.time() - boot),
        "process_user": _current_user(),
        "process_pid": os.getpid(),
        "is_root": _is_root(),
    }


def _distro_name():
    """Pretty Linux distro name from /etc/os-release, falling back to platform."""
    path = "/etc/os-release"
    if os.path.exists(path):
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
    return platform.system()


def _current_user():
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "unknown")


def _is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# --- Hardware sensors and network identity ------------------------------------
# Laptop-class facts the Server card can show when the machine has them, and
# stays quiet about when it does not: CPU temperature, fan tachometers,
# battery charge, and the two addresses the box answers to. Everything here is
# a read of sysfs, /proc or the routing table, so it never changes state and
# degrades to None on hardware that does not publish it.

FAN_NOT_REPORTED = 0xFFFF   # a ThinkPad EC reports this when the tach is unreadable

_CACHE_PUBLIC_IP_TTL = 600  # seconds an answer stays fresh; the address rarely moves
_public_ip = {"value": "", "t": 0.0, "busy": False}


def _read_int(path):
    """Integer contents of a sysfs file, or None when unreadable or not a number."""
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def cpu_temp(hwmon="/sys/class/hwmon", thermal="/sys/class/thermal"):
    """Best available CPU temperature as {"c": celsius, "label": source}.

    hwmon chips that sit on the CPU itself (coretemp, k10temp, zenpower,
    cpu_thermal) win over acpitz, the generic ACPI zone that reads a little
    off the die. thermal_zone entries are the last resort for boards that
    publish nothing in hwmon. None when no sensor is readable.
    """
    try:
        chips = sorted(os.listdir(hwmon))
    except OSError:
        chips = []
    ranked = []
    for chip in chips:
        root = os.path.join(hwmon, chip)
        name = ""
        try:
            with open(os.path.join(root, "name")) as f:
                name = f.read().strip()
        except OSError:
            pass
        low = name.lower()
        if low in ("coretemp", "k10temp", "zenpower", "cpu_thermal"):
            ranked.append((0, root, name))
        elif low == "acpitz":
            ranked.append((1, root, name))
    for _, root, name in sorted(ranked):
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            entries = []
        for entry in entries:
            if not (entry.startswith("temp") and entry.endswith("_input")):
                continue
            val = _read_int(os.path.join(root, entry))
            if val is not None and 0 < val < 150000:
                return {"c": val / 1000.0, "label": name or entry}
    try:
        zones = sorted(os.listdir(thermal))
    except OSError:
        zones = []
    for zone in zones:
        if not zone.startswith("thermal_zone"):
            continue
        val = _read_int(os.path.join(thermal, zone, "temp"))
        if val is not None and 0 < val < 150000:
            label = ""
            try:
                with open(os.path.join(thermal, zone, "type")) as f:
                    label = f.read().strip()
            except OSError:
                pass
            return {"c": val / 1000.0, "label": label or zone}
    return None


def _thinkpad_fan_rpm(path="/proc/acpi/ibm/fan"):
    """Fan speed in RPM from the ThinkPad ACPI interface, or None."""
    try:
        with open(path) as f:
            for line in f:
                key, _, val = line.partition(":")
                if key.strip() == "speed" and val.strip().isdigit():
                    return int(val.strip())
    except OSError:
        pass
    return None


def fan_speeds(hwmon="/sys/class/hwmon", thinkpad="/proc/acpi/ibm/fan"):
    """([{"rpm", "label", "percent"}, ...], not_reported) for every fan.

    Every fan*_input in hwmon is used; its fan*_label names it and its
    fan*_max turns the reading into a percent when the sensor publishes one.
    The ThinkPad ACPI tachometer is the fallback for models without a hwmon
    fan attribute. not_reported is True when a sensor is present but answers
    only with the 0xFFFF sentinel, which is a hardware fault, not a speed.
    """
    readings = []
    not_reported = False
    try:
        chips = sorted(os.listdir(hwmon))
    except OSError:
        chips = []
    for chip in chips:
        root = os.path.join(hwmon, chip)
        name = ""
        try:
            with open(os.path.join(root, "name")) as f:
                name = f.read().strip()
        except OSError:
            pass
        try:
            entries = [e for e in sorted(os.listdir(root))
                       if e.startswith("fan") and e.endswith("_input")]
        except OSError:
            entries = []
        for entry in entries:
            rpm = _read_int(os.path.join(root, entry))
            if rpm is None:
                continue
            if rpm == FAN_NOT_REPORTED:
                not_reported = True
                continue
            stem = entry[: -len("_input")]          # fan1_input -> fan1
            label = name or "fan"
            try:
                with open(os.path.join(root, stem + "_label")) as f:
                    label = f.read().strip() or label
            except OSError:
                pass
            percent = None
            max_rpm = _read_int(os.path.join(root, stem + "_max"))
            if max_rpm is not None and max_rpm > 0:
                percent = min(100, round(100.0 * rpm / max_rpm))
            readings.append({"rpm": rpm, "label": label, "percent": percent})
    if not readings:
        rpm = _thinkpad_fan_rpm(thinkpad)
        if rpm is not None:
            if rpm == FAN_NOT_REPORTED:
                not_reported = True
            else:
                readings.append({"rpm": rpm, "label": "thinkpad", "percent": None})
    return readings, not_reported


def battery(base="/sys/class/power_supply"):
    """{"percent": int, "state": str} of the first battery, or None."""
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return None
    for entry in entries:
        if not entry.upper().startswith("BAT"):
            continue
        root = os.path.join(base, entry)
        cap = _read_int(os.path.join(root, "capacity"))
        if cap is None:
            continue
        state = ""
        try:
            with open(os.path.join(root, "status")) as f:
                state = f.read().strip()
        except OSError:
            pass
        return {"percent": cap, "state": state}
    return None


def private_ip():
    """{"ip": str, "iface": str} the default route would carry, or None.

    No packet is sent: the UDP connect only asks the kernel which local
    address a route to the outside would use, which is the one a remote peer
    sees as the source. The interface name is looked up through psutil when
    it is available.
    """
    import socket
    ip = None
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
    except OSError:
        ip = None
    finally:
        if sock:
            sock.close()
    if not ip:
        return None
    iface = ""
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if getattr(addr, "family", None) == socket.AF_INET and addr.address == ip:
                    iface = name
                    break
            if iface:
                break
    except Exception:
        pass
    return {"ip": ip, "iface": iface}


def _fetch_public_ip(timeout=7):
    """Ask an outside service for this server's public address, or None.

    Behind NAT the local interfaces cannot answer this, so it has to come
    from beyond the router. Cloudflare's trace echo is tried first, then two
    plain IP echoes, and the first parseable answer wins.
    """
    import urllib.request
    attempts = (
        ("https://cloudflare.com/cdn-cgi/trace", True),
        ("https://api.ipify.org", False),
        ("https://ifconfig.me/ip", False),
    )
    for url, parse_trace in attempts:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "argus-management"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read(4096).decode("utf-8", "replace")
        except Exception:
            continue
        if parse_trace:
            for line in text.splitlines():
                if line.startswith("ip="):
                    return line[3:].strip() or None
            continue
        text = text.strip()
        if text:
            return text
    return None


def public_ip():
    """Last known public IP, refreshed in the background when it goes stale.

    The lookup leaves the machine and can take seconds, far too long to sit
    inside a request handler, so a request only ever reads the cache and the
    first caller after the TTL kicks off a daemon thread to refill it.
    """
    import threading
    cache = _public_ip
    fresh = cache["value"] and time.time() - cache["t"] < _CACHE_PUBLIC_IP_TTL
    if not fresh and not cache["busy"]:
        cache["busy"] = True

        def refresh():
            try:
                found = _fetch_public_ip()
                if found:
                    cache["value"] = found
                    cache["t"] = time.time()
            finally:
                cache["busy"] = False

        threading.Thread(target=refresh, daemon=True).start()
    return cache["value"]


def live_stats():
    """Fast-changing telemetry sampled on every poll. Non-blocking psutil calls
    (cpu_percent uses interval=None → instantaneous since the last call)."""
    import psutil

    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    try:
        disk = psutil.disk_usage("/")
    except Exception:
        disk = None

    # Network rate: delta of cumulative counters since the previous sample.
    net = psutil.net_io_counters()
    now = time.time()
    rate_in = rate_out = 0.0
    if _net_last["t"] is not None:
        dt = now - _net_last["t"]
        if dt > 0:
            rate_out = max(0.0, (net.bytes_sent - _net_last["sent"]) / dt)
            rate_in = max(0.0, (net.bytes_recv - _net_last["recv"]) / dt)
    _net_last.update(t=now, sent=net.bytes_sent, recv=net.bytes_recv)

    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = 0.0

    boot = psutil.boot_time()

    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "cpu_per_core": psutil.cpu_percent(interval=None, percpu=True),
        "ram": {
            "total": vm.total, "used": vm.used, "available": vm.available,
            "percent": vm.percent, "used_h": _human_bytes(vm.used),
            "total_h": _human_bytes(vm.total),
        },
        "swap": {
            "total": sm.total, "used": sm.used, "percent": sm.percent,
            "used_h": _human_bytes(sm.used), "total_h": _human_bytes(sm.total),
        },
        "disk": {
            "total": disk.total if disk else 0,
            "used": disk.used if disk else 0,
            "percent": disk.percent if disk else 0,
            "used_h": _human_bytes(disk.used) if disk else "0 B",
            "total_h": _human_bytes(disk.total) if disk else "0 B",
        } if disk else {"total": 0, "used": 0, "percent": 0, "used_h": "0 B", "total_h": "0 B"},
        "net": {
            "rate_in": rate_in, "rate_out": rate_out,
            "rate_in_h": _human_bytes(rate_in) + "/s",
            "rate_out_h": _human_bytes(rate_out) + "/s",
            "total_in": net.bytes_recv, "total_out": net.bytes_sent,
            "total_in_h": _human_bytes(net.bytes_recv),
            "total_out_h": _human_bytes(net.bytes_sent),
        },
        "load": {"1": round(load1, 2), "5": round(load5, 2), "15": round(load15, 2)},
        "processes": len(psutil.pids()),
        "uptime_seconds": int(time.time() - boot),
        "ts": now,
    }


def run_command(cmd, timeout=30):
    """Execute a shell command for the dashboard root terminal and return its
    output. A `cd` to a directory is resolved in-process so the working directory
    persists across calls, like a real interactive shell.

    Runs with the privileges of the Main.py process, launch the server as root
    (the production box) for true root-terminal access. Admin-gated in Main.py.
    """
    global _term_cwd
    cmd = (cmd or "").strip()
    if not cmd:
        return {"stdout": "", "stderr": "", "returncode": 0, "cwd": _term_cwd}

    # Handle a bare `cd` (or `cd <dir>`) by updating the persistent cwd directly,
    # so subsequent commands run from the new location.
    if cmd == "cd" or cmd.startswith("cd ") and "&&" not in cmd and "|" not in cmd and ";" not in cmd:
        target = cmd[2:].strip() or os.path.expanduser("~")
        target = os.path.expanduser(target)
        new_dir = target if os.path.isabs(target) else os.path.normpath(os.path.join(_term_cwd, target))
        if os.path.isdir(new_dir):
            _term_cwd = new_dir
            return {"stdout": "", "stderr": "", "returncode": 0, "cwd": _term_cwd}
        return {"stdout": "", "stderr": f"cd: no such directory: {target}\n",
                "returncode": 1, "cwd": _term_cwd}

    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            cwd=_term_cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "cwd": _term_cwd,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Command timed out after {timeout}s\n",
                "returncode": 124, "cwd": _term_cwd}
    except Exception as e:
        return {"stdout": "", "stderr": f"{type(e).__name__}: {e}\n",
                "returncode": 1, "cwd": _term_cwd}


def terminal_cwd():
    return _term_cwd


# --- Interactive PTY terminal -------------------------------------------------
# run_command() above is the legacy one-shot model (one command -> one response),
# which cannot host interactive programs (a REPL, top, vim, the Claude CLI) because
# there is no controlling tty and no persistent process. PtySession spawns a real
# login shell attached to a pseudo-terminal so the browser (xterm.js over a
# WebSocket in Main.py) behaves like an actual terminal: streaming output, live
# keystrokes, window resize, job control. Runs with the Main.py process privileges.
# --- the limited terminal's boundary ---------------------------------------- #
#
# Dropping to the staff member's own OS account stops them writing anywhere they
# should not, but it does not stop them looking: `cd ..` walks out of their home
# into /home, /etc and the rest of the machine, which is not what "limited"
# means to the person who granted it.
#
# Two layers answer that. The outer one is bubblewrap: the shell runs in a mount
# namespace where the filesystem is read-only, /home holds nothing but their own
# directory, /root and the panel's own files are not there at all, and /tmp is
# private to the session. The inner one is a `cd` that refuses to leave their
# home, so the boundary is a sentence they can read rather than a directory that
# turns out to be empty.
#
# The inner layer alone would be decoration: `builtin cd ..` walks straight
# through it. It is there for the message. The namespace is the boundary.
JAIL_RC_DIR = "/run/argus"
JAIL_RC_PATH = os.path.join(JAIL_RC_DIR, "jail.bashrc")
JAIL_RC_IN_SANDBOX = "/tmp/.argus-jail.bashrc"

_JAIL_RC = """# Written by the Argus management panel for a limited terminal.
ARGUS_HOME="$HOME"

cd() {
  local dest
  if [ "$#" -eq 0 ]; then builtin cd -- "$ARGUS_HOME"; return; fi
  dest=$(builtin cd -- "$1" >/dev/null 2>&1 && pwd -P) || {
    printf 'cd: %s: no such directory\\n' "$1" >&2; return 1; }
  case "$dest" in
    "$ARGUS_HOME"|"$ARGUS_HOME"/*) builtin cd -- "$dest" ;;
    *) printf 'This terminal is limited to %s, so there is nowhere above it to go.\\n' \\
         "$ARGUS_HOME" >&2; return 1 ;;
  esac
}
readonly -f cd 2>/dev/null

# `builtin cd` goes around the function above, so every prompt checks where the
# shell actually is and walks it back. The sandbox already means there is nothing
# out there to find; this is what makes that obvious instead of puzzling.
argus_anchor() {
  case "$PWD" in
    "$ARGUS_HOME"|"$ARGUS_HOME"/*) ;;
    *) builtin cd -- "$ARGUS_HOME" ;;
  esac
}
PROMPT_COMMAND=argus_anchor
readonly PROMPT_COMMAND 2>/dev/null

PS1='\\[\\e[38;5;173m\\]\\u\\[\\e[0m\\]:\\[\\e[38;5;110m\\]\\w\\[\\e[0m\\]$ '
builtin cd -- "$ARGUS_HOME" 2>/dev/null
printf 'Limited terminal: %s is the top of your area.\\n' "$ARGUS_HOME"
"""


def jail_binary():
    return shutil.which("bwrap") or ""


def jail_available():
    return bool(jail_binary())


def write_jail_rc():
    """Put the shell profile somewhere only root can write.

    Not /tmp: the file is sourced by the jailed user's shell, so anybody who
    could write it would be running code in their session.
    """
    try:
        os.makedirs(JAIL_RC_DIR, mode=0o755, exist_ok=True)
        with open(JAIL_RC_PATH, "w", encoding="utf-8") as fh:
            fh.write(_JAIL_RC)
        os.chmod(JAIL_RC_PATH, 0o644)
        return JAIL_RC_PATH
    except OSError as e:
        logging.warning(f"could not write the limited shell profile: {e}")
        return ""


# The sandbox is built up rather than pared down: it starts empty, and the only
# things in it are the programs a shell needs, the configuration those programs
# read, and this person's own home directory. Nothing is bound that was not
# named here, which is why /root, every other home, /var and /opt are simply not
# in the filesystem the session sees.
_JAIL_SYSTEM = ("/usr", "/etc")
_JAIL_COMPAT = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")


def _jail_command(home, rc_path):
    """The argv that runs a shell inside the sandbox."""
    args = [
        jail_binary(),
        "--die-with-parent",
        "--unshare-uts", "--unshare-ipc", "--unshare-pid", "--unshare-cgroup-try",
        "--hostname", "argus",
    ]
    for path in _JAIL_SYSTEM:
        args += ["--ro-bind", path, path]
    # A usr-merged system has /bin as a symlink into /usr; an older one has a
    # real directory. Reproduce whichever this machine is, or nothing on PATH
    # resolves inside the sandbox.
    for path in _JAIL_COMPAT:
        if os.path.islink(path):
            args += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path):
            args += ["--ro-bind", path, path]
    args += [
        "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",                  # private, so nothing is shared out
        "--tmpfs", "/var",
        "--tmpfs", "/home",                 # every other home disappears
        "--bind", home, home,               # theirs, and the only writable place
    ]
    if rc_path:
        args += ["--ro-bind", rc_path, JAIL_RC_IN_SANDBOX]
    args += ["--chdir", home, "--"]
    if rc_path:
        args += ["bash", "--rcfile", JAIL_RC_IN_SANDBOX, "-i"]
    else:
        args += ["bash", "-i"]
    return args


class PtySession:
    """A login shell running on its own pseudo-terminal.

    spawn() forks a child whose stdin/stdout/stderr are the pty slave; the parent
    keeps the master fd (self.fd) for bidirectional streaming. The async WebSocket
    handler in Main.py reads/writes self.fd and forwards resize events.
    """

    SHELL = ["bash", "-il"]  # interactive login shell -> reads profile, shows prompt

    def __init__(self, cwd=None, env=None, run_as=None, jail=False):
        self.cwd = cwd or _PROJECT_DIR
        self.env = env
        self.run_as = run_as  # OS username to drop into, or None to stay as this process's user
        # Confine the session to run_as's home directory. Only meaningful with
        # run_as set: there is nothing to confine an admin's own shell to.
        self.jail = bool(jail and run_as)
        self.jailed = False   # whether the namespace actually took
        self.pid = None
        self.fd = None

    def _drop_privileges(self):
        """Runs in the forked child, still as root: switch to self.run_as before
        exec so a restricted panel user's terminal cannot touch anything the
        target OS account can't. Any failure here must never fall through to
        an exec as root, so every error path is a hard exit, not a return."""
        import pwd
        try:
            pw = pwd.getpwnam(self.run_as)
        except KeyError:
            os._exit(126)
        try:
            os.setgid(pw.pw_gid)
            os.initgroups(self.run_as, pw.pw_gid)
            os.setuid(pw.pw_uid)
        except OSError:
            os._exit(126)
        if os.getuid() == 0:
            os._exit(126)  # setuid silently no-op'd somehow, so refuse to run as root
        return pw.pw_dir

    def _jail_argv(self, home, rc_path):
        """The shell for a limited session, sandboxed if this machine can.

        Without bubblewrap the session still starts inside their own home with a
        `cd` that will not leave it, and their OS account's permissions still
        apply; what is missing is the part that hides the rest of the machine.
        """
        if jail_available():
            return _jail_command(home, rc_path)
        if rc_path:
            return ["bash", "--rcfile", rc_path, "-i"]
        return list(self.SHELL)

    def spawn(self, rows=24, cols=80):
        import pty
        # The profile has to be written before the fork, because after it the
        # child is the unprivileged user and /run/argus is root's to write.
        rc_path = write_jail_rc() if self.jail else ""
        self.jailed = bool(self.jail and jail_available())
        pid, fd = pty.fork()
        if pid == 0:
            # Child: this process becomes the shell. pty.fork() already made the
            # slave our controlling tty and wired std{in,out,err} to it.
            home = None
            if self.run_as:
                home = self._drop_privileges()
            chdir_target = home or self.cwd
            try:
                os.chdir(chdir_target)
            except Exception:
                try:
                    os.chdir(_PROJECT_DIR if not self.run_as else "/")
                except Exception:
                    pass
            env = dict(os.environ)
            env.update({
                "TERM": "xterm-256color",
                "COLORTERM": "truecolor",
                "LANG": env.get("LANG") or "C.UTF-8",
                # Make the project's bundled `claude` and vendored bins reachable.
                "PATH": _PROJECT_DIR + os.pathsep
                        + os.path.join(_PROJECT_DIR, "vendor", "bin") + os.pathsep
                        + env.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            })
            if self.run_as:
                env.update({"HOME": home or "/", "USER": self.run_as, "LOGNAME": self.run_as})
            if self.env:
                env.update(self.env)
            if self.jail:
                # The panel's own directory is not in the sandbox, so leaving it
                # on PATH would only produce commands that are not there.
                env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
                argv = self._jail_argv(home or "/", rc_path)
                try:
                    os.execvpe(argv[0], argv, env)
                except Exception:
                    os._exit(127)   # never fall back to an unconfined shell
            try:
                os.execvpe(self.SHELL[0], self.SHELL, env)
            except Exception:
                # execvpe failed (no bash?), fall back to plain sh, then bail.
                try:
                    os.execvpe("sh", ["sh", "-i"], env)
                except Exception:
                    os._exit(127)
        else:
            self.pid = pid
            self.fd = fd
            self.set_winsize(rows, cols)
            return self

    def set_winsize(self, rows, cols):
        """Tell the pty its window size so full-screen TUIs lay out correctly."""
        if self.fd is None:
            return
        try:
            import fcntl
            import termios
            import struct
            winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
        except Exception:
            pass

    def write(self, data):
        """Feed keystrokes (bytes) from the browser into the shell."""
        if self.fd is None:
            return
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        try:
            os.write(self.fd, data)
        except OSError:
            pass

    def read(self, max_bytes=65536):
        """Read available shell output (bytes). Empty bytes => shell exited."""
        if self.fd is None:
            return b""
        try:
            return os.read(self.fd, max_bytes)
        except OSError:
            return b""

    def alive(self):
        if self.pid is None:
            return False
        try:
            wpid, _ = os.waitpid(self.pid, os.WNOHANG)
            return wpid == 0
        except ChildProcessError:
            return False
        except Exception:
            return True

    def close(self):
        """Terminate the shell and release the pty."""
        import signal
        if self.pid:
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(self.pid, sig)
                except ProcessLookupError:
                    break
                except Exception:
                    pass
                try:
                    wpid, _ = os.waitpid(self.pid, os.WNOHANG)
                    if wpid != 0:
                        break
                except Exception:
                    break
        if self.fd is not None:
            try:
                os.close(self.fd)
            except Exception:
                pass
        self.fd = None
        self.pid = None


# =====================================================================
# --- Drill-down detail for the Server overview cards ---
# (top processes by CPU/mem, live network connections, and a read-only
#  file browser with guarded downloads). All admin-gated in Main.py.
# =====================================================================
def top_processes(by="cpu", limit=25):
    """Top processes by CPU or memory. CPU needs two samples, so we prime the
    per-process counters, briefly sleep, then read, hence offloaded to a worker
    thread by Main.py so the event loop never stalls."""
    import psutil
    procs = list(psutil.process_iter(["pid", "name", "username", "memory_percent", "cmdline"]))
    for p in procs:
        try:
            p.cpu_percent(None)   # prime
        except Exception:
            pass
    time.sleep(0.25)
    ncpu = psutil.cpu_count() or 1
    out = []
    for p in procs:
        try:
            info = p.info
            cpu = p.cpu_percent(None) / ncpu     # normalise to whole-machine %
            out.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "",
                "user": info.get("username") or "",
                "cpu": round(cpu, 1),
                "mem": round(info.get("memory_percent") or 0.0, 1),
                "cmd": (" ".join(info.get("cmdline") or []) or info.get("name") or "")[:160],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    key = "mem" if by == "mem" else "cpu"
    out.sort(key=lambda r: r[key], reverse=True)
    return {"by": key, "processes": out[:limit]}


def net_connections(limit=300):
    """Live inbound/outbound network connections with the owning process and port."""
    import psutil
    import socket
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "connections": []}
    name_cache = {}
    out = []
    for c in conns:
        pid = c.pid
        pname = ""
        if pid:
            if pid not in name_cache:
                try:
                    name_cache[pid] = psutil.Process(pid).name()
                except Exception:
                    name_cache[pid] = ""
            pname = name_cache[pid]
        out.append({
            "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
            "lport": c.laddr.port if c.laddr else 0,
            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
            "status": c.status or "",
            "pid": pid or "",
            "process": pname,
        })
    # listening sockets first, then by local port
    out.sort(key=lambda r: (r["status"] != "LISTEN", r["lport"]))
    return {"connections": out[:limit]}


# Files that must never be offered for download. Source code is blocked because
# the owner asked; the credential/key files are blocked because they are the
# actually catastrophic ones (e.g. the wallet-encryption key).
_DL_BLOCK_EXT = {".py", ".pyc", ".pyo", ".pyw", ".pem", ".key"}
_DL_BLOCK_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
                   ".wallet_secret", ".session_secret", "shadow", "gshadow"}

def _download_blocked(path):
    b = os.path.basename(path).lower()
    _, ext = os.path.splitext(b)
    if ext in _DL_BLOCK_EXT:
        return True
    if b in _DL_BLOCK_NAMES:
        return True
    if "secret" in b or b.startswith(".env"):
        return True
    return False


def _sandbox_root(root):
    """Normalize a sandbox prefix, or None for unrestricted access."""
    return os.path.realpath(root) if root else None


def _within(root, full):
    """True when an already-resolved path lies inside the sandbox.

    Both sides are passed through realpath before this runs, which is what
    stops a symlink planted inside the sandbox from pointing back out of it.
    """
    if not root:
        return True
    return full == root or full.startswith(root + os.sep)


def list_dir(path=None, root=None):
    """Read-only directory listing for the file browser. Folders first, then
    files; each file is flagged downloadable unless it is source or a secret.

    When root is set the listing is confined to that subtree: a path outside it
    is refused, and the parent link stops at the sandbox instead of walking up
    into the rest of the filesystem.
    """
    root = _sandbox_root(root)
    base = os.path.realpath(os.path.expanduser(path or root or "/"))
    if not _within(root, base):
        return {"error": "Outside your permitted area", "path": root,
                "parent": None, "entries": []}
    if not os.path.isdir(base):
        return {"error": "Not a directory", "path": base, "parent": None, "entries": []}
    try:
        names = os.listdir(base)
    except PermissionError:
        parent = os.path.dirname(base)
        return {"error": "Permission denied", "path": base,
                "parent": parent if _within(root, parent) and base != (root or "/") else None,
                "entries": []}
    entries = []
    for name in names:
        full = os.path.join(base, name)
        try:
            is_dir = os.path.isdir(full)
            size = 0 if is_dir else os.path.getsize(full)
            entries.append({
                "name": name,
                "path": full,
                "is_dir": is_dir,
                "size_h": "" if is_dir else _human_bytes(size),
                "downloadable": (not is_dir) and (not _download_blocked(full)),
                "deletable": (not is_dir) and (not _delete_blocked(full)),
            })
        except Exception:
            continue
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    top = root or "/"
    return {"path": base, "parent": (os.path.dirname(base) if base != top else None),
            "entries": entries}


def resolve_download(path, root=None):
    """Validate a download request. Returns (abspath, None) when allowed, or
    (None, reason) when the file is missing, blocked, or outside the sandbox."""
    root = _sandbox_root(root)
    full = os.path.realpath(os.path.expanduser(path or ""))
    if not _within(root, full):
        return None, "blocked"
    if not os.path.isfile(full):
        return None, "not_found"
    if _download_blocked(full):
        return None, "blocked"
    return full, None


# Whole subtrees a delete must never touch, even for an admin, because a misclick
# here is not recoverable the way an accidental download is.
_DELETE_DENY_PREFIXES = ("/etc", "/boot", "/sys", "/proc", "/dev", "/bin", "/sbin",
                          "/lib", "/lib64", "/usr", "/var/lib/postgresql")
_DELETE_DENY_EXACT = {"/", "/root", "/home"}

def _delete_blocked(path):
    if path in _DELETE_DENY_EXACT:
        return True
    for prefix in _DELETE_DENY_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return _download_blocked(path)  # never delete secrets, keys, or source either


def resolve_delete(path, root=None):
    """Validate a delete request. Directories are refused outright, this is
    a file browser and not rm -rf. Returns (abspath, None) or (None, reason)."""
    root = _sandbox_root(root)
    full = os.path.realpath(os.path.expanduser(path or ""))
    if not _within(root, full):
        return None, "blocked"
    if not os.path.exists(full):
        return None, "not_found"
    if os.path.isdir(full):
        return None, "is_directory"
    if _delete_blocked(full):
        return None, "blocked"
    return full, None


def delete_file(path, root=None):
    full, reason = resolve_delete(path, root=root)
    if reason:
        return False, reason
    try:
        os.remove(full)
        return True, None
    except OSError as e:
        return False, str(e)


# --- Server launch configuration ---------------------------------------------
def get_server_config():
    """Return the (host, port) Main.py should bind, read from system_settings
    with the bootstrap defaults as a fallback. Never raises, a DB hiccup just
    yields the defaults so the server can still start."""
    host, port = DEFAULT_HOST, DEFAULT_PORT
    try:
        import DB
        host = DB.get_setting("server_host", DEFAULT_HOST) or DEFAULT_HOST
        raw_port = DB.get_setting("server_port", DEFAULT_PORT)
        port = int(raw_port) if raw_port else DEFAULT_PORT
    except Exception as e:
        logging.warning(f"System.get_server_config falling back to defaults: {e}")
    return host, port


def set_server_config(host, port):
    """Persist the chosen host/port. Validates inputs and writes to
    system_settings. Returns the normalized (host, port). Raises ValueError on
    bad input. Takes effect on the next Main.py restart (uvicorn binds at boot)."""
    host = (host or "").strip()
    if not host:
        raise ValueError("Host is required")
    # Allow 0.0.0.0, localhost, or a dotted IPv4 / hostname.
    if not _valid_host(host):
        raise ValueError(f"Invalid host: {host}")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ValueError("Port must be a number")
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")

    import DB
    DB.set_setting("server_host", host)
    DB.set_setting("server_port", port)
    return host, port


def _valid_host(host):
    import re
    if host in ("0.0.0.0", "localhost", "127.0.0.1", "::", "::1"):
        return True
    # IPv4
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        return all(0 <= int(o) <= 255 for o in host.split("."))
    # Hostname
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+", host))


def server_config_view():
    """Convenience bundle for the Configuration tab UI."""
    host, port = get_server_config()
    return {
        "host": host,
        "port": port,
        "default_host": DEFAULT_HOST,
        "default_port": DEFAULT_PORT,
        "public_host": PUBLIC_HOST,
        "fallback_port": FALLBACK_PORT,
        "scheme": "http",
    }
