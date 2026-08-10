# Installing what is missing, from the panel, while it is running.
#
# A feature that needs a package the machine does not have used to end in a
# sentence telling the operator to go and install it. This module is the answer
# to that: the panel installs it, reports what it did, and the feature carries
# on. Nothing here is interactive, so a job either completes or says why it
# could not, and no request ever waits on apt.
#
# The one rule that matters for safety: no string from a request ever reaches a
# command line. A caller names a component from COMPONENTS, and the component
# names its own packages. Everything runs as a fixed argv list, never a shell.
import os
import shutil
import subprocess
import threading
import time

APT_TIMEOUT = 1800


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def escalation():
    """The prefix that runs a package manager, or None when nothing can.

    `sudo -n` only: a password prompt in a background job would hang forever
    with nobody to type into it, so a machine that would ask is treated the
    same as one that refuses.
    """
    if is_root():
        return []
    if shutil.which("sudo") and _run(["sudo", "-n", "true"], timeout=15)[0] == 0:
        return ["sudo", "-n"]
    return None


def _run(args, timeout=120, env=None):
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} did not finish within {timeout}s."
    except OSError as e:
        return 126, str(e)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _apt_env():
    return dict(os.environ, DEBIAN_FRONTEND="noninteractive",
                APT_LISTCHANGES_FRONTEND="none")


# --------------------------------------------------------------- the checks
def _compose_present():
    if shutil.which("docker") and _run(["docker", "compose", "version"], timeout=30)[0] == 0:
        return True
    return bool(shutil.which("docker-compose"))


def _docker_present():
    return bool(shutil.which("docker"))


def _docker_running():
    return _docker_present() and _run(
        ["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)[0] == 0


def _jail_present():
    return bool(shutil.which("bwrap"))


# ---------------------------------------------------------- the components
#
# `packages` is a list of alternatives, tried in order until one installs and
# the check passes. Distributions disagree about what Compose is called, and
# guessing wrong should cost a failed apt run, not the feature.
COMPONENTS = {
    "docker": {
        "label": "Docker",
        "why": "mailcow runs as a set of containers, so it needs a container engine.",
        "packages": (("docker.io",), ("docker-ce", "docker-ce-cli", "containerd.io")),
        # Installed is the binary being there; usable is its daemon answering.
        # Splitting the two is what lets a stopped daemon be started instead of
        # being reported as a missing package.
        "check": _docker_present,
        "ready": _docker_running,
        "services": ("docker",),
    },
    "compose": {
        "label": "Docker Compose",
        "why": "mailcow is defined as a compose project, so it is started with compose.",
        "packages": (("docker-compose-plugin",), ("docker-compose-v2",),
                     ("docker-compose",)),
        "check": _compose_present,
        "services": (),
    },
    "jail": {
        "label": "Bubblewrap",
        "why": ("a limited terminal is confined with it, so a staff account "
                "cannot walk out of its own home directory."),
        "packages": (("bubblewrap",),),
        "check": _jail_present,
        "services": (),
    },
}


def present(component):
    spec = COMPONENTS.get(component)
    return bool(spec) and bool(spec["check"]())


def missing():
    """The components this machine does not have, in install order."""
    return [key for key in COMPONENTS if not present(key)]


def _package_manager():
    for mgr in ("apt-get", "dnf", "yum", "pacman", "zypper", "apk"):
        if shutil.which(mgr):
            return mgr
    return ""


def _install_packages(packages):
    """(rc, output) for one alternative. apt is the only manager given its own
    treatment because it is the only one that needs an index refresh first."""
    mgr = _package_manager()
    sudo = escalation()
    if sudo is None:
        return 1, ("this panel cannot install packages: it is not running as "
                   "root and sudo would ask for a password.")
    if not mgr:
        return 1, "no package manager this panel knows how to drive was found."
    if mgr == "apt-get":
        _run(sudo + ["apt-get", "update", "-qq"], timeout=900, env=_apt_env())
        return _run(sudo + ["apt-get", "install", "-y", "--no-install-recommends"]
                    + list(packages), timeout=APT_TIMEOUT, env=_apt_env())
    if mgr == "pacman":
        return _run(sudo + ["pacman", "-Sy", "--noconfirm"] + list(packages),
                    timeout=APT_TIMEOUT)
    if mgr == "zypper":
        return _run(sudo + ["zypper", "--non-interactive", "install"] + list(packages),
                    timeout=APT_TIMEOUT)
    if mgr == "apk":
        return _run(sudo + ["apk", "add"] + list(packages), timeout=APT_TIMEOUT)
    return _run(sudo + [mgr, "install", "-y"] + list(packages), timeout=APT_TIMEOUT)


def _start_services(names):
    sudo = escalation()
    if sudo is None or not shutil.which("systemctl"):
        return
    for name in names:
        _run(sudo + ["systemctl", "enable", "--now", name], timeout=120)


def _make_usable(spec):
    """Installed is not the same as working: a daemon can be there and stopped.
    Start what the component needs, give it a moment, and report honestly."""
    ready = spec.get("ready")
    if ready is None or ready():
        return True, f"{spec['label']} is already installed."
    _start_services(spec.get("services", ()))
    for _ in range(10):
        if ready():
            return True, f"{spec['label']} is installed and its service is running."
        time.sleep(1)
    return False, (f"{spec['label']} is installed but not answering. Its service "
                   "may need starting by hand.")


def ensure(component):
    """Install one component if it is not already here. (ok, detail).

    Blocking, and slow: an image-less docker install is a few hundred megabytes.
    Call it from a background job, never from a request.
    """
    spec = COMPONENTS.get(component)
    if not spec:
        return False, "unknown component"
    if spec["check"]():
        return _make_usable(spec)
    tried = []
    for packages in spec["packages"]:
        rc, out = _install_packages(packages)
        if rc == 0 and spec["check"]():
            ok, detail = _make_usable(spec)
            if ok:
                return True, f"installed {spec['label']} ({' '.join(packages)})."
            tried.append(f"{' '.join(packages)}: {detail}")
            continue
        if rc == 0:
            tried.append(f"{' '.join(packages)}: installed, but {spec['label']} "
                         "is still not on this machine")
            continue
        tried.append(f"{' '.join(packages)}: {out.strip().splitlines()[-1][:200]}"
                     if out.strip() else f"{' '.join(packages)}: failed")
    return False, f"could not install {spec['label']}: " + "; ".join(tried[:3])


def ensure_all(components):
    """Install several in order, stopping at the first that will not go on.
    (ok, detail) with one line per component."""
    lines = []
    for name in components:
        ok, detail = ensure(name)
        lines.append(detail)
        if not ok:
            return False, "\n".join(lines)
    return True, "\n".join(lines)


# ------------------------------------------------------------- the job
# One installation at a time, polled by the page, in the same shape as the
# mailcow and Cloudflare jobs so the front end has one pattern to follow.
_state = {"action": "", "started": 0.0, "done": True, "ok": True,
          "output": "", "error": ""}
_lock = threading.Lock()


def job_state():
    with _lock:
        return {"action": _state["action"], "busy": not _state["done"],
                "ok": _state["ok"], "error": _state["error"],
                "output": _state["output"][-1500:],
                "seconds": int(time.time() - _state["started"]) if _state["started"] else 0}


def install_async(components):
    """Start installing. (started, message)."""
    wanted = [c for c in components if c in COMPONENTS]
    if not wanted:
        return False, "Nothing to install."
    labels = ", ".join(COMPONENTS[c]["label"] for c in wanted)
    with _lock:
        if not _state["done"]:
            return False, f"Already busy with {_state['action']}."
        _state.update({"action": f"installing {labels}", "started": time.time(),
                       "done": False, "ok": True, "output": "", "error": ""})

    def work():
        try:
            ok, detail = ensure_all(wanted)
        except Exception as e:                       # pragma: no cover, defensive
            ok, detail = False, f"{type(e).__name__}: {e}"
        with _lock:
            _state.update({"done": True, "ok": ok, "output": detail[-4000:],
                           "error": "" if ok else detail.strip()[-400:]})

    threading.Thread(target=work, daemon=True).start()
    return True, f"Installing {labels}."
