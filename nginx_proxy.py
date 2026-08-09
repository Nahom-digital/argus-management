# Reverse proxy host management: detect nginx's own layout, list what is
# already configured (ours and hand-written alike), and generate new server
# blocks for it. Deliberately does not touch TLS/certificates; that is a
# separate, explicit follow-up, not something this module reaches for.
import glob
import os
import re
import subprocess

MANAGED_MARKER = "# managed-by: argus-management"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
TARGET_RE = re.compile(r"^[a-zA-Z0-9_.-]+:[0-9]{1,5}$")


def nginx_installed():
    return subprocess.run(["which", "nginx"], capture_output=True).returncode == 0


def _dirs():
    """Returns (available_dir, enabled_dir_or_None). Debian-style layouts have
    both; RHEL-style conf.d has files that are active as soon as they exist."""
    if os.path.isdir("/etc/nginx/sites-available"):
        return "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"
    if os.path.isdir("/etc/nginx/conf.d"):
        return "/etc/nginx/conf.d", None
    return None, None


def _slug(domain):
    return re.sub(r"[^a-z0-9.-]", "", domain.lower())


def _config_path(domain):
    available, _ = _dirs()
    if not available:
        return None
    suffix = ".conf" if available.endswith("conf.d") else ""
    return os.path.join(available, _slug(domain) + suffix)


def _parse_server_block(text):
    domain_m = re.search(r"(?im)^\s*server_name\s+([^;]+);", text)
    target_m = re.search(r"(?im)^\s*proxy_pass\s+https?://([^;\s]+);", text)
    ws_m = re.search(r"(?im)Upgrade\s+\$http_upgrade", text)
    return {
        "domain": (domain_m.group(1).split()[0] if domain_m else ""),
        "target": (target_m.group(1) if target_m else ""),
        "websockets": bool(ws_m),
        "managed": MANAGED_MARKER in text,
    }


def list_hosts():
    """Every server block nginx would actually load: our own generated
    ones and anything hand-written, detected the same way."""
    available, enabled = _dirs()
    if not available:
        return []
    paths = sorted(glob.glob(os.path.join(available, "*")))
    active_names = None
    if enabled and os.path.isdir(enabled):
        active_names = set(os.listdir(enabled))
    hosts = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path) as f:
                text = f.read()
        except OSError:
            continue
        if "server_name" not in text:
            continue
        info = _parse_server_block(text)
        info["file"] = os.path.basename(path)
        info["enabled"] = True if active_names is None else (os.path.basename(path) in active_names)
        hosts.append(info)
    return hosts


def domain_problem(domain):
    if not domain or not NAME_RE.match(domain):
        return "Enter a real domain name, for example example.com."
    return ""


def target_problem(target):
    if not target or not TARGET_RE.match(target):
        return "Target must look like host:port, for example 127.0.0.1:8080."
    return ""


def _render(domain, target, websockets):
    upgrade_block = ""
    if websockets:
        upgrade_block = (
            "        proxy_http_version 1.1;\n"
            "        proxy_set_header Upgrade $http_upgrade;\n"
            "        proxy_set_header Connection \"upgrade\";\n"
        )
    return f"""{MANAGED_MARKER}
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    location / {{
        proxy_pass http://{target};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
{upgrade_block}    }}
}}
"""


def _reload():
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        return False, test.stderr.strip()[:600]
    r = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
        if r.returncode != 0:
            return False, r.stderr.strip()[:600]
    return True, ""


def create_host(domain, target, websockets):
    problem = domain_problem(domain) or target_problem(target)
    if problem:
        raise ValueError(problem)
    path = _config_path(domain)
    if not path:
        raise RuntimeError("nginx is not installed, or its layout was not recognized")
    if os.path.exists(path):
        raise ValueError(f"a config for {domain} already exists")

    with open(path, "w") as f:
        f.write(_render(domain, target, websockets))

    _, enabled = _dirs()
    if enabled and os.path.isdir(enabled):
        link = os.path.join(enabled, os.path.basename(path))
        if not os.path.exists(link):
            os.symlink(path, link)

    ok, err = _reload()
    if not ok:
        os.remove(path)
        _, enabled = _dirs()
        if enabled:
            link = os.path.join(enabled, os.path.basename(path))
            if os.path.islink(link):
                os.remove(link)
        raise RuntimeError(f"nginx rejected the new config: {err}")
    return True


def delete_host(filename):
    available, enabled = _dirs()
    if not available:
        raise RuntimeError("nginx is not installed")
    safe_name = os.path.basename(filename)
    path = os.path.join(available, safe_name)
    if not os.path.isfile(path):
        raise ValueError("no such host")
    with open(path) as f:
        text = f.read()
    if MANAGED_MARKER not in text:
        raise ValueError("this host was not created here, so it will not be removed automatically")
    if enabled:
        link = os.path.join(enabled, safe_name)
        if os.path.islink(link) or os.path.exists(link):
            os.remove(link)
    os.remove(path)
    ok, err = _reload()
    if not ok:
        raise RuntimeError(f"nginx reload failed after removal: {err}")
    return True
