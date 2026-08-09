# Reverse proxy host management.
#
# Generates nginx server blocks from a structured description: an incoming
# scheme and domain on one side, a forward scheme, host and port on the other,
# with TLS options, behaviour toggles, and any number of custom locations that
# each forward somewhere of their own.
#
# Two rules run through the whole module:
#   * a config this panel did not write is read-only. It is listed so the
#     operator can see it, and it is never edited or deleted from here.
#   * nothing is kept that nginx will not load. Every write is followed by
#     nginx -t, and a rejected config is rolled back before the error surfaces.
import glob
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess

MANAGED_MARKER = "# managed-by: argus-management"
META_PREFIX = "# argus-meta: "

DOMAIN_RE = re.compile(
    r"^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
HOST_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,253}$")
# A location must start with / and stay printable. No newlines, no braces, no
# semicolons: those are how you would break out of the generated block.
LOCATION_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,200}$")

LISTEN_SCHEMES = ("http", "https", "tcp", "udp")
FORWARD_SCHEMES = ("http", "https")

BEHAVIOUR_FLAGS = ("cache_assets", "block_exploits", "websockets")
TLS_FLAGS = ("force_ssl", "hsts", "hsts_subdomains", "http2")


# ---------------------------------------------------------------------------
# Layout discovery
# ---------------------------------------------------------------------------
def nginx_installed():
    return shutil.which("nginx") is not None


def nginx_version():
    """(major, minor, patch), or None when nginx is not installed."""
    if not nginx_installed():
        return None
    r = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", (r.stderr or "") + (r.stdout or ""))
    return tuple(int(g) for g in m.groups()) if m else None


def _http2_as_directive():
    """nginx 1.25.1 deprecated "listen ... http2" in favour of a standalone
    "http2 on;". Emitting the old form on a current nginx logs a warning on
    every reload, and it is scheduled to stop working."""
    version = nginx_version()
    return version is None or version >= (1, 25, 1)


def _dirs():
    """(available_dir, enabled_dir_or_None). Debian-style layouts have both;
    RHEL-style conf.d files are active as soon as they exist."""
    if os.path.isdir("/etc/nginx/sites-available"):
        return "/etc/nginx/sites-available", "/etc/nginx/sites-enabled"
    if os.path.isdir("/etc/nginx/conf.d"):
        return "/etc/nginx/conf.d", None
    return None, None


def _stream_dir():
    """Where a stream (TCP/UDP) block can live. nginx only loads these if the
    main config has a stream {} block including this directory, which is
    reported rather than assumed."""
    for path in ("/etc/nginx/stream.d", "/etc/nginx/streams-enabled"):
        if os.path.isdir(path):
            return path
    return None


def stream_module_available():
    """(available, reason). The stream module is what makes TCP and UDP
    forwarding possible, and on Debian it ships as a separate package. A
    directory to write into is not proof the module is loaded: without it,
    nginx reads "stream" as an unknown directive and refuses to start."""
    if not nginx_installed():
        return False, "nginx is not installed."
    r = subprocess.run(["nginx", "-V"], capture_output=True, text=True)
    build = (r.stderr or "") + (r.stdout or "")
    if "--with-stream=dynamic" in build:
        for conf in glob.glob("/etc/nginx/modules-enabled/*.conf"):
            try:
                with open(conf) as fh:
                    body = fh.read()
            except OSError:
                continue
            if "load_module" in body and "stream_module" in body:
                return True, ""
        return False, ("The stream module is built but not loaded. Install "
                       "libnginx-mod-stream to forward TCP or UDP.")
    if "--with-stream" in build:
        return True, ""
    return False, "This nginx was built without the stream module."


def stream_supported():
    """TCP and UDP forwarding needs both a place to put the config and a
    loaded stream module."""
    return _stream_dir() is not None and stream_module_available()[0]


def stream_problem():
    """Why TCP and UDP forwarding is unavailable, or "" when it works."""
    ok, reason = stream_module_available()
    if not ok:
        return reason
    if _stream_dir() is None:
        return ("No stream config directory. Create /etc/nginx/stream.d and "
                "include it from a stream {} block in nginx.conf.")
    return ""


def _slug(domain):
    """The filename for a host, derived from its domain and nothing else.

    Path separators are dropped rather than escaped, runs of dots are collapsed
    and leading dots are stripped, so the result can neither leave the directory
    nor land as a dotfile. validate() would already have refused a domain shaped
    like that; this is the second lock on the same door.
    """
    slug = re.sub(r"[^a-z0-9.*-]", "", domain.lower()).replace("*", "wildcard")
    slug = re.sub(r"\.{2,}", ".", slug).strip(".-")
    return slug or "unnamed"


def _config_path(domain):
    available, _ = _dirs()
    if not available:
        return None
    suffix = ".conf" if available.endswith("conf.d") else ""
    return os.path.join(available, _slug(domain) + suffix)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _bad_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return "Enter a port number."
    if not 1 <= port <= 65535:
        return "Port must be between 1 and 65535."
    return ""


def resolves(host):
    """True when nginx will be able to resolve this name at config load.

    nginx resolves proxy_pass hostnames when it reads the config, not per
    request. A name that does not resolve is an [emerg], and an emerg stops
    nginx from loading at all, taking every other proxy host down with it.
    So an unresolvable name has to be refused in the form, before the file
    is ever written.
    """
    host = (host or "").strip()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, UnicodeError, OSError):
        return False


def validate(spec):
    """Returns a list of human-readable problems. Empty means acceptable."""
    problems = []
    domain = (spec.get("domain") or "").strip().lower()
    if not DOMAIN_RE.match(domain):
        problems.append("Enter a real domain name, for example app.example.com.")

    listen = (spec.get("listen_scheme") or "https").lower()
    if listen not in LISTEN_SCHEMES:
        problems.append(f"Incoming scheme must be one of {', '.join(LISTEN_SCHEMES)}.")

    forward_scheme = (spec.get("forward_scheme") or "http").lower()
    if listen in ("tcp", "udp"):
        if _bad_port(spec.get("listen_port")):
            problems.append("A TCP or UDP host needs the port to listen on.")
        blocked = stream_problem()
        if blocked:
            problems.append(blocked)
    elif forward_scheme not in FORWARD_SCHEMES:
        problems.append("Forward scheme must be http or https.")

    host = (spec.get("forward_host") or "").strip()
    if not HOST_RE.match(host):
        problems.append("Forward hostname must be a hostname or an IP address.")
    elif not resolves(host):
        problems.append(f"{host} does not resolve from this server. nginx looks "
                        "the name up when it loads the config, so it would "
                        "refuse to start. Use an IP address, or add the name "
                        "to /etc/hosts or DNS first.")
    problem = _bad_port(spec.get("forward_port"))
    if problem:
        problems.append(f"Forward port: {problem}")

    if listen == "https":
        cert = (spec.get("cert_path") or "").strip()
        key = (spec.get("cert_key_path") or "").strip()
        for label, path in (("certificate", cert), ("certificate key", key)):
            if not path:
                problems.append(f"An HTTPS host needs a {label} path.")
            elif not os.path.isabs(path):
                problems.append(f"The {label} path must be absolute.")
            elif not os.path.isfile(path):
                problems.append(f"No {label} file at {path}.")

    for i, loc in enumerate(spec.get("locations") or [], 1):
        path = (loc.get("path") or "").strip()
        if not LOCATION_RE.match(path):
            problems.append(f"Custom location {i}: path must start with / and "
                            "contain no spaces or punctuation nginx would read as syntax.")
        loc_host = (loc.get("forward_host") or "").strip()
        if not HOST_RE.match(loc_host):
            problems.append(f"Custom location {i}: forward hostname is not valid.")
        elif not resolves(loc_host):
            problems.append(f"Custom location {i}: {loc_host} does not resolve "
                            "from this server, so nginx would refuse to start.")
        problem = _bad_port(loc.get("forward_port"))
        if problem:
            problems.append(f"Custom location {i} port: {problem}")
        if (loc.get("forward_scheme") or "http").lower() not in FORWARD_SCHEMES:
            problems.append(f"Custom location {i}: forward scheme must be http or https.")

    return problems


def normalize(spec):
    """A stored, validated spec with every key present and nothing extra."""
    listen = (spec.get("listen_scheme") or "https").lower()
    out = {
        "domain": (spec.get("domain") or "").strip().lower(),
        "listen_scheme": listen if listen in LISTEN_SCHEMES else "https",
        "listen_port": int(spec.get("listen_port") or (443 if listen == "https" else 80)),
        "forward_scheme": (spec.get("forward_scheme") or "http").lower(),
        "forward_host": (spec.get("forward_host") or "").strip(),
        "forward_port": int(spec.get("forward_port") or 80),
        "cert_path": (spec.get("cert_path") or "").strip(),
        "cert_key_path": (spec.get("cert_key_path") or "").strip(),
        "locations": [],
    }
    if out["forward_scheme"] not in FORWARD_SCHEMES:
        out["forward_scheme"] = "http"
    for flag in TLS_FLAGS + BEHAVIOUR_FLAGS:
        out[flag] = bool(spec.get(flag))
    for loc in spec.get("locations") or []:
        entry = {
            "path": (loc.get("path") or "").strip(),
            "forward_scheme": (loc.get("forward_scheme") or "http").lower(),
            "forward_host": (loc.get("forward_host") or "").strip(),
            "forward_port": int(loc.get("forward_port") or 80),
        }
        if entry["forward_scheme"] not in FORWARD_SCHEMES:
            entry["forward_scheme"] = "http"
        for flag in BEHAVIOUR_FLAGS:
            entry[flag] = bool(loc.get(flag))
        out["locations"].append(entry)
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
_PROXY_HEADERS = """        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
"""

_WEBSOCKET = """        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
"""

# Request shapes that only ever show up in automated probing. Deliberately
# narrow: a rule broad enough to catch everything also blocks real traffic.
_EXPLOIT_GUARD = """    # Block Common Exploits
    location ~* "\\.(?:git|svn|env|htaccess|htpasswd)$" { deny all; }
    location ~* "/(?:wp-admin|wp-login\\.php|xmlrpc\\.php)" { deny all; }
    if ($query_string ~* "(<|%3C).*script.*(>|%3E)") { return 403; }
    if ($query_string ~* "union.*select.*\\(") { return 403; }
"""

_CACHE_ASSETS = """    # Cache Assets
    location ~* \\.(?:jpg|jpeg|png|gif|webp|avif|ico|svg|css|js|woff2?|ttf|eot|mp4|webm)$ {
        proxy_pass {upstream};
{headers}        expires 30d;
        add_header Cache-Control "public, max-age=2592000, immutable";
        access_log off;
    }
"""


def _location_body(scheme, host, port, flags, indent="        "):
    upstream = f"{scheme}://{host}:{port}"
    body = f"        proxy_pass {upstream};\n" + _PROXY_HEADERS
    if flags.get("websockets"):
        body += _WEBSOCKET
    return body


def _render_location(loc):
    return (f"    location {loc['path']} {{\n"
            + _location_body(loc["forward_scheme"], loc["forward_host"],
                             loc["forward_port"], loc)
            + "    }\n")


def _render_stream(spec):
    """A TCP or UDP forward. Streams have no notion of Host, headers or
    locations, so those options are simply not part of the output."""
    udp = " udp" if spec["listen_scheme"] == "udp" else ""
    return f"""{MANAGED_MARKER}
{META_PREFIX}{json.dumps(spec, sort_keys=True)}
# {spec['listen_scheme'].upper()} forward for {spec['domain']}
server {{
    listen {spec['listen_port']}{udp};
    proxy_pass {spec['forward_host']}:{spec['forward_port']};
    proxy_timeout 60s;
    proxy_connect_timeout 10s;
}}
"""


def render(spec):
    """The nginx config for a normalized spec."""
    spec = normalize(spec)
    if spec["listen_scheme"] in ("tcp", "udp"):
        return _render_stream(spec)

    domain = spec["domain"]
    upstream = f"{spec['forward_scheme']}://{spec['forward_host']}:{spec['forward_port']}"
    https = spec["listen_scheme"] == "https"

    parts = [MANAGED_MARKER, META_PREFIX + json.dumps(spec, sort_keys=True)]

    # A plain-HTTP server block exists either as the whole host, or purely to
    # redirect to HTTPS when Force SSL is on.
    if https and spec["force_ssl"]:
        parts.append(f"""server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    return 301 https://$host$request_uri;
}}""")

    listen_lines, extra = [], []
    if https:
        if spec["http2"] and _http2_as_directive():
            listen_lines.append("    listen 443 ssl;")
            listen_lines.append("    listen [::]:443 ssl;")
            extra.append("    http2 on;")
        else:
            http2 = " http2" if spec["http2"] else ""
            listen_lines.append(f"    listen 443 ssl{http2};")
            listen_lines.append(f"    listen [::]:443 ssl{http2};")
    else:
        listen_lines.append("    listen 80;")
        listen_lines.append("    listen [::]:80;")

    block = ["server {"]
    block += listen_lines
    block += extra
    block.append(f"    server_name {domain};")

    if https:
        block.append(f"    ssl_certificate {spec['cert_path']};")
        block.append(f"    ssl_certificate_key {spec['cert_key_path']};")
        block.append("    ssl_protocols TLSv1.2 TLSv1.3;")
        block.append("    ssl_prefer_server_ciphers off;")
        block.append("    ssl_session_cache shared:SSL:10m;")
        block.append("    ssl_session_timeout 1d;")
        if spec["hsts"]:
            subdomains = "; includeSubDomains" if spec["hsts_subdomains"] else ""
            block.append(f'    add_header Strict-Transport-Security '
                         f'"max-age=63072000{subdomains}" always;')

    block.append("    client_max_body_size 0;")

    if spec["block_exploits"]:
        block.append(_EXPLOIT_GUARD.rstrip("\n"))

    if spec["cache_assets"]:
        block.append(_CACHE_ASSETS.replace("{upstream}", upstream)
                     .replace("{headers}", _PROXY_HEADERS).rstrip("\n"))

    # Custom locations come before / so the more specific prefix wins.
    for loc in spec["locations"]:
        block.append(_render_location(loc).rstrip("\n"))

    block.append("    location / {")
    block.append(_location_body(spec["forward_scheme"], spec["forward_host"],
                                spec["forward_port"], spec).rstrip("\n"))
    block.append("    }")
    block.append("}")

    parts.append("\n".join(block))
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# Reading what is on disk
# ---------------------------------------------------------------------------
def _parse(text, path):
    """Everything known about one config file. A managed file carries its own
    spec as JSON, so reading it back is exact rather than reverse-engineered
    from the generated directives."""
    managed = MANAGED_MARKER in text
    spec = None
    if managed:
        m = re.search(re.escape(META_PREFIX) + r"(.*)", text)
        if m:
            try:
                spec = normalize(json.loads(m.group(1)))
            except (ValueError, TypeError):
                spec = None

    domain_m = re.search(r"(?im)^\s*server_name\s+([^;]+);", text)
    target_m = re.search(r"(?im)^\s*proxy_pass\s+(?:(https?)://)?([^;\s]+);", text)
    info = {
        "file": os.path.basename(path),
        "managed": managed,
        "spec": spec,
        "domain": spec["domain"] if spec else (
            domain_m.group(1).split()[0] if domain_m else ""),
        "target": (f"{target_m.group(1) or 'tcp'}://{target_m.group(2)}"
                   if target_m else ""),
        "https": bool(re.search(r"(?im)^\s*listen\s+443\s+ssl", text)),
        "websockets": bool(re.search(r"(?im)Upgrade\s+\$http_upgrade", text)),
    }
    return info


def list_hosts():
    """Every server block nginx would load: ours and hand-written alike.
    Unmanaged entries are marked so the interface can refuse to edit them."""
    hosts = []
    for directory in filter(None, (_dirs()[0], _stream_dir())):
        available, enabled = _dirs()
        active = None
        if directory == available and enabled and os.path.isdir(enabled):
            active = set(os.listdir(enabled))
        for path in sorted(glob.glob(os.path.join(directory, "*"))):
            if not os.path.isfile(path):
                continue
            try:
                with open(path) as f:
                    text = f.read()
            except OSError:
                continue
            if "server_name" not in text and "proxy_pass" not in text:
                continue
            info = _parse(text, path)
            info["enabled"] = True if active is None else (
                os.path.basename(path) in active)
            hosts.append(info)
    return hosts


def get_host(filename):
    available, _ = _dirs()
    if not available:
        return None
    for directory in filter(None, (available, _stream_dir())):
        path = os.path.join(directory, os.path.basename(filename))
        if os.path.isfile(path):
            with open(path) as f:
                return _parse(f.read(), path)
    return None


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
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


def _target_path(spec):
    if spec["listen_scheme"] in ("tcp", "udp"):
        directory = _stream_dir()
        if not directory:
            raise RuntimeError(
                "This nginx has no stream directory, so TCP and UDP forwards "
                "cannot be added. Add a stream block to nginx.conf that "
                "includes /etc/nginx/stream.d/*.conf, then try again.")
        return os.path.join(directory, _slug(spec["domain"]) + ".conf")
    path = _config_path(spec["domain"])
    if not path:
        raise RuntimeError("nginx is not installed, or its layout was not recognized")
    return path


def _write_and_reload(path, text, previous=None):
    """Write, test, and roll back if nginx refuses. previous=None means the
    file is new and should be removed on failure."""
    enabled_link = None
    available, enabled = _dirs()
    with open(path, "w") as f:
        f.write(text)
    if enabled and os.path.dirname(path) == available:
        enabled_link = os.path.join(enabled, os.path.basename(path))
        if not os.path.exists(enabled_link):
            os.symlink(path, enabled_link)

    ok, err = _reload()
    if ok:
        return
    if previous is None:
        os.remove(path)
        if enabled_link and os.path.islink(enabled_link):
            os.remove(enabled_link)
    else:
        with open(path, "w") as f:
            f.write(previous)
        _reload()
    raise RuntimeError(f"nginx rejected the config: {err}")


def create_host(spec):
    problems = validate(spec)
    if problems:
        raise ValueError(" ".join(problems))
    spec = normalize(spec)
    path = _target_path(spec)
    if os.path.exists(path):
        raise ValueError(f"a config for {spec['domain']} already exists")
    _write_and_reload(path, render(spec))
    return {"file": os.path.basename(path), "spec": spec}


def update_host(filename, spec):
    """Edit a host this panel created. A hand-written config is refused: the
    operator's own file is not this panel's to rewrite."""
    existing = get_host(filename)
    if existing is None:
        raise ValueError("no such host")
    if not existing["managed"]:
        raise ValueError("this host was not created here, so it is read-only")

    problems = validate(spec)
    if problems:
        raise ValueError(" ".join(problems))
    spec = normalize(spec)

    old_path = _target_path(existing["spec"] or spec)
    with open(old_path) as f:
        previous = f.read()

    new_path = _target_path(spec)
    if new_path != old_path:
        if os.path.exists(new_path):
            raise ValueError(f"a config for {spec['domain']} already exists")
        _write_and_reload(new_path, render(spec))
        delete_host(os.path.basename(old_path))
        return {"file": os.path.basename(new_path), "spec": spec}

    _write_and_reload(old_path, render(spec), previous=previous)
    return {"file": os.path.basename(old_path), "spec": spec}


def delete_host(filename):
    safe_name = os.path.basename(filename)
    available, enabled = _dirs()
    for directory in filter(None, (available, _stream_dir())):
        path = os.path.join(directory, safe_name)
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            text = f.read()
        if MANAGED_MARKER not in text:
            raise ValueError(
                "this host was not created here, so it will not be removed automatically")
        if enabled and directory == available:
            link = os.path.join(enabled, safe_name)
            if os.path.islink(link) or os.path.exists(link):
                os.remove(link)
        os.remove(path)
        ok, err = _reload()
        if not ok:
            raise RuntimeError(f"nginx reload failed after removal: {err}")
        return True
    raise ValueError("no such host")


# ---------------------------------------------------------------------------
# Certificate discovery, for the file picker in the form
# ---------------------------------------------------------------------------
_CERT_ROOTS = ("/etc/letsencrypt/live", "/etc/ssl/certs", "/etc/nginx/ssl",
               "/etc/ssl/private", "/etc/pki/tls/certs")
_CERT_SUFFIXES = (".pem", ".crt", ".cer", ".key")


def list_certificates():
    """Certificate and key files already on the box, so the operator picks one
    instead of typing a path. Only names are returned, never contents."""
    found = []
    for root in _CERT_ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            if dirpath.count(os.sep) - root.count(os.sep) > 2:
                continue
            for name in sorted(filenames):
                if not name.endswith(_CERT_SUFFIXES):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    size = os.path.getsize(full)
                except OSError:
                    continue
                found.append({
                    "path": full,
                    "name": name,
                    "is_key": "privkey" in name or name.endswith(".key"),
                    "size": size,
                })
            if len(found) > 400:
                return found
    return found
