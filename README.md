# Argus Management Panel

A self-contained FastAPI **server management panel**, live telemetry (CPU load
and temperature, fan speed, battery, RAM, disk, network, private and public IP),
an in-browser terminal, process/connection views, systemd service control, and a
security/activity log. It ships as **one easy-to-deploy app**: clone it, run one
command, answer a few questions, and it's live.
 (nginx → `127.0.0.1:8080`).

## Quick start

```bash
python3 management.py
```

That is the whole install. No `pip install`, no `apt install`, no database setup.

The wizard does all of it for you:

1. **Installs its own Python dependencies.** If pip is missing it bootstraps it. On
   Debian/Kali/Ubuntu, where pip refuses to touch system site-packages (PEP 668), it
   retries with `--user`, then `--break-system-packages`, then distro packages, and
   finally builds a private `.venv` and restarts itself inside it. One of those always
   works.
2. **Makes sure PostgreSQL is installed and running**, installing it with apt / dnf /
   yum / pacman / zypper / apk / brew and starting the service if it isn't. It also
   installs nginx the same way, best-effort, only the Proxy card in Config needs it,
   so a failed install there never stops the rest of setup.
3. **Finds a privileged way into the server**, even when the configured role does not
   exist yet: direct TCP, the local unix socket, and `sudo -u postgres psql` (the
   standard bootstrap path on Debian-likes, which psycopg2 cannot reach on its own).
   Only if all of those fail does it ask you for a superuser login.
4. **Lists every database on the server** so you can pick one. If there are none it
   says so plainly and offers to create one, asking for the database name, the
   database user, and a password (leave it blank and a strong one is generated).
5. **Creates the tables this panel needs**, then verifies all of them landed.
6. **Creates your panel administrator account**, the username and password you sign
   in with. Any leftover insecure `admin`/`admin` account is removed.
7. **Asks which host and port to bind**, warning you if the port is already taken.
8. **Offers to install itself as a systemd service.** Say yes and it installs, starts,
   verifies the port is live, tells you the port, and exits, the panel keeps running
   and comes back on boot. Say no and it runs in the foreground, warning you that
   closing the terminal stops the panel.

Answers are saved to `deploy.json` (non-secret) and `.env` (mode 0600). Re-running the
wizard over an existing install is safe, every step is idempotent.

## Commands

```bash
python3 management.py             # setup wizard, then run
python3 management.py --service   # install + start the systemd service, then exit
python3 management.py --upgrade   # git pull the latest code, then restart the service
python3 management.py --update    # re-check and update the system structure: dependencies, tables, config, service
python3 management.py --serve     # run in the foreground from deploy.json
python3 management.py --status    # config / dependency / database / service report
python3 management.py --recovery-codes   # mint new single-use recovery codes
python3 management.py --setup     # force the wizard even without a TTY
python3 management.py --help
```

If you chose **not** to run as a service and want to switch later, that's
`python3 management.py --service`. Installing a system service needs root, so run it
with `sudo` if you aren't root.

Once installed the service is ordinary systemd:

```bash
systemctl status  argus-management
systemctl restart argus-management
journalctl -u argus-management -f
```

## Signing in, and getting back in

The panel password is stored only as a PBKDF2-SHA256 hash, so **it cannot be
looked up**, not in `deploy.json`, not in `.env`. (`DB_PASSWORD` in `.env` is the
*PostgreSQL* password, which is a different thing.) There are two supported ways
to change it.

**You know the current password.** Sign in, click your username in the top bar,
and use the Account pane. Changing the password signs out every other browser
using the account.

**You don't.** The wizard writes five single-use recovery codes to `.recovery`
(mode 0600, git-ignored), twelve digits each, and the only plaintext copy that
exists; the database keeps salted hashes. On the login page, **"Forgot your
password?"** asks for your username, one code, and a new password. A code stops
working the moment it is used, and a successful reset signs out every existing
session.

```bash
python3 management.py --recovery-codes   # mint a fresh set (retires the old ones)
```

You can also regenerate them from the Account pane, which shows the new codes
once. `--status` reports how many are left. If you run out, `--recovery-codes` is
the way back.

Guard rails on the recovery endpoint: a wrong username and a wrong code return
the same message and take the same time (no account enumeration), attempts are
throttled per-IP and globally, and every attempt, accepted or not, lands in
`management_log` under `SECURITY`.

## Config

The Config tab is where the panel administers itself. The admin sees all five
cards; a staff account sees its own account card plus whatever its grants
unlock.

- **User Management.** Create staff accounts with their own login and their own
  set of grants, edit those grants later, reset their password, or delete them.
  Their username is fixed once created, because the derived system account and
  the whole audit trail are keyed on it.

  A "restricted" terminal grant provisions a real, unprivileged OS account
  (`useradd`, no password, no SSH key) that the panel drops privileges into
  before spawning that user's shell, so their terminal can never reach anything
  the admin's can. Granting "their own files" disk access provisions the same
  account, so there is a home directory to confine file browsing to.
- **Server Configuration.** The host/port this panel binds to, and SSH access
  to the box: generate an ed25519 keypair (the public half is added to root's
  `authorized_keys`, the private half stays on disk and a copy is kept
  encrypted in Postgres so it can be re-downloaded from here), a reference
  password field (stored encrypted, informational only, it does not change
  any real account password), and a password-login-vs-key-only toggle for
  `sshd`.
- **Service.** The systemd service list and controls that used to be their
  own tab.
- **Database.** A row-level viewer and editor over this panel's own tables
  only, never anything else that might live in the same Postgres database.
  Reading, changing and seeing the change log are three separate grants, so a
  staff account can be given any combination of them.
- **Proxy.** Detects every nginx server block on the box and manages the ones
  this panel wrote. A host is described by its incoming scheme (HTTP, HTTPS,
  TCP or UDP), the domain, and where it forwards to. HTTPS never asks for a
  certificate: a host without one is served as plain HTTP, which is exactly
  what a tunnel already fronts with TLS. Force SSL, HSTS, HSTS subdomains and
  HTTP/2 stay as separate switches. Cache assets, block common exploits and
  websocket support are per-host toggles, and any number of custom locations
  can send a path under the domain somewhere else with their own toggles.
  Hosts written by hand are shown but never edited or deleted.
  A saved host can be reopened and changed: the generated file carries its own
  settings, so editing shows what was saved rather than a guess.
- **Firewall settings.** Inbound and outbound port rules, each one on or off,
  plus the list of blocked addresses. A proxy host puts its own inbound port on
  the allow list as it is saved. Delegable separately from the proxy itself.

### Permissions

There are eighteen grants, defined in one place: the `PERMISSIONS` registry in
`panel_users.py`. That registry is what validates a submitted permission set,
what the request path reads when it decides whether to answer, and what the
admin's form is generated from. Building the form from the same definition the
enforcement reads is deliberate: it makes it impossible to ship a checkbox no
endpoint honours, or an endpoint gated on something the admin cannot grant.

| group | grants |
|-------|--------|
| Terminal | none, own account only, or root |
| Disk | reach nothing / their own files / the whole filesystem, plus download, upload and delete as separate switches |
| Database | read tables, change rows, view the change log |
| Network | connection detail in the Server section, manage proxy hosts, manage firewall settings |
| CPU and memory | the top-process lists behind both meters |
| Services | see status, start and restart, stop |
| Logs | the Logs tab and its readers |

Adding a permission means adding one line to the registry and one check at its
endpoint. Nothing else needs a migration, because grants are stored as a single
normalized JSON object per account.

Four things worth knowing about how this is enforced:

- **Hiding is a courtesy, refusing is the boundary.** Every grant is checked
  server-side on every request. The copy sent to the browser only decides which
  controls are worth drawing, and is assumed to be tampered with.
- **Files are confined by resolved path.** A staff account scoped to its own
  files has every requested path passed through `realpath` before the prefix
  comparison, so a symlink planted inside the sandbox cannot point out of it.
- **Uploads are staged and never overwrite.** A new file is streamed into a
  hidden temporary file in the browsed folder, then given its real name only
  after the whole body has arrived. An existing name is refused. Staff
  accounts cannot upload into root's home or the protected system trees,
  because the panel writes as root. A single upload is capped at 1 GB, and any
  proxy in front of the panel needs a matching request-body limit.
- **Revocation is per account.** Resetting one staff password, or taking a grant
  away, signs out that person on their next request and nobody else.

Recovery codes belong to the admin account alone. A staff member who forgets
their password asks an admin, who resets it from the user list, which is a
stronger check than a code sitting in a file.

## Files

| file | what it is |
|------|------------|
| `management.py` | deployment front door: dependency bootstrap, DB provisioning, setup wizard, service installer |
| `recovery.py`   | password hashing + single-use recovery codes, shared by the CLI and the panel |
| `panel.py`      | the FastAPI panel itself (routes, UI, websocket terminal) |
| `DB.py`         | PostgreSQL pool, admin auth, settings, security/activity logs |
| `System.py`     | host telemetry, PTY terminal, process/connection helpers, file browser |
| `vault.py`      | symmetric encryption for the few secrets that must be read back, not just verified |
| `ssh_vault.py`  | SSH keypair generation and encrypted storage for the Server Configuration card |
| `panel_users.py`| staff accounts and their permission grants |
| `nginx_proxy.py`| renders, validates and manages nginx server blocks for the Proxy card |
| `firewall.py`   | port rules, blocked addresses, and the automatic block after repeated SSH failures |
| `static_mgmt/`  | CSS design system + panel JS + icon sprite |
| `vendor/`       | bundled fonts, xterm.js, icons (no external CDN needed) |

## Database schema

The wizard creates exactly what the panel runs on:

| table | purpose |
|-------|---------|
| `admin` | panel login accounts (PBKDF2-SHA256) |
| `admin_recovery_code` | single-use account recovery codes (salted PBKDF2 hashes) |
| `system_settings` | key/value runtime configuration |
| `management_log` | the panel's own structured event + audit log |
| `admin_action` | append-only administrator audit trail |
| `ssh_log` | SSH authentication events collected from journald |
| `web_login_log` | panel login attempts with device fingerprints |
| `web_fp_block` / `web_login_block` | brute-force blocks by device and by IP |
| `web_session_log` | issued panel sessions |
| `http_access_log` | HTTP request/response log |
| `ssh` | encrypted SSH keypair and reference password for Server Configuration |
| `panel_user` | staff accounts and their permission grants |

Picking an existing database only adds these tables; nothing already there is touched,
and the Database card only ever shows this list, never other tables that might already
live in the same Postgres database.

## Configuration

Non-secret runtime choices live in **`deploy.json`**; the DB password lives in **`.env`**
(mode 0600). Both are git-ignored, see `deploy.example.json` and `.env.example`.
Environment variables (`DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`,
`MGMT_BASE`) override both.

## Reverse proxy

nginx serves the panel at the root of `domain.com` and proxies to the
loopback port, forwarding websocket upgrades for the in-browser terminal. Set
`base_path` to `""` when serving from a subdomain root, or to e.g. `/management` when
mounting under a path on a shared host.

### TCP and UDP hosts

Forwarding raw TCP or UDP needs nginx's stream module, which Debian ships as a
separate package and which is not loaded by default. `management.py` installs
`libnginx-mod-stream`, creates `/etc/nginx/stream.d`, and adds a `stream` block
to `nginx.conf` that includes it, rolling the change back if `nginx -t` refuses.
Until both are in place the panel refuses to write a TCP or UDP host and says
why, because a `stream` block nginx does not understand stops it from starting
at all and would take every other host down with it.

The same reasoning covers forward hostnames. nginx resolves a `proxy_pass` name
when it loads the config, not per request, so a name that does not resolve is a
fatal error rather than one broken host. The form checks that the name resolves
before writing anything.
